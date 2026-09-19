#!/usr/bin/env python3
"""KAT harness for the KLEE SHA-3 family Machines (SHA3-224/256/384/512, SHAKE128/256).

What is validated (spec anchors, by heading):
  src/ace-ISA-machines.adoc (Book 2)
  [[KLEE-SHA-3]], [[KLEE-SHA-3-parameters]]
      -- parameter table (n, c, b, t, XOF, suffix D); Provisioning Input = the MDH
         only; Serialized Content = `state` (pos. i, 1600 bits) and `block_base`
         (pos. ii, 16 bits), implicitly zero-padded to a multiple of 128 bits;
         P() / process_block() / update(); States and transitions; direct XOR
         absorption; S = D || pad10*1 with its one-block (|S| = b - block_base)
         and two-block (|S| = 2b - block_base) clauses; a single t-bit digest
         then _Success_ for SHA3-n; unbounded squeezing for SHAKE.
  [[KLEE-hash-functions]]
      -- _Ready_ initialisation; entry into _Hash_Output_ (finalize,
         block_base <- 0); the Form C squeeze loop, including the clearing of
         OUTPUT beyond output_base on _Success_ and the interruption point
         klstart <- output_base / 8 (resumption output_base <- 8 * klstart).
  [[KLEE-process-VLI]]
      -- the SHA-3 invocation (max_len = 0, block = state, state_offset = 0,
         cumul_len = None, finalize = None, mode = xor_accumulate), the Form A
         entry, Form B transfers, the interruption point klstart <- input_base/8,
         resumption input_base <- 8 * klstart, the rejection of a same-State
         transition, and the constraint state_offset + b <= n.
  [[KLEE-Machine-rules]] (AGR1, AGR2), [[KLEE-truncation-vs-length]],
  [[KLEE-state-constants-symmetric]], [[KLEE-exec-encodings]] (Type 6, Modes
  0-5), [[KLEE-derive-endpoints]] (`kl.exec` endpoints, index 0).
  src/ace-ISA-unpriv.adoc (Book 1)
  [[KLEE-CSR-klstart]]          -- klstart written with 0 when the instruction
                                   retires; empty transfer window; interruption
                                   points (input: _Invalid_, output only: no
                                   operation).
  [[KLEE-instruction-exec]], [[KLEE-usage-input-output]] (Form D substitution),
  [[KLEE-instruction-derive]], [[KLEE-State-management]] (SGR2, SGR5, SGR6,
  SGR7, SGR8, SGR10, SGR16), [[KLEE-resumability]] (IRR6), [[KLEE-length-rule]],
  [[KLEE-instruction-size]], [[KLEE-metadata-header]] (_Machine_, _State_).
  src/ace-notation.adoc: FIPS 202 row of [[KLEE-Notation-standards]] -- direct
  mapping of the absorbed string, lanes little-endian (values are the KLEE
  little-endian ints of common.py).

Layered anchoring:
  1. Keccak-f[1600] is implemented FROM SCRATCH below (round constants and rho
     offsets transcribed from FIPS 202 / the Keccak reference).
  2. A bit-level FIPS 202 reference sponge built on it is checked against EMBEDDED
     standard digests and against Python's hashlib (labeled reference oracle).
  3. The KLEE model (MDH, States, process_VLI, padding clauses, squeeze loop,
     Serialized Content, kl.derive endpoints, implemented literally from the
     spec text) is checked against the embedded vectors, the reference sponge,
     and the hashlib oracle.
  Bit-granular cases (the two-block padding spill) have no external oracle
  (hashlib is byte-only): they are anchored model-vs-reference, with the reference's
  uniform pad10*1 having been anchored at byte granularity.

Embedded vector provenance:
  * "" and "abc" digests/XOF prefixes: FIPS 202 known answers (NIST CSRC
    "Example Values" files SHA3-224.pdf ... SHAKE256.pdf); cross-checked against
    Python hashlib at development time (2026-08-26).
  * 200 x 0xA3 (1600-bit message): NIST CSRC "Example Values" SHA3-224_1600.pdf,
    SHA3-256_1600.pdf, SHA3-384_1600.pdf, SHA3-512_1600.pdf, SHAKE128_1600.pdf,
    SHAKE256_1600.pdf; cross-checked against hashlib at development time.
  * Pattern-message, derive and serialisation cases carry no embedded constant
    and are anchored at runtime against the hashlib oracle (labeled [oracle])
    or against the embedded vectors.

Negative controls (must mismatch, declared via KAT-EXPECT-FAIL):
  * suffix bit order  -- the domain suffix byte (0x06 / 0x1F) applied MSB-aligned
    (bit-reversed) instead of the FIPS 202 LSB-first convention.
  * klstart units     -- klstart written as a bit count and consumed under the
    architectural byte convention on resumption.
  * serialized field order -- the Serialized Content assembled with the `@`
    operator (first field in the MORE significant bits) instead of in table order.

Verdict: per-case PASS/FAIL lines and a final `KAT-RESULT: PASS|FAIL`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl, cat    # KLEE value conventions (do not modify common.py)

import hashlib                          # LABELED REFERENCE ORACLE ONLY

# --------------------------------------------------------------- Keccak-f[1600]
# From scratch.  Round constants and rho offsets are the well-known FIPS 202 /
# Keccak-reference tables; they are verified end-to-end through the embedded
# FIPS 202 digests below.

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_RHO = [  # _RHO[x][y]
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_M64 = (1 << 64) - 1


def _rol64(v, s):
    s %= 64
    if s == 0:
        return v
    return ((v << s) | (v >> (64 - s))) & _M64


def keccak_f1600(state):
    """KECCAK-p[1600,24] on a 1600-bit KLEE value.

    Per the FIPS 202 row of the KLEE conventions table the mapping is direct:
    lane (x, y) of FIPS 202 3.1 occupies bits [64*(5y+x)+63 : 64*(5y+x)] of the
    value, each lane little-endian -- which is exactly the identity on the KLEE
    little-endian integer of the state byte string.
    """
    A = [(state >> (64 * i)) & _M64 for i in range(25)]     # lane i = (x=i%5, y=i//5)
    for rc in _KECCAK_RC:
        # theta
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
        A = [A[i] ^ D[i % 5] for i in range(25)]
        # rho + pi
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(A[x + 5 * y], _RHO[x][y])
        # chi
        A = [B[i] ^ ((~B[(i % 5 + 1) % 5 + 5 * (i // 5)])
                     & B[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        # iota
        A[0] ^= rc
    v = 0
    for i in range(24, -1, -1):
        v = (v << 64) | (A[i] & _M64)
    return v


# --------------------------------------------------- FIPS 202 reference sponge
# Bit-level, straight from FIPS 202 5.1/6: P = M || D || 1 || 0^j || 1, absorbed
# r bits at a time; bit j of every string is bit j of its KLEE value (the FIPS 202
# h2b order coincides with the KLEE little-endian convention).

def ref_sponge(rate_bits, msg_val, msg_bits, d_bits, out_bytes):
    S = 0
    for j, bit in enumerate(d_bits):
        S |= bit << j
    S |= 1 << len(d_bits)                       # leading 1 of pad10*1
    total = msg_bits + len(d_bits) + 1
    plen = (total // rate_bits + 1) * rate_bits  # room for the final 1, j >= 0
    P = (msg_val & ((1 << msg_bits) - 1)) | (S << msg_bits) | (1 << (plen - 1))
    st = 0
    rmask = (1 << rate_bits) - 1
    for off in range(0, plen, rate_bits):
        st ^= (P >> off) & rmask
        st = keccak_f1600(st)
    out = b''
    while len(out) < out_bytes:
        out += v2b(st & rmask, rate_bits // 8)
        if len(out) < out_bytes:
            st = keccak_f1600(st)
    return out[:out_bytes]


def ref_hash(name, msg, out_bytes=None):
    c, b, t, xof, D = PARAMS[name]
    n = out_bytes if out_bytes is not None else t // 8
    return ref_sponge(b, b2v(msg) if msg else 0, 8 * len(msg), D, n)


# ------------------------------------------------------------------ parameters
N_STATE = 1600                          # [[KLEE-SHA-3]]: n = 1600
GRANULARITY = 32                        # [[KLEE-SHA-3]]: smallest vector element width
STATE_OFFSET = 0                        # the SHA-3 invocation of process_VLI

# Transcribed from the spec table [[KLEE-SHA-3-parameters]].  D is the
# domain-separation suffix as a bit sequence, first-appended bit first
# (= LSB-first in the KLEE value): "01" -> (0,1), "1111" -> (1,1,1,1).
PARAMS = {
    #            c     b     t    XOF    D
    'SHA3-224': (448, 1152, 224, False, (0, 1)),
    'SHA3-256': (512, 1088, 256, False, (0, 1)),
    'SHA3-384': (768,  832, 384, False, (0, 1)),
    'SHA3-512': (1024, 576, 512, False, (0, 1)),
    'SHAKE128': (256, 1344, 1344, True, (1, 1, 1, 1)),
    'SHAKE256': (512, 1088, 1088, True, (1, 1, 1, 1)),
}

# [[KLEE-exec-encodings]]: _Machine_ = Type [11:4] @ Mode [3:0].
MACHINE_TYPE_MODE = {
    'SHA3-224': (6, 0), 'SHA3-256': (6, 1), 'SHA3-384': (6, 2),
    'SHA3-512': (6, 3), 'SHAKE128': (6, 4), 'SHAKE256': (6, 5),
}
MACHINE_CODE = {nm: (ty << 4) | mo for nm, (ty, mo) in MACHINE_TYPE_MODE.items()}
MACHINE_NAME = {code: nm for nm, code in MACHINE_CODE.items()}

_ORACLE = {
    'SHA3-224': lambda m, n: hashlib.sha3_224(m).digest(),
    'SHA3-256': lambda m, n: hashlib.sha3_256(m).digest(),
    'SHA3-384': lambda m, n: hashlib.sha3_384(m).digest(),
    'SHA3-512': lambda m, n: hashlib.sha3_512(m).digest(),
    'SHAKE128': lambda m, n: hashlib.shake_128(m).digest(n),
    'SHAKE256': lambda m, n: hashlib.shake_256(m).digest(n),
}


def oracle(name, msg, out_bytes=None):
    """Python hashlib -- LABELED REFERENCE ORACLE (not part of the model)."""
    c, b, t, xof, D = PARAMS[name]
    n = out_bytes if out_bytes is not None else t // 8
    # For the fixed-output functions hashlib always returns the whole digest;
    # a shorter request is a prefix of it (the KLEE model emits a prefix too).
    return _ORACLE[name](msg, n)[:n]


# ------------------------------------------------------------ embedded vectors
# See the module docstring for provenance.  SHAKE entries are 64-byte XOF prefixes.
MSG_EMPTY = b''
MSG_ABC = b'abc'
MSG_A3 = b'\xa3' * 200          # the NIST 1600-bit example message

VECTORS = {
    ('SHA3-224', 'empty'): '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
    ('SHA3-256', 'empty'): 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    ('SHA3-384', 'empty'): '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a'
                           'c3713831264adb47fb6bd1e058d5f004',
    ('SHA3-512', 'empty'): 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6'
                           '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
    ('SHAKE128', 'empty'): '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'
                           '3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2',
    ('SHAKE256', 'empty'): '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'
                           'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be',
    ('SHA3-224', 'abc'): 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
    ('SHA3-256', 'abc'): '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    ('SHA3-384', 'abc'): 'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2'
                         '98d88cea927ac7f539f1edf228376d25',
    ('SHA3-512', 'abc'): 'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e'
                         '10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
    ('SHAKE128', 'abc'): '5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8'
                         '44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378',
    ('SHAKE256', 'abc'): '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739'
                         'd5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4',
    ('SHA3-224', 'a3_200'): '9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0',
    ('SHA3-256', 'a3_200'): '79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787',
    ('SHA3-384', 'a3_200'): '1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd'
                            '76197a31fd55ee989f2d7050dd473e8f',
    ('SHA3-512', 'a3_200'): 'e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8'
                            '1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00',
    ('SHAKE128', 'a3_200'): '131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037'
                            'cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe343817197846',
    ('SHAKE256', 'a3_200'): 'cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d'
                            '2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b',
}
MSGS = {'empty': MSG_EMPTY, 'abc': MSG_ABC, 'a3_200': MSG_A3}


# ------------------------------------------------------ KLEE architectural state
# _State_ values: [[KLEE-state-off]], [[KLEE-states-valid]], [[KLEE-states-error]],
# [[KLEE-state-constants-symmetric]].
KL_STATE_UNCONFIGURED = 0
KL_STATE_READY = 1
KL_STATE_HASH_ABSORB = 2
KL_STATE_HASH_LAST_BLOCK = 3
KL_STATE_HASH_OUTPUT = 6
KL_STATE_SUCCESS = 46
KL_STATE_FAILURE = 47
KL_STATE_INVALID = 49
KL_CFG_PROVISIONING = 56
ERROR_STATES = range(48, 56)


class IllegalInstruction(Exception):
    """An illegal-instruction exception of Book 1."""


class NotModelled(Exception):
    """A case the specification leaves open; no check depends on it."""


def mdh_pack(machine, state):
    """[[KLEE-metadata-header]]: _Machine_ at [11:0], _State_ at [24:19]; every
    other field (policies, localities, ...) is zero in this harness."""
    return v2b(machine | (state << 19), 16)


def mdh_fields(mdh):
    v = b2v(mdh)
    return sl(v, 11, 0), sl(v, 24, 19)


def ceil128(nbits):
    return -(-nbits // 128) * 128


# Serialized Content of [[KLEE-SHA-3]]: (field, size in bits), in table order.
SERIALIZED_FIELDS = (('state', N_STATE), ('block_base', 16))
CONTENT1_BITS = ceil128(sum(w for _, w in SERIALIZED_FIELDS))   # implicit padding
CONTENT1_SIZE = CONTENT1_BITS // 8
PI_CONTENT_SIZE = 0                     # "The Provisioning Input contains only the MDH."


def kl_size(state):
    """[[KLEE-instruction-size]] for a SHA-3 MDH with AuxDataLen = 0."""
    if state == KL_STATE_UNCONFIGURED:
        return 16 + PI_CONTENT_SIZE     # a supplied MDH of a PI
    if state in ERROR_STATES:
        return 16
    if state == KL_CFG_PROVISIONING:
        return 16 + PI_CONTENT_SIZE
    assert 1 <= state <= 47
    return 32 + CONTENT1_SIZE


def make_pi(name):
    """Provisioning Input: the MDH (supplied with _State_ = _Unconfigured_) only."""
    return mdh_pack(MACHINE_CODE[name], KL_STATE_UNCONFIGURED) + bytes(PI_CONTENT_SIZE)


class Hart:
    """The hart-level KLEE CSR used here: klstart (a byte count)."""

    def __init__(self):
        self.klstart = 0


# ----------------------------------------------------------------- KLEE CL model
class KleeSha3CL:
    """A CL holding a KLEE SHA-3 CC, implemented literally from [[KLEE-SHA-3]] +
    [[KLEE-hash-functions]] + [[KLEE-process-VLI]] and the Book 1 rules.

    `state` is the 1600-bit KLEE value; for the SHA-3 family `block` is `state`
    (inputs are XORed directly into the rate, state_offset = 0), max_len = 0 (no
    maximum length enforced) and cumul_len = None, so process_VLI's per-iteration
    amount is min(KLLEN - input_base, b - block_base).
    """

    def __init__(self, hart):
        self.hart = hart
        self.machine = 0
        self.st = KL_STATE_UNCONFIGURED     # MDH _State_
        self.name = None
        self.state = 0                      # Internal State: `state`, n bits
        self.block_base = 0                 # Internal State: `block_base`, bits
        self.pad_case = None                # instrumentation: padding clause fired
        self.wrong_suffix = False           # negative-control hook

    # ---------------------------------------------------------- configuration
    def _set_machine(self, machine):
        name = MACHINE_NAME[machine]
        c, b, t, xof, D = PARAMS[name]
        self.machine, self.name = machine, name
        self.b, self.t, self.xof, self.D = b, t, xof, D

    def provision(self, pi):
        """kl.mgmt (provisioning) + transfer of the PI + completing kl.mgmt."""
        machine, st = mdh_fields(pi[:16])
        assert st == KL_STATE_UNCONFIGURED   # [[KLEE-Metadata-validity]]
        self._set_machine(machine)
        assert len(pi) == 16 + PI_CONTENT_SIZE
        self._enter_ready()                  # provisioning completes in _Ready_ only

    def export_content(self, order_by_at=False):
        """Serialized Content, fields in table order from bit 0 upwards, zero
        padded to CONTENT1_BITS.  order_by_at=True is a NEGATIVE CONTROL: the
        fields concatenated with `@` (first field most significant)."""
        if order_by_at:
            v = cat((self.state, N_STATE), (self.block_base, 16))
        else:
            v = self.state | (self.block_base << N_STATE)
        return v2b(v, CONTENT1_SIZE)

    def import_scc(self, mdh, content):
        """Completing an import: the MDH _State_ and the Serialized Content are
        restored; `input_base` is not serialized."""
        machine, st = mdh_fields(mdh)
        self._set_machine(machine)
        assert len(content) == CONTENT1_SIZE
        v = b2v(content)
        self.state = sl(v, N_STATE - 1, 0)           # pos. i
        self.block_base = sl(v, N_STATE + 15, N_STATE)   # pos. ii
        self.st = st
        if self.block_base >= self.b:
            # An image whose `block_base` is not a position within a block is
            # inconsistent Content; the specification defines no behaviour for
            # it, and the harness invalidates the CL (only the negative control
            # below produces such an image).
            self._invalidate()

    def mdh(self):
        return mdh_pack(self.machine, self.st)

    def clear(self):                         # kl.clear
        self.__init__(self.hart)

    def _clear_content(self):                # SGR10
        self.state = 0
        self.block_base = 0

    def _invalidate(self):
        self.st = KL_STATE_INVALID
        self._clear_content()
        return 'invalid'

    # ----------------------------------------------------------------- States
    def _enter_ready(self):
        # [[KLEE-hash-functions]]: last_blk_len, block_base, cumul_len and block
        # are set to zero (only block_base exists here); [[KLEE-SHA-3]]: `state`
        # is zeroed.
        self.st = KL_STATE_READY
        self.state = 0
        self.block_base = 0

    def _enter_output(self):
        # [[KLEE-process-VLI]]: finalize = None, so nothing is done on leaving
        # _Hash_Absorb_.  [[KLEE-SHA-3]], "Upon transitioning to State
        # _Hash_Output_": S = D || pad10*1, the smallest |S| >= |D| + 2 making
        # block_base + |S| a positive multiple of b.
        b, D = self.b, self.D
        room = b - self.block_base
        S_len = room if room >= len(D) + 2 else room + b
        S = sum(bit << j for j, bit in enumerate(D))
        S |= 1 << len(D)                     # pad10*1 leading 1
        if self.wrong_suffix:
            # NEGATIVE CONTROL: the suffix byte (0x06 / 0x1F) written MSB-aligned,
            # i.e. bit-reversed within its byte, violating the FIPS 202 h2b /
            # KLEE little-endian bit order.
            first = int('{:08b}'.format(S & 0xFF)[::-1], 2)
            S = (S & ~0xFF) | first
        S |= 1 << (S_len - 1)                # pad10*1 final 1
        if S_len == room:                    # |S| = b - block_base
            self.pad_case = 1
            self.state ^= S << self.block_base
            self.state = keccak_f1600(self.state)
        else:                                # |S| = 2b - block_base
            self.pad_case = 2
            self.state ^= (S & ((1 << room) - 1)) << self.block_base
            self.state = keccak_f1600(self.state)
            self.state ^= S >> room          # the remaining b bits, at rate bit 0
            self.state = keccak_f1600(self.state)
        # [[KLEE-hash-functions]], upon entering _Hash_Output_:
        # block[t-1:0] <- finalize(): block is `state`, whose bits [t-1:0] already
        # hold the output after the padding step, so this is the identity;
        # block_base <- 0.
        self.block_base = 0
        self.st = KL_STATE_HASH_OUTPUT

    # --------------------------------------------------------------- kl.setst
    def setst(self, immed, form='A', aux=None):
        if immed == KL_STATE_UNCONFIGURED:           # kl.clear
            self.clear()
            return 'cleared'
        if immed in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            raise IllegalInstruction('SGR7: immediates 46 and 47 are reserved')
        if immed in ERROR_STATES:                    # a configuration instruction (SGR20)
            if self.st == KL_STATE_UNCONFIGURED:
                return 'noop'
            self.st = KL_STATE_INVALID if immed >= 54 else immed
            self._clear_content()
            return 'error-state'
        if self.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction('SGR12')
        if self.st in ERROR_STATES:                  # SGR15, SGR16
            return 'noop'
        if immed == KL_STATE_READY:                  # SGR8 (and SGR6 in _Success_)
            self._enter_ready()
            return 'ok'
        if self.st == KL_STATE_SUCCESS:              # SGR5, SGR6
            return self._invalidate()
        if immed == KL_STATE_HASH_ABSORB:
            # [[KLEE-process-VLI]]: max_len is set by the Machine, so the entering
            # kl.setst must be of Form A; transitioning to the same State
            # _Current_State_ invalidates the CL.
            if self.st == KL_STATE_READY and form == 'A':
                self.st = KL_STATE_HASH_ABSORB
                return 'ok'
            return self._invalidate()
        if immed == KL_STATE_HASH_OUTPUT:
            if self.st == KL_STATE_HASH_OUTPUT:
                raise NotModelled('same-State kl.setst in _Hash_Output_ (SGR4)')
            if self.st == KL_STATE_HASH_ABSORB and form == 'A':
                self._enter_output()
                return 'ok'
            return self._invalidate()                # e.g. _Ready_ -> _Hash_Output_
        # kl_state_hash_last_block and any other Machine State: SHA-3 has no
        # _Hash_Absorb_Last_Block_ (AGR1).
        return self._invalidate()

    # ---------------------------------------------------------------- kl.exec
    def _zero_window(self, out):
        """IRR6 / SGR16 / [[KLEE-instruction-exec]]: the unwritten part of the
        output window, bytes [klstart, top), is zeroed."""
        if out is not None:
            k = min(self.hart.klstart, len(out))
            out[k:] = bytes(len(out) - k)

    def _retire(self, status):
        self.hart.klstart = 0                        # [[KLEE-CSR-klstart]]
        return status

    def _invalid_exec(self, out):
        self._invalidate()
        self._zero_window(out)
        return self._retire('invalid')

    def exec_(self, form, inp=None, out=None, sew=None, interrupt_at=None,
              end_halt=False, literal_units=False):
        """kl.exec.  `inp` is the input transfer window (bytes [0, KLLEN/8)), `out`
        the output window (a bytearray).  `sew` is the element width of a vector
        operand (None for the KLIOBUF of a Form D substitution).  The instruction
        halts at the first interruption point p >= interrupt_at (bytes); an
        interruption point at the end of the window is used only if end_halt.
        Returns 'done', 'success', 'interrupted', 'noop' or 'invalid'."""
        if self.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction('SGR12')
        if self.st in ERROR_STATES:                  # SGR16: no operation
            self._zero_window(out)
            return self._retire('noop')
        if self.st == KL_STATE_HASH_ABSORB:
            if form not in ('B', 'D') or inp is None or out is not None:
                return self._invalid_exec(out)       # AGR1: only Form B expected
            if sew is not None:
                assert (8 * len(inp)) % sew == 0     # KLLEN = VL * SEW
                if sew < GRANULARITY:
                    return self._invalid_exec(out)   # AGR2
            return self._absorb(inp, interrupt_at, end_halt, literal_units)
        if self.st == KL_STATE_HASH_OUTPUT:
            if form not in ('C', 'D') or inp is not None or out is None:
                return self._invalid_exec(out)       # AGR1: only Form C expected
            return self._squeeze(out, interrupt_at, end_halt)
        # _Ready_ (SGR2) and _Success_ (SGR5: a SHA3-n does not produce
        # arbitrarily long output; SHAKE never reaches _Success_).
        return self._invalid_exec(out)

    # [[KLEE-CSR-klstart]]: "an interruption point ... is a klstart value that the
    # Machine can itself produce on a precise halt in that State".  A CL can only
    # test what its own state implies: process_VLI yields after every iteration,
    # and an iteration that ends before the end of the window ends on a block
    # boundary, after process_block() and block_base <- 0.
    def _absorb_point_ok(self, p, top):
        if p == 0 or p == top:
            return True
        if p > top:
            return False
        return self.block_base == 0

    def _vli(self, INPUT, KLLEN, input_base, interrupt_at, end_halt, literal_units):
        """The loop of [[KLEE-process-VLI]] with the SHA-3 arguments."""
        while input_base < KLLEN:
            # max_len = 0
            amount = min(KLLEN - input_base, self.b - self.block_base)
            # mode = xor_accumulate, state_offset = 0
            self.state ^= (sl(INPUT, input_base + amount - 1, input_base)
                           << (self.block_base + STATE_OFFSET))
            input_base += amount
            self.block_base += amount
            # max_len = 0: cumul_len is not updated (it is None)
            if self.block_base == self.b:
                self.state = keccak_f1600(self.state)     # process_block() = P()
                self.block_base = 0
            # max_len = 0: no termination step.
            # "Here, and only here, the instruction may be interrupted, with
            # klstart <- input_base / 8."
            if (interrupt_at is not None and input_base // 8 >= interrupt_at
                    and (input_base < KLLEN or end_halt)):
                # literal_units: NEGATIVE CONTROL, klstart as a bit count
                self.hart.klstart = input_base if literal_units else input_base // 8
                return 'interrupted'
        return 'done'

    def _absorb(self, inp, interrupt_at, end_halt, literal_units):
        top = len(inp)
        p = self.hart.klstart
        if not self._absorb_point_ok(p, top):        # input operand: _Invalid_
            return self._invalid_exec(None)
        if p >= top:                                 # empty transfer window
            return self._retire('noop')
        # "If starting ... input_base <- 0; if resuming ... input_base <- 8 * klstart"
        st = self._vli(b2v(inp), 8 * top, 8 * p, interrupt_at, end_halt,
                       literal_units)
        return st if st == 'interrupted' else self._retire(st)

    def absorb_bits(self, val, nbits):
        """Bit-granular absorption through the same process_VLI loop.

        process_VLI is defined in bits; only the kl.exec transfer interface
        restricts amounts to whole bytes.  This entry point exercises the
        bit-level generality (needed to reach the two-block padding clause)
        and is NOT reachable through architecturally legal kl.exec transfers.
        """
        assert self.st == KL_STATE_HASH_ABSORB, self.st
        self._vli(val & ((1 << nbits) - 1), nbits, 0, None, False, False)

    def _squeeze_point_ok(self, p, top):
        # Hash_Output yields only after update() and block_base <- 0, which a
        # fixed-output function never performs (it enters _Success_ instead).
        if p == 0:
            return True
        if not self.xof or p > top:
            return False
        return self.block_base == 0

    def _squeeze(self, out, interrupt_at, end_halt):
        top = len(out)
        p = self.hart.klstart
        if not self._squeeze_point_ok(p, top) or p >= top:
            # output-only operand: no operation (interruption-point check, then
            # the empty-window rule)
            self._zero_window(out)
            return self._retire('noop')
        KLLEN, t = 8 * top, self.t
        OUT = b2v(out)
        # output_base <- 0 // upon resumption, output_base <- 8 * klstart
        output_base = 8 * p
        while output_base < KLLEN:
            amount = min(KLLEN - output_base, t - self.block_base)
            chunk = sl(self.state, self.block_base + amount - 1, self.block_base)
            OUT = ((OUT & ~(((1 << amount) - 1) << output_base))
                   | (chunk << output_base))
            output_base += amount
            self.block_base += amount
            if self.block_base == t:
                if not self.xof:
                    # "any bits of OUTPUT beyond output_base are cleared, the
                    # state transitions to _Success_, and the instruction returns"
                    OUT &= (1 << output_base) - 1
                    out[:] = v2b(OUT, top)
                    self.st = KL_STATE_SUCCESS
                    return self._retire('success')
                self.state = keccak_f1600(self.state)     # update() = P()
                self.block_base = 0
                # "Here the instruction can be interrupted, with
                # klstart <- output_base / 8."
                if (interrupt_at is not None and output_base // 8 >= interrupt_at
                        and (output_base < KLLEN or end_halt)):
                    out[:] = v2b(OUT, top)
                    self.hart.klstart = output_base // 8
                    return 'interrupted'
        out[:] = v2b(OUT, top)
        return self._retire('done')


# --------------------------------------------------------------------- kl.derive
def kl_derive(hart, dst, src, length, interrupt_at=None):
    """kl.derive Kd, Ks, Xs2 (Xs2 = length) between two SHA-3-family CLs, whose
    only endpoints are the `kl.exec` ones (index 0) of [[KLEE-derive-endpoints]]:
    the output of _Hash_Output_ and the input of _Hash_Absorb_."""
    if dst is src:
        raise IllegalInstruction('source and destination must differ')
    for cl in (src, dst):                            # SGR19, source first
        if cl.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction('SGR12')
    if src.st in ERROR_STATES or dst.st in ERROR_STATES:
        hart.klstart = 0
        return 'noop'
    # Check 1: the State of each CL must admit its endpoint.  A SHA3-n in
    # _Success_ admits no kl.exec (SGR5); a CL in _Success_ or _Failure_ is never
    # a destination.
    src_ok = src.st == KL_STATE_HASH_OUTPUT
    dst_ok = dst.st == KL_STATE_HASH_ABSORB
    if not (src_ok and dst_ok):
        if not src_ok:
            src._invalidate()
        if not dst_ok:
            dst._invalidate()
        hart.klstart = 0
        return 'invalid'
    if length == 0:                                  # transfers nothing
        hart.klstart = 0
        return 'done'
    if not src.xof and 8 * length > src.t - src.block_base:
        raise NotModelled('a fixed-output source asked for more than its digest')
    pos = hart.klstart
    if pos != 0 and not (0 < pos < length and src.block_base == 0
                         and dst.block_base == 0):
        raise NotModelled('kl.derive resumed at a klstart the harness does not test')
    while pos < length:
        amount = min(length - pos, (src.t - src.block_base) // 8,
                     (dst.b - dst.block_base) // 8)
        bits = 8 * amount
        chunk = sl(src.state, src.block_base + bits - 1, src.block_base)
        src.block_base += bits                       # as a Form C kl.exec would
        dst.state ^= chunk << dst.block_base         # as a Form B kl.exec would
        dst.block_base += bits
        pos += amount
        dst_point = src_point = False
        if dst.block_base == dst.b:
            dst.state = keccak_f1600(dst.state)
            dst.block_base = 0
            dst_point = True
        if src.block_base == src.t:
            if not src.xof:
                src.st = KL_STATE_SUCCESS            # the digest has been made available
            else:
                src.state = keccak_f1600(src.state)
                src.block_base = 0
                src_point = True
        # "The interruption points of a kl.derive are the klstart values that are
        # interruption points of both endpoints, each in its current State."
        if (interrupt_at is not None and pos >= interrupt_at and pos < length
                and src_point and dst_point):
            hart.klstart = pos
            return 'interrupted'
    hart.klstart = 0
    return 'done'


# ------------------------------------------------------------------- reporting
_n_pass = 0
_n_fail = 0
_controls_ok = True


def check(label, got, want):
    global _n_pass, _n_fail
    ok = got == want
    if ok:
        _n_pass += 1
        print('PASS  %s' % label)
    else:
        _n_fail += 1
        print('FAIL  %s' % label)
        print('        got  %s' % (got.hex() if isinstance(got, (bytes, bytearray)) else got))
        print('        want %s' % (want.hex() if isinstance(want, (bytes, bytearray)) else want))
    return ok


def check_true(label, cond, detail=''):
    global _n_pass, _n_fail
    if cond:
        _n_pass += 1
        print('PASS  %s' % label)
    else:
        _n_fail += 1
        print('FAIL  %s  %s' % (label, detail))
    return cond


def negative_control(label, mismatched):
    """A wrong formulation must NOT reproduce the standard result."""
    global _controls_ok, _n_pass
    if mismatched:
        _n_pass += 1
        print('FAIL  %s -- wrong formulation mismatches the standard, as it must '
              '(expected)' % label)
    else:
        _controls_ok = False
        print('ERROR %s -- negative control did not fire: the wrong formulation '
              'REPRODUCED the standard result' % label)


def _notice(tag, lines):
    print('%s: %s' % (tag, lines[0]))
    for ln in lines[1:]:
        print(' ' * (len(tag) + 2) + ln)


def info(*lines):
    _notice('INFO', lines)


def spec_note(*lines):
    _notice('SPEC-NOTE', lines)


# ------------------------------------------------------------------ test drive
def new_cl(name, hart=None):
    cl = KleeSha3CL(hart if hart is not None else Hart())
    cl.provision(make_pi(name))
    return cl


def absorbing_cl(name, msg=b'', hart=None):
    cl = new_cl(name, hart)
    cl.setst(KL_STATE_HASH_ABSORB)
    if msg:
        assert cl.exec_('B', inp=msg) == 'done'
    return cl


def squeezing_cl(name, msg, hart=None):
    cl = absorbing_cl(name, msg, hart)
    cl.setst(KL_STATE_HASH_OUTPUT)
    return cl


def kl_hash_oneshot(name, msg, out_bytes=None, chunks=None, interrupt=None,
                    wrong_suffix=False, literal_units=False, forms=('B', 'C')):
    """Run the full KLEE state machine: provision, absorb (optionally
    chunked/interrupted and resumed), pad, squeeze out_bytes (default t/8) in one
    exec.  Returns (output window, cl)."""
    cl = new_cl(name)
    cl.wrong_suffix = wrong_suffix
    cl.setst(KL_STATE_HASH_ABSORB)
    for i, ch in enumerate(chunks if chunks is not None else [msg]):
        intr = interrupt[1] if (interrupt is not None and interrupt[0] == i) else None
        st = cl.exec_(forms[0], inp=ch, interrupt_at=intr,
                      literal_units=literal_units)
        if st == 'interrupted':
            cl.exec_(forms[0], inp=ch)               # re-execution resumes at klstart
    cl.setst(KL_STATE_HASH_OUTPUT)
    n = out_bytes if out_bytes is not None else PARAMS[name][2] // 8
    out = bytearray(n)
    cl.exec_(forms[1], out=out)
    return bytes(out), cl


def main():
    print('== shake-kat: KLEE SHA-3 family Machines vs FIPS 202 ==')
    print()
    print('-- 1. reference sponge vs embedded FIPS 202 vectors and hashlib oracle --')
    for name in PARAMS:
        for mid, msg in MSGS.items():
            want = bytes.fromhex(VECTORS[(name, mid)])
            got = ref_hash(name, msg, len(want))
            check('reference  %-8s %-6s' % (name, mid), got, want)
            check('[oracle]   %-8s %-6s (hashlib vs embedded)' % (name, mid),
                  oracle(name, msg, len(want)), want)

    print()
    print('-- 2. parameter table [[KLEE-SHA-3-parameters]] and the SHA-3 '
          'process_VLI invocation --')
    for name, (c, b, t, xof, D) in PARAMS.items():
        check_true('%-8s b = 1600 - c, t = %s, state_offset + b <= n'
                   % (name, 'b (XOF)' if xof else 'c/2'),
                   b == N_STATE - c and t == (b if xof else c // 2)
                   and STATE_OFFSET + b <= N_STATE and b % 8 == 0)
        check_true('%-8s _Machine_ = Type 6, Mode %d, round-trips through the MDH'
                   % (name, MACHINE_TYPE_MODE[name][1]),
                   mdh_fields(make_pi(name))[0] == (6 << 4) | MACHINE_TYPE_MODE[name][1]
                   and new_cl(name).name == name)

    print()
    print('-- 3. KLEE model, single-exec absorption --')
    for name in PARAMS:
        for mid, msg in MSGS.items():
            want = bytes.fromhex(VECTORS[(name, mid)])
            got, cl = kl_hash_oneshot(name, msg, out_bytes=len(want))
            check('KLEE model  %-8s %-6s' % (name, mid), got, want)
            if not PARAMS[name][3]:
                check_true('KLEE model  %-8s %-6s reached _Success_' % (name, mid),
                           cl.st == KL_STATE_SUCCESS, 'state=%s' % cl.st)
    got, _ = kl_hash_oneshot('SHA3-256', MSG_A3, forms=('D', 'D'))
    check('Form D (KLIOBUF substitution) for Forms B and C, SHA3-256 a3_200',
          got, bytes.fromhex(VECTORS[('SHA3-256', 'a3_200')]))
    info('granularity 32 is read as [[KLEE-SHA-3]] states it: the smallest vector '
         'element width, not a',
         'constraint on the message length.  Transfers whose length is not a '
         'multiple of 32 bits are modelled as',
         'KLIOBUF (Form D) transfers; only the last transfer of a sequence has such '
         'a length ([[KLEE-process-VLI]]).')

    print()
    print('-- 4. chunked absorption through process_VLI '
          '(granularity 32 bits, partial-block boundaries) --')
    # SHAKE128 (rate 168 B): transfers 68+4+100+28 = 200 B; the 100-B transfer
    # crosses the 168-B block boundary mid-transfer.
    got, _ = kl_hash_oneshot('SHAKE128', MSG_A3, out_bytes=64,
                             chunks=[MSG_A3[:68], MSG_A3[68:72],
                                     MSG_A3[72:172], MSG_A3[172:]])
    check('KLEE chunked SHAKE128 a3_200 (68+4+100+28 B transfers)',
          got, bytes.fromhex(VECTORS[('SHAKE128', 'a3_200')]))
    # SHA3-512 (rate 72 B): 12+60 hits the block boundary exactly at a transfer
    # edge; 100 crosses it mid-transfer; tail 28.
    got, _ = kl_hash_oneshot('SHA3-512', MSG_A3,
                             chunks=[MSG_A3[:12], MSG_A3[12:72],
                                     MSG_A3[72:172], MSG_A3[172:]])
    check('KLEE chunked SHA3-512 a3_200 (12+60+100+28 B transfers)',
          got, bytes.fromhex(VECTORS[('SHA3-512', 'a3_200')]))
    # AGR2: a vector input whose element width is below the granularity.
    cl = absorbing_cl('SHA3-256')
    st = cl.exec_('B', inp=MSG_A3[:16], sew=16)
    check_true('SHA3-256 Form B with SEW = 16 < granularity 32 -> _Invalid_ (AGR2)',
               st == 'invalid' and cl.st == KL_STATE_INVALID, (st, cl.st))
    cl = absorbing_cl('SHA3-256')
    check_true('SHA3-256 Form B with SEW = 32 and SEW = 64 accepted',
               cl.exec_('B', inp=MSG_A3[:8], sew=32) == 'done'
               and cl.exec_('B', inp=MSG_A3[8:24], sew=64) == 'done'
               and cl.block_base == 8 * 24)

    print()
    print('-- 5. interrupted/resumed absorption (klstart in bytes) --')
    # SHA3-256 (rate 136 B), one 200-B exec interrupted at the interruption point
    # after the first full block (input_base = 136 B).
    hart = Hart()
    cl = absorbing_cl('SHA3-256', hart=hart)
    st = cl.exec_('B', inp=MSG_A3, interrupt_at=100)
    check_true('SHA3-256 absorb interrupted at the process_VLI interruption point',
               st == 'interrupted', st)
    check_true('klstart = input_base / 8 = 136 (after the 136-B block)',
               hart.klstart == 136, 'klstart=%r' % hart.klstart)
    st = cl.exec_('B', inp=MSG_A3)                   # input_base <- 8 * klstart
    check_true('resumed exec completes and retires with klstart = 0',
               st == 'done' and hart.klstart == 0, (st, hart.klstart))
    cl.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(32)
    cl.exec_('C', out=out)
    check('SHA3-256 a3_200 digest after interrupt/resume', bytes(out),
          bytes.fromhex(VECTORS[('SHA3-256', 'a3_200')]))
    # Context switch between halt and resumption: export, clear, import into
    # another CL, restore klstart, re-execute.  input_base is not serialized.
    hart = Hart()
    cl = absorbing_cl('SHA3-384', hart=hart)
    cl.exec_('B', inp=MSG_A3[:12])
    st = cl.exec_('B', inp=MSG_A3[12:], interrupt_at=1)   # halts at 104 - 12 = 92
    saved = (cl.mdh(), cl.export_content(), hart.klstart)
    cl.setst(KL_STATE_UNCONFIGURED)
    hart.klstart = 0                                 # other software runs
    cl2 = KleeSha3CL(hart)
    cl2.import_scc(saved[0], saved[1])
    hart.klstart = saved[2]
    st2 = cl2.exec_('B', inp=MSG_A3[12:])
    cl2.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(48)
    cl2.exec_('C', out=out)
    check_true('SHA3-384 halt at klstart = 92 (block boundary after a 12-B transfer)',
               st == 'interrupted' and saved[2] == 92, (st, saved[2]))
    check('SHA3-384 a3_200 after halt, export, clear, import and resumption',
          bytes(out), bytes.fromhex(VECTORS[('SHA3-384', 'a3_200')]))
    # A halt after the last iteration: klstart = KLLEN/8, the re-executed
    # instruction has an empty window and performs no operation.
    hart = Hart()
    cl = absorbing_cl('SHA3-256', hart=hart)
    st = cl.exec_('B', inp=MSG_A3[:136], interrupt_at=136, end_halt=True)
    snap = (cl.state, cl.block_base)
    st2 = cl.exec_('B', inp=MSG_A3[:136])
    check_true('halt at the end of the window (klstart = 136 = KLLEN/8); '
               're-execution is a no-op that retires',
               st == 'interrupted' and st2 == 'noop' and hart.klstart == 0
               and (cl.state, cl.block_base) == snap, (st, st2, hart.klstart))
    cl.exec_('B', inp=MSG_A3[136:])
    cl.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(32)
    cl.exec_('C', out=out)
    check('SHA3-256 a3_200 digest after the end-of-window halt', bytes(out),
          bytes.fromhex(VECTORS[('SHA3-256', 'a3_200')]))
    # A klstart that the Machine cannot have produced, on an input operand.
    hart = Hart()
    cl = absorbing_cl('SHA3-256', MSG_A3[:4], hart=hart)
    hart.klstart = 100
    st = cl.exec_('B', inp=MSG_A3)
    check_true('input operand, klstart = 100 with block_base = 32 (no interruption '
               'point) -> _Invalid_, klstart = 0',
               st == 'invalid' and cl.st == KL_STATE_INVALID and hart.klstart == 0,
               (st, cl.st, hart.klstart))
    check_true('the invalidated CL retains only its MDH (SGR10)',
               cl.state == 0 and cl.block_base == 0)
    hart.klstart = 0
    check_true('a later kl.setst on the Error State CL is a no-op (SGR16)',
               cl.setst(KL_STATE_HASH_OUTPUT) == 'noop' and cl.st == KL_STATE_INVALID)
    out = bytearray(b'\xee' * 32)
    st = cl.exec_('C', out=out)
    check_true('a later Form C kl.exec is a no-op that zeroes its output window '
               '(SGR16)', st == 'noop' and out == bytearray(32)
               and cl.st == KL_STATE_INVALID, (st, cl.st))
    info('interruption points: a CL can only test what its own state implies -- 0, '
         'the end of the window, or,',
         'with block_base = 0, an interior value.  The harness exercises only '
         'values that fail that test.')

    print()
    print('-- 6. suffix-and-padding S = D || pad10*1 --')
    pat = bytes((7 * i + 3) & 0xFF for i in range(256))
    # (a) one-block clause, tightest byte-aligned case: rate-minus-1-byte message,
    #     |S| = 8 bits (whole suffix + both pad bits inside the final byte).
    for name in PARAMS:
        c, b, t, xof, D = PARAMS[name]
        msg = pat[:b // 8 - 1]
        n = min(32, t // 8)
        got, cl = kl_hash_oneshot(name, msg, out_bytes=n)
        check('[oracle] %-8s rate-1-byte msg (%3d B), one-block padding'
              % (name, len(msg)), got, oracle(name, msg, n))
        check_true('%-8s padding clause 1 fired (|S| = b - block_base = 8)'
                   % name, cl.pad_case == 1, 'case=%r' % cl.pad_case)
    # (b) rate-exact message: block_base = 0 at the transition, |S| = b
    #     ("positive multiple of b" -> a full padding block).
    for name in ('SHAKE128', 'SHA3-512'):
        c, b, t, xof, D = PARAMS[name]
        msg = pat[:b // 8]
        got, cl = kl_hash_oneshot(name, msg, out_bytes=32)
        check('[oracle] %-8s rate-exact msg (%3d B), full padding block'
              % (name, len(msg)), got, oracle(name, msg, 32))
        check_true('%-8s padding clause 1 fired (|S| = b, block_base = 0)'
                   % name, cl.pad_case == 1, 'case=%r' % cl.pad_case)
    # (c) two-block spill clause (|S| = 2b - block_base).  Only reachable with a
    #     bit-granular block_base: kl.exec transfers whole bytes, so
    #     b - block_base >= 8 > |D| + 2 always, and the clause is dead code at
    #     the architectural interface.  Exercised here through the bit-level
    #     definition of process_VLI; anchor is model-vs-reference (hashlib
    #     cannot do bit strings).
    info('the two-block padding clause of [[KLEE-SHA-3]] requires b - block_base < '
         '|D| + 2 <= 6, while block_base is',
         'always a multiple of 8 (Units paragraph of [[KLEE-process-VLI]]); the '
         'clause is reachable only at the bit',
         'level of process_VLI, which is how it is exercised here.')
    for name, nbits in (('SHAKE128', 1342), ('SHA3-256', 1085), ('SHA3-512', 573)):
        c, b, t, xof, D = PARAMS[name]
        assert (b - nbits % b) < len(D) + 2
        val = b2v(pat[: (nbits + 7) // 8]) & ((1 << nbits) - 1)
        cl = absorbing_cl(name)
        cl.absorb_bits(val, nbits)
        cl.setst(KL_STATE_HASH_OUTPUT)
        out = bytearray(32)
        cl.exec_('C', out=out)
        check('%-8s %4d-bit msg, two-block padding spill vs bit-level reference'
              % (name, nbits), bytes(out), ref_sponge(b, val, nbits, D, 32))
        check_true('%-8s padding clause 2 fired (|S| = 2b - block_base = %d)'
                   % (name, 2 * b - nbits % b), cl.pad_case == 2,
                   'case=%r' % cl.pad_case)
    # (d) boundary of clause 1: block_base = b - (|D| + 2) exactly.
    name, nbits = 'SHA3-256', 1084          # b - block_base = 4 = |D| + 2
    c, b, t, xof, D = PARAMS[name]
    val = b2v(pat[: (nbits + 7) // 8]) & ((1 << nbits) - 1)
    cl = absorbing_cl(name)
    cl.absorb_bits(val, nbits)
    cl.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(32)
    cl.exec_('C', out=out)
    check('SHA3-256 1084-bit msg, minimal one-block padding (|S| = |D| + 2)',
          bytes(out), ref_sponge(b, val, nbits, D, 32))
    check_true('SHA3-256 padding clause 1 fired at its boundary',
               cl.pad_case == 1, 'case=%r' % cl.pad_case)

    print()
    print('-- 7. _Hash_Output_ squeezing (XOFs) --')
    # (a) one long exec vs the oracle stream.
    stream = oracle('SHAKE128', MSG_ABC, 512)
    check_true('[oracle] SHAKE128 abc stream prefix matches embedded vector',
               stream[:64] == bytes.fromhex(VECTORS[('SHAKE128', 'abc')]))
    got, cl = kl_hash_oneshot('SHAKE128', MSG_ABC, out_bytes=512)
    check('[oracle] SHAKE128 abc 512-B squeeze, single exec', got, stream)
    check_true('SHAKE128 stays in _Hash_Output_ (XOFs never reach _Success_)',
               cl.st == KL_STATE_HASH_OUTPUT, cl.st)
    # (b) the same 512 bytes across several Form C execs (block_base persists).
    cl = squeezing_cl('SHAKE128', MSG_ABC)
    parts = []
    for n in (100, 68, 200, 144):
        out = bytearray(n)
        st = cl.exec_('C', out=out)
        assert st == 'done', st
        parts.append(bytes(out))
    check('[oracle] SHAKE128 abc 512-B squeeze across execs of 100+68+200+144 B',
          b''.join(parts), stream)
    check_true('SHAKE128 still in _Hash_Output_ after multi-exec squeeze',
               cl.st == KL_STATE_HASH_OUTPUT, cl.st)
    # (c) interrupted/resumed squeeze: klstart = output_base / 8; bytes beyond
    #     the halt are not written by the halted attempt.
    hart = Hart()
    cl = squeezing_cl('SHAKE128', MSG_ABC, hart=hart)
    out = bytearray(b'\xee' * 400)
    st = cl.exec_('C', out=out, interrupt_at=1)
    check_true('SHAKE128 squeeze interrupted at the first interruption point',
               st == 'interrupted', st)
    check_true('klstart = output_base/8 = 168 (t bits = one rate)',
               hart.klstart == 168, 'klstart=%r' % hart.klstart)
    check_true('the halted attempt left bytes [168, 400) unwritten (IRR6)',
               out[168:] == bytearray(b'\xee' * 232))
    st = cl.exec_('C', out=out)
    check_true('resumed squeeze completes and retires with klstart = 0',
               st == 'done' and hart.klstart == 0, (st, hart.klstart))
    check('[oracle] SHAKE128 abc 400-B squeeze with interrupt/resume',
          bytes(out), oracle('SHAKE128', MSG_ABC, 400))
    # (d) SHAKE256 multi-exec squeeze on the long message.
    cl = squeezing_cl('SHAKE256', MSG_A3)
    parts = []
    for n in (64, 8, 264):
        out = bytearray(n)
        cl.exec_('C', out=out)
        parts.append(bytes(out))
    check('[oracle] SHAKE256 a3_200 336-B squeeze across execs of 64+8+264 B',
          b''.join(parts), oracle('SHAKE256', MSG_A3, 336))
    # (e) halt at the end of the window, then a no-op re-execution.
    hart = Hart()
    cl = squeezing_cl('SHAKE256', MSG_A3, hart=hart)
    out = bytearray(136)
    st = cl.exec_('C', out=out, interrupt_at=136, end_halt=True)
    kept = bytes(out)
    st2 = cl.exec_('C', out=out)
    out2 = bytearray(64)
    cl.exec_('C', out=out2)
    check_true('SHAKE256 halt at klstart = 136 = KLLEN/8; re-execution is a no-op '
               'leaving OUTPUT intact', st == 'interrupted' and st2 == 'noop'
               and bytes(out) == kept and hart.klstart == 0, (st, st2))
    check('[oracle] SHAKE256 stream continues at byte 136 after the no-op',
          kept + bytes(out2), oracle('SHAKE256', MSG_A3, 200))
    # (f) empty transfer window and a non-interruption point, output only.
    hart = Hart()
    cl = squeezing_cl('SHAKE128', MSG_ABC, hart=hart)
    out = bytearray(10)
    cl.exec_('C', out=out)                           # block_base = 80
    snap = (cl.st, cl.state, cl.block_base)
    hart.klstart = 64
    out = bytearray(b'\xee' * 64)
    st = cl.exec_('C', out=out)
    check_true('output only, klstart = 64 >= KLLEN/8 (empty window): no operation',
               st == 'noop' and (cl.st, cl.state, cl.block_base) == snap
               and out == bytearray(b'\xee' * 64) and hart.klstart == 0, st)
    hart.klstart = 5
    out = bytearray(b'\xee' * 64)
    st = cl.exec_('C', out=out)
    check_true('output only, klstart = 5 with block_base = 80 (no interruption '
               'point): no operation, CL unchanged',
               st == 'noop' and (cl.st, cl.state, cl.block_base) == snap
               and hart.klstart == 0, st)
    check_true('... and the output window [5, 64) is zeroed '
               '([[KLEE-instruction-exec]])',
               out == bytearray(b'\xee' * 5 + bytes(59)))
    out = bytearray(502)
    cl.exec_('C', out=out)
    check('[oracle] SHAKE128 abc stream intact after the two no-ops',
          bytes(out), stream[10:])
    spec_note('[[KLEE-instruction-exec]] zeroes the unwritten output window of a '
              'kl.exec that performs no operation, and',
              'SGR16 zeroes it for the no-operation cases it lists; '
              '[[KLEE-usage-input-output]] says instead that a KLIOBUF',
              'output substitution whose klstart is no interruption point performs '
              '"no operation: no state changes",',
              'and that "bytes of the window it does not write are unchanged".  The '
              'harness models a vector output',
              '(zeroed) and checks the CL itself, which both readings agree on.')

    print()
    print('-- 8. SHA3-n _Success_ transition after t bits --')
    # (a) digest split across two execs; _Success_ exactly at the t-th bit.
    cl = squeezing_cl('SHA3-256', MSG_ABC)
    d1 = bytearray(12)
    s1 = cl.exec_('C', out=d1)
    check_true('SHA3-256 12-B partial digest exec completes without _Success_',
               s1 == 'done' and cl.st == KL_STATE_HASH_OUTPUT, (s1, cl.st))
    d2 = bytearray(20)
    s2 = cl.exec_('C', out=d2)
    check_true('SHA3-256 reaches _Success_ at the t-th bit', s2 == 'success'
               and cl.st == KL_STATE_SUCCESS, (s2, cl.st))
    check('SHA3-256 abc digest split 12+20 B', bytes(d1 + d2),
          bytes.fromhex(VECTORS[('SHA3-256', 'abc')]))
    # (b) OUTPUT longer than the digest: the instruction returns at _Success_
    #     and the bits of OUTPUT beyond output_base are cleared.
    cl = squeezing_cl('SHA3-384', MSG_ABC)
    out = bytearray(b'\xee' * 64)
    s = cl.exec_('C', out=out)
    check_true('SHA3-384 64-B exec returns at _Success_, bytes [48, 64) cleared',
               s == 'success' and out[48:] == bytearray(16), (s, out[48:].hex()))
    check('SHA3-384 abc digest from oversized exec', bytes(out[:48]),
          bytes.fromhex(VECTORS[('SHA3-384', 'abc')]))
    # (c) a fixed-output function has no output interruption point.
    hart = Hart()
    cl = squeezing_cl('SHA3-512', MSG_ABC, hart=hart)
    hart.klstart = 4
    out = bytearray(64)
    st = cl.exec_('C', out=out)
    check_true('SHA3-512 Form C with klstart = 4: no operation, still in '
               '_Hash_Output_ at block_base 0', st == 'noop'
               and cl.st == KL_STATE_HASH_OUTPUT and cl.block_base == 0, st)
    st = cl.exec_('C', out=out)
    check('SHA3-512 abc digest after the no-op', bytes(out),
          bytes.fromhex(VECTORS[('SHA3-512', 'abc')]))
    # (d) in _Success_: kl.exec invalidates (SGR5); _Ready_ restarts the CC.
    cl = squeezing_cl('SHA3-256', MSG_ABC)
    cl.exec_('C', out=bytearray(32))
    out = bytearray(b'\xee' * 32)
    st = cl.exec_('C', out=out)
    check_true('SHA3-256 kl.exec in _Success_ -> _Invalid_, output window zeroed '
               '(SGR5, IRR6)', st == 'invalid' and cl.st == KL_STATE_INVALID
               and out == bytearray(32), (st, cl.st))
    cl = squeezing_cl('SHA3-256', MSG_EMPTY)
    cl.exec_('C', out=bytearray(32))
    ok = cl.setst(KL_STATE_READY) == 'ok' and cl.state == 0 and cl.block_base == 0
    cl.setst(KL_STATE_HASH_ABSORB)
    cl.exec_('B', inp=MSG_ABC)
    cl.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(32)
    cl.exec_('C', out=out)
    check_true('_Success_ -> _Ready_ (SGR6) zeroes state and block_base', ok)
    check('SHA3-256 abc digest from the CC reused after _Ready_', bytes(out),
          bytes.fromhex(VECTORS[('SHA3-256', 'abc')]))

    print()
    print('-- 9. States, transitions and expected Forms --')
    cases = []
    cl = new_cl('SHA3-256')
    cases.append(('kl.exec in _Ready_ -> _Invalid_ (SGR2)',
                  cl.exec_('B', inp=MSG_ABC) == 'invalid'))
    cl = new_cl('SHA3-256')
    cases.append(('_Ready_ -> _Hash_Output_ is not a listed transition -> _Invalid_',
                  cl.setst(KL_STATE_HASH_OUTPUT) == 'invalid'))
    cl = new_cl('SHA3-256')
    cases.append(('Form B kl.setst entering _Hash_Absorb_ -> _Invalid_ '
                  '(max_len is Machine-defined: Form A)',
                  cl.setst(KL_STATE_HASH_ABSORB, form='B', aux=64) == 'invalid'))
    cl = absorbing_cl('SHA3-256', MSG_ABC)
    cases.append(('same-State kl.setst in _Hash_Absorb_ -> _Invalid_ '
                  '([[KLEE-process-VLI]])',
                  cl.setst(KL_STATE_HASH_ABSORB) == 'invalid'))
    cl = absorbing_cl('SHA3-256', MSG_ABC)
    cases.append(('Form B kl.setst #kl_state_hash_last_block -> _Invalid_ '
                  '(no such State in SHA-3)',
                  cl.setst(KL_STATE_HASH_LAST_BLOCK, form='B', aux=8) == 'invalid'))
    cl = absorbing_cl('SHA3-256', MSG_ABC)
    cases.append(('Form C kl.exec in _Hash_Absorb_ -> _Invalid_ (AGR1)',
                  cl.exec_('C', out=bytearray(32)) == 'invalid'))
    cl = absorbing_cl('SHA3-256', MSG_ABC)
    cases.append(('Form A kl.exec in _Hash_Absorb_ -> _Invalid_ (AGR1)',
                  cl.exec_('A', inp=MSG_ABC + bytes(1),
                           out=bytearray(4)) == 'invalid'))
    cl = squeezing_cl('SHAKE256', MSG_ABC)
    cases.append(('Form B kl.exec in _Hash_Output_ -> _Invalid_ (AGR1)',
                  cl.exec_('B', inp=MSG_ABC) == 'invalid'))
    cl = squeezing_cl('SHAKE256', MSG_ABC)
    cases.append(('_Hash_Output_ -> _Hash_Absorb_ -> _Invalid_',
                  cl.setst(KL_STATE_HASH_ABSORB) == 'invalid'))
    cl = squeezing_cl('SHA3-224', MSG_ABC)
    cl.exec_('C', out=bytearray(28))
    cases.append(('_Success_ -> _Hash_Absorb_ -> _Invalid_ (SGR5, SGR6)',
                  cl.setst(KL_STATE_HASH_ABSORB) == 'invalid'))
    cl = squeezing_cl('SHA3-224', MSG_ABC)
    try:
        cl.setst(KL_STATE_SUCCESS)
        raised = False
    except IllegalInstruction:
        raised = True
    cases.append(('kl.setst #kl_state_success raises an illegal-instruction '
                  'exception (SGR7)', raised and cl.st == KL_STATE_HASH_OUTPUT))
    for label, ok in cases:
        check_true(label, ok)
    # from any valid State to _Ready_, then a correct digest
    for mid_state in ('Hash_Absorb', 'Hash_Output'):
        cl = absorbing_cl('SHAKE128', MSG_A3[:50])
        if mid_state == 'Hash_Output':
            cl.setst(KL_STATE_HASH_OUTPUT)
            cl.exec_('C', out=bytearray(20))
        cl.setst(KL_STATE_READY)
        cl.setst(KL_STATE_HASH_ABSORB)
        cl.exec_('B', inp=MSG_ABC)
        cl.setst(KL_STATE_HASH_OUTPUT)
        out = bytearray(64)
        cl.exec_('C', out=out)
        check('_%s_ -> _Ready_ restarts SHAKE128 (abc)' % mid_state, bytes(out),
              bytes.fromhex(VECTORS[('SHAKE128', 'abc')]))
    info('a same-State kl.setst in _Hash_Output_ is permitted by SGR4 and counts as '
         'a transition for AGR10, but',
         '[[KLEE-SHA-3]] does not say whether the padding step "upon transitioning to '
         '_Hash_Output_" is then',
         'repeated; the harness does not exercise it.  The Form of the kl.setst to '
         '_Hash_Output_ is not stated',
         'either: Form A (no auxiliary operand) is used.')

    print()
    print('-- 10. Provisioning Input and Serialized Content --')
    check_true('PI = MDH only: kl.size of a supplied PI MDH is 16 bytes',
               len(make_pi('SHA3-256')) == 16 and kl_size(KL_STATE_UNCONFIGURED) == 16)
    check_true('Serialized Content = 1600 + 16 bits, zero-padded to 1664 bits '
               '(208 bytes); kl.size of the SCC = 32 + 208',
               CONTENT1_BITS == 1664 and kl_size(KL_STATE_HASH_ABSORB) == 240
               and kl_size(KL_STATE_INVALID) == 16)
    cl = absorbing_cl('SHA3-256', MSG_A3[:100])
    content = cl.export_content()
    check_true('layout: bytes [0,200) = state, [200,202) = bin(block_base,16) = 800 '
               'bits, [202,208) = 0',
               len(content) == 208 and content[:200] == v2b(cl.state, 200)
               and content[200:202] == v2b(800, 2) and content[202:] == bytes(6))
    info('`block_base` is serialized in bits, the unit that [[KLEE-process-VLI]] '
         'defines for it; the table',
         'of [[KLEE-SHA-3]] gives no unit.')
    # round trips at various points, each resumed on a fresh CL
    trips = [
        ('SHA3-256 in _Hash_Absorb_ at block_base 800', 'SHA3-256', 100, None,
         bytes.fromhex(VECTORS[('SHA3-256', 'a3_200')])),
        ('SHA3-512 in _Hash_Absorb_ at block_base 0', 'SHA3-512', 144, None,
         bytes.fromhex(VECTORS[('SHA3-512', 'a3_200')])),
        ('SHA3-384 in _Hash_Output_ at block_base 160', 'SHA3-384', 200, 20,
         bytes.fromhex(VECTORS[('SHA3-384', 'a3_200')])),
        ('SHAKE128 in _Hash_Output_ at block_base 800', 'SHAKE128', 200, 100,
         oracle('SHAKE128', MSG_A3, 336)),
        ('SHAKE256 in _Hash_Output_ at block_base 0', 'SHAKE256', 200, 136,
         oracle('SHAKE256', MSG_A3, 336)),
    ]
    for label, name, n_abs, n_out, want in trips:
        cl = absorbing_cl(name, MSG_A3[:n_abs])
        head = b''
        if n_out is not None:
            cl.setst(KL_STATE_HASH_OUTPUT)
            o = bytearray(n_out)
            cl.exec_('C', out=o)
            head = bytes(o)
        mdh, content = cl.mdh(), cl.export_content()
        cl2 = KleeSha3CL(Hart())
        cl2.import_scc(mdh, content)
        if n_out is None:
            cl2.exec_('B', inp=MSG_A3[n_abs:])
            cl2.setst(KL_STATE_HASH_OUTPUT)
        o = bytearray(len(want) - len(head))
        cl2.exec_('C', out=o)
        check('export/import round trip, %s' % label, head + bytes(o), want)
    cl = KleeSha3CL(Hart())
    cl.import_scc(new_cl('SHAKE256').mdh(), new_cl('SHAKE256').export_content())
    cl.setst(KL_STATE_HASH_ABSORB)
    cl.exec_('B', inp=MSG_ABC)
    cl.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(64)
    cl.exec_('C', out=out)
    check('export/import round trip, SHAKE256 in _Ready_, then abc', bytes(out),
          bytes.fromhex(VECTORS[('SHAKE256', 'abc')]))

    print()
    print('-- 11. kl.derive between kl.exec endpoints ([[KLEE-derive-endpoints]]) --')
    info('[[KLEE-derive-endpoints]] is marked work in progress.  A source is '
         'modelled as advancing like the Form C',
         'kl.exec producing the transferred bytes, whose squeeze loop keeps the '
         'unused part of a block in',
         'block_base; the "unused part ... is discarded" reading differs only in '
         'the source position afterwards,',
         'so the source is continued only after derives that end on its block '
         'boundary.')
    # (a) SHAKE128 output -> SHA3-256 absorb; destination left open and
    #     continued, source continued.
    hart = Hart()
    src = squeezing_cl('SHAKE128', MSG_ABC, hart=hart)
    dst = absorbing_cl('SHA3-256', MSG_A3[:10], hart=hart)
    st = kl_derive(hart, dst, src, 336)
    xof = oracle('SHAKE128', MSG_ABC, 400)
    dst.exec_('B', inp=MSG_ABC)
    dst.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(32)
    dst.exec_('C', out=out)
    check_true('derive SHAKE128 -> SHA3-256 (336 B) completes, klstart = 0',
               st == 'done' and hart.klstart == 0, (st, hart.klstart))
    check('[oracle] SHA3-256(a3[:10] || SHAKE128(abc)[:336] || abc) via the open '
          'destination', bytes(out),
          oracle('SHA3-256', MSG_A3[:10] + xof[:336] + MSG_ABC))
    out = bytearray(64)
    src.exec_('C', out=out)
    check('[oracle] the SHAKE128 source continues at byte 336', bytes(out),
          xof[336:400])
    # (b) SHA3-512 digest -> SHAKE256 absorb; the source reaches _Success_.
    hart = Hart()
    src = squeezing_cl('SHA3-512', MSG_A3, hart=hart)
    dst = absorbing_cl('SHAKE256', hart=hart)
    st = kl_derive(hart, dst, src, 64)
    dst.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(64)
    dst.exec_('C', out=out)
    check_true('derive of the whole SHA3-512 digest leaves the source in _Success_',
               st == 'done' and src.st == KL_STATE_SUCCESS, (st, src.st))
    check('[oracle] SHAKE256(SHA3-512(a3_200))', bytes(out),
          oracle('SHAKE256', bytes.fromhex(VECTORS[('SHA3-512', 'a3_200')]), 64))
    # (c) interrupted derive: SHAKE128 (t = 168 B) -> SHA3-512 (b = 72 B), whose
    #     common interruption points are the multiples of lcm(168, 72) = 504.
    hart = Hart()
    src = squeezing_cl('SHAKE128', MSG_A3, hart=hart)
    dst = absorbing_cl('SHA3-512', hart=hart)
    st = kl_derive(hart, dst, src, 600, interrupt_at=1)
    k1 = hart.klstart
    st2 = kl_derive(hart, dst, src, 600)
    dst.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(64)
    dst.exec_('C', out=out)
    check_true('derive halts at the first common interruption point, klstart = 504; '
               'the resumed derive retires with 0',
               st == 'interrupted' and k1 == 504 and st2 == 'done'
               and hart.klstart == 0, (st, k1, st2, hart.klstart))
    check('[oracle] SHA3-512(SHAKE128(a3_200)[:600]) after the interrupted derive',
          bytes(out), oracle('SHA3-512', oracle('SHAKE128', MSG_A3, 600)))
    # (d) length 0, and a destination that cannot import.
    hart = Hart()
    src = squeezing_cl('SHAKE256', MSG_ABC, hart=hart)
    dst = absorbing_cl('SHA3-224', MSG_ABC, hart=hart)
    snap = (src.state, src.block_base, dst.state, dst.block_base)
    st = kl_derive(hart, dst, src, 0)
    check_true('derive with length 0 transfers nothing and changes no state',
               st == 'done' and snap == (src.state, src.block_base, dst.state,
                                         dst.block_base))
    dst = squeezing_cl('SHA3-224', MSG_ABC, hart=hart)
    dst.exec_('C', out=bytearray(28))                # destination in _Success_
    snap = (src.st, src.state, src.block_base)
    st = kl_derive(hart, dst, src, 16)
    check_true('a destination in _Success_ is invalidated (SGR5); nothing is '
               'transferred from the source',
               st == 'invalid' and dst.st == KL_STATE_INVALID
               and (snap == (src.st, src.state, src.block_base)
                    or src.st == KL_STATE_INVALID), (st, dst.st, src.st))
    spec_note('[[KLEE-instruction-derive]] says that "if the transfer is not allowed, '
              'then both CLs transition to Error',
              'State _Invalid_", while its Checks invalidate "the offending CL, or '
              'both"; the two differ exactly when',
              'one endpoint alone is at fault.  The harness invalidates the offending '
              'CL and checks only what both',
              'readings share.')

    print()
    print('-- 12. negative controls --')
    print('KAT-EXPECT-FAIL: suffix bit order')
    print('KAT-EXPECT-FAIL: klstart units')
    print('KAT-EXPECT-FAIL: serialized field order')
    got, _ = kl_hash_oneshot('SHA3-256', MSG_EMPTY, wrong_suffix=True)
    negative_control('suffix bit order (SHA3-256 suffix byte 0x06 MSB-aligned)',
                     got != bytes.fromhex(VECTORS[('SHA3-256', 'empty')]))
    got, _ = kl_hash_oneshot('SHAKE128', MSG_EMPTY, out_bytes=64,
                             wrong_suffix=True)
    negative_control('suffix bit order (SHAKE128 suffix byte 0x1F MSB-aligned)',
                     got != bytes.fromhex(VECTORS[('SHAKE128', 'empty')]))
    # klstart stored as a bit count: the re-execution reads it as bytes, and the
    # text rejects it as no interruption point.
    got, _ = kl_hash_oneshot('SHA3-256', MSG_A3, chunks=[MSG_A3],
                             interrupt=(0, 100), literal_units=True)
    negative_control('klstart units (bit count consumed as bytes)',
                     got != bytes.fromhex(VECTORS[('SHA3-256', 'a3_200')]))
    cl = absorbing_cl('SHA3-256', MSG_A3[:100])
    cl2 = KleeSha3CL(Hart())
    cl2.import_scc(cl.mdh(), cl.export_content(order_by_at=True))
    cl2.exec_('B', inp=MSG_A3[100:])
    cl2.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(32)
    cl2.exec_('C', out=out)
    negative_control('serialized field order (Serialized Content built with @)',
                     bytes(out) != bytes.fromhex(VECTORS[('SHA3-256', 'a3_200')]))

    print()
    print('summary: %d passed, %d failed, negative controls %s'
          % (_n_pass, _n_fail, 'fired' if _controls_ok else 'DID NOT FIRE'))
    ok = _n_fail == 0 and _controls_ok
    print('KAT-RESULT: %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
