#!/usr/bin/env python3
"""KAT harness for the ACE SHA-3 family rules (SHA3-224/256/384/512, SHAKE128/256).

What is validated (spec anchors in src/ace-ISA-algorithms.adoc, by heading):
  [[ACE-process-VLI]]      -- bit-accounted absorption loop, chunking across several
                              ace.exec transfers, partial-block boundaries, and the
                              interruption/resumption points (acestart).
  [[ACE-hash-functions]]   -- the generic _Hash_Output_ squeeze loop, including
                              multi-exec squeezing, resumption via
                              output_base <- 8*acestart, and the _Success_ rule.
  [[ACE-SHA-3]]            -- direct XOR absorption into `state` (block == state),
                              the suffix-and-padding string S = D || pad10*1 with its
                              one-block (|S| = b - block_base) and two-block
                              (|S| = 2b - block_base) clauses, and the parameter table.
  src/ace-notation.adoc    -- FIPS 202 row of the conventions table: direct mapping of
                              the absorbed string, lanes little-endian (values are the
                              ACE little-endian ints of common.py).

Layered anchoring:
  1. Keccak-f[1600] is implemented FROM SCRATCH below (round constants and rho
     offsets transcribed from FIPS 202 / the Keccak reference).
  2. A bit-level FIPS 202 reference sponge built on it is checked against EMBEDDED
     standard digests and against Python's hashlib (labeled reference oracle).
  3. The ACE model (state machine + process_VLI + padding clauses, implemented
     literally from the spec text) is checked against the embedded vectors, the
     reference sponge, and the hashlib oracle.
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
  * Pattern-message cases carry no embedded constant and are anchored at runtime
    against the hashlib oracle (labeled [oracle]).

Known spec issue exercised (ACE-spec-review-0.7.0.md, finding M4):
  process_VLI stores `acestart <- input_base` (a BIT count) at its interruption
  point although acestart is architecturally a BYTE count (cf. Hash_Output, which
  correctly writes `acestart <- output_base / 8`).  This harness models the
  corrected byte interpretation (acestart = input_base/8, resume at 8*acestart)
  and demonstrates the unit clash as a negative control.

Negative controls (must mismatch, declared via KAT-EXPECT-FAIL):
  * suffix bit order  -- the domain suffix byte (0x06 / 0x1F) applied MSB-aligned
    (bit-reversed) instead of the FIPS 202 LSB-first convention.
  * M4 literal units  -- acestart written as a bit count and consumed under the
    architectural byte convention on resumption.

Verdict: per-case PASS/FAIL lines and a final `KAT-RESULT: PASS|FAIL`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl        # ACE value conventions (do not modify common.py)

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
    """KECCAK-p[1600,24] on a 1600-bit ACE value.

    Per the FIPS 202 row of the ACE conventions table the mapping is direct:
    lane (x, y) of FIPS 202 3.1 occupies bits [64*(5y+x)+63 : 64*(5y+x)] of the
    value, each lane little-endian -- which is exactly the identity on the ACE
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
# r bits at a time; bit j of every string is bit j of its ACE value (the FIPS 202
# h2b order coincides with the ACE little-endian convention).

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
# Transcribed from the spec table [[ACE-SHA-3-parameters]].  D is the
# domain-separation suffix as a bit sequence, first-appended bit first
# (= LSB-first in the ACE value): "01" -> (0,1), "1111" -> (1,1,1,1).
PARAMS = {
    #            c     b     t    XOF    D
    'SHA3-224': (448, 1152, 224, False, (0, 1)),
    'SHA3-256': (512, 1088, 256, False, (0, 1)),
    'SHA3-384': (768,  832, 384, False, (0, 1)),
    'SHA3-512': (1024, 576, 512, False, (0, 1)),
    'SHAKE128': (256, 1344, 1344, True, (1, 1, 1, 1)),
    'SHAKE256': (512, 1088, 1088, True, (1, 1, 1, 1)),
}

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
    return _ORACLE[name](msg, n)


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


# ----------------------------------------------------------------- ACE CC model
class AceSha3CC:
    """Model of an ACE SHA-3 crypto context, implemented literally from
    [[ACE-SHA-3]] + [[ACE-hash-functions]] + [[ACE-process-VLI]].

    `state` is the 1600-bit ACE value; for the SHA-3 family `block` == `state`
    (inputs are XORed directly into the rate, state_offset = 0) and `len` = 0
    (no maximum length enforced), so process_VLI's per-iteration amount is
    min(ACELEN - input_base, b - block_base).
    """

    def __init__(self, name):
        self.name = name
        c, b, t, xof, D = PARAMS[name]
        self.b, self.t, self.xof, self.D = b, t, xof, D
        # State _Ready_: state is zeroed; block_base/input_base zero.
        self.state = 0
        self.block_base = 0                 # bits
        self.acestart = 0                   # BYTES (architectural; M4-corrected)
        self.mstate = 'Ready'
        self.pad_case = None                # instrumentation: padding clause fired

    # -- ace.setst (Form A): _Ready_ -> _Hash_Absorb_
    def setst_absorb(self):
        assert self.mstate == 'Ready', self.mstate
        self.mstate = 'Hash_Absorb'

    # -- process_VLI inner loop, shared by exec_absorb and absorb_bits
    def _vli_loop(self, INPUT, acelen_bits, input_base, interrupt_at_byte,
                  literal_units):
        while input_base < acelen_bits:
            amount = min(acelen_bits - input_base, self.b - self.block_base)
            chunk = sl(INPUT, input_base + amount - 1, input_base)
            # block == state: XOR into state at block_base (state_offset = 0)
            self.state ^= chunk << self.block_base
            input_base += amount
            self.block_base += amount
            if self.block_base == self.b:
                self.state = keccak_f1600(self.state)     # absorb() = P()
                self.block_base = 0
            # process_VLI interruption point.  The spec literally says
            # "acestart <- input_base" although input_base is a BIT offset and
            # acestart is architecturally a BYTE count (M4, ACE-spec-review-0.7.0.md);
            # the corrected reading acestart <- input_base/8 is used (always
            # integral here, as the spec itself argues).
            if (interrupt_at_byte is not None and input_base < acelen_bits
                    and input_base // 8 >= interrupt_at_byte):
                if literal_units:
                    self.acestart = input_base            # LITERAL spec text: bits
                else:
                    self.acestart = input_base // 8       # M4-corrected: bytes
                return 'interrupted'
        return 'done'

    # -- ace.exec (Form B) in _Hash_Absorb_
    def exec_absorb(self, data, resume=False, interrupt_at_byte=None,
                    literal_units=False):
        assert self.mstate == 'Hash_Absorb', self.mstate
        INPUT = b2v(data) if data else 0
        acelen = 8 * len(data)
        if resume:
            # Spec: "If resuming an ace.exec instruction, then input_base <- acestart."
            # acestart is architecturally a byte count, so the corrected reading is
            # input_base <- 8 * acestart (M4).  With literal_units the stored bit
            # count is consumed under the byte convention, exhibiting the clash.
            input_base = 8 * self.acestart
        else:
            input_base = 0
        return self._vli_loop(INPUT, acelen, input_base, interrupt_at_byte,
                              literal_units)

    def absorb_bits(self, val, nbits):
        """Bit-granular absorption through the same process_VLI loop.

        process_VLI is defined in bits; only the ace.exec transfer interface
        restricts amounts to whole bytes.  This entry point exercises the
        bit-level generality (needed to reach the two-block padding clause)
        and is NOT reachable through architecturally legal ace.exec transfers.
        """
        assert self.mstate == 'Hash_Absorb', self.mstate
        return self._vli_loop(val & ((1 << nbits) - 1), nbits, 0, None, False)

    # -- ace.setst: _Hash_Absorb_ -> _Hash_Output_ (SHA-3 padding rules)
    def setst_output(self, wrong_suffix_bit_order=False):
        assert self.mstate == 'Hash_Absorb', self.mstate
        b, D = self.b, self.D
        # S = D || pad10*1, smallest |S| >= |D| + 2 making block_base + |S| a
        # positive multiple of b.
        room = b - self.block_base
        S_len = room if room >= len(D) + 2 else room + b
        S = 0
        S |= sum(bit << j for j, bit in enumerate(D))
        S |= 1 << len(D)                    # pad10*1 leading 1
        if wrong_suffix_bit_order:
            # NEGATIVE CONTROL: the suffix byte (0x06 / 0x1F) written MSB-aligned,
            # i.e. bit-reversed within its byte, violating the FIPS 202 h2b /
            # ACE little-endian bit order.
            first = S & 0xFF
            first = int('{:08b}'.format(first)[::-1], 2)
            S = (S & ~0xFF) | first
        S |= 1 << (S_len - 1)               # pad10*1 final 1
        if S_len == room:                   # clause 1: |S| = b - block_base
            self.pad_case = 1
            self.state ^= S << self.block_base
            self.state = keccak_f1600(self.state)
        else:                               # clause 2: |S| = 2b - block_base
            self.pad_case = 2
            self.state ^= (S & ((1 << room) - 1)) << self.block_base
            self.state = keccak_f1600(self.state)
            self.state ^= S >> room         # remaining b bits, at rate bit 0
            self.state = keccak_f1600(self.state)
        # Entering _Hash_Output_ (generic rules): block[t-1:0] <- finalize() --
        # for SHA-3 the digest is the rate part of state and block == state, so
        # finalize() is the identity; block_base <- 0.
        self.block_base = 0
        self.mstate = 'Hash_Output'

    # -- ace.exec (Form C) in _Hash_Output_
    def exec_squeeze(self, out_bytes, resume=False, interrupt_at_byte=None):
        """Returns (status, start_byte, data) with data covering OUTPUT bytes
        [start_byte, start_byte + len(data)).  status is 'done', 'interrupted'
        (acestart holds the resumption byte offset), or 'success' (SHA3-n
        transitioned to _Success_; the instruction returns, OUTPUT beyond the
        digest is not written)."""
        assert self.mstate == 'Hash_Output', self.mstate
        acelen = 8 * out_bytes
        t = self.t
        # Spec: output_base <- 0 // upon resumption, output_base <- 8 * acestart
        output_base = 8 * self.acestart if resume else 0
        start_byte = output_base // 8
        OUTPUT = 0
        while output_base < acelen:
            amount = min(acelen - output_base, t - self.block_base)
            chunk = sl(self.state, self.block_base + amount - 1, self.block_base)
            OUTPUT |= chunk << (output_base - 8 * start_byte)
            output_base += amount
            self.block_base += amount
            if self.block_base == t:
                if not self.xof:
                    # Hash function: transition to _Success_ and return.
                    self.mstate = 'Success'
                    return ('success', start_byte,
                            v2b(OUTPUT, output_base // 8 - start_byte))
                self.state = keccak_f1600(self.state)     # update() = P()
                self.block_base = 0
                # Interruption point: acestart <- output_base / 8 (spec, correct
                # units here).
                if (interrupt_at_byte is not None and output_base < acelen
                        and output_base // 8 >= interrupt_at_byte):
                    self.acestart = output_base // 8
                    return ('interrupted', start_byte,
                            v2b(OUTPUT, output_base // 8 - start_byte))
        return ('done', start_byte, v2b(OUTPUT, out_bytes - start_byte))


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


# ------------------------------------------------------------------ test drive
def ace_hash_oneshot(name, msg, out_bytes=None, chunks=None,
                     interrupt=None, wrong_suffix=False, literal_units=False):
    """Run the full ACE state machine: absorb (optionally chunked/interrupted),
    pad, squeeze out_bytes (default t/8) in one exec.  Returns (digest, cc)."""
    c, b, t, xof, D = PARAMS[name]
    cc = AceSha3CC(name)
    cc.setst_absorb()
    if chunks is None:
        chunks = [msg]
    for i, ch in enumerate(chunks):
        intr = interrupt if (interrupt is not None and interrupt[0] == i) else None
        st = cc.exec_absorb(ch, interrupt_at_byte=intr[1] if intr else None,
                            literal_units=literal_units)
        if st == 'interrupted':
            st = cc.exec_absorb(ch, resume=True, literal_units=literal_units)
            assert st == 'done'
    cc.setst_output(wrong_suffix_bit_order=wrong_suffix)
    n = out_bytes if out_bytes is not None else t // 8
    status, start, data = cc.exec_squeeze(n)
    assert start == 0
    return data, cc


def main():
    print('== shake-kat: ACE SHA-3 family rules vs FIPS 202 ==')
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
    print('-- 2. ACE model, single-exec absorption --')
    for name in PARAMS:
        for mid, msg in MSGS.items():
            want = bytes.fromhex(VECTORS[(name, mid)])
            got, cc = ace_hash_oneshot(name, msg, out_bytes=len(want))
            check('ACE model  %-8s %-6s' % (name, mid), got, want)
            if not PARAMS[name][3]:
                check_true('ACE model  %-8s %-6s reached _Success_' % (name, mid),
                           cc.mstate == 'Success', 'state=%s' % cc.mstate)

    print()
    print('-- 3. chunked absorption through process_VLI '
          '(granularity 32 bits, partial-block boundaries) --')
    # SHAKE128 (rate 168 B): transfers 68+4+100+28 = 200 B; the 100-B transfer
    # crosses the 168-B block boundary mid-transfer.
    got, _ = ace_hash_oneshot('SHAKE128', MSG_A3, out_bytes=64,
                              chunks=[MSG_A3[:68], MSG_A3[68:72],
                                      MSG_A3[72:172], MSG_A3[172:]])
    check('ACE chunked SHAKE128 a3_200 (68+4+100+28 B transfers)',
          got, bytes.fromhex(VECTORS[('SHAKE128', 'a3_200')]))
    # SHA3-512 (rate 72 B): 12+60 hits the block boundary exactly at a transfer
    # edge; 100 crosses it mid-transfer; tail 28.
    got, _ = ace_hash_oneshot('SHA3-512', MSG_A3,
                              chunks=[MSG_A3[:12], MSG_A3[12:72],
                                      MSG_A3[72:172], MSG_A3[172:]])
    check('ACE chunked SHA3-512 a3_200 (12+60+100+28 B transfers)',
          got, bytes.fromhex(VECTORS[('SHA3-512', 'a3_200')]))

    print()
    print('-- 4. interrupted/resumed absorption (M4-corrected acestart, in bytes) --')
    # SHA3-256 (rate 136 B), one 200-B exec interrupted at the interruption point
    # after the first full block (input_base = 136 B).
    cc = AceSha3CC('SHA3-256')
    cc.setst_absorb()
    st = cc.exec_absorb(MSG_A3, interrupt_at_byte=100)
    check_true('SHA3-256 absorb interrupted at process_VLI interruption point',
               st == 'interrupted', st)
    check_true('acestart is a BYTE count = 136 (first interruption point after '
               'the 136-B block; M4-corrected)', cc.acestart == 136,
               'acestart=%r' % cc.acestart)
    st = cc.exec_absorb(MSG_A3, resume=True)     # input_base <- 8 * acestart
    check_true('resumed exec completes', st == 'done', st)
    cc.setst_output()
    _, _, data = cc.exec_squeeze(32)
    check('SHA3-256 a3_200 digest after interrupt/resume',
          data, bytes.fromhex(VECTORS[('SHA3-256', 'a3_200')]))

    print()
    print('-- 5. suffix-and-padding S = D || pad10*1 --')
    pat = bytes((7 * i + 3) & 0xFF for i in range(256))
    # (a) one-block clause, tightest byte-aligned case: rate-minus-1-byte message,
    #     |S| = 8 bits (whole suffix + both pad bits inside the final byte).
    for name in PARAMS:
        c, b, t, xof, D = PARAMS[name]
        msg = pat[:b // 8 - 1]
        got, cc = ace_hash_oneshot(name, msg, out_bytes=32)
        check('[oracle] %-8s rate-1-byte msg (%3d B), one-block padding'
              % (name, len(msg)), got, oracle(name, msg, 32))
        check_true('%-8s padding clause 1 fired (|S| = b - block_base = 8)'
                   % name, cc.pad_case == 1, 'case=%r' % cc.pad_case)
    # (b) rate-exact message: block_base = 0 at the transition, |S| = b
    #     ("positive multiple of b" -> a full padding block).
    for name in ('SHAKE128', 'SHA3-512'):
        c, b, t, xof, D = PARAMS[name]
        msg = pat[:b // 8]
        got, cc = ace_hash_oneshot(name, msg, out_bytes=32)
        check('[oracle] %-8s rate-exact msg (%3d B), full padding block'
              % (name, len(msg)), got, oracle(name, msg, 32))
        check_true('%-8s padding clause 1 fired (|S| = b, block_base = 0)'
                   % name, cc.pad_case == 1, 'case=%r' % cc.pad_case)
    # (c) two-block spill clause (|S| = 2b - block_base).  Only reachable with a
    #     bit-granular block_base: ace.exec transfers whole bytes, so
    #     b - block_base >= 8 > |D| + 2 always, and the clause is dead code at
    #     the architectural interface.  Exercised here through the bit-level
    #     definition of process_VLI; anchor is model-vs-reference (hashlib
    #     cannot do bit strings).
    print('NOTE: spec observation -- the two-block padding clause of [[ACE-SHA-3]] '
          'requires b - block_base < |D| + 2, which')
    print('      cannot occur through byte-granular ace.exec transfers '
          '(b - block_base is always >= 8); it is reachable only')
    print('      at the bit level of process_VLI.')
    for name, nbits in (('SHAKE128', 1342), ('SHA3-256', 1085), ('SHA3-512', 573)):
        c, b, t, xof, D = PARAMS[name]
        assert (b - nbits % b) < len(D) + 2
        val = b2v(pat[: (nbits + 7) // 8]) & ((1 << nbits) - 1)
        cc = AceSha3CC(name)
        cc.setst_absorb()
        cc.absorb_bits(val, nbits)
        cc.setst_output()
        _, _, data = cc.exec_squeeze(32)
        check('%-8s %4d-bit msg, two-block padding spill vs bit-level reference'
              % (name, nbits), data, ref_sponge(b, val, nbits, D, 32))
        check_true('%-8s padding clause 2 fired (|S| = 2b - block_base = %d)'
                   % (name, 2 * b - nbits % b), cc.pad_case == 2,
                   'case=%r' % cc.pad_case)
    # (d) boundary of clause 1: block_base = b - (|D| + 2) exactly.
    name, nbits = 'SHA3-256', 1084          # b - block_base = 4 = |D| + 2
    c, b, t, xof, D = PARAMS[name]
    val = b2v(pat[: (nbits + 7) // 8]) & ((1 << nbits) - 1)
    cc = AceSha3CC(name)
    cc.setst_absorb()
    cc.absorb_bits(val, nbits)
    cc.setst_output()
    _, _, data = cc.exec_squeeze(32)
    check('SHA3-256 1084-bit msg, minimal one-block padding (|S| = |D| + 2)',
          data, ref_sponge(b, val, nbits, D, 32))
    check_true('SHA3-256 padding clause 1 fired at its boundary',
               cc.pad_case == 1, 'case=%r' % cc.pad_case)

    print()
    print('-- 6. _Hash_Output_ squeezing (XOFs) --')
    # (a) one long exec vs the oracle stream.
    stream = oracle('SHAKE128', MSG_ABC, 512)
    check_true('[oracle] SHAKE128 abc stream prefix matches embedded vector',
               stream[:64] == bytes.fromhex(VECTORS[('SHAKE128', 'abc')]))
    got, cc = ace_hash_oneshot('SHAKE128', MSG_ABC, out_bytes=512)
    check('[oracle] SHAKE128 abc 512-B squeeze, single exec', got, stream)
    check_true('SHAKE128 stays in _Hash_Output_ (XOFs never reach _Success_)',
               cc.mstate == 'Hash_Output', cc.mstate)
    # (b) the same 512 bytes across several Form C execs (block_base persists).
    cc = AceSha3CC('SHAKE128')
    cc.setst_absorb()
    cc.exec_absorb(MSG_ABC)
    cc.setst_output()
    out = b''
    for n in (100, 68, 200, 144):
        status, start, data = cc.exec_squeeze(n)
        assert status == 'done' and start == 0
        out += data
    check('[oracle] SHAKE128 abc 512-B squeeze across execs of 100+68+200+144 B',
          out, stream)
    check_true('SHAKE128 still in _Hash_Output_ after multi-exec squeeze',
               cc.mstate == 'Hash_Output', cc.mstate)
    # (c) interrupted/resumed squeeze: acestart = output_base / 8.
    cc = AceSha3CC('SHAKE128')
    cc.setst_absorb()
    cc.exec_absorb(MSG_ABC)
    cc.setst_output()
    status, start, first = cc.exec_squeeze(400, interrupt_at_byte=1)
    check_true('SHAKE128 squeeze interrupted at first interruption point',
               status == 'interrupted' and start == 0, status)
    check_true('acestart = output_base/8 = 168 (t bits = one rate)',
               cc.acestart == 168, 'acestart=%r' % cc.acestart)
    status, start, rest = cc.exec_squeeze(400, resume=True)
    check_true('resumed squeeze continues at byte 168',
               status == 'done' and start == 168, (status, start))
    check('[oracle] SHAKE128 abc 400-B squeeze with interrupt/resume',
          first + rest, oracle('SHAKE128', MSG_ABC, 400))
    # (d) SHAKE256 multi-exec squeeze on the long message.
    cc = AceSha3CC('SHAKE256')
    cc.setst_absorb()
    cc.exec_absorb(MSG_A3)
    cc.setst_output()
    out = b''
    for n in (64, 8, 264):
        status, start, data = cc.exec_squeeze(n)
        out += data
    check('[oracle] SHAKE256 a3_200 336-B squeeze across execs of 64+8+264 B',
          out, oracle('SHAKE256', MSG_A3, 336))

    print()
    print('-- 7. SHA3-n _Success_ transition after t bits --')
    # (a) digest split across two execs; _Success_ exactly at the t-th bit.
    cc = AceSha3CC('SHA3-256')
    cc.setst_absorb()
    cc.exec_absorb(MSG_ABC)
    cc.setst_output()
    s1, _, d1 = cc.exec_squeeze(12)
    check_true('SHA3-256 12-B partial digest exec completes without _Success_',
               s1 == 'done' and cc.mstate == 'Hash_Output', (s1, cc.mstate))
    s2, _, d2 = cc.exec_squeeze(20)
    check_true('SHA3-256 reaches _Success_ at the t-th bit', s2 == 'success'
               and cc.mstate == 'Success', (s2, cc.mstate))
    check('SHA3-256 abc digest split 12+20 B', d1 + d2,
          bytes.fromhex(VECTORS[('SHA3-256', 'abc')]))
    # (b) OUTPUT longer than the digest: the instruction returns at _Success_
    #     with only t/8 bytes written.
    cc = AceSha3CC('SHA3-384')
    cc.setst_absorb()
    cc.exec_absorb(MSG_ABC)
    cc.setst_output()
    s, _, d = cc.exec_squeeze(64)
    check_true('SHA3-384 64-B exec returns at _Success_ with only 48 B written',
               s == 'success' and len(d) == 48, (s, len(d)))
    check('SHA3-384 abc digest from oversized exec', d,
          bytes.fromhex(VECTORS[('SHA3-384', 'abc')]))

    print()
    print('-- 8. negative controls --')
    print('KAT-EXPECT-FAIL: suffix bit order')
    print('KAT-EXPECT-FAIL: M4 literal units')
    got, _ = ace_hash_oneshot('SHA3-256', MSG_EMPTY, wrong_suffix=True)
    negative_control('suffix bit order (SHA3-256 suffix byte 0x06 MSB-aligned)',
                     got != bytes.fromhex(VECTORS[('SHA3-256', 'empty')]))
    got, _ = ace_hash_oneshot('SHAKE128', MSG_EMPTY, out_bytes=64,
                              wrong_suffix=True)
    negative_control('suffix bit order (SHAKE128 suffix byte 0x1F MSB-aligned)',
                     got != bytes.fromhex(VECTORS[('SHAKE128', 'empty')]))
    # M4: acestart stored as a bit count (literal process_VLI text) and consumed
    # under the architectural byte convention on resumption -> the tail of the
    # message is never absorbed.
    got, _ = ace_hash_oneshot('SHA3-256', MSG_A3, chunks=[MSG_A3],
                              interrupt=(0, 100), literal_units=True)
    negative_control('M4 literal units (acestart bit count consumed as bytes)',
                     got != bytes.fromhex(VECTORS[('SHA3-256', 'a3_200')]))
    print('NOTE: spec discrepancy M4 (ACE-spec-review-0.7.0.md) -- '
          '[[ACE-process-VLI]] writes "acestart <- input_base" with input_base')
    print('      in bits, while acestart is architecturally a byte count and '
          '_Hash_Output_ correctly uses acestart <- output_base/8.')
    print('      This harness models the corrected byte interpretation.')

    print()
    print('summary: %d passed, %d failed, negative controls %s'
          % (_n_pass, _n_fail, 'fired' if _controls_ok else 'DID NOT FIRE'))
    ok = _n_fail == 0 and _controls_ok
    print('KAT-RESULT: %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
