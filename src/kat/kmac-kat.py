#!/usr/bin/env python3
"""KAT harness for the KLEE KMAC Machines (KMAC128/256, KMACXOF128/256).

What is validated (spec anchors, by heading):
  modules/ROOT/pages/Zkl-ISA-machines.adoc (Book 2)
  [[KLEE-KMAC]]             -- parameters (n, c, b, t = b, L, granularity); the CC
                              holds two provisioner-prepared rate-sized blocks,
                              cshake_block = bytepad(encode_string("KMAC") ||
                              encode_string(S), b/8) and key_block =
                              bytepad(encode_string(K), b/8), and the table of
                              maximum |K| and |S|; the Provisioning Input (MDH,
                              cshake_block at pos. ii, key_block at pos. iii); the
                              Serialized Content (state, block_base, 48-bit padding,
                              cshake_block, key_block, L, implicit zero padding to a
                              multiple of 128 bits); _Ready_ = zero `state`, then
                              XOR each block into the rate and apply P(); the Form B
                              (KMAC, auxiliary L, L != 0) and Form A (KMACXOF, L = 0)
                              transitions to _Hash_Output_; right_encode(L) absorbed
                              continuing from block_base; the cSHAKE suffix D = 00
                              with pad10*1; exactly L bits (the last byte
                              zero-padded) then _Success_ for KMAC, unlimited output
                              for KMACXOF.
  [[KLEE-SHA-3]]            -- inherited: direct XOR absorption, P(), the
                              one-block / two-block padding clauses, States.
  [[KLEE-process-VLI]]      -- chunked absorption across several kl.exec
                              transfers, partial-block boundaries, the Form A entry,
                              the same-State rejection, and the interruption point
                              klstart <- input_base / 8.
  [[KLEE-hash-functions]]   -- the _Hash_Output_ squeeze loop, multi-exec output,
                              resumption via output_base <- 8 * klstart, clearing
                              of OUTPUT beyond output_base.
  [[KLEE-Machine-rules]] (MGR1, MGR2, MGR6), [[KLEE-exec-encodings]] (Type 6,
  Modes 10-13), [[KLEE-derive-endpoints]] (KMAC is no endpoint).
  modules/ROOT/pages/Zkl-ISA-unpriv.adoc (Book 1): [[KLEE-CSR-klstart]], [[KLEE-instruction-exec]],
  [[KLEE-instruction-derive]], [[KLEE-State-management]] (SGR2, SGR5, SGR6,
  SGR10, SGR16), [[KLEE-resumability]] (IRR6), [[KLEE-length-rule]],
  [[KLEE-instruction-size]], [[KLEE-metadata-header]].
  modules/ROOT/pages/Zkl-notation.adoc: FIPS 202 row of [[KLEE-Notation-standards]] -- direct
  mapping of the absorbed string, lanes little-endian.

Layered anchoring:
  1. Keccak-f[1600] implemented FROM SCRATCH here (round constants and rho
     offsets are the well-known FIPS 202 tables), anchored by embedded FIPS 202
     SHA3-256 / SHAKE128 / SHAKE256 known answers.
  2. An SP 800-185 reference (left_encode / right_encode / encode_string /
     bytepad / cSHAKE / KMAC), anchored by the embedded official NIST sample
     outputs.
  3. The KLEE model (state machine from the spec text) checked against the same
     official outputs and against the reference on the derived cases.
  hashlib is used only as a LABELED REFERENCE ORACLE for the plain SHA-3/SHAKE
  anchors; it has no KMAC and takes no part in the KMAC checks.

Embedded vector provenance:
  * KMAC128 samples 1-3 and KMAC256 samples 4-6: NIST CSRC "KMAC_samples.pdf"
    (csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/
    documents/examples/KMAC_samples.pdf).  Transcribed from two independent
    mirrors that cite that file -- BouncyCastle core/src/test/java/org/
    bouncycastle/crypto/test/KMACTest.java and PyCryptodome lib/Crypto/SelfTest/
    Hash/test_KMAC.py -- which agree byte for byte (checked 2026-08-26).
  * KMACXOF128 samples 1-3 and KMACXOF256 samples 4-6: NIST CSRC
    "KMACXOF_samples.pdf" (same directory), text-extracted from the official PDF
    on 2026-08-26.  KMACXOF128 sample 2 is independently confirmed by
    BouncyCastle's doFinalTest() (31a44527...b16c).
  * FIPS 202 anchors for the Keccak core: SHA3-256/SHAKE128/SHAKE256 of "".

Review finding M4, since FIXED:
  process_VLI used to store `klstart <- input_base` (a BIT count) although
  klstart is architecturally a BYTE count.  The spec now converts explicitly
  (`klstart <- input_base / 8`, resume at `input_base <- 8 * klstart`), which
  this harness transcribes; the pre-fix text is kept as a negative control.

Negative controls (must mismatch, declared via KAT-EXPECT-FAIL):
  * left_encode  -- left_encode(L) absorbed in place of right_encode(L).
  * suffix D     -- the raw SHAKE suffix 1111 in place of the cSHAKE suffix 00.
  * M4 literal units -- klstart written as a bit count, consumed as bytes.
  * unpadded last byte -- ceil(L/8) raw squeezed bytes delivered instead of
    exactly L bits with the last byte zero-padded.
  * serialized field order -- the Serialized Content assembled with the `@`
    operator (first field in the MORE significant bits) instead of in table order.

Verdict: per-case PASS/FAIL lines and a final `KAT-RESULT: PASS|FAIL`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl, cat    # KLEE value conventions (do not modify common.py)

import hashlib                          # LABELED REFERENCE ORACLE (SHA-3 anchors only)

# --------------------------------------------------------------- Keccak-f[1600]
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_RHO = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_M64 = (1 << 64) - 1


def _rol64(v, s):
    s %= 64
    return v if s == 0 else ((v << s) | (v >> (64 - s))) & _M64


def keccak_f1600(state):
    """KECCAK-p[1600,24] on a 1600-bit KLEE value (lane (x,y) at bits
    [64*(5y+x)+63 : 64*(5y+x)], each lane little-endian -- the identity on the
    KLEE little-endian integer of the state byte string)."""
    A = [(state >> (64 * i)) & _M64 for i in range(25)]
    for rc in _KECCAK_RC:
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
        A = [A[i] ^ D[i % 5] for i in range(25)]
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(A[x + 5 * y], _RHO[x][y])
        A = [B[i] ^ ((~B[(i % 5 + 1) % 5 + 5 * (i // 5)])
                     & B[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        A[0] ^= rc
    v = 0
    for i in range(24, -1, -1):
        v = (v << 64) | (A[i] & _M64)
    return v


# ------------------------------------------------- FIPS 202 / cSHAKE reference
def ref_sponge(rate_bits, data, suffix_bits, out_bytes):
    """Byte-string sponge with a bit-level domain suffix followed by pad10*1."""
    S = sum(bit << j for j, bit in enumerate(suffix_bits))
    S |= 1 << len(suffix_bits)                  # leading 1 of pad10*1
    msg_bits = 8 * len(data)
    total = msg_bits + len(suffix_bits) + 1
    plen = (total // rate_bits + 1) * rate_bits
    P = b2v(data) | (S << msg_bits) | (1 << (plen - 1))
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


# ------------------------------------------------------ SP 800-185 2.3 encodings
def left_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, 'big')


def right_encode(x):
    """SP 800-185 2.3.1 as restated in [[KLEE-KMAC]]: x as an unsigned big-endian
    integer on the smallest positive number m of bytes, followed by a byte m."""
    n = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, 'big') + bytes([n])


def encode_string(s):
    return left_encode(8 * len(s)) + s


def bytepad(x, w):
    z = left_encode(w) + x
    return z + bytes((-len(z)) % w)


RATE = {128: 168, 256: 136}             # b/8 in bytes; c = 256 / 512


def trunc_bits(data, nbits):
    """The first nbits of a byte string as ceil(nbits/8) bytes, the unused bits
    of the last byte zero (FIPS 202 bit order: bit j of the string is bit j of
    its KLEE value)."""
    n = (nbits + 7) // 8
    return v2b(b2v(data[:n]) & ((1 << nbits) - 1), n)


def ref_kmac(sec, K, X, L, S=b'', xof=False, out_bytes=None):
    """SP 800-185 4.3 KMAC / 4.3.1 KMACXOF: cSHAKE(bytepad(encode_string(K), w)
    || X || right_encode(L or 0), L, "KMAC", S).  KMAC returns exactly L bits."""
    w = RATE[sec]
    newX = bytepad(encode_string(K), w) + X + right_encode(0 if xof else L)
    prefix = bytepad(encode_string(b"KMAC") + encode_string(S), w)
    if xof:
        return ref_sponge(8 * w, prefix + newX, (0, 0), out_bytes)  # cSHAKE suffix 00
    return trunc_bits(ref_sponge(8 * w, prefix + newX, (0, 0), (L + 7) // 8), L)


# ------------------------------------------------------------ embedded vectors
KEY = bytes.fromhex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f')
DATA4 = bytes.fromhex('00010203')
DATA200 = bytes(range(200))              # 00 01 ... C7
TAG = b'My Tagged Application'

# (label, sec, xof, K, X, S, L_bits, expected_hex)
SAMPLES = [
    ('KMAC128 sample #1', 128, False, KEY, DATA4, b'', 256,
     'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e'),
    ('KMAC128 sample #2', 128, False, KEY, DATA4, TAG, 256,
     '3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5'),
    ('KMAC128 sample #3', 128, False, KEY, DATA200, TAG, 256,
     '1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230'),
    ('KMAC256 sample #4', 256, False, KEY, DATA4, TAG, 512,
     '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7'
     'f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd'),
    ('KMAC256 sample #5', 256, False, KEY, DATA200, b'', 512,
     '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691'
     '589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69'),
    ('KMAC256 sample #6', 256, False, KEY, DATA200, TAG, 512,
     'b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9'
     '70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965'),
    ('KMACXOF128 sample #1', 128, True, KEY, DATA4, b'', 256,
     'cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35'),
    ('KMACXOF128 sample #2', 128, True, KEY, DATA4, TAG, 256,
     '31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c'),
    ('KMACXOF128 sample #3', 128, True, KEY, DATA200, TAG, 256,
     '47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f'),
    ('KMACXOF256 sample #4', 256, True, KEY, DATA4, TAG, 512,
     '1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa9'
     '6faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b'),
    ('KMACXOF256 sample #5', 256, True, KEY, DATA200, b'', 512,
     'ff7b171f1e8a2b24683eed37830ee797538ba8dc563f6da1e667391a75edc02c'
     'a633079f81ce12a25f45615ec89972031d18337331d24ceb8f8ca8e6a19fd98b'),
    ('KMACXOF256 sample #6', 256, True, KEY, DATA200, TAG, 512,
     'd5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce'
     '67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d'),
]

# FIPS 202 anchors for the Keccak core (NIST CSRC example values, "" message)
FIPS202_EMPTY = {
    'SHA3-256': ((0, 1), 1088,
                 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'),
    'SHAKE128': ((1, 1, 1, 1), 1344,
                 '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'),
    'SHAKE256': ((1, 1, 1, 1), 1088,
                 '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'),
}


# ------------------------------------------------------------------ parameters
N_STATE = 1600                          # [[KLEE-KMAC]]: n = 1600
GRANULARITY = 32                        # "with the same meaning as in [[KLEE-SHA-3]]"
STATE_OFFSET = 0

# [[KLEE-KMAC]] Parameters:  name -> (sec, c, b, XOF); t = b.
KMAC_PARAMS = {
    'KMAC128':    (128, 256, 1344, False),
    'KMACXOF128': (128, 256, 1344, True),
    'KMAC256':    (256, 512, 1088, False),
    'KMACXOF256': (256, 512, 1088, True),
}
# [[KLEE-exec-encodings]]: _Machine_ = Type [11:4] @ Mode [3:0].
MACHINE_TYPE_MODE = {'KMAC128': (6, 10), 'KMACXOF128': (6, 11),
                     'KMAC256': (6, 12), 'KMACXOF256': (6, 13)}
MACHINE_CODE = {nm: (ty << 4) | mo for nm, (ty, mo) in MACHINE_TYPE_MODE.items()}
MACHINE_NAME = {code: nm for nm, code in MACHINE_CODE.items()}


def kmac_name(sec, xof):
    return ('KMACXOF%d' if xof else 'KMAC%d') % sec


# ------------------------------------------------------ KLEE architectural state
KL_STATE_UNCONFIGURED = 0
KL_STATE_READY = 1
KL_STATE_HASH_ABSORB = 2
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
    other field is zero in this harness."""
    return v2b(machine | (state << 19), 16)


def mdh_fields(mdh):
    v = b2v(mdh)
    return sl(v, 11, 0), sl(v, 24, 19)


def ceil128(nbits):
    return -(-nbits // 128) * 128


def serialized_fields(b):
    """Serialized Content of [[KLEE-KMAC]], table order: (field, bits)."""
    return (('state', N_STATE), ('block_base', 16), ('padding', 48),
            ('cshake_block', b), ('key_block', b), ('L', 32))


def content1_size(b):
    return ceil128(sum(w for _, w in serialized_fields(b))) // 8


def pi_content_size(b):
    return 2 * b // 8                   # cshake_block (pos. ii) and key_block (pos. iii)


def kl_size(state, b):
    """[[KLEE-instruction-size]] for a KMAC MDH with AuxDataLen = 0."""
    if state in (KL_STATE_UNCONFIGURED, KL_CFG_PROVISIONING):
        return 16 + pi_content_size(b)
    if state in ERROR_STATES:
        return 16
    assert 1 <= state <= 47
    return 32 + content1_size(b)


def provision_blocks(sec, K, S):
    """What the provisioner prepares, per [[KLEE-KMAC]]."""
    w = RATE[sec]
    cshake_block = bytepad(encode_string(b"KMAC") + encode_string(S), w)
    key_block = bytepad(encode_string(K), w)
    if len(cshake_block) != w:
        raise ValueError('customization string exceeds one rate block')
    if len(key_block) != w:
        raise ValueError('key exceeds one rate block')
    return cshake_block, key_block


def make_pi(sec, xof, K, S):
    """Provisioning Input: MDH (pos. i, _State_ = _Unconfigured_), cshake_block
    (pos. ii), key_block (pos. iii)."""
    cb, kb = provision_blocks(sec, K, S)
    return mdh_pack(MACHINE_CODE[kmac_name(sec, xof)], KL_STATE_UNCONFIGURED) + cb + kb


class Hart:
    """The hart-level KLEE CSR used here: klstart (a byte count)."""

    def __init__(self):
        self.klstart = 0


# ----------------------------------------------------------------- KLEE CL model
class KleeKmacCL:
    """A CL holding a KLEE KMAC CC, implemented literally from [[KLEE-KMAC]] on
    top of [[KLEE-SHA-3]] / [[KLEE-hash-functions]] / [[KLEE-process-VLI]].

    block is `state` for the whole SHA-3 family, so absorbed data is XORed
    directly into the rate at block_base (state_offset = 0), and process_VLI
    runs with max_len = 0 (no enforced maximum) and cumul_len = None.
    """

    D_CSHAKE = (0, 0)                   # cSHAKE domain-separation suffix

    def __init__(self, hart):
        self.hart = hart
        self.machine = 0
        self.st = KL_STATE_UNCONFIGURED
        self.name = None
        self.state = 0
        self.block_base = 0             # bits
        self.cshake_block = b''
        self.key_block = b''
        self.L = 0
        # Not in the spec (see the SPEC-NOTE in section 9): bits made available
        # in _Hash_Output_, needed to stop after exactly L bits when L > t.
        self.out_bits = 0
        self.pad_case = None
        # negative-control hooks
        self.wrong_suffix = False
        self.use_left_encode = False
        self.raw_last_byte = False

    # ---------------------------------------------------------- configuration
    def _set_machine(self, machine):
        name = MACHINE_NAME[machine]
        sec, c, b, xof = KMAC_PARAMS[name]
        self.machine, self.name = machine, name
        self.sec, self.b, self.t, self.xof = sec, b, b, xof     # t = b
        self.D = (1, 1, 1, 1) if self.wrong_suffix else self.D_CSHAKE

    def provision(self, pi):
        machine, st = mdh_fields(pi[:16])
        assert st == KL_STATE_UNCONFIGURED   # [[KLEE-Metadata-validity]]
        self._set_machine(machine)
        content = pi[16:]
        assert len(content) == pi_content_size(self.b)
        w = self.b // 8
        self.cshake_block = content[:w]      # pos. ii
        self.key_block = content[w:2 * w]    # pos. iii
        self._enter_ready()                  # provisioning completes in _Ready_ only

    def export_content(self, order_by_at=False):
        """Serialized Content in table order from bit 0 upwards, zero-padded to a
        multiple of 128 bits.  order_by_at=True is a NEGATIVE CONTROL."""
        b = self.b
        if order_by_at:
            v = cat((self.state, N_STATE), (self.block_base, 16), (0, 48),
                    (b2v(self.cshake_block), b), (b2v(self.key_block), b),
                    (self.L, 32))
        else:
            v = (self.state | (self.block_base << N_STATE)
                 | (b2v(self.cshake_block) << 1664)
                 | (b2v(self.key_block) << (1664 + b))
                 | (self.L << (1664 + 2 * b)))
        return v2b(v, content1_size(b))

    def import_scc(self, mdh, content, out_bits=None):
        """Completing an import: each field is read at the position the table of
        [[KLEE-KMAC]] gives it (the padding at pos. iii and the implicit trailing
        padding are ignored, so that the negative control can feed a wrongly
        ordered image).  `out_bits` has no field in the Serialized Content; by
        default it is taken as block_base, which is what the listed fields imply
        as long as no update() has taken place in _Hash_Output_."""
        machine, st = mdh_fields(mdh)
        self._set_machine(machine)
        b = self.b
        assert len(content) == content1_size(b)
        v = b2v(content)
        self.state = sl(v, N_STATE - 1, 0)               # pos. i
        self.block_base = sl(v, N_STATE + 15, N_STATE)   # pos. ii
        self.cshake_block = v2b(sl(v, 1663 + b, 1664), b // 8)      # pos. iv
        self.key_block = v2b(sl(v, 1663 + 2 * b, 1664 + b), b // 8)  # pos. v
        self.L = sl(v, 1695 + 2 * b, 1664 + 2 * b)                   # pos. vi
        self.out_bits = self.block_base if out_bits is None else out_bits
        self.st = st
        if self.block_base >= b:
            # An image whose `block_base` is not a position within a block is
            # inconsistent Content; the specification defines no behaviour for
            # it, and the harness invalidates the CL (only the negative control
            # below produces such an image).
            self._invalidate()

    def mdh(self):
        return mdh_pack(self.machine, self.st)

    def clear(self):
        hooks = (self.wrong_suffix, self.use_left_encode, self.raw_last_byte)
        self.__init__(self.hart)
        self.wrong_suffix, self.use_left_encode, self.raw_last_byte = hooks

    def _clear_content(self):                            # SGR10
        self.state = 0
        self.block_base = 0
        self.cshake_block = bytes(len(self.cshake_block))
        self.key_block = bytes(len(self.key_block))
        self.L = 0
        self.out_bits = 0

    def _invalidate(self):
        self.st = KL_STATE_INVALID
        self._clear_content()
        return 'invalid'

    # ----------------------------------------------------------------- States
    def _enter_ready(self):
        # [[KLEE-KMAC]], In State _Ready_: state is zeroed; cshake_block is XORed
        # into the rate and P() applied; key_block likewise.  block_base is set
        # to zero ([[KLEE-hash-functions]]).
        self.st = KL_STATE_READY
        self.state = 0
        self.state ^= b2v(self.cshake_block)
        self.state = keccak_f1600(self.state)
        self.state ^= b2v(self.key_block)
        self.state = keccak_f1600(self.state)
        self.block_base = 0

    def _enter_output(self):
        # "Upon transitioning to State _Hash_Output_":
        # 1. right_encode(L) is absorbed, continuing from the current block_base.
        enc = left_encode(self.L) if self.use_left_encode else right_encode(self.L)
        self._vli(b2v(enc), 8 * len(enc), 0, None, False, False)
        # 2. S = D || pad10*1 absorbed exactly as in [[KLEE-SHA-3]], D = 00.
        b, D = self.b, self.D
        room = b - self.block_base
        S_len = room if room >= len(D) + 2 else room + b
        S = sum(bit << j for j, bit in enumerate(D)) | (1 << len(D))
        S |= 1 << (S_len - 1)
        if S_len == room:
            self.pad_case = 1
            self.state ^= S << self.block_base
            self.state = keccak_f1600(self.state)
        else:
            self.pad_case = 2
            self.state ^= (S & ((1 << room) - 1)) << self.block_base
            self.state = keccak_f1600(self.state)
            self.state ^= S >> room
            self.state = keccak_f1600(self.state)
        # [[KLEE-hash-functions]] upon entering _Hash_Output_: finalize() is the
        # identity for block = state; block_base <- 0.
        self.block_base = 0
        self.out_bits = 0
        self.st = KL_STATE_HASH_OUTPUT

    # --------------------------------------------------------------- kl.setst
    def setst(self, immed, form='A', aux=None):
        if immed == KL_STATE_UNCONFIGURED:
            self.clear()
            return 'cleared'
        if immed in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            raise IllegalInstruction('SGR7: immediates 46 and 47 are reserved')
        if immed in ERROR_STATES:                        # configuration instruction
            if self.st == KL_STATE_UNCONFIGURED:
                return 'noop'
            self.st = KL_STATE_INVALID if immed >= 54 else immed
            self._clear_content()
            return 'error-state'
        if self.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction('SGR12')
        if self.st in ERROR_STATES:                      # SGR15, SGR16
            return 'noop'
        if immed == KL_STATE_READY:                      # SGR8, SGR6
            self._enter_ready()
            return 'ok'
        if self.st == KL_STATE_SUCCESS:                  # SGR5, SGR6
            return self._invalidate()
        if immed == KL_STATE_HASH_ABSORB:
            if self.st == KL_STATE_READY and form == 'A':
                self.st = KL_STATE_HASH_ABSORB
                return 'ok'
            return self._invalidate()                    # incl. the same State
        if immed == KL_STATE_HASH_OUTPUT:
            if self.st == KL_STATE_HASH_OUTPUT:
                raise NotModelled('same-State kl.setst in _Hash_Output_ (SGR4)')
            if self.st != KL_STATE_HASH_ABSORB:
                return self._invalidate()
            if self.xof:
                # "For KMACXOF128 and KMACXOF256, a Form A kl.setst instruction is
                # expected, and L is assumed to be zero in the following."
                if form != 'A':
                    return self._invalidate()
                self.L = 0
            else:
                # "a Form B kl.setst instruction is expected for KMAC128 and
                # KMAC256, whose auxiliary argument sets L ... L must be non-zero"
                if form != 'B':
                    return self._invalidate()
                if aux >> 32:
                    raise NotModelled('an auxiliary L wider than the 32-bit field')
                if aux == 0:
                    return self._invalidate()
                self.L = aux
            self._enter_output()
            return 'ok'
        return self._invalidate()

    # ---------------------------------------------------------------- kl.exec
    def _zero_window(self, out):
        if out is not None:
            k = min(self.hart.klstart, len(out))
            out[k:] = bytes(len(out) - k)

    def _retire(self, status):
        self.hart.klstart = 0
        return status

    def _invalid_exec(self, out):
        self._invalidate()
        self._zero_window(out)
        return self._retire('invalid')

    def exec_(self, form, inp=None, out=None, sew=None, interrupt_at=None,
              end_halt=False, literal_units=False):
        """kl.exec, as in shake-kat.py: `inp` is the input window, `out` the
        output window (bytearray), `sew` the element width of a vector operand."""
        if self.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction('SGR12')
        if self.st in ERROR_STATES:                      # SGR16
            self._zero_window(out)
            return self._retire('noop')
        if self.st == KL_STATE_HASH_ABSORB:
            if form not in ('B', 'D') or inp is None or out is not None:
                return self._invalid_exec(out)           # MGR1
            if sew is not None:
                assert (8 * len(inp)) % sew == 0
                if sew < GRANULARITY:
                    return self._invalid_exec(out)       # MGR2
            return self._absorb(inp, interrupt_at, end_halt, literal_units)
        if self.st == KL_STATE_HASH_OUTPUT:
            if form not in ('C', 'D') or inp is not None or out is None:
                return self._invalid_exec(out)           # MGR1
            return self._squeeze(out, interrupt_at, end_halt)
        # _Ready_ (SGR2) and _Success_ (SGR5: KMAC's output is not arbitrarily
        # long; KMACXOF never reaches _Success_)
        return self._invalid_exec(out)

    def _absorb_point_ok(self, p, top):
        if p == 0 or p == top:
            return True
        if p > top:
            return False
        return self.block_base == 0

    def _vli(self, INPUT, KLLEN, input_base, interrupt_at, end_halt, literal_units):
        """The loop of [[KLEE-process-VLI]] with the SHA-3 arguments."""
        while input_base < KLLEN:
            amount = min(KLLEN - input_base, self.b - self.block_base)
            self.state ^= (sl(INPUT, input_base + amount - 1, input_base)
                           << (self.block_base + STATE_OFFSET))
            input_base += amount
            self.block_base += amount
            if self.block_base == self.b:
                self.state = keccak_f1600(self.state)    # process_block() = P()
                self.block_base = 0
            # Here: klstart <- input_base / 8
            if (interrupt_at is not None and input_base // 8 >= interrupt_at
                    and (input_base < KLLEN or end_halt)):
                self.hart.klstart = input_base if literal_units else input_base // 8
                return 'interrupted'
        return 'done'

    def _absorb(self, inp, interrupt_at, end_halt, literal_units):
        top = len(inp)
        p = self.hart.klstart
        if not self._absorb_point_ok(p, top):
            return self._invalid_exec(None)
        if p >= top:
            return self._retire('noop')
        st = self._vli(b2v(inp), 8 * top, 8 * p, interrupt_at, end_halt,
                       literal_units)
        return st if st == 'interrupted' else self._retire(st)

    def _squeeze_point_ok(self, p, top):
        if p == 0:
            return True
        if p > top:
            return False
        return self.block_base == 0                      # halts follow update()

    def _squeeze(self, out, interrupt_at, end_halt):
        top = len(out)
        p = self.hart.klstart
        if not self._squeeze_point_ok(p, top) or p >= top:
            self._zero_window(out)
            return self._retire('noop')
        KLLEN, t = 8 * top, self.t
        # [[KLEE-KMAC]] states the end of the output in terms of L, so the generic
        # "if we are in a Hash function ... the state transitions to _Success_"
        # branch that [[KLEE-hash-functions]] takes at block_base = t does not
        # apply here: at t bits KMAC applies update() and goes on, until L bits
        # have been made available.
        if self.xof:
            limit = None
        elif self.raw_last_byte:                         # NEGATIVE CONTROL
            limit = 8 * ((self.L + 7) // 8)
        else:
            limit = self.L                               # exactly L bits
        OUT = b2v(out)
        output_base = 8 * p
        while output_base < KLLEN:
            amount = min(KLLEN - output_base, t - self.block_base)
            if limit is not None:
                amount = min(amount, limit - self.out_bits)
            chunk = sl(self.state, self.block_base + amount - 1, self.block_base)
            OUT = ((OUT & ~(((1 << amount) - 1) << output_base))
                   | (chunk << output_base))
            output_base += amount
            self.block_base += amount
            self.out_bits += amount
            if limit is not None and self.out_bits == limit:
                # exactly L bits made available (the last byte zero-padded) and
                # the rest of OUTPUT cleared ([[KLEE-hash-functions]], MGR6);
                # then _Success_.
                OUT &= (1 << output_base) - 1
                out[:] = v2b(OUT, top)
                self.st = KL_STATE_SUCCESS
                return self._retire('success')
            if self.block_base == t:
                self.state = keccak_f1600(self.state)    # update() = P()
                self.block_base = 0
                if (interrupt_at is not None and output_base // 8 >= interrupt_at
                        and (output_base < KLLEN or end_halt)):
                    out[:] = v2b(OUT, top)
                    self.hart.klstart = output_base // 8
                    return 'interrupted'
        out[:] = v2b(OUT, top)
        return self._retire('done')


def kl_derive_kmac(hart, dst, src, length):
    """kl.derive with KMAC CLs as endpoints: [[KLEE-derive-endpoints]] lists no
    exportable and no importable field for [[KLEE-KMAC]], so neither CL admits
    an endpoint in any State (Check 1 of [[KLEE-instruction-derive]])."""
    if dst is src:
        raise IllegalInstruction('source and destination must differ')
    for cl in (src, dst):
        if cl.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction('SGR12')
    if src.st in ERROR_STATES or dst.st in ERROR_STATES:
        hart.klstart = 0
        return 'noop'
    src._invalidate()
    dst._invalidate()
    hart.klstart = 0
    return 'invalid'


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
    global _controls_ok, _n_pass
    if mismatched:
        _n_pass += 1
        print('FAIL  %s -- wrong formulation mismatches the standard, as it must '
              '(expected)' % label)
    else:
        _controls_ok = False
        print('ERROR %s -- negative control did not fire: the wrong formulation '
              'REPRODUCED the official output' % label)


def _notice(tag, lines):
    print('%s: %s' % (tag, lines[0]))
    for ln in lines[1:]:
        print(' ' * (len(tag) + 2) + ln)


def info(*lines):
    _notice('INFO', lines)


def spec_note(*lines):
    _notice('SPEC-NOTE', lines)


# ------------------------------------------------------------------ test drive
def new_cl(sec, K, S, xof=False, hart=None, **hooks):
    cl = KleeKmacCL(hart if hart is not None else Hart())
    for k, v in hooks.items():
        setattr(cl, k, v)
    cl.provision(make_pi(sec, xof, K, S))
    return cl


def to_output(cl, L):
    """The kl.setst to _Hash_Output_: Form B with L for KMAC, Form A for KMACXOF."""
    if cl.xof:
        return cl.setst(KL_STATE_HASH_OUTPUT)
    return cl.setst(KL_STATE_HASH_OUTPUT, form='B', aux=L)


def absorbing_cl(sec, K, S, X=b'', xof=False, hart=None):
    cl = new_cl(sec, K, S, xof, hart)
    cl.setst(KL_STATE_HASH_ABSORB)
    if X:
        assert cl.exec_('B', inp=X) == 'done'
    return cl


def squeezing_cl(sec, K, S, X, L, xof=False, hart=None):
    cl = absorbing_cl(sec, K, S, X, xof, hart)
    assert to_output(cl, L) == 'ok'
    return cl


def kl_kmac(sec, K, X, L, S=b'', xof=False, out_bytes=None, chunks=None,
            interrupt=None, literal_units=False, **hooks):
    cl = new_cl(sec, K, S, xof, **hooks)
    cl.setst(KL_STATE_HASH_ABSORB)
    for i, ch in enumerate(chunks if chunks is not None else [X]):
        intr = interrupt[1] if (interrupt and interrupt[0] == i) else None
        st = cl.exec_('B', inp=ch, interrupt_at=intr, literal_units=literal_units)
        if st == 'interrupted':
            cl.exec_('B', inp=ch)
    to_output(cl, L)
    n = out_bytes if out_bytes is not None else (L + 7) // 8
    out = bytearray(n)
    cl.exec_('C', out=out)
    return bytes(out), cl


def main():
    print('== kmac-kat: KLEE KMAC/KMACXOF Machines vs NIST SP 800-185 ==')
    print()
    print('-- 1. Keccak core anchored on FIPS 202 empty-message values --')
    for name, (D, rate, want) in FIPS202_EMPTY.items():
        got = ref_sponge(rate, b'', D, 32)
        check('reference sponge %-8s ("")' % name, got, bytes.fromhex(want))
    check('[oracle] hashlib SHA3-256("") vs embedded',
          hashlib.sha3_256(b'').digest(),
          bytes.fromhex(FIPS202_EMPTY['SHA3-256'][2]))
    check('[oracle] hashlib SHAKE128("") vs embedded',
          hashlib.shake_128(b'').digest(32),
          bytes.fromhex(FIPS202_EMPTY['SHAKE128'][2]))

    print()
    print('-- 2. SP 800-185 encodings (2.3) --')
    check('left_encode(0)', left_encode(0).hex(), '0100')
    check('left_encode(168)', left_encode(168).hex(), '01a8')
    check('left_encode(256)', left_encode(256).hex(), '020100')
    check('right_encode(0)', right_encode(0).hex(), '0001')
    check('right_encode(256)', right_encode(256).hex(), '010002')
    check('right_encode(512)', right_encode(512).hex(), '020002')
    check('encode_string(b"KMAC")', encode_string(b'KMAC').hex(),
          '01204b4d4143')
    check_true('bytepad(encode_string(K),168) is one rate block',
               len(bytepad(encode_string(KEY), 168)) == 168)

    print()
    print('-- 3. SP 800-185 reference vs the official sample outputs --')
    for label, sec, xof, K, X, S, L, exp in SAMPLES:
        want = bytes.fromhex(exp)
        got = ref_kmac(sec, K, X, L, S, xof=xof, out_bytes=len(want))
        check('reference  %-20s (|X|=%3d, |S|=%2d, L=%d)'
              % (label, len(X), len(S), L), got, want)

    print()
    print('-- 4. parameters and _Machine_ encodings --')
    for name, (sec, c, b, xof) in KMAC_PARAMS.items():
        check_true('%-10s c = %d, b = 1600 - c = %d bits = %d B, t = b, '
                   'state_offset + b <= n' % (name, c, b, RATE[sec]),
                   b == N_STATE - c and b == 8 * RATE[sec] and c == 2 * sec
                   and STATE_OFFSET + b <= N_STATE)
        cl = new_cl(sec, KEY, b'', xof)
        check_true('%-10s _Machine_ = Type 6, Mode %d, round-trips through the PI'
                   % (name, MACHINE_TYPE_MODE[name][1]),
                   cl.name == name and cl.t == cl.b and cl.st == KL_STATE_READY)

    print()
    print('-- 5. KLEE model vs the official sample outputs --')
    for label, sec, xof, K, X, S, L, exp in SAMPLES:
        want = bytes.fromhex(exp)
        got, cl = kl_kmac(sec, K, X, L, S, xof=xof, out_bytes=len(want))
        check('KLEE model  %-20s' % label, got, want)
        if xof:
            check_true('KLEE model  %-20s stays in _Hash_Output_ (never _Success_)'
                       % label, cl.st == KL_STATE_HASH_OUTPUT, cl.st)
        else:
            check_true('KLEE model  %-20s reached _Success_ after exactly L bits'
                       % label, cl.st == KL_STATE_SUCCESS, cl.st)

    print()
    print('-- 6. chunked absorption through process_VLI '
          '(granularity 32 bits, partial-block boundaries) --')
    # KMAC128 rate 168 B; the 200-B message crosses the block boundary.  The
    # 100-B transfer straddles it; the first two transfers end mid-block.
    want = bytes.fromhex(SAMPLES[2][7])
    got, _ = kl_kmac(128, KEY, DATA200, 256, TAG, out_bytes=32,
                     chunks=[DATA200[:68], DATA200[68:72], DATA200[72:172],
                             DATA200[172:]])
    check('KLEE chunked KMAC128 sample #3 (68+4+100+28 B transfers)', got, want)
    # KMAC256 rate 136 B: 136 exactly fills the block at a transfer edge.
    want = bytes.fromhex(SAMPLES[5][7])
    got, _ = kl_kmac(256, KEY, DATA200, 512, TAG, out_bytes=64,
                     chunks=[DATA200[:136], DATA200[136:140], DATA200[140:]])
    check('KLEE chunked KMAC256 sample #6 (136+4+60 B transfers)', got, want)
    # KMACXOF128 in many small transfers.
    want = bytes.fromhex(SAMPLES[8][7])
    got, _ = kl_kmac(128, KEY, DATA200, 256, TAG, xof=True, out_bytes=32,
                     chunks=[DATA200[i:i + 8] for i in range(0, 200, 8)])
    check('KLEE chunked KMACXOF128 sample #3 (25 transfers of 8 B)', got, want)
    cl = absorbing_cl(128, KEY, TAG)
    st = cl.exec_('B', inp=DATA200[:8], sew=8)
    check_true('KMAC128 Form B with SEW = 8 < granularity 32 -> _Invalid_ (MGR2)',
               st == 'invalid' and cl.st == KL_STATE_INVALID, (st, cl.st))

    print()
    print('-- 7. interrupted/resumed absorption (klstart in bytes) --')
    hart = Hart()
    cl = absorbing_cl(128, KEY, TAG, hart=hart)
    st = cl.exec_('B', inp=DATA200, interrupt_at=100)
    check_true('KMAC128 absorb interrupted at the process_VLI interruption point',
               st == 'interrupted', st)
    check_true('klstart = input_base / 8 = 168 (the rate; first interruption point)',
               hart.klstart == 168, 'klstart=%r' % hart.klstart)
    st = cl.exec_('B', inp=DATA200)
    check_true('resumed exec completes and retires with klstart = 0',
               st == 'done' and hart.klstart == 0, (st, hart.klstart))
    to_output(cl, 256)
    out = bytearray(32)
    cl.exec_('C', out=out)
    check('KMAC128 sample #3 after interrupt/resume', bytes(out),
          bytes.fromhex(SAMPLES[2][7]))
    # halt, export, clear, import into another CL, resume
    hart = Hart()
    cl = absorbing_cl(256, KEY, TAG, DATA200[:40], hart=hart)
    st = cl.exec_('B', inp=DATA200[40:], interrupt_at=1)        # 136 - 40 = 96
    saved = (cl.mdh(), cl.export_content(), hart.klstart)
    cl.setst(KL_STATE_UNCONFIGURED)
    hart.klstart = 0
    cl2 = KleeKmacCL(hart)
    cl2.import_scc(saved[0], saved[1])
    hart.klstart = saved[2]
    cl2.exec_('B', inp=DATA200[40:])
    to_output(cl2, 512)
    out = bytearray(64)
    cl2.exec_('C', out=out)
    check_true('KMAC256 halt at klstart = 96 (block boundary after a 40-B transfer)',
               st == 'interrupted' and saved[2] == 96, (st, saved[2]))
    check('KMAC256 sample #6 after halt, export, clear, import and resumption',
          bytes(out), bytes.fromhex(SAMPLES[5][7]))
    # a klstart the Machine cannot have produced (input operand)
    hart = Hart()
    cl = absorbing_cl(128, KEY, TAG, DATA4, hart=hart)
    hart.klstart = 100
    st = cl.exec_('B', inp=DATA200)
    check_true('input operand, klstart = 100 with block_base = 32 -> _Invalid_, '
               'Content cleared (SGR10), klstart = 0',
               st == 'invalid' and cl.st == KL_STATE_INVALID and cl.state == 0
               and cl.key_block == bytes(168) and hart.klstart == 0,
               (st, cl.st, hart.klstart))
    info('interruption points: a CL can only test what its own state implies -- 0, '
         'the end of the window, or,',
         'with block_base = 0, an interior value.  The harness exercises only values '
         'that fail that test.')

    print()
    print('-- 8. right_encode(L) absorbed continuing from block_base --')
    # After a 200-B message at rate 168 the block_base is 32 B;
    # right_encode(256) = 01 00 02 lands at bytes [32, 35) of the rate.
    cl = absorbing_cl(128, KEY, TAG, DATA200)
    check_true('block_base after the 200-B message is 32 B (200 - 168)',
               cl.block_base == 8 * 32, 'block_base=%r' % cl.block_base)
    to_output(cl, 256)
    check_true('padding clause 1 fired (|S| = b - block_base after '
               'right_encode(256))', cl.pad_case == 1, 'case=%r' % cl.pad_case)
    # KMACXOF absorbs right_encode(0) = 00 01, one byte shorter than
    # right_encode(256): the model and the reference must agree on both.
    for sec in (128, 256):
        want = ref_kmac(sec, KEY, DATA4, 0, TAG, xof=True, out_bytes=32)
        got, cl = kl_kmac(sec, KEY, DATA4, 256, TAG, xof=True, out_bytes=32)
        check('KMACXOF%d absorbs right_encode(0) = 0001 (field L = %d)'
              % (sec, cl.L), got, want)

    print()
    print('-- 9. output-length semantics --')
    # (a) KMAC output truncation: a shorter L is NOT a prefix of a longer one
    #     (L enters the absorbed right_encode(L)) -- each L is its own function.
    a = ref_kmac(128, KEY, DATA4, 256, TAG)
    b_ = ref_kmac(128, KEY, DATA4, 512, TAG)
    check_true('KMAC128 L=512 output is not an extension of L=256 (L is absorbed)',
               b_[:32] != a)
    got, cl = kl_kmac(128, KEY, DATA4, 512, TAG)
    check('KLEE model KMAC128 L=512 vs reference', got, b_)
    check_true('KMAC128 L=512 delivered 64 B then _Success_',
               len(got) == 64 and cl.st == KL_STATE_SUCCESS, cl.st)
    # (b) L not a multiple of 8: exactly L bits, the last byte zero-padded, in
    #     ceil(L/8) bytes.
    for L in (255, 250, 257, 1000, 1001):
        nb = (L + 7) // 8
        want = ref_kmac(128, KEY, DATA4, L, TAG)
        got, cl = kl_kmac(128, KEY, DATA4, L, TAG)
        check('KMAC128 L=%4d: exactly L bits in ceil(L/8) = %d B, last byte '
              'zero-padded' % (L, nb), got, want)
        check_true('KMAC128 L=%4d reached _Success_' % L,
                   cl.st == KL_STATE_SUCCESS and len(got) == nb, cl.st)
    spec_note('[[KLEE-KMAC]] says, for the kl.setst to _Hash_Output_, that "the last '
              'byte may be zero-padded in its',
              'significant bits", while _Hash_Output_ makes "exactly L bits" '
              'available, "the last one zero-padded".',
              'The padding is in the unused (non-significant) bits and is not '
              'optional; suggested wording: "the last',
              'byte is zero-padded in its 8 - (L mod 8) most significant bits".  '
              'The harness follows _Hash_Output_.')
    # (c) OUTPUT longer than ceil(L/8), and an L that ends inside a byte: the
    #     rest of OUTPUT is cleared.
    cl = squeezing_cl(128, KEY, TAG, DATA4, 250)
    out = bytearray(b'\xee' * 40)
    st = cl.exec_('C', out=out)
    check_true('KMAC128 L=250, 40-B OUTPUT: _Success_, bits [319:250] of OUTPUT '
               'cleared', st == 'success' and out[32:] == bytearray(8)
               and out[31] >> 2 == 0, (st, out[31:].hex()))
    check('KMAC128 L=250 from an oversized exec', bytes(out[:32]),
          ref_kmac(128, KEY, DATA4, 250, TAG))
    # (d) KMACXOF squeezes indefinitely across execs, with interrupt/resume.
    want = ref_kmac(128, KEY, DATA200, 0, TAG, xof=True, out_bytes=600)
    check_true('KMACXOF128 sample #3 prefix matches the official 32-B output',
               want[:32] == bytes.fromhex(SAMPLES[8][7]))
    cl = squeezing_cl(128, KEY, TAG, DATA200, 0, xof=True)
    parts = []
    for n in (32, 100, 168, 300):
        out = bytearray(n)
        st = cl.exec_('C', out=out)
        assert st == 'done', st
        parts.append(bytes(out))
    check('KMACXOF128 600-B squeeze across execs of 32+100+168+300 B',
          b''.join(parts), want)
    check_true('KMACXOF128 still in _Hash_Output_ after 600 B',
               cl.st == KL_STATE_HASH_OUTPUT, cl.st)
    hart = Hart()
    cl = squeezing_cl(128, KEY, TAG, DATA200, 0, xof=True, hart=hart)
    out = bytearray(b'\xee' * 400)
    st = cl.exec_('C', out=out, interrupt_at=1)
    check_true('KMACXOF128 squeeze interrupted after one rate, klstart = 168, '
               'bytes [168, 400) unwritten', st == 'interrupted'
               and hart.klstart == 168 and out[168:] == bytearray(b'\xee' * 232),
               (st, hart.klstart))
    st = cl.exec_('C', out=out)
    check_true('resumed squeeze completes and retires with klstart = 0',
               st == 'done' and hart.klstart == 0, (st, hart.klstart))
    check('KMACXOF128 400-B squeeze with interrupt/resume', bytes(out), want[:400])
    # (e) KMAC output split across execs, _Success_ on the last byte.
    cl = squeezing_cl(256, KEY, TAG, DATA4, 512)
    d1 = bytearray(20)
    s1 = cl.exec_('C', out=d1)
    check_true('KMAC256 20-B partial output, still in _Hash_Output_',
               s1 == 'done' and cl.st == KL_STATE_HASH_OUTPUT, (s1, cl.st))
    d2 = bytearray(44)
    s2 = cl.exec_('C', out=d2)
    check_true('KMAC256 reaches _Success_ on the 64th byte',
               s2 == 'success' and cl.st == KL_STATE_SUCCESS, (s2, cl.st))
    check('KMAC256 sample #4 split 20+44 B', bytes(d1 + d2),
          bytes.fromhex(SAMPLES[3][7]))
    # (f) an OUTPUT longer than ceil(L/8): only ceil(L/8) bytes are written and
    #     the rest is cleared.
    cl = squeezing_cl(256, KEY, TAG, DATA4, 512)
    out = bytearray(b'\xee' * 200)
    s = cl.exec_('C', out=out)
    check_true('KMAC256 200-B exec returns at _Success_, bytes [64, 200) cleared',
               s == 'success' and out[64:] == bytearray(136), s)
    check('KMAC256 sample #4 from an oversized exec', bytes(out[:64]),
          bytes.fromhex(SAMPLES[3][7]))
    # (g) L > t: output spans several applications of P(), across execs and
    #     with an interruption.
    want = ref_kmac(256, KEY, DATA200, 4096, TAG)
    got, cl = kl_kmac(256, KEY, DATA200, 4096, TAG)
    check('KMAC256 L=4096 (512 B, 4 rates of 136 B) vs reference', got, want)
    check_true('KMAC256 L=4096 reached _Success_', cl.st == KL_STATE_SUCCESS)
    hart = Hart()
    cl = squeezing_cl(256, KEY, TAG, DATA200, 4097, hart=hart)
    want = ref_kmac(256, KEY, DATA200, 4097, TAG)
    o1 = bytearray(b'\xee' * 300)
    s1 = cl.exec_('C', out=o1, interrupt_at=200)
    k1 = hart.klstart
    s1b = cl.exec_('C', out=o1)
    o2 = bytearray(b'\xee' * 300)
    s2 = cl.exec_('C', out=o2)
    check_true('KMAC256 L=4097: 300-B exec halted at klstart = 272, resumed; the '
               'next exec ends at bit 4097 with _Success_',
               (s1, k1, s1b, s2) == ('interrupted', 272, 'done', 'success')
               and cl.st == KL_STATE_SUCCESS, (s1, k1, s1b, s2))
    check('KMAC256 L=4097 in two 300-B execs (213 B written in the second, the rest '
          'cleared)', bytes(o1) + bytes(o2), want + bytes(600 - len(want)))
    # The missing output counter.
    cl_a = squeezing_cl(256, KEY, TAG, DATA200, 4096)
    cl_a.exec_('C', out=bytearray(137))              # bit 1096 = 1088 + 8
    cl_b = squeezing_cl(256, KEY, TAG, DATA200, 4096)
    cl_b.exec_('C', out=bytearray(273))              # bit 2184 = 2 * 1088 + 8
    ea, eb = cl_a.export_content(), cl_b.export_content()
    same_rest = ea[200:] == eb[200:]
    spec_note('[[KLEE-KMAC]] makes exactly L bits available "at b bits per '
              'application of P()", but neither its',
              'Internal State nor its Serialized Content records how many bits have '
              'been made available: block_base',
              'restarts at 0 after every update() and output_base with every kl.exec.  '
              'For L = 4096, KMAC256 exports',
              'taken at output bits 1096 and 2184 differ only in `state` (all other '
              'fields equal: %s), yet 3000 and' % same_rest,
              '1912 bits remain.  The harness keeps an extra counter (out_bits) and '
              'carries it out of band across',
              'export/import.  Suggested fix: a 32-bit output counter in the Internal '
              'State and the Serialized Content',
              '(e.g. in the 48-bit padding after block_base), zeroed on entering '
              '_Hash_Output_, or L counting down.')

    print()
    print('-- 10. States, transitions and expected Forms --')
    cases = []
    cl = absorbing_cl(128, KEY, TAG, DATA4)
    cases.append(('KMAC128 Form B kl.setst with L = 0 -> _Invalid_',
                  cl.setst(KL_STATE_HASH_OUTPUT, form='B', aux=0) == 'invalid'
                  and cl.st == KL_STATE_INVALID))
    cl = absorbing_cl(128, KEY, TAG, DATA4)
    cases.append(('KMAC128 Form A kl.setst to _Hash_Output_ -> _Invalid_ (Form B '
                  'expected)', cl.setst(KL_STATE_HASH_OUTPUT) == 'invalid'))
    cl = absorbing_cl(256, KEY, TAG, DATA4, xof=True)
    cases.append(('KMACXOF256 Form B kl.setst to _Hash_Output_ -> _Invalid_ (Form A '
                  'expected)',
                  cl.setst(KL_STATE_HASH_OUTPUT, form='B', aux=512) == 'invalid'))
    cl = new_cl(128, KEY, TAG)
    cases.append(('kl.exec in _Ready_ -> _Invalid_ (SGR2)',
                  cl.exec_('B', inp=DATA4) == 'invalid'))
    cl = new_cl(128, KEY, TAG)
    cases.append(('Form B kl.setst entering _Hash_Absorb_ -> _Invalid_',
                  cl.setst(KL_STATE_HASH_ABSORB, form='B', aux=32) == 'invalid'))
    cl = absorbing_cl(128, KEY, TAG, DATA4)
    cases.append(('same-State kl.setst in _Hash_Absorb_ -> _Invalid_',
                  cl.setst(KL_STATE_HASH_ABSORB) == 'invalid'))
    cl = squeezing_cl(128, KEY, TAG, DATA4, 256)
    cases.append(('Form B kl.exec in _Hash_Output_ -> _Invalid_ (MGR1)',
                  cl.exec_('B', inp=DATA4) == 'invalid'))
    cl = squeezing_cl(128, KEY, TAG, DATA4, 256)
    cl.exec_('C', out=bytearray(32))
    out = bytearray(b'\xee' * 32)
    cases.append(('kl.exec in _Success_ -> _Invalid_, output window zeroed (SGR5)',
                  cl.exec_('C', out=out) == 'invalid' and out == bytearray(32)))
    for label, ok in cases:
        check_true(label, ok)
    # _Ready_ re-absorbs cshake_block and key_block: a CC reused after _Success_
    cl = squeezing_cl(128, KEY, TAG, DATA200, 256)
    cl.exec_('C', out=bytearray(32))
    cl.setst(KL_STATE_READY)
    cl.setst(KL_STATE_HASH_ABSORB)
    cl.exec_('B', inp=DATA4)
    to_output(cl, 256)
    out = bytearray(32)
    cl.exec_('C', out=out)
    check('_Success_ -> _Ready_ re-initialises KMAC128 (sample #2 after sample #3)',
          bytes(out), bytes.fromhex(SAMPLES[1][7]))
    cl = absorbing_cl(256, KEY, b'', DATA200[:50], xof=True)
    cl.setst(KL_STATE_READY)
    cl.setst(KL_STATE_HASH_ABSORB)
    cl.exec_('B', inp=DATA200)
    to_output(cl, 0)
    out = bytearray(64)
    cl.exec_('C', out=out)
    check('_Hash_Absorb_ -> _Ready_ re-initialises KMACXOF256 (sample #5)',
          bytes(out), bytes.fromhex(SAMPLES[10][7]))
    info('an auxiliary L of 2^32 or more (the Form B operand is XLEN bits, the field '
         '32) is not exercised: the',
         'text does not say whether it is truncated or rejected.  _KeyType_ = 1 (a '
         'SKID in place of key_block, MGR8)',
         'is not exercised either: [[KLEE-KMAC]] gives no PI/SCC layout for it.')

    print()
    print('-- 11. provisioning, Provisioning Input and Serialized Content --')
    for sec, kmax, smax in ((128, 163, 157), (256, 131, 125)):
        cb, kb = provision_blocks(sec, bytes(kmax), bytes(smax))
        check_true('KMAC%d: |K|=%d and |S|=%d still fit one rate block'
                   % (sec, kmax, smax),
                   len(cb) == RATE[sec] and len(kb) == RATE[sec])
        too_long = False
        try:
            provision_blocks(sec, bytes(kmax + 1), b'')
        except ValueError:
            too_long = True
        check_true('KMAC%d: |K|=%d overflows the key block (table bound is tight)'
                   % (sec, kmax + 1), too_long)
        too_long = False
        try:
            provision_blocks(sec, bytes(16), bytes(smax + 1))
        except ValueError:
            too_long = True
        check_true('KMAC%d: |S|=%d overflows the cSHAKE block (table bound is '
                   'tight)' % (sec, smax + 1), too_long)
    for sec, pi_len, c1_bits, c1_len in ((128, 352, 4480, 560), (256, 288, 3968, 496)):
        b = 8 * RATE[sec]
        pi = make_pi(sec, False, KEY, TAG)
        cb, kb = provision_blocks(sec, KEY, TAG)
        check_true('KMAC%d PI = MDH @ [0,16) || cshake_block @ [16,%d) || key_block '
                   '@ [%d,%d); kl.size = %d' % (sec, 16 + b // 8, 16 + b // 8,
                                                pi_len, pi_len),
                   len(pi) == pi_len == kl_size(KL_STATE_UNCONFIGURED, b)
                   and pi[16:16 + b // 8] == cb and pi[16 + b // 8:] == kb)
        check_true('KMAC%d Serialized Content = 1696 + 2b bits, zero-padded to %d '
                   '(%d B); kl.size of the SCC = %d'
                   % (sec, c1_bits, c1_len, 32 + c1_len),
                   content1_size(b) == c1_len and 8 * c1_len == c1_bits
                   and kl_size(KL_STATE_READY, b) == 32 + c1_len)
        cl = squeezing_cl(sec, KEY, TAG, DATA4, 1234)
        cl.exec_('C', out=bytearray(8))
        ct = cl.export_content()
        w = b // 8
        check_true('KMAC%d layout: state [0,200), block_base [200,202) = 64, zero '
                   '[202,208), cshake_block, key_block, L = 1234 at [%d,%d), zero '
                   'padding' % (sec, 208 + 2 * w, 212 + 2 * w),
                   ct[:200] == v2b(cl.state, 200) and ct[200:202] == v2b(64, 2)
                   and ct[202:208] == bytes(6) and ct[208:208 + w] == cb
                   and ct[208 + w:208 + 2 * w] == kb
                   and ct[208 + 2 * w:212 + 2 * w] == v2b(1234, 4)
                   and ct[212 + 2 * w:] == bytes(c1_len - 212 - 2 * w))
    # round trips
    trips = [
        ('KMAC128 in _Ready_', 128, False, None, None, None,
         bytes.fromhex(SAMPLES[2][7])),
        ('KMAC128 in _Hash_Absorb_ at block_base 800', 128, False, 100, None, None,
         bytes.fromhex(SAMPLES[2][7])),
        ('KMAC256 in _Hash_Output_ at block_base 160 (L = 512)', 256, False, 200, 512,
         20, bytes.fromhex(SAMPLES[5][7])),
        ('KMACXOF256 in _Hash_Output_ at block_base 0', 256, True, 200, 0, 136,
         ref_kmac(256, KEY, DATA200, 0, TAG, xof=True, out_bytes=300)),
    ]
    for label, sec, xof, n_abs, L, n_out, want in trips:
        cl = new_cl(sec, KEY, TAG, xof)
        head = b''
        if n_abs is not None:
            cl.setst(KL_STATE_HASH_ABSORB)
            cl.exec_('B', inp=DATA200[:n_abs])
        if n_out is not None:
            to_output(cl, L)
            o = bytearray(n_out)
            cl.exec_('C', out=o)
            head = bytes(o)
        cl2 = KleeKmacCL(Hart())
        cl2.import_scc(cl.mdh(), cl.export_content())
        if n_abs is None:
            cl2.setst(KL_STATE_HASH_ABSORB)
            cl2.exec_('B', inp=DATA200)
        elif n_out is None:
            cl2.exec_('B', inp=DATA200[n_abs:])
        if n_out is None:
            to_output(cl2, 256)
        o = bytearray(len(want) - len(head))
        cl2.exec_('C', out=o)
        check('export/import round trip, %s' % label, head + bytes(o), want)
    cl = squeezing_cl(256, KEY, TAG, DATA200, 4096)
    o1 = bytearray(300)
    cl.exec_('C', out=o1)
    cl2 = KleeKmacCL(Hart())
    cl2.import_scc(cl.mdh(), cl.export_content(), out_bits=cl.out_bits)
    o2 = bytearray(212)
    st = cl2.exec_('C', out=o2)
    check('export/import round trip, KMAC256 L = 4096 after 2 update()s (output '
          'counter carried out of band)', bytes(o1) + bytes(o2),
          ref_kmac(256, KEY, DATA200, 4096, TAG))
    check_true('... and the imported CL reaches _Success_ at bit 4096',
               st == 'success' and cl2.st == KL_STATE_SUCCESS, (st, cl2.st))

    print()
    print('-- 12. kl.derive: KMAC is no endpoint ([[KLEE-derive-endpoints]]) --')
    hart = Hart()
    src = squeezing_cl(128, KEY, TAG, DATA4, 0, xof=True, hart=hart)
    dst = absorbing_cl(128, KEY, TAG, DATA4, hart=hart)
    st = kl_derive_kmac(hart, dst, src, 32)
    check_true('kl.derive KMACXOF128 output -> KMAC128 absorb: both CLs transition to '
               '_Invalid_, klstart = 0', st == 'invalid'
               and src.st == dst.st == KL_STATE_INVALID and hart.klstart == 0,
               (st, src.st, dst.st))
    spec_note('[[KLEE-derive-endpoints]] lists no `kl.exec` endpoint for '
              '[[KLEE-KMAC]], although its _Hash_Absorb_',
              'and _Hash_Output_ are those of [[KLEE-SHA-3]], which has both, and '
              'KMAC/KMACXOF is an approved KDF',
              '(SP 800-108r1).  Suggested: list `kl.exec` output (0) and input into '
              '_Hash_Absorb_ (0) for KMAC, or',
              'state why they are excluded (the section is marked work in progress).')

    print()
    print('-- 13. negative controls --')
    print('KAT-EXPECT-FAIL: left_encode')
    print('KAT-EXPECT-FAIL: suffix D')
    print('KAT-EXPECT-FAIL: M4 literal units')
    print('KAT-EXPECT-FAIL: unpadded last byte')
    print('KAT-EXPECT-FAIL: serialized field order')
    got, _ = kl_kmac(128, KEY, DATA4, 256, TAG, use_left_encode=True)
    negative_control('left_encode (left_encode(L) absorbed instead of '
                     'right_encode(L), KMAC128 #2)',
                     got != bytes.fromhex(SAMPLES[1][7]))
    got, _ = kl_kmac(256, KEY, DATA200, 512, TAG, use_left_encode=True)
    negative_control('left_encode (KMAC256 #6)',
                     got != bytes.fromhex(SAMPLES[5][7]))
    got, _ = kl_kmac(128, KEY, DATA4, 256, TAG, wrong_suffix=True)
    negative_control('suffix D (raw SHAKE 1111 instead of the cSHAKE 00)',
                     got != bytes.fromhex(SAMPLES[1][7]))
    got, _ = kl_kmac(128, KEY, DATA200, 256, TAG, chunks=[DATA200],
                     interrupt=(0, 100), literal_units=True)
    negative_control('M4 literal units (klstart bit count consumed as bytes)',
                     got != bytes.fromhex(SAMPLES[2][7]))
    mism = False
    for L in (250, 1001):
        got, _ = kl_kmac(128, KEY, DATA4, L, TAG, raw_last_byte=True)
        mism = mism or got != ref_kmac(128, KEY, DATA4, L, TAG)
    negative_control('unpadded last byte (ceil(L/8) raw bytes for L = 250, 1001)',
                     mism)
    cl = absorbing_cl(128, KEY, TAG, DATA200[:100])
    cl2 = KleeKmacCL(Hart())
    cl2.import_scc(cl.mdh(), cl.export_content(order_by_at=True))
    cl2.exec_('B', inp=DATA200[100:])
    to_output(cl2, 256)
    out = bytearray(32)
    cl2.exec_('C', out=out)
    negative_control('serialized field order (Serialized Content built with @)',
                     bytes(out) != bytes.fromhex(SAMPLES[2][7]))

    print()
    print('summary: %d passed, %d failed, negative controls %s'
          % (_n_pass, _n_fail, 'fired' if _controls_ok else 'DID NOT FIRE'))
    ok = _n_fail == 0 and _controls_ok
    print('KAT-RESULT: %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
