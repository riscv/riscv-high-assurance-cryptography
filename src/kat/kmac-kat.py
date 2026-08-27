#!/usr/bin/env python3
"""KAT harness for the ACE KMAC rules (KMAC128/256, KMACXOF128/256).

What is validated (spec anchors in src/ace-ISA-algorithms.adoc, by heading):
  [[ACE-KMAC]]             -- the CC holds two provisioner-prepared rate-sized
                              blocks, cshake_block = bytepad(encode_string("KMAC")
                              || encode_string(S), b/8) and key_block =
                              bytepad(encode_string(K), b/8), each XORed into the
                              rate and followed by P() in State _Ready_;
                              right_encode(L) absorbed on the transition to
                              _Hash_Output_, continuing from the current
                              block_base; the cSHAKE suffix D = 00 with pad10*1;
                              exactly ceil(L/8) bytes for KMAC (then _Success_),
                              unlimited output for KMACXOF (which uses L = 0, so
                              right_encode(0) is absorbed).
  [[ACE-SHA-3]]            -- inherited: direct XOR absorption, P(), the
                              one-block / two-block padding clauses.
  [[ACE-process-VLI]]      -- chunked absorption across several ace.exec
                              transfers, partial-block boundaries, and the
                              interruption/resumption point (acestart).
  [[ACE-hash-functions]]   -- the _Hash_Output_ squeeze loop, multi-exec output
                              and resumption via output_base <- 8*acestart.
  src/ace-notation.adoc    -- FIPS 202 row: direct mapping of the absorbed
                              string, lanes little-endian.

Layered anchoring:
  1. Keccak-f[1600] implemented FROM SCRATCH here (round constants and rho
     offsets are the well-known FIPS 202 tables), anchored by embedded FIPS 202
     SHA3-256 / SHAKE128 / SHAKE256 known answers.
  2. An SP 800-185 reference (left_encode / right_encode / encode_string /
     bytepad / cSHAKE / KMAC), anchored by the embedded official NIST sample
     outputs.
  3. The ACE model (state machine from the spec text) checked against the same
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
  process_VLI used to store `acestart <- input_base` (a BIT count) although
  acestart is architecturally a BYTE count.  The spec now converts explicitly
  (`acestart <- input_base / 8`, resume at `input_base <- 8 * acestart`), which
  is what this harness models.

Negative controls (must mismatch, declared via KAT-EXPECT-FAIL):
  * left_encode  -- left_encode(L) absorbed in place of right_encode(L).
  * suffix D     -- the raw SHAKE suffix 1111 in place of the cSHAKE suffix 00.
  * M4 literal units -- acestart written as a bit count, consumed as bytes.

Verdict: per-case PASS/FAIL lines and a final `KAT-RESULT: PASS|FAIL`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl        # ACE value conventions (do not modify common.py)

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
    """KECCAK-p[1600,24] on a 1600-bit ACE value (lane (x,y) at bits
    [64*(5y+x)+63 : 64*(5y+x)], each lane little-endian -- the identity on the
    ACE little-endian integer of the state byte string)."""
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
    """SP 800-185 2.3.1 as restated in [[ACE-KMAC]]: x as an unsigned big-endian
    integer on the smallest positive number m of bytes, followed by a byte m."""
    n = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, 'big') + bytes([n])


def encode_string(s):
    return left_encode(8 * len(s)) + s


def bytepad(x, w):
    z = left_encode(w) + x
    return z + bytes((-len(z)) % w)


RATE = {128: 168, 256: 136}             # b/8 in bytes; c = 256 / 512
CAP_RATE_BITS = {128: 1344, 256: 1088}


def ref_kmac(sec, K, X, L, S=b'', xof=False, out_bytes=None):
    """SP 800-185 4.3 KMAC / 4.3.1 KMACXOF: cSHAKE(bytepad(encode_string(K), w)
    || X || right_encode(L or 0), L, "KMAC", S)."""
    w = RATE[sec]
    newX = bytepad(encode_string(K), w) + X + right_encode(0 if xof else L)
    prefix = bytepad(encode_string(b"KMAC") + encode_string(S), w)
    n = out_bytes if out_bytes is not None else (L + 7) // 8
    return ref_sponge(8 * w, prefix + newX, (0, 0), n)      # cSHAKE suffix 00


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


# ----------------------------------------------------------------- ACE CC model
class AceKmacCC:
    """Model of an ACE KMAC crypto context, implemented literally from
    [[ACE-KMAC]] on top of [[ACE-SHA-3]] / [[ACE-hash-functions]] /
    [[ACE-process-VLI]].

    block == state for the whole SHA-3 family, so absorbed data is XORed
    directly into the rate at block_base (state_offset = 0), and process_VLI
    runs with len = 0 (no enforced maximum).
    """

    D_CSHAKE = (0, 0)                   # cSHAKE domain-separation suffix

    def __init__(self, sec, cshake_block, key_block, xof, wrong_suffix=False):
        self.b = 8 * RATE[sec]
        self.t = self.b                 # t = b for KMAC and KMACXOF
        self.xof = xof
        self.D = (1, 1, 1, 1) if wrong_suffix else self.D_CSHAKE
        self.L = 0
        self.state = 0                  # State _Ready_: state is zeroed
        self.block_base = 0             # bits
        self.acestart = 0               # BYTES (architectural; M4-corrected)
        self.emitted = 0                # bits made available in _Hash_Output_
        self.mstate = 'Ready'
        self.pad_case = None
        # State _Ready_, steps 2 and 3: the two provisioner-prepared blocks.
        assert len(cshake_block) == self.b // 8 and len(key_block) == self.b // 8
        self.state ^= b2v(cshake_block)
        self.state = keccak_f1600(self.state)
        self.state ^= b2v(key_block)
        self.state = keccak_f1600(self.state)

    # -- ace.setst (Form A): _Ready_ -> _Hash_Absorb_
    def setst_absorb(self):
        assert self.mstate == 'Ready', self.mstate
        self.mstate = 'Hash_Absorb'

    def _vli_loop(self, INPUT, acelen_bits, input_base, interrupt_at_byte,
                  literal_units):
        while input_base < acelen_bits:
            amount = min(acelen_bits - input_base, self.b - self.block_base)
            chunk = sl(INPUT, input_base + amount - 1, input_base)
            self.state ^= chunk << self.block_base
            input_base += amount
            self.block_base += amount
            if self.block_base == self.b:
                self.state = keccak_f1600(self.state)      # absorb() = P()
                self.block_base = 0
            # process_VLI interruption point.  The literal text says
            # "acestart <- input_base" with input_base in BITS, while acestart is
            # architecturally a byte count (<<ACE-CSR-acestart>>); the
            # corrected reading acestart <- input_base/8 is used here.
            if (interrupt_at_byte is not None and input_base < acelen_bits
                    and input_base // 8 >= interrupt_at_byte):
                self.acestart = input_base if literal_units else input_base // 8
                return 'interrupted'
        return 'done'

    # -- ace.exec (Form B) in _Hash_Absorb_
    def exec_absorb(self, data, resume=False, interrupt_at_byte=None,
                    literal_units=False):
        assert self.mstate == 'Hash_Absorb', self.mstate
        INPUT = b2v(data) if data else 0
        # "If resuming an ace.exec instruction, then input_base <- acestart",
        # read with the M4 correction as input_base <- 8 * acestart.
        input_base = 8 * self.acestart if resume else 0
        return self._vli_loop(INPUT, 8 * len(data), input_base,
                              interrupt_at_byte, literal_units)

    def _absorb_string(self, data):
        """Absorb a byte string through the same process_VLI accounting,
        continuing from the current block_base (used for right_encode(L))."""
        self._vli_loop(b2v(data) if data else 0, 8 * len(data), 0, None, False)

    # -- ace.setst (Form B for KMAC, Form A for KMACXOF): -> _Hash_Output_
    def setst_output(self, L=0, use_left_encode=False):
        assert self.mstate == 'Hash_Absorb', self.mstate
        if self.xof:
            # Form A: L is assumed to be zero.
            assert L == 0
            self.L = 0
        else:
            assert L != 0, 'L must be non-zero (else Error State _Invalid_)'
            self.L = L
        enc = left_encode(self.L) if use_left_encode else right_encode(self.L)
        self._absorb_string(enc)                  # step 1, from current block_base
        # step 2: S = D || pad10*1 with D = 00 (cSHAKE), exactly as in ACE-SHA-3.
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
        self.block_base = 0
        self.emitted = 0
        self.mstate = 'Hash_Output'

    # -- ace.exec (Form C) in _Hash_Output_
    def exec_squeeze(self, out_bytes, resume=False, interrupt_at_byte=None):
        """Returns (status, start_byte, data).  status is 'done', 'interrupted'
        (acestart holds the resumption byte offset) or 'success' (KMAC delivered
        its ceil(L/8) bytes and transitioned to _Success_)."""
        assert self.mstate == 'Hash_Output', self.mstate
        acelen = 8 * out_bytes
        limit = None if self.xof else 8 * ((self.L + 7) // 8)
        output_base = 8 * self.acestart if resume else 0
        start_byte = output_base // 8
        OUTPUT = 0
        while output_base < acelen:
            amount = min(acelen - output_base, self.t - self.block_base)
            if limit is not None:
                amount = min(amount, limit - self.emitted)
            chunk = sl(self.state, self.block_base + amount - 1, self.block_base)
            OUTPUT |= chunk << (output_base - 8 * start_byte)
            output_base += amount
            self.block_base += amount
            self.emitted += amount
            if limit is not None and self.emitted == limit:
                # KMAC: exactly ceil(L/8) bytes made available, then _Success_.
                self.mstate = 'Success'
                return ('success', start_byte,
                        v2b(OUTPUT, output_base // 8 - start_byte))
            if self.block_base == self.t:
                self.state = keccak_f1600(self.state)       # update() = P()
                self.block_base = 0
                if (interrupt_at_byte is not None and output_base < acelen
                        and output_base // 8 >= interrupt_at_byte):
                    self.acestart = output_base // 8        # correct units here
                    return ('interrupted', start_byte,
                            v2b(OUTPUT, output_base // 8 - start_byte))
        return ('done', start_byte, v2b(OUTPUT, out_bytes - start_byte))


def provision(sec, K, S):
    """What the provisioner puts into the Provisioning Input, per [[ACE-KMAC]]."""
    w = RATE[sec]
    cshake_block = bytepad(encode_string(b"KMAC") + encode_string(S), w)
    key_block = bytepad(encode_string(K), w)
    assert len(cshake_block) == w, 'customization string exceeds one rate block'
    assert len(key_block) == w, 'key exceeds one rate block'
    return cshake_block, key_block


def ace_kmac(sec, K, X, L, S=b'', xof=False, out_bytes=None, chunks=None,
             interrupt=None, use_left_encode=False, wrong_suffix=False,
             literal_units=False):
    cb, kb = provision(sec, K, S)
    cc = AceKmacCC(sec, cb, kb, xof, wrong_suffix=wrong_suffix)
    cc.setst_absorb()
    for i, ch in enumerate(chunks if chunks is not None else [X]):
        intr = interrupt[1] if (interrupt and interrupt[0] == i) else None
        st = cc.exec_absorb(ch, interrupt_at_byte=intr, literal_units=literal_units)
        if st == 'interrupted':
            st = cc.exec_absorb(ch, resume=True, literal_units=literal_units)
    cc.setst_output(0 if xof else L, use_left_encode=use_left_encode)
    n = out_bytes if out_bytes is not None else (L + 7) // 8
    status, start, data = cc.exec_squeeze(n)
    assert start == 0
    return data, cc


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


# ------------------------------------------------------------------ test drive
def main():
    print('== kmac-kat: ACE KMAC/KMACXOF rules vs NIST SP 800-185 ==')
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
    print('-- 4. ACE model vs the official sample outputs --')
    for label, sec, xof, K, X, S, L, exp in SAMPLES:
        want = bytes.fromhex(exp)
        got, cc = ace_kmac(sec, K, X, L, S, xof=xof, out_bytes=len(want))
        check('ACE model  %-20s' % label, got, want)
        if xof:
            check_true('ACE model  %-20s stays in _Hash_Output_ (never _Success_)'
                       % label, cc.mstate == 'Hash_Output', cc.mstate)
        else:
            check_true('ACE model  %-20s reached _Success_ after ceil(L/8) bytes'
                       % label, cc.mstate == 'Success', cc.mstate)

    print()
    print('-- 5. chunked absorption through process_VLI '
          '(granularity 32 bits, partial-block boundaries) --')
    # KMAC128 rate 168 B; the 200-B message crosses the block boundary.  The
    # 100-B transfer straddles it; the first two transfers end mid-block.
    want = bytes.fromhex(SAMPLES[2][7])
    got, _ = ace_kmac(128, KEY, DATA200, 256, TAG, out_bytes=32,
                      chunks=[DATA200[:68], DATA200[68:72], DATA200[72:172],
                              DATA200[172:]])
    check('ACE chunked KMAC128 sample #3 (68+4+100+28 B transfers)', got, want)
    # KMAC256 rate 136 B: 136 exactly fills the block at a transfer edge.
    want = bytes.fromhex(SAMPLES[5][7])
    got, _ = ace_kmac(256, KEY, DATA200, 512, TAG, out_bytes=64,
                      chunks=[DATA200[:136], DATA200[136:140], DATA200[140:]])
    check('ACE chunked KMAC256 sample #6 (136+4+60 B transfers)', got, want)
    # KMACXOF128 in many small transfers.
    want = bytes.fromhex(SAMPLES[8][7])
    got, _ = ace_kmac(128, KEY, DATA200, 256, TAG, xof=True, out_bytes=32,
                      chunks=[DATA200[i:i + 8] for i in range(0, 200, 8)])
    check('ACE chunked KMACXOF128 sample #3 (25 transfers of 8 B)', got, want)

    print()
    print('-- 6. interrupted/resumed absorption (M4-corrected acestart, bytes) --')
    cb, kb = provision(128, KEY, TAG)
    cc = AceKmacCC(128, cb, kb, xof=False)
    cc.setst_absorb()
    st = cc.exec_absorb(DATA200, interrupt_at_byte=100)
    check_true('KMAC128 absorb interrupted at the process_VLI interruption point',
               st == 'interrupted', st)
    check_true('acestart is a BYTE count = 168 (the rate; first interruption '
               'point)', cc.acestart == 168, 'acestart=%r' % cc.acestart)
    st = cc.exec_absorb(DATA200, resume=True)
    check_true('resumed exec completes', st == 'done', st)
    cc.setst_output(256)
    _, _, data = cc.exec_squeeze(32)
    check('KMAC128 sample #3 after interrupt/resume', data,
          bytes.fromhex(SAMPLES[2][7]))

    print()
    print('-- 7. right_encode(L) absorbed continuing from block_base --')
    # Instrumented: after a 200-B message at rate 168 the block_base is 32 B;
    # right_encode(256) = 01 00 02 must land at bits [8*32 .. 8*35].
    cb, kb = provision(128, KEY, TAG)
    cc = AceKmacCC(128, cb, kb, xof=False)
    cc.setst_absorb()
    cc.exec_absorb(DATA200)
    check_true('block_base after the 200-B message is 32 B (200 - 168)',
               cc.block_base == 8 * 32, 'block_base=%r' % cc.block_base)
    cc.setst_output(256)
    check_true('padding clause 1 fired (|S| = b - block_base after '
               'right_encode(256))', cc.pad_case == 1, 'case=%r' % cc.pad_case)
    # KMACXOF absorbs right_encode(0) = 00 01, two bytes shorter than
    # right_encode(256): the model and the reference must agree on both.
    for sec, xof, L in ((128, True, 0), (256, True, 0)):
        want = ref_kmac(sec, KEY, DATA4, 256, TAG, xof=True, out_bytes=32)
        got, _ = ace_kmac(sec, KEY, DATA4, 256, TAG, xof=True, out_bytes=32)
        check('KMACXOF%d absorbs right_encode(0) = 0001' % sec, got, want)

    print()
    print('-- 8. output-length semantics --')
    # (a) KMAC output truncation: a shorter L is NOT a prefix of a longer one
    #     (L enters the absorbed right_encode(L)) -- each L is its own function.
    a = ref_kmac(128, KEY, DATA4, 256, TAG)
    b_ = ref_kmac(128, KEY, DATA4, 512, TAG)
    check_true('KMAC128 L=512 output is not an extension of L=256 (L is absorbed)',
               b_[:32] != a)
    got, cc = ace_kmac(128, KEY, DATA4, 512, TAG)
    check('ACE model KMAC128 L=512 vs reference', got, b_)
    check_true('KMAC128 L=512 delivered 64 B then _Success_',
               len(got) == 64 and cc.mstate == 'Success', cc.mstate)
    # (b) L not a multiple of 8: ceil(L/8) bytes are delivered.
    for L in (255, 250, 257, 1000):
        nb = (L + 7) // 8
        want = ref_kmac(128, KEY, DATA4, L, TAG)
        got, cc = ace_kmac(128, KEY, DATA4, L, TAG)
        check('KMAC128 L=%4d delivers ceil(L/8)=%d bytes' % (L, nb), got, want)
        check_true('KMAC128 L=%4d reached _Success_' % L,
                   cc.mstate == 'Success' and len(got) == nb, cc.mstate)
    print('NOTE: spec observation -- [[ACE-KMAC]] says that for L not a multiple '
          'of 8 "the last byte may be zero-padded in')
    print('      its significant bits".  The spec\'s own squeeze loop copies raw '
          'state bits, so the excess bits of the last')
    print('      byte are squeeze output, not zeros; SP 800-185 defines only the '
          'L significant bits.  The wording should say')
    print('      "non-significant bits", and should state whether the excess bits '
          'are zeroed or left as squeezed.  Both')
    print('      readings agree on the L significant bits, which is what is '
          'checked here.')
    # Both readings agree on the significant bits:
    for L in (255, 250, 257):
        got, _ = ace_kmac(128, KEY, DATA4, L, TAG)
        want = ref_kmac(128, KEY, DATA4, L, TAG)
        mask = (1 << (L % 8)) - 1 if L % 8 else 0xFF
        check_true('KMAC128 L=%4d: the L significant bits agree with SP 800-185'
                   % L, got[:L // 8] == want[:L // 8]
                   and (got[-1] & mask) == (want[-1] & mask))
    # (c) KMACXOF squeezes indefinitely across execs, with interrupt/resume.
    want = ref_kmac(128, KEY, DATA200, 0, TAG, xof=True, out_bytes=600)
    check_true('KMACXOF128 sample #3 prefix matches the official 32-B output',
               want[:32] == bytes.fromhex(SAMPLES[8][7]))
    cb, kb = provision(128, KEY, TAG)
    cc = AceKmacCC(128, cb, kb, xof=True)
    cc.setst_absorb()
    cc.exec_absorb(DATA200)
    cc.setst_output(0)
    out = b''
    for n in (32, 100, 168, 300):
        status, start, data = cc.exec_squeeze(n)
        assert status == 'done' and start == 0, (status, start)
        out += data
    check('KMACXOF128 600-B squeeze across execs of 32+100+168+300 B', out, want)
    check_true('KMACXOF128 still in _Hash_Output_ after 600 B',
               cc.mstate == 'Hash_Output', cc.mstate)
    # interrupted squeeze
    cc = AceKmacCC(128, cb, kb, xof=True)
    cc.setst_absorb()
    cc.exec_absorb(DATA200)
    cc.setst_output(0)
    status, start, first = cc.exec_squeeze(400, interrupt_at_byte=1)
    check_true('KMACXOF128 squeeze interrupted after one rate',
               status == 'interrupted' and start == 0, (status, start))
    check_true('acestart = output_base/8 = 168', cc.acestart == 168,
               'acestart=%r' % cc.acestart)
    status, start, rest = cc.exec_squeeze(400, resume=True)
    check_true('resumed squeeze restarts at byte 168',
               status == 'done' and start == 168, (status, start))
    check('KMACXOF128 400-B squeeze with interrupt/resume', first + rest,
          want[:400])
    # (d) KMAC output split across execs, _Success_ on the last byte.
    cb2, kb2 = provision(256, KEY, TAG)
    cc = AceKmacCC(256, cb2, kb2, xof=False)
    cc.setst_absorb()
    cc.exec_absorb(DATA4)
    cc.setst_output(512)
    s1, _, d1 = cc.exec_squeeze(20)
    check_true('KMAC256 20-B partial output, still in _Hash_Output_',
               s1 == 'done' and cc.mstate == 'Hash_Output', (s1, cc.mstate))
    s2, _, d2 = cc.exec_squeeze(44)
    check_true('KMAC256 reaches _Success_ on the 64th byte',
               s2 == 'success' and cc.mstate == 'Success', (s2, cc.mstate))
    check('KMAC256 sample #4 split 20+44 B', d1 + d2,
          bytes.fromhex(SAMPLES[3][7]))
    # (e) an OUTPUT longer than ceil(L/8): only ceil(L/8) bytes are written.
    cc = AceKmacCC(256, cb2, kb2, xof=False)
    cc.setst_absorb()
    cc.exec_absorb(DATA4)
    cc.setst_output(512)
    s, _, d = cc.exec_squeeze(200)
    check_true('KMAC256 200-B exec returns at _Success_ with only 64 B written',
               s == 'success' and len(d) == 64, (s, len(d)))
    check('KMAC256 sample #4 from an oversized exec', d,
          bytes.fromhex(SAMPLES[3][7]))
    # (f) L > b: output spans several applications of P().
    want = ref_kmac(256, KEY, DATA200, 4096, TAG)
    got, cc = ace_kmac(256, KEY, DATA200, 4096, TAG)
    check('KMAC256 L=4096 (512 B, 4 rates of 136 B) vs reference', got, want)
    check_true('KMAC256 L=4096 reached _Success_', cc.mstate == 'Success')

    print()
    print('-- 9. provisioning bounds of [[ACE-KMAC]] --')
    for sec, kmax, smax in ((128, 163, 157), (256, 131, 125)):
        cb, kb = provision(sec, bytes(kmax), bytes(smax))
        check_true('KMAC%d: |K|=%d and |S|=%d still fit one rate block'
                   % (sec, kmax, smax),
                   len(cb) == RATE[sec] and len(kb) == RATE[sec])
        too_long = False
        try:
            provision(sec, bytes(kmax + 1), b'')
        except AssertionError:
            too_long = True
        check_true('KMAC%d: |K|=%d overflows the key block (table bound is tight)'
                   % (sec, kmax + 1), too_long)
        too_long = False
        try:
            provision(sec, bytes(16), bytes(smax + 1))
        except AssertionError:
            too_long = True
        check_true('KMAC%d: |S|=%d overflows the cSHAKE block (table bound is '
                   'tight)' % (sec, smax + 1), too_long)

    print()
    print('-- 10. negative controls --')
    print('KAT-EXPECT-FAIL: left_encode')
    print('KAT-EXPECT-FAIL: suffix D')
    print('KAT-EXPECT-FAIL: M4 literal units')
    got, _ = ace_kmac(128, KEY, DATA4, 256, TAG, use_left_encode=True)
    negative_control('left_encode (left_encode(L) absorbed instead of '
                     'right_encode(L), KMAC128 #2)',
                     got != bytes.fromhex(SAMPLES[1][7]))
    got, _ = ace_kmac(256, KEY, DATA200, 512, TAG, use_left_encode=True)
    negative_control('left_encode (KMAC256 #6)',
                     got != bytes.fromhex(SAMPLES[5][7]))
    got, _ = ace_kmac(128, KEY, DATA4, 256, TAG, wrong_suffix=True)
    negative_control('suffix D (raw SHAKE 1111 instead of the cSHAKE 00)',
                     got != bytes.fromhex(SAMPLES[1][7]))
    got, _ = ace_kmac(128, KEY, DATA200, 256, TAG, chunks=[DATA200],
                      interrupt=(0, 100), literal_units=True)
    negative_control('M4 literal units (acestart bit count consumed as bytes)',
                     got != bytes.fromhex(SAMPLES[2][7]))
    print('NOTE: former spec discrepancy M4, since fixed -- '
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
