#!/usr/bin/env python3
"""SHA-2 family KAT for the ACE specification (<<ACE-SHA-2>> over <<ACE-hash-functions>>).

WHAT IS MODELED (from the spec text, not from FIPS directly):
  * _Hash_Absorb_ runs Subalgorithm process_VLI (<<ACE-process-VLI>>) with len = 0
    (no max_length), block separate from state, state_offset = 0: the message is
    accumulated into `block` across ace.exec boundaries and `absorb()` fires each
    time block_base reaches b.
  * The j-th message word of a block is int(bswap(block[(j+1)w-1 : jw])) and the
    digest places the i-th chaining variable at bytes i*w/8 as bswap(bin(H_i, w)),
    truncated to t bits (<<ACE-SHA-2>>, "Endianness").
  * Padding and length encoding are performed by the CALLER (finalize = None for
    stand-alone hashing); on the transition to _Hash_Output_ the model enforces
    block_base = 0 and otherwise raises Error State _Invalid_.
  * _Hash_Output_ implements the generic squeeze loop of <<ACE-hash-functions>>
    (block[t-1:0] <- digest, then per-instruction copy with amount =
    min(ACELEN - output_base, t - block_base), Success at block_base = t); the
    digest is read out across two Form C ace.exec instructions in one plan.
  * Interruption/resumption of a Form B ace.exec is exercised at every
    interruption point of process_VLI.  M4 (ACE-spec-review-0.7.0.md): the spec
    literally writes `acestart <- input_base` and `input_base <- acestart`, a bit
    count in the byte-counting acestart CSR; this model uses the CORRECTED
    interpretation acestart <- input_base/8 and input_base <- 8*acestart, mirroring
    the explicit /8 and *8 that _Hash_Output_ already performs.

COMPRESSION CORES are implemented from scratch (FIPS 180-4 sect. 6): both the
32-bit (SHA-224/256) and 64-bit (SHA-384/512/512-224/512-256) cores.  Round
constants and initial hash values are derived from the fractional parts of the
roots of the primes with exact integer arithmetic (FIPS 180-4 sect. 4.2.2/5.3),
and the SHA-512/t IVs by the sect. 5.3.6 generation procedure, spot-checked
against the published constants.

VECTORS (embedded; provenance): FIPS 180-4 / NIST CSRC "Examples with
Intermediate Values" test strings: the empty string, "abc", the two-block
448-bit message "abcdbcde..." for the 32-bit family and the two-block 896-bit
message "abcdefghbcdefghi..." for the 64-bit family, with their published
digests.  hashlib is used ONLY as an independent reference oracle, clearly
labeled; the ACE model never calls it.

NEGATIVE CONTROL (KAT-EXPECT-FAIL: no-bswap): the same model with the bswap
omitted from the message-word extraction must NOT reproduce the FIPS vector.
"""
import os, sys, math, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl, bswap, bin_

import hashlib  # independent reference oracle ONLY -- never used by the ACE model

T0 = time.time()

# ------------------------------------------------------- FIPS 180-4 constants
# Derived with exact integer arithmetic from the fractional parts of the cube /
# square roots of the primes (FIPS 180-4 sect. 4.2.2, 5.3), then spot-checked.

def _primes(k):
    ps, n = [], 2
    while len(ps) < k:
        if all(n % p for p in ps):
            ps.append(n)
        n += 1
    return ps

def _icbrt(n):
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            break
        x = y
    while x ** 3 > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x

def _frac_cbrt(p, w):
    return _icbrt(p << (3 * w)) & ((1 << w) - 1)

def _frac_sqrt(p, w):
    return math.isqrt(p << (2 * w)) & ((1 << w) - 1)

_P80 = _primes(80)
K256 = [_frac_cbrt(p, 32) for p in _P80[:64]]
K512 = [_frac_cbrt(p, 64) for p in _P80]
H256 = [_frac_sqrt(p, 32) for p in _P80[:8]]
H224 = [_frac_sqrt(p, 64) & 0xffffffff for p in _P80[8:16]]   # 2nd 32 bits (5.3.2)
H512 = [_frac_sqrt(p, 64) for p in _P80[:8]]
H384 = [_frac_sqrt(p, 64) for p in _P80[8:16]]                # 1st 64 bits (5.3.4)
assert K256[0] == 0x428a2f98 and K256[63] == 0xc67178f2       # FIPS 180-4 4.2.2
assert K512[0] == 0x428a2f98d728ae22 and K512[79] == 0x6c44198c4a475817
assert H256[0] == 0x6a09e667 and H256[7] == 0x5be0cd19        # FIPS 180-4 5.3.3
assert H224[0] == 0xc1059ed8 and H384[0] == 0xcbbb9d5dc1059ed8  # 5.3.2 / 5.3.4
assert H512[0] == 0x6a09e667f3bcc908 and H512[7] == 0x5be0cd19137e2179  # 5.3.5

# ------------------------------------------------------- compression (FIPS 180-4 sect. 6)

def sha2_compress(H, W16, w, K, rounds):
    if w == 32:
        s0, s1, S0, S1 = (7, 18, 3), (17, 19, 10), (2, 13, 22), (6, 11, 25)
    else:
        s0, s1, S0, S1 = (1, 8, 7), (19, 61, 6), (28, 34, 39), (14, 18, 41)
    M = (1 << w) - 1
    rotr = lambda x, r: ((x >> r) | (x << (w - r))) & M
    W = list(W16)
    for t in range(16, rounds):
        x, y = W[t - 15], W[t - 2]
        W.append((W[t - 16] + (rotr(x, s0[0]) ^ rotr(x, s0[1]) ^ (x >> s0[2]))
                  + W[t - 7] + (rotr(y, s1[0]) ^ rotr(y, s1[1]) ^ (y >> s1[2]))) & M)
    a, b, c, d, e, f, g, h = H
    for t in range(rounds):
        T1 = (h + (rotr(e, S1[0]) ^ rotr(e, S1[1]) ^ rotr(e, S1[2]))
              + ((e & f) ^ (~e & g & M)) + K[t] + W[t]) & M
        T2 = ((rotr(a, S0[0]) ^ rotr(a, S0[1]) ^ rotr(a, S0[2]))
              + ((a & b) ^ (a & c) ^ (b & c))) & M
        a, b, c, d, e, f, g, h = (T1 + T2) & M, a, b, c, (d + T1) & M, e, f, g
    return [(x + y) & M for x, y in zip(H, [a, b, c, d, e, f, g, h])]

def _sha512_be(msg, H0):
    """Byte-level big-endian SHA-512 core, used only for the 5.3.6 IV generation."""
    m = msg + b'\x80' + bytes((-(len(msg) + 17)) % 128) + (8 * len(msg)).to_bytes(16, 'big')
    H = list(H0)
    for i in range(0, len(m), 128):
        H = sha2_compress(H, [int.from_bytes(m[i + 8 * j: i + 8 * j + 8], 'big')
                              for j in range(16)], 64, K512, 80)
    return H

H512_224 = _sha512_be(b"SHA-512/224", [h ^ 0xa5a5a5a5a5a5a5a5 for h in H512])
H512_256 = _sha512_be(b"SHA-512/256", [h ^ 0xa5a5a5a5a5a5a5a5 for h in H512])
# published IVs, FIPS 180-4 sect. 5.3.6.1 / 5.3.6.2 (spot check of the generation)
assert H512_224[0] == 0x8c3d37c819544da2 and H512_224[7] == 0x1112e6ad91d692a1
assert H512_256[0] == 0x22312194fc2bf72c and H512_256[7] == 0x0eb72ddc81c52ca2

# ------------------------------------------------------- the ACE model

def set_slice(v, hi, lo, x):
    """v with v[hi:lo] <- x (the assignment form of the spec's bit slices)."""
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    return (v & ~mask) | ((x << lo) & mask)

class Invalid(Exception):
    """CR transition to Error State _Invalid_."""

class AceSha2:
    """One SHA-2 CC per <<ACE-SHA-2>>; values are ACE little-endian values."""

    def __init__(self, name, be_words=True):
        self.w, iv, self.t = FN[name]
        self.b, self.n = 16 * self.w, 8 * self.w
        self.K, self.rounds = (K256, 64) if self.w == 32 else (K512, 80)
        self.be_words = be_words
        # _Ready_: state <- IV (5.3), block_base/cumul_len/block zeroed
        self.state = list(iv)
        self.block = 0
        self.block_base = 0
        self.cumul_len = 0
        self.acestart = 0
        self.state_name = 'Hash_Absorb'     # after _Ready_ -> _Hash_Absorb_

    def _absorb(self):
        """absorb(): FIPS 180-4 compression; word j = int(bswap(block[(j+1)w-1:jw]))."""
        W = []
        for j in range(16):
            word = sl(self.block, (j + 1) * self.w - 1, j * self.w)
            W.append(bswap(word, self.w // 8) if self.be_words else word)
        self.state = sha2_compress(self.state, W, self.w, self.K, self.rounds)

    def exec_input(self, data, resume=False, interrupt_after=None):
        """Form B ace.exec in _Hash_Absorb_ = process_VLI(<<ACE-process-VLI>>), len=0.

        Granularity (32 bits) is a caller obligation; the driver's transfer plans
        respect it.  Returns 'done' or 'interrupted'."""
        assert self.state_name == 'Hash_Absorb'
        INPUT, ACELEN = b2v(data), 8 * len(data)
        if resume:
            # M4 (ACE-spec-review-0.7.0.md): spec literally `input_base <- acestart`
            # (bit count read from the byte-counting CSR); corrected: * 8.
            input_base = 8 * self.acestart
        else:
            input_base = 0
        iters = 0
        while input_base < ACELEN:
            # len = 0: amount = min(ACELEN - input_base, b - block_base)
            amount = min(ACELEN - input_base, self.b - self.block_base)
            # block != state: block[block_base+amount-1:block_base] <- INPUT[...]
            self.block = set_slice(self.block, self.block_base + amount - 1,
                                   self.block_base,
                                   sl(INPUT, input_base + amount - 1, input_base))
            input_base += amount
            self.block_base += amount
            self.cumul_len += amount
            if self.block_base == self.b:
                self._absorb()              # process_block()
                self.block_base = 0
            iters += 1
            # the (only) interruption point of process_VLI.
            # M4 (fixed): the spec now writes `acestart <- input_base / 8`.
            if interrupt_after is not None and iters >= interrupt_after \
                    and input_base < ACELEN:
                self.acestart = input_base // 8
                return 'interrupted'
        return 'done'

    def setst_output(self):
        """Form A ace.setst: _Hash_Absorb_ -> _Hash_Output_."""
        # <<ACE-SHA-2>>: stand-alone hashing requires block_base = 0 here.
        if self.block_base != 0:
            raise Invalid('block_base != 0 on entry to _Hash_Output_')
        # <<ACE-hash-functions>>: block[t-1:0] <- finalize(); block_base <- 0.
        # For SHA-2, the digest value has chaining variable i at bytes i*w/8
        # as bswap(bin(H_i, w)), truncated to t bits ("Endianness" paragraph).
        dig = 0
        for i, hi in enumerate(self.state):
            dig |= bswap(bin_(hi, self.w), self.w // 8) << (i * self.w)
        self.block = sl(dig, self.t - 1, 0)
        self.block_base = 0
        self.state_name = 'Hash_Output'

    def exec_output(self, nbytes):
        """Form C ace.exec squeeze loop of <<ACE-hash-functions>> _Hash_Output_."""
        assert self.state_name == 'Hash_Output'
        ACELEN, OUTPUT, output_base = 8 * nbytes, 0, 0
        while output_base < ACELEN:
            amount = min(ACELEN - output_base, self.t - self.block_base)
            OUTPUT |= sl(self.block, self.block_base + amount - 1,
                         self.block_base) << output_base
            output_base += amount
            self.block_base += amount
            if self.block_base == self.t:
                self.state_name = 'Success'   # hash function: -> _Success_, return
                break
        return v2b(OUTPUT, output_base // 8)

# ------------------------------------------------------- drivers

FN = {  # name: (w, IV, t)   [parameters of <<ACE-SHA-2-parameters>>]
    'SHA-224':     (32, H224,     224),
    'SHA-256':     (32, H256,     256),
    'SHA-384':     (64, H384,     384),
    'SHA-512':     (64, H512,     512),
    'SHA-512/224': (64, H512_224, 224),
    'SHA-512/256': (64, H512_256, 256),
}

def fips_pad(msg, w, b):
    """FIPS 180-4 sect. 5.1 padding, applied by the CALLER per <<ACE-SHA-2>>."""
    lb = 2 * w // 8
    return (msg + b'\x80' + bytes((-(len(msg) + 1 + lb)) % (b // 8))
            + (8 * len(msg)).to_bytes(lb, 'big'))

def ace_digest(name, msg, plan, be_words=True):
    """Run one message through the CC model.

    plan 'multi':     absorb the padded message in three ace.exec transfers cut at
                      non-block-aligned offsets (multiples of 4 bytes: granularity
                      32); read the digest with two Form C ace.exec instructions.
    plan 'interrupt': absorb in a single ace.exec that is interrupted at every
                      process_VLI interruption point and resumed via acestart
                      (M4-corrected units); read the digest in one instruction.
    """
    cc = AceSha2(name, be_words)
    mp = fips_pad(msg, cc.w, cc.b)
    if plan == 'multi':
        c1, c2 = 4, len(mp) // 2 - 8          # cuts inside a block, 4-byte multiples
        for piece in (mp[:c1], mp[c1:c1 + c2], mp[c1 + c2:]):
            assert cc.exec_input(piece) == 'done'
        cc.setst_output()
        out = cc.exec_output(cc.t // 8 - 8) + cc.exec_output(8)
    else:
        st = cc.exec_input(mp, interrupt_after=1)
        while st == 'interrupted':
            st = cc.exec_input(mp, resume=True, interrupt_after=1)
        cc.setst_output()
        out = cc.exec_output(cc.t // 8)
    assert cc.state_name == 'Success'
    return out

# Test strings: FIPS 180-4 / NIST CSRC examples.
M_EMPTY = b''
M_ABC = b'abc'
M2_32 = b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'          # 448 bits
M2_64 = (b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn'
         b'hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu')        # 896 bits

# Published digests (FIPS 180-4 examples / NIST CSRC "Examples with Intermediate
# Values"; SHA-512/t one-block values also in NIST's SHA512_224.pdf, SHA512_256.pdf).
VEC = {
    'SHA-224': {
        M_EMPTY: 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
        M_ABC:   '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
        M2_32:   '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525',
    },
    'SHA-256': {
        M_EMPTY: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        M_ABC:   'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        M2_32:   '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    },
    'SHA-384': {
        M_EMPTY: '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da'
                 '274edebfe76f65fbd51ad2f14898b95b',
        M_ABC:   'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed'
                 '8086072ba1e7cc2358baeca134c825a7',
        M2_64:   '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712'
                 'fcc7c71a557e2db966c3e9fa91746039',
    },
    'SHA-512': {
        M_EMPTY: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
                 '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        M_ABC:   'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
                 '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
        M2_64:   '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018'
                 '501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909',
    },
    'SHA-512/224': {
        M_EMPTY: '6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4',
        M_ABC:   '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa',
        M2_64:   '23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9',
    },
    'SHA-512/256': {
        M_EMPTY: 'c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a',
        M_ABC:   '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23',
        M2_64:   '3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a',
    },
}
HASHLIB = {'SHA-224': 'sha224', 'SHA-256': 'sha256', 'SHA-384': 'sha384',
           'SHA-512': 'sha512', 'SHA-512/224': 'sha512_224',
           'SHA-512/256': 'sha512_256'}
MNAME = {id(M_EMPTY): 'empty', id(M_ABC): '"abc"',
         id(M2_32): 'two-block (448b)', id(M2_64): 'two-block (896b)'}

ok = True
print('SHA-2 family per <<ACE-SHA-2>> / <<ACE-hash-functions>> / <<ACE-process-VLI>>')
print('NOTE (spec, M4): process_VLI resumption modeled with acestart = input_base/8,')
print('  the corrected byte-count interpretation of ACE-spec-review-0.7.0.md M4.\n')
print(f'{"function":13} {"message":18} {"multi-chunk":12} {"interrupted":12} {"oracle"}')
for name in FN:
    for msg, exp_hex in VEC[name].items():
        exp = bytes.fromhex(exp_hex)
        a = ace_digest(name, msg, 'multi')
        b = ace_digest(name, msg, 'interrupt')
        # hashlib: independent reference oracle only (never part of the ACE model)
        try:
            r = hashlib.new(HASHLIB[name], msg).digest()
            orac = 'PASS' if (r == exp) else 'FAIL'
        except ValueError:
            orac = 'n/a'
        ga, gb = a == exp, b == exp
        ok &= ga and gb and orac != 'FAIL'
        print(f'{name:13} {MNAME[id(msg)]:18} {"PASS" if ga else "FAIL":12} '
              f'{"PASS" if gb else "FAIL":12} {orac}')

# spec rule: unpadded input (block_base != 0) is rejected on entry to _Hash_Output_
cc = AceSha2('SHA-256')
cc.exec_input(b'abc')                       # 3 bytes: allowed as the last transfer
try:
    cc.setst_output()
    rejected = False
except Invalid:
    rejected = True
ok &= rejected
print(f'\nunpadded message rejected at _Hash_Output_ (block_base != 0 -> _Invalid_): '
      f'{"PASS" if rejected else "FAIL"}')

# negative control: word extraction without the spec's bswap must NOT match FIPS
print('KAT-EXPECT-FAIL: no-bswap')
bad = ace_digest('SHA-256', M_ABC, 'multi', be_words=False)
fired = bad != bytes.fromhex(VEC['SHA-256'][M_ABC])
print(f'no-bswap control, SHA-256("abc") vs FIPS vector: '
      f'{"FAIL (expected: control is effective)" if fired else "PASS (CONTROL IS DEAD)"}')
ok &= fired

print(f'\nruntime: {time.time() - T0:.2f} s')
print(f'KAT-RESULT: {"PASS" if ok else "FAIL"}')
sys.exit(0 if ok else 1)
