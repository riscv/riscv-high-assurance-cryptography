#!/usr/bin/env python3
"""HMAC KAT for the ACE specification (<<ACE-HMAC>> over <<ACE-SHA-2>>/<<ACE-SHA-3>>).

WHAT IS MODELED (from the spec text):
  * Both PI variants of <<ACE-HMAC>>.
    - NIK ("No Initial Key"): _Ready_ -> _Set_Key_ -> _Hash_Absorb_ -> ... ; in
      _Set_Key_ the b-bit K0 is loaded by one or more Form B ace.exec through
      process_VLI entered as process_VLI(b, block=K0, b, state=K0, n=b,
      input_base, block_base, 0, cumul_len, None, None, mode=assign).  The harness
      loads K0 in several transfers and interrupts/resumes one of them.
    - KIP ("Key in PI"): K0 arrives in the Provisioning Input; _Set_Key_ is absent
      and any attempt to re-key is refused (a KIP CC cannot be re-keyed).
  * K0 itself is FIPS 198-1 sect. 3: the key zero-padded to b bits, or hashed by H
    first if longer than b bits.  Per <<ACE-HMAC>> this derivation is the
    PROVISIONER's job, so it is done outside the CC model, in provisioner_K0().
  * Entering _Hash_Absorb_: state <- IV of H, then `key xor ipad` is absorbed; the
    message then follows the underlying hash's own semantics (process_VLI).
  * Entering _Hash_Output_: finalize the inner hash, inner <- state[d-1:0],
    reinitialize state, absorb `key xor opad`, absorb inner, finalize.  Under HMAC
    the SHA-2/SM3 padding is applied INTERNALLY over the total absorbed length,
    b + cumul_len bits for the inner hash and b + d bits for the outer, using
    cumul_len (which is maintained only under HMAC) -- <<ACE-HMAC>> and the
    finalize() clause of <<ACE-SHA-2>>.  The tag is then squeezed by the generic
    _Hash_Output_ loop of <<ACE-hash-functions>>.
  * M4 (earlier review, since fixed): process_VLI stores the bit count input_base into
    the byte-counting acestart CSR.  The corrected interpretation
    (acestart = input_base/8, input_base = 8*acestart) is used throughout, and is
    exercised by the interrupted _Set_Key_ and _Hash_Absorb_ transfers.

CORES.  SHA-224/256/384/512 are implemented FROM SCRATCH here (FIPS 180-4 sect. 6
compression, IVs and round constants derived by exact integer arithmetic from the
roots of the primes), and the ACE model uses only those.  For HMAC-SHA-3 the ACE
model calls hashlib's sha3_* as the underlying H -- <<ACE-HMAC>> delegates H to
<<ACE-SHA-3>>, which this harness does not re-derive; the HMAC LAYER (K0 padding to
the sponge rate b, ipad/opad, inner/outer flow, state machine) is still the model's
own.  This is noted as the one place where a library primitive sits inside the model.

For HMAC-SHA-3, <<ACE-HMAC>> defines b as "the input block size of the underlying
hash function", which for a sponge is the RATE of <<ACE-SHA-3-parameters>>
(1088 bits for SHA3-256, 576 for SHA3-512).  That reading is confirmed here against
the reference oracle; the alternative reading (b = digest or capacity) does not
reproduce standard HMAC-SHA3.

VECTORS: RFC 4231 test cases 1, 2, 3, 4, 6 and 7 (case 5 is the truncation case and
is out of scope) for HMAC-SHA-224/256/384/512; cases 6 and 7 exercise the
longer-than-block key, i.e. the provisioner's hash-then-pad rule.  Every embedded
digest was cross-checked against Python's hmac module, which is also run as an
independent reference oracle on each case.  HMAC-SHA3-256 and HMAC-SHA3-512 are
checked against hmac+hashlib on the same messages.

NEGATIVE CONTROL (KAT-EXPECT-FAIL: swapped-pads): swapping ipad and opad must not
reproduce the RFC 4231 tags.
"""
import os, sys, math, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl, bswap, bin_, bxor

import hashlib, hmac as _hmac    # reference oracle; hashlib.sha3_* also used as H
                                 # for the SHA-3 instantiation, see the header

T0 = time.time()

# ------------------------------------------------------- FIPS 180-4 constants

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

_P80 = _primes(80)
_fc = lambda p, w: _icbrt(p << (3 * w)) & ((1 << w) - 1)
_fs = lambda p, w: math.isqrt(p << (2 * w)) & ((1 << w) - 1)
K256 = [_fc(p, 32) for p in _P80[:64]]
K512 = [_fc(p, 64) for p in _P80]
H256 = [_fs(p, 32) for p in _P80[:8]]
H224 = [_fs(p, 64) & 0xffffffff for p in _P80[8:16]]
H512 = [_fs(p, 64) for p in _P80[:8]]
H384 = [_fs(p, 64) for p in _P80[8:16]]
assert K256[0] == 0x428a2f98 and K512[79] == 0x6c44198c4a475817
assert H256[0] == 0x6a09e667 and H224[0] == 0xc1059ed8
assert H512[0] == 0x6a09e667f3bcc908 and H384[0] == 0xcbbb9d5dc1059ed8

def sha2_compress(H, W16, w, K, rounds):
    """FIPS 180-4 sect. 6.2.2 / 6.4.2, both word sizes."""
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

SHA2 = {  # name: (w, IV, t = d)
    'SHA-224': (32, H224, 224), 'SHA-256': (32, H256, 256),
    'SHA-384': (64, H384, 384), 'SHA-512': (64, H512, 512),
}

# ------------------------------------------------------- ACE model helpers

def set_slice(v, hi, lo, x):
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    return (v & ~mask) | ((x << lo) & mask)

class Invalid(Exception):
    """CR transition to Error State _Invalid_."""

class Sha2Core:
    """The underlying SHA-2 hash CC (<<ACE-SHA-2>>) as driven by <<ACE-HMAC>>.

    `state` is the eight chaining variables; `block`/`block_base`/`cumul_len` are
    the internal-state fields the section lists, with cumul_len maintained because
    the function is operating under HMAC."""

    def __init__(self, name):
        self.name = name
        self.w, self.iv, self.d = SHA2[name]
        self.b, self.n, self.t = 16 * self.w, 8 * self.w, self.d
        self.K, self.rounds = (K256, 64) if self.w == 32 else (K512, 80)
        self.reinit()

    def reinit(self):
        """state <- initial value of H; block_base and cumul_len zeroed."""
        self.state = list(self.iv)
        self.block = 0
        self.block_base = 0
        self.cumul_len = 0

    def absorb(self):
        """absorb(): word j = int(bswap(block[(j+1)w-1 : jw]))  (<<ACE-SHA-2>>)."""
        W = [bswap(sl(self.block, (j + 1) * self.w - 1, j * self.w), self.w // 8)
             for j in range(16)]
        self.state = sha2_compress(self.state, W, self.w, self.K, self.rounds)

    def _fill(self, INPUT, ACELEN, input_base, count, interrupt_after=None):
        """The process_VLI inner loop (len = 0 form), shared by all absorptions."""
        iters = 0
        while input_base < ACELEN:
            amount = min(ACELEN - input_base, self.b - self.block_base)
            self.block = set_slice(self.block, self.block_base + amount - 1,
                                   self.block_base,
                                   sl(INPUT, input_base + amount - 1, input_base))
            input_base += amount
            self.block_base += amount
            if count:
                self.cumul_len += amount
            if self.block_base == self.b:
                self.absorb()
                self.block_base = 0
            iters += 1
            if interrupt_after is not None and iters >= interrupt_after \
                    and input_base < ACELEN:
                # M4 (fixed): the spec now writes `acestart <- input_base / 8`;
                # it used to store the bit count into the byte-counting CSR.
                return input_base // 8
        return None

    def exec_input(self, data, resume_from=None, interrupt_after=None):
        """Form B ace.exec in _Hash_Absorb_: the message, counted in cumul_len."""
        # M4-corrected: input_base <- 8 * acestart on resumption.
        base = 8 * resume_from if resume_from is not None else 0
        return self._fill(b2v(data), 8 * len(data), base, True, interrupt_after)

    def inject(self, data):
        """Internal absorption by the algorithm itself (key blocks, padding, the
        inner digest): not counted in cumul_len, which counts caller data only."""
        self._fill(b2v(data), 8 * len(data), 0, False, None)

    def finalize_padding(self, total_bits):
        """finalize() under HMAC: FIPS 180-4 sect. 5.1 padding over `total_bits`,
        applied internally rather than by the caller (<<ACE-HMAC>>)."""
        lb = 2 * self.w // 8
        nbytes = total_bits // 8
        pad = b'\x80' + bytes((-(nbytes + 1 + lb)) % (self.b // 8)) \
              + total_bits.to_bytes(lb, 'big')
        self.inject(pad)
        if self.block_base != 0:
            raise Invalid('padding did not complete the block')

    def digest_value(self):
        """The value of `state` in the emission form of <<ACE-SHA-2>>: chaining
        variable i at bytes i*w/8 as bswap(bin(H_i, w))."""
        v = 0
        for i, hi in enumerate(self.state):
            v |= bswap(bin_(hi, self.w), self.w // 8) << (i * self.w)
        return v

class Sha3Core:
    """The underlying SHA-3 hash CC, with H delegated to hashlib (see header).

    Only b (= the rate of <<ACE-SHA-3-parameters>>) and d matter to the HMAC layer;
    absorbed data is buffered and hashed in one call at finalization."""
    RATE = {'SHA3-224': 1152, 'SHA3-256': 1088, 'SHA3-384': 832, 'SHA3-512': 576}

    def __init__(self, name):
        self.name = name
        self.b = self.RATE[name]
        self.d = self.t = int(name.split('-')[1])
        self.n = 1600
        self.reinit()

    def reinit(self):
        self.buf = b''
        self.cumul_len = 0
        self.block_base = 0

    def exec_input(self, data, resume_from=None, interrupt_after=None):
        base = resume_from if resume_from is not None else 0
        if interrupt_after is not None and base + 1 < len(data):
            cut = base + max(1, (len(data) - base) // 2)
            self.buf += data[base:cut]
            self.cumul_len += 8 * (cut - base)
            return cut                       # acestart, in bytes (M4-corrected)
        self.buf += data[base:]
        self.cumul_len += 8 * (len(data) - base)
        return None

    def inject(self, data):
        self.buf += data

    def finalize_padding(self, total_bits):
        pass                                 # pad10*1 is internal to <<ACE-SHA-3>>

    def digest_value(self):
        return b2v(hashlib.new(self.name.replace('SHA3-', 'sha3_'), self.buf).digest())

def make_core(name):
    return Sha3Core(name) if name.startswith('SHA3') else Sha2Core(name)

# ------------------------------------------------------- <<ACE-HMAC>> meta-algorithm

def provisioner_K0(name, key, b_bits):
    """FIPS 198-1 sect. 3, performed by whoever provisions the key, per <<ACE-HMAC>>."""
    if 8 * len(key) > b_bits:
        if name.startswith('SHA3'):
            key = hashlib.new(name.replace('SHA3-', 'sha3_'), key).digest()
        else:
            c = make_core(name)
            c.inject(key)
            c.finalize_padding(8 * len(key))
            key = v2b(sl(c.digest_value(), c.d - 1, 0), c.d // 8)
    return key + bytes(b_bits // 8 - len(key))

class AceHmac:
    """A HMAC CC per <<ACE-HMAC>>, in either the NIK or the KIP variant."""

    def __init__(self, name, variant, K0=None, swap_pads=False):
        self.h = make_core(name)
        self.name, self.variant = name, variant
        self.b, self.d = self.h.b, self.h.d
        ip, op = b'\x36', b'\x5c'
        if swap_pads:                                   # negative control
            ip, op = op, ip
        self.ipad, self.opad = ip * (self.b // 8), op * (self.b // 8)
        self.key = 0                                    # `key` holds K0, b bits
        if variant == 'KIP':
            assert K0 is not None and 8 * len(K0) == self.b
            self.key = b2v(K0)
            self.state_name = 'Ready'
            self.keyed = True
        else:
            self.state_name = 'Set_Key'
            self.keyed = False
            self.kb_block_base = 0                      # process_VLI block_base
            self.kb_cumul_len = 0                       # process_VLI cumul_len

    # ---- _Set_Key_ (NIK only)
    def exec_set_key(self, data, resume_from=None, interrupt_after=None):
        """process_VLI(b, block=key, b, state=key, n=0, ..., None, None)."""
        if self.variant != 'NIK':
            raise Invalid('a KIP CC cannot be re-keyed')
        if self.state_name != 'Set_Key':
            raise Invalid('not in _Set_Key_')
        INPUT, ACELEN = b2v(data), 8 * len(data)
        # M4-corrected resumption
        input_base = 8 * resume_from if resume_from is not None else 0
        iters = 0
        while input_base < ACELEN:
            # len = b here, so the third term of the min is live
            amount = min(ACELEN - input_base, self.b - self.kb_block_base,
                         self.b - self.kb_cumul_len)
            self.key = set_slice(self.key, self.kb_block_base + amount - 1,
                                 self.kb_block_base,
                                 sl(INPUT, input_base + amount - 1, input_base))
            input_base += amount
            self.kb_block_base += amount
            self.kb_cumul_len += amount
            if self.kb_block_base == self.b:
                self.kb_block_base = 0                  # process_block = None
            if self.kb_cumul_len == self.b:
                self.keyed = True                       # finalize = None
                return None
            iters += 1
            if interrupt_after is not None and iters >= interrupt_after \
                    and input_base < ACELEN:
                return input_base // 8                  # acestart, M4-corrected
        return None

    # ---- _Hash_Absorb_
    def enter_absorb(self):
        if not self.keyed:
            raise Invalid('K0 not loaded')
        self.h.reinit()                                 # state <- IV of H
        self.h.inject(bxor(v2b(self.key, self.b // 8), self.ipad))  # absorb K0^ipad
        self.state_name = 'Hash_Absorb'

    def exec_input(self, data, resume_from=None, interrupt_after=None):
        assert self.state_name == 'Hash_Absorb'
        return self.h.exec_input(data, resume_from, interrupt_after)

    # ---- _Hash_Output_
    def enter_output(self):
        h = self.h
        h.finalize_padding(self.b + h.cumul_len)        # inner: b + cumul_len bits
        inner = v2b(sl(h.digest_value(), self.d - 1, 0), self.d // 8)
        h.reinit()                                      # state <- IV of H
        h.inject(bxor(v2b(self.key, self.b // 8), self.opad))       # absorb K0^opad
        h.inject(inner)
        h.finalize_padding(self.b + self.d)             # outer: b + d bits
        self.block = sl(h.digest_value(), h.t - 1, 0)   # block[t-1:0] <- finalize()
        self.block_base = 0
        self.t = h.t
        self.state_name = 'Hash_Output'

    def exec_output(self, nbytes):
        """The generic _Hash_Output_ squeeze loop of <<ACE-hash-functions>>."""
        assert self.state_name == 'Hash_Output'
        ACELEN, OUTPUT, output_base = 8 * nbytes, 0, 0
        while output_base < ACELEN:
            amount = min(ACELEN - output_base, self.t - self.block_base)
            OUTPUT |= sl(self.block, self.block_base + amount - 1,
                         self.block_base) << output_base
            output_base += amount
            self.block_base += amount
            if self.block_base == self.t:
                self.state_name = 'Success'
                break
        return v2b(OUTPUT, output_base // 8)

def ace_hmac(name, key, msg, variant='KIP', swap_pads=False, split=True):
    """Drive a full HMAC CC and return the tag."""
    b_bits = (Sha3Core.RATE[name] if name.startswith('SHA3')
              else 16 * SHA2[name][0])
    K0 = provisioner_K0(name, key, b_bits)
    if variant == 'KIP':
        cc = AceHmac(name, 'KIP', K0=K0, swap_pads=swap_pads)
    else:
        cc = AceHmac(name, 'NIK', swap_pads=swap_pads)
        # load K0 in three Form B transfers, interrupting/resuming the second
        q = len(K0) // 4
        parts = [K0[:q], K0[q:3 * q], K0[3 * q:]]
        assert cc.exec_set_key(parts[0]) is None
        st = cc.exec_set_key(parts[1], interrupt_after=1)
        while st is not None:
            st = cc.exec_set_key(parts[1], resume_from=st, interrupt_after=1)
        assert cc.exec_set_key(parts[2]) is None
        assert cc.keyed
    cc.enter_absorb()
    if split and len(msg) > 8:
        c = len(msg) // 3
        assert cc.exec_input(msg[:c]) is None
        st = cc.exec_input(msg[c:], interrupt_after=1)   # interrupted transfer
        while st is not None:
            st = cc.exec_input(msg[c:], resume_from=st, interrupt_after=1)
    else:
        assert cc.exec_input(msg) is None
    cc.enter_output()
    d8 = cc.t // 8
    tag = cc.exec_output(d8 - 4) + cc.exec_output(4)     # two Form C instructions
    assert cc.state_name == 'Success'
    return tag

# ------------------------------------------------------- vectors: RFC 4231

RFC4231 = {  # case: (key, data)   -- case 5 (truncation) is out of scope
    1: (bytes.fromhex('0b' * 20), b'Hi There'),
    2: (b'Jefe', b'what do ya want for nothing?'),
    3: (bytes.fromhex('aa' * 20), bytes.fromhex('dd' * 50)),
    4: (bytes(range(1, 26)), bytes.fromhex('cd' * 50)),
    6: (bytes.fromhex('aa' * 131),
        b'Test Using Larger Than Block-Size Key - Hash Key First'),
    7: (bytes.fromhex('aa' * 131),
        b'This is a test using a larger than block-size key and a larger '
        b'than block-size data. The key needs to be hashed before being '
        b'used by the HMAC algorithm.'),
}
TAGS = {  # RFC 4231 sect. 4: the published HMAC values
    ('SHA-224', 1): '896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22',
    ('SHA-256', 1): 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    ('SHA-384', 1): 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c'
                    'faea9ea9076ede7f4af152e8b2fa9cb6',
    ('SHA-512', 1): '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde'
                    'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    ('SHA-224', 2): 'a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44',
    ('SHA-256', 2): '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    ('SHA-384', 2): 'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e'
                    '8e2240ca5e69e2c78b3239ecfab21649',
    ('SHA-512', 2): '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554'
                    '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    ('SHA-224', 3): '7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea',
    ('SHA-256', 3): '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    ('SHA-384', 3): '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b'
                    '2a5ab39dc13814b94e3ab6e101a34f27',
    ('SHA-512', 3): 'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39'
                    'bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
    ('SHA-224', 4): '6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a',
    ('SHA-256', 4): '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    ('SHA-384', 4): '3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e'
                    '6801dd23c4a7d679ccf8a386c674cffb',
    ('SHA-512', 4): 'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db'
                    'a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
    ('SHA-224', 6): '95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e',
    ('SHA-256', 6): '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    ('SHA-384', 6): '4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6'
                    '0c2ef6ab4030fe8296248df163f44952',
    ('SHA-512', 6): '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352'
                    '6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
    ('SHA-224', 7): '3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1',
    ('SHA-256', 7): '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    ('SHA-384', 7): '6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5'
                    'a678cc31e799176d3860e6110c46523e',
    ('SHA-512', 7): 'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944'
                    'b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
}
HL = {'SHA-224': 'sha224', 'SHA-256': 'sha256', 'SHA-384': 'sha384',
      'SHA-512': 'sha512', 'SHA3-256': 'sha3_256', 'SHA3-512': 'sha3_512'}

# ------------------------------------------------------- run

ok = True
print('HMAC per <<ACE-HMAC>> over <<ACE-SHA-2>> / <<ACE-SHA-3>>')
print('NOTE (spec, M4): process_VLI resumption uses acestart = input_base/8,')
print('  the byte-count reading now stated in <<ACE-CSR-acestart>>.')
print('NOTE: for HMAC-SHA3, b = the sponge RATE (1088 / 576 bits), the reading of')
print('  "input block size" of <<ACE-HMAC>> that matches NIST HMAC-SHA3 practice.\n')

print(f'{"function":9} {"case":5} {"KIP (RFC 4231)":16} {"NIK (Set_Key)":15} {"oracle"}')
for name in ('SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'):
    for case, (key, data) in RFC4231.items():
        exp = bytes.fromhex(TAGS[(name, case)])
        kip = ace_hmac(name, key, data, 'KIP')
        nik = ace_hmac(name, key, data, 'NIK')
        ref = _hmac.new(key, data, HL[name]).digest()
        gk, gn, go = kip == exp, nik == exp, ref == exp
        ok &= gk and gn and go
        print(f'{name:9} {case:<5} {"PASS" if gk else "FAIL":16} '
              f'{"PASS" if gn else "FAIL":15} {"PASS" if go else "FAIL"}')

print()
print(f'{"function":9} {"case":5} {"KIP vs oracle":16} {"NIK vs oracle"}')
for name in ('SHA3-256', 'SHA3-512'):
    for case, (key, data) in RFC4231.items():
        ref = _hmac.new(key, data, HL[name]).digest()
        gk = ace_hmac(name, key, data, 'KIP') == ref
        gn = ace_hmac(name, key, data, 'NIK') == ref
        ok &= gk and gn
        print(f'{name:9} {case:<5} {"PASS" if gk else "FAIL":16} '
              f'{"PASS" if gn else "FAIL"}')

# a KIP CC refuses to be re-keyed (<<ACE-HMAC>>: "A KIP CC cannot be re-keyed")
cc = AceHmac('SHA-256', 'KIP', K0=bytes(64))
try:
    cc.exec_set_key(bytes(64)); refused = False
except Invalid:
    refused = True
ok &= refused
print(f'\nKIP CC refuses _Set_Key_ (cannot be re-keyed): '
      f'{"PASS" if refused else "FAIL"}')

# NIK CC refuses to absorb before K0 is fully loaded
cc = AceHmac('SHA-256', 'NIK')
cc.exec_set_key(bytes(32))                     # half a K0
try:
    cc.enter_absorb(); refused2 = False
except Invalid:
    refused2 = True
ok &= refused2
print(f'NIK CC refuses _Hash_Absorb_ with K0 incomplete: '
      f'{"PASS" if refused2 else "FAIL"}')

print('KAT-EXPECT-FAIL: swapped-pads')
key, data = RFC4231[1]
bad = ace_hmac('SHA-256', key, data, 'KIP', swap_pads=True)
fired = bad != bytes.fromhex(TAGS[('SHA-256', 1)])
print(f'swapped ipad/opad control, HMAC-SHA-256 case 1: '
      f'{"FAIL (expected: control is effective)" if fired else "PASS (CONTROL IS DEAD)"}')
ok &= fired

print(f'\nruntime: {time.time() - T0:.2f} s')
print(f'KAT-RESULT: {"PASS" if ok else "FAIL"}')
sys.exit(0 if ok else 1)
