#!/usr/bin/env python3
"""HMAC KAT for the KLEE specification (<<KLEE-HMAC>> over <<KLEE-SHA-2>>/<<KLEE-SHA-3>>).

WHAT IS MODELED, transcribed from the current text of modules/ROOT/pages/Zkl-ISA-machines.adoc:
  * _Machine_: <<KLEE-exec-encodings>> Types 4/5 (SHA-2, Modes 6-11) and 6/7 (SHA-3,
    Modes 6-9), the lower Type the "No Initial Key" (NIK) variant, the higher the
    "Key In PI" (KIP) variant.  A NIK Mode with _KeyType_ != 0 is invalid Metadata, so
    provisioning ends in _Invalid_ (<<KLEE-MVR-open>>).
  * PI: NIK = the MDH only; KIP = MDH || K0 (b bits).  K0 is FIPS 198-1 sect. 3 (the
    key zero-padded to b bits, hashed first if longer); per <<KLEE-HMAC>> deriving it
    is the provisioner's job, done outside the CC in provisioner_K0().
  * States: _Ready_, _Set_Key_ (NIK only), _Hash_Absorb_, _Hash_Output_, _Success_.
    NIK: _Ready_ -> _Set_Key_ -> _Hash_Absorb_ -> _Hash_Output_ -> _Success_; KIP:
    _Ready_ -> _Hash_Absorb_ -> ...; any valid State -> _Ready_.  Any other transition
    (_Set_Key_ on a KIP CC: "cannot be re-keyed"; _Ready_ -> _Hash_Absorb_ on a NIK
    CC) invalidates the locker (<<KLEE-MGR-not-allowed-instructions>>).  The text gives
    _Set_Key_ no State number (SPEC-NOTE); the harness uses 15.
  * _Set_Key_: entry zeroes K0, block_base and cumul_len; each Form B kl.exec runs
    process_VLI(b, block=K0, b, state=K0, n=b, input_base, block_base, 0, cumul_len,
    None, None, mode=assign) step by step: the load ends at cumul_len = b with any
    excess ignored (4.h), and a further kl.exec invalidates (step 1).  Leaving
    _Set_Key_ for _Hash_Absorb_ before K0 is complete invalidates ("K0 must be
    explicitly loaded ... before _Hash_Absorb_ can be entered").
  * _Hash_Absorb_ entry: state <- initial value of H; block, block_base and
    cumul_len <- 0; then K0 xor ipad absorbed, not counted in cumul_len; the
    message then follows H's own process_VLI.  Under HMAC the SHA-2 padding is applied
    internally over b + cumul_len bits (inner) and b + d bits (outer); the harness
    runs the SHA-2 process_VLI with a system-defined max_len = 2^64 - 1 - b (SPEC-NOTE).
  * _Hash_Output_ entry: inner hash finalized, inner <- state[d-1:0], state <- IV of H,
    K0 xor opad and inner absorbed, H finalized.  Each Form C kl.exec runs the output
    loop of <<KLEE-hash-functions-MACs-XOFs>> reading `state` (<<KLEE-SHA-2>>); at d bits the
    bits of OUTPUT beyond output_base are cleared and the locker goes to _Success_.
  * Serialized Content (SHA-2 underlying hashes): the table of <<KLEE-hash-functions-MACs-XOFs>>
    as <<KLEE-SHA-2>> instantiates it under HMAC (cumul_len present), padded to 128
    bits, then K0 (b bits), padded.  Round trips in _Set_Key_, _Hash_Absorb_ and
    _Hash_Output_.
  * kl.derive between the kl.exec endpoints (index 0): an HMAC tag moved into the
    _Hash_Absorb_ of another HMAC CC (<<KLEE-DER-exec-implies-unrestricted>>).
  * process_VLI's only interruption point is step 4.i with klstart <- input_base / 8,
    resumed at input_base <- 8 * klstart.  In _Set_Key_ the block is K0 itself
    (b = max_len), so the load has no interior interruption point.

CORES.  SHA-224/256/384/512/512-224/512-256 are implemented FROM SCRATCH (FIPS 180-4
sect. 6 compression; IVs and round constants by exact integer arithmetic from the roots
of the primes; the SHA-512/t IVs by the sect. 5.3.6 generation), and the KLEE model
uses only those.  For HMAC-SHA-3 the KLEE model calls hashlib's sha3_* as the
underlying H over the absorbed blocks -- <<KLEE-HMAC>> delegates H to <<KLEE-SHA-3>>,
which kat/shake-kat.py models; the HMAC LAYER (K0 at the sponge rate b, ipad/opad,
inner/outer flow, state machine) is still the model's own.  This is the one place
where a library primitive sits inside the model.

For HMAC-SHA-3, <<KLEE-HMAC>> defines b as "the input block size of the underlying hash
function", which for a sponge is the RATE of <<KLEE-SHA-3-parameters>> (1152, 1088, 832,
576 bits); that reading reproduces the reference oracle, while b = digest or capacity
does not.

VECTORS: RFC 4231 test cases 1, 2, 3, 4, 6 and 7 (case 5 is the truncation case and is
out of scope) for HMAC-SHA-224/256/384/512; cases 6 and 7 exercise the longer-than-block
key, i.e. the provisioner's hash-then-pad rule.  Python's hmac module is run as an
independent reference oracle on each case.  HMAC-SHA-512/224, HMAC-SHA-512/256 and
HMAC-SHA3-224/256/384/512 are checked against an independent FIPS 198-1 reference
(from-scratch SHA-2) and hmac+hashlib on the same messages.

NEGATIVE CONTROLS:
  KAT-EXPECT-FAIL: swapped-pads     ipad and opad swapped.
  KAT-EXPECT-FAIL: literal-cumul_len  NIK with cumul_len not zeroed on entering
                                    _Hash_Absorb_: the b bits of K0 loaded in
                                    _Set_Key_ enter the padding.
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

def _sha2_be(msg, H0, w, d):
    """Byte-level big-endian SHA-2 (FIPS 180-4 sect. 5.1 padding, sect. 6), used by
    the provisioner, the independent HMAC reference and the sect. 5.3.6 IV generation.
    Never used by the KLEE model."""
    K, rounds, bb, lb = (K256, 64, 64, 8) if w == 32 else (K512, 80, 128, 16)
    m = msg + b'\x80' + bytes((-(len(msg) + 1 + lb)) % bb) + (8 * len(msg)).to_bytes(lb, 'big')
    H = list(H0)
    for i in range(0, len(m), bb):
        H = sha2_compress(H, [int.from_bytes(m[i + j * w // 8: i + (j + 1) * w // 8], 'big')
                              for j in range(16)], w, K, rounds)
    return b''.join(h.to_bytes(w // 8, 'big') for h in H)[:d // 8]

H512_224 = [int.from_bytes(_sha2_be(b"SHA-512/224", [h ^ 0xa5a5a5a5a5a5a5a5 for h in H512],
                                    64, 512)[8 * i: 8 * i + 8], 'big') for i in range(8)]
H512_256 = [int.from_bytes(_sha2_be(b"SHA-512/256", [h ^ 0xa5a5a5a5a5a5a5a5 for h in H512],
                                    64, 512)[8 * i: 8 * i + 8], 'big') for i in range(8)]
# published IVs, FIPS 180-4 sect. 5.3.6.1 / 5.3.6.2 (spot check of the generation)
assert H512_224[0] == 0x8c3d37c819544da2 and H512_224[7] == 0x1112e6ad91d692a1
assert H512_256[0] == 0x22312194fc2bf72c and H512_256[7] == 0x0eb72ddc81c52ca2

SHA2 = {  # name: (w, IV, d)
    'SHA-224': (32, H224, 224), 'SHA-256': (32, H256, 256),
    'SHA-384': (64, H384, 384), 'SHA-512': (64, H512, 512),
    'SHA-512/224': (64, H512_224, 224), 'SHA-512/256': (64, H512_256, 256),
}
SHA3_RATE = {'SHA3-224': 1152, 'SHA3-256': 1088, 'SHA3-384': 832, 'SHA3-512': 576}

# ------------------------------------------------------- KLEE constants

KL_STATE_UNCONFIGURED = 0       # <<KLEE-state-off>>
KL_STATE_READY = 1              # <<KLEE-states-valid>>
KL_STATE_HASH_ABSORB = 2        # <<KLEE-state-constants-symmetric>>
KL_STATE_HASH_OUTPUT = 6        # <<KLEE-state-constants-symmetric>>
KL_STATE_SET_KEY = 15           # harness value: <<KLEE-HMAC>> gives _Set_Key_ no number
KL_STATE_SUCCESS = 46           # <<KLEE-states-valid>>
KL_STATE_FAILURE = 47           # <<KLEE-states-valid>>
KL_STATE_INVALID = 49           # <<KLEE-states-error>>
ERROR_STATES = range(48, 56)    # <<KLEE-states-error>> (54 and 55 reserved)

ENCODING = {  # <<KLEE-exec-encodings>>: (NIK Type, Mode); the KIP Type is NIK + 1
    'SHA-224': (4, 6), 'SHA-256': (4, 7), 'SHA-384': (4, 8), 'SHA-512': (4, 9),
    'SHA-512/224': (4, 10), 'SHA-512/256': (4, 11),
    'SHA3-224': (6, 6), 'SHA3-256': (6, 7), 'SHA3-384': (6, 8), 'SHA3-512': (6, 9),
}

# ------------------------------------------------------- notation helpers

def set_slice(v, hi, lo, x):
    """v with v[hi:lo] <- x (the assignment form of the spec's bit slices)."""
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    return (v & ~mask) | ((x << lo) & mask)

def pack(fields):
    """Serialize (value, width) fields in the listed order, the first at the lowest
    address (<<KLEE-Notation>>), zero-padded to a multiple of 128 bits."""
    v = pos = 0
    for val, width in fields:
        v |= bin_(val, width) << pos
        pos += width
    pos += (-pos) % 128
    return v2b(v, pos // 8)

def chain_to_state(H, w):
    """`state` from the chaining variables: state[(i+1)w-1 : iw] = bswap(bin(H_i, w)),
    the layout of kat/sha2-kat.py."""
    v = 0
    for i, h in enumerate(H):
        v |= bswap(bin_(h, w), w // 8) << (i * w)
    return v

def state_to_chain(state, w):
    return [bswap(sl(state, (i + 1) * w - 1, i * w), w // 8) for i in range(8)]

class IllegalInstruction(Exception):
    """An illegal-instruction exception (<<KLEE-illegal-instruction-grounds>>)."""

class Hart:
    """The hart state the Machines use: the klstart CSR, a byte count
    (<<KLEE-CSR-klstart>>)."""
    def __init__(self):
        self.klstart = 0

class Ref:
    """A reference to a variable of the caller Machine (<<KLEE-process-VLI>>)."""
    def __init__(self, obj, attr):
        self.obj, self.attr = obj, attr
    def get(self):
        return getattr(self.obj, self.attr)
    def set(self, v):
        setattr(self.obj, self.attr, v)
    def same(self, other):
        return self.obj is other.obj and self.attr == other.attr

ASSIGN = 'assign'

def process_VLI(max_len, block, b, state, n, block_base, state_offset, cumul_len,
                process_block, finalize, mode, *, hart, INPUT, KLLEN, resuming,
                halt=False):
    """One kl.exec of <<KLEE-process-VLI>> (State Machine Behavior, steps 1-4), as in
    kat/sha2-kat.py; only mode = assign is used here.  Returns 'invalid',
    'terminated', 'interrupted' or 'retired'."""
    assert mode == ASSIGN
    assert cumul_len is None or not cumul_len.same(block_base)
    if max_len != 0 and cumul_len.get() >= max_len:                   # 1.
        return 'invalid'
    input_base = 8 * hart.klstart if resuming else 0                   # 2. / 3.
    while input_base < KLLEN:                                          # 4.
        bb = block_base.get()
        if max_len != 0:                                               # 4.a
            amount = min(KLLEN - input_base, b - bb, max_len - cumul_len.get())
        else:
            amount = min(KLLEN - input_base, b - bb)
        block.set(set_slice(block.get(), bb + amount - 1, bb,          # 4.b
                            sl(INPUT, input_base + amount - 1, input_base)))
        input_base += amount                                           # 4.d
        block_base.set(bb + amount)                                    # 4.e
        if max_len != 0:                                               # 4.f
            cumul_len.set(cumul_len.get() + amount)
        if block_base.get() == b:                                      # 4.g
            if process_block is not None:
                process_block()
            block_base.set(0)
        if max_len != 0 and cumul_len.get() == max_len:                # 4.h
            if finalize is not None:
                finalize()
            hart.klstart = 0
            return 'terminated'
        if halt and input_base < KLLEN:                                # 4.i
            hart.klstart = input_base // 8
            return 'interrupted'
    hart.klstart = 0
    return 'retired'

# ------------------------------------------------------- the underlying hash H

class _Core:
    def _fill(self, data):
        """absorb() of <<KLEE-HMAC>>: the Machine's own absorption (K0 xor ipad/opad,
        inner, padding) of whole bytes; not counted in cumul_len."""
        INPUT, KLLEN, base = b2v(data), 8 * len(data), 0
        while base < KLLEN:
            amount = min(KLLEN - base, self.b - self.block_base)
            self.block = set_slice(self.block, self.block_base + amount - 1,
                                   self.block_base, sl(INPUT, base + amount - 1, base))
            base += amount
            self.block_base += amount
            if self.block_base == self.b:
                self.process_block()
                self.block_base = 0

class Sha2Core(_Core):
    """The underlying SHA-2 hash (<<KLEE-SHA-2>>) inside an HMAC CC: `state` (n
    bits), `block`, `block_base` and `cumul_len` (kept: operating under HMAC)."""
    sha3 = False

    def __init__(self, name):
        self.name = name
        self.w, self.iv, self.d = SHA2[name]
        self.b, self.n = 16 * self.w, 8 * self.w
        self.K, self.rounds = (K256, 64) if self.w == 32 else (K512, 80)
        self.ready()

    def ready(self):
        """_Ready_ of <<KLEE-SHA-2>>: state <- IV; block, block_base, cumul_len <- 0."""
        self.state = chain_to_state(self.iv, self.w)
        self.block = self.block_base = self.cumul_len = 0

    def reinit(self):
        """"state is set to the initial value of the underlying hash function"."""
        self.state = chain_to_state(self.iv, self.w)

    def process_block(self):
        W = [bswap(sl(self.block, (j + 1) * self.w - 1, j * self.w), self.w // 8)
             for j in range(16)]
        self.state = chain_to_state(sha2_compress(state_to_chain(self.state, self.w), W,
                                                  self.w, self.K, self.rounds), self.w)

    def finalize(self, total_bits):
        """finalize() under HMAC: FIPS 180-4 sect. 5.1 padding over total_bits,
        applied internally (<<KLEE-SHA-2>>, <<KLEE-HMAC>>)."""
        lb = 2 * self.w // 8
        self._fill(b'\x80' + bytes((-(total_bits // 8 + 1 + lb)) % (self.b // 8))
                   + total_bits.to_bytes(lb, 'big'))
        assert self.block_base == 0

class Sha3Core(_Core):
    """The underlying SHA-3 hash, with H delegated to hashlib (see the header): the
    absorbed blocks are collected and hashed at finalization, the digest left in
    state[d-1:0]."""
    sha3 = True

    def __init__(self, name):
        self.name = name
        self.b, self.d, self.n = SHA3_RATE[name], int(name.split('-')[1]), 1600
        self.ready()

    def ready(self):
        self.buf, self.state = b'', 0
        self.block = self.block_base = self.cumul_len = 0

    def reinit(self):
        self.buf, self.state = b'', 0

    def process_block(self):
        self.buf += v2b(self.block, self.b // 8)
        self.block = 0

    def finalize(self, total_bits):
        """The suffix-and-padding of <<KLEE-SHA-3>>, inside hashlib."""
        tail = v2b(self.block, self.block_base // 8)
        self.state = b2v(hashlib.new(self.name.replace('SHA3-', 'sha3_'),
                                     self.buf + tail).digest())
        self.buf, self.block, self.block_base = b'', 0, 0

def make_core(name):
    return Sha3Core(name) if name.startswith('SHA3') else Sha2Core(name)

# ------------------------------------------------------- the KLEE model

class KleeHmacLocker:
    """One locker holding an HMAC CC per <<KLEE-HMAC>>, NIK or KIP variant."""

    def __init__(self, name, hart, swap_pads=False, literal_cumul=False):
        self.name, self.hart = name, hart
        self.h = make_core(name)
        self.b, self.d = self.h.b, self.h.d
        ip, op = b'\x36', b'\x5c'
        if swap_pads:                                   # negative control
            ip, op = op, ip
        self.ipad, self.opad = ip * (self.b // 8), op * (self.b // 8)
        self.literal_cumul = literal_cumul              # negative control
        # system-defined max_len of the SHA-2 message absorption (harness choice, see
        # the header); 0 for SHA-3, whose process_VLI invocation fixes max_len = 0
        self.max_len = 0 if self.h.sha3 else (1 << 64) - 1 - self.b
        self.st = KL_STATE_UNCONFIGURED
        self.variant, self.machine, self.K0 = None, 0, 0

    # ---- configuration
    def provision(self, variant, K0=None, key_type=0):
        typ, mode = ENCODING[self.name]
        self.variant = variant
        self.machine = ((typ + (variant == 'KIP')) << 4) | mode
        if variant == 'NIK' and key_type != 0:
            # "A NIK variant must have _KeyType_ = 0 ... Any other _KeyType_ with a
            # NIK Mode is invalid metadata" -> <<KLEE-MVR-open>>
            self._invalid()
            return self
        if variant == 'KIP':
            assert K0 is not None and 8 * len(K0) == self.b
            self.K0 = b2v(K0)
        self.h.ready()
        self.st = KL_STATE_READY
        return self

    def export_content1(self):
        """Content1: the Serialized Content of H in its entirety (the SHA-2 table of
        <<KLEE-hash-functions-MACs-XOFs>> with cumul_len present, padded to 128 bits), then K0."""
        h = self.h
        assert not h.sha3
        return pack([(h.state, h.n), (0, 16), (h.block_base, 16), (0, 32),
                     (h.cumul_len, 64), (h.block, h.b)]) + pack([(self.K0, self.b)])

    def import_content1(self, variant, mdh_state, content1):
        h = self.h
        typ, mode = ENCODING[self.name]
        self.variant = variant
        self.machine = ((typ + (variant == 'KIP')) << 4) | mode
        hl = len(pack([(0, h.n + 128 + h.b)]))
        v, k = b2v(content1[:hl]), b2v(content1[hl:])
        h.state = sl(v, h.n - 1, 0)
        h.block_base = sl(v, h.n + 31, h.n + 16)
        h.cumul_len = sl(v, h.n + 127, h.n + 64)
        h.block = sl(v, h.n + 128 + h.b - 1, h.n + 128)
        self.K0 = sl(k, self.b - 1, 0)
        self.st = mdh_state
        return self

    # ---- internal
    def _invalid(self):
        self.st = KL_STATE_INVALID
        self.K0 = 0
        self.h.ready()
        self.h.state = 0                # <<KLEE-SGR-clear-locker-content-error-state>>

    def _enter_absorb(self):
        h = self.h
        h.reinit()                                      # state <- IV of H
        cumul = h.cumul_len
        h.block = h.block_base = h.cumul_len = 0
        if self.literal_cumul:                          # negative control
            h.cumul_len = cumul
        h._fill(bxor(v2b(self.K0, self.b // 8), self.ipad))    # absorb K0 xor ipad
        self.st = KL_STATE_HASH_ABSORB

    def _enter_output(self):
        h, d = self.h, self.d
        h.finalize(self.b + h.cumul_len)                # inner: b + cumul_len bits
        inner = v2b(sl(h.state, d - 1, 0), d // 8)      # inner <- state[d-1:0]
        h.reinit()                                      # state <- IV of H
        h._fill(bxor(v2b(self.K0, self.b // 8), self.opad))    # absorb K0 xor opad
        h._fill(inner)                                  # absorb inner
        h.finalize(self.b + d)                          # outer: b + d bits
        h.block_base = 0
        self.st = KL_STATE_HASH_OUTPUT

    # ---- usage instructions
    def kl_setst(self, immed, form='A'):
        """kl.setst Kd, #immed7 (<<KLEE-instruction-setst>>)."""
        st = self.st
        if immed in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            raise IllegalInstruction('#immed7 46 and 47 are reserved encodings')
        if immed == KL_STATE_UNCONFIGURED:              # kl.clear
            self.__init__(self.name, self.hart)
            return
        if immed in ERROR_STATES:
            if st != KL_STATE_UNCONFIGURED:
                self._invalid()
                self.st = immed if immed <= 53 else KL_STATE_INVALID
            return
        if st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction('usage-controlled instruction on _Unconfigured_')
        if st in ERROR_STATES:                          # only a change of Error State
            return
        if immed == KL_STATE_READY:                     # from any valid State
            self.h.ready()                              # K0 is kept
            self.st = KL_STATE_READY
            return
        if st == KL_STATE_SUCCESS:                      # <<KLEE-SGR-setst-in-success-failure>>
            self._invalid()
            return
        if immed == KL_STATE_SET_KEY:
            # NIK only, from _Ready_; a same-State transition is not allowed and
            # max_len (= b) is set by the Machine, so Form A (<<KLEE-process-VLI>>)
            if self.variant != 'NIK' or st != KL_STATE_READY or form != 'A':
                self._invalid()
                return
            self.K0 = 0
            self.h.block_base = self.h.cumul_len = 0
            self.st = KL_STATE_SET_KEY
            return
        if immed == KL_STATE_HASH_ABSORB:
            if form != 'A' or not (
                    (self.variant == 'KIP' and st == KL_STATE_READY) or
                    (self.variant == 'NIK' and st == KL_STATE_SET_KEY
                     and self.h.cumul_len == self.b)):
                self._invalid()
                return
            self._enter_absorb()
            return
        if immed == KL_STATE_HASH_OUTPUT:
            if st != KL_STATE_HASH_ABSORB or form != 'A':
                self._invalid()
                return
            self._enter_output()
            return
        self._invalid()                                 # e.g. #kl_state_hash_last_block

    def kl_exec(self, form, data=b'', nbytes=0, resuming=False, halt=False, prior=None):
        """kl.exec Form B (input only) or Form C (output only).
        Returns (status, output bytes or None)."""
        KLLEN = 8 * (len(data) if form == 'B' else nbytes)
        st, h = self.st, self.h
        if st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction('usage-controlled instruction on _Unconfigured_')
        if st in ERROR_STATES:                          # no operation, window zeroed
            return 'noop', (bytes(nbytes) if form == 'C' else None)
        if st == KL_STATE_SET_KEY and form == 'B':
            r = process_VLI(self.b, Ref(self, 'K0'), self.b, Ref(self, 'K0'), self.b,
                            Ref(h, 'block_base'), 0, Ref(h, 'cumul_len'), None, None,
                            ASSIGN, hart=self.hart, INPUT=b2v(data), KLLEN=KLLEN,
                            resuming=resuming, halt=halt)
        elif st == KL_STATE_HASH_ABSORB and form == 'B':
            r = process_VLI(self.max_len, Ref(h, 'block'), h.b, Ref(h, 'state'), h.n,
                            Ref(h, 'block_base'), 0,
                            None if h.sha3 else Ref(h, 'cumul_len'),
                            h.process_block, None, ASSIGN, hart=self.hart,
                            INPUT=b2v(data), KLLEN=KLLEN, resuming=resuming, halt=halt)
        elif st == KL_STATE_HASH_OUTPUT and form == 'C':
            return 'retired', v2b(self._hash_output(KLLEN, prior), nbytes)
        else:
            # _Ready_ (<<KLEE-SGR-no-exec-in-ready>>), _Success_
            # (<<KLEE-SGR-success-failure>>), or a Form the State does not expect
            # (<<KLEE-MGR-not-allowed-instructions>>)
            r = 'invalid'
        if r == 'invalid':
            self._invalid()
            return r, (bytes(nbytes) if form == 'C' else None)
        return r, None

    def _hash_output(self, KLLEN, prior):
        """The _Hash_Output_ loop of <<KLEE-hash-functions-MACs-XOFs>>, reading `state`."""
        h, t = self.h, self.d
        OUTPUT = b2v(prior) if prior is not None else 0
        output_base = 0
        while output_base < KLLEN:
            amount = min(KLLEN - output_base, t - h.block_base)
            OUTPUT = set_slice(OUTPUT, output_base + amount - 1, output_base,
                               sl(h.state, h.block_base + amount - 1, h.block_base))
            output_base += amount
            h.block_base += amount
            if h.block_base == t:
                OUTPUT = sl(OUTPUT, output_base - 1, 0)  # bits beyond output_base cleared
                self.st = KL_STATE_SUCCESS
                break
        self.hart.klstart = 0
        return sl(OUTPUT, KLLEN - 1, 0) if KLLEN else 0

def kl_derive(dst, src, length, hart):
    """kl.derive between the kl.exec endpoints (index 0): an HMAC output into the
    _Hash_Absorb_ of a MAC (<<KLEE-DER-exec-implies-unrestricted>>)."""
    if src.st in ERROR_STATES or dst.st in ERROR_STATES:   # <<KLEE-SGR-gate-order>>
        return 'noop'
    # <<KLEE-DER-checks>> item 1, source first.  The kl.exec input of _Set_Key_ loads
    # the key, which is no index-0 endpoint, and K0 (index 1) is written in _Ready_.
    src_ok = src.st == KL_STATE_HASH_OUTPUT
    dst_ok = dst.st == KL_STATE_HASH_ABSORB
    if not (src_ok and dst_ok):
        if not src_ok:
            src._invalid()
        if not dst_ok:
            dst._invalid()
        return 'refused'
    if length == 0:
        return 'noop'
    _, data = src.kl_exec('C', nbytes=length)
    dst.kl_exec('B', data=data)
    hart.klstart = 0
    return 'done'

# ------------------------------------------------------- provisioner and references

def provisioner_K0(name, key, b_bits):
    """FIPS 198-1 sect. 3, performed by whoever provisions the key, per <<KLEE-HMAC>>."""
    if 8 * len(key) > b_bits:
        key = ref_hash(name, key)
    return key + bytes(b_bits // 8 - len(key))

def ref_hash(name, msg):
    if name.startswith('SHA3'):
        return hashlib.new(name.replace('SHA3-', 'sha3_'), msg).digest()
    w, iv, d = SHA2[name]
    return _sha2_be(msg, iv, w, d)

def ref_hmac(name, key, msg):
    """Independent FIPS 198-1 reference over ref_hash (no KLEE model)."""
    b = SHA3_RATE[name] if name.startswith('SHA3') else 16 * SHA2[name][0]
    K0 = provisioner_K0(name, key, b)
    inner = ref_hash(name, bxor(K0, b'\x36' * (b // 8)) + msg)
    return ref_hash(name, bxor(K0, b'\x5c' * (b // 8)) + inner)

HL = {'SHA-224': 'sha224', 'SHA-256': 'sha256', 'SHA-384': 'sha384',
      'SHA-512': 'sha512', 'SHA-512/224': 'sha512_224', 'SHA-512/256': 'sha512_256',
      'SHA3-224': 'sha3_224', 'SHA3-256': 'sha3_256', 'SHA3-384': 'sha3_384',
      'SHA3-512': 'sha3_512'}

def oracle(name, key, msg):
    """Python hmac: reference oracle only (never part of the KLEE model)."""
    try:
        return _hmac.new(key, msg, HL[name]).digest()
    except ValueError:
        return None

# ------------------------------------------------------- drivers

HART = Hart()

def fresh(name, variant='KIP', key=b'key', **kw):
    cl = KleeHmacLocker(name, HART, **kw)
    return cl.provision(variant, provisioner_K0(name, key, cl.b) if variant == 'KIP'
                        else None)

def load_key(cl, K0, parts=3):
    """_Ready_ -> _Set_Key_, then K0 in `parts` Form B transfers."""
    cl.kl_setst(KL_STATE_SET_KEY)
    q = len(K0) // parts
    cuts = [0] + [q * i for i in range(1, parts)] + [len(K0)]
    for i in range(parts):
        cl.kl_exec('B', K0[cuts[i]:cuts[i + 1]])

def kl_hmac(name, key, msg, variant='KIP', **kw):
    """Drive a full HMAC CC and return the tag, or None if it did not reach _Success_.
    The message goes in up to three Form B transfers, the one crossing a block
    boundary halted at every process_VLI interruption point and resumed from
    klstart; the tag is read by two Form C kl.exec instructions."""
    cl = KleeHmacLocker(name, HART, **kw)
    K0 = provisioner_K0(name, key, cl.b)
    if variant == 'KIP':
        cl.provision('KIP', K0)
    else:
        cl.provision('NIK')
        load_key(cl, K0)
    cl.kl_setst(KL_STATE_HASH_ABSORB)
    c = len(msg) // 3
    for piece in (msg[:c], msg[c:]):
        if piece:
            st, _ = cl.kl_exec('B', piece, halt=True)
            while st == 'interrupted':
                st, _ = cl.kl_exec('B', piece, resuming=True, halt=True)
    cl.kl_setst(KL_STATE_HASH_OUTPUT)
    d8 = cl.d // 8
    tag = cl.kl_exec('C', nbytes=d8 - 4)[1] + cl.kl_exec('C', nbytes=4)[1]
    return tag if cl.st == KL_STATE_SUCCESS else None

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

# ------------------------------------------------------- run

ok = True

def check(label, cond):
    global ok
    ok &= bool(cond)
    print(f'  {"PASS" if cond else "FAIL"}  {label}')

def pf(c):
    return 'PASS' if c else 'FAIL'

print('HMAC per <<KLEE-HMAC>> over <<KLEE-SHA-2>> / <<KLEE-SHA-3>>\n')
print(f'{"function":12} {"case":5} {"KIP (RFC 4231)":16} {"NIK (Set_Key)":15} {"oracle"}')
for name in ('SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'):
    for case, (key, data) in RFC4231.items():
        exp = bytes.fromhex(TAGS[(name, case)])
        gk = kl_hmac(name, key, data, 'KIP') == exp
        gn = kl_hmac(name, key, data, 'NIK') == exp
        r = oracle(name, key, data)
        orac = 'n/a' if r is None else pf(r == exp)
        ok &= gk and gn and orac != 'FAIL'
        print(f'{name:12} {case:<5} {pf(gk):16} {pf(gn):15} {orac}')

print()
print(f'{"function":12} {"case":5} {"KIP vs ref":16} {"NIK vs ref":15} {"ref vs oracle"}')
for name in ('SHA-512/224', 'SHA-512/256', 'SHA3-224', 'SHA3-256', 'SHA3-384',
             'SHA3-512'):
    for case, (key, data) in RFC4231.items():
        ref = ref_hmac(name, key, data)
        gk = kl_hmac(name, key, data, 'KIP') == ref
        gn = kl_hmac(name, key, data, 'NIK') == ref
        r = oracle(name, key, data)
        orac = 'n/a' if r is None else pf(r == ref)
        ok &= gk and gn and orac != 'FAIL'
        print(f'{name:12} {case:<5} {pf(gk):16} {pf(gn):15} {orac}')

print('\nState machine and error handling:')
key, data = RFC4231[7]
TAG7 = bytes.fromhex(TAGS[('SHA-256', 7)])
K0_7 = provisioner_K0('SHA-256', key, 512)

cl = KleeHmacLocker('SHA-256', HART).provision('NIK', key_type=1)
check('NIK Mode with _KeyType_ = 1: invalid Metadata, provisioning ends in _Invalid_ '
      '(<<KLEE-exec-encodings>>, <<KLEE-MVR-open>>)', cl.st == KL_STATE_INVALID)
cl = fresh('SHA-256', 'KIP')
check('_Machine_ of KIP HMAC-SHA-256 = Type 5, Mode 7; NIK = Type 4, Mode 7',
      cl.machine == (5 << 4) | 7
      and KleeHmacLocker('SHA-256', HART).provision('NIK').machine == (4 << 4) | 7)

cl = fresh('SHA-256', 'KIP')
cl.kl_setst(KL_STATE_SET_KEY)
check('KIP: kl.setst to _Set_Key_ -> _Invalid_ ("A KIP CC cannot be re-keyed")',
      cl.st == KL_STATE_INVALID)
cl = fresh('SHA-256', 'NIK')
cl.kl_setst(KL_STATE_HASH_ABSORB)
check('NIK: _Ready_ -> _Hash_Absorb_ -> _Invalid_ (K0 must be loaded in _Set_Key_ first)',
      cl.st == KL_STATE_INVALID)
cl = fresh('SHA-256', 'NIK')
cl.kl_setst(KL_STATE_SET_KEY)
cl.kl_exec('B', K0_7[:32])
cl.kl_setst(KL_STATE_HASH_ABSORB)
check('NIK: _Set_Key_ -> _Hash_Absorb_ with half of K0 loaded -> _Invalid_',
      cl.st == KL_STATE_INVALID)
cl = fresh('SHA-256', 'NIK')
cl.kl_setst(KL_STATE_SET_KEY)
cl.kl_setst(KL_STATE_SET_KEY)
check('NIK: same-State kl.setst to _Set_Key_ -> _Invalid_ (<<KLEE-process-VLI>>)',
      cl.st == KL_STATE_INVALID)
cl = fresh('SHA-256', 'NIK')
cl.kl_setst(KL_STATE_SET_KEY, form='B')
check('NIK: Form B kl.setst to _Set_Key_ -> _Invalid_ (max_len = b is set by the '
      'Machine, so Form A)', cl.st == KL_STATE_INVALID)

cl = fresh('SHA-256', 'NIK')
cl.kl_setst(KL_STATE_SET_KEY)
st, _ = cl.kl_exec('B', K0_7 + b'\xde\xad\xbe\xef' * 4)
term = st == 'terminated' and cl.h.cumul_len == 512 and cl.K0 == b2v(K0_7)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', data)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, tag = cl.kl_exec('C', nbytes=32)
check('NIK: K0 plus 16 excess bytes in one transfer: the load ends at cumul_len = b, '
      'the excess is ignored (<<KLEE-process-VLI>> step 4.h); RFC 4231 case 7',
      term and tag == TAG7)
cl = fresh('SHA-256', 'NIK')
load_key(cl, K0_7)
cl.kl_exec('B', bytes(4))
check('NIK: a kl.exec after K0 is complete -> _Invalid_ (<<KLEE-process-VLI>> step 1, '
      '<<KLEE-MGR-load-long-field>>)', cl.st == KL_STATE_INVALID)

cl = fresh('SHA-256', 'NIK')
load_key(cl, provisioner_K0('SHA-256', b'first key', 512))
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', b'ignored')
cl.kl_setst(KL_STATE_READY)
load_key(cl, K0_7, parts=5)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', data)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, tag = cl.kl_exec('C', nbytes=32)
check('NIK: _Hash_Absorb_ -> _Ready_ -> _Set_Key_ replaces K0 (entry zeroes it); '
      'RFC 4231 case 7 with the second key', tag == TAG7)

cl = fresh('SHA-256', 'KIP', key)
cl.kl_exec('B', data)
check('kl.exec in _Ready_ -> _Invalid_ (<<KLEE-SGR-no-exec-in-ready>>)',
      cl.st == KL_STATE_INVALID)
cl = fresh('SHA-256', 'KIP', key)
cl.kl_setst(KL_STATE_HASH_ABSORB)
_, out = cl.kl_exec('C', nbytes=16)
check('Form C kl.exec in _Hash_Absorb_ -> _Invalid_, output window zeroed '
      '(<<KLEE-MGR-not-allowed-instructions>>)',
      cl.st == KL_STATE_INVALID and out == bytes(16))
cl = fresh('SHA-256', 'KIP', key)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_setst(KL_STATE_HASH_ABSORB)
check('same-State kl.setst to _Hash_Absorb_ -> _Invalid_ (<<KLEE-process-VLI>>)',
      cl.st == KL_STATE_INVALID)
cl = fresh('SHA-256', 'KIP', key)
cl.kl_setst(KL_STATE_HASH_ABSORB)
try:
    cl.kl_setst(KL_STATE_SUCCESS)
    raised = False
except IllegalInstruction:
    raised = True
check('kl.setst #kl_state_success: illegal-instruction exception, State kept '
      '(<<KLEE-illegal-instruction-grounds>>)', raised and cl.st == KL_STATE_HASH_ABSORB)

cl = fresh('SHA-256', 'KIP', key)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', data)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = cl.kl_exec('C', nbytes=40, prior=b'\xa5' * 40)
check('tag read with KLLEN = 320 > d: 32 tag bytes, the 8 beyond cleared, -> _Success_ '
      '(<<KLEE-hash-functions-MACs-XOFs>>)', out == TAG7 + bytes(8) and cl.st == KL_STATE_SUCCESS)
cl.kl_setst(KL_STATE_READY)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', data)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, tag = cl.kl_exec('C', nbytes=32)
check('KIP: _Success_ -> _Ready_ keeps K0; a second tag is right '
      '(<<KLEE-SGR-setst-in-success-failure>>)', tag == TAG7)
_, out = cl.kl_exec('C', nbytes=32, prior=b'\xa5' * 32)
check('kl.exec in _Success_ -> _Invalid_, output window zeroed '
      '(<<KLEE-SGR-success-failure>>)', cl.st == KL_STATE_INVALID and out == bytes(32))
st, out = cl.kl_exec('C', nbytes=32, prior=b'\xa5' * 32)
check('kl.exec on a locker in _Invalid_: no operation, State kept, output zeroed '
      '(<<KLEE-SGR-usage-locker-error-state>>)',
      st == 'noop' and cl.st == KL_STATE_INVALID and out == bytes(32))

print('\nSerialized Content (Content1), SHA-2 underlying hashes:')
for name, exp_len in (('SHA-224', 176), ('SHA-256', 176), ('SHA-384', 336),
                      ('SHA-512', 336), ('SHA-512/224', 336), ('SHA-512/256', 336)):
    got = len(fresh(name).export_content1())
    check(f'{name:12} {got} bytes (expected {exp_len}: n + 16 + 16 + 32 + 64 + b bits '
          f'padded to 128, then K0, padded)', got == exp_len)
TRIPS = [  # (label, variant, stop point)
    ('NIK in _Set_Key_ with 40 of 64 K0 bytes loaded', 'NIK', 'set_key'),
    ('KIP in _Hash_Absorb_ at block_base 288 (cumul_len 800)', 'KIP', 'absorb'),
    ('KIP in _Hash_Output_ after 12 tag bytes', 'KIP', 'output'),
]
for label, variant, stop in TRIPS:
    cl = KleeHmacLocker('SHA-256', HART).provision(
        variant, K0_7 if variant == 'KIP' else None)
    if variant == 'NIK':
        cl.kl_setst(KL_STATE_SET_KEY)
        cl.kl_exec('B', K0_7[:40])
    else:
        cl.kl_setst(KL_STATE_HASH_ABSORB)
        cl.kl_exec('B', data[:100])
    head = b''
    if stop == 'output':
        cl.kl_exec('B', data[100:])
        cl.kl_setst(KL_STATE_HASH_OUTPUT)
        head = cl.kl_exec('C', nbytes=12)[1]
    cl2 = KleeHmacLocker('SHA-256', HART).import_content1(variant, cl.st,
                                                          cl.export_content1())
    if stop == 'set_key':
        cl2.kl_exec('B', K0_7[40:])
        cl2.kl_setst(KL_STATE_HASH_ABSORB)
        cl2.kl_exec('B', data)
    if stop == 'absorb':
        cl2.kl_exec('B', data[100:])
    if stop != 'output':
        cl2.kl_setst(KL_STATE_HASH_OUTPUT)
    tag = head + cl2.kl_exec('C', nbytes=32 - len(head))[1]
    check(f'export/import round trip, HMAC-SHA-256 {label}: RFC 4231 case 7',
          tag == TAG7 and cl2.st == KL_STATE_SUCCESS)

print('\nkl.derive between kl.exec endpoints (<<KLEE-DER-exec-implies-unrestricted>>):')
k1, m1 = RFC4231[2]
src = fresh('SHA-256', 'KIP', k1)
src.kl_setst(KL_STATE_HASH_ABSORB)
src.kl_exec('B', m1)
src.kl_setst(KL_STATE_HASH_OUTPUT)
dst = fresh('SHA-512', 'NIK')
load_key(dst, provisioner_K0('SHA-512', key, 1024))
dst.kl_setst(KL_STATE_HASH_ABSORB)
dst.kl_exec('B', b'prefix')
r = kl_derive(dst, src, 32, HART)
dst.kl_exec('B', b'suffix')
dst.kl_setst(KL_STATE_HASH_OUTPUT)
_, tag = dst.kl_exec('C', nbytes=64)
t2 = bytes.fromhex(TAGS[('SHA-256', 2)])
check('HMAC-SHA-256 tag (RFC 4231 case 2) -> open NIK HMAC-SHA-512 _Hash_Absorb_ '
      '(32 B): HMAC-SHA-512(K, "prefix" || tag || "suffix") = reference; source -> '
      '_Success_', r == 'done' and src.st == KL_STATE_SUCCESS
      and tag == ref_hmac('SHA-512', key, b'prefix' + t2 + b'suffix'))
src = fresh('SHA-256', 'KIP', k1)
src.kl_setst(KL_STATE_HASH_ABSORB)
src.kl_exec('B', m1)
src.kl_setst(KL_STATE_HASH_OUTPUT)
dst = fresh('SHA-256', 'NIK')
dst.kl_setst(KL_STATE_SET_KEY)
r = kl_derive(dst, src, 32, HART)
check('destination in _Set_Key_ (its kl.exec input is no index-0 endpoint): refused, '
      'destination -> _Invalid_, nothing taken from the source',
      r == 'refused' and dst.st == KL_STATE_INVALID
      and src.st == KL_STATE_HASH_OUTPUT and src.h.block_base == 0)

print('\nNegative controls:')
print('KAT-EXPECT-FAIL: swapped-pads')
key, data = RFC4231[1]
fired = kl_hmac('SHA-256', key, data, 'KIP', swap_pads=True) != \
    bytes.fromhex(TAGS[('SHA-256', 1)])
print(f'  swapped-pads control, HMAC-SHA-256 case 1: '
      f'{"FAIL (expected: control is effective)" if fired else "PASS (CONTROL IS DEAD)"}')
ok &= fired
print('KAT-EXPECT-FAIL: literal-cumul_len')
fired = kl_hmac('SHA-256', key, data, 'NIK', literal_cumul=True) != \
    bytes.fromhex(TAGS[('SHA-256', 1)])
print(f'  literal-cumul_len control, NIK HMAC-SHA-256 case 1: '
      f'{"FAIL (expected: control is effective)" if fired else "PASS (CONTROL IS DEAD)"}')
ok &= fired

print()
print('SPEC-NOTE: <<KLEE-HMAC>> inserts State _Set_Key_ but gives it no number or')
print('  mnemonic (<<KLEE-state-constants-symmetric>> has none), so the kl.setst that')
print('  enters it cannot be encoded.  The harness uses 15.')
print('SPEC-NOTE: under HMAC the SHA-2/SM3 padding covers b + cumul_len bits, but')
print('  process_VLI advances cumul_len only when max_len != 0 (step 4.f), and')
print('  <<KLEE-SHA-2>> passes a system-defined max_len "or zero if none is enforced".')
print('  The harness gives the SHA-2 message absorption max_len = 2^64 - 1 - b.')
print('SPEC-NOTE: <<KLEE-derive-endpoints>> makes K0 of the NIK variant importable')
print('  (index 1), and <<KLEE-DER-checks>> item 1 writes a key only in _Ready_; but')
print('  from _Ready_ a NIK CC reaches _Hash_Absorb_ only through _Set_Key_, whose entry')
print('  zeroes K0, so a derived K0 can never be used.  Nor does any listed source fit:')
print('  <<KLEE-DER-shared-secret>> targets encryption schemes, and a 32-byte shared')
print('  secret is shorter than K0 (b/8 = 64 or 128 bytes; item 4).')
print('SPEC-NOTE: the HMAC tag is `kl.exec` output and _Hash_Absorb_ takes `kl.exec`')
print('  input, and <<KLEE-DER-exec-implies-unrestricted>> always allows such transfers,')
print('  yet <<KLEE-derive-endpoints>> lists no index-0 endpoint for <<KLEE-HMAC>>')
print('  (KIP: "-- | --").  The harness follows the rule.')
print('SPEC-NOTE: the _Set_Key_ process_VLI (max_len = b) relies on cumul_len, which')
print('  the Serialized Content of <<KLEE-SHA-3>> does not carry.  For HMAC-SHA-3 a')
print('  partial load survives an export through block_base (equal to cumul_len until')
print('  K0 is complete), but a complete one does not: after an import block_base and')
print('  cumul_len read 0, so a further kl.exec reloads K0 instead of invalidating, and')
print('  the completion that entering _Hash_Absorb_ presupposes is lost.')
print('INFO: HMAC-SHA-3 has no Serialized Content round trip here: its H is hashlib.')
print('INFO: a KIP K0 given as a SKID (_KeyType_ = 1, 64 bits) is not exercised.')

print(f'\nruntime: {time.time() - T0:.2f} s')
print(f'KAT-RESULT: {"PASS" if ok else "FAIL"}')
sys.exit(0 if ok else 1)
