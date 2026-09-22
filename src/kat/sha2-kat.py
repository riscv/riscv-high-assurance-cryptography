#!/usr/bin/env python3
"""SHA-2 family KAT for the KLEE specification (<<KLEE-SHA-2>> over <<KLEE-hash-functions>>).

WHAT IS MODELED, transcribed from the current text of modules/ROOT/pages/Zkl-ISA-machines.adoc:
  * Parameters w, b, n, t from <<KLEE-SHA-2-parameters>>; the _Machine_ encodings
    Type 4, Modes 0-5 of <<KLEE-exec-encodings>>; the State values of
    <<KLEE-states-valid>>, <<KLEE-state-constants-symmetric>> and <<KLEE-states-error>>.
  * PI: the MDH only.  _Ready_: `state` <- the initial hash value of FIPS 180-4
    sect. 5.3; last_blk_len, block_base, cumul_len and block <- 0.
  * `state` is one n-bit value.  <<KLEE-SHA-2>> fixes its layout only through
    _Hash_Output_, which emits state[t-1:0] as "the chaining variables in the
    big-endian encoding"; the model keeps state[(i+1)w-1 : iw] = bswap(bin(H_i, w)).
    process_block() is the FIPS 180-4 sect. 6 compression with message word
    j = int(bswap(block[(j+1)w-1 : jw])), the FIPS 180-4 row of
    <<KLEE-Notation-standards>> ("message schedule words ... via bswap").  The
    "Endianness" paragraph that used to state both explicitly is commented out in
    the current text (SPEC-NOTE line).
  * _Ready_ -> _Hash_Absorb_ by a Form A kl.setst: max_len is set by the Machine
    (<<KLEE-process-VLI>>, State Machine Behavior).  In _Hash_Absorb_ each Form B
    kl.exec runs process_VLI(max_len, block, b, state, n, input_base, block_base, 0,
    cumul_len, process_block(), None, mode=assign), transcribed step by step
    (steps 1 to 4.i), with max_len = 0 ("zero if none is enforced") except in the
    max_len checks, which give the CL a small system-defined value.  The only
    interruption point is step 4.i, with klstart <- input_base / 8; resumption sets
    input_base <- 8 * klstart (step 3).  This byte/bit conversion, once review
    finding M4, is now explicit in the text; the pre-fix unit clash is kept as a
    negative control.
  * _Hash_Absorb_ -> _Hash_Output_ (Form A): finalize() is None; block_base must be
    0, else _Invalid_; the entry step block[t-1:0] <- finalize() is not performed;
    block_base <- 0.  In _Hash_Output_ each Form C kl.exec runs the output loop of
    <<KLEE-hash-functions>> reading state[...] in place of block[...]; at
    block_base = t the bits of OUTPUT beyond output_base are cleared and the CL goes
    to _Success_.
  * Error handling: <<KLEE-MGR-not-allowed-instructions>> (a State, transition or
    Form the Machine does not allow), <<KLEE-SGR-no-exec-in-ready>>,
    <<KLEE-SGR-success-failure>>, <<KLEE-SGR-usage-cr-error-state>> (no operation,
    output window zeroed), <<KLEE-instruction-setst>> (an unsupported #immed7), and
    the process_VLI rules (same-State kl.setst; cumul_len >= max_len; termination
    at max_len with the excess input ignored).
  * Serialized Content (Content1): the table of <<KLEE-hash-functions>> as
    <<KLEE-SHA-2>> instantiates it -- no key field (unkeyed), state, last_blk_len
    replaced by padding, block_base, 32 padding bits, cumul_len absent (it is kept
    only under HMAC), block -- zero-padded to a multiple of 128 bits ("Definition of
    a Machine in KLEE").  Every vector is also run through an export/import of
    Content1 taken in the middle of a block.
  * kl.derive between the kl.exec endpoints (index 0) that <<KLEE-derive-endpoints>>
    gives the hash functions (<<KLEE-instruction-derive>>,
    <<KLEE-derive-rule-both-fixed-size>>): a digest is moved into the _Hash_Absorb_
    State of another CL, which the caller then pads and finishes with kl.exec.
  MGR10 (<<KLEE-MGR-progress-discard>>) does not apply: no SHA-2 State performs a
  long-running operation without data.

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
digests.  For kl.derive: SHA-256(SHA-256("hello")) =
9595c9df...83a419833d50, the double-SHA-256 example of the Bitcoin wiki page
"Protocol documentation" (section "Hashes").  hashlib is used ONLY as an
independent reference oracle, clearly labeled; the KLEE model never calls it.

NEGATIVE CONTROLS:
  KAT-EXPECT-FAIL: no-bswap         message words taken without the bswap.
  KAT-EXPECT-FAIL: klstart-in-bits  the pre-M4 unit clash: klstart written as a
                                    bit count and read back as a byte count.
"""
import os, sys, math, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl, bswap, bin_

import hashlib  # independent reference oracle ONLY -- never used by the KLEE model

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

# ------------------------------------------------------- KLEE constants

KL_STATE_READY = 1              # <<KLEE-states-valid>>
KL_STATE_HASH_ABSORB = 2        # <<KLEE-state-constants-symmetric>>
KL_STATE_HASH_LAST_BLOCK = 3    # <<KLEE-state-constants-symmetric>>
KL_STATE_HASH_OUTPUT = 6        # <<KLEE-state-constants-symmetric>>
KL_STATE_SUCCESS = 46           # <<KLEE-states-valid>>
KL_STATE_INVALID = 49           # <<KLEE-states-error>>
ERROR_STATES = range(48, 56)    # <<KLEE-states-error>> (54 and 55 reserved)

PARAMS = {  # <<KLEE-SHA-2-parameters>>: (w, b, n, t)
    'SHA-224':     (32,  512, 256, 224),
    'SHA-256':     (32,  512, 256, 256),
    'SHA-384':     (64, 1024, 512, 384),
    'SHA-512':     (64, 1024, 512, 512),
    'SHA-512/224': (64, 1024, 512, 224),
    'SHA-512/256': (64, 1024, 512, 256),
}
ENCODING = {  # <<KLEE-exec-encodings>>: (Type, Mode)
    'SHA-224': (4, 0), 'SHA-256': (4, 1), 'SHA-384': (4, 2), 'SHA-512': (4, 3),
    'SHA-512/224': (4, 4), 'SHA-512/256': (4, 5),
}
IVS = {  # FIPS 180-4 sect. 5.3
    'SHA-224': H224, 'SHA-256': H256, 'SHA-384': H384, 'SHA-512': H512,
    'SHA-512/224': H512_224, 'SHA-512/256': H512_256,
}
# Content1 length in bytes, transcribed from the Serialized Content table of
# <<KLEE-hash-functions>>: n + 16 + 16 + 32 + b bits, padded to a multiple of 128.
EXPECTED_C1_BYTES = {'SHA-224': 112, 'SHA-256': 112, 'SHA-384': 208,
                     'SHA-512': 208, 'SHA-512/224': 208, 'SHA-512/256': 208}

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
    """`state` from the chaining variables: state[(i+1)w-1 : iw] = bswap(bin(H_i, w))."""
    v = 0
    for i, h in enumerate(H):
        v |= bswap(bin_(h, w), w // 8) << (i * w)
    return v

def state_to_chain(state, w):
    """H_i = int(bswap(state[(i+1)w-1 : iw]))."""
    return [bswap(sl(state, (i + 1) * w - 1, i * w), w // 8) for i in range(8)]

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

ASSIGN, XOR_ACCUMULATE = 'assign', 'xor_accumulate'

def process_VLI(max_len, block, b, state, n, block_base, state_offset, cumul_len,
                process_block, finalize, mode, *, hart, INPUT, KLLEN, resuming,
                halt=False, klstart_in_bits=False):
    """One kl.exec of <<KLEE-process-VLI>> (State Machine Behavior, steps 1-4).

    block, state, block_base and cumul_len are references to variables of the
    caller Machine; cumul_len may be None (not tracked).  input_base belongs to the
    instruction: step 2 resets it, step 3 restores it from klstart.  halt=True
    models an interrupt pending at the first step-4.i point that still leaves input
    unprocessed.  Returns 'invalid', 'terminated', 'interrupted' or 'retired'."""
    # the IMPORTANT box: block_base and cumul_len are distinct storage locations
    assert cumul_len is None or not cumul_len.same(block_base)
    # 1.
    if max_len != 0 and cumul_len.get() >= max_len:
        return 'invalid'
    # 2. / 3.  input_base is in bits, klstart in bytes
    input_base = 8 * hart.klstart if resuming else 0
    # 4.
    while input_base < KLLEN:
        bb = block_base.get()
        # 4.a
        if max_len != 0:
            amount = min(KLLEN - input_base, b - bb, max_len - cumul_len.get())
        else:
            amount = min(KLLEN - input_base, b - bb)
        assert amount > 0
        chunk = sl(INPUT, input_base + amount - 1, input_base)
        if mode == ASSIGN:                                   # 4.b
            block.set(set_slice(block.get(), bb + amount - 1, bb, chunk))
        else:                                                # 4.c
            assert state_offset + b <= n
            state.set(state.get() ^ (chunk << (bb + state_offset)))
        input_base += amount                                 # 4.d
        block_base.set(bb + amount)                          # 4.e
        if max_len != 0:                                     # 4.f
            cumul_len.set(cumul_len.get() + amount)
        if block_base.get() == b:                            # 4.g
            if process_block is not None:
                process_block()
            block_base.set(0)
        if max_len != 0 and cumul_len.get() == max_len:      # 4.h
            if finalize is not None:
                finalize()
            hart.klstart = 0
            return 'terminated'
        # 4.i  "Here, and only here, the instruction may be interrupted"
        if halt and input_base < KLLEN:
            hart.klstart = input_base if klstart_in_bits else input_base // 8
            return 'interrupted'
    hart.klstart = 0        # <<KLEE-CSR-klstart>>: written with 0 when the instruction retires
    return 'retired'

# ------------------------------------------------------- the KLEE model

class KleeSha2CL:
    """One CL holding a SHA-2 CC per <<KLEE-SHA-2>>; all quantities are KLEE values."""

    def __init__(self, name, hart, max_len=0, be_words=True, klstart_in_bits=False):
        self.name, self.hart = name, hart
        self.w, self.b, self.n, self.t = PARAMS[name]
        typ, mode = ENCODING[name]
        self.machine = (typ << 4) | mode            # _Type_ in [11:4], _Mode_ in [3:0]
        self.iv = IVS[name]
        self.K, self.rounds = (K256, 64) if self.w == 32 else (K512, 80)
        self.max_len = max_len                      # system-defined, 0 if none enforced
        self.be_words = be_words                    # negative-control switch
        self.klstart_in_bits = klstart_in_bits      # negative-control switch
        self.mdh_state = 0                          # _Unconfigured_
        self._clear_content()

    # ---- configuration
    def provision(self):
        """The PI is the MDH only (<<KLEE-SHA-2>>): no Content follows it."""
        self.mdh_state = KL_STATE_READY
        self._enter_ready()
        return self

    def export_content1(self):
        """Content1 per the Serialized Content table of <<KLEE-hash-functions>>."""
        return pack([
            # i    key or SKID: unkeyed, 0 bits
            (self.state, self.n),           # ii   state
            (0, 16),                        # iii  last_blk_len: unused, padding
            (self.block_base, 16),          # iv   block_base (bits, as process_VLI keeps it)
            (0, 32),                        # v    padding
            # vi   cumul_len: absent outside HMAC
            (self.block, self.b),           # vii  block
        ])

    def import_content1(self, mdh_state, content1):
        """Completing an import: the MDH supplies _State_, Content1 the fields."""
        v, n, b = b2v(content1), self.n, self.b
        self.state = sl(v, n - 1, 0)
        self.last_blk_len = 0
        self.block_base = sl(v, n + 31, n + 16)
        self.cumul_len = 0
        self.block = sl(v, n + 64 + b - 1, n + 64)
        self.mdh_state = mdh_state
        return self

    # ---- internal
    def _clear_content(self):
        self.state = self.block = self.block_base = self.cumul_len = self.last_blk_len = 0

    def _to_error(self, s):
        self.mdh_state = s
        self._clear_content()           # <<KLEE-SGR-clear-cr-content-error-state>>

    def _invalid(self):
        self._to_error(KL_STATE_INVALID)

    def _enter_ready(self):
        # <<KLEE-hash-functions>>: last_blk_len, block_base, cumul_len, block <- 0
        self._clear_content()
        # <<KLEE-SHA-2>>: state <- initial hash value (FIPS 180-4 sect. 5.3)
        self.state = chain_to_state(self.iv, self.w)

    def _process_block(self):
        """process_block(): FIPS 180-4 sect. 6 compression of `block` into `state`."""
        W = []
        for j in range(16):
            word = sl(self.block, (j + 1) * self.w - 1, j * self.w)
            W.append(bswap(word, self.w // 8) if self.be_words else word)
        H = sha2_compress(state_to_chain(self.state, self.w), W, self.w,
                          self.K, self.rounds)
        self.state = chain_to_state(H, self.w)

    # ---- usage instructions
    def kl_setst(self, immed, form='A'):
        """kl.setst Kd, #immed7 [, aux] (<<KLEE-instruction-setst>>)."""
        st = self.mdh_state
        if immed in ERROR_STATES:       # accepted in any State, without an exception
            self._to_error(immed if immed <= 53 else KL_STATE_INVALID)
            return
        if st in ERROR_STATES:          # only a change of Error State is possible
            return
        if immed == KL_STATE_READY:     # from any valid State, _Success_ included
            self._enter_ready()
            self.mdh_state = KL_STATE_READY
            return
        if st == KL_STATE_SUCCESS:      # <<KLEE-SGR-setst-in-success-failure>>
            self._invalid()
            return
        if immed == KL_STATE_HASH_ABSORB:
            # <<KLEE-process-VLI>>: a same-State transition is not allowed; max_len is
            # set by the Machine, so the kl.setst must be of Form A.
            if st != KL_STATE_READY or form != 'A':
                self._invalid()
                return
            self.mdh_state = KL_STATE_HASH_ABSORB
            return
        if immed == KL_STATE_HASH_OUTPUT:
            if st != KL_STATE_HASH_ABSORB or form != 'A':
                self._invalid()
                return
            # process_VLI performs finalize() before leaving the State: None here.
            # <<KLEE-SHA-2>>: stand-alone hashing requires block_base = 0.
            if self.block_base != 0:
                self._invalid()
                return
            # <<KLEE-hash-functions>> entry steps: block[t-1:0] <- finalize() is not
            # performed (<<KLEE-SHA-2>>); block_base <- 0.
            self.block_base = 0
            self.mdh_state = KL_STATE_HASH_OUTPUT
            return
        # _Hash_Absorb_Last_Block_ (SHA-2 has none) or any other unsupported value
        self._invalid()

    def kl_exec(self, form, data=b'', nbytes=0, resuming=False, halt=False, prior=None):
        """kl.exec Form B (input only) or Form C (output only).
        Returns (status, output bytes or None)."""
        KLLEN = 8 * (len(data) if form == 'B' else nbytes)
        st = self.mdh_state
        if st in ERROR_STATES:          # no operation; the output window is zeroed
            return 'noop', (bytes(nbytes) if form == 'C' else None)
        if st == KL_STATE_HASH_ABSORB and form == 'B':
            r = process_VLI(self.max_len, Ref(self, 'block'), self.b, Ref(self, 'state'),
                            self.n, Ref(self, 'block_base'), 0, Ref(self, 'cumul_len'),
                            self._process_block, None, ASSIGN,
                            hart=self.hart, INPUT=b2v(data), KLLEN=KLLEN,
                            resuming=resuming, halt=halt,
                            klstart_in_bits=self.klstart_in_bits)
            if r == 'invalid':
                self._invalid()
            return r, None
        if st == KL_STATE_HASH_OUTPUT and form == 'C':
            return 'retired', v2b(self._hash_output(KLLEN, resuming, prior), nbytes)
        # _Ready_ (<<KLEE-SGR-no-exec-in-ready>>), _Success_ of a hash function
        # (<<KLEE-SGR-success-failure>>), or a Form the State does not expect
        # (<<KLEE-MGR-not-allowed-instructions>>)
        self._invalid()
        return 'invalid', (bytes(nbytes) if form == 'C' else None)

    def _hash_output(self, KLLEN, resuming, prior):
        """The _Hash_Output_ loop of <<KLEE-hash-functions>>, reading `state`."""
        OUTPUT = b2v(prior) if prior is not None else 0   # the register's old content
        output_base = 8 * self.hart.klstart if resuming else 0
        while output_base < KLLEN:
            amount = min(KLLEN - output_base, self.t - self.block_base)
            OUTPUT = set_slice(OUTPUT, output_base + amount - 1, output_base,
                               sl(self.state, self.block_base + amount - 1,
                                  self.block_base))
            output_base += amount
            self.block_base += amount
            if self.block_base == self.t:
                # a hash function: the bits of OUTPUT beyond output_base are
                # cleared, the State becomes _Success_, and the instruction returns
                OUTPUT = sl(OUTPUT, output_base - 1, 0)
                self.mdh_state = KL_STATE_SUCCESS
                break
            # update(); block_base <- 0; interruption point -- XOFs only
        self.hart.klstart = 0
        return sl(OUTPUT, KLLEN - 1, 0) if KLLEN else 0

def kl_derive(dst, src, length, hart):
    """kl.derive dst, src, length between the kl.exec endpoints (0) that
    <<KLEE-derive-endpoints>> gives the hash functions (<<KLEE-instruction-derive>>)."""
    # <<KLEE-SGR-gate-order>>: an Error State on either endpoint makes it a no-op
    if src.mdh_state in ERROR_STATES or dst.mdh_state in ERROR_STATES:
        return 'noop'
    # Checks, item 1, source first: each State must admit its endpoint.  The source
    # endpoint is a kl.exec output, admitted where a Form C kl.exec is (not in
    # _Success_, <<KLEE-SGR-success-failure>>); the destination endpoint is the
    # kl.exec input of _Hash_Absorb_.
    src_ok = src.mdh_state == KL_STATE_HASH_OUTPUT
    dst_ok = dst.mdh_state == KL_STATE_HASH_ABSORB
    if not (src_ok and dst_ok):
        if not src_ok:
            src._invalid()
        if not dst_ok:
            dst._invalid()
        return 'refused'                # nothing is transferred
    if length == 0:                     # transfers nothing, changes no state
        return 'noop'
    # Transfer: not a field destination, so eff_length = length.  Each endpoint
    # advances as the kl.exec producing / consuming these bytes would.
    _, data = src.kl_exec('C', nbytes=length)
    dst.kl_exec('B', data=data)
    hart.klstart = 0
    return 'done'

# ------------------------------------------------------- drivers

HART = Hart()

def fips_pad(nbytes, w, b):
    """The caller's padding for an nbytes message: FIPS 180-4 sect. 5.1."""
    lb = 2 * w // 8
    return (b'\x80' + bytes((-(nbytes + 1 + lb)) % (b // 8))
            + (8 * nbytes).to_bytes(lb, 'big'))

def fresh(name='SHA-256', **kw):
    return KleeSha2CL(name, HART, **kw).provision()

def kl_digest(name, msg, plan, be_words=True, klstart_in_bits=False):
    """Run one message through a CL.

    'multi':     the padded message in three transfers cut inside blocks (4-byte
                 multiples: granularity 32); the digest read by two Form C kl.exec.
    'interrupt': a 4-byte transfer, then the rest in one kl.exec halted at every
                 process_VLI interruption point and resumed from klstart.
    'export':    stop with a partial block pending, export Content1, import it into
                 a fresh CL and finish there.
    """
    cl = KleeSha2CL(name, HART, be_words=be_words,
                    klstart_in_bits=klstart_in_bits).provision()
    w, b, t = cl.w, cl.b, cl.t
    mp = msg + fips_pad(len(msg), w, b)
    cl.kl_setst(KL_STATE_HASH_ABSORB)
    if plan == 'multi':
        c1, c2 = 4, len(mp) // 2 - 8
        for piece in (mp[:c1], mp[c1:c1 + c2], mp[c1 + c2:]):
            assert cl.kl_exec('B', piece)[0] == 'retired'
    elif plan == 'interrupt':
        assert cl.kl_exec('B', mp[:4])[0] == 'retired'
        st, _ = cl.kl_exec('B', mp[4:], halt=True)
        while st == 'interrupted':
            st, _ = cl.kl_exec('B', mp[4:], resuming=True, halt=True)
        assert st == 'retired'
    else:
        cut = len(mp) - 28                  # leaves b/8 - 28 bytes of a block pending
        assert cl.kl_exec('B', mp[:cut])[0] == 'retired' and cl.block_base != 0
        c1 = cl.export_content1()
        cl = KleeSha2CL(name, HART).import_content1(KL_STATE_HASH_ABSORB, c1)
        assert cl.kl_exec('B', mp[cut:])[0] == 'retired'
    cl.kl_setst(KL_STATE_HASH_OUTPUT)
    if plan == 'multi':
        out = cl.kl_exec('C', nbytes=t // 8 - 8)[1] + cl.kl_exec('C', nbytes=8)[1]
    else:
        out = cl.kl_exec('C', nbytes=t // 8)[1]
    return out if cl.mdh_state == KL_STATE_SUCCESS else None

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
# Bitcoin wiki, "Protocol documentation", section "Hashes": SHA-256(SHA-256("hello"))
SHA256D_HELLO = '9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50'

HASHLIB = {'SHA-224': 'sha224', 'SHA-256': 'sha256', 'SHA-384': 'sha384',
           'SHA-512': 'sha512', 'SHA-512/224': 'sha512_224',
           'SHA-512/256': 'sha512_256'}
MNAME = {id(M_EMPTY): 'empty', id(M_ABC): '"abc"',
         id(M2_32): 'two-block (448b)', id(M2_64): 'two-block (896b)'}

def oracle(name, msg):
    """hashlib: independent reference oracle only (never part of the KLEE model)."""
    try:
        return hashlib.new(HASHLIB[name], msg).digest()
    except ValueError:
        return None

ok = True

def check(label, cond):
    global ok
    ok &= bool(cond)
    print(f'  {"PASS" if cond else "FAIL"}  {label}')

def pf(c):
    return 'PASS' if c else 'FAIL'

print('SHA-2 family per <<KLEE-SHA-2>> / <<KLEE-hash-functions>> / <<KLEE-process-VLI>>\n')
print(f'{"function":13} {"message":18} {"multi-chunk":12} {"interrupted":12} '
      f'{"export/import":14} {"oracle"}')
for name in PARAMS:
    for msg, exp_hex in VEC[name].items():
        exp = bytes.fromhex(exp_hex)
        ga = kl_digest(name, msg, 'multi') == exp
        gb = kl_digest(name, msg, 'interrupt') == exp
        gc = kl_digest(name, msg, 'export') == exp
        r = oracle(name, msg)
        orac = 'n/a' if r is None else pf(r == exp)
        ok &= ga and gb and gc and orac != 'FAIL'
        print(f'{name:13} {MNAME[id(msg)]:18} {pf(ga):12} {pf(gb):12} {pf(gc):14} {orac}')

print('\nSerialized Content (Content1) length, <<KLEE-hash-functions>> table:')
for name in PARAMS:
    cl = fresh(name)
    cl.kl_setst(KL_STATE_HASH_ABSORB)
    cl.kl_exec('B', bytes(8))
    got = len(cl.export_content1())
    check(f'{name:12} {got} bytes (expected {EXPECTED_C1_BYTES[name]}: n + 16 + 16 + '
          f'32 + b bits, padded to 128)', got == EXPECTED_C1_BYTES[name])

print('\nState machine and error handling:')
PAD_ABC_256 = M_ABC + fips_pad(3, 32, 512)
DIG_ABC_256 = bytes.fromhex(VEC['SHA-256'][M_ABC])

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', b'abc')                     # 3 bytes: admissible as a last transfer
cl.kl_setst(KL_STATE_HASH_OUTPUT)
check('unpadded message (block_base != 0) -> _Invalid_ on entering _Hash_Output_ '
      '(<<KLEE-SHA-2>>)', cl.mdh_state == KL_STATE_INVALID)

cl = fresh()
cl.kl_exec('B', PAD_ABC_256)
check('kl.exec in _Ready_ -> _Invalid_ (<<KLEE-SGR-no-exec-in-ready>>)',
      cl.mdh_state == KL_STATE_INVALID)

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB, form='B')
check('Form B kl.setst to _Hash_Absorb_ -> _Invalid_ (max_len is set by the Machine, '
      'so Form A is required: <<KLEE-process-VLI>>)', cl.mdh_state == KL_STATE_INVALID)

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_setst(KL_STATE_HASH_ABSORB)
check('same-State kl.setst to _Hash_Absorb_ -> _Invalid_ (<<KLEE-process-VLI>>)',
      cl.mdh_state == KL_STATE_INVALID)

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_setst(KL_STATE_HASH_LAST_BLOCK, form='B')
check('kl.setst #kl_state_hash_last_block -> _Invalid_ (<<KLEE-SHA-2>> has no such '
      'State)', cl.mdh_state == KL_STATE_INVALID)

cl = fresh()
cl.kl_setst(KL_STATE_HASH_OUTPUT)
check('_Ready_ -> _Hash_Output_ -> _Invalid_ (not an allowed transition)',
      cl.mdh_state == KL_STATE_INVALID)

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
_, out = cl.kl_exec('C', nbytes=16)
check('Form C kl.exec in _Hash_Absorb_ -> _Invalid_, output window zeroed '
      '(<<KLEE-MGR-not-allowed-instructions>>)',
      cl.mdh_state == KL_STATE_INVALID and out == bytes(16))

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', PAD_ABC_256)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
cl.kl_exec('B', bytes(64))
check('Form B kl.exec in _Hash_Output_ -> _Invalid_ '
      '(<<KLEE-MGR-not-allowed-instructions>>)', cl.mdh_state == KL_STATE_INVALID)

cl = fresh('SHA-224')
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', M_ABC + fips_pad(3, 32, 512))
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = cl.kl_exec('C', nbytes=32, prior=b'\xa5' * 32)
check('SHA-224 read with KLLEN = 256 > t: 28 digest bytes, the 4 beyond cleared, '
      '-> _Success_ (<<KLEE-hash-functions>>)',
      out == bytes.fromhex(VEC['SHA-224'][M_ABC]) + bytes(4)
      and cl.mdh_state == KL_STATE_SUCCESS)
_, out = cl.kl_exec('C', nbytes=28, prior=b'\xa5' * 28)
check('kl.exec in _Success_ of a hash function -> _Invalid_, output window zeroed '
      '(<<KLEE-SGR-success-failure>>)',
      cl.mdh_state == KL_STATE_INVALID and out == bytes(28))
st, out = cl.kl_exec('C', nbytes=28, prior=b'\xa5' * 28)
check('kl.exec on a CL in _Invalid_: no operation, State kept, output zeroed '
      '(<<KLEE-SGR-usage-cr-error-state>>)',
      st == 'noop' and cl.mdh_state == KL_STATE_INVALID and out == bytes(28))

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', PAD_ABC_256)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
cl.kl_exec('C', nbytes=32)
cl.kl_setst(KL_STATE_READY)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', PAD_ABC_256)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = cl.kl_exec('C', nbytes=32)
check('_Success_ -> _Ready_ (<<KLEE-SGR-setst-in-success-failure>>), then a second '
      'digest', out == DIG_ABC_256 and cl.mdh_state == KL_STATE_SUCCESS)

cl = fresh('SHA-384')
cl.kl_setst(KL_STATE_HASH_ABSORB)
mp = M2_64 + fips_pad(len(M2_64), 64, 1024)
cl.kl_exec('B', mp[:132])                   # one block processed, 4 bytes pending
dirty = cl.block_base != 0 and cl.state != chain_to_state(H384, 64)
cl.kl_setst(KL_STATE_READY)
reset = (cl.state == chain_to_state(H384, 64) and cl.block == 0
         and cl.block_base == 0 and cl.cumul_len == 0 and cl.last_blk_len == 0)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', M_ABC + fips_pad(3, 64, 1024))
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = cl.kl_exec('C', nbytes=48)
check('_Hash_Absorb_ -> _Ready_ mid-message: state <- IV, block, block_base, '
      'cumul_len <- 0; the next digest is right',
      dirty and reset and out == bytes.fromhex(VEC['SHA-384'][M_ABC]))

MP2 = M2_32 + fips_pad(len(M2_32), 32, 512)     # 1024 bits
cl = fresh(max_len=1024)
cl.kl_setst(KL_STATE_HASH_ABSORB)
st, _ = cl.kl_exec('B', MP2 + b'\xde\xad\xbe\xef' * 2)
term = st == 'terminated' and cl.cumul_len == 1024
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = cl.kl_exec('C', nbytes=32)
check('system-defined max_len = 1024: the instruction ends at cumul_len = max_len, the '
      '8 excess bytes are ignored (<<KLEE-process-VLI>> step 4.h)',
      term and out == bytes.fromhex(VEC['SHA-256'][M2_32]))
cl = fresh(max_len=1024)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', MP2)
cl.kl_exec('B', bytes(4))
check('max_len reached: a further kl.exec -> _Invalid_ (<<KLEE-process-VLI>> step 1)',
      cl.mdh_state == KL_STATE_INVALID)

print('\nkl.derive between kl.exec endpoints (<<KLEE-derive-endpoints>>):')
hello = b'hello'
src = fresh()
src.kl_setst(KL_STATE_HASH_ABSORB)
src.kl_exec('B', hello + fips_pad(len(hello), 32, 512))
src.kl_setst(KL_STATE_HASH_OUTPUT)
dst = fresh()
dst.kl_setst(KL_STATE_HASH_ABSORB)
r = kl_derive(dst, src, 32, HART)
moved = (r == 'done' and src.mdh_state == KL_STATE_SUCCESS
         and dst.mdh_state == KL_STATE_HASH_ABSORB and dst.block_base == 256)
dst.kl_exec('B', fips_pad(32, 32, 512))     # the caller pads the 256-bit message
dst.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = dst.kl_exec('C', nbytes=32)
check('SHA-256 digest -> SHA-256 _Hash_Absorb_ (32 bytes), caller pads: '
      'SHA-256(SHA-256("hello")) = Bitcoin-wiki value; source -> _Success_',
      moved and out == bytes.fromhex(SHA256D_HELLO))

src512 = fresh('SHA-512')
src512.kl_setst(KL_STATE_HASH_ABSORB)
src512.kl_exec('B', M_ABC + fips_pad(3, 64, 1024))
src512.kl_setst(KL_STATE_HASH_OUTPUT)
dst224 = fresh('SHA-224')
dst224.kl_setst(KL_STATE_HASH_ABSORB)
r = kl_derive(dst224, src512, 64, HART)
whole = r == 'done' and dst224.block_base == 0 and \
    dst224.state != chain_to_state(H224, 32)
dst224.kl_exec('B', fips_pad(64, 32, 512))
dst224.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = dst224.kl_exec('C', nbytes=28)
check('SHA-512 digest -> SHA-224 _Hash_Absorb_ (64 bytes = one block, processed '
      'during the transfer) = SHA-224(SHA-512("abc")) [hashlib oracle]',
      whole and out == hashlib.sha224(bytes.fromhex(VEC['SHA-512'][M_ABC])).digest())

late = fresh()
late.kl_setst(KL_STATE_HASH_ABSORB)
r = kl_derive(late, src, 32, HART)          # src is in _Success_
check('source in _Success_ (digest already emitted): refused, source -> _Invalid_, '
      'destination untouched', r == 'refused' and src.mdh_state == KL_STATE_INVALID
      and late.mdh_state == KL_STATE_HASH_ABSORB and late.block_base == 0)

src = fresh()
src.kl_setst(KL_STATE_HASH_ABSORB)
src.kl_exec('B', PAD_ABC_256)
src.kl_setst(KL_STATE_HASH_OUTPUT)
dst = fresh()                               # still in _Ready_
r = kl_derive(dst, src, 32, HART)
kept = src.mdh_state == KL_STATE_HASH_OUTPUT and src.block_base == 0
check('destination in _Ready_: refused, destination -> _Invalid_, nothing taken from '
      'the source', r == 'refused' and dst.mdh_state == KL_STATE_INVALID and kept)
dst = fresh()
dst.kl_setst(KL_STATE_HASH_ABSORB)
r0 = kl_derive(dst, src, 0, HART)
_, out = src.kl_exec('C', nbytes=32)
check('length = 0: nothing transferred, no State changes; the source still emits its '
      'digest', r0 == 'noop' and dst.mdh_state == KL_STATE_HASH_ABSORB
      and dst.block_base == 0 and out == DIG_ABC_256)

print('\nNegative controls:')
print('KAT-EXPECT-FAIL: no-bswap')
bad = kl_digest('SHA-256', M_ABC, 'multi', be_words=False)
fired = bad != DIG_ABC_256
print(f'  no-bswap control, SHA-256("abc") vs FIPS vector: '
      f'{"FAIL (expected: control is effective)" if fired else "PASS (CONTROL IS DEAD)"}')
ok &= fired
print('KAT-EXPECT-FAIL: klstart-in-bits')
bad = kl_digest('SHA-256', M2_32, 'interrupt', klstart_in_bits=True)
fired = bad != bytes.fromhex(VEC['SHA-256'][M2_32])
print(f'  klstart-in-bits control, SHA-256(two-block) interrupted: '
      f'{"FAIL (expected: control is effective)" if fired else "PASS (CONTROL IS DEAD)"}')
ok &= fired

print()
print('SPEC-NOTE: the "Endianness" paragraph of <<KLEE-SHA-2>> is commented out, so the')
print('  Machine no longer states the message-word mapping or the layout of `state`;')
print('  only the FIPS 180-4 row of <<KLEE-Notation-standards>> (an aid that "does not')
print('  relieve an algorithm description of the obligation to be explicit") and the words')
print('  "big-endian encoding" of _Hash_Output_ remain.  The model uses the mapping that')
print('  paragraph gave: word j = int(bswap(block[(j+1)w-1 : jw])).')
print('INFO: `state` layout chosen as state[(i+1)w-1 : iw] = bswap(bin(H_i, w)), the one')
print('  under which _Hash_Output_ emits state[t-1:0] as the big-endian digest.')
print('INFO: Serialized Content: the table says cumul_len is "absent" outside HMAC, the')
print('  NOTE under it that an unused one "is replaced by a corresponding padding block";')
print('  the model follows the table (block at bit n + 64).  Both give the same length.')
print('  block_base is serialized as bin(block_base, 16) in bits, the process_VLI unit.')
print('SPEC-NOTE: with a system-defined max_len != 0, process_VLI keeps cumul_len (steps')
print('  1, 4.f, 4.h), but <<KLEE-SHA-2>> lists cumul_len only under HMAC and the')
print('  Serialized Content omits it, so the limit restarts after an export/import.')
print('INFO: _Hash_Absorb_ -> _Hash_Output_ is modeled as a Form A kl.setst; the text')
print('  names no auxiliary parameter for it.')
print('INFO: granularity 32 is honored by the transfer plans; the only violation a SHA-2')
print('  CL can detect is a non-zero block_base on entering _Hash_Output_.')
print('INFO: kl.derive is exercised with length = t/8 only.  For a shorter length the')
print('  text allows two readings of the source side ("the unused part of the last block')
print('  is discarded" vs "advances as the kl.exec operations ... would").  A refused')
print('  transfer invalidates only the offending CL (Checks, item 1), not "both CLs".')

print(f'\nruntime: {time.time() - T0:.2f} s')
print(f'KAT-RESULT: {"PASS" if ok else "FAIL"}')
sys.exit(0 if ok else 1)
