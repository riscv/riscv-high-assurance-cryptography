#!/usr/bin/env python3
"""SM3 KAT for the KLEE specification (<<KLEE-SM3>> over <<KLEE-SHA-2>>/<<KLEE-hash-functions>>).

<<KLEE-SM3>> says that SM3 "follows exactly the rules of the SHA-2 family
(<<KLEE-SHA-2>>) with w = 32, b = 512, n = 256, and t = 256: it has a big-endian
representation with the same padding rule and word mapping as SHA-256, and the same
state machine.  The initial hash value and the compression function are those of the
SM3 standard."  This harness therefore instantiates the same model as
kat/sha2-kat.py, transcribed from the current text, with the GB/T 32905-2016 core:

  * Parameters w, b, n, t from <<KLEE-SM3>>; the _Machine_ encoding Type 9, Mode 0 of
    <<KLEE-exec-encodings>>; the State values of <<KLEE-states-valid>>,
    <<KLEE-state-constants-symmetric>> and <<KLEE-states-error>>.
  * PI: the MDH only.  _Ready_: `state` <- the IV of GB/T 32905-2016; last_blk_len,
    block_base, cumul_len and block <- 0.
  * `state` is one n-bit value with state[(i+1)w-1 : iw] = bswap(bin(V_i, w)), the
    layout under which _Hash_Output_ emits state[t-1:0] as "the chaining variables in
    the big-endian encoding"; process_block() takes message word
    j = int(bswap(block[(j+1)w-1 : jw])) -- the word mapping of SHA-256, which the
    FIPS 180-4 row of <<KLEE-Notation-standards>> states as "message schedule words
    ... via bswap" (SPEC-NOTE: the paragraph of <<KLEE-SHA-2>> that spelled both out
    is commented out in the current text).
  * _Ready_ -> _Hash_Absorb_ by a Form A kl.setst (max_len is set by the Machine,
    <<KLEE-process-VLI>>).  In _Hash_Absorb_ each Form B kl.exec runs
    process_VLI(max_len, block, b, state, n, input_base, block_base, 0, cumul_len,
    process_block(), None, mode=assign), transcribed step by step, with max_len = 0
    except in the max_len checks.  The only interruption point is step 4.i, with
    klstart <- input_base / 8 and resumption at input_base <- 8 * klstart; the pre-M4
    unit clash is kept as a negative control.
  * _Hash_Absorb_ -> _Hash_Output_ (Form A): block_base must be 0, else _Invalid_;
    the entry step block[t-1:0] <- finalize() is not performed; block_base <- 0.  In
    _Hash_Output_ each Form C kl.exec runs the output loop of
    <<KLEE-hash-functions>> reading state[...]; at block_base = t the bits of OUTPUT
    beyond output_base are cleared and the CL goes to _Success_.
  * Error handling: <<KLEE-MGR-not-allowed-instructions>>,
    <<KLEE-SGR-no-exec-in-ready>>, <<KLEE-SGR-success-failure>>,
    <<KLEE-SGR-usage-cr-error-state>>, and the process_VLI rules (same-State
    kl.setst; cumul_len >= max_len; termination at max_len).
  * Serialized Content (Content1) per <<KLEE-hash-functions>>: state, last_blk_len
    replaced by padding, block_base, 32 padding bits, cumul_len absent (kept only
    under HMAC), block, zero-padded to a multiple of 128 bits; every vector is also
    run through an export/import taken in the middle of a block.
  * kl.derive between the kl.exec endpoints (index 0) that <<KLEE-derive-endpoints>>
    gives the hash functions, SM3 included.

Checks: both GB/T 32905-2016 appendix A vectors in three transfer plans; the model
against an independent byte-oriented SM3 reference over many message lengths; the
Content1 length; the state machine and error rules; a double-SM3 kl.derive; and, when
the platform's hashlib provides 'sm3', a labeled reference oracle.

NEGATIVE CONTROLS:
  KAT-EXPECT-FAIL: no-bswap         message words taken without the bswap.
  KAT-EXPECT-FAIL: klstart-in-bits  the pre-M4 unit clash: klstart written as a bit
                                    count and read back as a byte count.

VECTOR PROVENANCE: GB/T 32905-2016 appendix A gives
  SM3("abc")       = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
  SM3("abcd" x 16) = debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
The first differs from the value quoted in this harness's commissioning brief
(66c7f0f4a54445d3...d28b), which is not the standard's digest; the published value is
used here and both implementations reproduce it.
"""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl, bswap, bin_

import hashlib  # optional reference oracle ONLY -- never used by the KLEE model

T0 = time.time()

# ------------------------------------------------------- SM3 core (GB/T 32905-2016)

M32 = 0xffffffff
IV_SM3 = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
          0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]

def rotl(x, r):
    r %= 32
    return ((x << r) | (x >> (32 - r))) & M32 if r else x

def P0(x): return x ^ rotl(x, 9) ^ rotl(x, 17)
def P1(x): return x ^ rotl(x, 15) ^ rotl(x, 23)

def sm3_compress(V, W16):
    """CF of GB/T 32905-2016 sect. 5.3.3 on the eight 32-bit chaining words."""
    W = list(W16)
    for j in range(16, 68):
        W.append(P1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15))
                 ^ rotl(W[j - 13], 7) ^ W[j - 6])
    Wp = [W[j] ^ W[j + 4] for j in range(64)]
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        T = 0x79cc4519 if j < 16 else 0x7a879d8a
        SS1 = rotl((rotl(A, 12) + E + rotl(T, j)) & M32, 7)
        SS2 = SS1 ^ rotl(A, 12)
        FF = (A ^ B ^ C) if j < 16 else ((A & B) | (A & C) | (B & C))
        GG = (E ^ F ^ G) if j < 16 else ((E & F) | (~E & G & M32))
        TT1 = (FF + D + SS2 + Wp[j]) & M32
        TT2 = (GG + H + SS1 + W[j]) & M32
        D, C, B, A = C, rotl(B, 9), A, TT1
        H, G, F, E = G, rotl(F, 19), E, P0(TT2)
    return [v ^ x for v, x in zip(V, [A, B, C, D, E, F, G, H])]

def sm3_ref(msg):
    """Independent byte-oriented reference: plain big-endian SM3, no KLEE model."""
    m = msg + b'\x80' + bytes((-(len(msg) + 9)) % 64) + (8 * len(msg)).to_bytes(8, 'big')
    V = list(IV_SM3)
    for i in range(0, len(m), 64):
        V = sm3_compress(V, [int.from_bytes(m[i + 4 * j: i + 4 * j + 4], 'big')
                             for j in range(16)])
    return b''.join(v.to_bytes(4, 'big') for v in V)

# ------------------------------------------------------- KLEE constants

KL_STATE_READY = 1              # <<KLEE-states-valid>>
KL_STATE_HASH_ABSORB = 2        # <<KLEE-state-constants-symmetric>>
KL_STATE_HASH_LAST_BLOCK = 3    # <<KLEE-state-constants-symmetric>>
KL_STATE_HASH_OUTPUT = 6        # <<KLEE-state-constants-symmetric>>
KL_STATE_SUCCESS = 46           # <<KLEE-states-valid>>
KL_STATE_INVALID = 49           # <<KLEE-states-error>>
ERROR_STATES = range(48, 56)    # <<KLEE-states-error>> (54 and 55 reserved)

W, B, N, T = 32, 512, 256, 256  # <<KLEE-SM3>>
MACHINE = (9 << 4) | 0          # <<KLEE-exec-encodings>>: Type 9, Mode 0
# Content1 length in bytes from the Serialized Content table of
# <<KLEE-hash-functions>>: n + 16 + 16 + 32 + b bits, padded to a multiple of 128.
EXPECTED_C1_BYTES = 112

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

def chain_to_state(V):
    """`state` from the chaining words: state[(i+1)w-1 : iw] = bswap(bin(V_i, w))."""
    v = 0
    for i, h in enumerate(V):
        v |= bswap(bin_(h, W), W // 8) << (i * W)
    return v

def state_to_chain(state):
    """V_i = int(bswap(state[(i+1)w-1 : iw]))."""
    return [bswap(sl(state, (i + 1) * W - 1, i * W), W // 8) for i in range(8)]

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

    block, state, block_base and cumul_len are references to variables of the caller
    Machine; cumul_len may be None (not tracked).  input_base belongs to the
    instruction: step 2 resets it, step 3 restores it from klstart.  halt=True models
    an interrupt pending at the first step-4.i point that still leaves input
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

class KleeSm3CL:
    """One CL holding an SM3 CC per <<KLEE-SM3>>; all quantities are KLEE values."""

    w, b, n, t = W, B, N, T
    machine = MACHINE

    def __init__(self, hart, max_len=0, be_words=True, klstart_in_bits=False):
        self.hart = hart
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
        # <<KLEE-SM3>>: state <- the initial hash value of the SM3 standard
        self.state = chain_to_state(IV_SM3)

    def _process_block(self):
        """process_block(): the GB/T 32905-2016 compression of `block` into `state`."""
        W16 = []
        for j in range(16):
            word = sl(self.block, (j + 1) * self.w - 1, j * self.w)
            W16.append(bswap(word, 4) if self.be_words else word)
        self.state = chain_to_state(sm3_compress(state_to_chain(self.state), W16))

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
        # _Hash_Absorb_Last_Block_ (SM3 has none) or any other unsupported value
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
                # a hash function: the bits of OUTPUT beyond output_base are cleared,
                # the State becomes _Success_, and the instruction returns
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

def caller_pad(nbytes):
    """The caller's padding: GB/T 32905-2016 sect. 4.2 (as FIPS 180-4 sect. 5.1)."""
    return b'\x80' + bytes((-(nbytes + 9)) % 64) + (8 * nbytes).to_bytes(8, 'big')

def fresh(**kw):
    return KleeSm3CL(HART, **kw).provision()

def kl_sm3(msg, plan='multi', be_words=True, klstart_in_bits=False):
    """Run one message through a CL.

    'multi':     the padded message in up to three transfers cut inside blocks
                 (4-byte multiples: granularity 32); the digest read by two Form C
                 kl.exec instructions.
    'interrupt': a 4-byte transfer, then the rest in one kl.exec halted at every
                 process_VLI interruption point and resumed from klstart.
    'export':    stop with a partial block pending, export Content1, import it into a
                 fresh CL and finish there.
    """
    cl = KleeSm3CL(HART, be_words=be_words, klstart_in_bits=klstart_in_bits).provision()
    mp = msg + caller_pad(len(msg))
    cl.kl_setst(KL_STATE_HASH_ABSORB)
    if plan == 'multi':
        c1 = 4 if len(mp) > 12 else len(mp)          # 32-bit granularity
        c2 = max(4, (len(mp) - c1) // 2 // 4 * 4)
        for piece in (mp[:c1], mp[c1:c1 + c2], mp[c1 + c2:]):
            if piece:
                assert cl.kl_exec('B', piece)[0] == 'retired'
    elif plan == 'interrupt':
        assert cl.kl_exec('B', mp[:4])[0] == 'retired'
        st, _ = cl.kl_exec('B', mp[4:], halt=True)
        while st == 'interrupted':
            st, _ = cl.kl_exec('B', mp[4:], resuming=True, halt=True)
        assert st == 'retired'
    else:
        cut = len(mp) - 28                  # leaves 36 bytes of a block pending
        assert cl.kl_exec('B', mp[:cut])[0] == 'retired' and cl.block_base != 0
        c1 = cl.export_content1()
        cl = KleeSm3CL(HART).import_content1(KL_STATE_HASH_ABSORB, c1)
        assert cl.kl_exec('B', mp[cut:])[0] == 'retired'
    cl.kl_setst(KL_STATE_HASH_OUTPUT)
    if plan == 'multi':
        out = cl.kl_exec('C', nbytes=24)[1] + cl.kl_exec('C', nbytes=8)[1]
    else:
        out = cl.kl_exec('C', nbytes=32)[1]
    return out if cl.mdh_state == KL_STATE_SUCCESS else None

# ------------------------------------------------------- vectors and checks

TV = [  # GB/T 32905-2016 appendix A
    ('"abc"', b'abc',
     '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
    ('"abcd" x 16 (512b)', b'abcd' * 16,
     'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'),
]

def oracle(msg):
    """hashlib 'sm3' where the platform provides it: reference oracle only."""
    try:
        return hashlib.new('sm3', msg).digest()
    except ValueError:
        return None

ok = True

def check(label, cond):
    global ok
    ok &= bool(cond)
    print(f'  {"PASS" if cond else "FAIL"}  {label}')

def pf(c):
    return 'PASS' if c else 'FAIL'

print('SM3 per <<KLEE-SM3>> (= the <<KLEE-SHA-2>> rules with the GB/T 32905-2016 core)\n')
print(f'{"message":22} {"multi-chunk":12} {"interrupted":12} {"export/import":14} '
      f'{"byte-oriented ref":18} {"hashlib"}')
for label, msg, exp_hex in TV:
    exp = bytes.fromhex(exp_hex)
    ga = kl_sm3(msg, 'multi') == exp
    gb = kl_sm3(msg, 'interrupt') == exp
    gc = kl_sm3(msg, 'export') == exp
    gr = sm3_ref(msg) == exp
    o = oracle(msg)
    orac = 'n/a' if o is None else pf(o == exp)
    ok &= ga and gb and gc and gr and orac != 'FAIL'
    print(f'{label:22} {pf(ga):12} {pf(gb):12} {pf(gc):14} {pf(gr):18} {orac}')

# KLEE model vs the independent byte-oriented reference over many lengths, covering
# every partial-block boundary and multi-block cases
lens = list(range(0, 130)) + [200, 255, 256, 512, 1000]
msgs = {L: bytes((i * 7 + 3) & 0xff for i in range(L)) for L in lens}
mism = [L for L in lens for plan in ('multi', 'interrupt', 'export')
        if kl_sm3(msgs[L], plan) != sm3_ref(msgs[L])]
ok &= not mism
print(f'\nKLEE model vs byte-oriented reference, {3 * len(lens)} runs over messages of '
      f'0..1000 bytes: {pf(not mism) if not mism else f"FAIL {mism[:5]}"}')

print('\nSerialized Content (Content1) length, <<KLEE-hash-functions>> table:')
cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', bytes(8))
got = len(cl.export_content1())
check(f'SM3 {got} bytes (expected {EXPECTED_C1_BYTES}: n + 16 + 16 + 32 + b bits, '
      f'padded to 128)', got == EXPECTED_C1_BYTES)

print('\nState machine and error handling:')
PAD_ABC = b'abc' + caller_pad(3)
DIG_ABC = bytes.fromhex(TV[0][2])

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', b'abc')                     # 3 bytes: admissible as a last transfer
cl.kl_setst(KL_STATE_HASH_OUTPUT)
check('unpadded message (block_base != 0) -> _Invalid_ on entering _Hash_Output_ '
      '(<<KLEE-SHA-2>>)', cl.mdh_state == KL_STATE_INVALID)

cl = fresh()
cl.kl_exec('B', PAD_ABC)
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
check('kl.setst #kl_state_hash_last_block -> _Invalid_ (SM3 follows <<KLEE-SHA-2>>, '
      'which has no such State)', cl.mdh_state == KL_STATE_INVALID)

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
cl.kl_exec('B', PAD_ABC)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
cl.kl_exec('B', bytes(64))
check('Form B kl.exec in _Hash_Output_ -> _Invalid_ '
      '(<<KLEE-MGR-not-allowed-instructions>>)', cl.mdh_state == KL_STATE_INVALID)

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', PAD_ABC)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = cl.kl_exec('C', nbytes=40, prior=b'\xa5' * 40)
check('read with KLLEN = 320 > t: 32 digest bytes, the 8 beyond cleared, -> _Success_ '
      '(<<KLEE-hash-functions>>)',
      out == DIG_ABC + bytes(8) and cl.mdh_state == KL_STATE_SUCCESS)
_, out = cl.kl_exec('C', nbytes=32, prior=b'\xa5' * 32)
check('kl.exec in _Success_ of a hash function -> _Invalid_, output window zeroed '
      '(<<KLEE-SGR-success-failure>>)',
      cl.mdh_state == KL_STATE_INVALID and out == bytes(32))
st, out = cl.kl_exec('C', nbytes=32, prior=b'\xa5' * 32)
check('kl.exec on a CL in _Invalid_: no operation, State kept, output zeroed '
      '(<<KLEE-SGR-usage-cr-error-state>>)',
      st == 'noop' and cl.mdh_state == KL_STATE_INVALID and out == bytes(32))

cl = fresh()
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', (b'abcd' * 16 + caller_pad(64))[:68])   # one block + 4 bytes pending
dirty = cl.block_base != 0 and cl.state != chain_to_state(IV_SM3)
cl.kl_setst(KL_STATE_READY)
reset = (cl.state == chain_to_state(IV_SM3) and cl.block == 0 and cl.block_base == 0
         and cl.cumul_len == 0 and cl.last_blk_len == 0)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', PAD_ABC)
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = cl.kl_exec('C', nbytes=32)
check('_Hash_Absorb_ -> _Ready_ mid-message: state <- IV, block, block_base, '
      'cumul_len <- 0; the next digest is right',
      dirty and reset and out == DIG_ABC)

MP512 = b'abcd' * 16 + caller_pad(64)           # 1024 bits, two blocks
cl = fresh(max_len=1024)
cl.kl_setst(KL_STATE_HASH_ABSORB)
st, _ = cl.kl_exec('B', MP512 + b'\xde\xad\xbe\xef' * 2)
term = st == 'terminated' and cl.cumul_len == 1024
cl.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = cl.kl_exec('C', nbytes=32)
check('system-defined max_len = 1024: the instruction ends at cumul_len = max_len, the '
      '8 excess bytes are ignored (<<KLEE-process-VLI>> step 4.h)',
      term and out == bytes.fromhex(TV[1][2]))
cl = fresh(max_len=1024)
cl.kl_setst(KL_STATE_HASH_ABSORB)
cl.kl_exec('B', MP512)
cl.kl_exec('B', bytes(4))
check('max_len reached: a further kl.exec -> _Invalid_ (<<KLEE-process-VLI>> step 1)',
      cl.mdh_state == KL_STATE_INVALID)

print('\nkl.derive between kl.exec endpoints (<<KLEE-derive-endpoints>>):')
src = fresh()
src.kl_setst(KL_STATE_HASH_ABSORB)
src.kl_exec('B', PAD_ABC)
src.kl_setst(KL_STATE_HASH_OUTPUT)
dst = fresh()
dst.kl_setst(KL_STATE_HASH_ABSORB)
r = kl_derive(dst, src, 32, HART)
moved = (r == 'done' and src.mdh_state == KL_STATE_SUCCESS
         and dst.mdh_state == KL_STATE_HASH_ABSORB and dst.block_base == 256)
dst.kl_exec('B', caller_pad(32))            # the caller pads the 256-bit message
dst.kl_setst(KL_STATE_HASH_OUTPUT)
_, out = dst.kl_exec('C', nbytes=32)
check('SM3 digest -> SM3 _Hash_Absorb_ (32 bytes), caller pads: SM3(SM3("abc")) '
      'matches the byte-oriented reference; source -> _Success_',
      moved and out == sm3_ref(DIG_ABC))

late = fresh()
late.kl_setst(KL_STATE_HASH_ABSORB)
r = kl_derive(late, src, 32, HART)          # src is in _Success_
check('source in _Success_ (digest already emitted): refused, source -> _Invalid_, '
      'destination untouched', r == 'refused' and src.mdh_state == KL_STATE_INVALID
      and late.mdh_state == KL_STATE_HASH_ABSORB and late.block_base == 0)

src = fresh()
src.kl_setst(KL_STATE_HASH_ABSORB)
src.kl_exec('B', PAD_ABC)
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
      and dst.block_base == 0 and out == DIG_ABC)

print('\nNegative controls:')
print('KAT-EXPECT-FAIL: no-bswap')
fired = kl_sm3(b'abc', 'multi', be_words=False) != DIG_ABC
print(f'  no-bswap control, SM3("abc") vs GB/T vector: '
      f'{"FAIL (expected: control is effective)" if fired else "PASS (CONTROL IS DEAD)"}')
ok &= fired
print('KAT-EXPECT-FAIL: klstart-in-bits')
fired = kl_sm3(b'abcd' * 16, 'interrupt', klstart_in_bits=True) != bytes.fromhex(TV[1][2])
print(f'  klstart-in-bits control, SM3(two-block) interrupted: '
      f'{"FAIL (expected: control is effective)" if fired else "PASS (CONTROL IS DEAD)"}')
ok &= fired

print()
print('SPEC-NOTE: <<KLEE-SM3>> refers to "the same padding rule and word mapping as')
print('  SHA-256", but the paragraph of <<KLEE-SHA-2>> that stated them ("Endianness")')
print('  is commented out in the current text, so neither the message-word mapping nor')
print('  the layout of `state` is written anywhere in the Machine descriptions.  The')
print('  model uses word j = int(bswap(block[(j+1)w-1 : jw])) and')
print('  state[(i+1)w-1 : iw] = bswap(bin(V_i, w)).')
print('INFO: Serialized Content: the table says cumul_len is "absent" outside HMAC, the')
print('  NOTE under it that an unused field "is replaced by a corresponding padding')
print('  block"; the model follows the table (block at bit n + 64).  Same total length.')
print('  block_base is serialized as bin(block_base, 16) in bits, the process_VLI unit.')
print('INFO: _Hash_Absorb_ -> _Hash_Output_ is modeled as a Form A kl.setst; the text')
print('  names no auxiliary parameter for it.')
print('INFO: kl.derive is exercised with length = t/8 only; for a shorter length the')
print('  source side has two readings ("the unused part of the last block is discarded"')
print('  vs "advances as the kl.exec operations ... would").  A refused transfer')
print('  invalidates only the offending CL (Checks, item 1), not "both CLs".')
print('INFO: <<KLEE-HMAC>> names SM3 as an underlying hash function, but')
print('  <<KLEE-exec-encodings>> gives SM3 only Type 9 Mode 0, with no HMAC pair, so no')
print('  HMAC-SM3 Machine can be encoded and none is exercised here.')

print(f'\nruntime: {time.time() - T0:.2f} s')
print(f'KAT-RESULT: {"PASS" if ok else "FAIL"}')
sys.exit(0 if ok else 1)
