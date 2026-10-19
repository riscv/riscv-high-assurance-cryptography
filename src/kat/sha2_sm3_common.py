"""The Merkle-Damgard hash Machine shared by the SHA-2 and SM3 KATs: <<KLE-SHA-2>>, <<KLE-SM3>> over
<<KLE-hash-functions-MACs-XOFs>> and <<KLE-process-VLI>>, with kl.derive (<<KLE-derive-endpoints>>).
The compression function, word size, IV, block and digest sizes come from the caller; the references stay in
the KATs."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, bswap, bin_, ERROR_STATES, inert,
                    KL_STATE_UNCONFIGURED, KL_STATE_READY, KL_STATE_HASH_ABSORB,
                    KL_STATE_HASH_LAST_BLOCK, KL_STATE_HASH_OUTPUT, KL_STATE_SUCCESS,
                    KL_STATE_INVALID, KL_STATE_UNSUPPORTED, md_pad, HashPort, IllegalInstruction)

class Hart:
    klstart = 0  # bytes, <<KLE-CSR-klstart>>

HART = Hart()

def setsl(v, hi, lo, x):
    m = ((1 << (hi - lo + 1)) - 1) << lo
    return (v & ~m) | ((x << lo) & m)

def pack(*fields):
    """Serialized fields in table order from bit 0, zero-padded to 128 bits."""
    v = pos = 0
    for x, w in fields:
        v, pos = v | bin_(x, w) << pos, pos + w
    return v2b(v, -(-pos // 128) * 16)

class MdHash:
    """The Machine with parameters (w, b, n, t), 8 words of w bits in `state`, the initial value iv, and
    compress(H, W) -> H on big-endian words."""

    def __init__(s, name, w, b, n, t, iv, compress, bswap_words=True, klstart_bits=False):
        s.name, s.w, s.b, s.n, s.t, s.iv, s.compress = name, w, b, n, t, iv, compress
        s.bswap_words, s.klstart_bits = bswap_words, klstart_bits
        s.reset(KL_STATE_UNCONFIGURED)

    def to_state(s, H):
        """Words H into `state`: word i in bits [w*i, w*i + w-1], byte-swapped."""
        return sum(bswap(bin_(h, s.w), s.w // 8) << (i * s.w) for i, h in enumerate(H))

    @property
    def iv_state(s):
        return s.to_state(s.iv)

    def reset(s, st=KL_STATE_INVALID):  # GR29 for an Error State
        s.st, s.state, s.block, s.block_base = st, 0, 0, 0
        s.cumul_len = s.last_block_len = s.out_len = 0
        if st == KL_STATE_READY:
            s.state = s.iv_state
        return s

    def provision(s, policy=0):  # PI = MDH only
        if policy:  # unsupported Metadata (<<KLE-hash-functions-MACs-XOFs>>, MDH: MachinePolicy)
            return s.reset(KL_STATE_UNSUPPORTED)
        return s.reset(KL_STATE_READY)

    def restrictl(s, clear):  # kl.restrictl of the _MachinePolicy_ that the Machine does not use
        if clear and not inert(s.st):  # a zero field changes nothing (<<KLE-instruction-restrict>>)
            s.reset()
        return s

    def process_block(s):
        wd = lambda v, j: sl(v, (j + 1) * s.w - 1, j * s.w)
        H = [bswap(wd(s.state, i), s.w // 8) for i in range(8)]
        W = [bswap(wd(s.block, j), s.w // 8) if s.bswap_words else wd(s.block, j) for j in range(16)]
        s.state = s.to_state(s.compress(H, W))

    def finalize(s):  # <<KLE-SHA-2>>: the rest of the padding, not counted in cumul_len
        p = md_pad(s.cumul_len, s.w)
        s.process_vli(b2v(p), 8 * len(p), False, False, count=False)

    def export(s):  # Serialized Content: iii last_block_len, iv block_base, v-vi out_len, vii cumul_len
        return pack((s.state, s.n), (s.last_block_len, 16), (s.block_base, 16), (s.out_len, 32), (s.cumul_len, 64),
                    (s.block, s.b))

    def restore(s, st, c1):
        """Import Content1 c1 in State st into this locker."""
        v, n = b2v(c1), s.n
        s.st, s.state, s.last_block_len = st, sl(v, n - 1, 0), sl(v, n + 15, n)
        s.block_base, s.out_len, s.cumul_len = sl(v, n + 31, n + 16), sl(v, n + 63, n + 32), sl(v, n + 127, n + 64)
        s.block = v >> (n + 128)
        return s

    def setst(s, immed, form='A', xs=None):  # <<KLE-instruction-setst>>
        if immed in (54, 55):
            raise IllegalInstruction('reserved #immed7')  # GR18
        if immed == KL_STATE_UNCONFIGURED or immed in ERROR_STATES:  # in any State
            if s.st != KL_STATE_UNCONFIGURED:
                s.reset(immed)
        elif inert(s.st):
            pass  # GR26
        elif immed == KL_STATE_READY and form == 'A':  # GR16: Form A
            s.reset(KL_STATE_READY)
        elif (s.st, immed, form) == (KL_STATE_READY, KL_STATE_HASH_ABSORB, 'A'):
            s.st, s.last_block_len = immed, s.b  # Form A; last_block_len <- b (<<KLE-hash-functions-MACs-XOFs>>)
        elif (s.st, immed) == (KL_STATE_HASH_ABSORB, KL_STATE_HASH_LAST_BLOCK) and (
                form == 'A' or form == 'B' and xs is not None and 0 <= xs <= s.b):
            s.st = immed  # any bit length, MSB-first (MR16, second bullet); Form A keeps b
            if form == 'B':
                s.last_block_len = xs
        elif immed == KL_STATE_HASH_OUTPUT and form in 'AB' and (
                s.st == KL_STATE_HASH_ABSORB or s.st == KL_STATE_HASH_LAST_BLOCK and s.last_block_len == 0):
            x = xs if form == 'B' else 0
            if x and (x % 8 or x > s.t):
                return s.reset()  # the bound: a multiple of 8, at most d = t
            s.finalize()
            s.st, s.block_base, s.last_block_len, s.out_len = immed, 0, 0, x or s.t
        else:
            s.reset()  # MR1; no same-State kl.setst (GR17); _Ready_ -> _Hash_Output_

    def exec(s, form, data=b'', nbytes=0, halt=False, resume=False, prior=None):
        """kl.exec Form B (data) or C (nbytes); returns (status, output)."""
        if inert(s.st):
            return 'noop', bytes(nbytes)  # GR26, GR28
        if s.st == KL_STATE_HASH_OUTPUT and form == 'C':
            p, prior = HART.klstart, prior or bytes(nbytes)
            if p >= nbytes:
                HART.klstart = 0
                return 'empty', prior  # empty window: only klstart = 0 (<<KLE-GR-transfer-window-checks>>)
            if p and s.block_base:  # not an interruption point (<<KLE-hash-functions-MACs-XOFs>>)
                s.reset()
                HART.klstart = 0
                return 'invalid', prior[:p] + bytes(nbytes - p)  # GR28
            return 'retired', s.output(nbytes, prior)
        if s.st == KL_STATE_HASH_LAST_BLOCK and form == 'B':
            L, p = s.last_block_len, HART.klstart if resume else 0
            if 8 * len(data) < L:  # MR2 / GR44 item 1: length first
                s.reset()
                HART.klstart = 0
                return 'invalid', bytes(nbytes)
            if p >= len(data):
                HART.klstart = 0
                return 'empty', bytes(nbytes)  # GR44 item 2
            if p or not L:  # interruption point 0 only (MR3, GR44 item 3); MR10
                s.reset()
                HART.klstart = 0
                return 'invalid', bytes(nbytes)
            nb, k = -(-L // 8), L % 8
            piece = bytearray(data[:nb])
            if k:  # MSB-first: the last byte carries k bits, then the bit 1 that starts the padding
                piece[-1] = (piece[-1] & (0xFF << (8 - k)) & 0xFF) | (1 << (7 - k))
            s.process_vli(b2v(bytes(piece)), 8 * nb, False, False, count=False)
            s.cumul_len, s.last_block_len = s.cumul_len + L, 0
            HART.klstart = 0
            return 'retired', bytes(nbytes)
        if resume and s.st == KL_STATE_HASH_ABSORB and form == 'B' and HART.klstart >= len(data):
            HART.klstart = 0
            return 'empty', bytes(nbytes)  # GR44 item 2, before item 3
        if resume and HART.klstart and s.block_base:
            r, HART.klstart = 'invalid', 0  # not an interruption point (<<KLE-process-VLI>>)
        else:
            r = s.process_vli(b2v(data), 8 * len(data), halt, resume) if (
                s.st == KL_STATE_HASH_ABSORB and form == 'B') else 'invalid'  # GR17 item 1, MR1
        if r == 'invalid':
            s.reset()
        return r, bytes(nbytes)

    def process_vli(s, INPUT, KLLEN, halt, resume, count=True):
        """PROCESS_VLI(0, block, b, state, n, input_base, block_base, 0, cumul_len, P, None, assign, 8)."""
        ib = 8 * HART.klstart if resume else 0
        while ib < KLLEN:
            amount = min(KLLEN - ib, s.b - s.block_base)
            s.block = setsl(s.block, s.block_base + amount - 1, s.block_base, sl(INPUT, ib + amount - 1, ib))
            ib, s.block_base = ib + amount, s.block_base + amount
            if count:
                s.cumul_len += amount
            if s.block_base == s.b:
                s.process_block()
                s.block_base = 0
            if halt and ib < KLLEN:  # 3.i: granularity 8 bits
                HART.klstart = ib if s.klstart_bits else ib // 8
                return 'interrupted'
        HART.klstart = 0
        return 'retired'

    def output(s, nbytes, prior):  # _Hash_Output_ loop reading `state`, bounded by out_len
        OUT, KLLEN, ob = b2v(prior or bytes(nbytes)), 8 * nbytes, 8 * HART.klstart
        while ob < KLLEN:
            amount = min(KLLEN - ob, s.t - s.block_base, s.out_len)
            OUT = setsl(OUT, ob + amount - 1, ob, sl(s.state, s.block_base + amount - 1, s.block_base))
            ob, s.block_base, s.out_len = ob + amount, s.block_base + amount, s.out_len - amount
            if s.out_len == 0:
                OUT, s.st = sl(OUT, ob - 1, 0), KL_STATE_SUCCESS
                break
        HART.klstart = 0
        return v2b(OUT, nbytes)

class MdPort(HashPort):
    """<<Zkl-software.adoc#KLE-pseudocode-hash>> on an MdHash locker cl; a subclass provides imported."""
    msb = True
    def __init__(p, cl): p.cl, p.b = cl, cl.b
    st = property(lambda p: p.cl.st)
    klstart = property(lambda p: HART.klstart)
    def setst(p, immed, form='A', xs=None): p.cl.setst(immed, form, xs)
    def exec_in(p, d, halt_at=None):
        return p.cl.exec('B', d, halt=halt_at is not None, resume=HART.klstart != 0)[0]
    def exec_out(p, n, halt_at=None, prior=None): return p.cl.exec('C', nbytes=n, prior=prior)
    def export(p): return p.cl.st, p.cl.export()

class KeyDest:
    """A symmetric `key` of n bytes, a destination in _Ready_ (<<KLE-derive-endpoints>>); only the key is modelled."""
    def __init__(s, n): s.st, s.n, s.key = KL_STATE_READY, n, None
    def reset(s): s.st, s.key = KL_STATE_INVALID, None

class Source:
    """A source endpoint, only its bytes modelled: a shared secret field (an ECC shared secret in _Output_ or the
    ML-KEM `sharedkey`, GR34) or, with secret=False, the `hash` of a CMAC in _Hash_Output_ (GR35).  A hash in
    _Hash_Output_ is not a source (<<KLE-derive-endpoints>>)."""
    def __init__(s, data, secret=True): s.st, s.data, s.secret = KL_STATE_HASH_OUTPUT, data, secret
    def reset(s): s.st = KL_STATE_INVALID

def kl_derive(dst, src, length):
    """A Source -> the _Hash_Absorb_ kl.exec input (GR34: a shared secret only) or a KeyDest (GR34, GR35);
    uninterruptible (GR38)."""
    if src.st in ERROR_STATES or dst.st in ERROR_STATES:
        return 'noop'  # GR26: an inert endpoint
    key = isinstance(dst, KeyDest)
    bad = [c for c, ok in ((src, isinstance(src, Source)),
                           (dst, dst.st == (KL_STATE_READY if key else KL_STATE_HASH_ABSORB))) if not ok]
    for c in bad:
        c.reset()  # GR32 items 1-2
    pos, HART.klstart = HART.klstart, 0  # uninterruptible (GR38): no resumption
    if bad:
        return 'refused'
    if not (key or src.secret):
        src.reset()  # GR32 item 3: both
        dst.reset()
        return 'refused'
    n = len(src.data)
    if pos or (min(length, n) < dst.n if key else length != n):  # GR32 item 5: the whole secret, exactly
        dst.reset()
        return 'refused'
    if key:
        dst.key = src.data[:dst.n]
    else:
        dst.exec('B', src.data)  # GR34: the whole secret (GR32 item 5)
    return 'done'

# ---------------------------------------------------------------- drivers

A = lambda c: c.setst(KL_STATE_HASH_ABSORB)
O = lambda c: c.setst(KL_STATE_HASH_OUTPUT)
R = lambda c: c.setst(KL_STATE_READY)
B = lambda d: lambda c: c.exec('B', d)
C = lambda n: lambda c: c.exec('C', nbytes=n, prior=b'\xa5' * n)

def run(c, *ops):
    """Apply ops to locker c; return the last result."""
    return [op(c) for op in ops][-1]
