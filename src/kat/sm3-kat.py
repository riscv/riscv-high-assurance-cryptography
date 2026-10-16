#!/usr/bin/env python3
"""SM3 KAT for KLE: <<KLE-SM3>>, i.e. the <<KLE-SHA-2>> Machine with the GB/T 32905-2016 core.
The core is from scratch; hashlib 'sm3', where present, is only a labeled reference oracle."""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, bswap, bin_, ERROR_STATES, inert,
                    KL_STATE_UNCONFIGURED, KL_STATE_READY, KL_STATE_HASH_ABSORB,
                    KL_STATE_HASH_LAST_BLOCK, KL_STATE_HASH_OUTPUT, KL_STATE_SUCCESS,
                    KL_STATE_FAILURE, KL_STATE_INVALID, section, check, control, info,
                    spec_note, raises, done)

# ---------------------------------------------------------------- GB/T 32905-2016

M32 = 0xffffffff
IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
rotl = lambda x, r: ((x << (r % 32)) | (x >> (32 - r % 32))) & M32
P0 = lambda x: x ^ rotl(x, 9) ^ rotl(x, 17)
P1 = lambda x: x ^ rotl(x, 15) ^ rotl(x, 23)

def compress(V, W):
    """CF, sect. 5.3.3."""
    W = list(W)
    for j in range(16, 68):
        W.append(P1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15)) ^ rotl(W[j - 13], 7) ^ W[j - 6])
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        SS1 = rotl((rotl(A, 12) + E + rotl(0x79cc4519 if j < 16 else 0x7a879d8a, j)) & M32, 7)
        FF = (A ^ B ^ C) if j < 16 else ((A & B) | (A & C) | (B & C))
        GG = (E ^ F ^ G) if j < 16 else ((E & F) | (~E & G & M32))
        TT1 = (FF + D + (SS1 ^ rotl(A, 12)) + (W[j] ^ W[j + 4])) & M32
        TT2 = (GG + H + SS1 + W[j]) & M32
        A, B, C, D, E, F, G, H = TT1, A, rotl(B, 9), C, P0(TT2), E, rotl(F, 19), G
    return [v ^ x for v, x in zip(V, (A, B, C, D, E, F, G, H))]

def pad(nbytes):
    """The caller's padding, sect. 5.2 (as FIPS 180-4 sect. 5.1)."""
    return b'\x80' + bytes(-(nbytes + 9) % 64) + (8 * nbytes).to_bytes(8, 'big')

def sm3_ref(msg):
    """Independent byte-oriented big-endian SM3 (no KLE model)."""
    m, V = msg + pad(len(msg)), IV
    for i in range(0, len(m), 64):
        V = compress(V, [int.from_bytes(m[j:j + 4], 'big') for j in range(i, i + 64, 4)])
    return b''.join(v.to_bytes(4, 'big') for v in V)

# ---------------------------------------------------------------- KLE model

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

to_state = lambda V: sum(bswap(bin_(h, 32), 4) << (32 * i) for i, h in enumerate(V))
IV_STATE = to_state(IV)

class Sm3:
    w, b, n, t = 32, 512, 256, 256  # <<KLE-SM3>>

    def __init__(s, bswap_words=True, klstart_bits=False):
        s.bswap_words, s.klstart_bits = bswap_words, klstart_bits
        s.reset(KL_STATE_UNCONFIGURED)

    def reset(s, st=KL_STATE_INVALID):  # GR30 for an Error State
        s.st, s.block, s.block_base = st, 0, 0
        s.state = IV_STATE if st == KL_STATE_READY else 0
        return s

    def provision(s):  # PI = MDH only
        return s.reset(KL_STATE_READY)

    def process_block(s):
        wd = lambda v, j: sl(v, 32 * j + 31, 32 * j)
        W = [bswap(wd(s.block, j), 4) if s.bswap_words else wd(s.block, j) for j in range(16)]
        s.state = to_state(compress([bswap(wd(s.state, i), 4) for i in range(8)], W))

    def export(s):  # <<KLE-hash-functions-MACs-XOFs>> Serialized Content, cumul_len absent
        return pack((s.state, s.n), (0, 16), (s.block_base, 16), (0, 16), (0, 16), (s.block, s.b))

    @classmethod
    def load(cls, st, c1):
        cl, v = cls(), b2v(c1)
        cl.st, cl.state, cl.block_base, cl.block = st, sl(v, cl.n - 1, 0), sl(v, cl.n + 31, cl.n + 16), v >> (cl.n + 64)
        return cl

    def setst(s, immed, form='A'):  # <<KLE-instruction-setst>>
        if immed == KL_STATE_UNCONFIGURED or immed in ERROR_STATES:  # in any State
            if s.st != KL_STATE_UNCONFIGURED:
                s.reset(KL_STATE_INVALID if immed > 53 else immed)
        elif inert(s.st):
            pass  # GR19.a
        elif immed == KL_STATE_READY:
            s.reset(KL_STATE_READY)
        # Form A: max_len = 0 is set by the Machine; no same-State _Hash_Absorb_ (<<KLE-process-VLI>>)
        # or _Hash_Output_ (GR23);
        # stand-alone hashing enters _Hash_Output_ with whole blocks only
        elif form != 'A' or (s.st, immed) not in ((KL_STATE_READY, KL_STATE_HASH_ABSORB),
                                                  (KL_STATE_HASH_ABSORB, KL_STATE_HASH_OUTPUT)) \
                or (immed == KL_STATE_HASH_OUTPUT and s.block_base):
            s.reset()
        else:
            s.st = immed

    def exec(s, form, data=b'', nbytes=0, halt=False, resume=False, prior=None):
        """kl.exec Form B (data) or C (nbytes); returns (status, output)."""
        if inert(s.st):
            return 'noop', bytes(nbytes)  # GR19.a, GR34
        if s.st == KL_STATE_HASH_OUTPUT and form == 'C':
            p, prior = HART.klstart, prior or bytes(nbytes)
            if p >= nbytes:
                HART.klstart = 0
                return 'empty', prior  # empty window: only klstart = 0 (<<KLE-GR-transfer-window-checks>>)
            if p:  # not an interruption point: a hash reaches _Success_ before any
                s.reset()
                HART.klstart = 0
                return 'invalid', prior[:p] + bytes(nbytes - p)  # GR34
            return 'retired', s.output(nbytes, prior)
        r = s.process_vli(b2v(data), 8 * len(data), halt, resume) if (
            s.st == KL_STATE_HASH_ABSORB and form == 'B') else 'invalid'  # GR24, GR28, MR1
        if r == 'invalid':
            s.reset()
        return r, bytes(nbytes)

    def process_vli(s, INPUT, KLLEN, halt, resume):
        """PROCESS_VLI(max_len=0, block, b, state, n, input_base, block_base, 0, None, P, None, assign)."""
        ib = 8 * HART.klstart if resume else 0
        while ib < KLLEN:
            amount = min(KLLEN - ib, s.b - s.block_base)
            s.block = setsl(s.block, s.block_base + amount - 1, s.block_base, sl(INPUT, ib + amount - 1, ib))
            ib, s.block_base = ib + amount, s.block_base + amount
            if s.block_base == s.b:
                s.process_block()
                s.block_base = 0
            if halt and ib < KLLEN:  # 4.i
                HART.klstart = ib if s.klstart_bits else ib // 8
                return 'interrupted'
        HART.klstart = 0
        return 'retired'

    def output(s, nbytes, prior):  # _Hash_Output_ loop reading `state`
        OUT, KLLEN, ob = b2v(prior or bytes(nbytes)), 8 * nbytes, 0
        while ob < KLLEN:
            amount = min(KLLEN - ob, s.t - s.block_base)
            OUT = setsl(OUT, ob + amount - 1, ob, sl(s.state, s.block_base + amount - 1, s.block_base))
            ob, s.block_base = ob + amount, s.block_base + amount
            if s.block_base == s.t:
                OUT, s.st = sl(OUT, ob - 1, 0), KL_STATE_SUCCESS
                break
        HART.klstart = 0
        return v2b(OUT, nbytes)

class KeyDest:
    """A symmetric `key` of n bytes, a destination in _Ready_ (<<KLE-derive-endpoints>>); only the key is modelled."""
    def __init__(s, n): s.st, s.n, s.key = KL_STATE_READY, n, None
    def reset(s): s.st, s.key = KL_STATE_INVALID, None

class Source:
    """A source endpoint, only its bytes modelled: a shared secret field (an ECC shared secret in _Output_ or the
    ML-KEM `sharedkey`, GR54) or, with secret=False, the `hash` of a CMAC in _Hash_Output_ (GR55).  A hash in
    _Hash_Output_ is not a source (<<KLE-derive-endpoints>>)."""
    def __init__(s, data, secret=True): s.st, s.data, s.secret = KL_STATE_HASH_OUTPUT, data, secret
    def reset(s): s.st = KL_STATE_INVALID

GRAN = 4  # bytes: the SM3 input granularity, 32 bits

def kl_derive(dst, src, length):
    """A Source -> the _Hash_Absorb_ kl.exec input (GR54: a shared secret only) or a KeyDest (GR54, GR55);
    uninterruptible (GR71)."""
    if src.st in ERROR_STATES or dst.st in ERROR_STATES:
        return 'noop'  # Gate Order Rule
    key = isinstance(dst, KeyDest)
    bad = [c for c, ok in ((src, isinstance(src, Source)),
                           (dst, dst.st == (KL_STATE_READY if key else KL_STATE_HASH_ABSORB))) if not ok]
    for c in bad:
        c.reset()  # GR50 items 1-2
    pos, HART.klstart = HART.klstart, 0  # uninterruptible (GR71): no resumption
    if bad:
        return 'refused'
    if not (key or src.secret):
        src.reset()  # GR50 item 3: both
        dst.reset()
        return 'refused'
    n = len(src.data)
    if pos or (min(length, n) < dst.n if key else not n <= length <= -(-n // GRAN) * GRAN):
        dst.reset()  # GR50 item 5
        return 'refused'
    if key:
        dst.key = src.data[:dst.n]
    else:
        dst.exec('B', src.data.ljust(length, b'\0'))  # GR49: zero beyond the field, which does not advance
    return 'done'

# ---------------------------------------------------------------- vectors and drivers

# GB/T 32905-2016 appendix A
TV = [('"abc"', b'abc', '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
      ('"abcd" x 16', b'abcd' * 16, 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')]
DIG_ABC, DIG_512 = bytes.fromhex(TV[0][2]), bytes.fromhex(TV[1][2])

A = lambda c: c.setst(KL_STATE_HASH_ABSORB)
O = lambda c: c.setst(KL_STATE_HASH_OUTPUT)
R = lambda c: c.setst(KL_STATE_READY)
B = lambda d: lambda c: c.exec('B', d)
C = lambda n: lambda c: c.exec('C', nbytes=n, prior=b'\xa5' * n)

def run(c, *ops):
    """Apply ops to locker c; return the last result."""
    return [op(c) for op in ops][-1]

def digest(msg, plan='multi', **kw):
    """Plans: multi (3 transfers, 2 reads), interrupt (halt at each 4.i, resume), export (mid-block)."""
    cl = Sm3(**kw).provision()
    mp = msg + pad(len(msg))
    A(cl)
    if plan == 'multi':
        c1 = 4 if len(mp) > 12 else len(mp)
        c2 = c1 + max(4, (len(mp) - c1) // 8 * 4)
        run(cl, *[B(p) for p in (mp[:c1], mp[c1:c2], mp[c2:]) if p])
    elif plan == 'interrupt':
        r = run(cl, B(mp[:4]), lambda c: c.exec('B', mp[4:], halt=True))[0]
        while r == 'interrupted':
            r = cl.exec('B', mp[4:], halt=True, resume=True)[0]
    else:
        B(mp[:-28])(cl)
        assert cl.block_base
        cl = Sm3.load(cl.st, cl.export())
        B(mp[-28:])(cl)
    O(cl)
    out = run(cl, C(24))[1] + run(cl, C(8))[1] if plan == 'multi' else run(cl, C(32))[1]
    return out if cl.st == KL_STATE_SUCCESS else None

def absorbing(data=b'', **kw):
    cl = Sm3(**kw).provision()
    run(cl, A, *([B(data)] if data else []))
    return cl

def outputting(msg=b'abc'):
    cl = absorbing(msg + pad(len(msg)))
    O(cl)
    return cl

# ---------------------------------------------------------------- checks

section('GB/T 32905-2016 vectors')
for label, msg, h in TV:
    want = bytes.fromhex(h)
    for plan in ('multi', 'interrupt', 'export'):
        check(f'SM3 {label} {plan}', None, digest(msg, plan), want)
    check(f'byte-oriented reference {label}', None, sm3_ref(msg), want)
    if 'sm3' in hashlib.algorithms_available:
        check(f'[oracle] hashlib sm3 {label}', None, hashlib.new('sm3', msg).digest(), want)
LENS = list(range(130)) + [200, 255, 256, 512, 1000]
msgs = {L: bytes((7 * i + 3) & 0xff for i in range(L)) for L in LENS}
check(f'KLE model = byte-oriented reference, 3 plans x {len(LENS)} lengths (0..1000 B)', None,
      [L for L in LENS for plan in ('multi', 'interrupt', 'export') if digest(msgs[L], plan) != sm3_ref(msgs[L])],
      [])

section('Serialized Content')
check('Content1 = n+64+b bits, padded to 128', None, len(absorbing(bytes(8)).export()), 112)

section('State machine')
PAD_ABC = b'abc' + pad(3)
for label, ops in [
        ('entering _Hash_Output_ with block_base != 0', (A, B(b'abc'), O)),
        ('kl.exec in _Ready_ (GR24)', (B(PAD_ABC),)),
        ('Form B kl.setst to _Hash_Absorb_', (lambda c: c.setst(KL_STATE_HASH_ABSORB, 'B'),)),
        ('same-State kl.setst to _Hash_Absorb_', (A, A)),
        ('same-State kl.setst to _Hash_Output_ (GR23)', (A, B(PAD_ABC), O, O)),
        ('kl.setst #kl_state_hash_last_block', (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B'))),
        ('_Ready_ -> _Hash_Output_', (O,)),
        ('Form C kl.exec in _Hash_Absorb_ (MR1), output zeroed', (A, C(16))),
        ('Form B kl.exec in _Hash_Output_ (MR1)', (A, B(PAD_ABC), O, B(bytes(64)))),
        ('kl.exec in _Success_ (GR28), output zeroed', (A, B(PAD_ABC), O, C(32), C(32)))]:
    cl = Sm3().provision()
    r = run(cl, *ops)
    check(f'_Invalid_: {label}', cl.st == KL_STATE_INVALID and not any(r[1] if r else b''))
check('kl.exec in _Invalid_: no operation, output zeroed (GR19.a, GR34)',
      C(32)(cl) == ('noop', bytes(32)) and cl.st == KL_STATE_INVALID)
cl, res = outputting(), []
for ks in (32, 40, 4):
    HART.klstart = ks
    res.append((C(32)(cl), cl.st, HART.klstart))
check('Form C, klstart >= KLLEN/8 (32, 40): empty window, only klstart = 0; klstart = 4 (no interruption point): '
      '_Invalid_, [4, 32) zeroed', None, res, [(('empty', b'\xa5' * 32), KL_STATE_HASH_OUTPUT, 0)] * 2
      + [(('invalid', b'\xa5' * 4 + bytes(28)), KL_STATE_INVALID, 0)])
cl = absorbing()
check('kl.setst #kl_state_success -> Invalid (GR26, MR1)',
      (raises(cl.setst, KL_STATE_SUCCESS), cl.st) == (False, KL_STATE_INVALID))
cl.setst(KL_STATE_UNCONFIGURED)
check('kl.clear; a later kl.exec or kl.setst performs no operation, output zeroed (GR19.a, GR34)',
      (cl.exec('C', nbytes=8), cl.setst(KL_STATE_READY), cl.st, cl.state)
      == (('noop', bytes(8)), None, KL_STATE_UNCONFIGURED, 0))
check('kl.setst #kl_state_failure on an Unconfigured locker: no operation (GR26, GR19.a)',
      (raises(cl.setst, KL_STATE_FAILURE), cl.st) == (False, KL_STATE_UNCONFIGURED))
cl = outputting()
check('KLLEN > t: digest, excess bits cleared, _Success_', None, (C(40)(cl)[1], cl.st),
      (DIG_ABC + bytes(8), KL_STATE_SUCCESS))
cl = absorbing((b'abcd' * 16 + pad(64))[:68])
dirty = cl.block_base and cl.state != IV_STATE
R(cl)
reset = (cl.state, cl.block, cl.block_base) == (IV_STATE, 0, 0)
check('_Hash_Absorb_ -> _Ready_ mid-message: state <- IV, block, block_base <- 0',
      dirty and reset and run(cl, A, B(PAD_ABC), O, C(32))[1] == DIG_ABC)

section('kl.derive')
SEC = bytes(range(0x40, 0x60))  # a 32-byte shared secret
src, dst, dst2 = Source(SEC), absorbing(), absorbing()
r = (kl_derive(dst, src, 32), dst.block_base, kl_derive(dst2, src, 32))
check('shared secret (32 B) -> SM3 absorb: SM3(secret) = reference; the field does not advance: derived twice', None,
      (r, run(dst, B(pad(32)), O, C(32))[1], run(dst2, B(pad(32)), O, C(32))[1]),
      (('done', 256, 'done'), sm3_ref(SEC), sm3_ref(SEC)))
src, dst = Source(SEC[:30]), absorbing()
check('shared secret (30 B), length 32 (30 rounded up to 4 B) -> SM3 absorb: zero beyond the secret',
      kl_derive(dst, src, 32) == 'done' and run(dst, B(pad(32)), O, C(32))[1] == sm3_ref(SEC[:30] + bytes(2)))
src, dst = outputting(), absorbing()
check('SM3 digest in _Hash_Output_ as a source (GR50 item 1): refused, source _Invalid_, destination untouched',
      kl_derive(dst, src, 32) == 'refused' and src.st == KL_STATE_INVALID
      and (dst.st, dst.block_base) == (KL_STATE_HASH_ABSORB, 0))
src, dst = Source(bytes(range(16)), secret=False), absorbing()
check('a CMAC (16 B) -> SM3 absorb: pair not admitted (GR50 item 3), both _Invalid_',
      kl_derive(dst, src, 16) == 'refused' and (src.st, dst.st) == (KL_STATE_INVALID, KL_STATE_INVALID))
src, dst = Source(SEC), Sm3().provision()
check('destination in _Ready_ (GR50 item 2): refused, destination _Invalid_, source untouched',
      kl_derive(dst, src, 32) == 'refused' and dst.st == KL_STATE_INVALID and src.st == KL_STATE_HASH_OUTPUT)
res = []
for s, length in ((SEC, 0), (SEC, 31), (SEC, 36), (SEC[:30], 33)):
    dst = absorbing()
    res.append((kl_derive(dst, Source(s), length), dst.st))
check('shared secret into SM3 absorb: 32 B with length 0, 31 or 36, 30 B with length 33 (GR50 item 5: from the '
      'secret length to it rounded up to 4 B): destination _Invalid_', None, res, [('refused', KL_STATE_INVALID)] * 4)

src, dst, h, dh = Source(SEC), KeyDest(16), outputting(), KeyDest(16)
check('shared secret -> an SM4 `key` in _Ready_, length 32: its first 16 bytes; SM3("abc") -> a key (GR50 item 1): '
      'source _Invalid_, key untouched', None,
      (kl_derive(dst, src, 32), dst.key, kl_derive(dh, h, 32), h.st, dh.st),
      ('done', SEC[:16], 'refused', KL_STATE_INVALID, KL_STATE_READY))

section('Negative controls')
control('message words without bswap', digest(b'abc', bswap_words=False) != DIG_ABC)
control('klstart written in bits', digest(b'abcd' * 16, 'interrupt', klstart_bits=True) != DIG_512)

done()
