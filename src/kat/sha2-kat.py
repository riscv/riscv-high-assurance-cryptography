#!/usr/bin/env python3
"""SHA-2 family KAT for KLE: <<KLE-SHA-2>> over <<KLE-hash-functions-MACs-XOFs>>, <<KLE-process-VLI>>.
FIPS 180-4 cores from scratch; hashlib is only a labeled reference oracle."""
import hashlib, math, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, bswap, bin_, ERROR_STATES, inert,
                    KL_STATE_UNCONFIGURED, KL_STATE_READY, KL_STATE_HASH_ABSORB,
                    KL_STATE_HASH_LAST_BLOCK, KL_STATE_HASH_OUTPUT, KL_STATE_SUCCESS,
                    KL_STATE_FAILURE, KL_STATE_INVALID, section, check, control, info,
                    spec_note, raises, done)

# ---------------------------------------------------------------- FIPS 180-4

def icbrt(n):
    x = 1 << -(-n.bit_length() // 3)
    while (y := (2 * x + n // (x * x)) // 3) < x:
        x = y
    return x

P80 = [p for p in range(2, 410) if all(p % d for d in range(2, p))]
frac = lambda x, w: x & ((1 << w) - 1)
K = {32: [frac(icbrt(p << 96), 32) for p in P80[:64]], 64: [frac(icbrt(p << 192), 64) for p in P80]}
IV = {'SHA-224': [frac(math.isqrt(p << 128), 32) for p in P80[8:16]],
      'SHA-256': [frac(math.isqrt(p << 64), 32) for p in P80[:8]],
      'SHA-384': [frac(math.isqrt(p << 128), 64) for p in P80[8:16]],
      'SHA-512': [frac(math.isqrt(p << 128), 64) for p in P80[:8]]}

def compress(H, W, w):
    """FIPS 180-4 sect. 6.2.2 / 6.4.2."""
    s0, s1, S0, S1 = (((7, 18, 3), (17, 19, 10), (2, 13, 22), (6, 11, 25)) if w == 32 else
                      ((1, 8, 7), (19, 61, 6), (28, 34, 39), (14, 18, 41)))
    M = (1 << w) - 1
    rotr = lambda x, r: ((x >> r) | (x << (w - r))) & M
    sig = lambda x, s: rotr(x, s[0]) ^ rotr(x, s[1]) ^ (x >> s[2])
    Sig = lambda x, s: rotr(x, s[0]) ^ rotr(x, s[1]) ^ rotr(x, s[2])
    W = list(W)
    for t in range(16, len(K[w])):
        W.append((W[t - 16] + sig(W[t - 15], s0) + W[t - 7] + sig(W[t - 2], s1)) & M)
    a, b, c, d, e, f, g, h = H
    for t in range(len(K[w])):
        T1 = (h + Sig(e, S1) + ((e & f) ^ (~e & g & M)) + K[w][t] + W[t]) & M
        T2 = (Sig(a, S0) + ((a & b) ^ (a & c) ^ (b & c))) & M
        a, b, c, d, e, f, g, h = (T1 + T2) & M, a, b, c, (d + T1) & M, e, f, g
    return [(x + y) & M for x, y in zip(H, (a, b, c, d, e, f, g, h))]

def fips_pad(nbytes, w):
    """The caller's padding, FIPS 180-4 sect. 5.1."""
    return b'\x80' + bytes(-(nbytes + 1 + w // 4) % (2 * w)) + (8 * nbytes).to_bytes(w // 4, 'big')

for t in (224, 256):  # sect. 5.3.6
    m = f'SHA-512/{t}'.encode()
    m += fips_pad(len(m), 64)
    IV[f'SHA-512/{t}'] = compress([h ^ 0xa5a5a5a5a5a5a5a5 for h in IV['SHA-512']],
                                  [int.from_bytes(m[j:j + 8], 'big') for j in range(0, 128, 8)], 64)
assert K[32][0] == 0x428a2f98 and K[32][63] == 0xc67178f2 and K[64][79] == 0x6c44198c4a475817
assert IV['SHA-256'][7] == 0x5be0cd19 and IV['SHA-224'][0] == 0xc1059ed8
assert IV['SHA-384'][0] == 0xcbbb9d5dc1059ed8 and IV['SHA-512'][7] == 0x5be0cd19137e2179
assert IV['SHA-512/224'][0] == 0x8c3d37c819544da2 and IV['SHA-512/256'][7] == 0x0eb72ddc81c52ca2

# <<KLE-SHA-2-parameters>>: (w, b, n, t)
PARAMS = {'SHA-224': (32, 512, 256, 224), 'SHA-256': (32, 512, 256, 256),
          'SHA-384': (64, 1024, 512, 384), 'SHA-512': (64, 1024, 512, 512),
          'SHA-512/224': (64, 1024, 512, 224), 'SHA-512/256': (64, 1024, 512, 256)}

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

class Sha2:
    def __init__(s, name='SHA-256', bswap_words=True, klstart_bits=False):
        s.name, (s.w, s.b, s.n, s.t) = name, PARAMS[name]
        s.bswap_words, s.klstart_bits = bswap_words, klstart_bits
        s.reset(KL_STATE_UNCONFIGURED)

    def reset(s, st=KL_STATE_INVALID):  # GR29 for an Error State
        s.st, s.state, s.block, s.block_base = st, 0, 0, 0
        if st == KL_STATE_READY:
            s.state = sum(bswap(bin_(h, s.w), s.w // 8) << (i * s.w) for i, h in enumerate(IV[s.name]))
        return s

    def provision(s):  # PI = MDH only
        return s.reset(KL_STATE_READY)

    def process_block(s):
        wd = lambda v, j: sl(v, (j + 1) * s.w - 1, j * s.w)
        H = [bswap(wd(s.state, i), s.w // 8) for i in range(8)]
        W = [bswap(wd(s.block, j), s.w // 8) if s.bswap_words else wd(s.block, j) for j in range(16)]
        s.state = sum(bswap(h, s.w // 8) << (i * s.w) for i, h in enumerate(compress(H, W, s.w)))

    def export(s):  # <<KLE-hash-functions-MACs-XOFs>> Serialized Content, cumul_len absent
        return pack((s.state, s.n), (0, 16), (s.block_base, 16), (0, 16), (0, 16), (s.block, s.b))

    @classmethod
    def load(cls, name, st, c1):
        cl, v = cls(name), b2v(c1)
        cl.st, cl.state, cl.block_base, cl.block = st, sl(v, cl.n - 1, 0), sl(v, cl.n + 31, cl.n + 16), v >> (cl.n + 64)
        return cl

    def setst(s, immed, form='A'):  # <<KLE-instruction-setst>>
        if immed == KL_STATE_UNCONFIGURED or immed in ERROR_STATES:  # in any State
            if s.st != KL_STATE_UNCONFIGURED:
                s.reset(KL_STATE_INVALID if immed > 53 else immed)
        elif inert(s.st):
            pass  # GR26
        elif immed == KL_STATE_READY:
            s.reset(KL_STATE_READY)
        # Form A: max_len = 0 is set by the Machine; no same-State _Hash_Absorb_ (<<KLE-process-VLI>>)
        # or _Hash_Output_ (GR17);
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
            return 'noop', bytes(nbytes)  # GR26, GR28
        if s.st == KL_STATE_HASH_OUTPUT and form == 'C':
            p, prior = HART.klstart, prior or bytes(nbytes)
            if p >= nbytes:
                HART.klstart = 0
                return 'empty', prior  # empty window: only klstart = 0 (<<KLE-GR-transfer-window-checks>>)
            if p:  # not an interruption point: a hash reaches _Success_ before any
                s.reset()
                HART.klstart = 0
                return 'invalid', prior[:p] + bytes(nbytes - p)  # GR28
            return 'retired', s.output(nbytes, prior)
        if resume and (HART.klstart % GRAN or HART.klstart and s.block_base):
            r, HART.klstart = 'invalid', 0  # not an interruption point (<<KLE-process-VLI>>)
        else:
            r = s.process_vli(b2v(data), 8 * len(data), halt, resume) if (
                s.st == KL_STATE_HASH_ABSORB and form == 'B') else 'invalid'  # GR17, GR16, MR1
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
            if halt and ib < KLLEN and ib % 32 == 0:  # 3.i: at a multiple of the granularity only
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
    ML-KEM `sharedkey`, GR34) or, with secret=False, the `hash` of a CMAC in _Hash_Output_ (GR35).  A hash in
    _Hash_Output_ is not a source (<<KLE-derive-endpoints>>)."""
    def __init__(s, data, secret=True): s.st, s.data, s.secret = KL_STATE_HASH_OUTPUT, data, secret
    def reset(s): s.st = KL_STATE_INVALID

GRAN = 4  # bytes: the SHA-2 input granularity, 32 bits

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
    if pos or (min(length, n) < dst.n if key else not n <= length <= -(-n // GRAN) * GRAN):
        dst.reset()  # GR32 item 5
        return 'refused'
    if key:
        dst.key = src.data[:dst.n]
    else:
        dst.exec('B', src.data.ljust(length, b'\0'))  # GR31: zero beyond the field, which does not advance
    return 'done'

# ---------------------------------------------------------------- vectors

M_EMPTY, M_ABC = b'', b'abc'
M2_32 = b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
M2_64 = (b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn'
         b'hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu')
# FIPS 180-4 examples (NIST CSRC "Examples with Intermediate Values")
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
# Bitcoin wiki, "Protocol documentation", "Hashes": SHA-256(SHA-256("hello"))
SHA256D_HELLO = '9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50'
HASHLIB = dict(zip(PARAMS, ('sha224', 'sha256', 'sha384', 'sha512', 'sha512_224', 'sha512_256')))
MNAME = {M_EMPTY: 'empty', M_ABC: '"abc"', M2_32: '448-bit', M2_64: '896-bit'}

# ---------------------------------------------------------------- drivers

A = lambda c: c.setst(KL_STATE_HASH_ABSORB)
O = lambda c: c.setst(KL_STATE_HASH_OUTPUT)
R = lambda c: c.setst(KL_STATE_READY)
B = lambda d: lambda c: c.exec('B', d)
C = lambda n: lambda c: c.exec('C', nbytes=n, prior=b'\xa5' * n)

def run(c, *ops):
    """Apply ops to locker c; return the last result."""
    return [op(c) for op in ops][-1]

def digest(name, msg, plan, **kw):
    """Plans: multi (3 transfers, 2 reads), interrupt (halt at each 3.i, resume), export (mid-block),
    odd (transfers of 1 and 3 bytes, then a 1-byte read)."""
    cl = Sha2(name, **kw).provision()
    mp = msg + fips_pad(len(msg), cl.w)
    A(cl)
    if plan == 'multi':
        c = len(mp) // 2 - 4
        run(cl, B(mp[:4]), B(mp[4:c]), B(mp[c:]))
    elif plan == 'odd':
        run(cl, B(mp[:1]), B(mp[1:4]), B(mp[4:]))
    elif plan == 'interrupt':
        r = run(cl, B(mp[:4]), lambda c: c.exec('B', mp[4:], halt=True))[0]
        while r == 'interrupted':
            r = cl.exec('B', mp[4:], halt=True, resume=True)[0]
    else:
        B(mp[:-28])(cl)
        assert cl.block_base
        cl = Sha2.load(name, cl.st, cl.export())
        B(mp[-28:])(cl)
    O(cl)
    reads = {'multi': (cl.t // 8 - 8, 8), 'odd': (1, cl.t // 8 - 1)}.get(plan, (cl.t // 8,))
    out = b''.join(run(cl, C(n))[1] for n in reads)
    return out if cl.st == KL_STATE_SUCCESS else None

def absorbing(name='SHA-256', data=b'', **kw):
    cl = Sha2(name, **kw).provision()
    run(cl, A, *([B(data)] if data else []))
    return cl

def outputting(name='SHA-256', msg=M_ABC):
    cl = absorbing(name, msg + fips_pad(len(msg), PARAMS[name][0]))
    O(cl)
    return cl

# ---------------------------------------------------------------- checks

section('FIPS 180-4 vectors through the KLE model')
for name in PARAMS:
    for msg, h in VEC[name].items():
        want = bytes.fromhex(h)
        for plan in ('multi', 'interrupt', 'export', 'odd'):
            check(f'{name} {MNAME[msg]} {plan}', None, digest(name, msg, plan), want)
        if HASHLIB[name] in hashlib.algorithms_available:
            check(f'[oracle] hashlib {name} {MNAME[msg]}', None, hashlib.new(HASHLIB[name], msg).digest(), want)

section('Serialized Content')
for name, (w, b, n, t) in PARAMS.items():
    check(f'{name} Content1 = n+64+b bits, padded to 128', None, len(absorbing(name, bytes(8)).export()),
          {32: 112, 64: 208}[w])

section('State machine')
PAD_ABC = M_ABC + fips_pad(3, 32)
DIG_ABC = bytes.fromhex(VEC['SHA-256'][M_ABC])
for label, ops in [
        ('entering _Hash_Output_ with block_base != 0', (A, B(b'abc'), O)),
        ('kl.exec in _Ready_ (GR17)', (B(PAD_ABC),)),
        ('Form B kl.setst to _Hash_Absorb_', (lambda c: c.setst(KL_STATE_HASH_ABSORB, 'B'),)),
        ('same-State kl.setst to _Hash_Absorb_', (A, A)),
        ('same-State kl.setst to _Hash_Output_ (GR17)', (A, B(PAD_ABC), O, O)),
        ('kl.setst #kl_state_hash_last_block', (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B'))),
        ('_Ready_ -> _Hash_Output_', (O,)),
        ('Form C kl.exec in _Hash_Absorb_ (MR1), output zeroed', (A, C(16))),
        ('Form B kl.exec in _Hash_Output_ (MR1)', (A, B(PAD_ABC), O, B(bytes(64)))),
        ('kl.exec in _Success_ (GR16), output zeroed', (A, B(PAD_ABC), O, C(32), C(32)))]:
    cl = Sha2().provision()
    r = run(cl, *ops)
    check(f'_Invalid_: {label}', cl.st == KL_STATE_INVALID and not any(r[1] if r else b''))
check('kl.exec in _Invalid_: no operation, output zeroed (GR26, GR28)',
      C(32)(cl) == ('noop', bytes(32)) and cl.st == KL_STATE_INVALID)
cl, res = outputting(), []
for ks in (32, 40, 4):
    HART.klstart = ks
    res.append((C(32)(cl), cl.st, HART.klstart))
check('Form C, klstart >= KLLEN/8 (32, 40): empty window, only klstart = 0; klstart = 4 (no interruption point): '
      '_Invalid_, [4, 32) zeroed', None, res, [(('empty', b'\xa5' * 32), KL_STATE_HASH_OUTPUT, 0)] * 2
      + [(('invalid', b'\xa5' * 4 + bytes(28)), KL_STATE_INVALID, 0)])
MP = M2_64 + fips_pad(len(M2_64), 32)  # 128 bytes for SHA-256
cl = absorbing(data=MP[:5])
r = cl.exec('B', MP[5:69], halt=True)[0], HART.klstart, cl.block_base
r += (run(cl, B(MP[69:]), O, C(32))[1],)
check('a 5-byte transfer, then a 64-byte one with a halt requested at each 3.i (<<KLE-process-VLI>>): no halt at '
      'klstart = 59 (8 x 59 not a multiple of 32), retired; the digest is correct', None, r,
      ('retired', 0, 40, hashlib.sha256(M2_64).digest()))
res = []
for ks in (59, 4):
    cl = absorbing(data=MP[:5])
    HART.klstart = ks
    res.append((cl.exec('B', MP[5:69], resume=True)[0], cl.st, HART.klstart))
check('after a 5-byte transfer, a forged resumption at klstart = 59 (not a multiple of 32 bits) or 4 (block_base '
      '!= 0 at the window start): not an interruption point, _Invalid_', None, res,
      [('invalid', KL_STATE_INVALID, 0)] * 2)
cl = absorbing()
check('kl.setst #kl_state_success -> Invalid (GR18, MR1)',
      (raises(cl.setst, KL_STATE_SUCCESS), cl.st) == (False, KL_STATE_INVALID))
cl.setst(KL_STATE_UNCONFIGURED)
check('kl.clear; a later kl.exec or kl.setst performs no operation, output zeroed (GR26, GR28)',
      (cl.exec('C', nbytes=8), cl.setst(KL_STATE_READY), cl.st, cl.state)
      == (('noop', bytes(8)), None, KL_STATE_UNCONFIGURED, 0))
check('kl.setst #kl_state_failure on an Unconfigured locker: no operation (GR18, GR26)',
      (raises(cl.setst, KL_STATE_FAILURE), cl.st) == (False, KL_STATE_UNCONFIGURED))
cl = outputting('SHA-224')
check('KLLEN > t: digest, excess bits cleared, _Success_', None, (C(32)(cl)[1], cl.st),
      (bytes.fromhex(VEC['SHA-224'][M_ABC]) + bytes(4), KL_STATE_SUCCESS))
cl = outputting()
check('_Success_ -> _Ready_ (GR16), second digest', None,
      run(cl, C(32), R, A, B(PAD_ABC), O, C(32))[1], DIG_ABC)
cl, ready = absorbing('SHA-384', (M2_64 + fips_pad(len(M2_64), 64))[:132]), Sha2('SHA-384').provision()
dirty = cl.block_base and cl.state != ready.state
R(cl)
reset = (cl.state, cl.block, cl.block_base) == (ready.state, 0, 0)
check('_Hash_Absorb_ -> _Ready_ mid-message: state <- IV, block, block_base <- 0',
      dirty and reset and run(cl, A, B(M_ABC + fips_pad(3, 64)), O, C(48))[1]
      == bytes.fromhex(VEC['SHA-384'][M_ABC]))

section('kl.derive')
SEC = bytes(range(0x40, 0x60))  # a 32-byte shared secret
src, dst, dst2 = Source(SEC), absorbing(), absorbing()
r = (kl_derive(dst, src, 32), dst.block_base, kl_derive(dst2, src, 32))
check('shared secret (32 B) -> SHA-256 absorb [hashlib oracle]; the field does not advance: derived twice', None,
      (r, run(dst, B(fips_pad(32, 32)), O, C(32))[1], run(dst2, B(fips_pad(32, 32)), O, C(32))[1]),
      (('done', 256, 'done'), hashlib.sha256(SEC).digest(), hashlib.sha256(SEC).digest()))
src, dst = Source(SEC[:30]), absorbing()
check('shared secret (30 B), length 32 (30 rounded up to 4 B) -> SHA-256 absorb: zero beyond the secret [hashlib]',
      kl_derive(dst, src, 32) == 'done' and run(dst, B(fips_pad(32, 32)), O, C(32))[1]
      == hashlib.sha256(SEC[:30] + bytes(2)).digest())
src, dst = Source(SEC * 2), absorbing('SHA-224')
r = kl_derive(dst, src, 64)
whole = r == 'done' and dst.block_base == 0 and dst.state != Sha2('SHA-224').provision().state
check('shared secret (64 B) -> SHA-224 absorb (one block) [hashlib oracle]', whole and run(dst, B(fips_pad(64, 32)), O,
      C(28))[1] == hashlib.sha224(SEC * 2).digest())
src, dst = outputting(msg=b'hello'), absorbing()
check('SHA-256 digest in _Hash_Output_ as a source (GR32 item 1): refused, source _Invalid_, destination untouched; '
      'the same digest moved by kl.exec gives SHA-256(SHA-256("hello"))',
      kl_derive(dst, src, 32) == 'refused' and src.st == KL_STATE_INVALID
      and (dst.st, dst.block_base) == (KL_STATE_HASH_ABSORB, 0)
      and run(dst, B(C(32)(outputting(msg=b'hello'))[1] + fips_pad(32, 32)), O, C(32))[1]
      == bytes.fromhex(SHA256D_HELLO))
src, dst = Source(bytes(range(16)), secret=False), absorbing()
check('a CMAC (16 B) -> SHA-256 absorb: pair not admitted (GR32 item 3), both _Invalid_',
      kl_derive(dst, src, 16) == 'refused' and (src.st, dst.st) == (KL_STATE_INVALID, KL_STATE_INVALID))
src, dst = Source(SEC), Sha2().provision()
check('destination in _Ready_ (GR32 item 2): refused, destination _Invalid_, source untouched',
      kl_derive(dst, src, 32) == 'refused' and dst.st == KL_STATE_INVALID and src.st == KL_STATE_HASH_OUTPUT)
res = []
for s, length in ((SEC, 0), (SEC, 31), (SEC, 36), (SEC[:30], 29), (SEC[:30], 33)):
    dst = absorbing()
    res.append((kl_derive(dst, Source(s), length), dst.st))
check('shared secret into SHA-256 absorb: 32 B with length 0, 31 or 36, 30 B with length 29 or 33 (GR32 item 5: from '
      'the secret length to it rounded up to 4 B): destination _Invalid_', None, res,
      [('refused', KL_STATE_INVALID)] * 5)

src, dst, s28, d28, h, dh = Source(SEC), KeyDest(32), Source(SEC[:28]), KeyDest(32), outputting(), KeyDest(32)
check('shared secret -> a 32-byte `key` in _Ready_, length 40: the secret; a 28-byte secret -> a 32-byte key '
      '(GR32 item 5): destination _Invalid_, source untouched; SHA-256("abc") -> a key (GR32 item 1): source '
      '_Invalid_, key untouched', None,
      (kl_derive(dst, src, 40), dst.key, kl_derive(d28, s28, 32), d28.st, s28.st, kl_derive(dh, h, 32), h.st, dh.st),
      ('done', SEC, 'refused', KL_STATE_INVALID, KL_STATE_HASH_OUTPUT, 'refused', KL_STATE_INVALID, KL_STATE_READY))

section('Negative controls')
control('message words without bswap', digest('SHA-256', M_ABC, 'multi', bswap_words=False) != DIG_ABC)
control('klstart written in bits', digest('SHA-256', M2_32, 'interrupt', klstart_bits=True)
        != bytes.fromhex(VEC['SHA-256'][M2_32]))

done()
