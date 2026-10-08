#!/usr/bin/env python3
"""SHA-2 family KAT for KLEE: <<KLEE-SHA-2>> over <<KLEE-hash-functions-MACs-XOFs>>, <<KLEE-process-VLI>>.
FIPS 180-4 cores from scratch; hashlib is only a labeled reference oracle."""
import hashlib, math, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, bswap, bin_, IllegalInstruction, ERROR_STATES,
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

# <<KLEE-SHA-2-parameters>>: (w, b, n, t)
PARAMS = {'SHA-224': (32, 512, 256, 224), 'SHA-256': (32, 512, 256, 256),
          'SHA-384': (64, 1024, 512, 384), 'SHA-512': (64, 1024, 512, 512),
          'SHA-512/224': (64, 1024, 512, 224), 'SHA-512/256': (64, 1024, 512, 256)}

# ---------------------------------------------------------------- KLEE model

class Hart:
    klstart = 0  # bytes, <<KLEE-CSR-klstart>>

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

    def reset(s, st=KL_STATE_INVALID):  # GR28 for an Error State
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

    def export(s):  # <<KLEE-hash-functions-MACs-XOFs>> Serialized Content, cumul_len absent
        return pack((s.state, s.n), (0, 16), (s.block_base, 16), (0, 16), (0, 16), (s.block, s.b))

    @classmethod
    def load(cls, name, st, c1):
        cl, v = cls(name), b2v(c1)
        cl.st, cl.state, cl.block_base, cl.block = st, sl(v, cl.n - 1, 0), sl(v, cl.n + 31, cl.n + 16), v >> (cl.n + 64)
        return cl

    def setst(s, immed, form='A'):  # <<KLEE-instruction-setst>>
        if immed in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            raise IllegalInstruction  # GR24
        if immed == KL_STATE_UNCONFIGURED or immed in ERROR_STATES:  # in any State
            if s.st != KL_STATE_UNCONFIGURED:
                s.reset(KL_STATE_INVALID if immed > 53 else immed)
        elif s.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction  # GR33
        elif s.st in ERROR_STATES:
            pass
        elif immed == KL_STATE_READY:
            s.reset(KL_STATE_READY)
        # Form A: max_len = 0 is set by the Machine; no same-State _Hash_Absorb_ (<<KLEE-process-VLI>>)
        # or _Hash_Output_ (MR17);
        # stand-alone hashing enters _Hash_Output_ with whole blocks only
        elif form != 'A' or (s.st, immed) not in ((KL_STATE_READY, KL_STATE_HASH_ABSORB),
                                                  (KL_STATE_HASH_ABSORB, KL_STATE_HASH_OUTPUT)) \
                or (immed == KL_STATE_HASH_OUTPUT and s.block_base):
            s.reset()
        else:
            s.st = immed

    def exec(s, form, data=b'', nbytes=0, halt=False, resume=False, prior=None):
        """kl.exec Form B (data) or C (nbytes); returns (status, output)."""
        if s.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction
        if s.st in ERROR_STATES:
            return 'noop', bytes(nbytes)  # GR32
        if s.st == KL_STATE_HASH_OUTPUT and form == 'C':
            p, prior = HART.klstart, prior or bytes(nbytes)
            if p >= nbytes:
                HART.klstart = 0
                return 'empty', prior  # empty window: only klstart = 0 (<<KLEE-CSR-klstart>>)
            if p:  # not an interruption point: a hash reaches _Success_ before any
                s.reset()
                HART.klstart = 0
                return 'invalid', prior[:p] + bytes(nbytes - p)  # GR32
            return 'retired', s.output(nbytes, prior)
        r = s.process_vli(b2v(data), 8 * len(data), halt, resume) if (
            s.st == KL_STATE_HASH_ABSORB and form == 'B') else 'invalid'  # GR22, GR26, MR1
        if r == 'invalid':
            s.reset()
        return r, bytes(nbytes)

    def process_vli(s, INPUT, KLLEN, halt, resume):
        """process_VLI(max_len=0, block, b, state, n, input_base, block_base, 0, None, P, None, assign)."""
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
    """A symmetric `key` of n bytes, a destination in _Ready_ (<<KLEE-derive-endpoints>>); only the key is modelled."""
    def __init__(s, n): s.st, s.n, s.key = KL_STATE_READY, n, None
    def reset(s): s.st, s.key = KL_STATE_INVALID, None

def kl_derive(dst, src, length):
    """_Hash_Output_ kl.exec output -> _Hash_Absorb_ kl.exec input (<<KLEE-derive-endpoints>>, GR47)
    or a KeyDest (GR47 key derivation, unrestricted)."""
    if src.st in ERROR_STATES or dst.st in ERROR_STATES:
        return 'noop'  # Gate Order Rule
    key = isinstance(dst, KeyDest)
    bad = [c for c, ok in ((src, src.st == KL_STATE_HASH_OUTPUT),
                           (dst, dst.st == (KL_STATE_READY if key else KL_STATE_HASH_ABSORB))) if not ok]
    for c in bad:
        c.reset()  # GR42 items 1-2
    if not bad and key:
        if min(length, (src.t - src.block_base) // 8) < dst.n:
            dst.reset()  # GR42 item 5
            return 'refused'
        dst.key = src.exec('C', nbytes=dst.n)[1]
        return 'done'
    if bad or not length:
        return 'refused' if bad else 'noop'
    dst.exec('B', src.exec('C', nbytes=length)[1])  # GR49: each endpoint advances as kl.exec would
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
    """Plans: multi (3 transfers, 2 reads), interrupt (halt at each 4.i, resume), export (mid-block)."""
    cl = Sha2(name, **kw).provision()
    mp = msg + fips_pad(len(msg), cl.w)
    A(cl)
    if plan == 'multi':
        c = len(mp) // 2 - 4
        run(cl, B(mp[:4]), B(mp[4:c]), B(mp[c:]))
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
    out = run(cl, C(cl.t // 8 - 8))[1] + run(cl, C(8))[1] if plan == 'multi' else run(cl, C(cl.t // 8))[1]
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

section('FIPS 180-4 vectors through the KLEE model')
for name in PARAMS:
    for msg, h in VEC[name].items():
        want = bytes.fromhex(h)
        for plan in ('multi', 'interrupt', 'export'):
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
        ('kl.exec in _Ready_ (GR22)', (B(PAD_ABC),)),
        ('Form B kl.setst to _Hash_Absorb_', (lambda c: c.setst(KL_STATE_HASH_ABSORB, 'B'),)),
        ('same-State kl.setst to _Hash_Absorb_', (A, A)),
        ('same-State kl.setst to _Hash_Output_ (MR17)', (A, B(PAD_ABC), O, O)),
        ('kl.setst #kl_state_hash_last_block', (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B'))),
        ('_Ready_ -> _Hash_Output_', (O,)),
        ('Form C kl.exec in _Hash_Absorb_ (MR1), output zeroed', (A, C(16))),
        ('Form B kl.exec in _Hash_Output_ (MR1)', (A, B(PAD_ABC), O, B(bytes(64)))),
        ('kl.exec in _Success_ (GR26), output zeroed', (A, B(PAD_ABC), O, C(32), C(32)))]:
    cl = Sha2().provision()
    r = run(cl, *ops)
    check(f'_Invalid_: {label}', cl.st == KL_STATE_INVALID and not any(r[1] if r else b''))
check('kl.exec in _Invalid_: no operation, output zeroed (GR32)',
      C(32)(cl) == ('noop', bytes(32)) and cl.st == KL_STATE_INVALID)
cl, res = outputting(), []
for ks in (32, 40, 4):
    HART.klstart = ks
    res.append((C(32)(cl), cl.st, HART.klstart))
check('Form C, klstart >= KLLEN/8 (32, 40): empty window, only klstart = 0; klstart = 4 (no interruption point): '
      '_Invalid_, [4, 32) zeroed', None, res, [(('empty', b'\xa5' * 32), KL_STATE_HASH_OUTPUT, 0)] * 2
      + [(('invalid', b'\xa5' * 4 + bytes(28)), KL_STATE_INVALID, 0)])
cl = absorbing()
check('kl.setst #kl_state_success raises, State kept (GR24)',
      raises(cl.setst, KL_STATE_SUCCESS) and cl.st == KL_STATE_HASH_ABSORB)
cl.setst(KL_STATE_UNCONFIGURED)
check('kl.clear; a later kl.exec raises (GR33)',
      raises(cl.exec, 'B', bytes(4)) and cl.st == KL_STATE_UNCONFIGURED and cl.state == 0)
cl = outputting('SHA-224')
check('KLLEN > t: digest, excess bits cleared, _Success_', None, (C(32)(cl)[1], cl.st),
      (bytes.fromhex(VEC['SHA-224'][M_ABC]) + bytes(4), KL_STATE_SUCCESS))
cl = outputting()
check('_Success_ -> _Ready_ (GR25), second digest', None,
      run(cl, C(32), R, A, B(PAD_ABC), O, C(32))[1], DIG_ABC)
cl, ready = absorbing('SHA-384', (M2_64 + fips_pad(len(M2_64), 64))[:132]), Sha2('SHA-384').provision()
dirty = cl.block_base and cl.state != ready.state
R(cl)
reset = (cl.state, cl.block, cl.block_base) == (ready.state, 0, 0)
check('_Hash_Absorb_ -> _Ready_ mid-message: state <- IV, block, block_base <- 0',
      dirty and reset and run(cl, A, B(M_ABC + fips_pad(3, 64)), O, C(48))[1]
      == bytes.fromhex(VEC['SHA-384'][M_ABC]))

section('kl.derive')
src, dst = outputting(msg=b'hello'), absorbing()
r = kl_derive(dst, src, 32)
moved = r == 'done' and src.st == KL_STATE_SUCCESS and dst.block_base == 256
check('SHA-256 digest -> SHA-256 absorb: SHA-256(SHA-256("hello")), source _Success_',
      moved and run(dst, B(fips_pad(32, 32)), O, C(32))[1] == bytes.fromhex(SHA256D_HELLO))
late = absorbing()
check('source in _Success_: refused, source _Invalid_, destination untouched',
      kl_derive(late, src, 32) == 'refused' and src.st == KL_STATE_INVALID
      and (late.st, late.block_base) == (KL_STATE_HASH_ABSORB, 0))
src, dst = outputting('SHA-512'), absorbing('SHA-224')
r = kl_derive(dst, src, 64)
whole = r == 'done' and dst.block_base == 0 and dst.state != Sha2('SHA-224').provision().state
check('SHA-512 digest -> SHA-224 absorb (one block) [hashlib oracle]', whole and run(dst, B(fips_pad(64, 32)), O,
      C(28))[1] == hashlib.sha224(bytes.fromhex(VEC['SHA-512'][M_ABC])).digest())
src, dst = outputting(), Sha2().provision()
check('destination in _Ready_: refused, destination _Invalid_, source untouched',
      kl_derive(dst, src, 32) == 'refused' and dst.st == KL_STATE_INVALID
      and (src.st, src.block_base) == (KL_STATE_HASH_OUTPUT, 0))
dst = absorbing()
check('length 0: nothing transferred, no State change (GR49)', kl_derive(dst, src, 0) == 'noop'
      and (dst.st, dst.block_base) == (KL_STATE_HASH_ABSORB, 0) and C(32)(src)[1] == DIG_ABC)

src, dst, s224, d224 = outputting(), KeyDest(32), outputting('SHA-224'), KeyDest(32)
check('GR47 key derivation: SHA-256("abc") -> a 32-byte `key` in _Ready_ (source _Success_); SHA-224 (28 B) -> '
      'a 32-byte key (GR42 item 5): destination _Invalid_, source untouched', None,
      (kl_derive(dst, src, 40), dst.key, src.st, kl_derive(d224, s224, 32), d224.st, s224.st),
      ('done', DIG_ABC, KL_STATE_SUCCESS, 'refused', KL_STATE_INVALID, KL_STATE_HASH_OUTPUT))

section('Negative controls')
control('message words without bswap', digest('SHA-256', M_ABC, 'multi', bswap_words=False) != DIG_ABC)
control('klstart written in bits', digest('SHA-256', M2_32, 'interrupt', klstart_bits=True)
        != bytes.fromhex(VEC['SHA-256'][M2_32]))

done()
