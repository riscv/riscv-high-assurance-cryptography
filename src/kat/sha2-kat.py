#!/usr/bin/env python3
"""SHA-2 family KAT for KLE: <<KLE-SHA-2>> over <<KLE-hash-functions-MACs-XOFs>>, <<KLE-process-VLI>>.
FIPS 180-4 cores from scratch; hashlib is only a labeled reference oracle."""
import hashlib, math, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (KL_STATE_INERT, KL_STATE_READY, KL_STATE_HASH_ABSORB, KL_STATE_HASH_LAST_BLOCK,
                    KL_STATE_HASH_OUTPUT, KL_STATE_SUCCESS, KL_STATE_FAILURE, KL_STATEEXT_INVALID, KL_STATEEXT_UNSUPPORTED, section, check,
                    control, raises, done, md_pad, hash_run, hash_msgs, check_hash)
from sha2_sm3_common import HART, MdHash, MdPort, KeyDest, Source, kl_derive, A, O, R, B, C, run

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

for t in (224, 256):  # sect. 5.3.6
    m = f'SHA-512/{t}'.encode()
    m += md_pad(8 * len(m), 64)
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

class Sha2(MdHash):
    """<<KLE-SHA-2>> with the PARAMS of name, granularity 8 bits."""
    def __init__(s, name='SHA-256', **kw):
        w, b, n, t = PARAMS[name]
        super().__init__(name, w, b, n, t, IV[name], lambda H, W: compress(H, W, w), **kw)

    @classmethod
    def load(cls, name, st, c1): return cls(name).restore(st, c1)

class Port(MdPort):
    """<<Zkl-software.adoc#KLE-pseudocode-hash>> on a Sha2 locker."""
    def __init__(p, name='SHA-256', cl=None):
        p.name = name
        super().__init__(cl or Sha2(name).provision())
    def imported(p, img): return Port(p.name, Sha2.load(p.name, *img))

def ref_bits(name, msg, nbits, nout=None):
    """FIPS 180-4 on a bit string (sect. 5.1.1, 5.1.2), independent of md_pad: the first nbits bits of msg,
    MSB-first."""
    w, b, n, t = PARAMS[name]
    bits = ''.join(format(x, '08b') for x in msg)[:nbits]
    bits += '1' + '0' * (-(nbits + 1 + 2 * w) % b) + format(nbits, f'0{2 * w}b')
    H = IV[name]
    for o in range(0, len(bits), b):
        blk = bits[o:o + b]
        H = compress(H, [int(blk[j:j + w], 2) for j in range(0, b, w)], w)
    return b''.join(h.to_bytes(w // 8, 'big') for h in H)[:t // 8][:nout]

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

def digest(name, msg, plan, **kw):
    """Plans: multi (3 transfers, 2 reads), interrupt (halt at each 3.i, resume), export (mid-block),
    odd (transfers of 1 and 3 bytes, then a 1-byte read)."""
    cl = Sha2(name, **kw).provision()
    A(cl)
    if plan == 'multi':
        c = max(4, len(msg) // 2 - 4)
        run(cl, B(msg[:4]), B(msg[4:c]), B(msg[c:]))
    elif plan == 'odd':
        run(cl, B(msg[:1]), B(msg[1:4]), B(msg[4:]))
    elif plan == 'interrupt':
        r = run(cl, B(msg[:4]), lambda c: c.exec('B', msg[4:], halt=True))[0]
        while r == 'interrupted':
            r = cl.exec('B', msg[4:], halt=True, resume=True)[0]
    else:
        B(msg[:len(msg) // 2])(cl)
        cl = Sha2.load(name, cl.st, cl.export())
        B(msg[len(msg) // 2:])(cl)
    O(cl)
    reads = {'multi': (cl.t // 8 - 8, 8), 'odd': (1, cl.t // 8 - 1)}.get(plan, (cl.t // 8,))
    out = b''.join(run(cl, C(n))[1] for n in reads)
    return out if cl.st == KL_STATE_SUCCESS else None

def absorbing(name='SHA-256', data=b'', **kw):
    cl = Sha2(name, **kw).provision()
    run(cl, A, *([B(data)] if data else []))
    return cl

def outputting(name='SHA-256', msg=M_ABC):
    cl = absorbing(name, msg)
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

DIG = hashlib.sha256(b'abc').digest()
section('The generic sequence (<<Zkl-software.adoc#KLE-pseudocode-hash>>): chunks, final pieces, halts, export/import')
for name, (w, b, n, t) in PARAMS.items():
    bb = b // 8
    ref = lambda m, nb, o, name=name: (hashlib.new(HASHLIB[name], m[:nb // 8]).digest()[:o]
                                       if nb % 8 == 0 and HASHLIB[name] in hashlib.algorithms_available
                                       else ref_bits(name, m, nb, o))
    msgs = hash_msgs(bb, edges=(bb - 2 * w // 8 - 1, bb - 2 * w // 8), bits=True)
    check_hash(name, lambda name=name: Port(name), ref, msgs if name in ('SHA-256', 'SHA-512') else msgs[::3], t // 8)
res = [ref_bits('SHA-256', b'abc', 24) == hashlib.sha256(b'abc').digest()]
for nb in (1, 5, 447, 448, 449, 511, 1000):
    m = bytes((3 * i + 7) & 0xFF for i in range(-(-nb // 8)))
    res.append(hash_run(Port(), m, nb, 32)[0] == ref_bits('SHA-256', m, nb))
check('bit-length messages of 1, 5, 447, 448, 449, 511 and 1000 bits: the final piece MSB-first, the pad bit in its '
      'last byte (<<KLE-SHA-2>>), against an independent FIPS 180-4 bit-string reference', all(res))
res = []
for name, nb in (('SHA-256', 510), ('SHA-256', 517), ('SHA-256', 1029), ('SHA-512', 1022), ('SHA-512', 1037)):
    m = bytes((3 * i + 7) & 0xFF for i in range(-(-nb // 8)))
    t = PARAMS[name][3] // 8
    res.append(hash_run(Port(name), m, nb, t, piece=nb % 8 + 16)[0] == ref_bits(name, m, nb))
check('a final piece of nbits mod 8 + 16 bits that ends at, or straddles, a block boundary (SHA-256 510, 517, 1029 '
      'bits; SHA-512 1022, 1037 bits): the pad bit in its last byte, against the bit-string reference', all(res))
r = []
for x in (8, 224, 256):
    o, st, _ = hash_run(Port(), b'abc', 24, x // 8, end=('B', x))
    r.append((o, st))
o_a, st_a, _ = hash_run(Port(), b'abc', 24, 32, end=('A', None))
check('bound (<<KLE-hash-functions-MACs-XOFs>>): Form B Xs = 8, t - 8, t gives that prefix of the digest and _Success_; '
      'Form A the full digest', None, (r, (o_a, st_a)),
      ([(DIG[:x // 8], KL_STATE_SUCCESS) for x in (8, 224, 256)], (DIG, KL_STATE_SUCCESS)))
res = []
for xs in (264, 12):
    cl = absorbing(data=b'abc')
    cl.setst(KL_STATE_HASH_OUTPUT, 'B', xs)
    res.append(cl.st)
cl = absorbing(data=b'abc')
cl.setst(KL_STATE_HASH_OUTPUT, 'B', 128)
o1 = C(8)(cl)[1]
cl = Sha2.load('SHA-256', cl.st, cl.export())
o2 = cl.exec('C', nbytes=16, prior=b'\xa5' * 16)[1]
check('bound Xs = t + 8 or 12 (not a multiple of 8) -> _Invalid_; Xs = 128 read as 8 B, export/import, then 16 B: '
      'the bound survives, the excess is cleared, _Success_', None, (res, o1 + o2, cl.st),
      ([KL_STATEEXT_INVALID] * 2, DIG[:16] + bytes(8), KL_STATE_SUCCESS))
res = []
for label, ops in [
        ('Xs = 0 then a kl.exec (MR8)', (A, B(b'ab'), lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 0), B(b'c'))),
        ('Xs = b + 8', (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 520))),
        ('_Hash_Output_ before the final piece (last_block_len != 0)',
         (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 8), O)),
        ('a second kl.exec in _Hash_Absorb_Last_Block_',
         (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 8), B(b'a'), B(b'b'))),
        ('a final piece of 16 bits in a KLLEN of 8 (MR1)',
         (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 16), B(b'a'))),
        ('_Ready_ -> _Hash_Absorb_Last_Block_', (lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 8),))]:
    cl = Sha2().provision()
    run(cl, *ops)
    res.append((label, cl.st))
check('final piece: _Invalid_ for ' + '; '.join(l for l, _ in res), None, [st for _, st in res], [KL_STATEEXT_INVALID] * 6)
res = []
for d, ks in ((b'', 0), (b'a', 2)):
    cl = Sha2().provision()
    run(cl, A, B(b'ab'), lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 16))
    HART.klstart = ks
    res.append((cl.exec('B', d, resume=ks != 0)[0], cl.st, HART.klstart))
check('final piece of 16 bits, KLLEN = 0, or KLLEN = 8 with klstart = 2: the length is checked before the empty '
      'window, _Invalid_ (MR1, GR53)', None, res, [('invalid', KL_STATEEXT_INVALID, 0)] * 2)
cl = Sha2().provision()
run(cl, A, B(b'ab'), lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 0))
r = B(b'')(cl)[0], cl.st
check('Xs = 0, then an empty kl.exec: empty window, State kept; the digest is that of "ab" (GR53)', None,
      (r, run(cl, O, C(32))[1]), (('empty', KL_STATE_HASH_LAST_BLOCK), hashlib.sha256(b'ab').digest()))
m = bytes(range(70))
cl = absorbing(data=m[:6])
run(cl, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 512), B(m[6:]), lambda c: c.setst(KL_STATE_HASH_OUTPUT, 'B', 0))
o = C(32)(cl)[1]
cl2 = absorbing(data=m[:6])
run(cl2, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 512), O)
cl3 = absorbing(data=m[:6])
run(cl3, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK), O)
check('Form B Xs = b into _Hash_Absorb_Last_Block_: a 512-bit piece, then Form B Xs = 0 into _Hash_Output_: the full '
      'digest, _Success_; Xs = b, then _Hash_Output_ before the piece: _Invalid_; Form A is Xs = 0: _Hash_Output_ '
      'directly gives the digest of the absorbed prefix', None,
      (o, cl.st, cl2.st, C(32)(cl3)[1]),
      (hashlib.sha256(m).digest(), KL_STATE_SUCCESS, KL_STATEEXT_INVALID, hashlib.sha256(m[:6]).digest()))
control('caller-padded message: the digest differs', digest('SHA-256', M_ABC + md_pad(24, 32), 'multi') != DIG)
cl = absorbing(data=b'abc')
HART.klstart = 3
r = cl.exec('B', b'xyz', resume=True)[0], cl.st, HART.klstart
check('_Hash_Absorb_ with block_base = 24, a 3-byte kl.exec with klstart = 3: empty window, State kept, klstart = 0 '
      '(GR53 item 2 precedes item 3); the digest is that of "abc"', None, (r, run(cl, O, C(32))[1]),
      (('empty', KL_STATE_HASH_ABSORB, 0), DIG))

check('a PI with _MachinePolicy_ = 1: unsupported Metadata; a kl.restrictl keeps the unused _MachinePolicy_ '
      'zero, whatever its request (<<KLE-hash-functions-MACs-XOFs>>, <<KLE-instruction-restrict>>)',
      None, (Sha2().provision(1).st, absorbing(data=b'abc').restrictl(1).st, absorbing(data=b'abc').restrictl(0).st),
      (KL_STATEEXT_UNSUPPORTED, KL_STATE_HASH_ABSORB, KL_STATE_HASH_ABSORB))

section('Serialized Content')
for name, (w, b, n, t) in PARAMS.items():
    check(f'{name} Content1 = n+16+16+32+64+b bits, padded to 128', None, len(absorbing(name, bytes(8)).export()),
          {32: 112, 64: 208}[w])

section('State machine')
DIG_ABC = bytes.fromhex(VEC['SHA-256'][M_ABC])
cl = Sha2().provision()
check('"abc" unpadded, then the kl.setst into _Hash_Output_ with block_base != 0: the Machine pads, digest correct',
      run(cl, A, B(b'abc'), O, C(32))[1] == DIG_ABC and cl.st == KL_STATE_SUCCESS)
for label, ops in [
        ('kl.exec in _Ready_ (GR21)', (B(M_ABC),)),
        ('Form B kl.setst to _Hash_Absorb_', (lambda c: c.setst(KL_STATE_HASH_ABSORB, 'B'),)),
        ('same-State kl.setst to _Hash_Absorb_', (A, A)),
        ('same-State kl.setst to _Hash_Output_ (GR21)', (A, B(M_ABC), O, O)),
        ('kl.setst #kl_state_hash_last_block without Xs', (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B'))),
        ('_Ready_ -> _Hash_Output_', (O,)),
        ('Form C kl.exec in _Hash_Absorb_ (GR22), output zeroed', (A, C(16))),
        ('Form B kl.exec in _Hash_Output_ (GR22)', (A, B(M_ABC), O, B(bytes(64)))),
        ('kl.exec in _Success_ (GR22, GR35), output zeroed', (A, B(M_ABC), O, C(32), C(32)))]:
    cl = Sha2().provision()
    r = run(cl, *ops)
    check(f'_Invalid_: {label}', cl.st == KL_STATEEXT_INVALID and not any(r[1] if r else b''))
check('kl.exec in _Invalid_: no operation, output zeroed (GR33, GR35)',
      C(32)(cl) == ('noop', bytes(32)) and cl.st == KL_STATEEXT_INVALID)
cl = outputting()
HART.klstart = 4
check('Form C, klstart = 4 at the start of _Hash_Output_ (block_base = 0): the first 28 digest bytes in [4, 31]',
      None, (C(32)(cl), cl.st, HART.klstart), (('retired', b'\xa5' * 4 + hashlib.sha256(M_ABC).digest()[:28]), KL_STATE_HASH_OUTPUT, 0))
cl, res = outputting(), []
for ks in (32, 40, 4):
    HART.klstart = ks
    res.append((C(32)(cl), cl.st, HART.klstart))
    if ks == 40:
        C(1)(cl)                                  # block_base = 8: klstart = 4 is no interruption point
check('Form C, klstart >= KLLEN/8 (32, 40): empty window, only klstart = 0; klstart = 4 with block_base != 0 '
      '(no interruption point): _Invalid_, [4, 31] zeroed', None, res, [(('empty', b'\xa5' * 32), KL_STATE_HASH_OUTPUT, 0)] * 2
      + [(('invalid', b'\xa5' * 4 + bytes(28)), KL_STATEEXT_INVALID, 0)])
MP = M2_64  # 112 bytes
cl = absorbing(data=MP[:5])
r = cl.exec('B', MP[5:69], halt=True)[0], HART.klstart, cl.block_base
r += (cl.exec('B', MP[5:69], resume=True)[0], run(cl, B(MP[69:]), O, C(32))[1])
check('a 5-byte transfer, then a 64-byte one with a halt requested at each 3.i (<<KLE-process-VLI>>): a halt at '
      'klstart = 59, where the block is full (granularity 8 bits), block_base = 0; resumed, the digest is correct',
      None, r, ('interrupted', 59, 0, 'retired', hashlib.sha256(M2_64).digest()))
res = []
for ks in (59, 4):
    cl = absorbing(data=MP[:5])
    HART.klstart = ks
    res.append((cl.exec('B', MP[5:69], resume=True)[0], cl.st, HART.klstart))
check('after a 5-byte transfer, a forged resumption at klstart = 59 or 4 (block_base != 0 at the window start): '
      'not an interruption point, _Invalid_', None, res,
      [('invalid', KL_STATEEXT_INVALID, 0)] * 2)
cl = absorbing()
check('kl.setst #kl_state_success -> Invalid (GR25, GR24)',
      (raises(cl.setst, KL_STATE_SUCCESS), cl.st) == (False, KL_STATEEXT_INVALID))
cl.setst(KL_STATE_INERT)
check('kl.clear; a later kl.exec or kl.setst performs no operation, output zeroed (GR33, GR35)',
      (cl.exec('C', nbytes=8), cl.setst(KL_STATE_READY), cl.st, cl.state)
      == (('noop', bytes(8)), None, KL_STATE_INERT, 0))
check('kl.setst #kl_state_failure on an Unconfigured locker: no operation (GR33)',
      (raises(cl.setst, KL_STATE_FAILURE), cl.st) == (False, KL_STATE_INERT))
check('kl.setst #48, #53 on an Unconfigured locker: no operation (GR33)',
      (raises(cl.setst, 48), raises(cl.setst, 53), cl.st) == (False, False, KL_STATE_INERT))
cl = outputting('SHA-224')
check('KLLEN > t: digest, excess bits cleared, _Success_', None, (C(32)(cl)[1], cl.st),
      (bytes.fromhex(VEC['SHA-224'][M_ABC]) + bytes(4), KL_STATE_SUCCESS))
cl = outputting()
check('_Success_ -> _Ready_ (GR23), second digest', None,
      run(cl, C(32), R, A, B(M_ABC), O, C(32))[1], DIG_ABC)
cl, ready = absorbing('SHA-384', (M2_64 * 2)[:132]), Sha2('SHA-384').provision()
dirty = cl.block_base and cl.state != ready.state
R(cl)
reset = (cl.state, cl.block, cl.block_base) == (ready.state, 0, 0)
check('_Hash_Absorb_ -> _Ready_ mid-message: state <- IV, block, block_base <- 0',
      dirty and reset and run(cl, A, B(M_ABC), O, C(48))[1]
      == bytes.fromhex(VEC['SHA-384'][M_ABC]))

section('kl.derive')
SEC = bytes(range(0x40, 0x60))  # a 32-byte shared secret
src, dst, dst2 = Source(SEC), absorbing(), absorbing()
r = (kl_derive(dst, src, 32), dst.block_base, kl_derive(dst2, src, 32))
check('shared secret (32 B) -> SHA-256 absorb [hashlib oracle]; the field does not advance: derived twice', None,
      (r, run(dst, O, C(32))[1], run(dst2, O, C(32))[1]),
      (('done', 256, 'done'), hashlib.sha256(SEC).digest(), hashlib.sha256(SEC).digest()))
src, dst = Source(SEC[:30]), absorbing()
check('shared secret (30 B), length 30 -> SHA-256 absorb: exactly the secret (GR40 item 5) [hashlib]',
      kl_derive(dst, src, 30) == 'done' and run(dst, O, C(32))[1] == hashlib.sha256(SEC[:30]).digest())
src, dst = Source(SEC * 2), absorbing('SHA-224')
r = kl_derive(dst, src, 64)
whole = r == 'done' and dst.block_base == 0 and dst.state != Sha2('SHA-224').provision().state
check('shared secret (64 B) -> SHA-224 absorb (one block) [hashlib oracle]', whole and run(dst, O,
      C(28))[1] == hashlib.sha224(SEC * 2).digest())
src, dst = outputting(msg=b'hello'), absorbing()
check('SHA-256 digest in _Hash_Output_ as a source (GR40 item 1): refused, source _Invalid_, destination untouched; '
      'the same digest moved by kl.exec gives SHA-256(SHA-256("hello"))',
      kl_derive(dst, src, 32) == 'refused' and src.st == KL_STATEEXT_INVALID
      and (dst.st, dst.block_base) == (KL_STATE_HASH_ABSORB, 0)
      and run(dst, B(C(32)(outputting(msg=b'hello'))[1]), O, C(32))[1]
      == bytes.fromhex(SHA256D_HELLO))
src, dst = Source(bytes(range(16)), secret=False), absorbing()
check('a CMAC (16 B) -> SHA-256 absorb: pair not admitted (GR40 item 3), both _Invalid_',
      kl_derive(dst, src, 16) == 'refused' and (src.st, dst.st) == (KL_STATEEXT_INVALID, KL_STATEEXT_INVALID))
src, dst = Source(SEC), Sha2().provision()
check('destination in _Ready_ (GR40 item 2): refused, destination _Invalid_, source untouched',
      kl_derive(dst, src, 32) == 'refused' and dst.st == KL_STATEEXT_INVALID and src.st == KL_STATE_HASH_OUTPUT)
res = []
for s, length in ((SEC, 0), (SEC, 31), (SEC, 36), (SEC[:30], 29), (SEC[:30], 32), (SEC[:30], 33)):
    dst = absorbing()
    res.append((kl_derive(dst, Source(s), length), dst.st))
check('shared secret into SHA-256 absorb: 32 B with length 0, 31 or 36, 30 B with length 29, 32 or 33 (GR40 item 5: '
      'exactly the secret length): destination _Invalid_', None, res,
      [('refused', KL_STATEEXT_INVALID)] * 6)
dst, dst2 = absorbing(data=b'abc'), absorbing(data=b'abc')
dst.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 0)
check('shared secret into SHA-256 _Hash_Absorb_Last_Block_ (not an endpoint, GR40 item 2): destination _Invalid_; '
      'after a 3-byte prefix in _Hash_Absorb_: the digest of the prefix and the secret [hashlib]', None,
      (kl_derive(dst, Source(SEC), 32), dst.st, kl_derive(dst2, Source(SEC), 32), run(dst2, O, C(32))[1]),
      ('refused', KL_STATEEXT_INVALID, 'done', hashlib.sha256(b'abc' + SEC).digest()))

src, dst, s28, d28, h, dh = Source(SEC), KeyDest(32), Source(SEC[:28]), KeyDest(32), outputting(), KeyDest(32)
check('shared secret -> a 32-byte `key` in _Ready_, length 40: the secret; a 28-byte secret -> a 32-byte key '
      '(GR40 item 5): destination _Invalid_, source untouched; SHA-256("abc") -> a key (GR40 item 1): source '
      '_Invalid_, key untouched', None,
      (kl_derive(dst, src, 40), dst.key, kl_derive(d28, s28, 32), d28.st, s28.st, kl_derive(dh, h, 32), h.st, dh.st),
      ('done', SEC, 'refused', KL_STATEEXT_INVALID, KL_STATE_HASH_OUTPUT, 'refused', KL_STATEEXT_INVALID, KL_STATE_READY))

section('Negative controls')
control('message words without bswap', digest('SHA-256', M_ABC, 'multi', bswap_words=False) != DIG_ABC)
control('klstart written in bits', digest('SHA-256', M2_64, 'interrupt', klstart_bits=True)
        != hashlib.sha256(M2_64).digest())

done()
