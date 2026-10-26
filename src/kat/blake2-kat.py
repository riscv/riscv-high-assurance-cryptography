#!/usr/bin/env pypy3.12
"""KAT: BLAKE2b / BLAKE2s Machines (RFC 7693) of Zkl-ISA-machines.adoc through hash_model.py; references hash_ref.py, hashlib."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hash_util import *
from hash_util import _do, _out
import hash_ref as R
import common
t0 = time.time()
FN = ('BLAKE2b', 'BLAKE2s')
HLIB = {'BLAKE2b': hashlib.blake2b, 'BLAKE2s': hashlib.blake2s}
def cfg(fn, nn=None, kk=0, sys_=None):
    """a Locker in Ready, parameters set by the Set_Aux_Value operation (caller key) or provisioned (system key)"""
    if sys_ is not None:
        L = Locker(fn, syskey=sys_, policy=1)
        if nn: L.setst('aux', 'B', nn)
        return L
    L = Locker(fn)
    if nn or kk: L.setst('aux', 'B', (nn or L.f.nnmax) | kk << 8)
    return L
def _ab(fn):
    L = cfg(fn); L.setst('absorb'); return L
def pad(fn, key): return key + bytes(R.B2[fn][2] - len(key))
section('RFC 7693 Appendix A and B: "abc", unkeyed')
RFC = {'BLAKE2b': 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
       'BLAKE2s': '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982'}
for fn in FN:
    check('%s reference "abc" = RFC 7693' % fn, R.blake2(fn, b'abc').hex() == RFC[fn] == HLIB[fn](b'abc').hexdigest())
    vector(fn, lambda fn=fn: cfg(fn), b'abc', 24, lambda m, n, fn=fn: R.blake2(fn, m), nlabel='RFC', plans=('multi', 'chunks', 'odd', 'export', 'last', 'last0'))
section('Digest, key and message lengths against the oracle')
for fn in FN:
    bs, nm = R.B2[fn][2], R.B2[fn][3]
    for nn in (1, 16, nm - 1, nm):
        for kk in (0, 1, nm // 2, nm):
            for n in (0, 1, bs - 1, bs, bs + 1, 2 * bs, 2 * bs + 5):
                if (nn, kk) not in ((1, 0), (16, 1), (nm, nm), (nm - 1, nm // 2)) and n not in (0, bs, bs + 1): continue
                m = msg_of(n); key = bytes((7 * i + 1) & 255 for i in range(kk)); full = pad(fn, key) + m if kk else m
                ref = lambda mm, nb, fn=fn, kk=kk, key=key, nn=nn: R.blake2(fn, mm[bs:] if kk else mm, key, nn)
                check('%s nn=%d kk=%d %d bytes: reference = hashlib' % (fn, nn, kk, n), R.blake2(fn, m, key, nn) == HLIB[fn](m, key=key, digest_size=nn).digest())
                vector(fn, lambda fn=fn, nn=nn, kk=kk: cfg(fn, nn, kk), full, 8 * len(full), ref, nlabel='nn=%d kk=%d' % (nn, kk), plans=('chunks', 'export', 'last', 'last0') if kk or n % 7 else PLANS)
    # system key
    for kk in (1, nm // 2, nm):
        sk = bytes((13 * i + 5) & 255 for i in range(kk))
        for n in (0, 1, bs - 1, bs, bs + 1, 3 * bs):
            m = msg_of(n)
            vector(fn, lambda fn=fn, sk=sk: cfg(fn, None, 0, sk), m, 8 * n, lambda mm, nb, fn=fn, sk=sk: R.blake2(fn, mm, sk), nlabel='system key kk=%d' % kk, plans=('multi', 'chunks', 'odd', 'export', 'last', 'last0'))
        vector(fn, lambda fn=fn, sk=sk: cfg(fn, 20, 0, sk), msg_of(77), 8 * 77, lambda mm, nb, fn=fn, sk=sk: R.blake2(fn, mm, sk, 20), nlabel='system key nn=20 kk=%d' % kk, plans=('chunks', 'last'))
section('BLAKE2 parameters, the Provisioning Input and Ready')
for fn in FN:
    f = Fn_ = Locker(fn).f; nm = f.nnmax
    L = Locker(fn); check('%s provisioned: nn = nn_max, kk = 0' % fn, (L.nn, L.kk) == (nm, 0))
    L = Locker(fn, syskey=b'k' * 5, policy=1); check('%s provisioned with system key: kk = key length' % fn, (L.nn, L.kk, L.st) == (nm, 5, 'Ready'))
    check('%s kk > kk_max (system key too long) -> invalid provisioning' % fn, raises(Locker, fn, syskey=bytes(nm + 1), policy=1, exc=Metadata))
    check('%s empty system key -> invalid' % fn, raises(Locker, fn, syskey=b'', policy=1, exc=Metadata))
    L = Locker(fn); L.setst('aux', 'B', 16 | 3 << 8); L.setst('absorb'); L.setst('ready'); check('%s Ready keeps nn, kk across Ready; h0 = IV0 ^ 0x01010000 ^ kk<<8 ^ nn' % fn, (L.nn, L.kk) == (16, 3) and (L.S & mask(f.w)) == R.B2IV[f.w][0] ^ 0x01010000 ^ (3 << 8) ^ 16)
    L = Locker(fn, syskey=b'k' * 5, policy=1); L.setst('aux', 'B', 9); check('%s system key: nn settable (Xs[15:8] = 0), kk stays' % fn, (L.nn, L.kk, L.st) == (9, 5, 'Ready'))
    for Xs, why in ((0, 'nn = 0'), (nm + 1, 'nn > nn_max'), (4 | (nm + 1) << 8, 'kk > kk_max'), (4 | 1 << 16, 'bit 16 set'), (4 | 1 << 31, 'bit 31 set')):
        check('%s Set_Aux_Value Xs=%#x (%s) -> Invalid' % (fn, Xs, why), inv(_do(Locker(fn), 'aux', 'B', Xs)))
    check('%s system key with Xs[15:8] != 0 -> Invalid' % fn, inv(_do(Locker(fn, syskey=b'k', policy=1), 'aux', 'B', 4 | 1 << 8)))
    check('%s Set_Aux_Value Form A -> Invalid' % fn, inv(_do(Locker(fn), 'aux', 'A', 0)))
    L = Locker(fn); L.setst('absorb'); check('%s Set_Aux_Value outside Ready -> Invalid' % fn, inv(_do(L, 'aux', 'B', 4)))
    for pol, ok in ((1, True), (0, False), (2, False), (3, False)):
        check('%s system key MachinePolicy=%d %s' % (fn, pol, 'accepted' if ok else 'invalid/unsupported Metadata'), ok == (not raises(Locker, fn, syskey=b'k', policy=pol, exc=Metadata)))
    check('%s MachinePolicy nonzero without system key: unsupported Metadata' % fn, raises(Locker, fn, policy=1, exc=Metadata))
    L = cfg(fn, None, 0, b'sec'); L.setst('absorb'); L.setst('output'); check('%s system key, MachinePolicy bit 0 enables Hash_Output' % fn, L.st == 'Output')
section('Messages ended in Hash_Absorb (Xs=0), Invalid outcomes')
for fn in FN:
    bs = R.B2[fn][2]
    for n in (0, 5, bs, bs + 3, 2 * bs):
        L = cfg(fn); L.setst('absorb'); run(L, [msg_of(n)]); L.setst('output')
        check('%s %d bytes ended by kl.setst Hash_Output from Hash_Absorb (block_base=%d held)' % (fn, n, L.bb if False else 0), out_all(L, R.B2[fn][3]) == HLIB[fn](msg_of(n)).digest())
    L = _ab(fn); L.exec('B', b'ab'); L.setst('last'); L.exec('B', b''); check('%s Xs=0 then an empty-window kl.exec -> Invalid (MR10, GR21)' % fn, inv(L))
    L = _ab(fn); L.exec('B', b'ab'); L.setst('last', 'B', 8); L.exec('B', b'c', 1); check('%s Xs=8, klstart=KLLEN/8: empty window, State kept' % fn, L.st == 'Last')
    L = cfg(fn, None, 3); L.setst('absorb'); L.setst('output'); check('%s kk != 0, no key block, empty message -> Invalid' % fn, inv(L))
    L = cfg(fn, None, 3); L.setst('absorb'); run(L, [pad(fn, b'abc')]); L.setst('output'); check('%s kk = 3, key block only (empty message): final key block' % fn, out_all(L, R.B2[fn][3]) == HLIB[fn](b'', key=b'abc').digest())
    L = cfg(fn, 8, 0); L.setst('absorb'); L.setst('output', 'B', 64); check('%s Output Xs > 8*nn... Xs=64 = 8*nn accepted' % fn, L.st == 'Output')
    L = cfg(fn, 8, 0); L.setst('absorb'); L.setst('output', 'B', 72); check('%s Output Xs=72 > t=8*nn -> Invalid' % fn, inv(L))
    L = cfg(fn, 8, 0); L.setst('absorb'); run(L, [b'abc']); L.setst('output'); o = L.exec('C', kllen=8 * 11); check('%s nn=8: Output of t bits, excess cleared, Success' % fn, o == HLIB[fn](b'abc', digest_size=8).digest() + bytes(3) and L.st == 'Success')
section('Serialized Content and interruption points of Hash_Absorb')
for fn in FN:
    f = Locker(fn).f; bs = f.b // 8
    L = cfg(fn, 24, 2); L.setst('absorb'); run(L, [msg_of(bs)]); fl = {n: v for n, v, _ in L.fields()}
    check('%s full block is held: block_base = b, cumul_len = b, nn/kk in Positions v, vi' % fn, (fl['block_base'], fl['cumul_len'], fl['nn'], fl['kk']) == (f.b, f.b, 24, 2))
    names = [n for n, _, _ in L.fields()]; check('%s Serialized Content fields end with nn, kk (16 bits each)' % fn, names[-2:] == ['nn', 'kk'])
    L = cfg(fn, None, 0, b'sec'); check('%s system key: SKID leads the Serialized Content, no key bytes' % fn, L.fields()[0][0] == 'SKID' and L.fields()[0][2] == 64)
    L.setst('absorb'); check('%s system key pending: cumul_len = 0 before the first byte' % fn, L.cum == 0)
    run(L, [b'x']); check('%s ... compressed by the instruction absorbing the first byte: cumul_len = b + 8' % fn, L.cum == f.b + 8)
    m = msg_of(3 * bs + 5)
    for cut in (0, 1, bs - 1, bs, bs + 1, 2 * bs):
        for sk in (None, b'secret'):
            L = cfg(fn, None, 0, sk); L.setst('absorb'); run(L, [m[:cut]]); L2 = copy.deepcopy(L); run(L2, [m[cut:]]); L2.setst('output')
            check('%s export/import after %d bytes%s' % (fn, cut, ', system key' if sk else ''), out_all(L2, f.nnmax) == (HLIB[fn](m, key=sk) if sk else HLIB[fn](m)).digest())
    L = cfg(fn); L.setst('absorb'); run(L, [msg_of(bs)]); L.exec('B', msg_of(2 * bs), 3 * 0 + 1); check('%s resumption klstart=1 with block_base = b (held) is an interruption point' % fn, L.st == 'Absorb')
    L = cfg(fn); L.setst('absorb'); run(L, [msg_of(7)]); L.exec('B', msg_of(40), 1); check('%s klstart != 0 with 0 < block_base < b -> Invalid' % fn, inv(L))
    L = cfg(fn); L.setst('absorb'); r = L.exec('B', msg_of(3 * bs), 0, halt=True)
    check('%s a halt leaves the full block held (block_base = b), klstart = %d' % (fn, bs), r == bs and L.bb == f.b)
    L.exec('B', msg_of(3 * bs), r); L.setst('output'); check('%s ... and resumes to the right digest' % fn, out_all(L, f.nnmax) == HLIB[fn](msg_of(3 * bs)).digest())
section('Final piece (Hash_Absorb_Last_Block), kl.derive, kl.clear')
for fn in FN:
    bs = R.B2[fn][2]
    check('%s final piece with a length not a multiple of 8 -> Invalid (MR11)' % fn, inv(_do(cfg(fn) if False else _ab(fn), 'last', 'B', 12)))
    for Lb in (8, bs * 8 - 8, bs * 8):
        for pre in (0, bs, 5):
            m = msg_of(pre + Lb // 8); L = _ab(fn); run(L, [m[:pre]]); L.setst('last', 'B', Lb); L.exec('B', m[pre:]); L.setst('output')
            check('%s %d bytes then final piece of %d bits (a final piece filling its block is held)' % (fn, pre, Lb), out_all(L, R.B2[fn][3]) == HLIB[fn](m).digest())
    for n in (1, 16, 33, bs, bs + 1, 2 * bs):
        sec = msg_of(n); L = cfg(fn, None, 0, b'k' * 4); L.setst('absorb'); ok = L.derive(sec); L.setst('output')
        check('%s system key, shared secret of %d bytes derived into Hash_Absorb as the first bytes' % (fn, n), ok and out_all(L, R.B2[fn][3]) == HLIB[fn](sec, key=b'k' * 4).digest())
    L = _ab(fn); L.setst('last', 'B', 8); check('%s derive not an endpoint in Hash_Absorb_Last_Block' % fn, not L.derive(b'a'))
    L = _ab(fn); L.exec('B', b'abc'); L.clear(); L.setst('output'); check('%s kl.clear then setst is a no-op' % fn, L.st == 'Inert')
    L = cfg(fn); L.setst('absorb'); L.exec('B', b'abc'); L.setst('ready'); L.setst('absorb'); L.exec('B', b'abc'); L.setst('output')
    check('%s Absorb -> Ready -> Absorb restarts the message' % fn, out_all(L, R.B2[fn][3]) == HLIB[fn](b'abc').digest())
section('Negative controls')
fn = 'BLAKE2s'; bs = 64
m = msg_of(bs); good = HLIB[fn](m).digest()
h = list(R.B2IV[32]); h[0] ^= 0x01010020
nofinal = R.blake2_F(fn, h, [int.from_bytes(m[i:i + 4], 'little') for i in range(0, 64, 4)], bs, False)
control('without hold-back a final full block compressed as non-final gives another digest', b''.join(x.to_bytes(4, 'little') for x in nofinal) != good)
control('a truncated full digest differs from the nn-byte digest', HLIB[fn](b'abc').digest()[:20] != HLIB[fn](b'abc', digest_size=20).digest())
control('a caller key absorbed without kk in the parameter block gives another digest', HLIB[fn](b'abc', key=b'k').digest() != R.blake2(fn, pad(fn, b'k') + b'abc'))
h2 = list(R.B2IV[32]); h2[0] ^= 0x01010120
syskeyblock = R.blake2_F(fn, h2, [int.from_bytes(pad(fn, b'k')[i:i + 4], 'little') for i in range(0, 64, 4)], 64, False)
control('empty message: the system key block compressed as non-final (on leaving Ready) differs from the final block', b''.join(x.to_bytes(4, 'little') for x in syskeyblock) != HLIB[fn](b'', key=b'k').digest())
info('%d checks, %.1fs' % (common.N_PASS + common.N_FAIL, time.time() - t0))
common.done()
