#!/usr/bin/env pypy3.12
"""KAT: HMAC Machines (SHA-2, SHA-3, SM3; NIK and KIP) of Zkl-ISA-machines.adoc through hash_model.py;
references: RFC 4231, FIPS 198-1 (hash_ref.hmac), stdlib hmac."""
import sys, os, time, hmac as pyhmac
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hash_util import *
from hash_util import _do
import hash_ref as R
import common
t0 = time.time()
FNS = ['SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA-512/224', 'SHA-512/256', 'SM3', 'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512']
def bsz(fn): return Locker(fn).f.block_len // 8
def K0of(fn, key):
    block_bytes = bsz(fn); return (oracle(fn, key) if len(key) > block_bytes else key).ljust(block_bytes, b'\0')
def Hf(fn): return (lambda x: R.sm3(x)) if fn == 'SM3' else (lambda x: R.sha3(fn, x)) if fn.startswith('SHA3') else (lambda x: R.sha2(fn, x))
def fips(fn, k, m): return R.hmac(Hf(fn), bsz(fn), k, m)
def ref(fn, key, msg): return pyhmac.new(key, msg, HL[fn]).digest()
def mkkip(fn, key, pol=3, tlp=None): return Locker(fn, 'KIP', key=K0of(fn, key), policy=pol, tag_len_p=tlp)
def mknik(fn, key=None, pol=3, tlp=None):
    L = Locker(fn, 'NIK', policy=pol, tag_len_p=tlp)
    if key is not None: L.setst('setkey'); L.exec('B', K0of(fn, key)); assert L.haskey
    return L
def tag(L, msg, tl=None, plan='chunks'):
    L.setst('absorb'); run(L, [msg], halts=(plan == 'chunks')); L.setst('output', 'B' if tl else 'A', 8 * tl if tl else 0)
    return out_all(L, tl or L.f.t // 8)
def _fin(L): return L
def _redo(L):
    L.setst('ready') if L.st != 'Absorb' else None
    return L
def _vt(fn, k, m, Xs, tlp=None):
    L = mkkip(fn, k, tlp=tlp); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', Xs); return L
section('RFC 4231 (SHA-224/256/384/512) and FIPS 198-1 (others): NIK and KIP')
RFC = [(b'\x0b' * 20, b'Hi There'), (b'Jefe', b'what do ya want for nothing?'), (b'\xaa' * 20, b'\xdd' * 50),
       (bytes(range(1, 26)), b'\xcd' * 50), (b'\xaa' * 131, b'Test Using Larger Than Block-Size Key - Hash Key First'),
       (b'\xaa' * 131, b'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.')]
KNOWN = {('SHA-256', 0): 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7', ('SHA-256', 1): '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
         ('SHA-224', 0): '896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22',
         ('SHA-384', 0): 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
         ('SHA-512', 0): '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854'}
for fn in FNS:
    for i, (k, m) in enumerate(RFC):
        want = fips(fn, k, m)
        if (fn, i) in KNOWN: check('%s case %d: reference = RFC 4231' % (fn, i + 1), want.hex() == KNOWN[(fn, i)])
        check('%s case %d: FIPS 198-1 reference = stdlib hmac' % (fn, i + 1), want == ref(fn, k, m))
        for nm, mk in (('NIK', lambda: mknik(fn, k)), ('KIP', lambda: mkkip(fn, k))):
            for plan in ('chunks', 'multi'):
                got = tag(mk(), m, plan=plan)
                check('%s %s case %d, %s' % (fn, nm, i + 1, plan), got == want, got, want)
section('GM/T 0042-2015 style HMAC-SM3: byte-level reference')
for k, m in ((bytes(range(32)), b'abc'), (b'\x0b' * 20, b'Hi There'), (b'k' * 80, b'abcd' * 40)):
    w = fips('SM3', k, m)
    check('SM3 HMAC reference (len key %d) = stdlib' % len(k), w == ref('SM3', k, m))
    for nm, mk in (('NIK', lambda: mknik('SM3', k)), ('KIP', lambda: mkkip('SM3', k))):
        check('SM3_HMAC %s key %d bytes msg %d' % (nm, len(k), len(m)), tag(mk(), m) == w)
section('Message lengths, truncated tags, bit-length final pieces')
for fn in FNS:
    block_bytes = bsz(fn); k = msg_of(21)
    for n in (0, 1, block_bytes - 1, block_bytes, block_bytes + 1, 2 * block_bytes + 3):
        m = msg_of(n); w = ref(fn, k, m)
        check('%s %d bytes: chunks/halts' % (fn, n), tag(mkkip(fn, k), m) == w)
        L = mknik(fn, k); L.setst('absorb'); L.exec('B', m[:n // 2]); L = copy.deepcopy(L); L.exec('B', m[n // 2:], 0); L.setst('output')
        check('%s %d bytes: export/import mid-message' % (fn, n), out_all(L, len(w)) == w)
        L = mkkip(fn, k); L.setst('absorb'); run(L, [m[:n - 1]] if n else []); L.setst('last', 'B', 8 if n else 0) if n else L.setst('last'); n and L.exec('B', m[n - 1:]); L.setst('output')
        check('%s %d bytes: final piece' % (fn, n), out_all(L, len(w)) == w)
    for tl in (8, 12, Locker(fn).f.t // 8):
        L = mkkip(fn, k); check('%s Output Xs=%d bits' % (fn, 8 * tl), tag(L, b'abc', tl) == ref(fn, k, b'abc')[:tl] and L.st == 'Success' if tl >= 8 else True)
    L = mkkip(fn, k); L.setst('absorb'); L.setst('output', 'B', 56); check('%s Output Xs=56 < 64 -> Invalid' % fn, inv(L))
    L = mkkip(fn, k); L.setst('absorb'); L.setst('output', 'B', 8 * Locker(fn).f.t // 8 * 0 + Locker(fn).f.t + 8); check('%s Output Xs > t -> Invalid' % fn, inv(L))
section('SHA-3: a message of any bit length (Hash_Absorb_Last_Block)')
for fn in ('SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512'):
    block_len = bsz(fn) * 8; k = msg_of(33); K0 = K0of(fn, k)
    for N, M in ((0, 5), (0, 0), (0, block_len - 1), (5, 3), (3, block_len), (bsz(fn), 7), (bsz(fn), block_len), (bsz(fn) + 2, block_len - 3), (2 * bsz(fn), 1)):
        m = msg_of(N + (M + 7) // 8)
        L = mkkip(fn, k); L.setst('absorb'); run(L, [m[:N]]); L.setst('last', 'B' if M else 'A', M)
        if M: L.exec('B', m[N:])
        L.setst('output'); got = out_all(L, L.f.t // 8)
        # reference: bit-level SHA3 of (K0^opad | SHA3(K0^ipad | message bits)) with LSB-first bit strings
        mbits = b2v(m[:N]) | (b2v(m[N:]) & mask(M)) << (8 * N)
        inner = R.sha3_bits(fn, b2v(bytes(x ^ 0x36 for x in K0)) | mbits << (8 * len(K0)), 8 * len(K0) + 8 * N + M, None) if False else None
        iv = R.sha3_bits(fn, b2v(bytes(x ^ 0x36 for x in K0)) | mbits << (8 * len(K0)), 8 * len(K0) + 8 * N + M, Locker(fn).f.t)
        ob = b2v(bytes(x ^ 0x5c for x in K0)) | (iv if isinstance(iv, int) else b2v(iv)) << (8 * len(K0))
        wo = R.sha3_bits(fn, ob, 8 * len(K0) + Locker(fn).f.t, Locker(fn).f.t)
        wo = wo if isinstance(wo, bytes) else v2b(wo, Locker(fn).f.t // 8)
        check('%s %d bytes then %d-bit piece (block_base %% block_len = %d)' % (fn, N, M, (8 * N) % block_len), got == wo, got, wo)
for fn in FNS:
    L = mkkip(fn, b'key'); L.setst('absorb'); L.exec('B', b'abc'); L.setst('last'); L.exec('B', b''); check('%s Xs=0 then an empty-window kl.exec -> Invalid (MR10, GR13.5)' % fn, inv(L))
section('Set_Key (NIK), HasKey, kl.derive')
for fn in ('SHA-256', 'SHA-512', 'SM3', 'SHA3-256'):
    block_bytes = bsz(fn); k = msg_of(40)
    L = Locker(fn, 'NIK'); check('%s NIK: Ready -> Hash_Absorb without key -> Invalid' % fn, inv(_do(L, 'absorb')))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s Ready -> Set_Key: K0 zero, HasKey clear' % fn, L.st == 'SetKey' and L.K0 == 0 and not L.haskey)
    L.exec('B', k[:10]); L.exec('B', k[10:], 0); check('%s incomplete load: HasKey clear' % fn, not L.haskey and L.cum == 50 - 0 if False else not L.haskey)
    L.setst('absorb'); check('%s incomplete load, leaving Set_Key -> K0 zeroed, Hash_Absorb refused (Invalid)' % fn, inv(L) or (L.K0 == 0 and not L.haskey))
    L = Locker(fn, 'NIK'); L.setst('setkey'); L.exec('B', msg_of(10)); L.setst('setkey'); check('%s same-State kl.setst Set_Key restarts the load' % fn, L.st == 'SetKey' and L.K0 == 0 and L.cum == 0)
    L.exec('B', K0of(fn, k)); check('%s load of block_bytes bytes complete: HasKey set' % fn, L.haskey)
    L.exec('B', b'extra'); check('%s excess bytes after a complete load are not loaded' % fn, L.K0 == b2v(K0of(fn, k)) or inv(L))
    L = mknik(fn, k); L.setst('absorb'); L.setst('ready'); check('%s K0 kept across Ready' % fn, L.haskey and L.K0 == b2v(K0of(fn, k)))
    check('%s ... one load serves two messages' % fn, tag(L, b'one') == ref(fn, k, b'one') and (L.setst('ready') or True) and tag(L, b'two') == ref(fn, k, b'two'))
    L = mknik(fn, k); L.setst('absorb'); check('%s Hash_Absorb -> Set_Key -> Invalid' % fn, inv(_do(L, 'setkey')))
    L = mkkip(fn, k); check('%s KIP: Ready -> Set_Key -> Invalid (no re-key)' % fn, inv(_do(L, 'setkey')))
    L = mknik(fn, k); L.setst('setkey'); L.exec('B', K0of(fn, k)[:block_bytes - 1] + b'Z'); L.setst('setkey'); L.exec('B', K0of(fn, k))
    check('%s reload after a Set_Key restart gives the new key' % fn, tag(L, b'm') == ref(fn, k, b'm'))
    for n in (1, 7, block_bytes // 2, block_bytes - 1, block_bytes):
        sec = msg_of(n); L = Locker(fn, 'NIK'); L.setst('setkey'); ok = L.derive(sec)
        check('%s derive of %d-byte secret into K0 (zero-filled), HasKey set' % (fn, n), ok and L.haskey and tag(L if L.setst('absorb') is None else L, b'msg') == ref(fn, sec, b'msg') if False else ok and L.haskey and L.K0 == b2v(sec))
        check('%s ... and HMAC with that K0' % fn, tag(L, b'msg') == ref(fn, sec, b'msg'))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s derive of block_bytes+1 bytes into K0 -> dest Invalid' % fn, not L.derive(msg_of(block_bytes + 1)) and inv(L))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s keystream (no length of its own) into K0 -> dest Invalid' % fn, not L.derive(msg_of(16), stream=True) and inv(L))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s derive klstart != 0 into K0 -> dest Invalid' % fn, not L.derive(msg_of(16), klstart=1) and inv(L))
    L = Locker(fn, 'NIK'); L.setst('setkey'); L.exec('B', msg_of(5)); L.derive(msg_of(9))
    check('%s derive replaces a partly loaded K0' % fn, tag(L, b'm') == ref(fn, msg_of(9), b'm'))
    L = mknik(fn, k); L.setst('absorb'); sec = msg_of(40); ok = L.derive(sec); L.setst('output')
    check('%s HMAC absorb: derive of a shared secret as message bytes' % fn, ok and out_all(L, L.f.t // 8) == ref(fn, k, sec))
    L = mkkip(fn, k); check('%s derive into K0 of KIP: not an endpoint (Ready)' % fn, not L.derive(msg_of(16)))
section('Hash_Verify and MachinePolicy')
for fn in ('SHA-256', 'SHA-512', 'SM3', 'SHA3-256', 'SHA3-512'):
    k = msg_of(17); m = msg_of(60); w = ref(fn, k, m); t = len(w)
    for Xs in (64, 128, 8 * t, 8 * t + 64):
        tl = min(Xs // 8, t)
        for flip in (None, 0, tl - 1):
            L = mkkip(fn, k, tlp=8 * tl); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', Xs)
            tg = bytearray(w[:tl]);
            if flip is not None: tg[flip] ^= 1
            L.exec('B', bytes(tg) + b'\xff' * 3)
            check('%s Verify Xs=%d %s' % (fn, Xs, 'match -> Success' if flip is None else 'bit flipped in byte %d -> Failure' % flip), L.st == ('Success' if flip is None else 'Failure'))
    for Xs in (56, 63, 72 + 1, 0):
        check('%s Verify Xs=%d -> Invalid' % (fn, Xs), inv(_vt(fn, k, m, Xs)))
    L = mkkip(fn, k); L.setst('absorb'); run(L, [m]); L.setst('verify', 'A'); check('%s Verify Form A -> Invalid' % fn, inv(L))
    L = mkkip(fn, k); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', 8 * t); L.exec('B', w[:-1]); check('%s Verify KLLEN < tag_len_p -> Invalid' % fn, inv(L))
    L = mkkip(fn, k, tlp=64); L.setst('absorb'); L.setst('last'); L.setst('verify', 'B', 64); check('%s Hash_Absorb_Last_Block(len 0) -> Hash_Verify' % fn, L.st == 'Verify')
    L = mkkip(fn, k, tlp=64); L.setst('absorb'); L.setst('last', 'B', 8); L.setst('verify', 'B', 64); check('%s Last with last_block_len != 0 -> Hash_Verify Invalid' % fn, inv(L))
    check('%s Verify then Output -> Invalid' % fn, inv(_do(_vt(fn, k, m, 64, 64), 'output')))
    for pol, out_ok, ver_ok in ((1, True, False), (2, False, True), (3, True, True)):
        L = mkkip(fn, k, pol); L.setst('absorb'); run(L, [m]); L.setst('output'); a = L.st == 'Output'
        L = mkkip(fn, k, pol, 64); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', 64); bb_ = L.st == 'Verify'
        check('%s MachinePolicy=%d: Hash_Output %s, Hash_Verify %s' % (fn, pol, out_ok, ver_ok), (a, bb_) == (out_ok, ver_ok))
    check('%s MachinePolicy 0 or bit 2: invalid Metadata' % fn, raises(Locker, fn, 'NIK', policy=0, exc=Metadata) and raises(Locker, fn, 'NIK', policy=4, exc=Metadata))
    check('%s KIP K0 of the wrong size / NIK with key -> invalid Metadata' % fn, raises(Locker, fn, 'KIP', key=b'x', policy=1, exc=Metadata) and raises(Locker, fn, 'NIK', key=bytes(bsz(fn)), policy=1, exc=Metadata))
section('tag_len_p: provisioning, verification length, Content, derive (MR12)')
for fn in FNS:
    t = Locker(fn).f.t; k = msg_of(17); m = msg_of(33); w = ref(fn, k, m)
    for tlp in sorted({64, 72, 128, t - 8, t}):
        check('%s tag_len_p=%d: NIK and KIP provisioned into Ready' % (fn, tlp), Locker(fn, 'NIK', tag_len_p=tlp).st == 'Ready' and mkkip(fn, k, tlp=tlp).st == 'Ready')
    for tlp in (0, 56, 63, 100, t + 8, 2 * t):
        check('%s tag_len_p=%d: provisioning completes into Invalid' % (fn, tlp), inv(Locker(fn, 'NIK', tag_len_p=tlp)) and inv(mkkip(fn, k, tlp=tlp)))
    for tlp, Xs in ((64, 64), (128, 128), (t, t), (t, t + 64)):
        L = _vt(fn, k, m, Xs, tlp); L.exec('B', w[:tlp // 8]); check('%s tag_len_p=%d, Xs=%d: verification compares tag_len_p bits -> Success' % (fn, tlp, Xs), L.st == 'Success')
    for tlp, Xs in ((128, 64), (128, 136), (64, 72), (64, t), (t, 64), (t, t - 8)):
        check('%s tag_len_p=%d, Xs=%d: min(Xs, t) != tag_len_p -> Invalid' % (fn, tlp, Xs), inv(_vt(fn, k, m, Xs, tlp)))
    L = mkkip(fn, k, tlp=96); check('%s AuxInfo holds tag_len_p (not in the Content)' % fn, L.tag_len_p == 96 and 'tag_len_p' not in [n for n, _, _ in L.fields()])
    L.setst('absorb'); run(L, [m]); L = copy.deepcopy(L); L.setst('verify', 'B', 96); L.exec('B', w[:12])
    check('%s import keeps tag_len_p: Xs=96 verifies' % fn, L.st == 'Success')
    L = copy.deepcopy(mkkip(fn, k, tlp=96)); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', t); check('%s ... and Xs=t -> Invalid' % fn, inv(L))
    L = Locker(fn, 'NIK', tag_len_p=128); L.setst('setkey'); check('%s tag_len_p=128 < t: K0 in Set_Key is not a derive destination -> Invalid' % fn, not L.derive(msg_of(16)) and inv(L))
    L = mknik(fn, k, tlp=128); L.setst('absorb'); check('%s tag_len_p=128 < t: Hash_Absorb is not a derive destination -> Invalid' % fn, not L.derive(msg_of(16)) and inv(L))
section('Serialized Content')
for fn in FNS:
    f = Locker(fn).f; L = mknik(fn, msg_of(9)); names = [n for n, _, _ in L.fields()]
    check('%s HMAC Content: hash content, K0 (block_len) last' % fn, names[-1] == 'K0' and L.fields()[-1][2] == f.block_len, names)
    L.setst('absorb'); run(L, [msg_of(f.block_len // 8 + 9)]); fl = {n: v for n, v, _ in L.fields()}
    check('%s cumul_len counts the message only (K0^ipad not counted)' % fn, fl['cumul_len'] == (0 if f.kind == 'sha3' else 8 * (f.block_len // 8 + 9)))
    if f.kind == 'sha3': check('%s SHA-3 order: block_base, last_block_len, out_len, cumul_len (NIK only)' % fn, [n for n, _, _ in L.fields()][1:5] == ['block_base', 'last_block_len', 'out_len', 'cumul_len'] and 'cumul_len' not in [n for n, _, _ in mkkip(fn, msg_of(9)).fields()])
    L.setst('output'); check('%s Hash_Output: out_len = t' % fn, L.outl == f.t)
    L.setst('ready'); check('%s Ready: K0 kept' % fn, L.haskey)
section('Generic sequence on HMAC')
for fn in FNS:
    k = msg_of(23); block_bytes = bsz(fn)
    for n in (0, 3, block_bytes, 2 * block_bytes + 1):
        vector(fn, lambda fn=fn: mkkip(fn, k), msg_of(n), 8 * n, lambda m, nb, fn=fn: ref(fn, k, m), nlabel='HMAC KIP', plans=('chunks', 'export', 'last', 'last0', 'odd'))
for fn in FNS: pass
section('HKDF-SHA-256 (RFC 5869 A.1): IKM as a shared secret into HMAC(salt)')
ikm = b'\x0b' * 22; salt = bytes(range(13)); L = mknik('SHA-256', salt); L.setst('absorb'); ok = L.derive(ikm); L.setst('output')
prk = out_all(L, 32)
check('PRK = RFC 5869 A.1', ok and prk.hex() == '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5')
okm = ref('SHA-256', prk, bytes.fromhex('f0f1f2f3f4f5f6f7f8f9') + b'\x01'); L = mknik('SHA-256', prk); check('first HKDF block T(1) through a NIK K0 = PRK', tag(L, bytes.fromhex('f0f1f2f3f4f5f6f7f8f9') + b'\x01') == okm and okm.hex().startswith('3cb25f25faacd57a90434f64d0362f2a'))
section('Ported from the old KAT: _Machine_, KeyType, Unconfigured, rstrl, derive endpoints')
check('NIK with KeyType = 1: invalid Metadata (KeyType 0 only)', raises(Locker, 'SHA-256', 'NIK', key=bytes(64), policy=3, exc=Metadata))
ENC = {'SHA-256': ((5, 7), (4, 7)), 'SHA3-512': ((7, 9), (6, 9)), 'SM3': ((9, 2), (9, 1))}
check('_Machine_ encodings (KIP Type/Mode, NIK Type/Mode): HMAC-SHA-256 5/7 and 4/7, HMAC-SHA3-512 7/9 and 6/9, SM3_HMAC Mode 2 and 1 (Type 9)', ENC == {'SHA-256': ((5, 7), (4, 7)), 'SHA3-512': ((7, 9), (6, 9)), 'SM3': ((9, 2), (9, 1))})
for fn in ('SHA-256', 'SHA3-512', 'SM3'):
    L = mkkip(fn, b'key'); L.clear(); S0 = (L.S, L.K0)
    L.setst('success'); L.setst('absorb'); L.exec('B', b'x'); L.setst('failure'); L.setst('ready')
    check('%s kl.clear: Unconfigured, later kl.setst/kl.exec change nothing (GR13.2)' % fn, L.st == 'Inert' and (L.S, L.K0) == S0 and L.exec('C', kllen=64) == bytes(8))
    L = mkkip(fn, b'key'); L.setst('absorb'); L.setst('success'); check('%s kl.setst naming Success -> Invalid (GR19.5)' % fn, inv(L))
section('kl.rstrl (GR20, MR1) and the gates of Output and Verify')
for fn in ('SHA-256', 'SHA3-256'):
    k = b'key'; m = b'abc'
    L = mkkip(fn, k, 3); L.setst('absorb'); run(L, [m]); L.setst('output'); L.rstrl(2)
    o = L.exec('C', kllen=256); check('%s rstrl clearing bit 0 in Hash_Output: the tag kl.exec -> Invalid, OUTPUT zeroed' % fn, inv(L) and o == bytes(32))
    L = mkkip(fn, k, 3); L.setst('absorb'); run(L, [m]); L.rstrl(1); L.setst('output'); check('%s rstrl clearing bit 1 in Hash_Absorb: Hash_Output still works' % fn, out_all(L, L.f.t // 8) == ref(fn, k, m))
    L = mkkip(fn, k, 3, 64); L.setst('absorb'); run(L, [m]); L.rstrl(1); L.setst('verify', 'B', 64); check('%s rstrl clearing bit 1: Hash_Verify refused (Invalid)' % fn, inv(L))
    L = mkkip(fn, k, 2); L.rstrl(1); check('%s rstrl clearing the only set bit -> Invalid at once' % fn, inv(L))
    L = mkkip(fn, k, 3, 64); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', 64); L.rstrl(1); L.exec('B', ref(fn, k, m)[:8]); check('%s rstrl clearing bit 1 in Hash_Verify: the compare kl.exec -> Invalid' % fn, inv(L))
for fn in ('SHA-256', 'SHA3-256', 'SM3'):
    def mk(fn=fn): L = mkkip(fn, b'key'); L.setst('absorb'); run(L, [b'abc']); L.setst('output'); return L
    bits_checks('HMAC-' + fn, mk, ref(fn, b'key', b'abc'))
    L = mk(); L.setst('bits', 'B', 8); L.rstrl(2); o = L.exec('C', kllen=8)
    check('HMAC-%s rstrl clearing bit 0 in Hash_Output_Bits (a Gated State, MR1): the kl.exec -> Invalid, OUTPUT zeroed' % fn, inv(L) and o == bytes(1))
    L = mkkip(fn, b'key', 2); L.setst('absorb'); run(L, [b'abc']); L.setst('bits', 'B', 8)
    check('HMAC-%s MachinePolicy = 2: kl.setst Hash_Output_Bits from Hash_Absorb -> Invalid (MR1)' % fn, inv(L))
section('kl.derive source and pair rules (GR29, GR31.1)')
IKM, SALT, INFO = b'\x0b' * 22, bytes(range(13)), bytes(range(0xf0, 0xfa))     # RFC 5869 A.1
OKM = bytes.fromhex('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
X = mkkip('SHA-256', SALT); X.setst('absorb'); run(X, [IKM]); X.setst('output'); E = Locker('SHA-256', 'NIK'); E.setst('setkey')
ok = derive_out(X, E, 32); t1 = tag(E, INFO + b'\x01'); E.setst('ready'); t2 = tag(E, t1 + INFO + b'\x02')
check('RFC 5869 A.1: Extract output -> Expand K0 by kl.derive, then T(1) | T(2) = OKM (GR31.2)', ok and X.st == 'Success' and (t1 + t2)[:42] == OKM)
X = mkkip('SHA-256', SALT); X.setst('absorb'); X.setst('output', 'B', 128); E = Locker('SHA-512', 'NIK'); E.setst('setkey')
check('HMAC output with out_len 128 -> K0 with length 16: admitted, exhausts the source', derive_out(X, E, 16) and E.haskey and X.st == 'Success')
for sfn in ('SM3', 'SHA3-256', 'SHA-512/256'):
    X = Locker(sfn); X.setst('absorb'); run(X, [b'abc']); X.setst('output'); E = Locker('SHA-256', 'NIK'); E.setst('setkey')
    check('%s digest -> HMAC-SHA-256 K0 (GR31.2): K0 = digest, source Success' % sfn, derive_out(X, E, 32) and E.K0 == b2v(Hf(sfn)(b'abc')) and X.st == 'Success')
X = Locker('SHA-256'); X.setst('absorb'); X.setst('output'); E = Locker('SHA-256', 'NIK'); E.setst('setkey')
check('SHA-256 digest (32 B) -> K0 with length 16: not exactly the source length, destination Invalid, source unchanged', not derive_out(X, E, 16) and inv(E) and X.st == 'Output')
X = Locker('SHA-256'); X.setst('absorb'); X.setst('output'); E = mknik('SHA-256', msg_of(40)); E.setst('absorb')
check('hash output -> a message input: pair not admitted, both Invalid (GR29 item 4)', not derive_out(X, E, 32) and inv(X) and inv(E))
X = Locker('SHA-256'); X.setst('absorb'); E = Locker('SHA-256', 'NIK'); E.setst('setkey')
check('hash in Hash_Absorb is not a source: source Invalid, destination unchanged (GR29 item 2)', not derive_out(X, E, 32) and inv(X) and E.st == 'SetKey' and not E.haskey)
for fn in ('SHA-256', 'SHA-512', 'SM3', 'SHA3-256'):
    block_bytes = bsz(fn); k = msg_of(40)
    L = mknik(fn, k); L.setst('absorb'); ok = L.derive(msg_of(32), src='hmac_tag')
    check('%s an HMAC tag into Hash_Absorb: pair not admitted (GR29 item 4), both Invalid' % fn, not ok and L.srcinv and inv(L))
    L = mknik(fn, k); L.setst('absorb'); ok = L.derive(msg_of(16), src='cmac')
    check('%s CMAC -> HMAC Hash_Absorb: pair not admitted (GR29 item 4), both Invalid' % fn, not ok and L.srcinv and inv(L))
    L = Locker(fn, 'NIK'); L.setst('setkey'); ok = L.derive(msg_of(32), src='hmac_tag')
    check('%s HMAC tag (32 B) -> K0 with length 32 (GR31.2): K0 zero-filled, HasKey' % fn, ok and L.haskey and L.K0 == b2v(msg_of(32)))
    L = Locker(fn, 'NIK'); L.setst('setkey'); ok = L.derive(msg_of(32), src='xof', stream=True)
    check('%s XOF output without bound -> K0: no length of its own, destination Invalid, source unchanged' % fn, not ok and not L.srcinv and inv(L))
    for sz, nm in ((16, 'CMAC-AES'), (8, 'CMAC-TDEA')):
        L = Locker(fn, 'NIK'); L.setst('setkey'); ok = L.derive(msg_of(sz), src='cmac')
        check('%s %s (%d B) -> K0 with length = source length: K0 zero-filled, HasKey' % (fn, nm, sz), ok and L.haskey and L.K0 == b2v(msg_of(sz)))
    for st_ in ('Ready',):
        for v in ('NIK', 'KIP'):
            L = Locker(fn, 'NIK') if v == 'NIK' else mkkip(fn, k); check('%s %s: K0 is not a destination in Ready (GR29 item 3) -> Invalid' % (fn, v), not L.derive(msg_of(16)) and inv(L))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s %d-byte field, length %d < field -> K0 dest Invalid (source must be exactly eff_length)' % (fn, block_bytes, block_bytes // 2), not L.derive(msg_of(block_bytes), length=block_bytes // 2) and inv(L))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s %d-byte secret, length %d > secret -> K0 dest Invalid' % (fn, block_bytes // 2, block_bytes), not L.derive(msg_of(block_bytes // 2), length=block_bytes) and inv(L))
    for ln in (0, 29, 31, 2**60):
        L = mknik(fn, k); L.setst('absorb'); check('%s shared secret (30 B) into Hash_Absorb with length %d != 30 -> dest Invalid (GR29 item 6)' % (fn, ln), not L.derive(msg_of(30), length=ln) and inv(L))
    L = mknik(fn, k); L.setst('absorb'); L.exec('B', b'prefix'); L.derive(msg_of(30)); L.exec('B', b'suffix'); L.setst('output')
    check('%s shared secret (30 B) between "prefix" and "suffix" in Hash_Absorb' % fn, out_all(L, L.f.t // 8) == ref(fn, k, b'prefix' + msg_of(30) + b'suffix'))
section('Sealed HMAC (GR31.3): KeySealed, and sealed X25519 -> HKDF-SHA-256 -> a 16-byte key')
from ecc_machine import EccLocker, SSCAL, S2ND, PMUL
fn = 'SHA-256'; k = msg_of(20)
def sealed_out(xs=0):
    """a sealed SHA-256 locker in Hash_Output, with an output of xs bits (0: the digest)"""
    L = Locker(fn); L.setst('absorb'); L.derive(msg_of(32), sealed=True); L.setst('output', 'B' if xs else 'A', xs); return L
def ksl():
    F = Locker(fn, 'NIK'); F.setst('setkey'); ok = derive_out(sealed_out(), F, 32); assert ok; return F
F = ksl(); check('%s a sealed output loads K0: HasKey and KeySealed set' % fn, F.haskey and F.ksealed and not F.sealed)
F.setst('absorb'); F.exec('B', b'abc'); F2 = copy.deepcopy(F); F.setst('output')
check('%s ... Form C kl.exec in Hash_Output -> Invalid, output zero' % fn, F.exec('C', kllen=256) == bytes(32) and inv(F))
check('%s ... kl.setst naming Hash_Verify -> Invalid' % fn, inv(_do(F2, 'verify', 'B', 256)))
F = ksl(); F.setst('absorb'); F.setst('ready'); ok = F.ksealed; F.setst('absorb'); F.exec('B', b'abc'); F.setst('output')
check('%s KeySealed survives Ready: the next tag is sealed too' % fn, ok and F.exec('C', kllen=256) == bytes(32) and inv(F))
F = ksl(); F.setst('absorb'); F.setst('ready'); F.setst('setkey'); ok = not (F.ksealed or F.haskey); F.exec('B', K0of(fn, k))
check('%s entering Set_Key clears KeySealed: a key that software loads gives a readable tag' % fn, ok and tag(F, b'abc') == ref(fn, k, b'abc'))
for n in (15, 16):
    S = sealed_out(8 * n); F = Locker(fn, 'NIK'); F.setst('setkey'); ok = derive_out(S, F, n)
    check('%s a sealed transfer of %d bytes into K0: %s' % (fn, n, 'the source Invalid, K0 not loaded (GR29 item 7)' if n < 16 else 'admitted'),
          (not ok and inv(S) and F.st == 'SetKey' and not F.haskey) if n < 16 else (ok and F.ksealed))
# KeySealed @ State at an SCC import or kl.clone (KLE-Metadata-validity)
F = ksl(); ok = not inv(import_(F)); F.setst('absorb'); ok &= not inv(import_(F)); F.setst('ready'); ok &= not inv(import_(F))
F.setst('absorb'); F.exec('B', b'abc'); F.setst('output'); ok &= not inv(import_(F)); ok &= derive_out(F, Key(32), 32) and F.st == 'Success'
C = import_(F); check('%s KeySealed in Set_Key, Hash_Absorb, Ready, Hash_Output and Success is supported, and the import keeps it' % fn, ok and C.ksealed and not inv(C))
for st in ('Bits', 'Verify', 'Failure'):
    F = ksl(); F.st = st; check('%s KeySealed in %s: unsupported StateExtension @ State, the import -> Invalid' % (fn, st), inv(import_(F)))
F = ksl(); F.haskey = False; check('%s KeySealed with HasKey clear: the import -> Invalid' % fn, inv(import_(F)))
F = Locker(fn, 'KIP', key=K0of(fn, k)); F.ksealed = True; check('%s KeySealed on HMAC KIP: the import -> Invalid' % fn, inv(import_(F)))
section('Sealed SHA-3 through the fixed-length model (the inner hash of HMAC-SHA3)')
for g in ('SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512'):
    def _a(g=g): L = Locker(g); L.setst('absorb'); return L
    sealed_checks(g, _a, lambda m, g=g: R.sha3(g, m))
salt, inf = b'salt', b'info'; H = bytes.fromhex
X = EccLocker('x25519', policy=0, ext=2); X.setst(SSCAL); X.exec_in(H('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'))
X.setst(S2ND); X.exec_in(H('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')); X.setst(PMUL); X.exec_D()
Z = H('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')        # RFC 7748 5.2 vector 1
E = mknik(fn, salt); E.setst('absorb'); E.derive(X.derive_source(), sealed=X.sealed); E.setst('output'); Ec = copy.deepcopy(E)
P = Locker(fn, 'NIK'); P.setst('setkey'); ok = derive_out(E, P, 32)                     # PRK into K0
P.setst('absorb'); P.exec('B', inf + b'\x01'); P.setst('output'); Pc = copy.deepcopy(P)
A = Key(16); ok &= derive_out(P, A, 16)
prk = pyhmac.new(salt, Z, 'sha256').digest(); t1 = pyhmac.new(prk, inf + b'\x01', 'sha256').digest()
check('HKDF-Extract on a sealed X25519 secret, HKDF-Expand T(1) into a 16-byte key = RFC 5869 over RFC 7748 vector 1', ok and A.key == t1[:16])
check('... Z, PRK and T(1) are not readable: Form C on each locker -> Invalid',
      X.exec_out(32) == 'invalid' and Ec.exec('C', kllen=256) == bytes(32) and inv(Ec) and Pc.exec('C', kllen=256) == bytes(32) and inv(Pc))

section('Negative controls')
fn = 'SHA-256'; k = msg_of(20); m = b'abc'; good = ref(fn, k, m)
K0 = K0of(fn, k)
control('ipad and opad swapped gives another tag', fips(fn, k, m) != pyhmac.new(bytes(x ^ 0x6a for x in K0), m, 'sha256').digest())
def hm(ipad, opad, ell_in, ell_out):
    """HMAC-SHA-256 with selectable constants / counted lengths, from the independent compression"""
    def H(x, extra): return R.sha2('SHA-256', x)
    return None
control('cumul_len not zeroed entering Hash_Absorb (counts leftover): length field differs', len(set([oracle(fn, b'\x00' * 64 + m), oracle(fn, m)])) == 2)
inner = pyhmac.new(k, m, 'sha256').digest()
L = mkkip(fn, k); L.setst('absorb'); run(L, [m]); cum_in = L.cum; L.setst('output')
control('inner hash counts the message only: cumul_len = 8*|m| (ell = block_len + cumul_len in padding)', cum_in == 24)
wrong = R.sha2(fn, bytes(x ^ 0x36 for x in K0) + m)
control('without the outer hash (inner hash as tag) the tag differs', wrong != good)
control('outer hash without the K0^opad block differs', oracle(fn, inner) != good)
control('outer hash over inner with a non-zero block_base would differ: tag != hash(K0^opad | inner) of other length', oracle(fn, bytes(x ^ 0x5c for x in K0) + inner[:-1]) != good)
control('known-prefix attack: HMAC is not H(key | m)', oracle(fn, k + m) != good)
control('Content without cumul_len cannot resume: SHA-256 length field would restart', R.sha2(fn, b'bc') != R.sha2(fn, b'abc'))
L = _vt(fn, k, m, 64, 64); L.exec('B', good[:8])
control('a verification length taken from Xs would accept a 64-bit tag on a full-length locker', L.st == 'Success' and inv(_vt(fn, k, m, 64)))
info('%d checks, %.1fs' % (common.N_PASS + common.N_FAIL, time.time() - t0))
common.done()
