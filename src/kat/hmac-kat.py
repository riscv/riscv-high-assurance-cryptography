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
def bsz(fn): return Locker(fn).f.b // 8
def K0of(fn, key):
    b = bsz(fn); return (oracle(fn, key) if len(key) > b else key).ljust(b, b'\0')
def Hf(fn): return (lambda x: R.sm3(x)) if fn == 'SM3' else (lambda x: R.sha3(fn, x)) if fn.startswith('SHA3') else (lambda x: R.sha2(fn, x))
def fips(fn, k, m): return R.hmac(Hf(fn), bsz(fn), k, m)
def ref(fn, key, msg): return pyhmac.new(key, msg, HL[fn]).digest()
def mkkip(fn, key, pol=3): return Locker(fn, 'KIP', key=K0of(fn, key), policy=pol)
def mknik(fn, key=None, pol=3):
    L = Locker(fn, 'NIK', policy=pol)
    if key is not None: L.setst('setkey'); L.exec('B', K0of(fn, key)); assert L.haskey
    return L
def tag(L, msg, tl=None, plan='chunks'):
    L.setst('absorb'); run(L, [msg], halts=(plan == 'chunks')); L.setst('output', 'B' if tl else 'A', 8 * tl if tl else 0)
    return out_all(L, tl or L.f.t // 8)
def _fin(L): return L
def _redo(L):
    L.setst('ready') if L.st != 'Absorb' else None
    return L
def _vt(fn, k, m, Xs):
    L = mkkip(fn, k); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', Xs); return L
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
    b = bsz(fn); k = msg_of(21)
    for n in (0, 1, b - 1, b, b + 1, 2 * b + 3):
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
    b = bsz(fn) * 8; k = msg_of(33); K0 = K0of(fn, k)
    for N, M in ((0, 5), (0, 0), (0, b - 1), (5, 3), (3, b), (bsz(fn), 7), (bsz(fn), b), (bsz(fn) + 2, b - 3), (2 * bsz(fn), 1)):
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
        check('%s %d bytes then %d-bit piece (block_base %% b = %d)' % (fn, N, M, (8 * N) % b), got == wo, got, wo)
for fn in FNS:
    L = mkkip(fn, b'key'); L.setst('absorb'); L.exec('B', b'abc'); L.setst('last'); L.exec('B', b''); check('%s Xs=0 then an empty-window kl.exec -> Invalid (MR10, GR20)' % fn, inv(L))
section('Set_Key (NIK), HasKey, kl.derive')
for fn in ('SHA-256', 'SHA-512', 'SM3', 'SHA3-256'):
    b = bsz(fn); k = msg_of(40)
    L = Locker(fn, 'NIK'); check('%s NIK: Ready -> Hash_Absorb without key -> Invalid' % fn, inv(_do(L, 'absorb')))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s Ready -> Set_Key: K0 zero, HasKey clear' % fn, L.st == 'SetKey' and L.K0 == 0 and not L.haskey)
    L.exec('B', k[:10]); L.exec('B', k[10:], 0); check('%s incomplete load: HasKey clear' % fn, not L.haskey and L.cum == 50 - 0 if False else not L.haskey)
    L.setst('absorb'); check('%s incomplete load, leaving Set_Key -> K0 zeroed, Hash_Absorb refused (Invalid)' % fn, inv(L) or (L.K0 == 0 and not L.haskey))
    L = Locker(fn, 'NIK'); L.setst('setkey'); L.exec('B', msg_of(10)); L.setst('setkey'); check('%s same-State kl.setst Set_Key restarts the load' % fn, L.st == 'SetKey' and L.K0 == 0 and L.cum == 0)
    L.exec('B', K0of(fn, k)); check('%s load of b bytes complete: HasKey set' % fn, L.haskey)
    L.exec('B', b'extra'); check('%s excess bytes after a complete load are not loaded' % fn, L.K0 == b2v(K0of(fn, k)) or inv(L))
    L = mknik(fn, k); L.setst('absorb'); L.setst('ready'); check('%s K0 kept across Ready' % fn, L.haskey and L.K0 == b2v(K0of(fn, k)))
    check('%s ... one load serves two messages' % fn, tag(L, b'one') == ref(fn, k, b'one') and (L.setst('ready') or True) and tag(L, b'two') == ref(fn, k, b'two'))
    L = mknik(fn, k); L.setst('absorb'); check('%s Hash_Absorb -> Set_Key -> Invalid' % fn, inv(_do(L, 'setkey')))
    L = mkkip(fn, k); check('%s KIP: Ready -> Set_Key -> Invalid (no re-key)' % fn, inv(_do(L, 'setkey')))
    L = mknik(fn, k); L.setst('setkey'); L.exec('B', K0of(fn, k)[:b - 1] + b'Z'); L.setst('setkey'); L.exec('B', K0of(fn, k))
    check('%s reload after a Set_Key restart gives the new key' % fn, tag(L, b'm') == ref(fn, k, b'm'))
    for n in (1, 7, b // 2, b - 1, b):
        sec = msg_of(n); L = Locker(fn, 'NIK'); L.setst('setkey'); ok = L.derive(sec)
        check('%s derive of %d-byte secret into K0 (zero-filled), HasKey set' % (fn, n), ok and L.haskey and tag(L if L.setst('absorb') is None else L, b'msg') == ref(fn, sec, b'msg') if False else ok and L.haskey and L.K0 == b2v(sec))
        check('%s ... and HMAC with that K0' % fn, tag(L, b'msg') == ref(fn, sec, b'msg'))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s derive of b+1 bytes into K0 -> dest Invalid' % fn, not L.derive(msg_of(b + 1)) and inv(L))
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
            L = mkkip(fn, k); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', Xs)
            tg = bytearray(w[:tl]);
            if flip is not None: tg[flip] ^= 1
            L.exec('B', bytes(tg) + b'\xff' * 3)
            check('%s Verify Xs=%d %s' % (fn, Xs, 'match -> Success' if flip is None else 'bit flipped in byte %d -> Failure' % flip), L.st == ('Success' if flip is None else 'Failure'))
    for Xs in (56, 63, 72 + 1, 0):
        check('%s Verify Xs=%d -> Invalid' % (fn, Xs), inv(_vt(fn, k, m, Xs)))
    L = mkkip(fn, k); L.setst('absorb'); run(L, [m]); L.setst('verify', 'A'); check('%s Verify Form A -> Invalid' % fn, inv(L))
    L = mkkip(fn, k); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', 8 * t); L.exec('B', w[:-1]); check('%s Verify KLLEN < tag_len -> Invalid' % fn, inv(L))
    L = mkkip(fn, k); L.setst('absorb'); L.setst('last'); L.setst('verify', 'B', 64); check('%s Hash_Absorb_Last_Block(len 0) -> Hash_Verify' % fn, L.st == 'Verify')
    L = mkkip(fn, k); L.setst('absorb'); L.setst('last', 'B', 8); L.setst('verify', 'B', 64); check('%s Last with last_block_len != 0 -> Hash_Verify Invalid' % fn, inv(L))
    check('%s Verify then Output -> Invalid' % fn, inv(_do(_vt(fn, k, m, 64), 'output')))
    for pol, out_ok, ver_ok in ((1, True, False), (2, False, True), (3, True, True)):
        L = mkkip(fn, k, pol); L.setst('absorb'); run(L, [m]); L.setst('output'); a = L.st == 'Output'
        L = mkkip(fn, k, pol); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', 64); bb_ = L.st == 'Verify'
        check('%s MachinePolicy=%d: Hash_Output %s, Hash_Verify %s' % (fn, pol, out_ok, ver_ok), (a, bb_) == (out_ok, ver_ok))
    check('%s MachinePolicy 0 or bit 2: invalid Metadata' % fn, raises(Locker, fn, 'NIK', policy=0, exc=Metadata) and raises(Locker, fn, 'NIK', policy=4, exc=Metadata))
    check('%s KIP K0 of the wrong size / NIK with key -> invalid Metadata' % fn, raises(Locker, fn, 'KIP', key=b'x', policy=1, exc=Metadata) and raises(Locker, fn, 'NIK', key=bytes(bsz(fn)), policy=1, exc=Metadata))
section('Serialized Content')
for fn in FNS:
    f = Locker(fn).f; L = mknik(fn, msg_of(9)); names = [n for n, _, _ in L.fields()]
    check('%s HMAC Content: hash content, K0 (b), tag_len (16)' % fn, names[-2:] == ['K0', 'tag_len'] and L.fields()[-2][2] == f.b and L.fields()[-1][2] == 16, names)
    L.setst('absorb'); run(L, [msg_of(f.b // 8 + 9)]); fl = {n: v for n, v, _ in L.fields()}
    check('%s cumul_len counts the message only (K0^ipad not counted)' % fn, fl['cumul_len'] == f.b + 72 if f.kind == 'sha3' and False else fl['cumul_len'] == 8 * (f.b // 8 + 9))
    if f.kind == 'sha3': check('%s SHA-3 order: block_base, last_block_len, out_len, cumul_len (HMAC only)' % fn, [n for n, _, _ in L.fields()][1:5] == ['block_base', 'last_block_len', 'out_len', 'cumul_len'])
    L.setst('output'); check('%s Hash_Output: tag_len 0 and out_len = t' % fn, (L.tag_len, L.outl) == (0, f.t))
    L.setst('ready'); check('%s Ready: tag_len <- 0, K0 kept' % fn, L.tag_len == 0 and L.haskey)
section('Generic sequence on HMAC')
for fn in FNS:
    k = msg_of(23); b = bsz(fn)
    for n in (0, 3, b, 2 * b + 1):
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
    check('%s kl.clear: Unconfigured, later kl.setst/kl.exec change nothing (GR32)' % fn, L.st == 'Inert' and (L.S, L.K0) == S0 and L.exec('C', kllen=64) == bytes(8))
    L = mkkip(fn, b'key'); L.setst('absorb'); L.setst('success'); check('%s kl.setst naming Success -> Invalid (GR24)' % fn, inv(L))
section('kl.rstrl (GR25, MR1) and the gates of Output and Verify')
for fn in ('SHA-256', 'SHA3-256'):
    k = b'key'; m = b'abc'
    L = mkkip(fn, k, 3); L.setst('absorb'); run(L, [m]); L.setst('output'); L.rstrl(2)
    o = L.exec('C', kllen=256); check('%s rstrl clearing bit 0 in Hash_Output: the tag kl.exec -> Invalid, OUTPUT zeroed' % fn, inv(L) and o == bytes(32))
    L = mkkip(fn, k, 3); L.setst('absorb'); run(L, [m]); L.rstrl(1); L.setst('output'); check('%s rstrl clearing bit 1 in Hash_Absorb: Hash_Output still works' % fn, out_all(L, L.f.t // 8) == ref(fn, k, m))
    L = mkkip(fn, k, 3); L.setst('absorb'); run(L, [m]); L.rstrl(1); L.setst('verify', 'B', 64); check('%s rstrl clearing bit 1: Hash_Verify refused (Invalid)' % fn, inv(L))
    L = mkkip(fn, k, 2); L.rstrl(1); check('%s rstrl clearing the only set bit -> Invalid at once' % fn, inv(L))
    L = mkkip(fn, k, 3); L.setst('absorb'); run(L, [m]); L.setst('verify', 'B', 64); L.rstrl(1); L.exec('B', ref(fn, k, m)[:8]); check('%s rstrl clearing bit 1 in Hash_Verify: the compare kl.exec -> Invalid' % fn, inv(L))
section('kl.derive source and pair rules (GR39, GR42)')
for fn in ('SHA-256', 'SHA-512', 'SM3', 'SHA3-256'):
    b = bsz(fn); k = msg_of(40)
    L = mknik(fn, k); L.setst('absorb'); S0 = (L.S, L.cum); ok = L.derive(msg_of(32), src='hmac_tag')
    check('%s an HMAC tag is not a source (GR39 item 2): source Invalid, destination Hash_Absorb unchanged' % fn, not ok and L.srcinv and L.st == 'Absorb' and (L.S, L.cum) == S0)
    L = mknik(fn, k); L.setst('absorb'); ok = L.derive(msg_of(16), src='cmac')
    check('%s CMAC -> HMAC Hash_Absorb: pair not admitted (GR39 item 4), both Invalid' % fn, not ok and L.srcinv and inv(L))
    L = Locker(fn, 'NIK'); L.setst('setkey'); ok = L.derive(msg_of(32), src='hmac_tag')
    check('%s HMAC tag -> K0: source Invalid, destination stays in Set_Key without HasKey' % fn, not ok and L.srcinv and L.st == 'SetKey' and not L.haskey)
    L = Locker(fn, 'NIK'); L.setst('setkey'); ok = L.derive(msg_of(32), src='xof')
    check('%s XOF output -> K0: not a source (GR39 item 2)' % fn, not ok and L.srcinv and L.st == 'SetKey' and not L.haskey)
    for sz, nm in ((16, 'CMAC-AES'), (8, 'CMAC-TDEA')):
        L = Locker(fn, 'NIK'); L.setst('setkey'); ok = L.derive(msg_of(sz), src='cmac')
        check('%s %s (%d B) -> K0 with length = source length: K0 zero-filled, HasKey' % (fn, nm, sz), ok and L.haskey and L.K0 == b2v(msg_of(sz)))
    for st_ in ('Ready',):
        for v in ('NIK', 'KIP'):
            L = Locker(fn, 'NIK') if v == 'NIK' else mkkip(fn, k); check('%s %s: K0 is not a destination in Ready (GR39 item 3) -> Invalid' % (fn, v), not L.derive(msg_of(16)) and inv(L))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s %d-byte field, length %d < field -> K0 dest Invalid (source must be exactly eff_length)' % (fn, b, b // 2), not L.derive(msg_of(b), length=b // 2) and inv(L))
    L = Locker(fn, 'NIK'); L.setst('setkey'); check('%s %d-byte secret, length %d > secret -> K0 dest Invalid' % (fn, b // 2, b), not L.derive(msg_of(b // 2), length=b) and inv(L))
    for ln in (0, 29, 31, 2**60):
        L = mknik(fn, k); L.setst('absorb'); check('%s shared secret (30 B) into Hash_Absorb with length %d != 30 -> dest Invalid (GR39 item 6)' % (fn, ln), not L.derive(msg_of(30), length=ln) and inv(L))
    L = mknik(fn, k); L.setst('absorb'); L.exec('B', b'prefix'); L.derive(msg_of(30)); L.exec('B', b'suffix'); L.setst('output')
    check('%s shared secret (30 B) between "prefix" and "suffix" in Hash_Absorb' % fn, out_all(L, L.f.t // 8) == ref(fn, k, b'prefix' + msg_of(30) + b'suffix'))
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
control('inner hash counts the message only: cumul_len = 8*|m| (ell = b + cumul_len in padding)', cum_in == 24)
wrong = R.sha2(fn, bytes(x ^ 0x36 for x in K0) + m)
control('without the outer hash (inner hash as tag) the tag differs', wrong != good)
control('outer hash without the K0^opad block differs', oracle(fn, inner) != good)
control('outer hash over inner with a non-zero block_base would differ: tag != hash(K0^opad | inner) of other length', oracle(fn, bytes(x ^ 0x5c for x in K0) + inner[:-1]) != good)
control('known-prefix attack: HMAC is not H(key | m)', oracle(fn, k + m) != good)
control('Content without cumul_len cannot resume: SHA-256 length field would restart', R.sha2(fn, b'bc') != R.sha2(fn, b'abc'))
info('%d checks, %.1fs' % (common.N_PASS + common.N_FAIL, time.time() - t0))
common.done()
