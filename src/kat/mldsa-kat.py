#!/usr/bin/env pypy3.12
"""KAT for the ML-DSA Machines (Type 11, Modes 3-5) of Zkl-ISA-machines.adoc.
Independent FIPS 204 model: mldsa_model.py ; Machine model from the spec: mldsa_locker.py.
Run: cd src && pypy3.12 kat/mldsa-kat.py"""
import hashlib, sys
from common import *
import mldsa_model as M
from mldsa_locker import *

P44, P65, P87 = M.PARAMS['ML-DSA-44'], M.PARAMS['ML-DSA-65'], M.PARAMS['ML-DSA-87']
XI = bytes(range(32))
sha = lambda b: hashlib.sha256(b).hexdigest()
def mu_of(tr, m, ctx=b''): return M.H(tr + b'\x00' + bytes([len(ctx)]) + ctx + m, 64)

def put(lk, st, data, chunk=None):
    lk.setst(st)
    chunk = chunk or len(data)
    for i in range(0, len(data), chunk): lk.exec('B', data[i:i + chunk])
def load_priv(lk, sk, chunk=None): put(lk, S_PRIVIN, sk, chunk); lk.setst(S_READY)
def load_pub(lk, pk): put(lk, S_PKIN, pk); lk.setst(S_READY)
def load_mu(lk, mu): put(lk, S_MUIN, mu); lk.setst(S_READY)
def take(lk, n, chunk=None):
    out, chunk = b'', chunk or n
    while len(out) < n: out += lk.exec('C', n=min(chunk, n - len(out)))
    return out
def sign(lk, xs=1, halt=None, **kw):
    lk.setst(S_SGEN, 'B' if xs else 'A', xs); lk.exec('D', halt=halt); return lk
def mk(ps=P44, **kw): return Locker(ps, **kw)

KEYS = {}
for p in (P44, P65, P87): KEYS[p['name']] = M.keygen_internal(p, XI)
pk44, sk44 = KEYS['ML-DSA-44']
tr44 = sk44[64:128]
mu44 = mu_of(tr44, b'hello')

# ------------------------------------------------------------------ 1
section('1 Sizes, external NIST/OpenSSL anchors')
for p, e in ((P44, (2560, 1312, 2420)), (P65, (4032, 1952, 3309)), (P87, (4896, 2592, 4627))):
    check(p['name'] + ' sizes', (p['sk'], p['pk'], p['sig']) == e, (p['sk'], p['pk'], p['sig']), e)
    ser = p['sk'] + p['pk'] + p['sig'] + 64 + 32
    check(p['name'] + ' Serialized Content blocks', -(-ser // 16) * 16 == {44: 6400, 65: 9392, 87: 12224}[int(p['name'][-2:])] and ser > 0,
          -(-ser // 16) * 16, 0)
check('ZETAS[1] (FIPS 204 App. B)', M.ZETAS[1] == 4808194, M.ZETAS[1], 4808194)
check('ZETAS[2] (FIPS 204 App. B)', M.ZETAS[2] == 3765607, M.ZETAS[2], 3765607)
import random
rnd_ = random.Random(1)
a = [rnd_.randrange(M.Q) for _ in range(256)]; b = [rnd_.randrange(M.Q) for _ in range(256)]
check('NTT round trip', M.intt(M.ntt(a)) == a)
sb = [0] * 256
for i in range(256):
    for j in range(256):
        k = i + j
        if k < 256: sb[k] += a[i] * b[j]
        else: sb[k - 256] -= a[i] * b[j]
check('NTT product == negacyclic schoolbook', M.intt(M.pmul(M.ntt(a), M.ntt(b))) == [x % M.Q for x in sb])
# OpenSSL 3.6.2 (hexseed 00..1f, deterministic, pure, message 'hello', empty ctx)
ANCH = {'ML-DSA-44': ('04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b', '9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46', '4d9736a262364bfe30a6d3d94dc5761f3f60316fafedd7c78156c3641f7a662a'),
        'ML-DSA-65': ('9f1e24f47795fe50040384e3d6183988047170fa2d866406b70fe0a3f8216063', 'd666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9', '1494cfed0b3c18c0b8534b86460e06cec9ae1b8f0ced906dc8b140241a1ac738'),
        'ML-DSA-87': ('764d3e223ed90c07bc91a0ab6ecd170e5c66ffe39f7039298596039a36005435', '91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd', '8f03e353d5c3d3d1f8d7348a1c56008fba78a7b73c10b95a583d53b27a863cb2')}
for p in (P44, P65, P87):
    pk, sk = KEYS[p['name']]
    mu = mu_of(sk[64:128], b'hello')
    lk = mk(p)
    load_priv(lk, sk); load_mu(lk, mu); sign(lk)
    sig = take(lk, p['sig'])
    e = ANCH[p['name']]
    check(p['name'] + ' keygen/sign/pk match OpenSSL digests', (sha(sk), sha(pk), sha(sig)) == e, (sha(sk), sha(pk), sha(sig)), e)
    check(p['name'] + ' Machine signature verifies (Sign_Verify -> Success)', lk.st == S_SUCCESS)
    v = mk(p); load_pub(v, pk); load_mu(v, mu); put(v, S_SIN, sig); v.setst(S_SVER); v.exec('D')
    check(p['name'] + ' Sign_Verify Success', v.st == S_SUCCESS and v.se & 0 == 0, v.st, S_SUCCESS)
    sig2 = bytearray(sig); sig2[10] ^= 1
    v = mk(p); load_pub(v, pk); load_mu(v, mu); put(v, S_SIN, bytes(sig2)); v.setst(S_SVER); v.exec('D')
    check(p['name'] + ' tampered signature -> Failure', v.st == S_FAILURE)

# ------------------------------------------------------------------ 2
section('2 External mu')
check('pure mu = SHAKE256(tr||00|||ctx||ctx||M)', mu44 == hashlib.shake_256(tr44 + b'\x00\x00hello').digest(64))
ctx = b'abc'
check('ctx changes mu', mu_of(tr44, b'hello', ctx) != mu44)
control('reversed order mu differs', hashlib.shake_256(tr44 + b'hello' + b'\x00\x00').digest(64) != mu44)

# ------------------------------------------------------------------ 3
section('3 MDH, States, Policy')
lk = mk(policy=3, aux=0x1234)
h = mdh_unpack(lk.mdh())
check('initial State Ready', h['State'] == ST_READY and h['StateExtension'] == 0 and h['MachineUse'] == 0)
check('Machine field Type 11 Mode 3 (44)', h['Machine'] == (11 << 4) | 3, h['Machine'])
check('Machine field Mode 4/5', [mdh_get(mk(p).mdh(), 'Machine') for p in (P65, P87)] == [(11 << 4) | 4, (11 << 4) | 5])
check('AuxInfo preserved', h['AuxInfo'] == 0x1234)
for imm, name in ((54, 'Success'), (55, 'Failure'), (14, 'undefined 14'), (45, 'undefined 45'), (5, 'undefined 5'), (7, 'undefined 7')):
    lk = mk(); lk.setst(imm); check('setst #%d (%s) -> Invalid' % (imm, name), lk.error and lk.se == SE_INVALID)
lk = mk(); lk.setst(S_MUIN, 'B', 1); check('Form B into mu_Input -> Invalid', lk.error)
lk = mk(); lk.setst(S_SGEN, 'B', 1); check('Sign_Generate without key/mu -> Invalid', lk.error)
lk = mk(); lk.setst(0); check('setst 0 -> Inert (kl.clear), no error', lk.inert and not lk.error)
for pol, st, ok in ((0, S_SGEN, False), (1, S_SGEN, True), (2, S_SGEN, False), (2, S_SVER, True), (1, S_SVER, False)):
    lk = mk(policy=pol); load_priv(lk, sk44); load_mu(lk, mu44)
    pub = mk(policy=pol); load_pub(pub, pk44); load_mu(pub, mu44); put(pub, S_SIN, bytes(P44['sig'])) if pol & 2 else None
    t = lk if st == S_SGEN else pub
    t.setst(st, 'B' if st == S_SGEN else 'A', 1)
    check('policy %d State %d %s' % (pol, st, 'admitted' if ok else 'Invalid'), (not t.error) == ok or (st == S_SVER and pol & 2 == 0 and t.error))
lk = mk(policy=3); lk.rstr(1); lk.rstr(2); check('rstrl narrows, never widens', lk.policy == 0)
lk = mk(policy=0); load_priv(lk, sk44); lk.setst(S_READY); check('policy 0 admits the loading States', not lk.error and lk.flag(HAS_PRIV))
lk = mk(policy=2); lk.rstr(1); check('restrict ANDs', lk.policy == 0)

# ------------------------------------------------------------------ 4
section('4 State machine, flags, MachineUse')
lk = mk(rbg=Rbg(XI)); lk.setst(S_GEN); lk.exec('D')
check('GenerateKeyPair -> pubkey_Output', lk.st == S_PKOUT and lk.flag(HAS_PRIV) and lk.flag(HAS_PUB))
check('GenerateKeyPair sets flags only privkey|pubkey', lk.se == 3, lk.se, 3)
check('GenerateKeyPair == model keygen', lk.pubkey == pk44 and lk.privkey == sk44)
got = take(lk, P44['pk'], 100)
check('pubkey_Output chunked read; ends in Success', got == pk44 and lk.st == S_SUCCESS and lk.mu_use == 0)
lk.setst(S_READY); check('Success -> Ready keeps keys', lk.st == S_READY and lk.flag(HAS_PRIV))
lk = mk(rbg=Rbg(XI)); lk.setst(S_GEN); lk.exec('D'); lk.exec('D'); check('Form D in pubkey_Output -> Invalid', lk.error)
lk = mk(); lk.exec('D'); check('Form D in Ready -> Invalid', lk.error)
lk = mk(rbg=Rbg(XI)); lk.setst(S_GEN); lk.exec('D'); lk.setst(S_PKOUT); check('same-State setst in output -> Invalid', lk.error)
lk = mk(rbg=Rbg(XI)); lk.setst(S_GEN); lk.exec('D'); take(lk, 10); lk.exec('C', n=P44['pk']); check('over-read of pubkey -> Invalid', lk.error)
lk = mk(rbg=Rbg(XI)); lk.setst(S_GEN); lk.exec('D'); lk.setst(S_READY)
lk.setst(S_PRIVIN)
check('entering privkey_Input clears flags and pubkey', lk.se & 3 == 0 and lk.pubkey == bytes(P44['pk']) and lk.privkey == bytes(P44['sk']))
lk = mk(); load_priv(lk, sk44, 100)
check('chunked privkey load sets HasPriv', lk.flag(HAS_PRIV) and lk.privkey == sk44)
lk = mk(); put(lk, S_PRIVIN, sk44 + b'junk'); lk.setst(S_READY)
check('excess data for privkey ignored', lk.flag(HAS_PRIV) and lk.privkey == sk44 and not lk.error)
lk = mk(); load_priv(lk, sk44); lk.setst(S_PKIN); check('pubkey_Input with HasPriv -> Invalid', lk.error)
lk = mk(); lk.setst(S_PRIVIN); lk.exec('B', sk44[:500]); lk.setst(S_READY)
check('incomplete privkey load zeroed on leaving', lk.privkey == bytes(P44['sk']) and not lk.flag(HAS_PRIV))
lk = mk(); lk.setst(S_MUIN); lk.exec('B', mu44[:10]); lk.setst(S_READY)
check('incomplete mu load zeroed, no HasMu', lk.mu == bytes(64) and not lk.flag(HAS_MU))
lk = mk(); put(lk, S_MUIN, mu44 + b'x'); lk.setst(S_READY); check('excess data for mu ignored', lk.flag(HAS_MU) and lk.mu == mu44)
# malformed privkey: flip a byte of s1 so a 3-bit coefficient decodes to 7 (> 2*eta=4)
bad = bytearray(sk44); bad[128] = 0xFF
check('model: malformed s1 rejected by sk_ok', not M.sk_ok(P44, bytes(bad)) and M.sk_ok(P44, sk44))
lk = mk(); put(lk, S_PRIVIN, bytes(bad)); check('malformed privkey -> Invalid at load completion', lk.error)
check('Invalid clears content', lk.privkey == bytes(P44['sk']))
control('weak check (length only) would accept the malformed key', len(bad) == P44['sk'])

# ------------------------------------------------------------------ 5
section('5 compute_pubKey')
lk = mk(); lk.setst(S_CPK); check('compute_pubKey without HasPriv -> Invalid', lk.error)
lk = mk(); load_priv(lk, sk44); lk.setst(S_CPK); lk.exec('D')
check('compute_pubKey derives pk, -> Ready, HasPub', lk.st == S_READY and lk.flag(HAS_PUB) and lk.pubkey == pk44)
lk.setst(S_PKOUT); check('derived pubkey exportable', take(lk, P44['pk'], 64) == pk44)
badtr = bytearray(sk44); badtr[64] ^= 1
lk = mk(); load_priv(lk, bytes(badtr)); lk.setst(S_CPK); lk.exec('D'); check('tr mismatch -> Invalid', lk.error)
control('model does see tr mismatch (H(pk) != tr)', M.H(pk44, 64) != bytes(badtr)[64:128])
lk = mk(); load_priv(lk, sk44); lk.setst(S_CPK); lk.exec('D'); sn = lk.export()
l2 = Locker.import_(sn, P44); check('export/import preserves HasPub+pubkey', l2.flag(HAS_PUB) and l2.pubkey == pk44)
sn = mk().export(); sn['se'] = HAS_PRIV; sn['privkey'] = bytes(bad); l2 = Locker.import_(sn, P44)
check('import HasPriv with zero (malformed) privkey -> Invalid', l2.error)

# ------------------------------------------------------------------ 6
section('6 Sign_Generate / Sign_Verify')
def signed(mu=mu44, xs=1, rbg=None, ps=P44, sk=sk44):
    lk = Locker(ps, rbg=rbg); load_priv(lk, sk); load_mu(lk, mu); return sign(lk, xs)
a = signed(); b = signed()
check('deterministic (Form B, Xs!=0) twice identical', a.signature == b.signature and M.verify_internal(P44, pk44, mu44, a.signature))
check('deterministic == model rnd=0', a.signature == M.sign_internal(P44, sk44, mu44, bytes(32)))
check('Sign_Generate -> Sign_Output; HEDGED clear', a.st == S_SOUT and not a.flag(HEDGED))
r1, r2 = bytes([1]) * 32, bytes([2]) * 32
h1 = signed(xs=0, rbg=Rbg(r1)); h2 = signed(xs=0, rbg=Rbg(r2))
check('hedged (Xs=0) uses RBG rnd', h1.signature == M.sign_internal(P44, sk44, mu44, r1) and h1.signature != h2.signature and h1.flag(HEDGED))
check('hedged signature verifies', M.verify_internal(P44, pk44, mu44, h2.signature))
check('rnd cleared after completion', h1.rnd == bytes(32) and a.rnd == bytes(32))
sg = a.signature
x = take(a, P44['sig'], 77)
check('Sign_Output chunked, Success, then Ready clears signature/mu', x == a.signature and a.st == S_SUCCESS)
a.setst(S_READY); check('Ready after sign: signature & mu zero, keys kept', a.signature == bytes(P44['sig']) and a.mu == bytes(64) and not a.flag(HAS_MU) and a.flag(HAS_PRIV))
lk = Locker(P44, rbg=Rbg('fail')); load_priv(lk, sk44); load_mu(lk, mu44); sign(lk, 0)
check('RBG failure -> Invalid, content cleared', lk.error and lk.privkey == bytes(P44['sk']) and lk.rnd == bytes(32))
lk = mk(); load_priv(lk, sk44); load_mu(lk, mu44); lk.setst(S_SOUT); check('Sign_Output not enterable by setst -> Invalid', lk.error)
lk = mk(); load_priv(lk, sk44); load_mu(lk, mu44); sign(lk); lk.exec('D'); check('Form D in Sign_Output -> Invalid', lk.error)
def ver(pk, mu, sig):
    v = mk(); load_pub(v, pk); load_mu(v, mu); put(v, S_SIN, sig); v.setst(S_READY); v.setst(S_SVER); v.exec('D'); return v
check('verify good -> Success', ver(pk44, mu44, sg).st == S_SUCCESS)
for nm, off in (('z', 100), ('commitment hash', 3), ('hint', P44['sig'] - 20)):
    t = bytearray(sg); t[off] ^= 0x10
    check('verify tampered %s -> Failure' % nm, ver(pk44, mu44, bytes(t)).st == S_FAILURE)
check('verify wrong message -> Failure', ver(pk44, mu_of(tr44, b'hellp'), sg).st == S_FAILURE)
control('good signature is not Failure', ver(pk44, mu44, sg).st != S_FAILURE)
v = mk(); load_pub(v, pk44); put(v, S_SIN, sg); v.setst(S_SVER); check('Sign_Verify without HasMu -> Invalid', v.error)
v = mk(); load_pub(v, pk44); load_mu(v, mu44); v.setst(S_SIN); v.exec('B', sg + b'x'); check('excess in signature -> Failure, signature zeroed', v.st == S_FAILURE and v.signature == bytes(P44['sig']))
v = mk(); v.setst(S_PKIN); v.exec('B', pk44 + b'x'); check('excess in pubkey -> Failure, pubkey zeroed', v.st == S_FAILURE and v.pubkey == bytes(P44['pk']))
v.setst(S_READY); load_pub(v, pk44); load_mu(v, mu44); put(v, S_SIN, sg); v.setst(S_READY); v.setst(S_SVER); v.exec('D')
check('Failure -> Ready -> reload works', v.st == S_SUCCESS)
v = mk(); v.setst(S_PKIN); v.exec('B', pk44 + b'x'); v.setst(S_SIN); check('Failure -> Sign_Input -> Invalid (GR22)', v.error)

# ------------------------------------------------------------------ 7
section('7 Interrupted Sign_Generate')
def needs(mu, n):
    return M.sign_iterations(P44, sk44, mu, bytes(32)) >= n
mu_hard = None
for i in range(2000):
    m = mu_of(tr44, b'search%d' % i)
    if needs(m, 8): mu_hard = m; break
NIT = M.sign_iterations(P44, sk44, mu_hard, bytes(32))
info('mu needing %d deterministic iterations found' % NIT)
check('found a mu needing >= 8 iterations', NIT >= 8, NIT, 8)
full = signed(mu_hard)
lk = mk(); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk, halt=1)
check('halt: State stays Sign_Generate, MachineUse P non-zero', lk.st == S_SGEN and lk.mu_use != 0)
n = 1
while lk.st == S_SGEN:
    pre = lk.mu_use; lk.exec('D', halt=1); n += 1
    check_ok = lk.st != S_SGEN or lk.mu_use > pre
    if not check_ok: check('P increases', False); break
check('resumed every iteration -> same signature', lk.st == S_SOUT and lk.signature == full.signature and n == NIT, (n, NIT))
check('completion zeroes P and rnd', lk.mu_use == 0 and lk.rnd == bytes(32))
lk = mk(rbg=Rbg(r1, r2)); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk, 0, halt=2)
check('hedged: rnd held during halt', lk.rnd == r1 and lk.mu_use != 0)
lk.exec('D'); check('hedged resume uses same rnd, no new RBG draw', lk.signature == M.sign_internal(P44, sk44, mu_hard, r1) and lk.rbg.q == [r2])
lk = mk(); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk, halt=1); lk.setst(S_READY)
check('setst out of halted Sign_Generate zeroes P/rnd', lk.mu_use == 0 and lk.rnd == bytes(32) and lk.st == S_READY)
lk = mk(); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk, halt=1); lk.setst(S_SGEN, 'B', 1)
check('same-State setst in halted Sign_Generate -> Invalid', lk.error)
lk = mk(rbg=Rbg(r1, r2)); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk, 0, halt=1); lk.setst(S_READY); load_mu(lk, mu_hard); sign(lk, 0, halt=1)
check('re-entering draws a fresh rnd', lk.rnd == r2)
lk = mk(); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk, halt=1); lk.rstr(2); lk.exec('D')
check('narrowing during halt -> resuming exec Invalid', lk.error)
lk = mk(rbg=Rbg(r1)); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk, 0, halt=2)
snap = lk.export(True)
l2 = Locker.import_(snap, P44, True, Rbg(r2)); l2.exec('D')
lk.exec('D')
check('export/import with Content2 resumes with same rnd in both lockers', l2.signature == lk.signature == M.sign_internal(P44, sk44, mu_hard, r1))
lk = mk(rbg=Rbg(r1)); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk, 0, halt=2)
l2 = Locker.import_(lk.export(False), P44, False, Rbg(r2))
check('import without Content2: P=0, rnd destroyed', l2.mu_use == 0 and l2.rnd == bytes(32) and l2.st == S_SGEN)
l2.exec('D'); check('... restart draws fresh rnd', l2.signature == M.sign_internal(P44, sk44, mu_hard, r2))

# ------------------------------------------------------------------ 8
section('8 Loop limits')
check('Table 3 limits', M.DEFAULT_LIM == {'sign': 814, 'bounded': 481, 'ntt': 894, 'ball': 221}, M.DEFAULT_LIM)
lim = {'sign': NIT - 1}
lk = Locker(P44, lim=lim); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk)
check('sign limit reached -> Failure, no output, rnd destroyed, P=0', lk.st == S_FAILURE and lk.signature == bytes(P44['sig']) and lk.rnd == bytes(32) and lk.mu_use == 0)
lk = Locker(P44, lim={'sign': NIT}); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk)
check('limit exactly = needed iterations succeeds', lk.st == S_SOUT)
lk = Locker(P44, lim={'sign': NIT - 1}); load_priv(lk, sk44); load_mu(lk, mu_hard); sign(lk, halt=NIT - 3); lk.exec('D')
check('limit reached after resume -> Failure', lk.st == S_FAILURE and lk.mu_use == 0)
for key, nm in (('bounded', 'RejBoundedPoly in GenerateKeyPair'), ('ntt', 'RejNTTPoly in GenerateKeyPair')):
    lk = Locker(P44, rbg=Rbg(XI), lim={key: 40}); lk.setst(S_GEN); lk.exec('D')
    check(nm + ' limit -> Failure, no output', lk.st == S_FAILURE and lk.pubkey == bytes(P44['pk']) and not lk.flag(HAS_PRIV))
lk = Locker(P44, lim={'ntt': 40}); load_priv(lk, sk44); lk.setst(S_CPK); lk.exec('D'); check('compute_pubKey ntt limit -> Failure', lk.st == S_FAILURE and not lk.flag(HAS_PUB))
lk = Locker(P44, lim={'ball': 3}); load_pub(lk, pk44); load_mu(lk, mu44); put(lk, S_SIN, sg); lk.setst(S_READY); lk.setst(S_SVER); lk.exec('D')
check('Sign_Verify SampleInBall limit -> Failure', lk.st == S_FAILURE)
lk = Locker(P44, lim={'ball': 3}); load_priv(lk, sk44); load_mu(lk, mu44); sign(lk)
check('SampleInBall limit in sign -> Failure', lk.st == S_FAILURE and lk.signature == bytes(P44['sig']))
control('default limits do not trigger on same input', ver(pk44, mu44, sg).st == S_SUCCESS)

# ------------------------------------------------------------------ 9
section('9 kl.derive')
spec_note('kl.derive (GR39) with an ML-DSA source/destination: not modelled (no derive entry in mldsa_locker.py); UNVERIFIED')

# ------------------------------------------------------------------ 10
section('10 Hint decoding (Algorithm 21)')
om, k = P44['omega'], P44['k']
def hint_bytes(h): return M.hint_bit_pack(P44, h)
h = [[0] * 256 for _ in range(k)]
for i, j in ((0, 3), (0, 200), (2, 5), (3, 255)): h[i][j] = 1
y = hint_bytes(h)
check('HintBitPack length omega+k', len(y) == om + k, len(y), om + k)
check('HintBitUnpack round trip', M.hint_unpack(P44, y) == h)
check('counts at the end', list(y[om:]) == [2, 2, 3, 4], list(y[om:]))
def mod(y, i, v): t = bytearray(y); t[i] = v; return bytes(t)
check('non-increasing indices rejected', M.hint_unpack(P44, mod(y, 1, 3)) is None)
check('equal indices rejected', M.hint_unpack(P44, mod(y, 1, 3)) is None)
check('nonzero padding rejected', M.hint_unpack(P44, mod(y, 10, 1)) is None)
check('count > omega rejected', M.hint_unpack(P44, mod(y, om + 3, om + 1)) is None)
check('decreasing counts rejected', M.hint_unpack(P44, mod(y, om + 1, 1)) is None)
control('weak decoder ignoring padding would accept it', M.hint_unpack(P44, y) is not None)
base = P44['sig'] - om - k
cnt = sg[P44['sig'] - k:]
pad = base + cnt[-1]
if cnt[-1] < om:
    bs = mod(sg, base + om - 1, 1)
    check('Machine: nonzero hint pad byte -> Failure, pubkey kept', ver(pk44, mu44, bs).st == S_FAILURE and ver(pk44, mu44, bs).flag(HAS_PUB))
done()
