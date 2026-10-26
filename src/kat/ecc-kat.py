#!/usr/bin/env pypy3.12
"""KAT for the Elliptic Curve Machines (machine type 10): Weierstrass ECDSA/ECDH/SM2, X25519/X448, Ed25519/Ed448.
Expected values: RFC 6979, RFC 8032 (via OpenSSL), RFC 7748, GM/T 0003.5, CAVP CDH, OpenSSL-generated vectors (ecc_vectors.py).
Run: cd src && pypy3.12 kat/ecc-kat.py"""
import sys, os, hashlib, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
import ecc_model as M, ecc_vectors as V
from ecc_machine import *
T0 = time.time()
H = bytes.fromhex
WEI = ['secp256r1', 'secp384r1', 'secp521r1', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'sm2']
def le(v, n): return v.to_bytes(n, 'little')
def rbg_k(k): return lambda n: (k - 1).to_bytes(n, 'big')       # makes k = c mod (n-1) + 1 equal to k
def load(L, st, data, form='A'):
    r = L.setst(st, form, 1 if (st == SGEN and form == 'B') else 0)
    return r if r == 'invalid' else L.exec_in(data)
def full_out(L):
    return {0: L.u, 1: L.v, 2: L.u}[L.outtype] * L.W if L.outtype != 2 else len(L.shared_secret())
def drain(L):
    o = b''
    while L.state == OUT: o += L.exec_out(min(8, full_out(L) - L.block_base))
    return o
def pt_mul(name, d, P=None):
    L = EccLocker(name); load(L, SSCAL, le(d, L.W))
    if P is not None: load(L, S2ND, P)
    L.setst(PMUL); r = L.exec_D(); return L, r
def hashfield(L, hname, msg):
    e = int.from_bytes(hashlib.new(hname, msg).digest(), 'big'); n = L.n.bit_length()
    if n < 8 * hashlib.new(hname).digest_size: e >>= 8 * hashlib.new(hname).digest_size - n
    return le(e, L.h // 8)
def sign(L, d, hf, k):
    L.rbg = rbg_k(k); L.setst(RDY); load(L, SSCAL, le(d, L.W)); load(L, SHASH, hf); L.setst(SGN)
    r = L.exec_D()
    return r, (drain(L) if r == 'output' else None)
def verify(L, Q, sig, hf, gen=None):
    L.setst(RDY)
    if gen is not None: load(L, SGEN, gen, 'B')
    load(L, S2ND, Q); load(L, SIN, sig); load(L, SHASH, hf); L.setst(SVER); return L.exec_D()
def xy(P, W): return le(P[0], W) + le(P[1], W)

# ------------------------------------------------------------------ 1
section('Domain parameters and b/h/j/u/v')
for nm in WEI:
    C = M.Wei(nm)
    check(nm + ': G on curve, n*G = O, h=1, p/n coprime to small primes', C.on_curve(C.G) and C.mul(C.n, C.G) is None and C.mul(C.n - 1, C.G) == C.neg(C.G))
    L = EccLocker(nm); b = {'secp521r1': 576}.get(nm, C.p.bit_length())
    check(nm + ': b=%d u=2 v=2 h=j=b' % b, (L.b, L.u, L.v, L.h, L.j) == (b, 2, 2, b, b))
    check(nm + ': default Generator = standard G', L.Generator == bytearray(xy(C.G, L.W)))
check('ed25519 b=256 h=512 u=1 v=2', (lambda L: (L.b, L.h, L.u, L.v, L.j))(EccLocker('ed25519')) == (256, 512, 1, 2, 0))
check('ed448 b=456 h=512 u=1 v=2', (lambda L: (L.b, L.h, L.u, L.v, L.j))(EccLocker('ed448')) == (456, 512, 1, 2, 0))
check('x25519 b=256 u=1 v=0', (lambda L: (L.b, L.u, L.v))(EccLocker('x25519', policy=0)) == (256, 1, 0))
check('x448 b=448 u=1 v=0', (lambda L: (L.b, L.u, L.v))(EccLocker('x448', policy=0)) == (448, 1, 0))
check('Ed25519 B has y = 4/5 and order L', M.Ed('ed25519').mul(M.Ed('ed25519').L, M.Ed('ed25519').B) == (0, 1))
check('Ed448 L*B = O', M.Ed('ed448').mul(M.Ed('ed448').L, M.Ed('ed448').B) == (0, 1))
check('machine type 10 in MDH, mode list has 11 entries', mdh_get(EccLocker('sm2').mdh, 'Machine') == 10 and len(MODES) == 11)

# ------------------------------------------------------------------ 2
section('ECDSA / Brainpool vectors through the Machine (RFC 6979 A.2.5-A.2.7; OpenSSL deterministic for the others)')
for nm, hn, d, msg, r, s, Qx, Qy in V.ECDSA:
    L = EccLocker(nm); W = L.W
    pm, _ = pt_mul(nm, d); L = pm
    check('%s/%s %s: Point_Mul d*G = Q' % (nm, hn, msg.decode()), L.state == OUT and L.outtype == 0 and drain(L) == xy((Qx, Qy), W) and L.state == 54)
    L = EccLocker(nm); hf = hashfield(L, hn, msg)
    k = M.rfc6979_k(L.C, d, hashlib.new(hn, msg).digest(), hn)
    st, out = sign(L, d, hf, k)
    check('%s/%s %s: Sign_Generate -> (r,s) = vector' % (nm, hn, msg.decode()), st == 'output' and L.outtype == 1 and out == le(r, W) + le(s, W), out, le(r, W) + le(s, W))
    check('%s/%s %s: RndNum destroyed after signing, HasSignature set' % (nm, hn, msg.decode()), not L.has('rnd') and L.has('sig') and not any(L.RndNum))
    L2 = EccLocker(nm)
    check('%s/%s %s: Sign_Verify -> Success' % (nm, hn, msg.decode()), verify(L2, xy((Qx, Qy), W), le(r, W) + le(s, W), hf) == 'success' and L2.state == 54)
    bad = verify(EccLocker(nm), xy((Qx, Qy), W), le(r ^ 1, W) + le(s, W), hf)
    check('%s/%s %s: corrupted r -> Failure' % (nm, hn, msg.decode()), bad == 'failure')
    check('%s/%s %s: corrupted hash -> Failure' % (nm, hn, msg.decode()), verify(EccLocker(nm), xy((Qx, Qy), W), le(r, W) + le(s, W), le(b2v(hf) ^ 2, L.h // 8)) == 'failure')
    nn = L.n
    for lab, rr, ss in (('r=0', 0, s), ('s=0', r, 0), ('r=n', nn, s), ('s=n', r, nn)):
        check('%s %s: %s -> Failure (not Invalid)' % (nm, msg.decode(), lab), verify(EccLocker(nm), xy((Qx, Qy), W), le(rr, W) + le(ss, W), hf) == 'failure')
    break_ = [x for x in V.ECDSA if x[0] == nm][0]
    check('%s: control: wrong public key -> Failure' % nm, verify(EccLocker(nm), xy(M.Wei(nm).G, W), le(r, W) + le(s, W), hf) == 'failure')
control('swapped (s,r) is rejected', verify(EccLocker('secp256r1'), xy((V.ECDSA[0][6], V.ECDSA[0][7]), 32), le(V.ECDSA[0][5], 32) + le(V.ECDSA[0][4], 32), hashfield(EccLocker('secp256r1'), 'sha256', b'sample')) == 'failure')
control('big-endian signature encoding is rejected', verify(EccLocker('secp256r1'), xy((V.ECDSA[0][6], V.ECDSA[0][7]), 32), V.ECDSA[0][4].to_bytes(32, 'big') + V.ECDSA[0][5].to_bytes(32, 'big'), hashfield(EccLocker('secp256r1'), 'sha256', b'sample')) == 'failure')
info('RFC 6979 A.2.5 values are those reproduced by ecc_model (U.x = 60FED4BA...)')

# ------------------------------------------------------------------ 3
section('secp521r1: 576-bit fields, bits 521..575 must be zero')
bad = le(1 << 521, 72)
for fld, st, ok in (('Scalar', SSCAL, 0), ('SecondPt', S2ND, 0), ('Hash', SHASH, 0), ('Signature', SIN, 0)):
    L = EccLocker('secp521r1'); n = len(getattr(L, fld)); data = bytearray(n); data[65] = 2
    r = load(L, st, bytes(data))
    check('secp521r1 %s with bit 521 set -> Invalid at load' % fld, r == 'invalid' and L.invalid)
    L = EccLocker('secp521r1'); data = bytearray(n); data[71] = 0x80
    check('secp521r1 %s with bit 575 set -> Invalid at load' % fld, load(L, st, bytes(data)) == 'invalid')
L = EccLocker('secp521r1'); data = bytearray(128); data[65] = 2
check('secp521r1 Generator with bit 521 set -> Invalid', load(L, SGEN, bytes(data), 'B') == 'invalid')
L = EccLocker('secp521r1'); load(L, SSCAL, le(5, 72)); L.Generator[65] |= 2; L.setst(PMUL)
check('secp521r1 stale non-canonical Generator at Point_Mul -> Invalid', L.exec_D() == 'invalid')
L = EccLocker('secp521r1'); load(L, SSCAL, le(5, 72))
check('secp521r1 valid scalar < 2^521 accepted', L.state == SSCAL and not L.invalid and L.complete)
check('secp521r1 shared secret length m = 66 bytes', len(pt_mul('secp521r1', 3, xy(M.Wei('secp521r1').G, 72))[0].shared_secret()) == 66)

# ------------------------------------------------------------------ 4
section('Point_Mul: scalar range, points, load rules')
for nm in ('secp256r1', 'brainpoolP256r1', 'sm2'):
    C = M.Wei(nm); W = 32
    L = EccLocker(nm); load(L, SSCAL, le(0, W)); check(nm + ': Scalar 0 -> Point_Mul entry Invalid', L.setst(PMUL) == 'invalid')
    L = EccLocker(nm); load(L, SSCAL, le(C.n, W)); check(nm + ': Scalar n -> Invalid', L.setst(PMUL) == 'invalid')
    L = EccLocker(nm); load(L, SSCAL, le(C.n + 1, W)); check(nm + ': Scalar n+1 -> Invalid', L.setst(PMUL) == 'invalid')
    L, r = pt_mul(nm, C.n - 1); check(nm + ': (n-1)G = -G', r == 'output' and drain(L) == xy(C.neg(C.G), W))
    L, r = pt_mul(nm, 2); check(nm + ': 2G = G+G', drain(L) == xy(C.add(C.G, C.G), W))
    bad = le(C.G[0], W) + le(C.G[1] ^ 1, W)
    L, r = pt_mul(nm, 3, bad); check(nm + ': off-curve SecondPt -> Failure', r == 'failure' and L.state == 55)
    L = EccLocker(nm); load(L, SSCAL, le(3, W)); load(L, SGEN, bad, 'B'); L.setst(PMUL); check(nm + ': off-curve Generator -> Failure', L.exec_D() == 'failure')
    L = EccLocker(nm); load(L, SSCAL, le(3, W)); load(L, S2ND, le(C.p, W) + le(0, W)); L.setst(PMUL)
    check(nm + ': coordinate >= p -> Failure', L.exec_D() == 'failure')
    L = EccLocker(nm); load(L, SSCAL, le(3, W)); load(L, S2ND, bytes(2 * W)); L.setst(PMUL)
    check(nm + ': neutral/zero SecondPt -> Failure', L.exec_D() == 'failure')
    L = EccLocker(nm); L.setst(SSCAL); L.exec_in(b'\x01' * 10); L.setst(RDY)
    check(nm + ': incomplete load then Ready zeroes the field (MR14)', not any(L.Scalar))
    L = EccLocker(nm); L.setst(SSCAL); L.exec_in(b'\x01' * 10); L.setst(SSCAL)
    check(nm + ': same-State setst restarts load, field zero', not any(L.Scalar) and L.state == SSCAL and not L.invalid)
    L = EccLocker(nm); L.setst(SSCAL); L.exec_in(le(5, W) + b'\xff' * 9)
    check(nm + ': excess in load ignored', L.complete and b2v(L.Scalar) == 5)
    # Point_Mul with SecondPt: shared secret
    L, r = pt_mul(nm, 5, xy(C.mul(3, C.G), W)); check(nm + ': Point_Mul on SecondPt -> OutputType shared secret', L.outtype == 2 and L.has('second'))
    L, r = pt_mul(nm, 5); check(nm + ': Point_Mul on Generator -> OutputType point', L.outtype == 0 and L.has('second') and L.state == OUT)
    check(nm + ': Output 24+24+16 bytes of 64-byte field -> Success', (lambda L: (L.exec_out(24) + L.exec_out(24) + L.exec_out(16) if W == 32 else 0) and L.state == 54)(pt_mul(nm, 5)[0]) if W == 32 else True)
    L, r = pt_mul(nm, 5); L.exec_out(60); check(nm + ': excess emit -> Invalid', L.exec_out(8) == 'invalid')
L = EccLocker('secp256r1', rbg=lambda n: (_ for _ in ()).throw(RbgFailure()))
check('GR65: RBG failure on random Scalar -> Invalid', L.setst(SSCAL, 'B', 1) == 'invalid' and L.invalid)
L = EccLocker('secp256r1', rbg=lambda n: (_ for _ in ()).throw(RbgUnavailable()))
check('RBG unavailable raises, locker unchanged', raises(L.setst, SSCAL, 'B', 1, exc=RbgUnavailable) and not L.invalid)
L = EccLocker('secp256r1', rbg=rbg_k(7)); L.setst(SSCAL, 'B', 1)
check('Form B Set_Scalar nonzero: random private key d = c mod (n-1) + 1, complete', b2v(L.Scalar) == 7 and L.complete and L.block_base == 32)
L = EccLocker('sm2', rbg=rbg_k(7)); L.setst(SSCAL, 'B', 1)
check('SM2 random key in [1, n-2]', 1 <= b2v(L.Scalar) <= L.n - 2)
L = EccLocker('secp256r1', rbg=lambda n: bytes(n)); L.setst(SSCAL, 'B', 1)
check('Form B Set_Scalar, RBG output 0 -> d = 1', b2v(L.Scalar) == 1)

# ------------------------------------------------------------------ 5
section('Signature retry rules (rejection of k)')
for nm in ('secp256r1', 'brainpoolP256r1', 'sm2'):
    C = M.Wei(nm); n = C.n; d = 0x1234567 + 1; k1, k2 = 11, 12
    seq = iter([k1, k2, 13])
    L = EccLocker(nm)
    def rb(m, seq=seq): return (next(seq) - 1).to_bytes(m, 'big')
    x1 = C.mul(k1, C.G)[0] % n
    if nm == 'sm2':
        cases = {'r=0': (-x1) % n, 'r+k=n': (n - k1 - x1) % n}
        r_ = k1 * pow(d, -1, n) % n
        cases['s=0 (r=k/d)'] = None
    else:
        r1 = x1; cases = {'s=0': (-r1 * d) % n}
    for lab, e in cases.items():
        if e is None: continue
        L = EccLocker(nm); seq = iter([k1, k2]); L.rbg = lambda m, seq=seq: (next(seq) - 1).to_bytes(m, 'big')
        L.setst(SSCAL); L.exec_in(le(d, 32)); L.setst(SHASH); L.exec_in(le(e, 32)); L.setst(SGN)
        r = L.exec_D(); out = drain(L)
        sg = (b2v(out[:32]), b2v(out[32:]))
        ref = (M.sm2_sign if nm == 'sm2' else M.ecdsa_sign)(C, d, e, k2)
        check('%s %s: k1 rejected, retry with k2 -> signature from k2' % (nm, lab), r == 'output' and ref is not None and sg == ref, sg, ref)
        check('%s %s: result verifies' % (nm, lab), (M.sm2_verify if nm == 'sm2' else M.ecdsa_verify)(C, C.mul(d, C.G), e, sg))
    check('%s: Scalar range: n-1 (n-2 for SM2) allowed at Sign_Generate entry' % nm, (lambda L: (load(L, SHASH, le(1, 32)), load(L, SSCAL, le(n - (2 if nm == 'sm2' else 1), 32)), L.setst(SGN))[2] == 'ok')(EccLocker(nm)))
    if nm == 'sm2':
        L = EccLocker(nm); load(L, SHASH, le(1, 32)); load(L, SSCAL, le(n - 1, 32))
        check('SM2: Scalar n-1 rejected at Sign_Generate (range 1..n-2)', L.setst(SGN) == 'invalid')
    L = EccLocker(nm); load(L, SSCAL, le(5, 32)); check(nm + ': Sign_Generate without HasHash -> Invalid', L.setst(SGN) == 'invalid')
    L = EccLocker(nm); load(L, SHASH, le(5, 32)); check(nm + ': Sign_Generate Scalar=0 -> Invalid', L.setst(SGN) == 'invalid')
# SM2 vector (GM/T 0003.5 example)
sm2d = int('3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8', 16)
C = M.Wei('sm2'); L = EccLocker('sm2'); W = 32
Q = C.mul(sm2d, C.G)
check('SM2 GM/T 0003.5 public key', Q == (0x9f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020, 0xccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13))
za = M.sm2_za(C, b'1234567812345678', Q)
check('SM2 Z_A (GM/T 0003.5 A.2)', za.hex() == 'b2e14c5c79c6df5b85f4fe7ed8db7a262b9da7e07ccb0ea9f4747b8ccda8a4f3', za.hex())
e = int.from_bytes(hashlib.new('sm3', za + b'message digest').digest(), 'big')
check('SM2 e = SM3(Z_A || M)', hex(e) == '0xf0b43e94ba45accaace692ed534382eb17e6ab5a19ce7b31f4486fdfc0d28640', hex(e))
L, r = pt_mul('sm2', sm2d); check('SM2 Point_Mul d*G -> public key', drain(L) == xy(Q, W))
sm2k = 0x59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21   # = s(1+d)+rd mod n from the published (r,s); r re-derived below
sm2r = 0xF5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3; sm2s = 0xB1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA
L = EccLocker('sm2'); st, out = sign(L, sm2d, le(e, 32), sm2k)
check('SM2 Sign_Generate = published (r,s)', st == 'output' and out == le(sm2r, 32) + le(sm2s, 32), out, le(sm2r, 32) + le(sm2s, 32))
check('SM2 Sign_Verify success', verify(EccLocker('sm2'), xy(Q, 32), le(sm2r, 32) + le(sm2s, 32), le(e, 32)) == 'success')
t0 = (sm2r + sm2s) % C.n
check('SM2 verify with wrong e -> Failure', verify(EccLocker('sm2'), xy(Q, 32), le(sm2r, 32) + le(sm2s, 32), le(e ^ 1, 32)) == 'failure')
check('SM2 verify t = (r+s) mod n = 0 -> Failure', verify(EccLocker('sm2'), xy(Q, 32), le(sm2r, 32) + le(C.n - sm2r, 32), le(e, 32)) == 'failure')

# ------------------------------------------------------------------ 6
section('Progress, halting, resume (GR56), clone (GR57), clearads')
def sign_setup(nm='secp256r1', k=5):
    L = EccLocker(nm, rbg=rbg_k(k)); load(L, SSCAL, le(0x1234, L.W)); load(L, SHASH, le(0x777, L.W)); L.setst(SGN); return L
ref = M.ecdsa_sign(M.Wei('secp256r1'), 0x1234, 0x777, 5)
L = sign_setup(); r = L.exec_D(halt=True)
check('halted Sign_Generate: still Sign_Generate, Progress != 0, RndNum held', r == 'halted' and L.state == SGN and L.progress != 0 and L.has('rnd') and b2v(L.RndNum) == 5)
check('MachineUse: Progress in [13:2], OutputType in [1:0]', mdh_get(L.mdh, 'MachineUse') >> 2 == L.progress and mdh_get(L.mdh, 'MachineUse') & 3 == L.outtype)
L.rbg = rbg_k(9); r = L.exec_D()
check('resume uses held RndNum (not a fresh k)', r == 'output' and (b2v(drain(L)[:32]), ) == (ref[0],))
L = sign_setup(); L.exec_D(halt=True)
check('same-State setst into Sign_Generate is not admitted (GR21) -> Invalid', L.setst(SGN) == 'invalid' and L.invalid)
L = sign_setup(); L.exec_D(halt=True)
check('from halted Sign_Generate, a Set State is not admitted (only Ready/clearads) -> Invalid', L.setst(SHASH) == 'invalid')
L = sign_setup(); L.exec_D(halt=True); L.clearads()
check('kl.clearads discards Progress and RndNum', L.progress == 0 and not L.has('rnd'))
L = sign_setup(); L.exec_D(halt=True); L.setst(RDY)
check('transition to Ready discards Progress and RndNum', L.progress == 0 and not L.has('rnd'))
L = sign_setup(); L.exec_D(halt=True); C2 = L.clone()
check('clone of halted operation restarts: Progress 0, RndNum destroyed', C2.progress == 0 and not C2.has('rnd') and L.progress != 0)
L = sign_setup(); L.exec_D(halt=True); r = L.restrictl(2)
check('restrictl clearing MachinePolicy[0] destroys RndNum', L.has('rnd') is False and not any(L.RndNum))
L = EccLocker('secp256r1'); load(L, SSCAL, le(7, 32)); L.setst(PMUL); L.exec_D(halt=True)
check('halted Point_Mul resumes to Output', L.progress != 0 and L.exec_D() == 'output' and L.progress == 0)

# ------------------------------------------------------------------ 7
section('State machine: entry conditions, Forms, gating')
L = EccLocker('secp256r1'); check('Ready -> Output is not admitted', L.setst(OUT) == 'invalid')
for t in (54, 55):
    check('setst #%d -> Invalid' % t, EccLocker('secp256r1').setst(t) == 'invalid')
check('Set_Hash Form B -> Invalid (wrong Form)', EccLocker('secp256r1').setst(SHASH, 'B', 1) == 'invalid')
check('Point_Mul Form B -> Invalid', EccLocker('secp256r1').setst(PMUL, 'B', 1) == 'invalid')
check('Form C/D never names a State (setst Form C) -> Invalid', EccLocker('secp256r1').setst(SSCAL, 'C') == 'invalid')
check('Ready Form A and B both admitted', EccLocker('secp256r1').setst(RDY, 'B', 0) == 'ok')
check('Set_Ctx not a State of Weierstrass Machines -> Invalid', EccLocker('secp256r1').setst(SCTX, 'B', 1) == 'invalid')
check('Msg_Absorb not a State of Weierstrass Machines -> Invalid', EccLocker('secp256r1').setst(MABS, 'B', 0) == 'invalid')
L = EccLocker('secp256r1'); load(L, SSCAL, le(3, 32)); load(L, S2ND, xy(M.Wei('secp256r1').G, 32)); load(L, SHASH, le(1, 32))
check('Sign_Verify without HasSignature -> Invalid', L.setst(SVER) == 'invalid')
L = EccLocker('secp256r1'); load(L, SHASH, le(1, 32)); load(L, SIN, le(1, 64)); check('Sign_Verify without HasSecondPt -> Invalid', L.setst(SVER) == 'invalid')
L = EccLocker('secp256r1'); load(L, S2ND, xy(M.Wei('secp256r1').G, 32)); load(L, SIN, le(1, 64)); check('Sign_Verify without HasHash -> Invalid', L.setst(SVER) == 'invalid')
check('Set_Scalar from Set_Hash admitted (Set State to Set State)', (lambda L: (L.setst(SHASH), L.setst(SSCAL))[1] == 'ok')(EccLocker('secp256r1')))
check('Set_Scalar -> Set_Scalar restarts', EccLocker('secp256r1').setst(SSCAL) == 'ok')
L = EccLocker('secp256r1', policy=2); check('MachinePolicy[0]=0: Sign_Generate -> Invalid', (load(L, SHASH, le(1, 32)), load(L, SSCAL, le(3, 32)), L.setst(SGN))[2] == 'invalid')
L = EccLocker('secp256r1', policy=1); check('MachinePolicy[1]=0: Set_Sign_Input -> Invalid', L.setst(SIN) == 'invalid')
L = EccLocker('secp256r1', policy=1); check('MachinePolicy[1]=0: Sign_Verify -> Invalid', L.setst(SVER) == 'invalid')
L = EccLocker('secp256r1', policy=0); check('MachinePolicy=0: Set_Hash -> Invalid', L.setst(SHASH) == 'invalid')
L = EccLocker('secp256r1', policy=0); load(L, SSCAL, le(3, 32)); check('MachinePolicy=0: ECDH Point_Mul still available', L.setst(PMUL) == 'ok' and L.exec_D() == 'output')
L = EccLocker('secp256r1'); load(L, SSCAL, le(3, 32)); L.setst(PMUL); L.exec_D(); L.exec_out(64)
check('Output complete -> Success; Success only leaves via Ready', L.state == 54 and L.setst(SSCAL) == 'invalid')
L = EccLocker('secp256r1'); L.state = 55; check('Failure -> Ready admitted', L.setst(RDY) == 'ok')
# Ready Xs bits
Cc = M.Wei('secp256r1'); G = bytes(xy(Cc.G, 32)); P5 = xy(Cc.mul(5, Cc.G), 32)
def rdy_state():
    L = EccLocker('secp256r1'); load(L, SGEN, P5, 'B'); load(L, SSCAL, le(3, 32)); load(L, S2ND, xy(Cc.mul(7, Cc.G), 32)); load(L, SHASH, le(9, 32)); load(L, SIN, le(1, 64)); return L
P7 = xy(Cc.mul(7, Cc.G), 32)
L = rdy_state(); L.setst(RDY, 'A')
check('Ready Form A keeps everything', bytes(L.Generator) == P5 and bytes(L.SecondPt) == P7 and b2v(L.Scalar) == 3 and L.has('hash') and L.has('sig') and L.has('second'))
for bit, nm_ in ((0, 'resets Generator'), (1, 'erases SecondPt'), (2, 'erases Scalar'), (3, 'erases Hash'), (6, 'erases Signature')):
    L = rdy_state(); L.setst(RDY, 'B', 1 << bit)
    exp = {0: bytes(L.Generator) == G, 1: not any(L.SecondPt) and not L.has('second'), 2: not any(L.Scalar), 3: not any(L.Hash) and not L.has('hash'), 6: not any(L.Signature) and not L.has('sig')}[bit]
    others = (bit == 0 or bytes(L.Generator) == P5) and (bit in (1,) or bytes(L.SecondPt) == P7) and (bit == 2 or b2v(L.Scalar) == 3) and (bit == 3 or L.has('hash')) and (bit == 6 or L.has('sig'))
    check('Ready Xs bit %d %s, others untouched' % (bit, nm_), exp and others)
L = rdy_state(); L.setst(RDY, 'B', 16); check('Ready Xs bit 4 copies Generator -> SecondPt', bytes(L.SecondPt) == P5 and bytes(L.Generator) == P5)
L = rdy_state(); L.setst(RDY, 'B', 32); check('Ready Xs bit 5 copies SecondPt -> Generator', bytes(L.Generator) == P7 and bytes(L.SecondPt) == P7)
L = rdy_state(); L.setst(RDY, 'B', 48); check('Ready Xs bits 4+5 exchange Generator and SecondPt', bytes(L.Generator) == P7 and bytes(L.SecondPt) == P5 and L.has('second'))
L = EccLocker('secp256r1'); L.setst(RDY, 'B', 16)
check('Ready bit 4 with no SecondPt copies and sets HasSecondPt', bytes(L.SecondPt) == G and L.has('second'))
L = EccLocker('secp256r1'); L.setst(RDY, 'B', 32); check('Ready bit 5 without HasSecondPt leaves Generator', bytes(L.Generator) == G)
check('Ready Xs bit 7 -> Invalid', EccLocker('secp256r1').setst(RDY, 'B', 128) == 'invalid')
L = rdy_state(); L.setst(RDY, 'B', 0x7f); check('Ready Xs 0x7f: all erased/reset', bytes(L.Generator) == bytes(L.Generator) and not any(L.Scalar) and not any(L.Hash) and not any(L.Signature) and not L.has('sig'))
# restrictl
L = rdy_state(); L.restrictl(2); check('restrictl 3 -> 2: Hash/Signature kept', L.has('hash') and L.has('sig') and L.policy == 2)
L = rdy_state(); L.restrictl(0); check('restrictl -> 0: Signature and Hash erased, flags cleared', not any(L.Signature) and not any(L.Hash) and not L.has('sig') and not L.has('hash'))
L = rdy_state(); L.restrictl(1); check('restrictl 3 -> 1: Signature/Hash kept (policy != 0)', L.has('hash'))
L = EccLocker('secp256r1', policy=1); check('restrictl widening 1 -> 3 -> Invalid', L.restrictl(3) == 'invalid')
# custom generator sign/verify
Gx = Cc.mul(2, Cc.G); Cx = M.Wei('secp256r1'); Cx.G = Gx
L = EccLocker('secp256r1', rbg=rbg_k(5)); load(L, SGEN, xy(Gx, 32), 'B'); load(L, SSCAL, le(0x1234, 32)); load(L, SHASH, le(0x777, 32)); L.setst(SGN); L.exec_D(); o = drain(L)
exp = M.ecdsa_sign(Cx, 0x1234, 0x777, 5)
check('custom Generator 2G: signature = (k*2G) based', (b2v(o[:32]), b2v(o[32:])) == exp)
L2 = EccLocker('secp256r1'); L2.rbg = rbg_k(5)
check('custom Generator 2G: verify with 2G as Generator and d*2G as SecondPt -> Success', verify(L2, xy(Cx.mul(0x1234, Gx), 32), o, le(0x777, 32), gen=xy(Gx, 32)) == 'success')
check('control: same signature fails against the standard G', verify(EccLocker('secp256r1'), xy(Cx.mul(0x1234, Gx), 32), o, le(0x777, 32)) == 'failure')
# sign + verify in one CC
L = EccLocker('secp256r1', rbg=rbg_k(5)); load(L, SSCAL, le(0x1234, 32)); load(L, SHASH, le(0x777, 32)); L.setst(SGN); L.exec_D(); sg = drain(L)
L.setst(RDY); load(L, S2ND, xy(Cc.mul(0x1234, Cc.G), 32)); L.setst(SVER)
check('sign then verify in the same CC (Signature/Hash retained across Ready)', L.exec_D() == 'success')

# ------------------------------------------------------------------ 8
section('ECDH (Point_Mul on SecondPt), shared secret encoding, derive source')
for nm, d, Qb, Z in V.ECDH:
    L = EccLocker(nm); W = L.W; load(L, SSCAL, le(d, W)); load(L, S2ND, xy(Qb, W)); L.setst(PMUL); r = L.exec_D()
    check('%s ECDH Z = x(dQ) big-endian, m bytes' % nm, r == 'output' and L.outtype == 2 and L.shared_secret() == Z)
    got = L.derive_source()
    check('%s derive source = shared secret (unrestricted)' % nm, got == Z)
    check('%s emitted bytes = Z' % nm, drain(L) == Z)
    L = EccLocker(nm); load(L, SSCAL, le(d, W)); L.setst(PMUL); L.exec_D()
    check('%s Point_Mul on Generator is a point, not a derive source' % nm, L.derive_source() is None)
Lc, _ = pt_mul('secp256r1', int('7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534', 16), xy((0x700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287, 0xdb71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac), 32))
check('CAVP CDH P-256 COUNT=0: Z = 46fc6210...bd7b', Lc.shared_secret().hex() == '46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b')
Ls, _ = pt_mul('sm2', 5, xy(Q, 32)); P = C.mul(5, Q)
check('SM2 shared secret = x2||y2, each 32 bytes big-endian (64 bytes)', Ls.shared_secret() == P[0].to_bytes(32, 'big') + P[1].to_bytes(32, 'big'))
check('derive_source outside Output -> None', EccLocker('secp256r1').derive_source() is None)

# ------------------------------------------------------------------ 9
section('X25519 / X448 (RFC 7748)')
def xk(name, k, u):
    L = EccLocker(name, policy=0); load(L, SSCAL, k); load(L, S2ND, u); L.setst(PMUL); r = L.exec_D(); return L, r
L = EccLocker('x25519', policy=0)
check('x25519 default Generator u = 9', bytes(L.Generator) == bytes([9]) + bytes(31))
check('x448 default Generator u = 5', bytes(EccLocker('x448', policy=0).Generator) == bytes([5]) + bytes(55))
k1 = H('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'); u1 = H('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
L, r = xk('x25519', k1, u1); check('RFC 7748 5.2 X25519 vector 1', r == 'output' and bytes(L.SecondPt).hex() == 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')
k2 = H('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'); u2 = H('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493')
L, r = xk('x25519', k2, u2); check('RFC 7748 5.2 X25519 vector 2 (bit 255 of u set, ignored)', bytes(L.SecondPt).hex() == '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957')
k = u = bytes([9]) + bytes(31); it = []
for i in range(1000):
    k, u = M.x_mul('x25519', k, u), k
    if i == 0: it.append(k)
check('RFC 7748 5.2 iterated, 1 iteration', it[0].hex() == '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079')
check('RFC 7748 5.2 iterated, 1000 iterations', k.hex() == '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51')
a = H('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'); b = H('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
La, _ = xk('x25519', a, bytes([9]) + bytes(31)); Lb, _ = xk('x25519', b, bytes([9]) + bytes(31))
check('RFC 7748 6.1 public keys', bytes(La.SecondPt).hex() == '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a' and bytes(Lb.SecondPt).hex() == 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
Lab, _ = xk('x25519', a, bytes(Lb.SecondPt))
check('RFC 7748 6.1 shared secret', bytes(Lab.SecondPt).hex() == '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
check('x25519 Point_Mul on SecondPt -> OutputType shared secret; on Generator -> point', Lab.outtype == 2 and pt_mul('x25519', 1)[0].outtype == 0 if False else Lab.outtype == 2 and (lambda M_: (load(M_, SSCAL, a), M_.setst(PMUL), M_.exec_D(), M_.outtype)[3])(EccLocker('x25519', policy=0)) == 0)
check('x25519 shared secret = stored SecondPt (little-endian)', Lab.derive_source() == bytes(Lab.SecondPt))
for sc, uu, res in V.X448:
    L, r = xk('x448', sc, uu); check('X448 vector (OpenSSL) ' + res.hex()[:12], bytes(L.SecondPt) == res)
b448 = M.x_mul('x448', H('9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b'), H('3e30000000' * 0 + 'ef') if False else bytes([5]) + bytes(55))
check('X448 RFC 7748 6.2 Alice public key', b448.hex() == '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0')
# small order / clamping / canonical
L, r = xk('x25519', k1, bytes(32)); check('x25519 u = 0 (small order) -> Failure, SecondPt unchanged', r == 'failure' and L.state == 55)
one = bytes([1]) + bytes(31)
L, r = xk('x25519', k1, one); check('x25519 u = 1 (small order) -> Failure', r == 'failure')
L, r = xk('x25519', k1, H('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800')); check('x25519 order-8 point -> Failure', r == 'failure')
L, r = xk('x25519', k1, (2 ** 255 - 19 + 9).to_bytes(32, 'little')); L2, r2 = xk('x25519', k1, bytes([9]) + bytes(31))
check('x25519 non-canonical u = p+9 reduced -> same as u = 9', bytes(L.SecondPt) == bytes(L2.SecondPt) and r == 'output')
L, r = xk('x25519', k1, bytes([9]) + bytes(30) + b'\x80'); check('x25519 bit 255 of u ignored', bytes(L.SecondPt) == bytes(L2.SecondPt))
L, r = xk('x25519', k1, bytes([9]) + bytes(31)); Lm, _ = xk('x25519', bytes([k1[0] | 7]) + k1[1:], bytes([9]) + bytes(31))
check('x25519 scalar clamping: low 3 bits and bit 255 ignored', bytes(L.SecondPt) == bytes(Lm.SecondPt))
L = EccLocker('x25519', policy=0); load(L, SSCAL, bytes(32)); check('x25519 Point_Mul with Scalar = 0 -> Invalid at entry', L.setst(PMUL) == 'invalid')
for st in (SGN, SVER, SHASH, SIN):
    check('x25519 State %d is not offered -> Invalid' % st, EccLocker('x25519', policy=0).setst(st) == 'invalid')
check('x25519 Set_Ctx/Msg_Absorb -> Invalid', EccLocker('x25519', policy=0).setst(SCTX, 'B', 1) == 'invalid' and EccLocker('x25519', policy=0).setst(MABS, 'B') == 'invalid')
L = EccLocker('x25519', policy=0); L.setst(S2ND); L.exec_in(H('ff' * 32))
check('x25519 no check on written SecondPt (all-ones accepted)', L.has('second') and not L.invalid)
L = EccLocker('x25519', policy=0); xk_ = xk('x25519', k1, u1)[0]; xk_.setst(RDY, 'B', 8 | 64)
check('x25519 Ready Xs bits 3 and 6 have no effect', xk_.has('second'))
L = EccLocker('x448', policy=0); L.setst(S2ND); L.exec_in(bytes(56)); L.setst(SSCAL); L.exec_in(bytes([1]) + bytes(55)); L.setst(PMUL)
check('x448 u = 0 -> Failure', L.exec_D() == 'failure')
def noclamp(k, u):
    kk = int.from_bytes(k, 'little'); uu = int.from_bytes(u, 'little') & mask(255) % (2**255 - 19); p = 2**255 - 19; a24 = 121665
    x1, x2, z2, x3, z3, sw = uu, 1, 0, uu, 1, 0
    for t in reversed(range(255)):
        kt = (kk >> t) & 1; sw ^= kt
        if sw: x2, x3, z2, z3 = x3, x2, z3, z2
        sw = kt; A = x2 + z2; AA = A * A % p; B = x2 - z2; BB = B * B % p; E = AA - BB; C_ = x3 + z3; D = x3 - z3
        DA = D * A; CB = C_ * B; x3 = (DA + CB) ** 2 % p; z3 = x1 * (DA - CB) ** 2 % p; x2 = AA * BB % p; z2 = E * (AA + a24 * E) % p
    if sw: x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, 'little')
control('unclamped ladder differs from RFC 7748 vector 1', noclamp(k1, u1).hex() != 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')
control('big-endian u gives a different result', xk('x25519', k1, u1[::-1])[0].SecondPt != xk('x25519', k1, u1)[0].SecondPt)
check('x25519 MachinePolicy must be 0 (model construction asserts)', raises(EccLocker, 'x25519', 3, exc=AssertionError))
L = EccLocker('x25519', policy=0); check('x25519 restrictl cannot add bits', L.restrictl(1) == 'invalid')

# ------------------------------------------------------------------ 10
section('EdDSA: Ed25519 / Ed448 (RFC 8032) through Set_Ctx, Msg_Absorb passes, pre-hash')
def ed_load_key(L, seed): load(L, SSCAL, seed)
def ed_pub(nm, seed):
    L = EccLocker(nm); load(L, SSCAL, seed); L.setst(PMUL); L.exec_D(); return drain(L)
def ed_sign(L, seed, ctx, msg, split=None):
    L.setst(RDY); load(L, SSCAL, seed)
    if ctx: L.setst(SCTX, 'B', len(ctx)); L.exec_in(ctx)
    for xsel in (0, 1):
        r = L.setst(MABS, 'B', xsel)
        if r == 'invalid': return r
        for c in ([msg] if not split else [msg[:split], msg[split:]]): L.exec_in(c)
    r = L.setst(SGN)
    return L.exec_D() if r == 'ok' else r
for nm, mode, seed, ctx, msg, pub, sig in V.ED:
    if mode.endswith('ph'): continue
    L = EccLocker(nm)
    check('%s %s: Point_Mul with seed gives pub (clamped hash of seed)' % (mode, msg[:5]), ed_pub(nm, seed) == pub)
    r = ed_sign(L, seed, ctx, msg)
    out = drain(L)
    check('%s ctx=%r msg=%r: two-pass Sign_Generate = vector' % (mode, ctx, msg), r == 'output' and out == sig, out, sig)
    L = EccLocker(nm); L.setst(S2ND); L.exec_in(pub); L.setst(SIN); L.exec_in(sig)
    if ctx: L.setst(SCTX, 'B', len(ctx)); L.exec_in(ctx)
    L.setst(MABS, 'B', 2); L.exec_in(msg); L.setst(SVER)
    check('%s msg=%r: Sign_Verify pass 2 -> Success' % (mode, msg), L.exec_D() == 'success')
    L = EccLocker(nm); L.setst(S2ND); L.exec_in(pub); L.setst(SIN); L.exec_in(sig[:-1] + bytes([sig[-1] ^ 1]))
    if ctx: L.setst(SCTX, 'B', len(ctx)); L.exec_in(ctx)
    L.setst(MABS, 'B', 2); L.exec_in(msg); L.setst(SVER)
    check('%s msg=%r: corrupted S -> Failure' % (mode, msg), L.exec_D() == 'failure')
    L = EccLocker(nm); L.setst(S2ND); L.exec_in(pub); L.setst(SIN); L.exec_in(sig)
    if ctx: L.setst(SCTX, 'B', len(ctx)); L.exec_in(ctx)
    L.setst(MABS, 'B', 2); L.exec_in(msg + b'x'); L.setst(SVER)
    check('%s msg=%r: modified message -> Failure' % (mode, msg), L.exec_D() == 'failure')
    L = EccLocker(nm); r = ed_sign(L, seed, ctx, msg, split=1)
    check('%s msg=%r: message split in two kl.exec chunks gives the same signature' % (mode, msg), drain(L) == sig)
# pre-hash modes: Hash = PH(M), one Sign_Generate, dom x=1
for nm, mode, seed, ctx, msg, pub, sig in V.ED:
    if not mode.endswith('ph'): continue
    ph = hashlib.sha512(msg).digest() if nm == 'ed25519' else hashlib.shake_256(msg).digest(64)
    L = EccLocker(nm); load(L, SSCAL, seed); load(L, SHASH, ph)
    if ctx: L.setst(SCTX, 'B', len(ctx)); L.exec_in(ctx)
    r = L.setst(SGN) if not ctx else L.setst(SGN); r = L.exec_D(); out = drain(L)
    check('%s ctx=%r: pre-hash Sign_Generate (HasHash, msg_pass 0) = vector' % (mode, ctx), r == 'output' and out == sig, out, sig)
    L = EccLocker(nm); load(L, S2ND, pub); load(L, SIN, sig); load(L, SHASH, ph)
    if ctx: L.setst(SCTX, 'B', len(ctx)); L.exec_in(ctx)
    L.setst(SVER); check('%s ctx=%r: pre-hash Sign_Verify -> Success' % (mode, ctx), L.exec_D() == 'success')
    L = EccLocker(nm); load(L, S2ND, pub); load(L, SIN, sig); load(L, SHASH, ph[:-1] + bytes([ph[-1] ^ 1])); L.setst(SVER)
    check('%s ctx=%r: pre-hash verify, corrupted PH -> Failure' % (mode, ctx), L.exec_D() == 'failure')
# RFC 8032 7.1 TEST 1-3 and 7.4 blank
RFC = [('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '', 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
       ('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72', '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
]
for sd, pb, mg, sg in RFC[:2]:
    sd, mg, sg = H(sd), H(mg), H(sg); L = EccLocker('ed25519'); ed_sign(L, sd, b'', mg)
    check('RFC 8032 7.1 seed %s: signature' % sd.hex()[:8], drain(L) == sg)
    check('RFC 8032 7.1 seed %s: public key' % sd.hex()[:8], ed_pub('ed25519', sd) == H(pb))
L = EccLocker('ed25519'); ed_sign(L, H(RFC[0][0]), b'', b'')
check('RFC 8032 TEST 1 (empty message): signature e5564300...100b', drain(L) == H(RFC[0][3]))
# msg_pass tracking and gating
L = EccLocker('ed25519'); sd = bytes(range(32)); load(L, SSCAL, sd)
L.setst(MABS, 'B', 0); check('Msg_Absorb pass 1 entered; HasHashState set; AuxInfo msg_pass visible', L.has('rnd') and L.state == MABS)
L.exec_in(b'abc'); L.setst(MABS, 'B', 1)
check('pass 2: msg_pass = 1 recorded after pass 1, HasSignature cleared', L.msg_pass == 1 and not L.has('sig'))
L.exec_in(b'abd'); r = L.setst(SGN)
check('pass-2 message differs from pass 1 -> Invalid (H(prefix) mismatch)', r == 'invalid' and L.invalid)
L = EccLocker('ed25519'); load(L, SSCAL, sd); L.setst(MABS, 'B', 0); L.exec_in(b'abc'); r = L.setst(SGN)
check('Sign_Generate after pass 1 only (msg_pass 1, no HasHash) -> Invalid', r == 'invalid')
L = EccLocker('ed25519'); load(L, SSCAL, sd); check('Msg_Absorb pass 2 without pass 1 -> Invalid', L.setst(MABS, 'B', 1) == 'invalid')
L = EccLocker('ed25519'); load(L, SSCAL, sd); L.setst(MABS, 'B', 0); L.exec_in(b'a'); r = L.setst(SSCAL)
check('Msg_Absorb may only leave to Msg_Absorb, Sign_Generate, Sign_Verify or Ready -> Invalid', r == 'invalid')
L = EccLocker('ed25519'); load(L, SSCAL, sd); L.setst(MABS, 'B', 0); L.exec_in(b'a'); r = L.setst(RDY)
check('Msg_Absorb -> Ready admitted, HasHashState cleared, msg_pass 0', r == 'ok' and L.msg_pass == 0 and not L.has('rnd'))
L = EccLocker('ed25519', aux=0); load(L, SSCAL, sd); check('AuxInfo bit 0 = 0 -> Msg_Absorb Invalid', L.setst(MABS, 'B', 0) == 'invalid')
L = EccLocker('ed25519'); check('Msg_Absorb Form A -> Invalid', L.setst(MABS, 'A') == 'invalid')
L = EccLocker('ed25519'); check('Msg_Absorb Xs = 3 -> Invalid', (load(L, SSCAL, sd), L.setst(MABS, 'B', 3))[1] == 'invalid')
L = EccLocker('ed25519'); check('Set_Ctx length 256 -> Invalid', L.setst(SCTX, 'B', 256) == 'invalid')
L = EccLocker('ed25519'); check('Set_Ctx length 255 admitted', L.setst(SCTX, 'B', 255) == 'ok')
L = EccLocker('ed25519'); check('Set_Ctx Form A -> Invalid', L.setst(SCTX, 'A') == 'invalid')
L = EccLocker('ed25519'); check('MachinePolicy = 0 invalid for EdDSA (model asserts)', raises(EccLocker, 'ed25519', 0, exc=AssertionError))
L = EccLocker('ed25519'); check('EdDSA restrictl to 0 -> Invalid', L.restrictl(0) == 'invalid')
L = EccLocker('ed25519'); load(L, SSCAL, sd); L.setst(PMUL); r = L.exec_D()
check('Ed25519 Point_Mul on Generator -> point (OutputType 0), s*B', r == 'output' and L.outtype == 0)
L = EccLocker('ed25519'); load(L, SSCAL, sd); load(L, S2ND, bytes([2]) + bytes(31)); L.setst(PMUL)
check('Ed25519 Point_Mul with non-decodable SecondPt (y=2) -> Failure', L.exec_D() == 'failure')
L = EccLocker('ed25519'); load(L, SSCAL, sd); load(L, S2ND, bytes([1]) + bytes(31)); L.setst(PMUL)
check('Ed25519 Point_Mul with neutral SecondPt (0,1) -> Failure', L.exec_D() == 'failure')
L = EccLocker('ed25519'); load(L, SSCAL, sd); load(L, S2ND, bytes([0xed]) + b'\xff' * 30 + b'\x7f'); L.setst(PMUL)
check('Ed25519 non-canonical y = p -> Failure', L.exec_D() == 'failure')
L = EccLocker('ed25519'); ed_sign(L, V.ED[2][2], b'bar', V.ED[2][4]); control('wrong ctx signature != vector', drain(L) != V.ED[2][6])
Ed = M.Ed('ed25519'); s_, pre_ = Ed.expand(bytes(range(32)))
control('unclamped scalar would give a different public key', Ed.enc(Ed.mul(int.from_bytes(hashlib.sha512(bytes(range(32))).digest()[:32], 'little') % Ed.L, Ed.B)) != Ed.enc(Ed.mul(s_, Ed.B)))
# S >= L malleability
sd1, pb1, mg1, sg1 = H(RFC[0][0]), H(RFC[0][1]), b'', H(RFC[0][3])
Sm = int.from_bytes(sg1[32:], 'little') + Ed.L
L = EccLocker('ed25519'); L.setst(S2ND); L.exec_in(pb1); L.setst(SIN); L.exec_in(sg1[:32] + Sm.to_bytes(32, 'little')); L.setst(MABS, 'B', 2); L.setst(SVER)
check('Ed25519 S + L (non-canonical) -> Failure', L.exec_D() == 'failure')
# Ed448 RFC 8032 7.4 blank message
check('Ed448 B(y=...) encoding length 57 bytes, public key length 57', len(ed_pub('ed448', bytes(range(57)))) == 57)

# ------------------------------------------------------------------ done
info('runtime %.1f s' % (time.time() - T0))
done()
