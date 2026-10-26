#!/usr/bin/env pypy3.12
"""KAT for AES128_GCM_SIV (and the AES-256 key size) Machine, RFC 8452.  Vectors: RFC 8452 Appendix A (POLYVAL) and
Appendix C.1/C.2; reference aead_ref.py.  Run: cd src && pypy3.12 kat/gcmsiv-kat.py"""
import random
from common import *
from aead_model import *
from aead_util import *
import aead_ref as R

H = bytes.fromhex
rnd = random.Random(9)
RB = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
def inv(m): return m.st == INV
NM = {16: 'AES128', 32: 'AES256'}
def mk(key, **kw): return GCMSIV(key, cipher=NM[len(key)], **kw)

section('POLYVAL and key derivation (RFC 8452 Appendix A, C)')
Hh = H('25629347589242761d31f826ba4b757b')
X = H('4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362')
want = H('f7a3b47b846119fae5b7866cf5e5b77e')
check('RFC 8452 App. A POLYVAL example, reference', R.polyval(Hh, X) == want)
t = 0
for i in (0, 16): t = montmul(t ^ b2v(X[i:i + 16]), b2v(Hh))
check('RFC 8452 App. A POLYVAL example, common.montmul chain', v2b(t, 16) == want)
k1, n1 = H('01' + '00' * 15), H('03' + '00' * 11)
m = mk(k1); m.setst(SAV, 'C', inp=b2v(n1))
ek, ak = R.siv_keys('AES128', k1, n1)
check('C.1 message-authentication key (auth_key) from key derivation', v2b(m.ak, 16) == ak and ak == H('d9b360279694941ac5dbc6987ada7377'))
check('C.1 message-encryption key (enc_key)', m.ek == ek and ek == H('4004a0dcd862f2a57360219d2d44ef6c'))
k2, n2 = H('01' + '00' * 31), n1
m = mk(k2); m.setst(SAV, 'C', inp=b2v(n2)); ek, ak = R.siv_keys('AES256', k2, n2)
check('C.2 auth_key and enc_key (32 bytes) equal the reference', v2b(m.ak, 16) == ak and m.ek == ek and len(m.ek) == 32)

V1 = [  # (key,nonce,aad,pt,ct,tag) RFC 8452 C.1 and C.2 (as published; aad empty unless given)
 (k1, n1, b'', b'', b'', 'dc20e2d83f25705bb49e439eca56de25'),
 (k1, n1, b'', H('0100000000000000'), H('b5d839330ac7b786'), '578782fff6013b815b287c22493a364c'),
 (k1, n1, b'', H('01' + '00' * 11), H('7323ea61d05932260047d942'), 'a4978db357391a0bc4fdec8b0d106639'),
 (k1, n1, b'', H('01' + '00' * 15), H('743f7c8077ab25f8624e2e948579cf77'), '303aaf90f6fe21199c6068577437a0c4'),
 (k2, n2, b'', b'', b'', '07f5f4169bbf55a8400cd47ea6fd400f'),
 (k2, n2, b'', H('0100000000000000'), H('c2ef328e5c71c83b'), '843122130f7364b761e0b97427e3df28'),
 (k2, n2, b'', H('01' + '00' * 11), H('9aab2aeb3faa0a34aea8e2b1'), '8ca50da9ae6559e48fd10f6e5c9ca17e'),
 (k2, n2, b'', H('01' + '00' * 15), H('85a01b63025ba19b7fd3ddfc033b3e76'), 'c9eac6fa700942702e90862383c6c366'),
]
section('Machine: RFC 8452 vectors (encrypt, decrypt, corrupted tag/ciphertext)')
for i, (k, n, a, p, c, t) in enumerate(V1):
    nm = NM[len(k)]; rc, rt = R.siv_enc(nm, k, n, a, p)
    check('ref vector %d (AES-%d, %d bytes) matches RFC' % (i, 8 * len(k), len(p)), (rc, rt) == (c, H(t)))
    gc, gt = siv_enc(mk(k), n, a, p)
    check('Machine vector %d encrypt: ciphertext and tag' % i, (gc, gt) == (c, H(t)))
    pp, ok = siv_dec(mk(k), n, a, c, H(t))
    check('Machine vector %d decrypt: Success, plaintext' % i, ok and pp == p)
    m = mk(k); _, ok = siv_dec(m, n, a, c, bytes([H(t)[0] ^ 1]) + H(t)[1:])
    check('Machine vector %d corrupted tag: Failure' % i, m.st == FAILURE)
    if c:
        m = mk(k); _, ok = siv_dec(m, n, a, bytes([c[0] ^ 1]) + c[1:], H(t))
        check('Machine vector %d corrupted ciphertext: Failure' % i, m.st == FAILURE)

section('differential vs reference: AD / plaintext lengths 0..2 blocks and partials, both key sizes')
bad = 0; cnt = 0
for kl in (16, 32):
    for al in (0, 1, 15, 16, 17, 32, 33):
        for pl in (0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 48):
            k, n, a, p = RB(kl), RB(12), RB(al), RB(pl)
            r = R.siv_enc(NM[kl], k, n, a, p); g = siv_enc(mk(k), n, a, p); cnt += 1
            bad += g != r
            pp, ok = siv_dec(mk(k), n, a, r[0], r[1]); bad += not (ok and pp == p)
check('%d random-key messages: encrypt equals reference, decrypt round trips (bad=%d)' % (cnt, bad), bad == 0)

def setup(k=k1, n=n1, a=b'', to=ABSORB, dec=False, **kw):
    m = mk(k, **kw); m.setst(SAV, 'C', inp=b2v(n))
    if dec: m.setst(SAV2, 'C', inp=0x1234)
    m.setst(ABSORB); return m
def enc_at(st, **kw):
    m = setup(**kw)
    if st == ABSORB: return m
    m.setst(ETF, 'A')
    if st == ETF: return m
    m.exec('A', 0, 128)
    if st == ENC: return m
    m.setst(ELB, 'B', 16); return m
def dec_at(st, **kw):
    m = setup(dec=True, **kw)
    if st == ABSORB: return m
    m.setst(DEC)
    if st == DEC: return m
    if st == DLB: m.setst(DLB, 'B', 16); return m
    m.setst(DTF, 'A'); return m

section('Set_Aux_Value / Set_Aux_Value_2')
m = mk(k1); m.setst(SAV, 'C', inp=b2v(n1) | (0xffff << 96))
check('Set_Aux_Value: only INPUT[95:0] is the nonce', m.nonce == b2v(n1))
m = mk(k1); m.setst(SAV, 'D'); check('Set_Aux_Value Form D setst: nonce 0 accepted', m.st == SAV and m.nonce == 0)
m = mk(k1); m.setst(SAV, 'B', 8); check('Form B setst into Set_Aux_Value: Invalid', inv(m))
m = mk(k1); m.setst(SAV, 'C', inp=1); m.setst(SAV, 'C', inp=1); check('same-State setst Set_Aux_Value: Invalid', inv(m))
m = mk(k1); m.setst(SAV, 'C', inp=1); m.setst(SAV2, 'C', inp=2); m.setst(SAV2, 'C', inp=2); check('same-State setst Set_Aux_Value_2: Invalid', inv(m))
m = mk(k1); m.setst(SAV2, 'C', inp=1); check('Ready -> Set_Aux_Value_2 directly: Invalid', inv(m))
m = mk(k1); m.setst(ABSORB); check('Ready -> Hash_Absorb without nonce: Invalid', inv(m))
m = mk(k1); m.setst(SAV, 'C', inp=1); m.setst(SAV2, 'C', inp=b2v(bytes(range(16))))
check('Set_Aux_Value_2: INPUT[127:0] is the expected tag (SIV)', m.siv == b2v(bytes(range(16))))
m = mk(k1); m.setst(SAV, 'C', inp=1); m.exec('B', 0, 128); check('kl.exec in Set_Aux_Value: Invalid (no exec)', inv(m))
m = mk(k1, policy=2); m.setst(SAV, 'C', inp=1); m.setst(SAV2, 'C', inp=1); m.setst(ABSORB)
check('decryption-only policy: Set_Aux_Value_2 -> Hash_Absorb', m.st == ABSORB)
m = setup(); m.setst(SAV, 'C', inp=1); check('Hash_Absorb -> Set_Aux_Value: Invalid', inv(m))

section('Forms, transitions and policy')
check('Hash_Absorb Form A kl.exec: Invalid', inv((lambda m: (m.exec('A', 0, 128), m)[1])(setup())))
check('Hash_Absorb Form C kl.exec: Invalid', inv((lambda m: (m.exec('C', 0, 128), m)[1])(setup())))
check('Enc_Tag_Finalize Form C setst: Invalid (Form A expected)', inv((lambda m: (m.setst(ETF, 'C', inp=1), m)[1])(setup())))
check('Enc_Tag_Finalize Form B setst: Invalid', inv((lambda m: (m.setst(ETF, 'B', 8), m)[1])(setup())))
check('Encrypt before Enc_Tag_Finalize (Hash_Absorb -> Encrypt): Invalid', inv((lambda m: (m.setst(ENC), m)[1])(setup())))
check('Encrypt after Enc_Tag_Finalize: Form A setst, ok', enc_at(ENC).st == ENC)
check('Encrypt Form B kl.exec: Invalid', inv((lambda m: (m.exec('B', 0, 128), m)[1])(enc_at(ENC))))
check('Dec_Tag_Finalize Form B kl.exec: single block, Success/Failure', (lambda m: (m.exec('B', 0, 128), m.st in (SUCCESS, FAILURE))[1])(dec_at(DTF)))
check('Dec_Tag_Finalize Form A kl.exec: Invalid', inv((lambda m: (m.exec('A', 0, 128), m)[1])(dec_at(DTF))))
check('Dec_Tag_Finalize KLLEN=64: Invalid (granularity)', inv((lambda m: (m.exec('B', 0, 64), m)[1])(dec_at(DTF))))
check('Enc_Tag_Finalize KLLEN=64: Invalid', inv((lambda m: (m.exec('A', 0, 64), m)[1])(enc_at(ETF))))
check('Hash_Absorb -> Decrypt without Set_Aux_Value_2 is allowed (policy)', (lambda m: (m.setst(DEC), m.st == DEC)[1])(setup()))
check('Decrypt -> Enc_Last_Block: Invalid', inv((lambda m: (m.setst(ELB, 'B', 8), m)[1])(dec_at(DEC))))
check('Encrypt -> Dec_Last_Block: Invalid', inv((lambda m: (m.setst(DLB, 'B', 8), m)[1])(enc_at(ENC))))
check('Encrypt -> Enc_Tag_Finalize again: Invalid', inv((lambda m: (m.setst(ETF, 'A'), m)[1])(enc_at(ENC))))
check('Encrypt -> Encrypt same State: Invalid (GR21)', inv((lambda m: (m.setst(ENC), m)[1])(enc_at(ENC))))
check('setst Ready from any State', all((lambda m: (m.setst(READY), m.st == READY)[1])(f()) for f in (lambda: enc_at(ENC), lambda: dec_at(DEC), lambda: setup())))
check('Success: setst Encrypt Invalid', inv((lambda m: (m.exec('B', 0, 128), m.setst(ENC), m)[2])(dec_at(DTF))))
for pol in (1, 2):
    for nm, mkf, st, isenc in (('Enc_Tag_Finalize', enc_at, ETF, True), ('Encrypt', enc_at, ENC, True), ('Enc_Last_Block', enc_at, ELB, True),
                               ('Decrypt', dec_at, DEC, False), ('Dec_Last_Block', dec_at, DLB, False), ('Dec_Tag_Finalize', dec_at, DTF, False)):
        try: m = mkf(st, policy=pol); ok = m.st == st
        except Exception: ok = False
        allowed = (pol == 1) == isenc
        check('MachinePolicy=%d, %s: %s' % (pol, nm, 'allowed' if allowed else 'Invalid'), ok if allowed else inv(m))
check('zero MachinePolicy rejected', raises(mk, k1, policy=0, exc=ValueError))

section('Counter, last blocks, interruption')
def ek_stream(m, siv, n): return [m.EE(cat((1, 1), (sl(siv, 126, 32), 95), ((sl(siv, 31, 0) + i) % 2**32, 32))) for i in range(n)]
k, n = RB(16), RB(12); a, p = RB(20), RB(80)
rc, rt = R.siv_enc('AES128', k, n, a, p)
m = mk(k); m.setst(SAV, 'C', inp=b2v(n)); m.setst(ABSORB); feed(m, 'B', a); feed(m, 'B', p); m.setst(ETF, 'A')
tag = v2b(m.exec('A', lenblk_siv(80, 20), 128), 16)  # the kl.exec itself enters Encrypt
o = m.exec('A', b2v(p), 640, halt_at=32)
check('Encrypt halted after 2 blocks: klstart=32, prefix committed', m.klstart == 32 and v2b(o, 80)[:32] == rc[:32] and tag == rt)
o2 = m.exec('A', b2v(p), 640, klstart=32)
check('resumed Encrypt: remaining ciphertext; counter continues', v2b(o2, 80)[32:] == rc[32:] and m.ctr == 5)
m = enc_at(ENC); m.exec('A', 0, 640); check('multi-block kl.exec of 5 blocks: ctr = 5', m.ctr == 5)
m = enc_at(ENC); m.ctr = 2**32 - 1; m.exec('A', 0, 128); check('ctr 2^32-1 -> 2^32 (last block): ok', m.st == ENC and m.ctr == 2**32)
m.exec('A', 0, 128); check('ctr == 2^32: Invalid', inv(m))
m = enc_at(ENC); m.ctr = 2**32 - 1; m.exec('A', 0, 256); check('2-block kl.exec crossing 2^32: Invalid', inv(m))
m = enc_at(ENC); m.ctr = 2**32 - 1; m.setst(ELB, 'B', 8); m.exec('A', 0, 128); check('Enc_Last_Block at ctr 2^32-1 still fine', m.st == ENC or m.st == ELB)
for xs in (0, 1, 7, 60, 100, 128, 136):
    m = enc_at(ENC); m.setst(ELB, 'B', xs) if xs else m.setst(ELB, 'A'); check('Enc_Last_Block Xs=%d: Invalid' % xs, inv(m))
    m = dec_at(DEC); m.setst(DLB, 'B', xs) if xs else m.setst(DLB, 'A'); check('Dec_Last_Block Xs=%d: Invalid' % xs, inv(m))
for xs in (8, 64, 120):
    m = enc_at(ENC); m.setst(ELB, 'B', xs); o = m.exec('A', mask(128), 128)
    check('Enc_Last_Block Xs=%d: output bits above Xs are zero' % xs, o >> xs == 0 and m.lbl == 0)
for kl in (64, 127):
    m = enc_at(ENC); m.setst(ELB, 'B', 16); m.exec('A', 0, kl) if kl >= 16 else None; check('Enc_Last_Block exec KLLEN=%d, lbl 16: accepted (>=lbl)' % kl, m.st != INV)
m = enc_at(ENC); m.setst(ELB, 'B', 32); m.exec('A', 0, 16); check('Enc_Last_Block exec KLLEN < last_block_len: Invalid', inv(m))
m = enc_at(ENC); m.setst(ELB, 'B', 32); m.exec('A', 0, 128); m.exec('A', 0, 128); check('second last-block kl.exec: Invalid', inv(m))
m = dec_at(DEC); m.exec('A', 0, 130); check('Decrypt KLLEN not multiple of 128: Invalid', inv(m))
m = enc_at(ENC); m.exec('A', 0, 128, klstart=8); check('Encrypt klstart=8 (not an interruption point): Invalid', inv(m))
m = enc_at(ENC); o = m.exec('A', 0, 128, klstart=16); check('Encrypt klstart >= length: empty window, no change', m.st == ENC and m.ctr == 0)
m = setup(); feed(m, 'B', RB(33)); check('Hash_Absorb AD zero-padded to 16 bytes (33 bytes, 3 blocks)', m.st == ABSORB)
m = setup(); m.exec('B', 0, 100); check('Hash_Absorb KLLEN=100: Invalid', inv(m))

section('Decrypt path details (absorbs plaintext; last block zero-padded; tag compared)')
k, n = RB(32), RB(12); a, p = RB(7), RB(37); rc, rt = R.siv_enc('AES256', k, n, a, p)
g, ok = siv_dec(mk(k), n, a, rc, rt); check('AES-256, 37-byte plaintext, 7-byte AD: Success', ok and g == p)
g, ok = siv_dec(mk(k), n, RB(7), rc, rt); check('different AD: Failure', not ok)
g, ok = siv_dec(mk(k), RB(12), a, rc, rt); check('different nonce: Failure', not ok)
m = mk(k); siv_dec(m, n, a, rc, bytes(16)); check('zero tag: Failure State', m.st == FAILURE)
m = dec_at(DEC); m.setst(DLB, 'B', 16); m.setst(DTF, 'A'); check('leaving Dec_Last_Block with last_block_len != 0 before exec: Invalid (MR10 item 5)', inv(m))
m = dec_at(DEC); m.setst(DTF, 'A'); check('Form A bypass of Dec_Last_Block (zero length) is admitted', m.st == DTF)
m = dec_at(DLB); m.exec('A', 0, 128); check('Dec_Last_Block kl.exec transitions to Dec_Tag_Finalize at once (MR10 item 3)', m.st == DTF)
m = dec_at(DLB); m.exec('A', 0, 128); m.setst(DTF, 'A'); check('no kl.setst needed or admitted after the Dec_Last_Block kl.exec', inv(m))
m = enc_at(ELB); m.exec('A', 0, 128); check('Enc_Last_Block has no successor: kl.exec keeps the State, last_block_len 0', m.st == ELB and m.lbl == 0)
m = enc_at(ELB); m.setst(ENC); check('leaving Enc_Last_Block with last_block_len != 0 before exec: Invalid', inv(m))

section('Serialized Content')
k, n = RB(16), RB(12); a, p = RB(16), RB(48); rc, rt = R.siv_enc('AES128', k, n, a, p)
m = mk(k); m.setst(SAV, 'C', inp=b2v(n)); m.setst(ABSORB); feed(m, 'B', a); feed(m, 'B', p); m.setst(ETF, 'A')
m.exec('A', lenblk_siv(48, 16), 128); m.exec('A', b2v(p), 128)
sc, w = m.export(); f = GCMSIV.unpack(sc, (128, 96, 32, 128, 128, 16))
check('SC width = key + 96 + 32 + 128 + 128 + 16', w == 128 + 400)
check('SC fields: key, nonce, ctr[31:0]=1, SIV = tag, tmp = tag, flags 0', f[0] == b2v(k) and f[1] == b2v(n) and f[2] == 1 and f[3] == b2v(rt) and f[4] == b2v(rt) and f[5] == 0)
q = GCMSIV.from_sc(ENC, sc, 16)
o = q.exec('A', b2v(p[16:]), 256)
check('import mid-Encrypt (derived keys recomputed), continue: ciphertext == reference', v2b(o, 32) == rc[16:48])
m = enc_at(ENC); m.ctr = 2**32 + 3; m.lbl = 5; sc, w = m.export(); f = GCMSIV.unpack(sc, (128, 96, 32, 128, 128, 16))
check('SC: ctr bit 32 in bit 15 of the last field, last_block_len in bits 6:0, ctr[31:0] separate', f[2] == 3 and f[5] == (1 << 15 | 5))
q = GCMSIV.from_sc(ENC, sc, 16); check('import restores ctr (33 bits) and last_block_len', q.ctr == 2**32 + 3 and q.lbl == 5)
m = dec_at(DEC); sc, w = m.export(); f = GCMSIV.unpack(sc, (128, 96, 32, 128, 128, 16)); check('SC in Decrypt: SIV = expected tag', f[3] == 0x1234)
q = GCMSIV.from_sc(DEC, sc, 16); o = q.exec('A', 0, 128); check('import into Decrypt continues', q.st == DEC)
q = GCMSIV.from_sc(READY, mk(k).export()[0], 16); check('import Ready', q.st == READY)
m = mk(RB(32)); check('AES-256 SC width = 256 + 400', m.export()[1] == 656)

section('kl.derive into the key')
k, k2, n = RB(16), RB(16), RB(12)
m = mk(k); m.derive_dest(k2); check('derive in Ready: new key used (nonce-derived keys follow)', siv_enc(m, n, b'a', b'b' * 20) == siv_enc(mk(k2), n, b'a', b'b' * 20))
m = setup(); m.derive_dest(k2); check('derive in Hash_Absorb: Invalid', inv(m))
m = mk(k); m.setst(SAV, 'C', inp=1); m.derive_dest(k2); check('derive in Set_Aux_Value: Invalid', inv(m))
m = mk(k); m.derive_dest(RB(32)); check('derive wrong size: Invalid', inv(m))
m = mk(k); m.derive_dest(k2); m.setst(SAV, 'C', inp=1); check('after derive, Ready usable', m.st == SAV)

section('kl.restrictl')
m = mk(k); m.restrict(1); check('restrict 3 -> 1 (encrypt only)', m.st == READY and m.policy == 1)
m.restrict(2); check('restrict to disjoint (policy would be 0): Invalid (GR25)', inv(m))
m = mk(k); m.restrict(0); check('restrict to 0: Invalid', inv(m))
m = mk(k); m.restrict(0xff); check('restrict with a superset mask leaves the policy', m.policy == 3)

section('negative controls')
k, n = k1, n1
rc, rt = R.siv_enc('AES128', k, n, b'', H('01' + '00' * 15))
control('RFC vector: wrong nonce gives a different tag', R.siv_enc('AES128', k, bytes(12), b'', H('01' + '00' * 15))[1] != rt)
control('stream block without the forced top bit differs', mk(k).__class__ is GCMSIV and (lambda m: (m.setst(SAV, 'C', inp=b2v(n)), m.EE(0) != m.EE(1 << 127))[1])(mk(k)))
control('POLYVAL differs from GHASH on the same input', ghash_mul(b2v(X[:16]), b2v(Hh)) != montmul(b2v(X[:16]), b2v(Hh)))
m = setup(); m.setst(SAV, 'C', inp=0)
control('Set_Aux_Value not re-enterable from Hash_Absorb', inv(m))

section('ported from the old KAT: empty window, Ready keeps last_block_len, no Zklio substitution')
m = GCMSIV(bytes(16)); m.setst(SAV, 'C', inp=1); m.setst(ABSORB); m.exec('B', 0, 0); check('KLLEN = 0 in Hash_Absorb: empty window, state kept', m.st == ABSORB)
m = GCMSIV(bytes(16)); m.setst(SAV, 'C', inp=1); m.setst(ABSORB); m.exec('D', 0, 128); check('Form D is a wrong Form here (the old KAT models no Zklio)', m.st == INV)
m = GCMSIV(bytes(16)); m.setst(SAV, 'C', inp=1); m.setst(ABSORB); m.setst(ETF, 'A'); m.exec('A', 0, 128); m.setst(ELB, 'B', 64); m.exec('A', 0, 64); m.exec('A', 0, 0); check('KLLEN = 0 in Enc_Last_Block after its kl.exec (empty final input): Invalid (MR10)', m.st == INV)
done()
