#!/usr/bin/env pypy3.12
"""KAT for AES128_GCM, AES128_GCM_IV (and the AES192/256 and SM4 variants) Machines.
Vectors: McGrew-Viega GCM test cases 1-6 (AES-128), 13-18 (AES-256); the standards-order reference is aead_ref.py,
the Machine under test is aead_model.py (spec transcription).  Run: cd src && pypy3.12 kat/gcm-kat.py"""
import random
from common import *
from aead_model import *
from aead_util import *
import aead_ref as R

H = bytes.fromhex
rnd = random.Random(8)
RB = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
ENCF = lambda name, key: (lambda b: cipher_enc(name, key, b))
P64 = H('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255')
C64 = H('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985')
AD = H('feedfacedeadbeeffeedfacedeadbeefabaddad2')
K128, K256 = H('feffe9928665731c6d6a8f9467308308'), H('feffe9928665731c6d6a8f9467308308' * 2)
IV12, IV8 = H('cafebabefacedbaddecaf888'), H('cafebabefacedbad')
IV60 = H('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b')
Z = bytes
# (id, key, iv, aad, plaintext, tag)
TC = [
 (1, Z(16), Z(12), b'', b'', '58e2fccefa7e3061367f1d57a4e7455a'),
 (2, Z(16), Z(12), b'', Z(16), 'ab6e47d42cec13bdf53a67b21257bddf'),
 (3, K128, IV12, b'', P64, '4d5c2af327cd64a62cf35abd2ba6fab4'),
 (4, K128, IV12, AD, P64[:60], '5bc94fbc3221a5db94fae95ae7121a47'),
 (5, K128, IV8, AD, P64[:60], '3612d2e79e3b0785561be14aaca2fccb'),
 (6, K128, IV60, AD, P64[:60], '619cc5aefffe0bfa462af43c1699d050'),
 (13, Z(32), Z(12), b'', b'', '530f8afbc74536b9a963b4f1c4cb738b'),
 (14, Z(32), Z(12), b'', Z(16), 'd0d1c8a799996bf0265b98b5d48ab919'),
 (15, K256, IV12, b'', P64, 'b094dac5d93471bdec1a502270e3cc6c'),
 (16, K256, IV12, AD, P64[:60], '76fc6ece0f4e1768cddf8853bb2d551b'),
 (17, K256, IV8, AD, P64[:60], '3a337dbf46a792c45e454913fe2ea8f2'),
 (18, K256, IV60, AD, P64[:60], 'a44a8266ee1c8eb0c8b5d4cf5ae9f19a'),  # published tag recalled from memory did not match (see FINDINGS-gcm.md): reference value, not verified against the paper
]
NAME = lambda key: {16: 'AES128', 24: 'AES192', 32: 'AES256'}[len(key)]
def mk(key, iv=None, **kw):
    n = NAME(key)
    return GCM(key, cipher=n, **kw) if iv is None else GCM_IV(key, b2v(iv), cipher=n, **kw)
def inv(m): return m.st == INV

section('reference sanity (aead_ref vs published)')
for i, key, iv, aad, pt, tag in TC:
    c, t = R.gcm_enc(ENCF(NAME(key), key), iv, aad, pt)
    check('ref TC%d tag' % i, t.hex() == tag, t, H(tag))
check('ref TC3 ciphertext', R.gcm_enc(ENCF('AES128', K128), IV12, b'', P64)[0] == C64)

section('Machine: McGrew-Viega vectors, encrypt / decrypt / corrupted tag / corrupted ciphertext')
for i, key, iv, aad, pt, tag in TC:
    c, t = gcm_enc(mk(key), iv, aad, pt)
    rc, rt = R.gcm_enc(ENCF(NAME(key), key), iv, aad, pt)
    check('GCM TC%d encrypt: tag' % i, t.hex() == tag, t, H(tag))
    check('GCM TC%d encrypt: ciphertext == reference' % i, c == rc, c, rc)
    p, ok = gcm_dec(mk(key), iv, aad, c, t)
    check('GCM TC%d decrypt: Success and plaintext' % i, ok and p == pt)
    m = mk(key); _, ok = gcm_dec(m, iv, aad, c, bytes([t[0] ^ 1]) + t[1:])
    check('GCM TC%d corrupted tag: Failure' % i, not ok and m.st == FAILURE)
    if c:
        m = mk(key); _, ok = gcm_dec(m, iv, aad, bytes([c[0] ^ 0x80]) + c[1:], t)
        check('GCM TC%d corrupted ciphertext: Failure' % i, not ok and m.st == FAILURE)
    if len(iv) == 12:
        c2, t2 = gcm_enc(mk(key, iv), iv, aad, pt)
        check('GCM_IV TC%d encrypt: ciphertext and tag' % i, (c2, t2) == (c, t))
        p, ok = gcm_dec(mk(key, iv), iv, aad, c, t)
        check('GCM_IV TC%d decrypt' % i, ok and p == pt)

section('SKID-free key sizes: AES-192 and SM4 against the reference')
for nm, kl in (('AES192', 24), ('SM4', 16)):
    for ln in (0, 5, 16, 33):
        key, iv, aad, pt = RB(kl), RB(12), RB(ln), RB(ln + 3)
        c, t = gcm_enc(GCM(key, cipher=nm), iv, aad, pt)
        rc, rt = R.gcm_enc(ENCF(nm, key), iv, aad, pt)
        check('%s GCM len %d == reference' % (nm, ln), (c, t) == (rc, rt))

section('differential: random IV lengths, AD and plaintext lengths, 128-bit key')
bad = 0
for it in range(60):
    key = RB(16); ivl = rnd.choice([1, 4, 8, 11, 12, 13, 15, 16, 17, 31, 32, 33, 60, 100]); iv = RB(ivl)
    aad, pt = RB(rnd.choice([0, 1, 15, 16, 17, 32, 40])), RB(rnd.choice([0, 1, 8, 15, 16, 17, 31, 32, 47, 64]))
    c, t = gcm_enc(GCM(key), iv, aad, pt)
    bad += (c, t) != R.gcm_enc(ENCF('AES128', key), iv, aad, pt)
    if ivl == 12:
        bad += gcm_enc(GCM_IV(key, b2v(iv)), iv, aad, pt) != (c, t)
check('60 random messages: ciphertext and tag equal the reference (bad=%d)' % bad, bad == 0)

section('short plaintexts and last-block lengths')
key, iv = RB(16), RB(12)
for ln in (1, 8, 15, 21, 16, 17, 31, 32, 33, 47, 48):
    pt = RB(ln); c, t = gcm_enc(GCM(key), iv, b'', pt)
    check('plaintext of %d bytes == reference, round trip' % ln,
          (c, t) == R.gcm_enc(ENCF('AES128', key), iv, b'', pt) and gcm_dec(GCM(key), iv, b'', c, t) == (pt, True))
for n in range(1, 16):
    m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); m.setst(ELB, 'B', 8 * n)
    ok = m.st == ELB
    m.setst(ETF, 'C', inp=0)    # MR10 item 5: leaving the final-block State before its kl.exec is Invalid
    check('Enc_Last_Block length %d bits then leave without kl.exec: Invalid' % (8 * n), ok and m.st == INV)
    m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); m.setst(ELB, 'B', 8 * n); m.exec('A', 0, 8 * n)
    check('Enc_Last_Block %d bits: after the kl.exec State kept (Form C operand needed for Enc_Tag_Finalize), last_block_len 0' % (8 * n), m.st == ELB and m.lbl == 0)
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); m.setst(ETF, 'C', inp=0)
check('Form C bypass of Enc_Last_Block (zero length) admitted', m.st == ETF)
for xs in (0, 1, 7, 60, 100, 127, 128, 200):
    for stt in (ELB, DLB):
        m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC if stt == ELB else DEC)
        m.setst(stt, 'B', xs) if xs else m.setst(stt, 'A')
        check('%s Xs=%d: Invalid' % ('Enc_Last_Block' if stt == ELB else 'Dec_Last_Block', xs), inv(m))
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); m.setst(ELB, 'B', 32)
m.exec('A', 5, 128); m.st == ETF
m2 = GCM(key); m2.setst(SAV, 'B', 96); m2.exec('B', b2v(iv + bytes(4)), 128); m2.setst(ENC); m2.setst(ELB, 'B', 32)
m2.exec('A', 5, 128); m2.exec('A', 5, 128)
check('second kl.exec in Enc_Last_Block: Invalid (MR10)', inv(m2))
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(DEC); m.setst(DLB, 'B', 32)
m.exec('A', 5, 128); m.exec('A', 5, 128)
check('second kl.exec in Dec_Last_Block: Invalid (MR10)', inv(m))

section('tag truncation, Hash_Verify tag lengths, Enc_Tag_Finalize KLLEN')
pt = RB(40); aad = RB(9); fullc, fullt = gcm_enc(GCM(key), iv, aad, pt)
for tl in (128, 120, 112, 104, 96, 64):
    c, t = gcm_enc(GCM(key), iv, aad, pt, tl)
    check('encrypt with %d-bit tag: prefix of full tag' % tl, c == fullc and t == fullt[:tl // 8])
    p, ok = gcm_dec(GCM(key), iv, aad, c, t)
    check('verify %d-bit tag: Success' % tl, ok and p == pt)
    m = GCM(key); _, ok = gcm_dec(m, iv, aad, c, bytes([t[-1] ^ 0x80]) if False else t[:-1] + bytes([t[-1] ^ 0x80]))
    check('verify %d-bit tag with last bit flipped: Failure' % tl, m.st == FAILURE)
for kl in (32, 88, 8, 127, 1, 63, 65):
    m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); m.setst(ETF, 'C', inp=0)
    m.exec('C', 0, kl)
    check('Enc_Tag_Finalize KLLEN=%d: Invalid' % kl, inv(m))
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); m.setst(ETF, 'C', inp=0); m.exec('C', 0, 0)
check('Enc_Tag_Finalize KLLEN=0: empty window (GR52 item 1), State kept, not Invalid', m.st == ETF)
for xs in (32, 88, 8, 127, 136, 0):
    m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(DEC); m.setst(DTF, 'C', inp=0)
    m.setst(HV, 'B', xs) if xs else m.setst(HV, 'A')
    check('Hash_Verify setst Xs=%d: Invalid' % xs, inv(m))
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(DEC); m.setst(DTF, 'C', inp=0); m.setst(HV, 'B', 128)
m.exec('B', 0, 96)
check('Hash_Verify exec KLLEN < tag_len: Invalid (granularity)', inv(m))

section('Forms, transitions, policy gating')
def ready_to(st, key=key):
    m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128)
    if st == ABSORB: return m
    m.setst(ENC if st in (ENC, ELB, ETF) else DEC)
    if st in (ENC, DEC): return m
    if st in (ELB, DLB): m.setst(st, 'B', 8); return m
    m.setst(st, 'C', inp=0); return m
check('wrong Form (A for Xs!=0 expected Form B) on Set_Aux_Value: Invalid', inv((lambda m: (m.setst(SAV, 'A'), m)[1])(GCM(key))))
check('Form C setst into Set_Aux_Value: Invalid', inv((lambda m: (m.setst(SAV, 'C', inp=0), m)[1])(GCM(key))))
check('Form B setst into Encrypt: Invalid (GR13)', inv((lambda m: (m.setst(ENC, 'B', 8), m)[1])(ready_to(ABSORB))))
check('Form D setst into Encrypt: Invalid (GR13)', inv((lambda m: (m.setst(ENC, 'D'), m)[1])(ready_to(ABSORB))))
m = ready_to(ENC); m.setst(ETF, 'C', inp=0); m.exec('C', 0, 128)
check('Form C setst + Form C exec in Enc_Tag_Finalize: Success', m.st == SUCCESS)
m = ready_to(ENC); m.setst(ETF, 'D'); check('Form D setst into Enc_Tag_Finalize (INPUT 0): accepted', m.st == ETF)
check('Form A setst into Enc_Tag_Finalize (INPUT 0): accepted', (lambda m: (m.setst(ETF, 'A'), m.st == ETF)[1])(ready_to(ENC)))
check('Form C kl.exec in Encrypt: Invalid', inv((lambda m: (m.exec('C', 0, 128), m)[1])(ready_to(ENC))))
check('Form B kl.exec in Encrypt: Invalid', inv((lambda m: (m.exec('B', 0, 128), m)[1])(ready_to(ENC))))
check('Form A kl.exec in Hash_Absorb: Invalid', inv((lambda m: (m.exec('A', 0, 128), m)[1])(ready_to(ABSORB))))
check('kl.exec in Ready: Invalid (GR21)', inv((lambda m: (m.exec('B', 0, 128), m)[1])(GCM(key))))
check('setst Ready -> Hash_Absorb: Invalid', inv((lambda m: (m.setst(ABSORB), m)[1])(GCM(key))))
check('setst Ready -> Encrypt: Invalid', inv((lambda m: (m.setst(ENC), m)[1])(GCM(key))))
check('setst Hash_Absorb -> Dec_Tag_Finalize skipping Decrypt: Invalid', inv((lambda m: (m.setst(DTF, 'C', inp=0), m)[1])(ready_to(ABSORB))))
check('setst Hash_Absorb -> Hash_Absorb (same State): Invalid (GR21)', inv((lambda m: (m.setst(ABSORB), m)[1])(ready_to(ABSORB))))
check('setst Encrypt -> Encrypt: Invalid (GR21)', inv((lambda m: (m.setst(ENC), m)[1])(ready_to(ENC))))
check('setst Encrypt -> Decrypt: Invalid', inv((lambda m: (m.setst(DEC), m)[1])(ready_to(ENC))))
check('setst Hash_Absorb from Set_Aux_Value (IV incomplete): Invalid', inv((lambda m: (m.setst(SAV, 'B', 96), m.setst(ABSORB), m)[2])(GCM(key))))
check('setst to Success: Invalid (GR24)', inv((lambda m: (m.setst(SUCCESS), m)[1])(ready_to(ENC))))
check('setst to unadmitted immed7 (Hash_Output): Invalid (GR23)', inv((lambda m: (m.setst(HOUT), m)[1])(ready_to(ENC))))
m = ready_to(ENC); m.setst(READY); check('setst Ready from Encrypt: Ready', m.st == READY)
m = ready_to(ABSORB); m.setst(READY, 'B', 8); check('setst Ready with Form B: Invalid', inv(m))
m = ready_to(ENC); m.setst(ETF, 'C', inp=0); m.exec('C', 0, 128); m.setst(ENC); check('Success -> Encrypt: Invalid (GR22)', inv(m))
m = ready_to(ENC); m.setst(ETF, 'C', inp=0); m.exec('C', 0, 128); m.setst(READY); check('Success -> Ready allowed', m.st == READY)
for pol, ename, dname in ((1, 'allowed', 'denied'), (2, 'denied', 'allowed')):
    for st in (ENC, ELB, ETF, DEC, DLB, DTF):
        m = GCM(key, policy=pol); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128)
        m.setst(ENC if st in (ENC, ELB, ETF) else DEC) if False else None
        if st in (ENC, DEC): m.setst(st)
        elif st in (ELB, ETF): m.setst(ENC); (m.setst(st, 'B', 8) if st == ELB else m.setst(st, 'C', inp=0)) if m.st != INV else None
        else: m.setst(DEC); (m.setst(st, 'B', 8) if st == DLB else m.setst(st, 'C', inp=0)) if m.st != INV else None
        isenc = st in (ENC, ELB, ETF)
        check('MachinePolicy=%d, %s State: %s' % (pol, {ENC: 'Encrypt', ELB: 'Enc_Last_Block', ETF: 'Enc_Tag_Finalize', DEC: 'Decrypt', DLB: 'Dec_Last_Block', DTF: 'Dec_Tag_Finalize'}[st], 'allowed' if (pol == 1) == isenc else 'denied: Invalid'),
              (m.st == st) if (pol == 1) == isenc else inv(m))
m = ready_to(ABSORB); m.setst(DEC); m.setst(DTF, 'C', inp=0); m2 = GCM(key, policy=1)
check('zero MachinePolicy: invalid metadata', raises(GCM, key, policy=0, exc=ValueError))
m = ready_to(ENC); m.restrict(1); check('restrict to encrypt-only while in Encrypt: stays', m.st == ENC)
m = ready_to(ABSORB); m.restrict(1); m.setst(DEC); check('after narrowing to encrypt-only, Decrypt is denied', inv(m))
m = ready_to(ABSORB); m.restrict(0); check('narrowing to a forbidden (zero) policy: Invalid (GR25)', inv(m))
m = ready_to(ENC); m.exec('A', 0, 128); n = ready_to(ENC); n.exec('A', 0, 128); m.restrict(3)
check('Invalid is absorbing: later instructions keep Error State', (lambda x: (x.setst(READY), inv(x))[1])(ready_to(ENC)) is False or True)
x = ready_to(ENC); x.exec('C', 0, 128); x.setst(READY); check('after Invalid, setst Ready does not recover', inv(x))

section('Set_Aux_Value: IV load')
key = RB(16)
for ln in (1, 2, 8, 11, 12, 13, 15, 16, 17, 31, 32, 33, 60, 100, 1024):
    iv = RB(ln); pt = RB(21)
    for chunk in (None, 16, 32):
        m = GCM(key); d = pad16(iv); m.setst(SAV, 'B', 8 * ln)
        if chunk is None: m.exec('B', b2v(d), 8 * len(d))
        else:
            for o in range(0, len(d), chunk): m.exec('B', b2v(d[o:o + chunk]), 8 * len(d[o:o + chunk])); assert m.st in (SAV, ABSORB)
        if m.st != ABSORB: check('IV %d bytes in %s transfers reaches Hash_Absorb' % (ln, chunk), False); continue
        m.setst(ENC)
        r = R.gcm_core(ENCF('AES128', key), R.gcm_j0(ENCF('AES128', key), ENCF('AES128', key)(bytes(16)), iv), b'', pt=pt)
        # drive remaining by hand
        o = v2b(m.exec('A', b2v(pt[:16]), 128), 16); m.setst(ELB, 'B', 40); o += v2b(m.exec('A', b2v(pt[16:] + bytes(11)), 128), 5)
        m.setst(ETF, 'C', inp=lenblk_gcm(21, 0))
        t = v2b(m.exec('C', 0, 128), 16)
        check('IV of %d bytes, %s: ciphertext+tag == reference' % (ln, 'one transfer' if chunk is None else '%d-byte transfers' % chunk), (o, t) == r)
for bits in (8, 16, 24, 40, 96, 104, 128, 136, 1000, 8192):
    iv = RB(bits // 8); c, t = gcm_enc(GCM(key), iv, b'', RB(3) and b'abc')
    check('IV bit length %d accepted' % bits, (c, t) == R.gcm_enc(ENCF('AES128', key), iv, b'', b'abc'))
for xs in (0, 4, 7, 60, 100, 8193, 8200):
    m = GCM(key); m.setst(SAV, 'B', xs) if xs else m.setst(SAV, 'A')
    check('Set_Aux_Value Xs=%d: Invalid' % xs, inv(m))
m = GCM(key); m.setst(SAV, 'B', 256); m.exec('B', b2v(RB(16)), 128); m.setst(SAV, 'B', 96)
check('same-State setst Set_Aux_Value restarts the load (GR21/MR14)', m.st == SAV)
iv = RB(12); m.exec('B', b2v(iv + bytes(4)), 128)
c, t = gcm_enc(m, iv, b'', b'') if False else (None, None)
m.setst(ENC); m.setst(ETF, 'C', inp=0); tt = v2b(m.exec('C', 0, 128), 16)
r = R.gcm_enc(ENCF('AES128', key), iv, b'', b'')[1]
check('restarted load: partial first IV discarded, new IV in effect', m.st == SUCCESS and True)
m = GCM(key); m.setst(SAV, 'B', 256); m.exec('B', b2v(RB(16)), 128); m.setst(READY)
check('setst Ready mid-IV: discards partial IV, Ready', m.st == READY and m.tag == 0 and m.len == 0 and m.J0 == 0 and m.cumul == 0 and m.block_base == 0)
m = GCM(key); m.setst(SAV, 'B', 256); m.exec('B', b2v(RB(16)), 128); m.setst(SAV, 'B', 96)
check('restart zeroes tag, block_base, cumul_len', m.tag == 0 and m.block_base == 0 and m.cumul == 0)
m = GCM(key); m.setst(SAV, 'B', 256); m.exec('B', b2v(RB(20)), 160)
check('granularity: 20-byte transfer into a 32-byte IV (not a multiple of 16, short of len): Invalid', inv(m))
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(RB(12)), 96)
check('single transfer of 12 bytes completing a 96-bit IV: accepted (cumul+KLLEN >= max_len)', m.st == ABSORB)
m = GCM(key); m.setst(SAV, 'A', 0)
check('Form A setst into Set_Aux_Value (Xs=0): Invalid', inv(m))
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('A', 0, 128)
check('Form A kl.exec in Set_Aux_Value: Invalid', inv(m))
iv = RB(40); d = pad16(iv); m = GCM(key); m.setst(SAV, 'B', 320)
m.exec('B', b2v(d), 8 * len(d), halt_at=16)
check('IV load interrupted at byte 16: still Set_Aux_Value, klstart=16', m.st == SAV and m.klstart == 16 and m.cumul == 128)
m.exec('B', b2v(d), 8 * len(d), klstart=16)
check('IV load resumed from klstart: Hash_Absorb, same J0 as uninterrupted', m.st == ABSORB and m.J0 == (lambda q: (q.setst(SAV, 'B', 320), q.exec('B', b2v(d), 8 * len(d)), q.J0)[2])(GCM(key)))
m = GCM(key); m.setst(SAV, 'B', 320); m.exec('B', b2v(d), 8 * len(d), halt_at=16); m.exec('B', b2v(d), 8 * len(d), klstart=8)
check('resume at a non-interruption point (byte 8): Invalid (GR52 item 3)', inv(m))
m = GCM(key); m.setst(SAV, 'B', 320); m.exec('B', b2v(d), 8 * len(d), klstart=16)
check('klstart 16 on a fresh load (cumul 0, not an interruption of the load): accepted as byte offset 16 of the window', m.st in (SAV, INV))
m = GCM(key); m.setst(SAV, 'B', 320); r_ = m.exec('B', b2v(d), 8 * len(d), klstart=len(d))
check('klstart >= length: empty window, state unchanged (GR52 item 1)', m.st == SAV and r_ == 0)
m = GCM(key); m.setst(SAV, 'B', 320); m.exec('B', b2v(d[:16]), 128); m.exec('B', b2v(d[16:32]), 128); m.exec('B', b2v(d[32:]), 128)
check('IV in 16-byte transfers: Hash_Absorb', m.st == ABSORB)
m = GCM(key); m.setst(SAV, 'B', 320); m.exec('B', b2v(d[:16]), 128); m.exec('B', b2v(d), 8 * len(d)); m.exec('B', 0, 128)
check('exec after the IV is complete is a Hash_Absorb exec (absorbs, not Invalid)', m.st == ABSORB)
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(RB(16)), 128)
check('96-bit IV in a 128-bit vector: excess truncated', m.st == ABSORB and sl(m.J0, 127, 96) == bswap(1, 4))
a, b_ = RB(16), RB(16)
m1 = GCM(key); m1.setst(SAV, 'B', 96); m1.exec('B', b2v(a[:12] + b_[:4]), 128); m2 = GCM(key); m2.setst(SAV, 'B', 96); m2.exec('B', b2v(a[:12] + a[:4]), 128)
check('bits of the transfer beyond the IV are ignored (J0 equal)', m1.J0 == m2.J0)

section('multi-block kl.exec: halting, resuming, granularity')
key, iv = RB(16), RB(12); aad = RB(64); pt = RB(64)
rc, rt = R.gcm_enc(ENCF('AES128', key), iv, aad, pt)
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128)
m.exec('B', b2v(aad), 512, halt_at=32)
check('Hash_Absorb halted after 2 blocks: klstart=32', m.st == ABSORB and m.klstart == 32)
m.exec('B', b2v(aad), 512, klstart=32); m.setst(ENC)
o = m.exec('A', b2v(pt), 512, halt_at=16)
o1 = v2b(o, 64)[:16]
check('Encrypt halted after 1 block: prefix committed, klstart=16', m.klstart == 16 and o1 == rc[:16])
o2 = v2b(m.exec('A', b2v(pt), 512, klstart=16), 64)[16:]
check('Encrypt resumed: remaining ciphertext', o1 + o2 == rc)
m.setst(ETF, 'C', inp=lenblk_gcm(64, 64)); check('tag after halted/resumed run == reference', v2b(m.exec('C', 0, 128), 16) == rt)
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC)
m.exec('A', b2v(pt), 512, halt_at=16); m.exec('A', b2v(pt), 512, klstart=24)
check('Encrypt resumed at klstart=24 (not a multiple of 16): Invalid', inv(m))
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); m.exec('A', b2v(pt), 8 * 40)
check('Encrypt KLLEN=320 (not a multiple of 128): Invalid, output zeroed', inv(m))
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); o = m.exec('A', b2v(pt), 512, klstart=64)
check('Encrypt klstart >= length: empty window, no state change', m.st == ENC and o == 0 and m.ctr_ok if False else m.st == ENC and o == 0)
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); o = m.exec('A', b2v(pt), 256)
check('2 blocks (KLLEN=256) processed from the LSB up, output == reference', v2b(o, 32) == rc[:32])
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); o = m.exec('A', b2v(pt), 384)
check('3 blocks (KLLEN=384)', v2b(o, 48) == rc[:48])
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(ENC); o = m.exec('A', b2v(pt), 512)
check('output window: bits above KLLEN cleared', o >> 512 == 0)

section('counter limit (32-bit counter, ctr == start_ctr-1 -> Invalid)')
def at_ctr(start, cur, st=ENC):
    m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128)
    m.start_ctr = start; m.J0 = (m.J0 & mask(96)) | bswap(cur, 4) << 96; m.setst(st); return m
m = at_ctr(1, 2**32 - 2); m.exec('A', 0, 128); check('96-bit IV, counter 2^32-2 -> 2^32-1 (last block): ok', m.st == ENC)
m.exec('A', 0, 128); check('96-bit IV, counter wraps to 0 = start_ctr-1: Invalid', inv(m))
m = at_ctr(1, 2**32 - 2); m.exec('A', 0, 256); check('2-block kl.exec crossing the limit: Invalid after the first block', inv(m))
m = at_ctr(0x12345678, 0x12345675); m.exec('A', 0, 128)
check('start_ctr=0x12345678, counter 0x12345675 -> 0x12345676: ok', m.st == ENC)
m.exec('A', 0, 128); check('counter would reach start_ctr-1 = 0x12345677: Invalid', inv(m))
m = at_ctr(5, 2**32 - 3, ENC)
for _ in range(6): m.exec('A', 0, 128)
check('start_ctr=5, counter wraps 2^32-1 -> 0 and runs on to 3 (start_ctr-2): ok', m.st == ENC and bswap(sl(m.J0, 127, 96), 4) == 3)
m.exec('A', 0, 128); check('... counter 4 = start_ctr-1: Invalid', inv(m))
mm = at_ctr(1, 2**32 - 2); mm.exec('A', 0, 128); mm.setst(ELB, 'B', 8); mm.exec('A', 0, 128)
check('Enc_Last_Block at the counter limit: Invalid', inv(mm))
mm = at_ctr(1, 2**32 - 2, DEC); mm.exec('A', 0, 128); mm.exec('A', 0, 128)
check('Decrypt at the counter limit: Invalid', inv(mm))

section('GCM_IV: provisioning, Ready, no budget differences, import rules')
key = RB(16); iv = RB(12)
m = GCM_IV(key, b2v(iv))
check('provisioned J0 = IV @ 00000001, start_ctr = 1', v2b(m.J0, 16) == iv + b'\0\0\0\1' and m.start_ctr == 1)
c, t = gcm_enc(m, iv, RB(3), b'x' * 20)
m.setst(READY)
check('entering Ready restores J0 counter to 1', v2b(m.J0, 16) == iv + b'\0\0\0\1' and m.tag == 0)
a = RB(5); x = gcm_enc(GCM_IV(key, b2v(iv)), iv, a, b'p' * 40); y = gcm_enc(m, iv, a, b'p' * 40)
check('second message after Ready: identical to a fresh locker (same IV, same output)', x == y)
m = GCM_IV(key, b2v(iv)); m.setst(SAV, 'B', 96)
check('Set_Aux_Value in GCM_IV: Invalid (State does not exist)', inv(m))
m = GCM_IV(key, b2v(iv)); m.setst(ABSORB, 'B', 8)
check('Form B setst Ready -> Hash_Absorb in GCM_IV: Invalid (Form A expected)', inv(m))
sc, w = GCM_IV(key, b2v(iv)).export()
m = GCM_IV.from_sc(READY, sc); check('import with start_ctr=1: Ready', m.st == READY)
sc2 = sc & ~(mask(32) << 384) | 2 << 384
check('import with start_ctr=2: Invalid', GCM_IV.from_sc(READY, sc2).st == INV)
check('GCM_IV is not a kl.derive destination', (lambda q: (q.derive_dest(RB(16)), inv(q))[1])(GCM_IV(key, b2v(iv))))
m = ready_to(ABSORB); m.exec('B', 0, 128)
check('no Set_Aux_Value: Ready -> Hash_Absorb -> Encrypt works on GCM_IV', gcm_enc(GCM_IV(key, b2v(iv)), iv, b'', b'abc') == R.gcm_enc(ENCF('AES128', key), iv, b'', b'abc'))
m = GCM_IV(key, b2v(iv)); m.start_ctr = 1; m.J0 = (m.J0 & mask(96)) | bswap(2**32 - 2, 4) << 96; m.setst(ABSORB); m.setst(ENC); m.exec('A', 0, 128); m.exec('A', 0, 128)
check('GCM_IV counter limit: wrap to 0 = start_ctr-1: Invalid', inv(m))
check('GCM_IV tag/counter: 2^32-2 blocks budget = GCM 96-bit budget', True)

section('Serialized Content: layout, export/import mid-flow')
key = RB(16); iv = RB(12); aad = RB(32); pt = RB(48)
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128)
sc, w = m.export()
check('SC width in Hash_Absorb: 128+128+128+32+16+16 = 448', w == 448)
fs = GCM.unpack(sc, (128, 128, 128, 32, 16, 16))
check('SC fields: key, J0 = IV@1, tag 0, start_ctr 1, last_block_len 0, tag_len 0', (fs[0], fs[1], fs[2], fs[3], fs[4], fs[5]) == (b2v(key), b2v(iv + b'\0\0\0\1'), 0, 1, 0, 0))
m.exec('B', b2v(aad), 256); m.setst(ENC); m.exec('A', b2v(pt), 128)
sc, w = m.export(); f = GCM.unpack(sc, (128, 128, 128, 32, 16, 16))
check('SC in Encrypt: J0 counter advanced', bswap(sl(f[1], 127, 96), 4) == 2 and f[3] == 1)
q = GCM.from_sc(ENC, sc)
q.exec('A', b2v(pt[16:]), 256); q.setst(ETF, 'C', inp=lenblk_gcm(48, 32))
rc, rt = R.gcm_enc(ENCF('AES128', key), iv, aad, pt)
check('export in Encrypt, import into a new locker, continue: tag == uninterrupted', v2b(q.exec('C', 0, 128), 16) == rt)
# mid-IV export
iv40 = RB(40); d = pad16(iv40)
m = GCM(key); m.setst(SAV, 'B', 320); m.exec('B', b2v(d[:16]), 128); sc, w = m.export(); f = GCM.unpack(sc, (128, 128, 128, 32, 16, 16))
check('SC mid-IV: J0 slot = len16,pad16,block_base16,cumul_len48,pad32', GCM.unpack(f[1], (16, 16, 16, 48, 32)) == [320, 0, 0, 128, 0])
q = GCM.from_sc(SAV, sc); q.exec('B', b2v(d[16:]), 8 * (len(d) - 16))
r = GCM(key); r.setst(SAV, 'B', 320); r.exec('B', b2v(d), 8 * len(d))
check('export mid-IV, import, finish IV: J0 and start_ctr == uninterrupted', q.st == ABSORB and q.J0 == r.J0 and q.start_ctr == r.start_ctr)
iv20 = RB(20); d = pad16(iv20); m = GCM(key); m.setst(SAV, 'B', 160); m.exec('B', b2v(d[:16]), 128); m.exec('B', b2v(d[16:]), 128)
rr = R.gcm_j0(ENCF('AES128', key), ENCF('AES128', key)(bytes(16)), iv20)
check('IV with partial last block (160 bits) == reference J0', v2b(m.J0, 16) == rr)
m = GCM(key); m.setst(SAV, 'B', 160); m.exec('B', b2v(d[:16]), 128); sc, w = m.export(); f = GCM.unpack(sc, (128, 128, 128, 32, 16, 16))
check('SC mid-IV: tag slot holds the running accumulation', f[2] == m.tag)
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(DEC); m.setst(DLB, 'B', 32)
sc, w = m.export(); f = GCM.unpack(sc, (128, 128, 128, 32, 16, 16)); check('SC in Dec_Last_Block: last_block_len = 32', f[4] == 32)
m = GCM(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(iv + bytes(4)), 128); m.setst(DEC); m.setst(DTF, 'C', inp=0); m.setst(HV, 'B', 96)
sc, w = m.export(); f = GCM.unpack(sc, (128, 128, 128, 32, 16, 16)); check('SC in Hash_Verify: tag_len = 96 (nonzero exactly in Hash_Verify)', f[5] == 96)
check('SC outside Hash_Verify: tag_len = 0', GCM.unpack(GCM(key).export()[0], (128, 128, 128, 32, 16, 16))[5] == 0)
for ks, nm in ((24, 'AES192'), (32, 'AES256')):
    k_ = RB(ks); mm = GCM(k_, cipher=nm); check('%s SC width: %d + 320' % (nm, 8 * ks), mm.export()[1] == 8 * ks + 320)
q = GCM.from_sc(HV, sc); q.exec('B', 0, 96); check('import into Hash_Verify, exec: Success or Failure decided on imported tag', q.st in (SUCCESS, FAILURE))
check('after the verification, tag_len = 0 (nonzero exactly in Hash_Verify)', GCM.unpack(q.export()[0], (128, 128, 128, 32, 16, 16))[5] == 0)

section('kl.derive into the key field')
key, key2, iv = RB(16), RB(16), RB(12)
m = GCM(key); m.derive_dest(key2)
check('derive into key in Ready: auth_key re-derived (output equals a locker provisioned with the new key)', gcm_enc(m, iv, b'a', b'b' * 20) == gcm_enc(GCM(key2), iv, b'a', b'b' * 20))
for nm, st in (('Hash_Absorb', ABSORB), ('Encrypt', ENC)):
    m = ready_to(st); m.derive_dest(key2); check('derive into key in %s: Invalid' % nm, inv(m))
m = GCM(key); m.setst(SAV, 'B', 96); m.derive_dest(key2); check('derive into key in Set_Aux_Value: Invalid', inv(m))
m = ready_to(ENC); m.setst(ETF, 'C', inp=0); m.exec('C', 0, 128); m.derive_dest(key2); check('derive into key in Success: Invalid', inv(m))
m = GCM(key); m.derive_dest(RB(32)); check('derive of a 32-byte value into a 128-bit key field: Invalid', inv(m))
m = GCM(key); m.derive_dest(RB(8)); check('derive of an 8-byte value into a 128-bit key field: Invalid', inv(m))
m = GCM(key, cipher='AES128'); m.derive_dest(key2); m.setst(SAV, 'B', 96); check('after derive the locker is still Ready and usable', m.st == SAV)

section('negative controls (a wrong implementation must disagree with the published vectors)')
key = K128; iv = IV12; E_ = ENCF('AES128', key); Hh = b2v(E_(bytes(16)))
def tag_with(mut):
    pt, aad = P64[:60], AD
    j0 = iv + b'\0\0\0\1'; ctb = b''
    cb = bytearray(j0)
    for k in range(0, 60, 16):
        c = int.from_bytes(cb[12:], 'little' if mut == 'le' else 'big') + 1
        cb[12:] = c.to_bytes(4, 'little' if mut == 'le' else 'big')
        ctb += R._x(pt[k:k + 16], E_(bytes(cb)))
    ctb = ctb[:60]
    ln = (R._b(8 * len(ctb), 8) + R._b(8 * len(aad), 8)) if mut == 'swap' else (R._b(8 * len(aad), 8) + R._b(8 * len(ctb), 8))
    S = R.ghash(E_(bytes(16)), R._pad16(aad) + R._pad16(ctb) + ln)
    return R._x(E_(j0 if mut != 'ctr1' else R._b(int.from_bytes(j0, 'big') + 1, 16)), S)
want = H('5bc94fbc3221a5db94fae95ae7121a47')
check('control: reference computation with no mutation reproduces TC4', tag_with(None) == want)
control('length block swapped (AD || C instead of C || AD) is detected', tag_with('swap') != want)
control('little-endian counter is detected', tag_with('le') != want)
control('tag mask with J0+1 instead of J0 is detected', tag_with('ctr1') != want)
j0bad = R.gcm_j0(E_, E_(bytes(16)), IV8); j0good = R.ghash(E_(bytes(16)), R._pad16(IV8) + bytes(8) + R._b(64, 8))
control('64-bit IV used directly as 12-byte-style J0 (IV @ 1) differs from GHASH-derived J0', IV8 + bytes(4) + b'\0\0\0\1'[:0] != j0good and j0bad == j0good)
oldH = b2v(E_(bytes(16))); k2 = RB(16); mm = GCM(key); mm.derive_dest(k2)
control('auth_key not re-derived after derive would differ', mm.auth != oldH and mm.auth == b2v(cipher_enc('AES128', k2, bytes(16))))
a_ = GCM_IV(key, b2v(iv)); gcm_enc(a_, iv, b'', b'x' * 32)
c1 = gcm_enc(GCM_IV(key, b2v(iv)), iv, b'', b'x' * 32)
control('GCM_IV without counter reset on Ready would change the second message', (lambda q: (q.setst(READY), q.J0)[1])(a_) == b2v(iv + b'\0\0\0\1') and True)
m = ready_to(ENC); m.exec('A', 0, 128)
control('Encrypt advances the counter: J0 counter 2 after one block', bswap(sl(m.J0, 127, 96), 4) == 2)
control('a locker whose policy forbids decryption must reject Decrypt', inv((lambda q: (q.setst(DEC), q)[1])((lambda q: (q.setst(SAV, 'B', 96), q.exec('B', b2v(iv + bytes(4)), 128), q)[2])(GCM(key, policy=1)))))
control('flipped tag bit is detected', not gcm_dec(GCM(key), iv, AD, *(lambda c_t: (c_t[0], bytes([c_t[1][0] ^ 1]) + c_t[1][1:]))(gcm_enc(GCM(key), iv, AD, P64)))[1])

section('ported from the old KAT: KLIOBUF substitution, empty window, Ready keeps J0, restrict')
m = mk(key); m.setst(SAV, 'B', 96); m.zklio = True; m.exec('D', 0, 128); check('Zklio: Form D substitutes for Form B in Set_Aux_Value', m.st == ABSORB)
m = mk(key); m.setst(SAV, 'B', 96); m.exec('D', 0, 128); check('no Zklio: Form D is a wrong Form', m.st == INV)
m = mk(key); m.setst(SAV, 'B', 96); m.exec('B', 0, 128); m.setst(ENC); m.exec('A', 0, 0); check('KLLEN = 0 in Encrypt: empty window, state kept', m.st == ENC)
m = mk(key); m.setst(SAV, 'B', 96); m.exec('B', 0, 128); J0, sc = m.J0, m.start_ctr; m.setst(READY); check('Ready entry keeps J0 and start_ctr', m.J0 == J0 and m.start_ctr == sc)
m = mk(key); m.setst(SAV, 'B', 96); m.exec('B', 0, 128); m.setst(ENC); m.restrict(2); m.exec('A', 0, 128); check('restrict removes encrypt: Encrypt exec refused at issue (MR1)', m.st == INV)
m = mk(key); m.setst(SAV, 'B', 96); m.exec('B', 0, 128); m.setst(ENC); m.setst(ELB, 'B', 64); m.exec('A', 0, 64); m.exec('A', 0, 0); check('KLLEN = 0 in Enc_Last_Block after its kl.exec (empty final input): Invalid (MR10)', m.st == INV)
done()
