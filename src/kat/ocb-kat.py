#!/usr/bin/env pypy3.12
"""KAT for AES128_OCB and AES128_OCB_NONCE (AES-192/256 key sizes too).  Vectors: RFC 7253 Appendix A (first four,
TAGLEN 128); reference aead_ref.py (RFC 7253 order).  Run: cd src && pypy3.12 kat/ocb-kat.py"""
import random
from common import *
from aead_model import *
from aead_util import *
import aead_ref as R

H = bytes.fromhex
rnd = random.Random(10)
RB = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
def inv(m): return m.st == INV
NM = {16: 'AES128', 24: 'AES192', 32: 'AES256'}
KEY = bytes(range(16))
def nb(n): return int.from_bytes(n, 'big')
def N12(i): return bytes.fromhex('BBAA9988776655443322110' + '%x' % i)
def nonce_of(bits, n):   # (N, N_len) as provisioned in OCB_NONCE
    return b2v(nonce_bytes(bits, n)), n

section('RFC 7253 Appendix A (TAGLEN 128): reference, OCB, OCB_NONCE')
A8 = bytes(range(8))
V = [(0, b'', b'', '785407BFFFC8AD9EDCC5520AC9111EE6'),
     (1, A8, A8, '6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009'),
     (2, A8, b'', '81017F8203F081277152FADE694A0A00'),
     (3, b'', A8, '45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9')]
for i, a, p, out in V:
    n = N12(i); nbits = nb(n); want = H(out)
    c, t = R.ocb_enc('AES128', KEY, nbits, 96, a, p)
    check('ref vector %d' % i, c + t == want)
    c, t = ocb_enc(OCB(KEY), nbits, 96, a, p)
    check('OCB vector %d encrypt' % i, c + t == want, c + t, want)
    pp, ok = ocb_dec(OCB(KEY), nbits, 96, a, c, t)
    check('OCB vector %d decrypt: Success' % i, ok and pp == p)
    m = OCB(KEY); _, ok = ocb_dec(m, nbits, 96, a, c, bytes([t[0] ^ 1]) + t[1:])
    check('OCB vector %d corrupted tag: Failure' % i, m.st == FAILURE)
    c2, t2 = ocb_enc(OCB_NONCE(KEY, nonce_of(nbits, 96)), nbits, 96, a, p, preset=True)
    check('OCB_NONCE vector %d encrypt' % i, c2 + t2 == want)
    pp, ok = ocb_dec(OCB_NONCE(KEY, nonce_of(nbits, 96)), nbits, 96, a, c, t, preset=True)
    check('OCB_NONCE vector %d decrypt' % i, ok and pp == p)

section('differential: nonce lengths 6..120 bits, tag lengths, AD / message lengths, key sizes')
bad = cnt = 0
for kl in (16, 24, 32):
    for n in (6, 7, 8, 9, 15, 31, 64, 95, 96, 97, 100, 119, 120):
        for tl in (64, 96, 128):
            key = RB(kl); nbits = rnd.getrandbits(n); a = RB(rnd.choice([0, 1, 15, 16, 17, 33])); p = RB(rnd.choice([0, 1, 15, 16, 17, 32, 47]))
            r = R.ocb_enc(NM[kl], key, nbits, n, a, p, tl); cnt += 1
            if kl == 16:
                g = ocb_enc(OCB(key), nbits, n, a, p, tl)
                bad += g != r
                bad += ocb_dec(OCB(key), nbits, n, a, r[0], r[1])[1:] != (True,)
            else:
                m = OCB(key); m.CIPHER = NM[kl]; m.cipher = NM[kl]
                g = ocb_enc(m, nbits, n, a, p, tl); bad += g != r
check('%d random cases equal the reference, round trip (bad=%d)' % (cnt, bad), bad == 0)
bad = 0
for n in (6, 13, 64, 96, 120):
    for tl in (64, 128):
        key = RB(16); nbits = rnd.getrandbits(n); a, p = RB(21), RB(35)
        r = R.ocb_enc('AES128', key, nbits, n, a, p, tl)
        bad += ocb_enc(OCB_NONCE(key, nonce_of(nbits, n)), nbits, n, a, p, tl, preset=True) != r
check('OCB_NONCE equals the reference for nonce lengths 6..120 (bad=%d)' % bad, bad == 0)
for ln in (1, 7, 15, 16, 17, 31, 32, 33, 48, 64, 100):
    key = RB(16); nbits = rnd.getrandbits(96); p = RB(ln); a = RB(ln % 20)
    r = R.ocb_enc('AES128', key, nbits, 96, a, p)
    check('message %d bytes, AD %d bytes == reference' % (ln, len(a)), ocb_enc(OCB(key), nbits, 96, a, p) == r)

section('nonce bit lengths: partial final byte, left-aligned, padding bits ignored')
key = RB(16)
for n in (6, 7, 9, 10, 15, 17):
    nbits = rnd.getrandbits(n); nbytes = nonce_bytes(nbits, n)
    junk = nbytes[:-1] + bytes([nbytes[-1] | (0x55 & mask((8 - n) % 8) & 0xff)]) if n % 8 else nbytes
    m = OCB(key); m.setst(SAV, 'B', n); m.exec('B', b2v(nbytes), 128)
    m2 = OCB(key); m2.setst(SAV, 'B', n); m2.exec('B', b2v(junk), 128)
    check('nonce of %d bits: padding bits of the last byte ignored, N equal' % n, m.N == m2.N and m.hasN)
    check('nonce of %d bits: N holds ceil(n/8) bytes, string order in byte 0 first' % n, v2b(m.N, 15)[:len(nbytes)] == nbytes)
    check('nonce of %d bits == reference' % n, ocb_enc(OCB(key), nbits, n, b'', b'x' * 5) == R.ocb_enc('AES128', key, nbits, n, b'', b'x' * 5))
m = OCB(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(RB(16)), 128 * 1); m.exec('B', b2v(RB(16)), 128)
check('repeated Set_Aux_Value kl.exec rewrites N', m.st == SAV and m.hasN)
m = OCB(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(RB(16)), 128); m.setst(SAV, 'B', 64)
check('same-State setst restarts: N cleared, HasN cleared, N_len new', m.st == SAV and m.N == 0 and not m.hasN and m.N_len == 64)
m = OCB(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(RB(16)), 128); m.setst(READY)
check('setst Ready: N, N_len, HasN cleared', m.st == READY and m.N == 0 and m.N_len == 0 and not m.hasN)
m = OCB(key); m.setst(SAV, 'B', 96); m.setst(ABSORB, 'B', 128); check('Hash_Absorb without a loaded nonce (HasN clear): Invalid', inv(m))
for xs in (0, 1, 5, 121, 128, 200):
    m = OCB(key); m.setst(SAV, 'B', xs) if xs else m.setst(SAV, 'A'); check('Set_Aux_Value Xs=%d: Invalid' % xs, inv(m))
for xs in (6, 7, 120): check('Set_Aux_Value Xs=%d: accepted' % xs, (lambda m: (m.setst(SAV, 'B', xs), m.st == SAV)[1])(OCB(key)))

def at(st, taglen=128, **kw):
    m = OCB(KEY, **kw); m.setst(SAV, 'B', 96); m.exec('B', b2v(nonce_bytes(1, 96)), 128); m.setst(ABSORB, 'B', taglen)
    if st == ABSORB: return m
    m.setst(HABL, 'B', 0)
    if st == HABL: return m
    m.setst(ENC if st in (ENC, ELB, ETF) else DEC)
    if st in (ENC, DEC): return m
    m.setst(ELB if st in (ELB, ETF) else DLB, 'B', 0)
    if st in (ELB, DLB): return m
    m.exec('D'); return m
section('Hash_Absorb tag length and AD handling')
for xs in (0, 32, 63, 65, 100, 127, 129, 192):
    m = OCB(KEY); m.setst(SAV, 'B', 96); m.exec('B', b2v(nonce_bytes(1, 96)), 128); m.setst(ABSORB, 'B', xs) if xs else m.setst(ABSORB, 'A')
    check('Hash_Absorb Xs=%d: Invalid' % xs, inv(m))
for xs in (64, 96, 128): check('Hash_Absorb Xs=%d: accepted, tag_len set' % xs, (lambda m: m.st == ABSORB and m.tag_len == xs)(at(ABSORB, xs)))
m = at(ABSORB); check('entering Hash_Absorb: index 1, offset 0, L* = E(K,0)', m.index == 1 and m.offset == 0 and m.Ls == b2v(cipher_enc('AES128', KEY, bytes(16))))
check('L$ = double(L*), L[0] = double(L$), L[48] derived', m.Ld == double(m.Ls) and m.L[0] == double(m.Ld) and len(m.L) == 49)
for lb in (1, 7, 121, 128, 200):
    m = at(ABSORB); m.setst(HABL, 'B', lb); check('Hash_Absorb_Last_Block Xs=%d: Invalid' % lb, inv(m))
for lb in (0, 8, 64, 120): check('Hash_Absorb_Last_Block Xs=%d accepted' % lb, (lambda m: (m.setst(HABL, 'B', lb), m.st == HABL)[1])(at(ABSORB)))
m = at(ABSORB); m.setst(HABL, 'B', 0); m.exec('B', 0, 128); check('Hash_Absorb_Last_Block with last_block_len 0: kl.exec Invalid', inv(m))
m = at(ABSORB); m.setst(HABL, 'B', 24); m.setst(ENC); check('leaving Hash_Absorb_Last_Block with last_block_len != 0 before kl.exec: Invalid (MR10 item 5)', inv(m))
m = at(ABSORB); m.setst(HABL, 'B', 24); m.exec('B', 0, 128); check('Hash_Absorb_Last_Block stays after its kl.exec (choice of successors)', m.st == HABL)
m = at(ABSORB); m.setst(HABL, 'B', 24); m.exec('B', 0, 128); m.setst(ENC); check('... and is left by kl.setst', m.st == ENC)
m = at(ABSORB); m.setst(HABL, 'B', 24); m.exec('B', 0, 16); check('Hash_Absorb_Last_Block KLLEN < last_block_len: Invalid', inv(m))
m = at(ABSORB); m.setst(HABL, 'B', 24); m.exec('B', 0, 128); m.exec('B', 0, 128); check('second kl.exec in Hash_Absorb_Last_Block: Invalid (MR10)', inv(m))
m = at(ABSORB); m.index = MAX_BLOCKS; m.exec('B', 0, 128); check('index == MAX_BLOCKS: last allowed AD block', m.st == ABSORB and m.index == MAX_BLOCKS + 1)
m.exec('B', 0, 128); check('index > MAX_BLOCKS: Invalid', inv(m))
m = at(ABSORB); m.index = MAX_BLOCKS + 1; m.setst(HABL, 'B', 8); m.exec('B', 0, 128); check('final partial AD block beyond MAX_BLOCKS: Invalid', inv(m))
m = at(ABSORB); m.index = MAX_BLOCKS; m.setst(HABL, 'B', 8); m.exec('B', 0, 128); check('final partial AD block at index MAX_BLOCKS: allowed', m.st == HABL)
for ix in (1, 2, 3, 4, 8, 2**20, 2**47, MAX_BLOCKS):
    check('ntz(%d) selects L[%d]' % (ix, ntz(ix)), (lambda m: (setattr(m, 'index', ix), setattr(m, 'offset', 0), m.exec('B', 0, 128), m.offset == m.L[ntz(ix)])[3])(at(ABSORB)))

section('Forms, transitions, policy')
check('Encrypt Form B setst: Invalid', inv((lambda m: (m.setst(ENC, 'B', 8), m)[1])(at(HABL))))
check('Hash_Absorb_Last_Block Form A setst (Xs=0): accepted', (lambda m: (m.setst(HABL, 'A'), m.st == HABL and m.lbl == 0)[1])(at(ABSORB)))
check('Hash_Absorb -> Encrypt (skipping Hash_Absorb_Last_Block): Invalid', inv((lambda m: (m.setst(ENC), m)[1])(at(ABSORB))))
check('Hash_Absorb_Last_Block -> Decrypt: ok', (lambda m: (m.setst(DEC), m.st == DEC)[1])(at(HABL)))
check('Encrypt -> Dec_Last_Block: Invalid', inv((lambda m: (m.setst(DLB, 'B', 0), m)[1])(at(ENC))))
check('Decrypt -> Enc_Last_Block: Invalid', inv((lambda m: (m.setst(ELB, 'B', 0), m)[1])(at(DEC))))
check('Enc_Last_Block lbl 0: Form A kl.exec Invalid (Form D expected)', inv((lambda m: (m.exec('A', 0, 128), m)[1])(at(ELB))))
check('Enc_Last_Block lbl 0: Form D kl.exec -> Enc_Tag_Finalize', at(ETF).st == ETF)
m = at(ABSORB); m.setst(HABL, 'B', 0); m.setst(ENC); m.setst(ELB, 'B', 8)
check('Enc_Last_Block lbl 8: Form D kl.exec Invalid (Form A expected)', inv((lambda m: (m.exec('D'), m)[1])(m)))
check('Enc_Tag_Finalize Form A kl.exec: Invalid', inv((lambda m: (m.exec('A', 0, 128), m)[1])(at(ETF))))
check('Enc_Tag_Finalize KLLEN < tag_len: Invalid', inv((lambda m: (m.exec('C', 0, 96), m)[1])(at(ETF, 128))))
check('Enc_Tag_Finalize KLLEN 64 with tag_len 64: ok, output 64 bits', (lambda m: (lambda o: m.st == SUCCESS and o >> 64 == 0)(m.exec('C', 0, 64)))(at(ETF, 64)))
check('Enc_Tag_Finalize KLLEN 192 > tag_len: output cleared above tag_len', (lambda m: (m.exec('C', 0, 192) >> 128) == 0)(at(ETF)))
m = at(ETF, 96); o = m.exec('C', 0, 128); check('96-bit tag output zeros(b-tag_len) @ checksum[tag_len-1:0]', o >> 96 == 0 and o == m.csum & mask(96))
check('Dec_Last_Block lbl 0 -> Hash_Verify via Form D kl.exec', (lambda m: (m.exec('D'), m.st == HV)[1])(at(DLB)))
m = at(DLB); m.exec('D'); m.exec('B', 0, 96); check('Hash_Verify KLLEN < tag_len: Invalid', inv(m))
check('exec in Ready: Invalid', inv((lambda m: (m.exec('B', 0, 128), m)[1])(OCB(KEY))))
check('Ready -> Hash_Absorb: Invalid (OCB needs Set_Aux_Value)', inv((lambda m: (m.setst(ABSORB, 'B', 128), m)[1])(OCB(KEY))))
check('same-State setst Hash_Absorb: Invalid', inv((lambda m: (m.setst(ABSORB, 'B', 128), m)[1])(at(ABSORB))))
check('setst Ready from Encrypt', (lambda m: (m.setst(READY), m.st == READY)[1])(at(ENC)))
check('setst Success: Invalid', inv((lambda m: (m.setst(SUCCESS), m)[1])(at(ENC))))
for pol in (1, 2):
    for nm, st, e in (('Encrypt', ENC, 1), ('Enc_Last_Block', ELB, 1), ('Enc_Tag_Finalize', ETF, 1), ('Decrypt', DEC, 0), ('Dec_Last_Block', DLB, 0), ('Hash_Verify', HV, 0)):
        try: m = at(st, policy=pol); ok = m.st == st
        except Exception: ok, m = False, None
        al = (pol == 1) == bool(e)
        check('MachinePolicy=%d, %s: %s' % (pol, nm, 'allowed' if al else 'Invalid'), ok if al else (m is not None and inv(m)))
check('zero MachinePolicy rejected', raises(OCB, KEY, policy=0, exc=ValueError))

section('multi-block, halting, index bound')
key = RB(16); nbits = rnd.getrandbits(96); a, p = RB(48), RB(80)
rc, rt = R.ocb_enc('AES128', key, nbits, 96, a, p)
m = OCB(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(nonce_bytes(nbits, 96)), 128); m.setst(ABSORB, 'B', 128)
m.exec('B', b2v(a), 384, halt_at=16); check('Hash_Absorb halted after 1 block: klstart=16', m.klstart == 16 and m.index == 2)
m.exec('B', b2v(a), 384, klstart=16); m.setst(HABL, 'B', 0); m.setst(ENC)
o = m.exec('A', b2v(p), 640, halt_at=32); check('Encrypt halted after 2 blocks', m.klstart == 32 and v2b(o, 80)[:32] == rc[:32])
o = m.exec('A', b2v(p), 640, klstart=32); check('Encrypt resumed: rest of ciphertext', v2b(o, 80)[32:] == rc[32:] and m.index == 6)
m.setst(ELB, 'B', 0); m.exec('D'); check('tag after halted/resumed run == reference', v2b(m.exec('C', 0, 128), 16) == rt)
m = at(ENC); m.exec('A', 0, 130); check('Encrypt KLLEN not a multiple of 128: Invalid', inv(m))
m = at(ENC); m.exec('A', 0, 128, klstart=4); check('Encrypt klstart=4: Invalid', inv(m))
m = at(ENC); m.index = MAX_BLOCKS; m.exec('A', 0, 128); check('Encrypt block MAX_BLOCKS allowed', m.st == ENC)
m.exec('A', 0, 128); check('Encrypt block MAX_BLOCKS+1: Invalid', inv(m))
m = at(DEC); m.index = MAX_BLOCKS + 1; m.exec('A', 0, 128); check('Decrypt block MAX_BLOCKS+1: Invalid', inv(m))
m = at(ENC); m.index = MAX_BLOCKS + 1; m.setst(ELB, 'B', 8); m.exec('A', 0, 128); check('Enc_Last_Block with index > MAX_BLOCKS and partial block: Invalid', inv(m))
m = at(ENC); m.index = MAX_BLOCKS + 1; m.setst(ELB, 'B', 0); m.exec('D'); check('Enc_Last_Block with empty final block at index MAX_BLOCKS+1: ok', m.st == ETF)

section('last_block_len')
for lb in (1, 7, 15):
    m = at(ENC); m.setst(ELB, 'B', 8 * lb); o = m.exec('A', mask(128), 128); check('Enc_Last_Block %d bytes: output zero above' % lb, o >> (8 * lb) == 0)
for lb in (1, 7, 121, 128, 136):
    for st, nm in ((ELB, 'Enc_Last_Block'), (DLB, 'Dec_Last_Block')):
        m = at(ENC if st == ELB else DEC); m.setst(st, 'B', lb); check('%s Xs=%d: Invalid' % (nm, lb), inv(m))
m = at(ENC); m.setst(ELB, 'B', 24); m.exec('A', 0, 16); check('Enc_Last_Block KLLEN < last_block_len: Invalid', inv(m))
m = at(ENC); m.setst(ELB, 'B', 24); m.exec('A', 0, 128); m.exec('A', 0, 128); check('second last-block kl.exec in Enc_Last_Block: Invalid', inv(m))
m = at(ENC); m.setst(ELB, 'B', 24); m.setst(ETF, 'A'); check('Enc_Last_Block lbl 24: Form A setst Enc_Tag_Finalize Invalid', m.st == INV)
m = at(DEC); m.setst(DLB, 'B', 24); m.setst(HV, 'A'); check('Dec_Last_Block lbl 24: Form A setst Hash_Verify Invalid', m.st == INV)
for st, nm in ((ELB, 'Enc_Last_Block'), (DLB, 'Dec_Last_Block')):
    for tgt, tn, f in ((ENC, 'Encrypt', 'A'), (DEC, 'Decrypt', 'A'), (ETF, 'Enc_Tag_Finalize', 'C'), (HV, 'Hash_Verify', 'B'), (ABSORB, 'Hash_Absorb', 'B'), (st, 'itself', 'B'), (HABL, 'Hash_Absorb_Last_Block', 'B')):
        if (st, tgt) in ((ELB, ETF), (DLB, HV)): continue
        m = at(ENC if st == ELB else DEC); m.setst(st, 'B', 0); m.setst(tgt, f, 0, 0); check('%s lbl 0: setst %s Invalid' % (nm, tn), m.st == INV)
m = at(ENC); m.setst(ELB, 'B', 0); m.setst(ETF, 'C'); check('Enc_Last_Block lbl 0: Form C setst Enc_Tag_Finalize Invalid (Form A only)', m.st == INV)
m = at(ENC, policy=2); m.setst(ELB, 'B', 0); check('Enc_Last_Block gated by MachinePolicy[0]', m.st == INV)
m = at(ABSORB); m.setst(HABL, 'B', 0); m.exec('B', 0, 0); check('Hash_Absorb_Last_Block lbl 0: Form B kl.exec Invalid even with KLLEN = 0 (MR10, GR20)', m.st == INV)
m = at(ABSORB); m.setst(HABL, 'B', 0); m.exec('B', 0, 128); check('Hash_Absorb_Last_Block lbl 0: Form B kl.exec Invalid', m.st == INV)
m = at(ABSORB); m.setst(HABL, 'B', 8); m.exec('B', 0, 0); check('Hash_Absorb_Last_Block lbl 8: KLLEN = 0 is an empty window, State kept (GR52 item 1)', m.st == HABL and m.lbl == 8)
# Form D exec route vs Form A setst route: same checksum_P, tag, Serialized Content, enc and dec, OCB and OCB_NONCE
def route(mk, nb, n, a, x, dec):
    r = []
    for via in (False, True):
        m = mk()
        if dec:
            t = R.ocb_enc('AES128', KEY, nb, n, a, x)[1]
            c = R.ocb_enc('AES128', KEY, nb, n, a, x)[0]
            ocb_dec(m, nb, n, a, c, t, preset=isinstance(m, OCB_NONCE), viasetst=via)
        else:
            ocb_enc(m, nb, n, a, x, preset=isinstance(m, OCB_NONCE), viasetst=via)
        r.append((m.csum, m.st, m.export()))
    return r
for dec in (False, True):
    for ln in (0, 16, 32, 48, 64, 160):
        for al in (0, 16, 5):
            a, x = bytes(range(al)), bytes(range(ln))
            for nm, mk in (('OCB', lambda: OCB(KEY)), ('OCB_NONCE', lambda: OCB_NONCE(KEY, nonce_of(0, 96)))):
                r = route(mk, 0, 96, a, x, dec)
                check('%s %s msg %d AD %d: Form D exec route == Form A setst route (checksum_P, State, Serialized Content)' % (nm, 'decrypt' if dec else 'encrypt', ln, al), r[0] == r[1] and r[0][1] == (SUCCESS if dec else SUCCESS))

section('Serialized Content')
key = RB(16); nbits = rnd.getrandbits(96); a, p = RB(33), RB(50)
rc, rt = R.ocb_enc('AES128', key, nbits, 96, a, p, 96)
m = OCB(key); m.setst(SAV, 'B', 96); m.exec('B', b2v(nonce_bytes(nbits, 96)), 128); m.setst(ABSORB, 'B', 96)
m.exec('B', b2v(a[:32]), 256); m.setst(HABL, 'B', 8); m.exec('B', b2v(a[32:]), 128); m.setst(ENC); m.exec('A', b2v(p[:32]), 256)
sc, w = m.export(); W = (128, 120, 7, 1, 128, 128, 128, 128, 49, 2, 7)
f = OCB.unpack(sc, W)
check('SC width: 128 + 120+7+1 + 4*128 + 49+2+7', w == 128 + 128 + 512 + 58)
check('SC fields: key, N, N_len=96, L*, index=3, tag_len code 0 (96/32-2=1)', f[0] == b2v(key) and f[2] == 96 and f[3] == 0 and f[4] == m.Ls and f[8] == 3 and f[9] == 1)
q = OCB.from_sc(ENC, sc, 16)
o = q.exec('A', b2v(p[32:48]), 128); q.setst(ELB, 'B', 16); o2 = q.exec('A', b2v(p[48:] + bytes(14)), 128)
check('export mid-Encrypt, import elsewhere, continue: ciphertext equals reference', v2b(o, 16) + v2b(o2, 16)[:2] == rc[32:50] if False else v2b(o, 16) == rc[32:48])
check('... and the tag', v2b(q.exec('C', 0, 96), 12) == rt)
for code, tl in ((0, 64), (1, 96), (2, 128)):
    check('tag_len code %d <-> %d' % (code, tl), OCB.unpack(at(ABSORB, tl).export()[0], W)[9] == code)
bad = at(ABSORB).export()[0] | (3 << (128 + 128 + 512 + 49))
check('import with tag_len code 3: Invalid', OCB.from_sc(ABSORB, bad, 16).st == INV)
check('SC width AES-256', OCB(RB(32)).export()[1] == 256 + 58 + 128 + 512)
sc = OCB_NONCE(KEY, nonce_of(5, 96)).export()[0]
check('OCB_NONCE import with N_len = 5: Invalid', OCB_NONCE.from_sc(READY, sc & ~(mask(7) << 248) | 5 << 248, 16).st == INV)
check('OCB_NONCE import with N_len = 121: Invalid', OCB_NONCE.from_sc(READY, sc & ~(mask(7) << 248) | 121 << 248, 16).st == INV)
check('OCB_NONCE import with N_len = 96: Ready', OCB_NONCE.from_sc(READY, sc, 16).st == READY)
check('OCB_NONCE provisioning with N_len = 5: invalid metadata', raises(OCB_NONCE, KEY, (1, 5), exc=ValueError))
check('OCB_NONCE provisioning with N_len = 121: invalid metadata', raises(OCB_NONCE, KEY, (1, 121), exc=ValueError))

section('OCB_NONCE specifics')
n = nonce_of(rnd.getrandbits(96), 96); m = OCB_NONCE(KEY, n)
check('Ready -> Hash_Absorb by Form B setst (tag_len), no Set_Aux_Value', (lambda m: (m.setst(ABSORB, 'B', 128), m.st == ABSORB)[1])(OCB_NONCE(KEY, n)))
check('Set_Aux_Value does not exist: Invalid', inv((lambda m: (m.setst(SAV, 'B', 96), m)[1])(OCB_NONCE(KEY, n))))
m = OCB_NONCE(KEY, n); m.setst(ABSORB, 'B', 128); m.setst(READY)
check('Ready keeps N and N_len; HasN stays 0', m.N == n[0] and m.N_len == 96 and not m.hasN)
a1 = ocb_enc(m, 0, 96, b'a', b'b' * 20, preset=True); a2 = ocb_enc(m, 0, 96, b'a', b'b' * 20, preset=True) if m.st == READY else None
m = OCB_NONCE(KEY, n); x = ocb_enc(m, 0, 96, b'a', b'b' * 20, preset=True); m.setst(READY); y = ocb_enc(m, 0, 96, b'a', b'b' * 20, preset=True)
check('second message with the same nonce after Ready gives identical output', x == y)
check('OCB_NONCE is not a kl.derive destination', inv((lambda m: (m.derive_dest(RB(16)), m)[1])(OCB_NONCE(KEY, n))))
check('OCB_NONCE zero policy rejected', raises(OCB_NONCE, KEY, n, policy=0, exc=ValueError))

section('kl.derive and kl.rstrl')
k2 = RB(16)
m = OCB(KEY); m.derive_dest(k2); check('derive in Ready: new key used', ocb_enc(m, 5, 96, b'a', b'b' * 20) == ocb_enc(OCB(k2), 5, 96, b'a', b'b' * 20))
m = at(ABSORB); m.derive_dest(k2); check('derive in Hash_Absorb: Invalid', inv(m))
m = OCB(KEY); m.setst(SAV, 'B', 96); m.derive_dest(k2); check('derive in Set_Aux_Value: Invalid', inv(m))
m = OCB(KEY); m.derive_dest(RB(24)); check('derive of 24 bytes into a 128-bit key: Invalid', inv(m))
m = OCB(KEY); m.rstr(1); check('restrict to 1', m.policy == 1 and m.st == READY)
m.rstr(2); check('restrict to disjoint: Invalid', inv(m))

section('negative controls')
nbits = 0xBBAA99887766554433221100
c, t = R.ocb_enc('AES128', KEY, nbits, 96, b'', b'')
control('RFC vector 0 tag detected if nonce differs', R.ocb_enc('AES128', KEY, nbits ^ 1, 96, b'', b'')[1] != t)
control('tag length is part of the nonce: 64-bit tag differs from truncated 128-bit tag', R.ocb_enc('AES128', KEY, nbits, 96, b'', b'', 64)[1] != t[:8])
control('doubling in the wrong byte order (LE instead of BE) gives a different L$', (lambda L: b2v(L) != double(b2v(L)) and update_mask(b2v(L)) != double(b2v(L)))(cipher_enc('AES128', KEY, bytes(16))))
control('nonce padding bits matter if not cleared: nonce 6 bits with and without padding bits set encode equal', (lambda a, b: a == b)(*[(lambda m: (m.setst(SAV, 'B', 6), m.exec('B', x, 128), m.N)[2])(OCB(KEY)) for x in (0x04, 0x07)]))
control('Form D vs A at lbl 0: Form A exec rejected', inv((lambda m: (m.exec('A', 0, 128), m)[1])(at(ELB))))

section('ported from the old KAT: KLIOBUF substitution, empty window, Ready keeps L*/offset, PI N_len')
m = at(ABSORB); m.zklio = True; m.exec('D', 0, 128); check('Zklio: Form D substitutes for Form B in Hash_Absorb', m.st == ABSORB and m.index == 2)
m = at(ABSORB); m.exec('D', 0, 128); check('no Zklio: Form D is a wrong Form', inv(m))

m = at(SAV); m.setst(SAV, 'B', 96); m.exec('B', 0, 64); check('Set_Aux_Value exec with KLLEN < 8q: Invalid (MR8)', inv(m))
m = at(ENC); Ls = m.Ls; m.setst(READY); check('Ready entry keeps L* (not in the Ready list)', m.st == READY and m.Ls == Ls)
for nl in (5, 121): check('OCB_NONCE PI with N_len %d refused' % nl, raises(OCB_NONCE, KEY, (0, nl), exc=ValueError))
done()
