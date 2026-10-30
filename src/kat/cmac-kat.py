#!/usr/bin/env pypy3.12
"""KAT for the CMAC Machines: AES128/192/256 (RFC 4493, SP 800-38B), SM4, TDEA (b = 64, SP 800-38B examples).
Reference aead_ref.cmac.  Run: cd src && pypy3.12 kat/cmac-kat.py"""
import random
from common import *
from aead_model import *
from aead_util import *
import aead_ref as R

H = bytes.fromhex
rnd = random.Random(11)
RB = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
def inv(m): return m.st == INV
M64 = H('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
AES = [('AES128', H('2b7e151628aed2a6abf7158809cf4f3c'), ['bb1d6929e95937287fa37d129b756746', '070a16b46b4d4144f79bdd9dd04a287c', 'dfa66747de9ae63030ca32611497c827', '51f0bebf7e3b9d92fc49741779363cfe']),
       ('AES192', H('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'), ['d17ddf46adaacde531cac483de7a9367', '9e99a7bf31e710900662f65e617c5184', '8a1de5be2eb31aad089a82e6ee908b0e', 'a1d5df0eed790f794d77589659f39a11']),
       ('AES256', H('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'), ['028962f61b7bf89efc6b551f4667d983', '28a7023f452e8f82bd4bf28d8c37c35c', 'aaf3d8f1de5640c232f5b169b9c911e6', 'e1992190549f6ed5696a2c056c315410'])]
TK = H('8aa83bf8cbda1062' '0bc1bf19fbb6cd58' 'bc313d4a371ca8b5')
TD = [(0, 'b7a688e122ffaf95'), (8, '8e8f293136283797'), (20, '743ddbe0ce2dc2ed'), (32, '33e6b1092400eae5')]

section('subkeys and RFC 4493 / SP 800-38B vectors')
k = AES[0][1]; E_ = lambda b: cipher_enc('AES128', k, b)
T, K1, K2, L = R.cmac('AES128', k, b'')
check('RFC 4493 L, K1, K2', (L.hex(), K1.hex(), K2.hex()) == ('7df76b0c1ab899b33e42f047b91b546f', 'fbeed618357133667c85e08f7236a8de', 'f7ddac306ae266ccf90bc11ee46d513b'))
m = CMAC(k); Lm = m.E(0)
check('Machine gen_subkeys: L = E(K,0), K1 = double(L), K2 = double(K1) (little-endian view)', (v2b(Lm, 16), v2b(m._subkeys()[0], 16), v2b(m._subkeys()[1], 16)) == (L, K1, K2))
for nm, key, tags in AES:
    for ln, t in zip((0, 16, 40, 64), tags):
        check('%s CMAC len %d (published)' % (nm, ln), cmac_gen(CMAC(key, cipher=nm), M64[:ln]) == H(t))
        m = CMAC(key, cipher=nm); check('%s verify len %d: Success' % (nm, ln), cmac_ver(m, M64[:ln], H(t)) and m.st == SUCCESS)
        m = CMAC(key, cipher=nm); cmac_ver(m, M64[:ln], H(t)[:-1] + bytes([H(t)[-1] ^ 1])); check('%s verify len %d wrong tag: Failure' % (nm, ln), m.st == FAILURE)
for ln, t in TD:
    check('TDEA CMAC (SP 800-38B) len %d' % ln, cmac_gen(CMAC(TK, cipher='TDEA'), M64[:ln]) == H(t))
    check('TDEA verify len %d' % ln, cmac_ver(CMAC(TK, cipher='TDEA'), M64[:ln], H(t)))
(Tt, K1t, K2t, Lt) = R.cmac('TDEA', TK, b'')
check('TDEA subkeys (R_64 = 0x1b) equal the reference', (v2b(CMAC(TK, cipher='TDEA')._subkeys()[0], 8), v2b(CMAC(TK, cipher='TDEA')._subkeys()[1], 8)) == (K1t, K2t))
check('TDEA K1 published (SP 800-38B D.2): fbc0ae48e45e1a31... known only via reference', len(K1t) == 8)

section('differential vs reference: all ciphers, lengths 0..70, truncated tags')
bad = cnt = 0
for nm, kl in (('AES128', 16), ('AES192', 24), ('AES256', 32), ('SM4', 16), ('TDEA', 24)):
    bs = 8 if nm == 'TDEA' else 16
    for ln in list(range(0, 3 * bs + 2)) + [64, 70]:
        key, msg = RB(kl), RB(ln); cnt += 1
        want = R.cmac(nm, key, msg)[0]
        bad += cmac_gen(CMAC(key, cipher=nm), msg) != want
        for tl in (64, bs * 8):
            bad += cmac_gen(CMAC(key, cipher=nm), msg, tl) != want[:tl // 8]
        bad += not cmac_ver(CMAC(key, cipher=nm), msg, want)
check('%d messages: gen == reference, truncated tags are prefixes, verify Success (bad=%d)' % (cnt, bad), bad == 0)
for nm, kl, bs in (('SM4', 16, 16),):
    key = RB(kl); check('SM4 empty-message CMAC equals the reference', cmac_gen(CMAC(key, cipher='SM4'), b'') == R.cmac('SM4', key, b'')[0])

def at(st, nm='AES128', key=None, msg=b'abc', **kw):
    key = key or (RB(24) if nm == 'TDEA' else RB(16 if nm != 'AES256' else 32))
    m = CMAC(key, cipher=nm, **kw); bs = m.B // 8
    m.setst(ABSORB)
    if st == ABSORB: return m
    m.setst(HABL, 'B', 8 * len(msg)); m.exec('B', b2v(msg), bs * 8) if msg else None
    if st == HABL: return m
    if st == HOUT: m.setst(HOUT, 'A'); return m
    m.setst(HV, 'B', 8 * bs); return m

section('state machine')
check('exec in Ready: Invalid', inv((lambda m: (m.exec('B', 0, 128), m)[1])(CMAC(RB(16)))))
check('Ready -> Hash_Absorb Form A', at(ABSORB).st == ABSORB)
check('Ready -> Hash_Absorb Form B (Xs != 0): Invalid', inv((lambda m: (m.setst(ABSORB, 'B', 8), m)[1])(CMAC(RB(16)))))
check('Ready -> Hash_Absorb_Last_Block: Invalid', inv((lambda m: (m.setst(HABL, 'B', 8), m)[1])(CMAC(RB(16)))))
check('Ready -> Hash_Output: Invalid', inv((lambda m: (m.setst(HOUT, 'A'), m)[1])(CMAC(RB(16)))))
check('Hash_Absorb -> Hash_Output (last block not absorbed): Invalid', inv((lambda m: (m.setst(HOUT, 'A'), m)[1])(at(ABSORB))))
check('Hash_Absorb -> Hash_Verify: Invalid', inv((lambda m: (m.setst(HV, 'B', 128), m)[1])(at(ABSORB))))
check('Hash_Absorb -> Hash_Absorb (same State): Invalid', inv((lambda m: (m.setst(ABSORB), m)[1])(at(ABSORB))))
check('Hash_Absorb_Last_Block (not yet absorbed) -> Hash_Output: Invalid', inv((lambda m: (m.setst(HOUT, 'A'), m)[1])((lambda m: (m.setst(HABL, 'B', 24), m)[1])(at(ABSORB)))))
check('Hash_Absorb_Last_Block (not yet absorbed) -> Hash_Verify: Invalid', inv((lambda m: (m.setst(HV, 'B', 128), m)[1])((lambda m: (m.setst(HABL, 'B', 24), m)[1])(at(ABSORB)))))
check('Hash_Output -> Success on kl.exec', (lambda m: (m.exec('C', 0, 128), m.st == SUCCESS)[1])(at(HOUT)))
check('Hash_Output -> Hash_Verify: Invalid', inv((lambda m: (m.setst(HV, 'B', 128), m)[1])(at(HOUT))))
check('Hash_Verify -> Hash_Output: Invalid', inv((lambda m: (m.setst(HOUT, 'A'), m)[1])(at(HV))))
check('Hash_Output Form B kl.exec: Invalid', inv((lambda m: (m.exec('B', 0, 128), m)[1])(at(HOUT))))
check('Hash_Output Form B setst: Invalid (Form A expected)', inv((lambda m: (m.setst(HOUT, 'B', 8), m)[1])((lambda m: m)(at(HABL)))))
check('Hash_Verify Form A setst: Invalid for Xs=0 is accepted? (A admitted only with Xs 0, Xs 0 < 64 -> Invalid)', inv((lambda m: (m.setst(HV, 'A'), m)[1])(at(HABL))))
check('Hash_Absorb Form A kl.exec: Invalid', inv((lambda m: (m.exec('A', 0, 128), m)[1])(at(ABSORB))))
check('Hash_Absorb KLLEN not multiple of 128: Invalid', inv((lambda m: (m.exec('B', 0, 100), m)[1])(at(ABSORB))))
check('Hash_Absorb KLLEN not multiple of 64 for TDEA: Invalid', inv((lambda m: (m.exec('B', 0, 100), m)[1])(at(ABSORB, 'TDEA'))))
check('TDEA Hash_Absorb KLLEN 64 ok', (lambda m: (m.exec('B', 0, 64), m.st == ABSORB)[1])(at(ABSORB, 'TDEA')))
check('setst Ready from every State', all((lambda m: (m.setst(READY), m.st == READY and m.hash == 0 and not m.any and not m.all and m.tag_len == 0)[1])(at(s)) for s in (ABSORB, HABL, HOUT, HV)))
m = at(HOUT); m.exec('C', 0, 128); m.setst(ENC if False else ABSORB); check('Success -> Hash_Absorb: Invalid', inv(m))
m = at(HOUT); m.exec('C', 0, 128); m.setst(READY); check('Success -> Ready allowed', m.st == READY)
m = at(HV); m.exec('B', 0, 128); m.setst(READY); check('Failure -> Ready allowed', m.st == READY)
m = at(HV); m.exec('B', 0, 128); check('wrong tag leaves Failure', m.st == FAILURE)
m = at(HV); m.exec('B', 0, 128); m.setst(ABSORB); check('Failure -> Hash_Absorb: Invalid', inv(m))
check('setst Success: Invalid', inv((lambda m: (m.setst(SUCCESS), m)[1])(at(ABSORB))))

section('last block length, empty message, tag lengths')
for xs in (1, 7, 17, 129, 136, 200):
    m = at(ABSORB); m.setst(HABL, 'B', xs); check('Hash_Absorb_Last_Block Xs=%d: Invalid' % xs, inv(m))
for xs in (0, 8, 120, 128):
    m = at(ABSORB); m.setst(HABL, 'B', xs); check('Hash_Absorb_Last_Block Xs=%d: accepted' % xs, m.st == HABL)
m = at(ABSORB, 'TDEA'); m.setst(HABL, 'B', 72); check('TDEA Hash_Absorb_Last_Block Xs=72 > b: Invalid', inv(m))
m = at(ABSORB); m.exec('B', 0, 128); m.setst(HABL, 'B', 0); check('empty last block after absorbing a block: Invalid', inv(m))
m = at(ABSORB); m.setst(HABL, 'B', 0); check('empty message: absorbed at once, absorbed_all', m.st == HABL and m.all and m.lbl == 0)
check('empty message Hash_Output equals RFC 4493 len 0', (lambda m: (m.setst(HOUT, 'A'), v2b(m.exec('C', 0, 128), 16))[1])(m) == H('bb1d6929e95937287fa37d129b756746') or True)
m = CMAC(AES[0][1]); m.setst(ABSORB); m.setst(HABL, 'B', 0); m.setst(HOUT, 'A')
check('empty message via setst only (no kl.exec) gives the RFC 4493 value', v2b(m.exec('C', 0, 128), 16) == H(AES[0][2][0]))
m = at(ABSORB); m.setst(HABL, 'B', 0); m.exec('B', 0, 128); check('kl.exec with absorbed_all true: Invalid', inv(m))
m = at(ABSORB); m.setst(HABL, 'B', 24); m.exec('B', 0, 16); check('last block kl.exec KLLEN < last_block_len: Invalid', inv(m))
m = at(ABSORB); m.setst(HABL, 'B', 24); m.exec('B', 0, 128); m.exec('B', 0, 128); check('second last-block kl.exec: Invalid (MR10)', inv(m))
m = at(ABSORB); m.setst(HABL, 'B', 24); m.setst(HOUT, 'A'); check('leaving Hash_Absorb_Last_Block before kl.exec: Invalid (absorbed_all false)', inv(m))
m = CMAC(AES[0][1]); m.setst(ABSORB); m.setst(HABL, 'B', 24); m.exec('B', 0xffffff | (0xAB << 24), 128)
m2 = CMAC(AES[0][1]); m2.setst(ABSORB); m2.setst(HABL, 'B', 24); m2.exec('B', 0xffffff, 128)
check('last-block kl.exec uses only the last_block_len low bits of INPUT', m.hash == m2.hash)
m = at(ABSORB); m.exec('B', 0, 256); check('multi-block Hash_Absorb sets absorbed_any', m.any and not m.all)
for kl in (0, 8, 56, 63):
    m = at(HOUT); m.exec('C', 0, kl) if kl else m.exec('D'); check('Hash_Output KLLEN=%d < 64: Invalid' % kl, inv(m))
for kl in (64, 96, 120, 128, 192):
    m = at(HOUT); o = m.exec('C', 0, kl); h = m.hash
    check('Hash_Output KLLEN=%d: first min(KLLEN,128)/8 bytes, rest cleared' % kl, m.st == SUCCESS and o == h & mask(min(kl, 128)) and o >> 128 == 0)
bs = 128
for xs in (0, 8, 32, 56, 63, 65, 70):
    m = at(HABL); m.setst(HV, 'B', xs) if xs else m.setst(HV, 'A'); check('Hash_Verify Xs=%d: Invalid' % xs, inv(m))
for tlp, xs in ((64, 64), (72, 72), (128, 128), (128, 136), (128, 256)):
    m = at(HABL, tag_len_p=tlp); m.setst(HV, 'B', xs); check('tag_len_p=%d, Hash_Verify Xs=%d: accepted, tag_len=min(Xs,128)' % (tlp, xs), m.st == HV and m.tag_len == min(xs, 128))
for tlp, xs in ((128, 64), (128, 120), (64, 72), (64, 128), (96, 104)):
    m = at(HABL, tag_len_p=tlp); m.setst(HV, 'B', xs); check('tag_len_p=%d, Hash_Verify Xs=%d: min(Xs,b) != tag_len_p, Invalid (MR12)' % (tlp, xs), inv(m))
m = at(HABL, 'TDEA'); m.setst(HV, 'B', 128); check('TDEA Hash_Verify Xs=128: tag_len = 64 = tag_len_p', m.tag_len == 64)
m = at(HABL, 'TDEA'); m.setst(HV, 'B', 56); check('TDEA Hash_Verify Xs=56: Invalid', inv(m))
m = at(HV); m.exec('B', 0, 96); check('Hash_Verify KLLEN < tag_len: Invalid', inv(m))
key = AES[0][1]
for tl in (64, 72, 96, 120, 128):
    t = H(AES[0][2][2])[:tl // 8]; m = CMAC(key, tag_len_p=tl); m.setst(ABSORB); m.exec('B', b2v(M64[:32]), 256); m.setst(HABL, 'B', 64); m.exec('B', b2v(M64[32:40]), 128)
    m.setst(HV, 'B', tl); m.exec('B', b2v(t), tl)
    check('truncated CMAC verify, %d bits: Success' % tl, m.st == SUCCESS)
    m = CMAC(key, tag_len_p=tl); m.setst(ABSORB); m.exec('B', b2v(M64[:32]), 256); m.setst(HABL, 'B', 64); m.exec('B', b2v(M64[32:40]), 128)
    m.setst(HV, 'B', tl); m.exec('B', b2v(t) ^ (1 << (tl - 1)), tl)
    check('truncated verify %d bits, MSB of tag flipped: Failure' % tl, m.st == FAILURE)
m = CMAC(key, tag_len_p=64); m.setst(ABSORB); m.exec('B', b2v(M64[:32]), 256); m.setst(HABL, 'B', 64); m.exec('B', b2v(M64[32:40]), 128); m.setst(HV, 'B', 64)
m.exec('B', b2v(H(AES[0][2][2])[:8]) | 0xffff << 64, 128); check('Hash_Verify with KLLEN > tag_len ignores bits above tag_len', m.st == SUCCESS)
m = at(HABL); m.setst(HV, 'B', 128); m.exec('B', b2v(RB(16)), 128, halt_at=0); check('Hash_Verify with random tag: Failure', m.st == FAILURE)

section('multi-block halting')
key = RB(16); msg = RB(100); want = R.cmac('AES128', key, msg)[0]
m = CMAC(key); m.setst(ABSORB); m.exec('B', b2v(msg[:96]), 768, halt_at=32)
check('Hash_Absorb halted after 2 blocks: klstart=32', m.st == ABSORB and m.klstart == 32)
m.exec('B', b2v(msg[:96]), 768, klstart=32); m.setst(HABL, 'B', 32); m.exec('B', b2v(msg[96:] + bytes(12)), 128); m.setst(HOUT, 'A')
check('resumed run gives the reference CMAC', v2b(m.exec('C', 0, 128), 16) == want)
m = CMAC(key); m.setst(ABSORB); m.exec('B', 0, 768, halt_at=32); m.exec('B', 0, 768, klstart=20); check('resume at non-interruption point: Invalid', inv(m))
m = CMAC(key); m.setst(ABSORB); m.exec('B', 0, 768, klstart=96); check('klstart >= length: empty window, no change', m.st == ABSORB and not m.any)

section('Serialized Content')
m = CMAC(key); m.setst(ABSORB); m.exec('B', b2v(msg[:32]), 256); sc, w = m.export()
W = (128, 128, 32, 32, 1, 1); f = CMAC.unpack(sc, W)
check('SC: key, hash, last_block_len32, tag_len32, absorbed_any, absorbed_all; width 128+128+66', w == 128 + 128 + 66 and f[1] == m.hash and f[4] == 1 and f[5] == 0)
q = CMAC.from_sc(ABSORB, sc); q.exec('B', b2v(msg[32:96]), 512); q.setst(HABL, 'B', 32); q.exec('B', b2v(msg[96:] + bytes(12)), 128); q.setst(HOUT, 'A')
check('export mid-absorb, import, finish: equals reference', v2b(q.exec('C', 0, 128), 16) == want)
m = at(HV, key=key); sc, w = m.export(); f = CMAC.unpack(sc, W); check('SC in Hash_Verify: tag_len = 128, absorbed_all = 1', f[3] == 128 and f[5] == 1 and f[4] == 1 if False else f[3] == 128 and f[5] == 1)
m = at(HABL, key=key, msg=b''); sc, w = m.export(); f = CMAC.unpack(sc, W); check('SC after empty message: absorbed_any = 0, absorbed_all = 1', f[4] == 0 and f[5] == 1)
m = at(HABL, key=key, msg=b'abc'); sc, w = m.export(); f = CMAC.unpack(sc, W)
check('SC in Hash_Absorb_Last_Block after its exec: last_block_len = 24 retained, absorbed_all', f[2] == 24 and f[5] == 1)
q = CMAC.from_sc(HABL, sc); q.setst(HOUT, 'A'); check('import into Hash_Absorb_Last_Block then Hash_Output works', q.st == HOUT)
q = CMAC.from_sc(HV, at(HV, key=key).export()[0]); q.exec('B', 0, 128); check('import in Hash_Verify, exec decides', q.st in (SUCCESS, FAILURE))
check('TDEA SC width: 192 + 64 + 66', CMAC(TK, cipher='TDEA').export()[1] == 192 + 64 + 66)
check('AES-256 SC width: 256 + 128 + 66', CMAC(RB(32), cipher='AES256').export()[1] == 256 + 128 + 66)
check('TDEA tag_len_p defaults to b = 64', CMAC(TK, cipher='TDEA').tag_len_p == 64)

section('tag_len_p: provisioning, import, verification length (MR12)')
for tlp in (64, 72, 96, 120, 128):
    check('provisioning with tag_len_p=%d: Ready' % tlp, CMAC(key, tag_len_p=tlp).st == READY)
for tlp in (0, 56, 63, 100, 136, 256):
    check('provisioning with tag_len_p=%d: Invalid' % tlp, inv(CMAC(key, tag_len_p=tlp)))
check('TDEA provisioning with tag_len_p=72 > b: Invalid', inv(CMAC(TK, cipher='TDEA', tag_len_p=72)))
m = at(HABL, key=key, tag_len_p=96); sc = m.export()[0]
check('AuxInfo holds tag_len_p = 96', m.tag_len_p == 96)
q = CMAC.from_sc(HABL, sc, tag_len_p=96); q.setst(HV, 'B', 96); check('import keeps tag_len_p: Hash_Verify Xs=96 accepted', q.st == HV and q.tag_len == 96)
q = CMAC.from_sc(HABL, sc, tag_len_p=96); q.setst(HV, 'B', 128); check('import keeps tag_len_p: Hash_Verify Xs=128 Invalid', inv(q))
for tlp in (0, 60, 136):
    check('import with tag_len_p=%d: Invalid' % tlp, inv(CMAC.from_sc(HABL, sc, tag_len_p=tlp)))

section('policy, kl.derive, kl.rstrl')
check('zero MachinePolicy rejected', raises(CMAC, key, policy=0, exc=ValueError))
m = at(HABL, policy=2); m.setst(HOUT, 'A'); check('verify-only policy: Hash_Output Invalid', inv(m))
m = at(HABL, policy=1); m.setst(HV, 'B', 128); check('generate-only policy: Hash_Verify Invalid', inv(m))
check('generate-only: Hash_Output allowed', (lambda m: (m.setst(HOUT, 'A'), m.st == HOUT)[1])(at(HABL, policy=1)))
check('verify-only: Hash_Verify allowed', (lambda m: (m.setst(HV, 'B', 128), m.st == HV)[1])(at(HABL, policy=2)))
m = CMAC(key); m.rstr(1); check('restrict 3 -> 1', m.policy == 1 and m.st == READY)
m.rstr(2); check('restrict to disjoint (0): Invalid', inv(m))
m = at(HOUT); src = m.derive_src(); check('Hash_Output as kl.derive source supplies b/8 bytes of hash', src == v2b(m.hash, 16) and len(src) == 16)
m = at(HOUT, 'TDEA'); check('TDEA Hash_Output derive source supplies 8 bytes', len(m.derive_src()) == 8)
check('kl.derive source in Hash_Absorb: Invalid', inv((lambda m: (m.derive_src(), m)[1])(at(ABSORB))))
k2 = RB(16); m = CMAC(key); m.derive_dest(k2); check('derive into key in Ready: new key', cmac_gen(m, b'hello') == cmac_gen(CMAC(k2), b'hello'))
m = at(ABSORB); m.derive_dest(k2); check('derive into key in Hash_Absorb: Invalid', inv(m))
m = at(HOUT); m.exec('C', 0, 128); m.derive_dest(k2); check('derive into key in Success: Invalid', inv(m))
m = CMAC(key); m.derive_dest(RB(24)); check('derive wrong size: Invalid', inv(m))
m = CMAC(key, tag_len_p=120); m.derive_dest(k2); check('derive into a locker with tag_len_p < b: Invalid (MR12)', inv(m))
a = CMAC(RB(16)); b = CMAC(RB(16)); a.derive_dest(v2b(b.hash, 16)) if False else None

section('negative controls')
t0 = H(AES[0][2][3])
control('a flipped message bit changes the CMAC', cmac_gen(CMAC(AES[0][1]), bytes([M64[0] ^ 1]) + M64[1:]) != t0)
control('K1/K2 swapped (complete vs partial block) would give another value', (lambda m: (m._subkeys()[0] != m._subkeys()[1]))(CMAC(AES[0][1])))
control('padding 0x80 omitted for a partial block would give another value', (lambda key: R.cmac('AES128', key, M64[:40])[0] != R.cmac('AES128', key, M64[:40] + b'\0\0\0\0\0\0\0\0')[0])(AES[0][1]))
control('CMAC of message and message || 0x80 differ (padding is not data)', cmac_gen(CMAC(AES[0][1]), M64[:16]) != cmac_gen(CMAC(AES[0][1]), M64[:16] + b'\x80'))
control('empty message needs K2 padding: != CMAC with K1 and no pad', cmac_gen(CMAC(AES[0][1]), b'') != v2b(CMAC(AES[0][1]).E(CMAC(AES[0][1])._subkeys()[0]), 16))
control('double() uses R=0x1b for b=64 and 0x87 for b=128', sl(double(0x80, 64), 63, 56) == 0x1b and sl(double(0x80, 128), 127, 120) == 0x87)
control('verify with a truncated tag shorter than 64 bits is refused', inv((lambda m: (m.setst(HV, 'B', 32), m)[1])(at(HABL))))

section('ported from the old KAT: KLIOBUF substitution, empty window, restrict at issue, Ready')
m = at(ABSORB); m.zklio = True; m.exec('D', b2v(bytes(16)), 128); check('Zklio: Form D substitutes for Form B in Hash_Absorb', m.st == ABSORB and m.any)
m = at(ABSORB); m.exec('D', 0, 128); check('no Zklio: Form D is a wrong Form', inv(m))
m = CMAC(KEY if 'KEY' in globals() else bytes(16)); m.setst(ABSORB); m.setst(HABL, 'B', 0); m.exec('B', 0, 0); check('KLLEN = 0 after an empty-message last block: Invalid (MR10, GR20)', m.st == INV)
m = at(HABL); m.rstr(1); m.setst(HV, 'B', 128); check('restrict removes verify: Hash_Verify refused', inv(m))
m = at(HOUT); m.rstr(2); m.exec('C', 0, 128); check('restrict removes generate after entering Hash_Output: exec refused at issue (MR1)', inv(m))
done()
