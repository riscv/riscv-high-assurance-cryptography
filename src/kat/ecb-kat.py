#!/usr/bin/env pypy3.12
"""KAT of the ECB Machines (AES128/192/256_ECB, SM4_ECB), Zkl-ISA-machines.adoc KLE-ECB-mode.
Standards: FIPS 197 App. C, SP 800-38A F.1, GB/T 32907-2016 App. A.  Run: cd src && pypy3.12 kat/ecb-kat.py"""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
from sym_model import *
from sym_ref import lib

H = bytes.fromhex
def blocks_v(bl): return b2v(b''.join(bl))
def blocks_b(v, n): return v2b(v, 16 * n)
def lk(typ, policy=3, key=None, mode=0):
    return Locker(machine(typ, mode), policy, key if key is not None else bytes(KEYLEN[TYPES[typ]]))
def run(L, imm, bl):
    L.setst(imm); return L.exec(blocks_v(bl), 128 * len(bl))[0]

section('FIPS 197 App. C single block: reference cipher and locker')
PT = H('00112233445566778899aabbccddeeff')
FIPS = [(0, H('000102030405060708090a0b0c0d0e0f'), H('69c4e0d86a7b0430d8cdb78070b4c55a')),
        (1, bytes(range(24)), H('dda97ca4864cdfe06eaf70a0ec0d7191')),
        (2, bytes(range(32)), H('8ea2b7ca516745bfeafc49904b496089'))]
FIPS[0] = (0, bytes(range(16)), FIPS[0][2])
for t, k, ct in FIPS:
    n = TYPES[t]
    check(n + ' reference enc', cipher_enc(n, k, PT) == ct); check(n + ' reference dec', cipher_dec(n, k, ct) == PT)
    L = lk(t, 3, k)
    check(n + '_ECB locker Encrypt', v2b(run(L, S_ENC, [PT]), 16) == ct)
    check(n + '_ECB locker Decrypt', v2b(run(L, S_DEC, [ct]), 16) == PT)

section('SP 800-38A F.1: four blocks in one kl.exec')
P4 = [H(x) for x in ('6bc1bee22e409f96e93d7e117393172a', 'ae2d8a571e03ac9c9eb76fac45af8e51',
                     '30c81c46a35ce411e5fbc1191a0a52ef', 'f69f2445df4f9b17ad2b417be66c3710')]
F1 = [(0, H('2b7e151628aed2a6abf7158809cf4f3c'), '3ad77bb40d7a3660a89ecaf32466ef97 f5d3d58503b9699de785895a96fdbaaf '
                                                '43b1cd7f598ece23881b00e3ed030688 7b0c785e27e8ad3f8223207104725dd4'),
      (1, H('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'), 'bd334f1d6e45f25ff712a214571fa5cc 974104846d0ad3ad7734ecb3ecee4eef '
                                                                 'ef7afd2270e2e60adce0ba2face6444e 9a4b41ba738d6c72fb16691603c18e0e'),
      (2, H('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'),
       'f3eed1bdb5d2a03c064b5a7e3db181f8 591ccb10d410ed26dc5ba74a31362870 b6ed21b99ca6f4f9f153e7b1beafed1d 23304b7a39f9f3ff067d8d8f9e24ecc7')]
for t, k, cts in F1:
    n = TYPES[t]; C4 = [H(x) for x in cts.split()]
    check(n + ' reference enc', [cipher_enc(n, k, p) for p in P4] == C4)
    L = lk(t, 3, k)
    check(n + '_ECB Encrypt 4 blocks', run(L, S_ENC, P4) == blocks_v(C4))
    check(n + '_ECB Decrypt 4 blocks', run(L, S_DEC, C4) == blocks_v(P4))
    if t == 0:
        control('MR13 block order reversed is detected', run(lk(0, 3, k), S_ENC, P4) != blocks_v(C4[::-1]))
        control('wrong key is detected', run(lk(0, 3, bytes(16)), S_ENC, P4) != blocks_v(C4))

section('SM4 (GB/T 32907-2016 App. A.1)')
K = H('0123456789abcdeffedcba9876543210')
check('SM4 example 1 enc', sm4_enc(K, K) == H('681edf34d206965e86b3e94f536e4246'))
check('SM4 example 1 dec', sm4_dec(K, H('681edf34d206965e86b3e94f536e4246')) == K)
x = K
for i in range(1000000): x = sm4_enc(K, x)
check('SM4 example 2: 1,000,000 encryptions', x == H('595298c7c6fd271f0402f804c33d3f66'))
L = lk(3, 3, K); x = K; ref = K
for i in range(2000):
    x = v2b(run(L, S_ENC, [x]) if i == 0 else L.exec(b2v(x), 128)[0], 16); ref = sm4_enc(K, ref)
check('SM4_ECB locker iterated 2000 times equals reference', x == ref)
check('SM4_ECB locker example 1', v2b(run(lk(3, 3, K), S_ENC, [K]), 16) == H('681edf34d206965e86b3e94f536e4246'))

section('Differential against OpenSSL (random keys and lengths)')
rnd = random.Random(1)
for t in range(4):
    n = TYPES[t]; bad = 0; cnt = 0
    for _ in range(40):
        k = bytes(rnd.getrandbits(8) for _ in range(KEYLEN[n])); nb = rnd.randint(1, 9)
        d = bytes(rnd.getrandbits(8) for _ in range(16 * nb)); L = lk(t, 3, k)
        r = lib(n, 'ECB', k, None, d)
        if r is None: break
        cnt += 1; bad += v2b(run(L, S_ENC, [d[i:i + 16] for i in range(0, len(d), 16)]), 16 * nb) != r
    if cnt: check(n + '_ECB vs OpenSSL, %d random cases' % cnt, bad == 0)
    else: info('cryptography package missing: differential skipped')

section('States, transitions, general rules')
k0 = bytes(range(16)); P = P4[0]
L = lk(0, 3, k0)
check('provisioned locker is Ready', L.state == S_READY and not L.inert() and mdh_get(L.mdh(), 'State') == ST_READY)
ref_c = cipher_enc('AES128', k0, P)
o, _ = L.exec(b2v(P), 128); check('kl.exec in Ready: Invalid, output zeros', o == 0 and mdh_get(L.mdh(), 'State') == 0
                                  and mdh_get(L.mdh(), 'StateExtension') == SE_INVALID)
check('Invalid locker: kl.exec is a no-op returning zeros', L.exec(b2v(P), 128) == (0, 0))
L.setst(S_ENC); check('Invalid locker: kl.setst is a no-op', L.inert() and mdh_get(L.mdh(), 'State') == 0)
L = lk(0, 3, k0); L.setst(S_ENC)
check('Ready -> Encrypt (State 7)', mdh_get(L.mdh(), 'State') == 7)
L.setst(S_ENC); check('same-State kl.setst changes nothing', mdh_get(L.mdh(), 'State') == 7 and L.key == k0 and L.exec(b2v(P), 128)[0] == b2v(ref_c))
L.setst(S_DEC); check('Encrypt -> Decrypt directly (State 8)', mdh_get(L.mdh(), 'State') == 8 and v2b(L.exec(b2v(ref_c), 128)[0], 16) == P)
L.setst(S_READY); check('Decrypt -> Ready', mdh_get(L.mdh(), 'State') == 1)
L.setst(S_READY); check('Ready -> Ready allowed (Form A)', mdh_get(L.mdh(), 'State') == 1 and not L.inert())
for pol, enc_ok, dec_ok in ((1, 1, 0), (2, 0, 1), (3, 1, 1)):
    L = lk(0, pol, k0); L.setst(S_ENC); a = not L.inert(); L = lk(0, pol, k0); L.setst(S_DEC); b = not L.inert()
    check('MachinePolicy %d: encrypt %s, decrypt %s' % (pol, bool(enc_ok), bool(dec_ok)), (a, b) == (bool(enc_ok), bool(dec_ok)))
check('MachinePolicy 0 is invalid Metadata (Error State Invalid)', lk(0, 0).err == SE_INVALID)
L = lk(0, 1, k0); L.setst(S_ENC); L.setst(S_DEC)
check('decrypt-only/encrypt-only: disallowed transition leaves Error State Invalid', L.err == SE_INVALID)
for imm in (13, 2, 48, 49, 50, 51, 52, 53, 54, 55, 66, 100):
    L = lk(0, 3, k0); L.setst(imm); check('kl.setst immediate %d is Invalid in ECB (GR24/GR25/GR21)' % imm, L.err == SE_INVALID)
L = lk(0, 3, k0); L.setst(S_ENC, 'C', vec=5); check('Form C kl.setst into Encrypt (ECB has no aux data): Invalid', L.err == SE_INVALID)
L = lk(0, 3, k0); L.setst(S_ENC, 'B', xs=5); check('Form B kl.setst into Encrypt: Invalid', L.err == SE_INVALID)
L = lk(0, 3, k0); L.setst(0); check('kl.clear: Unconfigured, inert', L.err == SE_UNCONFIGURED and L.exec(b2v(P), 128) == (0, 0))
L = lk(0, 3, k0); L.setst(S_ENC)
L = lk(0, 3, k0); L.setst(S_ENC); check('KLLEN = 0 below the 128-bit minimum: empty window (GR53 item 1), no-op, State kept', L.exec(0, 0) == (0, 0) and not L.inert() and L.err != SE_INVALID)
o, _ = L.exec(b2v(P) | (3 << 128), 136); check('MR6: KLLEN=136 violates granularity: Invalid, window zero', o == 0 and L.err == SE_INVALID)

section('MR1: SCC imported in a State that its MachinePolicy disables')
L = lk(0, 3, k0); L.setst(S_ENC); mdh, c1 = L.export()
Li = Locker.import_(mdh_put(mdh, 'MachinePolicy', 2), c1); check('SCC in Encrypt with MachinePolicy = 10b: imports (Encrypt)', Li.state == S_ENC and not Li.inert())
Li.exec(b2v(P), 128); check('... kl.exec -> Invalid (MR1)', Li.err == SE_INVALID)
Li = Locker.import_(mdh_put(mdh, 'MachinePolicy', 2), c1); Li.setst(S_DEC); check('... a kl.setst naming Decrypt is admitted', Li.state == S_DEC and not Li.inert())

section('Window, halting and resume (GR46-GR53)')
k = H('2b7e151628aed2a6abf7158809cf4f3c'); C4 = [cipher_enc('AES128', k, p) for p in P4]
for stop in (1, 2, 3):
    L = lk(0, 3, k); L.setst(S_ENC); inp = blocks_v(P4); acc = 0; ks = 0; steps = 0
    while True:
        o, ks = L.exec(inp, 512, ks, stop=stop); acc |= o; steps += 1
        if ks == 0: break
    check('interrupt after every %d blocks, resume: result equals one shot' % stop, acc == blocks_v(C4) and steps == -(-4 // stop))
L = lk(0, 3, k); L.setst(S_ENC); o, ks = L.exec(blocks_v(P4), 512, 0, stop=1)
check('halted after block 0: klstart = 16, output bits below 8*klstart set only', ks == 16 and o == b2v(C4[0]))
o, ks = L.exec(blocks_v(P4), 512, ks, stop=1); check('resume at klstart 16: output window [8*klstart, KLLEN-1] only', ks == 32 and o == b2v(C4[1]) << 128)
L = lk(0, 3, k); L.setst(S_ENC); check('klstart >= KLLEN/8: empty window, klstart <- 0, Machine not reached', L.exec(blocks_v(P4), 512, 64) == (0, 0) and not L.inert())
o, ks = L.exec(blocks_v(P4), 512, 8); check('klstart = 8 is not an interruption point: Invalid', o == 0 and L.err == SE_INVALID)

section('PI and serialized Content sizes (GR kl.size)')
for t, pi, c1, scc in ((0, 32, 16, 48), (1, 48, 32, 64), (2, 48, 32, 64), (3, 32, 16, 48)):
    L = lk(t, 3); n = TYPES[t] + '_ECB'
    check(n + ' PI %d bytes' % pi, pi_size(machine(t, 0)) == pi)
    check(n + ' Content1 %d bytes, SCC %d bytes' % (c1, scc), len(L.content1()) == c1 and 32 + len(L.content1()) == scc)
    check(n + ' by SKID: PI 32, Content1 16, SCC 48', pi_size(machine(t, 0), 1) == 32 and len(Locker(machine(t, 0), 3, bytes(8), skid=True).content1()) == 16)
L = lk(0, 3, k); L.setst(S_ENC); L.exec(blocks_v(P4[:2]), 256)
mdh, c1 = L.export(); L2 = Locker.import_(mdh, c1)
check('export after 2 blocks, import: Encrypt, same key, same output', L2.state == S_ENC and L2.exec(blocks_v(P4), 512)[0] == blocks_v(C4))
check('import with MachinePolicy 0: Invalid', Locker.import_(mdh_put(mdh, 'MachinePolicy', 0), c1).err == SE_INVALID)
check('import with a State ECB does not have: Invalid', Locker.import_(mdh_put(mdh, 'State', 9), c1).err == SE_INVALID)
check('import with non-zero StateExtension at State: Invalid (unsupported)', Locker.import_(mdh_put(mdh, 'StateExtension', 1), c1).err == SE_INVALID)

section('kl.derive into the key field (GR38-GR44)')
KS = bytes(range(64))
for t, need in ((0, 16), (1, 24), (2, 32), (3, 16)):
    L = lk(t); n = TYPES[t]
    check(n + ' derive length 64 uses exactly %d bytes' % need, L.load_key(KS, 64) and L.key == KS[:need])
    check(n + ' derive then Encrypt matches reference', (L.setst(S_ENC), v2b(L.exec(b2v(PT), 128)[0], 16))[1] == cipher_enc(n, KS[:need], PT))
    L = lk(t); check(n + ' derive length %d < %d: Invalid' % (need - 1, need), not L.load_key(KS, need - 1) and L.err == SE_INVALID)
    L = lk(t); check(n + ' derive length 0: Invalid', not L.load_key(KS, 0))
    L = lk(t); L.setst(S_ENC); check(n + ' derive into Encrypt (destination not Ready): Invalid', not L.load_key(KS, 64))
L = Locker(machine(0, 0), 3, bytes(8), skid=True); check('derive into KeyType 1 (SKID) key field: Invalid', not L.load_key(KS, 64))
L = lk(0); L.setst(S_ENC); L.derive_out(16); check('ECB as kl.derive source: Invalid', L.err == SE_INVALID)
control('wrong expected key is detected', cipher_enc('AES128', KS[:16], PT) != cipher_enc('AES128', KS[1:17], PT))
spec_note('Form D (KLIOBUF) substitution, GR narrowing GR41/GR44 and CMAC Hash_Output sources need the Zklio / CMAC models: covered by their KATs')
done()
