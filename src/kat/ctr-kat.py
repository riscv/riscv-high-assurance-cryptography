#!/usr/bin/env pypy3.12
"""KAT of the CTR (j = 32) and XCTR (j = 64, HCTR2) Machines (Zkl-ISA-machines.adoc, CTR/XCTR section).
Standards: SP 800-38A F.5; XCTR from the HCTR2 definition (Crowley et al.), implemented independently below.
Run: cd src && pypy3.12 kat/ctr-kat.py"""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
from sym_model import *
from sym_ref import lib

H = bytes.fromhex
def hx(s): return [H(x) for x in s.split()]
def V(bl): return b2v(b''.join(bl))
P4 = hx('6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51 30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710')
KEYS = {0: H('2b7e151628aed2a6abf7158809cf4f3c'), 1: H('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'),
        2: H('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')}
T1 = H('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'); CTR0 = 0xfcfdfeff
CT = {0: hx('874d6191b620e3261bef6864990db6ce 9806f66b7970fdff8617187bb9fffdff 5ae4df3edbd5d35e5b4f09020db03eab 1e031dda2fbe03d1792170a0f3009cee'),
      1: hx('1abc932417521ca24f2b0459fe7e6e0b 090339ec0aa6faefd5ccc2c6f4ce8e94 1e36b26bd1ebc670d1bd1d665620abf7 4f78a7f6d29809585a97daec58c6b050'),
      2: hx('601ec313775789a5b7a7f504bbf3d228 f443e3ca4d62b59aca84e990cacaf5c5 2b0930daa23de94ce87017ba2d84988d dfc9c58db67aada613c2dd08457941a6')}
def lk(t, mode=4, key=None, policy=3):
    return Locker(machine(t, mode), policy, key if key is not None else bytes(KEYLEN[TYPES[t]]))
def ctr_ref(cipher, key, iv12, ctr, n):          # counter block = IV(12 bytes) | 32-bit big-endian counter
    return [cipher_enc(cipher, key, iv12 + ((ctr + i) & 0xffffffff).to_bytes(4, 'big')) for i in range(n)]
def xctr_ref(cipher, key, iv16, ctr, n):         # HCTR2: E(K, IV xor le64(ctr)), 64-bit little-endian counter
    return [cipher_enc(cipher, key, bytes(a ^ b for a, b in zip(iv16, ((ctr + i) & (2**64 - 1)).to_bytes(8, 'little') + bytes(8)))) for i in range(n)]
def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))

section('CTR (SP 800-38A F.5.1/F.5.3/F.5.5)')
for t in range(3):
    n = TYPES[t]; k = KEYS[t]; C = CT[t]
    check(n + ' reference model reproduces F.5 ciphertext', [xor(p, e) for p, e in zip(P4, ctr_ref(n, k, T1[:12], CTR0, 4))] == C)
    L = lk(t, 4, k); L.setst(S_AUX, 'B', xs=CTR0); L.setst(S_OPERATE, 'C', vec=b2v(T1))
    check(n + '_CTR Form B ctr, Form C IV: keystream xor P = C (one kl.exec KLLEN=512)', L.exec(None, 512)[0] ^ V(P4) == V(C))
    L = lk(t, 4, k); L.setst(S_OPERATE, 'C', vec=b2v(T1)); L.setst(S_AUX, 'B', xs=CTR0)
    check(n + '_CTR ctr set after entering Operate (operation, State unchanged)', L.state == S_OPERATE and L.exec(None, 512)[0] ^ V(P4) == V(C))
    L = lk(t, 4, k); L.setst(S_AUX, 'B', xs=CTR0); L.setst(S_OPERATE, 'C', vec=b2v(T1))
    ks = [v2b(L.exec(None, 128)[0], 16) for _ in range(4)]
    check(n + '_CTR four single-block kl.exec', [xor(p, e) for p, e in zip(P4, ks)] == C)
    check(n + '_CTR vs OpenSSL', lib(n, 'CTR', k, T1, b''.join(P4)) in (None, b''.join(C)))
L = lk(0, 4, KEYS[0]); L.setst(S_AUX, 'B', xs=CTR0); L.setst(S_OPERATE, 'C', vec=b2v(T1))
control('no bswap of the counter is detected', ctr_ref('AES128', KEYS[0], T1[:12], CTR0, 4)[1] != cipher_enc('AES128', KEYS[0], T1[:12] + (CTR0 + 1).to_bytes(4, 'little')))
control('reversed block order (MR13) is detected', L.exec(None, 512)[0] ^ V(P4[::-1]) != V(CT[0]))

section('CTR counter: wrap at 2^32, no carry into IV; random access')
iv = bytes(range(1, 13)); k = KEYS[0]
L = lk(0, 4, k); L.setst(S_AUX, 'B', xs=0xfffffffe); L.setst(S_OPERATE, 'C', vec=b2v(iv))
out = [v2b(L.exec(None, 128)[0], 16) for _ in range(4)]
check('ctr 0xfffffffe, 0xffffffff, 0, 1 (wrap mod 2^32, IV intact)', out == ctr_ref('AES128', k, iv, 0xfffffffe, 4) and L.ctr == 2)
L = lk(0, 4, k); L.setst(S_OPERATE, 'C', vec=b2v(iv)); L.exec(None, 256)
L.setst(S_AUX, 'B', xs=1000); o = v2b(L.exec(None, 128)[0], 16)
check('Form B Set_Aux_Value in Operate: random access to block 1000', o == ctr_ref('AES128', k, iv, 1000, 1)[0] and L.state == S_OPERATE)
L.setst(S_AUX, 'A'); check('Form A Set_Aux_Value: ctr = 0', v2b(L.exec(None, 128)[0], 16) == ctr_ref('AES128', k, iv, 0, 1)[0])
L = lk(0, 4, k); L.setst(S_AUX, 'B', xs=2 ** 40 + 7); check('Xs wider than j: bin(Xs, 32)', L.ctr == 7 and L.state == S_READY)
L.setst(S_OPERATE, 'C', vec=b2v(iv) | (0xabcd << 96)); check('Form C setst: only the low n = 96 bits are the IV; ctr unchanged', L.iv == b2v(iv) and L.ctr == 7)

section('XCTR (HCTR2)')
iv16 = bytes(range(16, 32))
for t in (0, 2, 3):
    n = TYPES[t]; k = bytes(range(KEYLEN[n]))
    L = lk(t, 5, k); check(n + '_XCTR after Ready: ctr = 1', L.ctr == 1 and L.iv == 0)
    L.setst(S_OPERATE, 'C', vec=b2v(iv16)); o = L.exec(None, 512)[0]
    check(n + '_XCTR keystream = E(K, IV xor le64(i)), i = 1..4', v2b(o, 64) == b''.join(xctr_ref(n, k, iv16, 1, 4)))
    L = lk(t, 5, k); L.setst(S_AUX, 'B', xs=2 ** 64 - 1); L.setst(S_OPERATE, 'C', vec=b2v(iv16)); o = L.exec(None, 384)[0]
    check(n + '_XCTR ctr = 2^64-1 wraps to 0 and 1', v2b(o, 48) == b''.join(xctr_ref(n, k, iv16, 2 ** 64 - 1, 3)))
    Lc = lk(t, 4, k); Lc.setst(S_OPERATE, 'C', vec=b2v(iv16))
    check(n + ' CTR and XCTR keystreams differ for the same key and IV', Lc.exec(None, 128)[0] != o & MASK128)
L = lk(0, 5, bytes(16)); L.setst(S_OPERATE, 'B', xs=5); check('Form B setst Operate: Xs zero-extended to the 128-bit IV', L.iv == 5)
L = lk(0, 5, bytes(16)); L.setst(S_OPERATE); check('Form A: IV = 0, ctr stays 1', L.iv == 0 and L.ctr == 1)
check('XCTR IV is 128 bits (all bits used)', (lambda L: (L.setst(S_OPERATE, 'C', vec=1 << 127), L.iv)[1])(lk(0, 5, bytes(16))) == 1 << 127)
control('XCTR counter big-endian instead of little-endian is detected', xctr_ref('AES128', bytes(16), iv16, 1, 1)[0] != cipher_enc('AES128', bytes(16), xor(iv16, bytes(15) + b'\x01')))

section('States, transitions, rules')
for mode in (4, 5):
    nm = 'CTR' if mode == 4 else 'XCTR'; dflt = 0 if mode == 4 else 1
    L = lk(0, mode, bytes(16)); L.setst(S_OPERATE, 'C', vec=77); L.setst(S_AUX, 'B', xs=9); L.exec(None, 256)
    L.setst(S_OPERATE, 'C', vec=88); check(nm + ' same-State setst replaces IV, keeps ctr', L.iv == 88 and L.ctr == 11)
    L.setst(S_READY); check(nm + ' Ready: IV = 0, ctr = %d' % dflt, L.iv == 0 and L.ctr == dflt and L.state == S_READY)
    L.setst(S_AUX, 'B', xs=9); L.setst(S_READY); check(nm + ' Ready resets a ctr set in Ready', L.ctr == dflt)
    L = lk(0, mode, bytes(16)); L.setst(S_AUX, 'B', xs=3); check(nm + ' Set_Aux_Value in Ready: State stays Ready', L.state == S_READY and L.ctr == 3)
    L.exec(None, 128); check(nm + ' kl.exec in Ready: Invalid', L.err == SE_INVALID)
    for imm in (S_ENC, S_DEC, 54, 55, 66, 50):
        L = lk(0, mode, bytes(16)); L.setst(imm); check(nm + ' kl.setst immediate %d: Invalid' % imm, L.err == SE_INVALID)
    L = lk(0, mode, bytes(16)); L.setst(S_AUX, 'C', vec=1); check(nm + ' Set_Aux_Value Form C: Invalid', L.err == SE_INVALID)
    L = lk(0, mode, bytes(16)); L.setst(S_OPERATE); L.exec(None, 160); check(nm + ' granularity b: KLLEN 160 Invalid', L.err == SE_INVALID)
    for pol in (1, 2, 3):
        L = lk(0, mode, bytes(16), pol); L.setst(S_OPERATE); check(nm + ' MachinePolicy %d admits Operate' % pol, not L.inert())
    check(nm + ' MachinePolicy 0 Invalid', lk(0, mode, bytes(16), 0).err == SE_INVALID)
    L = lk(0, mode, bytes(16)); L.setst(S_OPERATE); L.setst(S_READY); L.setst(S_OPERATE); check(nm + ' Operate -> Ready -> Operate', not L.inert())
    L = lk(0, mode, bytes(16)); L.setst(0); check(nm + ' kl.clear inerts the locker', L.exec(None, 128) == (0, 0) and L.err == SE_UNCONFIGURED)

section('Halting, window')
k = KEYS[0]
for stop in (1, 2, 3):
    L = lk(0, 4, k); L.setst(S_AUX, 'B', xs=CTR0); L.setst(S_OPERATE, 'C', vec=b2v(T1)); acc = 0; ks = 0
    while True:
        o, ks = L.exec(None, 512, ks, stop=stop); acc |= o
        if ks == 0: break
    check('CTR halt every %d blocks and resume: counter continues, keystream complete' % stop, acc ^ V(P4) == V(CT[0]))
L = lk(0, 4, k); L.setst(S_OPERATE); o, ks = L.exec(None, 512, 0, stop=2)
check('halt after 2 blocks: klstart = 32, ctr = 2', ks == 32 and L.ctr == 2 and o >> 256 == 0)
o, ks = L.exec(None, 512, 8); check('klstart 8 not an interruption point: Invalid', L.err == SE_INVALID)
L = lk(0, 4, k); L.setst(S_OPERATE); check('klstart >= KLLEN/8: empty window, counter untouched', L.exec(None, 512, 64) == (0, 0) and L.ctr == 0)

section('PI and Content sizes')
for t, pi, c1 in ((0, 32, 32), (1, 48, 48), (2, 48, 48), (3, 32, 32)):
    L = lk(t, 4); check(TYPES[t] + '_CTR PI %d, Content1 %d (key|IV 12|ctr 4), SCC %d' % (pi, c1, 32 + c1),
                         pi_size(machine(t, 4)) == pi and len(L.content1()) == c1)
check('AES128_XCTR Content1 = key 16 | IV 16 | ctr 8 = 40, padded 48', len(lk(0, 5).content1()) == 48)
L = lk(0, 4, k); L.setst(S_OPERATE, 'C', vec=b2v(T1)); L.setst(S_AUX, 'B', xs=CTR0); L.exec(None, 128); mdh, c1 = L.export()
L2 = Locker.import_(mdh, c1); check('export/import keeps IV, ctr: stream continues', L2.exec(None, 384)[0] == V(ctr_ref('AES128', k, T1[:12], CTR0 + 1, 3)))
check('import with MachinePolicy 0 Invalid', Locker.import_(mdh_put(mdh, 'MachinePolicy', 0), c1).err == SE_INVALID)
check('import with State Encrypt (not a CTR State) Invalid', Locker.import_(mdh_put(mdh, 'State', S_ENC), c1).err == SE_INVALID)

section('kl.derive')
src = lk(0, 4, k); src.setst(S_OPERATE, 'C', vec=b2v(T1)); dst = lk(1)
ksb = src.derive_out(24); dst.load_key(ksb, 40)
check('CTR keystream into AES192 key: effective length 24 = 2 blocks consumed', src.ctr == 2 and dst.key == b''.join(ctr_ref('AES128', k, T1[:12], 0, 2))[:24])
for mode in (4, 5):
    d = lk(0, mode, bytes(16)); d.setst(S_AUX, 'B', xs=5); d.load_key(bytes(range(16, 32)), 16)
    check('derive into %s key (Ready): entering-Ready operations reset IV = 0, ctr = %d' % ('CTR' if mode == 4 else 'XCTR', 0 if mode == 4 else 1),
          d.ctr == (0 if mode == 4 else 1) and d.iv == 0 and d.key == bytes(range(16, 32)))
d = lk(0, 4, bytes(16)); d.setst(S_OPERATE); check('derive into key in Operate: Invalid', not d.load_key(bytes(32), 32))
src = lk(0, 5, k); src.setst(S_OPERATE); d = lk(2); d.load_key(src.derive_out(32), 32)
check('XCTR keystream into AES256 key', d.key == b''.join(xctr_ref('AES128', k, bytes(16), 1, 2)))
src = lk(0, 4, k); src.derive_out(16); check('derive from CTR in Ready (no keystream State): Invalid', src.err == SE_INVALID)
rnd = random.Random(5); bad = 0
for t in range(4):
    n = TYPES[t]; kk = bytes(rnd.getrandbits(8) for _ in range(KEYLEN[n])); i12 = bytes(rnd.getrandbits(8) for _ in range(12)); c0 = rnd.getrandbits(32)
    L = lk(t, 4, kk); L.setst(S_AUX, 'B', xs=c0); L.setst(S_OPERATE, 'C', vec=b2v(i12)); bad += v2b(L.exec(None, 640)[0], 80) != b''.join(ctr_ref(n, kk, i12, c0, 5))
check('random CTR keystreams equal the reference model (4 ciphers)', bad == 0)
done()
