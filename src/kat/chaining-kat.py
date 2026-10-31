#!/usr/bin/env pypy3.12
"""KAT of the chaining Machines CBC, CFB (segment size u) and OFB (Zkl-ISA-machines.adoc KLE-chaining).
Standards: SP 800-38A F.2 (CBC), F.3 (CFB1/8/128), F.4 (OFB).  Run: cd src && pypy3.12 kat/chaining-kat.py"""
import os, random, sys
from math import gcd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
from sym_model import *
from sym_ref import lib

H = bytes.fromhex
def V(bl): return b2v(b''.join(bl))
KEYS = {0: H('2b7e151628aed2a6abf7158809cf4f3c'), 1: H('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'),
        2: H('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')}
IV = bytes(range(16))
P4 = [H(x) for x in ('6bc1bee22e409f96e93d7e117393172a', 'ae2d8a571e03ac9c9eb76fac45af8e51',
                     '30c81c46a35ce411e5fbc1191a0a52ef', 'f69f2445df4f9b17ad2b417be66c3710')]
def hx(s): return [H(x) for x in s.split()]
CBC = {0: hx('7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2 73bed6b8e3c1743b7116e69e22229516 3ff1caa1681fac09120eca307586e1a7'),
       1: hx('4f021db243bc633d7178183a9fa071e8 b4d9ada9ad7dedf4e5e738763f69145a 571b242012fb7ae07fa9baac3df102e0 08b0e27988598881d920a9e64f5615cd'),
       2: hx('f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d 39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b')}
CFB = {0: hx('3b3fd92eb72dad20333449f8e83cfb4a c8a64537a0b3a93fcde3cdad9f1ce58b 26751f67a3cbb140b1808cf187a4f4df c04b05357c5d1c0eeac4c66f9ff7f2e6'),
       1: hx('cdc80d6fddf18cab34c25909c99a4174 67ce7f7f81173621961a2b70171d3d7a 2e1e8a1dd59b88b1c8e60fed1efac4c9 c05f9f9ca9834fa042ae8fba584b09ff'),
       2: hx('dc7e84bfda79164b7ecd8486985d3860 39ffed143b28b1c832113c6331e5407b df10132415e54b92a13ed0a8267ae2f9 75a385741ab9cef82031623d55b1e471')}
OFB = {0: hx('3b3fd92eb72dad20333449f8e83cfb4a 7789508d16918f03f53c52dac54ed825 9740051e9c5fecf64344f7a82260edcc 304c6528f659c77866a510d9c1d6ae5e'),
       1: hx('cdc80d6fddf18cab34c25909c99a4174 fcc28b8d4c63837c09e81700c1100401 8d9a9aeac0f6596f559c6d4daf59a5f2 6d9f200857ca6c3e9cac524bd9acc92a'),
       2: hx('dc7e84bfda79164b7ecd8486985d3860 4febdc6740d20b3ac88f6ad82a4fb08d 71ab47a086e86eedf39d1c5bba97c408 0126141d67f37be8538f5a8be740e484')}

def lk(t, mode, key=None, policy=3, u=None):
    return Locker(machine(t, mode), policy, key if key is not None else bytes(KEYLEN[TYPES[t]]), aux=u)
def start(L, s, iv=None):
    if iv is None: L.setst(s)
    else: L.setst(s, 'C', vec=b2v(iv))
    return L
def bits(bs):
    return [(b >> (7 - i)) & 1 for b in bs for i in range(8)]
def unbits(bl):
    bl = bl + [0] * (-len(bl) % 8)
    return bytes(sum(bl[8 * i + j] << (7 - j) for j in range(8)) for i in range(len(bl) // 8))
def cfb_ref(cipher, key, iv, data, s, enc, nbits=None):
    """SP 800-38A CFB with s-bit segments, written on bit lists (MSB of byte 0 first). Trailing bits < s are dropped (zero)."""
    d = bits(data); n = (len(d) if nbits is None else nbits) // s; reg = bits(iv); out = []
    for j in range(n):
        o = bits(cipher_enc(cipher, key, unbits(reg)))[:s]; seg = d[j * s:(j + 1) * s]
        y = [a ^ b for a, b in zip(seg, o)]; reg = reg[s:] + (y if enc else seg); out += y
    return unbits(out + [0] * (len(d) - len(out)))

section('CBC (SP 800-38A F.2)')
for t in range(3):
    n = TYPES[t]; k = KEYS[t]; C = CBC[t]; L = lk(t, 1, k)
    check(n + '_CBC Encrypt, IV by Form C kl.setst', start(L, S_ENC, IV).exec(V(P4), 512)[0] == V(C))
    check(n + '_CBC Decrypt', start(L, S_DEC, IV).exec(V(C), 512)[0] == V(P4))
    L = start(lk(t, 1, k), S_ENC, IV); a = L.exec(V(P4[:2]), 256)[0]; b = L.exec(V(P4[2:]), 256)[0]
    check(n + '_CBC chaining across kl.exec: IV <- last ciphertext', a | b << 256 == V(C))
    r = lib(n, 'CBC', k, IV, b''.join(P4)); check(n + '_CBC vs OpenSSL', r is None or r == b''.join(C))
L = lk(0, 1, KEYS[0])
control('IV not applied is detected', start(L, S_ENC).exec(V(P4), 512)[0] != V(CBC[0]))
control('reversed block order is detected', start(lk(0, 1, KEYS[0]), S_ENC, IV).exec(V(P4[::-1]), 512)[0] != V(CBC[0]))
L = start(lk(0, 1, KEYS[0]), S_ENC, IV); L.exec(V(P4[:1]), 128); L.setst(S_ENC, 'C', vec=b2v(IV))
check('same-State kl.setst replaces the IV, keeps the key', L.exec(V(P4), 512)[0] == V(CBC[0]))
L = start(lk(0, 1, KEYS[0]), S_ENC); z = L.exec(V(P4), 512)[0]
check('Form A kl.setst: IV = 0', v2b(z, 16) == cipher_enc('AES128', KEYS[0], P4[0]))
L = start(lk(0, 1, KEYS[0]), S_ENC, IV); L.exec(V(P4), 512); L.setst(S_READY)
check('Ready zeroes the IV', L.iv == 0)
L.setst(S_ENC); check('Ready then Encrypt Form A: IV 0 (not the old one)', v2b(L.exec(V(P4[:1]), 128)[0], 16) == cipher_enc('AES128', KEYS[0], P4[0]))
L = start(lk(0, 1, KEYS[0]), S_ENC, IV); L.exec(V(P4[:2]), 256); mdh, c1 = L.export()
L2 = Locker.import_(mdh, c1)
check('export/import round trip keeps key and IV (2 blocks done)', L2.iv == L.iv and L2.exec(V(P4[2:]), 256)[0] == (V(CBC[0]) >> 256))
check('Content1 of AES128_CBC: key|IV = 32 bytes', len(c1) == 32)
rnd = random.Random(2); inv = 0
for t in range(4):
    k = bytes(rnd.getrandbits(8) for _ in range(KEYLEN[TYPES[t]])); d = [bytes(rnd.getrandbits(8) for _ in range(16)) for _ in range(5)]
    e = start(lk(t, 1, k), S_ENC).exec(V(d), 640)[0]; inv += start(lk(t, 1, k), S_DEC).exec(e, 640)[0] != V(d)
    r = lib(TYPES[t], 'CBC', k, bytes(16), b''.join(d)); check(TYPES[t] + '_CBC zero IV vs OpenSSL', r is None or r == v2b(e, 80))
check('Decrypt inverts Encrypt with zero IV (random, 4 ciphers)', inv == 0)
L = lk(0, 1, KEYS[0]); L.setst(S_ENC); L.exec(V(P4[:1]) | 1 << 128, 136); check('MR6: KLLEN = 136 Invalid', L.err == SE_INVALID)
L = lk(0, 1, KEYS[0]); L.exec(V(P4), 512); check('kl.exec in Ready: Invalid', L.err == SE_INVALID)
for imm in (S_OPERATE, S_AUX, 54, 55, 49):
    L = lk(0, 1, KEYS[0]); L.setst(imm); check('CBC kl.setst immediate %d: Invalid' % imm, L.err == SE_INVALID)
L = lk(0, 1, KEYS[0], 1); L.setst(S_DEC); check('CBC encrypt-only MachinePolicy refuses Decrypt', L.err == SE_INVALID)
L = start(lk(3, 1, KEYS[0][:16]), S_ENC, IV); sm = L.exec(V(P4), 512)[0]
check('SM4_CBC vs OpenSSL', lib('SM4', 'CBC', KEYS[0][:16], IV, b''.join(P4)) in (None, v2b(sm, 64)))

section('CFB, u = b (SP 800-38A F.3.13-F.3.18)')
for t in range(3):
    n = TYPES[t]; k = KEYS[t]; C = CFB[t]
    L = lk(t, 2, k); check(n + '_CFB provisioned: u = b', L.u == 128)
    check(n + '_CFB Encrypt', start(L, S_ENC, IV).exec(V(P4), 512)[0] == V(C))
    check(n + '_CFB Decrypt', start(L, S_DEC, IV).exec(V(C), 512)[0] == V(P4))
    check(n + '_CFB reference bit model (u=128)', cfb_ref(n, k, IV, b''.join(P4), 128, True) == b''.join(C))
section('CFB8 (F.3.7/F.3.8) and CFB1 (F.3.1/F.3.2)')
p18 = b''.join(P4)[:18]; c18 = H('3b79424c9c0dd436bace9e0ed4586a4f32b9')
L = lk(0, 2, KEYS[0], u=8); check('u = 8 from AuxInfo', L.state == S_READY and L.u == 8)
L.setst(S_ENC, 'C', vec=b2v(IV)); check('CFB8 Encrypt 18 bytes (F.3.7)', v2b(L.exec(b2v(p18), 144)[0], 18) == c18)
L = lk(0, 2, KEYS[0], u=8); L.setst(S_DEC, 'C', vec=b2v(IV)); check('CFB8 Decrypt (F.3.8)', v2b(L.exec(b2v(c18), 144)[0], 18) == p18)
q0 = cipher_enc('AES128', KEYS[0], IV)[0]     # Q computed once, from the IV at the start of the kl.exec
control('Q not recomputed per segment is detected (F.3.7)', bytes(p ^ q0 for p in p18) != c18 and cfb_ref('AES128', KEYS[0], IV, p18, 8, True) == c18)
L = lk(0, 2, KEYS[0], u=1); L.setst(S_ENC, 'C', vec=b2v(IV))
check('CFB1 Encrypt 16 bits 6bc1 -> 68b3 (F.3.1)', v2b(L.exec(b2v(H('6bc1')), 16)[0], 2) == H('68b3'))
L = lk(0, 2, KEYS[0], u=1); L.setst(S_DEC, 'C', vec=b2v(IV))
check('CFB1 Decrypt 68b3 -> 6bc1 (F.3.2)', v2b(L.exec(b2v(H('68b3')), 16)[0], 2) == H('6bc1'))
control('wrong bit order (no brev8 semantics) is detected', cfb_ref('AES128', KEYS[0], IV, H('6bc1'), 1, True) == H('68b3') and cfb_ref('AES128', KEYS[0], IV, H('d683'), 1, True) != H('68b3'))

section('CFB with u in {1,3,7,8,12,64,127,128}: independent bit model, lib, round trip')
rnd = random.Random(3)
for u in (1, 3, 7, 8, 12, 64, 127, 128):
    bad = 0
    for t in (0, 2, 3):
        n = TYPES[t]; k = bytes(rnd.getrandbits(8) for _ in range(KEYLEN[n])); iv = bytes(rnd.getrandbits(8) for _ in range(16))
        L = lk(t, 2, k, u=u); L.setst(S_ENC, 'C', vec=b2v(iv))
        d = bytes(rnd.getrandbits(8) for _ in range(24)); kl = 192; out = L.exec(b2v(d), kl)[0]
        e = cfb_ref(n, k, iv, d, u, True); bad += v2b(out, 24) != e
        D = lk(t, 2, k, u=u); D.setst(S_DEC, 'C', vec=b2v(iv))
        D = lk(t, 2, k, u=u); D.setst(S_DEC, 'C', vec=b2v(iv))
        bad += v2b(D.exec(b2v(e), kl)[0], 24) != cfb_ref(n, k, iv, e, u, False)
        if 192 % u == 0:
            D = lk(t, 2, k, u=u); D.setst(S_DEC, 'C', vec=b2v(iv)); bad += v2b(D.exec(b2v(e), kl)[0], 24) != d
        nfull = 192 // u * u // 8 if u in (1, 8, 128) else 0
        lb = {8: 'CFB8', 128: 'CFB', 1: 'CFB1'}.get(u)
        if lb:
            r = lib(n, lb, k, iv, d); bad += r is not None and r[:nfull] != e[:nfull]
    check('CFB u=%d: enc/dec equal bit model (3 ciphers), round trip, OpenSSL where available' % u, bad == 0)
L = lk(0, 2, KEYS[0], u=3); L.setst(S_ENC, 'C', vec=b2v(IV))
d = H('6bc1'); o1 = L.exec(b2v(d), 16)[0]; i1 = L.iv
L = lk(0, 2, KEYS[0], u=3); L.setst(S_ENC, 'C', vec=b2v(IV)); o2 = L.exec(b2v(d) ^ (1 << 8), 16)[0]   # bit-string index 15 = INPUT bit 8 (brev8)
check('CFB3, KLLEN 16: 5 segments, the 16th input bit is ignored (output and IV)', o1 == o2 and L.iv == i1)
check('CFB3, KLLEN 16: output bit-string index 15 (bit 8) is zero', (o1 >> 8) & 1 == 0)
check('CFB3 matches bit model on 15 bits', v2b(o1, 2) == cfb_ref('AES128', KEYS[0], IV, d, 3, True))

section('CFB: u in AuxInfo, fixed at provisioning')
L = lk(0, 2, KEYS[0], u=12); L.setst(S_ENC, 'C', vec=7); L.setst(S_READY)
check('u = AuxInfo[7:0] of the MDH; Ready keeps u, zeroes IV', L.u == 12 and mdh_get(L.mdh(), 'AuxInfo') == 12 and L.iv == 0 and L.state == S_READY)
L = lk(0, 2, KEYS[0], u=8); L.setst(S_ENC, 'C', vec=7); L.setst(S_ENC, 'C', vec=9)
check('same-State Encrypt setst replaces IV, keeps u and key', L.u == 8 and L.iv == 9 and L.key == KEYS[0])
for u in (0, 129, 255, 8 | 1 << 8):
    check('provisioning with AuxInfo = %#x: Invalid' % u, lk(0, 2, KEYS[0], u=u).err == SE_INVALID)
for imm in (S_AUX,):
    L = lk(0, 2, KEYS[0], u=8); L.setst(imm, 'B', xs=8); check('CFB has no Set_Aux_Value: kl.setst immediate %d Invalid' % imm, L.err == SE_INVALID)
L = lk(0, 2, KEYS[0], u=8); L.setst(S_ENC, 'C', vec=5); mdh, c1 = L.export()
L2 = Locker.import_(mdh, c1); check('export/import keeps u (MDH) and IV', (L2.u, L2.iv, L2.state) == (8, 5, S_ENC))
check('Content1 of AES128_CFB = key|IV = 32 bytes (u not serialized)', len(c1) == 32)
check('import with AuxInfo u = 0 Invalid', Locker.import_(mdh_put(mdh, 'AuxInfo', 0), c1).err == SE_INVALID)
check('import with AuxInfo u = 129 Invalid', Locker.import_(mdh_put(mdh, 'AuxInfo', 129), c1).err == SE_INVALID)
check('import with AuxInfo[15:8] != 0 Invalid', Locker.import_(mdh_put(mdh, 'AuxInfo', 8 | 1 << 8), c1).err == SE_INVALID)
L = lk(0, 2, KEYS[0], u=8); L.setst(S_READY); mdh, c1 = L.export()
check('import in Ready keeps u = 8', Locker.import_(mdh, c1).u == 8)
L = lk(0, 2, KEYS[0], u=8); L.setst(S_ENC); L.exec(b2v(P4[0]), 7); check('CFB granularity is 8 bits: KLLEN 7 Invalid', L.err == SE_INVALID)
L = lk(0, 2, KEYS[0], u=64); L.setst(S_ENC); o = L.exec(b2v(P4[0]), 32); check('KLLEN < u (32 < 64): no segment, output zero, valid', o == (0, 0) and not L.inert())
L = lk(0, 2, KEYS[0]); L.setst(S_ENC); check('CFB Ready -> Encrypt directly (u = b)', L.state == S_ENC)

section('CFB halting: interruption points at multiples of lcm(8,u)/8 bytes')
for u, unit in ((12, 3), (8, 1), (128, 16), (1, 1), (3, 3), (64, 8)):
    k = KEYS[0]; d = bytes(range(48))
    kl = 48 * 8 if (48 * 8) % u == 0 else (48 * 8 // u * u)
    kl -= kl % 8
    L = lk(0, 2, k, u=u); L.setst(S_ENC, 'C', vec=b2v(IV)); one = L.exec(b2v(d), kl)[0]
    L = lk(0, 2, k, u=u); L.setst(S_ENC, 'C', vec=b2v(IV)); acc = 0; ks = 0; ok = True; st = 0
    while True:
        o, ks = L.exec(b2v(d), kl, ks, stop=1); acc |= o; st += 1
        if ks == 0: break
        ok &= ks % unit == 0
    check('u=%d: halting every interruption point, resume equals one shot (points multiple of %d bytes)' % (u, unit), ok and acc == one and st > 1)
L = lk(0, 2, KEYS[0], u=12); L.setst(S_ENC); L.exec(b2v(bytes(48)), 384, 1)
check('u=12: klstart 1 is not an interruption point: Invalid', L.err == SE_INVALID)
L = lk(0, 2, KEYS[0]); L.setst(S_ENC); L.exec(b2v(bytes(48)), 384, 8); check('u=128: klstart 8 Invalid', L.err == SE_INVALID)
L = lk(0, 2, KEYS[0]); L.setst(S_ENC); check('klstart >= KLLEN/8: empty window', L.exec(b2v(bytes(48)), 384, 48) == (0, 0) and not L.inert())

section('OFB (SP 800-38A F.4)')
for t in range(3):
    n = TYPES[t]; k = KEYS[t]; C = OFB[t]; L = lk(t, 3, k)
    ks = start(L, S_OPERATE, IV).exec(None, 512)[0]
    check(n + '_OFB keystream xor plaintext = F.4 ciphertext', ks ^ V(P4) == V(C))
    check(n + '_OFB keystream xor ciphertext = plaintext (decrypt)', start(lk(t, 3, k), S_OPERATE, IV).exec(None, 512)[0] ^ V(C) == V(P4))
    r = lib(n, 'OFB', k, IV, b''.join(P4)); check(n + '_OFB vs OpenSSL', r is None or r == b''.join(C))
L = start(lk(0, 3, KEYS[0]), S_OPERATE, IV); a = L.exec(None, 256)[0]
check('OFB continuity: IV <- keystream block across kl.exec', a | L.exec(None, 256)[0] << 256 == start(lk(0, 3, KEYS[0]), S_OPERATE, IV).exec(None, 512)[0])
L.setst(S_OPERATE, 'C', vec=b2v(IV)); check('same-State setst replaces IV', L.exec(None, 512)[0] == start(lk(0, 3, KEYS[0]), S_OPERATE, IV).exec(None, 512)[0])
L = start(lk(0, 3, KEYS[0]), S_OPERATE); k1 = L.exec(None, 128)[0]
check('Form A: IV = 0 (keystream block 0 is E(0))', v2b(k1, 16) == cipher_enc('AES128', KEYS[0], bytes(16)))
L.setst(S_READY); check('Ready zeroes IV', L.iv == 0); L.setst(S_OPERATE); check('Ready -> Operate again from zero IV', L.exec(None, 128)[0] == k1)
for pol in (1, 2, 3):
    L = lk(0, 3, KEYS[0], pol); L.setst(S_OPERATE); check('OFB MachinePolicy %d: Operate admitted' % pol, not L.inert())
check('OFB MachinePolicy 0: Invalid', lk(0, 3, KEYS[0], 0).err == SE_INVALID)
L = lk(0, 3, KEYS[0]); L.setst(S_ENC); check('OFB has no Encrypt State: Invalid', L.err == SE_INVALID)
L = lk(0, 3, KEYS[0]); L.exec(None, 128); check('OFB kl.exec in Ready: Invalid', L.err == SE_INVALID)
L = start(lk(0, 3, KEYS[0]), S_OPERATE, IV); ks = L.derive_out(40)
full = start(lk(0, 3, KEYS[0]), S_OPERATE, IV).exec(None, 640)[0]
check('kl.derive source: 40 bytes = 3 whole keystream blocks, last 8 bytes of block 3 discarded', ks == v2b(full, 80)[:40]
      and L.exec(None, 128)[0] == (full >> 384) & MASK128)
L = lk(0, 1, KEYS[0]); L.setst(S_ENC); L.derive_out(16); check('CBC is not a derive source: Invalid', L.err == SE_INVALID)
L = start(lk(0, 3, KEYS[0]), S_OPERATE, IV); L.exec(None, 256); mdh, c1 = L.export(); L2 = Locker.import_(mdh, c1)
check('OFB export/import keeps the IV; Content1 32 bytes', L2.exec(None, 128)[0] == (start(lk(0, 3, KEYS[0]), S_OPERATE, IV).exec(None, 384)[0] >> 256) and len(c1) == 32)
L = start(lk(0, 3, KEYS[0]), S_OPERATE, IV); L.exec(None, 160); check('OFB granularity b: KLLEN 160 Invalid', L.err == SE_INVALID)
done()
