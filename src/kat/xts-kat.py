#!/usr/bin/env pypy3.12
"""KAT of the XEX Machines (AES128/AES256/SM4_XEX) and of XTS built from them, incl. ciphertext stealing
(Zkl-ISA-machines.adoc KLE-XEX-XTS-modes).  Standards: IEEE 1619-2007/2018 App. B vectors 2,3 (and 1 for the reference),
SP 800-38E, GB/T 17964-2021 (SM4 variant, cross-checked against OpenSSL 3.6.2 `SM4-XTS` with xts_standard=GB, vectors embedded).
Run: cd src && pypy3.12 kat/xts-kat.py"""
import hashlib, os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
from sym_model import *

H = bytes.fromhex
def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))
def lk(t, k1, k2, policy=3): return Locker(machine(t, 6), policy, k1, k2)

# ---- independent reference: polynomial arithmetic in GF(2)[x]/(x^128+x^7+x^2+x+1)
def to_poly(blk, gb):      # AES/IEEE: bit i of the LE integer = coefficient of x^i; GB: byte j bit (7-i) = x^(8j+i)
    p = 0
    for i in range(128):
        bit = (blk[i // 8] >> (i % 8)) & 1 if not gb else (blk[i // 8] >> (7 - i % 8)) & 1
        p |= bit << i
    return p
def from_poly(p, gb):
    out = bytearray(16)
    for i in range(128):
        if (p >> i) & 1: out[i // 8] |= (1 << (i % 8)) if not gb else (1 << (7 - i % 8))
    return bytes(out)
def tweaks(cipher, k2, tw, n, gb):
    p = to_poly(cipher_enc(cipher, k2, tw), gb); res = []
    for _ in range(n):
        res.append(from_poly(p, gb)); p <<= 1
        if p >> 128: p ^= (1 << 128) | 0x87
    return res
def xts_ref(cipher, k1, k2, tw, data, enc, gb=False):
    m, s = divmod(len(data), 16); T = tweaks(cipher, k2, tw, m + 1, gb)
    E = (lambda b: cipher_enc(cipher, k1, b)) if enc else (lambda b: cipher_dec(cipher, k1, b))
    blk = lambda x, t: xor(E(xor(x, t)), t)
    B = [data[16 * i:16 * i + 16] for i in range(m)]; tail = data[16 * m:]
    if s == 0: return b''.join(blk(b, T[i]) for i, b in enumerate(B))
    out = [blk(b, T[i]) for i, b in enumerate(B[:-1])]
    if enc:
        cc = blk(B[-1], T[m - 1]); out += [blk(tail + cc[s:], T[m]), cc[:s]]
    else:
        pp = blk(B[-1], T[m]); out += [blk(tail + pp[s:], T[m - 1]), pp[:s]]
    return b''.join(out)

# ---- XTS software on top of the Machine (spec recipe, KLE-XTS-from-XEX)
def xts_locker(L, tweak, data, enc, steal_check=None):
    m, s = divmod(len(data), 16); L.setst(S_ENC if enc else S_DEC, 'C', vec=tweak)
    blocks = [data[16 * i:16 * i + 16] for i in range(m)]
    run = lambda bl: v2b(L.exec(b2v(b''.join(bl)), 128 * len(bl))[0], 16 * len(bl))
    if s == 0: return run(blocks)
    head = run(blocks[:-1]) if m > 1 else b''
    if enc:
        cc = run([blocks[-1]]); cm, cp = cc[:s], cc[s:]
        return head + run([data[16 * m:] + cp]) + cm
    L.setst(66)
    pp = run([blocks[-1]]); pm, cp = pp[:s], pp[s:]
    return head + run([data[16 * m:] + cp]) + pm

section('Reference algorithm against IEEE 1619-2007 App. B vectors')
V1 = H('917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e')
V2 = (H('11' * 16 + '22' * 16), H('3333333333' + '00' * 11), bytes([0x44]) * 32,
      H('c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0'))
V3 = (H('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0' + '22' * 16), V2[1], V2[2],
      H('af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89'))
check('vector 1 (key1 = key2 = 0, tweak 0, 32 zero bytes)', xts_ref('AES128', bytes(16), bytes(16), bytes(16), bytes(32), True) == V1)
for i, (k, tw, pt, ct) in enumerate((V2, V3), 2):
    check('vector %d encrypt (reference)' % i, xts_ref('AES128', k[:16], k[16:], tw, pt, True) == ct)
    check('vector %d decrypt (reference)' % i, xts_ref('AES128', k[:16], k[16:], tw, ct, False) == pt)

section('update_mask transcription (spec Machine-Specific Functions) against polynomial arithmetic')
rnd = random.Random(7); bad = {False: 0, True: 0}; inv = {False: 0, True: 0}
cases = [0, 1, 1 << 127, MASK128, 0x87, 1 << 7, 1 << 8, 1 << 120, 0x80 << 120 | 1]
cases += [rnd.getrandbits(128) for _ in range(400)]
for gb in (False, True):
    for v in cases:
        want = b2v(from_poly((to_poly(v2b(v, 16), gb) << 1) ^ (((to_poly(v2b(v, 16), gb) >> 127) & 1) * ((1 << 128) | 0x87)), gb))
        bad[gb] += update_mask(v, gb) != want; inv[gb] += update_mask_inv(update_mask(v, gb), gb) != v or update_mask(update_mask_inv(v, gb), gb) != v
check('update_mask (AES, IEEE 1619 5.2) equals multiplication by x, V[i] = coefficient of x^i', bad[False] == 0)
check('update_mask (SM4_XEX, GB/T 17964: byte 0 bit 7 = x^0) equals multiplication by x', bad[True] == 0)
check('update_mask_inv inverts update_mask (AES and SM4_XEX, carry cases included)', inv[False] == 0 and inv[True] == 0)
check('SM4_XEX update_mask: carry out of byte 15 bit 0 xors 0xE1 into byte 0', update_mask(1 << 120, True) == 0xE1)
check('SM4_XEX update_mask: byte 0 bit 0 moves to byte 1 bit 7', update_mask(1, True) == 1 << 15)
check('AES update_mask: carry xors 0x87', update_mask(1 << 127) == 0x87)
control('AES and SM4 update_mask differ (wrong variant is detected)', update_mask(0x1234, False) != update_mask(0x1234, True))
control('OCB3 big-endian double instead of update_mask is detected', double(0x1234 | 1 << 127) != update_mask(0x1234 | 1 << 127))

section('SM4_XEX: GB/T 17964-2021 cross-check (OpenSSL 3.6.2 SM4-XTS, xts_standard=GB, embedded vectors)')
SK = bytes(range(32)); ST = bytes(range(16, 32)); SD = bytes(range(100, 200))
GB = {48: 'dac447dce6c6ec13d334f662a24d9fa09bb19b60e5b8b929c5108e6a49270f8bbbf89ddc252af3f9f8557559d960a53f',
      17: '483440d347c850b350d9c2fdf7f3f32fda', 31: '6942750e238dbc3b57f4f56d0103a109dac447dce6c6ec13d334f662a24d9f',
      40: 'dac447dce6c6ec13d334f662a24d9fa0cbe121d6f7769080cacea87d470e056b9bb19b60e5b8b929',
      47: 'dac447dce6c6ec13d334f662a24d9fa08f1e49e4f158d2aadf8ee5c1474744a69bb19b60e5b8b929c5108e6a49270f',
      64: 'dac447dce6c6ec13d334f662a24d9fa09bb19b60e5b8b929c5108e6a49270f8bbbf89ddc252af3f9f8557559d960a53f00d20f54e1bdf0b67181897478c3bc87'}
for n, c in GB.items():
    c = H(c); pt = SD[:n]
    check('SM4_XEX/GB %d bytes: reference (GB mask) equals GB/T 17964 vector' % n, xts_ref('SM4', SK[:16], SK[16:], ST, pt, True, True) == c)
    check('SM4_XEX/GB %d bytes: locker encrypt' % n, xts_locker(lk(3, SK[:16], SK[16:]), b2v(ST), pt, True) == c)
    check('SM4_XEX/GB %d bytes: locker decrypt' % n, xts_locker(lk(3, SK[:16], SK[16:]), b2v(ST), c, False) == pt)
control('IEEE (AES-style) mask update gives a different SM4 ciphertext', xts_ref('SM4', SK[:16], SK[16:], ST, SD[:48], True, False) != H(GB[48]))
check('SM4_XEX first block equals the IEEE one (block 0 uses the unmultiplied mask)', xts_ref('SM4', SK[:16], SK[16:], ST, SD[:16], True, False) == H(GB[48])[:16])
L = lk(3, SK[:16], SK[16:]); L.setst(S_ENC, 'C', vec=b2v(ST))
check('SM4_XEX mask after Encrypt setst = SM4_enc(key2, tweak) as a byte string', v2b(L.mask, 16) == sm4_enc(SK[16:], ST))

section('XEX Machine, full blocks: IEEE 1619 vectors 2, 3 through the locker')
for i, (k, tw, pt, ct) in enumerate((V2, V3), 2):
    L = lk(0, k[:16], k[16:])
    check('AES128_XEX vector %d encrypt, tweak = Form C INPUT' % i, v2b(L.exec(b2v(pt), 256)[0] if L.setst(S_ENC, 'C', vec=b2v(tw)) is None else 0, 32) == ct)
    L = lk(0, k[:16], k[16:]); L.setst(S_DEC, 'C', vec=b2v(tw)); check('AES128_XEX vector %d decrypt' % i, v2b(L.exec(b2v(ct), 256)[0], 32) == pt)
    L = lk(0, k[:16], k[16:]); L.setst(S_ENC, 'B', xs=b2v(tw)); check('Form B tweak (Xs zero-extended) gives the same result', v2b(L.exec(b2v(pt), 256)[0], 32) == ct)
check('vector 1 (key2 = key1): Invalid Metadata, Error State Invalid', lk(0, bytes(16), bytes(16)).err == SE_INVALID)
L = lk(0, bytes(16), bytes(16)); L.setst(S_ENC); check('... the Error-State locker stays inert', L.exec(0, 256) == (0, 0) and L.err == SE_INVALID)
L = lk(0, V2[0][:16], V2[0][16:]); L.setst(S_ENC, 'C', vec=b2v(V2[1])); o1 = L.exec(b2v(V2[2]), 128)[0]
check('mask evolves per block: two kl.exec of one block equal one of two', o1 | L.exec(b2v(V2[2][16:]), 128)[0] << 128 == b2v(V2[3]))
Lr = lk(0, V2[0][:16], V2[0][16:]); Lr.setst(S_ENC, 'C', vec=b2v(V2[1]))
control('reversed block order (MR13) is detected', Lr.exec(b2v(V2[2][:16] + bytes(range(16))), 256)[0] != b2v(V2[3][:16] + V2[3][16:]) and
        v2b(Lr.exec(0, 0 + 128)[0], 16) != b'')

section('XTS-AES-256 with the IEEE 1619 vector 15-19 keys/tweak/data: embedded OpenSSL vectors, ciphertext stealing')
K1 = H('2718281828459045235360287471352662497757247093699959574966967627'); K2 = H('3141592653589793238462643383279502884197169399375105820974944592')
TW = bytes([0xff]) + bytes(15); D = bytes(i % 256 for i in range(512))
AES = {17: '990b3d5708499ecacac51584606f5d761c', 18: '22198698e5b15908a03bb6311e2af2b01c3b', 19: '7b3392c4b71bc01bf8a7d3d40120a6621c3b3a',
       20: 'bf4c6230fd0b520912383064f121273e1c3b3a10', 31: 'b7a469d9a0a8237d178ad4323b2746321c3b3a102f770386e4836c99e370cf',
       33: '1c3b3a102f770386e4836c99e370cf9b9bee4cdc56e3a896a412a76f007c85f9ea',
       47: '1c3b3a102f770386e4836c99e370cf9b9cd1c0d093eb321fe784b6fb478d1602ea00803f5e482357a4ae12d414a3e6',
       48: '1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44'}
for n, c in AES.items():
    c = H(c); pt = D[:n]
    check('XTS-AES-256 (IEEE keys 15-19): %d bytes, reference' % n, xts_ref('AES256', K1, K2, TW, pt, True) == c)
    check('%d bytes encrypt via Machine (steal recipe)' % n, xts_locker(lk(2, K1, K2), b2v(TW), pt, True) == c)
    check('%d bytes decrypt via Machine (kl_xex_state_steal)' % n, xts_locker(lk(2, K1, K2), b2v(TW), c, False) == pt)
c520 = xts_locker(lk(2, K1, K2), b2v(TW), (D + D)[:520], True)
check('520 bytes (32 blocks + 8): SHA-256 of ciphertext', hashlib.sha256(c520).hexdigest() == 'f4e58dddc53736fe76523a88ff6699028e112193828008e219f4844776b828b9')
K3 = bytes(range(64)); a31 = H('012603e6a9a883164c5b6c445dc2f73775de381013f2a09b6655cf5e407ca7'); a33 = H('75de381013f2a09b6655cf5e407ca71cc797b85292be938d811051e250dd876dcb')
check('AES256 key, 31 and 33 bytes: encrypt', xts_locker(lk(2, K3[:32], K3[32:]), b2v(TW), D[:31], True) == a31 and xts_locker(lk(2, K3[:32], K3[32:]), b2v(TW), D[:33], True) == a33)

section('Round trips and reference agreement for all lengths (AES128, AES256, SM4)')
bad = 0; cnt = 0
for t, (a, kl_) in ((0, ('AES128', 16)), (2, ('AES256', 32)), (3, ('SM4', 16))):
    for n in list(range(16, 80)) + [128, 129, 255, 256]:
        k1 = bytes(rnd.getrandbits(8) for _ in range(kl_)); k2 = bytes(rnd.getrandbits(8) for _ in range(kl_)); d = bytes(rnd.getrandbits(8) for _ in range(n))
        tw = bytes(rnd.getrandbits(8) for _ in range(16)); gb = t == 3
        c = xts_locker(lk(t, k1, k2), b2v(tw), d, True); cnt += 1
        bad += c != xts_ref(a, k1, k2, tw, d, True, gb) or xts_locker(lk(t, k1, k2), b2v(tw), c, False) != d or len(c) != n
check('%d (cipher, length) pairs: locker = reference, decrypt inverts' % cnt, bad == 0)

section('StealSkip / StealBack, States and transitions')
k1, k2 = V2[0][:16], V2[0][16:]; tw = b2v(V2[1]); P = bytes(range(32))
def dec_locker():
    L = lk(0, k1, k2); L.setst(S_DEC, 'C', vec=tw); return L
L = dec_locker(); L.setst(66)
check('kl_xex_state_steal in Decrypt: State unchanged, StealSkip (StateExtension bit 0) set', L.state == S_DEC and mdh_get(L.mdh(), 'StateExtension') == 1 and not L.inert())
L.setst(66); check('second steal while StealSkip set: Invalid', L.err == SE_INVALID)
L = lk(0, k1, k2); L.setst(S_ENC, 'C', vec=tw); L.setst(66); check('kl_xex_state_steal in Encrypt: Invalid', L.err == SE_INVALID)
L = lk(0, k1, k2); L.setst(66); check('kl_xex_state_steal in Ready: Invalid', L.err == SE_INVALID)
L = dec_locker(); L.setst(66, 'B', xs=1); check('kl_xex_state_steal needs Form A', L.err == SE_INVALID)
L = dec_locker(); L.setst(66); L.exec(b2v(P), 256)
check('StealSkip: kl.exec with KLLEN 256 processes exactly one block; StealBack set, StealSkip clear',
      mdh_get(L.mdh(), 'StateExtension') == 2 and L.state == S_DEC)
o = L.exec(b2v(P), 128)[0]; check('StealBack: next kl.exec leaves State Success (54)', L.state == S_SUCCESS and mdh_get(L.mdh(), 'State') == 54)
L.exec(b2v(P), 128); check('kl.exec in Success: Invalid', L.err == SE_INVALID)
L = dec_locker(); L.setst(66); L.exec(b2v(P), 256); L.exec(b2v(P), 128); L.setst(S_READY)
check('Success -> Ready: mask 0, StealSkip/StealBack clear', L.state == S_READY and L.mask == 0 and L.steal == 0)
L = dec_locker(); L.setst(66); o, ks = L.exec(b2v(P), 256, 0); L = dec_locker(); L.setst(66); L.exec(b2v(P), 256, 16)
check('StealSkip: klstart 16 (not the single interruption point 0) is Invalid', L.err == SE_INVALID)
L = dec_locker(); L.setst(66); o, ks = L.exec(b2v(P), 256, 0, stop=1)
check('StealSkip: one-block kl.exec completes in a single step (klstart 0)', ks == 0)
L = dec_locker(); L.setst(66); L.setst(S_DEC, 'C', vec=tw)
check('same-State setst after steal clears StealSkip and re-tweaks', L.steal == 0 and not L.inert())
L = dec_locker(); L.setst(66); L.exec(b2v(P), 128); L.setst(S_DEC, 'C', vec=tw); check('... also clears StealBack', L.steal == 0 and L.state == S_DEC)
L = dec_locker(); L.setst(66); mdh, c1 = L.export(); L2 = Locker.import_(mdh, c1)
check('export/import with StealSkip keeps it', L2.steal == 1 and L2.mask == L.mask)
check('import with StealSkip and StealBack both set: Invalid', Locker.import_(mdh_put(mdh, 'StateExtension', 3), c1).err == SE_INVALID)
check('import with other StateExtension (4): Invalid (unsupported)', Locker.import_(mdh_put(mdh, 'StateExtension', 4), c1).err == SE_INVALID)
L = lk(0, k1, k2); L.setst(S_ENC, 'C', vec=tw); mdh, c1 = L.export()
check('import of StealSkip in State Encrypt: Invalid', Locker.import_(mdh_put(mdh, 'StateExtension', 1), c1).err == SE_INVALID)
check('import with key2 = key1: Invalid', Locker.import_(mdh, c1[:16] + c1[:16] + c1[32:]).err == SE_INVALID)
L = lk(0, k1, k2, 2); L.setst(S_DEC, 'C', vec=tw); mdh, c1 = L.export(); L = Locker.import_(mdh_put(mdh, 'MachinePolicy', 1), c1); L.setst(66)
check('Decrypt SCC narrowed to encrypt-only: kl_xex_state_steal -> Invalid (MR1)', L.err == SE_INVALID)
L = dec_locker(); L.setst(66); mdh, c1 = L.export(); L = Locker.import_(mdh_put(mdh, 'MachinePolicy', 1), c1); L.exec(b2v(P), 256)
check('SCC with StealSkip narrowed to encrypt-only: kl.exec -> Invalid (MR1)', L.err == SE_INVALID)
# cross transitions, AES and SM4
for t, kk1, kk2, gb in ((0, k1, k2, False), (2, K1, K2, False), (3, SK[:16], SK[16:], True)):
    n = TYPES[t]; Pd = bytes(range(48)); L = lk(t, kk1, kk2); L.setst(S_DEC, 'C', vec=5); L.setst(66); L.exec(b2v(Pd), 128)
    check(n + ': Decrypt with StealBack -> Encrypt: admitted, StealSkip/StealBack cleared', (L.setst(S_ENC, 'C', vec=9), L.state == S_ENC and L.steal == 0 and not L.inert())[1])
    c = v2b(L.exec(b2v(Pd), 384)[0], 48)
    check(n + ': ... Encrypt after cross transition uses the new tweak (reference)', c == xts_ref(n, kk1, kk2, (9).to_bytes(16, 'little'), Pd, True, gb))
    L.setst(S_DEC, 'C', vec=9); check(n + ': Encrypt -> Decrypt, then decrypts what was encrypted', v2b(L.exec(b2v(c), 384)[0], 48) == Pd)
    L = lk(t, kk1, kk2); L.setst(S_DEC, 'C', vec=5); L.setst(66); L.setst(S_ENC, 'C', vec=5)
    check(n + ': Decrypt with StealSkip -> Encrypt clears StealSkip', L.steal == 0 and L.state == S_ENC and not L.inert())
    L.exec(0, 128); L.setst(S_DEC); check(n + ': Encrypt -> Decrypt Form A: tweak 0, mask reset', v2b(L.mask, 16) == cipher_enc(n, kk2, bytes(16)))
    L = lk(t, kk1, kk2, 1); L.setst(S_ENC); L.setst(S_DEC); check(n + ': policy gate: encrypt-only Encrypt -> Decrypt Invalid', L.err == SE_INVALID)
    L = lk(t, kk1, kk2, 2); L.setst(S_DEC); L.setst(S_ENC); check(n + ': policy gate: decrypt-only Decrypt -> Encrypt Invalid', L.err == SE_INVALID)
    L = lk(t, kk1, kk2); L.setst(S_DEC, 'C', vec=5); L.setst(66); L.exec(b2v(Pd), 128); L.exec(b2v(Pd), 128); L.setst(S_ENC)
    check(n + ': Success -> Encrypt/Decrypt still Invalid (only -> Ready listed)', L.err == SE_INVALID)
# transitions
L = lk(0, k1, k2); check('provisioned: Ready, mask 0', L.state == S_READY and L.mask == 0)
L.setst(S_ENC, 'C', vec=7); check('Encrypt: mask = enc_blk(key2, tweak) with tweak bin(7,128) LE', v2b(L.mask, 16) == aes_enc(k2, (7).to_bytes(16, 'little')))
m0 = L.mask; L.setst(S_ENC, 'C', vec=7); check('same-State setst re-tweaks (mask restored)', L.mask == m0 and L.state == S_ENC)
L.exec(0, 128); L.setst(S_ENC); check('Form A tweak = 0: mask = enc_blk(key2, 0)', v2b(L.mask, 16) == aes_enc(k2, bytes(16)))
L.setst(S_DEC, 'C', vec=11)
check('Encrypt -> Decrypt directly (spec table): admitted, new tweak, mask recomputed', L.state == S_DEC and not L.inert() and v2b(L.mask, 16) == aes_enc(k2, (11).to_bytes(16, 'little')))
L = lk(0, k1, k2); L.setst(S_ENC, 'C', vec=7); L.setst(S_READY); check('-> Ready: mask 0', L.mask == 0 and L.state == S_READY)
L.setst(S_DEC); check('Ready -> Decrypt (Form A)', L.state == S_DEC)
L = lk(0, k1, k2); L.exec(0, 128); check('kl.exec in Ready: Invalid', L.err == SE_INVALID)
for imm in (S_OPERATE, S_AUX, 54, 55, 50):
    L = lk(0, k1, k2); L.setst(imm); check('kl.setst immediate %d: Invalid' % imm, L.err == SE_INVALID)
for pol, e, d in ((1, 1, 0), (2, 0, 1), (3, 1, 1)):
    a = lk(0, k1, k2, pol); a.setst(S_ENC); b = lk(0, k1, k2, pol); b.setst(S_DEC)
    check('MachinePolicy %d: encrypt %s, decrypt %s' % (pol, bool(e), bool(d)), (not a.inert(), not b.inert()) == (bool(e), bool(d)))
check('MachinePolicy 0: Invalid', lk(0, k1, k2, 0).err == SE_INVALID)
L = lk(0, k1, k2); L.setst(S_ENC); L.exec(0, 136); check('MR6: KLLEN 136 Invalid', L.err == SE_INVALID)
L = lk(0, k1, k2); L.setst(S_ENC); L.exec(0, 256, 8); check('klstart 8 Invalid', L.err == SE_INVALID)
L = lk(0, k1, k2); L.setst(S_ENC); check('klstart >= KLLEN/8: empty window', L.exec(0, 256, 32) == (0, 0) and not L.inert())
for stop in (1, 3, 7):
    L = lk(0, k1, k2); L.setst(S_ENC, 'C', vec=9); d = bytes(i * 7 % 256 for i in range(16 * 31)); acc = 0; ks = 0
    while True:
        o, ks = L.exec(b2v(d), 16 * 8 * 31, ks, stop=stop); acc |= o
        if ks == 0: break
    check('31 blocks, halting every %d blocks, resume: result equals reference' % stop, v2b(acc, len(d)) == xts_ref('AES128', k1, k2, (9).to_bytes(16, 'little'), d, True))

section('PI and Content sizes, kl.derive of key1 || key2')
check('AES128_XEX PI 48, AES256_XEX PI 80, by SKID PI 32', pi_size(machine(0, 6)) == 48 and pi_size(machine(2, 6)) == 80 and pi_size(machine(0, 6), 1) == 32)
check('AES128_XEX Content1 = key1|key2|mask = 48, SCC 80; AES256 80/112', len(lk(0, k1, k2).content1()) == 48 and len(lk(2, K1, K2).content1()) == 80)
KS = bytes(range(1, 97))
for t, need in ((0, 32), (2, 64), (3, 32)):
    L = lk(t, bytes(need // 2), bytes([1]) * (need // 2)); ok = L.load_key(KS, 96)
    check(TYPES[t] + '_XEX derive length 96: key1||key2 = first %d bytes' % need, ok and L.key == KS[:need // 2] and L.key2 == KS[need // 2:need])
    L = lk(t, bytes(need // 2), bytes([1]) * (need // 2)); check(TYPES[t] + '_XEX derive length %d < %d: Invalid' % (need - 1, need), not L.load_key(KS, need - 1) and L.err == SE_INVALID)
    L = lk(t, bytes(need // 2), bytes([1]) * (need // 2)); check(TYPES[t] + '_XEX derive with key1 = key2 in the source: Invalid', not L.load_key(bytes(need), 96))
L = lk(0, k1, k2); L.setst(S_ENC); check('derive into key in Encrypt: Invalid', not L.load_key(KS, 96))
L = lk(0, k1, k2); L.setst(S_ENC, 'C', vec=3); src = Locker(machine(0, 4), 3, bytes(16)); src.setst(S_OPERATE)
L = lk(0, k1, k2); L.setst(S_ENC, 'C', vec=3); L.setst(S_READY); L.load_key(src.derive_out(32), 32)
check('CTR keystream into XEX keys (32 bytes = 2 blocks consumed); ctr 2', L.key + L.key2 == b''.join(cipher_enc('AES128', bytes(16), bytes(12) + i.to_bytes(4, 'big')) for i in range(2)) and src.ctr == 2)
L = lk(0, k1, k2); L.load_key(KS, 96); L.setst(S_ENC, 'C', vec=0)
check('derived keys work: Encrypt result equals reference with those keys', v2b(L.exec(b2v(P), 256)[0], 32) == xts_ref('AES128', KS[:16], KS[16:32], bytes(16), P, True))
done()
