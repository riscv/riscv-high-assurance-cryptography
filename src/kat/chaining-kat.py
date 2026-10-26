#!/usr/bin/env python3
"""CBC, CFB and OFB Machines (<<KLE-chaining>>) against SP 800-38A F.2, F.3.13 and F.4.1: the
chaining value `IV` over Encrypt/Decrypt/Operate, the entry through `kl.setst`, and the Ready reset."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import aes_encrypt, aes_decrypt, bxor, section, check, done

KEY, IV0 = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'), bytes(range(16))
PT = [bytes.fromhex(x) for x in ('6bc1bee22e409f96e93d7e117393172a', 'ae2d8a571e03ac9c9eb76fac45af8e51',
                                 '30c81c46a35ce411e5fbc1191a0a52ef', 'f69f2445df4f9b17ad2b417be66c3710')]
CT = {'CBC': ('7649abac8119b246cee98e9b12e9197d', '5086cb9b507219ee95db113a917678b2',
              '73bed6b8e3c1743b7116e69e22229516', '3ff1caa1681fac09120eca307586e1a7'),
      'CFB': ('3b3fd92eb72dad20333449f8e83cfb4a', 'c8a64537a0b3a93fcde3cdad9f1ce58b',
              '26751f67a3cbb140b1808cf187a4f4df', 'c04b05357c5d1c0eeac4c66f9ff7f2e6'),
      'OFB': ('3b3fd92eb72dad20333449f8e83cfb4a', '7789508d16918f03f53c52dac54ed825',
              '9740051e9c5fecf64344f7a82260edcc', '304c6528f659c77866a510d9c1d6ae5e')}
CT = {m: [bytes.fromhex(x) for x in v] for m, v in CT.items()}


def raises_exec(c):
    try: c.exec(bytes(16))
    except RuntimeError: return True
    return False


class Chain:
    """The Machine: `mode` CBC/CFB/OFB, `st` Ready/Encrypt/Decrypt/Operate, chaining value `iv`."""
    B = 128
    def __init__(s, mode): s.mode, s.st, s.iv, s.s = mode, 'Ready', bytes(16), 128

    def set_s(s, xs):                                # Form B kl.setst into Set_Aux_Value (CFB)
        assert s.mode == 'CFB'
        if not 0 < xs <= s.B: s.st = 'Invalid'; return
        s.st, s.s = 'Set_Aux_Value', xs

    def setst(s, st, inp=None):                      # Form C with `inp`; Form A is a zero `inp`
        if s.st in ('Invalid',): return
        assert st in (('Operate',) if s.mode == 'OFB' else ('Encrypt', 'Decrypt'))
        s.st, s.iv = st, (bytes(16) if inp is None else inp)

    def ready(s): s.st, s.iv, s.s = 'Ready', bytes(16), 128

    def exec(s, blk):                                # one Form A (CBC, CFB) or Form C (OFB) block
        e = lambda x: aes_encrypt(KEY, x)
        if s.st in ('Ready', 'Set_Aux_Value', 'Invalid'): raise RuntimeError('kl.exec not admitted')
        if s.mode == 'OFB':
            s.iv = e(s.iv); return s.iv
        if s.mode == 'CBC':
            if s.st == 'Encrypt': out = e(bxor(blk, s.iv)); s.iv = out
            else: out = bxor(aes_decrypt(KEY, blk), s.iv); s.iv = blk
        else:
            out = bxor(blk, e(s.iv)); s.iv = out if s.st == 'Encrypt' else blk
        return out

    def segments(s, data, st):                       # CFB-s over a bit string: data is (int, nbits)
        v, n = data; o = 0                       # the n - n // u * u tail bits are ignored
        for j in range(n // s.s):
            seg = (v >> (n - (j + 1) * s.s)) & ((1 << s.s) - 1)
            ks = int.from_bytes(aes_encrypt(KEY, s.iv), 'big') >> (128 - s.s)
            r = seg ^ ks
            c = r if st == 'Encrypt' else seg
            s.iv = (((int.from_bytes(s.iv, 'big') << s.s) | c) & (2**128 - 1)).to_bytes(16, 'big')
            o = o << s.s | r
        return o << n - n // s.s * s.s           # OUTPUT zero beyond the last segment


def run(mode, st, data, iv=IV0):
    m = Chain(mode); m.setst(st, iv)
    if mode == 'OFB':                                # the caller combines the keystream with the data
        return [bxor(m.exec(None), b) for b in data]
    return [m.exec(b) for b in data]


for mode in ('CBC', 'CFB', 'OFB'):
    section(mode)
    enc = 'Operate' if mode == 'OFB' else 'Encrypt'
    dec = 'Operate' if mode == 'OFB' else 'Decrypt'
    check(f'{mode} encryption, SP 800-38A', run(mode, enc, PT) == CT[mode])
    check(f'{mode} decryption, SP 800-38A', run(mode, dec, CT[mode]) == PT)
    m = Chain(mode); m.setst(enc, IV0); a = m.exec(PT[0])
    m.setst(enc, IV0)                                # same-State setst replaces `IV`
    check(f'{mode}: a same-State kl.setst replaces IV, so the first block repeats', m.exec(PT[0]) == a)
    m.setst(enc)                                     # Form A: a zero INPUT
    check(f'{mode}: a Form A kl.setst sets IV to 0', m.iv == bytes(16))
    m.exec(PT[0]); m.ready()
    check(f'{mode}: returning to Ready zeroes IV', m.iv == bytes(16) and m.st == 'Ready')
    if mode == 'CFB':
        c = Chain('CFB')
        check('CFB: u defaults to b = 128', c.s == 128)
        c.set_s(8); check('CFB: Set_Aux_Value admits no kl.exec', raises_exec(c))
        c.setst('Encrypt', IV0); pt = bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d')
        ct = c.segments((int.from_bytes(pt, 'big'), 144), 'Encrypt').to_bytes(18, 'big')
        check('CFB8 encryption, SP 800-38A F.3.7', ct == bytes.fromhex('3b79424c9c0dd436bace9e0ed4586a4f32b9'))
        c = Chain('CFB'); c.set_s(8); c.setst('Decrypt', IV0)
        check('CFB8 decryption, SP 800-38A F.3.8', c.segments((int.from_bytes(ct, 'big'), 144), 'Decrypt').to_bytes(18, 'big') == pt)
        c = Chain('CFB'); c.set_s(1); c.setst('Encrypt', IV0)
        check('CFB1 encryption, SP 800-38A F.3.4', c.segments((0x6bc1, 16), "Encrypt") == 0x68b3)
        c = Chain('CFB'); c.set_s(1); c.setst('Decrypt', IV0)
        check('CFB1 decryption, SP 800-38A F.3.5', c.segments((0x68b3, 16), 'Decrypt') == 0x6bc1)
        c.ready(); check('CFB: Ready restores u = b', c.s == 128 and c.st == 'Ready')
        for bad in (0, 129, 2**64 - 1):
            c = Chain('CFB'); c.set_s(bad); check(f'CFB: u = {bad} is Invalid', c.st == 'Invalid')
        def bits_cfb(u, data, st):                   # independent model on strings of '0'/'1'
            bs = lambda x: ''.join(f'{v:08b}' for v in x)
            iv, p, out = bs(IV0), bs(data), ''
            for j in range(0, len(p), u):
                ks = bs(aes_encrypt(KEY, int(iv, 2).to_bytes(16, 'big')))[:u]
                o = ''.join(str(int(x) ^ int(y)) for x, y in zip(p[j:j + u], ks))
                iv, out = iv[u:] + (o if st == 'Encrypt' else p[j:j + u]), out + o
            return out
        for u, g in ((3, 24), (7, 56)):              # whole segments over 2*lcm(8, u) bits
            n, pt = 2 * g, bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')[:g // 4]
            c = Chain('CFB'); c.set_s(u); c.setst('Encrypt', IV0)
            ct = c.segments((int.from_bytes(pt, 'big'), n), 'Encrypt')
            check(f'CFB{u} encryption over 2*lcm(8, {u}) bits, independent bit model',
                  format(ct, f'0{n}b') == bits_cfb(u, pt, 'Encrypt'))
            c = Chain('CFB'); c.set_s(u); c.setst('Decrypt', IV0)
            check(f'CFB{u} decryption inverts it', c.segments((ct, n), 'Decrypt') == int.from_bytes(pt, 'big'))
        # The KLE formulation of the spec (little-endian values, brev8, segments from the LSBs)
        # must give the byte string that the standard's big-endian model gives.
        def brev8(v, n): return int.from_bytes(bytes(int(f'{x:08b}'[::-1], 2) for x in v.to_bytes(n, 'little')), 'little')
        def kle_cfb(u, data, st):
            n, iv, out = len(data), IV0, 0
            X = brev8(int.from_bytes(data, 'little'), n)
            for j in range(8 * n // u):
                W = brev8(int.from_bytes(iv, 'little'), 16)
                Q = brev8(int.from_bytes(aes_encrypt(KEY, iv), 'little'), 16) & (2**u - 1)
                Xj = X >> (j * u) & (2**u - 1); Y = Xj ^ Q; out |= Y << (j * u)
                iv = brev8((Y if st == 'Encrypt' else Xj) << (128 - u) | W >> u, 16).to_bytes(16, 'little')
            return brev8(out, n).to_bytes(n, 'little')
        from math import lcm
        for u in (1, 3, 7, 8, 12, 64, 127, 128):
            data = bytes(range(1, 1 + 2 * lcm(8, u) // 8)) if u < 128 else bytes(range(1, 33))
            for st in ('Encrypt', 'Decrypt'):
                c = Chain('CFB'); c.set_s(u); c.setst(st, IV0)
                ref = c.segments((int.from_bytes(data, 'big'), 8 * len(data)), st).to_bytes(len(data), 'big')
                check(f'CFB{u} {st}: the spec formulas (brev8, LSB segments) match the standard', kle_cfb(u, data, st) == ref)
        # Byte granularity: a KLLEN that is no multiple of u processes floor(KLLEN/u) segments and ignores the tail.
        c = Chain('CFB'); c.set_s(3); c.setst('Encrypt', IV0)
        full = c.segments((0x6bc1be, 24), 'Encrypt')                       # 8 segments
        c = Chain('CFB'); c.set_s(3); c.setst('Encrypt', IV0)
        part = c.segments((0x6bc1, 16), 'Encrypt')                         # 5 segments, 1 tail bit
        check('CFB3: a 16-bit KLLEN processes 5 segments, ignores 1 bit, zeroes it in OUTPUT',
              part >> 1 == full >> 9 and part & 1 == 0)
        rest = c.segments((0x6bc1be & 0x1FF, 9), 'Encrypt')  # software shifts the tail in: 3 segments
        check('CFB3: shifting the tail into the next kl.exec continues the stream', rest == (full & 0x1FF))
        c = Chain('CFB'); c.set_s(64); c.setst('Encrypt', IV0); c.setst('Encrypt', IV0)
        check('CFB: a same-State kl.setst in Encrypt keeps u', c.s == 64)
    if mode != 'OFB':
        m = Chain(mode); m.setst('Encrypt', IV0); m.exec(PT[0])
        blob = m.iv + bytes([m.s])                   # Serialized Content: IV (b bits), u (8 bits)
        r = Chain(mode); r.st, r.iv, r.s = 'Encrypt', blob[:16], blob[16]
        check(f'{mode}: Serialized Content (IV, u) round trip continues the stream', r.exec(PT[1]) == m.exec(PT[1]))
        d = run(mode, 'Decrypt', run(mode, 'Encrypt', PT, bytes(16)), bytes(16))
        check(f'{mode}: decryption inverts encryption under a zero IV', d == PT)
done()
