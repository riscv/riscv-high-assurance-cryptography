"""Ascon-AEAD128: check the corrected ACE _Enc_Last_Block_ / _Dec_Last_Block_ text.

C8 (empty final block: state[0] ^= 1) and C9 (partial final block: XOR the padded
*plaintext* into the rate, not assign pad(ciphertext)) are both properties of
encrypt/decrypt agreement, so a round-trip + tamper test has direct power over them.
The old formulation is run too, to confirm the test can actually fail.
"""
M64 = (1 << 64) - 1
RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]

def rotr(x, n): return ((x >> n) | (x << (64 - n))) & M64

def P(s, rounds):
    for c in RC[12 - rounds:]:
        s[2] ^= c
        s[0] ^= s[4]; s[4] ^= s[3]; s[2] ^= s[1]
        t = [(~s[i]) & s[(i + 1) % 5] for i in range(5)]
        for i in range(5): s[i] ^= t[(i + 1) % 5]
        s[1] ^= s[0]; s[0] ^= s[4]; s[3] ^= s[2]; s[2] ^= M64
        s[0] ^= rotr(s[0], 19) ^ rotr(s[0], 28)
        s[1] ^= rotr(s[1], 61) ^ rotr(s[1], 39)
        s[2] ^= rotr(s[2], 1) ^ rotr(s[2], 6)
        s[3] ^= rotr(s[3], 10) ^ rotr(s[3], 17)
        s[4] ^= rotr(s[4], 7) ^ rotr(s[4], 41)
    return s

IV = 0x00001000808c0001            # SP 800-232 Ascon-AEAD128
def b2v(bs): return int.from_bytes(bs, 'little')
def v2b(v, n): return (v & ((1 << (8*n)) - 1)).to_bytes(n, 'little')
def sl(v, hi, lo): return (v >> lo) & ((1 << (hi - lo + 1)) - 1)

def ace_pad(x, n, r=128):           # spec: pad(x,r) = 0^j @ 1 @ x
    return (1 << n) | (x & ((1 << n) - 1)) if n else 1

def init(key, nonce):
    k0, k1 = b2v(key[:8]), b2v(key[8:])
    s = [IV, k0, k1, b2v(nonce[:8]), b2v(nonce[8:])]
    P(s, 12)
    s[3] ^= k0; s[4] ^= k1
    return s, k0, k1

def absorb_ad(s, A):
    if not A: return
    blocks = A + b'\x01' + bytes((-len(A) - 1) % 16)   # user-supplied padding
    for i in range(0, len(blocks), 16):
        blk = b2v(blocks[i:i+16])
        s[0] ^= sl(blk, 63, 0); s[1] ^= sl(blk, 127, 64)
        P(s, 8)

def finalize(s, k0, k1):
    s[2] ^= k0; s[3] ^= k1
    P(s, 12)
    s[3] ^= k0; s[4] ^= k1
    return v2b(s[3], 8) + v2b(s[4], 8)

def ace_enc(key, nonce, A, Pt):
    s, k0, k1 = init(key, nonce); absorb_ad(s, A)
    s[4] ^= (1 << 63)                                   # domain separation
    C = b''
    full, rest = len(Pt) // 16 * 16, len(Pt) % 16
    for i in range(0, full, 16):
        blk = b2v(Pt[i:i+16])
        s[0] ^= sl(blk, 63, 0); s[1] ^= sl(blk, 127, 64)
        C += v2b(s[0], 8) + v2b(s[1], 8)
        P(s, 8)
    n = rest * 8
    if n == 0:
        s[0] ^= 1                                       # C8
    else:
        tmp = ace_pad(b2v(Pt[full:]), n)
        s[0] ^= sl(tmp, 63, 0); s[1] ^= sl(tmp, 127, 64)
        C += v2b((s[1] << 64) | s[0], 16)[:rest]
    return C + finalize(s, k0, k1)

def ace_dec(key, nonce, A, C_and_tag, old=False):
    C, tag = C_and_tag[:-16], C_and_tag[-16:]
    s, k0, k1 = init(key, nonce); absorb_ad(s, A)
    s[4] ^= (1 << 63)
    Pt = b''
    full, rest = len(C) // 16 * 16, len(C) % 16
    for i in range(0, full, 16):
        blk = b2v(C[i:i+16])
        tmp = ((s[1] ^ sl(blk, 127, 64)) << 64) | (s[0] ^ sl(blk, 63, 0))
        s[0] = sl(blk, 63, 0); s[1] = sl(blk, 127, 64)
        P(s, 8)
        Pt += v2b(tmp, 16)
    n = rest * 8
    if n == 0:
        s[0] ^= 1
    elif old:                                           # OLD text (buggy)
        S_r = (s[1] << 64) | s[0]
        tmp = S_r ^ b2v(C[full:].ljust(16, b'\0'))
        Pt += v2b(sl(tmp, n - 1, 0), rest)
        t2 = ace_pad(b2v(C[full:]), n)                  # pad(INPUT), assigned
        s[0] = sl(t2, 63, 0); s[1] = sl(t2, 127, 64)
    else:                                               # CORRECTED text
        S_r = (s[1] << 64) | s[0]
        out = sl(S_r, n - 1, 0) ^ b2v(C[full:])
        Pt += v2b(out, rest)
        S_r ^= ace_pad(out, n)
        s[0] = sl(S_r, 63, 0); s[1] = sl(S_r, 127, 64)
    return finalize(s, k0, k1) == tag, Pt

import os
key = bytes(range(16)); nonce = bytes(range(16, 32))
cases = [(la, lp) for la in (0, 5, 16, 23) for lp in range(0, 40)]
newok = oldok = True
tamper_ok = True
for la, lp in cases:
    A, Pt = bytes(range(la)), bytes((i * 7 + 3) & 0xff for i in range(lp))
    ct = ace_enc(key, nonce, A, Pt)
    ok, rec = ace_dec(key, nonce, A, ct)
    newok &= ok and rec == Pt
    ok2, rec2 = ace_dec(key, nonce, A, ct, old=True)
    oldok &= ok2 and rec2 == Pt
    bad = bytearray(ct); bad[0] ^= 0x40
    okt, _ = ace_dec(key, nonce, A, bytes(bad))
    tamper_ok &= not okt

print(f"cases tested: {len(cases)}  (AD len 0/5/16/23 x PT len 0..39)")
print("corrected text  - round-trip + tag verify :", "PASS" if newok else "FAIL")
print("corrected text  - tamper rejected         :", "PASS" if tamper_ok else "FAIL")
print("previous text   - round-trip + tag verify :",
      "PASS (test has no power!)" if oldok else "FAIL (expected: the bug is real)")
print()
print("Ascon-AEAD128 IV in use: 0x%016x" % IV)
