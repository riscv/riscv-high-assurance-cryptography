"""SM3 as instantiated by <<ACE-SM3>>.

The section defines SM3 as following the SHA-2 family rules with w=32, b=512, n=256,
t=256: a big-endian Merkle-Damgard function with the same padding rule and word mapping
as SHA-256, and the IV and compression function of GB/T 32905-2016. ACE implements
exactly that: words are absorbed as int(bswap(block[(j+1)w-1 : jw])) under the ACE value
model, and the digest is emitted big-endian per chaining variable.

Anchored against the two vectors of GB/T 32905-2016 appendix A, and cross-checked
against hashlib's 'sm3' when the OpenSSL build provides it. A negative control absorbs
the words without the bswap and must fail.
"""
import os, sys, hashlib
d = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, d)
exec(open(os.path.join(d, 'ocb-kat.py')).read()
     .split('# ------------------------------------------------------------------ vectors')[0])

M32 = 0xffffffff
IV_SM3 = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
          0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]

def rotl(x, r): r %= 32; return ((x << r) | (x >> (32 - r))) & M32
def P0(x): return x ^ rotl(x, 9) ^ rotl(x, 17)
def P1(x): return x ^ rotl(x, 15) ^ rotl(x, 23)

def sm3_compress(V, W16):
    W = list(W16)
    for j in range(16, 68):
        W.append(P1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15)) ^ rotl(W[j-13], 7) ^ W[j-6])
    Wp = [W[j] ^ W[j+4] for j in range(64)]
    A,B,C,D,E,F,G,H = V
    for j in range(64):
        T = 0x79cc4519 if j < 16 else 0x7a879d8a
        SS1 = rotl((rotl(A, 12) + E + rotl(T, j)) & M32, 7)
        SS2 = SS1 ^ rotl(A, 12)
        FF = (A ^ B ^ C) if j < 16 else ((A & B) | (A & C) | (B & C))
        GG = (E ^ F ^ G) if j < 16 else ((E & F) | ((~E) & G & M32))
        TT1 = (FF + D + SS2 + Wp[j]) & M32
        TT2 = (GG + H + SS1 + W[j]) & M32
        D, C, B, A = C, rotl(B, 9), A, TT1
        H, G, F, E = G, rotl(F, 19), E, P0(TT2)
    return [v ^ x for v, x in zip(V, [A,B,C,D,E,F,G,H])]

def ace_sm3(msg, be_words=True):
    """<<ACE-SM3>> in the ACE value model: SHA-256's padding and word mapping."""
    L = len(msg) * 8
    msg = msg + b'\x80' + bytes((-(len(msg) + 1 + 8)) % 64) + L.to_bytes(8, 'big')
    V = list(IV_SM3)
    for i in range(0, len(msg), 64):
        block_v = b2v(msg[i:i + 64])
        W = [(bswap(sl(block_v, (j+1)*32 - 1, j*32), 32) if be_words
              else sl(block_v, (j+1)*32 - 1, j*32)) for j in range(16)]
        V = sm3_compress(V, W)
    dig_v, pos = 0, 0
    for vi in V:
        dig_v |= bswap(vi, 32) << pos; pos += 32
    return v2b(dig_v, 32)

TV = [  # GB/T 32905-2016 appendix A
    (b'abc',
     '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
    (b'abcd' * 16,
     'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'),
]
ok = True
for m, h in TV:
    a = ace_sm3(m)
    good = a == bytes.fromhex(h)
    ok &= good
    print(f"SM3({m[:12]!r}{'...' if len(m) > 12 else ''}) vs GB/T 32905 vector: "
          f"{'PASS' if good else 'FAIL'}")

try:                                    # cross-check against OpenSSL, if available
    n = 0
    for m in [b'', b'abc', b'a'*63, b'a'*64, bytes(range(200))]:
        assert ace_sm3(m) == hashlib.new('sm3', m).digest(); n += 1
    print(f"cross-check against hashlib 'sm3': PASS ({n} cases)")
except (ValueError, AssertionError) as e:
    if isinstance(e, AssertionError):
        ok = False; print("cross-check against hashlib 'sm3': FAIL")
    else:
        print("cross-check against hashlib 'sm3': skipped (not provided by OpenSSL)")

neg = ace_sm3(b'abc', be_words=False) != bytes.fromhex(TV[0][1])
print(f"negative control (words absorbed without bswap) is caught: "
      f"{'PASS' if neg else 'FAIL'}")
ok &= neg
print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
