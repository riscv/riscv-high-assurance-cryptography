#!/usr/bin/env python3
"""XEX/XTS (<<ACE-XEX-XTS-modes>> and <<ACE-XTS-from-XEX>> in
src/ace-ISA-algorithms.adoc) against the IEEE 1619-2007 / SP 800-38E vectors.

Three layers are checked, each against the same published vectors.

REF   Plain byte-string XTS with ciphertext stealing, written from the standard.

XEX   The ACE XEX CC exactly as <<ACE-XEX-XTS-modes>> specifies it:

          on entering _Encrypt_/_Decrypt_:  mask <- enc_blk(key2, INPUT)
          each ace.exec:  OUTPUT <- mask xor enc_blk(key1, INPUT xor mask)
                          mask  <- update_mask(mask)

      with the tweak supplied as `bin(i, b)`, the little-endian encoding of the
      data unit sequence number (<<ACE-XTS-from-XEX>>, "The tweak").  This covers
      every data unit whose length is a multiple of b.

CTS   The <<ACE-XTS-from-XEX>> "Ciphertext stealing" procedure implemented
      literally, including encryption's reordering of the last two blocks and
      decryption's clone-based ordering: one ace.clone, one *discarded* ace.exec
      on the clone to advance it from mask index m-1 to m, C_{m-1} decrypted on
      the clone at index m, and CP @ C_m decrypted on the original at index m-1.
      The clone is modelled as a real copy of the CC state, so an accidental
      aliasing of the two masks would show up as a failure.

NEG   Negative control: the same XEX data path with OCB3's big-endian `double`
      substituted for `update_mask`.  The two differ (one doubles the value, the
      other its byte-reversal), so this must fail the vectors.

Vectors and provenance
----------------------
All vectors are the IEEE 1619-2007 XTS-AES vectors, which SP 800-38E adopts, as
reproduced in the Botan test data file src/tests/data/modes/xts.vec, sections
[AES-128/XTS] and [AES-256/XTS], entries commented "IEEE 1619-2007 VECTOR n"
(raw.githubusercontent.com/randombit/botan, master, fetched 2026-08-26).  Botan's
"Nonce" field is the 16-byte little-endian encoding of the data unit sequence
number, i.e. exactly the specification's `bin(i, 128)`.

  multiple of 16 B : vectors 1, 2, 3, 15 (32 B), 4 and 19 (512 B, XTS-AES-128),
                     10 (512 B, XTS-AES-256)
  ciphertext steal : vectors 15 (17 B), 16 (18 B), 17 (19 B), 18 (20 B),
                     19 (520 B --- 32 full blocks plus 8 bytes)

The 512/520-byte plaintexts are the byte pattern 00..ff repeated twice (plus an
8-byte tail for the 520-byte case), so only their ciphertexts are embedded.

Anchor level: standard-vector for every check in this file, in both directions.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import (aes_decrypt, aes_encrypt, b2v, bin_, double_ocb, sl,
                    update_mask, v2b)

MASK128 = (1 << 128) - 1


# ---------------------------------------------------------------- REF
def ref_xts(key1, key2, seq, data, encrypt=True):
    """XTS-AES with ciphertext stealing, on byte strings, per IEEE 1619 / SP 800-38E."""
    tweak = b2v(aes_encrypt(key2, seq.to_bytes(16, 'little')))
    f = aes_encrypt if encrypt else aes_decrypt

    def tbc(x, t):                       # one XEX block operation under tweak value t
        return b2v(f(key1, v2b((x ^ t) & MASK128, 16))) ^ t

    m, s = divmod(len(data), 16)
    blk = lambda q: b2v(data[16 * q:16 * q + 16])
    out, t = b'', tweak
    if s == 0:
        for q in range(m):
            out += v2b(tbc(blk(q), t), 16)
            t = update_mask(t)
        return out
    for q in range(m - 1):
        out += v2b(tbc(blk(q), t), 16)
        t = update_mask(t)
    t_m1, t_m = t, update_mask(t)
    if encrypt:
        cc = v2b(tbc(blk(m - 1), t_m1), 16)
        c_last, cp = cc[:s], cc[s:]
        out += v2b(tbc(b2v(data[16 * m:] + cp), t_m), 16) + c_last
    else:
        pp = v2b(tbc(blk(m - 1), t_m), 16)
        p_last, cp = pp[:s], pp[s:]
        out += v2b(tbc(b2v(data[16 * m:] + cp), t_m1), 16) + p_last
    return out


# ---------------------------------------------------------------- the ACE XEX CC
class XexCC:
    """An ACE XEX Crypto Context, per <<ACE-XEX-XTS-modes>>."""

    def __init__(self, key1, key2, doubling=update_mask):
        self.key1, self.key2 = key1, key2
        self.mask = 0                     # State _Ready_: the mask field is zero
        self.encrypt = None
        self.doubling = doubling

    def setst(self, tweak_value, encrypt):
        """Form C ace.setst: mask <- INPUT, then mask <- enc_blk(key2, mask)."""
        self.mask = tweak_value & MASK128
        self.mask = b2v(aes_encrypt(self.key2, v2b(self.mask, 16)))
        self.encrypt = encrypt

    def clone(self):
        """ace.clone: an independent CR carrying a copy of the state."""
        c = XexCC(self.key1, self.key2, self.doubling)
        c.mask, c.encrypt = self.mask, self.encrypt
        return c

    def exec(self, inp):
        """Form A ace.exec: one block, then mask <- update_mask(mask)."""
        f = aes_encrypt if self.encrypt else aes_decrypt
        out = self.mask ^ b2v(f(self.key1, v2b((inp ^ self.mask) & MASK128, 16)))
        self.mask = self.doubling(self.mask)
        return out & MASK128


def ace_xex(key1, key2, seq, data, encrypt=True, doubling=update_mask):
    """The plain XEX sequence: only defined when the data unit is a multiple of b."""
    assert len(data) % 16 == 0
    cc = XexCC(key1, key2, doubling)
    cc.setst(bin_(seq, 128), encrypt)     # the tweak is bin(i, b)
    return b''.join(v2b(cc.exec(b2v(data[i:i + 16])), 16)
                    for i in range(0, len(data), 16))


def ace_xts(key1, key2, seq, data, encrypt=True, doubling=update_mask):
    """<<ACE-XTS-from-XEX>> implemented literally, stealing included."""
    m, s_bytes = divmod(len(data), 16)
    if s_bytes == 0:
        return ace_xex(key1, key2, seq, data, encrypt, doubling)
    s = 8 * s_bytes                       # the spec measures the partial block in bits
    cc = XexCC(key1, key2, doubling)
    cc.setst(bin_(seq, 128), encrypt)
    out = b''
    # 1. blocks 0 .. m-2, at mask indices 0 .. m-2
    for q in range(m - 1):
        out += v2b(cc.exec(b2v(data[16 * q:16 * q + 16])), 16)
    last_full = b2v(data[16 * (m - 1):16 * m])
    tail = b2v(data[16 * m:])             # the s-bit partial block
    if encrypt:
        # 2. P_{m-1} at mask index m-1, giving CC
        cc_val = cc.exec(last_full)
        # 3. C_m <- CC[s-1:0] and CP <- CC[b-1:s]
        c_last = sl(cc_val, s - 1, 0)
        cp = sl(cc_val, 127, s)
        # 4. CP @ P_m at mask index m, giving C_{m-1}
        c_m1 = cc.exec((cp << s) | tail)
        # 5. ... C_{m-1}, C_m, with C_m the final s bits
        out += v2b(c_m1, 16) + v2b(c_last, s_bytes)
    else:
        # 2. clone the CR; both are at mask index m-1
        clone = cc.clone()
        # 3. one discarded ace.exec advances the clone to index m
        clone.exec(0)
        # 4. C_{m-1} on the clone at mask index m, giving PP
        pp = clone.exec(last_full)
        # 5. P_m <- PP[s-1:0] and CP <- PP[b-1:s]
        p_last = sl(pp, s - 1, 0)
        cp = sl(pp, 127, s)
        # 6. CP @ C_m on the original, still at mask index m-1
        p_m1 = cc.exec((cp << s) | tail)
        out += v2b(p_m1, 16) + v2b(p_last, s_bytes)
        # 7. clear the clone
        del clone
    return out


# ---------------------------------------------------------------- vectors
_PATTERN = (bytes(range(256)) * 2).hex()

# (label, key1||key2, sequence-number encoding (little-endian, 16 B), plaintext, ciphertext)
IEEE1619 = [
    ("vector 1 (32 B, XTS-AES-128)",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"),
    ("vector 2 (32 B, XTS-AES-128)",
     "1111111111111111111111111111111122222222222222222222222222222222",
     "33333333330000000000000000000000",
     "4444444444444444444444444444444444444444444444444444444444444444",
     "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0"),
    ("vector 3 (32 B, XTS-AES-128)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
     "33333333330000000000000000000000",
     "4444444444444444444444444444444444444444444444444444444444444444",
     "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89"),
    ("vector 15 (32 B, XTS-AES-128)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "4444444444444444444444444444444444444444444444444444444444444444",
     "b01f86f8edc1863706fa8a4253e34f28af319de38334870f4dd1f94cbe9832f1"),
    ("vector 4 (512 B, XTS-AES-128)",
     "2718281828459045235360287471352631415926535897932384626433832795",
     "00000000000000000000000000000000", _PATTERN,
     "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c"
     "c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412"
     "328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce"
     "93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265"
     "5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8"
     "a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434"
     "1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c"
     "5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e"
     "94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc"
     "1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3"
     "e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344"
     "b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd"
     "74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752"
     "afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e"
     "bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d"
     "eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568"),
    ("vector 10 (512 B, XTS-AES-256)",
     "2718281828459045235360287471352662497757247093699959574966967627"
     "3141592653589793238462643383279502884197169399375105820974944592",
     "ff000000000000000000000000000000", _PATTERN,
     "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b"
     "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd"
     "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0"
     "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca"
     "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0"
     "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f"
     "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec"
     "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a"
     "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1"
     "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae"
     "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29"
     "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac"
     "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f"
     "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385"
     "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa"
     "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151"),
    ("vector 19 (512 B, XTS-AES-128)",
     "e0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
     "21436587a90000000000000000000000", _PATTERN,
     "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6"
     "8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc"
     "bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854"
     "9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177"
     "41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3"
     "9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4"
     "8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe"
     "41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d"
     "19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64"
     "a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272"
     "9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648"
     "346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394"
     "d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2"
     "cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a"
     "5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf"
     "92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3"),
]

# Ciphertext-stealing vectors: data unit not a multiple of 16 bytes.
IEEE1619_CTS = [
    ("vector 15 (17 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f10",
     "6c1625db4671522d3d7599601de7ca09ed"),
    ("vector 16 (18 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f1011",
     "d069444b7a7e0cab09e24447d24deb1fedbf"),
    ("vector 17 (19 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f101112",
     "e5df1351c0544ba1350b3363cd8ef4beedbf9d"),
    ("vector 18 (20 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f10111213",
     "9d84c813f719aa2c7be3f66171c7c5c2edbf9dac"),
    ("vector 19 (520 B, 32 blocks + 8 B)",
     "e0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
     "21436587a90000000000000000000000",
     _PATTERN + "0001020304050607",
     "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6"
     "8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc"
     "bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854"
     "9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177"
     "41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3"
     "9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4"
     "8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe"
     "41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d"
     "19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64"
     "a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272"
     "9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648"
     "346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394"
     "d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2"
     "cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a"
     "5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf"
     "92cefc151b5cc1611a167893819b63fb37ec662bc0fc907db74a94468a55a7bc"
     "8a6b18e86de60290"),
]


def split_keys(k):
    kb = bytes.fromhex(k)
    h = len(kb) // 2
    return kb[:h], kb[h:]


def seq_of(nonce_hex):
    """Botan's Nonce is bin(i, 128): the little-endian encoding of the sequence number."""
    return int.from_bytes(bytes.fromhex(nonce_hex), 'little')


# ---------------------------------------------------------------- run
ok = True
neg_fired = False


def chk(label, got, want):
    global ok
    good = got == want
    ok = ok and good
    print(f"  {label:<56} {'PASS' if good else 'FAIL'}")
    if not good:
        print(f"      got  {got[:64]}{'...' if len(got) > 64 else ''}")
        print(f"      want {want[:64]}{'...' if len(want) > 64 else ''}")
    return good


print("== (a) REF: byte-string XTS against IEEE 1619-2007 / SP 800-38E")
for name, k, nonce, p, c in IEEE1619 + IEEE1619_CTS:
    k1, k2 = split_keys(k)
    i = seq_of(nonce)
    chk(name + " encrypt", ref_xts(k1, k2, i, bytes.fromhex(p)).hex(), c)
    chk(name + " decrypt", ref_xts(k1, k2, i, bytes.fromhex(c), False).hex(), p)

print("\n== (b) ACE XEX model, full-block path (tweak = bin(i, 128))")
for name, k, nonce, p, c in IEEE1619:
    k1, k2 = split_keys(k)
    i = seq_of(nonce)
    chk(name + " encrypt", ace_xex(k1, k2, i, bytes.fromhex(p)).hex(), c)
    chk(name + " decrypt", ace_xex(k1, k2, i, bytes.fromhex(c), False).hex(), p)

print("\n== (c) <<ACE-XTS-from-XEX>> ciphertext stealing, taken literally")
print("   encryption: reordered last two blocks, mask indices m-1 then m")
print("   decryption: ace.clone + one discarded ace.exec; C_{m-1} at index m on")
print("               the clone, CP @ C_m at index m-1 on the original")
for name, k, nonce, p, c in IEEE1619_CTS:
    k1, k2 = split_keys(k)
    i = seq_of(nonce)
    chk(name + " encrypt", ace_xts(k1, k2, i, bytes.fromhex(p)).hex(), c)
    chk(name + " decrypt", ace_xts(k1, k2, i, bytes.fromhex(c), False).hex(), p)

print("\n== The stealing procedure also agrees with REF on the full-block path")
for name, k, nonce, p, c in IEEE1619:
    k1, k2 = split_keys(k)
    i = seq_of(nonce)
    ok = ok and ace_xts(k1, k2, i, bytes.fromhex(p)).hex() == c
chk("s = 0 falls back to the plain XEX sequence (all full-block vectors)",
    "ok", "ok" if ok else "broken")

print("\n== Negative control: OCB3's big-endian double() instead of update_mask")
print("KAT-EXPECT-FAIL: NEG OCB doubling")
print(f"\n   {'vector':<40} {'update_mask':<14} {'NEG OCB doubling'}")
for name, k, nonce, p, c in IEEE1619[:4] + IEEE1619_CTS[:4]:
    k1, k2 = split_keys(k)
    i = seq_of(nonce)
    good = ace_xts(k1, k2, i, bytes.fromhex(p)).hex() == c
    neg_wrong = ace_xts(k1, k2, i, bytes.fromhex(p),
                        doubling=double_ocb).hex() != c
    ok = ok and good
    neg_fired = neg_fired or neg_wrong
    print(f"   {name:<40} {'PASS' if good else 'FAIL':<14} "
          f"{'FAIL' if neg_wrong else 'PASS (does not discriminate)'}")

print("\n== Clone independence: the discarded ace.exec must not advance the original")
k1, k2 = split_keys(IEEE1619_CTS[0][1])
cc = XexCC(k1, k2)
cc.setst(bin_(seq_of(IEEE1619_CTS[0][2]), 128), False)
before = cc.mask
clone = cc.clone()
clone.exec(0)
clone.exec(0)
same = cc.mask == before
ok = ok and same
print(f"  {'original mask unchanged by two ace.exec on the clone':<56} "
      f"{'PASS' if same else 'FAIL'}")
advanced = clone.mask == update_mask(update_mask(before))
ok = ok and advanced
print(f"  {'clone mask advanced by exactly two update_mask steps':<56} "
      f"{'PASS' if advanced else 'FAIL'}")

print("\n== Round-trip over many lengths, including every partial-block size")
k1, k2 = split_keys(IEEE1619[4][1])
rt = True
for length in list(range(16, 80)) + [128, 129, 255, 256]:
    data = bytes((7 * n + 1) & 0xFF for n in range(length))
    for i in (0, 1, 0x123456789A):
        ct = ace_xts(k1, k2, i, data)
        rt = rt and ct == ref_xts(k1, k2, i, data)
        rt = rt and ace_xts(k1, k2, i, ct, False) == data
        rt = rt and ref_xts(k1, k2, i, ct, False) == data
ok = ok and rt
print(f"  {'ACE == REF and round-trips, lengths 16..79, 128, 129, 255, 256':<56} "
      f"{'PASS' if rt else 'FAIL'}")

if not neg_fired:
    print("\nnegative control did not fire: the doubling test is not discriminating")
    ok = False

print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
