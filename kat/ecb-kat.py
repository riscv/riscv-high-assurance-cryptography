#!/usr/bin/env python3
"""ECB mode (<<ACE-ECB-mode>> in src/ace-ISA-algorithms.adoc) against FIPS 197,
SP 800-38A F.1 and GB/T 32907-2016 (SM4).

Three things are checked.

REF   A plain byte-string ECB reference: split the message into b-bit blocks in
      address order and apply enc_blk/dec_blk to each.  Anchored directly on the
      published vectors.

ACE   The specification's own formulation.  <<ACE-ECB-mode>> says that when
      `ACELEN` > `b` the operation proceeds

          foreach(i from 0 to ACELEN-b by b) {
            OUTPUT[i+b-1:i] <- enc_blk(key, INPUT[i+b-1:i]) }

      i.e. *from the blocks in the least significant positions to the most
      significant positions*.  Under <<ACE-Notation>> byte j of a byte string sits
      at bits [8j+7:8j], so the least significant block of the ACE value is the
      block at the lowest address, and the two views must agree.  The check builds
      a genuine 4-block ACE value with cat() (left operand more significant, so the
      blocks are listed in reverse address order), runs the spec loop over bit
      slices, and compares the result to REF on the byte-string view.

NEG   A negative control that processes the blocks most-significant-first, which
      reverses the block order of the byte string.  It must disagree with REF.

SM4 is included because ACE names it as an instantiable block cipher, and because
it exercises the value/byte-string mapping with a cipher whose own specification is
written big-endian.

Vectors and provenance
----------------------
* FIPS 197 Appendix C.1/C.2/C.3 -- single-block AES-128/192/256.  (Also re-checked
  inside kat/common.py's self-test; repeated here so this file stands alone.)
* SP 800-38A Appendix F.1.1/F.1.2 (ECB-AES128), F.1.3/F.1.4 (ECB-AES192),
  F.1.5/F.1.6 (ECB-AES256) -- the four-block message.  These twelve output blocks
  were additionally recomputed with the independent AES in kat/common.py, whose
  own anchor is FIPS 197.
* SM4 S-box: transcribed from the OpenSSL SM4 reference implementation,
  crypto/sm4/sm4.c, SM4_S[256] (raw.githubusercontent.com/openssl/openssl,
  master, fetched 2026-08-26).  The table is only a starting point: the
  implementation built on it is anchored below on the GB/T standard vectors.
* GB/T 32907-2016 Example 1 (single block, key = plaintext =
  0123456789abcdeffedcba9876543210 -> 681edf34d206965e86b3e94f536e4246).  Also
  reproduced in the Linux kernel crypto/testmgr.h sm4_tv_template as
  "GB/T 32907-2016 Example 1".
* GB/T 32907-2016 Example 2, the full 1,000,000-round iteration vector
  (-> 595298c7c6fd271f0402f804c33d3f66).  This runs in about 30 s in pure Python,
  which fits the time budget, so the vector is used whole rather than truncated.
  The intermediate values at rounds 100/1000/10000 are recorded alongside it as
  reference-implementation checkpoints (they are not published constants, and are
  labelled as such); they exist only so that a failure can be localized.
* SM4 multi-block ECB: GB/T 32907-2016 A.2.1.1 and A.2.1.2, as reproduced in the
  Linux kernel crypto/testmgr.h sm4_tv_template.

Coverage note: SM4 decryption is checked only by round-tripping and by the
reverse-round-key inversion of the published encryption vectors; no independent
published SM4 decryption vector is used.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import aes_decrypt, aes_encrypt, b2v, cat, sl, v2b

# ---------------------------------------------------------------- SM4
# S-box: OpenSSL crypto/sm4/sm4.c, SM4_S[256].
SM4_SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948")
SM4_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _sm4_tau(a):
    return ((SM4_SBOX[(a >> 24) & 0xFF] << 24) | (SM4_SBOX[(a >> 16) & 0xFF] << 16)
            | (SM4_SBOX[(a >> 8) & 0xFF] << 8) | SM4_SBOX[a & 0xFF])


def _sm4_T(a):
    b = _sm4_tau(a)
    return b ^ _rotl32(b, 2) ^ _rotl32(b, 10) ^ _rotl32(b, 18) ^ _rotl32(b, 24)


def _sm4_Tp(a):
    b = _sm4_tau(a)
    return b ^ _rotl32(b, 13) ^ _rotl32(b, 23)


def sm4_key_schedule(key):
    """The 32 round keys of GB/T 32907-2016 5.2 (words big-endian, as the standard writes them)."""
    mk = [int.from_bytes(key[4 * i:4 * i + 4], 'big') for i in range(4)]
    k = [mk[i] ^ SM4_FK[i] for i in range(4)]
    rks = []
    for i in range(32):
        ck = 0
        for j in range(4):
            ck = (ck << 8) | ((28 * i + 7 * j) & 0xFF)
        k.append(k[i] ^ _sm4_Tp(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck))
        rks.append(k[i + 4])
    return rks


def _sm4_block(rks, blk):
    x = [int.from_bytes(blk[4 * i:4 * i + 4], 'big') for i in range(4)]
    for i in range(32):
        x.append(x[i] ^ _sm4_T(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rks[i]))
    return b''.join(x[35 - i].to_bytes(4, 'big') for i in range(4))


def sm4_encrypt(key, blk):
    return _sm4_block(sm4_key_schedule(key), blk)


def sm4_decrypt(key, blk):
    """Decryption is the same round function with the round keys reversed (GB/T 32907-2016 5.4)."""
    return _sm4_block(list(reversed(sm4_key_schedule(key))), blk)


# ---------------------------------------------------------------- REF and ACE models
def ref_ecb(enc, key, data, bsz=16):
    """Byte-string ECB: apply the block function to each b-bit block in address order."""
    return b''.join(enc(key, data[i:i + bsz]) for i in range(0, len(data), bsz))


def ace_ecb(enc, key, inp, acelen, b=128):
    """State _Encrypt_/_Decrypt_ of <<ACE-ECB-mode>>, on ACE values.

    Literally the specification's loop:

        foreach(i from 0 to ACELEN-b by b) {
          OUTPUT[i+b-1:i] <- enc_blk(key, INPUT[i+b-1:i]) }

    Each block is taken from, and returned to, the same bit position, so the
    result is independent of the order in which the loop visits them.  What the
    loop does fix is *which* bits form a block, and that is what the byte-string
    comparison in this file exercises.
    """
    out = 0
    for i in range(0, acelen, b):
        blk = sl(inp, i + b - 1, i)
        out |= b2v(enc(key, v2b(blk, b // 8))) << i
    return out


def ace_ecb_bigendian_misread(enc, key, inp, acelen, b=128):
    """Negative control: the big-endian misreading of <<ACE-Notation>>.

    ECB treats every block independently, so getting the *order of the loop*
    wrong is unobservable --- the specification's "least significant positions
    first" phrasing has no effect on the result by itself.  What is observable,
    and what that phrasing exists to pin down, is the correspondence between block
    positions in the ACE value and block offsets in the byte string.  This control
    takes the opposite correspondence, mapping the most significant block of the
    value to the first block of the string, and must disagree with the vector.
    """
    nblk = acelen // b
    out = 0
    for i in range(0, acelen, b):
        blk = sl(inp, i + b - 1, i)
        res = b2v(enc(key, v2b(blk, b // 8)))
        out |= res << ((nblk - 1) * b - i)
    return out


# ---------------------------------------------------------------- vectors
# FIPS 197 Appendix C.
FIPS197 = [
    ("C.1 AES-128", "000102030405060708090a0b0c0d0e0f",
     "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("C.2 AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617",
     "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("C.3 AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
]

# SP 800-38A Appendix F.1: the same four-block plaintext under three key sizes.
SP38A_PT = ("6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710")
SP38A_F1 = [
    ("F.1.1/F.1.2 ECB-AES128", "2b7e151628aed2a6abf7158809cf4f3c",
     "3ad77bb40d7a3660a89ecaf32466ef97"
     "f5d3d58503b9699de785895a96fdbaaf"
     "43b1cd7f598ece23881b00e3ed030688"
     "7b0c785e27e8ad3f8223207104725dd4"),
    ("F.1.3/F.1.4 ECB-AES192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
     "bd334f1d6e45f25ff712a214571fa5cc"
     "974104846d0ad3ad7734ecb3ecee4eef"
     "ef7afd2270e2e60adce0ba2face6444e"
     "9a4b41ba738d6c72fb16691603c18e0e"),
    ("F.1.5/F.1.6 ECB-AES256",
     "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "f3eed1bdb5d2a03c064b5a7e3db181f8"
     "591ccb10d410ed26dc5ba74a31362870"
     "b6ed21b99ca6f4f9f153e7b1beafed1d"
     "23304b7a39f9f3ff067d8d8f9e24ecc7"),
]

# GB/T 32907-2016.
SM4_KEY1 = "0123456789abcdeffedcba9876543210"
SM4_EX1_CT = "681edf34d206965e86b3e94f536e4246"
# GB/T 32907-2016 Example 2: encrypt the plaintext under its own key 1e6 times.
SM4_EX2_ROUNDS = 1000000
SM4_EX2_CT = "595298c7c6fd271f0402f804c33d3f66"
# Reference-implementation checkpoints, for localizing a failure only.
SM4_EX2_CHECKPOINTS = {
    100: "8da24cb1008bd3271aa3b60105a7d5fd",
    1000: "d735e91cc5689cf312bcc1efb740e813",
    10000: "2d8bfc27381c68ecb316320ee72ba074",
}
SM4_MULTI = [
    ("A.2.1.1 SM4-ECB", SM4_KEY1,
     "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb",
     "5ec8143de509cff7b5179f8f474b86192f1d305a7fb17df985f81c8482192304"),
    ("A.2.1.2 SM4-ECB", "fedcba98765432100123456789abcdef",
     "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb",
     "c5876897e4a59bbba72a10c83872245b12dd90bc2d200692b529a4155ac9e600"),
]

# ---------------------------------------------------------------- run
ok = True
neg_fired = False


def chk(label, got, want, column=None):
    global ok
    good = got == want
    ok = ok and good
    print(f"  {label:<42} {'PASS' if good else 'FAIL'}")
    if not good:
        print(f"      got  {got}")
        print(f"      want {want}")
    return good


print("== FIPS 197 Appendix C: single-block AES (REF and ACE, b = ACELEN)")
for name, k, p, c in FIPS197:
    key, pt, ct = bytes.fromhex(k), bytes.fromhex(p), bytes.fromhex(c)
    chk(name + " encrypt", aes_encrypt(key, pt).hex(), c)
    chk(name + " decrypt", aes_decrypt(key, ct).hex(), p)
    # the ACE model with ACELEN = b must be the bare block function
    chk(name + " ACE model ACELEN=b",
        v2b(ace_ecb(aes_encrypt, key, b2v(pt), 128), 16).hex(), c)

print("\n== SP 800-38A F.1: four-block ECB, REF (byte string)")
pt = bytes.fromhex(SP38A_PT)
for name, k, c in SP38A_F1:
    key = bytes.fromhex(k)
    chk(name + " encrypt", ref_ecb(aes_encrypt, key, pt).hex(), c)
    chk(name + " decrypt", ref_ecb(aes_decrypt, key, bytes.fromhex(c)).hex(), SP38A_PT)

print("\n== ACE multi-block rule: ACELEN = 4b, least significant block position first")
print("   (the 4-block operand is built with cat(); its LEFT part is the most")
print("    significant, i.e. the LAST block of the byte string)")
print("\nKAT-EXPECT-FAIL: NEG big-endian misread")
print(f"\n   {'vector':<32} {'ACE spec order':<16} {'NEG big-endian misread'}")
for name, k, c in SP38A_F1:
    key = bytes.fromhex(k)
    blocks = [pt[i:i + 16] for i in range(0, 64, 16)]
    # cat() takes the most significant part first: reverse the address order.
    inp = cat(*[(b2v(b), 128) for b in reversed(blocks)])
    spec = v2b(ace_ecb(aes_encrypt, key, inp, 512), 64).hex()
    neg = v2b(ace_ecb_bigendian_misread(aes_encrypt, key, inp, 512), 64).hex()
    good_spec = spec == c
    good_neg = neg != c                      # the control must NOT reproduce the vector
    ok = ok and good_spec
    neg_fired = neg_fired or good_neg
    print(f"   {name:<32} {'PASS' if good_spec else 'FAIL':<16} "
          f"{'FAIL' if good_neg else 'PASS (does not discriminate)'}")
    # and the decryption direction, spec order only
    dec = v2b(ace_ecb(aes_decrypt, key,
                      cat(*[(b2v(bytes.fromhex(c)[i:i + 16]), 128)
                            for i in range(48, -1, -16)]), 512), 64).hex()
    ok = ok and dec == SP38A_PT

print("\n== SM4 (GB/T 32907-2016)")
k1 = bytes.fromhex(SM4_KEY1)
chk("Example 1 single block", sm4_encrypt(k1, k1).hex(), SM4_EX1_CT)
chk("Example 1 decrypt", sm4_decrypt(k1, bytes.fromhex(SM4_EX1_CT)).hex(), SM4_KEY1)
rks = sm4_key_schedule(k1)
x = k1
for r in range(1, SM4_EX2_ROUNDS + 1):
    x = _sm4_block(rks, x)
    if r in SM4_EX2_CHECKPOINTS:
        chk(f"Example 2 round {r} [ref-impl checkpoint]", x.hex(),
            SM4_EX2_CHECKPOINTS[r])
chk(f"Example 2 full {SM4_EX2_ROUNDS} rounds", x.hex(), SM4_EX2_CT)
for name, k, p, c in SM4_MULTI:
    key = bytes.fromhex(k)
    chk(name + " REF", ref_ecb(sm4_encrypt, key, bytes.fromhex(p)).hex(), c)
    chk(name + " REF decrypt", ref_ecb(sm4_decrypt, key, bytes.fromhex(c)).hex(), p)
    blocks = [bytes.fromhex(p)[i:i + 16] for i in range(0, len(p) // 2, 16)]
    inp = cat(*[(b2v(b), 128) for b in reversed(blocks)])
    chk(name + " ACE model", v2b(ace_ecb(sm4_encrypt, key, inp, 128 * len(blocks)),
                                 16 * len(blocks)).hex(), c)

if not neg_fired:
    print("\nnegative control did not fire: the block-order test is not discriminating")
    ok = False

print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
