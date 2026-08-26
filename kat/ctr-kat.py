#!/usr/bin/env python3
"""CTR and XCTR keystream generation (<<ACE-keystream-modes>> in
src/ace-ISA-algorithms.adoc) against SP 800-38A F.5 and the HCTR2 reference vectors.

The specification keeps the keystream state as two separate fields, `IV` of `n`
bits and `ctr` of `j` bits, and forms the block fed to the keystream function as

    CTR  :  tmp <- keystream_block(bswap(ctr) @ IV)      with b = n + j
    XCTR :  tmp <- keystream_block(IV xor ctr)           with b = n = j

Under <<ACE-Notation>> the LEFT operand of `@` occupies the more significant bits,
and byte i of a byte string lives at bits [8i+7:8i].  So `bswap(ctr) @ IV` puts the
IV in the *first* bytes of the counter block and the counter, big-endian, in the
*trailing* bytes --- which is what SP 800-38A and GCM require.  The `bswap` is
load-bearing: without it the counter would be little-endian in those bytes.

Models
------
REF-CTR   SP 800-38A written directly on byte strings: counter block =
          nonce || big-endian(ctr, j bits), incremented as an integer mod 2^j.
REF-XCTR  The HCTR2 paper's XCTR on byte strings: E_K(IV xor LE(i, 128)), the
          counter little-endian and full width, numbered from 1.
ACE       The two formulas above evaluated on ACE values, with tick_ctr() and the
          Form B "set initial counter" operation (`ctr <- lsb_j(Xs)`).
NEG       Negative control: the same CTR formula with the `bswap` dropped, i.e.
          a little-endian counter in the trailing bytes.  It must fail SP 800-38A.

Vectors and provenance
----------------------
* SP 800-38A Appendix F.5.1 (CTR-AES128), F.5.3 (CTR-AES192), F.5.5 (CTR-AES256):
  initial counter block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff over the four standard
  plaintext blocks.  Transcribed from the Linux kernel crypto/testmgr.h,
  aes_ctr_tv_template, entries commented "From NIST Special Publication 800-38A,
  Appendix F.5" (raw.githubusercontent.com/torvalds/linux, master, fetched
  2026-08-26).
* XCTR: google/hctr2 test_vectors/ours/XCTR/XCTR_AES{128,256}.json
  (raw.githubusercontent.com/google/hctr2, main, fetched 2026-08-26).  These are
  the reference vectors of the HCTR2 paper's own implementation, so XCTR here is
  anchored on a reference implementation, not on a standards body's vectors ---
  no NIST XCTR vectors exist.

Anchor levels: CTR is standard-vector anchored for the full-block-counter case
(n = 0, j = 128), and reference-consistency anchored for the nonce/counter splits
(no published vector exercises them; REF-CTR, itself anchored, is the oracle).
XCTR is reference-implementation anchored.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import aes_encrypt, b2v, bin_, bswap, bxor, cat, v2b

MASK128 = (1 << 128) - 1


# ---------------------------------------------------------------- REF models
def ref_ctr(key, nonce, j, ctr0, msg):
    """SP 800-38A CTR: block = nonce || big-endian(ctr, j/8 bytes)."""
    out, ctr = b'', ctr0
    for i in range(0, len(msg), 16):
        ks = aes_encrypt(key, nonce + ctr.to_bytes(j // 8, 'big'))
        chunk = msg[i:i + 16]
        out += bxor(ks[:len(chunk)], chunk)
        ctr = (ctr + 1) % (1 << j)
    return out


def ref_xctr(key, iv, ctr0, msg):
    """HCTR2's XCTR: block = IV xor little-endian(ctr, 16 bytes), counter from 1."""
    out, ctr = b'', ctr0
    for i in range(0, len(msg), 16):
        ks = aes_encrypt(key, bxor(iv, ctr.to_bytes(16, 'little')))
        chunk = msg[i:i + 16]
        out += bxor(ks[:len(chunk)], chunk)
        ctr = (ctr + 1) % (1 << 128)
    return out


# ---------------------------------------------------------------- the ACE model
class KeystreamCC:
    """A CTR/XCTR CC as <<ACE-keystream-modes>> describes it, on ACE values.

    In State _Ready_ both `IV` and `ctr` are zero.  A Form C ace.setst sets the IV
    (`set_iv`), a Form B ace.setst sets the initial counter (`set_ctr`), and a
    Form C ace.exec emits one keystream block (`exec`).
    """

    def __init__(self, key, n, j, mode='ctr', variant='spec'):
        self.key, self.n, self.j, self.mode = key, n, j, mode
        self.variant = variant
        self.IV = 0
        self.ctr = 0
        if mode == 'ctr':
            assert n + j == 128, "CTR requires b = n + j"
        else:
            assert n == j == 128, "XCTR requires b = n = j"

    def set_iv(self, value, acelen=None):
        """Form C ace.setst: IV <- INPUT, keeping only the n least significant bits."""
        self.IV = value & ((1 << self.n) - 1)

    def set_ctr(self, xs):
        """Form B ace.setst, #ace_state_set_aux_value: ctr <- lsb_j(Xs)."""
        self.ctr = xs & ((1 << self.j) - 1)

    def _tick(self):
        self.ctr = (self.ctr + 1) % (1 << self.j)

    def exec(self):
        """One Form C ace.exec: emit a b-bit keystream block and tick the counter."""
        if self.mode == 'ctr':
            if self.variant == 'spec':
                blk = cat((bswap(self.ctr, self.j // 8), self.j), (self.IV, self.n))
            else:                       # NEG: the same layout without the bswap
                blk = cat((bin_(self.ctr, self.j), self.j), (self.IV, self.n))
        else:
            blk = self.IV ^ self.ctr
        self._tick()
        return b2v(aes_encrypt(self.key, v2b(blk, 16)))

    def keystream(self, nbytes):
        out = b''
        while len(out) < nbytes:
            out += v2b(self.exec(), 16)
        return out[:nbytes]


def ace_ctr(key, iv_value, n, j, msg, ctr0=0, variant='spec'):
    cc = KeystreamCC(key, n, j, 'ctr', variant)
    cc.set_iv(iv_value)
    cc.set_ctr(ctr0)
    return bxor(cc.keystream(len(msg)), msg)


def ace_xctr(key, iv_value, msg, ctr0=0):
    cc = KeystreamCC(key, 128, 128, 'xctr')
    cc.set_iv(iv_value)
    cc.set_ctr(ctr0)
    return bxor(cc.keystream(len(msg)), msg)


# ---------------------------------------------------------------- vectors
SP38A_PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                         "ae2d8a571e03ac9c9eb76fac45af8e51"
                         "30c81c46a35ce411e5fbc1191a0a52ef"
                         "f69f2445df4f9b17ad2b417be66c3710")
SP38A_ICB = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
SP38A_F5 = [
    ("F.5.1 CTR-AES128", "2b7e151628aed2a6abf7158809cf4f3c",
     "874d6191b620e3261bef6864990db6ce"
     "9806f66b7970fdff8617187bb9fffdff"
     "5ae4df3edbd5d35e5b4f09020db03eab"
     "1e031dda2fbe03d1792170a0f3009cee"),
    ("F.5.3 CTR-AES192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
     "1abc932417521ca24f2b0459fe7e6e0b"
     "090339ec0aa6faefd5ccc2c6f4ce8e94"
     "1e36b26bd1ebc670d1bd1d665620abf7"
     "4f78a7f6d29809585a97daec58c6b050"),
    ("F.5.5 CTR-AES256",
     "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "601ec313775789a5b7a7f504bbf3d228"
     "f443e3ca4d62b59aca84e990cacaf5c5"
     "2b0930daa23de94ce87017ba2d84988d"
     "dfc9c58db67aada613c2dd08457941a6"),
]

# google/hctr2 XCTR reference vectors: (label, key, nonce, plaintext, ciphertext)
HCTR2_XCTR = [
    ("XCTR-AES128 len 16", "bc1b120c3f18cc1f5a1dab81a8687c63",
     "22c1dd250b18cba54ada150773d98810",
     "246e64c615269cda2a4b5712ff7cd6b5",
     "d6478d5892b284f9b7ee0d98a1394d8f"),
    ("XCTR-AES128 len 31", "4403bf4c30f0a7d6bd54bb668ea60e8a",
     "e6f726df8c3caa88cec1bd433b0962ad",
     "3ce346b98f9d3f8deff253ab24e22908f87e1da66d867d60976393297194b4",
     "d4a3c6b8c16f701a520ced4caf5156234845071034c5ba71e5f81ed8cba6e7"),
    ("XCTR-AES256 len 16",
     "afd91414d5dbc9ce765c5abf43052924c41368cce837bdb94120f55348d0a2d6",
     "a7b400087910aef502bf85b2694cc604",
     "ac6aa80cb084bf4cae9420587e009389",
     "d5aae2e9864c954edeb615cbdc1f1338"),
    ("XCTR-AES256 len 17",
     "ede38be71c17bf4a02e2fc76acf53c005ddcfc83eb45b4cb596260ec699c1645",
     "e40e2b90d2fa942e10e5642b972815c7",
     "e653ff600ec451e4934de555c5d9ad4852",
     "ba2528f5cf319180da2b955f20cbfb9fc6"),
    ("XCTR-AES256 len 48",
     "a12f4ddefea1ffa873dde3e295fcea9cd080420cb8433e9939380a8ce8453a7b",
     "32c46fb11443d187e26f5a5802367e2a",
     "9e5c1ef1d67d0957184855da7d44f96daccd59bb10a29467d16ffe6b4a11e804"
     "09264f8d5da17b42f94b66763812fefe",
     "42bca764159a04712c5f94ba893aadbc87b3f4094f570618dc8420f76485ca3b"
     "abe6335634605d4b2e1613d477de2d2b"),
]

# ---------------------------------------------------------------- run
ok = True
neg_fired = False


def chk(label, got, want):
    global ok
    good = got == want
    ok = ok and good
    print(f"  {label:<52} {'PASS' if good else 'FAIL'}")
    if not good:
        print(f"      got  {got}")
        print(f"      want {want}")
    return good


print("== SP 800-38A F.5: REF-CTR implements the standard")
icb = int.from_bytes(SP38A_ICB, 'big')       # the whole block is the counter: n=0, j=128
for name, k, c in SP38A_F5:
    key = bytes.fromhex(k)
    chk(name + " REF", ref_ctr(key, b'', 128, icb, SP38A_PT).hex(), c)

print("\n== The ACE formula keystream_block(bswap(ctr) @ IV), n = 0, j = 128")
print("   (with no IV the whole counter block is bswap(ctr); the counter value is")
print("    the integer whose big-endian encoding is the standard's initial block)")
for name, k, c in SP38A_F5:
    key = bytes.fromhex(k)
    chk(name + " ACE", ace_ctr(key, 0, 0, 128, SP38A_PT, ctr0=icb).hex(), c)

print("\n== Negative control: the same formula with bswap dropped")
print("KAT-EXPECT-FAIL: NEG little-endian counter")
print(f"\n   {'vector':<26} {'ACE (bswap)':<14} {'NEG little-endian counter'}")
for name, k, c in SP38A_F5:
    key = bytes.fromhex(k)
    good = ace_ctr(key, 0, 0, 128, SP38A_PT, ctr0=icb).hex() == c
    neg_wrong = ace_ctr(key, 0, 0, 128, SP38A_PT, ctr0=icb, variant='neg').hex() != c
    ok = ok and good
    neg_fired = neg_fired or neg_wrong
    print(f"   {name:<26} {'PASS' if good else 'FAIL':<14} "
          f"{'FAIL' if neg_wrong else 'PASS (does not discriminate)'}")

print("\n== Nonce/counter splits: ACE vs REF-CTR [reference-consistency only]")
print("   b = n + j, IV in the first n/8 bytes, counter big-endian in the last j/8")
key = bytes.fromhex(SP38A_F5[0][1])
for n, j in ((96, 32), (64, 64), (120, 8), (32, 96), (112, 16)):
    nonce = bytes(range(1, n // 8 + 1))
    msg = bytes(range(80))
    for ctr0 in (0, 1, 7, (1 << j) - 2):     # the last one also exercises wraparound
        r = ref_ctr(key, nonce, j, ctr0, msg)
        a = ace_ctr(key, b2v(nonce), n, j, msg, ctr0=ctr0)
        ok = ok and r == a
    chk(f"n = {n:3d}, j = {j:3d}  (4 starting counters, incl. wrap)",
        ace_ctr(key, b2v(nonce), n, j, msg, ctr0=0).hex(),
        ref_ctr(key, nonce, j, 0, msg).hex())

print("\n== Form B set initial counter: ctr <- lsb_j(Xs)")
print("   resume F.5.1 at block 2 and reproduce the standard's own tail")
key = bytes.fromhex(SP38A_F5[0][1])
tail_ct = SP38A_F5[0][2][2 * 32:]            # ciphertext blocks 2 and 3
cc = KeystreamCC(key, 0, 128, 'ctr')
cc.set_iv(0)
cc.set_ctr(icb + 2)                          # Form B: jump into the stream
resumed = bxor(cc.keystream(32), SP38A_PT[32:]).hex()
chk("F.5.1 blocks 2..3 via Form B", resumed, tail_ct)
# and lsb_j really truncates: setting ctr with a wider Xs keeps only j bits
cc2 = KeystreamCC(key, 96, 32, 'ctr')
cc2.set_iv(b2v(bytes(range(1, 13))))
cc2.set_ctr((0xdeadbeef << 32) | 5)          # only the low 32 bits may survive
chk("lsb_j truncation of Xs",
     bxor(cc2.keystream(32), bytes(32)).hex(),
     ref_ctr(key, bytes(range(1, 13)), 32, 5, bytes(32)).hex())

print("\n== XCTR [reference-implementation anchor: google/hctr2]")
print("   HCTR2 numbers the counter from 1, while an ACE CC leaves State _Ready_")
print("   with ctr = 0, so the Form B operation supplies the initial counter 1.")
for name, k, iv, p, c in HCTR2_XCTR:
    key, nonce = bytes.fromhex(k), bytes.fromhex(iv)
    pt, ct = bytes.fromhex(p), bytes.fromhex(c)
    chk(name + " REF", ref_xctr(key, nonce, 1, pt).hex(), c)
    chk(name + " ACE (Form B ctr <- 1)", ace_xctr(key, b2v(nonce), pt, ctr0=1).hex(), c)
    chk(name + " ACE decrypt round-trip",
        ace_xctr(key, b2v(nonce), ct, ctr0=1).hex(), p)

print("\n== XCTR/CTR mutual consistency and separation")
key = bytes.fromhex(SP38A_F5[0][1])
iv = bytes(range(16))
msg = bytes(range(64))
chk("REF-XCTR == ACE-XCTR over 4 blocks, ctr from 0",
    ref_xctr(key, iv, 0, msg).hex(), ace_xctr(key, b2v(iv), msg, ctr0=0).hex())
# the ACE default start (ctr = 0) must differ from HCTR2's (ctr = 1): the Form B
# step above is necessary, not decorative.
differs = ace_xctr(key, b2v(iv), msg, 0) != ace_xctr(key, b2v(iv), msg, 1)
ok = ok and differs
print(f"  {'ctr=0 and ctr=1 XCTR streams differ':<52} {'PASS' if differs else 'FAIL'}")
# CTR and XCTR must not coincide, or the specification's distinction is vacuous
nonce = bytes(range(1, 13))
differs = (ace_ctr(key, b2v(nonce), 96, 32, msg)
           != ace_xctr(key, b2v(nonce + bytes(4)), msg))
ok = ok and differs
print(f"  {'CTR and XCTR produce different keystreams':<52} "
      f"{'PASS' if differs else 'FAIL'}")

if not neg_fired:
    print("\nnegative control did not fire: the bswap test is not discriminating")
    ok = False

print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
