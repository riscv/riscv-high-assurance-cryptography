#!/usr/bin/env python3
"""CMAC known-answer test: the ACE specification text against SP 800-38B / RFC 4493.

Two independent implementations are checked against the published vectors:

  REF   SP 800-38B / RFC 4493 written directly on byte strings, with the
        subkey doubling over the big-endian string view as the standard
        specifies.
  ACE   the state machine of <<ACE-CMAC-mode>> (src/ace-ISA-algorithms.adoc),
        implemented formula-by-formula in the ACE value model of
        src/ace-notation.adoc (byte i of a string lives at bits [8i+7:8i];
        the left operand of @ is more significant).  gen_subkeys uses
        `double`, the OCB3 doubling of <<ACE-OCB-mode>>.

Vectors and provenance
  * RFC 4493 section 4 (identical to SP 800-38B Appendix D.1), AES-128:
    subkey generation anchors (AES-128(K,0), K1, K2) and examples 1-4 with
    Mlen = 0, 16, 40, 64 bytes.
  * NIST "CMAC Mode for Authentication" example file (the SP 800-38B
    example set, csrc.nist.gov .../examples/AES_CMAC.pdf), CMAC-AES192 and
    CMAC-AES256 examples 1-4 with Mlen = 0, 16, 20, 64 bytes, including
    their published L, K1 and K2 values.
    The AES-128 Mlen = 20 example from the same file is included too, so
    every key size exercises a partial final block.

Checks performed
  * REF vs published tag, and ACE vs published tag, for all 13 examples.
  * The published subkey anchors (L, K1, K2) against ACE gen_subkeys, for
    all three key sizes.
  * Every path of _Hash_Absorb_Last_Block_ is covered:
      Xs = 0     empty message           (K2, all-padding block)
      Xs = b     full final block        (K1 path)
      0 < Xs < b partial final block     (K2, ocb-style padded block)
  * Both _Hash_Output_ options: the Form C `ace.exec` emit, and the Form C
    `ace.setst #ace_state_hash_verify` comparison (Success on the right tag,
    Failure on a tampered one).
  * The `Xs` validity rule of the Form B setst: Xs > b and Xs not a
    multiple of 8 must drive the CR to Error State _Invalid_.
  * Negative controls (must NOT reproduce the standard):
      NC-K2full  : take the K2 path for a full final block instead of K1.
      NC-lemask  : derive the subkeys with the little-endian update_mask
                   instead of double() = bswap(update_mask(bswap(S))).

Known spec issue exercised (review finding m6, since fixed)
  With last_blk_len = 0 the spec's padding formula reads INPUT[-1:0], an
  undefined slice.  This harness adopts the recommended reading — INPUT is
  ignored and the padded block is zeros(b-8) @ 0b10000000 — and *proves*
  the reading is the interoperable one by feeding a nonzero dummy INPUT in
  the empty-message case and checking the published tag still results.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bswap, aes_encrypt, update_mask,
                    double_ocb, bxor)

B = 128                      # block size (spec parameter b)

# ====================================================================== REF
# SP 800-38B section 6.1-6.2 / RFC 4493 section 2, on byte strings.

def _ref_double(S):
    """L << 1 over the big-endian string, xor R_128 = 0x87 if the first bit was 1."""
    n = int.from_bytes(S, 'big')
    r = ((n << 1) & ((1 << 128) - 1)) ^ (0x87 if n >> 127 else 0)
    return r.to_bytes(16, 'big')

def ref_subkeys(K):
    L = aes_encrypt(K, bytes(16))
    K1 = _ref_double(L)
    K2 = _ref_double(K1)
    return L, K1, K2

def ref_cmac(K, M):
    _, K1, K2 = ref_subkeys(K)
    if len(M) and len(M) % 16 == 0:
        blocks = [M[i:i + 16] for i in range(0, len(M), 16)]
        last = bxor(blocks.pop(), K1)                      # complete final block
    else:
        n = len(M) // 16
        blocks = [M[i * 16:(i + 1) * 16] for i in range(n)]
        tail = M[n * 16:]
        last = bxor(tail + b'\x80' + bytes(15 - len(tail)), K2)
    X = bytes(16)
    for blk in blocks:
        X = aes_encrypt(K, bxor(X, blk))
    return aes_encrypt(K, bxor(X, last))

# ====================================================================== ACE
# The state machine of <<ACE-CMAC-mode>>, transcribed step by step.

class Invalid(Exception):
    """CR transition to Error State _Invalid_."""

class AceCmac:
    def __init__(self, key, double_fn=double_ocb, force_k2=False):
        self.keyb = key
        self.double = double_fn
        self.force_k2 = force_k2                  # negative control NC-K2full
        # State _Ready_:
        self.last_blk_len = 0
        self.hash = 0                             # zeros(b)
        self.block_base = 0

    def enc(self, v):
        return b2v(aes_encrypt(self.keyb, v2b(v, 16)))

    def gen_subkeys(self):
        # L <- enc_blk(K, zeros(b)); K1 <- double(L); K2 <- double(K1)
        L = self.enc(0)
        K1 = self.double(L)
        K2 = self.double(K1)
        return L, K1, K2

    def exec_absorb(self, INPUT):                 # Form B in _Hash_Absorb_
        # hash <- enc_blk(key, hash xor INPUT)
        self.hash = self.enc(self.hash ^ INPUT)

    def setst_last_block(self, Xs):               # Form B setst -> _Hash_Absorb_Last_Block_
        if self.block_base != 0:
            raise Invalid('previous block incomplete')
        if Xs > B or Xs % 8 != 0:
            raise Invalid('Xs > b, or Xs not a multiple of 8')
        self.last_blk_len = Xs

    def exec_absorb_last(self, INPUT=0):          # Form B in _Hash_Absorb_Last_Block_
        _, K1, K2 = self.gen_subkeys()
        n = self.last_blk_len
        if n == B:
            # NC-K2full applies the wrong subkey on the full-block path.  Note
            # that the K2 *branch* cannot be taken here at all: its padding
            # expression zeros(b-8-n) is undefined for n = b, which is exactly
            # why the spec splits the two cases on last_blk_len = b.
            tmp = self.hash ^ INPUT ^ (K2 if self.force_k2 else K1)
        else:
            # zeros(b - 8 - n) @ 0b10000000 @ INPUT[n-1:0]
            # For n = 0 the spec writes INPUT[-1:0] (review m6); the reading
            # adopted here is that INPUT is ignored and the block is all padding.
            body = cat((0, B - 8 - n), (0x80, 8), (sl(INPUT, n - 1, 0), n)) if n \
                   else cat((0, B - 8), (0x80, 8))
            tmp = self.hash ^ body ^ K2
        self.hash = self.enc(tmp)

    def exec_output(self):                        # Form C ace.exec in _Hash_Output_
        return self.hash

    def setst_hash_verify(self, INPUT):           # Form C ace.setst in _Hash_Output_
        # the b least significant bits of INPUT are compared with hash
        return sl(INPUT, B - 1, 0) == self.hash   # Success / Failure


def ace_cmac(K, M, double_fn=double_ocb, force_k2=False, dummy_empty_input=0):
    """Drive the state machine the way software would; return the b-bit tag."""
    m = AceCmac(K, double_fn, force_k2)
    if len(M) and len(M) % 16 == 0:
        nfull, tail = len(M) // 16 - 1, M[-16:]   # last full block is the last block
    else:
        nfull, tail = len(M) // 16, M[(len(M) // 16) * 16:]
    for i in range(nfull):                        # _Hash_Absorb_
        m.exec_absorb(b2v(M[i * 16:(i + 1) * 16]))
    m.setst_last_block(len(tail) * 8)             # Form B setst, Xs = bit length
    if tail:
        m.exec_absorb_last(b2v(tail))
    else:
        m.exec_absorb_last(dummy_empty_input)     # Xs = 0: INPUT ignored (m6)
    return m


# ================================================================== vectors
# RFC 4493 section 4 / SP 800-38B D.1 (AES-128), and the NIST CMAC example
# file for AES-192 (D.2) and AES-256 (D.3).
MSG = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710")

K128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
K192 = bytes.fromhex("8e73b0f7da0e6452c810f32b809079e5"
                     "62f8ead2522c6b7b")
K256 = bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                     "1f352c073b6108d72d9810a30914dff4")

# (label, key, published L, published K1, published K2)
SUBKEYS = [
    ("AES-128", K128, "7DF76B0C1AB899B33E42F047B91B546F",
                      "FBEED618357133667C85E08F7236A8DE",
                      "F7DDAC306AE266CCF90BC11EE46D513B"),
    ("AES-192", K192, "22452D8E49A8A5939F7321CEEA6D514B",
                      "448A5B1C93514B273EE6439DD4DAA296",
                      "8914B63926A2964E7DCC873BA9B5452C"),
    ("AES-256", K256, "E568F68194CF76D6174D4CC04310A854",
                      "CAD1ED03299EEDAC2E9A99808621502F",
                      "95A3DA06533DDB585D3533010C42A0D9"),
]

# (label, key, Mlen in bytes, expected tag)
VECTORS = [
    ("AES-128 ex1", K128,  0, "BB1D6929E95937287FA37D129B756746"),
    ("AES-128 ex2", K128, 16, "070A16B46B4D4144F79BDD9DD04A287C"),
    ("AES-128 ex3", K128, 20, "7D85449EA6EA19C823A7BF78837DFADE"),
    ("AES-128 ex4", K128, 40, "DFA66747DE9AE63030CA32611497C827"),
    ("AES-128 ex5", K128, 64, "51F0BEBF7E3B9D92FC49741779363CFE"),
    ("AES-192 ex1", K192,  0, "D17DDF46ADAACDE531CAC483DE7A9367"),
    ("AES-192 ex2", K192, 16, "9E99A7BF31E710900662F65E617C5184"),
    ("AES-192 ex3", K192, 20, "3D75C194ED96070444A9FA7EC740ECF8"),
    ("AES-192 ex4", K192, 64, "A1D5DF0EED790F794D77589659F39A11"),
    ("AES-256 ex1", K256,  0, "028962F61B7BF89EFC6B551F4667D983"),
    ("AES-256 ex2", K256, 16, "28A7023F452E8F82BD4BF28D8C37C35C"),
    ("AES-256 ex3", K256, 20, "156727DC0878944A023C1FE03BAD6D93"),
    ("AES-256 ex4", K256, 64, "E1992190549F6ED5696A2C056C315410"),
]

def path_of(n):
    if n == 0:
        return "Xs=0 empty"
    if n % 16 == 0:
        return "Xs=b   K1"
    return "0<Xs<b K2"

# ==================================================================== run
def main():
    ok = True
    def chk(cond):
        nonlocal ok
        ok = ok and cond
        return 'PASS' if cond else 'FAIL'

    print("gen_subkeys vs the published L / K1 / K2 anchors "
          "(RFC 4493 section 4; NIST CMAC example file):")
    print(f"{'key':10} {'L':6} {'K1':6} {'K2':6}")
    for label, K, wl, w1, w2 in SUBKEYS:
        L, K1, K2 = AceCmac(K).gen_subkeys()
        rl, r1, r2 = ref_subkeys(K)
        good = (v2b(L, 16).hex().upper() == wl and rl.hex().upper() == wl)
        g1 = (v2b(K1, 16).hex().upper() == w1 and r1.hex().upper() == w1)
        g2 = (v2b(K2, 16).hex().upper() == w2 and r2.hex().upper() == w2)
        print(f"{label:10} {chk(good):6} {chk(g1):6} {chk(g2):6}")

    print("\nCMAC vectors (REF = SP 800-38B on byte strings; "
          "ACE = <<ACE-CMAC-mode>> state machine):")
    print(f"{'case':14} {'Mlen':>5}  {'last-block path':16} "
          f"{'REF':6} {'ACE-emit':9} {'verify':7} {'tamper':7}")
    for label, K, n, want in VECTORS:
        M = MSG[:n]
        W = bytes.fromhex(want)
        r = ref_cmac(K, M)
        m = ace_cmac(K, M)
        emitted = v2b(m.exec_output(), 16)
        good_verify = m.setst_hash_verify(b2v(W))
        bad = bytearray(W); bad[0] ^= 0x80
        evil_verify = ace_cmac(K, M).setst_hash_verify(b2v(bytes(bad)))
        print(f"{label:14} {n:>5}  {path_of(n):16} "
              f"{chk(r == W):6} {chk(emitted == W):9} "
              f"{chk(good_verify):7} {chk(not evil_verify):7}")

    print("\nempty-message reading of the INPUT[-1:0] slice (review m6): "
          "with Xs = 0 the tag must not depend on INPUT")
    for label, K, want in (("AES-128", K128, "BB1D6929E95937287FA37D129B756746"),
                           ("AES-192", K192, "D17DDF46ADAACDE531CAC483DE7A9367"),
                           ("AES-256", K256, "028962F61B7BF89EFC6B551F4667D983")):
        t0 = v2b(ace_cmac(K, b'', dummy_empty_input=0).exec_output(), 16)
        t1 = v2b(ace_cmac(K, b'', dummy_empty_input=(1 << 128) - 1).exec_output(), 16)
        agree = t0 == t1 == bytes.fromhex(want)
        print(f"  {label}: INPUT = 0 and INPUT = ones(128) both give the "
              f"published tag: {chk(agree)}")

    print("\nForm B setst validity rule for Xs (must reach Error State _Invalid_):")
    for Xs, why in ((136, "Xs > b"), (129, "Xs > b"), (4, "not a multiple of 8"),
                    (12, "not a multiple of 8"), (127, "not a multiple of 8")):
        try:
            AceCmac(K128).setst_last_block(Xs)
            fired = False
        except Invalid:
            fired = True
        print(f"  Xs = {Xs:3} ({why:19}): {chk(fired)}")
    for Xs in (0, 8, 64, 120, 128):
        try:
            AceCmac(K128).setst_last_block(Xs)
            fired = True
        except Invalid:
            fired = False
        print(f"  Xs = {Xs:3} ({'admissible':19}): {chk(fired)}")

    # ------------------------------------------------------ negative controls
    print("\nnegative controls (wrong formulations must NOT reproduce the standard):")
    print("KAT-EXPECT-FAIL: NC-K2full")
    print("KAT-EXPECT-FAIL: NC-lemask")
    # NC-K2full: only meaningful where the final block is full (Mlen = 16, 64).
    fired1 = all(v2b(ace_cmac(K, MSG[:n], force_k2=True).exec_output(), 16)
                 != bytes.fromhex(w)
                 for lbl, K, n, w in VECTORS if n and n % 16 == 0)
    print(f"  NC-K2full (K2 used for a full final block, not K1)   : "
          f"{'FAIL as expected' if fired1 else 'MATCHED (control did not fire)'}")
    # NC-lemask: the little-endian XTS doubling instead of the big-endian double().
    fired2 = any(v2b(ace_cmac(K, MSG[:n], double_fn=update_mask).exec_output(), 16)
                 != bytes.fromhex(w)
                 for lbl, K, n, w in VECTORS)
    print(f"  NC-lemask (subkeys via little-endian update_mask)    : "
          f"{'FAIL as expected' if fired2 else 'MATCHED (control did not fire)'}")
    ok = ok and fired1 and fired2

    print("\nNOTE: per review m6, the spec's last-block formula reads "
          "INPUT[last_blk_len-1:0], i.e. INPUT[-1:0], when last_blk_len = 0. "
          "The interoperable reading, confirmed above, is that INPUT is "
          "ignored and the padded block is zeros(b-8) @ 0b10000000.")
    print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
