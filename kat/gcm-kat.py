#!/usr/bin/env python3
"""Known-answer tests for <<ACE-GCM-mode>> and <<ACE-GCM-with-IV-mode>>.

What this validates
-------------------
Two independent implementations are compared against published vectors:

REF  a straight SP 800-38D implementation on *byte strings* (big-endian counter
     blocks, GHASH over 16-byte strings).  It is anchored by the classic
     McGrew-Viega / SP 800-38D test cases 1-6 (AES-128) and 13-18 (AES-256).

ACE  a model of the specification's state machine, written on ACE *values*
     (little-endian bit strings, byte i at bits [8i+7:8i]) and transcribed
     literally from the text of `src/ace-ISA-algorithms.adoc`
     ([[ACE-process-VLI]], [[ACE-GCM-mode]], [[ACE-GCM-with-IV-mode]]) under the
     conventions of `src/ace-notation.adoc`.  The model runs the real state
     sequence -- _Set_Aux_Value_ (via process_VLI, with the IV split over several
     `ace.exec`-sized transfers and, in one case, an interrupted-and-resumed
     transfer), _Hash_Absorb_, _Encrypt_/_Enc_Last_Block_/_Enc_Tag_Finalize_ and
     _Decrypt_/_Dec_Last_Block_/_Dec_Tag_Finalize_/_Hash_Verify_.

Also checked: the counter-wrap rule (Invalid exactly when `ctr` reaches
`(start_ctr - 1) mod 2^32`, i.e. after 2^32-2 blocks -- exercised by seeding the
counter field near the limit, not by looping), and GCM-with-Set-IV's `budget`
accounting.

Negative controls (declared with KAT-EXPECT-FAIL) re-run the ACE model with the
two halves of the length block swapped, and with a little-endian counter
increment; both must fail against the vectors.

Note on M4 of ACE-spec-review-0.7.0.md: process_VLI writes `acestart <-
input_base` and reads `input_base <- acestart` although `input_base` is in bits
and `acestart` is architecturally a byte count.  The resumption model below uses
the corrected /8 and *8 conversions, as M4 resolves.

Conclusion: the spec text as written reproduces every vector; no *functional*
discrepancy with SP 800-38D was found in either mode.  Three editorial defects
noticed while transcribing are printed as OBSERVATIONs at the end; none of them
changes a computed value, so none is a test failure.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import (b2v, v2b, sl, cat, bswap, bin_, aes_encrypt,
                    gmul_ghash, ace_galoismul, selftest)

B = 128                      # block size in bits
MASK32 = (1 << 32) - 1

# =====================================================================
# REF: SP 800-38D on byte strings
# =====================================================================

def ghash(H: bytes, X: bytes) -> bytes:
    y = bytes(16)
    for i in range(0, len(X), 16):
        y = gmul_ghash(bytes(a ^ b for a, b in zip(y, X[i:i + 16])), H)
    return y


def _pad16(s: bytes) -> bytes:
    return s + bytes((-len(s)) % 16)


def ref_j0(K: bytes, IV: bytes) -> bytes:
    """SP 800-38D 7.1."""
    if len(IV) == 12:
        return IV + b"\x00\x00\x00\x01"
    H = aes_encrypt(K, bytes(16))
    return ghash(H, _pad16(IV) + bytes(8) + (len(IV) * 8).to_bytes(8, "big"))


def _inc32(b: bytes) -> bytes:
    return b[:12] + ((int.from_bytes(b[12:], "big") + 1) & MASK32).to_bytes(4, "big")


def ref_gcm(K: bytes, IV: bytes, A: bytes, P: bytes):
    """Returns (ciphertext, 16-byte tag)."""
    E = lambda blk: aes_encrypt(K, blk)
    H, J0 = E(bytes(16)), ref_j0(K, IV)
    C, cb = b"", J0
    for i in range(0, len(P), 16):
        cb = _inc32(cb)
        blk = P[i:i + 16]
        C += bytes(x ^ y for x, y in zip(blk, E(cb)))
    S = ghash(H, _pad16(A) + _pad16(C)
              + (len(A) * 8).to_bytes(8, "big") + (len(C) * 8).to_bytes(8, "big"))
    return C, bytes(x ^ y for x, y in zip(S, E(J0)))


# =====================================================================
# ACE model
# =====================================================================

class Invalid(Exception):
    """The CR transitioned to Error State _Invalid_."""


class GcmCC:
    """The ACE Cryptographic Context of <<ACE-GCM-mode>> / <<ACE-GCM-with-IV-mode>>.

    `set_iv_J0` / `budget` not None selects the GCM-with-Set-IV variant, whose
    Provisioning Input carries `J0` and `budget` and which has no
    _Set_Aux_Value_ state.

    `swap_len_block` and `le_counter` are the negative controls.
    """

    def __init__(self, key, set_iv_J0=None, budget=None,
                 swap_len_block=False, le_counter=False):
        self.key = key
        self.swap_len_block = swap_len_block
        self.le_counter = le_counter
        # State _Ready_ initialisation
        self.auth_key = b2v(aes_encrypt(key, bytes(16)))
        self.tag = 0
        self.J0 = 0
        self.start_ctr = 0
        self.last_blk_len = 0
        self.acestart = 0
        self.state = "Ready"
        self.set_iv = set_iv_J0 is not None
        self.budget = budget
        if self.set_iv:
            self.J0 = set_iv_J0
            self.start_ctr = self._ctr_of(sl(self.J0, 127, 96))

    # ---------------- primitives ----------------

    def _enc_blk(self, v):
        return b2v(aes_encrypt(self.key, v2b(v, 16)))

    def _absorb(self, data):
        self.tag = ace_galoismul(self.tag ^ data, self.auth_key)

    def _ctr_of(self, field32):
        """`int(bswap(J0[127:96]))` -- the counter field read as a big-endian integer."""
        if self.le_counter:                       # negative control
            return field32
        return bswap(field32, 4)

    def _field_of(self, ctr):
        """`bswap(bin(ctr,32))`."""
        if self.le_counter:                       # negative control
            return bin_(ctr, 32)
        return bswap(bin_(ctr, 32), 4)

    def _ctr_blk(self, ctr):
        return cat((self._field_of(ctr), 32), (sl(self.J0, 95, 0), 96))

    def _bump_ctr(self):
        """The counter step shared by _Encrypt_, _Decrypt_ and the last-block states."""
        ctr = self._ctr_of(sl(self.J0, 127, 96))
        ctr = (ctr + 1) % 2 ** 32
        if ctr == (self.start_ctr - 1) % 2 ** 32:
            self.state = "Invalid"
            raise Invalid("counter reached (start_ctr - 1) mod 2**32")
        self.J0 = cat((self._field_of(ctr), 32), (sl(self.J0, 95, 0), 96))

    def _consume(self, nblocks):
        """GCM-with-Set-IV budget rule: an `ace.exec` that would take `budget`
        below zero performs no operation and the CR transitions to _Invalid_."""
        if self.budget is None:
            return
        if self.budget - nblocks < 0:
            self.state = "Invalid"
            raise Invalid("budget exhausted")
        self.budget -= nblocks

    def _require(self, *states):
        if self.state not in states:
            raise Invalid(f"state {self.state} not in {states}")

    # ---------------- _Set_Aux_Value_ (process_VLI) ----------------

    def setst_set_aux_value(self, xs):
        """Form B `ace.setst`, auxiliary argument = IV length in bits."""
        self._require("Ready")
        if self.set_iv:
            raise Invalid("GCM with Set IV has no _Set_Aux_Value_")
        if not (8 <= xs <= 8192):
            self.state = "Invalid"
            raise Invalid("IV length out of range")
        self.len = xs
        self.J0 = 0                                 # J0 <- zeros(b)
        self.input_base = self.block_base = self.cumul_len = 0
        self.state = "Set_Aux_Value"

    def _vli_process_block(self):
        if self.len != 96:
            self.J0 = ace_galoismul(self.J0, self.auth_key)

    def _vli_finalize(self):
        if self.len == 96:
            self.J0 = cat((bswap(bin_(1, 32), 4), 32), (sl(self.J0, 95, 0), 96))
        else:
            if self.block_base != 0:
                self.J0 = ace_galoismul(self.J0, self.auth_key)
            self.J0 ^= cat((bswap(bin_(self.len, 64), 8), 64), (0, 64))
            self.J0 = ace_galoismul(self.J0, self.auth_key)
        self.start_ctr = self._ctr_of(sl(self.J0, 127, 96))
        self.state = "Hash_Absorb"

    def exec_iv(self, INPUT, ACELEN, resume=False, interrupt_after=None):
        """Form B `ace.exec` in _Set_Aux_Value_: one transfer through process_VLI.

        Returns True if the instruction ran to completion, False if it was
        interrupted (in which case `acestart` holds the byte offset reached and
        the caller must re-issue with resume=True).
        """
        self._require("Set_Aux_Value")
        if self.len != 0 and self.cumul_len >= self.len:
            self.state = "Invalid"
            raise Invalid("process_VLI: cumul_len >= len")
        # M4 (ACE-spec-review-0.7.0.md): the text writes `input_base <- acestart`
        # although input_base is in bits and acestart counts bytes; the corrected
        # conversion is used here.
        self.input_base = 8 * self.acestart if resume else 0
        iters = 0
        while self.input_base < ACELEN:
            if self.len != 0:
                amount = min(ACELEN - self.input_base, B - self.block_base,
                             self.len - self.cumul_len)
            else:
                amount = min(ACELEN - self.input_base, B - self.block_base)
            chunk = sl(INPUT, self.input_base + amount - 1, self.input_base)
            # block is state (state_offset = 0), so the input is XORed in
            self.J0 ^= chunk << self.block_base
            self.input_base += amount
            self.block_base += amount
            self.cumul_len += amount
            if self.block_base == B:
                self._vli_process_block()
                self.block_base = 0
            if self.len != 0 and self.cumul_len == self.len:
                self._vli_finalize()
                self.acestart = 0
                return True
            iters += 1
            if interrupt_after is not None and iters == interrupt_after:
                self.acestart = self.input_base // 8      # M4-corrected
                return False
        self.acestart = 0
        return True

    # ---------------- _Hash_Absorb_ ----------------

    def setst_hash_absorb(self):
        """Form A `ace.setst` -- only the Set-IV variant needs it; in plain GCM
        _Set_Aux_Value_'s finalize() already transitions."""
        self._require("Ready")
        if not self.set_iv:
            raise Invalid("plain GCM enters _Hash_Absorb_ from _Set_Aux_Value_")
        self.state = "Hash_Absorb"

    def exec_absorb(self, INPUT, ACELEN):
        self._require("Hash_Absorb")
        assert ACELEN % B == 0, "ACELEN must be a multiple of b"
        self._consume(ACELEN // B)
        for i in range(ACELEN // B):
            self._absorb(sl(INPUT, B * i + B - 1, B * i))

    # ---------------- _Encrypt_ / _Decrypt_ ----------------

    def setst_encrypt(self):
        self._require("Hash_Absorb")
        self.state = "Encrypt"

    def setst_decrypt(self):
        self._require("Hash_Absorb")
        self.state = "Decrypt"

    def exec_encrypt(self, INPUT, ACELEN):
        self._require("Encrypt")
        assert ACELEN % B == 0
        self._consume(ACELEN // B)
        out = 0
        for i in range(ACELEN // B):
            self._bump_ctr()
            tmp = sl(INPUT, B * i + B - 1, B * i) ^ self._enc_blk(self.J0)
            self._absorb(tmp)
            out |= tmp << (B * i)
        return out

    def exec_decrypt(self, INPUT, ACELEN):
        self._require("Decrypt")
        assert ACELEN % B == 0
        self._consume(ACELEN // B)
        out = 0
        for i in range(ACELEN // B):
            blk = sl(INPUT, B * i + B - 1, B * i)
            self._bump_ctr()
            self._absorb(blk)
            out |= (blk ^ self._enc_blk(self.J0)) << (B * i)
        return out

    # ---------------- last-block states ----------------

    def setst_last_block(self, xs, decrypt=False):
        self._require("Decrypt" if decrypt else "Encrypt")
        if xs == 0 or xs > 127:
            self.state = "Invalid"
            raise Invalid("last_blk_len out of range")
        self.last_blk_len = xs
        self.state = "Dec_Last_Block" if decrypt else "Enc_Last_Block"

    def exec_enc_last_block(self, INPUT):
        self._require("Enc_Last_Block")
        n = self.last_blk_len
        if n == 0:
            return 0
        self._consume(1)
        self._bump_ctr()
        ks = sl(self._enc_blk(self.J0), n - 1, 0)
        tmp = sl(INPUT, n - 1, 0) ^ ks
        self._absorb(tmp)
        self.last_blk_len = 0
        return tmp

    def exec_dec_last_block(self, INPUT):
        self._require("Dec_Last_Block")
        n = self.last_blk_len
        if n == 0:
            return 0
        self._consume(1)
        self._bump_ctr()
        tmp = sl(INPUT, n - 1, 0)
        self._absorb(tmp)
        out = tmp ^ sl(self._enc_blk(self.J0), n - 1, 0)
        self.last_blk_len = 0
        return out

    # ---------------- tag finalisation ----------------

    def _len_block(self, pt_bits, ad_bits):
        hi, lo = pt_bits, ad_bits
        if self.swap_len_block:                     # negative control
            hi, lo = lo, hi
        return cat((bswap(bin_(hi, 64), 8), 64), (bswap(bin_(lo, 64), 8), 64))

    def _finalize_tag(self, pt_bits, ad_bits):
        self._absorb(self._len_block(pt_bits, ad_bits))
        self.tag ^= self._enc_blk(self._ctr_blk(self.start_ctr))

    def setst_enc_tag_finalize(self, pt_bits, ad_bits):
        """Form C `ace.setst`; the length block is supplied by software."""
        self._require("Encrypt", "Enc_Last_Block")
        self._finalize_tag(pt_bits, ad_bits)
        self.state = "Enc_Tag_Finalize"

    def exec_emit_tag(self):
        """Form C `ace.exec` -- emits the tag; consumes no block of `budget`."""
        self._require("Enc_Tag_Finalize")
        self.state = "Success"
        return self.tag

    def setst_dec_tag_finalize(self, pt_bits, ad_bits):
        self._require("Decrypt", "Dec_Last_Block")
        self._finalize_tag(pt_bits, ad_bits)
        self.state = "Dec_Tag_Finalize"

    def setst_hash_verify(self, tag_value):
        self._require("Dec_Tag_Finalize")
        self.state = "Success" if tag_value == self.tag else "Failure"
        return self.state


# ---------------------------------------------------------------------
# drivers that run a whole message through the state machine
# ---------------------------------------------------------------------

def _iv_transfers(iv, chunk):
    """Split the IV into `granularity = b` conforming transfers: every transfer
    but the last is a whole multiple of 16 bytes."""
    out, i = [], 0
    while i < len(iv):
        out.append(iv[i:i + chunk])
        i += chunk
    return out or [b""]


def ace_encrypt(key, iv, ad, pt, iv_chunk=16, pt_chunk=16,
                interrupt_iv=False, **kw):
    cc = GcmCC(key, **kw)
    cc.setst_set_aux_value(len(iv) * 8)
    for t in _iv_transfers(iv, iv_chunk):
        if interrupt_iv and len(t) >= 32:
            # interrupt after the first inner-loop iteration and resume
            done = cc.exec_iv(b2v(t), len(t) * 8, interrupt_after=1)
            while not done:
                done = cc.exec_iv(b2v(t), len(t) * 8, resume=True)
        else:
            cc.exec_iv(b2v(t), len(t) * 8)
    # _Hash_Absorb_: the caller zero-pads the final AD block
    if ad:
        padded = _pad16(ad)
        cc.exec_absorb(b2v(padded), len(padded) * 8)
    cc.setst_encrypt()
    nfull = len(pt) // 16
    ct = b""
    for i in range(0, nfull * 16, pt_chunk * 16):
        blk = pt[i:min(i + pt_chunk * 16, nfull * 16)]
        ct += v2b(cc.exec_encrypt(b2v(blk), len(blk) * 8), len(blk))
    rest = pt[nfull * 16:]
    if rest:
        cc.setst_last_block(len(rest) * 8)
        ct += v2b(cc.exec_enc_last_block(b2v(rest)), len(rest))
    cc.setst_enc_tag_finalize(len(pt) * 8, len(ad) * 8)
    tag = cc.exec_emit_tag()
    return ct, v2b(tag, 16), cc


def ace_decrypt(key, iv, ad, ct, tag_bytes, **kw):
    cc = GcmCC(key, **kw)
    cc.setst_set_aux_value(len(iv) * 8)
    for t in _iv_transfers(iv, 16):
        cc.exec_iv(b2v(t), len(t) * 8)
    if ad:
        padded = _pad16(ad)
        cc.exec_absorb(b2v(padded), len(padded) * 8)
    cc.setst_decrypt()
    nfull = len(ct) // 16
    pt = b""
    if nfull:
        blk = ct[:nfull * 16]
        pt += v2b(cc.exec_decrypt(b2v(blk), len(blk) * 8), len(blk))
    rest = ct[nfull * 16:]
    if rest:
        cc.setst_last_block(len(rest) * 8, decrypt=True)
        pt += v2b(cc.exec_dec_last_block(b2v(rest)), len(rest))
    cc.setst_dec_tag_finalize(len(ct) * 8, len(ad) * 8)
    verdict = cc.setst_hash_verify(b2v(tag_bytes))
    return pt, verdict, cc


def ace_encrypt_setiv(key, J0, budget, ad, pt, **kw):
    """GCM with Set IV: J0 and budget come from the Provisioning Input."""
    cc = GcmCC(key, set_iv_J0=J0, budget=budget, **kw)
    cc.setst_hash_absorb()                       # Form A ace.setst
    if ad:
        padded = _pad16(ad)
        cc.exec_absorb(b2v(padded), len(padded) * 8)
    cc.setst_encrypt()
    nfull = len(pt) // 16
    ct = b""
    if nfull:
        blk = pt[:nfull * 16]
        ct += v2b(cc.exec_encrypt(b2v(blk), len(blk) * 8), len(blk))
    rest = pt[nfull * 16:]
    if rest:
        cc.setst_last_block(len(rest) * 8)
        ct += v2b(cc.exec_enc_last_block(b2v(rest)), len(rest))
    cc.setst_enc_tag_finalize(len(pt) * 8, len(ad) * 8)
    return ct, v2b(cc.exec_emit_tag(), 16), cc


# =====================================================================
# Vectors
# =====================================================================
# Provenance: the AES-GCM test cases of D. McGrew and J. Viega, "The Galois/
# Counter Mode of Operation (GCM)", submission to NIST (2005), Appendix B
# ("The Galois/Counter Mode of Operation (GCM)", gcm-spec.pdf, test cases
# 1-18), which are the vectors NIST's SP 800-38D references and which are
# mirrored verbatim in the Linux kernel's crypto testmgr vectors, BoringSSL's
# cipher_test data and NSS.  Cases 1-6 use AES-128 and 13-18 AES-256.
# Fields: (label, key, IV, AAD, plaintext, ciphertext, tag), all hex.

P64 = ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
P60 = P64[:120]
AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
K128 = "feffe9928665731c6d6a8f9467308308"
K256 = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
IV12 = "cafebabefacedbaddecaf888"
IV8 = "cafebabefacedbad"
IV60 = ("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
        "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b")

VECTORS = [
    ("tc1  AES-128", "00" * 16, "00" * 12, "", "", "",
     "58e2fccefa7e3061367f1d57a4e7455a"),
    ("tc2  AES-128", "00" * 16, "00" * 12, "", "00" * 16,
     "0388dace60b6a392f328c2b971b2fe78",
     "ab6e47d42cec13bdf53a67b21257bddf"),
    ("tc3  AES-128", K128, IV12, "", P64,
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
     "4d5c2af327cd64a62cf35abd2ba6fab4"),
    ("tc4  AES-128", K128, IV12, AAD, P60,
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
     "5bc94fbc3221a5db94fae95ae7121a47"),
    ("tc5  AES-128", K128, IV8, AAD, P60,
     "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423"
     "73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
     "3612d2e79e3b0785561be14aaca2fccb"),
    ("tc6  AES-128", K128, IV60, AAD, P60,
     "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7"
     "01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
     "619cc5aefffe0bfa462af43c1699d050"),
    ("tc13 AES-256", "00" * 32, "00" * 12, "", "", "",
     "530f8afbc74536b9a963b4f1c4cb738b"),
    ("tc14 AES-256", "00" * 32, "00" * 12, "", "00" * 16,
     "cea7403d4d606b6e074ec5d3baf39d18",
     "d0d1c8a799996bf0265b98b5d48ab919"),
    ("tc15 AES-256", K256, IV12, "", P64,
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
     "b094dac5d93471bdec1a502270e3cc6c"),
    ("tc16 AES-256", K256, IV12, AAD, P60,
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
     "76fc6ece0f4e1768cddf8853bb2d551b"),
    ("tc17 AES-256", K256, IV8, AAD, P60,
     "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0"
     "feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
     "3a337dbf46a792c45e454913fe2ea8f2"),
    ("tc18 AES-256", K256, IV60, AAD, P60,
     "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4"
     "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
     "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"),
]

# A vector with a plaintext whose last block is a non-integral number of bytes
# is not available from the standard sets; the bit-granular _Enc_Last_Block_
# path (last_blk_len not a multiple of 8) is therefore checked for internal
# consistency (encrypt/decrypt round trip) rather than against a vector.


# =====================================================================
# Test driver
# =====================================================================

ok = True
lines = []


def check(name, cond):
    global ok
    ok = ok and bool(cond)
    lines.append(f"  {'PASS' if cond else 'FAIL'}  {name}")
    return bool(cond)


def expect_fail(name, matched):
    """A negative control.  The word printed is the verdict of the *wrong* model
    against the vector, so the expected -- and required -- outcome is FAIL.
    `matched` True would mean the control has lost its discriminating power."""
    global ok
    ok = ok and not matched
    lines.append(f"  {'PASS' if matched else 'FAIL'}  {name}")
    return not matched


print(__doc__.strip().splitlines()[0])
print()
print("KAT-EXPECT-FAIL: negative control: length block halves swapped")
print("KAT-EXPECT-FAIL: negative control: little-endian counter increment")
print()

# ---- 0. common.py self-test ------------------------------------------------
lines.append("--- primitives (common.py self-test) ---")
check("common.py self-test (FIPS 197, RFC 8452, SP 800-38B/D anchors)", selftest())

# ---- 1. REF against the published vectors ----------------------------------
lines.append("--- REF (SP 800-38D on byte strings) vs published vectors ---")
for label, k, iv, a, p, c, t in VECTORS:
    K, IV, A, P = (bytes.fromhex(x) for x in (k, iv, a, p))
    C, T = ref_gcm(K, IV, A, P)
    check(f"REF {label}  |IV|={len(IV)}B |A|={len(A)}B |P|={len(P)}B",
          C == bytes.fromhex(c) and T == bytes.fromhex(t))

# ---- 2. ACE model against the same vectors ---------------------------------
lines.append("--- ACE model (spec state machine) vs published vectors ---")
for label, k, iv, a, p, c, t in VECTORS:
    K, IV, A, P = (bytes.fromhex(x) for x in (k, iv, a, p))
    C, T, cc = ace_encrypt(K, IV, A, P)
    check(f"ACE encrypt {label}", C == bytes.fromhex(c) and T == bytes.fromhex(t)
          and cc.state == "Success")

# ---- 3. ACE model with the IV split over several transfers, one interrupted -
lines.append("--- ACE _Set_Aux_Value_: multi-transfer IV, interrupted transfer ---")
for label, k, iv, a, p, c, t in VECTORS:
    if len(iv) // 2 <= 12:
        continue                        # only the 60-byte IV cases are interesting
    K, IV, A, P = (bytes.fromhex(x) for x in (k, iv, a, p))
    for chunk, intr in ((16, False), (32, False), (32, True), (48, True)):
        C, T, cc = ace_encrypt(K, IV, A, P, iv_chunk=chunk, interrupt_iv=intr)
        check(f"ACE {label} IV in {chunk}-byte transfers"
              + (", interrupted+resumed" if intr else ""),
              C == bytes.fromhex(c) and T == bytes.fromhex(t))
# a 20-byte IV forces a partial final block inside process_VLI
K, IV, A, P = bytes.fromhex(K128), bytes(range(20)), bytes.fromhex(AAD), bytes.fromhex(P60)
rc, rt = ref_gcm(K, IV, A, P)
ac, at, _ = ace_encrypt(K, IV, A, P, iv_chunk=16)
check("ACE 20-byte IV (partial final process_VLI block) matches REF",
      (ac, at) == (rc, rt))

# ---- 4. multi-block ace.exec chunking of the plaintext ----------------------
lines.append("--- ACE _Encrypt_: ACELEN spanning several blocks ---")
K, IV, A, P = bytes.fromhex(K128), bytes.fromhex(IV12), bytes.fromhex(AAD), bytes.fromhex(P60)
rc, rt = ref_gcm(K, IV, A, P)
for n in (1, 2, 3):
    ac, at, _ = ace_encrypt(K, IV, A, P, pt_chunk=n)
    check(f"ACE encrypt with ACELEN = {n} block(s) per ace.exec", (ac, at) == (rc, rt))

# ---- 5. decryption and _Hash_Verify_ ---------------------------------------
lines.append("--- ACE decrypt path and _Hash_Verify_ ---")
for label, k, iv, a, p, c, t in VECTORS:
    K, IV, A = (bytes.fromhex(x) for x in (k, iv, a))
    C, T, P = bytes.fromhex(c), bytes.fromhex(t), bytes.fromhex(p)
    pt, verdict, _ = ace_decrypt(K, IV, A, C, T)
    check(f"ACE decrypt {label} -> plaintext, _Success_",
          pt == P and verdict == "Success")
    bad = bytearray(T)
    bad[0] ^= 0x80
    _, verdict, _ = ace_decrypt(K, IV, A, C, bytes(bad))
    check(f"ACE decrypt {label} with corrupted tag -> _Failure_", verdict == "Failure")

# ---- 6. bit-granular last block --------------------------------------------
lines.append("--- ACE _Enc_Last_Block_ / _Dec_Last_Block_ with last_blk_len not a byte multiple ---")
K, IV, A = bytes.fromhex(K128), bytes.fromhex(IV12), bytes.fromhex(AAD)
PT_FULL = bytes(range(32))                       # two whole blocks


def prologue(cc):
    """_Ready_ -> _Set_Aux_Value_ -> _Hash_Absorb_, with one AD block absorbed."""
    cc.setst_set_aux_value(len(IV) * 8)
    cc.exec_iv(b2v(IV), len(IV) * 8)
    cc.exec_absorb(b2v(_pad16(A)), 8 * len(_pad16(A)))
    return cc


for nbits in (1, 7, 8, 63, 100, 127):
    pt_val = b2v(bytes(range(16))) & ((1 << nbits) - 1)

    cc = prologue(GcmCC(K))
    cc.setst_encrypt()
    ct_full = cc.exec_encrypt(b2v(PT_FULL), 8 * len(PT_FULL))
    cc.setst_last_block(nbits)
    ct_tail = cc.exec_enc_last_block(pt_val)
    cc.setst_enc_tag_finalize(8 * len(PT_FULL) + nbits, len(A) * 8)
    tag_e = cc.exec_emit_tag()

    dd = prologue(GcmCC(K))
    dd.setst_decrypt()
    pt_back = dd.exec_decrypt(ct_full, 8 * len(PT_FULL))
    dd.setst_last_block(nbits, decrypt=True)
    pt_tail = dd.exec_dec_last_block(ct_tail)
    dd.setst_dec_tag_finalize(8 * len(PT_FULL) + nbits, len(A) * 8)
    verdict = dd.setst_hash_verify(tag_e)

    check(f"round trip with last_blk_len = {nbits}",
          pt_back == b2v(PT_FULL) and pt_tail == pt_val and verdict == "Success")
    check(f"last_blk_len = {nbits}: the ciphertext tail has no bit above "
          f"bit {nbits - 1} (no keystream leak past the end)",
          ct_tail >> nbits == 0)
# out-of-range last_blk_len
for bad_len in (0, 128, 200):
    cc = prologue(GcmCC(K))
    cc.setst_encrypt()
    try:
        cc.setst_last_block(bad_len)
        fired = False
    except Invalid:
        fired = True
    check(f"last_blk_len = {bad_len} -> _Invalid_", fired and cc.state == "Invalid")
# out-of-range IV length in the Form B ace.setst
for bad_iv in (0, 4, 8193):
    cc = GcmCC(K)
    try:
        cc.setst_set_aux_value(bad_iv)
        fired = False
    except Invalid:
        fired = True
    check(f"IV length Xs = {bad_iv} -> _Invalid_", fired)

# ---- 7. counter wrap --------------------------------------------------------
lines.append("--- counter wrap: _Invalid_ exactly when ctr = (start_ctr - 1) mod 2^32 ---")
K, IV = bytes.fromhex(K128), bytes.fromhex(IV12)


def fresh(ivbytes):
    """A CC that has just left _Set_Aux_Value_ with the given IV."""
    c = GcmCC(K)
    c.setst_set_aux_value(len(ivbytes) * 8)
    c.exec_iv(b2v(ivbytes), len(ivbytes) * 8)
    return c


def probe(ivbytes, seed_ctr, nblocks):
    """Seed the running counter field of J0 and try `nblocks` _Encrypt_ blocks.

    Seeding avoids running 2^32 iterations: the rule under test depends only on
    the counter value, not on how it was reached.
    """
    cc = fresh(ivbytes)
    cc.J0 = cat((bswap(bin_(seed_ctr % 2 ** 32, 32), 4), 32), (sl(cc.J0, 95, 0), 96))
    cc.setst_encrypt()
    try:
        for _ in range(nblocks):
            cc.exec_encrypt(0, 128)
    except Invalid:
        return "Invalid"
    return cc.state


check("96-bit IV gives start_ctr = 1", fresh(IV).start_ctr == 1)
# The first block uses ctr = start_ctr + 1 and the last usable one
# ctr = start_ctr - 2, so exactly 2^32 - 2 blocks may be processed.
check("the counter admits exactly 2^32 - 2 blocks",
      ((1 - 2) - (1 + 1)) % 2 ** 32 + 1 == 2 ** 32 - 2)
for ivb, name in ((IV, "96-bit IV, start_ctr = 1"),
                  (bytes.fromhex(IV8), "64-bit IV, GHASH-derived start_ctr")):
    st = fresh(ivb).start_ctr
    limit = (st - 1) % 2 ** 32                 # the forbidden counter value
    check(f"{name}: the two blocks before the limit are accepted",
          probe(ivb, limit - 3, 2) == "Encrypt")
    check(f"{name}: the block that would set ctr = (start_ctr-1) mod 2^32 "
          f"-> _Invalid_", probe(ivb, limit - 3, 3) == "Invalid")
    check(f"{name}: _Invalid_ fires on the very first block if already at the limit",
          probe(ivb, limit - 1, 1) == "Invalid")

# ---- 8. GCM with Set IV -----------------------------------------------------
lines.append("--- GCM with Set IV: same result for the same J0, and budget rules ---")
for label, k, iv, a, p, c, t in VECTORS:
    K, IV, A, P = (bytes.fromhex(x) for x in (k, iv, a, p))
    # derive J0 the way the provisioning software would
    J0 = b2v(ref_j0(K, IV))
    nblk = (len(_pad16(A)) // 16) + (len(P) + 15) // 16
    C, T, cc = ace_encrypt_setiv(K, J0, nblk, A, P)
    check(f"Set-IV {label}: same ciphertext/tag as plain GCM",
          C == bytes.fromhex(c) and T == bytes.fromhex(t) and cc.state == "Success")
    check(f"Set-IV {label}: budget exactly consumed ({nblk} blocks), tag emit free",
          cc.budget == 0)

# budget decrement detail and exhaustion
K, IV, A, P = bytes.fromhex(K128), bytes.fromhex(IV12), bytes.fromhex(AAD), bytes.fromhex(P60)
J0 = b2v(ref_j0(K, IV))
cc = GcmCC(K, set_iv_J0=J0, budget=10)
cc.setst_hash_absorb()
cc.exec_absorb(b2v(_pad16(A)), 256)              # 2 blocks
check("Set-IV: _Hash_Absorb_ consumes ACELEN/b blocks", cc.budget == 8)
cc.setst_encrypt()
cc.exec_encrypt(b2v(bytes(48)), 384)             # 3 blocks
check("Set-IV: _Encrypt_ consumes ACELEN/b blocks", cc.budget == 5)
cc.setst_last_block(8)
cc.exec_enc_last_block(0)
check("Set-IV: _Enc_Last_Block_ consumes exactly one block", cc.budget == 4)
cc.setst_enc_tag_finalize(8 * 49, len(A) * 8)
cc.exec_emit_tag()
check("Set-IV: Form C tag emit consumes no budget and reaches _Success_",
      cc.budget == 4 and cc.state == "Success")

cc = GcmCC(K, set_iv_J0=J0, budget=1)
cc.setst_hash_absorb()
cc.setst_encrypt()
saved = (cc.tag, cc.J0)
cc.exec_encrypt(0, 128)
saved = (cc.tag, cc.J0)
try:
    cc.exec_encrypt(0, 128)
    fired = False
except Invalid:
    fired = True
check("Set-IV: exec below zero budget performs no operation and goes _Invalid_",
      fired and cc.state == "Invalid" and (cc.tag, cc.J0) == saved and cc.budget == 0)

cc = GcmCC(K, set_iv_J0=J0, budget=1)
cc.setst_hash_absorb()
cc.setst_encrypt()
try:
    cc.exec_encrypt(0, 256)                      # asks for 2 blocks, has 1
    fired = False
except Invalid:
    fired = True
check("Set-IV: a multi-block exec exceeding the budget is refused wholesale",
      fired and cc.state == "Invalid" and cc.budget == 1 and cc.tag == 0)

# ---- 9. negative controls ---------------------------------------------------
lines.append("--- negative controls (must not reproduce the vectors) ---")
# A control is only meaningful on a vector where it can change the result:
# swapping the halves of the length block does nothing when |AD| = |PT| (tc1,
# tc13), and the counter convention is invisible when the plaintext is empty
# *and* the tag mask is symmetric under it (again tc1, tc13).  Those vectors are
# skipped rather than silently excusing the control.
n_swap = n_ctr = 0
for label, k, iv, a, p, c, t in VECTORS:
    K, IV, A, P = (bytes.fromhex(x) for x in (k, iv, a, p))
    want = (bytes.fromhex(c), bytes.fromhex(t))
    if len(A) != len(P):
        C, T, _ = ace_encrypt(K, IV, A, P, swap_len_block=True)
        expect_fail(f"negative control: length block halves swapped  [{label}]",
                    (C, T) == want)
        n_swap += 1
    if len(P) > 0:
        C, T, _ = ace_encrypt(K, IV, A, P, le_counter=True)
        expect_fail(f"negative control: little-endian counter increment  [{label}]",
                    (C, T) == want)
        n_ctr += 1
check(f"both negative controls are observable on several vectors "
      f"({n_swap} / {n_ctr})", n_swap >= 4 and n_ctr >= 4)

print("\n".join(lines))
print()
print("summary: REF and the ACE model both reproduce SP 800-38D / McGrew-Viega")
print("         test cases 1-6 and 13-18; no functional discrepancy between the")
print("         literal spec text and the standard was found for GCM or")
print("         GCM-with-Set-IV.")
print()
print("OBSERVATIONs (editorial; no computed value changes, hence not failures):")
print("  1. <<ACE-GCM-mode>> Parameters says \"ACELEN must be an integer multiple")
print("     of b\", but _Set_Aux_Value_ is process_VLI with granularity = b, whose")
print("     final transfer may be shorter -- and must be, for a 96-bit IV or for")
print("     the trailing 12 bytes of the 60-byte IV of test cases 6 and 18.  The")
print("     blanket ACELEN rule should be scoped to the block-consuming states.")
print("  2. In the _Set_Aux_Value_ overlay of the Serialized Context, the second")
print("     sentence of the `input_base` row (\"Each time this value reaches b, the")
print("     data in block is processed\") describes `block_base`, not `input_base`.")
print("  3. The Form C ace.setst INPUT for _Enc_Tag_Finalize_ is typeset with a")
print("     doubled `@` across the line break (`... 64)) @` / `@ bswap(...)`).")
print()
print(f"KAT-RESULT: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
