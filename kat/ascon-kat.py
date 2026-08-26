#!/usr/bin/env python3
"""Known-Answer Tests for the ACE Ascon algorithms against NIST SP 800-232.

WHAT IS UNDER TEST
------------------
The *specification text* of

  <<ACE-Ascon-AEAD128>>            src/ace-ISA-algorithms.adoc
  <<ACE-Ascon-AEAD128-wsn>>        (set nonce + budget)
  <<ACE-Ascon-AEAD128-N-masking>>  (K1 as key, N xor K2 as nonce)
  <<ACE-Ascon-Hash256>>
  <<ACE-Ascon-XOF128>>
  <<ACE-Ascon-CXOF128>>

is transcribed below, clause by clause, into an executable state machine
(classes `AceAsconAEAD128`, `AceAsconSponge`).  Nothing is "fixed up": each
numbered step of the .adoc is reproduced as written, on ACE *values* (little-
endian bit strings held in Python ints, per src/ace-notation.adoc, whose
"Conventions of the Referenced Standards" table records SP 800-232 as
"little-endian throughout ... Direct mapping").

ANCHORING (three levels, in this order)
---------------------------------------
1. The Ascon permutation is implemented from scratch here: the SP 800-232
   round constants are *computed* from their nibble rule (not transcribed from
   a table), the x^5 S-box is applied in its bit-sliced Boolean form, and the
   linear layer uses the five (rot,rot) pairs of SP 800-232 Table 5.
2. `ref_*` below is a plain byte-string SP 800-232 implementation.  It is
   checked against the embedded official vectors.  During development it was
   additionally run against the *complete* official KAT files (1089 AEAD,
   1025 Hash256, 1025 XOF128, 1089 CXOF128 records) with zero mismatches, so
   the interpretation of those files is not in doubt; the subset embedded here
   is representative, not exhaustive.
3. The ACE state-machine model is checked against the official vectors
   directly, and against `ref_*` on the cases official vectors do not cover
   (short tags, budget accounting, squeeze splitting).

VECTOR PROVENANCE
-----------------
All vectors are verbatim from the NIST-final genkat files of the Ascon
reference implementation, github.com/ascon/ascon-c @ main:

  crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt
  crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt
  crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt
  crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt

Each embedded case carries its `Count` from the corresponding file.

SPEC DISCREPANCY MODELLED HERE (review finding m5)
--------------------------------------------------
The intro of <<ACE-Ascon-AEAD128>> says "the caller is responsible for applying
proper padding to the AD and the plaintext ... and for truncating the last
plaintext block".  That contradicts the state machine directly below it:
_Enc_Last_Block_ computes `tmp <- pad(INPUT[last_blk_len-1:0], 128)` and
_Dec_Last_Block_ computes `S_r <- S_r xor pad(P[last_blk_len-1:0], 128)`, i.e.
the final plaintext/ciphertext block is padded *internally*.  A caller obeying
the prose would double-pad and produce wrong ciphertext.  The state machine is
the correct reading and is what this harness models: the caller pads the AD
only; the final PT/CT block goes through _*_Last_Block_ with the internal
pad().  This is reported as a wording bug, not patched here.

Run directly; prints per-case PASS/FAIL and a final `KAT-RESULT:` line.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl, cat, bin_          # noqa: F401  (ACE notation)

M64 = (1 << 64) - 1
M128 = (1 << 128) - 1

# ===================================================================== the permutation
#
# SP 800-232 Sec. 3.  Implemented from scratch.

def _round_constants():
    """The 16 round constants of SP 800-232 Table 4, computed, not transcribed.

    Reading the table, entry j (0-based) is the byte  (15 - l) @ l  where the
    low nibble l = (j + 12) mod 16 and the high nibble is its ones' complement:

        j :  0     1     2     3     4     5   ...  15
        c : 0x3c  0x2d  0x1e  0x0f  0xf0  0xe1 ... 0x4b

    An n-round permutation ASCON(n) uses the LAST n entries, so ASCON(12)
    starts at 0xf0 and ASCON(8) at 0xb4.
    """
    out = []
    for j in range(16):
        l = (j + 12) % 16
        out.append(((15 - l) << 4) | l)
    return out

RC16 = _round_constants()
assert RC16[4] == 0xf0 and RC16[8] == 0xb4 and RC16[15] == 0x4b

def _rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M64

# SP 800-232 Table 5: the linear diffusion rotation pairs.
SIGMA = ((19, 28), (61, 39), (1, 6), (10, 17), (7, 41))

def ascon_p(S, rounds):
    """ASCON(rounds): apply `rounds` rounds of the Ascon permutation to S[0..4]."""
    for c in RC16[16 - rounds:]:
        # p_C : constant addition into x2
        S[2] ^= c
        # p_S : the 5-bit S-box (x^5 over GF(2^5)) in bit-sliced Boolean form
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        t = [((S[i] ^ M64) & S[(i + 1) % 5]) for i in range(5)]
        for i in range(5):
            S[i] ^= t[(i + 1) % 5]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= M64
        # p_L : linear diffusion, x_i ^= rotr(x_i,a) ^ rotr(x_i,b)
        for i, (a, b) in enumerate(SIGMA):
            S[i] ^= _rotr(S[i], a) ^ _rotr(S[i], b)
    return S

# IV constants, quoted verbatim from the .adoc "In State _Ready_" clauses.
IV_AEAD = 0x00001000808c0001      # <<ACE-Ascon-AEAD128>>
IV_HASH = 0x0000080100cc0002      # <<ACE-Ascon-Hash256>>
IV_XOF  = 0x0000080000cc0003      # <<ACE-Ascon-XOF128>>
IV_CXOF = 0x0000080000cc0004      # <<ACE-Ascon-CXOF128>>

# ===================================================================== byte-string reference
#
# Anchor level 2.  Straight SP 800-232, byte strings, no ACE notation.

def _abs_ad(S, ad):
    if not ad:
        return                                   # SP 800-232: empty AD, no absorption
    a = ad + b'\x01' + bytes((-len(ad) - 1) % 16)
    for i in range(0, len(a), 16):
        S[0] ^= b2v(a[i:i + 8]); S[1] ^= b2v(a[i + 8:i + 16])
        ascon_p(S, 8)

def _init(key, nonce):
    k0, k1 = b2v(key[:8]), b2v(key[8:])
    S = [IV_AEAD, k0, k1, b2v(nonce[:8]), b2v(nonce[8:])]
    ascon_p(S, 12)
    S[3] ^= k0; S[4] ^= k1
    return S, k0, k1

def _final(S, k0, k1, tag_len=128):
    S[2] ^= k0; S[3] ^= k1
    ascon_p(S, 12)
    tag = v2b(S[3] ^ k0, 8) + v2b(S[4] ^ k1, 8)
    return tag[:tag_len // 8]

def ref_aead_encrypt(key, nonce, ad, pt, tag_len=128):
    S, k0, k1 = _init(key, nonce)
    _abs_ad(S, ad)
    S[4] ^= 1 << 63
    ct, full = b'', len(pt) // 16 * 16
    for i in range(0, full, 16):
        S[0] ^= b2v(pt[i:i + 8]); S[1] ^= b2v(pt[i + 8:i + 16])
        ct += v2b(S[0], 8) + v2b(S[1], 8)
        ascon_p(S, 8)
    last = pt[full:]
    lp = last + b'\x01' + bytes(15 - len(last))
    S[0] ^= b2v(lp[:8]); S[1] ^= b2v(lp[8:])
    ct += (v2b(S[0], 8) + v2b(S[1], 8))[:len(last)]
    return ct + _final(S, k0, k1, tag_len)

def ref_aead_decrypt(key, nonce, ad, ct_and_tag, tag_len=128):
    tl = tag_len // 8
    ct, tag = ct_and_tag[:-tl], ct_and_tag[-tl:]
    S, k0, k1 = _init(key, nonce)
    _abs_ad(S, ad)
    S[4] ^= 1 << 63
    pt, full = b'', len(ct) // 16 * 16
    for i in range(0, full, 16):
        c0, c1 = b2v(ct[i:i + 8]), b2v(ct[i + 8:i + 16])
        pt += v2b(S[0] ^ c0, 8) + v2b(S[1] ^ c1, 8)
        S[0], S[1] = c0, c1
        ascon_p(S, 8)
    last = ct[full:]
    n = 8 * len(last)
    Sr = (S[1] << 64) | S[0]
    p = (Sr ^ b2v(last)) & ((1 << n) - 1) if n else 0
    pt += v2b(p, len(last))
    Sr ^= (1 << n) | p                            # xor pad(P,128)
    S[0], S[1] = Sr & M64, (Sr >> 64) & M64
    return _final(S, k0, k1, tag_len) == tag, pt

def _ref_squeeze(S, outlen):
    out = b''
    while len(out) < outlen:
        out += v2b(S[0], 8)
        if len(out) < outlen:
            ascon_p(S, 12)
    return out[:outlen]

def ref_sponge(iv, msg, outlen, prefix=b''):
    S = [iv, 0, 0, 0, 0]
    ascon_p(S, 12)
    m = prefix + msg + b'\x01' + bytes((-len(msg) - 1) % 8)
    for i in range(0, len(m), 8):
        S[0] ^= b2v(m[i:i + 8]); ascon_p(S, 12)
    return _ref_squeeze(S, outlen)

def ref_hash256(msg):
    return ref_sponge(IV_HASH, msg, 32)

def ref_xof128(msg, outlen=64):
    return ref_sponge(IV_XOF, msg, outlen)

def cxof_prefix(z):
    """SP 800-232 Sec. 5.3: Ascon-CXOF128 absorbs len(Z) as a 64-bit LE integer,
    then Z padded to the 64-bit rate, before the message.  <<ACE-Ascon-CXOF128>>
    leaves "the management and padding of the customization string ... to the
    caller", so in the ACE model this prefix is caller-supplied absorbed data."""
    return v2b(8 * len(z), 8) + z + b'\x01' + bytes((-len(z) - 1) % 8)

def ref_cxof128(msg, z, outlen=64):
    return ref_sponge(IV_CXOF, msg, outlen, prefix=cxof_prefix(z))

# ===================================================================== ACE model: helpers

class Invalid(Exception):
    """The CR transitioned to Error State _Invalid_."""

def ace_pad(x, n, r=128):
    """The spec's `pad(x,r) = 0^j @ 1 @ x`, j = (-|x|-1) mod r, on ACE values.
    With |x| = n < r this is exactly (1 << n) | x, an r-bit value."""
    j = (-n - 1) % r
    assert j + 1 + n == r
    return cat((0, j), (1, 1), (x & ((1 << n) - 1), n))

# ===================================================================== ACE model: Ascon-AEAD128

class AceAsconAEAD128:
    """<<ACE-Ascon-AEAD128>>, and via flags <<ACE-Ascon-AEAD128-wsn>>.

    Every method is one architectural instruction; `self.st` is the _State_
    field.  `dsep_wrong_word` is the negative control of this harness.
    """

    def __init__(self, key, nonce=None, budget=None, dsep_wrong_word=False):
        # -- State _Ready_ : the initialization operations, verbatim
        self.key = key & M128
        self.k0 = sl(self.key, 63, 0)
        self.k1 = sl(self.key, 127, 64)
        self.s = [IV_AEAD, self.k0, self.k1, 0, 0]
        self.tag_len = 128
        self.last_blk_len = 0
        self.st = 'Ready'
        self.dsep_wrong_word = dsep_wrong_word
        # -- <<ACE-Ascon-AEAD128-wsn>>: the nonce comes from the PI, and words
        #    3 and 4 of `state` are initialized from it in State _Ready_.
        self.set_nonce = nonce is not None
        self.budget = budget
        if self.set_nonce:
            self.s[3] = sl(nonce, 63, 0)
            self.s[4] = sl(nonce, 127, 64)

    # ---- budget bookkeeping (<<ACE-Ascon-AEAD128-wsn>>)
    def _spend(self, blocks):
        if self.budget is None:
            return
        if self.budget - blocks < 0:
            # "performs no operation, and the CR transitions to Error State _Invalid_"
            self.st = 'Invalid'
            raise Invalid('budget exhausted')
        self.budget -= blocks

    # ---- Form B ace.setst #ace_state_set_aux_value : tag_len
    def setst_tag_len(self, Xs):
        assert self.st == 'Ready'
        if not (64 <= Xs <= 128):
            self.st = 'Invalid'
            raise Invalid('tag_len out of range')
        self.tag_len = Xs                     # the _State_ field is unchanged

    # ---- transition Ready -> Hash_Absorb
    def setst_start(self, INPUT=None, acelen=128):
        assert self.st == 'Ready'
        if self.set_nonce:
            # Form A: no additional inputs; state[3..4] already hold the nonce.
            assert INPUT is None
        else:
            # Form C: "If ACELEN > 128, only the 128 lsbs of INPUT are considered."
            assert INPUT is not None
            n = INPUT & M128
            self.s[3] = sl(n, 63, 0)
            self.s[4] = sl(n, 127, 64)
        ascon_p(self.s, 12)
        self.s[3] ^= self.k0
        self.s[4] ^= self.k1
        self.st = 'Hash_Absorb'

    # ---- State _Hash_Absorb_, Form B ace.exec
    def exec_ad(self, INPUT, acelen):
        assert self.st == 'Hash_Absorb'
        assert acelen % 128 == 0 and acelen > 0
        nblk = acelen // 128
        self._spend(nblk)
        for i in range(nblk):
            blk = sl(INPUT, 128 * i + 127, 128 * i)
            self.s[0] ^= sl(blk, 63, 0)
            self.s[1] ^= sl(blk, 127, 64)
            ascon_p(self.s, 8)

    # ---- domain separation on entering _Encrypt_ / _Decrypt_
    def _enter(self, which):
        assert self.st == 'Hash_Absorb'
        if self.dsep_wrong_word:
            self.s[0] ^= (1 << 63)            # NEGATIVE CONTROL: wrong word
        else:
            self.s[4] ^= (1 << 63)            # spec: state[4] xor (1 << 63)
        self.st = which

    def enter_encrypt(self):
        self._enter('Encrypt')

    def enter_decrypt(self):
        self._enter('Decrypt')

    # ---- State _Encrypt_, Form A ace.exec
    def exec_encrypt(self, INPUT, acelen):
        assert self.st == 'Encrypt'
        assert acelen % 128 == 0 and acelen > 0
        nblk = acelen // 128
        self._spend(nblk)
        OUT = 0
        for i in range(nblk):
            blk = sl(INPUT, 128 * i + 127, 128 * i)
            self.s[0] ^= sl(blk, 63, 0)
            self.s[1] ^= sl(blk, 127, 64)
            OUT |= cat((self.s[1], 64), (self.s[0], 64)) << (128 * i)
            ascon_p(self.s, 8)
        return OUT

    # ---- transition to _Enc_Last_Block_ / _Dec_Last_Block_
    def setst_last_blk_len(self, Xs):
        assert self.st in ('Encrypt', 'Decrypt')
        if Xs > 127:
            self.st = 'Invalid'
            raise Invalid('last_blk_len > 127')
        nxt = 'Hash_Output' if self.st == 'Encrypt' else 'Hash_Verify'
        if Xs == 0:
            # pad(EMPTY,128) = zeros(127) @ 1, absorbed directly.  This is the
            # "Xs = 0 direct pad path" exercised by exact-block-multiple inputs.
            self.s[0] ^= 1
            self.last_blk_len = 0
            self.st = nxt
        else:
            self.last_blk_len = Xs
            self.st = 'Enc_Last_Block' if nxt == 'Hash_Output' else 'Dec_Last_Block'

    # ---- State _Enc_Last_Block_, Form A ace.exec, exactly one block
    def exec_enc_last(self, INPUT):
        assert self.st == 'Enc_Last_Block' and self.last_blk_len
        self._spend(1)
        L = self.last_blk_len
        tmp = ace_pad(sl(INPUT, L - 1, 0), L, 128)
        self.s[0] ^= sl(tmp, 63, 0)
        self.s[1] ^= sl(tmp, 127, 64)
        tmp = cat((self.s[1], 64), (self.s[0], 64))
        OUT = cat((0, 128 - L), (sl(tmp, L - 1, 0), L))
        self.st = 'Hash_Output'
        return OUT

    # ---- State _Decrypt_, Form A ace.exec
    def exec_decrypt(self, INPUT, acelen):
        assert self.st == 'Decrypt'
        assert acelen % 128 == 0 and acelen > 0
        nblk = acelen // 128
        self._spend(nblk)
        OUT = 0
        for i in range(nblk):
            blk = sl(INPUT, 128 * i + 127, 128 * i)
            tmp = cat((self.s[1] ^ sl(blk, 127, 64), 64),
                      (self.s[0] ^ sl(blk, 63, 0), 64))
            self.s[0] = sl(blk, 63, 0)
            self.s[1] = sl(blk, 127, 64)
            ascon_p(self.s, 8)
            OUT |= tmp << (128 * i)
        return OUT

    # ---- State _Dec_Last_Block_, Form A ace.exec, exactly one block
    def exec_dec_last(self, INPUT):
        assert self.st == 'Dec_Last_Block' and self.last_blk_len
        self._spend(1)
        L = self.last_blk_len
        S_r = cat((self.s[1], 64), (self.s[0], 64))
        P = cat((0, 128 - L), (sl(S_r, L - 1, 0) ^ sl(INPUT, L - 1, 0), L))
        OUT = P
        S_r ^= ace_pad(sl(P, L - 1, 0), L, 128)
        self.s[0] = sl(S_r, 63, 0)
        self.s[1] = sl(S_r, 127, 64)
        self.st = 'Hash_Verify'
        return OUT

    # ---- the common tag computation of _Hash_Output_ / _Hash_Verify_
    def _tag(self):
        self.s[2] ^= self.k0
        self.s[3] ^= self.k1
        ascon_p(self.s, 12)
        self.s[3] ^= self.k0
        self.s[4] ^= self.k1
        return cat((self.s[4], 64), (self.s[3], 64))

    # ---- State _Hash_Output_, Form C ace.exec (does NOT decrement budget)
    def exec_tag(self):
        assert self.st == 'Hash_Output'
        t = self._tag()
        OUT = cat((0, 128 - self.tag_len), (sl(t, self.tag_len - 1, 0), self.tag_len))
        self.st = 'Success'
        return OUT

    # ---- State _Hash_Verify_, Form B ace.exec (does NOT decrement budget)
    def exec_verify(self, INPUT):
        assert self.st == 'Hash_Verify'
        t = self._tag()
        ok = sl(INPUT, self.tag_len - 1, 0) == sl(t, self.tag_len - 1, 0)
        self.st = 'Success' if ok else 'Failure'
        return ok

# --------------------------------------------------------- ACE driver sequences

def pad_ad_caller(ad):
    """The caller's obligation (finding m5: the AD, and only the AD)."""
    if not ad:
        return b''
    return ad + b'\x01' + bytes((-len(ad) - 1) % 16)

def ace_encrypt(key, nonce, ad, pt, tag_len=128, ad_chunk=1, pt_chunk=1,
                budget=None, set_nonce=False, dsep_wrong_word=False):
    """Drive the ACE state machine through a full encryption.

    `ad_chunk` / `pt_chunk` are the number of 128-bit blocks per ace.exec, i.e.
    ACELEN / 128, which exercises the multi-block forms of the .adoc clauses.
    Returns (ciphertext_bytes, tag_bytes, cc).
    """
    nv = b2v(nonce)
    cc = AceAsconAEAD128(b2v(key), nonce=nv if set_nonce else None,
                         budget=budget, dsep_wrong_word=dsep_wrong_word)
    if tag_len != 128:
        cc.setst_tag_len(tag_len)
    cc.setst_start(None if set_nonce else nv)

    a = pad_ad_caller(ad)
    for i in range(0, len(a), 16 * ad_chunk):
        chunk = a[i:i + 16 * ad_chunk]
        cc.exec_ad(b2v(chunk), 8 * len(chunk))
    cc.enter_encrypt()

    ct, full = b'', len(pt) // 16 * 16
    for i in range(0, full, 16 * pt_chunk):
        chunk = pt[i:min(i + 16 * pt_chunk, full)]
        out = cc.exec_encrypt(b2v(chunk), 8 * len(chunk))
        ct += v2b(out, len(chunk))
    last = pt[full:]
    cc.setst_last_blk_len(8 * len(last))
    if last:
        ct += v2b(sl(cc.exec_enc_last(b2v(last)), 8 * len(last) - 1, 0), len(last))
    tag = v2b(cc.exec_tag(), 16)[:tag_len // 8]
    return ct, tag, cc

def ace_encrypt_masked(K1, K2, N, ad, pt, **kw):
    """<<ACE-Ascon-AEAD128-N-masking>>, modelled exactly as the .adoc defines it:
    "the same states as Ascon-AEAD128 ... with the key `key` equal to `K1` and
    the nonce `N` replaced throughout by `N xor K2`".  The masking therefore
    lives entirely in the PI/initialization; no other clause changes."""
    Nm = bytes(a ^ b for a, b in zip(N, K2))
    return ace_encrypt(K1, Nm, ad, pt, **kw)

def ace_decrypt_masked(K1, K2, N, ad, ct, tag, **kw):
    Nm = bytes(a ^ b for a, b in zip(N, K2))
    return ace_decrypt(K1, Nm, ad, ct, tag, **kw)

def ace_decrypt(key, nonce, ad, ct, tag, tag_len=128, ad_chunk=1, pt_chunk=1,
                budget=None, set_nonce=False):
    """Drive the ACE state machine through a full decryption + Hash_Verify.
    Returns (ok, plaintext_bytes, cc)."""
    nv = b2v(nonce)
    cc = AceAsconAEAD128(b2v(key), nonce=nv if set_nonce else None, budget=budget)
    if tag_len != 128:
        cc.setst_tag_len(tag_len)
    cc.setst_start(None if set_nonce else nv)

    a = pad_ad_caller(ad)
    for i in range(0, len(a), 16 * ad_chunk):
        chunk = a[i:i + 16 * ad_chunk]
        cc.exec_ad(b2v(chunk), 8 * len(chunk))
    cc.enter_decrypt()

    pt, full = b'', len(ct) // 16 * 16
    for i in range(0, full, 16 * pt_chunk):
        chunk = ct[i:min(i + 16 * pt_chunk, full)]
        out = cc.exec_decrypt(b2v(chunk), 8 * len(chunk))
        pt += v2b(out, len(chunk))
    last = ct[full:]
    cc.setst_last_blk_len(8 * len(last))
    if last:
        pt += v2b(sl(cc.exec_dec_last(b2v(last)), 8 * len(last) - 1, 0), len(last))
    ok = cc.exec_verify(b2v(tag))
    return ok, pt, cc

# ===================================================================== ACE model: sponges

class AceAsconSponge:
    """<<ACE-Ascon-Hash256>>, <<ACE-Ascon-XOF128>>, <<ACE-Ascon-CXOF128>>.

    The three differ only in the IV and in whether `countdown` is used, exactly
    as the .adoc states.  Rate b = 64.
    """

    def __init__(self, iv, use_countdown):
        # State _Ready_
        self.s = [iv, 0, 0, 0, 0]
        ascon_p(self.s, 12)
        self.use_countdown = use_countdown
        self.countdown = None
        self.st = 'Hash_Absorb'
        self._first = True        # XOF/CXOF: no permutation before the 1st word

    # ---- State _Hash_Absorb_, Form B ace.exec
    def exec_absorb(self, INPUT, acelen):
        assert self.st == 'Hash_Absorb'
        assert acelen % 64 == 0 and acelen > 0
        for i in range(acelen // 64):
            self.s[0] ^= sl(INPUT, 64 * i + 63, 64 * i)
            ascon_p(self.s, 12)

    # ---- transition into _Hash_Finalize_
    def enter_finalize(self):
        assert self.st == 'Hash_Absorb'
        self.st = 'Hash_Finalize'
        if self.use_countdown:
            self.countdown = 3

    # ---- State _Hash_Finalize_, Form C ace.exec
    def exec_squeeze(self, acelen):
        assert self.st == 'Hash_Finalize'
        assert acelen % 64 == 0 and acelen > 0
        OUT, nwords = 0, acelen // 64
        for i in range(nwords):
            if self.use_countdown:
                if self.countdown != 3:
                    ascon_p(self.s, 12)
            else:
                if not self._first:
                    ascon_p(self.s, 12)
            OUT |= self.s[0] << (64 * i)
            if self.use_countdown:
                if self.countdown == 0:
                    self.st = 'Success'
                    return OUT, (i + 1) * 8      # remaining words undefined
                self.countdown -= 1
            self._first = False
        return OUT, nwords * 8

def ace_hash256(msg, absorb_chunk=1, squeeze_acelen=256):
    """Drive Ascon-Hash256.  `squeeze_acelen` selects 1, 2, or 4 ace.exec's."""
    cc = AceAsconSponge(IV_HASH, use_countdown=True)
    m = msg + b'\x01' + bytes((-len(msg) - 1) % 8)
    for i in range(0, len(m), 8 * absorb_chunk):
        chunk = m[i:i + 8 * absorb_chunk]
        cc.exec_absorb(b2v(chunk), 8 * len(chunk))
    cc.enter_finalize()
    out = b''
    while len(out) < 32:
        v, n = cc.exec_squeeze(squeeze_acelen)
        out += v2b(v & ((1 << (8 * n)) - 1), n)
    assert cc.st == 'Success'
    return out[:32]

def ace_xof(iv, msg, outlen, prefix=b'', absorb_chunk=1, squeeze_acelen=64):
    cc = AceAsconSponge(iv, use_countdown=False)
    m = prefix + msg + b'\x01' + bytes((-len(msg) - 1) % 8)
    for i in range(0, len(m), 8 * absorb_chunk):
        chunk = m[i:i + 8 * absorb_chunk]
        cc.exec_absorb(b2v(chunk), 8 * len(chunk))
    cc.enter_finalize()
    out = b''
    while len(out) < outlen:
        v, n = cc.exec_squeeze(squeeze_acelen)
        out += v2b(v & ((1 << (8 * n)) - 1), n)
    assert cc.st == 'Hash_Finalize'          # never transitions to _Success_
    return out[:outlen]

def ace_xof128(msg, outlen=64, **kw):
    return ace_xof(IV_XOF, msg, outlen, **kw)

def ace_cxof128(msg, z, outlen=64, **kw):
    # <<ACE-Ascon-CXOF128>>: "the message is prepended with the customization
    # string"; its management and padding are the caller's job.
    return ace_xof(IV_CXOF, msg, outlen, prefix=cxof_prefix(z), **kw)

# ===================================================================== vectors
#
# github.com/ascon/ascon-c @ main,
# crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt
# (CT includes the 128-bit tag as its last 16 bytes)

AEAD_KAT = [
    # (Count, AD hex, PT hex, CT||tag hex, description)
    (1,    "", "",
     "4f9c278211bec9316bf68f46ee8b2ec6",
     "empty AD, empty PT (Xs=0 direct pad path, no AD permutation)"),
    (17,   "303132333435363738393a3b3c3d3e3f", "",
     "e4230cdb8330ee9dc0cfd7c7b346e6dc",
     "one full AD block, empty PT"),
    (166,  "", "2021222324",
     "e8c3deee2421812a398a8ff074c8b7da46c82a94a7",
     "empty AD, partial PT (5 bytes -> Enc_Last_Block)"),
    (235,  "303132", "20212223242526",
     "66d0d52bf401c64cfccea25bb53cef292120521d154bf4",
     "partial AD, partial PT"),
    (511,  "303132333435363738393a3b3c3d3e", "202122232425262728292a2b2c2d2e",
     "20fd19dabc1a5cc449a621d34dac60d7f316f7f9aee44f263c8d7b7094c199",
     "15-byte AD and PT (both one short of the rate)"),
    (529,  "", "202122232425262728292a2b2c2d2e2f",
     "e8c3deee246cc5eae3e872313897a2bb9eaa915c9dd3245d77048f24d46d27a7",
     "empty AD, exactly one PT block (Xs=0 pad path)"),
    (545,  "303132333435363738393a3b3c3d3e3f", "202122232425262728292a2b2c2d2e2f",
     "6373ebb28be97c9bac090cf399c13ef13abfc0d209e8f4844c90814d13f32c59",
     "one full AD block, one full PT block"),
    (579,  "303132333435363738393a3b3c3d3e3f40", "202122232425262728292a2b2c2d2e2f30",
     "bf77c71b3de9f1c5b372ef273a08e89be9d507d7b3c2aee97911e791f7970d6635",
     "17-byte AD and PT: full block + 1-byte partial final block each"),
    (1055, "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e",
     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e",
     "4b392e5fa60e0cbbca547db96e3262bd8382d6c0e608e24f441aaafc4726e57640e8294794dd3c2aa021192b091de3",
     "31-byte AD and PT: multi-block with partial final block"),
    (1057, "", "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
     "e8c3deee246cc5eae3e872313897a2bb6089aa3e15e80307970f2d1f006654c2aaa5fa172cb9f07d07463cefc7440bc1",
     "empty AD, exactly two PT blocks (Xs=0 pad path, multi-block)"),
    (1089, "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
     "cb34d04660a66dbfbe9c856601f5b8aa51a499b55ac8f7fbefbc331a613ee9cdfd191750a47f211c0a15ed28173d7caa",
     "two full AD blocks, two full PT blocks"),
]
KAT_KEY   = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
KAT_NONCE = bytes.fromhex("101112131415161718191a1b1c1d1e1f")

# crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt
HASH_KAT = [
    (1,  "", "0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2"),
    (2,  "00", "0728621035af3ed2bca03bf6fde900f9456f5330e4b5ee23e7f6a1e70291bc80"),
    (9,  "0001020304050607",
     "b88e497ae8e6fb641b87ef622eb8f2fca0ed95383f7ffebe167acf1099ba764f"),
    (33, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "bd9d3d60a66b53868eab2a5c74539a518a1f60f01eb176c60e43dee81680b33e"),
    (65, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
     "a6f241bea5d16405812c06019d9f72d60132bd7c089c60549b2e56bb01c64f48"),
]

# crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt  (MD is 64 bytes = 512 bits)
XOF_KAT = [
    (1,  "", "473d5e6164f58b39dfd84aacdb8ae42ec2d91fed33388ee0d960d9b3993295c6"
             "ad77855a5d3b13fe6ad9e6098988373af7d0956d05a8f1665d2c67d1a3ad10ff"),
    (2,  "00", "51430e0438ecdf642b393630d977625f5f337656ba58ab1e960784ac32a16e0d"
               "446405551f5469384f8ea283cf12e64fa72c426bfebaea3aa1529e2c4ab23a2f"),
    (9,  "0001020304050607",
     "8d1886f5d3ec4af8d15b44bc62b74da6ea91bc28fb82f9c34079b5ed6e38b6c9"
     "51803d7dfb3c5e512a0ef5e4060062a6fd067f9c73ef9bee527411bda67fc896"),
    (33, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "2e5f3403f4171471cc7934b51982cece8d6628435db70e89880f3be4e0b7b052"
     "32dfe63c44a836d771337c9c5a2688d1b71ecabe0d5c2006fef36ef3186138ad"),
    (65, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
     "0865c2fa92c71058e79e5c4214f3a1505540411586920536ccee85fbf2940b9f"
     "0131385ffe92f15f35bd35373f14d8bf11f078d9850096016f857d27575da423"),
]

# crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt
CXOF_KAT = [
    (1,   "", "", "4f50159ef70bb3dad8807e034eaebd44c4fa2cbbc8cf1f05511ab66cdcc52990"
                  "5ca12083fc186ad899b270b1473dc5f7ec88d1052082dcdfe69fb75d269e7b74"),
    (2,   "", "10", "0c93a483e7d574d49fe52cce03ee646117977d57a8aa57704ab4daf44b501430"
                    "ff6ac11a5d1fd6f2154b5c65728268270c8bb578508487b8965718ada6272fd6"),
    (18,  "", "101112131415161718191a1b1c1d1e1f20",
     "f74d02f0215e2c5e71a89e2315a533f64843223a368df68b0f2d3603bdba664f"
     "2297abd5ea4edf25004d7c7e1093c53212eb7c231a6142aa9fbe3a74cff7a378"),
    (35,  "00", "10", "63fa8ba86382f2d544580f51322d080424b42c556eb74503cd73cf052bb993bd"
                      "6f5210984c71c9c445f43ccc5b158226e509bd339cd634414377f79411aa8d5c"),
    (100, "000102", "",
     "1093da88c318f6d9f26e1a222dbc30016d03953edfd9ba3d75d7d8451b9df542"
     "d7d00745922b271a911fdc5209f6e63fc3d3a279c65b78d4f3c84bf3aaeb8493"),
    (290, "0001020304050607", "101112131415161718191a1b1c1d1e1f202122232425262728",
     "3e0fe4a71142cc010189456cde8b13b753bc9352130c93e33f082cf398492841"
     "ec0ca2f96d03a9e56e7b84523771aaa726d7fd32e0d82882c7709cac22be8f44"),
]

# ===================================================================== harness

_ok = True
_n = 0

def chk(name, got, want):
    global _ok, _n
    _n += 1
    good = (got == want)
    _ok = _ok and good
    print(f"  {'PASS' if good else 'FAIL'}  {name}")
    if not good:
        print(f"          got  {got}")
        print(f"          want {want}")
    return good

def chk_fails(name, got, want):
    """A check that is *expected* to differ (negative control)."""
    global _ok, _n
    _n += 1
    fired = (got != want)
    _ok = _ok and fired
    print(f"  {'FAIL' if fired else 'PASS'}  {name}")
    if not fired:
        print("          negative control did not fire: the test has no power")
    return fired

def main():
    h = bytes.fromhex

    # ---------------------------------------------------------- level 1: permutation
    print("Ascon permutation, SP 800-232 Sec. 3 (built from scratch)")
    chk("round constants ASCON(12) start at 0xf0, ASCON(8) at 0xb4",
        (RC16[16 - 12], RC16[16 - 8]), (0xf0, 0xb4))
    # The permutation is an involution-free bijection; a cheap structural check
    # is that ASCON(12) of the all-zero state is the well-known constant that
    # falls out of the Ascon-XOF128 IV path; it is anchored by the vectors below.
    S = [0, 0, 0, 0, 0]
    ascon_p(S, 12)
    chk("ASCON(12) on the zero state is non-degenerate",
        len({x for x in S}) == 5 and all(x != 0 for x in S), True)

    # ---------------------------------------------------------- level 2: byte reference
    print("\nByte-string SP 800-232 reference vs official vectors")
    print("  (during development this same code matched ALL 1089/1025/1025/1089")
    print("   records of the four official KAT files; the subset below is embedded)")
    for count, ad, pt, ct, desc in AEAD_KAT:
        chk(f"ref  AEAD  LWC_AEAD_KAT_128_128 Count={count:<4} {desc}",
            ref_aead_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt)).hex(), ct)
    for count, msg, md in HASH_KAT:
        chk(f"ref  Hash256  LWC_HASH_KAT_128_256 Count={count}", ref_hash256(h(msg)).hex(), md)
    for count, msg, md in XOF_KAT:
        chk(f"ref  XOF128   LWC_XOF_KAT_128_512  Count={count}", ref_xof128(h(msg), 64).hex(), md)
    for count, msg, z, md in CXOF_KAT:
        chk(f"ref  CXOF128  LWC_CXOF_KAT_128_512 Count={count}",
            ref_cxof128(h(msg), h(z), 64).hex(), md)

    # ---------------------------------------------------------- level 3: ACE model
    print("\n<<ACE-Ascon-AEAD128>> state machine vs official vectors")
    for count, ad, pt, ctt, desc in AEAD_KAT:
        ct, tag, cc = ace_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt))
        chk(f"enc  Count={count:<4} {desc}", (ct + tag).hex(), ctt)
        chk(f"     Count={count:<4} final State = Success", cc.st, "Success")

    print("\n  multi-block ace.exec (ACELEN = 256 and 384) gives identical results")
    for count, ad, pt, ctt, _ in AEAD_KAT:
        ct, tag, _ = ace_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt), ad_chunk=2, pt_chunk=3)
        chk(f"enc  Count={count:<4} ACELEN=256(AD)/384(PT)", (ct + tag).hex(), ctt)

    print("\nDecryption path: _Decrypt_ / _Dec_Last_Block_ / _Hash_Verify_")
    for count, ad, pt, ctt, desc in AEAD_KAT:
        blob = h(ctt)
        ct, tag = blob[:-16], blob[-16:]
        ok, rec, cc = ace_decrypt(KAT_KEY, KAT_NONCE, h(ad), ct, tag)
        chk(f"dec  Count={count:<4} plaintext recovered", rec.hex(), pt)
        chk(f"dec  Count={count:<4} Hash_Verify -> Success", (ok, cc.st), (True, "Success"))
        # tampered tag must land in _Failure_
        bad = bytearray(tag); bad[3] ^= 0x80
        ok2, _, cc2 = ace_decrypt(KAT_KEY, KAT_NONCE, h(ad), ct, bytes(bad))
        chk(f"dec  Count={count:<4} tampered tag -> Failure", (ok2, cc2.st), (False, "Failure"))
        if ct:
            # tampered ciphertext must also fail
            bad = bytearray(ct); bad[0] ^= 0x01
            ok3, _, cc3 = ace_decrypt(KAT_KEY, KAT_NONCE, h(ad), bytes(bad), tag)
            chk(f"dec  Count={count:<4} tampered ciphertext -> Failure",
                (ok3, cc3.st), (False, "Failure"))

    print("\nRound-trip over every partial-block length 0..47 (AD 0/5/16/23)")
    rt_ok = True
    for la in (0, 5, 16, 23):
        for lp in range(0, 48):
            ad = bytes((i * 11 + 1) & 0xff for i in range(la))
            pt = bytes((i * 7 + 3) & 0xff for i in range(lp))
            ct, tag, _ = ace_encrypt(KAT_KEY, KAT_NONCE, ad, pt)
            ok, rec, cc = ace_decrypt(KAT_KEY, KAT_NONCE, ad, ct, tag)
            rt_ok &= ok and rec == pt and cc.st == "Success"
            # and the ACE model must agree with the byte-string reference
            rt_ok &= (ct + tag) == ref_aead_encrypt(KAT_KEY, KAT_NONCE, ad, pt)
    chk("ACE decrypt(encrypt(x)) == x and ACE == reference, 192 length pairs",
        rt_ok, True)

    print("\ntag_len truncation semantics (SP 800-232 permits tag_len >= 64;")
    print("  the official KATs use 128, so 64/96 are checked for self-consistency:")
    print("  OUTPUT = zeros(128-tag_len) @ tag[tag_len-1:0], i.e. the FIRST")
    print("  tag_len/8 bytes of the 128-bit tag under the ACE value mapping)")
    ad, pt = h("30313233"), h("202122232425262728292a2b2c2d2e2f30")
    _, tag128, _ = ace_encrypt(KAT_KEY, KAT_NONCE, ad, pt)
    for tl in (64, 96, 128):
        ct, tag, cc = ace_encrypt(KAT_KEY, KAT_NONCE, ad, pt, tag_len=tl)
        chk(f"tag_len={tl:<3} emitted tag == tag128[:{tl // 8}]", tag.hex(), tag128[:tl // 8].hex())
        ok, rec, cc2 = ace_decrypt(KAT_KEY, KAT_NONCE, ad, ct, tag, tag_len=tl)
        chk(f"tag_len={tl:<3} verify accepts, plaintext recovered",
            (ok, rec == pt, cc2.st), (True, True, "Success"))
        bad = bytearray(tag); bad[0] ^= 0x01
        ok2, _, cc3 = ace_decrypt(KAT_KEY, KAT_NONCE, ad, ct, bytes(bad), tag_len=tl)
        chk(f"tag_len={tl:<3} verify rejects a flipped bit inside the tag",
            (ok2, cc3.st), (False, "Failure"))
    for tl in (0, 8, 63, 129, 255):
        cc = AceAsconAEAD128(b2v(KAT_KEY))
        try:
            cc.setst_tag_len(tl)
            got = "accepted"
        except Invalid:
            got = "Invalid"
        chk(f"tag_len={tl:<3} rejected (spec: 64 <= Xs <= 128)", (got, cc.st),
            ("Invalid", "Invalid"))

    print("\nlast_blk_len bounds: Xs > 127 -> Error State _Invalid_")
    for xs in (128, 129, 255):
        cc = AceAsconAEAD128(b2v(KAT_KEY))
        cc.setst_start(b2v(KAT_NONCE))
        cc.enter_encrypt()
        try:
            cc.setst_last_blk_len(xs)
            got = "accepted"
        except Invalid:
            got = "Invalid"
        chk(f"Xs={xs:<4} -> Invalid", (got, cc.st), ("Invalid", "Invalid"))

    # ---------------------------------------------------------- set-nonce variant
    print("\n<<ACE-Ascon-AEAD128-wsn>>: PI-carried nonce and the budget mechanism")
    for count, ad, pt, ctt, desc in AEAD_KAT:
        ct, tag, cc = ace_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt),
                                  set_nonce=True, budget=64)
        chk(f"set-nonce  Count={count:<4} same ciphertext as base algorithm",
            (ct + tag).hex(), ctt)
    # budget accounting: exactly ACELEN/128 per consuming exec, 1 per last block,
    # and neither _Hash_Output_ nor _Hash_Verify_ decrements it.
    ad = h("303132333435363738393a3b3c3d3e3f40")     # 17 B -> 2 padded AD blocks
    pt = h("202122232425262728292a2b2c2d2e2f30")     # 17 B -> 1 full + 1 last blk
    _, _, cc = ace_encrypt(KAT_KEY, KAT_NONCE, ad, pt, set_nonce=True, budget=100)
    chk("budget: 2 AD + 1 PT + 1 Enc_Last_Block = 4 blocks spent; tag-emit free",
        cc.budget, 96)
    ct, tag, _ = ace_encrypt(KAT_KEY, KAT_NONCE, ad, pt, set_nonce=True, budget=100)
    _, _, ccd = ace_decrypt(KAT_KEY, KAT_NONCE, ad, ct, tag, set_nonce=True, budget=100)
    chk("budget: decrypt spends the same 4 blocks; Hash_Verify free", ccd.budget, 96)
    # exactly-enough budget succeeds
    ct2, tag2, cc2 = ace_encrypt(KAT_KEY, KAT_NONCE, ad, pt, set_nonce=True, budget=4)
    chk("budget = 4 exactly: completes, budget hits 0", (cc2.budget, cc2.st, ct2 + tag2),
        (0, "Success", ct + tag))
    # one short must trap
    for b in (0, 1, 2, 3):
        try:
            ace_encrypt(KAT_KEY, KAT_NONCE, ad, pt, set_nonce=True, budget=b)
            got = ("completed", None)
        except Invalid as e:  # noqa: F841
            got = ("Invalid", "Invalid")
        chk(f"budget = {b} (< 4 needed): no operation, Error State Invalid",
            got, ("Invalid", "Invalid"))
    # multi-block exec spends ACELEN/128
    cc = AceAsconAEAD128(b2v(KAT_KEY), nonce=b2v(KAT_NONCE), budget=10)
    cc.setst_start()
    cc.exec_ad(0, 384)
    chk("budget: one ace.exec with ACELEN=384 spends 3 blocks", cc.budget, 7)
    # "No transition back to State _Ready_ is allowed": once the state machine
    # has run to _Success_ the CC is spent, and a second setst_start (which would
    # reinstall the same nonce and reuse the keystream) must not be accepted.
    _, _, spent = ace_encrypt(KAT_KEY, KAT_NONCE, ad, pt, set_nonce=True, budget=100)
    try:
        spent.setst_start()
        reused = True
    except AssertionError:
        reused = False
    chk("set-nonce CC in _Success_ cannot be restarted (no return to _Ready_)",
        (spent.st, reused), ("Success", False))

    # ---------------------------------------------------------- nonce masking
    print("\n<<ACE-Ascon-AEAD128-N-masking>>: key = K1, nonce = N xor K2")
    K1 = h("0f0e0d0c0b0a09080706050403020100")
    K2 = h("a5a4a3a2a1a09f9e9d9c9b9a99989796")
    N = KAT_NONCE
    Nm = bytes(a ^ b for a, b in zip(N, K2))

    # (a) Hard anchor: with K2 = 0 the masked algorithm must reproduce the
    #     official Ascon-AEAD128 vectors exactly, key = the KAT key.
    Z16 = bytes(16)
    for count, ad, pt, ctt, desc in AEAD_KAT:
        ct, tag, cc = ace_encrypt_masked(KAT_KEY, Z16, KAT_NONCE, h(ad), h(pt))
        chk(f"masked  K2=0  Count={count:<4} reproduces the official KAT",
            (ct + tag).hex(), ctt)

    # (b) With a non-zero K2 the result must equal the *independent* byte-string
    #     reference run on (key=K1, nonce=N xor K2), and must differ from the
    #     unmasked run on (K1, N) -- otherwise the mask is not being applied.
    for count, ad, pt, _c, desc in AEAD_KAT[:6]:
        ct, tag, cc = ace_encrypt_masked(K1, K2, N, h(ad), h(pt))
        chk(f"masked  Count={count:<4} == ref(key=K1, nonce=N xor K2)",
            (ct + tag).hex(), ref_aead_encrypt(K1, Nm, h(ad), h(pt)).hex())
        unmasked, utag, _ = ace_encrypt(K1, N, h(ad), h(pt))
        chk(f"masked  Count={count:<4} differs from the unmasked nonce N",
            (ct + tag) != (unmasked + utag), True)
        # round-trip through the masked decryption path
        ok, rec, ccd = ace_decrypt_masked(K1, K2, N, h(ad), ct, tag)
        chk(f"masked  Count={count:<4} masked decrypt recovers the plaintext",
            (ok, rec.hex(), ccd.st), (True, pt, "Success"))

    # (c) The combination "nonce masking + set nonce" of the .adoc's last
    #     paragraph: K1 as key, N xor K2 supplied as the PI nonce, budget rules
    #     of <<ACE-Ascon-AEAD128-wsn>> in force.
    ct_a, tag_a, _ = ace_encrypt_masked(K1, K2, N, h("3031"), h("2021222324"))
    ct_b, tag_b, ccb = ace_encrypt_masked(K1, K2, N, h("3031"), h("2021222324"),
                                          set_nonce=True, budget=8)
    chk("masked + set-nonce == masked with the Form C nonce", (ct_b, tag_b), (ct_a, tag_a))
    chk("masked + set-nonce spends 1 AD + 1 Enc_Last_Block block", ccb.budget, 6)

    # ---------------------------------------------------------- Hash256 / XOF / CXOF
    print("\n<<ACE-Ascon-Hash256>> vs official vectors")
    for count, msg, md in HASH_KAT:
        chk(f"Hash256  Count={count:<4} (ACELEN=256, one squeeze)",
            ace_hash256(h(msg)).hex(), md)
    print("\n  countdown: 1 / 2 / 4 ace.exec squeezes must agree")
    for count, msg, md in HASH_KAT:
        a = ace_hash256(h(msg), squeeze_acelen=256).hex()
        b = ace_hash256(h(msg), squeeze_acelen=128).hex()
        c = ace_hash256(h(msg), squeeze_acelen=64).hex()
        chk(f"Hash256  Count={count:<4} squeeze 1x256 == 2x128 == 4x64 == KAT",
            (a, b, c), (md, md, md))
    print("\n  multi-word absorb (ACELEN = 192) agrees")
    for count, msg, md in HASH_KAT:
        chk(f"Hash256  Count={count:<4} ACELEN=192 absorb", ace_hash256(h(msg), absorb_chunk=3).hex(), md)
    # countdown really stops the machine at four words
    cc = AceAsconSponge(IV_HASH, use_countdown=True)
    cc.exec_absorb(b2v(b'\x01' + bytes(7)), 64)
    cc.enter_finalize()
    got = []
    for _ in range(4):
        if cc.st == 'Success':
            break
        cc.exec_squeeze(64)
        got.append(cc.countdown)
    chk("Hash256 countdown runs 3,2,1,0 then State = Success",
        (got, cc.st), ([2, 1, 0, 0], "Success"))

    print("\n<<ACE-Ascon-XOF128>> vs official vectors (512-bit output)")
    for count, msg, md in XOF_KAT:
        chk(f"XOF128   Count={count:<4} 512-bit squeeze (8 x ace.exec)",
            ace_xof128(h(msg), 64).hex(), md)
        chk(f"XOF128   Count={count:<4} same via ACELEN=256 squeezes",
            ace_xof128(h(msg), 64, squeeze_acelen=256).hex(), md)
    # squeeze beyond 256 bits must extend, not restart
    for count, msg, md in XOF_KAT[:3]:
        chk(f"XOF128   Count={count:<4} first 256 bits are a prefix of the 512-bit MD",
            ace_xof128(h(msg), 32).hex(), md[:64])
        chk(f"XOF128   Count={count:<4} 1024-bit squeeze matches the reference stream",
            ace_xof128(h(msg), 128).hex(), ref_xof128(h(msg), 128).hex())
    cc = AceAsconSponge(IV_XOF, use_countdown=False)
    cc.exec_absorb(b2v(b'\x01' + bytes(7)), 64)
    cc.enter_finalize()
    for _ in range(20):
        cc.exec_squeeze(64)
    chk("XOF128 never transitions to _Success_ after 20 squeezes", cc.st, "Hash_Finalize")

    print("\n<<ACE-Ascon-CXOF128>> vs official vectors")
    for count, msg, z, md in CXOF_KAT:
        chk(f"CXOF128  Count={count:<4} caller-prepended customization string",
            ace_cxof128(h(msg), h(z), 64).hex(), md)
    chk("CXOF128 with an empty Z differs from XOF128 on the same message (IV differs)",
        ace_cxof128(b"abc", b"", 32) != ace_xof128(b"abc", 32), True)

    # ---------------------------------------------------------- negative control
    print("\nNegative control: domain separation applied to the WRONG word")
    print("  (spec: `state[4] <- state[4] xor (1 << 63)` on entering _Encrypt_;")
    print("   the control instead xors the MSB of state[0] and must NOT match)")
    print("KAT-EXPECT-FAIL: dsep on state[0]")
    fired = True
    for count, ad, pt, ctt, _ in AEAD_KAT[:4]:
        ct, tag, _ = ace_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt), dsep_wrong_word=True)
        fired &= chk_fails(f"dsep on state[0]  Count={count:<4} must differ from the KAT",
                           (ct + tag).hex(), ctt)

    print(f"\n{_n} checks executed")
    print("KAT-RESULT:", "PASS" if _ok else "FAIL")
    return 0 if _ok else 1

if __name__ == "__main__":
    sys.exit(main())
