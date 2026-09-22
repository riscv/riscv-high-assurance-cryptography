#!/usr/bin/env python3
"""AES-GCM-SIV known-answer tests for the KLEE GCM-SIV Machine.

Validates <<KLEE-GCM-SIV-mode>> (modules/ROOT/pages/Zkl-ISA-machines.adoc) against RFC 8452.

Two independent implementations are exercised:

  REF   AES-GCM-SIV exactly as RFC 8452 sections 4-5 specify it, one-pass
        functions over byte strings.
  KLEE  the Machine of <<KLEE-GCM-SIV-mode>>, transcribed literally on KLEE
        values (modules/ROOT/pages/Zkl-notation.adoc; common.py conventions) and driven by
        numbered kl.setst / kl.exec instructions (State constants of
        <<KLEE-state-constants-symmetric>>): RFC8452_KeyDeriv(k, key, nonce) as
        listed in <<KLEE-GCM-SIV-KeyDeriv>>, absorb(data) = { tmp ^= data;
        tmp = Montmul(tmp, auth_key) }, the States Set_Aux_Value /
        Set_Aux_Value_2 / Hash_Absorb / Enc_Tag_Finalize / Encrypt /
        Enc_Last_Block / Decrypt / Dec_Last_Block / Dec_Tag_Finalize entered
        with the kl.setst Forms the text prescribes (Form A for Hash_Absorb,
        Enc_Tag_Finalize, Decrypt and Dec_Tag_Finalize; Encrypt only through the
        Enc_Tag_Finalize kl.exec), the counter block
        1 @ SIV[126:32] @ bin((int(SIV[31:0]) + ctr) mod 2^32, 32), the
        ctr = 2^32-1 Invalid rule, the last_blk_len rules, the Serialized
        Content, the derived fields enc_key and auth_key (MGR4) and the kl.derive
        endpoint `key` (<<KLEE-derive-endpoints>>).  Montmul is checked against
        its definition in <<KLEE-SCC-AEAD>>.

Anchors (embedded, offline):
  * RFC 8452 Appendix C.1 (AES-128-GCM-SIV), C.2 (AES-256-GCM-SIV) and
    C.3 (counter-wrap) test vectors, transcribed from
    https://www.rfc-editor.org/rfc/rfc8452.txt (April 2019).
    Selection covers empty AAD+PT, non-block-multiple PT (Enc_Last_Block /
    Dec_Last_Block), nonempty AAD, multi-block PT, and the counter wrap
    mod 2^32.  Five vectors carry the RFC's per-vector intermediates
    (record_authentication_key, record_enc_key, POLYVAL result), anchoring
    RFC8452_KeyDeriv and the absorb chain separately from the final result.

Negative controls (KAT-EXPECT-FAIL): assembling the length block with
big-endian (GCM-style, bswap) length encodings instead of the spec's
little-endian bin() must change the tag; and a CL imported part-way through a
message without re-deriving enc_key and auth_key (MGR4) must not complete it.

Resolved since the previous revision of this harness: RFC8452_KeyDeriv is now
defined in <<KLEE-GCM-SIV-mode>> itself for k = 128 and k = 256 (it used to be
the 256-bit-only SCC key derivation), and review findings m8 (the kl.setst Form
of every transition is stated) and M2 (_Encrypt_ is reachable only through the
_Enc_Tag_Finalize_ kl.exec) are fixed; the model follows the stated Forms.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bin_, montmul, aes_encrypt, MASK128,
                    selftest)

M32 = (1 << 32) - 1


def mask(n):
    return (1 << n) - 1


def pad128(n):
    return -(-n // 128) * 128


# ======================================================================
# REF: RFC 8452 sections 4-5, byte-string view
# ======================================================================

def ref_derive_keys(key: bytes, nonce: bytes):
    """RFC 8452 section 4: message authentication and encryption keys."""
    n = 4 if len(key) == 16 else 6
    halves = [aes_encrypt(key, i.to_bytes(4, 'little') + nonce)[:8]
              for i in range(n)]
    return halves[0] + halves[1], b''.join(halves[2:])   # (auth 16B, enc 16/32B)

def ref_polyval(H: bytes, data: bytes) -> bytes:
    """POLYVAL over a byte string, len(data) a multiple of 16."""
    h = b2v(H)
    acc = 0
    for i in range(0, len(data), 16):
        acc = montmul(acc ^ b2v(data[i:i + 16]), h)
    return v2b(acc, 16)

def _pad16(s: bytes) -> bytes:
    return s + bytes(-len(s) % 16)

def _le64(n: int) -> bytes:
    return n.to_bytes(8, 'little')

def _ctr_block(tag: bytes, i: int) -> bytes:
    """Counter block i: tag with MSB of last byte set, first 4 bytes
    incremented as a little-endian integer mod 2^32."""
    c = (int.from_bytes(tag[:4], 'little') + i) & M32
    return c.to_bytes(4, 'little') + tag[4:15] + bytes([tag[15] | 0x80])

def ref_encrypt(key: bytes, nonce: bytes, pt: bytes, aad: bytes) -> bytes:
    auth, enc = ref_derive_keys(key, nonce)
    lb = _le64(len(aad) * 8) + _le64(len(pt) * 8)
    S = ref_polyval(auth, _pad16(aad) + _pad16(pt) + lb)
    S = bytes(a ^ b for a, b in zip(S, nonce + bytes(4)))
    S = S[:15] + bytes([S[15] & 0x7F])
    tag = aes_encrypt(enc, S)
    ct = bytearray()
    for i in range(0, len(pt), 16):
        ks = aes_encrypt(enc, _ctr_block(tag, i // 16))
        ct += bytes(a ^ b for a, b in zip(pt[i:i + 16], ks))
    return bytes(ct) + tag

def ref_decrypt(key: bytes, nonce: bytes, ctag: bytes, aad: bytes):
    auth, enc = ref_derive_keys(key, nonce)
    ct, tag = ctag[:-16], ctag[-16:]
    pt = bytearray()
    for i in range(0, len(ct), 16):
        ks = aes_encrypt(enc, _ctr_block(tag, i // 16))
        pt += bytes(a ^ b for a, b in zip(ct[i:i + 16], ks))
    pt = bytes(pt)
    lb = _le64(len(aad) * 8) + _le64(len(pt) * 8)
    S = ref_polyval(auth, _pad16(aad) + _pad16(pt) + lb)
    S = bytes(a ^ b for a, b in zip(S, nonce + bytes(4)))
    S = S[:15] + bytes([S[15] & 0x7F])
    expected = aes_encrypt(enc, S)
    if expected != tag:
        return False, bytes(len(pt))
    return True, pt

# ======================================================================
# Montmul from its definition in <<KLEE-SCC-AEAD>>
# ======================================================================

_G = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1

def _gf_mul(a, b):
    """Plain multiplication in F = GF(2)[x] / (x^128 + x^127 + x^126 + x^121 + 1),
    V[k] being the coefficient of x^k."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a, b = a << 1, b >> 1
    for d in range(r.bit_length() - 1, 127, -1):
        if (r >> d) & 1:
            r ^= _G << (d - 128)
    return r

def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a, e = _gf_mul(a, a), e >> 1
    return r

X_MINUS_128 = _gf_pow(_gf_mul(1 << 127, 2), (1 << 128) - 2)    # (x^128)^-1

def montmul_def(a, b):
    """Montmul(a, b) = a . b . x^-128 in the field F."""
    return _gf_mul(_gf_mul(a, b), X_MINUS_128)

# ======================================================================
# KLEE: the Machine of <<KLEE-GCM-SIV-mode>>, on KLEE values
# ======================================================================

# <<KLEE-states-valid>>, <<KLEE-state-constants-symmetric>>, <<KLEE-states-error>>
KL_STATE_UNCONFIGURED = 0
KL_STATE_READY = 1
KL_STATE_HASH_ABSORB = 2
KL_STATE_ENCRYPT = 7
KL_STATE_DECRYPT = 8
KL_STATE_ENC_LAST_BLOCK = 9
KL_STATE_DEC_LAST_BLOCK = 10
KL_STATE_ENC_TAG_FINALIZE = 11
KL_STATE_DEC_TAG_FINALIZE = 12
KL_STATE_SET_AUX_VALUE = 13
KL_STATE_SET_AUX_VALUE_2 = 14
KL_STATE_SUCCESS = 46
KL_STATE_FAILURE = 47
KL_STATE_INVALID = 49
KL_STATE_EXPIRED = 53
ERROR_STATES = range(48, 56)

NAME = {1: 'Ready', 2: 'Hash_Absorb', 7: 'Encrypt', 8: 'Decrypt',
        9: 'Enc_Last_Block', 10: 'Dec_Last_Block', 11: 'Enc_Tag_Finalize',
        12: 'Dec_Tag_Finalize', 13: 'Set_Aux_Value', 14: 'Set_Aux_Value_2',
        46: 'Success', 47: 'Failure', 49: 'Invalid', 53: 'Expired'}

SKS = {0x00C0FFEE00C0FFEE: bytes.fromhex('01000000000000000000000000000000')}

KEYDERIV_CALLS = []                          # enc_blk calls made by RFC8452_KeyDeriv


def enc_blk(key: bytes, p: int) -> int:
    return b2v(aes_encrypt(key, v2b(p, 16)))


def RFC8452_KeyDeriv(k: int, key: bytes, nonce: int):
    """<<KLEE-GCM-SIV-KeyDeriv>>, line by line.  Returns (enc_key, auth_key) as
    KLEE values of k and 128 bits."""
    A = [0] * 6                               # local A : array [0..5] of bits(128)
    E = 0                                     # local E : bits(k)
    for i in range(0, k // 64 + 2):           # foreach(i from 0 to k/64 + 1)
        A[i] = enc_blk(key, cat((nonce, 96), (bin_(i, 32), 32)))
        KEYDERIV_CALLS.append(i)
    for i in range(2, k // 64 + 2):           # foreach(i from 2 to k/64 + 1)
        hi, lo = 64 * i - 65, 64 * i - 128    # E[64*i-65 : 64*i-128] <- A[i][63:0]
        E = (E & ~(mask(hi - lo + 1) << lo)) | (sl(A[i], 63, 0) << lo)
    return E, cat((sl(A[1], 63, 0), 64), (sl(A[0], 63, 0), 64))


def SCC_KeyDeriv(key: bytes, nonce: int):
    """<<KLEE-SCC-key-derivation>> (Book 1), for the cross-check at k = 256."""
    A = [enc_blk(key, cat((nonce, 96), (bin_(i, 32), 32))) for i in range(6)]
    return (cat((sl(A[5], 63, 0), 64), (sl(A[4], 63, 0), 64),
                (sl(A[3], 63, 0), 64), (sl(A[2], 63, 0), 64)),
            cat((sl(A[1], 63, 0), 64), (sl(A[0], 63, 0), 64)))


class GcmSivCL:
    """A CL holding a CC of <<KLEE-GCM-SIV-mode>>, driven instruction by instruction.

    The MDH is reduced to _State_, _MachinePolicy_ (bit 0 encryption, bit 1
    decryption) and _KeyType_; `klstart` stands for the hart CSR.
    `stale_derived` is a negative control: no MGR4 re-derivation at import.
    """

    def __init__(self, policy=0b11, stale_derived=False):
        self.policy, self.stale_derived = policy, stale_derived
        self.state = KL_STATE_UNCONFIGURED
        self.klstart = 0
        self.halted = False
        self.polyval_probe = None             # tmp right after the length absorb
        self._clear()

    def _clear(self):
        self.k = self.key_type = self.skid = 0
        self.key = b''
        self.enc_key = self.auth_key = 0
        self.nonce = self.ctr = self.SIV = self.tmp = self.last_blk_len = 0

    # -- provisioning, derived fields, export, import ------------------
    @classmethod
    def provisioned(cls, key=None, skid=None, **kw):
        cl = cls(**kw)
        cl.key_type = 1 if skid is not None else 0
        cl.skid = skid or 0
        cl.key = SKS[skid] if skid is not None else key
        assert len(cl.key) in (16, 32)       # k = 128 or 256
        cl.k = 8 * len(cl.key)
        cl.state = KL_STATE_READY             # a completed provisioning leads to _Ready_
        cl._enter_ready()
        return cl

    def _rederive(self):
        """(enc_key, auth_key) <- RFC8452_KeyDeriv(k, key, nonce)  (MGR4)."""
        self.enc_key, self.auth_key = RFC8452_KeyDeriv(self.k, self.key, self.nonce)

    def _enter_ready(self):
        """Upon entering _Ready_: nonce, ctr, tmp, SIV <- 0."""
        self.nonce = self.ctr = self.tmp = self.SIV = 0
        self._rederive()                      # nonce changed (MGR4)

    def export_content(self):
        """Serialized Content: key | nonce | ctr | SIV | tmp | last_blk_len."""
        if self.state in ERROR_STATES:
            return 0, 0                       # SGR11: the MDH alone
        kbits = 64 if self.key_type == 1 else self.k
        kf = self.skid if self.key_type == 1 else b2v(self.key)
        v = cat((bin_(self.last_blk_len, 16), 16), (self.tmp, 128), (self.SIV, 128),
                (bin_(self.ctr, 32), 32), (self.nonce, 96), (kf, kbits))
        return v, pad128(kbits + 96 + 32 + 128 + 128 + 16)

    @classmethod
    def imported(cls, state, content, k, key_type=0, **kw):
        cl = cls(**kw)
        cl.k, cl.key_type = k, key_type
        kb = 64 if key_type == 1 else k
        kf = sl(content, kb - 1, 0)
        if key_type == 1:
            cl.skid, cl.key = kf, SKS[kf]
        else:
            cl.key = v2b(kf, k // 8)
        cl.nonce = sl(content, kb + 95, kb)
        cl.ctr = sl(content, kb + 127, kb + 96)
        cl.SIV = sl(content, kb + 255, kb + 128)
        cl.tmp = sl(content, kb + 383, kb + 256)
        cl.last_blk_len = sl(content, kb + 399, kb + 384)
        cl.state = state
        if not cl.stale_derived:
            cl._rederive()                    # MGR4, at kl_cfg_management_end
        return cl

    def _invalid(self, why=''):
        """Transition to Error State _Invalid_; the Content is cleared (SGR10)."""
        self.state = KL_STATE_INVALID
        self._clear()
        self.why = why
        return 0

    # -- Machine-specific functions ---------------------------------------
    def _enc(self, p):
        return enc_blk(v2b(self.enc_key, self.k // 8), p)

    def _absorb(self, data):
        self.tmp ^= data                      # tmp <- tmp xor data
        self.tmp = montmul(self.tmp, self.auth_key)   # tmp <- Montmul(tmp, auth_key)

    def _keystream(self):
        """enc_blk(enc_key, 1 @ SIV[126:32] @ bin((int(SIV[31:0]) + ctr) mod 2^32, 32))."""
        return self._enc(cat((1, 1), (sl(self.SIV, 126, 32), 95),
                             (bin_((sl(self.SIV, 31, 0) + self.ctr) % 2 ** 32, 32), 32)))

    def _finalize_tmp(self, INPUT):
        self._absorb(INPUT & MASK128)         # "If KLLEN > 128, only the 128 LSBs"
        self.polyval_probe = self.tmp
        # tmp <- enc_blk(enc_key, 0 @ tmp[126:96] @ (tmp[95:0] xor nonce))
        self.tmp = self._enc(cat((0, 1), (sl(self.tmp, 126, 96), 31),
                                 (sl(self.tmp, 95, 0) ^ self.nonce, 96)))

    # -- kl.setst -----------------------------------------------------------
    def _setst_table(self):
        A_, B_, C_ = 'A', 'B', 'C'
        return {
            (KL_STATE_READY, KL_STATE_SET_AUX_VALUE): (C_, self._set_nonce),
            (KL_STATE_SET_AUX_VALUE, KL_STATE_SET_AUX_VALUE): (C_, self._set_nonce),
            (KL_STATE_SET_AUX_VALUE, KL_STATE_SET_AUX_VALUE_2): (C_, self._set_siv),
            (KL_STATE_SET_AUX_VALUE_2, KL_STATE_SET_AUX_VALUE_2): (C_, self._set_siv),
            (KL_STATE_SET_AUX_VALUE, KL_STATE_HASH_ABSORB): (A_, self._go),
            (KL_STATE_SET_AUX_VALUE_2, KL_STATE_HASH_ABSORB): (A_, self._go),
            (KL_STATE_HASH_ABSORB, KL_STATE_HASH_ABSORB): (A_, self._go),
            (KL_STATE_HASH_ABSORB, KL_STATE_ENC_TAG_FINALIZE): (A_, self._go_policy),
            (KL_STATE_ENC_TAG_FINALIZE, KL_STATE_ENC_TAG_FINALIZE): (A_, self._go),
            (KL_STATE_HASH_ABSORB, KL_STATE_DECRYPT): (A_, self._go_policy),
            (KL_STATE_DECRYPT, KL_STATE_DECRYPT): (A_, self._go),
            (KL_STATE_ENCRYPT, KL_STATE_ENC_LAST_BLOCK): (B_, self._set_lbl),
            (KL_STATE_ENC_LAST_BLOCK, KL_STATE_ENC_LAST_BLOCK): (B_, self._set_lbl),
            (KL_STATE_DECRYPT, KL_STATE_DEC_LAST_BLOCK): (B_, self._set_lbl),
            (KL_STATE_DEC_LAST_BLOCK, KL_STATE_DEC_LAST_BLOCK): (B_, self._set_lbl),
            (KL_STATE_DECRYPT, KL_STATE_DEC_TAG_FINALIZE): (A_, self._go),
            (KL_STATE_DEC_LAST_BLOCK, KL_STATE_DEC_TAG_FINALIZE): (A_, self._go),
            (KL_STATE_DEC_TAG_FINALIZE, KL_STATE_DEC_TAG_FINALIZE): (A_, self._go),
        }

    def setst(self, immed7, form='A', aux=0):
        st = self.state
        if st in ERROR_STATES:                # SGR15, SGR16
            if immed7 in ERROR_STATES:
                self.state = immed7 if immed7 < 54 else KL_STATE_INVALID
            return
        if immed7 in ERROR_STATES:
            self.state = immed7 if immed7 < 54 else KL_STATE_INVALID
            self._clear()
            return
        if immed7 == KL_STATE_READY and form == 'A':
            self.state = KL_STATE_READY       # SGR6, SGR8
            self._enter_ready()
            return
        if st in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            self._invalid('SGR5/SGR6')
            return
        if immed7 == KL_STATE_ENCRYPT:
            # "State _Encrypt_ is *not* entered by kl.setst ... an kl.setst naming
            # _Encrypt_ is a not-allowed transition and invalidates the CL"
            self._invalid('kl.setst naming _Encrypt_')
            return
        entry = self._setst_table().get((st, immed7))
        if entry is None:
            self._invalid(f'MGR1: {NAME.get(st)} -> {NAME.get(immed7, immed7)}')
            return
        want, fn = entry
        if form != want:
            self._invalid(f'MGR1: Form {form}, Form {want} required')
            return
        fn(immed7, aux)

    def _go(self, immed7, aux):
        self.state = immed7

    def _go_policy(self, immed7, aux):
        # "possible only if encryption (decryption) is allowed"
        bit = 1 if immed7 == KL_STATE_ENC_TAG_FINALIZE else 2
        if not self.policy & bit:
            self._invalid('MGR1: _MachinePolicy_')
            return
        self.state = immed7

    def _set_nonce(self, immed7, INPUT):
        self.state = immed7
        self.nonce = sl(INPUT, 95, 0)                               # nonce <- INPUT[95:0]
        self._rederive()                                            # RFC8452_KeyDeriv(k, key, nonce)

    def _set_siv(self, immed7, INPUT):
        self.state = immed7
        self.SIV = INPUT & MASK128                                  # SIV <- INPUT (MGR5)

    def _set_lbl(self, immed7, Xs):
        if Xs == 0 or Xs > 120 or Xs % 8:
            self._invalid('last_blk_len')
            return
        self.last_blk_len = Xs
        self.state = immed7

    # -- kl.exec --------------------------------------------------------------
    def _exec_table(self):
        return {
            KL_STATE_HASH_ABSORB: ('B', self._x_absorb),
            KL_STATE_ENC_TAG_FINALIZE: ('A', self._x_enc_tag_finalize),
            KL_STATE_ENCRYPT: ('A', self._x_crypt),
            KL_STATE_DECRYPT: ('A', self._x_crypt),
            KL_STATE_ENC_LAST_BLOCK: ('A', self._x_last_block),
            KL_STATE_DEC_LAST_BLOCK: ('A', self._x_last_block),
            KL_STATE_DEC_TAG_FINALIZE: ('B', self._x_dec_tag_finalize),
        }

    def exec(self, form, INPUT=0, KLLEN=128, resume=False, interrupt_after=None):
        """kl.exec; returns OUTPUT (KLLEN bits) for Forms A and C."""
        self.halted = False
        st = self.state
        if st in ERROR_STATES:
            return 0                          # SGR16
        if st == KL_STATE_READY:
            return self._invalid('SGR2')
        if st in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            return self._invalid('SGR5')
        entry = self._exec_table().get(st)
        if entry is None:
            return self._invalid(f'MGR1: no kl.exec in {NAME.get(st)}')
        want, fn = entry
        if form != want:
            return self._invalid(f'MGR1: Form {form} in {NAME.get(st)}')
        return fn(INPUT, KLLEN, resume, interrupt_after)

    def _blocks(self, KLLEN, resume):
        """First block of a block-iterated kl.exec (IRR7), or None: MGR2 or a
        klstart that is not an interruption point."""
        if KLLEN % 128:
            return None
        if not resume:
            return 0
        return None if self.klstart % 16 else self.klstart // 16

    def _x_absorb(self, INPUT, KLLEN, resume, interrupt_after):
        first = self._blocks(KLLEN, resume)
        if first is None:
            return self._invalid('MGR2 / klstart')
        for j in range(first, KLLEN // 128):
            if interrupt_after is not None and j - first == interrupt_after:
                self.klstart, self.halted = 16 * j, True
                return None
            self._absorb(sl(INPUT, 128 * j + 127, 128 * j))
        self.klstart = 0
        return None

    def _x_enc_tag_finalize(self, INPUT, KLLEN, resume, interrupt_after):
        self._finalize_tmp(INPUT)
        self.SIV = self.tmp                   # SIV <- tmp and OUTPUT <- SIV
        self.state = KL_STATE_ENCRYPT         # the state transitions to _Encrypt_
        return self.SIV & mask(KLLEN)         # MGR6 beyond 128 bits

    def _x_crypt(self, INPUT, KLLEN, resume, interrupt_after):
        first = self._blocks(KLLEN, resume)
        if first is None:
            return self._invalid('MGR2 / klstart')
        OUTPUT = 0
        for j in range(first, KLLEN // 128):
            if interrupt_after is not None and j - first == interrupt_after:
                self.klstart, self.halted = 16 * j, True
                return OUTPUT
            if self.ctr == M32:               # IRR6: the completed prefix stays
                self._invalid('ctr = 2^32-1')
                return OUTPUT
            out = sl(INPUT, 128 * j + 127, 128 * j) ^ self._keystream()
            if self.state == KL_STATE_DECRYPT:
                self._absorb(out)             # absorb(OUTPUT)
            OUTPUT |= out << (128 * j)
            self.ctr += 1                     # ctr <- ctr + 1
        self.klstart = 0
        return OUTPUT

    def _x_last_block(self, INPUT, KLLEN, resume, interrupt_after):
        lbl = self.last_blk_len
        if lbl == 0:
            return 0                          # terminate the instruction
        if KLLEN < lbl:
            return self._invalid('KLLEN < last_blk_len')
        if self.ctr == M32:
            return self._invalid('ctr = 2^32-1')
        # OUTPUT <- zeros(128-lbl) @ (INPUT xor enc_blk(...))[lbl-1:0]
        OUTPUT = cat((0, 128 - lbl), (sl(INPUT ^ self._keystream(), lbl - 1, 0), lbl))
        if self.state == KL_STATE_DEC_LAST_BLOCK:
            self._absorb(OUTPUT)              # the zero-padded plaintext
        self.ctr += 1
        self.last_blk_len = 0
        return OUTPUT & mask(KLLEN)

    def _x_dec_tag_finalize(self, INPUT, KLLEN, resume, interrupt_after):
        self._finalize_tmp(INPUT)
        self.state = KL_STATE_SUCCESS if self.tmp == self.SIV else KL_STATE_FAILURE
        return None

    # -- kl.derive destination endpoint j = 1 (`key`) --------------------------
    def derive_into_key(self, src: bytes, length: int):
        if self.state in ERROR_STATES:
            return
        if self.key_type == 1 or self.state != KL_STATE_READY:
            self._invalid('kl.derive destination')
            return
        if length == 0:
            return
        eff = min(length, self.k // 8)
        self.key = src[:eff] + bytes(self.k // 8 - eff)
        self._rederive()                      # MGR4


# -- drivers: <<KLEE-pseudocode-GCM-SIV-encryption>> / -decryption ---------

def _absorb_string(m, s: bytes, KLLEN: int):
    """Feed the zero-padded byte string s through Hash_Absorb in chunks of
    at most `KLLEN` bits; the final chunk covers only the remaining blocks."""
    p = _pad16(s)
    step = KLLEN // 8
    for i in range(0, len(p), step):
        chunk = p[i:i + step]
        m.exec('B', b2v(chunk), 8 * len(chunk))

def _length_block(aad: bytes, pt: bytes) -> int:
    """INPUT <- bin(len_in_bits(plaintext), 64) @ bin(len_in_bits(AD), 64)."""
    return cat((bin_(len(pt) * 8, 64), 64), (bin_(len(aad) * 8, 64), 64))

def _length_block_be(aad: bytes, pt: bytes) -> int:
    """GCM-style negative control: 64-bit big-endian (bswap'd) encodings,
    laid out as the GCM length block byte string BE64(lenA) || BE64(lenP)."""
    return b2v((len(aad) * 8).to_bytes(8, 'big') +
               (len(pt) * 8).to_bytes(8, 'big'))

def _crypt_body(m, text, KLLEN, last_state):
    full, rem = divmod(len(text), 16)
    out = bytearray()
    step = KLLEN // 8
    body = text[:16 * full]
    for i in range(0, len(body), step):
        chunk = body[i:i + step]
        out += v2b(m.exec('A', b2v(chunk), 8 * len(chunk)), len(chunk))
    if rem:
        m.setst(last_state, 'B', 8 * rem)
        tail = text[16 * full:]
        out += v2b(m.exec('A', b2v(tail), 8 * rem), rem)
    return bytes(out)

def kl_encrypt(key, nonce, aad, pt, KLLEN=128, length_block=None, m=None):
    m = m or GcmSivCL.provisioned(key)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(nonce))
    m.setst(KL_STATE_HASH_ABSORB)
    _absorb_string(m, aad, KLLEN)
    _absorb_string(m, pt, KLLEN)
    m.setst(KL_STATE_ENC_TAG_FINALIZE)                     # Form A kl.setst
    lb = _length_block(aad, pt) if length_block is None else length_block
    tag_v = m.exec('A', lb, 128)                           # enters _Encrypt_
    ct = _crypt_body(m, pt, KLLEN, KL_STATE_ENC_LAST_BLOCK)
    return ct + v2b(tag_v, 16), m

def kl_decrypt(key, nonce, aad, ctag, KLLEN=128, length_block=None, m=None,
               set_siv=True):
    ct, tag = ctag[:-16], ctag[-16:]
    m = m or GcmSivCL.provisioned(key)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(nonce))
    if set_siv:
        m.setst(KL_STATE_SET_AUX_VALUE_2, 'C', b2v(tag))
    m.setst(KL_STATE_HASH_ABSORB)
    _absorb_string(m, aad, KLLEN)
    m.setst(KL_STATE_DECRYPT)                              # Form A kl.setst
    pt = _crypt_body(m, ct, KLLEN, KL_STATE_DEC_LAST_BLOCK)
    m.setst(KL_STATE_DEC_TAG_FINALIZE)                     # Form A kl.setst
    lb = _length_block(aad, pt) if length_block is None else length_block
    m.exec('B', lb, 128)                                   # Form B kl.exec
    return NAME.get(m.state), pt


# ======================================================================
# Vectors: RFC 8452 Appendix C, https://www.rfc-editor.org/rfc/rfc8452.txt
# (April 2019).  'ct_tag' is the RFC's "Result" (ciphertext || tag); the
# optional intermediates are the RFC's "Record authentication key",
# "Record encryption key" and "POLYVAL result" lines.
# ======================================================================

VECTORS = [
    {   # C.1 #1: empty AAD, empty PT, with intermediates
        'src': 'RFC 8452 C.1 #1 (PT 0 B, AAD 0 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '',
        'ct_tag': 'dc20e2d83f25705bb49e439eca56de25',
        'auth_key': 'd9b360279694941ac5dbc6987ada7377',
        'enc_key': '4004a0dcd862f2a57360219d2d44ef6c',
        'polyval': '00000000000000000000000000000000',
    },
    {   # C.1 #2: 8-byte PT (Enc_Last_Block only), with intermediates
        'src': 'RFC 8452 C.1 #2 (PT 8 B, AAD 0 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '0100000000000000',
        'ct_tag': 'b5d839330ac7b786578782fff6013b815b287c22493a364c',
        'auth_key': 'd9b360279694941ac5dbc6987ada7377',
        'enc_key': '4004a0dcd862f2a57360219d2d44ef6c',
        'polyval': 'eb93b7740962c5e49d2a90a7dc5cec74',
    },
    {   # C.1 #4: exactly one block
        'src': 'RFC 8452 C.1 #4 (PT 16 B, AAD 0 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '01000000000000000000000000000000',
        'ct_tag': '743f7c8077ab25f8624e2e948579cf77'
                  '303aaf90f6fe21199c6068577437a0c4',
    },
    {   # C.1 #5: two blocks (chunked absorb / multi-block CTR)
        'src': 'RFC 8452 C.1 #5 (PT 32 B, AAD 0 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '',
        'pt': '01000000000000000000000000000000'
              '02000000000000000000000000000000',
        'ct_tag': '84e07e62ba83a6585417245d7ec413a9'
                  'fe427d6315c09b57ce45f2e3936a9445'
                  '1a8e45dcd4578c667cd86847bf6155ff',
    },
    {   # C.1 #14: nonempty AAD, fractional PT
        'src': 'RFC 8452 C.1 #14 (PT 4 B, AAD 12 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '010000000000000000000000',
        'pt': '02000000',
        'ct_tag': 'a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14',
    },
    {   # C.1 #15: fractional AAD and PT, with intermediates
        'src': 'RFC 8452 C.1 #15 (PT 20 B, AAD 18 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '010000000000000000000000000000000200',
        'pt': '0300000000000000000000000000000004000000',
        'ct_tag': '6bb0fecf5ded9b77f902c7d5da236a43'
                  '91dd029724afc9805e976f451e6d87f6fe106514',
        'auth_key': 'd9b360279694941ac5dbc6987ada7377',
        'enc_key': '4004a0dcd862f2a57360219d2d44ef6c',
        'polyval': '4781d492cb8f926c504caa36f61008fe',
    },
    {   # C.1 #21: random-looking key/nonce, fractional AAD and PT
        'src': 'RFC 8452 C.1 #21 (PT 12 B, AAD 20 B)',
        'key': 'b3fed1473c528b8426a582995929a149',
        'nonce': '9e9ad8780c8d63d0ab4149c0',
        'aad': 'c9882e5386fd9f92ec489c8fde2be2cf97e74e93',
        'pt': '9f572c614b4745914474e7c7',
        'ct_tag': 'f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0',
    },
    {   # C.2 #1: AES-256, empty AAD and PT
        'src': 'RFC 8452 C.2 #1 (PT 0 B, AAD 0 B)',
        'key': '01000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '',
        'ct_tag': '07f5f4169bbf55a8400cd47ea6fd400f',
    },
    {   # C.2 #2: AES-256, 8-byte PT, with intermediates
        'src': 'RFC 8452 C.2 #2 (PT 8 B, AAD 0 B)',
        'key': '01000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '0100000000000000',
        'ct_tag': 'c2ef328e5c71c83b843122130f7364b761e0b97427e3df28',
        'auth_key': 'b5d3c529dfafac43136d2d11be284d7f',
        'enc_key': 'b914f4742be9e1d7a2f84addbf96dec3'
                   '456e3c6c05ecc157cdbf0700fedad222',
        'polyval': '05230f62f0eac8aa14fe4d646b59cd41',
    },
    {   # C.2 #6: AES-256, three blocks
        'src': 'RFC 8452 C.2 #6 (PT 48 B, AAD 0 B)',
        'key': '01000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '',
        'pt': '01000000000000000000000000000000'
              '02000000000000000000000000000000'
              '03000000000000000000000000000000',
        'ct_tag': 'c00d121893a9fa603f48ccc1ca3c57ce'
                  '7499245ea0046db16c53c7c66fe717e3'
                  '9cf6c748837b61f6ee3adcee17534ed5'
                  '790bc96880a99ba804bd12c0e6a22cc4',
    },
    {   # C.2 #15: AES-256, fractional AAD and PT, with intermediates
        'src': 'RFC 8452 C.2 #15 (PT 20 B, AAD 18 B)',
        'key': '01000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '010000000000000000000000000000000200',
        'pt': '0300000000000000000000000000000004000000',
        'ct_tag': '43dd0163cdb48f9fe3212bf61b201976'
                  '067f342bb879ad976d8242acc188ab59cabfe307',
        'auth_key': 'b5d3c529dfafac43136d2d11be284d7f',
        'enc_key': 'b914f4742be9e1d7a2f84addbf96dec3'
                   '456e3c6c05ecc157cdbf0700fedad222',
        'polyval': '973ef4fd04bd31d193816ab26f8655ca',
    },
    {   # C.2 #24: AES-256, random-looking, fractional AAD and PT
        'src': 'RFC 8452 C.2 #24 (PT 21 B, AAD 35 B)',
        'key': '3c535de192eaed3822a2fbbe2ca9dfc8'
               '8255e14a661b8aa82cc54236093bbc23',
        'nonce': '688089e55540db1872504e1c',
        'aad': '734320ccc9d9bbbb19cb81b2af4ecbc3'
               'e72834321f7aa0f70b7282b4f33df23f167541',
        'pt': 'ced532ce4159b035277d4dfbb7db62968b13cd4eec',
        'ct_tag': '626660c26ea6612fb17ad91e8e767639'
                  'edd6c9faee9d6c7029675b89eaf4ba1ded1a286594',
    },
    {   # C.3 #1: counter wraps mod 2^32
        'src': 'RFC 8452 C.3 #1 (counter wrap, PT 32 B)',
        'key': '00000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '000000000000000000000000',
        'aad': '',
        'pt': '00000000000000000000000000000000'
              '4db923dc793ee6497c76dcc03a98e108',
        'ct_tag': 'f3f80f2cf0cb2dd9c5984fcda908456c'
                  'c537703b5ba70324a6793a7bf218d3ea'
                  'ffffffff000000000000000000000000',
    },
    {   # C.3 #2: counter wrap with a fractional final block
        'src': 'RFC 8452 C.3 #2 (counter wrap, PT 24 B)',
        'key': '00000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '000000000000000000000000',
        'aad': '',
        'pt': 'eb3640277c7ffd1303c7a542d02d3e4c0000000000000000',
        'ct_tag': '18ce4f0b8cb4d0cac65fea8f79257b20'
                  '888e53e72299e56dffffffff000000000000000000000000',
    },
]


# ======================================================================
# Test driver
# ======================================================================

ok = True

def chk(cond, desc):
    global ok
    ok = ok and bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {desc}")

def expect_fail(desc, matched):
    """A negative control: the wrong model must NOT reproduce the vector."""
    global ok
    ok = ok and not matched
    print(f"{'PASS' if matched else 'FAIL (expected)'}  {desc}")

def unhex(v, *names):
    return tuple(bytes.fromhex(v[n]) for n in names)

def main():
    global ok
    print(__doc__.splitlines()[0])
    print("Anchor level: mode standard-anchored against RFC 8452 Appendix C "
          "(final results and per-vector intermediates).\n")
    print("KAT-EXPECT-FAIL: BE-lengths")
    print("KAT-EXPECT-FAIL: stale-derived")
    print()

    chk(selftest(), "common.py self-test (FIPS 197, RFC 8452 Appendix A)")
    H = b2v(bytes.fromhex('25629347589242761d31f826ba4b757b'))
    X = b2v(bytes.fromhex('4f4f95668c83dfb6401762bb2d01a262'))
    chk(all(montmul(a, b) == montmul_def(a, b)
            for a, b in ((H, X), (X, X), (1, H), (H, 1 << 127))),
        "montmul equals Montmul as defined in <<KLEE-SCC-AEAD>> (a.b.x^-128, V[k] ~ x^k)")

    for v in VECTORS:
        key, nonce, aad, pt, want = unhex(v, 'key', 'nonce', 'aad', 'pt', 'ct_tag')
        name = v['src']

        # REF: encryption and decryption
        got = ref_encrypt(key, nonce, pt, aad)
        chk(got == want, f"REF encrypt          {name}")
        okd, ptd = ref_decrypt(key, nonce, want, aad)
        chk(okd and ptd == pt, f"REF decrypt          {name}")
        bad = want[:-1] + bytes([want[-1] ^ 0x40])
        okd, ptd = ref_decrypt(key, nonce, bad, aad)
        chk(not okd and ptd == bytes(len(pt)), f"REF tampered tag     {name}")

        # REF intermediates, where the RFC gives them
        if 'auth_key' in v:
            auth, enc = ref_derive_keys(key, nonce)
            chk(auth.hex() == v['auth_key'] and enc.hex() == v['enc_key'],
                f"REF KeyDeriv interm. {name}")
            lb = _le64(len(aad) * 8) + _le64(len(pt) * 8)
            pv = ref_polyval(auth, _pad16(aad) + _pad16(pt) + lb)
            chk(pv.hex() == v['polyval'], f"REF POLYVAL interm.  {name}")

        # KLEE model: encryption, KLLEN = 128
        got, m = kl_encrypt(key, nonce, aad, pt, KLLEN=128)
        chk(got == want and m.state in (KL_STATE_ENCRYPT, KL_STATE_ENC_LAST_BLOCK),
            f"KLEE encrypt 128      {name}")

        # KLEE intermediates, where the RFC gives them
        if 'auth_key' in v:
            del KEYDERIV_CALLS[:]
            ek, ak = RFC8452_KeyDeriv(8 * len(key), key, b2v(nonce))
            chk(v2b(ak, 16).hex() == v['auth_key']
                and v2b(ek, len(key)).hex() == v['enc_key']
                and KEYDERIV_CALLS == list(range(len(key) // 8 + 2)),
                f"KLEE KeyDeriv interm. {name} (k/64 + 2 = "
                f"{len(key) // 8 + 2} enc_blk calls)")
            chk(v2b(m.polyval_probe, 16).hex() == v['polyval'],
                f"KLEE POLYVAL interm.  {name}")

        # KLEE model: chunked Hash_Absorb / multi-block exec, KLLEN = 256
        got, _ = kl_encrypt(key, nonce, aad, pt, KLLEN=256)
        chk(got == want, f"KLEE encrypt 256      {name}")

        # KLEE model: decryption, matching and tampered
        st, ptd = kl_decrypt(key, nonce, aad, want, KLLEN=128)
        chk(st == 'Success' and ptd == pt, f"KLEE decrypt          {name}")
        st, _ = kl_decrypt(key, nonce, aad, bad, KLLEN=256)
        chk(st == 'Failure', f"KLEE tampered tag     {name}")
        if len(want) > 16:
            badc = bytes([want[0] ^ 1]) + want[1:]
            st, _ = kl_decrypt(key, nonce, aad, badc)
            chk(st == 'Failure', f"KLEE tampered CT      {name}")

    # -- key derivation ----------------------------------------------------
    print()
    k256, n0 = bytes.fromhex(VECTORS[8]['key']), b2v(bytes.fromhex(VECTORS[8]['nonce']))
    chk(RFC8452_KeyDeriv(256, k256, n0) == SCC_KeyDeriv(k256, n0),
        "RFC8452_KeyDeriv(256, ...) equals the SCC_KeyDeriv of <<KLEE-SCC-key-derivation>>")

    key = bytes.fromhex(VECTORS[1]['key'])
    nonce = bytes.fromhex(VECTORS[1]['nonce'])
    v5 = VECTORS[5]
    k5, n5, a5, p5, w5 = unhex(v5, 'key', 'nonce', 'aad', 'pt', 'ct_tag')

    def at_hash_absorb(**kw):
        m = GcmSivCL.provisioned(key, **kw)
        m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(nonce))
        m.setst(KL_STATE_HASH_ABSORB)
        return m

    def at_encrypt(n_blocks=2, **kw):
        m = at_hash_absorb(**kw)
        m.setst(KL_STATE_ENC_TAG_FINALIZE)
        m.exec('A', _length_block(b'', bytes(16 * n_blocks)), 128)
        return m

    def at_decrypt(**kw):
        m = at_hash_absorb(**kw)
        m.setst(KL_STATE_DECRYPT)
        return m

    # -- kl.setst Forms and transitions (m8, M2) ---------------------------
    print()
    m = at_hash_absorb()
    m.setst(KL_STATE_ENC_TAG_FINALIZE, 'C', _length_block(b'', b''))
    chk(m.state == KL_STATE_INVALID,
        "the transition to Enc_Tag_Finalize is a Form A kl.setst (Form C -> Invalid)")
    m = at_hash_absorb()
    m.setst(KL_STATE_ENC_TAG_FINALIZE)
    m.exec('B', _length_block(b'', b''), 128)
    chk(m.state == KL_STATE_INVALID,
        "Enc_Tag_Finalize expects a Form A kl.exec (Form B -> Invalid)")
    m = at_decrypt()
    m.setst(KL_STATE_DEC_TAG_FINALIZE)
    out = m.exec('A', _length_block(b'', b''), 128)
    chk(m.state == KL_STATE_INVALID and out == 0,
        "Dec_Tag_Finalize expects a Form B kl.exec (Form A -> Invalid, no SIV output)")
    m = at_hash_absorb()
    m.setst(KL_STATE_DECRYPT, 'C', 0)
    chk(m.state == KL_STATE_INVALID, "the transition to Decrypt is a Form A kl.setst")
    m = GcmSivCL.provisioned(key)
    m.setst(KL_STATE_SET_AUX_VALUE)
    chk(m.state == KL_STATE_INVALID,
        "the transition to Set_Aux_Value is a Form C kl.setst (Form A -> Invalid)")
    m = GcmSivCL.provisioned(key)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(nonce))
    m.exec('B', 0, 128)
    chk(m.state == KL_STATE_INVALID, "no kl.exec is defined in Set_Aux_Value (-> Invalid)")

    victim_tag = bytes.fromhex(VECTORS[1]['ct_tag'])[-16:]
    m = GcmSivCL.provisioned(key)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(nonce))
    m.setst(KL_STATE_SET_AUX_VALUE_2, 'C', b2v(victim_tag))     # inject a chosen SIV
    m.setst(KL_STATE_HASH_ABSORB)
    injected = m.SIV
    m.setst(KL_STATE_ENC_TAG_FINALIZE)
    m.exec('A', _length_block(b'', b''), 128)
    chk(m.state == KL_STATE_ENCRYPT and m.SIV != injected
        and v2b(m.SIV, 16) == bytes.fromhex(VECTORS[0]['ct_tag']),
        "M2: the Enc_Tag_Finalize kl.exec enters Encrypt and overwrites the injected SIV")
    for pre, label in ((at_hash_absorb, 'Hash_Absorb'),
                       (lambda: _sav2(), 'Set_Aux_Value_2'),
                       (lambda: _etf(), 'Enc_Tag_Finalize'),
                       (at_decrypt, 'Decrypt')):
        pass
    def _sav2():
        m = GcmSivCL.provisioned(key)
        m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(nonce))
        m.setst(KL_STATE_SET_AUX_VALUE_2, 'C', b2v(victim_tag))
        return m
    def _etf():
        m = at_hash_absorb()
        m.setst(KL_STATE_ENC_TAG_FINALIZE)
        return m
    for pre, label in ((at_hash_absorb, 'Hash_Absorb'), (_sav2, 'Set_Aux_Value_2'),
                       (_etf, 'Enc_Tag_Finalize'), (at_decrypt, 'Decrypt')):
        m = pre()
        m.setst(KL_STATE_ENCRYPT)
        chk(m.state == KL_STATE_INVALID,
            f"M2: a kl.setst naming Encrypt in {label} invalidates the CL")
    m = at_encrypt()
    m.setst(KL_STATE_ENCRYPT)
    chk(m.state == KL_STATE_INVALID,
        "a kl.setst naming Encrypt issued in Encrypt itself also invalidates the CL "
        "(reading of SPEC-NOTE 1)")

    # -- Set_Aux_Value / Set_Aux_Value_2 -------------------------------------
    print()
    m = GcmSivCL.provisioned(k5)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(bytes(range(12))))
    got, _ = kl_encrypt(k5, n5, a5, p5, m=m)       # issues Set_Aux_Value again
    chk(got == w5, "Set_Aux_Value repeated: nonce overwritten, enc_key/auth_key "
                   "recomputed (C.1 #15 reproduced)")
    m = GcmSivCL.provisioned(k5)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(n5) | (0xDEADBEEF << 96))
    m.setst(KL_STATE_HASH_ABSORB)
    _absorb_string(m, a5, 128)
    _absorb_string(m, p5, 128)
    m.setst(KL_STATE_ENC_TAG_FINALIZE)
    chk(v2b(m.exec('A', _length_block(a5, p5), 128), 16) == w5[-16:],
        "nonce <- INPUT[95:0]: bits above 95 of a 128-bit INPUT are ignored (MGR5)")
    m = GcmSivCL.provisioned(k5)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(n5))
    m.setst(KL_STATE_SET_AUX_VALUE_2, 'C', 0x1234)
    m.setst(KL_STATE_SET_AUX_VALUE_2, 'C', b2v(w5[-16:]) | (0x77 << 200))
    siv_ok = m.SIV == b2v(w5[-16:])
    st, ptd = kl_decrypt(k5, n5, a5, w5, m=_fresh_ready(m))
    chk(siv_ok and st == 'Success' and ptd == p5,
        "Set_Aux_Value_2 repeated overwrites SIV; a 256-bit INPUT keeps its 128 LSBs")
    m = GcmSivCL.provisioned(k5)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(n5))
    m.setst(KL_STATE_SET_AUX_VALUE_2, 'C', 0)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(n5))
    chk(m.state == KL_STATE_INVALID,
        "Set_Aux_Value_2 -> Set_Aux_Value is not a listed transition (-> Invalid)")
    st0, pt0 = kl_decrypt(k5, n5, a5, w5[:-16] + bytes(16))
    st1, pt1 = kl_decrypt(k5, n5, a5, w5, set_siv=False)
    chk(st0 == st1 == 'Failure' and pt0 == pt1,
        "skipping Set_Aux_Value_2 is equivalent to setting SIV to zero")

    # -- end of the encryption path, return to Ready ------------------------
    print()
    m = GcmSivCL.provisioned(k5)
    got1, _ = kl_encrypt(k5, n5, a5, p5, m=m)
    end_state = m.state
    m.setst(KL_STATE_READY)
    reset = (m.nonce, m.ctr, m.tmp, m.SIV) == (0, 0, 0, 0)
    v6 = VECTORS[4]
    k6, n6, a6, p6, w6 = unhex(v6, 'key', 'nonce', 'aad', 'pt', 'ct_tag')
    got2, _ = kl_encrypt(k6, n6, a6, p6, m=m)
    st, ptd = kl_decrypt(k5, n5, a5, w5, m=_fresh_ready(m))
    chk(end_state == KL_STATE_ENC_LAST_BLOCK and reset and got1 == w5 and got2 == w6
        and st == 'Success' and ptd == p5,
        "the encryption path ends in Enc_Last_Block (no Success); kl.setst Ready "
        "clears nonce, ctr, tmp, SIV and the same CL encrypts C.1 #14, then decrypts #15")
    m = GcmSivCL.provisioned(k5)
    kl_decrypt(k5, n5, a5, w5, m=m)
    m.exec('B', 0, 128)
    chk(m.state == KL_STATE_INVALID, "SGR5: kl.exec in Success -> Invalid")
    m = GcmSivCL.provisioned(k5)
    m.exec('A', 0, 128)
    chk(m.state == KL_STATE_INVALID, "SGR2: kl.exec in Ready -> Invalid")

    # -- counter rule ---------------------------------------------------------
    print()
    for path, label in ((at_encrypt, 'Encrypt'), (at_decrypt, 'Decrypt')):
        m = path()
        m.ctr = M32 - 1
        m.exec('A', 0, 128)
        st1 = m.state
        m.exec('A', 0, 128)
        chk(st1 != KL_STATE_INVALID and m.state == KL_STATE_INVALID,
            f"{label}: ctr = 2^32-2 is processed, ctr = 2^32-1 puts the CL in Invalid")
    for path, last, label in ((at_encrypt, KL_STATE_ENC_LAST_BLOCK, 'Enc_Last_Block'),
                              (at_decrypt, KL_STATE_DEC_LAST_BLOCK, 'Dec_Last_Block')):
        m = path()
        m.ctr = M32
        m.setst(last, 'B', 8)
        m.exec('A', 0x5A, 8)
        chk(m.state == KL_STATE_INVALID, f"{label}: ctr = 2^32-1 puts the CL in Invalid")
    m = at_encrypt(4)
    ref = at_encrypt(4)
    ref.ctr = M32 - 2
    want2 = ref.exec('A', b2v(bytes(range(32))), 256)
    m.ctr = M32 - 2
    got = m.exec('A', b2v(bytes(range(32)) + bytes(32)), 512)
    chk(got == want2 and m.state == KL_STATE_INVALID and m.export_content() == (0, 0),
        "IRR6/SGR16/SGR10: a 4-block kl.exec hitting ctr = 2^32-1 at its third block "
        "keeps two blocks, zeroes the rest, and the CL keeps only its MDH")

    # -- last blocks ------------------------------------------------------------
    print()
    for path, last, label in ((at_encrypt, KL_STATE_ENC_LAST_BLOCK, 'Enc'),
                              (at_decrypt, KL_STATE_DEC_LAST_BLOCK, 'Dec')):
        for bad_lbl in (0, 4, 12, 121, 128):
            m = path()
            if path is at_encrypt:
                m.exec('A', 0, 0)
            m.setst(last, 'B', bad_lbl)
            chk(m.state == KL_STATE_INVALID,
                f"{label}_Last_Block: last_blk_len = {bad_lbl} puts the CL in Invalid")
        for good in (8, 120):
            m = path()
            m.setst(last, 'B', good)
            chk(m.state == last and m.last_blk_len == good,
                f"{label}_Last_Block: last_blk_len = {good} is accepted")
        m = path()
        m.setst(last, 'B', 64)
        first = m.exec('A', b2v(bytes(range(1, 17))), 128)
        snap = (m.ctr, m.tmp)
        again = m.exec('A', b2v(bytes(range(1, 17))), 128)
        chk(first >> 64 == 0 and first != 0 and again == 0 and (m.ctr, m.tmp) == snap,
            f"{label}_Last_Block: excess input ignored, OUTPUT above last_blk_len clear "
            f"(MGR6); a second kl.exec is a no-op writing zeros")
        m = path()
        m.setst(last, 'B', 64)
        m.exec('A', b2v(bytes(7)), 56)
        chk(m.state == KL_STATE_INVALID,
            f"{label}_Last_Block: KLLEN (56) < last_blk_len (64) -> Invalid")

    # -- general rules ------------------------------------------------------------
    print()
    for pre, form, label in ((at_hash_absorb, 'B', 'Hash_Absorb'),
                             (at_encrypt, 'A', 'Encrypt'), (at_decrypt, 'A', 'Decrypt')):
        m = pre()
        out = m.exec(form, b2v(bytes(15)), 120)
        chk(m.state == KL_STATE_INVALID and not out,
            f"MGR2: KLLEN = 120 in {label} -> no operation, zero output, Invalid")
    m = at_hash_absorb()
    m.exec('A', 0, 128)
    chk(m.state == KL_STATE_INVALID, "MGR1: Form A kl.exec in Hash_Absorb -> Invalid")
    m = at_hash_absorb(policy=0b10)
    m.setst(KL_STATE_ENC_TAG_FINALIZE)
    chk(m.state == KL_STATE_INVALID,
        "_MachinePolicy_ = decrypt only: Hash_Absorb -> Enc_Tag_Finalize -> Invalid")
    m = at_hash_absorb(policy=0b01)
    m.setst(KL_STATE_DECRYPT)
    chk(m.state == KL_STATE_INVALID,
        "_MachinePolicy_ = encrypt only: Hash_Absorb -> Decrypt -> Invalid")
    st, ptd = kl_decrypt(k5, n5, a5, w5, m=GcmSivCL.provisioned(k5, policy=0b10))
    chk(st == 'Success', "_MachinePolicy_ = decrypt only: the decryption path works")
    m = at_encrypt()
    m.setst(KL_STATE_EXPIRED)
    out = m.exec('A', 0x1234, 128)
    m.setst(KL_STATE_READY)
    chk(m.state == KL_STATE_EXPIRED and out == 0,
        "SGR15/SGR16: in an Error State kl.exec and kl.setst Ready do nothing")
    m = at_hash_absorb()
    m.setst(KL_STATE_HASH_ABSORB)
    _absorb_string(m, a5, 128)
    m.setst(KL_STATE_DECRYPT)
    m.setst(KL_STATE_DECRYPT)
    chk(m.state == KL_STATE_DECRYPT, "SGR4: same-State kl.setst in Hash_Absorb and Decrypt")
    m = at_hash_absorb()
    m.setst(KL_STATE_ENC_TAG_FINALIZE)
    siv = m.exec('A', _length_block(b'', b'') | (0xFF << 140), 256)
    chk(v2b(siv, 32) == bytes.fromhex(VECTORS[0]['ct_tag']) + bytes(16),
        "Enc_Tag_Finalize: only the 128 LSBs of a 256-bit INPUT are considered, "
        "OUTPUT[255:128] is clear")
    st, _ = kl_decrypt(key, nonce, b'', bytes.fromhex(VECTORS[0]['ct_tag']),
                       length_block=_length_block(b'', b'') | (0xFF << 140))
    chk(st == 'Success', "Dec_Tag_Finalize: only the 128 LSBs of a longer INPUT are considered")

    # -- interruption (IRR7) ------------------------------------------------------
    print()
    v10 = VECTORS[9]
    k10, n10, a10, p10, w10 = unhex(v10, 'key', 'nonce', 'aad', 'pt', 'ct_tag')
    m = GcmSivCL.provisioned(k10)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(n10))
    m.setst(KL_STATE_HASH_ABSORB)
    m.exec('B', b2v(p10), 384, interrupt_after=2)
    h = (m.halted, m.klstart)
    m.exec('B', b2v(p10), 384, resume=True)
    m.setst(KL_STATE_ENC_TAG_FINALIZE)
    tag = m.exec('A', _length_block(a10, p10), 128)
    o1 = m.exec('A', b2v(p10), 384, interrupt_after=1)
    h2 = (m.halted, m.klstart)
    o2 = m.exec('A', b2v(p10), 384, resume=True)
    ct = v2b(sl(o1, 127, 0) | (o2 & ~MASK128), 48)
    chk(h == (True, 32) and h2 == (True, 16) and ct + v2b(tag, 16) == w10,
        "IRR7: Hash_Absorb halted at klstart = 32 and Encrypt at klstart = 16, both "
        "resumed: C.2 #6 reproduced")
    m = at_encrypt()
    m.klstart = 8
    m.exec('A', 0, 256, resume=True)
    chk(m.state == KL_STATE_INVALID, "resuming at klstart = 8 (not an interruption point) -> Invalid")

    # -- Serialized Content, export/import, MGR4 -------------------------------------
    print()
    for kk, skid, blocks in ((key, None, 5), (k256, None, 6), (None, 0x00C0FFEE00C0FFEE, 4)):
        m = GcmSivCL.provisioned(kk, skid=skid)
        _, nb = m.export_content()
        kb = 64 if skid else 8 * len(kk)
        chk(nb == 128 * blocks == pad128(kb + 400),
            f"Content for {'a SKID' if skid else f'k = {8 * len(kk)}'}: {kb} + 96 + 32 + "
            f"128 + 128 + 16 bits, {blocks} blocks")
    got, _ = kl_encrypt(None, n5, a5, p5, m=GcmSivCL.provisioned(skid=0x00C0FFEE00C0FFEE))
    chk(got == w5, "a key given by a SKID (MGR8): C.1 #15 reproduced")
    m = GcmSivCL.provisioned(k5)
    m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(n5))
    m.setst(KL_STATE_HASH_ABSORB)
    _absorb_string(m, a5, 128)
    m.setst(KL_STATE_ENC_TAG_FINALIZE)
    siv = m.exec('A', _length_block(a5, p5 + bytes(12)), 128)   # any lengths will do here
    m.exec('A', b2v(p5[:16]), 128)
    v_, nb = m.export_content()
    chk(sl(v_, 127, 0) == b2v(k5) and sl(v_, 223, 128) == b2v(n5)
        and sl(v_, 255, 224) == 1 and sl(v_, 383, 256) == siv
        and sl(v_, 511, 384) == m.tmp and sl(v_, 527, 512) == 0 and v_ >> 528 == 0,
        "positions: key [127:0], nonce [223:128], bin(ctr,32) [255:224], SIV [383:256], "
        "tmp [511:384], last_blk_len [527:512]")
    for where in ('Hash_Absorb', 'Encrypt', 'Dec_Last_Block'):
        for ctl in (False, True):
            m = GcmSivCL.provisioned(k5)
            if where == 'Dec_Last_Block':
                m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(n5))
                m.setst(KL_STATE_SET_AUX_VALUE_2, 'C', b2v(w5[-16:]))
                m.setst(KL_STATE_HASH_ABSORB)
                _absorb_string(m, a5, 128)
                m.setst(KL_STATE_DECRYPT)
                pt = v2b(m.exec('A', b2v(w5[:16]), 128), 16)
                m.setst(KL_STATE_DEC_LAST_BLOCK, 'B', 32)
                v_, _ = m.export_content()
                m2 = GcmSivCL.imported(m.state, v_, 128, stale_derived=ctl)
                pt += v2b(m2.exec('A', b2v(w5[16:20]), 32), 4)
                m2.setst(KL_STATE_DEC_TAG_FINALIZE)
                m2.exec('B', _length_block(a5, pt), 128)
                good = m2.state == KL_STATE_SUCCESS and pt == p5
            else:
                m.setst(KL_STATE_SET_AUX_VALUE, 'C', b2v(n5))
                m.setst(KL_STATE_HASH_ABSORB)
                _absorb_string(m, a5, 128)
                if where == 'Encrypt':
                    _absorb_string(m, p5, 128)
                    m.setst(KL_STATE_ENC_TAG_FINALIZE)
                    tag = m.exec('A', _length_block(a5, p5), 128)
                    ct = v2b(m.exec('A', b2v(p5[:16]), 128), 16)
                v_, _ = m.export_content()
                m2 = GcmSivCL.imported(m.state, v_, 128, stale_derived=ctl)
                if where == 'Hash_Absorb':
                    _absorb_string(m2, p5, 128)
                    m2.setst(KL_STATE_ENC_TAG_FINALIZE)
                    tag = m2.exec('A', _length_block(a5, p5), 128)
                    ct = b''
                    rest = p5
                else:
                    rest = p5[16:]
                ct += _crypt_body(m2, rest, 128, KL_STATE_ENC_LAST_BLOCK)
                good = ct + v2b(tag, 16) == w5
            if ctl:
                expect_fail(f"stale-derived: import in {where} without MGR4 "
                            f"re-derivation completes C.1 #15", good)
            else:
                chk(good, f"export in {where}, import (enc_key/auth_key re-derived, "
                          f"MGR4), completion: C.1 #15 reproduced")

    # -- kl.derive into `key` -------------------------------------------------------
    print()
    src = bytes.fromhex(VECTORS[11]['key'])
    for vv, length in ((VECTORS[6], 16), (VECTORS[6], 32), (VECTORS[11], 32)):
        kx, nx, ax, px, wx = unhex(vv, 'key', 'nonce', 'aad', 'pt', 'ct_tag')
        m = GcmSivCL.provisioned(bytes(len(kx)))
        source = kx + src[len(kx):] if length > len(kx) else kx
        m.derive_into_key(source, length)
        got, _ = kl_encrypt(None, nx, ax, px, m=m)
        chk(got == wx, f"kl.derive of {length} bytes into `key` (k = {8 * len(kx)}) in "
                       f"Ready: {vv['src']} reproduced")
    m = at_hash_absorb()
    m.derive_into_key(src, 16)
    chk(m.state == KL_STATE_INVALID, "kl.derive into `key` outside Ready -> Invalid")
    m = GcmSivCL.provisioned(skid=0x00C0FFEE00C0FFEE)
    m.derive_into_key(src, 16)
    chk(m.state == KL_STATE_INVALID, "kl.derive into a `key` configured by a SKID -> Invalid")

    # -- negative control ---------------------------------------------------------
    # GCM assembles its length block big-endian; the spec mandates bin()
    # (little-endian).  Using bswap'd/big-endian encodings must not
    # reproduce the RFC tag.
    print()
    v = VECTORS[1]                           # nonzero lengths
    key, nonce, aad, pt, want = unhex(v, 'key', 'nonce', 'aad', 'pt', 'ct_tag')
    got_be, _ = kl_encrypt(key, nonce, aad, pt,
                           length_block=_length_block_be(aad, pt))
    fired = got_be != want
    print(f"{'FAIL (expected)' if fired else 'PASS'}  "
          f"BE-lengths GCM-style length block vs {v['src']}")
    chk(fired, "negative control fired: BE length block changes the tag")

    print("\nSPEC-NOTE 1: <<KLEE-GCM-SIV-mode>> says an kl.setst naming Encrypt \"is a "
          "not-allowed transition and invalidates the CL\", while SGR4 lets kl.setst "
          "name the current State in any Valid State, and Book 4's "
          "<<KLEE-pseudocode-GCM-SIV-encryption>> issues `kl.setst K0, "
          "#kl_state_encrypt` right after the Enc_Tag_Finalize kl.exec, i.e. in "
          "Encrypt.  The model follows the Machine text (Invalid), under which the "
          "Book 4 sequence invalidates the CL; either drop that line from Book 4 or "
          "restrict the rule to kl.setst issued in a State other than Encrypt.")
    print("INFO 1: the counter rule (ctr = 2^32-1 -> Invalid) admits at most "
          "2^32 - 1 blocks per message, one fewer than RFC 8452's P_MAX = 2^36 "
          "bytes; a message of exactly 2^36 bytes cannot be processed.")
    print("INFO 2: the encryption path ends in Encrypt or Enc_Last_Block, never in "
          "Success; software returns to Ready with kl.setst (SGR8), as done here.")
    print("INFO 3: MGR10 does not apply: no GCM-SIV State performs an IRR4 "
          "instruction; block-iterated kl.exec is interrupted between blocks "
          "(IRR7) and klstart must be a multiple of 16 bytes on resumption.  A "
          "transition that _MachinePolicy_ forbids is taken to be not allowed "
          "(MGR1).  After a kl.derive into `key` and on entering Ready, enc_key "
          "and auth_key are re-derived (MGR4); this is not observable, since "
          "Set_Aux_Value derives them again.")
    print("OBSERVATIONs (editorial): (1) the Dec_Tag_Finalize kl.exec is typeset "
          "``kl.exec Kn|K{Xn}, INPUT``` with a third backtick; (2) \"If `tmp` = "
          "SIV match\" should read \"If `tmp` = SIV\"; (3) in Enc_Last_Block and "
          "Dec_Last_Block, `INPUT xor enc_blk(...)` xors a KLLEN-bit INPUT with a "
          "128-bit block, which the notation (|V| = |W|) does not allow when "
          "KLLEN < 128; `INPUT[last_blk_len-1:0] xor enc_blk(...)[last_blk_len-1:0]` "
          "would; (4) \"a `kl.setst`\" in the Encrypt paragraph (rename residue).")

    print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def _fresh_ready(m):
    """Return m after a kl.setst to Ready (a CL reused for the next message)."""
    m.setst(KL_STATE_READY)
    return m


if __name__ == '__main__':
    sys.exit(main())
