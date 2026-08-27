#!/usr/bin/env python3
"""AES-GCM-SIV known-answer tests for the ACE GCM-SIV mode.

Validates the GCM-SIV mode of the draft ACE specification, section
<<ACE-GCM-SIV-mode>> (src/ace-ISA-algorithms.adoc), against RFC 8452.

Two independent implementations are exercised:

  REF   AES-GCM-SIV exactly as RFC 8452 sections 4-5 specify it, one-pass
        functions over byte strings.
  ACE   the state machine of <<ACE-GCM-SIV-mode>>, transcribed literally:
        ACE values (little-endian, common.py conventions), states
        Set_Aux_Value / Set_Aux_Value_2 / Hash_Absorb / Enc_Tag_Finalize /
        Encrypt / Enc_Last_Block / Decrypt / Dec_Last_Block /
        Dec_Tag_Finalize, with absorb(data) = { tmp ^= data;
        tmp = Montmul(tmp, auth_key) }, chunked Hash_Absorb (ACELEN a
        multiple of 128), the counter block
        1 @ SIV[126:32] @ bin((int(SIV[31:0])+ctr) mod 2^32, 32),
        the ctr = 2^32-1 Invalid rule and the last_blk_len rules.

Anchors (embedded, offline):
  * RFC 8452 Appendix C.1 (AES-128-GCM-SIV), C.2 (AES-256-GCM-SIV) and
    C.3 (counter-wrap) test vectors, transcribed from
    https://www.rfc-editor.org/rfc/rfc8452.txt (April 2019).
    Selection covers empty AAD+PT, non-block-multiple PT (Enc_Last_Block /
    Dec_Last_Block), nonempty AAD, multi-block PT, and the counter wrap
    mod 2^32.  Five vectors carry the RFC's per-vector intermediates
    (record_authentication_key, record_enc_key, POLYVAL result), anchoring
    RFC8452_KeyDeriv and the absorb chain separately from the final result.

Negative control (KAT-EXPECT-FAIL): assembling the length block with
big-endian (GCM-style, bswap) length encodings instead of the spec's
little-endian bin() must change the tag.

Spec notes (reported, not patched):
  * RFC8452_KeyDeriv is defined (<<ACE-SCC-RFC8452-derivation>>) only for
    256-bit keys via AESE256, yet <<ACE-GCM-SIV-mode>> admits k = 128 and
    invokes RFC8452_KeyDeriv(key, nonce) for it.  For k = 128 this harness
    implements the natural RFC 8452 derivation (AES-128, counter blocks
    0..3), which the C.1 intermediates confirm.
  * The instruction/Form used to enter Enc_Tag_Finalize, Encrypt, Decrypt
    and Dec_Tag_Finalize is now stated (review finding m8, fixed): each is a
    Form A ace.setst, and the value the state consumes is the INPUT of the
    ace.exec issued *in* the state, not an argument of the transition.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bin_, montmul, aes_encrypt, MASK128,
                    selftest)

M32 = (1 << 32) - 1

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
# ACE: the state machine of <<ACE-GCM-SIV-mode>>, on ACE values
# ======================================================================

class AceGcmSiv:
    """Literal transcription of the <<ACE-GCM-SIV-mode>> state machine.

    Each method is one instruction of the spec text.  ACELEN is the bit
    length of the INPUT value passed to a chunked instruction; it must be
    a multiple of 128 (b = 128) and blocks within INPUT are processed in
    increasing byte (= increasing bit-significance) order.
    """
    TRANSITIONS = {
        'Ready':           {'Set_Aux_Value'},
        'Set_Aux_Value':   {'Set_Aux_Value', 'Set_Aux_Value_2', 'Hash_Absorb'},
        'Set_Aux_Value_2': {'Set_Aux_Value_2', 'Hash_Absorb'},
        'Hash_Absorb':     {'Enc_Tag_Finalize', 'Decrypt'},
        'Enc_Tag_Finalize': {'Encrypt'},
        'Encrypt':         {'Enc_Last_Block'},
        'Decrypt':         {'Dec_Last_Block', 'Dec_Tag_Finalize'},
        'Dec_Last_Block':  {'Dec_Tag_Finalize'},
        'Dec_Tag_Finalize': {'Success', 'Failure'},
    }

    def __init__(self, key: bytes):
        assert len(key) in (16, 32)          # 128|k
        self.key = key
        self.state = 'Ready'
        # Ready-state initialization: nonce, ctr, tmp, SIV <- 0
        self.nonce = 0
        self.ctr = 0
        self.tmp = 0
        self.SIV = 0
        self.last_blk_len = 0
        self.enc_key = None
        self.auth_key = 0
        self.polyval_probe = None            # tmp right after the length absorb

    # -- plumbing ------------------------------------------------------
    def _goto(self, st):
        if self.state == 'Invalid':
            return
        assert st in self.TRANSITIONS.get(self.state, ()), \
            f'illegal transition {self.state} -> {st}'
        self.state = st

    def _invalid(self):
        self.state = 'Invalid'

    def _enc_blk(self, v128: int) -> int:
        return b2v(aes_encrypt(self.enc_key, v2b(v128, 16)))

    def _absorb(self, data128: int):
        self.tmp ^= data128
        self.tmp = montmul(self.tmp, self.auth_key)

    def _keystream_block(self) -> int:
        blk = cat((1, 1), (sl(self.SIV, 126, 32), 95),
                  ((sl(self.SIV, 31, 0) + self.ctr) & M32, 32))
        return self._enc_blk(blk)

    # -- instructions --------------------------------------------------
    def setst_set_aux_value(self, INPUT: int):
        """ace.setst Form C, #ace_state_set_aux_value."""
        self._goto('Set_Aux_Value')
        self.nonce = sl(INPUT, 95, 0)
        self.enc_key, self.auth_key = rfc8452_keyderiv(self.key, self.nonce)

    def setst_set_aux_value_2(self, INPUT: int):
        """ace.setst Form C, #ace_state_set_aux_value_2 (SIV, decryption)."""
        self._goto('Set_Aux_Value_2')
        self.SIV = INPUT & MASK128

    def setst_hash_absorb(self):
        """ace.setst Form A, #ace_state_hash_absorb."""
        self._goto('Hash_Absorb')

    def exec_hash_absorb(self, INPUT: int, acelen: int):
        """ace.exec Form B in Hash_Absorb; absorbs ACELEN/128 blocks."""
        assert self.state == 'Hash_Absorb' and acelen % 128 == 0
        for j in range(acelen // 128):
            self._absorb(sl(INPUT, 128 * j + 127, 128 * j))

    def exec_enc_tag_finalize(self, INPUT: int) -> int:
        """ace.exec Form A in Enc_Tag_Finalize; INPUT is the length block."""
        self._goto('Enc_Tag_Finalize')
        self._absorb(INPUT & MASK128)        # ACELEN > 128: 128 LSBs only
        self.polyval_probe = self.tmp
        self.tmp = self._enc_blk(cat((0, 1), (sl(self.tmp, 126, 96), 31),
                                     (sl(self.tmp, 95, 0) ^ self.nonce, 96)))
        self.SIV = self.tmp
        return self.SIV                      # OUTPUT

    def exec_encrypt(self, INPUT: int, acelen: int) -> int:
        """ace.exec Form A in Encrypt; ACELEN/128 full blocks."""
        if self.state != 'Encrypt':
            self._goto('Encrypt')
        assert acelen % 128 == 0
        OUTPUT = 0
        for j in range(acelen // 128):
            if self.ctr == M32:
                self._invalid()
                return 0
            blk = sl(INPUT, 128 * j + 127, 128 * j)
            OUTPUT |= (blk ^ self._keystream_block()) << (128 * j)
            self.ctr += 1
        return OUTPUT

    def setst_enc_last_block(self, Xs: int):
        """ace.setst Form B entering Enc_Last_Block; Xs = last_blk_len."""
        self._goto('Enc_Last_Block')
        if Xs == 0 or Xs > 120 or Xs % 8 != 0:
            self._invalid()
            return
        self.last_blk_len = Xs

    def exec_enc_last_block(self, INPUT: int) -> int:
        assert self.state == 'Enc_Last_Block'
        if self.last_blk_len == 0:
            return 0
        if self.ctr == M32:
            self._invalid()
            return 0
        lbl = self.last_blk_len
        OUTPUT = sl(INPUT ^ self._keystream_block(), lbl - 1, 0)
        self.ctr += 1
        self.last_blk_len = 0
        return OUTPUT                        # zeros(128-lbl) @ ...

    def exec_decrypt(self, INPUT: int, acelen: int) -> int:
        """ace.exec Form A in Decrypt; decrypt then absorb the plaintext."""
        if self.state != 'Decrypt':
            self._goto('Decrypt')
        assert acelen % 128 == 0
        OUTPUT = 0
        for j in range(acelen // 128):
            if self.ctr == M32:
                self._invalid()
                return 0
            blk = sl(INPUT, 128 * j + 127, 128 * j)
            out = blk ^ self._keystream_block()
            self._absorb(out)
            OUTPUT |= out << (128 * j)
            self.ctr += 1
        return OUTPUT

    def setst_dec_last_block(self, Xs: int):
        self._goto('Dec_Last_Block')
        if Xs == 0 or Xs > 120 or Xs % 8 != 0:
            self._invalid()
            return
        self.last_blk_len = Xs

    def exec_dec_last_block(self, INPUT: int) -> int:
        assert self.state == 'Dec_Last_Block'
        if self.last_blk_len == 0:
            return 0
        if self.ctr == M32:
            self._invalid()
            return 0
        lbl = self.last_blk_len
        OUTPUT = sl(INPUT ^ self._keystream_block(), lbl - 1, 0)
        self._absorb(OUTPUT)                 # zero-padded plaintext
        self.ctr += 1
        self.last_blk_len = 0
        return OUTPUT

    def exec_dec_tag_finalize(self, INPUT: int):
        """ace.exec Form B in Dec_Tag_Finalize; internal comparison."""
        self._goto('Dec_Tag_Finalize')
        self._absorb(INPUT & MASK128)
        self.polyval_probe = self.tmp
        self.tmp = self._enc_blk(cat((0, 1), (sl(self.tmp, 126, 96), 31),
                                     (sl(self.tmp, 95, 0) ^ self.nonce, 96)))
        self._goto('Success' if self.tmp == self.SIV else 'Failure')


def rfc8452_keyderiv(key: bytes, nonce_v: int):
    """<<ACE-SCC-RFC8452-derivation>>: A[i] = AESE(key, nonce @ bin(i,32)),
    enc_key = A[5][63:0] @ ... @ A[2][63:0], auth_key = A[1][63:0] @ A[0][63:0].

    The spec defines the function for 256-bit keys only (AESE256); for
    k = 128 (admitted by <<ACE-GCM-SIV-mode>>) this is the natural RFC 8452
    generalization: AES-128 with counter blocks 0..3.
    Returns (enc_key as bytes, auth_key as ACE value)."""
    n = 4 if len(key) == 16 else 6
    A = [b2v(aes_encrypt(key, v2b(cat((nonce_v, 96), (bin_(i, 32), 32)), 16)))
         for i in range(n)]
    auth_key = cat((sl(A[1], 63, 0), 64), (sl(A[0], 63, 0), 64))
    enc_parts = A[2:]
    enc_key = 0
    for j, a in enumerate(enc_parts):        # A[2] least significant
        enc_key |= sl(a, 63, 0) << (64 * j)
    return v2b(enc_key, 8 * len(enc_parts)), auth_key


# -- drivers -----------------------------------------------------------

def _absorb_string(m: AceGcmSiv, s: bytes, acelen: int):
    """Feed the zero-padded byte string s through Hash_Absorb in chunks of
    at most `acelen` bits; the final chunk covers only the remaining blocks."""
    p = _pad16(s)
    step = acelen // 8
    for i in range(0, len(p), step):
        chunk = p[i:i + step]
        m.exec_hash_absorb(b2v(chunk), 8 * len(chunk))

def _length_block(aad: bytes, pt: bytes) -> int:
    """INPUT <- bin(len_in_bits(plaintext), 64) @ bin(len_in_bits(AD), 64)."""
    return cat((bin_(len(pt) * 8, 64), 64), (bin_(len(aad) * 8, 64), 64))

def _length_block_be(aad: bytes, pt: bytes) -> int:
    """GCM-style negative control: 64-bit big-endian (bswap'd) encodings,
    laid out as the GCM length block byte string BE64(lenA) || BE64(lenP)."""
    return b2v((len(aad) * 8).to_bytes(8, 'big') +
               (len(pt) * 8).to_bytes(8, 'big'))

def ace_encrypt(key, nonce, aad, pt, acelen=128, length_block=None):
    m = AceGcmSiv(key)
    m.setst_set_aux_value(b2v(nonce))
    m.setst_hash_absorb()
    _absorb_string(m, aad, acelen)
    _absorb_string(m, pt, acelen)
    lb = _length_block(aad, pt) if length_block is None else length_block
    tag_v = m.exec_enc_tag_finalize(lb)
    full, rem = divmod(len(pt), 16)
    ct = bytearray()
    step = acelen // 8
    body = pt[:16 * full]
    for i in range(0, len(body), step):
        chunk = body[i:i + step]
        out = m.exec_encrypt(b2v(chunk), 8 * len(chunk))
        ct += v2b(out, len(chunk))
    if rem:
        if not body:
            m.exec_encrypt(0, 0)             # enter Encrypt with no blocks
        m.setst_enc_last_block(8 * rem)
        out = m.exec_enc_last_block(b2v(pt[16 * full:]))
        ct += v2b(out, 16)[:rem]
    return bytes(ct) + v2b(tag_v, 16), m

def ace_decrypt(key, nonce, aad, ctag, acelen=128, length_block=None):
    ct, tag = ctag[:-16], ctag[-16:]
    m = AceGcmSiv(key)
    m.setst_set_aux_value(b2v(nonce))
    m.setst_set_aux_value_2(b2v(tag))
    m.setst_hash_absorb()
    _absorb_string(m, aad, acelen)
    full, rem = divmod(len(ct), 16)
    pt = bytearray()
    step = acelen // 8
    body = ct[:16 * full]
    m.exec_decrypt(0, 0)                     # enter Decrypt (m8: no stated insn)
    for i in range(0, len(body), step):
        chunk = body[i:i + step]
        out = m.exec_decrypt(b2v(chunk), 8 * len(chunk))
        pt += v2b(out, len(chunk))
    if rem:
        m.setst_dec_last_block(8 * rem)
        out = m.exec_dec_last_block(b2v(ct[16 * full:]))
        pt += v2b(out, 16)[:rem]
    lb = _length_block(aad, bytes(pt)) if length_block is None else length_block
    m.exec_dec_tag_finalize(lb)
    return m.state, bytes(pt)


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

def main():
    global ok
    print(__doc__.splitlines()[0])
    print("Anchor level: mode standard-anchored against RFC 8452 Appendix C "
          "(final results and per-vector intermediates).\n")

    chk(selftest(), "common.py self-test (FIPS 197, RFC 8452 Appendix A)")

    for v in VECTORS:
        key, nonce = bytes.fromhex(v['key']), bytes.fromhex(v['nonce'])
        aad, pt = bytes.fromhex(v['aad']), bytes.fromhex(v['pt'])
        want = bytes.fromhex(v['ct_tag'])
        name = v['src']

        # REF: encryption and decryption
        got = ref_encrypt(key, nonce, pt, aad)
        chk(got == want, f"REF encrypt          {name}")
        okd, ptd = ref_decrypt(key, nonce, want, aad)
        chk(okd and ptd == pt, f"REF decrypt          {name}")
        bad = want[:-1] + bytes([want[-1] ^ 0x40])
        okd, ptd = ref_decrypt(key, nonce, bad, aad)
        chk(not okd and ptd == bytes(len(pt)),
            f"REF tampered tag     {name}")

        # REF intermediates, where the RFC gives them
        if 'auth_key' in v:
            auth, enc = ref_derive_keys(key, nonce)
            chk(auth.hex() == v['auth_key'] and enc.hex() == v['enc_key'],
                f"REF KeyDeriv interm. {name}")
            lb = _le64(len(aad) * 8) + _le64(len(pt) * 8)
            pv = ref_polyval(auth, _pad16(aad) + _pad16(pt) + lb)
            chk(pv.hex() == v['polyval'], f"REF POLYVAL interm.  {name}")

        # ACE model: encryption, ACELEN = 128
        got, m = ace_encrypt(key, nonce, aad, pt, acelen=128)
        chk(got == want, f"ACE encrypt 128      {name}")

        # ACE intermediates, where the RFC gives them
        if 'auth_key' in v:
            ek, ak = rfc8452_keyderiv(key, b2v(nonce))
            chk(v2b(ak, 16).hex() == v['auth_key'] and ek.hex() == v['enc_key'],
                f"ACE KeyDeriv interm. {name}")
            chk(v2b(m.polyval_probe, 16).hex() == v['polyval'],
                f"ACE POLYVAL interm.  {name}")

        # ACE model: chunked Hash_Absorb / multi-block exec, ACELEN = 256
        got, _ = ace_encrypt(key, nonce, aad, pt, acelen=256)
        chk(got == want, f"ACE encrypt 256      {name}")

        # ACE model: decryption, matching and tampered
        st, ptd = ace_decrypt(key, nonce, aad, want, acelen=128)
        chk(st == 'Success' and ptd == pt, f"ACE decrypt          {name}")
        st, _ = ace_decrypt(key, nonce, aad, bad, acelen=256)
        chk(st == 'Failure', f"ACE tampered tag     {name}")
        if len(want) > 16:
            badc = bytes([want[0] ^ 1]) + want[1:]
            st, _ = ace_decrypt(key, nonce, aad, badc)
            chk(st == 'Failure', f"ACE tampered CT      {name}")

    # -- structural rules ---------------------------------------------
    key = bytes.fromhex(VECTORS[1]['key'])
    nonce = bytes.fromhex(VECTORS[1]['nonce'])

    m = AceGcmSiv(key)
    m.setst_set_aux_value(b2v(nonce))
    m.setst_hash_absorb()
    m.exec_enc_tag_finalize(_length_block(b'', b'x' * 16))
    m.ctr = M32                              # force the saturation condition
    m.exec_encrypt(0, 128)
    chk(m.state == 'Invalid', "ctr = 2^32-1 in Encrypt puts the CR in Invalid")

    for bad_lbl in (0, 4, 121, 128):
        m = AceGcmSiv(key)
        m.setst_set_aux_value(b2v(nonce))
        m.setst_hash_absorb()
        m.exec_enc_tag_finalize(_length_block(b'', b'x' * 18))
        m.exec_encrypt(0, 0)
        m.setst_enc_last_block(bad_lbl)
        chk(m.state == 'Invalid',
            f"last_blk_len = {bad_lbl} puts the CR in Invalid")

    # -- negative control ---------------------------------------------
    # GCM assembles its length block big-endian; the spec mandates bin()
    # (little-endian).  Using bswap'd/big-endian encodings must not
    # reproduce the RFC tag.
    print("\nKAT-EXPECT-FAIL: BE-lengths")
    v = VECTORS[1]                           # nonzero lengths
    key, nonce = bytes.fromhex(v['key']), bytes.fromhex(v['nonce'])
    aad, pt = bytes.fromhex(v['aad']), bytes.fromhex(v['pt'])
    want = bytes.fromhex(v['ct_tag'])
    got_be, _ = ace_encrypt(key, nonce, aad, pt,
                            length_block=_length_block_be(aad, pt))
    fired = got_be != want
    print(f"{'FAIL (expected)' if fired else 'PASS'}  "
          f"BE-lengths GCM-style length block vs {v['src']}")
    chk(fired, "negative control fired: BE length block changes the tag")

    print("\nSPEC-NOTE: RFC8452_KeyDeriv (<<ACE-SCC-RFC8452-derivation>>) is "
          "defined for 256-bit keys only (AESE256), but <<ACE-GCM-SIV-mode>> "
          "admits k = 128 and calls RFC8452_KeyDeriv(key, nonce); the k = 128 "
          "derivation is underspecified.  This harness uses the natural "
          "RFC 8452 rule (AES-128, counter blocks 0..3), confirmed by the "
          "C.1 intermediates.")
    print("SPEC-NOTE: review m8 is fixed. Each transition into "
          "Enc_Tag_Finalize, Encrypt, Decrypt and Dec_Tag_Finalize is now "
          "stated to be a Form A ace.setst, with the value the state consumes "
          "supplied as the INPUT of the ace.exec issued in the state; the "
          "model no longer has to infer the Form.")

    print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
