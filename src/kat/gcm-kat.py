#!/usr/bin/env python3
"""Known-answer tests for <<KLEE-GCM-mode>> and <<KLEE-GCM-with-IV-mode>>.

What this validates
-------------------
REF   a straight SP 800-38D implementation on *byte strings* (big-endian counter
      blocks, GHASH over 16-byte strings), anchored by the classic McGrew-Viega /
      SP 800-38D test cases 1-6 (AES-128) and 13-18 (AES-256).  A second
      rendering, REF-bits, follows SP 800-38D sections 6-7 on *bit strings*
      (MSB_s, 0^s, [x]_s); it is anchored by reducing to REF on the same vectors
      and is the reference for lengths that are not whole bytes.

KLEE  the two Machines of `src/ace-ISA-machines.adoc` (<<KLEE-process-VLI>>,
      <<KLEE-GCM-mode>>, <<KLEE-GCM-with-IV-mode>>), transcribed literally on
      KLEE values (`src/ace-notation.adoc`: byte i at bits [8i+7:8i], the left
      operand of @ most significant) and driven by numbered kl.setst / kl.exec
      instructions with the State constants of <<KLEE-state-constants-symmetric>>.
      _Set_Aux_Value_ runs Procedure process_VLI literally (mode = xor_accumulate,
      block = state = tag), with the IV split over several transfers, interrupted
      and resumed through klstart, and exported/imported part-way through.
      Galoismul is checked against its own definition in <<KLEE-GCM-mode>>.

Also checked: the counter-wrap rule (Invalid exactly when `ctr` reaches
`(start_ctr - 1) mod 2^32`, exercised by seeding the counter field, and in the
middle of a multi-block kl.exec, whose completed prefix stays written); the
Serialized Content layout and export/import, including the _Set_Aux_Value_
overlay; the derived field `auth_key` (AGR4) on import and after a kl.derive
into `key` (<<KLEE-derive-endpoints>>); the kl.setst/kl.exec rules of the
Machines and of the general rules (AGR1-AGR6, SGR2-SGR16, IRR6/IRR7); and GCM
with Set IV: key and J0 in the PI, no _Set_Aux_Value_, no block budget, and a
permitted transition back to _Ready_.

Negative controls (declared with KAT-EXPECT-FAIL) re-run the KLEE model with the
two halves of the length block swapped, with a little-endian counter, with the
IV accumulated in J0 (whose Serialized Content slot the _Set_Aux_Value_ overlay
replaces) across an export/import, and with `auth_key` not re-derived after a
kl.derive into `key`; all must fail.

Both length parameters, last_blk_len and the IV length Xs, are restricted to
multiples of 8: for any other value the Machine keeps the LOW bits of the final
byte (INPUT[last_blk_len-1:0], enc_blk(...)[last_blk_len-1:0]), whereas
SP 800-38D's bit strings use its HIGH bits (MSB_len, and IV || 0^s), and the
GHASH length block is the byte count times 8 (<<KLEE-truncation-vs-length>>)
rather than the true bit length.  No placement of a partial byte reproduces
SP 800-38D, so such lengths send the CL to _Invalid_; the checks below cover
both the conformance of every admissible length and that rejection.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import (b2v, v2b, sl, cat, bswap, bin_, aes_encrypt,
                    gmul_ghash, kl_galoismul, selftest, MASK128)

B = 128                      # <<KLEE-GCM-mode>> Parameters: b (and the granularity)
MASK32 = (1 << 32) - 1


def mask(n):
    return (1 << n) - 1


def pad128(n):
    """Implicit zero padding of a PI or Serialized Content to a multiple of 128 bits."""
    return -(-n // 128) * 128


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


def _be64(n):
    return n.to_bytes(8, "big")


def ref_j0(K: bytes, IV: bytes) -> bytes:
    """SP 800-38D 7.1."""
    if len(IV) == 12:
        return IV + b"\x00\x00\x00\x01"
    H = aes_encrypt(K, bytes(16))
    return ghash(H, _pad16(IV) + bytes(8) + _be64(len(IV) * 8))


def _inc32(b: bytes, n=1) -> bytes:
    return b[:12] + ((int.from_bytes(b[12:], "big") + n) & MASK32).to_bytes(4, "big")


def ref_gctr(K: bytes, icb: bytes, X: bytes) -> bytes:
    """SP 800-38D 6.5 on byte strings."""
    out, cb = b"", icb
    for i in range(0, len(X), 16):
        out += bytes(x ^ y for x, y in zip(X[i:i + 16], aes_encrypt(K, cb)))
        cb = _inc32(cb)
    return out


def ref_gcm_j0(K: bytes, J0: bytes, A: bytes, P: bytes, icb=None):
    """SP 800-38D 7.1 steps 3-6 for a given J0 (ICB inc32(J0) unless given)."""
    H = aes_encrypt(K, bytes(16))
    C = ref_gctr(K, _inc32(J0) if icb is None else icb, P)
    S = ghash(H, _pad16(A) + _pad16(C) + _be64(len(A) * 8) + _be64(len(C) * 8))
    return C, bytes(x ^ y for x, y in zip(S, aes_encrypt(K, J0)))


def ref_gcm(K: bytes, IV: bytes, A: bytes, P: bytes):
    """Returns (ciphertext, 16-byte tag)."""
    return ref_gcm_j0(K, ref_j0(K, IV), A, P)


# ---------------------------------------------------------------------
# REF-bits: SP 800-38D 6-7 on bit strings (value, nbits), first bit = MSB
# ---------------------------------------------------------------------

def bits_of(b: bytes):
    return (int.from_bytes(b, "big"), 8 * len(b))


def bits_cat(*xs):
    v, n = 0, 0
    for x, m in xs:
        v, n = (v << m) | x, n + m
    return (v, n)


def bits_msb(x, s):
    return (x[0] >> (x[1] - s), s)


def bits_ghash(H: bytes, X):
    v, n = X
    assert n % 128 == 0
    y = bytes(16)
    for i in range(n // 128):
        blk = ((v >> (n - 128 * (i + 1))) & MASK128).to_bytes(16, "big")
        y = gmul_ghash(bytes(a ^ b for a, b in zip(y, blk)), H)
    return y


def bits_gctr(K: bytes, icb: bytes, X):
    v, n = X
    out, cb, pos = (0, 0), icb, 0
    while pos < n:
        m = min(128, n - pos)
        xi = (v >> (n - pos - m)) & mask(m)
        yi = xi ^ bits_msb(bits_of(aes_encrypt(K, cb)), m)[0]
        out, cb, pos = bits_cat(out, (yi, m)), _inc32(cb), pos + m
    return out


def ref_bits_gcm(K: bytes, IV, A, P):
    """SP 800-38D Algorithm 4 with IV, A, P bit strings; returns (C, T) bit strings."""
    H = aes_encrypt(K, bytes(16))
    if IV[1] == 96:
        J0 = bits_cat(IV, (0, 31), (1, 1))[0].to_bytes(16, "big")
    else:
        s = pad128(IV[1]) - IV[1]
        J0 = bits_ghash(H, bits_cat(IV, (0, s + 64), (IV[1], 64)))
    C = bits_gctr(K, _inc32(J0), P)
    u, v = pad128(C[1]) - C[1], pad128(A[1]) - A[1]
    S = bits_ghash(H, bits_cat(A, (0, v), C, (0, u), (A[1], 64), (C[1], 64)))
    return C, bits_gctr(K, J0, bits_of(S))


def bits_to_bytes(x):
    """SP 800-38D's own byte serialization: a partial final byte is LEFT-aligned."""
    v, n = x
    q = -(-n // 8)
    return (v << (8 * q - n)).to_bytes(q, "big")


# =====================================================================
# Galoismul from its definition in <<KLEE-GCM-mode>>
# =====================================================================

def galoismul_def(a, b):
    """GF(2)[x] mod x^128 + x^7 + x^2 + x + 1; the value V represents the element
    whose coefficient of x^(8i+j) is V[8i + (7-j)]."""
    def to_poly(V):
        return sum(1 << (8 * i + j) for i in range(16) for j in range(8)
                   if (V >> (8 * i + 7 - j)) & 1)

    def from_poly(p):
        return sum(1 << (8 * i + 7 - j) for i in range(16) for j in range(8)
                   if (p >> (8 * i + j)) & 1)

    pa, pb, r = to_poly(a), to_poly(b), 0
    while pb:
        if pb & 1:
            r ^= pa
        pa, pb = pa << 1, pb >> 1
    for d in range(254, 127, -1):
        if (r >> d) & 1:
            r ^= (1 << d) | (0x87 << (d - 128))
    return from_poly(r)


# =====================================================================
# KLEE model
# =====================================================================

# State constants: <<KLEE-state-off>>, <<KLEE-states-valid>>,
# <<KLEE-state-constants-symmetric>>, <<KLEE-states-error>>.
KL_STATE_UNCONFIGURED = 0
KL_STATE_READY = 1
KL_STATE_HASH_ABSORB = 2
KL_STATE_HASH_VERIFY = 5
KL_STATE_ENCRYPT = 7
KL_STATE_DECRYPT = 8
KL_STATE_ENC_LAST_BLOCK = 9
KL_STATE_DEC_LAST_BLOCK = 10
KL_STATE_ENC_TAG_FINALIZE = 11
KL_STATE_DEC_TAG_FINALIZE = 12
KL_STATE_SET_AUX_VALUE = 13
KL_STATE_SUCCESS = 46
KL_STATE_FAILURE = 47
KL_STATE_PRIV_VIOLATION = 52
KL_STATE_INVALID = 49
ERROR_STATES = range(48, 56)

STATE_NAME = {0: "Unconfigured", 1: "Ready", 2: "Hash_Absorb", 5: "Hash_Verify",
              7: "Encrypt", 8: "Decrypt", 9: "Enc_Last_Block", 10: "Dec_Last_Block",
              11: "Enc_Tag_Finalize", 12: "Dec_Tag_Finalize", 13: "Set_Aux_Value",
              46: "Success", 47: "Failure", 49: "Invalid", 52: "Privilege Violation"}

# A system-specific System Key Store (<<KLEE-system-keys>>) for the SKID cases.
SKS = {0x0123456789ABCDEF: bytes.fromhex("feffe9928665731c6d6a8f9467308308")}


def process_VLI(M, INPUT, KLLEN, *, max_len, block, b, state, n, input_base,
                block_base, state_offset, cumul_len, process_block, finalize,
                mode, granularity, resuming=False, interrupt_after=None):
    """<<KLEE-process-VLI>>, *State Machine Behavior*, the kl.exec part, step by step.

    The parameters are references: `max_len`, `block`, `state`, `input_base`,
    `block_base` and `cumul_len` name attributes of the caller Machine M.
    `granularity` is enforced by the caller (Rule AGR2).  Returns 'invalid',
    'interrupted' (klstart set), 'terminated' (after finalize) or 'done'.
    """
    g = lambda r: getattr(M, r)
    s = lambda r, v: setattr(M, r, v)
    assert len({input_base, block_base, cumul_len}) == 3        # distinct locations
    ml = g(max_len)
    if ml != 0 and g(cumul_len) >= ml:                           # step 1
        return "invalid"
    s(input_base, 8 * M.klstart if resuming else 0)             # steps 2 and 3
    iterations = 0
    while g(input_base) < KLLEN:                                 # step 4
        if ml != 0:                                              # 4.a
            amount = min(KLLEN - g(input_base), b - g(block_base), ml - g(cumul_len))
        else:
            amount = min(KLLEN - g(input_base), b - g(block_base))
        assert amount > 0
        ib, bb = g(input_base), g(block_base)
        data = sl(INPUT, ib + amount - 1, ib)
        if mode == "assign":                                     # 4.b
            s(block, (g(block) & ~(mask(amount) << bb)) | (data << bb))
        else:                                                    # 4.c, xor_accumulate
            assert state_offset + b <= n
            s(state, g(state) ^ (data << (bb + state_offset)))
        s(input_base, ib + amount)                               # 4.d
        s(block_base, bb + amount)                               # 4.e
        if ml != 0:                                              # 4.f
            s(cumul_len, g(cumul_len) + amount)
        if g(block_base) == b:                                   # 4.g
            if process_block is not None:
                process_block()
            s(block_base, 0)
        if ml != 0 and g(cumul_len) == ml:                       # 4.h
            if finalize is not None:
                finalize()
            return "terminated"
        iterations += 1                                          # 4.i
        if interrupt_after is not None and iterations == interrupt_after \
                and g(input_base) < KLLEN:
            M.klstart = g(input_base) // 8
            return "interrupted"
    return "done"


class GcmCL:
    """A CL holding a CC of <<KLEE-GCM-mode>> (set_iv False) or of
    <<KLEE-GCM-with-IV-mode>> (set_iv True).

    The MDH is reduced to _State_, _MachinePolicy_ (bit 0 encryption, bit 1
    decryption, <<KLEE-Machine-field>>) and _KeyType_; `klstart` stands for the
    hart CSR.  `halted` is True after a precise halt (the instruction did not
    retire and is re-issued with resume=True).

    Negative-control switches: `le_counter` (counter read without bswap),
    `iv_into_J0` (the IV accumulated in J0), `stale_auth_key` (no AGR4
    re-derivation after `key` changes).
    """

    def __init__(self, set_iv=False, policy=0b11, *, le_counter=False,
                 iv_into_J0=False, stale_auth_key=False):
        self.set_iv, self.policy = set_iv, policy
        self.le_counter, self.iv_into_J0 = le_counter, iv_into_J0
        self.stale_auth_key = stale_auth_key
        self.state = KL_STATE_UNCONFIGURED
        self.klstart = 0
        self.halted = False
        self._clear_content()

    def _clear_content(self):
        self.k = self.key_type = self.skid = 0
        self.key = b""
        self.J0 = self.auth_key = self.tag = 0
        self.start_ctr = self.last_blk_len = 0
        self.len = self.input_base = self.block_base = self.cumul_len = 0

    # ---------------- provisioning, export, import ----------------

    @staticmethod
    def pi_content(key=None, J0=None, skid=None):
        """Provisioning Input Content (the fields after the MDH): `key` or SKID
        at Pos. ii, and for GCM with Set IV `J0` at Pos. iii.  Returns (value, bits)."""
        v, nbits = (skid, 64) if skid is not None else (b2v(key), 8 * len(key))
        if J0 is not None:
            v, nbits = v | (J0 << nbits), nbits + 128
        return v, pad128(nbits)

    def provision(self, content, k, key_type=0):
        """kl.mgmt completing a provisioning with the given PI Content."""
        self._clear_content()
        self.k, self.key_type = k, key_type
        kbits = 64 if key_type == 1 else k
        kf = sl(content, kbits - 1, 0)
        if key_type == 1:
            self.skid, self.key = kf, SKS[kf]
        else:
            self.key = v2b(kf, k // 8)
        if self.set_iv:
            # <<KLEE-GCM-with-IV-mode>>: "Upon provisioning, start_ctr <- int(bswap(J0[127:96]))"
            self.J0 = sl(content, kbits + 127, kbits)
            self.start_ctr = self._ctr_of(sl(self.J0, 127, 96))
        self.state = KL_STATE_READY           # "Completing a provisioning ... leads only to _Ready_"
        self._enter_ready()
        return self

    @classmethod
    def provisioned(cls, key, J0=None, skid=None, **kw):
        cl = cls(set_iv=J0 is not None, **kw)
        k = 8 * len(SKS[skid] if skid is not None else key)
        v, _ = cls.pi_content(key, J0, skid)
        return cl.provision(v, k, 1 if skid is not None else 0)

    def export_content(self):
        """The Serialized Content (Content1 plaintext), as (value, bits).
        A CL in an Error State is its MDH alone (SGR11)."""
        if self.state in ERROR_STATES:
            return 0, 0
        kbits = 64 if self.key_type == 1 else self.k
        kf = self.skid if self.key_type == 1 else b2v(self.key)
        if self.state == KL_STATE_SET_AUX_VALUE:
            # "While in state _Set_Aux_Value_, J0 is replaced by": len, input_base,
            # block_base, cumul_len (16+16+16+48 bits), then 32 bits of J0_padding.
            slot = cat((0, 32), (self.cumul_len, 48), (self.block_base, 16),
                       (self.input_base, 16), (self.len, 16))
        else:
            slot = self.J0
        v = cat((bin_(self.last_blk_len, 16), 16), (bin_(self.start_ctr, 32), 32),
                (self.tag, 128), (slot, 128), (kf, kbits))
        return v, pad128(kbits + 128 + 128 + 32 + 16)

    @classmethod
    def imported(cls, state, content, k, key_type=0, set_iv=False, policy=0b11, **kw):
        """kl.mgmt completing an import (kl_cfg_management_end)."""
        cl = cls(set_iv, policy, **kw)
        cl.k, cl.key_type = k, key_type
        kbits = 64 if key_type == 1 else k
        kf = sl(content, kbits - 1, 0)
        if key_type == 1:
            cl.skid, cl.key = kf, SKS[kf]
        else:
            cl.key = v2b(kf, k // 8)
        slot = sl(content, kbits + 127, kbits)
        if state == KL_STATE_SET_AUX_VALUE:
            cl.len, cl.input_base = sl(slot, 15, 0), sl(slot, 31, 16)
            cl.block_base, cl.cumul_len = sl(slot, 47, 32), sl(slot, 95, 48)
            cl.J0 = 0
        else:
            cl.J0 = slot
        cl.tag = sl(content, kbits + 255, kbits + 128)
        cl.start_ctr = sl(content, kbits + 287, kbits + 256)
        cl.last_blk_len = sl(content, kbits + 303, kbits + 288)
        cl.state = state
        if not cl.stale_auth_key:
            cl._rederive()                    # AGR4: recomputed when an import completes
        return cl

    # ---------------- derived field, Ready, errors ----------------

    def _rederive(self):
        """`auth_key` is a derived field: auth_key <- enc_blk(key, zeros(128))."""
        self.auth_key = self._enc_blk(0)

    def _enter_ready(self):
        """In State _Ready_: auth_key <- enc_blk(key, zeros(b)), and tag <- zeros(b)."""
        self.auth_key = self._enc_blk(0)
        self.tag = 0

    def _error(self, st, why=""):
        """Transition to an Error State: the Content beyond the MDH is cleared (SGR10)."""
        self.state = st
        self._clear_content()
        self.why = why
        return 0

    def _invalid(self, why=""):
        return self._error(KL_STATE_INVALID, why)

    # ---------------- Machine-specific functions ----------------

    def _enc_blk(self, p):
        return b2v(aes_encrypt(self.key, v2b(p, 16)))

    def _absorb(self, data):
        self.tag = kl_galoismul(self.tag ^ data, self.auth_key)

    def _ctr_of(self, field32):
        """int(bswap(J0[127:96]))."""
        return field32 if self.le_counter else bswap(field32, 4)

    def _field_of(self, ctr):
        """bswap(bin(ctr,32))."""
        return bin_(ctr, 32) if self.le_counter else bswap(bin_(ctr, 32), 4)

    def _next_ctr(self):
        """ctr <- int(bswap(J0[127:96])); ctr <- (ctr + 1) mod 2^32; None when
        ctr = (start_ctr - 1) mod 2^32, i.e. when the CL goes to _Invalid_."""
        ctr = (self._ctr_of(sl(self.J0, 127, 96)) + 1) % 2 ** 32
        return None if ctr == (self.start_ctr - 1) % 2 ** 32 else ctr

    def _set_ctr(self, ctr):
        """J0[127:96] <- bswap(bin(ctr,32))."""
        self.J0 = cat((self._field_of(ctr), 32), (sl(self.J0, 95, 0), 96))

    # ---------------- kl.setst ----------------

    def _setst_table(self):
        t = {
            (KL_STATE_HASH_ABSORB, KL_STATE_HASH_ABSORB): ("A", self._noop),
            (KL_STATE_HASH_ABSORB, KL_STATE_ENCRYPT): ("A", self._to_crypt),
            (KL_STATE_HASH_ABSORB, KL_STATE_DECRYPT): ("A", self._to_crypt),
            (KL_STATE_ENCRYPT, KL_STATE_ENCRYPT): ("A", self._noop),
            (KL_STATE_DECRYPT, KL_STATE_DECRYPT): ("A", self._noop),
        }
        for crypt, last, fin in ((KL_STATE_ENCRYPT, KL_STATE_ENC_LAST_BLOCK,
                                  KL_STATE_ENC_TAG_FINALIZE),
                                 (KL_STATE_DECRYPT, KL_STATE_DEC_LAST_BLOCK,
                                  KL_STATE_DEC_TAG_FINALIZE)):
            t[(crypt, last)] = t[(last, last)] = ("B", self._to_last_block)
            t[(crypt, fin)] = t[(last, fin)] = t[(fin, fin)] = ("C", self._to_tag_finalize)
        t[(KL_STATE_DEC_TAG_FINALIZE, KL_STATE_HASH_VERIFY)] = ("C", self._hash_verify)
        if self.set_iv:
            # "There is no state _Set_Aux_Value_. The transition is from _Ready_ to
            # _Hash_Absorb_", with a Form A kl.setst.
            t[(KL_STATE_READY, KL_STATE_HASH_ABSORB)] = ("A", self._noop)
        else:
            t[(KL_STATE_READY, KL_STATE_SET_AUX_VALUE)] = ("B", self._to_set_aux_value)
            # a transition listed by the Machine may be requested by kl.setst (SGR3);
            # process_VLI performs finalize() before leaving _Current_State_
            t[(KL_STATE_SET_AUX_VALUE, KL_STATE_HASH_ABSORB)] = ("A", self._leave_set_aux_value)
        return t

    def setst(self, immed7, form="A", aux=0):
        """kl.setst <CL>, #immed7 [, aux]: Form A (no input), B (Xs), C (INPUT)."""
        st = self.state
        if st in ERROR_STATES:
            # SGR15: only the Error State may be changed; any other use is a no-op (SGR16)
            if immed7 in ERROR_STATES:
                self.state = immed7 if immed7 < 54 else KL_STATE_INVALID
            return
        if immed7 in ERROR_STATES:
            # <<KLEE-instruction-setst>>: accepted in any State; 54 and 55 give _Invalid_
            self._error(immed7 if immed7 < 54 else KL_STATE_INVALID)
            return
        if immed7 == KL_STATE_READY and form == "A" and st != KL_STATE_UNCONFIGURED:
            if st == KL_STATE_SET_AUX_VALUE:
                self._vli_finalize()          # process_VLI: finalize() before leaving
            self.state = KL_STATE_READY       # SGR6 (from _Success_/_Failure_), SGR8
            self._enter_ready()
            return
        if st in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            self._invalid("SGR5/SGR6: kl.setst not allowed in _Success_/_Failure_")
            return
        if (st, immed7) == (KL_STATE_SET_AUX_VALUE, KL_STATE_SET_AUX_VALUE):
            self._invalid("process_VLI: transitioning to the same State is not allowed")
            return
        entry = self._setst_table().get((st, immed7))
        if entry is None:
            self._invalid(f"AGR1: {STATE_NAME.get(st)} -> {STATE_NAME.get(immed7, immed7)}")
            return
        want, fn = entry
        if form != want:
            self._invalid(f"AGR1: Form {form} where Form {want} is required")
            return
        fn(immed7, aux)

    def _noop(self, immed7, aux):
        self.state = immed7

    def _to_set_aux_value(self, immed7, Xs):
        # "Xs must satisfy 8 <= Xs <= 8192 and be a multiple of 8"
        if not 8 <= Xs <= 8192 or Xs % 8:
            self._invalid("IV length out of range or not a multiple of 8")
            return
        self.len = Xs                                     # len <- Xs
        self.tag = 0                                      # "Upon entering the state, tag is cleared"
        self.input_base = self.block_base = self.cumul_len = 0
        if self.iv_into_J0:
            self.J0 = 0                                   # negative control: J0 <- zeros(b)
        self.state = KL_STATE_SET_AUX_VALUE

    def _leave_set_aux_value(self, immed7, aux):
        self._vli_finalize()                              # finalize() enters _Hash_Absorb_

    def _to_crypt(self, immed7, aux):
        # "_Hash_Absorb_ -> _Encrypt_, if encryption is allowed" (and likewise decryption)
        bit = 1 if immed7 == KL_STATE_ENCRYPT else 2
        if not self.policy & bit:
            self._invalid("AGR1: _MachinePolicy_ does not allow this path")
            return
        self.state = immed7

    def _to_last_block(self, immed7, Xs):
        # "A value of zero, larger than 127, or not a multiple of 8" -> _Invalid_
        if Xs == 0 or Xs > 127 or Xs % 8:
            self._invalid("last_blk_len out of range or not a multiple of 8")
            return
        self.last_blk_len = Xs
        self.state = immed7

    def _to_tag_finalize(self, immed7, INPUT):
        INPUT &= MASK128              # "If KLLEN > 128, only the 128 least significant bits"
        self._absorb(INPUT)
        self.tag ^= self._enc_blk(cat((self._field_of(self.start_ctr), 32),
                                      (sl(self.J0, 95, 0), 96)))
        self.state = immed7

    def _hash_verify(self, immed7, INPUT):
        # Form C: the value to compare against; a single 128-bit value (AGR5)
        self.state = KL_STATE_SUCCESS if INPUT & MASK128 == self.tag else KL_STATE_FAILURE

    # ---------------- _Set_Aux_Value_: process_VLI ----------------

    def _acc(self):
        return "J0" if self.iv_into_J0 else "tag"

    def _vli_process_block(self):
        """if len != 96, process_block() performs tag <- Galoismul(tag, auth_key)."""
        if self.len != 96:
            a = self._acc()
            setattr(self, a, kl_galoismul(getattr(self, a), self.auth_key))

    def _vli_finalize(self):
        a = self._acc()
        acc = getattr(self, a)
        if self.len == 96:
            self.J0 = cat((bswap(bin_(1, 32), 4), 32), (sl(acc, 95, 0), 96))
        else:
            if self.block_base != 0:
                acc = kl_galoismul(acc, self.auth_key)
            acc ^= cat((bswap(bin_(self.len, 64), 8), 64), (0, 64))
            acc = kl_galoismul(acc, self.auth_key)
            self.J0 = acc
        self.start_ctr = self._ctr_of(sl(self.J0, 127, 96))
        self.tag = 0
        self.state = KL_STATE_HASH_ABSORB

    def _exec_set_aux_value(self, INPUT, KLLEN, resume, interrupt_after):
        # granularity = b: every transfer but the last one (the one that reaches len)
        # is a whole multiple of b; otherwise AGR2.
        if KLLEN % B and self.cumul_len + KLLEN < self.len:
            return self._invalid("AGR2: short transfer that is not the last")
        if resume and self.klstart % (B // 8):
            return self._invalid("klstart is not an interruption point")
        acc = self._acc()
        r = process_VLI(self, INPUT, KLLEN, max_len="len", block=acc, b=B,
                        state=acc, n=B, input_base="input_base",
                        block_base="block_base", state_offset=0,
                        cumul_len="cumul_len", process_block=self._vli_process_block,
                        finalize=self._vli_finalize, mode="xor_accumulate",
                        granularity=B, resuming=resume, interrupt_after=interrupt_after)
        if r == "invalid":
            return self._invalid("process_VLI step 1")
        if r == "interrupted":
            self.halted = True
            return None
        self.klstart = 0
        return None

    # ---------------- kl.exec ----------------

    def _exec_table(self):
        return {
            KL_STATE_SET_AUX_VALUE: ("B", self._exec_set_aux_value),
            KL_STATE_HASH_ABSORB: ("B", self._exec_hash_absorb),
            KL_STATE_ENCRYPT: ("A", self._exec_crypt),
            KL_STATE_DECRYPT: ("A", self._exec_crypt),
            KL_STATE_ENC_LAST_BLOCK: ("A", self._exec_last_block),
            KL_STATE_DEC_LAST_BLOCK: ("A", self._exec_last_block),
            KL_STATE_ENC_TAG_FINALIZE: ("C", self._exec_emit_tag),
        }

    def exec(self, form, INPUT=0, KLLEN=128, resume=False, interrupt_after=None):
        """kl.exec: Form A (in, out), B (in), C (out).  Returns OUTPUT (KLLEN bits)
        for Forms A and C.  An instruction that performs no operation, or that
        invalidates the CL, leaves zeros in the part of the window it did not write."""
        self.halted = False
        st = self.state
        if st in ERROR_STATES:
            return 0                  # SGR16: no operation, _State_ unchanged
        if st == KL_STATE_READY:
            return self._invalid("SGR2: kl.exec in _Ready_")
        if st in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            return self._invalid("SGR5: kl.exec in _Success_/_Failure_")
        entry = self._exec_table().get(st)
        if entry is None:
            return self._invalid(f"AGR1: no kl.exec in {STATE_NAME.get(st)}")
        want, fn = entry
        if form != want:
            return self._invalid(f"AGR1: Form {form} in {STATE_NAME.get(st)}")
        return fn(INPUT, KLLEN, resume, interrupt_after)

    def _first_block(self, resume):
        """The block at which a block-iterated kl.exec starts: 0, or klstart/16 on
        resumption (IRR7); None if klstart is not an interruption point."""
        if not resume:
            return 0
        return None if self.klstart % (B // 8) else self.klstart // (B // 8)

    def _exec_hash_absorb(self, INPUT, KLLEN, resume, interrupt_after):
        if KLLEN % B:
            return self._invalid("AGR2: KLLEN not a multiple of b")
        first = self._first_block(resume)
        if first is None:
            return self._invalid("klstart is not an interruption point")
        for i in range(first, KLLEN // B):
            if interrupt_after is not None and i - first == interrupt_after:
                self.klstart, self.halted = i * (B // 8), True
                return None
            self._absorb(sl(INPUT, B * i + B - 1, B * i))     # absorb(INPUT)
        self.klstart = 0
        return None

    def _exec_crypt(self, INPUT, KLLEN, resume, interrupt_after):
        """_Encrypt_ and _Decrypt_, applied to each b-bit block (AGR3)."""
        if KLLEN % B:
            return self._invalid("AGR2: KLLEN not a multiple of b")
        first = self._first_block(resume)
        if first is None:
            return self._invalid("klstart is not an interruption point")
        OUTPUT = 0
        for i in range(first, KLLEN // B):
            if interrupt_after is not None and i - first == interrupt_after:
                self.klstart, self.halted = i * (B // 8), True
                return OUTPUT
            blk = sl(INPUT, B * i + B - 1, B * i)
            ctr = self._next_ctr()
            if ctr is None:
                # IRR6: the completed prefix stays written, the rest is zeroed (SGR16)
                self._invalid("counter reached (start_ctr - 1) mod 2^32")
                return OUTPUT
            if self.state == KL_STATE_ENCRYPT:
                self._set_ctr(ctr)                            # J0[127:96] <- bswap(bin(ctr,32))
                tmp = blk ^ self._enc_blk(self.J0)            # tmp <- INPUT xor enc_blk(key, J0)
                self._absorb(tmp)                             # absorb(tmp)
                OUTPUT |= tmp << (B * i)                      # OUTPUT <- tmp
            else:
                self._absorb(blk)                             # absorb(INPUT)
                self._set_ctr(ctr)
                OUTPUT |= (blk ^ self._enc_blk(self.J0)) << (B * i)
        self.klstart = 0
        return OUTPUT

    def _exec_last_block(self, INPUT, KLLEN, resume, interrupt_after):
        lbl = self.last_blk_len
        if lbl == 0:
            return 0                  # "terminate the instruction": no operation
        if KLLEN < lbl:
            # <<KLEE-truncation-vs-length>>: the only restriction is KLLEN >= last_blk_len
            return self._invalid("AGR2: KLLEN < last_blk_len")
        ctr = self._next_ctr()
        if ctr is None:
            return self._invalid("counter reached (start_ctr - 1) mod 2^32")
        pad = 128 - lbl
        if self.state == KL_STATE_ENC_LAST_BLOCK:
            self._set_ctr(ctr)
            tmp = (cat((0, pad), (sl(INPUT, lbl - 1, 0), lbl))
                   ^ cat((0, pad), (sl(self._enc_blk(self.J0), lbl - 1, 0), lbl)))
            self._absorb(tmp)
            OUTPUT = tmp
        else:
            tmp = cat((0, pad), (sl(INPUT, lbl - 1, 0), lbl))
            self._absorb(tmp)
            self._set_ctr(ctr)
            OUTPUT = tmp ^ cat((0, pad), (sl(self._enc_blk(self.J0), lbl - 1, 0), lbl))
        self.last_blk_len = 0
        return OUTPUT & mask(KLLEN)   # AGR3: one block; AGR6: the rest of OUTPUT is clear

    def _exec_emit_tag(self, INPUT, KLLEN, resume, interrupt_after):
        """Form C: writes the tag to OUTPUT; the state transitions to _Success_."""
        OUTPUT = self.tag & mask(KLLEN)
        self.state = KL_STATE_SUCCESS
        return OUTPUT

    # ---------------- kl.derive destination endpoint j = 1 (`key`) ----------------

    def derive_into_key(self, src: bytes, length: int):
        """<<KLEE-derive-endpoints>>: `key` (1) is importable, filled in State _Ready_."""
        if self.state in ERROR_STATES:
            return                    # SGR19: an Error State endpoint makes it a no-op
        if self.key_type == 1:
            self._invalid("a field configured by a SKID is never importable")
            return
        if self.state != KL_STATE_READY:
            self._invalid("a destination whose key is written must be in _Ready_")
            return
        if length == 0:
            return
        dest = self.k // 8
        eff = min(length, dest)       # Transfer Size Rules
        self.key = src[:eff] + bytes(dest - eff)
        if not self.stale_auth_key:
            self._rederive()          # AGR4: "again whenever a field it depends upon is modified"


# ---------------------------------------------------------------------
# drivers: <<KLEE-pseudocode-GCM-encryption>> / -decryption, on the model
# ---------------------------------------------------------------------

def len_block(pt_bits, ad_bits, swapped=False):
    """INPUT <- bswap(bin(len_in_bits(plaintext), 64)) @ bswap(bin(len_in_bits(AD), 64))."""
    hi, lo = (ad_bits, pt_bits) if swapped else (pt_bits, ad_bits)
    return cat((bswap(bin_(hi, 64), 8), 64), (bswap(bin_(lo, 64), 8), 64))


def feed_iv(cl, iv, chunk=16, interrupt=False):
    """The IV as `granularity = b` transfers: all but the last whole blocks."""
    for i in range(0, len(iv), chunk):
        t = iv[i:i + chunk]
        if interrupt and len(t) >= 32:
            cl.exec("B", b2v(t), 8 * len(t), interrupt_after=1)
            while cl.halted:
                cl.exec("B", b2v(t), 8 * len(t), resume=True)
        else:
            cl.exec("B", b2v(t), 8 * len(t))


def absorb_ad(cl, ad):
    """_Hash_Absorb_: the caller zero-fills the final AD block."""
    if ad:
        p = _pad16(ad)
        cl.exec("B", b2v(p), 8 * len(p))


def run_crypt(cl, text, nblk_per_exec, last_state):
    """Whole blocks through _Encrypt_/_Decrypt_, then a fractional last block."""
    nfull = len(text) // 16
    out = b""
    for i in range(0, nfull * 16, nblk_per_exec * 16):
        blk = text[i:min(i + nblk_per_exec * 16, nfull * 16)]
        out += v2b(cl.exec("A", b2v(blk), 8 * len(blk)), len(blk))
    rest = text[nfull * 16:]
    if rest:
        cl.setst(last_state, "B", 8 * len(rest))
        out += v2b(cl.exec("A", b2v(rest), 8 * len(rest)), len(rest))
    return out


def kl_encrypt(key, iv, ad, pt, iv_chunk=16, pt_chunk=1, interrupt_iv=False,
               swap_len_block=False, cl=None, **kw):
    cl = cl or GcmCL.provisioned(key, **kw)
    cl.setst(KL_STATE_SET_AUX_VALUE, "B", 8 * len(iv))
    feed_iv(cl, iv, iv_chunk, interrupt_iv)
    absorb_ad(cl, ad)
    cl.setst(KL_STATE_ENCRYPT)
    ct = run_crypt(cl, pt, pt_chunk, KL_STATE_ENC_LAST_BLOCK)
    cl.setst(KL_STATE_ENC_TAG_FINALIZE, "C", len_block(8 * len(pt), 8 * len(ad), swap_len_block))
    tag = cl.exec("C", KLLEN=128)
    return ct, v2b(tag, 16), cl


def kl_decrypt(key, iv, ad, ct, tag_bytes, cl=None, **kw):
    cl = cl or GcmCL.provisioned(key, **kw)
    cl.setst(KL_STATE_SET_AUX_VALUE, "B", 8 * len(iv))
    feed_iv(cl, iv)
    absorb_ad(cl, ad)
    cl.setst(KL_STATE_DECRYPT)
    pt = run_crypt(cl, ct, len(ct) // 16 or 1, KL_STATE_DEC_LAST_BLOCK)
    cl.setst(KL_STATE_DEC_TAG_FINALIZE, "C", len_block(8 * len(ct), 8 * len(ad)))
    cl.setst(KL_STATE_HASH_VERIFY, "C", b2v(tag_bytes))
    return pt, STATE_NAME.get(cl.state), cl


def kl_encrypt_setiv(ad, pt, cl):
    """GCM with Set IV on a provisioned CL in _Ready_: J0 came with the PI."""
    cl.setst(KL_STATE_HASH_ABSORB)                  # Form A kl.setst
    absorb_ad(cl, ad)
    cl.setst(KL_STATE_ENCRYPT)
    ct = run_crypt(cl, pt, len(pt) // 16 or 1, KL_STATE_ENC_LAST_BLOCK)
    cl.setst(KL_STATE_ENC_TAG_FINALIZE, "C", len_block(8 * len(pt), 8 * len(ad)))
    return ct, v2b(cl.exec("C", KLLEN=128), 16)


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

# No published vector has a length that is not a whole number of bytes; REF-bits
# (anchored on the vectors above) is the reference for those lengths.


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


def section(title):
    lines.append(f"--- {title} ---")


def fired(fn):
    """Run fn; report whether the CL it returns ended in _Invalid_."""
    cl = fn()
    return cl.state == KL_STATE_INVALID


print(__doc__.strip().splitlines()[0])
print()
print("KAT-EXPECT-FAIL: negative control: length block halves swapped")
print("KAT-EXPECT-FAIL: negative control: little-endian counter increment")
print("KAT-EXPECT-FAIL: negative control: IV accumulated in J0")
print("KAT-EXPECT-FAIL: negative control: auth_key not re-derived")
print()

# ---- 0. primitives -----------------------------------------------------------
section("primitives (common.py self-test, Galoismul definition)")
check("common.py self-test (FIPS 197, RFC 8452, SP 800-38B/D anchors)", selftest())
H1 = b2v(aes_encrypt(bytes.fromhex(K128), bytes(16)))
samples = [(H1, H1), (H1, b2v(bytes.fromhex(AAD[:32]))), (1 << 7, H1),
           (b2v(bytes.fromhex(P64[:32])), b2v(bytes.fromhex(P64[32:64])))]
check("kl_galoismul equals Galoismul as defined in <<KLEE-GCM-mode>> "
      "(coefficient of x^(8i+j) is V[8i+(7-j)])",
      all(kl_galoismul(a, b) == galoismul_def(a, b) for a, b in samples))
check("the value 1 << 7 (byte 0 = 0x80) is the multiplicative identity",
      galoismul_def(1 << 7, H1) == H1)

# ---- 1. REF against the published vectors ----------------------------------
section("REF (SP 800-38D on byte strings) vs published vectors")
for label, k, iv, a, p, c, t in VECTORS:
    K, IV, A, P = (bytes.fromhex(x) for x in (k, iv, a, p))
    C, T = ref_gcm(K, IV, A, P)
    check(f"REF {label}  |IV|={len(IV)}B |A|={len(A)}B |P|={len(P)}B",
          C == bytes.fromhex(c) and T == bytes.fromhex(t))
n_bits = 0
for label, k, iv, a, p, c, t in VECTORS:
    K, IV, A, P = (bytes.fromhex(x) for x in (k, iv, a, p))
    C, T = ref_bits_gcm(K, bits_of(IV), bits_of(A), bits_of(P))
    n_bits += bits_to_bytes(C) == bytes.fromhex(c) and bits_to_bytes(T) == bytes.fromhex(t)
check(f"REF-bits (SP 800-38D on bit strings) reproduces all {len(VECTORS)} vectors",
      n_bits == len(VECTORS))

# ---- 2. KLEE model against the same vectors ---------------------------------
section("KLEE model (spec state machine) vs published vectors")
for label, k, iv, a, p, c, t in VECTORS:
    K, IV, A, P = (bytes.fromhex(x) for x in (k, iv, a, p))
    C, T, cl = kl_encrypt(K, IV, A, P)
    check(f"KLEE encrypt {label} -> _Success_",
          C == bytes.fromhex(c) and T == bytes.fromhex(t) and cl.state == KL_STATE_SUCCESS)
cl = GcmCL.provisioned(None, skid=0x0123456789ABCDEF)
C, T, _ = kl_encrypt(None, bytes.fromhex(IV12), bytes.fromhex(AAD), bytes.fromhex(P60), cl=cl)
check("KLEE encrypt tc4 with the key given by a SKID (KeyType 1, AGR8)",
      (C, T) == ref_gcm(bytes.fromhex(K128), bytes.fromhex(IV12),
                        bytes.fromhex(AAD), bytes.fromhex(P60)))

# ---- 3. _Set_Aux_Value_: process_VLI ----------------------------------------
section("KLEE _Set_Aux_Value_: process_VLI, multi-transfer IV, interruption")
for label, k, iv, a, p, c, t in VECTORS:
    if len(iv) // 2 <= 12:
        continue                        # only the 60-byte IV cases are interesting
    K, IV, A, P = (bytes.fromhex(x) for x in (k, iv, a, p))
    for chunk, intr in ((16, False), (32, False), (32, True), (48, True)):
        C, T, _ = kl_encrypt(K, IV, A, P, iv_chunk=chunk, interrupt_iv=intr)
        check(f"KLEE {label} IV in {chunk}-byte transfers"
              + (", interrupted (klstart <- input_base/8) and resumed" if intr else ""),
              C == bytes.fromhex(c) and T == bytes.fromhex(t))
K, A, P = bytes.fromhex(K128), bytes.fromhex(AAD), bytes.fromhex(P60)
for ivlen in (1, 13, 20, 16, 32, 64, 1024):
    IV = bytes((7 * i + 3) & 0xFF for i in range(ivlen))
    ac, at, _ = kl_encrypt(K, IV, A, P, iv_chunk=16)
    check(f"KLEE {ivlen}-byte IV ({8 * ivlen} bits) matches REF", (ac, at) == ref_gcm(K, IV, A, P))
IV = bytes.fromhex(IV12)
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 96)
check("entering _Set_Aux_Value_ sets len <- Xs, clears tag and the process_VLI counters",
      (cl.len, cl.tag, cl.input_base, cl.block_base, cl.cumul_len) == (96, 0, 0, 0, 0))
cl.exec("B", b2v(IV + bytes(4)), 128)
check("a 128-bit transfer for a 96-bit IV: the excess 32 bits are ignored and "
      "finalize() enters _Hash_Absorb_ with J0 = IV || 0^31 || 1, tag = 0, start_ctr = 1",
      cl.state == KL_STATE_HASH_ABSORB and v2b(cl.J0, 16) == IV + b"\x00\x00\x00\x01"
      and cl.tag == 0 and cl.start_ctr == 1)
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 480)
cl.exec("B", b2v(bytes(range(16))), 128)
check("the IV is absorbed into tag (J0 untouched until finalize())",
      cl.J0 == 0 and cl.tag == kl_galoismul(b2v(bytes(range(16))), cl.auth_key)
      and (cl.block_base, cl.cumul_len) == (0, 128))
for bad_iv in (0, 4, 7, 8193):
    cl = GcmCL.provisioned(K)
    cl.setst(KL_STATE_SET_AUX_VALUE, "B", bad_iv)
    check(f"IV length Xs = {bad_iv} -> _Invalid_", cl.state == KL_STATE_INVALID)
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 480)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 480)
check("process_VLI: kl.setst to _Set_Aux_Value_ while in it -> _Invalid_",
      cl.state == KL_STATE_INVALID)
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 480)
cl.exec("B", b2v(bytes(12)), 96)
check("AGR2: a 96-bit transfer that does not complete a 480-bit IV -> _Invalid_",
      cl.state == KL_STATE_INVALID)
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 480)
cl.klstart = 5
cl.exec("B", b2v(bytes(32)), 256, resume=True)
check("resuming with klstart = 5 (not an interruption point) -> _Invalid_",
      cl.state == KL_STATE_INVALID)
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 96)
cl.exec("A", b2v(IV), 96)
check("AGR1: a Form A kl.exec in _Set_Aux_Value_ -> _Invalid_", cl.state == KL_STATE_INVALID)
# Leaving _Set_Aux_Value_ by kl.setst: process_VLI performs finalize() first.
IV20 = bytes(range(20))
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 160)
cl.exec("B", b2v(IV20[:16]), 128)
cl.setst(KL_STATE_HASH_ABSORB)
H = aes_encrypt(K, bytes(16))
check("kl.setst _Hash_Absorb_ part-way through the IV runs finalize() on what was "
      "absorbed (J0 = GHASH(IV[0..15] || 0^64 || [160]_64)) and enters _Hash_Absorb_",
      cl.state == KL_STATE_HASH_ABSORB
      and v2b(cl.J0, 16) == ghash(H, IV20[:16] + bytes(8) + _be64(160)))
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 480)
cl.exec("B", b2v(bytes.fromhex(IV60)[:16]), 128)
cl.setst(KL_STATE_READY)
C6, T6, _ = kl_encrypt(K, bytes.fromhex(IV60), A, P, cl=cl)
check("SGR8: _Set_Aux_Value_ -> _Ready_ part-way through the IV; the next message "
      "(tc6) is unaffected", (C6.hex(), T6.hex()) == (VECTORS[5][5], VECTORS[5][6]))

# ---- 4. multi-block kl.exec and IRR7 resumption ----------------------------
section("KLEE _Encrypt_: KLLEN spanning several blocks, interrupted and resumed")
IV = bytes.fromhex(IV12)
rc, rt = ref_gcm(K, IV, A, P)
for n in (1, 2, 3):
    ac, at, _ = kl_encrypt(K, IV, A, P, pt_chunk=n)
    check(f"KLEE encrypt with KLLEN = {n} block(s) per kl.exec", (ac, at) == (rc, rt))


def prologue(cl, iv=IV, ad=A):
    """_Ready_ -> _Set_Aux_Value_ -> _Hash_Absorb_, with the AD absorbed."""
    cl.setst(KL_STATE_SET_AUX_VALUE, "B", 8 * len(iv))
    feed_iv(cl, iv)
    absorb_ad(cl, ad)
    return cl


PT3 = P[:48]
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
out1 = cl.exec("A", b2v(PT3), 384, interrupt_after=1)
h1, k1 = cl.halted, cl.klstart
out2 = cl.exec("A", b2v(PT3), 384, resume=True)
joined = v2b(sl(out1, 127, 0) | (out2 & ~MASK128), 48)
check("IRR7: a 3-block _Encrypt_ halted after one block (klstart = 16) and "
      "resumed gives the uninterrupted ciphertext",
      h1 and k1 == 16 and cl.klstart == 0 and joined == rc[:48])
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
cl.klstart = 8
cl.exec("A", b2v(PT3), 384, resume=True)
check("_Encrypt_ resumed at klstart = 8 (not an interruption point) -> _Invalid_",
      cl.state == KL_STATE_INVALID)
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 96)
cl.exec("B", b2v(IV), 96)
cl.exec("B", b2v(A[:16]), 128, interrupt_after=0)
cl.exec("B", b2v(A[:16]), 128, resume=True)
check("klstart = 0 is an interruption point: _Hash_Absorb_ halted before its first "
      "block resumes from it", cl.tag == kl_galoismul(b2v(A[:16]), cl.auth_key)
      and cl.klstart == 0 and not cl.halted)

# ---- 5. decryption and _Hash_Verify_ ---------------------------------------
section("KLEE decrypt path and _Hash_Verify_")
for label, k, iv, a, p, c, t in VECTORS:
    Kx, IVx, Ax = (bytes.fromhex(x) for x in (k, iv, a))
    Cx, Tx, Px = bytes.fromhex(c), bytes.fromhex(t), bytes.fromhex(p)
    pt, verdict, _ = kl_decrypt(Kx, IVx, Ax, Cx, Tx)
    check(f"KLEE decrypt {label} -> plaintext, _Success_", pt == Px and verdict == "Success")
    bad = bytearray(Tx)
    bad[0] ^= 0x80
    _, verdict, _ = kl_decrypt(Kx, IVx, Ax, Cx, bytes(bad))
    check(f"KLEE decrypt {label} with corrupted tag -> _Failure_", verdict == "Failure")
C4, T4 = rc, rt
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_DECRYPT)
run_crypt(cl, C4, 3, KL_STATE_DEC_LAST_BLOCK)
cl.setst(KL_STATE_DEC_TAG_FINALIZE, "C", len_block(8 * len(C4), 8 * len(A)))
leak = cl.exec("C", KLLEN=128)
check("no kl.exec in _Dec_Tag_Finalize_: a Form C kl.exec -> _Invalid_ and "
      "writes zeros, never the recomputed tag",
      cl.state == KL_STATE_INVALID and leak == 0)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_DECRYPT)
run_crypt(cl, C4, 3, KL_STATE_DEC_LAST_BLOCK)
cl.setst(KL_STATE_DEC_TAG_FINALIZE, "C", len_block(8 * len(C4), 8 * len(A)))
cl.setst(KL_STATE_HASH_VERIFY, "C", b2v(T4) | (0xABCD << 128))
check("_Hash_Verify_ compares only the 128 least significant bits of a longer value "
      "(AGR5)", cl.state == KL_STATE_SUCCESS)

# ---- 6. last blocks -----------------------------------------------------------
section("KLEE _Enc_Last_Block_ / _Dec_Last_Block_")
PT_FULL = bytes(range(32))                       # two whole blocks
for nbits in (8, 16, 56, 96, 120):
    pt_val = b2v(bytes(range(16))) & mask(nbits)
    cl = prologue(GcmCL.provisioned(K))
    cl.setst(KL_STATE_ENCRYPT)
    ct_full = cl.exec("A", b2v(PT_FULL), 8 * len(PT_FULL))
    cl.setst(KL_STATE_ENC_LAST_BLOCK, "B", nbits)
    ct_tail = cl.exec("A", pt_val, 128)
    cl.setst(KL_STATE_ENC_TAG_FINALIZE, "C", len_block(8 * len(PT_FULL) + nbits, 8 * len(A)))
    tag_e = cl.exec("C", KLLEN=128)
    dd = prologue(GcmCL.provisioned(K))
    dd.setst(KL_STATE_DECRYPT)
    pt_back = dd.exec("A", ct_full, 8 * len(PT_FULL))
    dd.setst(KL_STATE_DEC_LAST_BLOCK, "B", nbits)
    pt_tail = dd.exec("A", ct_tail, 128)
    dd.setst(KL_STATE_DEC_TAG_FINALIZE, "C", len_block(8 * len(PT_FULL) + nbits, 8 * len(A)))
    dd.setst(KL_STATE_HASH_VERIFY, "C", tag_e)
    check(f"round trip with last_blk_len = {nbits}",
          pt_back == b2v(PT_FULL) and pt_tail == pt_val and dd.state == KL_STATE_SUCCESS)
    check(f"last_blk_len = {nbits}: no OUTPUT bit above bit {nbits - 1} "
          f"(no keystream leak, AGR6)", ct_tail >> nbits == 0)
for immed, name in ((KL_STATE_ENC_LAST_BLOCK, "Enc"), (KL_STATE_DEC_LAST_BLOCK, "Dec")):
    for bad_len in (0, 128, 200, 1, 7, 100, 127):
        cl = prologue(GcmCL.provisioned(K))
        cl.setst(KL_STATE_ENCRYPT if name == "Enc" else KL_STATE_DECRYPT)
        cl.setst(immed, "B", bad_len)
        why = "not a multiple of 8" if bad_len % 8 else "out of range"
        check(f"_{name}_Last_Block_ with last_blk_len = {bad_len} ({why}) -> _Invalid_",
              cl.state == KL_STATE_INVALID)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
cl.setst(KL_STATE_ENC_LAST_BLOCK, "B", 96)
first = cl.exec("A", b2v(P[:12]), 96)
snap = (cl.tag, cl.J0)
again = cl.exec("A", b2v(P[:12]), 96)
check("a second kl.exec in _Enc_Last_Block_ (last_blk_len = 0) performs no "
      "operation and writes zeros", first != 0 and again == 0 and (cl.tag, cl.J0) == snap
      and cl.state == KL_STATE_ENC_LAST_BLOCK)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
cl.setst(KL_STATE_ENC_LAST_BLOCK, "B", 96)
wide = cl.exec("A", b2v(P[:12] + bytes(range(1, 21))), 256)
check("_Enc_Last_Block_ with KLLEN = 256 processes one block, ignores the excess "
      "input and clears OUTPUT above bit 95 (AGR3, AGR6)", wide == first)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
cl.setst(KL_STATE_ENC_LAST_BLOCK, "B", 104)
cl.exec("A", b2v(P[:12]), 96)
check("_Enc_Last_Block_ with KLLEN (96) < last_blk_len (104) -> _Invalid_",
      cl.state == KL_STATE_INVALID)
ac, at, _ = kl_encrypt(K, IV, A, P)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
run_crypt(cl, P, 3, KL_STATE_ENC_LAST_BLOCK)
cl.setst(KL_STATE_ENC_TAG_FINALIZE, "C", len_block(8 * len(P), 8 * len(A)) | (0x5A << 128))
wide_tag = cl.exec("C", KLLEN=256)
check("_Enc_Tag_Finalize_: only the 128 LSBs of a 256-bit INPUT are considered, "
      "and the tag emitted with KLLEN = 256 has OUTPUT[255:128] clear",
      wide_tag == b2v(at) and cl.state == KL_STATE_SUCCESS)

# ---- 6b. SP 800-38D conformance, and the byte-granularity restriction -------
section("SP 800-38D conformance of the admissible (byte-granular) lengths")


def placements(x):
    """The KLEE values an SP 800-38D bit string could be supplied as: its own byte
    serialization (partial byte LEFT-aligned) and the same with the partial byte
    RIGHT-aligned, which is what a truncation to INPUT[len-1:0] keeps."""
    v, n = x
    q, r = divmod(n, 8)
    left = bits_to_bytes(x)
    if r == 0:
        return {"left": left}
    right = bytearray(left)
    right[q] >>= 8 - r
    return {"left": left, "right": bytes(right)}


def unplace(b: bytes, n, how):
    q, r = divmod(n, 8)
    bb = bytearray(b[:-(-n // 8)])
    if r and how == "right":
        bb[q] = (bb[q] << (8 - r)) & 0xFF
    return (int.from_bytes(bytes(bb), "big") >> ((-n) % 8), n)


def klee_bits_message(Pbits, how, ivb=IV):
    """Encrypt the bit string Pbits with the KLEE model; full blocks via _Encrypt_,
    the rest via _Enc_Last_Block_ with last_blk_len = its bit length."""
    cl = prologue(GcmCL.provisioned(K), iv=ivb)
    cl.setst(KL_STATE_ENCRYPT)
    body = placements(Pbits)[how]
    nfull = Pbits[1] // 128
    out = b""
    if nfull:
        out += v2b(cl.exec("A", b2v(body[:16 * nfull]), 128 * nfull), 16 * nfull)
    lbl = Pbits[1] - 128 * nfull
    if lbl:
        cl.setst(KL_STATE_ENC_LAST_BLOCK, "B", lbl)
        tail = body[16 * nfull:]
        out += v2b(cl.exec("A", b2v(tail), 8 * len(tail)), len(tail))
    cl.setst(KL_STATE_ENC_TAG_FINALIZE, "C", len_block(Pbits[1], 8 * len(A)))
    return unplace(out, Pbits[1], how), bits_of(v2b(cl.exec("C", KLLEN=128), 16))


SRC = int.from_bytes(bytes.fromhex(P64), "big")
for nbits in (8, 64, 120, 168):
    Pbits = (SRC >> (512 - nbits), nbits)
    want = ref_bits_gcm(K, bits_of(IV), bits_of(A), Pbits)
    hits = [how for how in placements(Pbits)
            if klee_bits_message(Pbits, how) == want]
    check(f"KLEE vs SP 800-38D, plaintext of {nbits} bits (last_blk_len = "
          f"{nbits % 128 or 128})", hits)
for ivbits in (96, 64, 480):
    IVb = (int.from_bytes(bytes.fromhex(IV60), "big") >> (480 - ivbits), ivbits)
    want = ref_bits_gcm(K, IVb, bits_of(A), bits_of(P))
    hits = []
    for how, ivbytes in placements(IVb).items():
        cl = GcmCL.provisioned(K)
        cl.setst(KL_STATE_SET_AUX_VALUE, "B", ivbits)
        cl.exec("B", b2v(ivbytes), 8 * len(ivbytes))
        absorb_ad(cl, A)
        cl.setst(KL_STATE_ENCRYPT)
        ct = run_crypt(cl, P, 4, KL_STATE_ENC_LAST_BLOCK)
        cl.setst(KL_STATE_ENC_TAG_FINALIZE, "C", len_block(8 * len(P), 8 * len(A)))
        tg = v2b(cl.exec("C", KLLEN=128), 16)
        if (bits_of(ct), bits_of(tg)) == want:
            hits.append(how)
    check(f"KLEE vs SP 800-38D, IV of {ivbits} bits", hits)
# The lengths that SP 800-38D would admit but the Machine does not: a partial
# byte has no defined position in a value (<<KLEE-truncation-vs-length>>), and
# the GHASH length block is the byte count times 8, so both length parameters
# are restricted to multiples of 8, as in <<KLEE-GCM-SIV-mode>> and
# <<KLEE-OCB-mode>>.  Were they not, the keystream and the tag would diverge
# from SP 800-38D whichever end of the final byte the bits were taken from.
for nbits in (60, 100, 127, 263):
    cl = prologue(GcmCL.provisioned(K))
    cl.setst(KL_STATE_ENCRYPT)
    cl.setst(KL_STATE_ENC_LAST_BLOCK, "B", nbits % 128 or 128)
    check(f"plaintext of {nbits} bits: last_blk_len = {nbits % 128 or 128} is not a "
          f"multiple of 8 -> _Invalid_", cl.state == KL_STATE_INVALID)
for ivbits in (100, 60, 8193, 0):
    cl = GcmCL.provisioned(K)
    cl.setst(KL_STATE_SET_AUX_VALUE, "B", ivbits)
    check(f"IV of {ivbits} bits is not an admissible len -> _Invalid_",
          cl.state == KL_STATE_INVALID)

# ---- 7. counter wrap --------------------------------------------------------
section("counter wrap: _Invalid_ exactly when ctr = (start_ctr - 1) mod 2^32")


def fresh(ivbytes, **kw):
    """A CL that has just left _Set_Aux_Value_ with the given IV."""
    c = GcmCL.provisioned(K, **kw)
    c.setst(KL_STATE_SET_AUX_VALUE, "B", 8 * len(ivbytes))
    feed_iv(c, ivbytes)
    return c


def seed(cl, ctr):
    """Seed the running counter field of J0 (avoids 2^32 iterations: the rule under
    test depends only on the counter value, not on how it was reached)."""
    cl.J0 = cat((bswap(bin_(ctr % 2 ** 32, 32), 4), 32), (sl(cl.J0, 95, 0), 96))


def probe(cl, seed_ctr, nblocks, path=KL_STATE_ENCRYPT):
    seed(cl, seed_ctr)
    cl.setst(path)
    for _ in range(nblocks):
        cl.exec("A", 0, 128)
        if cl.state == KL_STATE_INVALID:
            break
    return cl.state


check("96-bit IV gives start_ctr = 1", fresh(IV).start_ctr == 1)
check("the counter admits exactly 2^32 - 2 blocks (first ctr = start_ctr + 1, "
      "last ctr = start_ctr - 2)", ((1 - 2) - (1 + 1)) % 2 ** 32 + 1 == 2 ** 32 - 2)
for ivb, name in ((IV, "96-bit IV, start_ctr = 1"),
                  (bytes.fromhex(IV8), "64-bit IV, GHASH-derived start_ctr")):
    st = fresh(ivb).start_ctr
    limit = (st - 1) % 2 ** 32                 # the forbidden counter value
    for path, pname in ((KL_STATE_ENCRYPT, "_Encrypt_"), (KL_STATE_DECRYPT, "_Decrypt_")):
        check(f"{name}, {pname}: the two blocks before the limit are accepted",
              probe(fresh(ivb), limit - 3, 2, path) == path)
        check(f"{name}, {pname}: the block that would set ctr = (start_ctr-1) mod 2^32 "
              f"-> _Invalid_", probe(fresh(ivb), limit - 3, 3, path) == KL_STATE_INVALID)
    cl = fresh(ivb)
    seed(cl, limit - 1)
    cl.setst(KL_STATE_ENCRYPT)
    cl.setst(KL_STATE_ENC_LAST_BLOCK, "B", 8)
    cl.exec("A", 0x55, 8)
    check(f"{name}: _Enc_Last_Block_ at the limit -> _Invalid_", cl.state == KL_STATE_INVALID)
cl = fresh(IV)
seed(cl, (cl.start_ctr - 1) % 2 ** 32 - 3)
cl.setst(KL_STATE_ENCRYPT)
ref_prefix = fresh(IV)
seed(ref_prefix, (ref_prefix.start_ctr - 1) % 2 ** 32 - 3)
ref_prefix.setst(KL_STATE_ENCRYPT)
want2 = ref_prefix.exec("A", b2v(P[:32]), 256)
got = cl.exec("A", b2v(P[:48] + bytes(16)), 512)
check("IRR6/SGR16: a 4-block kl.exec that hits the limit at its third block keeps "
      "the two completed blocks and zeroes the rest of its window",
      got == want2 and cl.state == KL_STATE_INVALID)
check("SGR10/SGR11: the invalidated CL retains only its MDH (Content cleared)",
      cl.export_content() == (0, 0) and cl.key == b"" and cl.tag == 0 and cl.J0 == 0)

# ---- 8. GCM with Set IV -------------------------------------------------------
section("GCM with Set IV: PI = key || J0, no _Set_Aux_Value_, no budget")
for label, k, iv, a, p, c, t in VECTORS:
    Kx, IVx, Ax, Px = (bytes.fromhex(x) for x in (k, iv, a, p))
    J0 = b2v(ref_j0(Kx, IVx))              # as the provisioning software computes it
    cl = GcmCL.provisioned(Kx, J0=J0)
    Cx, Tx = kl_encrypt_setiv(Ax, Px, cl)
    check(f"Set-IV {label}: same ciphertext/tag as GCM, -> _Success_",
          Cx == bytes.fromhex(c) and Tx == bytes.fromhex(t) and cl.state == KL_STATE_SUCCESS)
J0b = ref_j0(K, IV)
pi, pibits = GcmCL.pi_content(K, J0=b2v(J0b))
check("Set-IV PI Content: key at Pos. ii, J0 at Pos. iii, 256 bits for k = 128 "
      "(no budget field)", pibits == 256 and v2b(pi, 32) == K + J0b)
pi, pibits = GcmCL.pi_content(None, J0=b2v(J0b), skid=0x0123456789ABCDEF)
check("Set-IV PI Content with a SKID: 64 + 128 bits, padded to 256",
      pibits == 256 and sl(pi, 191, 64) == b2v(J0b))
cl = GcmCL.provisioned(K, J0=b2v(ref_j0(K, bytes.fromhex(IV8))))
check("provisioning sets start_ctr <- int(bswap(J0[127:96]))",
      cl.start_ctr == int.from_bytes(ref_j0(K, bytes.fromhex(IV8))[12:], "big"))
cl = GcmCL.provisioned(K, J0=b2v(J0b))
cl.setst(KL_STATE_HASH_ABSORB, "C", 0)
check("Set-IV: the kl.setst to _Hash_Absorb_ must be of Form A (Form C -> _Invalid_)",
      cl.state == KL_STATE_INVALID)
cl = GcmCL.provisioned(K, J0=b2v(J0b))
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 96)
check("Set-IV: there is no _Set_Aux_Value_ (kl.setst naming it -> _Invalid_)",
      cl.state == KL_STATE_INVALID)
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_HASH_ABSORB)
check("GCM (Mode 4): _Ready_ -> _Hash_Absorb_ is not a listed transition -> _Invalid_",
      cl.state == KL_STATE_INVALID)
# No budget: a Set-IV CL keeps processing blocks across many kl.exec.
cl = GcmCL.provisioned(K, J0=b2v(J0b))
cl.setst(KL_STATE_HASH_ABSORB)
cl.setst(KL_STATE_ENCRYPT)
for _ in range(40):
    cl.exec("A", 0, 1024)
check("Set-IV: 320 blocks in 40 kl.exec, no budget and no _Invalid_",
      cl.state == KL_STATE_ENCRYPT and cl._ctr_of(sl(cl.J0, 127, 96)) == 321)
# The prohibition of a transition back to _Ready_ is withdrawn (SGR8 applies).
cl = GcmCL.provisioned(K, J0=b2v(J0b))
C1, T1 = kl_encrypt_setiv(A, P, cl)
cl.setst(KL_STATE_READY)
back = cl.state == KL_STATE_READY and cl.tag == 0
C2, T2 = kl_encrypt_setiv(A, P, cl)
n1 = -(-len(P) // 16)
rc2, rt2 = ref_gcm_j0(K, J0b, A, P, icb=_inc32(J0b, n1 + 1))
check("Set-IV: kl.setst _Ready_ from _Success_ is allowed (SGR6/SGR8) and "
      "clears tag", back and (C1, T1) == ref_gcm(K, IV, A, P))
check("Set-IV: the second message continues the counter (J0 is not re-initialised "
      "in _Ready_; the tag mask is still enc_blk(key, J0 with start_ctr))  [INFO 2]",
      (C2, T2) == (rc2, rt2) and C2 != C1)
states = []
for s_ in (2 ** 32 - 2, 2 ** 32 - 1):
    cl = GcmCL.provisioned(K, J0=b2v(J0b))
    seed(cl, s_)
    cl.setst(KL_STATE_HASH_ABSORB)
    cl.setst(KL_STATE_ENCRYPT)
    cl.exec("A", 0, 128)
    states.append(cl.state)
check("Set-IV: the counter rule still bounds the blocks (start_ctr = 1: ctr = 2^32-1 "
      "is accepted, ctr wrapping to 0 = start_ctr - 1 -> _Invalid_)",
      states == [KL_STATE_ENCRYPT, KL_STATE_INVALID])

# ---- 9. general rules ---------------------------------------------------------
section("general rules: AGR1, AGR2, SGR2, SGR4-SGR8, SGR15, SGR16, _MachinePolicy_")
cl = GcmCL.provisioned(K)
check("SGR2: kl.exec in _Ready_ -> _Invalid_ and zero output",
      cl.exec("A", b2v(P[:16]), 128) == 0 and cl.state == KL_STATE_INVALID)
_, _, cl = kl_encrypt(K, IV, A, P)
cl.exec("A", 0, 128)
check("SGR5: kl.exec in _Success_ -> _Invalid_", cl.state == KL_STATE_INVALID)
_, _, cl = kl_encrypt(K, IV, A, P)
cl.setst(KL_STATE_ENCRYPT)
check("SGR5/SGR6: kl.setst other than _Ready_/Error in _Success_ -> _Invalid_",
      cl.state == KL_STATE_INVALID)
_, _, cl = kl_encrypt(K, IV, A, P)
cl.setst(KL_STATE_READY)
C3, T3, _ = kl_encrypt(K, bytes.fromhex(IV8), A, P, cl=cl)
check("SGR6/SGR8: back to _Ready_ from _Success_, the same CL reproduces tc5",
      (C3.hex(), T3.hex()) == (VECTORS[4][5], VECTORS[4][6]))
_, verdict, cl = kl_decrypt(K, IV, A, C4, bytes(16))
cl.setst(KL_STATE_READY)
pt, verdict2, _ = kl_decrypt(K, IV, A, C4, T4, cl=cl)
check("from _Failure_ back to _Ready_, the same CL decrypts and verifies",
      verdict == "Failure" and verdict2 == "Success" and pt == P)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
cl.exec("A", b2v(P[:16]), 128)
cl.setst(KL_STATE_READY)
C5, T5, _ = kl_encrypt(K, IV, A, P, cl=cl)
check("SGR8: _Encrypt_ -> _Ready_ mid-message; the next message is unaffected",
      (C5, T5) == (rc, rt))
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_HASH_ABSORB)
cl.setst(KL_STATE_ENCRYPT)
cl.setst(KL_STATE_ENCRYPT)
ct = run_crypt(cl, P, 4, KL_STATE_ENC_LAST_BLOCK)
check("SGR4: same-State kl.setst in _Hash_Absorb_ and _Encrypt_ change nothing", ct == rc)
for form, st, name in (("A", KL_STATE_HASH_ABSORB, "Form A kl.exec in _Hash_Absorb_"),
                       ("B", KL_STATE_ENCRYPT, "Form B kl.exec in _Encrypt_"),
                       ("B", KL_STATE_DECRYPT, "Form B kl.exec in _Decrypt_")):
    cl = prologue(GcmCL.provisioned(K))
    if st != KL_STATE_HASH_ABSORB:
        cl.setst(st)
    cl.exec(form, b2v(P[:16]), 128)
    check(f"AGR1: {name} -> _Invalid_", cl.state == KL_STATE_INVALID)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT, "B", 5)
check("AGR1: a Form B kl.setst to _Encrypt_ -> _Invalid_", cl.state == KL_STATE_INVALID)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
cl.setst(KL_STATE_ENC_TAG_FINALIZE, "B", 5)
check("AGR1: a Form B kl.setst to _Enc_Tag_Finalize_ -> _Invalid_", cl.state == KL_STATE_INVALID)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
cl.setst(KL_STATE_HASH_VERIFY, "C", 0)
check("AGR1: _Encrypt_ -> _Hash_Verify_ is not a listed transition -> _Invalid_",
      cl.state == KL_STATE_INVALID)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_DECRYPT)
cl.setst(KL_STATE_ENC_LAST_BLOCK, "B", 8)
check("AGR1: _Decrypt_ -> _Enc_Last_Block_ -> _Invalid_", cl.state == KL_STATE_INVALID)
for st, name in ((KL_STATE_HASH_ABSORB, "_Hash_Absorb_"), (KL_STATE_ENCRYPT, "_Encrypt_"),
                 (KL_STATE_DECRYPT, "_Decrypt_")):
    cl = prologue(GcmCL.provisioned(K))
    if st != KL_STATE_HASH_ABSORB:
        cl.setst(st)
    out = cl.exec("B" if st == KL_STATE_HASH_ABSORB else "A", b2v(P[:15]), 120)
    check(f"AGR2: KLLEN = 120 in {name} -> no operation, zero output, _Invalid_",
          cl.state == KL_STATE_INVALID and not out)
cl = prologue(GcmCL.provisioned(K, policy=0b10))
cl.setst(KL_STATE_ENCRYPT)
check("_MachinePolicy_ = decrypt only: _Hash_Absorb_ -> _Encrypt_ -> _Invalid_",
      cl.state == KL_STATE_INVALID)
cl = GcmCL.provisioned(K, policy=0b10)
pt, verdict, _ = kl_decrypt(K, IV, A, C4, T4, cl=cl)
check("_MachinePolicy_ = decrypt only: the decryption path works", verdict == "Success")
cl = prologue(GcmCL.provisioned(K, policy=0b01))
cl.setst(KL_STATE_DECRYPT)
check("_MachinePolicy_ = encrypt only: _Hash_Absorb_ -> _Decrypt_ -> _Invalid_",
      cl.state == KL_STATE_INVALID)
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
cl.setst(KL_STATE_PRIV_VIOLATION)
st1 = cl.state
out = cl.exec("A", b2v(P[:16]), 128)
cl.setst(KL_STATE_READY)
st2 = cl.state
cl.setst(KL_STATE_INVALID)
check("an Error State immediate is accepted; in an Error State kl.exec and a "
      "kl.setst to _Ready_ do nothing (SGR15, SGR16), and the Error State may change",
      st1 == st2 == KL_STATE_PRIV_VIOLATION and out == 0 and cl.state == KL_STATE_INVALID)

# ---- 10. Serialized Content, export and import ------------------------------
section("Serialized Content: layout, export/import, AGR4")
for k_, kt, blocks in ((128, 0, 4), (192, 0, 4), (256, 0, 5), (128, 1, 3)):
    cl = GcmCL.provisioned(bytes(k_ // 8) if kt == 0 else None,
                           skid=0x0123456789ABCDEF if kt else None)
    _, nb = cl.export_content()
    kb = 64 if kt else k_
    check(f"Content of {'a SKID' if kt else f'k = {k_}'}: {kb} + 128 + 128 + 32 + 16 bits, "
          f"{blocks} blocks of 128", nb == 128 * blocks == pad128(kb + 304))
cl = prologue(GcmCL.provisioned(K))
cl.setst(KL_STATE_ENCRYPT)
cl.exec("A", b2v(P[:16]), 128)
v, nb = cl.export_content()
check("positions: key [127:0], J0 [255:128], tag [383:256], bin(start_ctr,32) "
      "[415:384], last_blk_len [431:416]",
      sl(v, 127, 0) == b2v(K) and sl(v, 255, 128) == cl.J0 and sl(v, 383, 256) == cl.tag
      and sl(v, 415, 384) == cl.start_ctr == 1 and sl(v, 431, 416) == 0 and v >> 432 == 0)
cl2 = GcmCL.imported(KL_STATE_ENCRYPT, v, 128)
ct = v2b(cl2.exec("A", b2v(P[16:48]), 256), 32)
cl2.setst(KL_STATE_ENC_LAST_BLOCK, "B", 96)
ct += v2b(cl2.exec("A", b2v(P[48:]), 96), 12)
cl2.setst(KL_STATE_ENC_TAG_FINALIZE, "C", len_block(8 * len(P), 8 * len(A)))
check("export in _Encrypt_ and import into a fresh CL: auth_key recomputed (AGR4), "
      "the message completes as tc4",
      ct == rc[16:] and v2b(cl2.exec("C", KLLEN=128), 16) == rt)
cl = GcmCL.provisioned(K)
cl.setst(KL_STATE_SET_AUX_VALUE, "B", 480)
cl.exec("B", b2v(bytes.fromhex(IV60)[:32]), 256)
v, nb = cl.export_content()
check("_Set_Aux_Value_ overlay in J0's slot: len [143:128], input_base [159:144], "
      "block_base [175:160], cumul_len [223:176]; the running hash stays in tag  [INFO 3]",
      (sl(v, 143, 128), sl(v, 159, 144), sl(v, 175, 160), sl(v, 223, 176))
      == (480, 256, 0, 256) and sl(v, 383, 256) == cl.tag and nb == 512)
for mid in (16, 32, 48):
    for ctl in (False, True):
        cl = GcmCL.provisioned(K, iv_into_J0=ctl)
        cl.setst(KL_STATE_SET_AUX_VALUE, "B", 480)
        feed_iv(cl, bytes.fromhex(IV60)[:mid])
        v, _ = cl.export_content()
        cl2 = GcmCL.imported(KL_STATE_SET_AUX_VALUE, v, 128, iv_into_J0=ctl)
        feed_iv(cl2, bytes.fromhex(IV60)[mid:])
        absorb_ad(cl2, A)
        cl2.setst(KL_STATE_ENCRYPT)
        ct = run_crypt(cl2, P, 4, KL_STATE_ENC_LAST_BLOCK)
        cl2.setst(KL_STATE_ENC_TAG_FINALIZE, "C", len_block(8 * len(P), 8 * len(A)))
        got = (ct.hex(), v2b(cl2.exec("C", KLLEN=128), 16).hex())
        if ctl:
            expect_fail(f"negative control: IV accumulated in J0  [export after {mid} "
                        f"IV bytes, tc6]", got == (VECTORS[5][5], VECTORS[5][6]))
        else:
            check(f"export in _Set_Aux_Value_ after {mid} of 60 IV bytes, import, "
                  f"resume: tc6 reproduced", got == (VECTORS[5][5], VECTORS[5][6]))

# ---- 11. kl.derive into `key` ------------------------------------------------
section("<<KLEE-derive-endpoints>>: `key` (1) importable, filled in _Ready_")
SRC32 = bytes.fromhex(K256)
for k_, length in ((128, 16), (128, 32), (256, 32)):
    for ctl in (False, True):
        cl = GcmCL.provisioned(bytes(range(k_ // 8)), stale_auth_key=ctl)
        cl.derive_into_key(SRC32, length)
        keyx = SRC32[:k_ // 8]
        C, T, _ = kl_encrypt(None, IV, A, P, cl=cl)
        good = (C, T) == ref_gcm(keyx, IV, A, P) and cl.state == KL_STATE_SUCCESS
        if ctl:
            expect_fail(f"negative control: auth_key not re-derived  [k = {k_}, "
                        f"length = {length}]", good)
        else:
            check(f"k = {k_}: kl.derive of {length} bytes into `key` in _Ready_, "
                  f"auth_key re-derived (AGR4), then a message matches REF", good)
cl = prologue(GcmCL.provisioned(K))
cl.derive_into_key(SRC32, 16)
check("kl.derive into `key` of a CL not in _Ready_ -> destination _Invalid_",
      cl.state == KL_STATE_INVALID)
cl = GcmCL.provisioned(None, skid=0x0123456789ABCDEF)
cl.derive_into_key(SRC32, 16)
check("kl.derive into a `key` configured by a SKID -> destination _Invalid_",
      cl.state == KL_STATE_INVALID)
_, _, cl = kl_encrypt(K, IV, A, P)
cl.derive_into_key(SRC32, 16)
check("a CL in _Success_ may not be a kl.derive destination -> _Invalid_ (SGR5)",
      cl.state == KL_STATE_INVALID)

# ---- 12. negative controls -----------------------------------------------------
section("negative controls (must not reproduce the vectors)")
# A control is only meaningful on a vector where it can change the result:
# swapping the halves of the length block does nothing when |AD| = |PT| (tc1,
# tc13), and the counter convention is invisible when the plaintext is empty
# *and* the tag mask is symmetric under it (again tc1, tc13).  Those vectors are
# skipped rather than silently excusing the control.
n_swap = n_ctr = 0
for label, k, iv, a, p, c, t in VECTORS:
    Kx, IVx, Ax, Px = (bytes.fromhex(x) for x in (k, iv, a, p))
    want = (bytes.fromhex(c), bytes.fromhex(t))
    if len(Ax) != len(Px):
        Cx, Tx, _ = kl_encrypt(Kx, IVx, Ax, Px, swap_len_block=True)
        expect_fail(f"negative control: length block halves swapped  [{label}]",
                    (Cx, Tx) == want)
        n_swap += 1
    if len(Px) > 0:
        Cx, Tx, _ = kl_encrypt(Kx, IVx, Ax, Px, le_counter=True)
        expect_fail(f"negative control: little-endian counter increment  [{label}]",
                    (Cx, Tx) == want)
        n_ctr += 1
check(f"both formula controls are observable on several vectors "
      f"({n_swap} / {n_ctr})", n_swap >= 4 and n_ctr >= 4)

print("\n".join(lines))
print()
print("summary: REF and the KLEE model both reproduce SP 800-38D / McGrew-Viega")
print("         test cases 1-6 and 13-18, for GCM and for GCM with Set IV, and every")
print("         admissible length, all of which are byte-granular.")
print()
print("NOTE on byte granularity: SP 800-38D is defined over bit strings, and the")
print("  Machine's formulas take the LOW bits of the final byte:")
print("  INPUT[last_blk_len-1:0] and enc_blk(key, J0)[last_blk_len-1:0] in")
print("  _Enc_Last_Block_/_Dec_Last_Block_, and INPUT[input_base+amount-1:input_base]")
print("  in process_VLI.  SP 800-38D takes MSB_len(CIPH(CB)) and absorbs C* || 0^u and")
print("  IV || 0^s, i.e. the HIGH bits of that byte (x^(8q)..x^(8q+r-1) are")
print("  V[8q+7]..V[8q+8-r] under Galoismul's representation), and its length block is")
print("  the true bit length, not the byte count times 8 as <<KLEE-truncation-vs-length>>")
print("  prescribes.  No placement of a partial byte therefore reproduces SP 800-38D,")
print("  which is why last_blk_len and Xs are restricted to multiples of 8, as in")
print("  <<KLEE-GCM-SIV-mode>> and <<KLEE-OCB-mode>>; the checks above confirm that")
print("  every other value sends the CL to _Invalid_.")
print()
print("INFO 1: interruption.  The model halts _Set_Aux_Value_ only at step 4.i of")
print("  process_VLI and the block-iterated states between blocks (IRR7); klstart must")
print("  be a multiple of 16 bytes on resumption.  A short transfer is taken to be the")
print("  last one when it reaches len (cumul_len + KLLEN >= len); any other short")
print("  transfer violates the granularity b (AGR2).  AGR10 does not apply: no GCM")
print("  State performs an IRR4 instruction (all carry a vector or KLIOBUF operand).")
print("INFO 2: GCM with Set IV.  The budget field and rule are gone, and the")
print("  prohibition of a transition back to _Ready_ is commented out, so SGR8 applies.")
print("  _Ready_ initialises only auth_key and tag, and start_ctr is set only upon")
print("  provisioning; the model therefore keeps J0's running counter, so a second")
print("  message after _Ready_ continues the keystream (no reuse) under the same tag")
print("  mask enc_blk(key, bswap(bin(start_ctr,32)) @ J0[95:0]).  The specification")
print("  does not say this explicitly.  <<KLEE-derive-endpoints>> lists")
print("  <<KLEE-GCM-mode>> but not <<KLEE-GCM-with-IV-mode>>; no derive is tested for it.")
print("INFO 3: the _Set_Aux_Value_ overlay lists 96 bits for J0's 128-bit slot; the")
print("  model leaves the other 32 bits as the J0_padding named in the Internal State")
print("  paragraph, so the Content length does not depend on _State_")
print("  (<<KLEE-length-rule>>).  A kl.setst naming _Hash_Absorb_ in _Set_Aux_Value_ is")
print("  taken to run finalize() first (process_VLI), on the IV absorbed so far.  A")
print("  transition that _MachinePolicy_ forbids is taken to be not allowed (AGR1).")
print()
print("OBSERVATIONs (editorial; no computed value changes, hence not failures):")
print("  1. The _Set_Aux_Value_ overlay rows are numbered iii.a-iii.d, but Pos. iii is")
print("     `tag`; the text (and the NOTE) says they replace J0, which is Pos. ii.")
print("  2. In that overlay, the second sentence of the `input_base` row (\"Each time")
print("     this value reaches b, the data in block is processed\") describes")
print("     `block_base`, not `input_base`.")
print("  3. The Form C kl.setst INPUT for _Enc_Tag_Finalize_ is typeset with a doubled")
print("     `@` across the line break (`... 64)) @` / `@ bswap(...)`).")
print("  4. \"Procedure _KLEE-process-VLI_\" in the Internal State paragraph names the")
print("     anchor, not the Procedure `process_VLI`.")
print()
print(f"KAT-RESULT: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
