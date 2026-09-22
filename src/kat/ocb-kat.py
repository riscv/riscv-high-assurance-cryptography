#!/usr/bin/env python3
"""OCB3 known-answer test: the KLEE specification text against RFC 7253.

Two independent implementations are checked against the published vectors:

  REF   RFC 7253 written directly on bit and byte strings (big-endian
        semantics), transcribed from sections 4.1-4.3 of the RFC.  The nonce
        is taken as a bit string of any length up to 120 bits (section 4.2).
  KLEE  the Machine of <<KLEE-OCB-mode>> (modules/ROOT/pages/Zkl-ISA-machines.adoc),
        implemented formula-by-formula in the KLEE value model of
        modules/ROOT/pages/Zkl-notation.adoc (byte i of a string lives at bits [8i+7:8i];
        the left operand of @ is more significant; bswap is byte reversal).
        The model is a CL driven by kl.setst / kl.exec Forms and KLLEN, so it
        also applies the General Rules for Machines (<<KLEE-Machines-other-rules>>,
        MGR1-MGR6) and the State rules of Book 1 (<<KLEE-State-field>>: SGR2,
        SGR4-SGR6, SGR8, SGR10, SGR16) where OCB relies on them, and it
        exports and imports the Serialized Content of <<KLEE-OCB-mode>>
        (the plaintext of `Content1`, <<KLEE-SCC>>; the sealing itself is
        covered by scc-kat.py).

Vectors and provenance
  * RFC 7253 Appendix A: the full AEAD_AES_128_OCB_TAGLEN128 sample set
    (K = 000102...0E0F, nonces BBAA9988776655443322110[0-F], 16 cases,
    AD/PT lengths 0..40 bytes including partial blocks), the published
    intermediate values for the last of those vectors (L_*, L_$, L_0, L_1,
    bottom, Ktop, Stretch, Offset_0), the AEAD_AES_128_OCB_TAGLEN96 sample
    (K = 0F0E...0100), and the long iterated test whose 128-bit-tag output
    is 67E944D23256C5E0B6C61FA22FDF1EA2.

Checks performed
  * REF vs RFC, and KLEE vs RFC for all 17 sample ciphertexts, the KLEE model
    being driven two ways: one block per kl.exec with the last blocks passed
    at their exact length, and all full blocks of the AD and of the plaintext
    in one multi-block kl.exec (MGR3) with filler above the nonce and the
    last blocks, which the Machine must ignore (<<KLEE-truncation-vs-length>>).
  * KLEE internal values vs the RFC's published intermediates.
  * KLEE decryption: plaintext recovery + Hash_Verify Success on the good
    tag, Failure on a tampered tag; block-multiple messages exercise the
    last_blk_len = 0 Form D path on both sides.
  * The Serialized Content: the CL is exported and re-imported after every
    instruction of every sample (encryption and decryption), with the derived
    L$ and L[i] recomputed on import (<<KLEE-MGR-recomputed-fields>>); every
    admissible field value fits its row; the sizes are reported.
  * The RFC 7253 iterated test, end-to-end through the KLEE model.
  * State machine: instructions and Forms not allowed in the current State
    (<<KLEE-MGR-not-allowed-instructions>>, <<KLEE-SGR-no-exec-in-ready>>,
    <<KLEE-SGR-success-failure>>), the KLIOBUF substitutions of
    <<KLEE-usage-input-output>>, KLLEN not a multiple of b (MGR2), one block
    whatever KLLEN in the last-block, finalize and verify States (MGR3) with
    OUTPUT cleared above the written bits (MGR6), the tag_len-bit comparison
    of Hash_Verify, the repeated nonce kl.exec, the _MachinePolicy_ gate on
    Encrypt/Decrypt (<<KLEE-Machine-field>>), the index = ones(48) guard in
    every block-consuming State, a return to Ready (SGR8), and Error State
    behaviour (<<KLEE-SGR-clear-cr-content-error-state>>,
    <<KLEE-SGR-usage-cr-error-state>>).
  * <<KLEE-derive-endpoints>>: `key` (j = 1) is the only importable field and
    is written with the CL in State Ready; OCB has no exportable field.
  * Nonces of any bit length 6..120 (review finding m4, fixed in the spec):
    KLEE vs the bit-string REF, which also anchors nonce_be(N, n); the
    padding bits of byte q-1 are ignored; out-of-range N_len is rejected.
  * Negative controls (must NOT match the standard, else the test has no
    discriminating power):
      NC-double     : the L-ladder derived with the little-endian update_mask
                      instead of double() = bswap(update_mask(bswap(S))).
      NC-ktop       : the bswap dropped from Ktop's input,
                      enc_blk(key, Nonce_be[127:6] @ zeros(6)).
      NC-blockorder : a multi-block kl.exec taking its blocks from the most
                      significant position downwards, contrary to MGR3.
      NC-scc-drop   : the Serialized Content without its `hash_A` row.
      NC-padbyte    : the nonce padding bits cleared in byte 0 instead of
                      byte q-1 (the reading this harness used until
                      2026-09-17); it must disagree with the REF.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bswap, bin_, aes_encrypt, aes_decrypt,
                    update_mask, double_ocb, bxor, MASK128)

B = 128                      # block size (spec parameter b)
ONES48 = (1 << 48) - 1

# _State_ values: <<KLEE-states-valid>>, <<KLEE-states-error>>, and the symmetric
# constants of <<KLEE-state-constants-symmetric>>.
S_READY = 1
S_HASH_ABSORB = 2            # kl_state_hash_absorb
S_HASH_LAST = 3              # kl_state_hash_last_block
S_HASH_VERIFY = 5            # kl_state_hash_verify
S_ENCRYPT = 7                # kl_state_encrypt
S_DECRYPT = 8                # kl_state_decrypt
S_ENC_LAST = 9               # kl_state_enc_last_block
S_DEC_LAST = 10              # kl_state_dec_last_block
S_ENC_TAG_FIN = 11           # kl_state_enc_tag_finalize
S_SET_AUX = 13               # kl_state_set_aux_value
S_SUCCESS = 46
S_FAILURE = 47
S_INVALID = 49               # kl_state_invalid

# filler placed above the bits that carry data; the Machine must ignore it
JUNK = int.from_bytes(bytes([0x5A, 0xC3]) * 32, 'little')

def junk_above(nbits, width=B):
    return (JUNK << nbits) & ((1 << width) - 1)


def ntz(n):
    assert n > 0
    return (n & -n).bit_length() - 1


def nonce_be(N, n):
    """<<KLEE-OCB-mode>> `nonce_be(N, n)`: the big-endian view of the n-bit nonce
    bit string held in N.

    RFC 7253 treats the nonce as a bit string whose first bit is the most
    significant, so serialized into bytes the final partial byte (byte q-1) is
    LEFT-ALIGNED: its r = n mod 8 most significant bits are nonce, the rest is
    padding.  With q = ceil(n/8),

        nonce_be(N, n) = bswap(N[8q-1:0], q) >> ((8 - r) mod 8)

    For r = 0 this reduces to bswap(N[n-1:0]).
    """
    q = (n + 7) // 8
    r = n % 8
    return bswap(sl(N, 8 * q - 1, 0), q) >> ((8 - r) % 8)


def nonce_bits(Nbytes, n):
    """The n-bit nonce string carried left-aligned in ceil(n/8) bytes, as an
    integer whose most significant bit is the first bit of the string."""
    return int.from_bytes(Nbytes, 'big') >> ((-n) % 8)

# ====================================================================== REF
# RFC 7253 sections 4.1-4.3, directly on byte strings.  All shifts and
# doublings are over the big-endian integer view of the strings, as the RFC
# specifies ("string of 128 bits", first bit most significant).

def _ref_double(S):
    n = int.from_bytes(S, 'big')
    r = ((n << 1) & MASK128) ^ (0x87 if n >> 127 else 0)
    return r.to_bytes(16, 'big')

def _ref_hash(K, A, Ldict):
    E = lambda x: aes_encrypt(K, x)
    L_star, L = Ldict['*'], Ldict['L']
    Sum, Offset = bytes(16), bytes(16)
    m = len(A) // 16
    for i in range(1, m + 1):
        Offset = bxor(Offset, L[ntz(i)])
        Sum = bxor(Sum, E(bxor(A[(i - 1) * 16:i * 16], Offset)))
    A_star = A[m * 16:]
    if A_star:
        Offset = bxor(Offset, L_star)
        CipherInput = bxor(A_star + b'\x80' + bytes(15 - len(A_star)), Offset)
        Sum = bxor(Sum, E(CipherInput))
    return Sum

def _ref_setup(K, Ldict):
    L_star = aes_encrypt(K, bytes(16))
    L_dollar = _ref_double(L_star)
    L = [_ref_double(L_dollar)]
    def Li(i):
        while len(L) <= i:
            L.append(_ref_double(L[-1]))
        return L[i]
    Ldict['*'], Ldict['$'] = L_star, L_dollar
    Ldict['L'] = type('LL', (), {'__getitem__': staticmethod(lambda i: Li(i))})()

def _ref_initial_offset(K, N_int, n, taglen_bits):
    # Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
    Nonce = (((taglen_bits % 128) << 121) | (1 << n) | N_int).to_bytes(16, 'big')
    bottom = Nonce[15] & 0x3F
    Ktop = aes_encrypt(K, Nonce[:15] + bytes([Nonce[15] & 0xC0]))
    Stretch = Ktop + bxor(Ktop[:8], Ktop[1:9])
    S = int.from_bytes(Stretch, 'big')          # 192 bits, bit 1 = msb
    return ((S >> (64 - bottom)) & MASK128).to_bytes(16, 'big')

def ref_ocb_encrypt(K, N, A, P, taglen_bits, n_len=None):
    """N is a byte string; with n_len given, it carries an n_len-bit nonce
    left-aligned in its bytes."""
    n = 8 * len(N) if n_len is None else n_len
    E = lambda x: aes_encrypt(K, x)
    Ld = {}
    _ref_setup(K, Ld)
    Offset = _ref_initial_offset(K, nonce_bits(N, n), n, taglen_bits)
    Checksum, C = bytes(16), b''
    m = len(P) // 16
    for i in range(1, m + 1):
        Offset = bxor(Offset, Ld['L'][ntz(i)])
        Pi = P[(i - 1) * 16:i * 16]
        C += bxor(Offset, E(bxor(Pi, Offset)))
        Checksum = bxor(Checksum, Pi)
    P_star = P[m * 16:]
    if P_star:
        Offset = bxor(Offset, Ld['*'])
        Pad = E(Offset)
        C += bxor(P_star, Pad[:len(P_star)])
        Checksum = bxor(Checksum, P_star + b'\x80' + bytes(15 - len(P_star)))
    Tag = bxor(E(bxor(bxor(Checksum, Offset), Ld['$'])), _ref_hash(K, A, Ld))
    return C + Tag[:taglen_bits // 8]

# ====================================================================== KLEE
# The Machine of <<KLEE-OCB-mode>>, transcribed step by step.  Every formula is
# the spec's own, evaluated on KLEE values.  `double_fn`, `ktop_bswap`,
# `msb_first` and `pad_byte0` parameterize the negative controls; the defaults
# are the specified behaviour.

class Invalid(Exception):
    """The CL transitioned to Error State _Invalid_.  `output` is the OUTPUT
    operand as the instruction leaves it: the blocks written before the
    transition, zeros elsewhere (<<KLEE-SGR-usage-cr-error-state>>)."""
    def __init__(self, why, output=0):
        super().__init__(why)
        self.output = output


SKS = {}                     # System Key Store: SKID -> key bytes (MGR8)


def ocb_layout(key_bits):
    """<<KLEE-OCB-mode>> Serialized Content, rows i-xi: (field, size in bits).
    The MDH is not part of it; it is implicitly zero-padded to a multiple of
    128 bits (Book 2, "Definition of a Machine in KLEE")."""
    return [('key', key_bits),         # i     `key` or System Key Identifier
            ('N', 120),                # ii
            ('N_len', 7),              # iii
            ('pad', 1),                # iv    Padding
            ('Lstar', 128),            # v     L*; L$ and L[i] re-derived on import
            ('offset', 128),           # vi
            ('hash_A', 128),           # vii
            ('checksum_P', 128),       # viii
            ('index', 48),             # ix
            ('tag_len', 2),            # x     tag_len/32 - 2
            ('last_blk_len', 7)]       # xi


def pack(fields):
    """Fields in table order from bit 0 upwards (the lowest address first,
    <<KLEE-Notation>>), then zero padding to a multiple of 128 bits."""
    v = pos = 0
    for val, w in fields:
        if not 0 <= val < (1 << w):
            raise OverflowError(f'{val} does not fit in {w} bits')
        v |= val << pos
        pos += w
    return v2b(v, -(-pos // B) * 16)


def unpack(data, layout):
    v, pos, out = b2v(data), 0, {}
    for f, w in layout:
        out[f] = sl(v, pos + w - 1, pos)
        pos += w
    assert v >> pos == 0 and len(data) * 8 == -(-pos // B) * B
    return out


class KleeOcb:
    """A CL holding an OCB CC.  kl.setst and kl.exec are issued through
    setst(immed, form, aux) and exec(form, INPUT, klen), with KLLEN = klen
    bits; exec returns OUTPUT as a klen-bit value (0 for Forms B and D)."""

    def __init__(self, key, policy=0b11, skid=None, double_fn=double_ocb,
                 ktop_bswap=True, msb_first=False, pad_byte0=False):
        self.keyb = key                   # `key`, k bits
        self.skid = skid                  # System Key Identifier, if any
        if skid is not None:
            SKS[skid] = key
        self.policy = policy              # _MachinePolicy_: [0] encrypt, [1] decrypt
        self.model = dict(double_fn=double_fn, ktop_bswap=ktop_bswap,
                          msb_first=msb_first, pad_byte0=pad_byte0)
        self.double = double_fn           # NC-double
        self.ktop_bswap = ktop_bswap      # NC-ktop
        self.msb_first = msb_first        # NC-blockorder
        self.pad_byte0 = pad_byte0        # NC-padbyte
        # fields no instruction has assigned yet read (and serialize) as zero
        self.Lstar = self.offset = self.last_blk_len = 0
        self.tag_len = None
        self.L, self.Ldollar = [], 0
        self.last_ad_done = False         # not in the spec's state: see SPEC-NOTE
        self.state = S_READY              # the kl.mgmt completing provisioning
        self._ready()

    # -- primitives and Machine-Specific Functions ----------------------
    def enc(self, v):
        return b2v(aes_encrypt(self.keyb, v2b(v, 16)))

    def dec(self, v):
        return b2v(aes_decrypt(self.keyb, v2b(v, 16)))

    @staticmethod
    def ocb_pad(X, n):
        # ocb_pad(X, n) = zeros(120-n) @ 0b10000000 @ X[n-1:0]
        assert n % 8 == 0 and 0 <= n <= 120
        if n == 0:                                # zeros(120) @ 0b10000000
            return cat((0, 120), (0x80, 8))
        return cat((0, 120 - n), (0x80, 8), (sl(X, n - 1, 0), n))

    def _ladder(self):
        # L$ <- double(L*); L[0] <- double(L$); L[i] <- double(L[i-1]) lazily
        self.Ldollar = self.double(self.Lstar)
        self.L = [self.double(self.Ldollar)]

    def _Li(self, i):
        assert 0 <= i < 48                        # 0 < i < 48, plus L[0]
        while len(self.L) <= i:
            self.L.append(self.double(self.L[-1]))
        return self.L[i]

    # -- State handling ----------------------------------------------------
    def _ready(self):                             # In State _Ready_
        self.N = 0                                # N <- zeros(120)
        self.N_len = 0
        self.hash_A = 0                           # zeros(128)
        self.checksum_P = 0                       # zeros(128)
        self.index = 0

    def _invalid(self, why, output=0):
        # <<KLEE-SGR-clear-cr-content-error-state>>: Content beyond the MDH cleared
        self.state = S_INVALID
        self.keyb, self.skid = None, None
        self.N = self.N_len = self.hash_A = self.checksum_P = self.index = 0
        self.Lstar = self.offset = self.last_blk_len = 0
        self.tag_len, self.L = None, []
        raise Invalid(why, output)

    def setst(self, immed, form='A', aux=None):
        """kl.setst Kd, #immed; Form B carries Xs in aux, Form C an INPUT."""
        s = self.state
        if s == S_INVALID:                        # <<KLEE-SGR-usage-cr-error-state>>
            return
        if immed == S_READY:                      # SGR8
            self.state = S_READY
            self._ready()
            return
        if s in (S_SUCCESS, S_FAILURE):           # <<KLEE-SGR-setst-in-success-failure>>
            self._invalid(f'kl.setst #{immed} in State {s}')
        if immed == S_HASH_VERIFY and form == 'A':
            form = 'C'                            # KLIOBUF substitution (Book 1)
        last = {S_HASH_LAST: S_HASH_ABSORB, S_ENC_LAST: S_ENCRYPT,
                S_DEC_LAST: S_DECRYPT}
        # Allowed State Transitions; SGR4 admits the immediate of the current State
        if immed == S_SET_AUX and form == 'B' and s in (S_READY, S_SET_AUX):
            # Xs sets N_len; 6 <= N_len <= 120, else Error State _Invalid_
            if not 6 <= aux <= 120:
                self._invalid('N_len out of range')
            self.N_len = aux
        elif immed == S_HASH_ABSORB and form == 'B' and s in (S_SET_AUX, S_HASH_ABSORB):
            if aux not in (64, 96, 128):
                self._invalid('tag_len not in {64, 96, 128}')
            self.index = 1                        # index <- 1
            self.tag_len = aux                    # tag_len <- Xs
            self.offset = 0                       # offset <- zeros(b)   (Offset_0)
            self.Lstar = self.enc(0)              # L* <- enc_blk(key, zeros(b))
            self._ladder()
        elif immed in last and form == 'B' and s in (last[immed], immed):
            # last_blk_len: a multiple of 8, at most 120 (Internal State)
            if aux % 8 or aux > 120:
                self._invalid('last_blk_len not a multiple of 8 <= 120')
            self.last_blk_len = aux
            if immed == S_HASH_LAST:
                self.last_ad_done = False
        elif (immed in (S_ENCRYPT, S_DECRYPT) and form == 'A'
              and s in (S_HASH_LAST, immed)
              and self.policy & (1 if immed == S_ENCRYPT else 2)):
            self._setup()
        elif immed == S_HASH_VERIFY and form == 'C' and s == S_HASH_VERIFY:
            # compare the tag_len least significant bits of INPUT and checksum_P
            t = self.tag_len
            match = sl(aux, t - 1, 0) == sl(self.checksum_P, t - 1, 0)
            self.state = S_SUCCESS if match else S_FAILURE
            return
        elif immed == S_ENC_TAG_FIN and form == 'A' and s == S_ENC_TAG_FIN:
            pass                                  # SGR4, nothing to perform
        else:
            self._invalid(f'kl.setst Form {form} #{immed} not allowed in State {s}')
        self.state = immed

    def _setup(self):
        # Upon entering _Encrypt_ or _Decrypt_ ("setup" and "init" of RFC 7253);
        # step 1: offset, L*, L$ as defined on entering _Hash_Absorb_.
        n = self.N_len
        self.Nonce_be = cat((bin_(self.tag_len % 128, 7), 7),
                            (0, 120 - n),
                            (1, 1),
                            (nonce_be(self.N, n), n))
        self.bottom = sl(self.Nonce_be, 5, 0)     # int(Nonce_be[5:0])
        ktop_in = cat((sl(self.Nonce_be, 127, 6), 122), (0, 6))
        if self.ktop_bswap:                       # bswap(Nonce_be[127:6] @ zeros(6))
            ktop_in = bswap(ktop_in, 16)
        self.Ktop = self.enc(ktop_in)
        Ktop_be = bswap(self.Ktop, 16)
        self.Stretch_be = cat((Ktop_be, 128),
                              (sl(Ktop_be, 127, 64) ^ sl(Ktop_be, 119, 56), 64))
        self.index = 1
        self.offset = bswap(sl(self.Stretch_be, 191 - self.bottom,
                               64 - self.bottom), 16)

    def exec(self, form, INPUT=0, klen=B):
        """kl.exec in Form A-D with KLLEN = klen."""
        s = self.state
        if s == S_INVALID:                        # no operation, OUTPUT zeroed
            return 0
        if s in (S_SET_AUX, S_HASH_ABSORB):
            want = 'B'
        elif s == S_HASH_LAST:                    # a single one, if last_blk_len != 0
            want = 'B' if self.last_blk_len and not self.last_ad_done else None
        elif s in (S_ENCRYPT, S_DECRYPT):
            want = 'A'
        elif s in (S_ENC_LAST, S_DEC_LAST):
            want = 'A' if self.last_blk_len else 'D'
        elif s == S_ENC_TAG_FIN:
            want = 'C'
        else:                                     # Ready (SGR2), Hash_Verify, Success,
            want = None                           # Failure (SGR5): no kl.exec at all
        # a Form D kl.exec substitutes Form A, B or C (<<KLEE-usage-input-output>>)
        if want is None or form not in (want, 'D'):
            self._invalid(f'kl.exec Form {form} not allowed in State {s}')
        if s == S_SET_AUX:
            self._set_nonce(INPUT, klen)
            return 0
        if s in (S_HASH_ABSORB, S_ENCRYPT, S_DECRYPT):
            return self._blocks(s, INPUT, klen)
        n = self.last_blk_len
        if s != S_ENC_TAG_FIN and klen < n:       # KLLEN >= last_blk_len
            self._invalid('KLLEN < last_blk_len')
        if s == S_HASH_LAST:
            self._hash_last(INPUT)
            self.last_ad_done = True
            return 0
        if s == S_ENC_TAG_FIN:
            # OUTPUT <- zeros(b - tag_len) @ checksum_P[tag_len-1:0]
            t = self.tag_len
            out = cat((0, B - t), (sl(self.checksum_P, t - 1, 0), t))
            self.state = S_SUCCESS
            return out & ((1 << klen) - 1)        # MGR6: bits beyond b are zero
        # _Enc_Last_Block_ / _Dec_Last_Block_: exactly one block (MGR3)
        if n == 0:                                # Form D
            self.checksum_P = self.enc(self.checksum_P ^ self.offset
                                       ^ self.Ldollar) ^ self.hash_A
            out = 0
        else:
            if self.index == ONES48:
                self._invalid('index = ones(48)')
            self.offset ^= self.Lstar
            tmp = sl(self.enc(self.offset), n - 1, 0)          # PAD in RFC 7253
            out = cat((0, 128 - n), (sl(INPUT, n - 1, 0) ^ tmp, n))
            plain = INPUT if s == S_ENC_LAST else out
            tmp = self.offset ^ self.ocb_pad(plain, n)
            self.checksum_P = self.enc(self.checksum_P ^ tmp
                                       ^ self.Ldollar) ^ self.hash_A   # tag
        self.state = S_ENC_TAG_FIN if s == S_ENC_LAST else S_HASH_VERIFY
        return out & ((1 << klen) - 1)            # MGR6: bits beyond b are zero

    def _set_nonce(self, INPUT, klen):
        # N <- zeros(120 - 8q) @ INPUT[8q-1:0], q = ceil(N_len/8), with the
        # (8 - N_len) mod 8 least significant bits of byte q-1 cleared.
        q = (self.N_len + 7) // 8
        pad = (-self.N_len) % 8
        assert klen >= 8 * q
        at = 0 if self.pad_byte0 else 8 * q - 8   # NC-padbyte clears byte 0
        img = sl(INPUT, 8 * q - 1, 0) & ~(((1 << pad) - 1) << at)
        self.N = cat((0, 120 - 8 * q), (img, 8 * q))

    def _blocks(self, s, INPUT, klen):
        if klen % B:                              # MGR2: no operation, Invalid
            self._invalid('KLLEN not a multiple of b')
        out = 0
        order = range(0, klen, B)                 # MGR3: i = 0, b, ..., KLLEN - b
        for i in (reversed(order) if self.msb_first else order):
            blk = sl(INPUT, i + B - 1, i)
            if self.index == ONES48:
                self._invalid('index = ones(48)', output=out)
            self.offset ^= self._Li(ntz(self.index))
            if s == S_HASH_ABSORB:
                self.hash_A ^= self.enc(blk ^ self.offset)
            elif s == S_ENCRYPT:
                self.checksum_P ^= blk
                out |= (self.offset ^ self.enc(blk ^ self.offset)) << i
            else:
                tmp = self.offset ^ self.dec(blk ^ self.offset)
                self.checksum_P ^= tmp
                out |= tmp << i
            self.index += 1
        return out

    def _hash_last(self, INPUT):
        if self.index == ONES48:
            self._invalid('index = ones(48)')
        n = self.last_blk_len
        if n != 0:
            self.offset ^= self.Lstar
            tmp = self.ocb_pad(INPUT, n) ^ self.offset
            self.hash_A ^= self.enc(tmp)

    # -- <<KLEE-derive-endpoints>> -----------------------------------------
    def derive_into(self, j, src, length):
        """This CL as the destination of a kl.derive (<<KLEE-instruction-derive>>)."""
        if self.state == S_INVALID:
            return
        if j != 1:
            self._invalid(f'j = {j} is not an importable field of OCB')
        if self.skid is not None:
            self._invalid('a field configured by a SKID is never importable')
        if self.state != S_READY:
            self._invalid('a destination whose key is written must be in Ready')
        k = len(self.keyb)                        # dest_length, bytes
        eff = min(length, k)                      # <<KLEE-derive-rule-both-fixed-size>>
        self.keyb = src[:eff] + bytes(k - eff)

    def derive_from(self, i):
        """This CL as the source of a kl.derive: OCB has no exportable field."""
        self._invalid(f'i = {i} is not an exportable field of OCB')

    # -- Serialized Content --------------------------------------------------
    def key_bits(self):
        return 64 if self.skid is not None else 8 * len(self.keyb)

    def export(self, layout=None):
        layout = layout or ocb_layout(self.key_bits())
        vals = {'key': self.skid if self.skid is not None else b2v(self.keyb),
                'N': self.N, 'N_len': self.N_len, 'pad': 0,
                'Lstar': self.Lstar, 'offset': self.offset,
                'hash_A': self.hash_A, 'checksum_P': self.checksum_P,
                'index': self.index,
                'tag_len': 0 if self.tag_len is None else self.tag_len // 32 - 2,
                'last_blk_len': self.last_blk_len}
        return pack([(vals[f], w) for f, w in layout])

    def imported(self, content1, layout=None):
        """A fresh CL of the same implementation, loaded with `content1` and the
        MDH of this CL (_State_, _MachinePolicy_, _KeyType_)."""
        layout = layout or ocb_layout(self.key_bits())
        f = unpack(content1, layout)
        key = SKS[f['key']] if self.skid is not None else v2b(f['key'], len(self.keyb))
        new = KleeOcb(key, self.policy, self.skid, **self.model)
        new.state = self.state
        new.N, new.N_len = f['N'], f['N_len']
        new.Lstar, new.offset = f['Lstar'], f['offset']
        new.hash_A, new.checksum_P = f.get('hash_A', 0), f['checksum_P']
        new.index, new.last_blk_len = f['index'], f['last_blk_len']
        new.tag_len = 32 * (f['tag_len'] + 2)
        new._ladder()                             # derived fields recomputed (MGR4)
        new.last_ad_done = False                  # nothing records it: SPEC-NOTE
        return new


def _chunks(data, per_exec):
    """The full blocks of `data` as kl.exec operands of per_exec blocks each
    (0: all of them in one kl.exec); a list of (INPUT, KLLEN)."""
    n = len(data) // 16
    step = per_exec or max(n, 1)
    return [(b2v(data[16 * a:16 * min(n, a + step)]), 8 * 16 * (min(n, a + step) - a))
            for a in range(0, n, step)]


def _tail(tail, junk):
    """A last-block operand: exactly the tail (KLLEN = its bit length), or a
    128-bit operand with filler above the tail."""
    n = 8 * len(tail)
    return (b2v(tail) | junk_above(n), B) if junk else (b2v(tail), n)


def _forms(subst):
    # expected Forms, or their KLIOBUF substitutions (<<KLEE-usage-input-output>>)
    return ('D', 'D', 'D', 'A') if subst else ('A', 'B', 'C', 'C')


def kl_ocb_encrypt(K, N, A, P, taglen_bits, n_len=None, per_exec=1, junk=False,
                   hop=False, layout=None, subst=False, machine_out=None,
                   skid=None, cl=None, tag_out=None, **model):
    """Drive the Machine as <<KLEE-pseudocode-OCB-encryption>> does; return
    C || truncated tag.  N is a byte string; with n_len given, it carries an
    n_len-bit nonce left-aligned in its bytes.  hop: export and re-import
    the CL after every instruction.  cl: an existing CL to use instead of a
    new one, in State Ready, or in Set_Aux_Value with its nonce set if N is
    None; tag_out: receives the 128-bit OUTPUT of the tag."""
    fA, fB, fC, _ = _forms(subst)
    cl = cl or KleeOcb(K, skid=skid, **model)
    nxt = (lambda c: c.imported(c.export(layout), layout)) if hop else (lambda c: c)
    if N is not None:
        cl.setst(S_SET_AUX, 'B', 8 * len(N) if n_len is None else n_len); cl = nxt(cl)
        cl.exec(fB, b2v(N) | (junk_above(8 * len(N)) if junk else 0)); cl = nxt(cl)
    cl.setst(S_HASH_ABSORB, 'B', taglen_bits); cl = nxt(cl)
    for INPUT, klen in _chunks(A, per_exec):
        cl.exec(fB, INPUT, klen); cl = nxt(cl)
    rest = A[len(A) // 16 * 16:]
    cl.setst(S_HASH_LAST, 'B', 8 * len(rest)); cl = nxt(cl)     # can be zero
    if rest:
        cl.exec(fB, *_tail(rest, junk)); cl = nxt(cl)
    cl.setst(S_ENCRYPT, 'A')
    if machine_out is not None:
        machine_out.append({
            'L_*': v2b(cl.Lstar, 16).hex().upper(),
            'L_$': v2b(cl.Ldollar, 16).hex().upper(),
            'L_0': v2b(cl.L[0], 16).hex().upper(),
            'L_1': v2b(cl._Li(1), 16).hex().upper(),
            'bottom': cl.bottom,
            'Ktop': v2b(cl.Ktop, 16).hex().upper(),
            'Stretch': cl.Stretch_be.to_bytes(24, 'big').hex().upper(),
            'Offset_0': v2b(cl.offset, 16).hex().upper(),
        })
    cl = nxt(cl)
    C = b''
    for INPUT, klen in _chunks(P, per_exec):
        C += v2b(cl.exec(fA, INPUT, klen), klen // 8); cl = nxt(cl)
    rest = P[len(P) // 16 * 16:]
    cl.setst(S_ENC_LAST, 'B', 8 * len(rest)); cl = nxt(cl)
    if rest:
        INPUT, klen = _tail(rest, junk)
        C += v2b(cl.exec(fA, INPUT, klen), klen // 8)[:len(rest)]
    else:
        cl.exec('D')                              # Form D: finalize the tag only
    cl = nxt(cl)
    tag = cl.exec(fC)                             # _Enc_Tag_Finalize_
    assert cl.state == S_SUCCESS
    if tag_out is not None:
        tag_out.append(tag)
    return C + v2b(tag, 16)[:taglen_bits // 8]


def kl_ocb_decrypt(K, N, A, CT, taglen_bits, n_len=None, per_exec=1, junk=False,
                   hop=False, layout=None, subst=False, **model):
    """Return (recovered plaintext, Hash_Verify Success?)."""
    fA, fB, _, sC = _forms(subst)
    tlb = taglen_bits // 8
    C, tag = CT[:-tlb], CT[-tlb:]
    cl = KleeOcb(K, **model)
    nxt = (lambda c: c.imported(c.export(layout), layout)) if hop else (lambda c: c)
    cl.setst(S_SET_AUX, 'B', 8 * len(N) if n_len is None else n_len); cl = nxt(cl)
    cl.exec(fB, b2v(N) | (junk_above(8 * len(N)) if junk else 0)); cl = nxt(cl)
    cl.setst(S_HASH_ABSORB, 'B', taglen_bits); cl = nxt(cl)
    for INPUT, klen in _chunks(A, per_exec):
        cl.exec(fB, INPUT, klen); cl = nxt(cl)
    rest = A[len(A) // 16 * 16:]
    cl.setst(S_HASH_LAST, 'B', 8 * len(rest)); cl = nxt(cl)
    if rest:
        cl.exec(fB, *_tail(rest, junk)); cl = nxt(cl)
    cl.setst(S_DECRYPT, 'A'); cl = nxt(cl)
    P = b''
    for INPUT, klen in _chunks(C, per_exec):
        P += v2b(cl.exec(fA, INPUT, klen), klen // 8); cl = nxt(cl)
    rest = C[len(C) // 16 * 16:]
    cl.setst(S_DEC_LAST, 'B', 8 * len(rest)); cl = nxt(cl)
    if rest:
        INPUT, klen = _tail(rest, junk)
        P += v2b(cl.exec(fA, INPUT, klen), klen // 8)[:len(rest)]
    else:
        cl.exec('D')                              # Form D, same formula on decrypt
    cl = nxt(cl)
    assert cl.state == S_HASH_VERIFY
    t = b2v(tag) | (junk_above(8 * tlb) if junk else 0)
    cl.setst(S_HASH_VERIFY, sC, t)                # Form C kl.setst comparison
    return P, cl.state == S_SUCCESS

# ================================================================== vectors
# RFC 7253 Appendix A, AEAD_AES_128_OCB_TAGLEN128.
K128 = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
S40 = bytes.fromhex("000102030405060708090A0B0C0D0E0F"
                    "101112131415161718191A1B1C1D1E1F"
                    "2021222324252627")
VEC128 = [  # (nonce_suffix, len(A), len(P), C||T hex)
    (0x0, 0, 0, "785407BFFFC8AD9EDCC5520AC9111EE6"),
    (0x1, 8, 8, "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009"),
    (0x2, 8, 0, "81017F8203F081277152FADE694A0A00"),
    (0x3, 0, 8, "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9"),
    (0x4, 16, 16, "571D535B60B277188BE5147170A9A22C"
                  "3AD7A4FF3835B8C5701C1CCEC8FC3358"),
    (0x5, 16, 0, "8CF761B6902EF764462AD86498CA6B97"),
    (0x6, 0, 16, "5CE88EC2E0692706A915C00AEB8B2396"
                 "F40E1C743F52436BDF06D8FA1ECA343D"),
    (0x7, 24, 24, "1CA2207308C87C010756104D8840CE19"
                  "52F09673A448A122C92C62241051F573"
                  "56D7F3C90BB0E07F"),
    (0x8, 24, 0, "6DC225A071FC1B9F7C69F93B0F1E10DE"),
    (0x9, 0, 24, "221BD0DE7FA6FE993ECCD769460A0AF2"
                 "D6CDED0C395B1C3CE725F32494B9F914"
                 "D85C0B1EB38357FF"),
    (0xA, 32, 32, "BD6F6C496201C69296C11EFD138A467A"
                  "BD3C707924B964DEAFFC40319AF5A485"
                  "40FBBA186C5553C68AD9F592A79A4240"),
    (0xB, 32, 0, "FE80690BEE8A485D11F32965BC9D2A32"),
    (0xC, 0, 32, "2942BFC773BDA23CABC6ACFD9BFD5835"
                 "BD300F0973792EF46040C53F1432BCDF"
                 "B5E1DDE3BC18A5F840B52E653444D5DF"),
    (0xD, 40, 40, "D5CA91748410C1751FF8A2F618255B68"
                  "A0A12E093FF454606E59F9C1D0DDC54B"
                  "65E8628E568BAD7AED07BA06A4A69483"
                  "A7035490C5769E60"),
    (0xE, 40, 0, "C5CD9D1850C141E358649994EE701B68"),
    (0xF, 0, 40, "4412923493C57D5DE0D700F753CCE0D1"
                 "D2D95060122E9F15A5DDBFC5787E50B5"
                 "CC55EE507BCB084E479AD363AC366B95"
                 "A98CA5F3000B1479"),
]
def nonce(sfx):
    return bytes.fromhex("BBAA998877665544332211%02X" % sfx)

# RFC 7253 Appendix A intermediates for the (0xF, taglen 128) vector:
INTER = {
    'L_*':      "C6A13B37878F5B826F4F8162A1C8D879",
    'L_$':      "8D42766F0F1EB704DE9F02C54391B075",
    'L_0':      "1A84ECDE1E3D6E09BD3E058A8723606D",
    'L_1':      "3509D9BC3C7ADC137A7C0B150E46C0DA",
    'bottom':   15,
    'Ktop':     "9862B0FDEE4E2DD56DBA6433F0125AA2",
    'Stretch':  "9862B0FDEE4E2DD56DBA6433F0125AA2FAD24D13A063F8B8",
    'Offset_0': "587EF72716EAB6DD3219F8092D517D69",
}

# RFC 7253 Appendix A, AEAD_AES_128_OCB_TAGLEN96 sample.
K96 = bytes.fromhex("0F0E0D0C0B0A09080706050403020100")
VEC96 = (nonce(0xD), S40, S40,
         "1792A4E31E0755FB03E31B22116E6C2D"
         "DF9EFD6E33D536F1A0124B0A55BAE884"
         "ED93481529C76B6AD0C515F4D1CDD4FD"
         "AC4F02AA")

ITER_OUT_128 = "67E944D23256C5E0B6C61FA22FDF1EA2"   # AEAD_AES_128_OCB_TAGLEN128

# ==================================================================== run
def main():
    ok = True
    def chk(cond):
        nonlocal ok
        ok = ok and bool(cond)
        return 'PASS' if cond else 'FAIL'
    def line(text, cond):
        print(f"  {text:<66} {chk(cond)}")
    def invalid(fn):
        """fn() must raise Invalid; returns the exception, or None."""
        try:
            fn()
        except Invalid as e:
            return e
        return None
    def info(text):
        print(f"INFO  {text}")
    def spec_note(text):
        print(f"SPEC-NOTE  {text}")

    print("RFC 7253 Appendix A, AEAD_AES_128_OCB_TAGLEN128\n"
          "  1blk  : one block per kl.exec, last blocks at their exact length\n"
          "  multi : one kl.exec per section (MGR3), filler above nonce and last blocks\n"
          "  dec   : both ways, P recovered + Hash_Verify Success; tamper: Failure\n"
          "  SCC   : encrypt and decrypt with export/import after every instruction")
    print(f"{'case':>4} {'|A|':>4} {'|P|':>4}  {'REF-enc':8} {'KLEE-1blk':10} "
          f"{'KLEE-multi':11} {'KLEE-dec':9} {'tamper':7} {'SCC-hop':8} finalize")
    for sfx, la, lp, ct in VEC128:
        N, A, P, CT = nonce(sfx), S40[:la], S40[:lp], bytes.fromhex(ct)
        r = ref_ocb_encrypt(K128, N, A, P, 128)
        a1 = kl_ocb_encrypt(K128, N, A, P, 128)
        am = kl_ocb_encrypt(K128, N, A, P, 128, per_exec=0, junk=True)
        Pd, good = kl_ocb_decrypt(K128, N, A, CT, 128)
        Pm, goodm = kl_ocb_decrypt(K128, N, A, CT, 128, per_exec=0, junk=True)
        bad = bytearray(CT); bad[-1] ^= 0x40      # tamper the tag
        _, evil = kl_ocb_decrypt(K128, N, A, bytes(bad), 128)
        ah = kl_ocb_encrypt(K128, N, A, P, 128, hop=True)
        Ph, goodh = kl_ocb_decrypt(K128, N, A, CT, 128, hop=True)
        fin = 'FormD' if lp % 16 == 0 else 'last-blk'
        print(f"  %02X {la:>4} {lp:>4}  {chk(r == CT):8} {chk(a1 == CT):10} "
              f"{chk(am == CT):11} {chk(Pd == P and good and Pm == P and goodm):9} "
              f"{chk(not evil):7} {chk(ah == CT and Ph == P and goodh):8} {fin}"
              % sfx)

    print("\nKLEE-model internal values vs RFC 7253 published intermediates "
          "(vector 0F, taglen 128):")
    ms = []
    kl_ocb_encrypt(K128, nonce(0xF), b'', S40, 128, machine_out=ms)
    for name, got in ms[0].items():
        print(f"  {name:9} {chk(got == INTER[name])}")

    print("\nRFC 7253 Appendix A, AEAD_AES_128_OCB_TAGLEN96 sample:")
    N, A, P, CT = VEC96[0], VEC96[1], VEC96[2], bytes.fromhex(VEC96[3])
    r = ref_ocb_encrypt(K96, N, A, P, 96)
    a = kl_ocb_encrypt(K96, N, A, P, 96)
    am = kl_ocb_encrypt(K96, N, A, P, 96, per_exec=0, junk=True, hop=True)
    Pd, good = kl_ocb_decrypt(K96, N, A, CT, 96)
    Pm, goodm = kl_ocb_decrypt(K96, N, A, CT, 96, per_exec=0, junk=True, hop=True)
    bad = bytearray(CT); bad[-1] ^= 1
    _, evil = kl_ocb_decrypt(K96, N, A, bytes(bad), 96)
    print(f"  REF-enc {chk(r == CT)}   KLEE-enc {chk(a == CT and am == CT)}   "
          f"KLEE-dec {chk(Pd == P and good and Pm == P and goodm)}   "
          f"tamper {chk(not evil)}")

    print("\nRFC 7253 iterated test, AEAD_AES_128_OCB_TAGLEN128, "
          "end-to-end through the KLEE model (multi-block kl.exec):")
    Kit = bytes(15) + bytes([128])                # zeros(KEYLEN-8) || num2str(TAGLEN,8)
    C = b''
    for i in range(128):
        S = bytes(i)                              # zeros(8i) = 8i bits = i bytes
        C += kl_ocb_encrypt(Kit, (3 * i + 1).to_bytes(12, 'big'), S, S, 128, per_exec=0)
        C += kl_ocb_encrypt(Kit, (3 * i + 2).to_bytes(12, 'big'), b'', S, 128, per_exec=0)
        C += kl_ocb_encrypt(Kit, (3 * i + 3).to_bytes(12, 'big'), S, b'', 128, per_exec=0)
    out = kl_ocb_encrypt(Kit, (385).to_bytes(12, 'big'), C, b'', 128, per_exec=0)
    print(f"  |C| = {len(C)} bytes (expect 22400): {chk(len(C) == 22400)}")
    print(f"  Output = {out.hex().upper()}  {chk(out.hex().upper() == ITER_OUT_128)}")

    # ---------------------------------------------- Serialized Content
    print("\nSerialized Content of <<KLEE-OCB-mode>> (plaintext of Content1; "
          "the MDH is not part of it):")
    info("the table gives the order and size of the fields only; they are packed "
         "here from bit 0 upwards (lowest address first, <<KLEE-Notation>>), then "
         "zero-padded to a multiple of 128 bits.")
    for label, kb in (("SKID", 64), ("k = 128", 128), ("k = 192", 192), ("k = 256", 256)):
        bits = sum(w for _, w in ocb_layout(kb))
        blocks = -(-bits // B)
        info(f"{label:8}: fields {bits} bits + {blocks * B - bits} padding = "
             f"{blocks} blocks; SCC = MDH + SIV + Content1 = {blocks + 2} blocks")
    fits = True
    for vals in ((K128, 0, 120, 128, ONES48, 120), (K128, ONES48 >> 1, 6, 64, 1, 0),
                 (K128, 1 << 119, 7, 96, ONES48 - 1, 8)):
        key, Nv, nl, tl, idx, lbl = vals
        cl = KleeOcb(key)
        cl.N, cl.N_len, cl.tag_len, cl.index, cl.last_blk_len = Nv, nl, tl, idx, lbl
        cl.Lstar = cl.offset = cl.hash_A = cl.checksum_P = MASK128
        try:
            back = cl.imported(cl.export())
            fits &= (back.N, back.N_len, back.tag_len, back.index,
                     back.last_blk_len) == (Nv, nl, tl, idx, lbl)
        except OverflowError:
            fits = False
    line("every admissible value fits its row (N_len, index, tag_len code, ...)", fits)
    for sk in (None, 0x0123456789ABCDEF):
        N, A, P, CT = nonce(0x7), S40[:24], S40[:24], bytes.fromhex(VEC128[7][3])
        got = kl_ocb_encrypt(K128, N, A, P, 128, hop=True, skid=sk, per_exec=0)
        line(f"export/import after every instruction, key "
             f"{'by value' if sk is None else 'as a 64-bit SKID'}: vector 07", got == CT)
    info("tag_len has no value before the first transition to _Hash_Absorb_; its "
         "2-bit code (tag_len/32 - 2) is exported as 0 until then, which is "
         "harmless since _Hash_Absorb_ assigns tag_len before any use.")

    # ------------------------------------------------ State machine
    print("\nState machine (MGR1-MGR6 of <<KLEE-Machines-other-rules>>, SGR rules "
          "of Book 1); vector 0D unless stated:")
    N13, CT13 = nonce(0xD), bytes.fromhex(VEC128[13][3])

    def at_hash_absorb(K=K128, N=N13, tag_len=128, **kw):
        cl = KleeOcb(K, **kw)
        cl.setst(S_SET_AUX, 'B', 8 * len(N))
        cl.exec('B', b2v(N))
        cl.setst(S_HASH_ABSORB, 'B', tag_len)
        return cl

    def at_crypt(dec=False, A=S40, **kw):
        """A CL that has absorbed A and entered Encrypt (or Decrypt)."""
        cl = at_hash_absorb(**kw)
        for INPUT, klen in _chunks(A, 0):
            cl.exec('B', INPUT, klen)
        rest = A[len(A) // 16 * 16:]
        cl.setst(S_HASH_LAST, 'B', 8 * len(rest))
        if rest:
            cl.exec('B', b2v(rest), 8 * len(rest))
        cl.setst(S_DECRYPT if dec else S_ENCRYPT, 'A')
        return cl

    def at_last(dec=False, n=64):
        """Vector 0D: the full blocks processed, the last block announced."""
        cl = at_crypt(dec)
        body = CT13[:32] if dec else S40[:32]
        out = cl.exec('A', b2v(body), 256)
        cl.setst(S_DEC_LAST if dec else S_ENC_LAST, 'B', n)
        return cl, out

    # -- instructions and Forms the current State does not allow (MGR1)
    cl = KleeOcb(K128)
    line("kl.exec in Ready -> Invalid (SGR2)",
         invalid(lambda: cl.exec('B', 0)) and cl.state == S_INVALID)
    line("the Content is cleared on entering the Error State (SGR10)",
         cl.keyb is None and cl.hash_A == cl.checksum_P == cl.offset == 0)
    line("later kl.exec: no operation, OUTPUT zero, State unchanged (SGR16)",
         invalid(lambda: cl.exec('A', 1234)) is None
         and cl.exec('A', 1234) == 0 and cl.state == S_INVALID)
    line("kl.setst #hash_absorb from Ready (Set_Aux_Value skipped) -> Invalid",
         invalid(lambda: KleeOcb(K128).setst(S_HASH_ABSORB, 'B', 128)))
    line("kl.setst #set_aux_value without Xs (Form A) -> Invalid",
         invalid(lambda: KleeOcb(K128).setst(S_SET_AUX, 'A')))
    line("kl.exec Form A in Hash_Absorb -> Invalid (Form B expected)",
         invalid(lambda: at_hash_absorb().exec('A', 0)))
    line("kl.setst #encrypt from Hash_Absorb (last AD block skipped) -> Invalid",
         invalid(lambda: at_hash_absorb().setst(S_ENCRYPT, 'A')))
    cl = at_hash_absorb()
    cl.setst(S_HASH_LAST, 'B', 0)
    line("kl.exec in Hash_Absorb_Last_Block with last_blk_len = 0 -> Invalid",
         invalid(lambda: cl.exec('D')))
    cl = at_hash_absorb()
    cl.setst(S_HASH_LAST, 'B', 64)
    cl.exec('B', b2v(S40[:8]), 64)
    line("a second kl.exec in Hash_Absorb_Last_Block -> Invalid (SPEC-NOTE below)",
         invalid(lambda: cl.exec('B', b2v(S40[:8]), 64)))
    line("kl.exec Form B in Encrypt -> Invalid (Form A expected)",
         invalid(lambda: at_crypt().exec('B', 0)))
    line("kl.exec Form C in Decrypt -> Invalid (Form A expected)",
         invalid(lambda: at_crypt(dec=True).exec('C')))
    line("kl.setst #enc_tag_finalize from Encrypt (last block skipped) -> Invalid",
         invalid(lambda: at_crypt().setst(S_ENC_TAG_FIN, 'A')))
    line("kl.exec Form A in Enc_Last_Block with last_blk_len = 0 -> Invalid",
         invalid(lambda: at_last(n=0)[0].exec('A', 0)))
    line("kl.setst #hash_verify in Decrypt, before the last block -> Invalid",
         invalid(lambda: at_crypt(dec=True).setst(S_HASH_VERIFY, 'C', 0)))
    cl, _ = at_last()
    cl.exec('A', b2v(S40[32:]), 64)
    line("kl.setst #hash_verify in Enc_Tag_Finalize (encryption path) -> Invalid",
         invalid(lambda: cl.setst(S_HASH_VERIFY, 'C', b2v(CT13[40:]))))
    def at_end(dec=False, tag=b''):
        """Vector 0D run to the end: Success, or Success/Failure on decryption."""
        cl, _ = at_last(dec)
        cl.exec('A', b2v((CT13 if dec else S40)[32:40]), 64)
        if dec:
            cl.setst(S_HASH_VERIFY, 'C', b2v(tag))
        else:
            cl.exec('C')
        return cl
    line("a second tag kl.exec, in State Success -> Invalid (SGR5)",
         invalid(lambda: at_end().exec('C')))
    for cl, st, text in ((at_end(), S_SUCCESS, 'Success'),
                         (at_end(True, bytes(16)), S_FAILURE, 'Failure')):
        line(f"kl.setst #decrypt in State {text} -> Invalid (SGR6)",
             cl.state == st and invalid(lambda: cl.setst(S_DECRYPT, 'A')))
    s7, la7, lp7, ct7 = VEC128[7]
    for cl, text in ((at_end(), 'Success'), (at_end(True, bytes(16)), 'Failure'),
                     (at_crypt(), 'Encrypt')):
        cl.setst(S_READY)                         # SGR8; Ready re-initializes
        line(f"kl.setst #ready from {text}, then vector 07 on the same CL (SGR8)",
             kl_ocb_encrypt(None, nonce(s7), S40[:la7], S40[:lp7], 128, cl=cl)
             == bytes.fromhex(ct7))
    # -- the KLIOBUF substitutions of <<KLEE-usage-input-output>>
    try:
        ok2 = all(kl_ocb_encrypt(K128, nonce(s), S40[:la], S40[:lp], 128, subst=True)
                  == bytes.fromhex(ct) for s, la, lp, ct in VEC128)
        ok3 = all(kl_ocb_decrypt(K128, nonce(s), S40[:la], bytes.fromhex(ct), 128,
                                 subst=True) == (S40[:lp], True)
                  for s, la, lp, ct in VEC128)
    except Invalid:
        ok2 = ok3 = False
    line("Form D kl.exec and Form A kl.setst #hash_verify (substitutions) "
         "reproduce all 16 vectors", ok2 and ok3)
    # -- KLLEN (MGR2, MGR3, MGR6) and the last_blk_len rules
    for klen in (64, 136, 200):
        cl = at_hash_absorb()
        line(f"KLLEN = {klen} in Hash_Absorb -> no operation, Invalid (MGR2)",
             invalid(lambda: cl.exec('B', 0, klen)) and cl.state == S_INVALID)
    cl = at_crypt()
    e = invalid(lambda: cl.exec('A', b2v(S40[:16]) | 1 << 140, 144))
    line("KLLEN = 144 in Encrypt -> no operation, OUTPUT zero, Invalid (MGR2)",
         e is not None and e.output == 0 and cl.state == S_INVALID)
    for bad in (4, 12, 124, 128, 136):
        line(f"last_blk_len = {bad:3} (not a multiple of 8, or > 120) -> Invalid",
             invalid(lambda: at_hash_absorb().setst(S_HASH_LAST, 'B', bad)))
    cl = at_hash_absorb()
    cl.setst(S_HASH_LAST, 'B', 64)
    line("kl.exec with KLLEN = 56 < last_blk_len = 64 -> Invalid (INFO below)",
         invalid(lambda: cl.exec('B', b2v(S40[:7]), 56)))
    info("<<KLEE-truncation-vs-length>> gives KLLEN >= last_blk_len as the only "
         "restriction on a last block without stating the consequence; the "
         "harness applies MGR2 (no operation, Error State _Invalid_).")
    cl, _ = at_last()
    out = cl.exec('A', b2v(S40[32:]) | junk_above(64, 256), 256)
    ok1 = cl.state == S_ENC_TAG_FIN and v2b(out, 32) == CT13[32:40] + bytes(24)
    tag = cl.exec('C', klen=256)
    line("Enc_Last_Block, Enc_Tag_Finalize with KLLEN = 256: one block each, "
         "OUTPUT above the written bits zero (MGR3, MGR6)",
         ok1 and v2b(tag, 32) == CT13[40:] + bytes(16) and cl.state == S_SUCCESS)
    cl, pfull = at_last(dec=True)
    out = cl.exec('A', b2v(CT13[32:40]) | junk_above(64, 256), 256)
    ok1 = v2b(pfull, 32) == S40[:32] and v2b(out, 32) == S40[32:] + bytes(24)
    cl.setst(S_HASH_VERIFY, 'C', b2v(CT13[40:]))
    line("Dec_Last_Block with KLLEN = 256: one block, OUTPUT above it zero; "
         "verify Success", ok1 and cl.state == S_SUCCESS)
    # -- tags and the nonce
    N, A, P, CT = VEC96[0], VEC96[1], VEC96[2], bytes.fromhex(VEC96[3])
    raw = []
    kl_ocb_encrypt(K96, N, A, P, 96, tag_out=raw)
    line("tag_len = 96: tag OUTPUT = zeros(32) @ checksum_P[95:0]",
         v2b(raw[0], 16) == CT[40:] + bytes(4))
    _, filler_ok = kl_ocb_decrypt(K96, N, A, CT, 96, junk=True)
    wide = CT[:-12] + bytes([CT[-12] ^ 0x01]) + CT[-11:]
    _, wide_ok = kl_ocb_decrypt(K96, N, A, wide, 96)
    line("Hash_Verify compares tag_len = 96 bits: filler above -> Success, "
         "bit 0 flipped -> Failure", filler_ok and not wide_ok)
    cl = KleeOcb(K128)
    cl.setst(S_SET_AUX, 'B', 96)
    cl.exec('B', b2v(nonce(0x3)))                 # overwritten below
    cl.exec('B', b2v(N13) | junk_above(96))       # rewrites N; filler ignored
    got = kl_ocb_encrypt(None, None, S40, S40, 128, cl=cl)
    line("a repeated nonce kl.exec rewrites N (the first nonce is not used)",
         got == CT13)
    # -- _MachinePolicy_ (<<KLEE-Machine-field>>: bit 0 encrypt, bit 1 decrypt)
    for pol, st, verdict in ((0b10, S_ENCRYPT, False), (0b01, S_DECRYPT, False),
                             (0b10, S_DECRYPT, True), (0b01, S_ENCRYPT, True)):
        cl = at_hash_absorb(policy=pol)
        cl.setst(S_HASH_LAST, 'B', 0)
        e = invalid(lambda: cl.setst(st, 'A'))
        what = 'encrypt' if st == S_ENCRYPT else 'decrypt'
        line(f"_MachinePolicy_ = {pol:02b}: kl.setst #{what} "
             f"{'accepted' if verdict else '-> Invalid'}",
             (e is None and cl.state == st) if verdict else e is not None)
    info("the text names no kl.setst Form for entering _Encrypt_ or _Decrypt_; "
         "the harness uses Form A, as <<KLEE-pseudocode-OCB-encryption>> does.")
    # -- index = ones(48): a CC exported mid-operation, its index row rewritten
    def with_index(cl, idx):
        f = unpack(cl.export(), ocb_layout(128))
        f['index'] = idx
        return cl.imported(pack([(f[n], w) for n, w in ocb_layout(128)]))
    cl = with_index(at_crypt(), ONES48 - 2)
    three = b2v(S40[:16]) * (1 + (1 << 128) + (1 << 256))
    e = invalid(lambda: cl.exec('A', three, 384))
    line("Encrypt at index = ones(48)-2, 3 blocks: 2 written, then Invalid, "
         "third OUTPUT block zero",
         e is not None and sl(e.output, 383, 256) == 0
         and sl(e.output, 255, 128) != 0 and sl(e.output, 127, 0) != 0)
    cl = with_index(at_crypt(dec=True), ONES48 - 1)
    cl.exec('A', 0)
    line("Decrypt: the block at index = ones(48)-1 passes, the next -> Invalid",
         invalid(lambda: cl.exec('A', 0)))
    line("Hash_Absorb at index = ones(48) -> Invalid",
         invalid(lambda: with_index(at_hash_absorb(), ONES48).exec('B', 0)))
    cl = at_hash_absorb()
    cl.setst(S_HASH_LAST, 'B', 64)
    line("Hash_Absorb_Last_Block at index = ones(48) -> Invalid",
         invalid(lambda: with_index(cl, ONES48).exec('B', 0, 64)))
    for dec, name in ((False, 'Enc'), (True, 'Dec')):
        line(f"{name}_Last_Block at index = ones(48), last_blk_len = 64 -> Invalid",
             invalid(lambda: with_index(at_last(dec)[0], ONES48).exec('A', 0, 64)))
    cl = with_index(at_last()[0], ONES48)
    cl.setst(S_ENC_LAST, 'B', 0)
    cl.exec('D')
    line("Enc_Last_Block Form D (last_blk_len = 0) has no index guard",
         cl.state == S_ENC_TAG_FIN)
    line("the largest L index an admissible block uses is ntz(2^47) = 47 < 48",
         max(ntz(i) for i in (1 << 47, ONES48 - 1, 3 << 46)) == 47)
    spec_note("<<KLEE-OCB-mode>> defines MAX_BLOCKS as 2^48 under Parameters but "
              "as 2^48-1 under `index`; with index starting at 1 and the guard "
              "index = ones(48), a section holds at most 2^48-2 blocks.  "
              "Suggested: one definition, MAX_BLOCKS = 2^48-2 (or the guard "
              "stated as the limit).")
    cl = at_hash_absorb()
    cl.setst(S_HASH_LAST, 'B', 64)
    cl.exec('B', b2v(S40[:8]), 64)
    cl2 = cl.imported(cl.export())
    after = 'Invalid' if invalid(lambda: cl2.exec('B', b2v(S40[:8]), 64)) else 'accepted'
    spec_note("<<KLEE-OCB-mode>> _Hash_Absorb_Last_Block_ admits a single kl.exec, "
              "but no transition follows it and neither the Internal State nor the "
              "Serialized Content records that it happened: after export/import a "
              f"second kl.exec is {after} (above, the CL rejects it only through a "
              "harness-private flag).  Suggested: `last_blk_len <- 0` after the "
              "absorption, so that the existing last_blk_len = 0 rule rejects a "
              "second kl.exec.")
    spec_note("Book 2, \"Definition of a Machine in KLEE\" (Zkl-ISA-machines.adoc:341), "
              "says an operation may instead use \"Form D kl.exec or Form C "
              "kl.setst\"; <<KLEE-usage-input-output>> makes Form A kl.setst the "
              "substitute of Form C, which is what this harness applies.")
    info("MGR10 (<<KLEE-MGR-progress-discard>>) does not apply: OCB designates no "
         "progress field and none of its States has an interruptible "
         "long-running instruction.")

    # ------------------------------------------------ derive endpoints
    print("\n<<KLEE-derive-endpoints>> (provisional in the spec): OCB imports "
          "`key` (j = 1) and exports nothing")
    src = K128 + bytes(range(0xF0, 0x100))        # e.g. a 256-bit shared secret
    for length in (16, 32):
        cl = KleeOcb(bytes(16))
        cl.derive_into(1, src, length)
        line(f"key derived in Ready (length = {length} bytes), then vector 0D",
             kl_ocb_encrypt(None, N13, S40, S40, 128, cl=cl, per_exec=0) == CT13)
    line("kl.derive into `key` of a CL in Hash_Absorb -> Invalid",
         invalid(lambda: at_hash_absorb().derive_into(1, src, 16)))
    line("kl.derive into a key configured by a SKID -> Invalid",
         invalid(lambda: KleeOcb(K128, skid=7).derive_into(1, src, 16)))
    for j in (0, 2):
        line(f"kl.derive into endpoint j = {j} (not importable) -> Invalid",
             invalid(lambda: KleeOcb(K128).derive_into(j, src, 16)))
    line("OCB as a kl.derive source (no exportable field) -> Invalid",
         invalid(lambda: at_crypt().derive_from(1)))

    # ------------------------------------------------------ negative controls
    print("\nnegative controls (wrong formulations must NOT reproduce the RFC):")
    print("KAT-EXPECT-FAIL: NC-double")
    print("KAT-EXPECT-FAIL: NC-ktop")
    print("KAT-EXPECT-FAIL: NC-blockorder")
    print("KAT-EXPECT-FAIL: NC-scc-drop")
    print("KAT-EXPECT-FAIL: NC-padbyte")
    fired = []
    def nc(label, text, differs):
        fired.append(differs)
        print(f"  {label:14}({text}): "
              f"{'FAIL as expected' if differs else 'MATCHED (control did not fire)'}")
    sfx, la, lp, ct = VEC128[7]                   # 24/24 bytes: full+partial blocks
    N, A, P, CT = nonce(sfx), S40[:la], S40[:lp], bytes.fromhex(ct)
    nc("NC-double", "L-ladder via little-endian update_mask",
       kl_ocb_encrypt(K128, N, A, P, 128, double_fn=update_mask) != CT)
    nc("NC-ktop", "bswap dropped from Ktop input",
       kl_ocb_encrypt(K128, N, A, P, 128, ktop_bswap=False) != CT)
    nc("NC-blockorder", "multi-block kl.exec, most significant block first",
       kl_ocb_encrypt(K128, nonce(0xD), S40, S40, 128, per_exec=0,
                      msb_first=True) != CT13)
    nc("NC-scc-drop", "Serialized Content without its hash_A row",
       kl_ocb_encrypt(K128, nonce(0xD), S40, S40, 128, hop=True,
                      layout=[r for r in ocb_layout(128) if r[0] != 'hash_A'])
       != CT13)
    Nb = bytes([0xA5, 0xA0])                      # 13-bit nonce, pad bits of byte 1 clear
    nc("NC-padbyte", "13-bit nonce padding cleared in byte 0",
       kl_ocb_encrypt(K128, Nb, S40, S40, 128, n_len=13, pad_byte0=True)
       != ref_ocb_encrypt(K128, Nb, S40, S40, 128, n_len=13))
    ok = ok and all(fired)

    # ---- m4, fixed in the spec: nonces of any bit length 6..120 ------------
    # ANCHOR: the bit-string REF of RFC 7253 section 4.2.  Every published
    # vector uses a byte-string nonce, so this path has no published answer;
    # it is checked against the independent REF instead.
    print("\nm4: nonces of any bit length 6..120 (ANCHOR: REF on bit strings, "
          "RFC 7253 section 4.2; no published vector)")
    print(f"{'N_len':>6}  {'reduces':8} {'vs REF':8} {'roundtrip':10} {'pad ignored':12}")
    Am, Pm = bytes(range(24)), bytes(range(40))
    red = all(nonce_be(b2v(x), 8 * len(x)) == bswap(b2v(x), len(x))
              for x in (bytes.fromhex('BBAA99887766554433221100'),
                        bytes.fromhex('0F1E2D3C4B5A69788796A5B4C3D2E1')))
    print(f"{'8|n':>6}  {chk(red):8} {'--':8} {'--':10} {'--':12}"
          "   nonce_be == bswap(N[n-1:0])")
    for n_len in (6, 7, 8, 13, 60, 61, 119, 120):
        q = (n_len + 7) // 8
        keep = (-n_len) % 8
        raw = bytes((0xA5 ^ i) for i in range(q))
        N = (raw[:-1] + bytes([raw[-1] & ((0xFF << keep) & 0xFF)])) if keep else raw
        ct = kl_ocb_encrypt(K128, N, Am, Pm, 128, n_len=n_len)
        refct = ref_ocb_encrypt(K128, N, Am, Pm, 128, n_len=n_len)
        pt, good = kl_ocb_decrypt(K128, N, Am, ct, 128, n_len=n_len)
        if keep:
            dirty = N[:-1] + bytes([N[-1] | ((1 << keep) - 1)])
            ct2 = kl_ocb_encrypt(K128, dirty, Am, Pm, 128, n_len=n_len)
            padres = chk(ct2 == ct)
        else:
            padres = '--'
        print(f"{n_len:>6}  {'--':8} {chk(ct == refct):8} "
              f"{chk(pt == Pm and good):10} {padres:12}")
    c6a = kl_ocb_encrypt(K128, bytes([0b10110100]), Am, Pm, 128, n_len=6)
    c6b = kl_ocb_encrypt(K128, bytes([0b10110000]), Am, Pm, 128, n_len=6)
    print(f"  N_len = 6, distinct nonces -> distinct ciphertexts : {chk(c6a != c6b)}")
    rej = []
    for bad in (0, 5, 121, 128, 255):
        rej.append(invalid(lambda: kl_ocb_encrypt(K128, bytes(15), Am, Pm, 128,
                                                  n_len=bad)) is not None)
    print(f"  N_len in {{0,5,121,128,255}} -> Error State Invalid  : {chk(all(rej))}")
    info("review m4 is fixed: N_len may be any bit length 6..120, nonce_be(N, n) "
         "covers the general case, and _Dec_Last_Block_ carries the index = "
         "ones(48) guard (checked above).")
    print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
