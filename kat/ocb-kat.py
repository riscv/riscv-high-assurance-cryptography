#!/usr/bin/env python3
"""OCB3 known-answer test: the ACE specification text against RFC 7253.

Two independent implementations are checked against the published vectors:

  REF   RFC 7253 written directly on byte strings (big-endian semantics),
        transcribed from sections 4.1-4.3 of the RFC.
  ACE   the state machine of <<ACE-OCB-mode>> (src/ace-ISA-algorithms.adoc),
        implemented formula-by-formula in the ACE value model of
        src/ace-notation.adoc (byte i of a string lives at bits [8i+7:8i];
        the left operand of @ is more significant; bswap is byte reversal).

Vectors and provenance
  * RFC 7253 Appendix A: the full AEAD_AES_128_OCB_TAGLEN128 sample set
    (K = 000102...0E0F, nonces BBAA9988776655443322110[0-F], 16 cases,
    AD/PT lengths 0..40 bytes including partial blocks), the published
    intermediate values for the last of those vectors (L_*, L_$, L_0, L_1,
    bottom, Ktop, Stretch, Offset_0), the AEAD_AES_128_OCB_TAGLEN96 sample
    (K = 0F0E...0100), and the long iterated test whose 128-bit-tag output
    is 67E944D23256C5E0B6C61FA22FDF1EA2.

Checks performed
  * REF vs RFC and ACE vs RFC for all 17 sample ciphertexts (encryption).
  * ACE internal values vs the RFC's published intermediates (anchors the
    Nonce_be / bottom / Ktop / Stretch_be / offset formulas directly).
  * ACE decryption: plaintext recovery + Hash_Verify Success on the good
    tag, Failure on a tampered tag, for every vector.  Block-multiple
    messages exercise the last_blk_len = 0 (Form D) finalize path on both
    the encrypt and decrypt sides.
  * The RFC 7253 iterated test, run end-to-end through the ACE model.
  * Negative controls (must NOT match the standard, else the test has no
    discriminating power):
      NC-double : the L-ladder derived with the little-endian update_mask
                  instead of double() = bswap(update_mask(bswap(S))).
      NC-ktop   : the bswap dropped from Ktop's input,
                  enc_blk(key, Nonce_be[127:6] @ zeros(6)).

Known spec restrictions honoured (review ACE-spec-review-0.7.0.md, m4)
  * bswap(N[N_len-1:0]) is undefined for non-byte-multiple N_len, so the
    KAT uses byte-multiple nonces only (the RFC vectors are 96-bit).
  * _Dec_Last_Block_ omits the index = ones(48) guard that
    _Enc_Last_Block_ has; the model below is literal and omits it too.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bswap, bin_, aes_encrypt, aes_decrypt,
                    update_mask, double_ocb, bxor)

B = 128                      # block size (spec parameter b)
ONES48 = (1 << 48) - 1

def ntz(n):
    assert n > 0
    return (n & -n).bit_length() - 1

# ====================================================================== REF
# RFC 7253 sections 4.1-4.3, directly on byte strings.  All shifts and
# doublings are over the big-endian integer view of the strings, as the RFC
# specifies ("string of 128 bits", first bit most significant).

def _ref_double(S):
    n = int.from_bytes(S, 'big')
    r = ((n << 1) & ((1 << 128) - 1)) ^ (0x87 if n >> 127 else 0)
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

def _ref_initial_offset(K, N, taglen_bits):
    # Nonce = num2str(TAGLEN mod 128,7) | zeros(120-bitlen(N)) | 1 | N
    Nonce = (((taglen_bits % 128) << 121) | (1 << (8 * len(N)))
             | int.from_bytes(N, 'big')).to_bytes(16, 'big')
    bottom = Nonce[15] & 0x3F
    Ktop = aes_encrypt(K, Nonce[:15] + bytes([Nonce[15] & 0xC0]))
    Stretch = Ktop + bxor(Ktop[:8], Ktop[1:9])
    S = int.from_bytes(Stretch, 'big')          # 192 bits, bit 1 = msb
    Offset = ((S >> (64 - bottom)) & ((1 << 128) - 1)).to_bytes(16, 'big')
    return Offset

def ref_ocb_encrypt(K, N, A, P, taglen_bits):
    E = lambda x: aes_encrypt(K, x)
    Ld = {}
    _ref_setup(K, Ld)
    Offset = _ref_initial_offset(K, N, taglen_bits)
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

# ====================================================================== ACE
# The state machine of <<ACE-OCB-mode>>, transcribed step by step.  Every
# formula is the spec's own, evaluated on ACE values.  `double_fn` and
# `ktop_bswap` parameterize the negative controls; the defaults are the
# specified behavior.

class Invalid(Exception):
    """CR transition to Error State _Invalid_."""

class AceOcb:
    def __init__(self, key, double_fn=double_ocb, ktop_bswap=True):
        self.keyb = key
        self.double = double_fn
        self.ktop_bswap = ktop_bswap
        # State _Ready_ initialization:
        self.N = cat((1, 1), (0, 120))            # N <- 1 @ zeros(120)
        self.N_len = 0
        self.hash_A = 0
        self.checksum_P = 0
        self.index = 0

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

    # -- transitions ----------------------------------------------------
    def setst_nonce_len(self, Xs):                # Ready -> Set_Aux_Value
        if not (6 <= Xs <= 120):
            raise Invalid('N_len out of range')
        self.N_len = Xs

    def exec_set_nonce(self, INPUT):              # Form B in Set_Aux_Value
        # N <- zeros(120-N_len) @ INPUT[N_len-1:0]
        self.N = cat((0, 120 - self.N_len), (sl(INPUT, self.N_len - 1, 0), self.N_len))

    def setst_tag_len(self, Xs):                  # Set_Aux_Value -> Hash_Absorb
        if Xs not in (64, 96, 128):
            raise Invalid('tag_len not in {64,96,128}')
        if self.N_len == 0:
            raise Invalid('N was not set')
        self.index = 1
        self.tag_len = Xs
        self.offset = 0                           # zeros(b)
        self.Lstar = self.enc(0)                  # enc_blk(key, zeros(b))
        self.Ldollar = self.double(self.Lstar)
        self.L = [self.double(self.Ldollar)]      # L[0]

    def _Li(self, i):                             # L[i] <- double(L[i-1]), lazily
        while len(self.L) <= i:
            self.L.append(self.double(self.L[-1]))
        return self.L[i]

    def exec_hash_absorb(self, INPUT):            # Form B in Hash_Absorb
        if self.index == ONES48:
            raise Invalid('index overflow')
        self.offset ^= self._Li(ntz(self.index))
        self.hash_A ^= self.enc(INPUT ^ self.offset)
        self.index += 1

    def setst_last_blk_len(self, Xs):             # -> *_Last_Block
        if Xs % 8 != 0 or Xs > 120:
            raise Invalid('last_blk_len not a byte multiple <= 120')
        self.last_blk_len = Xs

    def exec_hash_absorb_last(self, INPUT):       # Form B in Hash_Absorb_Last_Block
        if self.index == ONES48:
            raise Invalid('index overflow')
        if self.last_blk_len != 0:
            self.offset ^= self.Lstar
            tmp = self.ocb_pad(INPUT, self.last_blk_len) ^ self.offset
            self.hash_A ^= self.enc(tmp)
        # last_blk_len = 0: no ace.exec may be executed at all

    def enter_crypt(self):                        # entering _Encrypt_ / _Decrypt_
        n = self.N_len
        # bswap(N[N_len-1:0]) is undefined for non-byte-multiple N_len (m4):
        assert n % 8 == 0, 'KAT restriction: byte-multiple nonces only'
        self.Nonce_be = cat((bin_(self.tag_len % 128, 7), 7),
                            (0, 120 - n),
                            (1, 1),
                            (bswap(sl(self.N, n - 1, 0), n // 8), n))
        self.bottom = sl(self.Nonce_be, 5, 0)     # int(Nonce_be[5:0])
        ktop_in = cat((sl(self.Nonce_be, 127, 6), 122), (0, 6))
        if self.ktop_bswap:                       # spec: bswap(Nonce_be[127:6] @ zeros(6))
            ktop_in = bswap(ktop_in, 16)
        self.Ktop = self.enc(ktop_in)
        Ktop_be = bswap(self.Ktop, 16)
        self.Stretch_be = cat((Ktop_be, 128),
                              (sl(Ktop_be, 127, 64) ^ sl(Ktop_be, 119, 56), 64))
        self.index = 1
        self.offset = bswap(sl(self.Stretch_be, 191 - self.bottom, 64 - self.bottom), 16)

    def exec_encrypt(self, INPUT):                # Form A in _Encrypt_
        if self.index == ONES48:
            raise Invalid('index overflow')
        self.offset ^= self._Li(ntz(self.index))
        self.checksum_P ^= INPUT
        OUTPUT = self.offset ^ self.enc(INPUT ^ self.offset)
        self.index += 1
        return OUTPUT

    def exec_enc_last(self, INPUT):               # Form A in _Enc_Last_Block_
        n = self.last_blk_len
        if self.index == ONES48:
            raise Invalid('index overflow')
        self.offset ^= self.Lstar
        tmp = sl(self.enc(self.offset), n - 1, 0)             # PAD's low n bits
        OUTPUT = cat((0, 128 - n), (sl(INPUT, n - 1, 0) ^ tmp, n))
        tmp = self.offset ^ self.ocb_pad(INPUT, n)
        self.checksum_P = self.enc(self.checksum_P ^ tmp ^ self.Ldollar) ^ self.hash_A
        return OUTPUT

    def exec_enc_last_empty(self):                # Form D (last_blk_len = 0)
        self.checksum_P = self.enc(self.checksum_P ^ self.offset ^ self.Ldollar) \
                          ^ self.hash_A

    def exec_tag_finalize(self):                  # Form C in _Enc_Tag_Finalize_
        # OUTPUT <- zeros(b - tag_len) @ checksum_P[tag_len-1:0]
        return cat((0, B - self.tag_len), (sl(self.checksum_P, self.tag_len - 1, 0),
                                           self.tag_len))

    def exec_decrypt(self, INPUT):                # Form A in _Decrypt_
        if self.index == ONES48:
            raise Invalid('index overflow')
        self.offset ^= self._Li(ntz(self.index))
        tmp = self.offset ^ self.dec(INPUT ^ self.offset)
        self.checksum_P ^= tmp
        self.index += 1
        return tmp                                # OUTPUT

    def exec_dec_last(self, INPUT):               # Form A in _Dec_Last_Block_
        # NOTE: the spec omits the index = ones(48) guard here (review m4);
        # this model is literal and omits it too.
        n = self.last_blk_len
        self.offset ^= self.Lstar
        tmp = sl(self.enc(self.offset), n - 1, 0)
        OUTPUT = cat((0, 128 - n), (sl(INPUT, n - 1, 0) ^ tmp, n))
        tmp = self.offset ^ self.ocb_pad(OUTPUT, n)
        self.checksum_P = self.enc(self.checksum_P ^ tmp ^ self.Ldollar) ^ self.hash_A
        return OUTPUT

    def setst_hash_verify(self, INPUT):           # Form C ace.setst -> Hash_Verify
        t = self.tag_len
        return sl(INPUT, t - 1, 0) == sl(self.checksum_P, t - 1, 0)   # Success/Failure


def ace_ocb_encrypt(K, N, A, P, taglen_bits, double_fn=double_ocb, ktop_bswap=True,
                    machine_out=None):
    """Drive the state machine the way software would; return C || truncated tag."""
    m = AceOcb(K, double_fn, ktop_bswap)
    m.setst_nonce_len(len(N) * 8)
    m.exec_set_nonce(b2v(N))
    m.setst_tag_len(taglen_bits)
    nA = len(A) // 16
    for i in range(nA):
        m.exec_hash_absorb(b2v(A[i * 16:(i + 1) * 16]))
    rest = A[nA * 16:]
    m.setst_last_blk_len(len(rest) * 8)           # mandatory, can be zero
    if rest:
        m.exec_hash_absorb_last(b2v(rest))
    m.enter_crypt()
    if machine_out is not None:
        machine_out.append(m)                     # snapshot point for anchors
    C = b''
    nP = len(P) // 16
    for i in range(nP):
        C += v2b(m.exec_encrypt(b2v(P[i * 16:(i + 1) * 16])), 16)
    rest = P[nP * 16:]
    m.setst_last_blk_len(len(rest) * 8)
    if rest:
        C += v2b(m.exec_enc_last(b2v(rest)), 16)[:len(rest)]
    else:
        m.exec_enc_last_empty()                   # Form D finalize path
    tag = m.exec_tag_finalize()
    return C + v2b(tag, 16)[:taglen_bits // 8]


def ace_ocb_decrypt(K, N, A, CT, taglen_bits):
    """Return (recovered plaintext, Hash_Verify Success?)."""
    tlb = taglen_bits // 8
    C, tag = CT[:-tlb], CT[-tlb:]
    m = AceOcb(K)
    m.setst_nonce_len(len(N) * 8)
    m.exec_set_nonce(b2v(N))
    m.setst_tag_len(taglen_bits)
    nA = len(A) // 16
    for i in range(nA):
        m.exec_hash_absorb(b2v(A[i * 16:(i + 1) * 16]))
    rest = A[nA * 16:]
    m.setst_last_blk_len(len(rest) * 8)
    if rest:
        m.exec_hash_absorb_last(b2v(rest))
    m.enter_crypt()
    P = b''
    nC = len(C) // 16
    for i in range(nC):
        P += v2b(m.exec_decrypt(b2v(C[i * 16:(i + 1) * 16])), 16)
    rest = C[nC * 16:]
    m.setst_last_blk_len(len(rest) * 8)
    if rest:
        P += v2b(m.exec_dec_last(b2v(rest)), 16)[:len(rest)]
    else:
        m.exec_enc_last_empty()                   # Form D, same formula on decrypt
    ok = m.setst_hash_verify(b2v(tag))            # Form C ace.setst comparison
    return P, ok

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
        ok = ok and cond
        return 'PASS' if cond else 'FAIL'

    print("RFC 7253 Appendix A, AEAD_AES_128_OCB_TAGLEN128 "
          "(encrypt; decrypt = P recovered + verify Success + tamper Failure)")
    print(f"{'case':>4} {'|A|':>4} {'|P|':>4}  {'REF-enc':8} {'ACE-enc':8} "
          f"{'ACE-dec':8} {'tamper':8} finalize")
    for sfx, la, lp, ct in VEC128:
        N, A, P, CT = nonce(sfx), S40[:la], S40[:lp], bytes.fromhex(ct)
        r = ref_ocb_encrypt(K128, N, A, P, 128)
        a = ace_ocb_encrypt(K128, N, A, P, 128)
        Pd, good = ace_ocb_decrypt(K128, N, A, CT, 128)
        bad = bytearray(CT); bad[-1] ^= 0x40      # tamper the tag
        _, evil = ace_ocb_decrypt(K128, N, A, bytes(bad), 128)
        fin = 'FormD' if lp % 16 == 0 else 'last-blk'
        print(f"  %02X {la:>4} {lp:>4}  {chk(r == CT):8} {chk(a == CT):8} "
              f"{chk(Pd == P and good):8} {chk(not evil):8} {fin}"
              % sfx)

    print("\nACE-model internal values vs RFC 7253 published intermediates "
          "(vector 0F, taglen 128):")
    ms = []
    ace_ocb_encrypt(K128, nonce(0xF), b'', S40, 128, machine_out=ms)
    m = ms[0]
    for name, got in [('L_*', v2b(m.Lstar, 16).hex().upper()),
                      ('L_$', v2b(m.Ldollar, 16).hex().upper()),
                      ('L_0', v2b(m.L[0], 16).hex().upper()),
                      ('L_1', v2b(m._Li(1), 16).hex().upper()),
                      ('bottom', m.bottom),
                      ('Ktop', v2b(m.Ktop, 16).hex().upper()),
                      ('Stretch', m.Stretch_be.to_bytes(24, 'big').hex().upper()),
                      ('Offset_0', v2b(m.offset, 16).hex().upper())]:
        print(f"  {name:9} {chk(got == INTER[name])}")

    print("\nRFC 7253 Appendix A, AEAD_AES_128_OCB_TAGLEN96 sample:")
    N, A, P, CT = VEC96[0], VEC96[1], VEC96[2], bytes.fromhex(VEC96[3])
    r = ref_ocb_encrypt(K96, N, A, P, 96)
    a = ace_ocb_encrypt(K96, N, A, P, 96)
    Pd, good = ace_ocb_decrypt(K96, N, A, CT, 96)
    bad = bytearray(CT); bad[-1] ^= 1
    _, evil = ace_ocb_decrypt(K96, N, A, bytes(bad), 96)
    print(f"  REF-enc {chk(r == CT)}   ACE-enc {chk(a == CT)}   "
          f"ACE-dec {chk(Pd == P and good)}   tamper {chk(not evil)}")

    print("\nRFC 7253 iterated test, AEAD_AES_128_OCB_TAGLEN128, "
          "end-to-end through the ACE model:")
    Kit = bytes(15) + bytes([128])                # zeros(KEYLEN-8) || num2str(TAGLEN,8)
    C = b''
    for i in range(128):
        S = bytes(8 * i)
        C += ace_ocb_encrypt(Kit, (3 * i + 1).to_bytes(12, 'big'), S, S, 128)
        C += ace_ocb_encrypt(Kit, (3 * i + 2).to_bytes(12, 'big'), b'', S, 128)
        C += ace_ocb_encrypt(Kit, (3 * i + 3).to_bytes(12, 'big'), S, b'', 128)
    out = ace_ocb_encrypt(Kit, (385).to_bytes(12, 'big'), C, b'', 128)
    print(f"  |C| = {len(C)} bytes (expect 22400): {chk(len(C) == 22400)}")
    print(f"  Output = {out.hex().upper()}  {chk(out.hex().upper() == ITER_OUT_128)}")

    # ------------------------------------------------------ negative controls
    print("\nnegative controls (wrong formulations must NOT reproduce the RFC):")
    print("KAT-EXPECT-FAIL: NC-double")
    print("KAT-EXPECT-FAIL: NC-ktop")
    sfx, la, lp, ct = VEC128[7]                   # 24/24 bytes: full+partial blocks
    N, A, P, CT = nonce(sfx), S40[:la], S40[:lp], bytes.fromhex(ct)
    nc1 = ace_ocb_encrypt(K128, N, A, P, 128, double_fn=update_mask)
    fired1 = nc1 != CT
    print(f"  NC-double (L-ladder via little-endian update_mask): "
          f"{'FAIL as expected' if fired1 else 'MATCHED (control did not fire)'}")
    nc2 = ace_ocb_encrypt(K128, N, A, P, 128, ktop_bswap=False)
    fired2 = nc2 != CT
    print(f"  NC-ktop   (bswap dropped from Ktop input)         : "
          f"{'FAIL as expected' if fired2 else 'MATCHED (control did not fire)'}")
    ok = ok and fired1 and fired2

    print("\nNOTE: per review m4, the KAT restricts itself to byte-multiple "
          "nonce lengths; bswap(N[N_len-1:0]) is undefined otherwise.")
    print("NOTE: per review m4, _Dec_Last_Block_ omits the index = ones(48) "
          "guard; the model above follows the literal text.")
    print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
