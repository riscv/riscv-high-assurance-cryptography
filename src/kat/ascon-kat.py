#!/usr/bin/env python3
"""Known-Answer Tests for the KLEE Ascon Machines against NIST SP 800-232.

WHAT IS UNDER TEST
------------------
The *specification text* (src/ace-ISA-machines.adoc) of

  <<KLEE-Ascon-AEAD128>>            Ascon-AEAD128             (Type 8, Mode 0)
  <<KLEE-Ascon-AEAD128-wsn>>        Ascon-AEAD128_Nonce       (Mode 1: nonce in the PI)
  <<KLEE-Ascon-AEAD128-N-masking>>  Ascon-AEAD128_Nonce_Mask  (Mode 2: key K1, nonce N xor K2)
  <<KLEE-Ascon-Hash256>>            Ascon-Hash256             (Mode 3)
  <<KLEE-Ascon-XOF128>>             Ascon-XOF128              (Mode 4)
  <<KLEE-Ascon-CXOF128>>            Ascon-CXOF128             (Mode 5)

and of what binds every Machine: "Definition of a Machine in KLEE" (the MDH is
implicit at Pos. i of every PI and is not part of the Serialized Content; PI and
Serialized Content are implicitly zero-padded to multiples of 128 bits), the AGR
rules of <<KLEE-Machines-other-rules>>, <<KLEE-truncation-vs-length>>,
<<KLEE-state-constants-symmetric>>, <<KLEE-rules-system-keys>> and
<<KLEE-derive-endpoints>>, with the Book 1 rules they lean on
(<<KLEE-State-management>>, <<KLEE-CSR-klstart>>, <<KLEE-instruction-derive>>,
<<KLEE-instruction-restrict>>).

The text is transcribed clause by clause into state machines driven one
architectural instruction at a time: `kl.setst` and `kl.exec` by Form,
`kl.derive`, `kl.restrictl`/`kl.restricth`, provisioning from a PI image, and
export/import of the Serialized Content (in clear: sealing is scc-kat.py's
business).  Only the vector Forms are driven; the KLIOBUF substitutions of
<<KLEE-usage-input-output>> are not.  Nothing is "fixed up": every numbered step
is reproduced as written, on KLEE *values* (little-endian bit strings held in
Python ints, src/ace-notation.adoc), whose table of referenced standards
(<<KLEE-Notation-standards>>) records SP 800-232 as "Little-endian throughout,
including ||" with a "Direct mapping", which SP 800-232 Appendix A (Fig. 9: S[0:0]
is the lsb of S0) confirms.

ANCHORING (three levels, in this order)
---------------------------------------
1. The permutation is written from scratch: the round constants are computed
   from their nibble rule and compared with SP 800-232 Table 5, the S-box is the
   bit-sliced Boolean form of Sec. 3.3, the linear layer uses the rotation pairs
   of Sec. 3.4, eqs. (8)-(12).  ASCON(12) is checked against the precomputed
   initial states of Table 12, and the four IVs the .adoc quotes against eq. (79)
   with the parameters of Table 13, and against Table 14.
2. `ref_*` are plain SP 800-232 implementations on byte strings (Algorithms 3-7),
   checked against the embedded official vectors, plus a bit-string transcription
   of Algorithms 3/4 (`ref_aead_bits_*`), checked against the byte version.
   SP 800-232 defines parse/pad on bit strings (Sec. 2.1) and truncates a tag to
   T[0:lambda-1] (Sec. 4.2.1); its KAT files hold byte strings and 128-bit tags
   only, so the bit-string version is what anchors non-byte final blocks and
   truncated tags.  During development the byte version was also run against the
   *complete* official KAT files (1089 AEAD, 1025 Hash256, 1025 XOF128, 1089
   CXOF128 records) with zero mismatches; the subset embedded here is
   representative, not exhaustive.
3. The KLEE Machines are checked against the official vectors and Table 12
   directly, and against `ref_*` where no official vector exists (truncated and
   non-byte tags, non-byte final blocks, nonce masking, squeeze splitting, keys
   obtained through `kl.derive`).  Architectural behaviour that no vector reaches
   (Forms, Error States, granularity, resumption, Serialized Content, derive and
   restrict checks) is checked against the specification text itself.

VECTOR PROVENANCE
-----------------
The AEAD/Hash/XOF/CXOF vectors are verbatim from the NIST-final genkat files of
the Ascon reference implementation, github.com/ascon/ascon-c @ main:

  crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt
  crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt
  crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt
  crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt

Each embedded case carries its `Count` from the corresponding file.  Tables 5,
12, 13 and 14 are transcribed from NIST SP 800-232 (August 2025),
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.pdf

SPECIFICATION FINDINGS (reported, not patched)
----------------------------------------------
Defects are printed as SPEC-NOTE lines; where the text is merely silent or
ambiguous, the reading this model adopts is printed as an INFO line.  In short:

* <<KLEE-Ascon-CXOF128>> leaves "the management and padding of the customization
  string" to the caller but never says that SP 800-232 Sec. 5.3 prefixes Z with
  the 64-bit block Z0 = int64(|Z|) (nor that |Z| <= 2048 bits).  A caller that
  prepends only pad(Z, 64) misses every CXOF vector: the model feeds the
  SP 800-232 prefix and shows, in labelled PASSing checks, that the literal
  reading fails.
* The tag-length clause justifies 64 <= Xs <= 128 by saying that SP 800-232
  "forbids tags shorter than 64 bits"; SP 800-232 Sec. 4.3 R4 admits 32 to 63
  bits after a risk analysis.  The KLEE bound itself is transcribed as written.
* <<KLEE-Ascon-AEAD128-wsn>> initializes state[3..4] from `nonce` "in State
  _Ready_", but `nonce` is in neither its Internal State nor its Serialized
  Content ("Same as for Ascon-AEAD128").  Since the Machine no longer forbids
  the return to _Ready_ (SGR8 applies), the model must keep the PI nonce to
  re-enter _Ready_, and an imported CC cannot re-enter it at all.
* <<KLEE-Ascon-XOF128>> speaks of "State _Hash_Output_/_Hash_Finalize_"; that
  Machine has no State _Hash_Output_.
* The key field of <<KLEE-Ascon-AEAD128>>'s Serialized Content is "128 or 64
  (padded to 128)", that of <<KLEE-Ascon-AEAD128-N-masking>> (and of every other
  Machine) "128 or 64" without padding: with a SKID the state words move by 64
  bits in one layout and not in the other.
* <<KLEE-derive-endpoints>> lists neither Ascon-Hash256 nor the set-nonce and
  nonce-masking Machines.

Earlier findings now fixed in the text: the intro of <<KLEE-Ascon-AEAD128>> says
that the caller pads the AD only (review m5), and the nonce-masking Machine now
lists and serializes `last_blk_len` (demonstrated below by a negative control).

Run directly; prints per-case PASS/FAIL and a final `KAT-RESULT:` line.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl, cat          # KLEE notation (src/ace-notation.adoc)

M64 = (1 << 64) - 1
M128 = (1 << 128) - 1
ONES = (1 << 1024) - 1                        # prior content of an output operand

# ===================================================================== the permutation
#
# SP 800-232 Sec. 3.  Implemented from scratch.

def _round_constants():
    """const_0 .. const_15 of SP 800-232 Table 5, computed rather than transcribed.

    Entry j (0-based) is the byte (15 - l) @ l, where the low nibble is
    l = (j + 12) mod 16 and the high nibble is its ones' complement:

        j :  0     1     2     3     4     5   ...  15
        c : 0x3c  0x2d  0x1e  0x0f  0xf0  0xe1 ... 0x4b

    Round i of Ascon-p[rnd] adds c_i = const_(16-rnd+i) (eq. (3)), i.e. the LAST
    rnd entries are used, so ASCON(12) starts at 0xf0 and ASCON(8) at 0xb4.
    """
    return [((15 - (j + 12) % 16) << 4) | ((j + 12) % 16) for j in range(16)]

RC16 = _round_constants()

# SP 800-232 Table 5, transcribed only to be compared with RC16.
TABLE5 = (0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3,
          0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b)

def _rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M64

# SP 800-232 Sec. 3.4, eqs. (8)-(12): Sigma_i(S_i) = S_i xor (S_i >>> a) xor (S_i >>> b).
SIGMA = ((19, 28), (61, 39), (1, 6), (10, 17), (7, 41))

def ascon_p(S, rounds):
    """Ascon-p[rounds] on the words S[0..4], in place: the .adoc's ASCON(p)."""
    for c in RC16[16 - rounds:]:
        # p_C : constant addition into S2 (eq. (4))
        S[2] ^= c
        # p_S : the 5-bit S-box in bit-sliced Boolean form (Sec. 3.3, Fig. 3)
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        t = [((S[i] ^ M64) & S[(i + 1) % 5]) for i in range(5)]
        for i in range(5):
            S[i] ^= t[(i + 1) % 5]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= M64
        # p_L : linear diffusion, S_i ^= (S_i >>> a) ^ (S_i >>> b)
        for i, (a, b) in enumerate(SIGMA):
            S[i] ^= _rotr(S[i], a) ^ _rotr(S[i], b)
    return S

# IV constants, quoted verbatim from the .adoc "In State _Ready_" clauses.
IV_AEAD = 0x00001000808c0001      # <<KLEE-Ascon-AEAD128>>
IV_HASH = 0x0000080100cc0002      # <<KLEE-Ascon-Hash256>>
IV_XOF  = 0x0000080000cc0003      # <<KLEE-Ascon-XOF128>>
IV_CXOF = 0x0000080000cc0004      # <<KLEE-Ascon-CXOF128>>

def iv_eq79(v, a, b, t, r8):
    """SP 800-232 eq. (79): IV = v || 0^8 || a || b || t || r/8 || 0^16, a bit string
    in the standard's little-endian order, so v occupies the least significant bits."""
    return cat((0, 16), (r8, 8), (t, 16), (b, 4), (a, 4), (0, 8), (v, 8))

# SP 800-232 Table 13: (v, a, b, t, r/8)
TABLE13 = {'Ascon-AEAD128': (1, 12, 8, 128, 16), 'Ascon-Hash256': (2, 12, 12, 256, 8),
           'Ascon-XOF128': (3, 12, 12, 0, 8), 'Ascon-CXOF128': (4, 12, 12, 0, 8)}
# SP 800-232 Table 14: initial values
TABLE14 = {'Ascon-AEAD128': 0x00001000808c0001, 'Ascon-Hash256': 0x0000080100cc0002,
           'Ascon-XOF128': 0x0000080000cc0003, 'Ascon-CXOF128': 0x0000080000cc0004}
# SP 800-232 Table 12: state words S0..S4 after the initialization phase
TABLE12 = {
    'Ascon-Hash256': (0x9b1e5494e934d681, 0x4bc3a01e333751d2, 0xae65396c6b34b81a,
                      0x3c7fd4a4d56a4db3, 0x1a5c464906c5976d),
    'Ascon-XOF128':  (0xda82ce768d9447eb, 0xcc7ce6c75f1ef969, 0xe7508fd780085631,
                      0x0ee0ea53416b58cc, 0xe0547524db6f0bde),
    'Ascon-CXOF128': (0x675527c2a0e8de03, 0x43d12d7dc0377bbc, 0xe9901dec426e81b5,
                      0x2ab14907720780b6, 0x8f3f1d02d432bc46),
}

# ===================================================================== SP 800-232 references
#
# Anchor level 2.  Straight SP 800-232, no KLEE notation.

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
    """SP 800-232 Sec. 5.3, eqs. (75)-(78): Z0 = int64(|Z|) (the length in bits, a 64-bit
    little-endian block), then pad(Z, 64), ahead of the message.  <<KLEE-Ascon-CXOF128>>
    leaves "the management and padding of the customization string ... to the caller",
    so in the KLEE model this prefix is caller-supplied absorbed data."""
    return v2b(8 * len(z), 8) + z + b'\x01' + bytes((-len(z) - 1) % 8)

def ref_cxof128(msg, z, outlen=64):
    return ref_sponge(IV_CXOF, msg, outlen, prefix=cxof_prefix(z))

# ---- bit-string transcription of SP 800-232 Algorithms 3 and 4 --------------------
#
# A bit string X is held as (value, length): X[k] is bit k of the value (Appendix A.1:
# "the first element of a bitstring is the least significant bit").  The 320-bit state
# S = S0 || ... || S4 is one integer with S[0:0] the lsb of S0 (Appendix A, Fig. 9).

def _parse(X, n, r):
    """Algorithm 1: X_0 .. X_(l-1) of r bits and the final block X~_l of n - l*r bits."""
    l = n // r
    return [sl(X, (i + 1) * r - 1, i * r) for i in range(l)], X >> (l * r), n - l * r

def _pad(X, n, r):
    """Algorithm 2: X || 1 || 0^j, j = (-|X|-1) mod r; the appended 1 is bit n."""
    return (X & ((1 << n) - 1)) | (1 << n)

def _p(S, rounds):
    w = ascon_p([sl(S, 64 * i + 63, 64 * i) for i in range(5)], rounds)
    return sum(x << (64 * i) for i, x in enumerate(w))

def _ref_bits_init(K, N, A, alen):
    S = _p(IV_AEAD | (K << 64) | (N << 192), 12)       # S <- Ascon-p[12](IV || K || N)
    S ^= K << 192                                       # S <- S xor (0^192 || K)
    if alen > 0:
        blocks, last, tl = _parse(A, alen, 128)
        for Ai in blocks + [_pad(last, tl, 128)]:
            S = _p(S ^ Ai, 8)                           # Ascon-p[8]((S[0:127] xor A_i) || S[128:319])
    return S ^ (1 << 319)                               # S <- S xor (0^319 || 1)

def _ref_bits_final(S, K, lam):
    S = _p(S ^ (K << 128), 12)                          # Ascon-p[12](S xor (0^128 || K || 0^64))
    return ((S >> 192) ^ K) & ((1 << lam) - 1)          # T <- S[192:319] xor K; T[0:lam-1]

def ref_aead_bits_enc(K, N, A, alen, P, plen, lam=128):
    """Algorithm 3 with the truncation of Sec. 4.2.1; returns (C, T) as values."""
    S = _ref_bits_init(K, N, A, alen)
    blocks, last, l = _parse(P, plen, 128)
    C = 0
    for i, Pi in enumerate(blocks):
        S ^= Pi                                         # S[0:127] <- S[0:127] xor P_i
        C |= (S & M128) << (128 * i)                    # C_i <- S[0:127]
        S = _p(S, 8)
    S ^= _pad(last, l, 128)                             # S[0:127] <- S[0:127] xor pad(P~_n, 128)
    if l:
        C |= sl(S, l - 1, 0) << (128 * len(blocks))     # C~_n <- S[0:l-1]
    return C, _ref_bits_final(S, K, lam)

def ref_aead_bits_dec(K, N, A, alen, C, clen, T, lam=128):
    """Algorithm 4 with the truncation of Sec. 4.2.1; returns (tag valid, P)."""
    S = _ref_bits_init(K, N, A, alen)
    blocks, last, l = _parse(C, clen, 128)
    P = 0
    for i, Ci in enumerate(blocks):
        P |= ((S & M128) ^ Ci) << (128 * i)             # P_i <- S[0:127] xor C_i
        S = (S & ~M128) | Ci                            # S[0:127] <- C_i
        S = _p(S, 8)
    if l:
        P |= (sl(S, l - 1, 0) ^ last) << (128 * len(blocks))   # P~_n <- S[0:l-1] xor C~_n
    S ^= 1 << l                                         # S[l:127] <- S[l:127] xor (1 || 0^(127-l))
    S = (S & ~((1 << l) - 1)) | last                    # S[0:l-1] <- C~_n
    return _ref_bits_final(S, K, lam) == T, P

# ===================================================================== reporting

_ok = True
_n = 0

def head(title):
    print(f"\n{title}")

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

def note(text):
    print(f"  SPEC-NOTE  {text}")

def info(text):
    print(f"  INFO       {text}")

# ===================================================================== KLEE model: the CL
#
# _State_ values: <<KLEE-state-off>>, <<KLEE-states-valid>>, <<KLEE-states-error>>, and the
# Machine-defined values of <<KLEE-state-constants-symmetric>> that the Ascon Machines use.

STATE = {
    'Unconfigured': 0, 'Ready': 1, 'Hash_Absorb': 2, 'Hash_Finalize': 4,
    'Hash_Verify': 5, 'Hash_Output': 6, 'Encrypt': 7, 'Decrypt': 8,
    'Enc_Last_Block': 9, 'Dec_Last_Block': 10, 'Set_Aux_Value': 13,
    'Success': 46, 'Failure': 47, 'Unsupported': 48, 'Invalid': 49,
}
STATE_NAME = {v: k for k, v in STATE.items()}

class Invalid(Exception):
    """Raised by the *drivers* (never by the model) when a CL has entered an Error State."""

class SpecGap(Exception):
    """The specification gives the model no value to use (see the SPEC-NOTE lines)."""

def pack(fields):
    """Serialize (value, width) fields in table order: Pos. i first, i.e. at the least
    significant bits (byte 0 of the image), implicitly zero-padded to a multiple of 128
    bits ("Definition of a Machine in KLEE").  Returns (image, unpadded bit length)."""
    v = off = 0
    for val, w in fields:
        if w == 0:
            continue
        assert 0 <= val < (1 << w), (val, w)
        v |= val << off
        off += w
    return v2b(v, -(-off // 128) * 16), off

def unpack(image, widths):
    v, off, out = b2v(image), 0, []
    for w in widths:
        out.append(sl(v, off + w - 1, off) if w else 0)
        off += w
    return out

class KleeCL:
    """What every Ascon Machine shares: the MDH fields the harness needs, the Error-State
    rules of <<KLEE-State-management>>, the `klstart` rules of <<KLEE-CSR-klstart>>, and the
    dispatch of `kl.setst`/`kl.exec` to the clauses of the Machine's current State."""

    MODE = None             # Type 8 (Ascon), Mode 0-5 (<<KLEE-exec-encodings>>)
    GRAN = None             # Parameters: granularity, in bits
    MULTI = ()              # States whose clause is a per-block operation (AGR3)
    USES_POLICY = False     # whether the Machine uses _MachinePolicy_ (<<KLEE-Machine-field>>)
    EXPORTABLE = {}         # <<KLEE-derive-endpoints>>: source index -> admitting States
    IMPORTABLE = {}         # destination index -> (admitting States, field size in bytes)

    def __init__(self):
        self.st = 'Unconfigured'
        self.policy = 0          # _MachinePolicy_: bit 0 encryption, bit 1 decryption
        self.machine_use = 0     # _MachineUse_, MDH bits [95:80] (<<KLEE-MachineUse>>)
        self.key_type = 0        # _KeyType_ (<<KLEE-KeyType-field>>)
        self.klstart = 0         # stands in for the hart's `klstart` CSR
        self.halted = False
        self._defaults()

    def _defaults(self):
        self._clear_content()

    # ---- Error States
    def in_error(self):
        return 48 <= STATE[self.st] <= 55

    def invalidate(self):
        """Error State _Invalid_.  <<KLEE-SGR-clear-cr-content-error-state>>: the Content beyond
        the MDH is cleared; the MDH, _MachineUse_ included, is retained."""
        self.st = 'Invalid'
        self._clear_content()

    # ---- kl.setst (<<KLEE-instruction-setst>>); `immed` names the State of `#immed7`
    def setst(self, immed, form='A', Xs=None, INPUT=0, KLLEN=0):
        if immed == 'Invalid':                  # an Error State is accepted in any State
            return self.invalidate()
        if self.in_error():                     # <<KLEE-SGR-usage-cr-error-state>>
            return None
        if immed == 'Ready' and form == 'A':
            # SGR8: "A transition from any valid state to _Ready_ ... is always permitted,
            # unless the Machine explicitly forbids it" (<<KLEE-SGR-setst-in-success-failure>>
            # for _Success_ and _Failure_).  No Ascon Machine forbids it any more.
            return self._enter_ready()
        clause = self._setst_clauses().get((self.st, immed, form))
        if clause is None:                      # <<KLEE-AGR-not-allowed-instructions>>
            return self.invalidate()
        return clause(Xs=Xs, INPUT=INPUT, KLLEN=KLLEN)

    # ---- kl.exec (<<KLEE-instruction-exec>>)
    def exec(self, form, INPUT=0, KLLEN=0, out=0, halt_after=None):
        """One `kl.exec` of Form `form`.  `out` is the prior content of the output operand and
        the value returned is its content afterwards (`KLLEN` bits).  `halt_after` = n halts a
        block-iterated instruction precisely after n blocks
        (<<KLEE-IRR-block-iterated-instructions>>); re-issuing it resumes at `klstart`."""
        has_in, has_out = form in ('A', 'B'), form in ('A', 'C')
        done = out & ((1 << (8 * self.klstart)) - 1)   # bytes below `klstart` stay written
        zeroed = done if has_out else out
        self.halted = False
        if self.in_error():
            # <<KLEE-SGR-usage-cr-error-state>>: no operation, _State_ unchanged, and the
            # unwritten part of the output window [klstart, KLLEN/8) is zeroed.
            return zeroed
        # <<KLEE-CSR-klstart>>: the interruption points are 0 and the whole multiples of the
        # granularity inside the window, in a State that processes whole blocks.
        ipoint = self.klstart == 0 or (self.st in self.MULTI and
                                       (8 * self.klstart) % self.GRAN == 0 and
                                       8 * self.klstart < KLLEN)
        if not ipoint:
            if has_in:                          # an input operand: Error State _Invalid_
                self.invalidate()
                return zeroed
            return out                          # an output-only operand: no operation
        if 8 * self.klstart >= KLLEN:           # empty window: no operation
            return out
        clause = self._exec_clauses().get((self.st, form))
        if clause is None:
            # <<KLEE-SGR-no-exec-in-ready>> in _Ready_, <<KLEE-SGR-success-failure>> in
            # _Success_/_Failure_, <<KLEE-AGR-not-allowed-instructions>> elsewhere.
            self.invalidate()
            return zeroed
        res = clause(INPUT, KLLEN, done, halt_after)
        if not self.halted:
            self.klstart = 0                    # the instruction retires
        if self.in_error():
            return zeroed
        return res & ((1 << KLLEN) - 1) if has_out else out

    def _blocks(self, KLLEN, b, halt_after):
        """AGR3: "for i = 0, b, 2b, ..., KLLEN - b, in that order", from 8*klstart when resumed."""
        for n, i in enumerate(range(8 * self.klstart, KLLEN, b)):
            if halt_after is not None and n == halt_after:
                self.klstart, self.halted = i // 8, True    # a prefix-complete point
                return
            yield i

    def _agr2(self, KLLEN, b):
        """AGR2: KLLEN that is not a whole multiple of `b` -> no operation, Error State _Invalid_."""
        if KLLEN % b:
            self.invalidate()
            return True
        return False

    # ---- Serialized Content (export/import of Content1, in clear)
    def _get(self, name):
        if name[:1] == 's' and name[1:].isdigit():
            return self.s[int(name[1:])]
        return getattr(self, name) or 0

    def _set(self, name, val):
        if name[:1] == 's' and name[1:].isdigit():
            self.s[int(name[1:])] = val
        else:
            setattr(self, name, val)

    def _resolve_key(self, sks):
        pass

    def export(self):
        """The MDH fields and the Serialized Content.  <<KLEE-SGR-error-state-CL-is-only-MDH>>:
        a CL in an Error State is its MDH and nothing else."""
        content = b'' if self.in_error() else pack(
            [(self._get(n), w) for n, w in self._layout()])[0]
        return dict(mode=self.MODE, key_type=self.key_type, policy=self.policy,
                    state=STATE[self.st], machine_use=self.machine_use, content1=content)

    @classmethod
    def import_(cls, scc, sks=None, **flags):
        """Complete an import: "Completing an import may result in any admissible value of the
        _State_ and _StateExtension_ fields, since these are restored to the values at export"
        (<<KLEE-State-management>>)."""
        assert scc['mode'] == cls.MODE
        obj = cls.__new__(cls)
        KleeCL.__init__(obj)
        for k, v in flags.items():
            setattr(obj, k, v)
        obj.policy, obj.key_type = scc['policy'], scc['key_type']
        obj.machine_use, obj.st = scc['machine_use'], STATE_NAME[scc['state']]
        if not obj.in_error():
            lay = obj._layout()
            for (name, _), val in zip(lay, unpack(scc['content1'], [w for _, w in lay])):
                obj._set(name, val)
            obj._resolve_key(sks)
        return obj

def kl_pad(x, n, r=128):
    """The .adoc's `pad(x,r) = 0^j @ 1 @ x`, j = (-|x|-1) mod r, on KLEE values."""
    j = (-n - 1) % r
    assert j + 1 + n == r
    return cat((0, j), (1, 1), (x & ((1 << n) - 1), n))

# ===================================================================== KLEE model: Ascon-AEAD128

class KleeAsconAEAD128(KleeCL):
    """<<KLEE-Ascon-AEAD128>>.  Every clause is transcribed in the method that implements it;
    `dsep_wrong_word` is a negative control."""

    MODE = 0
    GRAN = 128                                   # Parameters: b = 128, k = 128, Granularity 128 bits
    MULTI = ('Hash_Absorb', 'Encrypt', 'Decrypt')    # the "(multi-block)" clauses
    USES_POLICY = True                           # "if encryption / decryption is allowed"
    IMPORTABLE = {1: (('Ready',), 16)}           # <<KLEE-derive-endpoints>>: `key` (1)

    def __init__(self, key, policy=0b11, skid=None, dsep_wrong_word=False):
        KleeCL.__init__(self)
        self._provision(key, policy, skid)       # PI: MDH (Pos. i), `key` or SKID (Pos. ii)
        self.dsep_wrong_word = dsep_wrong_word
        self._enter_ready()                      # "Completing a provisioning ... leads only to State _Ready_"

    def _provision(self, key, policy, skid):
        self.policy = policy
        self.key = key & M128
        if skid is not None:                     # AGR8: the key field holds the 64-bit SKID
            self.key_type, self.skid = 1, skid

    def _defaults(self):
        self.dsep_wrong_word = False
        self._clear_content()

    def _clear_content(self):
        # Internal State: `key`, `state[0 .. 4]`, `tag_len` (8 bits), `last_blk_len` (9 bits)
        self.key, self.skid, self.s = 0, None, [0] * 5
        self.tag_len = self.last_blk_len = 0

    def _layout(self):
        # Serialized Content, Pos. i-viii
        return ([('skid' if self.key_type else 'key', 128)]      # i: "128 or 64 (padded to 128)"
                + [('s%d' % i, 64) for i in range(5)]            # ii-vi: state[0] .. state[4]
                + [('last_blk_len', 16), ('tag_len', 16)])       # vii, viii

    def _resolve_key(self, sks):
        if self.key_type:
            ent = (sks or {}).get(self.skid)
            if ent is None:                      # <<KLEE-MVR-open>>: an unresolved SKID
                return self.invalidate()
            self._system_keys(ent)
        return None

    def _system_keys(self, ent):
        self.key = ent

    # ---- "In State _Ready_: The following initialization operations are performed:"
    def _enter_ready(self):
        self.s[0] = IV_AEAD                          # . state[0] <- 0x00001000808c0001
        self.s[1] = sl(self.key, 63, 0)              # . state[1] <- key[63:0]
        self.s[2] = sl(self.key, 127, 64)            # . state[2] <- key[127:64]
        self.s[3], self.s[4] = self._ready_words()   # . state[3] <- zeros(64)  . state[4] <- zeros(64)
        self.tag_len = 128                           # . tag_len <- 128
        self.st = 'Ready'

    def _ready_words(self):
        return 0, 0

    def _nonce(self, N):
        return N

    def _setst_clauses(self):
        return {
            ('Ready', 'Set_Aux_Value', 'B'): self._c_tag_len,
            ('Ready', 'Hash_Absorb', 'C'): self._c_set_nonce,
            ('Hash_Absorb', 'Encrypt', 'A'): lambda **_: self._c_enter('Encrypt', 0b01),
            ('Hash_Absorb', 'Decrypt', 'A'): lambda **_: self._c_enter('Decrypt', 0b10),
            ('Encrypt', 'Enc_Last_Block', 'B'):
                lambda Xs, **_: self._c_last(Xs, 'Enc_Last_Block', 'Hash_Output'),
            ('Decrypt', 'Dec_Last_Block', 'B'):
                lambda Xs, **_: self._c_last(Xs, 'Dec_Last_Block', 'Hash_Verify'),
        }

    def _exec_clauses(self):
        return {
            ('Hash_Absorb', 'B'): self._x_absorb,
            ('Encrypt', 'A'): self._x_encrypt,
            ('Enc_Last_Block', 'A'): self._x_enc_last,
            ('Hash_Output', 'C'): self._x_tag,
            ('Decrypt', 'A'): self._x_decrypt,
            ('Dec_Last_Block', 'A'): self._x_dec_last,
            ('Hash_Verify', 'B'): self._x_verify,
        }

    # ---- "In State _Ready_, a Form B kl.setst Kn, #kl_state_set_aux_value, Xs sets
    #      tag_len <- Xs.  Admissible values satisfy 64 <= Xs <= 128; any other value causes
    #      the CL to transition to Error State _Invalid_ ... The _State_ field is unchanged"
    def _c_tag_len(self, Xs, **_):
        if not (64 <= Xs <= 128):
            return self.invalidate()
        self.tag_len = Xs
        return None

    # ---- Ready -> Hash_Absorb: "a Form C kl.setst is expected, whose INPUT sets the nonce"
    def _c_set_nonce(self, INPUT, KLLEN, **_):
        if KLLEN < 128:                          # INFO: a short nonce breaks the granularity (AGR2)
            return self.invalidate()
        # "If KLLEN > 128, only the 128 least significant bits of INPUT are considered." (AGR5)
        N = self._nonce(sl(INPUT, 127, 0))
        self.s[3] = sl(N, 63, 0)                 # . state[3] <- INPUT[63:0]
        self.s[4] = sl(N, 127, 64)               # . state[4] <- INPUT[127:64]
        return self._c_init()

    def _c_init(self, **_):
        ascon_p(self.s, 12)                      # . ASCON(12)
        self.s[3] ^= sl(self.key, 63, 0)         # . state[3] <- state[3] xor key[63:0]
        self.s[4] ^= sl(self.key, 127, 64)       # . state[4] <- state[4] xor key[127:64]
        self.st = 'Hash_Absorb'

    # ---- "_Hash_Absorb_ -> _Encrypt_, if encryption is allowed" (resp. _Decrypt_)
    def _c_enter(self, target, bit):
        if not self.policy & bit:
            return self.invalidate()
        # "Upon entering State _Encrypt_ or _Decrypt_, the following domain separation
        #  operation is performed:"
        if self.dsep_wrong_word:
            self.s[0] ^= 1 << 63                 # NEGATIVE CONTROL: the wrong word
        else:
            self.s[4] ^= 1 << 63                 # . state[4] <- state[4] xor (1 << 63)
        self.st = target
        return None

    # ---- "To transition to State _Enc_Last_Block_ [_Dec_Last_Block_], a Form B kl.setst
    #      instruction must be issued, whose auxiliary argument Xs is the bit length of the
    #      final block."
    def _c_last(self, Xs, last_state, tag_state):
        if Xs > 127:                             # . If Xs > 127, then: ... Error State _Invalid_.
            return self.invalidate()
        if Xs == 0:                              # . If Xs is zero, then:
            self.s[0] ^= 1                       # .. state[0] <- state[0] xor 1  (pad(EMPTY,128))
            self.st = tag_state                  # .. transitions to _Hash_Output_ / _Hash_Verify_
        else:                                    # . else:
            self.last_blk_len = Xs               # .. last_blk_len <- Xs
            self.st = last_state
        return None

    # ---- "In State _Hash_Absorb_, only (multi-block) kl.exec instructions of Form B"
    def _x_absorb(self, INPUT, KLLEN, out, halt):
        if self._agr2(KLLEN, 128):
            return out
        for i in self._blocks(KLLEN, 128, halt):
            self.s[0] ^= sl(INPUT, i + 63, i)            # . state[0] <- state[0] xor INPUT[63:0]
            self.s[1] ^= sl(INPUT, i + 127, i + 64)      # . state[1] <- state[1] xor INPUT[127:64]
            ascon_p(self.s, 8)                           # . ASCON(8)
        return out

    # ---- "In State _Encrypt_, (multi-block) kl.exec instructions ... of Form A"
    def _x_encrypt(self, INPUT, KLLEN, out, halt):
        if self._agr2(KLLEN, 128):
            return out
        for i in self._blocks(KLLEN, 128, halt):
            self.s[0] ^= sl(INPUT, i + 63, i)            # . state[0] <- state[0] xor INPUT[63:0]
            self.s[1] ^= sl(INPUT, i + 127, i + 64)      # . state[1] <- state[1] xor INPUT[127:64]
            out |= cat((self.s[1], 64), (self.s[0], 64)) << i    # . OUTPUT <- state[1] @ state[0]
            ascon_p(self.s, 8)                           # . ASCON(8)
        return out

    # ---- "State _Enc_Last_Block_ ... exactly one kl.exec instruction of Form A"
    def _x_enc_last(self, INPUT, KLLEN, out, halt):
        L = self.last_blk_len
        if KLLEN < L:            # <<KLEE-truncation-vs-length>>: "KLLEN >= last_blk_len" (INFO)
            self.invalidate()
            return out
        tmp = kl_pad(sl(INPUT, L - 1, 0), L, 128)        # . tmp <- pad(INPUT[last_blk_len-1:0], 128)
        self.s[0] ^= sl(tmp, 63, 0)                      # . state[0] <- state[0] xor tmp[63:0]
        self.s[1] ^= sl(tmp, 127, 64)                    # . state[1] <- state[1] xor tmp[127:64]
        tmp = cat((self.s[1], 64), (self.s[0], 64))      # . tmp <- state[1] @ state[0]
        OUTPUT = cat((0, 128 - L), (sl(tmp, L - 1, 0), L))   # . OUTPUT <- zeros(128-L) @ tmp[L-1:0]
        # "(Only the 128 lsbs of OUTPUT are written to.)"  AGR6 clears the rest (INFO).
        self.st = 'Hash_Output'                          # . transitions to State _Hash_Output_
        return OUTPUT

    # ---- the steps _Hash_Output_ and _Hash_Verify_ share
    def _tag(self):
        self.s[2] ^= sl(self.key, 63, 0)         # . state[2] <- state[2] xor key[63:0]
        self.s[3] ^= sl(self.key, 127, 64)       # . state[3] <- state[3] xor key[127:64]
        ascon_p(self.s, 12)                      # . ASCON(12)
        self.s[3] ^= sl(self.key, 63, 0)         # . state[3] <- state[3] xor key[63:0]
        self.s[4] ^= sl(self.key, 127, 64)       # . state[4] <- state[4] xor key[127:64]
        return cat((self.s[4], 64), (self.s[3], 64))

    # ---- "In State _Hash_Output_, only one kl.exec instruction of Form C"
    def _x_tag(self, INPUT, KLLEN, out, halt):
        if self._agr2(KLLEN, 128):               # INFO: the tag is not a "last block"
            return out
        t = self._tag()
        # . OUTPUT <- zeros(128 - tag_len) @ (state[4] @ state[3])[tag_len-1:0]
        OUTPUT = cat((0, 128 - self.tag_len), (sl(t, self.tag_len - 1, 0), self.tag_len))
        self.st = 'Success'                      # . transitions to State _Success_
        return OUTPUT

    # ---- "In State _Decrypt_, (multi-block) kl.exec instructions ... of Form A"
    def _x_decrypt(self, INPUT, KLLEN, out, halt):
        if self._agr2(KLLEN, 128):
            return out
        for i in self._blocks(KLLEN, 128, halt):
            # . tmp <- (state[1] xor INPUT[127:64]) @ (state[0] xor INPUT[63:0])
            tmp = cat((self.s[1] ^ sl(INPUT, i + 127, i + 64), 64),
                      (self.s[0] ^ sl(INPUT, i + 63, i), 64))
            self.s[0] = sl(INPUT, i + 63, i)             # . state[0] <- INPUT[63:0]
            self.s[1] = sl(INPUT, i + 127, i + 64)       # . state[1] <- INPUT[127:64]
            ascon_p(self.s, 8)                           # . ASCON(8)
            out |= tmp << i                              # . OUTPUT <- tmp
        return out

    # ---- "In State _Dec_Last_Block_, only one kl.exec instruction of Form A"
    def _x_dec_last(self, INPUT, KLLEN, out, halt):
        L = self.last_blk_len
        if KLLEN < L:
            self.invalidate()
            return out
        S_r = cat((self.s[1], 64), (self.s[0], 64))                           # . S_r <- state[1] @ state[0]
        P = cat((0, 128 - L), (sl(S_r, L - 1, 0) ^ sl(INPUT, L - 1, 0), L))   # . P <- zeros(128-L) @ (...)
        OUTPUT = P                                                            # . OUTPUT <- P
        S_r ^= kl_pad(sl(P, L - 1, 0), L, 128)                                # . S_r <- S_r xor pad(P[L-1:0], 128)
        self.s[0] = sl(S_r, 63, 0)                                            # . state[0] <- S_r[63:0]
        self.s[1] = sl(S_r, 127, 64)                                          # . state[1] <- S_r[127:64]
        self.st = 'Hash_Verify'                                               # . transitions to _Hash_Verify_
        return OUTPUT

    # ---- "In State _Hash_Verify_, only one kl.exec instruction of Form B"
    def _x_verify(self, INPUT, KLLEN, out, halt):
        if self._agr2(KLLEN, 128):
            return out
        t = self._tag()
        # . INPUT[tag_len-1:0] is compared to (state[4] @ state[3])[tag_len-1:0].
        ok = sl(INPUT, self.tag_len - 1, 0) == sl(t, self.tag_len - 1, 0)
        self.st = 'Success' if ok else 'Failure'
        return out

    # ---- kl.derive destination `key` (1), "filled with the destination CL in State _Ready_"
    def derive_dest(self, j, data, dest_len):
        # <<KLEE-derive-rule-both-fixed-size>>: eff_length bytes, zero-filled beyond them
        self.key = b2v(data.ljust(dest_len, b'\0'))
        self._enter_ready()      # INFO: the Ready initialization picks up the new key

class KleeAsconAEAD128Nonce(KleeAsconAEAD128):
    """<<KLEE-Ascon-AEAD128-wsn>>: "the nonce is not supplied on the transition into State
    _Hash_Absorb_, which therefore uses a Form A kl.setst"."""

    MODE = 1
    IMPORTABLE = {}              # not listed in <<KLEE-derive-endpoints>>

    def __init__(self, key, nonce, policy=0b11, skid=None):
        KleeCL.__init__(self)
        self._provision(key, policy, skid)       # PI Pos. ii: `key` or SKID
        # PI Pos. iii: `nonce`.  SPEC-NOTE: the Internal State ("Same as for Ascon-AEAD128")
        # has no such field; the model keeps it to perform the _Ready_ initialization below.
        self.nonce = nonce & M128
        self._enter_ready()

    def _clear_content(self):
        super()._clear_content()
        self.nonce = None        # also what an import yields: the SCC does not carry it

    def _ready_words(self):
        # "In State _Ready_, words 3 and 4 of `state` are initialized thus:
        #  . state[3] <- nonce[63:0] and . state[4] <- nonce[127:64]."
        if self.nonce is None:
            raise SpecGap("`nonce` is in neither the Internal State nor the Serialized Content")
        return sl(self.nonce, 63, 0), sl(self.nonce, 127, 64)

    def _setst_clauses(self):
        c = super()._setst_clauses()
        # "To transition to State _Hash_Absorb_, the kl.setst instruction must be of Form A,
        #  i.e., _without any additional inputs_, since the nonce is already included in the PI."
        del c[('Ready', 'Hash_Absorb', 'C')]
        c[('Ready', 'Hash_Absorb', 'A')] = self._c_init
        return c

class KleeAsconAEAD128NonceMask(KleeAsconAEAD128):
    """<<KLEE-Ascon-AEAD128-N-masking>>: "the same states as Ascon-AEAD128's ... with the key
    `key` equal to `K1` and the nonce `N` replaced throughout by `N xor K2`"."""

    MODE = 2
    IMPORTABLE = {}              # not listed in <<KLEE-derive-endpoints>>
    legacy_layout = False        # NEGATIVE CONTROL: the Serialized Content before last_blk_len

    def __init__(self, K1, K2, policy=0b11, skid=None):
        KleeCL.__init__(self)
        self._provision(K1, policy, skid)        # PI Pos. ii: `K1` or SKID
        self.K2 = K2 & M128                      # PI Pos. iii: `K2`, or nothing with a SKID
        self._enter_ready()

    def _clear_content(self):
        super()._clear_content()
        self.K2 = 0

    def _nonce(self, N):
        return N ^ self.K2       # "the nonce N replaced throughout by N xor K2"

    def _system_keys(self, ent):
        self.key, self.K2 = ent  # AGR9: a single SKID retrieves both keys

    def _layout(self):
        f = ([('skid', 64), ('K2', 0)] if self.key_type       # i: "128 or 64", ii: "128 or 0"
             else [('key', 128), ('K2', 128)])
        f += [('s%d' % i, 64) for i in range(5)]               # iii-vii: state[0] .. state[4]
        if not self.legacy_layout:
            f.append(('last_blk_len', 16))                     # viii
        return f + [('tag_len', 16)]                           # ix

# ===================================================================== KLEE model: the sponges

class KleeAsconHash256(KleeCL):
    """<<KLEE-Ascon-Hash256>>."""

    MODE = 3
    IV = IV_HASH
    GRAN = 64                                    # Parameters: b = 64, Granularity: b
    MULTI = ('Hash_Absorb', 'Hash_Finalize')     # both clauses run KLLEN/64 times
    COUNTDOWN_ON_ENTRY = 3

    def __init__(self):
        KleeCL.__init__(self)                    # "The Provisioning Input contains only the MDH."
        self._enter_ready()

    def _clear_content(self):
        self.s = [0] * 5                         # Internal State: `state[0 .. 4]`

    def _layout(self):
        return [('s%d' % i, 64) for i in range(5)]    # Serialized Content, Pos. i-v

    # "A `countdown`, an integer going from 3 down to 0, is stored in bits [1:0] of _MachineUse_"
    @property
    def countdown(self):
        return sl(self.machine_use, 1, 0)

    @countdown.setter
    def countdown(self, v):
        self.machine_use = (self.machine_use & ~0b11) | (v & 0b11)

    def _enter_ready(self):
        # "In State _Ready_ : The following initialization operations are performed:"
        self.s[:] = [self.IV, 0, 0, 0, 0]        # . state[0] <- IV  . state[1..4] <- zeros(64)
        ascon_p(self.s, 12)                      # . ASCON(12)
        self.st = 'Ready'

    def _setst_clauses(self):
        # "_Ready_ -> _Hash_Absorb_ -> _Hash_Finalize_ -> _Success_" (Forms: INFO)
        return {('Ready', 'Hash_Absorb', 'A'): self._c_absorb,
                ('Hash_Absorb', 'Hash_Finalize', 'A'): self._c_finalize}

    def _exec_clauses(self):
        return {('Hash_Absorb', 'B'): self._x_absorb,
                ('Hash_Finalize', 'C'): self._x_squeeze}

    def _c_absorb(self, **_):
        self.st = 'Hash_Absorb'

    def _c_finalize(self, **_):
        self.countdown = self.COUNTDOWN_ON_ENTRY # "Upon entering _Hash_Finalize_, countdown is set to 3."
        self.st = 'Hash_Finalize'

    # ---- "In State _Hash_Absorb_, only (multi-block) kl.exec instructions of Form B"
    def _x_absorb(self, INPUT, KLLEN, out, halt):
        if self._agr2(KLLEN, 64):
            return out
        for i in self._blocks(KLLEN, 64, halt):
            self.s[0] ^= sl(INPUT, i + 63, i)    # . state[0] <- state[0] xor INPUT
            ascon_p(self.s, 12)                  # . ASCON(12)
        return out

    # ---- "In State _Hash_Finalize_, at most four kl.exec instructions of Form C"; "If KLLEN >= 128,
    #      these operations are executed KLLEN/64 times, writing to OUTPUT[63:0] the first time,
    #      then to OUTPUT[127:64], OUTPUT[191:128], and OUTPUT[255:192]."
    def _x_squeeze(self, INPUT, KLLEN, out, halt):
        if self._agr2(KLLEN, 64):
            return out
        for i in self._blocks(KLLEN, 64, halt):
            if self.countdown != 3:              # . If countdown != 3, then:
                ascon_p(self.s, 12)              # .. ASCON(12)
            out |= self.s[0] << i                # . OUTPUT[63:0] <- state[0]
            if self.countdown == 0:              # . If countdown = 0 then:
                self.st = 'Success'              # .. Transition to State _Success_.
                break    # "the unwritten bits are cleared" (`out` holds zeros above i + 63)
            self.countdown -= 1                  # . else: .. countdown <- countdown - 1
        return out

class KleeAsconXOF128(KleeAsconHash256):
    """<<KLEE-Ascon-XOF128>>: "the same as Ascon-Hash256 ... with the following differences"."""

    MODE = 4
    IV = IV_XOF                                  # 1. "The IV written to state[0] ... is 0x0000080000cc0003."
    COUNTDOWN_ON_ENTRY = 1                       # 2. "Upon entering _Hash_Finalize_, countdown is set to 1."
    EXPORTABLE = {0: ('Hash_Finalize',)}         # <<KLEE-derive-endpoints>>: `kl.exec` output (0)
    IMPORTABLE = {0: (('Hash_Absorb',), None)}   # `kl.exec` input into _Hash_Absorb_ (0)

    # "In State _Hash_Finalize_, any number of kl.exec instructions of Form C can be issued."
    # The KLLEN/64 repetition is inherited from Ascon-Hash256 (INFO).
    def _x_squeeze(self, INPUT, KLLEN, out, halt):
        if self._agr2(KLLEN, 64):
            return out
        for i in self._blocks(KLLEN, 64, halt):
            out |= self._squeeze_word() << i
        return out           # 3. "... the Machine never transitions to State _Success_."

    def _squeeze_word(self):
        if self.countdown == 0:                  # . If countdown = 0, then:
            ascon_p(self.s, 12)                  # .. ASCON(12)
        word = self.s[0]                         # . OUTPUT[63:0] <- state[0]
        if self.countdown != 0:                  # . If countdown != 0 then:
            self.countdown = 0                   # .. countdown <- 0
        return word

    # ---- kl.derive endpoints: "a source producing output in blocks of b bytes produces the
    #      blocks needed to cover them, and the unused part of the last block is discarded";
    #      "the destination consumes the bytes in its blocks of b' bytes"
    def derive_source(self, i, n):
        out = b''
        while len(out) < n:
            out += v2b(self._squeeze_word(), 8)
        return out[:n]

    def derive_dest(self, j, data, dest_len):
        for off in range(0, len(data), 8):
            self.s[0] ^= b2v(data[off:off + 8])  # the per-block operation of _Hash_Absorb_
            ascon_p(self.s, 12)

class KleeAsconCXOF128(KleeAsconXOF128):
    """<<KLEE-Ascon-CXOF128>>: "the IV is 0x0000080000cc0004, and the message is prepended with
    the customization string ... left to the caller"."""
    MODE = 5
    IV = IV_CXOF

# ===================================================================== KLEE model: kl.derive, kl.restrict*

def kl_derive(dst, j, src, i, length):
    """`kl.derive` (<<KLEE-instruction-derive>>) between the endpoints that
    <<KLEE-derive-endpoints>> gives the Ascon Machines; `i`, `j` are the endpoint indices."""
    if src.in_error() or dst.in_error():         # <<KLEE-SGR-gate-order>>: a no-op
        return
    # "If the transfer is not allowed, then both CLs transition to Error State _Invalid_."
    if i not in src.EXPORTABLE or j not in dst.IMPORTABLE:
        src.invalidate()
        dst.invalidate()
        return
    # Check 1, the source first: "The _State_ ... of each CL must admit its endpoint, and a
    # destination whose key is written must be in State _Ready_"
    dst_states, dest_len = dst.IMPORTABLE[j]
    bad_src, bad_dst = src.st not in src.EXPORTABLE[i], dst.st not in dst_states
    if bad_src or bad_dst:
        if bad_src:
            src.invalidate()
        if bad_dst:
            dst.invalidate()
        return
    # Check 2: "A field configured by a SKID is never importable." (INFO: the destination)
    if dest_len is not None and dst.key_type:
        dst.invalidate()
        return
    # Transfer Size Rules (<<KLEE-derive-rule-both-fixed-size>>) and check 3
    eff = min(length, dest_len) if dest_len is not None else length
    if dest_len is None and eff % (dst.GRAN // 8):   # INFO: granularity of an Ascon absorb
        dst.invalidate()
        return
    if length == 0:
        return
    dst.derive_dest(j, src.derive_source(i, eff), dest_len)

def kl_restrictl(cc, machine_policy):
    """`kl.restrictl` requesting only _MachinePolicy_ (<<KLEE-instruction-restrict>>)."""
    if machine_policy == 0 or cc.st == 'Unconfigured':   # a zero field changes nothing
        return
    if not cc.USES_POLICY:       # "if the Machine does not use the field ... _Invalid_"
        return cc.invalidate()
    if machine_policy & ~cc.policy:     # "only if every bit it sets was already set"
        return cc.invalidate()
    dropped = cc.policy & ~machine_policy
    # "as does disabling an operation ... while in a State allowed only while performing it"
    if ((dropped & 0b01 and cc.st in ('Encrypt', 'Enc_Last_Block', 'Hash_Output')) or
            (dropped & 0b10 and cc.st in ('Decrypt', 'Dec_Last_Block', 'Hash_Verify'))):
        return cc.invalidate()
    cc.policy = machine_policy
    return None

def kl_restricth(cc, machine_use):
    """`kl.restricth` requesting only _MachineUse_: "the CL transitions to _Invalid_ where the
    Machine uses the field to hold state, such as ... the squeeze counter of
    <<KLEE-Ascon-Hash256>> ..., and wherever the Machine does not define the field as writable
    by kl.restrict*".  No Ascon Machine defines it as writable."""
    if machine_use == 0 or cc.st == 'Unconfigured':
        return
    cc.invalidate()

# ===================================================================== provisioning

def mdh_pi(mode, policy=0, key_type=0):
    """The MDH of a PI (<<KLEE-metadata-header>>): _Machine_ [11:0] = Type 8 @ Mode,
    _MachinePolicy_ [13:12], _State_ [24:19] = _Unconfigured_, _KeyType_ [30:29]."""
    return cat((key_type, 2), (0, 15), (policy, 2), (8, 8), (mode, 4))

def build_pi(mode, fields, policy=0, key_type=0):
    """"All PI contain an MDH ... in the first position", then the fields of the Machine's
    table in order, implicitly zero-padded to a multiple of 128 bits."""
    return pack([(mdh_pi(mode, policy, key_type), 128)] + list(fields))[0]

def provision(pi, sks=None):
    """Complete a provisioning from a PI image, reading each field where its table puts it."""
    v = b2v(pi)
    mdh = sl(v, 127, 0)
    assert sl(mdh, 11, 4) == 8 and sl(mdh, 24, 19) == 0
    mode, policy, kt = sl(mdh, 3, 0), sl(mdh, 13, 12), sl(mdh, 30, 29)
    if mode in (3, 4, 5):                        # "The Provisioning Input contains only the MDH."
        return {3: KleeAsconHash256, 4: KleeAsconXOF128, 5: KleeAsconCXOF128}[mode]()
    kw = 64 if kt else 128                       # Pos. ii: "128 or 64" (AGR8)
    k = sl(v, 128 + kw - 1, 128)
    skid, ent = (k, (sks or {}).get(k)) if kt else (None, None)
    if mode == 0:
        cc = KleeAsconAEAD128(ent or 0 if kt else k, policy=policy, skid=skid)
    elif mode == 1:
        nonce = sl(v, 128 + kw + 127, 128 + kw)  # Pos. iii: `nonce`
        cc = KleeAsconAEAD128Nonce(ent or 0 if kt else k, nonce, policy=policy, skid=skid)
    else:                                        # Pos. iii: `K2` (128) or nothing (0)
        K1, K2 = (ent or (0, 0)) if kt else (k, sl(v, 383, 256))
        cc = KleeAsconAEAD128NonceMask(K1, K2, policy=policy, skid=skid)
    if kt and ent is None:
        cc.invalidate()                          # <<KLEE-MVR-open>>: an unresolved SKID
    return cc

# ===================================================================== drivers

def pad_ad_caller(ad):
    """The caller's obligation: pad(., 128) on the AD, and on the AD only."""
    if not ad:
        return b''
    return ad + b'\x01' + bytes((-len(ad) - 1) % 16)

def _step(cc, after):
    cc = after(cc) if after else cc
    if cc.in_error():
        raise Invalid(cc.st)
    return cc

def aead_run(cc, decrypt, nonce, ad, data, tag=0, tag_len=128, ad_chunk=1, pt_chunk=1,
             last_block_128=False, after=None):
    """Issue on the provisioned CL `cc` the instruction sequence of <<KLEE-Ascon-AEAD128>>:
    tag_len (if not 128); the nonce (Form C, or Form A when `nonce` is None); the padded AD
    (Form B, KLLEN = 128 * `ad_chunk`); _Encrypt_/_Decrypt_; the full blocks (Form A, KLLEN
    = 128 * `pt_chunk`); the last-block kl.setst; the final block (KLLEN = 8 * its length,
    or a whole 128-bit INPUT with junk beyond last_blk_len); the tag (KLLEN = 128; for
    decryption `tag` is a value zero-extended to 128 bits).  `after(cc)` runs after every
    instruction and may replace the CL.  Returns (cc, data out, tag bytes or verdict)."""
    if tag_len != 128:
        cc.setst('Set_Aux_Value', 'B', Xs=tag_len)
        cc = _step(cc, after)
    if nonce is None:
        cc.setst('Hash_Absorb', 'A')
    else:
        cc.setst('Hash_Absorb', 'C', INPUT=b2v(nonce), KLLEN=128)
    cc = _step(cc, after)
    a = pad_ad_caller(ad)
    for off in range(0, len(a), 16 * ad_chunk):
        chunk = a[off:off + 16 * ad_chunk]
        cc.exec('B', b2v(chunk), 8 * len(chunk))
        cc = _step(cc, after)
    cc.setst('Decrypt' if decrypt else 'Encrypt', 'A')
    cc = _step(cc, after)
    full, out = len(data) // 16 * 16, b''
    for off in range(0, full, 16 * pt_chunk):
        chunk = data[off:min(off + 16 * pt_chunk, full)]
        o = cc.exec('A', b2v(chunk), 8 * len(chunk), out=ONES & ((1 << (8 * len(chunk))) - 1))
        cc = _step(cc, after)
        out += v2b(o, len(chunk))
    last = data[full:]
    cc.setst('Dec_Last_Block' if decrypt else 'Enc_Last_Block', 'B', Xs=8 * len(last))
    cc = _step(cc, after)
    if last:
        n = 8 * len(last)
        if last_block_128:
            o = cc.exec('A', b2v(last) | ((0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a << n) & M128), 128,
                        out=M128)
        else:
            o = cc.exec('A', b2v(last), n)
        cc = _step(cc, after)
        out += v2b(sl(o, n - 1, 0), len(last))
    if decrypt:
        cc.exec('B', tag, 128)
        cc = _step(cc, after)
        return cc, out, cc.st == 'Success'
    t = cc.exec('C', 0, 128, out=M128)
    cc = _step(cc, after)
    return cc, out, v2b(t, 16)[:(tag_len + 7) // 8]

def aead_run_bits(cc, decrypt, N, A, alen, D, dlen, T=0, tag_len=128):
    """`aead_run` on bit strings (value, length): the caller applies pad(., 128) to the AD;
    the final Xs = dlen mod 128 bits are supplied in ceil(Xs/8) bytes.  Returns (data out,
    tag or verdict, final State)."""
    if tag_len != 128:
        cc.setst('Set_Aux_Value', 'B', Xs=tag_len)
    cc.setst('Hash_Absorb', 'C', INPUT=N, KLLEN=128)
    if alen:
        cc.exec('B', _pad(A, alen, 128), -(-(alen + 1) // 128) * 128)
    cc.setst('Decrypt' if decrypt else 'Encrypt', 'A')
    nfull, Xs = dlen // 128, dlen % 128
    out = cc.exec('A', sl(D, 128 * nfull - 1, 0), 128 * nfull) if nfull else 0
    cc.setst('Dec_Last_Block' if decrypt else 'Enc_Last_Block', 'B', Xs=Xs)
    if Xs:
        o = cc.exec('A', D >> (128 * nfull), -(-Xs // 8) * 8)
        out |= sl(o, Xs - 1, 0) << (128 * nfull)
    if decrypt:
        cc.exec('B', T, 128)
        return out, cc.st == 'Success', cc.st
    return out, cc.exec('C', 0, 128), cc.st

def kl_encrypt(key, nonce, ad, pt, dsep_wrong_word=False, **kw):
    cc = KleeAsconAEAD128(b2v(key), dsep_wrong_word=dsep_wrong_word)
    cc, ct, tag = aead_run(cc, False, nonce, ad, pt, **kw)
    return ct, tag, cc

def kl_decrypt(key, nonce, ad, ct, tag, **kw):
    cc = KleeAsconAEAD128(b2v(key))
    cc, pt, ok = aead_run(cc, True, nonce, ad, ct, tag=b2v(tag), **kw)
    return ok, pt, cc

LAST5 = bytes.fromhex("2021222324")          # Count=166: empty AD, 5-byte plaintext ...
C166 = bytes.fromhex("e8c3deee24")           # ... its ciphertext
T166 = bytes.fromhex("21812a398a8ff074c8b7da46c82a94a7")    # ... and its tag

def aead_to(target, policy=0b11):
    """A fresh Ascon-AEAD128 CL (KAT key and nonce, empty AD, Count=166's 5-byte block)
    driven up to State `target`."""
    dec = target in ('Decrypt', 'Dec_Last_Block', 'Hash_Verify')
    stage = {'Ready': 0, 'Hash_Absorb': 1, 'Encrypt': 2, 'Decrypt': 2, 'Enc_Last_Block': 3,
             'Dec_Last_Block': 3, 'Hash_Output': 4, 'Hash_Verify': 4, 'Success': 5}[target]
    cc = KleeAsconAEAD128(b2v(KAT_KEY), policy=policy)
    if stage >= 1:
        cc.setst('Hash_Absorb', 'C', INPUT=b2v(KAT_NONCE), KLLEN=128)
    if stage >= 2:
        cc.setst('Decrypt' if dec else 'Encrypt', 'A')
    if stage >= 3:
        cc.setst('Dec_Last_Block' if dec else 'Enc_Last_Block', 'B', Xs=40)
    if stage >= 4:
        cc.exec('A', b2v(C166 if dec else LAST5), 40)
    if stage >= 5:
        cc.exec('C', 0, 128)
    assert cc.st == target, (cc.st, target)
    return cc

def sponge_run(cc, msg, outlen, prefix=b'', absorb_chunk=1, squeeze=(64,), after=None):
    """The <<KLEE-Ascon-Hash256>> sequence: Form A into _Hash_Absorb_, the caller-padded
    message in Form B (KLLEN = 64 * `absorb_chunk`), Form A into _Hash_Finalize_, then
    Form C with the a `kls in `squeeze` (the last one repeated) until `outlen` bytes are
    collected or the CL leaves _Hash_Finalize_.  Each output operand starts all ones."""
    cc.setst('Hash_Absorb', 'A')
    cc = _step(cc, after)
    m = prefix + msg + b'\x01' + bytes((-len(msg) - 1) % 8)
    for off in range(0, len(m), 8 * absorb_chunk):
        chunk = m[off:off + 8 * absorb_chunk]
        cc.exec('B', b2v(chunk), 8 * len(chunk))
        cc = _step(cc, after)
    cc.setst('Hash_Finalize', 'A')
    cc = _step(cc, after)
    out, k = b'', 0
    while len(out) < outlen and cc.st == 'Hash_Finalize':
        n = squeeze[min(k, len(squeeze) - 1)]
        k += 1
        o = cc.exec('C', 0, n, out=ONES & ((1 << n) - 1))
        cc = _step(cc, after)
        out += v2b(o, n // 8)
    return cc, out[:outlen]

def kl_hash256(msg, **kw):
    cc, md = sponge_run(KleeAsconHash256(), msg, 32, **kw)
    return md, cc

def kl_xof(cls, msg, outlen, **kw):
    cc, out = sponge_run(cls(), msg, outlen, **kw)
    return out, cc

def sponge_at_finalize(cls, msg, prefix=b''):
    cc = cls()
    cc.setst('Hash_Absorb', 'A')
    m = prefix + msg + b'\x01' + bytes((-len(msg) - 1) % 8)
    cc.exec('B', b2v(m), 8 * len(m))
    cc.setst('Hash_Finalize', 'A')
    return cc

def migrate(cls, sks=None, **flags):
    """An `after` hook: export the CL and complete an import of the image into a fresh CL."""
    return lambda cc: cls.import_(cc.export(), sks=sks, **flags)

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

def main():
    h = bytes.fromhex
    K, NN = b2v(KAT_KEY), b2v(KAT_NONCE)
    K1, K2 = h("0f0e0d0c0b0a09080706050403020100"), h("a5a4a3a2a1a09f9e9d9c9b9a99989796")
    K1v, K2v = b2v(K1), b2v(K2)
    Nm = bytes(a ^ b for a, b in zip(KAT_NONCE, K2))
    SKID_A, SKID_M = 0x1122334455667788, 0x0000000000abcdef
    SKS = {SKID_A: K, SKID_M: (K1v, K2v)}        # a toy System Key Store
    c579 = AEAD_KAT[7]                            # Count=579: both AD and PT have a partial block
    ad579, pt579, blob579 = h(c579[1]), h(c579[2]), h(c579[3])

    # ------------------------------------------------------------------ level 1
    head("Level 1: permutation and constants (SP 800-232 Sec. 3, eq. (79), Tables 5, 12-14)")
    chk("round constants computed from the nibble rule == Table 5", tuple(RC16), TABLE5)
    chk("ASCON(12) starts at const_4 = 0xf0, ASCON(8) at const_8 = 0xb4",
        (RC16[16 - 12], RC16[16 - 8]), (0xf0, 0xb4))
    for name, iv in (('Ascon-AEAD128', IV_AEAD), ('Ascon-Hash256', IV_HASH),
                     ('Ascon-XOF128', IV_XOF), ('Ascon-CXOF128', IV_CXOF)):
        chk(f"IV quoted by the .adoc for {name} == eq. (79) with Table 13 == Table 14",
            (iv, iv), (iv_eq79(*TABLE13[name]), TABLE14[name]))
    for name, iv in (('Ascon-Hash256', IV_HASH), ('Ascon-XOF128', IV_XOF),
                     ('Ascon-CXOF128', IV_CXOF)):
        chk(f"Ascon-p[12](IV || 0^256) == Table 12 for {name}",
            tuple(ascon_p([iv, 0, 0, 0, 0], 12)), TABLE12[name])

    # ------------------------------------------------------------------ level 2
    head("Level 2: SP 800-232 references vs official vectors")
    print("  (during development the byte version matched ALL 1089/1025/1025/1089")
    print("   records of the four official KAT files; the subset below is embedded)")
    for count, ad, pt, ct, desc in AEAD_KAT:
        chk(f"ref  AEAD  LWC_AEAD_KAT_128_128 Count={count:<4} {desc}",
            ref_aead_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt)).hex(), ct)
        blob = h(ct)
        chk(f"ref  AEAD  Count={count:<4} decrypts and verifies",
            ref_aead_decrypt(KAT_KEY, KAT_NONCE, h(ad), blob), (True, h(pt)))
        C, T = ref_aead_bits_enc(K, NN, b2v(h(ad)), 8 * len(h(ad)), b2v(h(pt)), 8 * len(h(pt)))
        ok, P = ref_aead_bits_dec(K, NN, b2v(h(ad)), 8 * len(h(ad)), C, 8 * len(h(pt)), T)
        chk(f"ref  AEAD  Count={count:<4} bit-string Algorithms 3/4 agree",
            (v2b(C, len(h(pt))) + v2b(T, 16), ok, P), (blob, True, b2v(h(pt))))
    for count, msg, md in HASH_KAT:
        chk(f"ref  Hash256  LWC_HASH_KAT_128_256 Count={count}", ref_hash256(h(msg)).hex(), md)
    for count, msg, md in XOF_KAT:
        chk(f"ref  XOF128   LWC_XOF_KAT_128_512  Count={count}", ref_xof128(h(msg), 64).hex(), md)
    for count, msg, z, md in CXOF_KAT:
        chk(f"ref  CXOF128  LWC_CXOF_KAT_128_512 Count={count}",
            ref_cxof128(h(msg), h(z), 64).hex(), md)

    # ------------------------------------------------------------------ level 3: AEAD128
    head("<<KLEE-Ascon-AEAD128>> vs official vectors")
    info("the Form of the kl.setst into _Encrypt_/_Decrypt_ (and into _Hash_Absorb_/"
         "_Hash_Finalize_ of the sponges) is not stated; no auxiliary input is defined, so Form A")
    info("the tag States are driven with KLLEN = 128: only \"last blocks\" are exempt from the "
         "128-bit granularity (Definition of a Machine), and the tag is not one")
    for count, ad, pt, ctt, desc in AEAD_KAT:
        ct, tag, cc = kl_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt))
        chk(f"enc  Count={count:<4} {desc}", ((ct + tag).hex(), cc.st), (ctt, 'Success'))
    print("  multi-block kl.exec, AGR3: KLLEN = 256 (AD) and 384 (plaintext)")
    for count, ad, pt, ctt, _ in AEAD_KAT:
        ct, tag, _ = kl_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt), ad_chunk=2, pt_chunk=3)
        chk(f"enc  Count={count:<4} KLLEN=256(AD)/384(PT)", (ct + tag).hex(), ctt)
    print("  final block in a whole 128-bit INPUT, junk beyond last_blk_len "
          "(<<KLEE-truncation-vs-length>>)")
    for count, ad, pt, ctt, _ in AEAD_KAT:
        ct, tag, _ = kl_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt), last_block_128=True)
        chk(f"enc  Count={count:<4} truncated final INPUT", (ct + tag).hex(), ctt)
    cc = aead_to('Enc_Last_Block')
    o = cc.exec('A', b2v(LAST5) | (0xabcdef << 40), 128, out=M128)
    chk("_Enc_Last_Block_ OUTPUT = zeros(128-last_blk_len) @ tmp[last_blk_len-1:0]",
        (sl(o, 39, 0), sl(o, 127, 40)), (b2v(C166), 0))

    head("Decryption path: _Decrypt_ / _Dec_Last_Block_ / _Hash_Verify_")
    for count, ad, pt, ctt, desc in AEAD_KAT:
        blob = h(ctt)
        ct, tag = blob[:-16], blob[-16:]
        ok, rec, cc = kl_decrypt(KAT_KEY, KAT_NONCE, h(ad), ct, tag)
        chk(f"dec  Count={count:<4} plaintext recovered, _Hash_Verify_ -> _Success_",
            (rec.hex(), ok, cc.st), (pt, True, 'Success'))
        ok, rec, cc = kl_decrypt(KAT_KEY, KAT_NONCE, h(ad), ct, tag, ad_chunk=2, pt_chunk=3,
                                 last_block_128=True)
        chk(f"dec  Count={count:<4} KLLEN=256/384, truncated final INPUT",
            (rec.hex(), ok, cc.st), (pt, True, 'Success'))
        bad = bytearray(tag); bad[3] ^= 0x80
        ok2, _, cc2 = kl_decrypt(KAT_KEY, KAT_NONCE, h(ad), ct, bytes(bad))
        chk(f"dec  Count={count:<4} tampered tag -> _Failure_", (ok2, cc2.st), (False, 'Failure'))
        if ct:
            bad = bytearray(ct); bad[0] ^= 0x01
            ok3, _, cc3 = kl_decrypt(KAT_KEY, KAT_NONCE, h(ad), bytes(bad), tag)
            chk(f"dec  Count={count:<4} tampered ciphertext -> _Failure_",
                (ok3, cc3.st), (False, 'Failure'))

    head("Round trip over every final-block length 0..47 bytes (AD 0/5/16/23 bytes)")
    rt_ok = True
    for la in (0, 5, 16, 23):
        for lp in range(0, 48):
            ad = bytes((i * 11 + 1) & 0xff for i in range(la))
            pt = bytes((i * 7 + 3) & 0xff for i in range(lp))
            ct, tag, _ = kl_encrypt(KAT_KEY, KAT_NONCE, ad, pt)
            ok, rec, cc = kl_decrypt(KAT_KEY, KAT_NONCE, ad, ct, tag)
            rt_ok &= ok and rec == pt and cc.st == 'Success'
            rt_ok &= (ct + tag) == ref_aead_encrypt(KAT_KEY, KAT_NONCE, ad, pt)
    chk("KLEE decrypt(encrypt(x)) == x and KLEE == reference, 192 length pairs", rt_ok, True)

    head("Non-byte AD and final blocks (0 < last_blk_len <= 127) vs SP 800-232 Algorithms 3/4")
    pat = b2v(bytes((i * 29 + 7) & 0xff for i in range(64)))
    for alen in (0, 3, 133):
        good = True
        for dlen in (1, 13, 64, 127, 141, 255):
            A, D = pat & ((1 << alen) - 1), (pat >> 11) & ((1 << dlen) - 1)
            C_ref, T_ref = ref_aead_bits_enc(K, NN, A, alen, D, dlen)
            C, T, st = aead_run_bits(KleeAsconAEAD128(K), False, NN, A, alen, D, dlen)
            P, ok, st2 = aead_run_bits(KleeAsconAEAD128(K), True, NN, A, alen, C, dlen, T=T)
            good &= (C, T, st, P, ok) == (C_ref, T_ref, 'Success', D, True)
        chk(f"AD of {alen:>3} bits, data of 1/13/64/127/141/255 bits: KLEE == ref, decryption "
            f"recovers the data", good, True)

    head("tag_len: Form B kl.setst #kl_state_set_aux_value, vs SP 800-232 Sec. 4.2.1 truncation")
    note("the clause says SP 800-232 \"forbids tags shorter than 64 bits\"; its Sec. 4.3 R4 admits "
         "32..63 bits after a careful risk analysis. The KLEE bound 64..128 is transcribed as written")
    A_, P_ = b2v(h("30313233")), b2v(h("202122232425262728292a2b2c2d2e2f30"))
    for tl in (64, 65, 96, 100, 127, 128):
        C_ref, T_ref = ref_aead_bits_enc(K, NN, A_, 32, P_, 136, lam=tl)
        C, T, st = aead_run_bits(KleeAsconAEAD128(K), False, NN, A_, 32, P_, 136, tag_len=tl)
        chk(f"tag_len={tl:<3} OUTPUT == zeros(128-tag_len) @ T[tag_len-1:0] of SP 800-232",
            (C, T, st), (C_ref, T_ref, 'Success'))
        junk = (0x3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c << tl) & M128
        P, ok, st = aead_run_bits(KleeAsconAEAD128(K), True, NN, A_, 32, C, 136, T=T | junk,
                                  tag_len=tl)
        chk(f"tag_len={tl:<3} verify accepts (INPUT bits above tag_len ignored), data recovered",
            (P, ok, st), (P_, True, 'Success'))
        _, ok, st = aead_run_bits(KleeAsconAEAD128(K), True, NN, A_, 32, C, 136,
                                  T=T ^ (1 << (tl - 1)), tag_len=tl)
        chk(f"tag_len={tl:<3} verify rejects a flip of bit tag_len-1", (ok, st), (False, 'Failure'))
    for tl in (0, 8, 32, 63, 129, 255):
        cc = KleeAsconAEAD128(K)
        cc.setst('Set_Aux_Value', 'B', Xs=tl)
        chk(f"tag_len={tl:<3} -> Error State _Invalid_ (64 <= Xs <= 128)", cc.st, 'Invalid')
    cc = KleeAsconAEAD128(K)
    cc.setst('Set_Aux_Value', 'B', Xs=96)
    chk("tag_len=96 leaves _State_ at _Ready_ (\"an operation, not a state\")",
        (cc.st, cc.tag_len), ('Ready', 96))

    head("last_blk_len: Form B kl.setst into _Enc_Last_Block_ / _Dec_Last_Block_")
    for xs in (128, 129, 255):
        for dec in (False, True):
            cc = aead_to('Decrypt' if dec else 'Encrypt')
            cc.setst('Dec_Last_Block' if dec else 'Enc_Last_Block', 'B', Xs=xs)
            chk(f"Xs={xs:<4}({'dec' if dec else 'enc'}) -> Error State _Invalid_", cc.st, 'Invalid')
    for xs, want in ((0, 'Hash_Output'), (1, 'Enc_Last_Block'), (127, 'Enc_Last_Block')):
        cc = aead_to('Encrypt')
        cc.setst('Enc_Last_Block', 'B', Xs=xs)
        chk(f"Xs={xs:<4}-> State _{want}_", (cc.st, cc.last_blk_len), (want, xs if xs else 0))
    for xs, want in ((0, 'Hash_Verify'), (127, 'Dec_Last_Block')):
        cc = aead_to('Decrypt')
        cc.setst('Dec_Last_Block', 'B', Xs=xs)
        chk(f"Xs={xs:<4}-> State _{want}_", cc.st, want)
    info("KLLEN < last_blk_len breaks \"the only restriction ... KLLEN >= last_blk_len\" of "
         "<<KLEE-truncation-vs-length>>; read as a granularity violation (AGR2)")
    cc = aead_to('Enc_Last_Block')
    o = cc.exec('A', b2v(LAST5), 32, out=0xffffffff)
    chk("KLLEN = 32 < last_blk_len = 40 -> Invalid, output window zeroed", (cc.st, o), ('Invalid', 0))
    info("setst #kl_state_hash_output straight from _Encrypt_ (\"_Encrypt_ -> { _Enc_Last_Block_ "
         "-> } _Hash_Output_\") would skip the pad of the Xs = 0 clause; only the Form B path is "
         "modelled, the direct setst is treated as not allowed")

    # ------------------------------------------------------------------ general rules
    head("General rules on Ascon-AEAD128 (Books 1 and 2)")
    cc = KleeAsconAEAD128(K)
    o = cc.exec('A', b2v(h("00" * 16)), 128, out=M128)
    chk("<<KLEE-SGR-no-exec-in-ready>>: Form A kl.exec in _Ready_ -> Invalid, output zeroed",
        (cc.st, o), ('Invalid', 0))
    chk("<<KLEE-SGR-clear-cr-content-error-state>>: key, state, tag_len cleared; the export "
        "is the MDH only", (cc.key, cc.s, cc.tag_len, cc.export()['content1']),
        (0, [0] * 5, 0, b''))
    o = cc.exec('A', 1, 128, out=M128)
    cc.setst('Ready')
    chk("<<KLEE-SGR-usage-cr-error-state>>: kl.exec on the Invalid CL is a no-op with its output "
        "window zeroed; kl.setst #kl_state_ready does nothing", (cc.st, o), ('Invalid', 0))
    cc = KleeAsconAEAD128(K)
    cc.exec('B', 0, 128)
    chk("<<KLEE-SGR-no-exec-in-ready>>: Form B kl.exec in _Ready_ -> Invalid", cc.st, 'Invalid')
    for label, start, act in (
            ("tag_len setst in _Hash_Absorb_", 'Hash_Absorb',
             lambda c: c.setst('Set_Aux_Value', 'B', Xs=96)),
            ("Form A kl.exec in _Hash_Absorb_", 'Hash_Absorb', lambda c: c.exec('A', 0, 128)),
            ("Form B kl.exec in _Encrypt_", 'Encrypt', lambda c: c.exec('B', 0, 128)),
            ("Form C kl.exec in _Decrypt_", 'Decrypt', lambda c: c.exec('C', 0, 128)),
            ("setst _Enc_Last_Block_ from _Hash_Absorb_", 'Hash_Absorb',
             lambda c: c.setst('Enc_Last_Block', 'B', Xs=8)),
            ("setst _Decrypt_ from _Encrypt_", 'Encrypt', lambda c: c.setst('Decrypt', 'A')),
            ("Form A kl.exec in _Hash_Output_", 'Hash_Output', lambda c: c.exec('A', 0, 128)),
            ("Form C kl.exec in _Hash_Verify_", 'Hash_Verify', lambda c: c.exec('C', 0, 128))):
        cc = aead_to(start)
        act(cc)
        chk(f"<<KLEE-AGR-not-allowed-instructions>>: {label} -> Invalid", cc.st, 'Invalid')
    cc = aead_to('Success')
    o = cc.exec('C', 0, 128, out=M128)
    chk("<<KLEE-SGR-success-failure>>: kl.exec in _Success_ (not a XOF) -> Invalid, output "
        "zeroed", (cc.st, o), ('Invalid', 0))

    print("  AGR2 (granularity) and AGR5 (single fixed-width value)")
    for label, start, form, KLLEN in (("Form B, KLLEN = 120, in _Hash_Absorb_", 'Hash_Absorb', 'B', 120),
                                      ("Form A, KLLEN = 136, in _Encrypt_", 'Encrypt', 'A', 136),
                                      ("Form A, KLLEN = 64, in _Decrypt_", 'Decrypt', 'A', 64)):
        cc = aead_to(start)
        o = cc.exec(form, (1 << KLLEN) - 1, KLLEN, out=(1 << KLLEN) - 1)
        chk(f"AGR2: {label} -> no operation, Invalid, output window zeroed",
            (cc.st, o if form == 'A' else 0), ('Invalid', 0))
    info("a nonce shorter than 128 bits in the Form C kl.setst is read as a granularity "
         "violation (AGR2); only KLLEN > 128 is addressed by the text")
    cc = KleeAsconAEAD128(K)
    cc.setst('Hash_Absorb', 'C', INPUT=NN, KLLEN=64)
    chk("Form C kl.setst with KLLEN = 64 -> Invalid", cc.st, 'Invalid')
    cc = KleeAsconAEAD128(K)
    cc.setst('Hash_Absorb', 'C', INPUT=NN | (0xdeadbeef << 150), KLLEN=256)
    cc, ct, tag = aead_run(cc, False, KAT_NONCE, ad579, pt579) if False else (cc, None, None)
    a = pad_ad_caller(ad579)
    cc.exec('B', b2v(a), 8 * len(a))
    cc.setst('Encrypt', 'A')
    o1 = cc.exec('A', b2v(pt579[:16]), 128)
    cc.setst('Enc_Last_Block', 'B', Xs=8)
    o2 = cc.exec('A', b2v(pt579[16:]), 8)
    t = cc.exec('C', 0, 128)
    chk("AGR5: nonce given with KLLEN = 256 and junk above bit 127 == Count=579",
        v2b(o1, 16) + v2b(o2, 1) + v2b(t, 16), blob579)

    print("  AGR6: bits of OUTPUT beyond those a State writes are cleared")
    info("\"(Only the 128 lsbs of OUTPUT are written to.)\" is read with AGR6: OUTPUT[KLLEN-1:128] "
         "is cleared, not left as it was")
    cc = aead_to('Enc_Last_Block')
    o = cc.exec('A', b2v(LAST5), 256, out=(1 << 256) - 1)
    t = cc.exec('C', 0, 256, out=(1 << 256) - 1)
    chk("_Enc_Last_Block_ and _Hash_Output_ with KLLEN = 256: Count=166, upper bits cleared",
        (sl(o, 39, 0), sl(o, 255, 40), sl(t, 127, 0), sl(t, 255, 128), cc.st),
        (b2v(C166), 0, b2v(T166), 0, 'Success'))
    cc = aead_to('Dec_Last_Block')
    o = cc.exec('A', b2v(C166), 256, out=(1 << 256) - 1)
    cc.exec('B', b2v(T166), 128)
    chk("_Dec_Last_Block_ with KLLEN = 256: plaintext, upper bits cleared, tag verifies",
        (sl(o, 39, 0), sl(o, 255, 40), cc.st), (b2v(LAST5), 0, 'Success'))
    cc = KleeAsconAEAD128(K)
    cc, _, tag = aead_run(cc, False, KAT_NONCE, ad579, pt579, tag_len=64)
    cc = aead_to('Hash_Output')
    cc.setst('Ready')
    cc.setst('Set_Aux_Value', 'B', Xs=64)
    cc.setst('Hash_Absorb', 'C', INPUT=NN, KLLEN=128)
    cc.setst('Encrypt', 'A')
    cc.setst('Enc_Last_Block', 'B', Xs=40)
    cc.exec('A', b2v(LAST5), 40)
    t = cc.exec('C', 0, 128, out=M128)
    chk("_Hash_Output_ with tag_len = 64: OUTPUT[127:64] cleared, OUTPUT[63:0] = first 8 tag bytes",
        (sl(t, 127, 64), v2b(sl(t, 63, 0), 8)), (0, T166[:8]))

    print("  SGR6/SGR8: back to _Ready_ from _Success_, _Failure_, and mid-stream")
    cc = KleeAsconAEAD128(K)
    cc, ct, tag = aead_run(cc, False, KAT_NONCE, ad579, pt579, tag_len=64)
    chk("first run with tag_len = 64 emits the first 8 bytes of the Count=579 tag",
        (ct + tag, cc.st), (blob579[:-8], 'Success'))
    cc.setst('Ready')
    chk("_Success_ -> _Ready_ re-performs the initialization, tag_len <- 128 included",
        (cc.st, cc.s, cc.tag_len), ('Ready', [IV_AEAD, sl(K, 63, 0), sl(K, 127, 64), 0, 0], 128))
    cc, ct, tag = aead_run(cc, False, KAT_NONCE, ad579, pt579)
    chk("... and the next run reproduces Count=579 with a 128-bit tag", ct + tag, blob579)
    cc = KleeAsconAEAD128(K)
    bad = blob579[-16:-1] + bytes([blob579[-1] ^ 1])
    cc, _, ok = aead_run(cc, True, KAT_NONCE, ad579, blob579[:-16], tag=b2v(bad))
    chk("tampered tag -> _Failure_", (ok, cc.st), (False, 'Failure'))
    cc.setst('Ready')
    cc, rec, ok = aead_run(cc, True, KAT_NONCE, ad579, blob579[:-16], tag=b2v(blob579[-16:]))
    chk("_Failure_ -> _Ready_ -> the genuine tag -> _Success_", (rec, ok, cc.st),
        (pt579, True, 'Success'))
    cc = aead_to('Encrypt')
    cc.exec('A', b2v(bytes(32)), 256)
    cc.setst('Ready')
    cc, ct, tag = aead_run(cc, False, KAT_NONCE, ad579, pt579)
    chk("_Encrypt_ -> _Ready_ (SGR8: from any Valid State) -> Count=579", ct + tag, blob579)

    print("  _MachinePolicy_: \"if encryption [decryption] is allowed\"; kl.restrictl / kl.restricth")
    cc = aead_to('Hash_Absorb', policy=0b10)
    cc.setst('Encrypt', 'A')
    chk("decryption-only CL: _Hash_Absorb_ -> _Encrypt_ -> Invalid", cc.st, 'Invalid')
    cc = KleeAsconAEAD128(K, policy=0b10)
    cc, rec, ok = aead_run(cc, True, KAT_NONCE, ad579, blob579[:-16], tag=b2v(blob579[-16:]))
    chk("decryption-only CL still decrypts Count=579", (rec, ok), (pt579, True))
    cc = aead_to('Hash_Absorb', policy=0b01)
    cc.setst('Decrypt', 'A')
    chk("encryption-only CL: _Hash_Absorb_ -> _Decrypt_ -> Invalid", cc.st, 'Invalid')
    cc = KleeAsconAEAD128(K)
    kl_restrictl(cc, 0b10)
    st0, pol0 = cc.st, cc.policy
    cc.setst('Hash_Absorb', 'C', INPUT=NN, KLLEN=128)
    cc.setst('Encrypt', 'A')
    chk("kl.restrictl in _Ready_ narrows the CL to decryption; _Encrypt_ is then refused",
        (st0, pol0, cc.st), ('Ready', 0b10, 'Invalid'))
    cc = aead_to('Encrypt')
    kl_restrictl(cc, 0b10)
    chk("kl.restrictl disabling encryption while in _Encrypt_ -> Invalid", cc.st, 'Invalid')
    cc = aead_to('Hash_Output')
    kl_restrictl(cc, 0b10)
    chk("kl.restrictl disabling encryption while in _Hash_Output_ -> Invalid", cc.st, 'Invalid')
    cc = aead_to('Hash_Absorb')
    kl_restrictl(cc, 0b01)
    chk("kl.restrictl disabling decryption in _Hash_Absorb_ is allowed",
        (cc.st, cc.policy), ('Hash_Absorb', 0b01))
    cc = KleeAsconAEAD128(K, policy=0b01)
    kl_restrictl(cc, 0b11)
    chk("kl.restrictl cannot enable decryption -> Invalid", cc.st, 'Invalid')
    cc = KleeAsconAEAD128(K)
    kl_restricth(cc, 0x0001)
    chk("kl.restricth on _MachineUse_ (not writable for Ascon-AEAD128) -> Invalid",
        cc.st, 'Invalid')

    print("  resumption: <<KLEE-IRR-block-iterated-instructions>>, <<KLEE-CSR-klstart>>")
    pt3 = bytes(range(48))
    cc = aead_to('Encrypt')
    whole = cc.exec('A', b2v(pt3), 384)
    for halt in (1, 2):
        cc = aead_to('Encrypt')
        o = cc.exec('A', b2v(pt3), 384, halt_after=halt)
        ks = cc.klstart
        o = cc.exec('A', b2v(pt3), 384, out=o)
        chk(f"Form A over 3 blocks, precise halt after {halt} (klstart = {16 * halt}), resumed: "
            f"same output, klstart <- 0", (ks, o, cc.klstart), (16 * halt, whole, 0))
    a = pad_ad_caller(h(AEAD_KAT[8][1]))
    cc = aead_to('Hash_Absorb')
    cc.exec('B', b2v(a), 256, halt_after=1)
    cc.exec('B', b2v(a), 256)
    cc.setst('Encrypt', 'A')
    ref_c = aead_to('Hash_Absorb')
    ref_c.exec('B', b2v(a), 256)
    ref_c.setst('Encrypt', 'A')
    chk("Form B over 2 AD blocks, halted after 1 and resumed: same state", cc.s, ref_c.s)
    cc = aead_to('Hash_Absorb')
    cc.klstart = 3
    cc.exec('B', b2v(a), 256)
    chk("klstart = 3, not an interruption point, on an input operand -> Invalid", cc.st, 'Invalid')
    info("<<KLEE-AGR-progress-discard>> (AGR10) does not apply: every Ascon kl.exec reads or writes a "
         "vector operand, so no State hosts an operation of <<KLEE-IRR-long-running-no-data>>; "
         "no Ascon field is \"(derived)\" (<<KLEE-AGR-recomputed-fields>>) or loaded piecewise "
         "(<<KLEE-AGR-load-long-field>>)")
    info("the \"In State _Ready_\" initialization is performed on every entry into _Ready_: at the "
         "end of provisioning, on each SGR8 transition, and after kl.derive writes `key`")

    # ------------------------------------------------------------------ Serialized Content
    head("Serialized Content and provisioning (Definition of a Machine; <<KLEE-rules-system-keys>>)")
    pi = build_pi(0, [(K, 128)], policy=0b11)
    chk("Ascon-AEAD128 PI = MDH @ key: 256 bits", len(pi), 32)
    for count, ad, pt, ctt, desc in AEAD_KAT:
        cc = provision(pi)
        cc, ct, tag = aead_run(cc, False, KAT_NONCE, h(ad), h(pt),
                               after=migrate(KleeAsconAEAD128))
        chk(f"AEAD128  Count={count:<4} provisioned from the PI, migrated after every instruction",
            ((ct + tag).hex(), cc.st), (ctt, 'Success'))
    cc = KleeAsconAEAD128(K)
    cc, rec, ok = aead_run(cc, True, KAT_NONCE, ad579, blob579[:-16], tag=b2v(blob579[-16:]),
                           after=migrate(KleeAsconAEAD128))
    chk("AEAD128  Count=579  decryption migrated after every instruction", (rec, ok), (pt579, True))
    img = aead_to('Enc_Last_Block').export()
    c1 = b2v(img['content1'])
    chk("AEAD128 Content1: key (i), state[0..4] (ii-vi), last_blk_len (vii), tag_len (viii); "
        "480 bits padded to 64 bytes", (len(img['content1']), sl(c1, 127, 0), sl(c1, 511, 480),
                                         sl(c1, 463, 448), sl(c1, 479, 464)),
        (64, K, 0, 40, 128))
    pi_s = build_pi(0, [(SKID_A, 64)], policy=0b11, key_type=1)
    cc = provision(pi_s, SKS)
    img = cc.export()
    c1 = b2v(img['content1'])
    chk("with a SKID: PI = MDH @ SKID (192 -> 256 bits); Content1 holds the SKID padded to 128 "
        "bits, state[0] still at bit 128", (len(pi_s), len(img['content1']), sl(c1, 63, 0),
                                            sl(c1, 127, 64), sl(c1, 191, 128)),
        (32, 64, SKID_A, 0, IV_AEAD))
    cc, ct, tag = aead_run(cc, False, KAT_NONCE, ad579, pt579, after=migrate(KleeAsconAEAD128, SKS))
    chk("SKID-keyed CL migrated after every instruction (the SKS resolves the SKID): Count=579",
        ct + tag, blob579)
    bad = KleeAsconAEAD128.import_(img, sks={})
    chk("import of a SKID the SKS does not resolve -> Invalid (<<KLEE-MVR-open>>)",
        bad.st, 'Invalid')
    chk("provisioning with an unresolved SKID -> Invalid", provision(pi_s, {}).st, 'Invalid')

    # ------------------------------------------------------------------ set nonce
    head("<<KLEE-Ascon-AEAD128-wsn>>: nonce in the PI, Form A into _Hash_Absorb_")
    pi = build_pi(1, [(K, 128), (NN, 128)], policy=0b11)
    chk("PI = MDH @ key @ nonce: 384 bits, no `budget` or padding field", len(pi), 48)
    for count, ad, pt, ctt, desc in AEAD_KAT:
        cc = provision(pi)
        cc, ct, tag = aead_run(cc, False, None, h(ad), h(pt))
        chk(f"set-nonce  Count={count:<4} same ciphertext as the base Machine",
            ((ct + tag).hex(), cc.st), (ctt, 'Success'))
    cc = provision(pi)
    cc, rec, ok = aead_run(cc, True, None, ad579, blob579[:-16], tag=b2v(blob579[-16:]))
    chk("set-nonce decryption of Count=579", (rec, ok), (pt579, True))
    pi_s = build_pi(1, [(SKID_A, 64), (NN, 128)], policy=0b11, key_type=1)
    cc = provision(pi_s, SKS)
    cc, ct, tag = aead_run(cc, False, None, ad579, pt579)
    chk("PI with a SKID: MDH @ SKID @ nonce (320 -> 384 bits), nonce at bit 192: Count=579",
        (len(pi_s), ct + tag), (48, blob579))
    cc = provision(pi)
    cc.setst('Hash_Absorb', 'C', INPUT=NN, KLLEN=128)
    chk("Form C kl.setst into _Hash_Absorb_ (\"must be of Form A\") -> Invalid", cc.st, 'Invalid')
    long_pt = bytes((i * 13 + 5) & 0xff for i in range(40 * 16 + 3))
    cc = provision(pi)
    cc, ct, tag = aead_run(cc, False, None, ad579, long_pt, pt_chunk=7)
    chk("no block budget any more: 40 blocks + 3 bytes complete and match the reference",
        (ct + tag, cc.st), (ref_aead_encrypt(KAT_KEY, KAT_NONCE, ad579, long_pt), 'Success'))
    cc = provision(pi)
    cc, ct, tag = aead_run(cc, False, None, ad579, pt579)
    cc.setst('Ready')
    st_r = cc.st
    cc, ct2, tag2 = aead_run(cc, False, None, ad579, pt579)
    chk("SGR8: _Success_ -> _Ready_ is no longer forbidden; the restart reuses the PI nonce (the "
        "NOTE: the Machine protects the nonce's confidentiality, not against its reuse)",
        (st_r, ct2 + tag2), ('Ready', ct + tag))
    cc = provision(pi)
    cc, ct, tag = aead_run(cc, False, None, ad579, pt579, after=migrate(KleeAsconAEAD128Nonce))
    chk("migrated after every instruction (Content1 as for Ascon-AEAD128): Count=579",
        ct + tag, blob579)
    note("<<KLEE-Ascon-AEAD128-wsn>> initializes state[3..4] from `nonce` in State _Ready_, but "
         "`nonce` is in neither its Internal State nor its Serialized Content (\"Same as for "
         "Ascon-AEAD128\"); with the prohibition of the return to _Ready_ removed, re-entering "
         "_Ready_ needs it. The model keeps the PI nonce; after an import it is unknown")
    try:
        cc.setst('Ready')
        got = 'State _Ready_ re-entered'
    except SpecGap:
        got = 'no nonce to reinstall'
    chk("demonstration: an imported set-nonce CL in _Success_ cannot re-enter _Ready_",
        got, 'no nonce to reinstall')

    # ------------------------------------------------------------------ nonce masking
    head("<<KLEE-Ascon-AEAD128-N-masking>>: key = K1, nonce N replaced by N xor K2")
    pi = build_pi(2, [(K, 128), (0, 128)], policy=0b11)
    chk("PI = MDH @ K1 @ K2: 384 bits", len(pi), 48)
    for count, ad, pt, ctt, desc in AEAD_KAT:
        cc = provision(pi)
        cc, ct, tag = aead_run(cc, False, KAT_NONCE, h(ad), h(pt))
        chk(f"masked  K2=0  Count={count:<4} reproduces the official KAT", (ct + tag).hex(), ctt)
    pi = build_pi(2, [(K1v, 128), (K2v, 128)], policy=0b11)
    for count, ad, pt, _c, desc in AEAD_KAT[:6]:
        ref = ref_aead_encrypt(K1, Nm, h(ad), h(pt))
        cc = provision(pi)
        cc, ct, tag = aead_run(cc, False, KAT_NONCE, h(ad), h(pt))
        chk(f"masked  Count={count:<4} == ref(key=K1, nonce=N xor K2) (SP 800-232 eq. (52))",
            ct + tag, ref)
        unmasked, utag, _ = kl_encrypt(K1, KAT_NONCE, h(ad), h(pt))
        chk(f"masked  Count={count:<4} differs from the unmasked nonce N",
            (ct + tag) != (unmasked + utag), True)
        cc = provision(pi)
        cc, rec, ok = aead_run(cc, True, KAT_NONCE, h(ad), ct, tag=b2v(tag))
        chk(f"masked  Count={count:<4} decryption recovers the plaintext (eq. (53))",
            (rec.hex(), ok, cc.st), (pt, True, 'Success'))
        cc = provision(pi)
        cc, ct2, tag2 = aead_run(cc, False, KAT_NONCE, h(ad), h(pt),
                                 after=migrate(KleeAsconAEAD128NonceMask))
        chk(f"masked  Count={count:<4} migrated after every instruction", ct2 + tag2, ref)
    img = aead_to_mask = provision(pi)
    aead_to_mask.setst('Hash_Absorb', 'C', INPUT=NN, KLLEN=128)
    aead_to_mask.setst('Encrypt', 'A')
    aead_to_mask.setst('Enc_Last_Block', 'B', Xs=40)
    img = aead_to_mask.export()
    c1 = b2v(img['content1'])
    chk("Content1: K1 (i), K2 (ii), state[0..4] (iii-vii), last_blk_len (viii), tag_len (ix); "
        "608 bits padded to 80 bytes", (len(img['content1']), sl(c1, 127, 0), sl(c1, 255, 128),
                                        sl(c1, 591, 576), sl(c1, 607, 592)),
        (80, K1v, K2v, 40, 128))
    pi_s = build_pi(2, [(SKID_M, 64)], policy=0b11, key_type=1)
    cc = provision(pi_s, SKS)
    c1 = b2v(cc.export()['content1'])
    chk("with a SKID: PI = MDH @ SKID (192 -> 256 bits); Content1 = SKID @ state @ lengths, "
        "416 bits -> 64 bytes, state[0] at bit 64", (len(pi_s), len(cc.export()['content1']),
                                                     sl(c1, 63, 0), sl(c1, 127, 64)),
        (32, 64, SKID_M, cc.s[0]))
    cc, ct, tag = aead_run(cc, False, KAT_NONCE, ad579, pt579,
                           after=migrate(KleeAsconAEAD128NonceMask, SKS))
    chk("SKID-keyed (AGR9: one SKID yields K1 and K2), migrated after every instruction",
        ct + tag, ref_aead_encrypt(K1, Nm, ad579, pt579))
    note("the key field of <<KLEE-Ascon-AEAD128>>'s Serialized Content is \"128 or 64 (padded to "
         "128)\", that of <<KLEE-Ascon-AEAD128-N-masking>> (as of every other Machine) \"128 or 64\": "
         "with a SKID, state[0] sits at bit 128 in one layout and at bit 64 in the other")
    cc = provision(build_pi(1, [(K1v, 128), (b2v(Nm), 128)], policy=0b11))
    cc, ct, tag = aead_run(cc, False, None, h("3031"), LAST5)
    cc2 = provision(pi)
    cc2, ct2, tag2 = aead_run(cc2, False, KAT_NONCE, h("3031"), LAST5)
    chk("masking + set nonce: the set-nonce Machine with key K1 and PI nonce N xor K2 == the "
        "masking Machine given N", (ct, tag), (ct2, tag2))
    cc2.setst('Ready')
    cc2, ct3, tag3 = aead_run(cc2, False, KAT_NONCE, h("3031"), LAST5)
    chk("SGR8 on the masking Machine: _Success_ -> _Ready_ -> same result", (ct3, tag3), (ct2, tag2))
    print("KAT-EXPECT-FAIL: legacy N-masking layout")
    cc = provision(pi)
    cc.legacy_layout = True
    try:
        cc, ct, tag = aead_run(cc, False, KAT_NONCE, ad579, pt579,
                               after=migrate(KleeAsconAEAD128NonceMask, legacy_layout=True))
        got = ct + tag
    except Invalid:
        got = b'Invalid'
    chk_fails("legacy N-masking layout (no last_blk_len, as before the fix) migrated through "
              "_Enc_Last_Block_ must differ from the reference",
              got, ref_aead_encrypt(K1, Nm, ad579, pt579))

    # ------------------------------------------------------------------ Hash256
    head("<<KLEE-Ascon-Hash256>>")
    pi = build_pi(3, [])
    cc = provision(pi)
    chk("PI = MDH only (128 bits); State _Ready_ holds SP 800-232 Table 12",
        (len(pi), cc.st, tuple(cc.s)), (16, 'Ready', TABLE12['Ascon-Hash256']))
    for count, msg, md in HASH_KAT:
        got, cc = kl_hash256(h(msg), squeeze=(256,))
        chk(f"Hash256  Count={count:<4} (one squeeze, KLLEN=256)", (got.hex(), cc.st), (md, 'Success'))
    print("  squeeze splitting: 4x64, 2x128, 192+192, 64+256, 128+64+64 all agree")
    for count, msg, md in HASH_KAT:
        got = [kl_hash256(h(msg), squeeze=s)[0].hex()
               for s in ((64,), (128,), (192,), (64, 256), (128, 64, 64))]
        chk(f"Hash256  Count={count:<4} every split == KAT", got, [md] * 5)
    print("  multi-word absorb (AGR3, KLLEN = 192)")
    for count, msg, md in HASH_KAT:
        chk(f"Hash256  Count={count:<4} KLLEN=192 absorb",
            kl_hash256(h(msg), absorb_chunk=3)[0].hex(), md)
    md = h(HASH_KAT[0][2])
    cc = sponge_at_finalize(KleeAsconHash256, b'')
    trace = [cc.countdown]
    while cc.st == 'Hash_Finalize':
        cc.exec('C', 0, 64)
        trace.append(cc.countdown)
    chk("countdown (bits [1:0] of _MachineUse_): 3 on entry, then 2, 1, 0, and _Success_ "
        "on the fourth word", (trace, sl(cc.machine_use, 1, 0), cc.st), ([3, 2, 1, 0, 0], 0, 'Success'))
    o = cc.exec('C', 0, 64, out=M64)
    chk("a fifth kl.exec, in _Success_ (not a XOF: <<KLEE-SGR-success-failure>>) -> Invalid, "
        "output zeroed", (cc.st, o), ('Invalid', 0))
    cc = sponge_at_finalize(KleeAsconHash256, b'')
    o1 = cc.exec('C', 0, 192, out=(1 << 192) - 1)
    o2 = cc.exec('C', 0, 192, out=(1 << 192) - 1)
    chk("KLLEN=192 twice: 3 words, then the 4th with OUTPUT[191:64] cleared (\"the unwritten bits "
        "are cleared\")", (v2b(o1, 24), v2b(sl(o2, 63, 0), 8), sl(o2, 191, 64), cc.st),
        (md[:24], md[24:], 0, 'Success'))
    cc = sponge_at_finalize(KleeAsconHash256, b'')
    cc.exec('C', 0, 64)
    o = cc.exec('C', 0, 256, out=(1 << 256) - 1)
    chk("KLLEN=64 then 256: words 2-4 restart at OUTPUT[63:0], OUTPUT[255:192] cleared",
        (v2b(sl(o, 191, 0), 24), sl(o, 255, 192), cc.st), (md[8:], 0, 'Success'))
    for halt in (1, 3):
        cc = sponge_at_finalize(KleeAsconHash256, b'')
        o = cc.exec('C', 0, 256, halt_after=halt)
        ks, cd = cc.klstart, cc.countdown
        o = cc.exec('C', 0, 256, out=o)
        chk(f"KLLEN=256 squeeze halted after {halt} word(s) (klstart = {8 * halt}, countdown = "
            f"{3 - halt}) and resumed == KAT", (ks, cd, v2b(o, 32), cc.st),
            (8 * halt, 3 - halt, md, 'Success'))
    cc = KleeAsconHash256()
    cc.exec('B', b2v(b'\x01' + bytes(7)), 64)
    chk("<<KLEE-SGR-no-exec-in-ready>>: Form B kl.exec in _Ready_ -> Invalid", cc.st, 'Invalid')
    for label, KLLEN, form, fin in (("Form B, KLLEN = 56, in _Hash_Absorb_", 56, 'B', False),
                                    ("Form C, KLLEN = 104, in _Hash_Finalize_", 104, 'C', True),
                                    ("Form B in _Hash_Finalize_", 64, 'B', True),
                                    ("Form A in _Hash_Absorb_", 64, 'A', False)):
        cc = sponge_at_finalize(KleeAsconHash256, b'') if fin else KleeAsconHash256()
        if not fin:
            cc.setst('Hash_Absorb', 'A')
        cc.exec(form, 0, KLLEN)
        chk(f"AGR1/AGR2: {label} -> Invalid", cc.st, 'Invalid')
    cc = sponge_at_finalize(KleeAsconHash256, b'')
    kl_restricth(cc, 0x0003)
    chk("kl.restricth rewriting the countdown in _MachineUse_ -> Invalid "
        "(<<KLEE-instruction-restrict>>)", cc.st, 'Invalid')
    cc = KleeAsconHash256()
    kl_restrictl(cc, 0b01)
    chk("kl.restrictl on _MachinePolicy_, which Ascon-Hash256 does not use -> Invalid",
        cc.st, 'Invalid')
    for count, msg, md_hex in HASH_KAT:
        got, cc = kl_hash256(h(msg), after=migrate(KleeAsconHash256))
        chk(f"Hash256  Count={count:<4} migrated after every instruction (countdown carried in "
            f"_MachineUse_)", (got.hex(), cc.st), (md_hex, 'Success'))

    # ------------------------------------------------------------------ XOF128
    head("<<KLEE-Ascon-XOF128>>")
    cc = provision(build_pi(4, []))
    chk("State _Ready_ holds SP 800-232 Table 12", (cc.st, tuple(cc.s)),
        ('Ready', TABLE12['Ascon-XOF128']))
    info("the multi-word squeeze of Ascon-Hash256 (\"executed KLLEN/64 times\") is taken to be "
         "inherited, with AGR3 extending its list of output positions beyond OUTPUT[255:192]")
    for count, msg, md in XOF_KAT:
        got = [kl_xof(KleeAsconXOF128, h(msg), 64, squeeze=s)[0].hex()
               for s in ((64,), (256,), (512,), (128, 64, 192, 128))]
        chk(f"XOF128   Count={count:<4} 8x64 == 2x256 == 1x512 == 128+64+192+128 == KAT",
            got, [md] * 4)
    for count, msg, md in XOF_KAT[:3]:
        chk(f"XOF128   Count={count:<4} first 256 bits are a prefix of the 512-bit MD",
            kl_xof(KleeAsconXOF128, h(msg), 32)[0].hex(), md[:64])
        chk(f"XOF128   Count={count:<4} 1024-bit squeeze matches the reference stream",
            kl_xof(KleeAsconXOF128, h(msg), 128, squeeze=(1024,))[0].hex(),
            ref_xof128(h(msg), 128).hex())
    cc = sponge_at_finalize(KleeAsconXOF128, b'')
    cd = [cc.countdown]
    for _ in range(20):
        cc.exec('C', 0, 64)
        cd.append(cc.countdown)
    chk("countdown: 1 on entering _Hash_Finalize_, 0 from the first word on; never _Success_",
        (cd[:3], set(cd[1:]), cc.st), ([1, 0, 0], {0}, 'Hash_Finalize'))
    cc = sponge_at_finalize(KleeAsconXOF128, b'')
    s_before = list(cc.s)
    cc.klstart = 3
    o = cc.exec('C', 0, 64, out=0x1234)
    chk("klstart = 3 on an output-only operand: no operation (State, countdown, state, output "
        "unchanged)", (cc.st, cc.countdown, cc.s, o), ('Hash_Finalize', 1, s_before, 0x1234))
    for count, msg, md in XOF_KAT:
        got, cc = kl_xof(KleeAsconXOF128, h(msg), 64, after=migrate(KleeAsconXOF128))
        chk(f"XOF128   Count={count:<4} migrated after every instruction", got.hex(), md)
    note("<<KLEE-Ascon-XOF128>> says \"in State _Hash_Output_/_Hash_Finalize_\"; the Machine has no "
         "State _Hash_Output_")
    print("KAT-EXPECT-FAIL: XOF resumed without its countdown")

    def lose_countdown(cc):
        img = cc.export()
        if img['state'] == STATE['Hash_Finalize']:
            img = dict(img, machine_use=0)
        return KleeAsconXOF128.import_(img)
    got, _ = kl_xof(KleeAsconXOF128, h(XOF_KAT[2][1]), 64, after=lose_countdown)
    chk_fails("XOF resumed without its countdown (_MachineUse_ cleared) must differ from the KAT",
              got.hex(), XOF_KAT[2][2])

    # ------------------------------------------------------------------ CXOF128
    head("<<KLEE-Ascon-CXOF128>>")
    cc = provision(build_pi(5, []))
    chk("State _Ready_ holds SP 800-232 Table 12", (cc.st, tuple(cc.s)),
        ('Ready', TABLE12['Ascon-CXOF128']))
    for count, msg, z, md in CXOF_KAT:
        got, cc = kl_xof(KleeAsconCXOF128, h(msg), 64, prefix=cxof_prefix(h(z)))
        chk(f"CXOF128  Count={count:<4} caller-prepended customization string", got.hex(), md)
        got, _ = kl_xof(KleeAsconCXOF128, h(msg), 64, prefix=cxof_prefix(h(z)), squeeze=(512,),
                        after=migrate(KleeAsconCXOF128))
        chk(f"CXOF128  Count={count:<4} one 512-bit squeeze, migrated after every instruction",
            got.hex(), md)
    chk("CXOF128 with an empty Z differs from XOF128 on the same message (IV differs)",
        kl_xof(KleeAsconCXOF128, b"abc", 32, prefix=cxof_prefix(b""))[0]
        != kl_xof(KleeAsconXOF128, b"abc", 32)[0], True)
    note("<<KLEE-Ascon-CXOF128>> leaves \"the management and padding of the customization string\" "
         "to the caller; SP 800-232 Sec. 5.3 prefixes Z0 = int64(|Z|) to pad(Z, 64) and bounds |Z| "
         "by 2048 bits, neither of which the text mentions")
    for count, msg, z, md in CXOF_KAT:
        if not h(z):
            continue
        pre = h(z) + b'\x01' + bytes((-len(h(z)) - 1) % 8)      # no int64(|Z|) block
        got, _ = kl_xof(KleeAsconCXOF128, h(msg), 64, prefix=pre)
        chk(f"CXOF128  Count={count:<4} literal KLEE reading (prefix pad(Z,64) only) does NOT "
            f"match the KAT -- spec gap", got.hex() != md, True)

    # ------------------------------------------------------------------ derive
    head("<<KLEE-derive-endpoints>> and <<KLEE-instruction-derive>>")
    msg = b"KLEE derive source"
    stream = ref_xof128(msg, 64)
    src = sponge_at_finalize(KleeAsconXOF128, msg)
    dst = KleeAsconAEAD128(0)
    kl_derive(dst, 1, src, 0, 16)
    chk("XOF128 output (i = 0) -> Ascon-AEAD128 `key` (j = 1) in _Ready_: the first 16 bytes",
        (src.st, dst.st, v2b(dst.key, 16), dst.s[1:3]),
        ('Hash_Finalize', 'Ready', stream[:16], [b2v(stream[:8]), b2v(stream[8:16])]))
    dst, ct, tag = aead_run(dst, False, KAT_NONCE, ad579, pt579)
    chk("... the destination then encrypts as SP 800-232 does under that key",
        ct + tag, ref_aead_encrypt(stream[:16], KAT_NONCE, ad579, pt579))
    o = src.exec('C', 0, 64)
    chk("... and the source advanced by exactly the two 8-byte blocks it produced",
        v2b(o, 8), stream[16:24])
    src = sponge_at_finalize(KleeAsconXOF128, msg)
    dst = KleeAsconAEAD128(0)
    kl_derive(dst, 1, src, 0, 24)
    o = src.exec('C', 0, 64)
    chk("length = 24 into the 16-byte key: eff_length = 16, still two source blocks",
        (v2b(dst.key, 16), v2b(o, 8)), (stream[:16], stream[16:24]))
    src = sponge_at_finalize(KleeAsconXOF128, msg)
    dst = aead_to('Hash_Absorb')
    kl_derive(dst, 1, src, 0, 16)
    o = src.exec('C', 0, 64)
    chk("destination not in _Ready_ -> destination Invalid, nothing transferred",
        (dst.st, src.st, v2b(o, 8)), ('Invalid', 'Hash_Finalize', stream[:8]))
    info("\"A field configured by a SKID is never importable\": the destination is invalidated")
    src = sponge_at_finalize(KleeAsconXOF128, msg)
    dst = KleeAsconAEAD128(K, skid=SKID_A)
    kl_derive(dst, 1, src, 0, 16)
    chk("SKID-configured key as destination -> destination Invalid", (dst.st, src.st),
        ('Invalid', 'Hash_Finalize'))
    src, dst = KleeAsconAEAD128(K), KleeAsconAEAD128(0)
    kl_derive(dst, 1, src, 1, 16)
    chk("Ascon-AEAD128 as a source (nothing exportable) -> both CLs Invalid",
        (src.st, dst.st), ('Invalid', 'Invalid'))
    src = sponge_at_finalize(KleeAsconXOF128, msg)
    dst = KleeAsconXOF128()
    dst.setst('Hash_Absorb', 'A')
    kl_derive(dst, 0, src, 0, 16)
    dst.exec('B', b2v(b'\x01' + bytes(7)), 64)
    dst.setst('Hash_Finalize', 'A')
    o = dst.exec('C', 0, 128)
    chk("XOF128 output (i = 0) -> XOF128 _Hash_Absorb_ (j = 0), continued with kl.exec: "
        "== XOF128(those 16 bytes)", v2b(o, 16), ref_xof128(stream[:16], 16))
    info("a transfer into an Ascon _Hash_Absorb_ must respect its 64-bit granularity: a final "
         "block shorter than 8 bytes is refused (check 3 of <<KLEE-instruction-derive>>)")
    src = sponge_at_finalize(KleeAsconXOF128, msg)
    dst = KleeAsconXOF128()
    dst.setst('Hash_Absorb', 'A')
    kl_derive(dst, 0, src, 0, 12)
    o = src.exec('C', 0, 64)
    chk("12 bytes into an Ascon absorb State -> destination Invalid, nothing transferred",
        (dst.st, src.st, v2b(o, 8)), ('Invalid', 'Hash_Finalize', stream[:8]))
    note("<<KLEE-derive-endpoints>> lists neither Ascon-Hash256 (the SHA-2 row suggests an "
         "oversight) nor the set-nonce and nonce-masking Machines (the latter has K1/K2, no `key`); "
         "their endpoints are not exercised")

    # ------------------------------------------------------------------ negative control
    head("Negative control: domain separation applied to the WRONG word")
    print("  (spec: `state[4] <- state[4] xor (1 << 63)` on entering _Encrypt_;")
    print("   the control instead xors the MSB of state[0] and must NOT match)")
    print("KAT-EXPECT-FAIL: dsep on state[0]")
    for count, ad, pt, ctt, _ in AEAD_KAT[:4]:
        ct, tag, _ = kl_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt), dsep_wrong_word=True)
        chk_fails(f"dsep on state[0]  Count={count:<4} must differ from the KAT",
                  (ct + tag).hex(), ctt)

    print(f"\n{_n} checks executed")
    print("KAT-RESULT:", "PASS" if _ok else "FAIL")
    return 0 if _ok else 1

if __name__ == "__main__":
    sys.exit(main())
