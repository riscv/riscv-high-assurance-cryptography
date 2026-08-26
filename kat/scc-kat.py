#!/usr/bin/env python3
"""Sealed Cryptographic Context (SCC) known-answer tests.

Validates the sealing construction of the draft ACE specification —
<<ACE-SCC-AEAD>>, <<ACE-SCC-RFC8452-derivation>>, <<ACE-SCC-POLYVAL>>,
<<ACE-SCC-GCM-SIV-enc>>, <<ACE-SCC-GCM-SIV-dec>>, <<ACE-SCC-export>>,
<<ACE-SCC-import>> and the format tables of <<ACE-data-formats>> /
<<ACE-length-rule>> (src/ace-ISA-unpriv.adoc) — transcribed literally onto
ACE values (little-endian; common.py conventions).

ANCHOR LEVEL — stated honestly, because it is not uniform:

  * AESE256                  STANDARD-ANCHORED.  FIPS 197 C.3, via the
                             common.py self-test.
  * Montmul / POLYVAL        STANDARD-ANCHORED.  RFC 8452 Appendix A
                             worked example (H, X_1, X_2 -> result), and
                             mulX_POLYVAL, re-checked here directly on the
                             spec's POLYVAL() function.
  * RFC8452_KeyDeriv         STANDARD-ANCHORED.  RFC 8452 Appendix C.2
                             "Record authentication key" / "Record
                             encryption key" intermediates.  The spec's
                             function is the RFC's derivation for 256-bit
                             keys, so this is a genuine standard vector,
                             not a self-check.
  * SCC_Encrypt/SCC_Decrypt  SELF-CONSISTENT ONLY.  The construction is a
    and the export/import    deliberate variant of AES-GCM-SIV — no nonce
    procedures               (zeros(96)) and no length block
                             (<<ACE-SCC-AEAD>> changes 1 and 2) — so no
                             published vector applies.  What is tested is
                             the set of structural properties the
                             architecture relies on: round-tripping,
                             rejection of every kind of tampering,
                             Locality binding, segment binding through
                             SIV, and the Error-State format.  Regression
                             vectors for the variant are printed at the
                             end so that a future change of the
                             construction is visible in a diff.

Vectors embedded offline, with provenance:
  * FIPS 197 Appendix C.3 (via common.selftest).
  * RFC 8452 Appendix A worked example and Appendix C.2 vector #2
    intermediates, transcribed from https://www.rfc-editor.org/rfc/rfc8452.txt
    (April 2019).
  * Synthetic CSK / LST / MDH / Content, defined in this file.

Negative control (KAT-EXPECT-FAIL): restoring the RFC 8452 length block
must change the SIV; if it did not, the deliberate omission would be
unobservable and the deviation untestable.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bin_, bswap, montmul, mulx_polyval,
                    aes_encrypt, MASK128, selftest)

M32 = (1 << 32) - 1


# ======================================================================
# <<ACE-SCC-AEAD>>: the primitive functions, transcribed literally
# ======================================================================

def AESE256(K: int, B: int) -> int:
    """AES-256 encryption of the 128-bit block B under the 256-bit key K,
    both as ACE values."""
    return b2v(aes_encrypt(v2b(K, 32), v2b(B, 16)))


def RFC8452_KeyDeriv(key: int, nonce: int):
    """<<ACE-SCC-RFC8452-derivation>>.

    A[i] <- AESE256(key, nonce @ bin(i,32))
    enc_key  = A[5][63:0] @ A[4][63:0] @ A[3][63:0] @ A[2][63:0]
    auth_key = A[1][63:0] @ A[0][63:0]
    """
    A = [AESE256(key, cat((nonce, 96), (bin_(i, 32), 32))) for i in range(6)]
    enc_key = cat((sl(A[5], 63, 0), 64), (sl(A[4], 63, 0), 64),
                  (sl(A[3], 63, 0), 64), (sl(A[2], 63, 0), 64))
    auth_key = cat((sl(A[1], 63, 0), 64), (sl(A[0], 63, 0), 64))
    return enc_key, auth_key


def POLYVAL(auth_key: int, blocks) -> int:
    """<<ACE-SCC-POLYVAL>>: tmp <- Montmul(tmp xor blocks[i], auth_key)."""
    tmp = 0
    for blk in blocks:
        tmp ^= blk
        tmp = montmul(tmp, auth_key)
    return tmp


def SCC_Encrypt(AD, N: int, P, K: int, length_block=None):
    """<<ACE-SCC-GCM-SIV-enc>>.

    length_block is not part of the spec: passing one restores the RFC 8452
    block that <<ACE-SCC-AEAD>> deliberately omits, and exists only to drive
    the negative control.
    """
    enc_key, auth_key = RFC8452_KeyDeriv(K, N)
    blocks = list(AD) + list(P) + ([] if length_block is None else [length_block])
    SIV = POLYVAL(auth_key, blocks)
    SIV = (SIV & ~((1 << 96) - 1)) | (sl(SIV, 95, 0) ^ N)   # SIV[95:0] ^= N
    SIV = AESE256(enc_key, cat((0, 1), (sl(SIV, 126, 0), 127)))
    C = [P[i] ^ AESE256(enc_key,
                        cat((1, 1), (sl(SIV, 126, 32), 95),
                            ((sl(SIV, 31, 0) + i) & M32, 32)))
         for i in range(len(P))]
    return SIV, C


def SCC_Decrypt(AD, N: int, SIV: int, C, K: int, length_block=None):
    """<<ACE-SCC-GCM-SIV-dec>>."""
    enc_key, auth_key = RFC8452_KeyDeriv(K, N)
    P = [C[i] ^ AESE256(enc_key,
                        cat((1, 1), (sl(SIV, 126, 32), 95),
                            ((sl(SIV, 31, 0) + i) & M32, 32)))
         for i in range(len(C))]
    blocks = list(AD) + list(P) + ([] if length_block is None else [length_block])
    tmp = POLYVAL(auth_key, blocks)
    tmp = (tmp & ~((1 << 96) - 1)) | (sl(tmp, 95, 0) ^ N)
    tmp = AESE256(enc_key, cat((0, 1), (sl(tmp, 126, 0), 127)))
    if tmp != SIV:
        return False, [0] * len(C)
    return True, P


# ======================================================================
# MDH helpers (<<ACE-metadata-header>>, <<ACE-locality-indexes>>)
# ======================================================================

# _Locality_ occupies MDH[77:69]; within that 9-bit field the architected
# Localities are encoded as (bit span within the field, value):
LOCALITY_ENC = {
    0: ((1, 0), 1), 1: ((1, 0), 2), 2: ((1, 0), 3),        # HW chain 1
    3: ((3, 2), 1), 4: ((3, 2), 2), 5: ((3, 2), 3),        # HW chain 2
    6: ((5, 4), 1), 7: ((5, 4), 2),                        # Boot Session
    8: ((6, 6), 1), 9: ((7, 7), 1), 10: ((8, 8), 1),       # SW Filter
}

def locality_field(indices) -> int:
    """The 9-bit _Locality_ field selecting exactly the given Localities."""
    f = 0
    for j in sorted(indices):
        (hi, lo), val = LOCALITY_ENC[j]
        assert sl(f, hi, lo) == 0, f'Locality #{j} conflicts with an earlier one'
        f |= val << lo
    return f

def localities_of(mdh: int):
    """The Localities that MDH._Locality_ includes, in index order 0..10 —
    the order in which <<ACE-SCC-export>> step 1.c appends them to AD."""
    f = sl(mdh, 77, 69)
    out = []
    for j in range(11):
        (hi, lo), val = LOCALITY_ENC[j]
        if sl(f, hi, lo) == val:
            out.append(j)
    return out

def make_mdh(algorithm=0x101, key_type=0, state=1, config_status=3,
             imp_data_len=0, localities=(), usage_policy=0):
    """Assemble a plausible MDH from the fields this harness needs."""
    return (bin_(algorithm, 12)
            | (1 << 12)                                  # AlgorithmPolicy: enc
            | (bin_(key_type, 2) << 19)
            | (bin_(state, 5) << 21)
            | (bin_(config_status, 2) << 30)             # ace_cfgst_complete
            | (bin_(imp_data_len, 14) << 32)
            | (bin_(usage_policy, 5) << 64)
            | (locality_field(localities) << 69))


# ======================================================================
# <<ACE-SCC-export>> / <<ACE-SCC-import>>
# ======================================================================

def _ad_segment1(saved_MDH: int, LST: dict):
    """AD[0] <- saved_MDH; then LST[j] for every Locality in the MDH."""
    AD = [saved_MDH]
    for j in localities_of(saved_MDH):
        AD.append(LST[j])
    return AD


def scc_export(saved_MDH: int, content1, CSK: int, LST: dict,
               IMPQUAL=None, content2=(), length_block=None) -> bytes:
    """<<ACE-SCC-export>>, returning the serialized SCC of
    <<ACE-data-formats>>: MDH || SIV || Content1_CT
    [ || IMPQUAL || SIV2 || Content2_CT ].

    _ImpDataLen_ counts the whole variable-length section (IMPQUAL, SIV2 and
    Content2) in 128-bit units, so it is 2 + len(content2) when present.
    The caller is responsible for having set it in saved_MDH, since
    saved_MDH is authenticated as AD[0] exactly as it appears in the SCC.
    """
    AD = _ad_segment1(saved_MDH, LST)
    SIV, C1 = SCC_Encrypt(AD, 0, list(content1), CSK, length_block)
    out = v2b(saved_MDH, 16) + v2b(SIV, 16)
    out += b''.join(v2b(c, 16) for c in C1)
    if sl(saved_MDH, 45, 32) != 0:
        assert IMPQUAL is not None
        AD2 = [IMPQUAL, SIV]                       # len_AD2 = 2
        SIV2, C2 = SCC_Encrypt(AD2, 0, list(content2), CSK, length_block)
        out += v2b(IMPQUAL, 16) + v2b(SIV2, 16)
        out += b''.join(v2b(c, 16) for c in C2)
    return out


def scc_export_error_state(mdh: int, CSK: int, LST: dict) -> bytes:
    """<<ACE-length-rule>> 2 and <<ACE-data-formats>>: a CR in an Error State
    exports the MDH and SIV only — Sections 3-6 empty, len_PC = 0, 32 bytes.
    _ImpDataLen_ has been set to 0 on entering the Error State."""
    assert sl(mdh, 45, 32) == 0, 'ImpDataLen is cleared on entering an Error State'
    AD = _ad_segment1(mdh, LST)
    SIV, C = SCC_Encrypt(AD, 0, [], CSK)
    assert C == []
    return v2b(mdh, 16) + v2b(SIV, 16)


def scc_import(scc: bytes, CSK: int, LST: dict, len_PC=None,
               support_vds=True, length_block=None) -> dict:
    """<<ACE-SCC-import>>.

    Returns a dict describing the resulting CR:
      {'status': 'ok' | 'ace_state_import_auth',
       'mdh', 'content1', 'imp_data_len', 'content2', 'vds_discarded'}

    len_PC is the length of Section 3 in blocks, which the real importer
    derives from _Algorithm_/_AlgorithmPolicy_/_KeyType_/_StateExtension_
    (<<ACE-length-rule>> 2); this harness is passed it directly.
    support_vds=False models step 5: the importer's maximum length for the
    Algorithm is exceeded, so the SCC length is adjusted to exclude the VDS.
    """
    M = b2v(scc[0:16])
    imp = sl(M, 45, 32)
    # Steps 1-6: determine the length and load.  An Error-State SCC has no
    # Sections 3-6 at all.
    if len(scc) == 32 and len_PC in (None, 0):
        len_PC = 0
    SIV = b2v(scc[16:32])
    body = scc[32:]
    if len_PC is None:
        raise ValueError('len_PC must be supplied')
    C1 = [b2v(body[16 * i:16 * i + 16]) for i in range(len_PC)]
    rest = body[16 * len_PC:]

    saved_MDH = M                                        # step 7
    AD = _ad_segment1(saved_MDH, LST)                    # steps 8-9
    correct, P1 = SCC_Decrypt(AD, 0, SIV, C1, CSK, length_block)
    if not correct:                                      # step 12
        return {'status': 'ace_state_import_auth', 'mdh': None,
                'content1': None, 'imp_data_len': 0, 'content2': None,
                'vds_discarded': False}

    res = {'status': 'ok', 'mdh': M, 'content1': P1,
           'imp_data_len': imp, 'content2': None, 'vds_discarded': False}
    if imp == 0:
        return res
    if not support_vds:                                  # step 5 adjustment
        res['imp_data_len'] = 0
        res['vds_discarded'] = True
        return res

    IMPQUAL = b2v(rest[0:16])
    SIV2 = b2v(rest[16:32])
    len_PC2 = imp - 2                                    # IMPQUAL + SIV2 + C2
    C2 = [b2v(rest[32 + 16 * i:48 + 16 * i]) for i in range(len_PC2)]
    AD2 = [IMPQUAL, SIV]
    correct2, P2 = SCC_Decrypt(AD2, 0, SIV2, C2, CSK, length_block)
    if not correct2:                                     # step 14
        res['imp_data_len'] = 0
        res['vds_discarded'] = True
        return res
    res['content2'] = P2
    res['impqual'] = IMPQUAL
    return res


# ======================================================================
# Anchoring vectors
# ======================================================================

# RFC 8452 Appendix A (https://www.rfc-editor.org/rfc/rfc8452.txt, April 2019):
# the POLYVAL worked example and mulX_POLYVAL.
RFC8452_A = {
    'H':  '25629347589242761d31f826ba4b757b',
    'X1': '4f4f95668c83dfb6401762bb2d01a262',
    'X2': 'd1a24ddd2721d006bbe45f20d3c9f362',
    'result': 'f7a3b47b846119fae5b7866cf5e5b77e',
    'mulx_in':  '9c98c04df9387ded828175a92ba652d8',
    'mulx_out': '3931819bf271fada0503eb52574ca572',
}

# RFC 8452 Appendix C.2 vector #2 (AEAD_AES_256_GCM_SIV): the derived-key
# intermediates.  The spec's RFC8452_KeyDeriv is exactly this derivation.
RFC8452_C2_2 = {
    'key':   '01000000000000000000000000000000'
             '00000000000000000000000000000000',
    'nonce': '030000000000000000000000',
    'auth_key': 'b5d3c529dfafac43136d2d11be284d7f',
    'enc_key':  'b914f4742be9e1d7a2f84addbf96dec3'
                '456e3c6c05ecc157cdbf0700fedad222',
}

# Synthetic material for the sealing construction (this file).
CSK = b2v(bytes(range(32)))
LST = {j: b2v(bytes([0x40 + j] * 16)) for j in range(11)}
LST_ALT = dict(LST)
LST_ALT[4] = LST[4] ^ (1 << 17)                 # Locality #4 changed; it is
                                                # selected by LOC_SETS[2]
LST_ALT_UNSEL = dict(LST)
LST_ALT_UNSEL[3] = LST[3] ^ (1 << 17)           # #3 is selected by no LOC_SET
IMPQUAL = b2v(bytes.fromhex('0badc0de00000000000000005ca1ab1e'))
CONTENT1 = [b2v(bytes([0x10 + i] * 16)) for i in range(4)]
CONTENT2 = [b2v(bytes([0xA0 + i] * 16)) for i in range(2)]

# The Locality sets exercised: none, one, and several (one per group,
# which is what <<ACE-locality-indexes>> permits concurrently).
LOC_SETS = [(), (2,), (1, 4, 6, 8, 9, 10)]


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
    print("SCC sealing construction (ACE <<ACE-SCC-export>> / <<ACE-SCC-import>>)")
    print("Anchor level: AESE256, Montmul/POLYVAL and RFC8452_KeyDeriv are")
    print("  STANDARD-ANCHORED (FIPS 197 C.3; RFC 8452 App. A; RFC 8452 App. C.2).")
    print("  The sealing construction itself is a declared RFC 8452 variant (no")
    print("  nonce, no length block) and is therefore SELF-CONSISTENT ONLY:")
    print("  structural properties are tested, and regression vectors printed.\n")

    # -- (a),(b) primitive anchors ------------------------------------
    chk(selftest(), "common.py self-test (FIPS 197 C.1-C.3, RFC 8452 App. A)")

    a = RFC8452_A
    chk(v2b(POLYVAL(b2v(bytes.fromhex(a['H'])),
                    [b2v(bytes.fromhex(a['X1'])),
                     b2v(bytes.fromhex(a['X2']))]), 16).hex() == a['result'],
        "POLYVAL()  vs RFC 8452 Appendix A worked example")
    chk(v2b(mulx_polyval(b2v(bytes.fromhex(a['mulx_in']))), 16).hex()
        == a['mulx_out'],
        "mulX_POLYVAL vs RFC 8452 Appendix A")
    chk(POLYVAL(b2v(bytes.fromhex(a['H'])), []) == 0,
        "POLYVAL() of the empty block array is zeros(128)")

    v = RFC8452_C2_2
    ek, ak = RFC8452_KeyDeriv(b2v(bytes.fromhex(v['key'])),
                              b2v(bytes.fromhex(v['nonce'])))
    chk(v2b(ak, 16).hex() == v['auth_key'],
        "RFC8452_KeyDeriv auth_key vs RFC 8452 C.2 #2 intermediate")
    chk(v2b(ek, 32).hex() == v['enc_key'],
        "RFC8452_KeyDeriv enc_key  vs RFC 8452 C.2 #2 intermediate")

    # Locality-field encoding sanity, before it is relied upon.
    for locs in LOC_SETS:
        chk(tuple(localities_of(make_mdh(localities=locs))) == tuple(sorted(locs)),
            f"MDH._Locality_ round-trips for Localities {locs or '(none)'}")

    # -- (c) export -> import round trip -------------------------------
    sccs = {}
    for locs in LOC_SETS:
        mdh = make_mdh(localities=locs)
        scc = scc_export(mdh, CONTENT1, CSK, LST)
        sccs[locs] = (mdh, scc)
        lbl = f"{len(locs)} Localit{'y' if len(locs)==1 else 'ies'} {locs or ''}"
        chk(len(scc) == 32 + 16 * len(CONTENT1),
            f"SCC length = MDH+SIV+Content1 ({lbl})")
        chk(scc[:16] == v2b(mdh, 16), f"SCC Section 1 is the plaintext MDH ({lbl})")
        chk(scc[32:] != b''.join(v2b(c, 16) for c in CONTENT1),
            f"Content1 is encrypted in the SCC ({lbl})")
        r = scc_import(scc, CSK, LST, len_PC=len(CONTENT1))
        chk(r['status'] == 'ok' and r['content1'] == CONTENT1
            and r['mdh'] == mdh,
            f"export -> import reproduces the CR and authenticates ({lbl})")

    # Different Locality sets must produce different SCCs.
    sivs = {locs: sccs[locs][1][16:32] for locs in LOC_SETS}
    chk(len(set(sivs.values())) == len(LOC_SETS),
        "distinct Locality sets give distinct SIVs")

    # -- (d) tamper detection ------------------------------------------
    locs = LOC_SETS[2]
    mdh, scc = sccs[locs]
    n = len(CONTENT1)

    def flips(region_lo, region_hi, step=7):
        """Bit positions to flip inside scc[region_lo:region_hi]."""
        return range(8 * region_lo, 8 * region_hi, step)

    def tampered(scc, bit):
        b = bytearray(scc)
        b[bit // 8] ^= 1 << (bit % 8)
        return bytes(b)

    for name, lo, hi in (('MDH', 0, 16), ('SIV', 16, 32),
                         ('a Content1 block', 32, 32 + 16 * n)):
        bad = 0
        for bit in flips(lo, hi):
            r = scc_import(tampered(scc, bit), CSK, LST, len_PC=n)
            if r['status'] == 'ok':
                bad += 1
        chk(bad == 0,
            f"every single-bit change in {name} fails authentication")

    # Cleared plaintext on failure, per <<ACE-SCC-GCM-SIV-dec>>.
    AD = _ad_segment1(mdh, LST)
    corr, P = SCC_Decrypt(AD, 0, b2v(scc[16:32]) ^ 1,
                          [b2v(scc[32 + 16 * i:48 + 16 * i]) for i in range(n)],
                          CSK)
    chk(not corr and P == [0] * n,
        "SCC_Decrypt zeroes P[] when authentication fails")

    # A changed Locality Secret table must not open the context.
    r = scc_import(scc, CSK, LST_ALT, len_PC=n)
    chk(r['status'] == 'ace_state_import_auth',
        "a changed Locality Secret table fails authentication")
    # ... but only when that Locality is actually selected: Locality #3 is in
    # no LOC_SET, so changing LST[3] must leave this SCC importable.
    chk(scc_import(scc, CSK, LST_ALT_UNSEL, len_PC=n)['status'] == 'ok',
        "an unselected Locality Secret does not affect the SCC")
    # A different CSK must not open it either.
    chk(scc_import(scc, CSK ^ 1, LST, len_PC=n)['status']
        == 'ace_state_import_auth',
        "a different CSK fails authentication")
    # An SCC sealed under one Locality set does not open under another:
    # the MDH carries the set, so this is the MDH-tamper case made explicit.
    mdh_b = make_mdh(localities=(2,))
    forged = v2b(mdh_b, 16) + scc[16:]
    chk(scc_import(forged, CSK, LST, len_PC=n)['status']
        == 'ace_state_import_auth',
        "substituting the MDH's Locality set fails authentication")

    # -- (e) the implementation-data segment ---------------------------
    imp_len = 2 + len(CONTENT2)                       # IMPQUAL + SIV2 + Content2
    mdh_i = make_mdh(localities=locs, imp_data_len=imp_len)
    scc_i = scc_export(mdh_i, CONTENT1, CSK, LST,
                       IMPQUAL=IMPQUAL, content2=CONTENT2)
    chk(len(scc_i) == 32 + 16 * n + 16 * imp_len,
        "SCC with ImpDataLen != 0 has the length of <<ACE-data-formats>>")
    r = scc_import(scc_i, CSK, LST, len_PC=n)
    chk(r['status'] == 'ok' and r['content1'] == CONTENT1
        and r['content2'] == CONTENT2 and not r['vds_discarded'],
        "both segments import and authenticate")

    # An unsupported/oversized VDS is excluded at step 5: segment 1 still
    # imports, ImpDataLen becomes 0.
    r = scc_import(scc_i, CSK, LST, len_PC=n, support_vds=False)
    chk(r['status'] == 'ok' and r['content1'] == CONTENT1
        and r['imp_data_len'] == 0 and r['vds_discarded'],
        "an unsupported VDS is excluded; segment 1 still imports")

    # Grafting: take segment 2 of SCC B onto SCC A.  AD2[1] = SIV differs,
    # so segment 2 must fail; per import step 14 the VDS is discarded but
    # segment 1 is still imported and ImpDataLen set to 0.
    CONTENT1_B = [c ^ 0xFF for c in CONTENT1]
    scc_b = scc_export(mdh_i, CONTENT1_B, CSK, LST,
                       IMPQUAL=IMPQUAL, content2=CONTENT2)
    chk(scc_i[16:32] != scc_b[16:32], "the two SCCs have different SIVs")
    graft = scc_i[:32 + 16 * n] + scc_b[32 + 16 * n:]
    r = scc_import(graft, CSK, LST, len_PC=n)
    chk(r['status'] == 'ok' and r['content1'] == CONTENT1
        and r['vds_discarded'] and r['imp_data_len'] == 0
        and r['content2'] is None,
        "a grafted segment 2 is rejected; segment 1 imports, ImpDataLen -> 0")
    # And SIV2 itself differs between the two, which is what makes the
    # graft detectable (the <<ACE-SCC-export>> IMPORTANT note).
    off = 32 + 16 * n
    chk(scc_i[off + 16:off + 32] != scc_b[off + 16:off + 32],
        "SIV2 changes when SIV changes (segment binding)")
    chk(scc_i[off + 32:] != scc_b[off + 32:],
        "the segment-2 keystream changes when SIV changes")
    # Tampering inside segment 2 discards the VDS but keeps segment 1.
    bad_vds = 0
    for bit in flips(off, len(scc_i), 23):
        r = scc_import(tampered(scc_i, bit), CSK, LST, len_PC=n)
        if not (r['status'] == 'ok' and r['content1'] == CONTENT1
                and (r['vds_discarded'] or r['content2'] == CONTENT2)):
            bad_vds += 1
        if r['status'] == 'ok' and r['content2'] == CONTENT2 \
           and bit >= 8 * (off + 16):
            bad_vds += 1              # a change in SIV2/Content2 went unnoticed
    chk(bad_vds == 0,
        "tampering in segment 2 discards the VDS and keeps segment 1")

    # -- (f) Error-State SCC -------------------------------------------
    # On entering an Error State the Content is cleared and ImpDataLen set
    # to 0; ConfigStatus is ace_cfgst_complete.  State 24 stands for an
    # Error State here; only its presence in the MDH matters.
    for locs_e in LOC_SETS:
        mdh_e = make_mdh(state=24, localities=locs_e)
        scc_e = scc_export_error_state(mdh_e, CSK, LST)
        chk(len(scc_e) == 32,
            f"Error-State SCC is exactly 32 bytes (Localities {locs_e or '(none)'})")
        r = scc_import(scc_e, CSK, LST, len_PC=0)
        chk(r['status'] == 'ok' and r['content1'] == []
            and r['mdh'] == mdh_e and r['imp_data_len'] == 0,
            f"Error-State SCC round-trips (Localities {locs_e or '(none)'})")
        bad = 0
        for bit in flips(0, 32, 5):
            if scc_import(tampered(scc_e, bit), CSK, LST,
                          len_PC=0)['status'] == 'ok':
                bad += 1
        chk(bad == 0, f"Error-State SCC rejects any single-bit change "
                      f"(Localities {locs_e or '(none)'})")

    # Determinism: the construction has no nonce, so sealing twice must give
    # the identical SCC (this is the property the 2^64-block bound rests on).
    chk(scc_export(mdh, CONTENT1, CSK, LST) == scc,
        "sealing is deterministic (no nonce, <<ACE-SCC-AEAD>> change 2)")

    # -- negative control ---------------------------------------------
    print("\nKAT-EXPECT-FAIL: length-block")
    lb = cat((bin_(16 * len(CONTENT1) * 8, 64), 64),
             (bin_(16 * len(_ad_segment1(mdh, LST)) * 8, 64), 64))
    scc_lb = scc_export(mdh, CONTENT1, CSK, LST, length_block=lb)
    fired = scc_lb[16:32] != scc[16:32]
    print(f"{'FAIL (expected)' if fired else 'PASS'}  "
          f"length-block restoring the RFC 8452 length block changes the SIV")
    chk(fired, "negative control fired: the length-block omission is observable")
    chk(scc_import(scc_lb, CSK, LST, len_PC=n)['status']
        == 'ace_state_import_auth',
        "an SCC sealed with a length block does not import under the spec rule")

    # -- regression vectors for the variant ----------------------------
    print("\nRegression vectors for the ACE sealing variant "
          "(CSK = 000102..1f, LST[j] = 16 x (0x40+j)):")
    for locs_v in LOC_SETS:
        mdh_v, scc_v = sccs[locs_v]
        print(f"  Localities {str(tuple(locs_v)):<18} MDH  = {v2b(mdh_v,16).hex()}")
        print(f"  {'':29} SIV  = {scc_v[16:32].hex()}")
        print(f"  {'':29} C1[0]= {scc_v[32:48].hex()}")
    print(f"  ImpDataLen={imp_len}, Localities {tuple(locs)}:")
    print(f"  {'':29} SIV2 = {scc_i[off+16:off+32].hex()}")
    print(f"  {'':29} C2[0]= {scc_i[off+32:off+48].hex()}")
    mdh_e = make_mdh(state=24, localities=LOC_SETS[2])
    print(f"  Error-State SCC (32 B)        "
          f"= {scc_export_error_state(mdh_e, CSK, LST).hex()}")

    print("\nSPEC-NOTE: the sealing construction has no external vectors by "
          "design (<<ACE-SCC-AEAD>> omits both the nonce and the length "
          "block); only its component functions are standard-anchored.")
    print("SPEC-NOTE: segment 1 and segment 2 are authenticated under the same "
          "derived keys, separated only by the shape of their AD "
          "(review finding m18); no domain-separation constant is present.")

    print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
