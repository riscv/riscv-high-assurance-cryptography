#!/usr/bin/env python3
"""Sealed Cryptographic Context (SCC) known-answer tests.

Validates the sealing construction and the SCC export/import procedures of the
draft KLEE specification (src/Zkl-ISA-unpriv.adoc) -- <<KLEE-SCC-AEAD>>,
<<KLEE-SCC-key-derivation>>, <<KLEE-SCC-POLYVAL>>, <<KLEE-SCC-GCM-SIV-enc>>,
<<KLEE-SCC-GCM-SIV-dec>>, <<KLEE-SCC-export>>, <<KLEE-SCC-import>>, the MDH of
<<KLEE-metadata-header>> with the _AuxDataLen_ / _ADSDropped_ rules of
<<KLEE-Auxiliary-Data-Section>>, the formats of <<KLEE-data-formats>> and
<<KLEE-SCC>>, the length rule of <<KLEE-length-rule>> with the image layout of
<<KLEE-instruction-mv>> and <<KLEE-instruction-size>>, and the Error-State
transfer of <<KLEE-error-state-transfer>> -- transcribed literally onto KLEE
values (little-endian; common.py conventions).

ANCHOR LEVEL -- stated honestly, because it is not uniform:

  * AESE256                  STANDARD-ANCHORED.  FIPS 197 C.3, via the
                             common.py self-test.
  * Montmul / POLYVAL        STANDARD-ANCHORED.  RFC 8452 Appendix A worked
                             example (H, X_1, X_2 -> result) and mulX_POLYVAL,
                             re-checked here directly on the spec's POLYVAL().
  * SCC_KeyDeriv             STANDARD-ANCHORED.  RFC 8452 Appendix C.2 #2
                             "Record authentication key" / "Record encryption
                             key" intermediates: the spec's function (listing
                             "RFC8452 Key Derivation") is the RFC's derivation
                             for 256-bit keys.
  * SCC_Encrypt/SCC_Decrypt  PARTIALLY STANDARD-ANCHORED.  The construction is
                             a deliberate variant of AES-256-GCM-SIV: no length
                             block, the nonce zeros(96), a segment selector
                             `sep` in bit 126 of both AES inputs, and, for
                             sep = 0, _ADSDropped_ (bit 47) cleared in a local
                             copy of AD[0].  With the RFC 8452 length block
                             restored (a harness-only argument) the functions
                             must reproduce RFC 8452 C.2 / C.3: every tag when
                             `sep` equals the RFC's own bit 126 of the tag
                             input, every plaintext through the counter blocks
                             when `sep` equals bit 126 of the tag (C.3 wraps
                             the counter mod 2^32), and the whole record where
                             the two bits coincide.  This anchors the POLYVAL
                             chain over AD || P, the nonce xor and both AES
                             input formats, up to the one bit that `sep`
                             replaces.
  * Export / import          SELF-CONSISTENT ONLY.  No published vector
    procedures, formats      applies.  What is tested is the set of structural
                             properties the architecture relies on: round
                             trips, rejection of every kind of tampering,
                             Locality binding and substitution, the
                             implementation qualifier, the ADS rules including
                             _ADSDropped_ as an unauthenticated format hint,
                             the SCC-shaped PCCC, the length rule, and the
                             Error-State transfer.  Regression vectors are
                             embedded and checked, so that a change of the
                             construction, of the MDH layout or of the SCC
                             layout is visible.

Vectors embedded offline, with provenance:
  * FIPS 197 Appendix C.3 (via common.selftest).
  * RFC 8452 Appendix A worked example; Appendix C.2 #1, #2, #6, #15, #24 and
    C.3 #1, #2 (AEAD_AES_256_GCM_SIV, with the C.2 #2 intermediates),
    transcribed from https://www.rfc-editor.org/rfc/rfc8452.txt (April 2019);
    gcmsiv-kat.py checks the same transcription against an independent
    RFC 8452 implementation.
  * Synthetic CSK, Locality Secrets, implementation identifiers, MDHs and
    Contents, defined in this file.

Model (choices the specification leaves to the implementation):
  * The KLEE unit implements one Machine, AES256_ECB (Type 2, Mode 0 of
    <<KLEE-exec-encodings>>), whose Content1 is the 256-bit key or a 64-bit
    SKID padded to a block (<<KLEE-ECB-mode>>), with side-channel protection
    levels 0-2, MDH _Version_ 0, Zklexpire, and an ADS of up to 16 blocks.
  * Memory beyond a stored image reads as zeros.  Each transfer is performed
    by one uninterrupted kl.load or kl.store (klstart = 0).
  * PI-shaped images and SKID resolution (_KeyType_ = 1) are not modelled.

Negative controls (KAT-EXPECT-FAIL):
  * length-block: restoring the RFC 8452 length block must change the SIV;
    otherwise the deliberate omission would be unobservable.
  * no-ads-clear: a first-segment authentication that does not clear
    _ADSDropped_ in its copy of AD[0] must reject the SCC-shaped PCCC of an
    import whose ADS was dropped; otherwise the clearing would be untested.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bin_, montmul, mulx_polyval,
                    aes_encrypt, aes_decrypt, MASK128, selftest)

M32 = (1 << 32) - 1


# ======================================================================
# <<KLEE-SCC-AEAD>>: the primitive functions, transcribed literally
# ======================================================================

def AESE256(K: int, B: int) -> int:
    """AES-256 encryption of the 128-bit block B under the 256-bit key K,
    both as KLEE values (<<KLEE-SCC-AEAD>>, FIPS 197)."""
    return b2v(aes_encrypt(v2b(K, 32), v2b(B, 16)))


def SCC_KeyDeriv(key: int, nonce: int):
    """<<KLEE-SCC-key-derivation>> (listing "RFC8452 Key Derivation").

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
    """<<KLEE-SCC-POLYVAL>>: tmp <- Montmul(tmp xor blocks[i], auth_key)."""
    tmp = 0
    for blk in blocks:
        tmp ^= blk
        tmp = montmul(tmp, auth_key)
    return tmp


def _tag_block(S: int, sep: int) -> int:
    """0 @ sep @ S[125:0]: the AES input of the tag computation.

    Bit 127 = 0 marks the tag domain (RFC 8452); bit 126 carries the segment
    selector, so the same AD and plaintext give different tags in the two
    segments.  Widths: 1 + 1 + 126 = 128.
    """
    return cat((0, 1), (sep & 1, 1), (sl(S, 125, 0), 126))


def _ctr_block(SIV: int, sep: int, i: int) -> int:
    """1 @ sep @ SIV[125:32] @ bin((int(SIV[31:0]) + i) mod 2**32, 32).

    <<KLEE-SCC-AEAD>> replaces RFC 8452's SIV[126] with an explicit segment
    selector, so the two segments' keystream inputs are disjoint by
    construction.  Widths: 1 + 1 + 94 + 32 = 128.
    """
    return cat((1, 1), (sep & 1, 1), (sl(SIV, 125, 32), 94),
               ((sl(SIV, 31, 0) + i) & M32, 32))


def SCC_Encrypt(AD, N: int, sep: int, P, K: int, length_block=None,
                clear_ads_dropped=True):
    """<<KLEE-SCC-GCM-SIV-enc>>.

    length_block and clear_ads_dropped are not part of the spec: the first
    restores the RFC 8452 block that <<KLEE-SCC-AEAD>> deliberately omits, the
    second suppresses the clearing of AD_auth[0][47]; both exist only for the
    RFC 8452 cross-checks and the negative controls.
    """
    AD_auth = list(AD)                    # local AD_auth <- AD[] (a copy)
    enc_key, auth_key = SCC_KeyDeriv(K, N)
    # if (sep = 0) then: AD_auth[0][47] <- 0.  len_AD >= 1 whenever sep = 0
    # in the procedures; the emptiness guard only serves the RFC 8452
    # cross-checks with empty AAD.
    if sep == 0 and clear_ads_dropped and AD_auth:
        AD_auth[0] &= ~(1 << 47)
    blocks = AD_auth + list(P) + ([] if length_block is None else [length_block])
    SIV = POLYVAL(auth_key, blocks)
    SIV = (SIV & ~((1 << 96) - 1)) | (sl(SIV, 95, 0) ^ N)   # SIV[95:0] ^= N
    SIV = AESE256(enc_key, _tag_block(SIV, sep))
    C = [P[i] ^ AESE256(enc_key, _ctr_block(SIV, sep, i)) for i in range(len(P))]
    return SIV, C


def SCC_Decrypt(AD, N: int, sep: int, SIV: int, C, K: int, length_block=None,
                clear_ads_dropped=True):
    """<<KLEE-SCC-GCM-SIV-dec>>; the harness-only arguments as for SCC_Encrypt."""
    AD_auth = list(AD)
    enc_key, auth_key = SCC_KeyDeriv(K, N)
    if sep == 0 and clear_ads_dropped and AD_auth:
        AD_auth[0] &= ~(1 << 47)
    P = [C[i] ^ AESE256(enc_key, _ctr_block(SIV, sep, i)) for i in range(len(C))]
    blocks = AD_auth + P + ([] if length_block is None else [length_block])
    s = POLYVAL(auth_key, blocks)
    tmp = s
    tmp = (tmp & ~((1 << 96) - 1)) | (sl(tmp, 95, 0) ^ N)
    tmp = AESE256(enc_key, _tag_block(tmp, sep))
    if tmp != SIV:
        return False, [0] * len(C)        # P[i] <- zeros(128)
    return True, P


# ======================================================================
# The MDH (<<KLEE-metadata-header>>) and the State numbers
# ======================================================================

MDH_FIELDS = (                              # (name, hi, lo), in table order
    ('Machine', 11, 0), ('MachinePolicy', 13, 12),
    ('MachineExtension', 15, 14), ('SCProtection', 18, 16),
    ('State', 24, 19), ('StateExtension', 28, 25), ('KeyType', 30, 29),
    ('Reserved31', 31, 31), ('AuxDataLen', 45, 32), ('Reserved46', 46, 46),
    ('ADSDropped', 47, 47), ('AuxInfo', 61, 48), ('Reserved62', 63, 62),
    ('UsagePolicy', 68, 64), ('Locality', 77, 69), ('Reserved78', 79, 78),
    ('MachineUse', 95, 80), ('ExpirationDate', 115, 96),
    ('Reserved116', 125, 116), ('Version', 127, 126),
)
FIELD = {name: (hi, lo) for name, hi, lo in MDH_FIELDS}
RESERVED = tuple(name for name in FIELD if name.startswith('Reserved'))


def fld(mdh: int, name: str) -> int:
    hi, lo = FIELD[name]
    return sl(mdh, hi, lo)


def put(mdh: int, name: str, value: int) -> int:
    hi, lo = FIELD[name]
    w = hi - lo + 1
    assert 0 <= value < (1 << w), f'{name} = {value} does not fit {w} bits'
    return (mdh & ~(((1 << w) - 1) << lo)) | (value << lo)


def field_of_bit(bit: int) -> str:
    for name, hi, lo in MDH_FIELDS:
        if lo <= bit <= hi:
            return name
    raise ValueError(bit)


# <<KLEE-State-field>>: <<KLEE-state-off>>, <<KLEE-states-valid>>,
# <<KLEE-states-error>>; <<KLEE-SC-sealing-status>>; <<KLEE-management-immeds>>.
KL_STATE_UNCONFIGURED = 0
KL_STATE_READY = 1
KL_STATE_SUCCESS, KL_STATE_FAILURE = 46, 47
ERROR_STATE_NAMES = {
    48: 'kl_state_unsupported', 49: 'kl_state_invalid',
    50: 'kl_state_out_of_memory', 51: 'kl_state_mgmt_auth',
    52: 'kl_state_priv_violation', 53: 'kl_state_expired',
    54: '(reserved Error State 54)', 55: '(reserved Error State 55)',
}
KL_STATE_INVALID = 49
KL_STATE_MGMT_AUTH = 51                     # _Authentication Failed_
KL_CFG_PROVISIONING = 56
KL_CFG_EXPORTING = 57
KL_CFG_IMPORTING = 58
KL_CFG_PPI_EXPORTING = 59
KL_CFG_PPI_IMPORTING = 60


def is_valid_state(st): return 1 <= st <= 47
def is_error_state(st): return 48 <= st <= 55
def is_complete_state(st): return 1 <= st <= 55


def base_type(st):
    """<<KLEE-nested-state-base-types>>."""
    if st in (KL_CFG_PROVISIONING, KL_CFG_PPI_EXPORTING, KL_CFG_PPI_IMPORTING):
        return 'pi'
    if st in (KL_CFG_EXPORTING, KL_CFG_IMPORTING):
        return 'scc'
    return None


# <<KLEE-exec-encodings>>: _Machine_ = Type [11:4] @ Mode [3:0]; AES256_ECB is
# Type 2, Mode 0.
AES256_ECB = cat((2, 8), (0, 4))


# ======================================================================
# Localities (<<KLEE-Localities>>, <<KLEE-locality-indexes>>)
# ======================================================================

# _Locality_ occupies MDH[77:69]; within that 9-bit field the architected
# Localities are encoded as (bit span within the field, value):
LOCALITY_ENC = {
    0: ((1, 0), 1), 1: ((1, 0), 2), 2: ((1, 0), 3),        # HW chain 1
    3: ((3, 2), 1), 4: ((3, 2), 2), 5: ((3, 2), 3),        # HW chain 2
    6: ((5, 4), 1), 7: ((5, 4), 2),                        # Boot Session
    8: ((6, 6), 1), 9: ((7, 7), 1), 10: ((8, 8), 1),       # SW Filter
}
# "If an entry is unconfigured, it is transparently replaced by the next
# defined entry in its chain: SiPScrt -> ChipFamScrt -> ChipScrt, and
# OEMScrt -> ProdScrt -> DevScrt."
HW_CHAIN_NEXT = {0: 1, 1: 2, 2: None, 3: 4, 4: 5, 5: None}


def locality_field(indices) -> int:
    """The 9-bit _Locality_ field selecting exactly the given Localities."""
    f = 0
    for j in sorted(indices):
        (hi, lo), val = LOCALITY_ENC[j]
        assert sl(f, hi, lo) == 0, f'Locality #{j} conflicts with an earlier one'
        f |= val << lo
    return f


def localities_of(mdh: int):
    """The Localities that MDH._Locality_ includes, in index order 0..10 --
    the order in which <<KLEE-SCC-export>> step 1.c appends them to AD."""
    f = fld(mdh, 'Locality')
    out = []
    for j in range(11):
        (hi, lo), val = LOCALITY_ENC[j]
        if sl(f, hi, lo) == val:
            out.append(j)
    return out


def make_mdh(machine=AES256_ECB, machine_policy=0b01, state=KL_STATE_READY,
             key_type=0, aux_data_len=0, ads_dropped=0, usage_policy=0,
             localities=(), **other) -> int:
    """Assemble an MDH (<<KLEE-metadata-header>>); `other` takes the remaining
    fields by their spec names in snake case (sc_protection, state_extension,
    machine_extension, aux_info, machine_use, expiration_date, version)."""
    names = {'sc_protection': 'SCProtection', 'state_extension': 'StateExtension',
             'machine_extension': 'MachineExtension', 'aux_info': 'AuxInfo',
             'machine_use': 'MachineUse', 'expiration_date': 'ExpirationDate',
             'version': 'Version'}
    m = 0
    m = put(m, 'Machine', machine)
    m = put(m, 'MachinePolicy', machine_policy)          # 0b01: encryption
    m = put(m, 'State', state)
    m = put(m, 'KeyType', key_type)
    m = put(m, 'AuxDataLen', aux_data_len)
    m = put(m, 'ADSDropped', ads_dropped)
    m = put(m, 'UsagePolicy', usage_policy)
    m = put(m, 'Locality', locality_field(localities))
    for key, value in other.items():
        m = put(m, names[key], value)
    return m


# ======================================================================
# Image layout and lengths (<<KLEE-SCC>>, <<KLEE-length-rule>>,
# <<KLEE-instruction-mv>>, <<KLEE-instruction-size>>)
# ======================================================================

def content_offset(mdh: int) -> int:
    """_ContentOffset_ (<<KLEE-instruction-mv>>; kl.load and kl.store use the
    same value).  _ADSDropped_ never affects it."""
    st = fld(mdh, 'State')
    if is_valid_state(st) or st in (KL_CFG_IMPORTING, KL_CFG_EXPORTING):
        aux = fld(mdh, 'AuxDataLen')
        if aux == 0:
            return 16
        if aux >= 2:
            return 48
        raise ValueError('AuxDataLen = 1 is invalid')
    if st in (KL_CFG_PROVISIONING, KL_CFG_PPI_IMPORTING, KL_CFG_PPI_EXPORTING):
        return 0
    raise ValueError(f'no image for State {st}')


def content2_size(mdh: int) -> int:
    """16 * (AuxDataLen - 2) if AuxDataLen >= 2 and ADSDropped = 0, else 0."""
    aux = fld(mdh, 'AuxDataLen')
    return 16 * (aux - 2) if aux >= 2 and fld(mdh, 'ADSDropped') == 0 else 0


def ser(blocks) -> bytes:
    return b''.join(v2b(b, 16) for b in blocks)


def deser(data: bytes):
    assert len(data) % 16 == 0
    return [b2v(data[i:i + 16]) for i in range(0, len(data), 16)]


class Mem:
    """Memory holding a stored image.  Reads beyond it return zeros; the
    highest offset read is recorded, to check what an import touches."""

    def __init__(self, data: bytes):
        self.data = bytes(data)
        self.hi = 0

    def read(self, off: int, n: int) -> bytes:
        self.hi = max(self.hi, off + n)
        chunk = self.data[off:off + n]
        return chunk + bytes(n - len(chunk))


class IllegalInstruction(Exception):
    pass


class KleeException(Exception):
    def __init__(self, cause):
        super().__init__(cause)
        self.cause = cause


class CL:
    """A Cryptographic Locker: its MDH and its Content, partitioned into
    Content1 and Content2 (<<KLEE-cryptographic-registers>>)."""

    def __init__(self, mdh=0, content1=None, content2=None):
        self.mdh = mdh
        self.content1 = None if content1 is None else list(content1)
        self.content2 = None if content2 is None else list(content2)

    def clear(self):
        self.mdh, self.content1, self.content2 = 0, None, None

    def state(self):
        return fld(self.mdh, 'State')

    def snapshot(self):
        return (self.mdh, tuple(self.content1 or ()),
                None if self.content2 is None else tuple(self.content2))


def enter_error_state(cl: CL, st: int):
    """Rule <<KLEE-SGR-clear-cr-content-error-state>>: the Content beyond the
    MDH is cleared, the ADS released, _AuxDataLen_ and _ADSDropped_ set to 0."""
    cl.content1 = cl.content2 = None
    cl.mdh = put(put(put(cl.mdh, 'State', st), 'AuxDataLen', 0), 'ADSDropped', 0)


def outcome(cl: CL) -> str:
    st = cl.state()
    if is_valid_state(st):
        return 'ok'
    if is_error_state(st):
        return ERROR_STATE_NAMES[st]
    if st == KL_CFG_IMPORTING:
        return 'importing'
    return f'State {st}'


# ======================================================================
# The KLEE unit of one hart, as far as SCC export and import see it
# ======================================================================

class Unit:
    SC_LEVELS = (0, 1, 2)            # <<KLEE-SC-protection-levels>> implemented
    VERSIONS = (0,)                  # <<KLEE-Machine-version>> supported

    def __init__(self, CSK, LST, klmvendorid, klmarchid, klmimpid,
                 max_aux=16, zklexpire=True):
        self.CSK = CSK
        # LST[j]: HW Binding entries absent when not populated; Boot Session
        # and SW Filter entries zeros(128) when unconfigured.
        self.LST = dict(LST)
        self.klmvendorid, self.klmarchid, self.klmimpid = (
            klmvendorid, klmarchid, klmimpid)
        self.max_aux = max_aux       # largest AuxDataLen supported for the Machine
        self.zklexpire = zklexpire
        # The three per-hart authentication registers (<<KLEE-CLF>>).
        self.reg_SIV = self.reg_IMPQUAL = self.reg_SIV2 = 0
        self.decrypts = []           # sep of every SCC_Decrypt call (DIEL factor)

    # -- identification ------------------------------------------------
    def impqual(self) -> int:
        """IMPQUAL := zeros(32) @ klmimpid @ klmarchid @ klmvendorid
        (<<KLEE-Auxiliary-Data-Section>>, <<KLEE-CSR-impl-ids>>)."""
        return cat((0, 32), (self.klmimpid, 32), (self.klmarchid, 32),
                   (self.klmvendorid, 32))

    # -- Localities ----------------------------------------------------
    def _substitute(self, j: int):
        """The substitution rules of <<KLEE-Localities>>: the value of entry j
        or of its replacement, or None if neither is configured."""
        if j in HW_CHAIN_NEXT:
            k = j
            while k is not None:
                if self.LST.get(k) is not None:
                    return self.LST[k]
                k = HW_CHAIN_NEXT[k]
            return None
        value = self.LST.get(j, 0)
        return value if value != 0 else None

    def unconfigured(self, j: int) -> bool:
        """Entry j names an unconfigured Locality Secret with no replacement,
        which makes Metadata invalid (<<KLEE-Metadata-validity>>)."""
        return self._substitute(j) is None

    def lst_eff(self, j: int) -> int:
        """LST_eff[j] of <<KLEE-SCC-export>>, used by the export and import
        algorithms alike: "a non-implemented entry with no configured
        replacement contributes zeros(128)"; the export is not refused."""
        value = self._substitute(j)
        return 0 if value is None else value

    # -- the Machine and the length rule -------------------------------
    def content1_size(self, mdh: int) -> int:
        """<<KLEE-length-rule>> 2 for AES256_ECB: the Serialized Content of
        <<KLEE-ECB-mode>> is the k = 256-bit key or a 64-bit SKID, padded to
        128-bit blocks.  Depends on _KeyType_ only among the admitted fields."""
        bits = 256 if fld(mdh, 'KeyType') == 0 else 64
        return 16 * ((bits + 127) // 128)

    def pi_content_size(self, mdh: int) -> int:
        """<<KLEE-length-rule>> 1: the ECB Provisioning Input has the same field."""
        return self.content1_size(mdh)

    def max_admissible(self, mdh: int) -> int:
        """<<KLEE-instruction-mv>>, SCC base type: content1_size plus the
        largest content2_size the implementation supports."""
        return self.content1_size(mdh) + 16 * max(0, self.max_aux - 2)

    # -- <<KLEE-Metadata-validity>> ------------------------------------
    def metadata_check(self, M: int, base: str, at_import=False):
        """None, 'unsupported' or 'invalid' for the MDH M of an image whose
        base type is `base` ('pi' or 'scc')."""
        if (fld(M, 'MachineExtension') != 0 or fld(M, 'Machine') != AES256_ECB
                or fld(M, 'SCProtection') not in self.SC_LEVELS):
            return 'unsupported'
        loc = fld(M, 'Locality')
        custom = (fld(M, 'Machine') >= 3072 or fld(M, 'SCProtection') >= 6
                  or fld(M, 'Version') == 3)
        invalid = (
            any(fld(M, r) for r in RESERVED)
            or fld(M, 'AuxDataLen') == 1
            or (base == 'pi' and (fld(M, 'ADSDropped') or fld(M, 'AuxDataLen')))
            or fld(M, 'MachinePolicy') == 0      # ECB needs a bit (<<KLEE-Machine-field>>)
            or fld(M, 'KeyType') in (2, 3)
            or sl(loc, 5, 4) == 3
            or any(self.unconfigured(j) for j in localities_of(M))
            or fld(M, 'AuxInfo') != 0            # not used by ECB
            or (fld(M, 'ExpirationDate') != 0 and not self.zklexpire)
            or fld(M, 'Version') not in self.VERSIONS
            or (custom and sl(loc, 1, 0) not in (2, 3))   # <<KLEE-GR-custom-locality>>
            or (at_import and fld(M, 'State') in (0, 61, 62, 63)))
        return 'invalid' if invalid else None

    # -- kl.size -------------------------------------------------------
    def kl_size(self, mdh: int, form='C') -> int:
        """<<KLEE-instruction-size>>; Form A takes the MDH of a CL, Form C a
        supplied MDH (whose validity is checked)."""
        st = fld(mdh, 'State')
        if form == 'A' and st == KL_STATE_UNCONFIGURED:
            return 0
        if form == 'C' and not is_error_state(st):
            if st in (61, 62, 63):
                return 0
            base = 'pi' if st == 0 or base_type(st) == 'pi' else 'scc'
            if self.metadata_check(mdh, base) is not None:
                return 0
        if is_error_state(st):
            return 16
        c1 = self.content1_size(mdh)
        if is_valid_state(st) or st in (KL_CFG_IMPORTING, KL_CFG_EXPORTING):
            if fld(mdh, 'AuxDataLen') == 0:
                return 32 + c1
            # The 64-byte fixed part includes IMPQUAL and SIV2 even when
            # ADSDropped = 1.
            return 64 + c1 + content2_size(mdh)
        return 16 + self.pi_content_size(mdh)

    # -- kl.mgmt #kl_cfg_importing: <<KLEE-SCC-import>> steps 1-5 -------
    def mgmt_open_import(self, cl: CL, ml: int):
        cl.clear()                                   # step 1: clear K(i)
        st = fld(ml, 'State')
        if is_error_state(st):
            self._short_import(cl, ml)
            return
        base = 'pi' if base_type(st) == 'pi' else 'scc'
        check = self.metadata_check(ml, base, at_import=True)     # step 3
        if check == 'unsupported':
            raise KleeException('kl_exc_unsupported')   # MDH remains all-zero
        if check == 'invalid':
            # All fields of the MDH other than State remain zero
            # (<<KLEE-CL-management>> 1).
            cl.mdh = put(0, 'State', KL_STATE_INVALID)
            return
        if base == 'pi':
            raise NotImplementedError('PI-shaped images are outside this harness')
        self.reg_SIV = self.reg_IMPQUAL = self.reg_SIV2 = 0      # <<KLEE-CLF>>
        # Steps 2 and 4-5: M loaded, layout from M, working ADSDropped.
        aux = fld(ml, 'AuxDataLen')
        dropped = 1 if aux >= 2 and (fld(ml, 'ADSDropped') == 1
                                     or aux > self.max_aux) else 0
        cl.mdh = put(put(ml, 'ADSDropped', dropped), 'State', KL_CFG_IMPORTING)

    def _short_import(self, cl: CL, ml: int):
        """<<KLEE-error-state-transfer>>: configure the CL into the Error State
        ml names (54 and 55 as Invalid), installing the entire MDH except that
        _AuxDataLen_ and _ADSDropped_ are set to 0; no Metadata-validity check;
        no management operation is opened, so the authentication registers
        take no part."""
        st = fld(ml, 'State')
        if st in (54, 55):
            st = KL_STATE_INVALID
        cl.mdh = put(put(put(ml, 'State', st), 'AuxDataLen', 0), 'ADSDropped', 0)

    # -- kl.load: <<KLEE-SCC-import>> step 6 ---------------------------
    def load(self, cl: CL, mem: Mem, at=16):
        if cl.state() not in (KL_CFG_PROVISIONING, KL_CFG_IMPORTING,
                              KL_CFG_PPI_IMPORTING):
            raise IllegalInstruction('kl.load: State not admitted (SGR21)')
        off = content_offset(cl.mdh)
        c1 = self.content1_size(cl.mdh)
        content_size = c1 + content2_size(cl.mdh)
        image_end = off + min(content_size, self.max_admissible(cl.mdh))
        S = mem.read(at, image_end)                  # offsets [0, image_end) of S
        self.reg_SIV = b2v(S[0:16])
        if off == 48:
            self.reg_IMPQUAL = b2v(S[16:32])
            self.reg_SIV2 = b2v(S[32:48])
        cl.content1 = deser(S[off:off + c1])
        has_content2 = (fld(cl.mdh, 'AuxDataLen') >= 2
                        and fld(cl.mdh, 'ADSDropped') == 0)
        cl.content2 = deser(S[off + c1:image_end]) if has_content2 else None

    # -- kl.mgmt #kl_cfg_exporting: <<KLEE-SCC-export>> steps 1-2 -------
    def mgmt_open_export(self, cl: CL):
        st = cl.state()
        if st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction('export of an Unconfigured CL')
        if is_error_state(st):
            return                                   # CL unchanged, nothing opened
        if is_valid_state(st):
            # After kl.clearads, import completion or provisioning a fully
            # configured CL has ADSDropped = 0.
            assert fld(cl.mdh, 'ADSDropped') == 0
            saved_MDH = cl.mdh                                        # 1.a
            AD = [saved_MDH]                                          # 1.b
            for j in localities_of(saved_MDH):                        # 1.c
                AD.append(self.lst_eff(j))
            # 1.d-1.e; SCC_Encrypt clears ADSDropped in its local copy only.
            self.reg_SIV, cl.content1 = SCC_Encrypt(AD, 0, 0, cl.content1, self.CSK)
            aux = fld(saved_MDH, 'AuxDataLen')
            if aux >= 2:                                              # 2
                assert self.klmimpid != 0     # <<KLEE-CSR-impl-ids>>: ADS producer
                assert len(cl.content2) == aux - 2                    # 2.b
                self.reg_IMPQUAL = self.impqual()
                AD2 = [self.reg_IMPQUAL, self.reg_SIV]                # 2.a
                self.reg_SIV2, cl.content2 = SCC_Encrypt(             # 2.c
                    AD2, 0, 1, cl.content2, self.CSK)
            cl.mdh = put(cl.mdh, 'State', KL_CFG_EXPORTING)
            return
        if base_type(st) == 'scc':
            # Nested export: no encryption or authentication; the contents
            # are exported verbatim (<<KLEE-CL-management>> 2).
            cl.mdh = put(cl.mdh, 'State', KL_CFG_EXPORTING)
            return
        raise NotImplementedError('PI-shaped images are outside this harness')

    # -- kl.store ------------------------------------------------------
    def store(self, cl: CL) -> bytes:
        if cl.state() not in (KL_CFG_EXPORTING, KL_CFG_PPI_EXPORTING):
            raise IllegalInstruction('kl.store: State not admitted (SGR22)')
        off = content_offset(cl.mdh)
        S = v2b(self.reg_SIV, 16)
        if off == 48:
            S += v2b(self.reg_IMPQUAL, 16) + v2b(self.reg_SIV2, 16)
        S += ser(cl.content1)
        if content2_size(cl.mdh):
            S += ser(cl.content2)
        image_size = off + self.content1_size(cl.mdh) + content2_size(cl.mdh)
        assert len(S) == image_size
        return S

    # -- kl.mgmt #kl_cfg_management_end: <<KLEE-SCC-import>> steps 7-15 --
    def mgmt_complete(self, cl: CL, ml: int, regen=None, clear_ads_dropped=True):
        """Completion of an import or an export of a CL of base type scc
        (<<KLEE-CL-management>> 3).  `regen` = (AuxDataLen, Content2) is a
        replacement ADS the Machine's state machine generates at step 15;
        clear_ads_dropped=False is the harness-only negative control."""
        if cl.state() not in (KL_CFG_IMPORTING, KL_CFG_EXPORTING):
            raise IllegalInstruction('no management operation open on the CL')
        st = fld(ml, 'State')
        if not (is_complete_state(st) or st in (KL_CFG_IMPORTING, KL_CFG_EXPORTING)):
            raise IllegalInstruction('ml.State not admitted for base type scc')
        # ml is consumed only for its State field.
        cl.mdh = put(cl.mdh, 'State', st)
        if not is_complete_state(st):
            return                                   # nested: no authentication
        saved_MDH = cl.mdh                           # step 7
        AD = [saved_MDH]                             # step 8
        for j in localities_of(saved_MDH):           # step 9
            AD.append(self.lst_eff(j))
        self.decrypts.append(0)                      # steps 10-11
        correct, cl.content1 = SCC_Decrypt(AD, 0, 0, self.reg_SIV, cl.content1,
                                           self.CSK,
                                           clear_ads_dropped=clear_ads_dropped)
        if not correct:                              # step 12
            enter_error_state(cl, KL_STATE_MGMT_AUTH)
            return
        attempted = False                            # step 13
        if fld(cl.mdh, 'AuxDataLen') >= 2 and fld(cl.mdh, 'ADSDropped') == 0:
            attempted = True
            AD2 = [self.reg_IMPQUAL, self.reg_SIV]
            if self.reg_IMPQUAL == self.impqual():
                self.decrypts.append(1)
                correct, cl.content2 = SCC_Decrypt(AD2, 0, 1, self.reg_SIV2,
                                                   cl.content2, self.CSK)
            else:
                correct = False
        if attempted and not correct:                # step 14
            cl.content2 = None
            cl.mdh = put(cl.mdh, 'ADSDropped', 1)
        # step 15
        if fld(cl.mdh, 'AuxDataLen') == 0 or fld(cl.mdh, 'ADSDropped') == 1:
            cl.mdh = put(cl.mdh, 'ADSDropped', 0)
            if regen is None:
                cl.mdh = put(cl.mdh, 'AuxDataLen', 0)
                cl.content2 = None
            else:
                aux2, payload = regen
                assert aux2 >= 2 and len(payload) == aux2 - 2
                cl.mdh = put(cl.mdh, 'AuxDataLen', aux2)
                cl.content2 = list(payload)
        else:
            cl.mdh = put(cl.mdh, 'ADSDropped', 0)    # ADS retained


# ======================================================================
# Software sequences (<<KLEE-management-operations>>, informative)
# ======================================================================

def export_cl(unit: Unit, cl: CL) -> bytes:
    """kl.size, kl.getmd, and -- unless the CL is in an Error State, whose
    image is the MDH alone (<<KLEE-error-state-transfer>>) -- kl.mgmt
    #kl_cfg_exporting, kl.store, and the completing kl.mgmt with the saved MDH."""
    size = unit.kl_size(cl.mdh, form='A')
    ml = cl.mdh                                      # kl.getmd
    image = v2b(ml, 16)
    if size == 16:
        return image
    unit.mgmt_open_export(cl)
    image += unit.store(cl)
    unit.mgmt_complete(cl, ml)
    assert len(image) == size, (len(image), size)
    return image


def import_image(unit: Unit, mem: Mem, ml=None, regen=None,
                 clear_ads_dropped=True):
    """Read the MDH, open the import with it, load the rest, and complete with
    the saved MDH ml (by default the MDH of the image)."""
    M = b2v(mem.read(0, 16))
    ml = M if ml is None else ml
    cl = CL()
    try:
        unit.mgmt_open_import(cl, M)
    except KleeException as e:
        return cl, e.cause
    if cl.state() == KL_CFG_IMPORTING:
        unit.load(cl, mem)
        unit.mgmt_complete(cl, ml, regen, clear_ads_dropped=clear_ads_dropped)
    return cl, outcome(cl)


def open_and_load(unit: Unit, image: bytes) -> CL:
    """The first two phases of an import, as preempted before completion."""
    mem = Mem(image)
    cl = CL()
    unit.mgmt_open_import(cl, b2v(mem.read(0, 16)))
    unit.load(cl, mem)
    return cl


def export_pccc(unit: Unit, cl: CL) -> bytes:
    """Nested export of a CL under import (<<KLEE-data-formats>>, PCCC): the
    saved MDH followed by the SCC-shaped image, exported verbatim."""
    ml = cl.mdh
    unit.mgmt_open_export(cl)
    image = v2b(ml, 16) + unit.store(cl)
    unit.mgmt_complete(cl, ml)                       # State kl_cfg_importing again
    return image


def reimport_pccc(unit: Unit, image: bytes) -> CL:
    """Re-import of an SCC-shaped PCCC, completed at the nested level."""
    cl = open_and_load(unit, image)
    unit.mgmt_complete(cl, b2v(image[0:16]))         # nested: no authentication
    return cl


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
# intermediates.  The spec's SCC_KeyDeriv is exactly this derivation.
RFC8452_C2_2 = {
    'key':   '01000000000000000000000000000000'
             '00000000000000000000000000000000',
    'nonce': '030000000000000000000000',
    'auth_key': 'b5d3c529dfafac43136d2d11be284d7f',
    'enc_key':  'b914f4742be9e1d7a2f84addbf96dec3'
                '456e3c6c05ecc157cdbf0700fedad222',
}

# RFC 8452 Appendix C.2 / C.3 records (AEAD_AES_256_GCM_SIV); 'ct_tag' is the
# RFC's "Result" (ciphertext || tag).  C.3 uses the SCC's own nonce, zeros(96).
_K1 = '01' + '00' * 31
_N3 = '03' + '00' * 11
RFC8452_AEAD = [
    ('RFC 8452 C.2 #1', _K1, _N3, '', '',
     '07f5f4169bbf55a8400cd47ea6fd400f'),
    ('RFC 8452 C.2 #2', _K1, _N3, '', '0100000000000000',
     'c2ef328e5c71c83b843122130f7364b761e0b97427e3df28'),
    ('RFC 8452 C.2 #6', _K1, _N3, '',
     '01000000000000000000000000000000'
     '02000000000000000000000000000000'
     '03000000000000000000000000000000',
     'c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e3'
     '9cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4'),
    ('RFC 8452 C.2 #15', _K1, _N3, '010000000000000000000000000000000200',
     '0300000000000000000000000000000004000000',
     '43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59'
     'cabfe307'),
    ('RFC 8452 C.2 #24',
     '3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23',
     '688089e55540db1872504e1c',
     '734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541',
     'ced532ce4159b035277d4dfbb7db62968b13cd4eec',
     '626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a2865'
     '94'),
    ('RFC 8452 C.3 #1', '00' * 32, '00' * 12, '',
     '000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108',
     'f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3ea'
     'ffffffff000000000000000000000000'),
    ('RFC 8452 C.3 #2', '00' * 32, '00' * 12, '',
     'eb3640277c7ffd1303c7a542d02d3e4c0000000000000000',
     '18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56d'
     'ffffffff000000000000000000000000'),
]

# Synthetic material for the sealing construction (this file).
CSK = b2v(bytes(range(32)))
LST = {j: b2v(bytes([0x40 + j] * 16)) for j in range(11)}
LST_ALT = dict(LST)
LST_ALT[4] = LST[4] ^ (1 << 17)                 # Locality #4 changed; it is
                                                # selected by LOC_SETS[2]
LST_ALT_UNSEL = dict(LST)
LST_ALT_UNSEL[3] = LST[3] ^ (1 << 17)           # #3 is selected by no LOC_SET
LST_NO_SIP = {j: v for j, v in LST.items() if j != 0}   # SiPScrt not populated
LST_NO_SLOC = dict(LST)
LST_NO_SLOC[10] = 0                             # SLocality unconfigured

# Implementation identifiers.  klmarchid bit 15 is IMPQUAL bit 47, the bit
# that first-segment authentication clears in AD[0]; it is set here so that
# the second segment is seen to keep it.
IDS = dict(klmvendorid=0x0000_0489, klmarchid=0x0000_8001, klmimpid=0x0102_0304)
IDS_NEXT_REV = dict(IDS, klmimpid=0x0102_0305)  # another version of the unit

KEY256 = bytes(range(0x80, 0xA0))
CONTENT1 = deser(KEY256)                        # AES256_ECB: the 256-bit key
CONTENT2 = [b2v(bytes([0xA0 + i] * 16)) for i in range(2)]
AUX_LEN = 2 + len(CONTENT2)                     # IMPQUAL + SIV2 + Content2

# The Locality sets exercised: none, one, and the maximum of six (one per
# HW chain, one Boot Session entry, all three SW Filter entries), which is
# what <<KLEE-Localities>> permits concurrently.
LOC_SETS = [(), (2,), (1, 4, 6, 8, 9, 10)]

# Regression vectors of this model (self-generated, not independent): a
# change here means the construction, the MDH layout or the SCC layout
# changed.  Keys: Locality set -> (MDH, SIV, first Content1 block).
REGRESSION = {
    (): ('20100800000000000000000000000000',
         '196751c2843a12d162a60ce9b19df8c2',
         'a31c0e23e516c7846b1d737a73510540'),
    (2,): ('20100800000000006000000000000000',
           '3c57b39eef6f198ad7f220d6059da41f',
           '8e5935c8f80d9b0a9a7f0cb409c1ac7e'),
    (1, 4, 6, 8, 9, 10): ('2010080000000000403b000000000000',
                          'cc2dda526d4eb89c17875489b78e055a',
                          '3520073eea6486e61c99fb0a000c24b9'),
}
REGRESSION_ADS = {                              # AuxDataLen = 4, LOC_SETS[2]
    'MDH': '2010080004000000403b000000000000',
    'SIV': '3a668ccb7faad708d200a55b3f8bcfbc',
    'IMPQUAL': '89040000018000000403020100000000',
    'SIV2': '54302cd496d39e24ddfbd4d9b4bbbee8',
    'C2[0]': 'f9a885e5330ad74234fda0d67a1ad7a1',
}
# The CL after an import whose Content1 was altered: State 51, AuxDataLen 0.
REGRESSION_ERROR_IMAGE = '2010980100000000403b000000000000'


# ======================================================================
# Test driver
# ======================================================================

ok = True


def chk(cond, desc):
    global ok
    ok = ok and bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {desc}")


def info(text):
    print(f"INFO  {text}")


def spec_note(text):
    print(f"SPEC-NOTE: {text}")


def flips(region_lo, region_hi, step=7):
    """Bit positions to flip inside scc[region_lo:region_hi]."""
    return range(8 * region_lo, 8 * region_hi, step)


def tampered(image: bytes, bit: int) -> bytes:
    b = bytearray(image)
    b[bit // 8] ^= 1 << (bit % 8)
    return bytes(b)


def new_unit(lst=LST, ids=IDS, csk=CSK, **kw) -> Unit:
    return Unit(csk, lst, **ids, **kw)


def sealed(unit: Unit, mdh: int, content1=CONTENT1, content2=None) -> bytes:
    """Export a fully configured CL holding the given Content."""
    return export_cl(unit, CL(mdh, content1, content2))


def main():
    global ok
    print("SCC sealing construction and SCC export/import "
          "(KLEE <<KLEE-SCC-export>> / <<KLEE-SCC-import>>)")
    print("Anchor level: AESE256, Montmul/POLYVAL and SCC_KeyDeriv are")
    print("  STANDARD-ANCHORED (FIPS 197 C.3; RFC 8452 App. A; RFC 8452 C.2 #2);")
    print("  SCC_Encrypt/SCC_Decrypt are PARTIALLY anchored on RFC 8452 C.2/C.3")
    print("  with the length block restored; the export/import procedures are")
    print("  SELF-CONSISTENT ONLY: structural properties are tested, and")
    print("  regression vectors checked.\n")

    unit = new_unit()
    n1 = unit.content1_size(make_mdh()) // 16

    # ------------------------------------------------------------------
    print("-- primitive anchors")
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
    ek, ak = SCC_KeyDeriv(b2v(bytes.fromhex(v['key'])),
                          b2v(bytes.fromhex(v['nonce'])))
    chk(v2b(ak, 16).hex() == v['auth_key'],
        "SCC_KeyDeriv auth_key vs RFC 8452 C.2 #2 intermediate")
    chk(v2b(ek, 32).hex() == v['enc_key'],
        "SCC_KeyDeriv enc_key  vs RFC 8452 C.2 #2 intermediate")

    # ------------------------------------------------------------------
    print("\n-- SCC_Encrypt / SCC_Decrypt against RFC 8452 C.2 / C.3 "
          "(length block restored)")
    def pad(s: bytes):
        """RFC 8452 zero-pads AAD and plaintext to whole blocks for POLYVAL."""
        return deser(s + bytes(-len(s) % 16))

    for src, k, nce, aad, pt, rec in RFC8452_AEAD:
        K, N = b2v(bytes.fromhex(k)), b2v(bytes.fromhex(nce))
        A, P, R = bytes.fromhex(aad), bytes.fromhex(pt), bytes.fromhex(rec)
        CT, TAG = R[:-16], R[-16:]
        # RFC 8452 section 4: le64(bitlen(AAD)) || le64(bitlen(PT)).
        lb = cat((bin_(8 * len(P), 64), 64), (bin_(8 * len(A), 64), 64))
        enc_key, _ = SCC_KeyDeriv(K, N)
        tag_in = b2v(aes_decrypt(v2b(enc_key, 32), TAG))   # the RFC's AES input
        s = sl(tag_in, 126, 126)          # bit 126 of POLYVAL(...) xor nonce
        t = sl(b2v(TAG), 126, 126)        # bit 126 of the tag
        siv, c = SCC_Encrypt(pad(A), N, s, pad(P), K, length_block=lb)
        chk(sl(tag_in, 127, 127) == 0 and v2b(siv, 16) == TAG,
            f"{src}: SCC_Encrypt with sep = {s} (the RFC's bit 126) "
            f"reproduces the tag")
        if P:
            # The loop body of SCC_Encrypt / SCC_Decrypt with sep = t is the
            # RFC's counter block; C.3 wraps int(SIV[31:0]) + i mod 2^32.
            ks = [AESE256(enc_key, _ctr_block(b2v(TAG), t, i))
                  for i in range(len(pad(CT)))]
            rec_pt = ser(x ^ y for x, y in zip(pad(CT), ks))[:len(P)]
            chk(rec_pt == P,
                f"{src}: the counter blocks with sep = {t} recover the "
                f"plaintext")
        corr = [SCC_Decrypt(pad(A), N, sp, b2v(TAG), pad(CT), K,
                            length_block=lb) for sp in (0, 1)]
        verifies = [sp for sp in (0, 1) if corr[sp][0]]
        if s == t:
            chk(ser(c)[:len(P)] == CT and verifies == [s]
                and ser(corr[s][1])[:len(P)] == P,
                f"{src}: bits coincide, so the whole record is reproduced "
                f"and verifies")
        else:
            chk(verifies == [],
                f"{src}: bits differ, so no sep verifies the record "
                f"(the one-bit price of sep)")

    # ------------------------------------------------------------------
    print("\n-- the MDH (<<KLEE-metadata-header>>)")
    covered = sorted(b for _, hi, lo in MDH_FIELDS for b in range(lo, hi + 1))
    chk(covered == list(range(128)),
        "the MDH fields tile bits [127:0] exactly, without overlap")
    probe = make_mdh(state=0x2A, state_extension=0x9)
    chk(((probe & M32) >> 19) & 0x3F == 0x2A
        and ((probe & M32) >> 25) & 0x0F == 0x9,
        "kl.getst / kl.getstx expansions (srli 19, andi 0x3F; srli 25, "
        "andi 0x0F) read _State_ / _StateExtension_ (<<KLEE-instruction-getst>>)")
    length_fields = ('Machine', 'MachinePolicy', 'KeyType', 'StateExtension',
                     'AuxDataLen', 'ADSDropped', 'SCProtection')
    chk(all(FIELD[f][0] < 64 for f in length_fields),
        "every field that determines a length or the CLF capacity lies in "
        "bits [63:0] (<<KLEE-length-rule>>)")
    for locs in LOC_SETS:
        chk(tuple(localities_of(make_mdh(localities=locs))) == tuple(sorted(locs)),
            f"MDH._Locality_ round-trips for Localities {locs or '(none)'}")
    most = max(len(localities_of(put(0, 'Locality', f)))
               for f in range(512) if sl(f, 5, 4) != 3)
    chk(most == 6 == len(LOC_SETS[2]),
        "at most six Localities can be named, so len_AD never exceeds 7 "
        "(<<KLEE-SCC-GCM-SIV-enc>>)")

    # ------------------------------------------------------------------
    print("\n-- length rule and layout (<<KLEE-length-rule>>, <<KLEE-SCC>>)")
    base = make_mdh(localities=LOC_SETS[2], aux_data_len=AUX_LEN)

    def image_len(m):
        """16 (MDH) + _ContentOffset_ + content_size (<<KLEE-instruction-mv>>)."""
        return 16 + content_offset(m) + unit.content1_size(m) + content2_size(m)

    chk(all(image_len(m) == unit.kl_size(m) for m in (
            base, make_mdh(), put(base, 'ADSDropped', 1),
            put(base, 'AuxDataLen', 2), make_mdh(key_type=1))),
        "image_size = kl.size - 16 (<<KLEE-instruction-mv>> vs "
        "<<KLEE-instruction-size>>)")
    states = list(range(1, 48)) + [KL_CFG_EXPORTING, KL_CFG_IMPORTING]
    chk(len({image_len(put(base, 'State', st)) for st in states}) == 1,
        "the SCC length does not depend on _State_ (Valid States and the scc "
        "Configuration States)")
    others = [('SCProtection', 2), ('UsagePolicy', 0b10101), ('Locality', 0),
              ('MachineUse', 0xBEEF), ('ExpirationDate', 0x12345),
              ('AuxInfo', 7), ('Version', 1), ('Reserved116', 5)]
    chk(all(image_len(put(base, f, x)) == image_len(base) for f, x in others),
        "no field outside the length rule changes the SCC length")
    chk(image_len(put(base, 'KeyType', 1)) != image_len(base),
        "_KeyType_ changes the SCC length (key by value vs SKID)")
    for aux in (0, 2, AUX_LEN, 16):
        m = put(make_mdh(localities=LOC_SETS[2]), 'AuxDataLen', aux)
        d = put(m, 'ADSDropped', 1)
        c1_at = content_offset(m)
        if aux == 0:
            chk(image_len(d) == image_len(m) and content_offset(d) == c1_at == 16,
                "AuxDataLen = 0: _ADSDropped_ changes nothing (Content1 at 16)")
        else:
            chk(content_offset(d) == c1_at == 48
                and image_len(m) - image_len(d) == 16 * (aux - 2),
                f"AuxDataLen = {aux}: _ADSDropped_ removes exactly Content2; "
                f"IMPQUAL and SIV2 stay, Content1 stays at 48")
    chk(unit.kl_size(put(base, 'AuxDataLen', 1)) == 0,
        "kl.size reports 0 for AuxDataLen = 1 (invalid Metadata)")
    chk(all(unit.kl_size(put(base, 'State', st)) == 16 for st in range(48, 56)),
        "kl.size reports 16 for every Error State (<<KLEE-error-state-transfer>>)")

    # ------------------------------------------------------------------
    print("\n-- export -> import round trip")
    sccs = {}
    for locs in LOC_SETS:
        mdh = make_mdh(localities=locs)
        cl0 = CL(mdh, CONTENT1)
        scc = export_cl(unit, cl0)
        sccs[locs] = (mdh, scc)
        lbl = f"{len(locs)} Localit{'y' if len(locs) == 1 else 'ies'} {locs or ''}"
        chk(len(scc) == 32 + 16 * n1 == unit.kl_size(mdh),
            f"SCC = MDH, SIV, Content1; length = kl.size ({lbl})")
        chk(scc[:16] == v2b(mdh, 16), f"SCC Section 1 is the plaintext MDH ({lbl})")
        chk(scc[32:] != ser(CONTENT1), f"Content1 is encrypted in the SCC ({lbl})")
        chk(cl0.snapshot() == (mdh, tuple(CONTENT1), None),
            f"the completing kl.mgmt restores the exported CL ({lbl})")
        cl, res = import_image(unit, Mem(scc))
        chk(res == 'ok' and cl.snapshot() == (mdh, tuple(CONTENT1), None),
            f"export -> import reproduces the CL and authenticates ({lbl})")
    sivs = {locs: sccs[locs][1][16:32] for locs in LOC_SETS}
    chk(len(set(sivs.values())) == len(LOC_SETS),
        "distinct Locality sets give distinct SIVs")
    chk(export_cl(unit, CL(sccs[LOC_SETS[2]][0], CONTENT1)) == sccs[LOC_SETS[2]][1],
        "sealing is deterministic (no nonce, <<KLEE-SCC-AEAD>> change 2)")

    # SCC_Encrypt/SCC_Decrypt work on a local copy of AD[0] (sep = 0).
    mdh, scc = sccs[LOC_SETS[2]]
    AD = [mdh | (1 << 47)] + [LST[j] for j in LOC_SETS[2]]
    siv_set, c_set = SCC_Encrypt(AD, 0, 0, CONTENT1, CSK)
    siv_clr, c_clr = SCC_Encrypt([mdh] + AD[1:], 0, 0, CONTENT1, CSK)
    chk((siv_set, c_set) == (siv_clr, c_clr) and AD[0] >> 47 & 1 == 1,
        "sep = 0: AD[0][47] (ADSDropped) is cleared in a local copy only")
    chk(SCC_Decrypt(AD, 0, 0, siv_clr, c_clr, CSK) == (True, CONTENT1)
        and AD[0] >> 47 & 1 == 1,
        "SCC_Decrypt authenticates either value of AD[0][47] and leaves "
        "AD[0] unchanged")

    # ------------------------------------------------------------------
    print("\n-- tamper detection, first segment")
    kinds = {}
    wrong = []
    for bit in range(128):
        img = tampered(scc, bit)
        cl, res = import_image(unit, Mem(img))
        name = field_of_bit(bit)
        value = fld(b2v(img[:16]), name)
        if bit == 47:
            chk(res == 'ok' and cl.snapshot() == (mdh, tuple(CONTENT1), None)
                and fld(open_and_load(unit, img).mdh, 'ADSDropped') == 0,
                "MDH bit 47 (_ADSDropped_) with AuxDataLen = 0 is ignored: the "
                "working value is 0 (step 5) and the same CL is imported")
            continue
        # The outcome <<KLEE-Metadata-validity>> and <<KLEE-SCC-import>>
        # prescribe for this field and value.
        if name in ('Machine', 'MachineExtension') or (
                name == 'SCProtection' and value not in Unit.SC_LEVELS):
            want = 'kl_exc_unsupported'
        elif (name in RESERVED or name in ('AuxInfo', 'Version')
              or (name == 'MachinePolicy' and value == 0)
              or (name == 'KeyType' and value >= 2)
              or (name == 'AuxDataLen' and value == 1)
              or (name == 'Locality' and sl(value, 5, 4) == 3)
              or (name == 'State' and value == 0)):
            want = 'kl_state_invalid'
        else:
            want = 'kl_state_mgmt_auth'
        kinds[want] = kinds.get(want, 0) + 1
        if res != want:
            wrong.append((bit, name, res, want))
        elif want == 'kl_state_invalid' and cl.mdh != put(0, 'State', 49):
            wrong.append((bit, name, 'MDH not zeroed', want))
        elif want == 'kl_state_mgmt_auth':
            exp = put(put(put(b2v(img[:16]), 'State', 51), 'AuxDataLen', 0),
                      'ADSDropped', 0)
            if cl.snapshot() != (exp, (), None):
                wrong.append((bit, name, 'Error-State CL wrong', want))
    chk(not wrong,
        "every other single-bit change of the MDH yields unsupported, "
        "invalid Metadata or Authentication Failed, as the field requires"
        + (f" -- mismatches: {wrong[:4]}" if wrong else ""))
    info("MDH single-bit changes: " + ", ".join(
        f"{v} {k}" for k, v in sorted(kinds.items())) + ", bit 47 ignored")
    exp_unit = new_unit(zklexpire=False)
    chk(all(import_image(exp_unit, Mem(tampered(scc, b)))[1] == 'kl_state_invalid'
            for b in (96, 105, 115)),
        "without Zklexpire a non-zero _ExpirationDate_ is invalid Metadata")

    for name, lo, hi in (('SIV', 16, 32), ('a Content1 block', 32, 32 + 16 * n1)):
        bad = sum(import_image(unit, Mem(tampered(scc, bit)))[1]
                  != 'kl_state_mgmt_auth' for bit in flips(lo, hi))
        chk(bad == 0,
            f"every single-bit change in {name} fails authentication "
            f"(kl_state_mgmt_auth)")

    AD = [mdh] + [LST[j] for j in LOC_SETS[2]]
    corr, P = SCC_Decrypt(AD, 0, 0, b2v(scc[16:32]) ^ 1, deser(scc[32:]), CSK)
    chk(not corr and P == [0] * n1,
        "SCC_Decrypt zeroes P[] when authentication fails")

    chk(import_image(new_unit(LST_ALT), Mem(scc))[1] == 'kl_state_mgmt_auth',
        "a changed Locality Secret fails authentication")
    chk(import_image(new_unit(LST_ALT_UNSEL), Mem(scc))[1] == 'ok',
        "an unselected Locality Secret does not affect the SCC")
    chk(import_image(new_unit(csk=CSK ^ 1), Mem(scc))[1] == 'kl_state_mgmt_auth',
        "a different CSK fails authentication")
    forged = v2b(make_mdh(localities=(2,)), 16) + scc[16:]
    chk(import_image(unit, Mem(forged))[1] == 'kl_state_mgmt_auth',
        "substituting the MDH's Locality set fails authentication")

    # ml is consumed only for its _State_ field (<<KLEE-CL-management>> 3).
    cl, res = import_image(unit, Mem(scc), ml=put(mdh, 'State', 7))
    chk(res == 'kl_state_mgmt_auth',
        "a completing kl.mgmt whose ml carries another _State_ fails "
        "authentication")
    ml_other = put(put(mdh, 'Locality', 0), 'UsagePolicy', 0b11111)
    cl, res = import_image(unit, Mem(scc), ml=ml_other)
    chk(res == 'ok' and cl.mdh == mdh,
        "fields of ml other than _State_ are not written into the CL")

    # Locality substitution (<<KLEE-Localities>>, LST_eff of <<KLEE-SCC-export>>).
    no_sip = new_unit(LST_NO_SIP)
    m0 = make_mdh(localities=(0,))
    scc0 = sealed(no_sip, m0)
    chk(import_image(no_sip, Mem(scc0))[1] == 'ok',
        "unpopulated SiPScrt on both sides: ChipFamScrt substitutes, import succeeds")
    chk(import_image(unit, Mem(scc0))[1] == 'kl_state_mgmt_auth',
        "SiPScrt populated only at the importer: authentication fails")
    dropped_siv, _ = SCC_Encrypt([m0], 0, 0, CONTENT1, CSK)
    chk(scc0[16:32] != v2b(dropped_siv, 16),
        "a substituted Locality is not dropped from AD")
    no_sloc = new_unit(LST_NO_SLOC)
    m10 = make_mdh(localities=(10,))
    cl10 = CL(m10, CONTENT1)
    scc10 = export_cl(no_sloc, cl10)
    chk(len(scc10) == 32 + 16 * n1
        and scc10[16:32] == v2b(SCC_Encrypt([m10, 0], 0, 0, CONTENT1, CSK)[0], 16)
        and cl10.snapshot() == (m10, tuple(CONTENT1), None),
        "an export naming an unconfigured SLocality is not refused: LST_eff "
        "is zeros(128), and the completion restores the CL with it")
    cl, res = import_image(no_sloc, Mem(scc10))
    chk(res == 'kl_state_invalid' and cl.mdh == put(0, 'State', 49),
        "... and its import there is invalid Metadata, not an authentication "
        "failure")
    chk(import_image(unit, Mem(scc10))[1] == 'kl_state_mgmt_auth',
        "... and where SLocality is configured it fails authentication")

    # ------------------------------------------------------------------
    print("\n-- the Auxiliary Data Section")
    mdh_i = make_mdh(localities=LOC_SETS[2], aux_data_len=AUX_LEN)
    scc_i = sealed(unit, mdh_i, CONTENT1, CONTENT2)
    off1, off2 = 64, 64 + 16 * n1                     # Content1, Content2
    chk(len(scc_i) == 64 + 16 * n1 + 16 * len(CONTENT2) == unit.kl_size(mdh_i),
        "SCC with AuxDataLen >= 2: length = kl.size = 64 + Content1 + Content2")
    chk(scc_i[32:48] == v2b(unit.impqual(), 16)
        and scc_i[32:48] == (IDS['klmvendorid'].to_bytes(4, 'little')
                             + IDS['klmarchid'].to_bytes(4, 'little')
                             + IDS['klmimpid'].to_bytes(4, 'little') + bytes(4)),
        "Section 3 is IMPQUAL = zeros(32) @ klmimpid @ klmarchid @ klmvendorid")
    AD1 = [mdh_i] + [LST[j] for j in LOC_SETS[2]]
    s1, c1 = SCC_Encrypt(AD1, 0, 0, CONTENT1, CSK)
    s2, c2 = SCC_Encrypt([unit.impqual(), s1], 0, 1, CONTENT2, CSK)
    chk(scc_i == v2b(mdh_i, 16) + v2b(s1, 16) + scc_i[32:48] + v2b(s2, 16)
        + ser(c1) + ser(c2),
        "section order MDH, SIV, IMPQUAL, SIV2, Content1, Content2 (<<KLEE-SCC>>)")

    unit.decrypts = []
    cl, res = import_image(unit, Mem(scc_i))
    chk(res == 'ok' and cl.snapshot() == (mdh_i, tuple(CONTENT1), tuple(CONTENT2))
        and unit.decrypts == [0, 1],
        "matching IMPQUAL: both segments authenticate; ADS retained, "
        "AuxDataLen preserved, ADSDropped 0")
    scc_re = export_cl(unit, cl)
    chk(scc_re == scc_i, "a retained ADS is exported again unchanged")

    m2 = make_mdh(localities=LOC_SETS[2], aux_data_len=2)
    scc_2 = sealed(unit, m2, CONTENT1, [])
    cl, res = import_image(unit, Mem(scc_2))
    chk(len(scc_2) == 64 + 16 * n1 and res == 'ok' and cl.content2 == []
        and fld(cl.mdh, 'AuxDataLen') == 2,
        "AuxDataLen = 2: an empty Content2 still carries IMPQUAL and SIV2")

    other = new_unit(ids=IDS_NEXT_REV)
    other.decrypts = []
    cl, res = import_image(other, Mem(scc_i))
    chk(res == 'ok' and cl.content1 == CONTENT1 and cl.content2 is None
        and fld(cl.mdh, 'AuxDataLen') == 0 and fld(cl.mdh, 'ADSDropped') == 0
        and other.decrypts == [0],
        "mismatching IMPQUAL: Content1 imports, Content2 is dropped without "
        "being decrypted, AuxDataLen -> 0")
    posing = scc_i[:32] + v2b(other.impqual(), 16) + scc_i[48:]
    other.decrypts = []
    cl, res = import_image(other, Mem(posing))
    chk(res == 'ok' and cl.content2 is None and other.decrypts == [0, 1]
        and fld(cl.mdh, 'AuxDataLen') == 0,
        "IMPQUAL rewritten to the importer's value: segment 2 fails "
        "(IMPQUAL is AD2[0]) and the ADS is dropped")
    flipped_q = unit.impqual() ^ (1 << 47)
    chk(SCC_Encrypt([flipped_q, s1], 0, 1, CONTENT2, CSK)[0] != s2,
        "sep = 1: AD2[0][47] (klmarchid bit 15) is authenticated, not cleared")

    small = new_unit(max_aux=AUX_LEN - 1)   # same qualifier: only the size decides
    small.decrypts = []
    mem = Mem(scc_i)
    cl, res = import_image(small, mem)
    chk(res == 'ok' and cl.content1 == CONTENT1 and cl.content2 is None
        and fld(cl.mdh, 'AuxDataLen') == 0 and small.decrypts == [0]
        and mem.hi == off2,
        "ADS larger than the importer's maximum: step 5 drops it, Content2 is "
        "not read, Content1 imports, AuxDataLen -> 0")
    cl = open_and_load(small, scc_i)
    chk(fld(cl.mdh, 'ADSDropped') == 1 and fld(cl.mdh, 'AuxDataLen') == AUX_LEN
        and cl.state() == KL_CFG_IMPORTING,
        "during that import K(i).MDH carries the working ADSDropped = 1 and "
        "the original AuxDataLen")

    regen = (3, [0x5EED])
    cl, res = import_image(other, Mem(scc_i), regen=regen)
    chk(res == 'ok' and fld(cl.mdh, 'AuxDataLen') == 3
        and fld(cl.mdh, 'ADSDropped') == 0 and cl.content2 == [0x5EED],
        "step 15: a replacement ADS sets AuxDataLen to its length (>= 2)")
    scc_r = export_cl(other, cl)
    cl2, res2 = import_image(other, Mem(scc_r))
    chk(scc_r[32:48] == v2b(other.impqual(), 16) and res2 == 'ok'
        and cl2.content2 == [0x5EED],
        "a later export emits the replacement ADS with the importer's IMPQUAL")
    cl, _ = import_image(other, Mem(scc_i))
    scc_n = export_cl(other, cl)
    chk(len(scc_n) == 32 + 16 * n1 and import_image(unit, Mem(scc_n))[1] == 'ok',
        "without a replacement a later export emits no ADS")

    # Grafting: segment 2 of SCC B onto SCC A.  AD2[1] = SIV differs, so
    # segment 2 fails; the ADS is dropped and segment 1 still imported.
    CONTENT1_B = [c ^ ((1 << 128) - 1) for c in CONTENT1]
    scc_b = sealed(unit, mdh_i, CONTENT1_B, CONTENT2)
    chk(scc_i[16:32] != scc_b[16:32], "the two SCCs have different SIVs")
    graft = scc_i[:48] + scc_b[48:64] + scc_i[off1:off2] + scc_b[off2:]
    cl, res = import_image(unit, Mem(graft))
    chk(res == 'ok' and cl.content1 == CONTENT1 and cl.content2 is None
        and fld(cl.mdh, 'AuxDataLen') == 0,
        "a grafted segment 2 is rejected; segment 1 imports, AuxDataLen -> 0")
    chk(scc_i[48:64] != scc_b[48:64],
        "SIV2 changes when SIV changes (segment binding)")
    chk(scc_i[off2:] != scc_b[off2:],
        "the segment-2 keystream changes when SIV changes")

    bad = 0
    for bit in list(flips(32, 64, 5)) + list(flips(off2, len(scc_i), 11)):
        cl, res = import_image(unit, Mem(tampered(scc_i, bit)))
        if not (res == 'ok' and cl.content1 == CONTENT1 and cl.content2 is None
                and fld(cl.mdh, 'AuxDataLen') == 0):
            bad += 1
    chk(bad == 0,
        "every change in IMPQUAL, SIV2 or Content2 drops the ADS and keeps "
        "Content1")
    bad = sum(import_image(unit, Mem(tampered(scc_i, bit)))[1]
              != 'kl_state_mgmt_auth' for bit in flips(off1, off2, 13))
    chk(bad == 0, "a change in Content1 rejects the whole SCC")

    # The segment separator (review finding m18): <<KLEE-SCC-AEAD>> puts sep
    # in bit 126 of both AES inputs.
    chk(_ctr_block(0, 0, 0) != _ctr_block(0, 1, 0),
        "sep separates the counter blocks even when the two SIVs are identical")
    chk(all(_ctr_block(x, sp, i).bit_length() <= 128
            for x in (0, MASK128, 0x5A5A << 32) for sp in (0, 1)
            for i in (0, 1, M32)),
        "counter block is 128 bits wide (1 + 1 + 94 + 32)")
    chk(sl(_ctr_block(MASK128, 0, 0), 127, 126) == 0b10
        and sl(_ctr_block(MASK128, 1, 0), 127, 126) == 0b11,
        "bit 127 = 1 (RFC 8452) and bit 126 = sep, overriding SIV[126]")
    enc0 = SCC_KeyDeriv(CSK, 0)[0]
    ks0 = [AESE256(enc0, _ctr_block(0x1234, 0, i)) for i in range(4)]
    ks1 = [AESE256(enc0, _ctr_block(0x1234, 1, i)) for i in range(4)]
    chk(all(x != y for x, y in zip(ks0, ks1)),
        "identical SIVs yield disjoint keystreams for the two segments")
    chk(_ctr_block(0, 0, 0) == _ctr_block(1 << 126, 0, 0),
        "SIV[126] no longer reaches the keystream input (94-bit SIV-derived IV)")
    chk(sl(_tag_block(MASK128, 0), 127, 126) == 0b00
        and sl(_tag_block(MASK128, 1), 127, 126) == 0b01,
        "tag input: bit 127 = 0 (RFC 8452 tag domain) and bit 126 = sep")
    chk(_tag_block(MASK128, 0).bit_length() <= 128
        and _tag_block(0, 1) == (1 << 126),
        "tag input is 128 bits wide (1 + 1 + 126)")
    t1, e1 = SCC_Encrypt(AD1, 0, 0, CONTENT1, CSK)
    t2, e2 = SCC_Encrypt(AD1, 0, 1, CONTENT1, CSK)
    chk(t1 != t2, "sep enters the tag: same AD and P give different SIVs")
    chk(e1 != e2, "sep enters the keystream: same AD and P give different C")
    chk(SCC_Decrypt(AD1, 0, 0, t1, e1, CSK)[0]
        and not SCC_Decrypt(AD1, 0, 1, t1, e1, CSK)[0],
        "a segment-1 payload does not authenticate when read with sep = 1")
    chk(_tag_block(0, 0) == _tag_block(1 << 126, 0),
        "POLYVAL bit 126 no longer reaches the tag input (126-bit tag input)")

    # ------------------------------------------------------------------
    print("\n-- _ADSDropped_, an unauthenticated format hint "
          "(<<KLEE-Auxiliary-Data-Section>>)")
    policy_fields = [f for f in FIELD if f not in ('AuxDataLen', 'ADSDropped')]
    ref_cl, _ = import_image(unit, Mem(scc_i))
    no_ads = (put(mdh_i, 'AuxDataLen', 0), tuple(CONTENT1), None)

    # Setting it in an SCC: "import also accepts the same layout when the bit
    # was set by modifying an SCC" (<<KLEE-data-formats>>).
    set47 = tampered(scc_i, 47)
    mem = Mem(set47)
    cl, res = import_image(unit, mem)
    chk(res == 'ok' and cl.snapshot() == no_ads
        and all(fld(cl.mdh, f) == fld(ref_cl.mdh, f) for f in policy_fields),
        "setting it drops Content2 only: Content1 and every policy field are "
        "those of the untouched import")
    chk(mem.hi == off2,
        "with it set, the import reads up to Content1 and no Content2 byte")
    short = set47[:off2]                             # the layout without Content2
    padded = short[:32] + bytes(range(0x60, 0x80)) + short[64:]
    chk(all(import_image(unit, Mem(img))[0].snapshot() == no_ads
            for img in (short, padded)),
        "with it set, IMPQUAL and SIV2 are ignored layout padding and "
        "Content1 stays at offset 48")

    # Clearing it requests second-segment processing on whatever follows
    # Content1; the failure drops Content2 and keeps Content1.
    unit.decrypts = []
    cl, res = import_image(unit, Mem(tampered(padded, 47)))
    chk(res == 'ok' and cl.snapshot() == no_ads and unit.decrypts == [0],
        "clearing it over junk IMPQUAL: segment 2 fails at the qualifier "
        "check; Content1 kept, Content2 dropped")
    unit.decrypts = []
    cl, res = import_image(unit, Mem(tampered(short, 47)))
    chk(res == 'ok' and cl.snapshot() == no_ads and unit.decrypts == [0, 1],
        "clearing it over the genuine IMPQUAL and SIV2 but no Content2: "
        "segment 2 fails authentication; Content1 kept, Content2 dropped")

    # KLEE itself produces ADSDropped = 1 only in an SCC-shaped PCCC: a nested
    # export of an import whose ADS was dropped (<<KLEE-data-formats>>).
    cl = open_and_load(small, scc_i)
    pccc = export_pccc(small, cl)
    pm = b2v(pccc[:16])
    chk(pm == put(put(mdh_i, 'ADSDropped', 1), 'State', KL_CFG_IMPORTING)
        and len(pccc) == off2 == small.kl_size(pm)
        and pccc[16:off2] == scc_i[16:off2],
        "SCC-shaped PCCC of a dropped import: the saved MDH (kl_cfg_importing, "
        "ADSDropped 1), then SIV, IMPQUAL, SIV2 and the Content1 ciphertext "
        "verbatim; length = kl.size")
    chk(cl.state() == KL_CFG_IMPORTING and fld(cl.mdh, 'ADSDropped') == 1,
        "the nested completion restores kl_cfg_importing")
    cl = reimport_pccc(small, pccc)
    chk(cl.state() == KL_CFG_IMPORTING and fld(cl.mdh, 'ADSDropped') == 1
        and cl.content2 is None,
        "re-import of that PCCC: working ADSDropped = 1, no Content2 loaded")
    small.mgmt_complete(cl, mdh_i)                    # the base completion
    chk(outcome(cl) == 'ok' and cl.snapshot() == no_ads,
        "the base completion authenticates Content1 with bit 47 cleared in "
        "its copy; AuxDataLen -> 0, ADSDropped -> 0")
    pccc_nc = pccc

    # Clearing it in that PCCC: the same importer sets it again at step 5; an
    # importer that can hold the ADS accepts only the authentic Content2.
    pccc_clr = tampered(pccc, 47)
    cl = reimport_pccc(small, pccc_clr)
    small.mgmt_complete(cl, mdh_i)
    chk(cl.snapshot() == no_ads,
        "clearing it in the PCCC: an importer too small for the ADS drops it "
        "again")
    for tail, want, what in (
            (bytes(16 * len(CONTENT2)), no_ads,
             "zeros after it: segment 2 fails, Content1 kept"),
            (scc_i[off2:], ref_cl.snapshot(),
             "the genuine Content2 ciphertext after it: only the authentic "
             "ADS is restored")):
        cl = reimport_pccc(unit, pccc_clr + tail)
        unit.mgmt_complete(cl, mdh_i)
        chk(outcome(cl) == 'ok' and cl.snapshot() == want,
            f"clearing it in the PCCC, {what}")

    cl = open_and_load(unit, scc_i)
    pccc_full = export_pccc(unit, cl)
    cl = reimport_pccc(unit, pccc_full)
    unit.mgmt_complete(cl, mdh_i)
    chk(len(pccc_full) == len(scc_i) and outcome(cl) == 'ok'
        and cl.snapshot() == ref_cl.snapshot(),
        "a PCCC of an import that kept its ADS carries Content2 and completes "
        "with the ADS retained")
    cl = reimport_pccc(unit, tampered(pccc_full, 47))
    unit.mgmt_complete(cl, mdh_i)
    chk(outcome(cl) == 'ok' and cl.content1 == CONTENT1 and cl.content2 is None
        and fld(cl.mdh, 'AuxDataLen') == 0,
        "setting bit 47 in that PCCC only drops the ADS")

    # ------------------------------------------------------------------
    print("\n-- Error States (<<KLEE-error-state-transfer>>)")
    bad_c1 = tampered(scc_i, 8 * (off1 + 6))         # a Content1 byte changed
    cl_fail, res = import_image(unit, Mem(bad_c1))
    failed_mdh = (mdh_i & ~((((1 << 14) - 1) << 32) | (0x3F << 19))) | (51 << 19)
    chk(res == 'kl_state_mgmt_auth' and cl_fail.snapshot() == (failed_mdh, (), None),
        "authentication failure: State 51, Content cleared, AuxDataLen and "
        "ADSDropped 0, the other MDH fields kept (SGR10)")
    cl, res = import_image(small, Mem(bad_c1))       # working ADSDropped = 1
    chk(res == 'kl_state_mgmt_auth' and cl.snapshot() == (failed_mdh, (), None),
        "the same holds when the failing import had dropped its ADS")
    before = (unit.reg_SIV, unit.reg_IMPQUAL, unit.reg_SIV2)
    img_e = export_cl(unit, cl_fail)
    chk(img_e == v2b(cl_fail.mdh, 16) and unit.kl_size(cl_fail.mdh, 'A') == 16
        and (unit.reg_SIV, unit.reg_IMPQUAL, unit.reg_SIV2) == before,
        "an Error-State CL exports as its 16-byte MDH (kl.getmd), with no "
        "kl.mgmt and no SIV")
    chk(export_cl(new_unit(LST_ALT, csk=CSK ^ 5), CL(cl_fail.mdh)) == img_e,
        "the Error-State image depends on neither the CSK nor the Locality "
        "Secrets")
    snap = cl_fail.snapshot()
    unit.mgmt_open_export(cl_fail)
    chk(cl_fail.snapshot() == snap,
        "kl.mgmt #kl_cfg_exporting on an Error-State CL leaves it unchanged")
    far = new_unit(LST_NO_SLOC, ids=IDS_NEXT_REV, csk=CSK ^ 7, max_aux=0)
    cl_e, res = import_image(far, Mem(img_e))
    chk(res == 'kl_state_mgmt_auth' and cl_e.snapshot() == snap,
        "short import elsewhere (other CSK, LST, implementation) reproduces the "
        "Error-State CL")
    try:
        far.mgmt_complete(cl_e, cl_e.mdh)
        raised = False
    except IllegalInstruction:
        raised = True
    chk(raised, "no management operation is open: kl_cfg_management_end is "
                "an illegal instruction")
    try:
        far.load(cl_e, Mem(img_e))
        raised = False
    except IllegalInstruction:
        raised = True
    chk(raised, "kl.load on an Error-State CL is an illegal instruction (SGR21)")

    dirty_body = make_mdh(machine=0xFFF, machine_policy=0, key_type=3,
                          aux_data_len=5, ads_dropped=1, usage_policy=0b10101,
                          machine_extension=2, sc_protection=7,
                          state_extension=0xF, aux_info=0x155,
                          machine_use=0xBEEF, expiration_date=0xFFFFF,
                          version=2)
    dirty_body = put(dirty_body, 'Locality', 0x1FF)
    for r in RESERVED:
        hi, lo = FIELD[r]
        dirty_body |= ((1 << (hi - lo + 1)) - 1) << lo
    bad = []
    for st in range(48, 56):
        dirty = put(dirty_body, 'State', st)
        unit.reg_SIV, unit.reg_IMPQUAL, unit.reg_SIV2 = 1, 2, 3
        cl_d = CL()
        unit.mgmt_open_import(cl_d, dirty)
        want_st = 49 if st in (54, 55) else st
        mask = ~((((1 << 14) - 1) << 32) | (1 << 47) | (0x3F << 19))
        want = (dirty & mask) | (want_st << 19)
        if not (cl_d.snapshot() == (want, (), None) and unit.kl_size(dirty) == 16
                and export_cl(unit, cl_d) == v2b(want, 16)
                and (unit.reg_SIV, unit.reg_IMPQUAL, unit.reg_SIV2) == (1, 2, 3)):
            bad.append(st)
    chk(not bad,
        "Error States 48-55: the short import installs the whole MDH without "
        "validity checks, AuxDataLen and ADSDropped 0, 54 and 55 as Invalid"
        + (f" -- failing: {bad}" if bad else ""))
    chk(import_image(unit, Mem(v2b(put(dirty_body, 'State', 1), 16)))[1]
        == 'kl_exc_unsupported',
        "the same MDH naming a Valid State is checked (unsupported)")
    info("the short import neither opens a management operation nor zeroizes "
         "the SIV/IMPQUAL/SIV2 registers: <<KLEE-CLF>> zeroizes them for 'a "
         "kl.mgmt that opens an import', and <<KLEE-error-state-transfer>> "
         "says the registers take no part in either path")

    # ------------------------------------------------------------------
    print("\nKAT-EXPECT-FAIL: length-block")
    lb = cat((bin_(16 * n1 * 8, 64), 64),
             (bin_(16 * (1 + len(LOC_SETS[2])) * 8, 64), 64))
    AD = [mdh] + [LST[j] for j in LOC_SETS[2]]
    siv_lb, c_lb = SCC_Encrypt(AD, 0, 0, CONTENT1, CSK, length_block=lb)
    fired = v2b(siv_lb, 16) != scc[16:32]
    print(f"{'FAIL (expected)' if fired else 'PASS'}  "
          f"length-block restoring the RFC 8452 length block changes the SIV")
    chk(fired, "negative control fired: the length-block omission is observable")
    scc_lb = scc[:16] + v2b(siv_lb, 16) + ser(c_lb)
    chk(import_image(unit, Mem(scc_lb))[1] == 'kl_state_mgmt_auth',
        "an SCC sealed with a length block does not import under the spec rule")

    print("\nKAT-EXPECT-FAIL: no-ads-clear")
    cl = reimport_pccc(small, pccc_nc)
    small.mgmt_complete(cl, mdh_i, clear_ads_dropped=False)
    fired = outcome(cl) != 'ok'
    print(f"{'FAIL (expected)' if fired else 'PASS'}  "
          f"no-ads-clear authenticating AD[0] with bit 47 kept rejects the "
          f"dropped-ADS PCCC")
    chk(fired and outcome(cl) == 'kl_state_mgmt_auth',
        "negative control fired: the clearing of AD[0][47] is observable")

    # ------------------------------------------------------------------
    print("\nRegression vectors for the KLEE sealing variant "
          "(CSK = 000102..1f, LST[j] = 16 x (0x40+j), AES256_ECB key 8081..9f):")
    for locs in LOC_SETS:
        m, s = sccs[locs]
        got = (v2b(m, 16).hex(), s[16:32].hex(), s[32:48].hex())
        print(f"  Localities {str(tuple(locs)):<20} MDH   = {got[0]}")
        print(f"  {'':31} SIV   = {got[1]}")
        print(f"  {'':31} C1[0] = {got[2]}")
        chk(got == REGRESSION[locs],
            f"REGRESSION  SCC for Localities {locs or '(none)'}")
    got = {'MDH': scc_i[:16].hex(), 'SIV': scc_i[16:32].hex(),
           'IMPQUAL': scc_i[32:48].hex(), 'SIV2': scc_i[48:64].hex(),
           'C2[0]': scc_i[off2:off2 + 16].hex()}
    print(f"  AuxDataLen = {AUX_LEN}, Localities {LOC_SETS[2]}:")
    for key in ('MDH', 'SIV', 'IMPQUAL', 'SIV2', 'C2[0]'):
        print(f"  {'':31} {key:<7}= {got[key]}")
    chk(got == REGRESSION_ADS, "REGRESSION  SCC with an ADS")
    print(f"  Error-State image (16 B), CL after a failed import = {img_e.hex()}")
    chk(img_e.hex() == REGRESSION_ERROR_IMAGE,
        "REGRESSION  Error-State image")

    # ------------------------------------------------------------------
    print()
    info("the sealing construction has no published vectors of its own "
         "(<<KLEE-SCC-AEAD>> omits the nonce and the length block, puts sep in "
         "bit 126 of both AES inputs and clears ADSDropped in AD[0]); the "
         "RFC 8452 cross-checks above anchor everything but those deviations.")
    info("review finding m18 stays fixed on both sides: 0 @ sep @ "
         "POLYVAL(...)[125:0] for the tag and 1 @ sep @ SIV[125:32] @ counter "
         "for the keystream; the price, checked above and stated in the "
         "<<KLEE-SCC-AEAD>> NOTE, is one bit on each side.")
    spec_note("<<KLEE-SCC-AEAD>> lists three differences from AES-GCM-SIV, but "
              "SCC_Encrypt/SCC_Decrypt now have a fourth: for sep = 0, "
              "AD_auth[0][47] (ADSDropped) is cleared in a local copy. Only the "
              "SIV NOTE of that section mentions it; the list should too.")
    spec_note("_ContentOffset_, content_size, max_admissible, image_size, "
              "image_end and S are now defined in <<KLEE-instruction-mv>>, yet "
              "<<KLEE-SCC-GCM-SIV-enc>> (len_PC bound), "
              "<<KLEE-Memory-Alignment>>, the PCCC paragraph of "
              "<<KLEE-data-formats>>, kl.store and kl.mv itself cite "
              "<<KLEE-instruction-load>>, which only refers back to kl.mv. "
              "This harness cites <<KLEE-instruction-mv>>.")
    spec_note("<<KLEE-CL-management>> (kl.mgmt opening, Error-State branch) "
              "configures the CL 'in that Error State' without the mapping of "
              "54 and 55 to Invalid that <<KLEE-error-state-transfer>> and "
              "kl.setst state; this harness applies the mapping.")
    spec_note("<<KLEE-import-and-DIEL>> item 4 says an unsupported ADS 'is "
              "skipped or only partially loaded', but step 5 of "
              "<<KLEE-SCC-import>> now sets ADSDropped, after which step 6 and "
              "max_admissible load no Content2 byte at all.")

    print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
