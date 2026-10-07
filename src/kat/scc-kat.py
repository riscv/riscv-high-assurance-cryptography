#!/usr/bin/env python3
"""SCC sealing and export/import, MDH, SCC/PCCC layout, kl.size, kl.load/kl.store, klmanagedlocker and
Error-State transfer, on a model unit implementing only AES256_ECB. Primitives are anchored on FIPS 197
and RFC 8452 (length block restored); the procedures by self-consistency and regression vectors."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bin_, montmul, mulx_polyval, aes_encrypt, aes_decrypt, MASK128,
                    selftest, MDH_FIELDS, MDH_FIELD, IllegalInstruction, KL_STATE_UNCONFIGURED as UNCONF,
                    KL_STATE_READY as READY, KL_STATE_ENCRYPT as ENCRYPT, KL_STATE_DECRYPT as DECRYPT,
                    KL_STATE_SUCCESS, KL_STATE_INVALID as INVALID, KL_STATE_MGMT_AUTH as AUTH,
                    KL_STATE_EXPIRED as EXPIRED, ERROR_STATES, KL_CFG_PROVISIONING,
                    KL_CFG_EXPORTING as EXPORTING, KL_CFG_IMPORTING as IMPORTING, KL_CFG_PPI_EXPORTING,
                    KL_CFG_PPI_IMPORTING,
                    section, check, control, info, raises, done)

M32 = (1 << 32) - 1

# ---------------------------------------------------------------- <<KLEE-SCC-AEAD>>, literally
def AESE256(K, B):
    return b2v(aes_encrypt(v2b(K, 32), v2b(B, 16)))

def SCC_KeyDeriv(key, nonce):                 # <<KLEE-SCC-key-derivation>>
    A = [sl(AESE256(key, cat((nonce, 96), (bin_(i, 32), 32))), 63, 0) for i in range(6)]
    return cat(*[(a, 64) for a in A[5:1:-1]]), cat((A[1], 64), (A[0], 64))

def POLYVAL(auth_key, blocks):                # <<KLEE-SCC-POLYVAL>>
    tmp = 0
    for blk in blocks:
        tmp = montmul(tmp ^ blk, auth_key)
    return tmp

def tag_block(S, sep):                        # 0 @ sep @ S[125:0]
    return cat((0, 1), (sep & 1, 1), (sl(S, 125, 0), 126))

def ctr_block(SIV, sep, i):                   # 1 @ sep @ SIV[125:32] @ bin((int(SIV[31:0]) + i) mod 2^32, 32)
    return cat((1, 1), (sep & 1, 1), (sl(SIV, 125, 32), 94), ((sl(SIV, 31, 0) + i) & M32, 32))

def _tag(AD, N, sep, P, K, length_block, clear_ads):
    """The common part of <<KLEE-SCC-GCM-SIV-enc>>/<<KLEE-SCC-GCM-SIV-dec>>. length_block (RFC 8452's)
    and clear_ads=False are harness-only, for the RFC cross-checks and the negative controls."""
    enc_key, auth_key = SCC_KeyDeriv(K, N)
    AD_auth = list(AD)
    if sep == 0 and clear_ads and AD_auth:
        AD_auth[0] &= ~(1 << 47)
    S = POLYVAL(auth_key, AD_auth + list(P) + ([] if length_block is None else [length_block]))
    return enc_key, AESE256(enc_key, tag_block(S ^ N, sep))     # S[95:0] xor N; N is 96 bits

def SCC_Encrypt(AD, N, sep, P, K, length_block=None, clear_ads=True):
    enc_key, SIV = _tag(AD, N, sep, P, K, length_block, clear_ads)
    return SIV, [p ^ AESE256(enc_key, ctr_block(SIV, sep, i)) for i, p in enumerate(P)]

def SCC_Decrypt(AD, N, sep, SIV, C, K, length_block=None, clear_ads=True):
    enc_key = SCC_KeyDeriv(K, N)[0]
    P = [c ^ AESE256(enc_key, ctr_block(SIV, sep, i)) for i, c in enumerate(C)]
    ok = _tag(AD, N, sep, P, K, length_block, clear_ads)[1] == SIV
    return ok, P if ok else [0] * len(C)

# ---------------------------------------------------------------- MDH, States, Localities
fld = lambda m, name: sl(m, *MDH_FIELD[name])
RESERVED = [(hi, lo) for n, hi, lo in MDH_FIELDS if n is None]

def put(m, name, x):
    hi, lo = MDH_FIELD[name]
    assert 0 <= x < 1 << (hi - lo + 1), (name, x)
    return m & ~(((1 << (hi - lo + 1)) - 1) << lo) | x << lo

def field_at(bit):
    return next((n or 'Reserved', hi, lo) for n, hi, lo in MDH_FIELDS if lo <= bit <= hi)

AES256_ECB = cat((2, 8), (0, 4))              # <<KLEE-exec-encodings>>: Type 2, Mode 0
ECB_STATES = (READY, ENCRYPT, DECRYPT)        # <<KLEE-ECB-mode>>
ERR_NAME = {48: 'kl_state_unsupported', 49: 'kl_state_invalid', 50: 'kl_state_out_of_memory',
            51: 'kl_state_mgmt_auth', 52: 'kl_state_priv_violation', 53: 'kl_state_expired'}
is_valid = lambda st: 1 <= st <= 47
is_complete = lambda st: 1 <= st <= 55
base_type = lambda st: ('pi' if st in (KL_CFG_PROVISIONING, KL_CFG_PPI_EXPORTING, KL_CFG_PPI_IMPORTING)
                        else 'scc' if st in (EXPORTING, IMPORTING) else None)

# <<KLEE-locality-indexes>>: index -> ((hi, lo) within the Locality field, value)
LOCALITY_ENC = {0: ((1, 0), 1), 1: ((1, 0), 2), 2: ((1, 0), 3), 3: ((3, 2), 1), 4: ((3, 2), 2),
                5: ((3, 2), 3), 6: ((5, 4), 1), 7: ((5, 4), 2), 8: ((6, 6), 1), 9: ((7, 7), 1), 10: ((8, 8), 1)}
HW_CHAIN_NEXT = {0: 1, 1: 2, 2: None, 3: 4, 4: 5, 5: None}   # <<KLEE-Localities>> substitution chains

def locality_field(indices):
    f = 0
    for j in indices:
        (hi, lo), val = LOCALITY_ENC[j]
        assert sl(f, hi, lo) == 0
        f |= val << lo
    return f

def localities_of(mdh):                        # in index order, as <<KLEE-SCC-export>> step 1.c appends them
    return [j for j, ((hi, lo), val) in LOCALITY_ENC.items() if sl(fld(mdh, 'Locality'), hi, lo) == val]

def make_mdh(localities=(), **f):
    return sum(v << MDH_FIELD[n][1] for n, v in {'Machine': AES256_ECB, 'MachinePolicy': 1, 'State': READY,
               **f, 'Locality': locality_field(localities)}.items())

# ---------------------------------------------------------------- layout (<<KLEE-instruction-mv>>)
def content_offset(mdh):                       # ADSDropped never affects it
    st, aux = fld(mdh, 'State'), fld(mdh, 'AuxDataLen')
    if is_valid(st) or st in (IMPORTING, EXPORTING):
        assert aux != 1
        return 48 if aux else 16
    assert base_type(st) == 'pi'
    return 0

def content2_size(mdh):
    aux = fld(mdh, 'AuxDataLen')
    return 16 * (aux - 2) if aux >= 2 and not fld(mdh, 'ADSDropped') else 0

ser = lambda blocks: b''.join(v2b(b, 16) for b in blocks)
deser = lambda d: [b2v(d[i:i + 16]) for i in range(0, len(d), 16)]

class Mem:
    """An image in memory; reads beyond it return zeros; `hi` records the highest offset read."""
    def __init__(self, data):
        self.data, self.hi = bytes(data), 0

    def read(self, off, n):
        self.hi = max(self.hi, off + n)
        return (self.data[off:off + n] + bytes(n))[:n]

class KleeException(Exception):
    pass

class Locker:
    def __init__(self, mdh=0, c1=None, c2=None, idx=0):
        self.idx, self.mdh = idx, mdh
        self.content1 = None if c1 is None else list(c1)
        self.content2 = None if c2 is None else list(c2)

    state = property(lambda s: fld(s.mdh, 'State'))

    def snapshot(self):
        return self.mdh, tuple(self.content1 or ()), None if self.content2 is None else tuple(self.content2)

def err_mdh(m, st):                            # <<KLEE-GR-clear-locker-content-error-state>>
    return put(put(put(m, 'State', st), 'AuxDataLen', 0), 'ADSDropped', 0)

def enter_error_state(cl, st):
    cl.content1, cl.content2, cl.mdh = None, None, err_mdh(cl.mdh, st)

def outcome(cl):
    st = cl.state
    return 'ok' if is_valid(st) else ERR_NAME.get(st, f'State {st}')

# ---------------------------------------------------------------- the KLEE unit of one hart
class Unit:
    SC_LEVELS, VERSIONS = (0, 1, 2), (0,)

    def __init__(self, CSK, LST, klmvendorid, klmarchid, klmimpid, max_aux=16, zklexpire=True):
        self.CSK, self.LST, self.max_aux, self.zklexpire = CSK, dict(LST), max_aux, zklexpire
        self.ids = (klmvendorid, klmarchid, klmimpid)
        self.reg_SIV = self.reg_IMPQUAL = self.reg_SIV2 = 0     # <<KLEE-KLF>>
        self.klmanagedlocker, self.decrypts = 32, []            # decrypts: sep of each SCC_Decrypt

    def _check_managed(self, cl):              # <<KLEE-locker-management>>, common step 1
        if self.klmanagedlocker not in (cl.idx, 32):
            raise IllegalInstruction

    def _set_managed(self, cl):                # common step 2
        self.klmanagedlocker = cl.idx if KL_CFG_PROVISIONING <= cl.state <= 60 else 32

    def _check_transfer(self, cl):             # GR38, GR39
        if cl.state in (IMPORTING, EXPORTING) and cl.idx != self.klmanagedlocker:
            raise IllegalInstruction

    def impqual(self):                         # zeros(32) @ klmimpid @ klmarchid @ klmvendorid
        v, a, i = self.ids
        return cat((0, 32), (i, 32), (a, 32), (v, 32))

    def _substitute(self, j):                  # None: unconfigured, no replacement
        if j in HW_CHAIN_NEXT:
            while j is not None and self.LST.get(j) is None:
                j = HW_CHAIN_NEXT[j]
            return None if j is None else self.LST[j]
        return self.LST.get(j) or None

    def lst_eff(self, j):                      # LST_eff of <<KLEE-SCC-export>>
        return self._substitute(j) or 0

    def content1_size(self, mdh):              # AES256_ECB: 256-bit key or 64-bit SKID
        return 32 if fld(mdh, 'KeyType') == 0 else 16

    def max_admissible(self, mdh):
        return self.content1_size(mdh) + 16 * max(0, self.max_aux - 2)

    def metadata_check(self, M, base, at_import=False, low_only=False):
        """<<KLEE-Metadata-validity>>: None, 'unsupported' or 'invalid'; low_only: MDH[63:0] only."""
        if (fld(M, 'MachineExtension') or fld(M, 'Machine') != AES256_ECB
                or fld(M, 'SCProtection') not in self.SC_LEVELS + (3,)):        # 3 is reserved: invalid
            return 'unsupported'
        st, loc = fld(M, 'State'), fld(M, 'Locality')
        custom = fld(M, 'Machine') >= 3072 or fld(M, 'Version') == 3
        invalid = (any(sl(M, hi, lo) for hi, lo in RESERVED if hi < 64) or fld(M, 'AuxDataLen') == 1
                   or base == 'pi' and (fld(M, 'ADSDropped') or fld(M, 'AuxDataLen'))
                   or fld(M, 'MachinePolicy') == 0 or fld(M, 'KeyType') >= 2 or fld(M, 'SCProtection') == 3
                   or fld(M, 'Version') not in self.VERSIONS or st in (54, 55)
                   or is_valid(st) and (st not in ECB_STATES or fld(M, 'StateExtension'))   # ECB uses none
                   or at_import and st in (0, 61, 62, 63))
        if not low_only:
            invalid = invalid or (any(sl(M, hi, lo) for hi, lo in RESERVED if hi >= 64) or sl(loc, 5, 4) == 3
                                  or any(self._substitute(j) is None for j in localities_of(M))
                                  or fld(M, 'ExpirationDate') and not self.zklexpire
                                  or custom and sl(loc, 1, 0) < 2)          # <<KLEE-GR-custom-locality>>
        return 'invalid' if invalid else None

    def kl_size(self, mdh, form='C'):          # <<KLEE-instruction-size>>
        mdh &= (1 << 64) - 1 if form == 'B' else (1 << 128) - 1
        st = fld(mdh, 'State')
        if form == 'A' and st == UNCONF:
            return 0
        if form != 'A' and st not in ERROR_STATES and (st in (61, 62, 63) or self.metadata_check(
                mdh, 'pi' if st == 0 or base_type(st) == 'pi' else 'scc', low_only=form == 'B')):
            return 0
        if st in ERROR_STATES:
            return 16
        if is_valid(st) or st in (IMPORTING, EXPORTING):
            return (64 + content2_size(mdh) if fld(mdh, 'AuxDataLen') else 32) + self.content1_size(mdh)
        return 16 + self.content1_size(mdh)    # PI: same key field

    # kl.mgmt #kl_cfg_importing: <<KLEE-SCC-import>> steps 1-5, or the short import
    def mgmt_open_import(self, cl, ml):
        self._check_managed(cl)
        try:
            self._open_import(cl, ml)
        finally:
            self._set_managed(cl)

    def _open_import(self, cl, ml):
        cl.__init__(idx=cl.idx)                # step 1: clear
        st = fld(ml, 'State')
        if st in ERROR_STATES:                 # <<KLEE-error-state-transfer>>; Expired without Zklexpire: read
            st = INVALID if st in (54, 55) or st == EXPIRED and not self.zklexpire else st
            cl.mdh = err_mdh(ml, st)
            return
        chk = self.metadata_check(ml, base_type(st) or 'scc', at_import=True)
        if chk == 'unsupported':
            raise KleeException('kl_exc_unsupported')
        if chk:
            cl.mdh = put(0, 'State', INVALID)  # every other MDH field stays zero
            return
        assert base_type(st) != 'pi', 'PI-shaped images are not modelled'
        aux = fld(ml, 'AuxDataLen')           # step 5: working ADSDropped
        dropped = int(aux >= 2 and (fld(ml, 'ADSDropped') == 1 or aux > self.max_aux))
        cl.mdh = put(put(ml, 'ADSDropped', dropped), 'State', IMPORTING)

    def load(self, cl, mem, at=16):            # kl.load: step 6
        if cl.state == UNCONF or cl.state in ERROR_STATES:
            return                             # GR35: no operation
        if cl.state not in (KL_CFG_PROVISIONING, IMPORTING, KL_CFG_PPI_IMPORTING):
            raise IllegalInstruction           # GR38
        self._check_transfer(cl)
        off, c1 = content_offset(cl.mdh), self.content1_size(cl.mdh)
        end = off + min(c1 + content2_size(cl.mdh), self.max_admissible(cl.mdh))   # image_end
        S = mem.read(at, end)
        self.reg_SIV = b2v(S[:16])
        if off == 48:
            self.reg_IMPQUAL, self.reg_SIV2 = b2v(S[16:32]), b2v(S[32:48])
        cl.content1 = deser(S[off:off + c1])
        has_c2 = fld(cl.mdh, 'AuxDataLen') >= 2 and not fld(cl.mdh, 'ADSDropped')
        cl.content2 = deser(S[off + c1:end]) if has_c2 else None

    def mgmt_open_export(self, cl):            # kl.mgmt #kl_cfg_exporting: <<KLEE-SCC-export>>
        self._check_managed(cl)
        st = cl.state
        if st == UNCONF:                       # GR35: common steps only
            self.klmanagedlocker = 32
            return
        if is_valid(st):
            AD = [cl.mdh] + [self.lst_eff(j) for j in localities_of(cl.mdh)]      # 1.a-1.c
            self.reg_SIV, cl.content1 = SCC_Encrypt(AD, 0, 0, cl.content1, self.CSK)
            aux = fld(cl.mdh, 'AuxDataLen')
            if aux >= 2:                       # 2: an ADS producer has klmimpid != 0
                assert self.ids[2] and len(cl.content2) == aux - 2
                self.reg_IMPQUAL = self.impqual()
                self.reg_SIV2, cl.content2 = SCC_Encrypt([self.reg_IMPQUAL, self.reg_SIV], 0, 1,
                                                         cl.content2, self.CSK)
        if st not in ERROR_STATES:             # Error State: unchanged, nothing opened
            assert base_type(st) != 'pi', 'PI-shaped images are not modelled'
            cl.mdh = put(cl.mdh, 'State', EXPORTING)   # nested: exported verbatim
        self._set_managed(cl)

    def store(self, cl):                       # kl.store
        if cl.state == UNCONF:
            return b''                         # GR35: no operation
        if cl.state not in (EXPORTING, KL_CFG_PPI_EXPORTING):
            raise IllegalInstruction           # GR39
        self._check_transfer(cl)
        S = v2b(self.reg_SIV, 16) + (v2b(self.reg_IMPQUAL, 16) + v2b(self.reg_SIV2, 16)
                                     if content_offset(cl.mdh) == 48 else b'')
        S += ser(cl.content1) + (ser(cl.content2) if content2_size(cl.mdh) else b'')
        assert len(S) == self.kl_size(cl.mdh, 'A') - 16          # image_size
        return S

    def mgmt_complete(self, cl, ml, regen=None, clear_ads=True):
        """kl_cfg_management_end for base type scc: <<KLEE-SCC-import>> steps 7-15. regen = (AuxDataLen,
        Content2) of a replacement ADS; clear_ads=False is the harness-only negative control."""
        self._check_managed(cl)
        if cl.state == UNCONF or cl.state in ERROR_STATES:   # GR35: common steps only
            self.klmanagedlocker = 32
            return
        st = fld(ml, 'State')
        if cl.state not in (IMPORTING, EXPORTING) or not (is_complete(st) or st in (IMPORTING, EXPORTING)):
            raise IllegalInstruction
        cl.mdh = put(cl.mdh, 'State', st)     # ml is consumed only for its State
        if is_complete(st):                    # nested completions do not authenticate
            self._authenticate(cl, regen, clear_ads)
        self._set_managed(cl)

    def _authenticate(self, cl, regen, clear_ads):
        AD = [cl.mdh] + [self.lst_eff(j) for j in localities_of(cl.mdh)]          # steps 7-9
        self.decrypts.append(0)
        ok, cl.content1 = SCC_Decrypt(AD, 0, 0, self.reg_SIV, cl.content1, self.CSK, clear_ads=clear_ads)
        if not ok:                             # step 12
            return enter_error_state(cl, AUTH)
        if fld(cl.mdh, 'AuxDataLen') >= 2 and not fld(cl.mdh, 'ADSDropped'):      # steps 13-14
            ok = self.reg_IMPQUAL == self.impqual()
            if ok:
                self.decrypts.append(1)
                ok, cl.content2 = SCC_Decrypt([self.reg_IMPQUAL, self.reg_SIV], 0, 1, self.reg_SIV2,
                                              cl.content2, self.CSK)
            if not ok:
                cl.content2, cl.mdh = None, put(cl.mdh, 'ADSDropped', 1)
        if fld(cl.mdh, 'AuxDataLen') == 0 or fld(cl.mdh, 'ADSDropped'):          # step 15
            aux, cl.content2 = regen or (0, None)
            cl.mdh = put(cl.mdh, 'AuxDataLen', aux)
        cl.mdh = put(cl.mdh, 'ADSDropped', 0)

# ---------------------------------------------------------------- software sequences
def export_cl(unit, cl):
    """kl.size, kl.getmd and, unless the image is the 16-byte Error-State MDH, kl.mgmt, kl.store, kl.mgmt."""
    size, ml = unit.kl_size(cl.mdh, 'A'), cl.mdh
    if size == 16:
        return v2b(ml, 16)
    unit.mgmt_open_export(cl)
    image = v2b(ml, 16) + unit.store(cl)
    unit.mgmt_complete(cl, ml)
    assert len(image) == size
    return image

def import_image(unit, mem, ml=None, regen=None, clear_ads=True):
    M, cl = b2v(mem.read(0, 16)), Locker()
    try:
        unit.mgmt_open_import(cl, M)
    except KleeException as e:
        return cl, e.args[0]
    if cl.state == IMPORTING:
        unit.load(cl, mem)
        unit.mgmt_complete(cl, M if ml is None else ml, regen, clear_ads)
    return cl, outcome(cl)

def open_and_load(unit, image):               # an import preempted before its completion
    cl, mem = Locker(), Mem(image)
    unit.mgmt_open_import(cl, b2v(mem.read(0, 16)))
    unit.load(cl, mem)
    return cl

def export_pccc(unit, cl):                     # nested export: saved MDH, then the SCC-shaped image verbatim
    ml = cl.mdh
    unit.mgmt_open_export(cl)
    image = v2b(ml, 16) + unit.store(cl)
    unit.mgmt_complete(cl, ml)
    return image

def reimport_pccc(unit, image):
    cl = open_and_load(unit, image)
    unit.mgmt_complete(cl, b2v(image[:16]))
    return cl

def kl_rename(unit, klf, s, d):                # <<KLEE-instruction-clone>>
    if s != d:
        klf[d], klf[s] = klf[s], Locker(idx=s)
        klf[d].idx = d
        unit.klmanagedlocker = {s: d, d: 32}.get(unit.klmanagedlocker, unit.klmanagedlocker)

def kl_swap(unit, klf, s, d):
    if s != d:
        klf[s], klf[d] = klf[d], klf[s]
        klf[s].idx, klf[d].idx = s, d
        unit.klmanagedlocker = {s: d, d: s}.get(unit.klmanagedlocker, unit.klmanagedlocker)

# ---------------------------------------------------------------- vectors
RFC8452_A = {  # RFC 8452 Appendix A (rfc-editor.org/rfc/rfc8452.txt, April 2019)
    'H':  '25629347589242761d31f826ba4b757b',
    'X1': '4f4f95668c83dfb6401762bb2d01a262',
    'X2': 'd1a24ddd2721d006bbe45f20d3c9f362',
    'result': 'f7a3b47b846119fae5b7866cf5e5b77e',
    'mulx_in':  '9c98c04df9387ded828175a92ba652d8',
    'mulx_out': '3931819bf271fada0503eb52574ca572',
}
RFC8452_C2_2 = {  # RFC 8452 C.2 #2 (AEAD_AES_256_GCM_SIV) derived-key intermediates
    'key':   '01000000000000000000000000000000'
             '00000000000000000000000000000000',
    'nonce': '030000000000000000000000',
    'auth_key': 'b5d3c529dfafac43136d2d11be284d7f',
    'enc_key':  'b914f4742be9e1d7a2f84addbf96dec3'
                '456e3c6c05ecc157cdbf0700fedad222',
}
_K1 = '01' + '00' * 31
_N3 = '03' + '00' * 11
RFC8452_AEAD = [  # RFC 8452 C.2/C.3: (source, key, nonce, AAD, plaintext, ciphertext || tag)
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
# Synthetic material; klmarchid bit 15 is IMPQUAL bit 47, which segment 2 must keep.
CSK = b2v(bytes(range(32)))
LST = {j: b2v(bytes([0x40 + j] * 16)) for j in range(11)}
LST_ALT = {**LST, 4: LST[4] ^ 1 << 17}         # #4 is selected by LOC_SETS[2]
LST_ALT_UNSEL = {**LST, 3: LST[3] ^ 1 << 17}   # #3 is selected by no set
LST_NO_SIP = {j: v for j, v in LST.items() if j}
LST_NO_SLOC = {**LST, 10: 0}
IDS = dict(klmvendorid=0x0000_0489, klmarchid=0x0000_8001, klmimpid=0x0102_0304)
IDS_NEXT_REV = dict(IDS, klmimpid=0x0102_0305)
CONTENT1 = deser(bytes(range(0x80, 0xA0)))     # the AES256_ECB key
CONTENT2 = [b2v(bytes([0xA0 + i] * 16)) for i in range(2)]
AUX_LEN = 2 + len(CONTENT2)
LOC_SETS = [(), (2,), (1, 4, 6, 8, 9, 10)]      # none, one, the maximum of six
# Regression vectors of this model (self-generated): Locality set -> (MDH, SIV, first Content1 block)
REGRESSION = {
    (): ('20100400000000000000000000000000',
         '0d9f0e3fcb063781bb68983a9e4614b6',
         'd296113f566edbab7bb4ac1caa29f51a'),
    (2,): ('20100400000000006000000000000000',
           'd6647d709ae9b04d66010cdb3ec25cd1',
           '085846e6c0fa9dad85e6977219f399b8'),
    (1, 4, 6, 8, 9, 10): ('2010040000000000403b000000000000',
                          '785422c077ef79150600caa4c9c3bf9a',
                          '1a28e4d4d7bb321c24240038b1db2a65'),
}
REGRESSION_ADS = {  # AuxDataLen = 4, LOC_SETS[2]
    'MDH': '2010040004000000403b000000000000',
    'SIV': '590eecfaad2db45379fca238916f9c64',
    'IMPQUAL': '89040000018000000403020100000000',
    'SIV2': '0710ba75b06702fa4d986a7b8756db59',
    'C2[0]': '85e6a5e475dbd8fbd8fcf8e2c7238c69',
}
REGRESSION_ERROR_IMAGE = '2010cc0000000000403b000000000000'   # after a failed import: State 51

# ---------------------------------------------------------------- checks
def eq(name, got, want):
    return check(name, None, got, want)

def tampered(image, bit):
    b = bytearray(image)
    b[bit // 8] ^= 1 << bit % 8
    return bytes(b)

def new_unit(lst=LST, ids=IDS, csk=CSK, **kw):
    return Unit(csk, lst, **ids, **kw)

def sealed(unit, mdh, c1=CONTENT1, c2=None):
    return export_cl(unit, Locker(mdh, c1, c2))

H, unit = bytes.fromhex, new_unit()
n1 = unit.content1_size(make_mdh()) // 16
imp = lambda u, img, **kw: import_image(u, Mem(img), **kw)[1]
AUTH_F, INV_MD = ERR_NAME[AUTH], ERR_NAME[INVALID]

section("primitive anchors")
check("common.py self-test (FIPS 197 C.1-C.3, RFC 8452 App. A)", selftest())
a = {k: b2v(H(v)) for k, v in RFC8452_A.items()}
eq("POLYVAL() vs RFC 8452 Appendix A; POLYVAL() of no blocks is zeros(128)",
   (POLYVAL(a['H'], [a['X1'], a['X2']]), POLYVAL(a['H'], [])), (a['result'], 0))
eq("mulX_POLYVAL vs RFC 8452 Appendix A", mulx_polyval(a['mulx_in']), a['mulx_out'])
ek, ak = SCC_KeyDeriv(b2v(H(RFC8452_C2_2['key'])), b2v(H(RFC8452_C2_2['nonce'])))
eq("SCC_KeyDeriv vs RFC 8452 C.2 #2 intermediates", (v2b(ak, 16).hex(), v2b(ek, 32).hex()),
   (RFC8452_C2_2['auth_key'], RFC8452_C2_2['enc_key']))

section("SCC_Encrypt / SCC_Decrypt vs RFC 8452 C.2 / C.3 (length block restored)")
pad = lambda s: deser(s + bytes(-len(s) % 16))
for src, k, nce, aad, pt, rec in RFC8452_AEAD:
    K, N, A, P, R = b2v(H(k)), b2v(H(nce)), H(aad), H(pt), H(rec)
    CT, TAG = R[:-16], R[-16:]
    lb = cat((bin_(8 * len(P), 64), 64), (bin_(8 * len(A), 64), 64))   # le64(AAD bits) || le64(PT bits)
    enc_key = SCC_KeyDeriv(K, N)[0]
    tag_in = b2v(aes_decrypt(v2b(enc_key, 32), TAG))
    s, t = sl(tag_in, 126, 126), sl(b2v(TAG), 126, 126)
    siv, c = SCC_Encrypt(pad(A), N, s, pad(P), K, length_block=lb)
    eq(f"{src}: SCC_Encrypt with sep = {s} (the RFC's bit 126) reproduces the tag",
       (sl(tag_in, 127, 127), v2b(siv, 16)), (0, TAG))
    if P:                                      # C.3 wraps int(SIV[31:0]) + i mod 2^32
        ks = [AESE256(enc_key, ctr_block(b2v(TAG), t, i)) for i in range(len(pad(CT)))]
        eq(f"{src}: counter blocks with sep = {t} recover the plaintext",
           ser(x ^ y for x, y in zip(pad(CT), ks))[:len(P)], P)
    dec = [SCC_Decrypt(pad(A), N, sp, b2v(TAG), pad(CT), K, length_block=lb) for sp in (0, 1)]
    verifies = [sp for sp in (0, 1) if dec[sp][0]]
    if s == t:
        eq(f"{src}: bits coincide: the record is reproduced and verifies",
           (ser(c)[:len(P)], verifies, ser(dec[s][1])[:len(P)]), (CT, [s], P))
    else:
        eq(f"{src}: bits differ: no sep verifies the record (the one-bit price of sep)", verifies, [])

section("the MDH (<<KLEE-metadata-header>>)")
eq("the MDH fields tile bits [127:0]", sorted(b for _, hi, lo in MDH_FIELDS for b in range(lo, hi + 1)),
   list(range(128)))
probe = make_mdh(State=0x2A, StateExtension=0x9)
eq("kl.getst / kl.getstx expansions (srli 18, andi 0x3F; srli 24, andi 0x0F)",
   ((probe & M32) >> 18 & 0x3F, (probe & M32) >> 24 & 0x0F), (0x2A, 0x9))
check("every length/capacity field and Version lies in [63:0] (<<KLEE-length-rule>>, kl.size Form B)",
      all(MDH_FIELD[f][0] < 64 for f in ('Machine', 'MachinePolicy', 'KeyType', 'StateExtension',
                                         'AuxDataLen', 'ADSDropped', 'SCProtection', 'Version')))
eq("Locality field round-trips for each Locality set",
   [localities_of(make_mdh(s)) for s in LOC_SETS], [list(s) for s in LOC_SETS])
eq("at most six Localities, so len_AD <= 7 (<<KLEE-SCC-GCM-SIV-enc>>)",
   max(len(localities_of(put(0, 'Locality', f))) for f in range(512) if sl(f, 5, 4) != 3), len(LOC_SETS[2]))

section("length rule and layout (<<KLEE-length-rule>>, <<KLEE-SCC>>, <<KLEE-instruction-size>>)")
base = make_mdh(LOC_SETS[2], AuxDataLen=AUX_LEN)
image_len = lambda m: 16 + content_offset(m) + unit.content1_size(m) + content2_size(m)
check("image_size = kl.size - 16 (<<KLEE-instruction-mv>>)", all(image_len(m) == unit.kl_size(m) for m in (
      base, make_mdh(), put(base, 'ADSDropped', 1), put(base, 'AuxDataLen', 2), make_mdh(KeyType=1))))
eq("the SCC length does not depend on State (Valid and scc Configuration States)",
   len({image_len(put(base, 'State', st)) for st in list(range(1, 48)) + [EXPORTING, IMPORTING]}), 1)
check("no field outside the length rule changes the SCC length", all(
      image_len(base ^ x << MDH_FIELD[f][1]) == image_len(base) for f, x in (
          ('SCProtection', 2), ('UsagePolicy', 0b10101), ('Locality', 0b1_01_11_11), ('MachineUse', 0x2EEF),
          ('ExpirationDate', 0x12345), ('AuxInfo', 7), ('Version', 1)))
      and image_len(base | 5 << 116) == image_len(base))
check("KeyType changes the SCC length (key by value vs SKID)",
      image_len(put(base, 'KeyType', 1)) != image_len(base))
for aux in (0, 2, AUX_LEN, 16):
    m = put(make_mdh(LOC_SETS[2]), 'AuxDataLen', aux)
    d = put(m, 'ADSDropped', 1)
    eq(f"AuxDataLen = {aux}: ADSDropped removes exactly Content2; Content1 stays at {48 if aux else 16}",
       (content_offset(m), content_offset(d), image_len(m) - image_len(d)),
       (48 if aux else 16,) * 2 + (16 * max(aux - 2, 0),))
eq("kl.size: AuxDataLen = 1 -> 0; every Error State -> 16, AuxDataLen and ADSDropped ignored; "
   "a Valid State ECB lacks -> 0",
   (unit.kl_size(put(base, 'AuxDataLen', 1)),
    {unit.kl_size(put(put(put(base, 'State', st), 'AuxDataLen', a), 'ADSDropped', 1))
     for st in ERROR_STATES for a in (1, 5)},
    unit.kl_size(put(base, 'State', 3))), (0, {16}, 0))
check("kl.size Form B equals Form C on valid Metadata",
      all(unit.kl_size(m, 'B') == unit.kl_size(m) != 0 for m in (
      base, make_mdh(), put(base, 'ADSDropped', 1), make_mdh(KeyType=1), put(base, 'State', IMPORTING))))
lean = new_unit(LST_NO_SLOC, zklexpire=False)
check("kl.size Form B ignores reserved bits, Locality and ExpirationDate in [127:64]; Form C reports 0",
      all(lean.kl_size(m) == 0 and lean.kl_size(m, 'B') == lean.kl_size(m & (1 << 64) - 1) != 0 for m in (
          base | 1 << 116, base | 2 << 78, put(base, 'Locality', 0b110000), make_mdh((10,)),
          make_mdh(ExpirationDate=5))))
eq("kl.size: MachineUse and AuxInfo are not checked (<<KLEE-MachineUse>>)",
   {unit.kl_size(put(put(base, 'MachineUse', 0x2EEF), 'AuxInfo', 7), f) for f in 'BC'}, {unit.kl_size(base)})
eq("kl.size Form B reports 0 for an unsupported Version",
   unit.kl_size(put(base, 'Version', 1), 'B'), 0)

section("export -> import round trip (<<KLEE-SCC-export>>, <<KLEE-SCC-import>>)")
sccs, plain = {}, lambda m: (m, tuple(CONTENT1), None)
for locs in LOC_SETS:
    mdh = make_mdh(locs)
    cl0 = Locker(mdh, CONTENT1)
    scc = sccs[locs] = export_cl(unit, cl0)
    cl, res = import_image(unit, Mem(scc))
    eq(f"Localities {locs}: SCC = MDH | SIV | encrypted Content1, length kl.size; completion restores the "
       f"locker; import reproduces it",
       (len(scc), scc[:16], scc[32:] != ser(CONTENT1), cl0.snapshot(), res, cl.snapshot()),
       (unit.kl_size(mdh), v2b(mdh, 16), True, plain(mdh), 'ok', plain(mdh)))
eq("distinct Locality sets give distinct SIVs", len({s[16:32] for s in sccs.values()}), len(LOC_SETS))
mdh, scc = make_mdh(LOC_SETS[2]), sccs[LOC_SETS[2]]
eq("sealing is deterministic (no nonce)", sealed(unit, mdh), scc)
AD = [mdh | 1 << 47] + [LST[j] for j in LOC_SETS[2]]
eq("sep = 0: AD[0][47] is cleared in a local copy only, for SCC_Encrypt and SCC_Decrypt",
   (SCC_Encrypt(AD, 0, 0, CONTENT1, CSK), SCC_Decrypt(AD, 0, 0, b2v(scc[16:32]), deser(scc[32:]), CSK),
    AD[0] >> 47 & 1),
   (SCC_Encrypt([mdh] + AD[1:], 0, 0, CONTENT1, CSK), (True, CONTENT1), 1))

section("tamper detection, first segment")
wrong = []
for bit in (b for b in range(128) if b != 47):
    img = tampered(scc, bit)
    cl, res = import_image(unit, Mem(img))
    name, hi, lo = field_at(bit)
    value = sl(b2v(img[:16]), hi, lo)
    if name in ('Machine', 'MachineExtension') or name == 'SCProtection' and value not in Unit.SC_LEVELS + (3,):
        want = ('kl_exc_unsupported', (0, (), None))
    elif (name in ('Reserved', 'Version') or name == 'MachinePolicy' and value == 0
          or name == 'KeyType' and value >= 2 or name == 'AuxDataLen' and value == 1
          or name == 'Locality' and sl(value, 5, 4) == 3 or name == 'State' and value not in ECB_STATES
          or name == 'StateExtension' or name == 'SCProtection' and value == 3):
        want = (INV_MD, (put(0, 'State', INVALID), (), None))
    else:
        want = (AUTH_F, (err_mdh(b2v(img[:16]), AUTH), (), None))
    if (res, cl.snapshot()) != want:
        wrong.append((bit, name, res))
eq("each single-bit MDH change (bit 47 aside) yields unsupported, invalid Metadata or Authentication "
   "Failed, as its field requires (StateExtension: invalid; MachineUse, AuxInfo: Authentication Failed)",
   wrong, [])
img = tampered(scc, 47)
eq("MDH bit 47 with AuxDataLen = 0 is ignored: working ADSDropped 0, the same locker imported",
   (fld(open_and_load(unit, img).mdh, 'ADSDropped'), imp(unit, img),
    import_image(unit, Mem(img))[0].snapshot()),
   (0, 'ok', plain(mdh)))
m_enc = make_mdh(LOC_SETS[2], MachinePolicy=3, State=ENCRYPT)
scc_enc = sealed(unit, m_enc)
eq("an SCC exported in Encrypt imports in Encrypt; Decrypt substituted fails authentication; "
   "Success (not an ECB State) is invalid Metadata",
   (import_image(unit, Mem(scc_enc))[0].state, imp(unit, v2b(put(m_enc, 'State', DECRYPT), 16) + scc_enc[16:]),
    imp(unit, v2b(put(m_enc, 'State', KL_STATE_SUCCESS), 16) + scc_enc[16:])),
   (ENCRYPT, AUTH_F, INV_MD))
eq("a StateExtension ECB does not support is invalid Metadata at open, in Ready and in Encrypt, and kl.size "
   "(Forms B and C) reports 0",
   {(imp(unit, v2b(put(m, 'State', st), 16) + scc_enc[16:]), unit.kl_size(put(m, 'State', st), f))
    for m in (put(m_enc, 'StateExtension', x) for x in (1, 8, 0xF)) for st in (READY, ENCRYPT) for f in 'BC'},
   {(INV_MD, 0)})
exp_unit = new_unit(zklexpire=False)
eq("without Zklexpire a non-zero ExpirationDate is invalid Metadata",
   {imp(exp_unit, tampered(scc, b)) for b in (96, 105, 115)}, {INV_MD})
eq("every sampled bit change in SIV or Content1 fails authentication",
   {imp(unit, tampered(scc, b)) for b in range(8 * 16, 8 * (32 + 16 * n1), 7)}, {AUTH_F})
eq("SCC_Decrypt zeroes P[] when authentication fails",
   SCC_Decrypt([mdh] + [LST[j] for j in LOC_SETS[2]], 0, 0, b2v(scc[16:32]) ^ 1, deser(scc[32:]), CSK),
   (False, [0] * n1))
eq("changed selected Locality Secret / unselected one / other CSK / substituted Locality set",
   (imp(new_unit(LST_ALT), scc), imp(new_unit(LST_ALT_UNSEL), scc), imp(new_unit(csk=CSK ^ 1), scc),
    imp(unit, v2b(make_mdh((2,)), 16) + scc[16:])), (AUTH_F, 'ok', AUTH_F, AUTH_F))
cl, res = import_image(unit, Mem(scc), ml=put(put(mdh, 'Locality', 0), 'UsagePolicy', 0b11111))
eq("ml is consumed only for State (<<KLEE-locker-management>>): another State fails, other fields ignored",
   (imp(unit, scc, ml=put(mdh, 'State', ENCRYPT)), res, cl.mdh), (AUTH_F, 'ok', mdh))
no_sip, m0 = new_unit(LST_NO_SIP), make_mdh((0,))
scc0 = sealed(no_sip, m0)
eq("unpopulated SiPScrt: ChipFamScrt substitutes on both sides; SiPScrt only at the importer fails; "
   "the Locality is substituted, not dropped",
   (imp(no_sip, scc0), imp(unit, scc0), scc0[16:32] != v2b(SCC_Encrypt([m0], 0, 0, CONTENT1, CSK)[0], 16)),
   ('ok', AUTH_F, True))
no_sloc, m10 = new_unit(LST_NO_SLOC), make_mdh((10,))
cl10 = Locker(m10, CONTENT1)
scc10 = export_cl(no_sloc, cl10)
eq("export naming an unconfigured SLocality is not refused: LST_eff = zeros(128); completion restores",
   (scc10[16:32], cl10.snapshot()), (v2b(SCC_Encrypt([m10, 0], 0, 0, CONTENT1, CSK)[0], 16), plain(m10)))
cl, res = import_image(no_sloc, Mem(scc10))
eq("... its import there is invalid Metadata (MDH zeroed); where configured, Authentication Failed",
   (res, cl.mdh, imp(unit, scc10)), (INV_MD, put(0, 'State', INVALID), AUTH_F))

section("the Auxiliary Data Section (<<KLEE-Auxiliary-Data-Section>>)")
mdh_i = make_mdh(LOC_SETS[2], AuxDataLen=AUX_LEN)
scc_i = sealed(unit, mdh_i, CONTENT1, CONTENT2)
off1, off2 = 64, 64 + 16 * n1
s1, c1 = SCC_Encrypt([mdh_i] + [LST[j] for j in LOC_SETS[2]], 0, 0, CONTENT1, CSK)
s2, c2 = SCC_Encrypt([unit.impqual(), s1], 0, 1, CONTENT2, CSK)
eq("SCC = MDH | SIV | IMPQUAL | SIV2 | Content1 | Content2, length kl.size (<<KLEE-SCC>>)",
   (scc_i, len(scc_i)),
   (b''.join(v2b(x, 16) for x in (mdh_i, s1, unit.impqual(), s2, *c1, *c2)), unit.kl_size(mdh_i)))
eq("IMPQUAL = zeros(32) @ klmimpid @ klmarchid @ klmvendorid", scc_i[32:48],
   b''.join(IDS[k].to_bytes(4, 'little') for k in ('klmvendorid', 'klmarchid', 'klmimpid')) + bytes(4))
full = (mdh_i, tuple(CONTENT1), tuple(CONTENT2))
no_ads = (put(mdh_i, 'AuxDataLen', 0), tuple(CONTENT1), None)
unit.decrypts = []
cl, res = import_image(unit, Mem(scc_i))
eq("matching IMPQUAL: both segments authenticate; ADS retained; re-exported unchanged",
   (res, cl.snapshot(), unit.decrypts[:], export_cl(unit, cl)), ('ok', full, [0, 1], scc_i))
scc_2 = sealed(unit, make_mdh(LOC_SETS[2], AuxDataLen=2), CONTENT1, [])
cl, res = import_image(unit, Mem(scc_2))
eq("AuxDataLen = 2: an empty Content2 still carries IMPQUAL and SIV2",
   (len(scc_2), res, cl.content2, fld(cl.mdh, 'AuxDataLen')), (64 + 16 * n1, 'ok', [], 2))
other = new_unit(ids=IDS_NEXT_REV)
for label, img, dec in (("mismatching IMPQUAL: Content2 dropped undecrypted", scc_i, [0]),
                        ("IMPQUAL rewritten to the importer's: segment 2 fails (IMPQUAL is AD2[0])",
                         scc_i[:32] + v2b(other.impqual(), 16) + scc_i[48:], [0, 1])):
    other.decrypts = []
    cl, res = import_image(other, Mem(img))
    eq(f"{label}; Content1 imports, AuxDataLen -> 0", (res, cl.snapshot(), other.decrypts), ('ok', no_ads, dec))
check("sep = 1: AD2[0][47] (klmarchid bit 15) is authenticated, not cleared",
      SCC_Encrypt([unit.impqual() ^ 1 << 47, s1], 0, 1, CONTENT2, CSK)[0] != s2)
small, mem = new_unit(max_aux=AUX_LEN - 1), Mem(scc_i)
cl, res = import_image(small, mem)
eq("ADS above the importer's maximum: step 5 drops it; Content2 not read; Content1 imports",
   (res, cl.snapshot(), small.decrypts, mem.hi), ('ok', no_ads, [0], off2))
cl = open_and_load(small, scc_i)
eq("during that import the locker MDH has the working ADSDropped = 1 and the original AuxDataLen",
   (fld(cl.mdh, 'ADSDropped'), fld(cl.mdh, 'AuxDataLen'), cl.state), (1, AUX_LEN, IMPORTING))
cl, res = import_image(other, Mem(scc_i), regen=(3, [0x5EED]))
scc_r = export_cl(other, cl)
eq("step 15: a replacement ADS sets AuxDataLen (>= 2); a later export emits it with the importer's IMPQUAL",
   (res, fld(cl.mdh, 'AuxDataLen'), fld(cl.mdh, 'ADSDropped'), scc_r[32:48],
    import_image(other, Mem(scc_r))[0].content2),
   ('ok', 3, 0, v2b(other.impqual(), 16), [0x5EED]))
scc_n = export_cl(other, import_image(other, Mem(scc_i))[0])
eq("without a replacement a later export emits no ADS", (len(scc_n), imp(unit, scc_n)), (32 + 16 * n1, 'ok'))
scc_b = sealed(unit, mdh_i, [c ^ MASK128 for c in CONTENT1], CONTENT2)
graft = scc_i[:48] + scc_b[48:64] + scc_i[off1:off2] + scc_b[off2:]
eq("SIV binds segment 2: SIV, SIV2 and the segment-2 ciphertext all differ; a graft drops the ADS only",
   (scc_i[16:32] != scc_b[16:32], scc_i[48:64] != scc_b[48:64], scc_i[off2:] != scc_b[off2:],
    import_image(unit, Mem(graft))[0].snapshot()), (True, True, True, no_ads))
eq("every sampled change in IMPQUAL, SIV2 or Content2 drops the ADS and keeps Content1",
   {import_image(unit, Mem(tampered(scc_i, b)))[0].snapshot()
    for b in list(range(8 * 32, 8 * 64, 5)) + list(range(8 * off2, 8 * len(scc_i), 11))}, {no_ads})
eq("a change in Content1 rejects the whole SCC",
   {imp(unit, tampered(scc_i, b)) for b in range(8 * off1, 8 * off2, 13)}, {AUTH_F})

section("the segment separator sep (<<KLEE-SCC-AEAD>>)")
enc0 = SCC_KeyDeriv(CSK, 0)[0]
eq("counter block: 128 bits, bit 127 = 1, bit 126 = sep overriding SIV[126]",
   (max(ctr_block(x, sp, i).bit_length() for x in (0, MASK128, 0x5A5A << 32) for sp in (0, 1)
        for i in (0, 1, M32)),
    sl(ctr_block(MASK128, 0, 0), 127, 126), sl(ctr_block(MASK128, 1, 0), 127, 126),
    ctr_block(0, 0, 0) == ctr_block(1 << 126, 0, 0)), (128, 0b10, 0b11, True))
eq("tag input: 128 bits, bit 127 = 0, bit 126 = sep; POLYVAL bit 126 does not reach it",
   (tag_block(MASK128, 0).bit_length(), sl(tag_block(MASK128, 0), 127, 126), tag_block(0, 1),
    tag_block(0, 0) == tag_block(1 << 126, 0)), (126, 0b00, 1 << 126, True))
check("identical SIVs give disjoint keystreams for the two segments", all(
      AESE256(enc0, ctr_block(0x1234, 0, i)) != AESE256(enc0, ctr_block(0x1234, 1, i)) for i in range(4)))
AD1 = [mdh_i] + [LST[j] for j in LOC_SETS[2]]
(t1, e1), (t2, e2) = SCC_Encrypt(AD1, 0, 0, CONTENT1, CSK), SCC_Encrypt(AD1, 0, 1, CONTENT1, CSK)
eq("sep enters tag and keystream; a segment-1 payload does not authenticate with sep = 1",
   (t1 != t2, e1 != e2, SCC_Decrypt(AD1, 0, 0, t1, e1, CSK)[0], SCC_Decrypt(AD1, 0, 1, t1, e1, CSK)[0]),
   (True, True, True, False))

section("ADSDropped, an unauthenticated format hint (<<KLEE-data-formats>>)")
ref_snap = import_image(unit, Mem(scc_i))[0].snapshot()
set47, mem = tampered(scc_i, 47), Mem(tampered(scc_i, 47))
cl, res = import_image(unit, mem)
eq("setting it drops only Content2 (policy fields untouched), and no Content2 byte is read",
   (res, cl.snapshot(), mem.hi), ('ok', no_ads, off2))
short = set47[:off2]
padded = short[:32] + bytes(range(0x60, 0x80)) + short[64:]
eq("with it set, IMPQUAL and SIV2 are ignored padding and Content1 stays at 48",
   [import_image(unit, Mem(i))[0].snapshot() for i in (short, padded)], [no_ads, no_ads])
for label, img, dec in (("junk IMPQUAL: segment 2 fails at the qualifier", padded, [0]),
                        ("genuine IMPQUAL/SIV2, no Content2: segment 2 fails authentication", short, [0, 1])):
    unit.decrypts = []
    cl, res = import_image(unit, Mem(tampered(img, 47)))
    eq(f"clearing it over {label}; Content1 kept", (res, cl.snapshot(), unit.decrypts), ('ok', no_ads, dec))
cl = open_and_load(small, scc_i)
pccc = export_pccc(small, cl)
eq("SCC-shaped PCCC of a dropped import: saved MDH (importing, ADSDropped 1), SIV..Content1 verbatim, "
   "length kl.size; the nested completion restores kl_cfg_importing",
   (b2v(pccc[:16]), len(pccc), small.kl_size(b2v(pccc[:16])), pccc[16:], cl.state, fld(cl.mdh, 'ADSDropped')),
   (put(put(mdh_i, 'ADSDropped', 1), 'State', IMPORTING), off2, off2, scc_i[16:off2], IMPORTING, 1))
cl = reimport_pccc(small, pccc)
st = (cl.state, fld(cl.mdh, 'ADSDropped'), cl.content2)
small.mgmt_complete(cl, mdh_i)
eq("its re-import has working ADSDropped 1 and no Content2; the base completion authenticates Content1",
   (st, outcome(cl), cl.snapshot()), ((IMPORTING, 1, None), 'ok', no_ads))
pccc_clr = tampered(pccc, 47)
for label, u, tail, want in (("an importer too small for the ADS drops it again", small, b'', no_ads),
                             ("zeros after it: segment 2 fails, Content1 kept", unit, bytes(32), no_ads),
                             ("the genuine Content2 after it: the authentic ADS returns", unit,
                              scc_i[off2:], ref_snap)):
    cl = reimport_pccc(u, pccc_clr + tail)
    u.mgmt_complete(cl, mdh_i)
    eq(f"clearing it in the PCCC, {label}", cl.snapshot(), want)
pccc_full = export_pccc(unit, open_and_load(unit, scc_i))
for label, img, want in (("a PCCC of an import that kept its ADS completes with it", pccc_full, ref_snap),
                         ("setting bit 47 in that PCCC only drops the ADS", tampered(pccc_full, 47), no_ads)):
    cl = reimport_pccc(unit, img)
    unit.mgmt_complete(cl, mdh_i)
    eq(label, cl.snapshot(), want)

section("klmanagedlocker (<<KLEE-CSR-klmanagedlocker>>); kl.rename and kl.swap under management "
        "(<<KLEE-instruction-clone>>)")
u, klf = new_unit(), {i: Locker(idx=i) for i in range(32)}
mem = Mem(scc_i)
u.mgmt_open_import(klf[3], b2v(mem.read(0, 16)))
u.load(klf[3], mem)
managed, snap = u.klmanagedlocker, klf[3].snapshot()
kl_rename(u, klf, 3, 7)
eq("the opening kl.mgmt names K3; kl.rename moves it unchanged and klmanagedlocker follows (3 -> 7)",
   (managed, klf[7].snapshot(), klf[3].state, u.klmanagedlocker), (3, snap, UNCONF, 7))
eq("kl.mgmt on another locker meanwhile: illegal instruction, no effect",
   (raises(u.mgmt_open_import, klf[2], mdh_i), klf[2].snapshot()), (True, (0, (), None)))
u.mgmt_complete(klf[7], mdh_i)
eq("the import completes on K7 with both segments (per-hart registers); klmanagedlocker -> 32",
   (klf[7].snapshot(), u.klmanagedlocker), (ref_snap, 32))
klf[2], klf[5] = Locker(mdh_i, CONTENT1, CONTENT2, idx=2), Locker(make_mdh(), CONTENT1, idx=5)
snap2, snap5, ml = klf[2].snapshot(), klf[5].snapshot(), klf[2].mdh
u.mgmt_open_export(klf[2])
kl_swap(u, klf, 2, 5)
eq("kl.swap mid-export exchanges the lockers; klmanagedlocker follows (2 -> 5)",
   (u.klmanagedlocker, klf[2].snapshot()), (5, snap5))
u.klmanagedlocker = 32
check("kl.store from a kl_cfg_exporting locker not named by klmanagedlocker: illegal (GR39)",
      raises(u.store, klf[5]))
u.klmanagedlocker = 5
img = v2b(ml, 16) + u.store(klf[5])
u.mgmt_complete(klf[5], ml)
eq("kl.store from K5 emits the original SCC; the completion on K5 restores it",
   (img, klf[5].snapshot(), u.klmanagedlocker), (scc_i, snap2, 32))
u.mgmt_open_import(klf[7], mdh_i)
klf[1] = Locker(make_mdh(), CONTENT1, idx=1)
snap1 = klf[1].snapshot()
kl_rename(u, klf, 1, 7)
eq("kl.rename onto the managed locker discards its import (GR18); klmanagedlocker -> 32",
   (u.klmanagedlocker, klf[7].snapshot(), klf[1].state), (32, snap1, UNCONF))
u.mgmt_open_import(klf[4], mdh_i)
u.load(klf[4], Mem(tampered(scc_i, 8 * (off1 + 6))))
u.mgmt_complete(klf[4], mdh_i)
eq("the managed locker transitions to an Error State (failed authentication): klmanagedlocker -> 32",
   (klf[4].state, u.klmanagedlocker), (AUTH, 32))

section("Error States (<<KLEE-error-state-transfer>>)")
bad_c1 = tampered(scc_i, 8 * (off1 + 6))
cl_fail, res = import_image(unit, Mem(bad_c1))
failed = err_mdh(mdh_i, AUTH)
eq("authentication failure: State 51, Content cleared, AuxDataLen and ADSDropped 0, other fields kept (GR28); "
   "also after a dropped ADS", (res, cl_fail.snapshot(), import_image(small, Mem(bad_c1))[0].snapshot()),
   (AUTH_F, (failed, (), None), (failed, (), None)))
before = (unit.reg_SIV, unit.reg_IMPQUAL, unit.reg_SIV2)
img_e = export_cl(unit, cl_fail)
eq("an Error-State locker exports as its 16-byte MDH, with no kl.mgmt and no SIV; CSK and LST do not matter",
   (img_e, unit.kl_size(cl_fail.mdh, 'A'), (unit.reg_SIV, unit.reg_IMPQUAL, unit.reg_SIV2),
    export_cl(new_unit(LST_ALT, csk=CSK ^ 5), Locker(cl_fail.mdh))),
   (v2b(failed, 16), 16, before, v2b(failed, 16)))
snap = cl_fail.snapshot()
unit.mgmt_open_export(cl_fail)
eq("kl.mgmt #kl_cfg_exporting on an Error-State locker leaves it unchanged", cl_fail.snapshot(), snap)
far = new_unit(LST_NO_SLOC, ids=IDS_NEXT_REV, csk=CSK ^ 7, max_aux=0)
cl_e, res = import_image(far, Mem(img_e))
far.mgmt_complete(cl_e, cl_e.mdh)
far.load(cl_e, Mem(img_e))
eq("the short import elsewhere reproduces it; kl_cfg_management_end and kl.load are then no-ops (GR35)",
   (res, cl_e.snapshot()), (AUTH_F, snap))
dirty = make_mdh(Machine=0xFFF, MachinePolicy=0, KeyType=3, AuxDataLen=5, ADSDropped=1, UsagePolicy=0b10101,
                 MachineExtension=2, SCProtection=3, StateExtension=0xF, AuxInfo=0x155, MachineUse=0x2EEF,
                 ExpirationDate=0xFFFFF, Version=2) | 0x1FF << 69
dirty |= sum(((1 << (hi - lo + 1)) - 1) << lo for hi, lo in RESERVED)
bad = []
for st in ERROR_STATES:
    m = put(dirty, 'State', st)
    unit.reg_SIV, unit.reg_IMPQUAL, unit.reg_SIV2 = 1, 2, 3
    cl_d = Locker()
    unit.mgmt_open_import(cl_d, m)
    want = err_mdh(m, INVALID if st > 53 else st)
    regs = unit.reg_SIV, unit.reg_IMPQUAL, unit.reg_SIV2
    if ((cl_d.snapshot(), unit.kl_size(m), export_cl(unit, cl_d), regs)
            != ((want, (), None), 16, v2b(want, 16), (1, 2, 3))):
        bad.append(st)
eq("Error States 48-55: the short import installs the whole MDH unchecked, AuxDataLen and ADSDropped 0, "
   "54 and 55 as Invalid, registers untouched", bad, [])
cl_x = Locker()
exp_unit.mgmt_open_import(cl_x, put(dirty, 'State', EXPIRED))
eq("without Zklexpire the short import of Expired installs the MDH in Invalid",
   cl_x.mdh, err_mdh(dirty, INVALID))
eq("the same MDH in a Valid State is checked (unsupported)", imp(unit, v2b(put(dirty, 'State', 1), 16)),
   'kl_exc_unsupported')
info("the short import neither opens a management operation nor zeroizes SIV/IMPQUAL/SIV2 (<<KLEE-KLF>> "
     "zeroizes them for a kl.mgmt that opens an import).")

section("negative controls")
lb = cat((bin_(8 * 16 * n1, 64), 64), (bin_(8 * 16 * (1 + len(LOC_SETS[2])), 64), 64))
siv_lb, c_lb = SCC_Encrypt([mdh] + [LST[j] for j in LOC_SETS[2]], 0, 0, CONTENT1, CSK, length_block=lb)
control("restoring the RFC 8452 length block changes the SIV", v2b(siv_lb, 16) != scc[16:32])
eq("an SCC sealed with a length block does not import", imp(unit, scc[:16] + v2b(siv_lb, 16) + ser(c_lb)),
   AUTH_F)
cl = reimport_pccc(small, pccc)
small.mgmt_complete(cl, mdh_i, clear_ads=False)
control("authenticating AD[0] with bit 47 kept rejects the dropped-ADS PCCC", outcome(cl) == AUTH_F)

section("regression vectors (CSK 000102..1f, LST[j] = 16 x (0x40+j), key 8081..9f)")
for locs, (m, s, c) in REGRESSION.items():
    eq(f"SCC for Localities {locs}", tuple(sccs[locs][i:i + 16].hex() for i in (0, 16, 32)), (m, s, c))
eq("SCC with an ADS", {'MDH': scc_i[:16].hex(), 'SIV': scc_i[16:32].hex(), 'IMPQUAL': scc_i[32:48].hex(),
                       'SIV2': scc_i[48:64].hex(), 'C2[0]': scc_i[off2:off2 + 16].hex()}, REGRESSION_ADS)
eq("Error-State image after a failed import", img_e.hex(), REGRESSION_ERROR_IMAGE)

done()
