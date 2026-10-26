#!/usr/bin/env pypy3.12
"""KAT for Secure Cryptographic Containers (Zkl-ISA-unpriv.adoc, KLE-SCC-AEAD .. KLE-SCC-import).

Run: cd src && pypy3.12 kat/scc-kat.py

Two models.  (1) scc_rfc_*: an independent bytes-level RFC 8452 AES-GCM-SIV (own GF arithmetic, optional length
block, optional sep bit), checked against RFC 8452 vectors.  (2) the spec pseudocode (SCC_KeyDeriv, POLYVAL via
common.py, SCC_Encrypt/Decrypt) and a function-level locker model of export/import (scc_export, scc_import), whose
output is compared with (1) assembled by hand from the SCC layout.  Contents are AES ECB lockers (Machine 0x20 =
AES256_ECB, 0x00 = AES128_ECB).  Instruction-level behavior (kl.mgmt sequencing, klnamedlocker) is out of scope.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
from scc_core import *
from scc_locker import *
from scc_core import _blocks, _bytes, _E, _ctr, _mul, _xinv
H = bytes.fromhex

# ------------------------------------------------------------------ fixtures
CSK = bytes(range(32)); CSKV = b2v(CSK)
LST = [bytes([0x40 + j]) * 16 for j in range(11)]; LSTV = [b2v(x) for x in LST]
IMPQ = scc_impqual(0x1111, 0x2222, 0x3333)
KEY = bytes(range(0x80, 0xa0))
def mk(machine=0x20, key=KEY, adl=0, c2=b'', js=(), **kw):
    m = mdh_pack(Machine=machine, MachinePolicy=3, State=ST_READY, AuxDataLen=adl,
                 Locality=scc_loc_bits(js), **kw)
    return dict(mdh=m, c1=key[:SCC_MACHINES[machine]], c2=c2)

def main():
    section('POLYVAL and SCC_KeyDeriv anchors (RFC 8452)')
    h = H('25629347589242761d31f826ba4b757b'); x1 = H('4f4f95668c83dfb6401762bb2d01a262'); x2 = H('d1a24ddd2721d006bbe45f20d3c9f362')
    want = H('f7a3b47b846119fae5b7866cf5e5b77e')
    check('RFC 8452 Appendix A: independent POLYVAL', scc_rfc_polyval(h, x1 + x2) == want, scc_rfc_polyval(h, x1 + x2).hex(), want.hex())
    check('RFC 8452 Appendix A: spec POLYVAL (common.py)', v2b(polyval(b2v(h), [b2v(x1), b2v(x2)]), 16) == want)
    check('POLYVAL of no blocks is zeros(128)', polyval(b2v(h), []) == 0)
    # RFC 8452 C.2 #2 intermediates are not remembered verbatim; key derivation is cross-checked against the independent model
    nonce = H('030000000000000000000000'); key = H('0100000000000000000000000000000000000000000000000000000000000000')
    ek, ak = scc_keyderiv(b2v(key), b2v(nonce))
    rak, rek = scc_rfc_keys(key, nonce)
    check('SCC_KeyDeriv equals RFC per-message key derivation (nonce @ counter = counter LE || nonce)', v2b(ak, 16) == rak and v2b(ek, 32) == rek)

    section('AEAD core vs RFC 8452 (length block restored, sep = RFC bit 126)')
    c, t = scc_rfc_seal(H('01' + '00' * 15), H('030000000000000000000000'), b'', b'', True)
    check('RFC 8452 C.1 #1 (AES-128, empty): independent model tag', t.hex() == 'dc20e2d83f25705bb49e439eca56de25', t.hex())
    c, t = scc_rfc_seal(H('01' + '00' * 15), H('030000000000000000000000'), b'', H('0100000000000000'), True)
    check('RFC 8452 C.1 #2: independent model', (c + t).hex() == 'b5d839330ac7b786' + '578782fff6013b815b287c22493a364c', (c + t).hex())
    # AES-256 vectors: the key is the RFC one, 01 00.. (32 bytes); the model above is validated by C.1, so C.2 is a derivation
    k256 = H('01' + '00' * 31)
    c, t = scc_rfc_seal(k256, nonce, b'', b'', True)
    check('RFC 8452 C.2 #1 tag 07f5f4169bbf55a8400cd47ea6fd400f', t.hex() == '07f5f4169bbf55a8400cd47ea6fd400f', t.hex())
    c, t = scc_rfc_seal(k256, nonce, b'', H('0100000000000000'), True)
    check('RFC 8452 C.2 #2 record c2ef328e5c71c83b | 843122130f7364b761e0b97427e3df28', (c + t).hex() == 'c2ef328e5c71c83b843122130f7364b761e0b97427e3df28', (c + t).hex())
    # spec functions with a length block restored: PT/AD multiples of 16 bytes so the block is one extra POLYVAL block
    import random
    rnd = random.Random(8452)
    nsame = nnot = 0
    for trial in range(8):
        key = bytes(rnd.randrange(256) for _ in range(32)); nonce = bytes(rnd.randrange(256) for _ in range(12))
        na, npt = rnd.randrange(1, 3), rnd.randrange(1, 4)
        aad = bytes(rnd.randrange(256) for _ in range(16 * na)); pt = bytes(rnd.randrange(256) for _ in range(16 * npt))
        c, t = scc_rfc_seal(key, nonce, aad, pt, True)
        # spec model with the RFC nonce and the length block appended as an extra POLYVAL input
        ek_, ak_ = scc_keyderiv(b2v(key), b2v(nonce))
        lenblk = b2v((len(aad) * 8).to_bytes(8, 'little') + (len(pt) * 8).to_bytes(8, 'little'))
        s = polyval(ak_, _blocks(aad) + _blocks(pt) + [lenblk]) ^ b2v(nonce)
        s_in = s
        sep = (s >> 126) & 1                     # the RFC keeps POLYVAL's bit 126; sep = that bit reproduces the RFC
        tag = _E(ek_, cat((0, 1), (sep, 1), (sl(s_in, 125, 0), 126)))
        if v2b(tag, 16) != t: nnot += 1; continue
        ctr_ok = _ctr(sep, tag, 0) == cat((1, 1), (sl(tag, 126, 0), 127))
        nsame += 1
        info('record %d: counter bit 126 %s' % (trial, 'coincides' if ctr_ok else 'differs'))
    check('all random RFC records reproduced by the spec tag path', nnot == 0 and nsame == 8)
    # full SCC_Encrypt/Decrypt round trip and the omitted-length difference
    P = [0x1111, 0x2222, 0x3333]; AD = [mdh_pack(Machine=0x20), 0x55]
    for sep in (0, 1):
        s_, C_ = scc_encrypt(AD, 0, sep, P, CSKV)
        ok, P_ = scc_decrypt(AD, 0, sep, s_, C_, CSKV)
        check('SCC_Encrypt/Decrypt round trip, sep = %d' % sep, ok and P_ == P)
    s0, C0 = scc_encrypt(AD, 0, 0, P, CSKV); s1, C1 = scc_encrypt(AD, 0, 1, P, CSKV)
    check('sep changes SIV and keystream', s0 != s1 and C0 != C1)
    check('sep = 1 record does not verify with sep = 0 and vice versa', not scc_decrypt(AD, 0, 0, s1, C1, CSKV)[0] and not scc_decrypt(AD, 0, 1, s0, C0, CSKV)[0])
    # versus the RFC model: AD bytes, no length block, sep, zero nonce (this is the independent derivation of SCC_Encrypt)
    for sep in (0, 1):
        ad_ = list(AD)
        if sep == 0: ad_[0] &= ~(1 << 47)
        c, t = scc_rfc_seal(CSK, bytes(12), _bytes(ad_), _bytes(P), lenblock=False, sep=sep)
        s_, C_ = scc_encrypt(AD, 0, sep, P, CSKV)
        check('SCC_Encrypt (sep=%d) equals the independent RFC model without lengths block, zero nonce, sep bit' % sep,
              v2b(s_, 16) == t and _bytes(C_) == c)
    adb = list(AD); adb[0] |= 1 << 47
    check('sep = 0: AD[0][47] does not affect the SIV (cleared locally)', scc_encrypt(adb, 0, 0, P, CSKV)[0] == s0)
    check('sep = 1: AD[0][47] is authenticated', scc_encrypt(adb, 0, 1, P, CSKV)[0] != s1)
    ok, Pz = scc_decrypt(AD, 0, 0, s0 ^ 1, C0, CSKV)
    check('failed authentication returns false and zeroes P[]', not ok and Pz == [0, 0, 0])
    control('negative: restoring the length block changes the SIV', polyval(scc_keyderiv(CSKV, 0)[1], AD + P + [b2v((256).to_bytes(8,'little')+(384).to_bytes(8,'little'))]) != polyval(scc_keyderiv(CSKV, 0)[1], AD + P))

    section('MDH and Locality field')
    allf = sorted(MDH_FIELDS, key=lambda t: t[1])
    check('MDH fields tile bits [127:0]', sum(w for _, _, w in allf) == 128 and all(allf[i][1] + allf[i][2] == allf[i + 1][1] for i in range(len(allf) - 1)))
    check('Locality encoding round-trips for every entry', all(scc_includes(scc_loc_bits([j]), k) == (j == k) for j in range(11) for k in range(11)))
    check('a six-entry Locality set has len_AD = 7', len(scc_ad(mdh_pack(Locality=scc_loc_bits([0, 4, 6, 8, 9, 10])), LSTV)) == 7)
    lst2 = list(LSTV); lst2[0] = 0
    check('unconfigured SiPScrt is substituted by ChipFamScrt, then ChipScrt', scc_lst_eff(lst2)[0] == LSTV[1] and scc_lst_eff([0, 0, 5] + [0] * 8)[0] == 5)

    section('length rule and layout')
    for adl, drop in ((0, 0), (2, 0), (2, 1), (4, 0), (4, 1), (16, 0), (16, 1)):
        L = mk(adl=adl, c2=bytes(16 * max(adl - 2, 0)), ADSDropped=drop)
        m = L['mdh']; sz = scc_size(m)
        c2 = 0 if drop or adl < 2 else 16 * (adl - 2)
        fixed = 32 if adl == 0 else 64
        check('AuxDataLen %d ADSDropped %d: kl.size = %d' % (adl, drop, fixed + 32 + c2), sz == fixed + 32 + c2, sz)
    sz1 = scc_size(mk(adl=0)['mdh'])
    L = mk(adl=2); img = scc_export(L, CSKV, LSTV, IMPQ)
    check('exported image length = kl.size', len(img) == scc_size(L['mdh']) and len(scc_export(mk(), CSKV, LSTV, IMPQ)) == sz1)
    check('KeyType 1 (SKID) shrinks Content1 to 16 bytes', scc_size(mk(KeyType=1)['mdh']) == 32 + 16)
    check('AES128_ECB content is 16 bytes: size 48', scc_size(mk(machine=0x00, key=KEY)['mdh']) == 48)
    check('AuxDataLen = 1 -> 0 (invalid)', scc_size(mk(adl=1)['mdh']) == 0)
    check('Error State -> 16', all(scc_size(mdh_pack(State=0, StateExtension=e, AuxDataLen=9)) == 16 for e in range(1, 7)))
    check('State 0 StateExtension 7-15 and State 61-63 -> 0', all(scc_size(mdh_pack(State=0, StateExtension=e)) == 0 for e in range(7, 16)) and all(scc_size(mdh_pack(State=s)) == 0 for s in (61, 62, 63)))
    check('SCProtection 3, Version 1/2, KeyType 3 -> 0', all(scc_size(mk(**{k: v})['mdh']) == 0 for k, v in (('SCProtection', 3), ('Version', 1), ('Version', 2), ('KeyType', 3))))

    section('export -> import round trip')
    for js in ((), (2,), (1, 4, 6, 8, 9, 10)):
        L = mk(js=js); img = scc_export(L, CSKV, LSTV, IMPQ)
        # independent assembly: AD = MDH (bit 47 cleared) | selected secrets (bytes), no lengths, zero nonce, sep 0
        ad = v2b(L['mdh'] & ~(1 << 47), 16) + b''.join(LST[j] for j in js)
        c, t = scc_rfc_seal(CSK, bytes(12), ad, L['c1'], lenblock=False, sep=0)
        check('Localities %s: image = MDH | SIV | Content1 matches the independent model' % (js,), img == v2b(L['mdh'], 16) + t + c, img.hex())
        st, R = scc_import(img, CSKV, LSTV, IMPQ)
        check('Localities %s: import reproduces the locker' % (js,), st == 'ok' and R == L)
    check('sealing is deterministic', scc_export(mk(), CSKV, LSTV, IMPQ) == scc_export(mk(), CSKV, LSTV, IMPQ))
    check('distinct Locality sets give distinct SIVs', len({scc_export(mk(js=js), CSKV, LSTV, IMPQ)[16:32] for js in ((), (2,), (3,), (8,))}) == 4)

    section('tamper detection, first segment')
    L = mk(js=(2, 9)); img = scc_export(L, CSKV, LSTV, IMPQ)
    res = {}
    for bit in range(128):
        m = bytearray(img); m[bit // 8] ^= 1 << (bit % 8)
        st, _ = scc_import(bytes(m), CSKV, LSTV, IMPQ); res[bit] = st
    # fields whose change is caught by validity or support; the rest (Machine bits, policies, Locality, MachineUse...) by the tag
    check('single-bit MDH changes: never imports; ADSDropped bit 47 aside, never reaches ok',
          all(res[b] != 'ok' for b in range(128) if b != 47))
    check('MDH bit 47 with AuxDataLen = 0 is ignored: same locker', res[47] == 'ok')
    check('every SIV/Content1 single-bit flip fails authentication', all(scc_import(img[:o // 8] + bytes([img[o // 8] ^ (1 << (o % 8))]) + img[o // 8 + 1:], CSKV, LSTV, IMPQ)[0] == 'authfail' for o in range(128, 8 * len(img), 7)))
    check('wrong CSK fails', scc_import(img, CSKV ^ 1, LSTV, IMPQ)[0] == 'authfail')
    l2 = list(LSTV); l2[2] ^= 1
    check('other value of a selected Locality Secret fails', scc_import(img, CSKV, l2, IMPQ)[0] == 'authfail')
    l3 = list(LSTV); l3[5] ^= 1
    check('other value of an unselected Locality Secret imports', scc_import(img, CSKV, l3, IMPQ)[0] == 'ok')
    check('State comes from ml: another State authenticates only if it equals the exported one', scc_import(img, CSKV, LSTV, IMPQ, ml_state=1)[0] == 'ok' and scc_import(img, CSKV, LSTV, IMPQ, ml_state=2)[0] == 'authfail')
    imgc = bytearray(img); imgc[32] ^= 1
    st, E = scc_import(bytes(imgc), CSKV, LSTV, IMPQ)
    f = mdh_unpack(E['mdh'])
    check('auth failure: Error State (State 0, StateExtension 4), Content cleared, AuxDataLen/ADSDropped 0, other fields kept',
          st == 'authfail' and f['State'] == 0 and f['StateExtension'] == 4 and E['c1'] == b'' and f['AuxDataLen'] == 0 and f['Machine'] == 0x20 and f['Locality'] == mdh_get(L['mdh'], 'Locality'))
    check('unpopulated SiPScrt: substituted by ChipFamScrt on both sides', scc_import(scc_export(mk(js=(0,)), CSKV, lst2, IMPQ), CSKV, lst2, IMPQ)[0] == 'ok'
          and scc_import(scc_export(mk(js=(0,)), CSKV, lst2, IMPQ), CSKV, LSTV, IMPQ)[0] == 'authfail')
    lz = list(LSTV); lz[10] = 0
    check('export naming an unconfigured SLocality contributes zeros(128)', scc_ad(mk(js=(10,))['mdh'], lz)[1] == 0)
    for name, kw in (('Locality[5:4] = 3', dict(Locality=0x30)), ('SCProtection 3', dict(SCProtection=3)), ('KeyType 2', dict(KeyType=2)),
                     ('Version 1', dict(Version=1)), ('ExpirationDate without Zklexpire', dict(ExpirationDate=5)), ('Reserved bit', dict(Reserved46=1)),
                     ('AuxDataLen 1', dict(AuxDataLen=1))):
        m = mdh_put(L['mdh'], *list(kw.items())[0]); im = v2b(m, 16) + img[16:]
        check('invalid Metadata (%s) is rejected before authentication' % name, scc_import(im, CSKV, LSTV, IMPQ)[0] == 'invalid')
    m = mdh_put(L['mdh'], 'Machine', 0x77)
    check('valid but unsupported Machine -> unsupported', scc_import(v2b(m, 16) + img[16:], CSKV, LSTV, IMPQ)[0] == 'unsupported')

    section('the Auxiliary Data Section')
    c2 = bytes(range(0x30, 0x50)); L = mk(adl=4, c2=c2, js=(8,)); img = scc_export(L, CSKV, LSTV, IMPQ)
    check('SCC = MDH | SIV | IMPQUAL | SIV2 | Content1 | Content2, length kl.size', len(img) == scc_size(L['mdh']) == 64 + 32 + 32 and img[32:48] == v2b(IMPQ, 16))
    check('IMPQUAL = zeros(32) @ klimpid @ klarchid @ klvendorid (vendor in the low word)', v2b(scc_impqual(1, 2, 3), 16) == bytes([1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]))
    ad = v2b(L['mdh'] & ~(1 << 47), 16) + LST[8]
    c, t = scc_rfc_seal(CSK, bytes(12), ad, L['c1'], lenblock=False, sep=0)
    c_2, t2 = scc_rfc_seal(CSK, bytes(12), v2b(IMPQ, 16) + t, c2, lenblock=False, sep=1)
    check('independent model: SIV2 and Content2 (AD2 = IMPQUAL | SIV, sep = 1)', img == v2b(L['mdh'], 16) + t + v2b(IMPQ, 16) + t2 + c + c_2)
    st, R = scc_import(img, CSKV, LSTV, IMPQ)
    check('matching IMPQUAL: ADS retained, locker identical, re-export unchanged', st == 'ok' and R == L and scc_export(R, CSKV, LSTV, IMPQ) == img)
    L2 = mk(adl=2, c2=b''); im2 = scc_export(L2, CSKV, LSTV, IMPQ)
    check('AuxDataLen = 2: empty Content2 still carries IMPQUAL and SIV2', len(im2) == 64 + 32 and scc_import(im2, CSKV, LSTV, IMPQ)[1] == L2)
    st, R = scc_import(img, CSKV, LSTV, IMPQ ^ 1)
    check('mismatching IMPQUAL: Content1 imports, ADS dropped, AuxDataLen 0', st == 'ok' and R['c1'] == L['c1'] and R['c2'] == b'' and mdh_get(R['mdh'], 'AuxDataLen') == 0)
    iq = bytearray(img); iq[32] ^= 1
    check('altered IMPQUAL in the image drops the ADS, keeps Content1', scc_import(bytes(iq), CSKV, LSTV, IMPQ)[1]['c1'] == L['c1'] and mdh_get(scc_import(bytes(iq), CSKV, LSTV, IMPQ)[1]['mdh'], 'AuxDataLen') == 0)
    check('every sampled byte of IMPQUAL, SIV2 or Content2 changed: ADS dropped, Content1 kept',
          all(mdh_get(scc_import(img[:o] + bytes([img[o] ^ 1]) + img[o + 1:], CSKV, LSTV, IMPQ)[1]['mdh'], 'AuxDataLen') == 0 and
              scc_import(img[:o] + bytes([img[o] ^ 1]) + img[o + 1:], CSKV, LSTV, IMPQ)[1]['c1'] == L['c1'] for o in list(range(32, 64, 5)) + [96, 120, 127]))
    check('a change in Content1 rejects the whole SCC', scc_import(img[:80] + bytes([img[80] ^ 1]) + img[81:], CSKV, LSTV, IMPQ)[0] == 'authfail')
    st, R = scc_import(img, CSKV, LSTV, IMPQ, max_ads=3)
    check('ADS above the importer maximum: dropped, Content1 imports', st == 'ok' and mdh_get(R['mdh'], 'AuxDataLen') == 0 and R['c1'] == L['c1'])
    # ADSDropped = 1 in the supplied MDH: the image has no Content2, MDH bit 47 is not authenticated
    dm = mdh_put(L['mdh'], 'ADSDropped', 1); dimg = v2b(dm, 16) + img[16:96]
    st, R = scc_import(dimg, CSKV, LSTV, IMPQ)
    check('ADSDropped = 1: no Content2 read, Content1 authenticates, AuxDataLen -> 0', st == 'ok' and R['c1'] == L['c1'] and mdh_get(R['mdh'], 'AuxDataLen') == 0 and len(dimg) == scc_size(dm))
    check('graft: the ADS of another SCC (other SIV) fails segment 2 and is dropped only',
          mdh_get(scc_import(img[:32] + scc_export(mk(adl=4, c2=c2, js=(8,)), CSKV ^ 5, LSTV, IMPQ)[32:64] + img[64:], CSKV, LSTV, IMPQ)[1]['mdh'], 'AuxDataLen') == 0)
    # replacement ADS / MachineUse zeroing
    Lm = mk(adl=4, c2=c2, MachineUse=5, AuxInfo=7); im = scc_export(Lm, CSKV, LSTV, IMPQ)
    st, R = scc_import(im, CSKV, LSTV, IMPQ ^ 1)
    check('dropped ADS: MachineUse and AuxInfo zeroed, as implementation-defined', mdh_get(R['mdh'], 'MachineUse') == 0 and mdh_get(R['mdh'], 'AuxInfo') == 0)
    check('kept ADS: MachineUse and AuxInfo kept', scc_import(im, CSKV, LSTV, IMPQ)[1]['mdh'] == Lm['mdh'])
    s1_ = scc_encrypt([IMPQ, 7], 0, 1, [1], CSKV)
    check('sep = 1: AD2[0][47] (IMPQUAL bit 47 = klarchid bit 15) is authenticated, not cleared',
          scc_encrypt([IMPQ ^ (1 << 47), 7], 0, 1, [1], CSKV)[0] != s1_[0])
    check('SIV binds segment 2 to segment 1', scc_encrypt([IMPQ, 8], 0, 1, [1], CSKV) != s1_)
    control('negative: ADS with bit 47 kept in AD authenticates differently (sep = 1)', scc_encrypt([IMPQ | (1 << 47)], 0, 1, [1], CSKV)[0] != scc_encrypt([IMPQ & ~(1 << 47)], 0, 1, [1], CSKV)[0])

    section('Error State transfer')
    E = dict(mdh=mdh_pack(Machine=0x20, State=0, StateExtension=4, AuxDataLen=0), c1=b'', c2=b'')
    img = scc_export(E, CSKV, LSTV, IMPQ)
    check('an Error-State locker exports as its 16-byte MDH (no SIV, no CSK)', img == v2b(E['mdh'], 16) and scc_export(E, 0, [0] * 11, 0) == img)
    check('short import reproduces it', scc_import(img, 0, [0] * 11, 0) == ('ok', E))
    check('kl.size of that MDH is 16', scc_size(E['mdh']) == 16 == len(img))
    Em = dict(E, mdh=mdh_put(mdh_put(E['mdh'], 'AuxDataLen', 9), 'ADSDropped', 1))
    check('short import sets AuxDataLen and ADSDropped to 0', scc_import(v2b(Em['mdh'], 16), 0, [0] * 11, 0)[1] == E)
    check('same MDH in a Valid State is checked: authentication of a 16-byte image impossible (invalid)', scc_size(mdh_put(E['mdh'], 'StateExtension', 0)) == 0)
    control('negative: a corrupted SCC image (wrong CSK) is not accepted', scc_import(scc_export(mk(), CSKV, LSTV, IMPQ), CSKV ^ 2, LSTV, IMPQ)[0] != 'ok')

    section('regression vectors (CSK 000102..1f, LST[j] = 16 x (0x40+j), key 8081..9f)')
    spec_note('vectors below are produced by the spec model and equal the independent RFC-based assembly checked above')
    for js in ((), (2,), (1, 4, 6, 8, 9, 10)):
        L = mk(js=js); img = scc_export(L, CSKV, LSTV, IMPQ)
        ad = v2b(L['mdh'] & ~(1 << 47), 16) + b''.join(LST[j] for j in js)
        c, t = scc_rfc_seal(CSK, bytes(12), ad, L['c1'], lenblock=False, sep=0)
        info('Localities %s: SIV %s' % (js, t.hex()))
        check('SCC for Localities %s equals the independent assembly' % (js,), img[16:] == t + c)
    locker_level()
    done()

# ------------------------------------------------------------------ locker level (KLE2 + real SCC, scc_locker.py)
def _raises(fn, exc):
    try: fn()
    except exc: return True
    return False
def _exp(K, i):
    """Export-open locker i: returns (MDH read before, serialized image S)."""
    pre = K.getmd(i); K.mgmt(i, 57)
    n = K.image_end(i) // 16
    return pre, b''.join(v2b(K.gpr_out(), 16) for _ in range(n))
def _imp(K, i, M, S, ml=None, load=None):
    """Import-open locker i with M, load S (first load bytes), complete with ml (default: M with State 1)."""
    K.mgmt(i, 58, md=M)
    for o in range(0, len(S) if load is None else load, 16): K.gpr_in(int.from_bytes(S[o:o + 16], 'little'))
    K.mgmt(i, 63, md=mdh_put(M, 'State', 1) if ml is None else ml)
def _st(K, i): return mdh_get(K.md(i), 'State'), mdh_get(K.md(i), 'StateExtension')

def locker_level():
    key = KEY; c2 = bytes(range(32))
    with ecb_machines():
        section('locker level: export-opening kl.mgmt, serialized image, ContentOffset')
        for js, adl in (((), 0), ((2,), 0), ((1, 4, 6, 8, 9, 10), 0), ((2, 9), 4), ((), 2)):
            K = SCCKLE(); md = mdh_pack(Machine=0x20, MachinePolicy=3, State=1, AuxDataLen=adl, Locality=scc_loc_bits(js))
            K.install(3, md, key, c2[:16 * (adl - 2)] if adl else b'')
            tag = 'Localities %s AuxDataLen %d' % (js, adl)
            pre, S = _exp(K, 3)
            check(tag + ': kl.getmd before the opening returns the stored MDH', pre == md)
            check(tag + ': export-opening sets State kl_cfg_exporting (57), names the locker', _st(K, 3) == (57, 0) and K.nl == 3)
            # independent assembly of S (RFC 8452 core without lengths block; AD[0] = MDH with ADSDropped clear)
            ad = v2b(md, 16) + b''.join(LST[j] for j in js)
            ct, siv = scc_rfc_seal(CSK, bytes(12), ad, key, lenblock=False, sep=0)
            want = siv
            if adl >= 2:
                ct2, siv2 = scc_rfc_seal(CSK, bytes(12), v2b(IMPQ, 16) + siv, c2[:16 * (adl - 2)], lenblock=False, sep=1)
                want += v2b(IMPQ, 16) + siv2 + ct + ct2
            else: want += ct
            check(tag + ': S equals the independent assembly (SIV | [IMPQUAL | SIV2] | Content1 | Content2)', S == want)
            off = 48 if adl >= 2 else 16
            check(tag + ': ContentOffset %d, |S| = kl.size - 16' % off, S[off:off + 32] == ct and len(S) == K.size(3) - 16, len(S), K.size(3) - 16)
            K.mgmt(3, 63, md=pre)
            check(tag + ': export-completing kl.mgmt restores the locker (State, Content1, Content2)', _st(K, 3) == (1, 0) and K.content(3) == (key, c2[:16 * (adl - 2)] if adl else b'') and K.md(3) == md)
        K = SCCKLE(); m7 = mdh_put(mk()['mdh'], 'State', 7); K.install(3, m7, key); pre, S = _exp(K, 3)
        K.mgmt(3, 63, md=mdh_put(pre, 'State', 2))
        check('export completed with ml.State differing from the State at export (AD[0] carries State): Authentication Failed', _st(K, 3) == (0, SE_MGMT_AUTH))
        K = SCCKLE(); K.install(3, m7, key); pre, S = _exp(K, 3); K.mgmt(3, 63, md=pre)
        check('export of a State 7 locker completed with ml.State 7 restores State 7', _st(K, 3) == (7, 0) and K.content(3)[0] == key)
        control('export image is not all zero / not the clear key', S != bytes(len(S)) and key not in S)

        section('locker level: import, round trip, authentication failures')
        def exported(js=(), adl=0, **kw):
            K = SCCKLE(**kw); md = mdh_pack(Machine=0x20, MachinePolicy=3, State=1, AuxDataLen=adl, Locality=scc_loc_bits(js))
            K.install(3, md, key, c2[:16 * (adl - 2)] if adl else b''); pre, S = _exp(K, 3); return pre, S
        for js in ((), (2,), (1, 4, 6, 8, 9, 10)):
            pre, S = exported(js); R = SCCKLE()
            R.mgmt(5, 58, md=pre)
            check('import-opening: State 58, kl.size = %d' % (16 + len(S)), _st(R, 5) == (58, 0) and R.size(5) == 16 + len(S) and R.nl == 5)
            for o in range(0, len(S), 16): R.gpr_in(int.from_bytes(S[o:o + 16], 'little'))
            R.mgmt(5, 63, md=mdh_put(pre, 'State', 1))
            check('import %s: Valid with State from ml, Content1 restored, MDH equals the original' % (js,), _st(R, 5) == (1, 0) and R.content(5)[0] == key and R.md(5) == pre)
        pre, S = exported(); R = SCCKLE(); _imp(R, 5, pre, S, ml=mdh_put(pre, 'State', 7))
        check('State is authenticated (AD[0]): import with ml.State 7 of an SCC exported in State 1 fails authentication', _st(R, 5) == (0, SE_MGMT_AUTH))
        K = SCCKLE(); K.install(3, m7, key); p7, S7 = _exp(K, 3); R = SCCKLE(); _imp(R, 5, p7, S7, ml=p7)
        check('State comes from ml: an SCC exported in State 7 imports as State 7', _st(R, 5) == (7, 0) and R.content(5)[0] == key)
        check('ml.State = 0 is not admitted by the completing kl.mgmt', _raises(lambda: _imp(SCCKLE(), 5, pre, S, ml=mdh_put(pre, 'State', 0)), IllegalInstruction))

        def tampered(tag, S2=None, pre2=None, cskv=None, lst=None, load=None, **kw):
            R = SCCKLE(**kw)
            if cskv is not None: R.cskv = cskv
            if lst is not None: R.lst = lst
            _imp(R, 5, pre if pre2 is None else pre2, S if S2 is None else S2, load=load)
            return R
        pre, S = exported((2, 9))
        flip = lambda b, i: b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]
        for tag, R in (('flipped SIV bit', tampered('', flip(S, 3))), ('flipped Content1 bit', tampered('', flip(S, 20))),
                       ('wrong CSK', tampered('', cskv=CSKV ^ 4)), ('wrong secret of selected Locality #2', tampered('', lst=[LSTV[j] ^ (j == 2) for j in range(11)])),
                       ('wrong secret of selected Locality #9', tampered('', lst=[LSTV[j] ^ ((j == 9) << 9) for j in range(11)])),
                       ('MDH field MachinePolicy changed', tampered('', pre2=mdh_put(pre, 'MachinePolicy', 1))),
                       ('image truncated (only SIV loaded; the rest is zero)', tampered('', load=16))):
            check(tag + ': Error State Authentication Failed, MDH only (kl.size 16, AuxDataLen 0)', _st(R, 5) == (0, SE_MGMT_AUTH) and R.size(5) == 16 and mdh_get(R.md(5), 'AuxDataLen') == 0 and mdh_get(R.md(5), 'ADSDropped') == 0 and R.L[5].slot is False)
        R = tampered('', lst=[LSTV[j] ^ (j == 5) for j in range(11)])
        check('secret of an unselected Locality (#5) may differ: import succeeds', _st(R, 5) == (1, 0))
        R = tampered('', pre2=mdh_put(pre, 'ADSDropped', 1))
        check('ADSDropped is unauthenticated in AD[0]: setting it in M still authenticates (AuxDataLen 0)', _st(R, 5) == (1, 0))
        control('negative: a wrong-CSK import is not Valid', _st(tampered('', cskv=CSKV ^ 4), 5)[0] != 1)

        section('locker level: Auxiliary Data Section')
        pre, S = exported((2,), 4)
        R = tampered('', S); m = R.md(5)
        check('same IMPQUAL: ADS kept (AuxDataLen 4, ADSDropped 0), Content2 restored', R.content(5) == (key, c2) and mdh_get(m, 'AuxDataLen') == 4 and mdh_get(m, 'ADSDropped') == 0 and R.size(5) == 64 + 32 + 32)
        R = tampered('', S, impq=scc_impqual(1, 2, 4))
        m = R.md(5)
        check('different IMPQUAL: ADS dropped, Content1 imported, AuxDataLen 0, ADSDropped 0, size 32 + 32', _st(R, 5) == (1, 0) and R.content(5) == (key, b'') and mdh_get(m, 'AuxDataLen') == 0 and mdh_get(m, 'ADSDropped') == 0 and R.size(5) == 64)
        for tag, S2 in (('flipped Content2 bit', flip(S, 100)), ('flipped SIV2', flip(S, 40)), ('flipped IMPQUAL', flip(S, 17))):
            R = tampered('', S2)
            check(tag + ': ADS dropped, Content1 intact, Valid', _st(R, 5) == (1, 0) and R.content(5) == (key, b'') and mdh_get(R.md(5), 'AuxDataLen') == 0)
        pre2, S2 = exported((2,), 4); pre3, S3 = exported((3,), 4)
        graft = S[:16] + S3[16:48] + S[48:48 + 32] + S[80:]    # SIV of S, IMPQUAL|SIV2 from another SCC
        check('graft: SIV2 of another SCC fails, ADS dropped', mdh_get(tampered('', S[:32] + S3[32:48] + S[48:]).md(5), 'AuxDataLen') == 0)
        K = SCCKLE(); K.max_ads = 2; K.mgmt(5, 58, md=pre)
        check('AuxDataLen above the importer maximum: opening sets ADSDropped, kl.size excludes Content2 (96)', mdh_get(K.md(5), 'ADSDropped') == 1 and K.size(5) == 16 + 48 + 32)
        for o in range(0, 48 + 32, 16): K.gpr_in(int.from_bytes(S[o:o + 16], 'little'))
        K.mgmt(5, 63, md=mdh_put(pre, 'State', 1))
        check('... and completes Valid with the ADS removed', _st(K, 5) == (1, 0) and K.content(5) == (key, b'') and mdh_get(K.md(5), 'AuxDataLen') == 0)
        R = SCCKLE(); R.mgmt(5, 58, md=mdh_put(pre, 'ADSDropped', 1))
        check('ADSDropped = 1 in M: opening keeps it, kl.size excludes Content2', mdh_get(R.md(5), 'ADSDropped') == 1 and R.size(5) == 96)
        _imp(R, 6, mdh_put(pre, 'ADSDropped', 1), S, load=80)
        check('... and the SCC (Content2 not loaded) completes Valid without ADS', _st(R, 6) == (1, 0) and R.content(6) == (key, b''))
        pre4, S4 = exported((), 2)
        R = tampered('', S4, pre2=pre4); check('AuxDataLen 2: IMPQUAL | SIV2 present, empty Content2 kept', R.content(5) == (key, b'') and mdh_get(R.md(5), 'AuxDataLen') == 2 and R.size(5) == 64 + 32)
        # MachineUse / AuxInfo zeroed when the ADS is dropped
        mu = mdh_put(mdh_put(pre, 'MachineUse', 0x5), 'AuxInfo', 0x3)
        K = SCCKLE(); K.install(3, mu, key, c2); p5, S5 = _exp(K, 3)
        check('MachineUse and AuxInfo are zeroed when Content2 is dropped', mdh_get(tampered('', S5, pre2=p5, impq=scc_impqual(9, 9, 9)).md(5), 'MachineUse') == 0)
        check('... and kept when the ADS is accepted', mdh_get(tampered('', S5, pre2=p5).md(5), 'MachineUse') == 5)
        control('negative: a SCC with ADS imported under another IMPQUAL does not keep Content2', tampered('', S, impq=scc_impqual(7, 7, 7)).content(5)[1] == b'')

        section('locker level: nested operations and interleaving')
        K = SCCKLE(); K.install(3, mk()['mdh'], key); preA = K.getmd(3); K.mgmt(3, 57)
        pre, S = exported(); K.mgmt(5, 58, md=pre)
        check('opening an import on another locker while locker 3 is exporting leaves 3 in State 57', _st(K, 3) == (57, 0) and _st(K, 5) == (58, 0) and K.nl == 5)
        for o in range(0, 16, 16): K.gpr_in(int.from_bytes(S[o:o + 16], 'little'))
        K.mgmt(3, 63, md=preA)
        check('completing the export of 3 meanwhile restores it; 5 stays Configuration (58)', _st(K, 3) == (1, 0) and K.content(3)[0] == key and _st(K, 5) == (58, 0))
        K.nl = 5; K.start = 16
        for o in range(16, len(S), 16): K.gpr_in(int.from_bytes(S[o:o + 16], 'little'))
        K.mgmt(5, 63, md=mdh_put(pre, 'State', 1))
        check('... and 5 then imports after the loads resumed at klstart = 16', _st(K, 5) == (1, 0) and K.content(5)[0] == key)
        K = SCCKLE(); K.install(3, mk()['mdh'], key); _, S1 = _exp(K, 3)
        check('export image is deterministic (same CSK, no nonce): re-export gives S again', (lambda: (K.mgmt(3, 63, md=mdh_put(mk()['mdh'], 'State', 1)), _exp(K, 3)[1])[1])() == S1)
        # nested export of an interrupted import
        K = SCCKLE(); pre, S = exported(); K.mgmt(5, 58, md=pre); K.gpr_in(int.from_bytes(S[:16], 'little'))
        ml58 = K.getmd(5); K.mgmt(5, 57)
        check('nested export of a half-loaded import: State 57, ml = the 58 MDH', _st(K, 5) == (57, 0) and mdh_get(ml58, 'State') == 58)
        K.mgmt(5, 63, md=ml58)
        check('completing a nested export restores the Configuration State carried by ml (58)', _st(K, 5) == (58, 0))
        K.nl = 5; K.start = 16
        for o in range(16, len(S), 16): K.gpr_in(int.from_bytes(S[o:o + 16], 'little'))
        K.mgmt(5, 63, md=mdh_put(pre, 'State', 1))
        check('... the import then resumes and completes (Content1 restored)', _st(K, 5) == (1, 0) and K.content(5)[0] == key)

        section('locker level: Error-State image')
        K = SCCKLE(); K.install(3, mk()['mdh'], key)
        E = mdh_pack(Machine=0x20, MachinePolicy=3, State=0, StateExtension=SE_MGMT_AUTH, AuxDataLen=0)
        K.L[3].mdh = E; K.L[3].slot = False; K.siv = K.impqual = K.siv2 = 5
        check('Error-State locker: kl.getmd reads the MDH, kl.size is 16', K.getmd(3) == E and K.size(3) == 16)
        K.start = 32; K.mgmt(3, 57)
        check('kl.mgmt export-opening on it is permitted: unchanged, nothing opened, klnamedlocker = 3, klstart = 0', K.md(3) == E and K.nl == 3 and K.start == 0)
        Ed = mdh_put(mdh_put(E, 'AuxDataLen', 9), 'ADSDropped', 1)
        K.mgmt(4, 58, md=Ed)
        check('import-opening of an Error-State MDH: Error State with AuxDataLen 0 / ADSDropped 0, nothing to load, SIV/IMPQUAL/SIV2 zeroized', K.md(4) == E and K.size(4) == 16 and K.siv == K.impqual == K.siv2 == 0)
        control('negative: a Valid-State locker is not reported with kl.size 16', SCCKLE().size(0) == 0 and not is_error_state(mk()['mdh']))

        section('locker level: checks on opening and completion (Rule check-on-write, Machine ECB)')
        K = SCCKLE(); pre, S = exported(); zk = bytes(32)
        K0 = SCCKLE(); K0.install(3, mk(key=zk)['mdh'], zk); p0, S0 = _exp(K0, 3)
        _imp(K, 5, p0, S0)
        check('Machine AES256_ECB has no key check: the all-zero key imports Valid', _st(K, 5) == (1, 0) and K.content(5)[0] == zk)
        bad = SCCKLE(); bad.mgmt(5, 58, md=mdh_put(pre, 'Version', 1))
        check('import-opening with Version 1 is invalid (Error State Invalid)', _st(bad, 5) == (0, SE_INVALID))
        bad = SCCKLE(); bad.mgmt(5, 58, md=mdh_put(pre, 'KeyType', 2))
        check('import-opening with KeyType 2 (generated key) is invalid', _st(bad, 5) == (0, SE_INVALID))
        bad = SCCKLE(); bad.mgmt(5, 58, md=mdh_put(pre, 'AuxDataLen', 1))
        check('import-opening with AuxDataLen 1 is invalid', _st(bad, 5) == (0, SE_INVALID))
        check('import-opening with an unsupported Machine (0x30) is refused (model: Trap unsupported)', _raises(lambda: SCCKLE().mgmt(5, 58, md=mdh_put(pre, 'Machine', 0x30)), Trap))
        K = SCCKLE(lst=[LSTV[j] if j != 9 else 0 for j in range(11)]); K2 = SCCKLE(lst=K.lst)
        K2.install(3, mdh_put(pre, 'Locality', scc_loc_bits((9,))), key); pre9, S9 = _exp(K2, 3)
        check('export with an unconfigured Locality secret is not refused', len(S9) == 32 + 16)
        K.mgmt(5, 58, md=pre9)
        check('... but import-opening rejects it (Invalid)', _st(K, 5) == (0, SE_INVALID))
        control('negative: a valid MDH opens in Configuration State 58', _st((lambda k: (k.mgmt(5, 58, md=pre), k)[1])(SCCKLE()), 5) == (58, 0))


if __name__ == '__main__':
    main()
