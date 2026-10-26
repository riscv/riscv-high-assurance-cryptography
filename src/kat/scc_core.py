"""SCC cryptography and function-level export/import (extracted from scc-kat.py so other KATs can import it)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *

from common import *

H = bytes.fromhex

# ------------------------------------------------------------------ (1) independent RFC 8452
_P = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1      # x^128+x^127+x^126+x^121+1
def _mul(a, b):
    r = 0
    for i in range(128):
        if (b >> i) & 1: r ^= a << i
    for i in range(255, 127, -1):
        if (r >> i) & 1: r ^= _P << (i - 128)
    return r
def _xinv(a):          # a * x^-1
    return (a ^ _P) >> 1 if a & 1 else a >> 1
def scc_rfc_polyval(h, data):
    h = int.from_bytes(h, 'little'); s = 0
    for i in range(0, len(data), 16):
        s = _mul(s ^ int.from_bytes(data[i:i + 16], 'little'), h)
        for _ in range(128): s = _xinv(s)
    return s.to_bytes(16, 'little')
def scc_rfc_keys(key, nonce):
    out = b''.join(aes_enc(key, i.to_bytes(4, 'little') + nonce)[:8] for i in range(6))
    return out[:16], out[16:] if len(key) == 32 else out[16:32]   # auth key, enc key
def scc_rfc_seal(key, nonce, aad, pt, lenblock=True, sep=None):
    """RFC 8452 encryption; lenblock=False omits the lengths block; sep (0/1) overrides bit 126 of tag input and counter."""
    ak, ek = scc_rfc_keys(key, nonce)
    pad = lambda x: x + b'\0' * (-len(x) % 16)
    d = pad(aad) + pad(pt) + ((len(aad) * 8).to_bytes(8, 'little') + (len(pt) * 8).to_bytes(8, 'little') if lenblock else b'')
    s = bytearray(scc_rfc_polyval(ak, d))
    for i in range(12): s[i] ^= nonce[i]
    s[15] &= 0x7f
    if sep is not None: s[15] = (s[15] & 0xbf) | (sep << 6)
    tag = aes_enc(ek, bytes(s))
    ctr = bytearray(tag); ctr[15] |= 0x80
    if sep is not None: ctr[15] = (ctr[15] & 0xbf) | (sep << 6)
    c = b''
    c0 = int.from_bytes(ctr[:4], 'little')
    for i in range(0, len(pt), 16):
        blk = ((c0 + i // 16) & 0xffffffff).to_bytes(4, 'little') + bytes(ctr[4:])
        c += bxor(pt[i:i + 16], aes_enc(ek, blk)[:len(pt[i:i + 16])])
    return c, tag

# ------------------------------------------------------------------ (2) spec pseudocode
def scc_keyderiv(key, nonce):                       # key: 256-bit value, nonce: 96-bit value
    A = [b2v(aes_enc(v2b(key, 32), v2b(cat((nonce, 96), (i, 32)), 16))) for i in range(6)]
    return (cat((sl(A[5], 63, 0), 64), (sl(A[4], 63, 0), 64), (sl(A[3], 63, 0), 64), (sl(A[2], 63, 0), 64)),
            cat((sl(A[1], 63, 0), 64), (sl(A[0], 63, 0), 64)))
def _E(k, v): return b2v(aes_enc(v2b(k, 32), v2b(v, 16)))
def _ctr(sep, siv, i): return cat((1, 1), (sep, 1), (sl(siv, 125, 32), 94), ((sl(siv, 31, 0) + i) % 2**32, 32))
def scc_encrypt(AD, N, sep, P, K):
    ek, ak = scc_keyderiv(K, N)
    ad = list(AD)
    if sep == 0: ad[0] &= ~(1 << 47)
    siv = polyval(ak, ad + list(P))
    siv ^= N
    siv = _E(ek, cat((0, 1), (sep, 1), (sl(siv, 125, 0), 126)))
    return siv, [p ^ _E(ek, _ctr(sep, siv, i)) for i, p in enumerate(P)]
def scc_decrypt(AD, N, sep, SIV, C, K):
    assert len(AD) <= 7
    ek, ak = scc_keyderiv(K, N)
    ad = list(AD)
    if sep == 0: ad[0] &= ~(1 << 47)
    P = [c ^ _E(ek, _ctr(sep, SIV, i)) for i, c in enumerate(C)]
    t = polyval(ak, ad + P) ^ N
    t = _E(ek, cat((0, 1), (sep, 1), (sl(t, 125, 0), 126)))
    return (True, P) if t == SIV else (False, [0] * len(C))

# ------------------------------------------------------------------ locker model of export / import
SCC_MACHINES = {0x20: 32, 0x00: 16}          # supported Machines: AES256_ECB, AES128_ECB (key bytes)
def scc_loc_bits(js):
    """Locality field with exactly the entries js (at most one per subfield; entries 8-10 independent)."""
    v = 0
    for j in js:
        if j < 3: v |= (j + 1)
        elif j < 6: v |= (j - 2) << 2
        elif j < 8: v |= (j - 5) << 4
        else: v |= 1 << (j - 2)
    return v
def scc_includes(loc, j):
    if j < 3: return sl(loc, 1, 0) == j + 1
    if j < 6: return sl(loc, 3, 2) == j - 2
    if j < 8: return sl(loc, 5, 4) == j - 5
    return sl(loc, 8, 6) >> (j - 8) & 1 == 1
def scc_lst_eff(lst):
    e = list(lst)
    for chain in ((0, 1, 2), (3, 4, 5)):
        for a in range(3):
            if e[chain[a]] == 0:
                for b in range(a + 1, 3):
                    if lst[chain[b]]: e[chain[a]] = lst[chain[b]]; break
    return e
def scc_content1_size(mdh):
    f = mdh_unpack(mdh); n = SCC_MACHINES[f['Machine']]
    return 16 if f['KeyType'] == 1 else n
def scc_content2_size(mdh):
    f = mdh_unpack(mdh)
    return 16 * (f['AuxDataLen'] - 2) if f['AuxDataLen'] >= 2 and not f['ADSDropped'] else 0
def scc_size(mdh):
    """kl.size for a Valid-State ECB MDH (items 7 and 8 of the list); 0 on invalid/unsupported; 16 for Error States."""
    f = mdh_unpack(mdh)
    if f['State'] in (61, 62, 63) or (f['State'] == 0 and f['StateExtension'] >= 7): return 0
    if f['State'] == 0 and f['StateExtension'] >= 1: return 16
    if f['Version'] in (1, 2) or f['SCProtection'] == 3 or f['KeyType'] == 3: return 0
    if scc_invalid(mdh) or f['Machine'] not in SCC_MACHINES: return 0
    c1 = scc_content1_size(mdh)
    return 32 + c1 if f['AuxDataLen'] == 0 else 64 + c1 + scc_content2_size(mdh)
def scc_invalid(mdh, lst=None):
    f = mdh_unpack(mdh)
    return (f['Version'] != 0 or f['KeyType'] in (2, 3) or f['SCProtection'] == 3 or sl(f['Locality'], 5, 4) == 3
            or f['Reserved31_30'] or f['Reserved46'] or f['Reserved79_78'] or f['Reserved127_116']
            or f['StateExtension'] != 0 or f['State'] in (0, 61, 62, 63) or f['ExpirationDate'] != 0
            or f['AuxDataLen'] == 1 )
def scc_impqual(vendor, arch, imp): return cat((0, 32), (imp, 32), (arch, 32), (vendor, 32))
def _blocks(b): return [b2v(b[i:i + 16]) for i in range(0, len(b), 16)]
def _bytes(vs): return b''.join(v2b(v, 16) for v in vs)
def scc_ad(mdh, lst):
    ad = [mdh]
    for j, s in enumerate(scc_lst_eff(lst)):
        if scc_includes(mdh_get(mdh, 'Locality'), j): ad.append(s)
    return ad
def scc_export(L, csk, lst, impq):
    """L: dict(mdh, c1 bytes, c2 bytes).  Returns the SCC image bytes."""
    f = mdh_unpack(L['mdh'])
    if f['State'] == 0 and f['StateExtension'] in ERROR_STATES: return v2b(L['mdh'], 16)
    assert f['ADSDropped'] == 0
    pad = L['c1'] + b'\0' * (-len(L['c1']) % 16)
    siv, c1 = scc_encrypt(scc_ad(L['mdh'], lst), 0, 0, _blocks(pad), csk)
    img = v2b(L['mdh'], 16) + v2b(siv, 16)
    if f['AuxDataLen'] >= 2:
        siv2, c2 = scc_encrypt([impq, siv], 0, 1, _blocks(L['c2']), csk)
        img += v2b(impq, 16) + v2b(siv2, 16)
    else: c2 = []
    return img + _bytes(c1) + _bytes(c2)
def scc_import(img, csk, lst, impq, max_ads=64, ml_state=None, zklexpire=False):
    """Returns ('ok', L) | ('invalid', None) | ('unsupported', None) | ('authfail', L_error)."""
    M = b2v(img[:16]); f = mdh_unpack(M)
    if f['State'] == 0 and 1 <= f['StateExtension'] <= (6 if zklexpire else 5):   # short import of an Error State
        if scc_invalid(mdh_put(mdh_put(mdh_put(M, 'State', 1), 'StateExtension', 0), 'AuxDataLen', 0)):   # M8: invalid Metadata
            return 'ok', dict(mdh=mdh_pack(State=0, StateExtension=SE_INVALID), c1=b'', c2=b'')
        return 'ok', dict(mdh=mdh_put(mdh_put(M, 'AuxDataLen', 0), 'ADSDropped', 0), c1=b'', c2=b'')
    if f['Machine'] not in SCC_MACHINES and not scc_invalid(M): return 'unsupported', None
    st = f['State'] if ml_state is None else ml_state
    Mv = M if ml_state is None else mdh_put(M, 'State', ml_state)
    if scc_invalid(mdh_put(Mv, 'State', 1)) : return 'invalid', None   # State is substituted from ml
    if f['Machine'] not in SCC_MACHINES: return 'unsupported', None
    drop = int(f['AuxDataLen'] >= 2 and (f['ADSDropped'] == 1 or f['AuxDataLen'] > max_ads))
    work = mdh_put(Mv, 'ADSDropped', drop)
    c1n = scc_content1_size(work); c1p = c1n + (-c1n % 16)
    ads = f['AuxDataLen'] >= 2
    o = 16; siv = b2v(img[o:o + 16]); o += 16
    if ads: iq = b2v(img[o:o + 16]); siv2 = b2v(img[o + 16:o + 32]); o += 32
    c1 = _blocks(img[o:o + c1p]); o += c1p
    c2 = _blocks(img[o:o + 16 * (f['AuxDataLen'] - 2)]) if ads and not drop else []
    ok, P = scc_decrypt(scc_ad(work, lst), 0, 0, siv, c1, csk)
    if not ok:
        e = mdh_put(mdh_put(mdh_put(work, 'State', 0), 'StateExtension', 4), 'AuxDataLen', 0)
        return 'authfail', dict(mdh=mdh_put(e, 'ADSDropped', 0), c1=b'', c2=b'')
    p2 = []
    if ads and not drop:
        good = iq == impq
        if good: good, p2 = scc_decrypt([iq, siv], 0, 1, siv2, c2, csk)
        if not good: drop = 1
        work = mdh_put(work, 'ADSDropped', drop)
    if f['AuxDataLen'] == 0 or drop:
        work = mdh_put(mdh_put(mdh_put(mdh_put(work, 'MachineUse', 0), 'AuxInfo', 0), 'ADSDropped', 0), 'AuxDataLen', 0)
        p2 = []
    return 'ok', dict(mdh=work, c1=_bytes(P)[:c1n], c2=_bytes(p2))
