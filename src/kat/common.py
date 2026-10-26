#!/usr/bin/env pypy3.12
"""Shared primitives of the new KAT suite (independent of src/kat_old/common.py).

Run `pypy3.12 src/kat_old/common.py` for the self-test.  Import as `from common import *`
(from src/kat, i.e. `cd src && pypy3.12 kat/x-kat.py`, where kat is sys.path[0]).

CONVENTIONS (Zkl-notation.adoc)
  A "value" is a Python int V holding an n-bit string, bit i = V[i] (bit 0 least significant).
  A byte string M0..Mn-1 is the value with V[8i+7:8i] = Mi, i.e. int.from_bytes(M, 'little').
  Widths are never stored in the int: pass them (bits `n`, or bytes `nbytes`) where needed.
  Block ciphers and v2b/b2v work on Python `bytes` in the STANDARD's order (byte 0 first);
  the modes' ints are obtained with b2v().  Units: `n` = bytes, `m`/`bits` = bits.

NOTATION
  b2v(bs: bytes) -> int                  bytes -> value (little-endian)
  v2b(v: int, nbytes: int) -> bytes      value -> bytes (v mod 2**(8*nbytes))
  sl(v, hi, lo) -> int                   v[hi:lo], both inclusive
  cat((a, wa), (b, wb), ...) -> int      a @ b @ ...; each part is (value, width_in_bits); first = most significant
  catw(...) -> (value, total_width)      same, also returns the width
  bswap(v, n) -> int                     reverse the n least significant bytes of v (n bytes)
  brev8(v, n) -> int                     reverse the bits inside each of the n bytes of v
  bin_(n, m) -> int                      m least significant bits of n (non-negative or two's complement)
  bxor(a, b) -> int | bytes              xor; both ints, or both bytes of equal length
  MASK128 = 2**128-1;  mask(m) = 2**m-1
  zeros/ones are plain ints: 0, mask(k)

BLOCK CIPHERS (bytes in, bytes out; key lengths 16/24/32 for AES, 16 for SM4, 24 for TDEA = K1|K2|K3)
  aes_enc(key, blk16) / aes_dec(key, blk16)
  sm4_enc(key16, blk16) / sm4_dec(key16, blk16)
  tdea_enc(key24, blk8) / tdea_dec(key24, blk8)   (EDE, K1 enc, K2 dec, K3 enc);  des_enc/des_dec(key8, blk8)
  cipher_enc(name, key, blk), cipher_dec: name in 'AES128','AES192','AES256','SM4','TDEA'

GF(2^128) (all operands/results 128-bit VALUES in the spec's representation)
  ghash_mul(a, b) -> int      Galoismul of Zkl-ISA-machines KLE-GCM-mode: GF(2)[x]/(x^128+x^7+x^2+x+1),
                              coefficient of x^(8i+j) is V[8i+(7-j)]
  montmul(a, b) -> int        Montmul of Zkl-ISA-unpriv KLE-SCC-POLYVAL: a*b*x^-128 in GF(2)[x]/(x^128+x^127+x^126+x^121+1),
                              coefficient of x^k is V[k]
  polyval(auth_key, blocks) -> int   the POLYVAL function of that listing (blocks: list of 128-bit values)
  update_mask(v, sm4=False) / update_mask_inv(v, sm4=False)   XEX/XTS mask update (x multiplication) and inverse;
                              sm4=True: SM4_XEX bit-reversed-bytes variant (literal transcription of the spec text)
  double(s, b=128) -> int     bswap(dbl(bswap(s))) of OCB3/CMAC; b = 128 or 64; for 128 equals bswap(update_mask(bswap(s)))

MDH (Zkl-ISA-unpriv KLE-metadata-header; 128-bit value)
  MDH_FIELDS: ordered list of (name, lo, width); reserved ones named Reserved31_30, Reserved46, Reserved79_78, Reserved127_116
  mdh_pack(**fields) -> int   unspecified fields are 0; ValueError on unknown name or value too wide
  mdh_unpack(mdh) -> dict     all fields incl. reserved
  mdh_get(mdh, name) -> int ; mdh_put(mdh, name, value) -> new mdh (ValueError if too wide)
  State / StateExtension constants: ST_INERT=0, ST_READY=1, ST_SUCCESS=54, ST_FAILURE=55,
  SE_UNCONFIGURED=0 .. SE_EXPIRED=6, ERROR_STATES = frozenset({1..6}) = StateExtension codes that, at State 0, are Error States;
  Configuration States CFG_PROVISIONING=56, CFG_EXPORTING=57, CFG_IMPORTING=58, CFG_PPI_EXPORTING=59, CFG_PPI_IMPORTING=60.
  Machine-defined State numbers (2..53) are NOT here: Machine KATs define their own.
  is_error_state(mdh) -> bool ; is_unconfigured(mdh) -> bool
  setst immed7 constants: KL_CFG_PROVISIONING=56, KL_CFG_EXPORTING=57, KL_CFG_IMPORTING=58, KL_CFG_MANAGEMENT_END=63,
  KL_CFG_CLEAR_ADS=64, KL_CFG_CLEARALL=65  (also: KL_STATE_INERT=0 = kl.clear, KL_STATE_READY=1)
  setst_encode(form, kd, immed7, rs1=0, r=0, g=0) -> int  32-bit instruction word of kl.setst (g=0), kl.setste (g=1),
                              kl.set* getters/setters (g=2: register form F=0 'A'/'B', immediate form F=1 'C'), kl.mgmt (g=3).  form 'A'|'B'|'C'|'D' -> F field (A,B: 0; C: 1; D: 2);
                              Form A forces rs1=0, Form B requires rs1 != 0 (rs1 = Xs / vector reg number in C, D)
  setst_decode(word) -> dict(opcode, kd, funct3, rs1, r, F, G, immed7, form)  form None if F=3 (reserved)

EXCEPTIONS: IllegalInstruction, LoopBound (plain Exception subclasses)

HARNESS (output: `== title`, `PASS  name`, `FAIL  name`, then `KAT-RESULT: PASS|FAIL`)
  section(title); check(name, ok, got=None, want=None) -> bool; control(name, fired): negative control, passes when
  `fired` is true (the test mechanism did detect the injected fault); info(text); spec_note(text) (does not count);
  raises(fn, *a, exc=Exception, **kw) -> bool; done() prints the result line and exits 0/1.
  Counters: N_PASS, N_FAIL (module globals).
"""
import sys

# ---------------------------------------------------------------- exceptions
class IllegalInstruction(Exception): pass
class LoopBound(Exception): pass

# ---------------------------------------------------------------- notation
MASK128 = (1 << 128) - 1
def mask(m): return (1 << m) - 1
def b2v(bs): return int.from_bytes(bytes(bs), 'little')
def v2b(v, nbytes): return (v & mask(8 * nbytes)).to_bytes(nbytes, 'little')
def sl(v, hi, lo): return (v >> lo) & mask(hi - lo + 1)
def catw(*parts):
    v = w = 0
    for x, wx in parts:
        v = (v << wx) | (x & mask(wx)); w += wx
    return v, w
def cat(*parts): return catw(*parts)[0]
def bswap(v, n): return int.from_bytes(v2b(v, n), 'big')
def brev8(v, n):
    r = 0
    for i in range(n):
        r |= int('{:08b}'.format((v >> (8 * i)) & 255)[::-1], 2) << (8 * i)
    return r
def bin_(n, m): return n & mask(m)
def bxor(a, b):
    if isinstance(a, (bytes, bytearray)):
        assert len(a) == len(b)
        return bytes(x ^ y for x, y in zip(a, b))
    return a ^ b

# ---------------------------------------------------------------- AES (FIPS 197)
def _gmul8(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a <<= 1
        if a & 0x100: a ^= 0x11b
        b >>= 1
    return r
def _mk_aes_sbox():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul8(a, b) == 1: inv[a] = b; break
    sb = []
    for a in range(256):
        x = inv[a]; y = x
        for k in (1, 2, 3, 4):
            y ^= ((x << k) | (x >> (8 - k))) & 255
        sb.append(y ^ 0x63)
    return sb
_SB = _mk_aes_sbox()
_ISB = [0] * 256
for _i, _v in enumerate(_SB): _ISB[_v] = _i

def _aes_ks(key):
    nk = len(key) // 4; nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rc = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [_SB[x] for x in t[1:] + t[:1]]; t[0] ^= rc; rc = _gmul8(rc, 2)
        elif nk > 6 and i % nk == 4:
            t = [_SB[x] for x in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum((w[4 * r + c] for c in range(4)), []) for r in range(nr + 1)], nr

def aes_enc(key, blk):
    assert len(key) in (16, 24, 32) and len(blk) == 16
    rk, nr = _aes_ks(key)
    s = [a ^ b for a, b in zip(blk, rk[0])]
    for r in range(1, nr + 1):
        s = [_SB[x] for x in s]
        s = [s[(i % 4) + 4 * (((i // 4) + (i % 4)) % 4)] for i in range(16)]
        if r != nr:
            t = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t += [_gmul8(a[0], 2) ^ _gmul8(a[1], 3) ^ a[2] ^ a[3],
                      a[0] ^ _gmul8(a[1], 2) ^ _gmul8(a[2], 3) ^ a[3],
                      a[0] ^ a[1] ^ _gmul8(a[2], 2) ^ _gmul8(a[3], 3),
                      _gmul8(a[0], 3) ^ a[1] ^ a[2] ^ _gmul8(a[3], 2)]
            s = t
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(s)

def aes_dec(key, blk):
    assert len(key) in (16, 24, 32) and len(blk) == 16
    rk, nr = _aes_ks(key)
    s = [a ^ b for a, b in zip(blk, rk[nr])]
    for r in range(nr - 1, -1, -1):
        s = [s[(i % 4) + 4 * (((i // 4) - (i % 4)) % 4)] for i in range(16)]
        s = [_ISB[x] for x in s]
        s = [a ^ b for a, b in zip(s, rk[r])]
        if r != 0:
            t = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t += [_gmul8(a[0], 14) ^ _gmul8(a[1], 11) ^ _gmul8(a[2], 13) ^ _gmul8(a[3], 9),
                      _gmul8(a[0], 9) ^ _gmul8(a[1], 14) ^ _gmul8(a[2], 11) ^ _gmul8(a[3], 13),
                      _gmul8(a[0], 13) ^ _gmul8(a[1], 9) ^ _gmul8(a[2], 14) ^ _gmul8(a[3], 11),
                      _gmul8(a[0], 11) ^ _gmul8(a[1], 13) ^ _gmul8(a[2], 9) ^ _gmul8(a[3], 14)]
            s = t
    return bytes(s)

# ---------------------------------------------------------------- SM4 (GB/T 32907-2016)
_SM4_SB = bytes.fromhex(
 'd690e9fecce13db716b614c228fb2c052b679a762abe04c3aa44132649860699'
 '9c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa6'
 '4707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35'
 '1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89e'
 'eabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e3'
 '1df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51'
 '8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b0'
 '89699 74a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948'.replace(' ', ''))
_SM4_FK = (0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc)
_SM4_CK = [sum((((4 * i + j) * 7) % 256) << (24 - 8 * j) for j in range(4)) for i in range(32)]
def _rol(x, k): return ((x << k) | (x >> (32 - k))) & 0xffffffff
def _sm4_t(x, key):
    y = sum(_SM4_SB[(x >> (24 - 8 * j)) & 255] << (24 - 8 * j) for j in range(4))
    if key: return y ^ _rol(y, 13) ^ _rol(y, 23)
    return y ^ _rol(y, 2) ^ _rol(y, 10) ^ _rol(y, 18) ^ _rol(y, 24)
def _sm4_rk(key):
    k = [int.from_bytes(key[4 * i:4 * i + 4], 'big') ^ _SM4_FK[i] for i in range(4)]
    for i in range(32):
        k.append(k[i] ^ _sm4_t(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _SM4_CK[i], True))
    return k[4:]
def _sm4(key, blk, dec):
    assert len(key) == 16 and len(blk) == 16
    rk = _sm4_rk(key)
    if dec: rk = rk[::-1]
    x = [int.from_bytes(blk[4 * i:4 * i + 4], 'big') for i in range(4)]
    for i in range(32):
        x.append(x[i] ^ _sm4_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i], False))
    return b''.join(v.to_bytes(4, 'big') for v in (x[35], x[34], x[33], x[32]))
def sm4_enc(key, blk): return _sm4(key, blk, False)
def sm4_dec(key, blk): return _sm4(key, blk, True)

# ---------------------------------------------------------------- DES / TDEA (FIPS 46-3, SP 800-67)
def _t(s): return [int(x) for x in s.split()]
_IP = _t('58 50 42 34 26 18 10 2 60 52 44 36 28 20 12 4 62 54 46 38 30 22 14 6 64 56 48 40 32 24 16 8 '
         '57 49 41 33 25 17 9 1 59 51 43 35 27 19 11 3 61 53 45 37 29 21 13 5 63 55 47 39 31 23 15 7')
_FP = [_IP.index(i + 1) + 1 for i in range(64)]
_E = _t('32 1 2 3 4 5 4 5 6 7 8 9 8 9 10 11 12 13 12 13 14 15 16 17 16 17 18 19 20 21 20 21 22 23 24 25 '
        '24 25 26 27 28 29 28 29 30 31 32 1')
_P = _t('16 7 20 21 29 12 28 17 1 15 23 26 5 18 31 10 2 8 24 14 32 27 3 9 19 13 30 6 22 11 4 25')
_PC1 = _t('57 49 41 33 25 17 9 1 58 50 42 34 26 18 10 2 59 51 43 35 27 19 11 3 60 52 44 36 '
          '63 55 47 39 31 23 15 7 62 54 46 38 30 22 14 6 61 53 45 37 29 21 13 5 28 20 12 4')
_PC2 = _t('14 17 11 24 1 5 3 28 15 6 21 10 23 19 12 4 26 8 16 7 27 20 13 2 '
          '41 52 31 37 47 55 30 40 51 45 33 48 44 49 39 56 34 53 46 42 50 36 29 32')
_SH = _t('1 1 2 2 2 2 2 2 1 2 2 2 2 2 2 1')
_S = [_t(s) for s in (
 '14 4 13 1 2 15 11 8 3 10 6 12 5 9 0 7 0 15 7 4 14 2 13 1 10 6 12 11 9 5 3 8 4 1 14 8 13 6 2 11 15 12 9 7 3 10 5 0 15 12 8 2 4 9 1 7 5 11 3 14 10 0 6 13',
 '15 1 8 14 6 11 3 4 9 7 2 13 12 0 5 10 3 13 4 7 15 2 8 14 12 0 1 10 6 9 11 5 0 14 7 11 10 4 13 1 5 8 12 6 9 3 2 15 13 8 10 1 3 15 4 2 11 6 7 12 0 5 14 9',
 '10 0 9 14 6 3 15 5 1 13 12 7 11 4 2 8 13 7 0 9 3 4 6 10 2 8 5 14 12 11 15 1 13 6 4 9 8 15 3 0 11 1 2 12 5 10 14 7 1 10 13 0 6 9 8 7 4 15 14 3 11 5 2 12',
 '7 13 14 3 0 6 9 10 1 2 8 5 11 12 4 15 13 8 11 5 6 15 0 3 4 7 2 12 1 10 14 9 10 6 9 0 12 11 7 13 15 1 3 14 5 2 8 4 3 15 0 6 10 1 13 8 9 4 5 11 12 7 2 14',
 '2 12 4 1 7 10 11 6 8 5 3 15 13 0 14 9 14 11 2 12 4 7 13 1 5 0 15 10 3 9 8 6 4 2 1 11 10 13 7 8 15 9 12 5 6 3 0 14 11 8 12 7 1 14 2 13 6 15 0 9 10 4 5 3',
 '12 1 10 15 9 2 6 8 0 13 3 4 14 7 5 11 10 15 4 2 7 12 9 5 6 1 13 14 0 11 3 8 9 14 15 5 2 8 12 3 7 0 4 10 1 13 11 6 4 3 2 12 9 5 15 10 11 14 1 7 6 0 8 13',
 '4 11 2 14 15 0 8 13 3 12 9 7 5 10 6 1 13 0 11 7 4 9 1 10 14 3 5 12 2 15 8 6 1 4 11 13 12 3 7 14 10 15 6 8 0 5 9 2 6 11 13 8 1 4 10 7 9 5 0 15 14 2 3 12',
 '13 2 8 4 6 15 11 1 10 9 3 14 5 0 12 7 1 15 13 8 10 3 7 4 12 5 6 11 0 14 9 2 7 11 4 1 9 12 14 2 0 6 10 13 15 3 5 8 2 1 14 7 4 10 8 13 15 12 9 0 3 5 6 11')]
def _perm(x, tbl, n):  # tables are 1-indexed from the MSB of an n-bit input
    r = 0
    for p in tbl: r = (r << 1) | ((x >> (n - p)) & 1)
    return r
def _des_ks(key8):
    k = _perm(int.from_bytes(key8, 'big'), _PC1, 64)
    c, d = k >> 28, k & 0xfffffff
    out = []
    for s in _SH:
        c = ((c << s) | (c >> (28 - s))) & 0xfffffff; d = ((d << s) | (d >> (28 - s))) & 0xfffffff
        out.append(_perm((c << 28) | d, _PC2, 56))
    return out
def _des(key8, blk, dec):
    ks = _des_ks(key8)
    if dec: ks = ks[::-1]
    x = _perm(int.from_bytes(blk, 'big'), _IP, 64)
    l, r = x >> 32, x & 0xffffffff
    for k in ks:
        e = _perm(r, _E, 32) ^ k
        f = 0
        for i in range(8):
            v = (e >> (42 - 6 * i)) & 63
            f = (f << 4) | _S[i][(((v >> 5) << 1) | (v & 1)) * 16 + ((v >> 1) & 15)]
        l, r = r, l ^ _perm(f, _P, 32)
    return _perm((r << 32) | l, _FP, 64).to_bytes(8, 'big')
def des_enc(key, blk): assert len(key) == 8 and len(blk) == 8; return _des(key, blk, False)
def des_dec(key, blk): assert len(key) == 8 and len(blk) == 8; return _des(key, blk, True)
def tdea_enc(key, blk):
    assert len(key) == 24
    return des_enc(key[16:], des_dec(key[8:16], des_enc(key[:8], blk)))
def tdea_dec(key, blk):
    assert len(key) == 24
    return des_dec(key[:8], des_enc(key[8:16], des_dec(key[16:], blk)))

_CIPHERS = {'AES128': (aes_enc, aes_dec), 'AES192': (aes_enc, aes_dec), 'AES256': (aes_enc, aes_dec),
            'SM4': (sm4_enc, sm4_dec), 'TDEA': (tdea_enc, tdea_dec)}
def cipher_enc(name, key, blk): return _CIPHERS[name][0](key, blk)
def cipher_dec(name, key, blk): return _CIPHERS[name][1](key, blk)

# ---------------------------------------------------------------- GF(2^128)
def _clmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a <<= 1; b >>= 1
    return r
def _polymod(p, poly):  # reduce p modulo poly (poly includes the x^128 term)
    for i in range(p.bit_length() - 1, 127, -1):
        if (p >> i) & 1: p ^= poly << (i - 128)
    return p
_GHASH_POLY = (1 << 128) | 0x87
def _ghash_to_poly(v):   # coefficient of x^(8i+j) is v[8i+7-j]  ==  brev8, then bit k = coeff of x^k
    return brev8(v, 16)
def ghash_mul(a, b):
    return brev8(_polymod(_clmul(_ghash_to_poly(a), _ghash_to_poly(b)), _GHASH_POLY), 16)
_POLYVAL_POLY = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1
def montmul(a, b):
    p = _polymod(_clmul(a, b), _POLYVAL_POLY)
    for _ in range(128):                 # multiply by x^-1: add the modulus if the constant term is set, shift down
        if p & 1: p ^= _POLYVAL_POLY
        p >>= 1
    return p
def polyval(auth_key, blocks):
    t = 0
    for b in blocks: t = montmul(t ^ b, auth_key)
    return t

def update_mask(v, sm4=False):
    if not sm4:
        return ((v << 1) & MASK128) ^ (0x87 if (v >> 127) & 1 else 0)
    B = [(v >> (8 * j)) & 255 for j in range(16)]
    Bp = [0] * 16
    for j in range(1, 16): Bp[j] = ((B[j - 1] & 1) << 7) | (B[j] >> 1)
    Bp[0] = (B[0] >> 1) ^ (0xE1 if B[15] & 1 else 0)
    return sum(x << (8 * j) for j, x in enumerate(Bp))
def update_mask_inv(v, sm4=False):
    if not sm4:
        if v & 1: return (((v ^ 0x87) >> 1)) ^ (1 << 127)
        return v >> 1
    B = [(v >> (8 * j)) & 255 for j in range(16)]
    c = B[0] >> 7
    A = B[0] ^ (0xE1 if c else 0)
    Bp = [0] * 16
    for j in range(1, 15): Bp[j] = ((B[j] & 127) << 1) | (B[j + 1] >> 7)
    Bp[0] = ((A & 127) << 1) | (B[1] >> 7)
    Bp[15] = ((B[15] & 127) << 1) | c
    return sum(x << (8 * j) for j, x in enumerate(Bp))
def double(s, b=128):
    R = {128: 0x87, 64: 0x1b}[b]
    v = bswap(s, b // 8)
    v = ((v << 1) & mask(b)) ^ (R if (v >> (b - 1)) & 1 else 0)
    return bswap(v, b // 8)

# ---------------------------------------------------------------- MDH
MDH_FIELDS = [
    ('Machine', 0, 12), ('MachinePolicy', 12, 2), ('MachineExtension', 14, 2), ('SCProtection', 16, 2),
    ('State', 18, 6), ('StateExtension', 24, 4), ('KeyType', 28, 2), ('Reserved31_30', 30, 2),
    ('AuxDataLen', 32, 14), ('Reserved46', 46, 1), ('ADSDropped', 47, 1), ('MachineUse', 48, 14),
    ('Version', 62, 2), ('UsagePolicy', 64, 5), ('Locality', 69, 9), ('Reserved79_78', 78, 2),
    ('AuxInfo', 80, 16), ('ExpirationDate', 96, 20), ('Reserved127_116', 116, 12)]
_MF = {n: (lo, w) for n, lo, w in MDH_FIELDS}
def mdh_get(mdh, name):
    lo, w = _MF[name]; return (mdh >> lo) & mask(w)
def mdh_put(mdh, name, value):
    lo, w = _MF[name]
    if not 0 <= value < (1 << w): raise ValueError('%s: %r does not fit %d bits' % (name, value, w))
    return (mdh & ~(mask(w) << lo) & MASK128) | (value << lo)
def mdh_pack(**fields):
    m = 0
    for k, v in fields.items():
        if k not in _MF: raise ValueError('unknown MDH field ' + k)
        m = mdh_put(m, k, v)
    return m
def mdh_unpack(mdh): return {n: mdh_get(mdh, n) for n, _, _ in MDH_FIELDS}

ST_INERT, ST_READY, ST_SUCCESS, ST_FAILURE = 0, 1, 54, 55
CFG_PROVISIONING, CFG_EXPORTING, CFG_IMPORTING, CFG_PPI_EXPORTING, CFG_PPI_IMPORTING = 56, 57, 58, 59, 60
(SE_UNCONFIGURED, SE_UNSUPPORTED, SE_INVALID, SE_OUT_OF_MEMORY, SE_MGMT_AUTH, SE_PRIV_VIOLATION, SE_EXPIRED) = range(7)
ERROR_STATES = frozenset(range(1, 7))   # StateExtension codes of the Error States (at State 0)
def is_error_state(mdh): return mdh_get(mdh, 'State') == 0 and mdh_get(mdh, 'StateExtension') in ERROR_STATES
def is_unconfigured(mdh): return mdh_get(mdh, 'State') == 0 and mdh_get(mdh, 'StateExtension') == 0

KL_STATE_INERT, KL_STATE_READY = 0, 1
KL_CFG_PROVISIONING, KL_CFG_EXPORTING, KL_CFG_IMPORTING, KL_CFG_MANAGEMENT_END = 56, 57, 58, 63
KL_CFG_CLEAR_ADS, KL_CFG_CLEARALL = 64, 65
_FORM_F = {'A': 0, 'B': 0, 'C': 1, 'D': 2}
def setst_encode(form, kd, immed7, rs1=0, r=0, g=0):
    if form not in _FORM_F: raise ValueError('form')
    if form == 'A': rs1 = 0
    if form == 'B' and rs1 == 0: raise ValueError('Form B needs rs1 != 0')
    for v, w in ((kd, 5), (rs1, 5), (r, 1), (g, 2), (immed7, 7)):
        if not 0 <= v < (1 << w): raise ValueError('field out of range')
    return (0x0F | (kd << 7) | (3 << 12) | (rs1 << 15) | (r << 20) | (_FORM_F[form] << 21) | (g << 23) | (immed7 << 25))
def setst_decode(w):
    F = (w >> 21) & 3
    form = {1: 'C', 2: 'D', 3: None}.get(F) or (None if F == 3 else ('A' if (w >> 15) & 31 == 0 else 'B'))
    return dict(opcode=w & 127, kd=(w >> 7) & 31, funct3=(w >> 12) & 7, rs1=(w >> 15) & 31, r=(w >> 20) & 1,
                F=F, G=(w >> 23) & 3, immed7=(w >> 25) & 127, form=form)

# ---------------------------------------------------------------- harness
N_PASS = N_FAIL = 0
def section(title): print('== ' + title, flush=True)
def _fmt(x):
    if isinstance(x, int): return hex(x)
    if isinstance(x, (bytes, bytearray)): return bytes(x).hex()
    return repr(x)
def check(name, ok, got=None, want=None):
    global N_PASS, N_FAIL
    if ok: N_PASS += 1; print('PASS  ' + name)
    else:
        N_FAIL += 1; print('FAIL  ' + name)
        if got is not None or want is not None: print('      got : %s\n      want: %s' % (_fmt(got), _fmt(want)))
    return bool(ok)
def control(name, fired): return check('control: ' + name, fired)
def info(text): print('INFO  ' + text)
def spec_note(text): print('NOTE  ' + text)
def raises(fn, *a, exc=Exception, **kw):
    try: fn(*a, **kw)
    except exc: return True
    return False
def done():
    print('\n%d passed, %d failed' % (N_PASS, N_FAIL))
    print('KAT-RESULT: PASS' if N_FAIL == 0 else 'KAT-RESULT: FAIL')
    sys.exit(0 if N_FAIL == 0 else 1)

# ---------------------------------------------------------------- self-test
def _selftest():
    import time
    H = bytes.fromhex
    section('AES (FIPS 197 App. C)')
    pt = H('00112233445566778899aabbccddeeff')
    for n, ct in ((16, '69c4e0d86a7b0430d8cdb78070b4c55a'), (24, 'dda97ca4864cdfe06eaf70a0ec0d7191'),
                  (32, '8ea2b7ca516745bfeafc49904b496089')):
        k = bytes(range(n))
        check('AES-%d enc' % (8 * n), aes_enc(k, pt) == H(ct), aes_enc(k, pt), H(ct))
        check('AES-%d dec' % (8 * n), aes_dec(k, H(ct)) == pt)
    check('AES-128 FIPS 197 App. B', aes_enc(H('2b7e151628aed2a6abf7158809cf4f3c'), H('3243f6a8885a308d313198a2e0370734'))
          == H('3925841d02dc09fbdc118597196a0b32'))
    control('AES wrong key detected', aes_enc(bytes(16), pt) != H('69c4e0d86a7b0430d8cdb78070b4c55a'))
    section('SM4 (GB/T 32907-2016)')
    k = H('0123456789abcdeffedcba9876543210')
    check('SM4 enc', sm4_enc(k, k) == H('681edf34d206965e86b3e94f536e4246'), sm4_enc(k, k))
    check('SM4 dec', sm4_dec(k, H('681edf34d206965e86b3e94f536e4246')) == k)
    t = time.time(); x = k
    for _ in range(1000000): x = sm4_enc(k, x)
    check('SM4 1,000,000 iterations', x == H('595298c7c6fd271f0402f804c33d3f66'), x)
    info('SM4 1e6 rounds: %.1fs' % (time.time() - t))
    section('DES / TDEA')
    check('DES 133457799BBCDFF1', des_enc(H('133457799BBCDFF1'), H('0123456789ABCDEF')) == H('85E813540F0AB405'))
    check('DES dec', des_dec(H('133457799BBCDFF1'), H('85E813540F0AB405')) == H('0123456789ABCDEF'))
    check('DES weak-key-free zero', des_enc(bytes(8), bytes(8)) == H('8ca64de9c1b123a7'))
    k3 = H('0123456789abcdef23456789abcdef01456789abcdef0123')
    m = b'Now is the time for all '
    ct = b''.join(tdea_enc(k3, m[i:i + 8]) for i in range(0, 24, 8))
    check('TDEA SP 800-67 sample "Now is the time"', ct == H('314f8327fa7a09a84362760cc13ba7daff55c5f80faaac45'), ct)  # first block as in SP 800-67 / NIST; rest derived with OpenSSL
    check('TDEA roundtrip', b''.join(tdea_dec(k3, ct[i:i + 8]) for i in range(0, 24, 8)) == m)
    check('TDEA K1=K2=K3 is DES', tdea_enc(H('133457799BBCDFF1') * 3, H('0123456789ABCDEF')) == H('85E813540F0AB405'))
    section('GF(2^128)')
    # GCM test case 2: H = E_K(0) with K=0; X1 = C xor ... ; GHASH(H, C) with C=0388dace60b6a392f328c2b971b2fe78
    Hk = b2v(aes_enc(bytes(16), bytes(16)))
    check('GCM H', v2b(Hk, 16) == H('66e94bd4ef8a2c3b884cfa59ca342b2e'))
    C = b2v(H('0388dace60b6a392f328c2b971b2fe78')); L = b2v(H('00000000000000000000000000000080'))
    g = ghash_mul(ghash_mul(C, Hk) ^ L, Hk)  # GHASH(H, {}, C) = ((C*H) ^ len)*H
    check('GCM test case 2 GHASH', v2b(g, 16) == H('f38cbb1ad69223dcc3457ae5b6b0f885'), v2b(g, 16))
    one = b2v(H('80000000000000000000000000000000'))  # x^0 in GHASH representation
    check('GHASH identity', ghash_mul(one, Hk) == Hk)
    # RFC 8452 App. A: POLYVAL(H, X1, X2)
    h = b2v(H('25629347589242761d31f826ba4b757b')); x1 = b2v(H('4f4f95668c83dfb6401762bb2d01a262'))
    x2 = b2v(H('d1a24ddd2721d006bbe45f20d3c9f362'))
    check('POLYVAL RFC 8452 App. A', v2b(polyval(h, [x1, x2]), 16) == H('f7a3b47b846119fae5b7866cf5e5b77e'),
          v2b(polyval(h, [x1, x2]), 16))
    check('Montmul(x^0... ) = a*x^-128 consistency', montmul(1, h) == polyval(h, [1]))
    section('masks and doubling')
    v = 0x80000000000000000000000000000001
    check('update_mask carry', update_mask(v) == 0x02 ^ 0x87 and update_mask_inv(update_mask(v)) == v)
    check('update_mask x^127 -> 0x87', update_mask(1 << 127) == 0x87)
    for sm4 in (False, True):
        import random
        r = random.Random(1)
        ok = all(update_mask_inv(update_mask(w, sm4), sm4) == w and update_mask(update_mask_inv(w, sm4), sm4) == w
                 for w in (r.getrandbits(128) for _ in range(200)))
        check('update_mask inverse sm4=%s' % sm4, ok)
    check('SM4 update_mask carry: B15[0]=1 -> B0 gets xor 0xE1', update_mask(1 << 120, True) == 0xE1 and update_mask(1, True) == 0x8000)
    # SP 800-38B / RFC 4493 subkey example: K=2b7e..., L=7df76b0c1ab899b33e42f047b91b546f, K1=fbeed618357133667c85e08f7236a8de
    L = b2v(H('7df76b0c1ab899b33e42f047b91b546f'))
    k1 = double(L)
    check('CMAC K1 (RFC 4493)', v2b(k1, 16) == H('fbeed618357133667c85e08f7236a8de'))
    check('CMAC K2 (RFC 4493)', v2b(double(k1), 16) == H('f7ddac306ae266ccf90bc11ee46d513b'))
    check('double == bswap update_mask bswap', double(L) == bswap(update_mask(bswap(L, 16)), 16))
    check('double b=64 (R64 = 0x1b)', double(b2v(H('8000000000000000')), 64) == b2v(H('000000000000001b')))
    section('notation')
    check('b2v/v2b', v2b(b2v(b'\x01\x02\x03'), 3) == b'\x01\x02\x03' and b2v(b'\x01\x02') == 0x0201)
    check('cat first most significant', cat((0xA, 4), (0xB, 4)) == 0xAB)
    check('bswap', bswap(0x1122334455667788, 8) == 0x8877665544332211)
    check('brev8', brev8(0x0180, 2) == 0x8001)
    check('bin_', bin_(0x1ff, 8) == 0xff and bin_(-1, 4) == 15)
    check('sl', sl(0xABCD, 11, 4) == 0xBC)
    check('bxor bytes', bxor(b'\x0f', b'\xff') == b'\xf0')
    section('MDH and setst')
    check('MDH widths total 128', sum(w for _, _, w in MDH_FIELDS) == 128 and
          all(MDH_FIELDS[i][1] + MDH_FIELDS[i][2] == MDH_FIELDS[i + 1][1] for i in range(len(MDH_FIELDS) - 1)))
    f = dict(Machine=0xABC, MachinePolicy=3, SCProtection=2, State=55, StateExtension=9, KeyType=2, AuxDataLen=0x3FFF,
             ADSDropped=1, MachineUse=0x2AAA, Version=3, UsagePolicy=0x1F, Locality=0x1FF, AuxInfo=0xBEEF,
             ExpirationDate=0xFFFFF)
    m = mdh_pack(**f)
    check('MDH round trip', all(mdh_unpack(m)[k] == v for k, v in f.items()))
    check('MDH positions', mdh_get(mdh_pack(State=1), 'State') == 1 and mdh_pack(State=1) == 1 << 18 and
          mdh_pack(Version=3) == 3 << 62 and mdh_pack(ExpirationDate=1) == 1 << 96 and mdh_pack(StateExtension=1) == 1 << 24)
    check('mdh_put overwrites', mdh_get(mdh_put(m, 'State', 1), 'State') == 1 and mdh_get(mdh_put(m, 'State', 1), 'Machine') == 0xABC)
    control('mdh_pack rejects too-wide value', raises(mdh_pack, State=64, exc=ValueError))
    check('error states', is_error_state(mdh_pack(StateExtension=6)) and not is_error_state(mdh_pack(StateExtension=7))
          and not is_error_state(mdh_pack(State=1, StateExtension=2)) and is_unconfigured(0))
    w = setst_encode('A', 5, 65)
    check('setst Form A', w == 0x0F | 5 << 7 | 3 << 12 | 65 << 25, hex(w))
    check('setst decode', setst_decode(setst_encode('D', 3, 9, rs1=10, r=1))['form'] == 'D'
          and setst_decode(setst_encode('B', 3, 9, rs1=10))['form'] == 'B'
          and setst_decode(setst_encode('C', 3, 9, rs1=2))['F'] == 1 and setst_decode(setst_encode('A', 1, 2, g=3))['G'] == 3)
    control('Form B with x0 rejected', raises(setst_encode, 'B', 1, 1, exc=ValueError))
    section('harness')
    control('raises detects', raises(lambda: 1 / 0, exc=ZeroDivisionError))
    done()

if __name__ == '__main__':
    _selftest()
