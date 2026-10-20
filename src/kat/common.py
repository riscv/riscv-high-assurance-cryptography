"""Shared utilities for the KLE KAT suite.

Values are little-endian bit strings in Python ints (Zkl-notation.adoc): byte i of a
string is bits [8i+7:8i]; `cat` is `@` (left operand most significant).  Also: AES,
GHASH/POLYVAL arithmetic, XTS/OCB doublings, the MDH layout, the State constants and
the reporting helpers every harness uses.  Run directly for the self-tests.
"""

import sys

MASK128 = (1 << 128) - 1

# ---------------------------------------------------------------- notation

def b2v(b: bytes) -> int:
    """Byte string -> KLE value (byte i at bits [8i+7:8i])."""
    return int.from_bytes(b, 'little')

def v2b(v: int, n: int) -> bytes:
    """KLE value -> byte string of n bytes."""
    return v.to_bytes(n, 'little')

def sl(v: int, hi: int, lo: int) -> int:
    """Bit slice V[hi:lo], both inclusive."""
    return (v >> lo) & ((1 << (hi - lo + 1)) - 1)

def cat(*parts) -> int:
    """cat((A, wa), (B, wb), ...) = A @ B @ ... ; the FIRST part is most significant."""
    v = 0
    for val, w in parts:
        v = (v << w) | (val & ((1 << w) - 1))
    return v

def bswap(v: int, n: int) -> int:
    """Reverse the byte order of the n-byte value v (the spec's bswap)."""
    return int.from_bytes(v.to_bytes(n, 'little'), 'big')

def bin_(n: int, m: int) -> int:
    """The spec's bin(n, m): m-bit little-endian representation as a value."""
    return n & ((1 << m) - 1)

def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ---------------------------------------------------------------- GF(2^8) and AES

def _gmul8(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r

def _rol8(x: int, s: int) -> int:
    return ((x << s) | (x >> (8 - s))) & 0xFF

def _make_sbox():
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if _gmul8(x, y) == 1:
                inv[x] = y
                break
    return [b ^ _rol8(b, 1) ^ _rol8(b, 2) ^ _rol8(b, 3) ^ _rol8(b, 4) ^ 0x63 for b in inv]

SBOX = _make_sbox()
INV_SBOX = [0] * 256
for _i, _s in enumerate(SBOX):
    INV_SBOX[_s] = _i

def _key_expand(key: bytes):
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rcon
            rcon = _gmul8(rcon, 2)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[x] for x in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(nr + 1)], nr

def _add_rk(s, rk):
    return [a ^ b for a, b in zip(s, rk)]

def aes_encrypt(key: bytes, block: bytes) -> bytes:
    assert len(block) == 16
    rks, nr = _key_expand(key)
    s = _add_rk(block, rks[0])
    for r in range(1, nr + 1):
        s = [SBOX[x] for x in s]                              # SubBytes
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]    # ShiftRows (col-major flat)
        if r != nr:                                           # MixColumns
            t = []
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                t += [
                    _gmul8(col[0], 2) ^ _gmul8(col[1], 3) ^ col[2] ^ col[3],
                    col[0] ^ _gmul8(col[1], 2) ^ _gmul8(col[2], 3) ^ col[3],
                    col[0] ^ col[1] ^ _gmul8(col[2], 2) ^ _gmul8(col[3], 3),
                    _gmul8(col[0], 3) ^ col[1] ^ col[2] ^ _gmul8(col[3], 2),
                ]
            s = t
        s = _add_rk(s, rks[r])
    return bytes(s)

def aes_decrypt(key: bytes, block: bytes) -> bytes:
    assert len(block) == 16
    rks, nr = _key_expand(key)
    s = _add_rk(block, rks[nr])
    for r in range(nr - 1, -1, -1):
        s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]    # InvShiftRows
        s = [INV_SBOX[x] for x in s]                          # InvSubBytes
        s = _add_rk(s, rks[r])
        if r != 0:                                            # InvMixColumns
            t = []
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                t += [
                    _gmul8(col[0], 14) ^ _gmul8(col[1], 11) ^ _gmul8(col[2], 13) ^ _gmul8(col[3], 9),
                    _gmul8(col[0], 9) ^ _gmul8(col[1], 14) ^ _gmul8(col[2], 11) ^ _gmul8(col[3], 13),
                    _gmul8(col[0], 13) ^ _gmul8(col[1], 9) ^ _gmul8(col[2], 14) ^ _gmul8(col[3], 11),
                    _gmul8(col[0], 11) ^ _gmul8(col[1], 13) ^ _gmul8(col[2], 9) ^ _gmul8(col[3], 14),
                ]
            s = t
    return bytes(s)

# ---------------------------------------------------------------- DES / TDEA (FIPS 46-3, SP 800-67): 64-bit blocks
_DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
           64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
_DES_FP = [_DES_IP.index(i) + 1 for i in range(1, 65)]
_DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
          16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
_DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
          2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
_DES_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 28, 20, 12, 4]
_DES_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
_DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_DES_S = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

def _des_perm(x: int, table, width: int) -> int:
    """FIPS 46-3 permutation: output bit i (1 = leftmost) is input bit table[i] of a `width`-bit value."""
    return sum(((x >> (width - t)) & 1) << (len(table) - 1 - i) for i, t in enumerate(table))

def _des_subkeys(key: bytes):
    cd = _des_perm(int.from_bytes(key, 'big'), _DES_PC1, 64)
    c, d, ks = cd >> 28, cd & 0xFFFFFFF, []
    for s in _DES_SHIFTS:
        c, d = ((c << s) | (c >> (28 - s))) & 0xFFFFFFF, ((d << s) | (d >> (28 - s))) & 0xFFFFFFF
        ks.append(_des_perm(c << 28 | d, _DES_PC2, 56))
    return ks

def _des(key: bytes, block: bytes, decrypt=False) -> bytes:
    ks = _des_subkeys(key)
    x = _des_perm(int.from_bytes(block, 'big'), _DES_IP, 64)
    l, r = x >> 32, x & 0xFFFFFFFF
    for k in (reversed(ks) if decrypt else ks):
        e, f = _des_perm(r, _DES_E, 32) ^ k, 0
        for i in range(8):
            six = (e >> (42 - 6 * i)) & 0x3F
            f = f << 4 | _DES_S[i][(six & 0x20) | (six & 1) << 4 | (six >> 1) & 0xF]
        l, r = r, l ^ _des_perm(f, _DES_P, 32)
    return _des_perm(r << 32 | l, _DES_FP, 64).to_bytes(8, 'big')

def tdea_encrypt(key: bytes, block: bytes) -> bytes:
    """TDEA (SP 800-67) EDE encryption of one 8-byte block; key = K1 || K2 || K3 (24 bytes) or K1 || K2 (16)."""
    assert len(block) == 8 and len(key) in (16, 24)
    k1, k2, k3 = key[:8], key[8:16], key[16:24] or key[:8]
    return _des(k3, _des(k2, _des(k1, block), decrypt=True))

# ---------------------------------------------------------------- GHASH field (SP 800-38D 6.3)

def gmul_ghash(X: bytes, Y: bytes) -> bytes:
    """Multiplication in the GHASH field on 16-byte big-endian-string operands."""
    x = int.from_bytes(X, 'big')
    z = 0
    v = int.from_bytes(Y, 'big')
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z.to_bytes(16, 'big')

def kl_galoismul(a: int, b: int) -> int:
    """The spec's Galoismul on KLE values (byte order forward, bits reflected per byte)."""
    return b2v(gmul_ghash(v2b(a, 16), v2b(b, 16)))

# ---------------------------------------------------------------- POLYVAL (RFC 8452)

_G_POLYVAL = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1

def _clmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        b >>= 1
    return r

def montmul(a: int, b: int) -> int:
    """The spec's Montmul: a * b * x^-128 in GF(2^128) mod x^128+x^127+x^126+x^121+1,
    on KLE values under the fully little-endian POLYVAL representation (V[k] = coeff of x^k)."""
    p = _clmul(a, b)
    for _ in range(128):
        if p & 1:
            p ^= _G_POLYVAL
        p >>= 1
    if p >> 128:
        p ^= _G_POLYVAL
    return p & MASK128

def mulx_polyval(v: int) -> int:
    """RFC 8452's mulX_POLYVAL on a KLE value."""
    c = v >> 127
    v = (v << 1) & MASK128
    if c:
        v ^= (1 << 127) | (1 << 126) | (1 << 121) | 1
    return v

# ---------------------------------------------------------------- SM4 (GB/T 32907-2016)
# S-box: OpenSSL crypto/sm4/sm4.c SM4_S[256]; anchored below on the GB/T vectors.
SM4_SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948")
SM4_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
_S4 = SM4_SBOX

_rotl = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
_tau = lambda a: (_S4[a >> 24] << 24) | (_S4[(a >> 16) & 255] << 16) | (_S4[(a >> 8) & 255] << 8) | _S4[a & 255]
_words = lambda b: [int.from_bytes(b[i:i + 4], 'big') for i in range(0, 16, 4)]

def sm4_rks(key):
    k = [w ^ f for w, f in zip(_words(key), SM4_FK)]
    for i in range(32):
        ck = int.from_bytes(bytes((28 * i + 7 * j) & 255 for j in range(4)), 'big')
        t = _tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck)
        k.append(k[i] ^ t ^ _rotl(t, 13) ^ _rotl(t, 23))
    return k[4:]

def sm4_block(rks, blk):
    x = _words(blk)
    for rk in rks:
        t = _tau(x[-3] ^ x[-2] ^ x[-1] ^ rk)
        x.append(x[-4] ^ t ^ _rotl(t, 2) ^ _rotl(t, 10) ^ _rotl(t, 18) ^ _rotl(t, 24))
    return b''.join(w.to_bytes(4, 'big') for w in reversed(x[-4:]))

sm4_encrypt = lambda key, blk: sm4_block(sm4_rks(key), blk)
sm4_decrypt = lambda key, blk: sm4_block(sm4_rks(key)[::-1], blk)   # round keys reversed

# ---------------------------------------------------------------- XTS / OCB doublings

def update_mask(v: int, b: int = 128) -> int:
    """XEX/XTS mask update (little-endian doubling), per KLE-XEX-XTS-modes: R_128 = 0x87, R_64 = 0x1B."""
    c = v >> (b - 1)
    v = (v << 1) & ((1 << b) - 1)
    if c:
        v ^= {128: 0x87, 64: 0x1B}[b]
    return v

def double_ocb(v: int, b: int = 128) -> int:
    """OCB3/CMAC doubling over the big-endian string view: bswap(update_mask(bswap(S)))."""
    return bswap(update_mask(bswap(v, b // 8), b), b // 8)

# ---------------------------------------------------------------- MDH and States

# <<KLE-metadata-header>>: (name, hi, lo); None marks a Reserved field.
MDH_FIELDS = [
    ('Machine', 11, 0), ('MachinePolicy', 13, 12), ('MachineExtension', 15, 14),
    ('SCProtection', 17, 16), ('State', 23, 18), ('StateExtension', 27, 24),
    ('KeyType', 29, 28), (None, 31, 30), ('AuxDataLen', 45, 32), (None, 46, 46),
    ('ADSDropped', 47, 47), ('MachineUse', 61, 48), ('Version', 63, 62),
    ('UsagePolicy', 68, 64), ('Locality', 77, 69), (None, 79, 78),
    ('AuxInfo', 95, 80), ('ExpirationDate', 115, 96), (None, 127, 116),
]
MDH_FIELD = {n: (hi, lo) for n, hi, lo in MDH_FIELDS if n}

def mdh_pack(**f) -> int:
    v = 0
    for n, x in f.items():
        hi, lo = MDH_FIELD[n]
        assert 0 <= x < 1 << (hi - lo + 1), (n, x)
        v |= x << lo
    return v

def mdh_unpack(v: int) -> dict:
    return {n: sl(v, hi, lo) for n, (hi, lo) in MDH_FIELD.items()}

# <<KLE-State-field>>, <<KLE-state-constants-symmetric>>
KL_STATE_UNCONFIGURED, KL_STATE_READY = 0, 1
KL_STATE_OPERATE = KL_STATE_HASH_ABSORB = 2
(KL_STATE_HASH_LAST_BLOCK, KL_STATE_HASH_FINALIZE, KL_STATE_HASH_VERIFY,
 KL_STATE_HASH_OUTPUT, KL_STATE_ENCRYPT, KL_STATE_DECRYPT, KL_STATE_ENC_LAST_BLOCK,
 KL_STATE_DEC_LAST_BLOCK, KL_STATE_ENC_TAG_FINALIZE, KL_STATE_DEC_TAG_FINALIZE,
 KL_STATE_SET_AUX_VALUE, KL_STATE_SET_AUX_VALUE_2, KL_STATE_SET_KEY) = range(3, 16)
KL_STATE_SUCCESS, KL_STATE_FAILURE = 46, 47
(KL_STATE_UNSUPPORTED, KL_STATE_INVALID, KL_STATE_OUT_OF_MEMORY, KL_STATE_MGMT_AUTH,
 KL_STATE_PRIV_VIOLATION, KL_STATE_EXPIRED) = range(48, 54)
ERROR_STATES = range(48, 56)
(KL_CFG_PROVISIONING, KL_CFG_EXPORTING, KL_CFG_IMPORTING, KL_CFG_PPI_EXPORTING,
 KL_CFG_PPI_IMPORTING) = range(56, 61)
KL_CFG_MANAGEMENT_END = 63

def inert(state) -> bool:
    """GR26: an _Unconfigured_ or Error-State locker, on which a usage instruction of any Machine
    performs no operation and raises no exception, its unwritten output zeroed (GR28)."""
    return state == KL_STATE_UNCONFIGURED or state in ERROR_STATES

class IllegalInstruction(Exception):
    pass

def install_key(keytype, field, importing, sks, generate, value=None):
    """<<KLE-KeyType-field>>, <<KLE-system-keys>>: what a key field installs, as (key, skid, KeyType), or None for
    _Invalid_.  KeyType 0: `value`, else the field; 1: the key(s) that the SKS resolves for the SKID in the field;
    2, in a PI only: generate(), after which KeyType is 0."""
    if keytype == 0:
        return (field if value is None else value), None, 0
    if keytype == 1 and field in sks:
        return sks[field], field, 1
    if keytype == 2 and not importing:
        return generate(), None, 0
    return None

class LoopBound(Exception):
    """A sampler reached the limit an implementation set on its loop (FIPS 203 Appendix B, FIPS 204 Appendix C)."""

# ---------------------------------------------------------------- reporting

_counts = {'pass': 0, 'fail': 0}

def section(title: str):
    print(f'\n== {title}')

def check(name: str, ok, got=None, want=None) -> bool:
    """Record one check.  With `got`/`want`, ok is taken as got == want."""
    if got is not None or want is not None:
        ok = got == want
    ok = bool(ok)
    _counts['pass' if ok else 'fail'] += 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok and (got is not None or want is not None):
        print(f'        got  {got}\n        want {want}')
    return ok

def control(name: str, fired) -> bool:
    """Negative control: a deliberately wrong formulation must be caught."""
    return check(f'negative control fired: {name}', fired)

def info(text: str):
    print(f'INFO  {text}')

def spec_note(text: str):
    print(f'SPEC-NOTE  {text}')

def raises(fn, *a, exc=IllegalInstruction, **kw) -> bool:
    try:
        fn(*a, **kw)
    except exc:
        return True
    return False

def done():
    """Print the verdict line read by run-kats.py and exit accordingly."""
    ok = _counts['fail'] == 0
    print(f"\n{_counts['pass']} passed, {_counts['fail']} failed")
    print(f"KAT-RESULT: {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)

# ---------------------------------------------------------------- generic hash driver

def md_pad(nbits: int, w: int) -> bytes:
    """The rest of the FIPS 180-4 sect. 5.1 / GB/T 32905 padding of a message of nbits bits (w = 32
    or 64), as <<KLE-SHA-2>> `finalize()` absorbs it: 0x80 if nbits is a multiple of 8 (otherwise
    the final piece already carries the bit 1), the zero bytes, then nbits as a 2w-bit big-endian
    integer.  For the models only: the references keep their own padding."""
    head = b'\x80' if nbits % 8 == 0 else b''
    nb = -(-nbits // 8) + len(head)
    return head + bytes(-(nb + w // 4) % (2 * w)) + nbits.to_bytes(w // 4, 'big')

def bits_of(msg: bytes, nbits: int, msb: bool) -> str:
    """The first nbits bits of msg as a '0'/'1' string in the order of the standard: MSB-first
    within each byte (FIPS 180-4, GB/T 32905) or LSB-first (FIPS 202, SP 800-232)."""
    return ''.join(format(x, '08b') if msb else format(x, '08b')[::-1] for x in msg)[:nbits]

class HashPort:
    """The interface a KAT gives its locker model, so that `hash_run` drives it as
    <<Zkl-software.adoc#KLE-pseudocode-hash>> does.  A subclass provides:
      b, msb               the block size in bits, and whether a partial byte is MSB-first
      bitwise              whether the final piece may have a non-byte length
      setst(immed, form='A', xs=None)
      exec_in(data, halt_at=None) -> str   Form B kl.exec from byte klstart: 'done', 'empty',
          'invalid' or 'interrupted' (precise halt at the first interruption point after byte
          halt_at, klstart set)
      exec_out(n, halt_at=None, prior=b'') -> (str, bytes)    Form C kl.exec of n bytes, likewise
      export() -> image;  imported(image) -> HashPort
      st, klstart (bytes)"""
    msb, bitwise = False, True

def hash_chunks(bb: int) -> dict:
    """Transfer-size plans for a rate of bb bytes (sizes cycled; 0 is an empty window)."""
    return {'whole': None, 'bytes': (1,), 'threes': (3,), 'odd': (1, 3, bb + 5),
            'blocks': (bb,), 'straddle': (bb - 1, 2, 2 * bb + 7), 'empties': (0, 5, 0, bb)}

def hash_msgs(bb: int, edges=(), bits=False) -> list:
    """(msg, nbits) pairs: lengths 0, 1, 3, bb - 1, bb, bb + 1, 2 bb, 2 bb + 3 and the padding
    edges, in bytes; with bits, also 5, 8 bb - 3, 8 bb + 5 and 16 bb + 61 bits."""
    lens = sorted({0, 1, 3, bb - 1, bb, bb + 1, 2 * bb, 2 * bb + 3, *edges})
    out = [(bytes((7 * i + 1) & 0xFF for i in range(n)), 8 * n) for n in lens]
    if bits:
        for nb in (5, 8 * bb - 3, 8 * bb + 5, 16 * bb + 61):
            out.append((bytes((5 * i + 3) & 0xFF for i in range(-(-nb // 8))), nb))
    return out

OUT_SPLITS = {'one': None, 'odd': (1, 3), 'bytes': (1,), 'tail1': (-1, 1)}  # -1: all but one

def _split(data, sizes):
    if not sizes:
        return [data] if data else []
    out, i, k = [], 0, 0
    while i < len(data) or (k < len(sizes) and sizes[k] == 0):
        n = sizes[k % len(sizes)]
        out.append(data[i:i + n])
        i, k = i + n, k + 1
        if k > 4 * len(data) + 8:
            break
    return out

def _out_sizes(n, split):
    if not split:
        return [n]
    if split == (-1, 1):
        return [n - 1, 1] if n > 1 else [n]
    out, k = [], 0
    while sum(out) < n:
        out.append(min(split[k % len(split)], n - sum(out)))
        k += 1
    return out

def _piece_bits(port, piece, nbits):
    """The final-piece length in bits for a `piece` variant, or None (direct, or not applicable)."""
    r = {'listing': nbits % 64, 'b': port.b, 'b-8': port.b - 8}.get(piece, piece)
    if r is None or r > nbits or (nbits - r) % 8 or (r % 8 and not port.bitwise):
        return None
    return r

def hash_run(port, msg, nbits, out_len, chunks=None, halt=False, migrate=False, out_split=None,
             end=('B', None), piece='listing', start=None):
    """The listing on `port` for the first nbits bits of msg: `start` (default: Form A into
    _Hash_Absorb_), the head in `chunks` transfers (each halted at every interruption point and
    resumed with halt; export and import after every transfer and halt with migrate), the final
    piece through _Hash_Absorb_Last_Block_ (piece: 'listing' = nbits mod 64, an int, 'b', 'b-8',
    or None for the direct kl.setst into _Hash_Output_), the kl.setst into _Hash_Output_ as
    end = (form, xs), xs None meaning 8 * out_len, and out_len bytes in out_split.  Returns
    (output, final State, halts)."""
    halts = []
    mig = (lambda p: p.imported(p.export())) if migrate else (lambda p: p)
    (start or (lambda p: p.setst(KL_STATE_HASH_ABSORB)))(port)
    port = mig(port)
    r = None if piece is None else _piece_bits(port, piece, nbits)
    head = msg[:(nbits - (r or 0)) // 8]
    for ch in _split(head, chunks):
        st = port.exec_in(ch, 0 if halt else None)
        while st == 'interrupted':
            halts.append(port.klstart)
            port = mig(port)
            st = port.exec_in(ch, port.klstart if halt else None)
        port = mig(port)
    if r is not None:
        port.setst(KL_STATE_HASH_LAST_BLOCK, 'B', r)
        port = mig(port)
        if r:
            port.exec_in(msg[len(head):len(head) + -(-r // 8)])
            port = mig(port)
    form, xs = end
    port.setst(KL_STATE_HASH_OUTPUT, form, (8 * out_len if xs is None else xs) if form == 'B' else None)
    port = mig(port)
    out = b''
    for n in _out_sizes(out_len, out_split):
        st, o = port.exec_out(n, 0 if halt else None)
        while st == 'interrupted':
            halts.append(port.klstart)
            port = mig(port)
            st, o = port.exec_out(n, port.klstart if halt else None, prior=o)
        out += o
    return out, port.st, halts

def check_hash(label, new, ref, msgs, out_len, final=KL_STATE_SUCCESS, chunk_plans=None,
               pieces=('listing', None, 0, 8, 'b-8', 'b'), splits=None, end=('B', None)):
    """One check per message: one factor at a time, every chunk plan, every final-piece variant,
    every output split, halts, export/import, and both together on odd chunks, give
    ref(msg, nbits, out_len) and the final State."""
    port0 = new()
    plans = chunk_plans or hash_chunks(port0.b // 8)
    for msg, nbits in msgs:
        want = ref(msg, nbits, out_len)
        cfgs = [dict(chunks=c) for c in plans.values()]
        cfgs += [dict(piece=p) for p in pieces]
        cfgs += [dict(out_split=s) for s in (splits or OUT_SPLITS).values()]
        cfgs += [dict(halt=True), dict(migrate=True), dict(halt=True, migrate=True, chunks=plans.get('odd'),
                                                          out_split=(1, 3))]
        bad = []
        for cfg in cfgs:
            cfg.setdefault('end', end)
            if 'piece' in cfg and (_piece_bits(port0, cfg['piece'], nbits) is None if cfg['piece'] is not None
                                   else nbits % 8):
                continue  # not applicable: a piece longer than the message, or a direct end of a bit message
            out, st, _ = hash_run(new(), msg, nbits, out_len, **cfg)
            if (out, st) != (want, final):
                bad.append(cfg)
        check(f'{label}: {nbits}-bit message, {len(cfgs)} chunk/piece/halt/export/output plans -> reference, '
              f'final State {final}', not bad, bad[:3] or None, [] if bad else None)
    wrong = []
    for form in ('B', 'C'):
        p = new()
        p.setst(KL_STATE_HASH_ABSORB)
        p.setst(KL_STATE_READY, form, 8)
        wrong.append(p.st)
    check(f'{label}: a Form B or C kl.setst naming _Ready_ is a wrong Form (GR16, GR65)', None, wrong,
          [KL_STATE_INVALID] * 2)

# ---------------------------------------------------------------- self-tests

def selftest(verbose: bool = False) -> bool:
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        if verbose or not good:
            print(f"  {'PASS' if good else 'FAIL'}  {name}")
            if not good:
                print(f"        got  {got}")
                print(f"        want {want}")

    # FIPS 197 Appendix C
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    k128 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    k192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    k256 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    chk("AES-128 FIPS197 C.1", aes_encrypt(k128, pt).hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
    chk("AES-192 FIPS197 C.2", aes_encrypt(k192, pt).hex(), "dda97ca4864cdfe06eaf70a0ec0d7191")
    chk("AES-256 FIPS197 C.3", aes_encrypt(k256, pt).hex(), "8ea2b7ca516745bfeafc49904b496089")
    for k in (k128, k192, k256):
        chk(f"AES-{len(k)*8} decrypt inverse", aes_decrypt(k, aes_encrypt(k, pt)).hex(), pt.hex())

    # RFC 8452 Appendix A: mulX_POLYVAL and POLYVAL
    chk("mulX_POLYVAL(1)",
        v2b(mulx_polyval(b2v(bytes.fromhex("01000000000000000000000000000000"))), 16).hex(),
        "02000000000000000000000000000000")
    chk("mulX_POLYVAL(sample)",
        v2b(mulx_polyval(b2v(bytes.fromhex("9c98c04df9387ded828175a92ba652d8"))), 16).hex(),
        "3931819bf271fada0503eb52574ca572")
    H = b2v(bytes.fromhex("25629347589242761d31f826ba4b757b"))
    X1 = b2v(bytes.fromhex("4f4f95668c83dfb6401762bb2d01a262"))
    X2 = b2v(bytes.fromhex("d1a24ddd2721d006bbe45f20d3c9f362"))
    acc = montmul(0 ^ X1, H)
    acc = montmul(acc ^ X2, H)
    chk("POLYVAL RFC8452 A", v2b(acc, 16).hex(), "f7a3b47b846119fae5b7866cf5e5b77e")

    # notation sanity: cat/@ and bswap
    chk("cat(A@B)", cat((0xAB, 8), (0xCD, 8)), 0xABCD)
    chk("bswap", bswap(0x0102030405060708, 8), 0x0807060504030201)

    # GHASH sanity: H from the zero key, per SP 800-38D test case 1 intermediate
    Hs = aes_encrypt(bytes(16), bytes(16))
    chk("GHASH H (38D tc1)", Hs.hex(), "66e94bd4ef8a2c3b884cfa59ca342b2e")

    # doubling: CMAC K1 for the SP 800-38B D.1 AES-128 key
    L = aes_encrypt(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"), bytes(16))
    K1 = double_ocb(b2v(L))
    chk("CMAC K1 (38B D.1)", v2b(K1, 16).hex(), "fbeed618357133667c85e08f7236a8de")

    # DES (the classic FIPS 46 worked example) and TDEA CMAC subkeys (NIST CMAC-TDES examples, 3-key)
    chk("DES", _des(bytes.fromhex("133457799bbcdff1"), bytes.fromhex("0123456789abcdef")).hex(), "85e813540f0ab405")
    L = tdea_encrypt(bytes.fromhex("0123456789abcdef23456789abcdef01456789abcdef0123"), bytes(8))
    chk("CMAC-TDES L", L.hex(), "4eba739c998bcb60")
    chk("CMAC-TDES K1, K2 (R_64)", [v2b(double_ocb(b2v(L), 64), 8).hex(),
        v2b(double_ocb(double_ocb(b2v(L), 64), 64), 8).hex()], ["9d74e739331796c0", "3ae9ce72662f2d9b"])

    # md_pad: SHA-256 built on it against hashlib, every length 0..129 bytes; the padding against
    # the FIPS 180-4 sect. 5.1.1 bit string for every bit length 0..1100, w = 32 and 64
    import hashlib, struct
    K = [int(x, 16) for x in (
        '428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be '
        '550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa '
        '5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85 '
        '2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3 '
        'd192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f '
        '682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2').split()]
    M32 = 0xffffffff
    ror = lambda x, n: ((x >> n) | (x << (32 - n))) & M32
    def sha256(data):
        H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        data += md_pad(8 * len(data), 32)
        for o in range(0, len(data), 64):
            w = list(struct.unpack('>16I', data[o:o + 64]))
            for i in range(16, 64):
                s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
                s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w.append((w[i - 16] + s0 + w[i - 7] + s1) & M32)
            a, b_, c, d, e, f, g, h = H
            for i in range(64):
                t1 = (h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) & M32
                t2 = ((ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b_) ^ (a & c) ^ (b_ & c))) & M32
                a, b_, c, d, e, f, g, h = (t1 + t2) & M32, a, b_, c, (d + t1) & M32, e, f, g
            H = [(x + y) & M32 for x, y in zip(H, (a, b_, c, d, e, f, g, h))]
        return struct.pack('>8I', *H)
    msgs = [bytes((7 * i + 1) & 0xFF for i in range(n)) for n in range(130)]
    chk("md_pad: SHA-256 = hashlib, 0..129 bytes", [n for n, m in enumerate(msgs) if sha256(m) != hashlib.sha256(m).digest()], [])
    bad = []
    for w in (32, 64):
        for nb in range(1101):
            m = bytes((5 * i + 3) & 0xFF for i in range(-(-nb // 8)))
            bs = bits_of(m, nb, True)
            ref = bs + '1' + '0' * (-(nb + 1 + 2 * w) % (16 * w)) + format(nb, f'0{2 * w}b')
            k = nb % 8
            last = (m[-1] & (0xFF << (8 - k)) & 0xFF) | (1 << (7 - k)) if k else None
            got = (m[:nb // 8] + (bytes([last]) if k else b'')) + md_pad(nb, w)
            if bits_of(got, len(got) * 8, True) != ref:
                bad.append((w, nb))
    chk("md_pad: = the FIPS 180-4 bit-string padding, 0..1100 bits, w = 32, 64", bad, [])

    # hash_run on a trivial port: an XOF over SHAKE128 that halts after every byte
    class _Port(HashPort):
        b, bitwise = 64, False
        def __init__(p, data=b'', st=KL_STATE_READY, pos=0):
            p.data, p.st, p.pos, p.klstart = data, st, pos, 0
        def setst(p, immed, form='A', xs=None): p.st = immed
        def exec_in(p, d, halt_at=None):
            if halt_at is not None and halt_at + 1 < len(d):
                p.data += d[p.klstart:halt_at + 1]
                p.klstart = halt_at + 1
                return 'interrupted'
            p.data += d[p.klstart:]
            p.klstart = 0
            return 'done'
        def exec_out(p, n, halt_at=None, prior=b''):
            out = hashlib.shake_128(p.data).digest(p.pos + n)[p.pos:p.pos + n]
            p.pos += n
            return 'done', out
        def export(p): return (p.data, p.st, p.pos, p.klstart)
        def imported(p, img):
            q = _Port(*img[:3])
            q.klstart = img[3]
            return q
    m = bytes(range(40))
    want = hashlib.shake_128(m).digest(20)
    res = {k: hash_run(_Port(), m, 320, 20, chunks=c, halt=True, migrate=True, out_split=(1, 3))[0]
           for k, c in hash_chunks(8).items()}
    chk("hash_run: every chunk plan with halts, export/import and odd output splits", res, {k: want for k in res})
    return ok

if __name__ == "__main__":
    good = selftest(verbose=True)
    print("KAT-RESULT:", "PASS" if good else "FAIL")
    sys.exit(0 if good else 1)
