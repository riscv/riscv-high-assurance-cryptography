"""Independent byte-level references for GCM, GCM-SIV, OCB3 and CMAC, written from the standards
(SP 800-38D, RFC 8452, RFC 7253, SP 800-38B).  Everything is in the STANDARD's order: bytes, big-endian
integers for GHASH/OCB.  Uses only the block ciphers of common.py (bytes in, bytes out); shares no code with
common.ghash_mul / montmul / double or with aead_model.py.
"""
from common import cipher_enc, cipher_dec

def _i(b): return int.from_bytes(b, 'big')
def _b(i, n): return (i % (1 << (8 * n))).to_bytes(n, 'big')
def _x(a, b): return bytes(p ^ q for p, q in zip(a, b))

# ---------------------------------------------------------------- GHASH (SP 800-38D 6.3: bit 0 = leftmost)
def gmul(X, Y):
    R = 0xE1 << 120
    Z, V = 0, Y
    for i in range(127, -1, -1):          # x_0 is the most significant bit of the big-endian integer
        if (X >> i) & 1: Z ^= V
        V = (V >> 1) ^ R if V & 1 else V >> 1
    return Z

def ghash(H, data):                      # H: 16 bytes; data: multiple of 16 bytes
    h, y = _i(H), 0
    for k in range(0, len(data), 16):
        y = gmul(y ^ _i(data[k:k + 16]), h)
    return _b(y, 16)

def _pad16(d): return d + bytes(-len(d) % 16)

def gcm_j0(E, H, iv):
    if len(iv) == 12: return iv + b'\0\0\0\1'
    return ghash(H, _pad16(iv) + bytes(8) + _b(8 * len(iv), 8))

def _inc32(blk): return blk[:12] + _b(_i(blk[12:]) + 1, 4)

def gcm_core(E, j0, aad, pt=None, ct=None):
    """E: block-encrypt function.  Encrypt pt or decrypt ct from the given J0; returns (output, full 16-byte tag)."""
    H = E(bytes(16))
    data = pt if pt is not None else ct
    out, cb = b'', j0
    for k in range(0, len(data), 16):
        cb = _inc32(cb)
        ks = E(cb)
        out += _x(data[k:k + 16], ks)
    c = out if pt is not None else ct
    S = ghash(H, _pad16(aad) + _pad16(c) + _b(8 * len(aad), 8) + _b(8 * len(c), 8))
    return out, _x(E(j0), S)

def gcm_enc(E, iv, aad, pt):
    H = E(bytes(16))
    return gcm_core(E, gcm_j0(E, H, iv), aad, pt=pt)

def gcm_dec(E, iv, aad, ct):
    H = E(bytes(16))
    return gcm_core(E, gcm_j0(E, H, iv), aad, ct=ct)

# ---------------------------------------------------------------- GCM-SIV (RFC 8452)
def _mulx_ghash(a):                      # RFC 8452 Appendix A: multiply by x in the GHASH field
    return (a >> 1) ^ (0xE1 << 120) if a & 1 else a >> 1

def polyval(H, X):                       # H 16 bytes, X multiple of 16 bytes; RFC 8452 Appendix A relation to GHASH
    rev = lambda b: b[::-1]
    hh = _mulx_ghash(_i(rev(H)))
    y = 0
    for k in range(0, len(X), 16):
        y = gmul(y ^ _i(rev(X[k:k + 16])), hh)
    return rev(_b(y, 16))

def siv_keys(E_name, key, nonce):
    n = len(key) // 8 + 2                # k/64 + 2 AES calls, 4 for 128 bit keys, 6 for 256 bit keys
    A = [cipher_enc(E_name, key, _b(i, 4)[::-1] + nonce)[:8] for i in range(n)]
    return b''.join(A[2:]), A[0] + A[1]  # enc_key, auth_key

def siv_tag(ek_name, enc_key, auth_key, nonce, aad, pt):
    S = polyval(auth_key, _pad16(aad) + _pad16(pt) + _b(8 * len(aad), 8)[::-1] + _b(8 * len(pt), 8)[::-1])
    S = bytearray(_x(S[:12], nonce) + S[12:])
    S[15] &= 0x7F
    return cipher_enc(ek_name, enc_key, bytes(S))

def siv_ctr(ek_name, enc_key, tag, data):
    cb = bytearray(tag); cb[15] |= 0x80
    c0 = int.from_bytes(cb[:4], 'little')
    out = b''
    for j, k in enumerate(range(0, len(data), 16)):
        blk = (c0 + j) % 2**32
        ks = cipher_enc(ek_name, enc_key, blk.to_bytes(4, 'little') + bytes(cb[4:]))
        out += _x(data[k:k + 16], ks)
    return out

def siv_enc(name, key, nonce, aad, pt):
    ek, ak = siv_keys(name, key, nonce)
    ename = name
    tag = siv_tag(ename, ek, ak, nonce, aad, pt)
    return siv_ctr(ename, ek, tag, pt), tag

def siv_dec(name, key, nonce, aad, ct, tag):
    ek, ak = siv_keys(name, key, nonce)
    pt = siv_ctr(name, ek, tag, ct)
    return pt, siv_tag(name, ek, ak, nonce, aad, pt) == tag

# ---------------------------------------------------------------- OCB3 (RFC 7253), 128-bit block, nonce a bit string
def _dbl(b):
    v = _i(b)
    v = (v << 1) ^ (0x87 if v >> 127 else 0)
    return _b(v, 16)

def _ntz(n): return (n & -n).bit_length() - 1

class OCB:
    def __init__(self, name, key, taglen=128):
        self.n, self.k, self.taglen = name, key, taglen
        self.E = lambda b: cipher_enc(name, key, b)
        self.D = lambda b: cipher_dec(name, key, b)
        self.Ls = self.E(bytes(16)); self.Ld = _dbl(self.Ls)
        self.L = [_dbl(self.Ld)]
        for _ in range(60): self.L.append(_dbl(self.L[-1]))

    def init_offset(self, nonce_bits, nbits):
        """nonce: integer holding the nbits-bit string, first bit = most significant (RFC 7253 order)."""
        # Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N, as a 128-bit string
        v = ((self.taglen % 128) << 121) | (1 << nbits) | nonce_bits
        Nb = _b(v, 16)
        bottom = Nb[15] & 0x3F
        Ktop = self.E(_b(_i(Nb) & ~0x3F, 16))
        Stretch = _i(Ktop) << 64 | ((_i(Ktop) >> 64) ^ (_i(Ktop) >> 56)) & 0xFFFFFFFFFFFFFFFF
        # Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]), 192 bits
        return _b((Stretch >> (64 - bottom)) & ((1 << 128) - 1), 16)

    def hash(self, A):
        S, off = bytes(16), bytes(16)
        m = len(A) // 16
        for i in range(1, m + 1):
            off = _x(off, self.L[_ntz(i)])
            S = _x(S, self.E(_x(A[16 * (i - 1):16 * i], off)))
        r = A[16 * m:]
        if r:
            off = _x(off, self.Ls)
            S = _x(S, self.E(_x(_pad(r), off)))
        return S

    def crypt(self, nonce_bits, nbits, A, data, decrypt=False, tag=None):
        off = self.init_offset(nonce_bits, nbits)
        cs, out = bytes(16), b''
        m = len(data) // 16
        for i in range(1, m + 1):
            off = _x(off, self.L[_ntz(i)])
            blk = data[16 * (i - 1):16 * i]
            if decrypt:
                p = _x(off, self.D(_x(blk, off))); cs = _x(cs, p); out += p
            else:
                cs = _x(cs, blk); out += _x(off, self.E(_x(blk, off)))
        r = data[16 * m:]
        if r:
            off = _x(off, self.Ls)
            pad = self.E(off)
            o = _x(r, pad[:len(r)])
            out += o
            cs = _x(cs, _pad(r if not decrypt else o))
        T = _x(self.E(_x(_x(cs, off), self.Ld)), self.hash(A))
        return out, T[:self.taglen // 8]

def _pad(r): return r + b'\x80' + bytes(15 - len(r))

def ocb_enc(name, key, nonce_bits, nbits, A, P, taglen=128):
    c, t = OCB(name, key, taglen).crypt(nonce_bits, nbits, A, P)
    return c, t

def ocb_dec(name, key, nonce_bits, nbits, A, C, taglen=128):
    return OCB(name, key, taglen).crypt(nonce_bits, nbits, A, C, decrypt=True)

# ---------------------------------------------------------------- CMAC (SP 800-38B)
def cmac(name, key, msg, tlen=None):
    bs = 8 if name == 'TDEA' else 16
    Rb = 0x1B if bs == 8 else 0x87
    E = lambda b: cipher_enc(name, key, b)
    def dbl(b):
        v = _i(b); return _b((v << 1) ^ (Rb if v >> (8 * bs - 1) else 0), bs)
    L = E(bytes(bs)); K1 = dbl(L); K2 = dbl(K1)
    n = max(1, -(-len(msg) // bs))
    last = msg[bs * (n - 1):]
    if len(msg) and len(last) == bs: last = _x(last, K1)
    else: last = _x(last + b'\x80' + bytes(bs - len(last) - 1), K2)
    C = bytes(bs)
    for i in range(n - 1): C = E(_x(C, msg[bs * i:bs * i + bs]))
    T = E(_x(C, last))
    return (T, K1, K2, L) if tlen is None else T[:tlen]
