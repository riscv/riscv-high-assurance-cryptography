"""Reference primitives for the sponge KATs, written from FIPS 202, SP 800-185, SP 800-232.
States are Python ints: bit k = state bit k (bytes little-endian, notation of Zkl-notation.adoc)."""
from common import b2v, v2b, mask

# ---- Keccak-f[1600] (FIPS 202 sec. 3): state int, lane (x,y) at bits 64*(5y+x)
def _rc_bit(t):
    R = 1
    for _ in range(t % 255):
        R <<= 1
        if R & 0x100: R ^= 0x171
    return R & 1
_RC = [sum(_rc_bit(7 * i + j) << ((1 << j) - 1) for j in range(7)) for i in range(24)]
_ROT = {}
_x, _y = 1, 0
_ROT[(0, 0)] = 0
for _t in range(24):
    _ROT[(_x, _y)] = ((_t + 1) * (_t + 2) // 2) % 64
    _x, _y = _y, (2 * _x + 3 * _y) % 5
def _rol64(v, r): r %= 64; return ((v << r) | (v >> (64 - r))) & mask(64) if r else v
def keccak_f(s):
    A = [(s >> (64 * i)) & mask(64) for i in range(25)]
    for rc in _RC:
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
        A = [A[i] ^ D[i % 5] for i in range(25)]
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[5 * ((2 * x + 3 * y) % 5) + y] = _rol64(A[5 * y + x], _ROT[(x, y)])
        A = [B[5 * y + x] ^ (~B[5 * y + (x + 1) % 5] & B[5 * y + (x + 2) % 5] & mask(64)) for y in range(5) for x in range(5)]
        A[0] ^= rc
    return sum(a << (64 * i) for i, a in enumerate(A))

# ---- Ascon-p (SP 800-232 sec. 3): state int, word i at bits 64i
_ARC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
def _ror(v, r): return ((v >> r) | (v << (64 - r))) & mask(64)
def ascon_p(s, rounds):
    x = [(s >> (64 * i)) & mask(64) for i in range(5)]
    for c in _ARC[12 - rounds:]:
        x[2] ^= c
        x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1]
        t = [~x[i] & x[(i + 1) % 5] & mask(64) for i in range(5)]
        for i in range(5): x[i] ^= t[(i + 1) % 5]
        x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] = ~x[2] & mask(64)
        for i, (a, b) in enumerate(((19, 28), (61, 39), (1, 6), (10, 17), (7, 41))):
            x[i] ^= _ror(x[i], a) ^ _ror(x[i], b)
    return sum(v << (64 * i) for i, v in enumerate(x))
def ascon12(s): return ascon_p(s, 12)
def ascon8(s): return ascon_p(s, 8)

# ---- bit strings: (value, nbits); bit i = message bit i (LSB-first inside bytes)
def bits_of(v, n): return [(v >> i) & 1 for i in range(n)]
def val_of(bits): return sum(b << i for i, b in enumerate(bits))

def ref_sponge(msg, P, rate, state0, suffix_pad, outbits):
    """msg: (value, nbits).  suffix_pad(nbits_msg) -> list of padding bits appended to the message bits
    (total length must be a multiple of rate).  Absorb: XOR block into rate, P.  Squeeze: rate bits, P."""
    bits = bits_of(*msg) + suffix_pad(msg[1])
    assert len(bits) % rate == 0
    s = state0
    for i in range(0, len(bits), rate):
        s = P(s ^ val_of(bits[i:i + rate]))
    out = []
    while True:
        out += bits_of(s & mask(rate), rate)
        if len(out) >= outbits: break
        s = P(s)
    return val_of(out[:outbits])

def _pad101(rate, suffix):
    def f(nb):
        j = (-(nb + len(suffix) + 2)) % rate
        return suffix + [1] + [0] * j + [1]
    return f
SHA3_SUFFIX = {'SHA3': [0, 1], 'SHAKE': [1, 1, 1, 1], 'CSHAKE': [0, 0]}
def ref_keccak(msg, rate, kind, outbits):
    return ref_sponge(msg, keccak_f, rate, 0, _pad101(rate, SHA3_SUFFIX[kind]), outbits)

# ---- SP 800-185 encodings (byte strings)
def left_encode(x):
    n = max(1, (x.bit_length() + 7) // 8); return bytes([n]) + x.to_bytes(n, 'big')
def right_encode(x):
    n = max(1, (x.bit_length() + 7) // 8); return x.to_bytes(n, 'big') + bytes([n])
def encode_string(s): return left_encode(8 * len(s)) + s
def bytepad(x, w):
    z = left_encode(w) + x
    return z + bytes((-len(z)) % w)
def ref_kmac(rate, K, X, L, S=b'', xof=False):
    """KMAC128/256 (rate 168/136) over byte string X; L output bits (SP 800-185 sec. 4.3); xof: KMACXOF."""
    newx = bytepad(encode_string(K), rate) + X + right_encode(0 if xof else L)
    pre = bytepad(encode_string(b'KMAC') + encode_string(S), rate)
    return ref_keccak((b2v(pre + newx), 8 * (len(pre) + len(newx))), rate * 8, 'CSHAKE', L)

# ---- Ascon (SP 800-232), byte-oriented references
IV_HASH, IV_XOF, IV_CXOF, IV_AEAD = 0x0000080100cc0002, 0x0000080000cc0003, 0x0000080000cc0004, 0x00001000808c0001
def _ascon_init(iv): return ascon12(iv)
def ascon_pad(nbits_msg):  # pad(M,64): 1 then zeros to a multiple of 64
    return [1] + [0] * ((-(nbits_msg + 1)) % 64)
def ref_ascon_hash(msg, outbits, iv=IV_HASH):
    return ref_sponge(msg, ascon12, 64, _ascon_init(iv), ascon_pad, outbits)
def ref_ascon_cxof(msg, Z, outbits):
    """Z: (value, nbits).  Z0 = bin(len,64), pad(Z,64), each block followed by ASCON(12) (sec. 5.3)."""
    s = _ascon_init(IV_CXOF)
    zb = bits_of(Z[1], 64) + bits_of(*Z) + ascon_pad(Z[1])
    for i in range(0, len(zb), 64): s = ascon12(s ^ val_of(zb[i:i + 64]))
    bits = bits_of(*msg) + ascon_pad(msg[1])
    for i in range(0, len(bits), 64): s = ascon12(s ^ val_of(bits[i:i + 64]))
    out = []
    while len(out) < outbits:
        out += bits_of(s & mask(64), 64); s = ascon12(s) if len(out) < outbits else s
    return val_of(out[:outbits])
def ref_ascon_aead(key, nonce, ad, pt, ptbits=None):
    """key, nonce: 16 bytes; ad, pt: bytes (pt may be cut to ptbits bits: last byte keeps its low bits).
    Returns (ct, ctbits, tag16).  Follows SP 800-232 Algorithm 3."""
    K0, K1 = b2v(key[:8]), b2v(key[8:]); N0, N1 = b2v(nonce[:8]), b2v(nonce[8:])
    s = [IV_AEAD, K0, K1, N0, N1]
    P = lambda s: [(ascon_p(sum(v << (64 * i) for i, v in enumerate(s)), 12) >> (64 * i)) & mask(64) for i in range(5)]
    P8 = lambda s: [(ascon_p(sum(v << (64 * i) for i, v in enumerate(s)), 8) >> (64 * i)) & mask(64) for i in range(5)]
    s = P(s); s[3] ^= K0; s[4] ^= K1
    if ad:
        a = ad + b'\x01' + bytes((-len(ad) - 1) % 16)
        for i in range(0, len(a), 16):
            s[0] ^= b2v(a[i:i + 8]); s[1] ^= b2v(a[i + 8:i + 16]); s = P8(s)
    s[4] ^= 1 << 63
    nb = 8 * len(pt) if ptbits is None else ptbits
    ct = 0
    full = nb // 128
    for i in range(full):
        s[0] ^= b2v(pt[16 * i:16 * i + 8]); s[1] ^= b2v(pt[16 * i + 8:16 * i + 16])
        ct |= (s[0] | s[1] << 64) << (128 * i); s = P8(s)
    r = nb - 128 * full
    last = (b2v(pt[16 * full:]) & mask(r)) | (1 << r)       # pad(P_last,128)
    s[0] ^= last & mask(64); s[1] ^= last >> 64
    ct |= ((s[0] | s[1] << 64) & mask(r)) << (128 * full)
    s[2] ^= K0; s[3] ^= K1; s = P(s); s[3] ^= K0; s[4] ^= K1
    return ct, nb, s[3] | s[4] << 64
