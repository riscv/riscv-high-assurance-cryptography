"""Independent references for the hash KATs: SHA-2 (FIPS 180-4), SM3 (GB/T 32905-2016), BLAKE2 (RFC 7693),
Keccak/SHA-3 (FIPS 202), HMAC (FIPS 198-1).  Messages are (bytes, nbits) bit strings in the STANDARD's order
(SHA-2/SM3: bit 0 = MSB of byte 0; SHA-3: bit 0 = LSB of byte 0).  Constants are derived, not typed in
(SHA-2), except the short SM3/BLAKE2 tables."""
import hashlib

def _isqrt(n): return __import__('math').isqrt(n)
def _icbrt(n):
    x = 1 << ((n.bit_length() + 2) // 3 + 1)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x: return x
        x = y
def _primes(k):
    p = []; c = 2
    while len(p) < k:
        if all(c % q for q in p): p.append(c)
        c += 1
    return p
_P = _primes(80)
K512 = [_icbrt(p << 192) & ((1 << 64) - 1) for p in _P]
K256 = [k >> 32 for k in K512[:64]]
IV512 = [_isqrt(p << 128) & ((1 << 64) - 1) for p in _P[:8]]
IV384 = [_isqrt(p << 128) & ((1 << 64) - 1) for p in _P[8:16]]
IV256 = [h >> 32 for h in IV512]
IV224 = [h & 0xffffffff for h in IV384]

def _rotr(x, n, w): return ((x >> n) | (x << (w - n))) & ((1 << w) - 1)
SHA2 = {  # name: (w, b_bits, t_bits)
    'SHA-224': (32, 512, 224), 'SHA-256': (32, 512, 256), 'SHA-384': (64, 1024, 384), 'SHA-512': (64, 1024, 512),
    'SHA-512/224': (64, 1024, 224), 'SHA-512/256': (64, 1024, 256)}

def sha2_compress(w, H, words):
    """one compression; H list of 8 ints, words list of 16 ints (big-endian words of the block)."""
    M = (1 << w) - 1
    if w == 32: K, r, s0, s1, S0, S1, R = K256, 64, (7, 18, 3), (17, 19, 10), (2, 13, 22), (6, 11, 25), 64
    else: K, r, s0, s1, S0, S1, R = K512, 80, (1, 8, 7), (19, 61, 6), (28, 34, 39), (14, 18, 41), 80
    W = list(words)
    for t in range(16, r):
        a = W[t - 15]; c = W[t - 2]
        g0 = _rotr(a, s0[0], w) ^ _rotr(a, s0[1], w) ^ (a >> s0[2])
        g1 = _rotr(c, s1[0], w) ^ _rotr(c, s1[1], w) ^ (c >> s1[2])
        W.append((g1 + W[t - 7] + g0 + W[t - 16]) & M)
    a, b, c, d, e, f, g, h = H
    for t in range(r):
        T1 = (h + (_rotr(e, S1[0], w) ^ _rotr(e, S1[1], w) ^ _rotr(e, S1[2], w)) + ((e & f) ^ (~e & M & g)) + K[t] + W[t]) & M
        T2 = ((_rotr(a, S0[0], w) ^ _rotr(a, S0[1], w) ^ _rotr(a, S0[2], w)) + ((a & b) ^ (a & c) ^ (b & c))) & M
        h, g, f, e, d, c, b, a = g, f, e, (d + T1) & M, c, b, a, (T1 + T2) & M
    return [(x + y) & M for x, y in zip(H, [a, b, c, d, e, f, g, h])]

def _words(blk, w):  # blk bytes -> big-endian words
    n = w // 8
    return [int.from_bytes(blk[i:i + n], 'big') for i in range(0, len(blk), n)]

def _md_pad_bits(msg, nbits, b, lw):
    """FIPS 180-4 5.1: append bit 1, zeros, then the length on lw bits; returns bytes (multiple of b/8)."""
    s = ''.join(format(x, '08b') for x in msg)[:nbits] + '1'
    s += '0' * ((-(nbits + 1 + lw)) % b) + format(nbits, '0%db' % lw)
    return int(s, 2).to_bytes(len(s) // 8, 'big')

def sha512t_iv(t):
    iv = [h ^ 0xa5a5a5a5a5a5a5a5 for h in IV512]
    return _chain(64, 1024, iv, ('SHA-512/%d' % t).encode(), 8 * len(('SHA-512/%d' % t)))

def _chain(w, b, H, msg, nbits):
    data = _md_pad_bits(msg, nbits, b, 2 * w)
    for i in range(0, len(data), b // 8):
        H = sha2_compress(w, H, _words(data[i:i + b // 8], w))
    return H

def sha2_iv(name):
    return {'SHA-224': IV224, 'SHA-256': IV256, 'SHA-384': IV384, 'SHA-512': IV512,
            'SHA-512/224': sha512t_iv(224), 'SHA-512/256': sha512t_iv(256)}[name]

def sha2(name, msg, nbits=None):
    w, b, t = SHA2[name]
    if nbits is None: nbits = 8 * len(msg)
    H = _chain(w, b, sha2_iv(name), msg, nbits)
    return b''.join(h.to_bytes(w // 8, 'big') for h in H)[:t // 8]

# ---- SM3
SM3_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
def _rl(x, n): n %= 32; return ((x << n) | (x >> (32 - n))) & 0xffffffff if n else x
def sm3_compress(V, words):
    P0 = lambda x: x ^ _rl(x, 9) ^ _rl(x, 17)
    P1 = lambda x: x ^ _rl(x, 15) ^ _rl(x, 23)
    W = list(words)
    for j in range(16, 68):
        W.append(P1(W[j - 16] ^ W[j - 9] ^ _rl(W[j - 3], 15)) ^ _rl(W[j - 13], 7) ^ W[j - 6])
    W1 = [W[j] ^ W[j + 4] for j in range(64)]
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        Tj = 0x79cc4519 if j < 16 else 0x7a879d8a
        SS1 = _rl((_rl(A, 12) + E + _rl(Tj, j)) & 0xffffffff, 7)
        SS2 = SS1 ^ _rl(A, 12)
        if j < 16: FF = A ^ B ^ C; GG = E ^ F ^ G
        else: FF = (A & B) | (A & C) | (B & C); GG = (E & F) | (~E & 0xffffffff & G)
        TT1 = (FF + D + SS2 + W1[j]) & 0xffffffff
        TT2 = (GG + H + SS1 + W[j]) & 0xffffffff
        D = C; C = _rl(B, 9); B = A; A = TT1; H = G; G = _rl(F, 19); F = E; E = P0(TT2)
    return [x ^ y for x, y in zip(V, [A, B, C, D, E, F, G, H])]
def sm3(msg, nbits=None):
    if nbits is None: nbits = 8 * len(msg)
    data = _md_pad_bits(msg, nbits, 512, 64); V = SM3_IV
    for i in range(0, len(data), 64): V = sm3_compress(V, _words(data[i:i + 64], 32))
    return b''.join(v.to_bytes(4, 'big') for v in V)

# ---- BLAKE2 (RFC 7693)
_SIGMA = [[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],[11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
          [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],[9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
          [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],[6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
          [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]]
B2 = {'BLAKE2b': (64, 12, 128, 64, (32, 24, 16, 63)), 'BLAKE2s': (32, 10, 64, 32, (16, 12, 8, 7))}  # w, rounds, block bytes, nnmax, rot
B2IV = {64: IV512, 32: IV256}
def blake2_F(name, h, m, counter, final):
    w, rounds, bb, _, R = B2[name]; M = (1 << w) - 1
    v = list(h) + list(B2IV[w])
    v[12] ^= counter & M; v[13] ^= (counter >> w) & M
    if final: v[14] ^= M
    def G(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & M; v[d] = _rotr(v[d] ^ v[a], R[0], w)
        v[c] = (v[c] + v[d]) & M;     v[b] = _rotr(v[b] ^ v[c], R[1], w)
        v[a] = (v[a] + v[b] + y) & M; v[d] = _rotr(v[d] ^ v[a], R[2], w)
        v[c] = (v[c] + v[d]) & M;     v[b] = _rotr(v[b] ^ v[c], R[3], w)
    for i in range(rounds):
        s = _SIGMA[i % 10]
        G(0,4,8,12,m[s[0]],m[s[1]]); G(1,5,9,13,m[s[2]],m[s[3]]); G(2,6,10,14,m[s[4]],m[s[5]]); G(3,7,11,15,m[s[6]],m[s[7]])
        G(0,5,10,15,m[s[8]],m[s[9]]); G(1,6,11,12,m[s[10]],m[s[11]]); G(2,7,8,13,m[s[12]],m[s[13]]); G(3,4,9,14,m[s[14]],m[s[15]])
    return [h[i] ^ v[i] ^ v[i + 8] for i in range(8)]
def blake2(name, msg, key=b'', nn=None):
    w, _, bb, nnmax, _ = B2[name]
    nn = nn or nnmax
    h = list(B2IV[w]); h[0] ^= 0x01010000 ^ (len(key) << 8) ^ nn
    data = (key + b'\0' * (bb - len(key)) if key else b'') + msg
    if not data: data = b'\0' * bb; cnt = 0
    else: cnt = len(data)
    blocks = [data[i:i + bb] for i in range(0, len(data), bb)]
    done = 0
    for i, blk in enumerate(blocks):
        done += len(blk); last = i == len(blocks) - 1
        blk = blk + b'\0' * (bb - len(blk))
        h = blake2_F(name, h, [int.from_bytes(blk[j:j + w // 8], 'little') for j in range(0, bb, w // 8)], done if cnt else 0, last)
    return b''.join(x.to_bytes(w // 8, 'little') for x in h)[:nn]

# ---- Keccak
_RC = []
def _rc():
    r = 1
    for _ in range(24):
        c = 0
        for j in range(7):
            if r & 1: c |= 1 << ((1 << j) - 1)
            r = ((r << 1) ^ (0x171 if r & 0x80 else 0)) & 0xff
        _RC.append(c)
_rc()
_ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
def keccak_f(S):
    """S: int of 1600 bits, lane (x,y) = bits 64*(x+5y)..; returns permuted int."""
    A = [[(S >> (64 * (x + 5 * y))) & (2**64 - 1) for y in range(5)] for x in range(5)]
    M = 2**64 - 1
    rl = lambda v, n: ((v << n) | (v >> (64 - n))) & M if n else v
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rl(C[(x + 1) % 5], 1) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5): B[y][(2 * x + 3 * y) % 5] = rl(A[x][y], _ROT[x][y])
        A = [[B[x][y] ^ (~B[(x + 1) % 5][y] & M & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= _RC[rnd]
    return sum(A[x][y] << (64 * (x + 5 * y)) for x in range(5) for y in range(5))
SHA3 = {'SHA3-224': (1152, 224, 0b10, 2), 'SHA3-256': (1088, 256, 0b10, 2), 'SHA3-384': (832, 384, 0b10, 2),
        'SHA3-512': (576, 512, 0b10, 2), 'SHAKE128': (1344, None, 0b1111, 4), 'SHAKE256': (1088, None, 0b1111, 4)}
def sha3_bits(name, v, nbits, outbits=None):
    """v: int, message bit i = v[i] (FIPS 202 bit order); returns digest bytes."""
    r, t, D, dl = SHA3[name]
    outbits = outbits or t
    M = v & ((1 << nbits) - 1) | (D << nbits)          # M || D
    n = nbits + dl
    M |= 1 << n; n += 1                                  # pad10*1
    while (n + 1) % r: n += 1
    M |= 1 << n; n += 1
    S = 0
    for i in range(0, n, r): S = keccak_f(S ^ ((M >> i) & ((1 << r) - 1)))
    out = 0; got = 0
    while got < outbits:
        out |= (S & ((1 << r) - 1)) << got; got += r
        if got < outbits: S = keccak_f(S)
    return (out & ((1 << outbits) - 1)).to_bytes((outbits + 7) // 8, 'little')
def sha3(name, msg, outbits=None): return sha3_bits(name, int.from_bytes(msg, 'little'), 8 * len(msg), outbits)

def hmac(H, b, key, msg):
    """FIPS 198-1 with H: bytes->bytes, b = block bytes (rate for SHA-3)."""
    if len(key) > b: key = H(key)
    k0 = key + b'\0' * (b - len(key))
    return H(bytes(x ^ 0x5c for x in k0) + H(bytes(x ^ 0x36 for x in k0) + msg))

def selftest():
    import os
    for n in SHA2:
        h = {'SHA-224': 'sha224', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512', 'SHA-512/224': 'sha512_224', 'SHA-512/256': 'sha512_256'}[n]
        for m in (b'', b'abc', os.urandom(200)): assert sha2(n, m) == hashlib.new(h, m).digest(), n
    for m in (b'', b'abc', os.urandom(150)): assert sm3(m) == hashlib.new('sm3', m).digest()
    for n, h in (('BLAKE2b', hashlib.blake2b), ('BLAKE2s', hashlib.blake2s)):
        for k in (b'', b'key'):
            for m in (b'', b'abc', os.urandom(300)):
                for nn in (None, 20): assert blake2(n, m, k, nn) == h(m, key=k, digest_size=nn or B2[n][3]).digest()
    for n in SHA3:
        for m in (b'', b'abc', os.urandom(400)):
            ref = hashlib.new(n.lower().replace('shake', 'shake_').replace('-', '_'), m)
            if n.startswith('SHAKE'): assert sha3(n, m, 8 * 400) == ref.digest(400)
            else: assert sha3(n, m) == ref.digest()
    return True
if __name__ == '__main__': print(selftest())
