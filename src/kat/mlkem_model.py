"""ML-KEM (FIPS 203), written from the standard.  Byte strings are Python bytes in the standard's order.
Public: PARAMS, keygen_internal(p,d,z), encaps_internal(p,ek,m), decaps(p,dk,c), ek_check(p,ek), dk_check(p,dk),
sample_ntt_iterations (instrumentation), SampleNTTLimit (raised when the iteration bound is hit).
"""
import hashlib
Q = 3329
PARAMS = {  # name: (k, eta1, eta2, du, dv)
    'ML-KEM-512': (2, 3, 2, 10, 4), 'ML-KEM-768': (3, 2, 2, 10, 4), 'ML-KEM-1024': (4, 2, 2, 11, 5)}
SIZES = {  # ek, dk, ct, K  (FIPS 203 Table 3)
    'ML-KEM-512': (800, 1632, 768, 32), 'ML-KEM-768': (1184, 2400, 1088, 32), 'ML-KEM-1024': (1568, 3168, 1568, 32)}
class SampleNTTLimit(Exception): pass
SAMPLE_LIMIT = [None]   # per-call bound on the rejection loop of SampleNTT (None = unbounded)

def H(x): return hashlib.sha3_256(x).digest()
def J(x): return hashlib.shake_256(x).digest(32)
def G(x): h = hashlib.sha3_512(x).digest(); return h[:32], h[32:]
def prf(eta, s, b): return hashlib.shake_256(s + bytes([b])).digest(64 * eta)

def _brv7(i): return int('{:07b}'.format(i)[::-1], 2)
ZETA = [pow(17, _brv7(i), Q) for i in range(128)]

def byte_encode(d, F):
    bits = []
    for a in F:
        bits += [(a >> j) & 1 for j in range(d)]
    return bytes(sum(bits[8 * i + j] << j for j in range(8)) for i in range(len(bits) // 8))
def byte_decode(d, B):
    bits = [(B[i // 8] >> (i % 8)) & 1 for i in range(8 * len(B))]
    m = Q if d == 12 else 1 << d
    return [sum(bits[i * d + j] << j for j in range(d)) % m for i in range(256)]
def compress(d, x): return [((x_ * (1 << d) + Q // 2) // Q) % (1 << d) for x_ in x]
def decompress(d, y): return [(y_ * Q + (1 << (d - 1))) >> d for y_ in y]

def sample_ntt(B):
    xof = hashlib.shake_128(B)
    out, j, pos, it = [], 0, 0, 0
    buf = xof.digest(3 * 4096)
    while j < 256:
        if SAMPLE_LIMIT[0] is not None and it >= SAMPLE_LIMIT[0]: raise SampleNTTLimit()
        if pos + 3 > len(buf): buf = xof.digest(len(buf) * 2)
        c = buf[pos:pos + 3]; pos += 3; it += 1
        d1 = c[0] + 256 * (c[1] % 16); d2 = (c[1] >> 4) + 16 * c[2]
        if d1 < Q: out.append(d1); j += 1
        if d2 < Q and j < 256: out.append(d2); j += 1
    return out
def sample_cbd(eta, B):
    bits = [(B[i // 8] >> (i % 8)) & 1 for i in range(8 * len(B))]
    return [(sum(bits[2 * i * eta:2 * i * eta + eta]) - sum(bits[2 * i * eta + eta:2 * i * eta + 2 * eta])) % Q for i in range(256)]

def ntt(f):
    f = list(f); i = 1; ln = 128
    while ln >= 2:
        for s in range(0, 256, 2 * ln):
            z = ZETA[i]; i += 1
            for j in range(s, s + ln):
                t = z * f[j + ln] % Q
                f[j + ln] = (f[j] - t) % Q; f[j] = (f[j] + t) % Q
        ln //= 2
    return f
def ntt_inv(f):
    f = list(f); i = 127; ln = 2
    while ln <= 128:
        for s in range(0, 256, 2 * ln):
            z = ZETA[i]; i -= 1
            for j in range(s, s + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = z * (f[j + ln] - t) % Q
        ln *= 2
    return [x * 3303 % Q for x in f]
def mul_ntt(f, g):
    h = [0] * 256
    for i in range(128):
        z = pow(17, 2 * _brv7(i) + 1, Q)
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 % Q * z) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h
def vadd(a, b): return [(x + y) % Q for x, y in zip(a, b)]
def vsub(a, b): return [(x - y) % Q for x, y in zip(a, b)]
def dot(u, v):
    r = [0] * 256
    for a, b in zip(u, v): r = vadd(r, mul_ntt(a, b))
    return r
def matvec(A, v, trans):
    k = len(v)
    return [dot([A[j][i] if trans else A[i][j] for j in range(k)], v) for i in range(k)]

def _matrix(rho, k):
    return [[sample_ntt(rho + bytes([j, i])) for j in range(k)] for i in range(k)]

def k_pke_keygen(p, d):
    k, e1, _, _, _ = PARAMS[p]
    rho, sig = G(d + bytes([k])); N = 0
    A = _matrix(rho, k)
    s = []; e = []
    for _ in range(k): s.append(ntt(sample_cbd(e1, prf(e1, sig, N)))); N += 1
    for _ in range(k): e.append(ntt(sample_cbd(e1, prf(e1, sig, N)))); N += 1
    t = [vadd(x, y) for x, y in zip(matvec(A, s, False), e)]
    ek = b''.join(byte_encode(12, x) for x in t) + rho
    dk = b''.join(byte_encode(12, x) for x in s)
    return ek, dk
def k_pke_encrypt(p, ek, m, r):
    k, e1, e2, du, dv = PARAMS[p]
    t = [byte_decode(12, ek[384 * i:384 * i + 384]) for i in range(k)]
    rho = ek[384 * k:]
    A = _matrix(rho, k); N = 0
    y = []; e_1 = []
    for _ in range(k): y.append(ntt(sample_cbd(e1, prf(e1, r, N)))); N += 1
    for _ in range(k): e_1.append(sample_cbd(e2, prf(e2, r, N))); N += 1
    e_2 = sample_cbd(e2, prf(e2, r, N))
    u = [vadd(ntt_inv(x), e) for x, e in zip(matvec(A, y, True), e_1)]
    mu = decompress(1, byte_decode(1, m))
    v = vadd(vadd(ntt_inv(dot(t, y)), e_2), mu)
    return b''.join(byte_encode(du, compress(du, x)) for x in u) + byte_encode(dv, compress(dv, v))
def k_pke_decrypt(p, dk, c):
    k, _, _, du, dv = PARAMS[p]
    c1, c2 = c[:32 * du * k], c[32 * du * k:]
    u = [decompress(du, byte_decode(du, c1[32 * du * i:32 * du * (i + 1)])) for i in range(k)]
    v = decompress(dv, byte_decode(dv, c2))
    s = [byte_decode(12, dk[384 * i:384 * i + 384]) for i in range(k)]
    w = vsub(v, ntt_inv(dot(s, [ntt(x) for x in u])))
    return byte_encode(1, compress(1, w))

def keygen_internal(p, d, z):
    ek, dkp = k_pke_keygen(p, d)
    return ek, dkp + ek + H(ek) + z
def encaps_internal(p, ek, m):
    K, r = G(m + H(ek))
    return K, k_pke_encrypt(p, ek, m, r)
def decaps(p, dk, c):
    k = PARAMS[p][0]
    dkp, ek, h, z = dk[:384 * k], dk[384 * k:768 * k + 32], dk[768 * k + 32:768 * k + 64], dk[768 * k + 64:]
    m = k_pke_decrypt(p, dkp, c)
    K, r = G(m + h)
    Kbar = J(z + c)
    c2 = k_pke_encrypt(p, ek, m, r)
    return K if c == c2 else Kbar

def ek_check(p, ek):
    """FIPS 203 7.2: type check and modulus check."""
    k = PARAMS[p][0]
    if len(ek) != 384 * k + 32: return False
    return all(byte_encode(12, byte_decode(12, ek[384 * i:384 * i + 384])) == ek[384 * i:384 * i + 384] for i in range(k))
def dk_check(p, dk):
    """FIPS 203 7.3 (decapsulation key): type check and hash check."""
    k = PARAMS[p][0]
    return len(dk) == 768 * k + 96 and H(dk[384 * k:768 * k + 32]) == dk[768 * k + 32:768 * k + 64]
def ct_check(p, c): return len(c) == SIZES[p][2]
