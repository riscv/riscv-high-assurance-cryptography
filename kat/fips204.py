"""FIPS 204 (ML-DSA) -- complete reference implementation, stdlib only.

NTT over Z_8380417, ExpandA / ExpandS / ExpandMask, SampleInBall,
Power2Round / Decompose / HighBits / LowBits / MakeHint / UseHint, the
SimpleBitPack / BitPack / HintBitPack encodings and pkEncode / skEncode /
sigEncode / w1Encode, and Algorithms 6, 7 and 8 (KeyGen_internal,
Sign_internal, Verify_internal) for ML-DSA-44/65/87.

Because the ACE unit signs over an *externally* computed message representative
mu = SHAKE256(tr || M', 64), the signing and verification entry points are
offered in both flavours: `sign_internal(sk, Mp, rnd)` / `verify_internal(pk,
Mp, sig)` take the formatted message M', while `sign_internal_mu(sk, mu, rnd)` /
`verify_internal_mu(pk, mu, sig)` take mu directly, which is what
[[ACE-PQC-ML-DSA]] specifies.

Anchored by kat/mldsa-kat.py against official NIST ACVP vectors; this module
holds no vectors of its own.
"""

import hashlib

Q = 8380417
N = 256
D = 13
ZETA = 1753

# tau, lambda, gamma1, gamma2, k, l, eta, beta, omega
PARAMS = {
    44: dict(tau=39, lam=128, gamma1=1 << 17, gamma2=(Q - 1) // 88,
             k=4, l=4, eta=2, beta=39 * 2, omega=80),
    65: dict(tau=49, lam=192, gamma1=1 << 19, gamma2=(Q - 1) // 32,
             k=6, l=5, eta=4, beta=49 * 4, omega=55),
    87: dict(tau=60, lam=256, gamma1=1 << 19, gamma2=(Q - 1) // 32,
             k=8, l=7, eta=2, beta=60 * 2, omega=75),
}

def _brv8(x):
    return int(f'{x:08b}'[::-1], 2)

_ZETAS = [pow(ZETA, _brv8(i), Q) for i in range(256)]

def H(data, outlen):
    return hashlib.shake_256(data).digest(outlen)

def bitlen(x):
    return x.bit_length()

def mod_pm(r, a):
    """r mod+- a, i.e. the representative in (-a/2, a/2]."""
    r %= a
    return r - a if r > a // 2 else r

def inf_norm(polys):
    return max((abs(mod_pm(c, Q)) for p in polys for c in p), default=0)

# ---------------------------------------------------------------- NTT (Alg. 41/42)

def ntt(w):
    w = list(w)
    k = 0
    length = 128
    while length >= 1:
        start = 0
        while start < 256:
            k += 1
            z = _ZETAS[k]
            for j in range(start, start + length):
                t = z * w[j + length] % Q
                w[j + length] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
            start += 2 * length
        length //= 2
    return w

def intt(w):
    w = list(w)
    k = 256
    length = 1
    while length < 256:
        start = 0
        while start < 256:
            k -= 1
            z = (-_ZETAS[k]) % Q
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % Q
                w[j + length] = z * (t - w[j + length]) % Q
            start += 2 * length
        length *= 2
    f = 8347681                      # 256^-1 mod q
    return [x * f % Q for x in w]

def pmul(a, b):
    return [x * y % Q for x, y in zip(a, b)]

def padd(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]

def psub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]

def vadd(u, v):
    return [padd(a, b) for a, b in zip(u, v)]

def vsub(u, v):
    return [psub(a, b) for a, b in zip(u, v)]

def matvec(A, v):
    """A (k x l) times v (l), all in the NTT domain."""
    out = []
    for row in A:
        acc = [0] * 256
        for a, b in zip(row, v):
            acc = padd(acc, pmul(a, b))
        out.append(acc)
    return out

# ---------------------------------------------------------------- rounding (Alg. 35-40)

def power2round(r):
    r = r % Q
    r0 = mod_pm(r, 1 << D)
    return (r - r0) >> D, r0

def decompose(r, gamma2):
    r = r % Q
    r0 = mod_pm(r, 2 * gamma2)
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * gamma2), r0

def high_bits(r, gamma2):
    return decompose(r, gamma2)[0]

def low_bits(r, gamma2):
    return decompose(r, gamma2)[1]

def make_hint(z, r, gamma2):
    return int(high_bits(r, gamma2) != high_bits((r + z) % Q, gamma2))

def use_hint(h, r, gamma2):
    m = (Q - 1) // (2 * gamma2)
    r1, r0 = decompose(r, gamma2)
    if h == 1:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1

# ---------------------------------------------------------------- bit packing (Alg. 16-21)

def _pack(vals, c, nbytes):
    v = 0
    for i, a in enumerate(vals):
        v |= (a & ((1 << c) - 1)) << (c * i)
    return v.to_bytes(nbytes, 'little')

def _unpack(b, c):
    v = int.from_bytes(b, 'little')
    m = (1 << c) - 1
    return [(v >> (c * i)) & m for i in range(256)]

def simple_bit_pack(w, b):
    c = bitlen(b)
    return _pack(w, c, 32 * c)

def simple_bit_unpack(v, b):
    return _unpack(v, bitlen(b))

def bit_pack(w, a, b):
    c = bitlen(a + b)
    return _pack([(b - x) % Q if x > b else b - x for x in w], c, 32 * c)

def bit_unpack(v, a, b):
    c = bitlen(a + b)
    return [(b - z) % Q for z in _unpack(v, c)]

def hint_bit_pack(h, omega, k):
    y = bytearray(omega + k)
    idx = 0
    for i in range(k):
        for j in range(256):
            if h[i][j] != 0:
                y[idx] = j
                idx += 1
        y[omega + i] = idx
    return bytes(y)

def hint_bit_unpack(y, omega, k):
    """Algorithm 21.  Returns None for a malformed hint (this is the check that
    bounds the hint weight by omega and enforces strictly increasing indices)."""
    h = [[0] * 256 for _ in range(k)]
    index = 0
    for i in range(k):
        if y[omega + i] < index or y[omega + i] > omega:
            return None
        first = index
        while index < y[omega + i]:
            if index > first and y[index - 1] >= y[index]:
                return None
            h[i][y[index]] = 1
            index += 1
    for i in range(index, omega):
        if y[i] != 0:
            return None
    return h

# ---------------------------------------------------------------- key/sig encoding (Alg. 22-28)

def pk_encode(rho, t1, ps):
    bound = (1 << (bitlen(Q - 1) - D)) - 1
    return rho + b''.join(simple_bit_pack(p, bound) for p in t1)

def pk_decode(pk, ps):
    p = PARAMS[ps]
    bound = (1 << (bitlen(Q - 1) - D)) - 1
    c = bitlen(bound)
    rho = pk[:32]
    t1 = [simple_bit_unpack(pk[32 + 32 * c * i: 32 + 32 * c * (i + 1)], bound)
          for i in range(p['k'])]
    return rho, t1

def sk_encode(rho, Kk, tr, s1, s2, t0, ps):
    p = PARAMS[ps]
    eta = p['eta']
    out = rho + Kk + tr
    out += b''.join(bit_pack(x, eta, eta) for x in s1)
    out += b''.join(bit_pack(x, eta, eta) for x in s2)
    out += b''.join(bit_pack(x, (1 << (D - 1)) - 1, 1 << (D - 1)) for x in t0)
    return out

def sk_decode(sk, ps):
    p = PARAMS[ps]
    eta, k, l = p['eta'], p['k'], p['l']
    ce = bitlen(2 * eta)
    rho, Kk, tr = sk[:32], sk[32:64], sk[64:128]
    off = 128
    s1 = []
    for _ in range(l):
        s1.append(bit_unpack(sk[off:off + 32 * ce], eta, eta)); off += 32 * ce
    s2 = []
    for _ in range(k):
        s2.append(bit_unpack(sk[off:off + 32 * ce], eta, eta)); off += 32 * ce
    t0 = []
    for _ in range(k):
        t0.append(bit_unpack(sk[off:off + 416], (1 << (D - 1)) - 1, 1 << (D - 1)))
        off += 416
    return rho, Kk, tr, s1, s2, t0

def sig_encode(c_tilde, z, h, ps):
    p = PARAMS[ps]
    g1 = p['gamma1']
    out = c_tilde + b''.join(bit_pack(x, g1 - 1, g1) for x in z)
    return out + hint_bit_pack(h, p['omega'], p['k'])

def sig_decode(sig, ps):
    p = PARAMS[ps]
    g1, k, l, omega = p['gamma1'], p['k'], p['l'], p['omega']
    cl = p['lam'] // 4
    c = bitlen(2 * g1 - 1)
    c_tilde = sig[:cl]
    off = cl
    z = []
    for _ in range(l):
        z.append(bit_unpack(sig[off:off + 32 * c], g1 - 1, g1)); off += 32 * c
    h = hint_bit_unpack(sig[off:off + omega + k], omega, k)
    return c_tilde, z, h

def w1_encode(w1, ps):
    p = PARAMS[ps]
    b = (Q - 1) // (2 * p['gamma2']) - 1
    return b''.join(simple_bit_pack(x, b) for x in w1)

# ---------------------------------------------------------------- sampling (Alg. 29-34)

def sample_in_ball(c_tilde, ps):
    tau = PARAMS[ps]['tau']
    c = [0] * 256
    xof = hashlib.shake_256(c_tilde)
    stream = xof.digest(8 + 1024)
    s, pos = stream[:8], 8
    bits = [(s[i // 8] >> (i % 8)) & 1 for i in range(64)]
    for i in range(256 - tau, 256):
        while True:
            if pos >= len(stream):
                stream = xof.digest(len(stream) + 1024)
            j = stream[pos]; pos += 1
            if j <= i:
                break
        c[i] = c[j]
        c[j] = (Q - 1) if bits[i + tau - 256] else 1
    return c

def _coeff_from_three_bytes(b0, b1, b2):
    z = ((b2 & 0x7F) << 16) | (b1 << 8) | b0
    return z if z < Q else None

def rej_ntt_poly(seed):
    a = []
    xof = hashlib.shake_128(seed)
    buf = xof.digest(3 * 256 + 168)
    pos = 0
    while len(a) < 256:
        if pos + 3 > len(buf):
            buf = xof.digest(len(buf) + 168)
        z = _coeff_from_three_bytes(buf[pos], buf[pos + 1], buf[pos + 2])
        pos += 3
        if z is not None:
            a.append(z)
    return a

def _coeff_from_half_byte(b, eta):
    if eta == 2 and b < 15:
        return 2 - (b % 5)
    if eta == 4 and b < 9:
        return 4 - b
    return None

def rej_bounded_poly(seed, eta):
    a = []
    xof = hashlib.shake_256(seed)
    buf = xof.digest(136 * 4)
    pos = 0
    while len(a) < 256:
        if pos >= len(buf):
            buf = xof.digest(len(buf) + 136)
        z0 = _coeff_from_half_byte(buf[pos] & 0x0F, eta)
        z1 = _coeff_from_half_byte(buf[pos] >> 4, eta)
        pos += 1
        if z0 is not None:
            a.append(z0 % Q)
        if z1 is not None and len(a) < 256:
            a.append(z1 % Q)
    return a

def expand_A(rho, ps):
    p = PARAMS[ps]
    return [[rej_ntt_poly(rho + bytes([s, r])) for s in range(p['l'])]
            for r in range(p['k'])]

def expand_S(rhop, ps):
    p = PARAMS[ps]
    eta, k, l = p['eta'], p['k'], p['l']
    s1 = [rej_bounded_poly(rhop + (i).to_bytes(2, 'little'), eta) for i in range(l)]
    s2 = [rej_bounded_poly(rhop + (i + l).to_bytes(2, 'little'), eta) for i in range(k)]
    return s1, s2

def expand_mask(rho, mu, ps):
    p = PARAMS[ps]
    g1, l = p['gamma1'], p['l']
    c = 1 + bitlen(g1 - 1)
    out = []
    for r in range(l):
        v = H(rho + (mu + r).to_bytes(2, 'little'), 32 * c)
        out.append(bit_unpack(v, g1 - 1, g1))
    return out

# ---------------------------------------------------------------- sizes

def sizes(ps):
    """(sk, pk, sig) sizes in bytes, per FIPS 204 Table 2."""
    p = PARAMS[ps]
    k, l, eta, g1, omega = p['k'], p['l'], p['eta'], p['gamma1'], p['omega']
    pk = 32 + 32 * k * (bitlen(Q - 1) - D)
    sk = 128 + 32 * ((k + l) * bitlen(2 * eta) + 13 * k)
    sig = p['lam'] // 4 + 32 * l * (1 + bitlen(g1 - 1)) + omega + k
    return sk, pk, sig

# ---------------------------------------------------------------- ML-DSA (Alg. 6-8)

def keygen_internal(xi, ps):
    p = PARAMS[ps]
    k, l = p['k'], p['l']
    seed = H(xi + bytes([k, l]), 128)
    rho, rhop, Kk = seed[:32], seed[32:96], seed[96:128]
    A = expand_A(rho, ps)
    s1, s2 = expand_S(rhop, ps)
    t = vadd([intt(x) for x in matvec(A, [ntt(x) for x in s1])], s2)
    t1, t0 = [], []
    for poly in t:
        a, b = zip(*(power2round(c) for c in poly))
        t1.append(list(a)); t0.append([x % Q for x in b])
    pk = pk_encode(rho, t1, ps)
    tr = H(pk, 64)
    sk = sk_encode(rho, Kk, tr, s1, s2, t0, ps)
    return pk, sk

def compute_pubkey(sk, ps):
    """FIPS 204 3.6 / Algorithm 6: re-derive pk from sk, and re-derive tr.

    Returns (pk, tr_from_pk, tr_in_sk); the ACE _compute_pubKey_ state requires
    tr_from_pk == tr_in_sk (see [[ACE-PQC-ML-DSA]])."""
    p = PARAMS[ps]
    rho, Kk, tr_sk, s1, s2, t0 = sk_decode(sk, ps)
    A = expand_A(rho, ps)
    t = vadd([intt(x) for x in matvec(A, [ntt(x) for x in s1])], s2)
    t1 = [[power2round(c)[0] for c in poly] for poly in t]
    pk = pk_encode(rho, t1, ps)
    return pk, H(pk, 64), tr_sk

def sign_internal_mu(sk, mu, rnd, ps, max_iters=1000):
    """ML-DSA.Sign_internal (Algorithm 7) with mu supplied externally, which is
    what the ACE _Sign_Generate_ state does."""
    p = PARAMS[ps]
    k, l = p['k'], p['l']
    g1, g2, beta, omega, tau = p['gamma1'], p['gamma2'], p['beta'], p['omega'], p['tau']
    rho, Kk, tr, s1, s2, t0 = sk_decode(sk, ps)
    s1h = [ntt(x) for x in s1]
    s2h = [ntt(x) for x in s2]
    t0h = [ntt(x) for x in t0]
    A = expand_A(rho, ps)
    rhopp = H(Kk + rnd + mu, 64)
    kappa = 0
    for _ in range(max_iters):
        y = expand_mask(rhopp, kappa, ps)
        w = [intt(x) for x in matvec(A, [ntt(t) for t in y])]
        w1 = [[high_bits(c, g2) for c in poly] for poly in w]
        c_tilde = H(mu + w1_encode(w1, ps), p['lam'] // 4)
        ch = ntt(sample_in_ball(c_tilde, ps))
        cs1 = [intt(pmul(ch, x)) for x in s1h]
        cs2 = [intt(pmul(ch, x)) for x in s2h]
        z = vadd(y, cs1)
        r0 = [[low_bits(c, g2) for c in poly] for poly in vsub(w, cs2)]
        kappa += l
        if inf_norm(z) >= g1 - beta or max(abs(c) for poly in r0 for c in poly) >= g2 - beta:
            continue
        ct0 = [intt(pmul(ch, x)) for x in t0h]
        wm = vadd(vsub(w, cs2), ct0)
        h = [[make_hint((-ct0[i][j]) % Q, wm[i][j], g2) for j in range(256)]
             for i in range(k)]
        if inf_norm(ct0) >= g2 or sum(sum(row) for row in h) > omega:
            continue
        zc = [[mod_pm(c, Q) % Q for c in poly] for poly in z]
        return sig_encode(c_tilde, zc, h, ps)
    return None

def sign_internal(sk, Mp, rnd, ps):
    tr = sk[64:128]
    return sign_internal_mu(sk, H(tr + Mp, 64), rnd, ps)

def verify_internal_mu(pk, mu, sig, ps):
    """ML-DSA.Verify_internal (Algorithm 8) with mu supplied externally."""
    p = PARAMS[ps]
    g1, g2, beta, k = p['gamma1'], p['gamma2'], p['beta'], p['k']
    if len(sig) != sizes(ps)[2] or len(pk) != sizes(ps)[1]:
        return False
    rho, t1 = pk_decode(pk, ps)
    c_tilde, z, h = sig_decode(sig, ps)
    if h is None:
        return False
    A = expand_A(rho, ps)
    c = sample_in_ball(c_tilde, ps)
    t1s = [[(x << D) % Q for x in poly] for poly in t1]
    az = matvec(A, [ntt(x) for x in z])
    ct = [pmul(ntt(c), ntt(x)) for x in t1s]
    wapp = [intt(psub(a, b)) for a, b in zip(az, ct)]
    w1 = [[use_hint(h[i][j], wapp[i][j], g2) for j in range(256)] for i in range(k)]
    ct2 = H(mu + w1_encode(w1, ps), p['lam'] // 4)
    return inf_norm(z) < g1 - beta and c_tilde == ct2

def verify_internal(pk, Mp, sig, ps):
    tr = H(pk, 64)
    return verify_internal_mu(pk, H(tr + Mp, 64), sig, ps)

def mu_external(tr, Mp):
    """The ACE external-mu convention: mu = SHAKE256(tr @ M', 64)."""
    return H(tr + Mp, 64)

def format_Mp(ctx, M, prehash=False, oid=b''):
    """M' = 0x00 @ bin(|ctx|,8) @ ctx @ M   (pure ML-DSA, FIPS 204 sect. 5.2)."""
    assert len(ctx) <= 255
    return bytes([1 if prehash else 0, len(ctx)]) + ctx + oid + M
