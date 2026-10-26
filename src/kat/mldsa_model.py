"""FIPS 204 (ML-DSA), written from the standard (Algorithms 6, 7, 8, 14-20, 22-37, 40-46).

Independent of src/kat/fips204.py.  The external message representative mu is an input
(Sign_internal / Verify_internal with mu supplied, as the KLE ML-DSA Machine does).

API
  PARAMS['ML-DSA-44'|'ML-DSA-65'|'ML-DSA-87']  -> dict k,l,eta,tau,beta,gamma1,gamma2,omega,lam,pk,sk,sig
  keygen_internal(ps, xi, lim=None) -> (pk, sk)
  sk_decode(ps, sk) -> (rho, K, tr, s1, s2, t0) ; None-safe check: sk_ok(ps, sk)
  pk_from_sk(ps, sk, lim=None) -> pk                       (steps 3,5,6,8 of Algorithm 6)
  sign_gen(ps, sk, mu, rnd, lim=None)  generator: yields the iteration count after every rejected
                                       iteration; returns (via StopIteration.value) the signature
  sign_internal(ps, sk, mu, rnd, lim=None) -> sig
  sign_iterations(ps, sk, mu, rnd) -> number of loop iterations used
  verify_internal(ps, pk, mu, sig, lim=None) -> bool
  hint_unpack(ps, y) -> list of hints or None (Algorithm 21)
  lim: dict with optional keys 'sign' (iterations), 'bounded' (bytes of XOF output of one RejBoundedPoly),
       'ntt' (bytes of one RejNTTPoly), 'ball' (bytes of one SampleInBall); exceeding raises LoopBound
Defaults: FIPS 204 Table 3 (814, 481, 894, 221).
"""
import hashlib

Q = 8380417
D = 13
N = 256
ZETA = 1753


class LoopBound(Exception):
    pass


DEFAULT_LIM = {'sign': 814, 'bounded': 481, 'ntt': 894, 'ball': 221}


def _P(k, l, eta, tau, gamma1, g2div, omega, lam, name):
    beta = tau * eta
    return dict(name=name, k=k, l=l, eta=eta, tau=tau, beta=beta, gamma1=gamma1, gamma2=(Q - 1) // g2div,
                omega=omega, lam=lam,
                pk=32 + 320 * k,
                sig=None)


PARAMS = {}
for _n, _a in (('ML-DSA-44', (4, 4, 2, 39, 1 << 17, 88, 80, 128)),
               ('ML-DSA-65', (6, 5, 4, 49, 1 << 19, 32, 55, 192)),
               ('ML-DSA-87', (8, 7, 2, 60, 1 << 19, 32, 75, 256))):
    _p = _P(*_a, _n)
    _eb = 3 if _p['eta'] == 2 else 4
    _p['etabits'] = _eb
    _p['sk'] = 32 + 32 + 64 + 32 * _eb * (_p['k'] + _p['l']) + 32 * 13 * _p['k']
    _p['z_bits'] = 18 if _p['gamma1'] == 1 << 17 else 20
    _p['sig'] = _p['lam'] // 4 + 32 * _p['l'] * _p['z_bits'] + _p['omega'] + _p['k']
    _p['w1bits'] = 6 if _p['gamma2'] == (Q - 1) // 88 else 4
    PARAMS[_n] = _p


# ---------------------------------------------------------------- XOF with counting
class XOF:
    def __init__(self, fn, data, limit=None):
        self.fn, self.data, self.buf, self.pos, self.limit = fn, data, b'', 0, limit

    def read(self, n):
        if self.limit is not None and self.pos + n > self.limit:
            raise LoopBound('XOF output limit')
        if self.pos + n > len(self.buf):
            self.buf = self.fn(self.data).digest(max(2 * len(self.buf), self.pos + n, 168))
        r = self.buf[self.pos:self.pos + n]
        self.pos += n
        return r


def H(data, n): return hashlib.shake_256(data).digest(n)


# ---------------------------------------------------------------- NTT
def _brv8(x): return int('{:08b}'.format(x)[::-1], 2)


ZETAS = [pow(ZETA, _brv8(i), Q) for i in range(256)]
INV256 = pow(256, Q - 2, Q)


def ntt(a):
    w = list(a)
    m, ln = 0, 128
    while ln >= 1:
        for start in range(0, 256, 2 * ln):
            m += 1
            z = ZETAS[m]
            for j in range(start, start + ln):
                t = z * w[j + ln] % Q
                w[j + ln] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
        ln //= 2
    return w


def intt(a):
    w = list(a)
    m, ln = 256, 1
    while ln < 256:
        for start in range(0, 256, 2 * ln):
            m -= 1
            z = -ZETAS[m]
            for j in range(start, start + ln):
                t = w[j]
                w[j] = (t + w[j + ln]) % Q
                w[j + ln] = z * (t - w[j + ln]) % Q
        ln *= 2
    return [x * INV256 % Q for x in w]


def padd(a, b): return [(x + y) % Q for x, y in zip(a, b)]
def psub(a, b): return [(x - y) % Q for x, y in zip(a, b)]
def pmul(a, b): return [x * y % Q for x, y in zip(a, b)]  # in the NTT domain


def mat_vec(A, vh, k, l):
    out = []
    for r in range(k):
        acc = [0] * N
        for s in range(l):
            acc = padd(acc, pmul(A[r][s], vh[s]))
        out.append(acc)
    return out


# ---------------------------------------------------------------- sampling
def rej_ntt_poly(seed, lim):
    g = XOF(hashlib.shake_128, seed, lim['ntt'])
    a = []
    while len(a) < N:
        b0, b1, b2 = g.read(3)
        z = ((b2 & 0x7F) << 16) | (b1 << 8) | b0
        if z < Q:
            a.append(z)
    return a


def rej_bounded_poly(ps, seed, lim):
    eta = ps['eta']
    g = XOF(hashlib.shake_256, seed, lim['bounded'])
    a = []

    def coeff(b):
        if eta == 2:
            return 2 - b % 5 if b < 15 else None
        return 4 - b if b < 9 else None
    while len(a) < N:
        z = g.read(1)[0]
        for h in (z & 15, z >> 4):
            c = coeff(h)
            if c is not None and len(a) < N:
                a.append(c % Q)
    return a


def expand_a(ps, rho, lim):
    return [[rej_ntt_poly(rho + bytes([s, r]), lim) for s in range(ps['l'])] for r in range(ps['k'])]


def expand_s(ps, rho2, lim):
    s1 = [rej_bounded_poly(ps, rho2 + r.to_bytes(2, 'little'), lim) for r in range(ps['l'])]
    s2 = [rej_bounded_poly(ps, rho2 + (r + ps['l']).to_bytes(2, 'little'), lim) for r in range(ps['k'])]
    return s1, s2


def expand_mask(ps, rho2, mu):
    out = []
    c = ps['z_bits']
    for r in range(ps['l']):
        v = H(rho2 + (mu + r).to_bytes(2, 'little'), 32 * c)
        out.append(bit_unpack(v, ps['gamma1'] - 1, ps['gamma1']))
    return out


def sample_in_ball(ps, rho, lim):
    g = XOF(hashlib.shake_256, rho, lim['ball'])
    s = g.read(8)
    hbits = int.from_bytes(s, 'little')
    c = [0] * N
    tau = ps['tau']
    for i in range(N - tau, N):
        j = g.read(1)[0]
        while j > i:
            j = g.read(1)[0]
        c[i] = c[j]
        c[j] = 1 - 2 * ((hbits >> (i + tau - N)) & 1)
    return [x % Q for x in c]


# ---------------------------------------------------------------- rounding
def modpm(r, m):
    r0 = r % m
    return r0 - m if r0 > m // 2 else r0


def power2round(r):
    rp = r % Q
    r0 = modpm(rp, 1 << D)
    return (rp - r0) >> D, r0


def decompose(ps, r):
    g2 = ps['gamma2']
    rp = r % Q
    r0 = modpm(rp, 2 * g2)
    if rp - r0 == Q - 1:
        return 0, r0 - 1
    return (rp - r0) // (2 * g2), r0


def high_bits(ps, r): return decompose(ps, r)[0]
def low_bits(ps, r): return decompose(ps, r)[1]


def make_hint(ps, z, r): return int(high_bits(ps, r) != high_bits(ps, r + z))


def use_hint(ps, h, r):
    m = (Q - 1) // (2 * ps['gamma2'])
    r1, r0 = decompose(ps, r)
    if h == 1:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1


def cnorm(x):
    x %= Q
    return Q - x if x > (Q - 1) // 2 else x   # |x| for the centred representative


# ---------------------------------------------------------------- encoding (little-endian bit packing)
def _pack(vals, bits):
    n = 0
    for i, v in enumerate(vals):
        n |= v << (i * bits)
    return n.to_bytes(len(vals) * bits // 8, 'little')


def _unpack(bs, bits):
    n = int.from_bytes(bs, 'little')
    return [(n >> (i * bits)) & ((1 << bits) - 1) for i in range(len(bs) * 8 // bits)]


def bitlen(x): return x.bit_length()


def bit_pack(w, a, b):
    return _pack([(b - x) for x in w], bitlen(a + b))


def bit_unpack(bs, a, b):
    return [(b - v) for v in _unpack(bs, bitlen(a + b))]


def hint_bit_pack(ps, h):
    om, k = ps['omega'], ps['k']
    y = bytearray(om + k)
    idx = 0
    for i in range(k):
        for j in range(N):
            if h[i][j]:
                y[idx] = j
                idx += 1
        y[om + i] = idx
    return bytes(y)


def hint_unpack(ps, y):
    om, k = ps['omega'], ps['k']
    h = [[0] * N for _ in range(k)]
    idx = 0
    for i in range(k):
        if y[om + i] < idx or y[om + i] > om:
            return None
        first = idx
        while idx < y[om + i]:
            if idx > first and y[idx - 1] >= y[idx]:
                return None
            h[i][y[idx]] = 1
            idx += 1
    for i in range(idx, om):
        if y[i] != 0:
            return None
    return h


def pk_encode(ps, rho, t1):
    return rho + b''.join(_pack(p, 10) for p in t1)


def pk_decode(ps, pk):
    rho = pk[:32]
    return rho, [_unpack(pk[32 + 320 * i:32 + 320 * (i + 1)], 10) for i in range(ps['k'])]


def sk_encode(ps, rho, K, tr, s1, s2, t0):
    eta = ps['eta']
    c = lambda p: [x - Q if x > Q // 2 else x for x in p]
    out = rho + K + tr
    for p in s1: out += bit_pack(c(p), eta, eta)
    for p in s2: out += bit_pack(c(p), eta, eta)
    for p in t0: out += bit_pack(c(p), (1 << (D - 1)) - 1, 1 << (D - 1))
    return out


def sk_decode_raw(ps, sk):
    """Algorithm 25 without a range check: returns (rho,K,tr,s1,s2,t0) with centred coefficients."""
    eta, k, l = ps['eta'], ps['k'], ps['l']
    rho, K, tr = sk[:32], sk[32:64], sk[64:128]
    ln = 32 * ps['etabits']
    o = 128
    s1 = [bit_unpack(sk[o + i * ln:o + (i + 1) * ln], eta, eta) for i in range(l)]
    o += l * ln
    s2 = [bit_unpack(sk[o + i * ln:o + (i + 1) * ln], eta, eta) for i in range(k)]
    o += k * ln
    t0 = [bit_unpack(sk[o + i * 416:o + (i + 1) * 416], (1 << (D - 1)) - 1, 1 << (D - 1)) for i in range(k)]
    return rho, K, tr, s1, s2, t0


def sk_ok(ps, sk):
    if len(sk) != ps['sk']:
        return False
    _, _, _, s1, s2, _ = sk_decode_raw(ps, sk)
    e = ps['eta']
    return all(-e <= x <= e for p in s1 + s2 for x in p)


def sk_decode(ps, sk):
    rho, K, tr, s1, s2, t0 = sk_decode_raw(ps, sk)
    m = lambda p: [x % Q for x in p]
    return rho, K, tr, [m(p) for p in s1], [m(p) for p in s2], [m(p) for p in t0]


def w1_encode(ps, w1):
    return b''.join(_pack(p, ps['w1bits']) for p in w1)


def sig_encode(ps, ct, z, h):
    g1 = ps['gamma1']
    c = lambda p: [x - Q if x > Q // 2 else x for x in p]
    return ct + b''.join(bit_pack(c(p), g1 - 1, g1) for p in z) + hint_bit_pack(ps, h)


def sig_decode(ps, sig):
    if len(sig) != ps['sig']:
        return None
    lam4 = ps['lam'] // 4
    zl = 32 * ps['z_bits']
    ct = sig[:lam4]
    z = [[x % Q for x in bit_unpack(sig[lam4 + i * zl:lam4 + (i + 1) * zl], ps['gamma1'] - 1, ps['gamma1'])]
         for i in range(ps['l'])]
    h = hint_unpack(ps, sig[lam4 + ps['l'] * zl:])
    if h is None:
        return None
    return ct, z, h


# ---------------------------------------------------------------- algorithms
def _lim(lim):
    d = dict(DEFAULT_LIM)
    if lim:
        d.update(lim)
    return d


def keygen_internal(ps, xi, lim=None):
    lim = _lim(lim)
    k, l = ps['k'], ps['l']
    e = H(xi + bytes([k, l]), 128)
    rho, rho2, K = e[:32], e[32:96], e[96:]
    A = expand_a(ps, rho, lim)
    s1, s2 = expand_s(ps, rho2, lim)
    s1h = [ntt(p) for p in s1]
    t = [padd(intt(a), b) for a, b in zip(mat_vec(A, s1h, k, l), s2)]
    t1, t0 = [], []
    for p in t:
        pr = [power2round(x) for x in p]
        t1.append([a for a, _ in pr])
        t0.append([b % Q for _, b in pr])
    pk = pk_encode(ps, rho, t1)
    tr = H(pk, 64)
    return pk, sk_encode(ps, rho, K, tr, s1, s2, t0)


def pk_from_sk(ps, sk, lim=None):
    """Steps 3,5,6,8 of Algorithm 6 on skDecode(sk); caller checks tr."""
    lim = _lim(lim)
    rho, K, tr, s1, s2, t0 = sk_decode(ps, sk)
    A = expand_a(ps, rho, lim)
    t = [padd(intt(a), b) for a, b in zip(mat_vec(A, [ntt(p) for p in s1], ps['k'], ps['l']), s2)]
    t1 = [[power2round(x)[0] for x in p] for p in t]
    return pk_encode(ps, rho, t1)


def sign_gen(ps, sk, mu, rnd, lim=None):
    lim = _lim(lim)
    k, l, g1, g2, beta, om = ps['k'], ps['l'], ps['gamma1'], ps['gamma2'], ps['beta'], ps['omega']
    rho, K, tr, s1, s2, t0 = sk_decode(ps, sk)
    s1h, s2h, t0h = [ntt(p) for p in s1], [ntt(p) for p in s2], [ntt(p) for p in t0]
    A = expand_a(ps, rho, lim)
    rho2 = H(K + rnd + mu, 64)
    kappa = 0
    it = 0
    while True:
        it += 1
        if it > lim['sign']:
            raise LoopBound('sign loop limit')
        y = expand_mask(ps, rho2, kappa)
        w = [intt(a) for a in mat_vec(A, [ntt(p) for p in y], k, l)]
        w1 = [[high_bits(ps, x) for x in p] for p in w]
        ct = H(mu + w1_encode(ps, w1), ps['lam'] // 4)
        c = sample_in_ball(ps, ct, lim)
        ch = ntt(c)
        cs1 = [intt(pmul(ch, p)) for p in s1h]
        cs2 = [intt(pmul(ch, p)) for p in s2h]
        z = [padd(a, b) for a, b in zip(y, cs1)]
        r0 = [[low_bits(ps, x) for x in psub(a, b)] for a, b in zip(w, cs2)]
        ok = (max(cnorm(x) for p in z for x in p) < g1 - beta and
              max(abs(x) for p in r0 for x in p) < g2 - beta)
        if ok:
            ct0 = [intt(pmul(ch, p)) for p in t0h]
            h = [[make_hint(ps, (-a) % Q, (b - c2 + a) % Q) for a, b, c2 in zip(p0, pw, p2)]
                 for p0, pw, p2 in zip(ct0, w, cs2)]
            if max(cnorm(x) for p in ct0 for x in p) < g2 and sum(map(sum, h)) <= om:
                return sig_encode(ps, ct, z, h)
        kappa += l
        yield it


def sign_internal(ps, sk, mu, rnd, lim=None):
    g = sign_gen(ps, sk, mu, rnd, lim)
    try:
        while True:
            next(g)
    except StopIteration as e:
        return e.value


def sign_iterations(ps, sk, mu, rnd):
    g = sign_gen(ps, sk, mu, rnd)
    n = 0
    try:
        while True:
            next(g)
            n += 1
    except StopIteration:
        return n + 1


def verify_internal(ps, pk, mu, sig, lim=None):
    lim = _lim(lim)
    if len(pk) != ps['pk']:
        return False
    k, l, g1, beta = ps['k'], ps['l'], ps['gamma1'], ps['beta']
    rho, t1 = pk_decode(ps, pk)
    d = sig_decode(ps, sig)
    if d is None:
        return False
    ct, z, h = d
    A = expand_a(ps, rho, lim)
    c = sample_in_ball(ps, ct, lim)
    ch = ntt(c)
    zh = [ntt(p) for p in z]
    Az = mat_vec(A, zh, k, l)
    wap = []
    for i in range(k):
        t1h = ntt([(x << D) % Q for x in t1[i]])
        wap.append(intt(psub(Az[i], pmul(ch, t1h))))
    w1 = [[use_hint(ps, h[i][j], wap[i][j]) for j in range(N)] for i in range(k)]
    ct2 = H(mu + w1_encode(ps, w1), ps['lam'] // 4)
    return max(cnorm(x) for p in z for x in p) < g1 - beta and ct == ct2
