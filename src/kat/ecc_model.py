"""ECC reference arithmetic for the new KAT (own code; parameters from OpenSSL, structure checked by the KAT).
Weierstrass (NIST/Brainpool/SM2), Edwards25519/448 (RFC 8032), Montgomery (RFC 7748), ECDSA (FIPS 186-5 6.4,
RFC 6979 k), SM2 (GM/T 0003.2).  Plain ints and bytes in the standards' own order; no KLE byte order here."""
import hashlib, hmac
ED448_BY = 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660  # B_y, RFC 8032 5.2 (checked: on curve, L*B = O)

WEI_PARAMS = {  # from `openssl ecparam -param_enc explicit` (OpenSSL 3.6.2); p, a, b, Gx, Gy, n (all cofactor 1)
    'secp256r1': (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff, 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc, 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
    'secp384r1': (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc, 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973),
    'secp521r1': (0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc, 0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409),
    'brainpoolP256r1': (0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377, 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9, 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6,
        0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262, 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997,
        0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7),
    'brainpoolP384r1': (0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53, 0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826, 0x4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11,
        0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e, 0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315,
        0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565),
    'brainpoolP512r1': (0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3, 0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca, 0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723,
        0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822, 0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892,
        0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069),
    'sm2': (0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff, 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc, 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93,
        0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7, 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0,
        0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123),
}

class Wei:
    def __init__(self, name):
        self.name = name
        self.p, self.a, self.b, gx, gy, self.n = WEI_PARAMS[name]
        self.G = (gx, gy)
        self.nbits = self.n.bit_length(); self.m = (self.p.bit_length() + 7) // 8
    def on_curve(self, P):
        if P is None: return False
        x, y = P
        return 0 <= x < self.p and 0 <= y < self.p and (y * y - x * x * x - self.a * x - self.b) % self.p == 0
    def add(self, P, Q):
        if P is None: return Q
        if Q is None: return P
        p = self.p
        if P[0] == Q[0]:
            if (P[1] + Q[1]) % p == 0: return None
            l = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], -1, p) % p
        else:
            l = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
        x = (l * l - P[0] - Q[0]) % p
        return (x, (l * (P[0] - x) - P[1]) % p)
    def mul(self, k, P):
        R = None
        for bit in bin(k)[2:] if k > 0 else '':
            R = self.add(R, R)
            if bit == '1': R = self.add(R, P)
        return R
    def neg(self, P): return None if P is None else (P[0], (-P[1]) % self.p)

def rfc6979_k(c, d, e_digest, hname):
    """RFC 6979 3.2 with qlen = bitlen(n); e_digest = the hash output bytes."""
    n = c.n; qlen = n.bit_length(); rolen = (qlen + 7) // 8
    def b2i(bs):
        v = int.from_bytes(bs, 'big')
        return v >> (8 * len(bs) - qlen) if 8 * len(bs) > qlen else v
    def i2o(v): return v.to_bytes(rolen, 'big')
    def b2o(bs): return i2o(b2i(bs) % n)
    hl = hashlib.new(hname).digest_size
    V = b'\x01' * hl; K = b'\x00' * hl
    H = lambda k, m: hmac.new(k, m, hname).digest()
    x = i2o(d); h1 = b2o(e_digest)
    K = H(K, V + b'\x00' + x + h1); V = H(K, V)
    K = H(K, V + b'\x01' + x + h1); V = H(K, V)
    while True:
        T = b''
        while len(T) * 8 < qlen: V = H(K, V); T += V
        k = b2i(T)
        if 1 <= k < n: return k
        K = H(K, V + b'\x00'); V = H(K, V)

def ecdsa_sign(c, d, e, k):
    """FIPS 186-5 6.4.1 with the nonce k given; e = integer of the (truncated) digest.  None if r = 0 or s = 0."""
    R = c.mul(k, c.G); r = R[0] % c.n
    if r == 0: return None
    s = pow(k, -1, c.n) * (e + r * d) % c.n
    return None if s == 0 else (r, s)

def ecdsa_verify(c, Q, e, rs):
    r, s = rs; n = c.n
    if not (1 <= r < n and 1 <= s < n): return False
    if not c.on_curve(Q) or c.mul(n, Q) is not None: return False
    w = pow(s, -1, n)
    X = c.add(c.mul(e % n * w % n, c.G), c.mul(r * w % n, Q))
    return X is not None and X[0] % n == r

def sm2_sign(c, d, e, k):
    """GM/T 0003.2 6.1 (k given); None if the retry rule fires (r = 0, r + k = n or s = 0)."""
    n = c.n
    x1 = c.mul(k, c.G)[0]; r = (e + x1) % n
    if r == 0 or r + k == n: return None
    s = pow(1 + d, -1, n) * (k - r * d) % n
    return None if s == 0 else (r, s)

def sm2_verify(c, Q, e, rs):
    r, s = rs; n = c.n
    if not (1 <= r < n and 1 <= s < n): return False
    if not c.on_curve(Q): return False
    t = (r + s) % n
    if t == 0: return False
    X = c.add(c.mul(s, c.G), c.mul(t, Q))
    return X is not None and (e + X[0]) % n == r

def sm2_za(c, ident, Q):
    f = lambda v: v.to_bytes(32, 'big')
    ent = (8 * len(ident)).to_bytes(2, 'big')
    return hashlib.new('sm3', ent + ident + f(c.a) + f(c.b) + f(c.G[0]) + f(c.G[1]) + f(Q[0]) + f(Q[1])).digest()

# ---------------------------------------------------------------- Edwards (RFC 8032), affine, complete formulas
class Ed:
    def __init__(self, name):
        self.name = name
        if name == 'ed25519':
            self.p = 2**255 - 19; self.d = -121665 * pow(121666, -1, self.p) % self.p; self.bits = 256; self.c = 3
            self.L = 2**252 + 27742317777372353535851937790883648493
            self.by = 4 * pow(5, -1, self.p) % self.p
        else:
            self.p = 2**448 - 2**224 - 1; self.d = (-39081) % self.p; self.bits = 456; self.c = 2
            self.L = 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
            self.by = ED448_BY
        self.nb = self.bits // 8
        self.B = (self.recover_x(self.by, 0), self.by)
    def recover_x(self, y, sign):
        p, d = self.p, self.d
        if y >= p: return None
        x2 = (y * y - 1) * pow(d * y * y + (1 if self.name == 'ed25519' else -1), -1, p) % p
        if x2 == 0: return None if sign else 0
        if p % 4 == 3: x = pow(x2, (p + 1) // 4, p)
        else:
            x = pow(x2, (p + 3) // 8, p)
            if (x * x - x2) % p: x = x * pow(2, (p - 1) // 4, p) % p
        if (x * x - x2) % p: return None
        return x if x & 1 == sign else p - x
    def on_curve(self, P):
        x, y = P; p = self.p
        a = -1 if self.name == 'ed25519' else 1
        return (a * x * x + y * y - 1 - self.d * x * x * y * y) % p == 0
    def add(self, P, Q):
        p, d = self.p, self.d; x1, y1 = P; x2, y2 = Q
        t = d * x1 * x2 * y1 * y2 % p
        a = -1 if self.name == 'ed25519' else 1
        x3 = (x1 * y2 + x2 * y1) * pow(1 + t, -1, p) % p
        y3 = (y1 * y2 - a * x1 * x2) * pow(1 - t, -1, p) % p
        return (x3, y3)
    def mul(self, k, P):
        R = (0, 1)
        for bit in bin(k)[2:] if k > 0 else '':
            R = self.add(R, R)
            if bit == '1': R = self.add(R, P)
        return R
    def enc(self, P): return (P[1] | ((P[0] & 1) << (self.bits - 1))).to_bytes(self.nb, 'little')
    def dec(self, s):
        if len(s) != self.nb: return None
        v = int.from_bytes(s, 'little'); sign = v >> (self.bits - 1); y = v & ((1 << (self.bits - 1)) - 1)
        x = self.recover_x(y, sign)
        return None if x is None else (x, y)
    # hashing
    def H(self, m):
        return hashlib.sha512(m).digest() if self.name == 'ed25519' else hashlib.shake_256(m).digest(114)
    def dom(self, x, ctx):
        if self.name == 'ed25519':
            return b'' if (x == 0 and not ctx) else b'SigEd25519 no Ed25519 collisions' + bytes([x, len(ctx)]) + ctx
        return b'SigEd448' + bytes([x, len(ctx)]) + ctx
    def expand(self, seed):
        h = self.H(seed); n = self.nb
        a = bytearray(h[:n])
        if self.name == 'ed25519': a[0] &= 248; a[31] &= 127; a[31] |= 64
        else: a[0] &= 252; a[55] |= 128; a[56] = 0
        return int.from_bytes(a, 'little'), h[n:2 * n]
    def pub(self, seed): return self.enc(self.mul(self.expand(seed)[0], self.B))
    def sign(self, seed, M, x=0, ctx=b''):
        """M = the message (x = 0) or PH(M) (x = 1)."""
        s, prefix = self.expand(seed); A = self.enc(self.mul(s, self.B)); dom = self.dom(x, ctx)
        r = int.from_bytes(self.H(dom + prefix + M), 'little') % self.L
        R = self.enc(self.mul(r, self.B))
        k = int.from_bytes(self.H(dom + R + A + M), 'little') % self.L
        return R + ((r + k * s) % self.L).to_bytes(self.nb, 'little')
    def verify(self, A, M, sig, x=0, ctx=b''):
        nb = self.nb
        if len(sig) != 2 * nb: return False
        Ap = self.dec(A); Rp = self.dec(sig[:nb]); S = int.from_bytes(sig[nb:], 'little')
        if Ap is None or Rp is None or S >= self.L: return False
        k = int.from_bytes(self.H(self.dom(x, ctx) + sig[:nb] + A + M), 'little') % self.L
        c = 1 << self.c
        lhs = self.mul(c * S, self.B); rhs = self.add(self.mul(c, Rp), self.mul(c * k % (c * self.L), Ap))
        return lhs == rhs

# ---------------------------------------------------------------- Montgomery (RFC 7748)
MONT = {'x25519': (2**255 - 19, 121665, 255, 32, 9), 'x448': (2**448 - 2**224 - 1, 39081, 448, 56, 5)}
def clamp(name, k):
    k = bytearray(k)
    if name == 'x25519': k[0] &= 248; k[31] &= 127; k[31] |= 64
    else: k[0] &= 252; k[55] |= 128
    return int.from_bytes(k, 'little')
def x_mul(name, kb, ub):
    """RFC 7748 5: kb, ub byte strings (LE); returns bytes.  Bit 255 of u is masked for x25519; u reduced mod p."""
    p, a24, bits, nb, _ = MONT[name]
    k = clamp(name, kb); u = int.from_bytes(ub, 'little')
    if name == 'x25519': u &= (1 << 255) - 1
    u %= p
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(bits - 1, -1, -1):
        kt = (k >> t) & 1; swap ^= kt
        if swap: x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        A = (x2 + z2) % p; AA = A * A % p; B = (x2 - z2) % p; BB = B * B % p; E = (AA - BB) % p
        C = (x3 + z3) % p; D = (x3 - z3) % p; DA = D * A % p; CB = C * B % p
        x3 = (DA + CB) ** 2 % p; z3 = x1 * (DA - CB) ** 2 % p
        x2 = AA * BB % p; z2 = E * (AA + a24 * E) % p
    if swap: x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(nb, 'little')
