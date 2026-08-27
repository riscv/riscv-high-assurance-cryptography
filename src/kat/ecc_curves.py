"""Curve parameters and group arithmetic for the ACE elliptic-curve KAT harness.

This module is a *helper* for `ecc-kat.py`; it contains no ACE semantics, only
the mathematics the ACE unit is specified to perform, plus the RFC-published
domain parameters.  Everything here is checked by `ecc-kat.py` against published
vectors (or, for the Brainpool curves, against the curve equation and the group
order) before it is used, so a transcription error cannot pass silently.

Provenance of the domain parameters:

  * NIST P-256 / P-384 / P-521 -- SP 800-186 D.1.2 (identical to the values in
    RFC 6979 A.2.5-A.2.7, which this harness also re-derives the public keys
    from);
  * brainpoolP256r1 / P384r1 / P512r1 -- RFC 5639 section 3.4, 3.6, 3.7;
  * SM2 recommended curve -- GM/T 0003.5-2012 / GB/T 32918.5-2017 Appendix A
    (the "sm2p256v1" parameters);
  * Ed25519 / Ed448 -- RFC 8032 sections 5.1 and 5.2.

Weierstrass arithmetic uses Jacobian coordinates, Edwards arithmetic extended
(a.k.a. "twisted Edwards, extended homogeneous") coordinates, so that a scalar
multiplication needs a single modular inversion.  The formulae used are the
standard complete/unified ones; they are exercised by every KAT in the caller.
"""


# ---------------------------------------------------------------- Weierstrass

class Weierstrass:
    """y^2 = x^3 + a*x + b over GF(p), with base point G of prime order n.

    Points are affine `(x, y)` tuples, or `None` for the point at infinity.
    `bbits` is the ACE parameter `b` (the width of a field element *as
    represented in a CR*, which for secp521r1 is 576 rather than 521), and
    `msb_zero` the number of most significant bits the ACE representation
    requires to be zero.
    """

    edwards = False

    def __init__(self, name, p, a, b, gx, gy, n, h, bbits, msb_zero=0):
        self.name = name
        self.p, self.a, self.b = p, a % p, b % p
        self.G = (gx, gy)
        self.n, self.h = n, h
        self.bbits = bbits
        self.nbytes = bbits // 8
        self.msb_zero = msb_zero
        self.u = 2                     # a point is (X, Y)
        self.v = 2                     # a signature is (R, S)

    # -- field helpers ----------------------------------------------------
    def inv(self, x):
        return pow(x, -1, self.p)

    def is_on_curve(self, P):
        if P is None:
            return True
        x, y = P
        if not (0 <= x < self.p and 0 <= y < self.p):
            return False
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def in_subgroup(self, P):
        """Curve membership plus, when the cofactor is not 1, prime-order test."""
        if not self.is_on_curve(P):
            return False
        if P is None:
            return True
        return self.h == 1 or self.mul(self.n, P) is None

    # -- Jacobian arithmetic ---------------------------------------------
    def _dbl(self, J):
        X1, Y1, Z1 = J
        if Y1 == 0 or Z1 == 0:
            return (0, 1, 0)
        p = self.p
        YY = Y1 * Y1 % p
        S = 4 * X1 * YY % p
        M = (3 * X1 * X1 + self.a * pow(Z1, 4, p)) % p
        X3 = (M * M - 2 * S) % p
        Y3 = (M * (S - X3) - 8 * YY * YY) % p
        Z3 = 2 * Y1 * Z1 % p
        return (X3, Y3, Z3)

    def _add(self, J1, J2):
        X1, Y1, Z1 = J1
        X2, Y2, Z2 = J2
        if Z1 == 0:
            return J2
        if Z2 == 0:
            return J1
        p = self.p
        Z1Z1 = Z1 * Z1 % p
        Z2Z2 = Z2 * Z2 % p
        U1 = X1 * Z2Z2 % p
        U2 = X2 * Z1Z1 % p
        S1 = Y1 * Z2 * Z2Z2 % p
        S2 = Y2 * Z1 * Z1Z1 % p
        if U1 == U2:
            if S1 != S2:
                return (0, 1, 0)
            return self._dbl(J1)
        H = (U2 - U1) % p
        R = (S2 - S1) % p
        HH = H * H % p
        HHH = H * HH % p
        V = U1 * HH % p
        X3 = (R * R - HHH - 2 * V) % p
        Y3 = (R * (V - X3) - S1 * HHH) % p
        Z3 = H * Z1 * Z2 % p
        return (X3, Y3, Z3)

    def _to_affine(self, J):
        X, Y, Z = J
        if Z == 0:
            return None
        zi = self.inv(Z)
        zi2 = zi * zi % self.p
        return (X * zi2 % self.p, Y * zi2 % self.p * zi % self.p)

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        return self._to_affine(self._add((P[0], P[1], 1), (Q[0], Q[1], 1)))

    def mul(self, k, P):
        if P is None or k == 0:
            return None
        J = (0, 1, 0)
        Q = (P[0], P[1], 1)
        for bit in bin(k)[2:]:
            J = self._dbl(J)
            if bit == '1':
                J = self._add(J, Q)
        return self._to_affine(J)

    def mul_g(self, k):
        return self.mul(k, self.G)


# ---------------------------------------------------------------- Edwards

class Edwards:
    """a*x^2 + y^2 = 1 + d*x^2*y^2 over GF(p), base point B of order L."""

    edwards = True

    def __init__(self, name, p, a, d, L, By, bbits, cofactor, sqrt_mode):
        self.name = name
        self.p, self.a, self.d = p, a % p, d % p
        self.L = L
        self.n = L                     # ACE calls the group order n
        self.h = cofactor
        self.bbits = bbits
        self.nbytes = (bbits + 7) // 8
        self.msb_zero = 0
        self.u = 1                     # compressed point, one b-bit string
        self.v = 2
        self._sqrt_mode = sqrt_mode
        Bx = self.recover_x(By, 0)
        self.B = (Bx, By)
        self.G = self.B

    # -- field helpers ----------------------------------------------------
    def inv(self, x):
        return pow(x, -1, self.p)

    def _sqrt(self, u, v):
        """Return a square root of u/v, or None if none exists."""
        p = self.p
        if v == 0:
            return None
        x2 = u * self.inv(v) % p
        if self._sqrt_mode == '3mod4':
            x = pow(x2, (p + 1) // 4, p)
        else:                                     # p == 5 (mod 8), Ed25519
            x = pow(x2, (p + 3) // 8, p)
            if x * x % p != x2 % p:
                x = x * pow(2, (p - 1) // 4, p) % p
        if x * x % p != x2 % p:
            return None
        return x

    def recover_x(self, y, sign):
        """x from y and the sign bit, per RFC 8032 5.1.3 / 5.2.3."""
        p = self.p
        if y >= p:
            return None
        x = self._sqrt((y * y - 1) % p, (self.d * y * y - self.a) % p)
        if x is None:
            return None
        if x == 0 and sign:
            return None
        if x & 1 != sign:
            x = (p - x) % p
        return x

    def is_on_curve(self, P):
        if P is None:
            return True
        x, y = P
        return (self.a * x * x + y * y - 1 - self.d * x * x * y * y) % self.p == 0

    def in_subgroup(self, P):
        return self.is_on_curve(P)

    # -- extended coordinates (X : Y : Z : T), x = X/Z, y = Y/Z, T = XY/Z --
    def _ext(self, P):
        if P is None:
            return (0, 1, 1, 0)
        x, y = P
        return (x % self.p, y % self.p, 1, x * y % self.p)

    def _unext(self, Q):
        X, Y, Z, _ = Q
        zi = self.inv(Z)
        return (X * zi % self.p, Y * zi % self.p)

    def _eadd(self, P, Q):
        p, d, a = self.p, self.d, self.a
        X1, Y1, Z1, T1 = P
        X2, Y2, Z2, T2 = Q
        A = X1 * X2 % p
        B = Y1 * Y2 % p
        C = T1 * d * T2 % p
        D = Z1 * Z2 % p
        E = ((X1 + Y1) * (X2 + Y2) - A - B) % p
        F = (D - C) % p
        G = (D + C) % p
        H = (B - a * A) % p
        return (E * F % p, G * H % p, F * G % p, E * H % p)

    def add(self, P, Q):
        return self._unext(self._eadd(self._ext(P), self._ext(Q)))

    def mul(self, k, P):
        R = (0, 1, 1, 0)
        Q = self._ext(P)
        for bit in bin(k)[2:] if k else '':
            R = self._eadd(R, R)
            if bit == '1':
                R = self._eadd(R, Q)
        return self._unext(R)

    def mul_g(self, k):
        return self.mul(k, self.B)

    # -- RFC 8032 point encoding -----------------------------------------
    def encode(self, P):
        x, y = P
        v = y | ((x & 1) << (self.bbits - 1))
        return v.to_bytes(self.nbytes, 'little')

    def decode(self, data):
        """Return the point, or None if the encoding is invalid."""
        if len(data) != self.nbytes:
            return None
        v = int.from_bytes(data, 'little')
        sign = (v >> (self.bbits - 1)) & 1
        y = v & ((1 << (self.bbits - 1)) - 1)
        if y >= self.p:
            return None
        x = self.recover_x(y, sign)
        if x is None:
            return None
        return (x, y)


# ---------------------------------------------------------------- instances

P256 = Weierstrass(
    'secp256r1',
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    h=1, bbits=256)

P384 = Weierstrass(
    'secp384r1',
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    a=-3,
    b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    h=1, bbits=384)

# secp521r1: the *mathematical* field is 521 bits, but the ACE representation
# is 576 bits wide with the 55 most significant bits required to be zero
# (src/ace-ISA-algorithms.adoc, <<ACE-ECC>> "Parameters").
P521 = Weierstrass(
    'secp521r1',
    p=(1 << 521) - 1,
    a=-3,
    b=0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    gx=0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
    gy=0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
    n=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
    h=1, bbits=576, msb_zero=55)

BP256 = Weierstrass(
    'brainpoolP256r1',
    p=0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377,
    a=0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9,
    b=0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6,
    gx=0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262,
    gy=0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997,
    n=0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7,
    h=1, bbits=256)

BP384 = Weierstrass(
    'brainpoolP384r1',
    p=0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53,
    a=0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826,
    b=0x04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11,
    gx=0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E,
    gy=0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315,
    n=0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565,
    h=1, bbits=384)

BP512 = Weierstrass(
    'brainpoolP512r1',
    p=0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3,
    a=0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA,
    b=0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723,
    gx=0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822,
    gy=0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892,
    n=0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069,
    h=1, bbits=512)

SM2C = Weierstrass(
    'sm2p256v1',
    p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
    gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
    n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
    h=1, bbits=256)

_P25519 = (1 << 255) - 19
ED25519 = Edwards(
    'ed25519',
    p=_P25519,
    a=-1,
    d=-121665 * pow(121666, -1, _P25519),
    L=(1 << 252) + 27742317777372353535851937790883648493,
    By=4 * pow(5, -1, _P25519) % _P25519,
    bbits=256, cofactor=8, sqrt_mode='5mod8')

_P448 = (1 << 448) - (1 << 224) - 1
ED448 = Edwards(
    'ed448',
    p=_P448,
    a=1,
    d=-39081,
    L=(1 << 446) - 13818066809895115352007386748515426880336692474882178609894547503885,
    By=0x693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14,
    bbits=456, cofactor=4, sqrt_mode='3mod4')

WEIERSTRASS_CURVES = {c.name: c for c in (P256, P384, P521, BP256, BP384, BP512, SM2C)}
EDWARDS_CURVES = {c.name: c for c in (ED25519, ED448)}
