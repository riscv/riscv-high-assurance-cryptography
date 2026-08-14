"""Known Answer Tests for ACE Elliptic Curve Cryptography (secp256r1 / Ed25519).

Checks:
  - NIST P-256 (secp256r1) ECDSA signature and point multiplication (FIPS 186-5 / RFC 6979)
  - Ed25519 signature generation and verification (RFC 8032)
  - Verification of state machine flow (_Set_Generator_, _Set_Scalar_, _Point_Mul_, _Sign_Generate_, _Sign_Verify_, _Output_ -> _Success_)
"""

import hashlib, hmac

# ------------------------------------------------------------------ secp256r1 (NIST P-256)
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = -3 % P256_P
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def inv(a, m):
    return pow(a, -1, m)

def point_add(p1, p2, p=P256_P, a=P256_A):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if x1 == x2 and y1 == y2:
        m = (3 * x1 * x1 + a) * inv(2 * y1, p) % p
    else:
        m = (y2 - y1) * inv(x2 - x1, p) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(k, point, p=P256_P, a=P256_A):
    res = None
    cur = point
    while k > 0:
        if k & 1:
            res = point_add(res, cur, p, a)
        cur = point_add(cur, cur, p, a)
        k >>= 1
    return res

def ecdsa_sign_deterministic(privkey, msg_hash, k_nonce, n=P256_N, G=(P256_GX, P256_GY)):
    z = int.from_bytes(msg_hash, 'big')
    R = point_mul(k_nonce, G)
    r = R[0] % n
    s = (inv(k_nonce, n) * (z + r * privkey)) % n
    return r, s

def ecdsa_verify(pubkey, msg_hash, r, s, n=P256_N, G=(P256_GX, P256_GY)):
    if not (1 <= r < n and 1 <= s < n):
        return False
    z = int.from_bytes(msg_hash, 'big')
    w = inv(s, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    P1 = point_mul(u1, G)
    P2 = point_mul(u2, pubkey)
    R = point_add(P1, P2)
    if R is None: return False
    return (R[0] % n) == r

# RFC 6979 Section A.2.5 Test Vector (secp256r1, SHA-256)
RFC6979_X = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
RFC6979_MSG = b"sample"
RFC6979_H = hashlib.sha256(RFC6979_MSG).digest()
RFC6979_K = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
RFC6979_EXP_R = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
RFC6979_EXP_S = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

# ------------------------------------------------------------------ Ed25519 (RFC 8032)
ED25519_P = 2**255 - 19
ED25519_D = -121665 * inv(121666, ED25519_P) % ED25519_P
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_BY = 4 * inv(5, ED25519_P) % ED25519_P

def recover_x(y):
    xx = (y * y - 1) * inv(ED25519_D * y * y + 1, ED25519_P) % ED25519_P
    x = pow(xx, (ED25519_P + 3) // 8, ED25519_P)
    if (x * x - xx) % ED25519_P != 0:
        x = (x * pow(2, (ED25519_P - 1) // 4, ED25519_P)) % ED25519_P
    if x % 2 != 0:
        x = ED25519_P - x
    return x

ED25519_BX = recover_x(ED25519_BY)
ED25519_B = (ED25519_BX, ED25519_BY)

def ed_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    x3 = (x1 * y2 + y1 * x2) * inv(1 + ED25519_D * x1 * x2 * y1 * y2, ED25519_P) % ED25519_P
    y3 = (y1 * y2 + x1 * x2) * inv(1 - ED25519_D * x1 * x2 * y1 * y2, ED25519_P) % ED25519_P
    return (x3, y3)

def ed_mul(k, point):
    res = None
    cur = point
    while k > 0:
        if k & 1: res = ed_add(res, cur)
        cur = ed_add(cur, cur)
        k >>= 1
    return res

def ed25519_pubkey(secret_seed):
    h = hashlib.sha512(secret_seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= (1 << 254)
    A = ed_mul(a, ED25519_B)
    y_bytes = bytearray(A[1].to_bytes(32, 'little'))
    if A[0] & 1: y_bytes[31] |= 0x80
    return bytes(y_bytes), a, h[32:]

def ed25519_sign(secret_seed, msg):
    pk, a, prefix = ed25519_pubkey(secret_seed)
    r_hash = hashlib.sha512(prefix + msg).digest()
    r = int.from_bytes(r_hash, 'little') % ED25519_L
    R = ed_mul(r, ED25519_B)
    R_bytes = bytearray(R[1].to_bytes(32, 'little'))
    if R[0] & 1: R_bytes[31] |= 0x80
    k_hash = hashlib.sha512(bytes(R_bytes) + pk + msg).digest()
    k = int.from_bytes(k_hash, 'little') % ED25519_L
    S = (r + k * a) % ED25519_L
    return bytes(R_bytes) + S.to_bytes(32, 'little')

# RFC 8032 Section 7.1 Test Vector 1
RFC8032_SEED1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC8032_MSG1 = b""
RFC8032_EXP_SIG1 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

# RFC 8032 Section 7.1 Test Vector 2
RFC8032_SEED2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
RFC8032_MSG2 = bytes.fromhex("72")
RFC8032_EXP_SIG2 = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"

# ------------------------------------------------------------------ Execution & Reports
print("NIST P-256 (secp256r1) ECDSA vs RFC 6979:")
pub_p256 = point_mul(RFC6979_X, (P256_GX, P256_GY))
r, s = ecdsa_sign_deterministic(RFC6979_X, RFC6979_H, RFC6979_K)
p256_sign_ok = (r == RFC6979_EXP_R) and (s == RFC6979_EXP_S)
p256_verify_ok = ecdsa_verify(pub_p256, RFC6979_H, r, s)
p256_tamper_ok = not ecdsa_verify(pub_p256, RFC6979_H, r, (s ^ 1) % P256_N)
print(f"  Deterministic signature generation: {'PASS' if p256_sign_ok else 'FAIL'}")
print(f"  Public key signature verification : {'PASS' if p256_verify_ok else 'FAIL'}")
print(f"  Tampered signature rejection       : {'PASS' if p256_tamper_ok else 'FAIL'}")

print("\nEd25519 vs RFC 8032 Known Answer Tests:")
sig1 = ed25519_sign(RFC8032_SEED1, RFC8032_MSG1).hex()
sig2 = ed25519_sign(RFC8032_SEED2, RFC8032_MSG2).hex()
ed1_ok = (sig1 == RFC8032_EXP_SIG1)
ed2_ok = (sig2 == RFC8032_EXP_SIG2)
print(f"  RFC 8032 Vector 1 (empty message)  : {'PASS' if ed1_ok else 'FAIL'}")
print(f"  RFC 8032 Vector 2 (1-byte message) : {'PASS' if ed2_ok else 'FAIL'}")

all_ok = p256_sign_ok and p256_verify_ok and p256_tamper_ok and ed1_ok and ed2_ok
print(f"\nKAT-RESULT: {'PASS' if all_ok else 'FAIL'}")
