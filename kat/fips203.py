"""FIPS 203 (ML-KEM) -- complete reference implementation, stdlib only.

Implements K-PKE (NTT over Z_3329, ExpandA via SHAKE128, CBD sampling,
compress/decompress, ByteEncode/ByteDecode) and the ML-KEM derandomized
interfaces KeyGen_internal(d, z), Encaps_internal(ek, m), Decaps_internal(dk, c)
for all three parameter sets (ML-KEM-512/768/1024), plus the FIPS 203 section
7.2 / 7.3 input-validation checks (encapsulation-key type+modulus check,
decapsulation input checks) as separate, callable predicates.

The checks are separate because the ACE draft specification does NOT require
them (spec gap M12 in ACE-spec-review-0.7.0.md); the KAT harness exercises them
explicitly, labelled "per FIPS 203 (spec gap M12)".

Anchored by kat/mlkem-kat.py against official vectors (NIST ACVP-Server sample
JSON and C2SP/CCTV); this module holds no vectors of its own.
"""

import hashlib

Q = 3329
N = 256

# k, eta1, eta2, du, dv
PARAMS = {
    512:  (2, 3, 2, 10, 4),
    768:  (3, 2, 2, 10, 4),
    1024: (4, 2, 2, 11, 5),
}

def _bitrev7(x):
    return int(f"{x:07b}"[::-1], 2)

# zeta = 17 is a primitive 256th root of unity mod q
_ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]          # NTT twiddles
_GAMMAS = [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]  # BaseCaseMultiply

# ---------------------------------------------------------------- hashes (FIPS 203 4.1)

def G(data):                      # SHA3-512 -> (32, 32)
    h = hashlib.sha3_512(data).digest()
    return h[:32], h[32:]

def H(data):                      # SHA3-256
    return hashlib.sha3_256(data).digest()

def J(data):                      # SHAKE256, 32 bytes
    return hashlib.shake_256(data).digest(32)

def PRF(eta, s, b):               # SHAKE256(s || b, 64*eta)
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)

# ---------------------------------------------------------------- NTT (Algorithms 9-11)

def ntt(f):
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            z = _ZETAS[i]; i += 1
            for j in range(start, start + length):
                t = z * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f

def intt(f):
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            z = _ZETAS[i]; i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = z * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]      # 3303 = 128^-1 mod q

def ntt_mul(f, g):
    """MultiplyNTTs (Algorithm 11): pairwise BaseCaseMultiply."""
    h = [0] * 256
    for i in range(128):
        a0, a1 = f[2 * i], f[2 * i + 1]
        b0, b1 = g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 % Q * _GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h

def poly_add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]

def poly_sub(f, g):
    return [(a - b) % Q for a, b in zip(f, g)]

# ---------------------------------------------------------------- sampling (Algorithms 7-8)

def sample_ntt(seed34):
    """SampleNTT: rejection-sample a polynomial in NTT domain from SHAKE128."""
    # SHAKE128 stream; 3 bytes -> two candidate 12-bit values
    out = []
    xof = hashlib.shake_128(seed34)
    buf = xof.digest(704)         # 704 bytes gives ~469 candidates; enough w.h.p.
    pos = 0
    while len(out) < 256:
        if pos + 3 > len(buf):
            buf = xof.digest(len(buf) + 512)   # extend deterministically (same stream prefix)
        c0, c1, c2 = buf[pos], buf[pos + 1], buf[pos + 2]
        pos += 3
        d1 = c0 + 256 * (c1 % 16)
        d2 = c1 // 16 + 16 * c2
        if d1 < Q:
            out.append(d1)
        if d2 < Q and len(out) < 256:
            out.append(d2)
    return out

def sample_cbd(eta, prf_out):
    """SamplePolyCBD_eta from 64*eta bytes of PRF output."""
    bits = []
    for byte in prf_out:
        for j in range(8):
            bits.append((byte >> j) & 1)
    f = []
    for i in range(256):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)
    return f

# ---------------------------------------------------------------- encode / compress (4.2.1)

def byte_encode(d, f):
    """ByteEncode_d: 256 d-bit ints -> 32*d bytes (little-endian bit packing)."""
    v = 0
    for i, a in enumerate(f):
        v |= (a & ((1 << d) - 1)) << (d * i)
    return v.to_bytes(32 * d, 'little')

def byte_decode(d, b):
    """ByteDecode_d: 32*d bytes -> 256 ints (mod q when d = 12)."""
    v = int.from_bytes(b, 'little')
    mask = (1 << d) - 1
    if d == 12:
        return [((v >> (12 * i)) & mask) % Q for i in range(256)]
    return [(v >> (d * i)) & mask for i in range(256)]

def compress(d, x):
    return (((x << d) + Q // 2) // Q) % (1 << d)

def decompress(d, y):
    return (Q * y + (1 << (d - 1))) >> d

# ---------------------------------------------------------------- K-PKE (Algorithms 13-15)

def _expand_A(rho, k):
    """A_hat[i][j] = SampleNTT(rho || j || i)  (FIPS 203 final, Kyber order)."""
    return [[sample_ntt(rho + bytes([j, i])) for j in range(k)] for i in range(k)]

def kpke_keygen(d, pset):
    k, eta1, _, _, _ = PARAMS[pset]
    rho, sigma = G(d + bytes([k]))
    A = _expand_A(rho, k)
    Nctr = 0
    s = []
    for _ in range(k):
        s.append(sample_cbd(eta1, PRF(eta1, sigma, Nctr))); Nctr += 1
    e = []
    for _ in range(k):
        e.append(sample_cbd(eta1, PRF(eta1, sigma, Nctr))); Nctr += 1
    s_hat = [ntt(p) for p in s]
    e_hat = [ntt(p) for p in e]
    t_hat = []
    for i in range(k):
        acc = e_hat[i]
        for j in range(k):
            acc = poly_add(acc, ntt_mul(A[i][j], s_hat[j]))
        t_hat.append(acc)
    ek = b''.join(byte_encode(12, t) for t in t_hat) + rho
    dk = b''.join(byte_encode(12, s) for s in s_hat)
    return ek, dk

def kpke_encrypt(ek, m, r, pset):
    k, eta1, eta2, du, dv = PARAMS[pset]
    t_hat = [byte_decode(12, ek[384 * i:384 * (i + 1)]) for i in range(k)]
    rho = ek[384 * k:384 * k + 32]
    A = _expand_A(rho, k)
    Nctr = 0
    y = []
    for _ in range(k):
        y.append(sample_cbd(eta1, PRF(eta1, r, Nctr))); Nctr += 1
    e1 = []
    for _ in range(k):
        e1.append(sample_cbd(eta2, PRF(eta2, r, Nctr))); Nctr += 1
    e2 = sample_cbd(eta2, PRF(eta2, r, Nctr))
    y_hat = [ntt(p) for p in y]
    u = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            acc = poly_add(acc, ntt_mul(A[j][i], y_hat[j]))   # A^T
        u.append(poly_add(intt(acc), e1[i]))
    mu = [decompress(1, b) for b in byte_decode(1, m)]
    acc = [0] * 256
    for j in range(k):
        acc = poly_add(acc, ntt_mul(t_hat[j], y_hat[j]))
    v = poly_add(poly_add(intt(acc), e2), mu)
    c1 = b''.join(byte_encode(du, [compress(du, x) for x in p]) for p in u)
    c2 = byte_encode(dv, [compress(dv, x) for x in v])
    return c1 + c2

def kpke_decrypt(dk, c, pset):
    k, _, _, du, dv = PARAMS[pset]
    u = [[decompress(du, y) for y in byte_decode(du, c[32 * du * i:32 * du * (i + 1)])]
         for i in range(k)]
    v = [decompress(dv, y) for y in byte_decode(dv, c[32 * du * k:])]
    s_hat = [byte_decode(12, dk[384 * i:384 * (i + 1)]) for i in range(k)]
    acc = [0] * 256
    for j in range(k):
        acc = poly_add(acc, ntt_mul(s_hat[j], ntt(u[j])))
    w = poly_sub(v, intt(acc))
    return byte_encode(1, [compress(1, x) for x in w])

# ---------------------------------------------------------------- sizes

def sizes(pset):
    """(ek, dk, ct, ss) sizes in bytes."""
    k, _, _, du, dv = PARAMS[pset]
    return 384 * k + 32, 768 * k + 96, 32 * (du * k + dv), 32

# ---------------------------------------------------------------- ML-KEM (Algorithms 16-18)

def keygen_internal(d, z, pset):
    ek, dk_pke = kpke_keygen(d, pset)
    dk = dk_pke + ek + H(ek) + z
    return ek, dk

def encaps_internal(ek, m, pset):
    K, r = G(m + H(ek))
    c = kpke_encrypt(ek, m, r, pset)
    return K, c

def decaps_internal(dk, c, pset, disable_implicit_rejection=False):
    """ML-KEM.Decaps_internal.  disable_implicit_rejection=True sabotages the
    c != c' branch for the harness's negative control; never use otherwise."""
    k = PARAMS[pset][0]
    dk_pke = dk[:384 * k]
    ek = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m2 = kpke_decrypt(dk_pke, c, pset)
    K2, r2 = G(m2 + h)
    Kbar = J(z + c)
    c2 = kpke_encrypt(ek, m2, r2, pset)
    if c != c2 and not disable_implicit_rejection:
        K2 = Kbar
    return K2

# ---------------------------------------------------------------- FIPS 203 7.2 / 7.3 checks
# The ACE draft does not require these (spec gap M12); harness applies them.

def check_encaps_input(ek, pset):
    """FIPS 203 7.2: encapsulation key check (type + modulus).  True = valid."""
    k = PARAMS[pset][0]
    if len(ek) != 384 * k + 32:
        return False                                   # type check
    for i in range(k):
        seg = ek[384 * i:384 * (i + 1)]
        if byte_encode(12, byte_decode(12, seg)) != seg:
            return False                               # modulus check
    return True

def check_ciphertext(c, pset):
    """FIPS 203 7.3: ciphertext type check.  True = valid.

    <<ACE-PQC-ML-KEM>> treats a failure here as a DATA error (State Failure),
    separately from the key checks below.
    """
    k, _, _, du, dv = PARAMS[pset]
    return len(c) == 32 * (du * k + dv)

def check_decaps_key(dk, pset):
    """FIPS 203 7.3: decapsulation key checks (type + hash).  True = valid.

    <<ACE-PQC-ML-KEM>> treats a failure here as a CONFIGURATION error
    (Error State Invalid).
    """
    k = PARAMS[pset][0]
    if len(dk) != 768 * k + 96:
        return False                                   # dk type check
    ek = dk[384 * k:768 * k + 32]
    if H(ek) != dk[768 * k + 32:768 * k + 64]:
        return False                                   # hash check
    return True

def check_decaps_input(dk, c, pset):
    """FIPS 203 7.3: both decapsulation input checks together.  True = valid.

    Retained because the ACVP `decapsulationKeyCheck` vectors exercise the pair.
    """
    return check_ciphertext(c, pset) and check_decaps_key(dk, pset)
