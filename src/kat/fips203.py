"""FIPS 203 (ML-KEM) -- complete reference implementation, stdlib only.

K-PKE (NTT over Z_3329, ExpandA via SHAKE128, CBD sampling, compress/decompress,
ByteEncode/ByteDecode), the derandomized interfaces KeyGen_internal(d, z),
Encaps_internal(ek, m), Decaps_internal(dk, c) (Alg. 16-18) and the external
KeyGen(), Encaps(ek), Decaps(dk, c) (Alg. 19-21, RBG passed in as a callable),
for ML-KEM-512/768/1024, plus the section 7.2/7.3 input checks as separate
predicates.

Algorithms 16-18 are also available as lists of steps over a work record
(`*_internal_steps`); the one-shot functions are built from those lists, so the
official vectors anchor both.  The KLEE harness halts between steps to model an
interrupted long-running operation (AGR10).

The input checks are separate predicates because <<KLEE-PQC-ML-KEM>> performs
them when `encapsk`, `decapsk` or `ciphertext` finishes loading and treats the
outcomes differently: a key check failure is a configuration error, a ciphertext
check failure a data error.

Anchored by kat/mlkem-kat.py against official NIST ACVP-Server vectors; this
module holds no vectors of its own.
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
# Each *_internal_steps(...) returns the algorithm as a list of callables over a work
# record `w` (a dict).  The comments give the FIPS 203 line numbers each step covers.

def keygen_internal_steps(pset):
    """Algorithm 16, ML-KEM.KeyGen_internal: `w` holds d, z on entry and ek, dk on exit."""
    def lines_1_2(w):             # (ek_PKE, dk_PKE) <- K-PKE.KeyGen(d); ek <- ek_PKE
        w['ek'], w['dk_pke'] = kpke_keygen(w['d'], pset)
    def line_3(w):                # dk <- (dk_PKE || ek || H(ek) || z)
        w['dk'] = w['dk_pke'] + w['ek'] + H(w['ek']) + w['z']
    return [lines_1_2, line_3]

def encaps_internal_steps(pset):
    """Algorithm 17, ML-KEM.Encaps_internal: `w` holds ek, m on entry and K, c on exit."""
    def line_1(w):                # (K, r) <- G(m || H(ek))
        w['K'], w['r'] = G(w['m'] + H(w['ek']))
    def line_2(w):                # c <- K-PKE.Encrypt(ek, m, r)
        w['c'] = kpke_encrypt(w['ek'], w['m'], w['r'], pset)
    return [line_1, line_2]

def decaps_internal_steps(pset, disable_implicit_rejection=False):
    """Algorithm 18, ML-KEM.Decaps_internal: `w` holds dk, c on entry and K on exit.

    disable_implicit_rejection=True sabotages lines 9-11 for the harness's negative
    control; never use it otherwise."""
    k = PARAMS[pset][0]
    def lines_1_5(w):             # slice dk; m' <- K-PKE.Decrypt(dk_PKE, c)
        dk = w['dk']
        w['dk_pke'] = dk[:384 * k]
        w['ek_pke'] = dk[384 * k:768 * k + 32]
        w['h'] = dk[768 * k + 32:768 * k + 64]
        w['z'] = dk[768 * k + 64:768 * k + 96]
        w['m2'] = kpke_decrypt(w['dk_pke'], w['c'], pset)
    def lines_6_7(w):             # (K', r') <- G(m' || h); K-bar <- J(z || c)
        w['K2'], w['r2'] = G(w['m2'] + w['h'])
        w['Kbar'] = J(w['z'] + w['c'])
    def line_8(w):                # c' <- K-PKE.Encrypt(ek_PKE, m', r')
        w['c2'] = kpke_encrypt(w['ek_pke'], w['m2'], w['r2'], pset)
    def lines_9_12(w):            # if c != c' then K' <- K-bar; return K'
        w['K'] = w['K2']
        if w['c'] != w['c2'] and not disable_implicit_rejection:
            w['K'] = w['Kbar']
    return [lines_1_5, lines_6_7, line_8, lines_9_12]

def _run(steps, w):
    for step in steps:
        step(w)
    return w

def keygen_internal(d, z, pset):
    w = _run(keygen_internal_steps(pset), {'d': d, 'z': z})
    return w['ek'], w['dk']

def encaps_internal(ek, m, pset):
    w = _run(encaps_internal_steps(pset), {'ek': ek, 'm': m})
    return w['K'], w['c']

def decaps_internal(dk, c, pset, disable_implicit_rejection=False):
    """ML-KEM.Decaps_internal.  disable_implicit_rejection=True sabotages the
    c != c' branch for the harness's negative control; never use otherwise."""
    w = _run(decaps_internal_steps(pset, disable_implicit_rejection), {'dk': dk, 'c': c})
    return w['K']

# ---------------------------------------------------------------- ML-KEM (Algorithms 19-21)
# `rbg` is a callable returning 32 random bytes, or None when the RBG fails (the NULL
# of the standard); a None result of these functions is the standard's bottom value.

def keygen(pset, rbg):
    """Algorithm 19, ML-KEM.KeyGen()."""
    d = rbg()                                          # line 1
    z = rbg()                                          # line 2
    if d is None or z is None:                         # lines 3-5
        return None
    return keygen_internal(d, z, pset)                 # lines 6-7

def encaps(ek, pset, rbg):
    """Algorithm 20, ML-KEM.Encaps(ek); the section 7.2 check is the caller's duty."""
    m = rbg()                                          # line 1
    if m is None:                                      # lines 2-4
        return None
    return encaps_internal(ek, m, pset)                # lines 5-6

def decaps(dk, c, pset):
    """Algorithm 21, ML-KEM.Decaps(dk, c); the section 7.3 checks are the caller's duty."""
    return decaps_internal(dk, c, pset)                # lines 1-2

# ---------------------------------------------------------------- FIPS 203 7.2 / 7.3 checks
# <<KLEE-PQC-ML-KEM>> performs these when the corresponding field finishes loading.

def check_encaps_input(ek, pset):
    """FIPS 203 7.2: encapsulation key check (type + modulus).  True = valid.

    <<KLEE-PQC-ML-KEM>>: performed upon completion of State _encapsk_Input_; a
    failure is a CONFIGURATION error (Error State Invalid).
    """
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

    <<KLEE-PQC-ML-KEM>>: performed upon completion of State _ciphertext_Input_; a
    failure is a DATA error (State Failure), unlike the key checks below.
    """
    k, _, _, du, dv = PARAMS[pset]
    return len(c) == 32 * (du * k + dv)

def check_decaps_key(dk, pset):
    """FIPS 203 7.3: decapsulation key checks (type + hash).  True = valid.

    <<KLEE-PQC-ML-KEM>>: performed upon completion of State _decapsk_Input_; a
    failure is a CONFIGURATION error (Error State Invalid).
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
