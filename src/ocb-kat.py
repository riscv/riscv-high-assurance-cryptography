"""Validate the corrected ACE OCB3 formulas against RFC 7253.

Two independent implementations:
  REF  - RFC 7253 written directly on byte strings (big-endian semantics)
  ACE  - the formulas as now written in ace-ISA-algorithms.adoc, evaluated in the
         ACE value model (byte i of a string lives at bits [8i+7:8i] of an integer)

Both are checked against RFC 7253 Appendix A vectors.
"""

# ---------------------------------------------------------------- AES-128 (enc)
SBOX = []
def _mk_sbox():
    p = q = 1
    sbox = [0]*256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80: q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
              ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1: break
    sbox[0] = 0x63
    return sbox
SBOX = _mk_sbox()

def xt(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1

def expand(key):
    w = [list(key[i*4:i*4+4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = xt(rcon)
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return w

def aes_encrypt(key, block):
    w = expand(key)
    s = list(block)                       # state[4*col + row]
    def addrk(r):
        for c in range(4):
            for j in range(4): s[4*c+j] ^= w[r*4+c][j]
    addrk(0)
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        t = list(s)                       # ShiftRows: row j left by j
        for c in range(4):
            for j in range(4): t[4*c+j] = s[4*((c+j) % 4)+j]
        s = t
        if rnd != 10:
            for c in range(4):
                a = s[4*c:4*c+4]
                u = a[0] ^ a[1] ^ a[2] ^ a[3]
                s[4*c:4*c+4] = [a[0] ^ u ^ xt(a[0] ^ a[1]),
                                a[1] ^ u ^ xt(a[1] ^ a[2]),
                                a[2] ^ u ^ xt(a[2] ^ a[3]),
                                a[3] ^ u ^ xt(a[3] ^ a[0])]
        addrk(rnd)
    return bytes(s)

assert aes_encrypt(bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                   bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == \
       "69c4e0d86a7b0430d8cdb78070b4c55a", "AES self-test failed (FIPS-197 C.1)"
print("AES-128 self-test (FIPS-197 C.1): PASS\n")

# ------------------------------------------------------------- REF: RFC 7253
def xs(a, b): return bytes(x ^ y for x, y in zip(a, b))
def ntz(n):
    i = 0
    while n % 2 == 0: n //= 2; i += 1
    return i

def dbl(s):
    n = int.from_bytes(s, 'big')
    msb = n >> 127
    n = ((n << 1) & ((1 << 128) - 1)) ^ (0x87 if msb else 0)
    return n.to_bytes(16, 'big')

def ref_ocb_encrypt(K, N, A, P, taglen=16):
    E = lambda b: aes_encrypt(K, b)
    Lstar = E(bytes(16)); Ldollar = dbl(Lstar); L = [dbl(Ldollar)]
    def Li(i):
        while len(L) <= i: L.append(dbl(L[-1]))
        return L[i]
    # HASH(K, A)
    Sum = bytes(16); Off = bytes(16)
    m = len(A) // 16
    for i in range(1, m + 1):
        Off = xs(Off, Li(ntz(i)))
        Sum = xs(Sum, E(xs(A[(i-1)*16:i*16], Off)))
    rest = A[m*16:]
    if rest:
        Off = xs(Off, Lstar)
        pad = rest + b'\x80' + bytes(15 - len(rest))
        Sum = xs(Sum, E(xs(pad, Off)))
    HashA = Sum
    # Nonce-dependent
    nonce = bytes([taglen * 8 % 128 << 1]) + bytes(11 - len(N)) + b'' if False else None
    Nonce = int.from_bytes(bytes(16), 'big')
    Nonce = ((taglen * 8 % 128) << 121) | (1 << (len(N) * 8)) | int.from_bytes(N, 'big')
    Nonce = Nonce.to_bytes(16, 'big')
    bottom = Nonce[15] & 0x3F
    Ktop = E(Nonce[:15] + bytes([Nonce[15] & 0xC0]))
    Stretch = Ktop + xs(Ktop[:8], Ktop[1:9])
    S = int.from_bytes(Stretch, 'big')
    Offset = ((S >> (192 - 128 - bottom)) & ((1 << 128) - 1)).to_bytes(16, 'big')
    Checksum = bytes(16); C = b''
    m = len(P) // 16
    for i in range(1, m + 1):
        Offset = xs(Offset, Li(ntz(i)))
        Pi = P[(i-1)*16:i*16]
        Checksum = xs(Checksum, Pi)
        C += xs(Offset, E(xs(Pi, Offset)))
    rest = P[m*16:]
    if rest:
        Offset = xs(Offset, Lstar)
        Pad = E(Offset)
        C += xs(rest, Pad[:len(rest)])
        Checksum = xs(Checksum, rest + b'\x80' + bytes(15 - len(rest)))
    Tag = xs(E(xs(xs(Checksum, Offset), Ldollar)), HashA)
    return C + Tag[:taglen]

# ------------------------------------------------------- ACE model helpers
M128 = (1 << 128) - 1
def b2v(bs):                      # byte string -> ACE value
    return int.from_bytes(bs, 'little')
def v2b(v, n):                    # ACE value -> byte string of n bytes
    return (v & ((1 << (8*n)) - 1)).to_bytes(n, 'little')
def sl(v, hi, lo):                # v[hi:lo]
    return (v >> lo) & ((1 << (hi - lo + 1)) - 1)
def cat(*parts):                  # (value, length) pairs, left = more significant
    r = 0
    for val, ln in parts: r = (r << ln) | (val & ((1 << ln) - 1))
    return r
def bswap(v, nbits):
    n = nbits // 8
    return int.from_bytes(v2b(v, n)[::-1], 'little')
def enc_v(K, v):                  # enc_blk on ACE values
    return b2v(aes_encrypt(K, v2b(v, 16)))

def ace_update_mask(M):           # spec: XEX/XTS little-endian doubling
    return ((M << 1) & M128) ^ (0x87 if sl(M, 127, 127) else 0)
def ace_double(S):                # spec: bswap(update_mask(bswap(S)))
    return bswap(ace_update_mask(bswap(S, 128)), 128)
def ocb_pad(X, n):                # spec: zeros(120-n) @ 0b10000000 @ X[n-1:0]
    return cat((0, 120 - n), (0x80, 8), (sl(X, n - 1, 0) if n else 0, n))

def ace_ocb_encrypt(K, N, A, P, taglen=16):
    """Follows ace-ISA-algorithms.adoc as now written."""
    Lstar = enc_v(K, 0); Ldollar = ace_double(Lstar); L = [ace_double(Ldollar)]
    def Li(i):
        while len(L) <= i: L.append(ace_double(L[-1]))
        return L[i]
    # _Hash_Absorb_ / _Hash_Absorb_Last_Block_
    hash_A = 0; offset = 0; index = 1
    m = len(A) // 16
    for i in range(m):
        offset ^= Li(ntz(index)); index += 1
        hash_A ^= enc_v(K, b2v(A[i*16:(i+1)*16]) ^ offset)
    rest = A[m*16:]
    last_blk_len = len(rest) * 8
    if last_blk_len:
        offset ^= Lstar
        tmp = ocb_pad(b2v(rest), last_blk_len) ^ offset      # <- corrected
        hash_A ^= enc_v(K, tmp)
    # entering _Encrypt_
    N_len = len(N) * 8
    Nv = b2v(N)
    Nonce_be = cat((taglen * 8 % 128, 7), (0, 120 - N_len), (1, 1),
                   (bswap(sl(Nv, N_len - 1, 0), N_len), N_len))
    bottom = sl(Nonce_be, 5, 0)
    Ktop = enc_v(K, bswap(cat((sl(Nonce_be, 127, 6), 122), (0, 6)), 128))
    Ktop_be = bswap(Ktop, 128)
    Stretch_be = cat((Ktop_be, 128), (sl(Ktop_be, 127, 64) ^ sl(Ktop_be, 119, 56), 64))
    index = 1
    offset = bswap(sl(Stretch_be, 191 - bottom, 64 - bottom), 128)
    checksum_P = 0; C = b''
    m = len(P) // 16
    for i in range(m):
        offset ^= Li(ntz(index)); index += 1
        Pi = b2v(P[i*16:(i+1)*16])
        checksum_P ^= Pi
        C += v2b(offset ^ enc_v(K, Pi ^ offset), 16)
    rest = P[m*16:]
    last_blk_len = len(rest) * 8
    if last_blk_len:
        offset ^= Lstar
        pad = enc_v(K, offset)
        INPUT = b2v(rest)
        out = sl(INPUT, last_blk_len - 1, 0) ^ sl(pad, last_blk_len - 1, 0)
        C += v2b(out, last_blk_len // 8)
        tmp = offset ^ ocb_pad(INPUT, last_blk_len)          # <- corrected (plaintext)
        checksum_P = enc_v(K, checksum_P ^ tmp ^ Ldollar) ^ hash_A
    else:
        checksum_P = enc_v(K, checksum_P ^ offset ^ Ldollar) ^ hash_A
    return C + v2b(sl(checksum_P, taglen * 8 - 1, 0), taglen)

# ------------------------------------------------------------------ vectors
K = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
VEC = [
 ("BBAA99887766554433221100", "", "", "785407BFFFC8AD9EDCC5520AC9111EE6"),
 ("BBAA99887766554433221101", "0001020304050607", "0001020304050607",
  "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009"),
 ("BBAA99887766554433221102", "0001020304050607", "",
  "81017F8203F081277152FADE694A0A00"),
 ("BBAA99887766554433221103", "", "0001020304050607",
  "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9"),
 ("BBAA99887766554433221104", "000102030405060708090A0B0C0D0E0F",
  "000102030405060708090A0B0C0D0E0F",
  "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358"),
 ("BBAA99887766554433221106", "", "000102030405060708090A0B0C0D0E0F",
  "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D"),
 ("BBAA99887766554433221107", "000102030405060708090A0B0C0D0E0F1011121314151617",
  "000102030405060708090A0B0C0D0E0F1011121314151617",
  "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F"),
]

print(f"{'nonce':26} {'REF vs RFC':12} {'ACE vs RFC':12} {'ACE vs REF'}")
okref = okace = True
for n, a, p, c in VEC:
    N, A, P, exp = bytes.fromhex(n), bytes.fromhex(a), bytes.fromhex(p), bytes.fromhex(c)
    r = ref_ocb_encrypt(K, N, A, P)
    v = ace_ocb_encrypt(K, N, A, P)
    okref &= (r == exp); okace &= (v == exp)
    print(f"{n:26} {'PASS' if r==exp else 'FAIL':12} "
          f"{'PASS' if v==exp else 'FAIL':12} {'PASS' if v==r else 'FAIL'}")
    if v != exp:
        print("   expected", exp.hex().upper())
        print("   ACE got  ", v.hex().upper())
print()
print("reference matches RFC 7253 vectors :", okref)
print("ACE spec matches RFC 7253 vectors  :", okace)

# ------------------------------------------------- ACE model: decryption path
INV = [0]*256
for i, v in enumerate(SBOX): INV[v] = i

def aes_decrypt(key, block):
    w = expand(key)
    s = list(block)
    def addrk(r):
        for c in range(4):
            for j in range(4): s[4*c+j] ^= w[r*4+c][j]
    def mul(a, b):
        r = 0
        while b:
            if b & 1: r ^= a
            a = xt(a); b >>= 1
        return r
    addrk(10)
    for rnd in range(9, -1, -1):
        t = list(s)                                  # InvShiftRows: row j right by j
        for c in range(4):
            for j in range(4): t[4*((c+j) % 4)+j] = s[4*c+j]
        s = [INV[b] for b in t]
        addrk(rnd)
        if rnd != 0:
            for c in range(4):
                a = s[4*c:4*c+4]
                s[4*c:4*c+4] = [
                    mul(a[0],14) ^ mul(a[1],11) ^ mul(a[2],13) ^ mul(a[3], 9),
                    mul(a[0], 9) ^ mul(a[1],14) ^ mul(a[2],11) ^ mul(a[3],13),
                    mul(a[0],13) ^ mul(a[1], 9) ^ mul(a[2],14) ^ mul(a[3],11),
                    mul(a[0],11) ^ mul(a[1],13) ^ mul(a[2], 9) ^ mul(a[3],14)]
    return bytes(s)

assert aes_decrypt(bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                   bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")).hex() == \
       "00112233445566778899aabbccddeeff", "AES inverse self-test failed"

def dec_v(K, v): return b2v(aes_decrypt(K, v2b(v, 16)))

def ace_ocb_decrypt(K, N, A, C_and_tag, taglen=16):
    """Follows the _Decrypt_ / _Dec_Last_Block_ / _Hash_Verify_ text as now written."""
    C, tag = C_and_tag[:-taglen], C_and_tag[-taglen:]
    Lstar = enc_v(K, 0); Ldollar = ace_double(Lstar); L = [ace_double(Ldollar)]
    def Li(i):
        while len(L) <= i: L.append(ace_double(L[-1]))
        return L[i]
    hash_A = 0; offset = 0; index = 1
    m = len(A) // 16
    for i in range(m):
        offset ^= Li(ntz(index)); index += 1
        hash_A ^= enc_v(K, b2v(A[i*16:(i+1)*16]) ^ offset)
    rest = A[m*16:]
    if rest:
        offset ^= Lstar
        hash_A ^= enc_v(K, ocb_pad(b2v(rest), len(rest)*8) ^ offset)
    N_len = len(N)*8; Nv = b2v(N)
    Nonce_be = cat((taglen*8 % 128, 7), (0, 120-N_len), (1, 1),
                   (bswap(sl(Nv, N_len-1, 0), N_len), N_len))
    bottom = sl(Nonce_be, 5, 0)
    Ktop = enc_v(K, bswap(cat((sl(Nonce_be, 127, 6), 122), (0, 6)), 128))
    Ktop_be = bswap(Ktop, 128)
    Stretch_be = cat((Ktop_be, 128), (sl(Ktop_be, 127, 64) ^ sl(Ktop_be, 119, 56), 64))
    index = 1
    offset = bswap(sl(Stretch_be, 191-bottom, 64-bottom), 128)
    checksum_P = 0; P = b''
    m = len(C) // 16
    for i in range(m):
        offset ^= Li(ntz(index)); index += 1
        Ci = b2v(C[i*16:(i+1)*16])
        tmp = offset ^ dec_v(K, Ci ^ offset)          # <- dec_blk, was enc_blk
        checksum_P ^= tmp
        P += v2b(tmp, 16)
    rest = C[m*16:]
    n = len(rest)*8
    if n:
        offset ^= Lstar
        pad = enc_v(K, offset)
        OUT = sl(b2v(rest), n-1, 0) ^ sl(pad, n-1, 0)
        P += v2b(OUT, n//8)
        tmp = offset ^ ocb_pad(OUT, n)                # <- plaintext OUTPUT
        checksum_P = enc_v(K, checksum_P ^ tmp ^ Ldollar) ^ hash_A
    else:
        checksum_P = enc_v(K, checksum_P ^ offset ^ Ldollar) ^ hash_A
    ok = v2b(sl(checksum_P, taglen*8-1, 0), taglen) == tag
    return ok, P

print("\n--- decryption path ---")
print(f"{'nonce':26} {'plaintext':12} {'tag verify':12} {'tamper rejected'}")
alldec = True
for n, a, p, c in VEC:
    N, A, P, ct = bytes.fromhex(n), bytes.fromhex(a), bytes.fromhex(p), bytes.fromhex(c)
    ok, rec = ace_ocb_decrypt(K, N, A, ct)
    bad = bytearray(ct); bad[0] ^= 1
    ok2, _ = ace_ocb_decrypt(K, N, A, bytes(bad))
    good = (rec == P) and ok and (not ok2)
    alldec &= good
    print(f"{n:26} {'PASS' if rec==P else 'FAIL':12} {'PASS' if ok else 'FAIL':12} "
          f"{'PASS' if not ok2 else 'FAIL'}")
print()
print("ACE decryption round-trips and authenticates:", alldec)
