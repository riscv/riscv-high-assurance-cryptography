import os; exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'ocb-kat.py')).read().split('# ------------------------------------------------------------------ vectors')[0])

def gmul(X, Y):                       # SP 800-38D 6.3, on 16-byte big-endian strings
    x = int.from_bytes(X, 'big'); y = int.from_bytes(Y, 'big'); z = 0; v = y
    for i in range(128):
        if (x >> (127 - i)) & 1: z ^= v
        v = (v >> 1) ^ (0xe1 << 120) if v & 1 else v >> 1
    return z.to_bytes(16, 'big')

def ghash(H, X):
    y = bytes(16)
    for i in range(0, len(X), 16):
        y = gmul(bytes(a ^ b for a, b in zip(y, X[i:i+16])), H)
    return y

def ref_gcm(K, IV, A, P):             # reference, byte-string / big-endian
    E = lambda b: aes_encrypt(K, b)
    H = E(bytes(16))
    J0 = IV + b'\x00\x00\x00\x01'
    def inc32(b):
        n = int.from_bytes(b[12:], 'big'); return b[:12] + ((n + 1) % 2**32).to_bytes(4, 'big')
    C = b''; cb = J0
    for i in range(0, len(P), 16):
        cb = inc32(cb)
        C += bytes(a ^ b for a, b in zip(P[i:i+16], E(cb)))
    pad = lambda s: s + bytes((-len(s)) % 16)
    S = ghash(H, pad(A) + pad(C) + (len(A)*8).to_bytes(8, 'big') + (len(C)*8).to_bytes(8, 'big'))
    T = bytes(a ^ b for a, b in zip(S, E(J0)))
    return C, T

# --- ACE model: convention = octet i at bits [8i+7:8i]; @ puts left operand high
def ace_galoismul(a, b):              # Galoismul per ACE conventions (bswap into 38D view)
    return b2v(gmul(v2b(a, 16), v2b(b, 16)))

def ace_gcm(K, IV, A, P, len_block_ad_first_octets=True, ctr_high=True):
    hash_key = b2v(aes_encrypt(K, bytes(16)))
    tag = 0
    def absorb(x):
        nonlocal tag
        tag = ace_galoismul(tag ^ x, hash_key)
    J0 = cat((b2v(bytes.fromhex("00000001")[::-1]) if False else
              int.from_bytes((1).to_bytes(4, 'big'), 'little'), 32), (b2v(IV), 96))
    start = sl(J0, 127, 96) if ctr_high else sl(J0, 31, 0)
    def block(c32):
        return cat((c32, 32), (sl(J0, 95, 0), 96)) if ctr_high else \
               cat((sl(J0, 127, 32), 96), (c32, 32))
    def bump(c32):                    # big-endian 32-bit increment
        if not ctr_high: return (c32 + 1) % 2**32
        n = (int.from_bytes(v2b(c32, 4), 'big') + 1) % 2**32     # big-endian counter
        return int.from_bytes(n.to_bytes(4, 'big'), 'little')
    for i in range(0, len(A), 16): absorb(b2v(A[i:i+16].ljust(16, b'\0')))
    C = b''; c = start
    for i in range(0, len(P), 16):
        c = bump(c)
        blk = P[i:i+16]
        ct = b2v(blk.ljust(16, b'\0')) ^ b2v(aes_encrypt(K, v2b(block(c), 16)))
        ct = sl(ct, len(blk)*8 - 1, 0)
        C += v2b(ct, len(blk)); absorb(ct)
    la, lc = len(A)*8, len(P)*8
    lb = cat((int.from_bytes((lc).to_bytes(8, 'big'), 'little'), 64),
             (int.from_bytes((la).to_bytes(8, 'big'), 'little'), 64)) \
         if len_block_ad_first_octets else \
         cat((int.from_bytes((la).to_bytes(8, 'big'), 'little'), 64),
             (int.from_bytes((lc).to_bytes(8, 'big'), 'little'), 64))
    absorb(lb)
    T = tag ^ b2v(aes_encrypt(K, v2b(block(start), 16)))
    return C, v2b(T, 16)

TV = [  # McGrew-Viega / SP 800-38D classic cases (96-bit IV)
 ("00000000000000000000000000000000", "000000000000000000000000", "",
  "", "", "58e2fccefa7e3061367f1d57a4e7455a"),
 ("00000000000000000000000000000000", "000000000000000000000000", "",
  "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78",
  "ab6e47d42cec13bdf53a67b21257bddf"),
]
print(f"{'case':6} {'REF':8} {'ACE(len:AD-first,ctr:high)':28} {'ACE(len swapped)':18} {'ACE(ctr low)'}")
for i,(k, iv, a, p, ec, et) in enumerate(TV):
    K, IV, A, P = bytes.fromhex(k), bytes.fromhex(iv), bytes.fromhex(a), bytes.fromhex(p)
    EC, ET = bytes.fromhex(ec), bytes.fromhex(et)
    rc, rt = ref_gcm(K, IV, A, P)
    c1, t1 = ace_gcm(K, IV, A, P, True,  True)
    c2, t2 = ace_gcm(K, IV, A, P, False, True)
    c3, t3 = ace_gcm(K, IV, A, P, True,  False)
    f = lambda c,t: "PASS" if (c,t)==(EC,ET) else "FAIL"
    print(f"{i:<6} {f(rc,rt):8} {f(c1,t1):28} {f(c2,t2):18} {f(c3,t3)}")
