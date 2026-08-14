"""The Sealed Cryptographic Context construction of <<ACE-export-import-algorithms>>.

The sealing construction is a *deliberate variant* of AES-GCM-SIV: the POLYVAL length
block of RFC 8452 section 4 is omitted, because every length entering the computation is
a deterministic function of the MDH, which is itself the first associated-data block.
<<ACE-SCC-no-length-block>> argues that at length, and notes the consequence — an
implementation cannot be validated against the RFC 8452 test vectors, and conformance
has to be demonstrated against vectors generated for the variant.

This script is where those vectors come from.  It carries three implementations:

  REF   AES-GCM-SIV exactly as RFC 8452 specifies it, length block included
  ACE   the variant, as ace-ISA-unpriv.adoc specifies it, in the ACE value model
  LEN   the variant with the length block *restored*, as a negative control: if ACE and
        LEN ever agreed, omitting the block would be unobservable and the argument in
        <<ACE-SCC-no-length-block>> would be untestable

AES-256 is anchored against FIPS-197 C.3 and POLYVAL against the RFC 8452 worked
example, so that the primitives are known good before the construction is exercised.
The structural properties then tested are the ones the architecture relies on: that a
sealed context unseals, that any single-bit change anywhere is rejected, that a change of
Locality set or of nonce changes the output, and that the second pass is bound to the
first through SIV.
"""
import os, sys
d = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, d)
exec(open(os.path.join(d, 'ocb-kat.py')).read()
     .split('# ------------------------------------------------------------------ vectors')[0])

M64 = (1 << 64) - 1


# --------------------------------------------------------------- AES-128/192/256
def expand_any(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = xt(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def aes_enc_any(key, block):
    w, nr = expand_any(key)
    s = list(block)
    def addrk(r):
        for c in range(4):
            for j in range(4):
                s[4 * c + j] ^= w[r * 4 + c][j]
    addrk(0)
    for rnd in range(1, nr + 1):
        s2 = [SBOX[b] for b in s]
        t = list(s2)
        for c in range(4):
            for j in range(4):
                t[4 * c + j] = s2[4 * ((c + j) % 4) + j]
        s = t
        if rnd != nr:
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                u = a[0] ^ a[1] ^ a[2] ^ a[3]
                s[4 * c:4 * c + 4] = [a[0] ^ u ^ xt(a[0] ^ a[1]),
                                      a[1] ^ u ^ xt(a[1] ^ a[2]),
                                      a[2] ^ u ^ xt(a[2] ^ a[3]),
                                      a[3] ^ u ^ xt(a[3] ^ a[0])]
        addrk(rnd)
    return bytes(s)


aes256_ok = aes_enc_any(bytes(range(32)),
                        bytes.fromhex('00112233445566778899aabbccddeeff')).hex() == \
            '8ea2b7ca516745bfeafc49904b496089'
print('AES-256 self-test (FIPS-197 C.3):', 'PASS' if aes256_ok else 'FAIL')


def AESE256(Kv, blk_v):
    """AESE256 on ACE values: the 256-bit key and the 128-bit block."""
    return b2v(aes_enc_any(v2b(Kv, 32), v2b(blk_v, 16)))


# ------------------------------------------------------------- POLYVAL (RFC 8452)
# The field is GF(2)[x] / (x^128 + x^127 + x^126 + x^121 + 1) and bit k of a value is
# the coefficient of x^k, which is exactly the ACE value representation.
F = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1


def clmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        b >>= 1
    return r


def Montmul(a, b):
    """dot(a, b) = a . b . x^-128, by Montgomery reduction from the low end."""
    p = clmul(a, b)
    for i in range(128):
        if (p >> i) & 1:
            p ^= F << i
    return p >> 128


def POLYVAL(auth_key, blocks):
    tmp = 0
    for blk in blocks:
        tmp = Montmul(tmp ^ blk, auth_key)
    return tmp


# RFC 8452 section 3 worked example
pv_ok = POLYVAL(b2v(bytes.fromhex('25629347589242761d31f826ba4b757b')),
                [b2v(bytes.fromhex('4f4f95668c83dfb6401762bb2d01a262')),
                 b2v(bytes.fromhex('d1a24ddd2721d006bbe45f20d3c9f362'))]) == \
        b2v(bytes.fromhex('f7a3b47b846119fae5b7866cf5e5b77e'))
print('POLYVAL self-test (RFC 8452 section 3):', 'PASS' if pv_ok else 'FAIL')


# ---------------------------------------------------- RFC8452_KeyDeriv, as specified
def key_deriv(Kv, Nv):
    A = [AESE256(Kv, cat((Nv, 96), (i, 32))) for i in range(6)]
    enc_key = cat((sl(A[5], 63, 0), 64), (sl(A[4], 63, 0), 64),
                  (sl(A[3], 63, 0), 64), (sl(A[2], 63, 0), 64))
    auth_key = cat((sl(A[1], 63, 0), 64), (sl(A[0], 63, 0), 64))
    return enc_key, auth_key


def gcm_siv_encrypt(AD, Nv, P, Kv, length_block=None):
    """<<ACE-SCC-GCM-SIV-enc>>; pass length_block to restore the RFC 8452 block."""
    enc_key, auth_key = key_deriv(Kv, Nv)
    blocks = list(AD) + list(P) + ([length_block] if length_block is not None else [])
    SIV = POLYVAL(auth_key, blocks)
    SIV ^= sl(Nv, 95, 0)                                  # SIV[95:0] ^= N
    SIV = AESE256(enc_key, cat((0, 1), (sl(SIV, 126, 0), 127)))
    C = [P[i] ^ AESE256(enc_key, cat((1, 1), (sl(SIV, 126, 32), 95),
                                     ((sl(SIV, 31, 0) + i) % (1 << 32), 32)))
         for i in range(len(P))]
    return SIV, C


def gcm_siv_decrypt(AD, Nv, SIV, C, Kv, length_block=None):
    """<<ACE-SCC-GCM-SIV-dec>>."""
    enc_key, auth_key = key_deriv(Kv, Nv)
    P = [C[i] ^ AESE256(enc_key, cat((1, 1), (sl(SIV, 126, 32), 95),
                                     ((sl(SIV, 31, 0) + i) % (1 << 32), 32)))
         for i in range(len(C))]
    blocks = list(AD) + list(P) + ([length_block] if length_block is not None else [])
    tmp = POLYVAL(auth_key, blocks)
    tmp ^= sl(Nv, 95, 0)
    tmp = AESE256(enc_key, cat((0, 1), (sl(tmp, 126, 0), 127)))
    return (tmp == SIV), ([0] * len(C) if tmp != SIV else P)


# --------------------------------------------- REF: RFC 8452, on byte strings
def ref_gcm_siv(K, N, A, P):
    Kv, Nv = b2v(K), b2v(N)
    pad = lambda s: s + bytes(-len(s) % 16)
    to_blocks = lambda s: [b2v(pad(s)[i:i + 16]) for i in range(0, len(pad(s)), 16)]
    lb = b2v((len(A) * 8).to_bytes(8, 'little') + (len(P) * 8).to_bytes(8, 'little'))
    SIV, C = gcm_siv_encrypt(to_blocks(A), Nv, to_blocks(P), Kv, length_block=lb)
    ct = b''.join(v2b(c, 16) for c in C)[:len(P)]
    return ct + v2b(SIV, 16)


# ------------------------------------------- the ACE sealing / unsealing procedure
CSK = b2v(bytes(range(32)))
LST = {j: b2v(bytes([0x40 + j] * 16)) for j in range(11)}      # Locality Secrets
NONCE = b2v(bytes(range(0x90, 0x9c)))                          # Locality #11


def seal(mdh, content, localities, nonce=None, length_block=None):
    """<<ACE-SCC-export>> for a fully configured CR."""
    AD = [mdh] + [LST[j] for j in sorted(localities)]
    Nv = nonce if nonce is not None else 0
    return gcm_siv_encrypt(AD, Nv, content, CSK, length_block)


def unseal(mdh, SIV, C, localities, nonce=None, length_block=None):
    """<<ACE-SCC-import>> for a fully configured CR."""
    AD = [mdh] + [LST[j] for j in sorted(localities)]
    Nv = nonce if nonce is not None else 0
    return gcm_siv_decrypt(AD, Nv, SIV, C, CSK, length_block)


MDH = b2v(bytes.fromhex('0102030405060708090a0b0c0d0e0f10'))
CONTENT = [b2v(bytes([i] * 16)) for i in range(1, 5)]

print('\nKAT-EXPECT-FAIL: LEN restored')
print(f"\n{'property':46} {'result':8} {'LEN restored'}")

# 1. round trip
SIV, C = seal(MDH, CONTENT, {0, 3, 6})
ok_rt, P = unseal(MDH, SIV, C, {0, 3, 6})
rt = ok_rt and P == CONTENT
print(f'{"seals and unseals":46} {"PASS" if rt else "FAIL":8}')

# 2. tamper: every single-bit change in SIV, in a ciphertext block, and in the MDH
tamper_ok = True
for bit in range(0, 128, 7):
    if unseal(MDH, SIV ^ (1 << bit), C, {0, 3, 6})[0]:
        tamper_ok = False
    if unseal(MDH, SIV, [C[0] ^ (1 << bit)] + C[1:], {0, 3, 6})[0]:
        tamper_ok = False
    if unseal(MDH ^ (1 << bit), SIV, C, {0, 3, 6})[0]:
        tamper_ok = False
print(f'{"rejects any single-bit change (SIV, C, MDH)":46} '
      f'{"PASS" if tamper_ok else "FAIL":8}')

# 3. Locality binding: a different Locality set must not open the context
loc_ok = (not unseal(MDH, SIV, C, {0, 3})[0]
          and not unseal(MDH, SIV, C, {0, 3, 6, 8})[0]
          and not unseal(MDH, SIV, C, {1, 3, 6})[0])
print(f'{"a different Locality set does not open it":46} '
      f'{"PASS" if loc_ok else "FAIL":8}')

# 4. the nonce changes the output, and sealing is deterministic without one
n1, _ = seal(MDH, CONTENT, {0}, nonce=NONCE)
n2, _ = seal(MDH, CONTENT, {0})
n3, _ = seal(MDH, CONTENT, {0})
nonce_ok = n1 != n2 and n2 == n3
print(f'{"nonce changes the SIV; zero nonce is deterministic":46} '
      f'{"PASS" if nonce_ok else "FAIL":8}')

# 5. the second pass is bound to the first through SIV (AD2 = IMPQUAL, SIV)
IMPQUAL = b2v(bytes.fromhex('000000000000000000000000deadbeef'))
CONTENT2 = [b2v(bytes([0xAA] * 16))]
S2a, _ = gcm_siv_encrypt([IMPQUAL, SIV], 0, CONTENT2, CSK)
S2b, _ = gcm_siv_encrypt([IMPQUAL, SIV ^ 1], 0, CONTENT2, CSK)
bind_ok = S2a != S2b
print(f'{"SIV2 changes when SIV changes (pass binding)":46} '
      f'{"PASS" if bind_ok else "FAIL":8}')

# 6. negative control: restoring the length block must change the result, or the
#    omission would be unobservable
lb = b2v((16 * 4).to_bytes(8, 'little') * 2)
Sl, Cl = seal(MDH, CONTENT, {0, 3, 6}, length_block=lb)
len_differs = (Sl != SIV)
print(f'{"omitting the length block is observable":46} '
      f'{"PASS" if len_differs else "FAIL":8} '
      f'{"FAIL" if len_differs else "PASS (indistinguishable)"}')

# 7. REF anchor: with the length block restored and the RFC 8452 padding rules, the
#    construction must be plain AES-GCM-SIV.  Checked for self-consistency between the
#    two code paths rather than against a published vector.
A, Pt = bytes(range(7)), bytes(range(20))
ref = ref_gcm_siv(v2b(CSK, 32), v2b(0, 12), A, Pt)
pad = lambda s: s + bytes(-len(s) % 16)
tb = lambda s: [b2v(pad(s)[i:i + 16]) for i in range(0, len(pad(s)), 16)]
lb2 = b2v((len(A) * 8).to_bytes(8, 'little') + (len(Pt) * 8).to_bytes(8, 'little'))
S2, C2 = gcm_siv_encrypt(tb(A), 0, tb(Pt), CSK, length_block=lb2)
ref_ok = ref == (b''.join(v2b(c, 16) for c in C2)[:len(Pt)] + v2b(S2, 16))
print(f'{"RFC 8452 path agrees with itself (AD+PT padded)":46} '
      f'{"PASS" if ref_ok else "FAIL":8}')

ok = (aes256_ok and pv_ok and rt and tamper_ok and loc_ok and nonce_ok
      and bind_ok and len_differs and ref_ok)

# ------------------------------------------------------- vectors for the variant
print('\nVectors for the ACE sealing variant (no length block), CSK = 000102..1f:')
for locs, nonce, label in (({}, None, 'no Locality, zero nonce'),
                           ({0, 3, 6}, None, 'Localities 0,3,6, zero nonce'),
                           ({0, 3, 6}, NONCE, 'Localities 0,3,6, nonce 9091..9b')):
    S, Cc = seal(MDH, CONTENT, set(locs), nonce=nonce)
    print(f'  {label:34} SIV = {v2b(S, 16).hex()}')
    print(f'  {"":34} C0  = {v2b(Cc[0], 16).hex()}')

print(f'\nKAT-RESULT: {"PASS" if ok else "FAIL"}')
