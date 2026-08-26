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

# --- ACE model: convention = byte i at bits [8i+7:8i]; @ puts left operand high
def ace_galoismul(a, b):              # Galoismul per ACE conventions (bswap into 38D view)
    return b2v(gmul(v2b(a, 16), v2b(b, 16)))

def ace_gcm(K, IV, A, P, len_block_ad_first_bytes=True, ctr_high=True):
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
         if len_block_ad_first_bytes else \
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
print("KAT-EXPECT-FAIL: ACE(len swapped)")   # negative controls: the wrong
print("KAT-EXPECT-FAIL: ACE(ctr low)")        # transcriptions must fail
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


# ==================================================================================
# Extension: IV lengths other than 96 bits (finding C2), plaintexts that are not a
# whole number of blocks (finding C4), and survival of the counter across an
# export/import (finding C1).
#
# The classic vectors above use a 96-bit IV and a block-aligned plaintext, so they
# exercise neither of the two paths the specification got wrong.  REF is anchored by
# them and is then used as the oracle for the cases they do not reach.
# ==================================================================================

def ref_j0(K, IV):
    """SP 800-38D 7.1: J0 for any IV length."""
    if len(IV) == 12:
        return IV + b'\x00\x00\x00\x01'
    H = aes_encrypt(K, bytes(16))
    pad = lambda s: s + bytes((-len(s)) % 16)
    return ghash(H, pad(IV) + bytes(8) + (len(IV) * 8).to_bytes(8, 'big'))


def ref_gcm2(K, IV, A, P):
    """REF GCM with an IV of any length and a plaintext of any length."""
    E = lambda b: aes_encrypt(K, b)
    H, J0 = E(bytes(16)), ref_j0(K, IV)
    inc32 = lambda b: b[:12] + ((int.from_bytes(b[12:], 'big') + 1) % 2**32).to_bytes(4, 'big')
    C, cb = b'', J0
    for i in range(0, len(P), 16):
        cb = inc32(cb)
        blk = P[i:i + 16]
        C += bytes(x ^ y for x, y in zip(blk, E(cb)[:len(blk)]))
    pad = lambda s: s + bytes((-len(s)) % 16)
    S = ghash(H, pad(A) + pad(C)
              + (len(A) * 8).to_bytes(8, 'big') + (len(C) * 8).to_bytes(8, 'big'))
    return C, bytes(x ^ y for x, y in zip(S, E(J0)))


def ace_j0(K, IV, reversed_len_block=False):
    """State _Set_Aux_Value_ of <<ACE-GCM-mode>> in the ACE value model.

    reversed_len_block reinstates `0^64 @ bswap(bin(8 len,64))`, the form the specification
    used to carry, as a negative control for finding C2.
    """
    auth_key = b2v(aes_encrypt(K, bytes(16)))
    n = len(IV)
    if n * 8 == 96:                                  # J0 <- bswap(bin(1,32)) @ J0[95:0]
        return cat((int.from_bytes((1).to_bytes(4, 'big'), 'little'), 32), (b2v(IV), 96))
    J0, block_base = 0, 0
    for i in range(0, n, 16):                        # process_VLI over the IV
        chunk = IV[i:i + 16]
        J0 ^= b2v(chunk.ljust(16, b'\0'))
        if len(chunk) == 16:
            J0 = ace_galoismul(J0, auth_key)
            block_base = 0
        else:
            block_base = len(chunk)
    if block_base != 0:                              # finalize()
        J0 = ace_galoismul(J0, auth_key)
    be = int.from_bytes((n * 8).to_bytes(8, 'big'), 'little')
    lenblk = cat((0, 64), (be, 64)) if reversed_len_block else cat((be, 64), (0, 64))
    J0 ^= lenblk
    return ace_galoismul(J0, auth_key)


def ace_gcm2(K, IV, A, P, reversed_len_block=False):
    """GCM as <<ACE-GCM-mode>> now specifies it, for any IV and plaintext length."""
    auth_key = b2v(aes_encrypt(K, bytes(16)))
    tag = 0
    def absorb(x):
        nonlocal tag
        tag = ace_galoismul(tag ^ x, auth_key)
    J0 = ace_j0(K, IV, reversed_len_block)
    start = sl(J0, 127, 96)
    blk_of = lambda c32: cat((c32, 32), (sl(J0, 95, 0), 96))
    def bump(c32):
        n = (int.from_bytes(v2b(c32, 4), 'big') + 1) % 2**32
        return int.from_bytes(n.to_bytes(4, 'big'), 'little')
    for i in range(0, len(A), 16):                   # caller zero-fills the last AD block
        absorb(b2v(A[i:i + 16].ljust(16, b'\0')))
    C, c = b'', start
    for i in range(0, len(P), 16):                   # _Encrypt_ / _Enc_Last_Block_
        c = bump(c)
        blk = P[i:i + 16]
        ct = b2v(blk.ljust(16, b'\0')) ^ b2v(aes_encrypt(K, v2b(blk_of(c), 16)))
        ct = sl(ct, len(blk) * 8 - 1, 0)             # keystream past the end is dropped
        C += v2b(ct, len(blk))
        absorb(ct)                                   # the zero-padded ciphertext
    la, lc = len(A) * 8, len(P) * 8
    absorb(cat((int.from_bytes(lc.to_bytes(8, 'big'), 'little'), 64),
               (int.from_bytes(la.to_bytes(8, 'big'), 'little'), 64)))
    return C, v2b(tag ^ b2v(aes_encrypt(K, v2b(blk_of(start), 16))), 16)


K = bytes.fromhex('feffe9928665731c6d6a8f9467308308')
BIG = bytes(range(256)) * 2

print('\nKAT-EXPECT-FAIL: reversed len block')
print(f"\n{'|IV| bytes':13} {'|A|':5} {'|P|':5} {'REF vs ACE':12} {'reversed len block'}")
iv_ok, c2_caught = True, False
for ivlen in (1, 8, 12, 15, 16, 17, 60, 64, 128):
    for alen, plen in ((0, 0), (20, 60), (16, 16), (5, 1), (32, 47), (17, 33)):
        IV, A, P = BIG[:ivlen], BIG[8:8 + alen], BIG[64:64 + plen]
        r = ref_gcm2(K, IV, A, P)
        a = ace_gcm2(K, IV, A, P)
        if r != a:
            iv_ok = False
        if ivlen != 12:
            if ref_gcm2(K, IV, A, P) != ace_gcm2(K, IV, A, P, reversed_len_block=True):
                c2_caught = True
    IV, A, P = BIG[:ivlen], BIG[8:28], BIG[64:124]
    same = ref_gcm2(K, IV, A, P) == ace_gcm2(K, IV, A, P)
    rev = ref_gcm2(K, IV, A, P) != ace_gcm2(K, IV, A, P, reversed_len_block=True)
    print(f'{ivlen:13} {20:5} {60:5} {"PASS" if same else "FAIL":12} '
          f'{"FAIL" if rev else ("n/a (96-bit IV)" if ivlen == 12 else "PASS (no effect)")}')

# ---- finding C1: the counter must survive an export and re-import mid-message ----
# The Serialized Context of <<ACE-GCM-mode>> lists key, J0, tag, start_ctr and
# last_blk_len.  Round-tripping only those fields must not change the result: if the
# running counter were not among them, the resumed run would repeat counter values.
SERIALIZED = ('key', 'J0', 'tag', 'start_ctr', 'last_blk_len')


def ace_gcm_resumable(K, IV, A, P, export_after):
    """Encrypt, but export and re-import the CC after `export_after` plaintext blocks,
    carrying across only the fields the Serialized Context names."""
    auth_key = b2v(aes_encrypt(K, bytes(16)))
    J0 = ace_j0(K, IV)
    st = {'key': K, 'J0': J0, 'tag': 0,
          'start_ctr': int.from_bytes(v2b(sl(J0, 127, 96), 4), 'big'),
          'last_blk_len': 0}
    for i in range(0, len(A), 16):
        st['tag'] = ace_galoismul(st['tag'] ^ b2v(A[i:i + 16].ljust(16, b'\0')), auth_key)
    C = b''
    for n, i in enumerate(range(0, len(P), 16)):
        if n == export_after:                        # export, then re-import
            st = {k: st[k] for k in SERIALIZED}      # nothing else survives
            auth_key = b2v(aes_encrypt(st['key'], bytes(16)))   # recomputed on import
        J0 = st['J0']
        c = (int.from_bytes(v2b(sl(J0, 127, 96), 4), 'big') + 1) % 2**32
        J0 = cat((int.from_bytes(c.to_bytes(4, 'big'), 'little'), 32), (sl(J0, 95, 0), 96))
        st['J0'] = J0
        blk = P[i:i + 16]
        ct = b2v(blk.ljust(16, b'\0')) ^ b2v(aes_encrypt(st['key'], v2b(J0, 16)))
        ct = sl(ct, len(blk) * 8 - 1, 0)
        C += v2b(ct, len(blk))
        st['tag'] = ace_galoismul(st['tag'] ^ ct, auth_key)
    la, lc = len(A) * 8, len(P) * 8
    st['tag'] = ace_galoismul(st['tag'] ^ cat(
        (int.from_bytes(lc.to_bytes(8, 'big'), 'little'), 64),
        (int.from_bytes(la.to_bytes(8, 'big'), 'little'), 64)), auth_key)
    mask = b2v(aes_encrypt(st['key'], v2b(cat(
        (int.from_bytes(st['start_ctr'].to_bytes(4, 'big'), 'little'), 32),
        (sl(st['J0'], 95, 0), 96)), 16)))
    return C, v2b(st['tag'] ^ mask, 16)


IV, A, P = BIG[:12], BIG[8:28], BIG[64:124]
base = ref_gcm2(K, IV, A, P)
resume_ok = all(ace_gcm_resumable(K, IV, A, P, k) == base for k in range(5))
print(f'\ncounter and tag survive export/import after each of 4 blocks : '
      f'{"PASS" if resume_ok else "FAIL"}')

ok = iv_ok and c2_caught and resume_ok
print(f'\nACE matches REF over 9 IV lengths x 6 AD/PT length pairs : {iv_ok}')
print(f'reversed length block is caught for a non-96-bit IV      : {c2_caught}')
print(f'state named by the Serialized Context suffices to resume : {resume_ok}')
print(f'\nKAT-RESULT: {"PASS" if ok else "FAIL"}')
