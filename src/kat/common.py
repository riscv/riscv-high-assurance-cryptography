"""Shared utilities for the KLEE KAT suite.

Values are little-endian bit strings in Python ints (Zkl-notation.adoc): byte i of a
string is bits [8i+7:8i]; `cat` is `@` (left operand most significant).  Also: AES,
GHASH/POLYVAL arithmetic, XTS/OCB doublings, the MDH layout, the State constants and
the reporting helpers every harness uses.  Run directly for the self-tests.
"""

import sys

MASK128 = (1 << 128) - 1

# ---------------------------------------------------------------- notation

def b2v(b: bytes) -> int:
    """Byte string -> KLEE value (byte i at bits [8i+7:8i])."""
    return int.from_bytes(b, 'little')

def v2b(v: int, n: int) -> bytes:
    """KLEE value -> byte string of n bytes."""
    return v.to_bytes(n, 'little')

def sl(v: int, hi: int, lo: int) -> int:
    """Bit slice V[hi:lo], both inclusive."""
    return (v >> lo) & ((1 << (hi - lo + 1)) - 1)

def cat(*parts) -> int:
    """cat((A, wa), (B, wb), ...) = A @ B @ ... ; the FIRST part is most significant."""
    v = 0
    for val, w in parts:
        v = (v << w) | (val & ((1 << w) - 1))
    return v

def bswap(v: int, n: int) -> int:
    """Reverse the byte order of the n-byte value v (the spec's bswap)."""
    return int.from_bytes(v.to_bytes(n, 'little'), 'big')

def bin_(n: int, m: int) -> int:
    """The spec's bin(n, m): m-bit little-endian representation as a value."""
    return n & ((1 << m) - 1)

def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ---------------------------------------------------------------- GF(2^8) and AES

def _gmul8(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r

def _rol8(x: int, s: int) -> int:
    return ((x << s) | (x >> (8 - s))) & 0xFF

def _make_sbox():
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if _gmul8(x, y) == 1:
                inv[x] = y
                break
    sbox = []
    for x in range(256):
        b = inv[x]
        s = b ^ _rol8(b, 1) ^ _rol8(b, 2) ^ _rol8(b, 3) ^ _rol8(b, 4) ^ 0x63
        sbox.append(s)
    return sbox

SBOX = _make_sbox()
INV_SBOX = [0] * 256
for _i, _s in enumerate(SBOX):
    INV_SBOX[_s] = _i

def _key_expand(key: bytes):
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rcon
            rcon = _gmul8(rcon, 2)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[x] for x in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    rks = []
    for r in range(nr + 1):
        rks.append(bytes(sum(w[4 * r:4 * r + 4], [])))
    return rks, nr

def _add_rk(s, rk):
    return [a ^ b for a, b in zip(s, rk)]

def aes_encrypt(key: bytes, block: bytes) -> bytes:
    assert len(block) == 16
    rks, nr = _key_expand(key)
    s = list(block)
    s = _add_rk(s, rks[0])
    for r in range(1, nr + 1):
        s = [SBOX[x] for x in s]                              # SubBytes
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]    # ShiftRows (col-major flat)
        if r != nr:                                           # MixColumns
            t = []
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                t += [
                    _gmul8(col[0], 2) ^ _gmul8(col[1], 3) ^ col[2] ^ col[3],
                    col[0] ^ _gmul8(col[1], 2) ^ _gmul8(col[2], 3) ^ col[3],
                    col[0] ^ col[1] ^ _gmul8(col[2], 2) ^ _gmul8(col[3], 3),
                    _gmul8(col[0], 3) ^ col[1] ^ col[2] ^ _gmul8(col[3], 2),
                ]
            s = t
        s = _add_rk(s, rks[r])
    return bytes(s)

def aes_decrypt(key: bytes, block: bytes) -> bytes:
    assert len(block) == 16
    rks, nr = _key_expand(key)
    s = list(block)
    s = _add_rk(s, rks[nr])
    for r in range(nr - 1, -1, -1):
        s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]    # InvShiftRows
        s = [INV_SBOX[x] for x in s]                          # InvSubBytes
        s = _add_rk(s, rks[r])
        if r != 0:                                            # InvMixColumns
            t = []
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                t += [
                    _gmul8(col[0], 14) ^ _gmul8(col[1], 11) ^ _gmul8(col[2], 13) ^ _gmul8(col[3], 9),
                    _gmul8(col[0], 9) ^ _gmul8(col[1], 14) ^ _gmul8(col[2], 11) ^ _gmul8(col[3], 13),
                    _gmul8(col[0], 13) ^ _gmul8(col[1], 9) ^ _gmul8(col[2], 14) ^ _gmul8(col[3], 11),
                    _gmul8(col[0], 11) ^ _gmul8(col[1], 13) ^ _gmul8(col[2], 9) ^ _gmul8(col[3], 14),
                ]
            s = t
    return bytes(s)

# ---------------------------------------------------------------- GHASH field (SP 800-38D 6.3)

def gmul_ghash(X: bytes, Y: bytes) -> bytes:
    """Multiplication in the GHASH field on 16-byte big-endian-string operands."""
    x = int.from_bytes(X, 'big')
    z = 0
    v = int.from_bytes(Y, 'big')
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z.to_bytes(16, 'big')

def kl_galoismul(a: int, b: int) -> int:
    """The spec's Galoismul on KLEE values (byte order forward, bits reflected per byte)."""
    return b2v(gmul_ghash(v2b(a, 16), v2b(b, 16)))

# ---------------------------------------------------------------- POLYVAL (RFC 8452)

_G_POLYVAL = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1

def _clmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        b >>= 1
    return r

def montmul(a: int, b: int) -> int:
    """The spec's Montmul: a * b * x^-128 in GF(2^128) mod x^128+x^127+x^126+x^121+1,
    on KLEE values under the fully little-endian POLYVAL representation (V[k] = coeff of x^k)."""
    p = _clmul(a, b)
    for _ in range(128):
        if p & 1:
            p ^= _G_POLYVAL
        p >>= 1
    if p >> 128:
        p ^= _G_POLYVAL
    return p & MASK128

def mulx_polyval(v: int) -> int:
    """RFC 8452's mulX_POLYVAL on a KLEE value."""
    c = v >> 127
    v = (v << 1) & MASK128
    if c:
        v ^= (1 << 127) | (1 << 126) | (1 << 121) | 1
    return v

# ---------------------------------------------------------------- XTS / OCB doublings

def update_mask(v: int) -> int:
    """XEX/XTS mask update (little-endian doubling), per KLEE-XEX-XTS-modes."""
    c = v >> 127
    v = (v << 1) & MASK128
    if c:
        v ^= 0x87
    return v

def double_ocb(v: int) -> int:
    """OCB3/CMAC doubling over the big-endian string view: bswap(update_mask(bswap(S)))."""
    return bswap(update_mask(bswap(v, 16)), 16)

# ---------------------------------------------------------------- MDH and States

# <<KLEE-metadata-header>>: (name, hi, lo); None marks a Reserved field.
MDH_FIELDS = [
    ('Machine', 11, 0), ('MachinePolicy', 13, 12), ('MachineExtension', 15, 14),
    ('SCProtection', 17, 16), ('State', 23, 18), ('StateExtension', 27, 24),
    ('KeyType', 29, 28), (None, 31, 30), ('AuxDataLen', 45, 32), (None, 46, 46),
    ('ADSDropped', 47, 47), ('MachineUse', 61, 48), ('Version', 63, 62),
    ('UsagePolicy', 68, 64), ('Locality', 77, 69), (None, 79, 78),
    ('AuxInfo', 95, 80), ('ExpirationDate', 115, 96), (None, 127, 116),
]
MDH_FIELD = {n: (hi, lo) for n, hi, lo in MDH_FIELDS if n}

def mdh_pack(**f) -> int:
    v = 0
    for n, x in f.items():
        hi, lo = MDH_FIELD[n]
        assert 0 <= x < 1 << (hi - lo + 1), (n, x)
        v |= x << lo
    return v

def mdh_unpack(v: int) -> dict:
    return {n: sl(v, hi, lo) for n, (hi, lo) in MDH_FIELD.items()}

def mdh_reserved(v: int) -> int:
    """The Reserved bits of an MDH, OR-ed together (0 if all clear)."""
    return any(sl(v, hi, lo) for n, hi, lo in MDH_FIELDS if n is None)

# <<KLEE-State-field>>, <<KLEE-state-constants-symmetric>>
KL_STATE_UNCONFIGURED, KL_STATE_READY = 0, 1
KL_STATE_OPERATE = KL_STATE_HASH_ABSORB = 2
(KL_STATE_HASH_LAST_BLOCK, KL_STATE_HASH_FINALIZE, KL_STATE_HASH_VERIFY,
 KL_STATE_HASH_OUTPUT, KL_STATE_ENCRYPT, KL_STATE_DECRYPT, KL_STATE_ENC_LAST_BLOCK,
 KL_STATE_DEC_LAST_BLOCK, KL_STATE_ENC_TAG_FINALIZE, KL_STATE_DEC_TAG_FINALIZE,
 KL_STATE_SET_AUX_VALUE, KL_STATE_SET_AUX_VALUE_2, KL_STATE_SET_KEY) = range(3, 16)
KL_STATE_SUCCESS, KL_STATE_FAILURE = 46, 47
(KL_STATE_UNSUPPORTED, KL_STATE_INVALID, KL_STATE_OUT_OF_MEMORY, KL_STATE_MGMT_AUTH,
 KL_STATE_PRIV_VIOLATION, KL_STATE_EXPIRED) = range(48, 54)
ERROR_STATES = range(48, 56)
(KL_CFG_PROVISIONING, KL_CFG_EXPORTING, KL_CFG_IMPORTING, KL_CFG_PPI_EXPORTING,
 KL_CFG_PPI_IMPORTING) = range(56, 61)
KL_CFG_MANAGEMENT_END = 63

class IllegalInstruction(Exception):
    pass

# ---------------------------------------------------------------- reporting

_counts = {'pass': 0, 'fail': 0}

def section(title: str):
    print(f'\n== {title}')

def check(name: str, ok, got=None, want=None) -> bool:
    """Record one check.  With `got`/`want`, ok is taken as got == want."""
    if got is not None or want is not None:
        ok = got == want
    ok = bool(ok)
    _counts['pass' if ok else 'fail'] += 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok and (got is not None or want is not None):
        print(f'        got  {got}\n        want {want}')
    return ok

def control(name: str, fired) -> bool:
    """Negative control: a deliberately wrong formulation must be caught."""
    return check(f'negative control fired: {name}', fired)

def info(text: str):
    print(f'INFO  {text}')

def spec_note(text: str):
    print(f'SPEC-NOTE  {text}')

def raises(fn, *a, exc=IllegalInstruction, **kw) -> bool:
    try:
        fn(*a, **kw)
    except exc:
        return True
    return False

def done():
    """Print the verdict line read by run-kats.py and exit accordingly."""
    ok = _counts['fail'] == 0
    print(f"\n{_counts['pass']} passed, {_counts['fail']} failed")
    print(f"KAT-RESULT: {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)

# ---------------------------------------------------------------- self-tests

def selftest(verbose: bool = False) -> bool:
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        if verbose or not good:
            print(f"  {'PASS' if good else 'FAIL'}  {name}")
            if not good:
                print(f"        got  {got}")
                print(f"        want {want}")

    # FIPS 197 Appendix C
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    k128 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    k192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    k256 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    chk("AES-128 FIPS197 C.1", aes_encrypt(k128, pt).hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
    chk("AES-192 FIPS197 C.2", aes_encrypt(k192, pt).hex(), "dda97ca4864cdfe06eaf70a0ec0d7191")
    chk("AES-256 FIPS197 C.3", aes_encrypt(k256, pt).hex(), "8ea2b7ca516745bfeafc49904b496089")
    for k in (k128, k192, k256):
        chk(f"AES-{len(k)*8} decrypt inverse", aes_decrypt(k, aes_encrypt(k, pt)).hex(), pt.hex())

    # RFC 8452 Appendix A: mulX_POLYVAL and POLYVAL
    chk("mulX_POLYVAL(1)",
        v2b(mulx_polyval(b2v(bytes.fromhex("01000000000000000000000000000000"))), 16).hex(),
        "02000000000000000000000000000000")
    chk("mulX_POLYVAL(sample)",
        v2b(mulx_polyval(b2v(bytes.fromhex("9c98c04df9387ded828175a92ba652d8"))), 16).hex(),
        "3931819bf271fada0503eb52574ca572")
    H = b2v(bytes.fromhex("25629347589242761d31f826ba4b757b"))
    X1 = b2v(bytes.fromhex("4f4f95668c83dfb6401762bb2d01a262"))
    X2 = b2v(bytes.fromhex("d1a24ddd2721d006bbe45f20d3c9f362"))
    acc = montmul(0 ^ X1, H)
    acc = montmul(acc ^ X2, H)
    chk("POLYVAL RFC8452 A", v2b(acc, 16).hex(), "f7a3b47b846119fae5b7866cf5e5b77e")

    # notation sanity: cat/@ and bswap
    chk("cat(A@B)", cat((0xAB, 8), (0xCD, 8)), 0xABCD)
    chk("bswap", bswap(0x0102030405060708, 8), 0x0807060504030201)

    # GHASH sanity: H from the zero key, per SP 800-38D test case 1 intermediate
    Hs = aes_encrypt(bytes(16), bytes(16))
    chk("GHASH H (38D tc1)", Hs.hex(), "66e94bd4ef8a2c3b884cfa59ca342b2e")

    # doubling sanity: CMAC K1 for the all-zero AES-128 key (SP 800-38B D.1)
    L = aes_encrypt(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"), bytes(16))
    K1 = double_ocb(b2v(L))
    chk("CMAC K1 (38B D.1)", v2b(K1, 16).hex(), "fbeed618357133667c85e08f7236a8de")
    return ok

if __name__ == "__main__":
    good = selftest(verbose=True)
    print("KAT-RESULT:", "PASS" if good else "FAIL")
    sys.exit(0 if good else 1)
