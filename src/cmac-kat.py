"""CMAC per SP 800-38B, and the ACE formulation of it.

This is the test that finding C3 needed.  The specification originally generated the
subkeys with `msb(L)`, the value-level `<<` and `C` xored into octet 0 — that is, the
little-endian XTS-style doubling — where SP 800-38B doubles over the *big-endian*
string.  It now uses `double`, which is the big-endian doubling already defined in
<<ACE-conventions-fields>>.

Three implementations are run:

  REF   SP 800-38B written directly on byte strings (big-endian semantics)
  ACE   the formulas as ace-ISA-algorithms.adoc now gives them, evaluated in the ACE
        value model (octet i of a string lives at bits [8i+7:8i] of an integer)
  OLD   the formulation the specification used to carry, as a negative control

A key whose L needs the reduction is what discriminates ACE from OLD, and a key for
which the two formulations happen to branch alike does not test anything.  The script
therefore searches for keys of each kind and reports both, so the discriminating power
of the test is visible rather than assumed.
"""
import os, sys
d = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, d)
exec(open(os.path.join(d, 'ocb-kat.py')).read()
     .split('# ------------------------------------------------------------------ vectors')[0])

Rb = 0x87                                  # SP 800-38B R_128


# ------------------------------------------------------------------ REF: SP 800-38B
def ref_dbl(s):
    """L << 1 over the big-endian string, xor R_128 if the first bit was 1."""
    n = int.from_bytes(s, 'big')
    n2 = (n << 1) & ((1 << 128) - 1)
    if n >> 127:
        n2 ^= Rb
    return n2.to_bytes(16, 'big')


def ref_subkeys(K):
    L = aes_encrypt(K, bytes(16))
    K1 = ref_dbl(L)
    K2 = ref_dbl(K1)
    return L, K1, K2


def ref_cmac(K, M):
    _, K1, K2 = ref_subkeys(K)
    if len(M) == 0:
        blocks, last, complete = [], b'', False
    else:
        n = (len(M) + 15) // 16
        blocks = [M[i * 16:(i + 1) * 16] for i in range(n)]
        last = blocks.pop()
        complete = len(last) == 16
    if complete:
        last = xs(last, K1)
    else:
        last = last + b'\x80' + bytes(15 - len(last))
        last = xs(last, K2)
    x = bytes(16)
    for blk in blocks:
        x = aes_encrypt(K, xs(x, blk))
    return aes_encrypt(K, xs(x, last))


# ------------------------------------------------- ACE: the spec's own formulation
def ace_subkeys_now(Kv, K):
    """gen_subkeys as the specification now reads: K1 <- double(L), K2 <- double(K1)."""
    L = enc_v(K, 0)
    K1 = ace_double(L)
    K2 = ace_double(K1)
    return L, K1, K2


def ace_subkeys_old(Kv, K):
    """The formulation the specification used to carry (negative control).

    if msb(L) == 0 then K1 <- L << 1 else K1 <- (L << 1) xor C, with msb = bit 127,
    the value-level shift, and C the bare numeral 0x87 — hence octet 0.
    """
    def step(v):
        v2 = (v << 1) & M128
        return v2 ^ 0x87 if sl(v, 127, 127) else v2
    L = enc_v(K, 0)
    K1 = step(L)
    K2 = step(K1)
    return L, K1, K2


def ace_cmac(K, M, subkeys):
    """State machine of <<ACE-CMAC-mode>> in the ACE value model.

    _Hash_Absorb_:            hash <- enc_blk(key, hash xor INPUT)
    _Hash_Absorb_Last_Block_: last_block_len == b  -> hash xor INPUT xor K1
                              otherwise            -> hash xor pad xor K2, where pad is
                              zeros(b-8-n) @ 0b10000000 @ INPUT[n-1:0]
    _Hash_Output_:            emit hash
    """
    b = 128
    _, K1, K2 = subkeys(None, K)
    blocks = len(M) * 8 // b
    rem = len(M) * 8 % b
    if rem == 0 and blocks > 0:
        blocks -= 1
        rem = b
    hash_ = 0
    for i in range(blocks):
        hash_ = enc_v(K, hash_ ^ b2v(M[i * 16:i * 16 + 16]))
    tail = M[blocks * 16:]
    INPUT = b2v(tail + bytes(16 - len(tail)))
    if rem == b:
        tmp = hash_ ^ INPUT ^ K1
    else:
        n = rem
        pad = cat((0, b - 8 - n), (0x80, 8), (sl(INPUT, n - 1, 0) if n else 0, n))
        tmp = hash_ ^ pad ^ K2
    return v2b(enc_v(K, tmp), 16)


# ---------------------------------------------------------------------- anchors
# RFC 4493 / SP 800-38B Appendix D.1, AES-128.  If one of these disagrees with REF the
# vector itself is suspect, not the specification: the line is labelled accordingly.
KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
MSG = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'
                    'ae2d8a571e03ac9c9eb76fac45af8e51'
                    '30c81c46a35ce411e5fbc1191a0a52ef'
                    'f69f2445df4f9b17ad2b417be66c3710')
ANCHORS = [
    (KEY, b'',           'bb1d6929e95937287fa37d129b756746'),
    (KEY, MSG[:16],      '070a16b46b4d4144f79bdd9dd04a287c'),
    (KEY, MSG[:40],      'dfa66747de9ae63030ca32611497c827'),
    (KEY, MSG[:64],      '51f0bebf7e3b9d92fc49741779363cfe'),
]

print('CMAC-AES-128 against the published vectors (REF implements SP 800-38B):')
anchor_ok = True
for K, M, t in ANCHORS:
    got = ref_cmac(K, M).hex()
    ok = got == t
    anchor_ok &= ok
    print(f'  |M| = {len(M):3d} octets : {"PASS" if ok else "FAIL (vector or REF suspect)"}')

# ------------------------------------------------------------------ discrimination
# The correct doubling branches on bit 7 of octet 0 of L; the old one branched on bit
# 127, the top bit of octet 15.  Keys for which those two bits differ are the ones that
# expose the defect.
disc, same = [], []
for i in range(4096):
    K = i.to_bytes(16, 'big')
    L = aes_encrypt(K, bytes(16))
    if (L[0] >> 7) != (L[15] >> 7):
        disc.append(K)
    else:
        same.append(K)
    if len(disc) >= 8 and len(same) >= 8:
        break
print(f'\nsearched keys for discriminating L: found {len(disc)} where bit 7 of octet 0 '
      f'and bit 127 differ')

print('\nKAT-EXPECT-FAIL: OLD')
print(f"\n{'case':28} {'REF vs ACE':12} {'OLD'}")
real_fail = False
old_ever_failed = False
LENS = [0, 1, 15, 16, 17, 31, 32, 40, 63, 64, 65]
for tag, keys in (('discriminating key', disc[:4]), ('non-discriminating key', same[:4])):
    for K in keys:
        for n in LENS:
            M = MSG[:n] if n <= len(MSG) else (MSG * 3)[:n]
            r = ref_cmac(K, M)
            a = ace_cmac(K, M, ace_subkeys_now)
            o = ace_cmac(K, M, ace_subkeys_old)
            if r != a:
                real_fail = True
            if r != o:
                old_ever_failed = True
    # one summary row per key class
    agree = all(ref_cmac(K, (MSG * 3)[:n]) == ace_cmac(K, (MSG * 3)[:n], ace_subkeys_now)
                for K in keys for n in LENS)
    olddiff = any(ref_cmac(K, (MSG * 3)[:n]) != ace_cmac(K, (MSG * 3)[:n], ace_subkeys_old)
                  for K in keys for n in LENS)
    print(f'{tag:28} {"PASS" if agree else "FAIL":12} '
          f'{"FAIL" if olddiff else "PASS (does not discriminate)"}')

ok = anchor_ok and not real_fail and old_ever_failed
print(f'\nREF (SP 800-38B) matches the published vectors        : {anchor_ok}')
print(f'ACE (as specified) matches REF on {len(LENS)} lengths x 8 keys : {not real_fail}')
print(f'OLD (previous text) is caught                        : {old_ever_failed}')
print(f'\nKAT-RESULT: {"PASS" if ok else "FAIL"}')
