"""CTR and XCTR keystream generation, and the ACE formulation of them.

This is the test that finding M6 needed.  The specification originally built the counter
block as `keystream_block(IV @ ctr)`, which under <<ACE-conventions>> places the counter
in the *first* octets and in little-endian order.  SP 800-38A — and GCM, in this same
document — put it in the *trailing* octets as a big-endian integer, which is
`keystream_block(bswap(ctr) @ IV)`.  The X modes are different and were always right:
there the counter is a full block, combined by `xor` rather than by position, and stays
little-endian.

  REF   CTR written directly from SP 800-38A: counter block = nonce || bswap(bin(ctr, j))
  ACE   the formulas as ace-ISA-algorithms.adoc now gives them, in the ACE value model
  OLD   `IV @ ctr`, the formulation the specification used to carry (negative control)

REF is first anchored against the SP 800-38A F.5.1 vectors, which use a full-block
counter, and is then used as the oracle for the nonce-plus-counter split that ACE
actually specifies.
"""
import os, sys
d = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, d)
exec(open(os.path.join(d, 'ocb-kat.py')).read()
     .split('# ------------------------------------------------------------------ vectors')[0])


# --------------------------------------------------------------- REF: SP 800-38A
def ref_ctr(K, nonce, j, ctr0, P):
    """CTR with the counter in the trailing j bits of the block, big-endian.

    nonce occupies the leading (128-j) bits.  This is the arrangement of
    SP 800-38A and the one GCM uses.
    """
    out, ctr = b'', ctr0
    for i in range(0, len(P), 16):
        blk = nonce + ctr.to_bytes(j // 8, 'big')
        ks = aes_encrypt(K, blk)
        chunk = P[i:i + 16]
        out += xs(ks[:len(chunk)], chunk)
        ctr = (ctr + 1) % (1 << j)
    return out


def ref_xctr(K, iv, ctr0, P):
    """XCTR: block = IV xor bin(ctr, 128), the counter little-endian and full width."""
    out, ctr = b'', ctr0
    for i in range(0, len(P), 16):
        blk = xs(iv, ctr.to_bytes(16, 'little'))
        ks = aes_encrypt(K, blk)
        chunk = P[i:i + 16]
        out += xs(ks[:len(chunk)], chunk)
        ctr = (ctr + 1) % (1 << 128)
    return out


# ----------------------------------------------- ACE: the spec's own formulation
def ace_keystream(K, IVv, n, j, nblocks, form):
    """State _Operate_ of <<ACE-keystream-modes>> in the ACE value model.

    form 'ctr' : tmp <- keystream_block(bswap(ctr) @ IV)      as now specified
    form 'old' : tmp <- keystream_block(IV @ ctr)             previous text
    form 'xctr': tmp <- keystream_block(IV xor ctr)           X modes
    Each iteration then does tick_ctr() and emits tmp.
    """
    ks, ctr = b'', 0
    for _ in range(nblocks):
        if form == 'ctr':
            blk = cat((bswap(ctr, j), j), (IVv, n))
        elif form == 'old':
            blk = cat((IVv, n), (ctr, j))
        else:
            blk = IVv ^ ctr
        ks += v2b(enc_v(K, blk), 16)
        ctr = (ctr + 1) % (1 << j)
    return ks


# ------------------------------------------------------- anchor: SP 800-38A F.5.1
KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
MSG = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'
                    'ae2d8a571e03ac9c9eb76fac45af8e51'
                    '30c81c46a35ce411e5fbc1191a0a52ef'
                    'f69f2445df4f9b17ad2b417be66c3710')
F51_CT = bytes.fromhex('874d6191b620e3261bef6864990db6ce'
                       '9806f66b7970fdff8617187bb9fffdff'
                       '5ae4df3edbd5d35e5b4f09020db03eab'
                       '1e031dda2fbe03d1792170a0f3009cee')
# F.5.1 uses a full-block counter: no nonce, j = 128, starting at f0f1..feff
anchor = ref_ctr(KEY, b'', 128, int.from_bytes(
    bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'), 'big'), MSG)
anchor_ok = anchor == F51_CT
print('CTR-AES-128 against SP 800-38A F.5.1 (REF implements the standard):',
      'PASS' if anchor_ok else 'FAIL (vector or REF suspect)')

# ------------------------------------------- differential: the split ACE specifies
print('\nKAT-EXPECT-FAIL: OLD')
print(f"\n{'n / j':12} {'blocks':7} {'REF vs ACE':12} {'OLD'}")
ctr_ok, old_caught = True, False
for n, j in ((96, 32), (64, 64), (120, 8), (32, 96)):
    for nblocks in (1, 2, 5):
        nonce = bytes(range(1, n // 8 + 1))
        IVv = b2v(nonce)                       # the IV occupies the first n/8 octets
        ref = ref_ctr(KEY, nonce, j, 0, bytes(16 * nblocks))
        ace = ace_keystream(KEY, IVv, n, j, nblocks, 'ctr')
        old = ace_keystream(KEY, IVv, n, j, nblocks, 'old')
        if ref != ace:
            ctr_ok = False
        if ref != old:
            old_caught = True
    print(f'{f"{n} / {j}":12} {"1,2,5":7} {"PASS" if ref == ace else "FAIL":12} '
          f'{"FAIL" if ref != old else "PASS (does not discriminate)"}')

# ------------------------------------------------------------------ the X modes
xctr_ok = True
for nblocks in (1, 2, 5):
    iv = bytes(range(16))
    ref = ref_xctr(KEY, iv, 0, bytes(16 * nblocks))
    ace = ace_keystream(KEY, b2v(iv), 128, 128, nblocks, 'xctr')
    if ref != ace:
        xctr_ok = False
print(f'\nXCTR (IV xor ctr, counter little-endian, full width) : '
      f'{"PASS" if xctr_ok else "FAIL"}')

# the two modes must not coincide, or the specification's distinction is vacuous
nonce = bytes(range(1, 13))
differ = (ace_keystream(KEY, b2v(nonce), 96, 32, 2, 'ctr')
          != ace_keystream(KEY, b2v(nonce + bytes(4)), 128, 128, 2, 'xctr'))
print(f'CTR and XCTR produce different keystreams           : '
      f'{"PASS" if differ else "FAIL"}')

ok = anchor_ok and ctr_ok and old_caught and xctr_ok and differ
print(f'\nREF matches SP 800-38A F.5.1                        : {anchor_ok}')
print(f'ACE (as specified) matches REF over 4 n/j splits    : {ctr_ok}')
print(f'OLD (`IV @ ctr`) is caught                          : {old_caught}')
print(f'\nKAT-RESULT: {"PASS" if ok else "FAIL"}')
