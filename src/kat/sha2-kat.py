#!/usr/bin/env pypy3.12
"""KAT: SHA-2 Machines (SHA-224/256/384/512/512-224/512-256) of Zkl-ISA-machines.adoc, run through the executable
model hash_model.py with references hash_ref.py (FIPS 180-4, derived constants) and hashlib."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hash_util import *
import hash_ref as R
import common
t0 = time.time()
ABC = {'SHA-224': '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
       'SHA-256': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
       'SHA-384': 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
       'SHA-512': 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
       'SHA-512/224': '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa',
       'SHA-512/256': '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23'}
M448 = b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
M896 = b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'
LONG = {'SHA-256': (M448, '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'),
        'SHA-224': (M448, '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525'),
        'SHA-512': (M896, '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'),
        'SHA-384': (M896, '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039')}
section('FIPS 180-4 vectors through the KLE model')
for fn in R.SHA2:
    mk = lambda fn=fn: Locker(fn)
    ref = lambda m, n, fn=fn: R.sha2(fn, m, n)
    check('%s reference "abc" = FIPS 180-4' % fn, R.sha2(fn, b'abc').hex() == ABC[fn] and oracle(fn, b'abc').hex() == ABC[fn])
    vector(fn, mk, b'abc', 24, ref, nlabel='"abc"')
    vector(fn, mk, b'', 0, ref, nlabel='empty')
    if fn in LONG:
        m, h = LONG[fn]; check('%s reference of the %d-bit FIPS message' % (fn, 8 * len(m)), R.sha2(fn, m).hex() == h)
        vector(fn, mk, m, 8 * len(m), ref, nlabel='FIPS long')
    # block boundaries and bit-level messages (FIPS 180-4 5.1.1/5.1.2 padding corner cases)
    w, b, t = R.SHA2[fn]
    for n in sorted({1, 7, 8, 9, b - 2 * w - 1, b - 2 * w, b - 2 * w + 1, b - 1, b, b + 1, 2 * b - 2 * w, 2 * b + 13, 3 * b - 3}):
        m = msg_of((n + 7) // 8)
        vector(fn, mk, m, n, ref, nlabel='boundary')
        check('%s %d bits: reference = hashlib where whole bytes' % (fn, n), n % 8 or R.sha2(fn, m, n) == oracle(fn, m))
section('Generic sequence (KLE-pseudocode-hash): sizes x chunk plans')
for fn in ('SHA-256', 'SHA-512'):
    for nb in (1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 200, 513):
        vector(fn, lambda fn=fn: Locker(fn), msg_of(nb), 8 * nb, lambda m, n, fn=fn: oracle(fn, m), nlabel='oracle hashlib', plans=('chunks', 'export', 'last'))
for fn in R.SHA2: machine_checks(fn, lambda m, fn=fn: oracle(fn, m))
section('Software example KLE-pseudocode-ECDH-KDF: P-256 ECDH, SP 800-56C one-step KDF with SHA-256, AES-256 key')
from ecc_machine import EccLocker, SSCAL, S2ND, PMUL, RDY
import ecc_model as EM
C = EM.Wei('secp256r1'); _, d, Q, Z = V0 = __import__('ecc_vectors').ECDH[0]; fi = b'FixedInfo'
Qb = Q[0].to_bytes(32, 'little') + Q[1].to_bytes(32, 'little'); dG = C.mul(d, C.G)
def ecdh_kdf(ext, Qb=Qb):
    """the listing: a random Scalar, its public key, [d]Q, then K = SHA-256(00000001 || Z || FixedInfo) into a key"""
    E = EccLocker('secp256r1', policy=0, ext=ext, rbg=lambda n: (d - 1).to_bytes(n, 'big'))   # the RBG gives d (FIPS 186-5 A.2.2)
    E.setst(SSCAL, 'B', 1); E.setst(PMUL); E.exec_D(); pub = E.exec_out(64)
    E.setst(RDY); E.setst(S2ND); E.exec_in(Qb); E.setst(PMUL); E.exec_D()
    H = Locker('SHA-256'); H.setst('absorb'); H.exec('B', b'\0\0\0\1')
    z = E.derive(); ok = z != 'invalid' and H.derive(z, sealed=E.sealed); H.exec('B', fi); H.setst('output')
    K = Key(32); ok = ok and derive_out(H, K, 32); return E, H, K, pub, ok
for ext in (0, 2):
    E, H, K, pub, ok = ecdh_kdf(ext)
    check('%s: the public key is readable, K = SHA-256(00000001 || Z || FixedInfo) over CAVP CDH P-256 COUNT=0' % ('sealed' if ext else 'unsealed'),
          ok and pub == dG[0].to_bytes(32, 'little') + dG[1].to_bytes(32, 'little') and K.key == hashlib.sha256(b'\0\0\0\1' + Z + fi).digest())
    check('... K1 and K0 end in Success, and K0 is %s' % ('sealed' if ext else 'not sealed'), E.state == 54 and H.st == 'Success' and H.sealed == bool(ext))
E, H, K, pub, ok = ecdh_kdf(0, Qb[:63] + bytes([Qb[63] ^ 1]))
check('a Q off the curve: Point_Mul -> Failure, the kl.derive leaves K1 outside Success, which the listing checks', not ok and E.state != 54)

section('Negative controls')
fn = 'SHA-256'; good = oracle(fn, b'abc')
w, bb, t = R.SHA2[fn]
Hs = R.sha2_iv(fn); blk = b'abc\x80' + bytes(59) + (24).to_bytes(8, 'big') if False else b'abc\x80' + bytes(52) + (24).to_bytes(8, 'big')
wrong = R.sha2_compress(32, Hs, [int.from_bytes(blk[i:i + 4], 'little') for i in range(0, 64, 4)])
control('message words without bswap give another digest', b''.join(h.to_bytes(4, 'big') for h in wrong) != good)
L = Locker(fn); L.setst('absorb'); L.exec('B', b'abcdefgh', 4); A = L.cum
L = Locker(fn); L.setst('absorb'); L.exec('B', b'abcdefgh', 32)
control('klstart in bits (32 instead of 4) skips the whole window instead of resuming', A == 32 and L.cum == 0)
control('a caller-padded message does not give the digest of the message', oracle(fn, b'abc\x80' + bytes(52) + (24).to_bytes(8, 'big')) != good)
control('digest of a bit-granular piece without bit-1 placement differs', R.sha2(fn, b'\xa0', 3) != R.sha2(fn, b'\x00', 3))
info('%d checks, %.1fs' % (common.N_PASS + common.N_FAIL, time.time() - t0))
common.done()
