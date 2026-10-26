#!/usr/bin/env pypy3.12
"""KAT: SM3 Machine (GB/T 32905-2016) of Zkl-ISA-machines.adoc through hash_model.py; references hash_ref.py, hashlib."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hash_util import *
import hash_ref as R
import common
t0 = time.time()
mk = lambda: Locker('SM3'); ref = lambda m, n: R.sm3(m, n)
V = {b'abc': '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
     b'abcd' * 16: 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'}
section('GB/T 32905-2016 vectors through the KLE model')
for m, h in V.items():
    check('reference SM3 of %d bytes = GB/T 32905 App. A' % len(m), R.sm3(m).hex() == h and oracle('SM3', m).hex() == h)
    vector('SM3', mk, m, 8 * len(m), ref, nlabel='GB/T')
section('Bit-length messages (final piece MSB-first, bit 1 placement) and block boundaries')
for n in (0, 1, 3, 7, 8, 9, 447, 448, 449, 455, 456, 504, 511, 512, 513, 959, 1000, 1024, 1025):
    m = msg_of((n + 7) // 8); vector('SM3', mk, m, n, ref, nlabel='bits')
    check('SM3 %d bits: hashlib agrees where whole bytes' % n, n % 8 or R.sm3(m, n) == oracle('SM3', m))
section('Generic sequence (KLE-pseudocode-hash)')
for nb in (1, 55, 56, 63, 64, 65, 119, 120, 128, 300):
    vector('SM3', mk, msg_of(nb), 8 * nb, lambda m, n: oracle('SM3', m), nlabel='oracle hashlib', plans=('chunks', 'odd', 'export', 'last'))
machine_checks('SM3', lambda m: oracle('SM3', m))
section('Negative controls')
good = oracle('SM3', b'abc')
control('SM3 differs from SHA-256 (same shape, different IV and compression)', good != oracle('SHA-256', b'abc'))
w = [int.from_bytes((b'abc\x80' + bytes(60))[i:i + 4], 'little') for i in range(0, 64, 4)]; w[15] = 24 << 24
control('message words read little-endian (no bswap) give another digest', b''.join(v.to_bytes(4, 'big') for v in R.sm3_compress(R.SM3_IV, w)) != good)
control('a caller-padded message does not give the digest of the message', oracle('SM3', b'abc\x80' + bytes(52) + (24).to_bytes(8, 'big')) != good)
control('the bit string "1" differs from the byte 0x01 and 0x80 (final piece bit order)', len({R.sm3(b'\x80', 1), R.sm3(b'\x01', 1) , R.sm3(b'\x01')}) >= 2 and R.sm3(b'\x80', 1) != R.sm3(b'\x80'))
L = Locker('SM3'); L.setst('absorb'); L.exec('B', b'abcdefgh', 4); a = L.cum; L = Locker('SM3'); L.setst('absorb'); L.exec('B', b'abcdefgh', 32)
control('klstart in bits skips the window instead of resuming at byte 4', a == 32 and L.cum == 0)
info('%d checks, %.1fs' % (common.N_PASS + common.N_FAIL, time.time() - t0))
common.done()
