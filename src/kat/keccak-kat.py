#!/usr/bin/env pypy3.12
"""KAT of the SHA-3 / SHAKE Machines (Type 6 Modes 0..5): Zkl-ISA-machines.adoc, KLE-SHA-3 and
KLE-hash-functions-MACs-XOFs.  Oracles: FIPS 202 published digests, hashlib, and sponge_ref (bit-level).
Run: cd src && pypy3.12 kat/keccak-kat.py"""
import hashlib
from common import *
from sponge_model import *
import sponge_ref as R

H = bytes.fromhex
FN = {'SHA3-224': hashlib.sha3_224, 'SHA3-256': hashlib.sha3_256, 'SHA3-384': hashlib.sha3_384, 'SHA3-512': hashlib.sha3_512}
XOF = {'SHAKE128': hashlib.shake_128, 'SHAKE256': hashlib.shake_256}
ALL = list(FN) + list(XOF)
def msg(n, seed=1): return hashlib.shake_128(bytes([seed])).digest(n)
def ref(kind, m, outbytes):
    h = FN.get(kind) or XOF[kind]
    return h(m).digest() if kind in FN else h(m).digest(outbytes)

def absorb(L, m, chunks=None):
    """Hash_Absorb with the message cut into the given chunk sizes (rest in one)."""
    L.setst(2, 'A'); i = 0
    for c in (chunks or []) + [len(m)]:
        if i >= len(m): break
        L.exec('B', m[i:i + c]); i += c

def digest(kind, m, chunks=None, xs=0, outlen=None):
    L = Locker(kind); absorb(L, m, chunks)
    L.setst(6, 'B' if xs else 'A', xs)
    n = outlen if outlen is not None else L.ol // 8 or L.d // 8
    o = bytearray(n); L.exec('C', out=o); return L, bytes(o)

section('Published digests (FIPS 202 examples)')
PUB = {('SHA3-224', b''): '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
       ('SHA3-256', b''): 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
       ('SHA3-256', b'abc'): '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
       ('SHA3-384', b''): '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004',
       ('SHA3-512', b''): 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
       ('SHAKE128', b''): '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
       ('SHAKE256', b''): '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'}
for (k, m), want in PUB.items():
    check('oracle %s(%r)' % (k, m), ref(k, m, len(want) // 2) == H(want))
    _, got = digest(k, m, outlen=len(want) // 2)
    check('Machine %s(%r) = published' % (k, m), got == H(want), got, H(want))

section('Machine vs reference: lengths around the rate, chunked transfers')
RATE = {k: Locker(k).b // 8 for k in ALL}
for k in ALL:
    r = RATE[k]; bad = []
    for n in (0, 1, r - 1, r, r + 1, 2 * r - 1, 2 * r, 2 * r + 5, 200):
        m = msg(n); want = ref(k, m, 100)
        for ch in ([], [1, 3], [r, 1], [r - 1, 1, r], [7, 2 * r]):
            L, got = digest(k, m, ch, outlen=len(want))
            if got != want: bad.append((n, ch))
    check('%s: %d message lengths x 5 chunkings' % (k, 9), not bad, bad[:3], None)

section('Output length: fixed digest, bounded Xs, split reads')
for k in FN:
    d = Locker(k).d // 8; m = msg(33)
    L, got = digest(k, m); check(k + ' default digest then Success', got == ref(k, m, d) and L.st == SUCCESS)
    L, got = digest(k, m, xs=64, outlen=8); check(k + ' Xs=64 prefix, Success', got == ref(k, m, d)[:8] and L.st == SUCCESS)
    L = Locker(k); absorb(L, m); L.setst(6, 'A'); a = bytearray(5); L.exec('C', out=a)
    check(k + ' partial read stays Hash_Output', L.st == OUTPUT and a == ref(k, m, d)[:5])
    b = bytearray(d - 5); L.exec('C', out=b); check(k + ' second read completes -> Success', L.st == SUCCESS and a + b == ref(k, m, d))
    L.exec('C', out=bytearray(4)); check(k + ' exec in Success -> Invalid', L.is_error() and L.se == SE_INV)
    for xs in (d * 8 + 8, 12):
        L = Locker(k); absorb(L, m); L.setst(6, 'B', xs); check('%s Xs=%d -> Invalid' % (k, xs), L.se == SE_INV and L.st == 0)
    L = Locker(k); absorb(L, m); L.setst(6, 'A'); o = bytearray(d + 8); o[:] = b'\xff' * (d + 8); L.exec('C', out=o)
    check(k + ' window beyond digest cleared (MR9)', o[d:] == bytes(8) and o[:d] == ref(k, m, d) and L.st == SUCCESS)

section('XOF: unbounded stream, bounded Xs, halts at interruption points')
for k in XOF:
    t = RATE[k]; m = b'abc'; want = ref(k, m, 4 * t + 17)
    L = Locker(k); absorb(L, m); L.setst(6, 'A'); o = bytearray(4 * t + 17); L.exec('C', out=o)
    check(k + ' single exec of %d B, still Hash_Output' % len(o), bytes(o) == want and L.st == OUTPUT)
    L = Locker(k); absorb(L, m); L.setst(6, 'A'); o = bytearray(); got = b''
    for n in (1, t - 1, t, 5, 2 * t):
        x = bytearray(n); L.exec('C', out=x); got += bytes(x)
    check(k + ' chunked reads concatenate to the stream', got == ref(k, m, len(got)))
    L = Locker(k); absorb(L, m); L.setst(6, 'A'); o = bytearray(3 * t); ks = L.exec('C', out=o, halt=1)
    check(k + ' halt at klstart = rate (first update)', ks == t and o[:t] == want[:t], ks, t)
    ks2 = L.exec('C', out=o, klstart=ks); check(k + ' resume completes the stream', ks2 == 0 and bytes(o) == ref(k, m, 3 * t))
    L = Locker(k); absorb(L, m); L.setst(6, 'A'); L.exec('C', out=bytearray(5)); o = bytearray(10)
    L.exec('C', out=o, klstart=2); check(k + ' klstart!=0 with block_base!=0 -> Invalid', L.se == SE_INV and o == bytes(10))
    L = Locker(k); absorb(L, m); L.setst(6, 'A'); o = bytearray(b'\x55' * 8); ks = L.exec('C', out=o, klstart=8)
    check(k + ' klstart=KLLEN/8 empty window: no-op, output intact', ks == 0 and o == b'\x55' * 8 and L.st == OUTPUT)
    L = Locker(k); absorb(L, m); L.setst(6, 'B', 8 * 300); o = bytearray(400); L.exec('C', out=o)
    check(k + ' Xs=2400 bits: 300 B then zeros, Success', L.st == SUCCESS and o[:300] == ref(k, m, 300) and o[300:] == bytes(100))
    L = Locker(k); absorb(L, m); L.setst(6, 'B', 2 ** 32); check(k + ' Xs=2^32 -> Invalid', L.se == SE_INV)
    L = Locker(k); absorb(L, m); L.setst(6, 'B', 8 * t); o = bytearray(t); L.exec('C', out=o)
    check(k + ' Xs = rate bits: Success, no further update', L.st == SUCCESS and o == ref(k, m, t))

section('Final piece of any bit length (Hash_Absorb_Last_Block)')
def piece_digest(kind, m, nbits, pre=b''):
    """pre: whole bytes via Hash_Absorb; m: bytes whose low nbits form the final piece."""
    L = Locker(kind); L.setst(2, 'A')
    if pre: L.exec('B', pre)
    L.setst(3, 'B' if nbits else 'A', nbits)
    if nbits: L.exec('B', m)
    L.setst(6, 'A'); n = Locker(kind).d // 8 or 64; o = bytearray(n); L.exec('C', out=o); return L, bytes(o)
def bitref(kind, pre, m, nbits, n):
    v = b2v(pre) | (b2v(m) & mask(nbits)) << (8 * len(pre))
    r = R.ref_keccak((v, 8 * len(pre) + nbits), RATE[kind] * 8, 'SHAKE' if kind in XOF else 'SHA3', 8 * n)
    return v2b(r, n)
for k in ALL:
    r = RATE[k] * 8; bad = []
    for nb in (1, 5, 8, 13, 100, r - 2, r - 1, r - 3, r - 4, r - 8, r - 10, r):
        for pre in (b'', msg(3, 2), msg(RATE[k] - 1, 3)):
            m = msg((nb + 7) // 8 + 1, 9)
            L, got = piece_digest(k, m[:(nb + 7) // 8], nb, pre)
            want = bitref(k, pre, m, nb, len(got))
            if got != want: bad.append((nb, len(pre)))
    check('%s: final pieces of %d bit lengths x 3 prefixes vs bit-level reference' % (k, 12), not bad, bad[:4], None)
k = 'SHA3-256'; L, got = piece_digest(k, bytes([0b10101]), 5)
check('CAVP-style Len=5 message 0b10101 (LSB first)', got == v2b(R.ref_keccak((0b10101, 5), 1088, 'SHA3', 256), 32))
L, _ = piece_digest(k, b'', 0, msg(10)); check('Xs=0 (Form A) = plain message', _ == hashlib.sha3_256(msg(10)).digest())
L = Locker(k); L.setst(2, 'A'); L.setst(3, 'A'); L.exec('B', b'x'); check('Xs=0 then exec with data -> Invalid', L.se == SE_INV)
L = Locker(k); L.setst(2, 'A'); L.setst(3, 'B', 1089); check('Xs=b+1 -> Invalid', L.se == SE_INV)
L = Locker(k); L.setst(2, 'A'); L.setst(3, 'B', 5); L.setst(6, 'A'); check('Hash_Output before the piece -> Invalid', L.se == SE_INV)
L = Locker(k); L.setst(2, 'A'); L.setst(3, 'B', 5); L.exec('B', b'\x01'); L.exec('B', b'\x01'); check('second exec in Last_Block -> Invalid (MR10)', L.se == SE_INV)
L = Locker(k); L.setst(2, 'A'); L.setst(3, 'B', 40); L.exec('B', b'\x01\x02'); check('KLLEN < last_block_len -> Invalid (MR6)', L.se == SE_INV)
L = Locker(k); L.setst(2, 'A'); L.setst(3, 'B', 8); L.setst(3, 'B', 8); check('same-state setst -> Invalid', L.se == SE_INV)
L = Locker(k); L.setst(2, 'A'); L.setst(3, 'B', 8); L.exec('B', b'a', klstart=1); check('empty window klstart=KLLEN/8 in Last_Block is a no-op', not L.is_error() and L.lbl == 8)
L = Locker(k); L.setst(2, 'A'); L.setst(3, 'B', 8); L.setst(1, 'A'); check('Last_Block -> Ready restarts', L.st == READY and L.lbl == 0 and L.s == 0)

section('Padding corner cases (second block only when needed)')
for k in ('SHA3-256', 'SHAKE128'):
    r = RATE[k]
    for n in (r - 1, r):
        _, got = digest(k, msg(n)); check('%s: %d-byte message (rate-1 / rate)' % (k, n), got == ref(k, msg(n), len(got)))

section('States and transitions')
def fresh(k='SHA3-256'): return Locker(k)
L = fresh(); L.exec('B', b'a'); check('exec in Ready -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(6, 'A'); check('Ready -> Hash_Output -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(2, 'B', 5); check('Form B setst to Hash_Absorb -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(2, 'A'); L.setst(2, 'A'); check('same-state setst -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(2, 'A'); L.exec('C', out=bytearray(8)); check('Form C exec in Hash_Absorb -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(2, 'A'); L.setst(6, 'A'); L.exec('B', b'a'); check('Form B exec in Hash_Output -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(2, 'A'); L.setst(6, 'A'); L.setst(6, 'A'); check('Hash_Output -> Hash_Output -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(2, 'A'); L.setst(6, 'A'); L.setst(2, 'A'); check('Hash_Output -> Hash_Absorb -> Invalid', L.se == SE_INV)
L, _ = digest('SHA3-256', b'q'); L.setst(2, 'A'); check('Success -> Hash_Absorb -> Invalid', L.se == SE_INV)
L, _ = digest('SHA3-256', b'q'); L.setst(54, 'A'); check('setst Success -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(55, 'A'); check('setst Failure -> Invalid', L.se == SE_INV)
L, _ = digest('SHA3-256', b'q'); L.setst(1, 'A'); check('Success -> Ready', L.st == READY and L.s == 0)
_l = fresh(); _l.setst(1, 'B', 3); check('setst Ready with Form B -> wrong Form, Invalid, no exception (GR19.3, GR13.5 item 4)', _l.se == SE_INV)
L = fresh(); L.setst(2, 'A'); L.exec('B', b'a'); L.setst(0, 'A'); L.exec('B', b'a'); L.setst(2, 'A')
check('kl.clear then exec/setst: no-op, stays inert', L.inert())
L = fresh(); L.setst(2, 'A'); L.exec('B', b'a'); L.setst(1, 'A'); L.setst(2, 'A'); L.exec('B', b'abc'); L.setst(6, 'A'); o = bytearray(32); L.exec('C', out=o)
check('Absorb -> Ready restarts SHA3-256', bytes(o) == hashlib.sha3_256(b'abc').digest())
L = fresh('SHAKE128'); L.setst(2, 'A'); L.exec('B', b'zz'); L.setst(6, 'A'); L.setst(1, 'A'); L.setst(2, 'A'); L.exec('B', b'abc'); L.setst(6, 'A'); o = bytearray(40); L.exec('C', out=o)
check('Output -> Ready restarts SHAKE128', bytes(o) == hashlib.shake_128(b'abc').digest(40))
L = fresh(); L.setst(2, 'A'); L.exec('B', b'a'); L.setst(7, 'A'); check('setst with Machine-undefined immediate -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(2, 'A'); L.exec('B', b'a'); L.setst(13, 'B', 5); check('setst Set_Aux_Value not in this Machine -> Invalid', L.se == SE_INV)
L = fresh(); L.setst(2, 'A'); L.exec('B', msg(10)); L.setst(6, 'A'); o = bytearray(4); L.exec('C', out=o)
L.invalid()
check('Invalid: content cleared, state zero, locker not Inert', L.s == 0 and L.se == SE_INV)
L.exec('C', out=(o := bytearray(b'\xff' * 4))); check('exec on Error State zeroes output window (GR14)', o == bytes(4))
L.setst(1, 'A'); check('setst on Error State is a no-op (GR13.2)', L.is_error())

section('Interrupted absorption (klstart)')
for k in ('SHA3-256', 'SHAKE128', 'SHA3-512'):
    r = RATE[k]; m = msg(3 * r + 10); want = ref(k, m, 60)
    L = Locker(k); L.setst(2, 'A'); ks = L.exec('B', m, halt=r);
    check(k + ' halt after the first block, klstart = rate', ks == r, ks, r)
    ks = L.exec('B', m, klstart=ks, halt=2 * r); check(k + ' resume halts again', ks == 2 * r)
    ks = L.exec('B', m, klstart=ks); L.setst(6, 'A'); o = bytearray(len(want)); L.exec('C', out=o)
    check(k + ' resumed to completion = reference', ks == 0 and bytes(o) == want)
    L = Locker(k); L.setst(2, 'A'); ks = L.exec('B', m, halt=1); data = L.export()
    L2 = Locker(k); L2.import_(data, ABSORB); ks = L2.exec('B', m, klstart=ks); L2.setst(6, 'A'); o = bytearray(len(want)); L2.exec('C', out=o)
    check(k + ' export/import between halt and resume', bytes(o) == want)
    L = Locker(k); L.setst(2, 'A'); L.exec('B', m[:5]); L.exec('B', m, klstart=r)
    check(k + ' klstart!=0 with block_base!=0 -> Invalid', L.se == SE_INV)
    L = Locker(k); L.setst(2, 'A'); ks = L.exec('B', m[:r], klstart=r // 1);
    check(k + ' klstart=KLLEN/8 empty window: no-op', ks == 0 and not L.is_error() and L.bb == 0)
    L = Locker(k); L.setst(2, 'A'); L.exec('B', m[:r], klstart=r + 5)
    check(k + ' klstart > KLLEN/8: no-op, klstart reset', not L.is_error())
    L = Locker(k); L.setst(2, 'A'); ks = L.exec('B', m[:2 * r + 3], halt=1); L.exec('B', m[:2 * r + 3], klstart=ks)
    check(k + ' complete message of 2 blocks + 3 B has block_base = 24 bits', L.bb == 24)

section('Provisioning Input and Serialized Content')
for k in ALL:
    L = Locker(k); sc0 = L.export(); check(k + ' SC length 208 B (1664 bits), Ready all zero', len(sc0) == 208 and sc0 == bytes(208))
L = Locker('SHA3-256'); L.setst(2, 'A'); L.exec('B', msg(5)); sc = L.export()
check('SC layout: state | block_base 40 | last_block_len = b | out_len 0', sc[200:202] == v2b(40, 2) and sc[202:204] == v2b(1088, 2) and sc[204:208] == bytes(4))
L.setst(6, 'B', 96); sc = L.export(); check('SC in Hash_Output: out_len = 96, last_block_len = 0', sc[204:208] == v2b(96, 4) and sc[202:204] == bytes(2))
for k in ('SHA3-384', 'SHAKE256'):
    m = msg(50)
    for stage in ('absorb', 'output'):
        L = Locker(k); L.setst(2, 'A'); L.exec('B', m)
        if stage == 'output': L.setst(6, 'A'); o1 = bytearray(7); L.exec('C', out=o1)
        L2 = Locker(k); L2.import_(L.export(), L.st)
        for X in (L, L2):
            if stage == 'absorb': X.setst(6, 'A')
        o, o2 = bytearray(30), bytearray(30); L.exec('C', out=o); L2.exec('C', out=o2)
        check('%s export/import in %s: identical continuation' % (k, stage), o == o2)

def _mko(k, xs=0):
    def mk(): L = Locker(k); absorb(L, b'abc'); L.setst(OUTPUT, 'B' if xs else 'A', xs); return L
    return mk
for k in FN: bits_checks(k, _mko(k), ref(k, b'abc', 0))
for k in XOF:
    bits_checks(k + ' unbounded', _mko(k), ref(k, b'abc', 16384), bounded=False)
    bits_checks(k + ' Xs=2400', _mko(k, 2400), ref(k, b'abc', 300))
section('Negative controls')
m = msg(20)
def raw(suffix_bits, m, kind='SHA3-256'):
    return v2b(R.ref_sponge((b2v(m), 8 * len(m)), R.keccak_f, 1088, 0, R._pad101(1088, suffix_bits), 256), 32)
control('suffix 1111 (SHAKE) instead of 01 changes SHA3-256', raw([1, 1, 1, 1], m) != hashlib.sha3_256(m).digest())
control('suffix 0x06 aligned to the MSB of a 5-bit piece differs from LSB-first', R.ref_keccak((0b10101, 5), 1088, 'SHA3', 256) != R.ref_keccak((0b10101 << 3, 5), 1088, 'SHA3', 256))
control('klstart read in bits instead of bytes would resume elsewhere', 8 * 1088 // 8 != 1088 // 8)
L, g = piece_digest('SHA3-256', b'\xff', 5); control('piece uses LSBs: ignoring Xs (whole byte) differs', g != hashlib.sha3_256(b'\xff').digest())
L, g = digest('SHA3-256', m); bad = bytearray(g); bad[0] ^= 1; control('digest comparison detects a flipped bit', bytes(bad) != hashlib.sha3_256(m).digest())
control('SHAKE128 is not SHAKE256 on the same input', ref('SHAKE128', m, 32) != ref('SHAKE256', m, 32))

section('kl.derive into SHA-3 / SHAKE (GR27-GR31.2, shared secret as message)')
def drv(kind, data=b'S' * 32, length=None, restricted=True, shared=True, ks=0, st=None):
    d = Locker(kind); d.setst(2, 'A')
    if st == 'last': d.setst(3, 'A')
    s = Secret(data, restricted, shared); derive(s, d, len(data) if length is None else length, ks); return d, s
d, s = drv('SHA3-256'); d.setst(6, 'A'); o = bytearray(32); d.exec('C', out=o)
check('shared secret 32 B -> SHA3-256 absorb: digest of the secret', bytes(o) == hashlib.sha3_256(b'S' * 32).digest())
d, s = drv('SHAKE256', b'T' * 66); d.setst(6, 'A'); o = bytearray(40); d.exec('C', out=o)
check('66-byte secret -> SHAKE256', bytes(o) == hashlib.shake_256(b'T' * 66).digest(40))
d = Locker('SHA3-256'); d.setst(2, 'A'); d.exec('B', b'ab'); derive(Secret(b'S' * 32), d, 32); d.setst(6, 'A'); o = bytearray(32); d.exec('C', out=o)
check('derive appends to an earlier message prefix', bytes(o) == hashlib.sha3_256(b'ab' + b'S' * 32).digest())
for nm, kw in (('length 0', dict(length=0)), ('length 31', dict(length=31)), ('length 33', dict(length=33)), ('klstart 8', dict(ks=1))):
    d, s = drv('SHA3-256', **kw); check('derive %s -> destination Invalid, source untouched' % nm, d.se == SE_INV and not s.bad)
d, s = drv('SHA3-256', st='last'); check('destination in Last_Block -> dest Invalid (GR29 item 3)', d.se == SE_INV)
d = Locker('SHA3-256'); derive(Secret(b'S' * 32), d, 32); check('destination in Ready (hash) -> Invalid', d.se == SE_INV)
d, s = drv('SHA3-256', shared=False); check('CMAC-type output into a hash input: pair not admitted, both Invalid (GR29 item 4)', d.se == SE_INV and s.bad)
o = Locker('SHAKE128'); o.setst(2, 'A'); o.setst(6, 'A'); d = Locker('SHA3-256'); d.setst(2, 'A'); derive(o, d, 32)
check('SHAKE128 output -> a hash input: pair not admitted, both Invalid (GR29 item 4)', o.se == SE_INV and d.se == SE_INV)
o = Locker('SHAKE128'); o.setst(2, 'A'); o.exec('B', b'ikm'); o.setst(6, 'A'); o.exec('C', out=bytearray(160)); d = Locker('ASCON-AEAD128'); derive(o, d, 16); x = bytearray(8); o.exec('C', out=x)
z = hashlib.shake_128(b'ikm').digest(184)
check('SHAKE128 output -> AEAD key across a squeeze (bytes 160..175), next Form C returns 176..183 (GR31.2, GR28)', d.key == b2v(z[160:176]) and bytes(x) == z[176:184])
o = Locker('SHA3-256'); o.setst(2, 'A'); o.setst(6, 'A'); d = Locker('ASCON-AEAD128_NONCE_MASK'); derive(o, d, 32)
check('SHA3-256 digest (32 B) -> K1|K2: admitted, source Success', d.se == 0 and d.key == b2v(hashlib.sha3_256(b'').digest()[:16]) and o.st == SUCCESS)
o = Locker('SHA3-256'); o.setst(2, 'A'); o.setst(6, 'A'); o.exec('C', out=bytearray(24)); d = Locker('ASCON-AEAD128'); derive(o, d, 16)
check('8 bytes left of a SHA3-256 digest -> 16-byte key: destination Invalid, source keeps its State (GR29 item 6)', d.se == SE_INV and o.st == OUTPUT_)
d = Locker('SHA3-256'); d.setst(2, 'A'); d.clear(); derive(Secret(b'S' * 32), d, 32); check('inert destination: no-op', d.inert())
z = Secret(b'S' * 32); d = Locker('SHA3-256'); d.setst(2, 'A'); derive(z, d, 32); e = Locker('SHA3-256'); e.setst(2, 'A'); derive(z, e, 32)
check('a shared secret feeds one kl.derive: a second makes the source Invalid, its destination unchanged (GR28, GR29 item 2)', not d.se and z.bad and e.se == 0 and e.bb == 0)

section('Sealed locker (GR31.3)')
def sl(kind='SHA3-256'):
    d = Locker(kind); d.setst(2, 'A'); derive(Secret(b'S' * 32, sealed=True), d, 32); d.setst(6, 'A'); return d
for kind, want in (('SHA3-256', hashlib.sha3_256(b'S' * 32).digest()), ('SHAKE128', hashlib.shake_128(b'S' * 32).digest(32))):
    d = sl(kind); o = bytearray(b'\xff' * 8); d.exec('C', out=o)
    check('%s a sealed secret in the message sets Sealed; Form C kl.exec in Hash_Output -> Invalid, output zero' % kind, d.se == SE_INV and bytes(o) == bytes(8))
    d = sl(kind); d.setst(BITS, 'B', 8); check('%s ... kl.setst naming Hash_Output_Bits -> Invalid' % kind, d.se == SE_INV)
    d = sl(kind); k = Locker('ASCON-AEAD128'); derive(d, k, 16)
    check('%s ... its output into an AEAD key: the output prefix' % kind, k.se == 0 and k.key == b2v(want[:16]))
    d = sl(kind); k = Locker('ASCON-AEAD128_NONCE_MASK'); derive(d, k, 32)
    check('%s ... into K1|K2: not admitted, both Invalid (an unsealed digest is admitted above)' % kind, d.se == SE_INV and k.se == SE_INV)
d = sl(); d.setst(1, 'A'); d.setst(2, 'A'); d.exec('B', b'abc'); d.setst(6, 'A'); o = bytearray(32); d.exec('C', out=o)
check('Ready clears Sealed: the next digest is readable', bytes(o) == hashlib.sha3_256(b'abc').digest())
for n in (15, 16):
    d = Locker('SHA3-256'); d.setst(2, 'A'); s = Secret(b'S' * n, sealed=True); derive(s, d, n)
    check('a sealed secret of %d bytes: %s' % (n, 'the source Invalid, the message unchanged (GR29 item 7)' if n < 16 else 'enters, Sealed set'),
          (s.bad and d.se == 0 and d.bb == 0 and not d.sealed) if n < 16 else (not s.bad and d.sealed))
for sealed in (False, True):
    d = Locker('KMAC128', K=b'k' * 16); d.setst(2, 'A'); derive(Secret(b'S' * 32, sealed=sealed), d, 32); d.setst(VERIFY, 'B', 256)
    check('KMAC128 %s secret in the message: kl.setst naming Hash_Verify %s' % (('a sealed', '-> Invalid') if sealed else ('an unsealed', 'admitted')),
          d.se == SE_INV if sealed else d.st == VERIFY)
# StateExtension @ State at an SCC import (KLE-Metadata-validity)
d = sl(); c = Locker('SHA3-256'); c.import_(d.export(), *d.mdh_state()); o = bytearray(8); c.exec('C', out=o)
check('a sealed Hash_Output reports StateExtension 2, and its import keeps Sealed: Form C -> Invalid', d.mdh_state() == (OUTPUT_, 2) and c.se == SE_INV)
d = Locker('SHA3-256'); d.setst(2, 'A'); derive(Secret(b'S' * 32, sealed=True), d, 32); c = Locker('SHA3-256'); c.import_(d.export(), *d.mdh_state())
check('... in Hash_Absorb too', c.sealed and c.st == ABSORB)
for st in (READY, BITS):
    c = Locker('SHA3-256'); c.import_(sl().export(), st, se=2); check('Sealed in State %d: unsupported StateExtension @ State, the import -> Invalid' % st, c.se == SE_INV)
c = Locker('KMAC128', K=b'k' * 16); c.import_(c.export(), VERIFY, se=2); check('KMAC128 Sealed in Hash_Verify: the import -> Invalid', c.se == SE_INV)
c = Locker('ASCON-AEAD128'); c.import_(c.export(), READY, se=2); check('Ascon-AEAD128 has no Sealed: the import -> Invalid', c.se == SE_INV)
# GR30: a sealed hop is a restricted transfer that narrows the destination MDH; an unsealed output narrows nothing (GR31.2)
d = Locker('SHA3-256'); d.mdh = mdh_pack(UsagePolicy=0x7); d.setst(2, 'A'); derive(Secret(b'S' * 32, sealed=True, mdh=mdh_pack(UsagePolicy=0x5, ExpirationDate=7)), d, 32)
d.setst(6, 'A'); k = Locker('ASCON-AEAD128'); k.mdh = mdh_pack(UsagePolicy=0x6); derive(d, k, 16)
check('GR30 across two sealed hops: the AEAD key gets UsagePolicy 0x4 and the ExpirationDate of the secret',
      k.se == 0 and (mdh_get(k.mdh, 'UsagePolicy'), mdh_get(k.mdh, 'ExpirationDate')) == (4, 7) and mdh_get(d.mdh, 'UsagePolicy') == 5)
d = sl(); d.scprot = 2; k = Locker('ASCON-AEAD128'); k.scprot = 1; derive(d, k, 16)
check('GR30: an AEAD key whose SCProtection does not include that of the sealed hash -> Privilege Violation, the source keeps its output', k.se == 5 and d.st == OUTPUT_)
d = Locker('SHA3-256'); d.mdh = mdh_pack(Locality=0x10); d.setst(2, 'A'); derive(Secret(b'S' * 32, sealed=True, mdh=mdh_pack(Locality=0x20)), d, 32)
check('GR30: failed narrowing (boot subfields differ) -> Privilege Violation, nothing absorbed', d.se == 5 and not d.sealed)
d = Locker('SHA3-256'); d.mdh = mdh_pack(UsagePolicy=1); d.setst(2, 'A'); d.exec('B', b'abc'); d.setst(6, 'A'); k = Locker('ASCON-AEAD128'); k.mdh = mdh_pack(UsagePolicy=6); derive(d, k, 16)
check('an unsealed output is unrestricted (GR31.2): no narrowing', k.se == 0 and mdh_get(k.mdh, 'UsagePolicy') == 6)
section('Software example KLE-pseudocode-SampleNTT: FIPS 203 SampleNTT by 12-bit reads in Hash_Output_Bits')
import mlkem_model as MK
for B in (bytes(range(32)) + bytes([1, 2]), bytes(34), b'\xff' * 34):
    L = Locker('SHAKE128'); L.setst(2, 'A'); L.exec('B', B); a = []; top = 0              # the first Hash_Output_Bits pads
    while len(a) < 256:
        L.setst(BITS, 'B', 12); o = bytearray(b'\xff\xff'); L.exec('C', out=o); v = int.from_bytes(o, 'little'); top |= v >> 12
        if v < 3329: a.append(v)
    check('SampleNTT(%s...) from Hash_Absorb = mlkem_model.sample_ntt, each read zero-extended to 16 bits' % B[:3].hex(), a == MK.sample_ntt(B) and top == 0)
section('Provisioning with MachinePolicy != 0 and rstrl (ungated Machine)')
for k in ('SHA3-256', 'SHAKE128'):
    l = Locker(k, policy=1); check(k + ' PI with MachinePolicy=1 -> State 0, StateExtension 1 (unsupported Metadata)', (l.st, l.se) == (0, 1))
l = Locker('SHA3-256'); l.rstrl(0); check('rstrl of the unused MachinePolicy keeps it zero, no State change', l.policy == 0 and l.st == READY)
l.rstrl(mask(64)); check('rstrl all-ones: no change', l.policy == 0 and l.st == READY)
section('Form D (KLIOBUF substitution of kl.exec)')
l = Locker('SHA3-256'); l.setst(2, 'A'); io = bytearray(b'abc'); l.exec_d(io, 3); l.setst(6, 'A'); io = bytearray(40); l.exec_d(io, 40)
check('Form D absorb + Form D output = SHA3-256("abc")', bytes(io[:32]) == hashlib.sha3_256(b'abc').digest())
l = Locker('SHAKE128'); l.setst(2, 'A'); l.exec_d(bytearray(b'abc'), 3); l.setst(6, 'A'); io = bytearray(b'\xff' * 300); l.exec_d(io, 300, klstart=0)
check('Form D output over a dirty KLIOBUF = SHAKE128 stream', bytes(io) == hashlib.shake_128(b'abc').digest(300))
l = Locker('SHA3-256'); l.setst(2, 'A'); io = bytearray(b'\x55' * 8); l.exec_d(io, 8); check('Form D exec in Hash_Absorb at klstart=0 absorbs', l.st == ABSORB)
l = Locker('SHA3-256'); io = bytearray(b'\x55' * 8); l.exec_d(io, 8); check('Form D in Ready -> Invalid, window zeroed', l.se == SE_INV and bytes(io) == bytes(8))
l = Locker('SHA3-256'); l.clear(); io = bytearray(b'\x55' * 8); l.exec_d(io, 8, klstart=3); check('Form D on inert locker zeroes [klstart, top-1] only (GR14)', bytes(io) == b'\x55' * 3 + bytes(5))
check('Form D with unconfigured KLIOBUF -> illegal instruction (GR11)', raises(lambda: Locker('SHA3-256').exec_d(bytearray(8), 0), exc=IllegalInstruction))

done()
