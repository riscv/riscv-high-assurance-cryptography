#!/usr/bin/env pypy3.12
"""KAT of the KMAC Machines (Type 6 Modes 10..13): Zkl-ISA-machines.adoc KLE-KMAC; oracle SP 800-185 (sponge_ref).
Run: cd src && pypy3.12 kat/kmac-kat.py"""
import hashlib
from common import *
from sponge_model import *
import sponge_ref as R

H = bytes.fromhex
RATE = {'KMAC128': 168, 'KMACXOF128': 168, 'KMAC256': 136, 'KMACXOF256': 136}
def msg(n, seed=1): return hashlib.shake_128(bytes([seed])).digest(n)
X4 = bytes(range(4)); KEY = bytes(range(0x40, 0x60)); TAG = b'My Tagged Application'

def mac(kind, K, X, S=b'', L=256, chunks=(), msgbits=None):
    """Run the Machine; returns (locker, output bytes of ceil(L/8))."""
    x = kind.startswith('KMACXOF')
    Lk = Locker(kind, K=K, S=S); Lk.setst(2, 'A'); i = 0
    for c in list(chunks) + [len(X)]:
        if i >= len(X): break
        Lk.exec('B', X[i:i + c]); i += c
    Lk.setst(6, 'A' if x and L == 0 else 'B', L)
    o = bytearray((L + 7) // 8 or 64); Lk.exec('C', out=o); return Lk, bytes(o)
def refmac(kind, K, X, S, L):
    r = R.ref_kmac(RATE[kind], K, X, L, S, xof=kind.startswith('KMACXOF'))
    return v2b(r, (L + 7) // 8)

section('SP 800-185 published samples and reference')
s1 = H('e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e')
s2 = H('3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5')
check('KMAC128 sample 1 (reference)', refmac('KMAC128', KEY, X4, b'', 256) == s1)
check('KMAC128 sample 2 (reference)', refmac('KMAC128', KEY, X4, TAG, 256) == s2)
check('KMAC128 sample 1 (Machine)', mac('KMAC128', KEY, X4)[1] == s1)
check('KMAC128 sample 2 (Machine)', mac('KMAC128', KEY, X4, TAG)[1] == s2)
s4 = refmac('KMAC256', KEY, X4, TAG, 512)
check('KMAC256 sample 4 prefix (reference)', s4[:16] == H('20c570c31346f703c9ac36c61c03cb64'), s4[:16])
check('KMAC256 sample 4 (Machine)', mac('KMAC256', KEY, X4, TAG, 512)[1] == s4)
chk = bytes(range(200))
check('KMAC128 sample 3 prefix (200-byte data, tag)', mac('KMAC128', KEY, chk, TAG)[1][:8] == H('1f5b4e6cca02209e'))
check('KMACXOF128 sample 1 (reference) = Machine', mac('KMACXOF128', KEY, X4, b'', 256)[1] == refmac('KMACXOF128', KEY, X4, b'', 256))
check('KMAC vs KMACXOF differ (right_encode(L) vs right_encode(0))', refmac('KMAC128', KEY, X4, b'', 256) != refmac('KMACXOF128', KEY, X4, b'', 256))

section('Machine vs reference: lengths, keys, customization, chunking, output lengths')
for k in RATE:
    r = RATE[k]; bad = []
    for n in (0, 1, r - 6, r - 5, r - 1, r, r + 1, 2 * r + 7):
        for K, S in ((b'', b''), (KEY, TAG), (msg(r - 5), msg(3))):
            for ch in ((), (1, 3), (r, 1)):
                L = 256 if n % 2 else 384
                if mac(k, K, msg(n), S, L, ch)[1] != refmac(k, K, msg(n), S, L): bad.append((n, len(K), ch))
    check('%s: 8 lengths x 3 key/custom x 3 chunkings' % k, not bad, bad[:3], None)
for k in ('KMAC128', 'KMAC256', 'KMACXOF128', 'KMACXOF256'):
    bad = []
    for L in (32, 39, 40, 250, 255, 257, 1000, 1001, 8 * RATE[k], 8 * RATE[k] + 8, 4096):
        if k.startswith('KMACXOF') and L % 8: continue
        Lk, g = mac(k, KEY, b'abc', b'', L)
        if g != refmac(k, KEY, b'abc', b'', L) or Lk.st != SUCCESS: bad.append(L)
    check('%s: output lengths exact, last byte zero-padded' % k, not bad, bad)
Lk, g = mac('KMAC128', KEY, b'abc', b'', 39); check('L=39: last byte keeps 7 bits, top bit clear', g[-1] < 128 and len(g) == 5)
Lk = Locker('KMAC128', K=KEY); Lk.setst(2, 'A'); Lk.setst(6, 'B', 40); o = bytearray(b'\xff' * 9); Lk.exec('C', out=o)
check('window larger than L: output cleared beyond L (MR9)', o[5:] == bytes(4) and Lk.st == SUCCESS)

section('XOF: unbounded output, halts')
k = 'KMACXOF128'; want = refmac(k, KEY, b'abc', b'', 8 * 500)
Lk = Locker(k, K=KEY); Lk.setst(2, 'A'); Lk.exec('B', b'abc'); Lk.setst(6, 'A'); o = bytearray(500); Lk.exec('C', out=o)
check('KMACXOF128 Form A: stream = right_encode(0) reference, stays Hash_Output', bytes(o) == want and Lk.st == OUTPUT)
Lk = Locker(k, K=KEY); Lk.setst(2, 'A'); Lk.exec('B', b'abc'); Lk.setst(6, 'A'); o = bytearray(500); ks = Lk.exec('C', out=o, halt=1)
check('halt at klstart = 168', ks == 168); ks = Lk.exec('C', out=o, klstart=ks); check('resume completes', ks == 0 and bytes(o) == want)
Lk = Locker(k, K=KEY); Lk.setst(2, 'A'); Lk.exec('B', b'abc'); Lk.setst(6, 'B', 80); o = bytearray(20); Lk.exec('C', out=o)
check('KMACXOF Xs=80 sets L: output = KMAC reference with right_encode(0) prefix, Success', Lk.st == SUCCESS and o[:10] == want[:10] and o[10:] == bytes(10))

section('States and transitions')
def kl(k='KMAC128'): L = Locker(k, K=KEY); L.setst(2, 'A'); L.exec('B', b'abc'); return L
for xs in (0, 31, 2 ** 32):
    L = kl(); L.setst(6, 'B', xs) if xs else L.setst(6, 'A'); check('KMAC128 Hash_Output Xs=%d / Form A -> Invalid' % xs, L.se == SE_INV)
L = kl('KMACXOF128'); L.setst(6, 'B', 12); check('KMACXOF Xs=12 (not whole bytes) -> Invalid', L.se == SE_INV)
L = kl('KMACXOF128'); L.setst(6, 'B', 2 ** 32); check('KMACXOF Xs=2^32 -> Invalid', L.se == SE_INV)
L = kl(); L.setst(6, 'B', 39); check('KMAC128 Xs=39 admitted (32 <= Xs, any bit length)', L.st == OUTPUT)
L = Locker('KMAC128', K=KEY); L.exec('B', b'a'); check('exec in Ready -> Invalid', L.se == SE_INV)
L = kl(); L.setst(2, 'A'); check('same-state setst -> Invalid', L.se == SE_INV)
L, _ = mac('KMAC128', KEY, b'abc'); L.exec('C', out=bytearray(4)); check('exec in Success -> Invalid', L.se == SE_INV)
L, _ = mac('KMAC128', KEY, b'abc', b'', 256); L.setst(1, 'A'); L.setst(2, 'A'); L.exec('B', b'abc'); L.setst(6, 'B', 256); o = bytearray(32); L.exec('C', out=o)
check('Success -> Ready re-absorbs cshake_block and key_block', bytes(o) == refmac('KMAC128', KEY, b'abc', b'', 256))
L = kl(); L.setst(5, 'B', 40); check('Hash_Verify on KMAC128 Xs=40 admitted', L.st == VERIFY)
L = kl('KMACXOF128'); L.setst(5, 'B', 128); check('Hash_Verify on KMACXOF -> Invalid', L.se == SE_INV)
for xs in (31, 36, 8 * 168 + 8):
    L = kl(); L.setst(5, 'B', xs); check('Hash_Verify Xs=%d -> Invalid' % xs, L.se == SE_INV)
L = kl(); L.setst(5, 'A'); check('Hash_Verify Form A -> Invalid', L.se == SE_INV)

section('Hash_Verify')
tag = refmac('KMAC128', KEY, b'abc', b'', 128)
def verify(t, xs=128, kllen=None):
    L = kl(); L.setst(5, 'B', xs); L.exec('B', t if kllen is None else t[:kllen]); return L
check('matching tag -> Success', verify(tag).st == SUCCESS)
bad = bytearray(tag); bad[7] ^= 0x10; check('flipped tag bit -> Failure', verify(bytes(bad)).st == FAILURE)
bad = bytearray(tag + b'\xaa'); check('bytes beyond L ignored -> Success', verify(bytes(bad)).st == SUCCESS)
check('KLLEN < L -> Invalid', verify(tag, kllen=15).se == SE_INV)
L = verify(tag); L.exec('B', tag); check('exec in Success after verify -> Invalid', L.se == SE_INV)
t40 = refmac('KMAC128', KEY, b'abc', b'', 40); check('L=40 verify', verify(t40, 40).st == SUCCESS)
L = Locker('KMAC128', policy=1, K=KEY); L.setst(2, 'A'); L.exec('B', b'abc'); L.setst(5, 'B', 128); check('MachinePolicy bit0 only: Hash_Verify not admitted', L.se == SE_INV)
L = Locker('KMAC128', policy=2, K=KEY); L.setst(2, 'A'); L.exec('B', b'abc'); L.setst(6, 'B', 128); check('MachinePolicy bit1 only: Hash_Output not admitted', L.se == SE_INV)
L = Locker('KMAC128', policy=2, K=KEY); L.setst(2, 'A'); L.exec('B', b'abc'); L.setst(5, 'B', 128); check('MachinePolicy bit1: Hash_Verify admitted', L.st == VERIFY)

section('Final piece of any bit length')
for k in ('KMAC128', 'KMAC256', 'KMACXOF256'):
    r8 = RATE[k] * 8; bad = []
    for nb in (1, 5, 8, 13, 100, r8 - 40, r8 - 30, r8 - 17, r8 - 16, r8 - 8, r8):
        for pre in (b'', msg(3), msg(RATE[k] - 2)):
            m = msg((nb + 7) // 8, 7)
            L = Locker(k, K=KEY); L.setst(2, 'A')
            if pre: L.exec('B', pre)
            L.setst(3, 'B', nb); L.exec('B', m); L.setst(6, 'A' if k.startswith('KMACXOF') else 'B', 0 if k.startswith('KMACXOF') else 256)
            o = bytearray(32); L.exec('C', out=o)
            v = b2v(pre) | (b2v(m) & mask(nb)) << (8 * len(pre)); nbits = 8 * len(pre) + nb
            newx = b2v(R.bytepad(R.encode_string(KEY), RATE[k])); lx = 8 * len(R.bytepad(R.encode_string(KEY), RATE[k]))
            pre_c = R.bytepad(R.encode_string(b'KMAC') + R.encode_string(b''), RATE[k])
            # bit-level reference: cSHAKE(pre_c || key_block || X || right_encode(L), 256) over bits
            full = b2v(pre_c) | newx << (8 * len(pre_c)) | v << (8 * len(pre_c) + lx)
            n = 8 * len(pre_c) + lx + nbits
            re = R.right_encode(0 if k.startswith('KMACXOF') else 256)
            full |= b2v(re) << n; n += 8 * len(re)
            want = v2b(R.ref_keccak((full, n), r8, 'CSHAKE', 256), 32)
            if bytes(o) != want: bad.append((nb, len(pre)))
    check('%s: final pieces (11 bit lengths x 3 prefixes) vs bit-level reference' % k, not bad, bad[:4], None)

section('Serialized Content')
L = kl(); sc = L.export(); check('SC length: 200+2+2+4+2*b/8 bytes (KMAC128)', len(sc) == 208 + 336)
check('SC tail = cshake_block | key_block', sc[208:208 + 168] == v2b(L.cs, 168) and sc[208 + 168:] == v2b(L.kb, 168))
check('SC block_base = 24 after "abc"', sc[200:202] == v2b(24, 2))
L.setst(6, 'B', 96); sc = L.export(); check('SC in Hash_Output: out_len = 96', sc[204:208] == v2b(96, 4))
for k in RATE:
    for stage in ('absorb', 'output'):
        L = Locker(k, K=KEY, S=TAG); L.setst(2, 'A'); L.exec('B', msg(300))
        if stage == 'output':
            L.setst(6, 'A' if k.startswith('KMACXOF') else 'B', 0 if k.startswith('KMACXOF') else 512); L.exec('C', out=bytearray(3))
        L2 = Locker(k, K=b'', S=b''); L2.import_(L.export(), L.st)
        if stage == 'absorb':
            for X in (L, L2): X.setst(6, 'A' if k.startswith('KMACXOF') else 'B', 0 if k.startswith('KMACXOF') else 256)
        o1, o2 = bytearray(20), bytearray(20); L.exec('C', out=o1); L2.exec('C', out=o2)
        check('%s export/import in %s: same continuation (SC carries cshake_block, key_block)' % (k, stage), o1 == o2)
L = Locker('KMAC128', K=KEY); L2 = Locker('KMAC128', K=KEY); L2.import_(L.export(), READY); L2.setst(2, 'A'); L2.exec('B', b'abc'); L2.setst(6, 'B', 256)
o = bytearray(32); L2.exec('C', out=o); check('import in Ready then full run', bytes(o) == refmac('KMAC128', KEY, b'abc', b'', 256))

section('Interrupted absorption')
m = msg(3 * 168 + 9); want = refmac('KMAC128', KEY, m, b'', 256)
L = Locker('KMAC128', K=KEY); L.setst(2, 'A'); ks = L.exec('B', m, halt=1); L2 = Locker('KMAC128'); L2.import_(L.export(), ABSORB)
L2.exec('B', m, klstart=ks); L2.setst(6, 'B', 256); o = bytearray(32); L2.exec('C', out=o)
check('halt, export, import, resume = reference', ks == 168 and bytes(o) == want)

section('Negative controls')
x = R.ref_kmac(168, KEY, bytes(4), 256, b'')
rep = lambda enc: R.bytepad(R.encode_string(KEY), 168) + bytes(4) + enc
mk = lambda enc: R.ref_keccak((b2v(R.bytepad(R.encode_string(b'KMAC') + R.encode_string(b''), 168) + rep(enc)), 8 * (168 + 168 + 4 + len(enc))), 1344, 'CSHAKE', 256)
control('left_encode(L) instead of right_encode(L) gives another MAC', mk(R.left_encode(256)) != mk(R.right_encode(256)))
control('SHAKE suffix 1111 instead of cSHAKE 00 gives another MAC',
        R.ref_keccak((b2v(R.bytepad(R.encode_string(b'KMAC') + R.encode_string(b''), 168) + rep(R.right_encode(256))), 8 * (336 + 4 + 2)), 1344, 'SHAKE', 256) != mk(R.right_encode(256)))
control('L=256 vs KMACXOF right_encode(0): domain separation', refmac('KMAC128', KEY, bytes(4), b'', 256) != refmac('KMACXOF128', KEY, bytes(4), b'', 256))
control('output of L=39 differs in the masked top bit from unmasked ceil bytes', refmac('KMAC128', KEY, b'abc', b'', 39) != refmac('KMAC128', KEY, b'abc', b'', 40)[:5])
control('wrong customization string changes the MAC', refmac('KMAC128', KEY, bytes(4), TAG, 256) != refmac('KMAC128', KEY, bytes(4), b'', 256))

section('kl.derive into KMAC (shared secret as message), GR37-GR43')
def kd(kind='KMAC128', data=b'S' * 32, length=None, shared=True, ks=0):
    d = Locker(kind, K=KEY); d.setst(2, 'A'); s = Secret(data, True, shared); derive(s, d, len(data) if length is None else length, ks); return d, s
d, s = kd(); d.setst(6, 'B', 256); o = bytearray(32); d.exec('C', out=o)
check('shared secret 32 B -> KMAC128 absorb = KMAC(K, secret)', bytes(o) == v2b(R.ref_kmac(168, KEY, b'S' * 32, 256), 32))
d, s = kd('KMACXOF256', b'T' * 70); d.setst(6, 'A'); o = bytearray(40); d.exec('C', out=o)
check('70-byte secret -> KMACXOF256', bytes(o) == v2b(R.ref_kmac(136, KEY, b'T' * 70, 320, xof=True), 40))
for nm, kw in (('length 0', dict(length=0)), ('length 31', dict(length=31)), ('klstart 8', dict(ks=1))):
    d, s = kd(**kw); check('derive %s -> destination Invalid, source untouched' % nm, d.se == SE_INV and not s.bad)
d, s = kd(shared=False); check('non-shared-secret source into KMAC input: both Invalid (GR39.4)', d.se == SE_INV and s.bad)
d = Locker('KMAC128', K=KEY); derive(Secret(b'S' * 32), d, 32); check('destination in Ready -> Invalid (GR39.3)', d.se == SE_INV)
o = Locker('KMAC128', K=KEY); o.setst(2, 'A'); o.setst(6, 'B', 128); d = Locker('KMAC256', K=KEY); d.setst(2, 'A'); derive(o, d, 32)
check('KMAC Hash_Output is not a source: source Invalid, dest untouched', o.se == SE_INV and d.st == ABSORB)

section('SKID key, MachinePolicy, restrictl, unsupported policy')
SKS = {0x0101010101010101: KEY}
def macof(L, x=b'abc', xs=256):
    L.setst(2, 'A'); L.exec('B', x); L.setst(6, 'B', xs); o = bytearray(xs // 8); L.exec('C', out=o); return bytes(o)
Ls = Locker('KMAC128', skid=0x0101010101010101, sks=SKS, S=b'cust')
check('SKID-keyed KMAC128 = KMAC with the resolved key', macof(Ls) == v2b(R.ref_kmac(168, KEY, b'abc', 256, b'cust'), 32))
check('SC with SKID: key_block replaced by the 8-byte SKID', len(Ls.export()) == 208 + 168 + 8, len(Ls.export()))
check('unresolved SKID -> Invalid at provisioning', Locker('KMAC128', skid=0x0202020202020202, sks=SKS).se == SE_INV)
d = Locker('KMAC128', skid=0x0101010101010101, sks=SKS); d.setst(2, 'A'); s = Secret(b'S' * 32); derive(s, d, 32)
check('derive into SKID-keyed KMAC absorb is still admitted (message input)', d.st == ABSORB)
for pol, vo, vv in ((1, True, False), (2, False, True), (3, True, True)):
    L = Locker('KMAC128', policy=pol, K=KEY); L.setst(2, 'A'); L.exec('B', b'abc'); L.setst(6, 'B', 128); check('MachinePolicy=%d: Hash_Output %s' % (pol, 'admitted' if vo else 'refused'), (L.st == OUTPUT_) == vo)
    L = Locker('KMAC128', policy=pol, K=KEY); L.setst(2, 'A'); L.exec('B', b'abc'); L.setst(5, 'B', 128); check('MachinePolicy=%d: Hash_Verify %s' % (pol, 'admitted' if vv else 'refused'), (L.st == VERIFY) == vv)
L = Locker('KMAC128', policy=3, K=KEY); L.restrictl(1); L.setst(2, 'A'); L.setst(6, 'B', 128); check('restrictl 3 -> 1: Hash_Output stays admitted', L.st == OUTPUT_)
L = Locker('KMAC128', policy=3, K=KEY); L.restrictl(1); L.setst(2, 'A'); L.setst(5, 'B', 128); check('restrictl 3 -> 1: Hash_Verify now refused', L.se == SE_INV)
L = Locker('KMAC128', policy=1, K=KEY); L.restrictl(2); check('restrictl narrowing to a forbidden value (0 bits) -> Invalid (GR25)', L.se == SE_INV)
L = Locker('KMAC128', policy=3, K=KEY); L.restrictl(mask(64)); check('restrictl all-ones: unchanged', L.policy == 3 and L.st == READY)
for k in ('KMACXOF128', 'KMACXOF256'):
    L = Locker(k, policy=1, K=KEY); check(k + ' with MachinePolicy != 0 -> unsupported Metadata (State 0, ext 1)', (L.st, L.se) == (0, 1))

section('Form D (KLIOBUF substitution of kl.exec)')
L = Locker('KMAC128', K=KEY); L.setst(2, 'A'); L.exec_d(bytearray(b'abc'), 3); L.setst(6, 'B', 256); io = bytearray(b'\xff' * 40); L.exec_d(io, 40)
check('Form D absorb and output: KMAC128 with window 40 B, tail cleared (MR9)', bytes(io) == v2b(R.ref_kmac(168, KEY, b'abc', 256), 32) + bytes(8))
L = Locker('KMAC128', K=KEY); L.setst(2, 'A'); L.exec_d(bytearray(b'abc'), 3); L.setst(5, 'B', 256)
tag = v2b(R.ref_kmac(168, KEY, b'abc', 256), 32); L.exec_d(bytearray(tag), 32); check('Form D Hash_Verify of the right tag -> Success', L.st == SUCCESS)
L = Locker('KMAC128', K=KEY); L.setst(2, 'A'); L.exec_d(bytearray(b'abc'), 3); L.setst(5, 'B', 256); L.exec_d(bytearray(32), 32); check('Form D Hash_Verify of a wrong tag -> Failure', L.st == FAILURE)
L = Locker('KMAC128', K=KEY); io = bytearray(b'q' * 4); L.exec_d(io, 4); check('Form D exec in Ready -> Invalid, window zeroed', L.se == SE_INV and bytes(io) == bytes(4))
check('Form D with unconfigured KLIOBUF -> illegal instruction', raises(lambda: Locker('KMAC128', K=KEY).exec_d(bytearray(4), 0), exc=IllegalInstruction))

section('Samples 5-6 and bit-level reference (own derivation, cross-checked Machine vs reference)')
def kmac_bits(kind, K, S, xv, xbits, L):
    rb = RATE[kind]; xof = kind.startswith('KMACXOF')
    pre = R.bytepad(R.encode_string(b'KMAC') + R.encode_string(S), rb); kb = R.bytepad(R.encode_string(K), rb)
    enc = R.right_encode(0 if xof else L); n = 8 * (len(pre) + len(kb))
    v = b2v(pre + kb) | (xv & mask(xbits)) << n | b2v(enc) << (n + xbits)
    return v2b(R.ref_keccak((v, n + xbits + 8 * len(enc)), 8 * rb, 'CSHAKE', L), (L + 7) // 8)
c200 = bytes(range(200))
for kind, X, S, L, lab in (('KMAC256', X4, TAG, 512, 'sample 4'), ('KMAC256', c200, b'', 512, 'sample 5'), ('KMAC256', c200, TAG, 512, 'sample 6')):
    a, b2, c = mac(kind, KEY, X, S, L)[1], refmac(kind, KEY, X, S, L), kmac_bits(kind, KEY, S, b2v(X), 8 * len(X), L)
    check('%s %s: Machine = reference = bit-level reference' % (kind, lab), a == b2 == c)
check('KMAC128 sample 3 vs bit-level', kmac_bits('KMAC128', KEY, TAG, b2v(c200), 1600, 256) == refmac('KMAC128', KEY, c200, TAG, 256))

section('kl.clear and setst of undefined immediates')
for kind in ('KMAC128', 'KMACXOF128'):
    for imm in (48, 53):
        L = Locker(kind, K=KEY); L.setst(2, 'A'); L.setst(imm, 'A'); check('%s: setst %d in Hash_Absorb -> Invalid' % (kind, imm), L.se == SE_INV)
    L = Locker(kind, K=KEY); L.setst(2, 'A'); L.setst(0, 'A'); st0 = (L.st, L.se)
    L.setst(1, 'A'); L.exec('B', b'a'); L.restrictl(3)
    check('%s: kl.clear -> Unconfigured; later setst/exec/restrictl change nothing' % kind, st0 == (0, 0) and (L.st, L.se) == (0, 0))

section('Generic sequence: random plans of chunks, halts, export/import, final piece, bound Xs')
import random
def plan_run(kind, rnd, S=b''):
    xof = kind.startswith('KMACXOF'); nbits = rnd.choice([0, 1, 8, 13, 100, 8 * RATE[kind] - 3, 8 * RATE[kind] - 2, 8 * RATE[kind], 8 * RATE[kind] + 5, 2000])
    m = msg((nbits + 7) // 8 + 1, rnd.randint(0, 255)); whole = nbits // 8 if rnd.random() < .5 else (nbits // 8 if nbits % 8 == 0 else nbits // 8)
    pre, piece = m[:whole], nbits - 8 * whole
    L = Locker(kind, K=KEY, S=S); L.setst(2, 'A'); i = 0
    while i < len(pre):
        c = rnd.randint(1, 400); seg = pre[i:i + c]; ks = L.exec('B', seg, halt=rnd.choice([None, 1, 50]))
        if ks:
            if rnd.random() < .5: sc, st = L.export(), L.st; L = Locker(kind, K=b'', S=b''); L.import_(sc, st)
            L.exec('B', seg, klstart=ks)
        i += c
    if piece: L.setst(3, 'B', piece); L.exec('B', m[whole:whole + 1])
    out = rnd.choice([32, 41]) if not xof else rnd.choice([0, 8, 40]); Xo = 8 * out if not xof else 8 * out
    L.setst(6, 'B' if (Xo or not xof) else 'A', Xo if not xof else Xo)
    o = bytearray(max(out, 1) + (3 if xof and out else 0)); L.exec('C', out=o)
    want = kmac_bits(kind, KEY, S, b2v(m), nbits, Xo or 256)[:len(o)] if not (xof and out == 0) else kmac_bits(kind, KEY, S, b2v(m), nbits, 8 * len(o))
    if xof and out == 0: return bytes(o) == want and L.st == OUTPUT_
    if xof: want = kmac_bits(kind, KEY, S, b2v(m), nbits, 8 * out)  # XOF: right_encode(0), prefix of the stream
    return bytes(o[:out]) == want[:out] and bytes(o[out:]) == bytes(len(o) - out) and L.st == SUCCESS
rnd = random.Random(7)
for kind in RATE:
    bad = [s for s in range(40) if not plan_run(kind, rnd)]
    check('%s: 40 random plans = reference, Success after the bound' % kind, not bad, bad[:3])

done()
