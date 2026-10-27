#!/usr/bin/env pypy3.12
"""KAT of the Ascon Machines (Type 8 Modes 0, 3, 4, 5): Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128
(Zkl-ISA-machines.adoc KLE-Ascon-*; SP 800-232).  Oracle: sponge_ref (checked against published empty-input vectors).
NOT covered: Ascon-AEAD128 nonce variants (_Nonce, _Nonce_Mask), SKID/KeyType, kl.derive, SCC authentication.
Run: cd src && pypy3.12 kat/ascon-kat.py"""
import hashlib
from common import *
from sponge_model import *
import sponge_ref as R

H = bytes.fromhex
def msg(n, seed=1): return hashlib.shake_128(bytes([seed])).digest(n)
KEY = bytes(range(16)); NONCE = bytes(range(16))
HASHES = ('ASCON-HASH256', 'ASCON-XOF128', 'ASCON-CXOF128')

section('Published empty-input vectors')
check('Ascon-Hash256("") published', v2b(R.ref_ascon_hash((0, 0), 256), 32) == H('0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2'))
check('Ascon-XOF128("") published (32 B)', v2b(R.ref_ascon_hash((0, 0), 256, R.IV_XOF), 32) == H('473d5e6164f58b39dfd84aacdb8ae42ec2d91fed33388ee0d960d9b3993295c6'))
ct, nb, tag = R.ref_ascon_aead(KEY, NONCE, b'', b'')
check('Ascon-AEAD128 key=nonce=00..0f, empty AD/PT: tag published', v2b(tag, 16) == H('4427d64b8e1e1451fc445960f0839bb0'))

def run_hash(kind, m=b'', nbits=None, pre=b'', xs_out=0, nout=32, Z=None, chunks=(), halt_plan=None):
    """Hash with final piece of nbits (via Last_Block) after whole-byte prefix pre."""
    L = Locker(kind)
    if Z is not None:
        zb, zn = Z; L.setst(13, 'B', zn) if zn or True else None
        if zn: L.exec('B', zb)
    L.setst(2, 'A'); i = 0
    for c in list(chunks) + [len(pre)]:
        if i >= len(pre): break
        L.exec('B', pre[i:i + c]); i += c
    if nbits is not None:
        L.setst(3, 'B' if nbits else 'A', nbits)
        if nbits: L.exec('B', m)
    L.setst(6, 'B' if xs_out else 'A', xs_out)
    o = bytearray(nout); L.exec('C', out=o); return L, bytes(o)
def href(kind, v, n, outbytes, Z=None):
    if kind == 'ASCON-CXOF128': return v2b(R.ref_ascon_cxof((v, n), Z if Z else (0, 0), 8 * outbytes), outbytes)
    return v2b(R.ref_ascon_hash((v, n), 8 * outbytes, R.IV_HASH if kind == 'ASCON-HASH256' else R.IV_XOF), outbytes)

section('Hash256 / XOF128 / CXOF128: lengths, chunking, squeezing')
for k in HASHES:
    bad = []
    for n in (0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100):
        for ch in ((), (1, 3), (8, 1), (5, 2, 9)):
            m = msg(n); L, g = run_hash(k, pre=m, chunks=ch, nout=32)
            if g != href(k, b2v(m), 8 * n, 32): bad.append((n, ch))
    check('%s: 12 message lengths x 4 chunkings, 32 B output' % k, not bad, bad[:3], None)
    L, g = run_hash(k, pre=b'', nout=100) if k != 'ASCON-HASH256' else (None, b'')
    if k != 'ASCON-HASH256': check(k + ' XOF: 100 B in one exec, no Success', g == href(k, 0, 0, 100) and L.st == OUTPUT)
    L = Locker(k); L.setst(2, 'A'); L.exec('B', b'abc'); L.setst(6, 'A'); got = b''
    for n in (1, 7, 8, 9, 3, 16):
        x = bytearray(n); L.exec('C', out=x); got += bytes(x)
        if k == 'ASCON-HASH256' and len(got) >= 32: break
    want = href(k, b2v(b'abc'), 24, len(got))
    if k == 'ASCON-HASH256': got, want = got[:32], want[:32]
    check(k + ' split reads (1,7,8,9,3,16) concatenate to the stream', got == want, got, want)
    L = Locker(k); L.setst(2, 'A'); L.exec('B', msg(30)); L.setst(6, 'A'); o = bytearray(40); ks = L.exec('C', out=o, halt=1)
    check(k + ' halt at klstart=8 (after each 64-bit word)', ks == 8, ks, 8)
    ks = L.exec('C', out=o, klstart=ks)
    check(k + ' resumed output = reference', bytes(o)[:32] == href(k, b2v(msg(30)), 240, 40)[:32] and ks == 0)

section('Ascon-Hash256 digest bound and states')
L, g = run_hash('ASCON-HASH256', pre=b'abc'); check('Hash256: 32 B digest then Success', L.st == SUCCESS)
L, g = run_hash('ASCON-HASH256', pre=b'abc', nout=10); check('Hash256: 10-byte read stays Hash_Output', L.st == OUTPUT)
L, g = run_hash('ASCON-HASH256', pre=b'abc', xs_out=96, nout=12); check('Hash256: Xs=96 -> 12 B prefix, Success', g == href('ASCON-HASH256', b2v(b'abc'), 24, 32)[:12] and L.st == SUCCESS)
L = Locker('ASCON-HASH256'); L.setst(2, 'A'); L.setst(6, 'B', 264); check('Hash256: Xs=264 > d -> Invalid', L.se == SE_INV)
L = Locker('ASCON-HASH256'); L.setst(2, 'A'); L.setst(6, 'B', 12); check('Hash256: Xs=12 -> Invalid', L.se == SE_INV)
L = Locker('ASCON-XOF128'); L.setst(2, 'A'); L.setst(6, 'B', 2 ** 32); check('XOF128: Xs=2^32 -> Invalid', L.se == SE_INV)
L = Locker('ASCON-XOF128'); L.setst(2, 'A'); L.setst(6, 'B', 80); o = bytearray(16); L.exec('C', out=o)
check('XOF128: Xs=80 bits then Success, rest cleared', o[:10] == href('ASCON-XOF128', 0, 0, 10) and o[10:] == bytes(6) and L.st == SUCCESS)
L, g = run_hash('ASCON-HASH256', pre=b'abc', nout=32); L.exec('C', out=bytearray(8)); check('exec in Success -> Invalid', L.se == SE_INV)
for imm_k in HASHES[:2]:
    L = Locker(imm_k); L.setst(13, 'B', 8); check(imm_k + ': Set_Aux_Value not defined -> Invalid', L.se == SE_INV)

section('Final piece of any bit length (Hash_Absorb_Last_Block)')
for k in HASHES:
    bad = []
    for nb in (1, 5, 8, 13, 31, 56, 57, 63, 64):
        for pre in (b'', msg(3, 2), msg(8, 3), msg(13, 4)):
            m = msg(8, 9); v = b2v(pre) | (b2v(m) & mask(nb)) << (8 * len(pre)); n = 8 * len(pre) + nb
            L, g = run_hash(k, m[:(nb + 7) // 8], nb, pre)
            if g != href(k, v, n, 32): bad.append((nb, len(pre)))
    check('%s: final pieces (9 bit lengths x 4 prefixes) vs bit-level reference' % k, not bad, bad[:4], None)
L = Locker('ASCON-HASH256'); L.setst(2, 'A'); L.setst(3, 'B', 65); check('Xs=65 > b -> Invalid', L.se == SE_INV)
L = Locker('ASCON-HASH256'); L.setst(2, 'A'); L.setst(3, 'B', 5); L.setst(6, 'A'); check('Hash_Output before the piece -> Invalid', L.se == SE_INV)
L = Locker('ASCON-HASH256'); L.setst(2, 'A'); L.setst(3, 'A'); L.exec('B', b'x'); check('Xs=0 then data -> Invalid', L.se == SE_INV)
L = Locker('ASCON-HASH256'); L.setst(2, 'A'); L.setst(3, 'B', 12); L.exec('B', b'\x01'); check('KLLEN < Xs -> Invalid', L.se == SE_INV)

section('CXOF128 customization string')
bad = []
for zn in (0, 1, 8, 9, 63, 64, 65, 128, 2047, 2048):
    zb = msg((zn + 7) // 8, 5); zv = b2v(zb) & mask(zn)
    for pre in (b'', b'abc', msg(20)):
        L, g = run_hash('ASCON-CXOF128', pre=pre, nout=24, Z=(zb, zn))
        if g != href('ASCON-CXOF128', b2v(pre), 8 * len(pre), 24, (zv, zn)): bad.append((zn, len(pre)))
check('CXOF128: Z of 10 bit lengths (0..2048) x 3 messages vs reference', not bad, bad[:4], None)
L = Locker('ASCON-CXOF128'); L.setst(13, 'B', 2049); check('Xs=2049 -> Invalid', L.se == SE_INV)
L = Locker('ASCON-CXOF128'); L.setst(13, 'B', 16); L.exec('B', b'ab'); L.setst(2, 'A'); L.exec('B', b'm'); L.setst(13, 'B', 8)
check('Set_Aux_Value after Hash_Absorb -> Invalid', L.se == SE_INV)
L = Locker('ASCON-CXOF128'); L.setst(13, 'B', 16); L.exec('B', b'a'); L.setst(2, 'A'); check('Absorb with Z incomplete (cumul != Z_len) -> Invalid', L.se == SE_INV)
L = Locker('ASCON-CXOF128'); L.setst(13, 'B', 16); L.exec('B', b'ab'); L.exec('B', b'c'); check('Z exec beyond Z_len -> Invalid', L.se == SE_INV)
L = Locker('ASCON-CXOF128'); L.setst(13, 'B', 0); L.exec('B', b'x'); check('Z_len=0 with non-empty window -> Invalid', L.se == SE_INV)
L = Locker('ASCON-CXOF128'); L.setst(13, 'B', 0); L.exec('B', b''); check('Z_len=0 with an empty window -> Invalid', L.se == SE_INV)
L = Locker('ASCON-CXOF128'); L.setst(13, 'B', 24); L.exec('B', b'abcdef'); L.setst(2, 'A'); L.exec('B', b'q'); L.setst(6, 'B', 64); o = bytearray(8); L.exec('C', out=o)
check('Z exec truncated to Z_len bits (extra bytes ignored)', bytes(o) == href('ASCON-CXOF128', ord('q'), 8, 8, (b2v(b'abc'), 24)))
L = Locker('ASCON-CXOF128'); L.setst(13, 'B', 16); L.exec('B', b'ab'); L.setst(13, 'B', 8); L.exec('B', b'Z'); L.setst(2, 'A'); L.setst(6, 'B', 64); o = bytearray(8); L.exec('C', out=o)
check('Set_Aux_Value restarts the customization string', bytes(o) == href('ASCON-CXOF128', 0, 0, 8, (ord('Z'), 8)))
L = Locker('ASCON-CXOF128'); L.setst(13, 'B', 40); ks = L.exec('B', b'abcde', halt=1); L2 = Locker('ASCON-CXOF128'); L2.import_(L.export(), AUX)
check('SC in Set_Aux_Value keeps Z_len and cumul (viii)', L2.zlen == 40 and L2.cum == L.cum)
L.setst(2, 'A'); L.setst(6, 'B', 64); o = bytearray(8); L.exec('C', out=o)
check('Z exec of 5 B (no halt below 64-bit block) completes', bytes(o) == href('ASCON-CXOF128', 0, 0, 8, (b2v(b'abcde'), 40)))

section('Serialized Content of the hashes')
for k in HASHES:
    L = Locker(k); check(k + ' SC = 48 bytes', len(L.export()) == 48)
L = Locker('ASCON-HASH256'); L.setst(2, 'A'); L.exec('B', msg(11)); sc = L.export()
check('SC layout: state 40 | block_base 24 | last_block_len 64 | viii 0', sc[40:42] == v2b(24, 2) and sc[42:44] == v2b(64, 2) and sc[44:48] == bytes(4))
L.setst(6, 'B', 96); check('SC in Hash_Output: out_len = 96', L.export()[44:48] == v2b(96, 4))
for k in HASHES:
    for stage in ('absorb', 'output'):
        L = Locker(k);
        if k == 'ASCON-CXOF128': L.setst(13, 'B', 8); L.exec('B', b'Z')
        L.setst(2, 'A'); L.exec('B', msg(21))
        if stage == 'output': L.setst(6, 'A'); L.exec('C', out=bytearray(5))
        L2 = Locker(k); L2.import_(L.export(), L.st)
        if stage == 'absorb':
            for X in (L, L2): X.setst(6, 'A')
        a, b = bytearray(24), bytearray(24); L.exec('C', out=a); L2.exec('C', out=b)
        check('%s export/import in %s: same continuation' % (k, stage), a == b)
    L = Locker(k); ks = 0; L.setst(2, 'A'); m = msg(40); ks = L.exec('B', m, halt=1); L2 = Locker(k)
    if k == 'ASCON-CXOF128': pass
    L2.import_(L.export(), ABSORB); L2.exec('B', m, klstart=ks); L2.setst(6, 'A'); o = bytearray(32); L2.exec('C', out=o)
    check(k + ' halt in absorption (klstart=8), export, import, resume', bytes(o) == href(k, b2v(m), 320, 32))
    L = Locker(k); L.setst(2, 'A'); L.exec('B', msg(3)); L.exec('B', msg(20), klstart=1)
    check(k + ' klstart!=0 with block_base!=0 -> Invalid', L.se == SE_INV)

section('Ascon-AEAD128')
def pad128(ad): return ad + b'\x01' + bytes((-len(ad) - 1) % 16) if ad else b''
def enc(L, ad, pt, nbits=None, tag_len=None):
    L.setst(2, 'C', inp=NONCE)
    if ad: L.exec('B', pad128(ad))
    L.setst(7, 'A'); nb = 8 * len(pt) if nbits is None else nbits; ct = b''
    for i in range(nb // 128):
        o = bytearray(16); L.exec('A', pt[16 * i:16 * i + 16], out=o); ct += bytes(o)
    r = nb % 128; L.setst(9, 'B', r) if r else L.setst(9, 'B', 0)
    if r: o = bytearray(16); L.exec('A', pt[16 * (nb // 128):16 * (nb // 128) + 16].ljust(16, b'\0'), out=o); ct += bytes(o[:(r + 7) // 8])
    t = bytearray(16); L.exec('C', out=t); return ct, bytes(t)
def dec(L, ad, ct, nbits, tag):
    L.setst(2, 'C', inp=NONCE)
    if ad: L.exec('B', pad128(ad))
    L.setst(8, 'A'); pt = b''
    for i in range(nbits // 128):
        o = bytearray(16); L.exec('A', ct[16 * i:16 * i + 16], out=o); pt += bytes(o)
    r = nbits % 128; L.setst(10, 'B', r) if r else L.setst(10, 'B', 0)
    if r: o = bytearray(16); L.exec('A', ct[16 * (nbits // 128):].ljust(16, b'\0'), out=o); pt += bytes(o[:(r + 7) // 8])
    L.exec('B', tag); return pt
bad = []; badd = []
for adn in (0, 1, 15, 16, 17, 32, 33):
    for pn in (0, 1, 15, 16, 17, 31, 32, 47):
        ad, pt = msg(adn, 4), msg(pn, 5)
        c, nb, tg = R.ref_ascon_aead(KEY, NONCE, ad, pt)
        L = Locker('ASCON-AEAD128', key=KEY); ct, t = enc(L, ad, pt)
        if ct != v2b(c, pn) or t != v2b(tg, 16) or L.st != SUCCESS: bad.append((adn, pn))
        L = Locker('ASCON-AEAD128', key=KEY); p = dec(L, ad, ct, 8 * pn, t)
        if p != pt or L.st != SUCCESS: badd.append((adn, pn))
check('encryption: 7 AD lengths x 8 PT lengths vs reference (ct, tag), Success', not bad, bad[:4], None)
check('decryption of the same: plaintext recovered, Success', not badd, badd[:4], None)
bad = []
for nbits in (1, 5, 8, 100, 127, 129, 255, 257):
    pt = msg((nbits + 7) // 8 + 1, 6); c, nb, tg = R.ref_ascon_aead(KEY, NONCE, b'AD', pt, nbits)
    L = Locker('ASCON-AEAD128', key=KEY); ct, t = enc(L, b'AD', pt, nbits)
    ok = b2v(ct) == c and nb == nbits and t == v2b(tg, 16)
    L = Locker('ASCON-AEAD128', key=KEY); p = dec(L, b'AD', ct, nbits, t); ok = ok and b2v(p) == b2v(pt) & mask(nbits) and L.st == SUCCESS
    if not ok: bad.append(nbits)
check('PT bit lengths 1..257: ciphertext of exactly that many bits, decrypts', not bad, bad)
pt = msg(20); c, nb, tg = R.ref_ascon_aead(KEY, NONCE, b'a', pt); L = Locker('ASCON-AEAD128', key=KEY); ct, t = enc(L, b'a', pt)
bt = bytearray(t); bt[3] ^= 4; L = Locker('ASCON-AEAD128', key=KEY); dec(L, b'a', ct, 160, bytes(bt)); check('tampered tag -> Failure', L.st == FAILURE)
bc = bytearray(ct); bc[2] ^= 1; L = Locker('ASCON-AEAD128', key=KEY); dec(L, b'a', bytes(bc), 160, t); check('tampered ciphertext -> Failure', L.st == FAILURE)
L = Locker('ASCON-AEAD128', key=KEY); dec(L, b'b', ct, 160, t); check('wrong AD -> Failure', L.st == FAILURE)
L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'C', inp=NONCE); L.setst(8, 'A'); L.setst(10, 'B', 0); L.exec('B', tg.to_bytes(16, 'little')[:0] + bytes(16))
check('empty message verify of a wrong tag -> Failure', L.st == FAILURE)

section('Ascon-AEAD128 tag length and rules')
for tl in (64, 72, 100, 128):
    pt = msg(20); c, nb, tg = R.ref_ascon_aead(KEY, NONCE, b'', pt)
    L = Locker('ASCON-AEAD128', key=KEY); L.setst(13, 'B', tl); ct, t = enc(L, b'', pt)
    check('tag_len=%d: tag = low bits of the 128-bit tag, rest cleared' % tl, b2v(t) == tg & mask(tl) and ct == v2b(c, 20))
    L = Locker('ASCON-AEAD128', key=KEY); L.setst(13, 'B', tl); dec(L, b'', ct, 160, t)
    check('tag_len=%d verifies' % tl, L.st == SUCCESS)
for tl in (63, 129, 1):
    L = Locker('ASCON-AEAD128', key=KEY); L.setst(13, 'B', tl); check('tag_len=%d -> Invalid' % tl, L.se == SE_INV)
L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'C', inp=NONCE); L.setst(13, 'B', 96); check('Set_Aux_Value outside Ready -> Invalid', L.se == SE_INV)
L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'A'); check('Hash_Absorb with Form A (no nonce) -> Invalid', L.se == SE_INV)
def _tail(f):
    L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'C', inp=NONCE); f(L); return L
A = _tail(lambda L: (L.setst(7, 'A'), L.setst(6, 'A'))); B = _tail(lambda L: (L.setst(7, 'A'), L.setst(9, 'B', 0)))
check('Encrypt -> Hash_Output (Form A bypass) == Enc_Last_Block Xs=0 entry', A.st == OUTPUT_ and A.export() == B.export())
A = _tail(lambda L: (L.setst(8, 'A'), L.setst(5, 'A'))); B = _tail(lambda L: (L.setst(8, 'A'), L.setst(10, 'B', 0)))
check('Decrypt -> Hash_Verify (Form A bypass) == Dec_Last_Block Xs=0 entry', A.st == VERIFY and A.export() == B.export())
check('bypass with Form B -> wrong Form, Invalid', _tail(lambda L: (L.setst(7, 'A'), L.setst(6, 'B', 0))).se == SE_INV)
for last, ex in ((9, 7), (10, 8)):
    L = _tail(lambda L: (L.setst(ex, 'A'), L.setst(last, 'B', 40))); o = bytearray(16); L.exec('A', bytes(16), out=o)
    check('Last_Block %d exec auto-transitions to Output/Verify' % last, L.st == (OUTPUT_ if last == 9 else VERIFY))
    L = _tail(lambda L: (L.setst(ex, 'A'), L.setst(last, 'B', 40))); L.exec('A', bytes(2), out=bytearray(16)); check('Last_Block %d short KLLEN -> Invalid' % last, L.se == SE_INV)
    L = _tail(lambda L: (L.setst(ex, 'A'), L.setst(last, 'B', 40))); L.exec('A', bytes(16), klstart=16, out=bytearray(16)); check('Last_Block %d empty window keeps State' % last, L.st == last)
    L = _tail(lambda L: (L.setst(ex, 'A'), L.setst(last, 'B', 40), L.setst(6 if last == 9 else 5, 'A'))); check('leaving Last_Block %d with Xs!=0 before exec -> Invalid' % last, L.se == SE_INV)
L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'C', inp=NONCE); L.setst(7, 'A'); L.setst(9, 'B', 128); check('Enc_Last_Block Xs=128 -> Invalid', L.se == SE_INV)
L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'C', inp=NONCE); L.setst(7, 'A'); L.setst(10, 'B', 5); check('Dec_Last_Block from Encrypt -> Invalid', L.se == SE_INV)
L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'C', inp=NONCE); L.setst(7, 'A'); L.exec('B', bytes(16)); check('Form B exec in Encrypt -> Invalid', L.se == SE_INV)
L = Locker('ASCON-AEAD128', key=KEY); L.exec('A', bytes(16), out=bytearray(16)); check('exec in Ready -> Invalid', L.se == SE_INV)
L = Locker('ASCON-AEAD128', key=KEY); ct, t = enc(L, b'', b'x'); L.exec('C', out=bytearray(16)); check('exec in Success -> Invalid', L.se == SE_INV)
L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'C', inp=NONCE); L.setst(7, 'A'); L.setst(9, 'B', 0); o = bytearray(8); L.exec('C', out=o)
check('Hash_Output KLLEN < tag_len -> Invalid', L.se == SE_INV)
for pol, okenc, okdec in ((1, True, False), (2, False, True), (3, True, True)):
    L = Locker('ASCON-AEAD128', policy=pol, key=KEY); L.setst(2, 'C', inp=NONCE); L.setst(7, 'A'); check('MachinePolicy=%d: Encrypt %s' % (pol, 'admitted' if okenc else 'refused'), (L.st == ENC) == okenc)
    L = Locker('ASCON-AEAD128', policy=pol, key=KEY); L.setst(2, 'C', inp=NONCE); L.setst(8, 'A'); check('MachinePolicy=%d: Decrypt %s' % (pol, 'admitted' if okdec else 'refused'), (L.st == DEC) == okdec)

section('Ascon-AEAD128 Serialized Content')
L = Locker('ASCON-AEAD128', key=KEY); L.setst(13, 'B', 96); sc = L.export()
check('SC length 64 B, key | state | last_block_len | tag_len', len(sc) == 64 and sc[:16] == KEY and sc[58:60] == v2b(96, 2))
pt = msg(40); ad = b'hdr'; c, nb, tg = R.ref_ascon_aead(KEY, NONCE, ad, pt)
for stage in ('absorb', 'encrypt', 'last'):
    L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'C', inp=NONCE); L.exec('B', pad128(ad))
    if stage in ('encrypt', 'last'):
        L.setst(7, 'A'); o = bytearray(16); L.exec('A', pt[:16], out=o)
    if stage == 'last': L.exec('A', pt[16:32], out=bytearray(16)); L.setst(9, 'B', 64)
    L2 = Locker('ASCON-AEAD128', key=b''); L2.import_(L.export(), L.st)
    outs = []
    for X in (L, L2):
        if stage == 'absorb': X.setst(7, 'A'); X.exec('A', pt[:16], out=bytearray(16))
        if stage != 'last' and True: o = bytearray(16); X.exec('A', pt[16:32], out=o); X.setst(9, 'B', 64)
        o = bytearray(16); X.exec('A', pt[32:40].ljust(16, b'\0'), out=o); t = bytearray(16); X.exec('C', out=t); outs.append((bytes(o), bytes(t)))
    check('export/import in %s: same continuation and tag = reference' % stage, outs[0] == outs[1] and outs[0][1] == v2b(tg, 16))

section('SP 800-232 style counts: message 00..n-1 (own reference), Machine vs reference')
for k in HASHES:
    bad = [n for n in range(0, 34) if run_hash(k, pre=bytes(range(n)), nout=32)[1] != href(k, b2v(bytes(range(n))), 8 * n, 32)]
    check('%s: counts for message lengths 0..33 B' % k, not bad, bad)
bad = []
for n in (0, 1, 15, 16, 17, 33):
    c, nb, tg = R.ref_ascon_aead(KEY, NONCE, bytes(range(n)), bytes(range(n)))
    L = Locker('ASCON-AEAD128', key=KEY); ct, t = enc(L, bytes(range(n)), bytes(range(n)))
    if (ct, t) != (v2b(c, n), v2b(tg, 16)): bad.append(n)
check('AEAD128: AD = PT = 00..n-1 counts', not bad, bad)

section('Generic sequence: random plans for Hash256 / XOF128 / CXOF128')
import random
rnd = random.Random(11)
for k in HASHES:
    bad = []
    for s in range(40):
        nbits = rnd.choice([0, 1, 8, 63, 64, 65, 200, 640]); m = msg((nbits + 7) // 8 + 1, s); whole = nbits // 8; piece = nbits - 8 * whole
        Z = (msg(3, 5), 17) if k == 'ASCON-CXOF128' and s % 2 else None
        L = Locker(k)
        if Z: L.setst(13, 'B', Z[1]); L.exec('B', Z[0])
        L.setst(2, 'A'); i = 0
        while i < whole:
            c = rnd.randint(1, 30); seg = m[i:min(i + c, whole)]; ks = L.exec('B', seg, halt=rnd.choice([None, 1, 8]))
            if ks:
                if rnd.random() < .5: sc, st = L.export(), L.st; L = Locker(k); L.import_(sc, st)
                L.exec('B', seg, klstart=ks)
            i += c
        if piece: L.setst(3, 'B', piece); L.exec('B', m[whole:whole + 1])
        bound = rnd.choice([0, 8, 96, 256]) if k != 'ASCON-HASH256' else rnd.choice([0, 8, 96, 256])
        L.setst(6, 'B' if bound else 'A', bound); o = bytearray(40); L.exec('C', out=o)
        unb = k != 'ASCON-HASH256' and not bound; n = bound // 8 or (40 if unb else 32)
        want = href(k, b2v(m) & mask(nbits), nbits, n, (b2v(Z[0]) & mask(Z[1]), Z[1]) if Z else None)
        ok = bytes(o[:n]) == want and bytes(o[n:]) == bytes(40 - n) and L.st == (OUTPUT if unb else SUCCESS)
        if not ok: bad.append((s, nbits, bound, L.st, bytes(o).hex()[:16], want.hex()[:16]))
    check('%s: 40 random plans (chunks, halts, export/import, piece, bound)' % k, not bad, bad[:4])

section('Tag is not a derive source; out_len on entering Ready; Error-State setst; GR40')
L = Locker('ASCON-AEAD128', key=KEY); L.setst(13, 'B', 100); ct, t = enc(L, b'', b'abc')
L2 = Locker('ASCON-AEAD128', key=KEY); L2.setst(2, 'C', inp=NONCE); L2.setst(7, 'A'); L2.setst(9, 'B', 0)
d = Locker('ASCON-AEAD128', key=bytes(16)); derive(L2, d, 13)
check('AEAD tag (Hash_Output) as source: source Invalid, destination untouched', L2.se == SE_INV and d.st == READY and d.key == 0)
Lh = Locker('ASCON-HASH256'); Lh.setst(2, 'A'); Lh.exec('B', b'a'); Lh.setst(6, 'A'); Lh.exec('C', out=bytearray(8)); before = Lh.ol
Lh.setst(1, 'A'); check('Hash256: entering Ready zeroes out_len', before == 192 and Lh.ol == 0 and Lh.export()[44:48] == bytes(4), before)
for k in HASHES:
    L = Locker(k); L.setst(2, 'A'); L.exec('B', b'abc')
    for imm in (48, 53):
        M = Locker(k); M.setst(2, 'A'); M.setst(imm, 'A'); check('%s: setst %d -> Invalid' % (k, imm), M.se == SE_INV)
    L.setst(0, 'A'); st0 = (L.st, L.se); L.setst(1, 'A'); L.exec('B', b'a'); L.rstrl(2)
    check('%s: kl.clear -> Unconfigured; later setst/exec/rstrl change nothing' % k, st0 == (0, 0) and (L.st, L.se) == (0, 0))
for scd, scs, want in ((1, 2, 5), (2, 1, 0), (2, 2, 0)):
    d = Locker('ASCON-AEAD128', key=bytes(16)); d.scprot = scd; s = Secret(bytes(range(32)), restricted=True, scprot=scs); derive(s, d, 32)
    check('GR40 restricted transfer, dst SCProtection %d, src %d -> %s' % (scd, scs, 'Privilege Violation' if want else 'transferred'), (d.se == 5) if want else (d.st == READY and d.se == 0 and d.key == b2v(bytes(range(16)))), (d.st, d.se))
d = Locker('ASCON-AEAD128', key=bytes(16)); d.scprot = 1; s = Secret(bytes(range(32)), restricted=False, scprot=2); derive(s, d, 32)
check('GR41 unrestricted transfer applies no SCProtection check', d.se == 0 and d.key != 0)

section('Negative controls')
m = msg(12)
control('domain separation: XOF128 differs from Hash256 on the same message', href('ASCON-XOF128', b2v(m), 96, 32) != href('ASCON-HASH256', b2v(m), 96, 32))
control('CXOF128 with Z differs from Z empty', href('ASCON-CXOF128', 0, 0, 16, (1, 8)) != href('ASCON-CXOF128', 0, 0, 16))
control('padding bit at bit 7 instead of bit 0 changes the hash',
        R.ref_sponge((b2v(m), 96), R.ascon12, 64, R.ascon12(R.IV_HASH), lambda n: [0] * 7 + [1] + [0] * ((-(n + 8)) % 64), 256)
        != R.ref_ascon_hash((b2v(m), 96), 256))
control('caller-padded message differs from the Machine-padded one', href('ASCON-HASH256', b2v(m + b'\x01'), 104, 32) != href('ASCON-HASH256', b2v(m), 96, 32))
L = Locker('ASCON-AEAD128', key=KEY); ct, t = enc(L, b'', b'abc')
control('a zero tag does not verify (Failure is reachable)', (dec(Locker('ASCON-AEAD128', key=KEY), b'', ct, 24, bytes(16)), True)[1] and t != bytes(16))
L = Locker('ASCON-AEAD128', key=KEY); dec(L, b'', ct, 24, bytes(16)); control('verify of a wrong tag ends in Failure', L.st == FAILURE)

section('Ascon-AEAD128_Nonce (stored nonce) and _Nonce_Mask (nonce XOR K2)')
K2 = bytes(range(100, 116)); NN = bytes(range(50, 66))
def full(L, setup, ad, pt):
    L.setst(*setup)
    if ad: L.exec('B', pad128(ad))
    L.setst(7, 'A'); ct = b''
    for i in range(len(pt) // 16): o = bytearray(16); L.exec('A', pt[16 * i:16 * i + 16], out=o); ct += bytes(o)
    r = len(pt) % 16; L.setst(9, 'B', 8 * r)
    if r: o = bytearray(16); L.exec('A', pt[-r:].ljust(16, b'\0'), out=o); ct += bytes(o[:r])
    tg = bytearray(16); L.exec('C', out=tg); return ct, bytes(tg)
bad = []
for adn in (0, 5, 16, 20):
    for pn in (0, 3, 16, 29):
        ad, pt = msg(adn, 4), msg(pn, 5)
        c, nb, tg = R.ref_ascon_aead(KEY, NN, ad, pt)
        r1 = full(Locker('ASCON-AEAD128_NONCE', key=KEY, nonce=NN), (2, 'A'), ad, pt)
        nm = bytes(a ^ b for a, b in zip(NN, K2)); c2, nb2, tg2 = R.ref_ascon_aead(KEY, nm, ad, pt)
        r2 = full(Locker('ASCON-AEAD128_NONCE_MASK', key=KEY, K2=K2), (2, 'C', 0, NN), ad, pt)
        if r1 != (v2b(c, pn), v2b(tg, 16)): bad.append(('wsn', adn, pn))
        if r2 != (v2b(c2, pn), v2b(tg2, 16)): bad.append(('mask', adn, pn))
check('_Nonce (Form A setup) and _Nonce_Mask (INPUT xor K2): 16 AD/PT pairs vs reference', not bad, bad[:3], None)
L = Locker('ASCON-AEAD128_NONCE', key=KEY, nonce=NN); L.setst(2, 'C', inp=NONCE); check('_Nonce: Form C into Hash_Absorb is a wrong Form -> Invalid', L.se == SE_INV)
L = Locker('ASCON-AEAD128_NONCE_MASK', key=KEY, K2=K2); L.setst(2, 'A'); check('_Nonce_Mask: Form A into Hash_Absorb -> Invalid', L.se == SE_INV)
L = Locker('ASCON-AEAD128_NONCE', key=KEY, nonce=NN); L.setst(13, 'B', 80); full_ok = L.se == 0 and L.st == READY
check('_Nonce: tag_len Set_Aux_Value as in the base Machine', full_ok)
L = Locker('ASCON-AEAD128_NONCE', key=KEY, nonce=NN); n1 = L.export(); check('SC _Nonce: base SC (60 B) then nonce, padded to 80 B', len(n1) == 80 and n1[60:76] == NN and n1[76:] == bytes(4), len(n1))
L = Locker('ASCON-AEAD128_NONCE_MASK', key=KEY, K2=K2); m1 = L.export(); check('SC _Nonce_Mask: K1 | K2 | state | lbl | tag_len (80 B)', len(m1) == 80 and m1[:16] == KEY and m1[16:32] == K2, len(m1))
for kind, kw, setup in (('ASCON-AEAD128_NONCE', dict(nonce=NN), (2, 'A')), ('ASCON-AEAD128_NONCE_MASK', dict(K2=K2), (2, 'C', 0, NN))):
    L = Locker(kind, key=KEY, **kw); L.setst(*setup); L.exec('B', pad128(b'hdr')); L.setst(7, 'A'); L.exec('A', msg(16), out=bytearray(16))
    L2 = Locker(kind, key=b'', **kw); L2.import_(L.export(), L.st); a = bytearray(16); b = bytearray(16)
    for X, o in ((L, a), (L2, b)): X.exec('A', msg(16, 2), out=o)
    check(kind + ' export/import mid-encryption: same continuation', a == b)

section('kl.derive into AEAD key fields (GR37-GR43)')
def dk(kind='ASCON-AEAD128', data=bytes(range(40)), length=None, restricted=True, shared=True, ks=0, **kw):
    d = Locker(kind, **kw); s = Secret(data, restricted, shared); derive(s, d, len(data) if length is None else length, ks); return d, s
d, s = dk(restricted=False, data=KEY + b'x' * 8); c, nb, tg = R.ref_ascon_aead(KEY, NONCE, b'', b'abc')
check('16-byte key from a 24-byte unrestricted secret: first 16 B become the key', full(d, (2, 'C', 0, NONCE), b'', b'abc') == (v2b(c, 3), v2b(tg, 16)))
d, s = dk(data=KEY + K2 + b'z' * 8, restricted=False, kind='ASCON-AEAD128_NONCE_MASK')
c, nb, tg = R.ref_ascon_aead(KEY, bytes(a ^ b for a, b in zip(NONCE, K2)), b'', b'abc')
check('K1|K2 from a 40-byte unrestricted secret into _Nonce_Mask', full(d, (2, 'C', 0, NONCE), b'', b'abc') == (v2b(c, 3), v2b(tg, 16)))
d, s = dk(kind='ASCON-AEAD128_NONCE_MASK'); check('restricted shared secret into K1|K2: both Invalid (GR39.4)', d.se == SE_INV and s.bad)
d, s = dk(kind='ASCON-AEAD128_NONCE', restricted=False, nonce=NN, key=KEY); check('_Nonce is not a destination -> dest Invalid', d.se == SE_INV and not s.bad)
for nm, kw in (('length 15', dict(length=15)), ('length 0', dict(length=0)), ('klstart 8', dict(ks=1))):
    d, s = dk(restricted=False, **kw); check('derive %s -> destination Invalid' % nm, d.se == SE_INV and not s.bad)
d, s = dk(data=bytes(12), length=16, restricted=False); check('12-byte source shorter than the key -> source Invalid (GR39.7)', s.bad and d.se == 0 and d.st == READY)
d = Locker('ASCON-AEAD128', key=KEY); d.setst(2, 'C', inp=NONCE); derive(Secret(bytes(16), False), d, 16); check('destination not in Ready -> Invalid (GR39.3)', d.se == SE_INV)
d = Locker('ASCON-AEAD128', skid=0x0101010101010101, sks={0x0101010101010101: KEY}); derive(Secret(bytes(16), False), d, 16); check('SKID-keyed destination refuses derive (KeyType 1) -> Invalid', d.se == SE_INV)
d, s = dk(shared=False, restricted=False, data=bytes(range(16))); check('CMAC-type output into AEAD key: admitted (GR43)', d.se == 0 and d.key == b2v(bytes(range(16))))
d, s = dk(kind='ASCON-AEAD128_NONCE_MASK', shared=False, restricted=False, data=bytes(16)); check('16-byte CMAC-type output into K1|K2 (32 B needed): dest Invalid', d.se == SE_INV)
o = Locker('ASCON-XOF128'); o.setst(2, 'A'); o.setst(6, 'A'); d = Locker('ASCON-AEAD128'); derive(o, d, 16); check('sponge Hash_Output is not a source: source Invalid, dest untouched', o.se == SE_INV and d.st == READY)
t2 = Locker('ASCON-AEAD128', key=KEY); ct, t_ = enc(t2, b'', b'x'); d = Locker('ASCON-AEAD128'); derive(t2, d, 16); check('AEAD tag output is not a source', t2.se == SE_INV and d.st == READY)

section('kl.derive into Ascon hashes (shared secret as message)')
for k in HASHES:
    d = Locker(k); d.setst(2, 'A'); s = Secret(b'S' * 32, False); derive(s, d, 32); d.setst(6, 'A'); o = bytearray(16); d.exec('C', out=o)
    check(k + ': 32-byte shared secret absorbed', bytes(o) == href(k, b2v(b'S' * 32), 256, 16))
    for nm, kw in (('length 31', dict(length=31)), ('klstart 8', dict(ks=1))):
        d = Locker(k); d.setst(2, 'A'); derive(Secret(b'S' * 32, False), d, kw.get('length', 32), kw.get('ks', 0)); check(k + ' derive %s -> dest Invalid' % nm, d.se == SE_INV)
    d = Locker(k); d.setst(2, 'A'); d.setst(3, 'B', 8); derive(Secret(b'S' * 32, False), d, 32); check(k + ' destination in Last_Block -> Invalid', d.se == SE_INV)
    d = Locker(k); d.setst(2, 'A'); s = Secret(b'S' * 32, False, False); derive(s, d, 32); check(k + ' CMAC-type source: both Invalid', d.se == SE_INV and s.bad)

section('MachinePolicy, rstrl, SKID, unsupported policy, Form D')
for k in HASHES: check(k + ' MachinePolicy=1 -> unsupported Metadata (0, 1)', (Locker(k, policy=1).st, Locker(k, policy=1).se) == (0, 1))
L = Locker('ASCON-AEAD128', policy=3, key=KEY); L.rstrl(1); L.setst(2, 'C', inp=NONCE); L.setst(8, 'A'); check('rstrl 3 -> 1: Decrypt refused', L.se == SE_INV)
L = Locker('ASCON-AEAD128', policy=3, key=KEY); L.rstrl(1); L.setst(2, 'C', inp=NONCE); L.setst(7, 'A'); check('rstrl 3 -> 1: Encrypt still admitted', L.st == ENC)
L = Locker('ASCON-AEAD128', policy=1, key=KEY); L.rstrl(2); check('rstrl to a forbidden value -> Invalid (GR25)', L.se == SE_INV)
L = Locker('ASCON-AEAD128', policy=2, key=KEY); L.rstrl(mask(64)); check('rstrl all-ones: unchanged', L.policy == 2 and L.st == READY)
L = Locker('ASCON-HASH256'); L.rstrl(0); check('rstrl on an ungated Machine: no change', L.policy == 0 and L.st == READY)
SK = {0x0101010101010101: KEY}; c, nb, tg = R.ref_ascon_aead(KEY, NONCE, b'a', b'abc')
check('SKID-keyed AEAD128 = AEAD with the resolved key', full(Locker('ASCON-AEAD128', skid=0x0101010101010101, sks=SK), (2, 'C', 0, NONCE), b'a', b'abc') == (v2b(c, 3), v2b(tg, 16)))
check('SKID unresolved -> Invalid', Locker('ASCON-AEAD128', skid=5, sks=SK).se == SE_INV)
check('SC with SKID: key field holds the 8-byte SKID (64 B)', Locker('ASCON-AEAD128', skid=0x0101010101010101, sks=SK).export()[:8] == v2b(0x0101010101010101, 8))
k2m = Locker('ASCON-AEAD128_NONCE_MASK', skid=0x0101010101010101, sks={0x0101010101010101: (KEY, K2)})
c2, nb2, tg2 = R.ref_ascon_aead(KEY, bytes(a ^ b for a, b in zip(NONCE, K2)), b'', b'abc')
check('SKID _Nonce_Mask: one SKID retrieves K1 and K2', full(k2m, (2, 'C', 0, NONCE), b'', b'abc') == (v2b(c2, 3), v2b(tg2, 16)))
L = Locker('ASCON-XOF128'); L.setst(2, 'A'); io = bytearray(b'abc'); L.exec_d(io, 3); L.setst(6, 'A'); io = bytearray(b'\xff' * 40); L.exec_d(io, 40)
check('Form D absorb + output on XOF128', bytes(io) == href('ASCON-XOF128', b2v(b'abc'), 24, 40))
L = Locker('ASCON-AEAD128', key=KEY); L.setst(2, 'C', inp=NONCE); io = bytearray(pad128(b'ad')); L.exec_d(io, 16); L.setst(7, 'A'); io = bytearray(msg(16)); L.exec_d(io, 16)
c, nb, tg = R.ref_ascon_aead(KEY, NONCE, b'ad', msg(16)); check('Form D on AEAD: Hash_Absorb (B) and Encrypt (A, in place)', bytes(io) == v2b(c, 16))
L = Locker('ASCON-HASH256'); io = bytearray(b'q' * 4); L.exec_d(io, 4); check('Form D in Ready -> Invalid, window zeroed', L.se == SE_INV and bytes(io) == bytes(4))
check('Form D with unconfigured KLIOBUF -> illegal instruction', raises(lambda: Locker('ASCON-HASH256').exec_d(bytearray(4), 0), exc=IllegalInstruction))

done()
