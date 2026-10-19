#!/usr/bin/env python3
"""SM3 KAT for KLE: <<KLE-SM3>>, i.e. the <<KLE-SHA-2>> Machine with the GB/T 32905-2016 core.
The core is from scratch; hashlib 'sm3', where present, is only a labeled reference oracle."""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (KL_STATE_UNCONFIGURED, KL_STATE_READY, KL_STATE_HASH_ABSORB, KL_STATE_HASH_LAST_BLOCK,
                    KL_STATE_HASH_OUTPUT, KL_STATE_SUCCESS, KL_STATE_FAILURE, KL_STATE_INVALID, KL_STATE_UNSUPPORTED, section, check,
                    control, raises, done, hash_run, hash_msgs, check_hash)
from sha2_sm3_common import HART, MdHash, MdPort, KeyDest, Source, kl_derive, A, O, R, B, C, run

# ---------------------------------------------------------------- GB/T 32905-2016

M32 = 0xffffffff
IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
rotl = lambda x, r: ((x << (r % 32)) | (x >> (32 - r % 32))) & M32
P0 = lambda x: x ^ rotl(x, 9) ^ rotl(x, 17)
P1 = lambda x: x ^ rotl(x, 15) ^ rotl(x, 23)

def compress(V, W):
    """CF, sect. 5.3.3."""
    W = list(W)
    for j in range(16, 68):
        W.append(P1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15)) ^ rotl(W[j - 13], 7) ^ W[j - 6])
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        SS1 = rotl((rotl(A, 12) + E + rotl(0x79cc4519 if j < 16 else 0x7a879d8a, j)) & M32, 7)
        FF = (A ^ B ^ C) if j < 16 else ((A & B) | (A & C) | (B & C))
        GG = (E ^ F ^ G) if j < 16 else ((E & F) | (~E & G & M32))
        TT1 = (FF + D + (SS1 ^ rotl(A, 12)) + (W[j] ^ W[j + 4])) & M32
        TT2 = (GG + H + SS1 + W[j]) & M32
        A, B, C, D, E, F, G, H = TT1, A, rotl(B, 9), C, P0(TT2), E, rotl(F, 19), G
    return [v ^ x for v, x in zip(V, (A, B, C, D, E, F, G, H))]

def pad(nbytes):
    """The padding of sect. 5.2, for the reference."""
    return b'\x80' + bytes(-(nbytes + 9) % 64) + (8 * nbytes).to_bytes(8, 'big')

def sm3_ref(msg):
    """Independent byte-oriented big-endian SM3 (no KLE model)."""
    m, V = msg + pad(len(msg)), IV
    for i in range(0, len(m), 64):
        V = compress(V, [int.from_bytes(m[j:j + 4], 'big') for j in range(i, i + 64, 4)])
    return b''.join(v.to_bytes(4, 'big') for v in V)

# ---------------------------------------------------------------- KLE model

class Sm3(MdHash):
    """<<KLE-SM3>>: (w, b, n, t) = (32, 512, 256, 256), granularity 8 bits."""
    def __init__(s, **kw): super().__init__('SM3', 32, 512, 256, 256, IV, compress, **kw)

    @classmethod
    def load(cls, st, c1): return cls().restore(st, c1)

IV_STATE = Sm3().iv_state

class Port(MdPort):
    """<<Zkl-software.adoc#KLE-pseudocode-hash>> on an Sm3 locker."""
    def __init__(p, cl=None): super().__init__(cl or Sm3().provision())
    def imported(p, img): return Port(Sm3.load(*img))

def sm3_ref_bits(msg, nbits):
    """SM3 on a bit string (GB/T 32905 sect. 5.2), independent of md_pad and of the model: the first nbits bits of msg,
    MSB-first."""
    bits = ''.join(format(x, '08b') for x in msg)[:nbits]
    bits += '1' + '0' * (-(nbits + 65) % 512) + format(nbits, '064b')
    V = IV
    for o in range(0, len(bits), 512):
        V = compress(V, [int(bits[o + j:o + j + 32], 2) for j in range(0, 512, 32)])
    return b''.join(v.to_bytes(4, 'big') for v in V)

# ---------------------------------------------------------------- vectors and drivers

# GB/T 32905-2016 appendix A
TV = [('"abc"', b'abc', '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
      ('"abcd" x 16', b'abcd' * 16, 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')]
DIG_ABC, DIG_512 = bytes.fromhex(TV[0][2]), bytes.fromhex(TV[1][2])

def digest(msg, plan='multi', **kw):
    """Plans: multi (3 transfers, 2 reads), interrupt (halt at each 3.i, resume), export (mid-block),
    odd (transfers of 1 and 3 bytes, then a 1-byte read)."""
    cl = Sm3(**kw).provision()
    A(cl)
    if plan == 'multi':
        c1 = 4 if len(msg) > 12 else len(msg)
        c2 = c1 + max(4, (len(msg) - c1) // 8 * 4)
        run(cl, *([B(p) for p in (msg[:c1], msg[c1:c2], msg[c2:]) if p] or [B(b'')]))
    elif plan == 'odd':
        run(cl, B(msg[:1]), B(msg[1:4]), B(msg[4:]))
    elif plan == 'interrupt':
        r = run(cl, B(msg[:4]), lambda c: c.exec('B', msg[4:], halt=True))[0]
        while r == 'interrupted':
            r = cl.exec('B', msg[4:], halt=True, resume=True)[0]
    else:
        B(msg[:len(msg) // 2])(cl)
        cl = Sm3.load(cl.st, cl.export())
        B(msg[len(msg) // 2:])(cl)
    O(cl)
    reads = {'multi': (24, 8), 'odd': (1, 31)}.get(plan, (32,))
    out = b''.join(run(cl, C(n))[1] for n in reads)
    return out if cl.st == KL_STATE_SUCCESS else None

def absorbing(data=b'', **kw):
    cl = Sm3(**kw).provision()
    run(cl, A, *([B(data)] if data else []))
    return cl

def outputting(msg=b'abc'):
    cl = absorbing(msg)
    O(cl)
    return cl

# ---------------------------------------------------------------- checks

section('GB/T 32905-2016 vectors')
for label, msg, h in TV:
    want = bytes.fromhex(h)
    for plan in ('multi', 'interrupt', 'export', 'odd'):
        check(f'SM3 {label} {plan}', None, digest(msg, plan), want)
    check(f'byte-oriented reference {label}', None, sm3_ref(msg), want)
    if 'sm3' in hashlib.algorithms_available:
        check(f'[oracle] hashlib sm3 {label}', None, hashlib.new('sm3', msg).digest(), want)
LENS = list(range(130)) + [200, 255, 256, 512, 1000]
msgs = {L: bytes((7 * i + 3) & 0xff for i in range(L)) for L in LENS}
check(f'KLE model = byte-oriented reference, 3 plans x {len(LENS)} lengths (0..1000 B)', None,
      [L for L in LENS for plan in ('multi', 'interrupt', 'export') if digest(msgs[L], plan) != sm3_ref(msgs[L])],
      [])

section('The generic sequence (<<Zkl-software.adoc#KLE-pseudocode-hash>>): chunks, final pieces, halts, export/import')
check_hash('SM3', Port, lambda m, nb, o: (sm3_ref(m[:nb // 8]) if nb % 8 == 0 else sm3_ref_bits(m, nb))[:o],
           hash_msgs(64, edges=(55, 56), bits=True), 32)
check('the bit-string reference agrees with the byte reference on "abc" and 64 B', None,
      (sm3_ref_bits(b'abc', 24), sm3_ref_bits(b'abcd' * 16, 512)), (DIG_ABC, DIG_512))
res = []
for nb in (1, 5, 447, 448, 449, 511, 1000):
    m = bytes((3 * i + 7) & 0xFF for i in range(-(-nb // 8)))
    res.append(hash_run(Port(), m, nb, 32)[0] == sm3_ref_bits(m, nb))
check('bit-length messages of 1, 5, 447, 448, 449, 511 and 1000 bits: the final piece MSB-first (<<KLE-SM3>>)', all(res))
r = [hash_run(Port(), b'abc', 24, x // 8, end=('B', x))[:2] for x in (8, 248, 256)]
check('bound: Form B Xs = 8, t - 8, t gives that prefix and _Success_; Xs = 264 -> _Invalid_', None,
      (r, (lambda c: (c.setst(KL_STATE_HASH_OUTPUT, 'B', 264), c.st)[1])(absorbing(b'abc'))),
      ([(DIG_ABC[:x // 8], KL_STATE_SUCCESS) for x in (8, 248, 256)], KL_STATE_INVALID))
control('caller-padded message: the digest differs', digest(b'abc' + pad(3)) != DIG_ABC)

check('a PI with _MachinePolicy_ = 1: unsupported Metadata; a kl.restrictl of the unused _MachinePolicy_ -> '
      '_Invalid_, one with a zero field changes nothing (<<KLE-hash-functions-MACs-XOFs>>, '
      '<<KLE-instruction-restrict>>)',
      None, (Sm3().provision(1).st, absorbing(data=b'abc').restrictl(1).st, absorbing(data=b'abc').restrictl(0).st),
      (KL_STATE_UNSUPPORTED, KL_STATE_INVALID, KL_STATE_HASH_ABSORB))

section('Serialized Content')
check('Content1 = n+16+16+32+64+b bits, padded to 128', None, len(absorbing(bytes(8)).export()), 112)

section('State machine')
cl = Sm3().provision()
check('"abc" unpadded, then the kl.setst into _Hash_Output_ with block_base != 0: the Machine pads, digest correct',
      run(cl, A, B(b'abc'), O, C(32))[1] == DIG_ABC and cl.st == KL_STATE_SUCCESS)
for label, ops in [
        ('kl.exec in _Ready_ (GR17)', (B(b'abc'),)),
        ('Form B kl.setst to _Hash_Absorb_', (lambda c: c.setst(KL_STATE_HASH_ABSORB, 'B'),)),
        ('same-State kl.setst to _Hash_Absorb_', (A, A)),
        ('same-State kl.setst to _Hash_Output_ (GR17)', (A, B(b'abc'), O, O)),
        ('kl.setst #kl_state_hash_last_block without Xs', (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B'))),
        ('a kl.exec after Xs = 0 (MR10)', (A, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 0), B(b'a'))),
        ('_Ready_ -> _Hash_Output_', (O,)),
        ('Form C kl.exec in _Hash_Absorb_ (MR1), output zeroed', (A, C(16))),
        ('Form B kl.exec in _Hash_Output_ (MR1)', (A, B(b'abc'), O, B(bytes(64)))),
        ('kl.exec in _Success_ (MR1, GR28), output zeroed', (A, B(b'abc'), O, C(32), C(32)))]:
    cl = Sm3().provision()
    r = run(cl, *ops)
    check(f'_Invalid_: {label}', cl.st == KL_STATE_INVALID and not any(r[1] if r else b''))
res = []
for d, ks in ((b'', 0), (b'a', 2)):
    cl = Sm3().provision()
    run(cl, A, B(b'ab'), lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 16))
    HART.klstart = ks
    res.append((cl.exec('B', d, resume=ks != 0)[0], cl.st, HART.klstart))
check('final piece of 16 bits, KLLEN = 0, or KLLEN = 8 with klstart = 2: the length is checked before the empty '
      'window, _Invalid_ (MR2, GR44)', None, res, [('invalid', KL_STATE_INVALID, 0)] * 2)
check('kl.exec in _Invalid_: no operation, output zeroed (GR26, GR28)',
      C(32)(cl) == ('noop', bytes(32)) and cl.st == KL_STATE_INVALID)
cl = outputting()
HART.klstart = 4
check('Form C, klstart = 4 at the start of _Hash_Output_ (block_base = 0): the first 28 digest bytes in [4, 31]',
      None, (C(32)(cl), cl.st, HART.klstart), (('retired', b'\xa5' * 4 + sm3_ref(b'abc')[:28]), KL_STATE_HASH_OUTPUT, 0))
cl, res = outputting(), []
for ks in (32, 40, 4):
    HART.klstart = ks
    res.append((C(32)(cl), cl.st, HART.klstart))
    if ks == 40:
        C(1)(cl)                                  # block_base = 8: klstart = 4 is no interruption point
check('Form C, klstart >= KLLEN/8 (32, 40): empty window, only klstart = 0; klstart = 4 with block_base != 0 '
      '(no interruption point): _Invalid_, [4, 31] zeroed', None, res, [(('empty', b'\xa5' * 32), KL_STATE_HASH_OUTPUT, 0)] * 2
      + [(('invalid', b'\xa5' * 4 + bytes(28)), KL_STATE_INVALID, 0)])
cl = absorbing()
check('kl.setst #kl_state_success -> Invalid (GR19, GR18)',
      (raises(cl.setst, KL_STATE_SUCCESS), cl.st) == (False, KL_STATE_INVALID))
cl.setst(KL_STATE_UNCONFIGURED)
check('kl.clear; a later kl.exec or kl.setst performs no operation, output zeroed (GR26, GR28)',
      (cl.exec('C', nbytes=8), cl.setst(KL_STATE_READY), cl.st, cl.state)
      == (('noop', bytes(8)), None, KL_STATE_UNCONFIGURED, 0))
check('kl.setst #kl_state_failure on an Unconfigured locker: no operation (GR26)',
      (raises(cl.setst, KL_STATE_FAILURE), cl.st) == (False, KL_STATE_UNCONFIGURED))
check('a reserved #immed7 (54, 55) raises illegal-instruction and changes nothing, also on an Unconfigured locker '
      '(GR18)', (raises(cl.setst, 54), raises(cl.setst, 55), cl.st) == (True, True, KL_STATE_UNCONFIGURED))
cl = outputting()
check('KLLEN > t: digest, excess bits cleared, _Success_', None, (C(40)(cl)[1], cl.st),
      (DIG_ABC + bytes(8), KL_STATE_SUCCESS))
cl = absorbing((b'abcd' * 32)[:68])
dirty = cl.block_base and cl.state != IV_STATE
R(cl)
reset = (cl.state, cl.block, cl.block_base) == (IV_STATE, 0, 0)
check('_Hash_Absorb_ -> _Ready_ mid-message: state <- IV, block, block_base <- 0',
      dirty and reset and run(cl, A, B(b'abc'), O, C(32))[1] == DIG_ABC)

MP = b'abcd' * 32  # 128 bytes
cl = absorbing(data=MP[:5])
r = cl.exec('B', MP[5:69], halt=True)[0], HART.klstart, cl.block_base
r += (cl.exec('B', MP[5:69], resume=True)[0], run(cl, B(MP[69:]), O, C(32))[1])
check('a 5-byte transfer, then a 64-byte one with a halt requested at each 3.i (<<KLE-process-VLI>>): a halt at '
      'klstart = 59, where the block is full (granularity 8 bits); resumed, the digest is correct', None, r,
      ('interrupted', 59, 0, 'retired', sm3_ref(MP)))
res = []
for ks in (59, 4):
    cl = absorbing(data=MP[:5]) if ks == 59 else absorbing()
    HART.klstart = ks
    res.append((cl.exec('B', MP[5:69] if ks == 59 else MP[:64], resume=True)[0], cl.st))
check('a resumption at klstart = 59 with block_base != 0 (GR44) -> _Invalid_; at klstart = 4 with block_base = 0 '
      '-> admitted', None, res, [('invalid', KL_STATE_INVALID), ('retired', KL_STATE_HASH_ABSORB)])

section('kl.derive')
SEC = bytes(range(0x40, 0x60))  # a 32-byte shared secret
src, dst, dst2 = Source(SEC), absorbing(), absorbing()
r = (kl_derive(dst, src, 32), dst.block_base, kl_derive(dst2, src, 32))
check('shared secret (32 B) -> SM3 absorb: SM3(secret) = reference; the field does not advance: derived twice', None,
      (r, run(dst, O, C(32))[1], run(dst2, O, C(32))[1]),
      (('done', 256, 'done'), sm3_ref(SEC), sm3_ref(SEC)))
src, dst = Source(SEC[:30]), absorbing()
check('shared secret (30 B), length 30 -> SM3 absorb: exactly the secret (GR32 item 5)',
      kl_derive(dst, src, 30) == 'done' and run(dst, O, C(32))[1] == sm3_ref(SEC[:30]))
src, dst = outputting(), absorbing()
check('SM3 digest in _Hash_Output_ as a source (GR32 item 1): refused, source _Invalid_, destination untouched',
      kl_derive(dst, src, 32) == 'refused' and src.st == KL_STATE_INVALID
      and (dst.st, dst.block_base) == (KL_STATE_HASH_ABSORB, 0))
src, dst = Source(bytes(range(16)), secret=False), absorbing()
check('a CMAC (16 B) -> SM3 absorb: pair not admitted (GR32 item 3), both _Invalid_',
      kl_derive(dst, src, 16) == 'refused' and (src.st, dst.st) == (KL_STATE_INVALID, KL_STATE_INVALID))
src, dst = Source(SEC), Sm3().provision()
check('destination in _Ready_ (GR32 item 2): refused, destination _Invalid_, source untouched',
      kl_derive(dst, src, 32) == 'refused' and dst.st == KL_STATE_INVALID and src.st == KL_STATE_HASH_OUTPUT)
res = []
for s, length in ((SEC, 0), (SEC, 31), (SEC, 36), (SEC[:30], 32), (SEC[:30], 33)):
    dst = absorbing()
    res.append((kl_derive(dst, Source(s), length), dst.st))
check('shared secret into SM3 absorb: 32 B with length 0, 31 or 36, 30 B with length 32 or 33 (GR32 item 5: '
      'exactly the secret length): destination _Invalid_', None, res, [('refused', KL_STATE_INVALID)] * 5)

src, dst, h, dh = Source(SEC), KeyDest(16), outputting(), KeyDest(16)
check('shared secret -> an SM4 `key` in _Ready_, length 32: its first 16 bytes; SM3("abc") -> a key (GR32 item 1): '
      'source _Invalid_, key untouched', None,
      (kl_derive(dst, src, 32), dst.key, kl_derive(dh, h, 32), h.st, dh.st),
      ('done', SEC[:16], 'refused', KL_STATE_INVALID, KL_STATE_READY))

section('Negative controls')
control('message words without bswap', digest(b'abc', bswap_words=False) != DIG_ABC)
control('klstart written in bits', digest(b'abcd' * 32, 'interrupt', klstart_bits=True) != sm3_ref(b'abcd' * 32))

done()
