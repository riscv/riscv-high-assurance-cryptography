#!/usr/bin/env python3
"""HMAC KAT for KLEE: <<KLEE-HMAC>> (NIK and KIP) over <<KLEE-SHA-2>> and <<KLEE-SHA-3>>.
SHA-2 from scratch; for HMAC-SHA-3 the underlying H is hashlib (the HMAC layer is the model's
own). Python hmac/hashlib are otherwise only labeled reference oracles."""
import hashlib, hmac, math, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, bswap, bin_, bxor, IllegalInstruction, ERROR_STATES,
                    KL_STATE_UNCONFIGURED, KL_STATE_READY, KL_STATE_HASH_ABSORB,
                    KL_STATE_HASH_OUTPUT, KL_STATE_SUCCESS, KL_STATE_FAILURE, KL_STATE_INVALID,
                    section, check, control, info, spec_note, raises, done)

# ---------------------------------------------------------------- FIPS 180-4

def icbrt(n):
    x = 1 << -(-n.bit_length() // 3)
    while (y := (2 * x + n // (x * x)) // 3) < x:
        x = y
    return x

P80 = [p for p in range(2, 410) if all(p % d for d in range(2, p))]
frac = lambda x, w: x & ((1 << w) - 1)
K = {32: [frac(icbrt(p << 96), 32) for p in P80[:64]], 64: [frac(icbrt(p << 192), 64) for p in P80]}
IV = {'SHA-224': [frac(math.isqrt(p << 128), 32) for p in P80[8:16]],
      'SHA-256': [frac(math.isqrt(p << 64), 32) for p in P80[:8]],
      'SHA-384': [frac(math.isqrt(p << 128), 64) for p in P80[8:16]],
      'SHA-512': [frac(math.isqrt(p << 128), 64) for p in P80[:8]]}

def compress(H, W, w):
    """FIPS 180-4 sect. 6.2.2 / 6.4.2."""
    s0, s1, S0, S1 = (((7, 18, 3), (17, 19, 10), (2, 13, 22), (6, 11, 25)) if w == 32 else
                      ((1, 8, 7), (19, 61, 6), (28, 34, 39), (14, 18, 41)))
    M = (1 << w) - 1
    rotr = lambda x, r: ((x >> r) | (x << (w - r))) & M
    sig = lambda x, s: rotr(x, s[0]) ^ rotr(x, s[1]) ^ (x >> s[2])
    Sig = lambda x, s: rotr(x, s[0]) ^ rotr(x, s[1]) ^ rotr(x, s[2])
    W = list(W)
    for t in range(16, len(K[w])):
        W.append((W[t - 16] + sig(W[t - 15], s0) + W[t - 7] + sig(W[t - 2], s1)) & M)
    a, b, c, d, e, f, g, h = H
    for t in range(len(K[w])):
        T1 = (h + Sig(e, S1) + ((e & f) ^ (~e & g & M)) + K[w][t] + W[t]) & M
        T2 = (Sig(a, S0) + ((a & b) ^ (a & c) ^ (b & c))) & M
        a, b, c, d, e, f, g, h = (T1 + T2) & M, a, b, c, (d + T1) & M, e, f, g
    return [(x + y) & M for x, y in zip(H, (a, b, c, d, e, f, g, h))]

def fips_pad(nbits, w):
    """FIPS 180-4 sect. 5.1 padding of an nbits-bit (whole-byte) message."""
    return b'\x80' + bytes(-(nbits // 8 + 1 + w // 4) % (2 * w)) + nbits.to_bytes(w // 4, 'big')

def sha2_be(msg, H, w, d):
    """Byte-level SHA-2 (provisioner, reference and IV generation; never the KLEE model)."""
    m = msg + fips_pad(8 * len(msg), w)
    for i in range(0, len(m), 2 * w):
        H = compress(H, [int.from_bytes(m[j:j + w // 8], 'big') for j in range(i, i + 2 * w, w // 8)], w)
    return b''.join(x.to_bytes(w // 8, 'big') for x in H)[:d // 8]

for t in (224, 256):  # sect. 5.3.6
    H = sha2_be(f'SHA-512/{t}'.encode(), [h ^ 0xa5a5a5a5a5a5a5a5 for h in IV['SHA-512']], 64, 512)
    IV[f'SHA-512/{t}'] = [int.from_bytes(H[j:j + 8], 'big') for j in range(0, 64, 8)]
assert K[32][63] == 0xc67178f2 and K[64][79] == 0x6c44198c4a475817 and IV['SHA-224'][0] == 0xc1059ed8
assert IV['SHA-512/224'][0] == 0x8c3d37c819544da2 and IV['SHA-512/256'][7] == 0x0eb72ddc81c52ca2

# name: (NIK Type, Mode, w or None, b, d); <<KLEE-exec-encodings>>, <<KLEE-SHA-2-parameters>>,
# <<KLEE-SHA-3-parameters>> (b = the rate)
HASHES = {'SHA-224': (4, 6, 32, 512, 224), 'SHA-256': (4, 7, 32, 512, 256),
          'SHA-384': (4, 8, 64, 1024, 384), 'SHA-512': (4, 9, 64, 1024, 512),
          'SHA-512/224': (4, 10, 64, 1024, 224), 'SHA-512/256': (4, 11, 64, 1024, 256),
          'SHA3-224': (6, 6, None, 1152, 224), 'SHA3-256': (6, 7, None, 1088, 256),
          'SHA3-384': (6, 8, None, 832, 384), 'SHA3-512': (6, 9, None, 576, 512)}
HL = {n: n.lower().replace('-', '_').replace('/', '_').replace('sha_', 'sha') for n in HASHES}
KL_STATE_SET_KEY = 15  # <<KLEE-HMAC>> gives _Set_Key_ no value

# ---------------------------------------------------------------- KLEE model

class Hart:
    klstart = 0  # bytes, <<KLEE-CSR-klstart>>

HART = Hart()

def setsl(v, hi, lo, x):
    m = ((1 << (hi - lo + 1)) - 1) << lo
    return (v & ~m) | ((x << lo) & m)

def pack(*fields):
    """Serialized fields in table order from bit 0, zero-padded to 128 bits."""
    v = pos = 0
    for x, w in fields:
        v, pos = v | bin_(x, w) << pos, pos + w
    return v2b(v, -(-pos // 128) * 16)

def process_vli(max_len, dst, attr, b, h, proc, INPUT, KLLEN, halt=False, resume=False):
    """process_VLI(max_len, block=dst.attr, b, ..., h.block_base, 0, h.cumul_len, proc, None, assign)."""
    if max_len and h.cumul_len >= max_len:
        return 'invalid'
    ib = 8 * HART.klstart if resume else 0
    while ib < KLLEN:
        amount = min(KLLEN - ib, b - h.block_base, *([max_len - h.cumul_len] if max_len else []))
        setattr(dst, attr, setsl(getattr(dst, attr), h.block_base + amount - 1, h.block_base,
                                 sl(INPUT, ib + amount - 1, ib)))
        ib, h.block_base = ib + amount, h.block_base + amount
        if max_len:
            h.cumul_len += amount
        if h.block_base == b:
            if proc:
                proc()
            h.block_base = 0
        if max_len and h.cumul_len == max_len:
            HART.klstart = 0
            return 'terminated'
        if halt and ib < KLLEN:  # 4.i
            HART.klstart = ib // 8
            return 'interrupted'
    HART.klstart = 0
    return 'retired'

class Core:
    """The underlying H: `state`, `block`, `block_base`, `cumul_len`."""
    def __init__(h, name):
        h.name, (_, _, h.w, h.b, h.d) = name, HASHES[name]
        h.n = 8 * h.w if h.w else 1600
        h.ready()

    def ready(h):
        h.reinit()
        h.block = h.block_base = h.cumul_len = 0

    def reinit(h):  # state <- initial value of H
        h.buf = b''
        h.state = sum(bswap(bin_(x, h.w), h.w // 8) << (i * h.w) for i, x in enumerate(IV[h.name])) if h.w else 0

    def process_block(h):
        if not h.w:  # SHA-3: blocks collected for hashlib
            h.buf += v2b(h.block, h.b // 8)
            return
        wd = lambda v, j: bswap(sl(v, (j + 1) * h.w - 1, j * h.w), h.w // 8)
        H = compress([wd(h.state, i) for i in range(8)], [wd(h.block, j) for j in range(16)], h.w)
        h.state = sum(bswap(x, h.w // 8) << (i * h.w) for i, x in enumerate(H))

    def absorb(h, data):  # absorb() as per H, not counted in cumul_len
        process_vli(0, h, 'block', h.b, h, h.process_block, b2v(data), 8 * len(data))

    def finalize(h, total_bits):
        if h.w:  # SHA-2 under HMAC: FIPS 180-4 sect. 5.1 over total_bits
            h.absorb(fips_pad(total_bits, h.w))
        else:    # SHA-3 suffix-and-padding, inside hashlib
            tail = v2b(h.block & ((1 << h.block_base) - 1), h.block_base // 8)
            h.state = b2v(hashlib.new(HL[h.name], h.buf + tail).digest())
            h.buf, h.block, h.block_base = b'', 0, 0

class Hmac:
    def __init__(s, name, swap_pads=False, keep_cumul=False):
        s.name, s.h = name, Core(name)
        s.b, s.d = s.h.b, s.h.d
        s.ipad, s.opad = (b'\x5c', b'\x36') if swap_pads else (b'\x36', b'\x5c')
        s.keep_cumul = keep_cumul
        s.max_len = (1 << 64) - 1 - s.b if s.h.w else 0  # SHA-2: system-defined, so cumul_len is kept
        s.reset(KL_STATE_UNCONFIGURED)

    def reset(s, st=KL_STATE_INVALID):  # SGR10 for an Error State
        s.st, s.K0 = st, 0
        s.h.ready()
        s.h.state = 0

    def provision(s, variant, K0=None, key_type=0):
        typ, mode = HASHES[s.name][:2]
        s.variant, s.machine = variant, ((typ + (variant == 'KIP')) << 4) | mode
        if variant == 'NIK' and key_type:
            s.reset()  # invalid Metadata, <<KLEE-MVR-open>>
            return s
        s.h.ready()
        s.st, s.K0 = KL_STATE_READY, b2v(K0) if variant == 'KIP' else 0
        return s

    def export(s):
        h = s.h
        return pack((h.state, h.n), (0, 16), (h.block_base, 16), (0, 16), (0, 16), (h.cumul_len, 64),
                    (h.block, h.b)) + pack((s.K0, s.b))

    @classmethod
    def load(cls, name, variant, st, c1):
        s = cls(name)
        h, s.variant, s.st = s.h, variant, st
        hl = len(pack((0, h.n + 128 + h.b)))
        v = b2v(c1[:hl])
        h.state, h.block_base = sl(v, h.n - 1, 0), sl(v, h.n + 31, h.n + 16)
        h.cumul_len, h.block, s.K0 = sl(v, h.n + 127, h.n + 64), v >> (h.n + 128), b2v(c1[hl:])
        return s

    def pad(s, p):
        return bxor(v2b(s.K0, s.b // 8), p * (s.b // 8))

    def setst(s, immed, form='A'):
        h = s.h
        allowed = {(KL_STATE_READY, KL_STATE_SET_KEY): s.variant == 'NIK',
                   (KL_STATE_READY, KL_STATE_HASH_ABSORB): s.variant == 'KIP',
                   (KL_STATE_SET_KEY, KL_STATE_HASH_ABSORB): h.cumul_len == s.b,  # K0 loaded
                   (KL_STATE_HASH_ABSORB, KL_STATE_HASH_OUTPUT): True}
        if immed in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            raise IllegalInstruction  # SGR7
        if immed == KL_STATE_UNCONFIGURED or immed in ERROR_STATES:  # in any State
            if s.st != KL_STATE_UNCONFIGURED:
                s.reset(KL_STATE_INVALID if immed > 53 else immed)
        elif s.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction  # SGR12
        elif s.st in ERROR_STATES:
            pass
        elif immed == KL_STATE_READY:  # K0 kept
            h.ready()
            s.st = KL_STATE_READY
        elif form != 'A' or not allowed.get((s.st, immed)):  # Form A: max_len set by the Machine
            s.reset()
        elif immed == KL_STATE_SET_KEY:
            s.st, s.K0, h.block_base, h.cumul_len = immed, 0, 0, 0
        elif immed == KL_STATE_HASH_ABSORB:
            h.reinit()
            h.block = h.block_base = 0
            h.cumul_len = h.cumul_len if s.keep_cumul else 0
            h.absorb(s.pad(s.ipad))
            s.st = immed
        else:
            h.finalize(s.b + h.cumul_len)
            inner = v2b(sl(h.state, s.d - 1, 0), s.d // 8)
            h.reinit()
            h.absorb(s.pad(s.opad))
            h.absorb(inner)
            h.finalize(s.b + s.d)
            s.st, h.block_base = immed, 0

    def exec(s, form, data=b'', nbytes=0, halt=False, resume=False, prior=None):
        """kl.exec Form B (data) or C (nbytes); returns (status, output)."""
        if s.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction
        if s.st in ERROR_STATES:
            return 'noop', bytes(nbytes)  # SGR16
        h, io = s.h, (b2v(data), 8 * len(data), halt, resume)
        if form == 'B' and s.st == KL_STATE_SET_KEY:
            r = process_vli(s.b, s, 'K0', s.b, h, None, *io)
        elif form == 'B' and s.st == KL_STATE_HASH_ABSORB:
            r = process_vli(s.max_len, h, 'block', h.b, h, h.process_block, *io)
        elif form == 'C' and s.st == KL_STATE_HASH_OUTPUT:
            return 'retired', s.output(nbytes, prior)
        else:
            r = 'invalid'  # SGR2, SGR5, MGR1
        if r == 'invalid':
            s.reset()
        return r, bytes(nbytes)

    def output(s, nbytes, prior):  # _Hash_Output_ loop of H, reading `state`
        h, OUT, KLLEN, ob = s.h, b2v(prior or bytes(nbytes)), 8 * nbytes, 0
        while ob < KLLEN:
            amount = min(KLLEN - ob, s.d - h.block_base)
            OUT = setsl(OUT, ob + amount - 1, ob, sl(h.state, h.block_base + amount - 1, h.block_base))
            ob, h.block_base = ob + amount, h.block_base + amount
            if h.block_base == s.d:
                OUT, s.st = sl(OUT, ob - 1, 0), KL_STATE_SUCCESS
                break
        HART.klstart = 0
        return v2b(OUT, nbytes)

def kl_derive(dst, src, length):
    """_Hash_Output_ kl.exec output -> _Hash_Absorb_ kl.exec input (<<KLEE-derive-endpoints>>, DER6)."""
    if src.st in ERROR_STATES or dst.st in ERROR_STATES:
        return 'noop'  # SGR19
    bad = [c for c, ok in ((src, src.st == KL_STATE_HASH_OUTPUT), (dst, dst.st == KL_STATE_HASH_ABSORB)) if not ok]
    for c in bad:
        c.reset()  # DER1 item 1
    if bad or not length:
        return 'refused' if bad else 'noop'
    dst.exec('B', src.exec('C', nbytes=length)[1])
    return 'done'

# ---------------------------------------------------------------- provisioner, references, drivers

def ref_hash(name, msg):
    _, _, w, _, d = HASHES[name]
    return sha2_be(msg, IV[name], w, d) if w else hashlib.new(HL[name], msg).digest()

def K0_of(name, key):
    """FIPS 198-1 sect. 3, done by the provisioner."""
    b8 = HASHES[name][3] // 8
    key = ref_hash(name, key) if len(key) > b8 else key
    return key + bytes(b8 - len(key))

def ref_hmac(name, key, msg):
    K0 = K0_of(name, key)
    ip, op = (bxor(K0, p * len(K0)) for p in (b'\x36', b'\x5c'))
    return ref_hash(name, op + ref_hash(name, ip + msg))

S = lambda st, form='A': lambda c: c.setst(st, form)
A, O, SK, R = S(KL_STATE_HASH_ABSORB), S(KL_STATE_HASH_OUTPUT), S(KL_STATE_SET_KEY), S(KL_STATE_READY)
B = lambda d: lambda c: c.exec('B', d)
C = lambda n: lambda c: c.exec('C', nbytes=n, prior=b'\xa5' * n)

def run(c, *ops):
    """Apply ops to locker c; return the last result."""
    return [op(c) for op in ops][-1]

def load_key(cl, K0, parts=3):
    q = len(K0) // parts
    run(cl, SK, *[B(K0[i * q: len(K0) if i == parts - 1 else (i + 1) * q]) for i in range(parts)])

def fresh(name='SHA-256', variant='KIP', key=b'key', **kw):
    """Provisioned locker; a NIK one with a key is left in _Set_Key_ with K0 loaded."""
    cl = Hmac(name, **kw).provision(variant, K0_of(name, key) if variant == 'KIP' else None)
    if variant == 'NIK' and key is not None:
        load_key(cl, K0_of(name, key))
    return cl

def tag_of(name, key, msg, variant='KIP', **kw):
    """Message in two transfers, each halted at every point 4.i and resumed; tag in two reads."""
    cl = fresh(name, variant, key, **kw)
    A(cl)
    c = len(msg) // 3
    for piece in (msg[:c], msg[c:]):
        r = cl.exec('B', piece, halt=True)[0] if piece else None
        while r == 'interrupted':
            r = cl.exec('B', piece, halt=True, resume=True)[0]
    tag = run(cl, O, C(cl.d // 8 - 4))[1] + C(4)(cl)[1]
    return tag if cl.st == KL_STATE_SUCCESS else None

# ---------------------------------------------------------------- RFC 4231

RFC4231 = {  # case: (key, data); case 5 (truncation) out of scope
    1: (bytes.fromhex('0b' * 20), b'Hi There'),
    2: (b'Jefe', b'what do ya want for nothing?'),
    3: (bytes.fromhex('aa' * 20), bytes.fromhex('dd' * 50)),
    4: (bytes(range(1, 26)), bytes.fromhex('cd' * 50)),
    6: (bytes.fromhex('aa' * 131),
        b'Test Using Larger Than Block-Size Key - Hash Key First'),
    7: (bytes.fromhex('aa' * 131),
        b'This is a test using a larger than block-size key and a larger '
        b'than block-size data. The key needs to be hashed before being '
        b'used by the HMAC algorithm.'),
}
TAGS = {  # RFC 4231 sect. 4
    ('SHA-224', 1): '896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22',
    ('SHA-256', 1): 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    ('SHA-384', 1): 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c'
                    'faea9ea9076ede7f4af152e8b2fa9cb6',
    ('SHA-512', 1): '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde'
                    'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    ('SHA-224', 2): 'a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44',
    ('SHA-256', 2): '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    ('SHA-384', 2): 'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e'
                    '8e2240ca5e69e2c78b3239ecfab21649',
    ('SHA-512', 2): '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554'
                    '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    ('SHA-224', 3): '7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea',
    ('SHA-256', 3): '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    ('SHA-384', 3): '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b'
                    '2a5ab39dc13814b94e3ab6e101a34f27',
    ('SHA-512', 3): 'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39'
                    'bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
    ('SHA-224', 4): '6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a',
    ('SHA-256', 4): '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    ('SHA-384', 4): '3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e'
                    '6801dd23c4a7d679ccf8a386c674cffb',
    ('SHA-512', 4): 'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db'
                    'a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
    ('SHA-224', 6): '95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e',
    ('SHA-256', 6): '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    ('SHA-384', 6): '4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6'
                    '0c2ef6ab4030fe8296248df163f44952',
    ('SHA-512', 6): '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352'
                    '6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
    ('SHA-224', 7): '3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1',
    ('SHA-256', 7): '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    ('SHA-384', 7): '6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5'
                    'a678cc31e799176d3860e6110c46523e',
    ('SHA-512', 7): 'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944'
                    'b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
}

# ---------------------------------------------------------------- checks

section('RFC 4231 (SHA-224/256/384/512); FIPS 198-1 reference (SHA-512/t, SHA3-*)')
for name in HASHES:
    for case, (key, data) in RFC4231.items():
        rfc = (name, case) in TAGS
        want = bytes.fromhex(TAGS[name, case]) if rfc else ref_hmac(name, key, data)
        for variant in ('KIP', 'NIK'):
            check(f'HMAC-{name} case {case} {variant}{"" if rfc else " = reference"}', None,
                  tag_of(name, key, data, variant), want)
        if HL[name] in hashlib.algorithms_available:
            check(f'[oracle] hmac HMAC-{name} case {case}', None, hmac.new(key, data, HL[name]).digest(), want)

section('State machine')
key7, data7 = RFC4231[7]
TAG7, K0_7 = bytes.fromhex(TAGS['SHA-256', 7]), K0_of('SHA-256', key7)
check('NIK Mode with _KeyType_ = 1: invalid Metadata, _Invalid_ (<<KLEE-MVR-open>>)',
      Hmac('SHA-256').provision('NIK', key_type=1).st == KL_STATE_INVALID)
check('_Machine_: KIP HMAC-SHA-256 = Type 5 Mode 7, NIK = Type 4 Mode 7', None,
      (fresh().machine, fresh(variant='NIK', key=None).machine), ((5 << 4) | 7, (4 << 4) | 7))
for label, variant, ops in [
        ('KIP kl.setst to _Set_Key_ (cannot be re-keyed)', 'KIP', (SK,)),
        ('NIK _Ready_ -> _Hash_Absorb_', 'NIK', (A,)),
        ('NIK _Set_Key_ -> _Hash_Absorb_ with half of K0', 'NIK', (SK, B(K0_7[:32]), A)),
        ('NIK same-State kl.setst to _Set_Key_', 'NIK', (SK, SK)),
        ('NIK Form B kl.setst to _Set_Key_', 'NIK', (S(KL_STATE_SET_KEY, 'B'),)),
        ('NIK kl.exec after K0 is complete (MGR7)', 'NIK', (SK, B(K0_7), B(bytes(4)))),
        ('kl.exec in _Ready_ (SGR2)', 'KIP', (B(data7),)),
        ('Form C kl.exec in _Hash_Absorb_ (MGR1), output zeroed', 'KIP', (A, C(16))),
        ('same-State kl.setst to _Hash_Absorb_', 'KIP', (A, A)),
        ('kl.exec in _Success_ (SGR5), output zeroed', 'KIP', (A, B(data7), O, C(32), C(32)))]:
    cl = fresh(variant=variant, key=key7 if variant == 'KIP' else None)
    r = run(cl, *ops)
    check(f'_Invalid_: {label}', cl.st == KL_STATE_INVALID and not any(r[1] if r else b''))
check('kl.exec in _Invalid_: no operation, output zeroed (SGR16)',
      C(32)(cl) == ('noop', bytes(32)) and cl.st == KL_STATE_INVALID)
cl = fresh(key=key7)
A(cl)
check('kl.setst #kl_state_success raises, State kept (SGR7)',
      raises(cl.setst, KL_STATE_SUCCESS) and cl.st == KL_STATE_HASH_ABSORB)
cl = fresh(variant='NIK', key=None)
r = run(cl, SK, B(K0_7 + b'\xde\xad\xbe\xef' * 4))[0]
term = r == 'terminated' and cl.h.cumul_len == 512 and cl.K0 == b2v(K0_7)
check('NIK K0 + 16 excess bytes: load ends at cumul_len = b, excess ignored (step 4.h)',
      term and run(cl, A, B(data7), O, C(32))[1] == TAG7)
cl = fresh(variant='NIK', key=b'first key')
run(cl, A, B(b'ignored'), R)
load_key(cl, K0_7, parts=5)
check('NIK _Ready_ -> _Set_Key_ replaces K0 (entry zeroes it)', None, run(cl, A, B(data7), O, C(32))[1], TAG7)
cl = fresh(key=key7)
check('KLLEN > d: tag, excess bits cleared, _Success_', None,
      (run(cl, A, B(data7), O, C(40))[1], cl.st), (TAG7 + bytes(8), KL_STATE_SUCCESS))
check('KIP _Success_ -> _Ready_ keeps K0: second tag (SGR6)', None, run(cl, R, A, B(data7), O, C(32))[1], TAG7)

section('Serialized Content (SHA-2)')
for name in list(HASHES)[:6]:
    check(f'HMAC-{name} Content1 = H (n+128+b, padded) then K0 (b, padded)', None, len(fresh(name).export()),
          176 if HASHES[name][2] == 32 else 336)
for label, variant, before, after in [
        ('NIK in _Set_Key_, 40 of 64 K0 bytes', 'NIK', (SK, B(K0_7[:40])), (B(K0_7[40:]), A, B(data7), O)),
        ('KIP in _Hash_Absorb_, block_base 288', 'KIP', (A, B(data7[:100])), (B(data7[100:]), O)),
        ('KIP in _Hash_Output_ after 12 bytes', 'KIP', (A, B(data7[:100]), B(data7[100:]), O, C(12)), ())]:
    cl = fresh(variant=variant, key=key7 if variant == 'KIP' else None)
    r = run(cl, *before)
    head = r[1] if variant == 'KIP' and not after else b''
    cl = Hmac.load('SHA-256', variant, cl.st, cl.export())
    tag = head + run(cl, *after, C(32 - len(head)))[1]
    check(f'export/import round trip, {label}', tag == TAG7 and cl.st == KL_STATE_SUCCESS)

section('kl.derive')
k2, m2 = RFC4231[2]
src, dst = fresh(key=k2), fresh('SHA-512', 'NIK', key7)
run(src, A, B(m2), O)
run(dst, A, B(b'prefix'))
r = kl_derive(dst, src, 32)
check('HMAC-SHA-256 tag -> NIK HMAC-SHA-512 absorb, between "prefix" and "suffix"; source _Success_',
      r == 'done' and src.st == KL_STATE_SUCCESS and run(dst, B(b'suffix'), O, C(64))[1]
      == ref_hmac('SHA-512', key7, b'prefix' + bytes.fromhex(TAGS['SHA-256', 2]) + b'suffix'))
src, dst = fresh(key=k2), fresh(variant='NIK', key=None)
run(src, A, B(m2), O)
SK(dst)
check('destination in _Set_Key_ (K0 is a destination only in _Ready_): refused, destination _Invalid_',
      kl_derive(dst, src, 32) == 'refused' and dst.st == KL_STATE_INVALID
      and (src.st, src.h.block_base) == (KL_STATE_HASH_OUTPUT, 0))

section('Negative controls')
key1, data1 = RFC4231[1]
TAG1 = bytes.fromhex(TAGS['SHA-256', 1])
control('ipad and opad swapped', tag_of('SHA-256', key1, data1, swap_pads=True) != TAG1)
control('NIK: cumul_len not zeroed on entering _Hash_Absorb_',
        tag_of('SHA-256', key1, data1, 'NIK', keep_cumul=True) != TAG1)

spec_note('<<KLEE-HMAC>> gives _Set_Key_ no State value (none in <<KLEE-state-constants-symmetric>>); '
          'the harness uses 15')
spec_note('SHA-2 padding under HMAC uses cumul_len, which process_VLI advances only if max_len != 0 '
          '(step 4.f); harness max_len = 2^64-1-b')
spec_note('<<KLEE-derive-endpoints>> makes NIK K0 a destination in _Ready_, but _Ready_ -> _Set_Key_, the '
          'only way to _Hash_Absorb_, zeroes K0: a derived K0 is never used')
spec_note('HMAC-SHA-3: _Set_Key_ relies on cumul_len, absent from the <<KLEE-SHA-3>> Serialized Content; '
          'a completed K0 load does not survive export/import')
info('b of HMAC-SHA-3 read as the rate of <<KLEE-SHA-3-parameters>>; KIP K0 as SKID (_KeyType_ = 1) '
     'not exercised')
done()
