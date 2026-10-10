#!/usr/bin/env python3
"""HMAC KAT for KLEE: <<KLEE-HMAC>> (NIK and KIP) over <<KLEE-SHA-2>>, <<KLEE-SM3>> and <<KLEE-SHA-3>>.
SHA-2, SM3 and Keccak-f from scratch; hashlib SHA-3 is the reference H of the HMAC-SHA-3 tags.
Python hmac/hashlib are otherwise only labeled reference oracles."""
import hashlib, hmac, math, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, bswap, bin_, bxor, IllegalInstruction, ERROR_STATES, KL_STATE_UNCONFIGURED,
                    KL_STATE_READY, KL_STATE_HASH_ABSORB, KL_STATE_HASH_OUTPUT, KL_STATE_SET_KEY, KL_STATE_SUCCESS,
                    KL_STATE_FAILURE, KL_STATE_INVALID, section, check, control, info, raises, done)

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

M32 = 0xffffffff
rotl = lambda x, r: ((x << (r % 32)) | (x >> (32 - r % 32))) & M32
P0, P1 = (lambda x: x ^ rotl(x, 9) ^ rotl(x, 17)), (lambda x: x ^ rotl(x, 15) ^ rotl(x, 23))

def sm3_compress(V, W, w=32):
    """GB/T 32905-2016 CF, sect. 5.3.3."""
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

CF = {'SM3': sm3_compress}  # else compress
IV['SM3'] = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]

def fips_pad(nbits, w):
    """FIPS 180-4 sect. 5.1 padding of an nbits-bit (whole-byte) message."""
    return b'\x80' + bytes(-(nbits // 8 + 1 + w // 4) % (2 * w)) + nbits.to_bytes(w // 4, 'big')

def sha2_be(msg, H, w, d, cf=compress):
    """Byte-level SHA-2 or SM3 (provisioner, reference and IV generation; never the KLEE model)."""
    m = msg + fips_pad(8 * len(msg), w)
    for i in range(0, len(m), 2 * w):
        H = cf(H, [int.from_bytes(m[j:j + w // 8], 'big') for j in range(i, i + 2 * w, w // 8)], w)
    return b''.join(x.to_bytes(w // 8, 'big') for x in H)[:d // 8]

for t in (224, 256):  # sect. 5.3.6
    H = sha2_be(f'SHA-512/{t}'.encode(), [h ^ 0xa5a5a5a5a5a5a5a5 for h in IV['SHA-512']], 64, 512)
    IV[f'SHA-512/{t}'] = [int.from_bytes(H[j:j + 8], 'big') for j in range(0, 64, 8)]
assert K[32][63] == 0xc67178f2 and K[64][79] == 0x6c44198c4a475817 and IV['SHA-224'][0] == 0xc1059ed8
assert IV['SHA-512/224'][0] == 0x8c3d37c819544da2 and IV['SHA-512/256'][7] == 0x0eb72ddc81c52ca2
assert sha2_be(b'abc', IV['SM3'], 32, 256, sm3_compress).hex().startswith('66c7f0f462eeedd9')  # GB/T 32905 A.1

# ---------------------------------------------------------------- FIPS 202

RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
RHO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1
rol = lambda v, s: ((v << s) | (v >> (64 - s))) & M64 if s else v

def keccak(v):
    """KECCAK-p[1600, 24]; lane (x, y) is v[64(5y+x)+63 : 64(5y+x)] (FIPS 202 sect. 3.1)."""
    A = [(v >> (64 * i)) & M64 for i in range(25)]
    for rc in RC:
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        A = [A[i] ^ C[(i - 1) % 5] ^ rol(C[(i + 1) % 5], 1) for i in range(25)]
        T = [0] * 25
        for x in range(5):
            for y in range(5):
                T[y + 5 * ((2 * x + 3 * y) % 5)] = rol(A[x + 5 * y], RHO[x][y])
        A = [T[i] ^ (~T[i - i % 5 + (i + 1) % 5] & T[i - i % 5 + (i + 2) % 5]) for i in range(25)]
        A[0] ^= rc
    return sum(a << (64 * i) for i, a in enumerate(A))

# name: (NIK Type, NIK Mode, w or None, b, d); <<KLEE-exec-encodings>>, <<KLEE-SHA-2-parameters>>,
# <<KLEE-SM3>>, <<KLEE-SHA-3-parameters>> (b = the rate)
HASHES = {'SHA-224': (4, 6, 32, 512, 224), 'SHA-256': (4, 7, 32, 512, 256),
          'SHA-384': (4, 8, 64, 1024, 384), 'SHA-512': (4, 9, 64, 1024, 512),
          'SHA-512/224': (4, 10, 64, 1024, 224), 'SHA-512/256': (4, 11, 64, 1024, 256),
          'SM3': (9, 1, 32, 512, 256),
          'SHA3-224': (6, 6, None, 1152, 224), 'SHA3-256': (6, 7, None, 1088, 256),
          'SHA3-384': (6, 8, None, 832, 384), 'SHA3-512': (6, 9, None, 576, 512)}
HL = {n: n.lower().replace('-', '_').replace('/', '_').replace('sha_', 'sha') for n in HASHES}

# ---------------------------------------------------------------- KLEE model

class HART:
    klstart = 0  # bytes, <<KLEE-CSR-klstart>>

def setsl(v, hi, lo, x):
    m = ((1 << (hi - lo + 1)) - 1) << lo
    return (v & ~m) | ((x << lo) & m)

def pack(*fields):
    """Serialized fields in table order from bit 0, zero-padded to 128 bits."""
    v = pos = 0
    for x, w in fields:
        v, pos = v | bin_(x, w) << pos, pos + w
    return v2b(v, -(-pos // 128) * 16)

def process_vli(max_len, dst, attr, b, h, proc, INPUT, KLLEN, halt=False, resume=False, track=True, xor=False):
    """process_VLI(max_len, block=dst.attr, b, ..., h.block_base, 0, h.cumul_len, proc, None, assign/xor_accumulate)."""
    if max_len and h.cumul_len >= max_len:
        return 'invalid'
    ib = 8 * HART.klstart if resume else 0
    while ib < KLLEN:
        amount = min(KLLEN - ib, b - h.block_base, *([max_len - h.cumul_len] if max_len else []))
        x, v = sl(INPUT, ib + amount - 1, ib), getattr(dst, attr)
        setattr(dst, attr, v ^ (x << h.block_base) if xor else setsl(v, h.block_base + amount - 1, h.block_base, x))
        ib, h.block_base = ib + amount, h.block_base + amount
        if track:                                    # 4.f: cumul_len is not None
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
    """The underlying H: `state`, `block` (not SHA-3), `block_base`, `cumul_len`."""
    def __init__(h, name):
        h.name, (_, _, h.w, h.b, h.d) = name, HASHES[name]
        h.attr, h.xor = ('block', False) if h.w else ('state', True)  # SHA-3: xor_accumulate into state
        h.fields = ((('state', 8 * h.w), (None, 16), ('block_base', 16), (None, 16), (None, 16), ('cumul_len', 64),
                     ('block', h.b)) if h.w else  # Serialized Content under HMAC
                    (('state', 1600), ('block_base', 16), ('cumul_len', 64)))
        h.ready()

    def ready(h):
        h.reinit()
        h.block = h.block_base = h.cumul_len = 0

    def reinit(h):  # state <- initial value of H
        h.state = sum(bswap(bin_(x, h.w), h.w // 8) << (i * h.w) for i, x in enumerate(IV[h.name])) if h.w else 0

    def process_block(h):
        if not h.w:
            h.state = keccak(h.state)
            return
        wd = lambda v, j: bswap(sl(v, (j + 1) * h.w - 1, j * h.w), h.w // 8)
        H = CF.get(h.name, compress)([wd(h.state, i) for i in range(8)], [wd(h.block, j) for j in range(16)], h.w)
        h.state = sum(bswap(x, h.w // 8) << (i * h.w) for i, x in enumerate(H))

    def absorb(h, data):  # absorb() as per H, not counted in cumul_len
        process_vli(0, h, h.attr, h.b, h, h.process_block, b2v(data), 8 * len(data), track=False, xor=h.xor)

    def finalize(h, total_bits):
        if h.w:  # SHA-2/SM3 under HMAC: FIPS 180-4 sect. 5.1 over total_bits
            h.absorb(fips_pad(total_bits, h.w))
        else:    # SHA-3: D = 01, pad10*1, one block (block_base is whole bytes)
            h.state = keccak(h.state ^ (0b110 | 1 << (h.b - h.block_base - 1)) << h.block_base)
            h.block_base = 0

class Hmac:
    def __init__(s, name, swap_pads=False, keep_cumul=False):
        s.name, s.h = name, Core(name)
        s.b, s.d = s.h.b, s.h.d
        s.ipad, s.opad = (b'\x5c', b'\x36') if swap_pads else (b'\x36', b'\x5c')
        s.keep_cumul, s.max_len = keep_cumul, 0  # max_len: none enforced
        s.reset(KL_STATE_UNCONFIGURED)

    def reset(s, st=KL_STATE_INVALID):  # GR27 for an Error State
        s.st, s.K0, s.has_key = st, 0, False
        s.h.ready()
        s.h.state = 0

    def provision(s, variant, K0=None, key_type=0):
        typ, mode = HASHES[s.name][:2]
        kip = variant == 'KIP'  # KIP: the higher Type, or for SM3_HMAC Mode 2 (<<KLEE-exec-encodings>>)
        s.variant, s.machine = variant, (typ << 4 | mode + kip) if typ == 9 else ((typ + kip) << 4 | mode)
        if variant == 'NIK' and key_type:
            s.reset()  # invalid Metadata, <<KLEE-MVR-open>>
            return s
        s.h.ready()
        s.st, s.K0, s.has_key = KL_STATE_READY, b2v(K0) if variant == 'KIP' else 0, False
        return s

    @property
    def se(s):  # _StateExtension_: bit 0 HasKey (NIK)
        return int(s.has_key)

    def export(s):
        return pack(*[(getattr(s.h, f) if f else 0, w) for f, w in s.h.fields]) + pack((s.K0, s.b))

    @classmethod
    def load(cls, name, variant, st, c1, se=0):
        s = cls(name)
        h, s.variant, s.st, pos = s.h, variant, st, 0
        s.has_key = variant == 'NIK' and bool(se & 1)
        hl = len(pack((0, sum(w for _, w in h.fields))))
        for f, w in h.fields:
            if f:
                setattr(h, f, sl(b2v(c1[:hl]), pos + w - 1, pos))
            pos += w
        s.K0 = b2v(c1[hl:])
        return s

    def pad(s, p):
        return bxor(v2b(s.K0, s.b // 8), p * (s.b // 8))

    def setst(s, immed, form='A'):
        h = s.h
        allowed = {(KL_STATE_READY, KL_STATE_SET_KEY): s.variant == 'NIK',
                   (KL_STATE_READY, KL_STATE_HASH_ABSORB): s.variant == 'KIP' or s.has_key,  # NIK: K0 kept
                   (KL_STATE_SET_KEY, KL_STATE_SET_KEY): True,  # GR20: restarts the load
                   (KL_STATE_SET_KEY, KL_STATE_HASH_ABSORB): s.has_key,  # MR11: K0 loaded
                   (KL_STATE_HASH_ABSORB, KL_STATE_HASH_OUTPUT): True}  # none from _Hash_Output_ (MR17)
        if immed in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            raise IllegalInstruction  # GR23
        if immed == KL_STATE_UNCONFIGURED or immed in ERROR_STATES:  # in any State
            if s.st != KL_STATE_UNCONFIGURED:
                s.reset(KL_STATE_INVALID if immed > 53 else immed)
        elif s.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction  # GR32
        elif s.st in ERROR_STATES:
            pass
        elif immed == KL_STATE_READY:  # K0 kept, unless its load was left incomplete (MR9)
            if s.st == KL_STATE_SET_KEY and h.cumul_len < s.b:
                s.K0 = 0
            h.ready()
            s.st = KL_STATE_READY
        elif form != 'A' or not allowed.get((s.st, immed)):  # Form A: max_len set by the Machine
            s.reset()
        elif immed == KL_STATE_SET_KEY:
            s.st, s.K0, s.has_key, h.block_base, h.cumul_len = immed, 0, False, 0, 0
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
            return 'noop', bytes(nbytes)  # GR31
        h, io = s.h, (b2v(data), 8 * len(data), halt, resume)
        if form == 'B' and s.st == KL_STATE_SET_KEY:
            r = process_vli(s.b, s, 'K0', s.b, h, None, *io)
            s.has_key = h.cumul_len == s.b  # MR9: set when the load completes
        elif form == 'B' and s.st == KL_STATE_HASH_ABSORB:
            r = process_vli(s.max_len, h, h.attr, h.b, h, h.process_block, *io, xor=h.xor)
        elif form == 'C' and s.st == KL_STATE_HASH_OUTPUT:
            p, prior = HART.klstart, prior or bytes(nbytes)
            if p >= nbytes:
                HART.klstart = 0
                return 'empty', prior  # empty window: only klstart = 0 (<<KLEE-CSR-klstart>>)
            if p:  # not an interruption point: the MAC reaches _Success_ before any
                s.reset()
                HART.klstart = 0
                return 'invalid', prior[:p] + bytes(nbytes - p)  # GR31
            return 'retired', s.output(nbytes, prior)
        else:
            r = 'invalid'  # GR21, GR25, MR1
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
    """_Hash_Output_ kl.exec output -> _Hash_Absorb_ kl.exec input (<<KLEE-derive-endpoints>>, GR46)
    or NIK `K0` in _Set_Key_ (GR46 key derivation, unrestricted), loaded through process_VLI as by kl.exec (GR48)."""
    if src.st in ERROR_STATES or dst.st in ERROR_STATES:
        return 'noop'  # Gate Order Rule
    key = dst.st == KL_STATE_SET_KEY
    bad = [c for c, ok in ((src, src.st == KL_STATE_HASH_OUTPUT), (dst, key or dst.st == KL_STATE_HASH_ABSORB)) if not ok]
    for c in bad:
        c.reset()  # GR41 items 1-2
    if bad:
        return 'refused'
    if key and min(length, (src.d - src.h.block_base) // 8) < dst.b // 8:
        dst.reset()  # GR41 item 5
        return 'refused'
    if not length:
        return 'noop'
    dst.exec('B', src.exec('C', nbytes=dst.b // 8 if key else length)[1])
    return 'done'

# ---------------------------------------------------------------- provisioner, references, drivers

def ref_hash(name, msg):
    _, _, w, _, d = HASHES[name]
    return (sha2_be(msg, IV[name], w, d, CF.get(name, compress)) if w else
            hashlib.new(HL[name], msg).digest())

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

def fresh(name='SHA-256', variant='KIP', key=b'key', ops=(), **kw):
    """Provisioned locker (a NIK one with a key: in _Set_Key_, K0 loaded), then ops applied."""
    cl = Hmac(name, **kw).provision(variant, K0_of(name, key) if variant == 'KIP' else None)
    if variant == 'NIK' and key is not None:
        load_key(cl, K0_of(name, key))
    for op in ops:
        op(cl)
    return cl

def tag_of(name, key, msg, variant='KIP', **kw):
    """Message in two transfers, each halted at every point 4.i and resumed; tag in two reads."""
    cl = fresh(name, variant, key, (A,), **kw)
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
TAGS = {  # RFC 4231 sect. 4: per case, the HMAC-SHA-224, -256, -384 and -512 tags
    1: '''896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22 b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726
          e9376c2e32cff7 afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa
          9cb6 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d91
          4eeb61f1702e696c203a126854''',
    2: '''a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44 5bdcc146bf60754e6a042426089575c75a003f089d2739839d
          ec58b964ec3843 af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab2
          1649 164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1
          a34d4a6b4b636e070a38bce737''',
    3: '''7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9
          635514ced565fe 88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a3
          4f27 fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a3
          37bee8942674278859e13292fb''',
    4: '''6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a
          2e3ff46729665b 3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674
          cffb b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f197
          41120c4f2de2adebeb10a298dd''',
    6: '''95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c51405
          46040f0ee37f54 4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f4
          4952 80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f
          73f63f0aec8b915a985d786598''',
    7: '''3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1 9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a
          7f51535c3a35e2 6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46
          523e e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676
          fb6de0446065c97440fa8c6a58''',
}
TAGS = {(f'SHA-{d}', c): bytes.fromhex(t)[o // 8:(o + d) // 8] for c, t in TAGS.items()
        for d, o in ((224, 0), (256, 224), (384, 480), (512, 864))}

GMT0042 = [  # HMAC-SM3, GM/T 0042-2015 App. D.3, as in Linux crypto/testmgr.h hmac_sm3_tv_template
    (bytes(range(1, 33)), b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' * 2,
     'ca05e144ed05d1857840d1f318a4a8669e559fc8391f414485bfdf7bb408963a'),
    (bytes(range(1, 38)), b'\xcd' * 50, '220bf579ded555393f0159f66c99877822a3ecf610d1552154b41d44b94db3ae'),
    (b'\x0b' * 32, b'Hi There', 'c0ba18c68b90c88bc07de794bfc7d2c8d19ec31ed8773bc2b390c9604e0be11e'),
    (b'Jefe', b'what do ya want for nothing?', '2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882')]

# ---------------------------------------------------------------- checks

section('RFC 4231 (SHA-224/256/384/512); FIPS 198-1 reference (SHA-512/t, SM3, SHA3-*)')
for name in HASHES:
    for case, (key, data) in RFC4231.items():
        rfc = (name, case) in TAGS
        want = TAGS[name, case] if rfc else ref_hmac(name, key, data)
        for variant in ('KIP', 'NIK'):
            check(f'HMAC-{name} case {case} {variant}{"" if rfc else " = reference"}', None,
                  tag_of(name, key, data, variant), want)
        if HL[name] in hashlib.algorithms_available:
            check(f'[oracle] hmac HMAC-{name} case {case}', None, hmac.new(key, data, HL[name]).digest(), want)

section('GM/T 0042-2015 App. D.3 (HMAC-SM3)')
for i, (key, data, tag) in enumerate(GMT0042, 1):
    for variant in ('KIP', 'NIK'):
        check(f'HMAC-SM3 vector {i} {variant}', None, tag_of('SM3', key, data, variant), bytes.fromhex(tag))
    check(f'byte-level reference HMAC-SM3 vector {i}', None, ref_hmac('SM3', key, data), bytes.fromhex(tag))
    if 'sm3' in hashlib.algorithms_available:
        check(f'[oracle] hmac HMAC-SM3 vector {i}', None, hmac.new(key, data, 'sm3').digest(), bytes.fromhex(tag))

section('State machine')
key7, data7 = RFC4231[7]
TAG7, K0_7 = TAGS['SHA-256', 7], K0_of('SHA-256', key7)
check('NIK Mode with _KeyType_ = 1: invalid Metadata, _Invalid_ (<<KLEE-MVR-open>>)',
      Hmac('SHA-256').provision('NIK', key_type=1).st == KL_STATE_INVALID)
check('_Machine_ (KIP, NIK): HMAC-SHA-256 Type 5/4 Mode 7, HMAC-SHA3-512 Type 7/6 Mode 9, '
      'SM3_HMAC Type 9 Mode 2/1', None,
      [(fresh(n).machine, fresh(n, 'NIK', None).machine) for n in ('SHA-256', 'SHA3-512', 'SM3')],
      [(5 << 4 | 7, 4 << 4 | 7), (7 << 4 | 9, 6 << 4 | 9), (9 << 4 | 2, 9 << 4 | 1)])
for label, variant, ops in [
        ('KIP kl.setst to _Set_Key_ (cannot be re-keyed)', 'KIP', (SK,)),
        ('NIK _Ready_ -> _Hash_Absorb_', 'NIK', (A,)),
        ('NIK _Set_Key_ -> _Hash_Absorb_ with half of K0', 'NIK', (SK, B(K0_7[:32]), A)),
        ('NIK Form B kl.setst to _Set_Key_', 'NIK', (S(KL_STATE_SET_KEY, 'B'),)),
        ('NIK kl.exec after K0 is complete (MR9)', 'NIK', (SK, B(K0_7), B(bytes(4)))),
        ('kl.exec in _Ready_ (GR21)', 'KIP', (B(data7),)),
        ('Form C kl.exec in _Hash_Absorb_ (MR1), output zeroed', 'KIP', (A, C(16))),
        ('same-State kl.setst to _Hash_Absorb_', 'KIP', (A, A)),
        ('same-State kl.setst to _Hash_Output_ (MR17)', 'KIP', (A, B(data7), O, O)),
        ('kl.exec in _Success_ (GR25), output zeroed', 'KIP', (A, B(data7), O, C(32), C(32)))]:
    r = run(cl := fresh(variant=variant, key=key7 if variant == 'KIP' else None), *ops)
    check(f'_Invalid_: {label}', cl.st == KL_STATE_INVALID and not any(r[1] if r else b''))
check('kl.exec in _Invalid_: no operation, output zeroed (GR31)',
      C(32)(cl) == ('noop', bytes(32)) and cl.st == KL_STATE_INVALID)
cl, res = fresh(key=key7, ops=(A, B(data7), O)), []
for ks in (32, 40, 4):
    HART.klstart = ks
    res.append((C(32)(cl), cl.st, HART.klstart))
check('Form C, klstart >= KLLEN/8 (32, 40): empty window, only klstart = 0; klstart = 4 (no interruption point): '
      '_Invalid_, [4, 32) zeroed', None, res, [(('empty', b'\xa5' * 32), KL_STATE_HASH_OUTPUT, 0)] * 2
      + [(('invalid', b'\xa5' * 4 + bytes(28)), KL_STATE_INVALID, 0)])
cl = fresh(key=key7, ops=(A,))
check('kl.setst #kl_state_success raises, State kept (GR23)',
      raises(cl.setst, KL_STATE_SUCCESS) and cl.st == KL_STATE_HASH_ABSORB)
cl = fresh(variant='NIK', key=None)
r = run(cl, SK, B(K0_7 + b'\xde\xad\xbe\xef' * 4))[0]
term = r == 'terminated' and cl.h.cumul_len == 512 and cl.K0 == b2v(K0_7)
check('NIK K0 + 16 excess bytes: load ends at cumul_len = b, excess ignored (step 4.h)',
      term and run(cl, A, B(data7), O, C(32))[1] == TAG7)
cl = fresh(variant='NIK', key=b'first key', ops=(A, B(b'ignored'), R))
load_key(cl, K0_7, parts=5)
check('NIK _Ready_ -> _Set_Key_ replaces K0 (entry zeroes it)', None, run(cl, A, B(data7), O, C(32))[1], TAG7)
cl = fresh(variant='NIK', key=b'first key')
check('NIK: HasKey (_StateExtension_ bit 0) set when the K0 load completes', cl.se == 1)
t1 = run(cl, A, B(data7), O, C(32))[1]
cl.setst(KL_STATE_READY)
t2 = run(cl, A, B(data7), O, C(32))[1]
check('NIK: K0 kept across _Ready_, _Ready_ -> _Hash_Absorb_ with HasKey: the same MAC twice', None, (t1 == t2, cl.st),
      (True, KL_STATE_SUCCESS))
cl = fresh(variant='NIK', key=b'first key', ops=(SK, B(K0_7[:32]), R))
check('NIK: entering _Set_Key_ clears HasKey; a load left incomplete keeps it clear: _Ready_ -> _Hash_Absorb_ -> Invalid',
      None, (cl.se, run(cl, A) or cl.st), (0, KL_STATE_INVALID))
cl = fresh(variant='NIK', key=None, ops=(SK, B(K0_7[:32]), R))
check('NIK K0 load left incomplete for _Ready_: K0 zeroed (MR9)', None, (cl.st, cl.K0), (KL_STATE_READY, 0))
cl = fresh(variant='NIK', key=None, ops=(SK, B(b'\x5a' * 40)))
run(cl, SK)
check('NIK same-State kl.setst to _Set_Key_ restarts the load (GR20): K0 and cumul_len zeroed',
      (cl.st, cl.K0, cl.h.cumul_len) == (KL_STATE_SET_KEY, 0, 0))
check('... and a full reload gives the RFC 4231 tag', None, run(cl, B(K0_7), A, B(data7), O, C(32))[1], TAG7)
cl = fresh(key=key7)
check('KLLEN > d: tag, excess bits cleared, _Success_', None,
      (run(cl, A, B(data7), O, C(40))[1], cl.st), (TAG7 + bytes(8), KL_STATE_SUCCESS))
check('KIP _Success_ -> _Ready_ keeps K0: second tag (GR24)', None, run(cl, R, A, B(data7), O, C(32))[1], TAG7)

section('Serialized Content')
for name in HASHES:
    check(f'HMAC-{name} Content1 = H then K0 (b, padded); H = ' + ('n+128+b' if HASHES[name][2] else
          'state, block_base, cumul_len (1600+16+64)') + ' bits, padded', None, len(fresh(name).export()),
          {32: 112 + 64, 64: 208 + 128, None: 224 + -(-HASHES[name][3] // 128) * 16}[HASHES[name][2]])
for name in ('SHA-256', 'SM3', 'SHA3-256'):
    tag, K0 = ref_hmac(name, key7, data7), K0_of(name, key7)
    for label, variant, before, after in [
            ('NIK in _Set_Key_, 40 K0 bytes', 'NIK', (SK, B(K0[:40])), (B(K0[40:]), A, B(data7), O)),
            ('NIK in _Set_Key_, K0 complete', 'NIK', (SK, B(K0)), (A, B(data7), O)),
            ('KIP in _Hash_Absorb_, block_base > 0', 'KIP', (A, B(data7[:100])), (B(data7[100:]), O)),
            ('KIP in _Hash_Output_ after 12 bytes', 'KIP', (A, B(data7[:100]), B(data7[100:]), O, C(12)), ())]:
        r = run(cl := fresh(name, variant, key7 if variant == 'KIP' else None), *before)
        head = r[1] if variant == 'KIP' and not after else b''
        cl = Hmac.load(name, variant, cl.st, cl.export(), cl.se)
        got = head + run(cl, *after, C(32 - len(head)))[1]
        check(f'HMAC-{name} export/import round trip, {label}', got == tag and cl.st == KL_STATE_SUCCESS)

section('kl.derive')
k2, m2 = RFC4231[2]
TAG2_512 = ref_hmac('SHA-512', k2, m2)
src, dst = fresh(key=k2, ops=(A, B(m2), O)), fresh('SHA-512', 'NIK', key7, (A, B(b'prefix')))
r = kl_derive(dst, src, 32)
check('HMAC-SHA-256 tag -> NIK HMAC-SHA-512 absorb, between "prefix" and "suffix"; source _Success_',
      r == 'done' and src.st == KL_STATE_SUCCESS and run(dst, B(b'suffix'), O, C(64))[1]
      == ref_hmac('SHA-512', key7, b'prefix' + TAGS['SHA-256', 2] + b'suffix'))
for length in (64, 80):
    src, dst = fresh('SHA-512', key=k2, ops=(A, B(m2), O)), fresh(variant='NIK', key=None, ops=(SK,))
    r = kl_derive(dst, src, length)
    check(f'HMAC-SHA-512 tag, length {length} -> NIK HMAC-SHA-256 K0 in _Set_Key_ (GR46 key derivation): b/8 = 64 B, '
          'load complete (cumul_len = b), source _Success_; then tags under K0 = tag',
          (r, dst.h.cumul_len, src.st) == ('done', 512, KL_STATE_SUCCESS)
          and run(dst, A, B(data7), O, C(32))[1] == ref_hmac('SHA-256', TAG2_512, data7))
res = []
for s512, variant, ops, length in [(1, 'NIK', (), 64), (1, 'KIP', (), 64), (1, 'NIK', (SK,), 32), (0, 'NIK', (SK,), 64)]:
    src = fresh('SHA-512' if s512 else 'SHA-256', key=k2, ops=(A, B(m2), O))
    dst = fresh(variant=variant, key=key7 if variant == 'KIP' else None, ops=(R, *ops))
    res.append((kl_derive(dst, src, length), dst.st, src.st, src.h.block_base))
check('K0 destination: NIK/KIP in _Ready_ (GR41 item 2), length 32 < b/8, source output 32 < b/8 '
      '(GR41 item 5): destination _Invalid_, source untouched', None, res,
      [('refused', KL_STATE_INVALID, KL_STATE_HASH_OUTPUT, 0)] * 4)

section('Negative controls')
control('ipad and opad swapped', tag_of('SHA-256', *RFC4231[1], swap_pads=True) != TAGS['SHA-256', 1])
control('NIK: cumul_len not zeroed on entering _Hash_Absorb_',
        tag_of('SHA-256', *RFC4231[1], 'NIK', keep_cumul=True) != TAGS['SHA-256', 1])
K0s3 = K0_of('SHA3-256', key7)
c1 = (cl := fresh('SHA3-256', 'NIK', None, ops=(SK, B(K0s3[:40])))).export()
cl = Hmac.load('SHA3-256', 'NIK', cl.st, v2b(b2v(c1) & ~(M64 << 1616), len(c1)), cl.se)
control('HMAC-SHA3-256 Content1 without cumul_len: a partial K0 load cannot be resumed',
        run(cl, B(K0s3[40:]), A, B(data7), O, C(32))[1] != ref_hmac('SHA3-256', key7, data7))
info('b of HMAC-SHA-3 read as the rate of <<KLEE-SHA-3-parameters>>; KIP K0 as SKID (_KeyType_ = 1) not exercised')
done()
