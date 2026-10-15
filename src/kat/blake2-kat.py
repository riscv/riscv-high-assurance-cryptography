#!/usr/bin/env python3
"""BLAKE2 KAT for KLE: <<KLE-BLAKE2>>, BLAKE2b and BLAKE2s (RFC 7693) on the interface of
<<KLE-hash-functions-MACs-XOFs>>.  Keyed hashing uses a system key, whose block the Machine compresses once its role
is known, or a caller's key, which the caller absorbs as the first block after setting kk; the Machine holds no key
by value.  The core is from scratch (RFC 7693 sections 2-3); hashlib is only a labeled reference oracle."""
import hashlib, os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, mdh_pack, mdh_unpack, KL_STATE_UNCONFIGURED as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_HASH_ABSORB as ABSORB, KL_STATE_HASH_LAST_BLOCK as LAST,
                    KL_STATE_HASH_OUTPUT as OUTPUT, KL_STATE_SUCCESS as SUCCESS, KL_STATE_INVALID as INVALID,
                    KL_STATE_SET_AUX_VALUE as SET_AUX, section, check, control, info, done)

# ---------------------------------------------------------------- RFC 7693

# <<KLE-BLAKE2-parameters>>: w, r, b, n, nn_max, kk_max, (R1, R2, R3, R4); Type 7, Modes 0 and 1
PARAMS = {'BLAKE2b': (64, 12, 1024, 512, 64, 64, (32, 24, 16, 63)),
          'BLAKE2s': (32, 10, 512, 256, 32, 32, (16, 12, 8, 7))}
MACHINE = {'BLAKE2b': 0x70, 'BLAKE2s': 0x71}
IV = {'BLAKE2b': [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
                  0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179],
      'BLAKE2s': [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]}
SIGMA = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
         [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
         [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
         [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
         [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]]


def compress(variant, h, block, t, final):
    """F of RFC 7693 section 3.2 on the eight words h, a b-bit block (bytes), counter t (bytes) and flag final."""
    w, r, _, _, _, _, R = PARAMS[variant]
    M = (1 << w) - 1
    ror = lambda x, s: ((x >> s) | (x << (w - s))) & M
    m = [int.from_bytes(block[j * w // 8:(j + 1) * w // 8], 'little') for j in range(16)]
    v = list(h) + list(IV[variant])
    v[12] ^= t & M
    v[13] ^= (t >> w) & M
    if final:
        v[14] ^= M

    def G(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & M; v[d] = ror(v[d] ^ v[a], R[0])
        v[c] = (v[c] + v[d]) & M;     v[b] = ror(v[b] ^ v[c], R[1])
        v[a] = (v[a] + v[b] + y) & M; v[d] = ror(v[d] ^ v[a], R[2])
        v[c] = (v[c] + v[d]) & M;     v[b] = ror(v[b] ^ v[c], R[3])
    for i in range(r):
        s = SIGMA[i % 10]
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);   G(1, 5, 9, 13, m[s[2]], m[s[3]])
        G(2, 6, 10, 14, m[s[4]], m[s[5]]);  G(3, 7, 11, 15, m[s[6]], m[s[7]])
        G(0, 5, 10, 15, m[s[8]], m[s[9]]);  G(1, 6, 11, 12, m[s[10]], m[s[11]])
        G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]])
    return [h[i] ^ v[i] ^ v[i + 8] for i in range(8)]


def oracle(variant, data, nn, key=b''):
    """Reference oracle: hashlib's BLAKE2."""
    return (hashlib.blake2b if variant == 'BLAKE2b' else hashlib.blake2s)(data, digest_size=nn, key=key).digest()


# ---------------------------------------------------------------- the Machine (<<KLE-BLAKE2>>)

class Blake2:
    """A locker holding a BLAKE2 CC.  bad: negative-control deviations ('no-hold', 'eager-key')."""

    def __init__(self, variant, sks=None, bad=()):
        self.v, self.sks, self.bad = variant, sks or {}, set(bad)
        self.w, self.r, self.b, self.n, self.nnmax, self.kkmax, _ = PARAMS[variant]
        self.st, self.keytype, self.skid, self.syskey = UNCONF, 0, None, None

    def invalid(self):
        self.st = INVALID
        return self

    # -- provisioning: the MDH only, or, with KeyType 1, the SKID (64 bits) and zero padding (64 bits)
    def provision_pi(self, pi):
        f = mdh_unpack(b2v(pi[:16]))
        if f['Machine'] != MACHINE[self.v] or len(pi) != (32 if f['KeyType'] == 1 else 16):
            return self.invalid()
        return self.provision(f['KeyType'], b2v(pi[16:24]) if f['KeyType'] == 1 else None)

    def provision(self, keytype=0, skid=None):
        if keytype == 2:                                  # the Machine holds no key by value
            return self.invalid()
        if keytype == 1:
            K = self.sks.get(skid)
            if K is None or not 1 <= len(K) <= self.kkmax:
                return self.invalid()
            self.syskey, self.skid = K, skid
        self.keytype = keytype
        return self.ready()

    def init_state(self):
        self.h = list(IV[self.v])
        self.h[0] ^= 0x01010000 ^ (self.kk << 8) ^ self.nn

    def ready(self):
        self.st, self.nn = READY, self.nnmax
        self.kk = len(self.syskey) if self.syskey else 0
        self.last_blk_len = self.block_base = self.cumul_len = 0
        self.init_state()
        self.block = bytearray((self.syskey or b'').ljust(self.b // 8, b'\0'))
        return self

    def F(self, final):
        self.h = compress(self.v, self.h, self.block, self.cumul_len // 8, final)

    def key_block(self):                                  # the system-key block, not the last
        if self.syskey and self.cumul_len == 0:
            self.cumul_len = self.b
            self.F(False)

    # -- kl.setst
    def setst(self, t, xs=None):
        if self.st in (UNCONF, INVALID):
            return self
        if t == READY:
            return self.ready()
        if t == SET_AUX:                                  # the operation: nn = Xs[7:0], kk = Xs[15:8]
            nn, kk = (xs or 0) & 0xFF, (xs or 0) >> 8 & 0xFF
            if (self.st != READY or xs is None or xs >> 16 or not 1 <= nn <= self.nnmax or kk > self.kkmax
                    or self.syskey and kk):
                return self.invalid()
            self.nn, self.kk = nn, self.kk if self.syskey else kk
            self.init_state()
            return self
        if t == ABSORB:
            if self.st not in (READY, ABSORB):
                return self.invalid()
            if self.st == READY:
                self.key_block()
            self.st = ABSORB
            return self
        if t == LAST:
            if self.st not in (READY, ABSORB) or xs is None or self.block_base or xs > self.b or xs % 8:
                return self.invalid()
            if xs == 0:                                   # the empty message, from Ready only
                if self.st != READY or not self.syskey and self.kk:
                    return self.invalid()
                if self.syskey and 'eager-key' not in self.bad:
                    self.cumul_len = self.b               # the system-key block is the final block
                else:
                    self.key_block()                      # negative control: that block taken as not last
                    self.block = bytearray(self.b // 8)
                self.F(True)
                self.st, self.block_base = OUTPUT, 0
                return self
            if self.st == READY:
                self.key_block()
            self.last_blk_len, self.st = xs, LAST
            return self
        return self.invalid()                             # e.g. _Hash_Output_ named directly (MR1)

    # -- kl.exec
    def exec(self, data):
        if self.st == ABSORB:
            limit, final = self.b, False
        elif self.st == LAST:
            limit, final = self.last_blk_len, True
        else:
            return self.invalid()                         # GR24 in _Ready_, MR1 elsewhere
        bits, ib = 8 * len(data), 0
        while ib < bits:
            amount = min(bits - ib, limit - self.block_base)
            self.block[self.block_base // 8:(self.block_base + amount) // 8] = data[ib // 8:(ib + amount) // 8]
            ib, self.block_base, self.cumul_len = ib + amount, self.block_base + amount, self.cumul_len + amount
            if self.block_base == limit:
                if final:                                 # process_last_block()
                    self.block[self.last_blk_len // 8:] = bytes((self.b - self.last_blk_len) // 8)
                    self.F(True)
                    self.st, self.block_base = OUTPUT, 0
                    return self
                self.F(False)
                self.block_base = 0
        return self

    def output(self, nbytes):
        if self.st != OUTPUT:
            self.invalid()
            return bytes(nbytes)
        digest = b''.join(x.to_bytes(self.w // 8, 'little') for x in self.h)[:self.nn]
        out = digest[self.block_base // 8:self.block_base // 8 + nbytes]
        self.block_base += 8 * len(out)
        if self.block_base == 8 * self.nn:
            self.st = SUCCESS
        return out.ljust(nbytes, b'\0')

    # -- Serialized Content: i the SKID if any, ii state, iii last_blk_len, iv block_base, v nn, vi kk,
    #    vii cumul_len, viii block, zero-padded to 128 bits
    def export(self):
        img = ((v2b(self.skid, 8) if self.syskey else b'') + b''.join(x.to_bytes(self.w // 8, 'little') for x in self.h)
               + b''.join(x.to_bytes(2, 'little') for x in (self.last_blk_len, self.block_base, self.nn, self.kk))
               + self.cumul_len.to_bytes(8, 'little') + bytes(self.block))
        return (self.st, self.keytype), img.ljust(-(-len(img) // 16) * 16, b'\0')

    @classmethod
    def imported(cls, variant, mdh, img, sks=None):
        c = cls(variant, sks)
        c.st, c.keytype = mdh
        o, q = (8 if c.keytype == 1 else 0), c.w // 8
        c.h = [int.from_bytes(img[o + i * q:o + (i + 1) * q], 'little') for i in range(8)]
        o += 8 * q
        c.last_blk_len, c.block_base, c.nn, c.kk = (int.from_bytes(img[o + 2 * i:o + 2 * i + 2], 'little')
                                                    for i in range(4))
        c.cumul_len = int.from_bytes(img[o + 8:o + 16], 'little')
        c.block = bytearray(img[o + 16:o + 16 + c.b // 8])
        if c.keytype == 1:                                # the SKID is resolved again after the import
            c.skid, c.syskey = b2v(img[:8]), c.sks.get(b2v(img[:8]))
            if c.syskey is None or len(c.syskey) != c.kk:
                return c.invalid()
        return c


def run(variant, data, nn=None, key=b'', c=None, chunks=None, direct=False, roundtrip=False, bad=(), nokk=False):
    """Hash data: whole blocks in _Hash_Absorb_, the final block (1 to b/8 bytes) in _Hash_Absorb_Last_Block_, the
    empty message by the Xs = 0 kl.setst from _Ready_.  A caller's key is absorbed as the first block, after the
    operation sets kk (nokk: a negative control that leaves kk unset)."""
    c = c or Blake2(variant, bad=bad).provision()
    bb = c.b // 8
    if nn is not None or key:
        c.setst(SET_AUX, (nn or c.nnmax) | (0 if nokk else len(key)) << 8)
    stream = (key.ljust(bb, b'\0') if key else b'') + data
    if not stream:
        c.setst(LAST, 0)
    else:
        last = (len(stream) - 1) % bb + 1
        head, tail = stream[:-last], stream[-last:]
        if 'no-hold' in bad and len(stream) % bb == 0:   # negative control: the final full block compressed early
            head, tail = stream, b''
        if head or not direct:
            c.setst(ABSORB)
            for piece in split(head, chunks):
                c.exec(piece)
                if roundtrip and c.block_base == 0:
                    c = Blake2.imported(variant, *c.export(), sks=c.sks)
        if tail:
            c.setst(LAST, 8 * len(tail)).exec(tail)
        else:
            c.setst(LAST, 0)
    return (c.output(c.nn) if c.st == OUTPUT else None), c


def split(data, sizes):
    if not sizes:
        return [data] if data else []
    out, i, k = [], 0, 0
    while i < len(data):
        out.append(data[i:i + sizes[k % len(sizes)]])
        i, k = i + sizes[k % len(sizes)], k + 1
    return out


def pi(variant, skid=None):
    mdh = v2b(mdh_pack(Machine=MACHINE[variant], KeyType=int(skid is not None)), 16)
    return mdh + (v2b(skid, 8) + bytes(8) if skid is not None else b'')


# ---------------------------------------------------------------- checks

VARIANTS = ('BLAKE2b', 'BLAKE2s')
SKID = 0x0123456789ABCDEF
RFC_ABC = {'BLAKE2b': 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1'
                      '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
           'BLAKE2s': '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982'}
rnd = random.Random(7693)
rbytes = lambda n: bytes(rnd.randrange(256) for _ in range(n))

section('RFC 7693 Appendices A and B: "abc", unkeyed, nn = nn_max')
for v in VARIANTS:
    check(f'{v}: the Machine gives the RFC 7693 digest of "abc"', None, run(v, b'abc', direct=True)[0].hex(), RFC_ABC[v])
    check(f'{v}: the reference oracle agrees', None, oracle(v, b'abc', PARAMS[v][4]).hex(), RFC_ABC[v])

section('<<KLE-BLAKE2-parameters>>, the Provisioning Input and _Ready_')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    check(f'{v}: n = 8 w, b = 16 w, nn_max = kk_max = w; the IV is the initial value of SHA-{512 if w == 64 else 256}',
          (n, b, nnmax, kkmax) == (8 * w, 16 * w, w, w) and IV[v][0] == (0x6A09E667F3BCC908 >> (64 - w)))
    sks = {SKID: rbytes(17)}
    c0, c1 = Blake2(v).provision_pi(pi(v)), Blake2(v, sks=sks).provision_pi(pi(v, SKID))
    check(f'{v}: the PI is the MDH only (16 B), or with a system key the SKID and 64 bits of padding (32 B); '
          'kk = 0, resp. the length of the SKS key (17)',
          (len(pi(v)), len(pi(v, SKID)), c0.st, c0.kk, c1.st, c1.kk) == (16, 32, READY, 0, READY, 17))
    c = Blake2(v).provision().setst(SET_AUX, 20 | 3 << 8)
    check(f'{v}: the operation sets nn = Xs[7:0] and kk = Xs[15:8], and h0 = IV0 ^ 0x01010000 ^ (kk << 8) ^ nn',
          (c.nn, c.kk, c.h[0], c.h[1:]) == (20, 3, IV[v][0] ^ 0x01010000 ^ (3 << 8) ^ 20, IV[v][1:]))

section('Digest, key and message lengths against the oracle')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    bb, cases, bad = b // 8, 0, []
    for kk in (0, 1, kkmax // 2, kkmax):
        key, sks = rbytes(kk), {}
        for system in ((False, True) if kk else (False,)):
            sks = {SKID: key} if system else {}
            for nn in (1, nnmax // 2 - 3, nnmax):
                for ln in (0, 1, bb - 1, bb, bb + 1, 2 * bb, 3 * bb - 5):
                    data, want = rbytes(ln), None
                    want = oracle(v, data, nn, key)
                    for direct in (False, True):
                        c = Blake2(v, sks=sks).provision(1, SKID) if system else None
                        got = run(v, data, nn, b'' if system else key, c=c, direct=direct)[0]
                        cases += 1
                        if got != want:
                            bad.append((kk, system, nn, ln, direct))
    check(f'{v}: {cases} cases (no key, a caller key or a system key of 1, half or all kk_max bytes; nn 1, middle, '
          'max; 0 to 3 blocks; through _Hash_Absorb_ or directly): the Machine equals the oracle', None, bad, [])
    data, key = rbytes(5 * bb + 17), rbytes(kkmax)
    got = [run(v, data, None, key, chunks=s)[0] for s in ([1], [3, 64, 5], [bb], [7 * bb])]
    check(f'{v}: kl.exec windows of 1 byte, of 3, 64 and 5 bytes, of a block, of 7 blocks: the same digest',
          got == [oracle(v, data, nnmax, key)] * 4)
    sks = {SKID: key}
    check(f'{v}: export and import after every kl.exec of _Hash_Absorb_, with a caller key and with a system key '
          '(the SKID resolved again): the same digest', None,
          [run(v, data, 20, key, chunks=[bb, 2 * bb], roundtrip=True)[0],
           run(v, data, 20, c=Blake2(v, sks=sks).provision(1, SKID), chunks=[bb, 2 * bb], roundtrip=True)[0]],
          [oracle(v, data, 20, key)] * 2)

section('_Ready_, the digest length and the key block')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    key, sks = b'k' * 16, {SKID: b's' * 24}
    d1, c = run(v, b'first', 20, key)
    c.setst(READY)
    check(f'{v}: _Ready_ resets nn to nn_max and kk to 0 (caller key); the next message, unkeyed, is correct',
          (d1, c.nn, c.kk, run(v, b'second', c=c)[0]) == (oracle(v, b'first', 20, key), nnmax, 0,
                                                         oracle(v, b'second', nnmax)))
    c = Blake2(v, sks=sks).provision(1, SKID)
    run(v, b'first', 20, c=c)
    c.setst(READY)
    check(f'{v}: _Ready_ restores kk and the block of the system key', (c.kk, bytes(c.block[:24]), c.cumul_len)
          == (24, b's' * 24, 0) and run(v, b'second', c=c)[0] == oracle(v, b'second', nnmax, b's' * 24))
    check(f'{v}: nn enters the parameter block: the 20-byte digest is no truncation of the full one',
          oracle(v, b'abc', 20) != oracle(v, b'abc', nnmax)[:20] and run(v, b'abc', 20)[0] == oracle(v, b'abc', 20))
    c = Blake2(v, sks=sks).provision(1, SKID)
    check(f'{v}: system key, empty message: the key block is the final block, cumul_len = b (RFC 7693 3.3)',
          run(v, b'', c=c)[0] == oracle(v, b'', nnmax, b's' * 24) and c.cumul_len == b)
    c = Blake2(v, sks=sks).provision(1, SKID).setst(ABSORB)
    check(f'{v}: system key: leaving _Ready_ for _Hash_Absorb_ compresses its block as not last, cumul_len = b',
          (c.cumul_len, c.block_base) == (b, 0))
    check(f'{v}: caller key, empty message: the caller absorbs the key block as the final block',
          run(v, b'', None, key)[0] == oracle(v, b'', nnmax, key))

section('_Invalid_ outcomes')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    bb, sks = b // 8, {SKID: b'k' * 8, 5: b'', 6: bytes(kkmax + 1)}
    fresh = lambda: Blake2(v, sks=sks).provision()
    system = lambda: Blake2(v, sks=sks).provision(1, SKID)
    cases = {
        'nn = 0': fresh().setst(SET_AUX, 0),
        'nn = nn_max + 1': fresh().setst(SET_AUX, nnmax + 1),
        'kk = kk_max + 1': fresh().setst(SET_AUX, 1 | (kkmax + 1) << 8),
        'Xs[15:8] != 0 with a system key': system().setst(SET_AUX, 16 | 1 << 8),
        'a set bit of Xs above bit 15': fresh().setst(SET_AUX, 16 | 1 << 16),
        'the operation outside _Ready_': fresh().setst(ABSORB).setst(SET_AUX, 16),
        'Xs = 0 from _Hash_Absorb_': fresh().setst(ABSORB).exec(bytes(bb)).setst(LAST, 0),
        'Xs = 0 after the caller set kk > 0': fresh().setst(SET_AUX, nnmax | 8 << 8).setst(LAST, 0),
        'a partial block left in _Hash_Absorb_': fresh().setst(ABSORB).exec(b'ab').setst(LAST, 8),
        'Xs > b': fresh().setst(LAST, b + 8),
        'Xs not a multiple of 8': fresh().setst(LAST, 12),
        '_Hash_Output_ named': fresh().setst(ABSORB).setst(OUTPUT),
        'kl.exec in _Ready_': fresh().exec(b'x'),
        'KeyType 2': Blake2(v).provision(2),
        'an empty SKS key': Blake2(v, sks=sks).provision(1, 5),
        'an SKS key longer than kk_max': Blake2(v, sks=sks).provision(1, 6),
    }
    check(f'{v}: ' + '; '.join(cases) + ' -> _Invalid_', None, [k for k, c in cases.items() if c.st != INVALID], [])

section('Serialized Content (<<KLE-hash-functions-MACs-XOFs>>)')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    sks = {SKID: b'k' * 9}
    c = Blake2(v, sks=sks).provision(1, SKID)
    img = c.export()[1]
    sizes = [len(Blake2(v).provision().export()[1]), len(img)]
    check(f'{v}: {sizes[0]} B without, {sizes[1]} B with a system key, whose SKID is Position i; nn and kk in v and vi',
          sizes == [-(-(n + 128 + b) // 128) * 16, -(-(64 + n + 128 + b) // 128) * 16]
          and img[:8] == v2b(SKID, 8) and img[8 + n // 8 + 4:8 + n // 8 + 8] == v2b(nnmax, 2) + v2b(9, 2))

section('Negative controls')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    bb, key, sks = b // 8, b'secret', {SKID: b'secret'}
    data = bytes(range(256))[:2 * bb]
    control(f'{v}: compressing the final full block in _Hash_Absorb_ (no hold-back) gives a wrong digest',
            run(v, data, bad=('no-hold',))[0] != oracle(v, data, nnmax))
    control(f'{v}: a system-key block taken as not last for the empty message gives a wrong digest',
            run(v, b'', c=Blake2(v, sks=sks, bad=('eager-key',)).provision(1, SKID))[0] != oracle(v, b'', nnmax, key))
    control(f'{v}: a caller key absorbed without kk in the parameter block gives a wrong digest',
            run(v, b'msg', None, key, nokk=True)[0] != oracle(v, b'msg', nnmax, key))
    control(f'{v}: a truncated full-length digest is not the 20-byte digest',
            oracle(v, b'abc', nnmax)[:20] != run(v, b'abc', 20)[0])
info('hashlib.blake2b/blake2s serve only as a reference oracle; the Machine runs the from-scratch core above.')

done()
