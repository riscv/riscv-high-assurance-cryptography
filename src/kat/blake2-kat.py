#!/usr/bin/env python3
"""BLAKE2 KAT for KLE: <<KLE-BLAKE2>>, BLAKE2b and BLAKE2s (RFC 7693) on the interface of
<<KLE-hash-functions-MACs-XOFs>>.  Keyed hashing uses a system key, whose block the Machine compresses once its role
is known, or a caller's key, which the caller absorbs as the first block after setting kk; the Machine holds no key
by value.  The core is from scratch (RFC 7693 sections 2-3); hashlib is only a labeled reference oracle."""
import hashlib, os, random, sys
from math import isqrt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, mdh_pack, mdh_unpack, KL_STATE_UNCONFIGURED as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_HASH_ABSORB as ABSORB, KL_STATE_HASH_LAST_BLOCK as LAST,
                    KL_STATE_HASH_OUTPUT as OUTPUT, KL_STATE_SUCCESS as SUCCESS, KL_STATE_INVALID as INVALID,
                    KL_STATE_SET_AUX_VALUE as SET_AUX, KL_STATE_UNSUPPORTED as UNSUP, section, check, control,
                    info, done, HashPort, hash_msgs, check_hash, ERROR_STATES, inert,
                    KL_STATE_OUT_OF_MEMORY, IllegalInstruction, raises)

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
        self.st, self.keytype, self.skid, self.syskey, self.policy = UNCONF, 0, None, None, 0

    def invalid(self):
        self.st = INVALID
        return self

    # -- provisioning: the MDH only, or, with KeyType 1, the SKID (64 bits) and zero padding (64 bits)
    def provision_pi(self, pi):
        f = mdh_unpack(b2v(pi[:16]))
        if f['Machine'] != MACHINE[self.v] or len(pi) != (32 if f['KeyType'] == 1 else 16):
            return self.invalid()
        return self.provision(f['KeyType'], b2v(pi[16:24]) if f['KeyType'] == 1 else None, f['MachinePolicy'])

    def provision(self, keytype=0, skid=None, policy=None):
        """policy: _MachinePolicy_; by default 1 (generation) with a system key, 0 otherwise."""
        policy = int(keytype == 1) if policy is None else policy
        if keytype == 2:                                  # the Machine holds no key by value
            return self.invalid()
        if policy & ~1 or keytype != 1 and policy:        # unsupported Metadata
            self.st = UNSUP
            return self
        if keytype == 1 and not policy & 1:               # a MAC that only generates: bit 0 required
            return self.invalid()
        self.policy = policy
        if keytype == 1:
            K = self.sks.get(skid)
            if K is None or not 1 <= len(K) <= self.kkmax:
                return self.invalid()
            self.syskey, self.skid = K, skid
        self.keytype = keytype
        return self.ready(True)

    def init_state(self):
        self.h = list(IV[self.v])
        self.h[0] ^= 0x01010000 ^ (self.kk << 8) ^ self.nn

    def ready(self, provisioning=False):
        self.st = READY
        if provisioning:                                  # nn and kk are kept across a return to _Ready_
            self.nn, self.kk = self.nnmax, len(self.syskey) if self.syskey else 0
        self.last_block_len = self.block_base = self.cumul_len = self.out_len = 0
        self.init_state()
        self.block = bytearray(self.b // 8)               # the system key is not held in `block`
        return self

    def F(self, final):
        self.h = compress(self.v, self.h, self.block, self.cumul_len // 8, final)

    def key_block(self, final=False):                     # the system-key block: syskey in `block` only here
        if self.syskey and self.cumul_len == 0:
            self.block = bytearray(self.syskey.ljust(self.b // 8, b'\0'))
            self.cumul_len = self.b
            self.F(final)
            self.block = bytearray(self.b // 8)

    def gated(self):                                      # MR11, GR20: with a system key the only operation (the MAC)
        return bool(self.syskey) and not self.policy & 1  # needs bit 0; every useful State leads only to it

    def restrict(self, clear):                            # kl.restrictl: clears _MachinePolicy_ bits (GR20)
        if clear and not inert(self.st):                  # a zero field changes nothing; GR26
            if not self.syskey:                           # the field is unused: <<KLE-instruction-restrict>>
                return self.invalid()
            self.policy &= ~clear
            if not self.policy & 1:                       # GR20: a value the Machine forbids (bit 0 must be set)
                return self.invalid()
        return self                                       # otherwise the restriction alone changes no State

    # -- kl.setst (xs None: Form A)
    def setst(self, t, xs=None):
        if t == UNCONF:                                   # kl.clear (#immed7 = 0), in any State and Form
            self.__init__(self.v, self.sks, self.bad)
            return self
        if t in (54, 55):
            raise IllegalInstruction('reserved #immed7')  # GR18
        if t in ERROR_STATES:                             # GR30: in every State; _Unconfigured_ is left unchanged
            if self.st != UNCONF:
                self.st = t
            return self
        if inert(self.st):                                # GR26
            return self
        if t == READY:                                    # GR16: Form A
            return self.ready() if xs is None else self.invalid()
        if t in (ABSORB, LAST, OUTPUT) and self.gated():  # GR20: States that lead only to the disabled operation
            return self.invalid()
        if t == SET_AUX:                                  # the operation: nn = Xs[7:0], kk = Xs[15:8]
            nn, kk = (xs or 0) & 0xFF, (xs or 0) >> 8 & 0xFF
            if (self.st != READY or xs is None or xs >> 16 or not 1 <= nn <= self.nnmax or kk > self.kkmax
                    or self.syskey and kk):
                return self.invalid()
            self.nn, self.kk = nn, self.kk if self.syskey else kk
            self.init_state()
            return self
        if t == ABSORB:
            if self.st != READY or xs is not None:        # Form A, from _Ready_ only (no same-State kl.setst)
                return self.invalid()
            if 'eager-key' in self.bad:                   # negative control: compression on leaving _Ready_
                self.key_block()
            self.st, self.last_block_len = ABSORB, self.b
            return self
        if t == LAST:                                     # Form A: a final piece of b bits
            if self.st != ABSORB or xs is not None and (xs % 8 or not 0 <= xs <= self.b):
                return self.invalid()
            self.st, self.last_block_len = LAST, self.b if xs is None else xs
            return self
        if t == OUTPUT:                                   # ends the message held in `block`
            if not (self.st == ABSORB or self.st == LAST and self.last_block_len == 0):
                return self.invalid()
            if xs and (xs % 8 or xs > 8 * self.nn):       # the bound: a multiple of 8, at most 8 nn
                return self.invalid()
            if not self.finalize():
                return self.invalid()
            self.st, self.block_base, self.last_block_len, self.out_len = OUTPUT, 0, 0, xs or 8 * self.nn
            return self
        return self.invalid()                             # e.g. _Hash_Output_ from _Ready_ (MR1)

    def finalize(self):
        """<<KLE-BLAKE2>> finalize(): F(true) on the block that holds the last byte, or on the empty message."""
        if self.block_base:
            self.block[self.block_base // 8:] = bytes((self.b - self.block_base) // 8)
            self.F(True)
        elif self.syskey and self.cumul_len == 0:         # the pending system-key block is the final block
            self.key_block(final=True)
        elif self.kk and not self.syskey or self.cumul_len:
            return False                                  # the caller's key block is missing
        else:
            self.F(True)                                  # the empty unkeyed message: the zero block
        self.block_base = 0
        return True

    # -- kl.exec
    def exec(self, data, halt=False, klstart=0):
        """halt: halt at the first interruption point; self.klstart then records it (GR41)."""
        self.klstart = 0
        if inert(self.st):                                # GR26
            return self
        if self.st in (ABSORB, LAST, OUTPUT) and self.gated():
            return self.invalid()                         # GR20: the first operation after the narrowing
        if self.st == ABSORB:
            bits, final = 8 * len(data), False
        elif self.st == LAST:
            L = self.last_block_len
            if 8 * len(data) < L:                         # the whole piece (MR2, GR44 item 1): length first
                return self.invalid()
            if klstart >= len(data):                      # GR44 item 2: an empty window does not reach the Machine
                return self
            if not L or klstart:                          # MR10; interruption point 0 only (MR3, GR44 item 3)
                return self.invalid()
            bits, final = L, True
        else:
            return self.invalid()                         # GR17 in _Ready_, MR1 elsewhere
        ib = 8 * klstart
        if klstart and klstart < len(data) and not (self.st == ABSORB and self.block_base in (0, self.b)):
            return self.invalid()                         # GR44 item 3: 0, or block_base = 0 or b in _Hash_Absorb_
        if ib < bits and 'eager-key' not in self.bad:
            self.key_block()                              # the pending system-key block, before the first byte
        while ib < bits:
            if self.block_base == self.b:                 # a full block is compressed before the next byte
                self.F(False)
                self.block_base = 0
            amount = min(bits - ib, self.b - self.block_base)
            self.block[self.block_base // 8:(self.block_base + amount) // 8] = data[ib // 8:(ib + amount) // 8]
            ib, self.block_base, self.cumul_len = ib + amount, self.block_base + amount, self.cumul_len + amount
            if halt and not final and ib < bits and self.block_base == self.b:
                self.klstart = ib // 8                    # a precise halt (<<KLE-BLAKE2>>)
                return self
            if self.block_base == self.b and 'no-hold' in self.bad:
                self.F(False)                             # negative control: eager compression
                self.block_base = 0
        if final:
            self.last_block_len = 0
        return self

    def output(self, nbytes, klstart=0, prior=None):
        head = (prior or bytes(nbytes))[:klstart]         # MR8: the bytes below klstart are not written
        if inert(self.st):                                # GR26, GR28
            return head.ljust(nbytes, b'\0')
        if self.st != OUTPUT or self.gated():             # GR20 in _Hash_Output_
            self.invalid()
            return head.ljust(nbytes, b'\0')              # GR28: [klstart, KLLEN/8-1] zeroed
        if klstart >= nbytes:                             # GR44 item 2: an empty window writes nothing
            return b''
        if klstart and self.block_base:                   # GR44 item 3: 0, or any byte offset at block_base = 0
            self.invalid()
            return head.ljust(nbytes, b'\0')              # GR28: [klstart, KLLEN/8-1] zeroed
        digest = b''.join(x.to_bytes(self.w // 8, 'little') for x in self.h)[:self.nn]
        n = min(nbytes - klstart, self.out_len // 8)
        out = digest[self.block_base // 8:self.block_base // 8 + n]
        self.block_base += 8 * len(out)
        self.out_len -= 8 * len(out)
        if self.out_len == 0:
            self.st = SUCCESS
        return (head + out).ljust(nbytes, b'\0')          # [0, klstart-1] kept (MR8)

    # -- Serialized Content: i the SKID if any, ii state, iii last_block_len (in _Hash_Output_: out_len),
    #    iv block_base, v nn, vi kk, vii cumul_len, viii block, zero-padded to 128 bits
    def export(self):
        iii = self.out_len if self.st == OUTPUT else self.last_block_len
        img = ((v2b(self.skid, 8) if self.syskey else b'') + b''.join(x.to_bytes(self.w // 8, 'little') for x in self.h)
               + b''.join(x.to_bytes(2, 'little') for x in (iii, self.block_base, self.nn, self.kk))
               + self.cumul_len.to_bytes(8, 'little') + bytes(self.block))
        return (self.st, self.keytype), img.ljust(-(-len(img) // 16) * 16, b'\0')

    @classmethod
    def imported(cls, variant, mdh, img, sks=None):
        c = cls(variant, sks)
        c.st, c.keytype = mdh
        c.policy = int(c.keytype == 1)                    # _MachinePolicy_ is in the MDH
        o, q = (8 if c.keytype == 1 else 0), c.w // 8
        c.h = [int.from_bytes(img[o + i * q:o + (i + 1) * q], 'little') for i in range(8)]
        o += 8 * q
        c.last_block_len, c.block_base, c.nn, c.kk = (int.from_bytes(img[o + 2 * i:o + 2 * i + 2], 'little')
                                                    for i in range(4))
        c.out_len = 0
        if c.st == OUTPUT:
            c.out_len, c.last_block_len = c.last_block_len, 0
        c.cumul_len = int.from_bytes(img[o + 8:o + 16], 'little')
        c.block = bytearray(img[o + 16:o + 16 + c.b // 8])
        if not 1 <= c.nn <= c.nnmax or c.kk > c.kkmax:    # MR13: the field checks of nn and kk
            return c.invalid()
        if c.keytype == 1:                                # the SKID is resolved again after the import
            c.skid, c.syskey = b2v(img[:8]), c.sks.get(b2v(img[:8]))
            if c.syskey is None or len(c.syskey) != c.kk:
                return c.invalid()
        return c


def run(variant, data, nn=None, key=b'', c=None, chunks=None, direct=False, roundtrip=False, bad=(), nokk=False,
        held=False):
    """Hash data by the generic sequence: Form A into _Hash_Absorb_, the head by kl.exec, the final piece (1 to b/8
    bytes) in _Hash_Absorb_Last_Block_, then the kl.setst into _Hash_Output_.  held: the whole message in
    _Hash_Absorb_ and Xs = 0, as after a kl.derive of its last bytes; direct: the whole message in _Hash_Absorb_ and the
    direct kl.setst into _Hash_Output_.  A caller's key is absorbed as the first block, after the operation sets kk
    (nokk: a negative control that leaves kk unset)."""
    c = c or Blake2(variant, bad=bad).provision()
    bb = c.b // 8
    if nn is not None or key:
        c.setst(SET_AUX, (nn or c.nnmax) | (0 if nokk else len(key)) << 8)
    stream = (key.ljust(bb, b'\0') if key else b'') + data
    last = (len(stream) - 1) % bb + 1 if stream else 0
    head, tail = stream[:len(stream) - last], stream[len(stream) - last:]
    if held or direct or 'no-hold' in bad and len(stream) % bb == 0:
        head, tail = stream, b''                          # 'no-hold': the final full block compressed early
    c.setst(ABSORB)
    for piece in split(head, chunks):
        c.exec(piece)
        if roundtrip and c.block_base in (0, c.b):
            c = Blake2.imported(variant, *c.export(), sks=c.sks)
    if not direct:
        c.setst(LAST, 8 * len(tail))
        if tail:
            c.exec(tail)
    c.setst(OUTPUT)
    return (c.output(c.nn) if c.st == OUTPUT else None), c


def split(data, sizes):
    if not sizes:
        return [data] if data else []
    out, i, k = [], 0, 0
    while i < len(data):
        out.append(data[i:i + sizes[k % len(sizes)]])
        i, k = i + sizes[k % len(sizes)], k + 1
    return out


def pi(variant, skid=None, policy=None):
    policy = int(skid is not None) if policy is None else policy
    mdh = v2b(mdh_pack(Machine=MACHINE[variant], KeyType=int(skid is not None), MachinePolicy=policy), 16)
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
          (n, b, nnmax, kkmax) == (8 * w, 16 * w, w, w) and IV[v] == [isqrt(p << 2 * w) & ((1 << w) - 1) for p in (2, 3, 5, 7, 11, 13, 17, 19)])
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
        key = rbytes(kk)
        for system in ((False, True) if kk else (False,)):
            sks = {SKID: key} if system else {}
            for nn in (1, nnmax // 2 - 3, nnmax):
                for ln in (0, 1, bb - 1, bb, bb + 1, 2 * bb, 3 * bb - 5):
                    data = rbytes(ln)
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
    kept = (c.nn, c.kk)
    c.setst(ABSORB).exec(key.ljust(b // 8, b'\0') + b'second').setst(OUTPUT)
    check(f'{v}: _Ready_ keeps nn and kk (caller key); the next message, with its key block, is the same keyed BLAKE2',
          (d1, kept, c.output(20)) == (oracle(v, b'first', 20, key), (20, 16), oracle(v, b'second', 20, key)))
    c = Blake2(v, sks=sks).provision(1, SKID)
    run(v, b'first', 20, c=c)
    c.setst(READY)
    check(f'{v}: _Ready_ keeps kk and nn, with a zero `block` (the key block is compressed with the first message byte)',
          (c.kk, c.nn, bytes(c.block), c.cumul_len) == (24, 20, bytes(b // 8), 0) and run(v, b'second', c=c)[0] == oracle(v, b'second', 20, b's' * 24))
    check(f'{v}: nn enters the parameter block: the 20-byte digest is no truncation of the full one',
          oracle(v, b'abc', 20) != oracle(v, b'abc', nnmax)[:20] and run(v, b'abc', 20)[0] == oracle(v, b'abc', 20))
    c = Blake2(v, sks=sks).provision(1, SKID)
    check(f'{v}: system key, empty message: the key block is the final block, cumul_len = b (RFC 7693 3.3)',
          run(v, b'', c=c)[0] == oracle(v, b'', nnmax, b's' * 24) and c.cumul_len == b)
    c = Blake2(v, sks=sks).provision(1, SKID).setst(ABSORB)
    cl0 = c.cumul_len
    c.exec(b'x')
    st = (cl0, c.cumul_len, c.block_base)
    check(f'{v}: system key: the key block stays pending after the kl.setst into _Hash_Absorb_ (cumul_len = 0), and '
          'the first absorbing kl.exec compresses it as not last (cumul_len = b + 8; the digest of "x" is right)', None,
          (st, c.setst(LAST, 0).setst(OUTPUT).output(nnmax)), ((0, b + 8, 8), oracle(v, b'x', nnmax, b's' * 24)))
    check(f'{v}: caller key, empty message: the caller absorbs the key block as the final block',
          run(v, b'', None, key)[0] == oracle(v, b'', nnmax, key))

section('A message ended in _Hash_Absorb_ (Xs = 0), as after a kl.derive of its last bytes')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    bb, sks = b // 8, {SKID: b's' * 24}
    data = bytes(range(256)) * 2
    lens = (1, bb - 1, bb, bb + 1, 2 * bb, 3 * bb - 5)
    check(f'{v}: lengths {lens}, unkeyed, caller key, system key, in pieces of 7 and 13 B with export/import: '
          'a full block is held until the next byte, Xs = 0 ends the message in `block` with F(true)',
          None, [run(v, data[:m], 20, k, c=Blake2(v, sks=sks).provision(1, SKID) if sk else None, chunks=(7, 13),
                     held=True, roundtrip=True)[0]
                 for m in lens for k, sk in ((b'', 0), (b'k' * 16, 0), (b'', 1))],
          [oracle(v, data[:m], 20, b's' * 24 if sk else k) for m in lens for k, sk in ((b'', 0), (b'k' * 16, 0), (b'', 1))])
    K = bytes(range(32))
    check(f'{v}: BLAKE2(K) for a 32-byte K, the ML-KEM `sharedkey` size, and a caller key with the empty message, '
          'both ended by Xs = 0 from _Hash_Absorb_', None,
          (run(v, K, held=True)[0], run(v, b'', None, b'k' * 16, held=True)[0]),
          (oracle(v, K, nnmax), oracle(v, b'', nnmax, b'k' * 16)))
    c = Blake2(v).provision().setst(ABSORB).exec(bytes(bb))
    bb0, bb1 = c.block_base, c.setst(LAST, 8).block_base
    check(f'{v}: a full block in _Hash_Absorb_ is held (block_base = b), still after the Xs > 0 kl.setst, and '
          'compressed by the first byte of the final piece', None,
          (bb0, bb1, c.exec(b'x').block_base, c.setst(OUTPUT).output(nnmax)), (b, b, 8, oracle(v, bytes(bb) + b'x', nnmax)))
    res = []
    for m in (bytes(bb), bytes(2 * bb)):
        for how in ('Xs = 0', 'direct', 'piece = b'):
            c = Blake2(v).provision().setst(ABSORB)
            if how == 'piece = b':
                c.exec(m[:-bb]).setst(LAST, b).exec(m[-bb:]).setst(OUTPUT)
            else:
                c.exec(m)
                if how == 'Xs = 0':
                    c.setst(LAST, 0)
                c.setst(OUTPUT)
            res.append(c.output(nnmax) == oracle(v, m, nnmax))
    check(f'{v}: a message ending on a block boundary (1 and 2 blocks), ended by Xs = 0, by the direct kl.setst into '
          '_Hash_Output_, or by a final piece of b bits: F(true) on the block holding the last byte (RFC 7693)',
          all(res))
    c = Blake2(v).provision().setst(ABSORB).exec(b'abc')
    c.setst(OUTPUT, 8 * 20)
    o = c.output(32)
    c2 = Blake2(v).provision().setst(ABSORB).exec(b'abc')
    check(f'{v}: bound Xs = 160: the first 20 bytes of the nn-byte digest (not the 20-byte digest), excess cleared, '
          '_Success_; Xs > 8 nn or 12 -> _Invalid_', None,
          (o, c.st, c2.setst(OUTPUT, 8 * nnmax + 8).st, Blake2(v).provision().setst(ABSORB).setst(OUTPUT, 12).st),
          (oracle(v, b'abc', nnmax)[:20] + bytes(12), SUCCESS, INVALID, INVALID))
    c = Blake2(v).provision().setst(ABSORB).exec(b'ab').setst(LAST)
    check(f'{v}: Form A into _Hash_Absorb_Last_Block_ keeps last_block_len = b; a b-bit piece gives the digest',
          None, (c.last_block_len, c.exec(bytes(b // 8)).setst(OUTPUT).output(nnmax)),
          (b, oracle(v, b'ab' + bytes(b // 8), nnmax)))

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
        'a kl.exec after Xs = 0 (MR10)': fresh().setst(ABSORB).setst(LAST, 0).exec(b'a'),
        'the kl.setst into _Hash_Output_ with kk > 0 and no key block (finalize())':
            fresh().setst(SET_AUX, nnmax | 8 << 8).setst(ABSORB).setst(LAST, 0).setst(OUTPUT),
        '_Ready_ -> _Hash_Absorb_Last_Block_': fresh().setst(LAST, 8),
        'Xs > b': fresh().setst(ABSORB).setst(LAST, b + 8),
        'Xs not a multiple of 8': fresh().setst(ABSORB).setst(LAST, 12),
        '_Ready_ -> _Hash_Output_': fresh().setst(OUTPUT),
        '_Hash_Output_ named before the final piece (system key)':
            system().setst(ABSORB).setst(LAST, 8).setst(OUTPUT),
        'a last block of 16 bits in a KLLEN of 8 (one kl.exec, MR2)':
            fresh().setst(ABSORB).setst(LAST, 16).exec(b'a'),
        'a same-State kl.setst into _Hash_Absorb_': fresh().setst(ABSORB).setst(ABSORB),
        'kl.exec in _Ready_': fresh().exec(b'x'),
        'KeyType 2': Blake2(v).provision(2),
        'an empty SKS key': Blake2(v, sks=sks).provision(1, 5),
        'an SKS key longer than kk_max': Blake2(v, sks=sks).provision(1, 6),
    }
    check(f'{v}: ' + '; '.join(cases) + ' -> _Invalid_', None, [k for k, c in cases.items() if c.st != INVALID], [])

section('_MachinePolicy_ (Rule MR11)')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    sks = {SKID: b's' * 24}
    states = [Blake2(v, sks=sks).provision_pi(pi(v, *a)).st for a in ((None, 0), (None, 1), (SKID, 1), (SKID, 0),
                                                                     (SKID, 2), (SKID, 3))]
    check(f'{v}: provisioning with _MachinePolicy_ 0 / 1 unkeyed, 1 / 0 / 2 / 3 with a system key', None, states,
          [READY, UNSUP, READY, INVALID, UNSUP, UNSUP])
    gate = [Blake2(v, sks=sks).provision(1, SKID).setst(ABSORB).exec(b'ab').restrict(1).st,
            Blake2(v, sks=sks).provision(1, SKID).setst(ABSORB).setst(LAST, 8).exec(b'x').setst(OUTPUT)
            .restrict(1).st,
            Blake2(v, sks=sks).provision(1, SKID).restrict(2).st]
    check(f'{v}: system key: a kl.restrictl clearing bit 0 leaves _MachinePolicy_ = 0, which the Machine forbids: '
          '_Invalid_ at once, in _Hash_Absorb_ and in _Hash_Output_ (GR20); clearing the unset bit 1 changes nothing',
          None, gate, [INVALID, INVALID, READY])
    check(f'{v}: without a system key nothing is gated, and a kl.restrictl of the unused _MachinePolicy_ -> _Invalid_; '
          'a zero _MachinePolicy_ field changes nothing (<<KLE-instruction-restrict>>)', None,
          (run(v, b'abc')[0], Blake2(v).provision().restrict(1).st, Blake2(v).provision().restrict(0).st),
          (oracle(v, b'abc', nnmax), INVALID, READY))

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
    part = Blake2(v, sks=sks).provision(1, SKID).setst(ABSORB).exec(b'ab').export()[1]
    check(f'{v}: no system-key byte in `block` of a Content in _Ready_ or after 2 B in _Hash_Absorb_ (GR68)',
          img[8 + n // 8 + 16:][:b // 8] == bytes(b // 8)
          and part[8 + n // 8 + 16:][:b // 8] == b'ab' + bytes(b // 8 - 2))

for v in VARIANTS:
    img = Blake2(v, sks={SKID: b'k' * 9}).provision(1, SKID).export()
    check(f'{v}: an import whose SKID resolves to a key of a length other than the restored kk (10 B for kk = 9) '
          '-> _Invalid_; the same length -> the restored State', None,
          [Blake2.imported(v, *img, sks={SKID: k}).st for k in (b'k' * 10, b'j' * 9)], [INVALID, READY])
res = []
for v in VARIANTS:
    ends = []
    for mig in (False, True):
        c = Blake2(v).provision().setst(ABSORB)
        c.exec(b'abc')
        c.setst(OUTPUT, 64)                       # the direct ending, bounded to 8 bytes
        if mig:
            c = Blake2.imported(v, *c.export())
        c.output(8)
        ends.append(c.export())
    q = Blake2(v).w // 8
    res.append((ends[0] == ends[1], ends[0][0][0] == SUCCESS, int.from_bytes(ends[0][1][8 * q:8 * q + 2], 'little')))
check('Success after a direct ending: the same Content with or without an export/import in _Hash_Output_, '
      'last_block_len = 0 in Position iii (<<KLE-hash-functions-MACs-XOFs>>)', None, res, [(True, True, 0)] * 2)

section('Interruption points of _Hash_Absorb_')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    bb, sks = b // 8, {SKID: b's' * 24}
    data = rbytes(5 * bb + 17)
    got, halts = [], []
    for c in (Blake2(v).provision(), Blake2(v, sks=sks).provision(1, SKID)):
        c.setst(ABSORB).exec(data[:3])
        c.exec(data[3:], halt=True)
        hs = []
        while c.klstart:
            hs.append(c.klstart)
            c.exec(data[3:], halt=True, klstart=c.klstart)
        halts.append(hs)
        got.append(c.setst(LAST, 0).setst(OUTPUT).output(nnmax))
    check(f'{v}: a kl.exec that starts at block_base = 24 halts at every offset at which block_base = b and resumes '
          'from it (Xs = 0 then ends the message): the digest, unkeyed and with a system key', None,
          (halts[0], got), ([bb - 3 + i * bb for i in range(5)], [oracle(v, data, nnmax), oracle(v, data, nnmax, b's' * 24)]))
    c = Blake2(v).provision().setst(ABSORB).exec(data[:3])
    check(f'{v}: a resumption at klstart = 1 while block_base is neither 0 nor b -> _Invalid_ (GR44)', None,
          c.exec(data[3:], klstart=1).st, INVALID)
    got = [Blake2(v).provision().setst(ABSORB).exec(data, klstart=5).setst(LAST, 0).setst(OUTPUT).output(nnmax),
           Blake2(v, sks=sks).provision(1, SKID).setst(ABSORB).exec(data, klstart=5).setst(LAST, 0).setst(OUTPUT)
           .output(nnmax)]
    check(f'{v}: a kl.exec issued at block_base = 0 resumes at any klstart, as in the generic Machine: the digest of '
          'the bytes from klstart on, unkeyed and with a system key', None, got,
          [oracle(v, data[5:], nnmax), oracle(v, data[5:], nnmax, b's' * 24)])

res = []
for v in VARIANTS:
    sk = b's' * 24
    new = lambda: Blake2(v, sks={SKID: sk}).provision(1, SKID).setst(ABSORB)
    c1 = new(); c1.exec(b'')                      # empty window: the key block stays pending
    c2 = new().setst(LAST, 8)                     # final piece not yet absorbed
    c3 = new(); c3.exec(rbytes(300), halt=True)   # halted in the first absorbing kl.exec
    c4 = new(); c4.exec(b'ab')
    res.append((c3.klstart != 0, c1.cumul_len, c2.cumul_len,
                [sk[:8] in c.export()[1][8:] for c in (new(), c1, c2, c3, c4)]))
check('system key: no Content holds a system-key byte, with the key block pending (after the kl.setst into '
      '_Hash_Absorb_, after an empty window, in _Hash_Absorb_Last_Block_ before its piece; cumul_len = 0), after a '
      'halt of the first absorbing kl.exec, or after 2 B (<<KLE-BLAKE2>>, GR68)', None, res,
      [(True, 0, 0, [False] * 5)] * 2)
res = []
for v in VARIANTS:
    nnmax, kkmax = PARAMS[v][4], PARAMS[v][5]
    mdh, img = Blake2(v).provision().export()
    o = 8 * (PARAMS[v][0] // 8) + 4
    def patched(pos, val):
        b = bytearray(img); b[o + 2 * pos:o + 2 * pos + 2] = val.to_bytes(2, 'little'); return bytes(b)
    res.append([Blake2.imported(v, mdh, im).st for im in
                (img, patched(0, 0), patched(0, nnmax + 1), patched(1, kkmax + 1))])
check('an import of nn = 0, nn = nn_max + 1 or kk = kk_max + 1 -> _Invalid_; the unmodified Content imports as '
      '_Ready_ (<<KLE-BLAKE2>>, MR13)', None, res, [[READY, INVALID, INVALID, INVALID]] * 2)
for v in VARIANTS:
    c = Blake2(v).provision().setst(ABSORB).exec(b'ab').setst(LAST, 0)
    st = c.exec(b'').st
    c2 = Blake2(v).provision().setst(ABSORB).exec(b'ab').setst(LAST, 8)
    st2 = c2.exec(b'c', klstart=1).st
    check(f'{v}: an empty-window kl.exec in _Hash_Absorb_Last_Block_ (KLLEN = 0 after Xs = 0; klstart = KLLEN/8 '
          'with Xs = 8) does not reach the Machine (GR44 item 2): the State is kept and the digest unchanged', None,
          (st, c.setst(OUTPUT).output(PARAMS[v][4]), st2),
          (LAST, oracle(v, b'ab', PARAMS[v][4]), LAST))

section('The generic sequence (<<Zkl-software.adoc#KLE-pseudocode-hash>>)')

class Port(HashPort):
    """<<Zkl-software.adoc#KLE-pseudocode-hash>> on a BLAKE2 locker (unkeyed, or with a system key)."""
    bitwise = False
    def __init__(p, v, sks=None, cl=None):
        p.v, p.sks = v, sks
        p.cl = cl or (Blake2(v, sks=sks).provision(1, SKID) if sks else Blake2(v).provision())
        p.b = p.cl.b
    st = property(lambda p: p.cl.st)
    klstart = property(lambda p: getattr(p.cl, 'klstart', 0))
    def setst(p, immed, form='A', xs=None):  # no kl.setst of BLAKE2 is native in Form C
        p.cl.invalid() if form == 'C' and not inert(p.cl.st) else p.cl.setst(immed, xs if form == 'B' else None)
    def exec_in(p, d, halt_at=None):
        k = getattr(p.cl, 'klstart', 0)
        p.cl.exec(d, halt=halt_at is not None, klstart=k)
        if p.cl.st == INVALID: return 'invalid'
        return 'interrupted' if p.cl.klstart else 'done'
    def exec_out(p, n, halt_at=None, prior=None):
        o = p.cl.output(n, klstart=getattr(p.cl, 'klstart', 0), prior=prior)
        p.cl.klstart = 0
        return ('invalid' if p.cl.st == INVALID else 'done'), o
    def export(p): return p.cl.export()
    def imported(p, img):
        c = Blake2.imported(p.v, *img, sks=p.sks)
        c.klstart = getattr(p.cl, 'klstart', 0)
        return Port(p.v, p.sks, c)

for v in VARIANTS:
    nnmax, bb = PARAMS[v][4], PARAMS[v][2] // 8
    for sks in (None, {SKID: b's' * 24}):
        key = sks[SKID] if sks else b''
        check_hash(f'{v}{" with a system key" if sks else ""}', lambda v=v, sks=sks: Port(v, sks),
                   lambda m, nb, o, v=v, key=key: oracle(v, m[:nb // 8], nnmax, key)[:o], hash_msgs(bb), nnmax)
for v in VARIANTS:
    nnmax = PARAMS[v][4]
    p = Port(v); p.setst(ABSORB); p.exec_in(b'abc'); p.setst(LAST, 'B', 0); p.setst(OUTPUT)
    p.cl.klstart = 5
    s1, o1 = p.exec_out(nnmax, prior=b'\xa5' * nnmax)
    q = Port(v); q.setst(ABSORB); q.exec_in(b'abc'); q.setst(LAST, 'B', 0); q.setst(OUTPUT)
    q.exec_out(8)
    q.cl.klstart = 1
    s2, o2 = q.exec_out(8, prior=b'\xa5' * 8)
    check(f'{v}, through the Port: a Form C kl.exec resumed at klstart = 5 with block_base = 0 writes '
          'digest[0:n-5] from byte 5, the bytes below kept (MR8); at klstart = 1 with block_base != 0 -> '
          '_Invalid_ (GR44 item 3), reported as such', None, (s1, o1, s2, q.st, o2),
          ('done', b'\xa5' * 5 + oracle(v, b'abc', nnmax)[:nnmax - 5], 'invalid', INVALID, b'\xa5' + bytes(7)))
res = []
for v in VARIANTS:
    c = Blake2(v).provision().setst(ABSORB).exec(b'ab')
    res.append(c.setst(LAST, 12).st)
check('a final piece of 12 bits (BLAKE2 is byte-oriented, Xs a multiple of 8) -> _Invalid_', None, res, [INVALID] * 2)

for v in VARIANTS:
    c = Blake2(v).provision().setst(ABSORB).exec(b'abc').setst(OUTPUT)
    e, st1 = c.output(8, klstart=8), c.st
    o1, st2 = c.output(8, klstart=1, prior=b'\xa5' * 8), c.st
    o2 = c.output(8, klstart=1, prior=b'\xa5' * 8)
    check(f'{v}: Form C in _Hash_Output_: klstart = KLLEN/8 is an empty window, the State is kept; klstart = 1 at '
          'block_base = 0 writes the digest from byte 1; klstart = 1 at block_base != 0 -> _Invalid_ (GR44 items 2, 3)', None,
          (e, st1, o1, st2, o2, c.st),
          (b'', OUTPUT, b'\xa5' + oracle(v, b'abc', PARAMS[v][4])[:7], OUTPUT, b'\xa5' + bytes(7), INVALID))

section('kl.derive of a shared secret into _Hash_Absorb_ (<<KLE-derive-endpoints>>)')


def kl_derive(c, secret, length, klstart=0):
    """A shared-secret field -> the _Hash_Absorb_ kl.exec input (GR34): the whole secret, with klstart = 0 and a
    length equal to that of the secret (GR32 item 5); uninterruptible (GR38).  Only the destination is modelled."""
    if c.st != ABSORB or klstart or length != len(secret):
        return c.invalid()                                # GR32 items 2 and 5: the destination
    return c.exec(secret)                                 # as a kl.exec: a pending system-key block first


SEC = bytes(range(0x40, 0x60))                            # a 32-byte shared secret
for v in VARIANTS:
    nnmax, bb, sks = PARAMS[v][4], PARAMS[v][2] // 8, {SKID: b'secret'}
    pres = (b'', b'abc', bytes(range(bb)))                # first input; after 3 B; after a full block, held
    got = [kl_derive(Blake2(v, sks=sks).provision(1, SKID).setst(ABSORB).exec(p), SEC, 32).exec(b'xyz')
           .setst(OUTPUT).output(nnmax) for p in pres]
    check(f'{v} with a system key: a shared secret derived as the first input, after 3 bytes and after a held full '
          'block, then "xyz": the keyed digest (the key block is compressed by the kl.derive that brings the first '
          'byte)', None, got, [oracle(v, p + SEC + b'xyz', nnmax, b'secret') for p in pres])
    res = [kl_derive(Blake2(v).provision().setst(ABSORB).exec(b'abc'), SEC, n, ks).st
           for n, ks in ((32, 1), (31, 0), (33, 0))]
    res.append(kl_derive(Blake2(v).provision().setst(ABSORB).setst(LAST, 0), SEC, 32).st)
    check(f'{v}: klstart = 1, a length of 31 or 33 bytes for a 32-byte secret (GR32 item 5), or a destination in '
          '_Hash_Absorb_Last_Block_ (GR32 item 2) -> _Invalid_', None, res, [INVALID] * 4)

section('kl.clear and kl.setst naming an Error State (<<KLE-instruction-setst>>, GR26, GR30)')
for v in VARIANTS:
    got = []
    for imm in (UNCONF, KL_STATE_OUT_OF_MEMORY):
        c = Blake2(v).provision().setst(ABSORB).exec(b'abc').setst(imm)
        got += [c.st, c.setst(READY).exec(b'x').restrict(1).st]
    c = Blake2(v).provision().setst(ABSORB)
    got += [raises(c.setst, 54), raises(c.setst, 55), c.st]
    check(f'{v}: kl.clear in _Hash_Absorb_ -> _Unconfigured_, a kl.setst naming _Out_of_Memory_ -> that State; '
          'then a kl.setst, a kl.exec and a kl.restrictl change nothing; a reserved 54 or 55 raises '
          'illegal-instruction (GR18)', None, got,
          [UNCONF, UNCONF, KL_STATE_OUT_OF_MEMORY, KL_STATE_OUT_OF_MEMORY, True, True, ABSORB])

section('Negative controls')
for v in VARIANTS:
    w, r, b, n, nnmax, kkmax, R = PARAMS[v]
    bb, key, sks = b // 8, b'secret', {SKID: b'secret'}
    data = bytes(range(256))[:2 * bb]
    control(f'{v}: compressing the final full block in _Hash_Absorb_ (no hold-back) leaves no block for F(true): no digest',
            run(v, data, bad=('no-hold',))[0] != oracle(v, data, nnmax))
    control(f'{v}: a system-key block compressed on leaving _Ready_ leaves no final block for the empty message: '
            'no digest',
            run(v, b'', c=Blake2(v, sks=sks, bad=('eager-key',)).provision(1, SKID))[0] != oracle(v, b'', nnmax, key))
    control(f'{v}: a caller key absorbed without kk in the parameter block gives a wrong digest',
            run(v, b'msg', None, key, nokk=True)[0] != oracle(v, b'msg', nnmax, key))
    control(f'{v}: a truncated full-length digest is not the 20-byte digest',
            oracle(v, b'abc', nnmax)[:20] != run(v, b'abc', 20)[0])
info('hashlib.blake2b/blake2s serve only as a reference oracle; the Machine runs the from-scratch core above.')

done()
