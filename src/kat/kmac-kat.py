#!/usr/bin/env python3
"""KAT for the KLEE KMAC Machines (<<KLEE-KMAC>> on <<KLEE-SHA-3>>) against the NIST SP 800-185 samples.
Keccak-f[1600] is written here and anchored on FIPS 202; hashlib is only a labelled oracle."""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, mdh_pack, mdh_unpack, ERROR_STATES, KL_CFG_PROVISIONING,
                    KL_STATE_UNCONFIGURED as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_HASH_ABSORB as ABSORB, KL_STATE_HASH_OUTPUT as OUTPUT,
                    KL_STATE_SUCCESS as SUCCESS, KL_STATE_INVALID as INVALID,
                    section, check, control, info, spec_note, done)

# ------------------------------------------------------------------ Keccak-f[1600]
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
RHO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1


def rol(v, s):
    return ((v << s) | (v >> (64 - s))) & M64 if s else v


def keccak(st):
    """KECCAK-p[1600,24] on a KLEE value (lane x + 5y at bits [64(x+5y)+63 : 64(x+5y)])."""
    A = [(st >> 64 * i) & M64 for i in range(25)]
    for rc in RC:
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        A = [A[i] ^ C[(i - 1) % 5] ^ rol(C[(i + 1) % 5], 1) for i in range(25)]
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = rol(A[x + 5 * y], RHO[x][y])
        A = [B[i] ^ (~B[(i + 1) % 5 + i - i % 5] & B[(i + 2) % 5 + i - i % 5]) for i in range(25)]
        A[0] ^= rc
    return sum(a << 64 * i for i, a in enumerate(A))


# ------------------------------------------------------------------ SP 800-185 reference
def ref_sponge(rate, data, suffix, n):
    """Byte-string sponge: data || suffix bits || pad10*1, squeezed to n bytes."""
    m = 8 * len(data)
    plen = ((m + len(suffix) + 1) // rate + 1) * rate
    P = b2v(data) | (sum(bit << j for j, bit in enumerate(suffix)) | 1 << len(suffix)) << m
    P |= 1 << (plen - 1)
    st, out = 0, b''
    for off in range(0, plen, rate):
        st = keccak(st ^ sl(P, off + rate - 1, off))
    while len(out) < n:
        out += v2b(sl(st, rate - 1, 0), rate // 8)
        st = keccak(st)
    return out[:n]


def left_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, 'big')


def right_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, 'big') + bytes([n])


def encode_string(s):
    return left_encode(8 * len(s)) + s


def bytepad(x, w):
    z = left_encode(w) + x
    return z + bytes(-len(z) % w)


RATE = {128: 168, 256: 136}


def trunc_bits(data, nbits):
    """The first nbits of data in ceil(nbits/8) bytes, the unused bits of the last byte zero."""
    n = (nbits + 7) // 8
    return v2b(b2v(data[:n]) & ((1 << nbits) - 1), n)


def ref_kmac(sec, K, X, L, S=b'', xof=False, n=None):
    w = RATE[sec]
    msg = (bytepad(encode_string(b'KMAC') + encode_string(S), w) + bytepad(encode_string(K), w)
           + X + right_encode(0 if xof else L))
    if xof:
        return ref_sponge(8 * w, msg, (0, 0), n)
    return trunc_bits(ref_sponge(8 * w, msg, (0, 0), (L + 7) // 8), L)


# ------------------------------------------------------------------ embedded vectors
KEY = bytes.fromhex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f')
DATA4 = bytes.fromhex('00010203')
DATA200 = bytes(range(200))              # 00 01 ... C7
TAG = b'My Tagged Application'

# NIST CSRC KMAC_samples.pdf / KMACXOF_samples.pdf: (label, sec, xof, K, X, S, L_bits, expected_hex)
SAMPLES = [
    ('KMAC128 sample #1', 128, False, KEY, DATA4, b'', 256,
     'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e'),
    ('KMAC128 sample #2', 128, False, KEY, DATA4, TAG, 256,
     '3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5'),
    ('KMAC128 sample #3', 128, False, KEY, DATA200, TAG, 256,
     '1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230'),
    ('KMAC256 sample #4', 256, False, KEY, DATA4, TAG, 512,
     '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7'
     'f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd'),
    ('KMAC256 sample #5', 256, False, KEY, DATA200, b'', 512,
     '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691'
     '589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69'),
    ('KMAC256 sample #6', 256, False, KEY, DATA200, TAG, 512,
     'b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9'
     '70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965'),
    ('KMACXOF128 sample #1', 128, True, KEY, DATA4, b'', 256,
     'cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35'),
    ('KMACXOF128 sample #2', 128, True, KEY, DATA4, TAG, 256,
     '31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c'),
    ('KMACXOF128 sample #3', 128, True, KEY, DATA200, TAG, 256,
     '47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f'),
    ('KMACXOF256 sample #4', 256, True, KEY, DATA4, TAG, 512,
     '1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa9'
     '6faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b'),
    ('KMACXOF256 sample #5', 256, True, KEY, DATA200, b'', 512,
     'ff7b171f1e8a2b24683eed37830ee797538ba8dc563f6da1e667391a75edc02c'
     'a633079f81ce12a25f45615ec89972031d18337331d24ceb8f8ca8e6a19fd98b'),
    ('KMACXOF256 sample #6', 256, True, KEY, DATA200, TAG, 512,
     'd5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce'
     '67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d'),
]
WANT = [bytes.fromhex(s[7]) for s in SAMPLES]

# FIPS 202 anchors for the Keccak core ("" message): suffix, rate, digest
FIPS202_EMPTY = {
    'SHA3-256': ((0, 1), 1088,
                 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'),
    'SHAKE128': ((1, 1, 1, 1), 1344,
                 '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'),
    'SHAKE256': ((1, 1, 1, 1), 1088,
                 '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'),
}

# ------------------------------------------------------------------ KLEE model
MODE = {'KMAC128': 10, 'KMACXOF128': 11, 'KMAC256': 12, 'KMACXOF256': 13}   # Type 6
NAME = {m: n for n, m in MODE.items()}


def kname(sec, xof):
    return f"KMAC{'XOF' if xof else ''}{sec}"


def pack(fields):
    v = off = 0
    for x, w in fields:
        v, off = v | x << off, off + w
    return v


def scc_len(b):                          # Serialized Content, zero-padded to 128 bits
    return -(-(1696 + 2 * b) // 128) * 16


def kl_size(state, b):                   # <<KLEE-instruction-size>>, AuxDataLen = 0
    if state in (UNCONF, KL_CFG_PROVISIONING):
        return 16 + 2 * b // 8
    return 16 if state in ERROR_STATES else 32 + scc_len(b)


def provision_blocks(sec, K, S):
    w = RATE[sec]
    cb, kb = bytepad(encode_string(b'KMAC') + encode_string(S), w), bytepad(encode_string(K), w)
    if len(cb) != w or len(kb) != w:
        raise ValueError('K or S exceeds one rate block')
    return cb, kb


def make_pi(sec, xof, K, S):
    cb, kb = provision_blocks(sec, K, S)
    return v2b(mdh_pack(Machine=0x60 | MODE[kname(sec, xof)], State=UNCONF), 16) + cb + kb


class Hart:
    klstart = 0


class Kmac:
    """A locker holding a KMAC CC; `bad` selects negative-control deviations."""

    def __init__(self, hart, bad=()):
        self.hart, self.bad, self.st, self.b = hart, set(bad), UNCONF, 0
        self._clear()

    def _machine(self, machine):
        self.machine, self.name = machine, NAME[machine & 0xF]
        self.sec, self.xof = int(self.name[-3:]), 'XOF' in self.name
        self.b = self.t = 8 * RATE[self.sec]                             # t = b
        self.D = (1, 1, 1, 1) if 'suffix' in self.bad else (0, 0)       # cSHAKE suffix

    def _clear(self):                                                    # SGR10
        self.state = self.block_base = self.cb = self.kb = self.L = self.out_bits = 0

    def invalidate(self):
        self.st = INVALID
        self._clear()

    def provision(self, pi):
        f = mdh_unpack(b2v(pi[:16]))
        self._machine(f['Machine'])
        w = self.b // 8
        assert f['State'] == UNCONF and len(pi) == 16 + 2 * w
        self.cb, self.kb = b2v(pi[16:16 + w]), b2v(pi[16 + w:])
        self.ready()

    def fields(self):
        return [(self.state, 1600), (self.block_base, 16), (0, 48), (self.cb, self.b),
                (self.kb, self.b), (self.L, 32)]

    def export(self, at=False):
        """(MDH, Serialized Content); at=True is the negative control that orders with `@`."""
        v = cat(*self.fields()) if at else pack(self.fields())
        return mdh_pack(Machine=self.machine, State=self.st), v2b(v, scc_len(self.b))

    def import_(self, mdh, content, out_bits=None):
        f = mdh_unpack(mdh)
        self._machine(f['Machine'])
        self.st, v = f['State'], b2v(content)
        vals = []
        for _, w in self.fields():
            vals.append(v & ((1 << w) - 1))
            v >>= w
        self.state, self.block_base, _, self.cb, self.kb, self.L = vals
        self.out_bits = self.block_base if out_bits is None else out_bits   # no field records it
        if self.block_base >= self.b:        # inconsistent image (only the negative control)
            self.invalidate()
        return self

    def ready(self):
        self.st, self.block_base = READY, 0
        self.state = keccak(keccak(self.cb) ^ self.kb)

    def setst(self, immed, form='A', aux=None):
        if immed == UNCONF:
            return self.__init__(self.hart, self.bad)
        if self.st in ERROR_STATES:                                      # SGR16
            return
        if immed == READY:                                               # SGR8
            return self.ready()
        if immed == ABSORB and self.st == READY and form == 'A':         # no same-State (process_VLI)
            self.st = ABSORB
            return
        if immed == OUTPUT and self.st == ABSORB and form == ('A' if self.xof else 'B'):
            if self.xof or aux:
                assert aux is None or aux < 1 << 32
                self.L = aux or 0
                return self._to_output()
        self.invalidate()

    def _to_output(self):
        enc = (left_encode if 'left_encode' in self.bad else right_encode)(self.L)
        self._vli(b2v(enc), 8 * len(enc), 0)
        room, D = self.b - self.block_base, self.D                       # <<KLEE-SHA-3>> padding
        n = room if room >= len(D) + 2 else room + self.b
        S = pack([(bit, 1) for bit in D]) | 1 << len(D) | 1 << (n - 1)
        self.pad_case = 1 if n == room else 2
        self.state = keccak(self.state ^ (S & ((1 << room) - 1)) << self.block_base)
        if n > room:
            self.state = keccak(self.state ^ S >> room)
        self.st, self.block_base, self.out_bits = OUTPUT, 0, 0

    def _end(self, status, out=None):
        if out is not None and status in ('invalid', 'noop'):             # SGR16
            k = min(self.hart.klstart, len(out))
            out[k:] = bytes(len(out) - k)
        self.hart.klstart = 0
        return status

    def exec(self, inp=None, out=None, sew=None, halt=None, literal=False):
        """kl.exec: Form B with `inp`, Form C with `out` (a bytearray); `halt` = byte count after
        which to halt at the next interruption point; `sew` = vector element width."""
        if self.st in ERROR_STATES:
            return self._end('noop', out)
        if self.st == ABSORB and inp is not None and out is None and (sew or 32) >= 32:  # MGR1, MGR2
            p, top = self.hart.klstart, len(inp)
            if not (p in (0, top) or (p < top and self.block_base == 0)):
                self.invalidate()
                return self._end('invalid')
            if p == top:
                return self._end('noop')
            st = self._vli(b2v(inp), 8 * top, 8 * p, halt, literal)
            return st if st == 'interrupted' else self._end(st)
        if self.st == OUTPUT and inp is None and out is not None:
            return self._squeeze(out, halt)
        self.invalidate()                                                # MGR1, SGR2, SGR5
        return self._end('invalid', out)

    def _vli(self, X, n, ib, halt=None, literal=False):                 # <<KLEE-process-VLI>>
        while ib < n:
            amt = min(n - ib, self.b - self.block_base)
            self.state ^= sl(X, ib + amt - 1, ib) << self.block_base
            ib, self.block_base = ib + amt, self.block_base + amt
            if self.block_base == self.b:
                self.state, self.block_base = keccak(self.state), 0
            if halt is not None and ib // 8 >= halt and ib < n:
                self.hart.klstart = ib if literal else ib // 8           # klstart <- input_base / 8
                return 'interrupted'
        return 'done'

    def _squeeze(self, out, halt):
        p, top = self.hart.klstart, len(out)
        if p >= top or (p and self.block_base):                          # output-only: no operation
            return self._end('done')
        limit = (None if self.xof else 8 * -(-self.L // 8) if 'raw_last_byte' in self.bad
                 else self.L)
        OUT, ob = b2v(out), 8 * p
        while ob < 8 * top:
            amt = min(8 * top - ob, self.t - self.block_base)
            if limit is not None:
                amt = min(amt, limit - self.out_bits)
            chunk = sl(self.state, self.block_base + amt - 1, self.block_base)
            OUT = OUT & ~(((1 << amt) - 1) << ob) | chunk << ob
            ob, self.block_base, self.out_bits = ob + amt, self.block_base + amt, self.out_bits + amt
            if self.out_bits == limit:                                   # exactly L bits, then MGR6
                out[:] = v2b(OUT & ((1 << ob) - 1), top)
                self.st = SUCCESS
                return self._end('success')
            if self.block_base == self.t:
                self.state, self.block_base = keccak(self.state), 0     # update()
                if halt is not None and ob // 8 >= halt and ob < 8 * top:
                    out[:] = v2b(OUT, top)
                    self.hart.klstart = ob // 8
                    return 'interrupted'
        out[:] = v2b(OUT, top)
        return self._end('done')


def derive(hart, dst, src, length):
    """kl.derive from the kl.exec output of `src` into the kl.exec input of `dst` (DER6, DER8)."""
    if src.st not in ERROR_STATES and dst.st not in ERROR_STATES:
        bad = [c for c, s in ((src, OUTPUT), (dst, ABSORB)) if c.st != s]   # DER1 checks 1, 3
        for c in bad:
            c.invalidate()
        if not bad and length:
            buf = bytearray(length)
            src.exec(out=buf)
            dst.exec(inp=bytes(buf))
    hart.klstart = 0


# ------------------------------------------------------------------ drivers
def locker(sec, xof=False, S=TAG, hart=None, bad=()):
    c = Kmac(hart or Hart(), bad)
    c.provision(make_pi(sec, xof, KEY, S))
    return c


def to_output(c, L):
    c.setst(OUTPUT, 'A') if c.xof else c.setst(OUTPUT, 'B', L)


def absorbing(sec, X=b'', xof=False, S=TAG, hart=None):
    c = locker(sec, xof, S, hart)
    c.setst(ABSORB)
    if X:
        assert c.exec(inp=X) == 'done'
    return c


def squeezing(sec, X, L, xof=False, S=TAG, hart=None):
    c = absorbing(sec, X, xof, S, hart)
    to_output(c, L)
    return c


def kl_kmac(sec, X, L, S=b'', xof=False, n=None, chunks=None, halt=None, literal=False, bad=()):
    c = locker(sec, xof, S, bad=bad)
    c.setst(ABSORB)
    for ch in chunks or [X]:
        if c.exec(inp=ch, halt=halt, literal=literal) == 'interrupted':
            c.exec(inp=ch)
    to_output(c, L)
    out = bytearray((L + 7) // 8 if n is None else n)
    c.exec(out=out)
    return bytes(out), c


def squeeze(c, *sizes, fill=0):
    outs = []
    for n in sizes:
        o = bytearray([fill] * n)
        outs.append((c.exec(out=o), o))
    return outs


# ------------------------------------------------------------------ checks
section('Keccak core (FIPS 202) and SP 800-185 encodings')
for nm, (D, rate, want) in FIPS202_EMPTY.items():
    check(f'reference sponge {nm}("")', True, ref_sponge(rate, b'', D, 32).hex(), want)
check('[oracle] hashlib SHA3-256/SHAKE128("") == embedded', True,
      (hashlib.sha3_256(b'').hexdigest(), hashlib.shake_128(b'').hexdigest(32)),
      (FIPS202_EMPTY['SHA3-256'][2], FIPS202_EMPTY['SHAKE128'][2]))
check('left_encode / right_encode / encode_string', True,
      [left_encode(0).hex(), left_encode(168).hex(), left_encode(256).hex(), right_encode(0).hex(),
       right_encode(256).hex(), right_encode(512).hex(), encode_string(b'KMAC').hex()],
      ['0100', '01a8', '020100', '0001', '010002', '020002', '01204b4d4143'])
check('bytepad(encode_string(K), 168) is one rate block', len(bytepad(encode_string(KEY), 168)) == 168)

section('SP 800-185 reference and KLEE model vs the official samples')
for (label, sec, xof, K, X, S, L, _), want in zip(SAMPLES, WANT):
    check(f'reference   {label}', True, ref_kmac(sec, K, X, L, S, xof, len(want)), want)
    got, c = kl_kmac(sec, X, L, S, xof, len(want))
    check(f'KLEE model  {label}: output, then {"stays in _Hash_Output_" if xof else "_Success_"}',
          True, (got, c.st), (want, OUTPUT if xof else SUCCESS))

section('Parameters and _Machine_ encodings (<<KLEE-exec-encodings>>)')
for nm, sec, c_ in (('KMAC128', 128, 256), ('KMACXOF128', 128, 256), ('KMAC256', 256, 512),
                    ('KMACXOF256', 256, 512)):
    c = locker(sec, 'XOF' in nm, b'')
    check(f'{nm}: Type 6 Mode {MODE[nm]}, c = {c_}, b = t = 1600 - c = 8 * {RATE[sec]}, _Ready_',
          True, (c.name, c.b, c.t, c.st), (nm, 1600 - c_, 8 * RATE[sec], READY))

section('Absorption through process_VLI (granularity 32 bits)')
got, _ = kl_kmac(128, DATA200, 256, TAG, n=32,
                 chunks=[DATA200[:68], DATA200[68:72], DATA200[72:172], DATA200[172:]])
check('KMAC128 #3 in 68+4+100+28 B transfers (partial-block edges)', True, got, WANT[2])
got, _ = kl_kmac(256, DATA200, 512, TAG, n=64,
                 chunks=[DATA200[:136], DATA200[136:140], DATA200[140:]])
check('KMAC256 #6 in 136+4+60 B transfers (block filled at a transfer edge)', True, got, WANT[5])
got, _ = kl_kmac(128, DATA200, 256, TAG, xof=True, n=32,
                 chunks=[DATA200[i:i + 8] for i in range(0, 200, 8)])
check('KMACXOF128 #3 in 25 transfers of 8 B', True, got, WANT[8])
c = absorbing(128)
check('MGR2: SEW = 8 < granularity -> _Invalid_', True, (c.exec(inp=DATA200[:8], sew=8), c.st),
      ('invalid', INVALID))

section('Interrupted absorption (klstart <- input_base / 8)')
h = Hart()
c = absorbing(128, hart=h)
st = c.exec(inp=DATA200, halt=100)
check('KMAC128 halts at the first interruption point after byte 100: klstart = 168', True,
      (st, h.klstart), ('interrupted', 168))
check('resumed exec retires with klstart = 0', True, (c.exec(inp=DATA200), h.klstart), ('done', 0))
to_output(c, 256)
check('KMAC128 #3 after interrupt/resume', True, bytes(squeeze(c, 32)[0][1]), WANT[2])
h = Hart()
c = absorbing(256, DATA200[:40], hart=h)
st = c.exec(inp=DATA200[40:], halt=1)
mdh, img, ks = *c.export(), h.klstart
c.setst(UNCONF)
c2 = Kmac(h).import_(mdh, img)
h.klstart = ks
c2.exec(inp=DATA200[40:])
to_output(c2, 512)
check('KMAC256: halt at klstart = 96 (block edge), export, clear, import, resume == #6', True,
      (st, ks, bytes(squeeze(c2, 64)[0][1])), ('interrupted', 96, WANT[5]))
h = Hart()
c = absorbing(128, DATA4, hart=h)
h.klstart = 100
st = c.exec(inp=DATA200)
check('input klstart = 100 with block_base = 32 -> _Invalid_, Content cleared, klstart = 0', True,
      (st, c.st, c.state, c.kb, h.klstart), ('invalid', INVALID, 0, 0, 0))

section('right_encode(L) and the <<KLEE-SHA-3>> padding on entering _Hash_Output_')
c = absorbing(128, DATA200)
bb = c.block_base
to_output(c, 256)
check('block_base = 32 B after 200 B; right_encode(256) then |S| = b - block_base (clause 1)', True,
      (bb, c.pad_case), (256, 1))
for sec in (128, 256):
    got, c = kl_kmac(sec, DATA4, 256, TAG, xof=True, n=32)
    check(f'KMACXOF{sec} absorbs right_encode(0) (L = {c.L})', True, got,
          ref_kmac(sec, KEY, DATA4, 0, TAG, True, 32))

section('Output length: exactly L bits, the last byte zero-padded')
a, b_ = ref_kmac(128, KEY, DATA4, 256, TAG), ref_kmac(128, KEY, DATA4, 512, TAG)
got, c = kl_kmac(128, DATA4, 512, TAG)
check('KMAC128 L=512 is not an extension of L=256; 64 B then _Success_', True,
      (b_[:32] != a, got, c.st), (True, b_, SUCCESS))
for L in (255, 250, 257, 1000, 1001):
    got, c = kl_kmac(128, DATA4, L, TAG)
    check(f'KMAC128 L={L}: ceil(L/8) B, last byte zero-padded, _Success_', True, (got, c.st),
          (ref_kmac(128, KEY, DATA4, L, TAG), SUCCESS))
spec_note('<<KLEE-KMAC>>: "the last byte may be zero-padded in its significant bits" contradicts '
          '"exactly L bits ... the last one zero-padded"; the harness follows the latter')
c = squeezing(128, DATA4, 250)
(st, o), = squeeze(c, 40, fill=0xEE)
check('KMAC128 L=250 into 40 B: _Success_, OUTPUT bits [319:250] cleared (MGR6)', True,
      (st, bytes(o[:32]), o[32:], o[31] >> 2),
      ('success', ref_kmac(128, KEY, DATA4, 250, TAG), bytearray(8), 0))
c = squeezing(256, DATA4, 512)
(s1, d1), (s2, d2) = squeeze(c, 20, 44)
check('KMAC256 #4 split 20+44 B: _Hash_Output_ after 20, _Success_ on byte 64', True,
      (s1, s2, c.st, bytes(d1 + d2)), ('done', 'success', SUCCESS, WANT[3]))
c = squeezing(256, DATA4, 512)
(st, o), = squeeze(c, 200, fill=0xEE)
check('KMAC256 #4 into 200 B: _Success_, bytes [64, 200) cleared', True, (st, bytes(o)),
      ('success', WANT[3] + bytes(136)))
got, c = kl_kmac(256, DATA200, 4096, TAG)
check('KMAC256 L=4096 (L > t: 4 applications of update()) then _Success_', True, (got, c.st),
      (ref_kmac(256, KEY, DATA200, 4096, TAG), SUCCESS))
h = Hart()
c = squeezing(256, DATA200, 4097, hart=h)
o1, o2 = bytearray(b'\xee' * 300), bytearray(b'\xee' * 300)
sts = (c.exec(out=o1, halt=200), h.klstart, c.exec(out=o1), c.exec(out=o2))
want = ref_kmac(256, KEY, DATA200, 4097, TAG)
check('KMAC256 L=4097 in two 300-B execs, the first halted at klstart = 272 and resumed', True,
      (sts, c.st, bytes(o1 + o2)), (('interrupted', 272, 'done', 'success'), SUCCESS,
                                   want + bytes(600 - len(want))))
ca, cb = squeezing(256, DATA200, 4096), squeezing(256, DATA200, 4096)
squeeze(ca, 137)
squeeze(cb, 273)
same = ca.export()[1][200:] == cb.export()[1][200:]
check('two KMAC256 L=4096 exports 1088 bits apart differ only in `state`', same)
spec_note('<<KLEE-KMAC>>: neither Internal State nor Serialized Content counts the output bits '
          'made available, so L > t cannot stop at L after an import; the harness carries it out of band')

section('KMACXOF: unlimited output (<<KLEE-hash-functions-MACs-XOFs>>)')
want = ref_kmac(128, KEY, DATA200, 0, TAG, True, 600)
c = squeezing(128, DATA200, 0, xof=True)
outs = squeeze(c, 32, 100, 168, 300)
check('KMACXOF128 #3: 600 B across execs of 32+100+168+300 B, still _Hash_Output_', True,
      (want[:32], b''.join(bytes(o) for _, o in outs), c.st), (WANT[8], want, OUTPUT))
h = Hart()
c = squeezing(128, DATA200, 0, xof=True, hart=h)
o = bytearray(b'\xee' * 400)
st1, ks = c.exec(out=o, halt=1), h.klstart
unwritten = bytes(o[168:])
st2 = c.exec(out=o)
check('KMACXOF128 squeeze halted at klstart = 168 (bytes beyond unwritten), resumed == reference',
      True, (st1, ks, unwritten, st2, h.klstart, bytes(o)),
      ('interrupted', 168, b'\xee' * 232, 'done', 0, want[:400]))
spec_note('<<KLEE-KMAC>> and <<KLEE-Ascon-XOF128>>: "producing `XLLEN` for each `ace.exec` call" '
          'should read KLLEN and kl.exec')

section('States, transitions and expected Forms')
for label, c, act in (
        ('KMAC128 Form B kl.setst with L = 0', absorbing(128, DATA4), lambda c: c.setst(OUTPUT, 'B', 0)),
        ('KMAC128 Form A kl.setst to _Hash_Output_', absorbing(128, DATA4), lambda c: c.setst(OUTPUT)),
        ('KMACXOF256 Form B kl.setst to _Hash_Output_', absorbing(256, DATA4, True),
         lambda c: c.setst(OUTPUT, 'B', 512)),
        ('kl.exec in _Ready_ (SGR2)', locker(128), lambda c: c.exec(inp=DATA4)),
        ('Form B kl.setst into _Hash_Absorb_', locker(128), lambda c: c.setst(ABSORB, 'B', 32)),
        ('same-State kl.setst in _Hash_Absorb_ (<<KLEE-process-VLI>>)', absorbing(128, DATA4),
         lambda c: c.setst(ABSORB)),
        ('Form B kl.exec in _Hash_Output_ (MGR1)', squeezing(128, DATA4, 256),
         lambda c: c.exec(inp=DATA4))):
    act(c)
    check(f'{label} -> _Invalid_', True, c.st, INVALID)
c = squeezing(128, DATA4, 256)
squeeze(c, 32)
(st, o), = squeeze(c, 32, fill=0xEE)
check('kl.exec in _Success_ -> _Invalid_, output window zeroed (SGR5, SGR16)', True,
      (st, c.st, bytes(o)), ('invalid', INVALID, bytes(32)))
c = squeezing(128, DATA200, 256)
squeeze(c, 32)
for s in (READY, ABSORB):
    c.setst(s)
c.exec(inp=DATA4)
to_output(c, 256)
check('_Success_ -> _Ready_ re-absorbs cshake_block and key_block (#2 after #3)', True,
      bytes(squeeze(c, 32)[0][1]), WANT[1])
c = absorbing(256, DATA200[:50], xof=True, S=b'')
for s in (READY, ABSORB):
    c.setst(s)
c.exec(inp=DATA200)
to_output(c, 0)
check('_Hash_Absorb_ -> _Ready_ restarts KMACXOF256 (#5)', True, bytes(squeeze(c, 64)[0][1]), WANT[10])
info('Form B L >= 2^32 (XLEN-bit operand, 32-bit field): truncation or rejection unstated; not exercised')
info('_KeyType_ = 1: <<KLEE-KMAC>> gives no SKID layout for its key blocks; not exercised')

section('Provisioning Input and Serialized Content')
for sec, kmax, smax in ((128, 163, 157), (256, 131, 125)):
    fits = [len(x) for x in provision_blocks(sec, bytes(kmax), bytes(smax))]
    over = []
    for K, S in ((bytes(kmax + 1), b''), (bytes(16), bytes(smax + 1))):
        try:
            provision_blocks(sec, K, S)
            over.append(False)
        except ValueError:
            over.append(True)
    check(f'KMAC{sec}: max |K| = {kmax}, |S| = {smax} fit one rate block, one more does not', True,
          (fits, over), ([RATE[sec]] * 2, [True, True]))
for sec, pi_len, c1_len in ((128, 352, 560), (256, 288, 496)):
    b, w = 8 * RATE[sec], RATE[sec]
    pi, (cbk, kbk) = make_pi(sec, False, KEY, TAG), provision_blocks(sec, KEY, TAG)
    check(f'KMAC{sec} PI = MDH, cshake_block, key_block ({pi_len} B = kl.size); SCC Content1 = '
          f'{c1_len} B, kl.size = {32 + c1_len}', True,
          (len(pi), kl_size(UNCONF, b), pi[16:16 + w], pi[16 + w:], scc_len(b), kl_size(READY, b),
           kl_size(INVALID, b)),
          (pi_len, pi_len, cbk, kbk, c1_len, 32 + c1_len, 16))
    c = squeezing(sec, DATA4, 1234)
    squeeze(c, 8)
    ct = c.export()[1]
    check(f'KMAC{sec} Content1: state, block_base = 64, 48-bit padding, cshake_block, key_block, '
          f'L = 1234, zero padding', True,
          (ct[:200], ct[200:202], ct[202:208], ct[208:208 + w], ct[208 + w:208 + 2 * w],
           ct[208 + 2 * w:212 + 2 * w], ct[212 + 2 * w:]),
          (v2b(c.state, 200), v2b(64, 2), bytes(6), cbk, kbk, v2b(1234, 4), bytes(c1_len - 212 - 2 * w)))
xof256 = ref_kmac(256, KEY, DATA200, 0, TAG, True, 300)
for label, sec, xof, n_abs, L, n_out, want in (
        ('KMAC128 in _Ready_', 128, False, None, None, None, WANT[2]),
        ('KMAC128 in _Hash_Absorb_, block_base 800', 128, False, 100, None, None, WANT[2]),
        ('KMAC256 in _Hash_Output_, block_base 160', 256, False, 200, 512, 20, WANT[5]),
        ('KMACXOF256 in _Hash_Output_, block_base 0', 256, True, 200, 0, 136, xof256)):
    c, head = locker(sec, xof), b''
    if n_abs is not None:
        c.setst(ABSORB)
        c.exec(inp=DATA200[:n_abs])
    if n_out is not None:
        to_output(c, L)
        head = bytes(squeeze(c, n_out)[0][1])
    c2 = Kmac(Hart()).import_(*c.export())
    if n_abs is None:
        c2.setst(ABSORB)
    if n_out is None:
        c2.exec(inp=DATA200[n_abs or 0:])
        to_output(c2, 256)
    check(f'export/import round trip, {label}', True,
          head + bytes(squeeze(c2, len(want) - len(head))[0][1]), want)
c = squeezing(256, DATA200, 4096)
(_, o1), = squeeze(c, 300)
c2 = Kmac(Hart()).import_(*c.export(), out_bits=c.out_bits)
(st, o2), = squeeze(c2, 212)
check('round trip, KMAC256 L = 4096 after 2 update()s (counter out of band), then _Success_', True,
      (bytes(o1 + o2), st, c2.st), (ref_kmac(256, KEY, DATA200, 4096, TAG), 'success', SUCCESS))

section('kl.derive between kl.exec endpoints (<<KLEE-derive-endpoints>>, DER6)')
info('KMAC is taken to be a MAC of the hash/MAC/XOF row of <<KLEE-derive-endpoints>>, which does not name it')
h = Hart()
src, dst = squeezing(128, DATA4, 0, xof=True, hart=h), absorbing(128, DATA4, hart=h)
derive(h, dst, src, 32)
stream = ref_kmac(128, KEY, DATA4, 0, TAG, True, 64)
dst.exec(inp=DATA4)
to_output(dst, 256)
check('KMACXOF128 output (32 B) -> open KMAC128 _Hash_Absorb_, continued; source continues', True,
      (h.klstart, bytes(squeeze(dst, 32)[0][1]), bytes(squeeze(src, 32)[0][1])),
      (0, ref_kmac(128, KEY, DATA4 + stream[:32] + DATA4, 256, TAG), stream[32:]))
src, dst = squeezing(256, DATA4, 512, hart=h), absorbing(256, xof=True, S=b'', hart=h)
derive(h, dst, src, 64)
to_output(dst, 0)
check('whole KMAC256 output (L = 512) -> KMACXOF256; source in _Success_', True,
      (src.st, bytes(squeeze(dst, 64)[0][1])),
      (SUCCESS, ref_kmac(256, KEY, WANT[3], 0, b'', True, 64)))
derive(h, absorbing(128, hart=h), src, 16)
check('source in _Success_ (no kl.exec output left, SGR5) -> source _Invalid_', True, src.st, INVALID)
src, dst = squeezing(128, DATA4, 0, xof=True, hart=h), squeezing(128, DATA4, 256, hart=h)
snap = (src.st, src.state, src.block_base)
derive(h, dst, src, 16)
check('destination in _Hash_Output_ -> destination _Invalid_, nothing taken from the source', True,
      (dst.st, (src.st, src.state, src.block_base)), (INVALID, snap))
src, dst = squeezing(128, DATA4, 0, xof=True, hart=h), absorbing(128, DATA4, hart=h)
snap = (src.state, src.block_base, dst.state, dst.block_base)
derive(h, dst, src, 0)
check('length = 0 changes no state (DER8)', True,
      (src.state, src.block_base, dst.state, dst.block_base), snap)

section('Negative controls')
control('left_encode(L) in place of right_encode(L) (#2, #6)',
        kl_kmac(128, DATA4, 256, TAG, bad={'left_encode'})[0] != WANT[1]
        and kl_kmac(256, DATA200, 512, TAG, bad={'left_encode'})[0] != WANT[5])
control('SHAKE suffix 1111 in place of the cSHAKE 00',
        kl_kmac(128, DATA4, 256, TAG, bad={'suffix'})[0] != WANT[1])
control('klstart written as a bit count, consumed as bytes',
        kl_kmac(128, DATA200, 256, TAG, halt=100, literal=True)[0] != WANT[2])
control('ceil(L/8) raw bytes instead of exactly L bits (L = 250, 1001)',
        any(kl_kmac(128, DATA4, L, TAG, bad={'raw_last_byte'})[0] != ref_kmac(128, KEY, DATA4, L, TAG)
            for L in (250, 1001)))
c = absorbing(128, DATA200[:100])
c2 = Kmac(Hart()).import_(*c.export(at=True))
c2.exec(inp=DATA200[100:])
to_output(c2, 256)
control('Serialized Content ordered with `@`', bytes(squeeze(c2, 32)[0][1]) != WANT[2])

done()
