#!/usr/bin/env python3
"""KAT for the KLE KMAC Machines (<<KLE-KMAC>> on <<KLE-SHA-3>>) against the NIST SP 800-185 samples.
Keccak-f[1600] is written here and anchored on FIPS 202; hashlib is only a labelled oracle."""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, mdh_pack, mdh_unpack, ERROR_STATES, KL_CFG_PROVISIONING,
                    KL_STATE_INERT as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_HASH_ABSORB as ABSORB, KL_STATE_HASH_OUTPUT as OUTPUT,
                    KL_STATE_HASH_LAST_BLOCK as LAST, KL_STATE_HASH_VERIFY as VERIFY, KL_STATE_FAILURE as FAILURE,
                    KL_STATE_SUCCESS as SUCCESS, KL_STATEEXT_INVALID as INVALID, KL_STATEEXT_UNSUPPORTED as UNSUP,
                    section, check, control, done, HashPort, hash_run, hash_msgs, check_hash,
                    KL_STATEEXT_OUT_OF_MEMORY, IllegalInstruction, raises)

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
    """KECCAK-p[1600,24] on a KLE value (lane x + 5y at bits [64(x+5y)+63 : 64(x+5y)])."""
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

# ------------------------------------------------------------------ KLE model
MODE = {'KMAC128': 10, 'KMACXOF128': 11, 'KMAC256': 12, 'KMACXOF256': 13}   # Type 6
NAME = {m: n for n, m in MODE.items()}


def kname(sec, xof):
    return f"KMAC{'XOF' if xof else ''}{sec}"


def pack(fields):
    v = off = 0
    for x, w in fields:
        v, off = v | x << off, off + w
    return v


def scc_len(b, kt=0):                    # Serialized Content, zero-padded to 128 bits
    return -(-(1664 + b + (64 if kt == 1 else b)) // 128) * 16


def kl_size(state, b, kt=0):             # <<KLE-instruction-size>>, AuxDataLen = 0
    if state in (UNCONF, KL_CFG_PROVISIONING):
        return 16 + -(-(b + (64 if kt == 1 else b)) // 128) * 16
    return 16 if state in ERROR_STATES else 32 + scc_len(b, kt)


def provision_blocks(sec, K, S):
    w = RATE[sec]
    cb, kb = bytepad(encode_string(b'KMAC') + encode_string(S), w), bytepad(encode_string(K), w)
    if len(cb) != w or len(kb) != w:
        raise ValueError('K or S exceeds one rate block')
    return cb, kb


def make_pi(sec, xof, K, S, skid=None, keytype=None, policy=None):
    """PI; with a SKID (_KeyType_ = 1, GR71) Pos. iii is the 64-bit SKID (b/8 + 8 is a multiple of 16); with
    _KeyType_ = 2 it has the layout of _KeyType_ = 0, and the unit replaces its key_block."""
    policy = (0 if xof else 0b11) if policy is None else policy     # KMACXOF: no _MachinePolicy_
    kt = int(skid is not None) if keytype is None else keytype
    cb, kb = provision_blocks(sec, b'' if kt == 1 else K, S)
    mdh = mdh_pack(Machine=0x60 | MODE[kname(sec, xof)], State=UNCONF, KeyType=kt, MachinePolicy=policy)
    return v2b(mdh, 16) + cb + (v2b(skid, 8) if kt == 1 else kb)


SKS = {0x0123456789ABCDEF: bytes(range(32)), 0x1111: bytes(164)}   # the second exceeds the KMAC128 maximum


class Hart:
    klstart = 0


class Kmac:
    """A locker holding a KMAC CC; `bad` selects negative-control deviations."""

    def __init__(self, hart, bad=()):
        self.hart, self.bad, self.st, self.b = hart, set(bad), UNCONF, 0
        self.policy = 0b11
        self.keytype = self.skid = 0
        self._clear()

    def _machine(self, machine):
        self.machine, self.name = machine, NAME[machine & 0xF]
        self.sec, self.xof = int(self.name[-3:]), 'XOF' in self.name
        self.b = self.t = 8 * RATE[self.sec]                             # t = b
        self.D = (1, 1, 1, 1) if 'suffix' in self.bad else (0, 0)       # cSHAKE suffix

    def _clear(self):                                                    # GR29
        self.state = self.block_base = self.last_block_len = self.cb = self.kb = self.L = 0

    def invalidate(self):
        self.st = INVALID
        self._clear()

    def _resolve(self, skid):
        """<<KLE-KMAC>>: the SKS returns K, or for _KeyType_ = 2 (skid None) K is random of c/2 bits; the unit
        forms key_block."""
        K = os.urandom(self.sec // 8) if skid is None else SKS.get(skid)
        try:
            self.kb = b2v(provision_blocks(self.sec, K, b'')[1]) if K is not None else None
        except ValueError:                                               # K longer than the maximum
            self.kb = None
        if self.kb is None:
            return self.invalidate()                                     # <<KLE-system-keys>>
        self.keytype, self.skid = (0, 0) if skid is None else (1, skid)
        return True

    def provision(self, pi):
        f = mdh_unpack(b2v(pi[:16]))
        self._machine(f['Machine'])
        self.policy = f['MachinePolicy']
        if self.bad_policy():
            return self._reject()                                        # <<KLE-MVR-open>>
        w, kt = self.b // 8, f['KeyType']
        assert f['State'] == UNCONF and len(pi) == kl_size(UNCONF, self.b, kt)
        self.cb = b2v(pi[16:16 + w])
        if kt == 0:
            self.kb = b2v(pi[16 + w:])
        elif not self._resolve(None if kt == 2 else b2v(pi[16 + w:16 + w + 8])):
            return
        self.ready()

    def bad_policy(self):
        """KMAC: at least one of generate/verify; KMACXOF gates no State, so non-zero is unsupported."""
        return bool(self.policy) if self.xof else not self.policy & 3  # a policy above 3 (unsupported) is not modelled

    def _reject(self):
        """KMAC without a set bit: invalid Metadata (_Invalid_); KMACXOF with one: unsupported Metadata, the KLE
        unsupported-Metadata exception, which the handler maps to _Unsupported_ (<<KLE-MVR-open>>)."""
        self.invalidate()
        if self.xof:
            self.st = UNSUP

    def fields(self):
        return [(self.state, 1600), (self.block_base, 16), (self.last_block_len, 16), (self.L, 32), (self.cb, self.b),
                (self.skid, 64) if self.keytype else (self.kb, self.b)]

    def export(self, at=False):
        """(MDH, Serialized Content); at=True is the negative control that orders with `@`."""
        v = cat(*self.fields()) if at else pack(self.fields())
        return (mdh_pack(Machine=self.machine, State=self.st, KeyType=self.keytype, MachinePolicy=self.policy),
                v2b(v, scc_len(self.b, self.keytype)))

    def import_(self, mdh, content):
        f = mdh_unpack(mdh)
        self._machine(f['Machine'])
        self.policy = f['MachinePolicy']
        self.st, v, self.keytype = f['State'], b2v(content), f['KeyType']
        vals = []
        for _, w in self.fields():
            vals.append(v & ((1 << w) - 1))
            v >>= w
        self.state, self.block_base, self.last_block_len, self.L, self.cb, key = vals
        if self.keytype:
            self._resolve(key)                                           # GR72: SKID resolved after import
        else:
            self.kb = key
        bad_base = self.block_base > (self.t if self.st == SUCCESS else self.b - 1)
        if bad_base and self.st not in ERROR_STATES:                     # inconsistent image (negative control)
            self.invalidate()
        elif self.bad_policy():                                          # <<KLE-MVR-open>>
            self._reject()
        return self

    def ready(self):                                                     # SHA-3: `state` zeroed; L <- 0
        self.st, self.block_base, self.last_block_len, self.state, self.L = READY, 0, 0, 0, 0

    def setst(self, immed, form='A', aux=None):
        if immed == UNCONF:                                              # kl.clear, in any State and Form
            return self.__init__(self.hart, self.bad)
        if immed in ERROR_STATES:                                        # GR30: in every State
            self.invalidate()
            self.st = immed
            return
        if self.st == UNCONF or self.st in ERROR_STATES:                 # GR26
            return
        if immed == READY and form == 'A':                               # GR16: Form A
            return self.ready()
        if immed == ABSORB and self.st == READY and form == 'A':         # no same-State (PROCESS_VLI)
            self.state = keccak(keccak(self.state ^ self.cb) ^ self.kb)  # the key enters `state` only here
            self.st, self.last_block_len = ABSORB, self.b
            return
        if immed == LAST and self.st == ABSORB and (form == 'A' or form == 'B' and aux is not None
                                                    and 0 <= aux <= self.b):
            self.st = LAST                                               # a final piece of any bit length
            if form == 'B':
                self.last_block_len = aux
            return
        done = self.st == ABSORB or self.st == LAST and self.last_block_len == 0
        if immed == OUTPUT and done and (form in 'AB' if self.xof else form == 'B') and (self.xof or self.policy & 1):
            x = (aux or 0) if form == 'B' else 0
            if (x % 8 == 0 and x < 1 << 32) if self.xof else 32 <= x < 1 << 32:  # KMAC: 32 <= L < 2^32 (SP 800-185)
                self.L = x
                return self._to_output()
        if immed == VERIFY and done and form == 'B' and not self.xof and self.policy & 2:   # MR11
            if aux is not None and aux % 8 == 0 and 32 <= aux <= self.b:   # SP 800-185 8.4.2
                self.L = aux
                return self._to_output(VERIFY)
        self.invalidate()

    def _to_output(self, target=OUTPUT):
        enc = (left_encode if 'left_encode' in self.bad else right_encode)(0 if self.xof else self.L)
        self._vli(b2v(enc), 8 * len(enc), 0)
        room, D = self.b - self.block_base, self.D                       # <<KLE-SHA-3>> padding
        n = room if room >= len(D) + 2 else room + self.b
        S = pack([(bit, 1) for bit in D]) | 1 << len(D) | 1 << (n - 1)
        self.pad_case = 1 if n == room else 2
        self.state = keccak(self.state ^ (S & ((1 << room) - 1)) << self.block_base)
        if n > room:
            self.state = keccak(self.state ^ S >> room)
        self.st, self.block_base, self.last_block_len = target, 0, 0
        if 'raw_last_byte' in self.bad and not self.xof:
            self.L = 8 * -(-self.L // 8)

    def _end(self, status, out=None):
        if out is not None and status in ('invalid', 'noop'):             # GR28
            k = min(self.hart.klstart, len(out))
            out[k:] = bytes(len(out) - k)
        self.hart.klstart = 0
        return status

    def restrictl(self, clear):                                          # kl.restrictl (GR20)
        if self.st == UNCONF or self.st in ERROR_STATES or not clear:    # GR26; a zero field changes nothing
            return
        if self.xof:                                                     # the field is unused: _Invalid_
            return self.invalidate()
        self.policy &= ~clear
        if not self.policy & 3:
            self.invalidate()                                            # GR20: 0 is forbidden

    def exec(self, inp=None, out=None, sew=None, halt=None, literal=False):
        """kl.exec: Form B with `inp`, Form C with `out` (a bytearray); `halt` = byte count after
        which to halt at the next interruption point; `sew` = vector element width."""
        if self.st == UNCONF or self.st in ERROR_STATES:                 # GR26
            return self._end('noop', out)
        if self.st in (OUTPUT, VERIFY) and not self.xof and not self.policy & (1 if self.st == OUTPUT else 2):
            self.invalidate()                                            # MR11 1.a, GR20
            return self._end('invalid', out)
        if self.st == ABSORB and inp is not None and out is None and (sew or 8) >= 8:  # MR1, MR2
            p, top = self.hart.klstart, len(inp)
            if p >= top:
                return self._end('empty')                                # empty window: only klstart = 0
            if p and self.block_base:                                    # not an interruption point
                self.invalidate()
                return self._end('invalid')
            st = self._vli(b2v(inp), 8 * top, 8 * p, halt, literal)
            return st if st == 'interrupted' else self._end(st)
        if self.st == LAST and inp is not None and out is None and (sew or 8) >= 8:
            p, top, L = self.hart.klstart, len(inp), self.last_block_len
            if 8 * top < L:                                              # MR2, GR44 item 1
                self.invalidate()
                return self._end('invalid')
            if p >= top:
                return self._end('empty')                                # GR44 item 2
            if p or not L:                                               # point 0 only; MR10
                self.invalidate()
                return self._end('invalid')
            self._vli(sl(b2v(inp), L - 1, 0), L, 0)                      # atomic, the L low bits (MR7)
            self.last_block_len = 0
            return self._end('done')
        if self.st == OUTPUT and inp is None and out is not None:
            return self._squeeze(out, halt)
        if self.st == VERIFY and inp is not None and out is None:
            if 8 * len(inp) < self.L:                                    # MR2, GR44 item 1
                self.invalidate()
                return self._end('invalid')
            if self.hart.klstart >= len(inp):
                return self._end('empty')                                # GR44 item 2
            if self.hart.klstart:                                        # point 0 only (MR3)
                self.invalidate()
                return self._end('invalid')
            L = self.L                                                   # MR14: constant-time compare of L bits
            self.st = SUCCESS if sl(b2v(inp), L - 1, 0) == sl(self.state, L - 1, 0) else FAILURE
            return self._end('done')
        self.invalidate()                                                # MR1, GR17 item 1
        return self._end('invalid', out)

    def _vli(self, X, n, ib, halt=None, literal=False):                 # <<KLE-process-VLI>>
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
        if p >= top:
            return self._end('empty')                                    # empty window: only klstart = 0
        if p and self.block_base:                                        # not an interruption point
            self.invalidate()
            return self._end('invalid', out)
        OUT, ob = b2v(out), 8 * p
        while ob < 8 * top:
            amt = min(8 * top - ob, self.t - self.block_base)
            bounded = self.L != 0                                        # L counts the bits left
            if bounded:
                amt = min(amt, self.L)
            chunk = sl(self.state, self.block_base + amt - 1, self.block_base)
            OUT = OUT & ~(((1 << amt) - 1) << ob) | chunk << ob
            ob, self.block_base = ob + amt, self.block_base + amt
            if bounded:
                self.L -= amt
                if self.L == 0:                                          # then MR8
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


class Port(HashPort):
    """<<Zkl-software.adoc#KLE-pseudocode-hash>> on a KMAC locker (key KEY, S = TAG)."""
    def __init__(p, sec=128, xof=False, cl=None, hart=None):
        p.sec, p.xof, p.hart = sec, xof, hart or Hart()
        p.cl = cl or locker(sec, xof, hart=p.hart)
        p.b = p.cl.b
    st = property(lambda p: p.cl.st)
    klstart = property(lambda p: p.hart.klstart)
    def setst(p, immed, form='A', xs=None): p.cl.setst(immed, form, xs)
    def exec_in(p, d, halt_at=None):
        return p.cl.exec(inp=d, halt=None if halt_at is None else halt_at + 1)
    def exec_out(p, n, halt_at=None, prior=None):
        o = bytearray(prior or bytes(n))
        r = p.cl.exec(out=o, halt=None if halt_at is None else halt_at + 1)
        return r, bytes(o)
    def export(p): return p.cl.export()
    def imported(p, img):
        c = Kmac(p.hart)
        c.import_(*img)
        return Port(p.sec, p.xof, c, p.hart)

class KeyDest:
    """A symmetric `key` of n bytes, a destination in _Ready_ (<<KLE-derive-endpoints>>); only the key is modelled."""
    def __init__(self, n): self.st, self.n, self.key = READY, n, None
    def invalidate(self): self.st, self.key = INVALID, None


class FieldSrc(bytes):
    """A shared-secret field (ECC _Output_ or ML-KEM `sharedkey`, GR34), which does not advance (GR31)."""
    st = OUTPUT


class CmacSrc:
    """A CMAC in _Hash_Output_ (<<KLE-derive-endpoints>>, GR35): its b/8 bytes of `hash`, then _Success_."""
    def __init__(self, mac): self.st, self.mac = OUTPUT, mac
    def invalidate(self): self.st = INVALID


def derive(hart, dst, src, length):
    """kl.derive of a shared-secret field into the kl.exec input of `dst` (GR34, GR31), or of a shared-secret
    field or a CMAC into a KeyDest; no KMAC output is a source (<<KLE-derive-endpoints>>). Uninterruptible
    (GR38)."""
    field, cmac = isinstance(src, FieldSrc), isinstance(src, CmacSrc)
    if (field or src.st not in ERROR_STATES) and dst.st not in ERROR_STATES:
        key = isinstance(dst, KeyDest)
        n = len(src) if field else len(src.mac) if cmac else 0
        if not (field or cmac and src.st == OUTPUT):
            src.invalidate()                                             # GR32 item 1
        elif dst.st != (READY if key else ABSORB):
            dst.invalidate()                                             # GR32 item 2
        elif not (key or field):
            src.invalidate()                                             # GR32 item 3: a message input takes
            dst.invalidate()                                             # only a shared secret
        elif hart.klstart or (length < dst.n or n < dst.n if key else length != n):
            dst.invalidate()                                             # GR32 item 5; 8-bit granularity
        elif key:
            dst.key = bytearray((bytes(src) if field else src.mac)[:dst.n])
            if cmac:
                src.st = SUCCESS
        else:
            dst.exec(inp=bytes(src))
    hart.klstart = 0


# ------------------------------------------------------------------ drivers
def locker(sec, xof=False, S=TAG, hart=None, bad=(), policy=None):
    c = Kmac(hart or Hart(), bad)
    c.provision(make_pi(sec, xof, KEY, S, policy=policy))
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

section('SP 800-185 reference and KLE model vs the official samples')
for (label, sec, xof, K, X, S, L, _), want in zip(SAMPLES, WANT):
    check(f'reference   {label}', True, ref_kmac(sec, K, X, L, S, xof, len(want)), want)
    got, c = kl_kmac(sec, X, L, S, xof, len(want))
    check(f'KLE model  {label}: output, then {"stays in _Hash_Output_" if xof else "_Success_"}',
          True, (got, c.st), (want, OUTPUT if xof else SUCCESS))

section('Parameters and _Machine_ encodings (<<KLE-exec-encodings>>)')
for nm, sec, c_ in (('KMAC128', 128, 256), ('KMACXOF128', 128, 256), ('KMAC256', 256, 512),
                    ('KMACXOF256', 256, 512)):
    c = locker(sec, 'XOF' in nm, b'')
    check(f'{nm}: Type 6 Mode {MODE[nm]}, c = {c_}, b = t = 1600 - c = 8 * {RATE[sec]}, _Ready_',
          True, (c.name, c.b, c.t, c.st), (nm, 1600 - c_, 8 * RATE[sec], READY))

section('Absorption through PROCESS_VLI (granularity 8 bits)')
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
check('granularity 8 bits: a Form B kl.exec with SEW = 8 is admitted', True, (c.exec(inp=DATA200[:8], sew=8), c.st),
      ('done', ABSORB))

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
h.klstart, snap = 300, (c.st, c.state, c.block_base)
check('input klstart = 300 > KLLEN/8: empty window, only klstart = 0', True,
      (c.exec(inp=DATA200), (c.st, c.state, c.block_base) == snap, h.klstart), ('empty', True, 0))
h.klstart = 100
check('input klstart = 100 with block_base = 32 -> _Invalid_, Content cleared, klstart = 0', True,
      (c.exec(inp=DATA200), c.st, c.state, c.kb, h.klstart), ('invalid', INVALID, 0, 0, 0))

section('right_encode(L) and the <<KLE-SHA-3>> padding on entering _Hash_Output_')
c = absorbing(128, DATA200)
bb = c.block_base
to_output(c, 256)
check('block_base = 32 B after 200 B; right_encode(256) then |S| = b - block_base (clause 1)', True,
      (bb, c.pad_case), (256, 1))
for sec in (128, 256):
    got, c = kl_kmac(sec, DATA4, 256, TAG, xof=True, n=32)
    check(f'KMACXOF{sec} absorbs right_encode(0) (L = {c.L})', True, got,
          ref_kmac(sec, KEY, DATA4, 0, TAG, True, 32))

res = []
for sec, rate in ((128, 168), (256, 136)):
    for L in (256, 70000):                         # right_encode(L) of 3, resp. 4 bytes
        for m in (rate - 1, rate - 2):
            X = bytes(range(256))[:m]
            got, _ = kl_kmac(sec, X, L, TAG, n=32)
            res.append(got == ref_kmac(sec, KEY, X, L, TAG)[:32])
check('right_encode(L) crossing the rate boundary (messages of b/8 - 1 and b/8 - 2 bytes, L = 256 and 70000): '
      'absorbed as by kl.exec, with P() at the boundary (SP 800-185 4.3)', True, res, [True] * 8)

section('Output length: exactly L bits, the last byte zero-padded')
a, b_ = ref_kmac(128, KEY, DATA4, 256, TAG), ref_kmac(128, KEY, DATA4, 512, TAG)
got, c = kl_kmac(128, DATA4, 512, TAG)
check('KMAC128 L=512 is not an extension of L=256; 64 B then _Success_', True,
      (b_[:32] != a, got, c.st), (True, b_, SUCCESS))
for L in (32, 39, 255, 250, 257, 1000, 1001):
    got, c = kl_kmac(128, DATA4, L, TAG)
    check(f'KMAC128 L={L}: ceil(L/8) B, last byte zero-padded, _Success_', True, (got, c.st),
          (ref_kmac(128, KEY, DATA4, L, TAG), SUCCESS))
c = squeezing(128, DATA4, 250)
(st, o), = squeeze(c, 40, fill=0xEE)
check('KMAC128 L=250 into 40 B: _Success_, OUTPUT bits [319:250] cleared (MR8)', True,
      (st, bytes(o[:32]), o[32:], o[31] >> 2),
      ('success', ref_kmac(128, KEY, DATA4, 250, TAG), bytearray(8), 0))
c = squeezing(256, DATA4, 512)
(s1, d1), (s2, d2) = squeeze(c, 20, 44)
check('KMAC256 #4 split 20+44 B: _Hash_Output_ after 20, _Success_ on byte 64', True,
      (s1, s2, c.st, bytes(d1 + d2)), ('done', 'success', SUCCESS, WANT[3]))
c = squeezing(256, DATA4, 512)
(st, o), = squeeze(c, 200, fill=0xEE)
check('KMAC256 #4 into 200 B: _Success_, bytes [64, 199] cleared', True, (st, bytes(o)),
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
ea, eb, w2 = ca.export()[1], cb.export()[1], 2 * RATE[256]
check('two KMAC256 L=4096 exports 1088 bits apart differ only in `state` and `L` (4096 - 1096, 4096 - 2184)', True,
      (ea[200:204] == eb[200:204], b2v(ea[204:208]), b2v(eb[204:208]),
       ea[208:] == eb[208:]), (True, 4096 - 1096, 4096 - 2184, True))

section('KMACXOF: unlimited output (<<KLE-hash-functions-MACs-XOFs>>)')
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
c = squeezing(128, DATA200, 0, xof=True, hart=h)
c.exec(out=bytearray(10))
o, snap, res = bytearray(b'\xee' * 64), (c.st, c.state, c.block_base), []
for ks in (64, 70):
    h.klstart = ks
    res.append((c.exec(out=o), h.klstart, bytes(o), (c.st, c.state, c.block_base) == snap))
check('output only, klstart >= KLLEN/8 (64, 70): empty window, only klstart = 0', True, res,
      [('empty', 0, b'\xee' * 64, True)] * 2)
h.klstart = 5
check('block_base = 80, output only, klstart = 5 -> _Invalid_, [5, 63] zeroed', True,
      (c.exec(out=o), c.st, h.klstart, bytes(o)), ('invalid', INVALID, 0, b'\xee' * 5 + bytes(59)))

section('States, transitions and expected Forms')
for label, c, act in (
        ('KMAC128 Form B kl.setst with L = 0', absorbing(128, DATA4), lambda c: c.setst(OUTPUT, 'B', 0)),
        ('KMAC128 Form B kl.setst with L = 31 < 32 (SP 800-185 8.4.2)', absorbing(128, DATA4),
         lambda c: c.setst(OUTPUT, 'B', 31)),
        ('KMAC128 Form B kl.setst with L = 2^32', absorbing(128, DATA4), lambda c: c.setst(OUTPUT, 'B', 1 << 32)),
        ('KMAC128 Form A kl.setst to _Hash_Output_', absorbing(128, DATA4), lambda c: c.setst(OUTPUT)),
        ('KMACXOF256 Form B kl.setst to _Hash_Output_ with a bound not a multiple of 8', absorbing(256, DATA4, True),
         lambda c: c.setst(OUTPUT, 'B', 513)),
        ('kl.exec in _Ready_ (GR17)', locker(128), lambda c: c.exec(inp=DATA4)),
        ('Form B kl.setst into _Hash_Absorb_', locker(128), lambda c: c.setst(ABSORB, 'B', 32)),
        ('same-State kl.setst in _Hash_Absorb_ (<<KLE-process-VLI>>)', absorbing(128, DATA4),
         lambda c: c.setst(ABSORB)),
        ('Form B kl.exec in _Hash_Output_ (MR1)', squeezing(128, DATA4, 256),
         lambda c: c.exec(inp=DATA4)),
        ('KMAC128 same-State kl.setst to _Hash_Output_ (GR17)', squeezing(128, DATA4, 256),
         lambda c: c.setst(OUTPUT, 'B', 256)),
        ('KMACXOF256 same-State kl.setst to _Hash_Output_ (GR17)', squeezing(256, DATA4, 0, True),
         lambda c: c.setst(OUTPUT))):
    act(c)
    check(f'{label} -> _Invalid_', True, c.st, INVALID)
c = squeezing(128, DATA4, 256)
squeeze(c, 32)
(st, o), = squeeze(c, 32, fill=0xEE)
check('kl.exec in _Success_ -> _Invalid_, output window zeroed (MR1, GR28)', True,
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

section('System Key Identifier (_KeyType_ = 1)')
SK = 0x0123456789ABCDEF
for sec in (128, 256):
    c = Kmac(Hart())
    c.provision(pi := make_pi(sec, False, None, TAG, SK))
    w = RATE[sec]
    check(f'KMAC{sec} PI with a SKID: MDH, cshake_block, SKID ({len(pi)} B = kl.size)', True,
          (len(pi), kl_size(UNCONF, 8 * w, 1), b2v(pi[16 + w:])), (16 + w + 8, 16 + w + 8, SK))
    c.setst(ABSORB)
    c.exec(inp=DATA4)
    to_output(c, 256)
    check(f'KMAC{sec}: the SKS returns K, the unit forms key_block: tag = KMAC under K', True,
          bytes(squeeze(c, 32)[0][1]), ref_kmac(sec, SKS[SK], DATA4, 256, TAG))
    mdh, img = c.export()
    check(f'KMAC{sec} Content1 with a SKID: key_block replaced by the 64-bit SKID (Pos. vi), KeyType kept', True,
          (len(img), mdh_unpack(mdh)['KeyType'], sl(b2v(img), 1664 + 8 * w + 63, 1664 + 8 * w)),
          (scc_len(8 * w, 1), 1, SK))
    c2 = Kmac(Hart()).import_(mdh, img)
    check(f'KMAC{sec}: import resolves the SKID again, same key_block', True, (c2.kb, c2.st), (c.kb, c.st))
c = Kmac(Hart())
c.provision(pi := make_pi(128, False, bytes(16), TAG, keytype=2))
check('_KeyType_ = 2: the PI of _KeyType_ = 0; a random K of c/2 = 128 bits forms key_block; _KeyType_ becomes 0, '
      'exported by value', True, (len(pi) == kl_size(UNCONF, 1344), c.st, c.keytype,
      c.kb != b2v(provision_blocks(128, bytes(16), b'')[1]), len(c.export()[1]) == scc_len(1344)),
      (True, READY, 0, True, True))
for label, skid in (('unresolved SKID', 0x42), ('SKS key longer than the 163-byte maximum', 0x1111)):
    c = Kmac(Hart())
    c.provision(make_pi(128, False, None, TAG, skid))
    check(f'KMAC128 {label}: _Invalid_ (<<KLE-system-keys>>)', True, c.st, INVALID)

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
for sec, pi_len, c1_len in ((128, 352, 544), (256, 288, 480)):
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
    check(f'KMAC{sec} Content1: state, block_base = 64, last_block_len = 0, L = 1234 - 64 bits left (Pos. iv, '
          f'the place of out_len), cshake_block, key_block, no padding', True,
          (ct[:200], ct[200:202], ct[202:204], ct[204:208], ct[208:208 + w], ct[208 + w:], len(ct)),
          (v2b(c.state, 200), v2b(64, 2), v2b(0, 2), v2b(1234 - 64, 4), cbk, kbk, 208 + 2 * w))
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
cs = Kmac(Hart())
cs.provision(make_pi(128, False, KEY, TAG, skid=0x0123456789ABCDEF))
check('the _Ready_ Content1 holds `state` = 0, with the key by value and with a SKID (key absorbed on leaving _Ready_)',
      None, [locker(128).export()[1][:200], cs.export()[1][:200]], [bytes(200)] * 2)
c = squeezing(256, DATA200, 4096)
(_, o1), = squeeze(c, 300)
c2 = Kmac(Hart()).import_(*c.export())
(st, o2), = squeeze(c2, 212)
check('round trip, KMAC256 L = 4096 after 2 update()s (L counts down in the Serialized Content), then _Success_', True,
      (bytes(o1 + o2), st, c2.st), (ref_kmac(256, KEY, DATA200, 4096, TAG), 'success', SUCCESS))

section('kl.derive (<<KLE-derive-endpoints>>, GR32, GR34)')
h = Hart()
SS = bytes(range(0x40, 0x60))
stream = ref_kmac(128, KEY, DATA4, 0, TAG, True, 64)
res = []
for sec, xof, L in ((128, False, 256), (256, True, 0)):
    dst = absorbing(sec, DATA4, xof=xof, hart=h)
    derive(h, dst, FieldSrc(SS), 32)
    dst.exec(inp=DATA4)
    to_output(dst, L)
    res.append((h.klstart, dst.st, bytes(squeeze(dst, 32)[0][1])))
check('shared secret (32 B, length 32) -> open KMAC128 and KMACXOF256 _Hash_Absorb_ between two DATA4 (GR34)', True,
      res, [(0, OUTPUT, ref_kmac(128, KEY, DATA4 + SS + DATA4, 256, TAG)),
            (0, OUTPUT, ref_kmac(256, KEY, DATA4 + SS + DATA4, 0, TAG, True, 32))])
dst = absorbing(128, DATA4, hart=h)
dst.setst(LAST, 'B', 0)
derive(h, dst, FieldSrc(SS), 32)
check('shared secret into KMAC128 _Hash_Absorb_Last_Block_ (not an endpoint, GR32 item 2): destination _Invalid_',
      True, dst.st, INVALID)
src, dst = squeezing(128, DATA4, 0, xof=True, hart=h), absorbing(128, DATA4, hart=h)
derive(h, dst, src, 32)
dst.exec(inp=DATA4)
to_output(dst, 256)
check('KMACXOF128 output -> open KMAC128 _Hash_Absorb_: no KMAC output is a source (GR32 item 1): source '
      '_Invalid_, destination unchanged', True, (src.st, h.klstart, bytes(squeeze(dst, 32)[0][1])),
      (INVALID, 0, ref_kmac(128, KEY, DATA4 + DATA4, 256, TAG)))
src, dst = squeezing(256, DATA4, 512, hart=h), absorbing(256, xof=True, S=b'', hart=h)
derive(h, dst, src, 64)
check('whole KMAC256 output (L = 512) -> KMACXOF256 (GR32 item 1): source _Invalid_, destination in _Hash_Absorb_',
      True, (src.st, dst.st), (INVALID, ABSORB))
src = squeezing(256, DATA4, 512, hart=h)
squeeze(src, 64)
derive(h, absorbing(128, hart=h), src, 16)
check('source in _Success_ (no endpoint, GR32 item 1) -> source _Invalid_', True, src.st, INVALID)
dst = squeezing(128, DATA4, 256, hart=h)
derive(h, dst, FieldSrc(SS), 32)
check('shared secret -> KMAC128 in _Hash_Output_ (GR32 item 2) -> destination _Invalid_', True, dst.st, INVALID)
src, dst = CmacSrc(bytes(16)), absorbing(128, DATA4, hart=h)
derive(h, dst, src, 16)
check('a CMAC -> KMAC128 _Hash_Absorb_: pair not admitted (GR32 item 3), both _Invalid_', True,
      (src.st, dst.st), (INVALID, INVALID))
res = []
for n, length, ks in ((32, 0, 0), (32, 31, 0), (32, 33, 0), (32, 1 << 60, 0), (32, 32, 4)):
    dst = absorbing(128, DATA4, hart=h)
    h.klstart = ks
    derive(h, dst, FieldSrc(SS[:n]), length)
    res.append((dst.st, h.klstart))
check('shared secret (32 B) into KMAC128 _Hash_Absorb_ with length 0, 31, 33 or 2^60 (8-bit granularity), or '
      'klstart = 4 (uninterruptible, GR38) -> destination _Invalid_ (GR32 item 5), klstart = 0', True, res,
      [(INVALID, 0)] * 5)

src, dst = squeezing(128, DATA4, 0, xof=True, hart=h), KeyDest(16)
s2, d2 = squeezing(256, DATA4, 512, hart=h), KeyDest(32)
for d, s_ in ((dst, src), (d2, s2)):
    derive(h, d, s_, 32)
check('KMACXOF128 -> a 16-byte `key`, KMAC256 (L = 512) -> a 32-byte key: not a source (GR32 item 1), source '
      '_Invalid_, key unwritten', True, (src.st, dst.st, dst.key, s2.st, d2.st, d2.key),
      (INVALID, READY, None, INVALID, READY, None))
res = []
for s_, d, length in ((FieldSrc(SS), KeyDest(16), 32), (FieldSrc(SS), KeyDest(32), 32),
                      (CmacSrc(stream[:16]), KeyDest(16), 16), (FieldSrc(SS[:16]), KeyDest(32), 32),
                      (FieldSrc(SS), KeyDest(32), 16), (CmacSrc(stream[:16]), KeyDest(32), 32)):
    derive(h, d, s_, length)
    res.append((d.st, d.key and bytes(d.key), s_.st))
check('shared secret (32 B) -> a 16- and a 32-byte `key`, a 16-byte CMAC -> a 16-byte key (then _Success_); a '
      '16-byte secret or CMAC, or length 16, into a 32-byte key (GR32 item 5): destination _Invalid_', True, res,
      [(READY, SS[:16], OUTPUT), (READY, SS, OUTPUT), (READY, stream[:16], SUCCESS),
       (INVALID, None, OUTPUT), (INVALID, None, OUTPUT), (INVALID, None, OUTPUT)])

section('A message X of any bit length (_Hash_Absorb_Last_Block_, <<KLE-SHA-3>>)')

def ref_kmac_bits(sec, K, xv, xbits, L, S=TAG, xof=False, n=None):
    """Bit-level SP 800-185 KMAC: bytepad(...) || bytepad(...) || X (xbits) || right_encode(L) || 00 || pad10*1."""
    w = RATE[sec]
    pre = bytepad(encode_string(b'KMAC') + encode_string(S), w) + bytepad(encode_string(K), w)
    enc = right_encode(0 if xof else L)
    m = 8 * len(pre) + xbits + 8 * len(enc)
    P = b2v(pre) | sl(xv, xbits - 1, 0) << 8 * len(pre) | b2v(enc) << (8 * len(pre) + xbits)
    plen = ((m + 3) // (8 * w) + 1) * 8 * w
    P |= 0b100 << m | 1 << (plen - 1)
    st, out = 0, b''
    for off in range(0, plen, 8 * w):
        st = keccak(st ^ sl(P, off + 8 * w - 1, off))
    nb = n if xof else (L + 7) // 8
    while len(out) < nb:
        out += v2b(sl(st, 8 * w - 1, 0), w)
        st = keccak(st)
    return out[:nb] if xof else trunc_bits(out[:nb], L)

for sec, xof in ((128, False), (256, True)):
    check(f'bit-level reference = SP 800-185 reference on whole bytes, {kname(sec, xof)}', True,
          ref_kmac_bits(sec, KEY, b2v(DATA200), 1600, 256, xof=xof, n=64), ref_kmac(sec, KEY, DATA200, 256, TAG, xof, 64))
for sec, xof in ((128, False), (256, False), (128, True), (256, True)):
    b = 8 * RATE[sec]
    for nb, Lp, what in ((0, 5, 'piece only'), (100, 3, 'piece after 100 B'),
                         (b // 8 - 4, 45, 'piece crosses a block boundary'), (b // 8, b, 'Form A: a full block')):
        xbits = 8 * nb + Lp
        xv = sl(b2v(DATA200 + DATA200), xbits - 1, 0)
        c = absorbing(sec, (DATA200 + DATA200)[:nb], xof)
        if Lp == b:
            c.setst(LAST)
        else:
            c.setst(LAST, 'B', Lp)
        piece = v2b(sl(xv, xbits - 1, 8 * nb) | 0xff << Lp, (Lp + 7) // 8 + 1)
        r = c.exec(inp=piece)
        to_output(c, 0 if xof else 256)
        got = bytes(squeeze(c, 32 if not xof else 64)[0][1])
        check(f'{kname(sec, xof)}: {nb} B, then a {Lp}-bit piece ({what}) = bit-level reference', True,
              (r, got), ('done', ref_kmac_bits(sec, KEY, xv, xbits, 256, xof=xof, n=64)))
for label, act in (('a kl.exec after Xs = 0 (MR10)', lambda c: (c.setst(LAST, 'B', 0), c.exec(inp=DATA4))),
                   ('_Hash_Output_ before the piece', lambda c: (c.setst(LAST, 'B', 13), to_output(c, 256))),
                   ('a second piece (MR10)', lambda c: (c.setst(LAST, 'B', 13), c.exec(inp=DATA4), c.exec(inp=DATA4))),
                   ('KLLEN = 0 < last_block_len = 16, the length before the empty window (GR44 item 1)',
                    lambda c: (c.setst(LAST, 'B', 16), c.exec(inp=b'')))):
    c = absorbing(128, DATA4)
    act(c)
    check(f'KMAC128 _Hash_Absorb_Last_Block_ -> _Invalid_: {label}', True, c.st, INVALID)
c = absorbing(256, DATA200[:7])
c.setst(LAST, 'B', 13)
c2 = Kmac(Hart()).import_(*c.export())
c2.exec(inp=DATA200[7:9])
to_output(c2, 256)
check('KMAC256: export/import between the kl.setst and the kl.exec of a 13-bit piece', True,
      bytes(squeeze(c2, 32)[0][1]), ref_kmac_bits(256, KEY, b2v(DATA200), 69, 256))

section('_Hash_Verify_ and _MachinePolicy_ (KMAC128/256: generate bit 0, verify bit 1; KMACXOF: none)')
def verifying(sec, L, X=DATA200, policy=0b11):
    c = locker(sec, policy=policy)
    c.setst(ABSORB)
    c.exec(inp=X)
    c.setst(VERIFY, 'B', L)
    return c
res = []
for sec in (128, 256):
    for L in (256, 64, 32, 8 * RATE[sec]):
        tag = ref_kmac(sec, KEY, DATA200, L, TAG)
        ok, bad = verifying(sec, L), verifying(sec, L)
        ok.exec(inp=tag)
        bad.exec(inp=bytes([tag[0] ^ 1]) + tag[1:])
        res.append((ok.st, bad.st))
check('KMAC128/256 _Hash_Verify_ with L = 256, 64, 32 and b (L enters right_encode, as SP 800-185 requires): match -> '
      'Success, first byte flipped -> Failure', True, res, [(SUCCESS, FAILURE)] * 8)
c = verifying(128, 64)
c.hart.klstart = 8
r = c.exec(inp=bytes(8))
res = (r, c.st, c.hart.klstart)
c.exec(inp=ref_kmac(128, KEY, DATA200, 64, TAG))
check('KMAC128 _Hash_Verify_, L = 64, KLLEN = 64, klstart = 8: an empty window (GR44 item 2), _Hash_Verify_ kept, '
      'klstart = 0; then the right tag -> Success', True, res + (c.st,), ('empty', VERIFY, 0, SUCCESS))
res = []
for label, act in (('L = 24 < 32', lambda: verifying(128, 24)), ('L = 100, not a multiple of 8', lambda: verifying(128, 100)),
                   ('L = b + 8', lambda: verifying(128, 8 * RATE[128] + 8)),
                   ('KLLEN = 64 < L = 256', lambda: (lambda c: (c.exec(inp=bytes(8)), c)[1])(verifying(128, 256))),
                   ('same-State kl.setst', lambda: (lambda c: (c.setst(VERIFY, 'B', 256), c)[1])(verifying(128, 256))),
                   ('verify with MachinePolicy = 0b01', lambda: verifying(128, 256, policy=1)),
                   ('output with MachinePolicy = 0b10', lambda: (lambda c: (c.setst(ABSORB), to_output(c, 256), c)[2])(
                       locker(128, policy=2))),
                   ('KMACXOF: _Hash_Verify_ does not exist (MR1)', lambda: (lambda c: (c.setst(ABSORB), c.setst(VERIFY, 'B', 256), c)[2])(
                       locker(128, xof=True)))):
    res.append(act().st)
check('KMAC _Invalid_: L = 24, 100, b + 8; KLLEN < L; same-State; verify on 0b01; output on 0b10; KMACXOF Hash_Verify',
      True, res, [INVALID] * 8)
check('MachinePolicy = 0: KMAC128 invalid Metadata; KMACXOF128 gates nothing and computes #3', True,
      (locker(128, policy=0).st, kl_kmac(128, DATA200, 256, TAG, xof=True, n=32)[0] ==
       (lambda c: (c.setst(ABSORB), c.exec(inp=DATA200), to_output(c, 0), bytes(squeeze(c, 32)[0][1]))[3])(
           locker(128, xof=True, policy=0))), (INVALID, True))
check('KMACXOF128 with _MachinePolicy_ = 1: unsupported Metadata (KLE unsupported-Metadata, _Unsupported_)',
      True, locker(128, xof=True, policy=1).st, UNSUP)

cg = squeezing(128, DATA200, 256)
cg.restrictl(1)
og = bytearray(b'\xa5' * 32)
rg = cg.exec(out=og)
cv = absorbing(128, DATA200)
cv.restrictl(1)
cv.setst(VERIFY, 'B', 256)
cv.exec(inp=ref_kmac(128, KEY, DATA200, 256, TAG))
cz, cx, c0 = locker(128, policy=2), locker(128, xof=True, policy=0), locker(128, xof=True, policy=0)
cz.restrictl(2)
cx.restrictl(1)
c0.restrictl(0)
check('kl.restrictl clearing bit 0 in _Hash_Output_: the output kl.exec -> _Invalid_, OUTPUT zeroed; in _Hash_Absorb_ '
      'verification still succeeds; clearing the only set bit -> _Invalid_; KMACXOF: any set bit -> _Invalid_, a zero '
      'field changes nothing (GR20, MR11, <<KLE-instruction-restrict>>)', True,
      (rg, bytes(og), cg.st, cv.st, cz.st, cx.st, c0.st), ('invalid', bytes(32), INVALID, SUCCESS, INVALID, INVALID, READY))

section('kl.clear and kl.setst naming an Error State (<<KLE-instruction-setst>>, GR26, GR30)')
got = []
for xof in (False, True):
    for imm in (UNCONF, KL_STATEEXT_OUT_OF_MEMORY):
        c = absorbing(128, DATA4, xof=xof)
        c.setst(imm)
        got.append(c.st)
        c.setst(READY); c.setst(ABSORB); c.exec(inp=DATA4); c.restrictl(3)
        got.append(c.st)
    for imm in (48, 53):
        c = absorbing(128, DATA4, xof=xof); c.setst(imm); got.append(c.st)
check('KMAC128 and KMACXOF128: kl.clear in _Hash_Absorb_ -> _Unconfigured_, a kl.setst naming _Out_of_Memory_ -> '
      'that State; then a kl.setst, a kl.exec and a kl.restrictl change nothing; 48 or 53, which the Machine does '
      'not define, -> _Invalid_', True, got,
      [UNCONF, UNCONF, KL_STATEEXT_OUT_OF_MEMORY, KL_STATEEXT_OUT_OF_MEMORY, INVALID, INVALID] * 2)

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

section('The generic sequence (<<Zkl-software.adoc#KLE-pseudocode-hash>>), the final piece, the bound')
for sec in (128, 256):
    for xof in (False, True):
        bb = RATE[sec]
        ref = lambda m, nb, o, sec=sec, xof=xof: ref_kmac_bits(sec, KEY, b2v(m), nb, 8 * o, xof=xof, n=o)
        msgs = hash_msgs(bb, edges=(bb - 3, bb - 2), bits=True)
        check_hash(f'KMAC{"XOF" if xof else ""}{sec}', lambda sec=sec, xof=xof: Port(sec, xof), ref,
                   msgs if sec == 128 else msgs[::3], 32)
c = absorbing(128, b'abc')
c.setst(LAST, 'B', 0)
st = c.st
to_output(c, 256)
check('KMAC128 Xs = 0 into _Hash_Absorb_Last_Block_: the State stays, then _Hash_Output_ gives the tag of "abc"', True,
      (st, bytes(squeeze(c, 32)[0][1])), (LAST, ref_kmac(128, KEY, b'abc', 256, TAG)))
r = []
for n in (8, 1000):
    o, st, _ = hash_run(Port(128, True), b'abc', 24, n)
    r.append((o == ref_kmac(128, KEY, b'abc', 0, TAG, xof=True, n=n), st))
c = absorbing(128, b'abc', xof=True)
c.setst(OUTPUT, 'B', 12)
c2 = absorbing(128, b'abc', xof=True)
c2.setst(OUTPUT, 'A')
check('KMACXOF128 bounded at 8 and 1000 B: the prefix of the unbounded stream (right_encode(0) kept), then _Success_; '
      'Xs = 12 -> _Invalid_; Form A stays in _Hash_Output_', True,
      (r, c.st, bytes(squeeze(c2, 300)[0][1]) == ref_kmac(128, KEY, b'abc', 0, TAG, xof=True, n=300), c2.st),
      ([(True, SUCCESS)] * 2, INVALID, True, OUTPUT))
o, st, _ = hash_run(Port(128, True), b'abc', 24, 1)
check('KMACXOF128 bounded at 8 bits, the granularity: 1 B, the prefix of the unbounded stream, then _Success_', True,
      (o == ref_kmac(128, KEY, b'abc', 0, TAG, xof=True, n=1), st), (True, SUCCESS))

c = squeezing(128, DATA4, 8 * RATE[128])
o = bytes(squeeze(c, RATE[128])[0][1])
c2 = Kmac(Hart()).import_(*c.export())
check('KMAC128 L = t = 1344: _Success_ with block_base = t (the loop returns before update()); '
      'export/import keeps _Success_', True, (o, c2.st, c2.block_base),
      (ref_kmac(128, KEY, DATA4, 8 * RATE[128], S=TAG), SUCCESS, 8 * RATE[128]))
done()
