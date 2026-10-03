#!/usr/bin/env python3
"""KAT for the KLEE Ascon Machines (<<KLEE-Ascon-AEAD128>> to <<KLEE-Ascon-CXOF128>>) against NIST SP 800-232.
The permutation is written from scratch and anchored on SP 800-232 Tables 5 and 12-14; vectors are from the
ascon-c genkat files (LWC_AEAD_KAT_128_128, LWC_HASH_KAT_128_256, LWC_XOF_KAT_128_512, LWC_CXOF_KAT_128_512)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bxor, mdh_pack, mdh_unpack, MDH_FIELD, ERROR_STATES,
                    KL_STATE_UNCONFIGURED as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_HASH_ABSORB as ABSORB, KL_STATE_HASH_FINALIZE as FINALIZE,
                    KL_STATE_HASH_VERIFY as VERIFY, KL_STATE_HASH_OUTPUT as OUTPUT,
                    KL_STATE_ENCRYPT as ENCRYPT, KL_STATE_DECRYPT as DECRYPT,
                    KL_STATE_ENC_LAST_BLOCK as ENC_LAST, KL_STATE_DEC_LAST_BLOCK as DEC_LAST,
                    KL_STATE_SET_AUX_VALUE as SET_AUX, KL_STATE_SUCCESS as SUCCESS,
                    KL_STATE_FAILURE as FAILURE, KL_STATE_INVALID as INVALID,
                    section, check, control, info, done)

M64, M128, ONES = (1 << 64) - 1, (1 << 128) - 1, (1 << 1024) - 1
h, mask = bytes.fromhex, lambda n: (1 << n) - 1

# ------------------------------------------------------------------ permutation (SP 800-232 Sec. 3)
RC16 = [((15 - (j + 12) % 16) << 4) | (j + 12) % 16 for j in range(16)]   # p[rnd] uses the last rnd
TABLE5 = (0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b)
SIGMA = ((19, 28), (61, 39), (1, 6), (10, 17), (7, 41))                   # eqs. (8)-(12)
rotr = lambda x, n: ((x >> n) | (x << (64 - n))) & M64

def ascon_p(S, rounds):
    """Ascon-p[rounds] on the words S[0..4], in place (the spec's ASCON(p))."""
    for c in RC16[16 - rounds:]:
        S[2] ^= c
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        t = [(S[i] ^ M64) & S[(i + 1) % 5] for i in range(5)]
        for i in range(5): S[i] ^= t[(i + 1) % 5]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= M64
        for i, (a, b) in enumerate(SIGMA): S[i] ^= rotr(S[i], a) ^ rotr(S[i], b)
    return S

IVS = {'Ascon-AEAD128': 0x00001000808c0001, 'Ascon-Hash256': 0x0000080100cc0002,   # as quoted by the spec
       'Ascon-XOF128': 0x0000080000cc0003, 'Ascon-CXOF128': 0x0000080000cc0004}
IV_AEAD, IV_HASH, IV_XOF, IV_CXOF = IVS.values()
def iv_eq79(v, a, b, t, r8): return cat((0, 16), (r8, 8), (t, 16), (b, 4), (a, 4), (0, 8), (v, 8))   # eq. (79)
TABLE13 = {'Ascon-AEAD128': (1, 12, 8, 128, 16), 'Ascon-Hash256': (2, 12, 12, 256, 8),
           'Ascon-XOF128': (3, 12, 12, 0, 8), 'Ascon-CXOF128': (4, 12, 12, 0, 8)}
TABLE14 = {'Ascon-AEAD128': 0x00001000808c0001, 'Ascon-Hash256': 0x0000080100cc0002,
           'Ascon-XOF128': 0x0000080000cc0003, 'Ascon-CXOF128': 0x0000080000cc0004}
TABLE12 = {'Ascon-Hash256': (0x9b1e5494e934d681, 0x4bc3a01e333751d2, 0xae65396c6b34b81a,
                             0x3c7fd4a4d56a4db3, 0x1a5c464906c5976d),
           'Ascon-XOF128':  (0xda82ce768d9447eb, 0xcc7ce6c75f1ef969, 0xe7508fd780085631,
                             0x0ee0ea53416b58cc, 0xe0547524db6f0bde),
           'Ascon-CXOF128': (0x675527c2a0e8de03, 0x43d12d7dc0377bbc, 0xe9901dec426e81b5,
                             0x2ab14907720780b6, 0x8f3f1d02d432bc46)}

# ------------------------------------------------------------------ SP 800-232 references
def pad_bytes(x, r): return x + b'\x01' + bytes((-len(x) - 1) % r)
def ref_sponge(iv, msg, outlen, prefix=b''):
    S = ascon_p([iv, 0, 0, 0, 0], 12)
    m = prefix + pad_bytes(msg, 8)
    for i in range(0, len(m), 8):
        S[0] ^= b2v(m[i:i + 8]); ascon_p(S, 12)
    out = v2b(S[0], 8)
    while len(out) < outlen: out += v2b(ascon_p(S, 12)[0], 8)
    return out[:outlen]
def cxof_prefix(z): return v2b(8 * len(z), 8) + pad_bytes(z, 8)       # SP 800-232 Sec. 5.3: Z0, pad(Z, 64)
def ref_hash256(msg): return ref_sponge(IV_HASH, msg, 32)
def ref_xof128(msg, n=64): return ref_sponge(IV_XOF, msg, n)
def ref_cxof128(msg, z, n=64): return ref_sponge(IV_CXOF, msg, n, cxof_prefix(z))

# Algorithms 3/4 on bit strings (value, length), X[k] = bit k (Appendix A): also non-byte blocks, short tags.
def _parse(X, n, r):
    l = n // r
    return [sl(X, (i + 1) * r - 1, i * r) for i in range(l)], X >> (l * r), n - l * r
def _pad(X, n): return (X & mask(n)) | (1 << n)
def _p(S, rounds):
    w = ascon_p([sl(S, 64 * i + 63, 64 * i) for i in range(5)], rounds)
    return sum(x << (64 * i) for i, x in enumerate(w))
def _bits_init(K, N, A, alen):
    S = _p(IV_AEAD | K << 64 | N << 192, 12) ^ K << 192
    if alen:
        blocks, last, tl = _parse(A, alen, 128)
        for Ai in blocks + [_pad(last, tl)]: S = _p(S ^ Ai, 8)
    return S ^ 1 << 319
def _bits_final(S, K, lam): return ((_p(S ^ K << 128, 12) >> 192) ^ K) & mask(lam)

def ref_aead_bits_enc(K, N, A, alen, P, plen, lam=128):
    S = _bits_init(K, N, A, alen)
    blocks, last, l = _parse(P, plen, 128)
    C = 0
    for i, Pi in enumerate(blocks):
        S ^= Pi
        C |= (S & M128) << (128 * i)
        S = _p(S, 8)
    S ^= _pad(last, l)
    if l: C |= sl(S, l - 1, 0) << (128 * len(blocks))
    return C, _bits_final(S, K, lam)

def ref_aead_bits_dec(K, N, A, alen, C, clen, T, lam=128):
    S = _bits_init(K, N, A, alen)
    blocks, last, l = _parse(C, clen, 128)
    P = 0
    for i, Ci in enumerate(blocks):
        P |= ((S & M128) ^ Ci) << (128 * i)
        S = _p((S & ~M128) | Ci, 8)
    if l: P |= (sl(S, l - 1, 0) ^ last) << (128 * len(blocks))
    S = ((S ^ 1 << l) & ~mask(l)) | last
    return _bits_final(S, K, lam) == T, P

def ref_aead_encrypt(key, nonce, ad, pt):
    C, T = ref_aead_bits_enc(b2v(key), b2v(nonce), b2v(ad), 8 * len(ad), b2v(pt), 8 * len(pt))
    return v2b(C, len(pt)) + v2b(T, 16)
def ref_aead_decrypt(key, nonce, ad, blob):
    n = len(blob) - 16
    ok, P = ref_aead_bits_dec(b2v(key), b2v(nonce), b2v(ad), 8 * len(ad), b2v(blob[:n]), 8 * n, b2v(blob[n:]))
    return ok, v2b(P, n)

# ------------------------------------------------------------------ KLEE model
class Invalid(Exception): pass    # a driver saw an Error State

def pack(fields):
    """Fields in table order from bit 0, zero-padded to a multiple of 128 bits."""
    v = off = 0
    for val, w in fields:
        v, off = v | (val & mask(w)) << off, off + w
    return v2b(v, -(-off // 128) * 16)
def unpack(image, widths):
    v = b2v(image)
    return [sl(v, sum(widths[:i]) + w - 1, sum(widths[:i])) if w else 0 for i, w in enumerate(widths)]
def kl_pad(x, n, r=128): return cat((0, (-n - 1) % r), (1, 1), (x & mask(n), n))    # 0^j @ 1 @ x

class Locker:
    MODE = GRAN = None        # Type 8 Mode; granularity (bits)
    MULTI = LAST = ()         # States with per-block clauses (MGR3); last-block States (exempt from MGR2)
    USES_POLICY = False
    SRC = DST = None          # <<KLEE-derive-endpoints>>: source States; (destination States, dest_length)
    def __init__(self):
        self.st, self.policy, self.machine_use, self.key_type, self.klstart, self.halted = UNCONF, 0, 0, 0, 0, False
        self._clear()
    def in_error(self): return self.st in ERROR_STATES
    def invalidate(self, **_): self.st = INVALID; self._clear()  # GR9
    def _resolve_key(self, sks): pass
    def setst(self, immed, form='A', Xs=None, INPUT=0, KLLEN=0):
        if self.in_error(): pass                                  # GR11
        elif immed == READY and form == 'A': self._enter_ready()  # GR21
        else: self._setst().get((self.st, immed, form), self.invalidate)(Xs=Xs, INPUT=INPUT, KLLEN=KLLEN)  # MGR1
        return self
    def exec(self, form, INPUT=0, KLLEN=0, out=0, halt_after=None):
        """One kl.exec; `out` is the prior content of the output operand, the result its content after.
        `halt_after` = n halts precisely after n blocks; re-issuing resumes at klstart."""
        has_out, done, self.halted = form in 'AC', out & mask(8 * self.klstart), False
        zeroed = done if has_out else out                        # GR11
        if self.in_error(): return zeroed
        ks = 8 * self.klstart                                    # <<KLEE-CSR-klstart>>: interruption point?
        clause = self._exec().get((self.st, form))
        if clause is None or (self.st not in self.LAST and KLLEN % self.GRAN):   # GR18, GR23, MGR1; MGR2
            self.invalidate(); self.klstart = 0; return zeroed
        if ks >= KLLEN:                                          # empty window: only klstart = 0
            self.klstart = 0; return out
        if ks % self.GRAN or ks and self.st not in self.MULTI:   # not an interruption point
            self.invalidate(); self.klstart = 0; return zeroed
        res = clause(INPUT, KLLEN, done, halt_after)
        if not self.halted: self.klstart = 0
        if self.in_error(): return zeroed
        return res & mask(KLLEN) if has_out else out
    def _blocks(self, KLLEN, halt_after):                        # MGR3, from 8 * klstart
        for n, i in enumerate(range(8 * self.klstart, KLLEN, self.GRAN)):
            if n == halt_after: self.klstart, self.halted = i // 8, True; return
            yield i
    def _get(self, n): return self.s[int(n[1])] if n[0] == 's' and n[1:].isdigit() else getattr(self, n) or 0
    def _set(self, n, v):
        if n[0] == 's' and n[1:].isdigit(): self.s[int(n[1])] = v
        else: setattr(self, n, v)
    def export(self):
        """(MDH, Content1); GR9: a locker in an Error State is its MDH alone."""
        mdh = mdh_pack(Machine=0x80 | self.MODE, MachinePolicy=self.policy, State=self.st,
                       KeyType=self.key_type, MachineUse=self.machine_use)
        return mdh, b'' if self.in_error() else pack([(self._get(n), w) for n, w in self._layout()])
    @classmethod
    def import_(cls, img, sks=None, **flags):
        f = mdh_unpack(img[0])
        assert f['Machine'] == 0x80 | cls.MODE
        obj = cls.__new__(cls); obj.__dict__.update(flags); Locker.__init__(obj)
        obj.policy, obj.key_type, obj.machine_use, obj.st = (f['MachinePolicy'], f['KeyType'],
                                                             f['MachineUse'], f['State'])
        if not obj.in_error():
            lay = obj._layout()
            for (n, _), v in zip(lay, unpack(img[1], [w for _, w in lay])): obj._set(n, v)
            obj._resolve_key(sks)
        return obj

class AEAD(Locker):
    """<<KLEE-Ascon-AEAD128>>; `dsep_wrong_word` is a negative control."""
    MODE, GRAN, USES_POLICY = 0, 128, True
    MULTI, LAST = (ABSORB, ENCRYPT, DECRYPT), (ENC_LAST, DEC_LAST)
    DST = ((READY,), 16)                                          # `key`; the tag is no source (DER6)
    dsep_wrong_word = False
    def __init__(self, key, policy=0b11, skid=None, **flags):
        Locker.__init__(self)
        self.__dict__.update(flags)
        self.policy, self.key = policy, key & M128
        if skid is not None: self.key_type, self.skid = 1, skid  # MGR15
        self._enter_ready()
    def _clear(self): self.key, self.skid, self.s, self.tag_len, self.last_blk_len = 0, None, [0] * 5, 0, 0
    def _layout(self):
        return ([('skid', 64) if self.key_type else ('key', 128)] + [(f's{i}', 64) for i in range(5)]
                + [('last_blk_len', 16), ('tag_len', 16)])
    def _resolve_key(self, sks):
        if self.key_type:
            ent = (sks or {}).get(self.skid)
            if ent is None: return self.invalidate()             # <<KLEE-MVR-open>>
            self._system_keys(ent)
    def _system_keys(self, ent): self.key = ent
    def _ready_words(self): return 0, 0
    def _nonce(self, N): return N
    def _rate(self): return cat((self.s[1], 64), (self.s[0], 64))
    def _enter_ready(self):
        self.s[:] = [IV_AEAD, sl(self.key, 63, 0), sl(self.key, 127, 64), *self._ready_words()]
        self.tag_len, self.st = 128, READY
    def _setst(self):
        el = lambda Xs, **_: self._c_last(Xs, ENC_LAST, OUTPUT)
        dl = lambda Xs, **_: self._c_last(Xs, DEC_LAST, VERIFY)
        return {(READY, SET_AUX, 'B'): self._c_tag_len, (READY, ABSORB, 'C'): self._c_nonce,
                (ABSORB, ENCRYPT, 'A'): lambda **_: self._c_enter(ENCRYPT, 0b01),
                (ABSORB, DECRYPT, 'A'): lambda **_: self._c_enter(DECRYPT, 0b10),
                (ENCRYPT, ENC_LAST, 'B'): el, (DECRYPT, DEC_LAST, 'B'): dl,
                # GR20 repeats; not into _Hash_Absorb_, _Encrypt_, _Decrypt_ (Machine rule), _Hash_Output_ (MGR18)
                (ENC_LAST, ENC_LAST, 'B'): el, (DEC_LAST, DEC_LAST, 'B'): dl,
                (VERIFY, VERIFY, 'C'): self._c_verify}               # MGR14: the tag comes with the kl.setst
    def _exec(self):
        return {(ABSORB, 'B'): self._x_absorb, (ENCRYPT, 'A'): self._x_encrypt,
                (ENC_LAST, 'A'): self._x_enc_last, (OUTPUT, 'C'): self._x_tag,
                (DECRYPT, 'A'): self._x_decrypt, (DEC_LAST, 'A'): self._x_dec_last}
    def _c_tag_len(self, Xs, **_):                               # the State is unchanged
        if not 64 <= Xs <= 128: return self.invalidate()
        self.tag_len = Xs
    def _c_nonce(self, INPUT, KLLEN, **_):
        if KLLEN < 128: return self.invalidate()
        N = self._nonce(sl(INPUT, 127, 0))                        # MGR5
        self.s[3], self.s[4] = sl(N, 63, 0), sl(N, 127, 64)
        self._c_init()
    def _c_init(self, **_):
        ascon_p(self.s, 12)
        self.s[3] ^= sl(self.key, 63, 0); self.s[4] ^= sl(self.key, 127, 64)
        self.st = ABSORB
    def _c_enter(self, target, bit):
        if not self.policy & bit: return self.invalidate()
        self.s[0 if self.dsep_wrong_word else 4] ^= 1 << 63
        self.st = target
    def _c_last(self, Xs, last, tag):
        if Xs > 127: return self.invalidate()
        if Xs: self.last_blk_len, self.st = Xs, last
        else: self.s[0] ^= 1; self.st = tag
    def _x_absorb(self, INPUT, KLLEN, out, halt, emit=False):
        for i in self._blocks(KLLEN, halt):
            self.s[0] ^= sl(INPUT, i + 63, i); self.s[1] ^= sl(INPUT, i + 127, i + 64)
            if emit: out |= self._rate() << i
            ascon_p(self.s, 8)
        return out
    def _x_encrypt(self, INPUT, KLLEN, out, halt): return self._x_absorb(INPUT, KLLEN, out, halt, True)
    def _x_enc_last(self, INPUT, KLLEN, out, halt):
        L = self.last_blk_len
        if KLLEN < L: return self.invalidate()
        tmp = kl_pad(sl(INPUT, L - 1, 0), L)
        self.s[0] ^= sl(tmp, 63, 0); self.s[1] ^= sl(tmp, 127, 64)
        self.st = OUTPUT
        return sl(self._rate(), L - 1, 0)                         # zeros(128-L) @ tmp[L-1:0]; MGR6
    def _tag(self):
        k0, k1 = sl(self.key, 63, 0), sl(self.key, 127, 64)
        self.s[2] ^= k0; self.s[3] ^= k1
        ascon_p(self.s, 12)
        self.s[3] ^= k0; self.s[4] ^= k1
        return sl(cat((self.s[4], 64), (self.s[3], 64)), self.tag_len - 1, 0)
    def _x_tag(self, *_): t = self._tag(); self.st = SUCCESS; return t
    def _x_decrypt(self, INPUT, KLLEN, out, halt):
        for i in self._blocks(KLLEN, halt):
            C = sl(INPUT, i + 127, i)
            out |= (self._rate() ^ C) << i
            self.s[0], self.s[1] = sl(C, 63, 0), sl(C, 127, 64)
            ascon_p(self.s, 8)
        return out
    def _x_dec_last(self, INPUT, KLLEN, out, halt):
        L = self.last_blk_len
        if KLLEN < L: return self.invalidate()
        P = sl(self._rate() ^ INPUT, L - 1, 0)
        S_r = self._rate() ^ kl_pad(P, L)
        self.s[0], self.s[1], self.st = sl(S_r, 63, 0), sl(S_r, 127, 64), VERIFY
        return P
    def _c_verify(self, INPUT, KLLEN, **_):
        if KLLEN < 128: return self.invalidate()                  # MGR5
        self.st = SUCCESS if sl(INPUT, self.tag_len - 1, 0) == self._tag() else FAILURE
    def derive_dest(self, data): self.key = b2v(data); self._enter_ready()

class AEADNonce(AEAD):
    """<<KLEE-Ascon-AEAD128-wsn>>: nonce in the PI, Form A into _Hash_Absorb_."""
    MODE = 1
    def __init__(self, key, nonce, policy=0b11, skid=None): super().__init__(key, policy, skid, nonce=nonce & M128)
    def _clear(self): super()._clear(); self.nonce = 0
    def _layout(self): return super()._layout() + [('nonce', 128)]     # Pos. ix
    def _ready_words(self): return sl(self.nonce, 63, 0), sl(self.nonce, 127, 64)
    def _setst(self):
        c = super()._setst()
        del c[(READY, ABSORB, 'C')]
        c[(READY, ABSORB, 'A')] = self._c_init
        return c

class AEADMask(AEAD):
    """<<KLEE-Ascon-AEAD128-N-masking>>: key K1, nonce N replaced by N xor K2."""
    MODE, DST = 2, ((READY,), 32)                                # `K1 || K2`
    legacy_layout = False                                         # negative control: no last_blk_len
    def __init__(self, K1, K2, policy=0b11, skid=None): super().__init__(K1, policy, skid, K2=K2 & M128)
    def _clear(self): super()._clear(); self.K2 = 0
    def _nonce(self, N): return N ^ self.K2
    def _system_keys(self, ent): self.key, self.K2 = ent          # MGR16
    def derive_dest(self, data): self.key, self.K2 = b2v(data[:16]), b2v(data[16:]); self._enter_ready()
    def _layout(self):
        f = [('skid', 64), ('K2', 0)] if self.key_type else [('key', 128), ('K2', 128)]
        f += [(f's{i}', 64) for i in range(5)]
        return f + ([] if self.legacy_layout else [('last_blk_len', 16)]) + [('tag_len', 16)]

class Hash256(Locker):
    """<<KLEE-Ascon-Hash256>>; countdown in _MachineUse_[1:0]."""
    MODE, IV, GRAN, COUNTDOWN = 3, IV_HASH, 64, 3
    MULTI = (ABSORB, FINALIZE)
    SRC, DST = (FINALIZE,), ((ABSORB,), None)                     # kl.exec output / input
    def __init__(self): Locker.__init__(self); self._enter_ready()
    def _clear(self): self.s = [0] * 5
    def _layout(self): return [(f's{i}', 64) for i in range(5)]
    def _enter_ready(self): self.s[:] = ascon_p([self.IV, 0, 0, 0, 0], 12); self.st = READY
    def _setst(self): return {(READY, ABSORB, 'A'): self._c_absorb, (ABSORB, ABSORB, 'A'): self._c_absorb,   # GR20
                              (ABSORB, FINALIZE, 'A'): self._c_finalize}
    def _exec(self): return {(ABSORB, 'B'): self._x_absorb, (FINALIZE, 'C'): self._x_squeeze}
    def _c_absorb(self, **_): self.st = ABSORB
    def _c_finalize(self, **_): self.countdown, self.st = self.COUNTDOWN, FINALIZE
    @property
    def countdown(self): return sl(self.machine_use, 1, 0)
    @countdown.setter
    def countdown(self, v): self.machine_use = (self.machine_use & ~0b11) | v
    def _x_absorb(self, INPUT, KLLEN, out, halt):
        for i in self._blocks(KLLEN, halt):
            self.s[0] ^= sl(INPUT, i + 63, i); ascon_p(self.s, 12)
        return out
    def _x_squeeze(self, INPUT, KLLEN, out, halt):
        for i in self._blocks(KLLEN, halt):
            if self.countdown != 3: ascon_p(self.s, 12)
            out |= self.s[0] << i
            if self.countdown == 0: self.st = SUCCESS; break      # the unwritten bits are cleared
            self.countdown -= 1
        return out
    def avail(self): return 8 * (self.countdown + 1)              # remaining output (DER1 item 5)
    def derive_source(self, n):                                   # DER8: whole blocks, excess discarded
        KL = -(-n // 8) * 64
        return v2b(self._x_squeeze(0, KL, 0, None), KL // 8)[:n]
    def derive_dest(self, data): self._x_absorb(b2v(data), 8 * len(data), 0, None)

class XOF(Hash256):
    """<<KLEE-Ascon-XOF128>>: the countdown step precedes each output word; never _Success_."""
    MODE, IV, COUNTDOWN = 4, IV_XOF, 1
    def _x_squeeze(self, INPUT, KLLEN, out, halt):
        for i in self._blocks(KLLEN, halt):
            if self.countdown == 0: ascon_p(self.s, 12)
            self.countdown = 0
            out |= self.s[0] << i
        return out
    def avail(self): return 1 << 60

class CXOF(XOF):
    """<<KLEE-Ascon-CXOF128>>."""
    MODE, IV = 5, IV_CXOF

class Secret:
    """A DER5 source: an ML-KEM `sharedkey` or ECC `SecondPt` in a source State (no MDH policies modelled)."""
    SRC, st = (SUCCESS,), SUCCESS
    def __init__(self, data): self.data = data
    def in_error(self): return False
    def invalidate(self): self.st = INVALID
    def avail(self): return len(self.data)
    def derive_source(self, n): return self.data[:n].ljust(n, b'\0')    # DER8

def kl_derive(dst, src, length):
    """kl.derive between the endpoints of <<KLEE-derive-endpoints>> under DER1-DER8."""
    if src.in_error() or dst.in_error(): return                   # GR16
    states, n = dst.DST or ((), None)                             # no endpoint: offending locker only
    bad = [c for c, ok in ((src, src.st in (src.SRC or ())), (dst, dst.st in states and not (n and dst.key_type)))
           if not ok]
    for c in bad: c.invalidate()                                  # DER1 items 1-2, DER4
    if bad: return
    # DER1 item 3 always holds here: DER5 (secret), DER6 (hash/XOF output, key derivation included)
    if (n and (length < n or src.avail() < n)) or (not n and length % (dst.GRAN // 8)):
        return dst.invalidate()                                   # DER1 items 4, 5
    eff = n or length                                             # DER8
    if eff: dst.derive_dest(src.derive_source(eff))

def kl_restrictl(cc, machine_policy, machine_use=0):               # _MachineUse_: not changeable
    if machine_use: return cc.invalidate()
    if not machine_policy: return
    dropped = cc.policy & ~machine_policy
    if (not cc.USES_POLICY or machine_policy & ~cc.policy
            or (dropped & 0b01 and cc.st in (ENCRYPT, ENC_LAST, OUTPUT))
            or (dropped & 0b10 and cc.st in (DECRYPT, DEC_LAST, VERIFY))):
        return cc.invalidate()
    cc.policy = machine_policy

def kl_restricth(cc, aux_info):                                   # not a field kl.restricth may change
    if aux_info: cc.invalidate()

def build_pi(mode, fields, policy=0, key_type=0):
    return pack([(mdh_pack(Machine=0x80 | mode, MachinePolicy=policy, KeyType=key_type), 128)] + fields)

def provision(pi, sks=None):
    v = b2v(pi)
    f = mdh_unpack(sl(v, 127, 0))
    assert f['Machine'] >> 4 == 8 and f['State'] == UNCONF
    mode, pol, kt = f['Machine'] & 0xF, f['MachinePolicy'], f['KeyType']
    if mode >= 3: return (Hash256, XOF, CXOF)[mode - 3]()           # the PI is the MDH alone
    kw = 64 if kt else 128                                        # MGR15
    k = sl(v, 127 + kw, 128)
    skid, ent = (k, (sks or {}).get(k)) if kt else (None, None)
    if mode == 0: cc = AEAD((ent or 0) if kt else k, pol, skid)
    elif mode == 1: cc = AEADNonce((ent or 0) if kt else k, sl(v, 255 + kw, 128 + kw), pol, skid)
    else: cc = AEADMask(*((ent or (0, 0)) if kt else (k, sl(v, 383, 256))), pol, skid)
    if kt and ent is None: cc.invalidate()                        # <<KLEE-MVR-open>>
    return cc

# ------------------------------------------------------------------ drivers
class Run:
    """Issues instructions on a locker; `after` runs after each one and may replace the locker."""
    def __init__(self, cc, after): self.cc, self.after = cc, after
    def __call__(self, fn, *a, **kw):
        r = getattr(self.cc, fn)(*a, **kw)
        if self.after: self.cc = self.after(self.cc)
        if self.cc.in_error(): raise Invalid(self.cc.st)
        return r

def aead_run(cc, decrypt, nonce, ad, data, tag=0, tag_len=128, ad_chunk=1, pt_chunk=1,
             last_block_128=False, after=None, nkl=128):
    """The <<KLEE-Ascon-AEAD128>> sequence on `cc` (nonce None: Form A into _Hash_Absorb_); `after` runs
    after every instruction and may replace the locker.  Returns (cc, data out, tag | verdict)."""
    step = Run(cc, after)
    if tag_len != 128: step('setst', SET_AUX, 'B', Xs=tag_len)
    if nonce is None: step('setst', ABSORB, 'A')
    else: step('setst', ABSORB, 'C', INPUT=nonce if isinstance(nonce, int) else b2v(nonce), KLLEN=nkl)
    a = pad_bytes(ad, 16) if ad else b''
    for chunk in (a[off:off + 16 * ad_chunk] for off in range(0, len(a), 16 * ad_chunk)):
        step('exec', 'B', b2v(chunk), 8 * len(chunk))
    step('setst', DECRYPT if decrypt else ENCRYPT, 'A')
    full, out = len(data) // 16 * 16, b''
    for off in range(0, full, 16 * pt_chunk):
        chunk = data[off:min(off + 16 * pt_chunk, full)]
        out += v2b(step('exec', 'A', b2v(chunk), 8 * len(chunk), out=ONES & mask(8 * len(chunk))), len(chunk))
    last, n = data[full:], 8 * (len(data) - full)
    step('setst', DEC_LAST if decrypt else ENC_LAST, 'B', Xs=n)
    if last:                                                      # last_block_128: junk beyond last_blk_len
        o = (step('exec', 'A', b2v(last) | ((0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a << n) & M128), 128, out=M128)
             if last_block_128 else step('exec', 'A', b2v(last), n))
        out += v2b(sl(o, n - 1, 0), len(last))
    if decrypt: step('setst', VERIFY, 'C', INPUT=tag, KLLEN=128); return step.cc, out, step.cc.st == SUCCESS
    return step.cc, out, v2b(step('exec', 'C', 0, 128, out=M128), 16)[:(tag_len + 7) // 8]

def aead_run_bits(cc, decrypt, N, A, alen, D, dlen, T=0, tag_len=128):
    """aead_run on bit strings; the final dlen mod 128 bits come in whole bytes.  Returns (out, tag|verdict, State)."""
    if tag_len != 128: cc.setst(SET_AUX, 'B', Xs=tag_len)
    cc.setst(ABSORB, 'C', INPUT=N, KLLEN=128)
    if alen: cc.exec('B', _pad(A, alen), -(-(alen + 1) // 128) * 128)
    cc.setst(DECRYPT if decrypt else ENCRYPT, 'A')
    nfull, Xs = dlen // 128, dlen % 128
    out = cc.exec('A', sl(D, 128 * nfull - 1, 0), 128 * nfull) if nfull else 0
    cc.setst(DEC_LAST if decrypt else ENC_LAST, 'B', Xs=Xs)
    if Xs: out |= sl(cc.exec('A', D >> (128 * nfull), -(-Xs // 8) * 8), Xs - 1, 0) << (128 * nfull)
    if decrypt: cc.setst(VERIFY, 'C', INPUT=T, KLLEN=128); return out, cc.st == SUCCESS, cc.st
    return out, cc.exec('C', 0, 128), cc.st

def enc(ad, pt, key=None, dsep_wrong_word=False, **kw):
    cc, ct, tag = aead_run(AEAD(b2v(key or KAT_KEY), dsep_wrong_word=dsep_wrong_word), False, KAT_NONCE, ad, pt, **kw)
    return ct + tag, cc.st

def dec(ad, blob, **kw):
    cc, pt, ok = aead_run(AEAD(b2v(KAT_KEY)), True, KAT_NONCE, ad, blob[:-16], tag=b2v(blob[-16:]), **kw)
    return pt, ok, cc.st

LAST5, C166, T166 = h("2021222324"), h("e8c3deee24"), h("21812a398a8ff074c8b7da46c82a94a7")   # Count=166

def drive(cc, target, dec_=False, xs=40):
    """Drive a fresh Ascon-AEAD128 locker (empty AD, Count=166's 5-byte block) up to `target`."""
    order = [READY, ABSORB, DECRYPT if dec_ else ENCRYPT, DEC_LAST if dec_ else ENC_LAST,
             VERIFY if dec_ else OUTPUT, SUCCESS]
    steps = [lambda: cc.setst(ABSORB, 'C', INPUT=b2v(KAT_NONCE), KLLEN=128),
             lambda: cc.setst(order[2], 'A'), lambda: cc.setst(order[3], 'B', Xs=xs),
             lambda: cc.exec('A', b2v(C166 if dec_ else LAST5), 40), lambda: cc.exec('C', 0, 128)]
    for s in steps[:order.index(target)]: s()
    assert cc.st == target, (cc.st, target)
    return cc

def aead_to(target, policy=0b11): return drive(AEAD(K, policy=policy), target, target in (DECRYPT, DEC_LAST, VERIFY))

def sponge_run(cc, msg, outlen, prefix=b'', absorb_chunk=1, squeeze=(64,), after=None):
    """Form A into _Hash_Absorb_, the caller-padded message (KLLEN = 64 * absorb_chunk), Form A into
    _Hash_Finalize_, then Form C with the KLLENs in `squeeze` (last one repeated).  Returns (out, cc)."""
    step = Run(cc, after)
    step('setst', ABSORB, 'A')
    m = prefix + pad_bytes(msg, 8)
    for chunk in (m[off:off + 8 * absorb_chunk] for off in range(0, len(m), 8 * absorb_chunk)):
        step('exec', 'B', b2v(chunk), 8 * len(chunk))
    step('setst', FINALIZE, 'A')
    out, k = b'', 0
    while len(out) < outlen and step.cc.st == FINALIZE:
        n, k = squeeze[min(k, len(squeeze) - 1)], k + 1
        out += v2b(step('exec', 'C', 0, n, out=ONES & mask(n)), n // 8)
    return out[:outlen], step.cc

def at_finalize(cls, msg=b''):
    cc, m = cls(), pad_bytes(msg, 8)
    cc.setst(ABSORB, 'A'); cc.exec('B', b2v(m), 8 * len(m)); cc.setst(FINALIZE, 'A')
    return cc

def migrate(cls, sks=None, **flags): return lambda cc: cls.import_(cc.export(), sks=sks, **flags)   # export, import

# ------------------------------------------------------------------ vectors (ascon-c genkat files)
# crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt: (Count, AD, PT, CT || 128-bit tag, description)
AEAD_KAT = [
    (1, "", "", "4f9c278211bec9316bf68f46ee8b2ec6", "empty AD and PT (Xs = 0 pad path, no AD permutation)"),
    (17, "303132333435363738393a3b3c3d3e3f", "", "e4230cdb8330ee9dc0cfd7c7b346e6dc", "one AD block, empty PT"),
    (166, "", "2021222324", "e8c3deee2421812a398a8ff074c8b7da46c82a94a7", "empty AD, 5-byte PT (Enc_Last_Block)"),
    (235, "303132", "20212223242526", "66d0d52bf401c64cfccea25bb53cef292120521d154bf4", "partial AD and PT"),
    (511, "303132333435363738393a3b3c3d3e", "202122232425262728292a2b2c2d2e",
     "20fd19dabc1a5cc449a621d34dac60d7f316f7f9aee44f263c8d7b7094c199", "15-byte AD and PT (one short of the rate)"),
    (529, "", "202122232425262728292a2b2c2d2e2f",
     "e8c3deee246cc5eae3e872313897a2bb9eaa915c9dd3245d77048f24d46d27a7", "empty AD, one PT block (Xs = 0 pad path)"),
    (545, "303132333435363738393a3b3c3d3e3f", "202122232425262728292a2b2c2d2e2f",
     "6373ebb28be97c9bac090cf399c13ef13abfc0d209e8f4844c90814d13f32c59", "one AD block, one PT block"),
    (579, "303132333435363738393a3b3c3d3e3f40", "202122232425262728292a2b2c2d2e2f30",
     "bf77c71b3de9f1c5b372ef273a08e89be9d507d7b3c2aee97911e791f7970d6635", "17-byte AD and PT (1-byte last blocks)"),
    (1055, "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e",
     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e",
     "4b392e5fa60e0cbbca547db96e3262bd8382d6c0e608e24f441aaafc4726e57640e8294794dd3c2aa021192b091de3",
     "31-byte AD and PT: multi-block with partial final block"),
    (1057, "", "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
     "e8c3deee246cc5eae3e872313897a2bb6089aa3e15e80307970f2d1f006654c2aaa5fa172cb9f07d07463cefc7440bc1",
     "empty AD, two PT blocks (Xs = 0 pad path, multi-block)"),
    (1089, "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
     "cb34d04660a66dbfbe9c856601f5b8aa51a499b55ac8f7fbefbc331a613ee9cdfd191750a47f211c0a15ed28173d7caa",
     "two AD blocks, two PT blocks"),
]
KAT_KEY, KAT_NONCE = h("000102030405060708090a0b0c0d0e0f"), h("101112131415161718191a1b1c1d1e1f")

# crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt
HASH_KAT = [
    (1,  "", "0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2"),
    (2,  "00", "0728621035af3ed2bca03bf6fde900f9456f5330e4b5ee23e7f6a1e70291bc80"),
    (9,  "0001020304050607", "b88e497ae8e6fb641b87ef622eb8f2fca0ed95383f7ffebe167acf1099ba764f"),
    (33, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "bd9d3d60a66b53868eab2a5c74539a518a1f60f01eb176c60e43dee81680b33e"),
    (65, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
     "a6f241bea5d16405812c06019d9f72d60132bd7c089c60549b2e56bb01c64f48"),
]

# crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt  (MD is 64 bytes = 512 bits)
XOF_KAT = [
    (1,  "", "473d5e6164f58b39dfd84aacdb8ae42ec2d91fed33388ee0d960d9b3993295c6"
             "ad77855a5d3b13fe6ad9e6098988373af7d0956d05a8f1665d2c67d1a3ad10ff"),
    (2,  "00", "51430e0438ecdf642b393630d977625f5f337656ba58ab1e960784ac32a16e0d"
               "446405551f5469384f8ea283cf12e64fa72c426bfebaea3aa1529e2c4ab23a2f"),
    (9,  "0001020304050607", "8d1886f5d3ec4af8d15b44bc62b74da6ea91bc28fb82f9c34079b5ed6e38b6c9"
                          "51803d7dfb3c5e512a0ef5e4060062a6fd067f9c73ef9bee527411bda67fc896"),
    (33, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "2e5f3403f4171471cc7934b51982cece8d6628435db70e89880f3be4e0b7b052"
     "32dfe63c44a836d771337c9c5a2688d1b71ecabe0d5c2006fef36ef3186138ad"),
    (65, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
     "0865c2fa92c71058e79e5c4214f3a1505540411586920536ccee85fbf2940b9f"
     "0131385ffe92f15f35bd35373f14d8bf11f078d9850096016f857d27575da423"),
]

# crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt
CXOF_KAT = [
    (1,   "", "", "4f50159ef70bb3dad8807e034eaebd44c4fa2cbbc8cf1f05511ab66cdcc52990"
                  "5ca12083fc186ad899b270b1473dc5f7ec88d1052082dcdfe69fb75d269e7b74"),
    (2,   "", "10", "0c93a483e7d574d49fe52cce03ee646117977d57a8aa57704ab4daf44b501430"
                    "ff6ac11a5d1fd6f2154b5c65728268270c8bb578508487b8965718ada6272fd6"),
    (18,  "", "101112131415161718191a1b1c1d1e1f20",
     "f74d02f0215e2c5e71a89e2315a533f64843223a368df68b0f2d3603bdba664f"
     "2297abd5ea4edf25004d7c7e1093c53212eb7c231a6142aa9fbe3a74cff7a378"),
    (35,  "00", "10", "63fa8ba86382f2d544580f51322d080424b42c556eb74503cd73cf052bb993bd"
                      "6f5210984c71c9c445f43ccc5b158226e509bd339cd634414377f79411aa8d5c"),
    (100, "000102", "", "1093da88c318f6d9f26e1a222dbc30016d03953edfd9ba3d75d7d8451b9df542"
                        "d7d00745922b271a911fdc5209f6e63fc3d3a279c65b78d4f3c84bf3aaeb8493"),
    (290, "0001020304050607", "101112131415161718191a1b1c1d1e1f202122232425262728",
     "3e0fe4a71142cc010189456cde8b13b753bc9352130c93e33f082cf398492841"
     "ec0ca2f96d03a9e56e7b84523771aaa726d7fd32e0d82882c7709cac22be8f44"),
]

# ------------------------------------------------------------------ checks
K, NN = b2v(KAT_KEY), b2v(KAT_NONCE)
K1, K2 = h("0f0e0d0c0b0a09080706050403020100"), h("a5a4a3a2a1a09f9e9d9c9b9a99989796")
K1v, K2v, Nm = b2v(K1), b2v(K2), bxor(KAT_NONCE, K2)
SKID_A, SKID_M = 0x1122334455667788, 0x0000000000abcdef
SKS = {SKID_A: K, SKID_M: (K1v, K2v)}                             # a toy System Key Store
ad579, pt579, blob579 = (h(x) for x in AEAD_KAT[7][1:4])
ct579, tag579 = blob579[:-16], blob579[-16:]
CTTS = [h(v[3]) for v in AEAD_KAT]

def seq(n, m, a): return bytes((i * m + a) & 0xff for i in range(n))
def after(cc, act): act(cc); return cc
def ref579(key, nonce=KAT_NONCE): return ref_aead_encrypt(key, nonce, ad579, pt579)
def seal(cc, nonce=KAT_NONCE, ad=ad579, pt=pt579, **kw):          # CT || tag (Count=579 by default)
    _, ct, tag = aead_run(cc, False, nonce, ad, pt, **kw)
    return ct + tag

section('Permutation and constants (SP 800-232 Sec. 3, eq. (79), Tables 5, 12-14)')
check('round constants from the nibble rule == Table 5; ASCON(12) starts at 0xf0, ASCON(8) at 0xb4', True,
      (tuple(RC16), RC16[4], RC16[8]), (TABLE5, 0xf0, 0xb4))
for name, iv in IVS.items():
    check(f'{name}: IV quoted by the spec == eq. (79) with Table 13 == Table 14', True, (iv, iv),
          (iv_eq79(*TABLE13[name]), TABLE14[name]))
    if name in TABLE12:
        check(f'{name}: Ascon-p[12](IV || 0^256) == Table 12', True, tuple(ascon_p([iv, 0, 0, 0, 0], 12)),
              TABLE12[name])

section('SP 800-232 references vs the official vectors')
for count, ad, pt, ctt, _ in AEAD_KAT:
    check(f'ref AEAD Count={count}: Algorithms 3/4 encrypt and decrypt', True,
          (ref_aead_encrypt(KAT_KEY, KAT_NONCE, h(ad), h(pt)).hex(),
           ref_aead_decrypt(KAT_KEY, KAT_NONCE, h(ad), h(ctt))),
          (ctt, (True, h(pt))))
for lab, fn, kat in (('Hash256', ref_hash256, HASH_KAT), ('XOF128', ref_xof128, XOF_KAT),
                     ('CXOF128', ref_cxof128, CXOF_KAT)):
    for count, *args, md in kat:
        check(f'ref {lab} Count={count}', True, fn(*map(h, args)).hex(), md)

section('<<KLEE-Ascon-AEAD128>> encryption and decryption')
info('the tag States take KLLEN = 128: the tag is not a "last block" exempt from the granularity')
for count, ad, pt, ctt, desc in AEAD_KAT:
    A, P, blob = h(ad), h(pt), h(ctt)
    check(f'enc Count={count} {desc}: plain / KLLEN 256 (AD) and 384 (PT) / truncated final INPUT', True,
          [enc(A, P), enc(A, P, ad_chunk=2, pt_chunk=3), enc(A, P, last_block_128=True)], [(blob, SUCCESS)] * 3)
    bad_tag = blob[:-1] + bytes([blob[-1] ^ 0x80])
    bad_ct = bytes([blob[0] ^ 1]) + blob[1:] if P else bad_tag
    check(f'dec Count={count}: plain / chunked + truncated final INPUT / tampered tag / tampered ciphertext',
          True, [dec(A, blob), dec(A, blob, ad_chunk=2, pt_chunk=3, last_block_128=True), dec(A, bad_tag)[1:],
                 dec(A, bad_ct)[1:]], [(P, True, SUCCESS)] * 2 + [(False, FAILURE)] * 2)
o = aead_to(ENC_LAST).exec('A', b2v(LAST5) | 0xabcdef << 40, 128, out=M128)
check('_Enc_Last_Block_: OUTPUT = zeros(128-last_blk_len) @ tmp[last_blk_len-1:0]', True,
      (sl(o, 39, 0), o >> 40), (b2v(C166), 0))
rt = True
for ad, pt in ((seq(la, 11, 1), seq(lp, 7, 3)) for la in (0, 5, 16, 23) for lp in range(48)):
    blob, st = enc(ad, pt)
    rt &= (st, blob, dec(ad, blob)) == (SUCCESS, ref_aead_encrypt(KAT_KEY, KAT_NONCE, ad, pt), (pt, True, SUCCESS))
check('192 AD/PT length pairs: KLEE == reference, decrypt(encrypt(x)) == x', rt)
pat = b2v(seq(64, 29, 7))
for alen in (0, 3, 133):
    good = True
    for dlen in (1, 13, 64, 127, 141, 255):
        A, D = pat & mask(alen), (pat >> 11) & mask(dlen)
        C, T, st = aead_run_bits(AEAD(K), False, NN, A, alen, D, dlen)
        good &= ((C, T, st, aead_run_bits(AEAD(K), True, NN, A, alen, C, dlen, T=T))
                 == (*ref_aead_bits_enc(K, NN, A, alen, D, dlen), SUCCESS, (D, True, SUCCESS)))
    check(f'AD of {alen} bits, data of 1/13/64/127/141/255 bits: == Algorithms 3/4, round trip', good)

section('tag_len and last_blk_len (Form B kl.setst)')
A_, P_ = b2v(h("30313233")), b2v(h("202122232425262728292a2b2c2d2e2f30"))
for tl in (64, 65, 96, 100, 127, 128):
    C, T, st = aead_run_bits(AEAD(K), False, NN, A_, 32, P_, 136, tag_len=tl)
    vrf = lambda T: aead_run_bits(AEAD(K), True, NN, A_, 32, C, 136, T=T, tag_len=tl)
    check(f'tag_len={tl}: == T[tag_len-1:0]; verify ignores INPUT above tag_len, rejects a flip of bit tag_len-1',
          True, ((C, T, st), vrf(T | (0x3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c << tl) & M128), vrf(T ^ 1 << (tl - 1))[1:]),
          ((*ref_aead_bits_enc(K, NN, A_, 32, P_, 136, lam=tl), SUCCESS), (P_, True, SUCCESS), (False, FAILURE)))
res = [(c.st, c.tag_len) for c in (AEAD(K).setst(SET_AUX, 'B', Xs=tl) for tl in (0, 8, 32, 63, 129, 255, 96, 128))]
check('tag_len outside 64..128 -> _Invalid_; 96 and 128 are set and _State_ stays _Ready_', True, res,
      [(INVALID, 0)] * 6 + [(READY, 96), (READY, 128)])
res = [(c.st, c.last_blk_len) for c in (aead_to((ENCRYPT, DECRYPT)[d]).setst((ENC_LAST, DEC_LAST)[d], 'B', Xs=xs)
       for xs, d in ((128, 0), (129, 0), (255, 0), (128, 1), (129, 1), (255, 1), (0, 0), (1, 0), (127, 0), (0, 1),
                     (127, 1)))]
check('Xs > 127 -> _Invalid_; Xs = 0 -> _Hash_Output_/_Hash_Verify_; else last_blk_len <- Xs', True, res,
      [(INVALID, 0)] * 6 + [(OUTPUT, 0), (ENC_LAST, 1), (ENC_LAST, 127), (VERIFY, 0), (DEC_LAST, 127)])
cc = aead_to(ENC_LAST)
check('KLLEN = 32 < last_blk_len = 40 -> _Invalid_, output window zeroed', True,
      (cc.exec('A', b2v(LAST5), 32, out=0xffffffff), cc.st), (0, INVALID))
info('_Encrypt_ -> _Hash_Output_ is taken only through the Xs = 0 clause; a direct kl.setst is MGR1')
check('kl.setst #kl_state_hash_output from _Encrypt_ -> _Invalid_', True, aead_to(ENCRYPT).setst(OUTPUT, 'A').st,
      INVALID)
check('MGR18: a same-State kl.setst into _Hash_Output_ -> _Invalid_', True, aead_to(OUTPUT).setst(OUTPUT, 'A').st,
      INVALID)
check('same-State kl.setst into _Hash_Absorb_ (Form C, and Form A with a set nonce), _Encrypt_, _Decrypt_ '
      '-> _Invalid_', True,
      [aead_to(ABSORB).setst(ABSORB, 'C', INPUT=NN, KLLEN=128).st, aead_to(ENCRYPT).setst(ENCRYPT, 'A').st,
       aead_to(DECRYPT).setst(DECRYPT, 'A').st,
       provision(build_pi(1, [(K, 128), (NN, 128)], policy=0b11)).setst(ABSORB, 'A').setst(ABSORB, 'A').st],
      [INVALID] * 4)
cc = AEAD(K).setst(ABSORB, 'C', INPUT=NN, KLLEN=128).setst(ENCRYPT, 'A').setst(ENC_LAST, 'B', Xs=16)
ct = v2b(cc.setst(ENC_LAST, 'B', Xs=40).exec('A', b2v(LAST5), 40), 16)[:5]
check('GR20 repeats admitted: _Enc_Last_Block_ (the second Xs replaces the first, Count=166 holds); '
      'MGR14: the same-State Form C kl.setst into _Hash_Verify_ carries the tag (Count=166: _Success_)', True,
      (ct + v2b(cc.exec('C', 0, 128), 16), aead_to(VERIFY).setst(VERIFY, 'C', INPUT=b2v(T166), KLLEN=128).st),
      (ref_aead_encrypt(KAT_KEY, KAT_NONCE, b'', LAST5), SUCCESS))

section('General rules on Ascon-AEAD128')
ca, cc = AEAD(K), AEAD(K)
res = [(ca.exec('A', 0, 128, out=M128), ca.st), (cc.exec('B', 0, 128), cc.st)]
o = cc.exec('A', 1, 128, out=M128)
cc.setst(READY)
check('GR18: Form A/B kl.exec in _Ready_ -> _Invalid_, output zeroed; GR9/11: Content cleared, export is '
      'the MDH only; GR11: kl.exec and kl.setst are no-ops', True,
      (res, cc.key, cc.s, cc.tag_len, cc.export()[1], o, cc.st),
      ([(0, INVALID)] * 2, 0, [0] * 5, 0, b'', 0, INVALID))
res = [after(aead_to(start), act).st for start, act in (
    (ABSORB, lambda c: c.setst(SET_AUX, 'B', Xs=96)), (ABSORB, lambda c: c.exec('A', 0, 128)),
    (ENCRYPT, lambda c: c.exec('B', 0, 128)), (DECRYPT, lambda c: c.exec('C', 0, 128)),
    (ABSORB, lambda c: c.setst(ENC_LAST, 'B', Xs=8)), (ENCRYPT, lambda c: c.setst(DECRYPT, 'A')),
    (OUTPUT, lambda c: c.exec('A', 0, 128)), (VERIFY, lambda c: c.exec('C', 0, 128)),
    (ENCRYPT, lambda c: c.setst(OUTPUT, 'A')), (DECRYPT, lambda c: c.setst(VERIFY, 'A')),
    (VERIFY, lambda c: c.exec('B', b2v(T166), 128)))]
cc = aead_to(SUCCESS)
res.append((cc.exec('C', 0, 128, out=M128), cc.st))
check('MGR1: tag_len in _Hash_Absorb_, wrong Forms and transitions, including _Encrypt_ -> _Hash_Output_ and '
      '_Decrypt_ -> _Hash_Verify_ without the padded last block, and a kl.exec in _Hash_Verify_ (MGR14) -> _Invalid_; '
      'GR23: kl.exec in _Success_ (not a XOF) -> _Invalid_, output zeroed', True, res, [INVALID] * 11 + [(0, INVALID)])
res = []
for start, form, n in ((ABSORB, 'B', 120), (ENCRYPT, 'A', 136), (DECRYPT, 'A', 64)):
    cc = aead_to(start)
    o = cc.exec(form, mask(n), n, out=mask(n))
    res.append((cc.st, o if form == 'A' else 0))
check('MGR2: KLLEN 120 (absorb), 136 (encrypt), 64 (decrypt) -> _Invalid_, output zeroed', True, res,
      [(INVALID, 0)] * 3)
check('nonce with KLLEN = 64 -> _Invalid_; MGR5: KLLEN = 256 with junk above bit 127 == Count=579', True,
      (AEAD(K).setst(ABSORB, 'C', INPUT=NN, KLLEN=64).st, seal(AEAD(K), NN | 0xdeadbeef << 150, nkl=256)),
      (INVALID, blob579))
cc, c2 = aead_to(ENC_LAST), aead_to(DEC_LAST)
o, t = cc.exec('A', b2v(LAST5), 256, out=mask(256)), cc.exec('C', 0, 256, out=mask(256))
o2 = c2.exec('A', b2v(C166), 256, out=mask(256))
c2.setst(VERIFY, 'C', INPUT=b2v(T166), KLLEN=128)
t3 = drive(aead_to(OUTPUT).setst(READY).setst(SET_AUX, 'B', Xs=64), OUTPUT).exec('C', 0, 128, out=M128)
check('MGR6: KLLEN = 256 into _Enc_Last_Block_, _Hash_Output_, _Dec_Last_Block_ clears OUTPUT above bit 127; '
      'tag_len = 64 clears OUTPUT[127:64]', True,
      (sl(o, 39, 0), o >> 40, sl(t, 127, 0), t >> 128, sl(o2, 39, 0), o2 >> 40, c2.st, t3 >> 64, v2b(t3, 8)),
      (b2v(C166), 0, b2v(T166), 0, b2v(LAST5), 0, SUCCESS, 0, T166[:8]))
cc, ct, tag = aead_run(AEAD(K), False, KAT_NONCE, ad579, pt579, tag_len=64)
st1 = (ct + tag, cc.st)
st2 = (cc.setst(READY).st, list(cc.s), cc.tag_len)
ct2 = seal(cc)
c2, _, ok = aead_run(AEAD(K), True, KAT_NONCE, ad579, ct579, tag=b2v(tag579) ^ 1 << 127)
st3 = (ok, c2.st)
c2, rec, ok = aead_run(c2.setst(READY), True, KAT_NONCE, ad579, ct579, tag=b2v(tag579))
c3 = aead_to(ENCRYPT)
c3.exec('A', 0, 256)
check('GR21: _Success_ (64-bit tag) -> _Ready_ re-initializes (tag_len <- 128); _Failure_ -> _Ready_ -> genuine '
      'tag; _Encrypt_ -> _Ready_ -> Count=579', True, (st1, st2, ct2, st3, (rec, ok, c2.st), seal(c3.setst(READY))),
      ((blob579[:-8], SUCCESS), (READY, [IV_AEAD, sl(K, 63, 0), sl(K, 127, 64), 0, 0], 128), blob579,
       (False, FAILURE), (pt579, True, SUCCESS), blob579))

section('_MachinePolicy_, kl.restrictl and kl.restricth')
_, rec, ok = aead_run(AEAD(K, policy=0b10), True, KAT_NONCE, ad579, ct579, tag=b2v(tag579))
res = [(rec, ok)] + [(c.st, c.policy) for c in (after(aead_to(start, policy=pol), act) for pol, start, act in (
    (0b10, ABSORB, lambda c: c.setst(ENCRYPT, 'A')), (0b01, ABSORB, lambda c: c.setst(DECRYPT, 'A')),
    (0b11, READY, lambda c: (kl_restrictl(c, 0b10), c.setst(ABSORB, 'C', INPUT=NN, KLLEN=128), c.setst(ENCRYPT, 'A'))),
    (0b11, ENCRYPT, lambda c: kl_restrictl(c, 0b10)), (0b11, OUTPUT, lambda c: kl_restrictl(c, 0b10)),
    (0b01, READY, lambda c: kl_restrictl(c, 0b11)), (0b11, ABSORB, lambda c: kl_restrictl(c, 0b01)),
    (0b11, READY, lambda c: kl_restricth(c, 0x0001))))]
check('decryption-only locker decrypts but cannot _Encrypt_ (and vice versa); kl.restrictl narrows, never '
      'enables, and not during the operation it disables; kl.restricth on _AuxInfo_ -> _Invalid_', True, res,
      [(pt579, True), (INVALID, 0b10), (INVALID, 0b01), (INVALID, 0b10), (INVALID, 0b11), (INVALID, 0b11),
       (INVALID, 0b01), (ABSORB, 0b01), (INVALID, 0b11)])

section('Resumption (<<KLEE-IRR-block-iterated-instructions>>, <<KLEE-CSR-klstart>>)')
pt3 = b2v(bytes(range(48)))
whole = aead_to(ENCRYPT).exec('A', pt3, 384)
for halt in (1, 2):
    cc = aead_to(ENCRYPT)
    o, ks = cc.exec('A', pt3, 384, halt_after=halt), cc.klstart
    check(f'Form A over 3 blocks halted after {halt} (klstart = {16 * halt}), resumed: same output', True,
          (ks, cc.exec('A', pt3, 384, out=o), cc.klstart), (16 * halt, whole, 0))
a = b2v(pad_bytes(h(AEAD_KAT[8][1]), 16))
cc, ref_c = aead_to(ABSORB), aead_to(ABSORB)
cc.exec('B', a, 256, halt_after=1); cc.exec('B', a, 256); ref_c.exec('B', a, 256)
check('Form B over 2 AD blocks halted and resumed == uninterrupted', True, cc.s, ref_c.s)

section('Serialized Content and provisioning (<<KLEE-rules-system-keys>>)')
pi = build_pi(0, [(K, 128)], policy=0b11)
res = [(ct + tag, cc.st) for cc, ct, tag in (aead_run(provision(pi), False, KAT_NONCE, h(ad), h(pt),
                                                      after=migrate(AEAD)) for _, ad, pt, _, _ in AEAD_KAT)]
_, rec, ok = aead_run(AEAD(K), True, KAT_NONCE, ad579, ct579, tag=b2v(tag579), after=migrate(AEAD))
check('PI = MDH, key (256 bits); every vector, and Count=579 decryption, migrated after every instruction', True,
      (len(pi), res, rec, ok), (32, [(c, SUCCESS) for c in CTTS], pt579, True))
img = aead_to(ENC_LAST).export()[1]; c1 = b2v(img)
check('Content1: key, state[0..4], last_blk_len, tag_len; 480 bits padded to 64 bytes', True,
      (len(img), sl(c1, 127, 0), sl(c1, 463, 448), sl(c1, 479, 464), c1 >> 480), (64, K, 40, 128, 0))
pi_s = build_pi(0, [(SKID_A, 64)], policy=0b11, key_type=1)
img = provision(pi_s, SKS).export(); c1 = b2v(img[1])
check('SKID: PI = MDH, SKID (256 bits); Content1 SKID in 64 bits, state[0] at bit 64 (416 bits, 64 bytes); '
      'migrated: Count=579', True, (len(pi_s), len(img[1]), sl(c1, 63, 0), sl(c1, 127, 64),
                                    seal(provision(pi_s, SKS), after=migrate(AEAD, SKS))),
      (32, 64, SKID_A, IV_AEAD, blob579))
check('an unresolved SKID -> _Invalid_ on import and on provisioning (<<KLEE-MVR-open>>)', True,
      (AEAD.import_(img, sks={}).st, provision(pi_s, {}).st), (INVALID, INVALID))

section('<<KLEE-Ascon-AEAD128-wsn>>')
pi = build_pi(1, [(K, 128), (NN, 128)], policy=0b11)
res = [(ct + tag, cc.st) for cc, ct, tag in (aead_run(provision(pi), False, None, h(ad), h(pt))
                                             for _, ad, pt, _, _ in AEAD_KAT)]
_, rec, ok = aead_run(provision(pi), True, None, ad579, ct579, tag=b2v(tag579))
pi_s = build_pi(1, [(SKID_A, 64), (NN, 128)], policy=0b11, key_type=1)
check('PI = MDH, key, nonce (384 bits): every vector with Form A into _Hash_Absorb_; Count=579 decrypts; SKID '
      'PI with the nonce at bit 192', True, (len(pi), res, rec, ok, len(pi_s), seal(provision(pi_s, SKS), None)),
      (48, [(c, SUCCESS) for c in CTTS], pt579, True, 48, blob579))
long_pt = seq(40 * 16 + 3, 13, 5)
c2, ct, tag = aead_run(provision(pi), False, None, ad579, long_pt, pt_chunk=7)
check('Form C kl.setst into _Hash_Absorb_ -> _Invalid_; no block budget (40 blocks + 3 bytes == reference)', True,
      (provision(pi).setst(ABSORB, 'C', INPUT=NN, KLLEN=128).st, ct + tag, c2.st),
      (INVALID, ref_aead_encrypt(KAT_KEY, KAT_NONCE, ad579, long_pt), SUCCESS))
cc, ct, tag = aead_run(provision(pi), False, None, ad579, pt579)
st_r = cc.setst(READY).st
check('GR21: _Success_ -> _Ready_ reuses the PI nonce; migrated after every instruction == Count=579', True,
      (st_r, seal(cc, None), seal(provision(pi), None, after=migrate(AEADNonce))), (READY, ct + tag, blob579))
cc = AEADNonce.import_(cc.export()).setst(READY)
check('nonce serialized (Pos. ix): an imported locker in _Success_ re-enters _Ready_ and reuses it', True,
      (seal(cc, None), len(cc.export()[1])), (blob579, 80))           # 608 bits, padded

section('<<KLEE-Ascon-AEAD128-N-masking>>')
pi0, pi = build_pi(2, [(K, 128), (0, 128)], policy=0b11), build_pi(2, [(K1v, 128), (K2v, 128)], policy=0b11)
check('PI = MDH, K1, K2 (384 bits); with K2 = 0 every vector is reproduced', True,
      (len(pi0), [seal(provision(pi0), ad=h(ad), pt=h(pt)) for _, ad, pt, _, _ in AEAD_KAT]), (48, CTTS))
for count, ad, pt, _, _ in AEAD_KAT[:6]:
    A, P = h(ad), h(pt)
    ref, blob = ref_aead_encrypt(K1, Nm, A, P), seal(provision(pi), ad=A, pt=P)
    cc, rec, ok = aead_run(provision(pi), True, KAT_NONCE, A, blob[:-16], tag=b2v(blob[-16:]))
    check(f'Count={count}: == ref(K1, N xor K2) (eq. (52)), != unmasked N, decrypts (eq. (53)), migrates', True,
          (blob, blob != enc(A, P, key=K1)[0], (rec, ok, cc.st),
           seal(provision(pi), ad=A, pt=P, after=migrate(AEADMask))),
          (ref, True, (P, True, SUCCESS), ref))
img = drive(provision(pi), ENC_LAST).export()[1]; c1 = b2v(img)
check('Content1: K1, K2, state[0..4], last_blk_len, tag_len; 608 bits padded to 80 bytes', True,
      (len(img), sl(c1, 127, 0), sl(c1, 255, 128), sl(c1, 591, 576), sl(c1, 607, 592)), (80, K1v, K2v, 40, 128))
pi_s = build_pi(2, [(SKID_M, 64)], policy=0b11, key_type=1)
cc = provision(pi_s, SKS)
img = cc.export()[1]; c1 = b2v(img)
check('SKID: PI = MDH, SKID (256 bits); Content1 = SKID, state, lengths (64 bytes), state[0] at bit 64; MGR16: '
      'one SKID yields K1 and K2, migrated', True,
      (len(pi_s), len(img), sl(c1, 63, 0), sl(c1, 127, 64), seal(cc, after=migrate(AEADMask, SKS))),
      (32, 64, SKID_M, provision(pi_s, SKS).s[0], ref579(K1, Nm)))
cc, ct, tag = aead_run(provision(pi), False, KAT_NONCE, h("3031"), LAST5)
check('set-nonce Machine with K1 and nonce N xor K2 == masking Machine given N; GR21 restart agrees', True,
      (seal(provision(build_pi(1, [(K1v, 128), (b2v(Nm), 128)], policy=0b11)), None, h("3031"), LAST5),
       seal(cc.setst(READY), ad=h("3031"), pt=LAST5)), (ct + tag, ct + tag))
cc = provision(pi)
cc.legacy_layout = True
try: got = seal(cc, after=migrate(AEADMask, legacy_layout=True))
except Invalid: got = b'Invalid'
control('Serialized Content without last_blk_len, migrated through _Enc_Last_Block_', got != ref579(K1, Nm))

section('<<KLEE-Ascon-Hash256>>')
pi = build_pi(3, [])
cc = provision(pi)
check('PI = MDH only (128 bits); _Ready_ holds Table 12', True, (len(pi), cc.st, tuple(cc.s)),
      (16, READY, TABLE12['Ascon-Hash256']))
for count, msg, md in HASH_KAT:
    m = h(msg)
    got = [sponge_run(Hash256(), m, 32, squeeze=s) for s in ((256,), (64,), (128,), (192,), (64, 256), (128, 64, 64))]
    got += [sponge_run(Hash256(), m, 32, absorb_chunk=3), sponge_run(Hash256(), m, 32, after=migrate(Hash256))]
    check(f'Count={count}: squeezes 256, 4x64, 2x128, 192+192, 64+256, 128+64+64; KLLEN=192 absorb; migrated '
          f'(countdown in _MachineUse_); then _Success_', True, [(o, c.st) for o, c in got], [(h(md), SUCCESS)] * 8)
md = h(HASH_KAT[0][2])
cc = at_finalize(Hash256)
trace = [cc.countdown]
while cc.st == FINALIZE: cc.exec('C', 0, 64); trace.append(cc.countdown)
check('countdown: 3 on entering _Hash_Finalize_, then 2, 1, 0 and _Success_ on the fourth word; a fifth '
      'kl.exec -> _Invalid_ (GR23), output zeroed', True,
      (trace, cc.st, cc.exec('C', 0, 64, out=M64), cc.st), ([3, 2, 1, 0, 0], SUCCESS, 0, INVALID))
cc, c2 = at_finalize(Hash256), at_finalize(Hash256)
o1, o2 = cc.exec('C', 0, 192, out=mask(192)), cc.exec('C', 0, 192, out=mask(192))
c2.exec('C', 0, 64)
o3 = c2.exec('C', 0, 256, out=mask(256))
check('KLLEN = 192 twice: 4th word, OUTPUT[191:64] cleared; 64 then 256: OUTPUT[255:192] cleared', True,
      (v2b(o1, 24), v2b(sl(o2, 63, 0), 8), o2 >> 64, v2b(sl(o3, 191, 0), 24), o3 >> 192, cc.st, c2.st),
      (md[:24], md[24:], 0, md[8:], 0, SUCCESS, SUCCESS))
for halt in (1, 3):
    cc = at_finalize(Hash256)
    o, ks, cd = cc.exec('C', 0, 256, halt_after=halt), cc.klstart, cc.countdown
    check(f'KLLEN = 256 halted after {halt} word(s) (klstart = {8 * halt}, countdown = {3 - halt}), resumed', True,
          (ks, cd, v2b(cc.exec('C', 0, 256, out=o), 32), cc.st), (8 * halt, 3 - halt, md, SUCCESS))
res = []
for KLLEN, form, fin in ((64, 'B', None), (56, 'B', False), (104, 'C', True), (64, 'B', True), (64, 'A', False)):
    cc = at_finalize(Hash256) if fin else Hash256().setst(ABSORB, 'A') if fin is False else Hash256()
    cc.exec(form, 0, KLLEN)
    res.append(cc.st)
cc, c2 = at_finalize(Hash256), Hash256()
kl_restrictl(cc, 0, machine_use=0x0003); kl_restrictl(c2, 0b01)
check('GR18; MGR2 (KLLEN 56, 104); MGR1 (Form B in _Hash_Finalize_, Form A in _Hash_Absorb_); kl.restrictl on '
      'the countdown; kl.restrictl on an unused _MachinePolicy_ -> _Invalid_', True, res + [cc.st, c2.st],
      [INVALID] * 7)
check('MGR18: a same-State kl.setst into _Hash_Finalize_ (Hash256, XOF128, CXOF128) -> _Invalid_', True,
      [at_finalize(c).setst(FINALIZE, 'A').st for c in (Hash256, XOF, CXOF)], [INVALID] * 3)
check('GR20: a same-State kl.setst into _Hash_Absorb_ of Ascon-Hash256 is admitted and changes nothing', True,
      sponge_run(Hash256().setst(ABSORB, 'A'), b'abc', 32)[0], sponge_run(Hash256(), b'abc', 32)[0])

section('<<KLEE-Ascon-XOF128>>')
check('_Ready_ holds Table 12', True, (provision(build_pi(4, [])).st, tuple(XOF().s)),
      (READY, TABLE12['Ascon-XOF128']))
for count, msg, md in XOF_KAT:
    got = [sponge_run(XOF(), h(msg), 64, squeeze=s)[0] for s in ((64,), (256,), (512,), (128, 64, 192, 128))]
    got.append(sponge_run(XOF(), h(msg), 64, after=migrate(XOF))[0])
    check(f'Count={count}: squeezes 8x64, 2x256, 512, 128+64+192+128; migrated', True, got, [h(md)] * 5)
check('Count=1, 2, 9: 256-bit squeeze is a prefix; 1024-bit squeeze == reference stream', True,
      [(sponge_run(XOF(), h(m), 32)[0], sponge_run(XOF(), h(m), 128, squeeze=(1024,))[0]) for _, m, _ in XOF_KAT[:3]],
      [(h(md)[:32], ref_xof128(h(m), 128)) for _, m, md in XOF_KAT[:3]])
cc = at_finalize(XOF)
cd = [cc.countdown]
for _ in range(20): cc.exec('C', 0, 64); cd.append(cc.countdown)
check('countdown: 1 on entering _Hash_Finalize_, 0 from the first word on; never _Success_', True,
      (cd[:3], set(cd[1:]), cc.st), ([1, 0, 0], {0}, FINALIZE))
cc = at_finalize(XOF)
s_before, res = list(cc.s), []
for ks in (8, 16):
    cc.klstart = ks
    res.append((cc.exec('C', 0, 64, out=0x1234), cc.st, cc.countdown, cc.s, cc.klstart))
cc.klstart = 13
res.append((cc.exec('C', 0, 104, out=0x1234), cc.st))
check('output-only klstart >= KLLEN / 8 (KLLEN = 64: 8, 16): empty window, only klstart = 0; KLLEN = 104, '
      'klstart = 13: invalid length first, _Invalid_', True, res,
      [(0x1234, FINALIZE, 1, s_before, 0)] * 2 + [(0x1234, INVALID)])
c3 = aead_to(ABSORB)
c3.klstart, s_before = 40, list(c3.s)
check('input klstart = 40 > KLLEN / 8: empty window, only klstart = 0', True,
      (c3.exec('B', a, 256), c3.st, c3.s, c3.klstart), (0, ABSORB, s_before, 0))
cc = at_finalize(XOF)
cc.klstart = 3
check('output-only klstart = 3 (no interruption point): _Invalid_, [3, 8) zeroed', True,
      (cc.exec('C', 0, 64, out=M64), cc.st), (mask(24), INVALID))

def lose_countdown(cc):
    mdh, content = cc.export()
    if mdh_unpack(mdh)['State'] == FINALIZE: mdh &= ~(0x3FFF << MDH_FIELD['MachineUse'][1])
    return XOF.import_((mdh, content))

control('XOF resumed without its countdown (_MachineUse_ cleared)',
        sponge_run(XOF(), h(XOF_KAT[2][1]), 64, after=lose_countdown)[0].hex() != XOF_KAT[2][2])

section('<<KLEE-Ascon-CXOF128>>')
check('_Ready_ holds Table 12', True, (provision(build_pi(5, [])).st, tuple(CXOF().s)),
      (READY, TABLE12['Ascon-CXOF128']))
for count, msg, z, md in CXOF_KAT:
    pre = cxof_prefix(h(z))
    check(f'Count={count}: caller-prepended Z0 || pad(Z, 64); also one 512-bit squeeze, migrated', True,
          [sponge_run(CXOF(), h(msg), 64, prefix=pre)[0],
           sponge_run(CXOF(), h(msg), 64, prefix=pre, squeeze=(512,), after=migrate(CXOF))[0]], [h(md)] * 2)
check('CXOF128 with an empty Z differs from XOF128 (IV differs)',
      sponge_run(CXOF(), b'abc', 32, prefix=cxof_prefix(b''))[0] != sponge_run(XOF(), b'abc', 32)[0])
control('prefix pad(Z, 64) without Z0 (literal reading) on every non-empty Z',
        all(sponge_run(CXOF(), h(m), 64, prefix=pad_bytes(h(z), 8))[0].hex() != md for _, m, z, md in CXOF_KAT if z))

section('kl.derive (<<KLEE-derive-endpoints>>, <<KLEE-instruction-derive>>)')
msg, sec = b"KLEE derive source", bytes(range(0x40, 0x60))   # sec: a 32-byte DER5 shared secret
stream = ref_xof128(msg, 64)
for length in (16, 24):
    dst = AEAD(0)
    kl_derive(dst, Secret(sec), length)
    check(f'shared secret, length {length} -> Ascon-AEAD128 `key` in _Ready_: the first 16 bytes (DER1 item 5), '
          '_Ready_ re-initialized, then encrypts as SP 800-232 under that key', True,
          ((dst.st, v2b(dst.key, 16), dst.s[1:3]), seal(dst)),
          ((READY, sec[:16], [b2v(sec[:8]), b2v(sec[8:16])]), ref579(sec[:16])))
nonce_pi = build_pi(1, [(K, 128), (NN, 128)], policy=0b11)
dst, dst2 = provision(nonce_pi), AEADMask(K1v, K2v)
kl_derive(dst, Secret(sec), 16)
kl_derive(dst2, Secret(sec), 40)
ct = seal(dst, None)
check('shared secret -> set-nonce `key` (16 B, PI nonce kept) and nonce-masking `K1 || K2` (length 40: 32 B, '
      'K1 first) in _Ready_; both encrypt as SP 800-232', True,
      (dst.st, ct, (dst2.st, v2b(dst2.key, 16), v2b(dst2.K2, 16)), seal(dst2)),
      (SUCCESS, ref579(sec[:16]), (READY, sec[:16], sec[16:]), ref579(sec[:16], bxor(KAT_NONCE, sec[16:]))))
res = []
for dst, src, length in ((aead_to(ABSORB), sec, 16), (AEAD(K, skid=SKID_A), sec, 16), (AEAD(K), sec, 8),
                         (AEAD(K), sec, 15), (AEAD(K), sec, 0), (AEAD(K), sec[:12], 16),
                         (provision(nonce_pi).setst(ABSORB, 'A'), sec, 16), (AEADMask(K1v, K2v), sec, 16),
                         (AEADMask(K1v, K2v), sec[:16], 32),
                         (provision(build_pi(2, [(SKID_M, 64)], policy=0b11, key_type=1), SKS), sec, 32)):
    kl_derive(dst, Secret(src), length)
    res.append((dst.st, dst.key, dst.s))
check('key destination not in _Ready_ (DER1 item 2), _KeyType_ = 1 (DER4), length 8, 15, 0 < 16, 12-byte source, '
      '16 B into the 32-byte `K1 || K2` (DER1 item 5): destination _Invalid_, no key', True, res,
      [(INVALID, 0, [0] * 5)] * 10)
src, dst = at_finalize(XOF, msg), XOF().setst(ABSORB, 'A')
kl_derive(dst, src, 12)
st0 = (dst.st, src.st, v2b(src.exec('C', 0, 64), 8))
src, dst = at_finalize(XOF, msg), AEAD(K)
kl_derive(dst, src, 16)
st1 = (src.st, dst.st, v2b(dst.key, 16), v2b(src.exec('C', 0, 64), 8))
ct = seal(dst)
src, dst = at_finalize(Hash256, msg), AEADMask(K1v, K2v)
kl_derive(dst, src, 32)
d32 = ref_hash256(msg)
check('12 bytes into a 64-bit-granular absorb (DER1 item 4): destination _Invalid_, source untouched; key derivation '
      '(DER6): XOF128 output -> AEAD128 `key` (the first 16 B, XOF advanced) and Ascon-Hash256 output -> `K1 || K2` '
      '(32 B, then _Success_), unrestricted; both encrypt as SP 800-232', True, (st0, st1, ct, src.st, seal(dst)),
      ((INVALID, FINALIZE, stream[:8]), (FINALIZE, READY, stream[:16], stream[16:24]), ref579(stream[:16]), SUCCESS,
       ref579(d32[:16], bxor(KAT_NONCE, d32[16:]))))
src, dst = at_finalize(Hash256, msg), AEAD(K)
src.exec('C', 0, 192)
kl_derive(dst, src, 16)
res = [(src.st, dst.st)]
for src in (AEAD(K), aead_to(OUTPUT)):
    dst = XOF().setst(ABSORB, 'A')
    kl_derive(dst, src, 16)
    res.append((src.st, dst.st))
check('Ascon-Hash256 with 8 B of output left -> 16-byte `key` (DER1 item 5): destination _Invalid_; Ascon-AEAD128 '
      'in _Ready_ (no Form C output) or with its tag in _Hash_Output_ (not a source, DER6) as a source (DER1 item 1): '
      'only the source _Invalid_', True, res, [(FINALIZE, INVALID), (INVALID, ABSORB), (INVALID, ABSORB)])
res = []
for src, n in ((at_finalize(XOF, msg), 16), (at_finalize(Hash256, msg), 32), (Secret(sec), 32)):
    dst = XOF().setst(ABSORB, 'A')
    kl_derive(dst, src, n)
    dst.exec('B', b2v(pad_bytes(b'', 8)), 64)
    res.append((src.st, v2b(dst.setst(FINALIZE, 'A').exec('C', 0, 128), 16)))
check('XOF128 (16 B), Ascon-Hash256 (32 B, then _Success_) output and a shared secret (32 B, DER5) -> XOF128 '
      '_Hash_Absorb_, continued with kl.exec', True, res,
      [(FINALIZE, ref_xof128(stream[:16], 16)), (SUCCESS, ref_xof128(ref_hash256(msg), 16)),
       (SUCCESS, ref_xof128(sec, 16))])

section('Negative control')
control('domain separation on state[0] instead of state[4] (Count=1, 17, 166, 235)',
        all(enc(h(ad), h(pt), dsep_wrong_word=True)[0].hex() != ctt for _, ad, pt, ctt, _ in AEAD_KAT[:4]))

done()
