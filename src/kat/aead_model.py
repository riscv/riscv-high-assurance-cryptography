"""Executable model of the AEAD/MAC Machines (GCM, GCM_IV, GCM-SIV, OCB, OCB_NONCE, CMAC), transcribed from
Zkl-ISA-machines.adoc in the spec's notation (values = little-endian ints, common.py).  Independent of aead_ref.py,
which works in the standards' own byte order; the KATs compare the two.

Interface (all Machines):
  m.st                  State number (READY, ..., SUCCESS, FAILURE) or INV (Error State Invalid)
  m.setst(st, form='A', xs=0, inp=0)
  m.exec(form, inp=0, kllen=None, klstart=0, halt_at=None) -> OUTPUT value (int); kllen in BITS (default: inferred
        by the caller), klstart and halt_at in BYTES.  halt_at = byte offset at which a multi-block/VLI exec is
        interrupted (only at the architected interruption points); the position is then in m.klstart.
  m.export() -> (SC value, width); Cls.from_sc(st, sc, ...) imports it.
  m.derive_dest(keybytes)  kl.derive into the key field; m.restrict(mask) narrows MachinePolicy.
Any rule violation sets m.st = INV; every later instruction keeps it there (content cleared, GR35).
"""
from common import *

READY, ABSORB, LAST, VERIFY, OUTPUT, ENC, DEC, ELB, DLB, ETF, DTF, SAV, SAV2 = 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
SUCCESS, FAILURE, INV = 54, 55, -1
HV, HABL, HOUT = VERIFY, LAST, OUTPUT
MAX_BLOCKS = 1 << 48

class Inv(Exception): pass

def need(c):
    if not c: raise Inv()

class Base:
    NAME = ''
    CIPHER = 'AES128'
    B = 128
    TRANS = {}          # st -> set of admitted next States (explicit setst)
    SETF = {}           # st -> expected Form of the entering setst
    EXF = {}            # st -> expected Form of kl.exec
    GATE = {}           # st -> MachinePolicy bit index
    NOKEYDER = False
    zklio = False                 # True: a Form D kl.exec substitutes for the native Form

    def __init__(self, key, policy=3):
        need_ = policy != 0
        if not need_: raise ValueError('zero MachinePolicy is invalid metadata (MR1)')
        self.cipher = self.CIPHER if len(key) in (16, 24, 32) and self.CIPHER == 'AES128' else self.CIPHER
        self.key, self.policy, self.st, self.klstart, self.out_partial = key, policy, READY, 0, 0
        self._ready()

    # ------------------------------------------------------------ plumbing
    def E(self, blk): return b2v(cipher_enc(self.cipher, self.key, v2b(blk, self.B // 8)))
    def D(self, blk): return b2v(cipher_dec(self.cipher, self.key, v2b(blk, self.B // 8)))
    def _fail(self):
        self.st = INV; self.key = None
    def _formok(self, exp, form, xs, inp):
        if exp is None: return False
        if form == exp: return True
        if form == 'A' and exp in 'BC': return xs == 0 and inp == 0
        if form == 'D' and exp == 'C': return True
        return False
    def restrict(self, mask):
        if self.st == INV: return
        self.policy &= mask
        if self.policy == 0: self._fail()
    def setst(self, st, form='A', xs=0, inp=0):
        if self.st == INV: return
        try:
            cur = self.st
            if st == READY:
                need(form == 'A'); self.st = READY; self._ready(); return
            need(cur not in (SUCCESS, FAILURE))                      # GR22
            need(st in self.TRANS.get(cur, ()) or st == cur and cur in self.SAMEOK)   # GR20/22/24
            need(self._formok(self.SETF.get(st), form, xs, inp))     # GR13
            if st in self.GATE: need(self.policy >> self.GATE[st] & 1)
            if st != cur: self._leave(cur, st)
            self.st = st
            self._enter(st, xs, inp if form != 'A' else 0)
        except Inv:
            self._fail()
    SAMEOK = ()
    def _leave(self, cur, nxt): pass
    def exec(self, form, inp=0, kllen=None, klstart=0, halt_at=None):
        if self.st == INV: return 0
        self.klstart = 0
        try:
            if self.zklio and form == 'D': form = self._expform(self.st)   # KLIOBUF substitution of the native Form
            if self.st in self.GATE: need(self.policy >> self.GATE[self.st] & 1)   # MR1 at issue
            need(form == self._expform(self.st))
            if kllen is not None and klstart * 8 >= kllen and not self._noexec(self.st): return 0   # GR52 item 1: empty window
            out = self._exec(self.st, inp, kllen, klstart, halt_at)
            return out & mask(kllen) if kllen is not None else out
        except Inv:
            out = self.out_partial; self.out_partial = 0
            self._fail(); return out
    def _expform(self, st): return self.EXF.get(st)
    def _noexec(self, st): return st in (ELB, DLB) and self.lbl == 0     # MR10: State admitting no kl.exec
    def _clean(self): self.out_partial = 0

    # multi-block helper: fn(i_block_value) -> out block value or None
    def _multi(self, inp, kllen, klstart, halt_at, fn):
        b = self.B
        need(kllen is not None and kllen % b == 0)      # MR6 granularity
        need(klstart * 8 % b == 0)                                    # GR52 item 3
        out = 0; self.out_partial = 0
        for i in range(klstart * 8 // b, kllen // b):
            if halt_at is not None and i * b == 8 * halt_at and i * b > 8 * klstart:
                self.klstart = halt_at; return out
            o = fn(sl(inp, i * b + b - 1, i * b))
            self.out_partial = out
            out |= (o or 0) << (i * b)
            self.out_partial = out
        self.out_partial = 0
        return out

    # serialization helpers
    @staticmethod
    def pack(*fields):
        v = w = 0
        for val, width in fields:
            assert 0 <= val < 1 << width, (val, width)
            v |= val << w; w += width
        return v, w
    @staticmethod
    def unpack(sc, widths):
        r, w = [], 0
        for x in widths: r.append(sl(sc, w + x - 1, w)); w += x
        return r
    @classmethod
    def _blank(cls, kb, policy, cipher='AES128'): return cls(bytes(kb), policy=policy)
    def derive_dest(self, newkey):
        if self.st == INV: return
        try:
            need(not self.NOKEYDER and self.st == READY and len(newkey) == len(self.key))
            self.key = newkey; self._ready()
        except Inv:
            self._fail()

# =================================================================== GCM / GCM_IV
class GCM(Base):
    NAME = 'GCM'
    TRANS = {READY: {SAV}, SAV: {ABSORB}, ABSORB: {ENC, DEC}, ENC: {ELB, ETF}, ELB: {ETF}, DEC: {DLB, DTF}, DLB: {DTF}, DTF: {HV}}
    SETF = {SAV: 'B', ABSORB: 'A', ENC: 'A', DEC: 'A', ELB: 'B', DLB: 'B', ETF: 'C', DTF: 'C', HV: 'B'}
    EXF = {SAV: 'B', ABSORB: 'B', ENC: 'A', DEC: 'A', ELB: 'A', DLB: 'A', ETF: 'C', HV: 'B'}
    GATE = {ENC: 0, ELB: 0, ETF: 0, DEC: 1, DLB: 1, DTF: 1, HV: 1}
    SAMEOK = (SAV,)
    IV = False

    def __init__(self, key, iv=None, policy=3, cipher='AES128'):
        self.CIPHER = cipher
        super().__init__(key, policy)
        self.cipher = cipher
        self._ready()

    def _ready(self):
        self.auth = self.E(0)
        self.tag = self.tag_len = 0
        if not hasattr(self, 'lbl'): self.lbl = 0
        if not hasattr(self, 'J0'): self.J0 = self.start_ctr = 0      # Ready entry does not touch J0, start_ctr
        self.len = self.block_base = self.cumul = 0
        if self.IV: self.J0 = (self.J0 & mask(96)) | bswap(1, 4) << 96
        self.klstart = 0

    def absorb(self, d): self.tag = ghash_mul(self.tag ^ d, self.auth)
    def ctr(self):
        c = (bswap(sl(self.J0, 127, 96), 4) + 1) % 2**32
        need(c != (self.start_ctr - 1) % 2**32)
        self.J0 = (self.J0 & mask(96)) | bswap(c, 4) << 96
    def _enter(self, st, xs, inp):
        if st == SAV:
            need(xs % 8 == 0 and 8 <= xs <= 8192)
            self.tag = self.block_base = self.cumul = 0; self.len = xs
        elif st in (ELB, DLB):
            need(xs % 8 == 0 and 8 <= xs <= 120); self.lbl = xs
        elif st in (ETF, DTF):
            self.absorb(inp & MASK128)
            self.tag ^= self.E(cat((bswap(self.start_ctr, 4), 32), (sl(self.J0, 95, 0), 96)))
        elif st == HV:
            need(xs in (128, 120, 112, 104, 96, 64)); self.tag_len = xs
    def _leave(self, cur, nxt):
        if cur == SAV: need(False)            # leaving SAV other than by completion/Ready is Invalid
        if cur in (ELB, DLB): need(self.lbl == 0)    # MR10 item 5: leaving a final-block State before its kl.exec
    def _exec(self, st, inp, kllen, klstart, halt_at):
        if st == SAV: return self._vli(inp, kllen, klstart, halt_at)
        if st == ABSORB: return self._multi(inp, kllen, klstart, halt_at, lambda x: self.absorb(x))
        if st == ENC:
            def f(x):
                self.ctr(); t = x ^ self.E(self.J0); self.absorb(t); return t
            return self._multi(inp, kllen, klstart, halt_at, f)
        if st == DEC:
            def f(x):
                self.ctr(); self.absorb(x); return x ^ self.E(self.J0)
            return self._multi(inp, kllen, klstart, halt_at, f)
        if st in (ELB, DLB):
            need(kllen is not None and kllen >= self.lbl)
            need(self.lbl != 0)                                  # MR10: empty final input admits no kl.exec, even KLLEN = 0
            n = self.lbl; self.ctr()
            x = sl(inp, n - 1, 0); ks = sl(self.E(self.J0), n - 1, 0)
            if st == ELB: t = x ^ ks; self.absorb(t)
            else: self.absorb(x); t = x ^ ks
            self.lbl = 0
            return t
        if st == ETF:
            need(kllen is not None and (kllen >= 128 or kllen in (120, 112, 104, 96, 64)))
            self.st = SUCCESS
            return self.tag & mask(min(kllen, 128))
        if st == HV:
            need(kllen is not None and kllen >= self.tag_len)
            ok = sl(inp, self.tag_len - 1, 0) == sl(self.tag, self.tag_len - 1, 0)
            self.st = SUCCESS if ok else FAILURE
            self.tag_len = 0
            return 0
        need(False)

    def _vli(self, inp, kllen, klstart, halt_at):
        need(kllen is not None)
        need(self.cumul < self.len)                                     # step 1
        need(not (kllen % 128 and self.cumul + kllen < self.len))       # granularity
        b4 = self.block_base
        need(klstart == 0 or (b4 == 0 and klstart * 8 % 128 == 0))
        ib = 8 * klstart
        while ib < kllen:
            amt = min(kllen - ib, 128 - self.block_base, self.len - self.cumul)
            self.tag ^= sl(inp, ib + amt - 1, ib) << self.block_base
            ib += amt; self.block_base += amt; self.cumul += amt
            if self.block_base == 128:
                self.absorb_mul(); self.block_base = 0
            if self.cumul == self.len:
                self._finalize(); return 0
            if ib < kllen and ib % 128 == 0 and halt_at is not None and ib == 8 * halt_at:
                self.klstart = ib // 8; return 0
        return 0
    def absorb_mul(self): self.tag = ghash_mul(self.tag, self.auth)
    def _finalize(self):
        if self.len == 96:
            self.J0 = cat((bswap(1, 4), 32), (sl(self.tag, 95, 0), 96))
        else:
            if self.block_base != 0: self.absorb_mul()
            self.tag ^= cat((bswap(self.len, 8), 64), (0, 64))
            self.absorb_mul(); self.J0 = self.tag
        self.start_ctr = bswap(sl(self.J0, 127, 96), 4)
        self.tag = 0; self.len = self.block_base = self.cumul = 0
        self.st = ABSORB
    def _leave_ok(self): pass

    # ---- Serialized Content
    def export(self):
        kb = 8 * len(self.key)
        if self.st == SAV:
            j = self.pack((self.len, 16), (0, 16), (self.block_base, 16), (self.cumul, 48), (0, 32))[0]
        else: j = self.J0
        tl = self.tag_len
        return self.pack((b2v(self.key), kb), (j, 128), (self.tag, 128), (self.start_ctr, 32), (self.lbl, 16), (tl, 16))
    @classmethod
    def from_sc(cls, st, sc, keybytes=16, policy=3, cipher='AES128'):
        m = cls._blank(keybytes, policy, cipher)
        k, j, tag, sctr, lbl, tl = cls.unpack(sc, (8 * keybytes, 128, 128, 32, 16, 16))
        m.key = v2b(k, keybytes); m.auth = m.E(0)
        m.st, m.tag, m.start_ctr, m.lbl, m.tag_len = st, tag, sctr, lbl, tl
        if st == SAV:
            m.len, _, m.block_base, m.cumul = sl(j, 15, 0), 0, sl(j, 47, 32), sl(j, 95, 48); m.J0 = 0
        else: m.J0 = j
        try:
            if cls.IV: need(sctr == 1)
        except Inv: m._fail()
        return m

class GCM_IV(GCM):
    NAME = 'GCM_IV'
    IV = True
    TRANS = {READY: {ABSORB}, ABSORB: {ENC, DEC}, ENC: {ELB, ETF}, ELB: {ETF}, DEC: {DLB, DTF}, DLB: {DTF}, DTF: {HV}}
    NOKEYDER = True
    @classmethod
    def _blank(cls, kb, policy, cipher='AES128'): return cls(bytes(kb), 0, policy, cipher)
    def __init__(self, key, iv, policy=3, cipher='AES128'):
        self.J0 = iv & mask(96)
        super().__init__(key, policy=policy, cipher=cipher)
        self.start_ctr = 1
    def _ready(self):
        super()._ready()
        self.start_ctr = 1

# =================================================================== GCM-SIV
class GCMSIV(Base):
    NAME = 'GCM-SIV'
    TRANS = {READY: {SAV}, SAV: {SAV2, ABSORB}, SAV2: {ABSORB}, ABSORB: {ETF, DEC}, ENC: {ELB}, DEC: {DLB, DTF}}
    SETF = {SAV: 'C', SAV2: 'C', ABSORB: 'A', ETF: 'A', ENC: 'A', DEC: 'A', ELB: 'B', DLB: 'B', DTF: 'A'}
    EXF = {ABSORB: 'B', ETF: 'A', ENC: 'A', ELB: 'A', DEC: 'A', DLB: 'A', DTF: 'B'}
    GATE = {ENC: 0, ELB: 0, ETF: 0, DEC: 1, DLB: 1, DTF: 1}
    def __init__(self, key, policy=3, cipher='AES128'):
        self.CIPHER = cipher
        super().__init__(key, policy); self.cipher = cipher
        self._ready()
    def _ready(self):
        self.nonce = self.ctr = self.tmp = self.siv = 0
        if not hasattr(self, 'lbl'): self.lbl = 0     # Ready entry leaves last_block_len
        self.ek = self.ak = None
    def _derive(self):
        k = len(self.key) * 8
        A = [b2v(cipher_enc(self.cipher, self.key, v2b(cat((self.nonce, 96), (i, 32)), 16))) for i in range(k // 64 + 2)]
        self.ak = cat((sl(A[1], 63, 0), 64), (sl(A[0], 63, 0), 64))
        self.ek = b''.join(v2b(sl(a, 63, 0), 8) for a in A[2:])
    def EE(self, blk): return b2v(cipher_enc(self.cipher, self.ek, v2b(blk, 16)))
    def absorb(self, d): self.tmp = montmul(self.tmp ^ d, self.ak)
    def _enter(self, st, xs, inp):
        if st == SAV: self.nonce = sl(inp, 95, 0); self._derive()
        elif st == SAV2: self.siv = inp & MASK128
        elif st in (ELB, DLB): need(xs % 8 == 0 and 8 <= xs <= 120); self.lbl = xs
    def _leave(self, cur, nxt):
        if cur in (ELB, DLB): need(self.lbl == 0)              # MR10 item 5
    def _fin(self):
        t = self.tmp
        return self.EE(cat((0, 1), (sl(t, 126, 96), 31), (sl(t, 95, 0) ^ self.nonce, 96)))
    def _ks(self):
        need(self.ctr != 2**32)
        s = self.siv
        k = self.EE(cat((1, 1), (sl(s, 126, 32), 95), ((sl(s, 31, 0) + self.ctr) % 2**32, 32)))
        self.ctr += 1; return k
    def _exec(self, st, inp, kllen, klstart, halt_at):
        if st == ABSORB: return self._multi(inp, kllen, klstart, halt_at, lambda x: self.absorb(x))
        if st == ETF:
            need(kllen is not None and kllen >= 128)
            self.absorb(inp & MASK128); self.siv = self.tmp = self._fin(); self.st = ENC
            return self.siv
        if st == ENC: return self._multi(inp, kllen, klstart, halt_at, lambda x: x ^ self._ks())
        if st == DEC:
            def f(x):
                o = x ^ self._ks(); self.absorb(o); return o
            return self._multi(inp, kllen, klstart, halt_at, f)
        if st in (ELB, DLB):
            need(kllen is not None and kllen >= self.lbl)
            need(self.lbl != 0)                                  # MR10: empty final input admits no kl.exec, even KLLEN = 0
            n = self.lbl; ks = self._ks(); o = sl(inp, n - 1, 0) ^ sl(ks, n - 1, 0)
            if st == DLB: self.absorb(o); self.st = DTF       # MR10 item 3: single successor
            self.lbl = 0
            return o
        if st == DTF:
            need(kllen is not None and kllen >= 128)
            self.absorb(inp & MASK128)
            self.tmp = self._fin(); self.st = SUCCESS if self.tmp == self.siv else FAILURE
            return 0
        need(False)
    def export(self):
        kb = 8 * len(self.key)
        return self.pack((b2v(self.key), kb), (self.nonce, 96), (self.ctr & mask(32), 32), (self.siv, 128), (self.tmp, 128),
                         ((self.ctr >> 32) << 15 | self.lbl, 16))
    @classmethod
    def from_sc(cls, st, sc, keybytes=16, policy=3, cipher='AES128'):
        m = cls._blank(keybytes, policy, cipher)
        k, n, c, siv, tmp, x = cls.unpack(sc, (8 * keybytes, 96, 32, 128, 128, 16))
        m.key = v2b(k, keybytes); m.nonce, m.siv, m.tmp, m.st = n, siv, tmp, st
        m.ctr = c | (x >> 15) << 32; m.lbl = x & 127
        if st != READY: m._derive()
        return m

# =================================================================== OCB / OCB_NONCE
def ntz(n): return (n & -n).bit_length() - 1
def ocb_pad(x, n): return cat((0, 120 - n), (0x80, 8), (sl(x, n - 1, 0) if n else 0, n))
def nonce_be(N, n):
    r, q = n % 8, -(-n // 8)
    return bswap(sl(N, 8 * q - 1, 0), q) >> ((8 - r) % 8)

class OCB(Base):
    NAME = 'OCB'
    def _leave(self, cur, nxt):
        if cur == HABL: need(self.lbl == 0)    # MR10 item 5: leaving the final-block State before its kl.exec
    TRANS = {READY: {SAV}, SAV: {ABSORB}, ABSORB: {HABL}, HABL: {ENC, DEC}, ENC: {ELB}, ELB: {ETF}, DEC: {DLB}, DLB: {HV}}
    SETF = {SAV: 'B', ABSORB: 'B', HABL: 'B', ENC: 'A', DEC: 'A', ELB: 'B', DLB: 'B', ETF: 'A', HV: 'A'}
    EXF = {SAV: 'B', ABSORB: 'B', HABL: 'B', ENC: 'A', DEC: 'A', ELB: 'A', DLB: 'A', ETF: 'C', HV: 'B'}
    GATE = {ENC: 0, ELB: 0, ETF: 0, DEC: 1, DLB: 1, HV: 1}
    SAMEOK = (SAV,)
    def __init__(self, key, policy=3, nonce=None):
        super().__init__(key, policy)
        if nonce is not None:
            self.N, self.N_len = nonce
            need_ok = 6 <= self.N_len <= 120
            if not need_ok: raise ValueError('N_len outside [6,120]')
    def _expform(self, st): return 'D' if st in (ELB, DLB) and self.lbl == 0 else self.EXF.get(st)
    def _noexec(self, st): return st == HABL and self.lbl == 0
    def _ready(self):
        if not hasattr(self, 'N') or not self.PRESET: self.N = self.N_len = 0
        self.hasN = False
        self.hash_A = self.csum = self.index = 0
        if not hasattr(self, 'offset'): self.offset = self.lbl = 0     # Ready entry leaves offset, L*, last_block_len
        self.tag_len = 128
        if not hasattr(self, 'Ls'): self.Ls = None
        self.Ld = None; self.L = []
    PRESET = False
    def _setup(self):
        self.Ls = self.E(0); self.Ld = double(self.Ls); self.L = [double(self.Ld)]
        for i in range(48): self.L.append(double(self.L[-1]))
    def _enter(self, st, xs, inp):
        if st == SAV:
            need(6 <= xs <= 120); self.N_len, self.N, self.hasN = xs, 0, False
        elif st == ABSORB:
            need(self.hasN or self.PRESET); need(xs in (64, 96, 128))
            self.index, self.tag_len, self.offset = 1, xs, 0; self._setup()
        elif st in (ETF, HV):          # Form A setst out of Enc/Dec_Last_Block: only with last_block_len = 0; does the Form D exec
            need(self.lbl == 0 and self.index <= MAX_BLOCKS)
            self.csum = self.E(self.csum ^ self.offset ^ self.Ld) ^ self.hash_A
        elif st in (HABL, ELB, DLB):
            need(xs % 8 == 0 and 0 <= xs <= 120); self.lbl = xs
        elif st in (ENC, DEC):
            Nb = cat((self.tag_len % 128, 7), (0, 120 - self.N_len), (1, 1), (nonce_be(self.N, self.N_len), self.N_len))
            bottom = sl(Nb, 5, 0)
            Ktop = self.E(bswap(cat((sl(Nb, 127, 6), 122), (0, 6)), 16))
            Kb = bswap(Ktop, 16)
            Stretch = cat((Kb, 128), (sl(Kb, 127, 64) ^ sl(Kb, 119, 56), 64))
            self.index = 1; self.offset = bswap(sl(Stretch, 191 - bottom, 64 - bottom), 16)
    def _exec(self, st, inp, kllen, klstart, halt_at):
        if st == SAV:
            q = -(-self.N_len // 8)
            need(kllen is not None and kllen >= 8 * q)          # MR8, MR6
            x = sl(inp, 8 * q - 1, 0)
            x &= ~(mask((8 - self.N_len) % 8) << 8 * (q - 1))
            self.N, self.hasN = x, True; return 0
        if st == ABSORB:
            def f(x):
                need(self.index <= MAX_BLOCKS)
                self.offset ^= self.L[ntz(self.index)]
                self.hash_A ^= self.E(x ^ self.offset); self.index += 1
            return self._multi(inp, kllen, klstart, halt_at, f)
        if st == HABL:
            need(self.lbl != 0 and kllen is not None and kllen >= self.lbl)   # MR10: empty final input admits no kl.exec, even KLLEN = 0
            need(self.index <= MAX_BLOCKS)
            self.offset ^= self.Ls
            self.hash_A ^= self.E(ocb_pad(inp, self.lbl) ^ self.offset); self.lbl = 0; return 0
        if st == ENC:
            def f(x):
                need(self.index <= MAX_BLOCKS)
                self.offset ^= self.L[ntz(self.index)]; self.csum ^= x
                o = self.offset ^ self.E(x ^ self.offset); self.index += 1; return o
            return self._multi(inp, kllen, klstart, halt_at, f)
        if st == DEC:
            def f(x):
                need(self.index <= MAX_BLOCKS)
                self.offset ^= self.L[ntz(self.index)]
                t = self.offset ^ self.D(x ^ self.offset); self.csum ^= t; self.index += 1; return t
            return self._multi(inp, kllen, klstart, halt_at, f)
        if st in (ELB, DLB):
            n = self.lbl
            if n == 0:
                self.csum = self.E(self.csum ^ self.offset ^ self.Ld) ^ self.hash_A; o = 0
            else:
                need(kllen is not None and kllen >= n)
                need(self.index <= MAX_BLOCKS)
                self.offset ^= self.Ls
                pad = sl(self.E(self.offset), n - 1, 0); o = sl(inp, n - 1, 0) ^ pad
                t = self.offset ^ ocb_pad(inp if st == ELB else o, n)
                self.csum = self.E(self.csum ^ t ^ self.Ld) ^ self.hash_A
            self.st = ETF if st == ELB else HV
            return o
        if st == ETF:
            need(kllen is not None and kllen >= self.tag_len)
            self.st = SUCCESS; return sl(self.csum, self.tag_len - 1, 0)
        if st == HV:
            need(kllen is not None and kllen >= self.tag_len)
            ok = sl(inp, self.tag_len - 1, 0) == sl(self.csum, self.tag_len - 1, 0)
            self.st = SUCCESS if ok else FAILURE; return 0
        need(False)
    def export(self):
        return self.pack((b2v(self.key), 8 * len(self.key)), (self.N, 120), (self.N_len, 7), (0, 1),
                         (self.Ls if self.Ls is not None else 0, 128), (self.offset, 128), (self.hash_A, 128), (self.csum, 128),
                         (self.index, 49), (self.tag_len // 32 - 2, 2), (self.lbl, 7))
    @classmethod
    def from_sc(cls, st, sc, keybytes=16, policy=3):
        m = cls._blank(keybytes, policy)
        k, N, nl, _, Ls, off, hA, cs, ix, tl, lb = cls.unpack(sc, (8 * keybytes, 120, 7, 1, 128, 128, 128, 128, 49, 2, 7))
        m.key = v2b(k, keybytes); m.st, m.N, m.N_len, m.offset, m.hash_A, m.csum, m.index, m.lbl = st, N, nl, off, hA, cs, ix, lb
        m.hasN = m.N_len != 0
        if tl == 3 or (cls.PRESET and not 6 <= nl <= 120): m._fail(); return m
        m.tag_len = 32 * (tl + 2)
        if st not in (READY, SAV): m._setup()
        return m

class OCB_NONCE(OCB):
    NAME = 'OCB_NONCE'
    PRESET = True
    TRANS = {READY: {ABSORB}, ABSORB: {HABL}, HABL: {ENC, DEC}, ENC: {ELB}, ELB: {ETF}, DEC: {DLB}, DLB: {HV}}
    SETF = dict(OCB.SETF)
    NOKEYDER = True
    SAMEOK = ()
    @classmethod
    def _blank(cls, kb, policy, cipher='AES128'): return cls(bytes(kb), (0, 6), policy)
    def __init__(self, key, nonce, policy=3):
        N, self.N_len = nonce
        if not 6 <= self.N_len <= 120: raise ValueError('N_len outside [6,120]')
        q = -(-self.N_len // 8)      # PI loads N as the Set_Aux_Value kl.exec does: pad bits of byte q-1 cleared
        self.N = sl(N, 8 * q - 1, 0) & ~(mask((8 - self.N_len) % 8) << 8 * (q - 1))
        Base.__init__(self, key, policy)

# =================================================================== CMAC
class CMAC(Base):
    NAME = 'CMAC'
    TRANS = {READY: {ABSORB}, ABSORB: {HABL}, HABL: {HOUT, HV}}
    SETF = {ABSORB: 'A', HABL: 'B', HOUT: 'A', HV: 'B'}
    EXF = {ABSORB: 'B', HABL: 'B', HOUT: 'C', HV: 'B'}
    GATE = {HOUT: 0, HV: 1}
    def __init__(self, key, policy=3, cipher='AES128'):
        self.CIPHER = cipher
        self.B = 64 if cipher == 'TDEA' else 128
        super().__init__(key, policy); self.cipher = cipher
        self._ready()
    def _ready(self):
        self.hash = self.lbl = self.tag_len = 0; self.any = self.all = False
    def _dbl(self, s): return double(s, self.B)
    def _noexec(self, st): return st == HABL and (self.all or self.lbl == 0)
    def _subkeys(self):
        K1 = self._dbl(self.E(0)); return K1, self._dbl(K1)
    def _enter(self, st, xs, inp):
        b = self.B
        if st == HABL:
            need(xs % 8 == 0 and xs <= b); need(xs != 0 or not self.any)
            self.lbl = xs
            if xs == 0:
                K1, K2 = self._subkeys()
                self.hash = self.E(self.hash ^ cat((0, b - 8), (0x80, 8)) ^ K2); self.all = True
        elif st == HOUT: need(self.all)
        elif st == HV:
            need(xs % 8 == 0 and xs >= 64 and self.all); self.tag_len = min(xs, b)
    def _exec(self, st, inp, kllen, klstart, halt_at):
        b = self.B
        if st == ABSORB:
            def f(x): self.hash = self.E(self.hash ^ x); self.any = True
            return self._multi(inp, kllen, klstart, halt_at, f)
        if st == HABL:
            need(kllen is not None and kllen >= self.lbl)
            need(not self.all and self.lbl != 0)                 # MR10: no kl.exec, even KLLEN = 0
            K1, K2 = self._subkeys(); n = self.lbl
            if n == b: t = self.hash ^ sl(inp, b - 1, 0) ^ K1
            else: t = self.hash ^ cat((0, b - 8 - n), (0x80, 8), (sl(inp, n - 1, 0), n)) ^ K2
            self.hash = self.E(t); self.all = True; return 0
        if st == HOUT:
            need(kllen is not None and kllen >= 64); self.st = SUCCESS
            return self.hash & mask(min(kllen, b))
        if st == HV:
            need(kllen is not None and kllen >= self.tag_len)
            ok = sl(inp, self.tag_len - 1, 0) == sl(self.hash, self.tag_len - 1, 0)
            self.st = SUCCESS if ok else FAILURE; return 0
        need(False)
    def derive_src(self):
        if self.st == INV: return None
        if self.st != HOUT or not self.all: self._fail(); return None
        return v2b(self.hash, self.B // 8)
    def export(self):
        b = self.B
        return self.pack((b2v(self.key), 8 * len(self.key)), (self.hash, b), (self.lbl, 32), (self.tag_len, 32), (int(self.any), 1), (int(self.all), 1))
    @classmethod
    def from_sc(cls, st, sc, keybytes=16, policy=3, cipher='AES128'):
        m = cls._blank(keybytes, policy, cipher)
        k, h, lb, tl, a, al = cls.unpack(sc, (8 * keybytes, m.B, 32, 32, 1, 1))
        m.key = v2b(k, keybytes); m.st, m.hash, m.lbl, m.tag_len, m.any, m.all = st, h, lb, tl, bool(a), bool(al)
        return m
