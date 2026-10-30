"""Locker model of the sponge Machines (SHA-3/SHAKE, KMAC, Ascon-Hash256/XOF128/CXOF128, Ascon-AEAD128),
written from Zkl-ISA-machines.adoc (KLE-hash-functions-MACs-XOFs, KLE-process-VLI, KLE-SHA-3, KLE-KMAC, KLE-Ascon-*).

L = Locker(kind, policy=0, K=b'', S=b'', key=b'', tag_len_p=None);  L.setst(imm, form, xs=0, inp=b'');
  AEAD: tag_len_p defaults to 128; a value outside 64..128 gives Invalid (MR12).  policy 0 means 3, and 2 for
  _NONCE, which admits no other value (MR1): any other policy gives Invalid.
L.exec(form, inp=b'' | None, klstart=0, out=None, halt=None) -> klstart'   (0 when the instruction completed)
  Form B: inp = INPUT bytes;  Form C/A output: out = bytearray (window, KLLEN = len(out)); Form A input: inp.
  halt = n: stop at the first interruption point with at least n bytes done (resumable via klstart').
L.export() / L.import_(sc, st)  serialized content; L.mdh_state() -> (State, StateExtension).
Also modeled: AEAD variants _NONCE/_NONCE_MASK, SKID (sks dict), rstrl, unsupported MachinePolicy, exec_d (Form D), Secret/derive.
Not modeled: SCC authentication, GR40 SCProtection narrowing.
"""
from common import *
import sponge_ref as R

READY, ABSORB, LAST, VERIFY, OUTPUT, ENC, DEC, ENCLAST, DECLAST, AUX = 1, 2, 3, 5, 6, 7, 8, 9, 10, 13
SUCCESS, FAILURE = 54, 55
SE_INV = 2
_BI = lambda v, n: R.bits_of(v, n)

SHA3P = {  # b, t, d, xof, suffix
    'SHA3-224': (1152, 224, 224, False, [0, 1]), 'SHA3-256': (1088, 256, 256, False, [0, 1]),
    'SHA3-384': (832, 384, 384, False, [0, 1]), 'SHA3-512': (576, 512, 512, False, [0, 1]),
    'SHAKE128': (1344, 1344, 0, True, [1, 1, 1, 1]), 'SHAKE256': (1088, 1088, 0, True, [1, 1, 1, 1])}
KMACP = {'KMAC128': (1344, False), 'KMACXOF128': (1344, True), 'KMAC256': (1088, False), 'KMACXOF256': (1088, True)}
AEADV = {'ASCON-AEAD128': 'base', 'ASCON-AEAD128_NONCE': 'wsn', 'ASCON-AEAD128_NONCE_MASK': 'mask'}
ASCONP = {'ASCON-HASH256': (R.IV_HASH, 256), 'ASCON-XOF128': (R.IV_XOF, 0), 'ASCON-CXOF128': (R.IV_CXOF, 0)}


class Locker:
    def __init__(self, kind, policy=0, K=b'', S=b'', key=b'', nonce=b'', K2=b'', skid=None, sks=None, tag_len_p=None):
        self.kind, self.policy = kind, policy
        self.skid, self.sks = skid, sks or {}
        bad = False
        if skid is not None:                        # GR75/GR76: the SKS resolves the SKID
            ent = self.sks.get(skid)
            if ent is None: bad = True
            elif kind == 'ASCON-AEAD128_NONCE_MASK': key, K2 = ent
            elif kind in KMACP: K = ent
            else: key = ent
        if kind in SHA3P: self.fam = 'sha3'; self.b, self.t, self.d, self.xof, self.suf = SHA3P[kind]; self.n = 1600
        elif kind in KMACP:
            self.fam = 'kmac'; self.b, self.xof = KMACP[kind]; self.t = self.b; self.d = 0; self.n = 1600
            rb = self.b // 8
            self.cs = b2v(R.bytepad(R.encode_string(b'KMAC') + R.encode_string(S), rb))
            self.kb = b2v(R.bytepad(R.encode_string(K), rb))
        elif kind in ASCONP:
            self.fam = 'ahash'; self.iv, self.d = ASCONP[kind]; self.b = self.t = 64; self.n = 320; self.xof = self.d == 0
        elif kind in AEADV:
            self.fam = 'aead'; self.var = AEADV[kind]; self.key = b2v(key); self.b = 128; self.n = 320; self.xof = False
            self.nonce = b2v(nonce); self.k2 = b2v(K2)
            self.tag_len_p = 128 if tag_len_p is None else tag_len_p
            if self.var == 'wsn' and policy in (0, 2): self.policy = 2
            elif self.var == 'wsn': bad = True                  # MR1: a preset nonce admits only MachinePolicy 0b10
            if not 64 <= self.tag_len_p <= 128: bad = True       # MR12: provisioning completes into Invalid
        else: raise ValueError(kind)
        self.P = R.keccak_f if self.n == 1600 else R.ascon12
        self.st, self.se = READY, 0
        self._ready()
        if bad: self.invalid()
        elif policy and (self.fam in ('sha3', 'ahash') or (self.fam == 'kmac' and self.xof)):
            self.invalid(); self.se = 1             # unsupported Metadata: State 0, StateExtension 1

    # ---- helpers
    def mdh_state(self): return (self.st, self.se)
    def is_error(self): return self.st == 0 and self.se != 0
    def inert(self): return self.st == 0 and self.se == 0

    def _ready(self):
        self.bb = self.lbl = self.ol = self.cum = 0
        self.L = 0; self.zlen = 0; self.tag_len = self.tag_len_p if self.fam == 'aead' else 128
        if self.fam in ('sha3', 'kmac'): self.s = 0
        elif self.fam == 'ahash':
            self.s = R.ascon12(self.iv)
        else: self.s = 0

    def invalid(self):
        """GR35: clear Content beyond the MDH."""
        self.st, self.se = 0, SE_INV
        self.s = self.bb = self.lbl = self.ol = self.cum = self.L = self.zlen = 0
        if self.fam == 'aead': self.key = self.nonce = self.k2 = 0
        if self.fam == 'kmac': self.cs = self.kb = 0

    def clear(self):
        self.invalid(); self.se = 0

    def w(self, i): return (self.s >> (64 * i)) & mask(64)
    def xw(self, i, v): self.s ^= (v & mask(64)) << (64 * i)
    def sw(self, i, v): self.s = (self.s & ~(mask(64) << (64 * i))) | ((v & mask(64)) << (64 * i))
    def perm(self, r): self.s = R.ascon_p(self.s, r)

    def _emit(self, v, nbits):
        """accumulate nbits of v into the rate at bb; process on completed block."""
        pos = 0
        while pos < nbits:
            a = min(nbits - pos, self.b - self.bb)
            self.s ^= ((v >> pos) & mask(a)) << self.bb
            pos += a; self.bb += a
            if self.bb == self.b: self.s = self.P(self.s); self.bb = 0

    def _pad101(self, suffix):
        self._emit(b2v(b'') + sum(x << i for i, x in enumerate(suffix + [1])), len(suffix) + 1)
        while self.bb != self.b - 1: self._emit(0, min(self.b - 1 - self.bb, 64))
        self._emit(1, 1)

    # ---- finalize
    def _finalize(self):
        if self.fam == 'sha3': self._pad101(self.suf)
        elif self.fam == 'kmac':
            re = R.right_encode(0 if self.xof else self.L)
            self._emit(b2v(re), 8 * len(re)); self._pad101([0, 0])
        elif self.fam == 'ahash':
            self.xw(0, 1 << self.bb); self.perm(12)

    # ---- setst
    def setst(self, imm, form, xs=0, inp=b''):
        if self.is_error() or self.inert(): return
        if imm == 0: self.clear(); return
        if imm == READY:
            if form != 'A': return self.invalid()   # wrong Form: GR20 item 4, no exception
            self._ready(); self.st = READY; return
        if self.st in (SUCCESS, FAILURE): return self.invalid()
        if imm in (SUCCESS, FAILURE): return self.invalid()
        getattr(self, '_setst_' + self.fam)(imm, form, xs, inp)

    def _gen_setst(self, imm, form, xs):
        """shared transitions of the hash framework; returns True if handled."""
        st = self.st
        if imm == ABSORB and st in (READY, AUX) and form == 'A':
            if self.kind == 'ASCON-CXOF128':
                if st == READY: self.perm(12); self.xw(0, 1); self.perm(12)   # Z0 = 0, then pad(empty)
                elif self.cum != self.zlen: return self.invalid() or True
                else: self.xw(0, 1 << self.bb); self.perm(12)
                self.zlen = self.cum = 0
            elif st == AUX: return False
            self.st = ABSORB; self.lbl = self.b; self.bb = 0; return True
        if imm == LAST and st == ABSORB and form in 'AB':
            if form == 'A': xs = 0
            if xs > self.b or (xs % 8 and not self.bits_ok): return self.invalid() or True
            self.st = LAST; self.lbl = xs; return True
        if imm == OUTPUT_ and st in (ABSORB, LAST) and form in 'AB':
            if st == LAST and self.lbl != 0: return self.invalid() or True
            if form == 'A': xs = 0
            return self._to_output(xs)
        return False

    bits_ok = True
    def _to_output(self, xs):
        if xs:
            if (self.xof and xs >= 1 << 32) or (not self.xof and xs > self.d) or xs % 8: return self.invalid() or True
        self._finalize(); self.bb = self.lbl = 0
        self.ol = xs if xs else (0 if self.xof else self.d); self.st = OUTPUT_; return True

    def _setst_sha3(self, imm, form, xs, inp):
        if not self._gen_setst(imm, form, xs): self.invalid()

    def _setst_ahash(self, imm, form, xs, inp):
        if self._gen_setst(imm, form, xs): return
        if imm == AUX and self.kind == 'ASCON-CXOF128' and self.st in (READY, AUX) and form == 'B' and xs <= 2048:
            self.s = R.ascon12(self.iv); self.zlen = xs; self.bb = self.cum = 0
            self.xw(0, xs); self.perm(12); self.st = AUX; return
        self.invalid()

    def _setst_ahash_absorb_hook(self): pass

    def _setst_kmac(self, imm, form, xs, inp):
        st = self.st
        if imm == ABSORB and st == READY and form == 'A':
            self.s ^= self.cs; self.s = self.P(self.s); self.s ^= self.kb; self.s = self.P(self.s)
            self.st = ABSORB; self.lbl = self.b; self.bb = 0; return
        if imm == LAST and st == ABSORB and form in 'AB':
            return self._gen_setst(imm, form, xs) or self.invalid()
        if imm in (OUTPUT_, VERIFY) and st in (ABSORB, LAST) and form in 'AB':
            if st == LAST and self.lbl != 0: return self.invalid()
            if form == 'A': xs = 0
            if imm == OUTPUT_:
                if not self.xof:
                    if form != 'B' or not (32 <= xs < 1 << 32) or not self.policy & 1 and self.policy: return self.invalid()
                elif xs and (xs % 8 or xs >= 1 << 32): return self.invalid()
            else:
                if self.xof or form != 'B' or xs % 8 or not 32 <= xs <= self.b or (self.policy and not self.policy & 2): return self.invalid()
            self.L = xs; self._finalize(); self.bb = self.lbl = 0
            if imm == OUTPUT_: self.ol = xs; self.st = OUTPUT_
            else: self.ol = xs; self.st = VERIFY
            return
        self.invalid()

    def _setst_aead(self, imm, form, xs, inp):
        st = self.st; pol = self.policy
        g0 = pol == 0 or pol & 1; g1 = pol == 0 or pol & 2
        if imm == AUX and st == READY and form == 'B' and xs == self.tag_len_p: self.tag_len = xs; return
        if imm == ABSORB and st == READY and form == ('A' if self.var == 'wsn' else 'C'):
            n = self.nonce if self.var == 'wsn' else b2v(inp[:16]) ^ (self.k2 if self.var == 'mask' else 0); k = self.key
            self.s = 0; self.sw(0, 0x00001000808c0001); self.sw(1, k); self.sw(2, k >> 64)
            self.sw(3, n); self.sw(4, n >> 64); self.perm(12); self.xw(3, k); self.xw(4, k >> 64)
            self.st = ABSORB; return
        if st in (ENCLAST, DECLAST) and self.lbl: return self.invalid()   # leaving before the exec
        if imm in (ENC, DEC) and st == ABSORB and form == 'A' and (g0 if imm == ENC else g1):
            self.xw(4, 1 << 63); self.st = imm; return
        if imm in (ENCLAST, DECLAST) and st == (ENC if imm == ENCLAST else DEC) and form == 'B' and xs <= 127 and (g0 if imm == ENCLAST else g1):
            if xs == 0: self.xw(0, 1); self.st = OUTPUT_ if imm == ENCLAST else VERIFY
            else: self.lbl = xs; self.st = imm
            return
        if imm in (OUTPUT_, VERIFY) and st == (ENC if imm == OUTPUT_ else DEC) and form == 'A' and (g0 if imm == OUTPUT_ else g1):
            self.xw(0, 1); self.st = imm; return     # bypass == Xs=0 entry (MR10 item 2)
        self.invalid()

    # ---- exec
    def exec(self, form, inp=None, klstart=0, out=None, halt=None):
        self._zk = klstart
        if self.is_error() or self.inert():
            if out is not None and form in 'AC':
                out[self._zk:] = bytes(max(0, len(out) - self._zk))   # GR34: [klstart, top-1] only
            return 0
        if self.st in (READY, SUCCESS, FAILURE): return self._inv_exec(out)
        return getattr(self, '_exec_' + self.fam)(form, inp, klstart, out, halt)

    def _inv_exec(self, out):
        self.invalid()
        self._zero(out); return 0

    def _zero(self, out):
        if out is not None: out[self._zk:] = bytes(max(0, len(out) - self._zk))   # GR34

    def _exec_hash(self, form, inp, klstart, out, halt):
        st = self.st
        if st in (ABSORB, LAST, AUX):
            if form != 'B': return self._inv_exec(out)
            return self._exec_in(st, inp, klstart, halt)
        if st == OUTPUT_ and form == 'C': return self._exec_out(klstart, out, halt)
        if st == VERIFY and form == 'B': return self._exec_verify(inp, klstart)
        return self._inv_exec(out)

    _exec_sha3 = _exec_hash
    _exec_kmac = _exec_hash
    _exec_ahash = _exec_hash

    def _exec_in(self, st, inp, klstart, halt):
        K = 8 * len(inp); v = b2v(inp)
        if st == LAST:
            if self.lbl == 0: self.invalid(); return 0     # MR10: no exec admitted, even an empty window
            if 8 * klstart >= K: return 0                  # empty window (GR52 item 1)
            if K < self.lbl or klstart: self.invalid(); return 0   # length (item 2), interruption point (item 3)
            ib = 0
            while ib < self.lbl:
                a = min(self.lbl - ib, self.b - self.bb)
                self.s ^= ((v >> ib) & mask(a)) << self.bb; ib += a; self.bb += a
                if self.bb == self.b: self.s = self.P(self.s); self.bb = 0
            self.lbl = 0; return 0
        ib = 8 * klstart
        if st == AUX and self.zlen == 0: self.invalid(); return 0   # Z_len = 0: any kl.exec, even an empty window
        if ib >= K: return 0                       # empty window (GR52)
        if klstart and self.bb != 0: self.invalid(); return 0
        mx = self.zlen if st == AUX else 0
        if st == AUX and self.cum >= mx: self.invalid(); return 0
        while ib < K:
            a = min(K - ib, self.b - self.bb)
            if st == AUX: a = min(a, mx - self.cum)
            self.s ^= ((v >> ib) & mask(a)) << self.bb
            ib += a; self.bb += a
            if st == AUX: self.cum += a
            if self.bb == self.b: self.s = self.P(self.s); self.bb = 0
            if st == AUX and self.cum == mx: return 0
            if ib < K and halt is not None and ib // 8 >= halt: return ib // 8
        return 0

    def _exec_out(self, klstart, out, halt):
        K = 8 * len(out); ob = 8 * klstart
        if ob >= K: return 0
        if klstart and self.bb != 0: self.invalid(); self._zero(out); return 0
        res = b2v(out); keep = res & mask(ob)
        while ob < K:
            a = min(K - ob, self.t - self.bb)
            if self.ol: a = min(a, self.ol)
            keep |= ((self.s >> self.bb) & mask(a)) << ob
            ob += a; self.bb += a
            if self.ol:
                self.ol -= a
                if self.ol == 0:
                    out[:] = v2b(keep, len(out)); self.st = SUCCESS; return 0
            if self.bb == self.t:
                self.s = self.P(self.s); self.bb = 0
                if ob < K and halt is not None and ob // 8 >= halt:
                    out[:] = v2b(keep, len(out)); return ob // 8
        out[:] = v2b(keep, len(out)); return 0

    def _exec_verify(self, inp, klstart=0):
        Lb = self.L
        if 8 * klstart >= 8 * len(inp): return 0                  # GR52 item 1: empty window
        if 8 * len(inp) < Lb: self.invalid(); return 0
        self.st = SUCCESS if (b2v(inp) ^ self.s) & mask(Lb) == 0 else FAILURE
        return 0

    # ---- AEAD
    def _gate_ok(self, st):
        p = self.policy or 3
        if self.fam == 'aead':
            if st in (ENC, ENCLAST, OUTPUT_): return bool(p & 1)
            if st in (DEC, DECLAST, VERIFY): return bool(p & 2)
        elif self.fam == 'kmac' and not self.xof:
            if st == OUTPUT_: return bool(p & 1)
            if st == VERIFY: return bool(p & 2)
        return True

    def rstrl(self, rq):
        """kl.rstrl: AND-narrowing of MachinePolicy (all-ones leaves it); GR25: forbidden value -> Invalid."""
        if self.is_error() or self.inert(): return
        if rq == mask(64): return
        if self.fam == 'aead' or (self.fam == 'kmac' and not self.xof):
            new = (self.policy or 3) & rq
            if new & 3 == 0: return self.invalid()
            self.policy = new
        # ungated Machine: MachinePolicy is 0 and stays 0; no State changes

    def exec_d(self, iobuf, top, klstart=0, halt=None):
        """Form D kl.exec (Zklio): KLIOBUF [klstart, top-1] stands for the native vector operand (GR11, GR12)."""
        if top == 0: raise IllegalInstruction('KLIOBUF not configured')   # GR14
        st = self.st
        if self.is_error() or self.inert():
            iobuf[klstart:top] = bytes(max(0, top - klstart)); return 0     # GR34
        nat = {ABSORB: 'B', LAST: 'B', AUX: 'B', VERIFY: 'B', OUTPUT_: 'C', ENC: 'A', DEC: 'A', ENCLAST: 'A', DECLAST: 'A'}.get(st)
        if self.fam == 'aead' and st == VERIFY: nat = 'B'
        if nat is None:
            self.invalid(); iobuf[klstart:top] = bytes(max(0, top - klstart)); return 0
        if nat == 'B': return self.exec('B', bytes(iobuf[:top]), klstart, None, halt)
        out = bytearray(iobuf[:top]); inp = bytes(iobuf[:top])
        ks = self.exec(nat, inp if nat == 'A' else None, klstart, out, halt)
        iobuf[:top] = out; return ks

    def _exec_aead(self, form, inp, klstart, out, halt):
        st = self.st
        if not self._gate_ok(st): return self._inv_exec(out)
        if klstart and not (self.st in (ENCLAST, DECLAST) and 8 * klstart >= 8 * len(inp)): raise NotImplementedError('AEAD klstart')
        if st == ABSORB and form == 'B':
            if len(inp) % 16: self.invalid(); return 0
            for i in range(0, len(inp), 16):
                self.xw(0, b2v(inp[i:i + 8])); self.xw(1, b2v(inp[i + 8:i + 16])); self.perm(8)
            return 0
        if st in (ENC, DEC) and form == 'A':
            I0, I1 = b2v(inp[:8]), b2v(inp[8:16])
            if st == ENC:
                self.xw(0, I0); self.xw(1, I1); out[:] = v2b(self.w(0) | self.w(1) << 64, 16)
            else:
                out[:] = v2b((self.w(0) ^ I0) | (self.w(1) ^ I1) << 64, 16); self.sw(0, I0); self.sw(1, I1)
            self.perm(8); return 0
        lb = self.lbl
        if st in (ENCLAST, DECLAST) and form == 'A':
            if klstart >= len(inp): return 0                        # GR52 item 1: empty window keeps the State
            if 8 * len(inp) < lb: return self._inv_exec(out)       # no zero padding: granularity
            if klstart: return self._inv_exec(out)
        if st == ENCLAST and form == 'A':
            tmp = b2v(inp[:16]) & mask(lb) | 1 << lb
            self.xw(0, tmp); self.xw(1, tmp >> 64)
            out[:] = v2b((self.w(0) | self.w(1) << 64) & mask(lb), 16); self.st = OUTPUT_; return 0
        if st == DECLAST and form == 'A':
            Sr = self.w(0) | self.w(1) << 64; Pl = (Sr ^ b2v(inp[:16])) & mask(lb)
            out[:] = v2b(Pl, 16); Sr ^= Pl | 1 << lb
            self.sw(0, Sr); self.sw(1, Sr >> 64); self.st = VERIFY; return 0
        if st in (OUTPUT_, VERIFY): return self._aead_tag(form, inp, out, klstart)
        return self._inv_exec(out)

    def _aead_tag(self, form, inp, out, klstart=0):
        tl = self.tag_len
        if self.st == OUTPUT_ and form != 'C' or self.st == VERIFY and form != 'B': return self._inv_exec(out)
        if klstart >= len(out if self.st == OUTPUT_ else inp): return 0   # GR52 item 1: empty window
        if (8 * len(out) if self.st == OUTPUT_ else 8 * len(inp)) < tl: return self._inv_exec(out)
        k = self.key; self.xw(2, k); self.xw(3, k >> 64); self.perm(12); self.xw(3, k); self.xw(4, k >> 64)
        tag = (self.w(3) | self.w(4) << 64) & mask(tl)
        if self.st == OUTPUT_: out[:] = v2b(tag, len(out)); self.st = SUCCESS
        else: self.st = SUCCESS if b2v(inp) & mask(tl) == tag else FAILURE
        return 0

    # ---- serialization
    def _viii(self):
        return (self.zlen & 0xffff | self.cum << 16) if (self.fam == 'ahash' and self.st == AUX) else self.ol

    def export(self):
        if self.fam == 'aead':
            kf = v2b(self.skid, 8) if self.skid is not None else v2b(self.key, 16)
            if self.var == 'mask' and self.skid is None: kf += v2b(self.k2, 16)
            r = kf + v2b(self.s, 40) + v2b(self.lbl, 2) + v2b(self.tag_len, 2) + v2b(self.tag_len_p, 2)
            if self.var == 'wsn': r += v2b(self.nonce, 16)
            return r + bytes(-len(r) % 16)
        n = 200 if self.n == 1600 else 40
        head = v2b(self.s, n) + v2b(self.bb, 2) + v2b(self.lbl, 2) + v2b(self._viii(), 4)
        if self.fam == 'kmac':
            head += v2b(self.cs, self.b // 8) + (v2b(self.skid, 8) if self.skid is not None else v2b(self.kb, self.b // 8))
        return head

    def import_(self, sc, st):
        """st: State to restore (the MDH is not part of SC here)."""
        if self.fam == 'aead':
            o = 8 if self.skid is not None else 16
            if self.skid is not None:
                ent = self.sks.get(b2v(sc[:8]))
                if ent is None: return self.invalid()             # GR76
                self.key, self.k2 = ent if self.var == 'mask' else (ent, 0)
            else:
                self.key = b2v(sc[:16])
                if self.var == 'mask': self.k2 = b2v(sc[16:32]); o = 32
            self.s = b2v(sc[o:o + 40]); self.lbl = b2v(sc[o + 40:o + 42]); self.tag_len = b2v(sc[o + 42:o + 44])
            self.tag_len_p = b2v(sc[o + 44:o + 46])
            if self.var == 'wsn': self.nonce = b2v(sc[o + 46:o + 62])
            if not 64 <= self.tag_len_p <= 128: return self.invalid()   # MR12: import completes into Invalid
        else:
            n = 200 if self.n == 1600 else 40
            self.s = b2v(sc[:n]); self.bb = b2v(sc[n:n + 2]); self.lbl = b2v(sc[n + 2:n + 4]); v = b2v(sc[n + 4:n + 8])
            if self.fam == 'ahash' and st == AUX: self.zlen, self.cum = v & 0xffff, v >> 16
            else: self.ol = v
            if self.fam == 'kmac':
                rb = self.b // 8; self.cs = b2v(sc[n + 8:n + 8 + rb])
                if self.skid is None: self.kb = b2v(sc[n + 8 + rb:n + 8 + 2 * rb])
                self.L = self.ol if st in (OUTPUT_, VERIFY) else 0
        self.st, self.se = st, 0


# ---- kl.derive (GR37-GR43, endpoint table of KLE-derive-endpoints)
class Secret:
    """A source: restricted=True is an ML-KEM sharedkey; False an ECC shared secret in Output or a GR43 output (CMAC, keystream).
    shared=False marks a non-shared-secret output (CMAC tag): admitted into a key, not into a hash input."""
    def __init__(self, data, restricted=True, shared=True, scprot=1): self.data, self.restricted, self.shared, self.bad, self.scprot = data, restricted, shared, False, scprot
    def invalid(self): self.bad = True; self.data = b''

def derive(src, dst, length, klstart=0):
    """kl.derive dst, src, length. Returns nothing; endpoints become Invalid per GR39 (checked in order)."""
    if isinstance(src, Locker) and (src.is_error() or src.inert()) or isinstance(dst, Locker) and (dst.is_error() or dst.inert()): return
    if klstart: return dst.invalid()                                                      # 1
    if not isinstance(src, Secret): return src.invalid()                                  # 2: not a source endpoint
    fam = dst.fam
    key_n = {'base': 16, 'mask': 32}.get(getattr(dst, 'var', None)) if fam == 'aead' else None
    ok = (key_n and dst.st == READY and dst.skid is None and dst.tag_len_p == 128) or (fam != 'aead' and dst.st == ABSORB)
    if not ok: return dst.invalid()                                                       # 3: not a destination endpoint
    if fam != 'aead' and not src.shared or key_n == 32 and src.restricted:                # 4: pair not admitted
        dst.invalid(); return src.invalid()
    if key_n:
        if length < key_n: return dst.invalid()                                           # 6
        if len(src.data) < key_n: return src.invalid()                                    # 7
    elif length != len(src.data) or length == 0: return dst.invalid()                     # 6 (hash input = whole secret)
    if src.restricted and getattr(dst, 'scprot', 1) < src.scprot:                         # GR40: SCProtection (MDH narrowing not modelled)
        dst.invalid(); dst.se = 5; return
    if key_n:
        dst.key = b2v(src.data[:16]); dst.k2 = b2v(src.data[16:32]) if key_n == 32 else 0
        if dst.skid is not None: dst.skid = None   # a derived key is not an SKID key
    else: dst.exec('B', src.data)

OUTPUT_ = OUTPUT = 6
