"""Model of an ML-DSA Machine locker, transcribed from Zkl-ISA-machines.adoc (KLE-PQC-ML-DSA, MR1-MR19)
and Zkl-ISA-unpriv.adoc (GR20-GR25, GR34-GR35, GR55-GR57, GR65).

Locker(ps, policy=3, aux=0, rbg=None, lim=None)
  State numbers: S_READY ... ; fields: st (0 = Inert), se (StateExtension: flags bits0-3, or the Error code when st == 0),
  mu_use (MachineUse = W or P), privkey, pubkey, signature, mu, rnd (bytes, zero-filled when empty), ads.
  setst(imm, form='A', xs=0); exec(form, data=None, n=None, halt=None) ; restrict(policy)
  export(content2=True) -> snapshot ; Locker.import_(snap, ps, content2=True, rbg=None, lim=None)
  mdh() -> 128-bit MDH value.   rbg(n) -> n bytes, or raises to model an RBG failure.
"""
import hashlib
from common import mdh_pack, ST_READY, ST_SUCCESS, ST_FAILURE
import mldsa_model as M

S_READY, S_GEN, S_PKOUT, S_PKIN, S_MUIN, S_SGEN, S_SOUT, S_SVER, S_SIN, S_PRIVIN, S_CPK = 1, 2, 3, 4, 6, 8, 9, 10, 11, 12, 13
S_SUCCESS, S_FAILURE = ST_SUCCESS, ST_FAILURE
DEFINED = {S_READY, S_GEN, S_PKOUT, S_PKIN, S_MUIN, S_SGEN, S_SOUT, S_SVER, S_SIN, S_PRIVIN, S_CPK}
HAS_PRIV, HAS_PUB, HEDGED, HAS_MU = 1, 2, 4, 8
SE_INVALID = 2
LOADING = {S_PRIVIN: 'privkey', S_PKIN: 'pubkey', S_MUIN: 'mu', S_SIN: 'signature'}
EMITTING = {S_PKOUT: 'pubkey', S_SOUT: 'signature'}
MACHINE_MODE = {'ML-DSA-44': 3, 'ML-DSA-65': 4, 'ML-DSA-87': 5}


class Rbg:
    """Deterministic test RBG: hands out the queued byte strings; 'fail' queued entries raise."""
    def __init__(self, *queue): self.q = list(queue); self.draws = 0

    def __call__(self, n):
        if not self.q: raise RuntimeError('RBG exhausted')
        v = self.q.pop(0)
        if v == 'fail': raise RuntimeError('RBG failure')
        assert len(v) == n
        self.draws += 1
        return v


_SIGCACHE = {}


def _sign(ps, sk, mu, rnd, lim):
    key = (ps['name'], sk, mu, rnd, tuple(sorted(lim.items())))
    if key not in _SIGCACHE:
        g = M.sign_gen(ps, sk, mu, rnd, lim)
        n = 0
        try:
            while True:
                next(g); n += 1
        except StopIteration as e:
            _SIGCACHE[key] = (n + 1, e.value)
        except M.LoopBound:
            _SIGCACHE[key] = None
    r = _SIGCACHE[key]
    if r is None: raise M.LoopBound
    return r


class Locker:
    def __init__(self, ps, policy=3, aux=0, rbg=None, lim=None):
        self.ps, self.policy, self.aux, self.rbg, self.lim = ps, policy, aux, rbg, lim or {}
        self.size = {'privkey': ps['sk'], 'pubkey': ps['pk'], 'signature': ps['sig'], 'mu': 64}
        self.st, self.se, self.mu_use, self.ads = S_READY, 0, 0, None
        self._zero_all()

    # ------------------------------------------------------------ helpers
    def _zero(self, f): setattr(self, f, bytes(self.size[f]))
    def _zero_all(self):
        for f in self.size: self._zero(f)
        self.rnd = bytes(32)

    @property
    def inert(self): return self.st == 0
    @property
    def error(self): return self.st == 0 and self.se != 0
    def flag(self, b): return bool(self.se & b)
    def _setflag(self, b, v): self.se = (self.se | b) if v else (self.se & ~b)

    def invalid(self):
        self._zero_all()
        self.st, self.se, self.mu_use, self.ads = 0, SE_INVALID, 0, None

    def mdh(self):
        return mdh_pack(Machine=(11 << 4) | MACHINE_MODE[self.ps['name']], MachinePolicy=self.policy, State=self.st,
                        StateExtension=self.se, MachineUse=self.mu_use, AuxInfo=self.aux)

    def _draw(self, n):
        try:
            return self.rbg(n)
        except RuntimeError:
            return None

    def _to(self, st):   # transition made by the Machine itself
        self.st, self.mu_use = st, 0

    def _enter_ready(self):
        if self.st in (S_SUCCESS, S_FAILURE):   # shortcut: spec text on what Ready clears is unverified
            self.signature = bytes(self.size['signature']); self.mu = bytes(64); self._setflag(HAS_MU, False)
        self.rnd = bytes(32)
        self.st, self.mu_use, self.ads = S_READY, 0, None

    # ------------------------------------------------------------ kl.setst
    def setst(self, imm, form='A', xs=0):
        if self.inert: return
        if imm == 0:
            self._zero_all(); self.st = self.se = self.mu_use = 0; self.ads = None; return
        if imm not in DEFINED or imm in (S_SUCCESS, S_FAILURE):      # undefined, 54, 55 (GR23, GR24)
            return self.invalid()
        if self.st in (S_SUCCESS, S_FAILURE) and imm != S_READY:    # GR22
            return self.invalid()
        if (imm == S_SGEN and form not in ('A', 'B')) or (imm != S_SGEN and form != 'A'):
            return self.invalid()                                    # wrong Form (GR13, GR20)
        if (imm in (S_SGEN, S_SOUT) and not self.policy & 1) or (imm in (S_SVER, S_SIN) and not self.policy & 2):
            return self.invalid()                                    # MR1
        if imm == S_SOUT: return self.invalid()                      # entered only on completion
        if imm == self.st and imm != S_READY and imm not in LOADING:
            return self.invalid()                                    # GR21
        # leaving the current State
        if self.st in LOADING and self.mu_use < self.size[LOADING[self.st]]:
            self._zero(LOADING[self.st])                             # MR14.5
            if self.st == S_MUIN: self._setflag(HAS_MU, False)
        if self.st == S_SGEN and self.mu_use:                        # GR56.3
            self.mu_use, self.rnd, self.ads = 0, bytes(32), None
        # entering imm
        if imm == S_READY: return self._enter_ready()
        if imm == S_PRIVIN:
            self._setflag(HAS_PRIV | HAS_PUB, False); self._zero('pubkey'); self._zero('privkey')
        elif imm == S_PKIN:
            if self.flag(HAS_PRIV): return self.invalid()
            self._setflag(HAS_PUB, False); self._zero('pubkey')
        elif imm == S_MUIN:
            self._setflag(HAS_MU, False); self._zero('mu')
        elif imm == S_SIN:
            self._zero('signature')
        elif imm == S_PKOUT:
            if not self.flag(HAS_PUB): return self.invalid()
        elif imm == S_CPK:
            if not self.flag(HAS_PRIV): return self.invalid()
        elif imm == S_SVER:
            if not (self.flag(HAS_PUB) and self.flag(HAS_MU)): return self.invalid()
        elif imm == S_SGEN:
            if not (self.flag(HAS_PRIV) and self.flag(HAS_MU)): return self.invalid()
            self._setflag(HEDGED, xs == 0)
        self._to(imm)

    # ------------------------------------------------------------ kl.exec
    def exec(self, form, data=None, n=None, halt=None):
        """Form 'B' with data (bytes) loads; Form 'C' with n (bytes) emits (returns the bytes); Form 'D' operates.
        halt: for Sign_Generate, the number of iterations after which the operation is interrupted (None: never)."""
        if self.inert: return None
        st = self.st
        if st in (S_READY, S_SUCCESS, S_FAILURE): return self.invalid()                         # GR21, GR22
        if (st in (S_SGEN, S_SOUT) and not self.policy & 1) or (st in (S_SVER, S_SIN) and not self.policy & 2):
            return self.invalid()                                                            # MR1
        if st in LOADING:
            if form != 'B' or self.mu_use >= self.size[LOADING[st]]: return self.invalid()
            f = LOADING[st]; size = self.size[f]
            take = min(len(data), size - self.mu_use)
            buf = bytearray(getattr(self, f)); buf[self.mu_use:self.mu_use + take] = data[:take]
            setattr(self, f, bytes(buf)); self.mu_use += take
            if self.mu_use < size: return None
            excess = len(data) > take
            if st == S_PRIVIN:
                if not M.sk_ok(self.ps, self.privkey): return self.invalid()
                self._setflag(HAS_PRIV, True)
            elif st == S_PKIN:
                if excess: self._zero('pubkey'); return self._to(S_FAILURE)
                self._setflag(HAS_PUB, True)
            elif st == S_MUIN:
                self._setflag(HAS_MU, True)
            elif st == S_SIN and excess:
                self._zero('signature'); return self._to(S_FAILURE)
            return None
        if st in EMITTING:
            f = EMITTING[st]; size = self.size[f]
            if form != 'C' or self.mu_use + n > size: return self.invalid()
            out = getattr(self, f)[self.mu_use:self.mu_use + n]; self.mu_use += n
            if self.mu_use == size: self._to(S_SUCCESS)
            return out
        if form != 'D': return self.invalid()
        ps = self.ps
        try:
            if st == S_GEN:
                xi = self._draw(32)
                if xi is None: return self.invalid()
                pk, sk = M.keygen_internal(ps, xi, self.lim)
                self.pubkey, self.privkey = pk, sk
                self._setflag(HAS_PRIV | HAS_PUB, True)
                return self._to(S_PKOUT)
            if st == S_CPK:
                pk = M.pk_from_sk(ps, self.privkey, self.lim)
                if M.H(pk, 64) != self.privkey[64:128]: return self.invalid()
                self.pubkey = pk; self._setflag(HAS_PUB, True)
                return self._enter_ready()
            if st == S_SVER:
                ok = M.verify_internal(ps, self.pubkey, self.mu, self.signature, self.lim)
                return self._to(S_SUCCESS if ok else S_FAILURE)
            if st == S_SGEN:
                return self._sign(halt)
        except M.LoopBound:
            if st == S_SGEN: self.rnd, self.ads = bytes(32), None
            return self._to(S_FAILURE)

    def _sign(self, halt):
        if self.mu_use and self.ads is None:                          # restart (GR56.1, GR57)
            self.mu_use, self.rnd = 0, bytes(32)
        if not self.mu_use:
            if self.flag(HEDGED):
                r = self._draw(32)
                if r is None: return self.invalid()
                self.rnd = r
            else:
                self.rnd = bytes(32)
            self.ads = {'done': 0}
        done = self.ads['done']
        L = {**M.DEFAULT_LIM, **self.lim}
        try:
            total, sig = _sign(self.ps, self.privkey, self.mu, self.rnd, L)
        except M.LoopBound:
            if halt is not None and done + halt <= L['sign']:      # interrupted before the bound is hit
                self.ads = {'done': done + halt}; self.mu_use = done + halt + 1
                return None
            raise
        if halt is not None and done + halt < total:
            self.ads = {'done': done + halt}; self.mu_use = done + halt + 1   # P: non-zero, increasing
            return None
        self.signature, self.rnd, self.ads = sig, bytes(32), None
        self._to(S_SOUT)

    # ------------------------------------------------------------ policy, export, import
    def restrict(self, pol): self.policy &= pol

    def export(self, content2=True):
        s = dict(st=self.st, se=self.se, mu_use=self.mu_use, policy=self.policy, aux=self.aux, rnd=self.rnd,
                 **{f: getattr(self, f) for f in self.size})
        s['ads'] = dict(self.ads) if (content2 and self.ads) else None
        return s

    @staticmethod
    def import_(s, ps, content2=True, rbg=None, lim=None):
        lk = Locker(ps, s['policy'], s['aux'], rbg, lim)
        for f in lk.size: setattr(lk, f, s[f])
        lk.st, lk.se, lk.mu_use, lk.rnd = s['st'], s['se'], s['mu_use'], s['rnd']
        lk.ads = dict(s['ads']) if (content2 and s['ads']) else None
        if lk.flag(HAS_PRIV) and not M.sk_ok(ps, lk.privkey): lk.invalid()               # MR3
        elif lk.st == S_SGEN and lk.mu_use and lk.ads is None:
            lk.mu_use, lk.rnd = 0, bytes(32)                                              # GR57
        return lk
