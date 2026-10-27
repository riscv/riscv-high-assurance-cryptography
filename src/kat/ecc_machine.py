"""Model of the Elliptic Curve Machines of Zkl-ISA-machines.adoc (KLE-ECC, KLE-X25519-X448, KLE-EdDSA), built from the spec text.
One `EccLocker` per Configuration Controlled locker.  Operations: setst(target, form, xs), exec_in(bytes) (Form B kl.exec
of a Set State), exec_D(halt) (Form D), exec_out(n) (Form C), rstrl(policy), clearads(), clone(), shared_secret().
Fields are bytearrays in the spec's little-endian order; an invalid configuration moves the locker to Error State Invalid.
Not modelled: export/import, kl.derive destinations (only the source bytes), SCProtection, Progress units."""
import copy
from common import *
import ecc_model as M

RDY, SGEN, SSCAL, PMUL, SGN, SVER, SHASH, S2ND, SIN, OUT, MABS, SCTX = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
SETS = (SGEN, SSCAL, SHASH, S2ND, SIN, SCTX)
MODES = ['secp256r1', 'secp384r1', 'secp521r1', 'x25519', 'x448', 'ed25519', 'ed448',
         'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'sm2']
class RbgFailure(Exception): pass       # GR65: the RBG failed -> Invalid
class RbgUnavailable(Exception): pass   # KLE RBG-unavailable exception, locker unchanged

class EccLocker:
    def __init__(self, name, policy=3, aux=1, rbg=None):
        self.name = name; self.kind = 'ed' if name.startswith('ed') else 'mont' if name.startswith('x') else 'wei'
        self.rbg = rbg or (lambda n: __import__('os').urandom(n))
        if self.kind == 'wei':
            self.C = M.Wei(name); self.W = {'secp521r1': 72}.get(name, (self.C.p.bit_length() + 7) // 8); self.u = 2
            self.n = self.C.n; self.h = self.j = self.W * 8; self.v = 2
        elif self.kind == 'ed':
            self.E = M.Ed(name); self.W = self.E.nb; self.u = 1; self.h = 512; self.j = 0; self.v = 2; self.n = self.E.L
        else:
            self.W = M.MONT[name][3]; self.u = 1; self.v = 0; self.h = self.j = 0
        self.b = self.W * 8; self.ub = self.u * self.b; self.vb = self.v * self.b
        assert (policy == 0) or self.kind != 'mont'
        assert policy != 0 or self.kind != 'ed'
        self.policy = policy; self.aux = aux & 1; self.state = RDY; self.err = None
        self.flags = 0; self.outtype = 0; self.progress = 0; self.block_base = 0
        self.Scalar = bytearray(self.W); self.SecondPt = bytearray(self.u * self.W); self.Hash = bytearray(self.h // 8)
        self.Signature = bytearray(self.v * self.W); self.RndNum = bytearray(self.j // 8)
        self.Generator = bytearray(self._default_gen())
        self.ctx = bytearray(255); self.ctxlen = 0; self.msg_pass = 0; self.r = 0; self.kp = 0
        self.msg = b''; self.pass_id = None; self.complete = True; self.out_total = 0
    # ------------------------------------------------------------ helpers
    HAS = {'second': 1, 'sig': 2, 'hash': 4, 'rnd': 8}
    def has(self, f): return bool(self.flags & self.HAS[f])
    def setf(self, f, v=True):
        self.flags = (self.flags | self.HAS[f]) if v else (self.flags & ~self.HAS[f])
    def _default_gen(self):
        if self.kind == 'wei': return self.C.G[0].to_bytes(self.W, 'little') + self.C.G[1].to_bytes(self.W, 'little')
        if self.kind == 'ed': return self.E.enc(self.E.B)
        return bytes([M.MONT[self.name][4]]) + bytes(self.W - 1)
    @property
    def mdh(self):
        mu = self.outtype | (self.progress << 2)
        aux = self.aux | (self.msg_pass << 1)
        if self.err is not None:
            return mdh_pack(Machine=10, MachinePolicy=self.policy, State=0, StateExtension=self.err, MachineUse=mu, AuxInfo=aux)
        return mdh_pack(Machine=10, MachinePolicy=self.policy, State=self.state, StateExtension=self.flags, MachineUse=mu, AuxInfo=aux)
    @property
    def invalid(self): return self.err == SE_INVALID
    def _inv(self):
        self.err = SE_INVALID; self.state = 0; return 'invalid'
    def _live(self):
        if self.err is not None: raise AssertionError('locker is in an Error State')
    def iv(self, f): return int.from_bytes(f, 'little')
    def _repr_ok(self, f, comps):
        """secp521r1: the 55 msbs of each W-byte component must be zero (the spec's `b` = 576)."""
        if self.name != 'secp521r1': return True
        return all(int.from_bytes(f[i * self.W:(i + 1) * self.W], 'little') >> 521 == 0 for i in range(comps))
    def _fields_ok(self, which):
        spec = {'Scalar': (self.Scalar, 1), 'Hash': (self.Hash, 1), 'RndNum': (self.RndNum, 1), 'Generator': (self.Generator, 2),
                'SecondPt': (self.SecondPt, 2), 'Signature': (self.Signature, 2)}
        return all(self._repr_ok(*spec[w]) for w in which)
    # ------------------------------------------------------------ points
    def _wpt(self, f):
        x = int.from_bytes(f[:self.W], 'little'); y = int.from_bytes(f[self.W:], 'little'); return (x, y)
    def _valid_wei(self, f):
        P = self._wpt(f); return P if self.C.on_curve(P) else None   # on_curve checks the coordinates < p
    def _valid_ed(self, f):
        P = self.E.dec(bytes(f))
        if P is None or P == (0, 1) or self.E.mul(self.E.L, P) != (0, 1): return None
        return P
    def _enc_wei(self, P): return P[0].to_bytes(self.W, 'little') + P[1].to_bytes(self.W, 'little')
    # ------------------------------------------------------------ entry conditions
    def _scalar_ok(self, sign=False):
        s = self.iv(self.Scalar)
        if self.kind == 'mont' or self.kind == 'ed': return s != 0
        top = self.n - 2 if (self.name == 'sm2' and sign) else self.n - 1
        return 1 <= s <= top
    def _gate_ok(self, t):
        pol = self.policy
        if t == PMUL: return self._scalar_ok()
        if self.kind == 'mont': return False
        if t == SGN:
            if not pol & 1 or not self._scalar_ok(True): return False
            return (self.msg_pass == 2 or (self.msg_pass == 0 and self.has('hash'))) if self.kind == 'ed' else self.has('hash')
        if t == SVER:
            if not pol & 2 or not (self.has('second') and self.has('sig')): return False
            return (self.msg_pass == 3 or (self.msg_pass == 0 and self.has('hash'))) if self.kind == 'ed' else self.has('hash')
        return True
    def _states(self):
        if self.kind == 'mont': return {RDY, SGEN, SSCAL, PMUL, S2ND, OUT}
        s = {RDY, SGEN, SSCAL, PMUL, SGN, SVER, SHASH, S2ND, SIN, OUT}
        if self.kind == 'ed': s |= {MABS, SCTX}
        return s
    # ------------------------------------------------------------ kl.setst
    def _abandon_load(self):
        """Leaving or restarting a Set State before its field is complete zeroes the field (MR14)."""
        s = self.state
        if s in SETS and not self.complete:
            f = {SGEN: self.Generator, SSCAL: self.Scalar, SHASH: self.Hash, S2ND: self.SecondPt, SIN: self.Signature, SCTX: self.ctx}[s]
            for i in range(len(f)): f[i] = 0
            if s == SCTX: self.ctxlen = 0
        self.complete = True
    def _discard_progress(self):
        if self.progress:
            self.progress = 0
        if self.kind != 'ed': self.RndNum[:] = bytes(len(self.RndNum)); self.setf('rnd', False)
    def setst(self, target, form='A', xs=0):
        self._live()
        if form not in ('A', 'B'):                        # Forms C and D never name a State (GR20)
            return self._inv()
        if target in (54, 55, OUT) or target not in self._states() | {0}: return self._inv()
        if target == 0: raise NotImplementedError('kl.clear is out of scope')
        st = self.state
        # Forms (GR20): Ready, Set_Generator, Set_Scalar take A or B; Set_Ctx, Msg_Absorb take B; the rest A
        need = {RDY: 'AB', SGEN: 'AB', SSCAL: 'AB', SCTX: 'B', MABS: 'B'}.get(target, 'A')
        if form not in need: return self._inv()
        if form == 'B' and xs == 0 and target not in (RDY, SGEN, SSCAL, MABS): return self._inv()
        if form == 'A' and xs: raise AssertionError('Form A has no operand')
        # admitted source/target pairs
        if target != RDY:
            ok_src = st == RDY or st in SETS or (st == MABS)
            if st == target and st not in SETS and st != MABS: ok_src = False       # GR21
            if st == MABS and target not in (MABS, SGN, SVER): ok_src = False
            if not ok_src: return self._inv()
        # MR14 / GR56: leaving a Set State drops an incomplete load; any setst drops Progress and RndNum
        if st == MABS and target in (MABS, SGN, SVER):
            if self._finalize_pass() == 'invalid': return 'invalid'
        elif st == MABS: self.msg = b''
        self._abandon_load(); self._discard_progress()
        self.block_base = 0
        if st == MABS: self.setf('rnd', False)       # HasHashState cleared on leaving, set again on re-entry
        if target in (PMUL, SGN, SVER) and not self._gate_ok(target): return self._inv()
        if target == SHASH and self.policy == 0: return self._inv()
        if target == SIN and not self.policy & 2: return self._inv()
        if target == RDY: return self._to_ready(form, xs)
        self.state = target
        if target == SGEN:
            if form == 'A' or xs == 0: self.Generator[:] = self._default_gen(); self.block_base = self.ub // 8
            else: self.Generator[:] = bytes(len(self.Generator)); self.complete = False
        elif target == SSCAL:
            self.Scalar[:] = bytes(self.W)
            if form == 'B' and xs: return self._random_key()
            self.complete = False
        elif target == SHASH: self.Hash[:] = bytes(len(self.Hash)); self.setf('hash', False); self.complete = False
        elif target == S2ND: self.SecondPt[:] = bytes(len(self.SecondPt)); self.setf('second', False); self.complete = False
        elif target == SIN: self.Signature[:] = bytes(len(self.Signature)); self.setf('sig', False); self.complete = False
        elif target == SCTX:
            if xs > 255: return self._inv()
            self.ctx[:] = bytes(255); self.ctxlen = xs; self.complete = xs == 0
        elif target == MABS: return self._enter_pass(xs)
        elif target in (PMUL, SGN, SVER): self.complete = True
        return 'ok'
    def _random_key(self):
        try: c = int.from_bytes(self.rbg(self.W + 8), 'big')
        except RbgFailure: return self._inv()
        if self.kind == 'wei':
            top = self.n - 2 if self.name == 'sm2' else self.n - 1   # FIPS 186-5 A.2.2: d = c mod (n-1) + 1 (SM2: mod n-2)
            d = c % top + 1; self.Scalar[:] = d.to_bytes(self.W, 'little')
        else:
            self.Scalar[:] = (c & mask(self.b)).to_bytes(self.W, 'little')
            if self.iv(self.Scalar) == 0: self.Scalar[0] = 1
        self.block_base = self.W; self.complete = True; return 'ok'
    def _to_ready(self, form, xs):
        if form == 'B' and xs >> 7: return self._inv()
        if form == 'B':
            gen, sec, hs = bytes(self.Generator), bytes(self.SecondPt), self.has('second')
            if xs >> 4 & 1: self.SecondPt[:] = gen; self.setf('second')
            if xs >> 5 & 1 and hs: self.Generator[:] = sec
            if xs & 1: self.Generator[:] = self._default_gen()
            if xs >> 1 & 1: self.SecondPt[:] = bytes(len(self.SecondPt)); self.setf('second', False)
            if xs >> 2 & 1 and True: self.Scalar[:] = bytes(self.W)
            if self.policy:
                if xs >> 3 & 1: self.Hash[:] = bytes(len(self.Hash)); self.setf('hash', False)
                if xs >> 6 & 1: self.Signature[:] = bytes(len(self.Signature)); self.setf('sig', False)
            if self.kind == 'mont': pass
        self.state = RDY
        if self.kind == 'ed':
            self.msg_pass = 0; self.r = 0; self.kp = 0; self.ctx[:] = bytes(255); self.ctxlen = 0; self.msg = b''
        return 'ok'
    # ------------------------------------------------------------ kl.exec Form B (load)
    def exec_in(self, data):
        self._live()
        s = self.state
        if s == MABS:
            self.msg += bytes(data); return 'ok'
        if s not in SETS or self.complete: return self._inv()          # MR14: no load in progress
        f = {SGEN: self.Generator, SSCAL: self.Scalar, SHASH: self.Hash, S2ND: self.SecondPt, SIN: self.Signature, SCTX: self.ctx}[s]
        size = self.ctxlen if s == SCTX else len(f)
        n = min(len(data), size - self.block_base)                      # the excess of the last kl.exec is ignored
        f[self.block_base:self.block_base + n] = bytes(data[:n]); self.block_base += n
        if s != SCTX and not self._fields_ok({SGEN: ['Generator'], SSCAL: ['Scalar'], SHASH: ['Hash'], S2ND: ['SecondPt'], SIN: ['Signature']}[s]):
            return self._inv()
        if self.block_base == size:
            self.complete = True
            if s == SHASH: self.setf('hash')
            if s == S2ND: self.setf('second')
            if s == SIN: self.setf('sig')
        return 'ok'
    # ------------------------------------------------------------ kl.exec Form D
    def exec_D(self, halt=False):
        self._live()
        s = self.state
        if s not in (PMUL, SGN, SVER): return self._inv()
        if self.kind == 'wei': return getattr(self, '_w' + {PMUL: 'mul', SGN: 'sign', SVER: 'ver'}[s])(halt)
        if self.kind == 'ed': return getattr(self, '_e' + {PMUL: 'mul', SGN: 'sign', SVER: 'ver'}[s])(halt)
        return self._xmul(halt)
    def _fail(self): self.state = 55; return 'failure'
    def _out(self, ot):
        self.outtype = ot; self.state = OUT; self.block_base = 0; self.progress = 0; return 'output'
    def _halted(self, halt):
        if halt: self.progress = 1; return True
        return False
    def _wmul(self, halt):
        use = ['Scalar', 'SecondPt' if self.has('second') else 'Generator']
        if not self._fields_ok(use): return self._inv()
        f = self.SecondPt if self.has('second') else self.Generator
        P = self._valid_wei(f)
        if P is None: return self._fail()
        if self._halted(halt): return 'halted'
        R = self.C.mul(self.iv(self.Scalar), P)
        self.SecondPt[:] = self._enc_wei(R); ss = self.has('second'); self.setf('second')
        return self._out(2 if ss else 0)
    def _draw_k(self):
        try: c = int.from_bytes(self.rbg(self.W + 8), 'big')
        except RbgFailure: return None
        return c % (self.n - 1) + 1        # FIPS 186-5 A.3.2 (also SM2): k = c mod (n-1) + 1
    def _wsign(self, halt):
        if not self._fields_ok(['Scalar', 'Hash', 'Generator'] + (['RndNum'] if self.progress else [])): return self._inv()
        if self._valid_wei(self.Generator) is None: return self._fail()
        if self.progress == 0:
            k = self._draw_k()
            if k is None: return self._inv()
            self.RndNum[:] = k.to_bytes(self.j // 8, 'little'); self.setf('rnd')
        if self._halted(halt): return 'halted'
        c = self._cv(); d = self.iv(self.Scalar); e = self.iv(self.Hash)
        sign = M.sm2_sign if self.name == 'sm2' else M.ecdsa_sign
        while True:
            rs = sign(c, d, e, self.iv(self.RndNum))
            if rs is not None: break
            k = self._draw_k()
            if k is None: return self._inv()
            self.RndNum[:] = k.to_bytes(self.j // 8, 'little')
        self.Signature[:] = rs[0].to_bytes(self.W, 'little') + rs[1].to_bytes(self.W, 'little'); self.setf('sig')
        self.RndNum[:] = bytes(len(self.RndNum)); self.setf('rnd', False)
        return self._out(1)
    def _wver(self, halt):
        if not self._fields_ok(['Hash', 'Generator', 'SecondPt', 'Signature']): return self._inv()
        Q = self._valid_wei(self.SecondPt)
        if Q is None or self._valid_wei(self.Generator) is None: return self._fail()
        if self._halted(halt): return 'halted'
        rs = (int.from_bytes(self.Signature[:self.W], 'little'), int.from_bytes(self.Signature[self.W:], 'little'))
        ver = M.sm2_verify if self.name == 'sm2' else M.ecdsa_verify
        self.progress = 0
        ok = ver(self._cv(), Q, self.iv(self.Hash), rs)
        if ok: self.state = 54; return 'success'
        return self._fail()
    def _cv(self):
        C = copy.copy(self.C); C.G = self._wpt(self.Generator); return C   # the base point is whatever Generator holds
    # custom Generator also used by signing
    # ------------------------------------------------------------ Montgomery
    def _xmul(self, halt):
        f = self.SecondPt if self.has('second') else self.Generator
        if self._halted(halt): return 'halted'
        R = M.x_mul(self.name, bytes(self.Scalar), bytes(f))
        if not any(R): return self._fail()
        ss = self.has('second'); self.SecondPt[:] = R; self.setf('second')
        return self._out(2 if ss else 0)
    # ------------------------------------------------------------ EdDSA
    def _prefix_s(self): return self.E.expand(bytes(self.Scalar))
    def _dom(self, x): return self.E.dom(x, bytes(self.ctx[:self.ctxlen]))
    def _emul(self, halt):
        f = self.SecondPt if self.has('second') else self.Generator
        P = self._valid_ed(f)
        if P is None: return self._fail()
        if self._halted(halt): return 'halted'
        s, _ = self._prefix_s(); R = self.E.mul(s, P)
        ss = self.has('second'); self.SecondPt[:] = self.E.enc(R); self.setf('second')
        return self._out(2 if ss else 0)
    def _esign(self, halt):
        E = self.E; s, prefix = self._prefix_s(); A = E.enc(E.mul(s, E.B))
        if self._halted(halt): return 'halted'
        if self.msg_pass == 2:
            R = bytes(self.Signature[:self.W]); S = (self.r + self.kp * s) % E.L
        else:
            Hm = bytes(self.Hash); dom = self._dom(1)
            r = int.from_bytes(E.H(dom + prefix + Hm), 'little') % E.L; R = E.enc(E.mul(r, E.B))
            k = int.from_bytes(E.H(dom + R + A + Hm), 'little') % E.L; S = (r + k * s) % E.L
        self.Signature[:] = R + S.to_bytes(self.W, 'little'); self.setf('sig')
        self.r = 0; self.kp = 0; self.msg_pass = 0; self.msg = b''
        return self._out(1)
    def _ever(self, halt):
        E = self.E; A = bytes(self.SecondPt); sig = bytes(self.Signature)
        if self._halted(halt): return 'halted'
        if self.msg_pass == 3: ok = self._ever_core(A, sig, self.kp)
        else:
            Hm = bytes(self.Hash); k = int.from_bytes(E.H(self._dom(1) + sig[:self.W] + A + Hm), 'little') % E.L
            ok = self._ever_core(A, sig, k)
        self.kp = 0; self.progress = 0
        if ok: self.state = 54; return 'success'
        return self._fail()
    def _ever_core(self, A, sig, k):
        E = self.E; Ap = E.dec(A); Rp = E.dec(sig[:self.W]); S = int.from_bytes(sig[self.W:], 'little')
        if Ap is None or Rp is None or S >= E.L: return False
        c = 1 << E.c
        return E.mul(c * S, E.B) == E.add(E.mul(c, Rp), E.mul(c * k, Ap))
    _emul_ = _emul
    def _enter_pass(self, xs):
        E = self.E
        if not self.aux & 1: return self._inv()
        s, prefix = self._prefix_s(); A = E.enc(E.mul(s, E.B)) if self.iv(self.Scalar) else None
        if xs == 0:
            if not (self.policy & 1 and self.iv(self.Scalar)): return self._inv()
            self.msg_pass = 0; self.kp = 0
        elif xs == 1:
            if self.msg_pass != 1: return self._inv()
        elif xs == 2:
            if not (self.policy & 2 and self.has('sig') and self.has('second')): return self._inv()
            self.msg_pass = 3; self.kp = 0
        else: return self._inv()
        self.state = MABS; self.pass_id = xs; self.msg = b''; self.setf('rnd'); return 'ok'   # bit 3 = HasHashState
    def _finalize_pass(self):
        E = self.E; pid = self.pass_id; self.setf('rnd', False)
        s, prefix = self._prefix_s(); dom = self._dom(0); Mg = self.msg; self.msg = b''
        if pid == 0:
            self.r = int.from_bytes(E.H(dom + prefix + Mg), 'little') % E.L
            self.Signature[:] = E.enc(E.mul(self.r, E.B)) + bytes(self.W); self.setf('sig', False); self.msg_pass = 1
        elif pid == 1:
            if int.from_bytes(E.H(dom + prefix + Mg), 'little') % E.L != self.r: return self._inv()
            A = E.enc(E.mul(s, E.B))
            self.kp = int.from_bytes(E.H(dom + bytes(self.Signature[:self.W]) + A + Mg), 'little') % E.L; self.msg_pass = 2
        else:
            self.kp = int.from_bytes(E.H(dom + bytes(self.Signature[:self.W]) + bytes(self.SecondPt) + Mg), 'little') % E.L
        return 'ok'
    # ------------------------------------------------------------ Output
    def shared_secret(self):
        if self.kind == 'wei':
            m = (self.C.p.bit_length() + 7) // 8
            if self.name == 'sm2':
                x, y = self._wpt(self.SecondPt); return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
            return self._wpt(self.SecondPt)[0].to_bytes(m, 'big')
        return bytes(self.SecondPt)
    def _outbytes(self):
        return {0: bytes(self.SecondPt), 1: bytes(self.Signature), 2: self.shared_secret()}[self.outtype]
    def exec_out(self, n):
        self._live()
        if self.state != OUT: return self._inv()
        o = self._outbytes()
        if self.outtype == 3 or self.block_base + n > len(o): return self._inv()
        chunk = o[self.block_base:self.block_base + n]; self.block_base += n
        if self.block_base == len(o): self.state = 54
        return chunk
    def derive_source(self):
        """kl.derive source: Output with OutputType shared secret, unrestricted (GR42); anything else is not a source."""
        if self.state == OUT and self.outtype == 2: return self.shared_secret()
        return None
    # ------------------------------------------------------------ restrict / clearads / clone
    def rstrl(self, pol):
        self._live()
        if pol & ~self.policy or (self.kind == 'ed' and pol == 0): return self._inv()   # GR25: narrowing only
        self.policy = pol
        if pol == 0:
            self.Signature[:] = bytes(len(self.Signature)); self.Hash[:] = bytes(len(self.Hash)); self.setf('sig', False); self.setf('hash', False)
        if not pol & 1 and self.kind != 'mont':
            self.RndNum[:] = bytes(len(self.RndNum))
            if self.kind != 'ed' or self.state != MABS: self.setf('rnd', False)
            self.progress = 0
        return 'ok'
    def clearads(self): self._live(); self._discard_progress(); return 'ok'
    def clone(self):
        c = copy.deepcopy(self); c.progress = 0; c.RndNum[:] = bytes(len(c.RndNum)); c.setf('rnd', False) if c.kind != 'ed' else None
        return c
