"""Model of the Elliptic Curve Machines of Zkl-ISA-machines.adoc (KLE-ECC, KLE-X25519-X448, KLE-EdDSA), built from the spec text.
One `EccLocker` per Configuration Controlled locker.  Operations: setst(target, form, xs), exec_in(bytes) (Form B kl.exec
of a Set State), exec_D(halt) (Form D), exec_out(n) (Form C), rstrl(policy), clearads(), clone(), shared_secret(),
export() -> (MDH, Content1), ads() -> Content2 and EccLocker.imported(name, mdh, content1, content2) (SCC export and import),
derive_to(D) (kl.derive of the shared secret into a destination of hash_model: a Locker or a Key).
Fields are bytearrays in the spec's little-endian order; an invalid configuration moves the locker to Error State Invalid.
The EdDSA hashes H and H' are running hash_model lockers (SHA-512, SHAKE256), so an open pass is serialized.
A halted operation keeps its ADS: Content2 holds the Progress value, as the model recomputes the intermediate values on
resumption.  SCProtection is carried in the MDH; its physical protection is not modelled, nor the SCC cryptography (scc-kat.py)."""
import copy
from common import *
import ecc_model as M
import hash_model as HM

RDY, SGEN, SSCAL, PMUL, SGN, SVER, SHASH, S2ND, SIN, OUT, MABS, SCTX = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
SETS = (SGEN, SSCAL, SHASH, S2ND, SIN, SCTX)
MODES = ['secp256r1', 'secp384r1', 'secp521r1', 'x25519', 'x448', 'ed25519', 'ed448',
         'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'sm2']
class RbgFailure(Exception): pass       # GR45: the RBG failed -> Invalid
class RbgUnavailable(Exception): pass   # KLE RBG-unavailable exception, locker unchanged

class EccLocker:
    def __init__(self, name, policy=3, aux=1, rbg=None, ext=0, scp=0):
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
        self.policy = policy; self.aux = aux & 1; self.ext = ext; self.scp = scp; self.state = RDY; self.err = None   # ext: MachineExtension (1 = public-points, 2 = sealed variant)
        if ext == 2 and self.kind == 'ed': self.err = SE_UNSUPPORTED; self.state = 0         # no sealed EdDSA
        self.flags = 0; self.outtype = 0; self.progress = 0; self.block_base = 0
        self.Scalar = bytearray(self.W); self.SecondPt = bytearray(self.u * self.W); self.Hash = bytearray(self.h // 8)
        self.Signature = bytearray(self.v * self.W); self.RndNum = bytearray(self.j // 8)
        self.Generator = bytearray(self._default_gen())
        self.ctx = bytearray(255); self.ctxlen = 0; self.msg_pass = 0; self.r = 0; self.kp = 0
        self.Hh = self.Hp = None; self.pass_id = None; self.complete = True; self.out_total = 0   # H, H': None while no pass is open
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
        aux = self.aux | (self.msg_pass << 1) | (self.block_base << 8)
        if self.err is not None:
            return mdh_pack(Machine=10, MachinePolicy=self.policy, MachineExtension=self.ext, SCProtection=self.scp, State=0, StateExtension=self.err, MachineUse=mu, AuxInfo=aux)
        return mdh_pack(Machine=10, MachinePolicy=self.policy, MachineExtension=self.ext, SCProtection=self.scp, State=self.state, StateExtension=self.flags,
                        MachineUse=mu, AuxInfo=aux, AuxDataLen=2 + len(self.ads()) // 16 if self.progress else 0)   # GR37: an ADS while Progress != 0
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
        if form not in ('A', 'B'):                        # Forms C and D never name a State (GR13.5)
            return self._inv()
        if target in (54, 55, OUT) or target not in self._states() | {0}: return self._inv()
        if target == 0: raise NotImplementedError('kl.clear is out of scope')
        st = self.state
        # Forms (GR13.5): Ready, Set_Generator, Set_Scalar take A or B; Set_Ctx, Msg_Absorb take B; the rest A
        need = {RDY: 'AB', SGEN: 'AB', SSCAL: 'AB', SCTX: 'B', MABS: 'B'}.get(target, 'A')
        if form not in need: return self._inv()
        if form == 'B' and xs == 0 and target not in (RDY, SGEN, SSCAL, MABS): return self._inv()
        if form == 'A' and xs: raise AssertionError('Form A has no operand')
        # admitted source/target pairs
        if target != RDY:
            ok_src = st == RDY or st in SETS or (st == MABS)
            if st == target and st not in SETS and st != MABS: ok_src = False       # GR19.2
            if st == MABS and target not in (MABS, SGN, SVER): ok_src = False
            if not ok_src: return self._inv()
        # a narrowed signing pass ends only toward Ready (KLE-EdDSA Allowed State Transitions)
        if st == MABS and self.pass_id in (0, 1) and self._pass_disabled() and target != RDY: return self._inv()
        # MR14 / GR38: leaving a Set State drops an incomplete load; any setst drops Progress and RndNum
        if st == MABS and target in (MABS, SGN, SVER):
            if self._finalize_pass() == 'invalid': return 'invalid'
        elif st == MABS: self.Hh = self.Hp = None
        self._abandon_load(); self._discard_progress()
        self.block_base = 0
        if st == MABS: self.setf('rnd', False)       # HasHashState cleared on leaving, set again on re-entry
        if target in (PMUL, SGN, SVER) and not self._gate_ok(target): return self._inv()
        if target == SHASH and self.policy == 0: return self._inv()
        if target == SIN and not self.policy & 2: return self._inv()
        if target == RDY: return self._to_ready(form, xs)
        self.state = target
        if target == SGEN:
            if self.ext and form == 'B' and xs != 0: return self._inv()
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
            if xs >> 5 & 1 and hs and self.ext: return self._inv()
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
            self.msg_pass = 0; self.r = 0; self.kp = 0; self.ctx[:] = bytes(255); self.ctxlen = 0; self.Hh = self.Hp = None
        return 'ok'
    # ------------------------------------------------------------ kl.exec Form B (load)
    def exec_in(self, data):
        self._live()
        s = self.state
        if s == MABS:                                   # H and H' absorb each kl.exec in lock step
            if self._pass_disabled(): return self._inv()  # MR1: the operation of the open pass is disabled
            for h in (self.Hh, self.Hp):
                if h: h.exec('B', bytes(data))
            return 'ok'
        if s not in SETS: return self._inv()
        if not data: return 'ok'                                        # GR18: empty window, State kept
        if self.complete: return self._inv()                           # MR14 item 3: load complete
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
        if self.ext == 1 and self.has('second'): return self._inv()
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
            self.progress = 0                  # a retry restarts: Progress is zero before the draw (MR19)
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
        if self.ext == 1 and self.has('second'): return self._inv()
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
        if self.ext == 1 and self.has('second'): return self._inv()
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
        dom = self._dom(0); R = bytes(self.Signature[:self.W]); self.Hp = None
        if xs == 0:
            if not (self.policy & 1 and self.iv(self.Scalar)): return self._inv()
            self.msg_pass = 0; self.kp = 0; self.Hh = self._newH(dom + prefix)
        elif xs == 1:
            if self.msg_pass != 1: return self._inv()
            self.Hh = self._newH(dom + R + A); self.Hp = self._newH(dom + prefix)
        elif xs == 2:
            if not (self.policy & 2 and self.has('sig') and self.has('second')): return self._inv()
            self.msg_pass = 3; self.kp = 0; self.Hh = self._newH(dom + R + bytes(self.SecondPt))
        else: return self._inv()
        self.state = MABS; self.pass_id = xs; self.setf('rnd'); return 'ok'   # bit 3 = HasHashState
    def _pass_disabled(self): return not self.policy & (2 if self.pass_id == 2 else 1)
    def _hname(self): return 'SHA-512' if self.name == 'ed25519' else 'SHAKE256'
    def _newH(self, x):
        """An instance of H set as entering Ready of its hash Machine, then absorbing the initial string x."""
        h = HM.Locker(self._hname()); h.setst('absorb'); h.exec('B', x); return h
    def _hmodL(self, h): return int.from_bytes(HM.digest(copy.deepcopy(h), 2 * self.W), 'little') % self.E.L
    def _finalize_pass(self):
        E = self.E; pid = self.pass_id; self.setf('rnd', False)
        h, hp = self.Hh, self.Hp; self.Hh = self.Hp = None
        if pid == 0:
            self.r = self._hmodL(h)
            self.Signature[:] = E.enc(E.mul(self.r, E.B)) + bytes(self.W); self.setf('sig', False); self.msg_pass = 1
        elif pid == 1:
            if self._hmodL(hp) != self.r: return self._inv()   # hp exists: without MachinePolicy[0] setst admits only Ready
            self.kp = self._hmodL(h); self.msg_pass = 2
        else:
            self.kp = self._hmodL(h)
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
        if self.state != OUT or self.ext == 2 and self.outtype == 2: return self._inv()   # sealed: no Form C of a shared secret
        o = self._outbytes()
        if self.outtype == 3 or self.block_base + n > len(o): return self._inv()
        chunk = o[self.block_base:self.block_base + n]; self.block_base += n
        if self.block_base == len(o): self.state = 54
        return chunk
    sealed = property(lambda self: self.ext == 2)
    def derive_source(self):
        """kl.derive source: Output with OutputType shared secret before any Form C (block_base = 0), unrestricted (GR31.1),
        or sealed (GR31.3) if self.sealed; anything else is not a source. A peek: derive() consumes it."""
        if self.state == OUT and self.outtype == 2 and self.block_base == 0: return self.shared_secret()
        return None
    def derive(self):
        """A committed kl.derive of the shared secret (GR28): Output -> Success; outside the source State, Invalid (GR29 item 2)."""
        self._live()
        z = self.derive_source()
        if z is None: return self._inv()
        self.state = 54; return z
    def derive_to(self, D, length=None):
        """kl.derive D <- shared secret, D a hash_model Locker (Set_Key, Hash_Absorb) or Key: unrestricted (GR31.1), or restricted
        with the MDH of this locker if sealed (GR31.3, GR30).  False if refused; D.srcinv: this locker transitions to Invalid too."""
        self._live(); D.srcinv = False; z = self.derive_source()
        if z is None: self._inv(); return False                                        # GR29 item 2: not a source endpoint
        ok = D.derive(z, length=len(z) if length is None else length, stream=False, src='secret', sealed=self.sealed,
                      smdh=self.mdh if self.sealed else None)
        if D.srcinv: self._inv()
        elif ok: self.state = 54                                                       # GR28: Output -> Success
        return ok
    # ------------------------------------------------------------ restrict / clearads / clone
    def rstrl(self, pol):
        self._live()
        if pol & ~self.policy or (self.kind == 'ed' and pol == 0): return self._inv()   # GR20: narrowing only
        self.policy = pol
        if pol == 0:
            self.Signature[:] = bytes(len(self.Signature)); self.Hash[:] = bytes(len(self.Hash)); self.setf('sig', False); self.setf('hash', False)
        if not pol & 1 and self.kind != 'mont':
            self.RndNum[:] = bytes(len(self.RndNum))
            if self.kind != 'ed' or self.state != MABS: self.setf('rnd', False)
            self.Hp = None                               # destroys the state of H', HasHashState unchanged
            self.progress = 0
        return 'ok'
    def clearads(self): self._live(); self._discard_progress(); return 'ok'
    def clone(self):
        c = copy.deepcopy(self); c.progress = 0; c.RndNum[:] = bytes(len(c.RndNum)); c.setf('rnd', False) if c.kind != 'ed' else None
        return c
    # ------------------------------------------------------------ SCC export / import (Serialized Content of KLE-ECC, KLE-EdDSA)
    HS = 1664 // 8                                       # hs, in bytes
    _HATTR = {'state': 'S', 'block_base': 'bb', 'cumul_len': 'cum', 'block': 'blk'}
    def _hkeep(self): return ('state', 'block_base', 'cumul_len', 'block') if self.name == 'ed25519' else ('state', 'block_base')
    def _hs(self, h):
        """Position xi or xii: those fields of the hash Machine's Serialized Content, zero-padded to hs; zero without an instance."""
        b = b''.join(v2b(v, w // 8) for n, v, w in h.fields() if n in self._hkeep()) if h else b''
        return b + bytes(self.HS - len(b))
    def _hs_load(self, bs):
        h = HM.Locker(self._hname()); h.setst('absorb'); o = 0
        for n, _, w in h.fields():
            if n in self._hkeep(): setattr(h, self._HATTR[n], b2v(bs[o:o + w // 8])); o += w // 8
        return h
    def _layout(self):
        """Content1 as [(field, bytes)] in Position order; paddings are named None."""
        P, X, z = self.policy != 0, self.policy & 1, lambda bits: bytes((-bits) % 128 // 8)
        L = [('Signature', bytes(self.Signature)), (None, z(self.vb))] if P else []
        if self.ext == 0: L += [('Generator', bytes(self.Generator))]
        L += [('SecondPt', bytes(self.SecondPt)), (None, z((1 + (self.ext == 0)) * self.ub)), ('Scalar', bytes(self.Scalar))]
        if P: L += [('Hash', bytes(self.Hash))]
        if X: L += [('RndNum', bytes(self.RndNum))]
        L += [(None, z(self.b + P * self.h + X * self.j))]
        if self.kind == 'ed':
            L += [('ctxlen', bytes([self.ctxlen])), ('ctx', bytes(self.ctx)), ('r', v2b(self.r, self.W)), ('kp', v2b(self.kp, self.W)),
                  ('H', self._hs(self.Hh))] + ([("H'", self._hs(self.Hp))] if X else []) + [(None, bytes(0 if self.name == 'ed25519' else 14))]
        return L
    @property
    def scc_clear_len1(self): return (self.policy != 0) * -(-self.vb // 128) + (self.ext == 1) * -(-self.ub // 128)
    def export(self):
        """SCC export: (MDH, Content1). block_base travels in AuxInfo[15:8], OutputType and Progress in MachineUse."""
        self._live(); return self.mdh, b''.join(v for _, v in self._layout())
    def ads(self): return v2b(self.progress, 16) if self.progress else b''   # Content2
    @classmethod
    def imported(cls, name, mdh, c, c2=None, rbg=None):
        """SCC import of (mdh, Content1) into a locker of curve `name`: invalid Metadata gives Error State Invalid,
        unsupported Metadata Error State Unsupported (KLE-Metadata-validity). Without Position ii, Generator is the default.
        c2 is the Content2 that the import retains, None when it retains no ADS (ADSDropped = 1, an IMPQUAL mismatch, a failed
        SIV2 check): a halted operation then restarts (GR38)."""
        m = mdh_unpack(mdh); pol, ext, aux = m['MachinePolicy'], m['MachineExtension'], m['AuxInfo']
        kind = 'ed' if name.startswith('ed') else 'mont' if name.startswith('x') else 'wei'
        if m['Machine'] != 10 or pol > 3 or ext > 2 or (kind == 'mont' and pol) or (kind == 'ed' and not pol) or m['AuxDataLen'] == 1:
            L = cls(name, 0 if kind == 'mont' else 3, rbg=rbg); L._inv(); return L
        L = cls(name, pol, aux & 1, rbg, ext, m['SCProtection'])
        if L.err is not None: return L                                    # sealed EdDSA
        if kind == 'ed' and aux >> 3 & 31: L.err = SE_UNSUPPORTED; L.state = 0; return L   # reserved AuxInfo bits [7:3]
        st, mu = m['State'], m['MachineUse']
        L.state, L.flags, L.outtype, L.progress, L.block_base = st, m['StateExtension'], mu & 3, mu >> 2, aux >> 8
        if kind == 'ed': L.msg_pass = aux >> 1 & 3
        if st not in L._states() | {54, 55} or len(c) != sum(len(v) for _, v in L._layout()): L._inv(); return L
        if kind == 'ed':    # HasHashState set exactly in Msg_Absorb, where msg_pass names an open pass (0, 1 or 3); m31
            bad = L.msg_pass not in {MABS: (0, 1, 3), SGN: (0, 2), SVER: (0, 3), 54: (0, 3), 55: (0, 3)}.get(st, (0,))
            if L.has('rnd') != (st == MABS) or bad: L._inv(); return L
        elif L.has('rnd') and st != SGN: L._inv(); return L
        o = 0
        for n, v in L._layout():
            f = c[o:o + len(v)]; o += len(v)
            if n in ('Signature', 'Generator', 'SecondPt', 'Scalar', 'Hash', 'RndNum', 'ctx'): getattr(L, n)[:] = f
            elif n == 'ctxlen': L.ctxlen = f[0]
            elif n in ('r', 'kp'): setattr(L, n, b2v(f))
            elif n == 'H' and st == MABS: L.Hh = L._hs_load(f)
            elif n == "H'" and st == MABS and L.msg_pass == 1: L.Hp = L._hs_load(f)
        if st == MABS: L.pass_id = {0: 0, 1: 1, 3: 2}[L.msg_pass]
        if st in SETS:      # a load is in progress until block_base reaches the field size (Rule KLE-MGR-load-long-field)
            f = {SGEN: L.Generator, SSCAL: L.Scalar, SHASH: L.Hash, S2ND: L.SecondPt, SIN: L.Signature, SCTX: L.ctx}[st]
            L.complete = L.block_base == (L.ctxlen if st == SCTX else len(f))
        if L.progress and (c2 is None or m['ADSDropped'] or m['AuxDataLen'] < 2 or c2 != L.ads()): L._discard_progress()   # restart
        return L
