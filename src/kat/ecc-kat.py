#!/usr/bin/env python3
"""KATs for the elliptic-curve Machines (<<KLE-ECC>>, <<KLE-X25519-X448>>, <<KLE-EdDSA>>): a locker model
driven by kl.setst / kl.exec / kl.derive against RFC 6979, RFC 7748, RFC 8032, GM/T 0003.5 and RFC 5639 data.
The RBG draw of k is injected (RFC 6979's deterministic k)."""
import copy, hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, section, check, control, info, raises, done,  # noqa: E402
                    KL_STATE_READY as READY, KL_STATE_SUCCESS as SUCCESS,
                    KL_STATE_FAILURE as FAILURE, KL_STATE_HASH_ABSORB as HASH_ABSORB,
                    KL_STATE_SET_KEY as SET_KEY)
import ecc_curves as EC                                                                # noqa: E402

(SET_GEN, SET_SCALAR, POINT_MUL, SIGN_GEN, SIGN_VER, SET_HASH, SET_SECONDPT, SET_SIG,
 OUTPUT, MSG_ABSORB, SET_CTX) = range(2, 13)
TIMEOUT = object()                                  # an RBG draw past the bound of GR64
SET_FIELD = {SET_GEN: 'gen', SET_SCALAR: 'scalar', SET_HASH: 'hash', SET_SECONDPT: 'sec', SET_SIG: 'sig'}
# <<KLE-ECC>> Parameters: b, h, j, u, v
PARAMS = {'secp256r1': (256, 256, 256, 2, 2), 'secp384r1': (384, 384, 384, 2, 2),
          'secp521r1': (576, 576, 576, 2, 2), 'brainpoolP256r1': (256, 256, 256, 2, 2),
          'brainpoolP384r1': (384, 384, 384, 2, 2), 'brainpoolP512r1': (512, 512, 512, 2, 2),
          'sm2p256v1': (256, 256, 256, 2, 2), 'ed25519': (256, 512, 0, 1, 2),
          'ed448': (456, 512, 0, 1, 2), 'x25519': (256, 0, 0, 1, 0), 'x448': (448, 0, 0, 1, 0)}
MSB_ZERO = {'secp521r1': 55}
MDH0 = dict(UsagePolicy=0, ExpirationDate=0, SCProtection=0, KeyType=0)

class Invalid(Exception):
    """Transition to Error State _Invalid_; `who` names the kl.derive endpoint(s)."""
    def __init__(self, msg='', who=None):
        super().__init__(msg)
        self.who = who

class RbgUnavailable(Exception):
    """KLE RBG-unavailable exception (GR64): random bits unavailable past the bound; State unchanged."""

def targets(state, eddsa, sig_exit=True, xdh=False):
    """kl.setst targets (<<KLE-ECC>>, <<KLE-EdDSA>>, <<KLE-X25519-X448>>, GR22, GR20). A same-State kl.setst is
    admitted only in _Ready_, in a Set State (it restarts the load, MR7) and in the EdDSA _Msg_Absorb_ (a pass
    boundary)."""
    if xdh:                                  # no signature States
        sets = {SET_GEN, SET_SCALAR, SET_SECONDPT}
        t = {READY: sets | {POINT_MUL}, POINT_MUL: {READY}, OUTPUT: {READY}, SUCCESS: {READY},   # MR18
             FAILURE: {READY}}.get(state, sets | {POINT_MUL, READY} if state in sets else set())
        return t | ({state} if state in sets | {READY} else set())
    entry = set(SET_FIELD) | ({SET_CTX} if eddsa else set())
    free = entry - (set() if sig_exit else {SET_SIG})
    ops, absorb = {POINT_MUL, SIGN_GEN, SIGN_VER}, {MSG_ABSORB} if eddsa else set()
    if state == READY:
        t = entry | ops | absorb
    elif state in free:
        t = free | ops | absorb | {READY}
    elif eddsa and state == MSG_ABSORB:      # <<KLE-EdDSA>>: no Set state between passes or before Sign_Verify
        t = {MSG_ABSORB, SIGN_GEN, SIGN_VER, READY}
    elif state in (POINT_MUL, SIGN_GEN):     # _Output_ is entered only by the Form D kl.exec (MR18)
        t = {READY}
    else:
        t = {READY} if state in (OUTPUT, SIGN_VER, SUCCESS, FAILURE) else set()
    return t | ({state} if state in entry | absorb | {READY} else set())

def retry_required(mode, r, s, k, n): return r == 0 or s == 0 or (mode == 'sm2' and (r + k) % n == 0)

OUT_POINT, OUT_SIG, OUT_SHARED = 0, 1, 2            # <<KLE-ECC-MachineUse>> OutputType

class Unsupported(Exception):
    """kl_exc_unsupported at provisioning or import (<<KLE-Metadata-validity>>)."""

class Locker:
    def __init__(self, c, sign=None, verify=None, sig_exit=True, aux_info=None, pure_impl=True):
        """aux_info: <<KLE-EdDSA>> _AuxInfo_ (0 pre-hash only, 1 pure as well; default 1 for EdDSA);
        pure_impl: the implementation offers pure mode for the curve.
        sign, verify: _MachinePolicy_[0], [1]; default both set, and both clear for x25519 / x448."""
        xdh = getattr(c, 'montgomery', False)
        sign, verify = (not xdh if x is None else x for x in (sign, verify))
        if xdh and (sign or verify):
            raise Unsupported('<<KLE-X25519-X448>>: _MachinePolicy_ is not used and must be zero')
        if c.edwards and not (sign or verify):
            raise Invalid('<<KLE-EdDSA>>: _MachinePolicy_ = 0 is invalid')
        self.c, self.policy, self.sig_exit = c, (sign, verify), sig_exit
        self.aux_info = (1 if c.edwards else 0) if aux_info is None else aux_info
        if c.edwards and (self.aux_info >> 3 or self.aux_info & 1 and not pure_impl):
            raise Unsupported('EdDSA _AuxInfo_ reserved bits [15:3], or pure mode not offered')
        self.aux_info &= 1                          # bits [2:1] (msg_pass) of a PI: ignored and zeroed
        self.b, h, self.j, u, v = PARAMS[c.name]
        self.mode = 'eddsa' if c.edwards else 'xdh' if xdh else 'sm2' if c is EC.SM2C else 'ecdsa'
        fw = self.fw = self.b // 8
        self.size = dict(gen=u * fw, sec=u * fw, scalar=fw, hash=h // 8, sig=v * fw)
        self.default_gen = self.gen = self.enc(c.G)
        self.scalar, self.sec, self.sig, self.hash, self.rnd = bytes(fw), None, None, None, None
        self.has, self.out_type, self.progress, self.bb, self.loading = set(), OUT_POINT, 0, 0, None
        self.msg_pass, self.ctx, self.absorb, self.pass_xs, self.r, self.kp = 0, b'', None, None, None, None
        self.mdh, self.state = dict(MDH0), READY

    # points: little-endian coordinates; the point at infinity has no encoding
    def enc(self, P):
        assert P is not None
        if self.mode == 'xdh':              # <<KLE-X25519-X448>>: the u-coordinate alone
            return v2b(P, self.fw)
        return self.c.encode(P) if self.c.edwards else v2b(P[0], self.fw) + v2b(P[1], self.fw)

    def dec(self, data):
        if self.c.edwards:
            return self.c.decode(data)
        P = (b2v(data[:self.fw]), b2v(data[self.fw:]))
        return P if max(P) < self.c.p else None

    def repr_ok(self, data):            # every b-bit component has its MSB_ZERO msbs clear
        top = self.b - MSB_ZERO.get(self.c.name, 0)
        return not any(b2v(data[i:i + self.fw]) >> top for i in range(0, len(data), self.fw))

    @property
    def machine_use(self):              # <<KLE-ECC-MachineUse>>
        return self.out_type | self.progress << 2

    def discard(self):                  # GR55; also kl.clearads, an import without Content2, a kl.clone copy (GR56)
        self.progress, self.rnd = 0, None
        self.has.discard('rnd')

    def halt(self, progress=1, k=None):
        """Precise halt of the current long-running kl.exec (GR54)."""
        if self.state not in (POINT_MUL, SIGN_GEN, SIGN_VER) or not 0 < progress < 1 << 12:
            raise Invalid('no long-running operation / bad Progress')
        if self.state == SIGN_GEN and self.mode != 'eddsa':
            self.rnd = v2b(k, self.j // 8)
            self.has.add('rnd')
        self.progress = progress

    def setst(self, t, xs=0, rand=None, form=None):
        """kl.setst #t; without `form`, xs = 0 means Form A."""
        if t not in targets(self.state, self.mode == 'eddsa', self.sig_exit, self.mode == 'xdh'):
            raise Invalid('transition not allowed')                   # GR21; #46, #47: GR24
        if t != READY and not self._leads_enabled(t, xs):
            self._policy_gate()                                         # MR9 item 1.a, before the State is left
        if form == 'C':
            raise Invalid('wrong Form: no Form C kl.setst is native')       # GR12
        if form == 'A' and t in (SET_CTX, MSG_ABSORB):
            raise Invalid('wrong Form: only Form B is native')         # GR12
        if (form or ('B' if xs or t in (SET_CTX, MSG_ABSORB) else 'A')) == 'B' and t not in (
                SET_GEN, SET_SCALAR, READY, SET_CTX, MSG_ABSORB):
            raise Invalid('wrong Form: only Form A is native')         # GR12
        if t == SET_HASH and not any(self.policy):
            raise Invalid('Hash exists only if signing or verification is allowed')   # MR9
        if t == SET_SIG and not self.policy[1]:
            raise Invalid('_Sign_Input_ is gated by _MachinePolicy_[1]')            # MR9
        if self.state == MSG_ABSORB:                # MR9: leave first, then check the destination's entry conditions
            self._abandon_pass() if t == READY else self._finalize_pass()
        f = self.loading
        if f and self.bb < self.size[f]:            # MR7: a load left incomplete leaves the field unconfigured
            if f == 'ctx':
                self.ctx, self.size['ctx'] = b'', 0
            else:
                setattr(self, f, bytes(self.size[f]) if f in ('gen', 'scalar') else None)
                self.has.discard(f)
        self.discard()
        self.bb, self.loading, self.buf = 0, None, b''
        f = SET_FIELD.get(t)
        if f == 'scalar':
            self.scalar = v2b(rand, self.fw) if xs else bytes(self.fw)   # Form B: drawn inside
        elif f == 'gen':
            self.gen = bytes(self.size['gen']) if xs else self.default_gen     # Form B: erased, then loaded
        elif f in ('sec', 'hash', 'sig'):
            setattr(self, f, None)
            self.has.discard(f)
        if f:
            self.loading = f
            if (f, bool(xs)) in (('gen', False), ('scalar', True)):
                self.bb = self.size[f]          # an immediate assignment completes the load (MR7)
        elif t == SET_CTX:
            if xs > 255:
                raise Invalid('ctxlen > 255')
            self.ctx, self.size['ctx'], self.loading = b'', xs, 'ctx' if xs else None
        elif t == MSG_ABSORB:
            self._enter_pass(xs)
        elif t == POINT_MUL:                        # MR9 entry condition: a configured Scalar (key or seed)
            k = b2v(self.scalar)
            if not k or self.mode in ('ecdsa', 'sm2') and k >= self.c.n:
                raise Invalid('Scalar does not hold a configured private key or seed')
        elif t == SIGN_GEN:
            if not self.policy[0]:
                raise Invalid('MachinePolicy[0] clear')
            if self.mode == 'eddsa':
                if not any(self.scalar) or not (self.msg_pass == 2 or self.msg_pass == 0 and 'hash' in self.has):
                    raise Invalid('no seed, or neither pure nor pre-hash path')
            elif 'hash' not in self.has or not 1 <= b2v(self.scalar) < self.c.n - (self.mode == 'sm2'):   # SM2: d <= n-2
                raise Invalid('HasHash and a configured private key required')
        elif t == SIGN_VER:
            if not self.policy[1]:
                raise Invalid('MachinePolicy[1] clear')
            if not ({'sec', 'sig'} <= self.has and (self.msg_pass == 3 or self.msg_pass == 0 and 'hash' in self.has)
                    if self.mode == 'eddsa' else {'sec', 'hash', 'sig'} <= self.has):
                raise Invalid('HasSecondPt and HasSignature, and (EdDSA) a pure or pre-hash path, or (else) HasHash')
        elif t == READY:
            self._ready(xs)
        self.state = t

    def restrictl_policy(self, clear_sign, clear_verify):
        """kl.restrictl or kl.restrictv on _MachinePolicy_ (<<KLE-instruction-restrict>>): a set bit removes its
        function, a clear one changes nothing; clearing both bits erases Hash and Signature and their flags
        (<<KLE-ECC>>), and is invalid for EdDSA (<<KLE-EdDSA>>)."""
        if self.mode == 'xdh' and (clear_sign or clear_verify):   # a Machine that does not use the field
            raise Invalid('x25519 / x448 use no _MachinePolicy_')   # <<KLE-instruction-restrict>>
        sign, verify = self.policy[0] and not clear_sign, self.policy[1] and not clear_verify
        if self.mode == 'eddsa' and not (sign or verify):
            raise Invalid('<<KLE-EdDSA>>: _MachinePolicy_ = 0 is invalid')   # a value the Machine forbids (GR25)
        self.policy = (sign, verify)                    # GR25: the State is kept; see _policy_gate
        if not sign:                                    # RndNum exists only if MachinePolicy[0]
            self.rnd = None
            self.has.discard('rnd')
        if not sign and not verify:
            self.hash = self.sig = None
            self.has -= {'hash', 'sig'}
        return self

    def _ready(self, xs):
        """Ready-return Xs bits; a set bit discards (bits 4, 5: copies), a clear bit retains; bits 7+ reserved."""
        if xs >> 7:
            raise Invalid('reserved Xs bits of the return to _Ready_')
        gen, sec, had_sec = self.gen, self.sec, 'sec' in self.has    # copies use the values held before
        if xs & 16:
            self.sec = gen
            self.has.add('sec')
        if xs & 32 and had_sec:
            self.gen = sec
        if xs & 1:
            self.gen = self.default_gen
        if xs & 4:
            self.scalar = bytes(self.fw)
        for bit, f in ((2, 'sec'), (8, 'hash'), (64, 'sig')):
            if xs & bit:
                setattr(self, f, None)
                self.has.discard(f)
        self.msg_pass, self.ctx, self.r, self.kp = 0, b'', None, None

    def _leads_enabled(self, t, xs):
        """MR9 item 1.a: whether target t leads to an enabled operation (_Point_Mul_ is never gated)."""
        if t == MSG_ABSORB:
            return self.policy[0] if xs in (0, 1) else self.policy[1]
        if t == SIGN_GEN:
            return self.policy[0]
        if t in (SIGN_VER, SET_SIG):
            return self.policy[1]
        return any(self.policy) if t == SET_HASH else True

    def _policy_gate(self):
        """GR25, MR9: in a State whose operation is disabled, or that leads only to disabled ones: _Invalid_."""
        signing = (self.state == SIGN_GEN or self.state == MSG_ABSORB and self.pass_xs in (0, 1)
                   or self.state == OUTPUT and self.out_type == OUT_SIG)            # MR9: follows uniquely
        verifying = self.state in (SIGN_VER, SET_SIG) or self.state == MSG_ABSORB and self.pass_xs == 2
        if (signing and not self.policy[0] or verifying and not self.policy[1]
                or self.state == SET_HASH and not any(self.policy)):
            raise Invalid('GR25: the operation of the State is disabled')

    def exec_in(self, data):
        """Form B kl.exec: MR7 loading with W = block_base, or message absorption."""
        self._policy_gate()
        if self.state == MSG_ABSORB:
            self.absorb += data
            return
        f = self.loading
        if f is None or self.bb >= self.size[f]:
            raise Invalid('no kl.exec expected')
        n = self.size[f]
        self.buf += data[:n - self.bb]
        self.bb += len(data)
        if self.bb >= n:
            if f != 'ctx' and not self.repr_ok(self.buf):
                raise Invalid(f'{f} violates the b-bit representation')
            setattr(self, f, self.buf)
            if f in ('sec', 'sig', 'hash'):
                self.has.add(f)

    def exec_run(self, rbg=(), bad=None, be=False):
        """Form D kl.exec; `bad(attempt)` forces a degenerate draw, `be` mis-encodes EdDSA S."""
        self._policy_gate()
        # MR11: the zero msbs of every value used are checked again (secp521r1)
        used = {POINT_MUL: ('scalar', 'sec' if 'sec' in self.has else 'gen'),
                SIGN_GEN: ('scalar', 'hash', 'gen') + ('rnd',) * bool(self.progress and 'rnd' in self.has),
                SIGN_VER: ('sig', 'hash', 'sec', 'gen')}.get(self.state, ())
        if any(getattr(self, f) is not None and not self.repr_ok(getattr(self, f)) for f in used):
            raise Invalid('msbs not zero when used')
        if self.state == POINT_MUL:
            return self._point_mul()
        if self.state == SIGN_GEN:
            if self.mode != 'eddsa' and not self.valid(self.gen):   # MR10 data error; EdDSA signs over B
                return self._fail()
            return self._eddsa_sign(be) if self.mode == 'eddsa' else self._sign(rbg, bad)
        if self.state == SIGN_VER:
            ok = self._eddsa_verify() if self.mode == 'eddsa' else self.valid(self.gen) and self._verify()
            if self.mode == 'eddsa':
                self.kp = None                      # k' zeroed on completion
            self.discard()
            self.state = SUCCESS if ok else FAILURE
            return ok
        raise Invalid('Form D kl.exec not expected')

    def _to_output(self, out_type, f):
        self.has.add(f)
        self.discard()
        self.out_type, self.bb, self.state = out_type, 0, OUTPUT

    def valid(self, data):
        """<<KLE-ECC>> valid point: coordinates < p, on the curve, not the neutral element (the point at
        infinity, resp. (0, 1) of an Edwards curve), in the prime-order subgroup."""
        P = self.dec(data)
        return P is not None and not (self.c.edwards and P == (0, 1)) and self.c.in_subgroup(P)

    def _fail(self):                                # MR10 data error: _Failure_, a Valid State
        self.discard()
        self.state = FAILURE

    def _point_mul(self):
        k, dh = b2v(self.scalar), 'sec' in self.has    # a loaded SecondPt: Diffie-Hellman
        base = self.sec if dh else self.gen
        if self.mode == 'xdh':                      # no range check, no point validation
            if not k:
                raise Invalid('no configured private key')
            R = self.c.x(self.scalar, base)
            if not any(R):                          # all-zero result: MR10 data error, SecondPt unchanged
                return self._fail()
            self.sec = R
        else:
            if not k or self.mode != 'eddsa' and k >= self.c.n:
                raise Invalid('no configured seed / Scalar out of range')
            if not self.valid(base):                # MR10 data error
                return self._fail()
            R = self.c.mul(self.keys()[0] if self.mode == 'eddsa' else k, self.dec(base))   # EdDSA: s from the seed
            self.sec = self.enc(R)
        self._to_output(OUT_SHARED if dh else OUT_POINT, 'sec')
        return R

    def _sign(self, rbg, bad):
        entry = (self.rnd, 'rnd' in self.has)          # restored on an RBG timeout (GR64)
        c, n, d, e = self.c, self.c.n, b2v(self.scalar), b2v(self.hash)
        G = self.dec(self.gen)                      # the base point is `Generator`
        draws = iter(([b2v(self.rnd)] if self.progress and 'rnd' in self.has else []) + list(rbg))
        attempt = 0
        while True:
            k = next(draws, None)
            if k is TIMEOUT:                        # GR64: KLE RBG-unavailable exception, State unchanged
                self.rnd = entry[0]
                if not entry[1]:
                    self.has.discard('rnd')
                raise RbgUnavailable()
            if k is None:                           # GR64: RBG failure
                raise Invalid('RBG failure')
            self.rnd = v2b(k, self.j // 8)
            self.has.add('rnd')
            x1 = c.mul(k, G)[0]
            if self.mode == 'sm2':
                r = (e + x1) % n
                s = pow(1 + d, -1, n) * (k - r * d) % n
            else:
                r = x1 % n
                s = pow(k, -1, n) * (e + r * d) % n
            if not (bad and bad(attempt)) and not retry_required(self.mode, r, s, k, n):
                break
            attempt += 1
        self.sig = v2b(r, self.fw) + v2b(s, self.fw)
        self._to_output(OUT_SIG, 'sig')
        return r, s, attempt

    def _verify(self):
        c, n = self.c, self.c.n
        r, s, e, Q = b2v(self.sig[:self.fw]), b2v(self.sig[self.fw:]), b2v(self.hash), self.dec(self.sec)
        if not (1 <= r < n and 1 <= s < n) or Q is None or not c.in_subgroup(Q):
            return False
        G = self.dec(self.gen)
        if self.mode == 'sm2':
            t = (r + s) % n
            X = c.add(c.mul(s, G), c.mul(t, Q)) if t else None
            return X is not None and (e + X[0]) % n == r
        w = pow(s, -1, n)
        X = c.add(c.mul(e * w % n, G), c.mul(r * w % n, Q))
        return X is not None and X[0] % n == r

    def shared(self):
        """<<KLE-ECC>> shared secret in its standard's byte order: Z = FE2OS(x) (SP 800-56A Rev. 3 5.7.1.2, C.2) for
        NIST and Brainpool; x2 || y2, 32 B each, big-endian, for SM2 (GM/T 0003.4); K of RFC 7748 for x25519 / x448."""
        if self.mode == 'ecdsa':
            return b2v(self.sec[:self.fw]).to_bytes((self.c.p.bit_length() + 7) // 8, 'big')
        if self.mode == 'sm2':
            return b2v(self.sec[:self.fw]).to_bytes(32, 'big') + b2v(self.sec[self.fw:]).to_bytes(32, 'big')
        return self.sec

    def out_buf(self):
        return self.sig if self.out_type == OUT_SIG else self.shared() if self.out_type == OUT_SHARED else self.sec

    def exec_out(self, nbytes):
        """Form C kl.exec in _Output_, then _Success_; a transfer past the field: _Invalid_ (MR7)."""
        if self.state != OUTPUT:
            raise Invalid('output transfer outside _Output_')
        self._policy_gate()
        buf = self.out_buf()
        if self.bb + nbytes > len(buf):
            raise Invalid('emitting kl.exec past the end of the field (MR7)')
        chunk = buf[self.bb:self.bb + nbytes]
        self.bb += nbytes
        if self.bb >= len(buf):
            self.state = SUCCESS
        return chunk

    def output_all(self, chunk=1 << 10):
        n, out = len(self.out_buf()), b''
        while self.state == OUTPUT:
            out += self.exec_out(min(chunk, n - self.bb))
        return out

    # <<KLE-EdDSA>>
    def H(self, data):
        return hashlib.sha512(data).digest() if self.c is EC.ED25519 else hashlib.shake_256(data).digest(114)

    def dom(self, x):
        if self.c is EC.ED448:
            return b'SigEd448' + bytes([x, len(self.ctx)]) + self.ctx
        return b'SigEd25519 no Ed25519 collisions' + bytes([x, len(self.ctx)]) + self.ctx if x or self.ctx else b''

    def keys(self):
        """(clamped s, prefix, encoded A) from the seed (RFC 8032 5.1.5, 5.2.5)."""
        hh = self.H(self.scalar)
        a = bytearray(hh[:self.fw])
        if self.c is EC.ED25519:
            a[0], a[31] = a[0] & 248, a[31] & 127 | 64
        else:
            a[0], a[55], a[56] = a[0] & 252, a[55] | 128, 0
        s = int.from_bytes(a, 'little')
        return s, hh[self.fw:2 * self.fw], self.c.encode(self.c.mul_g(s))

    def _enter_pass(self, xs):
        if self.aux_info == 0:
            raise Invalid('Msg_Absorb with _AuxInfo_ = 0 (pre-hash only)')
        if xs == 0 and self.policy[0] and any(self.scalar):
            self.msg_pass, self.absorb, self.kp = 0, self.dom(0) + self.keys()[1], None
        elif xs == 1 and self.msg_pass == 1:
            self.absorb = self.dom(0) + self.sig[:self.fw] + self.keys()[2]
        elif xs == 2 and self.policy[1] and {'sig', 'sec'} <= self.has:
            self.msg_pass, self.absorb, self.kp = 3, self.dom(0) + self.sig[:self.fw] + self.sec, None
        else:
            raise Invalid(f'Msg_Absorb Xs = {xs}: precondition unmet')
        self.pass_xs = xs
        self.has.add('hstate')                     # HasHashState: StateExtension bit 3

    def state_se_supported(self):
        """<<KLE-Metadata-validity>>: _StateExtension_ bit 3 is HasRndNum only in _Sign_Generate_, HasHashState
        exactly in _Msg_Absorb_ (EdDSA); x25519 / x448 have only HasSecondPt."""
        if self.mode == 'eddsa':
            return ('hstate' in self.has) == (self.state == MSG_ABSORB)
        if self.mode == 'xdh':
            return self.has <= {'sec'}
        return 'rnd' not in self.has or self.state == SIGN_GEN

    def aux(self):
        """_AuxInfo_: bit 0 pure mode, bits [2:1] msg_pass (<<KLE-EdDSA>>)."""
        return self.aux_info | self.msg_pass << 1

    HS_BITS = {'ed25519': 1664, 'ed448': 1792}                    # serialized SHA-512 / SHAKE256 state

    def eddsa_content1_extra_bits(self):
        """Positions viii-xiii of <<KLE-EdDSA>>: ctxlen, ctx, r, k', the state of H, and that of H' if
        MachinePolicy[0]; independent of HasHashState."""
        return 8 + 2040 + 2 * self.b + (any(self.policy) + bool(self.policy[0])) * self.HS_BITS[self.c.name]

    def serialized(self):
        """Fields iv-vii of <<KLE-ECC>> in Content1: SecondPt; Signature and Hash if MachinePolicy != 0; RndNum (j > 0)
        if MachinePolicy[0]; independent of State and StateExtension."""
        return ['sec'] + (['sig', 'hash'] if any(self.policy) else []) + (['rnd'] if self.policy[0] and self.j else [])

    def varlen(self):
        """Size in bytes of Fields iv-vii: ub/8 + (MachinePolicy != 0) (vb + h)/8 + MachinePolicy[0] j/8."""
        b, h, j, u, v = PARAMS[self.c.name]
        return (u * b + any(self.policy) * (v * b + h) + bool(self.policy[0]) * j) // 8

    def _abandon_pass(self):
        """Leaving _Msg_Absorb_ for _Ready_ (<<KLE-EdDSA>>): no hash completed, no binding check."""
        self.absorb, self.pass_xs = None, None
        self.has.discard('hstate')

    def _finalize_pass(self):
        xs, data, self.absorb, self.pass_xs = self.pass_xs, self.absorb, None, None
        self.has.discard('hstate')
        val = b2v(self.H(data)) % self.c.L
        if xs == 0:
            self.r, self.msg_pass = val, 1
            self.sig = self.c.encode(self.c.mul_g(val)) + bytes(self.fw)   # intermediate: HasSignature clear
            self.has.discard('sig')
            return
        if xs == 1:
            msg = data[len(self.dom(0)) + 2 * self.fw:]
            if b2v(self.H(self.dom(0) + self.keys()[1] + msg)) % self.c.L != self.r:
                raise Invalid('pass-2 message differs from pass 1')
        self.kp, self.msg_pass = val, 2 if xs == 1 else 3

    def _eddsa_sign(self, be=False):
        (s, prefix, A), L = self.keys(), self.c.L
        if self.msg_pass == 2:
            r, kp, R = self.r, self.kp, self.sig[:self.fw]
        else:
            r = b2v(self.H(self.dom(1) + prefix + self.hash)) % L
            R = self.c.encode(self.c.mul_g(r))
            kp = b2v(self.H(self.dom(1) + R + A + self.hash)) % L
        self.sig = R + ((r + kp * s) % L).to_bytes(self.fw, 'big' if be else 'little')
        self.r = self.kp = None
        self.msg_pass = 0
        self._to_output(OUT_SIG, 'sig')
        return self.sig

    def _eddsa_verify(self):
        c, R_enc = self.c, self.sig[:self.fw]
        S, R, A = b2v(self.sig[self.fw:]), c.decode(R_enc), c.decode(self.sec)
        if S >= c.L or R is None or A is None:
            return False
        kp = self.kp if self.msg_pass == 3 else b2v(self.H(self.dom(1) + R_enc + self.sec + self.hash)) % c.L
        return c.mul(c.h * S, c.B) == c.add(c.mul(c.h, R), c.mul(c.h * kp, A))

# ---------------------------------------------------------------- vectors

# RFC 6979 A.2.5 (P-256), A.2.6 (P-384), A.2.7 (P-521).
RFC6979 = {
    'secp256r1': dict(
        x=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
        Ux=0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
        Uy=0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299,
        sigs=[
            ('sample', 'sha256',
             0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
             0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
             0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8),
            ('test', 'sha256',
             0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0,
             0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
             0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083)]),
    'secp384r1': dict(
        x=0x6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5,
        Ux=0xEC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13,
        Uy=0x8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720,
        sigs=[
            ('sample', 'sha384',
             0x94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA2907E3E83BA95368623B8C4686915CF9,
             0x94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46,
             0x99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8),
            ('test', 'sha384',
             0x015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092ADA71F4A459BC0DA98ADB95837DB8312EA,
             0x8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB,
             0xDDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5)]),
    'secp521r1': dict(
        x=0x0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538,
        Ux=0x1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4,
        Uy=0x0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5,
        sigs=[
            ('sample', 'sha512',
             0x1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3,
             0x0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA,
             0x0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A)]),
}

# RFC 8032 7.1 (Ed25519), 7.3 (Ed25519ph), 7.4 (Ed448): name, seed, pk, msg, [ctx,] sig.
RFC8032_ED25519 = [
    ('7.1 TEST 1 (empty message)',
     '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
     'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
     'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015'
     '55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
    ('7.1 TEST 2 (1-byte message)',
     '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
     '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
     '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
     '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
    ('7.1 TEST 3 (2-byte message)',
     'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
     'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
     '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac'
     '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a')]
RFC8032_ED25519PH = (
    '7.3 TEST abc (Ed25519ph)',
    '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf', '616263',
    '98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41'
    '31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406')
# RFC 8032 7.2 (Ed25519ctx): name, seed, pk, msg, ctx, sig.
ED25519CTX_SEED = '0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6'
ED25519CTX_PK = 'dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292'
RFC8032_ED25519CTX = [
    ('7.2 foo', ED25519CTX_SEED, ED25519CTX_PK, 'f726936d19c800494e3fdaff20b276a8', '666f6f',
     '55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a'
     '8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d'),
    ('7.2 bar', ED25519CTX_SEED, ED25519CTX_PK, 'f726936d19c800494e3fdaff20b276a8', '626172',
     'fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3'
     '216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d'),
    ('7.2 foo2', ED25519CTX_SEED, ED25519CTX_PK, '508e9e6882b979fea900f62adceaca35', '666f6f',
     '8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc6490'
     '8922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b'),
    ('7.2 foo3', 'ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560',
     '0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772', 'f726936d19c800494e3fdaff20b276a8', '666f6f',
     '21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85'
     'e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f')]
# RFC 8032 7.5 (Ed448ph): name, seed, pk, msg, ctx, sig.
ED448PH_SEED = ('833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42'
                'ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49')
ED448PH_PK = ('259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743'
              'c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880')
RFC8032_ED448PH = [
    ('7.5 TEST abc', ED448PH_SEED, ED448PH_PK, '616263', '',
     '822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae38'
     '1f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd'
     '433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3'
     'ad203df7dc7ce360c3cd3696d9d9fab90f00'),
    ('7.5 TEST abc (with context)', ED448PH_SEED, ED448PH_PK, '616263', '666f6f',
     'c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa48'
     '1065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3'
     '653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab7128'
     '4f8d0704a608c54a6b62d97beb511d132100')]
ED448_SEED1 = ('c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a'
               'fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e')
ED448_PK1 = ('43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086'
             '6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480')
RFC8032_ED448 = [
    ('7.4 Blank (empty message)',
     '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3'
     '528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b',
     '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778'
     'edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180', '', '',
     '533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f'
     '2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a'
     '9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db'
     'b61149f05a7363268c71d95808ff2e652600'),
    ('7.4 1 octet', ED448_SEED1, ED448_PK1, '03', '',
     '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435'
     '2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb'
     'cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f'
     'f3348ab21aa4adafd1d234441cf807c03a00'),
    ('7.4 1 octet (with context "foo")', ED448_SEED1, ED448_PK1, '03', '666f6f',
     'd4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2'
     '151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da'
     '1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d'
     '5428407e85dcbc98a49155c13764e66c3c00')]

# GM/T 0003.5-2012 / GB/T 32918.5-2017 Appendix A, message "message digest".
SM2_VEC = dict(
    ida=b'1234567812345678', msg=b'message digest',
    d=0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8,
    Px=0x09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020,
    Py=0xCCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13,
    ZA=0xB2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3,
    e=0xF0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640,
    k=0x59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21,
    r=0xF5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3,
    s=0xB1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA)

# ---------------------------------------------------------------- drivers

def ecdsa_e(c, digest):
    """FIPS 186-5 6.4: leftmost min(N, outlen) bits (the caller's job)."""
    return int.from_bytes(digest, 'big') >> max(0, len(digest) * 8 - c.n.bit_length())

def load(cr, st, data, chunk=None, xs=None):
    cr.setst(st, int(st == SET_GEN) if xs is None else xs)
    step = chunk or len(data) or 1
    for i in range(0, len(data), step):
        cr.exec_in(data[i:i + step])
    return cr

def locker(c, *loads, to=None, **kw):
    """A fresh locker after the (State, data[, chunk]) `loads`, then kl.setst #to."""
    cr = Locker(c, **kw)
    for ld in loads:
        load(cr, *ld)
    if to is not None:
        cr.setst(to)
    return cr

def pt(c, P): return Locker(c).enc(P)
def sc(k, n=32): return (SET_SCALAR, v2b(k, n))
def hs(e, n=32): return (SET_HASH, v2b(e, n))
def invalid(fn, *a, **kw): return raises(fn, *a, exc=Invalid, **kw)

def sign(c, d, e, ks, bad=None):
    b, h = PARAMS[c.name][:2]
    cr = locker(c, sc(d, b // 8), hs(e, h // 8), to=SIGN_GEN)
    r, s, att = cr.exec_run(ks, bad)
    return (r, s), cr.output_all(16), att, cr

def verify(c, pub, e, sig, chunk=None, gen=None):
    pre = ((SET_GEN, gen),) if gen is not None else ()
    cr = locker(c, *pre, (SET_SECONDPT, pub, chunk), hs(e, PARAMS[c.name][1] // 8), (SET_SIG, sig, chunk),
                to=SIGN_VER)
    cr.exec_run()
    return cr.state

def ed_sign(c, seed, msg, ctx=b'', chunk=None, be=False, msg2=None, gen=None):
    pre = ((SET_GEN, gen),) if gen is not None else ()
    cr = locker(c, *pre, (SET_SCALAR, seed, chunk), (SET_CTX, ctx, None, len(ctx)))
    cr.setst(MSG_ABSORB, 0)
    cr.exec_in(msg)
    cr.setst(MSG_ABSORB, 1)
    p1 = cr.msg_pass
    cr.exec_in(msg if msg2 is None else msg2)
    cr.setst(SIGN_GEN)
    cr.exec_run(be=be)
    return cr.output_all(c.nbytes), p1, cr

def ed_verify(c, pk, sig, msg, ctx=b'', gen=None):
    pre = ((SET_GEN, gen),) if gen is not None else ()
    cr = locker(c, *pre, (SET_SECONDPT, pk), (SET_SIG, sig), (SET_CTX, ctx, None, len(ctx)))
    cr.setst(MSG_ABSORB, 2)
    cr.exec_in(msg)
    cr.setst(SIGN_VER)
    cr.exec_run()
    return cr.state

def ed_point_mul(c, seed):
    cr = locker(c, (SET_SCALAR, seed), to=POINT_MUL)
    cr.exec_run()
    return cr.output_all()

# ---------------------------------------------------------------- tests

P256, V256 = EC.P256, RFC6979['secp256r1']
D256, PUB256 = v2b(V256['x'], 32), pt(EC.P256, (V256['Ux'], V256['Uy']))
MSG0, HN0, K0, R0, S0 = V256['sigs'][0]
E0 = ecdsa_e(P256, hashlib.new(HN0, MSG0.encode()).digest())

section('Domain parameters and the b / h / j / u / v table')
for name, c in EC.WEIERSTRASS_CURVES.items():
    b = PARAMS[name][0]
    check(f'{name}: G on curve, n*G = O, h = 1', c.is_on_curve(c.G) and c.mul(c.n, c.G) is None and c.h == 1)
    check(f'{name}: b = {b} holds the field, whole bytes', b >= c.p.bit_length() and b % 8 == 0)
for name, c in EC.EDWARDS_CURVES.items():
    check(f'{name}: B on curve, L*B = identity', c.is_on_curve(c.B) and c.mul(c.L, c.B) == (0, 1))
    check(f'{name}: b = {c.bbits}, u = 1, v = 2', (PARAMS[name][0], *PARAMS[name][3:]) == (c.bbits, 1, 2))
check('secp521r1: b = 576 with 55 zero msbs covers the 521-bit field',
      PARAMS['secp521r1'][0] - MSB_ZERO['secp521r1'] == EC.P521.p.bit_length())

section('ECDSA: RFC 6979 A.2.5-A.2.7')
for name, vec in RFC6979.items():
    c, fw = EC.WEIERSTRASS_CURVES[name], PARAMS[name][0] // 8
    pub = pt(c, (vec['Ux'], vec['Uy']))
    cr = locker(c, (SET_SCALAR, v2b(vec['x'], fw), 8), to=POINT_MUL)
    check(f'{name}: Point_Mul d*G = U, Output, Success',
          (cr.exec_run(), cr.output_all(16), cr.state) == ((vec['Ux'], vec['Uy']), pub, SUCCESS))
    for msg, hn, k, r, s in vec['sigs']:
        e = ecdsa_e(c, hashlib.new(hn, msg.encode()).digest())
        rs, sig, _, cr = sign(c, vec['x'], e, [k])
        check(f'{name}/{hn} "{msg}": Sign_Generate', None, (rs, sig, cr.state),
              ((r, s), v2b(r, fw) + v2b(s, fw), SUCCESS))
        check(f'{name}/{hn} "{msg}": Sign_Verify -> Success', verify(c, pub, e, sig, 16) == SUCCESS)
        check(f'{name}/{hn} "{msg}": corrupted signature -> Failure',
              verify(c, pub, e, bytes([sig[0] ^ 1]) + sig[1:]) == FAILURE)
    for label, r, s in (('r = 0', 0, 1), ('s = 0', 1, 0), ('r = n', c.n, 1), ('s = n', 1, c.n)):
        check(f'{name}: {label} -> Failure', verify(c, pub, 1, v2b(r, fw) + v2b(s, fw)) == FAILURE)

msg, hn, k, r, s_ = RFC6979['secp256r1']['sigs'][0]
dg = hashlib.new(hn, msg.encode()).digest()
check('`Hash` = bin(e, h), e the big-endian digest integer (FIPS 186-5 6.4.1 step 2): the RFC 6979 signature; '
      'a little-endian e gives another', True,
      (sign(P256, V256['x'], ecdsa_e(P256, dg), [k])[0] == (r, s_),
       sign(P256, V256['x'], int.from_bytes(dg, 'little'), [k])[0] != (r, s_)), (True, True))

cr = locker(EC.ED25519, sc(7), (SET_GEN, pt(EC.ED25519, (0, 1))), to=POINT_MUL)
cr.exec_run()
check('ed25519 _Point_Mul_ with `Generator` = the neutral element (0, 1): not a valid point, _Failure_', None,
      cr.state, FAILURE)

section('secp521r1: 576-bit fields with 55 zero msbs, checked at load and at use')
c, V521 = EC.P521, 12345
G521, Q521, H7 = Locker(c).gen, pt(c, c.mul_g(V521)), hs(7, 72)
check('default Generator: 144 bytes, 55 zero msbs per coordinate', Locker(c).repr_ok(G521) and len(G521) == 144)
for label, st, data in (('Scalar with bit 521 set', SET_SCALAR, v2b(1 << 521, 72)),
                        ('SecondPt with bit 575 set', SET_SECONDPT, v2b(c.G[0] | 1 << 575, 72) + v2b(c.G[1], 72)),
                        ('all-ones SecondPt', SET_SECONDPT, b'\xff' * 144)):
    check(f'{label} -> Invalid at load', invalid(load, Locker(c), st, data))
(r, s), sig521, _, _ = sign(c, V521, 7, [99])
for label, st, f, loads, rbg in (               # bit 575 set in a value read (MR11)
        ('Point_Mul uses a Generator', POINT_MUL, 'gen', [sc(V521, 72)], ()),
        ('Sign_Generate uses a Hash', SIGN_GEN, 'hash', [sc(V521, 72), H7], [99]),
        ('a resumed Sign_Generate uses a RndNum', SIGN_GEN, 'rnd', [sc(V521, 72), H7], []),
        ('Sign_Verify uses a Signature', SIGN_VER, 'sig', [(SET_SECONDPT, Q521), H7, (SET_SIG, sig521)], ())):
    good, bad = locker(c, *loads, to=st), locker(c, *loads, to=st)
    if f == 'rnd':
        good.halt(5, 99), bad.halt(5, 99)
    setattr(bad, f, v2b(b2v(getattr(bad, f)[:72]) | 1 << 575, 72) + getattr(bad, f)[72:])
    good.exec_run(rbg)
    check(f'{label} with bit 575 set -> Invalid' + (', not Failure (unaltered: Success)' if st == SIGN_VER
                                                    else ' (unaltered: Output)'),
          invalid(bad.exec_run, rbg) and good.state == (SUCCESS if st == SIGN_VER else OUTPUT))

section('Point_Mul: scalar range, curve validation, no point at infinity')
for label, k in (('0', 0), ('n', P256.n), ('n+1', P256.n + 1)):
    check(f'Scalar = {label}: the kl.setst into _Point_Mul_ -> Invalid (MR9 entry condition)',
          invalid(locker, P256, sc(k), to=POINT_MUL))
for label, k, want in (('n-1: accepted, result -G', P256.n - 1, (P256.G[0], P256.p - P256.G[1])),
                       ('2: accepted, result G+G', 2, P256.add(P256.G, P256.G))):
    cr = locker(P256, sc(k), to=POINT_MUL)
    check(f'Scalar = {label}', (cr.exec_run(), cr.state) == (want, OUTPUT))
off = v2b(P256.G[0], 32) + v2b(P256.G[1] + 1, 32)
cr = locker(P256, sc(2), (SET_SECONDPT, off), to=POINT_MUL)
cr.exec_run()
check('off-curve SecondPt in _Point_Mul_ -> Failure (MR10 data error), SecondPt unchanged',
      (cr.state, cr.sec) == (FAILURE, off))
check('Sign_Verify with an off-curve public key -> Failure', verify(P256, off, 1, v2b(1, 32) * 2) == FAILURE)
cr = locker(P256, sc(2), (SET_SECONDPT, b'\xff' * 64), to=POINT_MUL)
cr.exec_run()
check('all-ones SecondPt as base point -> Failure', cr.state == FAILURE)
cr = locker(P256, sc(2), (SET_GEN, off), to=POINT_MUL)
cr.exec_run()
check('off-curve Generator in _Point_Mul_ -> Failure', cr.state == FAILURE)
cr = locker(P256, sc(2), (SET_GEN, Locker(P256).gen[:40]), to=POINT_MUL)
cr.exec_run()
check('Generator load left incomplete: Generator zeroed (MR7), not a valid point: _Point_Mul_ -> Failure',
      cr.state == FAILURE and cr.gen == bytes(64))
cr = locker(P256, (SET_SCALAR, v2b(5, 32)[:16]))
check('Scalar load left incomplete: Scalar zeroed (MR7); the kl.setst into _Point_Mul_ -> Invalid (MR9)',
      invalid(cr.setst, POINT_MUL) and cr.scalar == bytes(32))
cr = locker(P256, (SET_SECONDPT, pt(P256, P256.mul_g(3))[:32]), to=SET_HASH)
check('SecondPt load left incomplete for another Set state: zeroed, HasSecondPt clear (MR7)',
      cr.sec is None and 'sec' not in cr.has and cr.state == SET_HASH)
cr = locker(P256, sc(5), (SET_GEN, off), hs(7, 32), to=SIGN_GEN)
cr.exec_run([3])
check('RBG failure in _Sign_Generate_ -> Invalid (GR64)',
      invalid(locker(P256, sc(5), hs(7, 32), to=SIGN_GEN).exec_run, []))
ct = locker(P256, sc(5), hs(7, 32), to=SIGN_GEN)
r = [raises(ct.exec_run, [TIMEOUT], exc=RbgUnavailable), ct.state, 'rnd' in ct.has, 'sig' in ct.has]
ct.exec_run([3])
check('RBG timeout in _Sign_Generate_: KLE RBG-unavailable exception, State unchanged, no RndNum; the reissue '
      'signs (GR64)', r == [True, SIGN_GEN, False, False] and ct.state == OUTPUT and 'sig' in ct.has)
check('off-curve Generator in _Sign_Generate_ -> Failure, no signature, RndNum not drawn',
      (cr.state, 'sig' in cr.has, 'rnd' in cr.has) == (FAILURE, False, False))
pk = pt(P256, P256.mul_g(5))
check('off-curve Generator in _Sign_Verify_ -> Failure',
      verify(P256, pk, 7, v2b(1, 32) * 2, gen=off) == FAILURE)

section('Signature retry rules')
n = P256.n
check('ECDSA: retry iff r = 0 or s = 0',
      [retry_required('ecdsa', *a, n) for a in ((0, 5, 7), (5, 0, 7), (5, 5, 7), (5, 5, n - 5))]
      == [True, True, False, False])
n2 = EC.SM2C.n
check('SM2: _Sign_Generate_ requires 1 <= int(Scalar) <= n - 2 (GM/T 0003): n - 1 -> _Invalid_, n - 2 admitted',
      [invalid(locker, EC.SM2C, sc(d), hs(5), to=SIGN_GEN) for d in (n2 - 1, n2 - 2)] == [True, False])
check('SM2: retry iff r = 0, r + k = n or s = 0',
      [retry_required('sm2', *a, n) for a in ((0, 5, 7), (5, 0, 7), (5, 5, n - 5), (5, 5, 7))]
      == [True, True, True, False])
rs, _, att, cr = sign(P256, V256['x'], E0, [0x1234, K0], bad=lambda a: a == 0)
check('degenerate first draw: a fresh k is drawn (RFC 6979 answer)', (att, rs) == (1, (R0, S0)))
check('RndNum destroyed, HasRndNum clear after signing', cr.rnd is None and 'rnd' not in cr.has)

def armed(): return locker(P256, (SET_SCALAR, D256), hs(E0), to=SIGN_GEN)
def cleared(cr): return (cr.progress, cr.rnd, 'rnd' in cr.has) == (0, None, False)

section('Progress and <<KLE-GR-progress-discard>>')
cr = armed()
check('Progress zero when nothing is interrupted', cr.machine_use == 0)
cr.halt(0x234, K0)
check('halt: Progress non-zero in MachineUse[13:2], RndNum kept, State unchanged',
      (cr.machine_use, b2v(cr.rnd), 'rnd' in cr.has, cr.state) == (0x234 << 2, K0, True, SIGN_GEN))
check('resume uses the held RndNum, draws nothing', None, cr.exec_run([])[:3], (R0, S0, 0))
check('completion zeroes Progress, destroys RndNum', cleared(cr))
cr = armed()
cr.halt(7, K0)
cr.setst(READY)
check(f'kl.setst #{READY} from a halted Sign_Generate discards Progress and RndNum', cleared(cr))
check('same-State kl.setst in a halted Sign_Generate -> Invalid (GR20, GR23)',
      invalid((lambda c: (c.halt(7, K0), c)[1])(armed()).setst, SIGN_GEN))
check('MR18: a kl.setst naming _Output_ from _Point_Mul_ or _Sign_Generate_ -> Invalid',
      bool(invalid(locker(P256, (SET_SCALAR, D256), to=POINT_MUL).setst, OUTPUT)) and bool(invalid(armed().setst, OUTPUT)))
check('a Form B kl.setst into _Set_Hash_, _Set_SecondPt_, _Sign_Input_ or _Point_Mul_ is a wrong Form '
      '(only Form A is native): _Invalid_ (GR12)', True,
      [invalid(locker(P256, (SET_SCALAR, D256)).setst, t, form='B') for t in (SET_HASH, SET_SECONDPT, SET_SIG, POINT_MUL)],
      [True] * 4)
check('a Form C kl.setst naming _Ready_ is a wrong Form (Form A or B is native): _Invalid_ (GR22, GR12)',
      bool(invalid(locker(P256, (SET_SCALAR, D256)).setst, READY, form='C')))
cr = Locker(P256)
cr.setst(SET_GEN, 1)
check('a Form B kl.setst into _Set_Generator_ with a non-zero GPR erases Generator when the load starts (MR7)',
      True, cr.gen, bytes(cr.size['gen']))
cr = locker(EC.ED25519, (SET_SCALAR, bytes(range(1, 33))), (SET_CTX, b'', None, 0))
cr.setst(MSG_ABSORB, 0); cr.exec_in(b'abc'); cr.setst(MSG_ABSORB, 1); cr.exec_in(b'abc')
cr.setst(MSG_ABSORB, 0)
check("re-entering signing pass 1 zeroes k'", True, (cr.msg_pass, cr.kp), (0, None))
cr = Locker(P256)
cr.setst(SET_GEN, form='B')
check('a Form B kl.setst into _Set_Generator_ with zero in the GPR is native: the default generator', True,
      (cr.state, cr.gen), (SET_GEN, cr.default_gen))
for how in ('kl.clearads', 'an import without Content2'):
    cr = armed()
    cr.halt(7, K0)
    cr.discard()
    check(f'{how} on a halted Sign_Generate discards Progress, RndNum, HasRndNum; State kept',
          cleared(cr) and cr.state == SIGN_GEN)
cr = armed()
cr.halt(7, K0)
cp = copy.deepcopy(cr)
cp.discard()
check('kl.clone of a halted Sign_Generate: the copy restarts, the source keeps Progress and RndNum',
      cleared(cp) and cp.state == SIGN_GEN and (cr.progress, b2v(cr.rnd)) == (7, K0))
cr = armed()
cr.halt(9, 0xDEAD)
cr.setst(READY)
cr.setst(SIGN_GEN)
check('after the discard the operation draws afresh', cr.exec_run([K0])[:2] == (R0, S0))
cr = locker(P256, (SET_SCALAR, D256), to=POINT_MUL)
cr.halt(0xFFF)
check('halted Point_Mul resumes to d*G, Progress zero after',
      (cr.exec_run(), cr.progress) == (P256.mul_g(V256['x']), 0))
cr = locker(P256, (SET_SCALAR, D256), to=POINT_MUL)
check('Progress at a halt is non-zero and fits [13:2]', invalid(cr.halt, 0) and invalid(cr.halt, 0x1000))
cr.out_type = OUT_SHARED
cr.halt(0xFFF)
check('OutputType [1:0] | Progress << 2 fits the 14-bit _MachineUse_', cr.machine_use == (1 << 14) - 2)
check('only long-running States can halt', invalid(locker(P256, hs(0, 0)).halt))
info('Progress encoding is implementation-defined: the model only tracks zero / non-zero.')

section('State machine: entry conditions, transfers, Output')
SIG0, H1 = bytes(64), hs(1)
for label, kw, loads, t in (
        ('fresh CC: Sign_Generate', {}, [], SIGN_GEN),
        ('no HasHash: Sign_Generate', {}, [(SET_SCALAR, D256)], SIGN_GEN),
        ('Scalar = 0: Sign_Generate', {}, [H1], SIGN_GEN),
        ('MachinePolicy[0] clear: Sign_Generate', dict(sign=False), [sc(3), H1], SIGN_GEN),
        ('no HasSecondPt: Sign_Verify', {}, [H1, (SET_SIG, SIG0)], SIGN_VER),
        ('no HasHash: Sign_Verify', {}, [(SET_SECONDPT, PUB256), (SET_SIG, SIG0)], SIGN_VER),
        ('no HasSignature: Sign_Verify', {}, [(SET_SECONDPT, PUB256), H1], SIGN_VER),
        ('MachinePolicy[1] clear: Sign_Input (MR9)', dict(verify=False), [(SET_SECONDPT, PUB256), H1], SET_SIG),
        ('MachinePolicy[1] clear: Sign_Verify', dict(verify=False), [(SET_SECONDPT, PUB256), H1], SIGN_VER),
        ('Ready -> Output (GR21)', {}, [], OUTPUT)):
    check(f'{label} -> Invalid', invalid(locker(P256, *loads, **kw).setst, t))
cr = locker(P256, sc(2), to=POINT_MUL, sign=False, verify=False)
check('MachinePolicy 0 on a generic ECC Machine: Point_Mul still available', True,
      (cr.exec_run(), cr.state), (P256.add(P256.G, P256.G), OUTPUT))
cr = locker(P256, to=SET_SECONDPT)
cr.exec_in(cr.default_gen[:20])
part = (cr.bb, 'sec' in cr.has)
cr.exec_in(cr.default_gen[20:] + b'\xaa' * 9)
check('block_base tracks a partial load; excess of the last kl.exec ignored',
      part == (20, False) and cr.sec == cr.default_gen and 'sec' in cr.has)
check('kl.exec after the field completes -> Invalid', invalid(cr.exec_in, b'\0' * 4))
cr = locker(P256, to=SET_SECONDPT)
cr.exec_in(cr.default_gen[:20])
cr.setst(SET_SECONDPT)
part = (cr.state, cr.bb, cr.sec, 'sec' in cr.has)
cr.exec_in(cr.default_gen)
check('same-State kl.setst in a Set State part-way restarts the load (GR20, MR7): block_base 0, field unconfigured; '
      'a full reload completes it', part == (SET_SECONDPT, 0, None, False) and cr.sec == cr.default_gen
      and 'sec' in cr.has)
cr = Locker(P256)
cr.setst(SET_SCALAR, xs=1, rand=V256['x'])
check('Form B Set_Scalar: random private key set, no kl.exec expected',
      b2v(cr.scalar) == V256['x'] and invalid(cr.exec_in, D256))
cr, gs = Locker(P256), []
for t, xs in ((SET_GEN, 0), (SET_SCALAR, 1)):
    cr.setst(t, xs=xs, rand=V256['x'])
    gs.append(cr.bb == cr.size['gen' if t == SET_GEN else 'scalar'])
    cr.setst(READY)
check('default Generator and random Scalar complete their load at once (block_base = field size, MR7), '
      'so leaving the Set State keeps them', gs == [True, True] and cr.gen == cr.default_gen
      and b2v(cr.scalar) == V256['x'])
cr = locker(P256, sc(2), to=POINT_MUL)
cr.exec_run()
check('Output: block_base-tracked, 24 + 24 + 16 bytes, then Success',
      b''.join(cr.exec_out(n) for n in (24, 24, 16)) == cr.sec and cr.state == SUCCESS)
cr = locker(P256, sc(2), to=POINT_MUL)
cr.exec_run()
cr.exec_out(24), cr.exec_out(24)
check('Output: a final 24-byte kl.exec past the 64-byte field -> Invalid (MR7)', invalid(cr.exec_out, 24))
for t in (SUCCESS, FAILURE):
    cr = Locker(P256)
    check(f'kl.setst #{t} -> Invalid (GR24, GR21)', invalid(cr.setst, t))
cr = locker(P256, sc(2), to=POINT_MUL)
cr.halt(3)
check('same-State kl.setst in a halted Point_Mul -> Invalid (GR20, GR23)', invalid(cr.setst, POINT_MUL))

def reach(eddsa, sig_exit=True):
    """Whether Sign_Verify is reachable by kl.setst from every Set state."""
    ok = True
    for st in set(SET_FIELD) | ({SET_CTX} if eddsa else set()):
        seen, todo = {st}, [st]
        while todo:
            new = targets(todo.pop(), eddsa, sig_exit) - seen
            seen |= new
            todo += new
        ok &= SIGN_VER in seen
    return ok

check('Sign_Verify reachable from every Set state (ECC, EdDSA)', reach(False) and reach(True))
control('_Sign_Input_ without exits: Sign_Verify unreachable, kl.setst -> Invalid',
        not reach(False, False) and invalid(locker(P256, (SET_SIG, SIG0), sig_exit=False).setst, SIGN_VER))

section('Ready-return Xs bits')
G1, G2 = pt(P256, P256.G), pt(P256, P256.add(P256.G, P256.G))
BASE = dict(gen=G2, scalar=7, sec=G1, hash=bytes(32), sig=SIG0)
for xs, change, label in (
        (0, {}, 'Form A / Xs = 0: every field retained'),
        (1, dict(gen=G1), 'bit 0: Generator reset to default'),
        (2, dict(sec=None), 'bit 1: SecondPt erased, HasSecondPt clear'),
        (4, dict(scalar=0), 'bit 2: Scalar erased'),
        (8, dict(hash=None), 'bit 3: Hash erased, HasHash clear'),
        (64, dict(sig=None), 'bit 6: Signature erased, HasSignature clear'),
        (16, dict(sec=G2), 'bit 4: Generator copied onto SecondPt'),
        (17, dict(sec=G2, gen=G1), 'bits 4+0: copy, then Generator reset'),
        (32, dict(gen=G1), 'bit 5: SecondPt copied onto Generator'),
        (34, dict(gen=G1, sec=None), 'bits 5+1: copy, then SecondPt erased'),
        (48, dict(gen=G1, sec=G2), 'bits 4+5: Generator and SecondPt exchanged'),
        (50, dict(gen=G1, sec=None), 'bits 4+5+1: exchange, then SecondPt erased')):
    cr = locker(P256, (SET_GEN, G2), (SET_SECONDPT, G1), sc(7), hs(0), (SET_SIG, SIG0))
    cr.setst(READY, xs)
    check(label, None, dict(gen=cr.gen, scalar=b2v(cr.scalar),
                            **{f: getattr(cr, f) if f in cr.has else None for f in ('sec', 'hash', 'sig')}),
          {**BASE, **change})

check('bits 7 and above of Xs are reserved: Form B kl.setst into _Ready_ with Xs = 128 -> Invalid',
      invalid(locker(P256, sc(7)).setst, READY, 128))
cr = locker(P256, (SET_GEN, G2))
cr.setst(READY, 32)
check('bit 5 with HasSecondPt clear: no effect, Generator kept', None, (cr.gen, 'sec' in cr.has), (G2, False))
cr.setst(READY, 16)
check('bit 4 sets HasSecondPt, so the copy is serialized and used by _Point_Mul_', None,
      (cr.sec, 'sec' in cr.has), (G2, True))

res = [invalid(Locker(P256, sign=False, verify=False).setst, t) for t in (SET_HASH, SET_SIG)]
res += [Locker(P256, sign=sg, verify=vf).setst(SET_HASH) is None for sg, vf in ((True, False), (False, True))]
res += [invalid(Locker(P256, sign=True, verify=False).setst, SET_SIG), Locker(P256, sign=False, verify=True).setst(SET_SIG) is None]
check('_Set_Hash_ needs _MachinePolicy_ != 0 (either bit); _Sign_Input_ is gated by _MachinePolicy_[1] (MR9): '
      'sign-only -> Invalid, verify-only admitted', None, res, [True] * 6)

cr = locker(P256, hs(E0), (SET_SIG, SIG0)).restrictl_policy(True, True)
check('kl.restrictl clearing both _MachinePolicy_ bits erases Hash and Signature and clears their flags', None,
      (cr.hash, cr.sig, {'hash', 'sig'} & cr.has, cr.policy), (None, None, set(), (False, False)))
cr = locker(P256, hs(E0), (SET_SIG, SIG0)).restrictl_policy(True, False)
check('... clearing only _MachinePolicy_[0] keeps them', None, ({'hash', 'sig'} <= cr.has), True)
cr = locker(P256, hs(E0), (SET_SIG, SIG0)).restrictl_policy(False, True)
check('... clearing _MachinePolicy_[1] in _Sign_Input_ keeps the State; the next kl.exec there -> Invalid (GR25, MR9)',
      None, (cr.state, invalid(cr.exec_in, bytes(8))), (SET_SIG, True))
sg = locker(P256, sc(7), hs(E0), to=SIGN_GEN).restrictl_policy(True, False)
check('... a set bit of a disabled function changes nothing; clearing _MachinePolicy_[0] in _Sign_Generate_ keeps the '
      'State, and the next kl.exec there -> _Invalid_ (GR25)', None,
      [Locker(P256, sign=False).restrictl_policy(True, False).policy, sg.state, invalid(sg.exec_run, [99])],
      [(False, True), SIGN_GEN, True])

cr = locker(P256, sc(7), hs(E0), to=SIGN_GEN)
cr.exec_run([99])
cr.restrictl_policy(True, True)
c2 = locker(P256, sc(7), hs(E0), to=SIGN_GEN)
c2.exec_run([99])
c2.restrictl_policy(False, True)
check('clearing both _MachinePolicy_ bits in _Output_ with OutputType = signature keeps the State; the next kl.exec '
      'there -> _Invalid_ (GR25); clearing only bit 1 there lets the signature be emitted', None,
      (cr.state, invalid(cr.exec_out, 64), c2.exec_out(64) is not None, c2.state), (OUTPUT, True, True, SUCCESS))

cr = locker(P256, sc(7), to=SET_HASH).restrictl_policy(True, True)
c2 = locker(P256, sc(7), to=SET_HASH).restrictl_policy(True, True)
check('clearing both _MachinePolicy_ bits in _Set_Hash_ keeps the State; the next kl.exec there -> _Invalid_ (gated '
      'by either bit, MR9); a kl.setst into _Set_Scalar_, which leads to _Point_Mul_, is admitted', None,
      (cr.state, invalid(cr.exec_in, bytes(32)), c2.setst(SET_SCALAR), c2.state), (SET_HASH, True, None, SET_SCALAR))
cr = armed()
cr.halt(1, k=99)
held = (cr.rnd is not None, 'rnd' in cr.has)
cr.restrictl_policy(True, False)
check('halted _Sign_Generate_: kl.restrictl clearing only _MachinePolicy_[0] destroys RndNum and clears HasRndNum '
      '(<<KLE-ECC>>); the State is kept and the next kl.exec -> _Invalid_', None,
      (held, cr.rnd, 'rnd' in cr.has, cr.state, invalid(cr.exec_run, [99])),
      ((True, True), None, False, SIGN_GEN, True))
cr = locker(P256, hs(E0), (SET_SIG, SIG0)).restrictl_policy(False, True)
c2 = locker(P256, hs(E0), (SET_SIG, SIG0)).restrictl_policy(False, True)
check('_Sign_Input_ with _MachinePolicy_[1] cleared: a kl.setst into _Set_Scalar_ (leads to _Point_Mul_) or '
      '_Set_Hash_ (leads to _Sign_Generate_) is admitted (MR9 item 1.a); into _Sign_Verify_ -> _Invalid_ (item 1.b)',
      None, (cr.setst(SET_SCALAR), cr.state, c2.setst(SET_HASH), c2.state,
             invalid(locker(P256, sc(7), hs(E0), (SET_SECONDPT, pt(P256, P256.G)), (SET_SIG, SIG0))
                     .restrictl_policy(False, True).setst, SIGN_VER)),
      (None, SET_SCALAR, None, SET_HASH, True))

section('Signing and verification over a custom `Generator`')
G2 = pt(P256, P256.mul_g(2))
cr = locker(P256, (SET_GEN, G2), (SET_SCALAR, D256), hs(E0), to=SIGN_GEN)
r2, s2, _ = cr.exec_run([K0])
check('_Sign_Generate_ uses `Generator`: r = x(k * 2G) mod n', r2 == P256.mul_g(2 * K0 % P256.n)[0] % P256.n)
sig2 = v2b(r2, 32) + v2b(s2, 32)
Q2 = pt(P256, P256.mul_g(2 * b2v(D256) % P256.n))
v_ok = locker(P256, (SET_GEN, G2), (SET_SECONDPT, Q2), hs(E0), (SET_SIG, sig2), to=SIGN_VER)
v_ok.exec_run()
check('... verifies over the same `Generator` with Q = d * 2G (Success), not over the default one (Failure)', True,
      (v_ok.state, verify(P256, Q2, E0, sig2)), (SUCCESS, FAILURE))

section('Sign and verify within one CC')
d = 0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464
e = 0xa41a41a12a799548211c410c65d8133afde34d28bdd542e4b680cf2899c8a8c4
cr = locker(P256, sc(d), to=POINT_MUL)
cr.exec_run()
pub = cr.output_all(16)
cr.setst(READY)
check('Point_Mul -> Success -> Ready keeps SecondPt = d*G and Scalar',
      cr.sec == pub == pt(P256, P256.mul_g(d)) and 'sec' in cr.has and b2v(cr.scalar) == d)
load(cr, *hs(e))
cr.setst(SIGN_GEN)
cr.exec_run([K0])
sig = cr.output_all(16)
cr.setst(READY)
check('Sign_Generate -> Success -> Ready keeps Signature, Hash, SecondPt',
      {'sig', 'hash', 'sec'} <= cr.has and cr.sig == sig and cr.sec == pub)
cr.setst(SIGN_VER)
cr.exec_run()
check('the CC verifies its own signature -> Success', cr.state == SUCCESS)
cr.setst(READY, 64)
check('Xs bit 6 drops the signature: Sign_Verify -> Invalid', invalid(cr.setst, SIGN_VER))

section('Ed25519 / Ed25519ctx / Ed25519ph: RFC 8032 7.1, 7.2, 7.3')
c = EC.ED25519
p = locker(P256)
v0 = p.varlen()
p.setst(SET_HASH); p.exec_in(bytes(16))
check('Fields iv-vii depend only on MachinePolicy: a half-loaded Hash, HasHash clear, is serialized with its '
      'prefix and block_base; P-256 varlen = ub/8 + (vb + h)/8 + j/8 = 192 bytes', None,
      (v0, p.varlen(), 'hash' in p.serialized(), 'hash' in p.has, p.bb), (192, 192, True, False, 16))
check('varlen for MachinePolicy 0 (DH only), sign only, verify only: 64, 192, 160 bytes', None,
      [Locker(P256, sign=s, verify=v).varlen() for s, v in ((False, False), (True, False), (False, True))], [64, 192, 160])
check('b = 256: the seed is b bits', all(len(bytes.fromhex(v[1])) * 8 == PARAMS['ed25519'][0] for v in RFC8032_ED25519))
for name, seed, pk, msg, sig in RFC8032_ED25519:
    seed, pk, msg, sig = map(bytes.fromhex, (seed, pk, msg, sig))
    check(f'{name}: A from the seed; _Point_Mul_ on the seed gives A = s*B',
          locker(c, (SET_SCALAR, seed)).keys()[2] == pk == ed_point_mul(c, seed))
    got, p1, cr = ed_sign(c, seed, msg, chunk=16)
    check(f'{name}: pure-mode signature', None, got.hex(), sig.hex())
    check(f'{name}: msg_pass 1 after pass 1, 0 after Sign_Generate; Success',
          (p1, cr.msg_pass, cr.state) == (1, 0, SUCCESS))
    check(f'{name}: Sign_Verify -> Success', ed_verify(c, pk, sig, msg) == SUCCESS)
    check(f'{name}: corrupted R -> Failure', ed_verify(c, pk, bytes([sig[0] ^ 0x40]) + sig[1:], msg) == FAILURE)
name, seed, pk, msg, sig = RFC8032_ED25519PH
seed, pk, msg, sig = map(bytes.fromhex, (seed, pk, msg, sig))
ph = hashlib.sha512(msg).digest()
check('h = 512 holds the 64-byte PH(M)', PARAMS['ed25519'][1] // 8 == len(ph))
cr = locker(c, (SET_SCALAR, seed), (SET_HASH, ph, 32), to=SIGN_GEN)
cr.exec_run()
check(f'{name}: pre-hash signature over PH(M) in Hash', None, cr.output_all().hex(), sig.hex())
cr = locker(c, (SET_SECONDPT, pk), (SET_SIG, sig), (SET_HASH, ph), to=SIGN_VER)
cr.exec_run()
check(f'{name}: Sign_Verify (msg_pass = 0, HasHash) -> Success', cr.state == SUCCESS)
for name, seed, pk, msg, ctx, sig in RFC8032_ED25519CTX:
    seed, pk, msg, ctx, sig = map(bytes.fromhex, (seed, pk, msg, ctx, sig))
    check(f'{name} (Ed25519ctx, dom2(0, ctx)): pure-mode signature', None, ed_sign(c, seed, msg, ctx)[0].hex(), sig.hex())
    check(f'{name}: Sign_Verify -> Success', ed_verify(c, pk, sig, msg, ctx) == SUCCESS)
cr = locker(c, (SET_SCALAR, seed), (SET_HASH, ph))
check('pre-hash _Sign_Verify_ without HasSecondPt and HasSignature -> Invalid (entry conditions)', invalid(cr.setst, SIGN_VER))
seed, msg = bytes.fromhex(RFC8032_ED25519[2][1]), bytes.fromhex(RFC8032_ED25519[2][3])
cr = locker(c, (SET_SCALAR, seed))
cr.setst(MSG_ABSORB, 0)
cr.exec_in(msg)
for label, cr_, t, xs in (
        ('Msg_Absorb Xs = 0 without a seed', Locker(c), MSG_ABSORB, 0),
        ('Msg_Absorb Xs = 1 with msg_pass != 1', locker(c, (SET_SCALAR, seed)), MSG_ABSORB, 1),
        ('Msg_Absorb Xs = 3', locker(c, (SET_SCALAR, seed)), MSG_ABSORB, 3),
        ('Sign_Generate after one pass', cr, SIGN_GEN, 0)):
    check(f'{label} -> Invalid', invalid(cr_.setst, t, xs))
check('different messages in the two signing passes -> Invalid at pass 2',
      invalid(ed_sign, c, seed, msg, msg2=msg + b'\0'))
check('_Point_Mul_ without a configured seed (Scalar zero) -> Invalid', invalid(ed_point_mul, c, bytes(c.nbytes)))
_, p1, cr = ed_sign(c, seed, msg)
check('identical messages in both passes sign', (p1, cr.state, 'sig' in cr.has) == (1, SUCCESS, True))
check('HasRndNum never set on the EdDSA path, j = 0', 'rnd' not in cr.has and PARAMS['ed25519'][2] == 0)
_, seed1, pk1, msg1, sig1 = (x if i == 0 else bytes.fromhex(x) for i, x in enumerate(RFC8032_ED25519[0]))
B2 = c.encode(c.mul(2, c.B))
check('EdDSA signs and verifies over B whatever `Generator` holds (here 2B): the RFC 8032 signature, verified',
      None, (ed_sign(c, seed1, msg1, gen=B2)[0].hex(), ed_verify(c, pk1, sig1, msg1, gen=B2)), (sig1.hex(), SUCCESS))
cr = locker(c, (SET_CTX, b'abcd', None, 10), to=READY)
check('ctx load left incomplete (4 of 10 bytes): ctx and ctxlen zeroed (MR7)', (cr.ctx, cr.size['ctx']) == (b'', 0))
check('_AuxInfo_ = 1 without pure mode, or a reserved bit of [15:3] (8): kl_exc_unsupported at provisioning; '
      'bits [2:1] of a PI (6) are ignored and zeroed', True,
      [raises(Locker, c, aux_info=1, pure_impl=False, exc=Unsupported), raises(Locker, c, aux_info=8, exc=Unsupported),
       Locker(c, aux_info=7).aux()], [True, True, 1])
ph2, sigs = hashlib.sha512(msg).digest(), []
for kw in ({}, dict(aux_info=0, pure_impl=False)):
    cr = locker(c, (SET_SCALAR, seed), (SET_HASH, ph2, 32), to=SIGN_GEN, **kw)
    cr.exec_run()
    sigs.append(cr.output_all())
cr = locker(c, (SET_SCALAR, seed), aux_info=0, pure_impl=False)
check('_AuxInfo_ = 0 (pre-hash only), also without pure mode in the implementation: provisioned, '
      'the same pre-hash signature; _Msg_Absorb_ -> Invalid', sigs[0] == sigs[1] and invalid(cr.setst, MSG_ABSORB, 0))

section('Ed448 / Ed448ph: RFC 8032 7.4, 7.5 (dom4, ctx, 57-byte encodings)')
c = EC.ED448
check('b = 456: seed, point and signature halves are 57 bytes',
      PARAMS['ed448'][0] // 8 == c.nbytes == 57 == len(bytes.fromhex(RFC8032_ED448[0][1])))
for name, seed, pk, msg, ctx, sig in RFC8032_ED448:
    seed, pk, msg, ctx, sig = map(bytes.fromhex, (seed, pk, msg, ctx, sig))
    check(f'{name}: A from the seed; _Point_Mul_ on the seed gives A = s*B',
          locker(c, (SET_SCALAR, seed, 19)).keys()[2] == pk == ed_point_mul(c, seed))
    check(f'{name}: pure-mode signature', None, ed_sign(c, seed, msg, ctx)[0].hex(), sig.hex())
    check(f'{name}: Sign_Verify -> Success', ed_verify(c, pk, sig, msg, ctx) == SUCCESS)
check('ctx-bound signature under the empty ctx -> Failure', ed_verify(c, pk, sig, msg) == FAILURE)
check('Set_Ctx with ctxlen > 255 -> Invalid', invalid(locker(c, (SET_SCALAR, seed)).setst, SET_CTX, 256))
for name, seed, pk, msg, ctx, sig in RFC8032_ED448PH:
    seed, pk, msg, ctx, sig = map(bytes.fromhex, (seed, pk, msg, ctx, sig))
    ph = hashlib.shake_256(msg).digest(64)
    cr = locker(c, (SET_SCALAR, seed, 19), (SET_CTX, ctx, None, len(ctx)), (SET_HASH, ph), to=SIGN_GEN)
    cr.exec_run()
    check(f'{name} (Ed448ph, dom4(1, ctx), PH = SHAKE256(M, 64)): pre-hash signature', None,
          cr.output_all().hex(), sig.hex())
    cr = locker(c, (SET_SECONDPT, pk), (SET_SIG, sig), (SET_CTX, ctx, None, len(ctx)), (SET_HASH, ph), to=SIGN_VER)
    cr.exec_run()
    check(f'{name}: pre-hash Sign_Verify -> Success', cr.state == SUCCESS)

c = EC.ED25519
seed = bytes.fromhex(RFC8032_ED25519[0][1])
res = []
for t, xs in ((MSG_ABSORB, 1), (READY, 0)):
    cr = locker(c, (SET_SCALAR, seed), (SET_SIG, bytes(range(64))))
    res.append('sig' in cr.has)
    cr.setst(MSG_ABSORB, 0)
    cr.exec_in(b'msg')
    cr.setst(t, xs)
    res.append('sig' in cr.has)
check('finalizing signing pass 1 clears a HasSignature set by an earlier load (Signature.R is an intermediate value); '
      'abandoning it for _Ready_ keeps it', None, res, [True, False, True, True])
cr = locker(c, (SET_SCALAR, seed), (SET_SIG, bytes(range(64))))
cr.setst(MSG_ABSORB, 0)
cr.exec_in(b'msg')
check('MR9: signing pass 1 -> _Msg_Absorb_ Xs = 2 with a loaded Signature -> Invalid '
      '(finalization clears HasSignature before the entry check)', invalid(cr.setst, MSG_ABSORB, 2))
cr = locker(c, (SET_SCALAR, seed))
cr.setst(MSG_ABSORB, 0)
cr.exec_in(b'msg')
cr.setst(MSG_ABSORB, 1)
cr.exec_in(b'ms')                                          # a partial, hence different, pass-2 message
cr.setst(READY)
check('signing pass 2 abandoned for _Ready_ with a different message: no binding check, Ready; msg_pass = 0, '
      'r and k\' cleared, HasHashState clear', None,
      (cr.state, cr.msg_pass, cr.r, cr.kp, 'hstate' in cr.has), (READY, 0, None, None, False))

_, seed, pk, msg, sig = (x if i == 0 else bytes.fromhex(x) for i, x in enumerate(RFC8032_ED25519[2]))
cr = locker(c, (SET_SCALAR, seed))
trace = [cr.aux() >> 1]
cr.setst(MSG_ABSORB, 0); cr.exec_in(msg); trace.append(cr.aux() >> 1)
cr.setst(MSG_ABSORB, 1); trace.append(cr.aux() >> 1)
hst = ['hstate' in cr.has, cr.eddsa_content1_extra_bits()]
cr.exec_in(msg[:1])
cr = copy.deepcopy(cr, {id(cr.c): cr.c})               # export/import mid-pass 2: H and H' travel in Content1
cr.exec_in(msg[1:])
cr.setst(SIGN_GEN); trace.append(cr.aux() >> 1)
hst += ['hstate' in cr.has, cr.eddsa_content1_extra_bits()]
cr.exec_run(); trace.append(cr.aux() >> 1)
check('AuxInfo[2:1] = msg_pass: 0 (pass 1 open), 1 (pass 2 open), 2 (pass 2 done), 0 after Sign_Generate; '
      'an export/import mid-pass 2 resumes the pass and yields the RFC 8032 7.1 signature', None,
      (trace, cr.output_all(c.nbytes).hex()), ([0, 0, 1, 2, 0], sig.hex()))
check("HasHashState (bit 3) set while a pass is open; Content1 carries H and H' (2 x 1664 bits for ed25519) whatever "
      'the flag, its length fixed by MachinePolicy', None, hst,
      [True, 8 + 2040 + 512 + 2 * 1664, False, 8 + 2040 + 512 + 2 * 1664])
e = locker(c, (SET_SCALAR, seed))
e.setst(MSG_ABSORB, 0); e.exec_in(msg); e.setst(MSG_ABSORB, 1)
check('between the signing passes Signature.R is an intermediate value, HasSignature clear, and is serialized',
      None, ('sig' in e.has, 'sig' in e.serialized(), e.sig is not None), (False, True, True))
cv = locker(c, (SET_SECONDPT, pk), (SET_SIG, sig))
cv.setst(MSG_ABSORB, 2); v_open = cv.aux() >> 1
cv.exec_in(msg); cv.setst(SIGN_VER); cv.exec_run()
check('verification pass: msg_pass 3 while open and once completed; Sign_Verify -> Success', None,
      (v_open, cv.aux() >> 1, cv.state), (3, 3, SUCCESS))
cv = locker(c, (SET_SECONDPT, pk), (SET_SIG, sig))
cv.setst(MSG_ABSORB, 2); cv.exec_in(msg); cv.setst(MSG_ABSORB, 2)
check("a verification pass re-entered with Xs = 2 after a completed one: k' <- 0 (<<KLE-EdDSA>>)", None,
      (cv.state, cv.aux() >> 1, cv.kp), (MSG_ABSORB, 3, None))

r1 = locker(EC.ED25519, (SET_SCALAR, seed)); r1.setst(MSG_ABSORB, 0)
r2 = locker(EC.ED25519, (SET_SCALAR, seed)); r2.setst(MSG_ABSORB, 0)
r1.restrictl_policy(True, False)
r2.restrictl_policy(False, True)
r2.exec_in(b'm')
check('EdDSA _Msg_Absorb_ in a signing pass: clearing _MachinePolicy_[0] keeps the State, and the next kl.exec of the '
      'pass -> Invalid (GR25); clearing [1] lets the pass continue', None,
      [r1.state, invalid(r1.exec_in, b'm'), r2.policy, r2.state], [MSG_ABSORB, True, (True, False), MSG_ABSORB])
r3 = locker(EC.ED25519, (SET_SCALAR, seed), (SET_CTX, b'', None, 0)); r3.setst(MSG_ABSORB, 0); r3.exec_in(b'm')
r3.restrictl_policy(True, False)
check('EdDSA signing pass 1 with _MachinePolicy_[0] cleared: the pass-2 kl.setst -> Invalid before pass 1 is '
      'finalized (MR9 item 1.a): no r, no R', None,
      (invalid(r3.setst, MSG_ABSORB, 1), r3.r, r3.msg_pass), (True, None, 0))
fa = [invalid(locker(EC.ED25519, (SET_SCALAR, seed)).setst, SET_CTX, 0, form='A'),
      invalid(locker(EC.ED25519, (SET_SCALAR, seed), (SET_CTX, b'', None, 0)).setst, MSG_ABSORB, 0, form='A')]
fb = locker(EC.ED25519, (SET_SCALAR, seed))
fb.setst(SET_CTX, 0, form='B'); fb.setst(MSG_ABSORB, 0, form='B')
check('EdDSA: a Form A kl.setst into _Set_Ctx_ or _Msg_Absorb_ -> Invalid (GR12); Form B admitted', None,
      fa + [fb.state], [True, True, MSG_ABSORB])
check('EdDSA: _MachinePolicy_ = 0 is invalid, at provisioning and as the result of kl.restrictl', None,
      [invalid(Locker, EC.ED25519, sign=False, verify=False),
       invalid(locker(EC.ED25519, (SET_SCALAR, seed)).restrictl_policy, True, True)], [True, True])
check('x25519 / x448: a kl.restrictl that requests a _MachinePolicy_ bit -> Invalid (<<KLE-instruction-restrict>>)',
      None, [invalid(Locker(c).restrictl_policy, cs, cv) for c in (EC.X25519, EC.X448)
             for cs, cv in ((True, False), (False, True))], [True] * 4)
ok_ed = locker(EC.ED25519, (SET_SCALAR, seed))
ok_ed.setst(MSG_ABSORB, 0)
bad_ed = copy.deepcopy(ok_ed, {id(ok_ed.c): ok_ed.c}); bad_ed.has.discard('hstate')
bad_ed2 = locker(EC.ED25519, (SET_SCALAR, seed)); bad_ed2.has.add('hstate')
bad_ec = locker(P256, sc(7)); bad_ec.has.add('rnd')
check('bit 3 of StateExtension in the wrong State is invalid Metadata at import: HasHashState outside _Msg_Absorb_ or '
      'clear in it (EdDSA), HasRndNum outside _Sign_Generate_ (ECC)', None,
      [ok_ed.state_se_supported(), bad_ed.state_se_supported(), bad_ed2.state_se_supported(), bad_ec.state_se_supported()],
      [True, False, False, False])

section('EdDSA: no Set state between the passes (R and Signature substitution)')
for c in (EC.ED25519, EC.ED448):
    seed, msg = bytes(range(c.nbytes)), b'attack at dawn'
    cr = locker(c, (SET_SCALAR, seed))
    cr.setst(MSG_ABSORB, 0)
    cr.exec_in(msg)
    res = [invalid(cr.setst, SET_SIG)]                        # would allow a chosen R with the same r: s leaks
    for t in (SET_SECONDPT, SET_SCALAR, SET_CTX, SET_HASH, POINT_MUL):
        cr = locker(c, (SET_SCALAR, seed))
        cr.setst(MSG_ABSORB, 0)
        cr.exec_in(msg)
        res.append(invalid(cr.setst, t))
    pk = locker(c, (SET_SCALAR, seed)).keys()[2]
    cv = locker(c, (SET_SECONDPT, pk), (SET_SIG, ed_sign(c, seed, b'other')[0]))
    cv.setst(MSG_ABSORB, 2)
    cv.exec_in(msg)
    res.append(invalid(cv.setst, SET_SIG))                    # would allow a forgery against the computed k'
    check(f'{c.name}: leaving _Msg_Absorb_ for a Set state or _Point_Mul_ (signing pass 1, verification pass) -> Invalid',
          None, res, [True] * 7)

section('SM2: GM/T 0003.5 Appendix A')
c, v = EC.SM2C, SM2_VEC
check('Point_Mul d*G = (Px, Py)', locker(c, sc(v['d']), to=POINT_MUL).exec_run() == (v['Px'], v['Py']))
try:
    be = b''.join(x.to_bytes(32, 'big') for x in (c.a, c.b, *c.G, v['Px'], v['Py']))
    za = hashlib.new('sm3', (len(v['ida']) * 8).to_bytes(2, 'big') + v['ida'] + be).digest()
    check('Z_A = SM3(ENTL || ID || a || b || G || P)', int.from_bytes(za, 'big') == v['ZA'])
    check('e = SM3(Z_A || M)', int.from_bytes(hashlib.new('sm3', za + v['msg']).digest(), 'big') == v['e'])
except ValueError:
    info('hashlib lacks SM3: Z_A and e taken from the example.')
pub = pt(c, (v['Px'], v['Py']))
rs, sig, _, _ = sign(c, v['d'], v['e'], [v['k']])
check('Sign_Generate (r, s)', None, (rs, sig), ((v['r'], v['s']), v2b(v['r'], 32) + v2b(v['s'], 32)))
check('Sign_Verify -> Success', verify(c, pub, v['e'], sig) == SUCCESS)
check('corrupted s -> Failure', verify(c, pub, v['e'], sig[:35] + bytes([sig[35] ^ 0x10]) + sig[36:]) == FAILURE)
check('t = (r + s) mod n = 0 -> Failure', verify(c, pub, v['e'], v2b(v['r'], 32) + v2b(c.n - v['r'], 32)) == FAILURE)

section('Brainpool: RFC 5639 parameters, k-injected sign / verify')
for name in ('brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'):
    c, fw = EC.WEIERSTRASS_CURVES[name], PARAMS[name][0] // 8
    d = (0x0123456789ABCDEF % (c.n - 1) + 1) * 0x9E3779B97F4A7C15 % (c.n - 1) + 1
    k = (d * 7 + 12345) % (c.n - 1) + 1
    cr = locker(c, sc(d, fw), to=POINT_MUL)
    Q, pub = cr.exec_run(), cr.output_all()
    check(f'{name}: Point_Mul d*G on curve, order n', c.is_on_curve(Q) and c.mul(c.n, Q) is None)
    e = ecdsa_e(c, hashlib.sha512(name.encode()).digest())
    (r, s), sig, _, _ = sign(c, d, e, [k])
    check(f'{name}: Sign_Generate meets the FIPS 186-5 equations',
          r == c.mul_g(k)[0] % c.n and s == pow(k, -1, c.n) * (e + r * d) % c.n)
    check(f'{name}: sign -> verify -> Success', verify(c, pub, e, sig) == SUCCESS)
    check(f'{name}: modified hash -> Failure', verify(c, pub, e ^ 1, sig) == FAILURE)
info('Brainpool is anchored on published parameters only: RFC 5639 / 8734 give no ECDSA vectors.')

class Dest:
    """A non-ECC destination: a `key` in _Ready_, an HMAC `K0` of `size` = b/8 bytes in _Set_Key_ ('k0'), a hash in
    _Hash_Absorb_ (byte-granular, <<KLE-hash-functions-MACs-XOFs>>), or 'none' (no destination endpoint, e.g.
    ML-DSA)."""
    def __init__(self, kind, state=None, size=32, **mdh):
        self.kind, self.size, self.data, self.mdh = kind, size, b'', {**MDH0, **mdh}
        self.state = state or {'hash': HASH_ABSORB, 'k0': SET_KEY}.get(kind, READY)

class HashSrc:
    """A hash in _Hash_Output_ whose kl.exec output is `out`: no kl.derive source (<<KLE-derive-endpoints>>)."""
    def __init__(self, out):
        self.out = out

def kl_derive(dest, src, length):
    """The only ECC endpoint (<<KLE-derive-endpoints>>): the shared secret in _Output_ with OutputType = shared
    secret, which kl.exec also exports, hence unrestricted (GR41). No point, signature or hash output is a source;
    no ECC field is a destination."""
    if isinstance(src, HashSrc) or src.state != OUTPUT or src.out_type != OUT_SHARED:
        raise Invalid(who='source')                                 # GR39 item 1: source first
    if isinstance(dest, Locker) or dest.kind == 'none' \
            or dest.state != {'key': READY, 'k0': SET_KEY}.get(dest.kind, HASH_ABSORB) \
            or dest.kind != 'hash' and dest.mdh['KeyType'] == 1:
        raise Invalid(who='destination')                            # GR39 item 2; GR74
    sh = src.shared()                                               # GR39 item 3: every destination is admitted
    if dest.kind == 'hash':                                         # the whole secret, exactly (GR39 item 5)
        ok = length == len(sh)
    elif dest.kind == 'k0':                                         # exactly eff_length bytes, which replace K0
        ok = min(length, dest.size) == len(sh)
    else:
        ok = length >= dest.size and len(sh) >= dest.size
    if not ok:
        raise Invalid(who='destination')                            # GR39 item 5
    # unrestricted (GR41): no narrowing, no SCProtection check (GR40); the source does not advance (GR38)
    if dest.kind == 'hash':
        dest.data += sh                                            # GR41: the whole secret (GR39 item 5)
    else:
        dest.data = sh[:dest.size].ljust(dest.size, b'\0')          # GR38: eff_length bytes, zero-filled beyond

def mdh(cr, **f):
    cr.mdh.update(f)
    return cr

def ecdh(**f):
    cr = mdh(locker(P256, (SET_SCALAR, D256), (SET_SECONDPT, pt(P256, P256.mul_g(db))), to=POINT_MUL), **f)
    return cr, cr.exec_run()

def scalar_dest(state=SET_SCALAR, **f): return mdh(locker(P256, to=state), **f)

def signing(**f):
    cr = mdh(armed(), **f)
    cr.exec_run([K0])
    return cr

def with_second(sign=False):            # HasSecondPt in _Set_SecondPt_, or in _Output_ after signing
    cr = locker(P256, (SET_SCALAR, D256), hs(E0), (SET_SECONDPT, pt(P256, P256.mul_g(db))))
    if sign:
        cr.setst(SIGN_GEN)
        cr.exec_run([K0])
    return cr

def derive_who(dest, src, length):
    try:
        kl_derive(dest, src, length)
    except Invalid as x:
        return x.who

section('kl.derive: ECC endpoints (<<KLE-derive-endpoints>>)')
db = 0x1D5A0B2C3E4F
cr, Z = ecdh()
check('ECDH: SecondPt = d_A * Q_B', Z == P256.mul(db, P256.mul_g(V256['x'])))
ZBE = Z[0].to_bytes(32, 'big')                  # SP 800-56A Rev. 3 5.7.1.2: Z = FE2OS(x), big-endian
h = Dest('hash')
kl_derive(h, cr, 32)
check('ECDH _Output_ (OutputType = shared secret): Z (big-endian X, 32 B) into SHA-256 _Hash_Absorb_ with length 32, '
      'source not advanced (GR38); a second kl.derive is admitted', None,
      (h.data, cr.state, cr.bb, cr.out_type, derive_who(Dest('hash'), cr, 32)),
      (ZBE, OUTPUT, 0, OUT_SHARED, None))
res = []
for n in (0, 16, 31, 33, 36, 64, 1 << 60):
    h = Dest('hash', UsagePolicy=5)
    res.append((derive_who(h, cr, n), h.data))
check('the 32-B shared secret into SHA-256 _Hash_Absorb_ with length 0, 16, 31, 33, 36, 64 or 2^60: destination '
      '_Invalid_, nothing absorbed, source unchanged (GR39 item 5)', None, (res, cr.state, cr.bb), ([('destination', b'')] * 7, OUTPUT, 0))
check('kl.exec emits the shared secret Z (32 B, big-endian X), then _Success_', None, (cr.output_all(), cr.state),
      (ZBE, SUCCESS))
check('_Success_ is no kl.derive source (GR39 item 1): source _Invalid_', None, derive_who(Dest('hash'), cr, 32), 'source')
cr = ecdh()[0]
cr.exec_out(16)
check('same-State kl.setst in _Output_ part-way -> Invalid: no re-emission (GR20, GR23)', invalid(cr.setst, OUTPUT))
check('same-State kl.setst in _Output_ before any kl.exec -> Invalid (GR20, GR23)', invalid(ecdh()[0].setst, OUTPUT))
pk = locker(P256, sc(2), to=POINT_MUL)
pk.exec_run()
h = Dest('hash')
check('public-key _Output_ (OutputType = point): the point is no kl.derive source: source _Invalid_ (GR39 item 1), '
      'nothing absorbed, nothing emitted', None, (derive_who(h, pk, 64), h.data, pk.out_type, pk.bb),
      ('source', b'', OUT_POINT, 0))
for name in ('secp384r1', 'secp521r1', 'brainpoolP256r1', 'brainpoolP512r1', 'SM2'):
    cs = EC.WEIERSTRASS_CURVES[name] if name != 'SM2' else EC.SM2C
    fw = PARAMS[cs.name][0] // 8
    dhl = locker(cs, (SET_SCALAR, v2b(3, fw)), (SET_SECONDPT, pt(cs, cs.mul(5, cs.G))), to=POINT_MUL)
    dhl.exec_run()
    x, y = cs.mul(15, cs.G)                     # 3 * (5 G), computed independently of the locker
    m = (cs.p.bit_length() + 7) // 8
    want = x.to_bytes(m, 'big') if cs is not EC.SM2C else x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    check(f'{name} ECDH: the shared secret is ' + (f'Z = FE2OS(x), {m} B big-endian (SP 800-56A C.2)'
          if cs is not EC.SM2C else 'x2 || y2, 32 B each, big-endian (GM/T 0003.4)'),
          None, (dhl.out_type, dhl.output_all()), (OUT_SHARED, want))
dhl = locker(EC.P521, (SET_SCALAR, v2b(3, 72)), (SET_SECONDPT, pt(EC.P521, EC.P521.mul(5, EC.P521.G))), to=POINT_MUL)
dhl.exec_run()
z521 = dhl.shared()
res = [(n, derive_who(h := Dest('hash'), dhl, n), h.data) for n in (65, 66, 67, 68, 72)]
check('secp521r1: the 66-B shared secret into a hash _Hash_Absorb_ (SHA-256 or SHA3-256, both byte-granular) admits '
      'only length 66, nothing appended; any other length: destination _Invalid_ (GR39 item 5)', None, res,
      [(65, 'destination', b''), (66, None, z521), (67, 'destination', b''), (68, 'destination', b''),
       (72, 'destination', b'')])
# NIST CAVP KAS ECC CDH primitive (SP 800-56A), P-256 COUNT = 0
QCAVS = (0x700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287,
         0xdb71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac)
dIUT = 0x7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534
dhl = locker(P256, (SET_SCALAR, v2b(dIUT, 32)), (SET_SECONDPT, pt(P256, QCAVS)), to=POINT_MUL)
dhl.exec_run()
check('CAVP ECC CDH P-256 COUNT = 0: the emitted shared secret equals ZIUT, byte for byte', None, dhl.output_all(),
      bytes.fromhex('46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b'))
cr, _ = ecdh(UsagePolicy=0b00010, ExpirationDate=700)
h = Dest('hash', UsagePolicy=0b10101, ExpirationDate=900)
kl_derive(h, cr, 32)
check('the shared secret into a hash is unrestricted (GR41): the hash locker is not narrowed', True,
      (h.mdh['UsagePolicy'], h.mdh['ExpirationDate'], h.data), (0b10101, 900, cr.shared()))
cr, _ = ecdh(UsagePolicy=0b10011, ExpirationDate=900, SCProtection=1)
k = Dest('key', UsagePolicy=0b10100, ExpirationDate=1200, SCProtection=2)
kl_derive(k, cr, 64)
check('SecondPt into an AES-256 `key` in _Ready_: first 32 bytes, MDH not narrowed (GR41)',
      (k.data, k.mdh['UsagePolicy'], k.mdh['ExpirationDate']) == (cr.shared(), 0b10100, 1200))
cr, k = ecdh(SCProtection=1)[0], Dest('key')
check('key with a lower SCProtection than the source: transferred: an unrestricted transfer is not '
      'compared (GR40, GR41)', derive_who(k, cr, 64) is None and k.data == cr.shared())
cr = ecdh(UsagePolicy=0b00011)[0]
res = []
for n in (32, 64, 16, 33):
    k0 = Dest('k0', size=64, UsagePolicy=0b00100)
    res.append((derive_who(k0, cr, n), k0.data, k0.mdh['UsagePolicy']))
check('the 32-B shared secret into an HMAC-SHA-256 `K0` (64 B) in _Set_Key_: length 32 admitted, K0 = Z zero-filled '
      'to 64 B, not narrowed (GR41); length 64, 16 or 33: eff_length is not the 32 B of the source, destination '
      '_Invalid_ (GR39 item 5)', None, res,
      [(None, ZBE + bytes(32), 0b00100)] + [('destination', b'', 0b00100)] * 3)
sm = locker(EC.SM2C, (SET_SCALAR, v2b(3, 32)), (SET_SECONDPT, pt(EC.SM2C, EC.SM2C.mul(5, EC.SM2C.G))), to=POINT_MUL)
sm.exec_run()
k0 = Dest('k0', size=64)
check('the 64-B SM2 shared secret into an HMAC-SHA-256 `K0` with length 64 (or more): exactly eff_length = 64 B, '
      'admitted (GR39 item 5)', None, (derive_who(k0, sm, 64), k0.data, derive_who(Dest('k0', size=64), sm, 100)),
      (None, sm.shared(), None))
cr = ecdh()[0]
d = scalar_dest(UsagePolicy=0b00100)
check('SecondPt into another ECC `Scalar` in _Set_Scalar_: the `Scalar` is no destination: destination _Invalid_ '
      '(GR39 item 2), Scalar not written, source unchanged', None, (derive_who(d, cr, 64), any(d.scalar), cr.state,
                                                                     cr.bb), ('destination', False, OUTPUT, 0))
res = []
for src in (signing(), with_second(True)):
    for dest in (scalar_dest(), Dest('key'), Dest('hash')):
        res.append((derive_who(dest, src, 64), src.bb, src.state))
check('signature output, with or without HasSecondPt, into an ECC `Scalar`, an AES-256 `key` or a hash: source '
      '_Invalid_ (GR39 item 1), checked first, nothing emitted', None, res, [('source', 0, OUTPUT)] * 6)
def kept_after_dh():                    # ECDH, then a Form A return to _Ready_ keeping SecondPt
    cr = ecdh()[0]
    cr.setst(READY)
    return cr
def failed_mul():                       # off-curve SecondPt: _Point_Mul_ -> _Failure_, HasSecondPt kept
    cr = locker(P256, sc(2), (SET_SECONDPT, off), to=POINT_MUL)
    cr.exec_run()
    return cr
for label, dest, src, n, who in (
        ('source without HasSecondPt', Dest('hash'), locker(P256, hs(0, 0)), 32, 'source'),
        ('source in _Failure_ with HasSecondPt (GR39 item 1)', Dest('hash'), failed_mul(), 32, 'source'),
        ('source in _Set_SecondPt_ with HasSecondPt (a loaded peer point)', Dest('key'), with_second(), 64, 'source'),
        ('source in _Ready_ keeping the ECDH result in SecondPt', Dest('hash'), kept_after_dh(), 32, 'source'),
        ('hash destination in _Ready_ (GR39 item 2)', Dest('hash', READY), ecdh()[0], 32, 'destination'),
        ('key destination outside _Ready_ (GR39 item 2)', Dest('key', HASH_ABSORB), ecdh()[0], 64, 'destination'),
        ('HMAC `K0` outside _Set_Key_ (GR39 item 2)', Dest('k0', READY, size=64), ecdh()[0], 32, 'destination'),
        ('key with length < key size (GR39 item 5)', Dest('key'), ecdh()[0], 16, 'destination'),
        ('key of KeyType 1 (GR74)', Dest('key', KeyType=1), ecdh()[0], 64, 'destination'),
        ('HMAC `K0` of KeyType 1 (GR74)', Dest('k0', size=64, KeyType=1), ecdh()[0], 32, 'destination'),
        ('ECC `Scalar` with length b/8 (GR39 item 2)', scalar_dest(), ecdh()[0], 32, 'destination'),
        ('ECC destination in _Ready_ (GR39 item 2)', scalar_dest(READY), ecdh()[0], 64, 'destination'),
        ('Machine without a destination endpoint (GR39 item 2)', Dest('none'), ecdh()[0], 64, 'destination')):
    check(f'{label} -> Invalid ({who}), nothing transferred',
          derive_who(dest, src, n) == who and not any(dest.scalar if isinstance(dest, Locker) else dest.data))
dg = hashlib.sha256(b'KLE kl.derive').digest()
d, k, d521 = scalar_dest(), Dest('key'), locker(EC.P521, to=SET_SCALAR)
check('a hash in _Hash_Output_ is no source: its SHA-256 output into an ECC `Scalar` or an AES-256 `key`: source '
      '_Invalid_ (GR39 item 1); the shared secret into a secp521r1 `Scalar`: destination _Invalid_ (GR39 item 2), '
      'so MR11 is never reached by a kl.derive', None,
      (derive_who(d, HashSrc(dg), 64), derive_who(k, HashSrc(dg), 40), derive_who(d521, ecdh()[0], 72),
       any(d.scalar), k.data, any(d521.scalar)), ('source', 'source', 'destination', False, b'', False))
info('the shared secret is a field source (GR38), unrestricted (GR41); a hash takes the whole secret, with a '
     'length equal to it (GR39 item 5); kl.derive is uninterruptible (GR45).')

section('X25519 and X448 (<<KLE-X25519-X448>>, RFC 7748)')
X25, X4 = EC.X25519, EC.X448
RFC7748 = {                                 # 5.2: (scalar, u, output) x 2; iterations 1, 1000; 6: a, A, b, B, K
    'x25519': dict(
        vec=(('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
              'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
              'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'),
             ('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
              'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
              '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957')),
        it=('422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079',
            '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51'),
        dh=('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
            '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
            '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
            'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
            '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')),
    'x448': dict(
        vec=(('3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b'
              '29259a4f1c600ad3',
              '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada1'
              '8aa7a7fb4ef8a086',
              'ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21'
              '766282f73dd96b6f'),
             ('203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b43712'
              '82dd2c8d5be3095f',
              '0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91c'
              'dfbde71ce8d157db',
              '884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c9'
              '54514e99da7c179d')),
        it=('3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b'
            '9bc2b3bca9cf4113',
            'aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353'
            'ef54faa26e219f38'),
        dh=('9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d'
            '9ac2d8c0a598726b',
            '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53'
            '177f80e532c41fa0',
            '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0'
            '366f10b65173992d',
            '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae'
            '07bdc1c67bf33609',
            '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a'
            '449a5037514a879d'))}

def xdh(c, k, u=None, chunk=None):
    """Scalar multiplication through the locker: (output, final State, locker); u = None: the Generator."""
    cr = locker(c, (SET_SCALAR, k, chunk), *(((SET_SECONDPT, u, chunk),) if u is not None else ()), to=POINT_MUL)
    cr.exec_run()
    return cr.output_all(16), cr.state, cr

for name, c in EC.MONTGOMERY_CURVES.items():
    v, n = RFC7748[name], c.nbytes
    b, h_, j_, u_, v_ = PARAMS[name]
    cr = Locker(c)
    check(f'{name}: b = {b}, u = 1, v = 0; fields are b/8 = {n} bytes; default Generator u = {c.G}; '
          '_MachinePolicy_ = 0', True,
          (u_, v_, n, cr.size['gen'], cr.size['sec'], cr.size['scalar'], b2v(cr.gen), cr.policy),
          (1, 0, b // 8, n, n, n, c.G, (False, False)))
    for i, (k, u, out) in enumerate(v['vec']):
        got, st, _ = xdh(c, bytes.fromhex(k), bytes.fromhex(u), chunk=16)
        check(f'{name}: RFC 7748 5.2 vector {i + 1} via _Set_Scalar_, _Set_SecondPt_, _Point_Mul_, _Output_', True,
              (got.hex(), st), (out, SUCCESS))
    k = u = v2b(c.G, n)
    for i in range(1000):
        k, u = c.x(k, u), k
        if i == 0:
            check(f'{name}: RFC 7748 5.2 iterated function, 1 iteration', True, k.hex(), v['it'][0])
    check(f'{name}: RFC 7748 5.2 iterated function, 1000 iterations', True, k.hex(), v['it'][1])
    a, A, b_, B, K = map(bytes.fromhex, v['dh'])
    pa, sa, ca = xdh(c, a)
    pb, sb, cb = xdh(c, b_)
    check(f'{name}: RFC 7748 6 public keys = Scalar * default Generator (HasSecondPt clear)', True, (pa, pb), (A, B))
    ca.setst(READY)                                         # Form A: Scalar kept
    load(ca, SET_SECONDPT, B)
    ca.setst(POINT_MUL)
    ca.exec_run()
    kb = xdh(c, b_, A)[0]
    check(f'{name}: RFC 7748 6 shared secret, both sides; the same Scalar serves both multiplications', True,
          (ca.sec, kb, ca.out_type, 'sec' in ca.has), (K, K, OUT_SHARED, True))
    key = Dest('key', size=32)
    kl_derive(key, ca, n)
    check(f'{name}: SecondPt (K) is an unrestricted kl.derive source in _Output_ (GR41): K not output', True,
          (key.data, ca.state), (K[:32], OUTPUT))
    check(f'{name}: a zero Scalar is not a configured private key: the kl.setst into _Point_Mul_ -> _Invalid_ (MR9)',
          invalid(locker, c, to=POINT_MUL))
    small = [0, 1, c.p - 1]                                 # order 2; order 4, on the curve or on its twist
    res = [xdh(c, a, v2b(u, n))[1:] for u in small]
    check(f'{name}: small-order u = 0, 1, p - 1: all-zero result -> _Failure_, SecondPt unchanged, no output',
          all(st == FAILURE and cr.sec == v2b(u, n) and cr.out_type == OUT_POINT for (st, cr), u in zip(res, small)))
    big = c.p + c.G                                         # non-canonical u, reduced modulo p
    check(f'{name}: non-canonical u = p + {c.G} accepted and reduced; no check on write or on read', True,
          xdh(c, a, v2b(big, n))[:2], (A, SUCCESS))
    check(f'{name}: _Sign_Generate_, _Sign_Verify_, _Set_Hash_, _Sign_Input_ (and the EdDSA States) are not '
          'defined: kl.setst -> _Invalid_ (GR21)',
          all(invalid(Locker(c).setst, t) for t in (SIGN_GEN, SIGN_VER, SET_HASH, SET_SIG, MSG_ABSORB, SET_CTX)))
    check(f'{name}: a non-zero _MachinePolicy_ is unsupported Metadata',
          all(raises(Locker, c, exc=Unsupported, **kw) for kw in (dict(sign=True), dict(verify=True))))
    cr = xdh(c, a)[2]
    cr.setst(READY, 0b1001000)                              # bits 3 and 6: no Hash, no Signature
    kept = (cr.sec, cr.scalar, 'sec' in cr.has)
    cr.setst(SET_GEN)
    cr.setst(READY, 0b110110)                               # exchange the points, then erase SecondPt and Scalar
    check(f'{name}: return to _Ready_: Xs bits 3 and 6 have no effect; bits 4, 5, 1, 2 as in <<KLE-ECC>>; '
          'bits 7+ -> _Invalid_', True,
          (kept, cr.gen, cr.sec, 'sec' in cr.has, any(cr.scalar), invalid(cr.setst, READY, 1 << 7)),
          ((A, a, True), A, None, False, False, True))
    cr, bad_se = xdh(c, a)[2], Locker(c)
    bad_se.has.add('hash')
    check(f'{name}: _StateExtension_: only HasSecondPt; varlen = b/8, HasSecondPt set or not; bits 1 to 3 '
          'unsupported', True, (cr.has, len(cr.sec), cr.varlen(), Locker(c).varlen(), cr.state_se_supported(),
                                bad_se.state_se_supported()), ({'sec'}, n, n, n, True, False))
check('x25519: bit 255 of the u-coordinate is ignored', True,
      xdh(X25, bytes.fromhex(RFC7748['x25519']['dh'][0]), v2b(9 | 1 << 255, 32))[0].hex(), RFC7748['x25519']['dh'][1])
XST = {READY, SET_GEN, SET_SCALAR, SET_SECONDPT, POINT_MUL, OUTPUT}
check('x25519 / x448: kl.setst reaches only _Ready_, the three _Set_ states and _Point_Mul_; _Output_, entered by '
      'the kl.exec of _Point_Mul_, is named by no kl.setst, not even a same-State one (GR20)', True,
      {t for s in XST | {SUCCESS, FAILURE} for t in targets(s, False, xdh=True)}, XST - {OUTPUT})

section('Negative controls')
k, u, out = map(bytes.fromhex, RFC7748['x25519']['vec'][0])
control('x25519 without clamping of the scalar differs from RFC 7748 5.2', X25.x(k, u, clamp=False) != out)
control('x25519 with a big-endian u-coordinate differs from RFC 7748 5.2', X25.x(k, u[::-1]) != out)
seed, pk, msg, sig = map(bytes.fromhex, RFC8032_ED25519[1][1:])
bad = ed_sign(EC.ED25519, seed, msg, be=True)[0]
control('ed25519 S encoded big-endian differs from RFC 8032 7.1 TEST 2', bad != sig)
control('ed25519 big-endian S rejected by Sign_Verify', ed_verify(EC.ED25519, pk, bad, msg) == FAILURE)
control('secp256r1 (s, r) swapped -> Failure', verify(P256, PUB256, E0, v2b(S0, 32) + v2b(R0, 32)) == FAILURE)

done()
