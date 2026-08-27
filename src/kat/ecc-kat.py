#!/usr/bin/env python3
"""Known-Answer Tests for the ACE elliptic-curve algorithms (<<ACE-ECC>>, <<ACE-EdDSA>>).

WHAT IS BEING TESTED.  This harness does not test an implementation; it tests the
*specification text* of `src/ace-ISA-algorithms.adoc`, sections `[[ACE-ECC]]` and
`[[ACE-EdDSA]]`.  A model of the ACE control register -- its fields, its
`block_base`-tracked "set"/"output" transfers, its state machine and its allowed
transitions -- is built strictly from that text, and standard vectors are then
pushed through the model exactly as a caller would drive a real ACE unit
(`ace.setst` / `ace.exec` / output transfers).  If the spec's prescription
disagreed with the standard, the model would produce the wrong answer and the
case would FAIL.

ANCHOR LEVELS, strongest first.  Each case prints its level.

  [KAT]   Published known-answer vector reproduced bit-exactly.
            * secp256r1, secp384r1, secp521r1 ECDSA -- RFC 6979 A.2.5/A.2.6/A.2.7
              (messages "sample" and "test"; the RFC's deterministic k is injected
              in place of the RBG draw, see NOTE ON k BELOW).  The RFC also
              publishes the public keys Ux,Uy, which anchor Point_Mul.
            * ed25519 -- RFC 8032 7.1 TEST 1/2/3; ed25519ph -- RFC 8032 7.3.
            * ed448 -- RFC 8032 7.4 (blank, 1 octet, 1 octet with context).
            * SM2 -- the worked example of GM/T 0003.5-2012 / GB/T 32918.5-2017
              Appendix A (message "message digest"), whose Z_A / e derivation is
              re-derived here with SM3 when the platform provides it.
  [PARAM] Published domain parameters validated (curve equation for G, n*G = O,
          cofactor), then k-injected sign -> verify round-trips.
            * brainpoolP256r1 / P384r1 / P512r1 (RFC 5639 3.4/3.6/3.7).  No
              ECDSA KAT vectors are published for these curves in the RFCs, so
              this is deliberately the weaker anchor.
  [MODEL] Properties of the specification itself: state-machine legality, entry
          conditions, field-retention (`Xs`) semantics, representation rules,
          retry rules.  Anchored on the spec text, not on an external vector.

NOTE ON k.  A real ACE unit draws the per-signature secret k from the RBG
(<<ACE-RBG>>) into `RndNum`; it is never supplied by software.  A signature over
a random k has no known answer, so -- as is standard practice for ECDSA KATs --
the model exposes the RBG as an injectable source and RFC 6979's deterministic k
is fed in.  This tests every part of the specified computation except the draw
itself.  The retry rules are additionally tested end-to-end by making the model's
first draw degenerate and checking that a *second* draw is taken and used.

SPEC BUG DEMONSTRATIONS.  Where the literal text is defective, this harness keeps
the literal behaviour visible in a labelled informational line rather than
silently patching it (see the SPEC-NOTE lines in the output).

Offline, stdlib only (hashlib is used for SHA-2/SHA-3/SHAKE, which the spec
delegates to the hash extensions).
"""

import os
import sys
import time
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import b2v, v2b                              # noqa: E402
import ecc_curves as EC                                  # noqa: E402


# ==================================================================== reporting

_FAILURES = []
_NEG_PENDING = set()
_NEG_FIRED = set()


def head(title):
    print()
    print(title)
    print('-' * len(title))


def chk(level, name, ok, detail=''):
    tag = 'PASS' if ok else 'FAIL'
    print(f'  {tag}  [{level:5}] {name}' + (f'   {detail}' if detail and not ok else ''))
    if not ok:
        _FAILURES.append(name)
    return ok


def note(text):
    print(f'  SPEC-NOTE     {text}')


def info(text):
    print(f'  info          {text}')


def declare_negative(label):
    """Announce a negative control to run-kats.py and to the reader."""
    _NEG_PENDING.add(label)
    print(f'KAT-EXPECT-FAIL: {label}')


def negative(label, must_fail, name):
    """A negative control: `must_fail` is True when the wrong thing was rejected."""
    if must_fail:
        _NEG_FIRED.add(label)
        print(f'  {label}  FAIL  {name} -- rejected as required (this FAIL is expected)')
    else:
        print(f'  PASS  [MODEL] {name} -- NOT rejected; negative control lost its power')
        _FAILURES.append(f'negative control {label} did not fire')


# ==================================================================== ACE model

# States of <<ACE-ECC>> ("States:" list) plus the two of <<ACE-EdDSA>>.
READY, SET_GEN, SET_SCALAR, POINT_MUL, SIGN_GEN = 1, 2, 3, 4, 5
SIGN_VER, SET_HASH, SET_SECONDPT, SET_SIG, OUTPUT = 6, 7, 8, 9, 10
MSG_ABSORB, SET_CTX = 11, 12
SUCCESS, FAILURE = 22, 23

SNAME = {READY: 'Ready', SET_GEN: 'Set_Generator', SET_SCALAR: 'Set_Scalar',
         POINT_MUL: 'Point_Mul', SIGN_GEN: 'Sign_Generate', SIGN_VER: 'Sign_Verify',
         SET_HASH: 'Set_Hash', SET_SECONDPT: 'Set_SecondPt', SET_SIG: 'Set_Signature',
         OUTPUT: 'Output', MSG_ABSORB: 'Msg_Absorb', SET_CTX: 'Set_Ctx',
         SUCCESS: 'Success', FAILURE: 'Failure'}


class ACEInvalid(Exception):
    """The CR transitioned to Error State _Invalid_."""


# -- the transition relation, transcribed from "Allowed State Transitions" ----

def transition_targets(state, eddsa, literal):
    """The set of states reachable from `state` by a single `ace.setst`.

    `literal=False` transcribes the bullet list of <<ACE-ECC>> as it now reads:
    the five _Set_ states are named collectively, any two of them may transition
    freely, and all of them are sources for _Point_Mul_/_Sign_Generate_/
    _Sign_Verify_.  <<ACE-EdDSA>> grants _Set_Ctx_ that same membership in words.

    `literal=True` reproduces the pre-fix bullet list, in which _Set_Signature_
    had no exit at all (review finding M10, since resolved).  It is kept so that
    test_sign_then_verify_one_cc()
    test_m10_dead_end() can demonstrate what the defect was and detect a
    regression.
    """
    free = {SET_GEN, SET_SCALAR, SET_HASH, SET_SECONDPT}
    if not literal:
        free = free | {SET_SIG}
    if eddsa:
        free = free | {SET_CTX}
    entry = {SET_GEN, SET_SCALAR, SET_HASH, SET_SECONDPT, SET_SIG}
    if eddsa:
        entry = entry | {SET_CTX}
    ops = {POINT_MUL, SIGN_GEN, SIGN_VER}
    if state == READY:
        t = entry | ops
    elif state in free:
        t = free | ops | {READY}
    elif state == MSG_ABSORB and eddsa:
        t = free | ops | {MSG_ABSORB, READY}
    elif state in (POINT_MUL, SIGN_GEN):
        t = {OUTPUT}
    elif state == OUTPUT:
        t = {SUCCESS}
    elif state == SIGN_VER:
        t = {SUCCESS, FAILURE}
    elif state in (SUCCESS, FAILURE):
        t = {READY}
    else:
        t = set()
    if eddsa and (state == READY or state in free):
        t = t | {MSG_ABSORB}
    return t


def retry_required(mode, r, s, k, n):
    """The retry rules of the "Random numbers and retry rules" bullet.

    FIPS 186-5 6.4.1 (NIST and Brainpool): retry if r = 0 or s = 0.
    GM/T 0003.2-2012 (SM2):                retry if r = 0, r + k = n, or s = 0.
    """
    if mode == 'sm2':
        return r == 0 or (r + k) % n == 0 or s == 0
    return r == 0 or s == 0


class CR:
    """A model of an ACE control register holding an elliptic-curve CC."""

    def __init__(self, curve, b, h, j, u, v, mode,
                 policy_sign=True, policy_verify=True, literal=False):
        self.c = curve
        self.b, self.h, self.j, self.u, self.v = b, h, j, u, v
        self.mode = mode                        # 'ecdsa' | 'sm2' | 'eddsa'
        self.policy_sign = policy_sign
        self.policy_verify = policy_verify
        self.literal = literal
        self.fw = b // 8                        # width of a b-bit field, bytes
        self.ptlen = u * self.fw
        self.siglen = v * self.fw
        self.hashlen = h // 8
        self.state = READY
        self.default_gen = self._enc_point(curve.G)
        self.provision()

    # -- provisioning ----------------------------------------------------
    def provision(self):
        self.gen = self.default_gen
        self.scalar = bytes(self.fw)            # "Scalar is set to zero"
        self.sec = None
        self.sig = None
        self.hash = None
        self.rnd = None
        self.has_sec = self.has_sig = self.has_hash = self.has_rnd = False
        self.out_type = False
        self.block_base = 0
        self.msg_pass = 0
        self.ctx = b''
        self._absorb = None
        self._pass_xs = None
        self._r = None
        self._kprime = None
        self._loading = None                    # (field name, target length)
        self.state = READY

    # -- ACE representation of field elements and points -----------------
    def _sentinel(self):
        return b'\xff' * self.fw

    def _enc_field(self, x):
        return v2b(x, self.fw)

    def _enc_point(self, P):
        if self.c.edwards:
            return self.c.encode(P) if P is not None else self._sentinel()
        if P is None:
            return self._sentinel() * 2
        return self._enc_field(P[0]) + self._enc_field(P[1])

    def _dec_point(self, data):
        """Decode; returns ('inf', None), ('pt', P) or ('bad', None)."""
        if self.c.edwards:
            if data == self._sentinel():
                return ('inf', None)
            P = self.c.decode(data)
            return ('pt', P) if P is not None else ('bad', None)
        if data == self._sentinel() * 2:
            return ('inf', None)
        x = b2v(data[:self.fw])
        y = b2v(data[self.fw:])
        if x >= self.c.p or y >= self.c.p:
            return ('bad', None)
        return ('pt', (x, y))

    def repr_ok(self, data):
        """The `b`-bit representation rule: for secp521r1 the 55 most significant
        bits of every b-bit field must be zero, the all-ones sentinel excepted."""
        if not self.c.msb_zero:
            return True
        for i in range(0, len(data), self.fw):
            f = data[i:i + self.fw]
            if f == self._sentinel():
                continue
            if b2v(f) >> (self.b - self.c.msb_zero):
                return False
        return True

    # -- state transitions ------------------------------------------------
    def setst(self, target, form='A', xs=0, rand_scalar=None):
        eddsa = self.mode == 'eddsa'
        if target not in transition_targets(self.state, eddsa, self.literal):
            raise ACEInvalid(f'{SNAME[self.state]} -> {SNAME.get(target, target)}'
                             ' is not an allowed transition (Generic Rule 2)')
        if self.state == MSG_ABSORB:
            self._finalize_pass()
        self.block_base = 0
        self._loading = None

        if target == SET_GEN:
            if form == 'A' or xs == 0:
                self.gen = self.default_gen              # default base point
            else:
                self._loading = ('gen', self.ptlen)
        elif target in (SET_SCALAR, SET_HASH, SET_SECONDPT, SET_SIG):
            fld = {SET_SCALAR: 'scalar', SET_HASH: 'hash',
                   SET_SECONDPT: 'sec', SET_SIG: 'sig'}[target]
            if fld == 'scalar':
                self.scalar = bytes(self.fw)
            else:
                setattr(self, fld, None)
                setattr(self, 'has_' + fld, False)
            if target == SET_SCALAR and form == 'B' and xs != 0:
                # random private key generated inside the CR, never disclosed
                if rand_scalar is None:
                    raise ACEInvalid('model needs an injected RBG value')
                self.scalar = self._enc_field(rand_scalar)
            else:
                ln = {'scalar': self.fw, 'hash': self.hashlen,
                      'sec': self.ptlen, 'sig': self.siglen}[fld]
                self._loading = (fld, ln)
        elif target == SET_CTX:
            if xs > 255:
                raise ACEInvalid('ctxlen > 255')
            self.ctx = b''
            self._loading = ('ctx', xs) if xs else None
        elif target == MSG_ABSORB:
            self._enter_msg_absorb(xs)
        elif target == POINT_MUL:
            pass                                          # checks are in exec
        elif target == SIGN_GEN:
            self._check_sign_entry()
        elif target == SIGN_VER:
            self._check_verify_entry()
        elif target == READY:
            self._return_to_ready(form, xs)
        self.state = target

    def _check_sign_entry(self):
        if not self.policy_sign:
            raise ACEInvalid('signature generation not permitted by AlgorithmPolicy')
        if self.mode == 'eddsa':
            if int.from_bytes(self.scalar, 'little') == 0:
                raise ACEInvalid('no seed configured')
            if self.msg_pass == 2:
                return                                    # pure mode
            if self.msg_pass == 0 and self.has_hash:
                return                                    # pre-hash mode
            raise ACEInvalid('Sign_Generate entered with msg_pass='
                             f'{self.msg_pass}, HasHash={self.has_hash}')
        if not self.has_hash:
            raise ACEInvalid('Sign_Generate requires HasHash')
        d = b2v(self.scalar)
        if not (1 <= d < self.c.n):
            raise ACEInvalid('Scalar does not hold a configured private key')

    def _check_verify_entry(self):
        if not self.policy_verify:
            raise ACEInvalid('verification not permitted by AlgorithmPolicy')
        if self.mode == 'eddsa':
            if self.msg_pass == 3:                        # verification pass complete
                return
            if self.msg_pass == 0 and self.has_hash:      # pre-hash
                return
            raise ACEInvalid('Sign_Verify entered with msg_pass='
                             f'{self.msg_pass}, HasHash={self.has_hash}')
        if not (self.has_sec and self.has_hash and self.has_sig):
            raise ACEInvalid('Sign_Verify requires HasSecondPt, HasHash, HasSignature')

    def _return_to_ready(self, form, xs):
        """The `Xs` field bits of the "Upon returning to State _Ready_" bullet.
        Uniform polarity: a set bit discards the field it names, a clear bit
        retains it. Bit 0 Generator, Bit 1 SecondPt, Bit 2 Scalar, Bit 3 Hash,
        Bit 4/5 the copies, Bit 6 Signature. Form A sets no bit, so it retains
        everything."""
        if form == 'B':
            if xs & (1 << 4):                             # Generator -> SecondPt
                self.sec = self.gen
                self.has_sec = True
            if xs & (1 << 5):                             # SecondPt -> Generator
                if self.sec is not None:
                    self.gen = self.sec
            if xs & 1:
                self.gen = self.default_gen
            if xs & 2:
                self.sec = None
                self.has_sec = False
            if xs & 4:
                self.scalar = bytes(self.fw)
            if xs & 8:
                self.hash = None
                self.has_hash = False
            if xs & (1 << 6):
                self.sig = None
                self.has_sig = False
        self.msg_pass = 0
        self.ctx = b''
        self._r = self._kprime = None

    # -- Form B ace.exec: block-tracked loading ---------------------------
    def exec_in(self, data):
        if self.state == MSG_ABSORB:
            self._absorb += data
            return
        if self._loading is None:
            raise ACEInvalid(f'no ace.exec expected in state {SNAME[self.state]}')
        fld, ln = self._loading
        if self.block_base >= ln:
            raise ACEInvalid('block_base already complete; no further ace.exec')
        take = data[:ln - self.block_base]                # excess data ignored
        # `scalar` is zero-filled rather than absent when a Set_ state is entered,
        # so it is rebuilt from the bytes accepted so far rather than appended to.
        base = self.scalar[:self.block_base] if fld == 'scalar' else (
            getattr(self, fld) or b'')
        setattr(self, fld, base + take)
        self.block_base += len(data)
        if self.block_base >= ln:
            self.block_base = ln
            val = getattr(self, fld)
            if fld in ('scalar', 'hash', 'sec', 'sig', 'gen') and not self.repr_ok(val):
                raise ACEInvalid(f'{fld} violates the {self.b}-bit representation rule')
            if fld in ('sec', 'sig', 'hash'):
                setattr(self, 'has_' + fld, True)

    # -- Form D ace.exec: the operation of the current state --------------
    def exec_run(self, rbg=None, degenerate_hook=None):
        if self.state == POINT_MUL:
            return self._point_mul()
        if self.state == SIGN_GEN:
            return self._sign(rbg, degenerate_hook)
        if self.state == SIGN_VER:
            return self._verify()
        raise ACEInvalid(f'Form D ace.exec not expected in {SNAME[self.state]}')

    def _point_mul(self):
        k = b2v(self.scalar)
        if not (1 <= k < self.c.n):
            raise ACEInvalid('Point_Mul requires 1 <= int(Scalar) < n')
        src = self.sec if self.has_sec else self.gen
        kind, P = self._dec_point(src)
        if kind == 'bad':
            raise ACEInvalid('base point is not a valid encoding')
        if kind == 'pt' and not self.c.in_subgroup(P):
            raise ACEInvalid('base point is not on the curve / not in the subgroup')
        R = self.c.mul(k, P) if kind == 'pt' else None
        self.sec = self._enc_point(R)
        self.has_sec = True
        self.out_type = False
        self.block_base = 0
        self.state = OUTPUT
        return R

    def _sign(self, rbg, degenerate_hook):
        if self.mode == 'eddsa':
            return self._eddsa_sign()
        n, c = self.c.n, self.c
        d = b2v(self.scalar)
        e = b2v(self.hash)
        it = iter(rbg)
        attempt = 0
        while True:
            k = next(it)
            self.rnd = v2b(k, self.j // 8)
            self.has_rnd = True
            if self.mode == 'sm2':
                x1 = c.mul_g(k)[0]
                r = (e + x1) % n
                s = (pow(1 + d, -1, n) * (k - r * d)) % n
            else:
                x1 = c.mul_g(k)[0]
                r = x1 % n
                s = (pow(k, -1, n) * (e + r * d)) % n
            forced = bool(degenerate_hook and degenerate_hook(attempt))
            if forced or retry_required(self.mode, r, s, k, n):
                attempt += 1
                continue
            break
        self.sig = self._enc_field(r) + self._enc_field(s)
        self.has_sig = True
        self.rnd = None
        self.has_rnd = False
        self.out_type = True
        self.block_base = 0
        self.state = OUTPUT
        return r, s, attempt

    def _verify(self):
        if self.mode == 'eddsa':
            ok = self._eddsa_verify()
        else:
            ok = self._weierstrass_verify()
        self.state = SUCCESS if ok else FAILURE
        return ok

    def _weierstrass_verify(self):
        c, n = self.c, self.c.n
        r = b2v(self.sig[:self.fw])
        s = b2v(self.sig[self.fw:])
        if not (1 <= r < n and 1 <= s < n):
            return False
        kind, Q = self._dec_point(self.sec)
        if kind != 'pt' or not c.in_subgroup(Q):
            return False
        e = b2v(self.hash)
        if self.mode == 'sm2':
            t = (r + s) % n
            if t == 0:
                return False
            X = c.add(c.mul_g(s), c.mul(t, Q))
            if X is None:
                return False
            return (e + X[0]) % n == r
        w = pow(s, -1, n)
        X = c.add(c.mul_g(e * w % n), c.mul(r * w % n, Q))
        if X is None:
            return False
        return X[0] % n == r

    # -- Form C ace.exec: block-tracked output ----------------------------
    def exec_out(self, nbytes):
        if self.state != OUTPUT:
            raise ACEInvalid('output transfer outside State Output')
        buf = self.sig if self.out_type else self.sec
        total = self.siglen if self.out_type else self.ptlen
        chunk = buf[self.block_base:self.block_base + nbytes]
        chunk = chunk + bytes(nbytes - len(chunk))        # zero-filled tail
        self.block_base = min(self.block_base + nbytes, total)
        if self.block_base >= total:
            self.state = SUCCESS
        return chunk

    def output_all(self, chunk=None):
        total = self.siglen if self.out_type else self.ptlen
        chunk = chunk or total
        out = b''
        while self.state == OUTPUT:
            out += self.exec_out(chunk)
        return out[:total]

    # ================================================ EdDSA-specific model
    def _H(self, data):
        if self.c is EC.ED25519:
            return hashlib.sha512(data).digest()
        return hashlib.shake_256(data).digest(114)

    def _dom(self, x):
        if self.c is EC.ED25519:
            if x == 0 and not self.ctx:
                return b''                                # pure Ed25519, empty ctx
            return b'SigEd25519 no Ed25519 collisions' + bytes([x, len(self.ctx)]) + self.ctx
        return b'SigEd448' + bytes([x, len(self.ctx)]) + self.ctx

    def _keys(self):
        """(clamped scalar s, prefix, encoded public key A) from the seed."""
        hh = self._H(self.scalar)
        half = self.fw
        a = bytearray(hh[:half])
        if self.c is EC.ED25519:
            a[0] &= 248
            a[31] &= 127
            a[31] |= 64
        else:
            a[0] &= 252
            a[55] |= 128
            a[56] = 0
        s = int.from_bytes(bytes(a), 'little')
        prefix = hh[half:2 * half]
        A = self.c.encode(self.c.mul_g(s))
        return s, prefix, A

    def _enter_msg_absorb(self, xs):
        if xs == 0:
            if not self.policy_sign:
                raise ACEInvalid('signing pass 1 without signature-generation policy')
            if int.from_bytes(self.scalar, 'little') == 0:
                raise ACEInvalid('signing pass 1 without a configured seed')
            self.msg_pass = 0
            _, prefix, _ = self._keys()
            self._absorb = self._dom(0) + prefix
        elif xs == 1:
            if self.msg_pass != 1:
                raise ACEInvalid('signing pass 2 requires msg_pass = 1')
            _, _, A = self._keys()
            self._absorb = self._dom(0) + self.sig[:self.fw] + A
        elif xs == 2:
            if not self.policy_verify:
                raise ACEInvalid('verification pass without verification policy')
            if not (self.has_sig and self.has_sec):
                raise ACEInvalid('verification pass requires HasSignature and HasSecondPt')
            self.msg_pass = 0
            self._absorb = self._dom(0) + self.sig[:self.fw] + self.sec
        else:
            raise ACEInvalid(f'Msg_Absorb with Xs = {xs}')
        self._pass_xs = xs

    def _finalize_pass(self):
        digest = self._H(self._absorb)
        val = int.from_bytes(digest, 'little') % self.c.L
        if self._pass_xs == 0:
            self._r = val
            R = self.c.encode(self.c.mul_g(val))
            self.sig = R + bytes(self.fw)                 # R only; HasSignature NOT set
            self.msg_pass = 1
        elif self._pass_xs == 1:
            self._kprime = val
            self.msg_pass = 2
        else:                                             # pass Xs = 2: verification
            self._kprime = val
            # 3, not 1: signing pass 1 also records a completed pass, and were both
            # to use 1 a caller could run signing pass 1 and then enter _Sign_Verify_,
            # which would verify against a k' that was never computed (<<ACE-EdDSA>>).
            self.msg_pass = 3
        self._absorb = None
        self._pass_xs = None

    def _eddsa_sign(self, be_scalar=False):
        s, prefix, A = self._keys()
        L = self.c.L
        if self.msg_pass == 2:                            # pure
            r, kp = self._r, self._kprime
            R = self.sig[:self.fw]
        else:                                             # pre-hash
            m = self.hash
            r = int.from_bytes(self._H(self._dom(1) + prefix + m), 'little') % L
            R = self.c.encode(self.c.mul_g(r))
            kp = int.from_bytes(self._H(self._dom(1) + R + A + m), 'little') % L
        S = (r + kp * s) % L
        enc = S.to_bytes(self.fw, 'big' if be_scalar else 'little')
        self.sig = R + enc
        self.has_sig = True
        self._r = self._kprime = None
        self.msg_pass = 0
        self.out_type = True
        self.block_base = 0
        self.state = OUTPUT
        return self.sig

    def _eddsa_verify(self):
        c = self.c
        R_enc = self.sig[:self.fw]
        S = int.from_bytes(self.sig[self.fw:], 'little')
        if S >= c.L:
            return False
        R = c.decode(R_enc)
        A = c.decode(self.sec)
        if R is None or A is None:
            return False
        if self.msg_pass == 3:                            # pure: k' from the verification pass
            kp = self._kprime
        else:
            kp = int.from_bytes(self._H(self._dom(1) + R_enc + self.sec + self.hash),
                                'little') % c.L
        h = c.h
        lhs = c.mul(h * S % (c.L * h), c.B)
        rhs = c.add(c.mul(h, R), c.mul(h * kp % (c.L * h), A))
        return lhs == rhs


# ------------------------------------------------------------ CR constructors
# The b / h / j / u / v values are those tabulated in <<ACE-ECC>> "Parameters".

CURVE_PARAMS = {
    'secp256r1':       dict(b=256, h=256, j=256, u=2, v=2, mode='ecdsa'),
    'secp384r1':       dict(b=384, h=384, j=384, u=2, v=2, mode='ecdsa'),
    'secp521r1':       dict(b=576, h=576, j=576, u=2, v=2, mode='ecdsa'),
    'brainpoolP256r1': dict(b=256, h=256, j=256, u=2, v=2, mode='ecdsa'),
    'brainpoolP384r1': dict(b=384, h=384, j=384, u=2, v=2, mode='ecdsa'),
    'brainpoolP512r1': dict(b=512, h=512, j=512, u=2, v=2, mode='ecdsa'),
    'sm2p256v1':       dict(b=256, h=256, j=256, u=2, v=2, mode='sm2'),
    'ed25519':         dict(b=256, h=512, j=0,   u=1, v=2, mode='eddsa'),
    'ed448':           dict(b=456, h=512, j=0,   u=1, v=2, mode='eddsa'),
}


def make_cr(curve, **kw):
    p = dict(CURVE_PARAMS[curve.name])
    p.update(kw)
    return CR(curve, **p)


# ==================================================================== vectors

# RFC 6979 Appendix A.2.5 (P-256), A.2.6 (P-384), A.2.7 (P-521).
# Fetched from https://www.rfc-editor.org/rfc/rfc6979.txt during development.
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
             0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083),
        ]),
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
             0xDDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5),
        ]),
    'secp521r1': dict(
        x=0x0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538,
        Ux=0x1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4,
        Uy=0x0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5,
        sigs=[
            ('sample', 'sha512',
             0x1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3,
             0x0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA,
             0x0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A),
        ]),
}

# RFC 8032 section 7.1 (Ed25519), 7.3 (Ed25519ph), 7.4 (Ed448).
# Fetched from https://www.rfc-editor.org/rfc/rfc8032.txt during development.
RFC8032_ED25519 = [
    ('7.1 TEST 1 (empty message)',
     '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
     'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
     '',
     'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015'
     '55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
    ('7.1 TEST 2 (1-byte message)',
     '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
     '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
     '72',
     '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
     '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
    ('7.1 TEST 3 (2-byte message)',
     'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
     'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
     'af82',
     '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac'
     '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'),
]

RFC8032_ED25519PH = (
    '7.3 TEST abc (Ed25519ph)',
    '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
    '616263',
    '98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41'
    '31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406')

RFC8032_ED448 = [
    ('7.4 Blank (empty message)',
     '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3'
     '528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b',
     '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778'
     'edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180',
     '', '',
     '533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f'
     '2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a'
     '9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db'
     'b61149f05a7363268c71d95808ff2e652600'),
    ('7.4 1 octet',
     'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a'
     'fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
     '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086'
     '6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
     '03', '',
     '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435'
     '2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb'
     'cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f'
     'f3348ab21aa4adafd1d234441cf807c03a00'),
    ('7.4 1 octet (with context "foo")',
     'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a'
     'fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
     '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086'
     '6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
     '03', '666f6f',
     'd4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2'
     '151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da'
     '1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d'
     '5428407e85dcbc98a49155c13764e66c3c00'),
]

# GM/T 0003.5-2012 / GB/T 32918.5-2017 Appendix A, worked example for the
# recommended 256-bit curve, message "message digest", ID_A = "1234567812345678".
SM2_VEC = dict(
    ida=b'1234567812345678',
    msg=b'message digest',
    d=0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8,
    Px=0x09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020,
    Py=0xCCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13,
    ZA=0xB2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3,
    e=0xF0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640,
    k=0x59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21,
    r=0xF5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3,
    s=0xB1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA)


# ==================================================================== helpers

def ecdsa_e(curve, digest):
    """FIPS 186-5 6.4: the leftmost min(N, outlen) bits of the digest, as an
    integer.  The spec makes this the *caller's* job; the model receives the
    result in `Hash`."""
    n_bits = curve.n.bit_length()
    e = int.from_bytes(digest, 'big')
    if len(digest) * 8 > n_bits:
        e >>= len(digest) * 8 - n_bits
    return e


def drive_sign(cr, e_int, k_list, hook=None):
    """Drive a full signature generation the way a caller would."""
    cr.setst(SET_HASH)
    cr.exec_in(v2b(e_int, cr.hashlen))
    cr.setst(SIGN_GEN)
    out = cr.exec_run(rbg=k_list, degenerate_hook=hook)
    sig = cr.output_all(chunk=16)
    return out, sig


def load_field(cr, state, data, chunk=None):
    """setst into a Set_ state and stream `data` in through Form B ace.exec."""
    cr.setst(state)
    if chunk is None:
        cr.exec_in(data)
    else:
        for i in range(0, len(data), chunk):
            cr.exec_in(data[i:i + chunk])


def fresh(curve, **kw):
    return make_cr(curve, **kw)


# ==================================================================== the tests

def test_parameters():
    head('Domain parameters and the b / h / j / u / v table of <<ACE-ECC>>')
    for name, c in EC.WEIERSTRASS_CURVES.items():
        p = CURVE_PARAMS[name]
        level = 'PARAM' if name.startswith('brainpool') else 'KAT'
        ok = c.is_on_curve(c.G) and c.mul(c.n, c.G) is None and c.h == 1
        chk(level, f'{name}: G on curve, n*G = O, cofactor 1', ok)
        # b must be wide enough for a field element, and a whole number of bytes
        need = c.p.bit_length()
        chk('MODEL', f'{name}: spec b = {p["b"]} holds a {need}-bit field element',
            p['b'] >= need and p['b'] % 8 == 0)
    for name, c in EC.EDWARDS_CURVES.items():
        p = CURVE_PARAMS[name]
        chk('KAT', f'{name}: B on curve, L*B = identity',
            c.is_on_curve(c.B) and c.mul(c.L, c.B) == (0, 1))
        chk('MODEL', f'{name}: spec b = {p["b"]}, u = 1 (compressed point of {p["b"]//8} bytes)',
            p['b'] == c.bbits and p['u'] == 1 and p['v'] == 2)
    chk('MODEL', 'secp521r1: b = 576 with 55 zero msbs covers the 521-bit field',
        CURVE_PARAMS['secp521r1']['b'] - EC.P521.msb_zero == 521)


def test_ecdsa_kats():
    head('ECDSA against RFC 6979 (k injected in place of the RBG draw)')
    for cname, vec in RFC6979.items():
        c = EC.WEIERSTRASS_CURVES[cname]
        d = vec['x']
        # --- Point_Mul anchored on the RFC's published public key U = xG
        cr = fresh(c)
        load_field(cr, SET_SCALAR, v2b(d, cr.fw), chunk=8)
        cr.setst(POINT_MUL)
        Q = cr.exec_run()
        out = cr.output_all(chunk=16)
        ok = Q == (vec['Ux'], vec['Uy'])
        ok = ok and out == v2b(vec['Ux'], cr.fw) + v2b(vec['Uy'], cr.fw)
        ok = ok and cr.state == SUCCESS
        chk('KAT', f'{cname}: Point_Mul d*G = U (RFC 6979 Ux,Uy) and Output -> Success', ok)

        pub = v2b(vec['Ux'], cr.fw) + v2b(vec['Uy'], cr.fw)
        for msg, hname, k, r_exp, s_exp in vec['sigs']:
            digest = hashlib.new(hname, msg.encode()).digest()
            e = ecdsa_e(c, digest)
            # --- Sign_Generate
            cr = fresh(c)
            load_field(cr, SET_SCALAR, v2b(d, cr.fw))
            (r, s, _), sig = drive_sign(cr, e, [k])
            ok = (r == r_exp and s == s_exp)
            ok = ok and sig == v2b(r_exp, cr.fw) + v2b(s_exp, cr.fw)
            ok = ok and cr.state == SUCCESS
            chk('KAT', f'{cname}/{hname} "{msg}": Sign_Generate (r,s)', ok,
                f'got r={r:x} s={s:x}')
            # --- Sign_Verify of the freshly produced signature
            cr = fresh(c)
            load_field(cr, SET_SECONDPT, pub, chunk=16)
            load_field(cr, SET_HASH, v2b(e, cr.hashlen))
            load_field(cr, SET_SIG, sig, chunk=16)
            cr.setst(SIGN_VER)
            good = cr.exec_run()
            chk('KAT', f'{cname}/{hname} "{msg}": Sign_Verify -> Success',
                good and cr.state == SUCCESS)
            # --- corrupted signature
            bad = bytearray(sig)
            bad[0] ^= 1
            cr = fresh(c)
            load_field(cr, SET_SECONDPT, pub)
            load_field(cr, SET_HASH, v2b(e, cr.hashlen))
            load_field(cr, SET_SIG, bytes(bad))
            cr.setst(SIGN_VER)
            chk('KAT', f'{cname}/{hname} "{msg}": corrupted signature -> Failure',
                not cr.exec_run() and cr.state == FAILURE)
        # --- out-of-range r and s
        for label, rr, ss in (('r = 0', 0, 1), ('s = 0', 1, 0),
                              ('r = n', c.n, 1), ('s = n', 1, c.n)):
            cr = fresh(c)
            load_field(cr, SET_SECONDPT, pub)
            load_field(cr, SET_HASH, v2b(1, cr.hashlen))
            load_field(cr, SET_SIG, v2b(rr, cr.fw) + v2b(ss, cr.fw))
            cr.setst(SIGN_VER)
            chk('MODEL', f'{cname}: out-of-range signature ({label}) -> Failure',
                not cr.exec_run() and cr.state == FAILURE)


def test_p521_representation():
    head('secp521r1: the 576-bit representation with 55 zero most significant bits')
    c = EC.P521
    cr = fresh(c)
    chk('MODEL', 'default Generator: both coordinates have 55 zero msbs',
        cr.repr_ok(cr.gen) and len(cr.gen) == 144)
    # a scalar whose bit 521 is set violates the rule
    bad_scalar = v2b(1 << 521, cr.fw)
    try:
        load_field(cr, SET_SCALAR, bad_scalar)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'Scalar with a non-zero bit above bit 520 -> Invalid', ok)
    cr = fresh(c)
    good = v2b(EC.P521.G[0], cr.fw)
    bad_pt = v2b(EC.P521.G[0] | (1 << 575), cr.fw) + v2b(EC.P521.G[1], cr.fw)
    try:
        load_field(cr, SET_SECONDPT, bad_pt)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'SecondPt coordinate with a non-zero bit above bit 520 -> Invalid', ok)
    # the all-ones sentinel is explicitly exempt
    cr = fresh(c)
    try:
        load_field(cr, SET_SECONDPT, b'\xff' * (2 * cr.fw))
        ok = cr.has_sec and cr._dec_point(cr.sec)[0] == 'inf'
    except ACEInvalid:
        ok = False
    chk('MODEL', 'point-at-infinity sentinel is exempt from the 55-zero-msb rule', ok)
    chk('MODEL', 'the sentinel is not a valid field element (all-ones > p)',
        b2v(b'\xff' * cr.fw) > c.p and len(good) == 72)
    note('the spec states the 55-zero-msb rule but never says *where* it is enforced;'
         ' this model rejects at field-load time (transition to Invalid).')


def test_point_mul_validation():
    head('Point_Mul: scalar range, curve validation, infinity sentinel')
    c = EC.P256
    # scalar = n must be rejected by 1 <= int(Scalar) < n
    for label, k in (('Scalar = 0', 0), ('Scalar = n', c.n), ('Scalar = n+1', c.n + 1)):
        cr = fresh(c)
        cr.setst(SET_SCALAR)
        cr.exec_in(v2b(k, cr.fw))
        cr.setst(POINT_MUL)
        try:
            cr.exec_run()
            ok = False
        except ACEInvalid:
            ok = True
        chk('MODEL', f'secp256r1: Point_Mul with {label} -> Invalid', ok)
    chk('MODEL', 'secp256r1: Point_Mul with Scalar = n-1 is accepted',
        _point_mul_ok(c, c.n - 1))
    # off-curve SecondPt
    cr = fresh(c)
    load_field(cr, SET_SCALAR, v2b(2, cr.fw))
    off = v2b(EC.P256.G[0], cr.fw) + v2b((EC.P256.G[1] + 1) % c.p, cr.fw)
    load_field(cr, SET_SECONDPT, off)
    cr.setst(POINT_MUL)
    try:
        cr.exec_run()
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'secp256r1: off-curve SecondPt -> Invalid (curve validation)', ok)
    # known small multiples of G
    cr = fresh(c)
    load_field(cr, SET_SCALAR, v2b(2, cr.fw))
    cr.setst(POINT_MUL)
    P2 = cr.exec_run()
    chk('MODEL', 'secp256r1: 2G matches the doubling of G computed independently',
        P2 == c.add(c.G, c.G) and c.is_on_curve(P2))
    # (n-1)*G then one more addition gives infinity -> sentinel
    cr = fresh(c)
    load_field(cr, SET_SCALAR, v2b(c.n - 1, cr.fw))
    cr.setst(POINT_MUL)
    Pm1 = cr.exec_run()
    chk('MODEL', 'secp256r1: (n-1)G = -G', Pm1 == (c.G[0], (c.p - c.G[1]) % c.p))
    cr2 = fresh(c)
    cr2.sec = cr2._enc_point(None)
    chk('MODEL', 'point at infinity is encoded by the all-ones sentinel',
        cr2.sec == b'\xff' * (2 * cr2.fw) and cr2._dec_point(cr2.sec)[0] == 'inf')
    note('Point_Mul requires the base point to be "a point of the curve", but the text'
         ' does not say whether the point-at-infinity *sentinel* is an acceptable input'
         ' in SecondPt. This model treats it as acceptable and returns the sentinel;'
         ' an explicit rejection would be the safer prescription. NEW FINDING.')


def _point_mul_ok(c, k):
    cr = fresh(c)
    load_field(cr, SET_SCALAR, v2b(k, cr.fw))
    cr.setst(POINT_MUL)
    try:
        cr.exec_run()
        return cr.state == OUTPUT
    except ACEInvalid:
        return False


def test_retry_rules():
    head('Signature-generation retry rules')
    n = EC.P256.n
    chk('MODEL', 'FIPS 186-5 6.4.1: retry iff r = 0 or s = 0',
        retry_required('ecdsa', 0, 5, 7, n) and retry_required('ecdsa', 5, 0, 7, n)
        and not retry_required('ecdsa', 5, 5, 7, n)
        and not retry_required('ecdsa', 5, 5, (n - 5) % n, n))
    chk('MODEL', 'SM2: retry iff r = 0, r + k = n, or s = 0',
        retry_required('sm2', 0, 5, 7, n) and retry_required('sm2', 5, 0, 7, n)
        and retry_required('sm2', 5, 5, n - 5, n)
        and not retry_required('sm2', 5, 5, 7, n))
    # end-to-end: force the first draw degenerate, the second must be used
    c = EC.P256
    vec = RFC6979['secp256r1']
    msg, hname, k, r_exp, s_exp = vec['sigs'][0]
    e = ecdsa_e(c, hashlib.new(hname, msg.encode()).digest())
    cr = fresh(c)
    load_field(cr, SET_SCALAR, v2b(vec['x'], cr.fw))
    (r, s, attempts), _ = drive_sign(cr, e, [0x1234, k], hook=lambda a: a == 0)
    chk('MODEL', 'a degenerate first draw is discarded and a fresh k drawn (RFC 6979 answer)',
        attempts == 1 and r == r_exp and s == s_exp)
    chk('MODEL', 'RndNum is destroyed and HasRndNum cleared after signing',
        cr.rnd is None and cr.has_rnd is False)


def test_state_machine():
    head('State machine: transitions, entry conditions, Ready-return Xs bits')
    c = EC.P256
    # Sign_Generate entry needs HasHash and a configured private key
    cr = fresh(c)
    try:
        cr.setst(SIGN_GEN)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'fresh CC (Scalar = 0, no Hash): Sign_Generate -> Invalid', ok)
    cr = fresh(c)
    load_field(cr, SET_SCALAR, v2b(RFC6979['secp256r1']['x'], cr.fw))
    try:
        cr.setst(SIGN_GEN)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'private key set but HasHash clear: Sign_Generate -> Invalid', ok)
    cr = fresh(c)
    load_field(cr, SET_HASH, v2b(1, cr.hashlen))
    try:
        cr.setst(SIGN_GEN)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'HasHash set but Scalar = 0: Sign_Generate -> Invalid', ok)
    # Sign_Verify entry needs HasSecondPt, HasHash, HasSignature
    for missing in ('SecondPt', 'Hash', 'Signature'):
        cr = fresh(c)
        if missing != 'SecondPt':
            load_field(cr, SET_SECONDPT, cr.default_gen)
        if missing != 'Hash':
            load_field(cr, SET_HASH, v2b(1, cr.hashlen))
        if missing != 'Signature':
            load_field(cr, SET_SIG, bytes(cr.siglen))
        try:
            cr.setst(SIGN_VER)
            ok = False
        except ACEInvalid:
            ok = True
        chk('MODEL', f'Sign_Verify without Has{missing} -> Invalid', ok)
    # AlgorithmPolicy
    cr = fresh(c, policy_sign=False)
    load_field(cr, SET_SCALAR, v2b(3, cr.fw))
    load_field(cr, SET_HASH, v2b(1, cr.hashlen))
    try:
        cr.setst(SIGN_GEN)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'AlgorithmPolicy[0] clear: Sign_Generate -> Invalid', ok)
    # block_base tracking
    cr = fresh(c)
    cr.setst(SET_SECONDPT)
    cr.exec_in(cr.default_gen[:20])
    part = (cr.block_base == 20 and not cr.has_sec)
    cr.exec_in(cr.default_gen[20:] + b'\xaa' * 9)         # excess must be ignored
    chk('MODEL', 'block_base tracks partial loads; excess in the last ace.exec ignored',
        part and cr.block_base == cr.ptlen and cr.has_sec and cr.sec == cr.default_gen)
    try:
        cr.exec_in(b'\x00' * 4)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'ace.exec after block_base has reached the field length -> Invalid', ok)
    # output in pieces, with zero fill past the end
    cr = fresh(c)
    load_field(cr, SET_SCALAR, v2b(2, cr.fw))
    cr.setst(POINT_MUL)
    cr.exec_run()
    pieces = [cr.exec_out(24), cr.exec_out(24), cr.exec_out(24)]
    chk('MODEL', 'Output: block_base-tracked export, zero fill, then -> Success',
        b''.join(pieces)[:cr.ptlen] == cr.sec and pieces[2][16:] == bytes(8)
        and cr.state == SUCCESS)
    # illegal transitions
    cr = fresh(c)
    try:
        cr.setst(OUTPUT)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'Ready -> Output is not allowed (Generic Rule 2) -> Invalid', ok)

    # ---- Ready-return Xs bits
    def loaded():
        cc = fresh(c)
        cc.gen = cc._enc_point(c.add(c.G, c.G))           # non-default generator
        load_field(cc, SET_SECONDPT, cc.default_gen)
        load_field(cc, SET_SCALAR, v2b(7, cc.fw))
        cc.sig = bytes(cc.siglen)
        cc.has_sig = True
        return cc
    cc = loaded()
    cc.setst(READY, form='A')
    chk('MODEL', 'Xs: Form A ace.setst leaves Generator/Scalar/SecondPt untouched',
        cc.gen != cc.default_gen and cc.has_sec and b2v(cc.scalar) == 7)
    chk('MODEL', 'Form A: Signature and HasSignature retained on return to Ready',
        cc.sig is not None and cc.has_sig)
    cc = loaded()
    cc.setst(READY, form='B', xs=1)
    chk('MODEL', 'Xs bit 0: Generator reset to the default value',
        cc.gen == cc.default_gen and cc.has_sec)
    cc = loaded()
    cc.setst(READY, form='B', xs=2)
    chk('MODEL', 'Xs bit 1: SecondPt erased and HasSecondPt unset',
        cc.sec is None and not cc.has_sec)
    cc = loaded()
    cc.setst(READY, form='B', xs=4)
    chk('MODEL', 'Xs bit 2: Scalar erased', b2v(cc.scalar) == 0 and cc.has_sec)
    cc = loaded()
    cc.hash = bytes(cc.hashlen)
    cc.has_hash = True
    cc.setst(READY, form='B', xs=8)
    chk('MODEL', 'Xs bit 3: Hash erased and HasHash unset, SecondPt kept',
        cc.hash is None and not cc.has_hash and cc.has_sec)
    cc = loaded()
    cc.hash = bytes(cc.hashlen)
    cc.has_hash = True
    cc.setst(READY, form='B', xs=0)
    chk('MODEL', 'Xs bit 3 clear: Hash and HasHash retained',
        cc.hash is not None and cc.has_hash)
    cc = loaded()
    cc.setst(READY, form='B', xs=1 << 6)
    chk('MODEL', 'Xs bit 6: Signature erased and HasSignature unset',
        cc.sig is None and not cc.has_sig)
    cc = loaded()
    cc.setst(READY, form='B', xs=0)
    chk('MODEL', 'Xs bit 6 clear: Signature and HasSignature retained',
        cc.sig is not None and cc.has_sig)
    cc = loaded()
    cc.hash = bytes(cc.hashlen)
    cc.has_hash = True
    cc.setst(READY, form='B', xs=0)
    chk('MODEL', 'uniform polarity: Xs = 0 retains every field',
        cc.gen != cc.default_gen and cc.has_sec and b2v(cc.scalar) == 7
        and cc.has_hash and cc.has_sig)
    cc = loaded()
    g = cc.gen
    cc.setst(READY, form='B', xs=1 << 4)
    chk('MODEL', 'Xs bit 4: Generator copied onto SecondPt',
        cc.sec == g and cc.has_sec and cc.gen == g)
    cc = loaded()
    cc.setst(READY, form='B', xs=(1 << 4) | 1)
    chk('MODEL', 'Xs bits 4+0: copy, then Generator reset to default',
        cc.sec == g and cc.gen == cc.default_gen)
    cc = loaded()
    sec0 = cc.sec
    cc.setst(READY, form='B', xs=1 << 5)
    chk('MODEL', 'Xs bit 5: SecondPt copied onto Generator',
        cc.gen == sec0 and cc.sec == sec0 and cc.has_sec)
    cc = loaded()
    cc.setst(READY, form='B', xs=(1 << 5) | 2)
    chk('MODEL', 'Xs bits 5+1: copy, then SecondPt erased and HasSecondPt False',
        cc.gen == sec0 and cc.sec is None and not cc.has_sec)
    note('"Upon returning to State _Ready_" previously assigned *SecondPt* to both Bit 1'
         ' and Bit 3, leaving Bit 3 with no distinct meaning, said nothing about the fate'
         ' of `Hash`, and reset `Signature` unconditionally. All three are now fixed, with'
         ' uniform polarity throughout: a set bit discards the field it names (Bit 3'
         ' `Hash`, Bit 6 `Signature`) and a clear bit retains it, so Form A and Xs = 0'
         ' retain everything and one CC can sign and then verify.')


# an arbitrary valid per-signature secret; this flow checks reachability, not a KAT
K_FIXED = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60


def test_sign_then_verify_one_cc():
    head('Sign AND verify within a single CC (fields survive the return to Ready)')
    c = EC.P256
    d = 0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464
    cr = fresh(c)
    cr.policy_sign = cr.policy_verify = True

    # 1. private key -> Point_Mul -> Output -> Success, leaving the public key in SecondPt
    load_field(cr, SET_SCALAR, v2b(d, cr.fw))
    cr.setst(POINT_MUL)
    cr.exec_run()
    cr.output_all(chunk=16)
    chk('MODEL', 'step 1: Point_Mul leaves the public key in SecondPt, state Success',
        cr.state == SUCCESS and cr.has_sec)
    pub = cr.sec

    # 2. Success -> Ready with Xs = 0 keeps Generator, SecondPt, Scalar
    cr.setst(READY, form='B', xs=0)
    chk('MODEL', 'step 2: Success -> Ready (Xs=0) retains SecondPt and Scalar',
        cr.has_sec and cr.sec == pub and b2v(cr.scalar) == d)

    # 3. load the message value, sign
    e = 0xa41a41a12a799548211c410c65d8133afde34d28bdd542e4b680cf2899c8a8c4
    load_field(cr, SET_HASH, v2b(e, cr.hashlen))
    cr.setst(SIGN_GEN)
    cr.exec_run(rbg=[K_FIXED, K_FIXED + 1, K_FIXED + 2])
    cr.output_all(chunk=16)
    chk('MODEL', 'step 3: Sign_Generate -> Output -> Success with HasSignature set',
        cr.state == SUCCESS and cr.has_sig)
    sig = cr.sig

    # 4. Success -> Ready: with no bit set, every field survives
    cr.setst(READY, form='B', xs=0)
    chk('MODEL', 'step 4: Signature, Hash and SecondPt survive the return to Ready',
        cr.has_sig and cr.sig == sig and cr.has_hash and cr.has_sec)

    # 5. Ready -> Sign_Verify: all three preconditions now hold
    cr.setst(SIGN_VER)
    good = cr.exec_run()
    chk('MODEL', 'step 5: the CC verifies its own signature -> Success',
        good and cr.state == SUCCESS)

    # Bit 6 is the way to drop a stale signature, and then verification is refused
    cr2 = fresh(c)
    cr2.policy_sign = cr2.policy_verify = True
    load_field(cr2, SET_SCALAR, v2b(d, cr2.fw))
    load_field(cr2, SET_SECONDPT, pub)
    load_field(cr2, SET_HASH, v2b(e, cr2.hashlen))
    cr2.setst(SIGN_GEN)
    cr2.exec_run(rbg=[K_FIXED, K_FIXED + 1, K_FIXED + 2])
    cr2.output_all(chunk=16)
    cr2.setst(READY, form='B', xs=1 << 6)
    try:
        cr2.setst(SIGN_VER)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'with Bit 6 the signature is discarded and Sign_Verify is refused', ok)


def test_m10_dead_end():
    head('Regression check: review finding M10 (Set_Signature dead end), now FIXED')
    # breadth-first search over the transition relation, pre-fix and current
    for literal, label in ((True, 'pre-fix'), (False, 'current text')):
        seen = {SET_SIG}
        frontier = [SET_SIG]
        while frontier:
            nxt = []
            for st in frontier:
                for t in transition_targets(st, eddsa=False, literal=literal):
                    if t not in seen:
                        seen.add(t)
                        nxt.append(t)
            frontier = nxt
        reachable = SIGN_VER in seen
        if literal:
            info(f'transition list {label}: states reachable from Set_Signature = '
                 f'{sorted(SNAME[s] for s in seen - {SET_SIG}) or "(none)"}')
            chk('MODEL', 'pre-fix relation had no legal path Set_Signature ->'
                ' Sign_Verify (this PASS records what the defect was)', not reachable)
        else:
            chk('MODEL', f'transition list {label}: Set_Signature -> Sign_Verify is reachable',
                reachable)
    note('M10 is RESOLVED in the current text. <<ACE-ECC>> "Allowed State Transitions"'
         ' now defines the five _Set_ states collectively, lets any two of them'
         ' transition freely, and admits all of them as sources for _Point_Mul_,'
         ' _Sign_Generate_ and _Sign_Verify_; _Point_Mul_ -> _Output_ -> _Success_ is'
         ' also completed. Previously _Set_Signature_ appeared in neither exit rule, so'
         ' by Generic Rule 2 a CR that had just loaded a signature could make no legal'
         ' move and verification was unreachable. The pre-fix relation is retained above'
         ' as a regression check.')
    # the strictness of the rest of the list is still enforced
    cr = fresh(EC.P256, literal=True)
    load_field(cr, SET_SIG, bytes(cr.siglen))
    try:
        cr.setst(SIGN_VER)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'literal model: Set_Signature -> Sign_Verify raises Invalid', ok)


def test_ed25519():
    head('Ed25519 / Ed25519ph against RFC 8032 7.1 and 7.3 (ACE two-pass model)')
    c = EC.ED25519
    for name, seed_h, pk_h, msg_h, sig_h in RFC8032_ED25519:
        seed, pk, msg = bytes.fromhex(seed_h), bytes.fromhex(pk_h), bytes.fromhex(msg_h)
        # public key derivation from the seed
        cr = fresh(c)
        load_field(cr, SET_SCALAR, seed)
        _, _, A = cr._keys()
        chk('KAT', f'ed25519 {name}: public key A derived from the seed', A == pk)
        # --- pure-mode signing, two Msg_Absorb passes
        cr = fresh(c)
        load_field(cr, SET_SCALAR, seed, chunk=16)
        cr.setst(MSG_ABSORB, form='B', xs=0)
        cr.exec_in(msg)
        cr.setst(MSG_ABSORB, form='B', xs=1)
        r_pass1 = cr.msg_pass                             # must be 1 after pass 0
        cr.exec_in(msg)
        cr.setst(SIGN_GEN)
        cr.exec_run()
        sig = cr.output_all(chunk=32)
        chk('KAT', f'ed25519 {name}: pure-mode signature', sig.hex() == sig_h,
            f'got {sig.hex()}')
        chk('MODEL', f'ed25519 {name}: msg_pass 1 after pass 0, 0 after Sign_Generate,'
            ' Output -> Success',
            r_pass1 == 1 and cr.msg_pass == 0 and cr.state == SUCCESS)
        # --- verification through the ACE model
        cr = fresh(c)
        load_field(cr, SET_SECONDPT, pk)
        load_field(cr, SET_SIG, bytes.fromhex(sig_h), chunk=32)
        cr.setst(MSG_ABSORB, form='B', xs=2)
        cr.exec_in(msg)
        cr.setst(SIGN_VER)
        chk('KAT', f'ed25519 {name}: Sign_Verify -> Success',
            cr.exec_run() and cr.state == SUCCESS)
        # --- corrupted signature
        bad = bytearray(bytes.fromhex(sig_h))
        bad[0] ^= 0x40
        cr = fresh(c)
        load_field(cr, SET_SECONDPT, pk)
        load_field(cr, SET_SIG, bytes(bad))
        cr.setst(MSG_ABSORB, form='B', xs=2)
        cr.exec_in(msg)
        cr.setst(SIGN_VER)
        chk('KAT', f'ed25519 {name}: corrupted R -> Failure',
            not cr.exec_run() and cr.state == FAILURE)
    # --- Ed25519ph (pre-hash), RFC 8032 7.3
    name, seed_h, pk_h, msg_h, sig_h = RFC8032_ED25519PH
    seed, pk, msg = bytes.fromhex(seed_h), bytes.fromhex(pk_h), bytes.fromhex(msg_h)
    ph = hashlib.sha512(msg).digest()
    cr = fresh(c)
    load_field(cr, SET_SCALAR, seed)
    load_field(cr, SET_HASH, ph, chunk=32)
    cr.setst(SIGN_GEN)
    cr.exec_run()
    sig = cr.output_all()
    chk('KAT', f'ed25519ph {name}: pre-hash signature over PH(M) in Hash',
        sig.hex() == sig_h, f'got {sig.hex()}')
    cr = fresh(c)
    load_field(cr, SET_SECONDPT, pk)
    load_field(cr, SET_SIG, bytes.fromhex(sig_h))
    load_field(cr, SET_HASH, ph)
    cr.setst(SIGN_VER)
    chk('KAT', f'ed25519ph {name}: Sign_Verify (msg_pass = 0, HasHash) -> Success',
        cr.exec_run() and cr.state == SUCCESS)
    chk('MODEL', 'ed25519: h = 512 matches the 64-byte PH(M) placed in Hash',
        CURVE_PARAMS['ed25519']['h'] // 8 == len(ph))
    # --- EdDSA-specific entry conditions
    cr = fresh(c)
    try:
        cr.setst(MSG_ABSORB, form='B', xs=0)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'Msg_Absorb Xs = 0 without a configured seed -> Invalid', ok)
    cr = fresh(c)
    load_field(cr, SET_SCALAR, seed)
    try:
        cr.setst(MSG_ABSORB, form='B', xs=1)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'Msg_Absorb Xs = 1 with msg_pass != 1 -> Invalid', ok)
    cr = fresh(c)
    load_field(cr, SET_SCALAR, seed)
    try:
        cr.setst(MSG_ABSORB, form='B', xs=3)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'Msg_Absorb with an out-of-range Xs -> Invalid', ok)
    cr = fresh(c)
    load_field(cr, SET_SCALAR, seed)
    cr.setst(MSG_ABSORB, form='B', xs=0)
    cr.exec_in(msg)
    try:
        cr.setst(SIGN_GEN)                                # msg_pass = 1, no Hash
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'Sign_Generate after only one pass (msg_pass = 1) -> Invalid', ok)
    chk('MODEL', 'HasRndNum is never set on the EdDSA path',
        cr.has_rnd is False and CURVE_PARAMS['ed25519']['j'] == 0)
    # different message in the two passes must not verify
    seed, pk, msg = (bytes.fromhex(RFC8032_ED25519[2][1]),
                     bytes.fromhex(RFC8032_ED25519[2][2]),
                     bytes.fromhex(RFC8032_ED25519[2][3]))
    cr = fresh(c)
    load_field(cr, SET_SCALAR, seed)
    cr.setst(MSG_ABSORB, form='B', xs=0)
    cr.exec_in(msg)
    cr.setst(MSG_ABSORB, form='B', xs=1)
    cr.exec_in(msg + b'\x00')                             # different message!
    cr.setst(SIGN_GEN)
    cr.exec_run()
    sig = cr.output_all()
    cr = fresh(c)
    load_field(cr, SET_SECONDPT, pk)
    load_field(cr, SET_SIG, sig)
    cr.setst(MSG_ABSORB, form='B', xs=2)
    cr.exec_in(msg)
    cr.setst(SIGN_VER)
    chk('MODEL', 'different messages in the two signing passes -> Failure (the spec NOTE)',
        not cr.exec_run() and cr.state == FAILURE)


def test_ed448():
    head('Ed448 against RFC 8032 7.4 (dom4, mandatory ctx, 57-byte encodings)')
    c = EC.ED448
    chk('MODEL', 'ed448: b = 456, so a point and each signature half are 57 bytes',
        CURVE_PARAMS['ed448']['b'] == 456 and 456 // 8 == 57)
    for name, seed_h, pk_h, msg_h, ctx_h, sig_h in RFC8032_ED448:
        seed, pk = bytes.fromhex(seed_h), bytes.fromhex(pk_h)
        msg, ctx = bytes.fromhex(msg_h), bytes.fromhex(ctx_h)
        cr = fresh(c)
        load_field(cr, SET_SCALAR, seed, chunk=19)
        _, _, A = cr._keys()
        chk('KAT', f'ed448 {name}: public key A derived from the seed', A == pk)
        cr = fresh(c)
        load_field(cr, SET_SCALAR, seed)
        cr.setst(SET_CTX, form='B', xs=len(ctx))
        if ctx:
            cr.exec_in(ctx)
        cr.setst(MSG_ABSORB, form='B', xs=0)
        cr.exec_in(msg)
        cr.setst(MSG_ABSORB, form='B', xs=1)
        cr.exec_in(msg)
        cr.setst(SIGN_GEN)
        cr.exec_run()
        sig = cr.output_all(chunk=57)
        chk('KAT', f'ed448 {name}: pure-mode signature (dom4)', sig.hex() == sig_h,
            f'got {sig.hex()}')
        cr = fresh(c)
        load_field(cr, SET_SECONDPT, pk)
        load_field(cr, SET_SIG, bytes.fromhex(sig_h))
        cr.setst(SET_CTX, form='B', xs=len(ctx))
        if ctx:
            cr.exec_in(ctx)
        cr.setst(MSG_ABSORB, form='B', xs=2)
        cr.exec_in(msg)
        cr.setst(SIGN_VER)
        chk('KAT', f'ed448 {name}: Sign_Verify -> Success',
            cr.exec_run() and cr.state == SUCCESS)
    # a signature made with ctx = "foo" must not verify with the empty context
    name, seed_h, pk_h, msg_h, ctx_h, sig_h = RFC8032_ED448[2]
    cr = fresh(c)
    load_field(cr, SET_SECONDPT, bytes.fromhex(pk_h))
    load_field(cr, SET_SIG, bytes.fromhex(sig_h))
    cr.setst(MSG_ABSORB, form='B', xs=2)                  # ctx left empty
    cr.exec_in(bytes.fromhex(msg_h))
    cr.setst(SIGN_VER)
    chk('KAT', 'ed448: context-bound signature does not verify under a different ctx',
        not cr.exec_run() and cr.state == FAILURE)
    cr = fresh(c)
    load_field(cr, SET_SCALAR, bytes.fromhex(seed_h))
    try:
        cr.setst(SET_CTX, form='B', xs=256)
        ok = False
    except ACEInvalid:
        ok = True
    chk('MODEL', 'Set_Ctx with ctxlen > 255 -> Invalid', ok)


def test_sm2():
    head('SM2 against the GM/T 0003.5 worked example')
    c = EC.SM2C
    v = SM2_VEC
    cr = fresh(c)
    load_field(cr, SET_SCALAR, v2b(v['d'], 32))
    cr.setst(POINT_MUL)
    Q = cr.exec_run()
    chk('KAT', 'sm2: Point_Mul d*G matches the example public key (Px, Py)',
        Q == (v['Px'], v['Py']))
    # Z_A and e are the caller's job; re-derive them when SM3 is available
    try:
        def be(x):
            return x.to_bytes(32, 'big')
        entl = (len(v['ida']) * 8).to_bytes(2, 'big')
        za = hashlib.new('sm3', entl + v['ida']
                         + be(c.a) + be(c.b) + be(c.G[0]) + be(c.G[1])
                         + be(v['Px']) + be(v['Py'])).digest()
        e = hashlib.new('sm3', za + v['msg']).digest()
        chk('KAT', 'sm2: Z_A = SM3(ENTL||ID||a||b||xG||yG||xA||yA) matches the example',
            int.from_bytes(za, 'big') == v['ZA'])
        chk('KAT', 'sm2: e = SM3(Z_A || M) matches the example',
            int.from_bytes(e, 'big') == v['e'])
    except ValueError:
        info('SM3 not available from hashlib on this platform; Z_A / e taken from the'
             ' embedded example values (the ACE unit computes neither).')
    pub = v2b(v['Px'], 32) + v2b(v['Py'], 32)
    cr = fresh(c)
    load_field(cr, SET_SCALAR, v2b(v['d'], 32))
    (r, s, _), sig = drive_sign(cr, v['e'], [v['k']])
    chk('KAT', 'sm2: Sign_Generate (r, s) matches the example',
        r == v['r'] and s == v['s'] and sig == v2b(v['r'], 32) + v2b(v['s'], 32),
        f'got r={r:x} s={s:x}')
    cr = fresh(c)
    load_field(cr, SET_SECONDPT, pub)
    load_field(cr, SET_HASH, v2b(v['e'], 32))
    load_field(cr, SET_SIG, sig)
    cr.setst(SIGN_VER)
    chk('KAT', 'sm2: Sign_Verify (t = (r+s) mod n) -> Success',
        cr.exec_run() and cr.state == SUCCESS)
    bad = bytearray(sig)
    bad[35] ^= 0x10
    cr = fresh(c)
    load_field(cr, SET_SECONDPT, pub)
    load_field(cr, SET_HASH, v2b(v['e'], 32))
    load_field(cr, SET_SIG, bytes(bad))
    cr.setst(SIGN_VER)
    chk('KAT', 'sm2: corrupted s -> Failure', not cr.exec_run() and cr.state == FAILURE)
    # t = 0 must be rejected: r + s = n
    cr = fresh(c)
    load_field(cr, SET_SECONDPT, pub)
    load_field(cr, SET_HASH, v2b(v['e'], 32))
    load_field(cr, SET_SIG, v2b(v['r'], 32) + v2b((c.n - v['r']) % c.n, 32))
    cr.setst(SIGN_VER)
    chk('MODEL', 'sm2: t = (r+s) mod n = 0 -> Failure',
        not cr.exec_run() and cr.state == FAILURE)


def test_brainpool():
    head('Brainpool: RFC 5639 parameter validation + k-injected sign -> verify')
    for name in ('brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'):
        c = EC.WEIERSTRASS_CURVES[name]
        chk('PARAM', f'{name}: RFC 5639 parameters -- G satisfies the curve equation,'
            ' n*G = O, h = 1',
            c.is_on_curve(c.G) and c.mul(c.n, c.G) is None and c.h == 1)
        d = 0x0123456789ABCDEF % (c.n - 1) + 1
        d = (d * 0x9E3779B97F4A7C15) % (c.n - 1) + 1      # a fixed, arbitrary key
        k = (d * 7 + 12345) % (c.n - 1) + 1
        cr = fresh(c)
        load_field(cr, SET_SCALAR, v2b(d, cr.fw))
        cr.setst(POINT_MUL)
        Q = cr.exec_run()
        pub = cr.output_all()
        chk('PARAM', f'{name}: Point_Mul d*G is a curve point of the right order',
            c.is_on_curve(Q) and c.mul(c.n, Q) is None)
        e = ecdsa_e(c, hashlib.sha512(name.encode()).digest())
        cr = fresh(c)
        load_field(cr, SET_SCALAR, v2b(d, cr.fw))
        (r, s, _), sig = drive_sign(cr, e, [k])
        # cross-check the signature equation independently of the model
        indep = (c.mul_g(k)[0] % c.n == r
                 and (pow(k, -1, c.n) * (e + r * d)) % c.n == s)
        chk('PARAM', f'{name}: Sign_Generate reproduces the FIPS 186-5 equations', indep)
        cr = fresh(c)
        load_field(cr, SET_SECONDPT, pub)
        load_field(cr, SET_HASH, v2b(e, cr.hashlen))
        load_field(cr, SET_SIG, sig)
        cr.setst(SIGN_VER)
        chk('PARAM', f'{name}: sign -> verify round-trip -> Success',
            cr.exec_run() and cr.state == SUCCESS)
        cr = fresh(c)
        load_field(cr, SET_SECONDPT, pub)
        load_field(cr, SET_HASH, v2b(e ^ 1, cr.hashlen))
        load_field(cr, SET_SIG, sig)
        cr.setst(SIGN_VER)
        chk('PARAM', f'{name}: verify under a modified hash -> Failure',
            not cr.exec_run() and cr.state == FAILURE)
    info('Brainpool anchor level is PARAM, not KAT: RFC 5639 / RFC 8734 publish domain'
         ' parameters but no ECDSA test vectors, so these cases prove parameter'
         ' correctness and self-consistency, not interoperability.')


def test_negative_controls():
    head('Negative controls (declared to run-kats.py as KAT-EXPECT-FAIL)')
    # 1. Ed25519 with the scalar S encoded big-endian instead of little-endian
    c = EC.ED25519
    name, seed_h, pk_h, msg_h, sig_h = RFC8032_ED25519[1]
    seed, msg = bytes.fromhex(seed_h), bytes.fromhex(msg_h)
    cr = fresh(c)
    load_field(cr, SET_SCALAR, seed)
    cr.setst(MSG_ABSORB, form='B', xs=0)
    cr.exec_in(msg)
    cr.setst(MSG_ABSORB, form='B', xs=1)
    cr.exec_in(msg)
    cr.setst(SIGN_GEN)
    cr._eddsa_sign(be_scalar=True)                        # deliberately wrong
    sig = cr.output_all()
    negative('NEG[ed25519-be-scalar]', sig.hex() != sig_h,
             'ed25519 with S encoded big-endian does not match RFC 8032 7.1 TEST 2')
    cr = fresh(c)
    load_field(cr, SET_SECONDPT, bytes.fromhex(pk_h))
    load_field(cr, SET_SIG, sig)
    cr.setst(MSG_ABSORB, form='B', xs=2)
    cr.exec_in(msg)
    cr.setst(SIGN_VER)
    negative('NEG[ed25519-be-scalar-verify]', not cr.exec_run(),
             'ed25519 big-endian-S signature is rejected by Sign_Verify')
    # 2. ECDSA verification with r and s swapped
    c = EC.P256
    vec = RFC6979['secp256r1']
    msg, hname, k, r_exp, s_exp = vec['sigs'][0]
    e = ecdsa_e(c, hashlib.new(hname, msg.encode()).digest())
    pub = v2b(vec['Ux'], 32) + v2b(vec['Uy'], 32)
    cr = fresh(c)
    load_field(cr, SET_SECONDPT, pub)
    load_field(cr, SET_HASH, v2b(e, 32))
    load_field(cr, SET_SIG, v2b(s_exp, 32) + v2b(r_exp, 32))   # swapped
    cr.setst(SIGN_VER)
    negative('NEG[ecdsa-swapped-rs]', not cr.exec_run() and cr.state == FAILURE,
             'secp256r1 verification with r and s swapped')


# ==================================================================== main

def main():
    t0 = time.time()
    print(__doc__.split('\n\n')[0])
    print()
    print('Model built from src/ace-ISA-algorithms.adoc, sections [[ACE-ECC]] and'
          ' [[ACE-EdDSA]].')
    print('Levels: [KAT] published vector | [PARAM] published parameters +'
          ' self-consistency | [MODEL] spec property.')
    print()
    for lab in ('NEG[ed25519-be-scalar]', 'NEG[ed25519-be-scalar-verify]',
                'NEG[ecdsa-swapped-rs]'):
        declare_negative(lab)

    test_parameters()
    test_ecdsa_kats()
    test_p521_representation()
    test_point_mul_validation()
    test_retry_rules()
    test_state_machine()
    test_sign_then_verify_one_cc()
    test_m10_dead_end()
    test_ed25519()
    test_ed448()
    test_sm2()
    test_brainpool()
    test_negative_controls()

    head('Summary')
    missed = _NEG_PENDING - _NEG_FIRED
    for m in sorted(missed):
        print(f'  negative control {m} did not fire')
        _FAILURES.append(m)
    print(f'  runtime {time.time() - t0:.1f} s, {len(_FAILURES)} failing checks')
    ok = not _FAILURES
    if not ok:
        for f in _FAILURES:
            print(f'  failed: {f}')
    print()
    print('KAT-RESULT:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
