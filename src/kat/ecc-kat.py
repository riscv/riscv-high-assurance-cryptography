#!/usr/bin/env python3
"""KATs for the elliptic-curve Machines (<<KLEE-ECC>>, <<KLEE-EdDSA>>): a locker model driven by
kl.setst / kl.exec / kl.derive against RFC 6979, RFC 8032, GM/T 0003.5 and RFC 5639 data.
The RBG draw of k is injected (RFC 6979's deterministic k)."""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, section, check, control, info, raises, done,  # noqa: E402
                    IllegalInstruction, KL_STATE_READY as READY, KL_STATE_SUCCESS as SUCCESS,
                    KL_STATE_FAILURE as FAILURE, KL_STATE_HASH_ABSORB as HASH_ABSORB)
import ecc_curves as EC                                                                # noqa: E402

(SET_GEN, SET_SCALAR, POINT_MUL, SIGN_GEN, SIGN_VER, SET_HASH, SET_SECONDPT, SET_SIG,
 OUTPUT, MSG_ABSORB, SET_CTX) = range(2, 13)
SET_FIELD = {SET_GEN: 'gen', SET_SCALAR: 'scalar', SET_HASH: 'hash', SET_SECONDPT: 'sec', SET_SIG: 'sig'}
# <<KLEE-ECC>> Parameters: b, h, j, u, v
PARAMS = {'secp256r1': (256, 256, 256, 2, 2), 'secp384r1': (384, 384, 384, 2, 2),
          'secp521r1': (576, 576, 576, 2, 2), 'brainpoolP256r1': (256, 256, 256, 2, 2),
          'brainpoolP384r1': (384, 384, 384, 2, 2), 'brainpoolP512r1': (512, 512, 512, 2, 2),
          'sm2p256v1': (256, 256, 256, 2, 2), 'ed25519': (256, 512, 0, 1, 2),
          'ed448': (456, 512, 0, 1, 2)}
MSB_ZERO = {'secp521r1': 55}
MDH0 = dict(UsagePolicy=0, ExpirationDate=0, SCProtection=0, KeyType=0)

class Invalid(Exception):
    """Transition to Error State _Invalid_; `who` names the kl.derive endpoint(s)."""
    def __init__(self, msg='', who=None):
        super().__init__(msg)
        self.who = who

def targets(state, eddsa, sig_exit=True):
    """kl.setst targets: <<KLEE-ECC>> transitions, <<KLEE-EdDSA>> changes, SGR4, SGR8."""
    entry = set(SET_FIELD) | ({SET_CTX} if eddsa else set())
    free = entry - (set() if sig_exit else {SET_SIG})
    ops, absorb = {POINT_MUL, SIGN_GEN, SIGN_VER}, {MSG_ABSORB} if eddsa else set()
    if state == READY:
        t = entry | ops | absorb
    elif state in free or (eddsa and state == MSG_ABSORB):
        t = free | ops | absorb | {READY}
    elif state in (POINT_MUL, SIGN_GEN):
        t = {OUTPUT, READY}
    else:
        t = {READY} if state in (OUTPUT, SIGN_VER, SUCCESS, FAILURE) else set()
    return t | ({state} if state not in (SUCCESS, FAILURE) else set())

def retry_required(mode, r, s, k, n): return r == 0 or s == 0 or (mode == 'sm2' and (r + k) % n == 0)

class Unsupported(Exception):
    """kl_exc_unsupported at provisioning or import (<<KLEE-Metadata-validity>>)."""

class Locker:
    def __init__(self, c, sign=True, verify=True, sig_exit=True, aux_info=None, pure_impl=True):
        """aux_info: <<KLEE-EdDSA>> _AuxInfo_ (0 pre-hash only, 1 pure as well; default 1 for EdDSA);
        pure_impl: the implementation offers pure mode for the curve."""
        self.c, self.policy, self.sig_exit = c, (sign, verify), sig_exit
        self.aux_info = (1 if c.edwards else 0) if aux_info is None else aux_info
        if c.edwards and (self.aux_info > 1 or self.aux_info == 1 and not pure_impl):
            raise Unsupported('EdDSA _AuxInfo_ reserved, or pure mode not offered')
        self.b, h, self.j, u, v = PARAMS[c.name]
        self.mode = 'eddsa' if c.edwards else 'sm2' if c is EC.SM2C else 'ecdsa'
        fw = self.fw = self.b // 8
        self.size = dict(gen=u * fw, sec=u * fw, scalar=fw, hash=h // 8, sig=v * fw)
        self.default_gen = self.gen = self.enc(c.G)
        self.scalar, self.sec, self.sig, self.hash, self.rnd = bytes(fw), None, None, None, None
        self.has, self.out_type, self.progress, self.bb, self.loading = set(), False, 0, 0, None
        self.msg_pass, self.ctx, self.absorb, self.pass_xs, self.r, self.kp = 0, b'', None, None, None, None
        self.mdh, self.state = dict(MDH0), READY

    # points: little-endian coordinates; the point at infinity has no encoding
    def enc(self, P):
        assert P is not None
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
    def machine_use(self):              # <<KLEE-ECC-MachineUse>>
        return int(self.out_type) | self.progress << 1

    def discard(self):                  # MGR8
        self.progress, self.rnd = 0, None
        self.has.discard('rnd')

    def halt(self, progress=1, k=None):
        """Precise halt of the current long-running kl.exec (IRR4)."""
        if self.state not in (POINT_MUL, SIGN_GEN, SIGN_VER) or not 0 < progress < 1 << 13:
            raise Invalid('no long-running operation / bad Progress')
        if self.state == SIGN_GEN and self.mode != 'eddsa':
            self.rnd = v2b(k, self.j // 8)
            self.has.add('rnd')
        self.progress = progress

    def setst(self, t, xs=0, rand=None):
        """kl.setst #t; Form A is modelled as xs = 0."""
        if t in (SUCCESS, FAILURE):
            raise IllegalInstruction                                  # SGR7
        if t not in targets(self.state, self.mode == 'eddsa', self.sig_exit):
            raise Invalid('transition not allowed')                   # MGR1
        if self.state == MSG_ABSORB:
            self._finalize_pass()
        f = self.loading
        if f and self.bb < self.size[f]:            # MGR7: a load left incomplete leaves the field unconfigured
            if f == 'ctx':
                self.ctx, self.size['ctx'] = b'', 0
            else:
                setattr(self, f, bytes(self.size[f]) if f in ('gen', 'scalar') else None)
                self.has.discard(f)
        self.discard()
        self.bb, self.loading, self.buf = 0, None, b''
        f = SET_FIELD.get(t)
        if f == 'scalar':
            self.scalar = v2b(rand, self.fw) if xs else bytes(self.fw)   # Form B: drawn inside, never loaded
        elif f == 'gen' and not xs:
            self.gen = self.default_gen
        elif f in ('sec', 'hash', 'sig'):
            setattr(self, f, None)
            self.has.discard(f)
        if f and (xs or f != 'gen') and not (xs and f == 'scalar'):
            self.loading = f
        elif t == SET_CTX:
            if xs > 255:
                raise Invalid('ctxlen > 255')
            self.ctx, self.size['ctx'], self.loading = b'', xs, 'ctx' if xs else None
        elif t == MSG_ABSORB:
            self._enter_pass(xs)
        elif t == SIGN_GEN:
            if not self.policy[0]:
                raise Invalid('MachinePolicy[0] clear')
            if self.mode == 'eddsa':
                if not any(self.scalar) or not (self.msg_pass == 2 or self.msg_pass == 0 and 'hash' in self.has):
                    raise Invalid('no seed, or neither pure nor pre-hash path')
            elif 'hash' not in self.has or not 1 <= b2v(self.scalar) < self.c.n:
                raise Invalid('HasHash and a configured private key required')
        elif t == SIGN_VER:
            if not self.policy[1]:
                raise Invalid('MachinePolicy[1] clear')
            if not (self.msg_pass == 3 or self.msg_pass == 0 and 'hash' in self.has if self.mode == 'eddsa'
                    else {'sec', 'hash', 'sig'} <= self.has):
                raise Invalid('EdDSA: neither pure nor pre-hash path; else HasSecondPt, HasHash, HasSignature')
        elif t == READY:
            self._ready(xs)
        self.state = t

    def _ready(self, xs):
        """Ready-return Xs bits; a set bit discards (bits 4, 5: copies), a clear bit retains."""
        if xs & 16:
            self.sec = self.gen
            self.has.add('sec')
        if xs & 32 and 'sec' in self.has:
            self.gen = self.sec
        if xs & 1:
            self.gen = self.default_gen
        if xs & 4:
            self.scalar = bytes(self.fw)
        for bit, f in ((2, 'sec'), (8, 'hash'), (64, 'sig')):
            if xs & bit:
                setattr(self, f, None)
                self.has.discard(f)
        self.msg_pass, self.ctx, self.r, self.kp = 0, b'', None, None

    def exec_in(self, data):
        """Form B kl.exec: MGR7 loading with W = block_base, or message absorption."""
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
        # secp521r1: the zero msbs of every value used are checked again (MGR16: KLF corruption)
        used = {POINT_MUL: ('scalar', 'sec' if 'sec' in self.has else 'gen'),
                SIGN_GEN: ('scalar', 'hash', 'gen') + ('rnd',) * bool(self.progress and 'rnd' in self.has),
                SIGN_VER: ('sig', 'hash', 'sec', 'gen')}.get(self.state, ())
        if any(getattr(self, f) is not None and not self.repr_ok(getattr(self, f)) for f in used):
            raise Invalid('msbs not zero when used')
        if self.state == POINT_MUL:
            return self._point_mul()
        if self.state == SIGN_GEN:
            if self.mode != 'eddsa' and not self.valid(self.gen):   # MGR15; EdDSA signs over B
                return self._fail()
            return self._eddsa_sign(be) if self.mode == 'eddsa' else self._sign(rbg, bad)
        if self.state == SIGN_VER:
            ok = self._eddsa_verify() if self.mode == 'eddsa' else self.valid(self.gen) and self._verify()
            self.discard()
            self.state = SUCCESS if ok else FAILURE
            return ok
        raise Invalid('Form D kl.exec not expected')

    def _to_output(self, out_type, f):
        self.has.add(f)
        self.discard()
        self.out_type, self.bb, self.state = out_type, 0, OUTPUT

    def valid(self, data):
        """<<KLEE-ECC>> valid point: on the curve, not the point at infinity, in the prime-order subgroup."""
        P = self.dec(data)
        return P is not None and self.c.in_subgroup(P)

    def _fail(self):                                # MGR15 data error: _Failure_, a Valid State
        self.discard()
        self.state = FAILURE

    def _point_mul(self):
        k = b2v(self.scalar)                        # <<KLEE-EdDSA>>: s from the configured seed
        if not k or self.mode != 'eddsa' and k >= self.c.n:
            raise Invalid('no configured seed / Scalar out of range')
        base = self.sec if 'sec' in self.has else self.gen
        if not self.valid(base):                    # not a valid point: data error (MGR15)
            return self._fail()
        P = self.dec(base)
        R = self.c.mul(self.keys()[0] if self.mode == 'eddsa' else k, P)
        self.sec = self.enc(R)
        self._to_output(False, 'sec')
        return R

    def _sign(self, rbg, bad):
        c, n, d, e = self.c, self.c.n, b2v(self.scalar), b2v(self.hash)
        G = self.dec(self.gen)                      # the base point is `Generator`, not the curve's default
        draws = iter(([b2v(self.rnd)] if self.progress and 'rnd' in self.has else []) + list(rbg))
        attempt = 0
        while True:
            k = next(draws, None)
            if k is None:                           # GR12: RBG failure
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
        self._to_output(True, 'sig')
        return r, s, attempt

    def _verify(self):
        c, n = self.c, self.c.n
        r, s, e, Q = b2v(self.sig[:self.fw]), b2v(self.sig[self.fw:]), b2v(self.hash), self.dec(self.sec)
        if not (1 <= r < n and 1 <= s < n) or Q is None or not c.in_subgroup(Q):
            return False
        G = self.dec(self.gen)                      # verification over `Generator` too
        if self.mode == 'sm2':
            t = (r + s) % n
            X = c.add(c.mul(s, G), c.mul(t, Q)) if t else None
            return X is not None and (e + X[0]) % n == r
        w = pow(s, -1, n)
        X = c.add(c.mul(e * w % n, G), c.mul(r * w % n, Q))
        return X is not None and X[0] % n == r

    def exec_out(self, nbytes, pad=False):
        """Form C kl.exec in _Output_, then _Success_; MGR7: carrying W past the field invalidates
        (`pad`: a kl.derive source, zero-padded under DER8)."""
        if self.state != OUTPUT:
            raise Invalid('output transfer outside _Output_')
        buf = self.sig if self.out_type else self.sec
        if self.bb + nbytes > len(buf) and not pad:
            raise Invalid('emitting kl.exec past the end of the field (MGR7)')
        chunk = buf[self.bb:self.bb + nbytes]
        self.bb += nbytes
        if self.bb >= len(buf):
            self.state = SUCCESS
        return chunk + bytes(nbytes - len(chunk))

    def output_all(self, chunk=1 << 10):
        n, out = len(self.sig if self.out_type else self.sec), b''
        while self.state == OUTPUT:                  # the final transfer is exactly the remainder
            out += self.exec_out(min(chunk, n - self.bb))
        return out

    # <<KLEE-EdDSA>>
    def H(self, data):
        return hashlib.sha512(data).digest() if self.c is EC.ED25519 else hashlib.shake_256(data).digest(114)

    def dom(self, x):
        if self.c is EC.ED448:
            return b'SigEd448' + bytes([x, len(self.ctx)]) + self.ctx
        return b'SigEd25519 no Ed25519 collisions' + bytes([x, len(self.ctx)]) + self.ctx if x or self.ctx else b''

    def keys(self):
        """(clamped s, prefix, encoded A) from the seed, RFC 8032 5.1.5 / 5.2.5."""
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
            self.msg_pass, self.absorb = 0, self.dom(0) + self.keys()[1]
        elif xs == 1 and self.msg_pass == 1:
            self.absorb = self.dom(0) + self.sig[:self.fw] + self.keys()[2]
        elif xs == 2 and self.policy[1] and {'sig', 'sec'} <= self.has:
            self.msg_pass, self.absorb = 0, self.dom(0) + self.sig[:self.fw] + self.sec
        else:
            raise Invalid(f'Msg_Absorb Xs = {xs}: precondition unmet')
        self.pass_xs = xs

    def _finalize_pass(self):
        xs, data, self.absorb, self.pass_xs = self.pass_xs, self.absorb, None, None
        val = b2v(self.H(data)) % self.c.L
        if xs == 0:
            self.r, self.msg_pass = val, 1
            self.sig = self.c.encode(self.c.mul_g(val)) + bytes(self.fw)   # HasSignature not set
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
        self._to_output(True, 'sig')
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

section('secp521r1: 576-bit fields with 55 zero msbs, checked at load and at use')
c, V521 = EC.P521, 12345
G521, Q521, H7 = Locker(c).gen, pt(c, c.mul_g(V521)), hs(7, 72)
check('default Generator: 144 bytes, 55 zero msbs per coordinate', Locker(c).repr_ok(G521) and len(G521) == 144)
for label, st, data in (('Scalar with bit 521 set', SET_SCALAR, v2b(1 << 521, 72)),
                        ('SecondPt with bit 575 set', SET_SECONDPT, v2b(c.G[0] | 1 << 575, 72) + v2b(c.G[1], 72)),
                        ('all-ones SecondPt (no infinity sentinel any more)', SET_SECONDPT, b'\xff' * 144)):
    check(f'{label} -> Invalid at load', invalid(load, Locker(c), st, data))
(r, s), sig521, _, _ = sign(c, V521, 7, [99])
for label, st, f, loads, rbg in (               # bit 575 set by a corruption of the locker file (MGR16)
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
    check(f'Scalar = {label} -> Invalid', invalid(locker(P256, sc(k), to=POINT_MUL).exec_run))
for label, k, want in (('n-1: accepted, result -G', P256.n - 1, (P256.G[0], P256.p - P256.G[1])),
                       ('2: accepted, result G+G', 2, P256.add(P256.G, P256.G))):
    cr = locker(P256, sc(k), to=POINT_MUL)
    check(f'Scalar = {label}', (cr.exec_run(), cr.state) == (want, OUTPUT))
off = v2b(P256.G[0], 32) + v2b(P256.G[1] + 1, 32)
cr = locker(P256, sc(2), (SET_SECONDPT, off), to=POINT_MUL)
cr.exec_run()
check('off-curve SecondPt in _Point_Mul_ -> Failure (MGR15 data error), SecondPt unchanged',
      (cr.state, cr.sec) == (FAILURE, off))
check('Sign_Verify with an off-curve public key -> Failure', verify(P256, off, 1, v2b(1, 32) * 2) == FAILURE)
cr = locker(P256, sc(2), (SET_SECONDPT, b'\xff' * 64), to=POINT_MUL)
cr.exec_run()
check('all-ones SecondPt (formerly the infinity sentinel) as base point -> Failure', cr.state == FAILURE)
cr = locker(P256, sc(2), (SET_GEN, off), to=POINT_MUL)
cr.exec_run()
check('off-curve Generator in _Point_Mul_ -> Failure', cr.state == FAILURE)
cr = locker(P256, sc(2), (SET_GEN, Locker(P256).gen[:40]), to=POINT_MUL)
cr.exec_run()
check('Generator load left incomplete: Generator zeroed (MGR7), not a valid point: _Point_Mul_ -> Failure',
      cr.state == FAILURE and cr.gen == bytes(64))
cr = locker(P256, (SET_SCALAR, v2b(5, 32)[:16]), to=POINT_MUL)
check('Scalar load left incomplete: Scalar zeroed (MGR7), _Point_Mul_ -> Invalid',
      cr.scalar == bytes(32) and invalid(cr.exec_run))
cr = locker(P256, (SET_SECONDPT, pt(P256, P256.mul_g(3))[:32]), to=SET_HASH)
check('SecondPt load left incomplete for another Set state: zeroed, HasSecondPt clear (MGR7)',
      cr.sec is None and 'sec' not in cr.has and cr.state == SET_HASH)
cr = locker(P256, sc(5), (SET_GEN, off), hs(7, 32), to=SIGN_GEN)
cr.exec_run([3])
check('RBG failure in _Sign_Generate_ -> Invalid (GR12)',
      invalid(locker(P256, sc(5), hs(7, 32), to=SIGN_GEN).exec_run, []))
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
check('SM2: retry iff r = 0, r + k = n or s = 0',
      [retry_required('sm2', *a, n) for a in ((0, 5, 7), (5, 0, 7), (5, 5, n - 5), (5, 5, 7))]
      == [True, True, True, False])
rs, _, att, cr = sign(P256, V256['x'], E0, [0x1234, K0], bad=lambda a: a == 0)
check('degenerate first draw: a fresh k is drawn (RFC 6979 answer)', (att, rs) == (1, (R0, S0)))
check('RndNum destroyed, HasRndNum clear after signing', cr.rnd is None and 'rnd' not in cr.has)

def armed(): return locker(P256, (SET_SCALAR, D256), hs(E0), to=SIGN_GEN)
def cleared(cr): return (cr.progress, cr.rnd, 'rnd' in cr.has) == (0, None, False)

section('Progress and <<KLEE-MGR-progress-discard>>')
cr = armed()
check('Progress zero when nothing is interrupted', cr.machine_use == 0)
cr.halt(0x1234, K0)
check('halt: Progress non-zero in MachineUse[13:1], RndNum kept, State unchanged',
      (cr.machine_use, b2v(cr.rnd), 'rnd' in cr.has, cr.state) == (0x1234 << 1, K0, True, SIGN_GEN))
check('resume uses the held RndNum, draws nothing', None, cr.exec_run([])[:3], (R0, S0, 0))
check('completion zeroes Progress, destroys RndNum', cleared(cr))
for t in (READY, OUTPUT, SIGN_GEN):
    cr = armed()
    cr.halt(7, K0)
    cr.setst(t)
    check(f'kl.setst #{t} from a halted Sign_Generate discards Progress and RndNum', cleared(cr))
cr = armed()
cr.halt(9, 0xDEAD)
cr.setst(READY)
cr.setst(SIGN_GEN)
check('after the discard the operation draws afresh', cr.exec_run([K0])[:2] == (R0, S0))
cr = locker(P256, (SET_SCALAR, D256), to=POINT_MUL)
cr.halt(0x1FFF)
check('halted Point_Mul resumes to d*G, Progress zero after',
      (cr.exec_run(), cr.progress) == (P256.mul_g(V256['x']), 0))
cr = locker(P256, (SET_SCALAR, D256), to=POINT_MUL)
check('Progress at a halt is non-zero and fits [13:1]', invalid(cr.halt, 0) and invalid(cr.halt, 0x2000))
cr.out_type = True
cr.halt(0x1FFF)
check('OutputType | Progress << 1 fits the 14-bit _MachineUse_', cr.machine_use == (1 << 14) - 1)
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
        ('MachinePolicy[1] clear: Sign_Verify', dict(verify=False), [(SET_SECONDPT, PUB256), H1, (SET_SIG, SIG0)],
         SIGN_VER),
        ('Ready -> Output (MGR1)', {}, [], OUTPUT)):
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
cr = Locker(P256)
cr.setst(SET_SCALAR, xs=1, rand=V256['x'])
check('Form B Set_Scalar: random private key set, no kl.exec expected',
      b2v(cr.scalar) == V256['x'] and invalid(cr.exec_in, D256))
cr = locker(P256, sc(2), to=POINT_MUL)
cr.exec_run()
check('Output: block_base-tracked, 24 + 24 + 16 bytes, then Success',
      b''.join(cr.exec_out(n) for n in (24, 24, 16)) == cr.sec and cr.state == SUCCESS)
cr = locker(P256, sc(2), to=POINT_MUL)
cr.exec_run()
cr.exec_out(24), cr.exec_out(24)
check('Output: a final 24-byte kl.exec past the 64-byte field -> Invalid (MGR7)', invalid(cr.exec_out, 24))
for t in (SUCCESS, FAILURE):
    cr = Locker(P256)
    check(f'kl.setst #{t}: illegal instruction, State unchanged (SGR7)', raises(cr.setst, t) and cr.state == READY)
cr = locker(P256, sc(2), to=POINT_MUL)
cr.halt(3)
cr.setst(POINT_MUL)
check('same-State kl.setst admitted (SGR4), zeroes Progress (MGR8)', (cr.state, cr.progress) == (POINT_MUL, 0))

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
control('Set_Signature without exits: Sign_Verify unreachable, kl.setst -> Invalid',
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
        (34, dict(gen=G1, sec=None), 'bits 5+1: copy, then SecondPt erased')):
    cr = locker(P256, (SET_GEN, G2), (SET_SECONDPT, G1), sc(7), hs(0), (SET_SIG, SIG0))
    cr.setst(READY, xs)
    check(label, None, dict(gen=cr.gen, scalar=b2v(cr.scalar),
                            **{f: getattr(cr, f) if f in cr.has else None for f in ('sec', 'hash', 'sig')}),
          {**BASE, **change})

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

section('Ed25519 / Ed25519ph: RFC 8032 7.1, 7.3')
c = EC.ED25519
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
check('ctx load left incomplete (4 of 10 bytes): ctx and ctxlen zeroed (MGR7)', (cr.ctx, cr.size['ctx']) == (b'', 0))
check('_AuxInfo_ = 1 without pure mode, or a reserved _AuxInfo_ (2): kl_exc_unsupported at provisioning', True,
      [raises(Locker, c, aux_info=1, pure_impl=False, exc=Unsupported), raises(Locker, c, aux_info=2, exc=Unsupported)],
      [True, True])
ph2, sigs = hashlib.sha512(msg).digest(), []
for kw in ({}, dict(aux_info=0, pure_impl=False)):
    cr = locker(c, (SET_SCALAR, seed), (SET_HASH, ph2, 32), to=SIGN_GEN, **kw)
    cr.exec_run()
    sigs.append(cr.output_all())
cr = locker(c, (SET_SCALAR, seed), aux_info=0, pure_impl=False)
check('_AuxInfo_ = 0 (pre-hash only), also without pure mode in the implementation: provisioned, '
      'the same pre-hash signature; _Msg_Absorb_ -> Invalid', sigs[0] == sigs[1] and invalid(cr.setst, MSG_ABSORB, 0))

section('Ed448: RFC 8032 7.4 (dom4, ctx, 57-byte encodings)')
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
    """A non-ECC destination: a `key` in _Ready_, a hash in _Hash_Absorb_, or 'none' (no destination
    endpoint, e.g. ML-DSA)."""
    def __init__(self, kind, state=None, size=32, **mdh):
        self.kind, self.size, self.data, self.mdh = kind, size, b'', {**MDH0, **mdh}
        self.state = state or (HASH_ABSORB if kind == 'hash' else READY)

class HashSrc:
    """A hash in _Hash_Output_: a DER6 source whose kl.exec output is `out` (its MDH: `mdh`)."""
    def __init__(self, out, **mdh):
        self.sig, self.bb, self.has, self.out_type, self.mdh = out, 0, set(), True, mdh

    def exec_out(self, n, pad=False):
        self.bb += n
        return self.sig[self.bb - n:self.bb].ljust(n, b'\0')

def kl_derive(dest, src, length):
    """ECC source by State (<<KLEE-derive-endpoints>>): `SecondPt` wherever HasSecondPt is set, except _Output_
    with OutputType = True, whose (signature) kl.exec output is the source (DER6); or a HashSrc."""
    ecc, kdf = isinstance(dest, Locker), isinstance(src, HashSrc)
    field = 'sec' in src.has and not (src.state == OUTPUT and src.out_type)
    kind = 'scalar' if ecc else dest.kind
    if not field and not kdf and src.state != OUTPUT:
        raise Invalid(who='source')                                 # DER1 items 1-2: source first
    if kind == 'none' or dest.state != {'scalar': SET_SCALAR, 'key': READY}.get(kind, HASH_ABSORB) \
            or kind != 'hash' and dest.mdh['KeyType'] == 1:
        raise Invalid(who='destination')                            # DER1 items 1-2; DER4
    if kind == 'key' and not field and not kdf:
        raise Invalid(who='both')                                   # DER1 item 3: DER6 is hash/MAC/XOF only
    if kind != 'hash':
        size = dest.fw if ecc else dest.size
        if length < size or (len(src.sec) if field else len(src.sig) - src.bb) < size:
            raise Invalid(who='destination')                        # DER1 item 5
    if field:                                                       # DER5 restricted, also into a hash: DER2
        s, d = src.mdh, dest.mdh
        if d['SCProtection'] < s['SCProtection']:
            raise Invalid(who='destination')
        d['UsagePolicy'] = (s['UsagePolicy'] | d['UsagePolicy']) & 0xF | s['UsagePolicy'] & d['UsagePolicy'] & 0x10
        d['ExpirationDate'] = min([x for x in (s['ExpirationDate'], d['ExpirationDate']) if x] or [0])
    if kind == 'hash':                                              # DER8
        dest.data += src.sec[:length].ljust(length, b'\0') if field else src.exec_out(length, pad=True)
        return
    data = src.sec[:size] if field else src.exec_out(size, pad=True)
    if ecc:
        if not dest.repr_ok(data):                                  # MGR17: checked when written
            raise Invalid('Scalar violates the b-bit representation', who='destination')
        dest.scalar, dest.bb = data, size                           # DER8: as a completing kl.exec
    else:
        dest.data = data

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

def with_second(sign=False):            # HasSecondPt in _Set_SecondPt_, or after signing
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

section('kl.derive: ECC endpoints (<<KLEE-derive-endpoints>>)')
db = 0x1D5A0B2C3E4F
cr, Z = ecdh()
check('ECDH: SecondPt = d_A * Q_B', Z == P256.mul(db, P256.mul_g(V256['x'])))
h = Dest('hash')
kl_derive(h, cr, 64)
check('in _Output_ with OutputType = False: SecondPt (a field) into a hash, source not advanced',
      (h.data, cr.state, cr.bb) == (cr.sec, OUTPUT, 0))
cr.output_all()
h = Dest('hash', UsagePolicy=5)
kl_derive(h, cr, 0)
check('length = 0 transfers nothing (DER8)', h.data == b'' and cr.state == SUCCESS)
kl_derive(h, cr, 80)
check('in _Success_ with HasSecondPt: 80 bytes into a hash, zero-padded (DER8)',
      (h.data, cr.state) == (cr.sec + bytes(16), SUCCESS))
cr, _ = ecdh(UsagePolicy=0b00010, ExpirationDate=700)
h = Dest('hash', UsagePolicy=0b10101, ExpirationDate=900)
kl_derive(h, cr, 64)
check('SecondPt into a hash is restricted (DER5): the hash locker is narrowed (DER2)', True,
      (h.mdh['UsagePolicy'], h.mdh['ExpirationDate'], h.data), (0b0111, 700, cr.sec))
cr, _ = ecdh(UsagePolicy=0b10011, ExpirationDate=900, SCProtection=1)
k = Dest('key', UsagePolicy=0b10100, ExpirationDate=1200, SCProtection=2)
kl_derive(k, cr, 64)
check('SecondPt into an AES-256 `key` in _Ready_: first 32 bytes, MDH narrowed (DER5, DER2)',
      (k.data, k.mdh['UsagePolicy'], k.mdh['ExpirationDate']) == (cr.sec[:32], 0b10111, 900))
cr, Z = ecdh(UsagePolicy=0b00011, ExpirationDate=900)
d = scalar_dest(UsagePolicy=0b00100)
kl_derive(d, cr, 64)
check('SecondPt into another ECC `Scalar` in _Set_Scalar_: x(Z), field complete, MDH narrowed (DER5)',
      (b2v(d.scalar), d.mdh['UsagePolicy'], d.mdh['ExpirationDate']) == (Z[0], 0b00111, 900)
      and invalid(d.exec_in, b'\0'))
d.setst(POINT_MUL)
check('the derived Scalar drives _Point_Mul_: x(Z) * G', d.exec_run() == P256.mul_g(Z[0]))
cr, d = signing(UsagePolicy=0b00011), scalar_dest()
kl_derive(d, cr, 64)
check('signature output into an ECC `Scalar`: r, source advanced as by Form C, not narrowed',
      (d.scalar, cr.bb, cr.state, d.mdh['UsagePolicy']) == (cr.sig[:32], 32, OUTPUT, 0))
sp, k = with_second(), Dest('key')
kl_derive(k, sp, 64)
check('in _Set_SecondPt_ with HasSecondPt: SecondPt into a `key` (DER5)', k.data == sp.sec[:32])
sp, h = with_second(sign=True), Dest('hash')
kl_derive(h, sp, 64)
check('signature _Output_ with HasSecondPt: the source is the kl.exec output (r || s), never SecondPt',
      (h.data, sp.bb) == (sp.sig, 64) and 'sec' in sp.has)
for label, dest, src, n, who in (
        ('source without HasSecondPt', Dest('hash'), locker(P256, hs(0, 0)), 64, 'source'),
        ('hash destination in _Ready_', Dest('hash', READY), ecdh()[0], 64, 'destination'),
        ('key destination outside _Ready_', Dest('key', HASH_ABSORB), ecdh()[0], 64, 'destination'),
        ('key with length < key size (DER1 item 5)', Dest('key'), ecdh()[0], 16, 'destination'),
        ('key with lower SCProtection (DER2)', Dest('key'), ecdh(SCProtection=1)[0], 64, 'destination'),
        ('key of KeyType 1 (DER4)', Dest('key', KeyType=1), ecdh()[0], 64, 'destination'),
        ('ECC Scalar of KeyType 1 (DER4)', scalar_dest(KeyType=1), ecdh()[0], 64, 'destination'),
        ('ECC destination in _Ready_', scalar_dest(READY), ecdh()[0], 64, 'destination'),
        ('ECC Scalar with length < b/8 (DER1 item 5)', scalar_dest(), ecdh()[0], 31, 'destination'),
        ('Machine without a destination endpoint', Dest('none'), ecdh()[0], 64, 'destination'),
        ('signature output into a `key` (not hash/MAC/XOF output: DER1 item 3)', Dest('key'), signing(), 64, 'both'),
        ('signature output with HasSecondPt into a `key` (DER1 item 3)', Dest('key'), with_second(True), 64, 'both')):
    check(f'{label} -> Invalid ({who}), nothing transferred',
          derive_who(dest, src, n) == who and not any(dest.scalar if isinstance(dest, Locker) else dest.data))
dg = hashlib.sha256(b'KLEE kl.derive').digest()
d, k = scalar_dest(), Dest('key')
kl_derive(d, HashSrc(dg, UsagePolicy=0b10011), 64)
kl_derive(k, HashSrc(hashlib.sha512(dg).digest(), UsagePolicy=0b10011), 40)
d.setst(POINT_MUL)
d521, ok521 = locker(EC.P521, to=SET_SCALAR), locker(EC.P521, to=SET_SCALAR)
top, fine = bytes(71) + b'\x02', v2b(12345, 72)                 # bit 569 set / a 14-bit value
check('MGR17: a kl.derive into a secp521r1 `Scalar` with a top bit set: destination _Invalid_; a value with the '
      '55 msbs zero is accepted', True,
      (derive_who(d521, HashSrc(top), 72), derive_who(ok521, HashSrc(fine), 72), ok521.scalar),
      ('destination', None, fine))
check('DER6 key derivation: SHA-256 output -> ECC `Scalar` in _Set_Scalar_ (b/8 bytes), SHA-512 output -> AES-256 '
      '`key` (first 32 B); unrestricted, not narrowed; the Scalar drives _Point_Mul_', True,
      (d.mdh['UsagePolicy'], k.data, k.mdh['UsagePolicy'], d.exec_run()),
      (0, hashlib.sha512(dg).digest()[:32], 0, P256.mul_g(b2v(dg))))
info('reading: SecondPt is a field source (DER8 truncation / zero-pad, source State unchanged), '
     'the DER5 shared secret.')

section('Negative controls')
seed, pk, msg, sig = map(bytes.fromhex, RFC8032_ED25519[1][1:])
bad = ed_sign(EC.ED25519, seed, msg, be=True)[0]
control('ed25519 S encoded big-endian differs from RFC 8032 7.1 TEST 2', bad != sig)
control('ed25519 big-endian S rejected by Sign_Verify', ed_verify(EC.ED25519, pk, bad, msg) == FAILURE)
control('secp256r1 (s, r) swapped -> Failure', verify(P256, PUB256, E0, v2b(S0, 32) + v2b(R0, 32)) == FAILURE)

done()
