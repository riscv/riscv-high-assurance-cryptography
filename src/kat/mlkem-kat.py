#!/usr/bin/env pypy3.12
"""ML-KEM Machines (Type 11, Modes 0-2) KAT: Zkl-ISA-machines.adoc KLE-PQC-ML-KEM.

Run: cd src && pypy3.12 kat/mlkem-kat.py
Expected values come from FIPS 203 (own implementation, mlkem_model.py) and from an independent oracle:
OpenSSL 3.5.9 ML-KEM (key generation from d||z, encapsulation, decapsulation incl. implicit rejection), whose
outputs were compared byte for byte with the model for 2 seeds per parameter set; the VEC table below stores
the seeds, the message m recovered from the OpenSSL ciphertext, SHA-256 digests of ek, dk, ct, and the keys K.
The Machine itself is an abstract executable reading of the State Machine text (setst / load / emit / exec /
derive); the ISA layer (SEW, KLIOBUF, ADS, export/import, GR57 halting and resumption) is NOT modelled.
Every group of checks is also run against a Machine with one deliberate fault: it must then fail (controls).
"""
import sys, hashlib
from common import *
import mlkem_model as M

NAMES = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']
S_GEN, S_ENC, S_DEC, S_EIN, S_DIN, S_EOUT, S_CIN, S_COUT, S_SOUT = range(2, 11)
ALLOWED = {1, 2, 3, 4, 5, 6, 7, 8, 9}      # kl.setst targets (not _sharedkey_Output_, not Failure)
SPEC_SIZES = {'ML-KEM-512': (800, 1632, 768, 32), 'ML-KEM-768': (1184, 2400, 1088, 32), 'ML-KEM-1024': (1568, 3168, 1568, 32)}
sha = lambda b: hashlib.sha256(bytes(b)).hexdigest()

class RBGFail(Exception): pass
class RBG:
    """Scripted RBG: returns the queued byte strings in order; fail=True models a dead entropy source."""
    def __init__(s, *q, fail=False): s.q, s.fail = list(q), fail
    def read(s, n):
        if s.fail or not s.q: raise RBGFail()
        r = s.q.pop(0); assert len(r) == n; return r

class Mach:
    def __init__(s, mode, rbg=None, policy=0, faults=(), limit=None):
        s.mode, s.p, s.rbg, s.f, s.limit = mode, NAMES[mode], rbg, set(faults), limit
        s.k = M.PARAMS[s.p][0]; s.sz = M.SIZES[s.p]; s.eo = 384 * s.k
        s.err = SE_UNSUPPORTED if policy else None      # MachinePolicy != 0: unsupported Metadata
        s.dk, s.ct, s.ss = bytearray(s.sz[1]), bytearray(s.sz[2]), bytearray(32)
        s.he = s.hd = s.hc = s.hs = 0; s.W = 0; s.st = 0 if policy else ST_READY
    # ---- observation
    def ext(s): return s.he | s.hd << 1 | s.hc << 2 | s.hs << 3
    def mdh(s):
        return mdh_pack(Machine=0xB0 | s.mode, State=s.st, MachineUse=s.W,
                        StateExtension=s.err if s.st == 0 else s.ext())
    def serialized(s): return bytes(s.dk) + bytes(s.ct) + bytes(s.ss)
    # ---- helpers
    def _clear(s): s.dk[:] = bytes(s.sz[1]); s.ct[:] = bytes(s.sz[2]); s.ss[:] = bytes(32); s.he = s.hd = s.hc = s.hs = 0
    def _invalid(s):
        s.st, s.err = 0, SE_INVALID
        if 'noclear' not in s.f: s._clear()                # GR36: Content cleared on transition to an Error State
    def setste(s, e):
        """kl.setste: any State, Error State e (GR37)."""
        s.st, s.err = 0, e
        if 'noclear' not in s.f: s._clear()
    def _fail(s): s.st, s.W = ST_FAILURE, 0
    def _fsize(s, st): return {S_EIN: s.sz[0], S_EOUT: s.sz[0], S_DIN: s.sz[1], S_CIN: s.sz[2], S_COUT: s.sz[2]}[st]
    def _zss(s): s.ss[:] = bytes(32); s.hs = 0
    def _zfield(s, st):
        if st == S_EIN: s.dk[:] = bytes(s.sz[1]); s.he = s.hd = 0
        elif st == S_DIN: s.dk[:] = bytes(s.sz[1]); s.he = s.hd = 0
        elif st == S_CIN: s.ct[:] = bytes(s.sz[2]); s.hc = 0
    def _leave(s, new):
        old = s.st
        if old in (S_EIN, S_DIN, S_CIN) and s.W < s._fsize(old) and 'nozero' not in s.f: s._zfield(old)
        if old == S_SOUT or (old == S_COUT and new != S_SOUT): s._zss()
    def _enter(s, new):
        s.st, s.W = new, 0
        if new == ST_READY or new in (S_ENC, S_DEC): s._zss()
        if new in (S_EIN, S_DIN): s._zfield(new)       # whole decapsk zeroed, flags cleared
        if new == S_CIN: s._zfield(new); s._zss()
        if (new == S_ENC and not s.he) or (new == S_DEC and not (s.hd and s.hc)) \
           or (new == S_EOUT and not s.he) or (new == S_COUT and not s.hc): s._invalid()
    def _goto(s, new): s._leave(new); s._enter(new)
    # ---- instructions
    def setst(s, n):
        if s.st == 0: return                               # inert
        if (s.st == ST_FAILURE and n != ST_READY) or n not in ALLOWED \
           or (n == s.st and n not in (ST_READY, S_EIN, S_DIN, S_CIN)): return s._invalid()
        s._goto(n)
    def load(s, data):
        """Form B kl.exec: one transfer of the loading State."""
        if s.st == 0: return
        if s.st not in (S_EIN, S_DIN, S_CIN) or s.W >= s._fsize(s.st): return s._invalid()
        size = s._fsize(s.st); take = min(len(data), size - s.W)
        dst, base = (s.ct, 0) if s.st == S_CIN else (s.dk, s.eo if s.st == S_EIN else 0)
        dst[base + s.W: base + s.W + take] = data[:take]; s.W += take
        if s.W < size: return
        excess = len(data) > take and 'noexcess' not in s.f
        if s.st == S_EIN:
            ok = M.ek_check(s.p, bytes(s.dk[s.eo:s.eo + size])) if 'nomod' not in s.f else True
            if ok and not excess: s.he = 1
            else: s.dk[:] = bytes(s.sz[1]); s.he = s.hd = 0; s._fail()
        elif s.st == S_DIN:
            ok = M.dk_check(s.p, bytes(s.dk)) if 'nohash' not in s.f else True
            if not ok or excess: return s._invalid()
            s.hd = 1; s.he = int(M.ek_check(s.p, bytes(s.dk[s.eo:s.eo + s.sz[0]])))
        else:
            if excess: s.ct[:] = bytes(s.sz[2]); s.hc = 0; s._fail()
            else: s.hc = 1; s._goto(ST_READY)
    def emit(s, n):
        """Form C kl.exec: n bytes of the emitted field."""
        if s.st == 0: return b''
        if s.st not in (S_EOUT, S_COUT) or s.W + n > s._fsize(s.st): s._invalid(); return b''
        src = s.dk[s.eo:s.eo + s.sz[0]] if s.st == S_EOUT else s.ct
        out = bytes(src[s.W:s.W + n]); s.W += n
        if s.W == s._fsize(s.st): s._goto(S_SOUT if s.st == S_COUT and s.hs else ST_READY)
        return out
    def exec(s):
        """Form D kl.exec."""
        if s.st == 0: return
        if s.st not in (S_GEN, S_ENC, S_DEC): return s._invalid()
        M.SAMPLE_LIMIT[0] = s.limit
        try:
            if s.st == S_GEN:
                r = s.rbg.read(64); ek, dk = M.keygen_internal(s.p, r[:32], r[32:])
                s.dk[:] = dk; s.he = s.hd = 1; nxt = S_EOUT
            elif s.st == S_ENC:
                K, c = M.encaps_internal(s.p, bytes(s.dk[s.eo:s.eo + s.sz[0]]), s.rbg.read(32))
                s.ss[:], s.ct[:] = K, c; s.hs = s.hc = 1; nxt = S_COUT
            else:
                K = M.decaps(s.p, bytes(s.dk), bytes(s.ct))
                if 'noreject' in s.f and K == M.J(bytes(s.dk[-32:]) + bytes(s.ct)): K = bytes(32)
                s.ss[:] = K; s.hs = 1; nxt = S_SOUT
        except RBGFail: return s._invalid()
        except M.SampleNTTLimit: return s._fail()
        finally: M.SAMPLE_LIMIT[0] = None
        s._goto(nxt)
    def derive(s, dest, length=None):
        """kl.derive from sharedkey (GR39-GR43). dest: ('key', dest_length), ('hash',) = kl.exec input of a hash/MAC/XOF
        listed for it, or ('other',) = any other endpoint. Returns the bytes the destination receives, or None when the
        destination (or, for a pair not admitted, both lockers) goes to Invalid."""
        if s.st == 0: return None
        if s.st != S_SOUT: s._invalid(); return None   # not a source endpoint in this State: the source transitions
        if dest[0] == 'other' and 'norestrict' not in s.f: s._invalid(); return None   # pair not admitted: both transition
        if dest[0] == 'key':
            dl = dest[1]; ln = dl if length is None else length
            if 'nolen' not in s.f and (ln < dl or dl > 32): return None
            return bytes(s.ss[:dl]) + bytes(max(0, dl - 32))
        ln = 32 if length is None else length
        if 'nolen' not in s.f and ln != 32: return None
        return bytes(s.ss)

CH = [1, 8, 16, 32, 64, 100, 7]
def load_all(m, data, ch=CH):
    i = j = 0
    while i < len(data):
        n = min(ch[j % len(ch)], len(data) - i); m.load(data[i:i + n]); i += n; j += 1
def emit_all(m, total, ch=CH):
    out, j = b'', 0
    while len(out) < total: out += m.emit(min(ch[j % len(ch)], total - len(out))); j += 1
    return out
st = lambda m: mdh_get(m.mdh(), 'State')

VEC = {  # OpenSSL 3.5.9 ML-KEM oracle: d||z seed, m recovered from its ciphertext; ek/dk/ct as SHA-256, K, Krej (ct byte 5 ^ 1)
    'ML-KEM-512/0': dict(
        d='20fe9e8e9e69eb7b585b56017ad3e1ea43fee020489fc0daed7d5d9c13a6ac90',
        z='81c461f4705a46e1bb9798b842893e8a1485c267e5d12cac9c32910ee673391e',
        m='8aac832bfda79e505238242082d850024cfff3ef423553ff2cbe103407267272',
        ek='316f857ff506efd2fa09c8a5ec212c715ac29f933e01d835a90e9ef74e72bf2c',
        dk='a1a7f94e01d73bb4bb0678eb0220aa015a762ba2f0412adcaaf08b95e2513c2a',
        ct='c282f7331517724ea8935f8ada0a29d39e8bacb9ee7c509f48dff6e73880541c',
        K='082649d7ddcccfaec7df8ca26aeea00b7818ff39a48a93a0706cc6d10bf040ff',
        Krej='41d6650abf787f4a69c1ff98bf244ed0d972f9089ffd33db9d0d3667c526b2cc'),
    'ML-KEM-512/1': dict(
        d='218295c2817ce30ca139e367aacf3fedd67b36e44213c9ef361b978121d8ab4b',
        z='887ad1fafb748d84175befef8f4b440d07c3b7ebfa292142d11e383f8517458c',
        m='33b7f15a920dbf19e55dd9fda51995281addaa8d3fc20de43c423b1a1b792519',
        ek='768b7e712ec443930a680c4fc3aa8aaf89926925ac92e16c184a27fd7df7e302',
        dk='9c34176fdd83b3381569fdd9193e7e21d7110b1ed5bc04a8244d2bfbeec0d52d',
        ct='950e1c653e7cef9f996cc275f1ea1fc3b74d43ef12a31799b216c3a669658bfd',
        K='ef2d067bf1157e98b52d9af95573087493adbb20649754350596a2fb4cfbadba',
        Krej='533f1d760e3507478d971360fc9fee8fb583f0abf5cf1abcf0ca58438616821a'),
    'ML-KEM-768/0': dict(
        d='668e602ae82ce19345da0159caba9986398c4d9f6b815a7859067c13d6eaddf1',
        z='0269cb9c33c39c6b55a1b5b7da1559ddd1134554691af338f6e3e7bb361b9477',
        m='c6cc5d3035832b7d1f1ade345addf87f16d70d527640b66d5b78aafc28b25e6d',
        ek='68abe5d78438bed2df9c72ef6b86cec1288b243faeb0af8bf88acb50ee634495',
        dk='fed90450333f3c4ca4887005d21b7a6038ec796786397777cb895b5a682b8f36',
        ct='8fa6d568773b62b0990969935f53f0697fc5f3186603468178c91dd43e091f71',
        K='3da43d0f183c53ceae6582354c030fdd8f82b9f127a5bb832c68a28a5ebf59dd',
        Krej='b69e1b53135e8801f144ef5b50bc71069c57053e3b53765d114d4a7199da0fe2'),
    'ML-KEM-768/1': dict(
        d='daa7e410dcf14156d3ab3a94f42aad2b43806b9e2d50c2a63241c1d6aee238e5',
        z='54bd57e2c196ac9e890e936f8c09f4838b30f5bf669335c0f7d10d01ed23efd3',
        m='d9274138f642a946f454a94989bac6216ad957952546c7cb447895fba6dcfc48',
        ek='0abd454fd0d4f902f23f5c66c1b9c4d429df60aeca96b4d95a4a002da4a862d2',
        dk='c9eb817e4a03d137c2a0ac101125607ab0921b1592993101f2dd4d866b9b41ec',
        ct='cbfa848b690e3810bbd3cb6fef87a049de78dad7baa7f907ce92684e6fd24fb9',
        K='f4c0002a945be199af425c3c9fafbe655583be0c09506467500b7be575bb3a5d',
        Krej='a8647f158bf02405ec9a761f279e3bbd85d137f714937408233d34dd23989255'),
    'ML-KEM-1024/0': dict(
        d='fe5c7783c5ec0143c4d33289801ba4c5d312988ec49e7d8486a18d0557facef4',
        z='0153e96b8bb8501438b4badbb175782d3e9feab28280d55c9df684b552ff096d',
        m='444c897b5f55d6f67575235ebed5ec5b36002fbfbfbc3a6d7a2fe9e015c7e874',
        ek='90febc552859974e96d27eef3f8d6c6ed2ceabf43cdfb0e4ce05487dc8778f91',
        dk='05b01b2af0da2c274fc38e5fce0b782ab2bac9b1225c8096404ce105fa0a9117',
        ct='0321f89d12821db73e456c9bac8e555e7c5dc60e98dfb0816e4f9f318c7a26f1',
        K='3a4d02d07f66ce5a543c27225d328e618be6a5b33558e52364c041ff2dc53285',
        Krej='89720ceacbf497bf08be285979c64d004a2018d86855644af2baf782be204558'),
    'ML-KEM-1024/1': dict(
        d='2a2bbdacdbfc08240bd7b3147363234b4e25b6850abe1f363657b26668109d05',
        z='d8efdcecd79c8634213c1a08718d4c3a78621df24b89d8130a6c449029fe2e99',
        m='88e4baec7647b62e0bb884bf953e0efe234fffb9c002cf7a1721a63077171fae',
        ek='00c3a9e587d6268c12e56e28a755c00905324d8c9c176972a6cefc72dbac7ef6',
        dk='e8584cf6ee6ca0ef297e4a0788987908144c313d8bfde394c77858fb6e021612',
        ct='317b8c0b73c5f9bfa445a74bf6cceabfaad1f3f9c5f0584e382500af5f04e5ea',
        K='5ae8832494d3374063f21ca4d45987a2dce5248d11bfac4b2a962d6805799c65',
        Krej='71012bd358854c250fb87ec4f0ecc007f45c10e03e99c6389071f623d9a62851'),
}

def flip(b, i=5): b = bytearray(b); b[i] ^= 1; return bytes(b)
def bad_ek(p, ek):
    """ek whose first coefficient is 4095 >= q (fails the modulus check, passes the type check)."""
    b = bytearray(ek); b[0] = 0xFF; b[1] |= 0x0F; return bytes(b)
def dk_with_ek(p, dk, ek):
    k = M.PARAMS[p][0]; return dk[:384 * k] + ek + M.H(ek) + dk[-32:]

def G_vec(mk, mode):
    """Full flows against the OpenSSL oracle (every vector of the parameter set)."""
    p = NAMES[mode]; R = []; a = lambda n, ok: R.append((n, bool(ok)))
    for key, v in VEC.items():
        if not key.startswith(p + '/'): continue
        d, z, mm = bytes.fromhex(v['d']), bytes.fromhex(v['z']), bytes.fromhex(v['m'])
        K, Krej = bytes.fromhex(v['K']), bytes.fromhex(v['Krej'])
        t = key + ' '
        m = mk(mode, RBG(d + z)); m.setst(S_GEN); m.exec()
        a(t + 'KeyGen -> encapsk_Output, HasEncapsk and HasDecapsk', st(m) == S_EOUT and m.ext() == 3 and m.W == 0)
        a(t + 'decapsk = OpenSSL dk', sha(m.dk) == v['dk'])
        ek = emit_all(m, m.sz[0])
        a(t + 'emitted encapsk = OpenSSL ek', sha(ek) == v['ek'])
        a(t + 'emission complete -> Ready, key pair kept', st(m) == ST_READY and m.ext() == 3 and m.W == 0)
        a(t + 'encapsk is the ek sub-field of decapsk', bytes(m.dk[m.eo:m.eo + m.sz[0]]) == ek)
        dk = bytes(m.dk)
        m.rbg = RBG(mm); m.setst(S_ENC); m.exec()
        a(t + 'Encapsulate -> ciphertext_Output, flags 15', st(m) == S_COUT and m.ext() == 15)
        ct = emit_all(m, m.sz[2])
        a(t + 'emitted ciphertext = OpenSSL ct', sha(ct) == v['ct'])
        a(t + 'ciphertext complete -> sharedkey_Output', st(m) == S_SOUT and m.W == 0 and m.ext() == 15)
        a(t + 'derive hash input = OpenSSL K', m.derive(('hash',)) == K)
        a(t + 'derive key of 16/24/32 bytes = first bytes of K', all(m.derive(('key', n)) == K[:n] for n in (16, 24, 32)))
        a(t + 'derive repeatable, State unchanged', m.derive(('hash',)) == K and st(m) == S_SOUT)
        m.setst(ST_READY)
        a(t + 'leaving sharedkey_Output zeroes sharedkey', bytes(m.ss) == bytes(32) and m.ext() == 7)
        m.setst(S_DEC); m.exec()
        a(t + 'Decapsulate -> sharedkey_Output', st(m) == S_SOUT and m.ext() == 15)
        a(t + 'Decapsulate K = OpenSSL K', m.derive(('hash',)) == K)
        m.setst(S_CIN); load_all(m, flip(ct))
        a(t + 'ciphertext_Input complete -> Ready, HasCiphertext', st(m) == ST_READY and m.hc == 1 and m.hs == 0)
        m.setst(S_DEC); m.exec()
        a(t + 'implicit rejection: modified ct -> z-derived key = OpenSSL', st(m) == S_SOUT and m.derive(('hash',)) == Krej)
        a(t + 'rejection key differs from K', Krej != K)
        # a second Machine: encapsk loaded, Encapsulate; third: decapsk + ciphertext loaded, Decapsulate
        b = mk(mode, RBG(mm)); b.setst(S_EIN); load_all(b, ek)
        a(t + 'encapsk_Input complete: HasEncapsk only, stays in State', st(b) == S_EIN and b.ext() == 1 and b.W == b.sz[0])
        a(t + 'only the encapsk sub-field is non-zero', bytes(b.dk[:b.eo]) == bytes(b.eo) and bytes(b.dk[b.eo + b.sz[0]:]) == bytes(len(b.dk) - b.eo - b.sz[0]))
        b.setst(S_ENC); b.exec()
        a(t + 'Encapsulate with loaded encapsk reproduces ct', st(b) == S_COUT and emit_all(b, b.sz[2]) == ct and b.derive(('hash',)) == K)
        c = mk(mode); c.setst(S_DIN); load_all(c, dk)
        a(t + 'decapsk_Input complete: HasEncapsk and HasDecapsk', st(c) == S_DIN and c.ext() == 3)
        c.setst(S_EOUT); a(t + 'encapsk of a loaded decapsk is emitted', emit_all(c, c.sz[0]) == ek)
        c.setst(S_CIN); load_all(c, ct); c.setst(S_DEC); c.exec()
        a(t + 'Decapsulate with loaded decapsk and ciphertext = K', st(c) == S_SOUT and c.derive(('hash',)) == K)
    return R

def G_checks(mk, mode):
    """Input checks of FIPS 203 7.2/7.3 and their outcomes."""
    p = NAMES[mode]; R = []; a = lambda n, ok: R.append((n, bool(ok)))
    v = [x for k, x in VEC.items() if k.startswith(p + '/')][0]
    ek, dk = M.keygen_internal(p, bytes.fromhex(v['d']), bytes.fromhex(v['z'])); sz = M.SIZES[p]
    bek = bad_ek(p, ek); a('test premise: bad ek fails 7.2, passes type check', not M.ek_check(p, bek) and len(bek) == sz[0])
    qek = bytearray(ek); qek[0:2] = (3329 & 255, (qek[1] & 0xF0) | (3329 >> 8)); qek = bytes(qek)
    a('coefficient exactly q fails the modulus check, q-1 passes', not M.ek_check(p, qek) and M.ek_check(p, bytes([3328 & 255, (3328 >> 8) | (ek[1] & 0xF0)]) + ek[2:]))
    m = mk(mode); m.setst(S_EIN); load_all(m, bek)
    a('encapsk modulus failure: Failure, decapsk zeroed, flags clear', st(m) == ST_FAILURE and m.ext() == 0 and bytes(m.dk) == bytes(sz[1]))
    m.setst(ST_READY); m.setst(S_ENC); a('after it Encapsulate is refused (needs HasEncapsk): Invalid', is_error_state(m.mdh()) and mdh_get(m.mdh(), 'StateExtension') == SE_INVALID)
    m = mk(mode); m.setst(S_EIN); load_all(m, ek[:-5]); m.load(ek[-5:] + b'\0' * 5)
    a('encapsk with excess data in the final transfer: Failure (data error)', st(m) == ST_FAILURE and m.he == 0 and bytes(m.dk) == bytes(sz[1]))
    m = mk(mode); m.setst(S_EIN); load_all(m, ek)
    a('control premise: exactly sized valid encapsk passes', m.he == 1 and st(m) == S_EIN)
    m.setst(ST_READY); a('leaving a completed encapsk load keeps encapsk and HasEncapsk', m.he == 1 and bytes(m.dk[m.eo:m.eo + sz[0]]) == ek)
    m = mk(mode); m.setst(S_EIN); load_all(m, ek[:300]); a('MachineUse counts the bytes loaded', m.W == 300)
    m.setst(ST_READY); a('leaving encapsk_Input early zeroes the field, flag clear', m.he == 0 and bytes(m.dk) == bytes(sz[1]) and m.W == 0)
    m = mk(mode); m.setst(S_EIN); load_all(m, ek[:300]); m.setst(S_EIN)
    a('same-State setst restarts the load: MachineUse 0, field zero', m.W == 0 and bytes(m.dk) == bytes(sz[1]) and st(m) == S_EIN)
    # decapsk
    dkb = bytearray(dk); dkb[-40] ^= 1; dkb = bytes(dkb)         # corrupt H(ek)
    m = mk(mode); m.setst(S_DIN); load_all(m, dkb)
    a('decapsk hash check failure: Invalid (configuration error)', is_error_state(m.mdh()) and mdh_get(m.mdh(), 'StateExtension') == SE_INVALID)
    m = mk(mode); m.setst(S_DIN); load_all(m, dk[:-3]); m.load(dk[-3:] + b'\1')
    a('decapsk with excess data: Invalid', is_error_state(m.mdh()))
    dkm = dk_with_ek(p, dk, bek)
    m = mk(mode); m.setst(S_DIN); load_all(m, dkm)
    a('decapsk, hash ok but embedded ek fails modulus: HasDecapsk set, HasEncapsk clear, no error', st(m) == S_DIN and m.ext() == 2)
    m.setst(S_EOUT); a('then entering encapsk_Output is refused (needs HasEncapsk)', is_error_state(m.mdh()))
    m = mk(mode); m.setst(S_DIN); load_all(m, dk[:1000]); m.setst(ST_READY)
    a('leaving decapsk_Input early zeroes decapsk, flags clear', bytes(m.dk) == bytes(sz[1]) and m.ext() == 0)
    # ciphertext
    ct = bytes(range(256)) * 7; ct = ct[:sz[2]]
    m = mk(mode); m.setst(S_CIN); load_all(m, ct)
    a('any ciphertext of the right length passes the type check: Ready, HasCiphertext', st(m) == ST_READY and m.hc == 1 and bytes(m.ct) == ct)
    m = mk(mode); m.setst(S_CIN); load_all(m, ct[:-9]); m.load(ct[-9:] + b'\0' * 4)
    a('ciphertext with excess data: Failure, ciphertext zeroed, HasCiphertext clear', st(m) == ST_FAILURE and m.hc == 0 and bytes(m.ct) == bytes(sz[2]))
    m = mk(mode); m.setst(S_CIN); load_all(m, ct[:500]); m.setst(ST_READY)
    a('leaving ciphertext_Input early: ciphertext zeroed, HasCiphertext clear', m.hc == 0 and bytes(m.ct) == bytes(sz[2]))
    return R

def G_sm(mk, mode):
    """State machine, flags, zeroings, failures, serialized content."""
    p = NAMES[mode]; R = []; a = lambda n, ok: R.append((n, bool(ok)))
    inv = lambda m: is_error_state(m.mdh()) and mdh_get(m.mdh(), 'StateExtension') == SE_INVALID
    v = [x for k, x in VEC.items() if k.startswith(p + '/')][0]
    d, z, mm = bytes.fromhex(v['d']), bytes.fromhex(v['z']), bytes.fromhex(v['m'])
    sz = M.SIZES[p]
    m = mk(mode)
    a('provisioning: Ready, ext 0, MachineUse 0, fields zero', st(m) == ST_READY and m.ext() == 0 and m.W == 0 and m.serialized() == bytes(sz[1] + sz[2] + 32))
    a('MDH Machine field is Type 11 @ Mode', mdh_get(m.mdh(), 'Machine') == 0xB0 + mode)
    a('MachinePolicy != 0 is unsupported Metadata', is_error_state(mk(mode, policy=1).mdh()) and mdh_get(mk(mode, policy=1).mdh(), 'StateExtension') == SE_UNSUPPORTED)
    m.exec(); a('kl.exec in Ready: Invalid', inv(m))
    for n in (S_ENC, S_DEC, S_EOUT, S_COUT, S_SOUT, 0, 11, 54, 55, 66):
        m = mk(mode); m.setst(n); a('setst %d from empty Ready: Invalid' % n, inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.setst(S_GEN); a('same-State setst in GenerateKeyPair: Invalid', inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.exec()
    a('kl.exec in encapsk_Output: Invalid', inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.emit(100)
    a('MachineUse counts bytes emitted', st(m) == S_EOUT and m.W == 100)
    m.emit(sz[0]); a('emit past the end of the field: Invalid', inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY)
    a('leaving encapsk_Output keeps the key pair', m.ext() == 3 and bytes(m.dk) != bytes(sz[1]))
    m.setst(S_ENC); m.exec()
    a('Encapsulate with kept key pair', st(m) == S_COUT)
    m.emit(10); m.setst(ST_READY)
    a('leaving ciphertext_Output early: sharedkey zeroed, HasSharedKey clear, ciphertext kept', bytes(m.ss) == bytes(32) and m.ext() == 7 and m.hc == 1)
    m.setst(S_COUT); out = emit_all(m, sz[2])
    a('re-emitting the kept ciphertext ends in Ready (HasSharedKey clear)', st(m) == ST_READY and sha(out) == v['ct'])
    m.setst(S_DEC); m.exec(); a('Decapsulate of the kept ciphertext = K', m.derive(('hash',)) == bytes.fromhex(v['K']))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(S_EIN)
    a('entering encapsk_Input discards key pair', bytes(m.dk) == bytes(sz[1]) and m.ext() == 0)
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(S_DIN)
    a('entering decapsk_Input clears flags', m.ext() == 0)
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(S_DEC)
    a('Decapsulate without ciphertext: Invalid', inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec(); m.setst(S_CIN)
    a('entering ciphertext_Input zeroes ciphertext and sharedkey, clears flags', m.serialized()[sz[1]:] == bytes(sz[2] + 32) and m.ext() == 3)
    m = mk(mode); m.setst(S_DIN); load_all(m, M.keygen_internal(p, d, z)[1]); m.setst(S_DEC)
    a('Decapsulate with decapsk but no ciphertext: Invalid', inv(m))
    m = mk(mode); m.setst(S_EIN); load_all(m, M.keygen_internal(p, d, z)[0]); m.setst(S_CIN); load_all(m, bytes(sz[2])); m.setst(S_DEC)
    a('Decapsulate with encapsk only: Invalid (needs HasDecapsk)', inv(m))
    m = mk(mode); m.setst(S_COUT); a('ciphertext_Output without HasCiphertext: Invalid', inv(m))
    # sharedkey_Output
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec(); emit_all(m, sz[2])
    m.exec(); a('kl.exec in sharedkey_Output: Invalid', inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec(); emit_all(m, sz[2])
    m.setst(S_SOUT); a('kl.setst naming sharedkey_Output: Invalid', inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.derive(('hash',)); a('kl.derive outside sharedkey_Output: Invalid', inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec(); emit_all(m, sz[2])
    m.setst(S_CIN); a('leaving sharedkey_Output zeroes sharedkey', bytes(m.ss) == bytes(32) and m.hs == 0)
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec(); emit_all(m, sz[2]); m.setst(S_EOUT)
    a('sharedkey_Output -> encapsk_Output admitted, sharedkey zeroed', st(m) == S_EOUT and bytes(m.ss) == bytes(32) and m.hs == 0)
    # serialized content
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec(); emit_all(m, sz[2])
    s_ = m.serialized(); n = len(s_)
    a('serialized content size = %d bytes = %d blocks' % ({0: 2432, 1: 3520, 2: 4768}[mode], {0: 152, 1: 220, 2: 298}[mode]),
      n == {0: 2432, 1: 3520, 2: 4768}[mode] and n % 16 == 0 and n // 16 == {0: 152, 1: 220, 2: 298}[mode])
    K, c = M.encaps_internal(p, M.keygen_internal(p, d, z)[0], mm)
    a('serialized content = decapsk | ciphertext | sharedkey', s_ == M.keygen_internal(p, d, z)[1] + c + K)
    # failures
    m = mk(mode, RBG(fail=True)); m.setst(S_GEN); m.exec()
    a('RBG failure in GenerateKeyPair: Invalid', inv(m))
    m = mk(mode, RBG(d + z), limit=1); m.setst(S_GEN); m.exec()
    a('SampleNTT limit in GenerateKeyPair: Failure, MachineUse 0, no key pair', st(m) == ST_FAILURE and m.W == 0 and m.ext() == 0)
    m.setst(S_EIN); a('from Failure only Ready is allowed', inv(m))
    m = mk(mode, RBG(d + z), limit=1); m.setst(S_GEN); m.exec(); m.setst(ST_READY)
    a('Failure -> Ready', st(m) == ST_READY)
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.rbg = RBG(fail=True); m.setst(S_ENC); m.exec()
    a('RBG failure in Encapsulate: Invalid', inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.limit = 1; m.setst(S_ENC); m.exec()
    a('SampleNTT limit in Encapsulate: Failure, MachineUse 0', st(m) == ST_FAILURE and m.W == 0)
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec(); m.setst(ST_READY)
    m.setst(S_CIN); load_all(m, bytes(sz[2])); m.setst(S_DEC); m.limit = 1; m.exec()
    a('SampleNTT limit in Decapsulate: Failure, MachineUse 0', st(m) == ST_FAILURE and m.W == 0)
    return R

def G_lock(mk, mode):
    """Locker level: error cases, forms, MR14 long fields, restricted sharedkey derive (GR21-GR43)."""
    p = NAMES[mode]; R = []; a = lambda n, ok: R.append((n, bool(ok)))
    inv = lambda m: is_error_state(m.mdh()) and mdh_get(m.mdh(), 'StateExtension') == SE_INVALID
    v = [x for k, x in VEC.items() if k.startswith(p + '/')][0]
    d, z, mm, K = bytes.fromhex(v['d']), bytes.fromhex(v['z']), bytes.fromhex(v['m']), bytes.fromhex(v['K'])
    sz = M.SIZES[p]; ek, dk = M.keygen_internal(p, d, z)
    def full():                      # Ready, key pair, ciphertext and shared key made; flags 7 (sharedkey cleared by Ready)
        m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec()
        emit_all(m, sz[2]); m.setst(ST_READY); return m
    def sk():
        m = full(); m.setst(S_DEC); m.exec(); return m
    zero = bytes(sz[1] + sz[2] + 32)
    # ---- Content cleared and inert Error States
    m = sk(); a('premise: Decapsulate result held in sharedkey_Output', st(m) == S_SOUT and m.serialized() != zero)
    m.exec(); a('Invalid clears the whole Content (GR36)', inv(m) and m.serialized() == zero and m.ext() == 0)
    snap = m.mdh()
    m.setst(ST_READY); m.load(b'\1'); m.emit(1); m.exec(); m.derive(('hash',))
    a('Error State is inert: setst, load, emit, exec, derive change nothing (GR33)', m.mdh() == snap and m.serialized() == zero)
    m.setste(SE_OUT_OF_MEMORY); a('kl.setste in an Error State: the new Error State replaces it (GR37)', is_error_state(m.mdh()) and mdh_get(m.mdh(), 'StateExtension') == SE_OUT_OF_MEMORY)
    for nm, mkm in (('Ready', full), ('sharedkey_Output', sk)):
        m = mkm(); m.setste(SE_PRIV_VIOLATION)
        a('kl.setste from %s: Error State, Content cleared' % nm, is_error_state(m.mdh()) and m.serialized() == zero)
    m = mk(mode, RBG(d + z, mm)); m.setst(S_EIN); load_all(m, ek[:100]); m.setste(SE_INVALID)
    a('kl.setste in a partly loaded field State: Content cleared', inv(m) and m.serialized() == zero)
    m = mk(mode, policy=1); snap = m.mdh(); m.setst(S_GEN); m.setst(ST_READY); m.exec(); m.load(b'1')
    a('MachinePolicy != 0: unsupported Metadata, inert', mdh_get(snap, 'StateExtension') == SE_UNSUPPORTED and m.mdh() == snap)
    # ---- State numbers
    for n in (0, 11, 12, 44, 45, 48, 53, 54, 55, 56, 65, 66, 10):
        m = full(); m.setst(n); a('kl.setst #%d: Invalid, Content cleared' % n, inv(m) and m.serialized() == zero)
    m = mk(mode, RBG(d + z), limit=1); m.setst(S_GEN); m.exec()
    for n in (S_GEN, S_ENC, S_EIN, S_COUT, 55):
        m2 = mk(mode, RBG(d + z), limit=1); m2.setst(S_GEN); m2.exec(); m2.setst(n)
        a('from Failure, kl.setst #%d: Invalid' % n, inv(m2))
    # ---- Forms in each State: only the Form of the State is admitted (GR21, GR57)
    forms = {'load': lambda m: m.load(b'\1' * 16), 'emit': lambda m: m.emit(16), 'exec': lambda m: m.exec(), 'derive': lambda m: m.derive(('hash',))}
    for f in forms:
        m3 = mk(mode, RBG(d + z), limit=1); m3.setst(S_GEN); m3.exec(); fl = st(m3) == ST_FAILURE; forms[f](m3)
        a('Failure: Form "%s" not admitted, Invalid' % f, fl and inv(m3))
    ok_form = {S_GEN: 'exec', S_ENC: 'exec', S_DEC: 'exec', S_EIN: 'load', S_DIN: 'load', S_CIN: 'load', S_EOUT: 'emit', S_COUT: 'emit'}
    names = {S_GEN: 'GenerateKeyPair', S_ENC: 'Encapsulate', S_DEC: 'Decapsulate', S_EIN: 'encapsk_Input', S_DIN: 'decapsk_Input', S_CIN: 'ciphertext_Input', S_EOUT: 'encapsk_Output', S_COUT: 'ciphertext_Output'}
    for t, ok in ok_form.items():
        for f in forms:
            if f == ok or (f == 'derive'): continue
            m = full(); m.rbg = RBG(d + z, mm); m.setst(t); forms[f](m)
            a('%s: Form of kl.exec "%s" is Invalid' % (names[t], f), inv(m) and m.serialized() == zero)
        m = full(); m.setst(t); m.derive(('hash',)); a('%s: kl.derive source is not available: Invalid' % names[t], inv(m))
    m = full(); m.exec(); a('kl.exec in Ready: Invalid', inv(m))
    m = full(); m.derive(('key', 16)); a('kl.derive in Ready (sharedkey cleared): Invalid', inv(m))
    # ---- Gates
    for t, need, nm in ((S_ENC, 'he', 'Encapsulate'), (S_DEC, 'hd', 'Decapsulate'), (S_DEC, 'hc', 'Decapsulate'), (S_EOUT, 'he', 'encapsk_Output'), (S_COUT, 'hc', 'ciphertext_Output')):
        m = full(); setattr(m, need, 0); m.setst(t); a('%s with %s clear: Invalid' % (nm, need), inv(m))
    m = full(); a('premise: all gates open after full flow', m.ext() == 7)
    for t in (S_ENC, S_EOUT, S_COUT): m = full(); m.setst(t); a('%s admitted with flags 7' % names[t], st(m) == t)
    # ---- MR14 long fields
    m = full(); m.setst(S_DIN)
    a('entering decapsk_Input zeroes the whole decapsk including encapsk, clears HasEncapsk and HasDecapsk, keeps ciphertext', bytes(m.dk) == bytes(sz[1]) and m.he == 0 and m.hd == 0 and m.hc == 1 and bytes(m.ct) != bytes(sz[2]))
    load_all(m, dk[:sz[1] - 1]); a('partial decapsk: MachineUse = bytes loaded, flags clear', m.W == sz[1] - 1 and m.ext() == 4)
    m.setst(ST_READY)
    a('leaving decapsk_Input one byte short zeroes the whole decapsk, flags clear', bytes(m.dk) == bytes(sz[1]) and m.he == 0 and m.hd == 0 and m.W == 0)
    m.setst(S_ENC); a('then Encapsulate (HasEncapsk clear): Invalid', inv(m))
    for t in (ST_READY, S_GEN, S_EIN, S_CIN, S_ENC, S_DEC):
        m = mk(mode, RBG(d + z, mm)); m.setst(S_DIN); load_all(m, dk[:777]); m.setst(t)
        a('decapsk_Input partly loaded, left for State %d: decapsk zeroed, flags clear' % t, (inv(m) or (bytes(m.dk) == bytes(sz[1]) and m.he == 0 and m.hd == 0)))
    for t in (ST_READY, S_GEN, S_DIN):
        m = mk(mode, RBG(d + z, mm)); m.setst(S_EIN); load_all(m, ek[:77]); m.setst(t)
        a('encapsk_Input partly loaded, left for State %d: field zeroed, HasEncapsk clear' % t, bytes(m.dk) == bytes(sz[1]) and m.ext() == 0)
    for t in (ST_READY, S_GEN, S_EIN, S_DIN):
        m = mk(mode, RBG(d + z, mm)); m.setst(S_CIN); load_all(m, bytes(range(200))); m.setst(t)
        a('ciphertext_Input partly loaded, left for State %d: ciphertext zeroed, HasCiphertext clear' % t, bytes(m.ct) == bytes(sz[2]) and m.hc == 0)
    m = mk(mode); m.setst(S_EIN); load_all(m, ek); m.load(b'\1'); a('load after completion: Invalid', inv(m))
    m = mk(mode); m.setst(S_CIN); load_all(m, bytes(sz[2])); a('ciphertext load completes in one State change: Ready', st(m) == ST_READY and m.W == 0)
    m = mk(mode); m.setst(S_EIN); load_all(m, ek)
    m.setst(S_DIN); a('completed encapsk replaced by entering decapsk_Input: whole field zeroed, HasEncapsk clear', bytes(m.dk) == bytes(sz[1]) and m.ext() == 0)
    m = mk(mode); m.setst(S_DIN); load_all(m, dk); m.setst(S_EIN)
    a('completed decapsk replaced by entering encapsk_Input: whole decapsk zeroed, both flags clear', bytes(m.dk) == bytes(sz[1]) and m.ext() == 0)
    m = mk(mode); m.setst(S_DIN); load_all(m, dk); m.setst(ST_READY)
    a('completed decapsk kept on leaving: both flags set', bytes(m.dk) == dk and m.ext() == 3)
    # ---- restricted sharedkey derive (GR39-GR43, KLE-ML-KEM)
    m = sk()
    for n in (16, 24, 32): a('key field of %d bytes receives the first %d bytes of the secret' % (n, n), m.derive(('key', n)) == bytes(m.ss[:n]))
    a('shared key of Decapsulate = ACVP/OpenSSL K, first bytes into keys', all(m.derive(('key', n)) == bytes(m.ss[:n]) for n in (16, 24, 32)) and m.derive(('key', 32)) == K)
    a('key field of 16 bytes with length 40 > dest_length: first 16 bytes', m.derive(('key', 16), 40) == K[:16])
    a('derive leaves the source State and the secret unchanged', st(m) == S_SOUT and bytes(m.ss) == K and m.ext() == 15)
    for n in (33, 48, 64):
        m = sk(); r = m.derive(('key', n)); a('key field of %d bytes (longer than the secret): destination Invalid, nothing transferred, source unchanged' % n, r is None and st(m) == S_SOUT and bytes(m.ss) == K)
    for n, ln in ((16, 15), (32, 31), (24, 0)):
        m = sk(); a('key field of %d bytes with length %d < dest_length: destination Invalid' % (n, ln), m.derive(('key', n), ln) is None and st(m) == S_SOUT)
    m = sk(); a('hash/MAC/XOF input with length 32 receives the whole secret', m.derive(('hash',)) == K and m.derive(('hash',), 32) == K)
    for ln in (0, 16, 31, 33, 64):
        a('message input with length %d != 32: destination Invalid' % ln, m.derive(('hash',), ln) is None and st(m) == S_SOUT)
    m = sk(); r = m.derive(('other',)); a('any other destination (no pair admitted): both lockers Invalid, source Content cleared', r is None and inv(m) and m.serialized() == zero)
    m = sk(); m.setst(ST_READY); m.derive(('hash',)); a('after leaving sharedkey_Output the secret is gone: kl.derive Invalid', inv(m))
    m = sk(); m.setst(S_EOUT); m.derive(('key', 16)); a('after leaving to encapsk_Output: kl.derive Invalid', inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec()
    a('Encapsulate result: ciphertext_Output holds sharedkey, kl.derive refused (only in sharedkey_Output)', st(m) == S_COUT and m.hs == 1 and m.derive(('key', 16)) is None and inv(m))
    m = mk(mode, RBG(d + z, mm)); m.setst(S_GEN); m.exec(); m.setst(ST_READY); m.setst(S_ENC); m.exec(); emit_all(m, sz[2])
    a('Encapsulate result: derive in sharedkey_Output = ACVP/OpenSSL K', m.derive(('hash',)) == K and m.derive(('key', 24)) == K[:24])
    return R

def run_group(G, title, faults, label):
    section(title)
    for mode in range(3):
        for n, ok in G(lambda md, rbg=None, **kw: Mach(md, rbg, **kw), mode): check('%s: %s' % (NAMES[mode], n), ok)
    for f in faults:
        bad = [n for mode in range(3) for n, ok in G(lambda md, rbg=None, **kw: Mach(md, rbg, faults={f}, **kw), mode) if not ok]
        control('%s: fault "%s" is detected (%d checks fail)' % (label, f, len(bad)), len(bad) > 0)

section('Sizes (KLE-ML-KEM-sizes) and model self-consistency')
for i, p in enumerate(NAMES):
    check(p + ': model sizes = spec table', M.SIZES[p] == SPEC_SIZES[p])
    check(p + ': OpenSSL vectors have these sizes (ek, dk, ct via digest of model output)', all(
        len(M.keygen_internal(p, bytes.fromhex(v['d']), bytes.fromhex(v['z']))[0]) == SPEC_SIZES[p][0] and
        len(M.keygen_internal(p, bytes.fromhex(v['d']), bytes.fromhex(v['z']))[1]) == SPEC_SIZES[p][1]
        for k, v in VEC.items() if k.startswith(p + '/')))
    k = M.PARAMS[p][0]
    check(p + ': dk = dk_PKE | ek | H(ek) | z layout, ek at offset 384k', SPEC_SIZES[p][1] == 384 * k + (384 * k + 32) + 64 and SPEC_SIZES[p][0] == 384 * k + 32)
section('Model vs OpenSSL (independent oracle), and FIPS 203 checks')
for k_, v in VEC.items():
    p = k_.split('/')[0]; d, z, mm = (bytes.fromhex(v[x]) for x in 'dzm')
    ek, dk = M.keygen_internal(p, d, z); K, c = M.encaps_internal(p, ek, mm)
    check(k_ + ': keygen/encaps/decaps/rejection = OpenSSL', sha(ek) == v['ek'] and sha(dk) == v['dk'] and sha(c) == v['ct']
          and K.hex() == v['K'] and M.decaps(p, dk, c) == K and M.decaps(p, dk, flip(c)).hex() == v['Krej'])
    check(k_ + ': FIPS 203 7.2/7.3 checks accept the genuine keys, reject corrupted ones',
          M.ek_check(p, ek) and M.dk_check(p, dk) and not M.ek_check(p, bad_ek(p, ek)) and not M.ek_check(p, ek[:-1])
          and not M.dk_check(p, flip(dk, len(dk) - 40)))
run_group(G_vec, 'Flows against the oracle', ['noreject'], 'implicit rejection disabled')
run_group(G_checks, 'Input checks and outcomes', ['nomod', 'nohash', 'noexcess', 'nozero'], 'check disabled')
run_group(G_sm, 'State machine', [], '')
run_group(G_lock, 'Locker level: errors, forms, long fields, restricted derive', ['noclear', 'nolen', 'norestrict', 'nozero'], 'locker fault')
section('Controls')
control('RBG failure path is reachable (RBG without data fails the scripted read)', raises(RBG().read, 32, exc=RBGFail))
control('SampleNTT limit path is reachable', raises(lambda: (M.SAMPLE_LIMIT.__setitem__(0, 1), M.keygen_internal('ML-KEM-512', bytes(32), bytes(32))), exc=M.SampleNTTLimit))
M.SAMPLE_LIMIT[0] = None
spec_note('Not modelled: ISA layer (SEW/KLIOBUF encodings, kl.size, ADS, export/import, GR57 halting and resumption of long-running exec); GR41 narrowing and SCProtection checks of derive.')
done()
