#!/usr/bin/env python3
"""OCB3 KAT: the Machine of <<KLEE-OCB-mode>> against RFC 7253 (and a bit-string REF for
nonces of any length), with its state machine, Serialized Content and kl.derive endpoints."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bswap, bin_, bxor, aes_encrypt, aes_decrypt, update_mask,
                    double_ocb, MASK128, IllegalInstruction,
                    KL_STATE_READY as READY, KL_STATE_HASH_ABSORB as ABSORB,
                    KL_STATE_HASH_LAST_BLOCK as LAST, KL_STATE_HASH_VERIFY as VERIFY,
                    KL_STATE_ENCRYPT as ENCRYPT, KL_STATE_DECRYPT as DECRYPT,
                    KL_STATE_ENC_LAST_BLOCK as ENC_LAST, KL_STATE_DEC_LAST_BLOCK as DEC_LAST,
                    KL_STATE_ENC_TAG_FINALIZE as TAG_FIN, KL_STATE_SET_AUX_VALUE as SET_AUX,
                    KL_STATE_SUCCESS as SUCCESS, KL_STATE_FAILURE as FAILURE,
                    KL_STATE_INVALID as INVALID, ERROR_STATES,
                    section, check, control, info, raises, done)

B, MAXB = 128, 1 << 48                                # MAX_BLOCKS
JUNK = b2v(bytes([0x5A, 0xC3]) * 32)
junk_above = lambda n, w=B: (JUNK << n) & ((1 << w) - 1)
ntz = lambda n: (n & -n).bit_length() - 1

def nonce_be(N, n):
    q, r = (n + 7) // 8, n % 8
    return bswap(sl(N, 8 * q - 1, 0), q) >> ((8 - r) % 8)

ocb_pad = lambda X, n: cat((0, 120 - n), (0x80, 8), (sl(X, n - 1, 0) if n else 0, n))

# ---------------------------------------------------------------- REF (RFC 7253 4.1-4.3)
def _dbl(S):
    n = int.from_bytes(S, 'big')
    return (((n << 1) & MASK128) ^ (0x87 if n >> 127 else 0)).to_bytes(16, 'big')

def ref_ocb(K, N, A, P, t, n_len=None):
    """N carries an n_len-bit nonce left-aligned in its bytes."""
    E, n = (lambda x: aes_encrypt(K, x)), 8 * len(N) if n_len is None else n_len
    L = [E(bytes(16))]                                 # L_*, L_$, L_0, L_1, ...
    while len(L) < 50:
        L.append(_dbl(L[-1]))
    Ls, Ld, L = L[0], L[1], L[2:]
    Nonce = (((t % 128) << 121) | (1 << n) | int.from_bytes(N, 'big') >> (-n % 8)).to_bytes(16, 'big')
    bottom = Nonce[15] & 0x3F
    Ktop = E(Nonce[:15] + bytes([Nonce[15] & 0xC0]))
    S = int.from_bytes(Ktop + bxor(Ktop[:8], Ktop[1:9]), 'big')
    off = ((S >> (64 - bottom)) & MASK128).to_bytes(16, 'big')
    C, chk, m = b'', bytes(16), len(P) // 16
    for i in range(1, m + 1):
        off = bxor(off, L[ntz(i)])
        C += bxor(off, E(bxor(P[16 * i - 16:16 * i], off)))
        chk = bxor(chk, P[16 * i - 16:16 * i])
    if P[16 * m:]:
        off = bxor(off, Ls)
        C += bxor(P[16 * m:], E(off))
        chk = bxor(chk, P[16 * m:] + b'\x80' + bytes(15 - len(P) % 16))
    tag = E(bxor(bxor(chk, off), Ld))
    hoff, m = bytes(16), len(A) // 16
    for i in range(1, m + 1):
        hoff = bxor(hoff, L[ntz(i)])
        tag = bxor(tag, E(bxor(A[16 * i - 16:16 * i], hoff)))
    if A[16 * m:]:
        tag = bxor(tag, E(bxor(A[16 * m:] + b'\x80' + bytes(15 - len(A) % 16), bxor(hoff, Ls))))
    return C + tag[:t // 8]

# ---------------------------------------------------------------- KLEE model
class Invalid(Exception): pass                         # args: (why, OUTPUT as left)

SKS = {}
LAYOUT = [('N', 120), ('N_len', 7), ('pad', 1), ('Lstar', 128), ('offset', 128), ('hash_A', 128),
          ('checksum_P', 128), ('index', 49), ('tag_len', 2), ('last_blk_len', 7)]

def pack(vals, lay):
    """Rows from bit 0 upwards, zero-padded to a multiple of 128 bits."""
    v = pos = 0
    for f, w in lay:
        if not 0 <= vals[f] < 1 << w:
            raise OverflowError(f)
        v, pos = v | vals[f] << pos, pos + w
    return v2b(v, -(-pos // B) * 16)

def unpack(data, lay):
    v, pos, out = b2v(data), 0, {}
    for f, w in lay:
        out[f], pos = sl(v, pos + w - 1, pos), pos + w
    return out

class Ocb:
    # (immed, Form) -> States it is allowed from (GR20 included); VERIFY Form A: KLIOBUF substitution
    SETST = {(SET_AUX, 'B'): (READY, SET_AUX), (ABSORB, 'B'): (SET_AUX, ABSORB),
             (LAST, 'B'): (ABSORB, LAST), (ENC_LAST, 'B'): (ENCRYPT, ENC_LAST),
             (DEC_LAST, 'B'): (DECRYPT, DEC_LAST), (ENCRYPT, 'A'): (LAST, ENCRYPT),
             (DECRYPT, 'A'): (LAST, DECRYPT), (VERIFY, 'C'): (VERIFY,), (VERIFY, 'A'): (VERIFY,),
             (TAG_FIN, 'A'): (TAG_FIN,)}
    def __init__(s, key, policy=0b11, skid=None, **nc):
        s.key, s.skid, s.policy, s.state = key, skid, policy, READY
        s.nc = dict(dict(dbl=double_ocb, ktop_bswap=True, msb_first=False, pad_byte0=False), **nc)
        if skid is not None:
            SKS[skid] = key
        s.Lstar = s.offset = s.last_blk_len = s.Ldollar = 0
        s.tag_len, s.L = None, []
        s._ready()
    def _ready(s):
        s.N = s.N_len = s.hash_A = s.checksum_P = s.index = 0
    def _invalid(s, why=None, out=0):
        s._ready()                                     # GR9
        s.state, s.key, s.skid, s.tag_len, s.L = INVALID, None, None, None, []
        s.Lstar = s.offset = s.last_blk_len = 0
        if why:
            raise Invalid(why, out)
    def enc(s, v):
        return b2v(aes_encrypt(s.key, v2b(v, 16)))
    def dec(s, v):
        return b2v(aes_decrypt(s.key, v2b(v, 16)))
    def _ladder(s):
        s.Ldollar = s.nc['dbl'](s.Lstar)
        s.L = [s.nc['dbl'](s.Ldollar)]
    def Li(s, i):
        while len(s.L) <= i:
            s.L.append(s.nc['dbl'](s.L[-1]))
        return s.L[i]
    def setst(s, immed, form='A', aux=0):
        if s.state in ERROR_STATES:                    # GR11
            return
        if immed == READY:                             # GR21
            s.state = READY
            return s._ready()
        if (s.state not in s.SETST.get((immed, form), ())   # MGR1, GR24
                or not s.policy & {ENCRYPT: 1, DECRYPT: 2}.get(immed, 3)):   # <<KLEE-Machine-field>>
            s._invalid('transition')
        if immed == SET_AUX:
            if not 6 <= aux <= 120:
                s._invalid('N_len')
            s.N_len = aux
        elif immed == ABSORB:
            if aux not in (64, 96, 128):
                s._invalid('tag_len')
            s.index, s.tag_len, s.offset, s.Lstar = 1, aux, 0, s.enc(0)
            s._ladder()
        elif immed in (LAST, ENC_LAST, DEC_LAST):
            if aux % 8 or aux > 120:
                s._invalid('last_blk_len')
            s.last_blk_len = aux
        elif immed in (ENCRYPT, DECRYPT):
            s._setup()
        elif immed == VERIFY:
            t = s.tag_len
            s.state = SUCCESS if sl(aux, t - 1, 0) == sl(s.checksum_P, t - 1, 0) else FAILURE
            return
        s.state = immed
    def _set_N(s, INPUT):                              # clear the pad bits of byte q-1
        q, pad = (s.N_len + 7) // 8, -s.N_len % 8
        s.N = sl(INPUT, 8 * q - 1, 0) & ~(((1 << pad) - 1) << (0 if s.nc['pad_byte0'] else 8 * q - 8))
    def _setup(s):
        n = s.N_len
        s.Nonce_be = cat((bin_(s.tag_len % 128, 7), 7), (0, 120 - n), (1, 1), (nonce_be(s.N, n), n))
        s.bottom = sl(s.Nonce_be, 5, 0)
        ktop_in = cat((sl(s.Nonce_be, 127, 6), 122), (0, 6))
        s.Ktop = s.enc(bswap(ktop_in, 16) if s.nc['ktop_bswap'] else ktop_in)
        Ktop_be = bswap(s.Ktop, 16)
        s.Stretch_be = cat((Ktop_be, 128), (sl(Ktop_be, 127, 64) ^ sl(Ktop_be, 119, 56), 64))
        s.index = 1
        s.offset = bswap(sl(s.Stretch_be, 191 - s.bottom, 64 - s.bottom), 16)
    def exec(s, form, INPUT=0, klen=B):
        st, n = s.state, s.last_blk_len
        if st in ERROR_STATES:                         # GR11
            return 0
        want = {SET_AUX: 'B', ABSORB: 'B', LAST: 'B' if n else '',
                ENCRYPT: 'A', DECRYPT: 'A', ENC_LAST: 'A' if n else 'D',
                DEC_LAST: 'A' if n else 'D', TAG_FIN: 'C'}.get(st, '')
        if want == 'A' and form in 'BC':               # <<KLEE-usage-input-output>>: no mixing
            raise IllegalInstruction(form)
        if not want or form not in (want, 'D'):
            s._invalid('Form')                         # MGR1, GR18, GR23
        if st == SET_AUX:
            s._set_N(INPUT)
            return 0
        if st in (ABSORB, ENCRYPT, DECRYPT):
            return s._blocks(st, INPUT, klen)
        if st == TAG_FIN:
            s.state, t = SUCCESS, s.tag_len
            return cat((0, B - t), (sl(s.checksum_P, t - 1, 0), t)) & ((1 << klen) - 1)
        if klen < n:
            s._invalid('KLLEN < last_blk_len')
        if n and s.index > MAXB:
            s._invalid('index > MAX_BLOCKS')
        if st == LAST:
            s.offset ^= s.Lstar
            s.hash_A ^= s.enc(ocb_pad(INPUT, n) ^ s.offset)
            s.last_blk_len = 0                         # a second kl.exec is not allowed (MGR9)
            return 0
        out, tmp = 0, s.offset                         # Form D when n = 0
        if n:
            s.offset ^= s.Lstar
            out = sl(INPUT, n - 1, 0) ^ sl(s.enc(s.offset), n - 1, 0)
            tmp = s.offset ^ ocb_pad(INPUT if st == ENC_LAST else out, n)
        s.checksum_P = s.enc(s.checksum_P ^ tmp ^ s.Ldollar) ^ s.hash_A
        s.state = TAG_FIN if st == ENC_LAST else VERIFY
        return out & ((1 << klen) - 1)                 # MGR3, MGR6
    def _blocks(s, st, INPUT, klen):
        if klen % B:
            s._invalid('MGR2')
        out, pos = 0, range(0, klen, B)                # MGR3
        for i in (reversed(pos) if s.nc['msb_first'] else pos):
            if s.index > MAXB:
                s._invalid('index > MAX_BLOCKS', out)
            blk = sl(INPUT, i + B - 1, i)
            s.offset ^= s.Li(ntz(s.index))
            if st == ABSORB:
                s.hash_A ^= s.enc(blk ^ s.offset)
            else:
                r = s.offset ^ (s.enc if st == ENCRYPT else s.dec)(blk ^ s.offset)
                s.checksum_P ^= blk if st == ENCRYPT else r
                out |= r << i
            s.index += 1
        return out
    def lay(s):
        return [('key', 64 if s.skid is not None else 8 * len(s.key))] + LAYOUT
    def export(s, lay=None):
        v = dict(vars(s), pad=0, key=s.skid if s.skid is not None else b2v(s.key),
                 tag_len=0 if s.tag_len is None else s.tag_len // 32 - 2)
        return pack(v, lay or s.lay())
    def imported(s, c1, lay=None):
        """A fresh locker with this locker's MDH, loaded from Content1; derived L$, L[i] recomputed (MGR4)."""
        f = unpack(c1, lay or s.lay())
        new = type(s)(SKS[f['key']] if s.skid is not None else v2b(f['key'], len(s.key)), s.policy, s.skid, **s.nc)
        for k in ('N', 'N_len', 'Lstar', 'offset', 'hash_A', 'checksum_P', 'index', 'last_blk_len'):
            setattr(new, k, f.get(k, 0))
        new.state, new.tag_len = s.state, 32 * (f['tag_len'] + 2)
        new._ladder()
        if isinstance(new, OcbNonce) and not 6 <= new.N_len <= 120:
            new._invalid()                             # MGR13: N_len is checked on import too
        return new

def derive(src, dst, length):
    """kl.derive into `key` (Ready; DER5/DER7 source) or `N` (Set_Aux_Value) from a listed source's bytes."""
    if dst.state in ERROR_STATES:
        return
    if isinstance(src, Ocb):                           # OCB defines no source endpoint
        src._invalid('DER1 items 1-2')
    if dst.state == SET_AUX:                           # DER8: min(length, q) bytes, zero-filled
        q = (dst.N_len + 7) // 8
        return dst.exec('B', b2v(src[:min(length, q)]), 8 * q)
    if dst.state != READY:
        dst._invalid('DER1 items 1-2')                # no endpoint in this State
    if dst.skid is not None or length < len(dst.key) or len(src) < len(dst.key):
        dst._invalid('DER4 (DER1 item 2), DER1 item 5')
    dst.key = src[:len(dst.key)]

def run(K, N, A, X, t, dec=False, n_len=None, per_exec=1, junk=False, hop=False, lay=None,
        subst=False, cl=None, skid=None, trace=None, **nc):
    """<<KLEE-pseudocode-OCB-encryption>>: C || tag, or (P, verified) with dec=True."""
    fA, fB = ('D', 'D') if subst else ('A', 'B')
    cl = cl or Ocb(K, skid=skid, **nc)
    nxt = (lambda c: c.imported(c.export(lay), lay)) if hop else (lambda c: c)
    def do(meth, *a):
        nonlocal cl
        r = getattr(cl, meth)(*a)
        cl = nxt(cl)
        return r
    def feed(data, form, last):
        out, nf = b'', len(data) // 16
        stp = per_exec or max(nf, 1)
        for a in range(0, nf, stp):
            e = min(nf, a + stp)
            out += v2b(do('exec', form, b2v(data[16 * a:16 * e]), 128 * (e - a)), 16 * (e - a))
        rest = data[16 * nf:]
        do('setst', last, 'B', 8 * len(rest))
        if rest:
            n = 8 * len(rest)
            out += v2b(do('exec', form, *((b2v(rest) | junk_above(n), B) if junk else (b2v(rest), n))),
                       16)[:len(rest)]
        elif last != LAST:
            do('exec', 'D')
        return out
    if N is not None:
        do('setst', SET_AUX, 'B', 8 * len(N) if n_len is None else n_len)
        do('exec', fB, b2v(N) | (junk_above(8 * len(N)) if junk else 0))
    do('setst', ABSORB, 'B', t)
    feed(A, fB, LAST)
    cl.setst(DECRYPT if dec else ENCRYPT, 'A')
    if trace is not None:
        trace.update({'L_*': cl.Lstar, 'L_$': cl.Ldollar, 'L_0': cl.L[0], 'L_1': cl.Li(1),
                      'bottom': cl.bottom, 'Ktop': cl.Ktop, 'Offset_0': cl.offset,
                      'Stretch': cl.Stretch_be.to_bytes(24, 'big').hex().upper()})
    cl = nxt(cl)
    if dec:
        P = feed(X[:-t // 8], fA, DEC_LAST)
        cl.setst(VERIFY, 'A' if subst else 'C', b2v(X[-t // 8:]) | (junk_above(t) if junk else 0))
        return P, cl.state == SUCCESS
    C = feed(X, fA, ENC_LAST)
    tag = cl.exec('D' if subst else 'C')
    if trace is not None:
        trace['tag'] = tag
    return C + v2b(tag, 16)[:t // 8]

class OcbNonce(Ocb):
    """<<KLEE-OCB-with-nonce-mode>>: N, N_len from the PI; no _Set_Aux_Value_; _Ready_ keeps them."""
    SETST = {k: tuple(READY if st == SET_AUX else st for st in v) for k, v in Ocb.SETST.items() if k[0] != SET_AUX}
    PI = [('N', 120), ('N_len', 7), ('pad', 1)]
    @classmethod
    def provisioned(cls, K, N, N_len, **kw):
        f = unpack(pack(dict(key=b2v(K), N=N, N_len=N_len, pad=0), [('key', 8 * len(K))] + cls.PI),
                   [('key', 8 * len(K))] + cls.PI)
        s = cls(v2b(f['key'], len(K)), **kw)
        if 6 <= f['N_len'] <= 120:
            s.N_len = f['N_len']
            s._set_N(f['N'])
        else:
            s._invalid()
        return s
    def _ready(s):
        keep = getattr(s, 'N', 0), getattr(s, 'N_len', 0)
        super()._ready()
        s.N, s.N_len = keep
    def _invalid(s, why=None, out=0):
        s.N = s.N_len = 0
        super()._invalid(why, out)

def inval(fn, *a):
    try:
        fn(*a)
    except Invalid as e:
        return e

# RFC 7253 Appendix A, AEAD_AES_128_OCB_TAGLEN128.
K128 = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
S40 = bytes.fromhex("000102030405060708090A0B0C0D0E0F"
                    "101112131415161718191A1B1C1D1E1F"
                    "2021222324252627")
VEC128 = [  # (nonce_suffix, len(A), len(P), C||T hex)
    (0x0, 0, 0, "785407BFFFC8AD9EDCC5520AC9111EE6"),
    (0x1, 8, 8, "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009"),
    (0x2, 8, 0, "81017F8203F081277152FADE694A0A00"),
    (0x3, 0, 8, "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9"),
    (0x4, 16, 16, "571D535B60B277188BE5147170A9A22C"
                  "3AD7A4FF3835B8C5701C1CCEC8FC3358"),
    (0x5, 16, 0, "8CF761B6902EF764462AD86498CA6B97"),
    (0x6, 0, 16, "5CE88EC2E0692706A915C00AEB8B2396"
                 "F40E1C743F52436BDF06D8FA1ECA343D"),
    (0x7, 24, 24, "1CA2207308C87C010756104D8840CE19"
                  "52F09673A448A122C92C62241051F573"
                  "56D7F3C90BB0E07F"),
    (0x8, 24, 0, "6DC225A071FC1B9F7C69F93B0F1E10DE"),
    (0x9, 0, 24, "221BD0DE7FA6FE993ECCD769460A0AF2"
                 "D6CDED0C395B1C3CE725F32494B9F914"
                 "D85C0B1EB38357FF"),
    (0xA, 32, 32, "BD6F6C496201C69296C11EFD138A467A"
                  "BD3C707924B964DEAFFC40319AF5A485"
                  "40FBBA186C5553C68AD9F592A79A4240"),
    (0xB, 32, 0, "FE80690BEE8A485D11F32965BC9D2A32"),
    (0xC, 0, 32, "2942BFC773BDA23CABC6ACFD9BFD5835"
                 "BD300F0973792EF46040C53F1432BCDF"
                 "B5E1DDE3BC18A5F840B52E653444D5DF"),
    (0xD, 40, 40, "D5CA91748410C1751FF8A2F618255B68"
                  "A0A12E093FF454606E59F9C1D0DDC54B"
                  "65E8628E568BAD7AED07BA06A4A69483"
                  "A7035490C5769E60"),
    (0xE, 40, 0, "C5CD9D1850C141E358649994EE701B68"),
    (0xF, 0, 40, "4412923493C57D5DE0D700F753CCE0D1"
                 "D2D95060122E9F15A5DDBFC5787E50B5"
                 "CC55EE507BCB084E479AD363AC366B95"
                 "A98CA5F3000B1479"),
]
def nonce(sfx):
    return bytes.fromhex("BBAA998877665544332211%02X" % sfx)

# RFC 7253 Appendix A intermediates for the (0xF, taglen 128) vector:
INTER = {
    'L_*':      "C6A13B37878F5B826F4F8162A1C8D879",
    'L_$':      "8D42766F0F1EB704DE9F02C54391B075",
    'L_0':      "1A84ECDE1E3D6E09BD3E058A8723606D",
    'L_1':      "3509D9BC3C7ADC137A7C0B150E46C0DA",
    'bottom':   15,
    'Ktop':     "9862B0FDEE4E2DD56DBA6433F0125AA2",
    'Stretch':  "9862B0FDEE4E2DD56DBA6433F0125AA2FAD24D13A063F8B8",
    'Offset_0': "587EF72716EAB6DD3219F8092D517D69",
}

# RFC 7253 Appendix A, AEAD_AES_128_OCB_TAGLEN96 sample.
K96 = bytes.fromhex("0F0E0D0C0B0A09080706050403020100")
VEC96 = (nonce(0xD), S40, S40,
         "1792A4E31E0755FB03E31B22116E6C2D"
         "DF9EFD6E33D536F1A0124B0A55BAE884"
         "ED93481529C76B6AD0C515F4D1CDD4FD"
         "AC4F02AA")

ITER_OUT_128 = "67E944D23256C5E0B6C61FA22FDF1EA2"   # AEAD_AES_128_OCB_TAGLEN128

VEC = [(f"{s:02X}", K128, nonce(s), S40[:la], S40[:lp], bytes.fromhex(ct), 128)
       for s, la, lp, ct in VEC128] + [("TAGLEN96", K96, *VEC96[:3], bytes.fromhex(VEC96[3]), 96)]
N13, CT13 = nonce(0xD), VEC[13][5]
E7 = VEC[7][1:5] + (128,)                         # (K, N, A, P, t) of vector 07

section("RFC 7253 Appendix A")
for lab, K, N, A, P, CT, t in VEC:
    bad = CT[:-1] + bytes([CT[-1] ^ 0x40])
    for name, got, want in (
            ("REF", ref_ocb(K, N, A, P, t), CT),
            ("one block per kl.exec", run(K, N, A, P, t), CT),
            ("multi-block kl.exec, filler above nonce and last blocks",
             run(K, N, A, P, t, per_exec=0, junk=True), CT),
            ("decrypt both ways, Hash_Verify Success",
             [run(K, N, A, CT, t, dec=True), run(K, N, A, CT, t, dec=True, per_exec=0, junk=True)],
             [(P, True)] * 2),
            ("tampered tag: Failure", run(K, N, A, bad, t, dec=True)[1], False),
            ("export/import after every instruction, both directions",
             (run(K, N, A, P, t, hop=True), run(K, N, A, CT, t, dec=True, hop=True)), (CT, (P, True)))):
        check(f"{lab} {name}", True, got, want)
tr = {}
run(K128, nonce(0xF), b'', S40, 128, trace=tr)
for k, want in INTER.items():
    got = tr[k] if k in ('bottom', 'Stretch') else v2b(tr[k], 16).hex().upper()
    check(f"intermediate {k}", True, got, want)
Kit, C = bytes(15) + bytes([128]), b''
for i in range(128):
    S = bytes(i)
    for j, (A, P) in enumerate(((S, S), (b'', S), (S, b''))):
        C += run(Kit, (3 * i + 1 + j).to_bytes(12, 'big'), A, P, 128, per_exec=0)
check("iterated test: |C| = 22400", True, len(C), 22400)
check("iterated test output", True,
      run(Kit, (385).to_bytes(12, 'big'), C, b'', 128, per_exec=0).hex().upper(), ITER_OUT_128)

section("Serialized Content")
info("<<KLEE-OCB-mode>> Serialized Content rows are packed from bit 0 upwards (lowest address first).")
FITS, fits = ('N', 'N_len', 'tag_len', 'index', 'last_blk_len', 'Lstar', 'offset', 'hash_A'), True
for vals in ((0, 120, 128, MAXB + 1, 120), ((1 << 47) - 1, 6, 64, 1, 0), (1 << 119, 7, 96, MAXB, 8)):
    cl = Ocb(K128)
    vars(cl).update(zip(FITS, vals + (MASK128,) * 3), checksum_P=MASK128)
    fits &= all(getattr(cl.imported(cl.export()), k) == getattr(cl, k) for k in FITS)
check("every admissible value fits its row", fits)
for sk in (None, 0x0123456789ABCDEF):
    check(f"export/import after every instruction, key {'by value' if sk is None else 'as SKID'}: "
          "vector 07", True, run(*E7, hop=True, skid=sk, per_exec=0), VEC[7][5])
info("tag_len is exported as code 0 before _Hash_Absorb_ first assigns it.")

section("state machine")
def at_absorb(K=K128, **kw):
    cl = Ocb(K, **kw)
    cl.setst(SET_AUX, 'B', 96)
    cl.exec('B', b2v(N13))
    cl.setst(ABSORB, 'B', 128)
    return cl
def at_crypt(dec=False, **kw):
    cl = at_absorb(**kw)
    cl.exec('B', b2v(S40[:32]), 256)
    cl.setst(LAST, 'B', 64)
    cl.exec('B', b2v(S40[32:]), 64)
    cl.setst(DECRYPT if dec else ENCRYPT, 'A')
    return cl
def at_last(dec=False, n=64, finish=False):
    cl = at_crypt(dec)
    out = cl.exec('A', b2v((CT13 if dec else S40)[:32]), 256)
    cl.setst(DEC_LAST if dec else ENC_LAST, 'B', n)
    finish and cl.exec('A', b2v((CT13 if dec else S40)[32:40]), 64)
    return cl, out
def at_end(dec=False):
    cl = at_last(dec, finish=True)[0]
    cl.setst(VERIFY, 'C', 0) if dec else cl.exec('C')
    return cl
def last_set(n=64, absorb=False):
    cl = at_absorb()
    cl.setst(LAST, 'B', n)
    absorb and cl.exec('B', b2v(S40[:8]), 64)
    return cl
last_done = lambda: last_set(absorb=True)
INVALID_CASES = [
    ("kl.setst #hash_absorb from Ready", lambda: Ocb(K128), lambda c: c.setst(ABSORB, 'B', 128)),
    ("kl.setst #set_aux_value Form A", lambda: Ocb(K128), lambda c: c.setst(SET_AUX, 'A')),
    ("kl.exec Form A in Hash_Absorb", at_absorb, lambda c: c.exec('A')),
    ("kl.setst #encrypt from Hash_Absorb", at_absorb, lambda c: c.setst(ENCRYPT, 'A')),
    ("kl.exec in Hash_Absorb_Last_Block, last_blk_len = 0", lambda: last_set(0), lambda c: c.exec('D')),
    ("second kl.exec in Hash_Absorb_Last_Block", last_done, lambda c: c.exec('B', 0, 64)),
    ("kl.setst #enc_tag_finalize from Encrypt", at_crypt, lambda c: c.setst(TAG_FIN, 'A')),
    ("kl.exec Form A in Enc_Last_Block, last_blk_len = 0", lambda: at_last(n=0)[0], lambda c: c.exec('A')),
    ("second kl.exec in Enc_Last_Block (now Enc_Tag_Finalize)", lambda: at_last(finish=True)[0],
     lambda c: c.exec('A', b2v(S40[32:40]), 64)),
    ("second kl.exec in Dec_Last_Block (now Hash_Verify)", lambda: at_last(True, finish=True)[0],
     lambda c: c.exec('A', b2v(CT13[32:40]), 64)),
    ("kl.setst #hash_verify in Decrypt", lambda: at_crypt(True), lambda c: c.setst(VERIFY, 'C')),
    ("kl.setst #hash_verify in Enc_Tag_Finalize", lambda: at_last(finish=True)[0],
     lambda c: c.setst(VERIFY, 'C')),
    ("second tag kl.exec, in Success (GR23)", at_end, lambda c: c.exec('C')),
    ("kl.setst #decrypt in Success (GR24)", at_end, lambda c: c.setst(DECRYPT, 'A')),
    ("kl.setst #decrypt in Failure (GR24)", lambda: at_end(True), lambda c: c.setst(DECRYPT, 'A')),
    ("KLLEN = 64 in Hash_Absorb (MGR2)", at_absorb, lambda c: c.exec('B', 0, 64)),
    ("KLLEN = 136 in Hash_Absorb (MGR2)", at_absorb, lambda c: c.exec('B', 0, 136)),
    ("KLLEN = 200 in Hash_Absorb (MGR2)", at_absorb, lambda c: c.exec('B', 0, 200)),
    ("KLLEN = 56 < last_blk_len = 64", last_set, lambda c: c.exec('B', 0, 56)),
] + [(f"last_blk_len = {n}", at_absorb, lambda c, n=n: c.setst(LAST, 'B', n))
     for n in (4, 12, 124, 128, 136)]
for name, mk, act in INVALID_CASES:
    cl = mk()
    check(f"{name} -> Invalid", inval(act, cl) is not None and cl.state == INVALID)
cl = Ocb(K128)
inval(cl.exec, 'B')
check("kl.exec in Ready -> Invalid (GR18); Content cleared (GR9); then no operation (GR11)",
      True, (cl.state, cl.key, cl.hash_A, cl.exec('A', 1234), cl.state), (INVALID, None, 0, 0, INVALID))
for dec, form in ((False, 'B'), (True, 'C')):
    cl = at_crypt(dec)
    check(f"kl.exec Form {form} where Form A is expected -> illegal instruction, State kept",
          raises(cl.exec, form, 0) and cl.state == (DECRYPT if dec else ENCRYPT))
check("Form D kl.exec, Form A kl.setst substitutions: all vectors, both directions",
      all(run(*v[1:5], v[6], subst=True) == v[5] and run(*v[1:3], v[3], v[5], v[6], dec=True, subst=True)
          == (v[4], True) for v in VEC))
for name, mk in (("Success", at_end), ("Failure", lambda: at_end(True)), ("Encrypt", at_crypt)):
    cl = mk()
    cl.setst(READY)
    check(f"kl.setst #ready from {name}, then vector 07 (GR21)", True,
          run(None, *E7[1:], cl=cl), VEC[7][5])
cl = at_crypt()
e = inval(cl.exec, 'A', b2v(S40[:16]) | 1 << 140, 144)
check("KLLEN = 144 in Encrypt -> Invalid, OUTPUT zero (MGR2)", e and e.args[1] == 0 and cl.state == INVALID)
cl = at_last()[0]
out = cl.exec('A', b2v(S40[32:]) | junk_above(64, 256), 256)
check("Enc_Last_Block, Enc_Tag_Finalize with KLLEN 256: one block, rest of OUTPUT zero (MGR3, MGR6)",
      True, (v2b(out, 32), v2b(cl.exec('C', klen=256), 32), cl.state),
      (CT13[32:40] + bytes(24), CT13[40:] + bytes(16), SUCCESS))
cl, pfull = at_last(dec=True)
out = cl.exec('A', b2v(CT13[32:40]) | junk_above(64, 256), 256)
cl.setst(VERIFY, 'C', b2v(CT13[40:]))
check("Dec_Last_Block with KLLEN 256: one block, rest of OUTPUT zero; verify Success", True,
      (v2b(pfull, 32), v2b(out, 32), cl.state), (S40[:32], S40[32:] + bytes(24), SUCCESS))
tr, (lab, K, N, A, P, CT, t) = {}, VEC[16]
run(K, N, A, P, t, trace=tr)
check("tag_len = 96: tag OUTPUT = zeros(32) @ checksum_P[95:0]", True, v2b(tr['tag'], 16),
      CT[40:] + bytes(4))
check("Hash_Verify compares tag_len = 96 bits: filler above -> Success, bit 0 flipped -> Failure",
      True, (run(K, N, A, CT, t, dec=True, junk=True)[1],
             run(K, N, A, CT[:-12] + bytes([CT[-12] ^ 1]) + CT[-11:], t, dec=True)[1]), (True, False))
cl = Ocb(K128)
cl.setst(SET_AUX, 'B', 96)
cl.exec('B', b2v(nonce(0x3)))
cl.exec('B', b2v(N13) | junk_above(96))
check("a repeated nonce kl.exec rewrites N", True, run(None, None, S40, S40, 128, cl=cl), CT13)
for pol, st in ((0b10, ENCRYPT), (0b01, DECRYPT), (0b10, DECRYPT), (0b01, ENCRYPT)):
    ok = bool(pol & (1 if st == ENCRYPT else 2))
    cl = at_absorb(policy=pol)
    cl.setst(LAST, 'B', 0)
    check(f"_MachinePolicy_ {pol:02b}: kl.setst #{'encrypt' if st == ENCRYPT else 'decrypt'} "
          f"{'accepted' if ok else '-> Invalid'}", True,
          (inval(cl.setst, st, 'A') is None, cl.state), (ok, st if ok else INVALID))

section("index > MAX_BLOCKS = 2^48")
def with_index(cl, idx):
    f = unpack(cl.export(), cl.lay())
    f['index'] = idx
    return cl.imported(pack(f, cl.lay()))
cl = with_index(at_crypt(), MAXB - 1)
e = inval(cl.exec, 'A', b2v(S40[:16]) * (1 + (1 << 128) + (1 << 256)), 384)
check("Encrypt at index 2^48-1, 3 blocks: blocks 2^48-1 and 2^48 written, then Invalid, third OUTPUT block zero",
      e and sl(e.args[1], 383, 256) == 0 and sl(e.args[1], 255, 128) and sl(e.args[1], 127, 0))
cl = with_index(at_crypt(dec=True), MAXB)
cl.exec('A', 0)
check("Decrypt: block 2^48 passes (L[48]), the next -> Invalid", cl.index == MAXB + 1 and inval(cl.exec, 'A', 0))
for name, mk, args in (("Hash_Absorb", at_absorb, ('B', 0)),
                       ("Hash_Absorb_Last_Block", last_set, ('B', 0, 64)),
                       ("Enc_Last_Block", lambda: at_last()[0], ('A', 0, 64)),
                       ("Dec_Last_Block", lambda: at_last(True)[0], ('A', 0, 64))):
    ok = with_index(mk(), MAXB)
    ok.exec(*args)
    check(f"{name}: a block at index 2^48 passes, at 2^48+1 -> Invalid",
          ok.state not in ERROR_STATES and inval(with_index(mk(), MAXB + 1).exec, *args))
cl = with_index(at_last()[0], MAXB + 1)
cl.setst(ENC_LAST, 'B', 0)
cl.exec('D')
check("Enc_Last_Block Form D (last_blk_len = 0) has no index guard", True, cl.state, TAG_FIN)
check("largest L index of an admissible block: ntz(2^48) = 48", True,
      max(ntz(i) for i in (1 << 47, MAXB - 1, MAXB, 3 << 46)), 48)
cl = last_done().imported(last_done().export())
check("Hash_Absorb_Last_Block: the kl.exec clears last_blk_len, so a second one, also after export/import, "
      "-> Invalid", cl.last_blk_len == 0 and inval(cl.exec, 'B', 0, 64) and inval(last_done().exec, 'B', 0, 64))

section("OCB with Set Nonce (Mode 9, `AES*_OCB_NONCE`, <<KLEE-OCB-with-nonce-mode>>)")
for lab, K, N, A, P, CT, t in VEC:
    ok = run(None, None, A, P, t, cl=OcbNonce.provisioned(K, b2v(N), 8 * len(N))) == CT
    ok &= run(None, None, A, CT, t, dec=True, cl=OcbNonce.provisioned(K, b2v(N), 8 * len(N))) == (P, True)
    check(f"vector {lab}: nonce from the PI, encrypt and decrypt", ok)
K7, N7, A7, P7, t7 = E7
cl = OcbNonce.provisioned(K7, b2v(N7), 8 * len(N7))
c1 = run(None, None, A7, P7, t7, cl=cl)
cl.setst(READY)
check("_Ready_ keeps N and N_len: the next message reuses the nonce", True,
      (cl.N_len, run(None, None, A7, P7, t7, cl=cl)), (8 * len(N7), c1))
check("export/import after every instruction: vector 07", True,
      run(None, None, A7, P7, t7, hop=True, cl=OcbNonce.provisioned(K7, b2v(N7), 8 * len(N7))), VEC[7][5])
cl = OcbNonce.provisioned(bytes(16), b2v(N7), 8 * len(N7))
derive(K7 + bytes(16), cl, 16)
check("kl.derive into `key` in _Ready_ (<<KLEE-derive-endpoints>>), then vector 7 under the PI nonce", True,
      run(None, None, A7, P7, t7, cl=cl), VEC[7][5])
check("kl.setst #set_aux_value -> Invalid", bool(inval(OcbNonce.provisioned(K7, b2v(N7), 96).setst, SET_AUX, 'B', 96)))
check("PI N_len 5 or 121 -> Invalid at provisioning", True,
      [OcbNonce.provisioned(K7, b2v(N7), n).state for n in (5, 121, 6, 120)], [INVALID, INVALID, READY, READY])
ref = Ocb(K7)
ref.setst(SET_AUX, 'B', 100)
ref.exec('B', (1 << 120) - 1)
check("PI N, N_len = 100: pad bits cleared as by the Set_Aux_Value kl.exec", True,
      OcbNonce.provisioned(K7, (1 << 120) - 1, 100).N, ref.N)

section("kl.derive")
secret = K128 + bytes(range(0xF0, 0x100))
for length in (16, 32):
    cl = Ocb(bytes(16))
    derive(secret, cl, length)
    check(f"`key` in Ready, length {length}, then vector 0D", True,
          run(None, N13, S40, S40, 128, cl=cl, per_exec=0), CT13)
for name, mk, src, n in [
        ("length 8 into the 16-byte key, no zero-fill (DER1 item 5)", lambda: Ocb(bytes(16)), secret, 8),
        ("length 0 into the key (DER1 item 5)", lambda: Ocb(bytes(16)), secret, 0),
        ("12-byte source into the 16-byte key (DER1 item 5)", lambda: Ocb(bytes(16)), secret[:12], 16),
        ("into a locker in Hash_Absorb (DER1 items 1-2)", at_absorb, secret, 16),
        ("into a locker in Success (DER1 items 1-2)", at_end, secret, 16),
        ("into the key of a KeyType 1 locker (DER4, DER1 item 2)", lambda: Ocb(K128, skid=7), secret, 16)]:
    cl = mk()
    check(f"{name} -> Invalid", inval(derive, src, cl, n) and cl.key is None)
for n, nv in ((12, N13), (8, N13[:8] + bytes(4))):
    cl = Ocb(K128)
    cl.setst(SET_AUX, 'B', 96)
    derive(N13 + bytes(4), cl, n)
    check(f"`N` in Set_Aux_Value, N_len = 96, length {n} (DER8 zero-fill)", True,
          run(None, None, S40, S40, 128, cl=cl), run(K128, nv, S40, S40, 128))
cl, src = Ocb(K128), bytes(0xA5 ^ i for i in range(16))
cl.setst(SET_AUX, 'B', 61)
derive(src, cl, 16)
check("`N` in Set_Aux_Value, N_len = 61, length 16: ceil(61/8) = 8 bytes, pad bits of byte 7 ignored", True,
      run(None, None, S40, S40, 128, cl=cl), run(K128, src[:7] + bytes([src[7] & 0xF8]), S40, S40, 128, n_len=61))
for where, src in (("Encrypt", at_crypt()), ("Enc_Tag_Finalize", at_last(finish=True)[0])):
    dst = Ocb(bytes(16))
    check(f"OCB in {where} as a kl.derive source (no source endpoint; an AEAD tag is none, DER6) -> only the "
          "source Invalid", inval(derive, src, dst, 16) and (src.state, dst.state, dst.key) == (INVALID, READY, bytes(16)))

section("nonces of any bit length 6..120 (REF on bit strings)")
Am, Pm = bytes(range(24)), bytes(range(40))
check("nonce_be(N, n) = bswap(N[n-1:0]) for 8 | n", all(
    nonce_be(b2v(x), 8 * len(x)) == bswap(b2v(x), len(x))
    for x in (bytes.fromhex('BBAA99887766554433221100'), bytes.fromhex('0F1E2D3C4B5A69788796A5B4C3D2E1'))))
for n_len in (6, 7, 8, 13, 60, 61, 119, 120):
    q, keep = (n_len + 7) // 8, -n_len % 8
    N = bytes(0xA5 ^ i for i in range(q))
    N = N[:-1] + bytes([N[-1] & (0xFF << keep) & 0xFF])
    ct = run(K128, N, Am, Pm, 128, n_len=n_len)
    check(f"N_len = {n_len}: KLEE == REF, round trip", True,
          (ct, run(K128, N, Am, ct, 128, dec=True, n_len=n_len)),
          (ref_ocb(K128, N, Am, Pm, 128, n_len), (Pm, True)))
    if keep:
        dirty = N[:-1] + bytes([N[-1] | ((1 << keep) - 1)])
        check(f"N_len = {n_len}: padding bits of byte q-1 ignored", True,
              run(K128, dirty, Am, Pm, 128, n_len=n_len), ct)
check("N_len = 6: distinct nonces -> distinct ciphertexts",
      run(K128, bytes([0b10110100]), Am, Pm, 128, n_len=6) !=
      run(K128, bytes([0b10110000]), Am, Pm, 128, n_len=6))
check("N_len in {0, 5, 121, 128, 255} -> Invalid",
      all(inval(run, K128, bytes(15), Am, Pm, 128, False, n) for n in (0, 5, 121, 128, 255)))

section("negative controls")
control("L-ladder via little-endian update_mask", run(*E7, dbl=update_mask) != VEC[7][5])
control("bswap dropped from the Ktop input", run(*E7, ktop_bswap=False) != VEC[7][5])
control("multi-block kl.exec, most significant block first",
        run(K128, N13, S40, S40, 128, per_exec=0, msb_first=True) != CT13)
control("Serialized Content without `hash_A`",
        run(K128, N13, S40, S40, 128, hop=True,
            lay=[r for r in Ocb(K128).lay() if r[0] != 'hash_A']) != CT13)
Nb = bytes([0xA5, 0xA0])
control("13-bit nonce padding cleared in byte 0 instead of byte q-1",
        run(K128, Nb, S40, S40, 128, n_len=13, pad_byte0=True) != ref_ocb(K128, Nb, S40, S40, 128, 13))
done()
