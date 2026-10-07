#!/usr/bin/env python3
"""CMAC KAT: the Machine of <<KLEE-CMAC-mode>> against SP 800-38B / RFC 4493, with its
state machine, Serialized Content and kl.derive endpoints."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bxor, aes_encrypt, update_mask, double_ocb, MASK128,
                    KL_STATE_READY as READY, KL_STATE_HASH_ABSORB as ABSORB,
                    KL_STATE_HASH_LAST_BLOCK as LAST, KL_STATE_HASH_VERIFY as VERIFY,
                    KL_STATE_HASH_OUTPUT as OUTPUT, KL_STATE_SUCCESS as SUCCESS,
                    KL_STATE_FAILURE as FAILURE, KL_STATE_INVALID as INVALID, ERROR_STATES,
                    section, check, control, info, raises, done)

B = 128
JUNK = b2v(bytes([0x5A, 0xC3]) * 32)
junk_above = lambda n, w=2 * B: (JUNK << n) & ((1 << w) - 1)

# ---------------------------------------------------------------- REF (SP 800-38B, byte strings)
def _dbl(n):
    return ((n << 1) & MASK128) ^ (0x87 if n >> 127 else 0)

def ref_cmac(K, M):
    E = lambda x: aes_encrypt(K, x)
    L = int.from_bytes(E(bytes(16)), 'big')
    K1, K2 = _dbl(L), _dbl(_dbl(L))
    n = max(1, -(-len(M) // 16))
    last = M[16 * (n - 1):]
    last = (bxor(last, K1.to_bytes(16, 'big')) if len(last) == 16 else
            bxor(last + b'\x80' + bytes(15 - len(last)), K2.to_bytes(16, 'big')))
    X = bytes(16)
    for i in range(n - 1):
        X = E(bxor(X, M[16 * i:16 * i + 16]))
    return E(bxor(X, last)), [x.to_bytes(16, 'big').hex().upper() for x in (L, K1, K2)]

# ---------------------------------------------------------------- KLEE model
class Invalid(Exception): pass
SKS = {}

def layout(kbits):
    return [('key', kbits), ('hash', B), ('last_blk_len', 32)]

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

class Cmac:
    def __init__(s, key, skid=None, policy=3, **nc):
        """policy: _MachinePolicy_, bit 0 tag output, bit 1 verification (<<KLEE-CMAC-mode>>, MGR11)."""
        s.key, s.skid, s.state, s.policy = key, skid, READY, policy
        s.nc = dict(dict(dbl=double_ocb, k2full=False, msb_first=False), **nc)
        if skid is not None:
            SKS[skid] = key
        s.hash = s.last_blk_len = 0
    def _invalid(s, why=None):
        s.state, s.key, s.skid = INVALID, None, None   # GR22
        s.hash = s.last_blk_len = 0
        if why:
            raise Invalid(why)
    def enc(s, v):
        return b2v(aes_encrypt(s.key, v2b(v, 16)))
    def gen_subkeys(s):
        L = s.enc(0)
        K1 = s.nc['dbl'](L)
        return L, K1, s.nc['dbl'](K1)
    # (immed, Form) -> States it is allowed from (none for _Hash_Output_: MGR17); VERIFY Form A: KLIOBUF substitution
    SETST = {(ABSORB, 'A'): (READY, ABSORB), (LAST, 'B'): (ABSORB, LAST),
             (VERIFY, 'C'): (OUTPUT,), (VERIFY, 'A'): (OUTPUT,)}
    def setst(s, immed, form='A', aux=0):
        if s.state in ERROR_STATES:               # GR26
            return
        if immed == READY:                        # GR15
            s.state, s.hash, s.last_blk_len = READY, 0, 0
            return
        if s.state not in s.SETST.get((immed, form), ()):
            s._invalid('transition')              # MGR1, GR20
        if immed == VERIFY and not s.policy & 2:
            s._invalid('MachinePolicy[1] clear')  # MGR11
        if immed == LAST:
            if aux > B or aux % 8:
                s._invalid('Xs')
            s.last_blk_len = aux
        s.state = immed if immed != VERIFY else SUCCESS if sl(aux, B - 1, 0) == s.hash else FAILURE
    def exec(s, form, INPUT=0, klen=B):
        st = s.state
        if st in ERROR_STATES:                    # GR26
            return 0
        if form not in ({ABSORB: 'BD', LAST: 'BD', OUTPUT: 'CD'}.get(st) or ''):
            s._invalid('Form')                    # MGR1, GR17, GR21
        if st == ABSORB:
            if klen % B:
                s._invalid('MGR2')
            pos = range(0, klen, B)               # MGR3
            for i in (reversed(pos) if s.nc['msb_first'] else pos):
                s.hash = s.enc(s.hash ^ sl(INPUT, i + B - 1, i))
            return 0
        if st == OUTPUT:
            if not s.policy & 1:
                s._invalid('MachinePolicy[0] clear')  # MGR11
            s.state = SUCCESS
            return s.hash & ((1 << klen) - 1)     # MGR8
        n = s.last_blk_len
        if klen < n:
            s._invalid('KLLEN < last_blk_len')
        INPUT = sl(INPUT, B - 1, 0)               # MGR7
        _, K1, K2 = s.gen_subkeys()
        if n == B:
            tmp = INPUT ^ (K2 if s.nc['k2full'] else K1)
        else:                                     # n = 0: INPUT is not read
            tmp = cat((0, B - 8 - n), (0x80, 8), (sl(INPUT, n - 1, 0) if n else 0, n)) ^ K2
        s.hash, s.state = s.enc(s.hash ^ tmp), OUTPUT
        return 0
    def lay(s):
        return layout(64 if s.skid is not None else 8 * len(s.key))
    def export(s, lay=None):
        return pack(dict(key=s.skid if s.skid is not None else b2v(s.key), hash=s.hash,
                         last_blk_len=s.last_blk_len), lay or s.lay())
    def imported(s, c1, lay=None):
        """A fresh locker with this locker's MDH, loaded from Content1."""
        f = unpack(c1, lay or s.lay())
        new = Cmac(SKS[f['key']] if s.skid is not None else v2b(f['key'], len(s.key)), s.skid, s.policy, **s.nc)
        new.state, new.hash = s.state, f.get('hash', 0)
        new.last_blk_len = f['last_blk_len']
        return new

def derive(src, dst, length):
    """kl.derive; src is a Cmac locker or the bytes of a GR40/GR42 source.
    Endpoints: output in Hash_Output (GR41 source); `key` in Ready, input in Hash_Absorb (destination)."""
    lockers = [c for c in (src, dst) if isinstance(c, Cmac)]
    if any(c.state in ERROR_STATES for c in lockers):
        return                                    # Gate Order Rule
    bad = [c for c, ok in ((src, src.state == OUTPUT) if isinstance(src, Cmac) else (src, True),
                           (dst, dst.state == ABSORB or (dst.state == READY and dst.skid is None))) if not ok]
    for c in bad:                                 # GR36 items 1-2 (GR39): only the offending lockers
        c._invalid('GR36 items 1-2' if c is bad[-1] else None)
    # GR36 item 3 holds: GR40/GR42 sources, and GR41 (a MAC tag into a key is key derivation, unrestricted)
    avail = B // 8 if isinstance(src, Cmac) else len(src)
    if dst.state == READY and (length < len(dst.key) or avail < len(dst.key)):
        dst._invalid('GR36 item 5')
    data = v2b(src.exec('C', klen=8 * length), length) if isinstance(src, Cmac) else src
    if dst.state == ABSORB:                       # consumed as kl.exec would be (GR43)
        return dst.exec('B', b2v(data[:length]), 8 * length)
    dst.key = data[:len(dst.key)]

def run(K, M, per_exec=1, junk=False, hop=False, lay=None, subst=False, dummy=0, cl=None,
        skid=None, **nc):
    """<<KLEE-pseudocode-CMAC>> up to _Hash_Output_; hop exports/imports after every instruction."""
    fB = 'D' if subst else 'B'
    cl = cl or Cmac(K, skid, **nc)
    nxt = (lambda c: c.imported(c.export(lay), lay)) if hop else (lambda c: c)
    cl.setst(ABSORB); cl = nxt(cl)
    nfull = (len(M) - 1) // 16 if M else 0
    step = per_exec or max(nfull, 1)
    for a in range(0, nfull, step):
        e = min(nfull, a + step)
        cl.exec(fB, b2v(M[16 * a:16 * e]), 128 * (e - a)); cl = nxt(cl)
    tail = M[16 * nfull:]
    cl.setst(LAST, 'B', 8 * len(tail)); cl = nxt(cl)
    if junk:
        cl.exec(fB, b2v(tail) | junk_above(8 * len(tail)), 2 * B)
    else:
        cl.exec(fB, *((b2v(tail), 8 * len(tail)) if tail else (dummy, B)))
    return nxt(cl)

def tag(*a, **kw):
    return v2b(run(*a, **kw).exec('C'), 16)

# RFC 4493 section 4 / SP 800-38B D.1-D.3 (NIST CMAC example file)
MSG = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
K128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
K192 = bytes.fromhex("8e73b0f7da0e6452c810f32b809079e5" "62f8ead2522c6b7b")
K256 = bytes.fromhex("603deb1015ca71be2b73aef0857d7781" "1f352c073b6108d72d9810a30914dff4")
SUBKEYS = [  # (label, key, L, K1, K2)
    ("AES-128", K128, "7DF76B0C1AB899B33E42F047B91B546F",
                      "FBEED618357133667C85E08F7236A8DE",
                      "F7DDAC306AE266CCF90BC11EE46D513B"),
    ("AES-192", K192, "22452D8E49A8A5939F7321CEEA6D514B",
                      "448A5B1C93514B273EE6439DD4DAA296",
                      "8914B63926A2964E7DCC873BA9B5452C"),
    ("AES-256", K256, "E568F68194CF76D6174D4CC04310A854",
                      "CAD1ED03299EEDAC2E9A99808621502F",
                      "95A3DA06533DDB585D3533010C42A0D9"),
]
VECTORS = [  # (label, key, Mlen, tag)
    ("AES-128 ex1", K128,  0, "BB1D6929E95937287FA37D129B756746"),
    ("AES-128 ex2", K128, 16, "070A16B46B4D4144F79BDD9DD04A287C"),
    ("AES-128 ex3", K128, 20, "7D85449EA6EA19C823A7BF78837DFADE"),
    ("AES-128 ex4", K128, 40, "DFA66747DE9AE63030CA32611497C827"),
    ("AES-128 ex5", K128, 64, "51F0BEBF7E3B9D92FC49741779363CFE"),
    ("AES-192 ex1", K192,  0, "D17DDF46ADAACDE531CAC483DE7A9367"),
    ("AES-192 ex2", K192, 16, "9E99A7BF31E710900662F65E617C5184"),
    ("AES-192 ex3", K192, 20, "3D75C194ED96070444A9FA7EC740ECF8"),
    ("AES-192 ex4", K192, 64, "A1D5DF0EED790F794D77589659F39A11"),
    ("AES-256 ex1", K256,  0, "028962F61B7BF89EFC6B551F4667D983"),
    ("AES-256 ex2", K256, 16, "28A7023F452E8F82BD4BF28D8C37C35C"),
    ("AES-256 ex3", K256, 20, "156727DC0878944A023C1FE03BAD6D93"),
    ("AES-256 ex4", K256, 64, "E1992190549F6ED5696A2C056C315410"),
]
VEC = [(lab, K, MSG[:n], bytes.fromhex(t)) for lab, K, n, t in VECTORS]
W4 = VEC[3][3]                                    # AES-128, Mlen = 40

section("gen_subkeys vs published L, K1, K2")
for lab, K, *pub in SUBKEYS:
    got = [v2b(x, 16).hex().upper() for x in Cmac(K).gen_subkeys()]
    check(f"{lab} L, K1, K2 (KLEE, REF)", True, (got, ref_cmac(K, b'')[1]), (pub, pub))

section("vectors")
def verified(K, M, t):
    cl = run(K, M)
    cl.setst(VERIFY, 'C', t)
    return cl.state
for lab, K, M, W in VEC:
    for name, got, want in (
            ("REF", ref_cmac(K, M)[0], W), ("one block per kl.exec", tag(K, M), W),
            ("multi-block kl.exec, KLLEN 2b, filler ignored (MGR3, MGR7, MGR8)",
             v2b(run(K, M, per_exec=0, junk=True).exec('C', klen=2 * B), 32), W + bytes(16)),
            ("#hash_verify: Success, filler ignored; tampered: Failure",
             [verified(K, M, b2v(W) | junk_above(B)), verified(K, M, b2v(W) ^ 1 << 7)],
             [SUCCESS, FAILURE]),
            ("export/import after every instruction", tag(K, M, hop=True), W)):
        check(f"{lab} {name}", True, got, want)
for lab, K, M, W in (v for v in VEC if not v[2]):
    check(f"{lab}: last_blk_len = 0 does not read INPUT", True, tag(K, M, dummy=MASK128), W)

section("Form B kl.setst #hash_last_block: Xs")
def at_absorb(K=K128, **kw):
    cl = Cmac(K, **kw)
    cl.setst(ABSORB)
    return cl
for Xs, bad in [(x, True) for x in (136, 129, 4, 12, 127)] + [(x, False) for x in (0, 8, 64, 120, 128)]:
    cl = at_absorb()
    check(f"Xs = {Xs} {'-> Invalid' if bad else 'admissible'}", True,
          (raises(cl.setst, LAST, 'B', Xs, exc=Invalid), cl.state), (bad, INVALID if bad else LAST))

section("Serialized Content")
info("<<KLEE-CMAC-mode>> Serialized Content rows are packed from bit 0 upwards (lowest address first).")
fits = True
for vals in ((MASK128, B), (0, 0), (1, B - 8)):
    cl = Cmac(K128)
    cl.hash, cl.last_blk_len = vals
    fits &= vars(cl.imported(cl.export())) == vars(cl)
check("every admissible value fits its row", fits)
check("export/import after every instruction, 64-bit SKID key: ex4", True,
      tag(K128, MSG[:40], hop=True, skid=0x0123456789ABCDEF), W4)

section("state machine")
def done_ok(verify=None):
    """ex4 run to Success (tag emitted), or to Success/Failure by verification."""
    cl = run(K128, MSG[:40])
    cl.exec('C') if verify is None else cl.setst(VERIFY, 'C', verify)
    return cl
def last_set():
    cl = at_absorb()
    cl.setst(LAST, 'B', 64)
    return cl
INVALID_CASES = [
    ("kl.exec in Ready (GR17)", lambda: Cmac(K128), lambda c: c.exec('B')),
    ("kl.setst #hash_last_block from Ready", lambda: Cmac(K128), lambda c: c.setst(LAST, 'B', 0)),
    ("kl.setst #hash_verify in Hash_Absorb", at_absorb, lambda c: c.setst(VERIFY, 'C', 0)),
    ("kl.exec Form A in Hash_Absorb", at_absorb, lambda c: c.exec('A')),
    ("kl.exec Form C in Hash_Absorb", at_absorb, lambda c: c.exec('C')),
    ("KLLEN = 64 in Hash_Absorb (MGR2)", at_absorb, lambda c: c.exec('B', 0, 64)),
    ("KLLEN = 136 in Hash_Absorb (MGR2)", at_absorb, lambda c: c.exec('B', 0, 136)),
    ("KLLEN = 200 in Hash_Absorb (MGR2)", at_absorb, lambda c: c.exec('B', 0, 200)),
    ("KLLEN = 56 < last_blk_len = 64", last_set, lambda c: c.exec('B', 0, 56)),
    ("second kl.exec after the last block", lambda: run(K128, MSG[:40]), lambda c: c.exec('B', 0, 64)),
    ("second tag kl.exec, in Success (GR21)", done_ok, lambda c: c.exec('C')),
    ("kl.setst #hash_absorb in Success (GR20)", done_ok, lambda c: c.setst(ABSORB)),
    ("kl.setst #hash_absorb in Failure (GR20)", lambda: done_ok(0), lambda c: c.setst(ABSORB)),
    ("MGR17: a same-State kl.setst into _Hash_Output_", lambda: run(K128, MSG[:40]), lambda c: c.setst(OUTPUT)),
]
INVALID_CASES += [
    ("tag output with MachinePolicy = 0b10 (MGR11)", lambda: run(K128, MSG[:40], cl=Cmac(K128, policy=2)),
     lambda c: c.exec('C')),
    ("kl.setst #hash_verify with MachinePolicy = 0b01 (MGR11)", lambda: run(K128, MSG[:40], cl=Cmac(K128, policy=1)),
     lambda c: c.setst(VERIFY, 'C', b2v(W4))),
]
for name, mk, act in INVALID_CASES:
    cl = mk()
    check(f"{name} -> Invalid", raises(act, cl, exc=Invalid) and cl.state == INVALID)
cl = Cmac(K128)
raises(cl.exec, 'B', exc=Invalid)
check("Error State: Content cleared (GR22); kl.exec no operation, OUTPUT 0 (GR26)", True,
      (cl.key, cl.hash, cl.exec('C'), cl.state), (None, 0, 0, INVALID))
subst = all(tag(K, M, subst=True) == W for _, K, M, W in VEC)
cl = run(K128, MSG[:40], subst=True)
cl.setst(VERIFY, 'A', b2v(W4))
check("Form D kl.exec, Form A kl.setst #hash_verify substitutions: all vectors",
      subst and cl.state == SUCCESS)
vcl = run(K128, MSG[:40], cl=Cmac(K128, policy=2))
vcl.setst(VERIFY, 'C', b2v(W4))
z_out, z_ver = run(K128, MSG[:40], cl=Cmac(K128, policy=0)), run(K128, MSG[:40], cl=Cmac(K128, policy=0))
check("MachinePolicy = 0b10 verifies, 0b01 emits the tag; MachinePolicy = 0 is admissible but useless: "
      "provisioned and absorbs, then both output and verification -> Invalid (MGR11)", True,
      (vcl.state, tag(None, MSG[:40], cl=Cmac(K128, policy=1)), z_out.state,
       raises(z_out.exec, 'C', exc=Invalid), raises(z_ver.setst, VERIFY, 'C', b2v(W4), exc=Invalid)),
      (SUCCESS, W4, OUTPUT, True, True))
check("truncated 64-bit tag -> Failure (all b bits compared)", True,
      done_ok(b2v(W4[:8])).state, FAILURE)
for name, mk in (("Success", done_ok), ("Failure", lambda: done_ok(0)),
                 ("Hash_Absorb", at_absorb)):
    cl = mk()
    cl.setst(READY)
    check(f"kl.setst #ready from {name}, then ex4 (GR15)", True, tag(None, MSG[:40], cl=cl), W4)

section("kl.derive")
secret = K128 + bytes(range(0xF0, 0x100))
for length in (16, 32):
    cl = Cmac(bytes(16))
    derive(secret, cl, length)
    check(f"shared secret (GR40) into `key` in Ready, length {length}, then ex4", True, tag(None, MSG[:40], cl=cl), W4)
new16 = lambda: Cmac(bytes(16))
for name, mk, src, n in [
        ("length 8 into the 16-byte key, no zero-fill (GR36 item 5)", new16, secret, 8),
        ("length 0 into the key (GR36 item 5)", new16, secret, 0),
        ("12-byte source into the 16-byte key (GR36 item 5)", new16, K128[:12], 16),
        ("into a locker in Hash_Absorb_Last_Block (GR36 items 1-2)", last_set, secret, 16),
        ("into a locker in Success (GR36 items 1-2)", done_ok, secret, 16),
        ("into the key of a KeyType 1 locker (GR39, GR36 item 2)", lambda: Cmac(K128, skid=7), secret, 16),
        ("24 bytes into Hash_Absorb: short block (GR43, MGR2)", at_absorb, MSG[:24], 24)]:
    cl = mk()
    check(f"{name} -> Invalid", raises(derive, src, cl, n, exc=Invalid) and cl.key is None)
cl = at_absorb()
derive(MSG[:32], cl, 32)
cl.setst(LAST, 'B', 64)
cl.exec('B', b2v(MSG[32:40]), 64)
check("32 bytes into Hash_Absorb, then the last block: ex4", True, v2b(cl.exec('C'), 16), W4)
src, dst = run(K128, MSG[:16]), at_absorb(K256)
derive(src, dst, 16)
dst.setst(LAST, 'B', 64)
dst.exec('B', b2v(MSG[:8]), 64)
check("CMAC tag (Hash_Output) into another CMAC's Hash_Absorb: REF; source in Success", True,
      (v2b(dst.exec('C'), 16), src.state), (ref_cmac(K256, VEC[1][3] + MSG[:8])[0], SUCCESS))
src, dst = run(K128, MSG[:16]), Cmac(bytes(16))
derive(src, dst, 16)
check("CMAC tag into another CMAC's `key` in Ready (GR41 key derivation, unrestricted), then MSG[:40]: REF",
      True, (src.state, dst.state, dst.key, tag(None, MSG[:40], cl=dst)),
      (SUCCESS, READY, VEC[1][3], ref_cmac(VEC[1][3], MSG[:40])[0]))
src, dst = run(K128, MSG[:16]), Cmac(bytes(32))
check("16-byte CMAC tag into a 32-byte `key` (GR36 item 5) -> only the destination Invalid",
      raises(derive, src, dst, 32, exc=Invalid) and (src.state, dst.state) == (OUTPUT, INVALID))
src, dst = at_absorb(), Cmac(bytes(16))
check("CMAC in Hash_Absorb as a source (no source endpoint) -> only the source Invalid",
      raises(derive, src, dst, 16, exc=Invalid) and (src.state, dst.state) == (INVALID, READY))

section("negative controls")
control("K2 for a full final block", all(tag(K, M, k2full=True) != W for _, K, M, W in VEC
                                         if M and len(M) % 16 == 0))
control("subkeys via little-endian update_mask", any(tag(K, M, dbl=update_mask) != W
                                                     for _, K, M, W in VEC))
control("multi-block kl.exec, most significant block first",
        all(tag(K, M, per_exec=0, msb_first=True) != W for _, K, M, W in VEC if len(M) >= 40))
control("Serialized Content without `hash`",
        all(tag(K, M, hop=True, lay=[r for r in layout(8 * len(K)) if r[0] != 'hash']) != W
            for _, K, M, W in VEC if len(M) >= 16))
done()
