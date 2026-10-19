#!/usr/bin/env python3
"""CMAC KAT: the Machine of <<KLE-CMAC-mode>> against SP 800-38B / RFC 4493, with its
state machine, Serialized Content and kl.derive endpoints."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bxor, aes_encrypt, tdea_encrypt, update_mask, double_ocb, MASK128,
                    KL_STATE_READY as READY, KL_STATE_HASH_ABSORB as ABSORB,
                    KL_STATE_HASH_LAST_BLOCK as LAST, KL_STATE_HASH_VERIFY as VERIFY,
                    KL_STATE_HASH_OUTPUT as OUTPUT, KL_STATE_SUCCESS as SUCCESS,
                    KL_STATE_FAILURE as FAILURE, KL_STATE_INVALID as INVALID, ERROR_STATES,
                    KL_STATE_UNCONFIGURED as UNCONF, KL_STATE_PRIV_VIOLATION as PRIV, inert, IllegalInstruction,
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

# ---------------------------------------------------------------- KLE model
class Invalid(Exception): pass
SKS = {}

def layout(kbits, b=128):
    return [('key', kbits), ('hash', b), ('last_block_len', 32), ('tag_len', 32), ('absorbed_any', 1), ('absorbed_all', 1)]

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
    def __init__(s, key, skid=None, policy=3, cipher='aes', **nc):
        """policy: _MachinePolicy_, bit 0 generation (_Hash_Output_), bit 1 verification (_Hash_Verify_);
        zero is invalid Metadata (<<KLE-CMAC-mode>>, <<KLE-Metadata-validity>>); a higher bit, unsupported
        Metadata, is not modelled."""
        if not policy:
            raise Invalid('MachinePolicy')
        s.key, s.skid, s.state, s.policy = key, skid, READY, policy
        s.cipher, s.b = cipher, 64 if cipher == 'tdea' else 128   # <<KLE-CMAC-mode>>: b = 64 or 128
        s.nc = dict(dict(dbl=double_ocb, k2full=False, msb_first=False, min_tag=64), **nc)
        if skid is not None:
            SKS[skid] = key
        s._ready()
    def _ready(s):
        s.hash = s.last_block_len = s.tag_len = 0
        s.absorbed_any = s.absorbed_all = False
    def _invalid(s, why=None):
        s.state, s.key, s.skid = INVALID, None, None   # GR29
        s._ready()
        if why:
            raise Invalid(why)
    def enc(s, v):
        E = tdea_encrypt if s.cipher == 'tdea' else aes_encrypt
        return b2v(E(s.key, v2b(v, s.b // 8)))
    def gen_subkeys(s):
        L = s.enc(0)
        K1 = s.nc['dbl'](L, s.b)
        return L, K1, s.nc['dbl'](K1, s.b)
    # (immed, Form) -> States it is allowed from; no same-State kl.setst (GR17): no State loads a field (MR9)
    SETST = {(ABSORB, 'A'): (READY,), (LAST, 'B'): (ABSORB,),
             (OUTPUT, 'A'): (LAST,), (VERIFY, 'B'): (LAST,)}
    def setst(s, immed, form='A', aux=0):
        if immed in (54, 55):
            raise IllegalInstruction('reserved #immed7')  # GR18
        if immed == UNCONF or immed in ERROR_STATES:  # kl.clear, GR30: in every State and Form
            if s.state != UNCONF:
                s.state, s.key, s.skid = immed, None, None  # GR29
                s._ready()
            return
        if inert(s.state):                        # GR26
            return
        if immed == READY and form == 'A':        # GR16: Form A
            s.state = READY
            return s._ready()
        if s.state not in s.SETST.get((immed, form), ()):
            s._invalid('transition')              # MR1, GR16
        if immed == LAST:
            if aux > s.b or aux % 8:
                s._invalid('Xs')
            s.last_block_len = aux
            if aux == 0:                          # empty final block: padded, absorbed, no kl.exec
                if s.absorbed_any:
                    s._invalid('Xs = 0 after a block')  # whole blocks end with a full last block
                s.hash, s.absorbed_all = s.enc(s.hash ^ cat((0, s.b - 8), (0x80, 8)) ^ s.gen_subkeys()[2]), True
        elif immed in (OUTPUT, VERIFY) and not s.policy & (1 if immed == OUTPUT else 2):
            s._invalid('MachinePolicy')           # MR11: generation, resp. verification, not permitted
        elif immed in (OUTPUT, VERIFY) and not s.absorbed_all:
            s._invalid('last block not absorbed')  # entering _Hash_Output_ or _Hash_Verify_
        elif immed == VERIFY:
            if aux < s.nc['min_tag'] or aux % 8:
                s._invalid('tag_len')
            s.tag_len = min(aux, s.b)
        s.state = immed
    def restrictl(s, clear):                      # kl.restrictl clearing _MachinePolicy_ bits (GR20)
        if inert(s.state):
            return
        s.policy &= ~clear
        if not s.policy:
            s._invalid('GR20: _MachinePolicy_ = 0, which the Machine forbids')
    def exec(s, form, INPUT=0, klen=None, klstart=0):
        klen = s.b if klen is None else klen
        st = s.state
        if inert(st):                             # GR26, GR28
            return 0
        if (st, s.policy & (1 if st == OUTPUT else 2)) in ((OUTPUT, 0), (VERIFY, 0)):
            s._invalid('MR11, GR20: the operation of the State is disabled')
        if form not in ({ABSORB: 'BD', LAST: 'BD', OUTPUT: 'CD', VERIFY: 'BD'}.get(st) or ''):
            s._invalid('Form')                    # MR1, GR17, GR16
        short = (st == ABSORB and klen % s.b or st == LAST and klen < s.last_block_len
                 or st == OUTPUT and klen < 64 or st == VERIFY and klen < s.tag_len)
        if not short and 8 * klstart >= klen:
            return 0                              # GR44 item 2: an empty window does not reach the Machine
        if not short and klstart and (st != ABSORB or 8 * klstart % s.b):
            s._invalid('GR44 item 3')             # MR3: block offsets in _Hash_Absorb_, 0 elsewhere
        if st == ABSORB:
            if klen % s.b:
                s._invalid('MR2')
            pos = range(8 * klstart, klen, s.b)     # MR3: a resumption skips the blocks done
            for i in (reversed(pos) if s.nc['msb_first'] else pos):
                s.hash = s.enc(s.hash ^ sl(INPUT, i + s.b - 1, i))
                s.absorbed_any = True
            return 0
        if st == OUTPUT:
            if klen < 64:
                s._invalid('MR2: a tag of fewer than 64 bits')
            s.state = SUCCESS
            return s.hash & ((1 << klen) - 1)     # MR8: the bits beyond b are cleared
        if st == VERIFY:                          # MR14: constant-time compare of the first tag_len bits
            n = s.tag_len
            if klen < n:
                s._invalid('KLLEN < tag_len')     # MR2
            s.state = SUCCESS if sl(INPUT, n - 1, 0) == sl(s.hash, n - 1, 0) else FAILURE
            return 0
        n = s.last_block_len
        if klen < n:
            s._invalid('KLLEN < last_block_len')  # MR2, GR44 item 1
        if klen == 0:
            return 0                              # GR44 item 2: an empty window does not reach the Machine
        if s.absorbed_all:
            s._invalid('second last block')
        INPUT = sl(INPUT, s.b - 1, 0)               # MR7
        _, K1, K2 = s.gen_subkeys()
        if n == s.b:
            tmp = INPUT ^ (K2 if s.nc['k2full'] else K1)
        else:                                     # 0 < n < s.b (n = 0 never reaches a kl.exec)
            tmp = cat((0, s.b - 8 - n), (0x80, 8), (sl(INPUT, n - 1, 0), n)) ^ K2
        s.hash, s.absorbed_all = s.enc(s.hash ^ tmp), True
        return 0
    def lay(s):
        return layout(64 if s.skid is not None else 8 * len(s.key), s.b)
    def export(s, lay=None):
        return pack(dict(key=s.skid if s.skid is not None else b2v(s.key), hash=s.hash,
                         last_block_len=s.last_block_len, tag_len=s.tag_len,
                         absorbed_any=int(s.absorbed_any), absorbed_all=int(s.absorbed_all)),
                    lay or s.lay())
    def imported(s, c1, lay=None):
        """A fresh locker with this locker's MDH, loaded from Content1."""
        f = unpack(c1, lay or s.lay())
        new = Cmac(SKS[f['key']] if s.skid is not None else v2b(f['key'], len(s.key)), s.skid, s.policy, s.cipher, **s.nc)
        new.state, new.hash = s.state, f.get('hash', 0)
        new.last_block_len, new.tag_len = f['last_block_len'], f.get('tag_len', 0)
        new.absorbed_any, new.absorbed_all = bool(f.get('absorbed_any', 0)), bool(f.get('absorbed_all', 0))
        return new

class Keystream(bytes):
    """The keystream that a Keystream generation locker in _Operate_ supplies (GR35)."""

def derive(src, dst, length):
    """kl.derive; src is a Cmac locker, a Keystream, or the bytes of a GR34/GR35 source.
    Endpoints: `hash` in Hash_Output (GR35 source, b/8 bytes); `key` in Ready (destination)."""
    lockers = [c for c in (src, dst) if isinstance(c, Cmac)]
    if any(inert(c.state) for c in lockers):
        return                                    # GR26: an inert endpoint
    if isinstance(src, Cmac) and src.state == OUTPUT and not src.policy & 1:
        src._invalid('MR11: generation disabled')
    if isinstance(src, Cmac) and src.state != OUTPUT:
        src._invalid('GR32 item 1')
    if dst.state != READY or dst.skid is not None:
        dst._invalid('GR32 item 2')               # the kl.exec input is no destination; GR68
    # GR32 item 3 holds: GR34-GR35 admit every source here into a key
    avail = src.b // 8 if isinstance(src, Cmac) else len(src)
    if length < len(dst.key) or avail < len(dst.key):
        dst._invalid('GR32 item 5')
    data = v2b(src.exec('C'), avail) if isinstance(src, Cmac) else src
    dst.key = data[:len(dst.key)]

def run(K, M, per_exec=1, junk=False, hop=False, lay=None, subst=False, cl=None,
        skid=None, to=OUTPUT, **nc):
    """<<KLE-pseudocode-CMAC>> up to the last block, then into `to` (None: stay in
    _Hash_Absorb_Last_Block_); hop exports/imports after every instruction."""
    fB = 'D' if subst else 'B'
    cl = cl or Cmac(K, skid, **nc)
    nxt = (lambda c: c.imported(c.export(lay), lay)) if hop else (lambda c: c)
    bs = cl.b // 8
    cl.setst(ABSORB); cl = nxt(cl)
    nfull = (len(M) - 1) // bs if M else 0
    step = per_exec or max(nfull, 1)
    for a in range(0, nfull, step):
        e = min(nfull, a + step)
        cl.exec(fB, b2v(M[bs * a:bs * e]), cl.b * (e - a)); cl = nxt(cl)
    tail = M[bs * nfull:]
    cl.setst(LAST, 'B', 8 * len(tail)); cl = nxt(cl)
    if tail and junk:
        cl.exec(fB, b2v(tail) | junk_above(8 * len(tail)), 2 * B)
    elif tail:
        cl.exec(fB, b2v(tail), 8 * len(tail))
    cl = nxt(cl)
    if to == OUTPUT:
        cl.setst(OUTPUT)
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
    check(f"{lab} L, K1, K2 (KLE, REF)", True, (got, ref_cmac(K, b'')[1]), (pub, pub))

section("vectors")
def verified(K, M, t, tag_len=B, form='B'):
    cl = run(K, M, to=None)
    cl.setst(VERIFY, 'B', tag_len)
    cl.exec(form, t, 2 * B)
    return cl.state
for lab, K, M, W in VEC:
    for name, got, want in (
            ("REF", ref_cmac(K, M)[0], W), ("one block per kl.exec", tag(K, M), W),
            ("multi-block kl.exec, KLLEN 2b, filler ignored (MR3, MR7, MR8)",
             v2b(run(K, M, per_exec=0, junk=True).exec('C', klen=2 * B), 32), W + bytes(16)),
            ("#hash_verify: Success, filler ignored; tampered: Failure",
             [verified(K, M, b2v(W) | junk_above(B)), verified(K, M, b2v(W) ^ 1 << 7)],
             [SUCCESS, FAILURE]),
            ("export/import after every instruction", tag(K, M, hop=True), W)):
        check(f"{lab} {name}", True, got, want)
for lab, K, M, W in (v for v in VEC if not v[2]):
    cl, cv = Cmac(K), Cmac(K)
    for c in (cl, cv):
        c.setst(ABSORB)
        c.setst(LAST, 'B', 0)
    st, ab = cl.state, cl.absorbed_all
    cl.setst(OUTPUT)
    cv.setst(VERIFY, 'B', B)
    cv.exec('B', b2v(W))
    check(f"{lab}: Xs = 0 absorbs the empty block without a kl.exec, stays in _Hash_Absorb_Last_Block_; then "
          "output and verification both work", True, (st, ab, v2b(cl.exec('C'), 16), cv.state),
          (LAST, True, W, SUCCESS))
    ce = Cmac(K)
    ce.setst(ABSORB)
    ce.setst(LAST, 'B', 0)
    try:
        ce.exec('B', 0, 0)
    except Invalid:
        pass
    st = ce.state
    check(f"{lab}: after Xs = 0, a kl.exec with KLLEN = 0 is an empty window that does not reach the Machine "
          "(GR44 item 2): _Hash_Absorb_Last_Block_ kept, the tag unchanged", True,
          (st, st == LAST and (ce.setst(OUTPUT) or v2b(ce.exec('C'), 16))), (LAST, W))

section("Form B kl.setst #hash_last_block: Xs")
def at_absorb(K=K128, **kw):
    cl = Cmac(K, **kw)
    cl.setst(ABSORB)
    return cl
for Xs, bad in [(x, True) for x in (136, 129, 4, 12, 127)] + [(x, False) for x in (0, 8, 64, 120, 128)]:
    cl = at_absorb()
    check(f"Xs = {Xs} {'-> Invalid' if bad else 'admissible'}", True,
          (raises(cl.setst, LAST, 'B', Xs, exc=Invalid), cl.state),
          (bad, INVALID if bad else LAST))

section("Serialized Content")
info("<<KLE-CMAC-mode>> Serialized Content rows are packed from bit 0 upwards (lowest address first).")
fits = True
for vals in ((MASK128, B, B, True, True), (0, 0, 0, False, False), (1, B - 8, 64, True, False)):
    cl = Cmac(K128)
    cl.hash, cl.last_block_len, cl.tag_len, cl.absorbed_all, cl.absorbed_any = vals
    fits &= vars(cl.imported(cl.export())) == vars(cl)
check("every admissible value fits its row", fits)
check("export/import after every instruction, 64-bit SKID key: ex4", True,
      tag(K128, MSG[:40], hop=True, skid=0x0123456789ABCDEF), W4)

section("state machine")
def done_ok(verify=None, tag_len=B):
    """ex4 run to Success (tag emitted), or to Success/Failure by verification."""
    if verify is None:
        cl = run(K128, MSG[:40])
        cl.exec('C')
        return cl
    cl = run(K128, MSG[:40], to=None)
    cl.setst(VERIFY, 'B', tag_len)
    cl.exec('B', verify)
    return cl
def last_set():
    cl = at_absorb()
    cl.setst(LAST, 'B', 64)
    return cl
at_last = lambda: run(K128, MSG[:40], to=None)
at_verify = lambda: (lambda c: (c.setst(VERIFY, 'B', B), c)[1])(at_last())
INVALID_CASES = [
    ("kl.exec in Ready (GR17)", lambda: Cmac(K128), lambda c: c.exec('B')),
    ("kl.setst #hash_last_block from Ready", lambda: Cmac(K128), lambda c: c.setst(LAST, 'B', 0)),
    ("kl.setst #hash_verify in Hash_Absorb", at_absorb, lambda c: c.setst(VERIFY, 'B', B)),
    ("kl.setst #hash_output before the last block is absorbed", last_set, lambda c: c.setst(OUTPUT)),
    ("kl.setst #hash_verify before the last block is absorbed", last_set, lambda c: c.setst(VERIFY, 'B', B)),
    ("kl.setst #hash_verify with Xs = 0: a 0-bit compare would accept any tag", at_last, lambda c: c.setst(VERIFY, 'B', 0)),
    ("kl.setst #hash_verify with Xs = 56 < 64", at_last, lambda c: c.setst(VERIFY, 'B', 56)),
    ("kl.setst #hash_verify with Xs = 100, not a multiple of 8", at_last, lambda c: c.setst(VERIFY, 'B', 100)),
    ("kl.setst #hash_verify of Form C", at_last, lambda c: c.setst(VERIFY, 'C', B)),
    ("Xs = 0 after a block was absorbed: not a CMAC of any message", lambda: (lambda c: (c.exec('B', 0), c)[1])(at_absorb()),
     lambda c: c.setst(LAST, 'B', 0)),
    ("same-State kl.setst #hash_verify (GR17)", at_verify, lambda c: c.setst(VERIFY, 'B', 64)),
    ("kl.setst #hash_output with MachinePolicy = 2 (verify only, MR11)",
     lambda: run(K128, MSG[:40], to=None, cl=Cmac(K128, policy=2)), lambda c: c.setst(OUTPUT)),
    ("kl.setst #hash_verify with MachinePolicy = 1 (generate only, MR11)",
     lambda: run(K128, MSG[:40], to=None, cl=Cmac(K128, policy=1)), lambda c: c.setst(VERIFY, 'B', B)),
    ("same-State kl.setst #hash_last_block after the last block (GR17)", at_last, lambda c: c.setst(LAST, 'B', 0)),
    ("same-State kl.setst #hash_last_block before its kl.exec, absorbed_all = false (GR17)", last_set,
     lambda c: c.setst(LAST, 'B', 64)),
    ("same-State kl.setst #hash_absorb (GR17)", at_absorb, lambda c: c.setst(ABSORB)),
    ("KLLEN = 64 < tag_len = 128 in Hash_Verify (MR2)", at_verify, lambda c: c.exec('B', 0, 64)),
    ("kl.exec Form C in Hash_Verify", at_verify, lambda c: c.exec('C')),
    ("kl.exec Form A in Hash_Absorb", at_absorb, lambda c: c.exec('A')),
    ("kl.exec Form C in Hash_Absorb", at_absorb, lambda c: c.exec('C')),
    ("KLLEN = 64 in Hash_Absorb (MR2)", at_absorb, lambda c: c.exec('B', 0, 64)),
    ("KLLEN = 136 in Hash_Absorb (MR2)", at_absorb, lambda c: c.exec('B', 0, 136)),
    ("KLLEN = 200 in Hash_Absorb (MR2)", at_absorb, lambda c: c.exec('B', 0, 200)),
    ("KLLEN = 56 < last_block_len = 64", last_set, lambda c: c.exec('B', 0, 56)),
    ("second kl.exec after the last block", at_last, lambda c: c.exec('B', 0, 64)),
    ("second tag kl.exec, in Success (GR16)", done_ok, lambda c: c.exec('C')),
    ("kl.setst #hash_absorb in Success (GR16)", done_ok, lambda c: c.setst(ABSORB)),
    ("kl.setst #hash_absorb in Failure (GR16)", lambda: done_ok(0), lambda c: c.setst(ABSORB)),
    ("same-State kl.setst #hash_output (GR17)", lambda: run(K128, MSG[:40]), lambda c: c.setst(OUTPUT)),
    ("Form B kl.setst naming Ready (GR16, GR62)", at_absorb, lambda c: c.setst(READY, 'B', 0)),
]
for name, mk, act in INVALID_CASES:
    cl = mk()
    check(f"{name} -> Invalid", raises(act, cl, exc=Invalid) and cl.state == INVALID)
cl = Cmac(K128)
raises(cl.exec, 'B', exc=Invalid)
check("Error State: Content cleared (GR29); kl.exec no operation, OUTPUT 0 (GR26, GR28)", True,
      (cl.key, cl.hash, cl.exec('C'), cl.state), (None, 0, 0, INVALID))
subst = all(tag(K, M, subst=True) == W for _, K, M, W in VEC)
check("Form D kl.exec substitutions, verification included: all vectors",
      subst and all(verified(K, M, b2v(W), form='D') == SUCCESS for _, K, M, W in VEC))
vcl = done_ok(b2v(W4))
def policy_run(p):
    g = tag(None, MSG[:40], cl=Cmac(K128, policy=p)) if p & 1 else None
    cl = run(K128, MSG[:40], to=None, cl=Cmac(K128, policy=p))
    if p & 2:
        cl.setst(VERIFY, 'B', B)
        cl.exec('B', b2v(W4))
    return g, cl.state if p & 2 else None
check("MachinePolicy: 1 generates only, 2 verifies only (a verify-only key), 3 both; 0 is invalid Metadata", True,
      ([policy_run(p) for p in (1, 2, 3)], vcl.state, raises(Cmac, K128, policy=0, exc=Invalid)),
      ([(W4, None), (None, SUCCESS), (W4, SUCCESS)], SUCCESS, True))
check("truncated tags (SP 800-38B MSB_Tlen = the first bytes): 64 and 96 bits verify, a wrong bit in them "
      "fails, one beyond them is not compared; Xs = 200 compares all b bits", True,
      [done_ok(b2v(W4[:8]), 64).state, done_ok(b2v(W4[:12]), 96).state, done_ok(b2v(W4[:8]) ^ 1 << 63, 64).state,
       done_ok(b2v(W4) ^ 1 << 64, 64).state, done_ok(b2v(W4[:8]), 200).state, done_ok(b2v(W4), 200).state],
      [SUCCESS, SUCCESS, FAILURE, SUCCESS, FAILURE, SUCCESS])
check("_Hash_Output_ with KLLEN 64 and 96 emits the first 8, resp. 12, bytes (SP 800-38B MSB_Tlen)", True,
      [v2b(run(K128, MSG[:40]).exec('C', klen=n), n // 8) for n in (64, 96)], [W4[:8], W4[:12]])
cl = run(K128, MSG[:40])
check("_Hash_Output_ with KLLEN = 32 < 64 (MR2) -> Invalid", True, (raises(cl.exec, 'C', 0, 32, exc=Invalid), cl.state),
      (True, INVALID))
for name, mk in (("Success", done_ok), ("Failure", lambda: done_ok(0)),
                 ("Hash_Absorb", at_absorb)):
    cl = mk()
    cl.setst(READY)
    check(f"kl.setst #ready from {name}, then ex4 (GR16)", True, tag(None, MSG[:40], cl=cl), W4)

cl = run(K128, MSG[:40]); cl.restrictl(1)
src, dst = run(K128, MSG[:40]), Cmac(bytes(16)); src.restrictl(1)
cv = run(K128, MSG[:40], to=None); cv.restrictl(1); cv.setst(VERIFY, 'B', B); cv.exec('B', b2v(W4))
cz = run(K128, MSG[:40], to=None, cl=Cmac(K128, policy=2)); raises(cz.restrictl, 2, exc=Invalid)
check("kl.restrictl clearing bit 0 (3 -> 2) in _Hash_Output_: the tag kl.exec -> Invalid, OUTPUT 0; as a kl.derive "
      "source -> only the source Invalid; in _Hash_Absorb_Last_Block_ verification still succeeds; clearing the only "
      "set bit -> _MachinePolicy_ = 0 -> Invalid at once (GR20, MR11)", True,
      (raises(cl.exec, 'C', exc=Invalid), cl.state, raises(derive, src, dst, 16, exc=Invalid), src.state, dst.state,
       cv.state, cz.state), (True, INVALID, True, INVALID, READY, SUCCESS, INVALID))

Kx = lambda: run(K128, MSG[:40], to=None)
cb = at_absorb(); cb.exec('B', b2v(MSG[:16])); cb.exec('B', b2v(MSG[:32]), 2 * B, klstart=16)
cb.setst(LAST, 'B', 64); cb.exec('B', b2v(MSG[32:40]), 64); cb.setst(OUTPUT)
cc = at_absorb(); raises(cc.exec, 'B', b2v(MSG[:32]), 2 * B, 1, exc=Invalid)
cd = last_set(); raises(cd.exec, 'B', b2v(MSG[:16]), B, 1, exc=Invalid)
ce = Kx(); ce.setst(OUTPUT); e = ce.exec('C', klen=B, klstart=16)
cf = Kx(); cf.setst(OUTPUT); raises(cf.exec, 'C', 0, B, 1, exc=Invalid)
cg = Kx(); cg.setst(VERIFY, 'B', B); raises(cg.exec, 'B', b2v(W4), B, 1, exc=Invalid)
check("klstart: a resumption in _Hash_Absorb_ at a block offset skips the blocks done (MR3); klstart = 1 in "
      "_Hash_Absorb_, and klstart != 0 in _Hash_Absorb_Last_Block_, _Hash_Output_ and _Hash_Verify_, is no "
      "interruption point (MR3, GR44 item 3) -> Invalid; klstart = KLLEN/8 is an empty window (GR44 item 2)", True,
      (v2b(cb.exec('C'), 16), cc.state, cd.state,
       (e, ce.state), cf.state, cg.state),
      (W4, INVALID, INVALID, (0, OUTPUT), INVALID, INVALID))
ch = Kx(); ch.setst(OUTPUT)
check("klstart = b/8 in _Hash_Output_ with KLLEN = 2b: the State processes a single block, so 16 is no "
      "interruption point (MR3, GR44 item 3) -> Invalid", True,
      (raises(ch.exec, 'C', 0, 2 * B, 16, exc=Invalid), ch.state), (True, INVALID))

section("kl.derive")
secret = K128 + bytes(range(0xF0, 0x100))
for length in (16, 32):
    cl = Cmac(bytes(16))
    derive(secret, cl, length)
    check(f"shared secret (GR34) into `key` in Ready, length {length}, then ex4", True, tag(None, MSG[:40], cl=cl), W4)
new16 = lambda: Cmac(bytes(16))
for name, mk, src, n in [
        ("length 8 into the 16-byte key, no zero-fill (GR32 item 5)", new16, secret, 8),
        ("length 0 into the key (GR32 item 5)", new16, secret, 0),
        ("12-byte source into the 16-byte key (GR32 item 5)", new16, K128[:12], 16),
        ("into a locker in Hash_Absorb_Last_Block (GR32 item 2)", last_set, secret, 16),
        ("into a locker in Success (GR32 item 2)", done_ok, secret, 16),
        ("into the key of a KeyType 1 locker (GR68, GR32 item 2)", lambda: Cmac(K128, skid=7), secret, 16),
        ("keystream into Hash_Absorb: the kl.exec input is no destination (GR32 item 2)", at_absorb,
         Keystream(MSG[:32]), 32),
        ("a shared secret into Hash_Absorb (no destination; GR32 item 2)", at_absorb, secret, 32)]:
    cl = mk()
    check(f"{name} -> Invalid", raises(derive, src, cl, n, exc=Invalid) and cl.key is None)
cl = Cmac(bytes(16))
derive(Keystream(MSG[:32]), cl, 32)
check("32 keystream bytes (GR35) into the 16-byte `key` in Ready: its first 16 bytes, then MSG[:40]: REF", True,
      (cl.key, tag(None, MSG[:40], cl=cl)), (MSG[:16], ref_cmac(MSG[:16], MSG[:40])[0]))
src, dst = run(K128, MSG[:16]), at_absorb(K256)
check("CMAC (Hash_Output) into another CMAC's Hash_Absorb (no destination, GR32 item 2) -> only the destination "
      "Invalid", raises(derive, src, dst, 16, exc=Invalid) and (src.state, dst.state) == (OUTPUT, INVALID))
for n in (16, 32):
    src, dst = run(K128, MSG[:16]), Cmac(bytes(16))
    derive(src, dst, n)
    check(f"CMAC (Hash_Output, b/8 = 16 bytes) into another CMAC's `key` in Ready (GR35, unrestricted), length {n}, "
          "then MSG[:40]: REF", True, (src.state, dst.state, dst.key, tag(None, MSG[:40], cl=dst)),
          (SUCCESS, READY, VEC[1][3], ref_cmac(VEC[1][3], MSG[:40])[0]))
src, dst = run(K128, MSG[:16]), Cmac(bytes(16))
check("CMAC as a source with length 8 < 16 (GR32 item 5; the source supplies all b/8 bytes, never a truncated tag) "
      "-> only the destination Invalid",
      raises(derive, src, dst, 8, exc=Invalid) and (src.state, dst.state) == (OUTPUT, INVALID))
src, dst = run(K128, MSG[:16]), Cmac(bytes(32))
check("16-byte CMAC into a 32-byte `key` (GR32 item 5) -> only the destination Invalid",
      raises(derive, src, dst, 32, exc=Invalid) and (src.state, dst.state) == (OUTPUT, INVALID))
src, dst = at_absorb(), Cmac(bytes(16))
check("CMAC in Hash_Absorb as a source (no source endpoint, GR32 item 1) -> only the source Invalid",
      raises(derive, src, dst, 16, exc=Invalid) and (src.state, dst.state) == (INVALID, READY))
src, dst = at_absorb(), at_absorb(K256)
check("neither endpoint valid: GR32 item 1 fails first -> only the source Invalid",
      raises(derive, src, dst, 16, exc=Invalid) and (src.state, dst.state) == (INVALID, ABSORB))

section("b = 64: CMAC-TDES (NIST CMAC examples, SP 800-38B R_64)")
TK3 = bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123")
TK2 = TK3[:16]                                    # 2-key TDEA: K3 = K1
TM = bytes.fromhex("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51")
TDES = [(TK3, 0, "7DB0D37DF936C550"), (TK3, 16, "30239CF1F52E6609"), (TK3, 20, "6C9F3EE4923F6BE2"),
        (TK3, 32, "99429BD0BF7904E5"), (TK2, 0, "79CE52A7F786A960"), (TK2, 16, "CC18A0B79AF2413B")]

run64 = lambda K, M, hop=False, to=OUTPUT: run(K, M, hop=hop, to=to, cipher='tdea')

check("CMAC-TDES subkeys (3-key): L, K1 = double(L), K2 = double(K1) with R_64 = 0x1B", True,
      [v2b(x, 8).hex().upper() for x in Cmac(TK3, cipher='tdea').gen_subkeys()],
      ["4EBA739C998BCB60", "9D74E739331796C0", "3AE9CE72662F2D9B"])
for K, n, want in TDES:
    for hop in (False, True):
        got = v2b(run64(K, TM[:n], hop).exec('C', klen=64), 8).hex().upper()
        check(f"CMAC-TDES {len(K) // 8}-key, Mlen = {8 * n}{', export/import after every instruction' if hop else ''}",
              True, got, want)
cl = run64(TK3, TM[:32], to=None)
cl.setst(VERIFY, 'B', 64)
cl.exec('B', b2v(bytes.fromhex("99429BD0BF7904E5")), 64)
cv = run64(TK3, TM[:32], to=None)
cv.setst(VERIFY, 'B', 128)                        # tag_len <- min(Xs, b) = 64
cv.exec('B', b2v(bytes.fromhex("99429BD0BF7904E4")), 64)
check("CMAC-TDES _Hash_Verify_: tag_len = 64 = b matches -> Success; Xs = 128 clamped to b, last bit flipped -> Failure",
      True, (cl.state, cv.tag_len, cv.state), (SUCCESS, 64, FAILURE))
src, dst = run64(TK3, TM[:32]), Cmac(bytes(16))
check("CMAC-TDES as a kl.derive source supplies b/8 = 8 bytes: into a 16-byte `key` (GR32 item 5) -> only the "
      "destination Invalid", raises(derive, src, dst, 16, exc=Invalid) and (src.state, dst.state) == (OUTPUT, INVALID))
check("CMAC-TDES: Serialized Content holds a 64-bit `hash`", True,
      [w for f, w in Cmac(TK3, cipher='tdea').lay() if f == 'hash'], [64])

section("kl.clear, Error-State kl.setst, reserved #immed7")
c1 = at_absorb(); c1.exec('B', b2v(MSG[:16])); c1.setst(UNCONF)
check("kl.clear in _Hash_Absorb_ -> _Unconfigured_, Content cleared; a later kl.exec or kl.setst performs no "
      "operation, OUTPUT zeroed (GR26, GR28)", True,
      (c1.state, c1.key, c1.hash, c1.exec('C'), c1.setst(READY), c1.state), (UNCONF, None, 0, 0, None, UNCONF))
c2 = Cmac(K128); c2.setst(PRIV); c3 = Kx(); c3.setst(OUTPUT); c3.setst(PRIV); c3.setst(INVALID)
check("kl.setst naming _Privilege Violation_ in _Ready_ and in _Hash_Output_ -> that State, Content cleared; a "
      "second Error-State kl.setst replaces it (GR30, GR29)", True,
      (c2.state, c2.key, c3.state, c3.hash), (PRIV, None, INVALID, 0))
c4 = at_absorb()
check("kl.setst with a reserved #immed7 (54, 55): illegal-instruction exception, the State kept (GR18)", True,
      ([raises(c4.setst, i) for i in (54, 55)], c4.state), ([True] * 2, ABSORB))

section("negative controls")
control("K2 for a full final block", all(tag(K, M, k2full=True) != W for _, K, M, W in VEC
                                         if M and len(M) % 16 == 0))
control("subkeys via little-endian update_mask", any(tag(K, M, dbl=update_mask) != W
                                                     for _, K, M, W in VEC))
control("multi-block kl.exec, most significant block first",
        all(tag(K, M, per_exec=0, msb_first=True) != W for _, K, M, W in VEC if len(M) >= 40))
cl = at_absorb()
cl.exec('B', b2v(MSG[:16]))
cl.absorbed_any = False                           # the check removed: Xs = 0 after one full block
cl.setst(LAST, 'B', 0)
cl.setst(OUTPUT)
control("without the `absorbed_any` check, Xs = 0 after a full block yields no standard CMAC of that block",
        v2b(cl.exec('C'), 16) != ref_cmac(K128, MSG[:16])[0])
cl = run(K128, MSG[:40], to=None, min_tag=0)
cl.setst(VERIFY, 'B', 0)
cl.exec('B', 0)
control("without the 64-bit minimum, a 0-bit comparison accepts a forged tag", cl.state == SUCCESS)
control("Serialized Content without `absorbed_all`: after an import the absorbed last block is lost, and the "
        "output is refused", raises(tag, K128, MSG[:40], hop=True,
                                    lay=[r for r in layout(128) if r[0] != 'absorbed_all'], exc=Invalid))
control("Serialized Content without `hash`",
        all(tag(K, M, hop=True, lay=[r for r in layout(8 * len(K)) if r[0] != 'hash']) != W
            for _, K, M, W in VEC if len(M) >= 16))
done()
