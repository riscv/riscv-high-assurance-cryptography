"""Shared plans for the hash KATs: drive a hash_model.Locker through the generic sequence of the spec
(Hash_Absorb chunks / halts / export-import / Hash_Absorb_Last_Block / Hash_Output pieces) and compare with a reference."""
import copy, random, hashlib, hmac as _hmac
from common import *
from hash_model import Locker, Metadata, run, digest

HL = {'SHA-224': 'sha224', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512', 'SHA-512/224': 'sha512_224',
      'SHA-512/256': 'sha512_256', 'SM3': 'sm3', 'SHA3-224': 'sha3_224', 'SHA3-256': 'sha3_256', 'SHA3-384': 'sha3_384',
      'SHA3-512': 'sha3_512', 'BLAKE2b': 'blake2b', 'BLAKE2s': 'blake2s'}
def oracle(name, msg): return hashlib.new(HL[name], msg).digest()

def out_all(L, n, halts=True, export=False):
    """Form C kl.exec of n bytes; on a halt resume at the recorded klstart (software keeps OUTPUT)."""
    buf = bytes(n); k = 0
    while True:
        r = L.exec('C', kllen=8 * n, klstart=k, halt=halts)
        buf = buf[:k] + r[k:]
        if L.halted is None or L.st != 'Output': return buf
        k = L.halted

def feed(L, msg, nbits, plan, rng):
    """absorb the bit string (msg, nbits) into a locker in Ready according to `plan`; leaves it before the setst Output."""
    b = L.f.b
    L.setst('absorb')
    if plan == 'multi' and nbits % 8 == 0:
        run(L, [msg]); return L
    if plan in ('last', 'last0') or nbits % 8:
        Lb = 0 if plan == 'last0' else (nbits - 1) % b + 1 if nbits else 0
        if nbits % 8 and plan == 'last0': raise ValueError
        k = (nbits - Lb) // 8
        run(L, [msg[:k]], halts=True)
        L.setst('last', 'B' if Lb else 'A', Lb)
        if Lb: L.exec('B', msg[k:k + (Lb + 7) // 8])
        return L
    cuts = sorted(rng.sample(range(len(msg) + 1), min(len(msg) + 1, 4))) if plan != 'odd' else list(range(1, len(msg), 7))
    parts = [msg[i:j] for i, j in zip([0] + cuts, cuts + [len(msg)])]
    for p in parts:
        run(L, [p], halts=True)
        if plan == 'export': L = copy.deepcopy(L)
    return L

PLANS = ('multi', 'chunks', 'odd', 'export', 'last', 'last0')
def vector(name, mk, msg, nbits, ref, plans=PLANS, nlabel=None, out=(0, 1, 5)):
    """one check per plan: digest through the model == ref; `out` = output piece plans (0 = single piece)."""
    for plan in plans:
        if plan in ('multi', 'last0') and nbits % 8: continue
        L = feed(mk(), msg, nbits, plan, random.Random(nbits * 7 + len(plan)))
        L.setst('output')
        want = ref(msg, nbits)
        got = out_all(L, len(want), halts=True)
        check('%s %s %d bits, %s' % (name, nlabel or '', nbits, plan), got == want and L.st == 'Success', got.hex(), want.hex())

def msg_of(n): return bytes((i * 37 + n + 11) & 255 for i in range(n))
def inv(L): return L.st == 'Invalid'

def machine_checks(fn, ref):
    """State machine, Serialized Content and kl.derive checks of the generic hash Machine (KLE-hash-functions-MACs-XOFs)
    on function `fn`; ref(msg_bytes) -> digest."""
    mk = lambda: Locker(fn)
    L0 = mk(); f = L0.f; b = f.b; d = f.d // 8; ab = b'abc'
    def at(st, msg=b''):
        L = mk(); L.setst('absorb'); run(L, [msg]) if msg else None; return L
    section('%s: state machine' % fn)
    L = mk(); check('%s Ready: S = IV, fields zero' % fn, L.st == 'Ready' and (L.lbl, L.bb, L.cum, L.outl, L.blk) == (0,) * 5)
    L.setst('absorb'); check('%s Absorb entry sets last_block_len = b' % fn, L.st == 'Absorb' and L.lbl == b)
    check('%s Form B kl.setst naming Ready -> Invalid' % fn, inv(_do(at('A'), 'ready', 'B', 8)))
    check('%s Form B kl.setst naming Hash_Absorb -> Invalid' % fn, inv(_do(mk(), 'absorb', 'B', 8)))
    L = at('A'); L.exec('B', b'ab', halt=False); L.exec('B', b''); L.exec('B', b'c')
    L.setst('output'); check('%s empty Form B kl.exec is an empty window' % fn, out_all(L, d) == ref(ab))
    for imm in ('output', 'last'):
        check('%s Ready -> %s -> Invalid' % (fn, imm), inv(_do(mk(), imm)))
    check('%s same-State kl.setst Hash_Absorb -> Invalid' % fn, inv(_do(at('A'), 'absorb')))
    L = at('A', ab); L.setst('output'); check('%s same-State kl.setst Hash_Output -> Invalid' % fn, inv(_do(L, 'output')))
    check('%s kl.setst Hash_Output then Hash_Absorb -> Invalid' % fn, inv(_do(_out(ab, mk), 'absorb')))
    for imm in ('success', 'failure'): check('%s kl.setst naming %s -> Invalid' % (fn, imm), inv(_do(at('A'), imm)))
    L = at('A', ab); L.setst('last'); check('%s Form A last = empty final piece (Xs=0)' % fn, L.st == 'Last' and L.lbl == 0)
    L.exec('B', b'x'); check('%s non-empty exec after Xs=0 -> Invalid' % fn, inv(L))
    L = at('A', ab); L.setst('last'); L.setst('output'); check('%s Last(len 0) -> Output ends message' % fn, out_all(L, d) == ref(ab))
    check('%s Xs > b -> Invalid' % fn, inv(_do(at('A'), 'last', 'B', b + 8)))
    L = at('A', ab); L.setst('last', 'B', 16); L.setst('output'); check('%s Last with last_block_len != 0 -> Output Invalid' % fn, inv(L))
    L = at('A', ab); L.setst('last', 'B', 24); L.exec('B', b'\x01\x02', 0); check('%s final piece with KLLEN < last_block_len -> Invalid' % fn, inv(L))
    L = at('A', ab); L.setst('last', 'B', 24); L.exec('B', b'', 0); check('%s KLLEN = 0 with last_block_len != 0: empty window, State kept (GR52 item 1)' % fn, L.st == 'Last' and L.lbl == 24)
    L = at('A', ab); L.setst('last'); L.exec('B', b'', 0); check('%s Xs=0 then an empty-window kl.exec (KLLEN=0) -> Invalid (MR10, GR20)' % fn, inv(L))
    L = at('A', ab); L.setst('last'); L.exec('B', b'xy', 2); check('%s Xs=0 then an empty window klstart=KLLEN/8 -> Invalid (MR10)' % fn, inv(L))
    L = at('A', ab); L.setst('last', 'B', 24); L.exec('B', b'xyzw', 1); check('%s final piece klstart != 0 -> Invalid' % fn, inv(L))
    L = at('A', ab); L.setst('last', 'B', 24); L.exec('B', b'abc'); L.exec('B', b'a'); check('%s a second final-piece exec -> Invalid (MR10)' % fn, inv(L))
    L = at('A', ab); L.setst('last', 'B', 24); L.exec('B', b'abc'); L.setst('output')
    check('%s final piece of "abc" after "abc" = "abcabc"' % fn, out_all(L, d) == ref(ab * 2))
    # output side
    for Xs, ok in ((8 * d, True), (64, True), (8 * d + 8, False), (63, False), (12, False)):
        L = at('A', ab); L.setst('output', 'B', Xs)
        if ok:
            o = out_all(L, Xs // 8); check('%s Output Xs=%d bits: prefix, Success' % (fn, Xs), o == ref(ab)[:Xs // 8] and L.st == 'Success')
        else: check('%s Output Xs=%d bits -> Invalid before finalize' % (fn, Xs), inv(L) and L.bb == 3 * 8 and L.cum == 24)
    L = at('A', ab); L.setst('output'); o = L.exec('C', kllen=8 * (d + 9)); check('%s KLLEN > t: digest, excess cleared, Success' % fn, o == ref(ab) + bytes(9) and L.st == 'Success')
    L = at('A', ab); L.setst('output'); o1 = L.exec('C', kllen=8 * 5, klstart=2); check('%s Form C klstart=2: digest starts at OUTPUT byte 2' % fn, o1 == bytes(2) + ref(ab)[:3] and L.st == 'Output')
    o2 = L.exec('C', kllen=8 * d); check('%s ... the next exec continues at block_base, excess cleared, Success' % fn, o2 == ref(ab)[3:] + bytes(3) and L.st == 'Success')
    L = at('A', ab); L.setst('output'); L.exec('C', kllen=8 * 2); o = L.exec('C', kllen=8 * 4, klstart=1); check('%s Output klstart != 0 with block_base != 0 -> Invalid, output zero' % fn, inv(L) and o == bytes(4))
    L = at('A', ab); L.setst('output'); o = L.exec('C', kllen=8 * 4, klstart=4); check('%s Output klstart >= KLLEN/8 = empty window' % fn, o == bytes(4) and L.st == 'Output')
    L = at('A', ab); L.setst('output'); o = L.exec('B', b'zz'); check('%s Form B kl.exec in Hash_Output -> Invalid' % fn, inv(L))
    L = at('A', ab); o = L.exec('C', kllen=32); check('%s Form C kl.exec in Hash_Absorb -> Invalid, output zero' % fn, inv(L) and o == bytes(4))
    for name, mkL in (('Ready', mk), ('Success', lambda: _succ(ab, mk))):
        L = mkL(); o = L.exec('C', kllen=64); L2 = mkL(); L2.exec('B', b'abc')
        check('%s kl.exec in %s -> Invalid, output zeroed' % (fn, name), o == bytes(8) and inv(L) and inv(L2))
    L = _do(at('A'), 'success'); o = L.exec('C', kllen=64); check('%s kl.exec in Invalid: stays Invalid, output zeroed' % fn, inv(L) and o == bytes(8))
    L = at('A', ab); L.clear(); S0 = L.S; L.exec('B', b'x'); L.setst('absorb'); check('%s after kl.clear exec/setst are no-ops' % fn, L.st == 'Inert' and L.S == S0)
    L = at('A', ab); L.setst('ready'); check('%s Absorb -> Ready mid-message resets state, block, block_base' % fn, L.st == 'Ready' and L.S == mk().S and L.bb == 0 and L.blk == 0 and L.cum == 0)
    L.setst('absorb'); run(L, [ab]); L.setst('output'); check('%s ... and the next message is unaffected' % fn, out_all(L, d) == ref(ab))
    L = _succ(ab, mk); L.setst('ready'); check('%s Success -> Ready' % fn, L.st == 'Ready'); L = _succ(ab, mk); check('%s Success admits only Ready' % fn, inv(_do(L, 'absorb')))
    L = at('A', b'x' * 70); L.exec('B', b'y' * 9, 3); check('%s resumption at klstart != 0 with block_base != 0 -> Invalid' % fn, inv(L) and L.bb != 0)
    L = at('A'); L.exec('B', b'abcdef', 6); check('%s Absorb klstart >= length: empty window' % fn, L.st == 'Absorb' and L.cum == 0)
    check('%s non-zero MachinePolicy is unsupported Metadata' % fn, raises(Locker, fn, policy=1, exc=Metadata))
    # Serialized Content
    section('%s: Serialized Content and export/import' % fn)
    w = [x[2] for x in mk().fields()]
    names = [x[0] for x in mk().fields()]
    check('%s fields in order' % fn, (w[0], w[-1]) == (f.n, b) and w[1:-1] == [16, 16, 32, 64] and names[1:3] == ['last_block_len', 'block_base'], names)
    pad = -sum(w) % 128; check('%s Serialized Content: %d bits + %d padding = multiple of 128' % (fn, sum(w), pad), (sum(w) + pad) % 128 == 0)
    L = at('A', msg_of(b // 8 + 5)); fl = {n: v for n, v, _ in L.fields()}
    check('%s fields after b/8+5 bytes: block_base = 40, cumul_len = b+40, last_block_len = b' % fn, (fl['block_base'], fl['cumul_len'], fl['last_block_len']) == (40, b + 40, b))
    for cut in (0, 1, b // 8 - 1, b // 8, b // 8 + 3):
        m = msg_of(cut + 77); L = at('A', m[:cut]); L2 = copy.deepcopy(L); run(L2, [m[cut:]]); L2.setst('output')
        check('%s export/import after %d bytes continues to the same digest' % (fn, cut), out_all(L2, d) == ref(m))
    L = _out(ab, mk); check('%s Hash_Output fields: out_len = d, last_block_len = block_base = 0' % fn, (L.outl, L.lbl, L.bb) == (8 * d, 0, 0))
    # derive
    section('%s: kl.derive of a shared secret' % fn)
    for n in (1, 16, 32, 48, 66):
        sec = msg_of(n); L = at('A'); ok = L.derive(sec); ok2 = L.derive(sec); L.setst('output')
        check('%s derive of %d-byte shared secret into Hash_Absorb, twice' % (fn, n), ok and ok2 and out_all(L, d) == ref(sec * 2))
    L = at('A'); check('%s derive with klstart != 0 -> destination Invalid' % fn, not L.derive(b'abc', klstart=1) and inv(L))
    L = at('A'); check('%s derive with length != secret length -> Invalid' % fn, not L.derive(b'abc', length=2) and inv(L))
    L = at('A', ab); L.setst('last', 'B', 8); check('%s derive is not an endpoint in Hash_Absorb_Last_Block' % fn, not L.derive(b'a') and inv(L))
    check('%s derive is not an endpoint in Ready' % fn, not mk().derive(b'a'))
    L = _out(ab, mk); check('%s derive not an endpoint in Hash_Output (digest is not a destination)' % fn, not L.derive(b'a') and inv(L))

def _do(L, imm, form='A', Xs=0): L.setst(imm, form, Xs); return L
def _out(msg, mk): L = mk(); L.setst('absorb'); run(L, [msg]); L.setst('output'); return L
def _succ(msg, mk): L = _out(msg, mk); out_all(L, L.f.d // 8); return L
