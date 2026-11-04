"""Shared plans for the hash KATs: drive a hash_model.Locker through the generic sequence of the spec
(Hash_Absorb chunks / halts / export-import / Hash_Absorb_Last_Block / Hash_Output pieces) and compare with a reference."""
import copy, random, hashlib, hmac as _hmac
from common import *
from hash_model import Locker, Metadata, run, digest, derive_out, Key, import_

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
    L = at('A', ab); L.setst('last', 'B', 24); L.exec('B', b'', 0); check('%s KLLEN = 0 with last_block_len != 0: empty window, State kept (GR18 item 1)' % fn, L.st == 'Last' and L.lbl == 24)
    L = at('A', ab); L.setst('last'); L.exec('B', b'', 0); check('%s Xs=0 then an empty-window kl.exec (KLLEN=0) -> Invalid (MR10, GR13.5)' % fn, inv(L))
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

    sealed_checks(fn, lambda: at('A'), ref)

    bits_checks(fn, lambda: _out(ab, mk), ref(ab))

def sealed_checks(fn, mk, ref):
    """Sealed locker (GR31.3), its GR30 narrowing and its StateExtension validity; mk() -> a locker in Hash_Absorb with
    no message byte absorbed, ref(msg_bytes) -> its digest of msg."""
    section('%s: sealed locker (GR31.3)' % fn)
    sec = msg_of(32); ab = b'abc'; d = len(ref(ab))
    def sl(): L = mk(); L.derive(sec, sealed=True); L.setst('output'); return L
    L = sl(); check('%s a sealed secret entering the message sets Sealed; Form C kl.exec in Hash_Output -> Invalid, output zero' % fn,
                    L.sealed and L.exec('C', kllen=64) == bytes(8) and inv(L))
    check('%s ... kl.setst naming Hash_Output_Bits -> Invalid' % fn, inv(_do(sl(), 'bits', 'B', 8)))
    L = sl(); K = Key(16); check('%s ... its output moves into a 16-byte key: the digest prefix' % fn, derive_out(L, K, 16) and K.key == ref(sec)[:16])
    L = sl(); K = Key(16, True); check('%s ... into the key of keystream generation, OFB or CMAC: both Invalid' % fn, not derive_out(L, K, 16) and inv(L) and K.st == 'Invalid')
    L = sl(); L2 = mk(); check('%s ... into a message input: both Invalid' % fn, not derive_out(L, L2, d) and inv(L) and inv(L2))
    L = sl(); L.setst('ready'); ok = not L.sealed; L.setst('absorb'); run(L, [ab]); L.setst('output')
    check('%s Ready clears Sealed: the next digest is readable' % fn, ok and out_all(L, d) == ref(ab))
    L = mk(); f0 = L.fields(); check('%s a sealed secret of 15 bytes: the source fails, the message is unchanged (GR29 item 7)' % fn,
                       not L.derive(sec[:15], sealed=True) and L.srcinv and L.st == 'Absorb' and L.fields() == f0 and not L.sealed)
    L = mk(); check('%s ... one of 16 bytes enters' % fn, L.derive(sec[:16], sealed=True) and L.sealed)
    # GR30: each sealed hop is a restricted transfer that narrows the next MDH
    src = mdh_pack(UsagePolicy=0x5, ExpirationDate=7, SCProtection=1)
    L = mk(); L.mdh = mdh_pack(UsagePolicy=0x7, SCProtection=1); L.derive(sec, sealed=True, smdh=src); L.setst('output')
    K = Key(16, mdh=mdh_pack(UsagePolicy=0x6, SCProtection=3)); ok = derive_out(L, K, 16)
    check('%s GR30 across two sealed hops: the key gets UsagePolicy 0x4 and the ExpirationDate of the secret' % fn,
          ok and (mdh_get(K.mdh, 'UsagePolicy'), mdh_get(K.mdh, 'ExpirationDate')) == (4, 7) and mdh_get(L.mdh, 'UsagePolicy') == 5)
    L = mk(); L.mdh = mdh_pack(SCProtection=0); check('%s GR30: a hash whose SCProtection does not include that of the secret -> Privilege Violation, nothing absorbed' % fn,
                                                    not L.derive(sec, sealed=True, smdh=src) and L.st == 'PrivViolation' and not L.sealed)
    L = sl(); L.mdh = mdh_pack(SCProtection=1); K = Key(16, mdh=mdh_pack(SCProtection=0))
    check('%s GR30: a key whose SCProtection does not include that of the sealed hash -> Privilege Violation, the source keeps its output' % fn,
          not derive_out(L, K, 16) and K.st == 'PrivViolation' and L.st == 'Output' and L.outl == 8 * d)
    L = mk(); L.mdh = mdh_pack(Transparent=1); check('%s GR30: a Transparent hash of a sealed secret that is not -> Privilege Violation, nothing absorbed' % fn,
                                                 not L.derive(sec, sealed=True, smdh=mdh_pack()) and L.st == 'PrivViolation' and not L.sealed)
    L = sl(); K = Key(16, mdh=mdh_pack(Transparent=1))
    check('%s GR30: a Transparent key of a sealed hash that is not -> Privilege Violation, the source keeps its output' % fn,
          not derive_out(L, K, 16) and K.st == 'PrivViolation' and L.st == 'Output' and L.outl == 8 * d)
    L = mk(); L.mdh = mdh_pack(Locality=0x10); check('%s GR30: failed narrowing (boot subfields differ) -> Privilege Violation' % fn,
                                                  not L.derive(sec, sealed=True, smdh=mdh_pack(Locality=0x20)) and L.st == 'PrivViolation')
    # StateExtension @ State at an SCC import or kl.clone (KLE-Metadata-validity)
    L = sl(); C = import_(L); check('%s import of a sealed Hash_Output keeps Sealed: Form C -> Invalid' % fn, C.sealed and C.exec('C', kllen=64) == bytes(8) and inv(C))
    L = sl(); derive_out(L, Key(d), d); check('%s Sealed in Success, reached after the whole output, is supported' % fn, L.st == 'Success' and L.sealed and not inv(import_(L)))
    L = mk(); L.derive(sec, sealed=True); ok = not inv(import_(L)); L.setst('last', 'B', 8); ok &= L.st == 'Last' and not inv(import_(L))
    check('%s Sealed in Hash_Absorb and Hash_Absorb_Last_Block is supported' % fn, ok)
    for st in ('Ready', 'Bits', 'Verify', 'Failure'):
        L = sl(); L.st = st; check('%s Sealed in %s: unsupported StateExtension @ State, the import -> Invalid' % (fn, st), inv(import_(L)))

def read_bits(L, r, kl=None, halts=False):
    """kl.setst Hash_Output_Bits with Xs = r, then Form C kl.execs of kl bits (default: one that holds r) until read_len
    is used up or the output ends, resuming after halts. -> (bits as int, number read, OUTPUT cleared beyond them)."""
    kl = kl or 8 * ((r + 7) // 8); L.setst('bits', 'B', r); v = got = 0; clean = True
    while L.st == 'Bits' and L.lbl:
        rl = L.lbl; k = 0; buf = bytes(kl // 8)
        while True:
            o = L.exec('C', kllen=kl, klstart=k, halt=halts); buf = buf[:k] + o[k:]
            if L.halted is None: break
            k = L.halted
        n = rl - L.lbl; x = b2v(buf); clean &= x >> n == 0; v |= (x & mask(n)) << got; got += n
    return v, got, clean

def bits_checks(fn, mk, ref):
    """Hash_Output_Bits (State 16) of KLE-hash-functions-MACs-XOFs; mk() -> a locker in Hash_Output whose output is ref."""
    section('%s: Hash_Output_Bits' % fn)
    R = b2v(ref); D = 8 * len(ref)
    for pieces, kl, halts in (((1, 3, 7, 8, 13), None, False), ((61, 5, 100), 16, True), ((3, 4000), 24, True), ((D,), 8, True)):
        L = mk(); v = got = 0; clean = True; i = 0
        while L.st == 'Output' or L.st == 'Bits':
            x, n, c = read_bits(L, pieces[i % len(pieces)], kl, halts); v |= x << got; got += n; clean &= c; i += 1
        check('%s reads of %s bits (KLLEN %s%s): the output LSB first, zero-filled, then Success' % (fn, pieces, kl or 'fitting', ', halt at every byte' if halts else ''),
              (v, got, clean, L.st) == (R, D, True, 'Success'), (hex(v), got))
    L = mk(); o = L.exec('C', kllen=40); x, n, _ = read_bits(L, 13)
    check('%s Hash_Output (5 bytes) then Hash_Output_Bits: the stream continues, block_base and out_len kept' % fn, (o, x, L.st, L.bb, L.outl) == (ref[:5], (R >> 40) & mask(13), 'Bits', 53, D - 53))
    x, n, _ = read_bits(L, 3); check('%s ... and continues across a new kl.setst' % fn, x == (R >> 53) & 7 and L.bb == 56)
    L = mk(); L.setst('bits', 'B', 20); o = L.exec('C', kllen=8)
    check('%s read_len > KLLEN: read_len carries to the next kl.exec' % fn, (o, L.st, L.lbl) == (ref[:1], 'Bits', 12))
    L.setst('bits', 'B', 4); o = L.exec('C', kllen=8)
    check('%s a new kl.setst drops the unread bits; the read of 4 bits is zero-filled' % fn, (o, L.lbl, L.bb) == (bytes([ref[1] & 15]), 0, 12))
    check('%s Form C with read_len = 0 -> Invalid' % fn, L.exec('C', kllen=8) == bytes(1) and inv(L))
    for Xs, form, why in ((0, 'B', 'Xs = 0'), (1 << 16, 'B', 'Xs = 2^16'), (0, 'A', 'Form A')):
        L = mk(); L.setst('bits', form, Xs); check('%s kl.setst Hash_Output_Bits with %s -> Invalid' % (fn, why), inv(L))
    L = mk(); L.setst('bits', 'B', 65535); check('%s Xs = 2^16 - 1 admitted' % fn, (L.st, L.lbl) == ('Bits', 65535))
    def via(last, direct):
        L = mk(); L.setst('ready'); L.setst('absorb'); run(L, [b'xyz'])
        if last: L.setst('last')
        if not direct: L.setst('output')
        L.setst('bits', 'B', 13); return L, L.exec('C', kllen=16)
    for last in (False, True):
        (A, a), (B, b) = via(last, True), via(last, False)
        check('%s kl.setst Hash_Output_Bits from %s = Form A Hash_Output then the same kl.setst' % (fn, 'Hash_Absorb_Last_Block' if last else 'Hash_Absorb'),
              not inv(B) and (a, A.st, A.bb, A.outl) == (b, B.st, B.bb, B.outl) and A.bb == 13)
    L = mk(); L.setst('bits', 'B', 8); L.exec('B', b'x'); check('%s Form B kl.exec in Hash_Output_Bits -> Invalid' % fn, inv(L))
    L = mk(); L.setst('bits', 'B', 8); L.setst('output'); check('%s Hash_Output_Bits -> Hash_Output: not a transition, Invalid' % fn, inv(L))
    L = mk(); L.setst('bits', 'B', 8); L.setst('ready'); check('%s Hash_Output_Bits -> Ready' % fn, L.st == 'Ready')
    L = mk(); read_bits(L, 3); L.setst('bits', 'B', 40); o = L.exec('C', kllen=64, klstart=2)
    check('%s klstart = 2 with block_base = 3 (any byte offset): the bits land at OUTPUT byte 2, the rest cleared' % fn,
          (o, L.lbl, L.bb) == (bytes(2) + v2b((R >> 3) & mask(40), 5) + bytes(1), 0, 43))
    L = mk(); read_bits(L, 3); L.setst('bits', 'B', 40); o = L.exec('C', kllen=64, halt=True)
    check('%s halt inside the output block at byte offset 1 (block_base = 11), then resume' % fn, (L.halted, L.bb, L.lbl) == (1, 11, 32))
    o = o[:1] + L.exec('C', kllen=64, klstart=1)[1:]; check('%s ... to the same 40 bits' % fn, b2v(o) == (R >> 3) & mask(40))
    L = mk(); L.setst('bits', 'B', 100); L.exec('C', kllen=24); fl = {n: v for n, v, _ in L.fields()}
    L2 = copy.deepcopy(L); o = L2.exec('C', kllen=80)
    check('%s export mid-read: last_block_len holds read_len = 76; the import continues the read' % fn,
          (fl['last_block_len'], fl['block_base'], b2v(o)) == (76, 24, (R >> 24) & mask(76)))
    L = mk(); read_bits(L, 5); E = Locker('SHA-256', 'NIK'); E.setst('setkey'); n = (D - 5 + 7) // 8
    if n <= 64: check('%s kl.derive from Hash_Output_Bits (block_base = 5) into K0: the rest of the output, source Success' % fn,
                      derive_out(L, E, n) and E.K0 == R >> 5 and L.st == 'Success')

def _do(L, imm, form='A', Xs=0): L.setst(imm, form, Xs); return L
def _out(msg, mk): L = mk(); L.setst('absorb'); run(L, [msg]); L.setst('output'); return L
def _succ(msg, mk): L = _out(msg, mk); out_all(L, L.f.d // 8); return L
