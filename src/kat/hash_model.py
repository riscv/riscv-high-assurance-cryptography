"""Executable model of the Merkle-Damgard / sponge hash Machines of Zkl-ISA-machines.adoc, derived from the spec
text only: generic hash Machine (KLE-hash-functions-MACs-XOFs, KLE-process-VLI), SHA-2, SM3, BLAKE2, HMAC (NIK/KIP,
on SHA-2, SM3, SHA-3) and SHA-3/SHAKE.  Values follow common.py conventions (ints, bit i = V[i], bytes = little endian).
Round functions come from hash_ref.py (independent of this model).

Locker(fname, hmac=None|'NIK'|'KIP', key=bytes K0 (KIP), syskey=bytes (BLAKE2 only), policy=int, tag_len_p=int (HMAC))
  tag_len_p defaults to t; a value not admitted (a multiple of 8 from 64 to t) gives Invalid (MR12).
  .st                         'Ready','Absorb','Last','Output','Verify','SetKey','Success','Failure','Invalid','Inert'
  .setst(imm, form='A', Xs=0) imm in ready absorb last output verify setkey aux success failure finalize
  .exec(form, data=b'', klstart=0, halt=False, kllen=None) -> bytes (Form C output, zero-filled) | None
        returns for Form B: None when complete, or the klstart of a halt (int) -> see .halted
  .derive(secret, klstart=0, stream=False) -> bool (destination side of kl.derive of a shared secret)
  .clear();  copy.deepcopy(locker) is an export/import snapshot.
Class Metadata(Exception): invalid or unsupported Metadata at provisioning."""
import copy, hash_ref as R
from common import b2v, v2b, mask

class Metadata(Exception): pass
M = mask
class Fn:
    def __init__(s, name):
        s.name = name
        if name in R.SHA2: s.kind = 'sha2'; s.w, s.b, s.t = R.SHA2[name]; s.n = 8 * s.w; s.xof = False
        elif name == 'SM3': s.kind = 'sm3'; s.w, s.b, s.t, s.n = 32, 512, 256, 256; s.xof = False
        elif name in R.B2: s.kind = 'blake2'; s.w, _, bb, nnm, _ = R.B2[name]; s.b = 8 * bb; s.nnmax = nnm; s.n = 8 * s.w; s.t = 8 * nnm; s.xof = False
        else: s.kind = 'sha3'; s.b, t, s.D, s.Dlen = R.SHA3[name]; s.n = 1600; s.xof = t is None; s.t = t or s.b
        s.d = s.t
    xor = property(lambda s: s.kind == 'sha3')
    hold = property(lambda s: s.kind == 'blake2')
    bit_ok = property(lambda s: s.kind in ('sha3', 'sha2', 'sm3'))   # final piece may have any bit length

class Locker:
    def __init__(s, fname, hmac=None, key=None, syskey=None, policy=None, tag_len_p=None):
        if policy is None: policy = 3 if hmac else 0
        f = s.f = Fn(fname); s.hmac = hmac; s.syskey = None; s.policy = policy; s.halted = None
        if hmac:
            if policy & ~3 or not policy & 3: raise Metadata('HMAC MachinePolicy')
            if hmac == 'KIP' and (key is None or len(key) != f.b // 8): raise Metadata('K0')
            if hmac == 'NIK' and key is not None: raise Metadata('NIK carries no key')
        elif f.kind == 'blake2' and syskey is not None:
            if not 1 <= len(syskey) <= f.nnmax: raise Metadata('kk range')   # locker Invalid in hardware; here at provisioning
            if policy != 1: raise Metadata('BLAKE2 sys key MachinePolicy')
            s.syskey = b2v(syskey + b'\0' * (f.b // 8 - len(syskey)))
        elif policy: raise Metadata('unsupported MachinePolicy')
        s.K0 = b2v(key) if key else 0; s.haskey = hmac == 'KIP'
        s.nn = f.t // 8 if f.kind == 'blake2' else 0
        s.kk = len(syskey) if syskey else 0
        s.tag_len = 0; s.input_key = None
        s.tag_len_p = (f.t if tag_len_p is None else tag_len_p) if hmac else None
        s.ready()
        if hmac and not s.tlp_ok(): s.inv()                               # MR12: provisioning completes into Invalid
    # ---- helpers
    def inv(s): s.st = 'Invalid'; return None
    def tlp_ok(s): return s.tag_len_p % 8 == 0 and 64 <= s.tag_len_p <= s.f.t
    def iv(s):
        f = s.f
        if f.kind == 'sha3': return 0
        if f.kind == 'sm3': return b2v(b''.join(v.to_bytes(4, 'big') for v in R.SM3_IV))
        if f.kind == 'blake2':
            h = list(R.B2IV[f.w]); h[0] ^= 0x01010000 ^ (s.kk << 8) ^ s.nn
            return sum(x << (f.w * i) for i, x in enumerate(h))
        return b2v(b''.join(h.to_bytes(f.w // 8, 'big') for h in R.sha2_iv(f.name)))
    def ready(s):
        s.st = 'Ready'; s.lbl = s.bb = s.cum = s.outl = 0; s.blk = 0; s.tag_len = 0; s.S = s.iv()
        if s.hmac == 'KIP': s.haskey = True
    def _P(s): s.S = R.keccak_f(s.S)
    def _comp(s, final=False):
        f = s.f; bl = v2b(s.blk, f.b // 8); S = v2b(s.S, f.n // 8)
        if f.kind == 'sha3': s._P(); return
        if f.kind == 'blake2':
            h = [b2v(S[i * f.w // 8:(i + 1) * f.w // 8]) for i in range(8)]
            m = [b2v(bl[j * f.w // 8:(j + 1) * f.w // 8]) for j in range(16)]
            h = R.blake2_F(f.name, h, m, s.cum // 8, final)
            s.S = sum(x << (f.w * i) for i, x in enumerate(h)); return
        wb = f.w // 8
        H = [int.from_bytes(S[i * wb:(i + 1) * wb], 'big') for i in range(8)]
        words = [int.from_bytes(bl[j * wb:(j + 1) * wb], 'big') for j in range(16)]
        H = R.sha2_compress(f.w, H, words) if f.kind == 'sha2' else R.sm3_compress(H, words)
        s.S = b2v(b''.join(h.to_bytes(wb, 'big') for h in H))
    def _vli(s, X, kllen, ib, count=True, halt=False):
        """PROCESS_VLI loop of _Hash_Absorb_ (and of the final piece) for the hash Machines."""
        f = s.f
        if f.kind == 'blake2' and s.syskey is not None and s.cum == 0 and ib < kllen:
            s.blk = s.syskey; s.cum = f.b; s._comp(False); s.blk = 0
        while ib < kllen:
            if f.hold and s.bb == f.b: s._comp(False); s.bb = 0
            a = min(kllen - ib, f.b - s.bb); c = (X >> ib) & M(a)
            if f.xor: s.S ^= c << s.bb
            else: s.blk = (s.blk & ~(M(a) << s.bb)) | (c << s.bb)
            ib += a; s.bb += a
            if count: s.cum += a
            if s.bb == f.b and not f.hold: s._comp(); s.bb = 0
            if halt and ib < kllen: return ib // 8
        return None
    def _put(s, data):   # finalize steps 3.a-e,g (cum not counted)
        s._vli(b2v(data), 8 * len(data), 0, count=False)
    def _finalize(s, ell=None):
        f = s.f
        if f.kind in ('sha2', 'sm3'):
            ell = s.cum if ell is None else ell
            if s.cum % 8 == 0: s._put(b'\x80')
            while s.bb != f.b - 2 * f.w: s._put(b'\0')
            s._put(ell.to_bytes(2 * f.w // 8, 'big'))
        elif f.kind == 'blake2':
            if s.bb > 0: s.blk &= M(s.bb); s._comp(True)
            elif s.syskey is not None: s.blk = s.syskey; s.cum = f.b; s._comp(True); s.blk = 0
            elif s.kk == 0: s.blk = 0; s._comp(True)
            else: s.inv(); return
            s.bb = 0
        else:
            D = f.D | (1 << f.Dlen); Dl = f.Dlen + 1       # D then the first 1 of pad10*1
            n = f.Dlen + 2
            while (s.bb + n) % f.b: n += 1
            Sx = D | (1 << (n - 1))
            s.S ^= (Sx & M(f.b - s.bb)) << s.bb; s._P()
            if n > f.b - s.bb: s.S ^= Sx >> (f.b - s.bb); s._P()
            s.bb = 0
    def _digest(s): return s.S & M(s.f.t)
    # ---- instructions
    def setst(s, imm, form='A', Xs=0):
        s.halted = None; f = s.f
        if s.st in ('Invalid', 'Inert'): return
        if form == 'A' and Xs: raise ValueError('Form A has no Xs')
        if imm == 'ready':
            if form != 'A': return s.inv()
            s.ready(); return
        st = s.st
        if st in ('Success', 'Failure') or imm in ('success', 'failure', 'finalize'): return s.inv()
        if st == 'SetKey':
            if imm == 'setkey' and form == 'A': s._enter_setkey(); return
            s._leave_setkey()
            if imm != 'absorb': return s.inv()
        if imm == 'aux':
            if st != 'Ready' or f.kind != 'blake2' or form != 'B': return s.inv()
            nn, kk = Xs & 255, (Xs >> 8) & 255
            if not 1 <= nn <= f.nnmax or kk > f.nnmax or Xs >> 16 or (s.syskey is not None and kk): return s.inv()
            s.nn = nn
            if s.syskey is None: s.kk = kk
            s.S = s.iv(); return
        if imm == 'setkey':
            if st != 'Ready' or s.hmac != 'NIK' or form != 'A': return s.inv()
            s._enter_setkey(); return
        if imm == 'absorb':
            if form != 'A' or st not in ('Ready', 'SetKey') or (s.hmac == 'NIK' and not s.haskey): return s.inv()
            s.cum = s.bb = 0; s.blk = 0; s.S = s.iv()
            if s.hmac: s._enter_hmac_absorb()
            s.lbl = f.b; s.st = 'Absorb'; return
        if imm == 'last':
            if st != 'Absorb' or form not in 'AB': return s.inv()
            if Xs > f.b or (Xs % 8 and not f.bit_ok): return s.inv()
            s.lbl = Xs; s.st = 'Last'; return
        if imm in ('output', 'verify'):
            if st not in ('Absorb', 'Last') or (st == 'Last' and s.lbl): return s.inv()
            if imm == 'output':
                if form not in 'AB' or (s.policy & 1) == 0 and (s.hmac or s.syskey is not None): return s.inv()
                if Xs and (Xs % 8 or Xs >= 2**32 if f.xof else Xs % 8 or Xs > (8 * s.nn if f.kind == 'blake2' else f.d)): return s.inv()
                if Xs and s.hmac and Xs < 64: return s.inv()
            else:
                if not s.hmac or form != 'B' or not s.policy & 2 or Xs % 8 or Xs < 64 or min(Xs, f.t) != s.tag_len_p: return s.inv()
            if s.hmac: s._hmac_outer()
            else: s._finalize()
            if s.st == 'Invalid': return
            s.bb = s.lbl = 0
            if imm == 'output':
                s.outl = Xs or (0 if f.xof else (8 * s.nn if f.kind == 'blake2' else f.d)); s.st = 'Output'
            else: s.tag_len = min(Xs, f.t); s.st = 'Verify'
            return
        return s.inv()
    def _enter_setkey(s): s.st = 'SetKey'; s.K0 = 0; s.haskey = False; s.bb = s.cum = 0
    def _leave_setkey(s):
        if s.cum != s.f.b: s.K0 = 0; s.haskey = False
    def _enter_hmac_absorb(s):
        f = s.f; s._vli(s.K0 ^ b2v(b'\x36' * (f.b // 8)), f.b, 0, count=False)
    def _hmac_outer(s):
        f = s.f
        s._finalize(f.b + s.cum if f.kind in ('sha2', 'sm3') else None)
        inner = s._digest()
        s.S = s.iv(); s.blk = s.bb = s.cum = 0
        s._vli(s.K0 ^ b2v(b'\x5c' * (f.b // 8)), f.b, 0, count=False)
        s._vli(inner, f.t, 0, count=True)
        s._finalize(f.b + s.cum if f.kind in ('sha2', 'sm3') else None); s.bb = s.lbl = 0
    def exec(s, form, data=b'', klstart=0, halt=False, kllen=None):
        s.halted = None; f = s.f; st = s.st; kl = 8 * len(data) if kllen is None else kllen
        if st in ('Invalid', 'Inert'): return None if form != 'C' else bytes(kl // 8)
        zero = bytes(kl // 8) if form == 'C' else None
        if st in ('Output', 'Verify') and s.hmac and not s.policy & (1 if st == 'Output' else 2): s.inv(); return zero   # GR25
        if st == 'Output':
            if form != 'C': return s.inv()
            return s._exec_out(kl, klstart, halt)
        if form != 'B' or st not in ('Absorb', 'Last', 'SetKey', 'Verify'): s.inv(); return zero
        if st == 'Verify':
            if klstart * 8 >= kl: return None                          # GR52 item 1
            if kl < s.tag_len: return s.inv()
            ok = (b2v(data) & M(s.tag_len)) == (s.S & M(s.tag_len))
            s.st = 'Success' if ok else 'Failure'; return None
        if st == 'Last':
            L = s.lbl
            if L == 0: return s.inv()                                  # MR10: empty final input admits no kl.exec, even an empty window
            if klstart * 8 >= kl: return None                          # GR52 item 1
            if kl < L or klstart: return s.inv()                       # GR52 items 2, 3
            X = b2v(data)
            if f.kind in ('sha2', 'sm3'):
                nb = (L + 7) // 8; q = L % 8; bs = bytearray(data[:nb])
                if q: bs[-1] = (bs[-1] & (0xff << (8 - q)) & 0xff) | (1 << (7 - q))
                s._vli(b2v(bytes(bs)), 8 * nb, 0, count=False); s.cum += L
            else: s._vli(X & M(L), L, 0, count=True)
            s.lbl = 0; return None
        if klstart * 8 >= kl: return None
        if klstart and not (s.bb == 0 or (f.hold and s.bb == f.b)): return s.inv()
        if st == 'SetKey':
            if s.cum >= f.b: return s.inv()
            ib = 8 * klstart; X = b2v(data)
            while ib < kl:
                a = min(kl - ib, f.b - s.bb, f.b - s.cum)
                s.K0 = (s.K0 & ~(M(a) << s.bb)) | (((X >> ib) & M(a)) << s.bb)
                ib += a; s.bb += a; s.cum += a
                if s.bb == f.b: s.bb = 0
                if s.cum == f.b: s.haskey = True; return None
                if halt and ib < kl: s.halted = ib // 8; return s.halted
            return None
        r = s._vli(b2v(data), kl, 8 * klstart, True, halt); s.halted = r; return r
    def _exec_out(s, kl, klstart, halt):
        f = s.f; out = 0; ob = 8 * klstart
        if klstart * 8 >= kl: return bytes(kl // 8)
        if klstart and s.bb: s.inv(); return bytes(kl // 8)
        while ob < kl:
            a = min(kl - ob, f.t - s.bb)
            if s.outl: a = min(a, s.outl)
            out |= ((s.S >> s.bb) & M(a)) << ob
            ob += a; s.bb += a
            if s.outl:
                s.outl -= a
                if s.outl == 0:
                    out &= M(ob); s.st = 'Success'; return v2b(out, kl // 8)
            if s.bb == f.t:
                if f.kind == 'sha3': s._P()
                s.bb = 0
                if halt and ob < kl: s.halted = ob // 8; return v2b(out, kl // 8)
        return v2b(out, kl // 8)
    def rstrl(s, mask):
        """kl.rstrl narrowing MachinePolicy (GR25): a value the Machine forbids -> Invalid; a cleared gate bit fails the next gated operation."""
        if s.st in ('Invalid', 'Inert'): return
        s.policy &= mask
        if s.hmac and not s.policy & 3: s.inv()
    def derive(s, secret, klstart=0, stream=False, length=None, src='secret'):
        """destination side of kl.derive of a shared secret; False (and dest Invalid) if refused."""
        s.srcinv = False
        if s.st in ('Invalid', 'Inert'): return False
        if klstart: s.inv(); return False                                     # GR39 item 1
        if src in ('hmac_tag', 'xof'): s.srcinv = True; return False          # GR39 item 2: not a source endpoint; destination unchanged
        if s.hmac and s.tag_len_p != s.f.t: s.inv(); return False             # MR12: a short tag_len_p is not a destination
        if src == 'cmac' and s.st == 'Absorb': s.srcinv = True; s.inv(); return False   # GR39 item 4: pair not admitted, both Invalid
        f = s.f; length = len(secret) if length is None else length
        if length != len(secret): s.inv(); return False
        if s.st == 'SetKey':
            if stream or len(secret) > f.b // 8: s.inv(); return False
            s.K0 = b2v(secret); s.bb = 0; s.cum = f.b; s.haskey = True; return True
        if s.st != 'Absorb': s.inv(); return False
        s._vli(b2v(secret), 8 * len(secret), 0, True); return True
    def clear(s): s.st = 'Inert'
    def fields(s):
        """(name, value, width_bits) of the Serialized Content in position order (unpadded)."""
        f = s.f; k = [] if not s.hmac and s.syskey is None else None
        if f.kind == 'sha3': L = [('state', s.S, 1600), ('block_base', s.bb, 16), ('last_block_len', s.lbl, 16), ('out_len', s.outl, 32)] + ([('cumul_len', s.cum, 64)] if s.hmac else [])
        else: L = [('state', s.S, f.n), ('last_block_len', s.lbl, 16), ('block_base', s.bb, 16), ('out_len', s.outl, 32), ('cumul_len', s.cum, 64), ('block', s.blk, f.b)]
        if f.kind == 'blake2': L = ([('SKID', 0, 64)] if s.syskey is not None else []) + L + [('nn', s.nn, 16), ('kk', s.kk, 16)]
        if s.hmac: L += [('K0', s.K0, f.b), ('tag_len', s.tag_len, 16)]
        return L

def run(L, chunks, halts=False):
    """feed chunks (bytes) by Form B kl.exec in Absorb; with halts, halt at every opportunity and resume."""
    for c in chunks:
        k = 0
        while True:
            r = L.exec('B', c, k, halt=halts)
            if r is None: break
            k = r
def digest(L, nbytes=None, Xs=0, chunk=None, halts=False):
    """kl.setst Output then Form C kl.exec reading nbytes (default: digest size) in pieces of chunk bytes."""
    L.setst('output', 'B' if Xs else 'A', Xs)
    n = nbytes if nbytes is not None else (Xs // 8 if Xs else L.nn if L.f.kind == 'blake2' else 32 if L.f.xof else L.f.d // 8)
    out = b''; k = 0
    chunk = chunk or n
    while len(out) < n and L.st == 'Output':
        want = min(chunk, n - len(out)); r = L.exec('C', kllen=8 * want)
        out += r
    return out
