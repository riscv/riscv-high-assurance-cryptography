"""Executable model of the Merkle-Damgard / sponge hash Machines of Zkl-ISA-machines.adoc, derived from the spec
text only: generic hash Machine (KLE-hash-functions-MACs-XOFs, KLE-process-VLI), SHA-2, SM3, BLAKE2, HMAC (NIK/KIP,
on SHA-2, SM3, SHA-3) and SHA-3/SHAKE.  Values follow common.py conventions (ints, bit i = V[i], bytes = little endian).
Round functions come from hash_ref.py (independent of this model).

Locker(fname, hmac=None|'NIK'|'KIP', key=bytes K0 (KIP), syskey=bytes (BLAKE2 only), policy=int, tag_len_p=int (HMAC))
  tag_len_p defaults to t; a value not admitted (a multiple of 8 from 64 to t) gives Invalid (MR12).
  .st                         'Ready','Absorb','Last','Output','Bits','Verify','SetKey','Success','Failure','Invalid','Inert'
  .setst(imm, form='A', Xs=0) imm in ready absorb last output bits verify setkey aux success failure finalize
        'bits' is _Hash_Output_Bits_ (State 16): read_len = Xs, held in lbl (the alias of last_block_len); from Absorb
        or Last it first does what setst('output') does
  .exec(form, data=b'', klstart=0, halt=False, kllen=None) -> bytes (Form C output, zero-filled) | None
        in Bits, halt=True stops at the first byte offset past klstart (see .halted)
        returns for Form B: None when complete, or the klstart of a halt (int) -> see .halted
  .derive(secret, klstart=0, stream=False, sealed=False, smdh=None) -> bool (destination side of kl.derive of a shared secret;
        smdh: the source MDH of a restricted transfer, narrowing .mdh by GR30, or 'PrivViolation')
  .sealed, .ksealed           `Sealed` and `KeySealed` (HMAC NIK) of StateExtension (GR31.3)
  .mdh                        UsagePolicy, Locality, ExpirationDate and SCProtection, for GR30 only (default 0)
  .meta_ok()                  StateExtension @ State supported (KLE-Metadata-validity); import_(L): SCC import or kl.clone
Key(n, src_out) is a key field of n bytes of another symmetric Machine in Ready, src_out marking keystream, OFB or CMAC.
  .clear();  copy.deepcopy(locker) is an export/import snapshot.
Class Metadata(Exception): invalid or unsupported Metadata at provisioning."""
import copy, hash_ref as R
from common import b2v, v2b, mask, gr40

class Metadata(Exception): pass
M = mask
class Fn:
    def __init__(s, name):
        s.name = name
        if name in R.SHA2: s.kind = 'sha2'; s.w, s.block_len, s.t = R.SHA2[name]; s.state_len = 8 * s.w; s.xof = False
        elif name == 'SM3': s.kind = 'sm3'; s.w, s.block_len, s.t, s.state_len = 32, 512, 256, 256; s.xof = False
        elif name in R.B2: s.kind = 'blake2'; s.w, _, bb, nnm, _ = R.B2[name]; s.block_len = 8 * bb; s.nnmax = nnm; s.state_len = 8 * s.w; s.t = 8 * nnm; s.xof = False
        else: s.kind = 'sha3'; s.block_len, t, s.D, s.Dlen = R.SHA3[name]; s.state_len = 1600; s.xof = t is None; s.t = t or s.block_len
        s.d = s.t
    mode = property(lambda s: 'xor_accumulate' if s.kind == 'sha3' else 'assign')
    hold = property(lambda s: s.kind == 'blake2')
    bit_ok = property(lambda s: s.kind in ('sha3', 'sha2', 'sm3'))   # final piece may have any bit length

class Locker:
    def __init__(s, fname, hmac=None, key=None, syskey=None, policy=None, tag_len_p=None):
        if policy is None: policy = 3 if hmac else 0
        f = s.f = Fn(fname); s.hmac = hmac; s.syskey = None; s.policy = policy; s.halted = None
        if hmac:
            if policy & ~3 or not policy & 3: raise Metadata('HMAC MachinePolicy')
            if hmac == 'KIP' and (key is None or len(key) != f.block_len // 8): raise Metadata('K0')
            if hmac == 'NIK' and key is not None: raise Metadata('NIK carries no key')
        elif f.kind == 'blake2' and syskey is not None:
            if not 1 <= len(syskey) <= f.nnmax: raise Metadata('kk range')   # locker Invalid in hardware; here at provisioning
            if policy != 1: raise Metadata('BLAKE2 sys key MachinePolicy')
            s.syskey = b2v(syskey + b'\0' * (f.block_len // 8 - len(syskey)))
        elif policy: raise Metadata('unsupported MachinePolicy')
        s.K0 = b2v(key) if key else 0; s.haskey = hmac == 'KIP'
        s.nn = f.t // 8 if f.kind == 'blake2' else 0
        s.kk = len(syskey) if syskey else 0
        s.tag_len = 0; s.input_key = None; s.ksealed = False; s.mdh = 0
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
        s.st = 'Ready'; s.lbl = s.bb = s.cum = s.outl = 0; s.blk = 0; s.tag_len = 0; s.S = s.iv(); s.sealed = False
        if s.hmac == 'KIP': s.haskey = True
    def _P(s): s.S = R.keccak_f(s.S)
    def _comp(s, final=False):
        f = s.f; bl = v2b(s.blk, f.block_len // 8); S = v2b(s.S, f.state_len // 8)
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
    def _vli(s, mode, X, kllen, ib, count=True, halt=False):
        """PROCESS_VLI loop of _Hash_Absorb_ (and of the final piece) for the hash Machines."""
        f = s.f
        if f.kind == 'blake2' and s.syskey is not None and s.cum == 0 and ib < kllen:
            s.blk = s.syskey; s.cum = f.block_len; s._comp(False); s.blk = 0
        while ib < kllen:
            if f.hold and s.bb == f.block_len: s._comp(False); s.bb = 0
            a = min(kllen - ib, f.block_len - s.bb); c = (X >> ib) & M(a)
            if mode == 'xor_accumulate': s.S ^= c << s.bb
            else: s.blk = (s.blk & ~(M(a) << s.bb)) | (c << s.bb)
            ib += a; s.bb += a
            if count: s.cum += a
            if s.bb == f.block_len and not f.hold: s._comp(); s.bb = 0
            if halt and ib < kllen: return ib // 8
        return None
    def _put(s, data):   # finalize steps 3.a-e,g (cum not counted)
        s._vli(s.f.mode, b2v(data), 8 * len(data), 0, count=False)
    def _finalize(s, ell=None):
        f = s.f
        if f.kind in ('sha2', 'sm3'):
            ell = s.cum if ell is None else ell
            if s.cum % 8 == 0: s._put(b'\x80')
            while s.bb != f.block_len - 2 * f.w: s._put(b'\0')
            s._put(ell.to_bytes(2 * f.w // 8, 'big'))
        elif f.kind == 'blake2':
            if s.bb > 0: s.blk &= M(s.bb); s._comp(True)
            elif s.syskey is not None: s.blk = s.syskey; s.cum = f.block_len; s._comp(True); s.blk = 0
            elif s.kk == 0: s.blk = 0; s._comp(True)
            else: s.inv(); return
            s.bb = 0
        else:
            D = f.D | (1 << f.Dlen); Dl = f.Dlen + 1       # D then the first 1 of pad10*1
            n = f.Dlen + 2
            while (s.bb + n) % f.block_len: n += 1
            Sx = D | (1 << (n - 1))
            s.S ^= (Sx & M(f.block_len - s.bb)) << s.bb; s._P()
            if n > f.block_len - s.bb: s.S ^= Sx >> (f.block_len - s.bb); s._P()
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
        if imm in ('bits', 'verify') and (s.sealed or s.ksealed): return s.inv()   # a sealed locker: no read, no verify
        if imm == 'bits':
            if st in ('Absorb', 'Last'):                                       # ends the message: a Form A Hash_Output, then this kl.setst
                s.setst('output')
                if s.st != 'Output': return
                st = 'Output'
            if st not in ('Output', 'Bits') or form != 'B' or not 0 < Xs < 2**16: return s.inv()
            s.lbl = Xs; s.st = 'Bits'; return                                  # no finalize(); block_base, out_len kept
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
            s.lbl = f.block_len; s.st = 'Absorb'; return
        if imm == 'last':
            if st != 'Absorb' or form not in 'AB': return s.inv()
            if Xs > f.block_len or (Xs % 8 and not f.bit_ok): return s.inv()
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
    def _enter_setkey(s): s.st = 'SetKey'; s.K0 = 0; s.haskey = s.ksealed = False; s.bb = s.cum = 0
    def _leave_setkey(s):
        if s.cum != s.f.block_len: s.K0 = 0; s.haskey = False
    def _enter_hmac_absorb(s):
        f = s.f; s._vli(f.mode, s.K0 ^ b2v(b'\x36' * (f.block_len // 8)), f.block_len, 0, count=False)
    def _hmac_outer(s):
        f = s.f
        s._finalize(f.block_len + s.cum if f.kind in ('sha2', 'sm3') else None)
        inner = s._digest()
        s.S = s.iv(); s.blk = s.bb = s.cum = 0
        s._vli(f.mode, s.K0 ^ b2v(b'\x5c' * (f.block_len // 8)), f.block_len, 0, count=False)
        s._vli(f.mode, inner, f.t, 0, count=True)
        s._finalize(f.block_len + s.cum if f.kind in ('sha2', 'sm3') else None); s.bb = s.lbl = 0
    def exec(s, form, data=b'', klstart=0, halt=False, kllen=None):
        s.halted = None; f = s.f; st = s.st; kl = 8 * len(data) if kllen is None else kllen
        if st in ('Invalid', 'Inert'): return None if form != 'C' else bytes(kl // 8)
        zero = bytes(kl // 8) if form == 'C' else None
        if st in ('Output', 'Bits', 'Verify') and s.hmac and not s.policy & (2 if st == 'Verify' else 1): s.inv(); return zero   # GR20
        if st in ('Output', 'Bits'):
            if form != 'C' or s.sealed or s.ksealed: s.inv(); return zero
            if st == 'Bits' and s.lbl == 0: s.inv(); return zero              # read_len exhausted: a new kl.setst is needed
            return s._exec_out(kl, klstart, halt, st == 'Bits')
        if form != 'B' or st not in ('Absorb', 'Last', 'SetKey', 'Verify'): s.inv(); return zero
        if st == 'Verify':
            if klstart * 8 >= kl: return None                          # GR18 item 1
            if kl < s.tag_len: return s.inv()
            ok = (b2v(data) & M(s.tag_len)) == (s.S & M(s.tag_len))
            s.st = 'Success' if ok else 'Failure'; return None
        if st == 'Last':
            L = s.lbl
            if L == 0: return s.inv()                                  # MR10: empty final input admits no kl.exec, even an empty window
            if klstart * 8 >= kl: return None                          # GR18 item 1
            if kl < L or klstart: return s.inv()                       # GR18 items 2, 3
            X = b2v(data)
            if f.kind in ('sha2', 'sm3'):
                nb = (L + 7) // 8; q = L % 8; bs = bytearray(data[:nb])
                if q: bs[-1] = (bs[-1] & (0xff << (8 - q)) & 0xff) | (1 << (7 - q))
                s._vli(f.mode, b2v(bytes(bs)), 8 * nb, 0, count=False); s.cum += L
            else: s._vli(f.mode, X & M(L), L, 0, count=True)
            s.lbl = 0; return None
        if klstart * 8 >= kl: return None
        if klstart and not (s.bb == 0 or (f.hold and s.bb == f.block_len)): return s.inv()
        if st == 'SetKey':
            if s.cum >= f.block_len: return s.inv()
            ib = 8 * klstart; X = b2v(data)
            while ib < kl:
                a = min(kl - ib, f.block_len - s.bb, f.block_len - s.cum)
                s.K0 = (s.K0 & ~(M(a) << s.bb)) | (((X >> ib) & M(a)) << s.bb)
                ib += a; s.bb += a; s.cum += a
                if s.bb == f.block_len: s.bb = 0
                if s.cum == f.block_len: s.haskey = True; return None
                if halt and ib < kl: s.halted = ib // 8; return s.halted
            return None
        r = s._vli(f.mode, b2v(data), kl, 8 * klstart, True, halt); s.halted = r; return r
    def _exec_out(s, kl, klstart, halt, bits=False):
        """Form C loop of Hash_Output; with bits, of Hash_Output_Bits (read_len = s.lbl)."""
        f = s.f; out = 0; ob = 8 * klstart
        if klstart * 8 >= kl: return bytes(kl // 8)
        if klstart and s.bb and not bits: s.inv(); return bytes(kl // 8)
        while ob < kl:
            a = min(kl - ob, f.t - s.bb)
            if s.outl: a = min(a, s.outl)
            if bits: a = min(a, s.lbl, 8 - ob % 8 if halt else a)          # a halt splits the loop at the next byte
            out |= ((s.S >> s.bb) & M(a)) << ob
            ob += a; s.bb += a
            if bits: s.lbl -= a
            if s.outl:
                s.outl -= a
                if s.outl == 0:
                    out &= M(ob); s.st = 'Success'; return v2b(out, kl // 8)
            if s.bb == f.t:
                if f.kind == 'sha3': s._P()
                s.bb = 0
                if halt and not bits and ob < kl: s.halted = ob // 8; return v2b(out, kl // 8)
            if bits and s.lbl == 0: out &= M(ob); return v2b(out, kl // 8)   # read done: rest of OUTPUT cleared
            if bits and halt and ob % 8 == 0 and ob < kl: s.halted = ob // 8; return v2b(out, kl // 8)
        return v2b(out, kl // 8)
    def rstrl(s, mask):
        """kl.rstrl narrowing MachinePolicy (GR20): a value the Machine forbids -> Invalid; a cleared gate bit fails the next gated operation."""
        if s.st in ('Invalid', 'Inert'): return
        s.policy &= mask
        if s.hmac and not s.policy & 3: s.inv()
    def _gr40(s, smdh):
        if smdh is None: return True
        nm = gr40(s.mdh, smdh)
        if nm is None: s.st = 'PrivViolation'; return False
        s.mdh = nm; return True
    def meta_ok(s):
        """StateExtension @ State supported: Sealed only in Absorb, Last, Output, Success; KeySealed (HMAC NIK) only with
        HasKey, and not in Bits, Verify or Failure."""
        if s.sealed and s.st not in ('Absorb', 'Last', 'Output', 'Success'): return False
        return not s.ksealed or s.hmac == 'NIK' and s.haskey and s.st not in ('Bits', 'Verify', 'Failure')
    def derive(s, secret, klstart=0, stream=False, length=None, src='secret', sealed=False, smdh=None):
        """destination side of kl.derive of a shared secret; False (and dest Invalid) if refused; srcinv: the source fails."""
        s.srcinv = False
        if s.st in ('Invalid', 'Inert'): return False
        if klstart: s.inv(); return False                                     # GR29 item 1
        if s.hmac and s.tag_len_p != s.f.t: s.inv(); return False             # MR12: a short tag_len_p is not a destination
        if src != 'secret' and s.st == 'Absorb': s.srcinv = True; s.inv(); return False   # GR29 item 4: only a shared secret enters a message, both Invalid
        f = s.f; length = len(secret) if length is None else length
        if length != len(secret): s.inv(); return False
        if s.st == 'SetKey':
            if stream or len(secret) > f.block_len // 8: s.inv(); return False
            if sealed and length < 16: s.srcinv = True; return False                 # GR29 item 7
            if not s._gr40(smdh): return False
            s.K0 = b2v(secret); s.bb = 0; s.cum = f.block_len; s.haskey = True; s.ksealed |= sealed; return True
        if s.st != 'Absorb': s.inv(); return False
        if sealed and length < 16: s.srcinv = True; return False
        if not s._gr40(smdh): return False
        s._vli(s.f.mode, b2v(secret), 8 * len(secret), 0, True); s.sealed |= sealed; return True
    def clear(s): s.st = 'Inert'
    def fields(s):
        """(name, value, width_bits) of the Serialized Content in position order (unpadded)."""
        f = s.f; k = [] if not s.hmac and s.syskey is None else None
        if f.kind == 'sha3': L = [('state', s.S, 1600), ('block_base', s.bb, 16), ('last_block_len', s.lbl, 16), ('out_len', s.outl, 32)] + ([('cumul_len', s.cum, 64)] if s.hmac else [])
        else: L = [('state', s.S, f.state_len), ('last_block_len', s.lbl, 16), ('block_base', s.bb, 16), ('out_len', s.outl, 32), ('cumul_len', s.cum, 64), ('block', s.blk, f.block_len)]
        if f.kind == 'blake2':                                 # nn, kk in Positions v, vi; out_len in vii in the output States
            vii = ('out_len', s.outl, 64) if s.st in ('Output', 'Bits') else ('cumul_len', s.cum, 64)
            L = ([('SKID', 0, 64)] if s.syskey is not None else []) + L[:3] + [('nn', s.nn, 16), ('kk', s.kk, 16), vii, L[5]]
        if s.hmac: L += [('K0', s.K0, f.block_len), ('tag_len', s.tag_len, 16)]
        return L

def derive_out(S, D, n):
    """kl.derive D <- S, with S in Hash_Output or Hash_Output_Bits (GR31.2; read_len is kept): unrestricted; the destination checks see the remaining output, of which
    the transfer takes n bytes as a Form C kl.exec would (GR28).  False if refused."""
    D.srcinv = False
    if S.st not in ('Output', 'Bits'): S.inv(); D.srcinv = True; return False       # GR29 item 2: not a source endpoint
    rem = (S.outl + 7) // 8 if S.outl else None                                      # None: an XOF without bound
    sealed = S.sealed or S.ksealed
    ok = D.derive(copy.deepcopy(S)._exec_out(8 * (rem or n), 0, False), length=n, stream=rem is None, src='out', sealed=sealed,
                  smdh=S.mdh if sealed else None)                                  # GR31.3: a sealed hop is restricted (GR30)
    if D.srcinv: S.inv()
    if ok: S._exec_out(8 * n, 0, False)
    return ok

class Key:
    """key field of n bytes of a symmetric Machine in Ready; src_out: keystream generation, OFB or CMAC, whose output is a source."""
    def __init__(s, n, src_out=False, mdh=0): s.n, s.src_out, s.key, s.st, s.mdh = n, src_out, None, 'Ready', mdh
    def inv(s): s.st = 'Invalid'
    _gr40 = Locker._gr40
    def derive(s, data, length, stream, src, sealed=False, smdh=None):
        s.srcinv = False
        if sealed and s.src_out: s.inv(); s.srcinv = True; return False             # GR31.3: not an admitted pair, both Invalid
        if length < s.n or len(data) < s.n: s.inv(); return False                    # GR29 item 6
        if sealed and s.n < 16: s.srcinv = True; return False                        # item 7 (eff_length = n)
        if not s._gr40(smdh): return False
        s.key = data[:s.n]; return True

def import_(L):
    """SCC import or kl.clone of L: a copy, Invalid if its StateExtension @ State is unsupported (KLE-Metadata-validity)."""
    C = copy.deepcopy(L)
    if not C.meta_ok(): C.inv()
    return C

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
