#!/usr/bin/env python3
"""GCM and GCM with Set IV (<<KLE-GCM-mode>>, <<KLE-GCM-with-IV-mode>>) through a model locker,
against McGrew-Viega / SP 800-38D test cases 1-6 and 13-18 and a byte-string SP 800-38D reference."""
import copy, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bswap, bxor, MASK128, aes_encrypt, gmul_ghash, kl_galoismul,
                    selftest, ERROR_STATES, IllegalInstruction, raises, section, check, control, done,
                    KL_STATE_INERT as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_HASH_ABSORB as HA, KL_STATE_HASH_VERIFY as HV,
                    KL_STATE_ENCRYPT as ENC, KL_STATE_DECRYPT as DEC,
                    KL_STATE_ENC_LAST_BLOCK as ELB, KL_STATE_DEC_LAST_BLOCK as DLB,
                    KL_STATE_ENC_TAG_FINALIZE as ETF, KL_STATE_DEC_TAG_FINALIZE as DTF,
                    KL_STATE_SET_AUX_VALUE as SAV, KL_STATE_SUCCESS as SUCC,
                    KL_STATE_FAILURE as FAIL, KL_STATEEXT_INVALID as INV,
                    KL_STATEEXT_PRIV_VIOLATION as PRIV)

def pad16(s): return s + bytes(-len(s) % 16)
def pad128(n): return -(-n // 128) * 128
def be64(n): return n.to_bytes(8, 'big')
def inc32(b, n=1): return b[:12] + ((int.from_bytes(b[12:], 'big') + n) % 2**32).to_bytes(4, 'big')

# ---------------------------------------------------------------- REF: SP 800-38D on byte strings
def ghash(H, X):
    y = bytes(16)
    for i in range(0, len(X), 16):
        y = gmul_ghash(bxor(y, X[i:i + 16]), H)
    return y

def ref_j0(K, IV):
    if len(IV) == 12:
        return IV + b'\0\0\0\1'
    return ghash(aes_encrypt(K, bytes(16)), pad16(IV) + bytes(8) + be64(8 * len(IV)))

def ref_gcm(K, IV, A, P):
    J0 = ref_j0(K, IV)
    cb, C = inc32(J0), b''
    for i in range(0, len(P), 16):
        C, cb = C + bxor(P[i:i + 16], aes_encrypt(K, cb)), inc32(cb)
    S = ghash(aes_encrypt(K, bytes(16)), pad16(A) + pad16(C) + be64(8 * len(A)) + be64(8 * len(C)))
    return C, bxor(S, aes_encrypt(K, J0))

def galoismul_def(a, b):
    """<<KLE-GCM-mode>>: V represents sum of V[8i+(7-j)] x^(8i+j) mod x^128+x^7+x^2+x+1."""
    def poly(V): return sum(1 << (8 * i + j) for i in range(16) for j in range(8) if V >> (8 * i + 7 - j) & 1)
    pa, pb, r = poly(a), poly(b), 0
    while pb:
        r, pa, pb = r ^ (pa if pb & 1 else 0), pa << 1, pb >> 1
    for d in range(254, 127, -1):
        if r >> d & 1:
            r ^= (1 << d) | (0x87 << (d - 128))
    return poly(r)          # the representation map is an involution

# ---------------------------------------------------------------- KLE model
SKID = 0x0123456789ABCDEF
SKS = {SKID: bytes.fromhex('feffe9928665731c6d6a8f9467308308')}

TAG_LENS = (128, 120, 112, 104, 96, 64)            # SP 800-38D 5.2.1.2; 32 excluded (floor 64)

GATED = {ENC: 1, ELB: 1, ETF: 1, DEC: 2, DLB: 2, DTF: 2, HV: 2}   # MR11: the Gated States and their bit

class Gcm:
    """A GCM (set_iv False) or GCM with Set IV locker; MDH reduced to State, MachinePolicy
    (bit 0 encrypt, bit 1 decrypt), KeyType.  le_counter, iv_into_J0, stale_auth_key, ready_keeps_ctr:
    negative controls."""

    def __init__(s, set_iv=False, policy=3, le_counter=False, iv_into_J0=False, stale_auth_key=False,
                 ready_keeps_ctr=False):
        s.set_iv, s.policy, s.le, s.stale, s.keep_ctr = set_iv, policy, le_counter, stale_auth_key, ready_keeps_ctr
        s.acc = 'J0' if iv_into_J0 else 'tag'
        s.klstart, s.halted, s.zklio = 0, False, True
        s._error(UNCONF)

    def _error(s, st):                                   # GR29
        s.state, s.key, s.k, s.key_type, s.skid = st, b'', 0, 0, 0
        s.J0 = s.auth_key = s.tag = s.start_ctr = s.last_block_len = 0
        s.len = s.input_base = s.block_base = s.cumul_len = 0
        return 0

    def _invalid(s): return s._error(INV)
    def restrictl(s, v):                             # a set bit removes a function (<<KLE-instruction-restrict>>)
        s.policy &= ~v                               # GR20: no transition by itself, unless the value is forbidden
        if s.state not in ERROR_STATES and s.policy == 0:
            s._invalid()                             # GCM requires a set bit

    def _load_key(s, v, k, key_type):                    # key or SKID (GR72)
        s.k, s.key_type = k, key_type
        kb = 64 if key_type else k
        f = sl(v, kb - 1, 0)
        s.skid, s.key = (f, SKS[f]) if key_type else (0, v2b(f, k // 8))
        return kb

    @staticmethod
    def pi(key=None, iv=None, skid=None):
        v, n = (skid, 64) if skid is not None else (b2v(key), 8 * len(key))
        if iv is not None:                               # GCM with Set IV: a 96-bit IV, never J0
            v, n = v | sl(iv, 95, 0) << n, n + 96
        return v, pad128(n)

    @classmethod
    def provisioned(cls, key=None, iv=None, skid=None, **kw):
        s = cls(set_iv=iv is not None, **kw)
        v = cls.pi(key, iv, skid)[0]
        kb = s._load_key(v, 8 * len(SKS[skid] if skid else key), int(skid is not None))
        if s.set_iv:                                     # J0 <- bswap(bin(1, 32)) @ IV, start_ctr <- 1
            s.J0 = cat((s._bs(1), 32), (sl(v, kb + 95, kb), 96))
            s.start_ctr = 1
        s.state = READY
        s._ready()
        return s

    def export(s):
        if s.state in ERROR_STATES:
            return 0, 0                                  # GR29
        kb = 64 if s.key_type else s.k
        slot = (cat((s.cumul_len, 48), (s.block_base, 16), (0, 16), (s.len, 16))   # ii.b and ii.e: padding
                if s.state == SAV else s.J0)
        return (cat((s.last_block_len, 16), (s.start_ctr, 32), (s.tag, 128), (slot, 128),
                    (s.skid if s.key_type else b2v(s.key), kb)), pad128(kb + 304))

    @classmethod
    def imported(cls, state, v, k, key_type=0, **kw):
        s = cls(**kw)
        kb = s._load_key(v, k, key_type)
        slot = sl(v, kb + 127, kb)
        if state == SAV:
            s.len, s.block_base, s.cumul_len = sl(slot, 15, 0), sl(slot, 47, 32), sl(slot, 95, 48)
        else:
            s.J0 = slot
        s.tag, s.start_ctr, s.last_block_len = (
            sl(v, kb + 255, kb + 128), sl(v, kb + 287, kb + 256), sl(v, kb + 303, kb + 288))
        s.state = state
        if s.set_iv and s.start_ctr != 1:
            return s._invalid() or s                     # MR13: start_ctr is 1 in every Set IV CC
        if not s.stale:
            s.auth_key = s._enc(0)                       # MR4
        return s

    def _ready(s):
        s.auth_key, s.tag = s._enc(0), 0
        if s.set_iv and not s.keep_ctr:
            s._set_ctr(s.start_ctr)                      # Set IV: the provisioned J0 restored

    def _enc(s, p): return b2v(aes_encrypt(s.key, v2b(p, 16)))
    def _absorb(s, d): s.tag = kl_galoismul(s.tag ^ d, s.auth_key)
    def _bs(s, x): return x if s.le else bswap(x, 4)    # int(bswap(.)) / bswap(bin(., 32))
    def _set_ctr(s, ctr): s.J0 = cat((s._bs(ctr), 32), (sl(s.J0, 95, 0), 96))

    def _next_ctr(s):
        ctr = (s._bs(sl(s.J0, 127, 96)) + 1) % 2**32
        return None if ctr == (s.start_ctr - 1) % 2**32 else ctr

    def _form(s, st, immed):
        """kl.setst Form of each listed transition; None if not listed (MR1)."""
        t = {(HA, ENC): 'A', (HA, DEC): 'A', (DTF, HV): 'C'}
        for c, l, f in ((ENC, ELB, ETF), (DEC, DLB, DTF)):
            t.update({(c, l): 'B', (c, f): 'C', (l, f): 'C'})   # no same-State pair: GR17
        if s.set_iv:
            t[READY, HA] = 'A'
        else:
            t.update({(READY, SAV): 'B', (SAV, SAV): 'B', (SAV, HA): 'A'})   # SAV -> SAV restarts the IV (GR17, MR9)
        return t.get((st, immed))

    def setst(s, immed, form='A', aux=0, klen=128):
        """klen: KLLEN of a Form C operand.  form 'A/iobuf': a Form A kl.setst, `aux` the KLIOBUF bytes;
        where the State expects Form C it is the substitution (<<KLE-usage-input-output>>)."""
        st = s.state
        if immed in ERROR_STATES:                        # <<KLE-instruction-setst>>, GR30
            return s._error(immed)
        if st in ERROR_STATES:
            return                                       # GR26
        if form == 'A/iobuf':                            # klstart ignored; truncated to 128 bits (MR7)
            form, klen, aux = (('C', 8 * len(aux), b2v(aux)) if s._form(st, immed) == 'C' else ('A', klen, 0))
        if immed == READY and form == 'A':               # GR16
            if st == SAV:                                # IV left incomplete: discarded, no finalize() (MR9)
                s.tag = s.J0 = s.len = s.block_base = s.cumul_len = 0
            s.state = READY
            return s._ready()
        if st in (SUCC, FAIL) or s._form(st, immed) != form:
            return s._invalid()                          # GR16, MR1
        if st == immed and st != SAV:
            return s._invalid()                          # GR17, GR18: only the IV load restarts (MR9)
        if immed in GATED and not s.policy & GATED[immed]:
            return s._invalid()                          # MR11: entering a Gated State
        if immed == SAV:
            if not (8 <= aux <= 8192 and aux % 8 == 0):
                return s._invalid()
            s.len, s.tag, s.input_base, s.block_base, s.cumul_len = aux, 0, 0, 0, 0
            if s.acc == 'J0':
                s.J0 = 0
        elif immed in (ELB, DLB):
            if not (0 < aux < 128 and aux % 8 == 0):
                return s._invalid()                      # MR16
            s.last_block_len = aux
        elif immed in (ETF, DTF):
            if klen < 128:
                return s._invalid()                      # MR7: shorter than the 128-bit fixed-width input
            s._absorb(aux & MASK128)
            s.tag ^= s._enc(cat((s._bs(s.start_ctr), 32), (sl(s.J0, 95, 0), 96)))
        elif immed == HV:                               # t = KLLEN, truncated to 128 (MR7); SP 800-38D 5.2.1.2
            t = min(klen, 128)
            if t not in TAG_LENS:
                return s._invalid()
            immed = SUCC if sl(aux, t - 1, 0) == sl(s.tag, t - 1, 0) else FAIL
        elif st == SAV:
            return s._invalid()                          # _Hash_Absorb_ needs a complete IV (MR11)
        s.state = immed

    def _finalize(s):
        acc = getattr(s, s.acc)
        if s.len == 96:
            s.J0 = cat((bswap(1, 4), 32), (sl(acc, 95, 0), 96))
        else:
            if s.block_base:
                acc = kl_galoismul(acc, s.auth_key)
            s.J0 = kl_galoismul(acc ^ bswap(s.len, 8) << 64, s.auth_key)
        s.start_ctr, s.tag, s.state = s._bs(sl(s.J0, 127, 96)), 0, HA

    def exec(s, form, INPUT=0, KLLEN=128, start=None, stop=None):
        """kl.exec; `start` resumes at that klstart, `stop` halts after that many units."""
        s.halted = False
        if s.state in ERROR_STATES:
            return 0                                     # GR26, GR28
        if s.state in GATED and not s.policy & GATED[s.state]:
            s._invalid()                                 # MR11, GR20: a narrowing takes effect here
            return 0
        want = {SAV: 'B', HA: 'B', ENC: 'A', DEC: 'A', ELB: 'A', DLB: 'A', ETF: 'C'}.get(s.state)
        if form == 'D' and want is not None and s.zklio:
            form = want                                  # the substitution of the native Form
        if want != form:
            return s._invalid()                          # GR17, GR16, MR1; a wrong Form (GR67, GR66)
        if (KLLEN % 128 and s.cumul_len + KLLEN < s.len if s.state == SAV else
                KLLEN < s.last_block_len if s.state in (ELB, DLB) else
                KLLEN < 128 and KLLEN not in TAG_LENS if s.state == ETF else KLLEN % 128):
            return s._invalid()                          # MR2, <<KLE-truncation-vs-length>>: length first
        s.klstart = start or 0
        if 8 * s.klstart >= KLLEN:
            s.klstart = 0                                # empty window, length 0 included (<<KLE-GR-transfer-window-checks>>)
            return 0
        if start is not None:
            if start % 16 or start and (s.state in (ELB, DLB, ETF) or s.state == SAV and s.block_base):
                return s._invalid()                      # not an interruption point (<<KLE-process-VLI>>)
        if s.state == SAV:
            return s._exec_vli(INPUT, KLLEN, start is not None, stop)
        if s.state in (ELB, DLB):
            return s._exec_last(INPUT, KLLEN)
        if s.state == ETF:
            s.state = SUCC
            return s.tag & ((1 << KLLEN) - 1)
        first = s.klstart // 16 if start is not None else 0
        st, out = s.state, 0
        for i in range(first, KLLEN // 128):
            if stop is not None and i - first == stop:
                s.klstart, s.halted = 16 * i, True       # GR41
                return out
            blk = sl(INPUT, 128 * i + 127, 128 * i)
            if st == HA:
                s._absorb(blk)
                continue
            ctr = s._next_ctr()
            if ctr is None:
                s._invalid()
                return out                               # GR41
            if st == DEC:
                s._absorb(blk)
            s._set_ctr(ctr)
            o = blk ^ s._enc(s.J0)
            if st == ENC:
                s._absorb(o)
            out |= o << 128 * i
        s.klstart = 0
        return out

    def _exec_last(s, INPUT, KLLEN):
        lbl = s.last_block_len
        if lbl == 0:                                   # MR10: the final block was already processed
            return s._invalid()
        ctr = s._next_ctr()
        if ctr is None:
            return s._invalid()
        s._set_ctr(ctr)
        m = (1 << lbl) - 1
        x, o = INPUT & m, (INPUT ^ s._enc(s.J0)) & m
        s._absorb(o if s.state == ELB else x)
        s.last_block_len = 0
        return o

    def _exec_vli(s, INPUT, KLLEN, resuming, stop):
        """PROCESS_VLI(len, tag, b, tag, b, input_base, block_base, 0, cumul_len, ..., xor_accumulate, b)."""
        if KLLEN % 128 and s.cumul_len + KLLEN < s.len:
            return s._invalid()                          # MR2: granularity b
        if s.cumul_len >= s.len:
            return s._invalid()
        s.input_base, it = 8 * s.klstart if resuming else 0, 0
        while s.input_base < KLLEN:
            amount = min(KLLEN - s.input_base, 128 - s.block_base, s.len - s.cumul_len)
            data = sl(INPUT, s.input_base + amount - 1, s.input_base)
            setattr(s, s.acc, getattr(s, s.acc) ^ data << s.block_base)
            s.input_base += amount
            s.block_base += amount
            s.cumul_len += amount
            if s.block_base == 128:
                if s.len != 96:
                    setattr(s, s.acc, kl_galoismul(getattr(s, s.acc), s.auth_key))
                s.block_base = 0
            if s.cumul_len == s.len:
                s._finalize()
                break
            it += 1
            if stop is not None and it == stop and s.input_base < KLLEN and s.input_base % 128 == 0:
                s.klstart, s.halted = s.input_base // 8, True
                return 0
        s.klstart = 0
        return 0

    def derive(s, src, length):
        """kl.derive destination (<<KLE-derive-endpoints>>): `key` in Ready, from a GR34-GR35 source (bytes).
        A Gcm is no source, its tag included; the IV (`kl.exec` input) in Set_Aux_Value is no destination."""
        if s.state in ERROR_STATES or isinstance(src, Gcm) and src.state in ERROR_STATES:
            return                                       # GR26: an inert endpoint
        if isinstance(src, Gcm):
            return src._invalid()                        # GR32 item 1
        if s.set_iv or s.key_type == 1 or s.state != READY:
            return s._invalid()                          # Set IV, GR72, Set_Aux_Value: no endpoint (GR32 item 2)
        if length < s.k // 8 or len(src) < s.k // 8:
            return s._invalid()                          # GR32 item 5
        s.key = src[:s.k // 8]
        if not s.stale:
            s.auth_key = s._enc(0)                       # MR4

# ---------------------------------------------------------------- drivers (<<KLE-pseudocode-GCM-encryption>>)
def len_block(p_bits, a_bits, swap=False):
    if swap:
        p_bits, a_bits = a_bits, p_bits
    return cat((bswap(p_bits, 8), 64), (bswap(a_bits, 8), 64))

def feed(cl, data, chunk=16, stop=None):
    """Form B kl.exec over data in chunk-byte transfers, resuming any halted one."""
    for i in range(0, len(data), chunk):
        t = data[i:i + chunk]
        cl.exec('B', b2v(t), 8 * len(t), None, stop)
        while cl.halted:
            cl.exec('B', b2v(t), 8 * len(t), cl.klstart)

def crypt(cl, text, nblk=1, last=ELB):
    n, out = len(text) // 16 * 16, b''
    for i in range(0, n, 16 * nblk):
        t = text[i:min(i + 16 * nblk, n)]
        out += v2b(cl.exec('A', b2v(t), 8 * len(t)), len(t))
    if text[n:]:
        cl.setst(last, 'B', 8 * len(text[n:]))
        out += v2b(cl.exec('A', b2v(text[n:]), 8 * len(text[n:])), len(text[n:]))
    return out

def form_c(value, subst=False, extra=b''):
    """Arguments of a Form C kl.setst, or of the Form A one that substitutes it with the KLIOBUF."""
    return ('A/iobuf', v2b(value, 16) + extra) if subst else ('C', value)

def finish(cl, ad, pt, nblk=1, swap=False, subst=False):
    feed(cl, pad16(ad), 4096)
    cl.setst(ENC)
    ct = crypt(cl, pt, nblk)
    cl.setst(ETF, *form_c(len_block(8 * len(pt), 8 * len(ad), swap), subst))
    return ct, v2b(cl.exec('C', 0, 128), 16), cl

def kl_encrypt(key, iv, ad, pt, cl=None, iv_chunk=16, iv_stop=None, nblk=1, swap=False, subst=False, **kw):
    cl = cl or Gcm.provisioned(key, **kw)
    if cl.set_iv:
        cl.setst(HA)
    else:
        cl.setst(SAV, 'B', 8 * len(iv))
        feed(cl, iv, iv_chunk, iv_stop)
    return finish(cl, ad, pt, nblk, swap, subst)

def kl_decrypt(key, iv, ad, ct, tag, cl=None, subst=False, extra=b'', **kw):
    cl = cl or Gcm.provisioned(key, **kw)
    if cl.set_iv:
        cl.setst(HA)
    else:
        cl.setst(SAV, 'B', 8 * len(iv))
        feed(cl, iv)
    feed(cl, pad16(ad), 4096)
    cl.setst(DEC)
    pt = crypt(cl, ct, max(1, len(ct) // 16), DLB)
    cl.setst(DTF, *form_c(len_block(8 * len(ct), 8 * len(ad)), subst, extra))
    cl.setst(HV, *form_c(b2v(tag), subst, extra))
    return pt, cl.state, cl

# ---------------------------------------------------------------- vectors
# McGrew-Viega, "The Galois/Counter Mode of Operation (GCM)", Appendix B, test cases 1-6 and 13-18
# (the SP 800-38D vectors).  Fields: label, key, IV, AAD, plaintext, ciphertext, tag.
P64 = ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
P60 = P64[:120]
AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
K128 = "feffe9928665731c6d6a8f9467308308"
K256 = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
IV12 = "cafebabefacedbaddecaf888"
IV8 = "cafebabefacedbad"
IV60 = ("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
        "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b")

VECTORS = [
    ("tc1  AES-128", "00" * 16, "00" * 12, "", "", "",
     "58e2fccefa7e3061367f1d57a4e7455a"),
    ("tc2  AES-128", "00" * 16, "00" * 12, "", "00" * 16,
     "0388dace60b6a392f328c2b971b2fe78",
     "ab6e47d42cec13bdf53a67b21257bddf"),
    ("tc3  AES-128", K128, IV12, "", P64,
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
     "4d5c2af327cd64a62cf35abd2ba6fab4"),
    ("tc4  AES-128", K128, IV12, AAD, P60,
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
     "5bc94fbc3221a5db94fae95ae7121a47"),
    ("tc5  AES-128", K128, IV8, AAD, P60,
     "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423"
     "73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
     "3612d2e79e3b0785561be14aaca2fccb"),
    ("tc6  AES-128", K128, IV60, AAD, P60,
     "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7"
     "01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
     "619cc5aefffe0bfa462af43c1699d050"),
    ("tc13 AES-256", "00" * 32, "00" * 12, "", "", "",
     "530f8afbc74536b9a963b4f1c4cb738b"),
    ("tc14 AES-256", "00" * 32, "00" * 12, "", "00" * 16,
     "cea7403d4d606b6e074ec5d3baf39d18",
     "d0d1c8a799996bf0265b98b5d48ab919"),
    ("tc15 AES-256", K256, IV12, "", P64,
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
     "b094dac5d93471bdec1a502270e3cc6c"),
    ("tc16 AES-256", K256, IV12, AAD, P60,
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
     "76fc6ece0f4e1768cddf8853bb2d551b"),
    ("tc17 AES-256", K256, IV8, AAD, P60,
     "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0"
     "feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
     "3a337dbf46a792c45e454913fe2ea8f2"),
    ("tc18 AES-256", K256, IV60, AAD, P60,
     "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4"
     "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
     "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"),
]

K, IV, A, P, IV60B, SRC = map(bytes.fromhex, (K128, IV12, AAD, P60, IV60, K256))
RC, RT = ref_gcm(K, IV, A, P)                              # tc4
J0B = ref_j0(K, IV)
TC5, TC6 = (tuple(map(bytes.fromhex, VECTORS[i][5:])) for i in (4, 5))

def at(where, **kw):
    """A locker in Ready, Set_Aux_Value (480-bit IV pending), Hash_Absorb/Encrypt/Decrypt after
    IV12 and AAD, Success after tc4, or a Set IV locker in Ready."""
    if where == 'success':
        return kl_encrypt(K, IV, A, P, **kw)[2]
    if where == 'setiv':
        return Gcm.provisioned(K, iv=b2v(IV), **kw)
    cl = Gcm.provisioned(K, **kw)
    if where == 'sav':
        cl.setst(SAV, 'B', 480)
    elif where != 'ready':
        cl.setst(SAV, 'B', 96)
        feed(cl, IV)
        feed(cl, A + bytes(12))
        if where != 'ha':
            cl.setst(ENC if where == 'enc' else DEC)
    return cl

def to_etf():
    """tc4 encrypted up to _Enc_Tag_Finalize_."""
    cl = at('enc')
    crypt(cl, P)
    cl.setst(ETF, 'C', len_block(8 * len(P), 8 * len(A)))
    return cl

def to_dtf():
    """tc4 decrypted up to _Dec_Tag_Finalize_."""
    cl = at('dec')
    crypt(cl, RC, 3, DLB)
    cl.setst(DTF, 'C', len_block(8 * len(RC), 8 * len(A)))
    return cl

def seed(cl, ctr):
    """Seed the running counter (the rule depends only on its value)."""
    cl.J0 = cat((bswap(ctr % 2**32, 4), 32), (sl(cl.J0, 95, 0), 96))

# ---------------------------------------------------------------- tests
section('primitives')
check('common.py self-test', selftest())
H1 = b2v(aes_encrypt(K, bytes(16)))
pairs = [(H1, H1), (H1, b2v(A[:16])), (1 << 7, H1), (b2v(P[:16]), b2v(P[16:32]))]
check('Galoismul matches its definition', all(kl_galoismul(a, b) == galoismul_def(a, b) for a, b in pairs))
check('Galoismul identity is 1 << 7', galoismul_def(1 << 7, H1) == H1)

section('test cases: REF; KLE encrypt, decrypt, corrupted tag; GCM with Set IV')
for label, *hx in VECTORS:
    Kx, IVx, Ax, Px, Cx, Tx = map(bytes.fromhex, hx)
    check(f'REF {label}', ref_gcm(Kx, IVx, Ax, Px) == (Cx, Tx))
    c, t, cl = kl_encrypt(Kx, IVx, Ax, Px)
    check(f'encrypt {label} -> Success', (c, t, cl.state) == (Cx, Tx, SUCC))
    check(f'decrypt {label} -> Success', kl_decrypt(Kx, IVx, Ax, Cx, Tx)[:2] == (Px, SUCC))
    check(f'decrypt {label}, corrupted tag -> Failure',
          kl_decrypt(Kx, IVx, Ax, Cx, bxor(Tx, b'\x80' + bytes(15)))[1] == FAIL)
    if len(IVx) == 12:                                   # GCM with Set IV provisions only a 96-bit IV
        c, t, cl = kl_encrypt(None, None, Ax, Px, cl=Gcm.provisioned(Kx, iv=b2v(IVx)))
        check(f'Set IV {label} -> Success', (c, t, cl.state) == (Cx, Tx, SUCC))
check('key given by a SKID (GR72): tc4', kl_encrypt(None, IV, A, P, cl=Gcm.provisioned(skid=SKID))[:2] == (RC, RT))
res = []
for t in TAG_LENS:
    cl, bad = to_dtf(), to_dtf()
    cl.setst(HV, 'C', b2v(RT[:t // 8]), t)
    bad.setst(HV, 'C', b2v(RT[:t // 8]) ^ 1 << (t - 1), t)
    res.append((cl.state, bad.state))
check('_Hash_Verify_ with MSB_t(T), t = KLLEN in {128, 120, 112, 104, 96, 64} (SP 800-38D 5.2.1.2) -> Success; '
      'its last bit flipped -> Failure', True, res, [(SUCC, FAIL)] * 6)
res = []
for t in (32, 88, 8):
    cl = to_dtf()
    cl.setst(HV, 'C', b2v(RT[:t // 8]), t)
    res.append(cl.state)
check('_Hash_Verify_ with t = 32, 88 or 8 (floor 64) -> Invalid', True, res, [INV] * 3)
cl = to_etf()
check('_Enc_Tag_Finalize_ with KLLEN = 96: MSB_96(T), then Success', True,
      (v2b(cl.exec('C', 0, 96), 12), cl.state), (RT[:12], SUCC))
def wrong(where, f, *a, zklio=True):
    cl = at('enc') if where == ENC else at('ready')
    if where == SAV:
        cl.setst(SAV, 'B', 96)
    cl.zklio = zklio
    out = cl.exec(f, *a)
    return out, cl.state
check('GR66: a wrong Form (A or C in _Set_Aux_Value_, B or C in _Encrypt_) -> Invalid; GR67: without Zklio the '
      'Form D substitution is a wrong Form; with Zklio it runs as the native Form', None,
      [wrong(SAV, 'A', 0, 128), wrong(SAV, 'C', 0, 128), wrong(ENC, 'B', 0, 128), wrong(ENC, 'C', 0, 128),
       wrong(SAV, 'D', b2v(IV), 96, zklio=False)[1], wrong(SAV, 'D', b2v(IV), 96)[1]],
      [(0, INV)] * 4 + [INV, HA])
check('Form A kl.setst substituting each Form C one, input in the KLIOBUF: tc4 tag and verification; '
      'KLIOBUF bytes beyond 16 ignored (MR7); a wrong tag fails', True,
      (kl_encrypt(K, IV, A, P, subst=True)[:2], kl_decrypt(K, IV, A, RC, RT, subst=True)[:2],
       kl_decrypt(K, IV, A, RC, RT, subst=True, extra=b'\x5a' * 16)[1],
       kl_decrypt(K, IV, A, RC, bytes(16), subst=True)[1]), ((RC, RT), (P, SUCC), SUCC, FAIL))
check('kl.setst #48, #53, which the Machine does not define -> Invalid (<<KLE-instruction-setst>>)', True,
      [(raises(c.setst, i), c.state) for i in (48, 53) for c in [at('enc')]], [(False, INV)] * 2)
check('kl.setst #kl_state_success, #kl_state_failure -> Invalid (GR19, GR18), from Encrypt and from Success', True,
      [(raises(c.setst, i), c.state) for i in (SUCC, FAIL) for c in (at('enc'), at('success'))], [(False, INV)] * 4)
for n in (1, 8, 15, 21):
    check(f'{n}-byte plaintext matches REF', kl_encrypt(K, IV, A, P[:n])[:2] == ref_gcm(K, IV, A, P[:n]))

section('Set_Aux_Value (PROCESS_VLI)')
for label, *hx in VECTORS[5::6]:
    Kx, IVx, Ax, Px, Cx, Tx = map(bytes.fromhex, hx)
    for chunk, stop in ((16, None), (32, None), (60, None), (32, 1), (48, 1)):
        check(f'{label}: IV in {chunk}-byte transfers' + (', halted and resumed' if stop else ''),
              kl_encrypt(Kx, IVx, Ax, Px, iv_chunk=chunk, iv_stop=stop)[:2] == (Cx, Tx))
for n in (1, 8, 13, 16, 20, 32, 64, 1024):
    iv = bytes((7 * i + 3) & 255 for i in range(n))
    check(f'{8 * n}-bit IV matches REF', kl_encrypt(K, iv, A, P)[:2] == ref_gcm(K, iv, A, P))
cl = at('ready')
cl.setst(SAV, 'B', 96)
check('entering: len <- Xs, tag and PROCESS_VLI counters cleared',
      (cl.len, cl.tag, cl.input_base, cl.block_base, cl.cumul_len) == (96, 0, 0, 0, 0))
cl.exec('B', b2v(IV + bytes(4)), 128)
check('96-bit IV in a 128-bit transfer: excess ignored, J0 = IV || 0^31 || 1, tag = 0, start_ctr = 1',
      (cl.state, v2b(cl.J0, 16), cl.tag, cl.start_ctr) == (HA, J0B, 0, 1))
cl = at('sav')
cl.exec('B', b2v(bytes(range(16))), 128)
check('the IV is absorbed into tag; J0 untouched until finalize()',
      (cl.J0, cl.tag, cl.block_base, cl.cumul_len) == (0, kl_galoismul(b2v(bytes(range(16))), cl.auth_key), 0, 128))
bad = (0, 4, 7, 60, 100, 8193)
check(f'Xs in {bad} -> Invalid', all(at('ready').setst(SAV, 'B', x) == 0 for x in bad))
cl = at('ready')
cl.setst(SAV, 'B', 160)
cl.exec('B', b2v(bytes(range(16))), 128)
c2 = copy.copy(cl)
cl.setst(HA)
check('kl.setst Hash_Absorb part-way -> _Invalid_: Hash_Absorb needs a complete IV (MR11)', cl.state == INV)
c2.setst(READY)
check('kl.setst Ready part-way: IV discarded, no finalize(); tag, J0, len, block_base, cumul_len zero (MR9)',
      (c2.state, c2.tag, c2.J0, c2.len, c2.block_base, c2.cumul_len) == (READY, 0, 0, 0, 0, 0))
c3 = Gcm.provisioned(K)
c3.setst(SAV, 'B', 160)
c3.exec('B', b2v(bytes(range(16))), 128)
c3.setst(SAV, 'B', 8 * len(IV))
feed(c3, IV)
check('same-State kl.setst into Set_Aux_Value part-way restarts the IV with its len (GR17, MR9): tc4',
      finish(c3, A, P)[:2] == (RC, RT))
cl = at('sav')
cl.exec('B', b2v(IV60B[:16]), 128)
cl.setst(READY)
check('GR16: Set_Aux_Value -> Ready part-way; next message (tc6) unaffected',
      kl_encrypt(K, IV60B, A, P, cl=cl)[:2] == TC6)
D1, D2 = (bytes((k * i + 5) & 255 for i in range(n)) for k, n in ((11, 1025), (13, 512)))
cl = at('ready')
cl.setst(SAV, 'B', 8192)
cl.exec('B', b2v(D1), 8200, 512)
r = (cl.cumul_len, cl.block_base, cl.klstart)
cl.exec('B', b2v(D2), 4096, None, 2)
check('len = 8192; KLLEN = 8200 resumed at klstart = 512, then KLLEN = 4096 with a halt after two iterations: '
      'no halt at klstart = 31 (input_base = 248), the IV completes, J0 correct (<<KLE-process-VLI>>)', True, (r, cl.halted, cl.klstart, cl.state, v2b(cl.J0, 16)),
      ((4104, 8, 0), False, 0, HA, ref_j0(K, D1[512:] + D2[:511])))
res = []
for ks in (31, 32):
    cl = at('ready')
    cl.setst(SAV, 'B', 8192)
    cl.exec('B', b2v(D1), 8200, 512)
    cl.exec('B', b2v(D2), 4096, ks)
    res.append(cl.state)
check('the same, the second transfer forged as a resumption at klstart = 31 (not a multiple of 16) or 32 '
      '(block_base = 8): no interruption point -> _Invalid_', True, res, [INV] * 2)

res = []
for last in (ELB, DLB):
    cl = at('enc' if last == ELB else 'dec')
    cl.setst(last, 'B', 64)
    cl.exec('A', 0x1122334455667788, 64)
    snap = dict(vars(cl))
    res.append((cl.exec('A', 0, 0), vars(cl) == snap))
check('KLLEN = 0 in Enc_Last_Block / Dec_Last_Block after its kl.exec: empty window, no operation, State kept '
      '(<<KLE-GR-transfer-window-checks>>, MR10)', True, res, [(0, True)] * 2)
section('multi-block kl.exec, GR41')
for n in (2, 3):
    check(f'{n} blocks per kl.exec', kl_encrypt(K, IV, A, P, nblk=n)[:2] == (RC, RT))
cl = at('enc')
o1 = cl.exec('A', b2v(P[:48]), 384, None, 1)
h = (cl.halted, cl.klstart)
o2 = cl.exec('A', b2v(P[:48]), 384, 16)
check('GR41: Encrypt halted after one block (klstart = 16) and resumed',
      h == (True, 16) and cl.klstart == 0 and v2b(sl(o1, 127, 0) | o2 & ~MASK128, 48) == RC[:48])
cl = at('ready')
cl.setst(SAV, 'B', 96)
cl.exec('B', b2v(IV), 96)
cl.exec('B', b2v(A[:16]), 128, None, 0)
cl.exec('B', b2v(A[:16]), 128, 0)
check('klstart = 0 is an interruption point of Hash_Absorb',
      cl.tag == kl_galoismul(b2v(A[:16]), cl.auth_key) and not cl.halted)

section('decryption, last blocks, tag finalization')

cl = to_dtf()
out = cl.exec('C', 0, 128)
check('no kl.exec in Dec_Tag_Finalize: Invalid, zeros written', (cl.state, out) == (INV, 0))
cl = to_dtf()
cl.setst(HV, 'C', b2v(RT) | 0xABCD << 128)
check('MR7: Hash_Verify compares the 128 LSBs', cl.state == SUCC)
for nbits in (8, 16, 56, 96, 120):
    x = b2v(bytes(range(16))) & ((1 << nbits) - 1)
    e = at('enc')
    cf = e.exec('A', b2v(bytes(range(32))), 256)
    e.setst(ELB, 'B', nbits)
    ct = e.exec('A', x, 128)
    lb = len_block(256 + nbits, 8 * len(A))
    e.setst(ETF, 'C', lb)
    d = at('dec')
    pf = d.exec('A', cf, 256)
    d.setst(DLB, 'B', nbits)
    pt = d.exec('A', ct, 128)
    d.setst(DTF, 'C', lb)
    d.setst(HV, 'C', e.exec('C', 0, 128))
    check(f'last_block_len = {nbits}: round trip -> Success, OUTPUT clear above it (MR8)',
          (pf, pt, d.state) == (b2v(bytes(range(32))), x, SUCC) and ct >> nbits == 0)
bad = (0, 1, 7, 60, 100, 127, 128, 200)
for where, last in (('enc', ELB), ('dec', DLB)):
    check(f'{"Enc" if last == ELB else "Dec"}_Last_Block: last_block_len in {bad} -> Invalid',
          all(at(where).setst(last, 'B', n) == 0 for n in bad))
cl = at('enc')
cl.setst(ELB, 'B', 96)
first = cl.exec('A', b2v(P[:12]), 96)
check('second kl.exec in Enc_Last_Block (MR10): _Invalid_, output zeroed',
      first and cl.exec('A', b2v(P[:12]), 96) == 0 and cl.state == INV)
cl = at('dec')
cl.setst(DLB, 'B', 96)
check('second kl.exec in Dec_Last_Block (MR10): _Invalid_, output zeroed',
      cl.exec('A', b2v(P[:12]), 96) and cl.exec('A', b2v(P[:12]), 96) == 0 and cl.state == INV)
for where, last in (('enc', ELB), ('dec', DLB)):
    cl, c2 = at(where), at(where)
    cl.setst(last, 'B', 64)
    cl.setst(last, 'B', 96)
    c2.setst(last, 'B', 96)
    ok = c2.exec('A', b2v(P[:12]), 96)
    c2.setst(last, 'B', 96)
    check(f'GR17: same-State kl.setst into {"Enc" if last == ELB else "Dec"}_Last_Block -> _Invalid_, '
          'before its kl.exec and after it (MR10)', ok and (cl.state, c2.state) == (INV, INV))
for fin in (ETF, DTF):
    cl = at('enc' if fin == ETF else 'dec')
    lb = len_block(0, 8 * len(A))
    cl.setst(fin, 'C', lb)
    ok = cl.state == fin
    cl.setst(fin, 'C', lb)
    check(f'GR17: same-State kl.setst into {"Enc" if fin == ETF else "Dec"}_Tag_Finalize -> _Invalid_',
          ok and cl.state == INV)
res = []
for fin in (ETF, DTF):
    for subst in (False, True):
        cl = at('enc' if fin == ETF else 'dec')
        lb = len_block(0, 8 * len(A))
        if subst:
            cl.setst(fin, 'A/iobuf', v2b(lb, 16)[:8])
        else:
            cl.setst(fin, 'C', lb & (1 << 64) - 1, klen=64)
        res.append(cl.state)
check('kl.setst into Enc_Tag_Finalize or Dec_Tag_Finalize with KLLEN = 64, Form C or the Form A substitution with '
      '8 KLIOBUF bytes -> Invalid (MR7)', True, res, [INV] * 4)
cl = at('enc')
cl.setst(ELB, 'B', 96)
check('Enc_Last_Block with KLLEN = 256: one block, excess ignored (MR3, MR8)',
      cl.exec('A', b2v(P[:12] + bytes(range(1, 21))), 256) == first)
cl = at('enc')
crypt(cl, P, 3)
cl.setst(ETF, 'C', len_block(8 * len(P), 8 * len(A)) | 0x5A << 128)
check('Enc_Tag_Finalize: 128 LSBs of a 256-bit INPUT; tag emitted with KLLEN = 256',
      (cl.exec('C', 0, 256), cl.state) == (b2v(RT), SUCC))
res = []
for kl in (8, 32, 40, 72, 100, 64, 96, 120):
    c = to_etf()
    res.append((c.exec('C', 0, kl), c.state))
check('Enc_Tag_Finalize: a KLLEN below 128 other than 120, 112, 104, 96, 64 -> Invalid, nothing emitted (MR2); '
      '64, 96 and 120 emit MSB_t(T)', True, res,
      [(0, INV)] * 5 + [(b2v(RT) & ((1 << kl) - 1), SUCC) for kl in (64, 96, 120)])

c48, t48 = ref_gcm(K, IV, A, P[:48])
e, d = at('enc'), at('dec')
e.exec('A', b2v(P[:48]), 384)
d.exec('A', b2v(c48), 384)
for cl, last, fin in ((e, ELB, ETF), (d, DLB, DTF)):
    cl.setst(last, 'B', 96)
    cl.setst(fin, 'C', len_block(384, 8 * len(A)))     # leaves the last-block State before its kl.exec
d.setst(HV, 'C', b2v(t48))
check('a kl.setst that leaves Enc_Last_Block or Dec_Last_Block before its kl.exec omits the final block: '
      'tag and verification of the 48 whole bytes', (v2b(e.exec('C', 0, 128), 16), d.state) == (t48, SUCC))

section('counter: Invalid when ctr reaches (start_ctr - 1) mod 2^32')

def fresh(iv):
    cl = Gcm.provisioned(K)
    cl.setst(SAV, 'B', 8 * len(iv))
    feed(cl, iv)
    return cl

check('96-bit IV: start_ctr = 1 (at most 2^32 - 2 blocks)', fresh(IV).start_ctr == 1)
for iv in (IV, bytes.fromhex(IV8)):
    for path in (ENC, DEC):
        states = []
        for nb in (2, 3):
            cl = fresh(iv)
            seed(cl, cl.start_ctr - 4)
            cl.setst(path)
            for _ in range(nb):
                cl.exec('A', 0, 128)
            states.append(cl.state)
        check(f'{8 * len(iv)}-bit IV, {"Encrypt" if path == ENC else "Decrypt"}: '
              f'two blocks before the limit pass, the next -> Invalid', states == [path, INV])
    cl = fresh(iv)
    seed(cl, cl.start_ctr - 2)
    cl.setst(ENC)
    cl.setst(ELB, 'B', 8)
    cl.exec('A', 0x55, 8)
    check(f'{8 * len(iv)}-bit IV: Enc_Last_Block at the limit -> Invalid', cl.state == INV)
cl, ref = fresh(IV), fresh(IV)
for c in (cl, ref):
    seed(c, -3)
    c.setst(ENC)
want = ref.exec('A', b2v(P[:32]), 256)
check('GR41/GR28: limit hit at block 3 of 4: prefix kept, rest zeroed, Invalid',
      cl.exec('A', b2v(P[:48] + bytes(16)), 512) == want and cl.state == INV)
check('GR29: the invalidated locker keeps only its MDH',
      cl.export() == (0, 0) and (cl.key, cl.tag, cl.J0) == (b'', 0, 0))

section('GCM with Set IV')
pi, n = Gcm.pi(K, b2v(IV))
check('PI Content: key, then the 96-bit IV; 224 bits padded to 256 for k = 128', n == 256 and v2b(pi, 32) == K + IV + bytes(4))
pi, n = Gcm.pi(iv=b2v(IV), skid=SKID)
check('PI Content with a SKID: 64 + 96 bits, padded to 256', n == 256 and sl(pi, 159, 64) == b2v(IV))
cl = Gcm.provisioned(K, iv=b2v(IV))
check('provisioning forms J0 = IV || 0^31 || 1 (SP 800-38D 7.1) and start_ctr = 1', (v2b(cl.J0, 16), cl.start_ctr) == (J0B, 1))
H0 = aes_encrypt(K, bytes(16))
dec = Gcm.provisioned(K, iv=0, policy=2)
dec.setst(HA)
dec.setst(DEC)
ks = v2b(dec.exec('A', 0, 128), 16)
check('decrypt-only Set IV locker, IV = 0: the first keystream block is E(K, 0^96 || 2), not H = E(K, 0)', True,
      (ks != H0, ks == aes_encrypt(K, bytes(12) + bytes([0, 0, 0, 2]))), (True, True))
cl = at('setiv')
cl.setst(HA)
cl.setst(ENC)
for _ in range(40):
    cl.exec('A', 0, 1024)
check('no block budget: 320 blocks in 40 kl.exec', cl.state == ENC and cl._bs(sl(cl.J0, 127, 96)) == 321)
cl = at('setiv')
c1 = kl_encrypt(None, None, A, P, cl=cl)[:2]
cl.setst(READY)
back = (cl.state, cl.export()) == (READY, at('setiv').export())
c2 = kl_encrypt(None, None, A, P, cl=cl)[:2]
check('GR16: Success -> Ready restores the provisioned J0: the Content of a fresh provisioning',
      back and c1 == (RC, RT))
check('after Ready the next message repeats the provisioned GCM invocation: tc4', c2 == (RC, RT))
cl = at('setiv')
cl.setst(HA)
cl.setst(ENC)
cl.exec('A', b2v(P[:32]), 256)
cl.setst(READY)
check('GR16: Encrypt -> Ready mid-message; the next message is tc4',
      kl_encrypt(None, None, A, P, cl=cl)[:2] == (RC, RT))
_, st1, cl = kl_decrypt(None, None, A, RC, bytes(16), cl=at('setiv'))
cl.setst(READY)
p2, st2, _ = kl_decrypt(None, None, A, RC, RT, cl=cl)
check('Failure -> Ready; the same Set IV locker decrypts and verifies tc4', (st1, st2, p2) == (FAIL, SUCC, P))
P2 = bytes(range(len(P)))
cl = at('setiv')
c1 = kl_encrypt(None, None, A, P, cl=cl)[0]
cl.setst(READY)
c2 = kl_encrypt(None, None, A, P2, cl=cl)[0]
check('another message after Ready reuses the keystream: C1 xor C2 = P1 xor P2 (<<KLE-MGR-caller-limits>>)',
      bxor(c1, c2) == bxor(P, P2))
states = []
for c0 in (2**32 - 2, 2**32 - 1):
    cl = at('setiv')
    seed(cl, c0)
    cl.setst(HA)
    cl.setst(ENC)
    cl.exec('A', 0, 128)
    states.append(cl.state)
check('Set IV: counter rule applies (ctr wrapping to start_ctr - 1 = 0 -> Invalid)', states == [ENC, INV])

section('general rules')
B16 = b2v(P[:16])
for name, where, ops, *kw in [
        ('MR1: same-State kl.setst into Set_Aux_Value in Form A (Form B required)', 'sav', [('setst', SAV, 'A', 0)]),
        ('MR2: short IV transfer that is not the last', 'sav', [('exec', 'B', 0, 96)]),
        ('MR1: Form A kl.exec in Set_Aux_Value', 'sav', [('exec', 'A', 0, 128)]),
        ('resume at klstart = 5 in Set_Aux_Value', 'sav', [('exec', 'B', 0, 256, 5)]),
        ('resume at klstart = 8 in Encrypt', 'enc', [('exec', 'A', 0, 384, 8)]),
        ('KLLEN (96) < last_block_len (104)', 'enc', [('setst', ELB, 'B', 104), ('exec', 'A', 0, 96)]),
        ('GR17: kl.exec in Ready', 'ready', [('exec', 'A', B16, 128)]),
        ('GR16: kl.exec in Success', 'success', [('exec', 'A', 0, 128)]),
        ('GR16: kl.setst Encrypt in Success', 'success', [('setst', ENC)]),
        ('MR1: GCM Ready -> Hash_Absorb', 'ready', [('setst', HA)]),
        ('MR1: Form A kl.exec in Hash_Absorb', 'ha', [('exec', 'A', B16, 128)]),
        ('MR1: Form B kl.setst to Encrypt', 'ha', [('setst', ENC, 'B', 5)]),
        ('MR1: Form B kl.setst to Enc_Tag_Finalize', 'enc', [('setst', ETF, 'B', 5)]),
        ('MR1: Encrypt -> Hash_Verify', 'enc', [('setst', HV, 'C', 0)]),
        ('MR1: Decrypt -> Enc_Last_Block', 'dec', [('setst', ELB, 'B', 8)]),
        ('MR2: KLLEN = 120 in Hash_Absorb', 'ha', [('exec', 'B', B16, 120)]),
        ('MR2: KLLEN = 120 in Encrypt', 'enc', [('exec', 'A', B16, 120)]),
        ('MR2: KLLEN = 120 in Decrypt', 'dec', [('exec', 'A', B16, 120)]),
        ('MachinePolicy decrypt-only: -> Encrypt', 'ha', [('setst', ENC)], {'policy': 2}),
        ('MachinePolicy encrypt-only: -> Decrypt', 'ha', [('setst', DEC)], {'policy': 1}),
        ('Set IV: Form C kl.setst to Hash_Absorb', 'setiv', [('setst', HA, 'C', 0)]),
        ('Set IV: no Set_Aux_Value', 'setiv', [('setst', SAV, 'B', 96)])]:
    cl = at(where, **(kw[0] if kw else {}))
    outs = [getattr(cl, op)(*a) for op, *a in ops]
    check(f'{name} -> Invalid, no output', cl.state == INV and not any(outs))
cl = at('ready')
cl.setst(SAV, 'B', 400)
cl.exec('B', 0, 128)
cl.exec('B', 0, 392, 16)                                 # 128 + 392 >= 400: admitted, block_base = 8
bb = cl.block_base
cl.exec('B', 0, 256, 16)
check('Set_Aux_Value with block_base != 0: klstart = 16 is no interruption point (<<KLE-process-VLI>>) -> Invalid',
      True, (bb, cl.state), (8, INV))
cls = [at(w) for w in ('enc', 'dec', 'enc', 'dec')]
check('a Form B or C kl.exec where Form A is native (Encrypt, Decrypt): a wrong Form, _Invalid_ (GR66, MR1)',
      True, ([c.exec(f, B16, 128) for c, f in zip(cls, 'BBCC')], [c.state for c in cls]), ([0] * 4, [INV] * 4))
cl = at('enc')
snap = dict(vars(cl))
check('klstart >= KLLEN/8 in Encrypt (16 of 128, 64 of 384): empty window, only klstart = 0',
      [(cl.exec('A', B16, kl, ks), vars(cl) == snap) for kl, ks in ((128, 16), (384, 64))] == [(0, True)] * 2)
check('KLLEN = 120, klstart = 15 in Encrypt: invalid length first, Invalid', (cl.exec('A', B16, 120, 15), cl.state)
      == (0, INV))
cl = at('success')
cl.setst(READY)
check('GR16: Success -> Ready; the same locker reproduces tc5',
      kl_encrypt(K, bytes.fromhex(IV8), A, P, cl=cl)[:2] == TC5)
_, st1, cl = kl_decrypt(K, IV, A, RC, bytes(16))
cl.setst(READY)
p2, st2, _ = kl_decrypt(K, IV, A, RC, RT, cl=cl)
check('Failure -> Ready; the same locker decrypts and verifies', (st1, st2, p2) == (FAIL, SUCC, P))
cl = at('enc')
cl.exec('A', B16, 128)
cl.setst(READY)
check('GR16: Encrypt -> Ready mid-message; next message unaffected',
      kl_encrypt(K, IV, A, P, cl=cl)[:2] == (RC, RT))
cl, c2 = at('ha'), at('enc')
cl.setst(HA)
c2.setst(ENC)
check('GR17: same-State kl.setst in Hash_Absorb and Encrypt -> _Invalid_', (cl.state, c2.state) == (INV, INV))
check('MachinePolicy decrypt-only: decryption works', kl_decrypt(K, IV, A, RC, RT, policy=2)[1] == SUCC)
cl = at('enc')
cl.setst(PRIV)
s1, out = cl.state, cl.exec('A', B16, 128)
cl.setst(READY)
s2 = cl.state
cl.setst(INV)
check('Error State immediate accepted; kl.exec and kl.setst Ready then do nothing; '
      'another Error State accepted (GR30, GR26)', (s1, s2, out, cl.state) == (PRIV, PRIV, 0, INV))

section('Serialized Content, export/import (MR4)')
for k, skid, nblk in ((16, None, 4), (24, None, 4), (32, None, 5), (16, SKID, 3)):
    kb = 64 if skid else 8 * k
    check(f'Content for {"a SKID" if skid else f"k = {8 * k}"}: {kb} + 304 bits, {nblk} blocks',
          Gcm.provisioned(None if skid else bytes(k), skid=skid).export()[1] == 128 * nblk == pad128(kb + 304))
cl = at('enc')
cl.exec('A', B16, 128)
v = cl.export()[0]
check('layout: key, J0, tag, bin(start_ctr,32), last_block_len',
      (sl(v, 127, 0), sl(v, 255, 128), sl(v, 383, 256), sl(v, 415, 384), sl(v, 431, 416), v >> 432)
      == (b2v(K), cl.J0, cl.tag, 1, 0, 0))
bad = v & ~(((1 << 32) - 1) << 384)              # start_ctr (bits 384-415) = 0 in the Content
check('Set IV: an import whose start_ctr is not 1 -> Invalid (MR13); with 1, Encrypt', True,
      (Gcm.imported(ENC, bad, 128, set_iv=True).state, Gcm.imported(ENC, v, 128, set_iv=True).state), (INV, ENC))
c2 = Gcm.imported(ENC, v, 128)
ct = crypt(c2, P[16:], 2)
c2.setst(ETF, 'C', len_block(8 * len(P), 8 * len(A)))
check('export in Encrypt, import (auth_key recomputed): tc4 completes',
      (ct, v2b(c2.exec('C', 0, 128), 16)) == (RC[16:], RT))
cl = at('sav')
cl.exec('B', b2v(IV60B[:32]), 256)
v, n = cl.export()
check("Set_Aux_Value overlay in J0's slot: len, padding, block_base, cumul_len, padding; hash in tag",
      (sl(v, 143, 128), sl(v, 159, 144), sl(v, 175, 160), sl(v, 223, 176), sl(v, 255, 224), sl(v, 383, 256), n)
      == (480, 0, 0, 256, 0, cl.tag, 512))
res = {}
for ctl in (False, True):
    for mid in (16, 32, 48):
        cl = Gcm.provisioned(K, iv_into_J0=ctl)
        cl.setst(SAV, 'B', 480)
        feed(cl, IV60B[:mid])
        c2 = Gcm.imported(SAV, cl.export()[0], 128, iv_into_J0=ctl)
        feed(c2, IV60B[mid:])
        res[ctl, mid] = finish(c2, A, P)[:2] == TC6
for mid in (16, 32, 48):
    check(f'export in Set_Aux_Value after {mid} of 60 IV bytes, import, resume: tc6', res[False, mid])

section('kl.derive (<<KLE-derive-endpoints>>, GR32, GR72, GR31; MR4)')
stale = []
for k, n in ((16, 16), (16, 32), (32, 32)):
    for ctl in (False, True):
        cl = Gcm.provisioned(bytes(range(k)), stale_auth_key=ctl)
        cl.derive(SRC, n)
        c, t, cl = kl_encrypt(None, IV, A, P, cl=cl)
        ok = (c, t, cl.state) == ref_gcm(SRC[:k], IV, A, P) + (SUCC,)
        if ctl:
            stale.append(ok)
        else:
            check(f'k = {8 * k}: {n} bytes into `key` in Ready, auth_key re-derived; message matches REF', ok)

for iv, n in ((IV60B, 60), (IV60B, 32), (IV, 12), (IV60B, 20), (IV60B, 0)):
    cl = at('ready')
    cl.setst(SAV, 'B', 8 * len(iv))
    cl.derive(iv, n)
    check(f'kl.derive of {n} of {len(iv)} IV bytes into Set_Aux_Value (no destination, GR32 item 2) -> Invalid', (cl.state, cl.cumul_len) == (INV, 0))
cl = Gcm.provisioned(bytes(16), iv=b2v(IV))
cl.derive(SRC, 16)
check('GCM with Set IV is not a kl.derive destination (<<KLE-GCM-with-IV-mode>>, GR32 item 2) -> Invalid',
      cl.state == INV)
for name, cl, n in (('in Hash_Absorb (GR32 item 2)', at('ha'), 16),
                    ('in Success (GR32 item 2)', at('success'), 16),
                    ('into a key configured by a SKID (GR72, GR32 item 2)', Gcm.provisioned(skid=SKID), 16),
                    ('of 8 bytes into a 128-bit key (GR32 item 5)', at('ready'), 8),
                    ('of 16 bytes into a 256-bit key (GR32 item 5)', Gcm.provisioned(bytes(32)), 16),
                    ('of 0 bytes into a key (GR32 item 5)', at('ready'), 0)):
    cl.derive(SRC, n)
    check(f'kl.derive {name} -> Invalid, no key written', (cl.state, cl.key) == (INV, b''))
src, dst = to_etf(), at('ready')
key0 = dst.key
dst.derive(src, 16)
check('the tag in Enc_Tag_Finalize as a source (none, GR32 item 1) into a 128-bit `key` -> only the source '
      'Invalid, the key kept', True, (src.state, dst.state, dst.key), (INV, READY, key0))
src, d1 = to_etf(), at('ready')
d1.setst(SAV, 'B', 128)
d1.derive(src, 16)
check('the tag in Enc_Tag_Finalize into the IV of another GCM: GR32 item 1 fails first -> only the source Invalid, '
      'nothing absorbed', True, (src.state, d1.state, d1.cumul_len), (INV, SAV, 0))

section('negative controls')
sw, le = [], []
for label, *hx in VECTORS:
    Kx, IVx, Ax, Px, Cx, Tx = map(bytes.fromhex, hx)
    if len(Ax) != len(Px):
        sw.append(kl_encrypt(Kx, IVx, Ax, Px, swap=True)[:2] != (Cx, Tx))
    if Px:
        le.append(kl_encrypt(Kx, IVx, Ax, Px, le_counter=True)[:2] != (Cx, Tx))
control(f'length block halves swapped ({len(sw)} vectors)', len(sw) >= 4 and all(sw))
control(f'little-endian counter ({len(le)} vectors)', len(le) >= 4 and all(le))
control('IV accumulated in J0, export/import in Set_Aux_Value', not any(res[True, m] for m in (16, 32, 48)))
control('auth_key not re-derived after kl.derive into `key`', not any(stale))
cl = at('setiv', ready_keeps_ctr=True)
kl_encrypt(None, None, A, P, cl=cl)
cl.setst(READY)
control('Set IV: Ready keeps the running counter', kl_encrypt(None, None, A, P, cl=cl)[:2] != (RC, RT))

section('MachinePolicy narrowing (GR20, MR11): the Gated States')
cl = to_etf()
cl.restrictl(1)
st0 = cl.state
cl.exec('C', 0, 128)
cl2 = to_dtf()
cl2.restrictl(2)
cl2.setst(HV, 'C', b2v(RT))
cl3 = at('ready')
cl3.setst(SAV, 'B', 8 * len(IV))
feed(cl3, IV)
cl3.restrictl(2)
ct, tag, _ = finish(cl3, A, P)
check('narrowing to encrypt-off in _Enc_Tag_Finalize_ keeps the State, the next kl.exec -> _Invalid_; '
      'decrypt-off in _Dec_Tag_Finalize_: kl.setst _Hash_Verify_ -> _Invalid_; decrypt-off in _Hash_Absorb_: '
      'encryption completes with the reference tag', (st0, cl.state, cl2.state, ct, tag) == (ETF, INV, INV, RC, RT))

done()
