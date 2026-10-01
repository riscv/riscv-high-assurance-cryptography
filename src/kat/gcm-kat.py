#!/usr/bin/env python3
"""GCM and GCM with Set IV (<<KLEE-GCM-mode>>, <<KLEE-GCM-with-IV-mode>>) through a model locker,
against McGrew-Viega / SP 800-38D test cases 1-6 and 13-18 and a byte-string SP 800-38D reference."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bswap, bxor, MASK128, aes_encrypt, gmul_ghash, kl_galoismul,
                    selftest, ERROR_STATES, section, check, control, info, spec_note, done,
                    KL_STATE_UNCONFIGURED as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_HASH_ABSORB as HA, KL_STATE_HASH_VERIFY as HV,
                    KL_STATE_ENCRYPT as ENC, KL_STATE_DECRYPT as DEC,
                    KL_STATE_ENC_LAST_BLOCK as ELB, KL_STATE_DEC_LAST_BLOCK as DLB,
                    KL_STATE_ENC_TAG_FINALIZE as ETF, KL_STATE_DEC_TAG_FINALIZE as DTF,
                    KL_STATE_SET_AUX_VALUE as SAV, KL_STATE_SUCCESS as SUCC,
                    KL_STATE_FAILURE as FAIL, KL_STATE_INVALID as INV,
                    KL_STATE_PRIV_VIOLATION as PRIV)

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

def ref_gcm(K, IV, A, P, J0=None, icb=None):
    J0 = J0 or ref_j0(K, IV)
    cb, C = icb or inc32(J0), b''
    for i in range(0, len(P), 16):
        C, cb = C + bxor(P[i:i + 16], aes_encrypt(K, cb)), inc32(cb)
    S = ghash(aes_encrypt(K, bytes(16)), pad16(A) + pad16(C) + be64(8 * len(A)) + be64(8 * len(C)))
    return C, bxor(S, aes_encrypt(K, J0))

def galoismul_def(a, b):
    """<<KLEE-GCM-mode>>: V represents sum of V[8i+(7-j)] x^(8i+j) mod x^128+x^7+x^2+x+1."""
    def poly(V): return sum(1 << (8 * i + j) for i in range(16) for j in range(8) if V >> (8 * i + 7 - j) & 1)
    pa, pb, r = poly(a), poly(b), 0
    while pb:
        r, pa, pb = r ^ (pa if pb & 1 else 0), pa << 1, pb >> 1
    for d in range(254, 127, -1):
        if r >> d & 1:
            r ^= (1 << d) | (0x87 << (d - 128))
    return poly(r)          # the representation map is an involution

# ---------------------------------------------------------------- KLEE model
SKID = 0x0123456789ABCDEF
SKS = {SKID: bytes.fromhex('feffe9928665731c6d6a8f9467308308')}

class Gcm:
    """A GCM (set_iv False) or GCM with Set IV locker; MDH reduced to State, MachinePolicy
    (bit 0 encrypt, bit 1 decrypt), KeyType.  le_counter, iv_into_J0, stale_auth_key: controls."""

    def __init__(s, set_iv=False, policy=3, le_counter=False, iv_into_J0=False, stale_auth_key=False):
        s.set_iv, s.policy, s.le, s.stale = set_iv, policy, le_counter, stale_auth_key
        s.acc = 'J0' if iv_into_J0 else 'tag'
        s.klstart, s.halted = 0, False
        s._error(UNCONF)

    def _error(s, st):                                   # SGR10
        s.state, s.key, s.k, s.key_type, s.skid = st, b'', 0, 0, 0
        s.J0 = s.auth_key = s.tag = s.start_ctr = s.last_blk_len = 0
        s.len = s.input_base = s.block_base = s.cumul_len = 0
        return 0

    def _invalid(s): return s._error(INV)

    def _load_key(s, v, k, key_type):                    # key or SKID (MGR9)
        s.k, s.key_type = k, key_type
        kb = 64 if key_type else k
        f = sl(v, kb - 1, 0)
        s.skid, s.key = (f, SKS[f]) if key_type else (0, v2b(f, k // 8))
        return kb

    @staticmethod
    def pi(key=None, J0=None, skid=None):
        v, n = (skid, 64) if skid is not None else (b2v(key), 8 * len(key))
        if J0 is not None:
            v, n = v | J0 << n, n + 128
        return v, pad128(n)

    @classmethod
    def provisioned(cls, key=None, J0=None, skid=None, **kw):
        s = cls(set_iv=J0 is not None, **kw)
        v = cls.pi(key, J0, skid)[0]
        kb = s._load_key(v, 8 * len(SKS[skid] if skid else key), int(skid is not None))
        if s.set_iv:
            s.J0 = sl(v, kb + 127, kb)
            s.start_ctr = s._bs(sl(s.J0, 127, 96))       # "Upon provisioning"
        s.state = READY
        s._ready()
        return s

    def export(s):
        if s.state in ERROR_STATES:
            return 0, 0                                  # SGR11
        kb = 64 if s.key_type else s.k
        slot = (cat((s.cumul_len, 48), (s.block_base, 16), (0, 16), (s.len, 16))   # ii.b padding, ii.e J0_padding
                if s.state == SAV else s.J0)
        return (cat((s.last_blk_len, 16), (s.start_ctr, 32), (s.tag, 128), (slot, 128),
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
        s.tag, s.start_ctr, s.last_blk_len = (
            sl(v, kb + 255, kb + 128), sl(v, kb + 287, kb + 256), sl(v, kb + 303, kb + 288))
        s.state = state
        if not s.stale:
            s.auth_key = s._enc(0)                       # MGR4
        return s

    def _ready(s):
        s.auth_key, s.tag = s._enc(0), 0

    def _enc(s, p): return b2v(aes_encrypt(s.key, v2b(p, 16)))
    def _absorb(s, d): s.tag = kl_galoismul(s.tag ^ d, s.auth_key)
    def _bs(s, x): return x if s.le else bswap(x, 4)    # int(bswap(.)) / bswap(bin(., 32))
    def _set_ctr(s, ctr): s.J0 = cat((s._bs(ctr), 32), (sl(s.J0, 95, 0), 96))

    def _next_ctr(s):
        ctr = (s._bs(sl(s.J0, 127, 96)) + 1) % 2**32
        return None if ctr == (s.start_ctr - 1) % 2**32 else ctr

    def _form(s, st, immed):
        """kl.setst Form of each listed transition; None if not listed (MGR1)."""
        t = {(HA, HA): 'A', (HA, ENC): 'A', (HA, DEC): 'A', (ENC, ENC): 'A', (DEC, DEC): 'A',
             (DTF, HV): 'C'}
        for c, l, f in ((ENC, ELB, ETF), (DEC, DLB, DTF)):
            t.update({(c, l): 'B', (l, l): 'B', (c, f): 'C', (l, f): 'C', (f, f): 'C'})
        if s.set_iv:
            t[READY, HA] = 'A'
        else:
            t.update({(READY, SAV): 'B', (SAV, HA): 'A'})
        return t.get((st, immed))

    def setst(s, immed, form='A', aux=0):
        st = s.state
        if immed in ERROR_STATES:                        # <<KLEE-instruction-setst>>, SGR15
            return s._error(immed if immed < 54 else INV)
        if st in ERROR_STATES:
            return                                       # SGR16
        if immed == READY and form == 'A':               # SGR6, SGR8
            if st == SAV:
                s._finalize()                            # process_VLI: finalize() before leaving
            s.state = READY
            return s._ready()
        if st in (SUCC, FAIL) or s._form(st, immed) != form:
            return s._invalid()                          # SGR5/SGR6, MGR1
        if immed in (ENC, DEC) and not s.policy & (1 if immed == ENC else 2):
            return s._invalid()
        if immed == SAV:
            if not (8 <= aux <= 8192 and aux % 8 == 0):
                return s._invalid()
            s.len, s.tag, s.input_base, s.block_base, s.cumul_len = aux, 0, 0, 0, 0
            if s.acc == 'J0':
                s.J0 = 0
        elif immed in (ELB, DLB):
            if not (0 < aux < 128 and aux % 8 == 0):
                return s._invalid()
            s.last_blk_len = aux
        elif immed in (ETF, DTF):
            s._absorb(aux & MASK128)
            s.tag ^= s._enc(cat((s._bs(s.start_ctr), 32), (sl(s.J0, 95, 0), 96)))
        elif immed == HV:
            immed = SUCC if aux & MASK128 == s.tag else FAIL
        elif st == SAV:
            return s._finalize()
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
            return 0                                     # SGR16
        if {SAV: 'B', HA: 'B', ENC: 'A', DEC: 'A', ELB: 'A', DLB: 'A', ETF: 'C'}.get(s.state) != form:
            return s._invalid()                          # SGR2, SGR5, MGR1
        if (KLLEN % 128 and s.cumul_len + KLLEN < s.len if s.state == SAV else
                KLLEN < s.last_blk_len if s.state in (ELB, DLB) else s.state != ETF and KLLEN % 128):
            return s._invalid()                          # MGR2, <<KLEE-truncation-vs-length>>: length first
        if start is not None:
            s.klstart = start
            if 8 * start >= KLLEN:
                s.klstart = 0                            # empty window: only klstart = 0 (<<KLEE-CSR-klstart>>)
                return 0
            if start % 16 or start and s.state in (ELB, DLB, ETF):
                return s._invalid()                      # not an interruption point
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
                s.klstart, s.halted = 16 * i, True       # IRR7
                return out
            blk = sl(INPUT, 128 * i + 127, 128 * i)
            if st == HA:
                s._absorb(blk)
                continue
            ctr = s._next_ctr()
            if ctr is None:
                s._invalid()
                return out                               # IRR6
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
        lbl = s.last_blk_len
        if lbl == 0:
            return 0
        ctr = s._next_ctr()
        if ctr is None:
            return s._invalid()
        s._set_ctr(ctr)
        m = (1 << lbl) - 1
        x, o = INPUT & m, (INPUT ^ s._enc(s.J0)) & m
        s._absorb(o if s.state == ELB else x)
        s.last_blk_len = 0
        return o

    def _exec_vli(s, INPUT, KLLEN, resuming, stop):
        """process_VLI(len, tag, b, tag, b, input_base, block_base, 0, cumul_len, ..., xor_accumulate, b)."""
        if KLLEN % 128 and s.cumul_len + KLLEN < s.len:
            return s._invalid()                          # MGR2: granularity b (kl.derive)
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
            if stop is not None and it == stop and s.input_base < KLLEN:
                s.klstart, s.halted = s.input_base // 8, True
                return 0
        s.klstart = 0
        return 0

    def derive(s, src, length):
        """kl.derive destination (<<KLEE-derive-endpoints>>): `key` in Ready (DER5/DER7 source), the IV
        (`kl.exec` input) in Set_Aux_Value."""
        if s.state in ERROR_STATES or isinstance(src, Gcm) and src.state in ERROR_STATES:
            return                                       # SGR19
        if isinstance(src, Gcm):                         # DER1 item 1: no source endpoint (the tag is none, DER6)
            return src._invalid()
        if s.state == SAV:                               # DER8: consumed as a Form B kl.exec would be
            return s._exec_vli(b2v(src[:length]), 8 * length, False, None) if length else None
        if s.key_type == 1 or s.state != READY or length < s.k // 8:
            return s._invalid()                          # DER4 (DER1 item 2); DER1 items 2, 5
        s.key = src[:s.k // 8]
        if not s.stale:
            s.auth_key = s._enc(0)                       # MGR4

# ---------------------------------------------------------------- drivers (<<KLEE-pseudocode-GCM-encryption>>)
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

def finish(cl, ad, pt, nblk=1, swap=False):
    feed(cl, pad16(ad), 4096)
    cl.setst(ENC)
    ct = crypt(cl, pt, nblk)
    cl.setst(ETF, 'C', len_block(8 * len(pt), 8 * len(ad), swap))
    return ct, v2b(cl.exec('C', 0, 128), 16), cl

def kl_encrypt(key, iv, ad, pt, cl=None, iv_chunk=16, iv_stop=None, nblk=1, swap=False, **kw):
    cl = cl or Gcm.provisioned(key, **kw)
    if cl.set_iv:
        cl.setst(HA)
    else:
        cl.setst(SAV, 'B', 8 * len(iv))
        feed(cl, iv, iv_chunk, iv_stop)
    return finish(cl, ad, pt, nblk, swap)

def kl_decrypt(key, iv, ad, ct, tag, cl=None, **kw):
    cl = cl or Gcm.provisioned(key, **kw)
    cl.setst(SAV, 'B', 8 * len(iv))
    feed(cl, iv)
    feed(cl, pad16(ad), 4096)
    cl.setst(DEC)
    pt = crypt(cl, ct, max(1, len(ct) // 16), DLB)
    cl.setst(DTF, 'C', len_block(8 * len(ct), 8 * len(ad)))
    cl.setst(HV, 'C', b2v(tag))
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
        return Gcm.provisioned(K, J0=b2v(J0B), **kw)
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

section('test cases: REF; KLEE encrypt, decrypt, corrupted tag; GCM with Set IV')
for label, *hx in VECTORS:
    Kx, IVx, Ax, Px, Cx, Tx = map(bytes.fromhex, hx)
    check(f'REF {label}', ref_gcm(Kx, IVx, Ax, Px) == (Cx, Tx))
    c, t, cl = kl_encrypt(Kx, IVx, Ax, Px)
    check(f'encrypt {label} -> Success', (c, t, cl.state) == (Cx, Tx, SUCC))
    check(f'decrypt {label} -> Success', kl_decrypt(Kx, IVx, Ax, Cx, Tx)[:2] == (Px, SUCC))
    check(f'decrypt {label}, corrupted tag -> Failure',
          kl_decrypt(Kx, IVx, Ax, Cx, bxor(Tx, b'\x80' + bytes(15)))[1] == FAIL)
    c, t, cl = kl_encrypt(None, None, Ax, Px, cl=Gcm.provisioned(Kx, J0=b2v(ref_j0(Kx, IVx))))
    check(f'Set IV {label} -> Success', (c, t, cl.state) == (Cx, Tx, SUCC))
check('key given by a SKID (MGR9): tc4', kl_encrypt(None, IV, A, P, cl=Gcm.provisioned(skid=SKID))[:2] == (RC, RT))
for n in (1, 8, 15, 21):
    check(f'{n}-byte plaintext matches REF', kl_encrypt(K, IV, A, P[:n])[:2] == ref_gcm(K, IV, A, P[:n]))

section('Set_Aux_Value (process_VLI)')
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
check('entering: len <- Xs, tag and process_VLI counters cleared',
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
cl.setst(HA)
check('kl.setst Hash_Absorb part-way runs finalize() on the IV absorbed so far', cl.state == HA and
      v2b(cl.J0, 16) == ghash(aes_encrypt(K, bytes(16)), bytes(range(16)) + bytes(8) + be64(160)))
cl = at('sav')
cl.exec('B', b2v(IV60B[:16]), 128)
cl.setst(READY)
check('SGR8: Set_Aux_Value -> Ready part-way; next message (tc6) unaffected',
      kl_encrypt(K, IV60B, A, P, cl=cl)[:2] == TC6)
info('Set_Aux_Value: a transfer not a multiple of b is admitted only if it reaches len (MGR2); '
     'kl.setst out of the state runs finalize() first')

section('multi-block kl.exec, IRR6/IRR7')
for n in (2, 3):
    check(f'{n} blocks per kl.exec', kl_encrypt(K, IV, A, P, nblk=n)[:2] == (RC, RT))
cl = at('enc')
o1 = cl.exec('A', b2v(P[:48]), 384, None, 1)
h = (cl.halted, cl.klstart)
o2 = cl.exec('A', b2v(P[:48]), 384, 16)
check('IRR7: Encrypt halted after one block (klstart = 16) and resumed',
      h == (True, 16) and cl.klstart == 0 and v2b(sl(o1, 127, 0) | o2 & ~MASK128, 48) == RC[:48])
cl = at('ready')
cl.setst(SAV, 'B', 96)
cl.exec('B', b2v(IV), 96)
cl.exec('B', b2v(A[:16]), 128, None, 0)
cl.exec('B', b2v(A[:16]), 128, 0)
check('klstart = 0 is an interruption point of Hash_Absorb',
      cl.tag == kl_galoismul(b2v(A[:16]), cl.auth_key) and not cl.halted)

section('decryption, last blocks, tag finalization')

def to_dtf():
    cl = at('dec')
    crypt(cl, RC, 3, DLB)
    cl.setst(DTF, 'C', len_block(8 * len(RC), 8 * len(A)))
    return cl

cl = to_dtf()
out = cl.exec('C', 0, 128)
check('no kl.exec in Dec_Tag_Finalize: Invalid, zeros written', (cl.state, out) == (INV, 0))
cl = to_dtf()
cl.setst(HV, 'C', b2v(RT) | 0xABCD << 128)
check('MGR5: Hash_Verify compares the 128 LSBs', cl.state == SUCC)
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
    check(f'last_blk_len = {nbits}: round trip -> Success, OUTPUT clear above it (MGR6)',
          (pf, pt, d.state) == (b2v(bytes(range(32))), x, SUCC) and ct >> nbits == 0)
bad = (0, 1, 7, 60, 100, 127, 128, 200)
for where, last in (('enc', ELB), ('dec', DLB)):
    check(f'{"Enc" if last == ELB else "Dec"}_Last_Block: last_blk_len in {bad} -> Invalid',
          all(at(where).setst(last, 'B', n) == 0 for n in bad))
cl = at('enc')
cl.setst(ELB, 'B', 96)
first = cl.exec('A', b2v(P[:12]), 96)
snap = (cl.tag, cl.J0)
check('second kl.exec in Enc_Last_Block: no operation, zeros written',
      first and cl.exec('A', b2v(P[:12]), 96) == 0 and (cl.tag, cl.J0, cl.state) == snap + (ELB,))
cl = at('enc')
cl.setst(ELB, 'B', 96)
check('Enc_Last_Block with KLLEN = 256: one block, excess ignored (MGR3, MGR6)',
      cl.exec('A', b2v(P[:12] + bytes(range(1, 21))), 256) == first)
cl = at('enc')
crypt(cl, P, 3)
cl.setst(ETF, 'C', len_block(8 * len(P), 8 * len(A)) | 0x5A << 128)
check('Enc_Tag_Finalize: 128 LSBs of a 256-bit INPUT; tag emitted with KLLEN = 256',
      (cl.exec('C', 0, 256), cl.state) == (b2v(RT), SUCC))

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
check('IRR6/SGR16: limit hit at block 3 of 4: prefix kept, rest zeroed, Invalid',
      cl.exec('A', b2v(P[:48] + bytes(16)), 512) == want and cl.state == INV)
check('SGR10/SGR11: the invalidated locker keeps only its MDH',
      cl.export() == (0, 0) and (cl.key, cl.tag, cl.J0) == (b'', 0, 0))

section('GCM with Set IV')
pi, n = Gcm.pi(K, b2v(J0B))
check('PI Content: key, then J0; 256 bits for k = 128', n == 256 and v2b(pi, 32) == K + J0B)
pi, n = Gcm.pi(J0=b2v(J0B), skid=SKID)
check('PI Content with a SKID: 64 + 128 bits, padded to 256', n == 256 and sl(pi, 191, 64) == b2v(J0B))
j = ref_j0(K, bytes.fromhex(IV8))
check('provisioning: start_ctr <- int(bswap(J0[127:96]))',
      Gcm.provisioned(K, J0=b2v(j)).start_ctr == int.from_bytes(j[12:], 'big'))
cl = at('setiv')
cl.setst(HA)
cl.setst(ENC)
for _ in range(40):
    cl.exec('A', 0, 1024)
check('no block budget: 320 blocks in 40 kl.exec', cl.state == ENC and cl._bs(sl(cl.J0, 127, 96)) == 321)
cl = at('setiv')
c1 = kl_encrypt(None, None, A, P, cl=cl)[:2]
cl.setst(READY)
back = (cl.state, cl.tag) == (READY, 0)
c2 = kl_encrypt(None, None, A, P, cl=cl)[:2]
check('SGR6/SGR8: Success -> Ready allowed, tag cleared', back and c1 == (RC, RT))
check('the next message continues the counter under the same tag mask',
      c2 == ref_gcm(K, IV, A, P, J0B, inc32(J0B, -(-len(P) // 16) + 1)))
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
        ('process_VLI: kl.setst to Set_Aux_Value in it', 'sav', [('setst', SAV, 'B', 480)]),
        ('MGR2: short IV transfer that is not the last', 'sav', [('exec', 'B', 0, 96)]),
        ('MGR1: Form A kl.exec in Set_Aux_Value', 'sav', [('exec', 'A', 0, 128)]),
        ('resume at klstart = 5 in Set_Aux_Value', 'sav', [('exec', 'B', 0, 256, 5)]),
        ('resume at klstart = 8 in Encrypt', 'enc', [('exec', 'A', 0, 384, 8)]),
        ('KLLEN (96) < last_blk_len (104)', 'enc', [('setst', ELB, 'B', 104), ('exec', 'A', 0, 96)]),
        ('SGR2: kl.exec in Ready', 'ready', [('exec', 'A', B16, 128)]),
        ('SGR5: kl.exec in Success', 'success', [('exec', 'A', 0, 128)]),
        ('SGR5/SGR6: kl.setst Encrypt in Success', 'success', [('setst', ENC)]),
        ('MGR1: GCM Ready -> Hash_Absorb', 'ready', [('setst', HA)]),
        ('MGR1: Form A kl.exec in Hash_Absorb', 'ha', [('exec', 'A', B16, 128)]),
        ('MGR1: Form B kl.exec in Encrypt', 'enc', [('exec', 'B', B16, 128)]),
        ('MGR1: Form B kl.exec in Decrypt', 'dec', [('exec', 'B', B16, 128)]),
        ('MGR1: Form B kl.setst to Encrypt', 'ha', [('setst', ENC, 'B', 5)]),
        ('MGR1: Form B kl.setst to Enc_Tag_Finalize', 'enc', [('setst', ETF, 'B', 5)]),
        ('MGR1: Encrypt -> Hash_Verify', 'enc', [('setst', HV, 'C', 0)]),
        ('MGR1: Decrypt -> Enc_Last_Block', 'dec', [('setst', ELB, 'B', 8)]),
        ('MGR2: KLLEN = 120 in Hash_Absorb', 'ha', [('exec', 'B', B16, 120)]),
        ('MGR2: KLLEN = 120 in Encrypt', 'enc', [('exec', 'A', B16, 120)]),
        ('MGR2: KLLEN = 120 in Decrypt', 'dec', [('exec', 'A', B16, 120)]),
        ('MachinePolicy decrypt-only: -> Encrypt', 'ha', [('setst', ENC)], {'policy': 2}),
        ('MachinePolicy encrypt-only: -> Decrypt', 'ha', [('setst', DEC)], {'policy': 1}),
        ('Set IV: Form C kl.setst to Hash_Absorb', 'setiv', [('setst', HA, 'C', 0)]),
        ('Set IV: no Set_Aux_Value', 'setiv', [('setst', SAV, 'B', 96)])]:
    cl = at(where, **(kw[0] if kw else {}))
    outs = [getattr(cl, op)(*a) for op, *a in ops]
    check(f'{name} -> Invalid, no output', cl.state == INV and not any(outs))
cl = at('enc')
snap = dict(vars(cl))
check('klstart >= KLLEN/8 in Encrypt (16 of 128, 64 of 384): empty window, only klstart = 0',
      [(cl.exec('A', B16, kl, ks), vars(cl) == snap) for kl, ks in ((128, 16), (384, 64))] == [(0, True)] * 2)
check('KLLEN = 120, klstart = 15 in Encrypt: invalid length first, Invalid', (cl.exec('A', B16, 120, 15), cl.state)
      == (0, INV))
cl = at('success')
cl.setst(READY)
check('SGR6/SGR8: Success -> Ready; the same locker reproduces tc5',
      kl_encrypt(K, bytes.fromhex(IV8), A, P, cl=cl)[:2] == TC5)
_, st1, cl = kl_decrypt(K, IV, A, RC, bytes(16))
cl.setst(READY)
p2, st2, _ = kl_decrypt(K, IV, A, RC, RT, cl=cl)
check('Failure -> Ready; the same locker decrypts and verifies', (st1, st2, p2) == (FAIL, SUCC, P))
cl = at('enc')
cl.exec('A', B16, 128)
cl.setst(READY)
check('SGR8: Encrypt -> Ready mid-message; next message unaffected',
      kl_encrypt(K, IV, A, P, cl=cl)[:2] == (RC, RT))
cl = at('ha')
cl.setst(HA)
cl.setst(ENC)
cl.setst(ENC)
check('SGR4: same-State kl.setst in Hash_Absorb and Encrypt change nothing', crypt(cl, P, 4) == RC)
check('MachinePolicy decrypt-only: decryption works', kl_decrypt(K, IV, A, RC, RT, policy=2)[1] == SUCC)
cl = at('enc')
cl.setst(PRIV)
s1, out = cl.state, cl.exec('A', B16, 128)
cl.setst(READY)
s2 = cl.state
cl.setst(INV)
check('Error State immediate accepted; then kl.exec and kl.setst Ready do nothing, '
      'the Error State may change (SGR15, SGR16)', (s1, s2, out, cl.state) == (PRIV, PRIV, 0, INV))

section('Serialized Content, export/import (MGR4)')
for k, skid, nblk in ((16, None, 4), (24, None, 4), (32, None, 5), (16, SKID, 3)):
    kb = 64 if skid else 8 * k
    check(f'Content for {"a SKID" if skid else f"k = {8 * k}"}: {kb} + 304 bits, {nblk} blocks',
          Gcm.provisioned(None if skid else bytes(k), skid=skid).export()[1] == 128 * nblk == pad128(kb + 304))
cl = at('enc')
cl.exec('A', B16, 128)
v = cl.export()[0]
check('layout: key, J0, tag, bin(start_ctr,32), last_blk_len',
      (sl(v, 127, 0), sl(v, 255, 128), sl(v, 383, 256), sl(v, 415, 384), sl(v, 431, 416), v >> 432)
      == (b2v(K), cl.J0, cl.tag, 1, 0, 0))
c2 = Gcm.imported(ENC, v, 128)
ct = crypt(c2, P[16:], 2)
c2.setst(ETF, 'C', len_block(8 * len(P), 8 * len(A)))
check('export in Encrypt, import (auth_key recomputed): tc4 completes',
      (ct, v2b(c2.exec('C', 0, 128), 16)) == (RC[16:], RT))
cl = at('sav')
cl.exec('B', b2v(IV60B[:32]), 256)
v, n = cl.export()
check("Set_Aux_Value overlay in J0's slot: len, padding, block_base, cumul_len, J0_padding; hash in tag",
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

section('kl.derive (<<KLEE-derive-endpoints>>, DER1, DER4, DER8; MGR4)')
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

def iv_by_derive(iv, n, xs=None):
    cl = at('ready')
    cl.setst(SAV, 'B', xs or 8 * len(iv))
    cl.derive(iv, n)
    return cl

for iv, n, want in ((IV60B, 60, TC6), (IV60B, 32, TC6), (IV, 12, (RC, RT))):
    cl = iv_by_derive(iv, n)
    feed(cl, iv[n:])
    check(f'{n} of {len(iv)} IV bytes by kl.derive into Set_Aux_Value, the rest by kl.exec',
          finish(cl, A, P)[:2] == want)
cl = iv_by_derive(IV60B, 0)
check('kl.derive of 0 bytes into Set_Aux_Value changes nothing (DER8)', (cl.state, cl.cumul_len) == (SAV, 0))
check('kl.derive of 20 bytes into a 480-bit IV (granularity b, DER1 item 4) -> Invalid',
      iv_by_derive(IV60B, 20).state == INV)
cl = Gcm.provisioned(bytes(16), J0=b2v(J0B))
cl.derive(SRC, 16)
check('GCM with Set IV: kl.derive into `key` in Ready; message matches REF',
      kl_encrypt(None, None, A, P, cl=cl)[:2] == ref_gcm(SRC[:16], IV, A, P))
for name, cl, n in (('in Hash_Absorb (DER1 items 1-2)', at('ha'), 16),
                    ('in Success (DER1 items 1-2)', at('success'), 16),
                    ('into a key configured by a SKID (DER4, DER1 item 2)', Gcm.provisioned(skid=SKID), 16),
                    ('of 8 bytes into a 128-bit key (DER1 item 5)', at('ready'), 8),
                    ('of 16 bytes into a 256-bit key (DER1 item 5)', Gcm.provisioned(bytes(32)), 16),
                    ('of 0 bytes into a key (DER1 item 5)', at('ready'), 0)):
    cl.derive(SRC, n)
    check(f'kl.derive {name} -> Invalid, no key written', (cl.state, cl.key) == (INV, b''))
src, dst = at('enc'), at('ready')
crypt(src, P, 1)
src.setst(ETF, 'C', len_block(8 * len(P), 8 * len(A)))
dst.derive(src, 16)
check('the tag in Enc_Tag_Finalize as a kl.derive source (an AEAD tag is no source, DER6; DER1 item 1) -> only '
      'the source Invalid', True, (src.state, dst.state, dst.key), (INV, READY, K))

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

done()
