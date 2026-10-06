#!/usr/bin/env python3
"""GCM-SIV (<<KLEE-GCM-SIV-mode>>) through a model locker, against RFC 8452 Appendix C.1-C.3
(results and per-vector intermediates) and a byte-string RFC 8452 reference."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, bin_, bxor, MASK128, montmul, aes_encrypt, selftest,
                    ERROR_STATES, section, check, control, info, done,
                    KL_STATE_UNCONFIGURED as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_HASH_ABSORB as HA, KL_STATE_ENCRYPT as ENC, KL_STATE_DECRYPT as DEC,
                    KL_STATE_ENC_LAST_BLOCK as ELB, KL_STATE_DEC_LAST_BLOCK as DLB,
                    KL_STATE_ENC_TAG_FINALIZE as ETF, KL_STATE_DEC_TAG_FINALIZE as DTF,
                    KL_STATE_SET_AUX_VALUE as SAV, KL_STATE_SET_AUX_VALUE_2 as SAV2,
                    KL_STATE_SUCCESS as SUCC, KL_STATE_FAILURE as FAIL, KL_STATE_INVALID as INV,
                    KL_STATE_EXPIRED as EXPIRED)

M32 = 2**32 - 1

def pad16(s): return s + bytes(-len(s) % 16)
def pad128(n): return -(-n // 128) * 128
def le64(n): return n.to_bytes(8, 'little')

# ---------------------------------------------------------------- REF: RFC 8452 sections 4-5
def ref_keys(key, nonce):
    h = [aes_encrypt(key, i.to_bytes(4, 'little') + nonce)[:8] for i in range(len(key) // 8 + 2)]
    return h[0] + h[1], b''.join(h[2:])

def ref_polyval(H, X):
    acc = 0
    for i in range(0, len(X), 16):
        acc = montmul(acc ^ b2v(X[i:i + 16]), b2v(H))
    return v2b(acc, 16)

def ref_tag(auth, enc, nonce, aad, pt):
    S = bxor(ref_polyval(auth, pad16(aad) + pad16(pt) + le64(8 * len(aad)) + le64(8 * len(pt))), nonce + bytes(4))
    return aes_encrypt(enc, S[:15] + bytes([S[15] & 0x7F]))

def ref_ctr(enc, tag, x):
    out = b''
    for i in range(0, len(x), 16):
        c = (int.from_bytes(tag[:4], 'little') + i // 16) % 2**32
        out += bxor(x[i:i + 16], aes_encrypt(enc, c.to_bytes(4, 'little') + tag[4:15] + bytes([tag[15] | 0x80])))
    return out

def ref_encrypt(key, nonce, aad, pt):
    auth, enc = ref_keys(key, nonce)
    tag = ref_tag(auth, enc, nonce, aad, pt)
    return ref_ctr(enc, tag, pt) + tag

def ref_decrypt(key, nonce, aad, ct):
    auth, enc = ref_keys(key, nonce)
    pt = ref_ctr(enc, ct[-16:], ct[:-16])
    return pt if ref_tag(auth, enc, nonce, aad, pt) == ct[-16:] else None

# ---------------------------------------------------------------- Montmul from <<KLEE-SCC-AEAD>>
G = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1

def gf_mul(a, b):
    """Multiplication in GF(2)[x]/G, V[k] the coefficient of x^k."""
    r = 0
    while b:
        r, a, b = r ^ (a if b & 1 else 0), a << 1, b >> 1
    for d in range(r.bit_length() - 1, 127, -1):
        if r >> d & 1:
            r ^= G << (d - 128)
    return r

def gf_inv(a):
    r, e = 1, 2**128 - 2
    while e:
        r, a, e = gf_mul(r, a) if e & 1 else r, gf_mul(a, a), e >> 1
    return r

X_M128 = gf_inv(gf_mul(1 << 127, 2))

def montmul_def(a, b): return gf_mul(gf_mul(a, b), X_M128)

# ---------------------------------------------------------------- KLEE model
SKID = 0x00C0FFEE00C0FFEE
SKS = {SKID: bytes.fromhex('01000000000000000000000000000000')}
CALLS = []                                               # enc_blk calls of RFC8452_KeyDeriv

def enc_blk(key, p): return b2v(aes_encrypt(key, v2b(p, 16)))

def RFC8452_KeyDeriv(k, key, nonce):
    """<<KLEE-GCM-SIV-KeyDeriv>>; returns (enc_key, auth_key)."""
    A, E = [0] * 6, 0
    for i in range(k // 64 + 2):
        A[i] = enc_blk(key, cat((nonce, 96), (bin_(i, 32), 32)))
        CALLS.append(i)
    for i in range(2, k // 64 + 2):
        E |= sl(A[i], 63, 0) << (64 * i - 128)           # E[64i-65 : 64i-128] <- A[i][63:0]
    return E, cat((sl(A[1], 63, 0), 64), (sl(A[0], 63, 0), 64))

def SCC_KeyDeriv(key, nonce):
    """<<KLEE-SCC-key-derivation>>."""
    A = [sl(enc_blk(key, cat((nonce, 96), (bin_(i, 32), 32))), 63, 0) for i in range(6)]
    return cat(*((A[i], 64) for i in (5, 4, 3, 2))), cat((A[1], 64), (A[0], 64))

# kl.setst Forms of the listed transitions; none enters Encrypt (reached by the ETF kl.exec)
FORMS = {(READY, SAV): 'C', (SAV, SAV): 'C', (SAV, SAV2): 'C', (SAV2, SAV2): 'C', (SAV, HA): 'A',
         (SAV2, HA): 'A', (HA, HA): 'A', (HA, ETF): 'A', (ETF, ETF): 'A', (HA, DEC): 'A',
         (DEC, DEC): 'A', (ENC, ELB): 'B', (ELB, ELB): 'B', (DEC, DLB): 'B', (DLB, DLB): 'B',
         (DEC, DTF): 'A', (DLB, DTF): 'A', (DTF, DTF): 'A'}

class Siv:
    """A GCM-SIV locker; MDH reduced to State, MachinePolicy (bit 0 encrypt, bit 1 decrypt),
    KeyType.  stale_derived (no MGR4 re-derivation on import) is a negative control."""

    def __init__(s, policy=3, stale_derived=False):
        s.policy, s.stale = policy, stale_derived
        s.klstart, s.halted, s.probe = 0, False, None
        s._error(UNCONF)

    def _error(s, st):                                   # GR21
        s.state, s.k, s.key_type, s.skid, s.key = st, 0, 0, 0, b''
        s.enc_key = s.auth_key = s.nonce = s.ctr = s.SIV = s.tmp = s.last_blk_len = 0
        return 0

    def _invalid(s): return s._error(INV)
    def _derive(s): s.enc_key, s.auth_key = RFC8452_KeyDeriv(s.k, s.key, s.nonce)

    @classmethod
    def provisioned(cls, key=None, skid=None, **kw):
        s = cls(**kw)
        s.key_type, s.skid, s.key = (1, skid, SKS[skid]) if skid is not None else (0, 0, key)
        s.k, s.state = 8 * len(s.key), READY
        s._ready()
        return s

    def _ready(s):
        s.nonce = s.ctr = s.tmp = s.SIV = 0
        s._derive()                                      # MGR4

    def export(s):
        if s.state in ERROR_STATES:
            return 0, 0                                  # GR22
        kb = 64 if s.key_type else s.k
        return (cat((s.last_blk_len, 16), (s.tmp, 128), (s.SIV, 128), (s.ctr % 2**32, 32), (s.nonce, 96),
                    (s.skid if s.key_type else b2v(s.key), kb)), pad128(kb + 400))

    @classmethod
    def imported(cls, state, v, k, **kw):
        s = cls(**kw)
        s.k, s.key, s.state = k, v2b(sl(v, k - 1, 0), k // 8), state
        s.nonce, s.ctr, s.SIV, s.tmp, s.last_blk_len = (sl(v, k + hi, k + lo) for hi, lo in
                                                         ((95, 0), (127, 96), (255, 128), (383, 256), (399, 384)))
        if not s.stale:
            s._derive()                                  # MGR4
        return s

    def _enc(s, p): return enc_blk(v2b(s.enc_key, s.k // 8), p)
    def _absorb(s, d): s.tmp = montmul(s.tmp ^ d, s.auth_key)
    def _ks(s): return s._enc(cat((1, 1), (sl(s.SIV, 126, 32), 95), ((sl(s.SIV, 31, 0) + s.ctr) % 2**32, 32)))

    def setst(s, immed, form='A', aux=0):
        st = s.state
        if immed in ERROR_STATES:                        # <<KLEE-instruction-setst>>, GR23
            return s._error(immed if immed < 54 else INV)
        if st in ERROR_STATES:
            return                                       # GR25
        if immed == READY and form == 'A':               # GR19, GR14
            s.state = READY
            return s._ready()
        if st in (SUCC, FAIL) or FORMS.get((st, immed)) != form:
            return s._invalid()                          # GR20/GR19, MGR1
        if immed in (ETF, DEC) and not s.policy & (1 if immed == ETF else 2):
            return s._invalid()
        if immed == SAV:
            s.nonce = sl(aux, 95, 0)
            s._derive()
        elif immed == SAV2:
            s.SIV = aux & MASK128                        # MGR7
        elif immed in (ELB, DLB):
            if not (0 < aux <= 120 and aux % 8 == 0):
                return s._invalid()
            s.last_blk_len = aux
        s.state = immed

    def exec(s, form, INPUT=0, KLLEN=128, start=None, stop=None):
        """kl.exec; `start` resumes at that klstart, `stop` halts after that many blocks."""
        s.halted, st = False, s.state
        if st in ERROR_STATES:
            return 0                                     # GR25
        if {HA: 'B', ETF: 'A', ENC: 'A', DEC: 'A', ELB: 'A', DLB: 'A', DTF: 'B'}.get(st) != form:
            return s._invalid()                          # GR16, GR20, MGR1
        if KLLEN < s.last_blk_len if st in (ELB, DLB) else st not in (ETF, DTF) and KLLEN % 128:
            return s._invalid()                          # MGR2: length first (<<KLEE-CSR-klstart>>)
        if start is not None:
            s.klstart = start
            if 8 * start >= KLLEN:
                s.klstart = 0                            # empty window: only klstart = 0 (<<KLEE-CSR-klstart>>)
                return 0
            if start % 16 or start and s.state in (ELB, DLB, ETF, DTF):
                return s._invalid()                      # not an interruption point
        if st in (ETF, DTF):
            s._absorb(INPUT & MASK128)                   # MGR7
            s.probe = s.tmp
            s.tmp = s._enc(cat((0, 1), (sl(s.tmp, 126, 96), 31), (sl(s.tmp, 95, 0) ^ s.nonce, 96)))
            if st == DTF:
                s.state = SUCC if s.tmp == s.SIV else FAIL
                return 0
            s.SIV, s.state = s.tmp, ENC
            return s.SIV & ((1 << KLLEN) - 1)            # MGR8
        if st in (ELB, DLB):
            lbl = s.last_blk_len
            if lbl == 0:                                 # MGR10: the final block was already processed
                return s._invalid()
            if s.ctr == 2**32:                           # one block more than P_MAX
                return s._invalid()
            o = (INPUT ^ s._ks()) & ((1 << lbl) - 1)
            if st == DLB:
                s._absorb(o)
            s.ctr, s.last_blk_len = s.ctr + 1, 0
            return o
        first, out = s.klstart // 16 if start is not None else 0, 0
        for j in range(first, KLLEN // 128):
            if stop is not None and j - first == stop:
                s.klstart, s.halted = 16 * j, True       # GR55
                return out
            blk = sl(INPUT, 128 * j + 127, 128 * j)
            if st == HA:
                s._absorb(blk)
                continue
            if s.ctr == 2**32:
                s._invalid()
                return out                               # GR54
            o = blk ^ s._ks()
            if st == DEC:
                s._absorb(o)
            out, s.ctr = out | o << 128 * j, s.ctr + 1
        s.klstart = 0
        return out

    def derive(s, src, length):
        """kl.derive destination (<<KLEE-derive-endpoints>>): `key` in Ready."""
        if s.state in ERROR_STATES or isinstance(src, Siv) and src.state in ERROR_STATES:
            return                                       # Gate Order Rule
        if isinstance(src, Siv):                         # GR35 item 1: no source endpoint (the tag is none, GR40)
            return src._invalid()
        if s.key_type or s.state != READY or length < s.k // 8:
            return s._invalid()                          # GR38 (GR35 item 2); GR35 items 2, 5
        s.key = src[:s.k // 8]
        s._derive()                                      # MGR4

# ---------------------------------------------------------------- drivers (<<KLEE-GCM-SIV-mode-examples>>)
def len_block(aad, pt, be=False):
    if be:                                               # GCM-style control
        return b2v((8 * len(aad)).to_bytes(8, 'big') + (8 * len(pt)).to_bytes(8, 'big'))
    return cat((8 * len(pt), 64), (8 * len(aad), 64))

def absorb(m, x, KLLEN=128):
    p, n = pad16(x), KLLEN // 8
    for i in range(0, len(p), n):
        m.exec('B', b2v(p[i:i + n]), 8 * len(p[i:i + n]))

def crypt(m, text, KLLEN=128, last=ELB):
    n, step, out = len(text) // 16 * 16, KLLEN // 8, b''
    for i in range(0, n, step):
        t = text[i:min(i + step, n)]
        out += v2b(m.exec('A', b2v(t), 8 * len(t)), len(t))
    if text[n:]:
        m.setst(last, 'B', 8 * len(text[n:]))
        out += v2b(m.exec('A', b2v(text[n:]), 8 * len(text[n:])), len(text[n:]))
    return out

def opened(key, nonce, aad=b'', siv=None, KLLEN=128, m=None, **kw):
    """Set_Aux_Value (nonce value), optionally Set_Aux_Value_2, Hash_Absorb, absorb aad."""
    m = m or Siv.provisioned(key, **kw)
    m.setst(SAV, 'C', nonce)
    if siv is not None:
        m.setst(SAV2, 'C', b2v(siv))
    m.setst(HA)
    absorb(m, aad, KLLEN)
    return m

def kl_encrypt(key, nonce, aad, pt, KLLEN=128, lb=None, m=None):
    m = opened(key, b2v(nonce), aad, None, KLLEN, m)
    absorb(m, pt, KLLEN)
    m.setst(ETF)
    tag = m.exec('A', len_block(aad, pt) if lb is None else lb, 128)
    return crypt(m, pt, KLLEN) + v2b(tag, 16), m

def kl_decrypt(key, nonce, aad, ctag, KLLEN=128, lb=None, m=None, set_siv=True):
    m = opened(key, b2v(nonce), aad, ctag[-16:] if set_siv else None, KLLEN, m)
    m.setst(DEC)
    pt = crypt(m, ctag[:-16], KLLEN, DLB)
    m.setst(DTF)
    m.exec('B', len_block(aad, pt) if lb is None else lb, 128)
    return m.state, pt

# ---------------------------------------------------------------- vectors
# RFC 8452 Appendix C (https://www.rfc-editor.org/rfc/rfc8452.txt); 'ct_tag' is the "Result";
# auth_key, enc_key and polyval are the "Record authentication key", "Record encryption key"
# and "POLYVAL result" lines.
VECTORS = [
    {   # C.1 #1: empty AAD, empty PT, with intermediates
        'src': 'RFC 8452 C.1 #1 (PT 0 B, AAD 0 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '',
        'ct_tag': 'dc20e2d83f25705bb49e439eca56de25',
        'auth_key': 'd9b360279694941ac5dbc6987ada7377',
        'enc_key': '4004a0dcd862f2a57360219d2d44ef6c',
        'polyval': '00000000000000000000000000000000',
    },
    {   # C.1 #2: 8-byte PT (Enc_Last_Block only), with intermediates
        'src': 'RFC 8452 C.1 #2 (PT 8 B, AAD 0 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '0100000000000000',
        'ct_tag': 'b5d839330ac7b786578782fff6013b815b287c22493a364c',
        'auth_key': 'd9b360279694941ac5dbc6987ada7377',
        'enc_key': '4004a0dcd862f2a57360219d2d44ef6c',
        'polyval': 'eb93b7740962c5e49d2a90a7dc5cec74',
    },
    {   # C.1 #4: exactly one block
        'src': 'RFC 8452 C.1 #4 (PT 16 B, AAD 0 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '01000000000000000000000000000000',
        'ct_tag': '743f7c8077ab25f8624e2e948579cf77'
                  '303aaf90f6fe21199c6068577437a0c4',
    },
    {   # C.1 #5: two blocks (chunked absorb / multi-block CTR)
        'src': 'RFC 8452 C.1 #5 (PT 32 B, AAD 0 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '',
        'pt': '01000000000000000000000000000000'
              '02000000000000000000000000000000',
        'ct_tag': '84e07e62ba83a6585417245d7ec413a9'
                  'fe427d6315c09b57ce45f2e3936a9445'
                  '1a8e45dcd4578c667cd86847bf6155ff',
    },
    {   # C.1 #14: nonempty AAD, fractional PT
        'src': 'RFC 8452 C.1 #14 (PT 4 B, AAD 12 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '010000000000000000000000',
        'pt': '02000000',
        'ct_tag': 'a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14',
    },
    {   # C.1 #15: fractional AAD and PT, with intermediates
        'src': 'RFC 8452 C.1 #15 (PT 20 B, AAD 18 B)',
        'key': '01000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '010000000000000000000000000000000200',
        'pt': '0300000000000000000000000000000004000000',
        'ct_tag': '6bb0fecf5ded9b77f902c7d5da236a43'
                  '91dd029724afc9805e976f451e6d87f6fe106514',
        'auth_key': 'd9b360279694941ac5dbc6987ada7377',
        'enc_key': '4004a0dcd862f2a57360219d2d44ef6c',
        'polyval': '4781d492cb8f926c504caa36f61008fe',
    },
    {   # C.1 #21: random-looking key/nonce, fractional AAD and PT
        'src': 'RFC 8452 C.1 #21 (PT 12 B, AAD 20 B)',
        'key': 'b3fed1473c528b8426a582995929a149',
        'nonce': '9e9ad8780c8d63d0ab4149c0',
        'aad': 'c9882e5386fd9f92ec489c8fde2be2cf97e74e93',
        'pt': '9f572c614b4745914474e7c7',
        'ct_tag': 'f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0',
    },
    {   # C.2 #1: AES-256, empty AAD and PT
        'src': 'RFC 8452 C.2 #1 (PT 0 B, AAD 0 B)',
        'key': '01000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '',
        'ct_tag': '07f5f4169bbf55a8400cd47ea6fd400f',
    },
    {   # C.2 #2: AES-256, 8-byte PT, with intermediates
        'src': 'RFC 8452 C.2 #2 (PT 8 B, AAD 0 B)',
        'key': '01000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '', 'pt': '0100000000000000',
        'ct_tag': 'c2ef328e5c71c83b843122130f7364b761e0b97427e3df28',
        'auth_key': 'b5d3c529dfafac43136d2d11be284d7f',
        'enc_key': 'b914f4742be9e1d7a2f84addbf96dec3'
                   '456e3c6c05ecc157cdbf0700fedad222',
        'polyval': '05230f62f0eac8aa14fe4d646b59cd41',
    },
    {   # C.2 #6: AES-256, three blocks
        'src': 'RFC 8452 C.2 #6 (PT 48 B, AAD 0 B)',
        'key': '01000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '',
        'pt': '01000000000000000000000000000000'
              '02000000000000000000000000000000'
              '03000000000000000000000000000000',
        'ct_tag': 'c00d121893a9fa603f48ccc1ca3c57ce'
                  '7499245ea0046db16c53c7c66fe717e3'
                  '9cf6c748837b61f6ee3adcee17534ed5'
                  '790bc96880a99ba804bd12c0e6a22cc4',
    },
    {   # C.2 #15: AES-256, fractional AAD and PT, with intermediates
        'src': 'RFC 8452 C.2 #15 (PT 20 B, AAD 18 B)',
        'key': '01000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '030000000000000000000000',
        'aad': '010000000000000000000000000000000200',
        'pt': '0300000000000000000000000000000004000000',
        'ct_tag': '43dd0163cdb48f9fe3212bf61b201976'
                  '067f342bb879ad976d8242acc188ab59cabfe307',
        'auth_key': 'b5d3c529dfafac43136d2d11be284d7f',
        'enc_key': 'b914f4742be9e1d7a2f84addbf96dec3'
                   '456e3c6c05ecc157cdbf0700fedad222',
        'polyval': '973ef4fd04bd31d193816ab26f8655ca',
    },
    {   # C.2 #24: AES-256, random-looking, fractional AAD and PT
        'src': 'RFC 8452 C.2 #24 (PT 21 B, AAD 35 B)',
        'key': '3c535de192eaed3822a2fbbe2ca9dfc8'
               '8255e14a661b8aa82cc54236093bbc23',
        'nonce': '688089e55540db1872504e1c',
        'aad': '734320ccc9d9bbbb19cb81b2af4ecbc3'
               'e72834321f7aa0f70b7282b4f33df23f167541',
        'pt': 'ced532ce4159b035277d4dfbb7db62968b13cd4eec',
        'ct_tag': '626660c26ea6612fb17ad91e8e767639'
                  'edd6c9faee9d6c7029675b89eaf4ba1ded1a286594',
    },
    {   # C.3 #1: counter wraps mod 2^32
        'src': 'RFC 8452 C.3 #1 (counter wrap, PT 32 B)',
        'key': '00000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '000000000000000000000000',
        'aad': '',
        'pt': '00000000000000000000000000000000'
              '4db923dc793ee6497c76dcc03a98e108',
        'ct_tag': 'f3f80f2cf0cb2dd9c5984fcda908456c'
                  'c537703b5ba70324a6793a7bf218d3ea'
                  'ffffffff000000000000000000000000',
    },
    {   # C.3 #2: counter wrap with a fractional final block
        'src': 'RFC 8452 C.3 #2 (counter wrap, PT 24 B)',
        'key': '00000000000000000000000000000000'
               '00000000000000000000000000000000',
        'nonce': '000000000000000000000000',
        'aad': '',
        'pt': 'eb3640277c7ffd1303c7a542d02d3e4c0000000000000000',
        'ct_tag': '18ce4f0b8cb4d0cac65fea8f79257b20'
                  '888e53e72299e56dffffffff000000000000000000000000',
    },
]

def vec(i): return tuple(bytes.fromhex(VECTORS[i][f]) for f in ('key', 'nonce', 'aad', 'pt', 'ct_tag'))

K, N, _, _, W1 = vec(0)                                  # C.1 #1: empty AAD and PT
K256 = bytes.fromhex(VECTORS[8]['key'])
k5, n5, a5, p5, w5 = vec(5)                              # C.1 #15

def at(where, **kw):
    """A C.1 #1 locker in Ready, Set_Aux_Value, Hash_Absorb, Enc_Tag_Finalize, Encrypt (after the
    Enc_Tag_Finalize kl.exec) or Decrypt; or a C.1 #15 locker in Success."""
    if where == 'success':
        m = Siv.provisioned(k5, **kw)
        kl_decrypt(k5, n5, a5, w5, m=m)
        return m
    m = Siv.provisioned(K, **kw)
    if where != 'ready':
        m.setst(SAV, 'C', b2v(N))
    for st in {'ha': (HA,), 'etf': (HA, ETF), 'enc': (HA, ETF), 'dec': (HA, DEC)}.get(where, ()):
        m.setst(st)
    if where == 'enc':
        m.exec('A', len_block(b'', bytes(32)), 128)
    return m

# ---------------------------------------------------------------- tests
section('primitives, key derivation')
check('common.py self-test', selftest())
H = b2v(bytes.fromhex('25629347589242761d31f826ba4b757b'))
X = b2v(bytes.fromhex('4f4f95668c83dfb6401762bb2d01a262'))
check('Montmul matches its definition (a.b.x^-128)',
      all(montmul(a, b) == montmul_def(a, b) for a, b in ((H, X), (X, X), (1, H), (H, 1 << 127))))
check('RFC8452_KeyDeriv(256, ...) equals SCC_KeyDeriv', RFC8452_KeyDeriv(256, K256, b2v(N)) == SCC_KeyDeriv(K256, b2v(N)))

section('RFC 8452 Appendix C')
for i, v in enumerate(VECTORS):
    key, nonce, aad, pt, want = vec(i)
    name = v['src']
    bad = want[:-1] + bytes([want[-1] ^ 0x40])
    check(f'REF {name}: encrypt, decrypt, tampered tag rejected',
          (ref_encrypt(key, nonce, aad, pt), ref_decrypt(key, nonce, aad, want), ref_decrypt(key, nonce, aad, bad))
          == (want, pt, None))
    got, m = kl_encrypt(key, nonce, aad, pt)
    check(f'encrypt {name}, KLLEN 128 and 256; ends in Encrypt/Enc_Last_Block',
          got == want == kl_encrypt(key, nonce, aad, pt, 256)[0] and m.state in (ENC, ELB))
    if 'auth_key' in v:
        CALLS.clear()
        ek, ak = RFC8452_KeyDeriv(8 * len(key), key, b2v(nonce))
        auth, enc = ref_keys(key, nonce)
        lb = le64(8 * len(aad)) + le64(8 * len(pt))
        check(f'{name}: auth_key, enc_key ({len(CALLS)} enc_blk calls), POLYVAL, REF and KLEE',
              (auth.hex(), enc.hex(), ref_polyval(auth, pad16(aad) + pad16(pt) + lb).hex())
              == (v2b(ak, 16).hex(), v2b(ek, len(key)).hex(), v2b(m.probe, 16).hex())
              == (v['auth_key'], v['enc_key'], v['polyval']) and CALLS == list(range(len(key) // 8 + 2)))
    badc = bytes([want[0] ^ 1]) + want[1:] if len(want) > 16 else bad
    check(f'decrypt {name} -> Success; tampered tag, CT -> Failure',
          kl_decrypt(key, nonce, aad, want) == (SUCC, pt)
          and kl_decrypt(key, nonce, aad, bad, 256)[0] == kl_decrypt(key, nonce, aad, badc)[0] == FAIL)

section('Set_Aux_Value, Set_Aux_Value_2, Encrypt only via Enc_Tag_Finalize')
m = Siv.provisioned(k5)
m.setst(SAV, 'C', b2v(bytes(range(12))))
check('Set_Aux_Value repeated: nonce overwritten, keys re-derived (C.1 #15)', kl_encrypt(k5, n5, a5, p5, m=m)[0] == w5)
m = opened(k5, b2v(n5) | 0xDEADBEEF << 96, a5)
absorb(m, p5)
m.setst(ETF)
check('nonce <- INPUT[95:0]: higher INPUT bits ignored', v2b(m.exec('A', len_block(a5, p5), 128), 16) == w5[-16:])
m = Siv.provisioned(k5)
m.setst(SAV, 'C', b2v(n5))
m.setst(SAV2, 'C', 0x1234)
m.setst(SAV2, 'C', b2v(w5[-16:]) | 0x77 << 200)
siv = m.SIV
m.setst(READY)
check('Set_Aux_Value_2 repeated overwrites SIV; a 256-bit INPUT keeps its 128 LSBs (MGR7)',
      siv == b2v(w5[-16:]) and kl_decrypt(k5, n5, a5, w5, m=m) == (SUCC, p5))
s0, s1 = kl_decrypt(k5, n5, a5, w5[:-16] + bytes(16)), kl_decrypt(k5, n5, a5, w5, set_siv=False)
check('skipping Set_Aux_Value_2 equals setting SIV to zero', s0 == s1 and s0[0] == FAIL)
m = opened(K, b2v(N), siv=bytes.fromhex(VECTORS[1]['ct_tag'])[-16:])
m.setst(ETF)
m.exec('A', len_block(b'', b''), 128)
check('the Enc_Tag_Finalize kl.exec enters Encrypt and overwrites an injected SIV', (m.state, v2b(m.SIV, 16)) == (ENC, W1))
got1, m = kl_encrypt(k5, n5, a5, p5)
end = m.state
m.setst(READY)
reset = (m.nonce, m.ctr, m.tmp, m.SIV) == (0, 0, 0, 0)
k6, n6, a6, p6, w6 = vec(4)
got2 = kl_encrypt(k6, n6, a6, p6, m=m)[0]
m.setst(READY)
check('encryption ends in Enc_Last_Block; kl.setst Ready clears nonce, ctr, tmp, SIV; the locker '
      'then encrypts C.1 #14 and decrypts C.1 #15',
      (end, reset, got1, got2, kl_decrypt(k5, n5, a5, w5, m=m)) == (ELB, True, w5, w6, (SUCC, p5)))
info('the encryption path ends in Encrypt or Enc_Last_Block, never in Success; software returns '
     'to Ready with kl.setst (GR14)')

section('counter, last blocks, interruption')
for where, path, last in (('enc', ENC, ELB), ('dec', DEC, DLB)):
    m = at(where)
    m.ctr = M32
    m.exec('A', 0, 128)
    st1, c1 = m.state, m.ctr
    m.exec('A', 0, 128)
    m2 = at(where)
    m2.ctr = M32
    m2.setst(last, 'B', 8)
    m2.exec('A', 0x5A, 8)
    m3 = at(where)
    m3.ctr = 2**32
    m3.setst(last, 'B', 8)
    m3.exec('A', 0x5A, 8)
    check(f'{where}: block 2^32 (ctr = 2^32-1) processed, also as the last block; ctr = 2^32 -> Invalid',
          (st1, c1, m.state, m2.state, m3.state) == (path, 2**32, INV, last, INV))
m, ref = at('enc'), at('enc')
m.ctr = ref.ctr = M32 - 1
want = ref.exec('A', b2v(bytes(range(32))), 256)
check('GR54/GR25/GR21: ctr = 2^32 at block 3 of 4: prefix kept, rest zeroed, MDH only',
      m.exec('A', b2v(bytes(range(32)) + bytes(32)), 512) == want and m.state == INV and m.export() == (0, 0))
m = at('dec')
m.ctr = 2**32
v, _ = m.export()
check('ctr = 2^32 is serialized as bin(ctr mod 2^32, 32): imported with ctr = 0',
      Siv.imported(DEC, v, m.k).ctr == 0)
bad = (0, 4, 12, 121, 128)
for where, last in (('enc', ELB), ('dec', DLB)):
    nm = 'Enc' if last == ELB else 'Dec'
    check(f'{nm}_Last_Block: last_blk_len in {bad} -> Invalid', all(at(where).setst(last, 'B', n) == 0 for n in bad))
    check(f'{nm}_Last_Block: last_blk_len 8 and 120 accepted',
          all(at(where).setst(last, 'B', n) is None for n in (8, 120)))
    m = at(where)
    m.setst(last, 'B', 64)
    first = m.exec('A', b2v(bytes(range(1, 17))), 128)
    check(f'{nm}_Last_Block: excess input ignored, OUTPUT above last_blk_len clear (MGR8); '
          'a second kl.exec -> _Invalid_, output zeroed (MGR10)',
          first >> 64 == 0 and first and m.exec('A', b2v(bytes(range(1, 17))), 128) == 0 and m.state == INV)
k10, n10, a10, p10, w10 = vec(9)
m = opened(k10, b2v(n10))
m.exec('B', b2v(p10), 384, None, 2)
h1 = (m.halted, m.klstart)
m.exec('B', b2v(p10), 384, 32)
m.setst(ETF)
tag = m.exec('A', len_block(a10, p10), 128)
o1 = m.exec('A', b2v(p10), 384, None, 1)
h2 = (m.halted, m.klstart)
o2 = m.exec('A', b2v(p10), 384, 16)
check('GR55: Hash_Absorb halted at klstart = 32 and Encrypt at 16, both resumed: C.2 #6',
      (h1, h2) == ((True, 32), (True, 16)) and v2b(sl(o1, 127, 0) | o2 & ~MASK128, 48) + v2b(tag, 16) == w10)

section('general rules')
LB0 = len_block(b'', b'')
for name, where, ops, *kw in [
        ('MGR1: Form C kl.setst to Enc_Tag_Finalize', 'ha', [('setst', ETF, 'C', LB0)]),
        ('MGR1: Form B kl.exec in Enc_Tag_Finalize', 'etf', [('exec', 'B', LB0, 128)]),
        ('MGR1: Form A kl.exec in Dec_Tag_Finalize', 'dec', [('setst', DTF), ('exec', 'A', LB0, 128)]),
        ('MGR1: Form C kl.setst to Decrypt', 'ha', [('setst', DEC, 'C', 0)]),
        ('MGR1: Form A kl.setst to Set_Aux_Value', 'ready', [('setst', SAV)]),
        ('MGR1: kl.exec in Set_Aux_Value', 'sav', [('exec', 'B', 0, 128)]),
        ('MGR1: Set_Aux_Value_2 -> Set_Aux_Value', 'sav', [('setst', SAV2, 'C', 0), ('setst', SAV, 'C', 0)]),
        ('kl.setst naming Encrypt in Hash_Absorb', 'ha', [('setst', ENC)]),
        ('kl.setst naming Encrypt in Set_Aux_Value_2', 'sav', [('setst', SAV2, 'C', 0), ('setst', ENC)]),
        ('kl.setst naming Encrypt in Enc_Tag_Finalize', 'etf', [('setst', ENC)]),
        ('kl.setst naming Encrypt in Decrypt', 'dec', [('setst', ENC)]),
        ('kl.setst naming Encrypt in Encrypt', 'enc', [('setst', ENC)]),
        ('GR16: kl.exec in Ready', 'ready', [('exec', 'A', 0, 128)]),
        ('GR20: kl.exec in Success', 'success', [('exec', 'B', 0, 128)]),
        ('MGR1: Form A kl.exec in Hash_Absorb', 'ha', [('exec', 'A', 0, 128)]),
        ('MGR2: KLLEN = 120 in Hash_Absorb', 'ha', [('exec', 'B', 1, 120)]),
        ('MGR2: KLLEN = 120 in Encrypt', 'enc', [('exec', 'A', 1, 120)]),
        ('MGR2: KLLEN = 120 in Decrypt', 'dec', [('exec', 'A', 1, 120)]),
        ('resume at klstart = 8 in Encrypt', 'enc', [('exec', 'A', 0, 256, 8)]),
        ('Enc_Last_Block: KLLEN (56) < last_blk_len (64)', 'enc', [('setst', ELB, 'B', 64), ('exec', 'A', 0, 56)]),
        ('Dec_Last_Block: KLLEN (56) < last_blk_len (64)', 'dec', [('setst', DLB, 'B', 64), ('exec', 'A', 0, 56)]),
        ('MachinePolicy decrypt-only: -> Enc_Tag_Finalize', 'ha', [('setst', ETF)], {'policy': 2}),
        ('MachinePolicy encrypt-only: -> Decrypt', 'ha', [('setst', DEC)], {'policy': 1})]:
    m = at(where, **(kw[0] if kw else {}))
    outs = [getattr(m, op)(*a) for op, *a in ops]
    check(f'{name} -> Invalid, no output', m.state == INV and not any(outs))
m = at('enc')
snap = dict(vars(m))
check('klstart >= KLLEN/8 in Encrypt (32, 48 of 256): empty window, only klstart = 0',
      [(m.exec('A', 1, kl, ks), vars(m) == snap) for kl, ks in ((256, 32), (256, 48))] == [(0, True)] * 2)
check('KLLEN = 120, klstart = 15 in Encrypt: invalid length first, Invalid', (m.exec('A', 1, 120, 15), m.state)
      == (0, INV))
check('MachinePolicy decrypt-only: decryption works', kl_decrypt(k5, n5, a5, w5, m=Siv.provisioned(k5, policy=2))[0] == SUCC)
m = at('enc')
m.setst(EXPIRED)
out = m.exec('A', 0x1234, 128)
m.setst(READY)
check('GR23/GR25: in an Error State kl.exec and kl.setst Ready do nothing', (m.state, out) == (EXPIRED, 0))
m = at('ha')
m.setst(HA)
absorb(m, a5)
m.setst(DEC)
m.setst(DEC)
check('GR15: same-State kl.setst in Hash_Absorb and Decrypt', m.state == DEC)
check('Enc_Tag_Finalize: 128 LSBs of a 256-bit INPUT; OUTPUT[255:128] clear',
      v2b(at('etf').exec('A', LB0 | 0xFF << 140, 256), 32) == W1 + bytes(16))
check('Dec_Tag_Finalize: 128 LSBs of a longer INPUT', kl_decrypt(K, N, b'', W1, lb=LB0 | 0xFF << 140)[0] == SUCC)

section('Serialized Content, export/import (MGR4)')
for key, skid, nblk in ((K, None, 5), (K256, None, 6), (None, SKID, 4)):
    kb = 64 if skid else 8 * len(key)
    check(f'Content for {"a SKID" if skid else f"k = {kb}"}: {kb} + 400 bits, {nblk} blocks',
          Siv.provisioned(key, skid).export()[1] == 128 * nblk == pad128(kb + 400))
check('key given by a SKID (SKR1): C.1 #15', kl_encrypt(None, n5, a5, p5, m=Siv.provisioned(skid=SKID))[0] == w5)
m = opened(k5, b2v(n5), a5)
m.setst(ETF)
siv = m.exec('A', len_block(a5, p5 + bytes(12)), 128)
m.exec('A', b2v(p5[:16]), 128)
v = m.export()[0]
check('layout: key, nonce, bin(ctr,32), SIV, tmp, last_blk_len',
      (sl(v, 127, 0), sl(v, 223, 128), sl(v, 255, 224), sl(v, 383, 256), sl(v, 511, 384), v >> 512)
      == (b2v(k5), b2v(n5), 1, siv, m.tmp, 0))

def resumed(where, stale):
    """Export C.1 #15 part-way in `where`, import, complete; True if it is reproduced."""
    m, ct = opened(k5, b2v(n5), a5, w5[-16:] if where == 'Dec_Last_Block' else None), b''
    if where == 'Dec_Last_Block':
        m.setst(DEC)
        ct = v2b(m.exec('A', b2v(w5[:16]), 128), 16)
        m.setst(DLB, 'B', 32)
    elif where == 'Encrypt':
        absorb(m, p5)
        m.setst(ETF)
        tag = m.exec('A', len_block(a5, p5), 128)
        ct = v2b(m.exec('A', b2v(p5[:16]), 128), 16)
    m2 = Siv.imported(m.state, m.export()[0], 128, stale_derived=stale)
    if where == 'Dec_Last_Block':
        pt = ct + v2b(m2.exec('A', b2v(w5[16:20]), 32), 4)
        m2.setst(DTF)
        m2.exec('B', len_block(a5, pt), 128)
        return (m2.state, pt) == (SUCC, p5)
    if where == 'Hash_Absorb':
        absorb(m2, p5)
        m2.setst(ETF)
        tag = m2.exec('A', len_block(a5, p5), 128)
    return ct + crypt(m2, p5[len(ct):]) + v2b(tag, 16) == w5

WHERE = ('Hash_Absorb', 'Encrypt', 'Dec_Last_Block')
for where in WHERE:
    check(f'export in {where}, import (enc_key, auth_key re-derived), completion: C.1 #15', resumed(where, False))

section('kl.derive (<<KLEE-derive-endpoints>>, GR35, GR38; MGR4)')
src = bytes.fromhex(VECTORS[11]['key'])
for i, n in ((6, 16), (6, 32), (11, 32)):
    kx, nx, ax, px, wx = vec(i)
    m = Siv.provisioned(bytes(len(kx)))
    m.derive(kx + src[len(kx):], n)
    check(f'{n} bytes into `key` (k = {8 * len(kx)}) in Ready: {VECTORS[i]["src"]}', kl_encrypt(None, nx, ax, px, m=m)[0] == wx)
for name, m, n in (('in Hash_Absorb (GR35 items 1-2)', at('ha'), 16),
                   ('in Set_Aux_Value (nonce is no endpoint, GR35 items 1-2)', at('sav'), 12),
                   ('in Success (GR35 items 1-2)', at('success'), 16),
                   ('into a key configured by a SKID (GR38, GR35 item 2)', Siv.provisioned(skid=SKID), 16),
                   ('of 8 bytes into a 128-bit key (GR35 item 5)', Siv.provisioned(K), 8),
                   ('of 16 bytes into a 256-bit key (GR35 item 5)', Siv.provisioned(K256), 16),
                   ('of 0 bytes into a key (GR35 item 5)', Siv.provisioned(K), 0)):
    m.derive(src, n)
    check(f'kl.derive {name} -> Invalid, no key written', (m.state, m.key) == (INV, b''))
s_, m = at('etf'), Siv.provisioned(K)
m.derive(s_, 16)
check('Enc_Tag_Finalize as a kl.derive source (an AEAD tag is no source, GR40; GR35 item 1) -> only the source '
      'Invalid', True, (s_.state, m.state, m.key), (INV, READY, K))

section('negative controls, spec notes')
k2, n2, a2, p2, w2 = vec(1)
control('big-endian (GCM-style) length block', kl_encrypt(k2, n2, a2, p2, lb=len_block(a2, p2, be=True))[0] != w2)
control('enc_key/auth_key not re-derived on import (MGR4)', not any(resumed(w, True) for w in WHERE))
done()
