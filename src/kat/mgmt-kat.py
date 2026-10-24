#!/usr/bin/env python3
"""KAT of the Machine-independent KLE rules: the Instructions chapter (Zkl-ISA-unpriv.adoc) and the
exception causes and *llockerstatus Off gate of Zkl-ISA-priv.adoc, on toy Machines.
SCC sealing follows <<KLE-SCC-AEAD>> with a SHA-256 stand-in for AESE256 (scc-kat.py covers the real one)."""

import functools
import hashlib
import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import (from_fields, state_fields, b2v, v2b, sl, cat, bin_, montmul, bxor, MASK128, MDH_FIELDS, MDH_FIELD,  # noqa: E402
                    mdh_pack, mdh_unpack, ERROR_STATES, section, check, control, info, done, setst_form,
                    KL_STATE_INERT as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_SUCCESS as SUCCESS, KL_STATE_FAILURE as FAILURE,
                    KL_STATEEXT_UNSUPPORTED as UNSUP, KL_STATEEXT_INVALID as INVALID,
                    KL_STATEEXT_OUT_OF_MEMORY as OOM, KL_STATEEXT_MGMT_AUTH as AUTH,
                    KL_STATEEXT_PRIV_VIOLATION as PRIV, KL_STATEEXT_EXPIRED as EXPIRED,
                    KL_CFG_PROVISIONING as PROV, KL_CFG_EXPORTING as EXP, KL_CFG_IMPORTING as IMP,
                    KL_CFG_PPI_EXPORTING as PPI_EXP, KL_CFG_PPI_IMPORTING as PPI_IMP,
                    KL_CFG_MANAGEMENT_END as END)

MASK64 = (1 << 64) - 1
CLEAR_ADS = 64
CLEARALL = 65                                # kl_cfg_clearall
NONE = 32                                    # klnamedlocker: no locker managed
KLV_SEWS = (8, 16, 32, 64)                   # <<KLE-KLV>>: SEW values, ELEN = 64; others set vtype.vill
MAX_RESTARTS = 2                             # GR48 option 5: this model's documented bound for memory instructions
VALID, PARTIAL, CONFIG = tuple(range(1, 56)), range(56, 64), range(56, 61)
COMPLETE = VALID + ERROR_STATES
raw_state = lambda st: 0 if st in ERROR_STATES or st > 63 else st   # the _State_ field of a model State
BASE_TYPE = {PROV: 'pi', EXP: 'scc', IMP: 'scc', PPI_EXP: 'pi', PPI_IMP: 'pi'}
EXC_STATE = {'unsupported': UNSUP, 'out_of_memory': OOM, 'privilege_violation': PRIV, 'clock_unavailable': EXPIRED}
RES_MASK = sum(((1 << hi - lo + 1) - 1) << lo for n, hi, lo in MDH_FIELDS if n is None)

def eq(name, got, want):
    return check(name, got == want, got, want)

# ---------------------------------------------------------------- MDH dicts (key 'res': reserved bits)

def md(**kw):
    m = dict.fromkeys(MDH_FIELD, 0)
    m['res'] = 0
    if 'Machine' in kw:                     # a CC: every mode allowed, Debug mode not, unless the caller says
        m['UsagePolicy'] = 0b01111
    assert set(kw) <= set(m), kw
    m.update(kw)
    if m['State'] > 63:       # normal form: a model Error State in 'State', its code in 'StateExtension'
        m['StateExtension'] = m['State'] >> 7
    elif m['State'] == 0 and m['StateExtension']:
        m['State'] = from_fields(0, m['StateExtension'])
    return m

def pack(m):
    return mdh_pack(**{k: v for k, v in m.items() if k != 'res'}) | m.get('res', 0)

def unpack(v):
    return dict(mdh_unpack(v), res=v & RES_MASK)

def mdh_bytes(m):
    return v2b(pack(m), 16)

def as_md(x):
    return unpack(x) if isinstance(x, int) else dict(x)

# ---------------------------------------------------------------- traps, operands, encodings

class Trap(Exception):
    def __init__(self, cause, group=None, tval=None):
        super().__init__(cause)
        self.tag = cause if group is None else f'{cause}/{group}'
        self.tval = tval

def trap_of(fn, *a, tval=False, **kw):
    try:
        fn(*a, **kw)
    except Trap as t:
        return (t.tag, t.tval) if tval else t.tag

def attempt(fn, *a, **kw):
    """The result of fn, or the tag of the Trap it raises."""
    try:
        return fn(*a, **kw)
    except Trap as t:
        return t.tag

def decode(w):
    """<<KLE-instructions-detailed>>: (mnemonic, ...), None outside KLE, Trap illegal/1 if reserved."""
    b = functools.partial(sl, w)
    op, f3, rd, rs1, rs2 = b(6, 0), b(14, 12), b(11, 7), b(19, 15), b(24, 20)
    def lk(r, reg, km=False):
        if r and reg == 0 and km: return 'KLNL'                       # GR4: the named locker
        if r: raise Trap('illegal', 1)                              # GR4: any other r or R value is reserved
        return f'K{reg}'
    if op == 0x0F and f3 == 4:
        f2 = b(31, 30)
        if f2 == 0 and not b(27, 27):
            if b(25, 25): raise Trap('illegal', 1)
            form, r = b(29, 28), b(26, 26)
            if form == 3 and rd:                                    # kl.mvin / kl.mvout: rd selects the variant
                if r: raise Trap('illegal', 1)                      # no locker is encoded: r = 0
                if rd in (1, 2, 3) and rs1 == 0 and (rd != 3 or rs2 == 0):
                    return ('kl.mvin', ('I', 'II', 'III')[rd - 1], ('X', 'V', 'KLIOBUF')[rd - 1] + str(rs2) * (rd != 3))
                if rd in (5, 6, 7) and rs2 == 0 and (rd != 7 or rs1 == 0):
                    return ('kl.mvout', ('IV', 'V', 'VI')[rd - 5], ('X', 'V', 'KLIOBUF')[rd - 5] + str(rs1) * (rd != 7))
                raise Trap('illegal', 1)
            k = lk(r, rs1, km=True)                                 # GR4: KLNL admitted
            if form == 0: return ('kl.exec', 'A', k)
            if form == 1 and rd == 0: return ('kl.exec', 'B', k)
            if form == 2 and rs2 == 0: return ('kl.exec', 'C', k)
            if form == 3 and rd == rs2 == 0: return ('kl.exec', 'D', k)
            raise Trap('illegal', 1)
        if f2 == 0:                                                 # kl.size, kl.avail
            F, r = b(29, 28), b(26, 26)
            if rs2 or (F, r) not in ((0, 0), (0, 1), (1, 0), (2, 0)): raise Trap('illegal', 1)
            return ('kl.avail' if b(25, 25) else 'kl.size', 'ABC'[F],
                    lk(r, rs1, km=True) if F == 0 else f"{'XV'[F - 1]}{rs1}")
        if f2 in (1, 3):                                            # kl.restrict*, kl.getmd*
            h, v = b(28, 28), b(29, 29)
            if b(25, 25) or b(27, 27) or rs2 or (h and v): raise Trap('illegal', 1)
            if f2 == 1: return ('kl.restrict' + 'lhv'[h + 2 * v], lk(b(26, 26), rd, km=True))
            return (('kl.getmdl', 'kl.getmd', 'kl.getmdv')[h + 2 * v], lk(b(26, 26), rs1, km=True))
        if b(29, 29): raise Trap('illegal', 1)
        T, R = b(28, 27), b(26, 25)
        if R == 3: raise Trap('illegal', 1)                         # GR4: KLNL for one locker, not both
        if T == 3: return ('kl.derive', lk(R & 1, rd, km=True), lk(R >> 1, rs1, km=True), f'X{rs2}')
        if rs2: raise Trap('illegal', 1)
        return (('kl.clone', 'kl.rename', 'kl.swap')[T], lk(R & 1, rd, km=True), lk(R >> 1, rs1, km=True))
    if op == 0x0F and f3 == 3:                                      # kl.setst, kl.mgmt
        r, F, G, imm = b(20, 20), b(22, 21), b(24, 23), b(31, 25)
        if G == 1:                                                  # kl.setste: Form A, #immed7 an Error code
            if F or rs1 or not 1 <= imm <= 6: raise Trap('illegal', 1)
            return ('kl.setste', 'A', lk(r, rd, km=True), imm << 7)   # the model Error State (ERROR_STATES)
        if G == 2:                                                  # kl.setnli, kl.setnl: Kd = 0, r = 0
            if r or rd or F > 1 or (F == 1 and imm) or (F == 0 and rs1): raise Trap('illegal', 1)
            return ('kl.setnli', imm) if F == 0 else ('kl.setnl', f'X{rs1}')
        if imm == CLEARALL and G == 0:                              # kl.clearall: Form A, Kd = 0, r = 0
            if F == 0 and not rs1 and not r and rd == 0: return ('kl.clearall',)
            raise Trap('illegal', 1)
        k = lk(r, rd, km=True)
        try:
            form = setst_form(F, rs1)                               # Form A is Form C with rs1 = X0
        except ValueError:
            raise Trap('illegal', 1)                                # GR1: F = 0b10 and 0b11 reserved
        if G == 3 or imm >> 3 == 0b0111:                            # kl.mgmt: G = 0b11, #immed7 56-58 or 63
            if G != 3 or imm >> 3 != 0b0111 or 59 <= imm <= 62: raise Trap('illegal', 1)
            return ('kl.mgmt', form, k, imm)
        return ({0: 'kl.clear', CLEAR_ADS: 'kl.clearads'}.get(imm, 'kl.setst'), form, k, imm)
    # kl.load / kl.input and kl.store / kl.output share one encoding each; klnamedlocker selects the target (GR5)
    return {(0x03, 7): ('kl.load', f'X{rd}'), (0x23, 5): ('kl.store', f'X{rs2}')}.get((op, f3))

def decoded(w):
    return attempt(decode, w)

def enc_r(f2, hi5, rs2=0, rs1=0, rd=0):
    return (f2 << 30) | (hi5 << 25) | (rs2 << 20) | (rs1 << 15) | (4 << 12) | (rd << 7) | 0x0F

def enc_setst(imm, F=0, r=0, rs1=0, rd=0, G=None):
    """G defaults to 0b11 (kl.mgmt) for #immed7 in 56-63, and to 0b00 (kl.setst) otherwise."""
    G = (3 if imm >> 3 == 0b0111 else 0) if G is None else G
    return (imm << 25) | (G << 23) | (F << 21) | (r << 20) | (rs1 << 15) | (3 << 12) | (rd << 7) | 0x0F

def enc_ls(store, xl=0, rs1=2, f3=None):
    f3 = (5 if store else 7) if f3 is None else f3
    return (xl << 20 | rs1 << 15 | f3 << 12 | 0x23) if store else (rs1 << 15 | f3 << 12 | xl << 7 | 0x03)

# ---------------------------------------------------------------- stand-ins and SCC sealing

def prf(*parts):
    h = hashlib.sha256(b'KLE-KAT toy PRF')
    for p in parts:
        p = p.to_bytes(32, 'little') if isinstance(p, int) else bytes(p)
        h.update(len(p).to_bytes(4, 'little') + p)
    return h.digest()

def to_blocks(b):
    b = bytes(b) + bytes(-len(b) % 16)
    return [b2v(b[i:i + 16]) for i in range(0, len(b), 16)]

def from_blocks(bl):
    return b''.join(v2b(x, 16) for x in bl)

def aese256(key, block):
    """Stand-in for AESE256 (not AES)."""
    return b2v(hashlib.sha256(b'AESE256 stand-in' + v2b(key, 32) + v2b(block, 16)).digest()[:16])

@functools.lru_cache(maxsize=None)
def scc_keyderiv(key, nonce):                                       # <<KLE-SCC-key-derivation>>
    A = [sl(aese256(key, cat((nonce, 96), (bin_(i, 32), 32))), 63, 0) for i in range(6)]
    return cat(*((A[i], 64) for i in (5, 4, 3, 2))), cat((A[1], 64), (A[0], 64))

def polyval(h, blocks):
    acc = 0
    for x in blocks:
        acc = montmul(acc ^ x, h)
    return acc

def _ctr(sep, siv, i):
    return cat((1, 1), (sep, 1), (sl(siv, 125, 32), 94), (bin_(sl(siv, 31, 0) + i, 32), 32))

def _tag(enc, auth, AD, N, sep, P, clear47):
    AD = list(AD)
    if sep == 0 and clear47:
        AD[0] &= ~(1 << 47)
    s = polyval(auth, AD + list(P)) ^ N
    return aese256(enc, cat((0, 1), (sep, 1), (sl(s, 125, 0), 126)))

def scc_encrypt(AD, N, sep, P, K):                                 # <<KLE-SCC-GCM-SIV-enc>>
    enc, auth = scc_keyderiv(K, N)
    siv = _tag(enc, auth, AD, N, sep, P, True)
    return siv, [p ^ aese256(enc, _ctr(sep, siv, i)) for i, p in enumerate(P)]

def scc_decrypt(AD, N, sep, siv, C, K, clear47=True):               # <<KLE-SCC-GCM-SIV-dec>>
    enc, auth = scc_keyderiv(K, N)
    P = [c ^ aese256(enc, _ctr(sep, siv, i)) for i, c in enumerate(C)]
    ok = _tag(enc, auth, AD, N, sep, P, clear47) == siv
    return ok, P if ok else [0] * len(C)

# ---------------------------------------------------------------- Localities

LOC_SUB = [('hw1', 1, 0), ('hw2', 3, 2), ('boot', 5, 4), ('mloc', 6, 6), ('hloc', 7, 7), ('sloc', 8, 8)]

def loc(hw1=0, hw2=0, boot=0, mloc=0, hloc=0, sloc=0):
    return hw1 | hw2 << 2 | boot << 4 | mloc << 6 | hloc << 7 | sloc << 8

def loc_entries(v):
    """<<KLE-locality-indexes>>: the LST indices a _Locality_ names."""
    h1, h2, bt = sl(v, 1, 0), sl(v, 3, 2), sl(v, 5, 4)
    return sorted(([h1 - 1] if h1 else []) + ([2 + h2] if h2 else []) + ([5 + bt] if bt in (1, 2) else [])
                  + [j for bit, j in ((6, 8), (7, 9), (8, 10)) if v >> bit & 1])

def loc_union(a, b):
    """<<KLE-system-keys>> union; None for two different Boot Session entries."""
    ba, bb = sl(a, 5, 4), sl(b, 5, 4)
    if ba and bb and ba != bb: return None
    return max(sl(a, 1, 0), sl(b, 1, 0)) | max(sl(a, 3, 2), sl(b, 3, 2)) << 2 | (ba or bb) << 4 \
        | (sl(a, 8, 6) | sl(b, 8, 6)) << 6

def narrow_up(cur, req):
    """<<KLE-Metadata-narrowing>> of _UsagePolicy_: a set bit allows a mode, so narrowing is the AND."""
    return cur & req

def custom_value(m):                                                # GR10
    return m['Machine'] >= 3072 or m['Version'] == 3

# ---------------------------------------------------------------- toy Machines

MAX_ADL, ADS_BLOCKS, SC_ORDER, VERSIONS = 6, 4, (0, 1, 2), (0,)
M_CIPHER, M_XOF, M_SIG, M_KEX, M_CUSTOM, M_ABSENT, M_HASH = 0x011, 0x021, 0x031, 0x041, 0xC05, 0x777, 0x051

def sc_rank(v):
    return SC_ORDER.index(v) if v in SC_ORDER else -1

class Machine:
    kind, policies, sc_levels = 'ops', {1, 2, 3}, {0}       # kind: 'ops' mask, 'sig' mask, 'none' field unused (zero)
    key_len, state_len, clf_base, clf_both, gran = 32, 16, 64, 0, 16
    op_states, states, stx = {}, frozenset(), frozenset({0})   # stx: StateExtension values outside Ready
    def __init__(self, ident):
        self.ident = ident
    def stx_ok(self, st, x):                                    # Ready holds no state block (on_ready)
        return x == 0 if st == READY else x in self.stx
    def key_field_len(self, m):
        return 16 if m['KeyType'] == 1 else self.key_len
    def pi_content_size(self, m):
        return self.key_field_len(m)
    def content1_size(self, m):
        return self.key_field_len(m) + (self.state_len if m['StateExtension'] & 1 else 0)
    def clf_capacity(self, m):
        return (self.clf_base + (self.clf_both if m['MachinePolicy'] == 3 else 0)) \
            * (1 + max(0, sc_rank(m['SCProtection'])))
    def get_state(self, cl):
        o = self.key_field_len(cl.mdh)
        return cl.c1[o:o + self.state_len] if cl.mdh['StateExtension'] & 1 else bytes(self.state_len)
    def put_state(self, cl, data):
        cl.c1 = cl.c1[:self.key_field_len(cl.mdh)] + bytes(data)
        cl.mdh['StateExtension'] |= 1
    def on_ready(self, cl):
        cl.c1 = cl.c1[:self.key_field_len(cl.mdh)]
        cl.mdh['StateExtension'] &= ~1
    def exec_form(self, m):
        return None
    def setst(self, u, cl, imm, aux):
        return False

class ToyCipher(Machine):
    sc_levels, clf_both = {0, 1, 2}, 16
    ENCRYPT, DECRYPT, VERIFY = 2, 3, 4
    op_states, states, stx = {2: 1, 3: 2}, frozenset({2, 3}), frozenset({0, 1})
    def exec_form(self, m):
        return 'A' if m['State'] in (2, 3) else None
    def verify_tag(self, u, cl):
        return b2v(prf(b'verify', u.key_of(cl))[:8])
    def setst(self, u, cl, imm, aux):
        # a same-State kl.setst into ENCRYPT or DECRYPT, which this Machine allows, sets a new IV (GR21)
        if imm in (2, 3) and cl.mdh['MachinePolicy'] & self.op_states[imm]:
            cl.mdh['State'] = imm
            self.put_state(cl, v2b(aux or 0, 16))
            return True
        if imm == self.VERIFY:                                      # GR29
            cl.mdh['State'] = SUCCESS if aux == self.verify_tag(u, cl) else FAILURE
            return True
        return False
    def process(self, u, cl, blk):
        st = self.get_state(cl)
        ctr = b2v(st[:8])
        self.put_state(cl, v2b(ctr + 1 & MASK64, 8) + st[8:])
        return bxor(blk, prf(b'keystream', u.key_of(cl), ctr)[:16])

class ToyXof(Machine):
    kind, policies, sc_levels, state_len, clf_base, gran = 'none', {0}, {0, 1}, 32, 96, 1
    ABSORB, FINAL, states, stx = 2, 3, frozenset({2, 3}), frozenset({0, 1})   # FINAL squeezes, as Hash_Output
    def exec_form(self, m):
        return {READY: 'B', self.ABSORB: 'B', self.FINAL: 'C'}.get(m['State'])
    def setst(self, u, cl, imm, aux):
        if imm == self.ABSORB and cl.mdh['State'] == READY:    # GR21: no same-State kl.setst into ABSORB
            cl.mdh['State'] = self.ABSORB
            self.put_state(cl, self.get_state(cl))
            return True
        if imm == self.FINAL and cl.mdh['State'] == self.ABSORB:
            cl.mdh['State'] = self.FINAL               # an unbounded XOF never reaches Success
            return True
        return False
    def on_ready(self, cl):
        super().on_ready(cl)
        cl.mdh['MachineUse'] = 0
    def absorb(self, u, cl, byte):
        self.put_state(cl, prf(b'absorb', u.key_of(cl), self.get_state(cl), byte))
        cl.mdh['State'] = self.ABSORB
    def squeeze(self, u, cl):
        out = prf(b'squeeze', self.get_state(cl), cl.mdh['MachineUse'])[:1]
        cl.mdh['MachineUse'] = cl.mdh['MachineUse'] + 1 & 0x3FFF
        return out
    def process(self, u, cl, x):
        if cl.mdh['State'] == self.FINAL: return self.squeeze(u, cl)
        self.absorb(u, cl, x)

class ToySig(Machine):
    kind, policies, sc_levels, key_len, clf_base, clf_both = 'sig', {0, 1, 2, 3}, {0, 1}, 64, 128, 32
    SIGN, VERIFY, SET_SCALAR = 2, 3, 4
    op_states, states = {2: 1, 3: 2}, frozenset({2, 3, 4})
    def exec_form(self, m):
        return 'A' if m['State'] == self.SIGN else None
    def setst(self, u, cl, imm, aux):
        if (imm in (2, 3) and cl.mdh['MachinePolicy'] & self.op_states[imm]) or \
                (imm == self.SET_SCALAR and cl.mdh['State'] == READY):
            cl.mdh['State'] = imm
            return True
        return False
    def process(self, u, cl, blk):
        return prf(b'sign', u.key_of(cl), blk)[:16]

class ToyCustom(Machine):
    policies, key_len, state_len, clf_base = {1}, 16, 0, 32

class ToyKex(Machine):
    """Key agreement: kl.setst SHARED computes an explicit shared secret into the state block."""
    kind, policies, sc_levels, state_len, clf_base = 'none', {0}, {0, 1, 2}, 64, 96
    SHARED, states, stx = 2, frozenset({2}), frozenset({0, 1})
    def setst(self, u, cl, imm, aux):
        if imm == self.SHARED and cl.mdh['State'] == READY:
            self.put_state(cl, prf(b'kex', u.key_of(cl), aux or 0) + prf(b'kex2', u.key_of(cl), aux or 0))
            cl.mdh['State'] = self.SHARED
            return True
        return False

class ToyHash(Machine):
    """A keyless Machine: its PI carries no key field, so _KeyType_ 1 or 2 is invalid (<<KLE-Metadata-validity>>)."""
    kind, policies, sc_levels, key_len, state_len, clf_base = 'none', {0}, {0}, 0, 32, 64
    states, stx = frozenset({2}), frozenset({0})

MACHINES = {m.ident: m for m in (ToyCipher(M_CIPHER), ToyXof(M_XOF), ToySig(M_SIG), ToyCustom(M_CUSTOM),
                                 ToyKex(M_KEX), ToyHash(M_HASH))}
# toy kl.derive endpoints, shaped as <<KLE-derive-endpoints>>: ENCRYPT stands for the keystream in Operate (its
# output on zero blocks), SHARED for the restricted ML-KEM sharedkey field; XOF output and the signature key are none
SRC_EP = {M_CIPHER: ({ToyCipher.ENCRYPT}, 'stream'), M_KEX: ({ToyKex.SHARED}, 'secret')}     # (States, kind)
DST_EP = {M_CIPHER: ('key', {READY}), M_XOF: ('absorb', {READY, ToyXof.ABSORB})}
ADMITTED = {'stream': {'key'}, 'secret': {'key', 'absorb'}}                  # <<KLE-admitted-pairs>>: GR43, GR44

def content2_size(m):
    return 16 * (m['AuxDataLen'] - 2) if m['AuxDataLen'] >= 2 and not m['ADSDropped'] else 0

# ---------------------------------------------------------------- memory and the KLE unit

BASE = 0x4000

class Memory:
    def __init__(self, data=b'', at=BASE):
        self.buf, self.unmapped, self.nonidem, self.accesses = bytearray(1 << 16), [], [], 0
        self.write(at, data)
    def write(self, a, d):
        self.buf[a:a + len(d)] = bytes(d)
    def read(self, a, n):
        return bytes(self.buf[a:a + n])
    def fault(self, a, n, kind):
        for rng, what in ((self.unmapped, 'page'), (self.nonidem, 'access')):     # GR64
            for lo, hi in rng:
                if a < hi and a + n > lo: return f'{kind}_{what}_fault', max(a, lo)

def _secret(label, j=0):
    return b2v(prf(b'LST', label, j)[:16]) | 1

DEFAULT_CSK = b2v(prf(b'CSK'))
SKS_KEY = prf(b'SKS key') + prf(b'SKS key 2')
SKID_A, SKID_B, SKID_C, SKID_D = 0x0123_4567_89AB_CDEF, 0x42, 0x43, 0x44
DEFAULT_SKS = {
    SKID_A: dict(key=SKS_KEY, allowed={M_CIPHER: 3, M_SIG: 1}, usage=0b01011, locality=loc(hw1=2)),
    SKID_B: dict(key=SKS_KEY[::-1], allowed={M_CIPHER: 1}, usage=0b11111, locality=loc(boot=1)),
    SKID_C: dict(key=SKS_KEY, allowed={M_CIPHER: 3}, usage=0b01111, locality=loc(boot=2)),
    SKID_D: dict(key=SKS_KEY, allowed={M_CIPHER: 3}, usage=0b01111, locality=loc(sloc=1)),
}

class Locker:
    def __init__(self):
        self.mdh, self.c1, self.c2, self.img, self.alloc, self.off = md(), b'', b'', None, 0, None

class Unit:
    IDS = (0xA11, 0x42, 0x7)                     # klvendorid, klarchid, klimpid
    RO_ID = ('klvendorid', 'klarchid', 'klimpid', 'klmaxiobuflen')     # URO aliases of the M-mode registers
    M_ID = {'mklvendorid': 'vendorid', 'mklarchid': 'archid', 'mklimpid': 'impid',
            'mklmaxiobuflen': 'klmaxiobuflen'}                             # MRW registers holding the values
    MIN_IOBUF = 16                                                         # lower bound of klmaxiobuflen
    def __init__(self, zklv=True, zklio=True, zklmv=True, zklexpire=True, zklmem_hw=True,
                 priv=True, h_ext=True, maxiobuflen=256, clf_total=1 << 20, clock=0, csk=DEFAULT_CSK,
                 ids=None, hw_missing=(), **attrs):
        self.zklv, self.zklio, self.zklmv, self.zklexpire = zklv, zklio, zklmv, zklexpire
        self.zklmem_hw, self.priv, self.h_ext = zklmem_hw, priv, h_ext
        self.vendorid, self.archid, self.impid = self.reset_ids = ids or self.IDS
        self.klmaxiobuflen = maxiobuflen if zklio else 0
        self.clf_total, self.clock, self.csk = clf_total, clock, csk     # clock None: unreadable
        self.hw = {j: _secret(b'hw', j) for j in range(6) if j not in hw_missing}
        self.sks = dict(DEFAULT_SKS)
        self.random_keys = True                                     # _KeyType_ 2 supported
        self.physbootscrt, self.virtbootscrt = _secret(b'phys'), _secret(b'virt')
        self.mlocality, self.hlocality, self.slocality = _secret(b'mloc'), _secret(b'hloc'), _secret(b'sloc')
        self.mode, self.kls_off, self.llstatus, self.vstart, self._rbg = 'M', False, {}, 0, 0
        self.zero_alloc = True                                      # <<KLE-destructive-config>>: allocations read 0
        self.kleemulation = False                                   # mstatus[27], <<KLE-kleemulation>>
        self.reset()
        self.__dict__.update(attrs)
    def reset(self):                                                # <<KLE-out-of-reset-unpriv>>
        self.lockers = [Locker() for _ in range(32)]
        self.kliobuflen = self.kliobuftop = self.klstart = self.restarts = 0
        self.kliobuf = bytearray()
        self.klnamedlocker = NONE
        self.siv = self.impqual = self.siv2 = 0
        self.klf = bytearray(self.clf_total)            # the KLF pool, zeroed out of reset; a clear frees without erasing

    # -- helpers
    def rbg(self, n):
        self._rbg += 1
        return b''.join(prf(b'RBG', self._rbg, i) for i in range(n // 32 + 1))[:n]
    def impqual_value(self):                                        # reset values, not M-mode writes
        vendorid, archid, impid = self.reset_ids
        return cat((0, 32), (impid, 32), (archid, 32), (vendorid, 32))
    def clf_free(self):
        return self.clf_total - sum(c.alloc for c in self.lockers)
    def _place(self, k):                                            # first fit; newly allocated capacity reads 0
        cl, used = self.lockers[k], sorted((c.off, c.off + c.alloc) for c in self.lockers if c.off is not None)
        off = 0
        for a, b in used:
            if a - off >= cl.alloc: break
            off = max(off, b)
        cl.off = off
        if self.zero_alloc:
            self.klf[off:off + cl.alloc] = bytes(cl.alloc)
    def _sync(self, k):                                             # the Content as the KLF holds it
        cl = self.lockers[k]
        if cl.off is not None:
            data = (cl.c1 + cl.c2)[:cl.alloc]
            self.klf[cl.off:cl.off + len(data)] = data
    def wants_ads(self, m):
        return sc_rank(m['SCProtection']) >= 1
    def gen_ads(self, cl):
        return prf(b'ADS', cl.c1)[:16 * (ADS_BLOCKS - 2)]
    def key_of(self, cl):
        n = MACHINES[cl.mdh['Machine']].key_len
        return self.sks[b2v(cl.c1[:8])]['key'][:n] if cl.mdh['KeyType'] == 1 else cl.c1[:n]

    # -- Localities
    def _lst_raw(self, j):
        if j <= 5: return self.hw.get(j, 0)
        return {6: self.physbootscrt, 7: self.virtbootscrt if self.h_ext else 0, 8: self.mlocality,
                9: self.hlocality if self.h_ext else 0, 10: self.slocality}[j]
    def lst_register(self, j):
        return {8: 'mkllocality', 9: 'hkllocality' if self.h_ext else None, 10: 'skllocality'}[j]
    def lst_eff(self, j):
        """LST_eff: substitution along the HW Binding chains, zeros(128) if none."""
        if j > 5: return self._lst_raw(j)
        return next((self._lst_raw(w) for w in range(j, 3 if j <= 2 else 6) if self._lst_raw(w)), 0)
    def locality_problem(self, v):
        if sl(v, 5, 4) == 3: return 'Locality[5:4] = 3'
        return next((f'unconfigured LST entry {j}' for j in loc_entries(v) if not self.lst_eff(j)), None)
    def sealing_ad(self, m):
        return [pack(m)] + [self.lst_eff(j) for j in loc_entries(m['Locality'])]

    # -- Metadata classes <<KLE-Metadata-validity>>
    def unsupported(self, m):
        mach = MACHINES.get(m['Machine'])
        if mach is None or m['MachineExtension']: return True
        if m['SCProtection'] in SC_ORDER and m['SCProtection'] not in mach.sc_levels: return True   # 3: invalid
        if m['KeyType'] == 1 and not self.sks: return True              # no SKID support
        if m['KeyType'] == 2 and not self.random_keys: return True      # no random key generation
        return m['MachinePolicy'] not in mach.policies and not (mach.kind == 'ops' and m['MachinePolicy'] == 0)
    def invalid(self, m, ctx, low=False):
        """ctx: 'provision', 'import' or 'size'; low: only bits [63:0] are examined."""
        mach, st = MACHINES.get(m['Machine']), m['State']
        pi = ctx == 'provision' or BASE_TYPE.get(st) == 'pi' or (ctx == 'size' and st == UNCONF)
        bad = [m['res'] & (MASK64 if low else MASK128), m['AuxDataLen'] == 1,
               pi and (m['AuxDataLen'] or m['ADSDropped']),
               mach and mach.kind == 'ops' and m['MachinePolicy'] == 0,
               m['KeyType'] == 3 or m['KeyType'] == 2 and not pi,              # <<KLE-KeyType-field>>
               mach and not mach.key_len and m['KeyType'] in (1, 2),            # no key field
               ctx == 'provision' and (raw_state(st) != UNCONF or m['StateExtension']), ctx == 'import' and (st == UNCONF or st > 60),
               mach and 2 <= st <= 53 and st not in mach.states,
               mach and st in VALID and not mach.stx_ok(st, m['StateExtension']),
               m['Version'] not in VERSIONS, m['SCProtection'] == 3]                  # reserved level
        if not low:
            bad += [self.locality_problem(m['Locality']), m['ExpirationDate'] and not self.zklexpire,
                    custom_value(m) and sl(m['Locality'], 1, 0) < 2]
        return any(bad)
    def available(self, m):
        mach = MACHINES.get(m['Machine'])
        return int(bool(mach) and not m['MachineExtension'] and m['MachinePolicy'] in mach.policies
                   and m['SCProtection'] in mach.sc_levels
                   and m['KeyType'] in {0, 1 if self.sks else 0, 2 if self.random_keys else 0})
    def usage_allowed(self, m):                                     # <<KLE-UsagePolicy>>
        up = m['UsagePolicy']
        bit = {'U': 0, 'VU': 0, 'VS': 1, 'HS': 2, 'S': 2, 'M': 3}
        if self.mode == 'D':                                        # outside authenticated Debug mode, bits 0-3
            dprv = getattr(self, 'debug_prv', 'M')                  # also apply to the mode Debug mode executes in
            return bool(up & 0b10000) and (dprv == 'M' or bool(up >> bit[dprv] & 1))
        return bool(up >> bit[self.mode] & 1)                       # a set bit allows its mode
    def expired(self, m):                                           # <<KLE-Metadata-expiration-date>>
        if not self.zklexpire or not m['ExpirationDate']: return False
        hours = min(max(0, self.clock), (1 << 20) - 1) if self.clock is not None else None   # 0 before the epoch,
        return hours is not None and hours >= m['ExpirationDate']                       # saturated at 2^20 - 1
    def clock_unreadable(self, m):                                  # kl_exc_clock_unavailable, State unchanged
        return self.zklexpire and bool(m['ExpirationDate']) and self.clock is None

    # -- gates
    def _exc_config(self, k):                                       # GR30: the State is kept
        raise Trap('privilege_violation')
    def _pre(self, ro_id=False):
        if not ro_id and self.kls_off: raise Trap('illegal', 1)
        if not ro_id and not self.csk: raise Trap('no_csk')
    def _idx(self, k, km=False):
        if k == 'KLNL':                                               # GR4: the named locker; NONE if there is none
            if not km: raise Trap('illegal', 1)
            return self.klnamedlocker
        return k
    def _in_effect(self):
        return self.priv and self.mode not in ('M', 'D')
    def _off(self, k, exempt=False):
        if self._in_effect() and self.llstatus.get(k) == 'off':
            if not exempt: raise Trap('locker_off')
            return True
        return False
    def _dirty(self, k):
        if self._in_effect():
            self.llstatus[k] = 'dirty'
    def _zeroize(self, k, dirty=True):                              # <<KLE-CSR-klnamedlocker>>
        self.lockers[k] = Locker()
        if self.klnamedlocker == k:
            self.klnamedlocker = NONE
        if dirty:
            self._dirty(k)
    def _enter_error(self, k, st):                                  # GR36
        cl = self.lockers[k]                                        # klnamedlocker keeps naming it
        cl.mdh.update(State=st, AuxDataLen=0, ADSDropped=0,
                      Version=0 if cl.mdh['Version'] == 3 else cl.mdh['Version'])   # GR36: a Version of 3 to 0
        cl.c1 = cl.c2 = b''
        cl.img, cl.alloc, cl.off = None, 0, None
        self._dirty(k)
    def _after_mgmt(self, k):
        self.klnamedlocker = NONE if self.lockers[k].mdh['State'] == UNCONF else k   # kept after completion
        self.klstart = 0

    # -- CSRs
    def _csr(self, name):
        if name in ('kliobuflen', 'kliobuftop') and not self.zklio: raise Trap('illegal', 1)
        if name in self.M_ID and self.mode != 'M': raise Trap('illegal', 1)
        self._pre(ro_id=name in self.RO_ID)
    def csr_read(self, name):
        self._csr(name)
        return {'klvendorid': self.vendorid, 'klarchid': self.archid, 'klimpid': self.impid}.get(
            name, getattr(self, self.M_ID.get(name, name), None))
    def csrs(self, **kv):
        for name, v in kv.items():
            self.csr_write(name, v)
        return self
    def csr_write(self, name, v):
        self._csr(name)
        if name in self.RO_ID: raise Trap('illegal', 1)
        if name == 'mklmaxiobuflen':                                # WARL; no effect without Zklio
            if self.zklio:
                self.klmaxiobuflen = max(self.MIN_IOBUF, v)
                if self.kliobuflen > self.klmaxiobuflen:
                    self.kliobuflen = self.kliobuftop = self.klmaxiobuflen
                    self.kliobuf = bytearray(self.kliobuflen)
        elif name in self.M_ID:
            setattr(self, self.M_ID[name], v)
        elif name == 'kliobuflen':
            self.kliobuflen = self.kliobuftop = min(v, self.klmaxiobuflen)       # WARL; zeroes the buffer
            self.kliobuf = bytearray(self.kliobuflen)
        elif name == 'kliobuftop':
            self.kliobuftop = min(v, self.kliobuflen)
        elif name == 'klstart':
            self.klstart = v
        elif v <= NONE:                                             # klnamedlocker: 33+ ignored
            self.klnamedlocker = v

    # -- kl.getmd*, kl.size, kl.avail
    def getmd(self, k):
        k = self._idx(k, km=True)
        self._pre()
        if k == NONE: return md()                                   # GR33: KLNL at 32 reads as Unconfigured
        self._off(k)
        return md(**self.lockers[k].mdh)
    def getmdl(self, k):
        return pack(self.getmd(k)) & MASK64
    def getst(self, k):                                             # kl.getst, then kl.getstx at _State_ 0
        return from_fields(self.getmdl(k) >> 18 & 0x3F, self.getstx(k))
    def getstx(self, k):                                            # kl.getmdl; srli 24; andi 0x0F
        return self.getmdl(k) >> 24 & 0x0F
    def _md_operand(self, form, k, lo, m, vec_bits):
        if form == 'C' and (not self.zklv or vec_bits < 128 or self.vstart):   # GR6; GR7: no vstart value
            raise Trap('illegal', 1)
        if form == 'A': return self.getmd(k), False
        self._pre()
        return (unpack(lo & MASK64), True) if form == 'B' else (as_md(m), True)
    def _not_native(self, m, supplied):                            # <<KLE-size-avail-lookup>>
        if not supplied or self.available(m): return False
        if self.kleemulation: raise Trap('illegal', 2)               # <<KLE-kleemulation>>
        return True
    def size(self, form='A', k=None, lo=None, m=None, vec_bits=128):     # <<KLE-instruction-size>>
        m, supplied = self._md_operand(form, k, lo, m, vec_bits)
        if supplied:
            st = m['State']
            if 60 < st <= 63 or st > 63 and m['StateExtension'] >= 7: return 0      # item 2
            if st > 63: return 16                                                     # item 3
            if m['Version'] in (1, 2) or m['SCProtection'] == 3 or m['KeyType'] == 3: return 0   # item 4
            if self._not_native(m, True): return 0                                    # item 5
        return self.size_of(m, supplied, low=form == 'B')
    def size_of(self, m, supplied, low=False):
        st = m['State']
        if not supplied and st == UNCONF: return 0
        if st > 63:                                                 # State 0, StateExtension non-zero
            if supplied and 7 <= m['StateExtension'] <= 15: return 0   # invalid
            return 16                                               # Error State, whatever its other fields
        if supplied and (st > 60 or self.unsupported(m) or self.invalid(m, 'size', low)): return 0
        if m['Version'] == 3: return 16 + 16 * m['AuxDataLen']     # GR73, kl.size item 3
        mach = MACHINES[m['Machine']]
        if st in VALID or st in (IMP, EXP):
            c1 = mach.content1_size(m)
            return 32 + c1 if m['AuxDataLen'] == 0 else 64 + c1 + content2_size(m)
        return 16 + mach.pi_content_size(m)
    def avail(self, form='A', k=None, lo=None, m=None, vec_bits=128):
        m, supplied = self._md_operand(form, k, lo, m, vec_bits)
        if not supplied: return 0 if m['State'] == UNCONF else self.available(m)  # item 1
        if m['Version'] != 0 or m['SCProtection'] == 3 or m['KeyType'] == 3: return 0  # item 2
        return 0 if self._not_native(m, True) else 1                                  # items 3-4
    def layout(self, m):
        """(ContentOffset, content_size, image_size, image_end) of <<KLE-serialized-image>>."""
        mach = MACHINES[m['Machine']]
        if BASE_TYPE.get(m['State']) == 'pi':
            n = mach.pi_content_size(m)
            return 0, n, n, n
        off, c1 = (16 if m['AuxDataLen'] == 0 else 48), mach.content1_size(m)
        n = c1 + content2_size(m)
        return off, n, off + n, off + min(n, c1 + 16 * (MAX_ADL - 2))

    # -- kl.mgmt  <<KLE-instruction-mgmt>>, <<KLE-locker-management>>
    def mgmt(self, k, imm, ml=None, form='C', vec_bits=128):
        if imm not in (PROV, EXP, IMP, END) or form not in ('A', 'B', 'C') or (form == 'B' and (not self.zklv or self.vstart)):  # GR7
            raise Trap('illegal', 1)
        via_km = k == 'KLNL'
        k = self._idx(k, km=True)
        if self.kls_off: raise Trap('illegal', 1)               # first group: klstart untouched
        return self._mgmt(k, imm, ml, form, vec_bits, via_km)
    def _mgmt(self, k, imm, ml, form, vec_bits=128, via_km=False):
        self._pre()
        opening = imm in (PROV, IMP)
        if k == NONE:                                               # GR33: KLNL at 32, an opening included
            self.klstart = 0                                        # GR33: common steps only
            self._mdh_check(form, vec_bits)                         # GR6, GR17 item 7: even if it falls through
            return 'noop'
        self._off(k, exempt=opening)
        self.klstart = 0                                            # common step 3: past the guard checks
        self._mdh_check(form, vec_bits)                             # GR6, GR17 item 7: locker-state-independent
        st = self.lockers[k].mdh['State']
        if (imm == EXP and st == UNCONF) or (imm == END and (st == UNCONF or st in ERROR_STATES)):   # GR33
            self.klnamedlocker = NONE if st == UNCONF else k
            return 'noop'
        if imm == END and st not in CONFIG: raise Trap('illegal', 2)
        if opening or (imm == END and st != PROV):
            ml = self._mgmt_md(form, ml, vec_bits)
        if imm == END and st != PROV and not (
                ml['State'] in VALID or ml['State'] in (IMP, EXP) if BASE_TYPE[st] == 'scc'
                else ml['State'] in (PROV, PPI_IMP, PPI_EXP)):
            raise Trap('illegal', 2)
        if opening: return self._open_in(k, imm, ml)
        return self._open_export(k) if imm == EXP else self._complete(k, ml)
    def _mdh_check(self, form, vec_bits=128):
        if form == 'B' and vec_bits < 128:                          # GR6: Form B
            raise Trap('illegal', 2)
    def _mgmt_md(self, form, ml, vec_bits=128):
        return as_md(0 if form == 'A' else ml)                      # Form A: an all-zero MDH (GR3)
    def _open_in(self, k, imm, ml):
        ml = md(**ml)
        self._zeroize(k)
        cl = self.lockers[k]
        if imm == IMP and ml['State'] in ERROR_STATES:                 # short import: StateExtension 1-6
            cl.mdh = dict(ml, AuxDataLen=0, ADSDropped=0, Version=0 if ml['Version'] == 3 else ml['Version'])
            if (ml['State'] == EXPIRED and not self.zklexpire) or ml['Version'] == 3:                         # Version 3 in an Error State: invalid
                cl.mdh['State'] = INVALID
            self._after_mgmt(k)
            return 'short import'
        if imm == IMP:                                              # import opening zeroizes SIV, IMPQUAL, SIV2
            self.siv = self.impqual = self.siv2 = 0
        if self.unsupported(ml): return self._fail_open(k, 'unsupported')
        if self.invalid(ml, 'provision' if imm == PROV else 'import'): return self._fail_open(k, 'invalid')
        need = MACHINES[ml['Machine']].clf_capacity(ml)
        if need > self.clf_free(): return self._fail_open(k, 'out_of_memory')
        m = dict(ml)
        if imm == PROV:
            m.update(MachineUse=0, State=PROV)
        else:                                                       # steps 6-8 of <<KLE-SCC-import>>
            adl = m['AuxDataLen']
            m['ADSDropped'] = int(adl >= 2 and bool(ml['ADSDropped'] or adl > MAX_ADL))
            m['State'] = PPI_IMP if BASE_TYPE.get(ml['State']) == 'pi' else IMP
        cl.mdh, cl.alloc = m, need
        self._place(k)
        off, _, _, iend = self.layout(m)
        cl.img = bytearray(iend - off)
        self._after_mgmt(k)
        return 'opened'
    def _fail_open(self, k, why):
        if why == 'invalid':
            self.lockers[k].mdh = md(State={'invalid': INVALID, **EXC_STATE}[why])
            self._after_mgmt(k)
            return why
        self.klnamedlocker = k                                    # names the zeroized locker, also for KLNL
        raise Trap(why)
    def _open_export(self, k):
        cl = self.lockers[k]
        m, st = cl.mdh, cl.mdh['State']
        if st in ERROR_STATES:
            self._after_mgmt(k)
            return 'unchanged'
        if st in VALID:                                             # <<KLE-SCC-export>>
            self.siv, ct = scc_encrypt(self.sealing_ad(m), 0, 0, to_blocks(cl.c1), self.csk)
            img = from_blocks(ct)
            if m['AuxDataLen'] >= 2:
                self.impqual = self.impqual_value()
                self.siv2, ct2 = scc_encrypt([self.impqual, self.siv], 0, 1, to_blocks(cl.c2), self.csk)
                img += from_blocks(ct2)
            cl.img, cl.c1, cl.c2 = bytearray(img), b'', b''
        m['State'] = PPI_EXP if BASE_TYPE.get(st) == 'pi' else EXP
        self._dirty(k)
        self._after_mgmt(k)
        return 'opened'
    def _complete(self, k, ml):
        cl = self.lockers[k]
        if cl.mdh['State'] == PROV:
            self._complete_provisioning(k)
        else:
            cl.mdh['State'] = ml['State']
            if ml['State'] in VALID:
                self._unseal(k)
            self._dirty(k)
        self._after_mgmt(k)
        return 'completed'
    def _unseal(self, k):
        cl = self.lockers[k]
        m = cl.mdh
        n1 = MACHINES[m['Machine']].content1_size(m)
        img = bytes(cl.img) + bytes(max(0, n1 - len(cl.img)))
        ok, p1 = scc_decrypt(self.sealing_ad(m), 0, 0, self.siv, to_blocks(img[:n1]), self.csk)
        if not ok: return self._enter_error(k, AUTH)
        cl.c1, c2, dropped = from_blocks(p1), b'', m['ADSDropped']
        if m['AuxDataLen'] >= 2 and not dropped:
            n2 = 16 * (m['AuxDataLen'] - 2)
            ok2 = self.impqual == self.impqual_value()
            if ok2:
                ok2, p2 = scc_decrypt([self.impqual, self.siv], 0, 1, self.siv2,
                                      to_blocks(img[n1:n1 + n2] + bytes(max(0, n1 + n2 - len(img)))), self.csk)
            c2, dropped = (from_blocks(p2), 0) if ok2 else (b'', 1)
        m['ADSDropped'] = 0
        if m['AuxDataLen'] == 0 or dropped:
            m['AuxDataLen'], c2 = (ADS_BLOCKS, self.gen_ads(cl)) if self.wants_ads(m) else (0, b'')
        cl.c2, cl.img = c2, None
        self._sync(k)
        if m['KeyType'] == 1:                                       # <<KLE-MVR-open>>, <<KLE-system-keys>>
            err = self.sks_resolve(cl)
            if err:
                self._enter_error(k, err)
    def _complete_provisioning(self, k):
        cl = self.lockers[k]
        m = cl.mdh
        if m['AuxDataLen'] or m['ADSDropped']: return self._enter_error(k, INVALID)
        pi, cl.img = bytes(cl.img), None
        if m['KeyType'] == 2:                                       # <<KLE-KeyType-field>>: random key, KeyType 0
            cl.c1, m['KeyType'] = self.rbg(MACHINES[m['Machine']].key_len), 0
        else:
            cl.c1 = pi[:16] if m['KeyType'] == 1 else pi
            err = self.sks_resolve(cl) if m['KeyType'] == 1 else None
            if err: return self._enter_error(k, err)
        m.update(State=READY, StateExtension=0, MachineUse=0)
        if self.wants_ads(m):
            m['AuxDataLen'], cl.c2 = ADS_BLOCKS, self.gen_ads(cl)
        self._sync(k)
        self._dirty(k)
    def sks_resolve(self, cl):                                      # <<KLE-system-keys>>: None, or the Error State
        m, e = cl.mdh, self.sks.get(b2v(cl.c1[:8]))
        if e is None or m['Machine'] not in e['allowed']: return INVALID          # not resolved
        allowed = e['allowed'][m['Machine']]
        if m['MachinePolicy'] & ~allowed:
            return INVALID
        new_loc = loc_union(m['Locality'], e['locality'])
        if new_loc is None or self.locality_problem(new_loc):        # failed narrowing (<<KLE-Metadata-narrowing>>)
            return PRIV
        m.update(UsagePolicy=narrow_up(m['UsagePolicy'], e['usage']), Locality=new_loc)
        return None

    # -- kl.setst family  <<KLE-instruction-setst>>
    def setst(self, k, imm, aux=None, form='A', vec_bits=128):
        if form not in ('A', 'B', 'C'): raise Trap('illegal', 1)   # GR1: no Form B
        if imm == EXPIRED and not self.zklexpire:                   # reserved (kl.setste: GR24)
            raise Trap('illegal', 1)
        if 56 <= imm <= 63: return self.mgmt(k, imm, aux, form=form, vec_bits=vec_bits)
        if imm == CLEARALL:                                         # kl.clearall: Form A, locker 0, r = 0
            if form == 'A' and k == 0: return self.clearall()
            raise Trap('illegal', 1)
        if form == 'B' and (not self.zklv or self.vstart): raise Trap('illegal', 1)          # GR7: no vstart value
        k = self._idx(k, km=True)                                   # GR4: KLNL admitted
        self._pre()
        if k == NONE: return 'noop'                                 # GR33: KLNL at 32, as on an Unconfigured locker
        if imm == UNCONF: return self.clear(k)
        self._off(k)
        if imm in ERROR_STATES:                                     # kl.setste, in every State (GR37)
            self._enter_error(k, imm)
            return 'error state'
        g = self._usage_gate(k)
        if g: return g
        cl = self.lockers[k]
        m = cl.mdh
        if imm == CLEAR_ADS:                                        # GR23: in every Valid State
            if form != 'A':                                         # GR23: Form A only (GR13, GR22)
                self._enter_error(k, INVALID)
                return 'invalid'
            m.update(AuxDataLen=0, ADSDropped=0)
            cl.c2 = b''
            self._dirty(k)
            return 'ads cleared'
        if imm in (SUCCESS, FAILURE):                               # GR25: admitted in no State (GR22)
            self._enter_error(k, INVALID)
            return 'invalid'
        if m['State'] in (SUCCESS, FAILURE) and imm != READY:       # GR23
            self._enter_error(k, INVALID)
            return 'invalid'
        mach = MACHINES[m['Machine']]
        if imm == READY and form != 'A':                            # GR23: Form A (GR13)
            self._enter_error(k, INVALID)
            return 'invalid'
        if imm == READY:                                            # GR23
            mach.on_ready(cl)
            m['State'] = READY
        elif imm in mach.op_states and not m['MachinePolicy'] & mach.op_states[imm] \
                or not mach.setst(self, cl, imm, aux):              # GR26: a disabled destination
            self._enter_error(k, INVALID)
            return 'invalid'
        self._dirty(k)
        return 'ok'
    def clear(self, k):
        off = self._off(k, exempt=True)
        self._zeroize(k, dirty=off or self.lockers[k].mdh['State'] != UNCONF)
        return 'cleared'
    def clearall(self):                                             # <<KLE-instruction-clearall>>
        self._pre()
        for k in range(32):
            self.clear(k)
        self.kliobuf = bytearray()
        self.kliobuflen = self.kliobuftop = self.klstart = self.siv = self.impqual = self.siv2 = 0
        self.klnamedlocker = NONE
        return 'cleared all'
    def _usage_gate(self, k, needs_buf=False):
        """GR17, GR33, GR22 items 1-5; a wrong Form is one of the Machine's rules (GR13)."""
        m = self.lockers[k].mdh
        if m['State'] == UNCONF or m['State'] in ERROR_STATES: return 'noop'          # GR33
        if m['State'] in PARTIAL: return self._exc_config(k)
        if needs_buf and not self.kliobuflen: raise Trap('illegal/2')                       # GR15: unconfigured KLIOBUF
        if not self.usage_allowed(m): raise Trap('privilege_violation')
        if self.clock_unreadable(m): raise Trap('clock_unavailable')
        if self.expired(m):
            self._enter_error(k, EXPIRED)
            return 'expired'

    # -- kl.exec  <<KLE-instruction-exec>>
    def exec_(self, k, form='A', vin=None, vout=None, sew=8, halt_after=None):
        if form != 'D' and (not self.zklv or sew not in KLV_SEWS): raise Trap('illegal', 1)
        k = self._idx(k, km=True)                                   # GR4: KLNL admitted
        self._pre()
        if k != NONE: self._off(k)
        nb = sew // 8
        if form != 'D' and self.klstart != self.vstart * nb: raise Trap('illegal', 2)
        def stop(result):                                           # GR35 output zeroing
            if form in ('A', 'C') and vout is not None:
                vout[self.vstart * nb:] = bytes(len(vout) - self.vstart * nb)
            elif form == 'D' and self.zklio and self.kliobuflen:
                self.kliobuf[self.klstart:self.kliobuftop] = bytes(max(0, self.kliobuftop - self.klstart))
            self.klstart = self.vstart = 0
            return result
        if k == NONE: return stop('noop')                           # GR33: KLNL at 32, as on an Unconfigured locker
        cl = self.lockers[k]
        m = cl.mdh
        mach = MACHINES.get(m['Machine'])
        want = mach.exec_form(m) if mach and m['State'] in VALID else None
        sub = form == 'D' and want in ('A', 'B', 'C') and self.zklio   # without Zklio a wrong Form (GR14)
        g = self._usage_gate(k, sub)
        if g: return stop(g)
        if want is None or not (form == want or sub):              # GR21, GR23; a wrong Form (GR13, GR22)
            self._enter_error(k, INVALID)
            return stop('invalid')
        if m['State'] in mach.op_states and not m['MachinePolicy'] & mach.op_states[m['State']]:
            self._enter_error(k, INVALID)                           # GR26: the narrowed policy disables it
            return stop('invalid')
        has_in, has_out = want in 'AB', want in 'AC'
        src, dst = (self.kliobuf, self.kliobuf) if sub else (vin, vout)
        window = self.kliobuftop if sub else len(vin if vin is not None else vout)
        j = self.klstart
        if window % mach.gran:                                      # invalid length, also output only
            self._enter_error(k, INVALID)
            return stop('invalid')
        if j >= window:                                             # empty window: only klstart = 0
            self.klstart = self.vstart = 0
            return 'empty'
        if j % mach.gran:                                           # not an interruption point
            self._enter_error(k, INVALID)
            return stop('invalid')
        if self.wants_ads(m) and not m['AuxDataLen']:               # ADS regenerated on use
            m['AuxDataLen'], cl.c2 = ADS_BLOCKS, self.gen_ads(cl)
        while j < window:
            if halt_after is not None and j - self.klstart >= halt_after:
                self.klstart, self.vstart = j, j // nb
                self._dirty(k)
                return 'halted'
            out = mach.process(self, cl, bytes(src[j:j + mach.gran]) if has_in else None)
            if has_out:
                dst[j:j + mach.gran] = out
            j += mach.gran
        self._dirty(k)
        self.klstart = self.vstart = 0
        return 'done'

    # -- kl.restrict*  <<KLE-instruction-restrict>>
    NAMED = {'l': ('MachinePolicy',), 'h': ('Locality', 'UsagePolicy', 'ExpirationDate')}   # never SCProtection
    def restrict(self, k, x, which='v', vec_bits=128):
        if which == 'v' and (not self.zklv or vec_bits < 128 or self.vstart): raise Trap('illegal', 1)   # GR6, GR7
        k = self._idx(k, km=True)                                   # GR4: KLNL admitted
        self._pre()
        if k == NONE: return 'noop'                                 # GR33: KLNL at 32
        self._off(k)
        cl = self.lockers[k]
        m, st = cl.mdh, cl.mdh['State']
        if st == UNCONF or st in ERROR_STATES: return 'noop'          # GR33
        if st in PARTIAL: return self._exc_config(k)
        xv = x if isinstance(x, int) else pack(x)
        xs = unpack(xv & {'l': MASK64, 'h': MASK128 ^ MASK64, 'v': MASK128}[which])
        named = self.NAMED['l'] + self.NAMED['h'] if which == 'v' else self.NAMED[which]
        mach, new = MACHINES.get(m['Machine']), dict(m)
        bad = [n for n in MDH_FIELD if n not in named and xs[n]] + [xs['res']]
        if which != 'h' and mach and mach.kind != 'none':          # a clear bit removes a function; an unused
            mp = m['MachinePolicy'] & xs['MachinePolicy']          # field stays zero whatever rq holds
            bad.append(mp not in mach.policies)                     # GR26: forbidden value
            new['MachinePolicy'] = mp
        elif which != 'h' and mach is None:
            bad.append(True)
        req, pv = xs['Locality'], []                                # pv: Usage Control failures (Privilege Violation)
        if req:
            for name, hi, lo in LOC_SUB:
                rv, cv = sl(req, hi, lo), sl(m['Locality'], hi, lo)
                if rv and rv != cv:
                    if cv and not (name in ('hw1', 'hw2') and rv > cv):
                        pv.append(True)
                    new['Locality'] = new['Locality'] & ~(((1 << hi - lo + 1) - 1) << lo) | rv << lo
            pv.append(new['Locality'] != m['Locality'] and self.locality_problem(new['Locality']))
        if new['Locality'] != m['Locality']:
            bad.append(custom_value(new) and sl(new['Locality'], 1, 0) < 2)          # GR10
        if which != 'l':                                            # all ones leaves the field unchanged
            new['UsagePolicy'] = narrow_up(m['UsagePolicy'], xs['UsagePolicy'])
        req = xs['ExpirationDate']
        if req:
            bad.append(not self.zklexpire)
            if not m['ExpirationDate'] or req <= m['ExpirationDate']:
                new['ExpirationDate'] = req                         # a later date is ignored, no error
        if any(bad) or any(pv):
            if any(bad):                                            # a malformed request wins
                self._enter_error(k, INVALID)
                return 'invalid'
            self._enter_error(k, PRIV)
            return 'privilege_violation'
        m.update(new)
        self._dirty(k)
        return 'ok'

    # -- kl.clone, kl.rename, kl.swap  <<KLE-instruction-clone>>
    def _pair(self, kd, ks):
        if kd == ks == 'KLNL': raise Trap('illegal', 1)               # GR4: R = 11 reserved
        kd, ks = self._idx(kd, km=True), self._idx(ks, km=True)       # GR4: KLNL for one of the two lockers
        self._pre()
        return kd, ks
    def clone(self, kd, ks):
        kd, ks = self._pair(kd, ks)
        if kd == ks or NONE in (kd, ks): return 'noop'              # GR33: KLNL at 32
        self._off(ks)
        self.clear(kd)                                  # destructive: Kd is cleared first, even if a trap follows
        src = self.lockers[ks]
        if src.mdh['State'] == UNCONF: return 'cleared'                 # the clone of no CC is no CC
        if src.mdh['State'] in PARTIAL: return self._exc_config(ks)
        if src.alloc > self.clf_free(): raise Trap('out_of_memory')
        dst = self.lockers[kd]
        dst.mdh, dst.c1, dst.c2, dst.alloc = dict(src.mdh), src.c1, src.c2, src.alloc
        self._place(kd)
        self._sync(kd)
        self._dirty(kd)
        return 'cloned'
    def rename(self, kd, ks):
        kd, ks = self._pair(kd, ks)
        if kd == ks or NONE in (kd, ks): return 'noop'
        self._off(ks)
        self._off(kd, exempt=True)
        self.lockers[kd], self.lockers[ks] = self.lockers[ks], Locker()
        self.klnamedlocker = {ks: kd, kd: NONE}.get(self.klnamedlocker, self.klnamedlocker)
        self._dirty(ks)
        self._dirty(kd)
        return 'renamed'
    def swap(self, kd, ks):
        kd, ks = self._pair(kd, ks)
        if kd == ks or NONE in (kd, ks): return 'noop'
        self._off(ks)
        self._off(kd)
        self.lockers[kd], self.lockers[ks] = self.lockers[ks], self.lockers[kd]
        self.klnamedlocker = {ks: kd, kd: ks}.get(self.klnamedlocker, self.klnamedlocker)
        self._dirty(ks)
        self._dirty(kd)
        return 'swapped'

    # -- kl.derive  <<KLE-instruction-derive>>, uninterruptible (GR47)
    def derive(self, kd, ks, length):
        r = self._derive(kd, ks, length)
        self.klstart = 0                                            # GR52: written 0 on retirement, not on a trap
        return r
    def _derive(self, kd, ks, length):
        km = 'KLNL' in (kd, ks)
        if kd == ks == 'KLNL': raise Trap('illegal', 1)               # GR4: R = 11 reserved
        kd, ks = self._idx(kd, km=True), self._idx(ks, km=True)
        if kd == ks and not km: raise Trap('illegal', 1)
        self._pre()
        if NONE in (kd, ks): return 'noop'                          # GR33: KLNL at 32
        if kd == ks: raise Trap('illegal', 2)                       # KLNL names the other locker
        self._off(ks)
        self._off(kd)
        ends = (ks, kd)
        for e in ends:                                              # GR38: State class, source then destination
            st = self.lockers[e].mdh['State']
            if st == UNCONF or st in ERROR_STATES: return 'noop'    # GR33
            if st in PARTIAL: return self._exc_config(e)            # GR30
        for e in ends:
            if not self.usage_allowed(self.lockers[e].mdh): raise Trap('privilege_violation')
        if any(self.clock_unreadable(self.lockers[e].mdh) for e in ends): raise Trap('clock_unavailable')
        exp = [e for e in ends if self.expired(self.lockers[e].mdh)]
        for e in exp:
            self._enter_error(e, EXPIRED)
        if exp: return 'expired'
        for e in ends:                                              # GR22 item 4, MR9 item 1.a: source first
            m, mach = self.lockers[e].mdh, MACHINES.get(self.lockers[e].mdh['Machine'])
            if mach and m['State'] in mach.op_states and not m['MachinePolicy'] & mach.op_states[m['State']]:
                self._enter_error(e, INVALID)
                return 'invalid'
        S, D = self.lockers[ks].mdh, self.lockers[kd].mdh
        se, de = SRC_EP.get(S['Machine']), DST_EP.get(D['Machine'])
        ok = ((ks, bool(se) and S['State'] in se[0]),                                     # GR40 items 1-2, GR76
              (kd, bool(de) and D['State'] in de[1] and not (de[0] == 'key' and D['KeyType'] == 1)))
        bad = [e for e, good in ok if not good] or ([] if de[0] in ADMITTED[se[1]] else [ks, kd])   # GR40 item 3
        if bad:
            for e in bad:
                self._enter_error(e, INVALID)
            return 'invalid'
        key, dlen, secret = de[0] == 'key', MACHINES[D['Machine']].key_len, se[1] == 'secret'
        slen = MACHINES[M_KEX].state_len if secret else 1 << 30     # a field, or the unbounded keystream
        if self.klstart or (length < dlen or slen < dlen if key else length != slen):   # GR40 items 5 and 7, GR43
            self._enter_error(kd, INVALID)
            return 'invalid'
        # GR40 item 6 binds no toy pair: both sources suffice
        if secret:                                                  # GR43 restricted (GR41); GR44 unrestricted
            if sc_rank(D['SCProtection']) < sc_rank(S['SCProtection']):   # GR41: never to a weaker level
                self._enter_error(kd, PRIV)
                return 'privilege_violation'
            union = loc_union(D['Locality'], S['Locality'])
            if union is None or self.locality_problem(union):        # a failed narrowing (<<KLE-Metadata-narrowing>>)
                self._enter_error(kd, PRIV)
                return 'privilege_violation'
            D.update(UsagePolicy=narrow_up(D['UsagePolicy'], S['UsagePolicy']), Locality=union)
            if self.zklexpire:
                D['ExpirationDate'] = min([x for x in (D['ExpirationDate'], S['ExpirationDate']) if x] or [0])
        n = min(length, dlen) if key else length                    # GR39 eff_length
        scl, dcl = self.lockers[ks], self.lockers[kd]
        if secret:                                                  # GR39: a field source does not advance
            data = MACHINES[M_KEX].get_state(scl)[:n]
        else:                                                       # whole blocks, the unused bytes discarded
            data = b''.join(MACHINES[M_CIPHER].process(self, scl, bytes(16)) for _ in range(-(-n // 16)))[:n]
        if key:
            dcl.c1 = data + dcl.c1[dlen:]
        else:
            for x in data:
                MACHINES[M_XOF].absorb(self, dcl, bytes([x]))
        self._dirty(ks)
        self._dirty(kd)
        return 'transferred'

    # -- the serialized image S (<<KLE-serialized-image>>) and the locker transfers
    def _s_get(self, k, j):
        cl = self.lockers[k]
        off, _, _, iend = self.layout(cl.mdh)
        if j >= iend: return bytes(16)
        if j < off: return v2b((self.siv, self.impqual, self.siv2)[j // 16], 16)
        return bytes(cl.img[j - off:j - off + 16]).ljust(16, b'\0')
    def _s_put(self, k, j, blk):
        cl = self.lockers[k]
        off, _, _, iend = self.layout(cl.mdh)
        if j < off:
            setattr(self, ('siv', 'impqual', 'siv2')[j // 16], b2v(bytes(blk)))
        elif j < iend:
            cl.img[j - off:j - off + 16] = bytes(blk)
    def _xfer_pre(self, writing, xl=0):                             # GR5; <<KLE-mv-locker-checks>>: GR31
        k = self.klnamedlocker                                    # the locker is never an operand
        self._pre()
        self._off(k)
        if xl: raise Trap('illegal', 2)                             # Xl must be 0 for a locker transfer, before GR34
        st = self.lockers[k].mdh['State']
        if st == UNCONF or st in ERROR_STATES: return None          # GR33: no operation
        if st not in ((PROV, IMP, PPI_IMP) if writing else (EXP, PPI_EXP)) or self.klstart % 16:
            raise Trap('illegal', 2)
        return k
    def _serial(self, end, step, fault, act, halt_after, restart):
        j = self.klstart
        while j < end:
            f = fault(j)
            if f or (halt_after is not None and j - self.klstart >= halt_after):
                rs = restart and not f and self.restarts < MAX_RESTARTS     # GR48: no restart on a fault, and
                self.restarts += rs                                 # option 3 once the bound is reached
                self.klstart = 0 if rs else j
                if f: raise Trap(f[0], tval=f[1])
                return 'halted'
            act(j)
            j += step
        self.klstart = self.restarts = 0
        return 'done'
    def _mem(self, mem, addr, xl=0, halt_after=None, restart=False, store=False):   # <<KLE-instruction-load>>, -store
        if self.klnamedlocker == NONE:                            # GR5: no named locker: kl.input / kl.output
            if xl == 0:                                             # GR34: a no-op, before Zklio and GR15
                self._pre()
                self.klstart = 0
                return 'empty'
            return self._io(mem, addr, xl, halt_after, restart, out=store)
        if not self.zklmem_hw: raise Trap('illegal', 1)
        k = self._xfer_pre(not store, xl)
        kind = 'store' if store else 'load'
        if addr % 16: raise Trap(f'{kind}_misaligned', tval=addr)
        if k is None:                                               # GR33: no locker operation
            self.klstart = 0
            return 'noop'
        _, _, isize, iend = self.layout(self.lockers[k].mdh)
        def act(j):
            mem.accesses += 1
            if store:
                mem.write(addr + j, self._s_get(k, j))
            else:
                self._s_put(k, j, mem.read(addr + j, 16))
                self._dirty(k)
        return self._serial(isize if store else iend, 16, lambda j: mem.fault(addr + j, 16, kind), act,
                            halt_after, restart)
    load, store = functools.partialmethod(_mem, store=False), functools.partialmethod(_mem, store=True)
    input_, output = load, store                                    # kl.input, kl.output: aliases (GR5)
    def _mv_pre(self, writing, vec_len=None, sew=8):
        if not self.zklmv or (vec_len is not None and not self.zklv): raise Trap('illegal', 1)
        if vec_len is not None and (sew not in KLV_SEWS or vec_len % 16 or self.vstart * sew // 8 % 16):
            raise Trap('illegal', 1)
        if self.klnamedlocker == NONE:                            # GR33: no locker under management: a no-op
            self._pre()
            return None, None
        k = self._xfer_pre(writing)
        return k, None if k is None else self.layout(self.lockers[k].mdh)[3]
    def mv_in(self, value):                                         # kl.mvin Xs2
        k, iend = self._mv_pre(True)
        if k is None: return 'noop'
        if self.klstart >= iend: return 'nothing'
        self._s_put(k, self.klstart, v2b(value, 16))
        self.klstart += 16
        self._dirty(k)
        return 'moved'
    def mv_out(self):                                               # kl.mvout Xd
        k, iend = self._mv_pre(False)
        if k is None or self.klstart >= iend: return 0
        self.klstart += 16
        return b2v(self._s_get(k, self.klstart - 16))
    def mv_vec(self, vec, sew=8, halt_after=None, out=False):       # kl.mvin Vs2 / kl.mvout Vd
        k, iend = self._mv_pre(not out, len(vec), sew)
        nb = sew // 8
        if k is None:
            if out:
                vec[self.vstart * nb:] = bytes(len(vec) - self.vstart * nb)
            self.vstart = 0
            return 'noop'
        pos, j = self.vstart * nb, self.klstart
        if pos >= len(vec): return 'noop'
        if j >= iend:
            if out:
                vec[pos:] = bytes(len(vec) - pos)
            self.vstart = 0
            return 'zeros' if out else 'nothing'
        start = pos
        while pos < len(vec):
            if halt_after is not None and pos - start >= halt_after:
                self.klstart, self.vstart = j, pos // nb
                if not out:
                    self._dirty(k)
                return 'halted'
            if out:
                vec[pos:pos + 16] = self._s_get(k, j) if j < iend else bytes(16)
            elif j < iend:
                self._s_put(k, j, vec[pos:pos + 16])
            j, pos = min(j + 16, max(iend, j)), pos + 16
        self.klstart, self.vstart = j, 0
        if not out:
            self._dirty(k)
        return 'moved'
    def mv_iobuf(self, out=False):                                  # kl.mvin KLIOBUF / kl.mvout KLIOBUF
        if not self.zklmv: raise Trap('illegal', 1)
        self._pre()
        if self.klnamedlocker == NONE:                            # GR33: a no-op; kl.mvout zeros its destination
            if out and self.zklio:
                self.kliobuf[:self.kliobuftop] = bytes(self.kliobuftop)
            return 'noop'
        if not self.zklio or not self.kliobuflen: raise Trap('illegal/2')     # GR15: unconfigured (always without Zklio)
        if self.kliobuftop % 16: raise Trap('illegal', 2)
        k, n = self._xfer_pre(not out), self.kliobuftop
        if k is None:
            if out:
                self.kliobuf[:n] = bytes(n)
            return 'noop'
        iend, j = self.layout(self.lockers[k].mdh)[3], self.klstart
        if j >= iend:
            if out:
                self.kliobuf[:n] = bytes(n)
            return 'zeros' if out else 'nothing'
        for pos in range(0, n, 16):                                 # a vector variant with vstart 0, vl*SEW/8 = top
            if out:
                self.kliobuf[pos:pos + 16] = self._s_get(k, j) if j < iend else bytes(16)
            elif j < iend:
                self._s_put(k, j, self.kliobuf[pos:pos + 16])
            j = min(j + 16, max(iend, j))
        self.klstart = j
        if not out:
            self._dirty(k)
        return 'moved'

    # -- KLIOBUF  <<KLE-iobuf-transfer-window>>
    def _io(self, mem, addr, xl, halt_after=None, restart=False, out=False):
        self._pre()
        if not self.zklio: raise Trap('illegal', 2)                 # second group: depends on klnamedlocker = 32
        if not self.kliobuflen: raise Trap('illegal/2')                       # GR15: unconfigured KLIOBUF
        end = min(xl, self.kliobuftop)
        if xl == 0 or self.klstart >= end:
            self.klstart = 0                                        # transfers nothing, retires
            return 'empty'
        def act(j):
            if out:
                mem.buf[addr + j] = self.kliobuf[j]
            else:
                self.kliobuf[j] = mem.buf[addr + j]
        return self._serial(end, 1, lambda j: mem.fault(addr + j, 1, 'store' if out else 'load'), act,
                            halt_after, restart)

# ---------------------------------------------------------------- software sequences

fresh = Unit

def rq(**kw):
    """A kl.restrict* request: all-ones _MachinePolicy_ and _UsagePolicy_ leave the field unchanged."""
    return md(**{'MachinePolicy': 0b11, 'UsagePolicy': 0b11111, **kw})

def cipher(**kw):
    return md(**{'Machine': M_CIPHER, 'MachinePolicy': 3, **kw})

def xof(**kw):
    return md(**{'Machine': M_XOF, **kw})

def sig(**kw):
    return md(**{'Machine': M_SIG, 'MachinePolicy': 3, **kw})

def pi_content(m, seed=0x31):
    return bytes(seed + 7 * i & 0xFF for i in range(MACHINES[m['Machine']].pi_content_size(m)))

def finished(u, saved):
    """Management code restores klnamedlocker when it is done (<<KLE-CSR-klnamedlocker>>)."""
    u.klnamedlocker = saved

def provision(u, k, m, content=None, via='load', form='C', done_form='C'):
    content, saved = pi_content(m) if content is None else content, u.klnamedlocker
    u.mgmt(k, PROV, m, form=form)
    if u.lockers[k].mdh['State'] == PROV:
        if via == 'load':
            u.load(Memory(content), BASE)
        elif via == 'mv':
            for o in range(0, len(content), 16):
                u.mv_in(b2v(content[o:o + 16]))
        else:
            u.vstart = 0
            u.mv_vec(bytearray(content), sew=32)
        u.mgmt(k, END, form=done_form)
    finished(u, saved)
    return u.lockers[k].mdh['State']

def listing_provision(clear_at=lambda s: False, m=None, on_trap=None, limit=8, error_at=None, start=None, p=0,
                      race=False):
    """Zklmem provisioning of <<KLE-management-code-snippets>>; clear_at(boundary) is a handler's kl.clear,
    on_trap(u, tag) a handler that returns past a trapping opening kl.mgmt; start: a CC already in the locker;
    p: the locker number, 32 for the named locker (locker 0); race: a kl.clear between the preamble and the opening."""
    u, m, step, raced = fresh(), m or cipher(), 0, []
    if start is not None:
        provision(u, 0, start)
    if p == 32:
        u.csrs(klnamedlocker=0)                                   # the caller has named locker 0
    def opening():
        if p < 32:
            u.csrs(klnamedlocker=p)                               # select_locker at restart: name locker p
        if race and not raced:
            raced.append(u.clear(0))                              # a handler clears it before the opening
        tag = trap_of(u.mgmt, 'KLNL', PROV, m)
        if tag:
            on_trap(u, tag)
    ops = (opening, lambda: u.load(Memory(pi_content(m)), BASE), lambda: u.mgmt('KLNL', END))
    for restarts in range(limit):
        if p == 32 and u.klnamedlocker == NONE:
            return 'no_locker', restarts                            # select_locker: error to the caller
        for op in ops:
            for act in (op, None):                                  # the instruction, then its kl.getst
                if clear_at(step):
                    u.clear(0)
                if step == error_at:
                    u.setst(0, OOM)                                 # a handler sets an Error State
                step += 1
                if act:
                    trap_of(act)                                    # a trap returns to the listing's kl.getst
            st = u.getst('KLNL')                                      # kl.getst t2, KLNL
            if st == UNCONF:
                break                                               # beqz t2, restart
            if st in ERROR_STATES:
                return st, restarts                                 # beq t3, t2, handle_errors
        else:
            return u.getst('KLNL'), restarts                          # finished: KLNL still names the locker
    return 'livelock', limit

def listing_export(clear_at=lambda s: False, error_at=None):
    """Zklmem export of <<KLE-management-code-snippets>>: (final State, image), or ('lost', None) at a check."""
    u, mem, step = pv(fresh(), 0, cipher()), Memory(), 0
    def tick():
        nonlocal step
        if clear_at(step):
            u.clear(0)
        if step == error_at:
            u.setst(0, OOM)
        step += 1
    u.csrs(klnamedlocker=0)                                       # kl.setnl t0
    tick()
    n = u.size(k='KLNL')
    tick()
    m = u.getmd('KLNL')
    if not n or m['State'] == UNCONF: return 'lost', None           # kl.size 0, or State 0 in the fetched MDH
    for op in (lambda: u.mgmt('KLNL', EXP), lambda: u.store(mem, BASE), lambda: u.mgmt('KLNL', END, m)):
        tick()
        trap_of(op)                                                 # a trap returns to the listing's kl.getst
        tick()
        st = u.getst('KLNL')
        if st == UNCONF: return 'lost', None                        # beqz t2, handle_errors
        if st in ERROR_STATES: return 'error', st                   # beq t3, t2, handle_errors
    return u.getst('KLNL'), mdh_bytes(m) + mem.read(BASE, n - 16)

def listing_checked(kind, checks, at, event='clear', via='load'):
    """A KLNL routine of <<KLE-management-code-snippets>> (kind 'prov', 'imp' or 'exp', transfers via 'load' or 'mv')
    that reads the _State_ after every step (checks 'each'), only after its last kl.mgmt ('last'), or only before it
    ('before-last'). At boundary `at`, a locker in a Configuration State is cleared by a handler that then restores 32
    ('clear'; for an export, against Rule SR8), or set to Out of Memory by a failed context restore ('error').
    Returns 'ok', 'restarted' (then Ready), 'reported', 'trap', or 'silent': finished without a Ready locker or an
    importable image."""
    img = export(pv(fresh(), 0, cipher()), 0) if kind == 'imp' else None
    u, m, step = pv(fresh(), 0, cipher()) if kind == 'exp' else fresh(), cipher(), 0
    def boundary():
        nonlocal step
        if step == at and u.lockers[0].mdh['State'] in CONFIG:
            if event == 'clear':
                u.clear(0)
                u.csrs(klnamedlocker=NONE)
            else:
                u.setst(0, OOM)
        step += 1
    if kind == 'exp':
        u.csrs(klnamedlocker=0)                                   # kl.setnl t0
        n, m, mem, out = u.size(k='KLNL'), u.getmd('KLNL'), Memory(), []
        xfer = [lambda: u.store(mem, BASE)] if via == 'load' else [lambda: out.append(u.mv_out())] * ((n - 16) // 16)
        ops = [lambda: u.mgmt('KLNL', EXP)] + xfer + [lambda: u.mgmt('KLNL', END, m)]
    else:
        data, ml = (pi_content(m), m) if kind == 'prov' else (img[16:], unpack(b2v(img[:16])))
        xfer = [lambda: u.load(Memory(data), BASE)] if via == 'load' else \
            [lambda o=o: u.mv_in(b2v(data[o:o + 16])) for o in range(0, len(data), 16)]
        ops = ([lambda: u.mgmt('KLNL', PROV if kind == 'prov' else IMP, ml)] + xfer
               + [lambda: u.mgmt('KLNL', END, None if kind == 'prov' else ml)])
    checked = range(len(ops)) if checks == 'each' else [len(ops) - (1 if checks == 'last' else 2)]
    for restarts in range(4):
        if kind != 'exp':
            u.csrs(klnamedlocker=0)                               # kl.setnl t0 at restart
        restart = False
        for i, op in enumerate(ops):
            boundary()
            if trap_of(op): return 'trap'
            if i == len(ops) - 1:
                boundary()
            if i in checked:
                st = u.getst('KLNL')                                # kl.getst t2, KLNL
                if st in ERROR_STATES or st == UNCONF and kind == 'exp': return 'reported'
                restart = st == UNCONF
                if restart: break                                   # beqz t2, restart
        if not restart: break
    if kind == 'exp':
        image = mdh_bytes(m) + (mem.read(BASE, n - 16) if via == 'load' else b''.join(v2b(x, 16) for x in out))
        return 'ok' if import_(fresh(), 3, image) == READY else 'silent'
    return 'silent' if u.getst(0) != READY else 'restarted' if restarts else 'ok'

def pv(u, k, m, content=None):
    provision(u, k, m, content)
    return u

def opened(imm=PROV, m=None, k=0, **kw):
    u = fresh(**kw)
    u.mgmt(k, imm, cipher() if m is None else m)
    return u

def export(u, k, via='store', form='C'):
    """MDH, then the image; an Error-State locker is its MDH alone."""
    m, n, saved = u.getmd(k), u.size(k=k), u.klnamedlocker
    if m['State'] in ERROR_STATES: return mdh_bytes(m)
    u.mgmt(k, EXP)
    if via == 'store':
        mem = Memory()
        u.store(mem, BASE)
        img = mem.read(BASE, n - 16)
    else:
        img = b''.join(v2b(u.mv_out(), 16) for _ in range(16, n, 16))
    u.mgmt(k, END, m, form=form)
    finished(u, saved)
    return mdh_bytes(m) + img

def import_(u, k, img, via='load', form='C', halt_after=None):
    ml, saved = unpack(b2v(img[:16])), u.klnamedlocker
    u.mgmt(k, IMP, ml, form=form)
    if u.lockers[k].mdh['State'] not in CONFIG:
        finished(u, saved)
        return u.lockers[k].mdh['State']
    if via == 'load':
        if u.load(Memory(img[16:]), BASE, halt_after=halt_after) == 'halted': return 'halted'
    else:
        for o in range(16, len(img), 16):
            u.mv_in(b2v(img[o:o + 16]))
    u.mgmt(k, END, ml, form=form)
    finished(u, saved)
    return u.lockers[k].mdh['State']

def export_pccc(u, k, saved):
    """Store a locker already opened for a nested export and complete it with `saved`."""
    n, out = u.size(k=k), Memory()
    u.store(out, BASE)
    u.mgmt(k, END, saved)
    return mdh_bytes(saved) + out.read(BASE, n - 16)

def snapshot(u):
    return (tuple(pack(c.mdh) for c in u.lockers),
            tuple((c.c1, c.c2, c.img and bytes(c.img), c.alloc) for c in u.lockers),
            u.siv, u.impqual, u.siv2, u.klstart, u.klnamedlocker, u.kliobuflen, u.kliobuftop, bytes(u.kliobuf))

def ready_cipher(u, k, **kw):
    """A cipher locker in State ENCRYPT; a _UsagePolicy_ is applied afterwards with kl.restricth."""
    up = kw.pop('UsagePolicy', None)
    provision(u, k, cipher(**kw))
    u.setst(k, ToyCipher.ENCRYPT, 0x77)
    if up is not None:                                          # narrowed from every mode, Debug excluded
        u.restrict(k, rq(UsagePolicy=up), 'h')
    return u

def rc(k=0, unit=None, **kw):
    return ready_cipher(unit or fresh(), k, **kw)

def final_cipher(final, **kw):
    w = pv(fresh(), 0, cipher(**kw))
    tag = MACHINES[M_CIPHER].verify_tag(w, w.lockers[0])
    w.setst(0, ToyCipher.VERIFY, tag if final == SUCCESS else tag ^ 1)
    return w

def xof_squeezing(u, k, seed=b'shared secret'):
    provision(u, k, xof())
    u.exec_(k, 'B', vin=bytearray(seed))
    u.setst(k, ToyXof.FINAL)
    return u

def interrupted_import(u, k, halt_after, decrypt=False):
    """An import into K(k) halted after `halt_after` bytes: (source unit, ml, memory, SCC)."""
    src = pv(fresh(), 0, cipher(SCProtection=1, Locality=loc(boot=1)))
    if decrypt:
        src.setst(0, ToyCipher.DECRYPT, 3)
    scc = export(src, 0)
    ml, mem = unpack(b2v(scc[:16])), Memory(scc[16:])
    u.mgmt(k, IMP, ml)
    u.load(mem, BASE, halt_after=halt_after)
    return src, ml, mem, scc

def ex(u, k, form='A', n=16, **kw):
    return u.exec_(k, form, vin=bytearray(n), vout=bytearray(n), **kw)

def white_box(st, img=None):
    """A locker forced into State st by writing the MDH directly."""
    u = pv(fresh(), 0, cipher())
    u.mgmt(0, EXP)
    u.lockers[0].mdh['State'] = st
    if img is not None:
        u.lockers[0].img = bytearray(img)
    return u

# ================================================================ tests

def t_mdh():
    section('MDH layout  <<KLE-metadata-header>>')
    cover = ovl = 0
    for _, hi, lo in MDH_FIELDS:
        m = ((1 << hi - lo + 1) - 1) << lo
        ovl, cover = ovl | cover & m, cover | m
    eq('fields tile [127:0] without overlap', (sum(hi - lo + 1 for _, hi, lo in MDH_FIELDS), ovl, cover),
       (128, 0, MASK128))
    bits = [(n, lo + b, 1 << b) for n, (hi, lo) in MDH_FIELD.items() for b in range(hi - lo + 1)]
    check('walking ones: each field bit at its position, no bleed',
          all(pack(md(**{n: v}, **z)) == 1 << p and unpack(1 << p) == md(**{n: v}, **z)
              for n, p, v in bits for z in [{'UsagePolicy': 0} if n == 'Machine' else {}]))
    ones = md(**{n: (1 << hi - lo + 1) - 1 for n, (hi, lo) in MDH_FIELD.items()}, res=RES_MASK)
    eq('all-ones MDH packs to ones(128) and round trips', (pack(ones), unpack(MASK128)), (MASK128, ones))
    eq('each reserved bit is detected; 116-127 lie above [63:0]',
       ([bool(unpack(1 << hi)['res']) for n, hi, lo in MDH_FIELDS if n is None], unpack(1 << 116)['res'] & MASK64),
       ([True] * 4, 0))
    w = lambda n: MDH_FIELD[n][0] - MDH_FIELD[n][1] + 1
    u = fresh()
    u.mgmt(4, IMP, dict(ones, State=INVALID))
    eq('kl.getst / kl.getstx expansions; kl.getmdl is MDH[63:0]', (u.getst(4), u.getstx(4), u.getmdl(4)),
       (INVALID, 2, pack(u.getmd(4)) & MASK64))
    eq('identifier [15:0], ADSDropped 47, Version [63:62], UsagePolicy and Locality widths',
       (MDH_FIELD['MachineExtension'][0], MDH_FIELD['ADSDropped'], MDH_FIELD['Version'], w('UsagePolicy'),
        w('Locality')), (15, (47, 47), (63, 62), 5, 9))
    check('the length-rule and kl.size fields lie in MDH[63:0]',
          all(MDH_FIELD[f][0] <= 63 for f in ('Machine', 'MachinePolicy', 'MachineExtension', 'KeyType',
                                              'StateExtension', 'AuxDataLen', 'ADSDropped', 'SCProtection',
                                              'State', 'Version')))
    years, rem = divmod(2 ** w('ExpirationDate') / 24, 365.2425)
    eq('ExpirationDate ~119 years 7 months; AuxDataLen max 262,128 bytes',
       (int(years), int(rem / (365.2425 / 12)), 16 * ((1 << w('AuxDataLen')) - 1)), (119, 7, 262128))
    eq('Unconfigured kl.getmd* all zero (GR33); MDH image little-endian; 6-bit State',
       (pack(u.getmd(0)), mdh_bytes(md(Machine=0x123, UsagePolicy=0)), bin_(END + 1, w('State'))), (0, v2b(0x123, 16), 0))

def t_states():
    section('States  <<KLE-State-field>>, <<KLE-SC-sealing-status>>')
    parts = [{0}, set(VALID), set(PARTIAL)]
    eq('Empty (0), Valid (1-55), Configuration (56-63) partition State; '
       'Complete = Valid + Error; 56-60 used, 61-63 reserved',
       (sum(map(len, parts)), set().union(*parts), set(COMPLETE), set(CONFIG) <= parts[2]),
       (64, set(range(64)), parts[1] | set(ERROR_STATES), True))
    eq('Ready, Success, Failure; Error States: State 0, StateExtension 1-6; Configuration base types',
       (READY, SUCCESS, FAILURE, [state_fields(s) for s in (UNSUP, INVALID, OOM, AUTH, PRIV, EXPIRED)],
        [BASE_TYPE[s] for s in CONFIG]),
       (1, 54, 55, [{'State': 0, 'StateExtension': c} for c in range(1, 7)], ['pi', 'scc', 'scc', 'pi', 'pi']))
    eq('kl.mgmt immediates 56, 57, 58, 63; 59-62 reserved',
       [i for i in range(56, 64) if trap_of(fresh().mgmt, 0, i, md()) != 'illegal/1'], [56, 57, 58, 63])
    def st_46_47(u, i):
        return attempt(u.setst, 0, i), u.getst(0)
    eq('kl.setst #54, #55 (GR25): Ready, Encrypt, Success, Failure -> Invalid (GR22); Unconfigured, Error State: '
       'no operation (GR33); Provisioning: as any usage instruction, an exception, State kept (GR30)',
       [st_46_47(mk(), i) for i in (SUCCESS, FAILURE) for mk in (lambda: pv(fresh(), 0, cipher()), rc,
        lambda: final_cipher(SUCCESS), lambda: final_cipher(FAILURE), fresh,
        lambda: (lambda u: (u.setst(0, OOM), u)[1])(pv(fresh(), 0, cipher())), opened)],
       [('invalid', INVALID)] * 4 + [('noop', UNCONF), ('noop', OOM), ('privilege_violation', PROV)]
       + [('invalid', INVALID)] * 4 + [('noop', UNCONF), ('noop', OOM), ('privilege_violation', PROV)])
    macro = lambda st, x: 'other' if st else 'unconfigured' if x == 0 else 'error'     # check_state
    model = lambda t: 'unconfigured' if t == 0 else 'error' if t > 63 else 'other'
    eq("check_state (kl.getst, then kl.getstx at State 0) tells Unconfigured, Error States and the others apart",
       [macro(s, x) for s in range(64) for x in range(16)],
       [model(from_fields(s, x)) for s in range(64) for x in range(16)])

def t_validity():
    section('Metadata validity  <<KLE-Metadata-validity>>, <<KLE-MVR-open>>')
    rows = []
    for kw in (dict(res=1 << 46), dict(res=1 << 116), dict(AuxDataLen=1), dict(ADSDropped=1), dict(AuxDataLen=2),
               dict(MachinePolicy=0), dict(KeyType=3), dict(Locality=loc(boot=3)),
               dict(Version=1), dict(Version=2), dict(Version=3, Locality=loc(hw1=3)), dict(SCProtection=3),
               dict(State=READY)):
        u = rc(3).csrs(klstart=16)
        rows.append((u.mgmt(3, PROV, cipher(**kw)), pack(u.getmd(3)), u.lockers[3].alloc, u.klnamedlocker, u.klstart))
    eq('13 invalid PIs -> Invalid, other fields zero, no capacity, klnamedlocker keeps naming it, klstart 0', rows,
       [('invalid', pack(md(State=INVALID)), 0, 3, 0)] * 13)
    eq('KeyType 1 or 2 for a Machine without a key field is invalid; KeyType 0 provisions it',
       [rc(3).mgmt(3, PROV, md(Machine=M_HASH, KeyType=1)), rc(3).mgmt(3, PROV, md(Machine=M_HASH, KeyType=2)),
        rc(3).mgmt(3, PROV, md(Machine=M_HASH))], ['invalid', 'invalid', 'opened'])
    eq('KeyType 2 opens a provisioning; outside a PI, at import, it is invalid (<<KLE-KeyType-field>>)',
       [rc(3).mgmt(3, PROV, cipher(KeyType=2)), rc(3).mgmt(3, IMP, cipher(State=READY, KeyType=2))],
       ['opened', 'invalid'])
    norand = rc(3)
    norand.random_keys = False
    eq('KeyType 2 without random key generation -> kl_exc_unsupported, kl.avail 0',
       [trap_of(norand.mgmt, 3, PROV, cipher(KeyType=2)), norand.avail('C', m=cipher(KeyType=2))],
       ['unsupported', 0])
    nosks = rc(3)
    nosks.sks = {}
    eq('KeyType 1 without SKID support -> kl_exc_unsupported, kl.avail 0',
       [trap_of(nosks.mgmt, 3, PROV, cipher(KeyType=1)), nosks.avail('C', m=cipher(KeyType=1))],
       ['unsupported', 0])
    eq('ExpirationDate without Zklexpire, unresolvable Locality -> Invalid',
       [fresh(zklexpire=False).mgmt(0, PROV, cipher(ExpirationDate=9)),
        fresh(hw_missing=(0, 1, 2)).mgmt(0, PROV, cipher(Locality=loc(hw1=1)))], ['invalid'] * 2)
    u = fresh()
    eq('GR10 ChipFamScrt/ChipScrt valid, SiPScrt (even substituted) not; AuxInfo and MachineUse unchecked '
       '(<<KLE-MachineUse>>); zero signature bits',
       [provision(u, 0, md(Machine=M_CUSTOM, MachinePolicy=1, Locality=loc(hw1=2))),
        provision(u, 1, md(Machine=M_CUSTOM, MachinePolicy=1, Locality=loc(hw1=3))),
        provision(fresh(hw_missing=(0,)), 1, md(Machine=M_CUSTOM, MachinePolicy=1, Locality=loc(hw1=1))),
        provision(u, 2, cipher(AuxInfo=5, MachineUse=7)), provision(u, 3, sig(MachinePolicy=0)),
        fresh().mgmt(0, IMP, cipher(State=2, AuxInfo=5, MachineUse=7))],
       [READY, READY, INVALID, READY, READY, 'opened'])
    rows = []
    for m in (md(Machine=M_ABSENT, MachinePolicy=1), cipher(MachineExtension=1), xof(MachinePolicy=2),
              md(Machine=M_ABSENT, State=5)):
        u = rc(5).csrs(klstart=32)
        rows.append((trap_of(u.mgmt, 5, PROV, m), pack(u.getmd(5)), u.klstart))
    eq('unsupported (also if invalid) -> kl_exc_unsupported, locker zeroized, klstart cleared', rows,
       [('unsupported', 0, 0)] * 4)
    eq('import of unsupported Metadata -> kl_exc_unsupported',
       trap_of(fresh().mgmt, 0, IMP, md(Machine=M_ABSENT, State=2)), 'unsupported')
    got = {st: fresh().mgmt(0, IMP, cipher(State=st)) for st in (0, 61, 62, 63, 4, 7, 45, 48, 53, 1, 2, 3, 54, 55, 56, 57, 58,
                                                                 59, 60)}
    eq('import ml.State 0, 61-63, undefined -> Invalid; Valid and Configuration open', got,
       {st: 'invalid' if st in (0, 61, 62, 63, 4, 7, 45, 48, 53) else 'opened' for st in got})
    eq('SCC MDH may carry AuxDataLen >= 2 and ADSDropped; a pi-base PCCC may not',
       [fresh().mgmt(0, IMP, cipher(State=2, AuxDataLen=4, ADSDropped=1)),
        fresh().mgmt(0, IMP, cipher(State=PROV, AuxDataLen=2)), fresh().mgmt(0, IMP, cipher(State=PROV, ADSDropped=1))],
       ['opened', 'invalid', 'invalid'])
    stx = [cipher(State=2, StateExtension=1), xof(State=ToyXof.FINAL, StateExtension=1),
           cipher(State=57, StateExtension=0xF),
           sig(State=58, StateExtension=6), cipher(State=2, StateExtension=2),
           cipher(State=READY, StateExtension=1), sig(State=2, StateExtension=1), xof(State=2, StateExtension=8)]
    eq('import and kl.size: a StateExtension the Machine uses in that State, or any in a Configuration State, '
       'opens; any other is invalid (also bit 0 in Ready, where no state block is held)',
       [(fresh().mgmt(0, IMP, m), fresh().size('B', lo=pack(m) & MASK64) > 0) for m in stx],
       [('opened', True)] * 4 + [('invalid', False)] * 4)
    u = opened(m=cipher(MachineUse=0xBEEF))
    eq('a PI MachineUse is ignored and zeroed by provisioning; a PI with a non-zero StateExtension is an Error State, invalid',
       (u.getmd(0)['StateExtension'], u.getmd(0)['MachineUse'], u.getst(0),
        fresh().mgmt(0, PROV, cipher(StateExtension=0xF))), (0, 0, PROV, 'invalid'))
    need = MACHINES[M_CIPHER].clf_capacity(cipher())
    u = fresh(clf_total=need - 1).csrs(klnamedlocker=0)
    eq('no KLF capacity: kl_exc_out_of_memory, Unconfigured, klnamedlocker names the locker',
       (trap_of(u.mgmt, 0, PROV, cipher()), u.getst(0), u.klnamedlocker), ('out_of_memory', 0, 0))
    u = fresh(clf_total=need)
    eq('exactly enough capacity; an Error-State locker holds none (GR36)',
       (provision(u, 0, cipher()), u.setst(0, INVALID), u.lockers[0].alloc, u.clf_free()),
       (READY, 'error state', 0, need))
    odd = md(Machine=M_ABSENT, State=AUTH, res=5 << 116, KeyType=3, ExpirationDate=7, AuxDataLen=9, ADSDropped=1,
             Locality=loc(boot=3))
    u = fresh(zklexpire=False)
    eq('the short import applies no validity check', (u.mgmt(0, IMP, odd), u.getmd(0)),
       ('short import', dict(odd, AuxDataLen=0, ADSDropped=0)))
    u = fresh(zklexpire=False)
    eq('the short import of an Error-State MDH with Version 3, invalid, installs Invalid and Version 0 (GR36)',
       (u.mgmt(0, IMP, dict(odd, Version=3)), u.getst(0), u.getmd(0)['Version']), ('short import', INVALID, 0))
    v3 = md(Machine=M_ABSENT, Version=3, State=AUTH, AuxDataLen=4)
    eq('kl.size of a supplied Error-State MDH with Version 3 is 16, as the short import reads (B, C; GR73)',
       [u.size('C', m=v3), u.size('B', lo=pack(v3) & MASK64)], [16, 16])
    eq('kl.size of a supplied, otherwise invalid Error-State MDH is 16 (B, C; GR73)',
       [u.size('C', m=odd), u.size('B', lo=pack(odd) & MASK64)], [16, 16])

def t_lengths():
    section('Length rule, kl.size, kl.avail  <<KLE-length-rule>>, <<KLE-instruction-size>>')
    u, cm, base = fresh(), MACHINES[M_CIPHER], cipher()
    same = lambda f, **kv: all(f(**{k: v}) == f() for k, v in kv.items())
    check('PI length independent of SCProtection, StateExtension, MachineUse, policies, AuxInfo, State, Version',
          same(lambda **kw: cm.pi_content_size(cipher(**kw)), SCProtection=1, StateExtension=1, MachineUse=9,
               UsagePolicy=0b01000, Locality=2, ExpirationDate=5, AuxInfo=3, State=5, Version=1))
    eq('PI length depends on KeyType, 2 as 0; Content1 on StateExtension',
       (cm.pi_content_size(base), cm.pi_content_size(cipher(KeyType=1)), cm.pi_content_size(cipher(KeyType=2)),
        cm.content1_size(cipher(StateExtension=1)) - cm.content1_size(base)), (32, 16, 32, 16))
    check('SCC length independent of SCProtection, MachineUse, AuxInfo, UsagePolicy, Locality, ExpirationDate, State',
          same(lambda **kw: u.size_of(cipher(**{'State': 2, 'AuxDataLen': 4, **kw}), True), SCProtection=1,
               MachineUse=9, AuxInfo=5, UsagePolicy=0b01000, Locality=2, ExpirationDate=5, State=3))
    need, res = MACHINES[M_CIPHER].clf_capacity(cipher()), []
    for z in (True, False):
        u = fresh(clf_total=need, zero_alloc=z)
        provision(u, 0, cipher())
        old = bytes(u.klf[:need])
        u.clear(0)
        stale = bytes(u.klf[:need]) == old
        u.mgmt(1, PROV, cipher())
        res.append((stale, u.lockers[1].off, bytes(u.klf[:need]) == bytes(need), any(old)))
    eq('kl.clear frees KLF capacity without erasing it; capacity that kl.mgmt allocates next reads as zero '
       '(<<KLE-destructive-config>>); witness: without the zero fill, the freed key reappears in the next locker', res,
       [(True, 0, True, True), (True, 0, False, True)])
    u = fresh(clf_total=2 * need, zero_alloc=False)
    provision(u, 0, cipher())
    u.clear(0)
    u.zero_alloc = True
    provision(u, 1, cipher())
    eq('kl.clone allocates zeroed capacity, then copies the source in', (u.clone(2, 1), u.lockers[2].off,
       bytes(u.klf[u.lockers[2].off:u.lockers[2].off + need]) == bytes(u.klf[:need])), ('cloned', need, True))
    check('KLF capacity depends only on SCProtection and MachinePolicy',
          same(lambda **kw: cm.clf_capacity(cipher(**kw)), KeyType=1, StateExtension=3, AuxDataLen=7, ADSDropped=1,
               UsagePolicy=0b00000, ExpirationDate=9)
          and cm.clf_capacity(cipher(SCProtection=1)) != cm.clf_capacity(base)
          != cm.clf_capacity(cipher(MachinePolicy=1)))
    c1 = cm.content1_size(cipher(StateExtension=1))
    S = lambda **kw: u.size('C', m=cipher(**kw))
    eq('kl.size 0: Unconfigured; unsupported, invalid, 61-63, PI with ADS fields, undefined State',
       [u.size(k=0), u.size('C', m=md(Machine=M_ABSENT, MachinePolicy=1, State=2)), S(State=2, KeyType=2),
        S(State=61), S(State=62), S(State=63), S(AuxDataLen=2), S(ADSDropped=1), S(State=9, AuxDataLen=4)], [0] * 9)
    pi_ok, scc_ok = u.size('C', m=cipher()), u.size('C', m=cipher(State=2, AuxDataLen=4))
    eq('Forms B and C: State 0 is validated as at provisioning (a PI: no ADS fields), any other State as at import',
       [pi_ok > 0, S(AuxDataLen=4), scc_ok > 0, u.size('B', lo=pack(cipher()) & MASK64) == pi_ok,
        u.size('B', lo=pack(cipher(AuxDataLen=4)) & MASK64), S(KeyType=2) == pi_ok], [True, 0, True, True, 0, True])
    em = [md(Machine=M_ABSENT, State=s, res=1 << 46, AuxDataLen=1 + 8 * (s & 1), ADSDropped=s & 1)
          for s in ERROR_STATES]
    eq('kl.size 16 for any Error-State MDH, even invalid or unsupported; AuxDataLen, ADSDropped ignored (B, C)',
       [u.size('C', m=x) for x in em] + [u.size('B', lo=pack(x)) for x in em], [16] * 2 * len(em))
    eq('kl.size: Valid 32+c1 / 64+c1+c2 (ADSDropped keeps 64); 57, 58 SCC; 56, 59, 60, PI',
       [S(State=2, StateExtension=1), S(State=2, StateExtension=1, AuxDataLen=4),
        S(State=2, StateExtension=1, AuxDataLen=4, ADSDropped=1), S(State=57, AuxDataLen=4), S(State=58, AuxDataLen=4),
        S(State=56), S(State=59), S(State=60), S(), S(KeyType=1)],
       [32 + c1, 96 + c1, 64 + c1, 128, 128, 48, 48, 48, 48, 32])
    fb = fresh(slocality=0)
    ul, gr, hr = cipher(State=2, Locality=loc(sloc=1)), md(Machine=M_CUSTOM, MachinePolicy=1, State=READY), \
        cipher(State=2, res=1 << 116)
    eq('Form C checks [127:64] (Locality, GR10); Form B does not (nor a reserved bit above 63)',
       [fb.size('C', m=ul), fb.size('B', lo=pack(ul)), fb.size('C', m=gr), fb.size('B', lo=pack(gr)),
        fb.size('B', lo=pack(hr))], [0, 64, 0, 32 + MACHINES[M_CUSTOM].content1_size(gr), 64])
    eq('Form B: unsupported Version -> 0, an Error-State MDH -> 16 as in Form C',
       [fb.size('B', lo=pack(cipher(State=2, Version=1))), fb.size('B', lo=pack(cipher(State=INVALID, Version=1))),
        fb.size('C', m=cipher(State=INVALID, Version=1))], [0, 16, 16])
    eq('Form C of kl.size needs VL*SEW >= 128 (GR6)', trap_of(u.size, 'C', m=base, vec_bits=64), 'illegal/1')
    g = pv(fresh(), 0, cipher())
    before, g.vstart = g.getmd(0), 16
    eq('vstart != 0 on a vector form that produces no vstart value: illegal-instruction exception (GR7), no effect',
       [trap_of(g.size, 'C', m=base), trap_of(g.avail, 'C', m=base), trap_of(g.mgmt, 1, PROV, cipher(), form='B'),
        trap_of(g.setst, 0, ToyCipher.ENCRYPT, 1, form='B'), trap_of(g.restrict, 0, rq(UsagePolicy=0b11110), 'v'),
        g.getmd(0) == before, g.getst(1), g.vstart], ['illegal/1'] * 5 + [True, 0, 16])
    ok = []
    for adl, drop in ((0, 0), (4, 0), (4, 1), (6, 0)):
        for st in CONFIG:
            if not (BASE_TYPE[st] == 'pi' and adl):
                m = cipher(State=st, StateExtension=1, AuxDataLen=adl, ADSDropped=drop)
                off, _, isize, iend = u.layout(m)
                ok.append(off == (0 if BASE_TYPE[st] == 'pi' else 48 if adl else 16)
                          and isize == u.size('C', m=m) - 16 == iend)
    check('ContentOffset 0/16/48; image_size = kl.size - 16 = image_end within the maximum', all(ok))
    a = fresh()
    eq('kl.avail 1 for implemented combinations, else 0; 0 for an Unconfigured locker',
       ([a.avail('C', m=m) for m in (base, cipher(KeyType=1), cipher(KeyType=2), xof(),
                                     sig(MachinePolicy=0), cipher(SCProtection=2))],
        [a.avail('C', m=m) for m in (cipher(MachineExtension=2), cipher(KeyType=3), cipher(SCProtection=3),
                                     cipher(MachinePolicy=0), xof(MachinePolicy=3),
                                     md(Machine=M_ABSENT, MachinePolicy=1))],
        a.avail(k=0)), ([1] * 6, [0] * 6, 0))
    eq('kl.avail examines no other field but Version; Form B uses [63:0]; Version 1-3 -> 0',
       (a.avail('C', m=cipher(State=63, res=3 << 116, Locality=loc(boot=3))), a.avail('B', lo=pack(base)),
        [a.avail('C', m=cipher(Version=v)) for v in (1, 2, 3)]),
       (1, 1, [0, 0, 0]))
    em_ = fresh(kleemulation=True)
    rdy, uns = md(Machine=M_ABSENT, MachinePolicy=1, State=READY), md(Machine=M_ABSENT, MachinePolicy=1, State=UNSUP)
    eq('kleemulation: Forms B/C of kl.avail and kl.size trap on a non-native MDH; an Error-State MDH is sized 16; '
       'Form A and native MDHs unaffected; clear: 0',
       [trap_of(em_.size, 'C', m=rdy), trap_of(em_.size, 'B', lo=pack(rdy) & MASK64), trap_of(em_.avail, 'C', m=rdy),
        trap_of(em_.avail, 'B', lo=pack(uns) & MASK64), em_.size('C', m=uns), em_.size('B', lo=pack(uns) & MASK64),
        em_.avail('C', m=base), em_.avail('A', 0), fresh().size('C', m=rdy), fresh().avail('C', m=rdy)],
       ['illegal/2'] * 4 + [16, 16, 1, 0, 0, 0])
    odd_v = md(Machine=M_ABSENT, MachinePolicy=1, State=62, Version=1)
    eq('kleemulation: the Machine-independent items precede the lookup: a non-native MDH with State 62 '
       'and Version 1 returns 0 without trapping; with Version 0 and State Ready it traps',
       [em_.size('C', m=odd_v), em_.avail('C', m=odd_v), trap_of(em_.size, 'C', m=dict(odd_v, State=READY, Version=0))],
       [0, 0, 'illegal/2'])
    provision(a, 0, base)
    a.setst(0, EXPIRED)
    a.mgmt(1, PROV, cipher(KeyType=3))
    eq('Error-State locker: kl.avail Form A uses its fields; kl.size 16 (GR37)',
       (a.avail(k=0), a.avail(k=1), a.size(k=0), a.size(k=1)), (1, 0, 16, 16))

def t_usage():
    section('_UsagePolicy_  <<KLE-UsagePolicy>>')
    bit, bad, u = {'U': 1, 'VU': 1, 'VS': 2, 'HS': 4, 'S': 4, 'M': 8}, [], fresh()
    for up in range(32):
        for u.mode in list(bit) + ['D']:
            if u.usage_allowed(cipher(UsagePolicy=up)) != (bool(up & 16) if u.mode == 'D' else bool(up & bit[u.mode])):
                bad.append((up, u.mode))
    eq('enforcement matrix, 32 policies x 7 modes (Debug: bit 4 only)', bad, [])
    bad = []
    for up in range(32):
        for u.debug_prv in ('U', 'VS', 'S'):
            u.mode = 'D'
            if u.usage_allowed(cipher(UsagePolicy=up)) != (bool(up & 16) and bool(up & bit[u.debug_prv])):
                bad.append((up, u.debug_prv))
    del u.debug_prv
    eq('Debug mode authorized only below M-mode: bit 4 and the bit of the mode it executes in (KLE-UsagePolicy)', bad, [])
    u.mode = 'U'
    fw = cipher(UsagePolicy=0b11000)                                # M-mode-only key with the Debug grant
    u.mode = 'D'; u.debug_prv = 'S'; s_only = u.usage_allowed(fw)
    u.debug_prv = 'M'; m_auth = u.usage_allowed(fw)
    del u.debug_prv; u.mode = 'U'
    eq('M-mode-only key with bit 4: denied to a debugger authorized only for S-mode, granted in authenticated Debug mode',
       (s_only, m_auth), (False, True))
    u = rc(UsagePolicy=0b01110)
    u.mode = 'U'
    eq('denied mode: kl.exec, kl.setst, kl.clearads -> kl_exc_privilege_violation (GR19)',
       [trap_of(ex, u, 0), trap_of(u.setst, 0, READY), trap_of(u.setst, 0, CLEAR_ADS), u.getst(0)],
       ['privilege_violation'] * 3 + [ToyCipher.ENCRYPT])
    eq('not usage instructions: getmd, getst, size, avail, restrict, clone, error setst, mgmt, clear',
       [u.getmd(0)['Machine'], u.getst(0), u.size(k=0), u.avail(k=0), u.restrict(0, rq(UsagePolicy=0b11101), 'h'),
        u.getmd(0)['UsagePolicy'], u.clone(1, 0), u.setst(1, EXPIRED), export(u, 0)[:16] == mdh_bytes(u.getmd(0)),
        u.getst(0), u.setst(0, 0)],
       [M_CIPHER, ToyCipher.ENCRYPT, 80, 1, 'ok', 0b01100, 'cloned', 'error state', True, ToyCipher.ENCRYPT, 'cleared'])

def t_restrict():
    section('kl.restrict*  <<KLE-instruction-restrict>>')
    probe, bad = fresh(), []
    for cur in range(32):
        for req in range(32):
            for probe.mode in ('U', 'VS', 'HS', 'M', 'D'):
                if probe.usage_allowed(cipher(UsagePolicy=narrow_up(cur, req))) \
                        and not probe.usage_allowed(cipher(UsagePolicy=cur)):
                    bad.append((cur, req, probe.mode))
    eq('no UsagePolicy request widens the modes (32 x 32 x 5)', bad, [])

    def run(pi, req, which='v', enc=False, **ukw):
        u = pv(fresh(**ukw), 0, pi)
        if enc:
            u.setst(0, ToyCipher.ENCRYPT, 1)
        return u.restrict(0, req, which), u.getmd(0), u
    rows = [  # (PI, request, which, enter ENCRYPT, unit kwargs, result, field, value)
        (cipher(UsagePolicy=0b01110), rq(UsagePolicy=0b01011), 'v', 0, {}, 'ok', 'UsagePolicy', 0b01010),
        (cipher(UsagePolicy=0b11111), rq(UsagePolicy=0b01111), 'v', 0, {}, 'ok', 'UsagePolicy', 0b01111),
        (cipher(UsagePolicy=0b11111), rq(UsagePolicy=0), 'h', 0, {}, 'ok', 'UsagePolicy', 0),   # zero: no mode left
        (cipher(ExpirationDate=1000), rq(ExpirationDate=900), 'v', 0, {}, 'ok', 'ExpirationDate', 900),
        (cipher(ExpirationDate=1000), rq(ExpirationDate=2000), 'v', 0, {}, 'ok', 'ExpirationDate', 1000),
        (cipher(), rq(ExpirationDate=5), 'v', 0, {}, 'ok', 'ExpirationDate', 5),
        (cipher(), rq(ExpirationDate=5), 'v', 0, {'zklexpire': False}, 'invalid', 'State', INVALID),
        (cipher(SCProtection=2), rq(SCProtection=1), 'v', 0, {}, 'invalid', 'AuxDataLen', 0),
        (cipher(SCProtection=1), rq(SCProtection=1), 'v', 0, {}, 'invalid', 'State', INVALID),
        (cipher(), rq(SCProtection=3), 'v', 0, {}, 'invalid', 'State', INVALID),
        (cipher(SCProtection=1), rq(SCProtection=2), 'v', 0, {}, 'invalid', 'State', INVALID),
        (cipher(), rq(MachinePolicy=1), 'v', 0, {}, 'ok', 'MachinePolicy', 1),     # a clear bit removes a function
        (cipher(MachinePolicy=1), rq(MachinePolicy=1), 'v', 0, {}, 'ok', 'MachinePolicy', 1),  # already removed
        (cipher(MachinePolicy=1), rq(MachinePolicy=0), 'v', 0, {}, 'invalid', 'State', INVALID),  # 0: invalid here
        (xof(), rq(MachinePolicy=0), 'v', 0, {}, 'ok', 'MachinePolicy', 0),   # field unused: stays zero, no error
        (cipher(), rq(MachinePolicy=2), 'v', 1, {}, 'ok', 'State', ToyCipher.ENCRYPT),     # GR26: the State is kept
        (cipher(), rq(MachinePolicy=1), 'v', 1, {}, 'ok', 'State', ToyCipher.ENCRYPT),
        (sig(MachinePolicy=0), rq(MachinePolicy=2), 'v', 0, {}, 'ok', 'MachinePolicy', 0),  # nothing to remove
        (sig(), rq(AuxInfo=1), 'h', 0, {}, 'invalid', 'State', INVALID),
        (sig(), rq(MachineUse=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), rq(Machine=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), rq(State=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), rq(AuxDataLen=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), rq(Version=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), rq(KeyType=1), 'v', 0, {}, 'invalid', 'State', INVALID),
        (sig(), rq(AuxInfo=1), 'l', 0, {}, 'ok', 'AuxInfo', 0),
        (sig(), rq(MachineUse=1), 'h', 0, {}, 'ok', 'MachineUse', 0),
        (cipher(), rq(SCProtection=1, UsagePolicy=0b11110), 'l', 0, {}, 'invalid', 'State', INVALID),
        (cipher(), rq(SCProtection=1, UsagePolicy=0b11110), 'h', 0, {}, 'ok', 'SCProtection', 0),
        (cipher(SCProtection=2), rq(SCProtection=1, UsagePolicy=0b11110), 'v', 0, {}, 'invalid', 'UsagePolicy', 0b01111),
    ]
    got = [(r, m[f]) for pi, req, wh, enc, kw, _, f, _ in rows for r, m, _ in [run(pi, req, wh, enc, **kw)]]
    eq(f'per-field rules, unnamed fields, halves, atomicity ({len(rows)} cases)', got, [(r, v) for *_, r, f, v in rows])
    r, m, u = run(cipher(), rq(MachinePolicy=2), enc=True)
    out = bytearray(b'\xff' * 16)
    u2 = pv(fresh(), 0, cipher())
    u2.setst(0, ToyCipher.DECRYPT, 1)
    u2.restrict(0, rq(MachinePolicy=2))
    u3 = pv(fresh(), 0, cipher())
    u3.setst(0, ToyCipher.ENCRYPT, 1)
    u3.restrict(0, rq(MachinePolicy=2))
    eq('GR26: a narrowing that disables the current State keeps it; the next kl.exec there goes to Invalid, '
       'output zeroed; kl.setst into the disabled State goes to Invalid, one naming Ready (GR23) is admitted',
       (r, m['State'], u.exec_(0, 'A', vin=bytearray(16), vout=out), u.getst(0), bytes(out),
        u2.setst(0, ToyCipher.ENCRYPT, 1), u2.getst(0), u3.setst(0, READY), u3.getst(0),
        u3.setst(0, ToyCipher.ENCRYPT, 1), u3.getst(0)),
       ('ok', ToyCipher.ENCRYPT, 'invalid', INVALID, bytes(16), 'invalid', INVALID, 'ok', READY, 'invalid', INVALID))
    r, m, u = run(cipher(SCProtection=1), rq(SCProtection=2, UsagePolicy=0b11110))
    eq('kl.restrict* never changes SCProtection: a request is an unnamed field -> Invalid, nothing applied, '
       'no KLF capacity allocated', (r, m['State'], m['UsagePolicy'], u.lockers[0].alloc), ('invalid', INVALID, 0b01111, 0))
    cases = [(loc(hw1=1), loc(hw1=2), loc(hw1=2)), (loc(hw1=1), loc(hw1=3), loc(hw1=3)),
             (loc(hw1=2), loc(hw1=3), loc(hw1=3)), (loc(hw1=3), loc(hw1=2), None), (loc(hw2=1), loc(hw2=3), loc(hw2=3)),
             (loc(hw2=3), loc(hw2=1), None), (0, loc(hw1=1), loc(hw1=1)), (loc(boot=1), loc(boot=2), None),
             (loc(boot=1), loc(boot=1), loc(boot=1)), (0, loc(boot=2), loc(boot=2)), (0, loc(boot=3), None),
             (0, loc(mloc=1, hloc=1, sloc=1), loc(mloc=1, hloc=1, sloc=1)),
             (loc(sloc=1), loc(sloc=1, hw2=2), loc(sloc=1, hw2=2)), (loc(hw1=1, hw2=3), loc(hw1=2, hw2=1), None)]
    u = pv(fresh(), 0, cipher())
    u.slocality = 0
    eq('Locality: fill zero subfields, HW Binding only stricter, others fixed; a weakening or an unconfigured entry '
       'is a Privilege Violation (a failed narrowing)',
       [(lambda r, m, _: m['Locality'] if r == 'ok' else m['State'])(*run(cipher(Locality=c), rq(Locality=q), 'h'))
        for c, q, _ in cases] + [u.restrict(0, rq(Locality=loc(sloc=1)), 'h')],
       [w if w is not None else PRIV for _, _, w in cases] + ['privilege_violation'])
    r, m, _ = run(cipher(), rq(UsagePolicy=0b11110, Locality=loc(hw1=1), ExpirationDate=9, MachinePolicy=1))
    eq('kl.restrictv applies both halves; needs VL*SEW >= 128 (GR6)',
       (r, [m[f] for f in ('UsagePolicy', 'Locality', 'ExpirationDate', 'MachinePolicy', 'State')],
        trap_of(fresh().restrict, 0, 0, 'v', vec_bits=96)), ('ok', [0b01110, loc(hw1=1), 9, 1, READY], 'illegal/1'))
    u = fresh()
    r0 = (u.restrict(0, rq(UsagePolicy=0b11110)), u.getst(0))
    u.mgmt(0, PROV, cipher())
    eq('Unconfigured: no operation; Configuration State: kl_exc_privilege_violation (GR30)',
       (r0, trap_of(u.restrict, 0, rq(UsagePolicy=0b11110))), (('noop', 0), 'privilege_violation'))
    u = pv(fresh(), 0, cipher(ExpirationDate=10))
    u.setst(0, EXPIRED)
    eq('Error State: no operation, whatever the request, and the MDH keeps its fields and Error State (GR33)',
       [u.restrict(0, rq(UsagePolicy=0b10111, ExpirationDate=9)), u.getmd(0)['UsagePolicy'], u.getmd(0)['ExpirationDate'],
        u.getst(0), u.restrict(0, rq(SCProtection=2)), u.restrict(0, rq(MachineUse=1)), u.getst(0)],
       ['noop', 0b01111, 10, EXPIRED, 'noop', 'noop', EXPIRED])
    u = pv(fresh(clock=5000), 0, cipher(ExpirationDate=10))
    eq('kl.restrict* is not an ExpirationDate evaluation point', (u.restrict(0, rq(ExpirationDate=9)), u.getst(0)),
       ('ok', READY))
    u = pv(fresh(), 0, cipher(UsagePolicy=0b11111))
    eq('kl.restricth UsagePolicy is AND-ed: 0b11110 removes U and keeps the Debug grant; 0b01111 then drops it',
       [u.restrict(0, rq(UsagePolicy=0b11110), 'h'), u.getmd(0)['UsagePolicy'], u.restrict(0, rq(UsagePolicy=0b01111), 'h'),
        u.getmd(0)['UsagePolicy']], ['ok', 0b11110, 'ok', 0b01110])

def t_localities():
    section('Localities  <<KLE-Localities>>, <<KLE-system-keys>>')
    eq('LST index of each subfield value; at most six active',
       ([loc_entries(v) for v in (loc(hw1=1), loc(hw1=2), loc(hw1=3), loc(hw2=1), loc(hw2=2), loc(hw2=3),
                                  loc(boot=1), loc(boot=2), loc(mloc=1), loc(hloc=1), loc(sloc=1))],
        max(len(loc_entries(v)) for v in range(512))), ([[j] for j in range(11)], 6))
    u = fresh(hw_missing=(0, 3))
    eq('chain substitution SiP->ChipFam->Chip, OEM->Prod->Dev, none for Chip; never dropped',
       [fresh(hw_missing=(0,)).lst_eff(0), fresh(hw_missing=(0, 1)).lst_eff(0), fresh(hw_missing=(3, 4)).lst_eff(3),
        fresh(hw_missing=(2,)).locality_problem(loc(hw1=3)), u.sealing_ad(cipher(Locality=loc(hw1=1, hw2=1)))[1:]],
       [_secret(b'hw', 1), _secret(b'hw', 2), _secret(b'hw', 5), 'unconfigured LST entry 2', [u.hw[1], u.hw[4]]])
    eq('an unconfigured entry with a configured substitute is valid Metadata (<<KLE-Metadata-validity>>)',
       [fresh(hw_missing=(0,)).locality_problem(loc(hw1=1)), fresh(hw_missing=(3, 4)).locality_problem(loc(hw2=1))],
       [None, None])
    nh = fresh(h_ext=False)
    eq('zero PhysBootScrt/MLocality/SLocality unconfigured; without H entries 7, 9 unconfigured',
       ([fresh(**{a: 0}).locality_problem(v) is not None for a, v in (('physbootscrt', loc(boot=1)),
                                                                       ('mlocality', loc(mloc=1)),
                                                                       ('slocality', loc(sloc=1)))],
        nh.lst_eff(7), nh.lst_eff(9)), ([True] * 3, 0, 0))
    eq('entries 8-10 are three registers, the same in every mode; entry 10 is skllocality at V=0 and at V=1',
       [[fresh(mode=m).lst_register(j) for j in (8, 9, 10)] for m in ('M', 'HS', 'U', 'VS', 'VU')],
       [['mkllocality', 'hkllocality', 'skllocality']] * 5)
    img = export(pv(fresh(), 0, cipher(Locality=loc(sloc=1, hw1=2))), 0)
    eq('SCC imports with matching secrets; other SLocality or substituted ChipFamScrt rejects',
       [import_(fresh(), 1, img), import_(fresh(slocality=_secret(b'sloc') ^ 1 << 77), 1, img),
        import_(fresh(hw_missing=(1,)), 1, img)], [READY, AUTH, AUTH])
    u = pv(fresh(), 0, cipher(Locality=loc(hloc=1)))
    u.hlocality = 0
    img0 = export(u, 0)
    eq('export not refused for an unconfigured entry; import Invalid, then Authentication Failed',
       (len(img0), u.getst(0), import_(fresh(hlocality=0), 1, img0), import_(fresh(), 1, img0)),
       (64, READY, INVALID, AUTH))
    os_hart = pv(fresh(h_ext=False, mode='S'), 0, cipher(Locality=loc(sloc=1)))
    guest = fresh(mode='VS', slocality=os_hart.slocality, hlocality=2)     # the OS still writes skllocality
    g1, g2 = (fresh(mode='VS', slocality=0x5555, hlocality=t) for t in (0x111, 0x222))
    provision(g1, 0, cipher(Locality=loc(hloc=1, sloc=1)))
    hv = pv(pv(fresh(mode='HS', hlocality=0x9999), 0, cipher(Locality=loc(hloc=1))), 1, cipher(Locality=loc(sloc=1)))
    handed, sl_img, hv_sloc = export(hv, 0), export(hv, 1), hv.slocality
    hv.mode, hv.slocality = 'VS', 0x7777                # entering the guest: skllocality holds the guest's value
    r = [import_(guest, 0, export(os_hart, 0)), import_(g2, 0, export(g1, 0)), import_(hv, 2, handed),
         import_(hv, 3, sl_img)]
    hv.slocality = hv_sloc                              # the hypervisor's own value left in place
    eq('interoperability: OS to guest; VM separation; HLocality hand-off; SLocality crosses levels only with '
       'the same skllocality value', r + [import_(hv, 3, sl_img)], [READY, AUTH, READY, AUTH, READY])
    info('skllocality is one register in every mode: a hypervisor separates its own SLocality-bound CCs from a '
         'guest by loading the guest\'s value into skllocality before it runs the guest.')
    u = pv(fresh(), 0, cipher(KeyType=1, UsagePolicy=0b11110, Locality=loc(hw1=1, mloc=1)), v2b(SKID_A, 16))
    m, img, v = u.getmd(0), export(u, 0), fresh()
    eq('SKID resolution narrows UsagePolicy and Locality, keeps KeyType 1 and the SKID; re-resolved at import',
       (m['UsagePolicy'], m['Locality'], m['KeyType'], u.lockers[0].c1, len(img), import_(v, 1, img), v.getmd(1)),
       (0b01010, loc(hw1=2, mloc=1), 1, v2b(SKID_A, 16), 48, READY, m))
    eq('SKID unknown, policy not a subset, Machine not allowed -> Invalid; a failed narrowing (Boot conflict, union '
       'unconfigured) -> Privilege Violation',
       [provision(fresh(slocality=0), 0, pi, v2b(skid, 16))
        for skid, pi in ((0x99, cipher(KeyType=1)), (SKID_B, cipher(KeyType=1)), (SKID_A, xof(KeyType=1)),
                         (SKID_C, cipher(KeyType=1, Locality=loc(boot=1))), (SKID_D, cipher(KeyType=1)))],
       [INVALID] * 3 + [PRIV] * 2)
    eq('a subset of an allowed MachinePolicy resolves; the privilege mode is irrelevant',
       (provision(fresh(), 0, cipher(KeyType=1, MachinePolicy=1), v2b(SKID_B, 16)),
        provision(fresh(mode='U'), 0, cipher(KeyType=1), v2b(SKID_A, 16))), (READY, READY))
    w = pv(pv(fresh(), 0, cipher(KeyType=2), bytes(32)), 1, cipher(KeyType=2), bytes(32))
    eq('KeyType 2: the PI has the KeyType 0 layout; keys generated at completion replace its key; KeyType becomes 0',
       (w.getmd(0)['KeyType'], len(w.lockers[0].c1), w.lockers[0].c1 != w.lockers[1].c1,
        bytes(32) not in (w.lockers[0].c1, w.lockers[1].c1), w.size(k=0)), (0, 32, True, True, 64))
    eq('the all-ones SKID is an ordinary SKID: unresolved -> Invalid (<<KLE-system-keys>>)',
       provision(fresh(), 0, cipher(KeyType=1), v2b(MASK64, 16)), INVALID)

def t_mgmt():
    section('kl.mgmt: provisioning, import, export  <<KLE-locker-management>>')
    m = cipher(UsagePolicy=0b01110, Locality=loc(hw1=2), SCProtection=1)
    content = pi_content(m)
    u = fresh(siv=1, impqual=2, siv2=3).csrs(kliobuflen=16, klstart=48)
    eq('opening provisioning: State 56, MDH, klnamedlocker, klstart 0, registers kept, PI size',
       (u.mgmt(0, PROV, m), u.getst(0), u.getmd(0)['Locality'], u.klnamedlocker, u.klstart,
        (u.siv, u.impqual, u.siv2), u.size(k=0)), ('opened', PROV, loc(hw1=2), 0, 0, (1, 2, 3), 48))
    eq('kl.load, then Form A completion: Ready, fields zeroed, klnamedlocker kept, ADS, Content',
       (u.load(Memory(content), BASE), u.klstart, u.mgmt(0, END, form='A'), u.getst(0), u.getstx(0),
        u.getmd(0)['MachineUse'], u.klnamedlocker, u.getmd(0)['AuxDataLen'], len(u.lockers[0].c2), u.lockers[0].c1,
        u.size(k=0)), ('done', 0, 'completed', READY, 0, 0, 0, ADS_BLOCKS, 32, content, 128))
    ref, got = (u.getmd(0), u.lockers[0].c1, u.lockers[0].c2), []
    for via, form in (('mv', 'C'), ('mvv', 'B'), ('load', 'C')):
        w = fresh().csrs(klstart=5 if via == 'load' else 0)
        provision(w, 0, m, via=via, form=form)
        got.append((w.getmd(0), w.lockers[0].c1, w.lockers[0].c2))
    eq('provisioning via kl.mvin, vector kl.mvin (Form B), kl.load (klstart ignored) agree', got, [ref] * 3)
    w, starts = opened(m=m), []
    for o in (0, 16):
        starts.append(w.klstart)
        w.mv_in(b2v(content[o:o + 16]))
    eq('kl.mvin accumulates klstart; the completing kl.mgmt clears it',
       (starts, w.klstart, w.mgmt(0, END), w.klstart), ([0, 16], 32, 'completed', 0))
    md0 = u.getmd(0)
    u.mgmt(0, EXP)
    eq('opening export: 57, klnamedlocker 0, klstart 0, only State changes, SIV/IMPQUAL/SIV2 written',
       (u.getst(0), u.klnamedlocker, u.klstart, dict(u.getmd(0), State=0), bool(u.siv), u.impqual, bool(u.siv2)),
       (EXP, 0, 0, dict(md0, State=0), True, u.impqual_value(), True))
    out, n = Memory(), u.size(k=0)
    u.store(out, BASE)
    img = mdh_bytes(md0) + out.read(BASE, n - 16)
    eq('kl.store: SIV, IMPQUAL, SIV2 lead S; Content is ciphertext; only klstart changes',
       ([b2v(img[16 + 16 * i:32 + 16 * i]) for i in range(3)], img[64:96] != content, u.getst(0), u.klstart),
       ([u.siv, u.impqual, u.siv2], True, EXP, 0))
    eq('completion restores the locker; only ml.State is used; klnamedlocker kept until a write or another kl.mgmt',
       (u.mgmt(0, END, dict(md0, UsagePolicy=0b01111, Locality=0)), u.getmd(0), u.lockers[0].c1, u.klnamedlocker,
        u.mgmt(1, PROV, cipher()), u.klnamedlocker), ('completed', md0, content, 0, 'opened', 1))
    u.csrs(klnamedlocker=NONE)
    v = fresh(siv=7, impqual=7, siv2=7)
    eq('kl.size Form B is the image length; opening an import zeroizes the registers, State 58',
       (v.size('B', lo=b2v(img[:8])), v.mgmt(1, IMP, unpack(b2v(img[:16]))), v.siv, v.impqual, v.siv2, v.getst(1),
        v.klnamedlocker), (len(img), 'opened', 0, 0, 0, IMP, 1))
    x = fresh(siv=7, impqual=7, siv2=7)
    x.mgmt(1, IMP, unpack(b2v(img[:16])))
    s1 = x.getmd(1)
    x.mgmt(1, EXP)
    eq('a nested export at once after an import opening emits zeros, not the values of an earlier operation',
       export_pccc(x, 1, s1)[16:], bytes(len(img) - 16))
    v.load(Memory(img[16:]), BASE)
    eq('kl.load fills the registers; the import round trips MDH, Content1, ADS',
       ((v.siv, v.impqual, v.siv2), v.mgmt(1, END, md0), v.getmd(1), v.lockers[1].c1, v.lockers[1].c2),
       ((u.siv, u.impqual, u.siv2), 'completed', md0, content, u.lockers[0].c2))
    w1, w3 = fresh(), fresh()
    eq('import via kl.mvin, Form B agree; export via kl.mvout agrees with kl.store',
       [(import_(w1, 2, img, via='mv'), w1.getmd(2), w1.lockers[2].c1),
        (w3.mgmt(2, IMP, md0, form='B'), import_(w3, 2, img)), export(v, 1, via='mv') == img],
       [(READY, md0, content), ('opened', READY), True])
    u = rc()
    ex(u, 0, n=32)
    st_md, img, c1 = u.getmd(0), export(u, 0), u.lockers[0].c1
    v = fresh()
    eq('a locker mid-operation round trips State, StateExtension, state block, and continues',
       (import_(v, 3, img), v.getmd(3), v.lockers[3].c1, ex(v, 3), ex(u, 0), v.lockers[3].c1 == u.lockers[0].c1),
       (ToyCipher.ENCRYPT, st_md, c1, 'done', 'done', True))
    t = bytearray(img)
    t[3] ^= 1 << 3                                                  # StateExtension bit 2
    eq('the same SCC with an unsupported StateExtension: Invalid at open, before authentication',
       import_(fresh(), 3, bytes(t)), INVALID)
    t = bytearray(img)
    t[40] ^= 1
    v = fresh()
    eq('a modified Content1 byte: Authentication Failed, no exception, klnamedlocker 32',
       (import_(v, 0, bytes(t)), v.getmd(0)['AuxDataLen'], v.klnamedlocker), (AUTH, 0, NONE))
    v = opened(IMP, st_md)
    v.load(Memory(img[16:]), BASE)
    u2 = pv(fresh(), 0, cipher())
    u2.mgmt(0, EXP)
    u2.siv ^= 1
    eq('altered MDH, other ml.State, other CSK, overwritten SIV at export -> Authentication Failed',
       [import_(fresh(), 0, mdh_bytes(dict(st_md, UsagePolicy=0b00000)) + img[16:]),
        (v.mgmt(0, END, dict(st_md, State=READY)), v.getst(0))[1], import_(fresh(csk=DEFAULT_CSK ^ 1), 0, img),
        (u2.mgmt(0, END, cipher(State=READY)), u2.getst(0))[1]], [AUTH] * 4)
    u = opened()
    eq('klnamedlocker = 0: a kl.mgmt that names locker 1 is not checked against klnamedlocker (SR5): it opens '
       'on locker 1 and names it; the provisioning of locker 0 stays open',
       (trap_of(u.mgmt, 1, PROV, cipher()), u.getst(1), u.klnamedlocker, u.getst(0)), (None, PROV, 1, PROV))
    eq('the second provisioning completes; the first one, abandoned, stays open',
       (u.mgmt(1, END), u.getst(1), u.getst(0)), ('completed', READY, PROV))
    got = []
    for mk, imm in ((lambda: rc(unit=fresh(zklio=False)), PROV), (lambda: rc(unit=fresh(zklio=False)), EXP),
                    (lambda: opened(zklio=False), END), (lambda: opened(IMP, cipher(State=1), zklio=False), END)):
        a, d = mk(), mk()
        got.append((trap_of(a.mgmt, 0, imm, form='A'), a.getmd(0), a.klnamedlocker, a.klstart)
                   == (trap_of(d.mgmt, 0, imm, 0), d.getmd(0), d.klnamedlocker, d.klstart))
    eq('Form A kl.mgmt is Form C with X0: an all-zero MDH, no KLIOBUF read, no Zklio needed (GR3); a PI '
       'completion, which reads no MDH, completes', (got, opened(zklio=False).mgmt(0, END, form='A')),
       ([True] * 4, 'completed'))
    w = opened(IMP, cipher(State=1)).csrs(klstart=16)
    u = rc(unit=fresh(zklv=False)).csrs(klstart=16)
    r = [trap_of(u.mgmt, 0, PROV, cipher(), form='B'), u.klstart]
    n = fresh(csk=0)
    n.klstart = 16
    r += [trap_of(n.mgmt, 0, EXP), n.klstart]
    r += [trap_of(u.mgmt, 0, END), u.klstart]
    eq('GR45: a first-group rejection (Form B without Zklv, GR7) and kl_exc_no_csk keep klstart; a later rejection (end on a '
       'Valid State) clears it', r, ['illegal/1', 16, 'no_csk', 16, 'illegal/2', 0])
    eq('an exception inside a management operation keeps State and klnamedlocker, clears klstart',
       (trap_of(w.mgmt, 0, END, form='B', vec_bits=64), w.getst(0), w.klnamedlocker, w.klstart),
       ('illegal/2', IMP, 0, 0))
    eq('Form B VL*SEW < 128 (GR6, second group for kl.mgmt); end on a Complete State illegal/2',
       [trap_of(w.mgmt, 0, PROV, cipher(), form='B', vec_bits=64), trap_of(rc().mgmt, 0, END, md(State=1))],
       ['illegal/2'] * 2)
    x, y = fresh().csrs(klstart=16), rc(3).csrs(klstart=16)
    y.setst(3, INVALID)
    eq('GR6 for kl.mgmt is locker-state-independent: a short Form B end on an Unconfigured or Error-State locker, which '
       'would fall through, is illegal/2, State kept, klstart cleared (GR17 item 7)',
       [trap_of(x.mgmt, 0, END, form='B', vec_bits=64), x.klstart,
        trap_of(y.mgmt, 3, END, form='B', vec_bits=64), y.getst(3), y.klstart],
       ['illegal/2', 0, 'illegal/2', INVALID, 0])
    v = fresh().csrs(klstart=16)
    eq('GR52, inert table: a kl.setst that falls through keeps klstart; a kl.exec that falls through writes 0',
       [v.setst(0, 2), v.klstart, v.exec_(0, 'D'), v.klstart], ['noop', 16, 'noop', 0])
    w = rc(5).csrs(klnamedlocker=32)
    st5 = w.getst(5)
    eq('GR27 item 1, GR45: a kl.mgmt that traps leaves klnamedlocker '
       'unchanged; one that raises no exception names its target',
       [trap_of(w.mgmt, 5, EXP, form='B', vec_bits=64), w.klnamedlocker, w.getst(5) == st5,
        trap_of(w.mgmt, 5, EXP) is None, w.klnamedlocker], ['illegal/2', 32, True, True, 5])
    v = fresh().csrs(klstart=16, klnamedlocker=0)
    v.siv, v.impqual, v.siv2 = 1, 2, 3
    eq('GR33: opening an export on an Unconfigured locker is a no-op: authentication registers kept, common '
       'steps only', (v.mgmt(0, EXP), v.getst(0), v.klnamedlocker, v.klstart, (v.siv, v.impqual, v.siv2),
                      fresh().csrs(klnamedlocker=3).mgmt(0, EXP)),
       ('noop', UNCONF, 32, 0, (1, 2, 3), 'noop'))
    v = fresh().csrs(klstart=16, klnamedlocker=0)
    eq('GR33: end on an Unconfigured locker is a no-op: ml unread (Form A), common steps only',
       (v.mgmt(0, END, form='A'), v.getst(0), v.klnamedlocker, v.klstart,
        fresh().csrs(klnamedlocker=3).mgmt(0, END)), ('noop', UNCONF, 32, 0, 'noop'))
    zero, traps = [], set()
    for priv, kw, imm, st in itertools.product((True, False), ({}, {'clf_total': 10}), (PROV, IMP), range(64)):
        for ml in (cipher(State=st), md(Machine=M_ABSENT, State=st), cipher(State=st, AuxDataLen=2)):
            v = fresh(priv=priv, **kw)
            tag = trap_of(v.mgmt, 0, imm, ml)
            traps.add(tag)
            zero += [(priv, imm, st)] * (tag is None and v.getst(0) == UNCONF)
    eq('an opening kl.mgmt that retires never leaves State 0, so 0 at the first check means a clear (restart); '
       'it traps only with kl_exc_unsupported, kl_exc_out_of_memory', (zero, traps),
       ([], {None, 'unsupported', 'out_of_memory'}))
    u = pv(fresh(), 0, cipher())
    eq('an opening zeroizes even a Valid locker (GR45), the one change a raising kl.mgmt keeps',
       (trap_of(u.mgmt, 0, PROV, md(Machine=M_ABSENT)), u.getst(0), u.clf_free() == u.clf_total),
       ('unsupported', 0, True))
    rows = []
    for f in (lambda w: w.setst(0, 0), lambda w: w.setst(0, INVALID), lambda w: w.clone(0, 1),
              lambda w: trap_of(w.mgmt, 0, PROV, md(Machine=M_ABSENT)), lambda w: w.setst(0, READY)):
        w = rc(1, rc()).csrs(klnamedlocker=0)
        rows.append((f(w), w.klnamedlocker))
    eq('klnamedlocker names a Valid locker: cleared, clone destination -> 32; Error State, raising opening, '
       'kl.setst keep it', rows,
       [('cleared', NONE), ('error state', 0), ('cloned', NONE), ('unsupported', 0), ('ok', 0)])
    u, absent = fresh().csrs(klnamedlocker=6), md(Machine=M_ABSENT, MachinePolicy=1)
    r = [trap_of(u.mgmt, 'KLNL', PROV, absent), u.getst(6), u.klnamedlocker]
    r += [u.setst(u.klnamedlocker, UNSUP), u.getst('KLNL')]
    eq('a KLNL opening that raises after zeroizing leaves klnamedlocker naming the locker, so the handler can '
       'set the Error State on it with kl.setste (GR37) and the routine reads it through KLNL', r,
       ['unsupported', 0, 6, 'error state', UNSUP])

def t_nested():
    section('Nested management and PCCCs  <<KLE-management-formats-and-states>>')
    table = {st: [s for s in (*range(64), *ERROR_STATES) if trap_of(white_box(st, bytearray(32) if BASE_TYPE[st] == 'pi' else None).mgmt,
                                                  0, END, md(State=s)) is None] for st in (EXP, IMP, PPI_EXP, PPI_IMP)}
    scc_ok = sorted(set(VALID) | {57, 58})
    eq('completion base-type rule: scc takes a Valid State, 57, 58; Error States and 0 are not admitted; pi takes 56, 59, 60', table,
       {EXP: scc_ok, IMP: scc_ok, PPI_EXP: [56, 59, 60], PPI_IMP: [56, 59, 60]})
    m = cipher(Locality=loc(hw2=2))
    content = pi_content(m, 0x51)
    u, mem = opened(m=m, k=4), Memory(content)
    u.load(mem, BASE, halt_after=16)
    saved, k0 = u.getmd(4), u.klstart
    eq('provisioning halted at 16; nested export opens 59, keeps klnamedlocker; PI size',
       (k0, u.mgmt(4, EXP), u.getst(4), u.klnamedlocker, u.klstart, u.size(k=4)), (16, 'opened', PPI_EXP, 4, 0, 48))
    pccc = export_pccc(u, 4, saved)
    eq('PI-shaped PCCC verbatim, unloaded bytes zero; nested completion restores 56',
       (pccc[16:], u.getst(4), u.klnamedlocker), (content[:16] + bytes(16), PROV, 4))
    u.mgmt(4, EXP)
    inner = u.getmd(4)
    r = [u.mgmt(4, EXP), u.getst(4), u.mgmt(4, END, inner), u.getst(4), u.mgmt(4, END, saved), u.getst(4),
         u.mgmt(4, EXP), trap_of(u.mgmt, 4, END, dict(saved, State=READY)), u.mgmt(4, END, saved), u.setst(4, 0),
         u.klnamedlocker, u.mgmt(4, IMP, saved), u.getst(4), u.klnamedlocker, u.load(Memory(pccc[16:]), BASE),
         u.mgmt(4, END, saved), u.getst(4), u.csrs(klstart=k0).load(mem, BASE), u.mgmt(4, END), u.lockers[4].c1]
    eq('double nesting stays 59; Complete ml illegal on pi; PCCC re-import 60 -> 56; resumption completes', r,
       ['opened', PPI_EXP, 'completed', PPI_EXP, 'completed', PROV, 'opened', 'illegal/2', 'completed', 'cleared',
        NONE, 'opened', PPI_IMP, 4, 'done', 'completed', PROV, 'done', 'completed', content])
    u = opened(m=cipher(KeyType=2))
    u.mv_in(0)
    u.mv_in(0)
    s0 = u.getmd(0)
    u.mgmt(0, EXP)
    pv_ = [u.mv_out() for _ in range(u.size(k=0) // 16 - 1)]
    u.mgmt(0, END, s0)
    u.mgmt(0, END)
    eq('KeyType 2: the PCCC keeps KeyType 2 and the loaded PI content; the key comes from the completing kl.mgmt',
       (s0['KeyType'], pv_, u.getmd(0)['KeyType'], len(u.lockers[0].c1), u.lockers[0].c1 != bytes(32)),
       (2, [0, 0], 0, 32, True))
    u = fresh()
    src, ml, mem, scc = interrupted_import(u, 2, 64)
    regs, s1, ks = (u.siv, u.impqual, u.siv2), u.getmd(2), u.klstart
    eq('import halted after SIV, IMPQUAL, SIV2, a block; nested export opens 57 without sealing',
       (ks, regs, u.mgmt(2, EXP), u.getst(2), (u.siv, u.impqual, u.siv2)),
       (64, (src.siv, src.impqual, src.siv2), 'opened', EXP, regs))
    pc = export_pccc(u, 2, s1)
    eq('SCC-shaped PCCC: registers, loaded ciphertext, zeros; nested completion returns to 58',
       (pc[16:], u.getst(2), u.klnamedlocker), (scc[16:80] + bytes(len(scc) - 80), IMP, 2))
    export(rc(9, u.csrs(klnamedlocker=32)), 9)
    r = [u.siv != regs[0], u.setst(2, 0), u.mgmt(2, IMP, s1), u.getst(2), u.load(Memory(pc[16:]), BASE),
         u.mgmt(2, END, s1), u.getst(2), (u.siv, u.impqual, u.siv2), u.klnamedlocker,
         u.csrs(klstart=ks).load(mem, BASE), u.mgmt(2, END, ml), u.getmd(2), u.lockers[2].c1, u.lockers[2].c2]
    eq('registers overwritten elsewhere; PCCC re-import restores 58 and them; the import completes', r,
       [True, 'cleared', 'opened', IMP, 'done', 'completed', IMP, regs, 2, 'done', 'completed', src.getmd(0),
        src.lockers[0].c1, src.lockers[0].c2])
    for tamper in (False, True):
        u = pv(fresh(), 1, sig(AuxInfo=3))
        base_md, out = u.getmd(1), Memory()
        u.mgmt(1, EXP)
        u.store(out, BASE, halt_after=32)
        ks, s2 = u.klstart, u.getmd(1)
        u.mgmt(1, EXP)
        st = u.getst(1)
        pc = bytearray(export_pccc(u, 1, s2))
        pc[40] ^= 0x80 * tamper
        r = [st, u.setst(1, 0), u.mgmt(1, IMP, s2), u.load(Memory(pc[16:]), BASE), u.mgmt(1, END, s2), u.getst(1),
             u.csrs(klstart=ks).store(out, BASE), u.mgmt(1, END, base_md), u.getst(1)]
        if tamper:
            eq('interrupted export via a tampered nested PCCC: detected at export completion', r,
               [EXP, 'cleared', 'opened', 'done', 'completed', EXP, 'done', 'completed', AUTH])
        else:
            img = mdh_bytes(base_md) + out.read(BASE, u.size(k=1) - 16)
            eq('interrupted export via a nested PCCC: 57 throughout; completes; its SCC imports',
               r + [u.getmd(1), len(u.lockers[1].c1), import_(fresh(), 0, img)],
               [EXP, 'cleared', 'opened', 'done', 'completed', EXP, 'done', 'completed', READY, base_md, 64, READY])


def t_error_states():
    section('Lockers in an Error State  <<KLE-error-state-transfer>>, <<KLE-insn-outcomes-inert>>')
    rows, want = [], []
    for st in ERROR_STATES[1:]:
        u = pv(fresh(), 0, cipher(SCProtection=1, ExpirationDate=77, UsagePolicy=0b01101))
        u.setst(0, ToyCipher.ENCRYPT, 5)
        r = u.csrs(klstart=32).setst(0, st)
        m, img, v = u.getmd(0), export(u, 0), fresh(siv=5).csrs(klstart=48)
        rows.append((r, m['State'], u.lockers[0].c1, m['AuxDataLen'], m['ExpirationDate'], m['StateExtension'],
                     u.lockers[0].alloc, u.klstart, u.size(k=0), img == mdh_bytes(m), v.mgmt(3, IMP, unpack(b2v(img))),
                     v.getmd(3) == m, v.klstart, v.klnamedlocker, v.siv, v.mgmt(3, END, m)))
        want.append(('error state', st, b'', 0, 77, st >> 7, 0, 32, 16, True, 'short import', True,
                     0, 3, 5, 'noop'))
    eq('kl.setste #2-#6 then export and short import (5 States, 16 properties each; the code overwrites '
       'StateExtension; end is then a no-op)', rows, want)
    u = rc(0, fresh(zklexpire=False))
    eq('kl.setst #48, #53, which the Machine does not define -> Invalid; kl.setste #6 without Zklexpire is reserved: '
       'illegal/1, the locker unchanged',
       [(trap_of(c.setst, 0, i), c.getst(0)) for i in (48, 53) for c in [rc()]] + [trap_of(u.setst, 0, EXPIRED),
        u.getst(0)], [(None, INVALID)] * 2 + ['illegal/1', ToyCipher.ENCRYPT])
    u = fresh()
    eq('import of a reserved StateExtension 7, 15: invalid Metadata, regular path -> Invalid; short import: ADS fields zeroed; no capacity; kl.setste #2 on '
       'Unconfigured records it (GR37)',
       [(u.mgmt(k, IMP, cipher(State=0, StateExtension=x)), u.getst(k), u.csrs(klnamedlocker=NONE))[:2]
        for k, x in ((0, 7), (1, 15))]
       + [(u.mgmt(2, IMP, cipher(State=EXPIRED, AuxDataLen=4, ADSDropped=1)), u.getmd(2)['AuxDataLen'],
           u.getmd(2)['ADSDropped'], u.lockers[2].alloc), (u.setst(3, INVALID), u.getst(3))],
       [('invalid', INVALID)] * 2 + [('short import', 0, 0, 0), ('error state', INVALID)])
    u = pv(fresh(), 0, cipher())
    u.setst(0, EXPIRED)
    provision(u, 1, cipher())
    before, vo = u.getmd(0), bytearray(b'\xAA' * 16)
    eq('export opening: unchanged, nothing opened, klstart 0, klnamedlocker names it; then kl.load/store/mvin/mvout '
       'and end are no-ops (GR33)',
       [u.csrs(klstart=16).mgmt(0, EXP), u.getmd(0) == before, u.klnamedlocker, u.klstart,
        u.csrs(klnamedlocker=0).load(Memory(), BASE), u.store(Memory(), BASE), u.mv_in(1), u.mv_out(), u.mgmt(0, END),
        u.getst(0)], ['unchanged', True, 0, 0, 'noop', 'noop', 'noop', 0, 'noop', EXPIRED])
    eq('use and kl.restrict* are no-ops, output zeroed; Error-State kl.setst changes it',
       [u.exec_(0, 'A', vin=bytearray(16), vout=vo), bytes(vo), u.setst(0, READY), u.setst(0, CLEAR_ADS),
        u.restrict(0, rq(UsagePolicy=0b10111)), u.setst(0, READY), u.getst(0), u.setst(0, UNSUP), u.getst(0)],
       ['noop', bytes(16), 'noop', 'noop', 'noop', 'noop', EXPIRED, 'error state', UNSUP])
    eq('kl.clone from it copies the MDH; onto it replaces; provisioning reconfigures; kl.clear clears',
       [u.clone(5, 0), u.getmd(5) == u.getmd(0), u.lockers[5].c1, u.lockers[5].alloc, u.clone(5, 1), u.getst(5),
        provision(u, 0, cipher()), u.setst(0, INVALID), u.setst(0, 0), u.getst(0)],
       ['cloned', True, b'', 0, 'cloned', READY, READY, 'error state', 'cleared', 0])

def t_ads():
    section('ADS, IMPQUAL, _ADSDropped_  <<KLE-SCC-import>>, <<KLE-Auxiliary-Data-Section>>')
    u, lo = rc(SCProtection=1), rc()
    m, scc = u.getmd(0), export(u, 0)
    c1 = MACHINES[M_CIPHER].content1_size(m)
    eq('SCC with ADS: MDH, SIV, IMPQUAL, SIV2, Content1, Content2; IMPQUAL; no ADS at SCProtection 0',
       (len(scc), b2v(scc[32:48]), len(export(lo, 0))),
       (64 + c1 + 16 * (ADS_BLOCKS - 2), u.impid << 64 | u.archid << 32 | u.vendorid, 32 + c1))
    v, o = fresh(), fresh(ids=(0xA11, 0x42, 0x99))
    eq('same implementation keeps the ADS; an IMPQUAL mismatch keeps Content1, regenerates the ADS',
       (import_(v, 0, scc), v.lockers[0].c2, v.getmd(0)['AuxDataLen'], import_(o, 0, scc), o.lockers[0].c1,
        o.lockers[0].c2 != u.lockers[0].c2, o.getmd(0)['AuxDataLen'], o.getmd(0)['ADSDropped']),
       (ToyCipher.ENCRYPT, u.lockers[0].c2, ADS_BLOCKS, ToyCipher.ENCRYPT, u.lockers[0].c1, True, ADS_BLOCKS, 0))
    x = rc(SCProtection=1)
    m0, c1_0, c2_0 = x.getmd(0), x.lockers[0].c1, x.lockers[0].c2
    x.mgmt(0, EXP)
    s1 = x.getmd(0)
    x.mgmt(0, EXP)
    pccc, got = export_pccc(x, 0, s1), []
    for ids in (None, (0xA11, 0x42, 0x99)):
        y = fresh(ids=ids)
        r1 = import_(y, 0, pccc)
        r2 = y.mgmt(0, END, m0)
        got.append((r1, r2, y.getst(0), y.lockers[0].c1 == c1_0, y.lockers[0].c2 == c2_0, y.getmd(0)['AuxDataLen']))
    eq('export completed on another implementation (a nested export moved between harts): Content1 restored; '
       'Content2 kept only with a matching IMPQUAL, otherwise dropped and regenerated (export completion runs the '
       'import steps 16-18)', got,
       [(EXP, 'completed', m0['State'], True, True, ADS_BLOCKS), (EXP, 'completed', m0['State'], True, False, ADS_BLOCKS)])
    got = []
    for off in (64 + c1, 48, 16):                  # a Content2 byte, SIV2, SIV
        t, v = bytearray(scc), fresh()
        t[off] ^= 1
        got.append((import_(v, 0, bytes(t)), v.lockers[0].c1 == u.lockers[0].c1, v.getmd(0)['ADSDropped']))
    eq('modified Content2 or SIV2 drops Content2 only; a modified SIV rejects the SCC', got,
       [(ToyCipher.ENCRYPT, True, 0)] * 2 + [(AUTH, False, 0)])
    dm, t = dict(m, ADSDropped=1), bytearray(scc)
    t[:16], t[32:64] = mdh_bytes(dm), bytes(32)
    v = opened(IMP, dm)
    lay = v.layout(v.getmd(0))[:2]
    v.load(Memory(t[16:]), BASE)
    v.mgmt(0, END, dm)
    eq('ADSDropped set in memory: offset 48, no Content2, Content1 and policies intact, ADS regenerated',
       (lay, v.size('C', m=dm), v.getst(0), v.lockers[0].c1, dict(v.getmd(0), AuxDataLen=0), v.getmd(0)['AuxDataLen']),
       ((48, c1), 64 + c1, ToyCipher.ENCRYPT, u.lockers[0].c1, dict(m, AuxDataLen=0), ADS_BLOCKS))
    big, bm = fresh(), dict(m, AuxDataLen=MAX_ADL + 2)
    siv, ct1 = scc_encrypt(big.sealing_ad(bm), 0, 0, to_blocks(u.lockers[0].c1), DEFAULT_CSK)
    iq = big.impqual_value()
    siv2, ct2 = scc_encrypt([iq, siv], 0, 1, to_blocks(bytes(16 * MAX_ADL)), DEFAULT_CSK)
    mem = Memory(v2b(siv, 16) + v2b(iq, 16) + v2b(siv2, 16) + from_blocks(ct1) + from_blocks(ct2))
    big.mgmt(0, IMP, bm)
    eq('AuxDataLen above the maximum: ADSDropped at opening, kl.load stops at image_end, Content1 only',
       (big.getmd(0)['ADSDropped'], big.load(mem, BASE), mem.accesses, big.mgmt(0, END, bm), big.getst(0),
        big.lockers[0].c1, big.getmd(0)['ADSDropped']),
       (1, 'done', (48 + c1) // 16, 'completed', ToyCipher.ENCRYPT, u.lockers[0].c1, 0))
    w = rc(SCProtection=1)
    eq('kl.clearads in _Encrypt_ (GR23): ADS fields 0, State kept, ADS-free SCC; the next use regenerates the ADS',
       (w.setst(0, CLEAR_ADS), w.getmd(0)['AuxDataLen'], w.lockers[0].c2, w.getst(0), len(export(w, 0)), ex(w, 0),
        w.getmd(0)['AuxDataLen']), ('ads cleared', 0, b'', ToyCipher.ENCRYPT, 32 + c1, 'done', ADS_BLOCKS))

def t_transfers():
    section('kl.load, kl.store, kl.mvin, kl.mvout  <<KLE-instruction-load>>, <<KLE-instruction-mv>>, '
            '<<KLE-instructions-memory>>')
    eq('kl.mvin into the named locker only in 56, 58, 60 (GR31), kl.mvout only in 57, 59 (GR31); no trap in '
       'Unconfigured or an Error State (GR33)',
       ([s for s in (*range(64), *ERROR_STATES) if trap_of(white_box(s).csrs(klnamedlocker=0).mv_in, 1) is None],
        [s for s in (*range(64), *ERROR_STATES) if trap_of(white_box(s).csrs(klnamedlocker=0).mv_out) is None]),
       ([0, 56, 58, 60, *ERROR_STATES], [0, 57, 59, *ERROR_STATES]))
    u, v = opened(), rc()
    r = [trap_of(u.store, Memory(), BASE), u.mgmt(0, EXP), trap_of(u.load, Memory(), BASE), v.mgmt(0, EXP),
         v.csrs(klnamedlocker=32).store(Memory(), BASE), v.mv_out(),
         v.csrs(klnamedlocker=0).store(Memory(), BASE)]
    for k, imm, ml in ((1, IMP, cipher(State=1)), (2, PROV, cipher())):
        v.csrs(klnamedlocker=32).mgmt(k, imm, ml)
    eq('kl.store in 56, kl.load in 57 illegal; klnamedlocker = 32: kl.store (Xl = 0), kl.mvout, kl.mvin are no-ops '
       '(GR33); klnamedlocker alone selects the locker (GR5), in 58 as in 56',
       r + [v.csrs(klnamedlocker=32).mv_in(1), v.csrs(klnamedlocker=1).mv_in(1),
            v.csrs(klnamedlocker=2).mv_in(1)],
       ['illegal/2', 'opened', 'illegal/2', 'opened', 'empty', 0, 'done', 'noop', 'moved', 'moved'])
    u = opened().csrs(klstart=8)
    eq('klstart not a multiple of 16; Xl != 0; no Zklmv; an emulated kl.load',
       [trap_of(u.load, Memory(), BASE), trap_of(u.mv_in, 1), trap_of(opened().load, Memory(), BASE, 16),
        trap_of(fresh(zklmv=False).mv_in, 1), trap_of(opened(zklmem_hw=False).load, Memory(), BASE)],
       ['illegal/2'] * 3 + ['illegal/1'] * 2)
    mem, vec, vo = Memory(), bytearray(b'\xAA' * 16), bytearray(b'\xAA' * 16)
    u.csrs(klnamedlocker=5).vstart = 0                            # K5 is Unconfigured
    r = [u.mv_in(1), u.mv_out(), u.mv_vec(vec), u.mv_vec(vo, out=True), bytes(vo), u.klstart,
         u.load(mem, BASE), u.klstart, u.csrs(klstart=8).store(mem, BASE), u.klstart, mem.accesses,
         trap_of(u.load, mem, BASE + 1), trap_of(u.store, mem, BASE + 1), u.klnamedlocker, u.getst(5)]
    eq('GR33, Unconfigured locker: kl.mvin/kl.mvout a no-op, zeros read, klstart (8) kept; kl.load, kl.store an empty '
       'window: no access, klstart 0, misalignment still raised; klnamedlocker kept', r,
       ['noop', 0, 'noop', 'noop', bytes(16), 8, 'noop', 0, 'noop', 0, 0, 'load_misaligned', 'store_misaligned', 5,
        UNCONF])
    for at in ('opened', 'loaded'):                                 # the check-then-use race
        u = opened()
        if at == 'loaded':
            u.mv_in(1)
        u.clear(0)                                                  # a handler clears instead of saving
        r = [u.klnamedlocker, u.mv_in(2), u.load(Memory(), BASE), u.mgmt(0, END), u.getst(0),
             provision(u, 0, cipher())]
        eq(f'GR27, GR33: locker cleared after the check ({at}): the clear leaves klnamedlocker = 32, and the next kl.mvin, '
           'kl.load (Xl = 0) and end are no-ops; restart provisions', r, [32, 'noop', 'empty', 'noop', UNCONF, READY])
    vo = bytearray(b'\xAA' * 16)
    eq('klnamedlocker = 32: kl.load/kl.store with Xl = 0 are no-ops before the Zklio and KLIOBUF checks, klstart 0; '
       'with Xl != 0 they are kl.input/kl.output (GR15; without Zklio illegal/2, second group); kl.mvout zeros its '
       'destination',
       [fresh().csrs(klstart=16).load(Memory(), BASE), fresh().load(Memory(), BASE + 1), fresh().klstart,
        trap_of(fresh().store, Memory(), BASE, 16), fresh(zklio=False).store(Memory(), BASE),
        trap_of(fresh(zklio=False).load, Memory(), BASE, 16), fresh().mv_vec(vo, out=True), bytes(vo),
        fresh().mv_iobuf(out=True)],
       ['empty', 'empty', 0, 'illegal/2', 'empty', 'illegal/2', 'noop', bytes(16), 'noop'])
    pc = pi_content(cipher())
    u, mem = opened(), Memory(pc)
    img = lambda w: bytes(w.lockers[0].img)
    r = [trap_of(u.load, mem, BASE + 4), img(u), trap_of(u.csrs(klstart=32).load, mem, BASE + 8),
         u.load(mem, BASE), img(u), u.klstart]
    eq('misaligned kl.load: nothing moved, also with an empty window; klstart >= image_end retires', r,
       ['load_misaligned', bytes(32), 'load_misaligned', 'done', bytes(32), 0])
    mem.unmapped.append((BASE + 16, BASE + 32))
    r = [trap_of(u.load, mem, BASE, tval=True), u.klstart, img(u)[:16] == pc[:16], trap_of(u.load, mem, BASE),
         u.klstart]
    mem.unmapped.clear()
    eq('page fault: precise halt, xtval; re-execution faults again; resumes once mapped',
       r + [u.load(mem, BASE), img(u) == pc], [('load_page_fault', BASE + 16), 16, True, 'load_page_fault', 16,
                                                  'done', True])
    u, w = opened(), opened()
    mem.nonidem.append((BASE + 20, BASE + 21))
    r = [trap_of(u.load, mem, BASE, tval=True), u.klstart]
    mem.nonidem.clear()
    mem.unmapped.append((BASE + 16, BASE + 32))
    r += [trap_of(w.load, mem, BASE, restart=True), w.klstart]
    mem.unmapped.clear()
    w = opened()
    eq('GR64: access fault at the byte, prefix committed; restart option for interrupts only (GR48)',
       r + [w.load(mem, BASE, halt_after=16, restart=True), w.klstart, w.load(mem, BASE), img(w) == pc],
       [('load_access_fault', BASE + 20), 16, 'load_page_fault', 16, 'halted', 0, 'done', True])
    w = opened()
    eq(f'GR48 option 5: at most {MAX_RESTARTS} consecutive restarts of one kl.load, then option 3 resumes it',
       [(w.load(mem, BASE, halt_after=16, restart=True), w.klstart) for _ in range(MAX_RESTARTS + 1)]
       + [w.load(mem, BASE), img(w) == pc], [('halted', 0)] * MAX_RESTARTS + [('halted', 16), 'done', True])
    u, out, ref = rc(), Memory(), Memory()
    u.mgmt(0, EXP)
    out.unmapped.append((BASE + 32, BASE + 48))
    r = [trap_of(u.store, out, BASE + 2), trap_of(u.store, out, BASE), u.klstart]
    out.unmapped.clear()
    u.store(out, BASE)
    u.store(ref, BASE)
    eq('kl.store: misaligned; fault halts at 32; resumption writes the same image; empty window retires',
       r + [out.read(BASE, 64) == ref.read(BASE, 64), u.csrs(klstart=128).store(out, BASE), u.klstart],
       ['store_misaligned', 'store_page_fault', 32, True, 'done', 0])
    u = opened()
    r = [u.mv_in(1), u.mv_in(2), u.mv_in(3), u.klstart, u.mgmt(0, END), u.mgmt(0, EXP)]
    vals = [u.mv_out() for _ in range(4)]
    eq('kl.mvin past image_end writes nothing, kl.mvout reads zero, klstart stays; SIV is read first',
       r + [vals[0] == u.siv, vals[3], u.klstart], ['moved', 'moved', 'nothing', 32, 'completed', 'opened', True, 0,
                                                    48])
    vd, vd2, vd3 = bytearray(b'\xEE' * 64), bytearray(b'\xEE' * 32), bytearray(b'\xEE' * 32)
    r = [u.csrs(klstart=32).mv_vec(vd, out=True), vd[:16] == v2b(vals[2], 16), bytes(vd[16:]), u.klstart, u.vstart,
         u.csrs(klstart=48).mv_vec(vd2, out=True), bytes(vd2), u.klstart]
    u.csrs(klstart=0).vstart = 4
    r += [u.mv_vec(vd3, sew=64, out=True), bytes(vd3), u.klstart]
    u.vstart = 1
    r += [trap_of(u.mv_vec, bytearray(32), out=True)]
    u.vstart = 0
    r += [trap_of(u.mv_vec, bytearray(24), out=True), trap_of(fresh(zklv=False).mv_vec, bytearray(16))]
    eq('vector kl.mvout across image_end, from beyond it, vstart >= vl, 16-byte multiples, Zklv', r,
       ['moved', True, bytes(48), 48, 0, 'zeros', bytes(32), 48, 'noop', b'\xEE' * 32, 0] + ['illegal/1'] * 3)
    content, imgs = pi_content(xof(), 0x10), []
    for sew in (8, 16, 32, 64):
        w = opened(m=xof())
        w.mv_vec(bytearray(content), sew=sew, halt_after=16)
        h = (w.klstart, w.vstart)
        imgs.append((h, w.mv_vec(bytearray(content), sew=sew), img(w), w.klstart, w.vstart))
    eq('interrupted vector kl.mvin: klstart in bytes, vstart in elements; same image for every SEW', imgs,
       [((16, 16 // (s // 8)), 'moved', content, 32, 0) for s in (8, 16, 32, 64)])
    u = opened(m=xof()).csrs(kliobuflen=64, kliobuftop=32)
    u.kliobuf[:32] = content[:32]
    r = [u.mv_iobuf(), u.klstart, img(u)[:32] == content[:32], trap_of(u.csrs(kliobuftop=24).mv_iobuf),
         fresh().csrs(kliobuflen=64).mv_iobuf(), trap_of(opened(zklio=False).mv_iobuf),
         trap_of(opened().mv_iobuf), u.csrs(kliobuftop=32).mgmt(0, END), u.mgmt(0, EXP), u.mv_iobuf(out=True),
         bytes(u.kliobuf[:16]) == v2b(u.siv, 16), u.klstart]
    eq('KLIOBUF variants: kliobuftop bytes (a multiple of 16) between KLIOBUF[0, top-1] and S from klstart, both ways; '
       'kliobuftop % 16 illegal/2; klnamedlocker 32 a no-op; no Zklio, hence no KLIOBUF, or an unconfigured one '
       'illegal/2 (second group, after the locker-state-independent checks)', r,
       ['moved', 32, True, 'illegal/2', 'noop', 'illegal/2', 'illegal/2', 'completed', 'opened', 'moved',
        True, 32])
    u.kliobuf[:48] = b'\xEE' * 48
    r = [u.csrs(kliobuftop=48).mv_iobuf(out=True), bytes(u.kliobuf[:16]) == bytes(u._s_get(u.klnamedlocker, 32)), bytes(u.kliobuf[16:48]),
         u.klstart]
    eq('KLIOBUF kl.mvout across image_end: the block before it moves, the later ones are zeroed, klstart stops '
       'at image_end', r, ['moved', True, bytes(32), 48])
    w, mem = opened(m=xof()), Memory(v2b(0xEF, 16) + v2b(0xCD, 16))
    w.mv_in(0xAB)
    eq('kl.mvin and kl.load combined: each byte holds the value last written',
       (w.csrs(klstart=16).load(mem, BASE), img(w), w.mv_in(0x77), img(w)[:16]),
       ('done', v2b(0xAB, 16) + v2b(0xCD, 16), 'moved', v2b(0x77, 16)))

def t_kliobuf():
    section('KLIOBUF  <<KLE-CSR-kliobuflen>>, <<KLE-CSR-kliobuftop>>, <<KLE-iobuf-transfer-window>>')
    u, n = fresh(maxiobuflen=128), fresh(zklio=False)
    r = [[u.csr_read(c) for c in ('kliobuflen', 'kliobuftop', 'klstart', 'klnamedlocker')],
         trap_of(u.input_, Memory(), BASE, 16), u.csrs(kliobuflen=64).kliobuftop]
    u.kliobuf[:4] = b'\xFF' * 4
    r += [bytes(u.csrs(kliobuftop=20, kliobuflen=64).kliobuf), u.kliobuftop,
          u.csrs(kliobuflen=1000, kliobuftop=1000).kliobuflen, u.kliobuftop]
    u.kliobuf[:4] = b'\1\2\3\4'
    eq('reset values, GR15, kliobuflen write zeroes and sets top, WARL, top keeps data, no Zklio',
       r + [bytes(u.csrs(kliobuftop=40).kliobuf[:4]), n.csr_read('klmaxiobuflen'), trap_of(n.csr_read, 'kliobuflen'),
            trap_of(n.csr_write, 'kliobuftop', 1), trap_of(n.input_, Memory(), BASE, 16),
            trap_of(u.csr_write, 'klmaxiobuflen', 5)],
       [[0, 0, 0, 32], 'illegal/2', 64, bytes(64), 64, 128, 128, b'\1\2\3\4', 0, 'illegal/1', 'illegal/1',
        'illegal/2', 'illegal/1'])
    m, s_, n2 = Unit(), Unit(), Unit(zklio=False)
    s_.mode = 'S'
    v = [m.csr_read('mklvendorid'), m.csr_read('mklarchid'), m.csr_read('mklimpid'), m.csr_read('mklmaxiobuflen')]
    m.csr_write('mklvendorid', 0x55); m.csr_write('mklarchid', 0x66); m.csr_write('mklimpid', 0x77)
    eq('IMPQUAL keeps the reset IDs after M-mode writes mkl*id (KLE-CSR-impl-ids)',
       m.impqual_value(), cat((0, 32), (0x7, 32), (0x42, 32), (0xA11, 32)))
    m.csrs(kliobuflen=200)
    m.csr_write('mklmaxiobuflen', 100)
    w = [m.csr_read(c) for c in Unit.RO_ID] + [m.kliobuflen, m.kliobuftop]
    m.csr_write('mklmaxiobuflen', 4)
    w += [m.csr_read('klmaxiobuflen')]
    n2.csr_write('mklmaxiobuflen', 64)
    eq('mkl* registers: M-mode read/write, klm* aliases follow, WARL maxiobuflen, reduction clips kliobuflen, '
       'illegal below M-mode, no effect without Zklio',
       v + w + [trap_of(s_.csr_read, 'mklimpid'), trap_of(s_.csr_write, 'mklmaxiobuflen', 32),
                s_.csr_read('klimpid'), n2.csr_read('mklmaxiobuflen'), n2.csr_read('klmaxiobuflen')],
       [0xA11, 0x42, 0x7, 256, 0x55, 0x66, 0x77, 100, 100, 100, 16, 'illegal/1', 'illegal/1', 0x7, 0, 0])
    src = bytes(0x10 + 3 * i & 0xFF for i in range(64))
    u, mem = fresh().csrs(kliobuflen=64, kliobuftop=48), Memory(src)
    u.input_(mem, BASE, 64)
    r = [bytes(u.kliobuf)]
    u.csrs(kliobuflen=64).input_(mem, BASE, 20)
    r += [bytes(u.kliobuf), u.input_(mem, BASE + 3, 4)]
    r += [(u.csrs(klstart=s).input_(mem, BASE, xl), u.klstart) for s, xl in ((7, 0), (64, 64), (65, 64), (30, 20))]
    eq('window [klstart, min(Xl, kliobuftop)); any alignment; transferring nothing retires with klstart 0',
       r + [(u.csrs(klstart=100).output(Memory(), BASE, 64), u.klstart)],
       [src[:48] + bytes(16), src[:20] + bytes(44), 'done'] + [('empty', 0)] * 5)
    u, dst = fresh().csrs(kliobuflen=64), Memory()
    r = [u.input_(mem, BASE, 64, halt_after=20), u.klstart, bytes(u.kliobuf), u.input_(mem, BASE, 64), u.klstart,
         bytes(u.kliobuf), u.output(dst, BASE, 64, halt_after=48), u.klstart, dst.read(BASE, 64),
         u.output(dst, BASE, 64),
         dst.read(BASE, 64), u.klstart, u.csrs(kliobuflen=32, klstart=8).input_(mem, BASE, 32), bytes(u.kliobuf)]
    dst.unmapped.append((BASE + 10, BASE + 11))
    r += [trap_of(u.csrs(klstart=0).output, dst, BASE, 32), u.klstart, trap_of(u.output, dst, BASE, 32, restart=True),
          u.klstart]
    dst.unmapped.clear()
    eq('interrupted transfers resume from klstart on both sides; faults halt at the byte; KLLEN',
       r + [u.csrs(klstart=0).output(dst, BASE, 32, halt_after=8, restart=True), u.klstart, u.kliobuftop * 8],
       ['halted', 20, src[:20] + bytes(44), 'done', 0, src, 'halted', 48, src[:48] + bytes(16), 'done', src, 0, 'done',
        bytes(8) + src[8:32], 'store_page_fault', 10, 'store_page_fault', 10, 'halted', 0, 256])

def t_sgr():
    section('State Management rules  <<KLE-State-management>>')
    u = pv(fresh(), 0, cipher())
    tag = MACHINES[M_CIPHER].verify_tag(u, u.lockers[0])
    eq('GR28: a new CC is Ready; GR29: VERIFY lands in Success or Failure',
       [u.getst(0)] + [(u.setst(0, ToyCipher.VERIFY, t), u.getst(0), u.setst(0, READY))[1] for t in (tag, tag ^ 1)],
       [READY, SUCCESS, FAILURE])
    u, x, out = pv(fresh(), 0, cipher()), pv(fresh(), 0, xof()), bytearray(b'\x55' * 16)
    eq('GR21: kl.exec in Ready -> Invalid, output zeroed, klstart 0; unless the Machine allows it',
       (u.exec_(0, 'A', vin=bytearray(16), vout=out), u.getst(0), bytes(out), u.klstart,
        x.exec_(0, 'B', vin=bytearray(b'abc')), x.getst(0)), ('invalid', INVALID, bytes(16), 0, 'done', ToyXof.ABSORB))
    u = rc()
    eq('GR21 same-State kl.setst; GR23 -> Ready erases state; unsupported or forbidden -> Invalid',
       (u.setst(0, ToyCipher.ENCRYPT, 3), u.getst(0), u.setst(0, READY), u.getst(0), u.getstx(0),
        [pv(fresh(), 0, cipher()).setst(0, imm) for imm in (5, 45, 66, 127)],
        pv(fresh(), 0, cipher(MachinePolicy=2)).setst(0, ToyCipher.ENCRYPT)),
       ('ok', ToyCipher.ENCRYPT, 'ok', READY, 0, ['invalid'] * 4, 'invalid'))
    x = pv(fresh(), 0, xof())
    eq('GR21: same-State kl.setst in Ready admitted; in a State where the Machine does not allow it -> Invalid',
       (x.setst(0, READY), x.getst(0), x.setst(0, ToyXof.ABSORB), x.setst(0, ToyXof.ABSORB), x.getst(0)),
       ('ok', READY, 'ok', 'invalid', INVALID))
    for final in (SUCCESS, FAILURE):
        w = [final_cipher(final, SCProtection=1) for _ in range(7)]
        eq(f'GR23 in State {final}: allowed exits, Invalid otherwise, permitted instructions',
           [w[0].setst(0, READY), w[0].getst(0), w[1].setst(0, 0), w[1].getst(0), w[2].setst(0, PRIV), w[2].getst(0),
            w[3].setst(0, CLEAR_ADS), w[3].getst(0), w[3].getmd(0)['AuxDataLen'], w[4].setst(0, ToyCipher.ENCRYPT),
            w[4].getst(0), ex(w[5], 0), w[5].getst(0), import_(fresh(), 0, export(w[6], 0)), w[6].size(k=0) > 16,
            w[6].avail(k=0), w[6].getst(0), w[6].clone(1, 0), w[6].restrict(0, rq(UsagePolicy=0b11110))],
           ['ok', READY, 'cleared', 0, 'error state', PRIV, 'ads cleared', final, 0, 'invalid', INVALID, 'invalid',
            INVALID, final, True, 1, final, 'cloned', 'ok'])
    u = xof_squeezing(fresh(), 0, b'seed')
    eq('an unbounded XOF squeezes in its output State and never reaches Success, where GR23 admits no kl.exec',
       (u.getst(0), u.exec_(0, 'C', vout=bytearray(4)), u.getmd(0)['MachineUse']), (ToyXof.FINAL, 'done', 4))
    u = fresh()
    vo = bytearray(b'\xAA' * 32)
    eq('GR33: usage instructions on an Unconfigured locker are no-ops, output zeroed, State kept',
       [u.exec_(0, 'D'), u.exec_(0, 'C', vout=vo), bytes(vo), u.setst(0, READY), u.setst(0, CLEAR_ADS),
        u.derive(1, 0, 32), u.getst(0), u.getst(1)],
       ['noop', 'noop', bytes(32), 'noop', 'noop', 'noop', UNCONF, UNCONF])
    u, w, buf = rc(), rc(), bytearray(b'\xBB' * 32)
    u.setst(0, INVALID)
    u.csrs(kliobuflen=64).kliobuf[:] = b'\xAA' * 64
    w.setst(0, EXPIRED)
    w.vstart = 2
    eq('GR35: Error-State kl.exec zeroes [klstart, kliobuftop-1] of Form D, elements vstart..vl-1 of Vd; '
       'SEW = 128 sets vtype.vill (KLV)',
       (u.csrs(klstart=16).exec_(0, 'D'), bytes(u.kliobuf),
        trap_of(w.csrs(klstart=16).exec_, 0, 'A', vin=buf, vout=buf, sew=128),
        w.exec_(0, 'A', vin=buf, vout=buf, sew=64), bytes(buf)),
       ('noop', b'\xAA' * 16 + bytes(48), 'illegal/1', 'noop', b'\xBB' * 16 + bytes(16)))
    info('A Form D kl.exec on an Error-State locker zeroes [klstart, kliobuftop-1], although whether it is a '
         'substitution depends on an operation the Error State does not define (per the purpose of GR35).')
    u, w = opened(), opened(k=3)
    r = [trap_of(u.exec_, 0, 'D'), trap_of(u.setst, 0, READY), trap_of(u.clone, 1, 0),
         trap_of(u.restrict, 0, rq(UsagePolicy=0b11110)), provision(u.csrs(klnamedlocker=32), 2, cipher())]
    eq('GR30 on a Configuration-State locker; cloning onto it releases klnamedlocker; same-index clone no-op',
       r + [u.csrs(klnamedlocker=0).clone(0, 2), u.getst(0), u.klnamedlocker, w.clone(3, 3), w.getst(3),
            w.clone(9, 9)],
       ['privilege_violation'] * 4 + [READY, 'cloned', READY, NONE, 'noop', PROV, 'noop'])

    def gated(**kw):
        w = rc(unit=fresh(**kw), ExpirationDate=5, UsagePolicy=0b00111)
        w.clock = 10
        return w
    w1, w2, w3, w4, w5, w6, w7, w8 = gated(), opened(), gated(), gated(zklio=False), gated(), \
        gated(mode='S').csrs(kliobuflen=16), rc(), pv(fresh(), 0, cipher())
    w9, w10 = gated(), gated(mode='S')                    # KLIOBUF unconfigured: checked before UsagePolicy and expiry
    w1.setst(0, INVALID)
    eq('GR17, GR33, GR22: Error State > Configuration > KLIOBUF > UsagePolicy > expiry > Machine; a wrong Form, '
       'a substitution without Zklio included, is one of the Machine\'s rules (GR14, GR13)',
       [(ex(w1, 0), w1.getst(0)), trap_of(w2.exec_, 0, 'B', vin=bytearray(16)),
        trap_of(w3.exec_, 0, 'B', vin=bytearray(16)),
        trap_of(w4.exec_, 0, 'D'), (trap_of(ex, w5, 0), w5.getst(0)), (w6.exec_(0, 'D'), w6.getst(0)),
        (trap_of(w7.exec_, 0, 'D'), w7.getst(0)), (w8.exec_(0, 'D'), w8.getst(0)),
        trap_of(w9.exec_, 0, 'D'), (trap_of(w10.exec_, 0, 'D'), w10.getst(0))],
       [('noop', INVALID), 'privilege_violation', 'privilege_violation', 'privilege_violation',
        ('privilege_violation', ToyCipher.ENCRYPT),
        ('expired', EXPIRED), ('illegal/2', ToyCipher.ENCRYPT), ('invalid', INVALID),
        'illegal/2', ('illegal/2', ToyCipher.ENCRYPT)])
    wf = [rc(), rc(), rc(unit=fresh(zklio=False))]
    eq('a wrong Form invalidates the locker, no exception: Form B or C kl.exec where Form A is native; a Form D '
       'substitution without Zklio (GR14, GR13, GR22)',
       [(wf[0].exec_(0, 'B', vin=bytearray(16)), wf[0].getst(0)), (wf[1].exec_(0, 'C', vout=bytearray(16)),
         wf[1].getst(0)), (wf[2].exec_(0, 'D'), wf[2].getst(0))], [('invalid', INVALID)] * 3)
    wr = [rc(), rc()]
    eq('GR23: a kl.setst naming Ready is of Form A; a Form B or C one is a wrong Form (GR13, GR22)',
       [(wr[0].setst(0, READY, 1, form='C'), wr[0].getst(0)), (wr[1].setst(0, READY, form='B'), wr[1].getst(0))],
       [('invalid', INVALID)] * 2)
    wc = [rc(), rc()]
    eq('GR23: kl.clearads is of Form A; a Form B or C kl.setst with #immed7 = 64 is a wrong Form (GR13, GR22)',
       [(wc[0].setst(0, CLEAR_ADS, 1, form='C'), wc[0].getst(0)), (wc[1].setst(0, CLEAR_ADS, form='B'),
         wc[1].getst(0))], [('invalid', INVALID)] * 2)
    rows = []
    for st in CONFIG:
        w, p = white_box(st, bytes(64)), opened()
        rows += [[trap_of(w.size, k=0), trap_of(w.avail, k=0), trap_of(w.getmd, 0), trap_of(w.getst, 0),
                  trap_of(w.swap, 1, 0), trap_of(w.rename, 0, 1), trap_of(w.setst, 0, EXPIRED)],
                 [trap_of(p.setst, 0, 0), trap_of(p.clearall)] + [None] * 5]
    w = opened()
    eq('GR30: size, avail, getmd*, getst, swap, rename, Error/clear kl.setst, kl.clearall in Configuration States',
       (rows, w.setst(0, INVALID), w.klnamedlocker), ([[None] * 7] * 10, 'error state', 0))
    w = rc().csrs(klstart=32, klnamedlocker=0)
    r = [w.setst(0, 0, aux=5, form='C'), w.klstart, w.klnamedlocker, w.clf_free() == w.clf_total]
    w = rc(unit=fresh(siv=3))
    w.mgmt(1, IMP, cipher(State=1))
    w.csrs(kliobuflen=64, klstart=16)
    eq('kl.clear, kl.clearall, reserved #immed7 65 forms',
       r + [w.setst(0, CLEARALL), [w.getst(k) for k in range(32)], w.kliobuflen, w.kliobuftop, bytes(w.kliobuf),
            w.klstart, w.klnamedlocker, w.siv, w.clf_free() == w.clf_total, trap_of(w.setst, 0, CLEARALL, form='C'),
            trap_of(w.setst, 3, CLEARALL)],
       ['cleared', 32, NONE, True, 'cleared all', [0] * 32, 0, 0, b'', 0, 32, 0, True] + ['illegal/1'] * 2)
    c = rc(5)                                                       # K0 Unconfigured, K5 configured
    eq('kl.clearall (#immed7 65, locker 0) clears every locker even when K0 is Unconfigured; not a no-op',
       (c.getst(0), c.setst(0, CLEARALL), c.getst(5)), (0, 'cleared all', 0))
    w = fresh()
    r = [w.clone(1, 0)]
    rc(unit=w, SCProtection=1)
    w.siv, w.impqual, w.siv2 = 1, 2, 3
    cl = lambda k: (w.getmd(k), w.lockers[k].c1, w.lockers[k].c2, w.lockers[k].alloc)
    r += [w.clone(1, 0), cl(1) == cl(0), (w.siv, w.impqual, w.siv2), import_(w, 2, export(w, 0)),
          cl(2)[:2] == cl(1)[:2]]
    t = rc(0, rc(1, fresh(clf_total=2 * MACHINES[M_CIPHER].clf_capacity(cipher(SCProtection=1))), SCProtection=1),
           SCProtection=1)
    r += [t.clone(1, 0), t.clf_free(), trap_of(t.clone, 2, 0), t.getst(2), t.restrict(1, rq(MachinePolicy=1)),
          t.getmd(1)['MachinePolicy'], t.getmd(0)['MachinePolicy']]
    eq('kl.clone: Unconfigured source clears Kd; perfect copy = export+import; capacity; clone then restrict', r,
       ['cleared', 'cloned', True, (1, 2, 3), ToyCipher.ENCRYPT, True, 'cloned', 0, 'out_of_memory', 0, 'ok', 1, 3])
    cap = lambda **kw: MACHINES[M_CIPHER].clf_capacity(cipher(**kw))
    t = rc(1, rc(0, fresh(clf_total=cap(SCProtection=1) + cap()), SCProtection=1)).csrs(klnamedlocker=1)
    c = opened(k=0)
    pv(c.csrs(klnamedlocker=32), 2, cipher())
    eq('kl.clone clears Kd first (destructive): Kd stays Unconfigured after out-of-memory or a Configuration-State '
       'source, and klnamedlocker naming Kd becomes 32',
       [trap_of(t.clone, 1, 0), t.getst(1), t.klnamedlocker, t.clf_free() == cap(),
        trap_of(c.clone, 2, 0), c.getst(2), c.getst(0)],
       ['out_of_memory', 0, NONE, True, 'privilege_violation', 0, PROV])
    w = rc().csrs(klstart=16)
    w.vstart = 16
    ks = [(f(), w.klstart)[1] for f in (lambda: w.getmd(0), lambda: w.size(k=0), lambda: w.avail(k=0),
                                        lambda: w.restrict(0, rq(UsagePolicy=0b11110), 'h'), lambda: w.clone(1, 0),
                                        lambda: w.rename(2, 1), lambda: w.swap(1, 2),
                                        lambda: w.setst(0, ToyCipher.ENCRYPT, 1))]
    eq('getmd, size, avail, restrict, clone, rename, swap, setst leave klstart', ks, [16] * 8)

def t_exec():
    section('kl.exec and klstart  <<KLE-resumability>>')
    pt, ref = bytes(0x61 + i & 0xFF for i in range(64)), rc()
    whole = bytearray(pt)
    ref.exec_(0, 'A', vin=whole, vout=whole)
    rows = []
    for sew in (8, 16, 32):
        u, buf = rc(), bytearray(pt)
        h = (u.exec_(0, 'A', vin=buf, vout=buf, sew=sew, halt_after=32), u.klstart, u.vstart)
        rows.append((h, u.exec_(0, 'A', vin=buf, vout=buf, sew=sew), buf == whole, u.lockers[0].c1 == ref.lockers[0].c1,
                     u.klstart, u.vstart))
    eq('an interrupted kl.exec commits whole blocks and resumes to the uninterrupted result', rows,
       [(('halted', 32, 32 * 8 // s), 'done', True, True, 0, 0) for s in (8, 16, 32)])
    u, buf = rc(), bytearray(pt)
    u.exec_(0, 'A', vin=buf, vout=buf, halt_after=32)
    r = [trap_of(u.csrs(klstart=16).exec_, 0, 'A', vin=buf, vout=buf)]
    u.lockers[0].mdh['State'] = INVALID
    r.append(trap_of(u.exec_, 0, 'A', vin=buf, vout=buf))
    u, buf = rc(), bytearray(pt)
    u.exec_(0, 'A', vin=buf, vout=buf, halt_after=32)
    u.csrs(klstart=0).vstart = 0
    u.exec_(0, 'A', vin=buf, vout=buf)
    eq('klstart != vstart*SEW/8 illegal/2 before the Error State; forced klstart 0 re-applies blocks',
       r + [buf != whole], ['illegal/2', 'illegal/2', True])
    rows = []
    for n, ks in ((64, 64), (64, 80), (0, 0), (40, 40)):
        v, b = rc(unit=fresh(vstart=ks)).csrs(klstart=ks), bytearray(pt[:n])
        rows.append((v.exec_(0, 'A', vin=b, vout=b), bytes(b), v.getst(0), v.klstart, v.vstart))
    eq('klstart >= VL*SEW/8 (64 of 64, 80 of 64) or a zero-length window: empty, never reaches the Machine, only '
       'klstart = vstart = 0; 40 of 40: invalid length first, Invalid', rows,
       [('empty', pt, ToyCipher.ENCRYPT, 0, 0)] * 2 + [('empty', b'', ToyCipher.ENCRYPT, 0, 0),
                                                       ('invalid', pt[:40], INVALID, 0, 0)])
    u, buf = rc(unit=fresh(vstart=8)).csrs(klstart=8), bytearray(pt)
    eq('input klstart = 8 (no interruption point) -> Invalid, elements vstart.. of Vd zeroed, Content cleared',
       (u.exec_(0, 'A', vin=buf, vout=buf), u.getst(0), bytes(buf), u.lockers[0].c1, u.klstart),
       ('invalid', INVALID, pt[:8] + bytes(56), b'', 0))
    u, w = rc().csrs(kliobuflen=64), rc().csrs(kliobuflen=40)
    x, y = (xof_squeezing(fresh(), 0, b'x').csrs(kliobuflen=16) for _ in range(2))
    u.kliobuf[:] = pt
    y.kliobuf[:] = b'\xCC' * 16
    b0, b1 = snapshot(x), snapshot(y)
    x.csrs(klstart=16), y.csrs(klstart=20)
    eq('Form D in place; bad kliobuftop Invalid; output-only klstart >= kliobuftop (16, 20) only writes klstart 0',
       [u.exec_(0, 'D'), u.kliobuf == whole, w.exec_(0, 'D'), w.getst(0), x.exec_(0, 'D'), snapshot(x) == b0,
        y.exec_(0, 'D'), snapshot(y) == b1, x.exec_(0, 'D'), x.getmd(0)['MachineUse'],
        trap_of(fresh(zklv=False).exec_, 0, 'A')],
       ['done', True, 'invalid', INVALID, 'empty', True, 'empty', True, 'done', 16, 'illegal/1'])

def t_expiration():
    section('_ExpirationDate_  <<KLE-Metadata-expiration-date>>')

    def eu(clock, ed=1000, **kw):
        u = rc(unit=fresh(**kw), ExpirationDate=ed, SCProtection=1)
        u.clock = clock
        return u
    u, out = eu(2000), bytearray(b'\x11' * 16)
    eq('kl.exec on an expired locker: Expired, no operation or exception, output zeroed, content cleared',
       (u.exec_(0, 'A', vin=bytearray(16), vout=out), u.getst(0), bytes(out), u.lockers[0].c1,
        u.getmd(0)['AuxDataLen'], u.getmd(0)['ExpirationDate']), ('expired', EXPIRED, bytes(16), b'', 0, 1000))
    eq('evaluation at kl.setst and kl.clearads; at the stated hour; before it; pre-epoch clock; date 0; a reading '
       'past 2^20 - 1 hours saturates (no wrap to 5), so even the last date expires',
       [eu(2000).setst(0, READY), eu(2000).setst(0, CLEAR_ADS), eu(1000).setst(0, READY),
        eu(999).setst(0, ToyCipher.ENCRYPT, 1), eu(-50, ed=1).setst(0, READY),
        rc(unit=fresh(clock=1 << 30)).setst(0, READY), eu((1 << 20) + 5, ed=10).setst(0, READY),
        eu((1 << 20) + 5, ed=(1 << 20) - 1).setst(0, READY)],
       ['expired', 'expired', 'expired', 'ok', 'ok', 'ok', 'expired', 'expired'])
    u, buf = eu(0), bytearray(64)
    u.exec_(0, 'A', vin=buf, vout=buf, halt_after=32)
    u.clock = 5000
    eq('a resumption point is an evaluation point', (u.exec_(0, 'A', vin=buf, vout=buf), u.getst(0), u.klstart),
       ('expired', EXPIRED, 0))
    u, v, w = eu(5000), fresh(clock=5000), opened(m=cipher(ExpirationDate=10), clock=5000)
    img, end = export(u, 0), (w.mgmt(0, END), w.getst(0), w.csrs(klnamedlocker=NONE))[:2]
    w.mgmt(1, IMP, cipher(State=2, ExpirationDate=10))
    eq('not evaluated by export, size, import, clone, restrict, clear, provisioning, or outside Valid States',
       [u.getst(0), len(img) == u.size(k=0), import_(v, 0, img), u.clone(1, 0), u.restrict(1, rq(ExpirationDate=5)),
        u.getst(1), u.setst(0, 0), u.getst(0), *end, trap_of(w.exec_, 1, 'D'), w.getst(1)],
       [ToyCipher.ENCRYPT, True, ToyCipher.ENCRYPT, 'cloned', 'ok', ToyCipher.ENCRYPT, 'cleared', 0, 'completed', READY,
        'privilege_violation', IMP])
    w = eu(5000)
    w.lockers[0].mdh['UsagePolicy'] = 0b00111
    eq('UsagePolicy precedes the expiration (GR22)', (trap_of(w.setst, 0, READY), w.getst(0)),
       ('privilege_violation', ToyCipher.ENCRYPT))
    n, e, n2 = fresh(zklexpire=False, clock=1 << 30), pv(fresh(), 0, cipher()), rc(1, fresh(zklexpire=False))
    e.setst(0, EXPIRED)
    eq('without Zklexpire no locker gets a date; an Expired MDH imports as Invalid; reserved #53 is illegal/1',
       ((n.mgmt(0, PROV, cipher(ExpirationDate=1)), n.csrs(klnamedlocker=NONE))[0],
        rc(1, n).restrict(1, rq(ExpirationDate=1)),
        import_(n2, 0, export(e, 0)), trap_of(n2.setst, 1, EXPIRED), n2.getst(1)),
       ('invalid', 'invalid', INVALID, 'illegal/1', ToyCipher.ENCRYPT))
    u, out = rc(1, eu(0, ed=1 << 19)), bytearray(b'\x22' * 16)
    u.clock = None
    eq('an unreadable clock: a usage instruction on a non-zero date raises kl_exc_clock_unavailable, output and State '
       'kept, usable again once the clock reads; date 0 unaffected',
       (trap_of(u.exec_, 0, 'A', vin=bytearray(16), vout=out), u.getst(0), bytes(out), u.setst(1, READY),
        (setattr(u, 'clock', 0), u.exec_(0, 'A', vin=bytearray(16), vout=bytearray(16)))[1]),
       ('clock_unavailable', ToyCipher.ENCRYPT, b'\x22' * 16, 'ok', 'done'))
    u.lockers[0].mdh['UsagePolicy'] = 0b00111
    u.clock = None
    eq('UsagePolicy precedes the unreadable clock (GR22)', trap_of(u.exec_, 0, 'A', vin=bytearray(16),
                                                                        vout=bytearray(16)), 'privilege_violation')
    h = rc(1, eu(0, ed=1 << 19))
    h.clock = None
    tag = trap_of(h.exec_, 0, 'A', vin=bytearray(16), vout=bytearray(16))
    eq('SR9: a handler that cannot resolve kl_exc_clock_unavailable sets Expired by a kl.setst, which is no usage '
       'instruction and reads no clock', (tag, (h.setst(0, EXC_STATE[tag]), h.getst(0))[1]),
       ('clock_unavailable', EXPIRED))

def t_derive():
    section('kl.derive  <<KLE-instruction-derive>>, <<KLE-derive-endpoints>>')

    def pair(**kw):
        return pv(rc(0, fresh(**kw)), 1, cipher())
    src0, expect = pair().lockers[0].c1, bytearray(48)
    rc().exec_(0, 'A', vin=bytearray(48), vout=expect)
    u, u2, u3 = pair(), pair(), pair()
    nxt = bytearray(16)
    eq('CTR keystream into a Ready key field (GR44), the source advanced as by kl.exec of whole blocks, the unused '
       'bytes discarded; length < key -> destination Invalid',
       (u.derive(1, 0, 32), u.lockers[1].c1[:32], u.exec_(0, 'A', vin=bytearray(16), vout=nxt), bytes(nxt),
        u.getst(1), u2.derive(1, 0, 40), u2.exec_(0, 'A', vin=bytearray(16), vout=nxt), bytes(nxt),
        u3.derive(1, 0, 16), u3.getst(1), u3.getst(0), u3.lockers[0].c1 == src0),
       ('transferred', bytes(expect[:32]), 'done', bytes(expect[32:]), READY, 'transferred', 'done',
        bytes(expect[32:]), 'invalid', INVALID, ToyCipher.ENCRYPT, True))
    info('Toy endpoints follow <<KLE-derive-endpoints>> and <<KLE-admitted-pairs>>: the cipher in ENCRYPT stands for '
         'the keystream in Operate, unrestricted into a key only (GR44); the KEX shared secret is a restricted field '
         'into a key or, whole, into a XOF input (GR43); XOF output and the signature key are no endpoints.')
    u = [pair() for _ in range(6)]
    u[1].setst(1, EXPIRED)
    u[2].setst(0, 0)
    u[3].mgmt(1, EXP)
    u[4].lockers[1].mdh['UsagePolicy'] = 0b00111
    u[5].lockers[0].mdh['ExpirationDate'] = u[5].lockers[1].mdh['ExpirationDate'] = 1
    u[5].clock = 9
    eq('equal indices; Error-State endpoint no-op; Unconfigured; Configuration; UsagePolicy; both expire',
       [trap_of(u[0].derive, 0, 0, 32), u[1].derive(1, 0, 32), u[1].lockers[0].c1 == src0,
        u[2].derive(1, 0, 32),
        trap_of(u[3].derive, 1, 0, 32), trap_of(u[4].derive, 1, 0, 32), u[5].derive(1, 0, 32), u[5].getst(0),
        u[5].getst(1)],
       ['illegal/1', 'noop', True, 'noop', 'privilege_violation', 'privilege_violation', 'expired', EXPIRED, EXPIRED])
    u = [pair() for _ in range(8)]
    u[0].setst(1, ToyCipher.ENCRYPT, 1)
    u[1].setst(1, ToyCipher.VERIFY, MACHINES[M_CIPHER].verify_tag(u[1], u[1].lockers[1]))
    u[2].setst(0, READY)
    provision(u[3], 2, md(Machine=M_CUSTOM, MachinePolicy=1, Locality=loc(hw1=2)))
    provision(u[4], 3, cipher(KeyType=1), v2b(SKID_A, 16))
    provision(u[5], 2, sig())
    u[6].setst(0, READY)
    u[6].setst(1, ToyCipher.ENCRYPT, 1)
    provision(u[7], 2, sig())
    u[7].setst(2, ToySig.SET_SCALAR)
    eq('GR40 items 1-2: only the offending lockers (State, no destination endpoint, KeyType-1 key, a signature key '
       'in Ready or in its Machine-named State)',
       [(u[0].derive(1, 0, 32), u[0].getst(1), u[0].getst(0)), (u[1].derive(1, 0, 32), u[1].getst(1)),
        (u[2].derive(1, 0, 32), u[2].getst(0), u[2].getst(1)), (u[3].derive(2, 0, 32), u[3].getst(0), u[3].getst(2)),
        (u[4].derive(3, 0, 32), u[4].getst(3), u[4].getst(0), u[4].lockers[0].c1 == src0),
        (u[5].derive(2, 0, 64), u[5].getst(2), u[5].getst(0)), (u[6].derive(1, 0, 32), u[6].getst(0), u[6].getst(1)),
        (u[7].derive(2, 0, 64), u[7].getst(2), u[7].getst(0))],
       [('invalid', INVALID, ToyCipher.ENCRYPT), ('invalid', INVALID), ('invalid', INVALID, READY),
        ('invalid', ToyCipher.ENCRYPT, INVALID),
        ('invalid', INVALID, ToyCipher.ENCRYPT, True), ('invalid', INVALID, ToyCipher.ENCRYPT),
        ('invalid', INVALID, INVALID), ('invalid', INVALID, ToyCipher.ENCRYPT)])
    u = pair()
    key1 = bytes(u.lockers[1].c1)
    u.restrict(0, rq(MachinePolicy=2))
    eq('MR9 item 1.a: a keystream source in a State that the narrowed MachinePolicy disables goes to Invalid, '
       'nothing moves', (u.derive(1, 0, 32), u.getst(0), u.getst(1), bytes(u.lockers[1].c1) == key1),
       ('invalid', INVALID, READY, True))
    u, u2 = pv(pair(), 4, xof()), pv(pair(), 4, xof())
    eq('GR40 item 3: the keystream into a XOF input is no admitted pair, both Invalid, length 0 included',
       (u.derive(4, 0, 32), u.getst(4), u.getst(0), u2.derive(4, 0, 0), u2.getst(4), u2.getst(0)),
       ('invalid', INVALID, INVALID, 'invalid', INVALID, INVALID))
    u = pair()
    u.lockers[0].mdh.update(UsagePolicy=0b01110, Locality=loc(hw1=2))
    before = u.getmd(1)
    eq('the keystream into a key (GR44) is an unrestricted transfer: no narrowing (GR41)',
       (u.derive(1, 0, 32), u.getmd(1)), ('transferred', before))

    def kex(src=None, dst=None, dst_md=cipher, **kw):
        w = pv(fresh(**kw), 0, md(Machine=M_KEX, **(src or {})))
        w.setst(0, ToyKex.SHARED, 0x1234)
        return pv(w, 1, dst_md(**(dst or {})))
    w = kex(src=dict(UsagePolicy=0b11110, Locality=loc(hw1=2, mloc=1), ExpirationDate=500),
            dst=dict(UsagePolicy=0b11101, Locality=loc(hw1=1, sloc=1), ExpirationDate=900))
    secret = MACHINES[M_KEX].get_state(w.lockers[0])
    w2, w3, w4 = kex(src=dict(ExpirationDate=500)), kex(src=dict(SCProtection=1), dst=dict(SCProtection=2)), \
        kex(src=dict(UsagePolicy=0b01011), dst_md=xof)
    w5, w6, w7 = kex(src=dict(SCProtection=2), dst=dict(SCProtection=1)), kex(dst_md=xof), kex(dst_md=xof)
    eq('shared secret: restricted into a key and, whole, into a XOF (GR41, GR43; 32 or 65 of 64 B: destination '
       'Invalid, GR40 item 5); a destination at a level not lower than the source receives it, its level unchanged; '
       'a lower one: Privilege Violation, nothing moved',
       [w.derive(1, 0, 32), w.lockers[1].c1[:32] == secret[:32], w.getmd(1)['UsagePolicy'], w.getmd(1)['Locality'],
        w.getmd(1)['ExpirationDate'], w.getst(0), w2.derive(1, 0, 32), w2.getmd(1)['ExpirationDate'],
        w3.derive(1, 0, 32), w3.getmd(1)['SCProtection'], w4.derive(1, 0, 64), w4.getmd(1)['UsagePolicy'],
        w6.derive(1, 0, 32), w6.getst(1), w7.derive(1, 0, 65), w7.getst(1), w5.derive(1, 0, 32), w5.getst(1),
        w5.lockers[1].c1, w5.getst(0)],
       ['transferred', True, 0b11100, loc(hw1=2, mloc=1, sloc=1), 500, ToyKex.SHARED, 'transferred', 500, 'transferred',
        2, 'transferred', 0b01011, 'invalid', INVALID, 'invalid', INVALID, 'privilege_violation', PRIV, b'', ToyKex.SHARED])
    pv(w2, 2, cipher())
    eq('a field source does not advance: the shared secret is derived again, whole, into a second key (GR39)',
       (w2.derive(2, 0, 32), w2.lockers[2].c1[:32] == w2.lockers[1].c1[:32] == secret[:32], w2.getst(0)),
       ('transferred', True, ToyKex.SHARED))
    rows = []
    for w, n in ((kex(), 32), (kex(dst_md=xof), 64), (pair(), 32)):
        w.csrs(klstart=16)
        rows.append((w.derive(1, 0, n), w.getst(1), w.klstart))
    w = fresh().csrs(klstart=16)
    eq('GR40 item 7: kl.derive requires klstart = 0, else destination Invalid; every retirement '
       'writes klstart = 0 (GR52), a no-op included',
       rows + [(w.derive(1, 0, 32), w.getst(1), w.klstart)], [('invalid', INVALID, 0)] * 3 + [('noop', UNCONF, 0)])
    p1, x = kex(src=dict(UsagePolicy=0b01110), dst_md=sig), pv(pair(), 2, sig())
    p1.setst(1, ToySig.SET_SCALAR)
    x.setst(2, ToySig.SET_SCALAR)
    eq('a private key is no destination, also in its Machine-named State (GR40 item 2): neither the shared secret '
       'nor the keystream moves, only the destination Invalid',
       [p1.derive(1, 0, 64), p1.getst(1), p1.getst(0), x.derive(2, 0, 64), x.getst(2),
        x.getst(0)],
       ['invalid', INVALID, ToyKex.SHARED, 'invalid', INVALID, ToyCipher.ENCRYPT])
    rows = []
    for kw in (dict(src=dict(Locality=loc(boot=1)), dst=dict(Locality=loc(boot=2))),
               dict(src=dict(Locality=loc(sloc=1)))):
        w = kex(**kw)
        w.slocality = 0
        rows.append((w.derive(1, 0, 32), w.getst(1), w.getst(0), MACHINES[M_KEX].get_state(w.lockers[0]) == secret))
    w1, w2, w3 = kex(), kex(), kex(src=dict(UsagePolicy=0b01011))
    w1.setst(0, READY)
    w2.setst(1, ToyCipher.ENCRYPT, 1)
    eq('GR41 failed narrowings: Privilege Violation; GR43 without a secret or a non-Ready key: Invalid; GR40 checks '
       'precede GR41 narrowing',
       rows + [(w1.derive(1, 0, 32), w1.getst(0), w1.getst(1)), (w2.derive(1, 0, 32), w2.getst(1), w2.getst(0)),
               (w3.derive(1, 0, 8), w3.getst(1), w3.getmd(1)['UsagePolicy'])],
       [('privilege_violation', PRIV, ToyKex.SHARED, True)] * 2
       + [('invalid', INVALID, READY), ('invalid', INVALID, ToyKex.SHARED), ('invalid', INVALID, 0b01111)])

def t_errors():
    section('Error handling, CSK, KLS, Off gate  <<KLE-error-architecture>>, <<KLE-CSR-llockerstatus>>')
    cap = MACHINES[M_CIPHER].clf_capacity(cipher())
    def excs(priv):
        u1, u2 = fresh(priv=priv).csrs(klstart=16), fresh(priv=priv, clf_total=10)
        u3 = rc(unit=fresh(priv=priv), UsagePolicy=0b00111)
        u4, u5 = opened(priv=priv), pv(fresh(priv=priv, clf_total=cap), 0, cipher())
        u5.mgmt(1, IMP, cipher(State=EXPIRED))
        return [trap_of(u1.mgmt, 0, PROV, md(Machine=M_ABSENT, MachinePolicy=1)), u1.getst(0), u1.klnamedlocker,
                trap_of(u2.mgmt, 0, IMP, cipher(State=1)), u2.getst(0), trap_of(ex, u3, 0), u3.getst(0),
                trap_of(u4.clone, 1, 0), trap_of(u4.restrict, 0, rq(UsagePolicy=0b11110), 'h'), u4.getst(0),
                trap_of(u5.clone, 2, 0), u5.getst(2), trap_of(fresh(priv=priv, csk=0).getmd, 0),
                trap_of(fresh(priv=priv).input_, Memory(), BASE, 1)]
    r = excs(False)
    eq('no Privileged Architecture: every KLE exception is still raised, exactly as with it; a locker in a '
       'Configuration State keeps its State (GR30)', (r, [r[i] for i in (0, 3, 5, 7, 8, 10, 12, 13)]),
       (excs(True), ['unsupported', 'out_of_memory', 'privilege_violation', 'privilege_violation',
                     'privilege_violation', 'out_of_memory', 'no_csk', 'illegal/2']))
    u, mem, out = pv(fresh(), 0, cipher()), Memory(), bytearray(b'\x11' * 16)
    m, n = u.getmd(0), u.size(k=0)
    u.mgmt(0, EXP)
    r = [trap_of(u.exec_, 0, 'A', vin=bytearray(16), vout=out), u.getst(0)]
    out[:] = bytes(16)                                              # the handler zeroes the output, keeps the State
    u.store(mem, BASE)
    r += [u.mgmt(0, END, m), u.getst(0), import_(fresh(), 3, mdh_bytes(m) + mem.read(BASE, n - 16))]
    eq('a stray kl.exec on a kl_cfg_exporting locker: privilege violation, State kept (GR30); the handler skips it, '
       'and the export completes and imports', r, ['privilege_violation', EXP, 'completed', READY, READY])
    u, ml, v = fresh(), md(Machine=M_ABSENT, MachinePolicy=1, UsagePolicy=0b01100), rc(UsagePolicy=0b00111)
    b0 = snapshot(v)
    eq('handler: kl.setste records the Error State on Unconfigured (GR37), and so does a short import, which '
       'installs its MDH; exceptions change no state',
       (trap_of(u.mgmt, 7, PROV, ml), u.setst(7, UNSUP), u.getst(7), u.mgmt(7, IMP, dict(ml, State=UNSUP)), u.getmd(7),
        trap_of(ex, v, 0), snapshot(v) == b0),
       ('unsupported', 'error state', UNSUP, 'short import', md(**dict(ml, State=UNSUP)), 'privilege_violation', True))
    u, k = fresh(csk=0), fresh(kls_off=True)
    eq('no CSK: kl_exc_no_csk; KLS Off: illegal/1; identification CSRs exempt from both',
       ([trap_of(u.getmd, 0), trap_of(u.clearall), trap_of(u.csr_read, 'klstart'),
         trap_of(u.input_, Memory(), BASE, 1)],
        [u.csr_read(c) for c in Unit.RO_ID], [trap_of(k.getmd, 0), trap_of(k.csr_write, 'klstart', 0),
                                              trap_of(k.mgmt, 0, PROV, cipher())], k.csr_read('klimpid')),
       (['no_csk'] * 4, [0xA11, 0x42, 0x7, 256], ['illegal/1'] * 3, 0x7))
    u = rc()
    u.mode, u.llstatus = 'S', {0: 'off', 5: 'off'}
    eq('Off locker: each access traps; first group precedes; precedes the second group; source never exempt',
       [trap_of(u.getmd, 0), trap_of(u.size, k=0), trap_of(u.exec_, 0, 'D'), trap_of(u.restrict, 0, 0, 'h'),
        trap_of(u.clone, 1, 0), trap_of(u.mgmt, 0, EXP), trap_of(u.csrs(klnamedlocker=0).load, Memory(), BASE),
        trap_of(u.mv_in, 1), trap_of(u.setst, 0, 61), trap_of(u.clone, 1, 5), trap_of(u.clone, 5, 0)],
       ['locker_off'] * 8 + ['illegal/1', 'locker_off', 'locker_off'])
    u.csrs(klnamedlocker=32)
    u.llstatus.update({0: 'clean', 6: 'off', 7: 'clean', 8: 'off', 9: 'off'})
    L = u.llstatus
    eq('exempt accesses execute and set Dirty; none before the zeroizing step',
       [u.clone(5, 0), L[5], u.setst(6, 0), L[6], u.setst(7, 0), L[7], u.mgmt(8, PROV, cipher()), L[8],
        trap_of(u.mgmt, 9, PROV, cipher(), form='B', vec_bits=64), L[9],
        trap_of(u.csrs(klnamedlocker=32).mgmt, 9, PROV, md(Machine=M_ABSENT)),
        L[9]],
       ['cloned', 'dirty', 'cleared', 'dirty', 'cleared', 'clean', 'opened', 'dirty', 'illegal/2', 'off', 'unsupported',
        'dirty'])
    rc(12, u.csrs(klnamedlocker=32))
    L.update({12: 'off', 13: 'off', 14: 'off', 15: 'off'})
    r = [trap_of(u.rename, 13, 12), L[13]]
    L[12] = 'clean'
    r += [u.rename(13, 12), L[12], L[13], u.clone(14, 14), u.rename(14, 14), L[14], trap_of(u.swap, 15, 13),
          trap_of(u.swap, 13, 15), u.swap(15, 15), L[15]]
    L.update({13: 'clean', 16: 'clean', 10: 'off'})
    r += [u.swap(16, 13), L[13], L[16], u.clearall(), L[10]]
    u.mode, L[0] = 'M', 'off'
    eq('kl.rename, same-index kl.clone/kl.rename/kl.swap (no-op, not Dirty), kl.swap, kl.clearall under Off; M-mode',
       r + [trap_of(u.getmd, 0)],
       ['locker_off', 'off', 'renamed', 'dirty', 'dirty', 'noop', 'noop', 'off', 'locker_off', 'locker_off', 'noop',
        'off', 'swapped', 'dirty', 'dirty', 'cleared all', 'dirty', None])

def build_context(u):
    """An interrupted import (K2, managed), an abandoned provisioning (K5), other lockers, a KLIOBUF."""
    ex(rc(0, u, SCProtection=1), 0, n=32)
    pv(u, 1, cipher()).setst(1, EXPIRED)
    pv(u, 7, sig()).restrict(7, rq(UsagePolicy=0b11110), 'h')
    u.mgmt(5, PROV, xof())
    u.mv_in(0x1111)
    src, ml, mem, _ = interrupted_import(u.csrs(klnamedlocker=32), 2, 64, decrypt=True)
    u.csrs(klnamedlocker=32, klstart=0, kliobuflen=64).input_(Memory(bytes(5 * i + 1 & 0xFF for i in range(64))),
                                                                BASE, 64)
    u.csrs(kliobuftop=40, klstart=64, klnamedlocker=2)
    return src, ml, mem

def save_context(u):
    """<<KLE-save-order>>: the named locker first, without the KLIOBUF (Rule SR6), then the KLIOBUF and the other
    lockers, with 32 written before the KLIOBUF save and before each export (SR5)."""
    ctx = {c: u.csr_read(c) for c in ('klstart', 'klnamedlocker', 'kliobuflen', 'kliobuftop')}
    mc, ctx['images'] = ctx['klnamedlocker'], {}
    if mc < 32 and u.getmd(mc)['State'] != UNCONF:
        ctx['images'][mc] = export(u, mc)
    if ctx['kliobuflen']:
        mem = Memory()
        u.csrs(klnamedlocker=32, klstart=0, kliobuftop=ctx['kliobuflen']).output(mem, BASE, ctx['kliobuflen'])
        ctx['kliobuf'] = mem.read(BASE, ctx['kliobuflen'])
    for k in range(32):
        if k != mc and u.getst(k) != UNCONF:
            ctx['images'][k] = export(u.csrs(klnamedlocker=32), k)
    u.csrs(klnamedlocker=32)
    return ctx

def restore_context(u, ctx, managed_first=False):
    """<<KLE-restore-order>>: the other lockers, the KLIOBUF, then the named locker, without the KLIOBUF (Rule SR6);
    managed_first restores the named locker before the other lockers, a negative control."""
    mc = ctx['klnamedlocker']
    named = [mc] if mc in ctx['images'] else []
    first, last = (named + [k for k in ctx['images'] if k != mc], []) if managed_first else \
                  ([k for k in ctx['images'] if k != mc], named)
    for k in first:
        import_(u.csrs(klnamedlocker=32), k, ctx['images'][k])
    u.csrs(klnamedlocker=32, kliobuflen=ctx['kliobuflen'])
    if ctx['kliobuflen']:
        u.csrs(klstart=0).input_(Memory(ctx['kliobuf']), BASE, ctx['kliobuflen'])
    u.csrs(kliobuftop=ctx['kliobuftop'])
    for k in last:
        import_(u.csrs(klnamedlocker=32), k, ctx['images'][k])
    u.csrs(klnamedlocker=mc, klstart=ctx['klstart'])

def t_save_restore():
    section('Reset, context save and restore  <<KLE-out-of-reset-unpriv>>, <<KLE-state-save-and-restore-order>>')
    u = rc(unit=fresh(siv=4)).csrs(kliobuflen=16)
    u.reset()
    eq('out of reset: Unconfigured, KLIOBUF off, klstart 0, klnamedlocker 32, registers 0; 33+ ignored',
       [[u.getst(k) for k in range(32)], u.kliobuflen, u.kliobuftop, u.klstart, u.klnamedlocker,
        (u.siv, u.impqual, u.siv2)] + [u.csrs(klnamedlocker=v).klnamedlocker for v in (33, 4, 1 << 40)],
       [[0] * 32, 0, 0, 0, 32, (0, 0, 0), 32, 4, 4])
    u = fresh()
    src, ml, mem = build_context(u)
    r, before = [u.getst(2), u.klnamedlocker, u.klstart, u.getst(5)], snapshot(u)
    ctx = save_context(u)
    eq('context: K2 importing and managed; the save leaves 58/56; managed image first, Error State 16 bytes',
       r + [u.getst(2), u.getst(5), u.getst(0), list(ctx['images'])[0], len(ctx['images'][1]), sorted(ctx['images'])],
       [IMP, 2, 64, PROV, IMP, PROV, ToyCipher.ENCRYPT, 2, 16, [0, 1, 2, 5, 7]])
    u.clearall()
    provision(u, 2, xof())
    u.csrs(kliobuflen=16, klnamedlocker=3, klstart=8).siv = 99
    u.clearall()
    restore_context(u, ctx)
    r = [snapshot(u) == before, u.load(mem, BASE), u.mgmt(2, END, ml),
         (u.getmd(2), u.lockers[2].c1, u.lockers[2].c2) == (src.getmd(0), src.lockers[0].c1, src.lockers[0].c2),
         u.csrs(klstart=16, klnamedlocker=5).mv_in(0x2222), u.mgmt(5, END), u.getst(5), u.lockers[5].c1]
    eq('the restore is exact; the import authenticates; the abandoned provisioning resumes', r,
       [True, 'done', 'completed', True, 'moved', 'completed', READY, v2b(0x1111, 16) + v2b(0x2222, 16)])
    u, w = pv(fresh(), 0, cipher()), fresh().csrs(klnamedlocker=0)
    u.mgmt(0, EXP)
    eq('ml passed in GPRs (Form C); klnamedlocker need not name a named locker (Unconfigured: no image)',
       (u.mgmt(0, END, cipher(State=READY)), u.getst(0), w.getmd(0)['State'], save_context(w)['images']),
       ('completed', READY, 0, {}))
    u, out = pv(fresh(), 3, cipher(SCProtection=1)), Memory()
    base = u.getmd(3)
    u.mgmt(3, EXP)
    u.store(out, BASE, halt_after=32)
    before, ctx = snapshot(u), save_context(u)
    u.clearall()
    restore_context(u, ctx)
    r = [snapshot(u) == before, u.store(out, BASE), u.mgmt(3, END, base), u.getst(3)]
    eq('an interrupted export survives save and restore, completes, and its SCC imports',
       r + [import_(fresh(), 0, mdh_bytes(base) + out.read(BASE, u.size(k=3) - 16))],
       [True, 'done', 'completed', READY, READY])

def t_encodings():
    section('Encodings and locker addressing  <<KLE-instructions-detailed>>, <<KLE-cryptographic-registers>>')
    d = lambda hi5, **kw: decoded(enc_r(2, hi5, **kw))
    names = ('kl.clone', 'kl.rename', 'kl.swap', 'kl.derive')
    eq('funct2 2: T selects clone, rename, swap, derive; R = 01 names KLNL as the destination, R = 10 as the source, '
       'with X0 in that field (GR4); R = 11, or R with another register, reserved; clone rs2 or bit 29 reserved',
       ([d(T << 2, rs1=3, rd=4)[0] for T in range(4)], [d(T << 2 | 1, rs1=6) for T in range(4)],
        [d(T << 2 | 2, rd=7) for T in range(4)], [d(T << 2 | 3) for T in range(4)],
        [d(T << 2 | R, rs1=6, rd=7) for T in range(4) for R in (1, 2)],
        d(12, rs2=9, rs1=6, rd=7), d(0, rs2=1, rs1=6, rd=7), d(16, rs1=6, rd=7), d(13), d(14)),
       (list(names), [(n, 'KLNL', 'K6') + (('X0',) if n == 'kl.derive' else ()) for n in names],
        [(n, 'K7', 'KLNL') + (('X0',) if n == 'kl.derive' else ()) for n in names], ['illegal/1'] * 4,
        ['illegal/1'] * 8, ('kl.derive', 'K7', 'K6', 'X9'), 'illegal/1', 'illegal/1',
        ('kl.derive', 'KLNL', 'K0', 'X0'), ('kl.derive', 'K0', 'KLNL', 'X0')))
    words = {'kl.exec': enc_r(0, 2, rs2=2, rs1=6, rd=3),
             'kl.size': enc_r(0, 6, rs1=6, rd=3), 'kl.restrictl': enc_r(1, 2, rs1=4, rd=6),
             'kl.getmdl': enc_r(3, 2, rs1=6, rd=3), 'kl.setst': enc_setst(2, F=1, r=1, rs1=4, rd=6),
             'kl.mgmt': enc_setst(PROV, r=1, rs1=4, rd=6)}
    eq('r = 1 with a register other than X0 is reserved (GR4); kl.load/kl.input and kl.store/kl.output share one '
       'encoding each with Xl (GR5); funct3 = 6 is not KLE',
       ({n: decoded(w) for n, w in words.items()},
        [decoded(enc_ls(st, 6)) for st in (False, True)], [decoded(enc_ls(st, f3=6)) for st in (False, True)]),
       ({n: 'illegal/1' for n in words}, [('kl.load', 'X6'), ('kl.store', 'X6')], [None, None]))
    eq('GR4: KLNL (r = 1, X0) on every instruction that names a locker: kl.clear, kl.setst (any #immed7, kl.clearads '
       'included), kl.setste, kl.mgmt, kl.exec, kl.getmd*, kl.size/kl.avail Form A, kl.restrict*; kl.clearall is #immed7 65 with '
       'Kd = 0, r = 0, its other forms reserved',
       [decoded(enc_setst(0, r=1)), decoded(enc_setst(2, r=1, G=1)), decoded(enc_setst(PROV, r=1, rs1=4)),
        decoded(enc_r(3, 2, rs1=0, rd=3)), decoded(enc_r(0, 6, rs1=0, rd=3)), decoded(enc_setst(CLEARALL)),
        decoded(enc_setst(CLEARALL, rd=3)), decoded(enc_setst(CLEARALL, r=1)), decoded(enc_setst(CLEARALL, F=1, rs1=2)),
        decoded(enc_r(0, 2, rs1=0)), decoded(enc_r(1, 2, rs1=4)), d(3, rs1=0, rd=7),
        decoded(enc_setst(1, r=1)), decoded(enc_setst(CLEAR_ADS, r=1))],
       [('kl.clear', 'A', 'KLNL', 0), ('kl.setste', 'A', 'KLNL', INVALID), ('kl.mgmt', 'C', 'KLNL', PROV),
        ('kl.getmdl', 'KLNL'),
        ('kl.size', 'A', 'KLNL'), ('kl.clearall',)] + ['illegal/1'] * 3 + [('kl.exec', 'A', 'KLNL')]
       + [('kl.restrictl', 'KLNL'), 'illegal/1', ('kl.setst', 'A', 'KLNL', 1), ('kl.clearads', 'A', 'KLNL', CLEAR_ADS)])
    def outcome(u, op, k, *a):
        return attempt(op(u), k, *a), u.getmd(5), u.klnamedlocker, bytes(u.kliobuf)
    steps = ((lambda u: u.setst, ToyCipher.DECRYPT, 1), (lambda u: u.exec_, 'D'), (lambda u: u.setst, CLEAR_ADS),
             (lambda u: u.setst, INVALID))
    v, t = rc(5).csrs(klnamedlocker=5, kliobuflen=32), rc(5).csrs(klnamedlocker=5, kliobuflen=32)
    for u in (v, t):
        u.kliobuf[:32] = bytes(range(32))
    eq('GR4: kl.setst (usage immediates and kl.clearads included) and kl.exec (Form D, KLIOBUF) name KLNL: each '
       'acts on the named locker exactly as when naming it, klnamedlocker unchanged',
       [outcome(v, op, 'KLNL', *a) for op, *a in steps], [outcome(t, op, 5, *a) for op, *a in steps])
    u = opened(k=5)
    r = [u.getst('KLNL'), u.size(k='KLNL') == u.size(k=5), u.mgmt('KLNL', END), u.getst(5), u.klnamedlocker,
         u.getst('KLNL')]
    v = rc(7, rc(5, UsagePolicy=0b01110)).csrs(klnamedlocker=5)
    r += [v.getmd(7) == v.getmd(5), v.setst(7, 0), v.getst(7), v.getst(5)]
    w = fresh()
    r += [w.getmd('KLNL') == md(), w.size(k='KLNL'), w.avail(k='KLNL'), w.setst('KLNL', 0),
          w.setst('KLNL', ToyCipher.ENCRYPT, 1), w.exec_('KLNL', 'D'), w.mgmt('KLNL', END),
          w.mgmt('KLNL', EXP), w.mgmt('KLNL', PROV, cipher()), w.klnamedlocker]
    u = fresh().csrs(klstart=16)
    r2 = [u.mgmt('KLNL', op, cipher()) for op in (PROV, IMP, EXP)] + [u.klstart, u.klnamedlocker]
    for op, m in ((PROV, cipher()), (IMP, cipher(State=2)), (EXP, None)):
        u = rc(5).csrs(klnamedlocker=5)
        r2 += [u.mgmt('KLNL', op, m), u.getst(5), u.klnamedlocker]
    v, x, y = rc(6).csrs(klnamedlocker=NONE), rc(4), fresh().csrs(klnamedlocker=3)
    x.setst(4, INVALID)
    r2 += [v.mgmt(6, PROV, cipher()), x.csrs(klnamedlocker=4).mgmt('KLNL', PROV, cipher()),
           y.mgmt('KLNL', EXP), y.klnamedlocker, listing_provision(start=cipher(SCProtection=1))]
    eq('GR33: a KLNL opening (provisioning, import, export) with klnamedlocker = 32 is a no-op: common steps only '
       '(klstart 0), klnamedlocker stays 32; '
       'otherwise it opens the locker, a Valid one included, and klnamedlocker is not changed; an explicit '
       'opening, or a KLNL opening of an Error-State locker, is not affected; a KLNL export opening on an '
       'Unconfigured locker is a no-op that sets 32; the provisioning listing reprovisions a Valid locker', r2,
       ['noop'] * 3 + [0, NONE, 'opened', PROV, 5, 'opened', IMP, 5, 'opened', EXP, 5, 'opened', 'opened', 'noop',
                            NONE, (READY, 0)])
    eq('GR4, GR33: KLNL is the named locker (State, size, completion); after completion KLNL still names it; '
       'an explicit '
       'locker is never redirected; KLNL at 32 reads as Unconfigured: kl.setst, kl.exec and end are no-ops, an '
       'export or a provisioning opening too', r,
       [PROV, True, 'completed', READY, 5, READY, False, 'cleared', 0, ToyCipher.ENCRYPT,
        True, 0, 0, 'noop', 'noop', 'noop', 'noop', 'noop', 'noop', NONE])
    src = pv(fresh(), 0, cipher(SCProtection=1))
    img = bytearray(export(src, 0))
    img[70] ^= 1                                                    # a tampered Content1 byte (offset 48 + 22)
    a = fresh().csrs(klnamedlocker=2)
    r = [a.mgmt('KLNL', IMP, unpack(b2v(bytes(img[:16])))), a.load(Memory(bytes(img[16:])), BASE),
         a.mgmt('KLNL', END, unpack(b2v(bytes(img[:16])))), a.getst('KLNL'), a.klnamedlocker,
         a.load(Memory(), BASE), a.mv_out()]
    b = pv(fresh(), 3, cipher()).csrs(klnamedlocker=3)            # completed, not cleaned up
    r += [trap_of(b.load, Memory(), BASE), trap_of(b.mv_out), trap_of(b.store, Memory(), BASE),
          b.mgmt(4, PROV, cipher()), b.getst(4), b.klnamedlocker]
    eq('kept klnamedlocker: an import failing authentication reads Authentication Failed through KLNL (no restart '
       'loop), transfers on it are no-ops; on a completed locker transfers trap; an opening on another locker is '
       'not checked against klnamedlocker and names its target', r,
       ['opened', 'done', 'completed', AUTH, 2, 'noop', 0, 'illegal/2', 'illegal/2', 'illegal/2', 'opened', PROV, 4])
    two = lambda w: (lambda d: d if isinstance(d, str) else d[:2])(decoded(w))
    eq('the unused register field of kl.exec Forms B and C must be zero, other values reserved',
       [two(enc_r(0, f << 3, rs2=s, rs1=6, rd=r)) for f, r, s in ((1, 0, 5), (1, 1, 5), (1, 2, 5), (2, 5, 0),
                                                                   (2, 5, 1), (2, 5, 2))],
       [('kl.exec', 'B'), 'illegal/1', 'illegal/1', ('kl.exec', 'C'), 'illegal/1', 'illegal/1'])
    eq('kl.mvin / kl.mvout: Form D with rd 1-3 (rs1 = 0) or 5-7 (rs2 = 0); rd 4, a stray register field or r = 1 '
       'reserved',
       [decoded(enc_r(0, 24, rs2=9, rd=1)), decoded(enc_r(0, 24, rs2=9, rd=2)), decoded(enc_r(0, 24, rd=3)),
        decoded(enc_r(0, 24, rs1=9, rd=5)), decoded(enc_r(0, 24, rs1=9, rd=6)), decoded(enc_r(0, 24, rd=7)),
        decoded(enc_r(0, 24, rs1=6)), decoded(enc_r(0, 24, rd=4)), decoded(enc_r(0, 24, rs1=1, rd=1)),
        decoded(enc_r(0, 24, rs2=1, rd=3)), decoded(enc_r(0, 24, rs2=1, rd=5)),
        decoded(enc_r(0, 26, rs2=9, rd=1))],
       [('kl.mvin', 'I', 'X9'), ('kl.mvin', 'II', 'V9'), ('kl.mvin', 'III', 'KLIOBUF'), ('kl.mvout', 'IV', 'X9'),
        ('kl.mvout', 'V', 'V9'), ('kl.mvout', 'VI', 'KLIOBUF'), ('kl.exec', 'D', 'K6')] + ['illegal/1'] * 5)
    names = [decoded(enc_setst(i, rs1=4, rd=6)) for i in range(128)]
    eq('#immed7: 0111xxx kl.mgmt (59-62 reserved; F = 0b10 reserved, GR1); 48-55 kl.setst (GR25); 0, 64; '
       '65 only as kl.clearall; '
       '66-127',
       ([i for i in range(128) if names[i][0] == 'kl.mgmt'], [i for i in range(128) if names[i] == 'illegal/1'],
        decoded(enc_setst(56, F=2, rs1=4, rd=6)), names[0][0], names[64][0], {names[i][0] for i in range(66, 128)}),
       ([56, 57, 58, 63], [59, 60, 61, 62, 65], 'illegal/1', 'kl.clear', 'kl.clearads', {'kl.setst'}))
    eq('G selects kl.setst (0b00), kl.setste (0b01), kl.setnl/kl.setnli (0b10) and kl.mgmt (0b11); #immed7 56-63 with '
       'G = 0b00, any other #immed7 with G = 0b11, and kl.setnl/kl.setnli with Kd, r or F other than 0b00/0b01 are reserved',
       [decoded(enc_setst(56, rs1=4, rd=6, G=0)), decoded(enc_setst(1, rs1=4, rd=6, G=3)),
        decoded(enc_setst(5, G=2)), decoded(enc_setst(0, F=1, rs1=9, G=2)), decoded(enc_setst(0, F=1, rs1=9, rd=1, G=2)),
        decoded(enc_setst(0, r=1, G=2)), decoded(enc_setst(1, F=1, rs1=9, G=2)), decoded(enc_setst(0, F=2, rs1=9, G=2)),
        decoded(enc_setst(CLEARALL, G=1)), decoded(enc_setst(CLEARALL, G=3))],
       ['illegal/1', 'illegal/1', ('kl.setnli', 5), ('kl.setnl', 'X9')] + ['illegal/1'] * 6)
    eq('kl.setst and kl.mgmt: F = 0b00 is Form A with rs1 = X0 and Form C otherwise, F = 0b01 Form B, '
       'F = 0b10 and 0b11 reserved (GR1)',
       [two(enc_setst(i, F=f, rs1=s, rd=6)) for i in (ToyCipher.ENCRYPT, PROV)
        for f, s in ((0, 0), (0, 4), (1, 4), (2, 0), (2, 4), (3, 0), (3, 4))],
       [x for n in ('kl.setst', 'kl.mgmt') for x in [(n, 'A'), (n, 'C'), (n, 'B')] + ['illegal/1'] * 4])

def t_klnl_pairs():
    section('KLNL in kl.clone, kl.rename, kl.swap and kl.derive  (GR4, GR33)')
    def twin(op, a, b):                     # the same operation, naming KLNL (klnamedlocker = 5) or locker 5
        u, v = rc(5, rc(2)).csrs(klnamedlocker=5), rc(5, rc(2)).csrs(klnamedlocker=5)
        r1, r2 = attempt(op(u), *a), attempt(op(v), *b)
        return (r1, [u.getmd(i) for i in (2, 3, 5)], u.klnamedlocker) == (r2, [v.getmd(i) for i in (2, 3, 5)], v.klnamedlocker)
    eq('KLNL as the source or the destination acts as naming the locker it names, klnamedlocker following the CC; '
       'kl.restricth on KLNL narrows the locker it names (GR4: every instruction that names a locker)',
       [twin(lambda u: u.clone, (3, 'KLNL'), (3, 5)), twin(lambda u: u.clone, ('KLNL', 2), (5, 2)),
        twin(lambda u: u.rename, (3, 'KLNL'), (3, 5)), twin(lambda u: u.rename, ('KLNL', 2), (5, 2)),
        twin(lambda u: u.swap, (3, 'KLNL'), (3, 5)), twin(lambda u: u.swap, ('KLNL', 2), (5, 2)),
        twin(lambda u: u.restrict, ('KLNL', rq(UsagePolicy=0b11101), 'h'), (5, rq(UsagePolicy=0b11101), 'h'))], [True] * 7)
    w = rc(5, rc(3))
    r = [w.clone(3, 'KLNL'), w.rename('KLNL', 3), w.swap(3, 'KLNL'), w.derive('KLNL', 3, 16),
         w.restrict('KLNL', rq(UsagePolicy=0b11101), 'h'), w.getst(3)]
    w.csrs(klnamedlocker=3)
    r += [w.clone(3, 'KLNL'), w.swap('KLNL', 3), trap_of(w.derive, 3, 'KLNL', 16), trap_of(w.clone, 'KLNL', 'KLNL'),
          trap_of(w.derive, 'KLNL', 0, 16) is None]
    eq('KLNL at 32: clone, rename, swap, derive and restrict perform no operation, the other locker untouched; KLNL naming '
       'the other locker: clone and swap no-ops, derive illegal/2; KLNL for both (R = 11) illegal/1; KLNL and K0, '
       'whose encoded fields are both 0, are no self-derivation', r,
       ['noop', 'noop', 'noop', 'noop', 'noop', ToyCipher.ENCRYPT, 'noop', 'noop', 'illegal/2', 'illegal/1', True])

def t_rename_swap():
    section('kl.rename and kl.swap  <<KLE-instruction-clone>>')
    cap = MACHINES[M_CIPHER].clf_capacity(cipher(SCProtection=1))
    u = rc(SCProtection=1)
    cl = lambda k: (u.getmd(k), u.lockers[k].c1, u.lockers[k].c2, u.lockers[k].alloc)
    img0 = cl(0)
    r = [u.rename(5, 0), cl(5) == img0, u.getst(0), u.lockers[0].alloc]
    free = rc(6, u, SCProtection=1).clf_free()
    r += [u.rename(6, 5), u.getmd(6) == img0[0], u.clf_free() - free]
    b0 = snapshot(u)
    r += [u.rename(6, 6), u.swap(6, 6), snapshot(u) == b0]
    a, b = pv(u, 1, sig(AuxInfo=2)).getmd(1), u.getmd(6)
    r += [u.swap(1, 6), (u.getmd(1), u.getmd(6)) == (b, a), u.lockers[1].alloc, u.clone(1, 9), u.rename(1, 9),
          u.getst(1)]
    t = rc(0, rc(1, fresh(clf_total=2 * cap), SCProtection=1), SCProtection=1)
    eq('rename moves, frees the destination; Ks = Kd no-op; swap exchanges; no capacity checks; '
       'an Unconfigured source (K9): clone and rename both clear Kd',
       r + [t.clf_free(), t.swap(0, 1), t.rename(2, 0), trap_of(t.clone, 3, 1)],
       ['renamed', True, 0, 0, 'renamed', True, cap, 'noop', 'noop', True, 'swapped', True, cap, 'cleared',
        'renamed', 0,
        0, 'swapped', 'renamed', 'out_of_memory'])
    e = rc()
    e.setst(0, EXPIRED)
    eq('GR33: a locker in an Error State becomes _Unconfigured_ as the destination of kl.rename from an '
       'Unconfigured source (acts as kl.clear Kd)', [e.getst(0), e.rename(0, 9), e.getst(0), e.getst(9)],
       [EXPIRED, 'renamed', 0, 0])
    u = fresh()
    src, ml, mem, _ = interrupted_import(u, 2, 48)
    regs, w = (u.siv, u.impqual, u.siv2), rc(4)
    w.mgmt(3, PROV, cipher())
    r = [u.rename(7, 2), u.getst(7), u.getst(2), u.klnamedlocker, u.klstart, (u.siv, u.impqual, u.siv2) == regs,
         u.csrs(klnamedlocker=2).load(mem, BASE), u.csrs(klnamedlocker=7).load(mem, BASE), u.mgmt(7, END, ml),
         u.getmd(7) == src.getmd(0),
         u.lockers[7].c1 == src.lockers[0].c1, w.swap(3, 4), w.klnamedlocker, w.getst(3), w.getst(4), w.swap(0, 1),
         w.klnamedlocker, w.rename(4, 3), w.klnamedlocker, w.getst(4), w.mgmt(8, PROV, cipher()),
         trap_of(w.clone, 9, 8), w.swap(9, 8), w.rename(8, 9), w.getst(8), w.klnamedlocker]
    eq('klnamedlocker follows rename and swap, 32 when overwritten (GR27); Configuration CC moves (GR30); '
       'kl.load with klnamedlocker naming the vacated index is a no-op (GR33)', r,
       ['renamed', IMP, 0, 7, 48, True, 'noop', 'done', 'completed', True, True, 'swapped', 4, ToyCipher.ENCRYPT,
        PROV, 'swapped', 4, 'renamed', 32, ToyCipher.ENCRYPT, 'opened', 'privilege_violation', 'swapped', 'renamed',
        PROV, 8])
    u, w = rc(UsagePolicy=0b01110, ExpirationDate=10).csrs(klstart=32), rc()
    u.mode, u.clock, u.siv = 'U', 99, 11
    w.setst(0, EXPIRED)
    m = w.getmd(0)
    r = [u.rename(1, 0), u.swap(2, 1), u.getst(2), u.getmd(2)['UsagePolicy'], u.klstart, u.siv,
         trap_of(u.csrs(klstart=0).exec_, 2, 'A', vin=bytearray(16), vout=bytearray(16)), w.rename(3, 0),
         w.getmd(3) == m,
         w.lockers[3].alloc, w.swap(4, 3), w.getmd(4) == m]
    for final in (SUCCESS, FAILURE):
        f = final_cipher(final)
        r += [f.rename(1, 0), f.swap(2, 1), f.getst(2)]
    eq('not usage instructions, no evaluation point, uninterruptible (GR47); Error, Success, Failure CCs move', r,
       ['renamed', 'swapped', ToyCipher.ENCRYPT, 0b01110, 32, 11, 'privilege_violation', 'renamed', True, 0, 'swapped', True,
        'renamed', 'swapped', SUCCESS, 'renamed', 'swapped', FAILURE])

def t_controls():
    section('Negative controls')
    cur, req = 0b00001, 0b11110
    u, probe, gained = pv(fresh(), 0, cipher(UsagePolicy=cur)), fresh(), []
    u.restrict(0, rq(UsagePolicy=req), 'h')
    for probe.mode in ('U', 'VS', 'HS', 'M'):
        if probe.usage_allowed(cipher(UsagePolicy=req)) and not probe.usage_allowed(cipher(UsagePolicy=cur)):
            gained.append(probe.mode)
    eq('the spec rule adds the requested denial and keeps the existing ones', u.getmd(0)['UsagePolicy'], 0)
    control('replace-if-non-zero UsagePolicy widens the allowed modes', gained == ['VS', 'HS', 'M'])
    src = pv(fresh(), 0, sig())
    img = export(src, 0)
    ml, mem, v, w = unpack(b2v(img[:16])), Memory(img[16:]), opened(IMP, unpack(b2v(img[:16])), k=1), fresh()
    v.load(mem, BASE, halt_after=32)
    k = v.klstart
    v.csrs(klstart=48).load(mem, BASE)
    v.mgmt(1, END, ml)
    eq('an import halted at 32 and resumed correctly round trips',
       (k, import_(w, 1, img, halt_after=32), w.load(mem, BASE), w.mgmt(1, END, ml), w.lockers[1].c1),
       (32, 'halted', 'done', 'completed', src.lockers[0].c1))
    control('an import resumed at a later klstart fails authentication', (v.getst(1), v.lockers[1].c1) == (AUTH, b''))
    u = pv(fresh(), 0, cipher(SCProtection=1))
    scc = export(u, 0)
    AD, c1, siv = u.sealing_ad(dict(u.getmd(0), ADSDropped=1)), to_blocks(scc[64:96]), b2v(scc[16:32])
    eq('with bit 47 cleared in AD_auth a toggled ADSDropped still authenticates',
       scc_decrypt(AD, 0, 0, siv, c1, DEFAULT_CSK)[0], True)
    control('authentication over an uncleared bit 47 rejects a toggled ADSDropped',
            not scc_decrypt(AD, 0, 0, siv, c1, DEFAULT_CSK, clear47=False)[0])
    m = md(State=EXP, StateExtension=0xF, KeyType=1)
    eq('the MDH layout satisfies the kl.getst and kl.getstx expansions', (pack(m) >> 18 & 0x3F, pack(m) >> 24 & 0xF),
       (EXP, 0xF))
    control('a layout with State at [26:21] fails the kl.getst expansion',
            (m['State'] << 21 | m['StateExtension'] << 27 | m['KeyType'] << 18) >> 18 & 0x3F != EXP)
    u = fresh()
    src, ml, mem = build_context(u)
    ctx = save_context(u)
    u.clearall()
    restore_context(u, ctx, managed_first=True)
    u.load(mem, BASE)
    u.mgmt(2, END, ml)
    control('restoring the named locker first loses its SIV (Authentication Failed)', u.getst(2) == AUTH)
    runs = {}
    for faithful in (True, False):
        u = fresh()
        src, ml, mem = build_context(u)
        if faithful:
            u.rename(9, 2)
        else:
            u.lockers[9], u.lockers[2] = u.lockers[2], Locker()
        runs[faithful] = attempt(u.load, mem, BASE)
    eq('after kl.rename the interrupted import resumes on the new index', runs[True], 'done')
    control('a rename leaving klnamedlocker behind strands the import: kl.load is a no-op on the vacated index '
            '(GR5, GR33)', runs[False] == 'noop')
    eq('a handler clear at any one boundary of the provisioning listing: Ready after at most one restart (GR33)',
       [listing_provision(lambda s, at=at: s == at) for at in range(6)], [(READY, 0)] + [(READY, 1)] * 5)
    eq('GR33: a clear between select_locker and the KLNL opening: the opening is a no-op and the check reads 0; the '
       'listing restarts and provisions locker p, or returns an error when p = 32',
       [listing_provision(race=True), listing_provision(race=True, p=32)], [(READY, 1), ('no_locker', 1)])
    eq('a handler Error State at any boundary after the opening: the next instruction is a no-op, the listing '
       'reaches handle_errors with it (GR33)', ([listing_provision(error_at=at) for at in range(1, 6)],
                                                  [listing_export(error_at=at)[0] for at in range(3, 8)]),
       ([(OOM, 0)] * 5, ['error'] * 5))
    control('a handler that clears at every context switch livelocks a single-stepped provisioning '
            '<<KLE-CC-management>>', listing_provision(lambda s: True) == ('livelock', 8))
    st, img = listing_export()
    eq('the export listing: a clear at any of its 8 boundaries is reported, else the image imports (GR33)',
       ([listing_export(lambda s, at=at: s == at) for at in range(8)], st, import_(fresh(), 3, img)),
       ([('lost', None)] * 8, READY, READY))
    kinds = [(kd, v, ev) for kd in ('prov', 'imp', 'exp') for v in ('load', 'mv') for ev in ('clear', 'error')]
    runs = {(kd, v, ev, c): [listing_checked(kd, c, at, ev, v) for at in range(24)]
            for kd, v, ev in kinds for c in ('each', 'last', 'before-last')}
    eq('a routine that reads the State only after its last kl.mgmt has the outcomes of one that reads it after every '
       'step: a clear or an Error State at any boundary is restarted or reported, never silent (GR33)',
       ([runs[x + ('last',)] for x in kinds],
        set().union(*runs.values()) - {'silent'} <= {'ok', 'restarted', 'reported'}),
       ([runs[x + ('each',)] for x in kinds], True))
    control('a provisioning or import that reads the State only before its last kl.mgmt misses a clear or an Error '
            'State just before it, and finishes without a Ready locker',
            all('silent' in runs[kd, v, ev, 'before-last'] for kd, v, ev in kinds if kd != 'exp'))
    u, mem = pv(fresh(), 0, cipher()), Memory()
    m, n = u.getmd(0), u.size(k=0)
    u.mgmt(0, EXP)
    u.clear(0)
    r = [u.store(mem, BASE), u.mgmt(0, END, m), u.getst(0)]
    control('an export cleared before kl.store and not checked: nothing is stored, and the image fails authentication '
            'at import', r == ['empty', 'noop', UNCONF]
            and import_(fresh(), 3, mdh_bytes(m) + mem.read(BASE, n - 16)) == AUTH)
    absent = md(Machine=M_ABSENT, MachinePolicy=1)
    eq('a handler past a trapping opening kl.mgmt sets the Error State: the listing reaches handle_errors',
       listing_provision(m=absent, on_trap=lambda u, tag: u.mgmt(u.klnamedlocker, IMP,
                                                                 dict(absent, State=EXC_STATE[tag]))),
       (UNSUP, 0))
    control('a handler past a trapping opening kl.mgmt that leaves the locker Unconfigured livelocks the listing',
            listing_provision(m=absent, on_trap=lambda u, tag: None) == ('livelock', 8))

if __name__ == '__main__':
    for t in (t_mdh, t_states, t_validity, t_lengths, t_usage, t_restrict, t_localities, t_mgmt, t_nested,
              t_error_states, t_ads, t_transfers, t_kliobuf, t_sgr, t_exec, t_expiration, t_derive, t_errors,
              t_save_restore, t_encodings, t_klnl_pairs, t_rename_swap, t_controls):
        t()
    done()
