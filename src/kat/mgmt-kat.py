#!/usr/bin/env python3
"""KAT of the Machine-independent KLEE rules: the Instructions chapter (Zkl-ISA-unpriv.adoc) and the
exception causes and *llockerstatus Off gate of Zkl-ISA-priv.adoc, on toy Machines.
SCC sealing follows <<KLEE-SCC-AEAD>> with a SHA-256 stand-in for AESE256 (scc-kat.py covers the real one)."""

import functools
import hashlib
import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import (b2v, v2b, sl, cat, bin_, montmul, bxor, MASK128, MDH_FIELDS, MDH_FIELD,  # noqa: E402
                    mdh_pack, mdh_unpack, ERROR_STATES, section, check, control, info, spec_note, done,
                    KL_STATE_UNCONFIGURED as UNCONF, KL_STATE_READY as READY,
                    KL_STATE_SUCCESS as SUCCESS, KL_STATE_FAILURE as FAILURE,
                    KL_STATE_UNSUPPORTED as UNSUP, KL_STATE_INVALID as INVALID,
                    KL_STATE_OUT_OF_MEMORY as OOM, KL_STATE_MGMT_AUTH as AUTH,
                    KL_STATE_PRIV_VIOLATION as PRIV, KL_STATE_EXPIRED as EXPIRED,
                    KL_CFG_PROVISIONING as PROV, KL_CFG_EXPORTING as EXP, KL_CFG_IMPORTING as IMP,
                    KL_CFG_PPI_EXPORTING as PPI_EXP, KL_CFG_PPI_IMPORTING as PPI_IMP,
                    KL_CFG_MANAGEMENT_END as END)

MASK64 = (1 << 64) - 1
ONES64 = MASK64
CLEAR_ADS = 64
NONE = 32                                    # klmanagedlocker: no locker managed
VALID, COMPLETE, PARTIAL, CONFIG = range(1, 48), range(1, 56), range(56, 64), range(56, 61)
BASE_TYPE = {PROV: 'pi', EXP: 'scc', IMP: 'scc', PPI_EXP: 'pi', PPI_IMP: 'pi'}
EXC_STATE = {'unsupported': UNSUP, 'out_of_memory': OOM, 'privilege_violation': PRIV}
RES_MASK = sum(((1 << hi - lo + 1) - 1) << lo for n, hi, lo in MDH_FIELDS if n is None)

def eq(name, got, want):
    return check(name, got == want, got, want)

# ---------------------------------------------------------------- MDH dicts (key 'res': reserved bits)

def md(**kw):
    m = dict.fromkeys(MDH_FIELD, 0)
    m['res'] = 0
    assert set(kw) <= set(m), kw
    m.update(kw)
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

class Ind:
    """Indirect locker operand K(Xreg) holding `value`."""
    def __init__(self, value, reg=5):
        self.value, self.reg = value, reg

def trap_of(fn, *a, tval=False, **kw):
    try:
        fn(*a, **kw)
    except Trap as t:
        return (t.tag, t.tval) if tval else t.tag

def decode(w, zklind=False):
    """<<KLEE-instructions-detailed>>: (mnemonic, ...), None outside KLEE, Trap illegal/1 if reserved."""
    b = functools.partial(sl, w)
    op, f3, rd, rs1, rs2 = b(6, 0), b(14, 12), b(11, 7), b(19, 15), b(24, 20)
    def lk(ind, reg, always=False):
        if ind and (not (zklind or always) or reg == 0):          # GR11
            raise Trap('illegal', 1)
        return f'K(X{reg})' if ind else f'K{reg}'
    if op == 0x0F and f3 == 4:
        f2 = b(31, 30)
        if f2 == 0 and not b(27, 27):
            if b(25, 25): raise Trap('illegal', 1)
            form, k = b(29, 28), lk(b(26, 26), rs1)
            if form == 0: return ('kl.exec', 'A', k)
            if form == 1 and rd < 3: return ('kl.exec', 'B', k) if rd == 0 else ('kl.mv', ('I', 'II')[rd - 1], k)
            if form == 2 and rs2 < 3: return ('kl.exec', 'C', k) if rs2 == 0 else ('kl.mv', ('III', 'IV')[rs2 - 1], k)
            if form == 3 and rd == rs2 == 0: return ('kl.exec', 'D', k)
            raise Trap('illegal', 1)
        if f2 == 0:                                                 # kl.size, kl.avail
            F, r = b(29, 28), b(26, 26)
            if rs2 or (F, r) not in ((0, 0), (0, 1), (1, 0), (2, 0)): raise Trap('illegal', 1)
            return ('kl.avail' if b(25, 25) else 'kl.size', 'ABC'[F],
                    lk(r, rs1) if F == 0 else f"{'XV'[F - 1]}{rs1}")
        if f2 in (1, 3):                                            # kl.restrict*, kl.getmd*
            h, v = b(28, 28), b(29, 29)
            if b(25, 25) or b(27, 27) or rs2 or (h and v): raise Trap('illegal', 1)
            if f2 == 1: return ('kl.restrict' + 'lhv'[h + 2 * v], lk(b(26, 26), rd))
            return (('kl.getmdl', 'kl.getmd', 'kl.getmdv')[h + 2 * v], lk(b(26, 26), rs1))
        if b(29, 29): raise Trap('illegal', 1)
        T, R = b(28, 27), b(26, 25)
        if T == 3: return ('kl.derive', lk(R & 1, rd), lk(R >> 1, rs1), f'X{rs2}')
        if rs2: raise Trap('illegal', 1)
        return (('kl.clone', 'kl.rename', 'kl.swap')[T], lk(R & 1, rd, True), lk(R >> 1, rs1, True))
    if op == 0x0F and f3 == 3:                                      # kl.setst, kl.mgmt
        r, F, imm = b(20, 20), b(22, 21), b(31, 25)
        if b(24, 23) or (F == 0 and rs1): raise Trap('illegal', 1)
        if r and rd == 0:
            if F == 0 and imm == 0: return ('kl.clearall',)
            raise Trap('illegal', 1)
        k = lk(r, rd)
        if imm >> 3 == 0b0111:
            if 59 <= imm <= 62 or F == 1: raise Trap('illegal', 1)
            return ('kl.mgmt', 'ABCD'[F], k, imm)
        if imm in (SUCCESS, FAILURE):                               # SGR7
            raise Trap('illegal', 1)
        return ({0: 'kl.clear', CLEAR_ADS: 'kl.clearads'}.get(imm, 'kl.setst'), 'ABCD'[F], k, imm)
    if op in (0x67, 0x23) and f3 in (6, 7):
        return ('kl.load' if op == 0x67 else 'kl.store', lk(f3 == 7, rd if op == 0x67 else rs2))
    return {(0x03, 7): ('kl.input',), (0x23, 5): ('kl.output',)}.get((op, f3))

def decoded(w, zklind=False):
    try:
        return decode(w, zklind)
    except Trap as t:
        return t.tag

def enc_r(f2, hi5, rs2=0, rs1=0, rd=0):
    return (f2 << 30) | (hi5 << 25) | (rs2 << 20) | (rs1 << 15) | (4 << 12) | (rd << 7) | 0x0F

def enc_setst(imm, F=0, r=0, rs1=0, rd=0):
    return (imm << 25) | (F << 21) | (r << 20) | (rs1 << 15) | (3 << 12) | (rd << 7) | 0x0F

def enc_ls(store, f3, ctx, rs1=2):
    return (ctx << 20 | rs1 << 15 | f3 << 12 | 0x23) if store else (rs1 << 15 | f3 << 12 | ctx << 7 | 0x67)

# ---------------------------------------------------------------- stand-ins and SCC sealing

def prf(*parts):
    h = hashlib.sha256(b'KLEE-KAT toy PRF')
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
def scc_keyderiv(key, nonce):                                       # <<KLEE-SCC-key-derivation>>
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

def scc_encrypt(AD, N, sep, P, K):                                 # <<KLEE-SCC-GCM-SIV-enc>>
    enc, auth = scc_keyderiv(K, N)
    siv = _tag(enc, auth, AD, N, sep, P, True)
    return siv, [p ^ aese256(enc, _ctr(sep, siv, i)) for i, p in enumerate(P)]

def scc_decrypt(AD, N, sep, siv, C, K, clear47=True):               # <<KLEE-SCC-GCM-SIV-dec>>
    enc, auth = scc_keyderiv(K, N)
    P = [c ^ aese256(enc, _ctr(sep, siv, i)) for i, c in enumerate(C)]
    ok = _tag(enc, auth, AD, N, sep, P, clear47) == siv
    return ok, P if ok else [0] * len(C)

# ---------------------------------------------------------------- Localities

LOC_SUB = [('hw1', 1, 0), ('hw2', 3, 2), ('boot', 5, 4), ('mloc', 6, 6), ('hloc', 7, 7), ('sloc', 8, 8)]

def loc(hw1=0, hw2=0, boot=0, mloc=0, hloc=0, sloc=0):
    return hw1 | hw2 << 2 | boot << 4 | mloc << 6 | hloc << 7 | sloc << 8

def loc_entries(v):
    """<<KLEE-locality-indexes>>: the LST indices a _Locality_ names."""
    h1, h2, bt = sl(v, 1, 0), sl(v, 3, 2), sl(v, 5, 4)
    return sorted(([h1 - 1] if h1 else []) + ([2 + h2] if h2 else []) + ([5 + bt] if bt in (1, 2) else [])
                  + [j for bit, j in ((6, 8), (7, 9), (8, 10)) if v >> bit & 1])

def loc_union(a, b):
    """<<KLEE-system-keys>> union; None for two different Boot Session entries."""
    ba, bb = sl(a, 5, 4), sl(b, 5, 4)
    if ba and bb and ba != bb: return None
    return max(sl(a, 1, 0), sl(b, 1, 0)) | max(sl(a, 3, 2), sl(b, 3, 2)) << 2 | (ba or bb) << 4 \
        | (sl(a, 8, 6) | sl(b, 8, 6)) << 6

def narrow_up(cur, req):
    """kl.restricth _UsagePolicy_: bits 0-3 set denials, bit 4 withdraws the Debug grant."""
    return (cur | req & 0b01111) & ~(req & 0b10000)

def narrow_skid(up, kp):
    return ((up | kp) & 0b01111) | (up & kp & 0b10000)

def custom_value(m):                                                # GR9
    return m['Machine'] >= 3072 or m['SCProtection'] in (6, 7) or m['Version'] == 3

# ---------------------------------------------------------------- toy Machines

MAX_ADL, ADS_BLOCKS, SC_ORDER, VERSIONS = 6, 4, (0, 1, 2, 6), (0,)
M_CIPHER, M_XOF, M_SIG, M_KEX, M_CUSTOM, M_ABSENT, M_HASH = 0x011, 0x021, 0x031, 0x041, 0xC05, 0x777, 0x051

def sc_rank(v):
    return SC_ORDER.index(v) if v in SC_ORDER else -1

class Machine:
    kind, policies, sc_levels = 'ops', {1, 2, 3}, {0}       # kind: 'ops' mask, 'sig' mask, 'ext' extends _Machine_
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
    sc_levels, clf_both = {0, 1, 2, 6}, 16
    ENCRYPT, DECRYPT, VERIFY = 2, 3, 4
    op_states, states, stx = {2: 1, 3: 2}, frozenset({2, 3}), frozenset({0, 1})
    def exec_form(self, m):
        return 'A' if m['State'] in (2, 3) else None
    def verify_tag(self, u, cl):
        return b2v(prf(b'verify', u.key_of(cl))[:8])
    def setst(self, u, cl, imm, aux):
        if imm in (2, 3) and cl.mdh['MachinePolicy'] & self.op_states[imm]:
            cl.mdh['State'] = imm
            self.put_state(cl, v2b(aux or 0, 16))
            return True
        if imm == self.VERIFY:                                      # SGR9
            cl.mdh['State'] = SUCCESS if aux == self.verify_tag(u, cl) else FAILURE
            return True
        return False
    def process(self, u, cl, blk):
        st = self.get_state(cl)
        ctr = b2v(st[:8])
        self.put_state(cl, v2b(ctr + 1 & MASK64, 8) + st[8:])
        return bxor(blk, prf(b'keystream', u.key_of(cl), ctr)[:16])

class ToyXof(Machine):
    kind, policies, sc_levels, state_len, clf_base, gran = 'ext', {0, 1}, {0, 1}, 32, 96, 1
    ABSORB, FINAL, states, stx = 2, 3, frozenset({2}), frozenset({0, 1})
    def exec_form(self, m):
        return {READY: 'B', self.ABSORB: 'B', SUCCESS: 'C'}.get(m['State'])
    def setst(self, u, cl, imm, aux):
        if imm == self.ABSORB and cl.mdh['State'] in (READY, self.ABSORB):
            cl.mdh['State'] = self.ABSORB
            self.put_state(cl, self.get_state(cl))
            return True
        if imm == self.FINAL and cl.mdh['State'] == self.ABSORB:
            cl.mdh['State'] = SUCCESS
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
        if cl.mdh['State'] == SUCCESS: return self.squeeze(u, cl)
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
    kind, policies, sc_levels, state_len, clf_base = 'ext', {0}, {0, 1, 2}, 64, 96
    SHARED, states, stx = 2, frozenset({2}), frozenset({0, 1})
    def setst(self, u, cl, imm, aux):
        if imm == self.SHARED and cl.mdh['State'] == READY:
            self.put_state(cl, prf(b'kex', u.key_of(cl), aux or 0) + prf(b'kex2', u.key_of(cl), aux or 0))
            cl.mdh['State'] = self.SHARED
            return True
        return False

class ToyHash(Machine):
    """A keyless Machine: its PI carries no key field (R7: _KeyType_ 1 is invalid Metadata)."""
    kind, policies, sc_levels, key_len, state_len, clf_base = 'ext', {0}, {0}, 0, 32, 64
    states, stx = frozenset({2}), frozenset({0})

MACHINES = {m.ident: m for m in (ToyCipher(M_CIPHER), ToyXof(M_XOF), ToySig(M_SIG), ToyCustom(M_CUSTOM),
                                 ToyKex(M_KEX), ToyHash(M_HASH))}
# toy kl.derive endpoints, shaped as <<KLEE-derive-endpoints>>
SRC_EP = {M_XOF: ({SUCCESS}, True), M_KEX: ({ToyKex.SHARED}, False)}    # (States, kl.exec-obtainable)
DST_EP = {M_CIPHER: ('key', {READY}), M_XOF: ('absorb', {READY, ToyXof.ABSORB}), M_SIG: ('key', {ToySig.SET_SCALAR})}

def content2_size(m):
    return 16 * (m['AuxDataLen'] - 2) if m['AuxDataLen'] >= 2 and not m['ADSDropped'] else 0

# ---------------------------------------------------------------- memory and the KLEE unit

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
        for rng, what in ((self.unmapped, 'page'), (self.nonidem, 'access')):     # MMR3
            for lo, hi in rng:
                if a < hi and a + n > lo: return f'{kind}_{what}_fault', max(a, lo)

def _secret(label, j=0):
    return b2v(prf(b'LST', label, j)[:16]) | 1

DEFAULT_CSK = b2v(prf(b'CSK'))
SKS_KEY = prf(b'SKS key') + prf(b'SKS key 2')
SKID_A, SKID_B, SKID_C, SKID_D = 0x0123_4567_89AB_CDEF, 0x42, 0x43, 0x44
DEFAULT_SKS = {
    SKID_A: dict(key=SKS_KEY, allowed={M_CIPHER: 3, M_SIG: 1}, usage=0b00100, locality=loc(hw1=2)),
    SKID_B: dict(key=SKS_KEY[::-1], allowed={M_CIPHER: 1}, usage=0b10000, locality=loc(boot=1)),
    SKID_C: dict(key=SKS_KEY, allowed={M_CIPHER: 3}, usage=0, locality=loc(boot=2)),
    SKID_D: dict(key=SKS_KEY, allowed={M_CIPHER: 3}, usage=0, locality=loc(sloc=1)),
}

class Locker:
    def __init__(self):
        self.mdh, self.c1, self.c2, self.img, self.alloc = md(), b'', b'', None, 0

class Unit:
    IDS = (0xA11, 0x42, 0x7)                     # klmvendorid, klmarchid, klmimpid
    RO_ID = ('klmvendorid', 'klmarchid', 'klmimpid', 'klmaxiobuflen')
    def __init__(self, zklv=True, zklio=True, zklmv=True, zklexpire=True, zklmem_hw=True, zklind=False,
                 priv=True, h_ext=True, maxiobuflen=256, clf_total=1 << 20, clock=0, csk=DEFAULT_CSK,
                 ids=None, hw_missing=(), **attrs):
        self.zklv, self.zklio, self.zklmv, self.zklexpire = zklv, zklio, zklmv, zklexpire
        self.zklmem_hw, self.zklind, self.priv, self.h_ext = zklmem_hw, zklind, priv, h_ext
        self.vendorid, self.archid, self.impid = ids or self.IDS
        self.klmaxiobuflen = maxiobuflen if zklio else 0
        self.clf_total, self.clock, self.csk = clf_total, clock, csk     # clock None: unreadable
        self.hw = {j: _secret(b'hw', j) for j in range(6) if j not in hw_missing}
        self.sks = dict(DEFAULT_SKS)
        self.physbootscrt, self.virtbootscrt = _secret(b'phys'), _secret(b'virt')
        self.mlocality, self.hlocality, self.slocality = _secret(b'mloc'), _secret(b'hloc'), _secret(b'sloc')
        self.mode, self.kls_off, self.llstatus, self.vstart, self._rbg = 'M', False, {}, 0, 0
        self.reset()
        self.__dict__.update(attrs)
    def reset(self):                                                # <<KLEE-out-of-reset-unpriv>>
        self.lockers = [Locker() for _ in range(32)]
        self.kliobuflen = self.kliobuftop = self.klstart = 0
        self.kliobuf = bytearray()
        self.klmanagedlocker = NONE
        self.siv = self.impqual = self.siv2 = 0

    # -- helpers
    def rbg(self, n):
        self._rbg += 1
        return b''.join(prf(b'RBG', self._rbg, i) for i in range(n // 32 + 1))[:n]
    def impqual_value(self):
        return cat((0, 32), (self.impid, 32), (self.archid, 32), (self.vendorid, 32))
    def clf_free(self):
        return self.clf_total - sum(c.alloc for c in self.lockers)
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

    # -- Metadata classes <<KLEE-Metadata-validity>>
    def unsupported(self, m):
        mach = MACHINES.get(m['Machine'])
        if mach is None or m['MachineExtension'] or m['SCProtection'] not in mach.sc_levels: return True
        if m['KeyType'] == 1 and not self.sks: return True              # no SKID support (R7)
        return m['MachinePolicy'] not in mach.policies and not (mach.kind == 'ops' and m['MachinePolicy'] == 0)
    def invalid(self, m, ctx, low=False):
        """ctx: 'provision', 'import' or 'size'; low: only bits [63:0] are examined."""
        mach, st = MACHINES.get(m['Machine']), m['State']
        pi = ctx == 'provision' or BASE_TYPE.get(st) == 'pi' or (ctx == 'size' and st == UNCONF)
        bad = [m['res'] & (MASK64 if low else MASK128), m['AuxDataLen'] == 1,
               pi and (m['AuxDataLen'] or m['ADSDropped']),
               mach and mach.kind == 'ops' and m['MachinePolicy'] == 0,
               m['KeyType'] > 1, mach and not mach.key_len and m['KeyType'] == 1,   # R7: no key field
               ctx == 'provision' and st != UNCONF, ctx == 'import' and (st == UNCONF or st > 60),
               st in (54, 55) or (mach and 2 <= st <= 45 and st not in mach.states),
               mach and st in VALID and not mach.stx_ok(st, m['StateExtension']),
               m['Version'] not in VERSIONS]
        if not low:
            bad += [self.locality_problem(m['Locality']), m['ExpirationDate'] and not self.zklexpire,
                    custom_value(m) and sl(m['Locality'], 1, 0) < 2]
        return any(bad)
    def available(self, m):
        mach = MACHINES.get(m['Machine'])
        return int(bool(mach) and not m['MachineExtension'] and m['MachinePolicy'] in mach.policies
                   and m['SCProtection'] in mach.sc_levels and m['KeyType'] in ((0, 1) if self.sks else (0,)))
    def usage_allowed(self, m):                                     # <<KLEE-UsagePolicy>>
        up = m['UsagePolicy']
        if self.mode == 'D': return bool(up & 0b10000)
        return not up >> {'U': 0, 'VU': 0, 'VS': 1, 'HS': 2, 'S': 2, 'M': 3}[self.mode] & 1
    def expired(self, m):                                           # <<KLEE-Metadata-expiration-date>>
        if not self.zklexpire or not m['ExpirationDate']: return False
        return self.clock is None or max(0, self.clock) >= m['ExpirationDate']

    # -- gates
    def _exc(self, cause):
        """kl_exc_no_csk / kl_exc_unconfigured_buffer; illegal without the Privileged Architecture."""
        return Trap(cause) if self.priv else Trap('illegal', 2)
    def _exc_locker(self, k, cause):
        if self.priv: raise Trap(cause)
        self._enter_error(k, EXC_STATE[cause])
        return 'error'
    def _pre(self, ro_id=False):
        if not ro_id and self.kls_off: raise Trap('illegal', 1)
        if not ro_id and not self.csk: raise self._exc('no_csk')
    def _idx(self, k, always=False):
        if isinstance(k, Ind):
            if not (self.zklind or always) or k.reg == 0 or not 0 <= k.value <= 31:   # GR11
                raise Trap('illegal', 1)
            return k.value
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
    def _zeroize(self, k, dirty=True):                              # <<KLEE-CSR-klmanagedlocker>>
        self.lockers[k] = Locker()
        if self.klmanagedlocker == k:
            self.klmanagedlocker = NONE
        if dirty:
            self._dirty(k)
    def _enter_error(self, k, st):                                  # SGR10, SGR11
        cl = self.lockers[k]
        if self.klmanagedlocker == k:
            self.klmanagedlocker = NONE
        cl.mdh.update(State=st, AuxDataLen=0, ADSDropped=0)
        cl.c1 = cl.c2 = b''
        cl.img, cl.alloc = None, 0
        self._dirty(k)
    def _after_mgmt(self, k):
        self.klmanagedlocker = k if self.lockers[k].mdh['State'] in PARTIAL else NONE
        self.klstart = 0

    # -- CSRs
    def _csr(self, name):
        if name in ('kliobuflen', 'kliobuftop') and not self.zklio: raise Trap('illegal', 1)
        self._pre(ro_id=name in self.RO_ID)
    def csr_read(self, name):
        self._csr(name)
        return {'klmvendorid': self.vendorid, 'klmarchid': self.archid, 'klmimpid': self.impid}.get(
            name, getattr(self, name, None))
    def csrs(self, **kv):
        for name, v in kv.items():
            self.csr_write(name, v)
        return self
    def csr_write(self, name, v):
        self._csr(name)
        if name in self.RO_ID: raise Trap('illegal', 1)
        if name == 'kliobuflen':
            self.kliobuflen = self.kliobuftop = min(v, self.klmaxiobuflen)       # WARL; zeroes the buffer
            self.kliobuf = bytearray(self.kliobuflen)
        elif name == 'kliobuftop':
            self.kliobuftop = min(v, self.kliobuflen)
        elif name == 'klstart':
            self.klstart = v
        elif v <= NONE:                                             # klmanagedlocker: 33+ ignored
            self.klmanagedlocker = v

    # -- kl.getmd*, kl.size, kl.avail
    def getmd(self, k):
        k = self._idx(k)
        self._pre()
        self._off(k)
        return dict(self.lockers[k].mdh)
    def getmdl(self, k):
        return pack(self.getmd(k)) & MASK64
    def getst(self, k):                                             # kl.getmdl; srli 19; andi 0x3F
        return self.getmdl(k) >> 19 & 0x3F
    def getstx(self, k):                                            # kl.getmdl; srli 25; andi 0x0F
        return self.getmdl(k) >> 25 & 0x0F
    def _md_operand(self, form, k, lo, m, vec_bits):
        if form == 'C' and (not self.zklv or vec_bits < 128):       # GR6
            raise Trap('illegal', 1)
        if form == 'A': return self.getmd(k), False
        self._pre()
        return (unpack(lo & MASK64), True) if form == 'B' else (as_md(m), True)
    def size(self, form='A', k=None, lo=None, m=None, vec_bits=128):     # <<KLEE-instruction-size>>
        m, supplied = self._md_operand(form, k, lo, m, vec_bits)
        return self.size_of(m, supplied, low=form == 'B')
    def size_of(self, m, supplied, low=False):
        st = m['State']
        if not supplied and st == UNCONF: return 0
        if st in ERROR_STATES: return 16
        if supplied and (st > 60 or self.unsupported(m) or self.invalid(m, 'size', low)): return 0
        mach = MACHINES[m['Machine']]
        if st in VALID or st in (IMP, EXP):
            c1 = mach.content1_size(m)
            return 32 + c1 if m['AuxDataLen'] == 0 else 64 + c1 + content2_size(m)
        return 16 + mach.pi_content_size(m)
    def avail(self, form='A', k=None, lo=None, m=None, vec_bits=128):
        m, supplied = self._md_operand(form, k, lo, m, vec_bits)
        return 0 if not supplied and m['State'] == UNCONF else self.available(m)
    def layout(self, m):
        """(ContentOffset, content_size, image_size, image_end) of <<KLEE-instruction-mv>>."""
        mach = MACHINES[m['Machine']]
        if BASE_TYPE.get(m['State']) == 'pi':
            n = mach.pi_content_size(m)
            return 0, n, n, n
        off, c1 = (16 if m['AuxDataLen'] == 0 else 48), mach.content1_size(m)
        n = c1 + content2_size(m)
        return off, n, off + n, off + min(n, c1 + 16 * (MAX_ADL - 2))

    # -- kl.mgmt  <<KLEE-instruction-mgmt>>, <<KLEE-locker-management>>
    def mgmt(self, k, imm, ml=None, form='D', vec_bits=128):
        if imm not in (PROV, EXP, IMP, END) or form == 'B' or (form == 'C' and (not self.zklv or vec_bits < 128)):
            raise Trap('illegal', 1)
        k = self._idx(k)
        if self.kls_off: raise Trap('illegal', 1)               # first group: klstart untouched
        return self._mgmt(k, imm, ml, form)
    def _mgmt(self, k, imm, ml, form):
        self._pre()
        opening = imm in (PROV, IMP)
        self._off(k, exempt=opening)
        if self.klmanagedlocker not in (k, NONE): raise Trap('illegal', 2)
        self.klstart = 0                                            # common step 3: past the guard checks
        st = self.lockers[k].mdh['State']
        if (imm == EXP and st == UNCONF) or (imm == END and (st == UNCONF or st in ERROR_STATES)):   # SGR24
            self.klmanagedlocker = NONE
            return 'noop'
        if imm == END and st not in CONFIG: raise Trap('illegal', 2)
        if opening or (imm == END and st != PROV):
            ml = self._mgmt_md(form, ml)
        if imm == END and st != PROV and not (
                ml['State'] in COMPLETE or ml['State'] in (IMP, EXP) if BASE_TYPE[st] == 'scc'
                else ml['State'] in (PROV, PPI_IMP, PPI_EXP)):
            raise Trap('illegal', 2)
        if opening: return self._open_in(k, imm, ml)
        return self._open_export(k) if imm == EXP else self._complete(k, ml)
    def _mgmt_md(self, form, ml):
        if form != 'A': return as_md(ml)
        if not self.zklio: raise Trap('illegal', 2)
        if not self.kliobuflen: raise self._exc('unconfigured_buffer')
        if self.kliobuftop < 16:                                    # GR6
            raise Trap('illegal', 2)
        return unpack(b2v(bytes(self.kliobuf[:16])))
    def _open_in(self, k, imm, ml):
        self._zeroize(k)
        cl = self.lockers[k]
        if imm == IMP and ml['State'] in ERROR_STATES:              # short import
            cl.mdh = dict(ml, AuxDataLen=0, ADSDropped=0)
            if ml['State'] in (54, 55) or (ml['State'] == EXPIRED and not self.zklexpire):
                cl.mdh['State'] = INVALID
            self._after_mgmt(k)
            return 'short import'
        if self.unsupported(ml): return self._fail_open(k, 'unsupported')
        if self.invalid(ml, 'provision' if imm == PROV else 'import'): return self._fail_open(k, 'invalid')
        need = MACHINES[ml['Machine']].clf_capacity(ml)
        if need > self.clf_free(): return self._fail_open(k, 'out_of_memory')
        m = dict(ml)
        if imm == PROV:
            m.update(StateExtension=0, MachineUse=0, State=PROV)
        else:                                                       # steps 1-5 of <<KLEE-SCC-import>>
            adl = m['AuxDataLen']
            m['ADSDropped'] = int(adl >= 2 and bool(ml['ADSDropped'] or adl > MAX_ADL))
            m['State'] = PPI_IMP if BASE_TYPE.get(ml['State']) == 'pi' else IMP
        cl.mdh, cl.alloc = m, need
        off, _, _, iend = self.layout(m)
        cl.img = bytearray(iend - off)
        self._after_mgmt(k)
        return 'opened'
    def _fail_open(self, k, why):
        if why == 'invalid' or not self.priv:
            self.lockers[k].mdh = md(State={'invalid': INVALID, **EXC_STATE}[why])
            self._after_mgmt(k)
            return why
        self.klmanagedlocker = NONE
        raise Trap(why)
    def _open_export(self, k):
        cl = self.lockers[k]
        m, st = cl.mdh, cl.mdh['State']
        if st in ERROR_STATES:
            self._after_mgmt(k)
            return 'unchanged'
        if st in VALID:                                             # <<KLEE-SCC-export>>
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
            if ml['State'] in COMPLETE:
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
        if m['KeyType'] == 1 and (b2v(cl.c1[:8]) == ONES64 or not self.sks_resolve(cl)):   # <<KLEE-MVR-open>>
            self._enter_error(k, INVALID)
    def _complete_provisioning(self, k):
        cl = self.lockers[k]
        m = cl.mdh
        if m['AuxDataLen'] or m['ADSDropped']: return self._enter_error(k, INVALID)
        pi, cl.img = bytes(cl.img), None
        if m['KeyType'] == 1 and b2v(pi[:8]) == ONES64:
            cl.c1, m['KeyType'] = self.rbg(MACHINES[m['Machine']].key_len), 0
        else:
            cl.c1 = pi[:16] if m['KeyType'] == 1 else pi
            if m['KeyType'] == 1 and not self.sks_resolve(cl): return self._enter_error(k, INVALID)
        m.update(State=READY, StateExtension=0, MachineUse=0)
        if self.wants_ads(m):
            m['AuxDataLen'], cl.c2 = ADS_BLOCKS, self.gen_ads(cl)
        self._dirty(k)
    def sks_resolve(self, cl):                                      # <<KLEE-system-keys>>
        m, e = cl.mdh, self.sks.get(b2v(cl.c1[:8]))
        if e is None or m['Machine'] not in e['allowed']: return False
        allowed = e['allowed'][m['Machine']]
        if (m['MachinePolicy'] != allowed) if MACHINES[m['Machine']].kind == 'ext' else m['MachinePolicy'] & ~allowed:
            return False
        new_loc = loc_union(m['Locality'], e['locality'])
        if new_loc is None or self.locality_problem(new_loc): return False
        m.update(UsagePolicy=narrow_skid(m['UsagePolicy'], e['usage']), Locality=new_loc)
        return True

    # -- kl.setst family  <<KLEE-instruction-setst>>
    def setst(self, k, imm, aux=None, form='A', vec_bits=128):
        if imm in (SUCCESS, FAILURE):                               # SGR7
            raise Trap('illegal', 1)
        if 56 <= imm <= 63: return self.mgmt(k, imm, aux, form=form, vec_bits=vec_bits)
        if k == 'X0':
            if form == 'A' and imm == UNCONF: return self.clearall()
            raise Trap('illegal', 1)
        if form == 'C' and not self.zklv: raise Trap('illegal', 1)
        k = self._idx(k)
        self._pre()
        if imm == UNCONF: return self.clear(k)
        self._off(k)
        if imm in ERROR_STATES:
            if self.lockers[k].mdh['State'] == UNCONF: return 'noop'
            self._enter_error(k, INVALID if imm in (54, 55) or (imm == EXPIRED and not self.zklexpire) else imm)
            return 'error state'
        g = self._usage_gate(k)
        if g: return g
        cl = self.lockers[k]
        m = cl.mdh
        if imm == CLEAR_ADS:                                        # SGR23: in every Valid State
            m.update(AuxDataLen=0, ADSDropped=0)
            cl.c2 = b''
            self._dirty(k)
            return 'ads cleared'
        if m['State'] in (SUCCESS, FAILURE) and imm != READY:       # SGR5, SGR6
            self._enter_error(k, INVALID)
            return 'invalid'
        if imm == READY:                                            # SGR8
            MACHINES[m['Machine']].on_ready(cl)
            m['State'] = READY
        elif not MACHINES[m['Machine']].setst(self, cl, imm, aux):
            self._enter_error(k, INVALID)
            return 'invalid'
        self._dirty(k)
        return 'ok'
    def clear(self, k):
        off = self._off(k, exempt=True)
        self._zeroize(k, dirty=off or self.lockers[k].mdh['State'] != UNCONF)
        return 'cleared'
    def clearall(self):                                             # <<KLEE-instruction-clearall>>
        self._pre()
        for k in range(32):
            self.clear(k)
        self.kliobuf = bytearray()
        self.kliobuflen = self.kliobuftop = self.klstart = self.siv = self.impqual = self.siv2 = 0
        self.klmanagedlocker = NONE
        return 'cleared all'
    def _usage_gate(self, k, forbidden_sub=False, needs_buf=False):
        """SGR19, conditions 1-7."""
        m = self.lockers[k].mdh
        if m['State'] == UNCONF: raise Trap('illegal', 2)
        if m['State'] in ERROR_STATES: return 'noop'
        if m['State'] in PARTIAL: return self._exc_locker(k, 'privilege_violation')
        if forbidden_sub: raise Trap('illegal', 2)
        if not self.usage_allowed(m): return self._exc_locker(k, 'privilege_violation')
        if self.expired(m):
            self._enter_error(k, EXPIRED)
            return 'expired'
        if needs_buf and not self.kliobuflen: raise self._exc('unconfigured_buffer')

    # -- kl.exec  <<KLEE-instruction-exec>>
    def exec_(self, k, form='A', vin=None, vout=None, sew=8, halt_after=None):
        if form != 'D' and not self.zklv: raise Trap('illegal', 1)
        k = self._idx(k)
        self._pre()
        self._off(k)
        nb = sew // 8
        if form != 'D' and self.klstart != self.vstart * nb: raise Trap('illegal', 2)
        cl = self.lockers[k]
        m = cl.mdh
        mach = MACHINES.get(m['Machine'])
        want = mach.exec_form(m) if mach and m['State'] in VALID else None
        sub = form == 'D' and want in ('A', 'B', 'C')
        def stop(result):                                           # SGR16 output zeroing
            if form in ('A', 'C') and vout is not None:
                vout[self.vstart * nb:] = bytes(len(vout) - self.vstart * nb)
            elif form == 'D' and self.zklio and self.kliobuflen:
                self.kliobuf[self.klstart:self.kliobuftop] = bytes(max(0, self.kliobuftop - self.klstart))
            self.klstart = self.vstart = 0
            return result
        g = self._usage_gate(k, (sub and not self.zklio) or (want == 'A' and form in ('B', 'C')), sub)
        if g: return stop(g)
        if want is None or form not in ('D', want):                 # SGR2, SGR5
            self._enter_error(k, INVALID)
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

    # -- kl.restrict*  <<KLEE-instruction-restrict>>
    NAMED = {'l': ('MachinePolicy', 'SCProtection'), 'h': ('Locality', 'UsagePolicy', 'ExpirationDate')}
    def restrict(self, k, x, which='v', vec_bits=128):
        if which == 'v' and (not self.zklv or vec_bits < 128): raise Trap('illegal', 1)
        k = self._idx(k)
        self._pre()
        self._off(k)
        cl = self.lockers[k]
        m, st = cl.mdh, cl.mdh['State']
        if st == UNCONF: return 'noop'
        if st in PARTIAL: return self._exc_locker(k, 'privilege_violation')
        xv = x if isinstance(x, int) else pack(x)
        xs = unpack(xv & {'l': MASK64, 'h': MASK128 ^ MASK64, 'v': MASK128}[which])
        named = self.NAMED['l'] + self.NAMED['h'] if which == 'v' else self.NAMED[which]
        mach, new = MACHINES.get(m['Machine']), dict(m)
        bad = [n for n in MDH_FIELD if n not in named and xs[n]] + [xs['res']]
        req = xs['MachinePolicy']
        if req:
            bad.append(mach is None or mach.kind == 'ext' or req & ~m['MachinePolicy'] or req not in mach.policies
                       or (st in mach.op_states and not req & mach.op_states[st]))
            new['MachinePolicy'] = req
        req = xs['SCProtection']
        if req:
            bad.append(mach is None or req not in mach.sc_levels or sc_rank(req) < sc_rank(m['SCProtection']))
            new['SCProtection'] = req
        req = xs['Locality']
        if req:
            for name, hi, lo in LOC_SUB:
                rv, cv = sl(req, hi, lo), sl(m['Locality'], hi, lo)
                if rv and rv != cv:
                    if cv and not (name in ('hw1', 'hw2') and rv > cv):
                        bad.append(True)
                    new['Locality'] = new['Locality'] & ~(((1 << hi - lo + 1) - 1) << lo) | rv << lo
            bad.append(new['Locality'] != m['Locality'] and self.locality_problem(new['Locality']))
        if (new['SCProtection'], new['Locality']) != (m['SCProtection'], m['Locality']):
            bad.append(custom_value(new) and sl(new['Locality'], 1, 0) < 2)          # GR9
        if xs['UsagePolicy']:
            new['UsagePolicy'] = narrow_up(m['UsagePolicy'], xs['UsagePolicy'])
        req = xs['ExpirationDate']
        if req:
            bad.append(not self.zklexpire or (m['ExpirationDate'] and req > m['ExpirationDate']))
            new['ExpirationDate'] = req
        if any(bad):
            if st in ERROR_STATES:                  # the original Error State is kept (SGR16)
                return 'noop'
            self._enter_error(k, INVALID)
            return 'invalid'
        if st not in ERROR_STATES:
            extra = mach.clf_capacity(new) - cl.alloc
            if extra > self.clf_free(): return self._exc_locker(k, 'out_of_memory')
            cl.alloc += max(0, extra)
        m.update(new)
        self._dirty(k)
        return 'ok'

    # -- kl.clone, kl.rename, kl.swap  <<KLEE-instruction-clone>>
    def _pair(self, kd, ks):
        kd, ks = self._idx(kd, True), self._idx(ks, True)
        self._pre()
        return kd, ks
    def clone(self, kd, ks):
        kd, ks = self._pair(kd, ks)
        if kd == ks: return 'noop'
        self._off(ks)
        self._off(kd, exempt=True)
        src = self.lockers[ks]
        if src.mdh['State'] == UNCONF: raise Trap('illegal', 2)
        if src.mdh['State'] in PARTIAL: return self._exc_locker(ks, 'privilege_violation')
        if src.alloc > self.clf_free() + self.lockers[kd].alloc: return self._exc_locker(kd, 'out_of_memory')
        self._zeroize(kd)
        dst = self.lockers[kd]
        dst.mdh, dst.c1, dst.c2, dst.alloc = dict(src.mdh), src.c1, src.c2, src.alloc
        return 'cloned'
    def rename(self, kd, ks):
        kd, ks = self._pair(kd, ks)
        if kd == ks: return 'noop'
        self._off(ks)
        self._off(kd, exempt=True)
        self.lockers[kd], self.lockers[ks] = self.lockers[ks], Locker()
        self.klmanagedlocker = {ks: kd, kd: NONE}.get(self.klmanagedlocker, self.klmanagedlocker)
        self._dirty(ks)
        self._dirty(kd)
        return 'renamed'
    def swap(self, kd, ks):
        kd, ks = self._pair(kd, ks)
        if kd == ks: return 'noop'
        self._off(ks)
        self._off(kd)
        self.lockers[kd], self.lockers[ks] = self.lockers[ks], self.lockers[kd]
        self.klmanagedlocker = {ks: kd, kd: ks}.get(self.klmanagedlocker, self.klmanagedlocker)
        self._dirty(ks)
        self._dirty(kd)
        return 'swapped'

    # -- kl.derive  <<KLEE-instruction-derive>>
    def derive(self, kd, ks, length):
        kd, ks = self._idx(kd), self._idx(ks)
        if kd == ks: raise Trap('illegal', 1)
        self._pre()
        self._off(ks)
        self._off(kd)
        ends = (ks, kd)
        if any(self.lockers[e].mdh['State'] == UNCONF for e in ends): raise Trap('illegal', 2)
        if any(self.lockers[e].mdh['State'] in ERROR_STATES for e in ends): return 'noop'
        for test in (lambda m: m['State'] in PARTIAL, lambda m: not self.usage_allowed(m)):     # SGR19
            for e in ends:
                if test(self.lockers[e].mdh): return self._exc_locker(e, 'privilege_violation')
        exp = [e for e in ends if self.expired(self.lockers[e].mdh)]
        for e in exp:
            self._enter_error(e, EXPIRED)
        if exp: return 'expired'
        S, D = self.lockers[ks].mdh, self.lockers[kd].mdh
        se, de = SRC_EP.get(S['Machine']), DST_EP.get(D['Machine'])
        ok = ((ks, bool(se) and S['State'] in se[0]),                                     # DER1 items 1-2, DER4
              (kd, bool(de) and D['State'] in de[1] and not (de[0] == 'key' and D['KeyType'] == 1)))
        bad = [e for e, good in ok if not good]
        if bad:
            for e in bad:
                self._enter_error(e, INVALID)
            return 'invalid'
        key, dlen = de[0] == 'key', MACHINES[D['Machine']].key_len
        slen = MACHINES[M_KEX].state_len if not se[1] else 1 << 30
        if key and (length < dlen or slen < dlen):                     # DER1 item 5
            self._enter_error(kd, INVALID)
            return 'invalid'
        if length == 0:                                             # DER8
            return 'nothing'
        if not se[1]:                                               # DER5 restricted (DER2); XOF output: DER6 unrestricted
            union = loc_union(D['Locality'], S['Locality'])
            if union is None or self.locality_problem(union) or sc_rank(D['SCProtection']) < sc_rank(S['SCProtection']):
                self._enter_error(kd, INVALID)
                return 'invalid'
            D.update(UsagePolicy=narrow_skid(D['UsagePolicy'], S['UsagePolicy']), Locality=union)
            if self.zklexpire:
                D['ExpirationDate'] = min([x for x in (D['ExpirationDate'], S['ExpirationDate']) if x] or [0])
        n = min(length, dlen) if key else length
        scl, dcl = self.lockers[ks], self.lockers[kd]
        if se[1]:
            data = b''.join(MACHINES[M_XOF].squeeze(self, scl) for _ in range(n))
        else:
            data = MACHINES[M_KEX].get_state(scl)[:n]
        if key:
            dcl.c1 = data + dcl.c1[dlen:]
        else:
            for x in data:
                MACHINES[M_XOF].absorb(self, dcl, bytes([x]))
        self._dirty(ks)
        self._dirty(kd)
        return 'transferred'

    # -- the serialized image S and the locker transfers
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
    def _xfer_pre(self, k, writing):                                # SGR21, SGR22
        k = self._idx(k)
        self._pre()
        self._off(k)
        st = self.lockers[k].mdh['State']
        if st == UNCONF or st in ERROR_STATES: return None          # SGR24: no operation
        if st not in ((PROV, IMP, PPI_IMP) if writing else (EXP, PPI_EXP)) or self.klstart % 16 \
                or (st in (IMP, EXP) and self.klmanagedlocker != k):
            raise Trap('illegal', 2)
        return k
    def _serial(self, end, step, fault, act, halt_after, restart):
        j = self.klstart
        while j < end:
            f = fault(j)
            if f or (halt_after is not None and j - self.klstart >= halt_after):
                self.klstart = 0 if restart and not f else j        # IRR3: no restart on a fault
                if f: raise Trap(f[0], tval=f[1])
                return 'halted'
            act(j)
            j += step
        self.klstart = 0
        return 'done'
    def _mem(self, k, mem, addr, halt_after=None, restart=False, store=False):       # <<KLEE-instruction-load>>, -store
        if not self.zklmem_hw: raise Trap('illegal', 1)
        k = self._xfer_pre(k, not store)
        kind = 'store' if store else 'load'
        if addr % 16: raise Trap(f'{kind}_misaligned', tval=addr)
        if k is None:                                               # SGR24: an empty transfer window
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
    def _mv_pre(self, k, writing, vec_len=None, sew=8):
        if not self.zklmv or (vec_len is not None and not self.zklv): raise Trap('illegal', 1)
        if vec_len is not None and (vec_len % 16 or self.vstart * sew // 8 % 16): raise Trap('illegal', 1)
        k = self._xfer_pre(k, writing)
        return k, None if k is None else self.layout(self.lockers[k].mdh)[3]
    def mv_in(self, k, value):                                      # kl.mv Kd, Xs2
        k, iend = self._mv_pre(k, True)
        if k is None: return 'noop'
        if self.klstart >= iend: return 'nothing'
        self._s_put(k, self.klstart, v2b(value, 16))
        self.klstart += 16
        self._dirty(k)
        return 'moved'
    def mv_out(self, k):                                            # kl.mv Xd, Ks1
        k, iend = self._mv_pre(k, False)
        if k is None or self.klstart >= iend: return 0
        self.klstart += 16
        return b2v(self._s_get(k, self.klstart - 16))
    def mv_vec(self, k, vec, sew=8, halt_after=None, out=False):    # kl.mv Kd, Vs2 / kl.mv Vd, Ks1
        k, iend = self._mv_pre(k, not out, len(vec), sew)
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

    # -- KLIOBUF  <<KLEE-iobuf-transfer-window>>
    def _io(self, mem, addr, xl, halt_after=None, restart=False, out=False):
        if not self.zklio: raise Trap('illegal', 1)
        self._pre()
        if not self.kliobuflen: raise self._exc('unconfigured_buffer')
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
    input_, output = functools.partialmethod(_io, out=False), functools.partialmethod(_io, out=True)

# ---------------------------------------------------------------- software sequences

fresh = Unit

def cipher(**kw):
    return md(**{'Machine': M_CIPHER, 'MachinePolicy': 3, **kw})

def xof(**kw):
    return md(**{'Machine': M_XOF, **kw})

def sig(**kw):
    return md(**{'Machine': M_SIG, 'MachinePolicy': 3, **kw})

def pi_content(m, seed=0x31):
    return bytes(seed + 7 * i & 0xFF for i in range(MACHINES[m['Machine']].pi_content_size(m)))

def provision(u, k, m, content=None, via='load', form='D', done_form='A'):
    content = pi_content(m) if content is None else content
    u.mgmt(k, PROV, m, form=form)
    if u.lockers[k].mdh['State'] == PROV:
        if via == 'load':
            u.load(k, Memory(content), BASE)
        elif via == 'mv':
            for o in range(0, len(content), 16):
                u.mv_in(k, b2v(content[o:o + 16]))
        else:
            u.vstart = 0
            u.mv_vec(k, bytearray(content), sew=32)
        u.mgmt(k, END, form=done_form)
    return u.lockers[k].mdh['State']

def listing_provision(clear_at=lambda s: False, m=None, on_trap=None, limit=8, error_at=None):
    """Zklmem provisioning of <<KLEE-management-code-snippets>>; clear_at(boundary) is a handler's kl.clear,
    on_trap(u, tag) a handler that returns past a trapping opening kl.mgmt."""
    u, m, step = fresh(), m or cipher(), 0
    def opening():
        tag = trap_of(u.mgmt, 0, PROV, m)
        if tag:
            on_trap(u, tag)
    ops = (opening, lambda: u.load(0, Memory(pi_content(m)), BASE), lambda: u.mgmt(0, END))
    for restarts in range(limit):
        for op in ops:
            for act in (op, None):                                  # the instruction, then its kl.getst
                if clear_at(step):
                    u.clear(0)
                if step == error_at:
                    u.setst(0, OOM)                                 # a handler sets an Error State
                step += 1
                if act:
                    act()
            if u.getst(0) == UNCONF:
                break                                               # beqz t2, restart
            if u.getst(0) in ERROR_STATES:
                return u.getst(0), restarts                         # beq t3, t2, handle_errors
        else:
            return u.getst(0), restarts
    return 'livelock', limit

def listing_export(clear_at=lambda s: False, error_at=None):
    """Zklmem export of <<KLEE-management-code-snippets>>: (final State, image), or ('lost', None) at a check."""
    u, mem, step = pv(fresh(), 0, cipher()), Memory(), 0
    def tick():
        nonlocal step
        if clear_at(step):
            u.clear(0)
        if step == error_at:
            u.setst(0, OOM)
        step += 1
    tick()
    n = u.size(k=0)
    tick()
    m = u.getmd(0)
    if not n or m['State'] == UNCONF: return 'lost', None           # kl.size 0, or State 0 in the fetched MDH
    for op in (lambda: u.mgmt(0, EXP), lambda: u.store(0, mem, BASE), lambda: u.mgmt(0, END, m)):
        tick()
        op()
        tick()
        if u.getst(0) == UNCONF: return 'lost', None                # beqz t2, handle_errors
        if u.getst(0) in ERROR_STATES: return 'error', u.getst(0)   # beq t3, t2, handle_errors
    return u.getst(0), mdh_bytes(m) + mem.read(BASE, n - 16)

def pv(u, k, m, content=None):
    provision(u, k, m, content)
    return u

def opened(imm=PROV, m=None, k=0, **kw):
    u = fresh(**kw)
    u.mgmt(k, imm, cipher() if m is None else m)
    return u

def export(u, k, via='store', form='D'):
    """MDH, then the image; an Error-State locker is its MDH alone."""
    m, n = u.getmd(k), u.size(k=k)
    if m['State'] in ERROR_STATES: return mdh_bytes(m)
    u.mgmt(k, EXP)
    if via == 'store':
        mem = Memory()
        u.store(k, mem, BASE)
        img = mem.read(BASE, n - 16)
    else:
        img = b''.join(v2b(u.mv_out(k), 16) for _ in range(16, n, 16))
    if form == 'A':
        u.kliobuf[:16] = mdh_bytes(m)
    u.mgmt(k, END, m, form=form)
    return mdh_bytes(m) + img

def import_(u, k, img, via='load', form='D', halt_after=None):
    ml = unpack(b2v(img[:16]))
    if form == 'A':
        u.kliobuf[:16] = img[:16]
    u.mgmt(k, IMP, ml, form=form)
    if u.lockers[k].mdh['State'] not in CONFIG: return u.lockers[k].mdh['State']
    if via == 'load':
        if u.load(k, Memory(img[16:]), BASE, halt_after=halt_after) == 'halted': return 'halted'
    else:
        for o in range(16, len(img), 16):
            u.mv_in(k, b2v(img[o:o + 16]))
    u.mgmt(k, END, ml, form=form)
    return u.lockers[k].mdh['State']

def export_pccc(u, k, saved):
    """Store a locker already opened for a nested export and complete it with `saved`."""
    n, out = u.size(k=k), Memory()
    u.store(k, out, BASE)
    u.mgmt(k, END, saved)
    return mdh_bytes(saved) + out.read(BASE, n - 16)

def snapshot(u):
    return (tuple(pack(c.mdh) for c in u.lockers),
            tuple((c.c1, c.c2, c.img and bytes(c.img), c.alloc) for c in u.lockers),
            u.siv, u.impqual, u.siv2, u.klstart, u.klmanagedlocker, u.kliobuflen, u.kliobuftop, bytes(u.kliobuf))

def ready_cipher(u, k, **kw):
    """A cipher locker in State ENCRYPT; a _UsagePolicy_ is applied afterwards with kl.restricth."""
    up = kw.pop('UsagePolicy', 0)
    provision(u, k, cipher(**kw))
    u.setst(k, ToyCipher.ENCRYPT, 0x77)
    if up:
        u.restrict(k, md(UsagePolicy=up), 'h')
    return u

def rc(k=0, unit=None, **kw):
    return ready_cipher(unit or fresh(), k, **kw)

def final_cipher(final, **kw):
    w = pv(fresh(), 0, cipher(**kw))
    tag = MACHINES[M_CIPHER].verify_tag(w, w.lockers[0])
    w.setst(0, ToyCipher.VERIFY, tag if final == SUCCESS else tag ^ 1)
    return w

def xof_success(u, k, seed=b'shared secret'):
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
    u.load(k, mem, BASE, halt_after=halt_after)
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
    section('MDH layout  <<KLEE-metadata-header>>')
    cover = ovl = 0
    for _, hi, lo in MDH_FIELDS:
        m = ((1 << hi - lo + 1) - 1) << lo
        ovl, cover = ovl | cover & m, cover | m
    eq('fields tile [127:0] without overlap', (sum(hi - lo + 1 for _, hi, lo in MDH_FIELDS), ovl, cover),
       (128, 0, MASK128))
    bits = [(n, lo + b, 1 << b) for n, (hi, lo) in MDH_FIELD.items() for b in range(hi - lo + 1)]
    check('walking ones: each field bit at its position, no bleed',
          all(pack(md(**{n: v})) == 1 << p and unpack(1 << p) == md(**{n: v}) for n, p, v in bits))
    ones = md(**{n: (1 << hi - lo + 1) - 1 for n, (hi, lo) in MDH_FIELD.items()}, res=RES_MASK)
    eq('all-ones MDH packs to ones(128) and round trips', (pack(ones), unpack(MASK128)), (MASK128, ones))
    eq('each reserved bit is detected; 116-127 lie above [63:0]',
       ([bool(unpack(1 << hi)['res']) for n, hi, lo in MDH_FIELDS if n is None], unpack(1 << 116)['res'] & MASK64),
       ([True] * 4, 0))
    w = lambda n: MDH_FIELD[n][0] - MDH_FIELD[n][1] + 1
    u = fresh()
    u.mgmt(4, IMP, dict(ones, State=INVALID))
    eq('kl.getst / kl.getstx expansions; kl.getmdl is MDH[63:0]', (u.getst(4), u.getstx(4), u.getmdl(4)),
       (INVALID, 0xF, pack(u.getmd(4)) & MASK64))
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
    eq('Unconfigured kl.getmd* all zero (SGR13); MDH image little-endian; 6-bit State',
       (pack(u.getmd(0)), mdh_bytes(md(Machine=0x123)), bin_(END + 1, w('State'))), (0, v2b(0x123, 16), 0))

def t_states():
    section('States  <<KLEE-State-field>>, <<KLEE-SC-sealing-status>>')
    parts = [{0}, set(VALID), set(ERROR_STATES), set(PARTIAL)]
    eq('Unconfigured, Valid, Error, Configuration (56-63) partition State; Complete = Valid + Error; 56-60 used, 61-63 reserved',
       (sum(map(len, parts)), set().union(*parts), set(COMPLETE), set(CONFIG) <= parts[3]),
       (64, set(range(64)), parts[1] | parts[2], True))
    eq('Ready, Success, Failure, Error States 48-53, Configuration base types',
       (READY, SUCCESS, FAILURE, [UNSUP, INVALID, OOM, AUTH, PRIV, EXPIRED], [BASE_TYPE[s] for s in CONFIG]),
       (1, 46, 47, list(range(48, 54)), ['pi', 'scc', 'scc', 'pi', 'pi']))
    eq('kl.mgmt immediates 56, 57, 58, 63; 59-62 reserved',
       [i for i in range(56, 64) if trap_of(fresh().mgmt, 0, i, md()) != 'illegal/1'], [56, 57, 58, 63])
    eq('kl.setst #46, #47 reserved even on an Unconfigured locker (SGR7)',
       (trap_of(fresh().setst, 0, 46), trap_of(fresh().setst, 0, 47)), ('illegal/1',) * 2)
    eq("'andi 0x38; beq 0x30' is true exactly on the Error States", {s for s in range(64) if s & 0x38 == 0x30},
       set(ERROR_STATES))

def t_validity():
    section('Metadata validity  <<KLEE-Metadata-validity>>, <<KLEE-MVR-open>>')
    rows = []
    for kw in (dict(res=1 << 46), dict(res=1 << 116), dict(AuxDataLen=1), dict(ADSDropped=1), dict(AuxDataLen=2),
               dict(MachinePolicy=0), dict(KeyType=2), dict(KeyType=3), dict(Locality=loc(boot=3)),
               dict(Version=1), dict(Version=2), dict(Version=3, Locality=loc(hw1=3)), dict(SCProtection=6),
               dict(State=READY)):
        u = rc(3).csrs(klstart=16)
        rows.append((u.mgmt(3, PROV, cipher(**kw)), pack(u.getmd(3)), u.lockers[3].alloc, u.klmanagedlocker, u.klstart))
    eq('14 invalid PIs -> Invalid, other fields zero, no capacity, klmanagedlocker 32, klstart 0', rows,
       [('invalid', pack(md(State=INVALID)), 0, NONE, 0)] * 14)
    eq('R7: KeyType 1 for a Machine without a key field is invalid; KeyType 0 provisions it',
       [rc(3).mgmt(3, PROV, md(Machine=M_HASH, KeyType=1)), rc(3).mgmt(3, PROV, md(Machine=M_HASH))],
       ['invalid', 'opened'])
    nosks = rc(3)
    nosks.sks = {}
    eq('R7: KeyType 1 without SKID support -> kl_exc_unsupported, kl.avail 0',
       [trap_of(nosks.mgmt, 3, PROV, cipher(KeyType=1)), nosks.avail('C', m=cipher(KeyType=1))],
       ['unsupported', 0])
    eq('ExpirationDate without Zklexpire, unresolvable Locality -> Invalid',
       [fresh(zklexpire=False).mgmt(0, PROV, cipher(ExpirationDate=9)),
        fresh(hw_missing=(0, 1, 2)).mgmt(0, PROV, cipher(Locality=loc(hw1=1)))], ['invalid'] * 2)
    u = fresh()
    eq('GR9 ChipFamScrt/ChipScrt valid, SiPScrt (even substituted) not; AuxInfo and MachineUse unchecked '
       '(<<KLEE-MachineUse>>); zero signature bits',
       [provision(u, 0, cipher(SCProtection=6, Locality=loc(hw1=2))),
        provision(u, 1, md(Machine=M_CUSTOM, MachinePolicy=1, Locality=loc(hw1=3))),
        provision(fresh(hw_missing=(0,)), 1, md(Machine=M_CUSTOM, MachinePolicy=1, Locality=loc(hw1=1))),
        provision(u, 2, cipher(AuxInfo=5, MachineUse=7)), provision(u, 3, sig(MachinePolicy=0)),
        fresh().mgmt(0, IMP, cipher(State=2, AuxInfo=5, MachineUse=7))],
       [READY, READY, INVALID, READY, READY, 'opened'])
    rows = []
    for m in (md(Machine=M_ABSENT, MachinePolicy=1), cipher(MachineExtension=1), cipher(SCProtection=3),
              xof(MachinePolicy=2), md(Machine=M_ABSENT, State=5)):
        u = rc(5).csrs(klstart=32)
        rows.append((trap_of(u.mgmt, 5, PROV, m), pack(u.getmd(5)), u.klstart))
    eq('unsupported (also if invalid) -> kl_exc_unsupported, locker zeroized, klstart cleared', rows,
       [('unsupported', 0, 0)] * 5)
    eq('import of unsupported Metadata -> kl_exc_unsupported',
       trap_of(fresh().mgmt, 0, IMP, md(Machine=M_ABSENT, State=2)), 'unsupported')
    got = {st: fresh().mgmt(0, IMP, cipher(State=st)) for st in (0, 61, 62, 63, 4, 7, 45, 1, 2, 3, 46, 47, 56, 57, 58,
                                                                 59, 60)}
    eq('import ml.State 0, 61-63, undefined -> Invalid; Valid and Configuration open', got,
       {st: 'invalid' if st in (0, 61, 62, 63, 4, 7, 45) else 'opened' for st in got})
    eq('SCC MDH may carry AuxDataLen >= 2 and ADSDropped; a pi-base PCCC may not',
       [fresh().mgmt(0, IMP, cipher(State=2, AuxDataLen=4, ADSDropped=1)),
        fresh().mgmt(0, IMP, cipher(State=PROV, AuxDataLen=2)), fresh().mgmt(0, IMP, cipher(State=PROV, ADSDropped=1))],
       ['opened', 'invalid', 'invalid'])
    stx = [cipher(State=2, StateExtension=1), xof(State=SUCCESS, StateExtension=1), cipher(State=57, StateExtension=0xF),
           sig(State=58, StateExtension=6), cipher(State=2, StateExtension=2),
           cipher(State=READY, StateExtension=1), sig(State=2, StateExtension=1), xof(State=2, StateExtension=8)]
    eq('import and kl.size: a StateExtension the Machine uses in that State, or any in a Configuration State, '
       'opens; any other is invalid (also bit 0 in Ready, where no state block is held)',
       [(fresh().mgmt(0, IMP, m), fresh().size('B', lo=pack(m) & MASK64) > 0) for m in stx],
       [('opened', True)] * 4 + [('invalid', False)] * 4)
    u = opened(m=cipher(StateExtension=0xF, MachineUse=0xBEEF))
    eq('a PI StateExtension is ignored (not examined for validity, kl.size > 0); provisioning zeroes it and MachineUse',
       (u.getmd(0)['StateExtension'], u.getmd(0)['MachineUse'], u.getst(0),
        fresh().size('B', lo=pack(cipher(StateExtension=0xF)) & MASK64) > 0), (0, 0, PROV, True))
    need = MACHINES[M_CIPHER].clf_capacity(cipher())
    u = fresh(clf_total=need - 1).csrs(klmanagedlocker=0)
    eq('no KLF capacity: kl_exc_out_of_memory, Unconfigured, klmanagedlocker 32',
       (trap_of(u.mgmt, 0, PROV, cipher()), u.getst(0), u.klmanagedlocker), ('out_of_memory', 0, NONE))
    u = fresh(clf_total=need)
    eq('exactly enough capacity; an Error-State locker holds none (SGR10)',
       (provision(u, 0, cipher()), u.setst(0, INVALID), u.lockers[0].alloc, u.clf_free()),
       (READY, 'error state', 0, need))
    odd = md(Machine=M_ABSENT, State=AUTH, res=5 << 116, KeyType=3, ExpirationDate=7, AuxDataLen=9, ADSDropped=1,
             Locality=loc(boot=3))
    u = fresh(zklexpire=False)
    eq('the short import applies no validity check', (u.mgmt(0, IMP, odd), u.getmd(0)),
       ('short import', dict(odd, AuxDataLen=0, ADSDropped=0)))

def t_lengths():
    section('Length rule, kl.size, kl.avail  <<KLEE-length-rule>>, <<KLEE-instruction-size>>')
    u, cm, base = fresh(), MACHINES[M_CIPHER], cipher()
    same = lambda f, **kv: all(f(**{k: v}) == f() for k, v in kv.items())
    check('PI length independent of SCProtection, StateExtension, MachineUse, policies, AuxInfo, State, Version',
          same(lambda **kw: cm.pi_content_size(cipher(**kw)), SCProtection=1, StateExtension=1, MachineUse=9,
               UsagePolicy=7, Locality=2, ExpirationDate=5, AuxInfo=3, State=5, Version=1))
    eq('PI length depends on KeyType; Content1 on StateExtension',
       (cm.pi_content_size(base), cm.pi_content_size(cipher(KeyType=1)),
        cm.content1_size(cipher(StateExtension=1)) - cm.content1_size(base)), (32, 16, 16))
    check('SCC length independent of SCProtection, MachineUse, AuxInfo, UsagePolicy, Locality, ExpirationDate, State',
          same(lambda **kw: u.size_of(cipher(**{'State': 2, 'AuxDataLen': 4, **kw}), True), SCProtection=1,
               MachineUse=9, AuxInfo=5, UsagePolicy=7, Locality=2, ExpirationDate=5, State=3))
    check('KLF capacity depends only on SCProtection and MachinePolicy',
          same(lambda **kw: cm.clf_capacity(cipher(**kw)), KeyType=1, StateExtension=3, AuxDataLen=7, ADSDropped=1,
               UsagePolicy=15, ExpirationDate=9)
          and cm.clf_capacity(cipher(SCProtection=1)) != cm.clf_capacity(base)
          != cm.clf_capacity(cipher(MachinePolicy=1)))
    c1 = cm.content1_size(cipher(StateExtension=1))
    S = lambda **kw: u.size('C', m=cipher(**kw))
    eq('kl.size 0: Unconfigured; unsupported, invalid, 61-63, PI with ADS fields, undefined State',
       [u.size(k=0), u.size('C', m=md(Machine=M_ABSENT, MachinePolicy=1, State=2)), S(State=2, KeyType=2),
        S(State=61), S(State=62), S(State=63), S(AuxDataLen=2), S(ADSDropped=1), S(State=9, AuxDataLen=4)], [0] * 9)
    em = [md(Machine=M_ABSENT, State=s, res=1 << 46, AuxDataLen=1 + 8 * (s & 1), ADSDropped=s & 1)
          for s in ERROR_STATES]
    eq('kl.size 16 for any Error-State MDH, even invalid or unsupported; AuxDataLen, ADSDropped ignored (B, C)',
       [u.size('C', m=x) for x in em] + [u.size('B', lo=pack(x)) for x in em], [16] * 16)
    eq('kl.size: Valid 32+c1 / 64+c1+c2 (ADSDropped keeps 64); 57, 58 SCC; 56, 59, 60, PI',
       [S(State=2, StateExtension=1), S(State=2, StateExtension=1, AuxDataLen=4),
        S(State=2, StateExtension=1, AuxDataLen=4, ADSDropped=1), S(State=57, AuxDataLen=4), S(State=58, AuxDataLen=4),
        S(State=56), S(State=59), S(State=60), S(), S(KeyType=1)],
       [32 + c1, 96 + c1, 64 + c1, 128, 128, 48, 48, 48, 48, 32])
    fb = fresh(slocality=0)
    ul, gr, hr = cipher(State=2, Locality=loc(sloc=1)), cipher(State=2, SCProtection=6), cipher(State=2, res=1 << 116)
    eq('Form C checks [127:64] (Locality, GR9); Form B does not (nor a reserved bit above 63)',
       [fb.size('C', m=ul), fb.size('B', lo=pack(ul)), fb.size('C', m=gr), fb.size('B', lo=pack(gr)),
        fb.size('B', lo=pack(hr))], [0, 64, 0, 64, 64])
    eq('Form B: unsupported Version -> 0, an Error-State MDH -> 16 as in Form C',
       [fb.size('B', lo=pack(cipher(State=2, Version=1))), fb.size('B', lo=pack(cipher(State=INVALID, Version=1))),
        fb.size('C', m=cipher(State=INVALID, Version=1))], [0, 16, 16])
    eq('Form C of kl.size needs VL*SEW >= 128 (GR6)', trap_of(u.size, 'C', m=base, vec_bits=64), 'illegal/1')
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
       ([a.avail('C', m=m) for m in (base, cipher(KeyType=1), xof(MachinePolicy=1), sig(MachinePolicy=0),
                                     cipher(SCProtection=6))],
        [a.avail('C', m=m) for m in (cipher(MachineExtension=2), cipher(KeyType=2), cipher(SCProtection=3),
                                     cipher(MachinePolicy=0), xof(MachinePolicy=3),
                                     md(Machine=M_ABSENT, MachinePolicy=1))],
        a.avail(k=0)), ([1] * 5, [0] * 6, 0))
    eq('kl.avail examines no other field; Form B uses [63:0]',
       (a.avail('C', m=cipher(State=63, res=3 << 116, Locality=loc(boot=3), Version=2)), a.avail('B', lo=pack(base))),
       (1, 1))
    provision(a, 0, base)
    a.setst(0, EXPIRED)
    a.mgmt(1, PROV, cipher(KeyType=2))
    eq('Error-State locker: kl.avail Form A uses its fields; kl.size 16 (SGR11)',
       (a.avail(k=0), a.avail(k=1), a.size(k=0), a.size(k=1)), (1, 0, 16, 16))

def t_usage():
    section('_UsagePolicy_  <<KLEE-UsagePolicy>>')
    bit, bad, u = {'U': 1, 'VU': 1, 'VS': 2, 'HS': 4, 'S': 4, 'M': 8}, [], fresh()
    for up in range(32):
        for u.mode in list(bit) + ['D']:
            if u.usage_allowed(cipher(UsagePolicy=up)) != (bool(up & 16) if u.mode == 'D' else not up & bit[u.mode]):
                bad.append((up, u.mode))
    eq('enforcement matrix, 32 policies x 7 modes (Debug: bit 4 only)', bad, [])
    u = rc(UsagePolicy=1)
    u.mode = 'U'
    eq('denied mode: kl.exec, kl.setst, kl.clearads -> kl_exc_privilege_violation (SGR17)',
       [trap_of(ex, u, 0), trap_of(u.setst, 0, READY), trap_of(u.setst, 0, CLEAR_ADS), u.getst(0)],
       ['privilege_violation'] * 3 + [ToyCipher.ENCRYPT])
    eq('not usage-controlled: getmd, getst, size, avail, restrict, clone, error setst, mgmt, clear',
       [u.getmd(0)['Machine'], u.getst(0), u.size(k=0), u.avail(k=0), u.restrict(0, md(UsagePolicy=2), 'h'),
        u.getmd(0)['UsagePolicy'], u.clone(1, 0), u.setst(1, EXPIRED), export(u, 0)[:16] == mdh_bytes(u.getmd(0)),
        u.getst(0), u.setst(0, 0)],
       [M_CIPHER, ToyCipher.ENCRYPT, 80, 1, 'ok', 3, 'cloned', 'error state', True, ToyCipher.ENCRYPT, 'cleared'])

def t_restrict():
    section('kl.restrict*  <<KLEE-instruction-restrict>>')
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
        (cipher(UsagePolicy=1), md(UsagePolicy=0b10100), 'v', 0, {}, 'ok', 'UsagePolicy', 0b101),
        (cipher(UsagePolicy=16), md(UsagePolicy=16), 'v', 0, {}, 'ok', 'UsagePolicy', 0),
        (cipher(ExpirationDate=1000), md(ExpirationDate=900), 'v', 0, {}, 'ok', 'ExpirationDate', 900),
        (cipher(ExpirationDate=1000), md(ExpirationDate=2000), 'v', 0, {}, 'invalid', 'State', INVALID),
        (cipher(), md(ExpirationDate=5), 'v', 0, {}, 'ok', 'ExpirationDate', 5),
        (cipher(), md(ExpirationDate=5), 'v', 0, {'zklexpire': False}, 'invalid', 'State', INVALID),
        (cipher(SCProtection=2), md(SCProtection=1), 'v', 0, {}, 'invalid', 'AuxDataLen', 0),
        (cipher(SCProtection=1), md(SCProtection=1), 'v', 0, {}, 'ok', 'SCProtection', 1),
        (cipher(), md(SCProtection=3), 'v', 0, {}, 'invalid', 'State', INVALID),
        (cipher(), md(SCProtection=6), 'v', 0, {}, 'invalid', 'State', INVALID),
        (cipher(Locality=loc(hw1=2)), md(SCProtection=6), 'v', 0, {}, 'ok', 'SCProtection', 6),
        (cipher(), md(MachinePolicy=1), 'v', 0, {}, 'ok', 'MachinePolicy', 1),
        (cipher(MachinePolicy=1), md(MachinePolicy=3), 'v', 0, {}, 'invalid', 'State', INVALID),
        (xof(MachinePolicy=1), md(MachinePolicy=1), 'v', 0, {}, 'invalid', 'State', INVALID),
        (cipher(), md(MachinePolicy=2), 'v', 1, {}, 'invalid', 'State', INVALID),
        (cipher(), md(MachinePolicy=1), 'v', 1, {}, 'ok', 'State', ToyCipher.ENCRYPT),
        (sig(MachinePolicy=0), md(MachinePolicy=1), 'v', 0, {}, 'invalid', 'State', INVALID),
        (sig(), md(AuxInfo=1), 'h', 0, {}, 'invalid', 'State', INVALID),
        (sig(), md(MachineUse=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), md(Machine=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), md(State=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), md(AuxDataLen=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), md(Version=1), 'l', 0, {}, 'invalid', 'State', INVALID),
        (sig(), md(KeyType=1), 'v', 0, {}, 'invalid', 'State', INVALID),
        (sig(), md(AuxInfo=1), 'l', 0, {}, 'ok', 'AuxInfo', 0),
        (sig(), md(MachineUse=1), 'h', 0, {}, 'ok', 'MachineUse', 0),
        (cipher(), md(SCProtection=1, UsagePolicy=1), 'l', 0, {}, 'ok', 'UsagePolicy', 0),
        (cipher(), md(SCProtection=1, UsagePolicy=1), 'h', 0, {}, 'ok', 'SCProtection', 0),
        (cipher(SCProtection=2), md(SCProtection=1, UsagePolicy=1), 'v', 0, {}, 'invalid', 'UsagePolicy', 0),
    ]
    got = [(r, m[f]) for pi, req, wh, enc, kw, _, f, _ in rows for r, m, _ in [run(pi, req, wh, enc, **kw)]]
    eq(f'per-field rules, unnamed fields, halves, atomicity ({len(rows)} cases)', got, [(r, v) for *_, r, f, v in rows])
    r, m, u = run(cipher(SCProtection=1), md(SCProtection=2))
    eq('raising SCProtection allocates KLF capacity', (r, u.lockers[0].alloc),
       ('ok', MACHINES[M_CIPHER].clf_capacity(cipher(SCProtection=2))))
    u = pv(fresh(clf_total=MACHINES[M_CIPHER].clf_capacity(cipher()) + 10), 0, cipher())
    before = u.getmd(0)
    eq('no capacity for the raise: kl_exc_out_of_memory, nothing applied; invalidity checked first',
       (trap_of(u.restrict, 0, md(SCProtection=2, UsagePolicy=1)), u.getmd(0) == before,
        u.restrict(0, md(SCProtection=2, ExpirationDate=5, UsagePolicy=1, MachinePolicy=3, Locality=loc(boot=3))),
        u.getst(0)), ('out_of_memory', True, 'invalid', INVALID))
    cases = [(loc(hw1=1), loc(hw1=2), loc(hw1=2)), (loc(hw1=1), loc(hw1=3), loc(hw1=3)),
             (loc(hw1=2), loc(hw1=3), loc(hw1=3)), (loc(hw1=3), loc(hw1=2), None), (loc(hw2=1), loc(hw2=3), loc(hw2=3)),
             (loc(hw2=3), loc(hw2=1), None), (0, loc(hw1=1), loc(hw1=1)), (loc(boot=1), loc(boot=2), None),
             (loc(boot=1), loc(boot=1), loc(boot=1)), (0, loc(boot=2), loc(boot=2)), (0, loc(boot=3), None),
             (0, loc(mloc=1, hloc=1, sloc=1), loc(mloc=1, hloc=1, sloc=1)),
             (loc(sloc=1), loc(sloc=1, hw2=2), loc(sloc=1, hw2=2)), (loc(hw1=1, hw2=3), loc(hw1=2, hw2=1), None)]
    u = pv(fresh(), 0, cipher())
    u.slocality = 0
    eq('Locality: fill zero subfields, HW Binding only stricter, others fixed; unconfigured entry invalid',
       [(lambda r, m, _: m['Locality'] if r == 'ok' else m['State'])(*run(cipher(Locality=c), md(Locality=q), 'h'))
        for c, q, _ in cases] + [u.restrict(0, md(Locality=loc(sloc=1)), 'h')],
       [w if w is not None else INVALID for _, _, w in cases] + ['invalid'])
    r, m, _ = run(cipher(), md(SCProtection=2, UsagePolicy=1, Locality=loc(hw1=1), ExpirationDate=9, MachinePolicy=1))
    eq('kl.restrictv applies both halves; needs VL*SEW >= 128 (GR6)',
       (r, [m[f] for f in ('SCProtection', 'UsagePolicy', 'Locality', 'ExpirationDate', 'MachinePolicy', 'State')],
        trap_of(fresh().restrict, 0, 0, 'v', vec_bits=96)), ('ok', [2, 1, loc(hw1=1), 9, 1, READY], 'illegal/1'))
    u = fresh()
    r0 = (u.restrict(0, md(UsagePolicy=1)), u.getst(0))
    u.mgmt(0, PROV, cipher())
    eq('Unconfigured: no operation; Configuration State: kl_exc_privilege_violation (SGR18)',
       (r0, trap_of(u.restrict, 0, md(UsagePolicy=1))), (('noop', 0), 'privilege_violation'))
    u = pv(fresh(), 0, cipher(ExpirationDate=10))
    u.setst(0, EXPIRED)
    eq('Error State: narrows, SCProtection allocates nothing, widening is a no-op keeping the Error State (A23)',
       [u.restrict(0, md(UsagePolicy=8, ExpirationDate=9)), u.getmd(0)['UsagePolicy'], u.getmd(0)['ExpirationDate'],
        u.getst(0), u.restrict(0, md(SCProtection=2)), u.lockers[0].alloc, u.restrict(0, md(ExpirationDate=99)),
        u.getst(0)], ['ok', 8, 9, EXPIRED, 'ok', 0, 'noop', EXPIRED])
    u = pv(fresh(clock=5000), 0, cipher(ExpirationDate=10))
    eq('kl.restrict* is not an ExpirationDate evaluation point', (u.restrict(0, md(ExpirationDate=9)), u.getst(0)),
       ('ok', READY))

def t_localities():
    section('Localities  <<KLEE-Localities>>, <<KLEE-system-keys>>')
    eq('LST index of each subfield value; at most six active',
       ([loc_entries(v) for v in (loc(hw1=1), loc(hw1=2), loc(hw1=3), loc(hw2=1), loc(hw2=2), loc(hw2=3),
                                  loc(boot=1), loc(boot=2), loc(mloc=1), loc(hloc=1), loc(sloc=1))],
        max(len(loc_entries(v)) for v in range(512))), ([[j] for j in range(11)], 6))
    u = fresh(hw_missing=(0, 3))
    eq('chain substitution SiP->ChipFam->Chip, OEM->Prod->Dev, none for Chip; never dropped',
       [fresh(hw_missing=(0,)).lst_eff(0), fresh(hw_missing=(0, 1)).lst_eff(0), fresh(hw_missing=(3, 4)).lst_eff(3),
        fresh(hw_missing=(2,)).locality_problem(loc(hw1=3)), u.sealing_ad(cipher(Locality=loc(hw1=1, hw2=1)))[1:]],
       [_secret(b'hw', 1), _secret(b'hw', 2), _secret(b'hw', 5), 'unconfigured LST entry 2', [u.hw[1], u.hw[4]]])
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
    u = pv(fresh(), 0, cipher(KeyType=1, UsagePolicy=0b10001, Locality=loc(hw1=1, mloc=1)), v2b(SKID_A, 16))
    m, img, v = u.getmd(0), export(u, 0), fresh()
    eq('SKID resolution narrows UsagePolicy and Locality, keeps KeyType 1 and the SKID; re-resolved at import',
       (m['UsagePolicy'], m['Locality'], m['KeyType'], u.lockers[0].c1, len(img), import_(v, 1, img), v.getmd(1)),
       (0b00101, loc(hw1=2, mloc=1), 1, v2b(SKID_A, 16), 48, READY, m))
    eq('SKID unknown, policy not a subset, Machine not allowed, Boot conflict, union unconfigured -> Invalid',
       [provision(fresh(slocality=0), 0, pi, v2b(skid, 16))
        for skid, pi in ((0x99, cipher(KeyType=1)), (SKID_B, cipher(KeyType=1)), (SKID_A, xof(KeyType=1)),
                         (SKID_C, cipher(KeyType=1, Locality=loc(boot=1))), (SKID_D, cipher(KeyType=1)))],
       [INVALID] * 5)
    eq('a subset of an allowed MachinePolicy resolves; the privilege mode is irrelevant',
       (provision(fresh(), 0, cipher(KeyType=1, MachinePolicy=1), v2b(SKID_B, 16)),
        provision(fresh(mode='U'), 0, cipher(KeyType=1), v2b(SKID_A, 16))), (READY, READY))
    w = pv(pv(fresh(), 0, cipher(KeyType=1), v2b(ONES64, 16)), 1, cipher(KeyType=1), v2b(ONES64, 16))
    eq('all-ones SKID: a key is generated at completion, KeyType becomes 0',
       (w.getmd(0)['KeyType'], len(w.lockers[0].c1), w.lockers[0].c1 != w.lockers[1].c1, w.size(k=0)),
       (0, 32, True, 64))
    src = pv(fresh(), 0, cipher(KeyType=1), v2b(SKID_A, 16))
    src.lockers[0].c1 = v2b(ONES64, 16)
    eq('an SCC whose Content1 carries the all-ones SKID -> Invalid (<<KLEE-MVR-open>>)',
       import_(fresh(), 0, export(src, 0)),
       INVALID)

def t_mgmt():
    section('kl.mgmt: provisioning, import, export  <<KLEE-locker-management>>')
    m = cipher(UsagePolicy=1, Locality=loc(hw1=2), SCProtection=1)
    content = pi_content(m)
    u = fresh(siv=1, impqual=2, siv2=3).csrs(klstart=48)
    eq('opening provisioning: State 56, MDH, klmanagedlocker, klstart 0, registers kept, PI size',
       (u.mgmt(0, PROV, m), u.getst(0), u.getmd(0)['Locality'], u.klmanagedlocker, u.klstart,
        (u.siv, u.impqual, u.siv2), u.size(k=0)), ('opened', PROV, loc(hw1=2), 0, 0, (1, 2, 3), 48))
    eq('kl.load, then Form A completion: Ready, fields zeroed, klmanagedlocker 32, ADS, Content',
       (u.load(0, Memory(content), BASE), u.klstart, u.mgmt(0, END, form='A'), u.getst(0), u.getstx(0),
        u.getmd(0)['MachineUse'], u.klmanagedlocker, u.getmd(0)['AuxDataLen'], len(u.lockers[0].c2), u.lockers[0].c1,
        u.size(k=0)), ('done', 0, 'completed', READY, 0, 0, NONE, ADS_BLOCKS, 32, content, 128))
    ref, got = (u.getmd(0), u.lockers[0].c1, u.lockers[0].c2), []
    for via, form in (('mv', 'D'), ('mvv', 'C'), ('load', 'A')):
        w = fresh()
        if form == 'A':
            w.csrs(kliobuflen=16).kliobuf[:16] = mdh_bytes(m)
            w.csrs(klstart=5)
        provision(w, 0, m, via=via, form=form)
        got.append((w.getmd(0), w.lockers[0].c1, w.lockers[0].c2))
    eq('provisioning via kl.mv, vector kl.mv (Form C), Form A (klstart ignored) agree', got, [ref] * 3)
    w, starts = opened(m=m), []
    for o in (0, 16):
        starts.append(w.klstart)
        w.mv_in(0, b2v(content[o:o + 16]))
    eq('kl.mv accumulates klstart; the completing kl.mgmt clears it',
       (starts, w.klstart, w.mgmt(0, END), w.klstart), ([0, 16], 32, 'completed', 0))
    md0 = u.getmd(0)
    u.mgmt(0, EXP)
    eq('opening export: 57, klmanagedlocker 0, klstart 0, only State changes, SIV/IMPQUAL/SIV2 written',
       (u.getst(0), u.klmanagedlocker, u.klstart, dict(u.getmd(0), State=0), bool(u.siv), u.impqual, bool(u.siv2)),
       (EXP, 0, 0, dict(md0, State=0), True, u.impqual_value(), True))
    out, n = Memory(), u.size(k=0)
    u.store(0, out, BASE)
    img = mdh_bytes(md0) + out.read(BASE, n - 16)
    eq('kl.store: SIV, IMPQUAL, SIV2 lead S; Content is ciphertext; only klstart changes',
       ([b2v(img[16 + 16 * i:32 + 16 * i]) for i in range(3)], img[64:96] != content, u.getst(0), u.klstart),
       ([u.siv, u.impqual, u.siv2], True, EXP, 0))
    eq('completion restores the locker; only ml.State is used; klmanagedlocker 32',
       (u.mgmt(0, END, dict(md0, UsagePolicy=0, Locality=0)), u.getmd(0), u.lockers[0].c1, u.klmanagedlocker),
       ('completed', md0, content, NONE))
    v = fresh(siv=7, impqual=7, siv2=7)
    eq('kl.size Form B is the image length; opening an import leaves the registers unchanged, State 58',
       (v.size('B', lo=b2v(img[:8])), v.mgmt(1, IMP, unpack(b2v(img[:16]))), v.siv, v.impqual, v.siv2, v.getst(1),
        v.klmanagedlocker), (len(img), 'opened', 7, 7, 7, IMP, 1))
    v.load(1, Memory(img[16:]), BASE)
    eq('kl.load fills the registers; the import round trips MDH, Content1, ADS',
       ((v.siv, v.impqual, v.siv2), v.mgmt(1, END, md0), v.getmd(1), v.lockers[1].c1, v.lockers[1].c2),
       ((u.siv, u.impqual, u.siv2), 'completed', md0, content, u.lockers[0].c2))
    w1, w2, w3 = fresh(), fresh().csrs(kliobuflen=64, kliobuftop=16), fresh()
    eq('import via kl.mv, Form A, Form C agree; export via kl.mv agrees with kl.store',
       [(import_(w1, 2, img, via='mv'), w1.getmd(2), w1.lockers[2].c1),
        (import_(w2, 2, img, form='A'), w2.getmd(2), w2.lockers[2].c1),
        (w3.mgmt(2, IMP, md0, form='C'), import_(w3, 2, img)), export(v, 1, via='mv') == img],
       [(READY, md0, content), (READY, md0, content), ('opened', READY), True])
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
    eq('a modified Content1 byte: Authentication Failed, no exception, klmanagedlocker 32',
       (import_(v, 0, bytes(t)), v.getmd(0)['AuxDataLen'], v.klmanagedlocker), (AUTH, 0, NONE))
    v = opened(IMP, st_md)
    v.load(0, Memory(img[16:]), BASE)
    u2 = pv(fresh(), 0, cipher())
    u2.mgmt(0, EXP)
    u2.siv ^= 1
    eq('altered MDH, other ml.State, other CSK, overwritten SIV at export -> Authentication Failed',
       [import_(fresh(), 0, mdh_bytes(dict(st_md, UsagePolicy=15)) + img[16:]),
        (v.mgmt(0, END, dict(st_md, State=READY)), v.getst(0))[1], import_(fresh(csk=DEFAULT_CSK ^ 1), 0, img),
        (u2.mgmt(0, END, cipher(State=READY)), u2.getst(0))[1]], [AUTH] * 4)
    u = opened()
    eq('klmanagedlocker = 0: any kl.mgmt on another locker is illegal/2 (also before GR7)',
       [trap_of(u.mgmt, 1, PROV, cipher()), u.getst(1), trap_of(u.mgmt, 1, EXP), trap_of(u.mgmt, 1, END, md()),
        trap_of(u.mgmt, 1, PROV, form='A')], ['illegal/2', 0, 'illegal/2', 'illegal/2', 'illegal/2'])
    eq('writing 32 releases the check; the first provisioning stays open',
       (provision(u.csrs(klmanagedlocker=32), 1, cipher()), u.getst(0)), (READY, PROV))
    u = rc()
    b0 = snapshot(u)
    r1 = (trap_of(u.mgmt, 0, PROV, form='A'), snapshot(u) == b0)
    b0 = snapshot(u.csrs(kliobuflen=64, kliobuftop=15))
    eq('Form A opening: unconfigured KLIOBUF, kliobuftop < 16 raise before any change',
       (r1, (trap_of(u.mgmt, 0, IMP, form='A'), snapshot(u) == b0)),
       (('unconfigured_buffer', True), ('illegal/2', True)))
    w, w2 = opened(IMP, cipher(State=1), zklio=False), opened()
    eq('Form A completion needing ml without Zklio illegal/2; export opening, PI completion need no KLIOBUF',
       (trap_of(w.mgmt, 0, END, form='A'), w2.mgmt(0, END, form='A'), w2.mgmt(0, EXP, form='A')),
       ('illegal/2', 'completed', 'opened'))
    w = opened(IMP, cipher(State=1)).csrs(klstart=16)
    u = rc().csrs(klstart=16)
    r = [trap_of(u.mgmt, 0, PROV, cipher(), form='B'), u.klstart]
    u.csrs(klmanagedlocker=3)
    n = fresh(csk=0)
    n.klstart = 16
    r += [trap_of(u.mgmt, 0, EXP), u.klstart, trap_of(n.mgmt, 0, EXP), n.klstart]
    u.csrs(klmanagedlocker=32)
    r += [trap_of(u.mgmt, 0, END), u.klstart]
    eq('A26: a first-group rejection (Form B), the klmanagedlocker check and kl_exc_no_csk keep klstart; a later '
       'rejection (end on a Valid State) clears it', r,
       ['illegal/1', 16, 'illegal/2', 16, 'no_csk', 16, 'illegal/2', 0])
    eq('an exception inside a management operation keeps State and klmanagedlocker, clears klstart',
       (trap_of(w.mgmt, 0, END, form='A'), w.getst(0), w.klmanagedlocker, w.klstart),
       ('unconfigured_buffer', IMP, 0, 0))
    eq('Form B reserved; Form C GR6; end on a Complete State illegal/2',
       [trap_of(w.mgmt, 0, PROV, cipher(), form='B'), trap_of(w.mgmt, 0, PROV, cipher(), form='C', vec_bits=64),
        trap_of(rc().mgmt, 0, END, md(State=1))], ['illegal/1'] * 2 + ['illegal/2'])
    v = fresh().csrs(klstart=16, klmanagedlocker=0)
    v.siv, v.impqual, v.siv2 = 1, 2, 3
    eq('SGR24: opening an export on an Unconfigured locker is a no-op: authentication registers kept, common '
       'steps only', (v.mgmt(0, EXP), v.getst(0), v.klmanagedlocker, v.klstart, (v.siv, v.impqual, v.siv2),
                      trap_of(fresh().csrs(klmanagedlocker=3).mgmt, 0, EXP)),
       ('noop', UNCONF, 32, 0, (1, 2, 3), 'illegal/2'))
    v = fresh().csrs(klstart=16, klmanagedlocker=0)
    eq('SGR24: end on an Unconfigured locker is a no-op: ml unread (Form A, no KLIOBUF), common steps only',
       (v.mgmt(0, END, form='A'), v.getst(0), v.klmanagedlocker, v.klstart,
        trap_of(fresh().csrs(klmanagedlocker=3).mgmt, 0, END)), ('noop', UNCONF, 32, 0, 'illegal/2'))
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
    eq('an opening zeroizes even a Valid locker (GR5), the one change a raising kl.mgmt keeps',
       (trap_of(u.mgmt, 0, PROV, md(Machine=M_ABSENT)), u.getst(0), u.clf_free() == u.clf_total),
       ('unsupported', 0, True))
    rows = []
    for f in (lambda w: w.setst(0, 0), lambda w: w.setst(0, INVALID), lambda w: w.clone(0, 1),
              lambda w: trap_of(w.mgmt, 0, PROV, md(Machine=M_ABSENT)), lambda w: w.setst(0, READY)):
        w = rc(1, rc()).csrs(klmanagedlocker=0)
        rows.append((f(w), w.klmanagedlocker))
    eq('klmanagedlocker names a Valid locker: cleared, Error State, clone destination, raising opening -> 32',
       rows, [('cleared', NONE), ('error state', NONE), ('cloned', NONE), ('unsupported', NONE), ('ok', 0)])

def t_nested():
    section('Nested management and PCCCs  <<KLEE-nested-state-base-types>>, <<KLEE-data-formats>>')
    table = {st: [s for s in range(64) if trap_of(white_box(st, bytearray(32) if BASE_TYPE[st] == 'pi' else None).mgmt,
                                                  0, END, md(State=s)) is None] for st in (EXP, IMP, PPI_EXP, PPI_IMP)}
    scc_ok = sorted(set(COMPLETE) | {57, 58})
    eq('completion base-type rule: scc takes Complete, 57, 58; pi takes 56, 59, 60', table,
       {EXP: scc_ok, IMP: scc_ok, PPI_EXP: [56, 59, 60], PPI_IMP: [56, 59, 60]})
    m = cipher(Locality=loc(hw2=2))
    content = pi_content(m, 0x51)
    u, mem = opened(m=m, k=4), Memory(content)
    u.load(4, mem, BASE, halt_after=16)
    saved, k0 = u.getmd(4), u.klstart
    eq('provisioning halted at 16; nested export opens 59, keeps klmanagedlocker; PI size',
       (k0, u.mgmt(4, EXP), u.getst(4), u.klmanagedlocker, u.klstart, u.size(k=4)), (16, 'opened', PPI_EXP, 4, 0, 48))
    pccc = export_pccc(u, 4, saved)
    eq('PI-shaped PCCC verbatim, unloaded bytes zero; nested completion restores 56',
       (pccc[16:], u.getst(4), u.klmanagedlocker), (content[:16] + bytes(16), PROV, 4))
    u.mgmt(4, EXP)
    inner = u.getmd(4)
    r = [u.mgmt(4, EXP), u.getst(4), u.mgmt(4, END, inner), u.getst(4), u.mgmt(4, END, saved), u.getst(4),
         u.mgmt(4, EXP), trap_of(u.mgmt, 4, END, dict(saved, State=READY)), u.mgmt(4, END, saved), u.setst(4, 0),
         u.klmanagedlocker, u.mgmt(4, IMP, saved), u.getst(4), u.klmanagedlocker, u.load(4, Memory(pccc[16:]), BASE),
         u.mgmt(4, END, saved), u.getst(4), u.csrs(klstart=k0).load(4, mem, BASE), u.mgmt(4, END), u.lockers[4].c1]
    eq('double nesting stays 59; Complete ml illegal on pi; PCCC re-import 60 -> 56; resumption completes', r,
       ['opened', PPI_EXP, 'completed', PPI_EXP, 'completed', PROV, 'opened', 'illegal/2', 'completed', 'cleared',
        NONE, 'opened', PPI_IMP, 4, 'done', 'completed', PROV, 'done', 'completed', content])
    u = opened(m=cipher(KeyType=1))
    u.mv_in(0, ONES64)
    s0 = u.getmd(0)
    u.mgmt(0, EXP)
    pv_ = [u.mv_out(0) for _ in range(u.size(k=0) // 16 - 1)]
    u.mgmt(0, END, s0)
    u.mgmt(0, END)
    eq('all-ones SKID: the PCCC carries only the SKID; the key comes from the completing kl.mgmt',
       (pv_, u.getmd(0)['KeyType'], len(u.lockers[0].c1)), ([ONES64], 0, 32))
    u = fresh()
    src, ml, mem, scc = interrupted_import(u, 2, 64)
    regs, s1, ks = (u.siv, u.impqual, u.siv2), u.getmd(2), u.klstart
    eq('import halted after SIV, IMPQUAL, SIV2, a block; nested export opens 57 without sealing',
       (ks, regs, u.mgmt(2, EXP), u.getst(2), (u.siv, u.impqual, u.siv2)),
       (64, (src.siv, src.impqual, src.siv2), 'opened', EXP, regs))
    pc = export_pccc(u, 2, s1)
    eq('SCC-shaped PCCC: registers, loaded ciphertext, zeros; nested completion returns to 58',
       (pc[16:], u.getst(2), u.klmanagedlocker), (scc[16:80] + bytes(len(scc) - 80), IMP, 2))
    export(rc(9, u.csrs(klmanagedlocker=32)), 9)
    r = [u.siv != regs[0], u.setst(2, 0), u.mgmt(2, IMP, s1), u.getst(2), u.load(2, Memory(pc[16:]), BASE),
         u.mgmt(2, END, s1), u.getst(2), (u.siv, u.impqual, u.siv2), u.klmanagedlocker,
         u.csrs(klstart=ks).load(2, mem, BASE), u.mgmt(2, END, ml), u.getmd(2), u.lockers[2].c1, u.lockers[2].c2]
    eq('registers overwritten elsewhere; PCCC re-import restores 58 and them; the import completes', r,
       [True, 'cleared', 'opened', IMP, 'done', 'completed', IMP, regs, 2, 'done', 'completed', src.getmd(0),
        src.lockers[0].c1, src.lockers[0].c2])
    for tamper in (False, True):
        u = pv(fresh(), 1, sig(AuxInfo=3))
        base_md, out = u.getmd(1), Memory()
        u.mgmt(1, EXP)
        u.store(1, out, BASE, halt_after=32)
        ks, s2 = u.klstart, u.getmd(1)
        u.mgmt(1, EXP)
        st = u.getst(1)
        pc = bytearray(export_pccc(u, 1, s2))
        pc[40] ^= 0x80 * tamper
        r = [st, u.setst(1, 0), u.mgmt(1, IMP, s2), u.load(1, Memory(pc[16:]), BASE), u.mgmt(1, END, s2), u.getst(1),
             u.csrs(klstart=ks).store(1, out, BASE), u.mgmt(1, END, base_md), u.getst(1)]
        if tamper:
            eq('interrupted export via a tampered nested PCCC: detected at export completion', r,
               [EXP, 'cleared', 'opened', 'done', 'completed', EXP, 'done', 'completed', AUTH])
        else:
            img = mdh_bytes(base_md) + out.read(BASE, u.size(k=1) - 16)
            eq('interrupted export via a nested PCCC: 57 throughout; completes; its SCC imports',
               r + [u.getmd(1), len(u.lockers[1].c1), import_(fresh(), 0, img)],
               [EXP, 'cleared', 'opened', 'done', 'completed', EXP, 'done', 'completed', READY, base_md, 64, READY])


def t_error_states():
    section('Lockers in an Error State  <<KLEE-error-state-transfer>>, <<KLEE-error-state-instructions>>')
    rows, want = [], []
    for st in ERROR_STATES:
        u = pv(fresh(), 0, cipher(SCProtection=1, ExpirationDate=77, UsagePolicy=2))
        u.setst(0, ToyCipher.ENCRYPT, 5)
        r = u.csrs(klstart=32).setst(0, st)
        m, img, v = u.getmd(0), export(u, 0), fresh(siv=5).csrs(klstart=48)
        rows.append((r, m['State'], u.lockers[0].c1, m['AuxDataLen'], m['ExpirationDate'], m['StateExtension'],
                     u.lockers[0].alloc, u.klstart, u.size(k=0), img == mdh_bytes(m), v.mgmt(3, IMP, unpack(b2v(img))),
                     v.getmd(3) == m, v.klstart, v.klmanagedlocker, v.siv, v.mgmt(3, END, m)))
        want.append(('error state', INVALID if st > 53 else st, b'', 0, 77, 1, 0, 32, 16, True, 'short import', True,
                     0, 32, 5, 'noop'))
    eq('kl.setst #48-#55 then export and short import (8 States, 16 properties each; end is then a no-op)', rows, want)
    u = fresh()
    eq('short import: 54, 55 -> Invalid; ADS fields zeroed; no capacity; kl.setst #49 on Unconfigured no-op',
       [(u.mgmt(k, IMP, cipher(State=s)), u.getst(k)) for k, s in ((0, 54), (1, 55))]
       + [(u.mgmt(2, IMP, cipher(State=EXPIRED, AuxDataLen=4, ADSDropped=1)), u.getmd(2)['AuxDataLen'],
           u.getmd(2)['ADSDropped'], u.lockers[2].alloc), (u.setst(3, INVALID), u.getst(3))],
       [('short import', INVALID)] * 2 + [('short import', 0, 0, 0), ('noop', 0)])
    u = pv(fresh(), 0, cipher())
    u.setst(0, EXPIRED)
    provision(u, 1, cipher())
    before, vo = u.getmd(0), bytearray(b'\xAA' * 16)
    eq('export opening: unchanged, nothing opened, klstart 0; kl.load/store/mv and end no-ops (SGR24)',
       [u.csrs(klstart=16).mgmt(0, EXP), u.getmd(0) == before, u.klmanagedlocker, u.klstart,
        u.load(0, Memory(), BASE), u.store(0, Memory(), BASE), u.mv_in(0, 1), u.mv_out(0), u.mgmt(0, END),
        u.getst(0)], ['unchanged', True, 32, 0, 'noop', 'noop', 'noop', 0, 'noop', EXPIRED])
    eq('use is a no-op with output zeroed; kl.restrict* narrows; Error-State kl.setst changes it',
       [u.exec_(0, 'A', vin=bytearray(16), vout=vo), bytes(vo), u.setst(0, READY), u.setst(0, CLEAR_ADS),
        u.restrict(0, md(UsagePolicy=8)), u.setst(0, READY), u.getst(0), u.setst(0, UNSUP), u.getst(0)],
       ['noop', bytes(16), 'noop', 'noop', 'ok', 'noop', EXPIRED, 'error state', UNSUP])
    eq('kl.clone from it copies the MDH; onto it replaces; provisioning reconfigures; kl.clear clears',
       [u.clone(5, 0), u.getmd(5) == u.getmd(0), u.lockers[5].c1, u.lockers[5].alloc, u.clone(5, 1), u.getst(5),
        provision(u, 0, cipher()), u.setst(0, INVALID), u.setst(0, 0), u.getst(0)],
       ['cloned', True, b'', 0, 'cloned', READY, READY, 'error state', 'cleared', 0])

def t_ads():
    section('ADS, IMPQUAL, _ADSDropped_  <<KLEE-SCC-import>>, <<KLEE-Auxiliary-Data-Section>>')
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
    v.load(0, Memory(t[16:]), BASE)
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
       (big.getmd(0)['ADSDropped'], big.load(0, mem, BASE), mem.accesses, big.mgmt(0, END, bm), big.getst(0),
        big.lockers[0].c1, big.getmd(0)['ADSDropped']),
       (1, 'done', (48 + c1) // 16, 'completed', ToyCipher.ENCRYPT, u.lockers[0].c1, 0))
    w = rc(SCProtection=1)
    eq('kl.clearads in _Encrypt_ (SGR23): ADS fields 0, State kept, ADS-free SCC; the next use regenerates the ADS',
       (w.setst(0, CLEAR_ADS), w.getmd(0)['AuxDataLen'], w.lockers[0].c2, w.getst(0), len(export(w, 0)), ex(w, 0),
        w.getmd(0)['AuxDataLen']), ('ads cleared', 0, b'', ToyCipher.ENCRYPT, 32 + c1, 'done', ADS_BLOCKS))

def t_transfers():
    section('kl.load, kl.store, kl.mv  <<KLEE-instruction-load>>, <<KLEE-instruction-mv>>, <<KLEE-Memory-Alignment>>')
    eq('kl.mv into a locker only in 56, 58, 60 (SGR21), out of one only in 57, 59 (SGR22); no trap in 0, 48-55 '
       '(SGR24)',
       ([s for s in range(64) if trap_of(white_box(s).mv_in, 0, 1) is None],
        [s for s in range(64) if trap_of(white_box(s).mv_out, 0) is None]),
       ([0, *range(48, 56), 56, 58, 60], [0, *range(48, 56), 57, 59]))
    u, v = opened(), rc()
    r = [trap_of(u.store, 0, Memory(), BASE), u.mgmt(0, EXP), trap_of(u.load, 0, Memory(), BASE), v.mgmt(0, EXP),
         trap_of(v.csrs(klmanagedlocker=32).store, 0, Memory(), BASE), trap_of(v.mv_out, 0),
         v.csrs(klmanagedlocker=0).store(0, Memory(), BASE)]
    for k, imm, ml in ((1, IMP, cipher(State=1)), (2, PROV, cipher())):
        v.csrs(klmanagedlocker=32).mgmt(k, imm, ml)
    v.csrs(klmanagedlocker=32)
    eq("kl.store in 56, kl.load in 57 illegal; in 57/58 only klmanagedlocker's locker, not in 56",
       r + [trap_of(v.mv_in, 1, 1), v.mv_in(2, 1)],
       ['illegal/2', 'opened', 'illegal/2', 'opened', 'illegal/2', 'illegal/2', 'done', 'illegal/2', 'moved'])
    u = opened().csrs(klstart=8)
    eq('klstart not a multiple of 16; no Zklmv; an emulated kl.load',
       [trap_of(u.load, 0, Memory(), BASE), trap_of(u.mv_in, 0, 1),
        trap_of(fresh(zklmv=False).mv_in, 0, 1), trap_of(fresh(zklmem_hw=False).load, 0, Memory(), BASE)],
       ['illegal/2'] * 2 + ['illegal/1'] * 2)
    mem, vec, vo = Memory(), bytearray(b'\xAA' * 16), bytearray(b'\xAA' * 16)
    r = [u.mv_in(5, 1), u.mv_out(5), u.csrs(vstart=0).mv_vec(5, vec), u.mv_vec(5, vo, out=True), bytes(vo), u.klstart,
         u.load(5, mem, BASE), u.klstart, u.csrs(klstart=8).store(5, mem, BASE), u.klstart, mem.accesses,
         trap_of(u.load, 5, mem, BASE + 1), trap_of(u.store, 5, mem, BASE + 1), u.klmanagedlocker, u.getst(5)]
    eq('SGR24, Unconfigured locker: kl.mv a no-op, zeros read, klstart (8) kept; kl.load, kl.store an empty '
       'window: no access, klstart 0, misalignment still raised; klmanagedlocker kept', r,
       ['noop', 0, 'noop', 'noop', bytes(16), 8, 'noop', 0, 'noop', 0, 0, 'load_misaligned', 'store_misaligned', 0,
        UNCONF])
    for at in ('opened', 'loaded'):                                 # the check-then-use race
        u = opened()
        if at == 'loaded':
            u.mv_in(0, 1)
        u.clear(0)                                                  # a handler clears instead of saving
        r = [u.klmanagedlocker, u.mv_in(0, 2), u.load(0, Memory(), BASE), u.mgmt(0, END), u.getst(0),
             provision(u, 0, cipher())]
        eq(f'SGR24: locker cleared after the check ({at}): the next kl.mv, kl.load, end are no-ops; restart '
           'provisions', r, [32, 'noop', 'noop', 'noop', UNCONF, READY])
    pc = pi_content(cipher())
    u, mem = opened(), Memory(pc)
    img = lambda w: bytes(w.lockers[0].img)
    r = [trap_of(u.load, 0, mem, BASE + 4), img(u), trap_of(u.csrs(klstart=32).load, 0, mem, BASE + 8),
         u.load(0, mem, BASE), img(u), u.klstart]
    eq('misaligned kl.load: nothing moved, also with an empty window; klstart >= image_end retires', r,
       ['load_misaligned', bytes(32), 'load_misaligned', 'done', bytes(32), 0])
    mem.unmapped.append((BASE + 16, BASE + 32))
    r = [trap_of(u.load, 0, mem, BASE, tval=True), u.klstart, img(u)[:16] == pc[:16], trap_of(u.load, 0, mem, BASE),
         u.klstart]
    mem.unmapped.clear()
    eq('page fault: precise halt, xtval; re-execution faults again; resumes once mapped',
       r + [u.load(0, mem, BASE), img(u) == pc], [('load_page_fault', BASE + 16), 16, True, 'load_page_fault', 16,
                                                  'done', True])
    u, w = opened(), opened()
    mem.nonidem.append((BASE + 20, BASE + 21))
    r = [trap_of(u.load, 0, mem, BASE, tval=True), u.klstart]
    mem.nonidem.clear()
    mem.unmapped.append((BASE + 16, BASE + 32))
    r += [trap_of(w.load, 0, mem, BASE, restart=True), w.klstart]
    mem.unmapped.clear()
    w = opened()
    eq('MMR3: access fault at the byte, prefix committed; restart option for interrupts only (IRR3)',
       r + [w.load(0, mem, BASE, halt_after=16, restart=True), w.klstart, w.load(0, mem, BASE), img(w) == pc],
       [('load_access_fault', BASE + 20), 16, 'load_page_fault', 16, 'halted', 0, 'done', True])
    u, out, ref = rc(), Memory(), Memory()
    u.mgmt(0, EXP)
    out.unmapped.append((BASE + 32, BASE + 48))
    r = [trap_of(u.store, 0, out, BASE + 2), trap_of(u.store, 0, out, BASE), u.klstart]
    out.unmapped.clear()
    u.store(0, out, BASE)
    u.store(0, ref, BASE)
    eq('kl.store: misaligned; fault halts at 32; resumption writes the same image; empty window retires',
       r + [out.read(BASE, 64) == ref.read(BASE, 64), u.csrs(klstart=128).store(0, out, BASE), u.klstart],
       ['store_misaligned', 'store_page_fault', 32, True, 'done', 0])
    u = opened()
    r = [u.mv_in(0, 1), u.mv_in(0, 2), u.mv_in(0, 3), u.klstart, u.mgmt(0, END), u.mgmt(0, EXP)]
    vals = [u.mv_out(0) for _ in range(4)]
    eq('kl.mv past image_end writes nothing, reads zero, klstart stays; SIV is read first',
       r + [vals[0] == u.siv, vals[3], u.klstart], ['moved', 'moved', 'nothing', 32, 'completed', 'opened', True, 0,
                                                    48])
    vd, vd2, vd3 = bytearray(b'\xEE' * 64), bytearray(b'\xEE' * 32), bytearray(b'\xEE' * 32)
    r = [u.csrs(klstart=32).mv_vec(0, vd, out=True), vd[:16] == v2b(vals[2], 16), bytes(vd[16:]), u.klstart, u.vstart,
         u.csrs(klstart=48).mv_vec(0, vd2, out=True), bytes(vd2), u.klstart]
    u.csrs(klstart=0).vstart = 4
    r += [u.mv_vec(0, vd3, sew=64, out=True), bytes(vd3), u.klstart]
    u.vstart = 1
    r += [trap_of(u.mv_vec, 0, bytearray(32), out=True)]
    u.vstart = 0
    r += [trap_of(u.mv_vec, 0, bytearray(24), out=True), trap_of(fresh(zklv=False).mv_vec, 0, bytearray(16))]
    eq('vector kl.mv across image_end, from beyond it, vstart >= vl, 16-byte multiples, Zklv', r,
       ['moved', True, bytes(48), 48, 0, 'zeros', bytes(32), 48, 'noop', b'\xEE' * 32, 0] + ['illegal/1'] * 3)
    content, imgs = pi_content(xof(), 0x10), []
    for sew in (8, 16, 32, 64):
        w = opened(m=xof())
        w.mv_vec(0, bytearray(content), sew=sew, halt_after=16)
        h = (w.klstart, w.vstart)
        imgs.append((h, w.mv_vec(0, bytearray(content), sew=sew), img(w), w.klstart, w.vstart))
    eq('interrupted vector kl.mv: klstart in bytes, vstart in elements; same image for every SEW', imgs,
       [((16, 16 // (s // 8)), 'moved', content, 32, 0) for s in (8, 16, 32, 64)])
    w, mem = opened(m=xof()), Memory(v2b(0xEF, 16) + v2b(0xCD, 16))
    w.mv_in(0, 0xAB)
    eq('kl.mv and kl.load combined: each byte holds the value last written',
       (w.csrs(klstart=16).load(0, mem, BASE), img(w), w.mv_in(0, 0x77), img(w)[:16]),
       ('done', v2b(0xAB, 16) + v2b(0xCD, 16), 'moved', v2b(0x77, 16)))

def t_kliobuf():
    section('KLIOBUF  <<KLEE-CSR-kliobuflen>>, <<KLEE-CSR-kliobuftop>>, <<KLEE-iobuf-transfer-window>>')
    u, n = fresh(maxiobuflen=128), fresh(zklio=False)
    r = [[u.csr_read(c) for c in ('kliobuflen', 'kliobuftop', 'klstart', 'klmanagedlocker')],
         trap_of(u.input_, Memory(), BASE, 16), u.csrs(kliobuflen=64).kliobuftop]
    u.kliobuf[:4] = b'\xFF' * 4
    r += [bytes(u.csrs(kliobuftop=20, kliobuflen=64).kliobuf), u.kliobuftop,
          u.csrs(kliobuflen=1000, kliobuftop=1000).kliobuflen, u.kliobuftop]
    u.kliobuf[:4] = b'\1\2\3\4'
    eq('reset values, GR7, kliobuflen write zeroes and sets top, WARL, top keeps data, no Zklio',
       r + [bytes(u.csrs(kliobuftop=40).kliobuf[:4]), n.csr_read('klmaxiobuflen'), trap_of(n.csr_read, 'kliobuflen'),
            trap_of(n.csr_write, 'kliobuftop', 1), trap_of(n.input_, Memory(), BASE, 16),
            trap_of(u.csr_write, 'klmaxiobuflen', 5)],
       [[0, 0, 0, 32], 'unconfigured_buffer', 64, bytes(64), 64, 128, 128, b'\1\2\3\4', 0] + ['illegal/1'] * 4)
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
    section('State Management rules  <<KLEE-State-management>>')
    u = pv(fresh(), 0, cipher())
    tag = MACHINES[M_CIPHER].verify_tag(u, u.lockers[0])
    eq('SGR1: a new CC is Ready; SGR9: VERIFY lands in Success or Failure',
       [u.getst(0)] + [(u.setst(0, ToyCipher.VERIFY, t), u.getst(0), u.setst(0, READY))[1] for t in (tag, tag ^ 1)],
       [READY, SUCCESS, FAILURE])
    u, x, out = pv(fresh(), 0, cipher()), pv(fresh(), 0, xof()), bytearray(b'\x55' * 16)
    eq('SGR2: kl.exec in Ready -> Invalid, output zeroed, klstart 0; unless the Machine allows it',
       (u.exec_(0, 'A', vin=bytearray(16), vout=out), u.getst(0), bytes(out), u.klstart,
        x.exec_(0, 'B', vin=bytearray(b'abc')), x.getst(0)), ('invalid', INVALID, bytes(16), 0, 'done', ToyXof.ABSORB))
    u = rc()
    eq('SGR4 same-State kl.setst; SGR8 -> Ready erases state; unsupported or forbidden -> Invalid',
       (u.setst(0, ToyCipher.ENCRYPT, 3), u.getst(0), u.setst(0, READY), u.getst(0), u.getstx(0),
        [pv(fresh(), 0, cipher()).setst(0, imm) for imm in (5, 45, 65, 127)],
        pv(fresh(), 0, cipher(MachinePolicy=2)).setst(0, ToyCipher.ENCRYPT)),
       ('ok', ToyCipher.ENCRYPT, 'ok', READY, 0, ['invalid'] * 4, 'invalid'))
    for final in (SUCCESS, FAILURE):
        w = [final_cipher(final, SCProtection=1) for _ in range(7)]
        eq(f'SGR5/SGR6 in State {final}: allowed exits, Invalid otherwise, permitted instructions',
           [w[0].setst(0, READY), w[0].getst(0), w[1].setst(0, 0), w[1].getst(0), w[2].setst(0, PRIV), w[2].getst(0),
            w[3].setst(0, CLEAR_ADS), w[3].getst(0), w[3].getmd(0)['AuxDataLen'], w[4].setst(0, ToyCipher.ENCRYPT),
            w[4].getst(0), ex(w[5], 0), w[5].getst(0), import_(fresh(), 0, export(w[6], 0)), w[6].size(k=0) > 16,
            w[6].avail(k=0), w[6].getst(0), w[6].clone(1, 0), w[6].restrict(0, md(UsagePolicy=1))],
           ['ok', READY, 'cleared', 0, 'error state', PRIV, 'ads cleared', final, 0, 'invalid', INVALID, 'invalid',
            INVALID, final, True, 1, final, 'cloned', 'ok'])
    u = xof_success(fresh(), 0, b'seed')
    eq('SGR5: in Success a XOF still produces output',
       (u.getst(0), u.exec_(0, 'C', vout=bytearray(4)), u.getmd(0)['MachineUse']), (SUCCESS, 'done', 4))
    u = fresh()
    eq('SGR12: usage-controlled instructions on an Unconfigured locker are illegal/2',
       [trap_of(u.exec_, 0, 'D'), trap_of(u.setst, 0, READY), trap_of(u.setst, 0, CLEAR_ADS),
        trap_of(u.derive, 1, 0, 32)],
       ['illegal/2'] * 4)
    u, w, buf = rc(), rc(), bytearray(b'\xBB' * 32)
    u.setst(0, INVALID)
    u.csrs(kliobuflen=64).kliobuf[:] = b'\xAA' * 64
    w.setst(0, EXPIRED)
    w.vstart = 1
    eq('SGR16: Error-State kl.exec zeroes [klstart, kliobuftop) of Form D, elements vstart..vl-1 of Vd',
       (u.csrs(klstart=16).exec_(0, 'D'), bytes(u.kliobuf),
        w.csrs(klstart=16).exec_(0, 'A', vin=buf, vout=buf, sew=128),
        bytes(buf)), ('noop', b'\xAA' * 16 + bytes(48), 'noop', b'\xBB' * 16 + bytes(16)))
    info('A Form D kl.exec on an Error-State locker zeroes [klstart, kliobuftop), although whether it is a '
         'substitution depends on an operation the Error State does not define (per the purpose of SGR16).')
    u, w = opened(), opened(k=3)
    r = [trap_of(u.exec_, 0, 'D'), trap_of(u.setst, 0, READY), trap_of(u.clone, 1, 0),
         trap_of(u.restrict, 0, md(UsagePolicy=1)), provision(u.csrs(klmanagedlocker=32), 2, cipher())]
    eq('SGR18 on a Configuration-State locker; cloning onto it releases klmanagedlocker; same-index clone no-op',
       r + [u.csrs(klmanagedlocker=0).clone(0, 2), u.getst(0), u.klmanagedlocker, w.clone(3, 3), w.getst(3),
            w.clone(9, 9)],
       ['privilege_violation'] * 4 + [READY, 'cloned', READY, NONE, 'noop', PROV, 'noop'])

    def gated(**kw):
        w = rc(unit=fresh(**kw), ExpirationDate=5, UsagePolicy=8)
        w.clock = 10
        return w
    w1, w2, w3, w4, w5, w6, w7, w8 = gated(), opened(), gated(), gated(zklio=False), gated(), gated(mode='S'), rc(), \
        pv(fresh(), 0, cipher())
    w6.mode = 'S'
    w1.setst(0, INVALID)
    eq('SGR19: Error State > Configuration > forbidden substitution > UsagePolicy > expiry > KLIOBUF > Machine',
       [(ex(w1, 0), w1.getst(0)), trap_of(w2.exec_, 0, 'B', vin=bytearray(16)),
        trap_of(w3.exec_, 0, 'B', vin=bytearray(16)),
        trap_of(w4.exec_, 0, 'D'), (trap_of(ex, w5, 0), w5.getst(0)), (w6.exec_(0, 'D'), w6.getst(0)),
        (trap_of(w7.exec_, 0, 'D'), w7.getst(0)), (w8.exec_(0, 'D'), w8.getst(0))],
       [('noop', INVALID), 'privilege_violation', 'illegal/2', 'illegal/2', ('privilege_violation', ToyCipher.ENCRYPT),
        ('expired', EXPIRED), ('unconfigured_buffer', ToyCipher.ENCRYPT), ('invalid', INVALID)])
    rows = []
    for st in CONFIG:
        w, p = white_box(st, bytes(64)), opened()
        rows += [[trap_of(w.size, k=0), trap_of(w.avail, k=0), trap_of(w.getmd, 0), trap_of(w.getst, 0),
                  trap_of(w.swap, 1, 0), trap_of(w.rename, 0, 1), trap_of(w.setst, 0, EXPIRED)],
                 [trap_of(p.setst, 0, 0), trap_of(p.clearall)] + [None] * 5]
    w = opened()
    eq('SGR20: size, avail, getmd*, getst, swap, rename, Error/clear kl.setst, kl.clearall in Configuration States',
       (rows, w.setst(0, INVALID), w.klmanagedlocker), ([[None] * 7] * 10, 'error state', 32))
    w, z = rc().csrs(klstart=32, klmanagedlocker=0), fresh(zklind=True)
    r = [w.setst(0, 0, aux=5, form='B'), w.klstart, w.klmanagedlocker, w.clf_free() == w.clf_total]
    w = rc(unit=fresh(siv=3))
    w.mgmt(1, IMP, cipher(State=1))
    w.csrs(kliobuflen=64, klstart=16)
    eq('kl.clear, kl.clearall, reserved X0 forms, GR11 index range',
       r + [w.setst('X0', 0), [w.getst(k) for k in range(32)], w.kliobuflen, w.kliobuftop, bytes(w.kliobuf), w.klstart,
            w.klmanagedlocker, w.siv, w.clf_free() == w.clf_total, trap_of(w.setst, 'X0', 0, form='B'),
            trap_of(w.setst, 'X0', 1), trap_of(z.getmd, Ind(32)), trap_of(z.setst, Ind(40), 0),
            trap_of(z.getmd, Ind(0, reg=0)), z.getst(Ind(31))],
       ['cleared', 32, NONE, True, 'cleared all', [0] * 32, 0, 0, b'', 0, 32, 0, True] + ['illegal/1'] * 5 + [0])
    w = fresh()
    r = [trap_of(w.clone, 1, 0)]
    rc(unit=w, SCProtection=1)
    w.siv, w.impqual, w.siv2 = 1, 2, 3
    cl = lambda k: (w.getmd(k), w.lockers[k].c1, w.lockers[k].c2, w.lockers[k].alloc)
    r += [w.clone(1, 0), cl(1) == cl(0), (w.siv, w.impqual, w.siv2), import_(w, 2, export(w, 0)),
          cl(2)[:2] == cl(1)[:2]]
    t = rc(0, rc(1, fresh(clf_total=2 * MACHINES[M_CIPHER].clf_capacity(cipher(SCProtection=1))), SCProtection=1),
           SCProtection=1)
    r += [t.clone(1, 0), t.clf_free(), trap_of(t.clone, 2, 0), t.getst(2), t.restrict(1, md(MachinePolicy=1)),
          t.getmd(1)['MachinePolicy'], t.getmd(0)['MachinePolicy']]
    eq('kl.clone: Unconfigured source; perfect copy = export+import; capacity; clone then restrict', r,
       ['illegal/2', 'cloned', True, (1, 2, 3), ToyCipher.ENCRYPT, True, 'cloned', 0, 'out_of_memory', 0, 'ok', 1, 3])
    w = rc().csrs(klstart=16)
    w.vstart = 16
    ks = [(f(), w.klstart)[1] for f in (lambda: w.getmd(0), lambda: w.size(k=0), lambda: w.avail(k=0),
                                        lambda: w.restrict(0, md(UsagePolicy=1)), lambda: w.clone(1, 0),
                                        lambda: w.rename(2, 1), lambda: w.swap(1, 2),
                                        lambda: w.setst(0, ToyCipher.ENCRYPT, 1))]
    eq('getmd, size, avail, restrict, clone, rename, swap, setst leave klstart', ks, [16] * 8)
    w = rc()
    w.setst(0, PRIV)
    eq('kl.restrict* in an Error State: a widening request is a no-op and keeps the Error State; a narrowing applies',
       [w.restrict(0, md(MachineUse=1)), w.getst(0), w.restrict(0, md(UsagePolicy=1)), w.getst(0),
        w.getmd(0)['UsagePolicy'] & 1], ['noop', PRIV, 'ok', PRIV, 1])

def t_exec():
    section('kl.exec and klstart  <<KLEE-CSR-klstart>>, <<KLEE-resumability>>')
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
    for n, ks in ((64, 64), (64, 80), (40, 40)):
        v, b = rc(unit=fresh(vstart=ks)).csrs(klstart=ks), bytearray(pt[:n])
        rows.append((v.exec_(0, 'A', vin=b, vout=b), bytes(b), v.getst(0), v.klstart, v.vstart))
    eq('klstart >= VL*SEW/8 (64 of 64, 80 of 64): empty window, only klstart = vstart = 0; 40 of 40: invalid '
       'length first, Invalid', rows, [('empty', pt, ToyCipher.ENCRYPT, 0, 0)] * 2 + [('invalid', pt[:40], INVALID, 0, 0)])
    u, buf = rc(unit=fresh(vstart=8)).csrs(klstart=8), bytearray(pt)
    eq('input klstart = 8 (no interruption point) -> Invalid, elements vstart.. of Vd zeroed, Content cleared',
       (u.exec_(0, 'A', vin=buf, vout=buf), u.getst(0), bytes(buf), u.lockers[0].c1, u.klstart),
       ('invalid', INVALID, pt[:8] + bytes(56), b'', 0))
    u, w = rc().csrs(kliobuflen=64), rc().csrs(kliobuflen=40)
    x, y = (xof_success(fresh(), 0, b'x').csrs(kliobuflen=16) for _ in range(2))
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
    section('_ExpirationDate_  <<KLEE-Metadata-expiration-date>>')

    def eu(clock, ed=1000, **kw):
        u = rc(unit=fresh(**kw), ExpirationDate=ed, SCProtection=1)
        u.clock = clock
        return u
    u, out = eu(2000), bytearray(b'\x11' * 16)
    eq('kl.exec on an expired locker: Expired, no operation or exception, output zeroed, content cleared',
       (u.exec_(0, 'A', vin=bytearray(16), vout=out), u.getst(0), bytes(out), u.lockers[0].c1,
        u.getmd(0)['AuxDataLen'], u.getmd(0)['ExpirationDate']), ('expired', EXPIRED, bytes(16), b'', 0, 1000))
    eq('evaluation at kl.setst and kl.clearads; at the stated hour; before it; pre-epoch clock; date 0',
       [eu(2000).setst(0, READY), eu(2000).setst(0, CLEAR_ADS), eu(1000).setst(0, READY),
        eu(999).setst(0, ToyCipher.ENCRYPT, 1), eu(-50, ed=1).setst(0, READY),
        rc(unit=fresh(clock=1 << 30)).setst(0, READY)],
       ['expired', 'expired', 'expired', 'ok', 'ok', 'ok'])
    u, buf = eu(0), bytearray(64)
    u.exec_(0, 'A', vin=buf, vout=buf, halt_after=32)
    u.clock = 5000
    eq('a resumption point is an evaluation point', (u.exec_(0, 'A', vin=buf, vout=buf), u.getst(0), u.klstart),
       ('expired', EXPIRED, 0))
    u, v, w = eu(5000), fresh(clock=5000), opened(m=cipher(ExpirationDate=10), clock=5000)
    img, end = export(u, 0), (w.mgmt(0, END), w.getst(0))
    w.mgmt(1, IMP, cipher(State=2, ExpirationDate=10))
    eq('not evaluated by export, size, import, clone, restrict, clear, provisioning, or outside Valid States',
       [u.getst(0), len(img) == u.size(k=0), import_(v, 0, img), u.clone(1, 0), u.restrict(1, md(ExpirationDate=5)),
        u.getst(1), u.setst(0, 0), u.getst(0), *end, trap_of(w.exec_, 1, 'D'), w.getst(1)],
       [ToyCipher.ENCRYPT, True, ToyCipher.ENCRYPT, 'cloned', 'ok', ToyCipher.ENCRYPT, 'cleared', 0, 'completed', READY,
        'privilege_violation', IMP])
    w = eu(5000)
    w.lockers[0].mdh['UsagePolicy'] = 8
    eq('UsagePolicy precedes the expiration (SGR19)', (trap_of(w.setst, 0, READY), w.getst(0)),
       ('privilege_violation', ToyCipher.ENCRYPT))
    n, e, n2 = fresh(zklexpire=False, clock=1 << 30), pv(fresh(), 0, cipher()), rc(1, fresh(zklexpire=False))
    e.setst(0, EXPIRED)
    eq('without Zklexpire no locker gets a date; an Expired MDH imports as Invalid; reserved #53 sets Invalid',
       (n.mgmt(0, PROV, cipher(ExpirationDate=1)), rc(1, n).restrict(1, md(ExpirationDate=1)),
        import_(n2, 0, export(e, 0)), n2.setst(1, EXPIRED), n2.getst(1)),
       ('invalid', 'invalid', INVALID, 'error state', INVALID))
    u, out = rc(1, eu(0, ed=1 << 19)), bytearray(b'\x22' * 16)
    u.clock = None
    eq('an unreadable clock expires a non-zero date at the next usage-controlled instruction, not date 0',
       (u.exec_(0, 'A', vin=bytearray(16), vout=out), u.getst(0), bytes(out), u.setst(1, READY)),
       ('expired', EXPIRED, bytes(16), 'ok'))

def t_derive():
    section('kl.derive  <<KLEE-instruction-derive>>, <<KLEE-derive-endpoints>>')

    def pair(**kw):
        return pv(xof_success(fresh(**kw), 0), 1, cipher())
    expect = bytearray(32)
    xof_success(fresh(), 0).exec_(0, 'C', vout=expect)
    u, u2, u3 = pair(), pair(), pair()
    eq('XOF output into a Ready key field (DER6 key derivation), source advanced as by kl.exec; length < key -> '
       'destination Invalid',
       (u.derive(1, 0, 32), u.lockers[1].c1[:32], u.getmd(0)['MachineUse'], u.getst(1), u2.derive(1, 0, 40),
        u2.getmd(0)['MachineUse'], u3.derive(1, 0, 16), u3.getst(1), u3.getst(0)),
       ('transferred', bytes(expect), 32, READY, 'transferred', 32, 'invalid', INVALID, SUCCESS))
    info('Toy endpoints follow <<KLEE-derive-endpoints>>: any listed source with any listed destination, subject to '
         'DER1-DER8; the XOF source is its kl.exec output in Success (SGR5), unrestricted also into a key (DER6 key '
         'derivation); the KEX shared secret is restricted (DER5); the signature private key is a destination '
         'only in its Machine-named State (DER1 item 2).')
    u = [pair() for _ in range(6)]
    u[1].setst(1, EXPIRED)
    u[2].setst(0, 0)
    u[3].mgmt(1, EXP)
    u[4].lockers[1].mdh['UsagePolicy'] = 8
    u[5].lockers[0].mdh['ExpirationDate'] = u[5].lockers[1].mdh['ExpirationDate'] = 1
    u[5].clock = 9
    eq('equal indices; Error-State endpoint no-op; Unconfigured; Configuration; UsagePolicy; both expire',
       [trap_of(u[0].derive, 0, 0, 32), u[1].derive(1, 0, 32), u[1].getmd(0)['MachineUse'],
        trap_of(u[2].derive, 1, 0, 32),
        trap_of(u[3].derive, 1, 0, 32), trap_of(u[4].derive, 1, 0, 32), u[5].derive(1, 0, 32), u[5].getst(0),
        u[5].getst(1)],
       ['illegal/1', 'noop', 0, 'illegal/2', 'privilege_violation', 'privilege_violation', 'expired', EXPIRED, EXPIRED])
    u = [pair() for _ in range(7)]
    u[0].setst(1, ToyCipher.ENCRYPT, 1)
    u[1].setst(1, ToyCipher.VERIFY, MACHINES[M_CIPHER].verify_tag(u[1], u[1].lockers[1]))
    u[2].setst(0, READY)
    provision(u[3], 2, md(Machine=M_CUSTOM, MachinePolicy=1, Locality=loc(hw1=2)))
    provision(u[4], 3, cipher(KeyType=1), v2b(SKID_A, 16))
    provision(u[5], 2, sig())
    u[6].setst(0, READY)
    u[6].setst(1, ToyCipher.ENCRYPT, 1)
    eq('DER1 items 1-2: only the offending lockers (State, no destination endpoint, KeyType-1 or non-key-State key)',
       [(u[0].derive(1, 0, 32), u[0].getst(1), u[0].getst(0)), (u[1].derive(1, 0, 32), u[1].getst(1)),
        (u[2].derive(1, 0, 32), u[2].getst(0), u[2].getst(1)), (u[3].derive(2, 0, 32), u[3].getst(0), u[3].getst(2)),
        (u[4].derive(3, 0, 32), u[4].getst(3), u[4].getst(0), u[4].getmd(0)['MachineUse']),
        (u[5].derive(2, 0, 64), u[5].getst(2), u[5].getst(0)), (u[6].derive(1, 0, 32), u[6].getst(0), u[6].getst(1))],
       [('invalid', INVALID, SUCCESS), ('invalid', INVALID), ('invalid', INVALID, READY), ('invalid', SUCCESS, INVALID),
        ('invalid', INVALID, SUCCESS, 0), ('invalid', INVALID, SUCCESS), ('invalid', INVALID, INVALID)])
    u = pv(pair(), 4, xof())
    eq('length 0 into an absorb destination changes nothing; a XOF destination absorbs',
       (u.derive(4, 0, 0), u.getst(4), u.getmd(0)['MachineUse'], u.derive(4, 0, 5), u.getst(4),
        u.getmd(0)['MachineUse']),
       ('nothing', READY, 0, 'transferred', ToyXof.ABSORB, 5))
    u = pair()
    u.lockers[0].mdh.update(UsagePolicy=1, Locality=loc(hw1=2))
    before = u.getmd(1)
    eq('XOF output into a key (DER6 key derivation) is an unrestricted transfer: no narrowing (DER3)',
       (u.derive(1, 0, 32), u.getmd(1)), ('transferred', before))

    def kex(src=None, dst=None, dst_md=cipher, **kw):
        w = pv(fresh(**kw), 0, md(Machine=M_KEX, **(src or {})))
        w.setst(0, ToyKex.SHARED, 0x1234)
        return pv(w, 1, dst_md(**(dst or {})))
    w = kex(src=dict(UsagePolicy=0b10001, Locality=loc(hw1=2, mloc=1), ExpirationDate=500),
            dst=dict(UsagePolicy=0b10010, Locality=loc(hw1=1, sloc=1), ExpirationDate=900))
    secret = MACHINES[M_KEX].get_state(w.lockers[0])
    w2, w3, w4 = kex(src=dict(ExpirationDate=500)), kex(src=dict(SCProtection=1), dst=dict(SCProtection=2)), \
        kex(src=dict(UsagePolicy=4), dst_md=xof)
    eq('shared secret: restricted into a key and into a XOF (DER2, DER5)',
       [w.derive(1, 0, 32), w.lockers[1].c1[:32] == secret[:32], w.getmd(1)['UsagePolicy'], w.getmd(1)['Locality'],
        w.getmd(1)['ExpirationDate'], w.getst(0), w2.derive(1, 0, 32), w2.getmd(1)['ExpirationDate'],
        w3.derive(1, 0, 32), w3.getmd(1)['SCProtection'], w4.derive(1, 0, 32), w4.getmd(1)['UsagePolicy']],
       ['transferred', True, 0b10011, loc(hw1=2, mloc=1, sloc=1), 500, ToyKex.SHARED, 'transferred', 500, 'transferred',
        2, 'transferred', 4])
    p1, p2, x, out = kex(src=dict(UsagePolicy=1), dst_md=sig), kex(dst_md=sig), pv(pair(), 2, sig()), bytearray(64)
    p1.setst(1, ToySig.SET_SCALAR)
    x.setst(2, ToySig.SET_SCALAR)
    x.lockers[0].mdh['UsagePolicy'] = 1
    xof_success(fresh(), 0).exec_(0, 'C', vout=out)
    s1 = MACHINES[M_KEX].get_state(p1.lockers[0])
    eq('private key in its Machine-named State (DER1 item 2): secret narrowed (DER5), XOF output not (DER6 key '
       'derivation); Ready Invalid',
       [p1.derive(1, 0, 64), p1.lockers[1].c1 == s1, p1.getmd(1)['UsagePolicy'], p1.getst(1), x.derive(2, 0, 64),
        x.lockers[2].c1 == bytes(out), x.getmd(2)['UsagePolicy'], p2.derive(1, 0, 64), p2.getst(1), p2.getst(0)],
       ['transferred', True, 1, ToySig.SET_SCALAR, 'transferred', True, 0, 'invalid', INVALID, ToyKex.SHARED])
    rows = []
    for kw in (dict(src=dict(Locality=loc(boot=1)), dst=dict(Locality=loc(boot=2))),
               dict(src=dict(SCProtection=2), dst=dict(SCProtection=1)), dict(src=dict(Locality=loc(sloc=1)))):
        w = kex(**kw)
        w.slocality = 0
        rows.append((w.derive(1, 0, 32), w.getst(1), w.getst(0), MACHINES[M_KEX].get_state(w.lockers[0]) == secret))
    w1, w2, w3 = kex(), kex(), kex(src=dict(UsagePolicy=4))
    w1.setst(0, READY)
    w2.setst(1, ToyCipher.ENCRYPT, 1)
    eq('DER2 failures; DER5 without a secret or a non-Ready key; DER1 checks precede DER2 narrowing',
       rows + [(w1.derive(1, 0, 32), w1.getst(0), w1.getst(1)), (w2.derive(1, 0, 32), w2.getst(1), w2.getst(0)),
               (w3.derive(1, 0, 8), w3.getst(1), w3.getmd(1)['UsagePolicy'])],
       [('invalid', INVALID, ToyKex.SHARED, True)] * 3
       + [('invalid', INVALID, READY), ('invalid', INVALID, ToyKex.SHARED), ('invalid', INVALID, 0)])

def t_errors():
    section('Error handling, CSK, KLS, Off gate  <<KLEE-error-architecture>>, <<KLEE-CSR-llockerstatus>>')
    cap = MACHINES[M_CIPHER].clf_capacity(cipher())
    u1, u2 = fresh(priv=False).csrs(klstart=16), fresh(priv=False, clf_total=10)
    u3 = rc(unit=fresh(priv=False), UsagePolicy=8)
    u4, u5 = opened(priv=False), pv(fresh(priv=False, clf_total=cap), 0, cipher())
    u5.mgmt(1, IMP, cipher(State=EXPIRED))
    eq('no Privileged Architecture: KLEE exceptions become Error States of the locker; no CSK and KLIOBUF illegal/2',
       [u1.mgmt(0, PROV, md(Machine=M_ABSENT, MachinePolicy=1)), u1.getmd(0), u1.klstart, u1.klmanagedlocker,
        u2.mgmt(0, IMP, cipher(State=1)), u2.getmd(0), ex(u3, 0), u3.getst(0), u3.lockers[0].c1, u4.clone(1, 0),
        u4.getst(0), u4.getst(1), u4.klmanagedlocker, u5.clone(2, 0), u5.getst(2), u5.restrict(0, md(SCProtection=2)),
        u5.getst(0), trap_of(fresh(priv=False, csk=0).getmd, 0), trap_of(fresh(priv=False).input_, Memory(), BASE, 1)],
       ['unsupported', md(State=UNSUP), 0, 32, 'out_of_memory', md(State=OOM), 'error', PRIV, b'', 'error', PRIV, 0, 32,
        'error', OOM, 'error', OOM, 'illegal/2', 'illegal/2'])
    u, ml, v = fresh(), md(Machine=M_ABSENT, MachinePolicy=1, UsagePolicy=3), rc(UsagePolicy=8)
    b0 = snapshot(v)
    eq('handler: kl.setst no-op on Unconfigured, short import installs its MDH; exceptions change no state',
       (trap_of(u.mgmt, 7, PROV, ml), u.setst(7, UNSUP), u.getst(7), u.mgmt(7, IMP, dict(ml, State=UNSUP)), u.getmd(7),
        trap_of(ex, v, 0), snapshot(v) == b0),
       ('unsupported', 'noop', 0, 'short import', dict(ml, State=UNSUP), 'privilege_violation', True))
    u, k = fresh(csk=0), fresh(kls_off=True)
    eq('no CSK: kl_exc_no_csk; KLS Off: illegal/1; identification CSRs exempt from both',
       ([trap_of(u.getmd, 0), trap_of(u.clearall), trap_of(u.csr_read, 'klstart'),
         trap_of(u.input_, Memory(), BASE, 1)],
        [u.csr_read(c) for c in Unit.RO_ID], [trap_of(k.getmd, 0), trap_of(k.csr_write, 'klstart', 0),
                                              trap_of(k.mgmt, 0, PROV, cipher())], k.csr_read('klmimpid')),
       (['no_csk'] * 4, [0xA11, 0x42, 0x7, 256], ['illegal/1'] * 3, 0x7))
    u = rc()
    u.mode, u.llstatus = 'S', {0: 'off', 5: 'off'}
    eq('Off locker: each access traps; first group precedes; precedes the second group; source never exempt',
       [trap_of(u.getmd, 0), trap_of(u.size, k=0), trap_of(u.exec_, 0, 'D'), trap_of(u.restrict, 0, 0, 'h'),
        trap_of(u.clone, 1, 0), trap_of(u.mgmt, 0, EXP), trap_of(u.load, 0, Memory(), BASE), trap_of(u.mv_in, 0, 1),
        trap_of(u.setst, 0, 46), trap_of(u.clone, 1, 5), trap_of(u.clone, 5, 0)],
       ['locker_off'] * 8 + ['illegal/1', 'locker_off', 'locker_off'])
    u.llstatus.update({0: 'clean', 6: 'off', 7: 'clean', 8: 'off', 9: 'off'})
    L = u.llstatus
    eq('exempt accesses execute and set Dirty; none before the zeroizing step',
       [u.clone(5, 0), L[5], u.setst(6, 0), L[6], u.setst(7, 0), L[7], u.mgmt(8, PROV, cipher()), L[8],
        trap_of(u.mgmt, 9, PROV, cipher()), L[9],
        trap_of(u.csrs(klmanagedlocker=32).mgmt, 9, PROV, md(Machine=M_ABSENT)),
        L[9]],
       ['cloned', 'dirty', 'cleared', 'dirty', 'cleared', 'clean', 'opened', 'dirty', 'illegal/2', 'off', 'unsupported',
        'dirty'])
    rc(12, u.csrs(klmanagedlocker=32))
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
    pv(u, 7, sig()).restrict(7, md(UsagePolicy=1), 'h')
    u.mgmt(5, PROV, xof())
    u.mv_in(5, 0x1111)
    src, ml, mem, _ = interrupted_import(u.csrs(klmanagedlocker=32), 2, 64, decrypt=True)
    u.csrs(klstart=0, kliobuflen=64).input_(Memory(bytes(5 * i + 1 & 0xFF for i in range(64))), BASE, 64)
    u.csrs(kliobuftop=40, klstart=64)
    return src, ml, mem

def save_context(u):
    """<<KLEE-state-save-and-restore-order>>, with 32 written before each export."""
    ctx = {c: u.csr_read(c) for c in ('klstart', 'klmanagedlocker', 'kliobuflen', 'kliobuftop')}
    if ctx['kliobuflen']:
        mem = Memory()
        u.csrs(klstart=0, kliobuftop=ctx['kliobuflen']).output(mem, BASE, ctx['kliobuflen'])
        ctx['kliobuf'] = mem.read(BASE, ctx['kliobuflen'])
    mc, ctx['images'] = ctx['klmanagedlocker'], {}
    if mc < 32 and u.getmd(mc)['State'] != UNCONF:
        ctx['images'][mc] = export(u, mc)
    for k in range(32):
        if k != mc and u.getst(k) != UNCONF:
            ctx['images'][k] = export(u.csrs(klmanagedlocker=32), k)
    u.csrs(klmanagedlocker=32)
    return ctx

def restore_context(u, ctx, managed_first=False):
    mc = ctx['klmanagedlocker']
    order = [k for k in ctx['images'] if k != mc]
    if mc in ctx['images']:
        order = [mc] + order if managed_first else order + [mc]
    for k in order:
        import_(u.csrs(klmanagedlocker=32), k, ctx['images'][k])
        if k != mc:
            u.csrs(klmanagedlocker=32)
    u.csrs(kliobuflen=ctx['kliobuflen'])
    if ctx['kliobuflen']:
        u.csrs(klstart=0).input_(Memory(ctx['kliobuf']), BASE, ctx['kliobuflen'])
    u.csrs(kliobuftop=ctx['kliobuftop'], klmanagedlocker=mc, klstart=ctx['klstart'])

def t_save_restore():
    section('Reset, context save and restore  <<KLEE-out-of-reset-unpriv>>, <<KLEE-state-save-and-restore-order>>')
    u = rc(unit=fresh(siv=4)).csrs(kliobuflen=16)
    u.reset()
    eq('out of reset: Unconfigured, KLIOBUF off, klstart 0, klmanagedlocker 32, registers 0; 33+ ignored',
       [[u.getst(k) for k in range(32)], u.kliobuflen, u.kliobuftop, u.klstart, u.klmanagedlocker,
        (u.siv, u.impqual, u.siv2)] + [u.csrs(klmanagedlocker=v).klmanagedlocker for v in (33, 4, 1 << 40)],
       [[0] * 32, 0, 0, 0, 32, (0, 0, 0), 32, 4, 4])
    u = fresh()
    src, ml, mem = build_context(u)
    r, before = [u.getst(2), u.klmanagedlocker, u.klstart, u.getst(5)], snapshot(u)
    ctx = save_context(u)
    eq('context: K2 importing and managed; the save leaves 58/56; managed image first, Error State 16 bytes',
       r + [u.getst(2), u.getst(5), u.getst(0), list(ctx['images'])[0], len(ctx['images'][1]), sorted(ctx['images'])],
       [IMP, 2, 64, PROV, IMP, PROV, ToyCipher.ENCRYPT, 2, 16, [0, 1, 2, 5, 7]])
    u.clearall()
    provision(u, 2, xof())
    u.csrs(kliobuflen=16, klmanagedlocker=3, klstart=8).siv = 99
    u.clearall()
    restore_context(u, ctx)
    r = [snapshot(u) == before, u.load(2, mem, BASE), u.mgmt(2, END, ml),
         (u.getmd(2), u.lockers[2].c1, u.lockers[2].c2) == (src.getmd(0), src.lockers[0].c1, src.lockers[0].c2),
         u.csrs(klstart=16).mv_in(5, 0x2222), u.mgmt(5, END), u.getst(5), u.lockers[5].c1]
    eq('the restore is exact; the import authenticates; the abandoned provisioning resumes', r,
       [True, 'done', 'completed', True, 'moved', 'completed', READY, v2b(0x1111, 16) + v2b(0x2222, 16)])
    u, w = pv(fresh(), 0, cipher()), fresh().csrs(klmanagedlocker=0)
    u.mgmt(0, EXP)
    u.csrs(kliobuflen=16).kliobuf[:16] = mdh_bytes(cipher(State=READY))
    eq('ml passed through the KLIOBUF (Form A); klmanagedlocker is a hint (Unconfigured: no image)',
       (u.mgmt(0, END, form='A'), u.getst(0), w.getmd(0)['State'], save_context(w)['images']),
       ('completed', READY, 0, {}))
    u, out = pv(fresh(), 3, cipher(SCProtection=1)), Memory()
    base = u.getmd(3)
    u.mgmt(3, EXP)
    u.store(3, out, BASE, halt_after=32)
    before, ctx = snapshot(u), save_context(u)
    u.clearall()
    restore_context(u, ctx)
    r = [snapshot(u) == before, u.store(3, out, BASE), u.mgmt(3, END, base), u.getst(3)]
    eq('an interrupted export survives save and restore, completes, and its SCC imports',
       r + [import_(fresh(), 0, mdh_bytes(base) + out.read(BASE, u.size(k=3) - 16))],
       [True, 'done', 'completed', READY, READY])

def t_encodings():
    section('Encodings and locker addressing  <<KLEE-instructions-detailed>>, <<KLEE-cryptographic-registers>>')
    d = lambda hi5, **kw: decoded(enc_r(2, hi5, **kw))
    eq('funct2 2: T selects clone, rename, swap, derive; R bit 25 destination, bit 26 source indirect',
       ([d(T << 2, rs1=3, rd=4)[0] for T in range(4)], [d(R, rs1=6, rd=7)[1:] for R in range(4)]),
       (['kl.clone', 'kl.rename', 'kl.swap', 'kl.derive'],
        [('K7', 'K6'), ('K(X7)', 'K6'), ('K7', 'K(X6)'), ('K(X7)', 'K(X6)')]))
    eq('clone/rename/swap indirect without Zklind; derive R != 00 needs Zklind; clone rs2 or bit 29 reserved',
       ([d(T << 2 | 3, rs1=6, rd=7) for T in range(3)], [d(12 | R, rs2=9, rs1=6, rd=7) for R in (1, 2, 3)],
        d(12, rs2=9, rs1=6, rd=7), decoded(enc_r(2, 15, rs2=9, rs1=6, rd=7), zklind=True), d(0, rs2=1, rs1=6, rd=7),
        d(16, rs1=6, rd=7)),
       ([(n, 'K(X7)', 'K(X6)') for n in ('kl.clone', 'kl.rename', 'kl.swap')], ['illegal/1'] * 3,
        ('kl.derive', 'K7', 'K6', 'X9'), ('kl.derive', 'K(X7)', 'K(X6)', 'X9'), 'illegal/1', 'illegal/1'))
    words = {'kl.exec': enc_r(0, 2, rs2=2, rs1=6, rd=3), 'kl.mv': enc_r(0, 10, rs2=4, rs1=6, rd=1),
             'kl.size': enc_r(0, 6, rs1=6, rd=3), 'kl.restrictl': enc_r(1, 2, rs1=4, rd=6),
             'kl.getmdl': enc_r(3, 2, rs1=6, rd=3), 'kl.setst': enc_setst(2, F=1, r=1, rs1=4, rd=6),
             'kl.mgmt': enc_setst(PROV, F=3, r=1, rs1=4, rd=6), 'kl.load': enc_ls(False, 7, 6),
             'kl.store': enc_ls(True, 7, 6)}
    eq('other instructions address indirectly only with Zklind; kl.load/kl.store select with funct3',
       ({n: (decoded(w), decoded(w, zklind=True)[0]) for n, w in words.items()},
        [decoded(enc_ls(s, 6, 6)) for s in (False, True)]),
       ({n: ('illegal/1', n) for n in words}, [('kl.load', 'K6'), ('kl.store', 'K6')]))
    eq('kl.clearall is r=1, rs1=rd=0 without Zklind; other X0 forms reserved; GR11 X0 index',
       [decoded(enc_setst(0, r=1)), decoded(enc_setst(1, r=1)), decoded(enc_setst(0, F=1, r=1)),
        decoded(enc_r(0, 2, rs1=0), zklind=True), d(3, rs1=0, rd=7)],
       [('kl.clearall',), 'illegal/1', 'illegal/1', 'illegal/1', 'illegal/1'])
    eq('kl.mv sub-opcodes in the unused register field of kl.exec Forms B and C',
       [decoded(enc_r(0, f << 3, rs2=s, rs1=6, rd=r))[:2] for f, r, s in ((1, 0, 5), (1, 1, 5), (1, 2, 5), (2, 5, 0),
                                                                           (2, 5, 1), (2, 5, 2))],
       [('kl.exec', 'B'), ('kl.mv', 'I'), ('kl.mv', 'II'), ('kl.exec', 'C'), ('kl.mv', 'III'), ('kl.mv', 'IV')])
    names = [decoded(enc_setst(i, F=3, rs1=4, rd=6)) for i in range(128)]
    eq('#immed7: 0111xxx kl.mgmt (59-62, Form B reserved); 46, 47 reserved; 0, 64, 65-127',
       ([i for i in range(128) if names[i][0] == 'kl.mgmt'], [i for i in range(128) if names[i] == 'illegal/1'],
        decoded(enc_setst(56, F=1, rs1=4, rd=6)), names[0][0], names[64][0], {names[i][0] for i in range(65, 128)}),
       ([56, 57, 58, 63], [46, 47, 59, 60, 61, 62], 'illegal/1', 'kl.clear', 'kl.clearads', {'kl.setst'}))
    u, v = rc(), rc(4, fresh(zklind=True))
    eq('model: indirect getmd, derive, load need Zklind; clone, rename, swap do not; Zklind selects',
       ([trap_of(u.getmd, Ind(0)), trap_of(u.derive, Ind(1), 0, 32), trap_of(u.load, Ind(0), Memory(), BASE)],
        (u.clone(Ind(1), Ind(0)), u.rename(Ind(2), Ind(1)), u.swap(Ind(3), Ind(2)), u.getst(3), u.getst(2)),
        (v.getst(Ind(4)), v.size(k=Ind(4)) == v.size(k=4))),
       (['illegal/1'] * 3, ('cloned', 'renamed', 'swapped', ToyCipher.ENCRYPT, 0), (ToyCipher.ENCRYPT, True)))

def t_rename_swap():
    section('kl.rename and kl.swap  <<KLEE-instruction-clone>>')
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
    r += [u.swap(1, 6), (u.getmd(1), u.getmd(6)) == (b, a), u.lockers[1].alloc, trap_of(u.clone, 1, 9), u.rename(1, 9),
          u.getst(1)]
    t = rc(0, rc(1, fresh(clf_total=2 * cap), SCProtection=1), SCProtection=1)
    eq('rename moves, frees the destination; Ks = Kd no-op; swap exchanges; no capacity checks; '
       'an Unconfigured source (K9): rename clears Kd, where clone traps',
       r + [t.clf_free(), t.swap(0, 1), t.rename(2, 0), trap_of(t.clone, 3, 1)],
       ['renamed', True, 0, 0, 'renamed', True, cap, 'noop', 'noop', True, 'swapped', True, cap, 'illegal/2',
        'renamed', 0,
        0, 'swapped', 'renamed', 'out_of_memory'])
    e = rc()
    e.setst(0, EXPIRED)
    eq('SGR12: a locker in an Error State becomes _Unconfigured_ as the destination of kl.rename from an '
       'Unconfigured source (acts as kl.clear Kd)', [e.getst(0), e.rename(0, 9), e.getst(0), e.getst(9)],
       [EXPIRED, 'renamed', 0, 0])
    u = fresh()
    src, ml, mem, _ = interrupted_import(u, 2, 48)
    regs, w = (u.siv, u.impqual, u.siv2), rc(4)
    w.mgmt(3, PROV, cipher())
    r = [u.rename(7, 2), u.getst(7), u.getst(2), u.klmanagedlocker, u.klstart, (u.siv, u.impqual, u.siv2) == regs,
         u.load(2, mem, BASE), u.load(7, mem, BASE), u.mgmt(7, END, ml), u.getmd(7) == src.getmd(0),
         u.lockers[7].c1 == src.lockers[0].c1, w.swap(3, 4), w.klmanagedlocker, w.getst(3), w.getst(4), w.swap(0, 1),
         w.klmanagedlocker, w.rename(4, 3), w.klmanagedlocker, w.getst(4), w.mgmt(8, PROV, cipher()),
         trap_of(w.clone, 9, 8), w.swap(9, 8), w.rename(8, 9), w.getst(8), w.klmanagedlocker]
    eq('klmanagedlocker follows rename and swap, 32 when overwritten; Configuration CC moves (SGR18, SGR20); '
       'kl.load on the vacated index is a no-op (SGR24)', r,
       ['renamed', IMP, 0, 7, 48, True, 'noop', 'done', 'completed', True, True, 'swapped', 4, ToyCipher.ENCRYPT,
        PROV, 'swapped', 4, 'renamed', 32, ToyCipher.ENCRYPT, 'opened', 'privilege_violation', 'swapped', 'renamed',
        PROV, 8])
    u, w = rc(UsagePolicy=1, ExpirationDate=10).csrs(klstart=32), rc()
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
    eq('not usage-controlled, no evaluation point, uninterruptible (IRR1); Error, Success, Failure CCs move', r,
       ['renamed', 'swapped', ToyCipher.ENCRYPT, 1, 32, 11, 'privilege_violation', 'renamed', True, 0, 'swapped', True,
        'renamed', 'swapped', SUCCESS, 'renamed', 'swapped', FAILURE])

def t_controls():
    section('Negative controls')
    cur, req = 0b01110, 0b00001
    u, probe, gained = pv(fresh(), 0, cipher(UsagePolicy=cur)), fresh(), []
    u.restrict(0, md(UsagePolicy=req), 'h')
    for probe.mode in ('U', 'VS', 'HS', 'M'):
        if probe.usage_allowed(cipher(UsagePolicy=req)) and not probe.usage_allowed(cipher(UsagePolicy=cur)):
            gained.append(probe.mode)
    eq('the spec rule adds the new denial and keeps the old ones', u.getmd(0)['UsagePolicy'], 0b01111)
    control('replace-if-non-zero UsagePolicy widens the allowed modes', gained == ['VS', 'HS', 'M'])
    src = pv(fresh(), 0, sig())
    img = export(src, 0)
    ml, mem, v, w = unpack(b2v(img[:16])), Memory(img[16:]), opened(IMP, unpack(b2v(img[:16])), k=1), fresh()
    v.load(1, mem, BASE, halt_after=32)
    k = v.klstart
    v.csrs(klstart=48).load(1, mem, BASE)
    v.mgmt(1, END, ml)
    eq('an import halted at 32 and resumed correctly round trips',
       (k, import_(w, 1, img, halt_after=32), w.load(1, mem, BASE), w.mgmt(1, END, ml), w.lockers[1].c1),
       (32, 'halted', 'done', 'completed', src.lockers[0].c1))
    control('an import resumed at a later klstart fails authentication', (v.getst(1), v.lockers[1].c1) == (AUTH, b''))
    u = pv(fresh(), 0, cipher(SCProtection=1))
    scc = export(u, 0)
    AD, c1, siv = u.sealing_ad(dict(u.getmd(0), ADSDropped=1)), to_blocks(scc[64:96]), b2v(scc[16:32])
    eq('with bit 47 cleared in AD_auth a toggled ADSDropped still authenticates',
       scc_decrypt(AD, 0, 0, siv, c1, DEFAULT_CSK)[0], True)
    control('authentication over an uncleared bit 47 rejects a toggled ADSDropped',
            not scc_decrypt(AD, 0, 0, siv, c1, DEFAULT_CSK, clear47=False)[0])
    m = md(State=EXPIRED, StateExtension=0xF, KeyType=1)
    eq('the MDH layout satisfies the kl.getst expansion', pack(m) >> 19 & 0x3F, EXPIRED)
    control('a layout with State at [25:21] fails the kl.getst expansion',
            (m['State'] << 21 | m['StateExtension'] << 26 | m['KeyType'] << 19) >> 19 & 0x3F != EXPIRED)
    u = fresh()
    src, ml, mem = build_context(u)
    ctx = save_context(u)
    u.clearall()
    restore_context(u, ctx, managed_first=True)
    u.load(2, mem, BASE)
    u.mgmt(2, END, ml)
    control('restoring the managed locker first loses its SIV (Authentication Failed)', u.getst(2) == AUTH)
    runs = {}
    for faithful in (True, False):
        u = fresh()
        src, ml, mem = build_context(u)
        if faithful:
            u.rename(9, 2)
        else:
            u.lockers[9], u.lockers[2] = u.lockers[2], Locker()
        runs[faithful] = trap_of(u.load, 9, mem, BASE)
    eq('after kl.rename the interrupted import resumes on the new index', runs[True], None)
    control('a rename leaving klmanagedlocker behind strands the import (SGR21)', runs[False] == 'illegal/2')
    eq('a handler clear at any one boundary of the provisioning listing: Ready after at most one restart (SGR24)',
       [listing_provision(lambda s, at=at: s == at) for at in range(6)], [(READY, 0)] + [(READY, 1)] * 5)
    eq('a handler Error State at any boundary after the opening: the next instruction is a no-op, the listing '
       'reaches handle_errors with it (SGR24)', ([listing_provision(error_at=at) for at in range(1, 6)],
                                                  [listing_export(error_at=at)[0] for at in range(3, 8)]),
       ([(OOM, 0)] * 5, ['error'] * 5))
    control('a handler that clears at every context switch livelocks a single-stepped provisioning '
            '<<KLEE-CC-management>>', listing_provision(lambda s: True) == ('livelock', 8))
    st, img = listing_export()
    eq('the export listing: a clear at any of its 8 boundaries is reported, else the image imports (SGR24)',
       ([listing_export(lambda s, at=at: s == at) for at in range(8)], st, import_(fresh(), 3, img)),
       ([('lost', None)] * 8, READY, READY))
    u, mem = pv(fresh(), 0, cipher()), Memory()
    m, n = u.getmd(0), u.size(k=0)
    u.mgmt(0, EXP)
    u.clear(0)
    r = [u.store(0, mem, BASE), u.mgmt(0, END, m), u.getst(0)]
    control('an export cleared before kl.store and not checked: the image fails authentication at import',
            r == ['noop', 'noop', UNCONF]
            and import_(fresh(), 3, mdh_bytes(m) + mem.read(BASE, n - 16)) == AUTH)
    absent = md(Machine=M_ABSENT, MachinePolicy=1)
    eq('a handler past a trapping opening kl.mgmt sets the Error State: the listing reaches handle_errors',
       listing_provision(m=absent, on_trap=lambda u, tag: u.mgmt(0, IMP, dict(absent, State=EXC_STATE[tag]))),
       (UNSUP, 0))
    control('a handler past a trapping opening kl.mgmt that leaves the locker Unconfigured livelocks the listing',
            listing_provision(m=absent, on_trap=lambda u, tag: None) == ('livelock', 8))

if __name__ == '__main__':
    for t in (t_mdh, t_states, t_validity, t_lengths, t_usage, t_restrict, t_localities, t_mgmt, t_nested,
              t_error_states, t_ads, t_transfers, t_kliobuf, t_sgr, t_exec, t_expiration, t_derive, t_errors,
              t_save_restore, t_encodings, t_rename_swap, t_controls):
        t()
    done()
