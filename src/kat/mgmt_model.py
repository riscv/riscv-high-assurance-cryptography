"""Function-level model of the KLE unit for the management KAT (Zkl-ISA-unpriv.adoc, Zkl-ISA-machines.adoc).
Toy Machines: 0x001 TOYENC (policy bit0 enc, bit1 dec, zero policy invalid; State 2 Encrypt, 3 Decrypt; 16-byte key),
0x002 TOYSIG (any policy; State 2; 32-byte key), 0x004 TOYKEY (like TOYENC, has a key field: KeyType 1/2 valid).
Any other Machine value is unsupported.  Not modelled: SCC cryptography (see scc-kat.py), kl.derive, KLIOBUF."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *

class Trap(Exception):
    def __init__(self, kind): Exception.__init__(self, kind); self.kind = kind

M_ENC, M_SIG, M_KEY, M_KEM, M_KEY32, M_HASH, M_VER, M_CMAC, M_XOF = 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100
CONTENT = {M_ENC: 16, M_SIG: 32, M_KEY: 16, M_KEM: 32, M_KEY32: 32, M_HASH: 16, M_VER: 16, M_CMAC: 16, M_XOF: 16}
NONE = 32
RESERVED = ('Reserved31_30', 'Reserved46', 'Reserved79_78', 'Reserved127_116')
PI_STATES, SCC_STATES = (56, 59, 60), (57, 58)
_LO = {n: lo for n, lo, _ in MDH_FIELDS}

def loc_entries(loc):
    js = []
    for sh, base in ((0, 0), (2, 3), (4, 6)):
        v = loc >> sh & 3
        if 1 <= v <= 3 and not (sh == 4 and v == 3): js.append(base + v - 1)
    return js + [8 + b for b in range(3) if loc >> (6 + b) & 1]

def base_type(st): return 'pi' if st in PI_STATES else 'scc'
def toy_tag(c):     # toy MAC over the whole value (every 64-bit chunk matters)
    h = 0x1234
    while c: h = (h * 0x9E3779B97F4A7C15 + (c & mask(64)) + 1) & mask(64); c >>= 64
    return h

def validate(md, ctx, zk=True):
    """ctx 'provision' or 'import'.  Returns 'ok', 'invalid' or 'unsupported' (invalid takes precedence)."""
    g = lambda n: mdh_get(md, n)
    st, se, mach = g('State'), g('StateExtension'), g('Machine')
    bad = any(g(r) for r in RESERVED) or g('SCProtection') == 3 or g('KeyType') == 3 or (g('Locality') >> 4 & 3) == 3
    ver = g('Version')
    if ver == 3:      # <<KLE-GR-sysfmt-import-only>>, <<KLE-Metadata-validity>>
        bad |= ctx != 'import' or st not in (0, 58, 57) or g('AuxDataLen') == 0 or bool(se or g('KeyType') or g('ADSDropped') or g('MachineUse'))
    else:
        bad |= ver != 0 or g('AuxDataLen') == 1
    bad |= (se == 6 and not zk) or bool(g('ExpirationDate') and not zk)
    if mach in (M_ENC, M_KEY) and g('MachinePolicy') == 0: bad = True
    if g('KeyType') in (1, 2) and mach != M_KEY: bad = True
    if ctx == 'provision':
        bad |= st != 0 or se != 0 or g('AuxDataLen') != 0 or g('ADSDropped') != 0
    else:
        bad |= st in (61, 62, 63) or (st == 0 and (se == 0 and ver != 3 or se > 6)) or g('KeyType') == 2
    if bad: return 'invalid'
    return 'ok' if mach in CONTENT else 'unsupported'

def size_of(md):
    st = mdh_get(md, 'State'); c1 = CONTENT[mdh_get(md, 'Machine')]
    if mdh_get(md, 'Version') == 3: return 16 + 16 * mdh_get(md, 'AuxDataLen')
    adl, dr = mdh_get(md, 'AuxDataLen'), mdh_get(md, 'ADSDropped')
    if st in (56, 59, 60) or st == 0: return 16 + c1
    if adl >= 2: return 64 + c1 + (16 * (adl - 2) if dr == 0 else 0)
    return 32 + c1

class Locker:
    def __init__(s): s.mdh = 0; s.content = 0; s.tag = 0; s.slot = False

class KLE:
    def __init__(s, slots=8, zk=True, mode=2, clock=0, csk=True, zero_alloc=True):
        s.L = [Locker() for _ in range(32)]; s.nl = NONE; s.start = 0; s.slots = slots; s.pool = []
        s.zk, s.mode, s.clock, s.csk, s.zero_alloc = zk, mode, clock, csk, zero_alloc
        s.rng = 0x1000; s.max_ads = 4
        s.lst = [1 + j for j in range(11)]; s.sks = {}; s.has_rng = True      # sks: None (no SKID support) or {skid: dict}
    # ---- helpers
    def md(s, k): return s.L[k].mdh
    def conf(s, j):                 # LST entry j after chain substitution (<<KLE-Localities>>)
        for ch in ((0, 1, 2), (3, 4, 5)):
            if j in ch:
                for b in ch[ch.index(j):]:
                    if s.lst[b]: return s.lst[b]
                return 0
        return s.lst[j]
    def val(s, md, ctx):
        v = validate(md, ctx, s.zk)
        if v != 'ok': return v
        loc = mdh_get(md, 'Locality')
        for j in loc_entries(loc):
            if not s.conf(j): return 'invalid'
        kt = mdh_get(md, 'KeyType')
        if (kt == 1 and s.sks is None) or (kt == 2 and not s.has_rng): return 'unsupported'
        return 'ok'
    def free(s, k):
        l = s.L[k]
        if l.slot: s.pool.append(l.content); s.slots += 1
        s.L[k] = Locker()
    def alloc(s, k):
        if s.slots == 0: raise Trap('out_of_memory')
        s.slots -= 1; l = s.L[k]; l.slot = True
        old = s.pool.pop() if s.pool else 0
        l.content = 0 if s.zero_alloc else old
    def err(s, k, se):             # GR35
        m = s.md(k)
        m = mdh_put(mdh_put(m, 'State', 0), 'StateExtension', se)
        m = mdh_put(mdh_put(m, 'AuxDataLen', 0), 'ADSDropped', 0)
        if mdh_get(m, 'Version') == 3: m = mdh_put(m, 'Version', 0)
        if mdh_get(m, 'KeyType') == 2: m = mdh_put(m, 'KeyType', 0)
        s.free(k); s.L[k].mdh = m
    def tgt(s, kd, r):             # GR4
        if r:
            if kd != 0: raise IllegalInstruction('GR4')
            return None if s.nl == NONE else s.nl
        return kd
    def common(s):                 # locker-state-independent checks (GR16), reduced
        if not s.csk: raise Trap('no_csk')
    def config(s, m): return 56 <= mdh_get(m, 'State') <= 60
    # ---- reads
    def getmd(s, kd, r=0, part='md'):
        k = s.tgt(kd, r); m = 0 if k is None else s.md(k)
        return {'md': m, 'l': m & mask(64), 'h': m >> 64}[part]
    def getst(s, kd, r=0):
        k = s.tgt(kd, r); return 0 if k is None else mdh_get(s.md(k), 'State')
    def getstx(s, kd, r=0):
        k = s.tgt(kd, r); return 0 if k is None else mdh_get(s.md(k), 'StateExtension')
    def getnl(s): return s.nl
    def setnl(s, v):
        if v <= 32: s.nl = v
    def size(s, kd=0, r=0, form='A', md=0):
        if form == 'A':
            k = s.tgt(kd, r)
            if k is None: return 0
            m = s.md(k)
            if is_unconfigured(m): return 0
            return 16 if is_error_state(m) else size_of(m)
        if form == 'B': md &= mask(64)
        g = lambda n: mdh_get(md, n)
        st, se = g('State'), g('StateExtension')
        if st >= 61 or (st == 0 and se > 6): return 0
        if st == 0 and se: return 16
        if g('Version') in (1, 2) or g('SCProtection') == 3 or g('KeyType') == 3: return 0
        v = s.val(md, 'provision' if st == 0 and g('Version') != 3 else 'import')
        return size_of(md) if v == 'ok' else 0
    def avail(s, kd=0, r=0, form='A', md=0):
        if form == 'A':
            k = s.tgt(kd, r)
            if k is None or is_unconfigured(s.md(k)): return 0
            return int(mdh_get(s.md(k), 'Machine') in CONTENT)
        if form == 'B': md &= mask(64)
        if mdh_get(md, 'Version') in (1, 2) or mdh_get(md, 'SCProtection') == 3 or mdh_get(md, 'KeyType') == 3: return 0
        return int(mdh_get(md, 'Machine') in CONTENT and not (mdh_get(md, 'KeyType') == 1 and s.sks is None) and not (mdh_get(md, 'KeyType') == 2 and not s.has_rng))
    # ---- destructive configuration
    def clear(s, kd, r=0):
        s.common(); k = s.tgt(kd, r)
        if k is None: return
        s.free(k)
        if s.nl == k: s.nl = NONE
    def clearall(s):
        s.common()
        for k in range(32): s.free(k)
        s.nl = NONE; s.start = 0
    def setste(s, kd, immed, r=0, form='A'):
        if form != 'A' or not 1 <= immed <= 6 or (immed == 6 and not s.zk): raise IllegalInstruction('setste')
        s.common(); k = s.tgt(kd, r)
        if k is None: return
        if is_unconfigured(s.md(k)): s.L[k].mdh = 0
        s.err(k, immed)
    # ---- usage instructions
    def usage_gate(s, k):
        """GR20 items 2,3: UsagePolicy then ExpirationDate.  False if an Error State was entered."""
        m = s.md(k)
        if not (mdh_get(m, 'UsagePolicy') >> s.mode & 1): raise Trap('privilege_violation')
        d = mdh_get(m, 'ExpirationDate')
        if s.zk and d:
            if s.clock is None: raise Trap('clock_unavailable')
            if min(max(s.clock, 0), mask(20)) >= d: s.err(k, SE_EXPIRED); return False
        return True
    def machine_admits(s, k, target):
        """MR1/MR18 toy table; target = new State, or None for kl.exec."""
        m = s.md(k); st = mdh_get(m, 'State'); mach = mdh_get(m, 'Machine'); pol = mdh_get(m, 'MachinePolicy')
        if target is None:
            if st == 2: return mach in (M_SIG, M_KEM, M_HASH) or bool(pol & 1)
            if st == 3: return mach == M_SIG or bool(pol & 2)
            return False
        if target == 1: return True
        if st != 1: return False
        if mach == M_SIG: return target in (2, 3)
        if mach in (M_KEM, M_HASH): return target == 2
        return (target == 2 and bool(pol & 1)) or (target == 3 and bool(pol & 2))
    def usage(s, kd, r, target):
        s.common(); k = s.tgt(kd, r)
        hon = target is None                      # kl.setst leaves klstart (<<KLE-GR-outcome-inert>> table)
        if k is None:
            if hon: s.start = 0
            return 'inert'
        m = s.md(k)
        if mdh_get(m, 'State') == 0:
            if hon: s.start = 0
            return 'inert'
        if s.config(m): raise Trap('privilege_violation')
        if not s.usage_gate(k): return 'expired'
        if not s.machine_admits(k, target): s.err(k, SE_INVALID); return 'invalid'
        if target is None: s.start = 0
        else: s.L[k].mdh = mdh_put(s.md(k), 'State', target)
        return 'ok'
    def exec(s, kd, r=0): return s.usage(kd, r, None)
    def setst(s, kd, immed, r=0, form='A', g=0, md=0):
        if g == 1: return s.setste(kd, immed, r, form)
        if g == 3: return s.mgmt(kd, immed, r, form, md)
        if immed == 0: return s.clear(kd, r)
        if immed == 65:
            if form != 'A' or kd != 0 or r: raise IllegalInstruction('clearall')
            return s.clearall()
        if immed == 64: return s.clearads(kd, r, form)
        if 56 <= immed <= 63: raise IllegalInstruction('GR23 reserved immed7')
        if immed in (54, 55) or immed > 65:        # GR24; no toy Machine defines 66-127
            s.common(); k = s.tgt(kd, r)
            if k is None or mdh_get(s.md(k), 'State') == 0: return
            if s.config(s.md(k)): raise Trap('privilege_violation')
            if s.usage_gate(k): s.err(k, SE_INVALID)
            return
        return s.usage(kd, r, immed)
    def clearads(s, kd, r=0, form='A'):
        s.common(); k = s.tgt(kd, r)
        if k is None: return
        m = s.md(k)
        if mdh_get(m, 'State') == 0: return
        if s.config(m): raise Trap('privilege_violation')
        if not s.usage_gate(k): return
        if form != 'A': s.err(k, SE_INVALID); return
        for n in ('AuxDataLen', 'ADSDropped', 'MachineUse', 'AuxInfo'): m = mdh_put(m, n, 0)
        s.L[k].mdh = m
    # ---- restrict
    def rstr(s, kd, rq, r=0, part='v'):
        s.common(); k = s.tgt(kd, r)
        if k is None: return
        m = s.md(k)
        if mdh_get(m, 'State') == 0: return
        if s.config(m): raise Trap('privilege_violation')
        lo = part in 'lv'; hi = part in 'hv'
        allowed = (['MachinePolicy'] if lo else []) + (['Locality', 'UsagePolicy', 'ExpirationDate'] if hi else [])
        for n, b, _ in MDH_FIELDS:
            if n not in allowed and ((b < 64 and lo) or (b >= 64 and hi)) and mdh_get(rq, n):
                s.err(k, SE_INVALID); return
        if hi and not s.zk and mdh_get(rq, 'ExpirationDate'): s.err(k, SE_INVALID); return
        if lo: m = mdh_put(m, 'MachinePolicy', mdh_get(m, 'MachinePolicy') & mdh_get(rq, 'MachinePolicy'))
        if hi:
            m = mdh_put(m, 'UsagePolicy', mdh_get(m, 'UsagePolicy') & mdh_get(rq, 'UsagePolicy'))
            e, c = mdh_get(rq, 'ExpirationDate'), mdh_get(m, 'ExpirationDate')
            if e and (c == 0 or e <= c): m = mdh_put(m, 'ExpirationDate', e)
            lm, lr = mdh_get(m, 'Locality'), mdh_get(rq, 'Locality'); out = lm
            for sh, hw in ((0, 1), (2, 1), (4, 0)):
                a, b = lm >> sh & 3, lr >> sh & 3
                if b == 0 or b == a: continue
                if a == 0 or (hw and b > a): out = (out & ~(3 << sh)) | (b << sh)
                else: raise Trap('privilege_violation')       # shortcut: earlier subfields not committed
            m = mdh_put(m, 'Locality', out | (lr & 0x1C0))
        s.L[k].mdh = m
    # ---- clone / rename / swap (d, src: locker number or 'NL' for klnamedlocker)
    def _two(s, d, src):
        s.common()
        return (s.nl if d == 'NL' else d), (s.nl if src == 'NL' else src)
    def clone(s, d, src):
        d, src = s._two(d, src)
        if d == NONE or src == NONE or d == src: return
        s.free(d)
        if s.nl == d: s.nl = NONE
        m = s.md(src)
        if mdh_get(m, 'State') == 0: s.L[d].mdh = m; return
        if s.config(m): raise Trap('privilege_violation')
        s.alloc(d); s.L[d].mdh = m; s.L[d].content = s.L[src].content; s.L[d].tag = s.L[src].tag
    def rename(s, d, src):
        d, src = s._two(d, src)
        if d == NONE or src == NONE or d == src: return
        if is_unconfigured(s.md(src)): return s.clear(d)
        s.free(d)
        if s.nl == d: s.nl = NONE
        s.L[d] = s.L[src]; s.L[src] = Locker()
        if s.nl == src: s.nl = d
    def swap(s, d, src):
        d, src = s._two(d, src)
        if d == NONE or src == NONE or d == src: return
        s.L[d], s.L[src] = s.L[src], s.L[d]
        if s.nl == d: s.nl = src
        elif s.nl == src: s.nl = d
    # ---- kl.mgmt
    def mgmt(s, kd, immed, r=0, form='C', md=0):
        if form == 'B' or immed not in (56, 57, 58, 63): raise IllegalInstruction('kl.mgmt')
        if form == 'A': md = 0
        s.common(); k = s.tgt(kd, r)
        if k is None: s.start = 0; return            # KLNL & 32: common steps only
        s.nl = k
        if immed == 63: return s._complete(k, md)
        if immed == 57: return s._export_open(k)
        s.start = 0; s.free(k)
        if immed == 58 and mdh_get(md, 'State') == 0 and 1 <= mdh_get(md, 'StateExtension') <= 6:
            # short import: invalid Metadata gives Invalid; otherwise the MDH is kept as is, but for GR35
            if s.val(md, 'import') == 'invalid': s.L[k].mdh = mdh_pack(State=0, StateExtension=SE_INVALID); return
            s.L[k].mdh = md; s.err(k, mdh_get(md, 'StateExtension')); return
        v = s.val(md, 'provision' if immed == 56 else 'import')
        if v == 'invalid': s.L[k].mdh = mdh_pack(State=0, StateExtension=SE_INVALID); return
        if v == 'unsupported': raise Trap('unsupported')
        s.alloc(k); m = md
        if immed == 56: m = mdh_put(mdh_put(mdh_put(m, 'MachineUse', 0), 'AuxInfo', 0), 'State', 56)
        else:
            m = mdh_put(m, 'State', 60 if base_type(mdh_get(md, 'State')) == 'pi' else 58)
            if mdh_get(md, 'Version') != 3:      # <<KLE-MVR-open>>: ADSDropped at import
                drop = mdh_get(md, 'AuxDataLen') >= 2 and (mdh_get(md, 'ADSDropped') or mdh_get(md, 'AuxDataLen') > s.max_ads)
                m = mdh_put(m, 'ADSDropped', int(bool(drop)))
        s.L[k].mdh = m
    def _export_open(s, k):
        s.start = 0; m = s.md(k); st = mdh_get(m, 'State')
        if st == 0: return
        s.L[k].mdh = mdh_put(m, 'State', (59 if st in PI_STATES else 57) if s.config(m) else 57)
    def mvin(s, content, tag=0):
        k = None if s.nl == NONE else s.nl
        if k is None or mdh_get(s.md(k), 'State') == 0: return
        if mdh_get(s.md(k), 'State') not in (56, 58, 60): raise IllegalInstruction('GR30')
        s.L[k].content = content; s.L[k].tag = tag
    def mvout(s):
        k = None if s.nl == NONE else s.nl
        if k is None or mdh_get(s.md(k), 'State') == 0: return (0, 0)
        if mdh_get(s.md(k), 'State') not in (57, 59): raise IllegalInstruction('GR30')
        return (s.L[k].content, toy_tag(s.L[k].content))
    def _sysfmt_complete(s, k): raise NotImplementedError
    def _complete(s, k, ml):
        s.start = 0; m = s.md(k); st = mdh_get(m, 'State'); l = s.L[k]
        if st == 0: return
        if not s.config(m): raise IllegalInstruction('completing mgmt on Valid State')
        if st == 56:   # <<KLE-GR-completion-state>>: provisioning ignores ml, ml.State is never read
            if mdh_get(m, 'AuxDataLen') or mdh_get(m, 'ADSDropped'): s.err(k, SE_INVALID); return
            if mdh_get(m, 'KeyType') == 2:
                s.rng = (s.rng * 6364136223846793005 + 1442695040888963407) & mask(64); l.content = s.rng
                m = mdh_put(m, 'KeyType', 0)
            l.mdh = mdh_put(mdh_put(mdh_put(mdh_put(m, 'State', 1), 'StateExtension', 0), 'MachineUse', 0), 'AuxInfo', 0); return
        mst = mdh_get(ml, 'State')
        v3 = mdh_get(m, 'Version') == 3
        adm = set(PI_STATES) if base_type(st) == 'pi' else set(range(1, 56)) | set(SCC_STATES)
        if v3: adm = {58, 57} | ({0} if st == 58 else set())
        if mst not in adm: raise IllegalInstruction('ml.State not admitted')
        if v3 and mst == 0: return s._sysfmt_complete(k)
        l.mdh = mdh_put(m, 'State', mst)
        if st in (58, 60) and 1 <= mst <= 55 and l.tag != toy_tag(l.content): s.err(k, SE_MGMT_AUTH)
