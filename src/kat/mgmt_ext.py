"""Extension of the management model: serialized image and memory instructions, KLIOBUF, kl.exec windows,
kl.derive, long-running operation, system-specific import, reset, instruction encodings.
Toy kl.exec: M_ENC State 2 Form A, 16-byte blocks, out = in xor key (granularity 16)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
from mgmt_model import *

PAGE = 4096
LR_STEPS = 5        # steps of the toy long-running operation (M_SIG State 3)

class Mem:
    """Byte memory with page faults and non-idempotent regions; log lists the byte addresses touched."""
    def __init__(s, size=1 << 16): s.b = bytearray(size); s.fault = set(); s.nonidem = set(); s.log = []
    def check(s, a, store):
        if a // PAGE in s.nonidem: raise Trap('store_access_fault' if store else 'load_access_fault')
        if a // PAGE in s.fault: raise Trap('store_page_fault' if store else 'load_page_fault')

def ks_block(content, j): return v2b(content ^ ((j + 1) * 0x0101010101010101), 16)      # toy keystream block j

def narrow(dmd, smd):
    """Metadata narrowing of dmd by smd (<<KLE-Metadata-narrowing>>), UsagePolicy, Locality, ExpirationDate; None on failure."""
    m = mdh_put(dmd, 'UsagePolicy', mdh_get(dmd, 'UsagePolicy') & mdh_get(smd, 'UsagePolicy'))
    a, b = mdh_get(dmd, 'Locality'), mdh_get(smd, 'Locality')
    out = 0
    for sh in (0, 2): out |= max(a >> sh & 3, b >> sh & 3) << sh
    ba, bb = a >> 4 & 3, b >> 4 & 3
    if ba and bb and ba != bb: return None
    out |= (ba or bb) << 4 | ((a | b) & 0x1C0)
    m = mdh_put(m, 'Locality', out)
    e1, e2 = mdh_get(dmd, 'ExpirationDate'), mdh_get(smd, 'ExpirationDate')
    return mdh_put(m, 'ExpirationDate', min(x for x in (e1, e2) if x) if (e1 or e2) else 0)

class KLE2(KLE):
    def __init__(s, *a, **kw):
        KLE.__init__(s, *a, **kw)
        s.zklio = False; s.kliobuflen = 0; s.kliobuftop = 0; s.iobuf = bytearray(256)
        s.siv = s.impqual = s.siv2 = 0; s.fmt_min_prot = 0; s.vext = True; s.csk_hardwired = False; s.debug = False; s.debug_auth = False; s.rbg_dead = False
        s.kls = 1; s.priv = 'M'; s.stateen = True; s.fatal = False; s.lstat = [1] * 32; s.kleemu = False; s._exm = False
        s.maxiobuf_reset = s.maxiobuf = 256
    # ---- privileged gates (<<KLE-KLS-field-in-mstatus>>, <<KLE-CSR-llockerstatus>>, <<KLE-exception-codes>>)
    def _pre1(s):
        if s.kls == 0 or (s.priv != 'M' and not s.stateen): raise IllegalInstruction('first group: KLS Off or stateen denial')
        if s.fatal: raise Trap('fatal')
    def common(s):
        s._pre1(); KLE.common(s)
    def tgt(s, kd, r):
        k = KLE.tgt(s, kd, r)
        if k is not None and not s._exm: s._off(k)
        return k
    def _off(s, k):
        if s.priv != 'M' and s.lstat[k] == 0: raise Trap('locker_off')
    def getmd(s, kd, r=0, part='md'): s._pre1(); return KLE.getmd(s, kd, r, part)
    def exec(s, kd, r=0): s.common(); return KLE.exec(s, kd, r)
    def getst(s, kd, r=0): s._pre1(); return KLE.getst(s, kd, r)
    def getstx(s, kd, r=0): s._pre1(); return KLE.getstx(s, kd, r)
    def setnl(s, v): s._pre1(); KLE.setnl(s, v)
    def clear(s, kd, r=0): s._exm = True; r_ = KLE.clear(s, kd, r) if True else None; s._exm = False; return r_
    def mgmt(s, kd, immed, r=0, form='C', md=0):
        s._exm = immed in (56, 58)
        try: return KLE2._mgmt(s, kd, immed, r, form, md)
        finally: s._exm = False
    def clone(s, d, src):
        s.common(); d, src = (s.nl if d == 'NL' else d), (s.nl if src == 'NL' else src)
        if d != src and d != NONE and src != NONE: s._off(src)
        return KLE2._clone(s, d, src)
    def rename(s, d, src):
        s.common(); d, src = (s.nl if d == 'NL' else d), (s.nl if src == 'NL' else src)
        if d != src and d != NONE and src != NONE: s._off(src)
        return KLE.rename(s, d, src)
    def swap(s, d, src):
        s.common(); d, src = (s.nl if d == 'NL' else d), (s.nl if src == 'NL' else src)
        if d != src and d != NONE and src != NONE: s._off(src); s._off(d)
        return KLE.swap(s, d, src)
    def snap(s): return (tuple((l.mdh, l.content) for l in s.L), s.nl, s.start, s.kliobuflen, s.kliobuftop, bytes(s.iobuf))
    def run(s, fn, *a, **kw):
        """Run an instruction; a changed KLE state sets KLS to Dirty (3) when it is not Off."""
        b = s.snap(); lb = [(l.mdh, l.content) for l in s.L]
        try: return fn(*a, **kw)
        finally:
            if s.kls and s.snap() != b: s.kls = 3
            if s.priv != 'M':       # <<KLE-CSR-llockerstatus>>: an instruction that modifies K(i) sets the field to Dirty
                for i, l in enumerate(s.L):
                    if (l.mdh, l.content) != lb[i] and s.lstat[i]: s.lstat[i] = 3
    # ---- CSR writes (<<KLE-CSR-kliobuflen>>, <<KLE-CSR-kliobuftop>>, <<KLE-CSR-klmaxiobuflen>>)
    def w_kliobuflen(s, v):
        if not s.zklio: return
        v = min(v, s.maxiobuf); s.iobuf[:v] = bytes(v); s.kliobuflen = v; s.kliobuftop = v
    def w_kliobuftop(s, v):
        if s.zklio: s.kliobuftop = min(v, s.kliobuflen)
    def w_maxiobuflen(s, v):
        if not s.zklio: return
        s.maxiobuf = max(16, min(v, s.maxiobuf_reset))
        if s.kliobuflen > s.maxiobuf: s.kliobuflen = s.kliobuftop = 0; s.iobuf = bytearray(len(s.iobuf))
    def r_maxiobuflen(s): return s.maxiobuf if s.zklio else 0
    # ---- serialized image
    def img(s, k):
        l = s.L[k]
        if getattr(l, 'img', None) is None: l.img = bytearray(s.image_end(k))
        return l.img
    def image_end(s, k): return size_of(s.md(k)) - 16
    def offset(s, md):
        if mdh_get(md, 'Version') == 3: return 0
        st = mdh_get(md, 'State')
        return 0 if st in PI_STATES else (48 if mdh_get(md, 'AuxDataLen') >= 2 else 16)
    def _export_open(s, k):
        KLE._export_open(s, k)
        l = s.L[k]; md = l.mdh
        if mdh_get(md, 'State') in (57, 59) and getattr(l, 'img', None) is None:
            im = bytearray(s.image_end(k)); o = s.offset(md); c1 = CONTENT[mdh_get(md, 'Machine')]
            if mdh_get(md, 'Version') != 3: im[o:o + c1] = v2b(getattr(l, 'skid', None) if mdh_get(md, 'KeyType') == 1 else l.content, c1)
            l.img = im; s.siv = toy_tag(l.content)
    def _mgmt(s, kd, immed, r=0, form='C', md=0):
        if immed == 58 and form != 'B':
            s.common(); k = s.tgt(kd, r)
            if k is not None: s.siv = s.impqual = s.siv2 = 0       # <<KLE-GR-exception-state-change>> zeroization
        return KLE.mgmt(s, kd, immed, r, form, md)
    def usage_gate(s, k):
        if s.debug:      # <<KLE-UsagePolicy>>: Debug needs bit 4 and, outside authenticated Debug, the bit of the mode
            up = mdh_get(s.md(k), 'UsagePolicy')
            if not (up >> 4 & 1) or not (s.debug_auth or up >> s.mode & 1): raise Trap('privilege_violation')
            return True       # shortcut: ExpirationDate is not evaluated under Debug in this model
        return KLE.usage_gate(s, k)
    def _complete(s, k, ml):
        l = s.L[k]; st = mdh_get(l.mdh, 'State')
        if st == 56 and mdh_get(l.mdh, 'KeyType') == 2 and s.rbg_dead and mdh_get(ml, 'State') in (56, 59, 60):
            s.start = 0; s.err(k, SE_INVALID); return
        if st in (58, 60) and getattr(l, 'img', None) is not None and mdh_get(l.mdh, 'Version') != 3:
            o = s.offset(l.mdh); c1 = CONTENT[mdh_get(l.mdh, 'Machine')]
            l.content = int.from_bytes(l.img[o:o + c1], 'little'); l.tag = s.siv
        if st == 56 and getattr(l, 'img', None) is not None:
            l.content = int.from_bytes(l.img[:CONTENT[mdh_get(l.mdh, 'Machine')]], 'little')
        r = KLE._complete(s, k, ml)
        m = s.md(k)
        if st in (56, 58) and 1 <= mdh_get(m, 'State') <= 55 and mdh_get(m, 'KeyType') == 1: s._resolve(k)
        if not s.config(s.md(k)) : s.L[k].img = None
        return r
    def _resolve(s, k):
        """<<KLE-GR-skid-resolution>>, <<KLE-GR-skid-policies>>: the key field holds the SKID until resolved."""
        l = s.L[k]; m = l.mdh; skid = l.content & mask(64); ent = s.sks.get(skid)
        if ent is None or mdh_get(m, 'Machine') not in ent['machines'] or mdh_get(m, 'MachinePolicy') & ~ent['pol']:
            s.err(k, SE_INVALID); return
        req = mdh_put(mdh_put(0, 'Locality', ent['loc']), 'UsagePolicy', ent.get('up', 0x1F))
        nm = narrow(m, req)
        if nm is None or mdh_get(m, 'SCProtection') < ent.get('minprot', 0): s.err(k, SE_PRIV_VIOLATION); return
        l.mdh = nm; l.skid = skid; l.content = ent['key']
    def _sysfmt_complete(s, k):
        """Toy GR72: S = tag(8) || payload; payload[:c1] is the key."""
        l = s.L[k]; im = bytes(s.img(k)); m = l.mdh; c1 = CONTENT[mdh_get(m, 'Machine')]
        pay = int.from_bytes(im[8:], 'little')
        if int.from_bytes(im[:8], 'little') != toy_tag(pay): s.err(k, SE_MGMT_AUTH); return
        if mdh_get(m, 'SCProtection') < s.fmt_min_prot: s.err(k, SE_PRIV_VIOLATION); return
        l.content = int.from_bytes(im[8:8 + c1], 'little')
        for n in ('Version', 'AuxDataLen'): m = mdh_put(m, n, 0)
        m = mdh_put(mdh_put(m, 'State', 1), 'AuxInfo', 0)
        l.mdh = m; l.img = None
    def size(s, kd=0, r=0, form='A', md=0):
        s._pre1()
        if form != 'A' and s.kleemu:
            m = md & (mask(64) if form == 'B' else mask(128)); st, se = mdh_get(m, 'State'), mdh_get(m, 'StateExtension')
            early = st >= 61 or (st == 0 and se) or mdh_get(m, 'Version') in (1, 2) or mdh_get(m, 'SCProtection') == 3 or mdh_get(m, 'KeyType') == 3
            if not early and mdh_get(m, 'Machine') not in CONTENT: raise IllegalInstruction('kleemulation')
        return KLE.size(s, kd, r, form, md)
    def avail(s, kd=0, r=0, form='A', md=0):
        s._pre1()
        if form != 'A' and s.kleemu:
            m = md & (mask(64) if form == 'B' else mask(128))
            early = mdh_get(m, 'Version') or mdh_get(m, 'SCProtection') == 3 or mdh_get(m, 'KeyType') == 3
            if not early and mdh_get(m, 'Machine') not in CONTENT: raise IllegalInstruction('kleemulation')
        return KLE.avail(s, kd, r, form, md)
    # ---- Locker checks of mv / load / store (<<KLE-mv-locker-checks>>)
    def _lock(s, inbound):
        k = None if s.nl == NONE else s.nl
        if k is not None: s._off(k)
        if k is None or mdh_get(s.md(k), 'State') == 0: return None
        if mdh_get(s.md(k), 'State') not in ((56, 58, 60) if inbound else (57, 59)) or s.start % 16: raise IllegalInstruction('locker checks')
        return k
    def _vec(s, vl, sew, vstart):
        if not s.vext or (vl * sew // 8) % 16 or (vstart * sew // 8) % 16: raise IllegalInstruction('vector operand')
    def _blk_in(s, k, data):
        e = s.image_end(k)
        if s.start < e: s.img(k)[s.start:s.start + 16] = data; s.start += 16
    def _blk_out(s, k):
        e = s.image_end(k)
        if s.start < e: b = bytes(s.img(k)[s.start:s.start + 16]); s.start += 16; return b
        return bytes(16)
    def gpr_in(s, v):
        s.common(); k = s._lock(True)
        if k is not None: s._blk_in(k, v2b(v, 16))
    def gpr_out(s):
        s.common(); k = s._lock(False)
        return 0 if k is None else int.from_bytes(s._blk_out(k), 'little')
    def vec_in(s, data, sew=32, vstart=0):
        vl = len(data) * 8 // sew; s._pre1(); s._vec(vl, sew, vstart); s.common(); k = s._lock(True)
        if k is None or vstart >= vl: return vstart
        while vstart < vl:
            s._blk_in(k, data[vstart * sew // 8:vstart * sew // 8 + 16]); vstart += 128 // sew
        return vstart
    def vec_out(s, vl, sew=32, vstart=0):
        s._pre1(); s._vec(vl, sew, vstart); s.common(); k = s._lock(False)
        n = (vl - vstart) * sew // 8
        if k is None or vstart >= vl: return bytes(max(n, 0))
        return b''.join(s._blk_out(k) for _ in range(n // 16))
    def _buf(s):
        if not s.zklio or s.kliobuflen == 0 or s.kliobuftop % 16: raise IllegalInstruction('KLIOBUF')
    def buf_in(s):
        s.common(); k = s._lock(True)
        if k is None: return
        s._buf()
        for j in range(0, s.kliobuftop, 16): s._blk_in(k, bytes(s.iobuf[j:j + 16]))
    def buf_out(s):
        s.common(); k = s._lock(False)
        if k is None:
            if s.zklio and s.kliobuflen: s.iobuf[:s.kliobuftop] = bytes(s.kliobuftop)
            return
        s._buf()
        for j in range(0, s.kliobuftop, 16): s.iobuf[j:j + 16] = s._blk_out(k)
    # ---- memory instructions
    def _mem_pre(s, mem, addr, xl, store):
        s.common()
        if s.nl != NONE and xl: raise IllegalInstruction('Xl != 0 with a locker')
        if s.nl != NONE and addr % 16: raise Trap('store_misaligned' if store else 'load_misaligned')
    def load(s, mem, addr, xl=0):
        s._mem_pre(mem, addr, xl, False)
        if s.nl == NONE:
            if xl == 0: s.start = 0; return
            s._iobuf_xfer(mem, addr, xl, False); return
        k = s._lock(True)
        if k is None: s.start = 0; return
        e = s.image_end(k)
        while s.start < e:
            for j in range(16): mem.check(addr + s.start + j, False)
            s.img(k)[s.start:s.start + 16] = mem.b[addr + s.start:addr + s.start + 16]; s.start += 16
        s.start = 0
    def store(s, mem, addr, xl=0):
        s._mem_pre(mem, addr, xl, True)
        if s.nl == NONE:
            if xl == 0: s.start = 0; return
            s._iobuf_xfer(mem, addr, xl, True); return
        k = s._lock(False)
        if k is None: s.start = 0; return
        e = s.image_end(k)
        while s.start < e:
            for j in range(16): mem.check(addr + s.start + j, True)
            mem.b[addr + s.start:addr + s.start + 16] = s.img(k)[s.start:s.start + 16]; s.start += 16
        s.start = 0
    def _iobuf_xfer(s, mem, addr, xl, store):
        if not s.zklio or s.kliobuflen == 0: raise IllegalInstruction('KLIOBUF unconfigured')
        n = min(xl, s.kliobuftop)
        for j in range(s.start, n):
            mem.check(addr + j, store)
            if store: mem.b[addr + j] = s.iobuf[j]
            else: s.iobuf[j] = mem.b[addr + j]
        s.start = 0
    # ---- kl.exec with transfer window (GR11-16, GR21, GR53)
    def execw(s, kd=0, r=0, form='A', data=None, halt_after=None):
        res = s._execw(kd, r, form, data, halt_after)
        if res in ('invalid', 'inert') or (isinstance(res, bytes) and False):   # GR35: zero the unwritten output window
            if form == 'D' and s.zklio and s.kliobuflen: s.iobuf[s.start:s.kliobuftop] = bytes(max(s.kliobuftop - s.start, 0))
            s.vout = bytes(len(data)) if data is not None else None
        return res
    def _execw(s, kd=0, r=0, form='A', data=None, halt_after=None):
        """data: Form A vector input (bytes).  Form D = substitution using the KLIOBUF [klstart, kliobuftop).
        Returns the output bytes (Form A) or 'ok', 'inert', 'invalid', 'halted'."""
        s.common(); k = s.tgt(kd, r)
        if k is None or mdh_get(s.md(k), 'State') == 0:
            s.start = 0; return bytes(len(data)) if data is not None and form == 'A' else 'inert'
        m = s.md(k)
        if s.config(m): raise Trap('privilege_violation')
        subst = form == 'D'
        if subst and s.zklio and s.kliobuflen == 0: raise IllegalInstruction('GR21 item 1')
        if not s.usage_gate(k): return 'expired'
        if mdh_get(m, 'State') != 2 or not s.machine_admits(k, None) or form not in ('A', 'D') or (subst and not s.zklio):
            s.err(k, SE_INVALID); return 'invalid'
        win = bytearray(s.iobuf[:s.kliobuftop]) if subst else bytearray(data)
        n = len(win)
        if s.start >= n: s.start = 0; return bytes(0) if subst else bytes(n)                                   # GR53.1
        if n % 16: s.err(k, SE_INVALID); return 'invalid'   # GR16, GR53.2
        if s.start % 16: s.err(k, SE_INVALID); return 'invalid'                                                  # GR53.3
        key = v2b(s.L[k].content, 16); out = bytearray(win); blocks = 0; j = s.start
        while j < n:
            if halt_after is not None and blocks == halt_after:
                s.start = j; r = bytes(out)
                if subst: s.iobuf[:n] = out
                return 'halted' if subst else ('halted', r)
            out[j:j + 16] = bytes(a ^ b for a, b in zip(win[j:j + 16], key)); j += 16; blocks += 1
        s.start = 0
        if subst: s.iobuf[:n] = out; return 'ok'
        return bytes(out)
    def execv(s, kd, tag):
        """Toy VERIFY Machine M_VER, State 2: a kl.exec compares tag (16 bytes) with the key in constant time; Success (54) or
        Failure (55), an outcome and not an error (<<KLE-MGR-config-data-error>>).  Returns the new State."""
        r = s.usage(kd, 0, None)
        if r != 'ok': return r
        l = s.L[kd]; ok = v2b(l.content, 16) == bytes(tag)
        l.mdh = mdh_put(l.mdh, 'State', 54 if ok else 55); return mdh_get(l.mdh, 'State')
    # ---- long-running operation (GR55-58): M_SIG State 3
    def lr(s, kd=0, budget=2):
        l0 = s.L[kd]
        r = s.usage(kd, 0, None)
        if r != 'ok' or mdh_get(s.md(kd), 'State') != 3 or mdh_get(s.md(kd), 'Machine') != M_SIG: return r
        l = s.L[kd]; l.steps = getattr(l, 'steps', 0) + budget
        if l.steps >= LR_STEPS: l.steps = 0; l.mdh = mdh_put(l.mdh, 'MachineUse', 0); return 'done'
        l.mdh = mdh_put(l.mdh, 'MachineUse', l.steps); return 'halted'
    def usage(s, kd, r, target):
        before = None if (s.tgt(kd, r) is None) else s.md(s.tgt(kd, r))
        res = KLE.usage(s, kd, r, target)
        if res == 'ok' and target is not None:
            l = s.L[s.tgt(kd, r)]; l.steps = 0
            if mdh_get(l.mdh, 'Machine') == M_SIG: l.mdh = mdh_put(l.mdh, 'MachineUse', 0)
        return res
    def clearads(s, kd, r=0, form='A'):
        KLE.clearads(s, kd, r, form)
        k = s.tgt(kd, r)
        if k is not None and mdh_get(s.md(k), 'Machine') == M_SIG and mdh_get(s.md(k), 'State') in (2, 3): s.L[k].steps = 0
    def _clone(s, d, src):
        KLE.clone(s, d, src)
        d, src = (s.nl if d == 'NL' else d), (s.nl if src == 'NL' else src)
        if d != src and d != NONE and mdh_get(s.md(d), 'Machine') == M_SIG and mdh_get(s.md(d), 'State') in (2, 3):
            s.L[d].steps = 0; s.L[d].mdh = mdh_put(s.md(d), 'MachineUse', 0)
    # ---- kl.derive (GR38-GR44)
    def derive(s, d, src, length):
        s.common()
        d, src = (s.nl if d == 'NL' else d), (s.nl if src == 'NL' else src)
        if d == src and d != NONE: raise IllegalInstruction('same locker')
        if d == NONE or src == NONE: return 'inert'
        ms, md_ = s.md(src), s.md(d)
        if mdh_get(ms, 'State') == 0 or mdh_get(md_, 'State') == 0: return 'inert'
        for k in (src, d):                                    # GR38: State class, source first
            if s.config(s.md(k)): raise Trap('privilege_violation')
        for k in (src, d):
            if not (mdh_get(s.md(k), 'UsagePolicy') >> s.mode & 1): raise Trap('privilege_violation')
        for k in (src, d):
            if s.zk and mdh_get(s.md(k), 'ExpirationDate'):
                if s.clock is None: raise Trap('clock_unavailable')
                if min(max(s.clock, 0), mask(20)) >= mdh_get(s.md(k), 'ExpirationDate'): s.err(k, SE_EXPIRED); return 'expired'
        sm, dm = mdh_get(ms, 'Machine'), mdh_get(md_, 'Machine')
        sst, dst = mdh_get(ms, 'State'), mdh_get(md_, 'State')
        # GR40 1: source endpoint
        if not (sst == 2 and sm in (M_KEM, M_ENC)) or mdh_get(ms, 'KeyType') == 1 and False:
            s.err(src, SE_INVALID); return 'invalid'
        # 2: destination endpoint (key field in Ready, never SKID; hash input in State 2)
        keyf = dst == 1 and dm in (M_ENC, M_KEY, M_KEY32) and mdh_get(md_, 'KeyType') != 1
        hin = dst == 2 and dm == M_HASH
        if not (keyf or hin): s.err(d, SE_INVALID); return 'invalid'
        # 3: admitted pair (GR43 secret -> key field or hash input, restricted; GR44 cipher output -> key field, unrestricted)
        if sm == M_ENC and not keyf: s.err(d, SE_INVALID); s.err(src, SE_INVALID); return 'invalid'
        restricted = sm == M_KEM
        dl = CONTENT[dm] if keyf else None
        eff = min(length, dl) if keyf else length
        # 4: effective length meets the destination constraints
        if hin and eff % 16: s.err(d, SE_INVALID); return 'invalid'
        # 5: whole-value destinations
        if keyf and (length < dl or (sm == M_KEM and CONTENT[M_KEM] < dl)): s.err(d, SE_INVALID); return 'invalid'
        if hin and sm == M_KEM and length != CONTENT[M_KEM]: s.err(d, SE_INVALID); return 'invalid'
        # 6: source supplies the suffix: both toy sources supply any length
        if s.start != 0: s.err(d, SE_INVALID); return 'invalid'
        if restricted and eff:                                # GR41
            if mdh_get(md_, 'SCProtection') < mdh_get(ms, 'SCProtection'): s.err(d, SE_PRIV_VIOLATION); return 'pv'
            nm = narrow(md_, ms)
            if nm is None: s.err(d, SE_PRIV_VIOLATION); return 'pv'
            md_ = nm
        if sm == M_KEM: val = v2b(s.L[src].content, 32)
        else: val = b''.join(ks_block(s.L[src].content, j) for j in range((eff + 15) // 16))
        val = val[:eff]
        if keyf: s.L[d].content = int.from_bytes(val + bytes(dl - len(val)), 'little')
        else: s.L[d].content = int.from_bytes(val, 'little')
        s.L[d].mdh = md_
        return 'ok'
    # ---- reset (<<KLE-out-of-reset-unpriv>>)
    def reset(s):
        for k in range(32): s.free(k)
        s.pool = []; s.nl = NONE; s.start = 0; s.slots = s.slots + 0
        s.kliobuflen = s.kliobuftop = 0; s.iobuf = bytearray(len(s.iobuf)); s.siv = s.impqual = s.siv2 = 0
        if not s.csk_hardwired: s.csk = False

# ---- encodings (<<KLE-instruction-exec>>, <<KLE-instruction-mv>>, <<KLE-instruction-derive>>, <<KLE-instruction-clone>>)
def enc_rtype(rd, rs1, rs2, b25=0, r=0, b27=0, form=0, f2=0):
    return 0x0F | rd << 7 | 4 << 12 | rs1 << 15 | rs2 << 20 | b25 << 25 | r << 26 | b27 << 27 | form << 28 | f2 << 30
def decode(w, xlen=64):
    """Decode a funct3=4 MISC-MEM word with funct2 in {0, 2}.  Returns (name, fields) or raises IllegalInstruction."""
    if w & 127 != 0x0F or (w >> 12) & 7 != 4: raise IllegalInstruction('not a KLE word')
    rd, rs1, rs2 = w >> 7 & 31, w >> 15 & 31, w >> 20 & 31
    f2, form = w >> 30 & 3, w >> 28 & 3
    if f2 == 0:
        if w >> 27 & 1: raise NotImplementedError('size/avail')
        if w >> 25 & 1: raise IllegalInstruction('bit 25 reserved')
        r = w >> 26 & 1
        if form == 3 and rd:                       # kl.mvin / kl.mvout
            if r: raise IllegalInstruction('r != 0 in mv')
            ok = {1: (0, None), 2: (0, None), 3: (0, 0), 5: (None, 0), 6: (None, 0), 7: (0, 0)}
            if rd not in ok: raise IllegalInstruction('reserved rd')
            a, b = ok[rd]
            if (a is not None and rs1 != a) or (b is not None and rs2 != b): raise IllegalInstruction('reserved rs')
            if rd == 1 and rs2 % (2 if xlen == 64 else 4): raise IllegalInstruction('GR2 pair/quartet')
            if rd == 5 and rs1 % (2 if xlen == 64 else 4): raise IllegalInstruction('GR2 pair/quartet')
            return ({1: 'mvin_x', 2: 'mvin_v', 3: 'mvin_buf', 5: 'mvout_x', 6: 'mvout_v', 7: 'mvout_buf'}[rd], dict(rs1=rs1, rs2=rs2))
        if (form == 1 and rd) or (form == 2 and rs2) or (form == 3 and (rd or rs2)): raise IllegalInstruction('unused field')
        return ('exec', dict(form='ABCD'[form], rd=rd, kn=rs1, rs2=rs2, r=r))
    if f2 == 2:
        R, T = w >> 25 & 3, w >> 27 & 3
        if R == 3: raise IllegalInstruction('R = 11')
        return (['clone', 'rename', 'swap', 'derive'][T], dict(kd=rd, ks=rs1, rs2=rs2, R=R))
    raise NotImplementedError('funct2 %d' % f2)

def vec_mdh_ok(instr, vl, sew, vstart):
    """GR6, GR7 for the vector MDH operand."""
    if vl * sew < 128: raise IllegalInstruction('GR6')
    if vstart != 0 and instr in ('getmdv', 'restrictv', 'size_C', 'avail_C', 'setst_C', 'mgmt_C'): raise IllegalInstruction('GR7')
