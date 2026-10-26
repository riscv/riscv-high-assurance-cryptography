"""Locker-level SCC: KLE2 (mgmt_ext.py) with the real SCC cryptography of scc_core.py instead of the toy tag.
API: SCCKLE(csk=CSKV, lst=[11 x 128-bit], impq=IMPQUAL, **KLE kwargs); k.install(i, mdh, c1, c2) puts a Valid locker;
k.content(i) -> (c1 bytes, c2 bytes); with ecb_machines(): ... makes Machines 0x00 (16-byte key) and 0x20 (32-byte key)
known to the model (the toy Machine 0x20 = M_HASH is hidden meanwhile).  Imports/exports use KLE2's image buffer:
img = SIV [IMPQUAL SIV2] Content1 [Content2], read/written by gpr_out/gpr_in/vec_*."""
import os, sys, contextlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
import mgmt_model
from mgmt_ext import *
from scc_core import *

@contextlib.contextmanager
def ecb_machines():
    old = dict(mgmt_model.CONTENT); mgmt_model.CONTENT.clear(); mgmt_model.CONTENT.update({0x00: 16, 0x20: 32})
    try: yield
    finally: mgmt_model.CONTENT.clear(); mgmt_model.CONTENT.update(old)

class SCCKLE(KLE2):
    def __init__(s, csk=None, lst=None, impq=None, **kw):
        KLE2.__init__(s, **kw)
        s.cskv = csk if csk is not None else b2v(bytes(range(32)))
        s.lst = list(lst) if lst is not None else [b2v(bytes([0x40 + j]) * 16) for j in range(11)]
        s.impq = impq if impq is not None else scc_impqual(0x1111, 0x2222, 0x3333)
    def eff(s): return [s.conf(j) for j in range(11)]
    def install(s, k, mdh, c1, c2=b''):
        l = s.L[k]; l.mdh = mdh; l.c1 = c1; l.c2 = c2; l.content = int.from_bytes(c1, 'little'); l.slot = True; l.img = None
    def content(s, k): l = s.L[k]; return l.c1, l.c2
    def _export_open(s, k):
        pre = s.md(k); st = mdh_get(pre, 'State'); l = s.L[k]
        KLE2._export_open(s, k)
        if 1 <= st <= 55 and mdh_get(s.md(k), 'State') == 57 and mdh_get(pre, 'Version') != 3:
            l.img = bytearray(scc_export(dict(mdh=pre, c1=l.c1, c2=l.c2), s.cskv, s.eff(), s.impq)[16:])
    def _complete(s, k, ml):
        l = s.L[k]; m = l.mdh; st = mdh_get(m, 'State'); mst = mdh_get(ml, 'State')
        if st in (57, 58) and mdh_get(m, 'Version') != 3 and getattr(l, 'img', None) is not None and 1 <= mst <= 55:
            full = v2b(m, 16) + bytes(l.img)
            status, R = scc_import(full, s.cskv, s.eff(), s.impq, s.max_ads, ml_state=mst)
            s.start = 0
            if status != 'ok': s.err(k, SE_MGMT_AUTH); return
            l.mdh = R['mdh']; l.c1, l.c2 = R['c1'], R['c2']; l.content = int.from_bytes(R['c1'], 'little'); l.img = None; return
        return KLE2._complete(s, k, ml)
