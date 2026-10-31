"""Locker model of the symmetric-cipher Machines (ECB, CBC, CFB, OFB, CTR, XCTR, XEX), derived from
Zkl-ISA-machines.adoc (KLE-ECB-mode, KLE-chaining, CTR/XCTR, KLE-XEX-XTS-modes), Machine Rules MR1-MR19 and
General Rules GR20-GR24, GR32-GR35, GR45-GR52 of Zkl-ISA-unpriv.adoc.  Bytes/ints as in common.py.

Locker(machine, policy, key, key2=None, skid=False) -> locker just provisioned (State Ready); an invalid PI
(policy 0, XEX key2 == key1) leaves an Error State Invalid.
  .setst(immed, form='A', xs=None, vec=None)  kl.setst; an inadmissible one makes the locker Error State Invalid
  .exec(inp, kllen, klstart=0, stop=None)     kl.exec -> (out, new_klstart); inp int of kllen bits (None: output-only);
                                              stop: halt after that many interruption points (models an interrupt)
  .derive_out(n) / .load_key(data, length)    kl.derive source (keystream) / destination (`key`, XEX `key1||key2`)
  .export() / Locker.import_(mdh, content)    abstract SCC: (MDH, Content1 bytes)
"""
from math import gcd
from common import *

TYPES = {0: 'AES128', 1: 'AES192', 2: 'AES256', 3: 'SM4'}
MODES = {0: 'ECB', 1: 'CBC', 2: 'CFB', 3: 'OFB', 4: 'CTR', 5: 'XCTR', 6: 'XEX'}
def machine(typ, mode): return typ << 4 | mode          # Type [11:4], Mode [3:0]
S_READY, S_OPERATE, S_ENC, S_DEC, S_AUX, S_SUCCESS, S_STEAL = 1, 2, 7, 8, 13, 54, 66
KEYLEN = {'AES128': 16, 'AES192': 24, 'AES256': 32, 'SM4': 16}
VALID_STATES = {'ECB': (1, 7, 8), 'CBC': (1, 7, 8), 'CFB': (1, 7, 8, 13), 'OFB': (1, 2), 'CTR': (1, 2), 'XCTR': (1, 2),
                'XEX': (1, 7, 8, 54)}
def pad16(n): return (n + 15) // 16 * 16

class Locker:
    def __init__(self, mach, policy, key, key2=None, skid=False, aux=None):
        self.m = mach; self.cipher = TYPES[mach >> 4]; self.mode = MODES[mach & 15]
        self.policy = policy; self.kl = KEYLEN[self.cipher]; self.skid = skid
        self.err = None; self.key, self.key2 = key, key2; self.state = S_READY; self.enter_ready()
        self.aux = aux if aux is not None else (128 if self.mode == 'CFB' else 0); self.u = self.aux & 255
        if self.mode == 'CFB' and not (0 < self.u <= 128 and self.aux >> 8 == 0): self.invalid()   # u = AuxInfo[7:0], fixed at provisioning
        if policy == 0 or (self.mode == 'XEX' and key2 is not None and key == key2): self.invalid()

    def enc(self, k, b): return cipher_enc(self.cipher, k, b)
    def dec(self, k, b): return cipher_dec(self.cipher, k, b)
    def invalid(self): self.err = SE_INVALID; self.state = 0; self.key = self.key2 = None
    def inert(self): return self.err is not None
    def enter_ready(self):
        self.iv = 0; self.ctr = 1 if self.mode == 'XCTR' else 0; self.mask = 0; self.steal = 0
    def mdh(self):
        return mdh_pack(Machine=self.m, MachinePolicy=self.policy, State=0 if self.inert() else self.state,
                        StateExtension=self.err or self.steal, KeyType=1 if self.skid else 0, AuxInfo=self.aux)

    # ---- kl.setst
    def allowed(self, s):
        m, st = self.mode, self.state
        if m in ('ECB', 'CBC'): return s in (S_ENC, S_DEC) and st in (S_READY, S_ENC, S_DEC)
        if m == 'CFB':
            return s in (S_ENC, S_DEC) and st in (S_READY, S_ENC, S_DEC)
        if m in ('OFB', 'CTR', 'XCTR'):
            if s == S_AUX: return m != 'OFB' and st in (S_READY, S_OPERATE)
            return s == S_OPERATE and st in (S_READY, S_OPERATE)
        if m == 'XEX': return s in (S_ENC, S_DEC) and st in (S_READY, S_ENC, S_DEC)
        return False

    def setst(self, immed, form='A', xs=None, vec=None):
        if self.inert(): return
        s, m = immed, self.mode
        if s == 0: self.err = SE_UNCONFIGURED; self.state = 0; self.key = self.key2 = None; return
        if s == S_STEAL:
            if m != 'XEX' or self.state != S_DEC or form != 'A' or self.steal or not self.policy & 2: return self.invalid()   # MR1
            self.mask = update_mask(self.mask, self.cipher == 'SM4'); self.steal = 1; return   # an operation
        if s == S_READY:
            if form != 'A': return self.invalid()
            self.state = S_READY; self.enter_ready(); return
        if s in (S_SUCCESS, 55) or not self.allowed(s): return self.invalid()
        if s in (S_ENC, S_DEC, S_OPERATE) and not self.policy & {S_ENC: 1, S_DEC: 2, S_OPERATE: 3}[s]:
            return self.invalid()                                   # MR1
        if s == S_AUX:
            if form not in ('A', 'B'): return self.invalid()
            self.ctr = bin_(0 if form == 'A' else xs, 32 if m == 'CTR' else 64); return   # operation
        if m == 'ECB':
            if form != 'A': return self.invalid()
            self.state = s; return
        if form == 'A': inp = 0
        elif form == 'C': inp = vec
        elif form == 'B' and m in ('CTR', 'XCTR', 'XEX'): inp = xs
        else: return self.invalid()
        if m in ('CBC', 'CFB', 'OFB'): self.iv = inp & MASK128
        elif m == 'CTR': self.iv = inp & mask(96)
        elif m == 'XCTR': self.iv = inp & MASK128
        elif m == 'XEX': self.steal = 0; self.mask = b2v(self.enc(self.key2, v2b(inp & MASK128, 16)))
        self.state = s

    # ---- kl.exec
    def exec(self, inp, kllen, klstart=0, stop=None):
        if self.inert(): return 0, 0
        m, st = self.mode, self.state
        okst = st in (S_ENC, S_DEC) if m in ('ECB', 'CBC', 'CFB', 'XEX') else st == S_OPERATE
        gran = 1 if m == 'CFB' else 16
        if okst and not self.policy & {S_ENC: 1, S_DEC: 2, S_OPERATE: 3}[st]: okst = False       # MR1: State disabled by MachinePolicy
        if not okst: self.invalid(); return 0, 0
        if klstart * 8 >= kllen: return 0, 0                        # GR52 item 1: empty window (KLLEN = 0 too)
        if kllen % (8 * gran): self.invalid(); return 0, 0          # GR52 item 2 / MR6: output window zeroed
        single = m == 'XEX' and self.steal                           # one block, only interruption point 0
        ip = kllen // 8 if single else (self.u * 8 // gcd(8, self.u) // 8 if m == 'CFB' else 16)
        if klstart % ip: self.invalid(); return 0, 0
        if m == 'CFB': return self._cfb(inp, kllen, klstart, stop)
        nblk = 1 if single else kllen // 128
        i = klstart // 16; out = 0; n = 0
        while i < nblk:
            if stop is not None and n == stop: return out, i * 16
            o = self._ks() if m in ('CTR', 'XCTR', 'OFB') else self._blk((inp >> (128 * i)) & MASK128)
            out |= o << (128 * i); i += 1; n += 1
        return out, 0

    def _ks(self):
        m = self.mode
        if m == 'OFB': self.iv = b2v(self.enc(self.key, v2b(self.iv, 16))); return self.iv
        if m == 'CTR': blk = (bswap(self.ctr, 4) << 96) | self.iv; self.ctr = (self.ctr + 1) & mask(32)
        else: blk = self.iv ^ self.ctr; self.ctr = (self.ctr + 1) & mask(64)
        return b2v(self.enc(self.key, v2b(blk, 16)))

    def _blk(self, x):
        m, st = self.mode, self.state
        E = lambda b: b2v(self.enc(self.key, v2b(b, 16)))
        D = lambda b: b2v(self.dec(self.key, v2b(b, 16)))
        if m == 'ECB': return E(x) if st == S_ENC else D(x)
        if m == 'CBC':
            if st == S_ENC: self.iv = E(x ^ self.iv); return self.iv
            o = D(x) ^ self.iv; self.iv = x; return o
        sm4 = self.cipher == 'SM4'                                   # XEX
        if st == S_ENC: o = self.mask ^ E(x ^ self.mask); self.mask = update_mask(self.mask, sm4); return o
        o = self.mask ^ D(x ^ self.mask)
        if self.steal == 0: self.mask = update_mask(self.mask, sm4)
        elif self.steal == 1: self.mask = update_mask_inv(self.mask, sm4); self.steal = 2     # StealSkip -> StealBack
        else: self.state = S_SUCCESS; self.steal = 0                                          # StealBack -> Success
        return o

    def _cfb(self, inp, kllen, klstart, stop):
        u = self.u; n = kllen // u; nb = kllen // 8
        X = brev8(inp, nb); Y = 0; j = klstart * 8 // u; pts = 0
        while j < n:
            if stop is not None and (j * u) % 8 == 0 and j * u > klstart * 8:
                pts += 1
                if pts == stop: return brev8(Y, nb), j * u // 8
            W = brev8(self.iv, 16); Eb = brev8(b2v(self.enc(self.key, v2b(self.iv, 16))), 16)   # W, Q from the current IV
            Xj = sl(X, (j + 1) * u - 1, j * u); Yj = Xj ^ (Eb & mask(u))
            C = Yj if self.state == S_ENC else Xj
            self.iv = brev8((C << (128 - u)) | (W >> u), 16)
            Y |= Yj << (j * u); j += 1
        return brev8(Y, nb), 0

    # ---- kl.derive
    def derive_out(self, nbytes):
        if self.inert() or self.state != S_OPERATE or self.mode not in ('OFB', 'CTR', 'XCTR'): self.invalid(); return None
        out = b''
        while len(out) < nbytes: out += v2b(self._ks(), 16)         # whole blocks, rest of the last one discarded
        return out[:nbytes]

    def load_key(self, data, length):
        need = self.kl * (2 if self.mode == 'XEX' else 1)
        if self.inert() or self.state != S_READY or self.skid or length < need: self.invalid(); return False
        k = data[:need]
        if self.mode == 'XEX':
            if k[:self.kl] == k[self.kl:]: self.invalid(); return False
            self.key, self.key2 = k[:self.kl], k[self.kl:]
        else: self.key = k
        self.enter_ready(); return True

    # ---- export / import
    def content1(self):
        c = self.key + (self.key2 or b''); m = self.mode
        if m in ('CBC', 'OFB'): c += v2b(self.iv, 16)
        if m == 'CFB': c += v2b(self.iv, 16)
        if m == 'CTR': c += v2b(self.iv, 12) + v2b(self.ctr, 4)
        if m == 'XCTR': c += v2b(self.iv, 16) + v2b(self.ctr, 8)
        if m == 'XEX': c += v2b(self.mask, 16)
        return c + bytes(pad16(len(c)) - len(c))
    def export(self): return self.mdh(), self.content1()

    @classmethod
    def import_(cls, mdh, content):
        f = mdh_unpack(mdh); L = object.__new__(cls)
        L.m = f['Machine']; L.cipher = TYPES[L.m >> 4]; L.mode = MODES[L.m & 15]; L.kl = k = KEYLEN[L.cipher]
        L.policy = f['MachinePolicy']; L.state = f['State']; L.err = None; L.skid = False; L.key2 = None
        L.enter_ready(); se = f['StateExtension']
        bad = L.policy == 0 or (se and not (L.mode == 'XEX' and L.state == S_DEC and se in (1, 2)))
        bad |= L.state not in VALID_STATES[L.mode]
        L.steal = 0 if bad else se
        L.key = content[:k]; p = k
        if L.mode == 'XEX': L.key2 = content[p:p + k]; p += k; bad |= L.key == L.key2
        if L.mode in ('CBC', 'OFB', 'CFB'): L.iv = b2v(content[p:p + 16]); p += 16
        L.aux = f['AuxInfo']; L.u = L.aux & 255
        if L.mode == 'CFB': bad |= not (0 < L.u <= 128 and L.aux >> 8 == 0)
        if L.mode == 'CTR': L.iv = b2v(content[p:p + 12]); L.ctr = b2v(content[p + 12:p + 16])
        if L.mode == 'XCTR': L.iv = b2v(content[p:p + 16]); L.ctr = b2v(content[p + 16:p + 24])
        if L.mode == 'XEX': L.mask = b2v(content[p:p + 16])
        if bad: L.invalid()
        return L

def pi_size(mach, keytype=0):
    k = KEYLEN[TYPES[mach >> 4]] if keytype == 0 else 8
    return pad16(16 + k + (k if mach & 15 == 6 and keytype == 0 else 0))
