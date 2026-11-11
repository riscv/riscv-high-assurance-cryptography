"""Unified AEAD protocol; reuse the existing cryptographic cores.

The instruction interface uses aead_model's bit-valued operands.  The common
driver below uses no algorithm IDs. Raw Content import assumes SCC authentication;
the KAT separately checks authentication of the public counter prefix and MDH
`MachineUse` flags.
"""
import hmac

from common import b2v, v2b, mask, cat, bswap, montmul
from aead_model import (Base, GCM, GCM_IV, GCMSIV, OCB, OCB_NONCE, Inv, need,
                        ntz, pad10, READY, ABSORB, LAST, ENC, DEC, ELB, DLB,
                        ETF, DTF, SAV, SAV2, SUCCESS, FAILURE, INV, MAX_BLOCKS)
from sponge_model import Locker

PRE, PRELAST = 17, 18
TAG_RECEIVED, AD_ABSORBED, SIV_GENERATED, DATA_ABSORBED = 1, 2, 4, 8


class UnifiedAEAD(Base):
    """GCM, GCM-SIV, OCB, or Ascon with the common AEAD state protocol.

    preset: GCM's 96-bit IV, OCB's (value, bit length), or Ascon's nonce bytes.
    mask_key: Ascon nonce-masking key.  No secret-dependent descriptor fields.
    """
    B = 128
    EXF = {SAV: 'B', SAV2: 'B', ABSORB: 'B', LAST: 'B', PRE: 'B',
           PRELAST: 'B', ENC: 'A', DEC: 'A', ELB: 'A', DLB: 'A',
           ETF: 'C', DTF: 'D'}
    GATE = {SAV2: 1, PRE: 0, PRELAST: 0, ENC: 0, ELB: 0, ETF: 0,
            DEC: 1, DLB: 1, DTF: 1}

    def __init__(self, family, key, policy=None, tag_len_p=128,
                 cipher='AES128', preset=None, mask_key=None):
        if family not in ('GCM', 'GCM-SIV', 'OCB', 'Ascon'):
            raise ValueError('unsupported AEAD family')
        if cipher not in ('AES128', 'AES192', 'AES256', 'SM4'):
            raise ValueError('unsupported cipher')
        if family in ('GCM-SIV', 'OCB') and cipher == 'SM4':
            raise ValueError('no standardized SM4 profile for this family')
        if family == 'GCM-SIV' and len(key) not in (16, 32):
            raise ValueError('GCM-SIV requires a 128- or 256-bit key')
        if len(key) != (16 if cipher in ('AES128', 'SM4') else 24 if cipher == 'AES192' else 32):
            raise ValueError('key length does not match cipher')
        if family == 'Ascon' and (len(key) != 16 or preset is not None and len(preset) != 16
                                  or mask_key is not None and len(mask_key) != 16):
            raise ValueError('Ascon keys and nonces have 128 bits')
        if family == 'GCM-SIV' and preset is not None or mask_key is not None and (family != 'Ascon' or preset is not None):
            raise ValueError('unsupported nonce variant')
        if preset is not None and family == 'GCM' and not 0 <= preset < 1 << 96:
            raise ValueError('preset GCM IV has 96 bits')
        if preset is not None and family == 'OCB' and not 6 <= preset[1] <= 120:
            raise ValueError('preset OCB nonce length outside [6,120]')
        self.family, self.CIPHER, self.preset, self.mask_key = family, cipher, preset, mask_key
        self.machine_use = 0
        self.DEC_ONLY = preset is not None
        self.NOKEYDER = self.DEC_ONLY or mask_key is not None
        self.glog, self.two_pt = (0 if family == 'Ascon' else 3), family == 'GCM-SIV'
        super().__init__(key, policy, tag_len_p)

    def tlps(self):
        if self.family == 'GCM': return (64, 96, 104, 112, 120, 128)
        if self.family == 'OCB': return (64, 96, 128)
        if self.family == 'Ascon': return tuple(range(64, 129, 8))
        return (128,)

    def getinfo(self):
        if self.st == INV: return 0
        return self.glog | int(self.two_pt) << 4

    @property
    def flags(self):
        return self.machine_use & 15

    @flags.setter
    def flags(self, value):
        self.machine_use = (self.machine_use & ~15) | value

    def header_widths(self):
        """Public prefix of the Content: only the fields this Machine uses."""
        if self.family == 'GCM': return (64, 64, 8, 120) if self.DEC_ONLY else (64, 64, 16, 8, 104)
        if self.family == 'GCM-SIV': return (64, 64, 8, 120)
        return (8, 120)

    def header(self):
        if self.family == 'GCM' and not self.DEC_ONLY: return (self.ad_len, self.payload_len, self.nonce_len, self.lbl, 0)
        if self.family in ('GCM', 'GCM-SIV'): return (self.ad_len, self.payload_len, self.lbl, 0)
        return (self.lbl, 0)

    def _ready(self):
        self.ad_len = self.payload_len = self.nonce_len = self.lbl = 0
        self.machine_use = 0
        self.received_tag = self.ad_hash = 0
        self.klstart = 0
        if self.family == 'GCM':
            args = dict(policy=self.policy, cipher=self.CIPHER, tag_len_p=self.tag_len_p)
            self.core = GCM(self.key, **args) if self.preset is None else GCM_IV(self.key, self.preset, **args)
        elif self.family == 'GCM-SIV': self.core = GCMSIV(self.key, self.policy, self.CIPHER)
        elif self.family == 'OCB':
            self.core = OCB(self.key, self.policy) if self.preset is None else OCB_NONCE(self.key, self.preset, self.policy)
        else:
            kind = 'ASCON-AEAD128_NONCE' if self.DEC_ONLY else 'ASCON-AEAD128_NONCE_MASK' if self.mask_key is not None else 'ASCON-AEAD128'
            self.core = Locker(kind, policy=self.policy, key=self.key, nonce=self.preset or b'',
                               K2=self.mask_key or b'', tag_len_p=self.tag_len_p)

    def _fail(self):
        super()._fail()
        self.core = self.mask_key = self.preset = None
        self.ad_len = self.payload_len = self.received_tag = self.ad_hash = 0
        self.nonce_len = self.lbl = 0
        self.machine_use = 0

    def _noexec(self, st): return st in (LAST, PRELAST, ELB, DLB) and self.lbl == 0

    def _setup(self, value=0):
        c = self.core
        if self.family == 'GCM':
            if self.DEC_ONLY: c.setst(ABSORB)
        elif self.family == 'GCM-SIV': c.setst(SAV, 'C', inp=value)
        elif self.family == 'OCB':
            if not self.DEC_ONLY: c.exec('B', value, (c.nonce_len + 7) // 8 * 8)
            c.setst(ABSORB, 'B', self.tag_len_p)
        else:
            c.setst(ABSORB, 'A' if self.DEC_ONLY else 'C', inp=v2b(value, 16))
        need(c.st != INV and not (self.family == 'Ascon' and c.is_error()))

    def setst(self, st, form='A', xs=0, inp=0):
        if self.st == INV: return
        try:
            cur = self.st
            if st == READY:
                need(form == 'A'); self.st = READY; self._ready(); return
            need(cur not in (SUCCESS, FAILURE))
            if st in self.GATE: need(self.policy >> self.GATE[st] & 1)
            if st == SAV:
                need(not self.DEC_ONLY and cur in (READY, SAV) and self._formok('B', form, xs, inp))
                need(8 <= xs <= 8192 and xs % 8 == 0 if self.family == 'GCM' else
                     xs == 96 if self.family == 'GCM-SIV' else 6 <= xs <= 120 if self.family == 'OCB' else xs == 128)
                self.nonce_len, self.flags = xs, 0
                if self.family in ('GCM', 'OCB'): self.core.setst(SAV, 'B', xs)
            elif st == ABSORB:
                need(self.DEC_ONLY and cur == READY and form == 'A'); self._setup()
            elif st == SAV2:
                need(cur == ABSORB and not self.flags & (AD_ABSORBED | TAG_RECEIVED)
                     and form == 'B' and xs == self.tag_len_p)
            elif st in (LAST, PRELAST, ELB, DLB):
                need(cur == {LAST: ABSORB, PRELAST: PRE, ELB: ENC, DLB: DEC}[st])
                need(self._formok('B', form, xs, inp) and 0 <= xs <= 128 and xs % (1 << self.glog) == 0)
                # Xs = 0 only if nothing of this AD, resp. PT or CT, was committed
                need(xs or not (self.flags & AD_ABSORBED if st == LAST else self.payload_len or self.flags & DATA_ABSORBED))
                self.lbl = xs; self.st = st
                if xs == 0: self._final_piece(0)
                return
            elif st in (PRE, ENC, DEC):
                need(cur == LAST and self.lbl == 0 and form == 'A')
                need(st == DEC if self.flags & TAG_RECEIVED else st == PRE if self.two_pt else st == ENC)
                if self.family == 'OCB': self.core._enter(DEC if st == DEC else ENC, 0, 0)
                if self.family == 'Ascon': self.core.xw(4, 1 << 63)
            else: need(False)
            self.st = st
        except Inv: self._fail()

    def _add(self, field, n):
        if self.family == 'OCB': need(self.core.index <= MAX_BLOCKS)    # OCB bounds lengths by index alone
        if self.family not in ('GCM', 'GCM-SIV'): return              # OCB and Ascon keep no length counters
        limit = mask(64)
        if self.family == 'GCM' and field != 'ad_len': limit = (1 << 39) - 256
        elif self.family == 'GCM-SIV': limit = 1 << 39
        v = getattr(self, field) + n
        need(v <= limit)
        setattr(self, field, v)

    def _ad(self, x, n):
        c = self.core
        if self.family in ('GCM', 'GCM-SIV'): c.absorb(x)
        elif self.family == 'OCB':
            c.offset ^= c.L[ntz(c.index)] if n == 128 else c.Ls
            c.hash_A ^= c.E((x if n == 128 else pad10(x, n)) ^ c.offset)
            c.index += int(n == 128)
        else:
            c.xw(0, x); c.xw(1, x >> 64)
            if n == 128: c.perm(8)

    def _payload(self, x, n):
        c, dec = self.core, self.st in (DEC, DLB)
        if self.st in (PRE, PRELAST): c.absorb(x); return 0
        if self.family == 'GCM':
            c.ctr(); y = (x ^ c.E(c.J0)) & mask(n); c.absorb(x if dec else y)
        elif self.family == 'GCM-SIV':
            y = (x ^ c._ks()) & mask(n); c.absorb(y if dec else x)
        elif self.family == 'OCB':
            if n == 128:
                c.offset ^= c.L[ntz(c.index)]
                y = c.offset ^ (c.D if dec else c.E)(x ^ c.offset)
                c.csum ^= y if dec else x; c.index += 1
            else:
                c.offset ^= c.Ls; y = (x ^ c.E(c.offset)) & mask(n)
                c.csum ^= pad10(y if dec else x, n)
        else:
            rate = c.s & mask(128); y = (rate ^ x) & mask(n)
            c.s = (c.s & ~mask(n)) | (x if dec else y)
            if n == 128: c.perm(8)
        return y

    def _consume(self, x, n):
        if self.st in (ABSORB, LAST):
            self._add('ad_len', n); self._ad(x, n); self.flags |= AD_ABSORBED; return 0
        self._add('payload_len', n)
        if self.family not in ('GCM', 'GCM-SIV'): self.flags |= DATA_ABSORBED    # data_len stands in for it
        return self._payload(x, n)

    def _final_piece(self, x):
        st, n, c = self.st, self.lbl, self.core
        out = self._consume(x & mask(n), n) if n else 0
        if st == LAST:
            if self.family == 'Ascon' and self.flags & AD_ABSORBED:
                c.xw(0, 1 << (n % 128)); c.xw(1, (1 << (n % 128)) >> 64); c.perm(8)
            if self.two_pt: self.ad_hash = c.tmp
        else:
            if self.family == 'Ascon':
                c.xw(0, 1 << (n % 128)); c.xw(1, (1 << (n % 128)) >> 64)
            self.st = DTF if st == DLB else ETF
        self.lbl = 0
        return out

    def _tag(self):
        c = self.core
        if self.family == 'GCM':
            c.absorb(cat((bswap(self.payload_len, 8), 64), (bswap(self.ad_len, 8), 64)))
            j0 = (c.J0 & mask(96)) | bswap(c.start_ctr, 4) << 96
            return c.tag ^ c.E(j0)
        if self.family == 'GCM-SIV':
            c.absorb(cat((self.payload_len, 64), (self.ad_len, 64))); return c._fin()
        if self.family == 'OCB': return c.E(c.csum ^ c.offset ^ c.Ld) ^ c.hash_A
        k = c.key
        c.xw(2, k); c.xw(3, k >> 64); c.perm(12); c.xw(3, k); c.xw(4, k >> 64)
        return c.w(3) | c.w(4) << 64

    def _equal_tag(self, tag):
        q = (self.tag_len_p + 7) // 8
        rx = self.core.siv if self.two_pt else self.received_tag     # GCM-SIV holds the received tag in SIV
        return hmac.compare_digest(v2b(tag & mask(self.tag_len_p), q), v2b(rx, q))

    def _exec(self, st, inp, kllen, klstart, halt_at):
        if st == SAV:
            if self.family == 'GCM':
                self.core.exec('B', inp, kllen, klstart, halt_at)
                need(self.core.st != INV)
                self.klstart = self.core.klstart
                if self.core.st != ABSORB: return 0
            else:
                need(kllen is not None and kllen >= (self.nonce_len + 7) // 8 * 8 and klstart == 0)
                self._setup(inp)
            self.st = ABSORB; return 0
        if st == SAV2:
            need(kllen is not None and kllen >= self.tag_len_p and klstart == 0)
            if self.two_pt: self.core.siv = inp & mask(self.tag_len_p)
            else: self.received_tag = inp & mask(self.tag_len_p)
            self.flags |= TAG_RECEIVED
            self.st = ABSORB; return 0
        if st in (ABSORB, PRE, ENC, DEC):
            return self._multi(inp, kllen, klstart, halt_at, lambda x: self._consume(x, 128))
        if st in (LAST, PRELAST, ELB, DLB):
            need(self.lbl != 0 and kllen is not None and kllen >= self.lbl and klstart == 0)
            return self._final_piece(inp)
        if st == ETF:
            need(kllen is not None and kllen >= self.tag_len_p and klstart == 0)
            tag = self._tag() & mask(self.tag_len_p)
            if self.two_pt and not self.flags & SIV_GENERATED:
                self.core.siv = tag; self.core.tmp = self.ad_hash
                self.payload_len = 0                                    # the second pass recounts the PT
                self.flags |= SIV_GENERATED; self.st = ENC
            else:
                ok = not self.two_pt or self._equal_tag(tag)
                self.st = SUCCESS if ok else FAILURE
                if not ok: return 0
            return tag
        if st == DTF:
            self.st = SUCCESS if self._equal_tag(self._tag()) else FAILURE
            return 0
        need(False)

    def export(self):
        need(self.st != INV)
        widths = self.header_widths()
        header = v2b(self.pack(*zip(self.header(), widths))[0], sum(widths) // 8)
        if self.family == 'Ascon': sc = self.core.export()[32:]   # the core's own header and rx_tag are this one's
        else:
            v, w = self.core.export(); sc = v2b(v, (w + 127) // 128 * 16)
        return header + v2b(self.ad_hash if self.two_pt else self.received_tag, 16) + sc

    def import_(self, sc, st, machine_use=0):
        """Restore authenticated Content and MachineUse into a locker."""
        if self.st == INV: return
        try:
            need(len(sc) == len(self.export()))
            widths = self.header_widths(); h = sum(widths) // 8
            fields = self.unpack(b2v(sc[:h]), widths)
            if self.family == 'GCM' and not self.DEC_ONLY: self.ad_len, self.payload_len, self.nonce_len, self.lbl, reserved = fields
            elif self.family in ('GCM', 'GCM-SIV'): self.ad_len, self.payload_len, self.lbl, reserved = fields
            else: self.lbl, reserved = fields
            self.machine_use = machine_use
            need(reserved == 0 and machine_use >> 14 == 0
                 and self.lbl <= 128 and self.lbl % (1 << self.glog) == 0)
            need(st in (READY, SAV, SAV2, ABSORB, LAST, PRE, PRELAST, ENC, DEC, ELB, DLB, ETF, DTF, SUCCESS, FAILURE))
            need(self.two_pt or st not in (PRE, PRELAST) and not self.flags & SIV_GENERATED)
            need(st not in (READY, SAV) or self.flags == 0)
            if self.two_pt: self.ad_hash = b2v(sc[h:h + 16])
            else: self.received_tag = b2v(sc[h:h + 16])
            sg = bool(self.flags & SIV_GENERATED)                     # selects the GCM-SIV Enc_Tag_Finalize steps
            need(not self.two_pt or not (sg and st in (PRE, PRELAST)) and not (not sg and st in (ENC, ELB)))
            tr = bool(self.flags & TAG_RECEIVED)                      # direction entry conditions
            need(not (tr and st in (PRE, PRELAST, ENC, ELB, ETF)) and not (not tr and st in (DEC, DLB, DTF)))
            need(self.two_pt or tr or self.received_tag == 0)       # rx_tag is zero before Set_Tag_Value
            core_st = ABSORB if st not in (READY, SAV) else SAV if st == SAV and self.family in ('GCM', 'OCB') else READY
            c = self.core
            if self.family == 'Ascon':
                c.import_(sc, core_st, tag_len_p=self.tag_len_p); need(not c.is_error())
            else:
                args = dict(keybytes=len(self.key), policy=self.policy)
                if self.family in ('GCM', 'GCM-SIV'): args['cipher'] = self.CIPHER
                if self.family == 'GCM': args['tag_len_p'] = self.tag_len_p
                self.core = type(c).from_sc(core_st, b2v(sc[h + 16:]), **args)
                need(self.core.st != INV)
                if self.family == 'GCM' and core_st == SAV: self.core.len = self.nonce_len
                if self.family == 'OCB': self.core.tag_len = self.tag_len_p
            self.nonce_len = {'GCM': self.nonce_len, 'GCM-SIV': 96, 'OCB': getattr(self.core, 'nonce_len', 0), 'Ascon': 128}[self.family]
            self.key = v2b(self.core.key, 16) if self.family == 'Ascon' else self.core.key
            if self.DEC_ONLY:
                self.preset = (self.core.J0 & mask(96) if self.family == 'GCM' else
                               (self.core.nonce, self.core.nonce_len) if self.family == 'OCB' else v2b(self.core.nonce, 16))
            if self.mask_key is not None: self.mask_key = v2b(self.core.k2, 16)
            self.st, self.klstart = st, 0
        except (Inv, ValueError): self._fail()


def run_aead(m, nonce, aad, data, tag=None, data_bits=None, ad_bits=None):
    """Common driver.  Inputs are bytes; meaningful lengths are bits."""
    info = m.getinfo()
    need(info or m.glog == 0)
    block_len, tag_len = 128, m.tag_len_p
    if m.DEC_ONLY: m.setst(ABSORB)
    else:
        value, nbits = nonce
        m.setst(SAV, 'B', nbits)
        m.exec('B', value, (nbits + 7) // 8 * 8)
    if tag is not None:
        m.setst(SAV2, 'B', tag_len); m.exec('B', b2v(tag), len(tag) * 8)

    def stream(buf, nbits, form, last):
        # Keep a full last block when present: this exercises the final-block contract.
        nfull = max(0, (nbits - 1) // block_len)
        full = nfull * block_len
        out = m.exec(form, b2v(buf), full) if full else 0
        m.setst(last, 'B', nbits - full)
        if nbits != full:
            out |= m.exec(form, b2v(buf) >> full, (nbits - full + 7) // 8 * 8) << full
        return out

    ad_bits = len(aad) * 8 if ad_bits is None else ad_bits
    data_bits = len(data) * 8 if data_bits is None else data_bits
    stream(aad, ad_bits, 'B', LAST)
    if tag is None and info & 16:
        m.setst(PRE); stream(data, data_bits, 'B', PRELAST)
        m.exec('C', kllen=(tag_len + 7) // 8 * 8)
    else: m.setst(DEC if tag is not None else ENC)
    out = stream(data, data_bits, 'A', DLB if tag is not None else ELB)
    result = m.exec('D') if tag is not None else m.exec('C', kllen=(tag_len + 7) // 8 * 8)
    return v2b(out, (data_bits + 7) // 8), (m.st == SUCCESS if tag is not None else v2b(result, (tag_len + 7) // 8))
