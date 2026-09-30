#!/usr/bin/env python3
"""CTR/XCTR keystream Machines (<<KLEE-keystream-modes>>) through a model locker, against
SP 800-38A F.5 and the google/hctr2 XCTR reference vectors; also the general rules, the
PI/SCC layout and kl.derive."""
import hashlib, os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (aes_encrypt, b2v, v2b, bswap, bxor, cat, sl, mdh_pack, MDH_FIELD,
                    KL_STATE_READY, KL_STATE_OPERATE, KL_STATE_ENCRYPT, KL_STATE_SET_AUX_VALUE,
                    KL_STATE_INVALID, ERROR_STATES, section, check, control, info, spec_note, done)

B, ONES64 = 128, (1 << 64) - 1
RDY, OP, AUX, INV = KL_STATE_READY, KL_STATE_OPERATE, KL_STATE_SET_AUX_VALUE, KL_STATE_INVALID
CIPHERS = {'AES-128': 128, 'AES-192': 192, 'AES-256': 256}
MACHINE = {(c, m): t << 4 | mode for t, c in enumerate(CIPHERS)              # <<KLEE-exec-encodings>>
           for m, mode in (('CTR', 1), ('XCTR', 2))}
KIND = {v: k for k, v in MACHINE.items()}

fld = lambda m, name: sl(m, *MDH_FIELD[name])

def put(m, name, x):
    hi, lo = MDH_FIELD[name]
    return m & ~(((1 << (hi - lo + 1)) - 1) << lo) | x << lo

pad16 = lambda bits: -(-bits // 128) * 16

def kl_size(mdh, c1_size, pi_size):          # <<KLEE-instruction-size>>, AuxDataLen = 0
    st = fld(mdh, 'State')
    return 16 if st in ERROR_STATES else 16 + pi_size if st == 0 else 32 + c1_size

def build_pi(cipher, key_field, mode='CTR', keytype=0):
    return v2b(mdh_pack(Machine=MACHINE[cipher, mode], MachinePolicy=3, KeyType=keytype), 16) \
        + v2b(key_field, pad16(64 if keytype else CIPHERS[cipher]))

def ref(key, block, msg):                     # byte-string keystream reference
    return bxor(b''.join(aes_encrypt(key, block(i)) for i in range(-(-len(msg) // 16))), msg)

# SP 800-38A CTR: nonce || big-endian(ctr, j bits); HCTR2 XCTR: IV xor little-endian(ctr, 128 bits)
ref_ctr = lambda key, nonce, j, ctr, msg: ref(
    key, lambda i: nonce + ((ctr + i) % (1 << j)).to_bytes(j // 8, 'big'), msg)
ref_xctr = lambda key, iv, ctr, msg: ref(key, lambda i: bxor(iv, (ctr + i).to_bytes(16, 'little')), msg)


class KsLocker:
    """n and j of CTR are implementation parameters: no MDH, PI or SCC field selects them."""

    def __init__(self, n=None, j=None, sks=None, variant='spec', order='spec'):
        self.n, self.j, self.sks, self.variant, self.order = n, j, sks or {}, variant, order
        self.mdh, self.key, self.skid, self.IV, self.ctr = 0, None, None, None, None

    state = property(lambda s: fld(s.mdh, 'State'))
    keytype = property(lambda s: fld(s.mdh, 'KeyType'))

    def params(self):
        cipher, mode = KIND[fld(self.mdh, 'Machine')]
        n, j = (B, B) if mode == 'XCTR' else (self.n, self.j)      # b = n = j, resp. b = n + j
        assert n + j == B or mode == 'XCTR'
        return CIPHERS[cipher], mode, n, j

    kw = property(lambda s: 64 if s.keytype == 1 else s.params()[0])

    def invalidate(self):
        self.mdh = put(self.mdh, 'State', INV)
        self.key = self.skid = self.IV = self.ctr = None

    def enter_ready(self):                    # "In State Ready, the ctr and IV fields are set to 0"
        self.mdh, self.IV, self.ctr = put(self.mdh, 'State', RDY), 0, 0

    def _install(self, field, importing):
        if self.keytype == 0:
            self.key = field
        elif field == ONES64 and not importing:
            self.key, self.mdh = random.Random(1).getrandbits(self.params()[0]), put(self.mdh, 'KeyType', 0)
        elif field != ONES64 and field in self.sks:
            self.skid, self.key = field, self.sks[field]
        else:
            self.invalidate()

    def provision(self, pi):
        self.mdh = b2v(pi[:16])
        self._install(sl(b2v(pi[16:]), self.kw - 1, 0), False)
        if self.state not in ERROR_STATES:
            self.enter_ready()

    def content1(self):                       # key or SKID (i), IV (ii), ctr (iii)
        _, _, n, j = self.params()
        return v2b(cat((self.ctr, j), (self.IV, n), (self.skid if self.keytype else self.key, self.kw)),
                   pad16(self.kw + n + j))

    def import_scc(self, mdh, c1):
        self.mdh, v = mdh, b2v(c1)
        _, _, n, j = self.params()
        self.IV, self.ctr = sl(v, self.kw + n - 1, self.kw), sl(v, self.kw + n + j - 1, self.kw + n)
        self._install(sl(v, self.kw - 1, 0), True)

    def setst(self, immed, form='A', operand=None, KLLEN=128):
        """form: 'A', 'A/iobuf' (operand = KLIOBUF bytes), 'B' (64-bit Xs), 'C' (KLLEN-bit value)."""
        if self.state in ERROR_STATES:
            return
        _, _, n, j = self.params()
        if immed == RDY and form == 'A':
            self.enter_ready()
        elif immed == OP and self.state in (RDY, OP) and form in ('C', 'A/iobuf'):
            value = b2v(operand) if form == 'A/iobuf' else sl(operand, KLLEN - 1, 0)
            self.IV, self.mdh = sl(value, n - 1, 0) if n else 0, put(self.mdh, 'State', OP)
        elif immed == AUX and self.state in (RDY, OP) and form == 'B':
            self.ctr = sl(operand, min(j, 64) - 1, 0)             # lsb_j(Xs), State unchanged
        else:
            self.invalidate()                                     # MGR1

    def exec(self, KLLEN, klstart=0, out=0, halt_after=None, iobuf=False):
        """Form C kl.exec (output only), or Form D into the KLIOBUF; returns (output, klstart)."""
        lo = 8 * klstart
        window = ((1 << KLLEN) - 1) >> lo << lo if lo < KLLEN else 0
        if self.state in ERROR_STATES:
            return out & ~window, 0
        if lo % B or lo >= KLLEN or KLLEN % B and iobuf:
            return out, klstart               # output only: <<KLEE-CSR-klstart>>, <<KLEE-usage-input-output>>
        if KLLEN % B or self.state != OP:
            self.invalidate()                 # MGR2, SGR2
            return out & ~window, 0
        k, mode, n, j = self.params()
        key, pos = v2b(self.key, k // 8), list(range(lo, KLLEN, B))   # MGR3
        for q, i in enumerate(pos if self.order == 'spec' else pos[::-1]):
            if q == halt_after:
                return out, i // 8
            if mode == 'XCTR':
                blk = self.IV ^ self.ctr
            else:
                blk = cat((bswap(self.ctr, j // 8) if self.variant == 'spec' else self.ctr, j), (self.IV, n))
            tmp = b2v(aes_encrypt(key, v2b(blk, 16)))
            self.ctr = (self.ctr + 1) % (1 << j)                    # tick_ctr()
            out = out & ~(((1 << B) - 1) << i) | tmp << i
        return out, 0

    def derive_key(self, src, length):
        """kl.derive into `key` (<<KLEE-derive-endpoints>>); src is a KsLocker or DRBG output bytes
        (DER7, unrestricted: no narrowing)."""
        if isinstance(src, KsLocker):         # keystream (DER6 source) into a key: pair not admitted
            return src.invalidate() if src.state != OP else (src.invalidate(), self.invalidate())
        n = self.params()[0] // 8
        if self.state != RDY or self.keytype == 1 or length < n or len(src) < n:
            return self.invalidate()          # DER1 items 2-3, DER4 (item 3), item 6
        self.key = b2v(src[:n])
        return True


def derive_to_hash(cl, h, length):
    """DER6: keystream (kl.exec-obtainable) into a hash in Hash_Absorb; DER8 discards the unused tail."""
    if cl.state != OP:
        return cl.invalidate()                # DER1 items 1, 3
    return h.update(keystream(cl, length)) or True

def keystream(cl, nbytes, per_block=False):
    nb = -(-nbytes // 16)
    parts = [(B, 16)] * nb if per_block else [(nb * B, nb * 16)]
    return b''.join(v2b(cl.exec(L)[0], m) for L, m in parts)[:nbytes]

def ctr_cl(key, n, j, ivv=None, ctr0=None, keytype=0, mode='CTR', **kw):
    """A provisioned locker; key is bytes, or an AES-128 key field (value or SKID)."""
    cl = KsLocker(n, j, **kw)
    cl.provision(build_pi(f"AES-{len(key) * 8}" if isinstance(key, bytes) else 'AES-128',
                          b2v(key) if isinstance(key, bytes) else key, mode, keytype))
    return operate(cl, ivv, ctr0)

def operate(cl, ivv=None, ctr0=None):         # Form C IV <- ivv, then Form B ctr <- ctr0
    if ivv is not None:
        cl.setst(OP, 'C', ivv)
    if ctr0 is not None:
        cl.setst(AUX, 'B', ctr0)
    return cl

def kl_ctr(key, ivv, n, j, msg, ctr0=0, per_block=False, **kw):
    return bxor(keystream(ctr_cl(key, n, j, ivv, ctr0, **kw), len(msg), per_block), msg)

def kl_xctr(key, ivv, msg, ctr0=None):
    return bxor(keystream(ctr_cl(key, None, None, ivv, ctr0, mode='XCTR'), len(msg)), msg)


# ---------------------------------------------------------------- vectors
SP38A_PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                         "ae2d8a571e03ac9c9eb76fac45af8e51"
                         "30c81c46a35ce411e5fbc1191a0a52ef"
                         "f69f2445df4f9b17ad2b417be66c3710")
SP38A_ICB = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
SP38A_F5 = [  # SP 800-38A F.5.1/F.5.3/F.5.5, via Linux crypto/testmgr.h aes_ctr_tv_template
    ("F.5.1 CTR-AES128", "2b7e151628aed2a6abf7158809cf4f3c",
     "874d6191b620e3261bef6864990db6ce"
     "9806f66b7970fdff8617187bb9fffdff"
     "5ae4df3edbd5d35e5b4f09020db03eab"
     "1e031dda2fbe03d1792170a0f3009cee"),
    ("F.5.3 CTR-AES192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
     "1abc932417521ca24f2b0459fe7e6e0b"
     "090339ec0aa6faefd5ccc2c6f4ce8e94"
     "1e36b26bd1ebc670d1bd1d665620abf7"
     "4f78a7f6d29809585a97daec58c6b050"),
    ("F.5.5 CTR-AES256",
     "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "601ec313775789a5b7a7f504bbf3d228"
     "f443e3ca4d62b59aca84e990cacaf5c5"
     "2b0930daa23de94ce87017ba2d84988d"
     "dfc9c58db67aada613c2dd08457941a6"),
]
# google/hctr2 test_vectors/ours/XCTR/XCTR_AES{128,256}.json: (label, key, nonce, plaintext, ciphertext)
HCTR2_XCTR = [
    ("XCTR-AES128 len 16", "bc1b120c3f18cc1f5a1dab81a8687c63",
     "22c1dd250b18cba54ada150773d98810",
     "246e64c615269cda2a4b5712ff7cd6b5",
     "d6478d5892b284f9b7ee0d98a1394d8f"),
    ("XCTR-AES128 len 31", "4403bf4c30f0a7d6bd54bb668ea60e8a",
     "e6f726df8c3caa88cec1bd433b0962ad",
     "3ce346b98f9d3f8deff253ab24e22908f87e1da66d867d60976393297194b4",
     "d4a3c6b8c16f701a520ced4caf5156234845071034c5ba71e5f81ed8cba6e7"),
    ("XCTR-AES256 len 16",
     "afd91414d5dbc9ce765c5abf43052924c41368cce837bdb94120f55348d0a2d6",
     "a7b400087910aef502bf85b2694cc604",
     "ac6aa80cb084bf4cae9420587e009389",
     "d5aae2e9864c954edeb615cbdc1f1338"),
    ("XCTR-AES256 len 17",
     "ede38be71c17bf4a02e2fc76acf53c005ddcfc83eb45b4cb596260ec699c1645",
     "e40e2b90d2fa942e10e5642b972815c7",
     "e653ff600ec451e4934de555c5d9ad4852",
     "ba2528f5cf319180da2b955f20cbfb9fc6"),
    ("XCTR-AES256 len 48",
     "a12f4ddefea1ffa873dde3e295fcea9cd080420cb8433e9939380a8ce8453a7b",
     "32c46fb11443d187e26f5a5802367e2a",
     "9e5c1ef1d67d0957184855da7d44f96daccd59bb10a29467d16ffe6b4a11e804"
     "09264f8d5da17b42f94b66763812fefe",
     "42bca764159a04712c5f94ba893aadbc87b3f4094f570618dc8420f76485ca3b"
     "abe6335634605d4b2e1613d477de2d2b"),
]

# ---------------------------------------------------------------- checks
def eq(name, got, want):
    return check(name, None, got, want)

H, PT, T1 = bytes.fromhex, SP38A_PT, b2v(SP38A_ICB)      # T1: the whole initial counter block
c0 = lambda n: int.from_bytes(SP38A_ICB[n // 8:], 'big')  # its trailing j/8 bytes, big-endian

section("SP 800-38A F.5: reference, and a locker (Form C IV <- T1, Form B ctr, one kl.exec of 4b)")
for name, k, c in SP38A_F5:
    key = H(k)
    eq(f"{name} reference (n, j) = (0, 128)", ref_ctr(key, b'', 128, c0(0), PT).hex(), c)
    for n, j in ((64, 64), (96, 32), (112, 16)):
        eq(f"{name} locker, (n, j) = ({n}, {j})", kl_ctr(key, T1, n, j, PT, c0(n)).hex(), c)
    eq(f"{name} locker, (96, 32), four kl.exec with KLLEN = b",
       kl_ctr(key, T1, 96, 32, PT, c0(96), per_block=True).hex(), c)
F51 = [(H(k), c) for _, k, c in SP38A_F5]
control("counter without bswap (little-endian in the trailing bytes) misses F.5",
        all(kl_ctr(key, T1, 64, 64, PT, c0(64), variant='neg').hex() != c for key, c in F51))
control("blocks filled most significant first (MGR3 reversed) misses F.5",
        all(kl_ctr(key, T1, 64, 64, PT, c0(64), order='neg').hex() != c for key, c in F51))
key, c = F51[0]
got = kl_ctr(key, T1, 120, 8, PT, 0xff)
eq("(n, j) = (120, 8): ctr wraps mod 2^8 after 0xff, so F.5.1 is not reproduced",
   (got.hex() != c, got), (True, ref_ctr(key, SP38A_ICB[:15], 8, 0xff, PT)))

section("Other splits: locker vs reference [reference-consistency only]")
msg = bytes(range(80))
for n, j in ((96, 32), (64, 64), (120, 8), (32, 96), (112, 16), (0, 128)):
    nonce = bytes(range(1, n // 8 + 1))
    starts = (0, 1, 7, (1 << j) - 2 if j <= 64 else ONES64)
    eq(f"n = {n}, j = {j}, starting counters {starts[:3]} and the wrap point",
       [kl_ctr(key, b2v(nonce), n, j, msg, s) for s in starts],
       [ref_ctr(key, nonce, j, s, msg) for s in starts])

section("Form B kl.setst #kl_state_set_aux_value: ctr <- lsb_j(Xs), State unchanged")
eq("F.5.1 blocks 2..3 by random access",
   bxor(keystream(ctr_cl(key, 64, 64, T1, c0(64) + 2), 32), PT[32:]).hex(), c[64:])
eq("lsb_j(Xs) with j = 32 keeps only the low 32 bits",
   keystream(ctr_cl(key, 96, 32, b2v(bytes(range(1, 13))), 0xdeadbeef << 32 | 5), 32),
   ref_ctr(key, bytes(range(1, 13)), 32, 5, bytes(32)))
cl = ctr_cl(key, 64, 64, ctr0=c0(64))
st = cl.state
cl.setst(OP, 'C', T1)
eq("Form B in Ready (State stays 1), then Form C: ctr survives the transition, F.5.1",
   (st, cl.state, bxor(keystream(cl, 64), PT).hex()), (RDY, OP, c))
cl.setst(AUX, 'B', c0(64))
eq("Form B in Operate leaves State 2", cl.state, OP)
info("Ready zeroes IV and ctr on entry only: a Form B ctr set in Ready survives the Form C move to Operate.")
info("Form B carries 64 bits: for j > 64, lsb_j(Xs) is read as Xs zero-extended (lsb_c needs c <= |x|).")

section("XCTR [reference-implementation anchor: google/hctr2; Form B sets HCTR2's initial ctr = 1]")
for name, xk, xiv, xp, xc in HCTR2_XCTR:
    eq(f"{name} reference / locker encrypt / locker decrypt",
       (ref_xctr(H(xk), H(xiv), 1, H(xp)).hex(), kl_xctr(H(xk), b2v(H(xiv)), H(xp), 1).hex(),
        kl_xctr(H(xk), b2v(H(xiv)), H(xc), 1).hex()), (xc, xc, xp))
iv, m64 = bytes(range(16)), bytes(range(64))
eq("XCTR with ctr = 0 as left by Ready matches the reference", kl_xctr(key, b2v(iv), m64),
   ref_xctr(key, iv, 0, m64))
eq("XCTR streams with ctr = 0 and ctr = 1 differ",
   kl_xctr(key, b2v(iv), m64, 0) != kl_xctr(key, b2v(iv), m64, 1), True)
eq("CTR (96, 32) and XCTR keystreams differ",
   kl_ctr(key, b2v(iv[:12]), 96, 32, m64) != kl_xctr(key, b2v(iv[:12] + bytes(4)), m64), True)

section("States, transitions and general rules (F.5.1, (n, j) = (64, 64))")
eq("State values Ready 1, Operate 2, Set_Aux_Value 13, Invalid 49", (RDY, OP, AUX, INV), (1, 2, 13, 49))
cl = ctr_cl(key, 64, 64)
eq("provisioning completes in Ready with IV = ctr = 0", (cl.state, cl.IV, cl.ctr), (RDY, 0, 0))
eq("kl.exec in Ready: Invalid, window zeroed, Content cleared (SGR2)",
   (cl.exec(512, out=ONES64)[0], cl.state, cl.key), (0, INV, None))
for label, args in (("kl.setst #kl_state_encrypt (no such transition)", (KL_STATE_ENCRYPT, 'C', T1)),
                    ("#kl_state_operate in Form B (Form C required)", (OP, 'B', T1 & ONES64)),
                    ("#kl_state_set_aux_value in Form C (Form B only)", (AUX, 'C', c0(64)))):
    cl = ctr_cl(key, 64, 64)
    cl.setst(*args)
    eq(f"{label} -> Invalid (MGR1)", cl.state, INV)
cl = ctr_cl(key, 64, 64, T1, c0(64))
keystream(cl, 64)
cl.setst(RDY)
cleared = (cl.state, cl.IV, cl.ctr)
cl.setst(OP, 'C', T1)
eq("Operate -> Ready zeroes IV and ctr; re-entry restarts at ctr = 0",
   (cleared, bxor(keystream(cl, 64), PT)), ((RDY, 0, 0), ref_ctr(key, SP38A_ICB[:8], 64, 0, PT)))
cl = ctr_cl(key, 64, 64, 0x1234, c0(64))
cl.setst(OP, 'C', T1)
eq("Operate -> Operate (SGR4): IV replaced, ctr kept; F.5.1",
   (cl.state, bxor(keystream(cl, 64), PT).hex()), (OP, c))
info("a same-State kl.setst #kl_state_operate (SGR4) replaces IV and keeps ctr (Ready is not entered).")
cl = ctr_cl(key, 64, 64)
cl.setst(OP, 'A/iobuf', SP38A_ICB)
cl.setst(AUX, 'B', c0(64))
eq("Form A kl.setst and Form D kl.exec with the KLIOBUF (kliobuftop 16, 64): F.5.1",
   bxor(v2b(cl.exec(512, iobuf=True)[0], 64), PT).hex(), c)
info("'a Form C kl.setst ... must be issued' is read as 'expected': its Form A KLIOBUF substitution applies.")
cl = ctr_cl(key, 64, 64, T1, c0(64))
eq("MGR2 (vector): KLLEN = 136 -> Invalid, window zeroed",
   (cl.exec(136, out=(1 << 136) - 1)[0], cl.state), (0, INV))
prior, cl = b2v(bytes(range(17))), ctr_cl(key, 64, 64, T1, c0(64))
eq("KLIOBUF output only, kliobuftop = 17 -> no operation, no state change",
   (cl.exec(136, out=prior, iobuf=True)[0], cl.state, cl.ctr), (prior, OP, c0(64)))
info("output-only KLIOBUF of invalid length: the no-operation rule of <<KLEE-usage-input-output>> beats MGR2.")
cl = ctr_cl(key, 64, 64, T1, c0(64))
eq("klstart = 8 (output only, no interruption point) -> no operation",
   (cl.exec(512, klstart=8, out=7)[0], cl.state, cl.ctr), (7, OP, c0(64)))
for q in (1, 2, 3):
    for iob in (False, True):
        cl = ctr_cl(key, 64, 64, T1, c0(64))
        part, ks = cl.exec(512, halt_after=q, iobuf=iob)
        whole, ks2 = cl.exec(512, klstart=ks, out=part, iobuf=iob)
        eq(f"Form {'D' if iob else 'C'} kl.exec halted after {q} block(s), resumed",
           (ks, bxor(v2b(whole, 64), PT).hex(), ks2), (16 * q, c, 0))
cl = ctr_cl(key, 120, 8, T1, 0xff)
cl.exec(B)
eq("no block limit: ctr wraps from 2^j - 1 to 0 and the locker stays in Operate", (cl.ctr, cl.state), (0, OP))

section("PI and Serialized Content (sizes by hand, AuxDataLen = 0)")
SKID = 0x0123456789abcdef
SKS = {SKID: b2v(key)}
for cipher, kt, pi_size, c1_size in (('AES-128', 0, 32, 32), ('AES-192', 0, 48, 48),
                                     ('AES-256', 0, 48, 48), ('AES-128', 1, 32, 32)):
    pi = build_pi(cipher, SKID if kt else (1 << CIPHERS[cipher]) - 1, keytype=kt)
    cl = KsLocker(64, 64, SKS)
    cl.provision(pi)
    eq(f"{cipher} {'SKID' if kt else 'by value'}: PI {pi_size}, Content1 {c1_size}, "
       f"kl.size {pi_size}/{32 + c1_size}",
       (len(pi), kl_size(b2v(pi[:16]), 0, len(pi) - 16), len(cl.content1()), kl_size(cl.mdh, c1_size, 0)),
       (pi_size, pi_size, c1_size, 32 + c1_size))
TAIL = "f0f1f2f3f4f5f6f7" + "01fffdfcfbfaf9f8"            # IV, then bin(ctr, 64) after 2 blocks
for label, kt, field, want_c1 in (("by value", 0, b2v(key), SP38A_F5[0][1] + TAIL),
                                  ("by SKID", 1, SKID, "efcdab8967452301" + TAIL + "00" * 8)):
    cl, cl2 = ctr_cl(field, 64, 64, T1, c0(64), keytype=kt, sks=SKS), KsLocker(64, 64, SKS)
    head = keystream(cl, 32)
    cl2.import_scc(cl.mdh, cl.content1())
    eq(f"{label}: Content1 after 2 blocks = key|IV|ctr; imported, it finishes F.5.1",
       (cl.content1().hex(), cl2.state, bxor(head + keystream(cl2, 32), PT).hex()), (want_c1, OP, c))
cl, other = ctr_cl(key, 64, 64, T1, c0(64)), KsLocker(96, 32)
head = keystream(cl, 32)
other.import_scc(cl.mdh, cl.content1())
eq("the same SCC imported with (n, j) = (96, 32) continues a different stream",
   bxor(head + keystream(other, 32), PT).hex() != c, True)
cl = KsLocker(64, 64, SKS)
cl.provision(build_pi('AES-128', ONES64, keytype=1))
eq("all-ones SKID: random key, KeyType 0, Content1 32 B",
   (cl.state, cl.keytype, len(cl.content1())), (RDY, 0, 32))
spec_note("no field fixes the CTR counter size j (n = b - j), on which the IV truncation, the tick_ctr "
          "wrap and the IV/ctr boundary in Content1 depend: implementations may read one SCC differently.")
info("<<KLEE-keystream-modes>> gates no transition on MachinePolicy; the PIs here set both bits.")

section("kl.derive (<<KLEE-derive-endpoints>>, <<KLEE-instruction-derive>>)")
drbg = key + H("5a" * 16)

def derived(length, keytype=0, state_op=False):
    cl = ctr_cl(SKID if keytype else 0, 64, 64, T1 if state_op else None, keytype=keytype, sks=SKS)
    if cl.derive_key(drbg, length):
        return cl.state, bxor(keystream(operate(cl, T1, c0(64)), 64), PT).hex()
    return cl.state, cl.key

eq("DRBG output (DER7), length 32, into the 16-byte key (DER1 item 6), then F.5.1", derived(32), (RDY, c))
for label, args in (("length 8 < 16", (8,)), ("length 0", (0,)), ("KeyType 1 destination (DER4, DER1 item 3)", (32, 1)),
                    ("destination in Operate (DER1 items 2-3)", (32, 0, True))):
    eq(f"{label} -> destination Invalid, no key", derived(*args), (INV, None))
src, dst = ctr_cl(key, 64, 64, T1, c0(64)), ctr_cl(key, 64, 64)
dst.derive_key(src, 16)
eq("CTR keystream into a CTR key (endpoints defined, pair not admitted) -> both Invalid", (src.state, dst.state),
   (INV, INV))
cl, h = ctr_cl(key, 64, 64, T1, c0(64)), hashlib.sha256()
ok = derive_to_hash(cl, h, 40)
eq("DER6: 40 keystream bytes into a SHA-256 absorb = SHA-256 of F.5.1 CT xor PT; source advanced 3 blocks",
   (ok, h.hexdigest(), bxor(keystream(cl, 16), PT[48:]).hex()),
   (True, hashlib.sha256(bxor(H(c), PT)[:40]).hexdigest(), c[96:]))
cl = ctr_cl(key, 64, 64)
derive_to_hash(cl, hashlib.sha256(), 40)
eq("DER6 with the source in Ready (no source endpoint, DER1 items 1, 3) -> only the source Invalid", cl.state, INV)
spec_note("DER6 'unconditionally exported' is undefined and <<KLEE-defined-derivation-endpoints>> lists no "
          "CTR/XCTR source; the Operate keystream (gated by no MachinePolicy bit) is taken as a DER6 source.")
done()
