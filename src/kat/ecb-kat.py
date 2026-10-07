#!/usr/bin/env python3
"""ECB Machines (<<KLEE-ECB-mode>>) through a model locker, against FIPS 197, SP 800-38A F.1
and GB/T 32907-2016 (SM4); also the general rules, the PI/SCC layout and kl.derive into `key`."""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (aes_encrypt, aes_decrypt, b2v, v2b, cat, sl, mdh_pack, MDH_FIELD,
                    KL_STATE_UNCONFIGURED, KL_STATE_READY, KL_STATE_OPERATE, KL_STATE_ENCRYPT,
                    KL_STATE_DECRYPT, KL_STATE_INVALID, ERROR_STATES,
                    section, check, control, info, done)

# ---------------------------------------------------------------- SM4 (GB/T 32907-2016)
# S-box: OpenSSL crypto/sm4/sm4.c SM4_S[256]; anchored below on the GB/T vectors.
SM4_SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948")
SM4_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
S = SM4_SBOX

rotl = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
tau = lambda a: (S[a >> 24] << 24) | (S[(a >> 16) & 255] << 16) | (S[(a >> 8) & 255] << 8) | S[a & 255]
words = lambda b: [int.from_bytes(b[i:i + 4], 'big') for i in range(0, 16, 4)]

def sm4_rks(key):
    k = [w ^ f for w, f in zip(words(key), SM4_FK)]
    for i in range(32):
        ck = int.from_bytes(bytes((28 * i + 7 * j) & 255 for j in range(4)), 'big')
        t = tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck)
        k.append(k[i] ^ t ^ rotl(t, 13) ^ rotl(t, 23))
    return k[4:]

def sm4_block(rks, blk):
    x = words(blk)
    for rk in rks:
        t = tau(x[-3] ^ x[-2] ^ x[-1] ^ rk)
        x.append(x[-4] ^ t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24))
    return b''.join(w.to_bytes(4, 'big') for w in reversed(x[-4:]))

sm4_encrypt = lambda key, blk: sm4_block(sm4_rks(key), blk)
sm4_decrypt = lambda key, blk: sm4_block(sm4_rks(key)[::-1], blk)   # round keys reversed

# ---------------------------------------------------------------- the model
B = 128
ONES64 = (1 << 64) - 1
POL_ENC, POL_DEC, POL_BOTH = 1, 2, 3
CIPHERS = {'AES-128': (aes_encrypt, aes_decrypt, 128), 'AES-192': (aes_encrypt, aes_decrypt, 192),
           'AES-256': (aes_encrypt, aes_decrypt, 256), 'SM4': (sm4_encrypt, sm4_decrypt, 128)}
MACHINE = {c: t << 4 for t, c in enumerate(CIPHERS)}       # <<KLEE-exec-encodings>>: Type t, Mode 0
CIPHER_OF = {m: c for c, m in MACHINE.items()}

fld = lambda m, name: sl(m, *MDH_FIELD[name])

def put(m, name, x):
    hi, lo = MDH_FIELD[name]
    return m & ~(((1 << (hi - lo + 1)) - 1) << lo) | x << lo

pad16 = lambda bits: -(-bits // 128) * 16

def kl_size(mdh, c1_size, pi_size):          # <<KLEE-instruction-size>>, AuxDataLen = 0
    st = fld(mdh, 'State')
    return 16 if st in ERROR_STATES else 16 + pi_size if st == 0 else 32 + c1_size

def build_pi(cipher, key_field, policy=POL_BOTH, keytype=0, **mdh):
    k = 64 if keytype else CIPHERS[cipher][2]
    return v2b(mdh_pack(Machine=MACHINE[cipher], MachinePolicy=policy, KeyType=keytype, **mdh), 16) \
        + v2b(key_field, pad16(k))

def narrow(dst, src):
    """<<KLEE-GR-narrowing>>: the narrowed destination MDH, or None (destination Invalid)."""
    u, us = fld(dst, 'UsagePolicy'), fld(src, 'UsagePolicy')
    lo, ls = fld(dst, 'Locality'), fld(src, 'Locality')
    if fld(dst, 'SCProtection') < fld(src, 'SCProtection'):
        return None
    if sl(lo, 5, 4) and sl(ls, 5, 4) and sl(lo, 5, 4) != sl(ls, 5, 4):
        return None
    loc = (max(sl(lo, 1, 0), sl(ls, 1, 0)) | max(sl(lo, 3, 2), sl(ls, 3, 2)) << 2   # stricter entry
           | (sl(lo, 5, 4) | sl(ls, 5, 4)) << 4 | (sl(lo, 8, 6) | sl(ls, 8, 6)) << 6)
    e = [x for x in (fld(dst, 'ExpirationDate'), fld(src, 'ExpirationDate')) if x]
    dst = put(put(dst, 'UsagePolicy', (u | us) & 15 | u & us & 16), 'Locality', loc)
    return put(dst, 'ExpirationDate', min(e) if e else 0)

class EcbLocker:
    def __init__(self, sks=None, order='spec'):
        self.mdh, self.key, self.skid = 0, None, None
        self.sks, self.order = sks or {}, order

    state = property(lambda s: fld(s.mdh, 'State'))
    keytype = property(lambda s: fld(s.mdh, 'KeyType'))
    cipher = property(lambda s: CIPHERS[CIPHER_OF[fld(s.mdh, 'Machine')]])
    key_width = property(lambda s: 64 if s.keytype == 1 else s.cipher[2])

    def invalidate(self):                     # <<KLEE-GR-clear-locker-content-error-state>>
        self.mdh, self.key, self.skid = put(self.mdh, 'State', KL_STATE_INVALID), None, None

    def _install(self, field, importing):     # <<KLEE-KeyType-field>>, <<KLEE-MVR-open>>
        if self.keytype == 0:
            self.key = field
        elif field == ONES64 and not importing:
            self.key, self.mdh = random.Random(1).getrandbits(self.cipher[2]), put(self.mdh, 'KeyType', 0)
        elif field != ONES64 and field in self.sks:
            self.skid, self.key = field, self.sks[field]
        else:
            self.invalidate()

    def provision(self, pi):
        self.mdh, self.key, self.skid = b2v(pi[:16]), None, None
        if fld(self.mdh, 'MachinePolicy') == 0:   # <<KLEE-Machine-field>>: at least one bit
            return self.invalidate()
        self._install(sl(b2v(pi[16:]), self.key_width - 1, 0), False)
        if self.state not in ERROR_STATES:
            self.mdh = put(self.mdh, 'State', KL_STATE_READY)

    def content1(self):                       # Serialized Content: key or SKID at position i
        return v2b(self.skid if self.keytype else self.key, pad16(self.key_width))

    def import_scc(self, mdh, c1):
        self.mdh, self.key, self.skid = mdh, None, None
        if self.state not in (KL_STATE_READY, KL_STATE_ENCRYPT, KL_STATE_DECRYPT) or fld(mdh, 'StateExtension'):
            return self.invalidate()          # <<KLEE-Metadata-validity>>: ECB uses no StateExtension
        self._install(sl(b2v(c1), self.key_width - 1, 0), True)

    def setst(self, immed):
        if self.state in ERROR_STATES:
            return                            # <<KLEE-GR-usage-locker-error-state>>
        pol = fld(self.mdh, 'MachinePolicy')
        if (immed == KL_STATE_READY or immed == KL_STATE_ENCRYPT and pol & POL_ENC
                or immed == KL_STATE_DECRYPT and pol & POL_DEC):
            self.mdh = put(self.mdh, 'State', immed)
        else:
            self.invalidate()                 # MGR1

    def exec(self, inp, KLLEN, klstart=0, halt_after=None):
        """Form A kl.exec with Vd = Vs2 (or its Form D substitution); returns (output, klstart)."""
        lo, out = 8 * klstart, inp
        window = ((1 << KLLEN) - 1) >> lo << lo if lo < KLLEN else 0
        if self.state in ERROR_STATES:
            return out & ~window, 0
        if self.state not in (KL_STATE_ENCRYPT, KL_STATE_DECRYPT) or KLLEN % B:
            self.invalidate()                 # GR17; MGR2 (<<KLEE-CSR-klstart>>: length first)
            return out & ~window, 0
        if lo >= KLLEN:
            return out, 0                     # empty window: only klstart = 0
        if lo % B:
            self.invalidate()                 # not an interruption point
            return out & ~window, 0
        enc, dec, k = self.cipher
        f, key = enc if self.state == KL_STATE_ENCRYPT else dec, v2b(self.key, k // 8)
        for q, i in enumerate(range(lo, KLLEN, B)):   # MGR3
            if q == halt_after:
                return out, i // 8
            dst = i if self.order == 'spec' else KLLEN - B - i
            out = out & ~(((1 << B) - 1) << dst) | b2v(f(key, v2b(sl(inp, i + B - 1, i), 16))) << dst
        return out, 0

    def derive_key(self, src, length):
        """kl.derive into `key` (<<KLEE-derive-endpoints>>, <<KLEE-instruction-derive>>);
        `src` is an EcbLocker or (kind, bytes, MDH) with kind 'shared' (GR40) or 'drbg' (GR42)."""
        if isinstance(src, EcbLocker):        # ECB defines no source endpoint: GR36 items 1-2
            return src.invalidate()
        kind, data, src_mdh = src
        n = self.cipher[2] // 8
        if self.state in ERROR_STATES:
            return False
        if self.state != KL_STATE_READY or self.keytype == 1 or length < n or len(data) < n:
            return self.invalidate()          # GR36 item 2 (GR39), item 5
        if kind == 'shared':                  # restricted: GR37; DRBG is unrestricted: GR38
            m = narrow(self.mdh, src_mdh)
            if m is None:
                return self.invalidate()
            self.mdh = m
        self.key = b2v(data[:n])              # exactly dest_length bytes (GR36 item 5, GR43)
        return True

def blocks_value(data):                       # cat() lists the most significant block first
    return cat(*[(b2v(data[i:i + 16]), B) for i in range(len(data) - 16, -1, -16)])

def ref(f, key, data):                        # byte-string ECB reference
    return b''.join(f(key, data[i:i + 16]) for i in range(0, len(data), 16))

def run(cl, data, **kw):
    out, ks = cl.exec(blocks_value(data), 8 * len(data), **kw)
    return v2b(out, len(data)), ks

def new_cl(cipher, key_hex, policy=POL_BOTH, state=None, **kw):
    cl = EcbLocker(**kw)
    cl.provision(build_pi(cipher, b2v(bytes.fromhex(key_hex)), policy))
    if state is not None:
        cl.setst(state)
    return cl

# ---------------------------------------------------------------- vectors
FIPS197 = [  # FIPS 197 Appendix C
    ("C.1 AES-128", "000102030405060708090a0b0c0d0e0f",
     "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("C.2 AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617",
     "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("C.3 AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
]
SP38A_PT = ("6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710")
SP38A_F1 = [  # SP 800-38A Appendix F.1
    ("F.1.1/F.1.2 ECB-AES128", "AES-128", "2b7e151628aed2a6abf7158809cf4f3c",
     "3ad77bb40d7a3660a89ecaf32466ef97"
     "f5d3d58503b9699de785895a96fdbaaf"
     "43b1cd7f598ece23881b00e3ed030688"
     "7b0c785e27e8ad3f8223207104725dd4"),
    ("F.1.3/F.1.4 ECB-AES192", "AES-192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
     "bd334f1d6e45f25ff712a214571fa5cc"
     "974104846d0ad3ad7734ecb3ecee4eef"
     "ef7afd2270e2e60adce0ba2face6444e"
     "9a4b41ba738d6c72fb16691603c18e0e"),
    ("F.1.5/F.1.6 ECB-AES256", "AES-256",
     "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "f3eed1bdb5d2a03c064b5a7e3db181f8"
     "591ccb10d410ed26dc5ba74a31362870"
     "b6ed21b99ca6f4f9f153e7b1beafed1d"
     "23304b7a39f9f3ff067d8d8f9e24ecc7"),
]
SM4_KEY1 = "0123456789abcdeffedcba9876543210"
SM4_EX1_CT = "681edf34d206965e86b3e94f536e4246"          # GB/T 32907-2016 Example 1
SM4_EX2_ROUNDS, SM4_EX2_CT = 1000000, "595298c7c6fd271f0402f804c33d3f66"   # Example 2
SM4_EX2_CHECKPOINTS = {  # reference-implementation checkpoints, not published constants
    100: "8da24cb1008bd3271aa3b60105a7d5fd",
    1000: "d735e91cc5689cf312bcc1efb740e813",
    10000: "2d8bfc27381c68ecb316320ee72ba074",
}
SM4_MULTI = [  # GB/T 32907-2016 A.2.1.1/A.2.1.2, via Linux crypto/testmgr.h sm4_tv_template
    ("A.2.1.1 SM4-ECB", SM4_KEY1,
     "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb",
     "5ec8143de509cff7b5179f8f474b86192f1d305a7fb17df985f81c8482192304"),
    ("A.2.1.2 SM4-ECB", "fedcba98765432100123456789abcdef",
     "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb",
     "c5876897e4a59bbba72a10c83872245b12dd90bc2d200692b529a4155ac9e600"),
]

# ---------------------------------------------------------------- checks
def eq(name, got, want):
    return check(name, None, got, want)

H, pt = bytes.fromhex, bytes.fromhex(SP38A_PT)
RDY, ENC, DEC, INV = KL_STATE_READY, KL_STATE_ENCRYPT, KL_STATE_DECRYPT, KL_STATE_INVALID
both = lambda ci, k, p, c: (run(new_cl(ci, k, state=ENC), H(p))[0].hex(),
                            run(new_cl(ci, k, state=DEC), H(c))[0].hex())

section("FIPS 197 C: single block, reference and locker with KLLEN = b")
for name, k, p, c in FIPS197:
    eq(f"{name} encrypt / decrypt", (aes_encrypt(H(k), H(p)).hex(), aes_decrypt(H(k), H(c)).hex()), (c, p))
    eq(f"{name} locker encrypt / decrypt", both(f"AES-{len(k) * 4}", k, p, c), (c, p))

section("SP 800-38A F.1: four blocks, reference and one kl.exec with KLLEN = 4b (MGR3)")
for name, ci, k, c in SP38A_F1:
    eq(f"{name} reference", (ref(aes_encrypt, H(k), pt).hex(), ref(aes_decrypt, H(k), H(c)).hex()),
       (c, SP38A_PT))
    eq(f"{name} locker encrypt / decrypt", both(ci, k, SP38A_PT, c), (c, SP38A_PT))
control("most significant block first (MGR3 order reversed) misses every F.1 vector",
        all(run(new_cl(ci, k, state=ENC, order='neg'), pt)[0].hex() != c for _, ci, k, c in SP38A_F1))

section("SM4 (GB/T 32907-2016)")
k1 = H(SM4_KEY1)
eq("Example 1 encrypt / decrypt", (sm4_encrypt(k1, k1).hex(), sm4_decrypt(k1, H(SM4_EX1_CT)).hex()),
   (SM4_EX1_CT, SM4_KEY1))
rks, x = sm4_rks(k1), k1
for r in range(1, SM4_EX2_ROUNDS + 1):
    x = sm4_block(rks, x)
    if r in SM4_EX2_CHECKPOINTS:
        eq(f"Example 2 round {r} [ref-impl checkpoint]", x.hex(), SM4_EX2_CHECKPOINTS[r])
eq(f"Example 2, {SM4_EX2_ROUNDS} rounds", x.hex(), SM4_EX2_CT)
for name, k, p, c in SM4_MULTI:
    eq(f"{name} reference", (ref(sm4_encrypt, H(k), H(p)).hex(), ref(sm4_decrypt, H(k), H(c)).hex()), (c, p))
    eq(f"{name} SM4_ECB locker encrypt / decrypt, one kl.exec", both('SM4', k, p, c), (c, p))

section("States, transitions and general rules (F.1.1)")
_, ci, k, c = SP38A_F1[0]
ct, v = H(c), blocks_value(pt)
eq("State values Ready 1, Operate 2, Encrypt 7, Decrypt 8, Invalid 49",
   (RDY, KL_STATE_OPERATE, ENC, DEC, INV), (1, 2, 7, 8, 49))
cl = new_cl(ci, k)
eq("provisioning completes in Ready", cl.state, RDY)
cl.setst(ENC)
out = run(cl, pt)[0]
cl.setst(DEC)
eq("Encrypt -> Decrypt directly (from any valid state)", (cl.state, run(cl, out)[0].hex()), (DEC, SP38A_PT))
cl.setst(DEC)
eq("same-State kl.setst (GR16)", (cl.state, run(cl, ct)[0].hex()), (DEC, SP38A_PT))
cl.setst(RDY)
eq("back to Ready (GR15)", cl.state, RDY)
eq("kl.exec in Ready: Invalid, window zeroed, Content cleared (GR17, GR22, GR26)",
   (cl.exec(v, 512)[0], cl.state, cl.key), (0, INV, None))
cl.setst(RDY)
eq("Invalid locker: kl.setst and kl.exec perform no operation (GR26)", (cl.state, cl.exec(v, 512)[0]),
   (INV, 0))
for pol, immed, want in ((POL_DEC, DEC, DEC), (POL_DEC, ENC, INV), (POL_ENC, DEC, INV),
                         (POL_BOTH, KL_STATE_OPERATE, INV)):
    eq(f"MachinePolicy {pol:02b}: kl.setst #{immed} -> State {want}", new_cl(ci, k, pol, state=immed).state,
       want)
eq("decrypt-only locker decrypts F.1.2", run(new_cl(ci, k, POL_DEC, state=DEC), ct)[0].hex(), SP38A_PT)
cl = new_cl(ci, k, state=ENC)
eq("MGR2: KLLEN = 136 -> no operation, Invalid, window zeroed", (cl.exec(b2v(pt[:17]), 136)[0], cl.state),
   (0, INV))
eq("Form D substitution (kliobuftop = 64): output in place of input",
   v2b(new_cl(ci, k, state=ENC).exec(b2v(pt), 512)[0], 64).hex(), c)
for q in (1, 2, 3):                           # <<KLEE-GR-block-iterated-instructions>>
    cl = new_cl(ci, k, state=ENC)
    part, ks = run(cl, pt, halt_after=q)
    res, ks2 = cl.exec(b2v(part), 512, klstart=ks)
    eq(f"halt after {q} block(s), resume at klstart = {16 * q}", (ks, v2b(res, 64).hex(), ks2),
       (16 * q, c, 0))
cl = new_cl(ci, k, state=ENC)
eq("klstart >= KLLEN/8 (64, 80 of 512): empty window, only klstart = 0; 17 of 136: invalid length first, Invalid",
   (cl.exec(v, 512, klstart=64), cl.exec(v, 512, klstart=80), cl.state, cl.exec(b2v(pt[:17]), 136, klstart=17),
    cl.state), ((v, 0), (v, 0), ENC, (b2v(pt[:17]), 0), INV))
cl = new_cl(ci, k, state=ENC)
eq("input klstart = 8 (no interruption point): Invalid, window from klstart zeroed",
   (cl.exec(v, 512, klstart=8)[0], cl.state), (b2v(pt[:8]), INV))

section("PI and Serialized Content (sizes by hand, AuxDataLen = 0)")
SKID = 0x0123456789abcdef
SKS = {SKID: b2v(H(SP38A_F1[1][2]))}
for label, (_, ci, key, want), kt, pi_size, c1 in (
        ("AES-128 by value", SP38A_F1[0], 0, 32, SP38A_F1[0][2]),
        ("AES-192 by value", SP38A_F1[1], 0, 48, SP38A_F1[1][2] + "00" * 8),
        ("AES-256 by value", SP38A_F1[2], 0, 48, SP38A_F1[2][2]),
        ("AES-192 by SKID", SP38A_F1[1], 1, 32, "efcdab8967452301" + "00" * 8)):
    pi = build_pi(ci, SKID if kt else b2v(H(key)), keytype=kt)
    cl, cl2 = EcbLocker(SKS), EcbLocker(SKS)
    cl.provision(pi)
    n1 = len(c1) // 2
    eq(f"{label}: PI {pi_size} B = kl.size, Content1 {n1} B, kl.size {32 + n1}",
       (len(pi), kl_size(b2v(pi[:16]), 0, len(pi) - 16), cl.content1().hex(), kl_size(cl.mdh, n1, 0)),
       (pi_size, pi_size, c1, 32 + n1))
    cl.setst(ENC)
    half = run(cl, pt[:32])[0]
    cl2.import_scc(cl.mdh, cl.content1())
    eq(f"{label}: export after 2 blocks, import (State Encrypt), finish F.1",
       (half + run(cl2, pt[32:])[0]).hex(), want)
m192 = mdh_pack(Machine=MACHINE['AES-192'], MachinePolicy=POL_BOTH, KeyType=1, State=RDY)
cl = EcbLocker(SKS)
cl.provision(build_pi('AES-192', SKID + 1, keytype=1))
eq("unresolved SKID at provisioning -> Invalid (<<KLEE-MVR-open>>)", cl.state, INV)
cl.provision(build_pi('AES-192', ONES64, keytype=1))
eq("all-ones SKID: random key, KeyType 0, Content1 32 B, kl.size 64",
   (cl.state, cl.keytype, kl_size(cl.mdh, len(cl.content1()), 0)), (RDY, 0, 64))
cl.import_scc(m192, v2b(ONES64, 16))
eq("SCC carrying the all-ones SKID in a Complete State -> Invalid", cl.state, INV)
cl.provision(build_pi('AES-128', b2v(H(SP38A_F1[0][2])), policy=0))
eq("PI with MachinePolicy = 0 -> Invalid", cl.state, INV)
cl.import_scc(put(put(m192, 'KeyType', 0), 'State', KL_STATE_OPERATE), H(SP38A_F1[1][2]))
eq("SCC whose State ECB does not define -> Invalid", (cl.state, cl.key), (INV, None))
cl.import_scc(put(put(put(m192, 'KeyType', 0), 'State', ENC), 'StateExtension', 1), H(SP38A_F1[1][2]))
eq("SCC in Encrypt with a StateExtension ECB does not use -> Invalid", (cl.state, cl.key), (INV, None))

section("kl.derive into `key` (destination in Ready; GR36-GR40, GR42, GR43)")
_, ci, k, c = SP38A_F1[1]                     # AES-192: dest_length = 24
secret = H(k) + H("a5" * 8)
SRC = mdh_pack(UsagePolicy=0b00010, Locality=0b1_00_01_11, ExpirationDate=500, SCProtection=1)
DST = dict(UsagePolicy=0b10001, Locality=0b0_01_00_10, SCProtection=1)
narrowed = lambda m: (fld(m, 'UsagePolicy'), fld(m, 'Locality'), fld(m, 'ExpirationDate'))

def derived(kind='shared', length=32, data=secret, state=None, keytype=0, src=SRC):
    cl = EcbLocker(SKS)
    cl.provision(build_pi(ci, SKID if keytype else 0, keytype=keytype, **DST))
    if state:
        cl.setst(state)
    ok = cl.derive_key((kind, data, src), length)
    cl.setst(ENC)
    return ok, cl.state, run(cl, pt)[0].hex() if ok else cl.key, cl.mdh

for kind, length in (('shared', 32), ('shared', 24), ('drbg', 32)):
    eq(f"{kind}, length {length} >= 24: exactly 24 bytes become the key, F.1.3",
       derived(kind, length)[:3], (True, ENC, c))
eq("shared secret (restricted, GR37): UsagePolicy, Locality, ExpirationDate narrowed",
   narrowed(derived()[3]), (0b00011, 0b1_01_01_11, 500))
eq("DRBG output (unrestricted, GR38): destination MDH not narrowed",
   narrowed(derived('drbg')[3]), (DST['UsagePolicy'], DST['Locality'], 0))
for label, kw in (("length 16 < 24 (GR36 item 5, no zero-fill)", dict(length=16)),
                  ("length 0 (GR36 item 5 fails before GR43)", dict(length=0)),
                  ("source field of 16 bytes < 24 (GR36 item 5)", dict(data=secret[:16])),
                  ("destination in Encrypt (GR36 item 2)", dict(state=ENC)),
                  ("KeyType 1 destination (GR39, GR36 item 2)", dict(keytype=1)),
                  ("source SCProtection above destination (GR37)", dict(src=put(SRC, 'SCProtection', 2))),
                  ("differing Boot Session entries (GR37)", dict(src=put(SRC, 'Locality', 0b0_10_00_00)))):
    eq(f"{label} -> destination Invalid, no key", derived(**kw)[1:3], (INV, None))
src_cl, dst_cl = new_cl(ci, k), new_cl(ci, "00" * 24)
dst_cl.derive_key(src_cl, 24)
eq("ECB locker as source (no source endpoint) -> only the source Invalid", (src_cl.state, dst_cl.state),
   (INV, KL_STATE_READY))
info("kl.derive into `key`: byte t of the transfer is byte t of the key.")

section("<<KLEE-pseudocode-ECB-encryption>> [informative]: its Error State test")
eq("'48 <= X1 <= 55' passes every Valid State and catches every Error State",
   [s for s in range(1, 56) if 48 <= s <= 55], list(ERROR_STATES))
done()
