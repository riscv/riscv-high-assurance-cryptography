#!/usr/bin/env python3
"""CTR and XCTR keystream generation (<<KLEE-keystream-modes>> in
src/ace-ISA-machines.adoc) against SP 800-38A F.5 and the HCTR2 reference vectors.

The specification keeps the keystream state as two separate fields, `IV` of `n`
bits and `ctr` of `j` bits, and forms the block fed to the keystream function as

    CTR  :  tmp <- keystream_block(bswap(ctr) @ IV)      with b = n + j
    XCTR :  tmp <- keystream_block(IV xor ctr)           with b = n = j

followed by tick_ctr() and OUTPUT <- tmp.  Under <<KLEE-Notation>> the LEFT operand
of `@` occupies the more significant bits, and byte i of a byte string lives at bits
[8i+7:8i].  So `bswap(ctr) @ IV` puts the IV in the *first* n/8 bytes of the counter
block and the counter, big-endian, in the *trailing* j/8 bytes, which is what
SP 800-38A requires.  The `bswap` is load-bearing: without it the counter would be
little-endian in those bytes.

Models
------
REF-CTR   SP 800-38A written directly on byte strings: counter block =
          nonce || big-endian(ctr, j bits), incremented as an integer mod 2^j.
REF-XCTR  The HCTR2 paper's XCTR on byte strings: E_K(IV xor LE(i, 128)), the
          counter little-endian and full width, numbered from 1.
KLEE      A model of a Cryptographic Locker holding a CTR/XCTR CC (class
          KeystreamCL).  It covers provisioning from a PI (the MDH first, then the key
          or SKID) and the States _Ready_ and _Operate_ with the values of
          <<KLEE-state-constants-symmetric>>.  It also covers the Form C kl.setst that
          sets `IV` (keeping its n least significant bits), the Form B
          `kl.setst #kl_state_set_aux_value, Xs` that sets `ctr <- lsb_j(Xs)` from a
          64-bit Xs, and the (multi-block) Form C kl.exec.  The Machine text gives
          only the per-block operation.  The block loop is rule MGR3 of
          <<KLEE-Machines-other-rules>>: for i = 0, b, ..., KLLEN - b, in that order,
          the operation produces OUTPUT[i+b-1:i].  So the keystream block for the
          counter value ctr + q is the q-th block of the output byte string.
NEG       Two negative controls, both of which must fail SP 800-38A: the CTR formula
          with the `bswap` dropped (a little-endian counter in the trailing bytes),
          and a multi-block kl.exec that fills the blocks from the most significant
          position down (the keystream blocks in reverse address order).

What changed in the specification, and how this file follows it
----------------------------------------------------------------
* A Form B kl.setst carries a 64-bit operand (<<KLEE-instruction-setst>>, Rule
  <<KLEE-GR-multiple-GPRs>>).  The former check with n = 0, j = 128 loaded the whole
  SP 800-38A initial counter block f0f1...ff into `ctr` through that operand, which
  cannot hold it.  F.5 is now reproduced with the splits (n, j) = (64, 64), (96, 32)
  and (112, 16).  The Form C INPUT is the whole initial block T1, of which the
  Machine keeps the n least significant bits (its first n/8 bytes).  Form B loads
  the integer value of the trailing j/8 bytes.  This anchors the nonce/counter splits
  on the standard vectors; the old file could only compare them with REF.
* The allowed transitions are now _Ready_ -> _Operate_ and _Operate_ -> _Ready_
  (formerly "any"), so any other target State invalidates the CL.
* The multi-block loop is rule MGR3 and the granularity rule is MGR2.  A kl.exec in
  _Ready_ falls under Rules <<KLEE-SGR-no-exec-in-ready>> and
  <<KLEE-MGR-not-allowed-instructions>>.
* The Serialized Content no longer lists the MDH: `key` (or SKID) is at position i,
  `IV` at ii and `ctr` at iii, zero-padded to a multiple of 128 bits.
* <<KLEE-derive-endpoints>> makes `key` (1) the only importable field.

Vectors and provenance
----------------------
* SP 800-38A Appendix F.5.1 (CTR-AES128), F.5.3 (CTR-AES192), F.5.5 (CTR-AES256):
  initial counter block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff over the four standard
  plaintext blocks.  Transcribed from the Linux kernel crypto/testmgr.h,
  aes_ctr_tv_template, entries commented "From NIST Special Publication 800-38A,
  Appendix F.5" (raw.githubusercontent.com/torvalds/linux, master, fetched
  2026-08-26).
* XCTR: google/hctr2 test_vectors/ours/XCTR/XCTR_AES{128,256}.json
  (raw.githubusercontent.com/google/hctr2, main, fetched 2026-08-26).  These are
  the reference vectors of the HCTR2 paper's own implementation, so XCTR here is
  anchored on a reference implementation, not on a standards body's vectors ---
  no NIST XCTR vectors exist.

Anchor levels: CTR is standard-vector anchored for the splits (64, 64), (96, 32)
and (112, 16), including resumption, export/import and kl.derive.  Other splits
(including n = 0, j = 128) are reference-consistency anchored, with REF-CTR, itself
anchored, as the oracle.  XCTR is reference-implementation anchored.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import aes_encrypt, b2v, bswap, bxor, cat, sl, v2b

B = 128                         # block size b of the keystream function (AES)

# ---------------------------------------------------------------- constants
# <<KLEE-metadata-header>>: (hi, lo) of the MDH fields this file uses
F_MACHINE, F_MACHINEPOLICY = (11, 0), (13, 12)
F_STATE, F_KEYTYPE = (24, 19), (30, 29)

# <<KLEE-state-off>>, <<KLEE-states-valid>>, <<KLEE-states-error>>
ST_UNCONFIGURED, ST_READY, ST_INVALID = 0, 1, 49
# <<KLEE-state-constants-symmetric>>
ST_OPERATE, ST_ENCRYPT, ST_SET_AUX_VALUE = 2, 7, 13

# <<KLEE-Machine-field>>
POL_BOTH = 0b11
ONES64 = (1 << 64) - 1

CIPHERS = {'AES-128': 128, 'AES-192': 192, 'AES-256': 256}   # name -> k


def machine(typ, mode):
    """<<KLEE-exec-encodings>>: _Machine_ = Type in bits [11:4], Mode in bits [3:0]."""
    return (typ << 4) | mode


# <<KLEE-exec-encodings>>: CTR is Mode 1 and XCTR Mode 2 of Types 0-2
KS_MACHINES = {}
for _t, _c in enumerate(CIPHERS):
    KS_MACHINES[machine(_t, 1)] = (_c, 'CTR')
    KS_MACHINES[machine(_t, 2)] = (_c, 'XCTR')
KS_OF = {v: k for k, v in KS_MACHINES.items()}

# <<KLEE-derive-endpoints>> (work in progress), row of <<KLEE-keystream-modes>>
KS_IMPORTABLE = {1: 'key'}


def fget(v, f):
    return sl(v, f[0], f[1])


def fset(v, f, x):
    hi, lo = f
    m = ((1 << (hi - lo + 1)) - 1) << lo
    return (v & ~m) | ((x << lo) & m)


def make_mdh(mach, policy, keytype=0, state=ST_UNCONFIGURED):
    mdh = fset(0, F_MACHINE, mach)
    mdh = fset(mdh, F_MACHINEPOLICY, policy)
    mdh = fset(mdh, F_KEYTYPE, keytype)
    return fset(mdh, F_STATE, state)


def kl_getst(mdh):
    """kl.getst on RV64 (<<KLEE-instruction-getst>>): kl.getmdl, srli 19, andi 0x3F."""
    return ((mdh & ONES64) >> 19) & 0x3F


def padded_bytes(bits):
    """Length in bytes of `bits` once implicitly zero-padded to a multiple of 128 bits."""
    return -(-bits // 128) * 16


def kl_size(mdh, content1_size, pi_content_size):
    """<<KLEE-instruction-size>> for a supplied MDH (Forms B/C) with _AuxDataLen_ = 0."""
    st = kl_getst(mdh)
    if 48 <= st <= 55:
        return 16
    if st == ST_UNCONFIGURED:            # the MDH of a PI
        return 16 + pi_content_size
    return 32 + content1_size


def build_pi(mach, keytype, field, policy=POL_BOTH):
    """A PI: the MDH (position i), then `key` or the SKID (position ii), zero-padded."""
    k = CIPHERS[KS_MACHINES[mach][0]]
    width = 64 if keytype == 1 else k
    return v2b(make_mdh(mach, policy, keytype), 16) + v2b(field, padded_bytes(width))


# ---------------------------------------------------------------- REF models
def ref_ctr(key, nonce, j, ctr0, msg):
    """SP 800-38A CTR: block = nonce || big-endian(ctr, j/8 bytes)."""
    out, ctr = b'', ctr0
    for i in range(0, len(msg), 16):
        ks = aes_encrypt(key, nonce + ctr.to_bytes(j // 8, 'big'))
        chunk = msg[i:i + 16]
        out += bxor(ks[:len(chunk)], chunk)
        ctr = (ctr + 1) % (1 << j)
    return out


def ref_xctr(key, iv, ctr0, msg):
    """HCTR2's XCTR: block = IV xor little-endian(ctr, 16 bytes), counter from 1."""
    out, ctr = b'', ctr0
    for i in range(0, len(msg), 16):
        ks = aes_encrypt(key, bxor(iv, ctr.to_bytes(16, 'little')))
        chunk = msg[i:i + 16]
        out += bxor(ks[:len(chunk)], chunk)
        ctr = (ctr + 1) % (1 << 128)
    return out


# ---------------------------------------------------------------- the KLEE model
class KeystreamCL:
    """A CL holding a CTR or XCTR CC (<<KLEE-keystream-modes>>).

    For CTR, `n` and `j` are parameters of the implementation: no field of the MDH,
    of the PI or of the SCC selects them (see the SPEC-NOTE printed by this file).
    """

    def __init__(self, n=None, j=None, sks=None, variant='spec', order='spec'):
        self.n, self.j = n, j
        self.mdh = 0                     # _Unconfigured_
        self.key = self.skid = self.IV = self.ctr = None
        self.sks = sks or {}
        self.variant, self.order = variant, order

    # ------------------------------------------------------------ helpers
    @property
    def state(self):
        return kl_getst(self.mdh)

    @property
    def keytype(self):
        return fget(self.mdh, F_KEYTYPE)

    def params(self):
        """(cipher, k, mode, n, j) with the constraints of the Parameters list."""
        cipher, mode = KS_MACHINES[fget(self.mdh, F_MACHINE)]
        if mode == 'XCTR':
            n = j = B                    # b = n = j
        else:
            n, j = self.n, self.j
            assert n + j == B and n % 8 == 0 and j % 8 == 0 and j > 0   # b = n + j
        return cipher, CIPHERS[cipher], mode, n, j

    def key_field_width(self):
        return 64 if self.keytype == 1 else self.params()[1]

    def in_error(self):
        return 48 <= self.state <= 55

    def invalidate(self):
        self.mdh = fset(self.mdh, F_STATE, ST_INVALID)
        self.key = self.skid = self.IV = self.ctr = None

    def enter_ready(self):
        """"In State _Ready_, the `ctr` and `IV` fields are set to 0." """
        self.mdh = fset(self.mdh, F_STATE, ST_READY)
        self.IV = self.ctr = 0

    def _install(self, field, importing):
        if self.keytype == 0:
            self.key = field
        elif field != ONES64 and field in self.sks:
            self.skid, self.key = field, self.sks[field]
        else:
            self.invalidate()            # unresolved SKID (<<KLEE-MVR-open>>)

    # ------------------------------------------------------------ configuration
    def provision(self, pi):
        self.mdh = b2v(pi[:16])          # position i: the MDH
        self._install(sl(b2v(pi[16:]), self.key_field_width() - 1, 0), False)
        if not self.in_error():
            self.enter_ready()           # provisioning ends in _Ready_

    def content1(self):
        """Serialized Content: key or SKID (i), IV (ii), ctr (iii); the MDH is not part of it."""
        _, _, _, n, j = self.params()
        kw = self.key_field_width()
        field = self.skid if self.keytype == 1 else self.key
        return v2b(cat((self.ctr, j), (self.IV, n), (field, kw)), padded_bytes(kw + n + j))

    def import_scc(self, mdh, content1):
        self.mdh = mdh
        _, _, _, n, j = self.params()
        kw = self.key_field_width()
        v = b2v(content1)
        self.IV = sl(v, kw + n - 1, kw) if n else 0
        self.ctr = sl(v, kw + n + j - 1, kw + n)
        self._install(sl(v, kw - 1, 0), True)

    # ------------------------------------------------------------ usage
    def setst(self, immed, form='A', operand=None, KLLEN=0):
        """kl.setst.  `form` is 'A' (no operand), 'A/iobuf' (the KLIOBUF substitution of
        Form C; `operand` = the bytes [0, kliobuftop)), 'B' (`operand` = the 64-bit Xs)
        or 'C' (`operand` = a KLLEN-bit vector value)."""
        if self.in_error():
            return
        _, _, _, n, j = self.params()
        st = self.state
        if immed == ST_READY and form == 'A':
            self.enter_ready()                                   # _Operate_ -> _Ready_, SGR8
        elif (immed == ST_OPERATE and st in (ST_READY, ST_OPERATE)
              and form in ('C', 'A/iobuf')):
            value = b2v(operand) if form == 'A/iobuf' else sl(operand, KLLEN - 1, 0)
            self.IV = sl(value, n - 1, 0) if n else 0            # n least significant bits
            self.mdh = fset(self.mdh, F_STATE, ST_OPERATE)
        elif (immed == ST_SET_AUX_VALUE and st in (ST_READY, ST_OPERATE)
              and form == 'B'):
            xs = sl(operand, 63, 0)                              # Xs is a 64-bit operand
            self.ctr = sl(xs, j - 1, 0) if j < 64 else xs        # lsb_j(Xs); _State_ unchanged
        else:
            self.invalidate()                                    # not an allowed instruction

    def exec(self, KLLEN, klstart=0, out=0, halt_after=None, iobuf=False):
        """(Multi-block) Form C kl.exec, or its Form D substitution into the KLIOBUF.

        The operand is output only: `out` is its prior value.  Returns (out, klstart).
        """
        lo = 8 * klstart
        window = (((1 << KLLEN) - 1) >> lo) << lo if lo < KLLEN else 0
        if self.in_error():
            return out & ~window, 0
        if lo % B or lo >= KLLEN:
            # an output-only operand: a klstart that is no interruption point, and an
            # empty window, both yield no operation (<<KLEE-CSR-klstart>>)
            return out, klstart
        if KLLEN % B:
            if iobuf:                    # KLIOBUF used only as output: no operation
                return out, klstart
            self.invalidate()            # MGR2
            return out & ~window, 0
        if self.state != ST_OPERATE:     # e.g. kl.exec in _Ready_
            self.invalidate()
            return out & ~window, 0
        cipher, k, mode, n, j = self.params()
        key = v2b(self.key, k // 8)
        positions = list(range(lo, KLLEN, B))      # MGR3: i = 0, b, ..., in that order
        if self.order != 'spec':
            positions.reverse()                    # NEG: most significant block first
        for q, i in enumerate(positions):
            if halt_after is not None and q == halt_after:
                return out, i // 8                 # precise halt
            if mode == 'CTR':
                if self.variant == 'spec':
                    blk = cat((bswap(self.ctr, j // 8), j), (self.IV, n))   # bswap(ctr) @ IV
                else:
                    blk = cat((self.ctr, j), (self.IV, n))                  # NEG: no bswap
            else:
                blk = self.IV ^ self.ctr                                    # IV xor ctr
            tmp = b2v(aes_encrypt(key, v2b(blk, B // 8)))   # tmp <- keystream_block(...)
            self.ctr = (self.ctr + 1) % (1 << j)            # tick_ctr()
            out = (out & ~(((1 << B) - 1) << i)) | (tmp << i)   # OUTPUT <- tmp
        return out, 0

    # ------------------------------------------------------------ kl.derive
    def derive_dest(self, j, src, length):
        if self.in_error():
            return False
        if j not in KS_IMPORTABLE or self.state != ST_READY or self.keytype == 1:
            self.invalidate()
            return False
        dest_length = self.params()[1] // 8
        eff_length = min(length, dest_length)
        if eff_length:
            self.key = b2v(src[:eff_length] + bytes(dest_length - eff_length))
        return True


def keystream(cl, nbytes, per_block=False):
    """Keystream bytes from Form C kl.exec: one multi-block instruction, or one per block."""
    nblk = -(-nbytes // 16)
    if per_block:
        out = b''.join(v2b(cl.exec(B)[0], 16) for _ in range(nblk))
    else:
        out = v2b(cl.exec(nblk * B)[0], nblk * 16)
    return out[:nbytes]                          # the caller discards excess bits


def ctr_cl(cipher, key, n, j, keytype=0, sks=None, **kw):
    cl = KeystreamCL(n, j, sks=sks, **kw)
    cl.provision(build_pi(KS_OF[(cipher, 'CTR')], keytype, key))
    return cl


def enter_operate(cl, iv_value, ctr0, ctr_first=False, KLLEN=128):
    """Form C kl.setst #kl_state_operate (IV <- INPUT) and Form B set initial counter."""
    if ctr_first:
        cl.setst(ST_SET_AUX_VALUE, 'B', ctr0)
    cl.setst(ST_OPERATE, 'C', iv_value, KLLEN)
    if not ctr_first:
        cl.setst(ST_SET_AUX_VALUE, 'B', ctr0)


def kl_ctr(key, iv_value, n, j, msg, ctr0=0, per_block=False, **kw):
    cipher = f"AES-{len(key) * 8}"
    cl = ctr_cl(cipher, b2v(key), n, j, **kw)
    enter_operate(cl, iv_value, ctr0)
    return bxor(keystream(cl, len(msg), per_block), msg)


def kl_xctr(key, iv_value, msg, ctr0=0, form_b=True):
    cipher = f"AES-{len(key) * 8}"
    cl = KeystreamCL()
    cl.provision(build_pi(KS_OF[(cipher, 'XCTR')], 0, b2v(key)))
    cl.setst(ST_OPERATE, 'C', iv_value, 128)
    if form_b:
        cl.setst(ST_SET_AUX_VALUE, 'B', ctr0)
    return bxor(keystream(cl, len(msg)), msg)


# ---------------------------------------------------------------- vectors
SP38A_PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                         "ae2d8a571e03ac9c9eb76fac45af8e51"
                         "30c81c46a35ce411e5fbc1191a0a52ef"
                         "f69f2445df4f9b17ad2b417be66c3710")
SP38A_ICB = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
SP38A_F5 = [
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

# google/hctr2 XCTR reference vectors: (label, key, nonce, plaintext, ciphertext)
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

T1 = b2v(SP38A_ICB)                  # the whole initial counter block, as a value
F5_SPLITS = ((64, 64), (96, 32), (112, 16))


def f5_ctr0(n):
    """The integer whose big-endian encoding is the trailing (128 - n)/8 bytes of T1."""
    return int.from_bytes(SP38A_ICB[n // 8:], 'big')


# ---------------------------------------------------------------- run
ok = True
neg_fired = {'bswap': False, 'order': False}
W = 64


def chk(label, got, want):
    global ok
    good = got == want
    ok = ok and good
    print(f"  {label:<{W}} {'PASS' if good else 'FAIL'}")
    if not good:
        print(f"      got  {got}")
        print(f"      want {want}")
    return good


def info(text):
    print(f"INFO  {text}")


def spec_note(text):
    print(f"SPEC-NOTE  {text}")


print("== SP 800-38A F.5: REF-CTR implements the standard")
icb = int.from_bytes(SP38A_ICB, 'big')       # the whole block is the counter: n=0, j=128
for name, k, c in SP38A_F5:
    key = bytes.fromhex(k)
    chk(name + " REF", ref_ctr(key, b'', 128, icb, SP38A_PT).hex(), c)

print("\n== KLEE: F.5 through a CL, one Form C kl.exec with KLLEN = 4b (MGR3)")
print("   Form C kl.setst #kl_state_operate with INPUT = T1 (KLLEN = 128 > n: the")
print("   n least significant bits, the first n/8 bytes, become IV); Form B")
print("   #kl_state_set_aux_value with Xs = the trailing j/8 bytes read big-endian")
for name, k, c in SP38A_F5:
    key = bytes.fromhex(k)
    for n, j in F5_SPLITS:
        chk(f"{name} KLEE, (n, j) = ({n}, {j})",
            kl_ctr(key, T1, n, j, SP38A_PT, ctr0=f5_ctr0(n)).hex(), c)
    chk(f"{name} KLEE, (96, 32), four kl.exec with KLLEN = b",
        kl_ctr(key, T1, 96, 32, SP38A_PT, ctr0=f5_ctr0(96), per_block=True).hex(), c)

print("\n== Negative controls, (n, j) = (64, 64)")
print("KAT-EXPECT-FAIL: NEG little-endian counter")
print("KAT-EXPECT-FAIL: NEG MS-first order")
print(f"\n   {'vector':<24} {'KLEE (spec)':<14} {'NEG little-endian counter':<28}"
      f"{'NEG MS-first order'}")
for name, k, c in SP38A_F5:
    key = bytes.fromhex(k)
    good = kl_ctr(key, T1, 64, 64, SP38A_PT, ctr0=f5_ctr0(64)).hex() == c
    neg1 = kl_ctr(key, T1, 64, 64, SP38A_PT, ctr0=f5_ctr0(64), variant='neg').hex() != c
    neg2 = kl_ctr(key, T1, 64, 64, SP38A_PT, ctr0=f5_ctr0(64), order='neg').hex() != c
    ok = ok and good
    neg_fired['bswap'] |= neg1
    neg_fired['order'] |= neg2
    print(f"   {name:<24} {'PASS' if good else 'FAIL':<14} "
          f"{'FAIL' if neg1 else 'PASS (does not discriminate)':<28}"
          f"{'FAIL' if neg2 else 'PASS (does not discriminate)'}")
print()
key = bytes.fromhex(SP38A_F5[0][1])
got = kl_ctr(key, T1, 120, 8, SP38A_PT, ctr0=f5_ctr0(120))
chk("(n, j) = (120, 8): ctr wraps mod 2^8 after 0xff, F.5.1 not reproduced",
    (got.hex() != SP38A_F5[0][2], got),
    (True, ref_ctr(key, SP38A_ICB[:15], 8, 0xff, SP38A_PT)))

print("\n== Nonce/counter splits: KLEE vs REF-CTR [reference-consistency only]")
print("   b = n + j, IV in the first n/8 bytes, counter big-endian in the last j/8;")
print("   starting counters 0, 1, 7 and the wrap point 2^j - 2, or, for j > 64,")
print("   2^64 - 1 (the largest value a Form B Xs holds; its tick carries into bit 64)")
key = bytes.fromhex(SP38A_F5[0][1])
msg = bytes(range(80))
for n, j in ((96, 32), (64, 64), (120, 8), (32, 96), (112, 16), (0, 128)):
    nonce = bytes(range(1, n // 8 + 1))
    starts = (0, 1, 7, (1 << j) - 2 if j <= 64 else ONES64)
    got = [kl_ctr(key, b2v(nonce), n, j, msg, ctr0=s) for s in starts]
    want = [ref_ctr(key, nonce, j, s, msg) for s in starts]
    chk(f"n = {n:3d}, j = {j:3d}  (4 starting counters)", got, want)
info("(n, j) = (0, 128) cannot reproduce F.5: its initial counter block exceeds the "
     "64 bits a Form B kl.setst can load into `ctr`, and Form C sets no counter bits.")

print("\n== Form B set initial counter: ctr <- lsb_j(Xs), _State_ unchanged")
name, k, c = SP38A_F5[0]
key = bytes.fromhex(k)
cl = ctr_cl('AES-128', b2v(key), 64, 64)
enter_operate(cl, T1, f5_ctr0(64) + 2)       # jump into the stream at block 2
chk("F.5.1 blocks 2..3 via Form B (random access)",
    bxor(keystream(cl, 32), SP38A_PT[32:]).hex(), c[64:])
cl = ctr_cl('AES-128', b2v(key), 96, 32)
enter_operate(cl, b2v(bytes(range(1, 13))), (0xdeadbeef << 32) | 5)
chk("lsb_j truncation of Xs (j = 32): only the low 32 bits survive",
    keystream(cl, 32), ref_ctr(key, bytes(range(1, 13)), 32, 5, bytes(32)))
cl = ctr_cl('AES-128', b2v(key), 64, 64)
cl.setst(ST_SET_AUX_VALUE, 'B', f5_ctr0(64))
st_ready = cl.state
cl.setst(ST_OPERATE, 'C', T1, 128)
st_op = cl.state
cl.setst(ST_SET_AUX_VALUE, 'B', f5_ctr0(64))
chk("Form B in _Ready_ and in _Operate_ leaves _State_ at 1, resp. 2",
    (st_ready, st_op, cl.state), (ST_READY, ST_OPERATE, ST_OPERATE))
cl = ctr_cl('AES-128', b2v(key), 64, 64)
enter_operate(cl, T1, f5_ctr0(64), ctr_first=True)
chk("Form B in _Ready_, then Form C: ctr survives the transition, F.5.1",
    bxor(keystream(cl, 64), SP38A_PT).hex(), c)
info("'In State _Ready_, the ctr and IV fields are set to 0' is read as happening on "
     "entry to _Ready_: Form B is allowed in _Ready_, and the transition to _Operate_ "
     "sets only IV.")
info("Form B carries 64 bits, so for j > 64 (XCTR, or CTR with n < 64) lsb_j(Xs) is "
     "read as Xs zero-extended to j bits; <<KLEE-Notation>> defines lsb_c only for "
     "c <= |x|.")

print("\n== XCTR [reference-implementation anchor: google/hctr2]")
print("   HCTR2 numbers the counter from 1, while a KLEE CC leaves State _Ready_")
print("   with ctr = 0, so the Form B operation supplies the initial counter 1;")
print("   the keystream comes from one multi-block Form C kl.exec (MGR3)")
for name, k, iv, p, c in HCTR2_XCTR:
    key, nonce = bytes.fromhex(k), bytes.fromhex(iv)
    pt, ct = bytes.fromhex(p), bytes.fromhex(c)
    chk(name + " REF", ref_xctr(key, nonce, 1, pt).hex(), c)
    chk(name + " KLEE (Form B ctr <- 1)", kl_xctr(key, b2v(nonce), pt, ctr0=1).hex(), c)
    chk(name + " KLEE decrypt round-trip",
        kl_xctr(key, b2v(nonce), ct, ctr0=1).hex(), p)

print("\n== XCTR/CTR mutual consistency and separation")
key = bytes.fromhex(SP38A_F5[0][1])
iv = bytes(range(16))
msg = bytes(range(64))
chk("REF-XCTR == KLEE-XCTR over 4 blocks, ctr = 0 as left by _Ready_",
    kl_xctr(key, b2v(iv), msg, form_b=False).hex(), ref_xctr(key, iv, 0, msg).hex())
# the KLEE default start (ctr = 0) must differ from HCTR2's (ctr = 1): the Form B
# step above is necessary, not decorative.
chk("ctr = 0 and ctr = 1 XCTR streams differ",
    kl_xctr(key, b2v(iv), msg, 0) != kl_xctr(key, b2v(iv), msg, 1), True)
# CTR and XCTR must not coincide, or the specification's distinction is vacuous
nonce = bytes(range(1, 13))
chk("CTR and XCTR produce different keystreams",
    kl_ctr(key, b2v(nonce), 96, 32, msg) != kl_xctr(key, b2v(nonce + bytes(4)), msg,
                                                    form_b=False), True)

print("\n== RULES: States, transitions and the general rules (F.5.1, (n, j) = (64, 64))")
name, k, c = SP38A_F5[0]
key = bytes.fromhex(k)
chk("state constants: Ready 1, Operate 2, Set_Aux_Value 13, Invalid 49",
    (ST_READY, ST_OPERATE, ST_SET_AUX_VALUE, ST_INVALID), (1, 2, 13, 49))
cl = ctr_cl('AES-128', b2v(key), 64, 64)
chk("provisioning completes in _Ready_ with IV = ctr = 0",
    (cl.state, cl.IV, cl.ctr), (ST_READY, 0, 0))
res, _ = cl.exec(512, out=ONES64)
chk("kl.exec in _Ready_: _Invalid_, output window zeroed, Content cleared",
    (cl.state, res, cl.key), (ST_INVALID, 0, None))
cl = ctr_cl('AES-128', b2v(key), 64, 64)
cl.setst(ST_ENCRYPT, 'C', T1, 128)
chk("kl.setst #kl_state_encrypt: not a listed transition -> _Invalid_",
    cl.state, ST_INVALID)
cl = ctr_cl('AES-128', b2v(key), 64, 64)
cl.setst(ST_OPERATE, 'B', T1 & ONES64)
chk("kl.setst #kl_state_operate in Form B (Form C required) -> _Invalid_",
    cl.state, ST_INVALID)
cl = ctr_cl('AES-128', b2v(key), 64, 64)
cl.setst(ST_SET_AUX_VALUE, 'C', f5_ctr0(64), 128)
chk("#kl_state_set_aux_value in Form C (Form B only) -> _Invalid_", cl.state, ST_INVALID)

cl = ctr_cl('AES-128', b2v(key), 64, 64)
enter_operate(cl, T1, f5_ctr0(64))
first = keystream(cl, 64)
cl.setst(ST_READY)
cleared = (cl.state, cl.IV, cl.ctr)
cl.setst(ST_OPERATE, 'C', T1, 128)
chk("_Operate_ -> _Ready_ zeroes IV and ctr; re-entry restarts at ctr = 0",
    (cleared, bxor(keystream(cl, 64), SP38A_PT)),
    ((ST_READY, 0, 0), ref_ctr(key, SP38A_ICB[:8], 64, 0, SP38A_PT)))
cl = ctr_cl('AES-128', b2v(key), 64, 64)
cl.setst(ST_OPERATE, 'C', 0x1234, 128)       # a wrong IV
cl.setst(ST_SET_AUX_VALUE, 'B', f5_ctr0(64))
cl.setst(ST_OPERATE, 'C', T1, 128)           # same-State kl.setst (SGR4)
chk("_Operate_ -> _Operate_ (SGR4): IV replaced, ctr kept; F.5.1",
    (cl.state, bxor(keystream(cl, 64), SP38A_PT).hex()), (ST_OPERATE, c))
info("a same-State kl.setst #kl_state_operate (SGR4) is read as the Form C "
     "transition into _Operate_: it replaces IV and, _Ready_ not being entered, "
     "keeps ctr.")

cl = ctr_cl('AES-128', b2v(key), 64, 64)
cl.setst(ST_OPERATE, 'A/iobuf', SP38A_ICB)   # KLIOBUF, kliobuftop = 16, Form A
cl.setst(ST_SET_AUX_VALUE, 'B', f5_ctr0(64))
buf = bytes(64)                              # kliobuftop = 64: Form D replacing Form C
res, _ = cl.exec(8 * 64, out=b2v(buf), iobuf=True)
chk("Form A kl.setst and Form D kl.exec with the KLIOBUF: F.5.1",
    bxor(v2b(res, 64), SP38A_PT).hex(), c)
info("'a Form C kl.setst instruction must be issued' is read as 'is expected', so the "
     "Form A substitution of <<KLEE-usage-input-output>> applies; read as 'required' "
     "it would make CTR unusable without Zklv.")

cl = ctr_cl('AES-128', b2v(key), 64, 64)
enter_operate(cl, T1, f5_ctr0(64))
res, _ = cl.exec(136, out=(1 << 136) - 1)    # vector KLLEN = 17 bytes
chk("MGR2 (vector): KLLEN = 136 -> no operation, _Invalid_, window zeroed",
    (cl.state, res), (ST_INVALID, 0))
cl = ctr_cl('AES-128', b2v(key), 64, 64)
enter_operate(cl, T1, f5_ctr0(64))
prior = b2v(bytes(range(17)))
res, _ = cl.exec(136, out=prior, iobuf=True)  # KLIOBUF with kliobuftop = 17
chk("KLIOBUF output only, kliobuftop = 17 -> no operation, no state change",
    (cl.state, cl.ctr, res), (ST_OPERATE, f5_ctr0(64), prior))
info("an output-only KLIOBUF operand of invalid length performs no operation "
     "(<<KLEE-usage-input-output>>), while MGR2 invalidates the CL for the same KLLEN "
     "in a vector Form C; the specific rule is applied to the KLIOBUF case, per "
     "'except when explicitly stated otherwise'.")
cl = ctr_cl('AES-128', b2v(key), 64, 64)
enter_operate(cl, T1, f5_ctr0(64))
res, ks = cl.exec(512, klstart=8, out=7)
chk("klstart = 8 (output only, no interruption point) -> no operation",
    (cl.state, cl.ctr, res), (ST_OPERATE, f5_ctr0(64), 7))
for q in (1, 2, 3):
    for iob in (False, True):
        cl = ctr_cl('AES-128', b2v(key), 64, 64)
        enter_operate(cl, T1, f5_ctr0(64))
        part, ks = cl.exec(512, halt_after=q, iobuf=iob)
        whole, ks2 = cl.exec(512, klstart=ks, out=part, iobuf=iob)
        chk(f"{'Form D' if iob else 'Form C'} kl.exec halted after {q} block(s) "
            f"(klstart = {16 * q}), resumed",
            (ks, bxor(v2b(whole, 64), SP38A_PT).hex(), ks2), (16 * q, c, 0))
cl = ctr_cl('AES-128', b2v(key), 120, 8)
enter_operate(cl, T1, 0xff)
cl.exec(B)
chk("no block limit: ctr wraps from 2^j - 1 to 0 and the CL stays in _Operate_",
    (cl.ctr, cl.state), (0, ST_OPERATE))

print("\n== DATA: Provisioning Input and Serialized Content")
print("   (sizes in bytes, worked out by hand from the tables; SCC with _AuxDataLen_ = 0)")
SKID = 0x0123456789abcdef
SKS = {SKID: b2v(key)}                       # the F.5.1 key as a system key
for cipher, kt, pi_size, c1_size in (('AES-128', 0, 32, 32), ('AES-192', 0, 48, 48),
                                     ('AES-256', 0, 48, 48), ('AES-128', 1, 32, 32)):
    field = SKID if kt else (1 << CIPHERS[cipher]) - 1
    pi = build_pi(KS_OF[(cipher, 'CTR')], kt, field)
    cl = KeystreamCL(64, 64, sks=SKS)
    cl.provision(pi)
    chk(f"{cipher} {'SKID' if kt else 'by value'}: PI {pi_size}, Content1 {c1_size}, "
        f"kl.size {pi_size} / {32 + c1_size}",
        (len(pi), kl_size(make_mdh(KS_OF[(cipher, 'CTR')], POL_BOTH, kt), 0, len(pi) - 16),
         len(cl.content1()), kl_size(cl.mdh, len(cl.content1()), 0)),
        (pi_size, pi_size, c1_size, 32 + c1_size))
# after two blocks of F.5.1: key || IV (first 8 bytes of T1) || bin(ctr, 64)
C1_VALUE = (k + "f0f1f2f3f4f5f6f7" + "01fffdfcfbfaf9f8")
C1_SKID = ("efcdab8967452301" + "f0f1f2f3f4f5f6f7" + "01fffdfcfbfaf9f8" + "00" * 8)
for label, kt, field, want_c1 in (("by value", 0, b2v(key), C1_VALUE),
                                  ("by SKID", 1, SKID, C1_SKID)):
    cl = ctr_cl('AES-128', field, 64, 64, keytype=kt, sks=SKS)
    enter_operate(cl, T1, f5_ctr0(64))
    head = keystream(cl, 32)
    c1 = cl.content1()
    cl2 = KeystreamCL(64, 64, sks=SKS)
    cl2.import_scc(cl.mdh, c1)
    tail = keystream(cl2, 32)
    chk(f"{label}: Content1 after 2 blocks = {len(want_c1) // 2} B, key|IV|ctr",
        c1.hex(), want_c1)
    chk(f"{label}: import it and finish: F.5.1",
        (cl2.state, bxor(head + tail, SP38A_PT).hex()), (ST_OPERATE, c))
cl = ctr_cl('AES-128', b2v(key), 64, 64)
enter_operate(cl, T1, f5_ctr0(64))
head = keystream(cl, 32)
other = KeystreamCL(96, 32)
other.import_scc(cl.mdh, cl.content1())
chk("the same SCC imported with (n, j) = (96, 32) continues a different stream",
    bxor(head + keystream(other, 32), SP38A_PT).hex() != c, True)
spec_note("the counter size j (hence n = b - j) of a CTR Machine is fixed by no field: "
          "<<KLEE-exec-encodings>> has one AES128_CTR, and neither the PI nor the "
          "Serialized Content carries j.  The length rule is unaffected (n + j = b), but "
          "the IV truncation, the wrap of tick_ctr and the IV/ctr boundary inside "
          "Content1 all depend on it, so two implementations choosing different splits "
          "interpret the same SCC differently (previous line).  This file exercises "
          "several splits as implementation parameters.")
info("the CTR/XCTR text gates no transition on _MachinePolicy_; the PIs of this file "
     "set both bits.")

print("\n== DERIVE: <<KLEE-derive-endpoints>>, destination `key` (1), CL in _Ready_")
source = key + bytes.fromhex("5a" * 16)      # a 32-byte source field
cl = ctr_cl('AES-128', 0, 64, 64)
done = cl.derive_dest(1, source, 32)
enter_operate(cl, T1, f5_ctr0(64))
chk("derive 32 bytes into the 16-byte key, then F.5.1",
    (done, bxor(keystream(cl, 64), SP38A_PT).hex()), (True, c))
cl = ctr_cl('AES-128', 0, 64, 64)
chk("destination index 2 (`IV` is not importable) -> _Invalid_",
    (cl.derive_dest(2, source, 32), cl.state), (False, ST_INVALID))
cl = ctr_cl('AES-128', 0, 64, 64)
enter_operate(cl, T1, 0)
chk("destination in _Operate_ -> _Invalid_",
    (cl.derive_dest(1, source, 32), cl.state), (False, ST_INVALID))

for label, fired in (("little-endian counter", neg_fired['bswap']),
                     ("MS-first order", neg_fired['order'])):
    if not fired:
        print(f"\nnegative control '{label}' did not fire: the test is not discriminating")
        ok = False

print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
