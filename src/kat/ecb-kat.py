#!/usr/bin/env python3
"""ECB mode (<<KLEE-ECB-mode>> in src/ace-ISA-machines.adoc) against FIPS 197,
SP 800-38A F.1 and GB/T 32907-2016 (SM4).

What is checked
---------------
REF    A plain byte-string ECB reference: split the message into b-bit blocks in
       address order and apply enc_blk/dec_blk to each.  Anchored directly on the
       published vectors.

KLEE   The ECB Machine as the specification now states it, driven through a small
       model of a Cryptographic Locker (class EcbCL): a PI is provisioned, the CL is
       moved between _Ready_, _Encrypt_ and _Decrypt_ with kl.setst, and data is
       processed with the (multi-block) Form A kl.exec, whose per-block operation
       <<KLEE-ECB-mode>> gives as

           OUTPUT <- enc_blk(key, INPUT)      resp.      OUTPUT <- dec_blk(key, INPUT)

       The block loop is no longer written in the ECB text.  It is now rule MGR3 of
       <<KLEE-Machines-other-rules>>: for i = 0, b, 2b, ..., KLLEN - b, in that
       order, the per-block operation consumes INPUT[i+b-1:i] and produces
       OUTPUT[i+b-1:i].  Under <<KLEE-Notation>> byte j of a byte string sits at
       bits [8j+7:8j], so the least significant block of the KLEE value is the
       block at the lowest address, and the byte-string view of the result must
       equal REF.  The 4-block operands are built with cat() (left operand more
       significant, so the blocks are listed in reverse address order).

NEG    A negative control mapping the most significant block of the value to the
       first block of the string.  It must disagree with the vectors.

RULES  Behaviour the ECB text now leaves to the general rules: a kl.exec in _Ready_
       invalidates the CL (Rules <<KLEE-SGR-no-exec-in-ready>> and
       <<KLEE-MGR-not-allowed-instructions>>); a KLLEN that is not a multiple of b
       performs no operation and invalidates the CL (MGR2), the output window is
       zeroed (Rule <<KLEE-SGR-usage-cr-error-state>>) and the Content cleared
       (Rule <<KLEE-SGR-clear-cr-content-error-state>>); the _MachinePolicy_ gate on
       the transitions (<<KLEE-Machine-field>>); the return to _Ready_ (SGR8 of
       <<KLEE-State-management>>); the KLIOBUF substitution
       (<<KLEE-usage-input-output>>); the interruption points and resumption of a
       multi-block kl.exec (<<KLEE-CSR-klstart>>, Rule
       <<KLEE-IRR-block-iterated-instructions>>).

DATA   The Provisioning Input and the Serialized Content as "Definition of a
       Machine in KLEE" now describes them.  The PI starts with the 128-bit MDH,
       which the Machine tables no longer list, and the key (or the 64-bit SKID of
       <<KLEE-rules-system-keys>>) is at its position ii.  The MDH is not part of the
       Serialized Content, where the key is at position i.  Both are zero-padded to a
       multiple of 128 bits.  The sizes are checked against kl.size
       (<<KLEE-instruction-size>>), hand-computed from those tables.  SKID resolution
       and the all-ones SKID are checked against <<KLEE-KeyType-field>>,
       <<KLEE-system-keys>> and <<KLEE-MVR-open>>.

DERIVE The destination endpoint `key` (1) of <<KLEE-derive-endpoints>>, with the
       Transfer Size Rules of <<KLEE-derive-rule-both-fixed-size>> (that table is
       marked work in progress).

BOOK 4 The informative example <<KLEE-pseudocode-ECB-encryption>> (SPEC-NOTE only).

SM4 is included because KLEE names it as an instantiable block cipher, and because
it exercises the value/byte-string mapping with a cipher whose own specification is
written big-endian.

Vectors and provenance
----------------------
* FIPS 197 Appendix C.1/C.2/C.3 -- single-block AES-128/192/256.  (Also re-checked
  inside common.py's self-test; repeated here so this file stands alone.)
* SP 800-38A Appendix F.1.1/F.1.2 (ECB-AES128), F.1.3/F.1.4 (ECB-AES192),
  F.1.5/F.1.6 (ECB-AES256) -- the four-block message.  These twelve output blocks
  were additionally recomputed with the independent AES in common.py, whose
  own anchor is FIPS 197.
* SM4 S-box: transcribed from the OpenSSL SM4 reference implementation,
  crypto/sm4/sm4.c, SM4_S[256] (raw.githubusercontent.com/openssl/openssl,
  master, fetched 2026-08-26).  The table is only a starting point: the
  implementation built on it is anchored below on the GB/T standard vectors.
* GB/T 32907-2016 Example 1 (single block, key = plaintext =
  0123456789abcdeffedcba9876543210 -> 681edf34d206965e86b3e94f536e4246).  Also
  reproduced in the Linux kernel crypto/testmgr.h sm4_tv_template as
  "GB/T 32907-2016 Example 1".
* GB/T 32907-2016 Example 2, the full 1,000,000-round iteration vector
  (-> 595298c7c6fd271f0402f804c33d3f66).  This runs in about 30 s in pure Python,
  which fits the time budget, so the vector is used whole rather than truncated.
  The intermediate values at rounds 100/1000/10000 are recorded alongside it as
  reference-implementation checkpoints (they are not published constants, and are
  labelled as such); they exist only so that a failure can be localized.
* SM4 multi-block ECB: GB/T 32907-2016 A.2.1.1 and A.2.1.2, as reproduced in the
  Linux kernel crypto/testmgr.h sm4_tv_template.

Anchor levels: the vector checks are standard-vector anchored.  The RULES, DATA and
DERIVE checks are anchored on the same vectors where a vector can express the rule
(a derived key must reproduce F.1.3, a resumed kl.exec must reproduce F.1.1).
Otherwise they compare the model with sizes and byte layouts worked out by hand
from the specification's tables.

Coverage note: SM4 decryption is checked only by round-tripping and by the
reverse-round-key inversion of the published encryption vectors; no independent
published SM4 decryption vector is used.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import aes_decrypt, aes_encrypt, b2v, cat, sl, v2b

# ---------------------------------------------------------------- SM4
# S-box: OpenSSL crypto/sm4/sm4.c, SM4_S[256].
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


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _sm4_tau(a):
    return ((SM4_SBOX[(a >> 24) & 0xFF] << 24) | (SM4_SBOX[(a >> 16) & 0xFF] << 16)
            | (SM4_SBOX[(a >> 8) & 0xFF] << 8) | SM4_SBOX[a & 0xFF])


def _sm4_T(a):
    b = _sm4_tau(a)
    return b ^ _rotl32(b, 2) ^ _rotl32(b, 10) ^ _rotl32(b, 18) ^ _rotl32(b, 24)


def _sm4_Tp(a):
    b = _sm4_tau(a)
    return b ^ _rotl32(b, 13) ^ _rotl32(b, 23)


def sm4_key_schedule(key):
    """The 32 round keys of GB/T 32907-2016 5.2 (words big-endian, as the standard writes them)."""
    mk = [int.from_bytes(key[4 * i:4 * i + 4], 'big') for i in range(4)]
    k = [mk[i] ^ SM4_FK[i] for i in range(4)]
    rks = []
    for i in range(32):
        ck = 0
        for j in range(4):
            ck = (ck << 8) | ((28 * i + 7 * j) & 0xFF)
        k.append(k[i] ^ _sm4_Tp(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck))
        rks.append(k[i + 4])
    return rks


def _sm4_block(rks, blk):
    x = [int.from_bytes(blk[4 * i:4 * i + 4], 'big') for i in range(4)]
    for i in range(32):
        x.append(x[i] ^ _sm4_T(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rks[i]))
    return b''.join(x[35 - i].to_bytes(4, 'big') for i in range(4))


def sm4_encrypt(key, blk):
    return _sm4_block(sm4_key_schedule(key), blk)


def sm4_decrypt(key, blk):
    """Decryption is the same round function with the round keys reversed (GB/T 32907-2016 5.4)."""
    return _sm4_block(list(reversed(sm4_key_schedule(key))), blk)


# ---------------------------------------------------------------- constants
B = 128                         # the block size b of every cipher in this file

# <<KLEE-metadata-header>>: (hi, lo) of the MDH fields this file uses
F_MACHINE, F_MACHINEPOLICY = (11, 0), (13, 12)
F_STATE, F_KEYTYPE = (24, 19), (30, 29)

# <<KLEE-state-off>>, <<KLEE-states-valid>>, <<KLEE-states-error>>
ST_UNCONFIGURED, ST_READY, ST_INVALID = 0, 1, 49
# <<KLEE-state-constants-symmetric>>
ST_OPERATE, ST_ENCRYPT, ST_DECRYPT = 2, 7, 8

# <<KLEE-Machine-field>>: lower bit of _MachinePolicy_ = encryption, upper = decryption
POL_ENC, POL_DEC = 0b01, 0b10
POL_BOTH = POL_ENC | POL_DEC

ONES64 = (1 << 64) - 1          # the all-ones SKID (<<KLEE-KeyType-field>>)


def machine(typ, mode):
    """<<KLEE-exec-encodings>>: _Machine_ = Type in bits [11:4], Mode in bits [3:0]."""
    return (typ << 4) | mode


# cipher name -> (enc_blk, dec_blk, k)
CIPHERS = {
    'AES-128': (aes_encrypt, aes_decrypt, 128),
    'AES-192': (aes_encrypt, aes_decrypt, 192),
    'AES-256': (aes_encrypt, aes_decrypt, 256),
    'SM4': (sm4_encrypt, sm4_decrypt, 128),
}
# <<KLEE-exec-encodings>>: the ECB Machines are Mode 0 of Types 0-3
ECB_MACHINES = {machine(0, 0): 'AES-128', machine(1, 0): 'AES-192',
                machine(2, 0): 'AES-256', machine(3, 0): 'SM4'}
ECB_OF = {v: k for k, v in ECB_MACHINES.items()}

# <<KLEE-derive-endpoints>> (work in progress), row of <<KLEE-ECB-mode>>
ECB_EXPORTABLE = {}             # "A secret key is never an exportable source."
ECB_IMPORTABLE = {1: 'key'}


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
    return ((mdh & ((1 << 64) - 1)) >> 19) & 0x3F


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
    return 32 + content1_size            # a Valid State


def build_pi(mach, policy, keytype, field):
    """A PI: the MDH (position i), then the key or SKID (position ii), zero-padded."""
    k = CIPHERS[ECB_MACHINES[mach]][2]
    width = 64 if keytype == 1 else k
    return v2b(make_mdh(mach, policy, keytype), 16) + v2b(field, padded_bytes(width))


# ---------------------------------------------------------------- REF
def ref_ecb(enc, key, data, bsz=16):
    """Byte-string ECB: apply the block function to each b-bit block in address order."""
    return b''.join(enc(key, data[i:i + bsz]) for i in range(0, len(data), bsz))


# ---------------------------------------------------------------- the KLEE model
class EcbCL:
    """A CL holding an ECB CC, per <<KLEE-ECB-mode>> and the general rules."""

    def __init__(self, sks=None, rng=None, order='spec'):
        self.mdh = 0                     # _Unconfigured_: every MDH field reads zero
        self.key = self.skid = None
        self.sks = sks or {}
        self.rng = rng or random.Random(2026)
        self.order = order               # 'spec' (MGR3) or the NEG misreading

    # ------------------------------------------------------------ helpers
    @property
    def state(self):
        return kl_getst(self.mdh)

    @property
    def keytype(self):
        return fget(self.mdh, F_KEYTYPE)

    def cipher(self):
        return CIPHERS[ECB_MACHINES[fget(self.mdh, F_MACHINE)]]

    def key_field_width(self):
        """`k` or 64 (the SKID, <<KLEE-rules-system-keys>>)."""
        return 64 if self.keytype == 1 else self.cipher()[2]

    def in_error(self):
        return 48 <= self.state <= 55

    def invalidate(self):
        """Error State _Invalid_; the Content beyond the MDH is cleared."""
        self.mdh = fset(self.mdh, F_STATE, ST_INVALID)
        self.key = self.skid = None

    def _install(self, field, importing):
        """Take the key field of a PI or SCC (<<KLEE-KeyType-field>>, <<KLEE-system-keys>>)."""
        if self.keytype == 0:
            self.key = field
        elif field == ONES64 and not importing:
            # random key material; _KeyType_ is then set to 0
            self.key = self.rng.getrandbits(self.cipher()[2])
            self.mdh = fset(self.mdh, F_KEYTYPE, 0)
        elif field != ONES64 and field in self.sks:
            self.skid, self.key = field, self.sks[field]
        else:
            # unresolved SKID, or the all-ones SKID in an SCC (<<KLEE-MVR-open>>)
            self.invalidate()

    # ------------------------------------------------------------ configuration
    def provision(self, pi):
        """kl.mgmt opening a provisioning with the PI's MDH, kl.mv, completing kl.mgmt."""
        self.mdh, self.key, self.skid = b2v(pi[:16]), None, None     # position i
        self._install(sl(b2v(pi[16:]), self.key_field_width() - 1, 0), False)
        if not self.in_error():
            self.mdh = fset(self.mdh, F_STATE, ST_READY)   # provisioning ends in _Ready_

    def content1(self):
        """The Serialized Content: key or SKID at position i; the MDH is not part of it."""
        field = self.skid if self.keytype == 1 else self.key
        return v2b(field, padded_bytes(self.key_field_width()))

    def import_scc(self, mdh, content1):
        """Import from the plaintext of an SCC; _State_ is restored from the MDH."""
        self.mdh, self.key, self.skid = mdh, None, None
        self._install(sl(b2v(content1), self.key_field_width() - 1, 0), True)

    # ------------------------------------------------------------ usage
    def setst(self, immed):
        """Form A kl.setst #immed (<<KLEE-ECB-mode>> names no Form and no operand)."""
        if self.in_error():
            return                       # no operation, _State_ unchanged
        pol = fget(self.mdh, F_MACHINEPOLICY)
        if (immed == ST_READY                                   # SGR8
                or (immed == ST_ENCRYPT and pol & POL_ENC)      # "if encryption is allowed"
                or (immed == ST_DECRYPT and pol & POL_DEC)):    # "if decryption is allowed"
            self.mdh = fset(self.mdh, F_STATE, immed)           # "From any valid state"
        else:
            self.invalidate()            # a transition the Machine does not allow

    def exec(self, inp, KLLEN, klstart=0, out=None, halt_after=None):
        """(Multi-block) Form A kl.exec, or its Form D substitution (in place).

        `inp` and `out` are the KLLEN-bit operands (`out` defaults to `inp`: Vd = Vs2,
        which is how a substituted Form A behaves); `klstart` is in bytes.  A precise
        halt after `halt_after` blocks is modelled as the shorter instruction that
        Rule <<KLEE-IRR-block-iterated-instructions>> equates it with.
        Returns (new value of the output operand, klstart).
        """
        out = inp if out is None else out
        lo = 8 * klstart
        window = (((1 << KLLEN) - 1) >> lo) << lo if lo < KLLEN else 0
        if self.in_error():
            return out & ~window, 0      # no operation; the window is zeroed
        if lo % B:                       # an input klstart that is no interruption point
            self.invalidate()
            return out & ~window, 0
        if lo >= KLLEN:
            return out, klstart          # empty window: no operation
        if (self.state not in (ST_ENCRYPT, ST_DECRYPT)     # kl.exec in _Ready_
                or KLLEN % B):                             # MGR2: granularity b
            self.invalidate()
            return out & ~window, 0
        enc, dec, k = self.cipher()
        f = enc if self.state == ST_ENCRYPT else dec
        key = v2b(self.key, k // 8)
        nblk = KLLEN // B
        # MGR3: i = 0, b, ..., KLLEN - b, in that order
        for q, i in enumerate(range(lo, KLLEN, B)):
            if halt_after is not None and q == halt_after:
                return out, i // 8       # precise halt, prefix-complete klstart
            res = b2v(f(key, v2b(sl(inp, i + B - 1, i), B // 8)))
            dst = i if self.order == 'spec' else (nblk - 1) * B - i
            out = (out & ~(((1 << B) - 1) << dst)) | (res << dst)
        return out, 0                    # retired: klstart <- 0

    # ------------------------------------------------------------ kl.derive
    def derive_dest(self, j, src, length):
        """This CL as the destination of kl.derive (<<KLEE-derive-endpoints>>).

        `src` stands for the bytes the source endpoint supplies.
        """
        if self.in_error():
            return False
        if (j not in ECB_IMPORTABLE
                or self.state != ST_READY        # "filled with the destination CL in State _Ready_"
                or self.keytype == 1):           # "A field configured by a SKID is never importable"
            self.invalidate()
            return False
        if length == 0:
            return True                          # transfers nothing, changes no state
        dest_length = self.cipher()[2] // 8
        eff_length = min(length, dest_length)
        self.key = b2v(src[:eff_length] + bytes(dest_length - eff_length))
        return True


def kl_derive_from_ecb(src_cl, i, dst_cl, j, length):
    """kl.derive with an ECB CL as the source.  ECB has no exportable field, so the
    endpoint descriptor is never allowed and both CLs are invalidated."""
    assert i not in ECB_EXPORTABLE
    src_cl.invalidate()
    dst_cl.invalidate()
    return False


def new_cl(cipher, key_hex, policy=POL_BOTH, **kw):
    cl = EcbCL(**kw)
    cl.provision(build_pi(ECB_OF[cipher], policy, 0, b2v(bytes.fromhex(key_hex))))
    return cl


def blocks_value(data):
    """The KLEE value of a byte string of whole blocks, built with cat()."""
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    # cat() takes the most significant part first: reverse the address order
    return cat(*[(b2v(blk), B) for blk in reversed(blocks)])


def cl_run(cl, data, klstart=0, halt_after=None):
    out, ks = cl.exec(blocks_value(data), 8 * len(data), klstart, halt_after=halt_after)
    return v2b(out, len(data)), ks


# ---------------------------------------------------------------- vectors
# FIPS 197 Appendix C.
FIPS197 = [
    ("C.1 AES-128", "000102030405060708090a0b0c0d0e0f",
     "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("C.2 AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617",
     "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("C.3 AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
]

# SP 800-38A Appendix F.1: the same four-block plaintext under three key sizes.
SP38A_PT = ("6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710")
SP38A_F1 = [
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

# GB/T 32907-2016.
SM4_KEY1 = "0123456789abcdeffedcba9876543210"
SM4_EX1_CT = "681edf34d206965e86b3e94f536e4246"
# GB/T 32907-2016 Example 2: encrypt the plaintext under its own key 1e6 times.
SM4_EX2_ROUNDS = 1000000
SM4_EX2_CT = "595298c7c6fd271f0402f804c33d3f66"
# Reference-implementation checkpoints, for localizing a failure only.
SM4_EX2_CHECKPOINTS = {
    100: "8da24cb1008bd3271aa3b60105a7d5fd",
    1000: "d735e91cc5689cf312bcc1efb740e813",
    10000: "2d8bfc27381c68ecb316320ee72ba074",
}
SM4_MULTI = [
    ("A.2.1.1 SM4-ECB", SM4_KEY1,
     "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb",
     "5ec8143de509cff7b5179f8f474b86192f1d305a7fb17df985f81c8482192304"),
    ("A.2.1.2 SM4-ECB", "fedcba98765432100123456789abcdef",
     "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb",
     "c5876897e4a59bbba72a10c83872245b12dd90bc2d200692b529a4155ac9e600"),
]

# ---------------------------------------------------------------- run
ok = True
neg_fired = False
W = 58


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


pt = bytes.fromhex(SP38A_PT)

print("== FIPS 197 Appendix C: single-block AES (REF, and a KLEE CL with KLLEN = b)")
for name, k, p, c in FIPS197:
    key, ptb, ct = bytes.fromhex(k), bytes.fromhex(p), bytes.fromhex(c)
    chk(name + " encrypt", aes_encrypt(key, ptb).hex(), c)
    chk(name + " decrypt", aes_decrypt(key, ct).hex(), p)
    cipher = f"AES-{len(key) * 8}"
    cl = new_cl(cipher, k)
    cl.setst(ST_ENCRYPT)
    chk(name + " KLEE CL, KLLEN = b", cl_run(cl, ptb)[0].hex(), c)
    cl.setst(ST_DECRYPT)
    chk(name + " KLEE CL decrypt, KLLEN = b", cl_run(cl, ct)[0].hex(), p)

print("\n== SP 800-38A F.1: four-block ECB, REF (byte string)")
for name, _, k, c in SP38A_F1:
    key = bytes.fromhex(k)
    chk(name + " encrypt", ref_ecb(aes_encrypt, key, pt).hex(), c)
    chk(name + " decrypt", ref_ecb(aes_decrypt, key, bytes.fromhex(c)).hex(), SP38A_PT)

print("\n== MGR3: one kl.exec with KLLEN = 4b, least significant block position first")
print("   (the 4-block operand is built with cat(); its LEFT part is the most")
print("    significant, i.e. the LAST block of the byte string)")
print("\nKAT-EXPECT-FAIL: NEG big-endian misread")
print(f"\n   {'vector':<32} {'KLEE spec order':<16} {'NEG big-endian misread'}")
for name, cipher, k, c in SP38A_F1:
    cl = new_cl(cipher, k)
    cl.setst(ST_ENCRYPT)
    spec = cl_run(cl, pt)[0].hex()
    neg_cl = new_cl(cipher, k, order='neg')
    neg_cl.setst(ST_ENCRYPT)
    neg = cl_run(neg_cl, pt)[0].hex()
    good_spec = spec == c
    good_neg = neg != c                      # the control must NOT reproduce the vector
    ok = ok and good_spec
    neg_fired = neg_fired or good_neg
    print(f"   {name:<32} {'PASS' if good_spec else 'FAIL':<16} "
          f"{'FAIL' if good_neg else 'PASS (does not discriminate)'}")
print()
for name, cipher, k, c in SP38A_F1:
    cl = new_cl(cipher, k)
    cl.setst(ST_DECRYPT)
    chk(name + " decrypt, one kl.exec", cl_run(cl, bytes.fromhex(c))[0].hex(), SP38A_PT)

print("\n== SM4 (GB/T 32907-2016)")
k1 = bytes.fromhex(SM4_KEY1)
chk("Example 1 single block", sm4_encrypt(k1, k1).hex(), SM4_EX1_CT)
chk("Example 1 decrypt", sm4_decrypt(k1, bytes.fromhex(SM4_EX1_CT)).hex(), SM4_KEY1)
rks = sm4_key_schedule(k1)
x = k1
for r in range(1, SM4_EX2_ROUNDS + 1):
    x = _sm4_block(rks, x)
    if r in SM4_EX2_CHECKPOINTS:
        chk(f"Example 2 round {r} [ref-impl checkpoint]", x.hex(),
            SM4_EX2_CHECKPOINTS[r])
chk(f"Example 2 full {SM4_EX2_ROUNDS} rounds", x.hex(), SM4_EX2_CT)
for name, k, p, c in SM4_MULTI:
    key = bytes.fromhex(k)
    chk(name + " REF", ref_ecb(sm4_encrypt, key, bytes.fromhex(p)).hex(), c)
    chk(name + " REF decrypt", ref_ecb(sm4_decrypt, key, bytes.fromhex(c)).hex(), p)
    cl = new_cl('SM4', k)                    # SM4_ECB: Type 3, Mode 0
    cl.setst(ST_ENCRYPT)
    chk(name + " KLEE CL (SM4_ECB), one kl.exec", cl_run(cl, bytes.fromhex(p))[0].hex(), c)
    cl.setst(ST_DECRYPT)
    chk(name + " KLEE CL decrypt, one kl.exec", cl_run(cl, bytes.fromhex(c))[0].hex(), p)

print("\n== RULES: States, transitions and the general rules (F.1.1 key and data)")
name, cipher, k, c = SP38A_F1[0]
ct = bytes.fromhex(c)
chk("state constants: Ready 1, Operate 2, Encrypt 7, Decrypt 8, Invalid 49",
    (ST_READY, ST_OPERATE, ST_ENCRYPT, ST_DECRYPT, ST_INVALID), (1, 2, 7, 8, 49))
cl = new_cl(cipher, k)
chk("provisioning completes in _Ready_ (kl.getst = 1)", cl.state, ST_READY)
cl.setst(ST_ENCRYPT)
chk("kl.setst #kl_state_encrypt: kl.getst = 7", cl.state, ST_ENCRYPT)
out, _ = cl_run(cl, pt)
cl.setst(ST_DECRYPT)                         # "From any valid state": no stop in _Ready_
chk("_Encrypt_ -> _Decrypt_ directly, then decrypt F.1.1",
    (cl.state, cl_run(cl, out)[0].hex()), (ST_DECRYPT, SP38A_PT))
cl.setst(ST_DECRYPT)                         # same-State kl.setst (SGR4)
chk("_Decrypt_ -> _Decrypt_ (SGR4) leaves the CL usable",
    (cl.state, cl_run(cl, ct)[0].hex()), (ST_DECRYPT, SP38A_PT))
cl.setst(ST_READY)
chk("back to _Ready_ (SGR8): kl.getst = 1", cl.state, ST_READY)
res, _ = cl.exec(blocks_value(pt), 512)
chk("kl.exec in _Ready_: _Invalid_ and output window zeroed", (cl.state, res),
    (ST_INVALID, 0))
chk("_Invalid_ CL: Content cleared (only the MDH remains)", (cl.key, cl.skid), (None, None))
cl.setst(ST_READY)
res, _ = cl.exec(blocks_value(pt), 512)
chk("_Invalid_ CL: kl.setst and kl.exec perform no operation", (cl.state, res),
    (ST_INVALID, 0))

cl = new_cl(cipher, k, policy=POL_DEC)
cl.setst(ST_DECRYPT)
chk("_MachinePolicy_ = decrypt only: _Decrypt_ allowed, F.1.2 decrypts",
    (cl.state, cl_run(cl, ct)[0].hex()), (ST_DECRYPT, SP38A_PT))
cl.setst(ST_ENCRYPT)
chk("_MachinePolicy_ = decrypt only: kl.setst #kl_state_encrypt -> _Invalid_",
    cl.state, ST_INVALID)
cl = new_cl(cipher, k, policy=POL_ENC)
cl.setst(ST_DECRYPT)
chk("_MachinePolicy_ = encrypt only: kl.setst #kl_state_decrypt -> _Invalid_",
    cl.state, ST_INVALID)
cl = new_cl(cipher, k)
cl.setst(ST_OPERATE)
chk("kl.setst #kl_state_operate (not an ECB State) -> _Invalid_", cl.state, ST_INVALID)

cl = new_cl(cipher, k)
cl.setst(ST_ENCRYPT)
inp = b2v(pt[:17])
res, _ = cl.exec(inp, 136)                   # KLLEN = 17 bytes, not a multiple of b
chk("MGR2: KLLEN = 136 -> no operation, _Invalid_, window zeroed",
    (cl.state, res), (ST_INVALID, 0))

cl = new_cl(cipher, k)
cl.setst(ST_ENCRYPT)
buf = bytearray(pt)                          # KLIOBUF with kliobuftop = 64
res, _ = cl.exec(b2v(bytes(buf)), 8 * 64)    # Form D replacing Form A: in place
chk("Form D substitution (kliobuftop = 64), output in place of input",
    v2b(res, 64).hex(), c)

print()
for q in (1, 2, 3):
    cl = new_cl(cipher, k)
    cl.setst(ST_ENCRYPT)
    part, ks = cl_run(cl, pt, halt_after=q)      # precise halt after q blocks
    resumed, ks2 = cl.exec(b2v(part), 512, klstart=ks)
    chk(f"kl.exec halted after {q} block(s) (klstart = {16 * q}), resumed",
        (ks, v2b(resumed, 64).hex(), ks2), (16 * q, c, 0))
cl = new_cl(cipher, k)
cl.setst(ST_ENCRYPT)
res, _ = cl.exec(blocks_value(pt), 512, klstart=8)
chk("klstart = 8, not an interruption point (input) -> _Invalid_",
    (cl.state, res & ((1 << 64) - 1), res >> 64), (ST_INVALID, b2v(pt[:8]), 0))
cl = new_cl(cipher, k)
cl.setst(ST_ENCRYPT)
res, ks = cl.exec(blocks_value(pt), 512, klstart=64)
chk("klstart = 64 = KLLEN/8: empty window, no operation",
    (cl.state, v2b(res, 64)), (ST_ENCRYPT, pt))

print("\n== DATA: Provisioning Input and Serialized Content")
print("   (sizes in bytes, worked out by hand from the tables; SCC with _AuxDataLen_ = 0)")
SKID = 0x0123456789abcdef
SKS = {SKID: b2v(bytes.fromhex(SP38A_F1[1][2]))}          # an AES-192 system key
rows = [
    # label, F.1 vector, keytype, key field, PI size, Content1 (hex)
    ("AES-128 by value", SP38A_F1[0], 0, b2v(bytes.fromhex(SP38A_F1[0][2])), 32,
     SP38A_F1[0][2]),
    ("AES-192 by value", SP38A_F1[1], 0, b2v(bytes.fromhex(SP38A_F1[1][2])), 48,
     SP38A_F1[1][2] + "00" * 8),
    ("AES-256 by value", SP38A_F1[2], 0, b2v(bytes.fromhex(SP38A_F1[2][2])), 48,
     SP38A_F1[2][2]),
    ("AES-192 by SKID", SP38A_F1[1], 1, SKID, 32,
     "efcdab8967452301" + "00" * 8),
]
for label, (_, cipher, _, want), kt, field, pi_size, c1 in rows:
    mach = ECB_OF[cipher]
    pi = build_pi(mach, POL_BOTH, kt, field)
    cl = EcbCL(sks=SKS)
    cl.provision(pi)
    mdh = cl.mdh
    chk(f"{label}: PI = {pi_size}, kl.size(PI MDH) = {pi_size}",
        (len(pi), kl_size(make_mdh(mach, POL_BOTH, kt), 0, len(pi) - 16)),
        (pi_size, pi_size))
    chk(f"{label}: Content1 = {len(c1) // 2} B, kl.size = {32 + len(c1) // 2}",
        (cl.content1().hex(), kl_size(mdh, len(cl.content1()), 0)),
        (c1, 32 + len(c1) // 2))
    cl.setst(ST_ENCRYPT)
    half, _ = cl_run(cl, pt[:32])
    cl2 = EcbCL(sks=SKS)
    cl2.import_scc(cl.mdh, cl.content1())    # _State_ _Encrypt_ travels in the MDH
    rest, _ = cl_run(cl2, pt[32:])
    chk(f"{label}: export after 2 blocks, import, finish F.1", (half + rest).hex(), want)
cl = EcbCL(sks=SKS)
cl.provision(build_pi(ECB_OF['AES-192'], POL_BOTH, 1, SKID + 1))
chk("unresolved SKID at provisioning -> _Invalid_", cl.state, ST_INVALID)
cl = EcbCL(sks=SKS)
cl.provision(build_pi(ECB_OF['AES-192'], POL_BOTH, 1, ONES64))
chk("all-ones SKID: random key, _KeyType_ 0, Content1 = 32 B (key by value)",
    (cl.state, cl.keytype, len(cl.content1()), kl_size(cl.mdh, len(cl.content1()), 0)),
    (ST_READY, 0, 32, 64))
cl2 = EcbCL(sks=SKS)
cl2.import_scc(make_mdh(ECB_OF['AES-192'], POL_BOTH, 1, ST_READY),
               v2b(ONES64, 16))
chk("SCC carrying the all-ones SKID in a Complete State -> _Invalid_",
    cl2.state, ST_INVALID)

print("\n== DERIVE: <<KLEE-derive-endpoints>>, destination `key` (1), CL in _Ready_")
name, cipher, k, c = SP38A_F1[1]                     # AES-192: dest_length = 24
source = bytes.fromhex(k) + bytes.fromhex("a5" * 8)  # a 32-byte source field
zero_key = "00" * 24


def derived(length, j=1, state=None, keytype=0):
    cl = EcbCL(sks=SKS)
    field = SKID if keytype else 0
    cl.provision(build_pi(ECB_OF[cipher], POL_BOTH, keytype, field))
    if state is not None:
        cl.setst(state)
    done = cl.derive_dest(j, source, length)
    return cl, done


cl, done = derived(32)
cl.setst(ST_ENCRYPT)
chk("length 32 > 24: eff_length 24, source truncated; F.1.3 reproduced",
    (done, cl_run(cl, pt)[0].hex()), (True, c))
cl, done = derived(24)
cl.setst(ST_ENCRYPT)
chk("length 24 = dest_length: F.1.3 reproduced", (done, cl_run(cl, pt)[0].hex()), (True, c))
cl, done = derived(16)
cl.setst(ST_ENCRYPT)
padded = bytes.fromhex(k)[:16] + bytes(8)
chk("length 16 < 24: key zero-filled beyond byte 16 [vs REF]",
    (done, cl_run(cl, pt)[0].hex()), (True, ref_ecb(aes_encrypt, padded, pt).hex()))
cl, done = derived(0)
chk("length 0: nothing transferred, no state change",
    (done, cl.state, v2b(cl.key, 24).hex()), (True, ST_READY, zero_key))
cl, done = derived(32, state=ST_ENCRYPT)
chk("destination in _Encrypt_ -> _Invalid_", (done, cl.state), (False, ST_INVALID))
cl, done = derived(32, j=2)
chk("destination index 2 (ECB imports only `key`) -> _Invalid_", (done, cl.state),
    (False, ST_INVALID))
cl, done = derived(32, keytype=1)
chk("key configured by a SKID is never importable -> _Invalid_", (done, cl.state),
    (False, ST_INVALID))
src_cl = new_cl(cipher, k)
dst_cl = new_cl(cipher, "00" * 24)
done = kl_derive_from_ecb(src_cl, 1, dst_cl, 1, 24)
chk("ECB CL as a source (a key is never exportable) -> both _Invalid_",
    (done, src_cl.state, dst_cl.state), (False, ST_INVALID, ST_INVALID))
info("kl.derive into `key`: byte t of the transfer is taken as byte t of the key "
     "(<<KLEE-Notation>>); the endpoint table is marked work in progress.")
info("a derive whose source endpoint does not exist invalidates both CLs, per "
     "'If the transfer is not allowed, then both CLs transition to Error State "
     "_Invalid_' (<<KLEE-instruction-derive>>).")

print("\n== BOOK 4: <<KLEE-pseudocode-ECB-encryption>> [informative]")
# The example checks `if (X1 >= 24) then: handle error` after each kl.getst.
ecb_states = (ST_READY, ST_ENCRYPT, ST_DECRYPT)
chk("the example's test lets the ECB States 1, 7, 8 through",
    [s >= 24 for s in ecb_states], [False] * 3)
chk("the example's test catches every Error State (48-55)",
    all(s >= 24 for s in range(48, 56)), True)
misread = [s for s in range(1, 48) if s >= 24]
spec_note("<<KLEE-pseudocode-ECB-encryption>> (src/ace-pseudocode.adoc) tests "
          "`X1 >= 24` for an error.  24 was the first Error State of the former 5-bit "
          f"_State_ field.  Error States are now 48-55 (<<KLEE-states-error>>), so the "
          f"test would report the {len(misread)} Valid States 24-47 (including "
          "_Success_ and _Failure_) as errors.  Harmless for ECB; suggest `X1 >= 48` "
          "(or the `andi 0x38` / `0x30` test of the management snippets).")

if not neg_fired:
    print("\nnegative control did not fire: the block-order test is not discriminating")
    ok = False

print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
