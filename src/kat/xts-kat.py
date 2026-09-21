#!/usr/bin/env python3
"""XEX/XTS (<<KLEE-XEX-XTS-modes>> and <<KLEE-XTS-from-XEX>> in
src/Zkl-ISA-machines.adoc) against the IEEE 1619-2007 / SP 800-38E vectors.

Models
------
REF   Plain byte-string XTS with ciphertext stealing, written from the standard,
      including IEEE 1619-2007 5.2's byte-wise multiplication by `{alpha}` over the
      16-byte tweak array.  It shares no doubling code with the KLEE side.

KLEE  A model of a Cryptographic Locker holding an XEX CC (class XexCL): the PI is
      provisioned (the MDH first, then `key1` and `key2`, or one SKID that retrieves
      both, MGR9), the CL moves between _Ready_, _Encrypt_ and _Decrypt_, and data is
      processed with the (multi-block) Form A kl.exec:

          on entering _Encrypt_/_Decrypt_ (Form C kl.setst):
                                   mask <- INPUT, then mask <- enc_blk(key2, mask)
          each block of a kl.exec:  OUTPUT <- mask xor enc_blk(key1, INPUT xor mask)
                                    mask  <- update_mask(mask)

      The block loop is rule MGR3 of <<KLEE-Machines-other-rules>>: for
      i = 0, b, ..., KLLEN - b, *in that order*, the per-block operation consumes
      INPUT[i+b-1:i] and produces OUTPUT[i+b-1:i].  Since the mask advances with
      every block, the order is observable here, unlike in ECB.  `update_mask` is
      transcribed literally from <<KLEE-XEX-XTS-modes>> and cross-checked against
      common.py's.  The tweak is `bin(i, b)`, the little-endian encoding of the data
      unit sequence number (<<KLEE-XTS-from-XEX>>, "The tweak").

CTS   The <<KLEE-XTS-from-XEX>> "Ciphertext stealing" procedure implemented step by
      step.  Encryption needs no reordering (mask indices m-1 then m, the ciphertext
      emitted as C_{m-1}, C_m); decryption uses one kl.clone, one *discarded*
      kl.exec on the clone to advance it from mask index m-1 to m, C_{m-1} decrypted
      on the clone at index m, CP @ C_m decrypted on the original at index m-1, and a
      kl.clear of the clone.  The clone is a real copy of the CL, so an accidental
      aliasing of the two masks would show up as a failure.

NEG   Two negative controls, each of which must fail the vectors: OCB3's big-endian
      `double` substituted for `update_mask` (the two differ, one doubling the value
      and the other its byte-reversal), and a multi-block kl.exec that consumes the
      blocks from the most significant position down, which assigns the mask indices
      in reverse address order.

RULES The behaviour the Machine text leaves to the general rules, and the parts of
      the state machine a vector can pin down: a kl.exec in _Ready_ invalidates the
      CL (Rules <<KLEE-SGR-no-exec-in-ready>> and
      <<KLEE-MGR-not-allowed-instructions>>); _Encrypt_ -> _Decrypt_ is *not* an
      allowed transition here (unlike <<KLEE-ECB-mode>> and <<KLEE-tweakable>>);
      _MachinePolicy_ gates the two transitions from _Ready_ (<<KLEE-Machine-field>>);
      returning to _Ready_ zeroes the mask, so the CC can be reused with a new tweak;
      a same-State kl.setst (SGR4 of <<KLEE-State-management>>) re-tweaks; a KLLEN
      that is not a multiple of b performs no operation and invalidates the CL
      (MGR2), the output window being zeroed (Rule
      <<KLEE-SGR-usage-cr-error-state>>) and the Content cleared (Rule
      <<KLEE-SGR-clear-cr-content-error-state>>); KLLEN > b truncates the tweak
      (MGR5); the KLIOBUF substitution of <<KLEE-usage-input-output>>; the
      interruption points and resumption of a multi-block kl.exec
      (<<KLEE-CSR-klstart>>, Rule <<KLEE-IRR-block-iterated-instructions>>).

DATA  The Provisioning Input and the Serialized Content as "Definition of a Machine
      in KLEE" now describes them: the PI begins with the 128-bit MDH, which the
      Machine tables no longer list, and `key1` and `key2` follow at positions ii and
      iii; the MDH is not part of the Serialized Content, where `key1`, `key2` and
      `mask` are at positions i, ii and iii, zero-padded to a multiple of 128 bits.
      With a SKID, position iii of the PI is empty and `mask` starts at byte 8 of
      Content1.  Sizes are checked against kl.size (<<KLEE-instruction-size>>).

DERIVE The destination endpoints `key1` (1) and `key2` (2) of
      <<KLEE-derive-endpoints>>, with the Transfer Size Rules of
      <<KLEE-derive-rule-both-fixed-size>> (that table is marked work in progress).

Vectors and provenance
----------------------
All vectors are the IEEE 1619-2007 XTS-AES vectors, which SP 800-38E adopts, as
reproduced in the Botan test data file src/tests/data/modes/xts.vec, sections
[AES-128/XTS] and [AES-256/XTS], entries commented "IEEE 1619-2007 VECTOR n"
(raw.githubusercontent.com/randombit/botan, master, fetched 2026-08-26).  Botan's
"Nonce" field is the 16-byte little-endian encoding of the data unit sequence
number, i.e. exactly the specification's `bin(i, 128)`.

  multiple of 16 B : vectors 1, 2, 3, 15 (32 B), 4 and 19 (512 B, XTS-AES-128),
                     10 (512 B, XTS-AES-256)
  ciphertext steal : vectors 15 (17 B), 16 (18 B), 17 (19 B), 18 (20 B),
                     19 (520 B --- 32 full blocks plus 8 bytes)

The 512/520-byte plaintexts are the byte pattern 00..ff repeated twice (plus an
8-byte tail for the 520-byte case), so only their ciphertexts are embedded.

Anchor level: standard-vector for every data-path check in this file, in both
directions.  The RULES, DATA and DERIVE checks are anchored on the same vectors
wherever a vector can express the rule, and otherwise on byte layouts and sizes
worked out by hand from the specification's tables.

Not covered: <<KLEE-tweakable>>.  No tweakable block cipher is instantiated by
<<KLEE-exec-encodings>>, so there is no Machine, and no published vector, to test.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import (aes_decrypt, aes_encrypt, b2v, bin_, bswap, bxor, cat,
                    double_ocb, sl, update_mask, v2b)

MASK128 = (1 << 128) - 1
B = 128                         # the block size b

# ---------------------------------------------------------------- constants
# <<KLEE-metadata-header>>: (hi, lo) of the MDH fields this file uses
F_MACHINE, F_MACHINEPOLICY = (11, 0), (13, 12)
F_STATE, F_KEYTYPE = (24, 19), (30, 29)

# <<KLEE-state-off>>, <<KLEE-states-valid>>, <<KLEE-states-error>>
ST_UNCONFIGURED, ST_READY, ST_INVALID = 0, 1, 49
# <<KLEE-state-constants-symmetric>>
ST_OPERATE, ST_ENCRYPT, ST_DECRYPT, ST_SET_AUX_VALUE = 2, 7, 8, 13

# <<KLEE-Machine-field>>: lower bit of _MachinePolicy_ = encryption, upper = decryption
POL_ENC, POL_DEC = 0b01, 0b10
POL_BOTH = POL_ENC | POL_DEC

ONES64 = (1 << 64) - 1          # the all-ones SKID (<<KLEE-KeyType-field>>)

CIPHERS = {'AES-128': 128, 'AES-192': 192, 'AES-256': 256}   # name -> k


def machine(typ, mode):
    """<<KLEE-exec-encodings>>: _Machine_ = Type in bits [11:4], Mode in bits [3:0]."""
    return (typ << 4) | mode


# <<KLEE-exec-encodings>>: XEX is Mode 3 of Types 0-2 (AES) and of Type 3 (SM4)
XEX_MACHINES = {machine(t, 3): c for t, c in enumerate(CIPHERS)}
XEX_OF = {v: k for k, v in XEX_MACHINES.items()}

# <<KLEE-derive-endpoints>> (work in progress), row of <<KLEE-XEX-XTS-modes>>
XEX_EXPORTABLE = {}                        # a key is never an exportable source
XEX_IMPORTABLE = {1: 'key1', 2: 'key2'}


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


def build_pi(mach, keytype, key1, key2=0, policy=POL_BOTH):
    """A PI: the MDH (i), then `key1` or the SKID (ii) and `key2` (iii, empty for a SKID)."""
    k = CIPHERS[XEX_MACHINES[mach]]
    if keytype == 1:
        content, width = key1, 64        # one SKID retrieves both keys (MGR8, MGR9)
    else:
        content, width = cat((key2, k), (key1, k)), 2 * k
    return v2b(make_mdh(mach, policy, keytype), 16) + v2b(content, padded_bytes(width))


# ---------------------------------------------------------------- update_mask
def kl_update_mask(V):
    """update_mask of <<KLEE-XEX-XTS-modes>>, transcribed for b = 128:

        update_mask(V) = V << 1                                    if V[127] = 0
        update_mask(V) = (V << 1) xor (zeros(120) @ 0b10000111)     otherwise
    """
    if sl(V, 127, 127) == 0:
        return (V << 1) & MASK128
    return ((V << 1) & MASK128) ^ cat((0, 120), (0b10000111, 8))


# ---------------------------------------------------------------- REF
def ref_mul_alpha(t):
    """IEEE 1619-2007 5.2: multiplication of the 16-byte tweak array by `alpha`."""
    t = bytearray(t)
    cin = cout = 0
    for j in range(16):
        cout = (t[j] >> 7) & 1
        t[j] = ((t[j] << 1) + cin) & 0xFF
        cin = cout
    if cout:
        t[0] ^= 0x87
    return bytes(t)


def ref_xts(key1, key2, seq, data, encrypt=True):
    """XTS-AES with ciphertext stealing, on byte strings, per IEEE 1619 / SP 800-38E."""
    f = aes_encrypt if encrypt else aes_decrypt
    m, s = divmod(len(data), 16)
    tw = [aes_encrypt(key2, seq.to_bytes(16, 'little'))]
    for _ in range(m):
        tw.append(ref_mul_alpha(tw[-1]))          # tw[q] = T (x) alpha^q

    def tbc(x, t):                                # one XEX block operation under tweak t
        return bxor(f(key1, bxor(x, t)), t)

    def blk(q):
        return data[16 * q:16 * q + 16]

    if s == 0:
        return b''.join(tbc(blk(q), tw[q]) for q in range(m))
    out = b''.join(tbc(blk(q), tw[q]) for q in range(m - 1))
    if encrypt:
        cc = tbc(blk(m - 1), tw[m - 1])
        c_last, cp = cc[:s], cc[s:]
        out += tbc(data[16 * m:] + cp, tw[m]) + c_last
    else:
        pp = tbc(blk(m - 1), tw[m])
        p_last, cp = pp[:s], pp[s:]
        out += tbc(data[16 * m:] + cp, tw[m - 1]) + p_last
    return out


# ---------------------------------------------------------------- the KLEE model
class XexCL:
    """A CL holding an XEX CC, per <<KLEE-XEX-XTS-modes>> and the general rules."""

    def __init__(self, sks=None, doubling=None, rng=None, order='spec'):
        self.mdh = 0                     # _Unconfigured_: every MDH field reads zero
        self.key1 = self.key2 = self.skid = self.mask = None
        self.sks = sks or {}
        self.doubling = doubling or kl_update_mask
        self.rng = rng or random.Random(2026)
        self.order = order

    # ------------------------------------------------------------ helpers
    @property
    def state(self):
        return kl_getst(self.mdh)

    @property
    def keytype(self):
        return fget(self.mdh, F_KEYTYPE)

    def k(self):
        return CIPHERS[XEX_MACHINES[fget(self.mdh, F_MACHINE)]]

    def content_widths(self):
        """(width of position i, width of position ii) of the Serialized Content."""
        return (64, 0) if self.keytype == 1 else (self.k(), self.k())

    def in_error(self):
        return 48 <= self.state <= 55

    def invalidate(self):
        self.mdh = fset(self.mdh, F_STATE, ST_INVALID)
        self.key1 = self.key2 = self.skid = self.mask = None

    def _install(self, field, key2, importing):
        if self.keytype == 0:
            self.key1, self.key2 = field, key2
        elif field == ONES64 and not importing:
            # random key material for every key of the Machine at once; _KeyType_ -> 0
            k = self.k()
            self.key1, self.key2 = self.rng.getrandbits(k), self.rng.getrandbits(k)
            self.mdh = fset(self.mdh, F_KEYTYPE, 0)
        elif field != ONES64 and field in self.sks:
            self.skid = field
            self.key1, self.key2 = self.sks[field]      # one SKID, two keys (MGR9)
        else:
            self.invalidate()            # unresolved SKID (<<KLEE-MVR-open>>)

    # ------------------------------------------------------------ configuration
    def provision(self, pi):
        self.mdh = b2v(pi[:16])          # position i of the PI: the MDH
        w1, w2 = self.content_widths()
        content = b2v(pi[16:])
        self._install(sl(content, w1 - 1, 0),
                      sl(content, w1 + w2 - 1, w1) if w2 else 0, False)
        if not self.in_error():
            self.mdh = fset(self.mdh, F_STATE, ST_READY)
            self.mask = 0                # in State _Ready_ the mask field is zero

    def content1(self):
        """Serialized Content: key1 or SKID (i), key2 (ii, empty for a SKID), mask (iii)."""
        w1, w2 = self.content_widths()
        first = self.skid if self.keytype == 1 else self.key1
        return v2b(cat((self.mask, B), (self.key2 if w2 else 0, w2), (first, w1)),
                   padded_bytes(w1 + w2 + B))

    def import_scc(self, mdh, content1):
        self.mdh = mdh
        w1, w2 = self.content_widths()
        v = b2v(content1)
        self.mask = sl(v, w1 + w2 + B - 1, w1 + w2)
        self._install(sl(v, w1 - 1, 0), sl(v, w1 + w2 - 1, w1) if w2 else 0, True)

    # ------------------------------------------------------------ usage
    def setst(self, immed, form='C', operand=0, KLLEN=128):
        """kl.setst.  `form` is 'A' (no operand), 'A/iobuf' (the KLIOBUF substitution of
        Form C, `operand` = the bytes [0, kliobuftop)) or 'C' (a KLLEN-bit vector)."""
        if self.in_error():
            return                       # no operation, _State_ unchanged
        pol = fget(self.mdh, F_MACHINEPOLICY)
        st = self.state
        allowed = {ST_ENCRYPT: pol & POL_ENC, ST_DECRYPT: pol & POL_DEC}
        if immed == ST_READY and form == 'A':
            self.mdh = fset(self.mdh, F_STATE, ST_READY)     # _Encrypt_/_Decrypt_ -> _Ready_
            self.mask = 0
        elif (immed in (ST_ENCRYPT, ST_DECRYPT) and form in ('C', 'A/iobuf')
              # _Ready_ -> _Encrypt_/_Decrypt_ if allowed, or the same State again (SGR4)
              and ((st == ST_READY and allowed[immed]) or st == immed)):
            value = b2v(operand) if form == 'A/iobuf' else sl(operand, KLLEN - 1, 0)
            self.mask = sl(value, B - 1, 0)                  # mask <- INPUT, b lsbs
            self.mask = b2v(aes_encrypt(v2b(self.key2, self.k() // 8),
                                        v2b(self.mask, B // 8)))  # mask <- enc_blk(key2, mask)
            self.mdh = fset(self.mdh, F_STATE, immed)
        else:
            self.invalidate()            # a transition the Machine does not allow

    def exec(self, inp, KLLEN, klstart=0, out=None, halt_after=None):
        """(Multi-block) Form A kl.exec, or its Form D substitution (in place).

        `inp` and `out` are the KLLEN-bit operands (`out` defaults to `inp`, i.e.
        Vd = Vs2, which is how a substituted Form A behaves); `klstart` is in bytes.
        Returns (new value of the output operand, klstart).
        """
        out = inp if out is None else out
        lo = 8 * klstart
        window = (((1 << KLLEN) - 1) >> lo) << lo if lo < KLLEN else 0
        if self.in_error():
            return out & ~window, 0
        if lo % B:                       # an input klstart that is no interruption point
            self.invalidate()
            return out & ~window, 0
        if lo >= KLLEN:
            return out, klstart          # empty window: no operation
        if (self.state not in (ST_ENCRYPT, ST_DECRYPT)     # e.g. kl.exec in _Ready_
                or KLLEN % B):                             # MGR2: granularity b
            self.invalidate()
            return out & ~window, 0
        f = aes_encrypt if self.state == ST_ENCRYPT else aes_decrypt
        key1 = v2b(self.key1, self.k() // 8)
        positions = list(range(lo, KLLEN, B))              # MGR3: i = 0, b, ..., in order
        if self.order != 'spec':
            positions.reverse()                            # NEG: most significant first
        for q, i in enumerate(positions):
            if halt_after is not None and q == halt_after:
                return out, i // 8       # precise halt, prefix-complete klstart
            x = sl(inp, i + B - 1, i)
            res = self.mask ^ b2v(f(key1, v2b((x ^ self.mask) & MASK128, B // 8)))
            self.mask = self.doubling(self.mask)           # mask <- update_mask(mask)
            out = (out & ~(MASK128 << i)) | ((res & MASK128) << i)
        return out, 0

    def exec1(self, value):
        """One single-block Form A kl.exec (KLLEN = b)."""
        return self.exec(value, B)[0]

    def clone(self):
        """kl.clone: the destination CL becomes a perfect copy of the source CL."""
        c = XexCL(self.sks, self.doubling, self.rng, self.order)
        c.mdh, c.key1, c.key2, c.skid, c.mask = (self.mdh, self.key1, self.key2,
                                                 self.skid, self.mask)
        return c

    def clear(self):
        """kl.clear: the CL becomes _Unconfigured_ and its Content is released."""
        self.mdh = 0
        self.key1 = self.key2 = self.skid = self.mask = None

    # ------------------------------------------------------------ kl.derive
    def derive_dest(self, j, src, length):
        """This CL as the destination of kl.derive (<<KLEE-derive-endpoints>>)."""
        if self.in_error():
            return False
        if (j not in XEX_IMPORTABLE
                or self.state != ST_READY        # a key is filled in State _Ready_
                or self.keytype == 1):           # a SKID-configured field is never importable
            self.invalidate()
            return False
        dest_length = self.k() // 8
        eff_length = min(length, dest_length)
        if eff_length:
            value = b2v(src[:eff_length] + bytes(dest_length - eff_length))
            if j == 1:
                self.key1 = value
            else:
                self.key2 = value
        return True


def new_xex(key1, key2, **kw):
    """Provision a CL by value with the given AES keys."""
    cl = XexCL(**{k: v for k, v in kw.items() if k in ('sks', 'doubling', 'rng', 'order')})
    cl.provision(build_pi(XEX_OF[f"AES-{len(key1) * 8}"], 0, b2v(key1), b2v(key2),
                          kw.get('policy', POL_BOTH)))
    return cl


def cl_run(cl, data, per_block=False, klstart=0, halt_after=None):
    """Process whole blocks: one multi-block kl.exec, or one kl.exec per block."""
    if not data:
        return b'', 0                    # no instruction is issued
    if per_block:
        return b''.join(v2b(cl.exec1(b2v(data[i:i + 16])), 16)
                        for i in range(0, len(data), 16)), 0
    out, ks = cl.exec(b2v(data), 8 * len(data), klstart, halt_after=halt_after)
    return v2b(out, len(data)), ks


def kl_xex(key1, key2, seq, data, encrypt=True, per_block=False, **kw):
    """The plain XEX sequence; defined only when the data unit is a multiple of b."""
    assert len(data) % 16 == 0
    cl = new_xex(key1, key2, **kw)
    cl.setst(ST_ENCRYPT if encrypt else ST_DECRYPT, 'C', bin_(seq, B), 128)  # tweak bin(i,b)
    return cl_run(cl, data, per_block)[0]


def kl_xts(key1, key2, seq, data, encrypt=True, per_block=False, discard=0, **kw):
    """<<KLEE-XTS-from-XEX>> implemented step by step, stealing included."""
    m, s_bytes = divmod(len(data), 16)
    if s_bytes == 0:                     # s = 0: the plain XEX sequence over m blocks
        return kl_xex(key1, key2, seq, data, encrypt, per_block, **kw)
    s = 8 * s_bytes                      # the spec measures the partial block in bits
    cl = new_xex(key1, key2, **kw)
    cl.setst(ST_ENCRYPT if encrypt else ST_DECRYPT, 'C', bin_(seq, B), 128)
    # 1. kl.exec for the blocks up to P_{m-2} / C_{m-2}; the mask is then at index m-1
    out = cl_run(cl, data[:16 * (m - 1)], per_block)[0]
    last_full = b2v(data[16 * (m - 1):16 * m])
    tail = b2v(data[16 * m:])            # the s-bit partial block
    if encrypt:
        # 2. P_{m-1} at mask index m-1, giving CC
        cc = cl.exec1(last_full)
        # 3. C_m <- CC[s-1:0] and CP <- CC[b-1:s]
        c_last, cp = sl(cc, s - 1, 0), sl(cc, 127, s)
        # 4. CP @ P_m at mask index m, giving C_{m-1}
        c_m1 = cl.exec1(cat((cp, B - s), (tail, s)))
        # 5. ... C_{m-1}, C_m, with C_m the final s bits
        out += v2b(c_m1, 16) + v2b(c_last, s_bytes)
    else:
        # 2. kl.clone the CL; both are at mask index m-1
        clone = cl.clone()
        # 3. one kl.exec on the clone whose output is discarded: index m-1 consumed
        clone.exec1(discard)
        # 4. C_{m-1} on the clone at mask index m, giving PP
        pp = clone.exec1(last_full)
        # 5. P_m <- PP[s-1:0] and CP <- PP[b-1:s]
        p_last, cp = sl(pp, s - 1, 0), sl(pp, 127, s)
        # 6. CP @ C_m on the original CL, still at mask index m-1
        p_m1 = cl.exec1(cat((cp, B - s), (tail, s)))
        out += v2b(p_m1, 16) + v2b(p_last, s_bytes)
        # 7. clear the clone
        clone.clear()
    return out


# ---------------------------------------------------------------- vectors
_PATTERN = (bytes(range(256)) * 2).hex()

# (label, key1||key2, sequence-number encoding (little-endian, 16 B), plaintext, ciphertext)
IEEE1619 = [
    ("vector 1 (32 B, XTS-AES-128)",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"),
    ("vector 2 (32 B, XTS-AES-128)",
     "1111111111111111111111111111111122222222222222222222222222222222",
     "33333333330000000000000000000000",
     "4444444444444444444444444444444444444444444444444444444444444444",
     "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0"),
    ("vector 3 (32 B, XTS-AES-128)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
     "33333333330000000000000000000000",
     "4444444444444444444444444444444444444444444444444444444444444444",
     "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89"),
    ("vector 15 (32 B, XTS-AES-128)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "4444444444444444444444444444444444444444444444444444444444444444",
     "b01f86f8edc1863706fa8a4253e34f28af319de38334870f4dd1f94cbe9832f1"),
    ("vector 4 (512 B, XTS-AES-128)",
     "2718281828459045235360287471352631415926535897932384626433832795",
     "00000000000000000000000000000000", _PATTERN,
     "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c"
     "c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412"
     "328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce"
     "93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265"
     "5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8"
     "a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434"
     "1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c"
     "5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e"
     "94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc"
     "1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3"
     "e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344"
     "b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd"
     "74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752"
     "afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e"
     "bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d"
     "eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568"),
    ("vector 10 (512 B, XTS-AES-256)",
     "2718281828459045235360287471352662497757247093699959574966967627"
     "3141592653589793238462643383279502884197169399375105820974944592",
     "ff000000000000000000000000000000", _PATTERN,
     "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b"
     "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd"
     "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0"
     "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca"
     "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0"
     "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f"
     "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec"
     "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a"
     "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1"
     "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae"
     "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29"
     "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac"
     "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f"
     "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385"
     "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa"
     "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151"),
    ("vector 19 (512 B, XTS-AES-128)",
     "e0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
     "21436587a90000000000000000000000", _PATTERN,
     "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6"
     "8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc"
     "bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854"
     "9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177"
     "41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3"
     "9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4"
     "8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe"
     "41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d"
     "19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64"
     "a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272"
     "9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648"
     "346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394"
     "d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2"
     "cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a"
     "5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf"
     "92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3"),
]

# Ciphertext-stealing vectors: data unit not a multiple of 16 bytes.
IEEE1619_CTS = [
    ("vector 15 (17 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f10",
     "6c1625db4671522d3d7599601de7ca09ed"),
    ("vector 16 (18 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f1011",
     "d069444b7a7e0cab09e24447d24deb1fedbf"),
    ("vector 17 (19 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f101112",
     "e5df1351c0544ba1350b3363cd8ef4beedbf9d"),
    ("vector 18 (20 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f10111213",
     "9d84c813f719aa2c7be3f66171c7c5c2edbf9dac"),
    ("vector 19 (520 B, 32 blocks + 8 B)",
     "e0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
     "21436587a90000000000000000000000",
     _PATTERN + "0001020304050607",
     "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6"
     "8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc"
     "bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854"
     "9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177"
     "41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3"
     "9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4"
     "8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe"
     "41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d"
     "19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64"
     "a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272"
     "9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648"
     "346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394"
     "d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2"
     "cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a"
     "5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf"
     "92cefc151b5cc1611a167893819b63fb37ec662bc0fc907db74a94468a55a7bc"
     "8a6b18e86de60290"),
]


def split_keys(k):
    kb = bytes.fromhex(k)
    h = len(kb) // 2
    return kb[:h], kb[h:]


def seq_of(nonce_hex):
    """Botan's Nonce is bin(i, 128): the little-endian encoding of the sequence number."""
    return int.from_bytes(bytes.fromhex(nonce_hex), 'little')


# ---------------------------------------------------------------- run
ok = True
neg_fired = {'double': False, 'order': False}
W = 60


def chk(label, got, want):
    global ok
    good = got == want
    ok = ok and good
    print(f"  {label:<{W}} {'PASS' if good else 'FAIL'}")
    if not good:
        print(f"      got  {str(got)[:72]}{'...' if len(str(got)) > 72 else ''}")
        print(f"      want {str(want)[:72]}{'...' if len(str(want)) > 72 else ''}")
    return good


def info(text):
    print(f"INFO  {text}")


def spec_note(text):
    print(f"SPEC-NOTE  {text}")


print("== (a) REF: byte-string XTS against IEEE 1619-2007 / SP 800-38E")
print("   (the tweak is advanced with IEEE 1619-2007 5.2's byte-wise multiplication")
print("    by alpha, which shares no code with the KLEE side's update_mask)")
for name, k, nonce, p, c in IEEE1619 + IEEE1619_CTS:
    k1, k2 = split_keys(k)
    i = seq_of(nonce)
    chk(name + " encrypt", ref_xts(k1, k2, i, bytes.fromhex(p)).hex(), c)
    chk(name + " decrypt", ref_xts(k1, k2, i, bytes.fromhex(c), False).hex(), p)
rnd = random.Random(7)
same = all(kl_update_mask(v) == update_mask(v)
           for v in [0, 1, 1 << 127, MASK128] + [rnd.getrandbits(128) for _ in range(64)])
chk("update_mask transcribed from <<KLEE-XEX-XTS-modes>> == common.update_mask",
    same, True)
chk("update_mask(V) on the value view == IEEE 1619 5.2 on the byte-string view",
    [v2b(kl_update_mask(b2v(bytes([q]) + bytes(15))), 16) for q in (1, 0x80, 0xff)],
    [ref_mul_alpha(bytes([q]) + bytes(15)) for q in (1, 0x80, 0xff)])

print("\n== (b) KLEE XEX CL, full-block path (tweak = bin(i, 128))")
print("   one multi-block Form A kl.exec per data unit (MGR3), and the same data")
print("   unit as one Form A kl.exec per block")
for name, k, nonce, p, c in IEEE1619:
    k1, k2 = split_keys(k)
    i = seq_of(nonce)
    chk(name + " encrypt", kl_xex(k1, k2, i, bytes.fromhex(p)).hex(), c)
    chk(name + " decrypt", kl_xex(k1, k2, i, bytes.fromhex(c), False).hex(), p)
    chk(name + " encrypt, one kl.exec per block",
        kl_xex(k1, k2, i, bytes.fromhex(p), per_block=True).hex(), c)

print("\n== (c) <<KLEE-XTS-from-XEX>> ciphertext stealing, taken step by step")
print("   encryption: mask indices m-1 then m, output C_{m-1} then C_m")
print("   decryption: kl.clone + one discarded kl.exec; C_{m-1} at index m on")
print("               the clone, CP @ C_m at index m-1 on the original")
for name, k, nonce, p, c in IEEE1619_CTS:
    k1, k2 = split_keys(k)
    i = seq_of(nonce)
    chk(name + " encrypt", kl_xts(k1, k2, i, bytes.fromhex(p)).hex(), c)
    chk(name + " decrypt", kl_xts(k1, k2, i, bytes.fromhex(c), False).hex(), p)
    chk(name + " decrypt, the discarded kl.exec fed all-ones instead of zeros",
        kl_xts(k1, k2, i, bytes.fromhex(c), False, discard=MASK128).hex(), p)

fallback = all(kl_xts(*split_keys(k), seq_of(nonce), bytes.fromhex(p)).hex() == c
               for name, k, nonce, p, c in IEEE1619)
chk("s = 0: the procedure falls back to the plain XEX sequence (7 vectors)",
    fallback, True)

print("\n== (d) Negative controls")
print("KAT-EXPECT-FAIL: NEG OCB doubling")
print("KAT-EXPECT-FAIL: NEG MS-first order")
print(f"\n   {'vector':<34} {'update_mask':<13} {'NEG OCB doubling':<20}"
      f"{'NEG MS-first order'}")
for name, k, nonce, p, c in IEEE1619[:4] + IEEE1619_CTS[:4]:
    k1, k2 = split_keys(k)
    i = seq_of(nonce)
    data = bytes.fromhex(p)
    good = kl_xts(k1, k2, i, data).hex() == c
    neg1 = kl_xts(k1, k2, i, data, doubling=double_ocb).hex() != c
    neg2 = kl_xts(k1, k2, i, data, order='neg').hex() != c
    ok = ok and good
    neg_fired['double'] |= neg1
    neg_fired['order'] |= neg2
    print(f"   {name:<34} {'PASS' if good else 'FAIL':<13} "
          f"{'FAIL' if neg1 else 'PASS (does not discriminate)':<20}"
          f"{'FAIL' if neg2 else 'PASS (does not discriminate)'}")
print()
# The MS-first control is vacuous on a data unit with a single full block, so
# make sure the vectors expected to discriminate really have two of them; the
# ciphertext-stealing vectors (17 to 20 bytes) have one full block and a partial
# one, and are reported as not discriminating in the table above.
chk("the MS-first control runs on multi-block data units",
    min(len(bytes.fromhex(p)) // 16 for _, _, _, p, _ in IEEE1619[:4]),
    2)

print("\n== (e) kl.clone: independence of the two CLs")
k1, k2 = split_keys(IEEE1619_CTS[0][1])
cl = new_xex(k1, k2)
cl.setst(ST_DECRYPT, 'C', bin_(seq_of(IEEE1619_CTS[0][2]), B), 128)
before = cl.mask
clone = cl.clone()
clone.exec1(0)
clone.exec1(0)
chk("two kl.exec on the clone leave the original mask unchanged", cl.mask, before)
chk("the clone's mask advanced by exactly two update_mask steps",
    clone.mask, kl_update_mask(kl_update_mask(before)))
chk("the clone is a perfect copy: same MDH, keys and _State_",
    (clone.mdh, clone.key1, clone.key2), (cl.mdh, cl.key1, cl.key2))
clone.clear()
chk("kl.clear on the clone: _Unconfigured_, no key material left",
    (clone.state, clone.key1, clone.key2, clone.mask), (ST_UNCONFIGURED, None, None, None))

print("\n== (f) RULES: States, transitions and the general rules (vector 2)")
name, k, nonce, p, c = IEEE1619[1]
k1, k2 = split_keys(k)
i = seq_of(nonce)
data, ct = bytes.fromhex(p), bytes.fromhex(c)
chk("state constants: Ready 1, Encrypt 7, Decrypt 8, Invalid 49",
    (ST_READY, ST_ENCRYPT, ST_DECRYPT, ST_INVALID), (1, 7, 8, 49))
cl = new_xex(k1, k2)
chk("provisioning completes in _Ready_ with mask = 0", (cl.state, cl.mask), (ST_READY, 0))
res, _ = cl.exec(b2v(data), 256)
chk("kl.exec in _Ready_: _Invalid_, window zeroed, Content cleared",
    (cl.state, res, cl.key1, cl.mask), (ST_INVALID, 0, None, None))
cl = new_xex(k1, k2)
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
chk("kl.setst #kl_state_encrypt: kl.getst = 7, mask = enc_blk(key2, bin(i,b))",
    (cl.state, cl.mask), (ST_ENCRYPT, b2v(aes_encrypt(k2, v2b(bin_(i, B), 16)))))
cl.setst(ST_DECRYPT, 'C', bin_(i, B), 128)
chk("_Encrypt_ -> _Decrypt_ is not an allowed transition -> _Invalid_",
    cl.state, ST_INVALID)
cl = new_xex(k1, k2, policy=POL_DEC)
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
chk("_MachinePolicy_ = decrypt only: -> _Encrypt_ gives _Invalid_", cl.state, ST_INVALID)
cl = new_xex(k1, k2, policy=POL_DEC)
cl.setst(ST_DECRYPT, 'C', bin_(i, B), 128)
chk("_MachinePolicy_ = decrypt only: -> _Decrypt_ decrypts vector 2",
    cl_run(cl, ct)[0].hex(), p)
cl = new_xex(k1, k2)
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
cl_run(cl, data)                             # the mask is now at index 2
cl.setst(ST_READY, 'A')
zeroed = (cl.state, cl.mask)
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)   # reuse with a (new) tweak
chk("_Encrypt_ -> _Ready_ zeroes the mask; the CC is reusable with a new tweak",
    (zeroed, cl_run(cl, data)[0].hex()), ((ST_READY, 0), c))
cl = new_xex(k1, k2)
cl.setst(ST_ENCRYPT, 'C', bin_(0xdead, B), 128)
cl_run(cl, data)                             # two blocks under the wrong tweak
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)   # same-State kl.setst (SGR4): re-tweak
chk("same-State kl.setst (SGR4) re-tweaks: mask index back to 0, vector 2",
    (cl.state, cl_run(cl, data)[0].hex()), (ST_ENCRYPT, c))
info("a same-State kl.setst is read as the Form C transition into that State: it sets "
     "the tweak afresh, so the mask restarts at index 0.")
cl = new_xex(k1, k2)
cl.setst(ST_ENCRYPT, 'C', (b2v(bytes.fromhex("5a" * 16)) << B) | bin_(i, B), 256)
chk("KLLEN = 256 > b: only the b least significant bits of INPUT are the tweak",
    cl_run(cl, data)[0].hex(), c)
cl = new_xex(k1, k2)
cl.setst(ST_ENCRYPT, 'A/iobuf', v2b(bin_(i, B), 16))     # KLIOBUF, kliobuftop = 16
res, _ = cl.exec(b2v(data), 8 * len(data))               # Form D replacing Form A
chk("Form A kl.setst and Form D kl.exec through the KLIOBUF: vector 2",
    v2b(res, len(data)).hex(), c)
cl = new_xex(k1, k2)
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
res, _ = cl.exec(b2v(data[:17]), 136)
chk("MGR2: KLLEN = 136 -> no operation, _Invalid_, window zeroed, Content cleared",
    (cl.state, res, cl.key1), (ST_INVALID, 0, None))
cl = new_xex(k1, k2)
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
res, _ = cl.exec(b2v(data), 256, klstart=8)
chk("klstart = 8, not an interruption point (input) -> _Invalid_",
    (cl.state, res), (ST_INVALID, b2v(data[:8])))
cl = new_xex(k1, k2)
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
res, ks = cl.exec(b2v(data), 256, klstart=32)
chk("klstart = 32 = KLLEN/8: empty window, no operation",
    (cl.state, v2b(res, 32)), (ST_ENCRYPT, data))
name4, k4, nonce4, p4, c4 = IEEE1619[4]      # vector 4: 512 B = 32 blocks
k41, k42 = split_keys(k4)
data4 = bytes.fromhex(p4)
for q in (1, 7, 31):
    cl = new_xex(k41, k42)
    cl.setst(ST_ENCRYPT, 'C', bin_(seq_of(nonce4), B), 128)
    part, ks = cl_run(cl, data4, halt_after=q)
    whole, ks2 = cl.exec(b2v(part), 8 * len(data4), klstart=ks)
    chk(f"vector 4: kl.exec halted after {q} block(s) (klstart = {16 * q}), resumed",
        (ks, v2b(whole, len(data4)).hex(), ks2), (16 * q, c4, 0))

print("\n== (g) The two-key construction is the only one architected")
# <<KLEE-XEX-XTS-modes>>: provisioning key2 = key1 gives E(K, P xor M) xor M with
# M = enc_blk(K, T), i.e. the single-key XEX *without* the multiplication by alpha
# that cite:[DBLP-conf-asiacrypt-Rogaway04] requires.  The architecture inserts none.
cl = new_xex(k1, k1)
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
m0 = b2v(aes_encrypt(k1, v2b(bin_(i, B), 16)))
plain = b2v(aes_encrypt(k1, v2b((b2v(data[:16]) ^ m0) & MASK128, 16))) ^ m0
alpha_masked = kl_update_mask(m0)
alpha_out = b2v(aes_encrypt(k1, v2b((b2v(data[:16]) ^ alpha_masked) & MASK128, 16))) \
    ^ alpha_masked
chk("key2 = key1: the mask is the raw enc_blk(key1, T), no alpha applied",
    (cl.exec1(b2v(data[:16])), plain != alpha_out), (plain, True))

print("\n== (h) DATA: Provisioning Input and Serialized Content")
print("   (sizes in bytes, worked out by hand from the tables; SCC with _AuxDataLen_ = 0)")
SKID = 0x0123456789abcdef
SKS = {SKID: (b2v(k1), b2v(k2))}             # one SKID, two independent keys (MGR9)
for cipher, kt, pi_size, c1_size in (('AES-128', 0, 48, 48), ('AES-256', 0, 80, 80),
                                     ('AES-128', 1, 32, 32)):
    kk = CIPHERS[cipher]
    field = SKID if kt else (1 << kk) - 1
    pi = build_pi(XEX_OF[cipher], kt, field, 0 if kt else (1 << kk) - 1)
    cl = XexCL(sks=SKS)
    cl.provision(pi)
    chk(f"{cipher} {'SKID' if kt else 'by value'}: PI {pi_size}, Content1 {c1_size}, "
        f"kl.size {pi_size} / {32 + c1_size}",
        (len(pi), kl_size(make_mdh(XEX_OF[cipher], POL_BOTH, kt), 0, len(pi) - 16),
         len(cl.content1()), kl_size(cl.mdh, len(cl.content1()), 0)),
        (pi_size, pi_size, c1_size, 32 + c1_size))
# Content1 by hand: key1 | key2 | mask (by value), SKID | mask | padding (by SKID)
tweak_mask = aes_encrypt(k2, v2b(bin_(i, B), 16))            # mask at index 0
mask2 = ref_mul_alpha(ref_mul_alpha(tweak_mask))             # after two blocks
for label, kt, want_c1 in (
        ("by value", 0, k1.hex() + k2.hex() + mask2.hex()),
        ("by SKID", 1, "efcdab8967452301" + mask2.hex() + "00" * 8)):
    cl = XexCL(sks=SKS)
    cl.provision(build_pi(XEX_OF['AES-128'], kt, SKID if kt else b2v(k1),
                          0 if kt else b2v(k2)))
    cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
    head = cl_run(cl, data)[0]                              # the whole 32-byte unit
    chk(f"{label}: Content1 after 2 blocks = {len(want_c1) // 2} B, key(s) | mask",
        cl.content1().hex(), want_c1)
    cl2 = XexCL(sks=SKS)
    cl2.import_scc(cl.mdh, cl.content1())                   # _State_ travels in the MDH
    chk(f"{label}: import it and encrypt two more blocks at mask indices 2, 3",
        (cl2.state, cl_run(cl2, data)[0].hex()),
        (ST_ENCRYPT, ref_xts(k1, k2, i, data + data)[32:].hex()))
    chk(f"{label}: the first two blocks were vector 2", head.hex(), c)
cl = XexCL(sks=SKS)
cl.provision(build_pi(XEX_OF['AES-128'], 1, SKID + 1))
chk("unresolved SKID at provisioning -> _Invalid_", cl.state, ST_INVALID)
cl = XexCL(sks=SKS)
cl.provision(build_pi(XEX_OF['AES-128'], 1, ONES64))
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
rand_ct = cl_run(cl, data)[0]
chk("all-ones SKID: two independent random keys, _KeyType_ 0, Content1 48 B",
    (cl.keytype, cl.key1 != cl.key2, len(cl.content1()),
     rand_ct == ref_xts(v2b(cl.key1, 16), v2b(cl.key2, 16), i, data)),
    (0, True, 48, True))

print("\n== (i) DERIVE: <<KLEE-derive-endpoints>>, `key1` (1) and `key2` (2), in _Ready_")
source1 = k1 + bytes.fromhex("5a" * 16)
source2 = k2 + bytes.fromhex("a5" * 16)
cl = new_xex(bytes(16), bytes(16))
d1 = cl.derive_dest(1, source1, 32)
d2 = cl.derive_dest(2, source2, 32)
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
chk("derive `key1` and `key2` (32 bytes each, truncated to 16), then vector 2",
    (d1, d2, cl_run(cl, data)[0].hex()), (True, True, c))
cl = new_xex(bytes(16), bytes(16))
cl.derive_dest(1, k1[:8], 8)
chk("length 8 < 16: `key1` zero-filled beyond byte 8",
    v2b(cl.key1, 16).hex(), k1[:8].hex() + "00" * 8)
cl = new_xex(bytes(16), bytes(16))
chk("destination index 3 (`mask` is not importable) -> _Invalid_",
    (cl.derive_dest(3, source1, 16), cl.state), (False, ST_INVALID))
cl = new_xex(bytes(16), bytes(16))
cl.setst(ST_ENCRYPT, 'C', bin_(i, B), 128)
chk("destination in _Encrypt_ -> _Invalid_",
    (cl.derive_dest(1, source1, 16), cl.state), (False, ST_INVALID))
cl = XexCL(sks=SKS)
cl.provision(build_pi(XEX_OF['AES-128'], 1, SKID))
chk("keys configured by a SKID are never importable -> _Invalid_",
    (cl.derive_dest(2, source2, 16), cl.state), (False, ST_INVALID))
src = new_xex(k1, k2)
dst = new_xex(bytes(16), bytes(16))
src.invalidate()
dst.invalidate()                             # no exportable field: the pair is not allowed
chk("an XEX CL as a source (a key is never exportable) -> both _Invalid_",
    (XEX_EXPORTABLE, src.state, dst.state), ({}, ST_INVALID, ST_INVALID))

print("\n== (j) Round-trip over many lengths, including every partial-block size")
k41, k42 = split_keys(IEEE1619[4][1])
rt = True
for length in list(range(16, 80)) + [128, 129, 255, 256]:
    payload = bytes((7 * n + 1) & 0xFF for n in range(length))
    for seq in (0, 1, 0x123456789A):
        ref = ref_xts(k41, k42, seq, payload)
        rt = rt and kl_xts(k41, k42, seq, payload) == ref
        rt = rt and kl_xts(k41, k42, seq, payload, per_block=True) == ref
        rt = rt and kl_xts(k41, k42, seq, ref, False) == payload
        rt = rt and ref_xts(k41, k42, seq, ref, False) == payload
chk("KLEE == REF and round-trips, lengths 16..79, 128, 129, 255, 256", rt, True)

print()
info("<<KLEE-XTS-from-XEX>> now reads \"the first `s`/8 bytes of the string\" and \"the "
     "`j`-th block processed after the tweak was set\"; both readings are the ones this "
     "harness models, the second because rule MGR3 makes one kl.exec process KLLEN/b "
     "blocks, each advancing the mask.")
info("<<KLEE-tweakable>> is not exercised: <<KLEE-exec-encodings>> instantiates no "
     "tweakable block cipher, so there is no Machine, and no published vector, for it.")
info("\"(multi-block) kl.exec instructions are expected to be of Form A\" is read with "
     "the substitutions of <<KLEE-usage-input-output>> available (Form D through the "
     "KLIOBUF), as 'expected' there prescribes.")

for label, fired in (("OCB doubling", neg_fired['double']),
                     ("MS-first order", neg_fired['order'])):
    if not fired:
        print(f"\nnegative control '{label}' did not fire: the test is not discriminating")
        ok = False

print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
