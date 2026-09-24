#!/usr/bin/env python3
"""Architectural-state-machine KAT for the KLEE management ISA (the Instructions chapter).

This harness transcribes the *Machine-independent* rules of the Instructions chapter of the draft
RISC-V KLEE specification (modules/ROOT/pages/Zkl-ISA-unpriv.adoc), with the exception causes
and the *lclstatus Off gate of the Privileged Architecture chapter (modules/ROOT/pages/Zkl-ISA-priv.adoc), and checks the
text's own invariants and worked sequences:

  * the 128-bit MDH layout (<<KLEE-metadata-header>>): tiling, walking ones,
    reserved bits, and the kl.getst / kl.getstx expansions;
  * the _State_ numbering (<<KLEE-State-field>>, <<KLEE-SC-sealing-status>>):
    Unconfigured, Valid, Error and Partial States, the Configuration States and
    their base types (<<KLEE-nested-state-base-types>>), the kl.setst immediate
    categories, and the State tests of the Pseudocode chapter snippets;
  * Metadata validity (<<KLEE-Metadata-validity>>, <<KLEE-MVR-open>>);
  * the length rule (<<KLEE-length-rule>>), kl.size and kl.avail
    (<<KLEE-instruction-size>>), including _ADSDropped_ and the serialized
    image S of <<KLEE-instruction-mv>>;
  * the _UsagePolicy_ enforcement matrix (<<KLEE-UsagePolicy>>);
  * kl.restrict* (<<KLEE-instruction-restrict>>);
  * _Locality_ substitution, LST_eff and the sealing associated data
    (<<KLEE-Localities>>, <<KLEE-Metadata-locality-interoperability>>), and
    the System Key Store narrowing (<<KLEE-system-keys>>);
  * kl.mgmt (<<KLEE-instruction-mgmt>>, <<KLEE-CL-management>>): opening a
    provisioning, an import or an export, completion, the base-type check,
    klmanagedcr and klstart, in the Zklmem and Zklmv variants and in Forms
    A, C and D;
  * nested management operations and PCCC shapes (<<KLEE-data-formats>>);
  * the short export and import of a CL in an Error State
    (<<KLEE-error-state-transfer>>, <<KLEE-error-state-instructions>>);
  * SCC import with an ADS: _ADSDropped_, IMPQUAL, second-segment failure
    (<<KLEE-SCC-import>>, <<KLEE-Auxiliary-Data-Section>>);
  * kl.load / kl.store / kl.mv: ContentOffset, image_end, 16-byte
    granularity, address alignment, faults, interrupted-transfer resumption;
  * the KLIOBUF CSRs and the kl.input / kl.output transfer window;
  * the State Management rules SGR1-SGR22 (<<KLEE-State-management>>),
    including the gate order of Rule SGR19 and the output zeroing of SGR16;
  * kl.exec resumption and the klstart checks (<<KLEE-CSR-klstart>>);
  * _ExpirationDate_ evaluation points (<<KLEE-Metadata-expiration-date>>);
  * kl.clone, kl.clear, kl.clearall, kl.clearads, and the generic gates of
    kl.derive (<<KLEE-instruction-derive>>);
  * the Error Handling Architecture (<<KLEE-error-architecture>>), with and
    without the Privileged Architecture, the CSK and KLS gates, and a compact
    model of the *lclstatus Off gate (<<KLEE-CSR-lclstatus>>);
  * the reset state and the context save and restore order
    (<<KLEE-state-save-and-restore-order>>), run end to end with a CL whose
    import was interrupted.

The Machines are three toy Machines whose only purpose is to have the shapes
the Machine-independent rules talk about (an operation mask, a policy that
extends _Machine_, a signature mask, a Machine-held counter, ...).  SCC sealing
transcribes SCC_KeyDeriv, POLYVAL, SCC_Encrypt and SCC_Decrypt of
<<KLEE-SCC-AEAD>> step by step, with AESE256 replaced by a clearly labelled
SHA-256 stand-in; the real construction is covered by scc-kat.py.  What is
tested here is *when* sealing happens, over which associated data, and what it
does to the architectural state.

Reporting follows ../run-kats.py: one PASS/FAIL line per check, a final
`KAT-RESULT: PASS|FAIL`, and `KAT-EXPECT-FAIL:` declarations for the negative
controls.  Lines starting with `INFO` record a reading this model had to choose
where the text is ambiguous; lines starting with `SPEC-NOTE` record text that
contradicts itself or the rest of the specification.  Both are review input,
not failures.
"""

import functools
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import b2v, v2b, sl, cat, bin_, montmul  # noqa: E402  (KLEE value conventions)

# =====================================================================
# reporting
# =====================================================================

_state = {"pass": 0, "fail": 0, "xfail_seen": set(), "xfail_want": []}


def section(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def check(name, got, want):
    ok = got == want
    if ok:
        _state["pass"] += 1
        print(f"PASS  {name}")
    else:
        _state["fail"] += 1
        print(f"FAIL  {name}")
        print(f"        got  {got!r}")
        print(f"        want {want!r}")
    return ok


def check_true(name, cond):
    return check(name, bool(cond), True)


def info(text):
    print(f"INFO  {text}")


def spec_note(text):
    print(f"SPEC-NOTE  {text}")


def declare_negative_control(label):
    _state["xfail_want"].append(label)
    print(f"KAT-EXPECT-FAIL: {label}")


def expect_fail(label, name, got, want):
    """A deliberately failing comparison: the harness's proof that it discriminates."""
    if got == want:
        _state["fail"] += 1
        print(f"FAIL  negative control {label} did not fail: {name}")
    else:
        _state["xfail_seen"].add(label)
        print(f"FAIL  {label}: {name}")
        print(f"        got  {got!r}")
        print(f"        want {want!r}")


# =====================================================================
# MDH format  --  <<KLEE-metadata-header>>
# =====================================================================

# (name, hi, lo, reserved?)
MDH_FIELDS = [
    ("Machine",           11,   0, False),
    ("MachinePolicy",     13,  12, False),
    ("MachineExtension",  15,  14, False),
    ("SCProtection",      18,  16, False),
    ("State",             24,  19, False),
    ("StateExtension",    28,  25, False),
    ("KeyType",           30,  29, False),
    ("Reserved31",        31,  31, True),
    ("AuxDataLen",        45,  32, False),
    ("Reserved46",        46,  46, True),
    ("ADSDropped",        47,  47, False),
    ("AuxInfo",           61,  48, False),
    ("Reserved62",        63,  62, True),
    ("UsagePolicy",       68,  64, False),
    ("Locality",          77,  69, False),
    ("Reserved78",        79,  78, True),
    ("MachineUse",        95,  80, False),
    ("ExpirationDate",   115,  96, False),
    ("Reserved116",      125, 116, True),
    ("Version",          127, 126, False),
]

FIELD = {f[0]: f for f in MDH_FIELDS}
MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1

# The layout of commit aba8573, used only by a negative control.
OLD_STATE_SPAN = (25, 21)


def fwidth(name):
    _, hi, lo, _ = FIELD[name]
    return hi - lo + 1


def mdh_new(**kw):
    m = {f[0]: 0 for f in MDH_FIELDS}
    for k, v in kw.items():
        if k not in m:
            raise KeyError(f"no such MDH field: {k}")
        m[k] = v
    return m


def mdh_pack(m):
    """MDH dict -> 128-bit KLEE value."""
    v = 0
    for name, hi, lo, _ in MDH_FIELDS:
        w = hi - lo + 1
        val = m.get(name, 0)
        if val >> w or val < 0:
            raise ValueError(f"field {name} value {val} does not fit in {w} bits")
        v |= val << lo
    return v


def mdh_unpack(v):
    """128-bit KLEE value -> MDH dict."""
    return {name: sl(v, hi, lo) for name, hi, lo, _ in MDH_FIELDS}


def mdh_bytes(m):
    return v2b(mdh_pack(m), 16)


def as_mdh(x):
    return mdh_unpack(x) if isinstance(x, int) else dict(x)


def reserved_bits_zero(m, low_only=False):
    return all(m.get(name, 0) == 0 for name, hi, lo, res in MDH_FIELDS
               if res and (hi <= 63 or not low_only))


# =====================================================================
# States  --  <<KLEE-State-field>>, <<KLEE-SC-sealing-status>>
# =====================================================================

ST_UNCONFIGURED = 0
ST_READY = 1
ST_SUCCESS = 46
ST_FAILURE = 47
ST_UNSUPPORTED = 48
ST_INVALID = 49
ST_OUT_OF_MEMORY = 50
ST_MGMT_AUTH = 51
ST_PRIV_VIOLATION = 52
ST_EXPIRED = 53

CFG_PROVISIONING = 56
CFG_EXPORTING = 57
CFG_IMPORTING = 58
CFG_PPI_EXPORTING = 59
CFG_PPI_IMPORTING = 60
CFG_MANAGEMENT_END = 63      # a kl.mgmt immediate, not a State
CFG_CLEAR_ADS = 64           # a kl.setst immediate, not a State

VALID_STATES = frozenset(range(1, 48))
ERROR_STATES = frozenset(range(48, 56))
COMPLETE_STATES = frozenset(range(1, 56))
PARTIAL_STATES = frozenset(range(56, 64))
CONFIG_STATES = frozenset(range(56, 61))
BASE_TYPE = {CFG_PROVISIONING: "pi", CFG_EXPORTING: "scc", CFG_IMPORTING: "scc",
             CFG_PPI_EXPORTING: "pi", CFG_PPI_IMPORTING: "pi"}
ERROR_STATE_FOR = {"unsupported": ST_UNSUPPORTED, "out_of_memory": ST_OUT_OF_MEMORY,
                   "privilege_violation": ST_PRIV_VIOLATION}
MANAGEDCL_NONE = 32


def completion_ml_ok(cl_state, ml_state):
    """The base-type rule for a completing kl.mgmt  (<<KLEE-CL-management>>)."""
    if BASE_TYPE[cl_state] == "scc":
        return ml_state in COMPLETE_STATES or ml_state in (CFG_IMPORTING, CFG_EXPORTING)
    return ml_state in (CFG_PROVISIONING, CFG_PPI_IMPORTING, CFG_PPI_EXPORTING)


# =====================================================================
# traps
# =====================================================================

class Trap(Exception):
    """A synchronous trap.  `cause` is 'illegal' (with `group` 1 or 2 of
    <<KLEE-illegal-instruction-grounds>>), a KLEE exception suffix of
    <<KLEE-exception-codes>> ('no_csk', 'CL_off', 'unsupported',
    'privilege_violation', 'out_of_memory', 'unconfigured_buffer'), or a memory
    exception ('load_misaligned', 'store_page_fault', ...)."""

    def __init__(self, cause, group=None, tval=None, note=""):
        super().__init__(f"{cause}{'' if group is None else '/' + str(group)} {note}")
        self.cause = cause
        self.group = group
        self.tval = tval
        self.note = note

    @property
    def tag(self):
        return self.cause if self.group is None else f"{self.cause}/{self.group}"


def trap_of(fn, *a, **kw):
    """The trap an instruction raises, as a tag, or None."""
    try:
        fn(*a, **kw)
    except Trap as t:
        return t.tag
    return None


def result_of(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Trap as t:
        return "trap:" + t.tag


# =====================================================================
# toy stand-ins
# =====================================================================

def prf(*parts):
    """STAND-IN keyed function used by the toy Machines and the toy RBG."""
    h = hashlib.sha256(b"KLEE-KAT toy PRF")
    for p in parts:
        if isinstance(p, int):
            p = p.to_bytes(32, "little")
        h.update(len(p).to_bytes(4, "little") + bytes(p))
    return h.digest()


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def to_blocks(b):
    b = bytes(b)
    if len(b) % 16:
        b += bytes(16 - len(b) % 16)
    return [b2v(b[i:i + 16]) for i in range(0, len(b), 16)]


def from_blocks(blocks):
    return b"".join(v2b(x, 16) for x in blocks)


# =====================================================================
# SCC sealing  --  <<KLEE-SCC-AEAD>>, AESE256 replaced by a stand-in
# =====================================================================

def toy_aese256(key, block):
    """STAND-IN for AESE256(K, B): SHA-256 based, not AES."""
    d = hashlib.sha256(b"KLEE-KAT AESE256 stand-in|" + v2b(key, 32) + v2b(block, 16)).digest()
    return b2v(d[:16])


@functools.lru_cache(maxsize=None)
def scc_keyderiv(key, nonce):
    """<<KLEE-SCC-key-derivation>>."""
    A = [toy_aese256(key, cat((nonce, 96), (bin_(i, 32), 32))) for i in range(6)]
    enc_key = cat((sl(A[5], 63, 0), 64), (sl(A[4], 63, 0), 64),
                  (sl(A[3], 63, 0), 64), (sl(A[2], 63, 0), 64))
    auth_key = cat((sl(A[1], 63, 0), 64), (sl(A[0], 63, 0), 64))
    return enc_key, auth_key


def polyval(auth_key, blocks):
    """<<KLEE-SCC-POLYVAL>>."""
    tmp = 0
    for blk in blocks:
        tmp ^= blk
        tmp = montmul(tmp, auth_key)
    return tmp


def _ctr_block(sep, siv, i):
    return cat((1, 1), (sep, 1), (sl(siv, 125, 32), 94), (bin_((sl(siv, 31, 0) + i) % 2**32, 32), 32))


def scc_encrypt(AD, N, sep, P, K, clear_bit47=True):
    """<<KLEE-SCC-GCM-SIV-enc>>.  `clear_bit47` exists only for a negative control."""
    AD_auth = list(AD)
    enc_key, auth_key = scc_keyderiv(K, N)
    if sep == 0 and clear_bit47:
        AD_auth[0] &= ~(1 << 47)
    SIV = polyval(auth_key, AD_auth + list(P))
    SIV ^= N                                   # SIV[95:0] <- SIV[95:0] xor N
    SIV = toy_aese256(enc_key, cat((0, 1), (sep, 1), (sl(SIV, 125, 0), 126)))
    C = [P[i] ^ toy_aese256(enc_key, _ctr_block(sep, SIV, i)) for i in range(len(P))]
    return SIV, C


def scc_decrypt(AD, N, sep, SIV, C, K, clear_bit47=True):
    """<<KLEE-SCC-GCM-SIV-dec>>."""
    AD_auth = list(AD)
    enc_key, auth_key = scc_keyderiv(K, N)
    if sep == 0 and clear_bit47:
        AD_auth[0] &= ~(1 << 47)
    P = [C[i] ^ toy_aese256(enc_key, _ctr_block(sep, SIV, i)) for i in range(len(C))]
    s = polyval(auth_key, AD_auth + P)
    tmp = s ^ N
    tmp = toy_aese256(enc_key, cat((0, 1), (sep, 1), (sl(tmp, 125, 0), 126)))
    if tmp != SIV:
        return False, [0] * len(C)
    return True, P


# =====================================================================
# Localities  --  <<KLEE-Localities>>, <<KLEE-locality-indexes>>
# =====================================================================

LOC_SUBFIELDS = [("hw1", 1, 0), ("hw2", 3, 2), ("boot", 5, 4),
                 ("mloc", 6, 6), ("hloc", 7, 7), ("sloc", 8, 8)]


def loc(hw1=0, hw2=0, boot=0, mloc=0, hloc=0, sloc=0):
    """Build a 9-bit _Locality_ field from its subfields."""
    return (hw1 & 3) | ((hw2 & 3) << 2) | ((boot & 3) << 4) \
        | ((mloc & 1) << 6) | ((hloc & 1) << 7) | ((sloc & 1) << 8)


def set_bits(v, hi, lo, x):
    w = hi - lo + 1
    return (v & ~(((1 << w) - 1) << lo)) | ((x & ((1 << w) - 1)) << lo)


def locality_entries(locality):
    """The LST indices a _Locality_ value names ("includes Locality #j")."""
    out = []
    h1, h2, bt = sl(locality, 1, 0), sl(locality, 3, 2), sl(locality, 5, 4)
    if h1:
        out.append(h1 - 1)
    if h2:
        out.append(2 + h2)
    if bt in (1, 2):
        out.append(5 + bt)
    for bit, j in ((6, 8), (7, 9), (8, 10)):
        if (locality >> bit) & 1:
            out.append(j)
    return sorted(out)


def locality_union(a, b):
    """The union of <<KLEE-system-keys>>: the stricter entry in each HW Binding
    chain, bits 6-8 or-ed; None when the two Boot Session entries conflict."""
    h1 = max(sl(a, 1, 0), sl(b, 1, 0))
    h2 = max(sl(a, 3, 2), sl(b, 3, 2))
    ba, bb = sl(a, 5, 4), sl(b, 5, 4)
    if ba and bb and ba != bb:
        return None
    return h1 | (h2 << 2) | ((ba or bb) << 4) | ((sl(a, 8, 6) | sl(b, 8, 6)) << 6)


def apply_usagepolicy_restriction(cur, req):
    """The _UsagePolicy_ rule of kl.restricth: bits 0-3 set the disallow bits,
    bit 4 clears the Debug grant; a clear bit changes nothing."""
    new = cur | (req & 0b01111)
    if req & 0b10000:
        new &= ~0b10000
    return new


def carries_custom_value(m):
    """Rule GR10's custom values present in the toy implementation."""
    return m["Machine"] >= 3072 or m["SCProtection"] in (6, 7) or m["Version"] == 3


# =====================================================================
# toy Machines  --  shapes only
# =====================================================================

ONES64 = (1 << 64) - 1
MAX_AUXDATALEN = 6        # the largest AuxDataLen this implementation supports
ADS_BLOCKS = 4            # AuxDataLen of the ADS this implementation generates
SC_ORDER = (0, 1, 2, 6)   # implementation-defined strength order; custom level 6 strongest
SUPPORTED_VERSIONS = (0,)

M_CIPHER = 0x011
M_XOF = 0x021
M_SIG = 0x031
M_CUSTOM = 0xC05          # a custom Machine: values 3072-4095 (<<KLEE-Machine-field>>)
M_ABSENT = 0x777          # an architected value this implementation does not implement


def sc_rank(v):
    return SC_ORDER.index(v) if v in SC_ORDER else -1


class Machine:
    kind = "ops"            # "ops": the MachinePolicy bits enable operations, one is required
                            # "sig": sign/verify bits, both may be zero
                            # "ext": the MachinePolicy field extends _Machine_
    policies = frozenset({1, 2, 3})
    sc_levels = frozenset({0})
    key_len = 32
    state_len = 16
    clf_base = 64
    clf_both = 0
    uses_auxinfo = False
    machineuse = "none"     # "none", or "state" where the Machine keeps a counter there
    op_states = {}          # State -> the MachinePolicy bit only that State's operation uses

    def __init__(self, ident, name):
        self.ident = ident
        self.name = name

    # -- lengths: <<KLEE-length-rule>> --------------------------------
    def key_field_len(self, m):
        return 16 if m["KeyType"] == 1 else self.key_len

    def pi_content_size(self, m):
        """(_Machine_, _MachinePolicy_, _KeyType_) only."""
        return self.key_field_len(m)

    def content1_size(self, m):
        """(_Machine_, _MachinePolicy_, _KeyType_, _StateExtension_) only."""
        return self.key_field_len(m) + (self.state_len if m["StateExtension"] & 1 else 0)

    def clf_capacity(self, m):
        """(_Machine_, _MachinePolicy_, _SCProtection_) only."""
        both = self.clf_both if m["MachinePolicy"] == 0b11 else 0
        return (self.clf_base + both) * (1 + max(0, sc_rank(m["SCProtection"])))

    # -- the Machine-held state block (present when StateExtension bit 0 is set)
    def get_state(self, cl):
        if not cl.mdh["StateExtension"] & 1:
            return bytes(self.state_len)
        o = self.key_field_len(cl.mdh)
        return cl.c1[o:o + self.state_len]

    def put_state(self, cl, data):
        o = self.key_field_len(cl.mdh)
        cl.c1 = cl.c1[:o] + bytes(data)
        cl.mdh["StateExtension"] |= 1

    def drop_state(self, cl):
        o = self.key_field_len(cl.mdh)
        cl.c1 = cl.c1[:o]
        cl.mdh["StateExtension"] &= ~1

    # -- behaviour ----------------------------------------------------
    def exec_form(self, m):
        return None

    def granularity(self, m):
        return 16

    def setst(self, unit, cl, imm, aux):
        return False

    def on_ready(self, cl):
        self.drop_state(cl)

    def process(self, unit, cl, unit_in):
        raise NotImplementedError


class ToyCipher(Machine):
    kind = "ops"
    policies = frozenset({1, 2, 3})
    sc_levels = frozenset({0, 1, 2, 6})
    key_len = 32
    state_len = 16
    clf_base = 64
    clf_both = 16
    ENCRYPT, DECRYPT, VERIFY = 2, 3, 4
    op_states = {2: 0b01, 3: 0b10}

    def exec_form(self, m):
        return "A" if m["State"] in (self.ENCRYPT, self.DECRYPT) else None

    def verify_tag(self, unit, cl):
        return b2v(prf(b"verify", unit.key_of(cl))[:8])

    def setst(self, unit, cl, imm, aux):
        m = cl.mdh
        if imm in (self.ENCRYPT, self.DECRYPT):
            if not m["MachinePolicy"] & self.op_states[imm]:
                return False
            m["State"] = imm
            self.put_state(cl, v2b(aux or 0, 16))      # the IV / counter block
            return True
        if imm == self.VERIFY:
            # SGR9: the State reached depends on the auxiliary input
            m["State"] = ST_SUCCESS if aux == self.verify_tag(unit, cl) else ST_FAILURE
            return True
        return False

    def process(self, unit, cl, blk):
        st = self.get_state(cl)
        ctr = b2v(st[0:8])
        out = xor_bytes(blk, prf(b"keystream", unit.key_of(cl), ctr)[:16])
        self.put_state(cl, v2b((ctr + 1) & ONES64, 8) + st[8:])
        return out


class ToyXof(Machine):
    kind = "ext"
    policies = frozenset({0, 1})
    sc_levels = frozenset({0, 1})
    key_len = 32
    state_len = 32
    clf_base = 96
    machineuse = "state"            # a squeeze counter
    ABSORB, FINAL = 2, 3

    def exec_form(self, m):
        if m["State"] in (ST_READY, self.ABSORB):
            return "B"                          # Ready explicitly allows kl.exec (SGR2)
        if m["State"] == ST_SUCCESS:
            return "C"                          # SGR5: further output of a XOF
        return None

    def granularity(self, m):
        return 1

    def setst(self, unit, cl, imm, aux):
        m = cl.mdh
        if imm == self.ABSORB and m["State"] in (ST_READY, self.ABSORB):
            m["State"] = self.ABSORB
            self.put_state(cl, self.get_state(cl))
            return True
        if imm == self.FINAL and m["State"] == self.ABSORB:
            m["State"] = ST_SUCCESS             # SGR9: lands in Success
            return True
        return False

    def on_ready(self, cl):
        self.drop_state(cl)
        cl.mdh["MachineUse"] = 0

    def absorb(self, unit, cl, byte):
        self.put_state(cl, prf(b"absorb", unit.key_of(cl), self.get_state(cl), byte)[:32])
        cl.mdh["State"] = self.ABSORB

    def squeeze(self, unit, cl):
        m = cl.mdh
        out = prf(b"squeeze", self.get_state(cl), m["MachineUse"])[0:1]
        m["MachineUse"] = (m["MachineUse"] + 1) & 0xFFFF
        return out

    def process(self, unit, cl, unit_in):
        if cl.mdh["State"] == ST_SUCCESS:
            return self.squeeze(unit, cl)
        self.absorb(unit, cl, unit_in)
        return None


class ToySig(Machine):
    kind = "sig"
    policies = frozenset({0, 1, 2, 3})
    sc_levels = frozenset({0, 1})
    key_len = 64
    state_len = 16
    clf_base = 128
    clf_both = 32
    uses_auxinfo = True
    SIGN, VERIFY = 2, 3
    op_states = {2: 0b01, 3: 0b10}

    def exec_form(self, m):
        return "A" if m["State"] == self.SIGN else None

    def setst(self, unit, cl, imm, aux):
        m = cl.mdh
        if imm in (self.SIGN, self.VERIFY) and m["MachinePolicy"] & self.op_states[imm]:
            m["State"] = imm
            return True
        return False

    def process(self, unit, cl, blk):
        return prf(b"sign", unit.key_of(cl), blk)[:16]


class ToyCustom(Machine):
    kind = "ops"
    policies = frozenset({1})
    sc_levels = frozenset({0})
    key_len = 16
    state_len = 0
    clf_base = 32


MACHINES = {m.ident: m for m in (ToyCipher(M_CIPHER, "toy-cipher"), ToyXof(M_XOF, "toy-xof"),
                                 ToySig(M_SIG, "toy-sig"), ToyCustom(M_CUSTOM, "toy-custom"))}


def content2_size(m):
    """<<KLEE-instruction-size>>."""
    return 16 * (m["AuxDataLen"] - 2) if m["AuxDataLen"] >= 2 and m["ADSDropped"] == 0 else 0


# =====================================================================
# memory
# =====================================================================

BASE = 0x4000   # where the software sequences keep images (16-byte aligned)


class Memory:
    """Hart-visible memory with page-fault and non-idempotent (PMA) ranges."""

    def __init__(self, size=1 << 16):
        self.buf = bytearray(size)
        self.unmapped = []
        self.nonidem = []
        self.accesses = 0

    def write(self, addr, data):
        self.buf[addr:addr + len(data)] = bytes(data)

    def read(self, addr, n):
        return bytes(self.buf[addr:addr + n])

    def fault(self, addr, n, kind):
        for lo, hi in self.unmapped:
            if addr < hi and addr + n > lo:
                return f"{kind}_page_fault", max(addr, lo)
        for lo, hi in self.nonidem:
            if addr < hi and addr + n > lo:
                return f"{kind}_access_fault", max(addr, lo)
        return None


# =====================================================================
# the modelled KLEE unit (one hart)
# =====================================================================

def _secret(label, j=0):
    return b2v(prf(b"LST", label, j)[:16]) | 1          # never zeros(128)


DEFAULT_HW = {j: _secret(b"hw", j) for j in range(6)}
DEFAULT_CSK = b2v(prf(b"CSK"))
SKS_KEY = prf(b"SKS key") + prf(b"SKS key 2")           # 64 bytes, truncated per Machine

SKID_A = 0x0123_4567_89AB_CDEF
SKID_B = 0x42
SKID_C = 0x43
SKID_D = 0x44
DEFAULT_SKS = {
    SKID_A: {"key": SKS_KEY, "allowed": {M_CIPHER: 0b11, M_SIG: 0b01},
             "usage": 0b00100, "locality": loc(hw1=2)},
    SKID_B: {"key": SKS_KEY[::-1], "allowed": {M_CIPHER: 0b01},
             "usage": 0b10000, "locality": loc(boot=1)},
    SKID_C: {"key": SKS_KEY, "allowed": {M_CIPHER: 0b11},
             "usage": 0, "locality": loc(boot=2)},
    SKID_D: {"key": SKS_KEY, "allowed": {M_CIPHER: 0b11},
             "usage": 0, "locality": loc(sloc=1)},
}


class CL:
    """A Cryptographic Locker: MDH, the plaintext Content1 / Content2 of a CL in a
    Valid State, the serialized Content while under management, CLF allocation."""

    def __init__(self):
        self.mdh = mdh_new()
        self.c1 = b""
        self.c2 = b""
        self.img = None
        self.alloc = 0


class Unit:
    IDS = (0x0000_0A11, 0x0000_0042, 0x0000_0007)   # klmvendorid, klmarchid, klmimpid
    RO_ID = ("klmvendorid", "klmarchid", "klmimpid", "klmaxiobuflen")

    def __init__(self, *, zklv=True, zklio=True, zklmv=True, zklexpire=True, zklmem_hw=True,
                 priv=True, h_ext=True, maxiobuflen=256, clf_total=1 << 20, clock=0,
                 csk=DEFAULT_CSK, ids=None, hw=None, sks=None):
        self.zklv, self.zklio, self.zklmv, self.zklexpire = zklv, zklio, zklmv, zklexpire
        self.zklmem_hw = zklmem_hw
        self.priv = priv
        self.h_ext = h_ext
        self.vendorid, self.archid, self.impid = ids or self.IDS
        self.klmaxiobuflen = maxiobuflen if zklio else 0
        self.clf_total = clf_total
        self.clock = clock                       # hours since 2027-01-01 00:00 UTC; < 0 before
        self.csk = csk
        self.hw = dict(DEFAULT_HW if hw is None else hw)
        self.sks = dict(DEFAULT_SKS if sks is None else sks)
        self.physbootscrt = _secret(b"phys")
        self.virtbootscrt = _secret(b"virt")
        self.mlocality = _secret(b"mloc")
        self.hlocality = _secret(b"hloc")
        self.slocality = _secret(b"sloc")
        self.vslocality = _secret(b"vsloc")
        self.mode = "M"
        self.V = 0
        self.kls_off = False
        self.lcr = {}                            # mlclstatus fields: 'off' / 'initial' / 'clean' / 'dirty'
        self.vstart = 0
        self._rbg = 0
        self.reset()

    # ------------------------------------------------------------ reset
    def reset(self):
        """<<KLEE-out-of-reset-unpriv>>."""
        self.cls = [CL() for _ in range(32)]
        self.kliobuflen = 0
        self.kliobuftop = 0
        self.kliobuf = bytearray()
        self.klstart = 0
        self.klmanagedcr = MANAGEDCL_NONE
        self.siv = self.impqual = self.siv2 = 0

    # ------------------------------------------------------------ helpers
    def rbg(self, n):
        """STAND-IN for the RBG of <<KLEE-RBG>>."""
        self._rbg += 1
        out, i = b"", 0
        while len(out) < n:
            out += prf(b"RBG", self._rbg, i)
            i += 1
        return out[:n]

    def impqual_value(self):
        """IMPQUAL := zeros(32) @ klmimpid @ klmarchid @ klmvendorid."""
        return cat((0, 32), (self.impid, 32), (self.archid, 32), (self.vendorid, 32))

    def clf_free(self):
        return self.clf_total - sum(c.alloc for c in self.cls)

    def wants_ads(self, m):
        return sc_rank(m["SCProtection"]) >= 1

    def gen_ads(self, cl):
        return prf(b"ADS", cl.c1)[:16 * (ADS_BLOCKS - 2)]

    def key_of(self, cl):
        m = cl.mdh
        mach = MACHINES[m["Machine"]]
        if m["KeyType"] == 1:
            return self.sks[b2v(cl.c1[0:8])]["key"][:mach.key_len]
        return cl.c1[0:mach.key_len]

    # -- Localities ----------------------------------------------------
    def _lst_raw(self, j):
        if j <= 5:
            return self.hw.get(j, 0)
        return {6: self.physbootscrt,
                7: self.virtbootscrt if self.h_ext else 0,
                8: self.mlocality,
                9: self.hlocality if self.h_ext else 0,
                10: self.vslocality if self.V else self.slocality}[j]

    def lst_register(self, j):
        """The register LST entry j denotes in the current mode (for the
        three-distinct-registers property)."""
        return {8: "mkllocality", 9: "hkllocality" if self.h_ext else None,
                10: "vskllocality" if self.V else "skllocality"}[j]

    def lst_eff(self, j):
        """LST_eff[j]: substitution along the HW Binding chains; zeros(128) when
        nothing is configured (<<KLEE-SCC-export>>)."""
        if j <= 5:
            end = 2 if j <= 2 else 5
            for w in range(j, end + 1):
                if self._lst_raw(w):
                    return self._lst_raw(w)
            return 0
        return self._lst_raw(j)

    def locality_problem(self, locality):
        if sl(locality, 5, 4) == 3:
            return "Locality[5:4] = 3"
        for j in locality_entries(locality):
            if self.lst_eff(j) == 0:
                return f"Locality names unconfigured LST entry {j}"
        return None

    def sealing_ad(self, m):
        return [mdh_pack(m)] + [self.lst_eff(j) for j in locality_entries(m["Locality"])]

    # -- classification --------------------------------------------------
    def unsupported(self, m):
        """Unsupported Metadata  (<<KLEE-Metadata-validity>>)."""
        mach = MACHINES.get(m["Machine"])
        if mach is None or m["MachineExtension"] != 0:
            return True
        if m["SCProtection"] not in mach.sc_levels:
            return True
        if m["MachinePolicy"] not in mach.policies:
            # a zero policy for a Machine that requires a bit is *invalid* instead
            return not (mach.kind == "ops" and m["MachinePolicy"] == 0)
        return False

    def invalid_reasons(self, m, ctx, low_only=False):
        """Invalid Metadata  (<<KLEE-Metadata-validity>>).  ctx: 'provision',
        'import' or 'size'; low_only: only bits [63:0] are examined (Form B)."""
        r = []
        mach = MACHINES.get(m["Machine"])
        st = m["State"]
        if ctx == "provision":
            pi_like = True
        else:
            pi_like = BASE_TYPE.get(st) == "pi" or (ctx == "size" and st == ST_UNCONFIGURED)
        if not reserved_bits_zero(m, low_only=low_only):
            r.append("reserved bit")
        if m["AuxDataLen"] == 1:
            r.append("AuxDataLen = 1")
        if pi_like and m["ADSDropped"]:
            r.append("ADSDropped in a PI-shaped image")
        if mach is not None and mach.kind == "ops" and m["MachinePolicy"] == 0:
            r.append("MachinePolicy zero")
        if m["KeyType"] in (2, 3):
            r.append("KeyType 2 or 3")
        if mach is not None and not mach.uses_auxinfo and m["AuxInfo"]:
            r.append("AuxInfo unused")
        if pi_like and m["AuxDataLen"]:
            r.append("AuxDataLen in a PI-shaped image")
        if ctx == "provision" and st != ST_UNCONFIGURED:
            r.append("State at provisioning")
        if ctx == "import" and (st == ST_UNCONFIGURED or st in (61, 62, 63)):
            r.append("State at import")
        if not low_only:
            p = self.locality_problem(m["Locality"])
            if p:
                r.append(p)
            if m["ExpirationDate"] and not self.zklexpire:
                r.append("ExpirationDate without Zklexpire")
            if m["Version"] not in SUPPORTED_VERSIONS:
                r.append("Version")
            if carries_custom_value(m) and sl(m["Locality"], 1, 0) not in (2, 3):
                r.append("GR10")
        return r

    def available(self, m):
        """kl.avail: _Machine_, _MachinePolicy_, _MachineExtension_, _KeyType_, _SCProtection_."""
        mach = MACHINES.get(m["Machine"])
        if mach is None or m["MachineExtension"]:
            return 0
        if m["MachinePolicy"] not in mach.policies or m["SCProtection"] not in mach.sc_levels:
            return 0
        if m["KeyType"] not in ((0, 1) if self.sks else (0,)):
            return 0
        return 1

    def usage_allowed(self, m):
        """<<KLEE-UsagePolicy>>; authenticated Debug mode (<<KLEE-interaction-with-debug>>)."""
        up = m["UsagePolicy"]
        if self.mode == "D":
            return bool(up & 0b10000)
        bit = {"U": 0, "VU": 0, "VS": 1, "HS": 2, "S": 2, "M": 3}[self.mode]
        return not (up >> bit) & 1

    def expired(self, m):
        """<<KLEE-Metadata-expiration-date>>, for a CL in a Valid State."""
        if not self.zklexpire or m["ExpirationDate"] == 0:
            return False
        converted = max(0, self.clock)
        return not converted < m["ExpirationDate"]

    # ------------------------------------------------------------ gates
    def _exc_trap(self, cause):
        """kl_exc_no_csk and kl_exc_unconfigured_buffer, per
        <<KLEE-exception-error-correspondence>>."""
        if self.priv:
            return Trap(cause)
        return Trap("illegal", 2, note=f"{cause} without the Privileged Architecture")

    def _exc_cl(self, k, cause):
        """An exception naming CL k; without the Privileged Architecture, the Error State."""
        if self.priv:
            raise Trap(cause)
        self._enter_error(k, ERROR_STATE_FOR[cause])
        return "error"

    def _pre(self, ro_id=False):
        if self.kls_off and not ro_id:
            raise Trap("illegal", 1, note="a KLS field in effect is Off")
        if not self.csk and not ro_id:
            raise self._exc_trap("no_csk")

    def _idx(self, k):
        if not isinstance(k, int) or not 0 <= k <= 31:
            raise Trap("illegal", 1, note="GR1: CL index")

    def _fields_in_effect(self):
        return self.priv and self.mode not in ("M", "D")

    def _off_gate(self, k, exempt=False):
        if self._fields_in_effect() and self.lcr.get(k) == "off":
            if not exempt:
                raise Trap("CL_off")
            return True
        return False

    def _dirty(self, k):
        if self._fields_in_effect():
            self.lcr[k] = "dirty"

    def _zeroize(self, k, dirty=True):
        was_cfg = self.cls[k].mdh["State"] in PARTIAL_STATES
        self.cls[k] = CL()
        if self.klmanagedcr == k and was_cfg:
            self.klmanagedcr = MANAGEDCL_NONE
        if dirty:
            self._dirty(k)

    def _enter_error(self, k, st):
        """SGR10 / SGR11."""
        cl = self.cls[k]
        was_cfg = cl.mdh["State"] in PARTIAL_STATES
        cl.mdh["State"] = st
        cl.mdh["AuxDataLen"] = 0
        cl.mdh["ADSDropped"] = 0
        cl.c1 = cl.c2 = b""
        cl.img = None
        cl.alloc = 0
        if self.klmanagedcr == k and was_cfg:
            self.klmanagedcr = MANAGEDCL_NONE
        self._dirty(k)

    def _after_mgmt(self, k):
        st = self.cls[k].mdh["State"]
        self.klmanagedcr = k if st in PARTIAL_STATES else MANAGEDCL_NONE
        self.klstart = 0

    def _retire(self):
        self.klstart = 0
        self.vstart = 0

    # ------------------------------------------------------------ CSRs
    def _csr_gate(self, name):
        if name in ("kliobuflen", "kliobuftop") and not self.zklio:
            raise Trap("illegal", 1, note=f"{name} is not present without Zklio")
        self._pre(ro_id=name in self.RO_ID)

    def csr_read(self, name):
        self._csr_gate(name)
        return {"klmvendorid": self.vendorid, "klmarchid": self.archid,
                "klmimpid": self.impid, "klmaxiobuflen": self.klmaxiobuflen,
                "kliobuflen": self.kliobuflen, "kliobuftop": self.kliobuftop,
                "klstart": self.klstart, "klmanagedcr": self.klmanagedcr}[name]

    def csr_write(self, name, value):
        self._csr_gate(name)
        if name in self.RO_ID:
            raise Trap("illegal", 1, note="write to a read-only CSR")
        if name == "kliobuflen":
            n = min(value, self.klmaxiobuflen)          # WARL
            self.kliobuflen = n
            self.kliobuf = bytearray(n)                 # zeroes the buffer ...
            self.kliobuftop = n                         # ... and sets kliobuftop
        elif name == "kliobuftop":
            self.kliobuftop = min(value, self.kliobuflen)
        elif name == "klstart":
            self.klstart = value
        elif name == "klmanagedcr":
            if value <= MANAGEDCL_NONE:                 # 33 and above: write ignored
                self.klmanagedcr = value

    # ------------------------------------------------------------ inspection
    def getmd(self, k):
        self._idx(k)
        self._pre()
        self._off_gate(k)
        return dict(self.cls[k].mdh)

    def getmdl(self, k):
        return sl(mdh_pack(self.getmd(k)), 63, 0)

    def getmdv(self, k, vec_bits=128):
        if not self.zklv:
            raise Trap("illegal", 1, note="kl.getmdv needs Zklv")
        if vec_bits < 128:
            raise Trap("illegal", 1, note="GR7")
        return mdh_pack(self.getmd(k))

    def getst(self, k):
        """The pseudo-instruction kl.getst, as its RV64 expansion."""
        xd = self.getmdl(k)          # kl.getmdl Xd, Ks
        xd = xd >> 19                # srli Xd, Xd, 19
        xd = xd & 0x3F               # andi Xd, Xd, 0x3F
        return xd

    def getstx(self, k):
        xd = self.getmdl(k)          # kl.getmdl Xd, Ks
        xd = xd >> 25                # srli Xd, Xd, 25
        xd = xd & 0x0F               # andi Xd, Xd, 0x0F
        return xd

    def _md_operand(self, form, k, lo, md, vec_bits):
        if form == "C":
            if not self.zklv:
                raise Trap("illegal", 1)
            if vec_bits < 128:
                raise Trap("illegal", 1, note="GR7")
        if form == "A":
            self._idx(k)
        self._pre()
        if form == "A":
            self._off_gate(k)
            return dict(self.cls[k].mdh), False
        if form == "B":
            return mdh_unpack(lo & MASK64), True
        return as_mdh(md), True

    def size(self, form="A", k=None, lo=None, md=None, vec_bits=128):
        """kl.size  (<<KLEE-instruction-size>>)."""
        m, supplied = self._md_operand(form, k, lo, md, vec_bits)
        return self.size_of(m, supplied=supplied, low_only=form == "B")

    def size_of(self, m, supplied, low_only=False):
        st = m["State"]
        if not supplied and st == ST_UNCONFIGURED:
            return 0                                                    # 1
        if supplied and st not in ERROR_STATES:                         # 2
            if st in (61, 62, 63) or self.unsupported(m) \
                    or self.invalid_reasons(m, "size", low_only=low_only):
                return 0
        if st in ERROR_STATES:
            return 16                                                   # 3
        mach = MACHINES[m["Machine"]]
        if st in VALID_STATES or st in (CFG_IMPORTING, CFG_EXPORTING):  # 4
            c1 = mach.content1_size(m)
            if m["AuxDataLen"] == 0:
                return 32 + c1
            return 64 + c1 + content2_size(m)
        return 16 + mach.pi_content_size(m)                             # 5

    def avail(self, form="A", k=None, lo=None, md=None, vec_bits=128):
        m, supplied = self._md_operand(form, k, lo, md, vec_bits)
        if not supplied and m["State"] == ST_UNCONFIGURED:
            return 0
        return self.available(m)

    def layout(self, m):
        """(ContentOffset, content_size, max_admissible, image_size, image_end)
        of <<KLEE-instruction-mv>>."""
        mach = MACHINES[m["Machine"]]
        if BASE_TYPE.get(m["State"]) == "pi":
            off = 0
            content = mach.pi_content_size(m)
            max_adm = content
        else:
            off = 16 if m["AuxDataLen"] == 0 else 48
            c1 = mach.content1_size(m)
            content = c1 + content2_size(m)
            max_adm = c1 + 16 * (MAX_AUXDATALEN - 2)
        return off, content, max_adm, off + content, off + min(content, max_adm)

    # ------------------------------------------------------------ kl.mgmt
    def mgmt(self, k, imm, md=None, form="D", vec_bits=128):
        """kl.mgmt  (<<KLEE-instruction-mgmt>>, <<KLEE-CL-management>>)."""
        if imm not in (CFG_PROVISIONING, CFG_EXPORTING, CFG_IMPORTING, CFG_MANAGEMENT_END):
            raise Trap("illegal", 1, note="kl.mgmt immediates 59-62 are reserved")
        if form == "B":
            raise Trap("illegal", 1, note="Form B of kl.mgmt is reserved")
        if form == "C":
            if not self.zklv:
                raise Trap("illegal", 1, note="Form C needs Zklv")
            if vec_bits < 128:
                raise Trap("illegal", 1, note="GR7")
        self._idx(k)
        self._pre()
        opening = imm in (CFG_PROVISIONING, CFG_IMPORTING)
        self._off_gate(k, exempt=opening)
        if self.klmanagedcr not in (k, MANAGEDCL_NONE):
            raise Trap("illegal", 2, note="klmanagedcr names another CL")
        st = self.cls[k].mdh["State"]
        if imm == CFG_EXPORTING and st == ST_UNCONFIGURED:
            raise Trap("illegal", 2, note="export opened on an Unconfigured CL")
        if imm == CFG_MANAGEMENT_END and st not in CONFIG_STATES:
            raise Trap("illegal", 2, note="no management operation is open")
        needs_md = opening or (imm == CFG_MANAGEMENT_END and st != CFG_PROVISIONING)
        ml = self._mgmt_md(form, md) if needs_md else None
        if imm == CFG_MANAGEMENT_END and st != CFG_PROVISIONING \
                and not completion_ml_ok(st, ml["State"]):
            raise Trap("illegal", 2, note="ml.State inconsistent with the base type")
        if opening:
            return self._open_in(k, imm, ml)
        if imm == CFG_EXPORTING:
            return self._open_export(k)
        return self._complete(k, ml)

    def _mgmt_md(self, form, md):
        if form == "A":
            if not self.zklio:
                raise Trap("illegal", 2, note="KLIOBUF substitution without Zklio")
            if self.kliobuflen == 0:
                raise self._exc_trap("unconfigured_buffer")
            if self.kliobuftop < 16:
                raise Trap("illegal", 2, note="GR7: kliobuftop < 16")
            return mdh_unpack(b2v(bytes(self.kliobuf[0:16])))      # bytes [0, 16), klstart ignored
        return as_mdh(md)

    def _open_in(self, k, imm, ml):
        self._zeroize(k)                                    # the target CL is zeroized
        cl = self.cls[k]
        if imm == CFG_IMPORTING and ml["State"] in ERROR_STATES:
            m = dict(ml)                                    # the short import path
            m["AuxDataLen"] = 0
            m["ADSDropped"] = 0
            if m["State"] in (54, 55):
                m["State"] = ST_INVALID
            cl.mdh = m
            self._after_mgmt(k)
            return "short import"
        if self.unsupported(ml):
            return self._fail_open(k, "unsupported")
        ctx = "provision" if imm == CFG_PROVISIONING else "import"
        if self.invalid_reasons(ml, ctx):
            return self._fail_open(k, "invalid")
        mach = MACHINES[ml["Machine"]]
        need = mach.clf_capacity(ml)
        if need > self.clf_free():
            return self._fail_open(k, "out_of_memory")
        m = dict(ml)
        if imm == CFG_PROVISIONING:
            m["StateExtension"] = 0
            m["MachineUse"] = 0
            m["State"] = CFG_PROVISIONING
        else:
            adl = m["AuxDataLen"]                           # steps 1-5 of <<KLEE-SCC-import>>
            m["ADSDropped"] = 1 if adl >= 2 and (ml["ADSDropped"] or adl > MAX_AUXDATALEN) else 0
            m["State"] = CFG_PPI_IMPORTING if BASE_TYPE.get(ml["State"]) == "pi" else CFG_IMPORTING
            self.siv = self.impqual = self.siv2 = 0         # zeroized by an opening import
        cl.mdh = m
        cl.alloc = need
        off, _, _, _, iend = self.layout(m)
        cl.img = bytearray(iend - off)
        self._after_mgmt(k)
        return "opened"

    def _fail_open(self, k, why):
        cl = self.cls[k]
        if why == "invalid" or not self.priv:
            # all fields other than State remain zero; no CLF capacity allocated
            cl.mdh = mdh_new(State={"invalid": ST_INVALID, "unsupported": ST_UNSUPPORTED,
                                    "out_of_memory": ST_OUT_OF_MEMORY}[why])
            self._after_mgmt(k)
            return why
        self.klmanagedcr = MANAGEDCL_NONE      # the zeroizing step left the CL Unconfigured
        raise Trap(why)

    def _open_export(self, k):
        cl = self.cls[k]
        m = cl.mdh
        st = m["State"]
        if st in ERROR_STATES:
            self._after_mgmt(k)
            return "unchanged"
        if st in VALID_STATES:
            # <<KLEE-SCC-export>>
            saved = dict(m)
            siv, ct1 = scc_encrypt(self.sealing_ad(saved), 0, 0, to_blocks(cl.c1), self.csk)
            ct = from_blocks(ct1)
            if m["AuxDataLen"] >= 2:
                impq = self.impqual_value()
                siv2, ct2 = scc_encrypt([impq, siv], 0, 1, to_blocks(cl.c2), self.csk)
                self.impqual, self.siv2 = impq, siv2
                ct += from_blocks(ct2)
            self.siv = siv
            cl.img = bytearray(ct)
            cl.c1 = cl.c2 = b""
            m["State"] = CFG_EXPORTING
        else:
            m["State"] = CFG_PPI_EXPORTING if BASE_TYPE[st] == "pi" else CFG_EXPORTING
        self._dirty(k)
        self._after_mgmt(k)
        return "opened"

    def _complete(self, k, ml):
        cl = self.cls[k]
        if cl.mdh["State"] == CFG_PROVISIONING:
            return self._complete_provisioning(k)
        cl.mdh["State"] = ml["State"]                 # only _State_ is taken from ml
        if ml["State"] in COMPLETE_STATES:
            self._unseal(k)
        self._dirty(k)
        self._after_mgmt(k)
        return "completed"

    def _unseal(self, k):
        """Completion of an import (<<KLEE-SCC-import>>) or of an export
        (<<ace-mgmt-completes-export>>) with a Complete ml._State_."""
        cl = self.cls[k]
        m = cl.mdh
        mach = MACHINES[m["Machine"]]
        n1 = mach.content1_size(m)
        img = bytes(cl.img)
        img += bytes(max(0, n1 - len(img)))
        ok, p1 = scc_decrypt(self.sealing_ad(m), 0, 0, self.siv, to_blocks(img[:n1]), self.csk)
        if not ok:
            self._enter_error(k, ST_MGMT_AUTH)
            return False
        cl.c1 = from_blocks(p1)
        c2 = b""
        adl, dropped = m["AuxDataLen"], m["ADSDropped"]
        if adl >= 2 and not dropped:
            n2 = 16 * (adl - 2)
            ok2 = False
            if self.impqual == self.impqual_value():
                seg = img[n1:n1 + n2]
                seg += bytes(n2 - len(seg))
                ok2, p2 = scc_decrypt([self.impqual, self.siv], 0, 1, self.siv2,
                                      to_blocks(seg), self.csk)
            if ok2:
                c2 = from_blocks(p2)
            else:
                dropped = 1                               # drop Content2
        m["ADSDropped"] = 0
        if adl == 0 or dropped:
            if self.wants_ads(m):                         # a replacement ADS
                m["AuxDataLen"] = ADS_BLOCKS
                c2 = self.gen_ads(cl)
            else:
                m["AuxDataLen"] = 0
                c2 = b""
        cl.c2 = c2
        cl.img = None
        if m["KeyType"] == 1:
            if b2v(cl.c1[0:8]) == ONES64 or not self.sks_resolve(cl):
                self._enter_error(k, ST_INVALID)
                return False
        return True

    def _complete_provisioning(self, k):
        cl = self.cls[k]
        m = cl.mdh
        if m["AuxDataLen"] or m["ADSDropped"]:
            self._enter_error(k, ST_INVALID)
            self._after_mgmt(k)
            return "invalid"
        mach = MACHINES[m["Machine"]]
        pi = bytes(cl.img)
        cl.img = None
        if m["KeyType"] == 1 and b2v(pi[0:8]) == ONES64:
            cl.c1 = self.rbg(mach.key_len)              # generated only now
            m["KeyType"] = 0
        elif m["KeyType"] == 1:
            cl.c1 = pi[0:16]
            if not self.sks_resolve(cl):
                self._enter_error(k, ST_INVALID)
                self._after_mgmt(k)
                return "invalid"
        else:
            cl.c1 = pi
        m["State"] = ST_READY
        m["StateExtension"] = 0
        m["MachineUse"] = 0
        if self.wants_ads(m):
            m["AuxDataLen"] = ADS_BLOCKS
            cl.c2 = self.gen_ads(cl)
        self._dirty(k)
        self._after_mgmt(k)
        return "completed"

    def sks_resolve(self, cl):
        """<<KLEE-system-keys>>; False when the CL must become Invalid."""
        m = cl.mdh
        e = self.sks.get(b2v(cl.c1[0:8]))
        if e is None or m["Machine"] not in e["allowed"]:
            return False
        allowed = e["allowed"][m["Machine"]]
        if MACHINES[m["Machine"]].kind == "ext":
            if m["MachinePolicy"] != allowed:
                return False
        elif m["MachinePolicy"] & ~allowed:
            return False
        up, kp = m["UsagePolicy"], e["usage"]
        new_up = ((up | kp) & 0b01111) | (up & kp & 0b10000)
        new_loc = locality_union(m["Locality"], e["locality"])
        if new_loc is None or self.locality_problem(new_loc):
            return False
        m["UsagePolicy"] = new_up
        m["Locality"] = new_loc
        return True

    # ------------------------------------------------------------ kl.setst family
    def setst(self, k, imm, aux=None, form="A", vec_bits=128):
        """kl.setst  (<<KLEE-instruction-setst>>)."""
        if imm in (ST_SUCCESS, ST_FAILURE):
            raise Trap("illegal", 1, note="SGR7: immediates 46 and 47 are reserved")
        if 56 <= imm <= 63:
            return self.mgmt(k, imm, aux, form=form, vec_bits=vec_bits)
        if k == "X0":
            if form == "A" and imm == ST_UNCONFIGURED:
                return self.clearall()
            raise Trap("illegal", 1, note="reserved kl.setst with r = 1 and X0")
        if form == "C" and not self.zklv:
            raise Trap("illegal", 1)
        self._idx(k)
        self._pre()
        if imm == ST_UNCONFIGURED:
            return self.clear(k)
        if imm in ERROR_STATES:
            self._off_gate(k)
            if self.cls[k].mdh["State"] == ST_UNCONFIGURED:
                return "noop"
            self._enter_error(k, ST_INVALID if imm in (54, 55) else imm)
            return "error state"
        self._off_gate(k)
        g = self._usage_gate(k)
        if g is not None:
            return g
        cl = self.cls[k]
        m = cl.mdh
        mach = MACHINES[m["Machine"]]
        if imm == CFG_CLEAR_ADS:                            # kl.clearads
            m["AuxDataLen"] = 0
            m["ADSDropped"] = 0
            cl.c2 = b""
            self._dirty(k)
            return "ads cleared"
        if m["State"] in (ST_SUCCESS, ST_FAILURE) and imm != ST_READY:
            self._enter_error(k, ST_INVALID)                # SGR5, SGR6
            return "invalid"
        if imm == ST_READY:                                 # SGR8
            mach.on_ready(cl)
            m["State"] = ST_READY
        elif not mach.setst(self, cl, imm, aux):
            self._enter_error(k, ST_INVALID)
            return "invalid"
        self._dirty(k)
        return "ok"

    def clear(self, k):
        """kl.clear: kl.setst with the kl_state_unconfigured immediate."""
        off = self._off_gate(k, exempt=True)
        was_unconfigured = self.cls[k].mdh["State"] == ST_UNCONFIGURED
        self._zeroize(k, dirty=off or not was_unconfigured)
        return "cleared"

    def clearall(self):
        """kl.clearall  (<<KLEE-instruction-clearall>>)."""
        self._pre()
        for k in range(32):
            off = self._off_gate(k, exempt=True)
            was_unconfigured = self.cls[k].mdh["State"] == ST_UNCONFIGURED
            self._zeroize(k, dirty=off or not was_unconfigured)
        self.kliobuf = bytearray()
        self.kliobuflen = self.kliobuftop = self.klstart = 0
        self.siv = self.impqual = self.siv2 = 0
        self.klmanagedcr = MANAGEDCL_NONE
        return "cleared all"

    def _usage_gate(self, k, forbidden_sub=False, needs_buf=False):
        """Rule SGR19, conditions 1-7, for one CL."""
        cl = self.cls[k]
        st = cl.mdh["State"]
        if st == ST_UNCONFIGURED:
            raise Trap("illegal", 2, note="SGR12: usage of an Unconfigured CL")
        if st in ERROR_STATES:
            return "noop"
        if st in PARTIAL_STATES:
            return self._exc_cl(k, "privilege_violation")
        if forbidden_sub:
            raise Trap("illegal", 2, note="forbidden KLIOBUF substitution")
        if not self.usage_allowed(cl.mdh):
            return self._exc_cl(k, "privilege_violation")
        if self.expired(cl.mdh):
            self._enter_error(k, ST_EXPIRED)
            return "expired"
        if needs_buf and self.kliobuflen == 0:
            raise self._exc_trap("unconfigured_buffer")
        return None

    # ------------------------------------------------------------ kl.exec
    def exec_(self, k, form="A", vin=None, vout=None, sew=8, halt_after=None):
        """kl.exec  (<<KLEE-instruction-exec>>).  Vector operands are bytearrays of
        VL * SEW/8 bytes, and may be the same object (Vd = Vs2)."""
        if form in ("A", "B", "C") and not self.zklv:
            raise Trap("illegal", 1, note="Forms A-C of kl.exec need Zklv")
        self._idx(k)
        self._pre()
        self._off_gate(k)
        nb = sew // 8
        if form in ("A", "B", "C") and self.klstart != self.vstart * nb:
            raise Trap("illegal", 2, note="klstart != vstart * SEW / 8")
        cl = self.cls[k]
        m = cl.mdh
        mach = MACHINES.get(m["Machine"])
        expected = mach.exec_form(m) if (mach and m["State"] in VALID_STATES) else None
        sub = form == "D" and expected in ("A", "B", "C")
        forbidden = (sub and not self.zklio) or (expected == "A" and form in ("B", "C"))

        def zero_output():                                  # SGR16
            if form in ("A", "C") and vout is not None:
                vout[self.vstart * nb:] = bytes(len(vout) - self.vstart * nb)
            elif form == "D" and self.zklio and self.kliobuflen:
                for i in range(self.klstart, self.kliobuftop):
                    self.kliobuf[i] = 0

        g = self._usage_gate(k, forbidden_sub=forbidden, needs_buf=sub)
        if g is not None:
            zero_output()
            self._retire()
            return g
        if expected is None or (form != "D" and form != expected):
            self._enter_error(k, ST_INVALID)                # SGR2, SGR5, MGR1
            zero_output()
            self._retire()
            return "invalid"
        if self.wants_ads(m) and m["AuxDataLen"] == 0:      # the ADS is regenerated on use
            m["AuxDataLen"] = ADS_BLOCKS
            cl.c2 = self.gen_ads(cl)
        has_in, has_out = expected in ("A", "B"), expected in ("A", "C")
        if sub:
            window, src, dst = self.kliobuftop, self.kliobuf, self.kliobuf
        else:
            window = len(vin if vin is not None else vout)
            src, dst = vin, vout
        gran = mach.granularity(m)
        ks = self.klstart
        if window % gran or ks % gran or ks > window:
            if has_in:
                self._enter_error(k, ST_INVALID)
                zero_output()
                self._retire()
                return "invalid"
            return "noop"                                   # output only: no state change
        if ks >= window:
            return "empty"
        j, done = ks, 0
        while j < window:
            if halt_after is not None and done >= halt_after:
                self.klstart = j
                self.vstart = j // nb
                self._dirty(k)
                return "halted"
            unit_out = mach.process(self, cl, bytes(src[j:j + gran]) if has_in else None)
            if has_out:
                dst[j:j + gran] = unit_out
            j += gran
            done += gran
        self._dirty(k)
        self._retire()
        return "done"

    # ------------------------------------------------------------ kl.restrict*
    def restrict(self, k, x, which="v", vec_bits=128):
        """kl.restrictl ('l'), kl.restricth ('h'), kl.restrictv ('v')."""
        if which == "v":
            if not self.zklv:
                raise Trap("illegal", 1)
            if vec_bits < 128:
                raise Trap("illegal", 1, note="GR7")
        self._idx(k)
        self._pre()
        self._off_gate(k)
        cl = self.cls[k]
        m = cl.mdh
        st = m["State"]
        if st == ST_UNCONFIGURED:
            return "noop"
        if st in PARTIAL_STATES:
            return self._exc_cl(k, "privilege_violation")
        xv = x if isinstance(x, int) else mdh_pack(x)
        if which == "l":
            xv &= MASK64
        elif which == "h":
            xv &= MASK128 & ~MASK64
        xs = mdh_unpack(xv)
        mach = MACHINES.get(m["Machine"])
        new = dict(m)
        bad = []
        named = {"l": ("MachinePolicy", "SCProtection"),
                 "h": ("Locality", "UsagePolicy", "ExpirationDate"),
                 "v": ("MachinePolicy", "SCProtection", "Locality", "UsagePolicy",
                       "ExpirationDate")}[which]
        for name, _, _, _ in MDH_FIELDS:
            if name not in named and xs[name]:
                bad.append(f"non-zero unnamed field {name}")
        req = xs["MachinePolicy"]
        if req:
            if mach is None or mach.kind == "ext":
                bad.append("MachinePolicy not a permission mask")
            elif req & ~m["MachinePolicy"]:
                bad.append("MachinePolicy would enable a function")
            elif req not in mach.policies:
                bad.append("MachinePolicy invalid for the Machine")
            elif st in mach.op_states and not req & mach.op_states[st]:
                bad.append("MachinePolicy disables the current State's operation")
            else:
                new["MachinePolicy"] = req
        req = xs["SCProtection"]
        if req:
            if mach is None or req not in mach.sc_levels:
                bad.append("SCProtection unsupported")
            elif sc_rank(req) < sc_rank(m["SCProtection"]):
                bad.append("SCProtection weaker")
            else:
                new["SCProtection"] = req
        req = xs["Locality"]
        if req:
            cur = newloc = m["Locality"]
            for name, hi, lo in LOC_SUBFIELDS:
                rv, cv = sl(req, hi, lo), sl(cur, hi, lo)
                if rv == 0 or rv == cv:
                    continue
                if cv == 0 or (name in ("hw1", "hw2") and rv > cv):
                    newloc = set_bits(newloc, hi, lo, rv)
                else:
                    bad.append(f"Locality {name} change")
            if newloc != cur:
                p = self.locality_problem(newloc)
                if p:
                    bad.append(p)
                new["Locality"] = newloc
        if (new["SCProtection"], new["Locality"]) != (m["SCProtection"], m["Locality"]):
            if carries_custom_value(new) and sl(new["Locality"], 1, 0) not in (2, 3):
                bad.append("GR10")
        req = xs["UsagePolicy"]
        if req:
            new["UsagePolicy"] = apply_usagepolicy_restriction(m["UsagePolicy"], req)
        req = xs["ExpirationDate"]
        if req:
            if not self.zklexpire:
                bad.append("ExpirationDate without Zklexpire")
            elif m["ExpirationDate"] == 0 or req <= m["ExpirationDate"]:
                new["ExpirationDate"] = req
            else:
                bad.append("ExpirationDate later")
        if bad:
            self._enter_error(k, ST_INVALID)
            return "invalid"
        if st not in ERROR_STATES:
            extra = mach.clf_capacity(new) - cl.alloc
            if extra > self.clf_free():
                return self._exc_cl(k, "out_of_memory")
            cl.alloc += max(0, extra)
        m.update(new)
        self._dirty(k)
        return "ok"

    # ------------------------------------------------------------ kl.clone
    def clone(self, kd, ks):
        """kl.clone  (<<KLEE-instruction-clone>>)."""
        self._idx(kd)
        self._idx(ks)
        self._pre()
        if kd == ks:
            return "noop"
        self._off_gate(ks)
        self._off_gate(kd, exempt=True)
        src = self.cls[ks]
        if src.mdh["State"] == ST_UNCONFIGURED:
            raise Trap("illegal", 2, note="kl.clone from an Unconfigured CL")
        if src.mdh["State"] in PARTIAL_STATES:
            return self._exc_cl(ks, "privilege_violation")
        if src.alloc > self.clf_free() + self.cls[kd].alloc:
            return self._exc_cl(kd, "out_of_memory")
        self._zeroize(kd)
        dst = self.cls[kd]
        dst.mdh = dict(src.mdh)
        dst.c1, dst.c2, dst.alloc = src.c1, src.c2, src.alloc
        return "cloned"

    # ------------------------------------------------------------ kl.derive
    PAIRS = {(M_XOF, M_CIPHER): ("key", 32), (M_XOF, M_XOF): ("absorb", 0)}

    def derive(self, kd, ks, length):
        """The generic part of kl.derive  (<<KLEE-instruction-derive>>), for two
        toy endpoint pairs: a XOF output into a cipher key field (minimum 32
        bytes), and a XOF output absorbed by another XOF (minimum 0)."""
        if kd == ks:
            raise Trap("illegal", 1, note="kl.derive with equal CL indices")
        self._idx(kd)
        self._idx(ks)
        self._pre()
        self._off_gate(ks)
        self._off_gate(kd)
        ends = (ks, kd)
        for e in ends:
            if self.cls[e].mdh["State"] == ST_UNCONFIGURED:
                raise Trap("illegal", 2, note="kl.derive with an Unconfigured endpoint")
        if any(self.cls[e].mdh["State"] in ERROR_STATES for e in ends):
            return "noop"
        for e in ends:
            if self.cls[e].mdh["State"] in PARTIAL_STATES:
                return self._exc_cl(e, "privilege_violation")
        for e in ends:
            if not self.usage_allowed(self.cls[e].mdh):
                return self._exc_cl(e, "privilege_violation")
        exp = [e for e in ends if self.expired(self.cls[e].mdh)]
        for e in exp:
            self._enter_error(e, ST_EXPIRED)
        if exp:
            return "expired"
        S, D = self.cls[ks].mdh, self.cls[kd].mdh
        pair = self.PAIRS.get((S["Machine"], D["Machine"]))
        src_ok = S["Machine"] == M_XOF and S["State"] == ST_SUCCESS
        if pair and pair[0] == "key":
            dst_ok = D["State"] == ST_READY
        elif pair:
            dst_ok = D["State"] in (ST_READY, ToyXof.ABSORB)
        else:
            dst_ok = D["State"] not in (ST_SUCCESS, ST_FAILURE)
        bad = [e for e, ok in ((ks, src_ok), (kd, dst_ok)) if not ok]
        if bad:
            for e in bad:
                self._enter_error(e, ST_INVALID)
            return "invalid"
        if pair is None:
            self._enter_error(ks, ST_INVALID)
            self._enter_error(kd, ST_INVALID)
            return "invalid"
        if pair[0] == "key" and D["KeyType"] == 1:
            self._enter_error(kd, ST_INVALID)
            return "invalid"
        eff = min(length, 32) if pair[0] == "key" else length
        if eff < pair[1]:
            self._enter_error(kd, ST_INVALID)
            return "invalid"
        if length == 0:
            return "nothing"
        xof = MACHINES[M_XOF]
        data = b"".join(xof.squeeze(self, self.cls[ks]) for _ in range(eff))
        dcl = self.cls[kd]
        if pair[0] == "key":
            dcl.c1 = data + bytes(32 - eff) + dcl.c1[32:]
        else:
            for b in data:
                xof.absorb(self, dcl, bytes([b]))
        self._dirty(ks)
        self._dirty(kd)
        return "transferred"

    # ------------------------------------------------------------ the image S
    def _s_block(self, k, j):
        cl = self.cls[k]
        off, _, _, _, iend = self.layout(cl.mdh)
        if j >= iend:
            return bytes(16)
        if j < off:
            return v2b((self.siv, self.impqual, self.siv2)[j // 16], 16)
        blk = bytes(cl.img[j - off:j - off + 16])
        return blk + bytes(16 - len(blk))

    def _s_put(self, k, j, blk):
        cl = self.cls[k]
        off, _, _, _, iend = self.layout(cl.mdh)
        if j >= iend:
            return
        if j < off:
            v = b2v(bytes(blk))
            if j == 0:
                self.siv = v
            elif j == 16:
                self.impqual = v
            else:
                self.siv2 = v
            return
        cl.img[j - off:j - off + 16] = bytes(blk)

    def _transfer_state(self, k, writing):
        st = self.cls[k].mdh["State"]
        ok = (CFG_PROVISIONING, CFG_IMPORTING, CFG_PPI_IMPORTING) if writing \
            else (CFG_EXPORTING, CFG_PPI_EXPORTING)
        if st not in ok or self.klstart % 16:
            raise Trap("illegal", 2, note="SGR21/SGR22, or klstart not a multiple of 16")

    # ------------------------------------------------------------ kl.load / kl.store
    def load(self, k, mem, addr, halt_after=None, restart=False):
        """kl.load  (<<KLEE-instruction-load>>)."""
        if not self.zklmem_hw:
            raise Trap("illegal", 1, note="kl.load is emulated (trap-and-emulate)")
        self._idx(k)
        self._pre()
        self._off_gate(k)
        self._transfer_state(k, writing=True)
        if addr % 16:
            raise Trap("load_misaligned", tval=addr)
        _, _, _, _, iend = self.layout(self.cls[k].mdh)
        j, moved = self.klstart, 0
        while j < iend:
            f = mem.fault(addr + j, 16, "load")
            if (halt_after is not None and moved >= halt_after) or f:
                self.klstart = 0 if restart else j
                if moved:
                    self._dirty(k)
                if f:
                    raise Trap(f[0], tval=f[1])
                return "halted"
            self._s_put(k, j, mem.read(addr + j, 16))
            mem.accesses += 1
            j += 16
            moved += 16
        self._dirty(k)
        self.klstart = 0
        return "done"

    def store(self, k, mem, addr, halt_after=None, restart=False):
        """kl.store  (<<KLEE-instruction-store>>)."""
        if not self.zklmem_hw:
            raise Trap("illegal", 1, note="kl.store is emulated (trap-and-emulate)")
        self._idx(k)
        self._pre()
        self._off_gate(k)
        self._transfer_state(k, writing=False)
        if addr % 16:
            raise Trap("store_misaligned", tval=addr)
        _, _, _, isize, _ = self.layout(self.cls[k].mdh)
        j, moved = self.klstart, 0
        while j < isize:
            f = mem.fault(addr + j, 16, "store")
            if (halt_after is not None and moved >= halt_after) or f:
                self.klstart = 0 if restart else j
                if f:
                    raise Trap(f[0], tval=f[1])
                return "halted"
            mem.write(addr + j, self._s_block(k, j))       # zero at or beyond image_end
            mem.accesses += 1
            j += 16
            moved += 16
        self.klstart = 0
        return "done"

    # ------------------------------------------------------------ kl.mv
    def _mv_pre(self, k, writing, vec_len=None, sew=8):
        if not self.zklmv or (vec_len is not None and not self.zklv):
            raise Trap("illegal", 1, note="kl.mv needs Zklmv (and Zklv for a vector)")
        if vec_len is not None and (vec_len % 16 or (self.vstart * (sew // 8)) % 16):
            raise Trap("illegal", 1, note="vl or vstart is not a multiple of 16 bytes")
        self._idx(k)
        self._pre()
        self._off_gate(k)
        self._transfer_state(k, writing)
        return self.layout(self.cls[k].mdh)[4]

    def mv_in(self, k, value):
        """kl.mv Kd, Xs2."""
        iend = self._mv_pre(k, True)
        if self.klstart >= iend:
            return "nothing"
        self._s_put(k, self.klstart, v2b(value, 16))
        self.klstart += 16
        self._dirty(k)
        return "moved"

    def mv_out(self, k):
        """kl.mv Xd, Ks1."""
        iend = self._mv_pre(k, False)
        if self.klstart >= iend:
            return 0
        v = b2v(self._s_block(k, self.klstart))
        self.klstart += 16
        return v

    def mv_in_vec(self, k, vec, sew=8, halt_after=None):
        """kl.mv Kd, Vs2."""
        iend = self._mv_pre(k, True, len(vec), sew)
        nb = sew // 8
        if self.vstart >= len(vec) // nb:
            return "noop"
        if self.klstart >= iend:
            self.vstart = 0
            return "nothing"
        j, pos, moved = self.klstart, self.vstart * nb, 0
        while pos < len(vec):
            if halt_after is not None and moved >= halt_after:
                self.klstart, self.vstart = j, pos // nb
                self._dirty(k)
                return "halted"
            if j < iend:
                self._s_put(k, j, vec[pos:pos + 16])
                j += 16
            pos += 16
            moved += 16
        self.klstart = j
        self.vstart = 0
        self._dirty(k)
        return "moved"

    def mv_out_vec(self, k, vd, sew=8, halt_after=None):
        """kl.mv Vd, Ks1: writes elements vstart .. vl-1 of `vd`."""
        iend = self._mv_pre(k, False, len(vd), sew)
        nb = sew // 8
        if self.vstart >= len(vd) // nb:
            return "noop"
        j, pos, moved = self.klstart, self.vstart * nb, 0
        if j >= iend:
            vd[pos:] = bytes(len(vd) - pos)
            self.vstart = 0
            return "zeros"
        while pos < len(vd):
            if halt_after is not None and moved >= halt_after:
                self.klstart, self.vstart = j, pos // nb
                return "halted"
            if j < iend:
                vd[pos:pos + 16] = self._s_block(k, j)
                j += 16
            else:
                vd[pos:pos + 16] = bytes(16)
            pos += 16
            moved += 16
        self.klstart = j
        self.vstart = 0
        return "moved"

    # ------------------------------------------------------------ KLIOBUF
    def _io_pre(self):
        if not self.zklio:
            raise Trap("illegal", 1, note="kl.input/kl.output need Zklio")
        self._pre()
        if self.kliobuflen == 0:
            raise self._exc_trap("unconfigured_buffer")

    def input_(self, mem, addr, xl, halt_after=None, restart=False):
        """kl.input  (<<KLEE-iobuf-transfer-window>>)."""
        self._io_pre()
        end = min(xl, self.kliobuftop)
        if xl == 0 or self.klstart >= end:
            return "empty"
        j, moved = self.klstart, 0
        while j < end:
            f = mem.fault(addr + j, 1, "load")
            if (halt_after is not None and moved >= halt_after) or f:
                self.klstart = 0 if restart else j
                if f:
                    raise Trap(f[0], tval=f[1])
                return "halted"
            self.kliobuf[j] = mem.buf[addr + j]
            j += 1
            moved += 1
        self.klstart = 0
        return "done"

    def output(self, mem, addr, xl, halt_after=None, restart=False):
        """kl.output  (<<KLEE-iobuf-transfer-window>>)."""
        self._io_pre()
        end = min(xl, self.kliobuftop)
        if xl == 0 or self.klstart >= end:
            return "empty"
        j, moved = self.klstart, 0
        while j < end:
            f = mem.fault(addr + j, 1, "store")
            if (halt_after is not None and moved >= halt_after) or f:
                self.klstart = 0 if restart else j
                if f:
                    raise Trap(f[0], tval=f[1])
                return "halted"
            mem.buf[addr + j] = self.kliobuf[j]
            j += 1
            moved += 1
        self.klstart = 0
        return "done"


# =====================================================================
# software sequences  --  <<KLEE-management-operations>>
# =====================================================================

def fresh(hw_missing=(), **kw):
    u = Unit(**kw)
    for j in hw_missing:
        u.hw.pop(j, None)
    return u


def cipher_pi(**kw):
    base = dict(Machine=M_CIPHER, MachinePolicy=0b11)
    base.update(kw)
    return mdh_new(**base)


def xof_pi(**kw):
    base = dict(Machine=M_XOF, MachinePolicy=0)
    base.update(kw)
    return mdh_new(**base)


def sig_pi(**kw):
    base = dict(Machine=M_SIG, MachinePolicy=0b11)
    base.update(kw)
    return mdh_new(**base)


def pi_content(m, seed=0x31):
    n = MACHINES[m["Machine"]].pi_content_size(m)
    return bytes((seed + 7 * i) & 0xFF for i in range(n))


def skid_content(skid):
    return v2b(skid, 16)


def provision(u, k, m, content=None, via="load", form="D", done_form="A"):
    """Provisioning: open, load the PI Content, complete."""
    content = pi_content(m) if content is None else content
    u.mgmt(k, CFG_PROVISIONING, m, form=form)
    if u.cls[k].mdh["State"] != CFG_PROVISIONING:
        return u.cls[k].mdh["State"]
    if via == "load":
        mem = Memory()
        mem.write(BASE, content)
        u.load(k, mem, BASE)
    elif via == "mv":
        for off in range(0, len(content), 16):
            u.mv_in(k, b2v(content[off:off + 16]))
    else:
        u.vstart = 0
        u.mv_in_vec(k, bytearray(content), sew=32)
    u.mgmt(k, CFG_MANAGEMENT_END, form=done_form)
    return u.cls[k].mdh["State"]


def export(u, k, via="store", form="D"):
    """Export: the MDH, then the rest of the image; the short path for an Error
    State (<<KLEE-error-state-transfer>>).  Returns the external image."""
    md = u.getmd(k)
    n = u.size(k=k)
    img = bytearray(n)
    img[0:16] = mdh_bytes(md)
    if md["State"] in ERROR_STATES:
        return bytes(img)
    u.mgmt(k, CFG_EXPORTING)
    if via == "store":
        mem = Memory()
        u.store(k, mem, BASE)
        img[16:] = mem.read(BASE, n - 16)
    else:
        for off in range(16, n, 16):
            img[off:off + 16] = v2b(u.mv_out(k), 16)
    if form == "A":
        u.kliobuf[0:16] = mdh_bytes(md)
    u.mgmt(k, CFG_MANAGEMENT_END, md, form=form)
    return bytes(img)


def import_(u, k, img, via="load", form="D", halt_after=None):
    """Import of an SCC, a PCCC or an Error-State MDH."""
    md = mdh_unpack(b2v(img[0:16]))
    if form == "A":
        u.kliobuf[0:16] = img[0:16]
    u.mgmt(k, CFG_IMPORTING, md, form=form)
    if u.cls[k].mdh["State"] not in CONFIG_STATES:
        return u.cls[k].mdh["State"]
    if via == "load":
        mem = Memory()
        mem.write(BASE, img[16:])
        r = u.load(k, mem, BASE, halt_after=halt_after)
        if r == "halted":
            return "halted"
    else:
        for off in range(16, len(img), 16):
            u.mv_in(k, b2v(img[off:off + 16]))
    u.mgmt(k, CFG_MANAGEMENT_END, md, form=form)
    return u.cls[k].mdh["State"]


def snapshot(u):
    return (tuple(mdh_pack(c.mdh) for c in u.cls),
            tuple((c.c1, c.c2, None if c.img is None else bytes(c.img), c.alloc) for c in u.cls),
            u.siv, u.impqual, u.siv2, u.klstart, u.klmanagedcr,
            u.kliobuflen, u.kliobuftop, bytes(u.kliobuf))


def cl_consistent(u, k):
    """For a CL in a Valid State, the plaintext has the length the length rule gives."""
    c = u.cls[k]
    m = c.mdh
    mach = MACHINES[m["Machine"]]
    return len(c.c1) == mach.content1_size(m) and len(c.c2) == content2_size(m)


def ready_cipher(u, k, **kw):
    """A provisioned cipher CL in State ENCRYPT.  A _UsagePolicy_ is applied with
    kl.restricth afterwards, so that the kl.setst itself is not gated by it."""
    up = kw.pop("UsagePolicy", 0)
    provision(u, k, cipher_pi(**kw))
    u.setst(k, ToyCipher.ENCRYPT, 0x77)
    if up:
        u.restrict(k, mdh_new(UsagePolicy=up), "h")
    return u


# =====================================================================
# 1. MDH layout
# =====================================================================

def test_mdh_layout():
    section("1.  MDH layout  --  <<KLEE-metadata-header>>")

    total = sum(hi - lo + 1 for _, hi, lo, _ in MDH_FIELDS)
    check("the MDH fields tile 128 bits", total, 128)
    covered = overlap = 0
    for _, hi, lo, _ in MDH_FIELDS:
        mask = ((1 << (hi - lo + 1)) - 1) << lo
        overlap |= covered & mask
        covered |= mask
    check("no two MDH fields overlap", overlap, 0)
    check("the MDH fields cover [127:0]", covered, MASK128)

    ok_walk = ok_iso = True
    for name, hi, lo, _ in MDH_FIELDS:
        for b in range(hi - lo + 1):
            v = mdh_pack(mdh_new(**{name: 1 << b}))
            ok_walk &= v == 1 << (lo + b)
            u = mdh_unpack(v)
            ok_walk &= u[name] == 1 << b
            ok_iso &= not any(u[o] for o in u if o != name)
    check_true("walking ones: every field bit packs to its tabulated position", ok_walk)
    check_true("walking ones: no field bleeds into another", ok_iso)
    ones = mdh_new(**{n: (1 << (h - l + 1)) - 1 for n, h, l, _ in MDH_FIELDS})
    check("all-ones fields pack to ones(128)", mdh_pack(ones), MASK128)
    check("an all-ones MDH round trips", mdh_unpack(mdh_pack(ones)), ones)

    for name, hi, lo, res in MDH_FIELDS:
        if res:
            bad = mdh_unpack(1 << hi)
            check_true(f"reserved bit {hi} ({name}) is detected", not reserved_bits_zero(bad))
    check_true("a reserved bit in [127:64] is not examined by a check on bits [63:0]",
               reserved_bits_zero(mdh_unpack(1 << 116), low_only=True))

    # statements elsewhere in the text that pin the layout independently
    check("_Machine_, _MachinePolicy_ and _MachineExtension_ form the 16-bit identifier "
          "[15:0] (<<KLEE-concepts>>)",
          (fwidth("Machine") + fwidth("MachinePolicy") + fwidth("MachineExtension"),
           FIELD["MachineExtension"][1]), (16, 15))
    u = fresh()
    ones_st = dict(ones, State=ST_INVALID)
    u.mgmt(4, CFG_IMPORTING, ones_st)          # the short import installs the MDH as given
    check("kl.getst's expansion (kl.getmdl; srli 19; andi 0x3F) extracts _State_",
          u.getst(4), ST_INVALID)
    check("kl.getstx's expansion (kl.getmdl; srli 25; andi 0x0F) extracts _StateExtension_",
          u.getstx(4), 0xF)
    check("kl.getmdl returns MDH[63:0]", u.getmdl(4), sl(mdh_pack(u.getmd(4)), 63, 0))
    check("_ADSDropped_ is bit 47, the bit SCC_Encrypt clears in AD_auth[0][47]",
          FIELD["ADSDropped"][1:3], (47, 47))
    check_true("every field the length rule and kl.size name lies in MDH[63:0]",
               all(FIELD[f][1] <= 63 for f in ("Machine", "MachinePolicy", "MachineExtension",
                                               "KeyType", "StateExtension", "AuxDataLen",
                                               "ADSDropped", "SCProtection", "State")))
    years, rem = divmod(2 ** fwidth("ExpirationDate") / 24, 365.2425)
    check("20-bit _ExpirationDate_: 'approximately 119 years and 7 months'",
          (int(years), int(rem / (365.2425 / 12))), (119, 7))
    check("14-bit _AuxDataLen_: 'maximum 2^14-1, corresponding to 262,128 bytes'",
          16 * ((1 << fwidth("AuxDataLen")) - 1), 262128)
    check("_Locality_ holds [1:0], [3:2], [5:4] and bits 6, 7, 8",
          (fwidth("Locality"), max(h for _, h, _ in LOC_SUBFIELDS)), (9, 8))
    check("_UsagePolicy_ has bits 0-4", fwidth("UsagePolicy"), 5)
    check("_Version_ is [127:126]", FIELD["Version"][1:3], (127, 126))
    check("kl.getmd* of an Unconfigured CL returns an all-zero MDH (SGR13)",
          mdh_pack(u.getmd(0)), 0)
    check("mdh_bytes is the little-endian image (common.v2b)",
          mdh_bytes(mdh_new(Machine=0x123)).hex(), v2b(0x123, 16).hex())
    check("b2v inverts mdh_bytes", b2v(mdh_bytes(ones_st)), mdh_pack(ones_st))
    check("bin(n, m) agrees with the 6-bit _State_ encoding",
          bin_(CFG_MANAGEMENT_END + 1, fwidth("State")), 0)


# =====================================================================
# 2. States
# =====================================================================

def test_states():
    section("2.  States  --  <<KLEE-State-field>>, <<KLEE-SC-sealing-status>>")

    everything = set(range(1 << fwidth("State")))
    parts = [{0}, set(VALID_STATES), set(ERROR_STATES), set(PARTIAL_STATES)]
    check("Unconfigured, Valid, Error and Partial States partition the 6-bit _State_",
          (sum(len(p) for p in parts), set().union(*parts)), (64, everything))
    check("Complete = 1-55 = Valid + Error", set(COMPLETE_STATES),
          set(VALID_STATES) | set(ERROR_STATES))
    check("the Partial States are exactly those neither Unconfigured nor Complete",
          set(PARTIAL_STATES), everything - {0} - set(COMPLETE_STATES))
    check("Ready 1, Success 46, Failure 47", (ST_READY, ST_SUCCESS, ST_FAILURE), (1, 46, 47))
    check("Error States 48-53 in decreasing severity, 54-55 reserved",
          [ST_UNSUPPORTED, ST_INVALID, ST_OUT_OF_MEMORY, ST_MGMT_AUTH, ST_PRIV_VIOLATION,
           ST_EXPIRED], list(range(48, 54)))
    check("Configuration States 56-60 carry base types pi/scc/scc/pi/pi",
          [BASE_TYPE[s] for s in sorted(CONFIG_STATES)], ["pi", "scc", "scc", "pi", "pi"])
    check_true("the Configuration States are Partial States", CONFIG_STATES <= PARTIAL_STATES)

    # kl.setst immediate categories
    cats = {}
    for imm in range(128):
        if (imm >> 3) == 0b0111:
            c = "kl.mgmt"
        elif imm == 0:
            c = "clear"
        elif imm in (46, 47):
            c = "reserved"
        elif 1 <= imm <= 45:
            c = "valid"
        elif 48 <= imm <= 55:
            c = "error"
        elif imm == 64:
            c = "clear_ads"
        else:
            c = "machine"
        cats.setdefault(c, []).append(imm)
    check("#immed7[6:3] = 0b0111 is exactly 56-63 (kl.mgmt)", cats["kl.mgmt"], list(range(56, 64)))
    check("65-127 are Machine-defined immediates", cats["machine"], list(range(65, 128)))
    check("the kl.mgmt immediates are 56, 57, 58 and 63; the others are reserved",
          [i for i in range(56, 64) if trap_of(fresh().mgmt, 0, i, mdh_new()) != "illegal/1"],
          [56, 57, 58, 63])
    u = fresh()
    check("kl.setst #46 is a reserved encoding (SGR7), even on an Unconfigured CL",
          (trap_of(u.setst, 0, 46), trap_of(u.setst, 0, 47)), ("illegal/1", "illegal/1"))

    # the State tests of the Pseudocode chapter snippets (<<KLEE-management-code-snippets>>, informative)
    andi = {s for s in everything if (s & 0x38) == 0x30}
    check("the Pseudocode chapter test 'andi 0x38; beq 0x30' is true exactly on the Error States",
          andi, set(ERROR_STATES))
    bltu = {s for s in everything if 0x30 < s}
    missed = sorted(set(ERROR_STATES) - bltu)
    extra = sorted(bltu - set(ERROR_STATES))
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    mem = Memory()
    mem.write(BASE, pi_content(cipher_pi()))
    u.load(0, mem, BASE)
    after_load = u.getst(0)
    ms = mdh_new(Machine=M_CIPHER, MachinePolicy=0b11)
    w = fresh()
    ready_cipher(w, 1)
    w.setst(1, ST_INVALID)
    end_on_error = trap_of(w.mgmt, 1, CFG_MANAGEMENT_END, ms)
    spec_note("<<KLEE-management-code-snippets>> (informative, marked as being rewritten): the "
              f"error test 'bltu t3, t2' with t3 = 0x30 is true for States {extra[0]}-{extra[-1]} "
              f"and misses State {missed[0]}; after kl.load the State is a Configuration State "
              f"({after_load}), so the Zklmem provisioning snippet always branches to 'finished' "
              "without completing, and the Zklmem import and export snippets always branch to "
              "handle_errors. The 'andi 0x38; beq 0x30' test is correct and should replace it.")
    spec_note("<<KLEE-management-code-snippets>>: the Zklmv export snippet jumps to 'finished' "
              "for an Error-State CL (kl.size = 16) and then issues kl_cfg_management_end, which "
              f"raises {end_on_error} on a CL with no management operation open; the Zklmem "
              "export shares a prefix that never sets t3; the Zklmv import subtracts 16 from s1 "
              "again at every jump to 'restart'. The ECB example (<<KLEE-ECB-mode-example>>) still "
              "tests 'X1 >= 24', the Error-State threshold of the old numbering, which now "
              "flags Success and Failure as errors.")


# =====================================================================
# 3. Metadata validity
# =====================================================================

def test_validity():
    section("3.  Metadata validity  --  <<KLEE-Metadata-validity>>, <<KLEE-MVR-open>>")

    good = cipher_pi()
    cases = [
        ("a Reserved bit", dict(Reserved46=1)),
        ("AuxDataLen = 1", dict(AuxDataLen=1)),
        ("ADSDropped in a PI", dict(ADSDropped=1)),
        ("MachinePolicy zero for a Machine that requires a bit", dict(MachinePolicy=0)),
        ("KeyType 2", dict(KeyType=2)),
        ("KeyType 3", dict(KeyType=3)),
        ("Locality[5:4] = 3", dict(Locality=loc(boot=3))),
        ("AuxInfo for a Machine that does not use it", dict(AuxInfo=5)),
        ("unsupported Version 1", dict(Version=1)),
        ("reserved Version 2", dict(Version=2)),
        ("system-specific Version 3, not supported here", dict(Version=3, Locality=loc(hw1=3))),
        ("custom SCProtection without ChipFamScrt/ChipScrt (GR10)", dict(SCProtection=6)),
        ("AuxDataLen non-zero in a PI", dict(AuxDataLen=2)),
        ("State not Unconfigured at provisioning", dict(State=ST_READY)),
        ("a reserved bit in [127:64]", dict(Reserved116=1)),
    ]
    for label, kw in cases:
        u = fresh()
        ready_cipher(u, 3)
        u.csr_write("klstart", 16)
        r = u.mgmt(3, CFG_PROVISIONING, cipher_pi(**kw))
        check(f"provisioning with invalid Metadata ({label}) -> Error State Invalid, "
              "other MDH fields zero, no CLF capacity",
              (r, mdh_pack(u.getmd(3)), u.cls[3].alloc, u.klmanagedcr, u.klstart),
              ("invalid", mdh_pack(mdh_new(State=ST_INVALID)), 0, MANAGEDCL_NONE, 0))
    u = fresh(zklexpire=False)
    check("provisioning with a non-zero ExpirationDate without Zklexpire -> Invalid",
          (u.mgmt(0, CFG_PROVISIONING, cipher_pi(ExpirationDate=9)), u.getst(0)),
          ("invalid", ST_INVALID))
    u = fresh(hw_missing=(0, 1, 2))
    check("provisioning naming an unresolvable Locality -> Invalid at the opening",
          (u.mgmt(0, CFG_PROVISIONING, cipher_pi(Locality=loc(hw1=1))), u.getst(0)),
          ("invalid", ST_INVALID))
    u = fresh()
    check("custom SCProtection naming ChipFamScrt is valid (GR10)",
          provision(u, 0, cipher_pi(SCProtection=6, Locality=loc(hw1=2))), ST_READY)
    check("a custom Machine naming ChipScrt is valid (GR10)",
          provision(u, 1, mdh_new(Machine=M_CUSTOM, MachinePolicy=1, Locality=loc(hw1=3))),
          ST_READY)
    check("a custom Machine naming only SiPScrt is invalid, even when SiPScrt is substituted",
          provision(fresh(hw_missing=(0,)), 1,
                    mdh_new(Machine=M_CUSTOM, MachinePolicy=1, Locality=loc(hw1=1))),
          ST_INVALID)
    check("AuxInfo is accepted for a Machine that uses it",
          provision(u, 2, sig_pi(AuxInfo=5)), ST_READY)
    check("both signature bits may be zero",
          provision(u, 3, sig_pi(MachinePolicy=0)), ST_READY)

    # unsupported Metadata raises before any invalidity is considered
    for label, m in (("an unimplemented Machine", mdh_new(Machine=M_ABSENT, MachinePolicy=1)),
                     ("a non-zero MachineExtension", cipher_pi(MachineExtension=1)),
                     ("an unimplemented SCProtection", cipher_pi(SCProtection=3)),
                     ("an unimplemented MachinePolicy variant", xof_pi(MachinePolicy=2)),
                     ("unsupported and also invalid (State != 0)",
                      mdh_new(Machine=M_ABSENT, State=5))):
        u = fresh()
        ready_cipher(u, 5)
        u.csr_write("klstart", 32)
        t = trap_of(u.mgmt, 5, CFG_PROVISIONING, m)
        check(f"provisioning {label} raises kl_exc_unsupported and leaves the CL "
              "Unconfigured (zeroized); klstart unchanged",
              (t, mdh_pack(u.getmd(5)), u.klstart), ("unsupported", 0, 32))
    u = fresh()
    check("importing an unsupported MDH raises kl_exc_unsupported",
          trap_of(u.mgmt, 0, CFG_IMPORTING, mdh_new(Machine=M_ABSENT, State=2)), "unsupported")

    # import-specific State rules
    for st, label in ((0, "Unconfigured"), (61, "61"), (62, "62"), (63, "63")):
        u = fresh()
        check(f"import with ml.State {label} -> Invalid",
              (u.mgmt(0, CFG_IMPORTING, cipher_pi(State=st)), u.getst(0)), ("invalid", ST_INVALID))
    for st in (1, 7, 45, 46, 47, 56, 57, 58, 59, 60):
        u = fresh()
        check(f"import with ml.State {st} opens",
              u.mgmt(0, CFG_IMPORTING, cipher_pi(State=st)), "opened")
    u = fresh()
    check("an SCC MDH may carry AuxDataLen >= 2 and ADSDropped at import",
          u.mgmt(0, CFG_IMPORTING, cipher_pi(State=2, AuxDataLen=4, ADSDropped=1)), "opened")
    for kw, label in ((dict(AuxDataLen=2), "AuxDataLen"), (dict(ADSDropped=1), "ADSDropped")):
        u = fresh()
        check(f"a PI-shaped PCCC (ml.State 56) with {label} set is invalid at import",
              u.mgmt(0, CFG_IMPORTING, cipher_pi(State=CFG_PROVISIONING, **kw)), "invalid")

    # the PI values of StateExtension and MachineUse are ignored
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi(StateExtension=0b1111, MachineUse=0xBEEF))
    check("provisioning replaces _StateExtension_ and _MachineUse_ with zero",
          (u.getmd(0)["StateExtension"], u.getmd(0)["MachineUse"], u.getst(0)),
          (0, 0, CFG_PROVISIONING))

    # insufficient CLF capacity
    need = MACHINES[M_CIPHER].clf_capacity(cipher_pi())
    u = fresh(clf_total=need - 1)
    u.csr_write("klmanagedcr", 0)
    check("insufficient CLF capacity raises kl_exc_out_of_memory; the CL stays Unconfigured; "
          "klmanagedcr is set to 32",
          (trap_of(u.mgmt, 0, CFG_PROVISIONING, cipher_pi()), u.getst(0), u.klmanagedcr),
          ("out_of_memory", 0, MANAGEDCL_NONE))
    u = fresh(clf_total=need)
    check("exactly enough CLF capacity suffices", provision(u, 0, cipher_pi()), ST_READY)
    check("an Error-State CL consumes no CLF capacity (SGR10)",
          (u.setst(0, ST_INVALID), u.cls[0].alloc, u.clf_free()), ("error state", 0, need))

    # the short import is exempt from every check
    u = fresh(zklexpire=False)
    odd = mdh_new(Machine=M_ABSENT, State=ST_EXPIRED, Reserved116=5, KeyType=3,
                  ExpirationDate=7, AuxDataLen=9, ADSDropped=1, Locality=loc(boot=3))
    check("the short import of an Error-State MDH applies none of the validity checks",
          (u.mgmt(0, CFG_IMPORTING, odd), u.getmd(0)),
          ("short import", dict(odd, AuxDataLen=0, ADSDropped=0)))


# =====================================================================
# 4. Length rule, kl.size, kl.avail
# =====================================================================

def test_lengths():
    section("4.  Length rule, kl.size, kl.avail  --  <<KLEE-length-rule>>, "
            "<<KLEE-instruction-size>>")

    u = fresh()
    cm = MACHINES[M_CIPHER]
    base = cipher_pi()
    # dependency sets
    for fld, val in (("SCProtection", 1), ("StateExtension", 1), ("MachineUse", 9),
                     ("UsagePolicy", 7), ("Locality", 2), ("ExpirationDate", 5),
                     ("AuxInfo", 3), ("State", 5), ("Version", 1)):
        check(f"PI Content length independent of {fld}",
              cm.pi_content_size(cipher_pi(**{fld: val})), cm.pi_content_size(base))
    check("PI Content length depends on KeyType",
          (cm.pi_content_size(base), cm.pi_content_size(cipher_pi(KeyType=1))), (32, 16))
    check("Content1 length depends on StateExtension",
          cm.content1_size(cipher_pi(StateExtension=1)) - cm.content1_size(base), 16)
    for fld, val in (("SCProtection", 1), ("MachineUse", 9), ("UsagePolicy", 7),
                     ("Locality", 2), ("ExpirationDate", 5), ("State", 9)):
        check(f"SCC length independent of {fld}",
              u.size_of(cipher_pi(State=2, AuxDataLen=4, **{fld: val}), supplied=True)
              if fld != "State" else
              u.size_of(cipher_pi(State=val, AuxDataLen=4), supplied=True),
              u.size_of(cipher_pi(State=2, AuxDataLen=4), supplied=True))
    for fld, val in (("KeyType", 1), ("StateExtension", 3), ("AuxDataLen", 7),
                     ("ADSDropped", 1), ("UsagePolicy", 15), ("ExpirationDate", 9)):
        check(f"CLF capacity independent of {fld}",
              cm.clf_capacity(cipher_pi(**{fld: val})), cm.clf_capacity(base))
    check_true("CLF capacity depends on SCProtection and MachinePolicy",
               cm.clf_capacity(cipher_pi(SCProtection=1)) != cm.clf_capacity(base)
               and cm.clf_capacity(cipher_pi(MachinePolicy=1)) != cm.clf_capacity(base))

    # kl.size, step by step
    c1 = cm.content1_size(cipher_pi(StateExtension=1))
    check("1: an Unconfigured CL -> 0", u.size(k=0), 0)
    check("2: an unsupported supplied MDH -> 0",
          u.size("C", md=mdh_new(Machine=M_ABSENT, MachinePolicy=1, State=2)), 0)
    check("2: an invalid supplied MDH -> 0", u.size("C", md=cipher_pi(State=2, KeyType=2)), 0)
    check("2: a supplied State 61-63 -> 0",
          [u.size("C", md=cipher_pi(State=s)) for s in (61, 62, 63)], [0, 0, 0])
    check("2: a supplied PI MDH with AuxDataLen set -> 0",
          u.size("C", md=cipher_pi(AuxDataLen=2)), 0)
    check("2: a supplied PI MDH with ADSDropped set -> 0",
          u.size("C", md=cipher_pi(ADSDropped=1)), 0)
    check("3: a supplied Error-State MDH -> 16, even if otherwise invalid or unsupported",
          [u.size("C", md=mdh_new(Machine=M_ABSENT, State=s, Reserved46=1)) for s in ERROR_STATES],
          [16] * 8)
    check("4: Valid, AuxDataLen = 0 -> 32 + content1_size",
          u.size("C", md=cipher_pi(State=2, StateExtension=1)), 32 + c1)
    check("4: Valid, AuxDataLen = 4 -> 64 + content1_size + 16 * (AuxDataLen - 2)",
          u.size("C", md=cipher_pi(State=2, StateExtension=1, AuxDataLen=4)), 64 + c1 + 32)
    check("4: ADSDropped = 1 removes Content2 but keeps the 64-byte fixed part",
          u.size("C", md=cipher_pi(State=2, StateExtension=1, AuxDataLen=4, ADSDropped=1)),
          64 + c1)
    check("4: kl_cfg_importing and kl_cfg_exporting take the SCC size",
          [u.size("C", md=cipher_pi(State=s, AuxDataLen=4)) for s in (57, 58)],
          [64 + 32 + 32] * 2)
    check("5: kl_cfg_provisioning and the ppi States take the PI size",
          [u.size("C", md=cipher_pi(State=s)) for s in (56, 59, 60)], [16 + 32] * 3)
    check("5: a supplied Unconfigured MDH (a PI) -> 16 + pi_content_size",
          (u.size("C", md=cipher_pi()), u.size("C", md=cipher_pi(KeyType=1))), (48, 32))
    check("a PI costs 16 bytes of header and an SCC 32 (the SIV)",
          u.size("C", md=cipher_pi(State=1)) - u.size("C", md=cipher_pi()), 16)
    # Form B examines only bits [63:0]
    unconf_loc = cipher_pi(State=2, Locality=loc(sloc=1))
    fb = fresh()
    fb.slocality = 0
    check("Form C applies the [127:64] conditions (unconfigured Locality -> 0)",
          fb.size("C", md=unconf_loc), 0)
    check("Form B does not examine [127:64] (same MDH -> the SCC size)",
          fb.size("B", lo=sl(mdh_pack(unconf_loc), 63, 0)), 32 + 32)
    gr10 = cipher_pi(State=2, SCProtection=6)
    check("Form B does not apply Rule GR10; Form C does",
          (fb.size("B", lo=mdh_pack(gr10)), fb.size("C", md=gr10)), (32 + 32, 0))
    check("Form B ignores a reserved bit above bit 63",
          fb.size("B", lo=mdh_pack(cipher_pi(State=2, Reserved116=1))), 32 + 32)
    check("Form C of kl.size needs a 128-bit vector operand (GR7)",
          trap_of(u.size, "C", md=cipher_pi(), vec_bits=64), "illegal/1")

    # image_size = kl.size - 16, and ContentOffset, in every Configuration State
    shapes = []
    for adl, dropped in ((0, 0), (4, 0), (4, 1), (6, 0)):
        for st in sorted(CONFIG_STATES):
            if BASE_TYPE[st] == "pi" and adl:
                continue
            m = cipher_pi(State=st, StateExtension=1, AuxDataLen=adl, ADSDropped=dropped)
            off, content, _, isize, iend = u.layout(m)
            shapes.append((st, adl, dropped, off, isize == u.size("C", md=m) - 16, iend == isize))
    check("image_size is kl.size - 16 and ContentOffset is 0 / 16 / 48 as tabulated",
          [(s[0], s[1], s[3], s[4]) for s in shapes],
          [(s[0], s[1], 0 if BASE_TYPE[s[0]] == "pi" else (16 if s[1] == 0 else 48), True)
           for s in shapes])
    check_true("image_end = image_size whenever AuxDataLen is within the maximum",
               all(s[5] for s in shapes))
    info("the Instructions chapter's own flows never reach image_end < image_size: an import whose "
         "_AuxDataLen_ exceeds the maximum sets _ADSDropped_ at the opening (step 5 of "
         "<<KLEE-SCC-import>>), so the zero-filled tail of kl.store is unobservable here.")

    # kl.avail
    a = fresh()
    check("kl.avail Form A of an Unconfigured CL -> 0", a.avail(k=0), 0)
    check("kl.avail of implemented combinations -> 1",
          [a.avail("C", md=m) for m in (cipher_pi(), cipher_pi(KeyType=1), xof_pi(MachinePolicy=1),
                                          sig_pi(MachinePolicy=0), cipher_pi(SCProtection=6))],
          [1] * 5)
    check("kl.avail of unimplemented combinations -> 0",
          [a.avail("C", md=m) for m in (cipher_pi(MachineExtension=2), cipher_pi(KeyType=2),
                                          cipher_pi(SCProtection=3), cipher_pi(MachinePolicy=0),
                                          xof_pi(MachinePolicy=3),
                                          mdh_new(Machine=M_ABSENT, MachinePolicy=1))],
          [0] * 6)
    check("kl.avail examines no other field (State, reserved bits, Locality, Version)",
          a.avail("C", md=cipher_pi(State=63, Reserved116=3, Locality=loc(boot=3), Version=2)), 1)
    check("kl.avail Form B uses bits [63:0]", a.avail("B", lo=mdh_pack(cipher_pi())), 1)
    provision(a, 0, cipher_pi())
    a.setst(0, ST_EXPIRED)
    a.mgmt(1, CFG_PROVISIONING, cipher_pi(KeyType=2))
    check("kl.avail Form A on an Error-State CL evaluates its retained identifying fields",
          (a.avail(k=0), a.avail(k=1)), (1, 0))
    check("kl.size of an Error-State CL is 16 (SGR11)", (a.size(k=0), a.size(k=1)), (16, 16))


# =====================================================================
# 5. UsagePolicy
# =====================================================================

def test_usage_policy():
    section("5.  _UsagePolicy_  --  <<KLEE-UsagePolicy>>")

    rows = []
    for up in range(32):
        for mode in ("U", "VU", "VS", "HS", "S", "M", "D"):
            u = fresh()
            u.mode = mode
            got = u.usage_allowed(cipher_pi(UsagePolicy=up))
            want = {"U": not up & 1, "VU": not up & 1, "VS": not up & 2, "HS": not up & 4,
                    "S": not up & 4, "M": not up & 8, "D": bool(up & 16)}[mode]
            rows.append((up, mode, got == bool(want)))
    check(f"the enforcement matrix over {len(rows)} (policy, mode) pairs",
          [r for r in rows if not r[2]], [])
    u = fresh()
    u.mode = "D"
    check_true("authenticated Debug: bits 0-3 are not evaluated",
               u.usage_allowed(cipher_pi(UsagePolicy=0b11111)))

    # enforced by usage-controlled instructions only (GR5 table)
    u = fresh()
    ready_cipher(u, 0, UsagePolicy=0b00001)
    u.mode = "U"
    vec = bytearray(16)
    u.vstart = 0
    check("kl.exec in a denied mode raises kl_exc_privilege_violation (SGR17)",
          (trap_of(u.exec_, 0, "A", vin=vec, vout=vec), u.getst(0)),
          ("privilege_violation", ToyCipher.ENCRYPT))
    check("a usage-controlled kl.setst in a denied mode raises it too",
          trap_of(u.setst, 0, ST_READY), "privilege_violation")
    check("kl.clearads is usage-controlled",
          trap_of(u.setst, 0, CFG_CLEAR_ADS), "privilege_violation")
    check("kl.getmd*, kl.getst, kl.size and kl.avail are not usage-controlled",
          (u.getmd(0)["Machine"], u.getst(0), u.size(k=0), u.avail(k=0)),
          (M_CIPHER, ToyCipher.ENCRYPT, 32 + 32 + 16, 1))
    check("kl.restrict* is not usage-controlled",
          (u.restrict(0, mdh_new(UsagePolicy=0b10), "h"), u.getmd(0)["UsagePolicy"]),
          ("ok", 0b11))
    check("kl.clone is not usage-controlled", u.clone(1, 0), "cloned")
    check("an Error-State kl.setst is not usage-controlled",
          (u.setst(1, ST_EXPIRED), u.getst(1)), ("error state", ST_EXPIRED))
    check("kl.mgmt is not usage-controlled",
          [export(u, 0)[:16] == mdh_bytes(u.getmd(0)), u.getst(0)], [True, ToyCipher.ENCRYPT])
    check("kl.clear is not usage-controlled", (u.setst(0, 0), u.getst(0)), ("cleared", 0))


# =====================================================================
# 6. kl.restrict*
# =====================================================================

def test_restrict():
    section("6.  kl.restrict*  --  <<KLEE-instruction-restrict>>")

    bad = []
    probe = fresh()
    for cur in range(32):
        for req in range(32):
            new = apply_usagepolicy_restriction(cur, req)
            for mode in ("U", "VS", "HS", "M", "D"):
                probe.mode = mode
                if probe.usage_allowed(cipher_pi(UsagePolicy=new)) and \
                        not probe.usage_allowed(cipher_pi(UsagePolicy=cur)):
                    bad.append((cur, req, mode))
    check("no _UsagePolicy_ request widens the set of modes (32 x 32 x 5)", bad, [])

    def run(pi, req, which="v", setup=None, **ukw):
        u = fresh(**ukw)
        provision(u, 0, pi)
        if setup:
            setup(u)
        r = u.restrict(0, req, which)
        return r, u.getmd(0), u

    r, m, _ = run(cipher_pi(UsagePolicy=0b00001), mdh_new(UsagePolicy=0b10100))
    check("UsagePolicy: set bits 0-3 are or-ed", (r, m["UsagePolicy"]), ("ok", 0b00101))
    r, m, _ = run(cipher_pi(UsagePolicy=0b10000), mdh_new(UsagePolicy=0b10000))
    check("UsagePolicy: a set bit 4 withdraws the Debug grant", m["UsagePolicy"], 0)
    r, m, _ = run(cipher_pi(ExpirationDate=1000), mdh_new(ExpirationDate=900))
    check("ExpirationDate may be brought forward", (r, m["ExpirationDate"]), ("ok", 900))
    r, m, _ = run(cipher_pi(ExpirationDate=1000), mdh_new(ExpirationDate=2000))
    check("a later ExpirationDate invalidates the CL", (r, m["State"]), ("invalid", ST_INVALID))
    r, m, _ = run(cipher_pi(), mdh_new(ExpirationDate=5))
    check("a zero ExpirationDate takes any request", m["ExpirationDate"], 5)
    r, m, _ = run(cipher_pi(), mdh_new(ExpirationDate=5), zklexpire=False)
    check("a non-zero ExpirationDate without Zklexpire invalidates", r, "invalid")
    r, m, u = run(cipher_pi(SCProtection=1), mdh_new(SCProtection=2))
    check("SCProtection may be raised; the CLF allocation follows",
          (r, m["SCProtection"], u.cls[0].alloc),
          ("ok", 2, MACHINES[M_CIPHER].clf_capacity(cipher_pi(SCProtection=2))))
    r, m, _ = run(cipher_pi(SCProtection=2), mdh_new(SCProtection=1))
    check("a weaker SCProtection invalidates, and the content is cleared",
          (r, m["State"], m["AuxDataLen"]), ("invalid", ST_INVALID, 0))
    r, m, _ = run(cipher_pi(SCProtection=1), mdh_new(SCProtection=1))
    check("an equal SCProtection changes nothing", (r, m["SCProtection"]), ("ok", 1))
    r, m, _ = run(cipher_pi(), mdh_new(SCProtection=3))
    check("an unsupported SCProtection invalidates", r, "invalid")
    r, m, _ = run(cipher_pi(), mdh_new(SCProtection=6))
    check("a custom SCProtection without ChipFamScrt/ChipScrt invalidates (GR10 on the result)",
          r, "invalid")
    r, m, _ = run(cipher_pi(Locality=loc(hw1=2)), mdh_new(SCProtection=6))
    check("a custom SCProtection with ChipFamScrt is accepted", (r, m["SCProtection"]), ("ok", 6))
    need = MACHINES[M_CIPHER].clf_capacity(cipher_pi())
    u = fresh(clf_total=need + 10)
    provision(u, 0, cipher_pi())
    before = u.getmd(0)
    check("a SCProtection raise without CLF capacity raises kl_exc_out_of_memory and "
          "changes nothing, not even the other requested fields",
          (trap_of(u.restrict, 0, mdh_new(SCProtection=2, UsagePolicy=1)), u.getmd(0)),
          ("out_of_memory", before))
    u = fresh(clf_total=need + 10)
    provision(u, 0, cipher_pi())
    check("an invalidating request is checked before the capacity allocation",
          (u.restrict(0, mdh_new(SCProtection=2, ExpirationDate=5, UsagePolicy=1,
                                 MachinePolicy=0b11, Locality=loc(boot=3))), u.getst(0)),
          ("invalid", ST_INVALID))

    # MachinePolicy
    r, m, _ = run(cipher_pi(MachinePolicy=0b11), mdh_new(MachinePolicy=0b01))
    check("MachinePolicy may be narrowed", (r, m["MachinePolicy"]), ("ok", 0b01))
    r, m, _ = run(cipher_pi(MachinePolicy=0b01), mdh_new(MachinePolicy=0b11))
    check("MachinePolicy may not re-enable a function", r, "invalid")
    r, m, _ = run(xof_pi(MachinePolicy=1), mdh_new(MachinePolicy=1))
    check("a MachinePolicy that extends _Machine_ may not be restricted, even to itself", r,
          "invalid")
    r, m, _ = run(cipher_pi(), mdh_new(MachinePolicy=0b10),
                  setup=lambda u: u.setst(0, ToyCipher.ENCRYPT, 1))
    check("disabling the operation of the current State invalidates", r, "invalid")
    r, m, _ = run(cipher_pi(), mdh_new(MachinePolicy=0b01),
                  setup=lambda u: u.setst(0, ToyCipher.ENCRYPT, 1))
    check("keeping the operation of the current State is fine", (r, m["State"]),
          ("ok", ToyCipher.ENCRYPT))
    r, m, _ = run(sig_pi(MachinePolicy=0), mdh_new(MachinePolicy=0b01))
    check("a signature Machine with both bits zero cannot gain one", r, "invalid")

    # fields of Xs1 that the instruction does not name must be zero
    for fld, which, label in (("MachineUse", "h", "_MachineUse_, which kl.restricth no longer "
                               "changes"),
                              ("Machine", "l", "_Machine_"),
                              ("State", "l", "_State_"),
                              ("AuxDataLen", "l", "_AuxDataLen_"),
                              ("Version", "h", "_Version_"),
                              ("KeyType", "v", "_KeyType_")):
        r, m, _ = run(sig_pi(), mdh_new(**{fld: 1}), which)
        check(f"a non-zero {label} in the operand is a field the instruction does not name",
              (r, m["State"]), ("invalid", ST_INVALID))
    r, m, _ = run(sig_pi(), mdh_new(MachineUse=1), "l")
    check("kl.restrictl does not examine _MachineUse_, which lies in [127:64]",
          (r, m["MachineUse"]), ("ok", 0))
    info("<<KLEE-instruction-restrict>> now says the fields of Xs1 the instruction does not name "
         "'must be zero' but does not say what a non-zero one causes. Modelled as a request that "
         "cannot be honoured, hence Error State _Invalid_, like every other unsupported or "
         "invalid request of the same instruction; an illegal-instruction exception would be the "
         "other defensible reading.")

    # Locality
    cases = [
        (loc(hw1=1), loc(hw1=2), "ok", loc(hw1=2)),
        (loc(hw1=1), loc(hw1=3), "ok", loc(hw1=3)),
        (loc(hw1=2), loc(hw1=3), "ok", loc(hw1=3)),
        (loc(hw1=3), loc(hw1=2), "invalid", None),
        (loc(hw2=1), loc(hw2=3), "ok", loc(hw2=3)),
        (loc(hw2=3), loc(hw2=1), "invalid", None),
        (loc(), loc(hw1=1), "ok", loc(hw1=1)),
        (loc(boot=1), loc(boot=2), "invalid", None),
        (loc(boot=1), loc(boot=1), "ok", loc(boot=1)),
        (loc(), loc(boot=2), "ok", loc(boot=2)),
        (loc(), loc(boot=3), "invalid", None),
        (loc(), loc(mloc=1, hloc=1, sloc=1), "ok", loc(mloc=1, hloc=1, sloc=1)),
        (loc(sloc=1), loc(sloc=1, hw2=2), "ok", loc(sloc=1, hw2=2)),
        (loc(hw1=1, hw2=3), loc(hw1=2, hw2=1), "invalid", None),
    ]
    for cur, req, want_r, want_v in cases:
        r, m, _ = run(cipher_pi(Locality=cur), mdh_new(Locality=req), "h")
        check(f"Locality {cur:#011b} + request {req:#011b}",
              (r, m["Locality"] if r == "ok" else m["State"]),
              (want_r, want_v if want_r == "ok" else ST_INVALID))
    u = fresh()
    provision(u, 0, cipher_pi())
    u.slocality = 0
    check("a Locality request naming an unconfigured entry invalidates",
          u.restrict(0, mdh_new(Locality=loc(sloc=1)), "h"), "invalid")

    # halves and atomicity
    r, m, _ = run(cipher_pi(), mdh_new(SCProtection=1, UsagePolicy=1), "l")
    check("kl.restrictl ignores [127:64]", (m["SCProtection"], m["UsagePolicy"]), (1, 0))
    r, m, _ = run(cipher_pi(), mdh_new(SCProtection=1, UsagePolicy=1), "h")
    check("kl.restricth ignores [63:0]", (m["SCProtection"], m["UsagePolicy"]), (0, 1))
    r, m, _ = run(cipher_pi(SCProtection=2), mdh_new(SCProtection=1, UsagePolicy=1))
    check("kl.restrictv: a failing half invalidates and applies nothing",
          (r, m["State"], m["UsagePolicy"]), ("invalid", ST_INVALID, 0))
    r, m, _ = run(cipher_pi(), mdh_new(SCProtection=2, UsagePolicy=1, Locality=loc(hw1=1),
                                       ExpirationDate=9, MachinePolicy=0b01))
    check("kl.restrictv applies both halves as one instruction",
          (r, m["SCProtection"], m["UsagePolicy"], m["Locality"], m["ExpirationDate"],
           m["MachinePolicy"], m["Machine"], m["State"]),
          ("ok", 2, 1, loc(hw1=1), 9, 0b01, M_CIPHER, ST_READY))
    u = fresh()
    check("kl.restrictv needs a 128-bit vector operand (GR7)",
          trap_of(u.restrict, 0, 0, "v", vec_bits=96), "illegal/1")

    # States
    u = fresh()
    check("kl.restrict* on an Unconfigured CL performs no operation",
          (u.restrict(0, mdh_new(UsagePolicy=1)), u.getst(0)), ("noop", 0))
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    check("kl.restrict* on a CL in a Configuration State raises kl_exc_privilege_violation "
          "(SGR18)", trap_of(u.restrict, 0, mdh_new(UsagePolicy=1)), "privilege_violation")
    u = fresh()
    provision(u, 0, cipher_pi(ExpirationDate=10))
    u.setst(0, ST_EXPIRED)
    check("kl.restrict* narrows the MDH of an Error-State CL, as in any Complete State",
          (u.restrict(0, mdh_new(UsagePolicy=0b1000, ExpirationDate=9)), u.getmd(0)["UsagePolicy"],
           u.getmd(0)["ExpirationDate"], u.getst(0)), ("ok", 0b1000, 9, ST_EXPIRED))
    check("... raising its SCProtection allocates nothing, the CL holding only its MDH",
          (u.restrict(0, mdh_new(SCProtection=2)), u.cls[0].alloc), ("ok", 0))
    check("... and a widening request turns it into Error State Invalid",
          (u.restrict(0, mdh_new(ExpirationDate=99)), u.getst(0)), ("invalid", ST_INVALID))
    info("An Error-State CL holds no CLF capacity (it is its MDH alone), so this model "
         "allocates nothing when kl.restrict* raises its _SCProtection_; the text states the "
         "capacity rule only in general terms.")
    u = fresh(clock=5000)
    provision(u, 0, cipher_pi(ExpirationDate=10))
    check("kl.restrict* is not an evaluation point of _ExpirationDate_",
          (u.restrict(0, mdh_new(ExpirationDate=9)), u.getst(0)), ("ok", ST_READY))


# =====================================================================
# 7. Localities
# =====================================================================

def test_localities():
    section("7.  Localities  --  <<KLEE-Localities>>, <<KLEE-system-keys>>")

    check("LST indices named by each subfield value",
          [locality_entries(v) for v in (loc(hw1=1), loc(hw1=2), loc(hw1=3), loc(hw2=1),
                                          loc(hw2=2), loc(hw2=3), loc(boot=1), loc(boot=2),
                                          loc(mloc=1), loc(hloc=1), loc(sloc=1))],
          [[j] for j in range(11)])
    everything = loc(hw1=2, hw2=3, boot=2, mloc=1, hloc=1, sloc=1)
    check("at most six architected Localities are active at once",
          (len(locality_entries(everything)), max(len(locality_entries(v)) for v in range(512))),
          (6, 6))

    u = fresh(hw_missing=(0,))
    check("unconfigured SiPScrt is replaced by ChipFamScrt", u.lst_eff(0), u.hw[1])
    u = fresh(hw_missing=(0, 1))
    check("the replacement walks the chain to ChipScrt", u.lst_eff(0), u.hw[2])
    u = fresh(hw_missing=(3, 4))
    check("OEMScrt falls through to DevScrt", u.lst_eff(3), u.hw[5])
    u = fresh(hw_missing=(2,))
    check("unconfigured ChipScrt has no replacement: invalid Metadata",
          u.locality_problem(loc(hw1=3)), "Locality names unconfigured LST entry 2")
    u = fresh(hw_missing=(0, 3))
    check("substituted, never dropped: the AD keeps one block per named entry",
          u.sealing_ad(cipher_pi(Locality=loc(hw1=1, hw2=1)))[1:], [u.hw[1], u.hw[4]])
    for attr, value, label in (("physbootscrt", loc(boot=1), "PhysBootScrt"),
                               ("mlocality", loc(mloc=1), "MLocality"),
                               ("slocality", loc(sloc=1), "SLocality")):
        u = fresh()
        setattr(u, attr, 0)
        check_true(f"a zero {label} is unconfigured and not substituted",
                   u.locality_problem(value) is not None)
    u = fresh(h_ext=False)
    check("without H, entry 9 (HLocality) and entry 7 (VirtBootScrt) are unconfigured",
          (u.lst_eff(9), u.lst_eff(7)), (0, 0))
    u = fresh()
    regs = {}
    for v in (0, 1):
        u.V = v
        regs[v] = [u.lst_register(j) for j in (8, 9, 10)]
    check("entry 10 is skllocality at V=0 and vskllocality at V=1; three distinct registers",
          (regs, all(len(set(r)) == 3 for r in regs.values())),
          ({0: ["mkllocality", "hkllocality", "skllocality"],
            1: ["mkllocality", "hkllocality", "vskllocality"]}, True))

    # binding and LST_eff at export and import
    u = fresh()
    provision(u, 0, cipher_pi(Locality=loc(sloc=1, hw1=2)))
    img = export(u, 0)
    v = fresh()
    check("an SCC imports where the named Locality Secrets match", import_(v, 1, img), ST_READY)
    v = fresh()
    v.slocality ^= 1 << 77
    check("a different SLocality value rejects the SCC", import_(v, 1, img), ST_MGMT_AUTH)
    v = fresh(hw_missing=(1,))
    check("ChipFamScrt substituted by ChipScrt changes LST_eff: the SCC is rejected",
          import_(v, 1, img), ST_MGMT_AUTH)
    u = fresh()
    provision(u, 0, cipher_pi(Locality=loc(hloc=1)))
    u.hlocality = 0                     # the hypervisor withdraws its tag
    m0 = u.getmd(0)
    img0 = export(u, 0)
    check("an export is not refused when a named entry became unconfigured",
          (img0[:16] == mdh_bytes(m0), len(img0), u.getst(0)), (True, 32 + 32, ST_READY))
    check("... the SCC is then rejected as invalid Metadata at import",
          import_(_hloc_zero(), 1, img0), ST_INVALID)
    w = fresh()
    check("... and, once the entry is configured again, by authentication (zeros(128) was "
          "sealed)", import_(w, 1, img0), ST_MGMT_AUTH)

    # the informative scenarios of <<KLEE-Metadata-locality-interoperability>>
    os_hart = fresh(h_ext=False)
    os_hart.mode = "S"
    provision(os_hart, 0, cipher_pi(Locality=loc(sloc=1)))
    scc = export(os_hart, 0)
    guest = fresh()
    guest.mode, guest.V = "VS", 1
    guest.vslocality = os_hart.slocality          # the guest OS writes skllocality
    guest.slocality ^= 1                          # whatever the hypervisor holds
    guest.hlocality ^= 1
    check("an OS becomes a guest: its SCCs import unchanged at V=1", import_(guest, 0, scc),
          ST_READY)
    g1, g2 = fresh(), fresh()
    for g, tag in ((g1, 0x111), (g2, 0x222)):
        g.mode, g.V = "VS", 1
        g.vslocality = 0x5555
        g.hlocality = tag
    provision(g1, 0, cipher_pi(Locality=loc(hloc=1, sloc=1)))
    check("a hypervisor separates its VMs: same vskllocality, different hkllocality",
          import_(g2, 0, export(g1, 0)), ST_MGMT_AUTH)
    hv = fresh()
    hv.mode, hv.V = "HS", 0
    hv.hlocality = 0x9999
    provision(hv, 0, cipher_pi(Locality=loc(hloc=1)))
    provision(hv, 1, cipher_pi(Locality=loc(sloc=1)))
    handed, sl_img = export(hv, 0), export(hv, 1)
    hv.mode, hv.V = "VS", 1
    check("a CC provisioned at V=0 naming HLocality imports at V=1", import_(hv, 2, handed),
          ST_READY)
    check("a CC naming SLocality cannot cross levels (entry 10 changes register)",
          import_(hv, 3, sl_img), ST_MGMT_AUTH)

    # System Key Store narrowing
    u = fresh()
    provision(u, 0, cipher_pi(KeyType=1, UsagePolicy=0b10001, Locality=loc(hw1=1, mloc=1)),
              skid_content(SKID_A))
    m = u.getmd(0)
    check("SKID resolution: UsagePolicy is the intersection (bits 0-3 or-ed, bit 4 and-ed)",
          m["UsagePolicy"], 0b00101)
    check("SKID resolution: Locality is the union (stricter HW entry, bits 6-8 or-ed)",
          m["Locality"], loc(hw1=2, mloc=1))
    check("SKID resolution keeps _KeyType_ 1 and the SKID as Content1",
          (m["KeyType"], u.cls[0].c1, u.getst(0)), (1, skid_content(SKID_A), ST_READY))
    img = export(u, 0)
    check("the SCC carries the SKID, not the key", len(img), 32 + 16)
    v = fresh()
    check("the SKID is resolved again at import; the narrowing is idempotent",
          (import_(v, 1, img), v.getmd(1)), (ST_READY, m))
    for skid, pi, label in ((0x99, cipher_pi(KeyType=1), "an unknown SKID"),
                            (SKID_B, cipher_pi(KeyType=1, MachinePolicy=0b11),
                             "a MachinePolicy that is not a subset of the allowed one"),
                            (SKID_A, xof_pi(KeyType=1), "a Machine the SKID is not allowed for"),
                            (SKID_C, cipher_pi(KeyType=1, Locality=loc(boot=1)),
                             "two different non-zero Boot Session entries"),
                            (SKID_D, cipher_pi(KeyType=1), "a union naming an unconfigured entry")):
        w = fresh()
        w.slocality = 0
        check(f"SKID resolution fails for {label}: Invalid at completion",
              provision(w, 0, pi, skid_content(skid)), ST_INVALID)
    w = fresh()
    check("a SKID allowed for a MachinePolicy is allowed for its subsets",
          provision(w, 0, cipher_pi(KeyType=1, MachinePolicy=0b01), skid_content(SKID_B)),
          ST_READY)
    w = fresh()
    w.mode = "U"
    check("the current privilege mode does not affect resolution",
          provision(w, 0, cipher_pi(KeyType=1), skid_content(SKID_A)), ST_READY)
    w = fresh()
    provision(w, 0, cipher_pi(KeyType=1), skid_content(ONES64))
    k1 = w.cls[0].c1
    provision(w, 1, cipher_pi(KeyType=1), skid_content(ONES64))
    check("the all-ones SKID: a key is generated at completion and _KeyType_ becomes 0",
          (w.getmd(0)["KeyType"], len(k1), k1 != w.cls[1].c1, w.size(k=0)),
          (0, 32, True, 32 + 32))


def _hloc_zero():
    u = fresh()
    u.hlocality = 0
    return u


# =====================================================================
# 8. kl.mgmt flows
# =====================================================================

def test_mgmt_flows():
    section("8.  kl.mgmt: provisioning, import, export  --  <<KLEE-CL-management>>")

    m = cipher_pi(UsagePolicy=0b0001, Locality=loc(hw1=2), SCProtection=1)
    content = pi_content(m)

    # -- provisioning, Zklmem
    u = fresh()
    u.csr_write("klstart", 48)
    u.siv, u.impqual, u.siv2 = 1, 2, 3
    check("the opening kl.mgmt reports an open provisioning",
          u.mgmt(0, CFG_PROVISIONING, m), "opened")
    check("... State kl_cfg_provisioning, the MDH loaded, klmanagedcr = 0, klstart cleared",
          (u.getst(0), u.getmd(0)["Locality"], u.klmanagedcr, u.klstart),
          (CFG_PROVISIONING, loc(hw1=2), 0, 0))
    check("... the authentication registers are untouched by provisioning",
          (u.siv, u.impqual, u.siv2), (1, 2, 3))
    check("kl.size while provisioning is the PI length", u.size(k=0), 16 + len(content))
    mem = Memory()
    mem.write(BASE, content)
    check("kl.load loads the PI Content; klstart cleared on completion",
          (u.load(0, mem, BASE), u.klstart), ("done", 0))
    check("the completing kl.mgmt (Form A, native) completes the provisioning",
          u.mgmt(0, CFG_MANAGEMENT_END, form="A"), "completed")
    check("... State Ready, StateExtension and MachineUse zero, klmanagedcr 32",
          (u.getst(0), u.getstx(0), u.getmd(0)["MachineUse"], u.klmanagedcr),
          (ST_READY, 0, 0, MANAGEDCL_NONE))
    check("... the implementation's ADS is recorded in _AuxDataLen_",
          (u.getmd(0)["AuxDataLen"], cl_consistent(u, 0)), (ADS_BLOCKS, True))
    check("... Content is the PI's", u.cls[0].c1, content)
    check("kl.size is now the SCC length with the ADS",
          u.size(k=0), 64 + len(content) + 16 * (ADS_BLOCKS - 2))

    # -- the three other ways of loading agree
    for via, form in (("mv", "D"), ("mvv", "C"), ("load", "A")):
        w = fresh()
        if form == "A":
            w.csr_write("kliobuflen", 16)
            w.kliobuf[0:16] = mdh_bytes(m)
            w.csr_write("klstart", 5)                   # ignored by the substitution
        provision(w, 0, m, via=via, form=form)
        check(f"provisioning via {via} with a Form {form} opening agrees with Zklmem",
              (w.getmd(0), w.cls[0].c1, w.cls[0].c2), (u.getmd(0), u.cls[0].c1, u.cls[0].c2))
    w = fresh()
    w.mgmt(0, CFG_PROVISIONING, m)
    starts = []
    for off in range(0, len(content), 16):
        starts.append(w.klstart)
        w.mv_in(0, b2v(content[off:off + 16]))
    check("kl.mv accumulates klstart across instructions and keeps it",
          (starts, w.klstart), (list(range(0, len(content), 16)), len(content)))
    w.mgmt(0, CFG_MANAGEMENT_END)
    check("the completing kl.mgmt clears it", w.klstart, 0)

    # -- export and import
    md = u.getmd(0)
    u.mgmt(0, CFG_EXPORTING)
    check("opening an export: State kl_cfg_exporting, klmanagedcr 0, klstart 0",
          (u.getst(0), u.klmanagedcr, u.klstart), (CFG_EXPORTING, 0, 0))
    check("... the opening kl.mgmt causes no changes to any MDH field other than _State_",
          dict(u.getmd(0), State=0), dict(md, State=0))
    check("... it writes SIV, IMPQUAL and SIV2 (AuxDataLen >= 2)",
          (u.siv != 0, u.impqual, u.siv2 != 0), (True, u.impqual_value(), True))
    n = u.size(k=0)
    out = Memory()
    u.store(0, out, BASE)
    img = mdh_bytes(md) + out.read(BASE, n - 16)
    check("kl.store: SIV, IMPQUAL and SIV2 are the leading bytes of S",
          [b2v(img[16 + 16 * i:32 + 16 * i]) for i in range(3)], [u.siv, u.impqual, u.siv2])
    check_true("the exported Content is not the plaintext", img[64:64 + 32] != content)
    check("kl.store may modify only klstart", (u.getst(0), u.klstart), (CFG_EXPORTING, 0))
    wrong = dict(md, UsagePolicy=0, Locality=0)
    check("completing the export with the saved ml restores the CL",
          (u.mgmt(0, CFG_MANAGEMENT_END, wrong), u.getmd(0), u.cls[0].c1),
          ("completed", md, content))
    check("... ml is consumed only for its _State_: the other fields of ml are ignored",
          (u.getmd(0)["UsagePolicy"], u.getmd(0)["Locality"]), (0b0001, loc(hw1=2)))
    check("... klmanagedcr is 32 again", u.klmanagedcr, MANAGEDCL_NONE)

    v = fresh()
    check("kl.size Form B of the stored MDH gives the image length",
          v.size("B", lo=b2v(img[0:8])), len(img))
    v.siv = v.impqual = v.siv2 = 7
    check("an opening import zeroizes the authentication registers",
          (v.mgmt(1, CFG_IMPORTING, img[0:16] and mdh_unpack(b2v(img[0:16]))),
           v.siv, v.impqual, v.siv2), ("opened", 0, 0, 0))
    check("... State kl_cfg_importing, klmanagedcr 1", (v.getst(1), v.klmanagedcr),
          (CFG_IMPORTING, 1))
    mem = Memory()
    mem.write(BASE, img[16:])
    v.load(1, mem, BASE)
    check("kl.load placed SIV, IMPQUAL, SIV2 in the per-hart registers",
          (v.siv, v.impqual, v.siv2), (u.siv, u.impqual, u.siv2))
    v.mgmt(1, CFG_MANAGEMENT_END, md)
    check("the import round trips MDH, Content1 and the ADS",
          (v.getmd(1), v.cls[1].c1, v.cls[1].c2), (md, content, u.cls[0].c2))
    for via, form in (("mv", "D"), ("load", "A")):
        w = fresh()
        if form == "A":
            w.csr_write("kliobuflen", 64)
            w.csr_write("kliobuftop", 16)
        check(f"import via {via}, Form {form}, agrees",
              (import_(w, 2, img, via=via, form=form), w.getmd(2), w.cls[2].c1),
              (ST_READY, md, content))
    w = fresh()
    check("import via Form C (vector MDH operand) agrees",
          (w.mgmt(2, CFG_IMPORTING, md, form="C"), import_(w, 2, img)), ("opened", ST_READY))
    exp_mv = export(v, 1, via="mv")
    check("export via kl.mv agrees with kl.store", exp_mv, img)

    # a CL mid-operation, exported and imported
    u = fresh()
    ready_cipher(u, 0)
    blk = bytearray(32)
    u.exec_(0, "A", vin=blk, vout=blk)
    st_md = u.getmd(0)
    img = export(u, 0)
    v = fresh()
    check("an SCC of a CL mid-operation restores State, StateExtension and the state block",
          (import_(v, 3, img), v.getmd(3), v.cls[3].c1), (ToyCipher.ENCRYPT, st_md, u.cls[0].c1))
    check("the imported CL continues the operation where it stopped",
          (v.exec_(3, "A", vin=bytearray(16), vout=bytearray(16)),
           u.exec_(0, "A", vin=bytearray(16), vout=bytearray(16)), v.cls[3].c1 == u.cls[0].c1),
          ("done", "done", True))

    # authentication at completion
    v = fresh()
    tampered = bytearray(img)
    tampered[40] ^= 1
    check("a modified Content1 byte: Authentication Failed, no exception",
          (import_(v, 0, bytes(tampered)), v.getmd(0)["AuxDataLen"], v.klmanagedcr),
          (ST_MGMT_AUTH, 0, MANAGEDCL_NONE))
    widened = mdh_bytes(dict(st_md, UsagePolicy=0)) + img[16:]
    widened = mdh_bytes(dict(st_md, ExpirationDate=0)) + img[16:] \
        if st_md["UsagePolicy"] == 0 else widened
    wid_md = dict(st_md, UsagePolicy=0b1111)
    v = fresh()
    check("an MDH altered in memory (UsagePolicy) is caught by authentication",
          import_(v, 0, mdh_bytes(wid_md) + img[16:]), ST_MGMT_AUTH)
    v = fresh()
    v.mgmt(0, CFG_IMPORTING, st_md)
    mem = Memory()
    mem.write(BASE, img[16:])
    v.load(0, mem, BASE)
    check("a completion with a different ml._State_ fails authentication",
          (v.mgmt(0, CFG_MANAGEMENT_END, dict(st_md, State=ST_READY)), v.getst(0)),
          ("completed", ST_MGMT_AUTH))
    v = fresh(csk=DEFAULT_CSK ^ 1)
    check("an SCC sealed under another CSK is rejected", import_(v, 0, img), ST_MGMT_AUTH)
    u = fresh()
    provision(u, 0, cipher_pi())
    u.mgmt(0, CFG_EXPORTING)
    u.siv ^= 1
    check("an export whose SIV register was overwritten fails at completion",
          (u.mgmt(0, CFG_MANAGEMENT_END, cipher_pi(State=ST_READY)), u.getst(0)),
          ("completed", ST_MGMT_AUTH))
    info("An opening import zeroizes SIV, IMPQUAL and SIV2 in this model only when the import "
         "is actually opened: the short import 'takes no part' in them "
         "(<<KLEE-error-state-transfer>>), and an opening that raises an exception changes no "
         "KLEE state other than the zeroized CL (the state change rule for exceptions).")

    # klmanagedcr and ordering of the kl.mgmt checks
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    check("kl.mgmt on another CL while klmanagedcr = 0 is an illegal instruction",
          (trap_of(u.mgmt, 1, CFG_PROVISIONING, cipher_pi()), u.getst(1)), ("illegal/2", 0))
    check("... also for an export or a completion",
          (trap_of(u.mgmt, 1, CFG_EXPORTING), trap_of(u.mgmt, 1, CFG_MANAGEMENT_END, mdh_new())),
          ("illegal/2", "illegal/2"))
    check("... the klmanagedcr check precedes Rule GR8 for a Form A opening",
          trap_of(u.mgmt, 1, CFG_PROVISIONING, form="A"), "illegal/2")
    u.csr_write("klmanagedcr", 32)
    check("writing 32 releases the check; the other CL can be managed",
          provision(u, 1, cipher_pi()), ST_READY)
    check("... the first CL is still being provisioned", u.getst(0), CFG_PROVISIONING)
    u = fresh()
    ready_cipher(u, 0)
    before = snapshot(u)
    check("Form A opening with an unconfigured KLIOBUF: kl_exc_unconfigured_buffer, "
          "no change to the CL", (trap_of(u.mgmt, 0, CFG_PROVISIONING, form="A"),
                                  snapshot(u) == before), ("unconfigured_buffer", True))
    u.csr_write("kliobuflen", 64)
    u.csr_write("kliobuftop", 15)
    before = snapshot(u)
    check("Form A opening with kliobuftop < 16: illegal instruction before any change",
          (trap_of(u.mgmt, 0, CFG_IMPORTING, form="A"), snapshot(u) == before),
          ("illegal/2", True))
    w = fresh(zklio=False)
    w.mgmt(0, CFG_IMPORTING, cipher_pi(State=1))
    check("a Form A completion that needs ml without Zklio is an illegal instruction",
          trap_of(w.mgmt, 0, CFG_MANAGEMENT_END, form="A"), "illegal/2")
    w = fresh()
    w.mgmt(0, CFG_PROVISIONING, cipher_pi())
    check("a Form A export opening and a Form A provisioning completion need no KLIOBUF",
          (w.mgmt(0, CFG_MANAGEMENT_END, form="A"), w.mgmt(0, CFG_EXPORTING, form="A")),
          ("completed", "opened"))
    w = fresh()
    w.mgmt(0, CFG_IMPORTING, cipher_pi(State=1))
    w.csr_write("klstart", 16)
    before = (w.getst(0), w.klmanagedcr, w.klstart)
    check("an exception during a management operation leaves klmanagedcr and klstart unchanged",
          (trap_of(w.mgmt, 0, CFG_MANAGEMENT_END, form="A"), (w.getst(0), w.klmanagedcr,
                                                              w.klstart)),
          ("unconfigured_buffer", before))
    check("Form B of kl.mgmt is reserved; Form C needs VL * SEW >= 128",
          (trap_of(w.mgmt, 0, CFG_PROVISIONING, cipher_pi(), form="B"),
           trap_of(w.mgmt, 0, CFG_PROVISIONING, cipher_pi(), form="C", vec_bits=64)),
          ("illegal/1", "illegal/1"))
    check("opening an export on an Unconfigured CL is an illegal instruction",
          trap_of(fresh().mgmt, 0, CFG_EXPORTING), "illegal/2")
    check("kl_cfg_management_end with no operation open is an illegal instruction",
          [trap_of(ready_cipher(fresh(), 0).mgmt, 0, CFG_MANAGEMENT_END, mdh_new(State=1)),
           trap_of(fresh().mgmt, 0, CFG_MANAGEMENT_END, mdh_new(State=1))],
          ["illegal/2", "illegal/2"])
    u = fresh()
    provision(u, 0, cipher_pi())
    k0 = snapshot(u)
    check("an opening provisioning zeroizes even a Valid CL (GR6), the operation then "
          "failing", (trap_of(u.mgmt, 0, CFG_PROVISIONING, mdh_new(Machine=M_ABSENT)),
                      u.getst(0), u.clf_free() == u.clf_total), ("unsupported", 0, True))
    check_true("... which is the one KLEE state change an exception does not undo",
               snapshot(u) != k0)


# =====================================================================
# 9. Nested management operations
# =====================================================================

def test_nested():
    section("9.  Nested management operations and PCCCs  --  <<KLEE-nested-state-base-types>>, "
            "<<KLEE-data-formats>>")

    # base-type rule for completions, exhaustively
    table = {}
    for cl_state in (CFG_EXPORTING, CFG_IMPORTING, CFG_PPI_EXPORTING, CFG_PPI_IMPORTING):
        acc = []
        for mls in range(64):
            u = fresh()
            provision(u, 0, cipher_pi())
            u.mgmt(0, CFG_EXPORTING)
            u.cls[0].mdh["State"] = cl_state            # white box: every Configuration State
            if BASE_TYPE[cl_state] == "pi":
                u.cls[0].img = bytearray(32)
            if trap_of(u.mgmt, 0, CFG_MANAGEMENT_END, mdh_new(State=mls)) is None:
                acc.append(mls)
        table[cl_state] = acc
    scc_ok = sorted(set(COMPLETE_STATES) | {57, 58})
    check("a completion of an scc-base CL accepts ml.State Complete, 57 or 58, nothing else",
          (table[57], table[58]), (scc_ok, scc_ok))
    check("a completion of a pi-base CL accepts ml.State 56, 59 or 60, nothing else",
          (table[59], table[60]), ([56, 59, 60], [56, 59, 60]))

    # -- a provisioning preempted, saved as a PI-shaped PCCC, and resumed
    m = cipher_pi(Locality=loc(hw2=2))
    content = pi_content(m, 0x51)
    u = fresh()
    u.mgmt(4, CFG_PROVISIONING, m)
    mem = Memory()
    mem.write(BASE, content)
    u.load(4, mem, BASE, halt_after=16)
    check("the provisioning halts with klstart = 16", (u.klstart, u.getst(4)),
          (16, CFG_PROVISIONING))
    saved_klstart = u.klstart
    saved = u.getmd(4)
    check("the nested export opens kl_cfg_ppi_exporting",
          (u.mgmt(4, CFG_EXPORTING), u.getst(4), u.klmanagedcr, u.klstart),
          ("opened", CFG_PPI_EXPORTING, 4, 0))
    n = u.size(k=4)
    check("kl.size of the PI-shaped PCCC is the PI length", n, 16 + len(content))
    out = Memory()
    u.store(4, out, BASE)
    pccc = mdh_bytes(saved) + out.read(BASE, n - 16)
    check("the PCCC is verbatim: loaded bytes in clear, the rest reads as zero",
          pccc[16:], content[:16] + bytes(16))
    check("a nested completion restores the saved State and keeps klmanagedcr",
          (u.mgmt(4, CFG_MANAGEMENT_END, saved), u.getst(4), u.klmanagedcr),
          ("completed", CFG_PROVISIONING, 4))
    # the double nesting of the informative text
    u.mgmt(4, CFG_EXPORTING)
    inner = u.getmd(4)
    check("a further nested export stays in kl_cfg_ppi_exporting",
          (u.mgmt(4, CFG_EXPORTING), u.getst(4)), ("opened", CFG_PPI_EXPORTING))
    u.mgmt(4, CFG_MANAGEMENT_END, inner)
    check("its completion restores kl_cfg_ppi_exporting", u.getst(4), CFG_PPI_EXPORTING)
    u.mgmt(4, CFG_MANAGEMENT_END, saved)
    check("the outer completion restores kl_cfg_provisioning", u.getst(4), CFG_PROVISIONING)
    check("a Complete ml cannot complete a pi-base CL (illegal instruction)",
          (u.mgmt(4, CFG_EXPORTING), trap_of(u.mgmt, 4, CFG_MANAGEMENT_END,
                                             dict(saved, State=ST_READY))),
          ("opened", "illegal/2"))
    u.mgmt(4, CFG_MANAGEMENT_END, saved)
    u.setst(4, 0)
    check("clearing the CL releases klmanagedcr", (u.getst(4), u.klmanagedcr),
          (0, MANAGEDCL_NONE))
    check("reimporting the PI-shaped PCCC opens kl_cfg_ppi_importing",
          (u.mgmt(4, CFG_IMPORTING, saved), u.getst(4), u.klmanagedcr),
          ("opened", CFG_PPI_IMPORTING, 4))
    mem2 = Memory()
    mem2.write(BASE, pccc[16:])
    u.load(4, mem2, BASE)
    check("its completion (ml.State 56) returns to kl_cfg_provisioning",
          (u.mgmt(4, CFG_MANAGEMENT_END, saved), u.getst(4)), ("completed", CFG_PROVISIONING))
    u.csr_write("klstart", saved_klstart)
    u.load(4, mem, BASE)
    check("the resumed provisioning completes with the original Content",
          (u.mgmt(4, CFG_MANAGEMENT_END), u.getst(4), u.cls[4].c1),
          ("completed", ST_READY, content))

    # the all-ones SKID leaves nothing secret in a PI-shaped PCCC
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi(KeyType=1))
    u.mv_in(0, ONES64)
    s0 = u.getmd(0)
    u.mgmt(0, CFG_EXPORTING)
    pv = [u.mv_out(0) for _ in range(u.size(k=0) // 16 - 1)]
    u.mgmt(0, CFG_MANAGEMENT_END, s0)
    check("a PCCC of an all-ones-SKID provisioning carries only the SKID", pv, [ONES64])
    u.mgmt(0, CFG_MANAGEMENT_END)
    check_true("the key is generated by the completing kl.mgmt only",
               u.getmd(0)["KeyType"] == 0 and len(u.cls[0].c1) == 32)

    # -- an import preempted, saved as an SCC-shaped PCCC, and resumed
    src = fresh()
    provision(src, 0, cipher_pi(SCProtection=1, Locality=loc(boot=1)))
    scc = export(src, 0)
    base_ml = mdh_unpack(b2v(scc[0:16]))
    u = fresh()
    u.mgmt(2, CFG_IMPORTING, base_ml)
    mem = Memory()
    mem.write(BASE, scc[16:])
    u.load(2, mem, BASE, halt_after=64)
    regs = (u.siv, u.impqual, u.siv2)
    check("the import halts after SIV, IMPQUAL, SIV2 and one Content block",
          (u.klstart, regs), (64, (src.siv, src.impqual, src.siv2)))
    k_saved = u.klstart
    s1 = u.getmd(2)
    check("a nested export of an interrupted import opens kl_cfg_exporting without sealing",
          (u.mgmt(2, CFG_EXPORTING), u.getst(2), (u.siv, u.impqual, u.siv2)),
          ("opened", CFG_EXPORTING, regs))
    pc = export_pccc(u, 2, s1)
    check("the SCC-shaped PCCC: the registers, the loaded ciphertext, zeros for the rest",
          pc[16:], scc[16:80] + bytes(len(scc) - 80))
    check("... and its nested completion returns to kl_cfg_importing",
          (u.getst(2), u.klmanagedcr), (CFG_IMPORTING, 2))
    u.csr_write("klmanagedcr", 32)
    ready_cipher(u, 9)                               # another management operation
    export(u, 9)
    check("another export overwrote the registers", u.siv != regs[0], True)
    u.setst(2, 0)
    check("reimporting the PCCC (ml.State 58) opens kl_cfg_importing",
          (u.mgmt(2, CFG_IMPORTING, s1), u.getst(2)), ("opened", CFG_IMPORTING))
    mem3 = Memory()
    mem3.write(BASE, pc[16:])
    u.load(2, mem3, BASE)
    u.mgmt(2, CFG_MANAGEMENT_END, s1)
    check("its completion returns to kl_cfg_importing with the registers restored",
          (u.getst(2), (u.siv, u.impqual, u.siv2), u.klmanagedcr),
          (CFG_IMPORTING, regs, 2))
    u.csr_write("klstart", k_saved)
    u.load(2, mem, BASE)
    check("the resumed import authenticates and round trips",
          (u.mgmt(2, CFG_MANAGEMENT_END, base_ml), u.getmd(2), u.cls[2].c1, u.cls[2].c2),
          ("completed", src.getmd(0), src.cls[0].c1, src.cls[0].c2))

    # -- an export preempted and resumed through a nested cycle, with tampering detected
    for tamper in (False, True):
        u = fresh()
        provision(u, 1, sig_pi(AuxInfo=3))
        base_md = u.getmd(1)
        u.mgmt(1, CFG_EXPORTING)
        out = Memory()
        u.store(1, out, BASE, halt_after=32)
        ks = u.klstart
        s2 = u.getmd(1)
        u.mgmt(1, CFG_EXPORTING)
        check(f"a nested export of an interrupted export stays kl_cfg_exporting (tamper={tamper})",
              u.getst(1), CFG_EXPORTING)
        pc = export_pccc(u, 1, s2)
        u.setst(1, 0)
        if tamper:
            pc = bytearray(pc)
            pc[40] ^= 0x80
            pc = bytes(pc)
        u.mgmt(1, CFG_IMPORTING, s2)
        memp = Memory()
        memp.write(BASE, pc[16:])
        u.load(1, memp, BASE)
        u.mgmt(1, CFG_MANAGEMENT_END, s2)
        check("the reimported PCCC returns to kl_cfg_exporting", u.getst(1), CFG_EXPORTING)
        u.csr_write("klstart", ks)
        u.store(1, out, BASE)
        u.mgmt(1, CFG_MANAGEMENT_END, base_md)
        if tamper:
            check("a modified PCCC is detected when the export completes",
                  u.getst(1), ST_MGMT_AUTH)
        else:
            check("the export completes by decrypting and authenticating the ciphertext",
                  (u.getmd(1), len(u.cls[1].c1)), (base_md, 64))
            v = fresh()
            img = mdh_bytes(base_md) + out.read(BASE, u.size(k=1) - 16)
            check("... and the SCC stored across the preemption imports",
                  (import_(v, 0, img), v.cls[0].c1), (ST_READY, u.cls[1].c1))


def export_pccc(u, k, saved):
    """Store a CL already opened for a nested export and complete it with `saved`."""
    n = u.size(k=k)
    out = Memory()
    u.store(k, out, BASE)
    u.mgmt(k, CFG_MANAGEMENT_END, saved)
    return mdh_bytes(saved) + out.read(BASE, n - 16)


# =====================================================================
# 10. Error-State CLs
# =====================================================================

def test_error_states():
    section("10. CLs in an Error State  --  <<KLEE-error-state-transfer>>, "
            "<<KLEE-error-state-instructions>>")

    for st in sorted(ERROR_STATES):
        u = fresh()
        provision(u, 0, cipher_pi(SCProtection=1, ExpirationDate=77, UsagePolicy=0b10))
        u.setst(0, ToyCipher.ENCRYPT, 5)
        u.csr_write("klstart", 32)
        r = u.setst(0, st)
        want = ST_INVALID if st in (54, 55) else st
        m = u.getmd(0)
        check(f"kl.setst #{st}: State {want}, content, AuxDataLen and ADSDropped cleared, "
              "MDH otherwise retained, klstart unchanged",
              (r, m["State"], u.cls[0].c1, m["AuxDataLen"], m["ExpirationDate"],
               m["StateExtension"], u.cls[0].alloc, u.klstart),
              ("error state", want, b"", 0, 77, 1, 0, 32))
        check(f"State {want}: kl.size is 16 and the short export is kl.getmd", u.size(k=0), 16)
        img = export(u, 0)
        check(f"State {want}: the exported image is the 16-byte MDH", img, mdh_bytes(m))
        v = fresh()
        v.csr_write("klstart", 48)
        v.siv = 5
        check(f"State {want}: the short import is one kl.mgmt, configures the CL, clears "
              "klstart, leaves klmanagedcr 32 and the registers alone",
              (v.mgmt(3, CFG_IMPORTING, mdh_unpack(b2v(img))), v.getmd(3), v.klstart,
               v.klmanagedcr, v.siv), ("short import", m, 0, 32, 5))
        check(f"State {want}: no kl_cfg_management_end follows (illegal instruction)",
              trap_of(v.mgmt, 3, CFG_MANAGEMENT_END, m), "illegal/2")
    u = fresh()
    check("a short import of State 54 or 55 configures Error State Invalid",
          [(u.mgmt(k, CFG_IMPORTING, cipher_pi(State=s)), u.getst(k)) for k, s in ((0, 54),
                                                                                   (1, 55))],
          [("short import", ST_INVALID)] * 2)
    u = fresh()
    check("the short import zeroes a supplied AuxDataLen and ADSDropped",
          (u.mgmt(0, CFG_IMPORTING, cipher_pi(State=ST_EXPIRED, AuxDataLen=4, ADSDropped=1)),
           u.getmd(0)["AuxDataLen"], u.getmd(0)["ADSDropped"]), ("short import", 0, 0))
    check("the short import allocates no CLF capacity", u.cls[0].alloc, 0)
    u = fresh()
    check("kl.setst with an Error-State immediate on an Unconfigured CL performs no operation",
          (u.setst(0, ST_INVALID), u.getst(0)), ("noop", 0))

    # the table of <<KLEE-error-state-instructions>>
    def err_unit():
        w = fresh()
        provision(w, 0, cipher_pi())
        w.setst(0, ST_EXPIRED)
        provision(w, 1, cipher_pi())
        return w
    u = err_unit()
    before = u.getmd(0)
    check("kl.mgmt opening an export on an Error-State CL leaves it unchanged, opens nothing, "
          "clears klstart", (u.csr_write("klstart", 16), u.mgmt(0, CFG_EXPORTING), u.getmd(0),
                             u.klmanagedcr, u.klstart),
          (None, "unchanged", before, 32, 0))
    check("kl.load, kl.store and kl.mv on an Error-State CL are illegal instructions",
          [trap_of(u.load, 0, Memory(), BASE), trap_of(u.store, 0, Memory(), BASE),
           trap_of(u.mv_in, 0, 1), trap_of(u.mv_out, 0)], ["illegal/2"] * 4)
    vo = bytearray(b"\xAA" * 16)
    check("kl.exec on an Error-State CL: no operation, no exception, output zeroed",
          (u.exec_(0, "A", vin=bytearray(16), vout=vo), vo, u.getst(0)),
          ("noop", bytearray(16), ST_EXPIRED))
    check("usage-controlled kl.setst and kl.clearads: no operation, State unchanged",
          (u.setst(0, ST_READY), u.setst(0, CFG_CLEAR_ADS), u.getst(0)),
          ("noop", "noop", ST_EXPIRED))
    check("the Error State is evaluated before the UsagePolicy and the expiration date",
          (u.restrict(0, mdh_new(UsagePolicy=0b1000)), u.setst(0, ST_READY), u.getst(0)),
          ("ok", "noop", ST_EXPIRED))
    check("kl.setst with an Error-State immediate changes the Error State (SGR15)",
          (u.setst(0, ST_UNSUPPORTED), u.getst(0)), ("error state", ST_UNSUPPORTED))
    check("kl.clone with the Error-State CL as source copies its MDH alone",
          (u.clone(5, 0), u.getmd(5), u.cls[5].c1, u.cls[5].alloc), ("cloned", u.getmd(0), b"", 0))
    check("kl.clone with an Error-State CL as destination replaces it",
          (u.clone(5, 1), u.getst(5), u.cls[5].c1 == u.cls[1].c1), ("cloned", ST_READY, True))
    check("kl.mgmt opening a provisioning on an Error-State CL reconfigures it (SGR12)",
          provision(u, 0, cipher_pi()), ST_READY)
    u.setst(0, ST_INVALID)
    check("kl.clear makes an Error-State CL Unconfigured", (u.setst(0, 0), u.getst(0)),
          ("cleared", 0))


# =====================================================================
# 11. SCC import with an ADS
# =====================================================================

def test_ads():
    section("11. ADS, IMPQUAL and _ADSDropped_  --  <<KLEE-SCC-import>>, "
            "<<KLEE-Auxiliary-Data-Section>>")

    u = fresh()
    provision(u, 0, cipher_pi(SCProtection=1))
    u.setst(0, ToyCipher.ENCRYPT, 9)
    md = u.getmd(0)
    scc = export(u, 0)
    c1 = MACHINES[M_CIPHER].content1_size(md)
    check("an SCC with an ADS: MDH, SIV, IMPQUAL, SIV2, Content1, Content2",
          len(scc), 16 + 48 + c1 + 16 * (ADS_BLOCKS - 2))
    check("IMPQUAL = zeros(32) @ klmimpid @ klmarchid @ klmvendorid",
          b2v(scc[32:48]), (u.impid << 64) | (u.archid << 32) | u.vendorid)

    v = fresh()
    check("same implementation: the ADS is retained", (import_(v, 0, scc), v.cls[0].c2,
                                                        v.getmd(0)["AuxDataLen"]),
          (ToyCipher.ENCRYPT, u.cls[0].c2, ADS_BLOCKS))

    other = fresh(ids=(0x0A11, 0x42, 0x99))
    check("another implementation (IMPQUAL mismatch): Content1 accepted, ADS dropped and "
          "regenerated", (import_(other, 0, scc), other.cls[0].c1, other.cls[0].c2 != u.cls[0].c2,
                          other.getmd(0)["AuxDataLen"], other.getmd(0)["ADSDropped"]),
          (ToyCipher.ENCRYPT, u.cls[0].c1, True, ADS_BLOCKS, 0))

    lo = fresh()
    provision(lo, 0, cipher_pi())
    lo.setst(0, ToyCipher.ENCRYPT, 9)
    scc_lo = export(lo, 0)
    check("an SCProtection-0 CL has no ADS", len(scc_lo), 32 + c1)

    t = bytearray(scc)
    t[16 + 48 + c1] ^= 1                     # a Content2 byte
    v = fresh()
    check("a modified Content2: second-segment failure drops Content2 without rejecting "
          "the SCC", (import_(v, 0, bytes(t)), v.cls[0].c1, v.getmd(0)["ADSDropped"]),
          (ToyCipher.ENCRYPT, u.cls[0].c1, 0))
    t = bytearray(scc)
    t[48] ^= 1                               # SIV2
    v = fresh()
    check("a modified SIV2: the same", (import_(v, 0, bytes(t)), v.cls[0].c1),
          (ToyCipher.ENCRYPT, u.cls[0].c1))
    t = bytearray(scc)
    t[16] ^= 1                               # SIV
    check("a modified SIV rejects the whole SCC", import_(fresh(), 0, bytes(t)), ST_MGMT_AUTH)

    # ADSDropped set in memory: Content2 dropped, Content1 and the policies untouched
    dropped_md = dict(md, ADSDropped=1)
    t = bytearray(scc)
    t[0:16] = mdh_bytes(dropped_md)
    t[32:64] = bytes(32)                     # IMPQUAL, SIV2: non-authoritative padding
    v = fresh()
    v.mgmt(0, CFG_IMPORTING, dropped_md)
    check("ADSDropped = 1 keeps ContentOffset 48 and removes Content2 from the layout",
          v.layout(v.getmd(0))[0:2], (48, c1))
    check("kl.size of the dropped layout", v.size("C", md=dropped_md), 64 + c1)
    mem = Memory()
    mem.write(BASE, bytes(t[16:]))
    v.load(0, mem, BASE)
    v.mgmt(0, CFG_MANAGEMENT_END, dropped_md)
    check("setting ADSDropped in memory cannot affect Content1 or any policy",
          (v.getst(0), v.cls[0].c1, dict(v.getmd(0), AuxDataLen=0, ADSDropped=0)),
          (ToyCipher.ENCRYPT, u.cls[0].c1, dict(md, AuxDataLen=0, ADSDropped=0)))
    check("... the import ends with ADSDropped 0 and a regenerated ADS",
          (v.getmd(0)["ADSDropped"], v.getmd(0)["AuxDataLen"]), (0, ADS_BLOCKS))

    # an ADS longer than this implementation supports
    big = fresh()
    big_md = dict(md, AuxDataLen=MAX_AUXDATALEN + 2)
    AD = big.sealing_ad(big_md)
    siv, ct1 = scc_encrypt(AD, 0, 0, to_blocks(u.cls[0].c1), DEFAULT_CSK)
    impq = big.impqual_value()
    siv2, ct2 = scc_encrypt([impq, siv], 0, 1, to_blocks(bytes(16 * MAX_AUXDATALEN)), DEFAULT_CSK)
    long_scc = (mdh_bytes(big_md) + v2b(siv, 16) + v2b(impq, 16) + v2b(siv2, 16)
                + from_blocks(ct1) + from_blocks(ct2))
    big.mgmt(0, CFG_IMPORTING, big_md)
    check("an AuxDataLen above the maximum sets ADSDropped at the opening",
          big.getmd(0)["ADSDropped"], 1)
    mem = Memory()
    mem.write(BASE, long_scc[16:])
    big.load(0, mem, BASE)
    check("... kl.load reads only up to image_end", mem.accesses, (48 + c1) // 16)
    big.mgmt(0, CFG_MANAGEMENT_END, big_md)
    check("... the SCC is accepted with Content1 only",
          (big.getst(0), big.cls[0].c1, big.getmd(0)["ADSDropped"]),
          (ToyCipher.ENCRYPT, u.cls[0].c1, 0))

    # kl.clearads
    w = fresh()
    provision(w, 0, cipher_pi(SCProtection=1))
    w.setst(0, ToyCipher.ENCRYPT, 1)
    check("kl.clearads sets AuxDataLen and ADSDropped to 0 and keeps the State",
          (w.setst(0, CFG_CLEAR_ADS), w.getmd(0)["AuxDataLen"], w.cls[0].c2, w.getst(0)),
          ("ads cleared", 0, b"", ToyCipher.ENCRYPT))
    check("an export then produces an ADS-free SCC", len(export(w, 0)), 32 + c1)
    w.exec_(0, "A", vin=bytearray(16), vout=bytearray(16))
    check("the first usage instruction needing the ADS regenerates it",
          w.getmd(0)["AuxDataLen"], ADS_BLOCKS)


# =====================================================================
# 12. kl.load, kl.store, kl.mv
# =====================================================================

def test_transfers():
    section("12. kl.load, kl.store, kl.mv  --  <<KLEE-instruction-load>>, "
            "<<KLEE-instruction-store>>, <<KLEE-instruction-mv>>, <<KLEE-Memory-Alignment>>")

    # admissible States (SGR21, SGR22)
    writable, readable = [], []
    for st in range(64):
        u = fresh()
        provision(u, 0, cipher_pi())
        u.mgmt(0, CFG_EXPORTING)
        u.cls[0].mdh["State"] = st                  # white box
        if trap_of(u.mv_in, 0, 1) is None:
            writable.append(st)
        u.cls[0].mdh["State"] = st
        u.csr_write("klstart", 0)
        if trap_of(u.mv_out, 0) is None:
            readable.append(st)
    check("kl.mv into a CL: exactly States 56, 58, 60 (SGR21)", writable, [56, 58, 60])
    check("kl.mv out of a CL: exactly States 57, 59 (SGR22)", readable, [57, 59])
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    check("kl.store in kl_cfg_provisioning, kl.load in kl_cfg_exporting: illegal",
          (trap_of(u.store, 0, Memory(), BASE),
           (u.mgmt(0, CFG_EXPORTING), trap_of(u.load, 0, Memory(), BASE))[1]),
          ("illegal/2", "illegal/2"))
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    u.csr_write("klstart", 8)
    check("a klstart that is not a multiple of 16 is an illegal instruction",
          (trap_of(u.load, 0, Memory(), BASE), trap_of(u.mv_in, 0, 1)),
          ("illegal/2", "illegal/2"))
    u.csr_write("klstart", 0)
    check("kl.mv on an Unconfigured CL is illegal", trap_of(u.mv_in, 5, 1), "illegal/2")
    check("kl.mv needs Zklmv", trap_of(fresh(zklmv=False).mv_in, 0, 1), "illegal/1")
    check("an emulated kl.load raises an illegal instruction in hardware",
          trap_of(fresh(zklmem_hw=False).load, 0, Memory(), BASE), "illegal/1")

    # alignment and memory exceptions
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    mem = Memory()
    mem.write(BASE, pi_content(cipher_pi()))
    check("a misaligned kl.load address: address-misaligned, nothing transferred",
          (trap_of(u.load, 0, mem, BASE + 4), bytes(u.cls[0].img)), ("load_misaligned", bytes(32)))
    u.csr_write("klstart", 32)
    check("the alignment check applies also to an empty window",
          trap_of(u.load, 0, mem, BASE + 8), "load_misaligned")
    check("klstart >= image_end: kl.load transfers nothing and retires (klstart 0)",
          (u.load(0, mem, BASE), bytes(u.cls[0].img), u.klstart), ("done", bytes(32), 0))
    mem.unmapped.append((BASE + 16, BASE + 32))
    try:
        u.load(0, mem, BASE)
        t = None
    except Trap as e:
        t = (e.tag, e.tval)
    check("a page fault halts precisely: klstart = the prefix-complete point, xtval",
          (t, u.klstart, bytes(u.cls[0].img[:16]) == pi_content(cipher_pi())[:16]),
          (("load_page_fault", BASE + 16), 16, True))
    check("re-execution raises the same fault before any further access",
          (trap_of(u.load, 0, mem, BASE), u.klstart), ("load_page_fault", 16))
    mem.unmapped.clear()
    check("once mapped, the transfer resumes and completes",
          (u.load(0, mem, BASE), bytes(u.cls[0].img)), ("done", pi_content(cipher_pi())))
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    mem.nonidem.append((BASE + 20, BASE + 21))
    try:
        u.load(0, mem, BASE)
        t = None
    except Trap as e:
        t = (e.tag, e.tval)
    check("MMR3: a non-idempotent byte raises an access fault at the offending address, "
          "the prefix committed", (t, u.klstart), (("load_access_fault", BASE + 20), 16))
    mem.nonidem.clear()
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    mem.unmapped.append((BASE + 16, BASE + 32))
    check("under the restart option a fault leaves klstart = 0",
          (trap_of(u.load, 0, mem, BASE, restart=True), u.klstart), ("load_page_fault", 0))
    mem.unmapped.clear()
    check("... and re-execution transfers everything again",
          (u.load(0, mem, BASE), bytes(u.cls[0].img)), ("done", pi_content(cipher_pi())))
    info("MMR3 says re-execution after a non-idempotent access fault raises it again 'before "
         "any component access'; that holds when klstart records the prefix-complete point, but "
         "not literally under the restart option of IRR3, where re-execution transfers the "
         "prefix again first. Modelled per IRR6/IRR8 (prefix committed, klstart = prefix point).")

    u = fresh()
    ready_cipher(u, 0)
    u.mgmt(0, CFG_EXPORTING)
    out = Memory()
    check("a misaligned kl.store address: address-misaligned",
          trap_of(u.store, 0, out, BASE + 2), "store_misaligned")
    out.unmapped.append((BASE + 32, BASE + 48))
    check("kl.store halts at the prefix-complete point on a page fault",
          (trap_of(u.store, 0, out, BASE), u.klstart), ("store_page_fault", 32))
    out.unmapped.clear()
    u.store(0, out, BASE)
    ref = Memory()
    u.store(0, ref, BASE)
    check("the resumed kl.store writes the same image as an uninterrupted one",
          out.read(BASE, 64), ref.read(BASE, 64))
    u.csr_write("klstart", 128)
    check("klstart >= image_size: kl.store transfers nothing and retires",
          (u.store(0, out, BASE), u.klstart), ("done", 0))

    # kl.mv details
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    check("kl.mv past image_end writes nothing and leaves klstart",
          (u.mv_in(0, 1), u.mv_in(0, 2), u.mv_in(0, 3), u.klstart), ("moved", "moved", "nothing", 32))
    u.mgmt(0, CFG_MANAGEMENT_END)
    u.mgmt(0, CFG_EXPORTING)
    vals = [u.mv_out(0) for _ in range(4)]
    check("kl.mv reads SIV then Content; at or beyond image_end it reads zero, klstart stays",
          (vals[0] == u.siv, vals[3], u.klstart), (True, 0, 48))
    vd = bytearray(b"\xEE" * 64)
    u.csr_write("klstart", 32)
    u.vstart = 0
    u.mv_out_vec(0, vd, sew=8)
    check("a vector kl.mv spanning image_end: transferred block, then zero elements, "
          "klstart stops at image_end", (vd[0:16] == v2b(vals[2], 16), bytes(vd[16:]), u.klstart,
                                         u.vstart), (True, bytes(48), 48, 0))
    vd = bytearray(b"\xEE" * 32)
    u.csr_write("klstart", 48)
    check("klstart >= image_end: every element from vstart is zeroed, klstart unchanged",
          (u.mv_out_vec(0, vd), bytes(vd), u.klstart), ("zeros", bytes(32), 48))
    u.csr_write("klstart", 0)
    u.vstart = 4                     # vl = 4 elements of 64 bits
    vd = bytearray(b"\xEE" * 32)
    check("vstart >= vl: no operation, klstart unchanged",
          (u.mv_out_vec(0, vd, sew=64), bytes(vd), u.klstart), ("noop", b"\xEE" * 32, 0))
    u.vstart = 1
    check("vstart * SEW/8 not a multiple of 16 is an illegal instruction",
          trap_of(u.mv_out_vec, 0, bytearray(32), sew=8), "illegal/1")
    u.vstart = 0
    check("vl * SEW/8 not a multiple of 16 is an illegal instruction",
          trap_of(u.mv_out_vec, 0, bytearray(24), sew=8), "illegal/1")
    check("a vector kl.mv needs Zklv", trap_of(fresh(zklv=False).mv_in_vec, 0, bytearray(16)),
          "illegal/1")

    content = pi_content(xof_pi(), 0x10)
    images = []
    for sew in (8, 16, 32, 64):
        w = fresh()
        w.mgmt(0, CFG_PROVISIONING, xof_pi())
        w.vstart = 0
        w.mv_in_vec(0, bytearray(content), sew=sew, halt_after=16)
        halted = (w.klstart, w.vstart)
        w.mv_in_vec(0, bytearray(content), sew=sew)
        images.append((sew, halted, bytes(w.cls[0].img), w.klstart, w.vstart))
    check("an interrupted vector kl.mv records klstart in bytes and vstart in elements, and "
          "resumes to the same image for every SEW",
          images, [(s, (16, 16 // (s // 8)), content, 32, 0) for s in (8, 16, 32, 64)])
    w = fresh()
    w.mgmt(0, CFG_PROVISIONING, xof_pi())
    w.mv_in(0, 0xAB)
    w.csr_write("klstart", 16)
    mem = Memory()
    mem.write(BASE + 16, v2b(0xCD, 16))
    mem.write(BASE, v2b(0xEF, 16))
    w.load(0, mem, BASE)
    check("kl.load after kl.mv: each byte holds the value last written, klstart honoured",
          bytes(w.cls[0].img), v2b(0xAB, 16) + v2b(0xCD, 16))
    w.mv_in(0, 0x77)
    check("kl.mv after kl.load (klstart 0 after the load) overwrites offset 0",
          bytes(w.cls[0].img[:16]), v2b(0x77, 16))


# =====================================================================
# 13. KLIOBUF
# =====================================================================

def test_kliobuf():
    section("13. KLIOBUF  --  <<KLEE-CSR-kliobuflen>>, <<KLEE-CSR-kliobuftop>>, "
            "<<KLEE-iobuf-transfer-window>>")

    u = fresh(maxiobuflen=128)
    check("out of reset: kliobuflen, kliobuftop, klstart 0; klmanagedcr 32",
          [u.csr_read(c) for c in ("kliobuflen", "kliobuftop", "klstart", "klmanagedcr")],
          [0, 0, 0, 32])
    check("kl.input on an unconfigured KLIOBUF raises kl_exc_unconfigured_buffer (GR8)",
          trap_of(u.input_, Memory(), BASE, 16), "unconfigured_buffer")
    u.csr_write("kliobuflen", 64)
    u.kliobuf[0:4] = b"\xFF" * 4
    check("writing kliobuflen sets kliobuftop", u.csr_read("kliobuftop"), 64)
    u.csr_write("kliobuftop", 20)
    u.csr_write("kliobuflen", 64)
    check("re-writing the same kliobuflen zeroes the buffer and resets kliobuftop",
          (bytes(u.kliobuf), u.kliobuftop), (bytes(64), 64))
    u.csr_write("kliobuflen", 1000)
    check("kliobuflen WARL: set to the maximum klmaxiobuflen", u.csr_read("kliobuflen"), 128)
    u.csr_write("kliobuftop", 1000)
    check("kliobuftop WARL: set to the maximum kliobuflen", u.csr_read("kliobuftop"), 128)
    u.csr_write("kliobuftop", 48)
    u.kliobuf[0:4] = b"\x01\x02\x03\x04"
    u.csr_write("kliobuftop", 40)
    check("writing kliobuftop does not alter the buffer", bytes(u.kliobuf[0:4]), b"\x01\x02\x03\x04")
    n = fresh(zklio=False)
    check("without Zklio: klmaxiobuflen reads 0; kliobuflen and kliobuftop are not present",
          (n.csr_read("klmaxiobuflen"), trap_of(n.csr_read, "kliobuflen"),
           trap_of(n.csr_write, "kliobuftop", 1)), (0, "illegal/1", "illegal/1"))
    check("without Zklio kl.input is an illegal instruction",
          trap_of(n.input_, Memory(), BASE, 16), "illegal/1")
    check("klmaxiobuflen is read-only", trap_of(u.csr_write, "klmaxiobuflen", 5), "illegal/1")

    u = fresh()
    u.csr_write("kliobuflen", 64)
    src = bytes((0x10 + 3 * i) & 0xFF for i in range(64))
    mem = Memory()
    mem.write(BASE, src)
    u.csr_write("kliobuftop", 48)
    u.input_(mem, BASE, 64)
    check("Xl > kliobuftop: only the window is transferred",
          (bytes(u.kliobuf[:48]), bytes(u.kliobuf[48:])), (src[:48], bytes(16)))
    u.csr_write("kliobuflen", 64)
    u.input_(mem, BASE, 20)
    check("Xl < kliobuftop: only Xl bytes", (bytes(u.kliobuf[:20]), bytes(u.kliobuf[20:])),
          (src[:20], bytes(44)))
    check("kl.input with a misaligned address is fine (byte-granular)",
          u.input_(mem, BASE + 3, 4), "done")
    for start, xl, label in ((7, 0, "Xl = 0"), (64, 64, "klstart = kliobuftop"),
                             (65, 64, "klstart > kliobuftop"), (30, 20, "klstart >= Xl")):
        u.csr_write("klstart", start)
        check(f"{label}: nothing is transferred; klstart unchanged",
              (u.input_(mem, BASE, xl), u.klstart), ("empty", start))
    u.csr_write("klstart", 100)
    check("kl.output with an empty window likewise", (u.output(Memory(), BASE, 64), u.klstart),
          ("empty", 100))
    info("kl.input and kl.output with an empty window: <<KLEE-CSR-klstart>> says an instruction "
         "with an empty window 'performs no operation' but also that an instruction honouring "
         "klstart writes 0 to it when it retires. This model leaves klstart unchanged, the "
         "reading under which 'no operation' means no state change.")

    # interruption and resumption
    u = fresh()
    u.csr_write("kliobuflen", 64)
    check("kl.input interrupted after 20 bytes: klstart 20",
          (u.input_(mem, BASE, 64, halt_after=20), u.klstart), ("halted", 20))
    check("... only the prefix landed", (bytes(u.kliobuf[:20]), bytes(u.kliobuf[20:])),
          (src[:20], bytes(44)))
    check("... resumption completes and clears klstart",
          (u.input_(mem, BASE, 64), u.klstart, bytes(u.kliobuf)), ("done", 0, src))
    dst = Memory()
    u.output(dst, BASE, 64, halt_after=48)
    check("kl.output interrupted: klstart 48, only the prefix written",
          (u.klstart, dst.read(BASE, 48), dst.read(BASE + 48, 16)), (48, src[:48], bytes(16)))
    u.output(dst, BASE, 64)
    check("... resumed: memory matches the buffer; klstart cleared",
          (dst.read(BASE, 64), u.klstart), (src, 0))
    u.csr_write("kliobuflen", 32)
    u.csr_write("klstart", 8)
    u.input_(mem, BASE, 32)
    check("resumption offsets both sides: memory base + j -> buffer byte j",
          (bytes(u.kliobuf[:8]), bytes(u.kliobuf[8:])), (bytes(8), src[8:32]))
    dst.unmapped.append((BASE + 10, BASE + 11))
    u.csr_write("klstart", 0)
    check("a page fault in kl.output halts at the offending byte",
          (trap_of(u.output, dst, BASE, 32), u.klstart), ("store_page_fault", 10))
    check("the restart option leaves klstart 0",
          (trap_of(u.output, dst, BASE, 32, restart=True), u.klstart), ("store_page_fault", 0))
    check("KLLEN = kliobuftop * 8", u.kliobuftop * 8, 256)


# =====================================================================
# 14. State Management rules
# =====================================================================

def test_sgr():
    section("14. State Management rules  --  <<KLEE-State-management>>")

    # SGR1, SGR9
    u = fresh()
    provision(u, 0, cipher_pi())
    tag = MACHINES[M_CIPHER].verify_tag(u, u.cls[0])
    check("SGR1: a new CC is Ready, readable from _State_ alone", u.getst(0), ST_READY)
    check("SGR9: kl.setst VERIFY lands in Success or Failure, not in the immediate",
          [(u.setst(0, ToyCipher.VERIFY, t), u.getst(0), u.setst(0, ST_READY))[1]
           for t in (tag, tag ^ 1)], [ST_SUCCESS, ST_FAILURE])

    # SGR2
    u = fresh()
    provision(u, 0, cipher_pi())
    out = bytearray(b"\x55" * 16)
    check("SGR2: kl.exec in Ready -> Invalid, output zeroed, klstart cleared",
          (u.exec_(0, "A", vin=bytearray(16), vout=out), u.getst(0), bytes(out), u.klstart),
          ("invalid", ST_INVALID, bytes(16), 0))
    u = fresh()
    provision(u, 0, xof_pi())
    check("SGR2: a Machine may allow kl.exec in Ready",
          (u.exec_(0, "B", vin=bytearray(b"abc")), u.getst(0)), ("done", ToyXof.ABSORB))

    # SGR4, SGR8
    u = fresh()
    ready_cipher(u, 0)
    check("SGR4: kl.setst with the current State's immediate is permitted",
          (u.setst(0, ToyCipher.ENCRYPT, 3), u.getst(0)), ("ok", ToyCipher.ENCRYPT))
    check("SGR8: any Valid State -> Ready is permitted; session state is erased",
          (u.setst(0, ST_READY), u.getst(0), u.getstx(0)), ("ok", ST_READY, 0))
    check("an immediate the Machine does not support -> Invalid",
          [(fresh_ready(), )[0].setst(0, imm) for imm in (5, 45, 65, 127)], ["invalid"] * 4)
    w = fresh()
    provision(w, 0, cipher_pi(MachinePolicy=0b10))
    check("a transition the MachinePolicy does not allow -> Invalid",
          w.setst(0, ToyCipher.ENCRYPT), "invalid")

    # SGR5, SGR6
    for final in (ST_SUCCESS, ST_FAILURE):
        def mk():
            w = fresh()
            provision(w, 0, cipher_pi(SCProtection=1))
            tg = MACHINES[M_CIPHER].verify_tag(w, w.cls[0])
            w.setst(0, ToyCipher.VERIFY, tg if final == ST_SUCCESS else 0)
            return w
        w = mk()
        check(f"SGR6 (State {final}): -> Ready", (w.setst(0, ST_READY), w.getst(0)),
              ("ok", ST_READY))
        w = mk()
        check(f"SGR6 (State {final}): -> Unconfigured", (w.setst(0, 0), w.getst(0)),
              ("cleared", 0))
        w = mk()
        check(f"SGR6 (State {final}): -> an explicit Error State",
              (w.setst(0, ST_PRIV_VIOLATION), w.getst(0)), ("error state", ST_PRIV_VIOLATION))
        w = mk()
        check(f"SGR6 (State {final}): kl.clearads clears the ADS, State unchanged",
              (w.setst(0, CFG_CLEAR_ADS), w.getst(0), w.getmd(0)["AuxDataLen"]),
              ("ads cleared", final, 0))
        w = mk()
        check(f"SGR5 (State {final}): another kl.setst -> Invalid",
              (w.setst(0, ToyCipher.ENCRYPT), w.getst(0)), ("invalid", ST_INVALID))
        w = mk()
        check(f"SGR5 (State {final}): kl.exec -> Invalid",
              (w.exec_(0, "A", vin=bytearray(16), vout=bytearray(16)), w.getst(0)),
              ("invalid", ST_INVALID))
        w = mk()
        check(f"SGR5 (State {final}): kl.mgmt, kl.size, kl.avail, kl.getmd*, kl.clone and "
              "kl.restrict* are permitted",
              (import_(fresh(), 0, export(w, 0)), w.size(k=0) > 16, w.avail(k=0),
               w.getst(0), w.clone(1, 0), w.restrict(0, mdh_new(UsagePolicy=1))),
              (final, True, 1, final, "cloned", "ok"))
    u = fresh()
    provision(u, 0, xof_pi())
    u.exec_(0, "B", vin=bytearray(b"seed"))
    u.setst(0, ToyXof.FINAL)
    o1 = bytearray(4)
    check("SGR5: in Success a XOF may still produce output with kl.exec",
          (u.getst(0), u.exec_(0, "C", vout=o1), u.getmd(0)["MachineUse"]),
          (ST_SUCCESS, "done", 4))

    # SGR12, SGR13
    u = fresh()
    check("SGR12: a usage-controlled instruction on an Unconfigured CL is illegal",
          [trap_of(u.exec_, 0, "D"), trap_of(u.setst, 0, ST_READY),
           trap_of(u.setst, 0, CFG_CLEAR_ADS), trap_of(u.derive, 1, 0, 32)],
          ["illegal/2"] * 4)

    # SGR16
    u = fresh()
    ready_cipher(u, 0)
    u.setst(0, ST_INVALID)
    u.csr_write("kliobuflen", 64)
    u.kliobuf[:] = b"\xAA" * 64
    u.csr_write("klstart", 16)
    check("SGR16: a Form D kl.exec on an Error-State CL zeroes [klstart, kliobuftop)",
          (u.exec_(0, "D"), bytes(u.kliobuf)), ("noop", b"\xAA" * 16 + bytes(48)))
    info("Whether a Form D kl.exec is a substitution 'depends on the operation the CL's State "
         "defines' (<<KLEE-illegal-instruction-grounds>>), and an Error State defines none, so it "
         "is unclear whether such an instruction has a KLIOBUF output window to zero. This model "
         "zeroes [klstart, kliobuftop), the reading that serves the stated purpose of Rule SGR16 "
         "that 'an in-place operation never leaves its input in place of the output it did not "
         "produce'.")
    u = fresh()
    ready_cipher(u, 0)
    u.setst(0, ST_EXPIRED)
    buf = bytearray(b"\xBB" * 32)
    u.vstart = 1
    u.csr_write("klstart", 16)
    check("SGR16: a vector output keeps elements below vstart and zeroes vstart..vl-1",
          (u.exec_(0, "A", vin=buf, vout=buf, sew=128), bytes(buf)),
          ("noop", b"\xBB" * 16 + bytes(16)))

    # SGR18
    u = fresh()
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    check("SGR18: use, cloning from, restricting a Configuration-State CL -> "
          "kl_exc_privilege_violation",
          [trap_of(u.exec_, 0, "D"), trap_of(u.setst, 0, ST_READY),
           trap_of(u.clone, 1, 0), trap_of(u.restrict, 0, mdh_new(UsagePolicy=1))],
          ["privilege_violation"] * 4)
    u.csr_write("klmanagedcr", 32)
    provision(u, 2, cipher_pi())
    u.csr_write("klmanagedcr", 0)
    check("... cloning onto it clears it and releases klmanagedcr",
          (u.clone(0, 2), u.getst(0), u.klmanagedcr), ("cloned", ST_READY, MANAGEDCL_NONE))
    u = fresh()
    u.mgmt(3, CFG_PROVISIONING, cipher_pi())
    check("... a clone naming it as both source and destination performs no operation",
          (u.clone(3, 3), u.getst(3), u.clone(9, 9)), ("noop", CFG_PROVISIONING, "noop"))

    # SGR19 order, pairwise
    def gated(clock=0, **kw):
        """A CL in State ENCRYPT that M-mode may not use and whose date has passed."""
        w = fresh(**kw)
        ready_cipher(w, 0, ExpirationDate=5, UsagePolicy=0b1000)
        w.clock = clock                     # only now, so that the setst is not gated
        return w
    w = gated(clock=10)
    w.setst(0, ST_INVALID)
    check("SGR19: the Error State precedes the UsagePolicy and the expiration",
          (w.exec_(0, "A", vin=bytearray(16), vout=bytearray(16)), w.getst(0)),
          ("noop", ST_INVALID))
    w = fresh()
    w.mgmt(0, CFG_PROVISIONING, cipher_pi())
    check("SGR19: a Configuration State precedes a forbidden substitution",
          trap_of(w.exec_, 0, "B", vin=bytearray(16)), "privilege_violation")
    w = gated(clock=10)
    check("SGR19: a forbidden substitution (Form B for Form A) precedes the UsagePolicy",
          trap_of(w.exec_, 0, "B", vin=bytearray(16)), "illegal/2")
    w = gated(clock=10, zklio=False)
    check("SGR19: a substitution without Zklio is a forbidden substitution",
          trap_of(w.exec_, 0, "D"), "illegal/2")
    w = gated(clock=10)
    check("SGR19: the UsagePolicy precedes the expiration (the CL survives)",
          (trap_of(w.exec_, 0, "A", vin=bytearray(16), vout=bytearray(16)), w.getst(0)),
          ("privilege_violation", ToyCipher.ENCRYPT))
    w = gated(clock=10)
    w.mode = "S"
    check("SGR19: the expiration precedes an unconfigured KLIOBUF",
          (w.exec_(0, "D"), w.getst(0)), ("expired", ST_EXPIRED))
    w = fresh()
    ready_cipher(w, 0)
    check("SGR19: an unconfigured KLIOBUF precedes the Machine's rules (KLLEN = 0 would "
          "invalidate under MGR2)", (trap_of(w.exec_, 0, "D"), w.getst(0)),
          ("unconfigured_buffer", ToyCipher.ENCRYPT))
    w = fresh()
    provision(w, 0, cipher_pi())
    check("a Form D kl.exec in a State that defines no operation is native, needs no KLIOBUF, "
          "and falls to the Machine's rules (SGR2)",
          (w.exec_(0, "D"), w.getst(0)), ("invalid", ST_INVALID))

    # SGR20
    rows = []
    for st in sorted(CONFIG_STATES):
        w = fresh()
        provision(w, 0, cipher_pi())
        w.mgmt(0, CFG_EXPORTING)
        w.cls[0].mdh["State"] = st                  # white box
        w.cls[0].img = bytearray(64)
        rows.append((st, trap_of(w.size, k=0), trap_of(w.avail, k=0), trap_of(w.getmd, 0),
                     trap_of(w.getst, 0), trap_of(w.setst, 0, ST_EXPIRED)))
        w = fresh()
        w.mgmt(0, CFG_PROVISIONING, cipher_pi())
        rows.append((st, trap_of(w.setst, 0, 0), trap_of(w.clearall), None, None, None))
    check("SGR20: kl.size, kl.avail, kl.getmd*, kl.getst, an Error-State or clearing kl.setst, "
          "kl.clear and kl.clearall are allowed in every Partial State",
          [r[1:] for r in rows], [(None,) * 5] * len(rows))
    w = fresh()
    w.mgmt(0, CFG_PROVISIONING, cipher_pi())
    check("SGR20: an Error-State kl.setst on the managed CL releases klmanagedcr",
          (w.setst(0, ST_INVALID), w.klmanagedcr), ("error state", 32))

    # kl.clear, kl.clearall
    w = fresh()
    ready_cipher(w, 0)
    w.csr_write("klstart", 32)
    w.csr_write("klmanagedcr", 0)
    check("kl.clear leaves klstart unchanged; klmanagedcr naming a CL not under management "
          "stays", (w.setst(0, 0, aux=5, form="B"), w.klstart, w.klmanagedcr, w.clf_free()),
          ("cleared", 32, 0, w.clf_total))
    w = fresh()
    ready_cipher(w, 0)
    w.mgmt(1, CFG_IMPORTING, cipher_pi(State=1))
    w.csr_write("kliobuflen", 64)
    w.csr_write("klstart", 16)
    w.siv = 3
    check("kl.clearall: every CL Unconfigured, KLIOBUF zeroed, the CSRs and registers reset",
          (w.setst("X0", 0), [w.getst(k) for k in range(32)], w.kliobuflen, w.kliobuftop,
           bytes(w.kliobuf), w.klstart, w.klmanagedcr, w.siv, w.clf_free()),
          ("cleared all", [0] * 32, 0, 0, b"", 0, 32, 0, w.clf_total))
    check("kl.setst through X0 other than Form A #0 is reserved",
          (trap_of(w.setst, "X0", 0, form="B"), trap_of(w.setst, "X0", 1)),
          ("illegal/1", "illegal/1"))
    check("GR1: an indirect CL index outside [0..31] is an illegal instruction",
          (trap_of(w.getmd, 32), trap_of(w.setst, 40, 0)), ("illegal/1", "illegal/1"))

    # kl.clone
    w = fresh()
    check("kl.clone from an Unconfigured CL is an illegal instruction",
          trap_of(w.clone, 1, 0), "illegal/2")
    ready_cipher(w, 0, SCProtection=1)
    check("kl.clone makes a perfect copy",
          (w.clone(1, 0), w.getmd(1), w.cls[1].c1, w.cls[1].c2, w.cls[1].alloc),
          ("cloned", w.getmd(0), w.cls[0].c1, w.cls[0].c2, w.cls[0].alloc))
    check("... equivalent to an export and an import",
          (import_(w, 2, export(w, 0)), w.getmd(2), w.cls[2].c1), (ToyCipher.ENCRYPT, w.getmd(1),
                                                                   w.cls[1].c1))
    cap = MACHINES[M_CIPHER].clf_capacity(cipher_pi(SCProtection=1))
    t = fresh(clf_total=2 * cap)
    ready_cipher(t, 0, SCProtection=1)
    ready_cipher(t, 1, SCProtection=1)
    check("kl.clone counts the capacity the destination frees",
          (t.clone(1, 0), t.clf_free()), ("cloned", 0))
    before = t.getmd(2)
    check("insufficient capacity: kl_exc_out_of_memory, destination unchanged",
          (trap_of(t.clone, 2, 0), t.getmd(2)), ("out_of_memory", before))
    check("clone and restrict give each process a narrower copy (the informative use case)",
          (t.restrict(1, mdh_new(MachinePolicy=0b01)), t.getmd(1)["MachinePolicy"],
           t.getmd(0)["MachinePolicy"]), ("ok", 1, 3))

    # GR5 table: which instructions modify klstart
    w = fresh()
    ready_cipher(w, 0)
    w.csr_write("klstart", 16)
    w.vstart = 16
    for label, fn in (("kl.getmd", lambda: w.getmd(0)), ("kl.size", lambda: w.size(k=0)),
                      ("kl.avail", lambda: w.avail(k=0)),
                      ("kl.restrict", lambda: w.restrict(0, mdh_new(UsagePolicy=1))),
                      ("kl.clone", lambda: w.clone(1, 0)),
                      ("kl.setst", lambda: w.setst(0, ToyCipher.ENCRYPT, 1))):
        fn()
        check(f"{label} leaves klstart unchanged", w.klstart, 16)


def fresh_ready():
    u = fresh()
    provision(u, 0, cipher_pi())
    return u


# =====================================================================
# 15. kl.exec and klstart
# =====================================================================

def test_exec_klstart():
    section("15. kl.exec and klstart  --  <<KLEE-CSR-klstart>>, <<KLEE-resumability>>")

    pt = bytes((0x61 + i) & 0xFF for i in range(64))
    ref = fresh()
    ready_cipher(ref, 0)
    whole = bytearray(pt)
    ref.exec_(0, "A", vin=whole, vout=whole)

    for sew in (8, 16, 32):
        u = fresh()
        ready_cipher(u, 0)
        buf = bytearray(pt)
        r = u.exec_(0, "A", vin=buf, vout=buf, sew=sew, halt_after=32)
        check(f"SEW={sew}: an interrupted kl.exec commits whole blocks; klstart 32, "
              f"vstart {32 // (sew // 8)}", (r, u.klstart, u.vstart), ("halted", 32, 32 // (sew // 8)))
        u.exec_(0, "A", vin=buf, vout=buf, sew=sew)
        check(f"SEW={sew}: resumption produces the uninterrupted output and state",
              (bytes(buf), u.cls[0].c1, u.klstart, u.vstart), (bytes(whole), ref.cls[0].c1, 0, 0))
    u = fresh()
    ready_cipher(u, 0)
    buf = bytearray(pt)
    u.exec_(0, "A", vin=buf, vout=buf, halt_after=32)
    u.csr_write("klstart", 16)
    check("klstart != vstart * SEW/8 at issue is an illegal instruction",
          trap_of(u.exec_, 0, "A", vin=buf, vout=buf), "illegal/2")
    u.setst(1, 0)
    u.cls[0].mdh["State"] = ST_INVALID     # white box: the check precedes the Error State
    check("... evaluated before the Error-State no-op of SGR19",
          trap_of(u.exec_, 0, "A", vin=buf, vout=buf), "illegal/2")
    u = fresh()
    ready_cipher(u, 0)
    buf = bytearray(pt)
    u.exec_(0, "A", vin=buf, vout=buf, halt_after=32)
    u.csr_write("klstart", 0)
    u.vstart = 0
    u.exec_(0, "A", vin=buf, vout=buf)
    check_true("writing 0 to klstart after committed blocks re-applies their state effects "
               "(why software must not force a restart)", bytes(buf) != bytes(whole))

    u = fresh()
    ready_cipher(u, 0)
    u.csr_write("klstart", 8)
    u.vstart = 8
    buf = bytearray(pt)
    check("a klstart that is not an interruption point, input operand -> Invalid",
          (u.exec_(0, "A", vin=buf, vout=buf), u.getst(0)), ("invalid", ST_INVALID))
    u = fresh()
    provision(u, 0, cipher_pi())
    ready = u
    ready.setst(0, ToyCipher.ENCRYPT)
    ready.csr_write("klstart", 64)
    ready.vstart = 64
    buf = bytearray(pt)
    check("klstart = VL * SEW/8: an empty window, no operation",
          (ready.exec_(0, "A", vin=buf, vout=buf), bytes(buf), ready.getst(0)),
          ("empty", pt, ToyCipher.ENCRYPT))
    info("An empty kl.exec window: <<KLEE-CSR-klstart>> evaluates the interruption-point check "
         "before the empty-window rule, and defines interruption points as multiples of the "
         "granularity 'within the transfer window'. Read with an exclusive window end, every "
         "empty window of an input operand would be Invalid and the empty-window rule would "
         "never apply to kl.exec. This model takes the window end as an interruption point, so "
         "klstart = VL x SEW/8 is a no-op and a larger value is Invalid.")

    # KLIOBUF substitution
    u = fresh()
    ready_cipher(u, 0)
    u.csr_write("kliobuflen", 64)
    u.kliobuf[:] = pt
    check("a Form D substitution of Form A works in place on [0, kliobuftop)",
          (u.exec_(0, "D"), bytes(u.kliobuf)), ("done", bytes(whole)))
    u = fresh()
    ready_cipher(u, 0)
    u.csr_write("kliobuflen", 40)
    check("kliobuftop not a multiple of the granularity, input operand -> Invalid",
          (u.exec_(0, "D"), u.getst(0)), ("invalid", ST_INVALID))
    u = fresh()
    provision(u, 0, xof_pi())
    u.exec_(0, "B", vin=bytearray(b"x"))
    u.setst(0, ToyXof.FINAL)
    u.csr_write("kliobuflen", 16)
    u.csr_write("klstart", 20)
    before = snapshot(u)
    check("an output-only substitution with an invalid klstart performs no operation",
          (u.exec_(0, "D"), snapshot(u) == before), ("noop", True))
    u.csr_write("klstart", 0)
    check("an output-only substitution writes [klstart, kliobuftop)",
          (u.exec_(0, "D"), u.getmd(0)["MachineUse"]), ("done", 16))
    check("Forms A-C of kl.exec need Zklv", trap_of(fresh(zklv=False).exec_, 0, "A"), "illegal/1")


# =====================================================================
# 16. ExpirationDate
# =====================================================================

def test_expiration():
    section("16. _ExpirationDate_  --  <<KLEE-Metadata-expiration-date>>")

    def exp_unit(clock, ed=1000, **kw):
        u = fresh(clock=0, **kw)
        ready_cipher(u, 0, ExpirationDate=ed, SCProtection=1)
        u.clock = clock
        return u

    u = exp_unit(2000)
    out = bytearray(b"\x11" * 16)
    check("kl.exec on an expired CL: Error State Expired, no operation, no exception",
          (u.exec_(0, "A", vin=bytearray(16), vout=out), u.getst(0), bytes(out)),
          ("expired", ST_EXPIRED, bytes(16)))
    check("... with the Error-State effects", (u.cls[0].c1, u.getmd(0)["AuxDataLen"],
                                               u.getmd(0)["ExpirationDate"]), (b"", 0, 1000))
    u = exp_unit(2000)
    check("a usage-controlled kl.setst on an expired CL -> Expired",
          (u.setst(0, ST_READY), u.getst(0)), ("expired", ST_EXPIRED))
    u = exp_unit(2000)
    check("kl.clearads is a usage-controlled kl.setst and is an evaluation point",
          (u.setst(0, CFG_CLEAR_ADS), u.getst(0)), ("expired", ST_EXPIRED))
    u = exp_unit(1000)
    check("the CC expires at the stated hour", u.setst(0, ST_READY), "expired")
    u = exp_unit(999)
    check("one hour earlier it is usable", u.setst(0, ToyCipher.ENCRYPT, 1), "ok")
    u = exp_unit(-50, ed=1)
    check("a clock reading before the epoch converts to 0", u.setst(0, ST_READY), "ok")
    u = fresh(clock=1 << 30)
    ready_cipher(u, 0)
    check("ExpirationDate 0 never expires", u.setst(0, ST_READY), "ok")

    buf = bytearray(64)
    u = exp_unit(0)
    u.exec_(0, "A", vin=buf, vout=buf, halt_after=32)
    u.clock = 5000
    check("a resumption point is an evaluation point",
          (u.exec_(0, "A", vin=buf, vout=buf), u.getst(0), u.klstart), ("expired", ST_EXPIRED, 0))

    u = exp_unit(5000)
    img = export(u, 0)
    check("management is not an evaluation point (export, kl.size, kl.getmd)",
          (u.getst(0), len(img)), (ToyCipher.ENCRYPT, u.size(k=0)))
    v = fresh(clock=5000)
    check("importing an expired CC is not an evaluation point", import_(v, 0, img),
          ToyCipher.ENCRYPT)
    check("kl.clone and kl.restrict* are not evaluation points",
          (u.clone(1, 0), u.restrict(1, mdh_new(ExpirationDate=5)), u.getst(1)),
          ("cloned", "ok", ToyCipher.ENCRYPT))
    check("kl.clear of an expired CL simply clears it", (u.setst(0, 0), u.getst(0)),
          ("cleared", 0))
    v = fresh(clock=5000)
    v.mgmt(0, CFG_PROVISIONING, cipher_pi(ExpirationDate=10))
    check("provisioning an already expired CC completes in Ready",
          (v.mgmt(0, CFG_MANAGEMENT_END), v.getst(0)), ("completed", ST_READY))
    v.mgmt(1, CFG_IMPORTING, cipher_pi(State=2, ExpirationDate=10))
    check("a CL not in a Valid State is not evaluated",
          (trap_of(v.exec_, 1, "D"), v.getst(1)), ("privilege_violation", CFG_IMPORTING))
    w = exp_unit(5000)
    w.mode = "M"
    w.cls[0].mdh["UsagePolicy"] = 0b1000
    check("the UsagePolicy is checked before the expiration (SGR19)",
          (trap_of(w.setst, 0, ST_READY), w.getst(0)), ("privilege_violation", ToyCipher.ENCRYPT))
    n = fresh(zklexpire=False, clock=1 << 30)
    check("without Zklexpire a non-zero ExpirationDate never reaches a CL",
          (n.mgmt(0, CFG_PROVISIONING, cipher_pi(ExpirationDate=1)),
           ready_cipher(n, 1).restrict(1, mdh_new(ExpirationDate=1))), ("invalid", "invalid"))


# =====================================================================
# 17. kl.derive
# =====================================================================

def test_derive():
    section("17. kl.derive, generic gates  --  <<KLEE-instruction-derive>>")

    def pair(**kw):
        u = fresh(**kw)
        provision(u, 0, xof_pi())
        u.exec_(0, "B", vin=bytearray(b"shared secret"))
        u.setst(0, ToyXof.FINAL)
        provision(u, 1, cipher_pi())
        return u

    u = pair()
    probe = fresh()
    provision(probe, 0, xof_pi())
    probe.exec_(0, "B", vin=bytearray(b"shared secret"))
    probe.setst(0, ToyXof.FINAL)
    expect = bytearray(32)
    probe.exec_(0, "C", vout=expect)
    check("a XOF output in Success moves into a Ready cipher's key field",
          (u.derive(1, 0, 32), u.cls[1].c1[:32], u.getmd(0)["MachineUse"], u.getst(1)),
          ("transferred", bytes(expect), 32, ST_READY))
    u = pair()
    check("the source advances as kl.exec would; a longer length fills only the field",
          (u.derive(1, 0, 40), u.getmd(0)["MachineUse"]), ("transferred", 32))
    u = pair()
    check("an effective length below the pair's minimum invalidates the destination",
          (u.derive(1, 0, 16), u.getst(1), u.getst(0)), ("invalid", ST_INVALID, ST_SUCCESS))
    u = pair()
    check("equal CL indices are an illegal instruction (first group)",
          trap_of(u.derive, 0, 0, 32), "illegal/1")
    u = pair()
    u.setst(1, ST_EXPIRED)
    check("an Error State on either endpoint makes the instruction a no-op",
          (u.derive(1, 0, 32), u.getmd(0)["MachineUse"]), ("noop", 0))
    u = pair()
    u.setst(0, 0)
    check("an Unconfigured endpoint is an illegal instruction", trap_of(u.derive, 1, 0, 32),
          "illegal/2")
    u = pair()
    u.mgmt(1, CFG_EXPORTING)
    check("a Configuration-State endpoint raises kl_exc_privilege_violation",
          trap_of(u.derive, 1, 0, 32), "privilege_violation")
    u = pair()
    u.cls[1].mdh["UsagePolicy"] = 0b1000
    check("each endpoint's UsagePolicy is evaluated", trap_of(u.derive, 1, 0, 32),
          "privilege_violation")
    u = pair()
    u.cls[0].mdh["ExpirationDate"] = 1
    u.cls[1].mdh["ExpirationDate"] = 1
    u.clock = 9
    check("both endpoints are checked for expiration",
          (u.derive(1, 0, 32), u.getst(0), u.getst(1)), ("expired", ST_EXPIRED, ST_EXPIRED))
    u = pair()
    u.setst(1, ToyCipher.ENCRYPT, 1)
    check("a key destination not in Ready invalidates the destination only",
          (u.derive(1, 0, 32), u.getst(1), u.getst(0)), ("invalid", ST_INVALID, ST_SUCCESS))
    u = pair()
    tg = MACHINES[M_CIPHER].verify_tag(u, u.cls[1])
    u.setst(1, ToyCipher.VERIFY, tg)
    check("a destination in Success is not allowed (SGR5)",
          (u.derive(1, 0, 32), u.getst(1)), ("invalid", ST_INVALID))
    u = pair()
    u.setst(0, ST_READY)
    check("a source not able to export invalidates the source",
          (u.derive(1, 0, 32), u.getst(0), u.getst(1)), ("invalid", ST_INVALID, ST_READY))
    u = pair()
    provision(u, 2, sig_pi())
    check("a pair the architecture does not list invalidates both CLs",
          (u.derive(2, 0, 32), u.getst(0), u.getst(2)), ("invalid", ST_INVALID, ST_INVALID))
    u = pair()
    provision(u, 3, cipher_pi(KeyType=1), skid_content(SKID_A))
    check("a field configured by a SKID is never importable",
          (u.derive(3, 0, 32), u.getst(3)), ("invalid", ST_INVALID))
    u = pair()
    provision(u, 4, xof_pi())
    check("length 0 with a zero minimum transfers nothing and changes no state",
          (u.derive(4, 0, 0), u.getst(4), u.getmd(0)["MachineUse"]), ("nothing", ST_READY, 0))
    check("a XOF destination absorbs the bytes",
          (u.derive(4, 0, 5), u.getst(4), u.getmd(0)["MachineUse"]),
          ("transferred", ToyXof.ABSORB, 5))
    info("kl.derive with length = 0 'transfers nothing and, if the checks above pass, changes no "
         "state'; with a pair whose minimum is non-zero the third check fails first, so this "
         "model invalidates the destination (toy cipher key pair) and leaves the state alone only "
         "for a pair with minimum 0.")


# =====================================================================
# 18. Error Handling Architecture, CSK, KLS, Off gate
# =====================================================================

def test_error_architecture():
    section("18. Error Handling  --  <<KLEE-error-architecture>>, <<KLEE-exception-codes>>, "
            "<<KLEE-CSK-requirements>>, <<KLEE-CSR-lclstatus>>")

    # without the Privileged Architecture (an M-mode-only hart)
    u = fresh(priv=False)
    u.csr_write("klstart", 16)
    check("no Privileged Architecture: an unsupported opening -> Error State Unsupported, "
          "other fields zero, klstart cleared",
          (u.mgmt(0, CFG_PROVISIONING, mdh_new(Machine=M_ABSENT, MachinePolicy=1)),
           u.getmd(0), u.klstart, u.klmanagedcr),
          ("unsupported", mdh_new(State=ST_UNSUPPORTED), 0, 32))
    u = fresh(priv=False, clf_total=10)
    check("... insufficient capacity -> Error State Out of Memory",
          (u.mgmt(0, CFG_IMPORTING, cipher_pi(State=1)), u.getmd(0)),
          ("out_of_memory", mdh_new(State=ST_OUT_OF_MEMORY)))
    u = fresh(priv=False)
    ready_cipher(u, 0, UsagePolicy=0b1000)
    check("... a Usage Control violation -> Error State Privilege Violation, content cleared",
          (u.exec_(0, "A", vin=bytearray(16), vout=bytearray(16)), u.getst(0), u.cls[0].c1),
          ("error", ST_PRIV_VIOLATION, b""))
    u = fresh(priv=False)
    u.mgmt(0, CFG_PROVISIONING, cipher_pi())
    check("... cloning a Configuration-State source: the source takes the Error State",
          (u.clone(1, 0), u.getst(0), u.getst(1), u.klmanagedcr),
          ("error", ST_PRIV_VIOLATION, 0, 32))
    cap = MACHINES[M_CIPHER].clf_capacity(cipher_pi())
    u = fresh(priv=False, clf_total=cap)
    provision(u, 0, cipher_pi())
    u.mgmt(1, CFG_IMPORTING, cipher_pi(State=ST_EXPIRED))
    check("... a clone without capacity: the destination takes Out of Memory",
          (u.clone(2, 0), u.getst(2)), ("error", ST_OUT_OF_MEMORY))
    check("... a restrict needing capacity: the CL takes Out of Memory",
          (u.restrict(0, mdh_new(SCProtection=2)), u.getst(0)), ("error", ST_OUT_OF_MEMORY))
    u = fresh(priv=False, csk=0)
    check("... no CSK and an unconfigured KLIOBUF raise illegal instructions",
          (trap_of(u.getmd, 0), trap_of(fresh(priv=False).input_, Memory(), BASE, 1)),
          ("illegal/2", "illegal/2"))

    # with it: the handler's duty for an unresolvable exception
    u = fresh()
    ml = mdh_new(Machine=M_ABSENT, MachinePolicy=1, UsagePolicy=3)
    t = trap_of(u.mgmt, 7, CFG_PROVISIONING, ml)
    check("the handler cannot set the Error State with kl.setst on the Unconfigured CL",
          (t, u.setst(7, ST_UNSUPPORTED), u.getst(7)), ("unsupported", "noop", 0))
    check("... it uses the short import, which installs the MDH it chooses",
          (u.mgmt(7, CFG_IMPORTING, dict(ml, State=ST_UNSUPPORTED)), u.getmd(7)),
          ("short import", dict(ml, State=ST_UNSUPPORTED)))
    u = fresh()
    ready_cipher(u, 0, UsagePolicy=0b1000)
    before = snapshot(u)
    check("the state change rule: kl_exc_privilege_violation changes no KLEE state",
          (trap_of(u.exec_, 0, "A", vin=bytearray(16), vout=bytearray(16)),
           snapshot(u) == before), ("privilege_violation", True))
    info("Without the Privileged Architecture a failed opening leaves an Error-State MDH whose "
         "other fields are zero, whereas a handler with it installs any MDH it chooses through "
         "the short import; the two configurations therefore report different MDHs for the "
         "same failure. Harmless, noted for completeness.")

    # CSK
    u = fresh(csk=0)
    check("no CSK: KLEE instructions and CSRs raise kl_exc_no_csk",
          [trap_of(u.getmd, 0), trap_of(u.clearall), trap_of(u.csr_read, "klstart"),
           trap_of(u.input_, Memory(), BASE, 1)], ["no_csk"] * 4)
    check("no CSK: the read-only identification CSRs remain readable",
          [u.csr_read(c) for c in Unit.RO_ID], [u.vendorid, u.archid, u.impid, 256])

    # KLS Off
    u = fresh()
    u.kls_off = True
    check("a KLS field Off: instructions and CSRs raise an illegal instruction (first group)",
          [trap_of(u.getmd, 0), trap_of(u.csr_write, "klstart", 0),
           trap_of(u.mgmt, 0, CFG_PROVISIONING, cipher_pi())], ["illegal/1"] * 3)
    check("... except the read-only identification CSRs", u.csr_read("klmimpid"), u.impid)

    # the Off gate of *lclstatus, compactly (mlclstatus in effect below M-mode)
    u = fresh()
    ready_cipher(u, 0)
    u.mode = "S"
    u.lcr[0] = "off"
    check("an access to an Off CL raises kl_exc_CL_off (kl.getmd*, kl.size, kl.exec, "
          "kl.restrict, kl.clone source, export, kl.load, kl.mv)",
          [trap_of(u.getmd, 0), trap_of(u.size, k=0), trap_of(u.exec_, 0, "D"),
           trap_of(u.restrict, 0, 0, "h"), trap_of(u.clone, 1, 0),
           trap_of(u.mgmt, 0, CFG_EXPORTING), trap_of(u.load, 0, Memory(), BASE),
           trap_of(u.mv_in, 0, 1)], ["CL_off"] * 8)
    check("the first illegal-instruction group precedes it", trap_of(u.setst, 0, 46), "illegal/1")
    u.lcr[5] = "off"
    check("it precedes the second group (kl.clone from an Off, Unconfigured CL)",
          trap_of(u.clone, 1, 5), "CL_off")
    check("an Off source is not exempt, whichever CL is the destination",
          trap_of(u.clone, 5, 0), "CL_off")
    u.lcr[0] = "clean"
    check("kl.clone naming an Off CL as destination executes and sets it Dirty",
          (u.clone(5, 0), u.lcr[5]), ("cloned", "dirty"))
    u.lcr[6] = "off"
    check("kl.clear of an Off CL executes and sets Dirty even if already Unconfigured",
          (u.setst(6, 0), u.lcr[6]), ("cleared", "dirty"))
    u.lcr[7] = "clean"
    check("kl.clear of an Unconfigured, accessible CL need not set Dirty",
          (u.setst(7, 0), u.lcr[7]), ("cleared", "clean"))
    u.lcr[8] = "off"
    check("an opening provisioning into an Off CL executes and sets Dirty",
          (u.mgmt(8, CFG_PROVISIONING, cipher_pi()), u.lcr[8]), ("opened", "dirty"))
    u.lcr[9] = "off"
    check("an exempted opening that raises before zeroizing sets no field",
          (trap_of(u.mgmt, 9, CFG_PROVISIONING, cipher_pi()), u.lcr[9]), ("illegal/2", "off"))
    u.csr_write("klmanagedcr", 32)
    check("an exempted opening that zeroizes and then raises has set Dirty",
          (trap_of(u.mgmt, 9, CFG_PROVISIONING, mdh_new(Machine=M_ABSENT)), u.lcr[9]),
          ("unsupported", "dirty"))
    u.lcr[10] = "off"
    check("kl.clearall executes over Off CLs and sets them Dirty",
          (u.clearall(), u.lcr[10]), ("cleared all", "dirty"))
    u.mode = "M"
    u.lcr[0] = "off"
    check("in M-mode no *lclstatus field is in effect", trap_of(u.getmd, 0), None)


# =====================================================================
# 19. Reset, and context save and restore
# =====================================================================

def build_context(u):
    """A hart state with a CL whose import was interrupted, plus assorted CLs."""
    ready_cipher(u, 0, SCProtection=1)
    u.exec_(0, "A", vin=bytearray(32), vout=bytearray(32))
    provision(u, 1, cipher_pi())
    u.setst(1, ST_EXPIRED)
    provision(u, 7, sig_pi())
    u.restrict(7, mdh_new(UsagePolicy=0b0001), "h")
    # an abandoned provisioning, not the managed CL
    u.mgmt(5, CFG_PROVISIONING, xof_pi())
    u.mv_in(5, 0x1111)
    u.csr_write("klmanagedcr", 32)
    # the managed CL: an import interrupted after SIV, IMPQUAL, SIV2 and one block
    src = fresh()
    provision(src, 0, cipher_pi(SCProtection=1, Locality=loc(boot=1)))
    src.setst(0, ToyCipher.DECRYPT, 3)
    scc = export(src, 0)
    base_ml = mdh_unpack(b2v(scc[0:16]))
    u.mgmt(2, CFG_IMPORTING, base_ml)
    mem = Memory()
    mem.write(BASE, scc[16:])
    u.load(2, mem, BASE, halt_after=64)
    # the KLIOBUF
    u.csr_write("klstart", 0)
    u.csr_write("kliobuflen", 64)
    data = Memory()
    data.write(BASE, bytes((5 * i + 1) & 0xFF for i in range(64)))
    u.input_(data, BASE, 64)
    u.csr_write("kliobuftop", 40)
    u.csr_write("klstart", 64)                 # the interrupted kl.load's progress
    return src, base_ml, mem


def save_context(u, managed_first=True):
    """<<KLEE-state-save-and-restore-order>>, save order."""
    ctx = {"klstart": u.csr_read("klstart"), "klmanagedcr": u.csr_read("klmanagedcr")}
    ctx["kliobuflen"] = u.csr_read("kliobuflen")
    ctx["kliobuftop"] = u.csr_read("kliobuftop")
    if ctx["kliobuflen"]:
        u.csr_write("klstart", 0)
        u.csr_write("kliobuftop", ctx["kliobuflen"])
        mem = Memory()
        u.output(mem, BASE, ctx["kliobuflen"])
        ctx["kliobuf"] = mem.read(BASE, ctx["kliobuflen"])
    images = {}
    mc = ctx["klmanagedcr"]
    if mc < 32 and u.getmd(mc)["State"] != ST_UNCONFIGURED:
        images[mc] = export(u, mc)
    for k in range(32):
        if k != mc and u.getst(k) != ST_UNCONFIGURED:
            # 32 before each export: a CL left in a Configuration State makes its own
            # nested export write its number to klmanagedcr again
            u.csr_write("klmanagedcr", 32)
            images[k] = export(u, k)
    u.csr_write("klmanagedcr", 32)
    ctx["images"] = images
    return ctx


def restore_context(u, ctx, managed_first=False):
    """<<KLEE-state-save-and-restore-order>>, restore order (`managed_first` inverts it,
    for a negative control)."""
    mc = ctx["klmanagedcr"]
    order = [k for k in ctx["images"] if k != mc]
    if mc in ctx["images"]:
        order = [mc] + order if managed_first else order + [mc]
    for k in order:
        u.csr_write("klmanagedcr", 32)
        import_(u, k, ctx["images"][k])
        if k != mc:
            u.csr_write("klmanagedcr", 32)
    u.csr_write("kliobuflen", ctx["kliobuflen"])
    if ctx["kliobuflen"]:
        u.csr_write("klstart", 0)
        u.csr_write("kliobuftop", ctx["kliobuflen"])
        mem = Memory()
        mem.write(BASE, ctx["kliobuf"])
        u.input_(mem, BASE, ctx["kliobuflen"])
    u.csr_write("kliobuftop", ctx["kliobuftop"])
    u.csr_write("klmanagedcr", mc)
    u.csr_write("klstart", ctx["klstart"])


def test_save_restore():
    section("19. Reset, context save and restore  --  <<KLEE-out-of-reset-unpriv>>, "
            "<<KLEE-state-save-and-restore-order>>")

    u = fresh()
    ready_cipher(u, 0)
    u.csr_write("kliobuflen", 16)
    u.siv = 4
    u.reset()
    check("out of reset: CLs Unconfigured, KLIOBUF unconfigured, klstart 0, klmanagedcr 32, "
          "registers zero",
          ([u.getst(k) for k in range(32)], u.kliobuflen, u.kliobuftop, u.klstart,
           u.klmanagedcr, (u.siv, u.impqual, u.siv2)),
          ([0] * 32, 0, 0, 0, 32, (0, 0, 0)))
    check("klmanagedcr: writing 33 or more leaves it unchanged; 0-32 are written",
          (u.csr_write("klmanagedcr", 33), u.klmanagedcr, u.csr_write("klmanagedcr", 4),
           u.klmanagedcr, u.csr_write("klmanagedcr", 1 << 40), u.klmanagedcr),
          (None, 32, None, 4, None, 4))

    u = fresh()
    src, base_ml, mem = build_context(u)
    check("the context: K2 is being imported and is the managed CL; klstart 64",
          (u.getst(2), u.klmanagedcr, u.klstart, u.getst(5)),
          (CFG_IMPORTING, 2, 64, CFG_PROVISIONING))
    before = snapshot(u)
    ctx = save_context(u)
    check("the save leaves the managed CL in its Configuration State",
          (u.getst(2), u.getst(5), u.getst(0)), (CFG_IMPORTING, CFG_PROVISIONING,
                                                 ToyCipher.ENCRYPT))
    check("the saved images: the managed CL's SCC-shaped PCCC first, an Error State as 16 bytes",
          (list(ctx["images"])[0], len(ctx["images"][1]), sorted(ctx["images"])),
          (2, 16, [0, 1, 2, 5, 7]))
    spec_note("<<KLEE-state-save-and-restore-order>> writes 32 to klmanagedcr once, before "
              "saving the other CLs, but the export of a CL that is itself in a Configuration "
              "State (one whose management software abandoned by writing 32) writes that CL's "
              "number to klmanagedcr again, so the next export raises an illegal-instruction "
              "exception. The save order needs the same 'before and after each' wording the "
              "restore order already has for imports.")
    # another context runs, then this one is switched back in
    u.clearall()
    provision(u, 2, xof_pi())
    u.csr_write("kliobuflen", 16)
    u.csr_write("klmanagedcr", 3)
    u.csr_write("klstart", 8)
    u.siv = 99
    u.clearall()
    restore_context(u, ctx)
    check("the restore reproduces the architectural state exactly", snapshot(u), before)
    u.load(2, mem, BASE)
    u.mgmt(2, CFG_MANAGEMENT_END, base_ml)
    check("the interrupted import then completes and authenticates",
          (u.getmd(2), u.cls[2].c1, u.cls[2].c2), (src.getmd(0), src.cls[0].c1, src.cls[0].c2))
    u.csr_write("klstart", 16)
    for off in range(16, 32, 16):
        u.mv_in(5, 0x2222)
    u.mgmt(5, CFG_MANAGEMENT_END)
    check("the abandoned provisioning can be resumed and completed",
          (u.getst(5), u.cls[5].c1), (ST_READY, v2b(0x1111, 16) + v2b(0x2222, 16)))

    # a Form A (KLIOBUF) completion needs kliobuflen >= 16
    u = fresh()
    provision(u, 0, cipher_pi())
    u.mgmt(0, CFG_EXPORTING)
    u.csr_write("kliobuflen", 16)
    u.kliobuf[0:16] = mdh_bytes(cipher_pi(State=ST_READY))
    check("a handler passing ml through the KLIOBUF completes an export with Form A",
          (u.mgmt(0, CFG_MANAGEMENT_END, form="A"), u.getst(0)), ("completed", ST_READY))

    # the hint: klmanagedcr naming an Unconfigured CL
    u = fresh()
    u.csr_write("klmanagedcr", 0)
    check("a handler checks the MDH first: klmanagedcr = 0 naming an Unconfigured CL",
          (u.getmd(0)["State"], trap_of(u.mgmt, 0, CFG_EXPORTING)), (0, "illegal/2"))
    ctx = save_context(u)
    check("... the save path saves no image for it", ctx["images"], {})

    # a managed CL whose export was interrupted
    u = fresh()
    provision(u, 3, cipher_pi(SCProtection=1))
    base = u.getmd(3)
    u.mgmt(3, CFG_EXPORTING)
    out = Memory()
    u.store(3, out, BASE, halt_after=32)
    before = snapshot(u)
    ctx = save_context(u)
    u.clearall()
    restore_context(u, ctx)
    check("an interrupted export survives save and restore", snapshot(u), before)
    u.store(3, out, BASE)
    u.mgmt(3, CFG_MANAGEMENT_END, base)
    img = mdh_bytes(base) + out.read(BASE, u.size(k=3) - 16)
    check("... completes, and its SCC imports", (u.getst(3), import_(fresh(), 0, img)),
          (ST_READY, ST_READY))


# =====================================================================
# 20. Negative controls
# =====================================================================

def test_negative_controls():
    section("20. Negative controls")

    for label in ("NEGCTRL-widen", "NEGCTRL-badresume", "NEGCTRL-adsbit",
                  "NEGCTRL-oldlayout", "NEGCTRL-restoreorder"):
        declare_negative_control(label)

    # 1: a restrict that replaces UsagePolicy when non-zero, as for other fields, widens
    cur, req = 0b01110, 0b00001
    widened = req if req else cur
    u = fresh()
    provision(u, 0, cipher_pi(UsagePolicy=cur))
    u.mode = "U"
    u.restrict(0, mdh_new(UsagePolicy=req), "h")
    check("the spec rule adds the new denial and keeps the old ones",
          u.getmd(0)["UsagePolicy"], 0b01111)
    probe = fresh()
    gained = []
    for mode in ("U", "VS", "HS", "M"):
        probe.mode = mode
        if probe.usage_allowed(cipher_pi(UsagePolicy=widened)) and \
                not probe.usage_allowed(cipher_pi(UsagePolicy=cur)):
            gained.append(mode)
    check("the replace-if-non-zero rule really widens", gained, ["VS", "HS", "M"])
    expect_fail("NEGCTRL-widen", "replace-if-non-zero UsagePolicy is monotone (it is not)",
                widened, cur)

    # 2: an import resumed at a later klstart silently skips a block
    src = fresh()
    provision(src, 0, sig_pi())
    img = export(src, 0)
    ml = mdh_unpack(b2v(img[0:16]))
    v = fresh()
    v.mgmt(1, CFG_IMPORTING, ml)
    mem = Memory()
    mem.write(BASE, img[16:])
    v.load(1, mem, BASE, halt_after=32)
    check("the interrupted import halted at a block boundary", v.klstart, 32)
    v.csr_write("klstart", 48)
    v.load(1, mem, BASE)
    v.mgmt(1, CFG_MANAGEMENT_END, ml)
    check("the wrongly resumed import fails authentication and clears the CL",
          (v.getst(1), v.cls[1].c1), (ST_MGMT_AUTH, b""))
    expect_fail("NEGCTRL-badresume", "an import resumed at the wrong klstart reproduces the "
                "Content", v.cls[1].c1, src.cls[0].c1)
    w = fresh()
    check("the correctly resumed import round trips",
          (import_(w, 1, img, halt_after=32), w.load(1, mem, BASE),
           w.mgmt(1, CFG_MANAGEMENT_END, ml), w.cls[1].c1),
          ("halted", "done", "completed", src.cls[0].c1))

    # 3: first-segment authentication without clearing bit 47
    u = fresh()
    provision(u, 0, cipher_pi(SCProtection=1))
    md = u.getmd(0)
    scc = export(u, 0)
    AD = u.sealing_ad(dict(md, ADSDropped=1))
    c1 = to_blocks(scc[64:64 + 32])
    ok_spec, _ = scc_decrypt(AD, 0, 0, b2v(scc[16:32]), c1, DEFAULT_CSK)
    ok_wrong, _ = scc_decrypt(AD, 0, 0, b2v(scc[16:32]), c1, DEFAULT_CSK, clear_bit47=False)
    check("with bit 47 cleared in AD_auth, a toggled ADSDropped still authenticates", ok_spec, True)
    expect_fail("NEGCTRL-adsbit", "authentication over an uncleared bit 47 accepts a toggled "
                "ADSDropped", ok_wrong, True)

    # 4: the MDH layout of commit aba8573 does not satisfy kl.getst's expansion
    m = mdh_new(State=ST_EXPIRED, StateExtension=0b1111, KeyType=1)
    hi, lo = OLD_STATE_SPAN
    old = (mdh_pack(mdh_new()) & ~(((1 << (hi - lo + 1)) - 1) << lo)) | (m["State"] << lo) \
        | (m["StateExtension"] << 26) | (m["KeyType"] << 19)
    check("the current layout satisfies the kl.getst expansion",
          (mdh_pack(m) >> 19) & 0x3F, ST_EXPIRED)
    expect_fail("NEGCTRL-oldlayout", "the aba8573 layout (State at [25:21]) satisfies the "
                "kl.getst expansion", (old >> 19) & 0x3F, ST_EXPIRED)

    # 5: restoring the managed CL before the others loses its in-flight SIV
    u = fresh()
    src, base_ml, mem = build_context(u)
    ctx = save_context(u)
    u.clearall()
    restore_context(u, ctx, managed_first=True)
    u.load(2, mem, BASE)
    u.mgmt(2, CFG_MANAGEMENT_END, base_ml)
    check("the misordered restore leaves an import that fails authentication",
          u.getst(2), ST_MGMT_AUTH)
    expect_fail("NEGCTRL-restoreorder", "restoring the managed CL first preserves its SIV",
                u.getst(2), src.getst(0))


# =====================================================================
# 21. Notes
# =====================================================================

def test_notes():
    section("21. Readings chosen, and text to review")

    info("MachinePolicy = 0 for a Machine that requires a bit is listed as invalid Metadata, "
         "while unsupported Metadata is 'a combination of _Machine_, _MachinePolicy_ and "
         "_SCProtection_ ... not implemented'. The opening kl.mgmt checks unsupported first, so "
         "the class decides between kl_exc_unsupported and Error State Invalid. Modelled as "
         "invalid (the explicit entry); kl.avail still returns 0 for it.")
    info("klmanagedcr after an opening kl.mgmt that zeroizes the CL and then raises: "
         "<<KLEE-CL-management>> sets it to 32 because the CL is Unconfigured, while "
         "<<KLEE-CSR-klmanagedcr>> sets it to 32 only when the named CL 'ceases to be in a "
         "Configuration State'. They differ only if software wrote the CL's own number while "
         "the CL was not under management; this model follows <<KLEE-CL-management>> for "
         "kl.mgmt and <<KLEE-CSR-klmanagedcr>> for kl.clear.")
    info("'kl.mgmt also clears klstart' is modelled as happening only when kl.mgmt does not "
         "raise an exception, per the state change rule for exceptions of "
         "<<KLEE-error-architecture>>.")
    info("kl.load and kl.store with klstart at or beyond their bound transfer nothing and "
         "retire, and the retirement rule of <<KLEE-CSR-klstart>> then writes 0 to klstart; the "
         "empty-window no-op rule is stated only for KLIOBUF and vector operands.")
    info("SGR5 permits kl.derive in Success 'under the conditions of use of kl.exec'; the toy "
         "XOF therefore admits a derive source only in Success. Pairs, minimums and field "
         "lengths are Machine-specific and are toy values here.")
    info("The Error States are listed 'in decreasing severity order', but no rule says what the "
         "order decides when two conditions coincide; SGR19 fixes the order of the conditions "
         "instead, which is what this model follows.")


def main():
    print(__doc__.strip().splitlines()[0])
    print()
    print("Toy Machines and a clearly labelled AESE256 stand-in are used; scc-kat.py covers the")
    print("real sealing construction. What is tested here is the architectural state machine.")

    test_mdh_layout()
    test_states()
    test_validity()
    test_lengths()
    test_usage_policy()
    test_restrict()
    test_localities()
    test_mgmt_flows()
    test_nested()
    test_error_states()
    test_ads()
    test_transfers()
    test_kliobuf()
    test_sgr()
    test_exec_klstart()
    test_expiration()
    test_derive()
    test_error_architecture()
    test_save_restore()
    test_negative_controls()
    test_notes()

    section("Summary")
    missing = [lab for lab in _state["xfail_want"] if lab not in _state["xfail_seen"]]
    for lab in missing:
        _state["fail"] += 1
        print(f"FAIL  declared negative control {lab} never fired")
    print(f"checks passed : {_state['pass']}")
    print(f"checks failed : {_state['fail']}")
    print(f"negative controls fired : {len(_state['xfail_seen'])}"
          f" of {len(_state['xfail_want'])}")
    ok = _state["fail"] == 0
    print()
    print("KAT-RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
