#!/usr/bin/env python3
"""Architectural-state-machine KAT for the ACE management ISA (Book 1 / Book 2).

This harness models the *algorithm-independent* rules of the draft RISC-V ACE
specification and checks the spec's own invariants and worked examples:

  * the 128-bit MDH field layout (<<ACE-metadata-header>>) -- pack/unpack round
    trip with walking-ones patterns on every field boundary, reserved bits zero;
  * the _UsagePolicy_ enforcement matrix and `ace.restrict*` monotonicity;
  * _Locality_ substitution chains and the substituted-never-dropped rule;
  * the generic _State_ rules 1-14 of <<ACE-State-field>>, including the
    Error-State entry effects and the 32-byte Error-State export;
  * _ConfigStatus_ gating and its instruction exemption list;
  * the provisioning / import / export flows of <<ACE-instruction-manage>>
    against the Book 4 sequences (<<ACE-management-code-snippets>>), in both the
    `Zklmv` (ace.mv) and `Zklmem` (ace.load / ace.store) variants, with
    interrupted-transfer resumption;
  * ACEIOBUF window semantics (`aceiobuflen` / `aceiobuftop` / `acestart`);
  * _ExpirationDate_ evaluation points and skip conditions;
  * `ace.size` Form A.

No real cryptography is involved: sealing is a deliberately trivial, clearly
labelled stand-in (SHA-256 keystream XOR plus a SHA-256 tag).  The real sealing
construction is covered by scc-kat.py; what is tested here is *when* sealing
happens and what it does to the architectural state, not *how* it is computed.

Reporting follows kat/run-kats.py: one PASS/FAIL line per case, a final
`KAT-RESULT: PASS|FAIL`, and `KAT-EXPECT-FAIL:` declarations for the two
negative controls.  Lines starting with `INFO` record places where the
specification contradicts itself or is silent, and where this model therefore
had to choose a reading; they are review input, not failures.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import b2v, v2b, sl, bin_  # noqa: E402  (ACE value conventions)

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
# MDH format  --  <<ACE-metadata-header>>
# =====================================================================

# (name, hi, lo, reserved?)
MDH_FIELDS = [
    ("Algorithm",       11,   0, False),
    ("AlgorithmPolicy", 13,  12, False),
    ("Reserved0",       15,  14, True),
    ("SCProtection",    18,  16, False),
    ("KeyType",         20,  19, False),
    ("State",           25,  21, False),
    ("StateExtension",  29,  26, False),
    ("ConfigStatus",    31,  30, False),
    ("ImpDataLen",      45,  32, False),
    ("AuxInfo",         61,  46, False),
    ("Reserved1",       62,  62, True),
    ("SystemFormat",    63,  63, False),
    ("UsagePolicy",     68,  64, False),
    ("Locality",        77,  69, False),
    ("Reserved2",       79,  78, True),
    ("AlgorithmUse",    95,  80, False),
    ("ExpirationDate", 115,  96, False),
    ("Reserved3",      127, 116, True),
]

FIELD = {f[0]: f for f in MDH_FIELDS}


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
    """MDH dict -> 128-bit ACE value."""
    v = 0
    for name, hi, lo, _ in MDH_FIELDS:
        w = hi - lo + 1
        val = m.get(name, 0)
        if val >> w:
            raise ValueError(f"field {name} value {val} does not fit in {w} bits")
        v |= (val & ((1 << w) - 1)) << lo
    return v


def mdh_unpack(v):
    """128-bit ACE value -> MDH dict."""
    return {name: sl(v, hi, lo) for name, hi, lo, _ in MDH_FIELDS}


def mdh_reserved_zero(m):
    return all(m.get(name, 0) == 0 for name, _, _, res in MDH_FIELDS if res)


def mdh_bytes(m):
    return v2b(mdh_pack(m), 16)


def mdh_lo64(m):
    """MDH[63:0], the half from which every length must be computable."""
    return sl(mdh_pack(m), 63, 0)


# =====================================================================
# States, ConfigStatus, exceptions  --  <<ACE-State-field>>, <<ACE-ConfigStatus>>
# =====================================================================

ST_UNCONFIGURED = 0
ST_READY = 1
ST_SUCCESS = 22
ST_FAILURE = 23
ST_UNSUPPORTED = 24
ST_INVALID = 25
ST_OUT_OF_MEMORY = 26
ST_IMPORT_AUTH = 27
ST_PRIVILEGE_VIOLATION = 28
ST_EXPIRED = 29

ERROR_STATES = range(24, 32)
VALID_STATES = range(1, 24)

CFG_COMPLETE = 0
CFG_PROVISIONING = 1
CFG_IMPORTING = 2
CFG_EXPORTING = 3

# algorithm-defined intermediate states used by the toy algorithms below
ST_ENCRYPT = 7
ST_DECRYPT = 8
ST_ABSORB = 9

MANAGEDCR_NONE = 32


class IllegalInstruction(Exception):
    pass


class AceException(Exception):
    """An ACE exception (ace_exc_*), named by its mnemonic suffix."""

    def __init__(self, which):
        super().__init__(which)
        self.which = which


# =====================================================================
# toy algorithm table and the length rule  --  <<ACE-length-rule>>
# =====================================================================

# A minimal, self-consistent algorithm table.  Only the *shape* matters: the
# length rule says PI length depends on (Algorithm, AlgorithmPolicy, KeyType)
# only, SCC length on those plus StateExtension and ImpDataLen, and CRF capacity
# on (Algorithm, AlgorithmPolicy, SCProtection) only.
ALG_CTR = 0x011      # a symmetric cipher mode: AlgorithmPolicy = enc/dec bits
ALG_HASH = 0x021     # a hash: AlgorithmPolicy unused (must be zero on restrict)
ALG_SIG = 0x031      # a signature scheme: AlgorithmPolicy = sign/verify bits

ALG_NAMES = {ALG_CTR: "toy-ctr", ALG_HASH: "toy-hash", ALG_SIG: "toy-sig"}

# algorithms whose AlgorithmPolicy field is not an operation mask
ALG_NO_POLICY = {ALG_HASH}

MAX_SCPROTECTION = 2  # levels 0..2 implemented; 3-5 reserved, 6-7 custom


def alg_supported(m):
    if m["Algorithm"] not in ALG_NAMES:
        return False
    if m["SCProtection"] > MAX_SCPROTECTION:
        return False
    if m["Algorithm"] in ALG_NO_POLICY:
        if m["AlgorithmPolicy"] != 0:
            return False
    else:
        if m["AlgorithmPolicy"] == 0:
            return False  # "at least one of the bits must be set"
    if m["KeyType"] > 1:
        return False      # 2 and 3 reserved
    return True


def content_len(m):
    """Bytes of algorithm content, per the length rule's PI dependency set."""
    alg, apol, kt = m["Algorithm"], m["AlgorithmPolicy"], m["KeyType"]
    if kt == 1:
        base = 16                       # a 64-bit SKID, padded to a 128-bit block
    elif alg == ALG_CTR:
        base = 32
    elif alg == ALG_HASH:
        base = 32
    elif alg == ALG_SIG:
        base = 96 if apol == 0b11 else 64
    else:
        raise ValueError("unsupported algorithm")
    if alg == ALG_CTR and apol == 0b11 and kt == 0:
        base += 16                      # both directions keep two schedules
    return base


def pi_len(m):
    """Total PI length in bytes (MDH included)."""
    return 16 + content_len(m)


def scc_len(m):
    """Total SCC length in bytes (MDH included)."""
    if m["State"] in ERROR_STATES:
        return 32                       # MDH + SIV only, irrespective of every field
    n = 16 + content_len(m) + 16        # MDH + content + SIV
    if m["StateExtension"]:
        n += 16                         # algorithm state carried across the export
    n += 16 * m["ImpDataLen"]           # variable-length implementation data
    return n


def serialized_len(m):
    """Length of what a CR with this MDH serializes to, PI or SCC per ConfigStatus."""
    if m["ConfigStatus"] == CFG_PROVISIONING:
        return pi_len(m)
    return scc_len(m)


def crf_capacity(m):
    """CRF capacity in bytes: (Algorithm, AlgorithmPolicy, SCProtection) only."""
    alg, apol, sc = m["Algorithm"], m["AlgorithmPolicy"], m["SCProtection"]
    base = {ALG_CTR: 64, ALG_HASH: 48, ALG_SIG: 128}[alg]
    if alg == ALG_CTR and apol == 0b11:
        base += 16
    if alg == ALG_SIG and apol == 0b11:
        base += 32
    return base * (1 + sc)


# =====================================================================
# toy seal  --  STAND-IN, not the real construction
# =====================================================================

TOY_CSK = b"ACE-KAT-toy-context-sealing-key!"


def _ks(seed, n):
    out = b""
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(seed + ctr.to_bytes(4, "little")).digest()
        ctr += 1
    return out[:n]


def toy_seal(content, ad):
    """STAND-IN sealing: XOR keystream + 16-byte checksum tag (SIV)."""
    ks = _ks(TOY_CSK + b"|enc|" + ad, len(content))
    ct = bytes(a ^ b for a, b in zip(content, ks))
    siv = hashlib.sha256(TOY_CSK + b"|tag|" + ad + content).digest()[:16]
    return ct + siv


def toy_unseal(blob, ad):
    """Returns (content, authentic)."""
    if len(blob) < 16:
        return b"", False
    ct, siv = blob[:-16], blob[-16:]
    ks = _ks(TOY_CSK + b"|enc|" + ad, len(ct))
    content = bytes(a ^ b for a, b in zip(ct, ks))
    good = hashlib.sha256(TOY_CSK + b"|tag|" + ad + content).digest()[:16] == siv
    return content, good


# =====================================================================
# Localities  --  <<ACE-Localities>>
# =====================================================================

LOC_HW1 = ("hw1", 1, 0)     # SiPScrt(1) -> ChipFamScrt(2) -> ChipScrt(3)
LOC_HW2 = ("hw2", 3, 2)     # OEMScrt(1) -> ProdScrt(2)    -> DevScrt(3)
LOC_BOOT = ("boot", 5, 4)   # PhysBootScrt(1) / VirtBootScrt(2); 3 unassigned
LOC_M = ("mloc", 6, 6)
LOC_H = ("hloc", 7, 7)
LOC_S = ("sloc", 8, 8)

LOC_SUBFIELDS = [LOC_HW1, LOC_HW2, LOC_BOOT, LOC_M, LOC_H, LOC_S]

# LST index of each (subfield, value) pair
LST_INDEX = {
    ("hw1", 1): 0, ("hw1", 2): 1, ("hw1", 3): 2,
    ("hw2", 1): 3, ("hw2", 2): 4, ("hw2", 3): 5,
    ("boot", 1): 6, ("boot", 2): 7,
    ("mloc", 1): 8, ("hloc", 1): 9, ("sloc", 1): 10,
}


def loc_get(locality, sub):
    _, hi, lo = sub
    return sl(locality, hi, lo)


def loc_set(locality, sub, val):
    _, hi, lo = sub
    w = hi - lo + 1
    return (locality & ~(((1 << w) - 1) << lo)) | ((val & ((1 << w) - 1)) << lo)


def loc(hw1=0, hw2=0, boot=0, mloc=0, hloc=0, sloc=0):
    """Build a 9-bit _Locality_ field from its subfields."""
    return (hw1 & 3) | ((hw2 & 3) << 2) | ((boot & 3) << 4) \
        | ((mloc & 1) << 6) | ((hloc & 1) << 7) | ((sloc & 1) << 8)


def loc_active_count(locality):
    n = 0
    for sub in LOC_SUBFIELDS:
        if loc_get(locality, sub):
            n += 1
    return n


# =====================================================================
# the modelled ACE unit
# =====================================================================

class CR:
    def __init__(self):
        self.clear()

    def clear(self):
        self.mdh = mdh_new()
        self.content = b""      # clear internal content, MDH excluded
        self.xfer = None        # bytearray being loaded (provision/import)
        self.export = None      # serialized payload after the MDH, when exporting
        self.crf = 0

    # -- convenience -------------------------------------------------
    @property
    def state(self):
        return self.mdh["State"]

    @property
    def cfg(self):
        return self.mdh["ConfigStatus"]

    def is_unconfigured(self):
        return mdh_pack(self.mdh) == 0 and not self.content

    def in_error(self):
        return self.state in ERROR_STATES

    def enter_error(self, st):
        """State rule 7: content cleared, ImpDataLen zeroed, ConfigStatus complete."""
        self.mdh["State"] = st
        self.mdh["StateExtension"] = 0
        self.mdh["ImpDataLen"] = 0
        self.mdh["ConfigStatus"] = CFG_COMPLETE
        self.content = b""
        self.xfer = None
        self.export = None
        self.crf = 0


class Unit:
    """A single ACE unit: CRF, ACEIOBUF, and the unprivileged CSRs."""

    def __init__(self, ncrs=8, maxiobuflen=256, modes=("U", "VU", "VS", "HS", "S", "M", "D"),
                 lst=None, clock=0, crf_capacity_total=1 << 20):
        self.crs = [CR() for _ in range(ncrs)]
        self.acestart = 0
        self.managedcr = MANAGEDCR_NONE
        self.open_op = None      # which management process is open on managedcr
        self.acemaxiobuflen = maxiobuflen
        self.aceiobuflen = 0
        self.aceiobuftop = 0
        self.aceiobuf = bytearray()
        self.modes = set(modes)
        self.mode = "M"
        self.clock = clock                  # hours since the ExpirationDate epoch
        self.zklexpire = True
        # configured LST entries, by index; unconfigured entries are absent
        self.lst = set(lst) if lst is not None else set(range(11))
        self.crf_free = crf_capacity_total

    # ---------------------------------------------------------------- CSRs
    def write_aceiobuflen(self, n):
        n = min(n, self.acemaxiobuflen)     # WARL clamp
        self.aceiobuflen = n
        self.aceiobuf = bytearray(n)        # write zeroes the buffer ...
        self.aceiobuftop = n                # ... and sets aceiobuftop
        return n

    def write_aceiobuftop(self, n):
        self.aceiobuftop = min(n, self.aceiobuflen)   # WARL clamp
        return self.aceiobuftop

    # ---------------------------------------------------------------- gating
    def usage_allowed(self, m):
        """The _UsagePolicy_ enforcement matrix of <<ACE-metadata-header>>."""
        up = m["UsagePolicy"]
        mode = self.mode
        if mode == "D":
            return bool(up & 0b10000)       # bit 4 GRANTS Debug use
        # a bit is ignored if the corresponding mode is not supported/enabled
        if mode in ("U", "VU"):
            return not (up & 1) if "U" in self.modes else True
        if mode == "VS":
            return not (up & 2) if "VS" in self.modes else True
        if mode in ("HS", "S"):
            return not (up & 4) if ("HS" in self.modes or "S" in self.modes) else True
        if mode == "M":
            return not (up & 8) if "M" in self.modes else True
        raise ValueError(mode)

    def expired(self, m):
        if not self.zklexpire:
            return False
        ed = m["ExpirationDate"]
        return ed != 0 and self.clock >= ed

    def _check_usage_gates(self, cr, *, is_resumption=False, usage_controlled=True):
        """Common dispatch checks for a *usage* instruction.

        Returns "noop" if the instruction must do nothing (Error-State CR),
        otherwise None.  Raises AceException on a gate violation.

        usage_controlled=False is for ace.restrict*, which is not
        usage-controlled (review m4/m13, since fixed): it can only narrow a CC,
        so permitting it in a mode the _UsagePolicy_ excludes grants that mode
        nothing.  ConfigStatus gating and the Error-State no-op still apply; the
        expiration check does not, since ace.restrict* is not one of the
        evaluation points of <<ACE-Metadata-expiration-date>>.
        """
        if cr.cfg != CFG_COMPLETE:
            # ConfigStatus gating: usage of a not-complete CR
            raise AceException("privilege_violation")
        if cr.in_error():
            return "noop"                    # State rule 13
        if not usage_controlled:
            return None
        if not self.usage_allowed(cr.mdh):   # State rule 14
            raise AceException("privilege_violation")
        if self.expired(cr.mdh):
            cr.enter_error(ST_EXPIRED)
            raise AceException("expired")
        return None

    # ---------------------------------------------------------------- instructions
    def getmdv(self, k):
        """ace.getmdv: full MDH; all zeros for an Unconfigured CR."""
        return dict(self.crs[k].mdh)

    def getmdl(self, k):
        """ace.getmdl: MDH[63:0]."""
        return mdh_lo64(self.crs[k].mdh)

    def getst(self, k):
        return self.crs[k].mdh["State"]

    def clear(self, k):
        """ace.clear / ace.setst #0."""
        self.crs[k].clear()
        if self.managedcr == k:
            self.managedcr = MANAGEDCR_NONE
            self.open_op = None
        self.acestart = 0

    def size_A(self, k):
        """ace.size Form A: size of the buffer needed to export this CR."""
        cr = self.crs[k]
        if cr.is_unconfigured():
            return 0
        if cr.in_error():
            return 32
        return serialized_len(cr.mdh)

    def size_B(self, m):
        """ace.size Form B/C, from an MDH supplied by software."""
        if not alg_supported(m) or not mdh_reserved_zero(m):
            # M2: the text says 32 here; ace.avail and Book 4 say 0.
            return 32
        return serialized_len(m)

    # -- management --------------------------------------------------
    def _mgmt_gate(self, k):
        if self.managedcr not in (k, MANAGEDCR_NONE):
            raise IllegalInstruction("managedcr busy with another CR")

    def mgmt_provision_start(self, k, ml):
        self._mgmt_gate(k)
        cr = self.crs[k]
        cr.clear()
        if not alg_supported(ml):
            raise AceException("unsupported")
        m = dict(ml)
        # provisioning-specific validity: State/StateExtension and ImpDataLen zero
        bad = (m["State"] != 0 or m["StateExtension"] != 0 or m["ImpDataLen"] != 0
               or not mdh_reserved_zero(m) or m["ConfigStatus"] != CFG_COMPLETE)
        if bad:
            cr.mdh = mdh_new(Algorithm=m["Algorithm"], AlgorithmPolicy=m["AlgorithmPolicy"],
                             SCProtection=m["SCProtection"], KeyType=m["KeyType"])
            cr.enter_error(ST_INVALID)
            self.acestart = 0
            return
        need = crf_capacity(m)
        if need > self.crf_free:
            raise AceException("out_of_memory")
        self.crf_free -= need
        cr.crf = need
        cr.mdh = m
        cr.mdh["State"] = ST_READY          # provisioning always yields Ready
        cr.mdh["ConfigStatus"] = CFG_PROVISIONING
        cr.xfer = bytearray(pi_len(m) - 16)
        self.managedcr = k
        self.open_op = "provision"
        self.acestart = 0
        return

    def mgmt_import_start(self, k, ml):
        self._mgmt_gate(k)
        cr = self.crs[k]
        cr.clear()
        if not alg_supported(ml):
            raise AceException("unsupported")
        m = dict(ml)
        # C2 (as fixed): for import, a nonzero _State_ is legal; only reserved
        # fields and the algorithm triple are checked here.
        if not mdh_reserved_zero(m):
            cr.enter_error(ST_INVALID)
            self.acestart = 0
            return
        need = crf_capacity(m)
        if need > self.crf_free:
            raise AceException("out_of_memory")
        self.crf_free -= need
        cr.crf = need
        cr.mdh = m
        cr.mdh["ConfigStatus"] = CFG_IMPORTING
        cr.xfer = bytearray(serialized_len(m) - 16)
        self.managedcr = k
        self.open_op = "import"
        self.acestart = 0
        return

    def mgmt_export_start(self, k):
        self._mgmt_gate(k)
        cr = self.crs[k]
        ml = dict(cr.mdh)
        if ml["ConfigStatus"] == CFG_COMPLETE:
            ad = mdh_bytes(ml)
            if cr.in_error():
                # Error-State export: MDH and tag only, 32 bytes total
                cr.export = bytearray(toy_seal(b"", ad))
            else:
                cr.export = bytearray(toy_seal(cr.content, ad))
            cr.mdh["ConfigStatus"] = CFG_EXPORTING
        else:
            # verbatim export of a partially configured CR: no encryption, no tag
            cr.export = bytearray(cr.xfer if cr.xfer is not None else cr.content)
        self.managedcr = k
        self.open_op = "export"
        self.acestart = 0
        return ml

    def mgmt_end(self, k, ml=None):
        """ace.mgmt #ace_CR_management_end, completing whatever is open on this CR."""
        self._mgmt_gate(k)
        cr = self.crs[k]
        # Which process is being completed is normally implied by _ConfigStatus_;
        # only the export of a *not-complete* CR, which leaves _ConfigStatus_
        # untouched, needs the extra bit of state modelled by `open_op`.
        op = self.open_op or {CFG_PROVISIONING: "provision",
                              CFG_IMPORTING: "import",
                              CFG_EXPORTING: "export"}.get(cr.cfg)
        if op == "provision":
            cr.content = bytes(cr.xfer)
            cr.xfer = None
            # validity of MDH[127:64] is only checked here
            if not mdh_reserved_zero(cr.mdh) or loc_resolve(self, cr.mdh["Locality"]) is None:
                cr.enter_error(ST_INVALID)
            else:
                cr.mdh["ConfigStatus"] = CFG_COMPLETE
        elif op == "import":
            if ml is None:
                raise IllegalInstruction("import completion requires ml")
            blob = bytes(cr.xfer)
            cr.xfer = None
            if ml["ConfigStatus"] == CFG_COMPLETE:
                content, good = toy_unseal(blob, mdh_bytes(ml))
                if not good:
                    cr.enter_error(ST_IMPORT_AUTH)
                else:
                    cr.mdh = dict(ml)
                    cr.content = content
                    cr.mdh["ConfigStatus"] = CFG_COMPLETE
            else:
                # a nested export, or the export of a not fully configured CR
                cr.content = blob
                cr.xfer = bytearray(blob)
                cr.mdh = dict(ml)
                cr.mdh["ConfigStatus"] = ml["ConfigStatus"]
        elif op == "export" and cr.cfg == CFG_EXPORTING:
            if ml is None:
                raise IllegalInstruction("export completion requires ml")
            if ml["ConfigStatus"] == CFG_COMPLETE:
                cr.mdh = dict(ml)
                cr.export = None
            # otherwise: no changes to the CR state
        else:
            # completing an export of a not-complete CR: nothing to do
            if ml is not None and ml["ConfigStatus"] != CFG_COMPLETE:
                cr.export = None
        self.managedcr = MANAGEDCR_NONE
        self.open_op = None
        self.acestart = 0

    # -- CR-directed transfers (Zklmem) ------------------------------
    def load(self, k, mem, base, halt_after=None):
        """ace.load: memory base+j <-> serialized offset 16+j (the C1 rule)."""
        cr = self.crs[k]
        if cr.cfg == CFG_COMPLETE:
            raise IllegalInstruction("ace.load on a complete CR")
        n = serialized_len(cr.mdh) - 16
        self.acestart = min(self.acestart, n)     # acestart clamp for CR transfers
        j = self.acestart
        moved = 0
        while j < n:
            if halt_after is not None and moved >= halt_after:
                self.acestart = j                  # prefix-complete interruption point
                return False
            cr.xfer[j:j + 16] = mem[base + j: base + j + 16]
            j += 16
            moved += 16
        self.acestart = 0                          # cleared on successful completion
        return True

    def store(self, mem, base, k, halt_after=None):
        """ace.store: the mirror of ace.load."""
        cr = self.crs[k]
        if cr.cfg == CFG_COMPLETE:
            raise IllegalInstruction("ace.store on a complete CR")
        payload = cr.export if cr.export is not None else bytes(cr.xfer or b"")
        n = len(payload)
        self.acestart = min(self.acestart, n)
        j = self.acestart
        moved = 0
        while j < n:
            if halt_after is not None and moved >= halt_after:
                self.acestart = j
                return False
            mem[base + j: base + j + 16] = payload[j:j + 16]
            j += 16
            moved += 16
        self.acestart = 0
        return True

    # -- CR-directed transfers (Zklmv) -------------------------------
    def mv_in(self, k, chunk):
        """ace.mv Kd, Vs2 : write `chunk` at offset acestart; acestart accumulates."""
        cr = self.crs[k]
        if cr.cfg not in (CFG_PROVISIONING, CFG_IMPORTING):
            raise IllegalInstruction("ace.mv into a CR that is not being configured")
        if len(chunk) % 16:
            cr.enter_error(ST_INVALID)
            return
        j = self.acestart
        cr.xfer[j:j + len(chunk)] = chunk
        self.acestart = j + len(chunk)   # NOT cleared: the documented ace.mv exemption

    def mv_out(self, k, nbytes):
        """ace.mv Vd, Ks1 : read `nbytes` at offset acestart; acestart accumulates."""
        cr = self.crs[k]
        if cr.cfg != CFG_EXPORTING:
            raise IllegalInstruction("ace.mv out of a CR that is not exporting")
        if nbytes % 16:
            cr.enter_error(ST_INVALID)
            return b""
        j = self.acestart
        out = bytes(cr.export[j:j + nbytes])
        self.acestart = j + nbytes
        return out

    # -- ACEIOBUF transfers ------------------------------------------
    def input_(self, mem, base, Xl, halt_after=None):
        if self.aceiobuflen == 0:
            raise AceException("unconfigured_buffer")
        end = min(Xl, self.aceiobuftop)
        if Xl == 0 or self.acestart >= end:
            return "noop"                 # acestart unchanged (the m1 reading)
        j = self.acestart
        moved = 0
        while j < end:
            if halt_after is not None and moved >= halt_after:
                self.acestart = j
                return False
            self.aceiobuf[j] = mem[base + j]
            j += 1
            moved += 1
        self.acestart = 0
        return True

    def output(self, mem, base, Xl, halt_after=None):
        if self.aceiobuflen == 0:
            raise AceException("unconfigured_buffer")
        end = min(Xl, self.aceiobuftop)
        if Xl == 0 or self.acestart >= end:
            return "noop"
        j = self.acestart
        moved = 0
        while j < end:
            if halt_after is not None and moved >= halt_after:
                self.acestart = j
                return False
            mem[base + j] = self.aceiobuf[j]
            j += 1
            moved += 1
        self.acestart = 0
        return True

    # -- usage -------------------------------------------------------
    def exec_(self, k, nbytes=16, is_resumption=False):
        """A generic usage instruction (ace.exec)."""
        cr = self.crs[k]
        if self._check_usage_gates(cr, is_resumption=is_resumption) == "noop":
            return "noop"
        # a toy "operation": stir the content so that use is observable
        cr.content = hashlib.sha256(cr.content + b"exec").digest()[:len(cr.content)] \
            if cr.content else cr.content
        return "done"

    def setst(self, k, imm, aux=None):
        """ace.setst with a 7-bit immediate."""
        cr = self.crs[k]
        if imm == ST_UNCONFIGURED:
            self.clear(k)                       # not usage-controlled
            return
        if imm in ERROR_STATES:
            cr.enter_error(imm)                 # not usage-controlled, no exception
            return
        # from here on this is a transition to a valid state: a usage instruction
        if cr.cfg != CFG_COMPLETE:
            raise AceException("privilege_violation")
        if cr.in_error():
            return "noop"                       # State rule 13
        if cr.state in (ST_SUCCESS, ST_FAILURE) and imm not in (ST_READY, ST_UNCONFIGURED):
            cr.enter_error(ST_INVALID)          # State rule 3
            return
        if not self.usage_allowed(cr.mdh):
            raise AceException("privilege_violation")
        if self.expired(cr.mdh):
            cr.enter_error(ST_EXPIRED)
            raise AceException("expired")
        if imm not in VALID_STATES:
            cr.enter_error(ST_INVALID)
            return
        cr.mdh["State"] = imm

    def clone(self, kd, ks):
        src = self.crs[ks]
        if src.cfg != CFG_COMPLETE:
            raise AceException("privilege_violation")
        dst = self.crs[kd]
        dst.mdh = dict(src.mdh)
        dst.content = src.content
        dst.xfer = None
        dst.export = None

    # -- ace.restrict* -----------------------------------------------
    def restrictl(self, k, xs):
        """AlgorithmPolicy and SCProtection, in MDH[63:0].  Not usage-controlled."""
        cr = self.crs[k]
        if self._check_usage_gates(cr, usage_controlled=False) == "noop":
            return "noop"
        m = cr.mdh
        if xs["AlgorithmPolicy"] != 0:
            if m["Algorithm"] in ALG_NO_POLICY:
                cr.enter_error(ST_INVALID)
                return "invalid"
            new, cur = xs["AlgorithmPolicy"], m["AlgorithmPolicy"]
            if new & ~cur:                              # would (re)enable something
                cr.enter_error(ST_INVALID)
                return "invalid"
            if new == 0:
                cr.enter_error(ST_INVALID)
                return "invalid"
            # state currently requiring an operation that would be disabled
            need = {ST_ENCRYPT: 0b01, ST_DECRYPT: 0b10}.get(m["State"])
            if need is not None and not (new & need):
                cr.enter_error(ST_INVALID)
                return "invalid"
            m["AlgorithmPolicy"] = new
        if xs["SCProtection"] != 0:
            if xs["SCProtection"] < m["SCProtection"]:
                cr.enter_error(ST_INVALID)
                return "invalid"
            m["SCProtection"] = xs["SCProtection"]
        return "ok"

    def restricth(self, k, xs):
        """Locality, UsagePolicy, ExpirationDate, AlgorithmUse, in MDH[127:64].
        Not usage-controlled."""
        cr = self.crs[k]
        if self._check_usage_gates(cr, usage_controlled=False) == "noop":
            return "noop"
        m = cr.mdh
        if xs["Locality"] != 0:
            newloc = m["Locality"]
            for sub in LOC_SUBFIELDS:
                req = loc_get(xs["Locality"], sub)
                cur = loc_get(newloc, sub)
                if req == 0 or req == cur:
                    continue
                if cur == 0:
                    newloc = loc_set(newloc, sub, req)          # rule 1
                elif sub in (LOC_HW1, LOC_HW2):
                    if req > cur:                               # rule 2: narrow only
                        newloc = loc_set(newloc, sub, req)
                    else:
                        cr.enter_error(ST_INVALID)
                        return "invalid"
                else:                                           # rules 3 and 4
                    cr.enter_error(ST_INVALID)
                    return "invalid"
            m["Locality"] = newloc
        if xs["UsagePolicy"]:
            m["UsagePolicy"] = apply_usagepolicy_restriction(
                m["UsagePolicy"], xs["UsagePolicy"])
        ed = xs["ExpirationDate"]
        if ed != 0:
            if m["ExpirationDate"] == 0 or ed <= m["ExpirationDate"]:
                m["ExpirationDate"] = ed
            # a larger value is silently not copied (see the INFO line on restricth)
        if xs["AlgorithmUse"] != 0:
            m["AlgorithmUse"] = xs["AlgorithmUse"]
        return "ok"

    def restrictv(self, k, xs):
        """restrictl then restricth; the second is skipped if the first errored."""
        r = self.restrictl(k, xs)
        if r in ("invalid", "noop"):
            return r
        return self.restricth(k, xs)


def apply_usagepolicy_restriction(cur, req):
    """The _UsagePolicy_ half of `ace.restricth`, as a pure field transformation.

    A zero bit in the request changes nothing.  A one in bits 0-3 sets the
    corresponding deny bit; a one in bit 4 *clears* the Debug grant.  Either way
    a one can only remove a permission.
    """
    if req == 0:
        return cur
    new = cur | (req & 0b01111)
    if req & 0b10000:
        new &= ~0b10000
    return new


def loc_resolve(unit, locality):
    """Resolve a requested _Locality_ against the LST.

    Returns the resolved LST index set, or None if the Metadata is invalid
    (an unconfigured entry with no later entry of its chain configured, or an
    unassigned encoding).
    """
    resolved = set()
    for sub in LOC_SUBFIELDS:
        req = loc_get(locality, sub)
        if req == 0:
            continue
        if sub is LOC_BOOT and req == 3:
            return None                    # [5:4] = 3 is reserved (m9, now normative)
        if sub in (LOC_HW1, LOC_HW2):
            cand = None
            for v in range(req, 4):        # substitute forward along the chain
                if LST_INDEX[(sub[0], v)] in unit.lst:
                    cand = v
                    break
            if cand is None:
                return None                # substituted, never dropped
            resolved.add(LST_INDEX[(sub[0], cand)])
        else:
            idx = LST_INDEX[(sub[0], req)]
            if idx not in unit.lst:
                return None
            resolved.add(idx)
    return resolved


# =====================================================================
# helper MDHs
# =====================================================================

def ctr_mdh(**kw):
    base = dict(Algorithm=ALG_CTR, AlgorithmPolicy=0b11, KeyType=0)
    base.update(kw)
    return mdh_new(**base)


def fresh_unit(**kw):
    return Unit(**kw)


def provision(unit, k, ml, content, use_mv=False, chunk=16):
    """The Book 4 provisioning sequence, in either variant."""
    unit.mgmt_provision_start(k, ml)
    if use_mv:
        for off in range(0, len(content), chunk):
            unit.mv_in(k, content[off:off + chunk])
    else:
        mem = bytearray(16 + len(content))
        mem[16:] = content
        unit.load(k, mem, 16)             # memory base maps to serialized offset 16
    unit.mgmt_end(k)


# =====================================================================
# tests
# =====================================================================

def test_mdh_format():
    section("1.  MDH format  --  <<ACE-metadata-header>>")

    total = sum(f[1] - f[2] + 1 for f in MDH_FIELDS)
    check("MDH fields tile all 128 bits", total, 128)

    covered = 0
    for _, hi, lo, _ in MDH_FIELDS:
        mask = ((1 << (hi - lo + 1)) - 1) << lo
        check_true(f"field span [{hi}:{lo}] does not overlap a previous one",
                   covered & mask == 0)
        covered |= mask
    check("MDH field spans cover [127:0] exactly", covered, (1 << 128) - 1)

    # walking ones over every bit of every field: pack/unpack round trip and
    # the bit lands exactly where the table says it does
    ok_walk = True
    ok_iso = True
    for name, hi, lo, _ in MDH_FIELDS:
        for b in range(hi - lo + 1):
            m = mdh_new(**{name: 1 << b})
            v = mdh_pack(m)
            if v != (1 << (lo + b)):
                ok_walk = False
            u = mdh_unpack(v)
            if u[name] != (1 << b):
                ok_walk = False
            if any(u[o] for o in u if o != name):
                ok_iso = False
    check_true("walking-ones: every field bit packs to its table position", ok_walk)
    check_true("walking-ones: no field bleeds into another", ok_iso)

    # all-ones per field, then the full round trip
    m = mdh_new(**{name: (1 << (hi - lo + 1)) - 1 for name, hi, lo, _ in MDH_FIELDS})
    check("all-ones MDH packs to ones(128)", mdh_pack(m), (1 << 128) - 1)
    check("all-ones MDH round trips", mdh_unpack(mdh_pack(m)), m)

    # a realistic MDH, checked field by field against hand-computed bit positions
    m = mdh_new(Algorithm=ALG_CTR, AlgorithmPolicy=0b01, SCProtection=2, KeyType=1,
                State=ST_ENCRYPT, StateExtension=0b0101, ConfigStatus=CFG_EXPORTING,
                ImpDataLen=3, AuxInfo=0x1234, SystemFormat=1, UsagePolicy=0b10011,
                Locality=0b101_10_11_10, AlgorithmUse=0xBEEF, ExpirationDate=0xABCDE)
    v = mdh_pack(m)
    check("sample MDH: Algorithm at [11:0]", sl(v, 11, 0), ALG_CTR)
    check("sample MDH: SCProtection at [18:16]", sl(v, 18, 16), 2)
    check("sample MDH: State at [25:21]", sl(v, 25, 21), ST_ENCRYPT)
    check("sample MDH: ConfigStatus at [31:30]", sl(v, 31, 30), CFG_EXPORTING)
    check("sample MDH: ImpDataLen at [45:32]", sl(v, 45, 32), 3)
    check("sample MDH: SystemFormat at [63]", sl(v, 63, 63), 1)
    check("sample MDH: UsagePolicy at [68:64]", sl(v, 68, 64), 0b10011)
    check("sample MDH: Locality at [77:69]", sl(v, 77, 69), 0b101_10_11_10)
    check("sample MDH: ExpirationDate at [115:96]", sl(v, 115, 96), 0xABCDE)
    check("sample MDH round trips", mdh_unpack(v), m)
    check_true("sample MDH has all reserved bits zero", mdh_reserved_zero(m))

    # reserved bits are detectable and are outside MDH[63:0]'s length-bearing part
    for name, hi, lo, res in MDH_FIELDS:
        if not res:
            continue
        bad = mdh_unpack(mdh_pack(mdh_new()) | (1 << lo))
        check_true(f"reserved {name} bit {lo} set is caught", not mdh_reserved_zero(bad))

    # MDH[63:0] carries every field the length rule names
    lo_fields = ("Algorithm", "AlgorithmPolicy", "KeyType", "StateExtension",
                 "ImpDataLen", "SCProtection")
    check_true("every length-determining field lies in MDH[63:0]",
               all(FIELD[f][1] <= 63 for f in lo_fields))

    # notation cross-check: the byte string of an MDH is little-endian
    check("mdh_bytes is the little-endian image (common.v2b)",
          mdh_bytes(mdh_new(Algorithm=0x123)).hex(),
          v2b(0x123, 16).hex())
    check("bin_(n, m) agrees with the field encoding", bin_(ST_ENCRYPT, 5), ST_ENCRYPT)
    check("b2v inverts mdh_bytes", b2v(mdh_bytes(m)), mdh_pack(m))


def test_length_rule():
    section("2.  The length rule  --  <<ACE-length-rule>>")

    base = ctr_mdh()
    # PI length depends only on Algorithm, AlgorithmPolicy, KeyType
    for fld, val in (("SCProtection", 2), ("StateExtension", 0), ("UsagePolicy", 0b1111),
                     ("Locality", 0b010), ("ExpirationDate", 0x1234),
                     ("AlgorithmUse", 0xFFFF), ("AuxInfo", 0x33)):
        m = ctr_mdh(**{fld: val})
        check(f"PI length independent of {fld}", pi_len(m), pi_len(base))

    # SCC length depends on Algorithm/AlgorithmPolicy/KeyType/StateExtension/ImpDataLen
    for fld, val in (("SCProtection", 2), ("UsagePolicy", 0b1111), ("Locality", 0b010),
                     ("ExpirationDate", 0x1234), ("AlgorithmUse", 0xFFFF),
                     ("ConfigStatus", CFG_EXPORTING)):
        m = ctr_mdh(**{fld: val})
        check(f"SCC length independent of {fld}", scc_len(m), scc_len(base))
    check("SCC length grows with StateExtension",
          scc_len(ctr_mdh(StateExtension=1)), scc_len(base) + 16)
    check("SCC length grows by 16 per ImpDataLen unit",
          scc_len(ctr_mdh(ImpDataLen=4)), scc_len(base) + 64)

    # CRF capacity depends only on Algorithm, AlgorithmPolicy, SCProtection
    for fld, val in (("KeyType", 1), ("StateExtension", 3), ("ImpDataLen", 7),
                     ("UsagePolicy", 0b1111), ("ExpirationDate", 9)):
        m = ctr_mdh(**{fld: val})
        check(f"CRF capacity independent of {fld}", crf_capacity(m), crf_capacity(base))
    check_true("CRF capacity grows with SCProtection",
               crf_capacity(ctr_mdh(SCProtection=2)) > crf_capacity(base))

    # the Error-State override
    for st in ERROR_STATES:
        m = ctr_mdh(State=st, ImpDataLen=9, StateExtension=3)
        check(f"Error State {st}: SCC length is 32 regardless of every field",
              scc_len(m), 32)

    # every length is computable from the first 8 bytes alone
    m = ctr_mdh(KeyType=1, StateExtension=2, ImpDataLen=2, UsagePolicy=0b1010,
                ExpirationDate=77)
    lo = mdh_lo64(m)
    m2 = mdh_unpack(lo)      # top half discarded
    check("SCC length computable from MDH[63:0] alone", scc_len(m2), scc_len(m))
    check("PI length computable from MDH[63:0] alone", pi_len(m2), pi_len(m))


def test_usage_policy():
    section("3.  UsagePolicy enforcement matrix  --  MDH[68:64]")

    # exhaustive matrix over the four privileged/unprivileged modes
    rows = []
    for up in range(32):
        for mode in ("U", "VU", "VS", "HS", "S", "M", "D"):
            u = fresh_unit()
            u.mode = mode
            m = ctr_mdh(UsagePolicy=up)
            got = u.usage_allowed(m)
            if mode in ("U", "VU"):
                want = not (up & 1)
            elif mode == "VS":
                want = not (up & 2)
            elif mode in ("HS", "S"):
                want = not (up & 4)
            elif mode == "M":
                want = not (up & 8)
            else:
                want = bool(up & 16)
            rows.append((up, mode, got, want))
    bad = [r for r in rows if r[2] != r[3]]
    check(f"UsagePolicy matrix: {len(rows)} (policy, mode) combinations", bad, [])

    # bit 0 governs U and VU together
    for up in range(32):
        u = fresh_unit()
        u.mode, mu = "U", ctr_mdh(UsagePolicy=up)
        a = u.usage_allowed(mu)
        u.mode = "VU"
        b = u.usage_allowed(mu)
        if a != b:
            check("bit 0 governs U and VU identically", (up, a, b), (up, a, a))
            break
    else:
        check_true("bit 0 governs U and VU identically", True)

    # bit 2 governs S with and without the H extension
    u_h = fresh_unit(modes=("U", "VU", "VS", "HS", "S", "M", "D"))
    u_noh = fresh_unit(modes=("U", "S", "M", "D"))
    for up in (0b000, 0b100):
        u_h.mode = "HS"
        u_noh.mode = "S"
        check(f"bit 2 governs S with and without H (UsagePolicy={up:#05b})",
              u_h.usage_allowed(ctr_mdh(UsagePolicy=up)),
              u_noh.usage_allowed(ctr_mdh(UsagePolicy=up)))

    # a bit for an unimplemented mode is ignored
    u = fresh_unit(modes=("U", "S", "M", "D"))     # no H, so no VS
    u.mode = "U"
    check_true("policy bit for an unsupported mode is ignored (VS bit set, U allowed)",
               u.usage_allowed(ctr_mdh(UsagePolicy=0b00010)))

    # Debug bit grants rather than denies
    u = fresh_unit()
    u.mode = "D"
    check_true("Debug denied when bit 4 clear (all other bits clear)",
               not u.usage_allowed(ctr_mdh(UsagePolicy=0b00000)))
    check_true("Debug granted when bit 4 set", u.usage_allowed(ctr_mdh(UsagePolicy=0b10000)))
    check_true("Debug grant is independent of the deny bits",
               u.usage_allowed(ctr_mdh(UsagePolicy=0b11111)))

    # the gate is enforced by usage instructions, and only by them
    u = fresh_unit()
    provision(u, 0, ctr_mdh(UsagePolicy=0b0001), b"\xAA" * content_len(ctr_mdh()))
    u.mode = "U"
    try:
        u.exec_(0)
        check("ace.exec in a denied mode raises privilege_violation", "no exception",
              "ace_exc_privilege_violation")
    except AceException as e:
        check("ace.exec in a denied mode raises privilege_violation", e.which,
              "privilege_violation")
    check("denied usage leaves State unchanged", u.getst(0), ST_READY)
    check_true("ace.getmd* is not usage-controlled", u.getmdv(0)["Algorithm"] == ALG_CTR)
    check("ace.size is not usage-controlled", u.size_A(0), scc_len(u.crs[0].mdh))
    u.setst(0, ST_UNCONFIGURED)          # ace.clear is never usage-controlled
    check("ace.clear is not usage-controlled", u.getst(0), ST_UNCONFIGURED)


def test_restrict():
    section("4.  ace.restrict* monotonicity  --  <<ACE-instruction-restrict>>")

    clen = content_len(ctr_mdh())

    # -- UsagePolicy can only ever remove permissions
    probe = fresh_unit()
    bad = []
    for cur in range(32):
        for req in range(32):
            new = apply_usagepolicy_restriction(cur, req)
            for mode in ("U", "VU", "VS", "HS", "M", "D"):
                probe.mode = mode
                was = probe.usage_allowed(ctr_mdh(UsagePolicy=cur))
                now = probe.usage_allowed(ctr_mdh(UsagePolicy=new))
                if now and not was:
                    bad.append((cur, req, mode))
    check(f"restricth never widens UsagePolicy ({32*32} field pairs x 6 modes)", bad, [])

    u = fresh_unit()
    provision(u, 0, ctr_mdh(UsagePolicy=0b00001), b"\x11" * clen)
    u.restricth(0, mdh_new(UsagePolicy=0b00100))
    check("restricth ORs deny bits 0-3", u.crs[0].mdh["UsagePolicy"], 0b00101)
    u.restricth(0, mdh_new(UsagePolicy=0b00000))
    check("a zero UsagePolicy request changes nothing", u.crs[0].mdh["UsagePolicy"], 0b00101)

    u = fresh_unit()
    provision(u, 0, ctr_mdh(UsagePolicy=0b10000), b"\x11" * clen)
    u.restricth(0, mdh_new(UsagePolicy=0b10000))
    check("a one in bit 4 withdraws the Debug grant", u.crs[0].mdh["UsagePolicy"], 0b00000)

    # -- ExpirationDate only ever decreases (when nonzero)
    u = fresh_unit()
    provision(u, 0, ctr_mdh(ExpirationDate=1000), b"\x11" * clen)
    u.restricth(0, mdh_new(ExpirationDate=900))
    check("ExpirationDate may be lowered", u.crs[0].mdh["ExpirationDate"], 900)
    u.restricth(0, mdh_new(ExpirationDate=2000))
    check("ExpirationDate may not be raised", u.crs[0].mdh["ExpirationDate"], 900)
    u.restricth(0, mdh_new(ExpirationDate=0))
    check("a zero ExpirationDate request changes nothing",
          u.crs[0].mdh["ExpirationDate"], 900)
    u = fresh_unit()
    provision(u, 0, ctr_mdh(ExpirationDate=0), b"\x11" * clen)
    u.restricth(0, mdh_new(ExpirationDate=5))
    check("a zero ExpirationDate is set unconditionally", u.crs[0].mdh["ExpirationDate"], 5)

    # -- SCProtection only strengthens
    u = fresh_unit()
    provision(u, 0, ctr_mdh(SCProtection=1), b"\x11" * clen)
    u.restrictl(0, mdh_new(SCProtection=2))
    check("SCProtection may be raised", u.crs[0].mdh["SCProtection"], 2)
    r = u.restrictl(0, mdh_new(SCProtection=1))
    check("a weaker SCProtection request invalidates the CR", (r, u.getst(0)),
          ("invalid", ST_INVALID))
    check("SCProtection weakening: Error-State entry cleared the content",
          u.crs[0].content, b"")

    # -- AlgorithmPolicy: no disabled operation may be re-enabled
    u = fresh_unit()
    provision(u, 0, ctr_mdh(AlgorithmPolicy=0b01), b"\x11" * content_len(ctr_mdh(AlgorithmPolicy=0b01)))
    r = u.restrictl(0, mdh_new(AlgorithmPolicy=0b11))
    check("re-enabling an AlgorithmPolicy bit invalidates the CR", (r, u.getst(0)),
          ("invalid", ST_INVALID))
    u = fresh_unit()
    provision(u, 0, ctr_mdh(AlgorithmPolicy=0b11), b"\x11" * content_len(ctr_mdh()))
    check("narrowing AlgorithmPolicy is allowed",
          (u.restrictl(0, mdh_new(AlgorithmPolicy=0b01)), u.crs[0].mdh["AlgorithmPolicy"]),
          ("ok", 0b01))
    # an algorithm that does not use AlgorithmPolicy must be given zero
    u = fresh_unit()
    hm = mdh_new(Algorithm=ALG_HASH, AlgorithmPolicy=0)
    provision(u, 0, hm, b"\x22" * content_len(hm))
    r = u.restrictl(0, mdh_new(AlgorithmPolicy=0b01))
    check("nonzero AlgorithmPolicy for an algorithm that does not use it invalidates",
          (r, u.getst(0)), ("invalid", ST_INVALID))
    # disabling the operation the current State requires
    u = fresh_unit()
    provision(u, 0, ctr_mdh(AlgorithmPolicy=0b11), b"\x11" * content_len(ctr_mdh()))
    u.setst(0, ST_ENCRYPT)
    r = u.restrictl(0, mdh_new(AlgorithmPolicy=0b10))
    check("disabling the operation required by the current State invalidates",
          (r, u.getst(0)), ("invalid", ST_INVALID))

    # -- Locality narrowing along the HW chains only
    cases = [
        # (current, requested, expected result, expected new value)
        (loc(hw1=1), loc(hw1=2), "ok", loc(hw1=2)),         # SiPScrt -> ChipFamScrt
        (loc(hw1=1), loc(hw1=3), "ok", loc(hw1=3)),         # SiPScrt -> ChipScrt
        (loc(hw1=2), loc(hw1=3), "ok", loc(hw1=3)),         # ChipFamScrt -> ChipScrt
        (loc(hw1=3), loc(hw1=2), "invalid", None),          # widening
        (loc(hw1=3), loc(hw1=1), "invalid", None),          # widening
        (loc(hw2=1), loc(hw2=3), "ok", loc(hw2=3)),         # OEMScrt -> DevScrt
        (loc(hw2=3), loc(hw2=1), "invalid", None),          # widening
        (loc(), loc(hw1=2), "ok", loc(hw1=2)),              # zero subfield -> anything
        (loc(boot=1), loc(boot=2), "invalid", None),        # Boot Session change
        (loc(boot=1), loc(boot=1), "ok", loc(boot=1)),      # Boot Session no-op
        (loc(), loc(boot=2), "ok", loc(boot=2)),            # zero Boot Session -> set
        (loc(), loc(sloc=1), "ok", loc(sloc=1)),            # SW Filter bit
        (loc(hw1=1, hw2=1), loc(hw1=2, hw2=2), "ok", loc(hw1=2, hw2=2)),  # both chains
        (loc(hw1=1, hw2=3), loc(hw1=2, hw2=1), "invalid", None),          # one widens
    ]
    for cur, req, want_r, want_v in cases:
        u = fresh_unit()
        provision(u, 0, ctr_mdh(Locality=cur), b"\x11" * clen)
        r = u.restricth(0, mdh_new(Locality=req))
        got_v = u.crs[0].mdh["Locality"] if r == "ok" else None
        check(f"Locality {cur:#011b} -> {req:#011b}", (r, got_v), (want_r, want_v))
        if want_r == "invalid":
            check(f"  ... and the CR is invalidated", u.getst(0), ST_INVALID)

    # -- restrictv composition: restrictl then restricth, second skipped on error
    u = fresh_unit()
    provision(u, 0, ctr_mdh(SCProtection=2, UsagePolicy=0), b"\x11" * clen)
    xs = mdh_new(SCProtection=1, UsagePolicy=0b0001)      # illegal weakening
    r = u.restrictv(0, xs)
    check("restrictv: an error in restrictl skips restricth",
          (r, u.getst(0), u.crs[0].mdh["UsagePolicy"]), ("invalid", ST_INVALID, 0))
    u = fresh_unit()
    provision(u, 0, ctr_mdh(SCProtection=0, UsagePolicy=0), b"\x11" * clen)
    xs = mdh_new(SCProtection=2, UsagePolicy=0b0001)
    r = u.restrictv(0, xs)
    check("restrictv: both halves applied when the first succeeds",
          (r, u.crs[0].mdh["SCProtection"], u.crs[0].mdh["UsagePolicy"]), ("ok", 2, 1))

    # -- restrict is NOT usage-controlled (m13, fixed), but still narrows only,
    #    and is still a no-op on an Error-State CR
    u = fresh_unit()
    provision(u, 0, ctr_mdh(UsagePolicy=0b0001), b"\x11" * clen)
    u.mode = "U"                       # bit 0 set: U-mode may not *use* this CC
    try:
        r = u.restricth(0, mdh_new(UsagePolicy=0b0010))
        check("ace.restrict is not usage-controlled: a mode barred from using "
              "the CC may still narrow it",
              (r, u.crs[0].mdh["UsagePolicy"]), ("ok", 0b0011))
    except AceException as e:
        check("ace.restrict is not usage-controlled", f"raised {e.which}", "ok")
    # ... and it still cannot widen, from any mode
    before = u.crs[0].mdh["UsagePolicy"]
    u.restricth(0, mdh_new(UsagePolicy=0))
    check("ace.restrict from a barred mode still cannot widen",
          u.crs[0].mdh["UsagePolicy"], before)
    u.mode = "M"
    u.setst(0, ST_INVALID)
    check("ace.restrict on an Error-State CR is a no-op",
          (u.restricth(0, mdh_new(UsagePolicy=0b1000)), u.getst(0)), ("noop", ST_INVALID))

    info("restricth: the spec says a too-large ExpirationDate 'is copied only if <=', "
         "i.e. silently ignored, whereas every other illegal widening invalidates the "
         "CR. Modelled as written (silent no-change); the asymmetry is worth a "
         "normative decision.")


def test_localities():
    section("5.  Locality substitution  --  <<ACE-Localities>>")

    full = set(range(11))
    # SiPScrt unconfigured -> ChipFamScrt substituted
    u = fresh_unit(lst=full - {0})
    res = loc_resolve(u, loc(hw1=1))
    check("unconfigured SiPScrt is substituted by ChipFamScrt", res, {1})
    # SiPScrt and ChipFamScrt unconfigured -> ChipScrt
    u = fresh_unit(lst=full - {0, 1})
    check("substitution walks the chain to ChipScrt", loc_resolve(u, loc(hw1=1)), {2})
    # ChipScrt unconfigured with nothing after it -> invalid
    u = fresh_unit(lst=full - {2})
    check("unconfigured ChipScrt with no successor: Metadata invalid",
          loc_resolve(u, loc(hw1=3)), None)
    # the second chain
    u = fresh_unit(lst=full - {3})
    check("unconfigured OEMScrt is substituted by ProdScrt",
          loc_resolve(u, loc(hw2=1)), {4})
    u = fresh_unit(lst=full - {3, 4})
    check("OEMScrt falls through to DevScrt", loc_resolve(u, loc(hw2=1)), {5})

    # never dropped: the resolved entry is in the same chain and no earlier than requested
    u = fresh_unit(lst=full - {0, 3})
    res = loc_resolve(u, 0b000000_01_01)
    check("substituted-never-dropped: both chains still bound", res, {1, 4})
    check_true("a request is never resolved to nothing", res is not None and len(res) == 2)

    # a Locality request whose entry is unconfigured outside the HW group is invalid
    u = fresh_unit(lst=full - {6})
    check("unconfigured PhysBootScrt cannot be substituted", loc_resolve(u, loc(boot=1)), None)
    u = fresh_unit(lst=full - {10})
    check("unconfigured SLocality cannot be substituted", loc_resolve(u, loc(sloc=1)), None)

    # the active-set limits of the field encoding
    everything = loc(hw1=2, hw2=3, boot=2, mloc=1, hloc=1, sloc=1)
    u = fresh_unit()
    check("six architected Localities active at once is representable",
          loc_active_count(everything), 6)
    check("all six resolve", len(loc_resolve(u, everything)), 6)
    check_true("the encoding cannot express two HW-group entries from one chain",
               fwidth("Locality") == 9)

    # a provisioning whose Locality cannot be resolved invalidates at sealing time
    u = fresh_unit(lst=full - {2})
    ml = ctr_mdh(Locality=loc(hw1=3))
    u.mgmt_provision_start(0, ml)
    mem = bytearray(16 + content_len(ml))
    u.load(0, mem, 16)
    u.mgmt_end(0)
    check("unresolvable Locality invalidates the CR at provisioning completion",
          u.getst(0), ST_INVALID)

    info("Locality encoding [5:4] = 3 is now declared reserved by <<ACE-Localities>> "
         "(review m9, fixed): a PI or SCC carrying it is invalid Metadata and the CR "
         "transitions to Error State Invalid. Previously the spec stated no behaviour "
         "for it and the model had to choose one.")


def test_state_machine():
    section("6.  Generic State rules  --  <<ACE-State-field>> rules 1-14")

    clen = content_len(ctr_mdh())

    # rule 12: getmd* on an Unconfigured CR returns all zeros
    u = fresh_unit()
    check("rule 12: getmdv of an Unconfigured CR is all zeros",
          mdh_pack(u.getmdv(0)), 0)
    check("rule 12: getmdl of an Unconfigured CR is zero", u.getmdl(0), 0)
    check("ace.size Form A of an Unconfigured CR is 0", u.size_A(0), 0)

    # rule 4: a transition from any valid state to Ready is always permitted
    for st in (ST_ENCRYPT, ST_ABSORB, ST_SUCCESS, ST_FAILURE):
        u = fresh_unit()
        provision(u, 0, ctr_mdh(), b"\x11" * clen)
        u.crs[0].mdh["State"] = st
        u.setst(0, ST_READY)
        check(f"rule 4: State {st} -> Ready is permitted", u.getst(0), ST_READY)

    # rule 3: in Success/Failure, setst may only target Ready or Unconfigured
    for st in (ST_SUCCESS, ST_FAILURE):
        u = fresh_unit()
        provision(u, 0, ctr_mdh(), b"\x11" * clen)
        u.crs[0].mdh["State"] = st
        u.setst(0, ST_UNCONFIGURED)
        check(f"rule 3: State {st} -> Unconfigured permitted", u.getst(0), ST_UNCONFIGURED)

        u = fresh_unit()
        provision(u, 0, ctr_mdh(), b"\x11" * clen)
        u.crs[0].mdh["State"] = st
        u.setst(0, ST_ENCRYPT)
        check(f"rule 3: State {st} -> Encrypt invalidates the CR", u.getst(0), ST_INVALID)

        u = fresh_unit()
        provision(u, 0, ctr_mdh(), b"\x11" * clen)
        u.crs[0].mdh["State"] = st
        u.setst(0, ST_INVALID)
        check(f"rule 3: State {st} -> an Error State is always permitted",
              u.getst(0), ST_INVALID)

    # rule 7: Error-State entry effects
    for st in ERROR_STATES:
        u = fresh_unit()
        # a CR as restored from an SCC: nonzero ImpDataLen and StateExtension
        # (a PI may carry neither, so this state is reached through import)
        m = ctr_mdh(ImpDataLen=2, StateExtension=3, ConfigStatus=CFG_COMPLETE)
        u.mgmt_import_start(0, m)
        payload = toy_seal(b"\x11" * (content_len(m) + 48), mdh_bytes(m))
        mem = bytearray(16 + len(payload))
        mem[16:] = payload
        u.load(0, mem, 16)
        u.mgmt_end(0, m)
        check_true(f"rule 7 (State {st}): the CR is set up and complete",
                   u.crs[0].cfg == CFG_COMPLETE and u.crs[0].mdh["ImpDataLen"] == 2)
        before = mdh_pack(u.crs[0].mdh)
        u.setst(0, st)
        cr = u.crs[0]
        check(f"rule 7 (State {st}): content beyond the MDH is cleared", cr.content, b"")
        check(f"rule 7 (State {st}): ImpDataLen is zeroed", cr.mdh["ImpDataLen"], 0)
        check(f"rule 7 (State {st}): ConfigStatus is set to complete",
              cr.mdh["ConfigStatus"], CFG_COMPLETE)
        check(f"rule 7 (State {st}): State field reflects the Error State",
              cr.mdh["State"], st)
        check(f"rule 7 (State {st}): the MDH is retained (Algorithm survives)",
              (cr.mdh["Algorithm"], before != 0), (ALG_CTR, True))
        # rule 9: the export of an Error-State CR is 32 bytes
        check(f"rule 9 (State {st}): ace.size returns 32", u.size_A(0), 32)
        # rule 11: getmd* still works
        check(f"rule 11 (State {st}): getmdv still returns the MDH",
              u.getmdv(0)["State"], st)
        # rule 13: usage is a no-op leaving State unchanged
        check(f"rule 13 (State {st}): ace.exec is a no-op",
              (u.exec_(0), u.getst(0)), ("noop", st))
        check(f"rule 13 (State {st}): ace.setst to a valid state is a no-op",
              (u.setst(0, ST_ENCRYPT), u.getst(0)), ("noop", st))

    # rule 10: an Error-State CR can be cleared, re-provisioned and cloned
    u = fresh_unit()
    provision(u, 0, ctr_mdh(), b"\x11" * clen)
    u.setst(0, ST_INVALID)
    u.clone(1, 0)
    check("rule 10: an Error-State CR can be cloned", u.getst(1), ST_INVALID)
    u.setst(0, ST_UNSUPPORTED)
    check("rule 10: setst may change one Error State to another", u.getst(0), ST_UNSUPPORTED)
    u.setst(0, ST_UNCONFIGURED)
    check("rule 8: an Error State -> Unconfigured by clearing the CR",
          (u.getst(0), u.crs[0].is_unconfigured()), (ST_UNCONFIGURED, True))
    provision(u, 0, ctr_mdh(), b"\x11" * clen)
    check("rule 10: a cleared CR can be re-provisioned", u.getst(0), ST_READY)

    # rule 1: Ready/Success/Failure/Error are all readable from the State field alone
    u = fresh_unit()
    provision(u, 0, ctr_mdh(), b"\x11" * clen)
    check("rule 1: a just-provisioned CC is in State Ready", u.getst(0), ST_READY)

    # the Book 4 error test: State > 23 is an Error State, State == 0 means cleared
    check_true("Book 4 test 'bltu 23, State': error iff State >= 24",
               all((s > 23) == (s in ERROR_STATES) for s in range(0, 32)))

    info("Rule 2 lists the instructions permitted in Success/Failure but does not say "
         "what a non-listed one (ace.clone, ace.restrict*, ace.derive) does there. "
         "Modelled only for ace.exec/ace.setst, whose behaviour rules 3 and 13 pin down.")


def test_config_status_gating():
    section("7.  ConfigStatus gating  --  <<ACE-ConfigStatus>>")

    clen = content_len(ctr_mdh())
    ml = ctr_mdh()

    for cfg, opener in ((CFG_PROVISIONING, "provisioning"), (CFG_IMPORTING, "importing")):
        u = fresh_unit()
        if cfg == CFG_PROVISIONING:
            u.mgmt_provision_start(0, ml)
        else:
            u.mgmt_import_start(0, ml)
        check(f"ace.mgmt start sets ConfigStatus to {opener}", u.crs[0].cfg, cfg)

        # usage is blocked
        try:
            u.exec_(0)
            check(f"usage of a {opener} CR raises privilege_violation", "none",
                  "privilege_violation")
        except AceException as e:
            check(f"usage of a {opener} CR raises privilege_violation", e.which,
                  "privilege_violation")
        # cloning is blocked
        try:
            u.clone(1, 0)
            check(f"cloning a {opener} CR raises privilege_violation", "none",
                  "privilege_violation")
        except AceException as e:
            check(f"cloning a {opener} CR raises privilege_violation", e.which,
                  "privilege_violation")
        # setst to a valid state is usage and is blocked
        try:
            u.setst(0, ST_ENCRYPT)
            check(f"setst to a valid state on a {opener} CR raises privilege_violation",
                  "none", "privilege_violation")
        except AceException as e:
            check(f"setst to a valid state on a {opener} CR raises privilege_violation",
                  e.which, "privilege_violation")

        # the exemption list
        check(f"exempt on a {opener} CR: ace.getmd*", u.getmdv(0)["Algorithm"], ALG_CTR)
        check(f"exempt on a {opener} CR: ace.getst", u.getst(0),
              ST_READY if cfg == CFG_PROVISIONING else 0)
        check(f"exempt on a {opener} CR: ace.size",
              u.size_A(0), serialized_len(u.crs[0].mdh))
        mem = bytearray(4096)
        u.load(0, mem, 16)
        check_true(f"exempt on a {opener} CR: ace.load", True)
        u.setst(0, ST_INVALID)
        check(f"exempt on a {opener} CR: setst to an Error State", u.getst(0), ST_INVALID)
        u.setst(0, ST_UNCONFIGURED)
        check(f"exempt on a {opener} CR: setst to Unconfigured (ace.clear)",
              u.crs[0].is_unconfigured(), True)

    # ace.load / ace.store / ace.mv on a complete CR: illegal instruction
    u = fresh_unit()
    provision(u, 0, ml, b"\x11" * clen)
    mem = bytearray(4096)
    for name, fn in (("ace.load", lambda: u.load(0, mem, 16)),
                     ("ace.store", lambda: u.store(mem, 16, 0)),
                     ("ace.mv in", lambda: u.mv_in(0, b"\x00" * 16)),
                     ("ace.mv out", lambda: u.mv_out(0, 16))):
        try:
            fn()
            check(f"{name} on a complete CR raises an illegal instruction", "none",
                  "IllegalInstruction")
        except IllegalInstruction:
            check_true(f"{name} on a complete CR raises an illegal instruction", True)

    # ace.mv gating on the exporting ConfigStatus
    u = fresh_unit()
    provision(u, 0, ml, b"\x11" * clen)
    u.mgmt_export_start(0)
    check("ace.mgmt export start sets ConfigStatus to exporting", u.crs[0].cfg, CFG_EXPORTING)
    check_true("ace.mv out is permitted while exporting", len(u.mv_out(0, 16)) == 16)


def test_management_flows():
    section("8.  Management flows  --  Book 4 sequences")

    ml = ctr_mdh(UsagePolicy=0b0001, Locality=loc(hw1=2))
    clen = content_len(ml)
    content = bytes((0x40 + i) & 0xFF for i in range(clen))

    # -- provisioning, Zklmem ----------------------------------------
    u = fresh_unit()
    u.mgmt_provision_start(0, ml)
    check("provision start: ConfigStatus = provisioning", u.crs[0].cfg, CFG_PROVISIONING)
    check("provision start: acestart cleared", u.acestart, 0)
    check("provision start: managedcr holds the CR number", u.managedcr, 0)
    check("provision start: State is Ready", u.getst(0), ST_READY)
    pi = bytearray(mdh_bytes(u.crs[0].mdh) + content)
    check("ace.size Form A while provisioning is the PI length", u.size_A(0), pi_len(ml))
    u.load(0, pi, 16)                      # memory base <-> serialized offset 16
    check("ace.load: acestart cleared on completion", u.acestart, 0)
    u.mgmt_end(0)
    check("provision end: ConfigStatus = complete", u.crs[0].cfg, CFG_COMPLETE)
    check("provision end: acestart cleared", u.acestart, 0)
    check("provision end: managedcr released", u.managedcr, MANAGEDCR_NONE)
    check("provision end: content is what the PI carried", u.crs[0].content, content)
    check("ace.size Form A when complete is the SCC length", u.size_A(0), scc_len(ml))

    # -- provisioning, Zklmv -----------------------------------------
    u2 = fresh_unit()
    u2.mgmt_provision_start(0, ml)
    starts = []
    for off in range(0, clen, 16):
        starts.append(u2.acestart)
        u2.mv_in(0, content[off:off + 16])
    check("ace.mv accumulates acestart across instructions", starts,
          list(range(0, clen, 16)))
    check("ace.mv: acestart is NOT cleared on completion (the documented exemption)",
          u2.acestart, clen)
    u2.mgmt_end(0)
    check("Zklmv and Zklmem provisioning agree",
          (u2.crs[0].content, u2.crs[0].cfg), (u.crs[0].content, u.crs[0].cfg))
    check("ace.mgmt end clears the accumulated acestart", u2.acestart, 0)

    # -- export of a complete CR, then re-import ---------------------
    saved_ml = u.mgmt_export_start(0)
    check("export start: ml carries ConfigStatus = complete",
          saved_ml["ConfigStatus"], CFG_COMPLETE)
    check("export start: acestart cleared", u.acestart, 0)
    n = scc_len(ml)
    mem = bytearray(n)
    mem[0:16] = mdh_bytes(saved_ml)         # software stores the MDH itself
    u.store(mem, 16, 0)
    check("ace.store: acestart cleared on completion", u.acestart, 0)
    check("ace.store wrote exactly the SCC payload", len(mem), n)
    check_true("the exported payload is not the plaintext content",
               bytes(mem[16:16 + clen]) != content)
    u.mgmt_end(0, saved_ml)
    check("export end: the CR is usable again", u.crs[0].cfg, CFG_COMPLETE)
    check("export end: the content was restored", u.crs[0].content, content)
    check("export end: managedcr released", u.managedcr, MANAGEDCR_NONE)

    # re-import into a different CR, Zklmem
    v = fresh_unit()
    imported_ml = mdh_unpack(b2v(bytes(mem[0:16])))
    check("ace.size Form B of the stored MDH is the SCC length", v.size_B(imported_ml), n)
    v.mgmt_import_start(1, imported_ml)
    check("import start: ConfigStatus = importing", v.crs[1].cfg, CFG_IMPORTING)
    check("import start: acestart cleared", v.acestart, 0)
    v.load(1, mem, 16)
    v.mgmt_end(1, imported_ml)
    check("import end: ConfigStatus = complete", v.crs[1].cfg, CFG_COMPLETE)
    check("import end: the content round trips", v.crs[1].content, content)
    check("import end: the MDH round trips", v.getmdv(1), u.getmdv(0))

    # re-import, Zklmv
    w = fresh_unit()
    w.mgmt_import_start(1, imported_ml)
    for off in range(16, n, 16):
        w.mv_in(1, bytes(mem[off:off + 16]))
    w.mgmt_end(1, imported_ml)
    check("Zklmv import agrees with Zklmem import",
          (w.crs[1].content, w.getmdv(1)), (v.crs[1].content, v.getmdv(1)))

    # -- import of an SCC with a nonzero State (the C2 case) ---------
    u = fresh_unit()
    provision(u, 0, ml, content)
    u.setst(0, ST_ENCRYPT)
    check("a CR mid-algorithm has a nonzero State", u.getst(0), ST_ENCRYPT)
    saved = u.mgmt_export_start(0)
    mem2 = bytearray(scc_len(saved))
    mem2[0:16] = mdh_bytes(saved)
    u.store(mem2, 16, 0)
    u.mgmt_end(0, saved)
    v = fresh_unit()
    ml2 = mdh_unpack(b2v(bytes(mem2[0:16])))
    v.mgmt_import_start(1, ml2)
    check("import start accepts a nonzero State (C2)", v.crs[1].cfg, CFG_IMPORTING)
    v.load(1, mem2, 16)
    v.mgmt_end(1, ml2)
    check("import restores the mid-algorithm State", v.getst(1), ST_ENCRYPT)
    check("import restores the content", v.crs[1].content, u.crs[0].content)

    # provisioning, by contrast, requires State == 0
    p = fresh_unit()
    p.mgmt_provision_start(0, ctr_mdh(State=ST_ENCRYPT))
    check("provision start rejects a nonzero State", p.getst(0), ST_INVALID)
    p = fresh_unit()
    p.mgmt_provision_start(0, ctr_mdh(ImpDataLen=1))
    check("provision start rejects a nonzero ImpDataLen", p.getst(0), ST_INVALID)
    p = fresh_unit()
    p.mgmt_provision_start(0, ctr_mdh(StateExtension=1))
    check("provision start rejects a nonzero StateExtension", p.getst(0), ST_INVALID)
    p = fresh_unit()
    p.mgmt_provision_start(0, mdh_unpack(mdh_pack(ctr_mdh()) | (1 << 14)))
    check("provision start rejects a nonzero reserved field", p.getst(0), ST_INVALID)
    p = fresh_unit()
    p.mgmt_import_start(0, mdh_unpack(mdh_pack(ctr_mdh()) | (1 << 14)))
    check("import start rejects a nonzero reserved field", p.getst(0), ST_INVALID)

    # unsupported algorithm raises rather than invalidating
    p = fresh_unit()
    try:
        p.mgmt_provision_start(0, mdh_new(Algorithm=0x777, AlgorithmPolicy=1))
        check("an unsupported Algorithm raises ace_exc_unsupported", "none", "unsupported")
    except AceException as e:
        check("an unsupported Algorithm raises ace_exc_unsupported", e.which, "unsupported")
    p = fresh_unit()
    try:
        p.mgmt_provision_start(0, ctr_mdh(SCProtection=5))
        check("an unsupported SCProtection raises ace_exc_unsupported", "none", "unsupported")
    except AceException as e:
        check("an unsupported SCProtection raises ace_exc_unsupported", e.which, "unsupported")

    # out of memory
    p = fresh_unit(crf_capacity_total=8)
    try:
        p.mgmt_provision_start(0, ml)
        check("insufficient CRF capacity raises ace_exc_out_of_memory", "none", "out_of_memory")
    except AceException as e:
        check("insufficient CRF capacity raises ace_exc_out_of_memory", e.which, "out_of_memory")

    # managedcr interlock
    p = fresh_unit()
    p.mgmt_provision_start(0, ml)
    try:
        p.mgmt_provision_start(1, ml)
        check("ace.mgmt on a second CR while one is managed is illegal", "none",
              "IllegalInstruction")
    except IllegalInstruction:
        check_true("ace.mgmt on a second CR while one is managed is illegal", True)

    # -- export of a partially provisioned CR, verbatim, and its re-import
    u = fresh_unit()
    u.mgmt_provision_start(0, ml)
    pi = bytearray(16 + clen)
    pi[0:16] = mdh_bytes(u.crs[0].mdh)
    pi[16:] = content
    u.load(0, pi, 16, halt_after=16)        # only part of the PI is in
    partial_ml = u.mgmt_export_start(0)
    check("export start of a not-complete CR leaves ConfigStatus alone",
          u.crs[0].cfg, CFG_PROVISIONING)
    check("export start of a not-complete CR: ml carries the partial ConfigStatus",
          partial_ml["ConfigStatus"], CFG_PROVISIONING)
    out = bytearray(pi_len(ml))
    out[0:16] = mdh_bytes(partial_ml)
    u.acestart = 0
    u.store(out, 16, 0)
    check("the partial export is verbatim (unencrypted)",
          bytes(out[16:32]), content[0:16])
    check("the partial export has the PI length", len(out), pi_len(ml))
    u.mgmt_end(0, partial_ml)
    check("completing the export of a not-complete CR makes no state change",
          u.crs[0].cfg, CFG_PROVISIONING)

    # re-import it: ConfigStatus must come back as `ml`.ConfigStatus
    v = fresh_unit()
    rml = mdh_unpack(b2v(bytes(out[0:16])))
    v.mgmt_import_start(2, rml)
    v.load(2, out, 16)
    v.mgmt_end(2, rml)
    check("re-import of a partial export restores ConfigStatus per ml (C2/partial path)",
          v.crs[2].cfg, CFG_PROVISIONING)
    check("re-import of a partial export leaves the CR resumable",
          bytes(v.crs[2].xfer[0:16]), content[0:16])
    # and the resumed provisioning can be finished
    v.acestart = 16
    v.load(2, pi, 16)
    v.mgmt_end(2)
    check("a re-imported partial provisioning can be completed",
          (v.crs[2].cfg, v.crs[2].content), (CFG_COMPLETE, content))

    # -- Error-State CR export is 32 bytes, and re-imports ------------
    u = fresh_unit()
    provision(u, 0, ml, content)
    u.setst(0, ST_FAILURE)
    u.setst(0, ST_INVALID)
    check("an Error-State CR exports 32 bytes", u.size_A(0), 32)
    eml = u.mgmt_export_start(0)
    membuf = bytearray(32)
    membuf[0:16] = mdh_bytes(eml)
    u.store(membuf, 16, 0)
    check("the Error-State export is MDH + SIV", len(membuf), 32)
    u.mgmt_end(0, eml)
    v = fresh_unit()
    iml = mdh_unpack(b2v(bytes(membuf[0:16])))
    v.mgmt_import_start(3, iml)
    v.load(3, membuf, 16)
    v.mgmt_end(3, iml)
    check("an Error-State SCC re-imports and keeps its Error State", v.getst(3), ST_INVALID)
    check("the re-imported Error-State CR has no content", v.crs[3].content, b"")

    info("C1: the current text defines the mapping explicitly -- 'the j-th byte after "
         "the MDH is loaded to/saved from memory address Xs1 + %offset + j' -- and "
         "ace.mgmt now clears acestart rather than setting it to 16. Modelled that way: "
         "the memory base passed to ace.load/ace.store corresponds to serialized offset "
         "16, and acestart counts payload bytes from 0.")


def test_resumption():
    section("9.  Interrupted transfers and resumption")

    ml = ctr_mdh(ImpDataLen=2)             # a longer payload, to halt in the middle
    clen = content_len(ml) + 32
    content = bytes((0x90 + i) & 0xFF for i in range(clen))

    # -- ace.load ----------------------------------------------------
    u = fresh_unit()
    u.mgmt_import_start(0, dict(ml, ConfigStatus=CFG_COMPLETE))
    n = scc_len(ml) - 16
    blob = bytes(range(n)) if n <= 256 else bytes((i * 7) & 0xFF for i in range(n))
    mem = bytearray(16 + n)
    mem[16:] = blob
    done = u.load(0, mem, 16, halt_after=32)
    check("ace.load interrupted: reports incompletion", done, False)
    check("ace.load interrupted: acestart is the prefix-complete offset", u.acestart, 32)
    saved = u.acestart
    u.acestart = 0xDEAD                     # a context switch clobbers the CSR
    u.acestart = saved                      # ... and restores it
    done = u.load(0, mem, 16)
    check("ace.load resumed: completes", done, True)
    check("ace.load resumed: acestart cleared", u.acestart, 0)
    check("ace.load resumed: every byte transferred exactly once", bytes(u.crs[0].xfer), blob)

    # resumption offsets both memory and CR by j
    u2 = fresh_unit()
    u2.mgmt_import_start(0, dict(ml, ConfigStatus=CFG_COMPLETE))
    u2.acestart = 32
    u2.load(0, mem, 16)
    check("ace.load from acestart=32 leaves the first 32 bytes untouched",
          bytes(u2.crs[0].xfer[0:32]), bytes(32))
    check("ace.load from acestart=32 places memory base+32 at payload offset 32",
          bytes(u2.crs[0].xfer[32:]), blob[32:])

    # acestart above the transfer size is clamped
    u3 = fresh_unit()
    u3.mgmt_import_start(0, dict(ml, ConfigStatus=CFG_COMPLETE))
    u3.acestart = n + 1000
    u3.load(0, mem, 16)
    check("acestart above the PI/SCC size is clamped to it (no transfer, then cleared)",
          (u3.acestart, bytes(u3.crs[0].xfer)), (0, bytes(n)))

    # -- ace.store ---------------------------------------------------
    u = fresh_unit()
    provision(u, 0, ctr_mdh(), b"\x5A" * content_len(ctr_mdh()))
    sml = u.mgmt_export_start(0)
    total = scc_len(sml)
    out = bytearray(total)
    out[0:16] = mdh_bytes(sml)
    ref = bytes(u.crs[0].export)
    done = u.store(out, 16, 0, halt_after=16)
    check("ace.store interrupted: reports incompletion", done, False)
    check("ace.store interrupted: acestart is the prefix-complete offset", u.acestart, 16)
    check("ace.store interrupted: only the prefix was written",
          bytes(out[16:32]), ref[0:16])
    check("ace.store interrupted: the tail is untouched",
          bytes(out[32:]), bytes(total - 32))
    saved = u.acestart
    u.acestart = 0
    u.acestart = saved
    u.store(out, 16, 0)
    check("ace.store resumed: the whole payload is in memory", bytes(out[16:]), ref)
    check("ace.store resumed: acestart cleared", u.acestart, 0)

    # -- ace.input / ace.output --------------------------------------
    u = fresh_unit()
    u.write_aceiobuflen(64)
    src = bytes((0x10 + i) & 0xFF for i in range(64))
    mem = bytearray(src)
    done = u.input_(mem, 0, 64, halt_after=20)
    check("ace.input interrupted: reports incompletion", done, False)
    check("ace.input interrupted: acestart is the byte offset", u.acestart, 20)
    check("ace.input interrupted: only the prefix landed in the buffer",
          bytes(u.aceiobuf[0:20]), src[0:20])
    check("ace.input interrupted: the rest of the buffer is untouched",
          bytes(u.aceiobuf[20:]), bytes(44))
    saved = u.acestart
    u.acestart = 999
    u.acestart = saved
    done = u.input_(mem, 0, 64)
    check("ace.input resumed: completes", done, True)
    check("ace.input resumed: acestart cleared on success", u.acestart, 0)
    check("ace.input resumed: the buffer matches memory", bytes(u.aceiobuf), src)

    dst = bytearray(64)
    done = u.output(dst, 0, 64, halt_after=48)
    check("ace.output interrupted: acestart is the byte offset", u.acestart, 48)
    check("ace.output interrupted: only the prefix was written", bytes(dst[0:48]), src[0:48])
    check("ace.output interrupted: the tail is untouched", bytes(dst[48:]), bytes(16))
    u.output(dst, 0, 64)
    check("ace.output resumed: memory matches the buffer", bytes(dst), src)
    check("ace.output resumed: acestart cleared on success", u.acestart, 0)

    # resumption offsets both sides by j
    u.write_aceiobuflen(32)
    mem = bytearray(bytes((0xC0 + i) & 0xFF for i in range(32)))
    u.acestart = 8
    u.input_(mem, 0, 32)
    check("ace.input at acestart=8: buffer bytes below 8 untouched",
          bytes(u.aceiobuf[0:8]), bytes(8))
    check("ace.input at acestart=8: memory base+j goes to buffer byte j",
          bytes(u.aceiobuf[8:]), bytes(mem[8:]))


def test_aceiobuf():
    section("10.  ACEIOBUF window semantics  --  aceiobuflen / aceiobuftop / acestart")

    u = fresh_unit(maxiobuflen=128)
    check("aceiobuflen out of reset is 0", u.aceiobuflen, 0)
    check("aceiobuftop out of reset is 0", u.aceiobuftop, 0)
    check("acestart out of reset is 0", u.acestart, 0)

    # unconfigured buffer
    try:
        u.input_(bytearray(16), 0, 16)
        check("ace.input on an unconfigured buffer raises", "none", "unconfigured_buffer")
    except AceException as e:
        check("ace.input on an unconfigured buffer raises", e.which, "unconfigured_buffer")

    # writing aceiobuflen zeroes the buffer and sets aceiobuftop
    u.write_aceiobuflen(64)
    u.aceiobuf[0:4] = b"\xFF\xFF\xFF\xFF"
    check("aceiobuflen write sets aceiobuftop to the same value", u.aceiobuftop, 64)
    u.write_aceiobuflen(64)                 # re-writing the same value
    check("re-writing aceiobuflen zeroes the buffer", bytes(u.aceiobuf), bytes(64))
    check("re-writing aceiobuflen re-sets aceiobuftop", u.aceiobuftop, 64)

    # m10 (fixed): without Zklio the ACEIOBUF does not exist, acemaxiobuflen
    # reads as zero, and aceiobuflen / aceiobuftop are not present at all.
    u_nolio = fresh_unit(maxiobuflen=0)
    check("without Zklio: acemaxiobuflen reads 0", u_nolio.acemaxiobuflen, 0)
    check("without Zklio: aceiobuflen cannot be made nonzero",
          (u_nolio.write_aceiobuflen(64), u_nolio.aceiobuflen), (0, 0))

    # WARL clamps
    got = u.write_aceiobuflen(1000)
    check("aceiobuflen WARL: clamped to acemaxiobuflen", (got, u.aceiobuflen), (128, 128))
    got = u.write_aceiobuftop(1000)
    check("aceiobuftop WARL: clamped to aceiobuflen", (got, u.aceiobuftop), (128, 128))
    u.write_aceiobuflen(64)
    u.write_aceiobuftop(48)
    check("aceiobuftop below aceiobuflen is taken as written", u.aceiobuftop, 48)
    u.write_aceiobuflen(32)                 # lowering aceiobuflen resets the top
    check("a later aceiobuflen write overrides aceiobuftop", u.aceiobuftop, 32)

    # the window is [acestart, min(Xl, aceiobuftop))
    u.write_aceiobuflen(64)
    u.write_aceiobuftop(48)
    src = bytes((i * 3 + 1) & 0xFF for i in range(64))
    mem = bytearray(src)
    u.input_(mem, 0, 64)                    # Xl > aceiobuftop
    check("ace.input with Xl > aceiobuftop transfers only the window",
          bytes(u.aceiobuf[0:48]), src[0:48])
    check("ace.input with Xl > aceiobuftop leaves bytes at/above the top untouched",
          bytes(u.aceiobuf[48:]), bytes(16))

    u.write_aceiobuflen(64)
    u.input_(mem, 0, 20)                    # Xl < aceiobuftop
    check("ace.input with Xl < aceiobuftop transfers only Xl bytes",
          (bytes(u.aceiobuf[0:20]), bytes(u.aceiobuf[20:])), (src[0:20], bytes(44)))

    # Xl == 0 and acestart >= min(Xl, aceiobuftop): no-op, acestart unchanged
    u.write_aceiobuflen(64)
    u.acestart = 7
    r = u.input_(mem, 0, 0)
    check("ace.input with Xl = 0 is a no-op with acestart unchanged", (r, u.acestart),
          ("noop", 7))
    u.acestart = 64
    r = u.input_(mem, 0, 64)
    check("ace.input with acestart >= min(Xl, aceiobuftop) is a no-op",
          (r, u.acestart), ("noop", 64))
    u.acestart = 30
    r = u.input_(mem, 0, 20)
    check("ace.input with acestart >= Xl (Xl < top) is a no-op", (r, u.acestart),
          ("noop", 30))
    u.acestart = 100
    r = u.output(bytearray(64), 0, 64)
    check("ace.output with acestart > aceiobuftop is a no-op with acestart unchanged",
          (r, u.acestart), ("noop", 100))
    # acestart is never clamped: both the equal and the strictly-greater case are
    # no-ops that leave it alone. The pre-fix text covered only acestart = aceiobuftop
    # in one place and clamped to aceiobuftop in another.
    for start, label in ((64, "acestart = aceiobuftop"),
                         (65, "acestart > aceiobuftop"),
                         (4096, "acestart far above aceiobuftop")):
        u.acestart = start
        r = u.input_(mem, 0, 64)
        check(f"{label}: no-op, and acestart is not clamped to aceiobuftop",
              (r, u.acestart), ("noop", start))

    info("m1 is RESOLVED in the current text, in favour of the no-op reading modelled "
         "here: acestart is no longer clamped for ACEIOBUF operands. If acestart >= "
         "aceiobuftop the operand window is empty, so the instruction performs no "
         "operation, causes no state transition, and leaves acestart unchanged -- the "
         "rule ace.input and ace.output already stated for their own transfers. The "
         "clamp for CR-directed transfers (ace.load/ace.store/ace.mv, bounded by the "
         "PI/SCC length) is a separate rule and is unaffected.")

    # shortening is done by lowering aceiobuftop, never by raising acestart
    u.write_aceiobuflen(64)
    u.write_aceiobuftop(16)
    u.acestart = 0
    u.input_(mem, 0, 64)
    check("shortening via aceiobuftop transfers exactly the shortened window",
          (bytes(u.aceiobuf[0:16]), bytes(u.aceiobuf[16:])), (src[0:16], bytes(48)))
    check("ACELEN = aceiobuftop * 8", u.aceiobuftop * 8, 128)


def test_expiration():
    section("11.  ExpirationDate  --  <<ACE-Metadata-expiration-date>>")

    clen = content_len(ctr_mdh())
    content = b"\x77" * clen

    def expired_cr(clock=2000, ed=1000, **kw):
        u = fresh_unit(clock=clock)
        provision(u, 0, ctr_mdh(ExpirationDate=ed, **kw), content)
        return u

    # usage of an expired CR
    u = expired_cr()
    try:
        u.exec_(0)
        check("ace.exec on an expired CR raises ace_state_expired", "none", "expired")
    except AceException as e:
        check("ace.exec on an expired CR raises ace_state_expired", e.which, "expired")
    check("the expired CR is in Error State Expired", u.getst(0), ST_EXPIRED)
    check("expiry performs the Error-State actions: content cleared", u.crs[0].content, b"")
    check("expiry performs the Error-State actions: ImpDataLen zeroed",
          u.crs[0].mdh["ImpDataLen"], 0)
    check("expiry performs the Error-State actions: ConfigStatus complete",
          u.crs[0].cfg, CFG_COMPLETE)

    # setst targeting a valid non-management state
    u = expired_cr()
    try:
        u.setst(0, ST_ENCRYPT)
        check("ace.setst to a valid state on an expired CR raises", "none", "expired")
    except AceException as e:
        check("ace.setst to a valid state on an expired CR raises", e.which, "expired")
    check("... and the CR is in Error State Expired", u.getst(0), ST_EXPIRED)

    # resumption of an interrupted usage operation
    u = expired_cr(clock=0)
    u.exec_(0)                              # still valid: the clock has not reached ED
    check("a not-yet-expired CR can be used", u.getst(0), ST_READY)
    u.clock = 5000
    try:
        u.exec_(0, is_resumption=True)
        check("resumption of an interrupted operation on an expired CR raises",
              "none", "expired")
    except AceException as e:
        check("resumption of an interrupted operation on an expired CR raises",
              e.which, "expired")

    # exactly at the expiration hour
    u = expired_cr(clock=1000, ed=1000)
    try:
        u.exec_(0)
        check("the CR expires at the stated hour, not after it", "none", "expired")
    except AceException as e:
        check("the CR expires at the stated hour, not after it", e.which, "expired")
    u = expired_cr(clock=999, ed=1000)
    u.exec_(0)
    check("one hour before expiry the CR is still usable", u.getst(0), ST_READY)

    # a zero ExpirationDate never expires
    u = fresh_unit(clock=1 << 30)
    provision(u, 0, ctr_mdh(ExpirationDate=0), content)
    u.exec_(0)
    check("ExpirationDate = 0 means no expiry", u.getst(0), ST_READY)

    # management operations skip the check
    u = expired_cr()
    check("ace.size on an expired CR does not trigger expiry",
          (u.size_A(0), u.getst(0)), (scc_len(u.crs[0].mdh), ST_READY))
    saved = u.mgmt_export_start(0)
    check("ace.mgmt export start on an expired CR does not trigger expiry",
          u.getst(0), ST_READY)
    mem = bytearray(scc_len(saved))
    u.store(mem, 16, 0)
    check("ace.store on an expired CR does not trigger expiry", u.getst(0), ST_READY)
    u.mgmt_end(0, saved)
    u.clone(1, 0)
    check("ace.clone of an expired CR does not trigger expiry", u.getst(1), ST_READY)
    u.setst(0, ST_UNCONFIGURED)
    check("ace.clear of an expired CR does not trigger expiry",
          u.crs[0].is_unconfigured(), True)

    # the check is skipped when ConfigStatus is not complete
    u = fresh_unit(clock=5000)
    u.mgmt_import_start(0, ctr_mdh(State=ST_ENCRYPT, ExpirationDate=1000,
                                   ConfigStatus=CFG_COMPLETE))
    check("a not-complete ConfigStatus skips the expiration check at import",
          u.getst(0), ST_ENCRYPT)
    mem = bytearray(scc_len(ctr_mdh()))
    u.load(0, mem, 16)
    check("ace.load on an expired-but-importing CR does not trigger expiry",
          u.getst(0), ST_ENCRYPT)

    # Zklexpire absent: a nonzero ExpirationDate must be rejected, never enforced
    u = fresh_unit(clock=1 << 30)
    u.zklexpire = False
    provision(u, 0, ctr_mdh(ExpirationDate=1), content)
    u.exec_(0)
    check("without Zklexpire the field is not enforced at usage", u.getst(0), ST_READY)

    info("The relative priority of the UsagePolicy check (rule 14) and the expiration "
         "check is not stated; both are evaluated 'at dispatch'. This model checks "
         "UsagePolicy first, so that a caller with no usage rights cannot destroy the "
         "CR's content. Worth stating normatively.")


def test_size():
    section("12.  ace.size  --  <<ACE-instruction-size>>")

    clen = content_len(ctr_mdh())
    u = fresh_unit()
    check("Form A: Unconfigured CR returns 0", u.size_A(0), 0)

    u.mgmt_provision_start(0, ctr_mdh())
    check("Form A: while provisioning, the PI length", u.size_A(0), pi_len(ctr_mdh()))
    mem = bytearray(pi_len(ctr_mdh()))
    u.load(0, mem, 16)
    u.mgmt_end(0)
    check("Form A: when complete, the SCC length", u.size_A(0), scc_len(ctr_mdh()))

    for st in (ST_UNSUPPORTED, ST_INVALID, ST_IMPORT_AUTH, ST_EXPIRED):
        u2 = fresh_unit()
        provision(u2, 0, ctr_mdh(), b"\x33" * clen)
        u2.setst(0, st)
        check(f"Form A: Error State {st} returns 32", u2.size_A(0), 32)

    # a CR being imported reports the SCC length; ImpDataLen and StateExtension count
    m = ctr_mdh(ImpDataLen=3, StateExtension=2, ConfigStatus=CFG_COMPLETE)
    u3 = fresh_unit()
    u3.mgmt_import_start(0, m)
    check("Form A: while importing, the SCC length including the variable-length data",
          u3.size_A(0), scc_len(m))

    # Form B agrees with Form A on a well-formed MDH
    check("Form B agrees with Form A for a complete CR",
          u.size_B(u.getmdv(0)), u.size_A(0))
    check("Form B of an unsupported algorithm returns 32 (see M2)",
          u.size_B(mdh_new(Algorithm=0x777, AlgorithmPolicy=1)), 32)
    check("Form B of a malformed MDH returns 32 (see M2)",
          u.size_B(mdh_unpack(mdh_pack(ctr_mdh()) | (1 << 14))), 32)

    info("M2 is unresolved in the current text: ace.size Forms B/C still 'return 32' on "
         "an unsupported algorithm or invalid Metadata, while the synopsis says 'or zero "
         "in case of error', ace.avail is described as an alias that returns 0, and the "
         "Book 4 import snippet branches on 'beqz t5'. 32 is also the legitimate size of "
         "an Error-State SCC, so it cannot signal 'unsupported' unambiguously. Modelled "
         "as written (32); a harness written to the Book 4 snippet would mis-handle it.")


def test_negative_controls():
    section("13.  Negative controls")

    declare_negative_control("NEGCTRL-widen")
    declare_negative_control("NEGCTRL-badresume")

    clen = content_len(ctr_mdh())

    # -- 1: a restrict that widens UsagePolicy must be caught --------
    # A plausible but wrong implementation: "replace the field if the request is
    # nonzero", the rule the spec states for AlgorithmPolicy/SCProtection/Locality.
    # Applied to UsagePolicy it widens, which ace.restrict must never do.
    def buggy_restrict_usagepolicy(cur, req):
        return req if req != 0 else cur

    # VS, HS and M are already denied; U still has use and issues the restrict.
    cur, req = 0b01110, 0b00001
    widened = buggy_restrict_usagepolicy(cur, req)
    u = fresh_unit()
    provision(u, 0, ctr_mdh(UsagePolicy=cur), b"\x11" * clen)
    u.mode = "U"
    u.restricth(0, mdh_new(UsagePolicy=req))
    correct = u.crs[0].mdh["UsagePolicy"]
    check("the spec rule adds the new denial and keeps the old ones", correct, 0b01111)
    probe = fresh_unit()
    gained = []
    for mode in ("U", "VS", "HS", "M"):
        probe.mode = mode
        if (probe.usage_allowed(ctr_mdh(UsagePolicy=widened))
                and not probe.usage_allowed(ctr_mdh(UsagePolicy=cur))):
            gained.append(mode)
    check("the buggy rule really does widen (three modes regain use)",
          gained, ["VS", "HS", "M"])
    expect_fail("NEGCTRL-widen",
                "assign-if-nonzero UsagePolicy is monotone (it is not)",
                widened, cur)

    # -- 2: an import resumed with the wrong acestart -----------------
    ml = mdh_new(Algorithm=ALG_SIG, AlgorithmPolicy=0b11)   # a 96-byte content
    n = scc_len(ml)
    content = bytes((0x20 + i) & 0xFF for i in range(content_len(ml)))
    u = fresh_unit()
    provision(u, 0, ml, content)
    saved = u.mgmt_export_start(0)
    mem = bytearray(n)
    mem[0:16] = mdh_bytes(saved)
    u.store(mem, 16, 0)
    u.mgmt_end(0, saved)

    v = fresh_unit()
    iml = mdh_unpack(b2v(bytes(mem[0:16])))
    v.mgmt_import_start(1, iml)
    v.load(1, mem, 16, halt_after=32)
    check("the interrupted import halted at a 16-byte boundary", v.acestart, 32)
    # WRONG: software restores an acestart from a later point of an earlier run,
    # so bytes [32, 48) are never transferred and the CR is silently sheared.
    # (Restoring a *lower* acestart is harmless under the mapping of the fixed
    # C1 rule, because the transfer is idempotent; only a higher one corrupts.)
    v.acestart = 48
    v.load(1, mem, 16)
    v.mgmt_end(1, iml)
    check("the wrongly resumed import fails authentication", v.getst(1), ST_IMPORT_AUTH)
    check("the failed import cleared the content (Error-State entry)",
          v.crs[1].content, b"")
    expect_fail("NEGCTRL-badresume",
                "import resumed at the wrong acestart reproduces the content",
                v.crs[1].content, content)

    # the correctly resumed import does round trip
    w = fresh_unit()
    w.mgmt_import_start(1, iml)
    w.load(1, mem, 16, halt_after=32)
    keep = w.acestart
    w.acestart = keep
    w.load(1, mem, 16)
    w.mgmt_end(1, iml)
    check("the correctly resumed import authenticates and round trips",
          (w.getst(1), w.crs[1].content), (ST_READY, content))


def test_notes():
    section("14.  Contradictions, open readings, and new findings")

    info("C1 (ace.load/ace.store address mapping) reads as RESOLVED: both instructions "
         "now state 'the j-th byte after the MDH ... is loaded to / saved to memory "
         "address Xs1 + %offset + j', ace.mgmt clears acestart at every start step, and "
         "the Book 4 import snippet now uses 16(t6) like the provisioning one.")
    info("C1 residue (NEW): ace.store still says 'Exports raw data ... starting with the "
         "8th byte of the MDH' and 'acestart keeps track of the number of stored bytes, "
         "starting from 8 or 16 depending on the use of ace.getmdl'. Both sentences "
         "contradict the new j-after-MDH rule and the new 'ace.mgmt ... sets acestart to "
         "zero'; hardware cannot observe which getmd* form software used. Delete them.")
    info("C1 residue (NEW): the ace.load description contains a paragraph describing "
         "ace.store ('ace.store copies the data from the serialized representations ...') "
         "-- copy-paste debris in the wrong instruction's Description block.")
    info("C2 (import-start metadata validation) reads as RESOLVED: the validity step is "
         "now split, with 'State and StateExtension must be zero' and 'ImpDataLen must "
         "be 0' listed only 'In case of provisioning', and the generic clause reduced to "
         "'a nonzero reserved field'. Modelled accordingly: import accepts any State.")
    info("C2 residue (NEW): the provisioning clause reads 'State and StateExtension must "
         "be zero, i.e., upon provisioning, State is always Ready' -- but Ready is 1, not "
         "0. The intended rule (MDH State field zero on input, CR State Ready after) "
         "should be stated as two separate sentences.")
    info("C3 (CSK gating) reads as RESOLVED for the CSR deadlock: the illegal-instruction "
         "list now exempts 'the macecsk group (if present)'. Still unstated: whether "
         "ace.reset and the read-only identification CSRs are CSK-gated.")
    info("M2 (ace.size 0 vs 32) is UNRESOLVED -- see the ace.size section above.")
    info("m1 (acestart clamp vs no-op for ACEIOBUF instructions) is RESOLVED as the "
         "no-op reading -- see the ACEIOBUF section above.")
    info("m2 (transfer granularity) is now partly settled for CR transfers: ace.load and "
         "ace.store both say 'acestart ... is a multiple of 16 ... loads/stores data in "
         "16-byte chunks'. This model halts CR transfers only at 16-byte boundaries and "
         "ACEIOBUF transfers at 1-byte boundaries. The forward-progress granule is still "
         "stated as 1 byte in <<ACE-forward-progress>>, so the two should be reconciled "
         "explicitly.")
    info("NEW (managedcr): the new CSR is introduced in the CSR table and used by every "
         "ace.mgmt step, but its reset value, its WARL behaviour on a software write, "
         "and its interaction with ace.clear of the managed CR are unspecified. This "
         "model assumes reset = 32, and that clearing the managed CR releases it.")
    info("NEW (partial export vs ace.mv): ace.mgmt export-start of a *not-complete* CR is "
         "specified to leave ConfigStatus alone (it stays provisioning/importing), yet "
         "the extraction forms of ace.mv are 'only valid if ConfigStatus is "
         "ace_cfgst_exporting'. Under the literal reading the Zklmv export loop of Book 4 "
         "raises an illegal instruction for exactly the partial-export case it exists to "
         "support. Either export-start must set ConfigStatus = exporting unconditionally, "
         "or ace.mv must also accept provisioning/importing.")
    info("NEW (which process does ace.mgmt end complete?): the single "
         "#ace_CR_management_end immediate has to complete whichever process is "
         "open. _ConfigStatus_ identifies it in three of the four cases, but not "
         "after the export-start of a not-complete CR, which leaves _ConfigStatus_ "
         "at provisioning/importing: the same CR state then means both 'resume "
         "loading' and 'finish exporting'. This model needs one extra bit of "
         "non-architectural state to disambiguate; the spec should either say "
         "ace.mgmt end is decoded from _ConfigStatus_ alone (and make export-start "
         "always set exporting) or give the two cases distinct immediates.")
    info("NEW (ace.store gate): ace.store raises an illegal instruction when ConfigStatus "
         "is complete, so the export sequence depends on export-start having changed it. "
         "For a partial export (ConfigStatus already not complete) nothing distinguishes "
         "'prepared for export' from 'mid-provisioning', so a stray ace.store can read a "
         "CR that was never prepared.")
    info("NEW (Success/Failure): rule 2 lists the instructions 'permitted' in Success and "
         "Failure but assigns no behaviour to the others (ace.clone, ace.restrict*, "
         "ace.derive, ace.input/ace.output). Illegal instruction, privilege violation, "
         "and transition to Invalid are all defensible; the text should choose.")
    info("NEW (ace.exec in Ready): State Ready says 'No ace.exec instruction may be "
         "executed in this state', again without saying what happens if one is. Not "
         "modelled here for that reason.")
    info("Not modelled, for want of a normative statement: the ordering of Error States "
         "by severity when two conditions coincide (e.g. an expired CR whose Locality "
         "also became unresolvable); the effect of ace.derive on the two CRs' states; "
         "the CRF-capacity discovery mechanism, which does not exist; and what "
         "'ace.restrict* raises ace_exc_out_of_memory' leaves the CR in when the handler "
         "does not free capacity.")


def main():
    print(__doc__.strip().splitlines()[0])
    print()
    print("A toy, clearly-labelled stand-in is used for sealing; scc-kat.py covers the")
    print("real construction. What is tested here is the architectural state machine.")

    test_mdh_format()
    test_length_rule()
    test_usage_policy()
    test_restrict()
    test_localities()
    test_state_machine()
    test_config_status_gating()
    test_management_flows()
    test_resumption()
    test_aceiobuf()
    test_expiration()
    test_size()
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
