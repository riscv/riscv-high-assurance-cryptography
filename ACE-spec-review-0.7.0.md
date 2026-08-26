# Adversarial Technical Review of the ACE (Zkl) Specification

**Document reviewed:** `src/ace.adoc` rev. 0.7.0 and its includes (Books 1–4, notation, front matter).
**Review date:** 2026-08-26.
**Scope notes:** Only `ace.adoc` and the files it includes were considered. The section
"Considering an interruptible ace.mgmt" in `ace-ISA-unpriv.adoc` was excluded (it is inside a
`////` comment block and not part of the rendered document). Line numbers refer to the sources as
read on the review date and may drift. Settled design decisions from earlier review rounds — the
ACEIOBUF window model (`aceiobuftop` VL-like, `acestart` vstart-like), the restart-permitted
policy for the transfer instructions, and the Off/`ace_exc_CR_off` lazy-loading pattern — are
treated as accepted design and not re-litigated.

All algorithm definitions in Book 2 were checked in detail against their source standards
(SP 800-38A/B/D/E, RFC 7253, RFC 8452, FIPS 180-4/197/202/203/204, SP 800-185, SP 800-232,
FIPS 186-5, RFC 8032, GB/T 32905/32907, GM/T 0003). A machine-checkable KAT suite accompanying
this review lives in `kat/`.

---

## 1. Executive Assessment

**Not ready for candidacy in its current form; a realistic path to "conditionally ready" exists.**

The technical core is unusually mature for a draft at this stage: the algorithm definitions in
Book 2 are, with the exceptions noted below, *bit-exact against their source standards* (verified:
GCM's J0/counter/tag construction, GCM-SIV's POLYVAL/counter-block/tag masking, OCB3's
Stretch/bottom/offset ladder and checksum finalization, CMAC subkeys and padding, Ascon's IVs,
round counts, domain separation and rate handling, and the XTS ciphertext-stealing-via-clone
procedure). The sealing construction (nonce-less AES-GCM-SIV keyed by the CSK, MDH and Locality
Secrets as AD, SIV cross-binding of the implementation segment) is coherent and its stated
deviations from RFC 8452 are justified in-document.

However, the specification is not yet self-consistent enough to implement interoperably. Three
defects are Critical: the memory↔CR address arithmetic of `ace.load`/`ace.store` under resumption
is undefined (and the spec's own examples contradict each other); the import-path
metadata-validity rule, as written, rejects every mid-operation SCC and therefore breaks context
switching; and the CSK-gating rule, as written, makes it impossible to ever configure a CSK. In
addition, the forward-progress guarantee — load-bearing text referenced normatively elsewhere —
currently sits inside a draft `WARNING` block that begins "Do we need to specify this?". Finally,
the acknowledged open items (opcodes in custom space, all cause codes TBD, `misa.L`/`mstatus.ACES`
allocations contested, ACEV undefined, RVWMO integration deferred) are individually reasonable
to defer but collectively preclude candidacy until at least provisionally resolved with the ARC.

---

---

**M4 — `process_VLI` conflates bits and bytes when reading/writing `acestart`**

- **Rationale:** `acestart` is architecturally a byte count (`src/ace-ISA-unpriv.adoc:1242`); the
  central shared procedure of Book 2 stores a bit count into it and reads it back as a bit offset.
  Every algorithm built on `process_VLI` (hashes, HMAC, KMAC, GCM IV absorption, EdDSA,
  ML-KEM/ML-DSA field loading) inherits the off-by-×8.
- **Location:** `src/ace-ISA-algorithms.adoc:806` ("If resuming … `input_base <- acestart`") and
  `src/ace-ISA-algorithms.adoc:824-827` ("interrupted, with `acestart <- input_base`"), where
  "Units" (`src/ace-ISA-algorithms.adoc:754-758`) declares `input_base` to be in bits. Contrast
  the correct conversion in _Hash_Output_ (`src/ace-ISA-algorithms.adoc:2085,2096`:
  `output_base <- 8·acestart`, `acestart <- output_base / 8`).
- **Resolution:** `input_base ← 8 · acestart` on resumption and `acestart ← input_base / 8` at the
  interruption point (guaranteed integral, as the text already argues).

---

**M5 — `ace.derive` semantics are unspecified outside ML-KEM**

- **Rationale:** A key-derivation instruction whose derivation function, output MDH, and
  per-algorithm applicability are undefined is both an interoperability hole and a
  cryptographic-soundness hole (implementers will invent KDFs of varying quality; SCCs and
  derived-CC behavior will not port).
- **Location:** `src/ace-ISA-unpriv.adoc:2510-2533` (generic description: "for instance using a
  key derivation mechanism"; "The behavior … is not expected to be deterministic");
  `src/ace-ISA-unpriv.adoc:2955-2963` (`<<ACE-derive-usage>>` piping rules); the only concrete
  definition is ML-KEM's Form B (`src/ace-ISA-algorithms.adoc:3627-3639,3783-3791`).
- **Issue:** For case 1 (unconfigured target): which algorithms support it, what KDF is used, what
  the derived CC's _Algorithm_/MDH is, and whether the result is portable across implementations
  are all unstated. For the piping rules: what data is piped, in what state the source CR must be,
  and the effect on source state are unstated ("the auxiliary parameter determining the size in
  bits of the piped data" floats free of any algorithm definition).
- **Resolution:** Either (a) restrict `ace.derive` normatively to the algorithm-defined cases
  (currently ML-KEM), stating that all other sources cause a transition to Error State _Invalid_,
  and delete/park `<<ACE-derive-usage>>`; or (b) architect the generic mechanism: name the KDF
  (e.g., KMAC256- or SHAKE256-based, with a domain-separation string), define the derived MDH
  construction, and add a "Derivable output" clause to each algorithm section. Option (a) is
  compatible with ratifying now.

---

**M9 — Unbounded "unpredictable results/behavior" in a secrecy-bearing ISA**

- **Rationale:** In an extension whose entire purpose is that CR internals never reach software,
  "unpredictable results" without bounds does not forbid an implementation from, e.g., emitting
  internal state to the output register. The specification fails to *require* a safe
  interpretation.
- **Location:** `src/ace-ISA-unpriv.adoc:1258-1259` ("writing zero to `acestart` … may lead to
  inconsistent or unpredictable results and is not permitted…" — with no defined consequence for
  doing it), `src/ace-ISA-unpriv.adoc:3043` ("may lead to unpredictable behavior when the input
  and output overlap"), `src/ace-ISA-algorithms.adoc:3917-3919` (ML-DSA: "may return unpredictable
  results").
- **Resolution:** Add a global bounding clause: *"Wherever this specification declares a result
  UNPREDICTABLE, the resulting values of software-visible destinations are UNSPECIFIED but must be
  a function only of architectural state the executing context is otherwise permitted to observe;
  the CC's Content, the CSK, and Locality Secrets must not be disclosed in whole or in part beyond
  what a permitted instruction sequence could produce. The CR either holds a state reachable by
  some legal sequence or transitions to Error State _Invalid_."* For the `acestart`-rewrite case
  specifically, prefer the deterministic outcome "the CR transitions to Error State _Invalid_"
  over UNPREDICTABLE.

---

**M10 — ECC state machine: _Set_Signature_ is a dead end; verification is unreachable as written**
FIXED — the "Allowed State Transitions" block of `<<ACE-ECC>>` now names the five _Set_ states
collectively, lets any two of them transition freely (and to themselves), admits all of them as
sources for _Point_Mul_/_Sign_Generate_/_Sign_Verify_, and completes
_Point_Mul_ -> _Output_ -> _Success_. This also supplies the definition of "the _Set_ states"
that `<<ACE-EdDSA>>` already referred to. `kat/ecc-kat.py` retains the pre-fix relation as a
regression check. See also K13, which closes the remaining reachability gap — signing and then
verifying within one CC — by making the `Xs` field-disposal bits uniform, so that `Signature`
survives the mandatory return to _Ready_ unless it is explicitly discarded.

- **Rationale:** By Generic Rule 2 (`src/ace-ISA-algorithms.adoc:182`), any transition not
  explicitly allowed invalidates the CR. The transition list omits _Set_Signature_ from both the
  free-transition group and the "From any of …" list, so after loading a signature no legal exit
  exists — ECDSA verification cannot be performed following the letter of the spec.
- **Location:** `src/ace-ISA-algorithms.adoc:3287-3303`: free transitions are "between
  _Set_Generator_, _Set_Scalar_, _Set_Hash_, and _Set_SecondPt_"; departures to
  _Point_Mul_/_Sign_Generate_/_Sign_Verify_ are "From any of _Ready_, _Set_Generator_,
  _Set_Scalar_, _Set_Hash_, _Set_SecondPt_" — _Set_Signature_ appears in neither, although
  _Sign_Verify_ requires `HasSignature`.
- **Resolution:** Add _Set_Signature_ (and, for EdDSA, _Set_Ctx_ — the EdDSA subsection partially
  patches this only for its own states) to both lists.

---

**M11 — No liveness or state-contract for multi-instruction management processes**

- **Rationale:** Forward progress is guaranteed per instruction, but the
  provisioning/import/export *processes* span several instructions, and handlers are expressly
  permitted to "force a restart by clearing partially configured or exported CRs at context save
  and restore" (`src/ace-ISA-unpriv.adoc:2092-2093`). Under sufficiently frequent preemption with
  a handler that always clears, a large import (an ML-DSA-87 SCC is ~12.5 KB, plus up to 256 KiB
  of implementation data) never completes — a livelock the architecture neither prevents nor
  acknowledges. Relatedly, the per-hart auxiliary sealing storage (`SIV`/`SIV2`/`IMPQUAL`,
  `src/ace-ISA-unpriv.adoc:3239-3245`) has no normative save/restore contract for *handlers*; the
  only stated rule ("interleaved management operations must be avoided… mutex") addresses
  same-context threads, yet a context-switch handler that saves CRs necessarily interleaves its
  own management operations with the interrupted one.
- **Location:** `src/ace-ISA-unpriv.adoc:2083-2097` (mgmt NOTE), `src/ace-ISA-unpriv.adoc:3230-3245`
  (CR representation).
- **Resolution (keeping restart legal, as designed):** Add two normative statements: (1) *"A
  handler that preserves a CR in a non-`ace_cfgst_complete` _ConfigStatus_ across a context switch
  must, before issuing any other management operation on that hart, export that CR (verbatim
  export captures the per-hart auxiliary sealing state into the serialized image) or clear it; the
  per-hart auxiliary sealing state is otherwise destroyed by the next `ace.mgmt
  #ace_CR_*_start`."* (2) A software-facing liveness note: *"System software must not
  unconditionally clear partially configured CRs on every context switch; doing so can prevent
  management processes from ever completing"* — or, if unconditional clearing is to remain legal,
  state explicitly that management-process completion under preemption is a software-stack
  responsibility, so the limitation is at least documented and testable.

---

**M12 — FIPS 203/204 required input validation not required; misnamed states; garbled verify clause**

- **Rationale:** Confirmed standards gap. FIPS 203 §7.2/§7.3 make encapsulation-key checking
  (type + modulus check) and decapsulation input checking (ciphertext/dk type checks, hash check)
  *shall*-level preconditions; the spec instead says results "may return invalid (and useless)
  results or fail with a transition to Error State `ace_state_failure`" — and `ace_state_failure`
  (23) is a *valid* state, not an Error State, so even the fallback is misdescribed.
- **Location:** `src/ace-ISA-algorithms.adoc:3740-3742` (ML-KEM), `src/ace-ISA-algorithms.adoc:3915-3919`
  (ML-DSA analogue); `src/ace-ISA-algorithms.adoc:4013` ("If `ML-DSA.Verify_internal` returns
  `true` and a return value, the latter is written to `signature`" — Algorithm 8 of FIPS 204
  returns only a Boolean; the sentence is not parseable).
- **Resolution:** Require the FIPS 203 §7.2/7.3 input checks on completion of
  `_encapsk_Input_`/`_decapsk_Input_`/`_ciphertext_Input_` (or at the start of
  `_Encapsulate_`/`_Decapsulate_`), with failure → State _Failure_ (or Error State _Invalid_ —
  choose and state). Fix the terminology ("transitions to State _Failure_") and rewrite the Verify
  clause: "If `ML-DSA.Verify_internal` returns `true`, the state machine transitions to State
  _Success_, else to State _Failure_."

---

### Minor

**m1 — `acestart` clamping vs. no-op contradiction.** `src/ace-ISA-unpriv.adoc:1253-1254` says that
when an ACEIOBUF instruction is issued with `acestart` > `aceiobuftop`, "`acestart` will be set to
`aceiobuftop` first"; `src/ace-ISA-unpriv.adoc:2696,2761` say the operation "does nothing and
`acestart` is unchanged". Pick one (recommend: no-op, `acestart` unchanged) and delete the other.

**m4 — OCB nonce handling.** `N_len` is only constrained to 6…120
(`src/ace-ISA-algorithms.adoc:1638`), but `bswap(N[N_len-1:0])` (`src/ace-ISA-algorithms.adoc:1700`)
is undefined for non-byte-multiple lengths (`bswap` is byte-string reversal); either require
8 | `N_len` or define the bit-level view. The ≥6 floor is also a silent deviation from RFC 7253
(which allows any length ≤ 120, including empty); if deliberate (cf. the cited eprint 2023/326),
say so in a note. `_Dec_Last_Block_` (`src/ace-ISA-algorithms.adoc:1781-1800`) omits the
`index = ones(48)` guard present in `_Enc_Last_Block_`.

**m5 — Ascon-AEAD128 padding-responsibility contradiction.** `src/ace-ISA-algorithms.adoc:2569`
says the caller pads "the AD and the plaintext", but `_Enc_Last_Block_`/`_Dec_Last_Block_` apply
`pad()` internally — a caller following the sentence double-pads. Reword: the caller pads the *AD*
only; the final plaintext/ciphertext block is padded internally via `last_blk_len`.

**m6 — CMAC empty-message notation.** With `last_blk_len` = 0 the formula uses
`INPUT[last_blk_len-1:0]` = `INPUT[-1:0]` (`src/ace-ISA-algorithms.adoc:1931`), an undefined
slice; the Book 4 example feeds a dummy zero block (`src/ace-pseudocode.adoc:751`). State
explicitly: "if `last_blk_len` = 0, `INPUT` is ignored and the padded block is
`zeros(b−8) @ 0b10000000`".

**m8 — GCM-SIV missing transition instructions.** The instruction/Form used to *enter*
`_Enc_Tag_Finalize_`, `_Encrypt_`, `_Decrypt_`, and `_Dec_Tag_Finalize_` is never stated (only the
`ace.exec` expected *inside* each state); Book 4 implies Form A `ace.setst`. Add the transition
clauses as GCM has them.

**m9 — Locality gaps.** Encoding [5:4] = 3 in the _Locality_ field is unassigned with no stated
behavior (`src/ace-ISA-unpriv.adoc:791-816`) — declare it invalid metadata. `sacelocality` has no
VS shadow: with V=1, a guest (V)S can read the host S-mode Locality Secret if the hypervisor fails
to swap it; unlike ordinary CSR state these are *secrets*, so add a normative warning (or a
`vsacelocality` shadow) (`src/ace-ISA-priv.adoc:765-782`).

**m10 — `acemaxiobuflen` without `Zklio`.** The CSR is "always present"
(`src/ace-ISA-unpriv.adoc:222-224`) but its value when the ACEIOBUF is absent is unspecified;
state it reads 0 when `Zklio` is not implemented.

**m12 — Editorial/encoding debris.** Stray "x" line breaking the paragraph before the
`ace.restrict` wavedrom (`src/ace-ISA-unpriv.adoc:2225`); `Content2~Plaintext[]` vs
`Content2~PT~[]` (`src/ace-ISA-unpriv.adoc:3507`); residual "an byte" from the octet→byte rename
(`src/ace-ISA-algorithms.adoc:757,827,1582`; also `src/ace-notation.adoc:25` "an *byte string*");
recurring "causes the CR to transitions to" (`src/ace-ISA-algorithms.adoc:1650,3854,3860,3973`,
`src/ace-pseudocode.adoc:160`); `ace.setst`/`ace.mgmt` Form B RV32 quartet alignment (multiple of
four?) unstated (`src/ace-ISA-unpriv.adoc:1944`); "either a B of `ace.setst`"
(`src/ace-ISA-algorithms.adoc:3999`).

**m13 — `ace.restrict*` usage control blocks the manager pattern.** A privileged manager without
usage rights on a CC cannot restrict-then-delegate it (restrict is usage-controlled,
`src/ace-ISA-unpriv.adoc:2359`), even though `ace.clear` — a strictly stronger denial primitive —
is not. Either exempt `ace.restrict*` from usage control (it can only tighten) or add a rationale
note.

**m14 — ECC _Output_ wording.** "export sections of the result to memory"
(`src/ace-ISA-algorithms.adoc:3402`) — Form C `ace.exec` writes `OUTPUT` (vector/ACEIOBUF), not
memory.

**m15 — ML-DSA `tr` for verify-only CCs.** `tr` is listed as internal state but serialized only
inside `privkey`; a verification-only CC (pubkey + `tr` via `_tr_Input_`) loses `tr` across
export/import. State where `tr` is serialized in that configuration, or state that it need not
survive (`src/ace-ISA-algorithms.adoc:3863-3920`).

**m16 — Offset immediates.** Whether `%offset` in `ace.load`/`ace.store`/`ace.input`/`ace.output`
is the standard sign-extended 12-bit I/S-type immediate is never stated.

**m17 — Opcode space and naming.** `custom-0/1/2` cannot host a standard extension (RISC-V unpriv
ISA: "custom" opcodes are permanently reserved for non-standard use); acknowledged as placeholder
but must be resolved before candidacy. Extension names with internal capitals (`ZklbpP256r1c`,
`ZklSM2c`) deviate from ISA-string naming practice (all-lowercase after the initial letter).

**m18 — Sealing domain separation is incidental (hardening).** Segment-1 (`AD` = MDH ‖ Localities)
and segment-2 (`AD2` = IMPQUAL ‖ SIV) authentications share the same derived keys, separated only
by AD structure; the cross-interpretation attack requires `LST[j]` = `SIV`, which is negligible,
but an explicit domain-separation constant as `AD[0]`'s companion (e.g., a fixed tag block per
segment) would make the separation deliberate and provable rather than accidental
(`src/ace-ISA-unpriv.adoc:3495-3517`).

---

## 3. Cross-Document Inconsistencies and Missing Requirements

Beyond the findings above (C1's snippet mismatch, C2 vs. Book 4's validity note, C3 vs. Book 3's
`macecsk`, M1's void anchor, M2's three-way contradiction, m11's anchor collision):

2. **Exception table vs. error architecture**: Book 3's table (`src/ace-ISA-priv.adoc:49-69`)
   omits the illegal-instruction conditions' priority relative to `ace_exc_*` for one instruction
   exhibiting several conditions; Book 1's "natural priority order"
   (`src/ace-ISA-unpriv.adoc:956`) covers only the priv-less mapping. One normative priority list
   should serve both.
3. **ACEIOBUF save/restore recipe**: the context-switch procedure (widen window to `aceiobuflen`,
   dump via `ace.output`, restore, re-narrow, restore `acestart` last) is left as an exercise; a
   Book 4 snippet would remove ambiguity.
4. **Missing requirement:** no discovery mechanism for CRF capacity (total or free); allocation
   failure is discoverable only via `ace_exc_out_of_memory` at provisioning time. At minimum,
   state this is deliberate.
5. **Missing requirement:** behavior of `ace.clone` when `Kd` = `Ks`, and its out-of-memory
   behavior (presumably `ace_exc_out_of_memory` as a configuration operation) are unstated
   (`src/ace-ISA-unpriv.adoc:2438-2450`).
6. **Missing requirement:** `ACELEN` = 0 (VL = 0, or `aceiobuftop` = 0 with a configured buffer)
   semantics for each instruction class — presumably "no operation, no state transition", but only
   the unconfigured-buffer case is defined (`src/ace-ISA-unpriv.adoc:954`).

---

## 4. Standards-Compliance Matrix

| Requirement / standard | Location in draft | Assessment | Evidence / notes |
|---|---|---|---|
| SP 800-38A ECB/CTR | `ACE-ECB-mode`, `ACE-keystream-modes` | **Compliant** | Counter block `bswap(ctr) @ IV` matches the big-endian trailing-byte counter; XCTR (XOR form) is a non-NIST but published construction, correctly distinguished. |
| SP 800-38B CMAC | `ACE-CMAC-mode` | **Compliant** (one notation gap, m6) | Subkeys via big-endian `double` = MSB-first shift ⊕ 0x87; 10*-padding position correct under the byte mapping. |
| SP 800-38D GCM | `ACE-GCM-mode` | **Compliant** | J0 (96-bit and GHASH paths), inc32, 2³²−2 block cap, GHASH bit-reflected representation, tag mask E(K, J0₀) all verified. |
| SP 800-38E XTS | `ACE-XEX-XTS-modes`, `ACE-XTS-from-XEX` | **Compliant** (two-key only) | Single-key XEX deliberately excluded with the Rogaway attack rationale; CTS-via-clone sequence consumes mask indices in the standard's order. |
| RFC 8452 AES-GCM-SIV | `ACE-GCM-SIV-mode` | **Compliant** | POLYVAL/Montmul representation, key derivation, counter block with MSB set, LE length block, tag-before-encrypt flow verified. |
| RFC 8452 as sealing algorithm | `ACE-SCC-AEAD` | **Deviation, declared** | Nonce omitted, length block omitted; both argued in-document (2⁶⁴-block bound; lengths bound via MDH). See m18 for hardening. |
| RFC 7253 OCB3 | `ACE-OCB-mode` | **Largely compliant** | Nonce/Stretch/bottom/offset/checksum verified against §4.2. Deviations: `N_len` ≥ 6 floor (undeclared, m4); bit-granular nonces unsupported/undefined (m4). |
| FIPS 180-4 / GB/T 32905 (SM3) | `ACE-SHA-2`, `ACE-SM3` | **Compliant** (interface choice) | Caller performs padding for stand-alone hashing — legitimate interface split, clearly stated. |
| FIPS 198-1 HMAC | `ACE-HMAC` | **Compliant** | K0 derivation assigned to provisioner; ipad/opad and internal finalization padding correct. |
| FIPS 202 / SP 800-185 | `ACE-SHA-3`, `ACE-KMAC` | **Compliant** | Suffix `01`/`1111`/`00` + pad10*1 handling incl. the two-block spill case; KMAC `bytepad` blocks precomputed by provisioner (declared interface choice); `right_encode(L)`, XOF non-terminating semantics correct. |
| SP 800-232 Ascon | `ACE-Ascon-*` | **Compliant** (wording bug m5) | IV constants, round counts (12/8/12), key XOR positions, domain-separation bit, ≥64-bit tag floor all match. |
| FIPS 186-5 / SM2 (GM/T 0003) | `ACE-ECC` | **Compliant** (M10 fixed) | Retry rules (r=0/s=0; SM2 r+k=n) present; k from Zkr-quality RBG; point/subgroup validation required. Deterministic ECDSA (RFC 6979) not offered — note as deliberate. |
| RFC 8032 EdDSA | `ACE-EdDSA` | **Compliant** | Two-pass structure, dom2/dom4, ctx, pure/pre-hash gating by hash extensions; deterministic nonce (no RndNum) correct. |
| FIPS 203 ML-KEM | `ACE-PQC-ML-KEM` | **Noncompliant as written (M12)** | §7.2/§7.3 input checks not required. Decaps implicit rejection correctly reflected (caller cannot distinguish). |
| FIPS 204 ML-DSA | `ACE-PQC-ML-DSA` | **Needs clarification** | Sign_internal/Verify_internal with externally computed μ: consistent with NIST's external-μ usage, but the draft should cite the exact FIPS 204 provision it relies on. Hedged/deterministic selection present. |
| Zkr entropy source | `ACE-RBG` | **Compliant by reference** | |
| RISC-V opcode-space policy | `ACE-instructions-detailed` | **Noncompliant, acknowledged** | custom-0/1/2 placeholders (m17). |
| `misa`/`mstatus` allocations | Book 3 | **Open, acknowledged** | `misa.L`, `mstatus[26:25]` flagged provisional in-document. |
| Smstateen non-integration claim | `src/ace-ISA-unpriv.adoc:1093`, `src/ace-ISA-priv.adoc:97` | **Plausible, verify with ARC** | Holds only if ACES gating covers *all* new user-visible state in all V/priv combinations; the claim should be argued, not asserted. |
| RVWMO integration | `ACE-Memory-Model` | **Deferred, acknowledged** | Informal model is coherent (prefix-completeness + conflicting-access rule); axiomatic work deferred to ARC — acceptable for candidacy only with ARC agreement. |
| Debug spec interaction | `ACE-interaction-with-debug` | **Plausible, flagged for ARC** | `dmstatus.authenticated` mapping is the right hook; destructive unauthenticated-entry semantics need Debug TG review (acknowledged in TODOs). |

---

## 5. Prioritized Remediation Plan

1. **Interoperability blockers (before any external review):** C1 (address-arithmetic rule +
   snippet fixes), C2 (split provisioning/import validity), C3 (CSK-gating exemptions), M2
   (`ace.size` returns), M3 (`ace.mv` semantics), M4 (`process_VLI` units).
2. **Normative-status and trap-model repairs:** M1 (promote forward-progress text), M6/M7 (fault
   binding for background completion; `ace_exc_fatal` delivery), M8 (reset table), M14 (`macecsk`
   flag rule, reserved `ace.mgmt` immediates), M9 (bounded-UNPREDICTABLE clause).
3. **Algorithm-book completeness:** M10 (ECC transitions), M12 (FIPS 203/204 validation), M5
   (scope or specify `ace.derive`), m4–m6, m8, m15.
4. **Conformance and ARC-track items:** M13 (priv conformance matrix), M15 (freeze ACEV or
   re-scope), m17 (opcodes/naming), cause-code allocation, `misa`/ACES placement, Smstateen
   argument, RVWMO axiomatization plan.
5. **Editorial sweep:** m1–m3, m7, m9–m12, m14, m16, m18; grep-driven fixes for "an byte", "to
   transitions", anchor rename.

---

## 6. Remaining Review Questions and Assumptions

- **Q1:** For C1, is the intended rule "memory base ↔ serialized byte 16" (software passes the
  advanced address, as the provisioning snippet suggests), or "memory base + `acestart`"? The fix
  differs; the former was assumed.
- **Q2:** Is the OCB `N_len` ≥ 6 floor a deliberate consequence of the cited nonce-length bound
  (eprint 2023/326), and is the byte-multiple restriction intended? Both need an explicit sentence
  either way.
- **Q3:** Should `ace.size` signal "unsupported" by 0 (recommended) — and if so, is the
  Error-State-SCC 32-byte size then reported only by Form A on a configured CR?
- **Q4:** For M13: is an M-mode-only ACE (no CSRs beyond the mandatory ones, error-state-only
  error model) an intended conforming configuration? The whole "Privileged Architecture not
  implemented" model presupposes yes, but Book 3's `misa`/ACES mandate says no.
- **Q5:** `mstatus.ACES` Dirty-tracking treats the *Locality* CSR groups as ACE state
  ("ACE-specific CSR" changes set Dirty per the `vsstatus` text, `src/ace-ISA-priv.adoc:191`) —
  but Book 3's note says context-switch software saves them "like any other CSR". Confirm whether
  Locality CSR writes set ACES Dirty; the two readings differ.
- **Assumption:** The `budget` mechanism (GCM-with-IV, Ascon-with-nonce) was treated as staying
  in; the intro marks it "DOUBLE CHECK… keep or remove". If removed, the serialized-context
  layouts and the Invalid-on-exhaustion clauses go with it.
- **Assumption:** `ace-whitepaper.adoc`, `ace-old-error-architecture.adoc`, and files outside the
  `ace.adoc` include graph were not reviewed; the commented-out interruptible-`ace.mgmt` section
  was excluded as directed.




#########################################################################################################


**FIXED C1 — `ace.load`/`ace.store` memory-address ↔ serialized-offset mapping is undefined under nonzero `acestart`**

- **Severity rationale:** These are the context-switch workhorse instructions. Two conforming
  implementations (or an implementation and the software written against another) can disagree on
  which memory byte corresponds to which serialized-CR byte whenever `acestart ≠ 0`, i.e., on
  every resumption and on every store that begins past the MDH. This prevents safe
  interoperability.
- **Location:** `src/ace-ISA-unpriv.adoc:1485-1491` (`ace.load`), `src/ace-ISA-unpriv.adoc:1543-1562`
  (`ace.store`); contradicting examples in `src/ace-pseudocode.adoc:83` (`ace.load K{t0}, 16(t6)`
  for provisioning) vs `src/ace-pseudocode.adoc:146` (`ace.load K{t0}, 8(t6)  # load the rest
  starting with SIV` for import).
- **Issue:** `ace.load` "reads memory starting at `%offset(Xs1)` and copies the data into the CR
  beginning with the current `acestart` byte offset." Unlike `ace.input`/`ace.output`, which
  define the mapping precisely (memory `base+j` ↔ buffer byte `j`), no formula relates memory
  address to serialized offset. Under the reading "memory `base+i` ↔ CR byte
  `acestart_at_issue + i`", the provisioning snippet (`16(t6)`, `acestart` = 16) is correct but
  the import snippet (`8(t6)`) reads MDH bytes 8–15 into the SIV slot; under the reading "memory
  `base + acestart`", both are wrong. Resumption is worse: if a re-executed `ace.load` again
  "reads memory starting at `%offset(Xs1)`" but writes at the advanced `acestart`, the transfer is
  silently sheared. For `ace.store`, "`acestart` keeps track of the number of stored bytes,
  starting from 8 or 16 *depending on the use of `ace.getmdl`*" is not implementable: hardware
  cannot observe which instruction software used earlier, and `ace.mgmt` export-start
  unconditionally sets `acestart` to 16 (`src/ace-ISA-unpriv.adoc:2041`), never 8.
- **Proposed resolution:** Define once, normatively, for both instructions: *"Let `j` range over
  serialized-CR byte offsets. The byte at serialized offset `j` corresponds to memory address
  `%offset(Xs1) + (j − j₀)`, where `j₀` = 16 (the serialized offset of the first byte after the
  MDH). The instruction transfers bytes `j` = `acestart` … `size−1`. On resumption, the same base
  address is passed and the correspondence is unchanged."* If starting a store at offset 8 is to
  remain possible, make `j₀` an explicit function of the `acestart` value that `ace.mgmt`
  establishes (and allow software to write `acestart` = 8 before the first `ace.store`), and say
  so. Fix the Book 4 import snippet to `16(t6)` (or whatever the chosen rule requires).

---

**FIXED C2 — Import-start metadata validation rejects every mid-operation SCC, breaking context save/restore**

- **Severity rationale:** As written, the normative import path contradicts the equally normative
  statement that "Completing an import can lead to any state" (`src/ace-ISA-unpriv.adoc:717`). An
  implementation following the letter rejects all SCCs of CRs captured mid-algorithm — the primary
  use case of export/import. Divergent implementer interpretations are guaranteed; internal
  unsoundness of the core mechanism.
- **Location:** `src/ace-ISA-unpriv.adoc:1963-1989`, specifically the step: "In other cases where
  the Metadata is invalid, such as, for instance, a nonzero _State_ or reserved field: The CR is
  transitioned to Error State _Invalid_" — which applies to "a provisioning, resp., *import*
  process" jointly. Reinforced by `src/ace-pseudocode.adoc:158-160` ("the validity of bits [63:0]
  of the metadata field is checked immediately"; _State_ is MDH[25:21], inside the low half).
- **Issue:** An SCC exported from a CR in, e.g., State _Encrypt_ (7) or an Error State (24–29) —
  both explicitly legal exports — carries a nonzero _State_. `ace.mgmt #ace_CR_import_start` with
  that MDH transitions the target CR to _Invalid_ per the quoted rule. Context restore, migration,
  and the Error-State re-import path of `src/ace-ISA-unpriv.adoc:604-607` all fail.
- **Proposed resolution:** Split the validity rules by operation: *"For provisioning: _State_ must
  be 0 or `ace_state_ready`, _ConfigStatus_ 0, _ImpDataLen_ 0, _SCProtection_/_StateExtension_ 0,
  reserved fields 0; otherwise the CR transitions to Error State _Invalid_. For import: reserved
  fields must be 0 and (_Algorithm_, _AlgorithmPolicy_, _KeyType_, _StateExtension_) must be
  supported and self-consistent; _State_ and _StateExtension_ may hold any value legal for the
  algorithm, deferred to authentication at `#ace_CR_management_end`."* Update the Book 4 note
  accordingly.

---

**FIXED C3 — CSK gating rule forbids configuring the CSK: bootstrap deadlock**
 NO CSK-> cannot configure CSK. FIXED

---

**FIXED M1 — The forward-progress guarantee is normatively void (inside a draft WARNING block)**

- **Rationale:** Termination/liveness of resumable instructions is a headline algorithmic
  property; the text establishing it is not currently part of the normative specification.
- **Location:** `src/ace-ISA-unpriv.adoc:2997-3028`: the `[WARNING]` block opens with "Do we need
  to specify this? I have a draft here. There is some redundancy." and contains
  `[[ACE-forward-progress]]` and the three completion strategies. It is referenced as binding from
  `src/ace-ISA-unpriv.adoc:2091` ("subject to the completion guarantee of
  <<ACE-forward-progress>>") and `src/ace-ISA-unpriv.adoc:3093`.
- **Issue/resolution:** Yes, it needs to be specified (the answer to the block's own question):
  without it, restart-on-interrupt implementations may livelock transfer instructions under
  periodic interrupts. Promote lines 3001–3027 to normative body text, delete the question, and
  de-duplicate against `src/ace-ISA-unpriv.adoc:3057-3065` (the second draft WARNING in
  "Resumption and Memory Model", which restates the same restart rule and should be folded into
  the prefix-completeness subsection).

---

**FIXED (I think) M2 — `ace.size` error-return contradiction (0 vs 32), and 32 is ambiguous**

- **Rationale:** Directly contradictory normative statements about an architecturally visible
  result; software written per `ace.avail`'s definition misbehaves on an implementation following
  `ace.size`'s.
- **Location:** `src/ace-ISA-unpriv.adoc:2611-2627` (Forms B/C: "the instruction returns `32`" on
  unsupported/invalid) vs `src/ace-ISA-unpriv.adoc:2880` (`ace.avail` "is an alias for Form B of
  `ace.size`, as the latter *returns 0* in case of error") vs `src/ace-pseudocode.adoc:101-102`
  (`ace.size t5, v2` / `beqz t5, handle_errors # algorithm not supported, or MDH invalid`). The
  intro flags this open (`src/ace-introduction.adoc:123`).
- **Issue:** Additionally, 32 is the *legitimate* size of an Error-State SCC
  (`src/ace-ISA-unpriv.adoc:604-606`), so "returns 32" cannot signal "unsupported" unambiguously.
- **Resolution:** Make Forms B/C return **0** for unsupported _Algorithm_/_AlgorithmPolicy_/
  _SCProtection_ or malformed MDH[63:0], and the true size (including the 32-byte Error-State
  case, distinguishable because the input MDH's _State_ field is inspectable by software)
  otherwise. Align Form A, `ace.avail`, and the snippets.

---

**FIXED M3 — `ace.mv` extraction variants: wrong byte count and wrong register-constraint field**

- **Rationale:** The normative semantics are internally inconsistent; a literal implementation
  moves half the data it claims, or faults on the fixed sub-opcode.
- **Location:** `src/ace-ISA-unpriv.adoc:1734-1739` (RV64 Form `0b10`/`rs2`=1): "**XLEN/8 bytes**
  of the CR at offset `acestart` are moved to `X[rd+1] @ X[rd]`. `acestart` is updated to
  **(XLEN/4)** + `acestart`. … **`rs2` must be even**, else an illegal-instruction exception is
  raised." Similarly `src/ace-ISA-unpriv.adoc:1755-1757` (RV32: "`rs2` must be a multiple of
  four").
- **Issue:** (a) A GPR pair holds XLEN/4 bytes, and `acestart` advances by XLEN/4, so "XLEN/8
  bytes" is wrong. (b) In Form `0b10`, `rs2` is the *sub-opcode* (fixed at `0b00001`, odd); the
  alignment constraint must bind `rd`, the destination GPR.
- **Resolution:** "`XLEN/4` bytes of the CR at offset `acestart` are moved to `X[rd+1] @ X[rd]`;
  `acestart ← acestart + XLEN/4`; `rd` must be even [RV32: a multiple of four]…". Mirror for RV32.

---

**FIXED M6 — Background completion vs. faulting component accesses is unresolved**

- **Rationale:** Exception/trap architecture gap. If a hart takes an asynchronous interrupt and
  the ACE unit continues an `ace.store` in the background (strategy 1 of
  `<<ACE-forward-progress>>`), a later component access can page-fault with no instruction to bind
  the trap to — an imprecise, unbindable exception, contrary to the priv architecture's
  synchronous-exception model.
- **Location:** `src/ace-ISA-unpriv.adoc:3007-3009` (background completion),
  `src/ace-ISA-priv.adoc:56-62` (misaligned/access/page-fault causes apply to ACE memory
  instructions); no text connects them.
- **Resolution:** Add: *"An implementation may treat an ACE memory instruction as complete
  (retiring it, or taking an interrupt with `xepc` past it) only after all address translation and
  permission checks for every byte of the transfer have succeeded, or it must use the precise-halt
  strategy so that any fault is reported synchronously on re-execution with `acestart` at a
  prefix-complete point. Component accesses performed after the instruction is treated as complete
  must not fault."*

---

**FIXED M7 — `ace_exc_fatal` delivery model undefined and priority statements conflict**

- **Resolution:** Specify: *"A fatal condition is recorded in the ACE unit. The first ACE
  instruction or ACE CSR access issued (or in flight) after detection does not perform its
  operation and raises `ace_exc_fatal`; `xepc` holds that instruction's address. The cause is not
  delegable below M-mode [or: delegable — decide]. The ACE state reset occurs before the trap is
  taken."* Reconcile the two priority statements.

---

**FIXED M8 — Reset architecture incomplete (`*lcrstatus`, `aceiobuflen`, CR contents)**

- **Rationale:** Reset values determine boot behavior. If `mlcrstatus` resets to all-Off, every
  sub-M access traps `ace_exc_CR_off` until firmware writes it; if all-Dirty, none do. Two
  implementations choosing differently are incompatible with the same OS.
- **Location:** `src/ace-ISA-priv.adoc:211-296` (no reset value for
  `mlcrstatus`/`slcrstatus`/`vslcrstatus`); `src/ace-ISA-unpriv.adoc:1153-1176` (no reset value
  for `aceiobuflen`); `src/ace-ISA-unpriv.adoc:309-310` (hart reset resets "the architectural
  state of its ACE unit" without enumerating post-reset values).
- **Resolution:** Add a consolidated reset table: all CRs _Unconfigured_ with zeroized contents;
  `aceiobuflen` = 0 (ACEIOBUF unconfigured), `aceiobuftop` = 0, `acestart` = 0;
  `mlcrstatus`/`slcrstatus`/`vslcrstatus` = recommended all-fields Dirty (3) or Initial (1) — pick
  one; ACES = Off; CSK unconfigured (except model 3); Locality secrets zero.

---

**FIXED M13 — Conformance/optionality of the Privileged Architecture is undefined**

- **Rationale:** Book 1 defines a complete alternate error model "when the Privileged Architecture
  is not implemented" (`src/ace-ISA-unpriv.adoc:938-970`), but Book 3 states "If `Zklv` or `Zklio`
  is implemented: `misa` must implement the `L` bit, `*status` must implement `ACES`"
  (`src/ace-ISA-priv.adoc:28`) — and Zkl conformance requires one of the two. So the priv-less
  configuration is simultaneously specified and impossible; and which of
  `Smacecrstatus`/`SmaceCSK`/`Smacepbootscrt`/`Smacevbootscrt`/`Smacelclt` a conforming system must
  implement is never stated (e.g., without `Smacecrstatus` there is no `ace_exc_CR_off`, no lazy
  loading, and no trap-and-emulate — yet trap-and-emulate is how `Zklmem` may be satisfied per
  `src/ace-ISA-unpriv.adoc:138`).
- **Resolution:** Add a conformance clause to Book 3: enumerate which CSR extensions are mandatory
  for (a) M-mode-only systems, (b) M+U, (c) M+S+U, (d) +H; state precisely which profile
  corresponds to "Privileged Architecture not implemented" (presumably M-mode-only without a CSR
  file), and note that trap-and-emulate of `Zklmem` requires `Smacecrstatus`.

---
**FIXED M14 — `macecsk` activation protocol: wrong/ambiguous flag-reset trigger; reserved `ace.mgmt` immediates unspecified**

- **Rationale:** The CSK write protocol is a security-critical atomicity mechanism; its edge rules
  must be exact.
- **Location:** `src/ace-ISA-priv.adoc:697`: "Any mode change **to** M-mode will reset the flags."
  Taken literally, a trap to M-mode (e.g., an interrupt hitting M-mode firmware between two
  `macecsk` writes, re-entering M via a nested trap) silently discards a partial write; more
  importantly the plainly intended trigger — leaving M-mode with a partial write outstanding — is
  not what the text says. Also `src/ace-ISA-unpriv.adoc:1947-1958`: `#immed7` values 0–3 are
  defined for `ace.mgmt`; values 4–127 have no specified behavior (contrast `ace.setst`, where
  unsupported immediates → Error State _Invalid_).
- **Resolution:** Replace with: *"Any transition of the hart out of M-mode, and any ACE unit
  reset, clears the write-tracking flags and discards the partially written value."* For
  `ace.mgmt`: *"Values of `#immed7` other than 0–3 are reserved; issuing `ace.mgmt` with a
  reserved value causes the target CR to transition to Error State _Invalid_ [or: raises an
  illegal-instruction exception — choose one]."*

---

**FIXED as a non-issue M15 — ACEV is normatively load-bearing but undefined; vector-side interactions unspecified**

- **Rationale:** `Zklv` conformance depends on "at least the ACEV subset"
  (`src/ace-ISA-unpriv.adoc:144`), which the spec itself marks as not to be finalized before
  ratification begins (`src/ace-ISA-unpriv.adoc:352-357`). Separately, for ACE instructions with
  vector operands, the interaction with `vstart` (must it be zero? is nonzero illegal?),
  tail-element policy for `Vd` beyond `ACELEN`, and `vtype.vill` are unstated; RVV requires each
  instruction to define these.
- **Location:** as cited; also `src/ace-ISA-unpriv.adoc:316-361`.
- **Resolution:** Before candidacy, either freeze ACEV's normative content (the bullet list at
  `src/ace-ISA-unpriv.adoc:330-343` is nearly there — remove the "(`vins`/`vext`?)" placeholders)
  or re-scope `Zklv` onto full V. Add: *"ACE instructions with vector operands require `vstart` = 0
  and raise an illegal-instruction exception otherwise [they use `acestart`, not `vstart`, for
  resumption]; elements of `Vd` past `ACELEN`/`SEW` follow the tail-agnostic policy; if
  `vtype.vill` is set, the instruction raises an illegal-instruction exception."*

---

m2 — Transfer granularity contradictions.** `ace.load`: "`acestart` is also a multiple of 16"
(`src/ace-ISA-unpriv.adoc:1484`) conflicts with the 1-byte granule in `<<ACE-forward-progress>>`
(`src/ace-ISA-unpriv.adoc:3015`) and byte-granular prefix-completeness; `ace.store` may start at 8,
which is not a multiple of 16. State one rule: `acestart` for CR transfers is a byte count;
implementations may halt only at 16-byte boundaries (if that is the intent), and the
forward-progress granule for these instructions is then 16 bytes.

---

**FIXED** 1. **`ace.load` "16th byte" vs. `ace.store` "8th byte"** (`src/ace-ISA-unpriv.adoc:1475` vs
`:1538`): the asymmetry is intended (store may begin after `ace.getmdl` of the low half) but is
   nowhere explained; C1's resolution should state both entry points and their `acestart` values
   in one table.

---

**FIXED m3 — `ace.getmd*` register constraints.** RV64 `ace.getmdl` writes one GPR yet requires even `d`
(`src/ace-ISA-unpriv.adoc:2165-2166`); RV32 `ace.getmdl` writes a pair yet requires `d` multiple of
four (`src/ace-ISA-unpriv.adoc:2178`), contradicting the general "odd register number … when a
register pair is expected" rule (`src/ace-ISA-unpriv.adoc:996`). Also typo "into GPR `Xd`. and bits
[127:64]" (`src/ace-ISA-unpriv.adoc:2168`). Relax to: no constraint for single-register writes;
even for pairs; multiple-of-four for quartets — or state that uniform alignment is deliberate.

---

**FIXED m7 — Dangling "Rule 3".** `src/ace-ISA-unpriv.adoc:3303` cites "Rule 3 of
<<ACE-rules-masked-implementations>>", but that section (`src/ace-ISA-unpriv.adoc:3276-3292`) has
no numbered rules.

---

**FIXED m11 — Anchor case-collision.** `[[ACE-Notation]]` (notation chapter) vs `[[ACE-algo-notation]]`
(Book 2 subsection) differ only in case; `src/ace-ISA-unpriv.adoc:361,1410` reference
`<<ACE-algo-notation>>` where the notation chapter appears intended. Rename the Book 2 anchor (e.g.,
`ACE-alg-notation`).

---

# Part II — Findings from the Machine-Checked KAT Suite

_Added after the narrative review above. A companion suite of 18 known-answer-test harnesses in
`kat/` models the specification's algorithms and state machines directly from the normative text
and checks them against published standard vectors. `python3 kat/run-kats.py` runs all 18 in ~33 s;
all pass. The findings below were produced or confirmed by that exercise; several could not have
been found by reading alone._

## 7. Suite Structure and Anchor Levels

`kat/common.py` provides the ACE notation layer (little-endian values, `@`/`cat`, `bswap`, `bin`)
and self-tested primitives: AES-128/192/256 with an algorithmically generated S-box (FIPS 197
C.1–C.3), GHASH multiplication (SP 800-38D §6.3), POLYVAL `Montmul` (RFC 8452 App. A), and the
XTS/OCB doublings (SP 800-38B D.1 subkey). Each harness additionally implements an independent
byte-string *reference* straight from the source standard, so that "ACE model vs. standard" and
"ACE model vs. reference" are separate signals.

Anchor levels are stated honestly per harness and are **not** uniform:

| Harness | Vectors / provenance | Anchor level |
|---|---|---|
| `ecb-kat.py` | FIPS 197 C.1–C.3; SP 800-38A F.1.1–F.1.6; GB/T 32907 Ex.1, Ex.2 (full 10⁶-round iteration), A.2.1 | standard-vector (no published SM4 *decrypt* vector: inversion only) |
| `ctr-kat.py` | SP 800-38A F.5.1/F.5.3/F.5.5; XCTR from `google/hctr2` test vectors | standard-vector (CTR); reference-impl (XCTR); reference-consistency (nonce/counter splits) |
| `xts-kat.py` | IEEE 1619 / SP 800-38E vectors incl. ciphertext stealing (via Botan `xts.vec`) | standard-vector, both directions incl. CTS |
| `gcm-kat.py` | McGrew–Viega / SP 800-38D cases 1–6, 13–18 | standard-vector |
| `gcmsiv-kat.py` | RFC 8452 App. C — 14 vectors incl. counter-wrap, with published intermediates | standard-vector incl. intermediates |
| `scc-kat.py` | RFC 8452 App. A/C for the shared functions | `AESE256`/`POLYVAL`/`RFC8452_KeyDeriv` standard-anchored; the nonce-less sealing construction **self-consistent only** (no vector can exist), with printed regression vectors |
| `ocb-kat.py` | RFC 7253 App. A — all 16 TAGLEN128 samples, TAGLEN96, the long iterated vector, and the published `L_*`/`Ktop`/`Stretch`/`Offset_0` intermediates | standard-vector, formula-by-formula |
| `cmac-kat.py` | RFC 4493 / SP 800-38B D.1–D.3 incl. published L/K1/K2 | standard-vector |
| `sha2-kat.py` | FIPS 180-4 test strings, six functions | standard-vector; constants *derived* from prime roots, not transcribed |
| `sm3-kat.py` | GB/T 32905-2016 App. A (both vectors) + 270 lengths vs. reference | standard-vector |
| `hmac-kat.py` | RFC 4231 cases 1–4, 6–7 × SHA-224/256/384/512; SHA3-256/512 vs. oracle | standard-vector (SHA-2); oracle (SHA-3, whose `H` the spec delegates) |
| `shake-kat.py` | FIPS 202 / CSRC example values; Keccak-f[1600] from scratch | standard-vector |
| `kmac-kat.py` | SP 800-185 `KMAC_samples.pdf` and `KMACXOF_samples.pdf` — all 12 samples | standard-vector |
| `ascon-kat.py` | `ascon/ascon-c` NIST-final genkat; reference validated against the **complete** files (1089 AEAD + 1025 Hash + 1025 XOF + 1089 CXOF records) | standard-vector |
| `ecc-kat.py` | RFC 6979 A.2.5–A.2.7; RFC 8032 7.1/7.3/7.4; GM/T 0003.5 App. A | standard-vector; **Brainpool parameter-validation + round-trip only** (no published ECDSA KATs) |
| `mlkem-kat.py` | NIST ACVP-Server `internalProjection.json`, with `tcId`s, incl. `encapsulationKeyCheck`/`decapsulationKeyCheck` | standard-vector; full FIPS 203 implementation |
| `mldsa-kat.py` | NIST ACVP-Server, incl. `externalMu` groups matching the ACE interface | standard-vector incl. hedged `Sign_internal`; full FIPS 204 implementation |
| `mgmt-kat.py` | none applicable | models Book 1 state machines; toy seal clearly labelled; 403 checks |

Every harness carries at least one declared negative control, and the runner fails a harness whose
negative control stops firing — so a test that has lost its power to discriminate is reported
rather than silently passing. `gcm-kat.py` further asserts a minimum number of *observable*
vectors per control (with empty AAD and empty plaintext, the swapped-length-block and
little-endian-counter models coincide with the correct one).

## 8. New Findings

### Major

**K1 — `RFC8452_KeyDeriv` is undefined for AES-128-GCM-SIV.**
`<<ACE-SCC-RFC8452-derivation>>` types the function `key : bits(256)`, builds it from `AESE256`
over counter blocks 0–5, and returns `enc_key : bits(256)`. But `<<ACE-GCM-SIV-mode>>` declares
`k` = 128|`k` and its _Set_Aux_Value_ calls that same function, and `AES128_GCM_SIV` is an
architected encoding (Type 0, Mode 6). For AES-128 the derivation must use AES-128 over counter
blocks 0–3 with a 128-bit `enc_key`; nothing in the document says so, so a conforming
AES-128-GCM-SIV cannot be built from the text. *Resolution:* generalize the signature to
`bits(k)`/`AESE(k)` with the block count `4 + k/128`, or state the `k` = 128 case explicitly.
(Confirmed against RFC 8452 C.1 intermediates by `gcmsiv-kat.py`.)

**K2 — `<<ACE-Ascon-CXOF128>>` omits the mandatory 64-bit customization-length field.**
The section says only that "the message is prepended with the customization string" and delegates
padding to the caller. SP 800-232 §5.3 requires the absorbed prefix to be
`bin(8·len(Z), 64) @ pad(Z, 64)` — a 64-bit little-endian *bit-length* field ahead of `Z`.
Following the ACE text literally produces output that does not match the official CXOF128 vectors,
and because the field is not mentioned at all, a caller cannot construct a conformant input. This
is a conformance break, not an ambiguity. *Resolution:* state the length-field prefix explicitly.

**K3 — `<<ACE-HMAC>>` does not say which rendering of `state` the inner-hash slice applies to.**
The step `inner <- state[d+state_offset-1 : state_offset]` is well-defined only once one knows
whether `state` denotes the raw chaining variables or the digest-emission form of
`<<ACE-SHA-2>>` (`bswap(bin(H~i~,w))` at byte `i·w/8`). Only the latter reproduces RFC 4231 for the
truncated variants: under the naive reading, HMAC-SHA-224 and HMAC-SHA-384 truncate the wrong end
of each word and produce wrong tags. *Resolution:* make the rendering explicit at that step.

**K4 — the `ace.mv` extraction gate makes the Book 4 `Zklmv` partial-export loop an illegal
instruction.** The extraction forms of `ace.mv` require _ConfigStatus_ = `ace_cfgst_exporting`, but
export-start of a *not-complete* CR leaves _ConfigStatus_ at `ace_cfgst_provisioning`/`importing`
(<<ACE-instruction-manage>>). The Book 4 `Zklmv` export sequence is therefore illegal in exactly
the partial-CR case it exists to serve. The same gap affects `ace.store`: for a partial CR nothing
distinguishes "prepared for export" from "mid-provisioning", so a stray `ace.store` can read a CR
that was never prepared for export. *Resolution:* either have export-start set a distinguishing
_ConfigStatus_ (or flag) for partial CRs, or widen the `ace.mv`/`ace.store` gates to admit the
partial statuses when an export has been opened.

**K5 — XCTR's counter origin is unspecified and defaults to a non-interoperable value.**
State _Ready_ sets `ctr` = 0, so the first keystream block is `keystream_block(IV xor 0)` =
`E_K(IV)`. HCTR2 — the construction XCTR exists to serve — numbers its counter from 1, so the two
streams differ (asserted by `ctr-kat.py`). ACE can express HCTR2 only if software first issues the
Form B "set initial counter" with `Xs` = 1, which the section never says. The commented-out line
`// (ctr is set to 1 if the algorithm is LFSR-based)` suggests the question was raised and left
open. *Resolution:* name the expected counter origin for each X-mode instantiation.

### Minor

**K6 — `<<ACE-HMAC>>`'s `b` is undefined for SHA-3.** It is "the input block size of the underlying
hash function", but `<<ACE-SHA-3>>` never defines a block size; its table names `b` the *rate*. The
rate reading (1088/576) is confirmed correct against the oracle. Add a clause.

**K7 — the two-block padding clause of `<<ACE-SHA-3>>` is unreachable at the architectural
interface.** `|S| = 2b − block_base` requires `b − block_base < |D| + 2 ≤ 6`, but `ace.exec`
transfers whole bytes, so `block_base` is always a multiple of 8 and `b − block_base ≥ 8`. The
clause is dead code for any legal instruction sequence, reachable only through `process_VLI`'s
bit-level generality. Either scope it explicitly to bit-granular callers or drop it for SHA-3.

**K8 — `<<ACE-KMAC>>` output-padding wording.** "the last byte may be zero-padded in its
significant bits" should read *non-significant* bits; moreover the spec's own _Hash_Output_ loop
copies raw state bits, so the excess bits are squeeze output rather than zeros. Both readings agree
on the `L` significant bits; the text should say which applies.

**K9 — GCM's blanket granularity rule contradicts its own _Set_Aux_Value_ state.** "`ACELEN` must
be an integer multiple of `b`" is contradicted by _Set_Aux_Value_, which is `process_VLI` with
`granularity` = `b` and therefore *requires* a short final transfer for a 96-bit IV (and for the
trailing 12 bytes of the 60-byte IVs of test cases 6/18). Scope the rule to the block-consuming
states.

**K10 — `<<ACE-keystream-modes>>` Form C refers to a nonexistent operand.** The paragraph says the
operations apply to "each of the `ACELEN/b` `b`-bit blocks of `INPUT`", but Form C
`ace.exec OUTPUT, Kn|K{Xn}` has no `INPUT` — a keystream generator consumes nothing. Should read
`OUTPUT`. ("the above *three* commands" is also off by one.)

**K11 — over-run rules are inconsistent across the PQC states.** ML-DSA ignores excess bits in
`_*_Input_` states but transitions to _Invalid_ on an over-long `_pubkey_Output_`/`_Sign_Output_`
transfer; ML-KEM states no over-run rule for its `_*_Output_` states at all. Three treatments of
one situation.

**K12 — the `_AuxInfo_` hash-function encoding is not defined in the document.** ML-DSA requires
`_AuxInfo_` to "encode a hash function that FIPS 204 admits", with the format of the _Algorithm_
and _AlgorithmPolicy_ fields — but that table is RVI-maintained and not reproduced here, so the
requirement is untestable and unimplementable from the document alone. The `ace.derive` destination
key length has the same dependency.

**K13 — ECC `Xs` bit 3 is a duplicate.** The Ready-return text mapped "Bit 0, 1, 2, resp., 3" onto
"`Generator` reset, `SecondPt`, `Scalar`, resp., `SecondPt` erased" — `SecondPt` appeared twice, so
bit 3 carried no distinct meaning; the fate of `Hash` on a return to _Ready_ was meanwhile not
stated at all.
FIXED — the bullet now assigns one field per bit with **uniform polarity throughout**: a set bit
discards the field it names (Bit 0 `Generator`, Bit 1 `SecondPt`, Bit 2 `Scalar`, Bit 3 `Hash`,
Bit 6 `Signature`), a clear bit retains it, and a Form A `ace.setst` — which sets no bit —
therefore retains everything. The previous unconditional reset of `Signature`/`HasSignature` is
gone; Bit 6 now exists to drop a *stale* signature rather than to preserve a fresh one.

Retaining the signature by default is what lets a single CC sign and then verify: a CR in
_Success_ may only move to _Ready_ or _Unconfigured_ (`<<ACE-State-field>>`), so the two operations
must be separated by a pass through _Ready_, which previously destroyed the signature. It is also
the consistent choice — `Scalar` holds the *private key* and was already retained by default, so
auto-erasing the public `(r,s)` made the least sensitive field the only special case. A worked
five-step sequence is given in a NOTE, and `kat/ecc-kat.py::test_sign_then_verify_one_cc` walks it
end to end, additionally checking that setting Bit 6 does discard the signature and that
`_Sign_Verify_` is then refused.

This also settles the question of whether to drop `_Ready_ -> _Sign_Verify_` from the transition
list: **keep it.** It was vacuous only because `HasSignature` was unconditionally cleared on entry
to _Ready_; with Bit 6 it is exactly the edge the sign-then-verify flow traverses. Ordinary
verification never needed that edge — it enters `_Sign_Verify_` from a `_Set_` state after loading
`SecondPt`, `Hash` and `Signature`.

**K14 — point-at-infinity as a `_Point_Mul_` input is unspecified.** The state must verify the base
point is on the curve, but the text never says whether the all-ones sentinel is an acceptable
`SecondPt`. Explicit rejection is the safer rule.

**K15 — the enforcement point of secp521r1's 55-zero-msb rule is unstated.** The constraint is
given but not where a violating value is caught; `ecc-kat.py` rejects at field-load time.

**K16 — the new `managedcr` CSR is unspecified** as to reset value, WARL behaviour on a software
write, and interaction with `ace.clear` of the managed CR.

**K17 — after export-start of a not-complete CR, the architectural state does not say which process
the closing `ace.mgmt` completes.** _ConfigStatus_ remains `provisioning`/`importing`, so the same
state means both "resume loading" and "finish exporting"; a model needs one non-architectural bit
to disambiguate.

**K18 — `ace.restricth` treats an over-large `_ExpirationDate_` asymmetrically:** it is silently
ignored, whereas every other illegal widening invalidates the CR.

**K19 — the ordering of the UsagePolicy check against the expiration check at dispatch is
unstated.** `mgmt-kat.py` checks UsagePolicy first, so that an unauthorised caller cannot destroy
CC content by triggering expiration.

**K20 — CMAC's K2 branch is undefined at `last_blk_len` = `b`** (the padding width
`zeros(b − 8 − last_blk_len)` goes negative). Harmless as written because the K1 branch splits that
case off first, but it means the branch split is load-bearing rather than an optimization; state
the `0 ≤ last_blk_len < b` precondition if m6's wording is revisited.

**K21 — ECB's "least significant positions first" rule is unobservable for ECB itself.** Each block
is read from and written to the same bit position, so loop order cannot affect the result; what the
sentence actually fixes is the value↔string block correspondence (which is what `ecb-kat.py`
tests). Since it is declared to hold "here, and in the rest of this document" it does carry weight
for chaining modes, but as placed it reads like a constraint where none is observable. Also, ECB
says "If `ACELEN` > `b`" where the keystream and XEX sections say "If `ACELEN` is a multiple of
`b`"; the latter is more precise.

**K22 — GCM editorial:** in the _Set_Aux_Value_ overlay the `input_base` row's second sentence
describes `block_base`; the _Enc_Tag_Finalize_ INPUT expression is typeset with a doubled `@`
across the line break.

### Residues of the fixes applied during this review

Confirmed by `mgmt-kat.py` against the current text: **C1 resolved** (both instructions now state
the *j*-th-byte-after-MDH rule; `ace.mgmt` clears `acestart`; the Book 4 import snippet reads
`16(t6)`), **C2 resolved** (validity split by operation; import accepts any _State_), **C3
resolved** for the deadlock (the illegal-instruction list now exempts the `macecsk` group).
**M2 remains unresolved** (Forms B/C still return `32`, against the synopsis, `ace.avail` and Book
4's `beqz`), **m1 remains unresolved** (the `aceiobuftop` clamp still coexists with the
`ace.input`/`ace.output` no-op), and **m2 is only partly settled** (the transfer instructions now
say 16-byte chunks, but `<<ACE-forward-progress>>` still states a 1-byte granule). Three residues:

**K23 —** `ace.store` still opens with "starting with the 8th byte of the MDH" and "`acestart` …
starting from 8 or 16 depending on the use of `ace.getmdl`". Both contradict the new rule and the
new "`ace.mgmt` … sets `acestart` to zero", and the `getmdl`-dependence is unimplementable:
hardware cannot observe which `getmd*` software executed earlier.

**K24 —** the `ace.load` _Description_ now contains a paragraph describing `ace.store` — copy-paste
debris in the wrong instruction.

**K25 —** "*State* and *StateExtension* must be zero, i.e., upon provisioning, *State* is always
*Ready*" conflates the MDH input value 0 with the resulting state _Ready_ (1).

## 9. Confirmations of Part I Findings

Demonstrated, not merely asserted:

- **M4** (`process_VLI` bit/byte clash): under the literal reading a resumed absorption restarts
  eight times too early and the message tail is never absorbed — wrong digests, not a cosmetic
  defect. Confirmed by `shake-kat.py`, `sha2-kat.py`, `kmac-kat.py`, `gcm-kat.py`.
- **M10** (ECC `_Set_Signature_` dead end): a breadth-first search over the transition relation as
  it was written found no state reachable from `_Set_Signature_`; verification was unreachable.
  **Since fixed** (see M10 above); `ecc-kat.py` keeps the pre-fix relation as a regression check
  and now asserts that `_Set_Signature_` -> `_Sign_Verify_` is reachable in the current text.
- **M12** (FIPS 203/204 validation): `mlkem-kat.py` shows the literal behaviour — a malformed `ek`
  with a coefficient ≡ q is accepted and `_Encapsulate_` proceeds — beside the conforming
  behaviour, anchored on NIST's own malformed-key test cases.
- **m4** (OCB): `bswap(N[N_len-1:0])` undefined for non-byte-multiple `N_len`; and the
  `index = ones(48)` guard present in `_Enc_Last_Block_` is absent from `_Dec_Last_Block_`.
- **m5** (Ascon padding): a caller obeying the prose double-pads and produces wrong ciphertext.
- **m6** (CMAC empty message): with `last_blk_len` = 0, feeding `INPUT` = 0 and `INPUT` = `ones(128)`
  both yield the published empty-message tag for all three key sizes — confirming the proposed
  wording "INPUT is ignored".
- **m8** (GCM-SIV transitions): the missing state-entry Forms forced the model to transition
  implicitly, and on the decrypt path to invent a zero-length call purely to enter _Decrypt_.
- **m18** (sealing domain separation): segment binding rests entirely on `AD2[1]` = `SIV`; both
  segments use the same derived keys with no domain-separation constant.

## 10. Ambiguities Left Unmodelled

Reported by `mgmt-kat.py` as too under-determined to model, and therefore review input in their own
right: the behaviour of non-listed instructions in _Success_/_Failure_ (rule 2 names only the
permitted set); the effect of `ace.exec` in _Ready_ ("no `ace.exec` may be executed", with no stated
consequence); Error-State severity ordering when two conditions coincide; `ace.derive`'s effect on
the two CRs (cf. M5); CRF-capacity discovery (no mechanism exists); and the CR state left behind
when `ace.restrict*` raises `ace_exc_out_of_memory` and the handler frees nothing.

## 11. Correction to Part I

The SM3("abc") digest quoted when commissioning the harnesses was wrong. The GB/T 32905-2016
Appendix A value is
`66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`, which both the from-scratch ACE
model and an independent reference reproduce. No specification text was affected; recorded here
because `sm3-kat.py` documents the discrepancy in its header.
