### **M3 — `ace.derive` aliasing, validation order, and partial-error behavior are undefined**
### **M10 — Expiration evaluation is inconsistent and the boundary is undefined**
### **M11 — Memory-fault and restart semantics are unsafe for side-effecting regions**

# 1. Executive assessment

## **Not ready for candidacy**

The reviewed Unprivileged Architecture contains multiple material correctness and interoperability-blocking defects. Most importantly:
- Provisioning confuses `_Unconfigured_` and `_Ready_`, leaving the post-provisioning state undefined.
- Oversized SCC imports have no safe, implementable staging and transfer model.
- `ace.derive` has undefined aliasing, validation ordering, and partial-failure semantics.
- The interruptibility rules directly disagree about `ace.mv`.
- Several serialized-format cases are internally contradictory, including `_AddDataLen = 1` and Error-State SCCs.

These are not merely editorial defects. Independent implementations could disagree about state transitions, partial instruction effects, and how much memory is accessed.

I excluded all items in both Group A and Group B of **Open Points** (`ace-introduction.adoc:95-199`), including opcode/CSR/cause allocation, ACEV EGW, formal RVWMO axiomatic integration, cross-hart CSK configuration, `ace.mgmt` preemptibility, nonce addition, and the other explicitly listed design questions.

---

# 2. Findings

## Critical

No Critical findings remain after incorporating the reviewed corrections.

---

## Major

---

### **M3 — `ace.derive` aliasing, validation order, and partial-error behavior are undefined**

**Severity rationale:** Implementations can produce different keys and state transitions, or advance a stateful source before discovering an invalid destination.

**Locations:**

- `ace-ISA-unpriv.adoc:2393-2499`.
- `ace-ISA-unpriv.adoc:2462-2470` — both state machines advance.
- `ace-ISA-unpriv.adoc:2472-2486` — truncation, padding, and open destinations.
- `ace-ISA-unpriv.adoc:2491-2498` — destination preconditions and independent policy checks.
- `ace-ISA-unpriv.adoc:2921-2929` — partial progress and “unpredictable” overlap.

**Issue:**

The encoding permits source and destination to name the same CR. The specification does not define:

- whether same-CR use is legal,
- whether the source or destination transition happens first,
- whether all policy, expiration, index, state, length, and capacity checks precede either transition,
- what happens to the source if the destination is invalid,
- or the post-error state after partial progress.

“Unpredictable” results are unacceptable for an architectural cryptographic operation, even if constrained to architectural state.

The fixed-source/fixed-destination padding rules are also not compositional. For example, where a 16-byte source, 32-byte destination, and `length = 24` are used, it is unclear whether the destination receives 16 data bytes plus 16 zeros, 16 data bytes plus 8 zeros while retaining its final 8 bytes, or another result.

**Proposed resolution:**

Prefer:

> `ace.derive` with identical source and destination CRs is reserved and raises an illegal-instruction exception without changing state.

Require a preflight stage:

```text
validate both CR indices and non-aliasing
validate ConfigStatus and State
validate both UsagePolicies
validate both expirations
validate i, j, Form, length, and endpoint sizes
validate required capacity
only then begin transfer
```

Define the exact produced byte string:

```text
T[k] = source[k] if k < source_size else 0, for 0 <= k < length
```

and destination write behavior, including untouched bytes. Define per-unit commit order and both CR postconditions on every error.

---

### **M10 — Expiration evaluation is inconsistent and the boundary is undefined**

**Severity rationale:** A key may remain usable for an extra hour or `ace.derive` may bypass expiration on some implementations.

**Locations:**

- `ace-ISA-unpriv.adoc:819-830` — normative evaluation points list only `ace.setst`, `ace.exec`, and resumption.
- `ace-ISA-unpriv.adoc:2496-2498` — `ace.derive` evaluates both expirations.
- `ace-ISA-unpriv.adoc:827` — “has passed” is not defined as `>` or `>=`.

**Issue:**

`ace.derive` is a usage instruction and can expose or overwrite secret fields, but it is absent from the supposedly exhaustive evaluation list. The phrase “expiration date has passed” is also ambiguous for a field expressed in whole hours.

**Proposed resolution:**

Define:

```text
expired(MDH) :=
    MDH.ExpirationDate != 0 &&
    secure_clock_hours_since_epoch >= MDH.ExpirationDate
```

Then state:

> Expiration is evaluated before any state or output effect of `ace.exec`, usage-controlled `ace.setst`, or `ace.derive`, and at every architectural resumption point. For `ace.derive`, both endpoints are checked before either endpoint changes.

---

### **M11 — Memory-fault and restart semantics are unsafe for side-effecting regions**

**Severity rationale:** Out-of-order component accesses followed by restart can duplicate or reorder MMIO effects. Prefix completion alone cannot roll back externally visible non-prefix accesses.

**Locations:**

- `ace-ISA-unpriv.adoc:855-869` — no atomicity.
- `ace-ISA-unpriv.adoc:2921-2927` — prefix commit and memory-fault rules.
- `ace-ISA-unpriv.adoc:2966-2989` — component order unconstrained.
- Commented-out conflicting-access requirement at `2952-2962`.

**Issue:**

Component memory operations may execute in any order. On fault, the architectural state commits only a prefix and resumption reissues later bytes. If a non-prefix access has already reached MMIO or another side-effecting region, its effect cannot be undone and may be repeated.

The text also fails to define the faulting address reported for a decomposed transfer or whether translation and PMA checks are performed before side effects.

This is distinct from the excluded Open Point about expressing already-settled behavior in the formal RVWMO axiomatic model; the necessary informal behavior is itself absent for side-effecting memory.

**Proposed resolution:**

Either prohibit such accesses:

> ACE multi-byte memory instructions are supported only for idempotent, cacheable main memory. If any byte maps to a non-idempotent or side-effecting PMA region, the instruction raises an access-fault exception before any component access occurs.

Or require all translation, permission, PMP/PMA, and side-effect checks before issuing any component operation, plus prefix issue order for non-idempotent regions. Define `xtval` as the lowest-address failing byte, or another precise rule.

---

## Minor

---

# 3. Cross-document inconsistencies and missing requirements

## Direct inconsistencies

| Topic | Location A | Location B | Conflict |
|---|---|---|---|
| Provisioned state | `ace-ISA-unpriv.adoc:502,510` | `1911-1913` | State 0 is `_Unconfigured_`, but provisioning calls zero `_Ready_`. |

| `ace.mv` interruption | `2907` | `2921,2927` | Uninterruptible/no writes versus resumable/prefix committing. |

** | `_AddDataLen = 1` | `716,726` | `3422,3467` | Marker for absent/discarded ADS versus trigger to process ADS. |
| Error-State SCC | `3036-3037`, `3100` | `3415-3426` | Exactly MDH+SIV versus generic Content/ADS processing. |
| Expiration | `821-830` | `2496-2498` | Exhaustive list omits `ace.derive`, which later checks expiration. |
| Reset/CSK | `1253,1262` | `1262,1307` | Hardwired CSK active immediately versus all reset CSKs unavailable. |
| Form B validation | `2597-2604` | `2791-2801` | Whole malformed MDH check versus only first 64 bits. |
| DIEL import timing | `460`, `3490` | `3497-3504` | Data-independent crypto latency versus data/failure-dependent import timing without a defined boundary. |

## Missing normative requirements

1. Prevalidation and error atomicity for two-CR instructions.
2. Same-CR behavior for `ace.clone` and `ace.derive`.
3. Exact postconditions for every instruction issued against:
   - `_Unconfigured_`,
   - each Error State,
   - incomplete `_ConfigStatus_`,
   - expired contexts.
4. Cryptographic erasure before CRF/staging reuse.
5. Bounded import staging and oversized-ADS behavior.
6. External legality rules for `_AddDataLen = 1`.
7. Exact fault address, partial-state, and MMIO/PMA behavior.
8. A complete per-CSK-model reset table.
9. Known-answer test vectors for the modified SCC construction.
10. Precise definitions of DIEL, first-order SCA protection, and fault tolerance.
11. `ace.getmd*` behavior on unconfigured CRs.
12. Capacity-allocation and failure semantics for `ace.clone`, especially when replacing a differently sized destination.
13. A normative statement that validation errors are detected before secret-dependent or irreversible endpoint changes wherever required.

---

# 4. Standards-compliance matrix

| Requirement / standard | ACE location | Assessment | Evidence |
|---|---|---|---|
| RFC 8452 constant-time tag comparison | `3353-3378`, `3485-3504` | **Covered in principle; DIEL definition needs clarification** | RFC 8452 §5 requires constant-time comparison. ACE applies DIEL to SCC authentication, which can satisfy this for fixed public operand dimensions if DIEL explicitly covers block processing and the final authentication decision; total time may vary with the public number of blocks. |
| RFC 8452 no release of unauthenticated plaintext | `3363-3377`, `3445-3476` | **Largely compliant, clarification needed** | Plaintext remains in CR-internal storage and is zeroed on failure. “Release” should explicitly include all architectural and implementation-defined CRF access paths. |
| RFC 8452 key-derivation block format | `3224-3241` | **Confirmed divergence; not necessarily prohibited** | RFC 8452 §4 uses LE32(counter) followed by nonce. ACE uses nonce followed by `bin(i,32)`. It is a custom construction and needs its own name, byte-order definition, analysis, and vectors. |
| RFC 8452 security limits | `3247-3249` | **Not assessed as a finding** | The nonce-related construction choice is explicitly listed as an Open Point and was excluded as instructed. Any claimed bound nevertheless requires independent analysis of the modified construction. |
| RISC-V Unprivileged ISA, RVWMO | `2966-2989` | **Incomplete; formal-integration issue excluded** | The draft says component operations obey RVWMO but does not resolve side-effecting-memory restart. The separate Open Point about axiomatic formalization was not treated as a finding. |
| RISC-V precise trap/restart conventions | `2921-2937` | **Needs clarification** | Prefix completion is described, but exact fault-address behavior and the contradictory `ace.mv` rules prevent deterministic restart. |
| RISC-V Vector 1.0 `vstart` restart model | `356-357`, `1143-1188`, `2900-2937` | **Substantively aligned; explicit software rule recommended** | `acestart` can use the ordinary `vstart` convention: handlers save it around nested use and restore it before resumption. The ACE text should state this obligation directly. ACEV EGW questions were excluded as Open Points. |
| RISC-V CSR address privilege/read-only encoding | `1014-1035` | **Not assessable from placeholders** | Addresses are `0xXXX`; allocation and placement are explicitly excluded Open Points. Final addresses must encode intended privilege and read-only properties. |
| RISC-V Scalar Cryptography `Zkr` entropy source | `847-852` | **Reference is imprecise** | `Zkr` specifies an entropy-source interface and associated requirements; it is not, by itself, a complete architected DRBG specification. ACE should identify the exact `Zkr` version and the DRBG standard it requires. |
| RISC-V Debug Specification, `dmstatus.authenticated` | `1276-1307` | **Conceptually consistent; mapping implementation-defined** | The Debug Module exposes authentication state. ACE correctly labels the mapping to its authenticated-debug signal implementation-defined. Further debug-review ownership is an excluded Open Point. |
| RISC-V extension naming and opcode allocation | `1320-1321` and Open Points | **Excluded** | Explicitly assigned to ARC/Open Points; not included as a finding. |
| RISC-V extension discoverability | `2789-2801` and Open Points | **Excluded except for Form B semantic contradiction** | Choice between `ace.avail` and Unified Discovery is open; the impossible whole-MDH validation claim is independently defective. |
| FIPS 197 AES-256 primitive | `3221-3223` | **Consistent at primitive level** | `AESE256` is defined as AES-256 encryption of a 128-bit block. Endianness and composition issues arise in the surrounding custom KDF, not AES itself. |

Version note: the ACE draft identifies itself as revision `0.7.0`, dated August 2026 (`ace.adoc:6-8`). Applicable RISC-V citations should be pinned to exact ratified publication versions in the bibliography rather than floating references. RFC 8452 is April 2019.

---

# 5. Suggested prioritized remediation plan

## Priority 0 — Security blockers

1. Resolve provisioning’s State 0 versus State 1 contradiction.
2. Prohibit or fully specify same-CR `ace.derive`; require complete prevalidation.

## Priority 1 — Serialized-format and memory safety

3. Define bounded import staging and oversized-ADS handling.
4. Make `_AddDataLen = 1` internal-only or otherwise give it a valid external format.
5. Add explicit Error-State SCC branches to export and import.
6. Specify MMIO/PMA restrictions and exact memory-fault behavior.
7. Require cryptographic erasure before storage reuse.

## Priority 2 — Resumption and lifecycle completeness

8. Resolve `ace.mv` interruptibility.
9. Define all Error-State, unconfigured, expiration, and partial-configuration instruction outcomes.
10. Add per-CSK-model reset semantics.
11. Define clone capacity allocation, aliasing, and failure atomicity.
12. State the `vstart`-style save/restore rule for nested ACE use.

## Priority 3 — Cryptographic assurance and testability

13. Rename or correct the RFC 8452 KDF; specify byte order.
14. Supply comprehensive SCC known-answer tests, including malformed and failure cases.
15. Define DIEL/SCA/fault-protection levels in testable terms, including value-independent per-block and final-authentication latency for fixed public dimensions.
16. Add negative tests for:
    - `_AddDataLen` values 0, 1, 2, maximum, and oversized,
    - Error-State SCCs with stale nonzero fields,
    - interruption at every permitted boundary,
    - nested ACE use with nonzero `acestart`,
    - source/destination aliasing,
    - page/PMP/PMA faults at every transfer granule,
    - reset during in-flight operations.

## Candidacy gate

Before candidacy, the task group should produce:

- one authoritative state-transition table,
- one instruction/error/postcondition matrix,
- a serialized-format grammar,
- an executable reference model,
- normative KATs and negative tests,
- and a trap/context-switch ABI for all ACE architectural state.

---

# 6. Remaining review questions and assumptions

1. **Scope restriction:** I did not inspect any project file other than:
   - `src/ace.adoc`
   - `src/ace-introduction.adoc`
   - `src/ace-ISA-unpriv.adoc`

   Therefore, I did not assume that the Algorithms or Privileged chapters repair omissions in the reviewed Unprivileged Architecture.

2. **Open Points excluded:** I did not count as findings:
   - opcode allocation,
   - `misa.L`/ACES placement,
   - CSR addresses,
   - exception cause allocation,
   - ACEV EGW/element-width scope,
   - formal RVWMO axiomatic integration,
   - naming,
   - discoverability mechanism,
   - debug-task-group review,
   - cross-hart CSK configuration,
   - whether `ace.mgmt` should be preemptible,
   - GCM/Ascon budgets,
   - addition of an SCC nonce,
   - additional random-key-generation inputs.

3. **Cryptographic proof:** No proof or test vectors for the modified SCC construction appear in the reviewed files. The RFC 8452 security analysis cannot automatically be assumed to cover changes to KDF input layout, fixed derivation inputs, omitted length blocks, or the two domain-separation bits. The nonce question itself was excluded, but the proposal still needs an analysis of the exact final construction before ratification.

4. **Meaning of DIEL:** I assumed DIEL is intended to protect against attacker-observable timing dependent on secrets or intermediate cryptographic values. If a narrower definition is intended, it must be stated explicitly.

5. **CRF erasure:** I assumed released CRF and staging capacity can eventually be reassigned. If the implementation guarantees that stale physical bits are forever inaccessible, that guarantee needs to be normative and cover implementation-defined M-mode/emulation access.

6. **Memory types:** The reviewed text does not limit ACE memory instructions to ordinary main memory. I therefore treated mappings to side-effecting PMA regions as architecturally possible.

7. **Pages:** Stable rendered page numbers were unavailable from the source files, so locations above use exact filenames, section names, and source lines.

8. **Candidate recommendation:** Even if later chapters happen to choose safe interpretations, the Unprivileged Architecture should not advance until those choices are made authoritative and internally consistent here. Security-critical interoperability cannot depend on implementers selecting the safest interpretation of contradictory text.








FIXED
### **M4 — `ace.mv` is simultaneously uninterruptible and resumable**

**Severity rationale:** Hardware and context-switch software cannot determine whether an interrupted vector move commits nothing or commits a prefix.

**Locations:**

- `ace-ISA-unpriv.adoc:1143-1169` — `ace.mv` honors and accumulates `acestart`.
- `ace-ISA-unpriv.adoc:1660-1695` — vector transfer and advancement.
- `ace-ISA-unpriv.adoc:2904-2910`, IRR1 — all `ace.mv` is uninterruptible.
- `ace-ISA-unpriv.adoc:2918-2927`, IRR4/IRR6 — vector and block-iterated `ace.mv` are resumable.

**Issue:**

IRR1 requires no destination write when `ace.mv` does not complete. IRR4 and IRR6 require fully processed blocks to remain committed. These outcomes are mutually exclusive.

**Proposed resolution:**

Choose one:

- Scalar `ace.mv` is uninterruptible; vector `ace.mv` is resumable and prefix-committing; or
- every `ace.mv` is uninterruptible.

If retaining resumable vectors:

> IRR1 applies only to scalar `ace.mv` variants. Vector `ace.mv` variants are governed exclusively by IRR4–IRR6.


FIXED
### **M1 — Provisioning confuses `_Unconfigured_` with `_Ready_`**

**Severity rationale:** The post-provisioning state is architecturally indeterminate. Implementations can produce unusable CRs or disagree on whether State 0 contains a usable CC.

**Locations:**

- `ace-ISA-unpriv.adoc:497-514` — State 0 is `_Unconfigured_`; State 1 is `_Ready_`.
- `ace-ISA-unpriv.adoc:529-534` — all Algorithms must support `_Ready_`.
- `ace-ISA-unpriv.adoc:1908-1915` — provisioning requires `_State_ = 0` while claiming it is “always _Ready_”.
- `ace-ISA-unpriv.adoc:1926-1935` — provisioning completion changes `_ConfigStatus_` but not `_State_`.

**Issue:**

A PI must contain State 0, but State 0 is explicitly `_Unconfigured_`. Completion never normatively sets State 1. Therefore a successfully provisioned CR may have:

```text
ConfigStatus = complete
State        = unconfigured
```

The specification elsewhere treats `_Unconfigured_` as meaning that no CC exists.

**Proposed resolution:**

> A PI must encode `_State = ace_state_unconfigured` and `_StateExtension = 0`; these values are initialization sentinels and are not the post-provisioning state. After all PI validation and secret generation succeed, completing provisioning must atomically set `_State = ace_state_ready`, `_StateExtension = 0`, and `_ConfigStatus = ace_cfgst_complete`. No intermediate combination is architecturally observable.

Alternatively require State 1 in the PI, but do not use State 0 both as “no CC” and “new CC ready”.


--

---
FIXED
### **M5 — `_AddDataLen = 1` means both “ADS absent/discarded” and “ADS present”**

**Severity rationale:** Malformed SCCs can trigger reads of nonexistent `IMPQUAL`/`SIV2` fields or divergent external-format acceptance.

**Locations:**

- `ace-ISA-unpriv.adoc:712-726` — value 1 signals discarded ADS; minimum actual ADS is 2 blocks.
- `ace-ISA-unpriv.adoc:3100-3103` — `_AddDataLen_` specifies total ADS size.
- `ace-ISA-unpriv.adoc:3422-3426` — export processes ADS whenever nonzero.
- `ace-ISA-unpriv.adoc:3467-3475` — import processes ADS whenever nonzero.

**Issue:**

A one-block ADS cannot contain both 16-byte `IMPQUAL` and 16-byte `SIV2`, even before `Content2`. Nevertheless both algorithms enter their ADS paths for value 1.

It is not stated whether 1 is:

- legal in an external SCC,
- an internal-only transient value,
- or a value that must be normalized before export.

**Proposed resolution:**

> `_AddDataLen = 1` is an internal-only marker. It is invalid in any PI or external SCC and must be rejected before transfer. An actual ADS is present if and only if `_AddDataLen >= 2`. Before export, an internal value of 1 must be normalized to zero or replaced with the size of a newly generated valid ADS.

Update all `!= 0` branches to `>= 2`.

---

---
FIXED
### **M6 — Secret storage release does not require cryptographic erasure**

ok, we have clearing.

**Severity rationale:** Key material, imported unauthenticated plaintext, and intermediate state may remain in reassigned CRF or staging storage.

**Locations:**

- `ace-ISA-unpriv.adoc:298-313` — CRF confidentiality/integrity and power-down zeroization.
- `ace-ISA-unpriv.adoc:1800-1802` — Error State may release resources.
- `ace-ISA-unpriv.adoc:2024-2027` — management failures clear CR.
- `ace-ISA-unpriv.adoc:2741-2748` — `ace.clear` releases CRF resources but does not require zeroization.
- `ace-ISA-unpriv.adoc:2811-2817` — reset values.
- `ace-ISA-unpriv.adoc:1260` — implementation-defined M-mode CRF access may exist for emulation.

**Issue:**

Reset and power-down explicitly zeroize some state, but normal clear, invalidation, authentication failure, and capacity release do not consistently require erasure before reuse. “Cleared” and “unconfigured” are not defined as physical or cryptographic erasure.

**Proposed resolution:**

> Before CRF capacity, import staging, generated-key workspace, or Algorithm temporaries can be reassigned, the implementation must make all previous secret values unrecoverable through every architecturally or implementation-defined access path. Logical invalidation alone is insufficient.
>
> `ace.clear` and `ace.clearall` must cryptographically erase all affected CR Content and temporaries. `ace.clearall` must also zero `acesiv*`, `acesiv2*`, and `aceiq*`, including RV32 shadows.

Explicitly state whether instruction `ace.clearall` affects CSK and Locality state; currently its name and synopsis are broader than its detailed effects.

---

---
I think this was already clear. Just some phrasing.
### **M13 — Reset behavior for hardwired CSKs is contradictory**

**Severity rationale:** Software cannot determine whether ACE is available immediately after reset or must establish a CSK.

**Locations:**

- `ace-ISA-unpriv.adoc:1247-1264`.
- `ace-ISA-unpriv.adoc:1262` — hart reset resets CSK and leaves unit unavailable.
- `ace-ISA-unpriv.adoc:1253`, `1262` — hardwired model is immediately available.
- `ace-ISA-unpriv.adoc:1303-1307` — ACE reset restores hardwired CSK after unauthenticated Debug recovery.

**Issue:**

The statement that every hart reset leaves the unit unavailable until re-establishment cannot apply to a CSK that is hardwired and not software-configurable.

**Proposed resolution:**

Give reset behavior per model:

| CSK model | State after ACE-unit reset |
|---|---|
| M-mode programmed | absent |
| secure-block configured | absent until block reconfigures |
| hardwired | active immediately |
| boot-generated | newly generated and active only after successful RBG completion |

Also define failure behavior if boot-time random generation fails.

---

IT IS NOT THE RFC 8452, in fact. NO ISSUE HERE.
ENDIANNESS: my fault since I did not include the notation file
### **M8 — “RFC8452 Key Derivation” does not use RFC 8452’s block layout**

**Severity rationale:** Independent implementations following the label versus the pseudocode will derive different keys. The cited RFC’s security analysis and test vectors do not directly validate this construction.

**Locations:**

- `ace-ISA-unpriv.adoc:3224-3241`.
- RFC 8452 §4, “Encryption — derive_keys”.

**Issue:**

RFC 8452 constructs each KDF block as:

```text
little_endian_uint32(counter) || nonce
```

ACE specifies:

```text
nonce @ bin(i,32)
```

This reverses the 96-bit and 32-bit fields, and the byte order of `bin(i,32)` is not defined in the reviewed files. The extraction/concatenation order of `A[i][63:0]` also needs explicit byte-level definition.

A custom KDF is permissible, but it must not be labelled RFC 8452 derivation or assumed to inherit RFC test vectors without proof.

**Proposed resolution:**

Either conform exactly to RFC 8452:

```text
A[i] ← AES-256(key, little_endian_uint32(i) || nonce)
auth_key ← first64(A[0]) || first64(A[1])
enc_key  ← first64(A[2]) || first64(A[3]) ||
           first64(A[4]) || first64(A[5])
```

or rename it `ACE_SCC_KeyDeriv`, define every byte order explicitly, provide a security rationale for the changed PRF domain, and publish complete known-answer vectors for derivation, encryption, decryption, Error-State SCCs, ADS, and Localities.

This finding does not challenge the separately listed open question about adding a nonce.

---

### **M2 — Oversized SCC imports have no safe, implementable transfer/staging model**

**Severity rationale:** Literal implementation requires storing attacker-selected SCC lengths in CR-associated storage even though that storage is not allocated based on `_AddDataLen_`. Defensive implementations will disagree about truncation, faults, and `acestart`.

**Locations:**

- `ace-ISA-unpriv.adoc:408`, `712-726` — `_AddDataLen_` permits approximately 262 KiB.
- `ace-ISA-unpriv.adoc:1471-1489` — `ace.load` always transfers through `size`; there is no `imglen` bound.
- `ace-ISA-unpriv.adoc:1921-1923` — CRF allocation ignores `_AddDataLen_`.
- `ace-ISA-unpriv.adoc:3039-3052` — CRF capacity must be independent of `_AddDataLen_`.
- `ace-ISA-unpriv.adoc:3120-3142` — imported ciphertext is represented inside the CR, with tags in shared CSRs.
- `ace-ISA-unpriv.adoc:3453-3459` — unsupported ADS is supposedly excluded or skipped.

**Issue:**

`ace.load` derives its end from the attacker-supplied MDH and transfers the entire declared SCC payload. The import algorithm only later says an unsupported ADS may be excluded. No instruction-level rule explains:

- where unwanted bytes are placed,
- whether they are read from memory at all,
- how `acestart` advances over skipped data,
- which memory faults may occur,
- or how the mandatory segment is distinguished before loading.

**Proposed resolution:**

At import start, compute and retain:

```text
declared_length
mandatory_length
accepted_ads_length
transfer_length
```

Then specify one model:

1. **Full staging:** authenticated staging of `declared_length` is guaranteed; or
2. **Bounded loading:** `ace.load` accesses only `mandatory_length + accepted_ads_length`, and skipped ADS bytes are not accessed.

The latter should state:

> `ace.load` must not access or allocate storage for rejected ADS bytes. `acestart` is measured over the accepted serialized image, not the attacker-declared discarded suffix. Memory faults in bytes outside the accepted image must not be reported.

---

FIXED
### **M9 — Form B `ace.size` promises validation it cannot perform**

**Severity rationale:** Software can mistake a nonzero size for validation of malformed metadata that later operations reject.

**Locations:**

- `ace-ISA-unpriv.adoc:393-418` — malformed conditions exist in both MDH halves.
- `ace-ISA-unpriv.adoc:2551-2555`, `2597-2604` — Form B receives only `[63:0]` but promises zero for otherwise malformed MDH.
- `ace-ISA-unpriv.adoc:2791-2801` — `ace.avail` more accurately says it validates the first 64 bits.

**Issue:**

Form B cannot inspect reserved high bits, `_Locality_`, `_UsagePolicy_`, or `_ExpirationDate_`. It therefore cannot determine whether the whole MDH is malformed.

**Proposed resolution:**

> Form B validates only fields contained in MDH `[63:0]` and computes the size that those fields imply. A nonzero result does not validate MDH `[127:64]`. Full-MDH validation occurs only in a form that receives all 128 bits or during `ace.mgmt`.

Align the `ace.avail` synopsis and return-value contract with this limitation.

---

FIXED
### **M7 — Error-State SCC format conflicts with the generic export algorithm**

**Severity rationale:** Implementations can emit different lengths and tags for the same Error-State CR.

**Locations:**

- `ace-ISA-unpriv.adoc:3030-3037` — authoritative Error-State SCC is exactly 32 bytes.
- `ace-ISA-unpriv.adoc:3073-3102` — Sections 3–6 are empty.
- `ace-ISA-unpriv.adoc:3406-3426` — generic export still processes `Content1` and any nonzero ADS.

**Issue:**

The generic export algorithm has no Error-State branch. It computes Section 3 and may compute Sections 4–6 whenever `_AddDataLen != 0`, contradicting the authoritative 32-byte format.

**Proposed resolution:**

Prepend to SCC generation:

```text
if saved_MDH.State is an Error State:
    AD[0] = normalize_error_MDH(saved_MDH)
    (SIV, empty) = SCC_Encrypt(AD, zeros(96), 0, empty, CSK, 1, 0)
    emit normalized MDH || SIV
    return
```

Define whether `_AddDataLen_` is authenticated as its old value or normalized to zero; whichever is chosen must be identical on export and import.

---

NOT AN ISSUE
### **M12 — DIEL and SCA protection levels are not testable architectural properties**

**Severity rationale:** Software cannot know what protection it is selecting, and implementations can claim compliance with materially different timing or fault behavior.

**Locations:**

- `ace-ISA-unpriv.adoc:450-469`.
- `ace-ISA-unpriv.adoc:299-300`.
- `ace-ISA-unpriv.adoc:3485-3504`.

**Issue:**

Terms including “Data-independent execution latency”, “first-order SCA protection”, and “fault-tolerant implementation” lack normative definitions. It is unclear:

- which values are secret,
- which timing observations are covered,
- whether cache, arbitration, stalls, interrupts, and shared-unit contention count,
- which leakage model “first-order” uses,
- what faults must be detected,
- and what post-fault state is required.

DIEL need not make total latency independent of the public operand length or number of processed blocks. Rather, for fixed public dimensions, each block-processing iteration and final authentication decision should have latency independent of the values processed. The abstract `tmp != SIV` in SCC import is therefore not a separate defect if DIEL is defined to cover the complete authentication operation; changing a supplied SIV also changes CTR decryption and the recomputed tag, so a byte-at-a-time tag-recovery oracle cannot be inferred merely from the comparison notation.

**Proposed resolution:**

Define each level in terms of explicit threat and observation models. At minimum:

> For a fixed instruction, Algorithm, public metadata, operand length, privilege state, and architecturally visible configuration, completion latency and interruption points must be independent of key material, plaintext, ciphertext, authentication tags, intermediate values, and random masks.

Specify whether platform contention is excluded. Reference an established SCA/fault standard only if the task group intends to require it; otherwise describe the exact architectural guarantee without claiming a standard protection class.

---

FIXED
### **m1 — `ace.mv` encoding prose names `rs2` as a destination**

**Severity rationale:** The encoding diagram and variant table are recoverable, but the prose can cause assembler or decoder mistakes.

**Location:** `ace-ISA-unpriv.adoc:1648-1649`.

**Issue:** Forms C/D state that `rs2` specifies the destination, while the destination is in `rd`; `rs2` carries the sub-opcode.

**Resolution:**

Replace with:

> In CR-to-register variants, `rd` specifies the destination GPR or vector register; `rs2` contains the `ace.mv` sub-opcode.

---

RENAMED
### **m3 — `ace.reset` is named as a full ACE reset but has narrower effects**

**Severity rationale:** Primarily terminology and software-expectation risk.

**Locations:** `ace-ISA-unpriv.adoc:2723-2748`, `2805-2817`.

**Issue:** The synopsis says it clears “the ACE state”, but it does not clear identification CSRs, CSK, Localities, or management scratch.

**Resolution:** Rename it, for example `ace.reset`, or explicitly say:

> `ace.reset` is not an ACE-unit reset. It affects only the unprivileged state listed below.

---
FIXED
### **m2 — `ace.getmd` behavior on an unconfigured CR is not explicit**

**Severity rationale:** Implementations may return zero, stale metadata, or trap differently.

**Locations:**

- `ace-ISA-unpriv.adoc:529` — State 0 denotes unconfigured.
- `ace-ISA-unpriv.adoc:2060-2122` — no unconfigured case.
- `ace-ISA-unpriv.adoc:2600` — `ace.size` explicitly handles unconfigured CRs.
- `ace-ISA-unpriv.adoc:2770-2782` — `ace.getst` relies on `ace.getmdl`.

**Resolution:**

> `ace.getmdl`, `ace.getmd`, and `ace.getmdv` on an unconfigured CR return an all-zero MDH and do not expose any previous occupant of released CRF storage.

---

FIXED
### **m5 — The `vstart`-style nested-use obligation for `acestart` should be explicit**

**Severity rationale:** This is a clarification and software-integration issue, not an architectural ownership defect. The expected RISC-V convention supplies a workable rule, but stating it explicitly would prevent handler mistakes.

**Locations:**

- `ace-ISA-unpriv.adoc:1136-1188` — `acestart` progress and save/restore behavior.
- `ace-ISA-unpriv.adoc:2900-2937` — interruption and resumption.

**Issue:**

`acestart` can follow the same model as `vstart`: privileged software saves the interrupted value, establishes the value needed by any nested ACE use, and restores the saved value before resuming the interrupted instruction. No hardware owner tag is required. Interrupted import/export payload misuse is additionally detected by SCC authentication with overwhelming probability.

The specification says software may save and restore `acestart`, but does not directly state the nested-handler obligation. For non-management operations such as `ace.exec` and `ace.derive`, an incorrect restore need not cause a later SCC authentication failure—the resulting state may subsequently be exported with a new valid tag—so the rule remains useful as a correctness requirement.

**Proposed resolution:**

> Trap handlers that execute an ACE instruction while another ACE instruction is precisely halted must save `acestart` before the nested ACE use and restore it before resuming the interrupted instruction, following the same software convention as `vstart`. A handler starting a distinct nested ACE operation must first establish the `acestart` value required by that operation, normally zero.

---

DONE
### **m4 — Incorrect and stale cross-reference descriptions**

**Severity rationale:** Lower-risk navigational defect, but harmful in a specification whose semantics are distributed across sections.

**Examples:**

- `ace-ISA-unpriv.adoc:291` says `ace.mgmt` is described by `<<ACE-instruction-setst>>` rather than `<<ACE-instruction-manage>>`.
- `ace-ISA-unpriv.adoc:1626` indexes `ace.mv` as `ace.exec`.
- `ace-ISA-unpriv.adoc:2071-2072` index labels for `ace.getmd`/`ace.getmdv` are reversed or stale.
- `ace-ISA-unpriv.adoc:3197-3200` says management semantics are detailed in code snippets outside the reviewed chapter, making this chapter’s completeness unclear.

**Resolution:** Run an anchor and semantic-link audit and require every normative instruction to have one authoritative section.
