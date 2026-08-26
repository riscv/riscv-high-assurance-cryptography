# Adversarial Technical Review — ACE (Atomic Cryptography / Cryptographic Lockers) Extension Specification

**Reviewer context.** This review was produced under the prompt in `src/prompt.txt`: a rigorous, adversarial technical review of the draft RISC-V ISA extension contained in `ace.adoc` (rev. 0.7.0) and its included `ace-*.adoc` files. The "Considering an interruptible ace.mgmt" appendix in `ace-ISA-unpriv.adoc` was excluded from scope per the prompt.

---

## 1. Executive Assessment

**Not ready for candidacy as a RISC-V ISA extension.**

The proposal is internally substantial and contains several sound ideas (atomic cryptographic operations, MDH-based usage control, Locality-bound SCCs, single-share key export for masked implementations). However, it is **not suitable** to advance as a candidate RISC-V extension in its current form. The defects below include:

- Multiple **critical** architectural defects likely to break interoperability, cause information leakage, allow infinite loops or livelocks, or silently violate the document's own security goals;
- Numerous **major** defects affecting correctness, completeness, and implementability;
- Several normative gaps of architectural magnitude (cause-code values, CSR addresses, `misa.L` bit, `mstatus[26:25]` allocation, exception priority order, RVWMO integration) that are explicitly **TBD/unresolved** in the body of the specification.

The document is internally inconsistent in places that are not editorial — e.g., it asserts property P on page X and the same property is violated on page Y. The threat model is plausible but the specification fails to enforce its own goals in several modes (GCM with Set IV, Ascon-AEAD128 with Set Nonce, ML-KEM.Decaps, KMAC NIK mode). I would classify this as a "well-developed research draft" rather than a candidate specification.

A candidate-stage extension should be **conditionally ready** only after every `C` defect and the major normative gaps are resolved and a second independent implementer has built and run the architectural test vectors across at least one symmetric, one ECC, and one PQC algorithm. I do not see how a competent reviewer could place the current revision on a fast-track to ratification.

---

## 2. Findings, ordered by severity

---

---

### C-3 — ML-KEM `_Decapsulate_` is modeled with a failure branch it cannot take, contradicting FIPS 203

Fixed

---


### C-8 — Exception codes, `misa.L`, `mstatus[26:25]` are **TBD/unallocated**, blocking every conforming implementation

All ok, it will be done at ratification.
---

### C-11 — `ace.size` returns `0` on Error States but `0` is also returned on unconfigured; software cannot disambiguate
needs more discussion beyond returning 32
---

### C-12 — Inconsistent state semantics for `_Failure_` (valid state 23) vs `_Invalid_` (Error State 25)

Fixed.

---

### M-1 — `ace.exec` indirect-CR access via `X0` documented as illegal "unless" but the special case is one place only

Fixed.

---

### M-2 — `ace.mv` RV32 register-pair semantics inconsistent with `ace.mgmt` RV32 register-pair semantics

Fixed: On RV32, `rs2` must be a multiple of 4; otherwise an illegal-instruction exception is raised."

---

### M-4 — Symmetric-state global constant table conflates per-algorithm state mnemonics

zzzzzz

---

### M-5 — `ace.exec` "expected" form vs substitute forms: illegality conditions not exhaustively listed

**Severity rationale.** Major — exception conditions are algorithm-dependent and not exhaustively listed.

For example, OCB `_Hash_Absorb_Last_Block_` expects Form B; if the caller issues Form A in that state, the spec is silent.

No, we do say it would be illegal.
---

### M-6 — `ace.exec` on a CR in an Error State has contradictory rules

(not really)
---

---

### M-10 — `acestart` clamp also breaks `ace.exec` multi-block progress

fixed.

---

### M-11 — `ace.derive` Form C with vector register, no ACEIOBUF available

**Severity rationale.** Major — silent failure.

**Location.** `ace-ISA-unpriv.adoc` L2949–2957.

**Issue.** "`ace.derive` to pipe output of an algorithm into another algorithm." A Form B `ace.exec` is replaced by an `ace.derive` followed by a Form D `ace.exec`. But `ace.derive` Form C requires V enabled (or ACEIOBUF available). On a `Zklio`-only system, Form C is replaced by Form A. But the replacement table at L2924 doesn't include `ace.derive`. So `ace.derive` Form C on `Zklio`-only is undefined.

**Proposed resolution.** Add Form C → Form A substitution rule for `ace.derive` to the table.

---

### M-12 — `_Hash_Verify_` state in CMAC, OCB, Ascon does not bound `ACELEN` against digest length

**Severity rationale.** Major — undefined-behavior input handling.

**Location.** `ace-ISA-algorithms.adoc` L1830–1835 (OCB), L1966 (CMAC), L2860 (Ascon).

**Issue.** All three use `Form C ace.setst #ace_state_hash_verify INPUT` to provide the comparison tag. The spec says nothing about what happens when `ACELEN` exceeds the tag length. GCM-SIV handles this correctly at L1499 ("If `ACELEN > 128, only the 128 least significant bits of `INPUT` are considered"). The other three algorithms' state machines do not.

**Proposed resolution.** Add the same clarification to OCB, CMAC, and Ascon `_Hash_Verify_` states.

---

### M-13 — ML-KEM `_Encapsulate_` SCA level not tied to MDH

**Proposed resolution.** State that `ML-KEM.Encaps` (and `.Decaps`) are executed at the SCA level declared in the MDH; if a stronger level is required, it must be requested via `ace.restricth` before the operation.

Isn';'t this obvious?

---

### M-14 — `_Locality_` field bit numbering inconsistent between MDH table and Locality table

**Severity rationale.** Major — pre-existing collapse of binding logic.

**Location.** `ace-ISA-unpriv.adoc` L793–818 vs L419–423.

**Issue.** The Locality table at L793–818 lists bit assignments in `Locality_` field bits [3:0], [5:4], [6], [7], [8], but the MDH table at L419 says `_Locality_` is bits [77:69] (9 bits) with reserved extension bits [79:78]. There is a 1-bit offset discrepancy: HW Binding bits [3:0] of `Locality_` correspond to bits [72:69] of the MDH; but SW Filter bits [8:6] of `Locality_` correspond to bits [77:75] — which collides with the reserved bits [79:78].

**Proposed resolution.** Reconcile the bit numbering. Show the explicit mapping from MDH bit position to Locality field bit position.

---

### M-15 — `_Algorithm_` table layout ambiguous for HMAC variants

**Severity rationale.** Major — encoding lookup ambiguity.

**Location.** `ace-ISA-algorithms.adoc` L19–100.

**Issue.** The table uses "two-rows-per-Mode-value" layouts such as `4/5` and `6/7` for HMAC variants. The same `_Algorithm_` field value uses different `_Type_` for NIK and KIP, but the table presentation makes precise lookup error-prone.

**Proposed resolution.** Replace the "two-rows-per-mode" layout with a single, explicit table of `_Algorithm_` field values.

---

### M-16 — `_UsagePolicy_` mixes "deny by default" (bits 0–3) with "allow by default" (bit 4)

**Severity rationale.** Major — confusing security policy.

**Location.** `ace-ISA-unpriv.adoc` L418; L2329.

**Issue.** Bits 0–3 of `_UsagePolicy_` disallow CC usage in U/VS/HS/M-mode. Bit 4 grants use in Debug mode. Naming bits 0–3 as "disallow in mode X" and bit 4 as "grant in Debug" means the field has two semantics. `ace.restricth` (L2329) further inverts bit 4 from "grant" to "deny" depending on direction.

**Proposed resolution.** Split into two fields, or use a single semantic (always "deny in mode X" with bit 4 renamed to "Debug-deny").

---

### M-17 — `ace.store` illegal when `_ConfigStatus_ = ace_cfgst_complete`

**Severity rationale.** Major — workaround burden on software.

**Location.** `ace-ISA-unpriv.adoc` L1553–1559.

**Issue.** "`ace.store` … If the `_ConfigStatus_` field is equal to `ace_cfgst_complete`, then an illegal-instruction exception is raised." An implementation that forgets the `ace.mgmt` transition first loses the CR.

**Proposed resolution.** Document the required sequence (1) `ace.getmd`/`ace.getmdv`, (2) `ace.mgmt` #`ace_CR_export_start`, (3) `ace.store` normatively, and state that other orderings raise an illegal-instruction exception.

---

### M-18 — `*lcrstatus` direct writes can downgrade recorded state against actual state

**Severity rationale.** Major — soft-state inconsistency.

**Location.** `ace-ISA-priv.adoc` L247, L263, L283.

**Issue.** "Any direct write to `mlcrstatus(i)` does not change either `slcrstatus(i)` or `vslcrstatus(i)` (if defined)." So software can write `mlcrstatus(i) = Clean` even if the actual state is Dirty.

**Proposed resolution.** Forbid direct writes that downgrade, or read `*lcrstatus` as the union of "soft" (software-written) and "hard" (actual). At minimum, add a NOTE warning that direct writes can desynchronize recorded state from actual state.

---

### M-19 — `misa.L` clear behavior on systems with emulated ACE

OOOOOOk

---

### M-20 — `mstatus.ACES` / `vsstatus.ACES` inconsistent-state semantics

**Severity rationale.** Major — inconsistent state.

**Location.** `ace-ISA-priv.adoc` L191–198, L201–203.

**Issue.** "Both `vsstatus.ACES` and `mstatus.ACES` are in effect." A direct write to `vsstatus.ACES` does not set `mstatus.ACES` to Dirty. A hypervisor that has saved VS state and now writes `vsstatus.ACES = Clean` directly can produce a one-bit window of stale state.

**Proposed resolution.** Define: "`vsstatus.ACES` is the union (or max) of the dirty bits of all VU/VS state, recorded by hardware. Software writes can only downgrade, not upgrade, and a downgrade is automatically reversed if the underlying state is Dirty."

---

### M-21 — Endianness restriction references an unspecified bit

**Severity rationale.** Major — interpretability of big-endian systems.

**Location.** `ace-notation.adoc` L10–14.

**Issue.** ACE has no architecture-level way to query the "effective data endianness." The spec is silent on which bit determines "effective data endianness" and whether ACE behavior is gated on `mstatus.MBE`/`hstatus.HBE`/`sstatus.SBE`.

**Proposed resolution.** Reference the specific bits explicitly.

---

### M-22 — `ace.exec` Form D substitution is not algorithm-aware

**Severity rationale.** Major — semantic drift between Form D and Form B/C/A.

**Location.** `ace-ISA-unpriv.adoc` L2897–2904.

**Issue.** "A Form D `ace.exec` can replace any of Forms A, B, or C." But for algorithms that expect a specific Form in a given state (e.g., CTR `_Operate_` expects Form C to produce a keystream), Form D does no useful work. The substitution must be **algorithm-aware**.

**Proposed resolution.** Specify substitution rules per algorithm state, not as a global rule.

---

### M-23 — Per-state legality of `ace.exec` Forms not exhaustively listed

**Severity rationale.** Major — implementation choices.

**Location.** All algorithm sections; e.g., `ace-ISA-algorithms.adoc` L327–339 (ECB).

**Issue.** ECB says: "In State _Encrypt_ or _Decrypt_, Form A `ace.exec` instructions can be issued." Form B, C, D in this state are presumably illegal but the spec doesn't explicitly say so.

**Proposed resolution.** State explicitly per state: "In States _Encrypt_/_Decrypt_, the only legal Forms of `ace.exec` are Form A. Forms B, C raise an illegal-instruction exception (Form D may replace Form A if ACEIOBUF is used)."

---

### M-24 — Multi-block `ace.exec` does not define behavior when `ACELEN` is not a multiple of `b`

**Severity rationale.** Major — input size restrictions.

**Location.** `ace-ISA-algorithms.adoc` L334–339 (ECB).

**Issue.** The example loop iterates `foreach(i from 0 to ACELEN-b by b)`, but the loop bound is unclear when `ACELEN` is not a multiple of `b`. With `ACELEN = 144` and `b = 128`, one full block + 16 bytes remain.

**Proposed resolution.** State that the last (possibly partial) block is processed by the algorithm's `_Enc_Last_Block_` state, or that the last partial block is dropped if no such state is defined.

---

### M-25 — HMAC NIK variant: empty Provisioning Input but length rule says PI length depends on `KeyType`

**Severity rationale.** Major — porting consistency.

**Location.** `ace-ISA-algorithms.adoc` L2260–2268, L3124–3130.

**Issue.** NIK variant has only the MDH (128 bits) as PI, with `KeyType = 0`. But the PI length rule says PI length depends on `_Algorithm_`, `_AlgorithmPolicy_`, `_KeyType`. A NIK variant with `KeyType = 0` and no key field: where does the implementation know the key will be supplied later?

**Proposed resolution.** Add: "For NIK HMAC variants, the PI contains only the MDH. The Serialized Context contains the key field (to be loaded via `Set_Key`)."

---

### M-26 — `ace.clone` propagates `_StateExtension_` flags (incl. `HasPrivKey`) without policy restriction

This is not a problem.

---

### M-27 — `ace.store` order of LSU stores is implementation-dependent but conflicts with prefix-completeness

**Severity rationale.** Major — portability hazard.

**Location.** `ace-ISA-unpriv.adoc` L1556–1561; L914–917; L3061–3077.

**Issue.** The prefix-completeness invariant relies on the source (a CR in `ace_cfgst_exporting`) being immutable between interruption and resumption. In trap-and-emulate implementations, the firmware must not modify the source; this requirement is not stated.

**Proposed resolution.** Add: "In trap-and-emulate implementations, the firmware must not modify the source of `ace.store`/`ace.load`/`ace.input`/`ace.output` between interruption and resumption."

---

### M-28 — `Zkl` conformance dependencies undocumented for `Zklascon` and PQC

**Severity rationale.** Major — discoverability.

**Location.** `ace-ISA-unpriv.adoc` L141–146, L150.

**Issue.** "`Zkl` conformance requires at least one of `Zklv`/`Zklio`, `Zklkn`, and `Zklmem`." But `Zklkn` depends on AES-256, AES-128, SHA-2, GCM, XEX, GCM-SIV. An implementation that only has SM4 cannot claim `Zkl` conformance.

**Proposed resolution.** Either redefine `Zkl` to require only `Zklv` or `Zklio` and a single algorithm, or document explicitly that `Zkl` requires `Zklkn` and all its dependencies.

---

### M-29 — AES-256 in `Zklkn`: questionable security default

It's a standard. ENd of story.

---

### M-30 — `ace.setst` to a same-state transition: allowed or not, algorithm-dependent

**Severity rationale.** Major — unstated exception.

**Location.** `ace-ISA-unpriv.adoc` L1851–1852; `ace-ISA-algorithms.adoc` L840.

**Issue.** The architecture-level rule says "It is allowed to issue `ace.setst` instructions to the current state" (L1851). But `process_VLI` says "Transitioning to the same State `_Current_State_` is not allowed" (L840). `process_VLI` violates the architecture-level rule.

**Proposed resolution.** Either add an exception to the architecture-level rule for `process_VLI`-managed states, or update `process_VLI` to allow re-entry.

---

### M-31 — Ascon `pad(x,r)` formula needs verification against NIST SP 800-232

**Severity rationale.** Major — algorithm correctness.

**Location.** `ace-ISA-algorithms.adoc` L2662.

**Issue.** `pad(x,r)` is defined as "`0^j^ @ 1 @ x`" where `j = (-|x|-1) mod r`. Spot checks at `|x| ∈ {0, 3, 127}` with `r = 128` agree with NIST SP 800-232 (cite:[nist-SP-800-232]) AEAD padding; but the derivation of the formula is not given. Also: the spec does not state whether the padding is applied to the value as a bit string or as an integer; the spec's formulation implies the former, but a derived-via-arithmetic reader could misinterpret it.

**Proposed resolution.** Add a worked example and cite NIST SP 800-232 §4 explicitly.

---

### M-32 — `_UsagePolicy_[4]` semantics flip between "grant Debug" and "deny Debug"

**Severity rationale.** Major — confusing security policy.

**Location.** `ace-ISA-unpriv.adoc` L2329.

**Issue.** "For bit 4, which _grants_ use in Debug when set, the corresponding bit of `MDH._UsagePolicy_` is instead cleared to 0, withdrawing that grant." A one-shot "Debug-allowed" flag combined with mode-deny flags is confusing.

**Proposed resolution.** Unify: bit 4 always means "Debug-deny" (consistent with bits 0–3).

---

### M-33 — `acemaxiobuflen` XLEN-bit width at XLEN=128

**Severity rationale.** Minor — encoding inconsistency.

**Location.** `ace-ISA-unpriv.adoc` L1133–1151.

**Issue.** "`acemaxiobuflen` is an XLEN-bit RO CSR." For XLEN = 128, max is 2^128 bytes — fine; for XLEN = 32, max is 4 GiB — also fine. But the spec doesn't address this.

**Proposed resolution.** Note: "The maximum configurable ACEIOBUF length is constrained by XLEN."

---

### M-34 — `ace.io.derive` Form C / Form B dispatch ambiguity

**Severity rationale.** Major — interoperability impact.

**Location.** `ace-ISA-unpriv.adoc` L2469–2533; encoding at L2476–2503.

**Issue.** The encoding uses bits [29:28] as Form, but bit 27 is part of the `R` field for `ace.clone`. The same `func2` (2) is used. A decoder that doesn't share state between `ace.clone` and `ace.derive` may mis-classify instructions. More importantly, Form C (`ace.derive Kd|K{Xd}, Ks1|K{Xs1}, Vs2`) requires V to be enabled (L2923); on a non-V hart, this is reserved/illegal. But the spec uses the same Form C encoding on a `Zklio`-only system where Vs is replaced by ACEIOBUF; whether the bit is reserved (illegal) or interpreted as "ACEIOBUF form" is not specified.

**Proposed resolution.** Make the Form-C-with-ACEIOBUF substitution explicit in §"Rules for ace.input and ace.output to Replace Vector Inputs and Outputs," identifying the bit pattern as Form A under the substitution.

---

### M-35 — `acemvendorid`, `acemarchid`, `acemimpid` for emulated ACE

**Severity rationale.** Minor — portability.

**Location.** `ace-ISA-priv.adoc` L107–110; `ace-ISA-unpriv.adoc` L1108–1117.

**Issue.** For a trap-and-emulate implementation, the "ACE unit" is firmware, and the values can be anything the firmware chooses. The choice affects SCC interoperability (ML-KEM/ML-DSA progress tracking via ImpDataLen).

**Proposed resolution.** Specify: "`acemvendorid`, `acemarchid`, `acemimpid` are part of the ACE unit's IMPQUAL; values must be globally unique per implementation. For trap-and-emulate ACE, the firmware sets these to a unique value at boot."

---

### M-36 — `Zfbfmin`, `Zvfbfa` interactions not stated

**Severity rationale.** Minor — implicit requirement gaps.

**Location.** N/A (omission).

**Issue.** The spec mentions `[Zvbc]` (`vclmul.v[vx]`) for ACEV (`ace-ISA-unpriv.adoc` L351). But the spec does not require `[Zfbfmin]` or state which subset of vector instructions is required for which algorithm. For instance, `Galoismul` (GCM) requires carry-less multiplication.

**Proposed resolution.** For each algorithm that requires additional vector instructions, state the requirement explicitly.

---

### m-1 — `ocb_pad` defined only for `n` a multiple of 8

**Severity rationale.** Minor — clarity.

**Location.** `ace-ISA-algorithms.adoc` L1582–1593.

**Issue.** "`ocb_pad` is defined for `n` a multiple of 8 with `0 ≤ n ≤ 120`; for `n = 0` it is `zeros(120) @ 0b10000000`." The constant bit `0b10000000` for `n=0` corresponds to placing the terminating `1` bit at byte 0's MSB, but the position is then byte 0, bit 7 — confusing because the bit was described as "after `X[n-1:0]`."

**Proposed resolution.** Re-express with a clear example.

---

---

### m-3 — `WARL` acronym listed but not used; `WARZ` listed but not used

**Severity rationale.** Minor — completeness.

**Location.** `ace-acronyms.adoc` L75–76.

**Issue.** `WARL` is used once (L1166, L1204), `WARZ` is never used.

**Proposed resolution.** Remove `WARZ` or use it consistently where appropriate.

---

### m-4 — `cb` parameter of `lsb` / `msb` not used in body

**Severity rationale.** Minor — completeness.

**Location.** `ace-notation.adoc` L83, L89.

**Issue.** `lsb~c~(x)` and `msb~c~(x)` are defined but not referenced anywhere in Books 1–3.

**Proposed resolution.** Remove if unused or use in algorithms where applicable.

---

### m-5 — Ascon "encapsk" field name inconsistency

**Severity rationale.** Minor — terminology.

**Location.** `ace-ISA-algorithms.adoc` L3699–3700.

**Issue.** ML-KEM mentions "`decapsk`: 13056/19200/25344 bits … Note that `decapsk` contains `encapsk`." But "encapsk" is a `decapsk` field; the encapsulation key is held in the decapsulation key. Use of `encapsk` as a separate state field elsewhere is inconsistent.

**Proposed resolution.** Unify terminology: state explicitly whether `encapsk` is a separate field or derived.

---

### m-6 — `provisional and contested` warnings on critical resource allocations

**Severity rationale.** Minor — process.

**Location.** `ace-ISA-priv.adoc` L112–120, L133–142.

**Issue.** Multiple "WARNING" blocks mark `misa.L` and `mstatus[26:25]` as "provisional and contested." Until these are settled, no conformant implementation is possible.

**Proposed resolution.** Track as blocking issues, not warnings.

---


### m-10 — `ace.exec` failing in an algorithm-specific way leaves inconsistent state across implementations

**Severity rationale.** Minor — portability.

**Location.** All algorithms.

**Issue.** Each algorithm specifies which errors are "Error State _Invalid_" vs. other. Some algorithms specify "may return unpredictable results or fail with a transition to Error State _ace_state_failure_" (L3783-3786). "Unpredictable results" is not architectural behavior; it is an implementation-defined anti-pattern.

**Proposed resolution.** Replace all "may return unpredictable results" with specified error states.

---

### m-11 — `AESE256` notation: same algorithm referred to as `enc_blk` and `AESE256` in different sections

**Severity rationale.** Minor — consistency.

**Location.** `ace-ISA-algorithms.adoc` L310–311, L526–527 (enc_blk); L3329 (AESE256).

**Issue.** Some sections use `enc_blk(key, plaintext)`; the AEAD section uses `AESE256(K, B)` for the AES-GCM-SIV derivation. Two names for the same operation.

**Proposed resolution.** Unify: use `AESE(key, block)` consistently.

---

### m-12 — `*lcrstatus` direct writes do not change other `*lcrstatus` — but `*lcrstatus` interacts with ACES

**Severity rationale.** Minor — process.

**Location.** `ace-ISA-priv.adoc` L247, L263, L283.

**Issue.** Neal already covered this in M-18; this is a process recommendation. Add explicit warning.

---

## 3. Cross-Document Inconsistencies and Missing Requirements

1. **`acestart` clamp** (`ace-ISA-unpriv.adoc` L1255) vs CR-directed transfer needs (L1238–1252; `ace-introduction.adoc` L123–143). See C-1, M-10, M-36.

2. **`ace.mgmt` non-preemptibility** (L2964) vs large PQC SCC sizes (L2090) and the introduction's own admission (L116–121). See C-2.

3. **Error State naming**: `_ace_state_failure` (L3783) is a valid state (value 23, L520), but the spec uses it as if it were an Error State. ML-DSA at L3965–3966 mixes both. See C-12.

4. **Bit numbering for `_Locality_`** (L419 vs L793–818). See M-14.

5. **`_Algorithm_` field encoding** (L19–100): the "two-rows-per-mode" layout is ambiguous. See M-15.

6. **`ace.setst` same-state transition**: architecture allows it (L1851), `process_VLI` forbids it (L840). See M-30.

7. **`ace.size` semantics for Error States**: spec says SCC is 32 bytes for Error States (L3140), but `ace.size` doesn't say it returns 32 in this case (L2596–2611). See C-11.

8. **`mstatus.ACES` / `vsstatus.ACES` interactions**: not all combinations are well-defined. See M-20.

9. **`Zkl` conformance**: requires `Zklkn` which requires AES-256; not explicitly stated. See M-28.

10. **Cause codes (`mcause`) are TBD**: see C-8.

11. **`misa.L` allocation is contested**: see C-8, m-6.

12. **`mstatus[26:25]` (ACES) allocation is provisional**: see C-8, m-6.

13. **`ace.clear` privilege** (L2807–2809) vs `ace.clone` privilege (L745): inconsistent. See M-7.

14. **`ace.io.derive` Form C on `Zklio` only**: undefined. See M-11.

15. **`_Hash_Verify_` ACELEN bound**: defined for GCM-SIV, not for OCB/CMAC/Ascon. See M-12.

16. **Debug mode interaction on already-loaded CRs**: see M-9.

17. **HMAC NIK variant PI length rule conflict**: see M-25.

18. **`ace.clone` propagates `_StateExtension_` flags without restriction**: see M-26.

19. **ML-KEM `Decaps` failure semantics**: see C-3.

20. **OCB `index` off-by-one**: see C-6.

---

## 4. Standards-Compliance Matrix

| Requirement / standard | Spec location | Assessment | Evidence |
|---|---|---|---|
| RISC-V RVWMO axiomatic integration | `ace-ISA-unpriv.adoc` L931–936 | **Noncompliant (TBD)** | Explicit WARNING block. |
| RVI `misa` bit allocation | `ace-ISA-priv.adoc` L106–120 | **Noncompliant (TBD)** | Bit 11 contested; WARNING block. |
| RVI `mstatus` field allocation (ACES) | `ace-ISA-priv.adoc` L133–142 | **Noncompliant (TBD)** | Bits 26:25 contested; WARNING block. |
| RVI `mcause` cause-code allocation | `ace-ISA-priv.adoc` L46 | **Noncompliant (TBD)** | "The actual numbers are TBD." |
| RISC-V Endianness (mstatus.MBE / hstatus.HBE / sstatus.SBE) | `ace-notation.adoc` L10–14 | **Partially compliant** | Restriction stated but bit references absent. |
| RISC-V Privileged (custom CSRs) | `ace-ISA-priv.adoc` L75–96 | **Partially compliant** | Addresses `0xXXX` placeholders; field semantics documented. |
| FIPS 197 (AES) | `ace-ISA-algorithms.adoc` L310–311 | Compliant | `enc_blk` used consistently. |
| NIST SP 800-38A (ECB, CTR, CMAC, XTS) | `ace-ISA-algorithms.adoc` L270–351, L355–467, L1844–1970, L470–660 | **Noncompliant**: OCB3 deviation in `ocb_pad`/`double` re-mapping; `acb_set_aux_value` for CTR may break keystream-reuse discipline if the algorithm omits nonce reuse. The spec adds the rule but does not enforce nonce uniqueness. CTR-XTR with set initial counter can reuse keystream if Xs = start_ctr; spec notes this as caller's responsibility. |
| NIST SP 800-38B (CMAC) | `ace-ISA-algorithms.adoc` L1844–1970 | Compliant | Follows FIPS 800-38B §6. |
| NIST SP 800-38D (GCM) | `ace-ISA-algorithms.adoc` L844–1175 | Compliant | GHASH, J0, IV processing match. |
| NIST SP 800-38E (XTS) | `ace-ISA-algorithms.adoc` L470–660, L608–657 | Compliant | Two-key construction, ciphertext stealing. |
| RFC 8452 (AES-GCM-SIV) | `ace-ISA-algorithms.adoc` L1255–1506 | **Noncompliant**: nonce length not validated; POLYVAL and counter handling correct. |
| RFC 7253 (OCB3) | `ace-ISA-algorithms.adoc` L1510–1840 | **Noncompliant**: off-by-one in `index` check vs. MAX_BLOCKS; bit-order conventions require extra `bswap`. |
| NIST FIPS 180-4 (SHA-2) | `ace-ISA-algorithms.adoc` L2127–2210 | Compliant | Endianness via `bswap`. Section generated by Fable, marked "need to be double-checked" — must be re-verified. |
| NIST FIPS 202 (SHA-3, SHAKE) | `ace-ISA-algorithms.adoc` L2368–2481 | Compliant | `P()`, suffix-and-padding match. |
| NIST SP 800-185 (cSHAKE, KMAC) | `ace-ISA-algorithms.adoc` L2485–2604 | Compliant | `cshake_block`, `key_block`, `right_encode` correct. |
| NIST SP 800-232 (Ascon) | `ace-ISA-algorithms.adoc` L2606–3006 | **Noncompliant**: Ascon-AEAD128 with Nonce Masking does not enforce K1 ≠ K2. |
| NIST FIPS 203 (ML-KEM) | `ace-ISA-algorithms.adoc` L3645–3845 | **Noncompliant**: implicit rejection not modeled; "may return unpredictable results" allowed. |
| NIST FIPS 204 (ML-DSA) | `ace-ISA-algorithms.adoc` L3847–4076 | **Noncompliant**: `_mu_Input_` and `_tr_Input_` work correctly, but progress tracking is implementation-specific. Same "may return unpredictable results" anti-pattern. |
| GB/T 32905-2016 (SM3) | `ace-ISA-algorithms.adoc` L2213–2228 | Compliant | Same as SHA-256. |
| RFC 8032 (EdDSA) | `ace-ISA-algorithms.adoc` L3473–3640 | Compliant | Pure and pre-hash modes; both signing passes. |
| NIST FIPS 186-5 (ECDSA, Brainpool, SM2) | `ace-ISA-algorithms.adoc` L3129–3472 | Compliant | Retry rules specified. |
| RISC-V `Smcsrind` / `Sscsrind` | `ace-ISA-priv.adoc` L33–36 | TBD | "May depend (this must be decided together with the ARC)." |
| IEEE 1619 (XTS tweak) | `ace-ISA-algorithms.adoc` L608–657 | Compliant | Tweak mapping explicit. |

---

## 5. Suggested Prioritized Remediation Plan

### Phase 0 — Blockers (must be resolved before candidate stage)

1. **C-8** Resolve `misa.L`, `mstatus[26:25]` (ACES), and `mcause` allocations with ARC.
2. **C-9** Provide RVWMO axiomatic integration.
3. **C-1** Fix `acestart` clamp.
4. **C-2** Resolve `ace.mgmt` interruptibility (adopt the appendix's model or document the long-running guarantee).
5. **C-3** Fix ML-KEM `_Decapsulate_` to use implicit rejection.
6. **C-10** Fix SCC import length-vs-authentication ordering.

### Phase 1 — Critical algorithmic correctness

7. **C-4** Enforce 96-bit nonce in GCM-SIV.
8. **C-5** Enforce K1 ≠ K2 in Ascon Nonce-Masking.
9. **C-6** Fix OCB `index` overflow.
10. **C-7** Tighten `ExpirationDate` rule.
11. **C-11** Define `ace.size` for Error States.
12. **C-12** Standardize `_Failure_` vs `_Invalid_` semantics.

### Phase 2 — Major defects and completeness

13. **M-1** through **M-36** — Address each in priority order: state-machine corrections (M-5, M-12, M-22, M-23, M-30), privilege (M-7, M-18, M-19, M-20), debug (M-9), error handling (M-6, M-32), encoding (M-2, M-11, M-14, M-15, M-34), behavior (M-3, M-8, M-10, M-13, M-21, M-25, M-26, M-27), conformance (M-28, M-29).

### Phase 3 — Editorial and clarity

14. **m-1** through **m-12** — Minor editorial, acronym list, terminology consistency.

### Phase 4 — Validation

15. Re-verify SHA-2 and SM3 sections ("need to be double checked" warning).
16. Run cross-implementer test vectors on at least one symmetric algorithm (AES-GCM), one ECC algorithm (Ed25519), one PQC algorithm (ML-KEM-768).
17. RVWMO litmus tests for ACE memory instructions.
18. Confirm the `_Algorithm_` table is unambiguous.

---

## 6. Remaining Review Questions and Assumptions

**Questions that cannot be resolved from the supplied documents:**

1. What is the RVI-assigned `mcause` value (or base) for ACE exceptions? (TBD.)
2. Is bit 11 of `misa` allocated to ACE, or will ACE use the unified discovery mechanism?
3. Is the `mstatus[26:25]` (ACES) allocation accepted by ARC?
4. Will `mcause` allocation for ACE use a contiguous range, or a single cause with sub-cause registers (as the introduction's TODO suggests)?
5. Will the `_Algorithm_` field's HMAC two-row encoding (`4/5`, `6/7`) be replaced by a single explicit table?
6. Is the `mstatus.MBE`/`SBE`/`UBE` scheme adopted, or has it been replaced by something else in current RVI discussion?
7. Will the appendix §"Considering an interruptible ace.mgmt" be promoted into the normative spec?
8. Are RVI's decisions on `Smcsrind` / `Sscsrind` finalized for use by ACE?

**Assumptions made during this review:**

- The numbering in the outline references in `ace-introduction.adoc` (L96-159) reflects the intended location of items to be added.
- The "WARNING" and "KEEP?" blocks are placeholders to be resolved before ratification.
- Where the spec says "may" in error handling, the implementation is free to choose, and therefore the spec is non-deterministic at that point. This was treated as a defect unless explicitly called out as IMPDEF.
- The `_Algorithm_` two-row layout is interpreted as: the lower of the two `Type` values is the NIK variant, the higher is the KIP variant (per the introduction at L97-99).
- The "Considering an interruptible ace.mgmt" appendix was excluded from scope per the prompt instructions, so its content was not separately reviewed.

---

## Closing remark

The authors have built a thoughtful draft. The defects above are not a repudiation of the design — many are close to being fixable with localized edits. But **a security-critical ISA extension** that says "the actual numbers are TBD" on `mcause`, leaves RVWMO integration as a future warning, and contains an `acestart` clamp that is known to deadlock is not a candidate. I would recommend the authors (i) resolve every Phase-0 blocker, (ii) re-run the standards-compliance matrix after Phase 1, and (iii) submit a v0.8.0 draft for a second review before approaching the Architecture Review Committee for candidacy.
