# Zkl technical review

## 1. Executive assessment

**Not ready.** The shared-secret transfer rules give contradictory atomicity guarantees, and the context-save protocol can lose the owner of live authentication state. Derivation failure, allocation, progress, and exception-priority rules also need precise, interoperable outcomes. The assessment covers only the six specified files, with the Discussion Points exclusions applied; dependencies that require other chapters are recorded in Section 6. Source files were not changed.

## 2. Findings

### C1 - Shared-secret transfers are both uninterruptible and resumable

**Severity rationale:** Atomic insertion of a secret is a confidentiality boundary. A conflicting permission to expose intermediate destination states can undermine that boundary.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== Derivation Rules,” L2244–2246; “=== Interruptibility and Resumability of KLE instructions,” L2339–2340, L2362–2370; modules/ROOT/pages/Zkl-rules-explanation.adoc, “P13,” L230.

**Issue:** GR49 and GR63 make shared-secret insertion into a message input uninterruptible, but GR66 excludes only key-field destinations from resumable `kl.derive`. GR65 also assigns block-iterated derivations resumable options without this exception. An implementation following those permissions could expose a destination containing only a secret prefix between blocks.

**Evidence:** GR63 explicitly explains that no locker may hold part of a shared secret; GR66 grants the opposite execution model for its message destination. There is no normative precedence between these rules. Exploitability depends on the receiving Machine's permitted operations, which were not inspected; the contradictory architectural guarantee is itself established in scope.

**Resolution:** Add to GR65–GR67: “A derivation covered by GR63 commits no partial transfer at either endpoint. The resumable derivation rules apply only to other derivations.” Change GR66 to exclude both key-field destinations and shared-secret insertion into message inputs. Internal preemption may use GR69–GR72 only without exposing a partially transferred secret or weakening GR63's architectural outcome.

### C2 - Retargeting the named locker hides the authentication-register owner

**Severity rationale:** Following the documented save procedure can overwrite the only authentication state of an interrupted export. The resulting loss of the only restorable CC prevents safe context switching.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “== The Cryptographic Locker File and Authentication Information,” L251–259; “=== klnamedlocker,” L849–852; “=== Requirements on Management Operations,” L3388–3399; “=== Context Save Order,” L3515–3524; “=== Context Restore Order,” L3533–3539; modules/ROOT/pages/Zkl-rules-explanation.adoc, “== Vocabulary,” L39, and “D6,” L333–334.

**Issue:** Selection and authentication ownership are conflated. Suppose locker A is exporting. A handler saves the index and sets `klnamedlocker=32` to save the KLIOBUF, as prescribed. A nested trap during `kl.output` sees 32; its save routine can export locker B first, overwriting A's authentication registers. Restoring the saved selector later cannot recover those registers. SR11 tests only the currently selected locker, so it misses A.

**Evidence:** Authentication registers exist once per hart; changing the selector does not save them. GR68 serializes in-flight instructions, not the interval between instructions of a management operation. SR9 explicitly permits temporary retargeting, and the save/restore sequences require it. SR12's general coordination advice supplies no reentrant ownership protocol.

**Resolution:** Define a software authentication-owner record independent of `klnamedlocker`, accessible to all interposed handlers through a specified platform convention. It must identify the owner, or none, across every trap boundary, including temporary selection of 32, and track opening, completion, clear, rename/swap, and suspended management levels. Specify how record publication and those operations remain consistent if interrupted. Before another operation overwrites authentication registers, save the actual owner by a completed nested export; preserve that image and its resumption state, then clear the saved locker under SR14 before reusing the registers. Restore its image before resuming it. Clarify that SR13 prohibits unconditional discard-and-restart, not this completed save/clear/restore sequence. Rewrite SR11 and the save/restore algorithms to consult the record. The default save path should save and clear the owner first using Form D `kl.mgmt` and locker memory transfers, then save the KLIOBUF and other lockers; restoration should restore the KLIOBUF before restoring the owner last, using the same buffer-independent forms. Apply SR7/SR9/SR15 to the final selector and progress values. Temporary KLIOBUF transfers during ordinary management still require the ownership record. Describe `klnamedlocker` consistently as a selector.

### M1 - End-of-field validation conflicts with committed derivation prefixes

**Severity rationale:** The rules do not determine the two endpoints' architectural state after a rejected field transfer. Independent implementations can consume different source data or retain different destination contents.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== Derivation Rules,” L2220–2233, L2235–2238, L2259–2265; “=== Interruptibility and Resumability of KLE instructions,” L2366–2370.

**Issue:** GR52 commits units at both endpoints, but says a field failing validation when its transfer completes “is not written.” GR67 preserves earlier transferred blocks. For an admitted multiunit field whose final validation fails, the text does not say whether earlier writes and source consumption survive, are rolled back, or were merely staged. This is the generic case GR52 anticipates; no particular out-of-scope field is assumed to use it.

**Evidence:** GR45 separates initial checks from transferred-value checks, so initial validation alone does not resolve this case. An Error State may destroy the destination, whereas a Machine-defined failure outcome need not describe the other endpoint. The commented-out alternative GR52 is not operative.

**Resolution:** Define final validation against the committed field prefix plus the staged final unit and zero-filled tail, before committing that unit. On failure, do not consume or commit the current source unit; preserve earlier source effects, and apply the destination's specified failure outcome, with the candidate field unusable. Explicitly permit required destination zeroization to supersede preservation of its prefix. On success, commit the final unit, tail, and completion state together. For GR63 transfers, stage the entire transfer and commit neither endpoint before successful validation. Specify the absolute field offset on resumption as `klstart + unit_offset`; empty transfers perform no zero-filling or validation side effect.

### M2 - Random-key provisioning lacks a capacity transition

**Severity rationale:** An otherwise valid provisioning may require more storage at completion than was allocated at opening, without a specified allocation failure or recovery outcome.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== _KeyType_ Field,” L393–395; “=== Length of External Formats and KLF Capacity Usage of a Locker,” L2768–2769; “==== kl.mgmt opens a provisioning or an import,” L2857; “==== kl.mgmt completes a management operation,” L2920–2926.

**Issue:** Opening allocates according to `_KeyType_=1`, which may use only an external-key reference. The all-ones SKID instead generates a resident key and changes `_KeyType_` to 0 at completion. The completion algorithm specifies neither reservation of the larger allocation nor an attempted expansion and its failure semantics.

**Evidence:** The text explicitly permits different capacities for the two key types. “Room for every field” does not specify whether the opening's type-1 allocation includes the subsequent type-0 representation. This also affects emulated implementations and simultaneous occupation of other lockers.

**Resolution:** Before random generation at completion, reserve the full final type-0 capacity, allowing an implementation to have reserved it earlier. If reservation fails, raise KLE out-of-memory and leave the type-1 provisioning image, MDH, and allocation unchanged, apart from already specified `kl.mgmt` effects; provisioning remains open for retry or abandonment. Commit the new allocation and `_KeyType_=0` only with successful completion; release provisional reservations on failure. State that the capacity becomes fixed after this commit.

### M3 - A faulting attempt cannot always advance one granule

**Severity rationale:** The progress guarantee conflicts with required precise fault handling on ordinary invalid memory accesses.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== Memory Model Rules,” L2293–2295, L2309–2310; “=== Interruptibility and Resumability of KLE instructions,” L2358–2367; modules/ROOT/pages/Zkl-rules-explanation.adoc, “P13,” L223–234.

**Issue:** Option 3 requires advancement by at least one granule per attempt; option 4 inherits it. A page fault or access fault on the first byte must instead leave zero additional progress, and an unresolved fault can recur indefinitely. GR55 explicitly requires repeated rejection of a non-idempotent mapping.

**Evidence:** RVV 1.0, §17.1, requires eventual forward progress, not positive progress on every faulting attempt. The draft itself requires that the failing unit have no effect. No hardware policy can resolve a permanently invalid software address by advancing the instruction.

**Resolution:** Qualify the progress guarantee: “A synchronous fault may halt with no additional progress. Eventual completion assumes that software resolves the fault and grants execution time. Once the instruction is otherwise executable and its required resources are available, the implementation must document and enforce a bound on consecutive zero-progress preemptions, after which at least one permitted unit completes before an asynchronous interruption.” Keep all committed prefixes and retain the exception-specific handling and bounded resource-wait rules. Apply the same qualification to P13.

### M4 - The self-derivation check has two incompatible scopes

**Severity rationale:** Operand legality and exception priority can differ between implementations for the same instruction and hart state.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== General Rules Governing Encoding and Arguments,” L897–899; “=== kl.derive,” L1725; “Illegal-Instruction Exceptions,” L2460–2463, L2469–2480.

**Issue:** The first exception group rejects equal locker indices, while the second separately rejects a `KLNL` operand resolving to the other locker. The first rule does not exclude the zero placeholder required for `KLNL`. Thus `kl.derive K0, KLNL, Xs2` has equal encoded fields even when the selected locker is K1; alternatively, equality of resolved indices duplicates the second group's test at a different priority.

**Evidence:** GR3 distinguishes the encoded zero placeholder from the selected locker. The two exception groups straddle fatal, missing-CSK, and locker-Off handling. This concerns operand interpretation and priority, not the cause-code allocation excluded by A4.

**Resolution:** Specify that the first-group equality test applies only when `R=00`, comparing the two direct locker indices. When `R=01` or `R=10`, resolve `KLNL` as GR8 prescribes and test equality after fatal, missing-CSK, and locker-Off checks, but before the conditions on either locker's State; add that position explicitly to the evaluation-order rule. Never compare a `KLNL` placeholder as a direct K0 operand. With no named locker, this test does not fire and the existing no-op rule remains applicable.

### m1 - Handler summaries undo the prescribed retirement outcome

**Severity rationale:** The normative rules take precedence, but contradictory implementation guidance can cause incorrect handler code.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== Requirements on `klstart`,” L3376–3377; “=== Requirements on Exception Handlers,” L3413–3417; “=== Duties of Every Exception Handler,” L3481–3486; “=== Handling a KLE Exception,” L3565–3568.

**Issue:** The summaries unconditionally restore saved `klstart`/`vstart` and zero the entire usage output. SR7 and SR15 instead require retirement effects when skipping an instruction and preservation of its committed output prefix.

**Evidence:** L3444 explicitly gives the SR rules precedence; this limits the defect to guidance, without making the contradictory summaries safe to follow.

**Resolution:** Split handler exit into resume and skip cases. Resume restores the saved progress; skip applies SR15's retirement effects and zeroes only the unwritten output window. Replace “zeroes the output” with an explicit reference to that suffix.

### m2 - Management claims confidentiality for plaintext metadata

**Severity rationale:** This overstates the security contract, although the actual wire format is clear.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== Fundamental Concepts and Definitions,” L51; “== Management of Cryptographic Contexts,” L2632; “=== Formats of PIs, SCCs, and Partially Configured Cryptographic Contexts,” L2711.

**Issue:** L2632 promises confidentiality and integrity of both MDH and Content. The MDH is exported in clear and is defined to need integrity, with stated exceptions for hints.

**Evidence:** The SCC table makes the MDH a separate plaintext section; `kl.getmd*` also exposes it by design.

**Resolution:** Replace the claim with: “Management preserves the integrity of authenticated MDH fields and the confidentiality and integrity of secret Content, subject to the explicitly defined PI, PCCC, Error-State, and ADS behaviors.” Do not encrypt the MDH to satisfy the mistaken sentence.

### m3 - SP 800-140F is cited as supplying test metrics it does not specify

**Severity rationale:** The reference can mislead readers assessing the advertised side-channel levels; no numerical testing threshold is currently imposed by this draft.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== _SCProtection_ Field,” L378–385.

**Issue:** The phrase “such as the test metrics of NIST SP 800-140F” suggests that this publication supplies acquisition-time or trace-count metrics for the preceding examples.

**Evidence:** [NIST SP 800-140F, March 2020](https://doi.org/10.6028/NIST.SP.800-140F), §§5 and 6.2, replaces the relevant ISO provisions but states “No additional requirements at this time.” The NIST publication page identifies that final edition. FIPS 140-3's adoption of the older ISO editions is correctly stated.

**Resolution:** Identify the edition and its actual role: “FIPS 140-3 uses CMVP modifications, including SP 800-140F (March 2020), whose §6.2 specifies no additional test-metric requirements.” Attribute any numerical metrics to a separately verified edition, clause, and assessment profile; retain the distinction between test effort and attack resistance.

### m4 - The strict memory-prefix rule is incorrectly attributed to RVV

**Severity rationale:** The stronger KLE rule is implementable, but its standards rationale invites an incompatible implementation shortcut.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== Memory Model Rules,” L2297–2300; “=== Interruptibility and Resumability of KLE instructions,” L2363.

**Issue:** GR65 says RVV §3.7 prescribes halting at KLE's last prefix-complete point. KLE forbids any visible effect at or beyond that point and forbids replay of committed accesses; RVV's precise-trap model permits some such effects in idempotent memory.

**Evidence:** RVV 1.0, §§3.7 and 17.1, distinguishes the restart index from the stronger no-effects-beyond-prefix property. Section 17.1 explicitly permits later idempotent stores if re-execution produces the correct result. KLE's decomposition permission remains constrained by its own stricter semantics.

**Resolution:** Say that KLE uses a restart cursor analogous to `vstart`, but imposes the stronger GR57 guarantee. Explain that sub-16-byte or out-of-order component accesses must still support a legal 16-byte locker-transfer halt: permission prevalidation and commitment scheduling must prevent a reported precise fault from leaving a visible partial granule or visible accesses beyond the recorded prefix. The entire 16-byte transfer need not become globally visible atomically.

### m5 - The clone description retains removed GPR-indirect operands

**Severity rationale:** A stale operand description contradicts the current encoding and can mislead assembly or emulator authors.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== General Rules Governing Encoding and Arguments,” L897–899; “=== kl.clone, kl.rename, and kl.swap,” L1656.

**Issue:** The description offers lockers indexed by `Xs` and `Xd`, although the encoding fields now select only direct locker operands or `KLNL`.

**Evidence:** GR3 reserves other nonzero `R` values and defines `KLNL` selection through `klnamedlocker`; this is unrelated to A1's provisional opcode allocation.

**Resolution:** Replace both parentheticals with “or the locker selected by `KLNL`, where that operand uses the GR3 encoding.” Use resolved source/destination indices throughout the three instruction descriptions.

### m6 - Authentication does not prove that every transfer instruction ran

**Severity rationale:** The note gives software an incorrect diagnostic guarantee about incomplete transfers.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, “=== Generation of an SCC from a Fully Configured Locker,” L3223–3224; “==== kl.mgmt opens a provisioning or an import,” L2838.

**Issue:** Premature export/import completion is said always to cause authentication failure. Omitted export bytes may already contain the correct image; an omitted import block may equal its initialized all-zero value. Authentication then sees the correct byte string and can succeed without forgery.

**Evidence:** No transfer-coverage bitmap is specified, and opening initializes unwritten imported bytes to zero. Authentication validates the resulting bytes, not their transfer history.

**Resolution:** State that incomplete transfers can yield invalid images and authentication failure, but completion is established by the software transfer count and outcome checks, not by authentication alone. Preserve acceptance of any correctly authenticated image; do not add a coverage bitmap solely to enforce the note.

### m7 - Truncating conversion is called an unrestricted inverse

**Severity rationale:** This is a mathematical precision defect in normative notation, with a straightforward correction.

**Location:** modules/ROOT/pages/Zkl-notation.adoc, “== Functions,” L71, L76.

**Issue:** `bin(n,m)` may truncate an unsigned integer, yet is called the inverse of `int` without a range qualification.

**Evidence:** For example, `int(bin(256,8))=0`, not 256. Only the width-constrained mapping is bijective.

**Resolution:** Replace the inverse claim with: “For an `m`-bit value `V`, `bin(int(V),m)=V`; for an unsigned integer `n`, `int(bin(n,m))=n mod 2**m`.” Keep the specified truncation semantics.

### m8 - Acronyms source has grammar errors

**Severity rationale:** These errors occur in a source comment and do not affect architectural semantics.

**Location:** modules/ROOT/pages/Zkl-acronyms.adoc, pre-table reviewer comment, L10–11.

**Issue:** L10: “can stay for” → “can stand for”; L11: “all other RISC-V cryptography extension” → “all other RISC-V cryptography extensions.”

**Evidence:** The idiom is “stand for,” and “all other” requires the plural count noun here. The comment's reviewer directions were not treated as review instructions.

**Resolution:** Apply the two replacements.

### m9 - Notation has spelling and grammatical labeling errors

**Severity rationale:** These are editorial defects with no change to byte representation.

**Location:** modules/ROOT/pages/Zkl-notation.adoc, “== Endianness,” L18, L25.

**Issue:** L18: “endianess” → “endianness”; L25: “Software Developers note:” → “Note to software developers:”.

**Evidence:** The first is a misspelling; the second avoids the missing possessive and unnecessary capitalization.

**Resolution:** Apply the two replacements.

### m10 - Symbols comment miscapitalizes Unicode

**Severity rationale:** This is a minor source-comment error.

**Location:** modules/ROOT/partials/Zkl-symbols.adoc, opening comment, L1.

**Issue:** “unicode characters” → “Unicode characters.”

**Evidence:** Unicode is the proper name.

**Resolution:** Capitalize “Unicode.”

## 3. Cross-document inconsistencies and missing requirements

- **C1:** GR65–GR67 conflict with GR49/GR63 and the rationale's all-or-nothing secret insertion.
- **C2:** Selection, authentication ownership, and the rationale's management model need a reentrant software contract.
- **M1:** A final rejected derivation lacks a consistent two-endpoint commit outcome.
- **M2:** Provisioning omits the capacity transition for the all-ones SKID.
- **M3:** The ISA and rationale need explicit fault and scheduling assumptions for progress.
- **M4:** Direct and resolved locker equality need disjoint priority rules.
- **m1:** Handler summaries disagree with SR7/SR15.
- **m2:** The management overview disagrees with the MDH protection and format definitions.
- **m5:** The clone description disagrees with the current operand convention.

All active, explicit cross-reference targets between the six files resolve; no duplicate active anchors were found. The root's in-scope includes resolve, and its symbol include agrees with the standalone pages. Commented-out definitions were not counted as normative targets.

## 4. Standards-compliance matrix

“Compliant” assesses the cited statement or convention, not certification of an implementation. “Not verified” identifies a bounded review limitation, not an established violation. U = `modules/ROOT/pages/Zkl-ISA-unpriv.adoc`; N = `modules/ROOT/pages/Zkl-notation.adoc`; A = `modules/ROOT/pages/Zkl-acronyms.adoc`.

| Requirement/standard | Location | Assessment | Evidence |
|---|---|---|---|
| RFC 8452 (April 2019), §4: AES-256 key derivation | N L100; U L3064–3074 | Compliant | Four little-endian counter bytes precede the nonce; the first eight bytes of each AES result supply the keys in the specified order. |
| RFC 8452, §3: POLYVAL representation and recurrence | N L126–128; U L3084–3104 | Compliant | Polynomial, bit coefficients, zero initialization, XOR, and multiplication by `x^-128` match. |
| RFC 8452, §§4–6: per-message length limits | U L1169, L3136–3144, L3161–3163 | Not verified | The RFC caps plaintext at `2^36` bytes. Whether every supported Machine bounds `Content1` accordingly requires the excluded Machine chapter; see Section 6. |
| RFC 8452 as a complete sealing construction | U L3049–3054, L3195–3205 | Not verified | The text expressly defines a variant. Full security equivalence is not asserted by this review; B1/B3 exclude the nonce choice and aggregate security claim. |
| SP 800-38D (November 2007), §7.1, Algorithm 4: 96-bit-IV `J0` | N L101–102 | Compliant | `bswap(bin(1,32)) @ IV` places `00 00 00 01` after the IV in the memory byte string. |
| SP 800-38D, §6.3: GHASH representation | N L123–125 | Compliant | Its first string bit represents the constant coefficient; relative to the draft's byte-to-value mapping, within-byte bit reflection is needed. Actual `Galoismul` is out of scope. |
| SP 800-38A (December 2001), Appendix B.1: CTR construction choice | N L116–122 | Compliant | The standard permits alternative incrementing functions preserving uniqueness; the draft labels its particular counter choice as KLE's. |
| SP 800-38B (May 2005, updated October 2016), §6.1: CMAC subkey shift | N L118, L122 | Compliant | The left-shift convention operates on the standard's most-significant-bit-first string. The Machine's `double` implementation was not followed. |
| FIPS 202 (August 2015), §§2.2, 3.1: SHAKE name and state mapping | A L85; N L134–137 | Compliant | SHAKE's listed expansion and the lane/string convention agree. This does not verify the excluded SHA-3 Machines. |
| SP 800-57 Part 1 Rev. 5 (May 2020), §§6.2.1.4, 6.2.1.6; SP 800-108 Rev. 1 Update 1 (August 2022), “Security Considerations” | U L2201 | Compliant | Associations, key separation, and context binding support the stated motivation; universal policy inheritance is explicitly a KLE choice. |
| FIPS 140-3 (March 2019), §§2–3: ISO adoption | U L382–383 | Compliant | The cited ISO/IEC 19790:2012 and 24759:2017 editions and CMVP modifications are correctly distinguished from later editions. |
| SP 800-140F (March 2020), §6.2: concrete test metrics | U L378–383 | Needs clarification | **m3**. The verified final publication supplies no additional test-metric requirements. |
| RVV 1.0, §3.7: `vstart` retirement and unsupported restart values | U L906–908 | Compliant | Reset on retirement and rejection of restart values an instruction cannot produce match the cited convention. |
| RVV 1.0, §17.1: eventual progress | U L2358–2367 | Needs clarification | **M3**. A faulting attempt may make no progress. |
| RVV 1.0, §§3.7, 17.1: precise-trap comparison | U L2299–2300, L2363 | Needs clarification | **m4**. KLE deliberately needs a stricter visible-prefix property. |
| Smstateen/Ssstateen v1.0.0, “State Enable Extensions,” published Privileged ISA release 20240411 | U L723–724 | Compliant | Denial selects illegal- or virtual-instruction behavior according to the denying gate and executing mode. Bit allocation remains excluded by A3. |
| Privileged ISA release 20240411, “Priority and Matching Logic” under PMP | U L1738–1747, L2297–2300 | Compliant | KLE may impose stronger fault-commit constraints than ordinary decomposed stores. Alignment to 16 bytes alone does not ensure permission for all component accesses; the strict KLE rules still apply. |
| RVWMO/RVTSO, fence and translation-order interactions | U L2289–2307 | Not verified | The draft incorporates these models, but no complete formal mapping of its component operations was checked; reference not verified. |
| RISC-V External Debug Security; RISC-V Platform Security Model | U L118, L364 | Not verified | Edition and applicable clauses cannot be established from the in-scope citation keys; reference not verified. |
| Zkr and SP 800-90A entropy/DRBG requirements | U L122, L2407–2412 | Not verified | Full entropy, health-test, and DRBG equivalence requirements were not verified; reference not verified. |
| ISO/IEC 19790:2025, 24759:2025, 17825:2024 | U L382–385 | Not verified | Full texts and assessment clauses were not inspected; reference not verified. No numeric acquisition limits or trace counts are endorsed here. |
| SP 800-38E/XTS, RFC 7253/OCB3, FIPS 180-4, SP 800-232, FIPS 203/204 | N L116–146 | Not verified | The referenced Machine definitions were not followed; the remaining convention claims were not independently checked against these standards. Reference not verified. |
| FIPS 197; IBM and Intel key-protection comparisons; Caliptra transport example | U L2628, L3058, L3582 | Not verified | The external implementations, AES mapping beyond the stated interface, and cited transport capability were not verified; reference not verified. |

## 5. Remediation plan

1. **C1** — Establish the atomic derivation boundary before changing transfer semantics.
2. **M1** — Define validation and commit outcomes within that boundary.
3. **C2** — Specify ownership and reentrant management, including nested faults and restore order.
4. **M2** — Define transactional capacity reservation; preserve the management outcomes established above.
5. **M4** — Make operand checks disjoint before validating combined fault cases.
6. **M3** — Qualify progress guarantees without weakening committed-prefix preservation.
7. **m4** — Align the RVV explanation with the corrected fault model.
8. **m1** — Update handler summaries after ownership and fault/retirement rules stabilize.
9. **m5** — Remove stale operand notation after the equality checks are settled.
10. **m2** — Correct the protection claim; independent of wire-format changes.
11. **m6** — Correct the transfer-completion note; retain bounded software counting.
12. **m3** — Correct the testing reference before publishing protection-profile claims.
13. **m7** — Clarify conversion domains; preserve all existing bit-level formulas.
14. **m8** — Apply the acronyms grammar corrections; independent.
15. **m9** — Apply the notation corrections after its mathematical edit.
16. **m10** — Correct the symbols comment; independent.

## 6. Open questions and assumptions

- **Scope:** The six named files were read in full. Only Discussion Points was read from the introduction. All live A1–A6 and B1–B3 items were excluded; commented proposals were not additional exclusions. The older filename in the consistency-pass instruction was treated as a carryover typo: the requested artifact is `review44.md`.
- **Machine dependencies:** Admitted endpoint tables, per-field validation, granularity, progress-state invalidation, random-material handling, and actual algorithm implementations are defined in `Zkl-ISA-machines.adoc`. They were not inspected. Consequently this review does not certify secret-to-MAC derivations, the earlier CMAC concern, or concrete Machine conformance.
- **Single-image sealing bound:** Does the Machine contract cap each sealed segment at `2^32` blocks and keep every image size representable by `kl.size`/`klstart` for each supported XLEN? If a segment can exceed that bound, counters at offsets `i` and `i+2^32` coincide in U L3138, exposing the XOR of their plaintext blocks. This is a conditional per-image concern, distinct from B3's aggregate bound; actual reachability cannot be determined without the excluded size definitions. Any eventual cap must be checked before allocation/crypto and must cover emulated and custom formats.
- **Privileged dependencies:** Detailed `*llockerstatus` transitions, CSK and Locality CSR access, reset differences, trap delegation, and reporting depend on `Zkl-ISA-priv.adoc`. The in-scope references establish dependencies, not their correctness. The illustrative management routines in `Zkl-pseudocode.adoc` were not followed.
- **Security profiles:** The complete secret-handling path and secure-clock properties are strong recommendations, not universally enforced ISA guarantees. Deployment assurance therefore depends on the documented, negotiated profile, including time error, recovery, physical leakage, fault injection, and CSK handling. No hardware or certification evidence was available; a safe profile was not assumed to cure any finding.
- **Resolved design boundary:** `_ADSDropped_` is explicitly a negative binding: authentication of the architected segment precedes clearing implementation-defined metadata and required restart. `kl.clearads` also clears those fields. This review does not assume that `IMPQUAL` alone authorizes their interpretation.
- **Build and publication dependencies:** `global-config.adoc`, bibliography records, release scripts, templates, and other includes are out of scope. No full documentation build was run because it would follow those files. Citation versions not independently identified above remain unverified.
