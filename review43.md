# 1. Executive assessment

**Not ready.** The generic derivation rules permit recovery of a protected shared secret through a caller-keyed MAC. Other defects undermine metadata interpretation, protection-level enforcement, and restart semantics. Several normative rules prescribe incompatible outcomes for the same instruction or context switch. The findings below exclude the numbered Discussion Points; unread dependencies and unverified standards are identified separately.

# 2. Findings

### C1 - A caller-keyed MAC can disclose a protected shared secret

**Severity rationale:** A permitted derivation sequence can recover an entire shared secret without compromising privileged software or breaking AES. This violates the architecture's no-extraction guarantee.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== Derivation Rules", L2196-2197, L2218-2220, L2233-2240; "=== Content Confidentiality", L1907-1913; modules/ROOT/pages/Zkl-rules-explanation.adoc, "== What the Principles do not determine", L439.

**Issue:** GR48 admits a shared-secret field as the message input of any MAC and permits release of its tag, asserting that a one-way function protects the secret. GR51 permits prefix truncation and repeated emission of a field. A caller allowed to use the source can provision a CMAC destination with a known key and compatible policies, derive successive prefixes into fresh MAC operations, and invert their tags. Assumption: a destination implements standard AES-CMAC with a full 128-bit tag; the generic architecture admits this case, independently of whether the unread Machine chapter currently instantiates it.

**Evidence:** NIST SP 800-38B (2005, updated 2016), §§6.1-6.2, gives, for full blocks, `T1 = AES_K(S1 xor K1)` and `T2 = AES_K(AES_K(S1) xor S2 xor K1)`. With known `K`, its subkey `K1` is known: `S1 = AES_K^-1(T1) xor K1`, then `S2 = AES_K^-1(T2) xor AES_K(S1) xor K1`. Two queries recover a 32-byte secret. This calculation was reproduced using OpenSSL CMAC and AES on synthetic data. Policy narrowing does not prevent it when the caller is authorized for both endpoints.

**Resolution:** Replace the generic MAC admission in GR48: "A shared-secret field may enter a message-input endpoint only when the architecture explicitly approves that endpoint as a one-way transformation under caller-controlled keys, parameters, prefix lengths, and repeated queries. MAC security alone does not establish this property. AES-CMAC message inputs are not admitted for restricted shared-secret transfers." Use an explicit allowlist for hash/XOF endpoints too; retain approved direct secret-to-key transfers and their narrowing. Update the rationale and add the two-query CMAC sequence as a negative conformance case.

### C2 - Discarding the ADS does not remove implementation-specific metadata semantics

**Severity rationale:** A valid authenticated SCC can be interpreted under a different implementation's meaning for the same MDH bits. The specified compatibility mechanism therefore fails to require preservation of cryptographic behavior.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== _MachineUse_ and _AuxInfo_ Fields", L593-600; "=== Content Confidentiality", L1918-1919; "==== kl.clearads", L1291-1297; "=== Decryption and Authentication of a Complete SCC into a Locker", L3226-3239; modules/ROOT/pages/Zkl-rules-explanation.adoc, "== Design Principles", L197-198.

**Issue:** Implementations may give unused `_MachineUse_` or `_AuxInfo_` bits private meanings, relying on ADS/IMPQUAL rather than a hardware Locality binding. Import discards a mismatched, unauthenticated, or explicitly dropped ADS and accepts `Content1`, but does not specify how these MDH bits are identified, translated, or cleared. `kl.clearads` also removes the purported qualifier without requiring normalization of those fields. Two implementations can assign incompatible meanings to the same authenticated value; a generic requirement to establish a "consistent internal state" does not identify the originating meaning.

**Evidence:** An attacker can set `_ADSDropped_` before import, bypassing second-segment processing without changing first-segment authentication. Even an empty `Content2` with `_AuxDataLen_ = 2` provides no compulsory interpretation check. GR67 resets long-running progress only; it does not define every permitted private use of `_AuxInfo_` or `_MachineUse_`.

**Resolution:** Define, for each Machine, masks identifying architected and implementation-only MDH bits. Require implementation-only bits to be optional cache/progress hints whose removal has a fully specified architected fallback; they must never alter policy, algorithm, or required parameters. For a resident Valid locker, `kl.clearads` must clear those bits and perform that fallback. For a Complete SCC, authenticate the received MDH before clearing implementation-only bits and applying fallback when the ADS is discarded. Opening an import, or saving/restoring an SCC-shaped PCCC, must retain the implementation-only MDH bits until base authentication. Preserve the existing management transitions of `_State_` and the working `_ADSDropped_` hint; reconstruct the authenticated State at base completion as already specified. A meaning that cannot survive this normalization must use a defined Machine encoding and its required binding, not implementation-only hints. Remove the claim that optional IMPQUAL alone binds MDH semantics.

### C3 - Selecting a protected Machine does not require a protected sealing path

**Severity rationale:** Leakage or fault compromise of the common sealing path can expose the keys of every protected locker. The draft allows this even when software selects its strongest protection level.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "== The Cryptographic Locker File and Authentication Information", L233-236; "=== _SCProtection_ Field", L374-385; "==== Single-Share Key Export Rule for Masked Implementations", L2754-2758.

**Issue:** Protection of `SCC_KeyDeriv`, sealing, unsealing, the CSK, and derived keys is only recommended. Meanwhile, every masked implementation reconstructs secrets for export and import. A conforming implementation can offer protected Machine operations but use an unprotected reconstruction or sealing path, allowing physical observations or injected faults during management to defeat the selected protection.

**Evidence:** L236 says "recommended", while L2754 mandates reconstructed values and L377-378 promises fault detection for Level C. Export is available regardless of UsagePolicy. This finding concerns the mandatory coverage of an advertised level, separately from the level definitions in M10.

**Resolution:** Require the complete path handling a locker's secrets—including reconstruction, re-sharing, KLF access, sealing, unsealing, and relevant CSK operations—to satisfy that locker's advertised protection profile. A shared sealing-key path must satisfy every protection profile it serves, using the strongest profile where the profiles form an ordered hierarchy. Reconstruction may be conceptual; it must not create an unprotected intermediate. An implementation unable to meet this requirement must not advertise the affected combination through `kl.avail` or accept it as supported Metadata.

### M1 - Resource exceptions after partial progress have incompatible state rules

**Severity rationale:** Independent implementations cannot agree on the state to resume after a late resource failure. Replaying completed cryptographic work can corrupt output or reuse state that was intended for one operation.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== State changes under exceptions", L2282-2287; "=== Interruptibility and Resumability of KLEE instructions", L2293-2294, L2323-2328; "=== Randomness", L2367-2369; "=== Requirements on `klstart`", L3350; "=== Requirements on Exception Handlers", L3384-3390.

**Issue:** GR59 permits committed prefixes only for memory exceptions; other exceptions must leave KLEE state unchanged. GR70 allows an RBG-unavailable exception after waiting, including during an operation that has already completed earlier blocks. GR63-GR64 require those blocks to remain committed. A later resumption can similarly encounter an unreadable expiration clock. The draft does not reconcile the instruction-entry state, the latest resumption state, and the committed prefix. If a handler instead skips the instruction, SR7 still requires restoration of saved progress, which can make the next instruction skip data.

**Evidence:** For a block-iterated operation, let one block complete and a later block need unavailable random bits. Preserving the first block contradicts GR59's exhaustive exceptions; undoing it contradicts GR64 and may be impossible after output became visible. This is not the excluded question B3 about whether `kl.mgmt` should be interruptible.

**Resolution:** Define exception state relative to the latest committed prefix. For resumable instructions, every nonfatal execution-time exception must retain that prefix, set `klstart` and applicable `vstart` consistently, and discard all uncommitted work of the failing unit at both endpoints. Re-execution starts there. For uninterruptible instructions, preserve the existing all-or-nothing rule and explicitly listed management effects. Amend GR59 and the handler rule so skipped instructions preserve completed output and zero only the remaining output window. A skipping handler must then emulate the instruction’s specified retirement effects on progress CSRs; explicitly exempt this path from SR7’s restoration of retry progress. Pre-execution legality failures retain their existing no-change semantics.

### M2 - Derivation lacks a complete byte-offset and length contract

**Severity rationale:** Correct transfers can produce different results after interruption, and malformed transfers have unspecified outcomes. This prevents interoperable implementations of the generic derivation interface.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== klstart", L806-822; "=== kl.derive", L1699-1707; "=== Derivation Rules", L2200-2207, L2233-2245.

**Issue:** The general transfer-window checks define only vector and KLIOBUF windows; `kl.derive` has neither. GR51 says a field source starts at its beginning on every `kl.derive`, while GR64 requires resumption after the committed prefix. It does not explicitly define the field offset on resumption, the result for an out-of-range `klstart`, the failure outcome for incompatible granularities, or handling of a requested suffix shorter than a source block when the source does not admit partial output. It also requires data-dependent destination constraints before transferring anything, without reconciling streaming validation and prefix commitment.

**Evidence:** Interrupt a field-to-stream transfer after its first granule. Restarting the field emission at byte zero duplicates the prefix; skipping it requires an unstated distinction between a new invocation and re-execution. Checking only the destination length does not establish that a stream source can supply the requested final unit.

**Resolution:** Specify a derivation window `[0, eff_length)` in bytes. After gates and endpoint/length checks, a key destination requires `klstart = 0`; otherwise invalidate the destination without transfer. For other destinations, `klstart >= eff_length` retires with `klstart = 0` and no endpoint or policy change; explicitly amend the zero-length rule to allow this CSR effect. An interior value must be an admitted common boundary. Resumption reads a field at offset `klstart`, while a stateful source continues from its committed state and supplies only the remaining suffix; a new invocation with zero progress starts the field at zero. Reject incompatible granularities by invalidating both endpoints, and unsupported partial source output by invalidating the source, before transfer. Separate preflight structural checks from per-unit data validation, which retains only the completed prefix under M1. Compute and validate narrowing before a nonempty transfer, but commit it atomically with the first transferred unit; a precommit resource exception must not leave a policy change behind. Key destinations remain uninterruptible.

### M3 - Restarting memory transfers at zero contradicts prefix completeness

**Severity rationale:** An allowed interrupt path violates the architectural definition of its saved progress. Replayed stores can also produce observations that a purportedly untouched suffix should not have produced.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== klstart", L799-802; "=== Memory Model Rules", L2261-2265; "=== Interruptibility and Resumability of KLEE instructions", L2293, L2313-2320; modules/ROOT/pages/Zkl-rules-explanation.adoc, "== Design Principles", L224-231.

**Issue:** The memory restart option permits resetting `klstart` to zero after partial work. GR55 requires that no access at or beyond the saved offset have any architecturally visible effect; the resumption introduction says committed prefixes are never recomputed. Idempotent memory does not erase stores already observed by another hart or make repeated loads sample identical data.

**Evidence:** After block zero of `kl.store` is visible to another hart, an interrupt using option 5 records zero. The visible block is now at or beyond the recorded progress, contradicting GR55. The same problem is not cured by bounding the number of restarts.

**Resolution:** Permit restart at zero only if the current attempt has produced no architecturally visible component effect and all private partial work is discarded. Once any prefix is committed, every interrupt must retain a permitted prefix-complete point and resume there; a store already observed by another hart cannot be rolled back. Clarify this restriction in the CSR description, GR55, GR62, and the rationale. Preserve the idempotent-region restriction and the precise synchronous-fault rule.

### M4 - Expiration trusts an unspecified notion of a secure clock

**Severity rationale:** Expiration is a security policy, but the draft does not require the clock properties needed to enforce it. Implementations can disagree on validity across rollback, suspension, or clock faults.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== _ExpirationDate_ Field", L559-583.

**Issue:** The only concrete clock restriction is that software below M-mode cannot set it. A readable clock that has rolled back, stopped, or lost its UTC mapping is treated as authoritative, including a pre-epoch reading clamped to zero. Previously expired SCCs can then become usable again after import. "Adequate for ... an on-SoC TPM" does not specify a UTC clock, advancement across power loss, or rollback behavior.

**Evidence:** Set `_ExpirationDate_ = e > 0`, retain an SCC, and import it after the clock returns a value below `e`. The specified comparison admits use regardless of whether real UTC has passed the deadline. Assumption: expiration is intended to follow the stated UTC instant; hostile M-mode is not part of this finding.

**Resolution:** Define the minimum clock contract: a trustworthy UTC mapping, advancement or trustworthy reconstruction across supported suspension/power cycles, and detection of loss of validity or rollback relative to that mapping. Treat detected loss of these guarantees as clock-unavailable until trusted recovery. State rounding explicitly as completed whole hours, retain the saturation rule, and document allowed clock error in a discoverable platform contract. Do not substitute a merely boot-relative TPM counter for UTC.

### M5 - Smstateen denial is incorrectly specified as always illegal-instruction

**Severity rationale:** The prescribed trap type can send a guest access to the wrong handler and break virtualization or emulation.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "== CSRs", L706-708; "== Error Handling Architecture", L2415-2417, L2427-2434.

**Issue:** L2434 attributes an illegal-instruction exception for a clear Smstateen gate to that extension without retaining its virtual-instruction case. The fatal-condition deferral text repeats the unconditional illegal-instruction outcome.

**Evidence:** RISC-V Privileged Architecture, published 20240411 source, "Smstateen/Ssstateen" version 1.0.0, "State Enable Extensions", explicitly permits/requires the applicable virtual-instruction exception in VS/VU instead of illegal-instruction. The in-scope requirement says otherwise. Overlap with A3: only gate semantics are reported; the existence/allocation of the KLEE stateen bit remains excluded. Exception-number allocation under A4 is also excluded.

**Resolution:** Replace the blanket outcome with "the illegal-instruction or virtual-instruction exception required by Smstateen/Ssstateen for the executing mode and denying gate." Preserve the gate's priority over deferred fatal reporting, for either outcome. Specify that all KLEE instruction and CSR accesses covered by the gate use this rule, and distinguish this denial from an absent-extension or malformed-encoding trap.

### M6 - The precise provisioning algorithm never installs the supplied MDH

**Severity rationale:** The listed state transition omits the operation that binds the caller's algorithm and policies to the new locker. Implementers must supply a consequential step themselves.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "==== kl.mgmt opens a provisioning or an import", L2805-2839; "==== kl.mgmt completes a management operation", L2888-2897.

**Issue:** The opening algorithm zeroizes the target, checks `ml`, allocates capacity, and sets `_State_`, but never assigns the rest of `ml` to the locker for provisioning. The import algorithm separately loads its MDH at L3214; provisioning has no corresponding step. Completion reads fields such as `_KeyType_` from the locker, making the missing assignment observable.

**Evidence:** Applying the enumerated provisioning steps literally leaves all fields except `_State_` zero, although the general descriptions say provisioning loads Metadata. The failure rule also requires those fields to remain zero on failed opening, so simply copying early creates a different inconsistency.

**Resolution:** After successful validity and capacity checks, atomically install `ml` into the locker, applying the specified PI normalization of `_StateExtension_` and `_MachineUse_`, then set `_State_ = kl_cfg_provisioning`. Use a local normalized MDH for precommit checks; retain the stated zero-MDH failure outcomes. Make the assignment explicit for import too, with its ADS-layout adjustment, and state which checks use the original or normalized copy.

### M7 - The software rules both require and forbid clearing a saved exporting locker

**Severity rationale:** The normative context-switch requirements cannot all be followed. A literal implementation cannot safely evict a locker during an interrupted export.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== Isolation of Contexts", L3322-3327; "=== Requirements on Management Operations", L3376-3378; "=== Context Save Order", L3497-3501; modules/ROOT/pages/Zkl-rules-explanation.adoc, "== Design Principles", L153-158.

**Issue:** SR14 says that, unless terminating the interrupted software, system software must save an exporting locker by nested export and "never clear it". SR1-SR2 require clearing lockers before transferring control or installing another context. The prohibition lacks the necessary exception after a complete saved image exists.

**Evidence:** A scheduler saves an interrupted export into a PCCC and needs its locker slot for the next task. Clearing it satisfies isolation but violates SR14; retaining it exposes another context's resident state. Persistence requires the saved image to be restorable after eviction.

**Resolution:** Replace SR14's last clause with "must not clear it until a complete nested-export image and all resumption metadata have been saved in storage protected for the owning context; it may then clear the resident locker and must restore it before resuming that context." Require bounded save/restore transfers and preservation of the interrupted pointer/progress, and update the context-switch guidance to distinguish an unsaved clear from eviction after saving.

### M8 - Successful management completion has two different pointer outcomes

**Severity rationale:** The discrepancy changes subsequent implicit operands and can redirect a transfer or make a success check appear to report a cleared locker.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== klmanagedlocker", L831-834; "=== Rules Governing the Managed Locker", L1848-1864; modules/ROOT/pages/Zkl-rules-explanation.adoc, "== What the Principles do not determine", L432.

**Issue:** The CSR definition says 32 is used after successful management completion. GR12 and the explanation explicitly keep the target index after completion until software resets it. Both are architectural statements, and neither is identified as obsolete.

**Evidence:** A completing `kl.mgmt` followed by `kl.getst Xd, KLML` returns the completed State under GR12, but zero under the CSR description. A following memory encoding also selects the locker or KLIOBUF according to this value.

**Resolution:** Make the CSR definition match GR12: "Successful completion retains the target locker number for outcome inspection. Software writes 32, or restores its saved value, after consuming that outcome." Remove successful completion as an example of automatic reset; preserve the existing automatic-reset cases for clearing and other explicitly listed operations.

### M9 - KLIOBUF legality conflicts with inert-locker fall-through

**Severity rationale:** The draft prescribes both trapping and silent completion for the same instruction. Trap handlers and conformance tests cannot implement a single gate order.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== kl.mvin and kl.mvout", L1172-1183; "=== Usage Control", L1898-1899; "=== Outcome of an Instruction on a Locker", L2001-2007; "=== Order of Evaluation for Usage Instructions", L2526-2538.

**Issue:** GR14 and the last paragraph of GR20 say an unconfigured KLIOBUF traps in every State. The detailed usage gate order returns early for an Unconfigured or Error-State locker, before checking the buffer required by a substitution. Move variants also combine an unconditional unconfigured-buffer exception with no-operation cases, explicitly defining the precedence only for `klmanagedlocker = 32`. The outcome for a named inert locker is consequently contradictory. Because an Error State no longer identifies the previous native Form, the output effect of inert Form D also needs an explicit rule.

**Evidence:** Issue Form D `kl.exec` on an Error-State locker with `kliobuflen = 0`: GR20's final paragraph demands illegal-instruction, but the usage gate order stops at condition 2. Issue `kl.mvout KLIOBUF` on an inert managed locker and the move description supplies competing rules too.

**Resolution:** Publish one precedence table distinguishing explicit KLIOBUF instructions from State-selected substitutions. Preserve the detailed usage rule: inert `kl.exec` does not require a substitution buffer. Make its output rule independent of the lost native State: inert Form D with a configured KLIOBUF zeroes `[klstart, kliobuftop)`, and with no buffer accesses none; both clear `klstart`. Explicitly exempt this inert case from the native-Form-D rule that preserves `klstart`. Vector output forms retain GR33 and GR5. For move variants, specify that the no-managed-locker and inert-locker cases precede configuration/length checks, but follow extension and encoding checks; zero an existing destination window while retaining the move rule that preserves `klstart`. Retain the explicit `Xl = 0` no-op exception for memory aliases. Qualify GR14 and GR20 to reference these exceptions.

### M10 - FIPS security levels are misrepresented as days of attack resistance

**Severity rationale:** The claim can cause a provider to negotiate a protection level on a false security premise. The draft gives no verified basis for the quantitative mapping.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== _SCProtection_ Field", L381-385.

**Issue:** The text assigns roughly one day of analysis resistance to FIPS 140-3 levels 1-3 and several days to level 4. FIPS 140-3 levels are qualitative module requirements, not universal attack-time guarantees. The nearby list also suggests equivalence between different editions and test regimes without specifying the common guarantees required for a KLEE level.

**Evidence:** FIPS 140-3 (March 22, 2019), the announcement’s item 3 "Explanation" and the specification’s §3 "Applicable Standards", describes four increasing qualitative security levels and adopts ISO/IEC 19790:2012 and ISO/IEC 24759:2017 with CMVP modifications. It does not supply the stated day counts. The exact clauses of the cited 2024/2025 ISO editions and SP 800-140F were not verified.

**Resolution:** Delete the day counts and the unsupported equivalence. Require a protection claim to identify the precise standard edition, validation/test profile, attack model, and measured limits; identify any cross-profile equivalence explicitly rather than inferring it from a level number. State that a FIPS level alone does not specify a duration of resistance. Apply these declared profiles to the complete secret-handling path under C3.

### m1 - The notation table attributes one CTR layout to the entire standard

**Severity rationale:** The chosen layout can be valid, but the attribution misstates the standard and can mislead future transcriptions.

**Location:** modules/ROOT/pages/Zkl-notation.adoc, "== Conventions of the Referenced Standards", L100-106.

**Issue:** The table says SP 800-38A's CTR counter is big-endian in the trailing bytes. That describes a permitted convention, not a universal requirement of the Recommendation.

**Evidence:** NIST SP 800-38A (December 2001), Appendix B.1, allows incrementing the whole block or a selected part and permits other incrementing functions that ensure uniqueness, including LFSR constructions.

**Resolution:** Replace the attribution with "SP 800-38A permits several unique-counter constructions. The KLEE CTR variant, where specified by its Machine, uses a big-endian counter in the designated trailing field." Keep the existing conversion rule scoped to that variant; do not change a Machine's algorithm through the notation table.

### m2 - The cited NIST documents do not establish universal policy inheritance

**Severity rationale:** The architectural policy may be chosen independently, but its purported standards derivation is overstated.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== Derivation Rules", L2183-2184; modules/ROOT/pages/Zkl-rules-explanation.adoc, "== Design Principles", L178-180.

**Issue:** The text attributes inheritance of every parental use constraint to SP 800-57 Part 1 §6.2.1 and SP 800-108r1 §8. The former concerns protection of key information in transit; the latter citation does not identify the relevant discussion in the checked revision. Neither inspected passage establishes inheritance of every ISA policy field or equal cryptoperiods across a key hierarchy.

**Evidence:** SP 800-57 Part 1 Rev. 5 (May 2020), §§6.2.1.4 and 6.2.1.6, requires integrity of associations with usage and related information. SP 800-108 Rev. 1, Update 1 (August 2022), "Security Considerations", discusses strength, key separation, and context binding; it does not prescribe Zkl's policy lattice. The draft's §8 reference is not verified as a valid target for this claim.

**Resolution:** State that the inheritance lattice is a Zkl architectural choice. Cite SP 800-57 for protecting metadata associations and SP 800-108 for the specific KDF properties they actually discuss; remove "these Recommendations expect ... every constraint" and supply correct section references for the selected editions.

### m3 - The principles appendix overstates several normative rules

**Severity rationale:** These informative discrepancies do not override the ISA, but they make the claimed derivation misleading and can propagate into future changes.

**Location:** modules/ROOT/pages/Zkl-rules-explanation.adoc, "== Vocabulary", L38; "== Design Principles", L172-180, L197; "== Design Decisions", L247, L276, L311-312, L331, L344; modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== Rules Governing the Managed Locker", L1848-1864; "=== Order of Evaluation for Usage Instructions", L2529-2536; "=== Generation of an SCC from a Fully Configured Locker", L3170-3179.

**Issue:** The appendix says the pointer is not a locker number and denotes a CC necessarily in transit; usage gates every progress change, although clone/import can restart progress; sealing derives its key from a Locality Secret, although the algorithms derive it from the CSK and authenticate Localities as data; management restores exactly the supplied MDH, although provisioning normalizes it and import may replace/drop the ADS; all policy misuse becomes Invalid, although UsagePolicy violations trap and leave the locker unchanged; all listed exception checks precede State checks, although several depend on State; only one CC can be in transit, although the pointer and software coordination do not enforce that invariant; and `vstart` always denotes the same progress as `klstart`, omitting the move exception.

**Evidence:** The in-scope algorithms and rules cited above explicitly make these distinctions. D6's pointer-retention statement also contradicts Vocabulary L38 even without referring to another chapter.

**Resolution:** Align each summary with its normative source: call the pointer a locker index that may survive completion; limit usage gating to usage instructions and list management restarts as exceptions; name the CSK as the sealing-key source; describe MDH normalization; distinguish MachinePolicy invalidation from UsagePolicy traps; separate State-independent and State-dependent gates; describe one active owner of the shared authentication registers as a software discipline; and exempt moves from equal-progress wording. Apply C1-C2 and M1-M9 before revising the derivation and coverage text.

### m4 - The instruction-effects table omits vector CSR writes

**Severity rationale:** The summary is inconsistent with an explicit operand rule, although that rule supplies the correct behavior.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== General Rules Governing Encoding and Arguments", L887-889; "=== Usage Control", L1876-1888.

**Issue:** The table says `kl.setst`, `kl.mgmt`, and `kl.restrict*` may not modify other state. Their vector forms reset the vector CSR `vstart` on retirement under GR5. This matters to software preserving vector state even when an instruction has no vector destination.

**Evidence:** `vstart` belongs to vector architectural state, and GR5 applies to every KLEE instruction with a vector operand. The table already distinguishes KLEE state from other state.

**Resolution:** Mark these rows "Yes, vector forms reset vstart" in the other-state column, or add an explicit table-wide exception for that CSR. Keep the precise-halt and illegal-instruction cases distinct from retirement.

### m5 - Writing zero to kliobuflen has inconsistent erasure descriptions

**Severity rationale:** Later reconfiguration prevents architectural readback, so this is a specification-clarity defect rather than a demonstrated disclosure.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== klmaxiobuflen", L751; "=== kliobuflen", L761-766; "=== Requirements on the KLIOBUF", L3335; modules/ROOT/pages/Zkl-rules-explanation.adoc, "== Design Principles", L89.

**Issue:** The `kliobuflen` rule zeroes only bytes below the new length; writing zero consequently erases no bytes. L751 describes immediate buffer zeroing as the effect of writing zero, while SR4 correctly relies on erasure at subsequent reconfiguration. These are different postconditions.

**Evidence:** With old length 16 and new length zero, the range below the new length is empty. The buffer is inaccessible and a later nonzero write clears it, but that does not establish immediate physical erasure.

**Resolution:** Keep the precise CSR rule and clarify that a zero write unconfigures the buffer, with readback prevented by clearing on every later reconfiguration. At L751, explicitly state that reducing the maximum below the current length additionally zeroizes the KLIOBUF, rather than claiming this follows from a zero `kliobuflen` write. Preserve the stronger explicit zeroization requirements for reset and `kl.clearall`.

### m6 - Grammar errors in the unprivileged architecture

**Severity rationale:** These are editorial defects; the corrections do not change the intended ISA behavior.

**Location:** modules/ROOT/pages/Zkl-ISA-unpriv.adoc, "=== Fundamental Concepts and Definitions", L65, L86; "== Cryptographic Lockers", L215; "==== kl.mgmt opens a provisioning or an import", L2833; "==== kl.mgmt completes an export", L2930; "=== Management Routines", L3487.

**Issue:** L65: "their semantics depends" → "their semantics depend"; L86: "nor they modify" → "nor do they modify"; L215: "that is hold no CC" → "that is, it holds no CC"; L2833: "decide" → "decides", agreeing with "The instruction"; L2930: "implementation may" → "an implementation may"; L3487: "Code that must coordinates them" → "Code that must interleave them coordinates them".

**Evidence:** The listed constructions have subject–verb agreement, inversion, article, or clause-completion errors in American English.

**Resolution:** Apply the listed replacements, retaining the existing cross-references and rule strength.

### m7 - Grammar errors in the principles appendix

**Severity rationale:** The omitted object and malformed comparison reduce clarity without independently changing a normative rule.

**Location:** modules/ROOT/pages/Zkl-rules-explanation.adoc, "== Design Principles", L66, L180.

**Issue:** L66: "software, which is in charge of handling" → "software, which handles capacity exhaustion"; L180: "additional operations than those defined at its provisioning" → "operations beyond those defined at its provisioning".

**Evidence:** "Handling" lacks its object, and "additional ... than" uses the wrong comparison construction.

**Resolution:** Apply these corrections while performing the substantive appendix revision in m3.

# 3. Cross-document inconsistencies and missing requirements

- C1: GR48 and its rationale mistake MAC security for one-way protection of the message.
- C2: Private MDH semantics lack a defined fallback when their optional qualifier is discarded.
- C3: Mandatory protection stops short of the shared secret-handling path.
- M1: Resource exceptions lack a consistent committed-prefix contract.
- M2: Derivation lacks complete restart offsets and source/destination length rules.
- M3: Restart-at-zero conflicts with prefix completeness and the appendix's no-recomputation claim.
- M4: Expiration lacks a minimum trustworthy-clock contract.
- M5: State-enable trap semantics disagree with the cited extension.
- M6: The precise provisioning transition omits MDH installation.
- M7: Saved-export eviction conflicts with the normative prohibition on clearing.
- M8: The CSR definition conflicts with GR12 and the appendix's completion rule.
- M9: Inert-locker fall-through conflicts with unconditional KLIOBUF legality claims.
- M10: Protection-level negotiation relies on an unsupported standards equivalence.
- m1: The notation table confuses a selected CTR convention with the standard's general rule.
- m2: The policy derivation overstates its NIST basis.
- m3: Informative summaries do not preserve the normative distinctions they purport to derive.
- m4: The effects table omits vector CSR effects required by GR5.
- m5: CSR and explanatory text disagree about immediate buffer erasure.

# 4. Standards-compliance matrix

Locations below abbreviate the scoped files as **U** = Zkl-ISA-unpriv.adoc, **N** = Zkl-notation.adoc, **A** = Zkl-acronyms.adoc, and **R** = Zkl-rules-explanation.adoc. Assessments cover only the stated checks, not entire standards or unread Machine implementations. "Not verified" is not an adverse conformance judgment.

| Requirement/standard | Location | Assessment | Evidence |
|---|---|---|---|
| AES-CMAC protects a secret supplied as its message | U L2218-2220, L2233-2240; R L439 | Noncompliant | C1. [SP 800-38B](https://doi.org/10.6028/NIST.SP.800-38B), 2005/update 2016, §§6.1-6.2; equations and synthetic OpenSSL reproduction contradict the asserted one-way property. The CMAC algorithm itself is not defective. |
| State-enable exception selection | U L2417, L2434 | Noncompliant | M5. [Smstateen/Ssstateen 1.0.0](https://github.com/riscv/riscv-isa-manual/blob/20240411/src/smstateen.adoc), "State Enable Extensions": applicable guest denials use virtual-instruction. Allocation is excluded by A3/A4. |
| Unsupported vector configuration sets vill and vl=0 | U L279-283 | Compliant | [V 1.0](https://github.com/riscv/riscv-v-spec/blob/v1.0/v-spec.adoc), "Configuration-Setting Instructions": this is the specified unsupported-vtype outcome. |
| Vector group alignment and nonproduced vstart values | U L887-889 | Compliant | V 1.0, "Vector Register Grouping (LMUL)" and §3.7: integer-LMUL grouping and rejection of vstart values the instruction cannot produce agree for the stated KLV subset. |
| Vector vstart reset at retirement | U L888; L1881, L1884, L1888 | Needs clarification | m4. V 1.0 §3.7 agrees with GR5, but the instruction-effects table omits these writes. |
| KLV versus full V/Zvbc scope | U L274-287 | Not verified | A5 excludes scope decisions. No claim that KLV implements every V configuration is inferred from calling it a subset; complete Zvbc compatibility was not verified. |
| RVWMO/RVTSO, fences, and precise restart | U L2253-2270, L2317 | Not verified | M3 establishes an internal contradiction independently of external compliance. A formal extension-to-memory-model mapping and current Ztso comparison were not verified; reference not verified. |
| JEDEC vendor-ID bank/offset convention | U L731 | Compliant | [Privileged Architecture, 20240411, Machine-Level ISA 1.13](https://github.com/riscv/riscv-isa-manual/blob/20240411/src/machine.adoc), "Machine Vendor ID Register mvendorid": the named 32-bit bank/offset convention matches. No allocation of actual KLEE IDs was checked. |
| KLEE architecture/implementation ID namespace | U L734-740 | Not verified | The analogous hart CSRs are specified, but RVI allocation of the proposed KLEE namespace was not verified. CSR address allocation is excluded by A3. |
| RFC 8452 key derivation and byte ordering | N L25-35, L80-84; U L3038-3048 | Compliant | [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452), April 2019, §4: LE32 counter followed by nonce, first eight ciphertext bytes retained, six blocks for AES-256. |
| POLYVAL field, bit mapping, and dot product | N L110-112; U L3058-3078 | Compliant | RFC 8452 §3: the polynomial, bit order, and multiplication by x^-128 agree. |
| SCC construction versus standardized AES-GCM-SIV | U L3023-3028, L3097-3149 | Not verified | Explicitly a modified construction, not a claim of bitwise RFC conformance. Overall security was not established. Nonce choice and the aggregate security bound are excluded by B4/B6. |
| GCM's 96-bit-IV J0 transcription | N L85-86 | Compliant | [SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D), November 2007, §7.1: the mapped bytes are IV followed by 00 00 00 01. |
| GHASH bit ordering | N L107-109 | Compliant | SP 800-38D §6.3: the leftmost bit represents the constant coefficient; relative to the scoped byte-value mapping this reverses bit significance within each byte. |
| CTR counter-layout attribution | N L100-106 | Needs clarification | m1. [SP 800-38A](https://doi.org/10.6028/NIST.SP.800-38A), December 2001, Appendix B.1, permits more constructions than the table suggests. |
| CMAC subkey shift orientation | N L102, L106 | Compliant | SP 800-38B §6.1 defines the big-endian string shift and reduction; actual out-of-scope double implementation was not checked. |
| SHAKE acronym | A L85 | Compliant | [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202), August 2015, §2.2: "Secure Hash Algorithm KECCAK" is the published expansion. |
| SHA-3 state indexing | N L118-121 | Compliant | FIPS 202 §3.1: A[x,y,z] = S[w(5y+x)+z], consistent with the stated lane mapping. |
| XTS, OCB, SHA-2, Ascon, ML-KEM, ML-DSA conventions | N L100-106, L113-117, L122-130 | Not verified | IEEE/XTS details, RFC 7253, FIPS 180-4, SP 800-232, FIPS 203, and FIPS 204: reference not verified for these table claims; their Machine definitions are outside scope. |
| Universal derived-key policy inheritance | U L2184; R L179 | Needs clarification | m2. [SP 800-57 Part 1 Rev. 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5), §§6.2.1.4/6.2.1.6, and [SP 800-108r1 Update 1](https://doi.org/10.6028/NIST.SP.800-108r1-upd1), "Security Considerations", support narrower claims. |
| FIPS 140-3 adoption of ISO editions | U L384 | Compliant | [FIPS 140-3](https://doi.org/10.6028/NIST.FIPS.140-3), March 2019, §§3.1-3.4: ISO/IEC 19790:2012 and 24759:2017 with CMVP modifications. |
| FIPS levels as days of resistance | U L385 | Noncompliant | M10. FIPS 140-3's qualitative levels do not establish the asserted timing scale. |
| ISO 2024/2025 clauses, CMVP test metrics, RISC-V Platform Security Model | U L367, L381-385 | Not verified | Exact edition/clauses and equivalence to KLEE levels: reference not verified. |
| External Debug Security prerequisite | U L119 | Not verified | Edition, dependency requirements, and the scoped architecture's satisfaction of them: reference not verified. |
| Zkr entropy source and SP 800-90A/equivalent DRBG | U L123-124, L2367-2369 | Not verified | Normative intent is explicit, but accepted equivalent standards, DRBG configurations, and compliance with the published entropy-source requirements were not verified. M1 concerns the independent architectural exception contract. |
| AES-256 primitive definition | U L3032 | Not verified | FIPS 197 is cited, but no AES implementation is in scope; primitive implementation and vectors were not verified. |
| IBM/Intel key-protection comparison and Caliptra example | U L2602, L3557-3558 | Not verified | Cited editions and the described interfaces: reference not verified. These examples do not establish interoperability. |

# 5. Remediation plan

Apply the fixes in this order; each item names its dependencies.

1. **C1** — close the generic secret-extraction path; no dependency.
2. **C2** — define portable MDH fallback semantics; no dependency.
3. **M10** — correct and identify protection profiles; no dependency.
4. **C3** — enforce those profiles across all secret handling; depends on step 3.
5. **M6** — make MDH installation explicit; use the normalization contract from step 2.
6. **M5** — correct state-enable trap selection; no dependency on final allocations.
7. **M4** — define the clock contract; use the gate precedence from step 6.
8. **M3** — establish one visible-prefix rule for memory interruption; no dependency.
9. **M1** — extend the prefix rule to resource exceptions; depends on steps 7 and 8.
10. **M2** — complete derivation validation and resumption; depends on steps 1 and 9.
11. **M9** — unify buffer gate and fall-through precedence; use the exception contracts above.
12. **M8** — make pointer retention unambiguous; no dependency.
13. **M7** — correct eviction after nested saving; depends on step 12 and the prefix rules.
14. **m4** — correct the effects table after instruction outcomes are fixed.
15. **m5** — reconcile erasure descriptions after step 11 fixes buffer handling.
16. **m1** — correct CTR attribution; independent of opcode or Machine changes.
17. **m2** — correct the NIST rationale after step 1 settles admitted derivations.
18. **m3** — rewrite informative derivations against the corrected normative rules.
19. **m6** — apply the unprivileged prose corrections after substantive edits.
20. **m7** — finish appendix grammar after step 18.

# 6. Open questions and assumptions

- **Review boundary:** All six permitted files were read in full. Only "Discussion Points" was extracted from the introduction. No other repository source, included file, image, bibliography, or example was opened. Explicit in-scope cross-reference targets exist; agreement defects are identified in Section 3. Root includes/attributes supplied by the unread global configuration and the generated rendering could not be validated.
- **Exclusions:** A1-A6 and B1-B7 were applied. In particular, this review does not decide opcode/CSR/cause allocation, KLS discovery, KLV scope or element sizing, effective endianness, removal of memory instructions, management interruptibility, sealing nonces, new KDF Machines, the aggregate sealing-security claim, or KLF capacity discovery. Commented-out prospective items were not treated as additional numbered exclusions.
- **Machine dependencies:** `KLEE-Machines`, the endpoint catalog, Machine policy gates, granularity, `process_VLI`, fixed-width operands, output clearing, field serialization/padding, and progress-discard/randomness rules reside in the unread Zkl-ISA-machines.adoc. Their algorithms, termination bounds, state tables, sizes, and actual CMAC endpoint availability remain unverified. C1 is a counterexample to the generic admission rule, not a claim about that unread catalog.
- **Privilege dependencies:** KLS/locker-status dirtiness, trap priority/delegation details, CSK writes, software Locality CSR groups, shared-secret reset behavior, debug authorization, and M-mode-only CSR availability depend on unread Zkl-ISA-priv.adoc. This review cannot establish the complete privilege-state machine or hardware/emulator interoperability. M5 reports an explicit contradiction in the scoped text, not inferred contents of that chapter.
- **Software dependencies:** Management examples and their bounded transfer/retry loops are in unread Zkl-pseudocode.adoc. Their correctness and compliance with the corrected software rules remain open. The separation discussion in unread Zkl-books.adoc was not used as evidence.
- **Trusted components:** Findings assume M-mode firmware and any authenticated debugger are within the stated trusted base. They do not treat deliberate M-mode key disclosure as a new Zkl vulnerability. Compartment-local software may choose inputs, keys, metadata, instruction sequences, and allowed management operations maliciously.
- **System-specific import and SKS:** Their external policy schemas, key-envelope authentication, minimum side-channel requirements, revocation, and trusted provisioning mechanisms are not supplied here. The text intentionally permits unauthenticated system-specific formats; no assurance that a particular external format protects its owner's original policies can be inferred. These deployment dependencies require explicit profiles before evaluating a concrete system.
- **Unverified standards:** Matrix entries marked Not verified remain limitations. The bibliography was not followed, so an in-text citation with no edition does not acquire one from an assumed bibliography entry. The published sources linked in the matrix identify the editions actually checked.
- **Validation limit:** The CMAC reproduction is a synthetic cryptographic counterexample, not an execution test of Zkl hardware. No in-scope implementation or executable ISA model was available for differential testing; the assessment otherwise rests on source-level state-transition and consistency analysis.
