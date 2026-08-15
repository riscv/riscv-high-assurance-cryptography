# Public Review — RISC-V Atomic Cryptography Extension (ACE)


1. **Book 2's algorithm definitions do not match the standards they cite.** This is the most serious area. GCM's counters are off by one against SP 800-38D; GCM-SIV derives its keys before the nonce is known and clears a tag bit that RFC 8452 does not; OCB uses a monotonic doubling schedule rather than RFC 7253's `ntz` schedule; Ascon has five independent defects including a domain-separation bit applied to the wrong end of the state word. None of these modes would pass the standards' own test vectors, and several are not merely non-interoperable but weakened. The authors' own warning at `ace-ISA-algorithms.adoc:1858` that "the ordering of the bits must be verified" was well founded — the verification finds real errors.

2. **The SCC sealing construction is not AES-GCM-SIV, and its authentication check does not work.** The import algorithm's tag comparison discards the recomputed POLYVAL value, so no imported context is actually authenticated. Key derivation omits the nonce, POLYVAL omits RFC 8452's length block, and the default nonce is zero — so sealing is deterministic and one key pair is reused for every SCC under a given CSK. This is the root of trust for every context that leaves a register.

3. **Several security guarantees the introduction claims are not enforced by the architecture.** Debug mode is permitted to *use* every resident context by default; SCCs have no anti-replay, so re-importing an old SCC rolls counter-mode state back and reuses keystream; Cryptographic Registers are shared across privilege modes while the management instructions are explicitly *not* usage-controlled, allowing a lower-privileged mode to substitute contexts under a higher one; and zeroization is nowhere actually guaranteed.

Beyond these, the privileged architecture has a hypervisor state-management hole (write-only secret CSRs that a hypervisor can neither read nor trap, making save/restore and the advertised VM migration impossible), and Books 1–4 disagree with each other on instruction names, extension names, CSR units and algorithm state machines to a degree that a reader cannot reliably determine the intended instruction set.

The threat model is currently **excluded from the built document** (`src/ace.adoc:105` comments out the annex include) and is marked non-normative where it does exist. For a specification whose entire value proposition is a security guarantee, that is a structural gap: there is no baseline against which any conformance claim can be evaluated.

**Recommendation:** the specification is not ready to freeze. The Book 2 algorithm definitions should be rewritten against the standards with test vectors added, the SCC construction reworked and analyzed, and the threat model promoted into the normative document, before a public review milestone is declared.

---

## Critical findings

### Sealed Cryptographic Context construction

**C1. The SCC import authentication check is inoperative.**
DONE

**C2. Key derivation omits the nonce, so the construction is not AES-GCM-SIV and has no applicable security proof.**
DONE, except that since this mode is nonce-misuse resistant, the nonce can be 0. Intel does the same. In our case the nonce is optional.

**C3. POLYVAL is invoked without RFC 8452's length block.**
We do not need this, since the metadata field already encodes the AD and plaintext lengths.

**C4. The import and export algorithms contain errors that make them unimplementable as written.**
DONE


### Security architecture

**C5. Debug mode may use every resident context by default, and nothing is zeroized on debug entry.**
DONE, also added questions to ARC.

**C6. SCCs have no anti-replay, so re-import rolls algorithm state back and reuses keystream.**
THIS IS KNOWN, and by choice, to avoid over complication.
Addressed any ambiguity in <<ACE-management-operations>>

**C7. Registers are shared across privilege modes while management instructions are not usage-controlled, permitting context substitution.**
This is by design, otherwise we cannot perform context switching.

**C8. Verbatim export of a partially configured register can dump generated or system key material in the clear.**
*Resolution:* require that random generation and SKS materialization occur only at `ace_CR_provision_end`, and forbid verbatim export of any register holding material the exporting context did not supply.
ADDRESSED for random values, however, this does not affect System Keys because these are never exposed outside the CR by other rules.


### Privileged architecture

**C9. Write-only secret CSRs are writable by the mode below the one that must manage them, making hypervisor save/restore and VM migration impossible.**
ADDRESSED
### Instruction definitions

**C10. `ace.mv`'s encoding and description specify opposite data directions.**
I THINK FIXED NOW

**C11. `ace.exec` Forms B and D leave the register index unencodable.**
I THINK FIXED NOW

### Cross-book contradictions

**C12. HMAC and KMAC have extensions and algorithm encodings but no definition, and Book 2 denies they are needed.**
HMAX FIXED
KMAC FIXED (I think)


**C13. Book 1 restricts the block-cipher modes to AES; Book 2 defines them for SM4.**
FIXED


### Algorithm definitions versus published standards

**C14. GCM counter values are off by one from SP 800-38D.**
FIXED

**C15. GCM decryption's tag finalization uses a malformed counter expression.**
FIXED

**C16. GCM-SIV derives its keys before the nonce is set.**
FIXED (in a different way)

**C17. GCM-SIV clears the tag's top bit after encryption, producing wrong tags and one-bit malleability.**
FIXED (I think)

**C18. The GCM-SIV counter-exhaustion check invalidates the register on the first block.**
OOOPS. FIXED

**C19. GCM and GCM-SIV are given the identical length-block formula although the two standards use opposite conventions.**
ADDED BIG ENDIANNESS CONDITIONS TO GCM
*Resolution:* define `bin()` and the byte-order mapping normatively, with mode-specific layouts.

**C20. OCB's offset schedule is not RFC 7253's.**
FIXED

**C21. OCB's final-block tag computation deviates from RFC 7253 in two ways.**
FIXED


**C22.  absorbs associated data with the permutation on the wrong side.**
FIXED

**C23. Ascon's domain-separation bit is applied to the wrong bit of the state word.**
FIXED

**C24. Ascon decryption swaps the halves of its output relative to encryption.**
FIXED

**C25. Ascon cannot decrypt standard length-preserving ciphertexts.**
FIXED

**C26. Ascon-Hash256 applies one permutation too many before the first output block.**
FIXED

**C27. Ascon-XOF128's IV is Ascon-Hash256's IV.**
FIXED

**C28. ML-KEM provides no way to input a ciphertext, so peer ciphertexts cannot be decapsulated.**
FIXED

**C29. P-521 ECDSA nonces are specified with 512 bits of randomness for a 521-bit group order.**
FIXED
---

## Major findings

### Security architecture

**M1. The threat model is excluded from the built document, non-normative where it exists, and omits major attacker classes.**
BROUGHT back to the main doc (introduction)  but it is not clear what else we can enforce

**M2. The CSK has no architectural requirements.** `src/ace-ISA-priv.adoc:300-317`.
PARTIALLY ADDRESSED, there is a limit to what we can enforce.

**M3. The VM-migration claim requires exporting the CSK — escrow of every sealed context — through an unspecified mechanism.**
IMPLEMENTATION CHOICE.

**M4. Localities do not isolate resident contexts, and their stated domains contradict their per-hart storage.** `src/ace-ISA-unpriv.adoc:55`, `:637-646`, `:652-674`. Localities are tweaks in SCC encryption only; a context already resident in a register can be used by any domain running on that hart, so the claim that ACE restricts usage to process domains holds only across a seal/unseal boundary and depends on software clearing registers at every context switch. Separately, the Domain column ("Device", "VM", "< M") contradicts per-hart storage: nothing requires an OS or hypervisor to write identical Locality Secrets to every hart, so a thread or vCPU that migrates silently fails to import its own SCCs. No save/restore rules are given for these WARZ registers. *Say explicitly that Localities are a sealing-time control, and add multi-hart consistency and save/restore rules.*

WHILE SOME CARE IS NEEDED AND I ADDED COMMENTS TO THAT EXTENT (ace-unpriv lines 652-653), WE CANNOT ENFORCE CRYPTOGRAPHIC BINDING AT EACH STEP. ULTIMATELY, SW HIERARCHY IS RESPONSIBLE NOT TO LEAK THEIR OWN CRS. I do not see why we should add rules to manage the Locality Secret registers. These are going to be annoying, but not more annoying than many other state values that must be set already.


**M5. Zeroization is never actually guaranteed.** `src/ace-ISA-unpriv.adoc:2184-2186`, `:469-471`; `src/ace-ISA-priv.adoc:143`. "Unconfigures", "releases its resources", "invalidated and emptied" are all weaker than zeroization, and none is defined. The specification demonstrates it knows the difference — `:1484` says the CRF memory "is zeroed" on `ace_CR_provision_start` — which makes the omission elsewhere conspicuous. There is no erasure requirement on hart reset, on ACE being disabled (`Setting ACES to Off ... does not clear CRs`), on power-down or resume (hibernation is a claimed feature), or on debug entry; the ACEIOBUF holds plaintext with no clearing rule at all. *Define "zeroize" once and require it at each of these points.*

!!!NEEDS TO BE DONE!!!


**M6. A usage-policy violation destroys the context, giving any lower-privileged mode a cross-domain kill primitive.**
CHOICE

**M7. `ace.restrictv` is specified to rewrite the entire MDH with no monotonicity constraint.** `
FIXED

**M8. `_SCProtection_` levels are unordered, unrestrictable, and contradicted by their own rationale note.**
I think the LLM here misunderstood what we have written.

**M9. DIEL is claimed as a protection level but never normatively defined.** `src/ace-ISA-unpriv.adoc:357`. The only elaboration anywhere is an informative subsection about IMPQUAL mismatch (`:2924-2930`). Nothing states whether data-independent execution latency covers key material as well as data, forbids key-dependent memory access patterns or branching, applies to `ace.load`/`ace.store` address streams, or relates to `Zkt`/`Zvkt`. Book 2 contains no occurrence of DIEL or latency at all, so no algorithm states its timing obligations. The requirement is untestable as written. *Add a normative DIEL section modelled on `Zkt` and cross-reference it from every algorithm.*

HOW TO DO THIS?


**M10. `_ExpirationDate_` depends on an undefined "secure clock" with no rollback resistance.**
FIXED

**M11. `ace.derive` has no restriction-inheritance rules.** `src/ace-ISA-unpriv.adoc:1925-1934`. The description never says what MDH the destination receives, so nothing prevents deriving from a heavily restricted key into an unrestricted context and exporting it — a laundering primitive. "The behavior of the instruction is not expected to be deterministic" is also incompatible with any key-agreement or KDF use, and no entropy source is specified. The encoding is being frozen now even though the instruction is reserved. *Require that the derived context inherits the source's restrictions, tightenable only.*

TBD

**M12. `ace.clone` does not state that policy metadata is copied, and is not usage-controlled.**
Added explicit statement, also "The instruction is not usage-controlled." was already there

**M13. Random key generation has no entropy-source requirement.** `src/ace-ISA-unpriv.adoc:383-384`.
15.
16.  For an architecture whose purpose is key confidentiality, the on-chip generator is specified in one sentence: no approved entropy source or DRBG, no health tests, no failure behavior, no statement that it is unobservable by untrusted contexts, no relation to `Zkr`. *Require a `Zkr`-conformant source or certified DRBG with defined fail-closed behavior.*

ADDED SOMETHING, but we nee dto discuss this.


**M14. The `_SystemFormat_` escape hatch is unbounded and ungated.** `src/ace-ISA-unpriv.adoc:320-324`, `:1045-1047`.
I DO NOT SEE THE ISSUE...

18.  Setting one MDH bit makes the remaining format "entirely system specific" and the semantics of `ace.load` "entirely implementation dependent", voiding metadata validation, sealing, Localities and usage control — with no requirement that a system-defined format preserve confidentiality or integrity, and no privilege gate on setting the bit. A conforming implementation could define a system format whose load/store path moves plaintext keys. *Require system formats to preserve the Content confidentiality/integrity invariant and restrict the bit to a platform-authorized context.*

**M15. The `ace.mgmt` terminator state machine permits an authentication-bypass path.** `src/ace-ISA-unpriv.adoc:1488-1506`. Nothing states which terminator is legal for which current `_ConfigStatus_`. `ace_CR_provision_end` is not forbidden on a register in `_CfgStImporting_`, so `import_start` → `ace.load` (SCC bytes) → `provision_end` reaches `_CfgStComplete_` with no decryption and no authentication. The value of `ml` at import_end is supplied by software, so software chooses whether authentication happens. *Add a normative table of legal (current status, immediate) pairs and require that a register entering via `import_start` can only complete through an authenticating `import_end`.*

>>>

**M16. CRF security requirements are inconsistent with the declared adversary.**
FIXED

### Privileged architecture and state model

**M17. `mstatus.TSR` and `hstatus.VTSR` are overloaded to trap ACE memory instructions.**
FIXED

**M18. No `Smstateen`/`Ssstateen` integration for the new less-privileged state.** `src/ace-ISA-priv.adoc:78-97`, `src/ace-ISA-unpriv.adoc:754-768`. ACE adds unprivileged CSRs (`acestart`, `aceiobuflen`, `aceiobuftop`, `acenonce*`, the ID registers) and supervisor CSRs with no stateen bits, contrary to the privileged architecture's policy that new state accessible to less-privileged modes must be gateable by an unaware M-mode or hypervisor. *Define stateen bits gating all ACE CSRs and instructions.*

**M19. ACES Initial/Clean semantics are underspecified and contradict the FS/VS/XS rules they incorporate.** `src/ace-ISA-priv.adoc:128-135`. "Initial" is defined only as "ACE enabled", but the FS restore protocol requires a defined initial state (all registers unconfigured? CSRs zero?) that is never given. "Clean" requires "At least one CR or ACEIOBUF is configured", making it unreachable for a context restored with none configured. And `:132` (unconfiguring a previously configured register makes ACES Dirty) contradicts `:135`, since the FS/VS/XS rules map unconfiguring to Initial. The same tension recurs at `:283` versus `:196`/`:205`/`:219`, where unconfiguring must produce Dirty although Dirty is defined as "configured" and Off as the unconfigured encoding. *Define the initial state explicitly and replace the blanket FS/VS/XS reference with an ACE-specific transition table.*

**M20. Behavior of ACE CSR accesses when ACES=Off is unspecified.** `src/ace-ISA-priv.adoc:128` says only that "The ACE state is inaccessible" and that ACE *instructions* trap. For FS=Off the privileged specification explicitly makes floating-point CSR accesses trap; ACE says nothing, so implementations will diverge and context-switch ordering is undefined. *Mirror the FS wording.*

**M21. `scrstatus` write semantics are unspecified and its invariants are software-violable.** `src/ace-ISA-priv.adoc:187-219`. The register is SRW, but nothing says what happens when software writes values inconsistent with actual register state (Off or Clean for a configured register, Clean for an unconfigured one) — whether writes are WARL-adjusted, ignored, or take effect and break the invariants that the exception semantics depend on. *Specify per-field WARL legalization.*

**M22. `mcrstatus`'s normative status is self-contradictory, and lazy loading depends on it.** `src/ace-ISA-priv.adoc:254-258` is a warning saying it "may be defined", while the extension table (`:19`) and CSR table (`:90`) list it as defined by `Smacestatus`; the lazy-SCC ownership search at `:287` ("search privilege modes from M-mode downward") needs it. The proposed remedy — making `sstatus.ACES` "unshadowed and independent" — would violate the rule that `sstatus` is a restricted view of `mstatus`. *Decide it normatively and keep `sstatus.ACES` a view of `mstatus.ACES`.*

**M23. The `vscrstatus` section is a copy-paste of `scrstatus`.** `src/ace-ISA-priv.adoc:232`, `:236`, `:239` all name `scrstatus`/`scrstatush` inside the section defining `vscrstatus` — including "`scrstatush` shadows bits [63:32] of `scrstatus`" — leaving `vscrstatush` and the actual bit layout formally undefined. *Rename the occurrences.*

**M24. "Propagation" of `*crstatus` is asserted but never defined, and the V=1 rules omit the HS-level view.** `src/ace-ISA-priv.adoc:294-296`, `:241-245`. There is no propagation concept for FS/VS in the base architecture to be "analogous to", and the V=1 rules set only `vscrstatus`(i) Dirty, leaving unstated whether `scrstatus`(i) is also updated — which breaks hypervisor-level lazy tracking. The ACES rule at `:171` does set both, so the asymmetry looks unintentional. *Give explicit rules.*

**M25. Trap-and-emulate has no effective-privilege mechanism, and hypervisors are forbidden from emulating.** `src/ace-ISA-unpriv.adoc:76`, `:308`; `src/ace-ISA-priv.adoc:386-417`. When M-mode emulates a trapped instruction for U- or VS-mode, the usage-control check sees privilege M, so a context whose policy disallows M-mode becomes unemulatable — and there is no MPRV analogue to assume the trapped mode's privilege. Meanwhile HS-mode is explicitly forbidden from implementing ACE, and the supporting emulation instructions exist only in a commented-out non-normative block. *Define an MPRV-style effective-ACE-privilege mechanism and normatively specify the emulation support.*

**M26. Trap behavior beyond cause numbers is undefined.** `src/ace-ISA-priv.adoc:44`, `:63`; `src/ace-ISA-unpriv.adoc:212-213`. Nothing states what is written to `mtval`/`stval`/`vstval` for the `ace_exc_*` causes, whether they are delegable via `medeleg`/`hedeleg`, or which xEPC applies; the blanket "the CSR `mcause` will reflect the error condition" ignores delegation to `scause`/`vscause` entirely. `ace_guru_meditation` reports CRF corruption detected asynchronously yet is architected as a synchronous exception with no binding to an instruction. *Specify xtval, delegability, and either bind guru-meditation to the next ACE instruction or make it an interrupt/RAS event.*

**M27. Exceptions `ace_exc_CR_unconf` and `ace_exc_CR_other` are defined in Book 3 but raised by no Book 1 instruction.** `src/ace-ISA-priv.adoc:64-65` versus the Book 1 instruction descriptions, which mention only `ace_exc_invalid`, `ace_exc_buf_unconf`, `ace_exc_out_of_mem` and `ace_guru_meditation`. Book 1 handles unconfigured registers purely through `_Off_` state semantics. *Add the causes to the relevant instruction descriptions or fold them per the authors' own open question.*

### Book 1 instruction and CSR definitions

**M28. `acestart` resume state is bound to no instruction or register.** `src/ace-ISA-unpriv.adoc:807-819`, `:1259-1283`, `:1503`. It records only a byte count, so any of `ace.load`/`store`/`input`/`output`/`exec` executed after an unrelated interruption will silently "resume" at a stale offset with no way for hardware to detect the mismatch. It also contradicts `ace.mv`, which reads and increments `acestart` in normal operation despite being among the instructions that clear it, and nothing states the value after a resumable instruction *completes*, which the Zlio substitution sequences at `:2271-2283` need. *Define the post-completion value and the cross-instruction case, vstart-style.*

**M29. Trap and resume PC behavior for interrupted instructions is never specified.** `src/ace-ISA-unpriv.adoc:2314-2341`. Nothing says that a trap mid-instruction sets xEPC to the ACE instruction so re-execution resumes at `acestart`, what `xtval` reports for a page fault inside a long `ace.load`, or whether partial updates before the fault are architecturally visible. Resumability is not portably implementable without this. *Add normative text modelled on the vector extension's `vstart` rules.*

**M30. The CSR chapter lacks reset values and WARL/WLRL discipline, and value-dependent write traps break save/restore.** `src/ace-ISA-unpriv.adoc:748-941`, `:819`, `:865`. No ACE CSR has a defined reset value or WARL/WLRL classification. Trapping on a *value* written to a CSR is unusual for RISC-V, and here `acestart`'s legal set is dynamic, so context-restore or migration code writing back a saved `acestart` on an implementation that does not support resumption (permitted by `:2356`) traps unpredictably. Raising `ace_exc_out_of_mem` from a CSR write is unprecedented. *Assign reset values, classify the fields, and replace value-dependent traps with WARL behavior.*

**M31. `aceiobuflen` is defined in bytes in one place and bits in another.** `src/ace-ISA-unpriv.adoc:764` ("length in bytes") versus `:859` ("programs the ACEIOBUF length in bits"). Implementations differ by a factor of eight, and comparisons against `acemaxiobuflen` and `aceiobuftop` (both bytes) become ill-defined. Book 2 compounds it: `ACELEN` is defined as `aceiobuftop` "in bits" at `src/ace-ISA-algorithms.adoc:199-201`. *Standardize on bytes and fix `ACELEN` to `8 * aceiobuftop`.*

**M32. The exception model is inconsistent about the privileged architecture and uses a nonexistent exception name.** `src/ace-ISA-unpriv.adoc:1026`, `:1108`, `:1481-1483`, `:1704`, `:2078`, `:2293-2301`. Some sites condition `ace_exc_*` on the privileged architecture being implemented while `ace.input`/`ace.output` raise them unconditionally, and Book 1 never says what happens on a `Zlio`-only implementation without it. "Invalid instruction exception" is not a RISC-V exception, and it is ambiguous whether illegal-instruction or `ace_exc_invalid` is meant. *Define which causes exist without the privileged extension and use exactly two consistent terms.*

**M33. Behavior of suppressed or disallowed operations is unspecified.** `src/ace-ISA-unpriv.adoc:456`, `:485-487`, `:1193-1206`. When an operation is suppressed (error state, usage violation, expiration), nothing says what is written to `Vd`, `Xd` or the ACEIOBUF — unchanged, zeroed or undefined — so implementations diverge and stale contents may leak. Rule 2 says only certain instructions "are permitted" in `_Success_`/`_Failed_` without defining what a non-permitted one does. `ace.exec` on an unconfigured register is covered by no rule, and there is no specification for operand-length mismatch. *Add a normative table of condition → exception, state transition, and destination effect.*

**M34. Instructions `ace.prov`, `ace.import` and `ace.export` are mandated and referenced across all three books but defined nowhere.** `src/ace-ISA-unpriv.adoc:129-131`, `:456`, `:814`; `src/ace-ISA-algorithms.adoc:819`, `:1123`; `src/ace-ISA-priv.adoc:56-59`. Book 1 says implementations "must support" them and points to the instruction chapter, which defines no such mnemonics — provisioning and import/export are actually `ace.mgmt` plus `ace.load`/`ace.store` sequences. Book 3's fault table attributes load/store faults to these phantom instructions. The SCC sections at `:2867-2918` and the resumability section attribute management immediates to `ace.setst` where `ace.mgmt` is meant (`:1444-1465`). *Define them as pseudo-instructions or purge the references.*

**M35. `ace.mgmt export_start` takes "no auxiliary input" yet its semantics depend on a scalar/vector variant.** `src/ace-ISA-unpriv.adoc:1462` versus `:1521`, where `acestart` "is set to 8 if the scalar variant was used, and 16 if the vector variant was used" — a distinction hardware cannot make with no auxiliary operand, since it cannot know whether software read the MDH with `ace.getmdl` or `ace.getmdv`. *Encode the start offset explicitly or fix it at one value.*

**M36. `ace.size` semantics during provisioning and import are undefined although the canonical code depends on them.** `src/ace-ISA-unpriv.adoc:2004-2013` defines Form A as the exported-SCC size, but the provisioning fragments at `:2407-2408` and `:2458-2459` run `ace.size` on a register in `_CfgStProvisioning_` and use the result as the PI length — and PI and SCC lengths differ (the SCC adds SIV, IMPQUAL, SIV2). *Specify the result per `_ConfigStatus_` value.*

**M37. `ace.clone` corner cases are unspecified.** `src/ace-ISA-unpriv.adoc:1853-1860`. "A CR whose `_ConfigStatus_` is not `_CfgStComplete_` cannot be cloned" does not say what the attempt does. Cloning onto an occupied destination, `Kd == Ks`, CRF exhaustion, cloning an error-state register (permitted by `:479`), and an `_Off_` source are all undefined. *Enumerate them with defined outcomes.*

**M38. When the `acestart ≤ aceiobuftop ≤ aceiobuflen` constraint is checked is ambiguous.** `src/ace-ISA-unpriv.adoc:895-896`. It is unspecified whether the illegal-instruction exception comes from the CSR write that creates the violation (and which of the three) or from the next instruction that uses the window. Since legitimate reprogramming sequences transiently violate it, implementations diverge and software has no defined safe write order. *Specify check-at-use with WARL clamping, or mandate a write order.*

**M39. `ace.setst` with an inadmissible immediate has no defined outcome.** `src/ace-ISA-unpriv.adoc:1349-1374`. Illegal instruction, `ace_exc_invalid`, transition to `ace_state_invalid`, and silent no-op are all plausible readings for reserved values (30–31), algorithm-undefined values (2–21), and disallowed transitions. *Define one outcome.*

**M40. `ace.clear` and `ace.setst` contradict each other on usage control.** `src/ace-ISA-unpriv.adoc:1380` ("The instruction is usage-controlled") versus `:2191` ("The instruction is not usage-controlled") — for `ace.clear`, which *is* an encoding of `ace.setst` with the `ace_state_off` immediate. The same executed instruction is both. *State that usage control applies except for the Off and error-state immediates.*

**M41. Memory-model gaps beyond the acknowledged TODOs.** `src/ace-ISA-unpriv.adoc:730-746`, `:64-79`, `:2371-2381`. Three things a reviewer should require before freeze: reconciliation of the attached-unit model (operations "execute independently of the issuing hart") with same-hart program-order visibility for ordinary loads and stores to a region an asynchronous `ace.store` is still writing; a normative invariant tying `acestart` to memory visibility on interruption (all bytes below it globally performed, none at or above it performed), without which resumption after migration can skip or double-write; and a forward-progress guarantee for resumable instructions under frequent interrupts.

**M42. Security-critical requirements appear only in informative notes.** `src/ace-ISA-unpriv.adoc:2505-2508` states that a nested export "must be the original encrypted data loaded so far, and not a re-encryption of a partially decrypted payload ... required for both correctness and security" — the rule that prevents a CSK oracle — inside a NOTE in an informative section. Likewise `:682-684` puts the requirement that implementations assign at-least-as-restrictive usage policies to system keys in a note. `src/ace-ISA-algorithms.adoc:829-841` puts a GCM "must" requirement in a NOTE. *Promote all three to normative text.*

**M43. `ace.store` is listed under the wrong extensions.** `src/ace-ISA-unpriv.adoc:1128-1137` lists `Zlv` and `Zlio`, while `ace.load` is in `Zlmem` and the overview defines `Zlmem` as "ACE with dedicated memory instructions"; the `Zlv`/`Zlio` footnotes at `:129-131` do not list `ace.store`. An implementer cannot tell which extension mandates it. *Change to `Zlmem`.*

**M44. `Zlkn` depends on three extensions that do not exist.** `src/ace-ISA-unpriv.adoc:128` names `Zlaes128`, `Zlaes256` and `Zlesha2`; the defined names are `Zlaes128p`, `Zlaes256p` and `Zlesha2h` (`:94`, `:96`, `:105`). The malformed table row also leaves `Zlkn` with no "Defined in" target, and it appears nowhere in Books 2–4 despite being mandated by the `Zlv`/`Zlio` footnotes. *Correct the names and the row.*

**M45. The relationship between `acenonce0/1` and Locality #11 is never stated.** `src/ace-ISA-unpriv.adoc:921-928` says the CSRs "define the nonce to be used in `ace.import` and `ace.export`", while the algorithms take the nonce from `LST[11]` (`:673`, `:2881`, `:2911`). Nothing says the CSRs *are* that entry, and nothing states explicitly that a cleared Nonce Locality bit forces `N` to zero even when the CSRs are programmed. *State the binding and the reset value.*

### Book 2 versus the standards

**M46. No normative byte/bit-ordering convention for symmetric data, and conventions are mixed within single algorithms.**
FIXED

**M47. Core field-arithmetic functions are named but never defined.**
FIXED

**M48. GCM/CTR mode parameters are never instantiated, GCM is silently limited to one IV length, and the exhaustion check is ill-typed.** `src/ace-ISA-algorithms.adoc:647`, `:358-363`, `:750`, `:788`. Nothing fixes `c = 32` (or `j`, `n` for CTR), so conforming implementations can disagree. Only `b-c`-bit IVs are supported — no GHASH-based `J0` for other lengths, a restriction never stated (SP 800-38D §5.2.1.1). The check `ctr = ones(c-1)` compares a `c`-bit counter against a `c-1`-bit value and does not match the 2³²−2 block limit. *Fix the parameters, state the 96-bit-IV restriction, and correct the check.*

**M49. XCTR starts its counter at 0 where XCTR starts at 1.** `src/ace-ISA-algorithms.adoc:408-409`, `:421-423`. ACE's first keystream block is `E_K(IV ⊕ 0) = E_K(IV)`; XCTR as defined in HCTR2 is `E_K(S ⊕ bin(1)) || E_K(S ⊕ bin(2)) || ...`. Anything built on this primitive is incompatible. *Initialize `ctr` to 1, as the LFSR modes already do.*

**M50. EdDSA is mis-cited and unimplementable as parameterized.**
FIXED

**M51. ECC signature operations are underspecified.** `src/ace-ISA-algorithms.adoc:2472`, `:2352`, `:2503-2554`. `_Gen_Rnd_Scalar_` is listed but never described; how `RndNum` is generated (RBG strength, hedged versus deterministic, whether user-supplied) is unstated; which signature equation each family uses is unstated, although ECDSA and SM2 differ; and point encoding is left optional ("non-compressed or compressed points may be used"). Two implementations cannot interoperate. *Specify per-family procedures by reference, mandate encodings, and define the RBG requirements.*

**M52. The ML-DSA section is written in ML-KEM's vocabulary.** `src/ace-ISA-algorithms.adoc:2853`, `:2819`, `:2844`, `:2857-2859`, `:2864`. Behavior clauses refer to `encapsk`, `decapsk`, `ciphertext` and `sharedkey` fields and a `_decapsk_Input_` state, none of which exist for ML-DSA, and the state list is headed "ML-KEM algorithms define". The normative behavior is not decidable from the text. *Rewrite in terms of `privkey`/`pubkey`/`signature` and state whether signing is hedged or deterministic per FIPS 204 §3.4.*

**M53. OCB nonce setup has an undefined parameter, no length bound, and an off-by-one slice.**
FIXED

**M54. Book 4's pseudocode does not match Book 2's state machines.**
FIXED

---

## Minor findings

**Instruction and encoding details.** `ace.getst`'s expansion shifts by 20 where `_State_` is MDH[25:21],x so every example built on it extracts the wrong field (`src/ace-ISA-unpriv.adoc:2227-2229`).
CORRECTED, also added `ace.getstx` for the State_Extension

The `ace.restrict` `v`-bit description is inverted — v=0 selects the GPR forms but the text names `ace.restrictv` (`:1674`). Opcode `0x27` is labelled "custom-1" in three encoding diagrams (`:1077`, `:2060`, `:2121`) although `0x27` is the standard STORE-FP opcode and custom-1 is `0x2b`. `ace.sysimport` appears in the `ace.load` encoding with a second funct3 code point but is never defined (`:1016`). `_UsagePolicy_` maps five modes onto "Bits 0, 1, 2, 4 and 4" (`:308`), skipping bit 3 and colliding M-mode with Debug. `_SystemFormat_` is addressed as "MDH[63:0]" where it is MDH[63] (`:323`). The `_SCProtection_` table reserves all values ≥3 while the following text authorizes implementations to use 6–7 (`:352-367`). Behavior of `ace.getmdh`/`ace.getmdv` on Off or error-state registers is unspecified, as are odd or zero register numbers for every GPR-pair operand on RV32 (`:481-483`, `:1615-1631`). `ace.reset`'s scope over `acestart`, `aceiobuflen` and `acenonce0/1` is unstated, and "ACEIOBUF is enabled" is used without ever defining an enable distinct from `aceiobuflen != 0` (`:2184-2189`). The interruptibility classification omits `ace.getmd*`, `ace.mv`, `ace.derive` and `ace.exec` entirely (`:2317`). `ace.restrict` requires `_State_` = `_Initial_` (`:1704`), so an imported mid-algorithm context can never be narrowed.

**Privileged details.** `misa.L` conflicts with current practice of discovering new extensions through unified discovery rather than new `misa` bits, and the effect of clearing a writable `L` is undefined (`src/ace-ISA-priv.adoc:106-107`). No reset or power-management specification exists for ACE state — reset values of ACES, `*crstatus` and the CSRs, and the security-critical question of whether registers are cleared across reset, suspend or non-retentive power states, are all absent. The consequences of the undecided `Smcsrind`/`Sscsrind` dependency are unanalyzed: all secret CSR groups are specified only as "(Indirect)" with no fallback addresses, so without it they are unaddressable and unvirtualizable (`:35`, `:88-97`). The "up to 3 direct" CSR count is wrong on RV32, where the `*crstatush` shadows are needed and appear in no table (`:80`). `scrstatus`'s existence without the S extension is asserted in a note rather than architected (`:221`). VS/VU CSR accesses are specified to raise illegal-instruction where the hypervisor extension requires virtual-instruction exceptions (`:343`, `:369`, `:382`). Debug-mode access and "Indirect" wording are inconsistent across the secret CSR groups (`:305` versus `:309`, `:330`, `:356`). The claim of "arbitrarily many levels of nested virtualization" (`src/ace-ISA-unpriv.adoc:2349`) is unsupported: there is exactly one `vscrstatus`, one `vsstatus.ACES`, one VirtBootScrt and one S/H Locality level.

**Algorithm details.**
DONE

**Documentation and repository.** The informative code fragments at `src/ace-ISA-unpriv.adoc:2400-2583` contain nonexistent instructions (`subi`, `bz`), reversed store operand order, immediate offsets on vector loads, an `ace.mgmt` operand order inconsistent with its definition, a register clobbered between two uses, an uninitialized register, and a branch to a nonexistent label — significant because `:2358-2359` claims the architecture is co-designed with these sequences. The stale extension name `Zlm` labels three of them (`:2430`, `:2481`, `:2553`). `readme.adoc:32` links to `src/contributors.adoc`, but the file is `src/ace-contributors.adoc`. The readme promises Kalyna and Kuznyechik GCM-SIV that no book delivers, and in Cyrillic script (`readme.adoc:22`). The introduction lists XTS among modes ACE defines, though the books architect only XEX (`src/ace-introduction.adoc:50-54`). CSR names use camelCase (`macePhysBootScrt`, `haceVirtBootScrt`, `maceLocality`), which is unprecedented in RISC-V, and the extension names mix case (`SmaceCSK`) while `Sm*`-prefixed extensions define S-, HS- and VS-mode CSRs. Book 3's extension table calls the two boot secrets "OS Secret Locality" and "Boot Secret Locality", terms defined nowhere and apparently swapped (`src/ace-ISA-priv.adoc:21-22`). `src/ace-examples.adoc` and `src/ace-instruction-summary.adoc` are dead: neither is included, both are wrapped in comment blocks, the summary lists eight obsolete mnemonics (`ace.init`, `ace.export`, `ace.state`, `ace.harden`, `ace.error`, `ace.enable`…), and the examples reference an undefined CSR `acecrstatus` and an undefined term RCSK. The excluded annex duplicates Book 3's `ACE-lazy-loading` anchor (re-inclusion would collide) and uses superseded CSR names. The acronym list has "HV | Hypervisor" twice, expands ASID as "Application Space Identifier" rather than "Address Space Identifier", breaks alphabetical order, and omits ACES, OCB, HMAC, KMAC, SHAKE and URW. Ten bibliography entries are never cited. There is no revision history or change log, and `.github/` has no issue template to guide public-review feedback. Tracked in the public repository: a 2.7 MB PDF, a scratch PDF, working notes (`instructions.txt`, `multiplication.txt`, `src/short names.txt`), five extra Makefile variants including one hardcoding a Qualcomm-internal registry, and an ungitignored 846 KB `src/ace.html`. Spell-check configurations (`cspell.json`, `codebook.toml`, `.harper-dictionary.txt`) are committed but wired into neither pre-commit nor CI.

**Build and version metadata.** `:revnumber: 0.0` in `src/ace.adoc:7` conflicts with `VERSION ?= v0.5.0` in the Makefile, so any build not going through `make` reports 0.0 — and every extension row says "Minimum version v0.0.0". The CI workflow sets `VERSION: v${{ github.event.inputs.version }}`, which on push and pull-request events evaluates to the literal `"v"` with an empty revision mark, overriding the Makefile defaults. CI pre-pulls `riscvintl/riscv-docs-base-container-image` while the Makefile runs `ghcr.io/riscv/riscv-docs-base-container-image`, so the pinned image is not the one used; `readme.adoc:71` documents the stale image too. `:revdate: 6/2025` is stale and in a nonstandard format, and `src/ace.adoc:48-49` carries leftover attributes (`:csrname: envcfg`, `:footnote:`) from another specification's template.

---

## Editorial findings

must -> shall

Typos that garble normative text: "shall be _Off_ or _Other_" (`src/ace-ISA-priv.adoc:197`, in a `shall` sentence); "The CR is may be configured" (`:199`); `ace.mgmtt` in the uninterruptible-instruction list (`src/ace-ISA-unpriv.adoc:2317`); "a CR can be _unconfigured_meaning" (`:155`); "can only be used permitted to transition" (`:458`); `ace.start` used for the CSR `acestart` throughout `:1486-1538`; `ace..restrictv` (`:1770`); "_Failed_" for the state named `_Failure_` (`:456`); "the the" (`:738`, `:1105`); "_Hash_Verify_ -> _Success_ or _Success_" where the second should be `_Failure_` (`src/ace-ISA-algorithms.adoc:1939`); `RFC8452_RFC8452_KeyDeriv` (`:1010`, `:1124`); "computation of teh NTT" (`:2788`); an unfinished sentence "and `block` is clearly also" (`:1636-1637`); "The principal procedures offered by the ML-KEM" heading the ML-DSA section (`:2729`); and a literal author note "**Anything else?**" left in the ML-DSA behavior list (`:2880`). "Risc-V" appears in the document's own disclaimer (`src/ace.adoc:87`, `src/ace-introduction.adoc:64`).

Naming and terminology drift: the readme expands CR as "Cryptographic Register" while the acronym table and body use "Context Register", and a Book 1 heading uses the former (`src/ace-ISA-unpriv.adoc:183`); the whitepaper expands ACE as "Atomic Cryptographic Extension" against the title's "Atomic Cryptography Extension"; the title claims "ZL" (capital) while all sub-extensions use `Zl` and "Z" names take lowercase; Book 2 requires `Zlcmac` where Book 1 defines `Zlcmacm` (`src/ace-ISA-algorithms.adoc:40`); the CSR section heading says `acevendorid`/`acearchid`/`aceimpid` while the body defines `acemvendorid`/`acemarchid`/`acemimpid`; Book 4 calls the same in-memory object a "CC" in half its examples and an "SCC" in the other half; and "a SCC" appears ten times against twenty-two of "an SCC".

---

## Appendix A — Items the authors have already flagged

These are not review findings; they are the specification's own open questions, listed so the review's scope is clear.

| Location | Open item |
|---|---|
| `src/ace-introduction.adoc:119-128` | TODO section: finalize RVV-mini; possible rename of `ace.`/CR to `kl.`/"Cryptographic Locker"; whether a Mode should be prevented from provisioning keys usable by higher-privileged Modes |
| `src/ace.adoc:87` | Preamble warning: ISA and non-ISA parts not separated; language may not follow RISC-V guidelines |
| `src/ace-ISA-unpriv.adoc:247-251` | RVV-mini subset not finalized; `Zvbc` `vclmul*` dependency undecided |
| `src/ace-ISA-unpriv.adoc:742-746`, `:2367-2370` | Memory model needs formal definition; LSU ordering for resumption to be discussed with the ARC |
| `src/ace-ISA-unpriv.adoc:948-951` | "The encodings presented here are preliminary" |
| `src/ace-ISA-unpriv.adoc:1353-1356`, `:1399-1402` | Possible re-encoding of `ace.mgmt` as `ace.setst` with `#immed7 ≥ 96` |
| `src/ace-ISA-unpriv.adoc:1880-1883` | `ace.derive` unused by any algorithm; encoding reserved |
| `src/ace-ISA-unpriv.adoc:108-109` | `Zlhmacm`/`Zlkmacm` "Defined in: TBD" |
| `src/ace-ISA-unpriv.adoc:759-768`, `src/ace-ISA-priv.adoc:88-97` | All CSR addresses are `0xXXX` placeholders |
| `src/ace-ISA-unpriv.adoc:2414`, `:2439`, `:2496`, `:2505-2508`, `:2586-2587` | Inline open questions in the code examples; whether concurrent exports are permitted |
| `src/ace-ISA-algorithms.adoc:22`, `:32`, `:34` | "(reserved)" = "specification not yet complete or contains ambiguities", applied to the LFSR modes |
| `src/ace-ISA-algorithms.adoc:1858-1861` | "In all ASCON algorithms, the ordering of the bits must be verified!" — see C22–C27 |
| `src/ace-ISA-algorithms.adoc:2809` | ML-DSA serialized-context sizes TBD |
| `src/ace-ISA-priv.adoc:35` | `Smcsrind`/`Sscsrind` dependency to be decided with the ARC |
| `src/ace-ISA-priv.adoc:47`, `:63-68`, `:71-74` | Exception cause numbers TBD; proposal to merge `ace_exc_CR_unconf` into `ace_exc_invalid` |
| `src/ace-ISA-priv.adoc:254-258` | `mcrstatus` "may be defined" |
| `src/ace-ISA-priv.adoc:386-417` | Emulated Operations section non-normative and commented out |
| `src/ace-annexes.adoc:33-34`, `:150-151`, `:213-237` | Lazy loading "requires careful consideration"; `Ztac` try/catch and horizontal traps open, whole sections commented out |
| `src/ace-examples.adoc:8-9` | Context-switching example is "TBD" |

## Appendix B — Suggested priorities

1. Rewrite Book 2's mode definitions against the cited standards and add known-answer test vectors for every algorithm (C14–C29, M46–M53). Test vectors would have caught nearly all of these mechanically.
2. Rework the SCC sealing construction — nonce-bearing key derivation, RFC 8452 length block, a working authentication check, and anti-replay — then have it analyzed independently (C1–C4, C6, M2).
3. Promote the threat model into the normative document and state the trust boundaries, particularly M-mode's (M1).
4. Resolve the register-sharing and provenance question, the Debug-mode default, and zeroization (C5, C7, C8, M5, M6).
5. Fix the hypervisor state-management model so ACE state can actually be saved, restored and migrated (C9, M17–M26).
6. Do a consistency pass that reconciles instruction names, extension names, CSR units and state machines across all four books (C10–C13, M28–M45, M54).
