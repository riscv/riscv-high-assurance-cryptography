# Public Review — RISC-V Atomic Cryptography Extension (ACE)


1. **Book 2's algorithm definitions do not match the standards they cite.**
**FIXED**

2. **The SCC sealing construction is not AES-GCM-SIV, and its authentication check does not work.**
**FIXED**

3. **Several security guarantees the introduction claims are not enforced by the architecture.**
Debug mode is permitted to *use* every resident context by default;
**FIXED**
SCC have no anti-replay, so re-importing an old SCC rolls counter-mode state back and reuses keystream;
**THIS IS BY DESIGN**

The threat model is currently **excluded from the built document** (`src/ace.adoc:105` comments out the annex include) and is marked non-normative where it does exist. For a specification whose entire value proposition is a security guarantee, that is a structural gap: there is no baseline against which any conformance claim can be evaluated.
**MOVED TO REDUCE COMPLAINTS**

**Recommendation:** the specification is not ready to freeze. The Book 2 algorithm definitions should be rewritten against the standards with test vectors added, the SCC construction reworked and analyzed, and the threat model promoted into the normative document, before a public review milestone is declared.

---

## Critical findings

### Sealed Cryptographic Context construction

**C1. The SCC import authentication check is inoperative.**
**FIXED**

**C2. Key derivation omits the nonce, so the construction is not AES-GCM-SIV and has no applicable security proof.**
**FIXED**, except that since this mode is nonce-misuse resistant, the nonce can be 0. Intel does the same. In our case the nonce is optional.

**C3. POLYVAL is invoked without RFC 8452's length block.**
**BY DESIGN: Length is still encoded, but in the MDH**

**C4. The import and export algorithms contain errors that make them unimplementable as written.**
**FIXED**


### Security architecture

**C5. Debug mode may use every resident context by default, and nothing is zeroized on debug entry.**
**FIXED**, also added questions to ARC.

**C6. SCCs have no anti-replay, so re-import rolls algorithm state back and reuses keystream.**
**BY DESIGN**
THIS IS KNOWN, and by choice, to avoid over complication.
Addressed any ambiguity in <<ACE-management-operations>>

**C7. Registers are shared across privilege modes while management instructions are not usage-controlled, permitting context substitution.**
**This is by design, otherwise we cannot perform context switching.**

**C8. Verbatim export of a partially configured register can dump generated or system key material in the clear.**
**FIXED** for random values, however, this does not affect System Keys because these are never exposed outside the CR by other rules.
*Resolution:* require that random generation and SKS materialization occur only at `ace_CR_provision_end`, and forbid verbatim export of any register holding material the exporting context did not supply.


### Privileged architecture

**C9. Write-only secret CSRs are writable by the mode below the one that must manage them, making hypervisor save/restore and VM migration impossible.**
**FIXED**
### Instruction definitions

**C10. `ace.mv`'s encoding and description specify opposite data directions.**
I THINK **FIXED** NOW

**C11. `ace.exec` Forms B and D leave the register index unencodable.**
I THINK **FIXED** NOW

### Cross-book contradictions

**C12. HMAC and KMAC have extensions and algorithm encodings but no definition, and Book 2 denies they are needed.**
HMAC **FIXED**
KMAC **FIXED**

**C13. Book 1 restricts the block-cipher modes to AES; Book 2 defines them for SM4.**
**FIXED**

### Algorithm definitions versus published standards

**C14. GCM counter values are off by one from SP 800-38D.**
**FIXED**

**C15. GCM decryption's tag finalization uses a malformed counter expression.**
**FIXED**

**C16. GCM-SIV derives its keys before the nonce is set.**
**FIXED** (in a different way)

**C17. GCM-SIV clears the tag's top bit after encryption, producing wrong tags and one-bit malleability.**
**FIXED** (I think)

**C18. The GCM-SIV counter-exhaustion check invalidates the register on the first block.**
**FIXED** (OOOPS)

**C19. GCM and GCM-SIV are given the identical length-block formula although the two standards use opposite conventions.**
**FIXED** ADDED BIG ENDIANNESS CONDITIONS TO GCM

**C20. OCB's offset schedule is not RFC 7253's.**
**FIXED**

**C21. OCB's final-block tag computation deviates from RFC 7253 in two ways.**
**FIXED**

**C22.  absorbs associated data with the permutation on the wrong side.**
**FIXED**

**C23. Ascon's domain-separation bit is applied to the wrong bit of the state word.**
**FIXED**

**C24. Ascon decryption swaps the halves of its output relative to encryption.**
**FIXED**

**C25. Ascon cannot decrypt standard length-preserving ciphertexts.**
**FIXED**

**C26. Ascon-Hash256 applies one permutation too many before the first output block.**
**FIXED**

**C27. Ascon-XOF128's IV is Ascon-Hash256's IV.**
**FIXED**

**C28. ML-KEM provides no way to input a ciphertext, so peer ciphertexts cannot be decapsulated.**
**FIXED**

**C29. P-521 ECDSA nonces are specified with 512 bits of randomness for a 521-bit group order.**
**FIXED**
---

## Major findings

### Security architecture

**M1. The threat model is excluded from the built document, non-normative where it exists, and omits major attacker classes.**
**FIXED**
BROUGHT back to the main doc (introduction)  but it is not clear what else we can enforce

**M2. The CSK has no architectural requirements.** `src/ace-ISA-priv.adoc:300-317`.
**FIXED**

**M3. The VM-migration claim requires exporting the CSK — escrow of every sealed context — through an unspecified mechanism.**
**FIXED** It is an IMPLEMENTATION DEFINED.

**M4. Localities do not isolate resident contexts, and their stated domains contradict their per-hart storage.**
**DONE:**

**M5. Zeroization is never actually guaranteed.**  *Define "zeroize" once and require it at each of these points.*
**DONE**

**M6. A usage-policy violation destroys the context, giving any lower-privileged mode a cross-domain kill primitive.**
**THIS IS BY CHOICE**
**HIGHER PRIVILEGED MODES MUST SAVE THE CCs THEY CARE ABOUT**
(They do not expect lower privileged modes to respect their GPRs or FP registers, right?)

**M7. `ace.restrictv` is specified to rewrite the entire MDH with no monotonicity constraint.** `
**FIXED**

**M8. `_SCProtection_` levels are unordered, unrestrictable, and contradicted by their own rationale note.**
I think the LLM here misunderstood what we have written.

**M9. DIEL is claimed as a protection level but never normatively defined.**
REVIEWER ERROR

**M10. `_ExpirationDate_` depends on an undefined "secure clock" with no rollback resistance.**
**FIXED** To the extent tht it is possible.

**M11. `ace.derive` has no restriction-inheritance rules.**
**FIXED**

**M12. `ace.clone` does not state that policy metadata is copied, and is not usage-controlled.**
**DONE:** Added explicit statement, also "The instruction is not usage-controlled." was already there

**M13. Random key generation has no entropy-source requirement.** `src/ace-ISA-unpriv.adoc:383-384`.
**FIXED**

**M14. The `_SystemFormat_` escape hatch is unbounded and ungated.** `src/ace-ISA-unpriv.adoc:320-324`, `:1045-1047`.
18.  Setting one MDH bit makes the remaining format "entirely system specific" and the semantics of `ace.load` "entirely implementation dependent", voiding metadata validation, sealing, Localities and usage control — with no requirement that a system-defined format preserve confidentiality or integrity, and no privilege gate on setting the bit. A conforming implementation could define a system format whose load/store path moves plaintext keys. *Require system formats to preserve the Content confidentiality/integrity invariant and restrict the bit to a platform-authorized context.*
**I DO NOT REALLY SEE THIS ISSUE**

**M15. The `ace.mgmt` terminator state machine permits an authentication-bypass path.**
**NO, it does not, but we now use clearer wording.**
**FIXED**

**M16. CRF security requirements are inconsistent with the declared adversary.**
**FIXED**

### Privileged architecture and state model

**M17. `mstatus.TSR` and `hstatus.VTSR` are overloaded to trap ACE memory instructions.**
**FIXED**

**M18. No `Smstateen`/`Ssstateen` integration for the new less-privileged state.**
**FIXED** we do not need these mechanisms, since we have the Off ACES.

**M19. ACES Initial/Clean semantics are underspecified and contradict the FS/VS/XS rules they incorporate.** `
**OVERZEALOUS REVIEWER**

**M20. Behavior of ACE CSR accesses when ACES=Off is unspecified.**
**FIXED**

**M21. `scrstatus` write semantics are unspecified and its invariants are software-violable.** `src/ace-ISA-priv.adoc:187-219`. The register is SRW, but nothing says what happens when software writes values inconsistent with actual register state (Off or Clean for a configured register, Clean for an unconfigured one) — whether writes are WARL-adjusted, ignored, or take effect and break the invariants that the exception semantics depend on. *Specify per-field WARL legalization.*

**M22. `mcrstatus`'s normative status is self-contradictory, and lazy loading depends on it.** `src/ace-ISA-priv.adoc:254-258` is a warning saying it "may be defined", while the extension table (`:19`) and CSR table (`:90`) list it as defined by `Smacestatus`; the lazy-SCC ownership search at `:287` ("search privilege modes from M-mode downward") needs it. The proposed remedy — making `sstatus.ACES` "unshadowed and independent" — would violate the rule that `sstatus` is a restricted view of `mstatus`. *Decide it normatively and keep `sstatus.ACES` a view of `mstatus.ACES`.*

**M23. The `vscrstatus` section is a copy-paste of `scrstatus`.**
**FIXED**

**M24. "Propagation" of `*crstatus` is asserted but never defined, and the V=1 rules omit the HS-level view.** `src/ace-ISA-priv.adoc:294-296`, `:241-245`. There is no propagation concept for FS/VS in the base architecture to be "analogous to", and the V=1 rules set only `vscrstatus`(i) Dirty, leaving unstated whether `scrstatus`(i) is also updated — which breaks hypervisor-level lazy tracking. The ACES rule at `:171` does set both, so the asymmetry looks unintentional. *Give explicit rules.*
**HOW**

**M25. Trap-and-emulate has no effective-privilege mechanism, and hypervisors are forbidden from emulating.**
**REVIEWER ERROR**

**M26. Trap behavior beyond cause numbers is undefined.**
**NO NEED SINCE THE TRAP HANDLER ALREADY HAS ALL THE INFORMATION**
(do we want to provide extra information?)

**M27. Exceptions `ace_exc_CR_unconf` and `ace_exc_CR_other` are defined in Book 3 but raised by no Book 1 instruction.**
**FIXED** they stay. The definitions in Book 3 are fine.

### Book 1 instruction and CSR definitions

**M28. `acestart` resume state is bound to no instruction or register.**
**REVIEWER ERROR**

**M29. Trap and resume PC behavior for interrupted instructions is never specified.** `src/ace-ISA-unpriv.adoc:2314-2341`. Nothing says that a trap mid-instruction sets xEPC to the ACE instruction so re-execution resumes at `acestart`, what `xtval` reports for a page fault inside a long `ace.load`, or whether partial updates before the fault are architecturally visible. Resumability is not portably implementable without this. *Add normative text modelled on the vector extension's `vstart` rules.*

**M30. The CSR chapter lacks reset values and WARL/WLRL discipline, and value-dependent write traps break save/restore.** `src/ace-ISA-unpriv.adoc:748-941`, `:819`, `:865`. No ACE CSR has a defined reset value or WARL/WLRL classification. Trapping on a *value* written to a CSR is unusual for RISC-V, and here `acestart`'s legal set is dynamic, so context-restore or migration code writing back a saved `acestart` on an implementation that does not support resumption (permitted by `:2356`) traps unpredictably. Raising `ace_exc_out_of_mem` from a CSR write is unprecedented. *Assign reset values, classify the fields, and replace value-dependent traps with WARL behavior.*

**M31. `aceiobuflen` is defined in bytes in one place and bits in another.**
**FIXED: CHANGED TO BYTES**

**M32. The exception model is inconsistent about the privileged architecture and uses a nonexistent exception name.**
Invalid instruction exception -> illegal-instruction exception **FIXED**

**M33. Behavior of suppressed or disallowed operations is unspecified.** `src/ace-ISA-unpriv.adoc:456`, `:485-487`, `:1193-1206`. When an operation is suppressed (error state, usage violation, expiration), nothing says what is written to `Vd`, `Xd` or the ACEIOBUF — unchanged, zeroed or undefined — so implementations diverge and stale contents may leak. Rule 2 says only certain instructions "are permitted" in `_Success_`/`_Failed_` without defining what a non-permitted one does. `ace.exec` on an unconfigured register is covered by no rule, and there is no specification for operand-length mismatch. *Add a normative table of condition → exception, state transition, and destination effect.*

**M34. Instructions `ace.prov`, `ace.export` and `ace.export` are mandated and referenced across all three books but defined nowhere.**
**FIXED**

**M35. `ace.mgmt export_start` takes "no auxiliary input" yet its semantics depend on a scalar/vector variant.**
**FIXED**

**M36. `ace.size` semantics during provisioning and import are undefined although the canonical code depends on them.** `src/ace-ISA-unpriv.adoc:2004-2013` defines Form A as the exported-SCC size, but the provisioning fragments at `:2407-2408` and `:2458-2459` run `ace.size` on a register in `_ace_cfgst_Provisioning_` and use the result as the PI length — and PI and SCC lengths differ (the SCC adds SIV, IMPQUAL, SIV2). *Specify the result per `_ConfigStatus_` value.
**NEED TO DOUBLE-CHECK**

**M37. `ace.clone` corner cases are unspecified.** `src/ace-ISA-unpriv.adoc:1853-1860`. "A CR whose `_ConfigStatus_` is not `_ace_cfgst_complete_` cannot be cloned" does not say what the attempt does. Cloning onto an occupied destination, `Kd == Ks`, CRF exhaustion, cloning an error-state register (permitted by `:479`), and an `_Off_` source are all undefined. *Enumerate them with defined outcomes.*

**M38. When the `acestart ≤ aceiobuftop ≤ aceiobuflen` constraint is checked is ambiguous.**
**DONE:**

**M39. `ace.setst` with an inadmissible immediate has no defined outcome.**
**FIXED**

**M40. `ace.clear` and `ace.setst` contradict each other on usage control.**
**FIXED**

**M41. Memory-model gaps beyond the acknowledged TODOs.** `src/ace-ISA-unpriv.adoc:730-746`, `:64-79`, `:2371-2381`. Three things a reviewer should require before freeze: reconciliation of the attached-unit model (operations "execute independently of the issuing hart") with same-hart program-order visibility for ordinary loads and stores to a region an asynchronous `ace.store` is still writing; a normative invariant tying `acestart` to memory visibility on interruption (all bytes below it globally performed, none at or above it performed), without which resumption after migration can skip or double-write; and a forward-progress guarantee for resumable instructions under frequent interrupts.

**M42. Security-critical requirements appear only in informative notes.** `src/ace-ISA-unpriv.adoc:2505-2508` states that a nested export "must be the original encrypted data loaded so far, and not a re-encryption of a partially decrypted payload ... required for both correctness and security" — the rule that prevents a CSK oracle — inside a NOTE in an informative section. Likewise `:682-684` puts the requirement that implementations assign at-least-as-restrictive usage policies to system keys in a note. `src/ace-ISA-algorithms.adoc:829-841` puts a GCM "must" requirement in a NOTE. *Promote all three to normative text.*

**M43. `ace.store` is listed under the wrong extensions.** `src/ace-ISA-unpriv.adoc:1128-1137` lists `Zklv` and `Zklio`, while `ace.load` is in `Zklmem` and the overview defines `Zklmem` as "ACE with dedicated memory instructions"; the `Zklv`/`Zklio` footnotes at `:129-131` do not list `ace.store`. An implementer cannot tell which extension mandates it. *Change to `Zklmem`.*

**M44. `Zklkn` depends on three extensions that do not exist.**
**FIXED**

**M45. The relationship between `acenonce0/1` and Locality #11 is never stated.**
**FIXED** by removing the nonce.

### Book 2 versus the standards

**M46. No normative byte/bit-ordering convention for symmetric data, and conventions are mixed within single algorithms.**
**FIXED**

**M47. Core field-arithmetic functions are named but never defined.**
**FIXED**

**M48. GCM/CTR mode parameters are never instantiated, GCM is silently limited to one IV length, and the exhaustion check is ill-typed.**
**FIXED**

**M49. XCTR starts its counter at 0 where XCTR starts at 1.**
**FIXED**

**M50. EdDSA is mis-cited and unimplementable as parameterized.**
**FIXED**

**M51. ECC signature operations are underspecified.**
**FIXED**

**M52. The ML-DSA section is written in ML-KEM's vocabulary.**
**FIXED**

**M53. OCB nonce setup has an undefined parameter, no length bound, and an off-by-one slice.**
**FIXED**

**M54. Book 4's pseudocode does not match Book 2's state machines.**
**FIXED** (for now)

---

## Minor findings

**Instruction and encoding details.** `ace.getst`'s expansion shifts by 20 where `_State_` is MDH[25:21],x so every example built on it extracts the wrong field (`src/ace-ISA-unpriv.adoc:2227-2229`).
CORRECTED, also added `ace.getstx` for the State_Extension

`ace.sysimport` appears in the `ace.load` encoding with a second funct3 code point but is never defined (`:1016`).  Behavior of `ace.getmdh`/`ace.getmdv` on Off or error-state registers is unspecified, as are odd or zero register numbers for every GPR-pair operand on RV32 (`:481-483`, `:1615-1631`). `ace.reset`'s scope over `acestart`, and `aceiobuflen`, and "ACEIOBUF is enabled" is used without ever defining an enable distinct from `aceiobuflen != 0` (`:2184-2189`). The interruptibility classification omits `ace.getmd*`, `ace.mv`, `ace.derive` and `ace.exec` entirely (`:2317`).

**`ace.restrict` requires `_State_` = `_Initial_` (`:1704`), so an imported (or derived!) mid-algorithm context can never be narrowed.**
**FIXED**

**Privileged details.** `misa.L` conflicts with current practice of discovering new extensions through unified discovery rather than new `misa` bits, and the effect of clearing a writable `L` is undefined (`src/ace-ISA-priv.adoc:106-107`). No reset or power-management specification exists for ACE state — reset values of ACES, `*crstatus` and the CSRs, and the security-critical question of whether registers are cleared across reset, suspend or non-retentive power states, are all absent. The consequences of the undecided `Smcsrind`/`Sscsrind` dependency are unanalyzed: all secret CSR groups are specified only as "(Indirect)" with no fallback addresses, so without it they are unaddressable and unvirtualizable (`:35`, `:88-97`). The "up to 3 direct" CSR count is wrong on RV32, where the `*crstatush` shadows are needed and appear in no table (`:80`). `scrstatus`'s existence without the S extension is asserted in a note rather than architected (`:221`). VS/VU CSR accesses are specified to raise illegal-instruction where the hypervisor extension requires virtual-instruction exceptions (`:343`, `:369`, `:382`). Debug-mode access and "Indirect" wording are inconsistent across the secret CSR groups (`:305` versus `:309`, `:330`, `:356`). The claim of "arbitrarily many levels of nested virtualization" (`src/ace-ISA-unpriv.adoc:2349`) is unsupported: there is exactly one `vscrstatus`, one `vsstatus.ACES`, one VirtBootScrt and one S/H Locality level.

**Algorithm details.**
**DONE**

**Documentation and repository.** The informative code fragments at `src/ace-ISA-unpriv.adoc:2400-2583` contain nonexistent instructions (`subi`, `bz`), reversed store operand order, immediate offsets on vector loads, a register clobbered between two uses, an uninitialized register, and a branch to a nonexistent label — significant because `:2358-2359` claims the architecture is co-designed with these sequences. The stale extension name `Zklm` labels three of them (`:2430`, `:2481`, `:2553`). `readme.adoc:32` links to `src/contributors.adoc`, but the file is `src/ace-contributors.adoc`.

*Book 3's extension table calls the two boot secrets "OS Secret Locality" and "Boot Secret Locality"*,* terms defined nowhere and apparently swapped (`src/ace-ISA-priv.adoc:21-22`). `src/ace-examples.adoc`
**FIXED**

* Ten bibliography entries are never cited. There is no revision history or change log, and `.github/` has no issue template to guide public-review feedback. Tracked in the public repository: a 2.7 MB PDF, a scratch PDF, working notes (`instructions.txt`, `multiplication.txt`, `src/short names.txt`), five extra Makefile variants including one hardcoding a Qualcomm-internal registry, and an ungitignored 846 KB `src/ace.html`. Spell-check configurations (`cspell.json`, `codebook.toml`, `.harper-dictionary.txt`) are committed but wired into neither pre-commit nor CI.

The introduction lists XTS among modes ACE defines, though the books architect only XEX (`src/ace-introduction.adoc:50-54`).
**KNOWN, NEED TO ADDRESS**

and `src/ace-instruction-summary.adoc` are dead: neither is included, both are wrapped in comment blocks, the summary lists eight obsolete mnemonics (`ace.init`, `ace.export`, `ace.state`, `ace.harden`, `ace.error`, `ace.enable`…),  
**FIXED** (it is also not included, but may be in the future)

CSR names use camelCase (`macephysbootscrt`, `hacevirtbootscrt`, `macelocality`), which is unprecedented in RISC-V,
**FIXED**

and the extension names mix case (`SmaceCSK`) while `Sm*`-prefixed extensions define S-, HS- and VS-mode CSRs.
**TBD**

The readme promises Kalyna and Kuznyechik GCM-SIV that no book delivers, and in Cyrillic script (`readme.adoc:22`).  
**WE DO NOT STRICTLY PROMISE THEM, BUT WE CAN GIVE THEM ENCODINGS**
---

## Editorial findings

must -> must

Typos that garble normative text: "must be _Off_ or _Other_" (`src/ace-ISA-priv.adoc:197`, in a `must` sentence); "The CR is may be configured" (`:199`); `ace.mgmtt` in the uninterruptible-instruction list (`src/ace-ISA-unpriv.adoc:2317`); "a CR can be _unconfigured_meaning" (`:155`); "can only be used permitted to transition" (`:458`); `ace.start` used for the CSR `acestart` throughout `:1486-1538`; `ace..restrictv` (`:1770`);  `RFC8452_RFC8452_KeyDeriv` (`:1010`, `:1124`); an unfinished sentence "and `block` is clearly also" (`:1636-1637`); "The principal procedures offered by the ML-KEM" heading the ML-DSA section (`:2729`); and a literal author note "**Anything else?**" left in the ML-DSA behavior list (`:2880`). "Risc-V" appears in the document's own disclaimer (`src/ace.adoc:87`, `src/ace-introduction.adoc:64`).

Naming and terminology drift: the readme expands CR as "Cryptographic Register" while the acronym table and body use "Context Register", and a Book 1 heading uses the former (`src/ace-ISA-unpriv.adoc:183`); the whitepaper expands ACE as "Atomic Cryptographic Extension" against the title's "Atomic Cryptography Extension"; the title claims "ZL" (capital) while all sub-extensions use `Zkl` and "Z" names take lowercase; Book 2 requires `Zklcmac` where Book 1 defines `Zklcmacm` (`src/ace-ISA-algorithms.adoc:40`); ; Book 4 calls the same in-memory object a "CC" in half its examples and an "SCC" in the other half; and "an SCC" appears ten times against twenty-two of "an SCC".

---

## Appendix A — Items the authors have already flagged

These are not review findings; they are the specification's own open questions, listed so the review's scope is clear.

| Location | Open item |
|---|---|
| `src/ace-introduction.adoc:119-128` | TODO section: finalize RVV-mini; possible rename of `ace.`/CR to `kl.`/"Cryptographic Locker"; whether a Mode should be prevented from provisioning keys usable by higher-privileged Modes |
| `src/ace.adoc:87` | Preamble warning: ISA and non-ISA parts not separated; language may not follow RISC-V guidelines |
| `src/ace-ISA-unpriv.adoc:247-251` | RVV-mini subset not finalized; `Zvbc` `vclmul*` dependency undecided |
| `src/ace-ISA-unpriv.adoc:742-746`, `:2367-2370` | Memory model needs formal definition; LSU ordering for resumption to be discussed with the ARC |
| `src/ace-ISA-unpriv.adoc:2414`, `:2439`, `:2496`, `:2505-2508`, `:2586-2587` | Inline open questions in the code examples; whether concurrent exports are permitted |
| `src/ace-ISA-priv.adoc:35` | `Smcsrind`/`Sscsrind` dependency to be decided with the ARC |
| `src/ace-ISA-priv.adoc:386-417` | Emulated Operations section non-normative and commented out |
| `src/ace-examples.adoc:8-9` | Context-switching example is "TBD" |

## Appendix B — Suggested priorities

1. Rewrite Book 2's mode definitions against the cited standards and add known-answer test vectors for every algorithm (C14–C29, M46–M53). Test vectors would have caught nearly all of these mechanically.
6. Do a consistency pass that reconciles instruction names, extension names, CSR units and state machines across all four books (C10–C13, M28–M45, M54).

DONE 2. Rework the SCC sealing construction — nonce-bearing key derivation, RFC 8452 length block, a working authentication check, and anti-replay — then have it analyzed independently (C1–C4, C6, M2).
DONE 3. Promote the threat model into the normative document and state the trust boundaries, particularly M-mode's (M1).
DONE 4. Resolve the register-sharing and provenance question, the Debug-mode default, and zeroization (C5, C7, C8, M5, M6).
DONE 5. Fix the hypervisor state-management model so ACE state can actually be saved, restored and migrated (C9, M17–M26).


* *Trap behavior beyond cause numbers is undefined.*
**NO NEED SINCE THE TRAP HANDLER ALREADY HAS ALL THE INFORMATION**

* Specify the result of `ace.size` per `_ConfigStatus_`
**DOUBLE-CHECK IT HAS BEEN CHANGED CORRECTLY**
