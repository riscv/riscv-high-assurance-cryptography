## Assistant

I've read the complete specification — `ace.adoc` and all 13 included files (~9,300 lines), including both normative Books 1–3, the informative Book 4, and the notation/introduction front matter. Below is the full adversarial review.

---

# Review of the RISC-V Atomic Cryptography Extension (Zkl / ACE), rev. 0.6.0

## 1. Executive Assessment

**Not ready for candidacy.** The architectural concept (opaque Cryptographic Contexts, sealed export/import, locality binding) is coherent and in several places carefully engineered (e.g., the endianness discipline, the SCC two-segment binding via `SIV` as AD, the single-share export rule, the deferred generation of random material at provisioning completion). However, the document is not yet a specification that two independent teams could implement interoperably, for four structural reasons:

1. **The error/exception architecture is internally incoherent** — normative text references exception codes and states that do not exist in the document (`ace_exc_CR_off`, `ace_exc_CR_other`, `_Hidden_`, `Lazy`), and the behavior of suppressed/disallowed operations is explicitly unspecified (a gap the authors themselves flag in the introduction's TODO list).
2. **Several core semantic definitions are missing or contradictory** — the ECC point-multiplication operation is never actually defined; the `Zklio` input-window semantics contradict themselves; the GCM IV-length interface disagrees on units between the API and the internal algorithm; the SCC export/import completion protocol is incomplete (author-flagged `WARNING`).
3. **Known open items block freeze**: opcodes squat on `custom-0/1/2`, cause codes are TBD, `misa.L`/`mstatus[26:25]` allocations are provisional, RVV-mini is unfinalized yet a normative dependency, and the memory-model/forward-progress gaps in §Introduction TODO are real and severe.
4. **At least one algorithm has an architecturally sanctioned catastrophic misuse path** (Ascon-AEAD128 with set nonce, C5), and the sealing construction's fixed zero nonce is asserted safe without the quantitative analysis the cited RFC requires (M2).

The document is a strong late-stage draft. With the C findings resolved and the M findings triaged, it could plausibly reach candidacy in one or two revision cycles.

---

## 2. Findings

### Critical

---

**C1 — Behavior of suppressed and disallowed operations is unspecified; multiple overlapping error models coexist**

- **Severity rationale:** Unspecified behavior at every error boundary of a security ISA is both a security defect (implementations will diverge on whether destinations are written, states change, or traps fire) and an interoperability blocker.
- **Location:** `ace-ISA-unpriv.adoc` §_State_ field rules (lines ~476–519), §Generic Rules (`ace-ISA-algorithms.adoc` lines 176–182), `ace.setst` description; author-acknowledged in `ace-introduction.adoc` lines 118–120.
- **Description:** The specification uses at least four distinct error behaviors — illegal-instruction exception, `ace_exc_*` exception ("if the Privileged Architecture is implemented"), silent transition to an Error State, and silent no-op — with no normative rule assigning conditions to behaviors. Examples of direct conflict: Book 2 Generic Rule 2 says a disallowed usage instruction raises an *illegal-instruction exception and invalidates the CR*, while Book 1 State rule 13 says use of a CR in an Error State "will not perform any operation" and leaves _State_ unchanged (no exception mentioned), and rule 14 says a Usage-Policy violation silently sets `ace_state_priv_viol`. Nothing specifies what is written to `Vd`, `Xd`, or the ACEIOBUF when an operation is suppressed. State rule 2 lists instructions "permitted" in _Success_/_Failure_ but omits `ace.getmd*` — on which the *permitted* `ace.getst` pseudo-instruction is built — and never says what a non-permitted instruction does.
- **Reasoning:** The introduction's own TODO ("Add a normative table of condition → exception, state transition, and destination effect") concedes the gap. RISC-V conventions (unprivileged spec §"Exceptions") require each exception condition to be architecturally defined; "safe" implementations cannot be assumed.
- **Proposed resolution:** Add a single normative table with columns *Condition | Instruction class | Trap (cause) | _State_ effect | _ConfigStatus_ effect | Destination (Vd/Xd/ACEIOBUF) effect | `acestart` effect*, and make every algorithm section reference it instead of restating behavior. State explicitly: "If an operation is suppressed, `Vd`/`Xd`/ACEIOBUF and all CR state other than the specified _State_ transition are unchanged."

---

**C2 — Dangling exception codes and CR states: `ace_exc_CR_off`, `ace_exc_CR_other`, `_Hidden_`, and `Lazy` are referenced normatively but never defined**

- **Severity rationale:** Normative dependencies on nonexistent architecture make the trap architecture unimplementable and conceal a security-relevant mechanism (lazy CR virtualization) whose definition exists only in commented-out text.
- **Location:** `ace-ISA-priv.adoc` exception table (lines 48–68) and the NOTE below it (lines 70–94); `ace-ISA-unpriv.adoc` §_ConfigStatus_ (line 646). The Lazy/`ace_exc_CR_other` machinery appears only inside `////` comment blocks (`ace-ISA-priv.adoc` lines 317–722).
- **Description:** (a) Book 1 mandates that misuse of a not-fully-configured CR "will raise exception `ace_exc_CR_off`", but that code is absent from the Book 3 cause table. (b) The Book 3 NOTE discusses "exemptions listed for `ace_exc_CR_off`" that are listed nowhere. (c) The same NOTE normatively describes `ace_exc_CR_other` and a "Lazy" `*lcrstatus` value; the active `*lcrstatus` encoding defines only Off/Initial/Clean/Dirty. (d) The cause table defines `ace_exc_CR_hidden` for "a CR in `*lcrstatus` _Hidden_" — a state that exists nowhere (and `*lcrstatus` is itself a typo for `*lcrstatus`).
- **Reasoning:** Cross-reference reconciliation across Books 1 and 3 fails; an implementer cannot determine the trap behavior for partially configured or lazily saved CRs.
- **Proposed resolution:** Either (i) restore the lazy-CR sections as normative text, define a `Lazy` encoding in `*lcrstatus`, and add `ace_exc_CR_off` and `ace_exc_CR_other` (or rename) to the cause table with their exemption lists; or (ii) delete `ace_exc_CR_hidden`/`ace_exc_CR_other` and rewrite the `ace_exc_CR_off` sentence in §_ConfigStatus_ to name a defined cause.

---

**C3 — No forward-progress guarantee for resumable instructions; missing `acestart`↔memory-visibility invariant (author-acknowledged)**

- **Severity rationale:** Nontermination: because "an implementation always has the option to restart an operation instead of resuming it, for any reason, and may ignore and clear `acestart`" (`ace-ISA-unpriv.adoc` line 2669), a long `ace.load`/`ace.store`/`ace.exec` on such an implementation makes zero guaranteed progress under a periodic interrupt whose period is shorter than the full transfer — a livelock reachable with an ordinary timer. Separately, without a normative invariant tying `acestart` to which bytes are globally visible, resumption after migration can skip or double-write bytes.
- **Location:** `ace-ISA-unpriv.adoc` §Interruptibility (~2624–2651), §Resumption and Memory Model (~2654–2671), §Memory Model WARNING (~816–820); acknowledged in `ace-introduction.adoc` lines 121–125.
- **Description:** The spec permits restart-instead-of-resume unconditionally and simultaneously permits the LSU to reorder component accesses arbitrarily. There is no statement that (a) a restarting implementation must guarantee eventual completion (e.g., completes if re-executed with no intervening interrupt for N cycles, or a minimum-progress rule), nor (b) that when hardware writes `acestart = k` on interruption, all bytes below offset `k` are globally performed and none at/above `k` are.
- **Proposed resolution:** Add two normative rules: (1) *Progress*: an implementation that restarts must ensure the instruction completes in the absence of interrupts, and `acestart`-honoring implementations must make monotonic progress (each resumption advances `acestart` by at least one granule before the next allowed interruption point). (2) *Visibility*: on interruption with `acestart = k`, all memory writes for offsets `< k` are globally performed; no write for offsets `≥ k` is performed (loads analogously). Both were already identified in the introduction TODO; they must be promoted to Book 1 normative text before freeze.

---

**C4 — `Zklio` window semantics are self-contradictory: `ACELEN` definition, `acestart` dual use, and the `ace.input`/`ace.output` length check break under resumption**

- **Severity rationale:** `Zklio` is one of only two sanctioned I/O paths (and the only one on vectorless cores). As written, conforming implementations will disagree on operand length, and a legal interrupted transfer re-raises `ace_exc_invalid` on resumption.
- **Location:** `ace-ISA-algorithms.adoc` §Notation (`ACELEN`, lines 200–204) vs. `ace-ISA-unpriv.adoc` §`aceiobuftop` (945–969), §`acestart` (983–1009), `ace.input` (2362–2382), `ace.output` (2425–2441).
- **Description:** (a) `ACELEN` is normatively defined as `aceiobuftop × 8`, but `aceiobuftop` is elsewhere defined as the *upper bound* of a window whose lower bound is `acestart` ("Together with `acestart` … it defines the active transfer window"; "`aceiobuftop − acestart` is a length not supported by the Algorithm"). Whether an operation processes `aceiobuftop` bytes or `aceiobuftop − acestart` bytes is therefore ambiguous whenever `acestart ≠ 0`. (b) `acestart` is simultaneously the window start *and* the hardware-written resumption pointer for the same instructions. (c) `ace.input` raises `ace_exc_invalid` "if `Xl` is greater than `aceiobuftop − acestart`". Take `aceiobuftop = 64`, `acestart = 0`, `Xl = 64`: legal. Interrupt after 32 bytes → hardware sets `acestart = 32`. Re-execution of the same instruction re-evaluates the check with `Xl = 64 > 32` → spurious `ace_exc_invalid`. It is also unspecified whether resumption re-reads memory from `Xs+offset` or from `Xs+offset+acestart`.
- **Proposed resolution:** Separate the two roles. Either introduce a distinct window-base (e.g., `aceiobufbase`) and let `acestart` be purely a progress counter relative to the window, or define normatively: "`ace.input` transfers bytes `j = acestart … Xl−1`, reading memory byte `Xs+offset+j`

into ACEIOBUF byte `j`; the length check `Xl ≤ aceiobuftop` is evaluated once, at first issue; on resumption the check is `acestart ≤ Xl`." Redefine `ACELEN` once, in one place, as the window length actually consumed by `ace.exec`/`ace.setst`, and delete the conflicting phrasing.

---

**C5 — Ascon-AEAD128 with set Nonce permits reset-to-_Ready_, enabling keystream reuse (two-time pad) under a preset nonce**

- **Severity rationale:** Security compromise of user data via an architecturally permitted instruction sequence, in the exact variant whose purpose is to prevent nonce misuse. The analogous variant "GCM with Set IV" was given explicit protections; this one was not.
- **Location:** `ace-ISA-algorithms.adoc` §Ascon-AEAD128 with set Nonce (2716–2743) and §Nonce Masking (2747–2798); interacting with the generic rule in `ace-ISA-unpriv.adoc` §_State_ field rule 4 (line 485): "A transition from any valid state to _Ready_ … is always permitted, unless the algorithm explicitly forbids it."
- **Description:** For `Ascon-AEAD128_Nonce` the nonce lives in the PI and is re-installed into `state[3..4]` on every entry to _Ready_. Since the variant does not forbid the generic any-state→_Ready_ transition and has no block budget, any holder of the CC can encrypt message 1, `ace.setst` back to _Ready_, and encrypt message 2 under the *same key and nonce*. Ascon-AEAD128 is not misuse-resistant: this yields keystream reuse (XOR of plaintexts leaks) and enables forgery. The same applies to the Nonce-Masking + set-nonce combination. GCM-with-Set-IV, by contrast, forbids return to _Ready_ *and* carries a `budget` field.
- **Reasoning:** The rationale note attached to rule 4 (reset protection is ineffective because SCC replay exists) does not justify the asymmetry: SCC replay requires holding an old SCC and re-importing, while _Ready_-reset is a single in-place instruction available to any code the usage policy admits; and the spec *did* consider reset dangerous enough to forbid it for GCM-IV. NIST SP 800-232 §4 makes nonce uniqueness a hard requirement.
- **Proposed resolution:** For `Ascon-AEAD128_Nonce` and the set-nonce Nonce-Masking configuration: forbid the transition to _Ready_ (as GCM-IV does), add a block/usage `budget` in the PI and Serialized Context, and state that exceeding it invalidates the CR. Alternatively, drop the set-nonce Ascon variants until protections equivalent to GCM-IV's are specified.

---

### Major

---

**M1 — GCM IV-length parameter: units contradict between API (bytes), constraint range, internal use (bits), and Book 4 example**

- **Location:** `ace-ISA-algorithms.adoc` GCM §Behavior (957–981); Book 4 `ace-pseudocode.adoc` 371–377.
- **Description:** The Form B `ace.setst` "sets the length of the IV *in bytes*: `len ← Xs`", constraint `8 ≤ Xs ≤ 8192`; but `process_VLI` is invoked "where `len` is the IV length *in bits*", the special-case test is `len ≠ 96` (96 *bits* is the standard IV), and the serialized `len` field says "Maximum 1024 bytes (8192 bits)". If `Xs` is bytes, a standard 12-byte IV gives `len = 12`, the `len = 96` fast path never triggers, and `J0` is computed by GHASH instead of `IV ∥ 0³¹ ∥ 1` — silently producing non-interoperable, non-conformant GCM. Book 4 passes `len_in_bytes(IV)`.
- **Resolution:** Make `Xs` the IV length in bits (matching the range 8…8192 and the `len ≠ 96` test), with the constraint "a multiple of 8"; fix the Book 4 example to pass `8·len_in_bytes(IV)`; or convert internally with `len ← 8·Xs` and rewrite the range as `1 ≤ Xs ≤ 1024`.

**M2 — SCC sealing uses AES-GCM-SIV with a permanently zero nonce; safety is asserted, not established, and the cited RFC's repeated-nonce limits are exceeded by design**

- **Location:** `ace-ISA-unpriv.adoc` §Generation of an SCC (3043–3068, `zeros(96)` nonce; IMPORTANT block 3060–3068); removed `acenonce` CSRs remain as commented-out text (1024–1046).
- **Description:** Every export under a given CSK uses the same key and nonce; the derived `enc_key`/`auth_key` are constants. Nonce-misuse resistance makes this *deterministic* AEAD: (a) identical CR contents produce identical SCCs (observable equality leak across time and across harts sharing a CSK — e.g., a context switcher learns a process's key material didn't change); (b) the security bounds of the scheme (Gueron–Langley–Lindell, cited) degrade with the number of encryptions under a single (key, nonce) pair, and RFC 8452 §9 explicitly bounds how many messages should repeat a nonce. Context switching can produce billions of exports per CSK lifetime. The IMPORTANT block claims safety "by construction" with no bound. *[Uncertainty: the exact RFC 8452 §9 numeric recommendation should be re-verified against the RFC text; the structural point — unbounded same-(key,nonce) use with no stated bound — stands regardless.]*
- **Resolution:** Either carry a per-export nonce in the SCC (e.g., a 96-bit counter or random value stored in plaintext ahead of `SIV` — the removed `acenonce` design), or add a normative note with a concrete advantage bound for q exports of ≤ l blocks and a mandatory CSK-rotation guideline (e.g., per boot via `PhysBootScrt`-style rekeying) that keeps the bound acceptable.

**M3 — `ace.restrict*` Locality "stricter" chain _MLocality_ → _HLocality_ → _SLocality_ moves binding control to *lower* privilege**

- **Location:** `ace-ISA-unpriv.adoc` §`ace.restrict*` (1988–1999); Localities table (687–712).
- **Description:** For the HW chains (SiP→ChipFam→Chip), "stricter" means narrower scope with unchanged configurability. For the SW Filter chain, replacing _MLocality_ with _SLocality_ re-binds the CC from a secret only M-mode can rotate to one (V)S-mode controls. Software holding a CC bound to _MLocality_ (e.g., to confine it to the current M-mode security state) can re-bind it to _SLocality_ and export; the resulting SCC now *survives* an M-mode rotation of _MLocality_ — defeating the higher-privilege revocation/confinement the binding was for. This is a policy *weakening* presented as a restriction.
- **Resolution:** Either forbid replacements within the SW Filter Group (allow only 0→any, i.e., adding a binding where none existed), or restrict replacement to the direction of *higher*-privilege control (S→H→M), or document a precise rationale showing no confinement property is lost. Also state whether the replacement takes effect for `Locality` values whose current binding is in active use.

**M4 — Software-programmable Locality secrets are write-only (WARZ) per-hart state with no context-switch or migration mechanism**

- **Location:** `ace-ISA-priv.adoc` §§`hacevirtbootscrt`, `hacelocality`, `sacelocality`, `macelocality` (751–823).
- **Description:** `sacelocality` is written by (V)S and readable by no one. When a hypervisor switches VMs, it cannot save/restore the guest's SLocality (WARZ), there is no `vsacelocality` shadow, and the guest is not notified that it must rewrite it. Two guests each using SLocality silently clobber each other's LST entry; every SLocality-bound SCC of the descheduled guest becomes unimportable with no error distinguishable from corruption. The same applies to `hacelocality` across supervisor-domain switches and `hacevirtbootscrt` across VM switches (H *can* rewrite from its own records, but nothing requires it to, and the spec is silent). This contradicts the claim that ACE "is compatible with … VM migration".
- **Resolution:** Either (i) define virtualized shadows (`vsacelocality`, swapped by hardware on V transitions) plus a normative requirement that each mode's scheduler rewrite the secrets it manages on context-in; or (ii) make the CSRs readable at strictly-higher privilege for save/restore; or (iii) normatively assign responsibility ("HS must re-establish SLocality/VirtBootScrt for the incoming VM before `sret`") and add discovery of staleness.

**M5 — SCC export/import completion protocol incomplete and ambiguous: which MDH image is authenticated, how `ml` is carried, and the vector-variant mismatch (author-flagged)**

- **Location:** `ace-ISA-unpriv.adoc` `ace.mgmt` semantics (1664–1753), §SCC export WARNING (3036–3041), §SCC import (3072–3099).
- **Description:** (a) The export algorithm's own WARNING admits the 64-bit-vs-128-bit initial-MDH cases are unwritten. (b) Import completion "must use Form B … to pass along the value of `ml`" — but if import was *started* with the vector variant, `ml` is 128 bits and Form B (one GPR / RV32 pair) cannot carry it on RV64. (c) The authenticated `AD[0]` is `saved_MDH` "with _ConfigStatus_ = `ace_cfgst_complete`", yet at import-completion time the CR's MDH has _ConfigStatus_ = `ace_cfgst_importing`; the spec never states that the implementation must reconstruct the authenticated image by substituting the software-supplied `ml._ConfigStatus_` (and only that field), nor what happens if the supplied `ml` disagrees with the MDH bits already loaded into the CR (silent auth failure? `ace_exc_invalid`?). (d) In the `≠ complete` path, `_ConfigStatus_ ← ml._ConfigStatus_` is taken from software with no authentication at all — state which values are legal and what a hostile value yields.
- **Resolution:** Write the two missing cases; specify normatively the exact byte image used as `AD[0]` (recommend: the MDH as carried in the SCC, i.e., CR-resident MDH with _ConfigStatus_ replaced by the completion parameter's value, all other supplied `ml` bits *ignored* or required-equal with a defined error); require Form C for completion of vector-started imports or define that completion always takes only MDH[63:0].

**M6 — ECC: the core operations are never defined; EdDSA state machine underspecified**

- **Location:** `ace-ISA-algorithms.adoc` §ACE-ECC (3119–3221), §EdDSA (3225–3324).
- **Description:** (a) _Point_Mul_'s computation is never stated — which operand is multiplied (Generator? SecondPt?), by what (Scalar), where the result lands, and *which instruction/Form triggers it* (ML-KEM/ML-DSA say "Form D `ace.exec`"; ECC says nothing). Same for _Sign_Generate_/_Sign_Verify_ (no statement that they implement FIPS 186-5 §6.4.1 / RFC 8032 §5.x equations beyond the retry rules). (b) The Internal State lists a `PublicKey` field that has no Set state, is never serialized, and duplicates `SecondPt` ("Can be the Public Key") — a phantom field. (c) EdDSA: who initializes `H` with `dom ∥ prefix` vs `dom ∥ R ∥ A`, what increments `msg_pass`, how the transition Msg_Absorb→(compute R)→Msg_Absorb pass 2 is sequenced, and what instruction finalizes each pass are all unstated. (d) secp521r1 "all-ones = point at infinity" conflicts with "55 msbs set to zero" for b = 576.
- **Resolution:** Give each of _Point_Mul_, _Sign_Generate_, _Sign_Verify_ a Behavior block of the same rigor as the symmetric modes: trigger instruction and Form, operand fields read, formulas by reference to the exact standard clause, result fields written, error cases. Delete `PublicKey` or define its Set state. For EdDSA, define the pass protocol as explicit states/transitions. Fix the infinity encoding for P-521 (e.g., all-ones within the 521 significant bits).

**M7 — SHA-2 and SM3 are claimed extensions with no normative instantiation; HMAC's outer-hash finalization contradicts the caller-pads model**

- **Location:** `ace-ISA-unpriv.adoc` extension table (Zklesha2h, Zklsm3h → `<<ACE-hash-functions>>`); `ace-ISA-algorithms.adoc` §Hash functions (1942–2091), §HMAC (2094–2219).
- **Description:** SHA-3 gets a dedicated instantiation (parameters, IVs, padding). SHA-2 and SM3 get nothing: no per-function `b/n/t/state_offset` table, no initial-value specification, no statement of the FIPS 180-4 big-endian word mapping in the little-endian value model (the Conventions table promises "via `binBE`" — a function no longer defined, see m1). Interoperable implementation is impossible from Book 2 alone. HMAC additionally requires the unit to "Finalize H" internally on the outer hash — but for SHA-2 the generic model makes padding and length-appending "the caller's responsibility", and the caller cannot inject padding in _Hash_Output_. So HMAC-SHA-2 requires a self-finalizing capability of H that Book 2 never defines.
- **Resolution:** Add SHA-2 and SM3 subsections parallel to §SHA-3 (parameters table, state mapping with explicit `bswap(bin(...))` for lengths/words, serialized-context layout), and define an internal `finalize()` (padding + length) for hashes used inside HMAC, stating that in stand-alone hashing padding remains the caller's duty (or, cleaner, move padding into the unit everywhere).

**M8 — ML-DSA Serialized Context: field list sums to 256 bits less than the stated totals for all three parameter sets**

- **Location:** `ace-ISA-algorithms.adoc` 3630–3653.
- **Description:** Listed fields (MDH 128 + privkey + pubkey + signature + ctxlen 8 + ctx 2040 + mu 512 + rnd 256) total 53,280 / 77,288 / 99,864 bits for ML-DSA-44/65/87; the text asserts 53,536 / 77,544 / 100,120 and derives block counts (419/606/783) from those. The 256-bit discrepancy is identical in all three sets — a field is missing from the table (plausibly the 32-byte seed ξ, or a `tr`-related half) or the totals are wrong. Either way the on-the-wire format — the interoperability contract Book 2 exists to fix — is indeterminate.
- **Resolution:** Reconcile: list the missing 256-bit field or correct totals/padding/block counts (which would become 96/24/104-adjusted accordingly).

**M9 — Extension partitioning is contradictory: instruction membership, conformance rules, and advertised-but-undefined modes**

- **Location:** `ace-ISA-unpriv.adoc` extensions table + conformance text (92–154); algorithm encodings table (`ace-ISA-algorithms.adoc` 19–100).
- **Description:** (a) `ace.load`/`ace.store` are "Included in `Zklmem`", yet the `Zklv` paragraph lists them among instructions `Zklv` supports; whether a `Zklv`-only core has them is undecidable. (b) "To claim `Zkl` conformance, at least one of `Zklv` or `Zklio`, and `Zklkn` are required. If `Zklmem` is not implemented in hardware, a trap-and-emulate implementation using `Zklmv` is required" — this simultaneously omits `Zklmem` from conformance and makes it (or its emulation, which requires `Zklmv`, itself optional) mandatory. (c) Footnote 2 says XEX/CTR/GCM/OCB modes apply to SM4, but the encoding table gives SM4 only modes 0–7 (no OCB/OCB_IV). (d) `Zklctrm`/`Zklxctrm` advertise "CTR **with set initial counter**" — no such algorithm exists in Book 2 (the keystream state machine zeroes `ctr` in _Ready_ and provides no way to set it).
- **Resolution:** Add an authoritative instruction×extension matrix; state conformance as a closed formula; either add SM4 OCB encodings or fix the footnote; define the set-initial-counter variants (e.g., Form B `ace.setst` supplying `ctr`) or delete the claim.

**M10 — CTR/XCTR counter wrap is unspecified: silent keystream reuse**

- **Location:** `ace-ISA-algorithms.adoc` §CTR/XCTR (349–441).
- **Description:** `tick_ctr()` "increases the counter by one" with no wrap rule. After 2^j blocks under one IV the counter wraps and the keystream repeats — a two-time pad. GCM and GCM-SIV both got explicit exhaustion guards; plain CTR/XCTR, marketed as misuse-reducing, has none. For j = 32 the wrap is 64 GiB — operationally reachable.
- **Resolution:** Mirror the GCM rule: on the `ace.exec` that would wrap `ctr` past its initial value, perform no operation and invalidate the CR.

**M11 — Encoding conflict: `ace.setst` with `r`=1, CR register = `X0` is simultaneously "reserved semantics" and the definition of `ace.reset`**

- **Location:** `ace-ISA-unpriv.adoc` 1533 vs. 2472–2482.
- **Description:** `ace.setst` says that encoding "has reserved semantics"; `ace.reset` is defined as exactly `ace.setst` with indirect addressing, `Xd = X0`, immediate 0. Also, Book 1's general rule "Use of `X0` as a CR index register raises an illegal-instruction exception unless explicitly indicated otherwise" adds a third behavior for the same bits.
- **Resolution:** State: "`ace.setst` with `r`=1, rd-field=`X0`, `#immed7`=0 is `ace.reset`; all other immediates with `r`=1 and rd-field=`X0` are reserved and raise illegal-instruction."

**M12 — ML-KEM: `ace.derive` Form contradiction and duplicated, conflicting _Encapsulate_ behavior**

- **Location:** `ace-ISA-algorithms.adoc` 3354–3358 ("the Form A `ace.derive` instruction … The auxiliary input in a GPR") vs 3524 ("must be of Form B"); _Encapsulate_ described twice (3477–3483 → _Failure_ only; 3485–3490 → _ciphertext_Output_/_Failure_).
- **Description:** Form A has no auxiliary input by definition, so the first sentence is self-contradictory; the duplicate _Encapsulate_ paragraphs must be merged (the success transition differs from _GenerateKeyPair_'s → _Success_, which is fine, but say it once). Also unspecified: the derived CC's MDH[127:64] other than bits [79:64] (ExpirationDate of the child? _State_?).
- **Resolution:** Keep Form B only; merge the two paragraphs; enumerate every MDH field of the derived CC (recommend: ExpirationDate 0 unless AuxInfo semantics extended; _State_ = _Ready_; _ConfigStatus_ = complete).

**M13 — Implementation VDS corruption: import algorithm rejects the whole SCC on `SIV2` failure, but the data-format section says the originating implementation "may silently restart" on corrupted additional data**

- **Location:** `ace-ISA-unpriv.adoc` import step 14 (3098) vs §Formats category 3 (2755); DIEL §3124.
- **Description:** Two normative statements disagree on whether a bad Implementation VDS is fatal (clear CR, _Authentication Failed_) or ignorable (discard, restart the interrupted operation). The difference is security-relevant: fatal turns a one-bit flip in *optional* data into destruction of the context (DoS amplification); ignorable must be specified carefully so that only the VDS, never `Content1`, is droppable.
- **Resolution:** Specify: if `SIV2` verification fails, discard the VDS, set _ImpDataLen_ ← 0, and proceed with the (already authenticated) architecture-dependent content; keep hard failure only for `SIV` (Content1) mismatch. Update the DIEL note accordingly.

**M14 — GCM-SIV decryption `last_blk_len` rule contradicts encryption and RFC 8452's byte orientation**

- **Location:** `ace-ISA-algorithms.adoc` 1400–1403 (enc: "zero, larger than 120, or not a multiple of 8 invalidates") vs 1431–1433 (dec: "zero, or larger than 127 invalidates").
- **Description:** RFC 8452 is byte-oriented; a decryption final block of, say, 13 bits is meaningless yet accepted by the dec-side rule. The two sides must match (≤120, multiple of 8, nonzero).
- **Resolution:** Copy the encryption rule to the decryption transition.

**M15 — Behavior on non-multiple `ACELEN` is unspecified across algorithms**

- **Location:** Throughout Book 2 — e.g., ECB (328–334: loop `foreach(i from 0 to ACELEN−b by b)` silently drops a trailing partial block), GCM ("ACELEN must be an integer multiple of b" with no stated consequence), Ascon, OCB.
- **Description:** "Must be a multiple" without a defined violation behavior is exactly the unspecified-behavior class this review is instructed to reject; implementations will variously truncate, trap, or process garbage.
- **Resolution:** One generic rule in §Generic Rules: "If `ACELEN` violates the granularity constraint of the current Algorithm and state, the instruction raises an illegal-instruction exception and performs no operation" (then delete per-algorithm restatements).

**M16 — Debug-mode policy contradicts itself between Books 1 and 3**

- **Location:** `ace-ISA-unpriv.adoc` §Interaction with Debug (1112–1120: "Debug mode is *not* granted access to any ACE-specific CSRs") vs `ace-ISA-priv.adoc` `macephysbootscrt` (760: "Access outside M-mode **or Debug mode** raises…") and `macelocality` (790).
- **Description:** Two CSR groups grant Debug access that Book 1 categorically denies; the introduction TODO separately admits Debug policy (including CRF zeroization on unauthenticated debug entry) is unresolved. For a key-holding unit, undefined Debug interaction is a key-extraction surface.
- **Resolution:** Pick one policy; recommend: all ACE state inaccessible in Debug unless an implementation-defined authenticated-debug signal is asserted, with mandatory CRF + LST + CSK zeroization on unauthenticated Debug entry, and remove the per-CSR Debug carve-outs.

**M17 — `ace.mgmt` is declared uninterruptible while performing unbounded work; contradicts "any management operation may be interrupted"**

- **Location:** `ace-ISA-unpriv.adoc` 2626 vs 1774; SCC sizes up to ~12.5 KB (ML-DSA-87).
- **Description:** Import completion decrypts+authenticates the whole SCC inside one uninterruptible `ace.mgmt` — ~800 AES blocks plus POLYVAL for ML-DSA-87 — an unbounded interrupt-latency source on small cores. The NOTE in `ace.mgmt` says "any management operation may be interrupted adn [sic] resumed" (presumably meaning the multi-instruction *process*), which at minimum needs disambiguation, and the latency problem needs an architectural answer.
- **Resolution:** State explicitly that the *instruction* is uninterruptible but the *process* is; bound the work (allow implementations to make completion resumable via `acestart`-style progress, or interleave decrypt/auth with `ace.load` as the existing NOTE at line 147 of Book 4 already contemplates — then make that interleaving normative-optional with defined interruption points).

**M18 — XEX single-key vs two-key selection is not encodable in the PI**

- **Location:** `ace-ISA-algorithms.adoc` XEX Data Structures (468–497) and mask-derivation branch (543–557).
- **Description:** The behavior branches on "if two independent keys are used", and the branch is *security-critical* (the single-key path needs the extra `update_mask`, per Rogaway). But the PI gives `key2` as "`k` or 0 — empty if `key1` given" (circular: key1 is always given), and no MDH field is identified that selects 1-key vs 2-key when keys are by value. An implementation cannot parse the PI or pick the branch deterministically.
- **Resolution:** Fix the PI table ("empty if _KeyType_ = 1", since one SKID fetches both keys) and normatively assign the 1-key/2-key selector (e.g., an _AlgorithmPolicy_-extension bit or distinct Mode), including its effect on PI/SCC length per §Length Rule.

**M19 — Big-endian harts: "behavior … is undefined"**

- **Location:** `ace-notation.adoc` 10–14.
- **Description:** Undefined behavior in a security extension is a vulnerability class (an attacker able to flip `mstatush.MBE`/`sstatus.UBE` gets unspecified crypto-unit behavior). RISC-V practice for endianness-sensitive features is to define behavior in terms of memory bytes independent of hart endianness, or to trap.
- **Resolution:** Replace with either "ACE memory instructions access memory as byte sequences and are endianness-invariant" (preferred — the byte-string model already supports this) or "any ACE instruction executed while the effective data endianness is big raises an illegal-instruction exception."

**M20 — Faulting ACE instructions have architectural side effects (invalidation, _State_ writes) with no stated retirement/re-execution model**

- **Location:** e.g., `ace-ISA-unpriv.adoc` Localities (719–723: transition to `ace_state_invalid` *and* raise `ace_exc_invalid`), GCM-IV budget (1212–1215), Generic Rule 2.
- **Description:** RISC-V precise exceptions normally imply the faulting instruction commits no architectural change. ACE repeatedly requires trap + CR mutation. That is permissible for custom state but must be said explicitly, along with what happens on re-execution of the (now-invalid-CR) instruction — otherwise trap handlers face non-idempotent replay.
- **Resolution:** Add to Book 1: "ACE instructions that raise an ACE exception may nevertheless update CR _State_/_ConfigStatus_ as specified; they never update `Vd`/`Xd`/memory/ACEIOBUF. Re-execution after such a trap encounters the updated CR state." Fold into the C1 table.

**M21 — Generic Hash _Hash_Output_ loop mixes units and contains an indexing error; 32-bit `cumul_len` caps message length; SHA-3 omits `cumul_len` from its Serialized Context**

- **Location:** `ace-ISA-algorithms.adoc` 2066–2090 (`output_base … byte counts` compared against `ACELEN` in bits; `block[block_base + amount − 1 : 8 block_base]`), 1998 (32-bit `cumul_len` ⇒ 2^32-bit ≈ 512 MiB absorption cap, unstated), 2278–2289 (SHA-3 SC lacks `cumul_len` though `process_VLI` is invoked with it).
- **Resolution:** Rewrite the output loop entirely in bits (as `process_VLI` is), fix `8 block_base` → `block_base`; either widen `cumul_len` or state the cap normatively; reconcile SHA-3's serialized fields with its `process_VLI` invocation.

**M22 — RVV-mini depends on nonexistent instructions and is itself unfinalized while normatively load-bearing**

- **Location:** `ace-ISA-unpriv.adoc` 253–287.
- **Description:** The required-instruction list includes `vins`/`vext` — no such mnemonics exist in ratified RVV (the intended operations are presumably `vslide*`/`vmv.x.s`/`vmv.s.x` or `vrgather`); `vand`/`vor`/`vxor` are not actual mnemonic forms either. Simultaneously a red warning says RVV-mini "need not be finalized before ACE ratification" — but Book 1's operand model (VL·SEW semantics, tail/mask-agnostic-only, LMUL set, illegal-instruction on unsupported configs) *is* normative ACE behavior. An extension cannot ratify against an undefined ISA subset.
- **Resolution:** Replace the list with real RVV mnemonics; either fully specify RVV-mini in this document (it is small) or make full `V` (with `Zvl128b`) the requirement for `Zklv` v1 and defer RVV-mini to a later extension.

**M23 — `macecsk` reset value "implementation-defined" contradicts the CSK-availability model**

- **Location:** `ace-ISA-priv.adoc` 747 vs `ace-ISA-unpriv.adoc` 1054–1078.
- **Description:** Book 1: "Without a CSK, every ACE instruction raises an illegal-instruction exception" and, for models 1/2/4, the unit is unavailable "until a first CSK value has been set" after any reset. Book 3: "The value of the CSK out of ACE unit reset is implementation-defined" — implying a usable (and possibly predictable!) CSK exists at reset. A predictable reset CSK would let an attacker who forces a reset unseal nothing directly (SCCs die with the CSK) but could let firmware unknowingly seal under a weak key.
- **Resolution:** Replace with: "Out of ACE unit reset the CSK is *unconfigured*; the ACE unit is unavailable until a CSK is established per §CSK-requirements (immediately, in model 3)."

---

### Minor (condensed; each entry = title · location · issue → fix)

- **m1 — `binBE` referenced but no longer defined.** `ace-notation.adoc` conventions table (rows SP 800-38D, FIPS 180-4) and Book 4 GCM examples (404, 435, 461–491) still use `binBE`; the definition lives only in a commented-out section (the refactor to `bswap(bin(...))` — visible in recent history — is incomplete). → Finish the substitution or re-add the definition.
- **m2 — Undefined `ace.mgmt` immediates `#ace_CR_provision_end` / `#ace_CR_import_end` / `#ace_CR_export_end`.** Used throughout Book 4 and in Books 1–2 (e.g., GCM import note, SCC import title); the table defines only `ace_CR_management_end` (3). → Define them as aliases of value 3 or rename uses.
- **m3 — Resumption section names the wrong instruction.** `ace-ISA-unpriv.adoc` 2671: "providing the first 8 bytes of the MDH to the `ace.setst` instruction used to prepare the CR" — that is `ace.mgmt`. → Fix.
- **m4 — CSR naming drift.** Priv CSR table says `mcrstatus`/`scrstatus`/`vscrstatus`; the defining section says `mlcrstatus`/`slcrstatus`/`vslcrstatus`; prose also uses `*lcrstatus` and `_X_crstatus`. → One name everywhere.
- **m5 — OCB `tag_len` serialization "encoded as `tag_len/64`" in 2 bits.** 96/64 = 1.5 is not encodable. → Encode as `tag_len/32 − 2` (values 0,1,2) or 2-bit enum.
- **m6 — OCB _Decrypt_ lacks the `index = ones(48)` exhaustion guard** present in _Hash_Absorb_/_Encrypt_. → Add it.
- **m7 — OCB `AD_finalized`/`text_finalized` are declared and serialized but never set or consulted;** the SC also stores a bare `L` while the internal state has `L`, `L₀`, and the `L~i~` array, without saying which is exported or that the rest are recomputed on import. → Specify or delete.
- **m8 — OCB last-block steps use `K` where every other line uses `key`** (1684, 1744). → Fix.
- **m9 — CMAC offers no _Hash_Verify_**, although §_State_ rule 6 presents MAC verification via `ace_state_hash_verify` as the canonical example; CMAC verification therefore requires releasing the tag to software (timing/comparison hazards). → Add optional _Hash_Verify_ or note the omission.
- **m10 — Ascon `tag_len` is a dead field** (initialized 128, no setter, yet consulted in _Hash_Verify_ and serialized in 16 bits vs 8-bit internal). → Remove or define a setter with SP 800-232's ≥64-bit floor.
- **m11 — Ascon-Hash256 `countdown` decrements after the Success test**, underflowing the 2-bit _AlgorithmUse_ subfield. → Reorder/guard.
- **m12 — CMAC Book 4 example reads `M[16*blocks .. 16*blocks+15]` even when `M_len = 0`** (out-of-bounds read of an empty message). → Guard the final `ace.exec`'s load.
- **m13 — `ace.getmd*`:** "The semantics of `ace.getmd` are the same as on RV64" — typo for `ace.getmdv`; "vector register (group) smaller than 128 bits" ambiguous between VLEN and VL·SEW. → Fix name; say "if `VL·SEW < 128`".
- **m14 — `ace.store` "does not modify state"** yet updates `acestart` and is resumable. → "does not modify CR state".
- **m15 — `ace.clear` "will change its state to _Dirty_"** conflates CR _State_ with ACES/`*lcrstatus` dirtiness. → "sets the relevant `*status.ACES` and `*lcrstatus` fields to Dirty".
- **m16 — `ace.size` Form C paragraph:** the trailing "Otherwise, Form C raises an illegal instruction exception" contradicts the preceding "returns 0" sentence; scope of "Otherwise" (missing `Zvl128b+`) must be explicit. Also `Zvl64b` wording absent but implied. → Rewrite.
- **m17 — State rule 2 permitted-instruction list omits `ace.getmd*`, `ace.clone`, `ace.restrict*`** in _Success_/_Failure_ although other rules permit them (rule 12 allows `ace.getmd*` in Error States; clone restrictions are elsewhere). → Make the list complete and authoritative.
- **m18 — Terminology collision "Off":** used for the ACES encoding, the `*lcrstatus` encoding, *and* as the caption of the _Unconfigured_ CR state table ("Global CC State Numbers: Off State"). → Rename the CR state table caption to "Unconfigured".
- **m19 — `bin(n,m)` definition:** "(m least significant bits, or sign extended)" is ambiguous for a function used almost exclusively on unsigned lengths/counters. → Define as zero-extended/truncated unsigned; add `binS` if signed needed.
- **m20 — _UsagePolicy_ bit map doesn't name VU or (non-H) S-mode.** Bits cover U, VS, HS, M; presumably bit 0 governs VU and bit 2 governs S when H is absent — say so.
- **m21 — `acemaxiobuflen` has no minimum**, so a conforming `Zklio` implementation can be too small for any implemented algorithm's block. → Require `acemaxiobuflen ≥` the largest granularity of any implemented algorithm.
- **m22 — Leftover editorial artifacts:** ACES table title "—Remove in version integrated into the SPEC§"; TODO/WARNING blocks throughout (fine for a draft, must go before candidacy); "adn" typo (1774); duplicated "Data Structures:::" label in ECC (2996/3027); KMAC SC position numbering skips vi; GCM _Dec_Tag_Finalize_ input formula missing `bin(...)` inside `bswap` (1111); GCM `tag` field description claims it buffers IV absorption though `J0` does (846 vs 869–879).
- **m23 — `ace-instruction-summary.adoc` is orphaned** (exists, is current, but is included nowhere), so the built document has no instruction overview table. → Include it or delete it.
- **m24 — funct3 = 4 on custom-2 is unassigned and unmentioned.** → Mark reserved.
- **m25 — `ace.exec` Form B/C with nonzero unused register fields** is `ace.mv` under `Zklmv` but undefined without it. → "Reserved; raises illegal-instruction if `Zklmv` absent."
- **m26 — `ace_guru_meditation`:** memorable, but a ratified RISC-V spec will want a sober mnemonic (`ace_exc_fatal`).
- **m27 — Notation chapter is normative but sits under `[preface]`**, which front-matter conventions treat as non-normative. → Move into the numbered body or Book 1.
- **m28 — Algorithm value 4095 "architecture-defined"** with no stated purpose (SystemFormat sentinel?). → State it.
- **m29 — HMAC SC key row:** "`b*` is the number of bits in the key" conflicts with the PI's definition of `K0` as exactly `b` bits. → Reconcile.
- **m30 — Substitution rule "no operation" for zero-length window** (`aceiobuftop − acestart = 0`, `ace-ISA-unpriv.adoc` 966–967) doesn't say whether the `ace.setst` state transition still occurs. → Specify.

---

## 3. Cross-document inconsistencies and missing requirements (summary index)

| Theme | Findings |
|---|---|
| Books 1↔3 exception architecture | C1, C2, M16, M20 |
| Books 1↔2 I/O and operand model | C4, M1, M15, M21 |
| Books 1↔2 management protocol | M5, M13, M17, m2, m3 |
| Extension/conformance tables ↔ algorithm tables | M9, m23, m25 |
| Undefined dependencies (RVV-mini, cause codes, opcodes, `misa.L`, `mstatus` bits) | M22 + author-flagged WARNINGs (accepted as known-open; must clear ARC before freeze) |
| Terminology (Off/Dirty/lcrstatus/`ml`) | m4, m15, m18 |
| Missing normative content | M6 (ECC ops), M7 (SHA-2/SM3), M9d (set-initial-counter), M18 (XEX key count), the two author-flagged export cases (M5) |

---

## 4. Standards-compliance matrix

| Standard / requirement | Location in draft | Assessment | Evidence |
|---|---|---|---|
| FIPS 197 (AES) via `AESE256` | SCC sealing (Book 1 §SCC-AEAD) | **Conforms** | Standard usage; key sizes consistent (256-bit CSK) |
| SP 800-38A CTR | Book 2 §Keystream | **Gap** | Counter-block assembly via `bswap` correct; wrap behavior unspecified (M10); set-initial-counter variant missing (M9) |
| SP 800-38B CMAC | Book 2 §CMAC | **Conforms** (incl. empty-message padding); big-endian `double` correct; SC arithmetic verified |
| SP 800-38D GCM | Book 2 §GCM | **Conforms in structure; one blocking defect** | J0/GHASH/length-block/2³²−2 bound all verified correct under the little-endian mapping; IV-length units contradiction (M1) breaks the 96-bit-IV path under one reading |
| SP 800-38E / IEEE 1619 XTS | Book 2 §XEX + §XTS-from-XEX | **Conforms** (mask polynomial, α-offset for 1-key, stealing procedure verified) except key-count encodability (M18) |
| RFC 8452 GCM-SIV (data-path) | Book 2 §GCM-SIV | **Conforms** (key derivation halves, POLYVAL/Montmul representation, tag mask, counter block verified) except dec-side `last_blk_len` (M14) |
| RFC 8452 usage limits (sealing) | Book 1 §SCC generation | **Needs justification** | Zero nonce for CSK lifetime; no bound stated (M2) |
| RFC 7253 OCB3 | Book 2 §OCB | **Conforms** (Nonce/Ktop/Stretch/bottom, offsets, checksum, `ocb_pad` all verified in the bswap view); minor guards missing (m5–m8) |
| FIPS 202 / SP 800-185 | Book 2 §SHA-3/§KMAC | **Conforms** (rates, suffixes `01`/`1111`/`00`, `right_encode(L)`, bytepad limits plausible) |
| FIPS 180-4 SHA-2, SM3 | claimed via `Zklesha2h`/`Zklsm3h` | **Missing** | No instantiation (M7); `binBE` dangling (m1) |
| FIPS 198-1 HMAC | Book 2 §HMAC | **Gap** | ipad/opad correct; outer finalization contradicts caller-pads model (M7) |
| SP 800-232 Ascon | Book 2 §Ascon-* | **Conforms on the data path** (IV constants, domain-separation bit, key XOR schedule, `pad` match my record of the final publication — *re-verify constants against the published SP 800-232*); set-nonce variant violates nonce-uniqueness enforcement intent (C5) |
| FIPS 203 ML-KEM | Book 2 §ML-KEM | **Conforms on sizes** (800/1632/768 … verified); instruction-form contradiction (M12) |
| FIPS 204 ML-DSA | Book 2 §ML-DSA | **Gap** | Sizes match FIPS 204; SCC accounting off by 256 bits (M8) |
| FIPS 186-5 / RFC 8032 ECC | Book 2 §ECC/EdDSA | **Incomplete** | Retry rules and pre-hash division correct; core operations undefined (M6) |
| RISC-V unprivileged conventions (opcodes, WARL, exceptions) | throughout | **Known-noncompliant, flagged** | `custom-0/1/2` squatting (author-acknowledged); trap-with-side-effects unstated (M20) |
| RISC-V privileged (misa, mstatus, Smcsrind, Zkr, RVWMO/Ztso) | Book 3, §RBG, §Memory Model | **Provisional** | `misa.L`, `mstatus[26:25]` contested (author-flagged); memory model formalization outstanding (C3); Zkr dependency stated adequately |

---

## 5. Prioritized remediation plan

1. **Freeze the error architecture (C1, C2, M20).** Write the single condition→behavior table; define or delete every exception/state name; decide the lazy-CR question (in or out).
2. **Repair the sealing protocol (M5, M2, M13, M23).** Write the missing 64/128-bit cases, specify the authenticated MDH image byte-exactly, decide nonce strategy or publish bounds, resolve VDS-failure semantics, fix CSK reset wording.
3. **Fix the crypto-visible defects (C5, M1, M10, M14, M18, M8).** These change bits on the wire or enable misuse; they must precede any KAT/reference-model work. Update the KAT scripts (`*-kat.py`) afterwards.
4. **Close the `Zklio`/operand model (C4, M15, M21).** One definition of `ACELEN`; window vs. progress separation; granularity-violation rule.
5. **Complete missing normative content (M6, M7, M9, M12, M22).** ECC/EdDSA behavior blocks, SHA-2/SM3 instantiations, extension matrix, RVV-mini realism.
6. **Progress/memory-model guarantees (C3, M17)** — jointly with ARC, since the answers constrain microarchitecture.
7. **Privilege/virtualization hygiene (M3, M4, M16, M19).** Locality hierarchy direction, WARZ context-switch story, one Debug policy, endianness rule.
8. **Editorial sweep (all m findings)** — mechanical; do last, then re-run cross-reference reconciliation.

---

## 6. Remaining review questions and assumptions

1. **Assumption:** `ace-instruction-summary.adoc` and `ace-whitepaper.adoc` are intentionally excluded from the build; I reviewed only `ace.adoc` and its includes, per instructions. If the summary table is meant to be in the spec, m23 applies.
2. **Question (M3):** Is the M→H→S Locality replacement direction intentional (narrower *scope* = stricter), accepting that it removes higher-privilege revocation? A written rationale is needed either way.
3. **Question (C5/M2):** Was the deletion of the `acenonce` CSRs (commented out) a deliberate decision that deterministic sealing is acceptable? If so, the IMPORTANT block should carry the quantitative argument.
4. **Question (M5):** At import completion, is the software-supplied `ml` *trusted* (used to reconstruct AD[0]) or *checked* against the CR-resident MDH? The security argument differs.
5. **Question:** Is Book 3 as a whole optional for `Zkl` conformance? Many Book 1 behaviors ("exception raised … if the latter is implemented") imply yes, but `misa.L`/ACES are stated as mandatory when `Zklv`/`Zklio` exist.
6. **Unverifiable from the supplied documents:** exact `mstatus[26:25]` availability, cause-code allocation, `misa.L` availability, Smcsrind addressing — all correctly flagged as ARC-dependent; and the SP 800-232 IV constants and RFC 8452 §9 numeric limits, which I checked against memory and recommend re-verifying against the published texts (no network access was used for this review).
7. **Assumption:** the KAT scripts in `src/` are development aids, not part of the specification; I did not audit them, but findings M1/M8/M14 imply at least the GCM and ML-DSA vectors need regeneration after fixes.

---

**Bottom line:** the symmetric-mode data paths are in notably good shape — I verified GCM, GCM-SIV, OCB3, CMAC, XTS, SHA-3/KMAC and Ascon bit-mappings against the cited standards and found the endianness discipline essentially sound, which is where such specs usually fail. What blocks candidacy is the surrounding architecture: error semantics, the sealing protocol's unfinished corners, `Zklio` operand semantics, the undefined ECC core, and the handful of genuine misuse holes (C5, M10) in an extension whose stated purpose is misuse resistance.
