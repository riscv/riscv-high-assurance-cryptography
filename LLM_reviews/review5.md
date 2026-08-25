# Review 5 — Adversarial Technical Review of the ACE (Zkl) Specification and Resolution Record

**Reviewer:** Claude (Fable 5, Anthropic)
**Date:** 2026-08-24 (review opened 2026-08-22 against working tree at `e3c79d1`; resolutions landed through 2026-08-24)
**Scope:** `src/ace.adoc` and all files it includes (Books 1–4, notation, introduction, front matter), ~9,300 lines, read in full. Cross-references reconciled across all Books. Findings verified against FIPS 197/180-4/186-5/198-1/202/203/204, SP 800-38A/B/D/E, SP 800-185, SP 800-232, RFC 5639/7253/8032/8452/8734, GB/T 32905, GM/T 0003, and RISC-V unprivileged/privileged conventions.

---

## 1. Executive Summary

The initial review assessed the specification as **not ready for candidacy**, on four structural grounds: an internally incoherent error/exception architecture; missing or contradictory core semantic definitions (ECC operations, `Zklio` operand model, GCM IV interface, sealing protocol corners); known open ARC items; and one architecturally sanctioned cryptographic misuse path (Ascon set-nonce reuse). It reported **5 Critical findings (C1–C5), 23 Major findings (M1–M23), and 30 minor findings (m1–m30)**.

Over the course of the engagement, **every finding was resolved, deliberately excluded, or explicitly parked as ratification-track work**:

- **Resolved:** C1–C5; M1, M3–M23; all minors except as noted below.
- **Excluded by owner decision (this session):** M2 (quantitative justification of the zero-nonce sealing construction).
- **Parked as ARC/ratification-track, flagged in the document itself:** cause-code and opcode assignments, `misa.L` and `mstatus[26:25]` allocations, the axiomatic RVWMO integration, RVV-mini's formal definition.

Final state verified by: a **warning-free full document build** (asciidoctor + bibtex/diagram/lists), a **clean cross-reference audit** (168 anchors, 368 references, 0 unresolved; all 38 citation keys present in `ace.bib`), and a **fully passing known-answer-test suite (15/15)**, including two new harnesses written for sections added during the review.

The data paths of the symmetric algorithms were found to be in notably good shape from the outset: the endianness discipline of GCM, GCM-SIV, OCB3, CMAC, XTS, SHA-3/KMAC and Ascon was verified bit-for-bit against the cited standards and, with one exception (the GCM IV-length units, M1), survived adversarial checking intact. The defects were concentrated in the surrounding architecture — error handling, resumption, operand windows, extension partitioning, and the under-specified asymmetric sections.

---

## 2. Critical Findings and Their Resolutions

### C1 — Behavior of suppressed and disallowed operations unspecified; multiple overlapping error models

The specification mixed four error behaviors (illegal-instruction, `ace_exc_*` "if the Privileged Architecture is implemented", silent Error-State transitions, silent no-ops) with no rule assigning conditions to behaviors, and never specified destination effects of suppressed operations.

**Resolution** (authored by the specification owner, iterated over several review rounds; superseded an earlier drop-in proposed by the reviewer): a normative **Error Handling Architecture** section in Book 1 comprising:

- a **fallback mapping table** defining, for every ACE exception, the behavior when the Privileged Architecture is not implemented (direct Error-State transitions) — keeping Book 3 genuinely optional while making the no-trap behavior total;
- a six-category condition taxonomy (Fatal, Illegal Instructions, LCRstatus Off, Unsupported Algorithms, Privilege Violations, Invalidating/Expired Conditions, Algorithmic Errors), with a single owner per condition and stated priority ordering consistent with the Book 3 cause table;
- a **destination rule** (suppressed operations write no vector register, GPR, ACEIOBUF octet, or memory) with a block-granular partial-progress exception for multi-block `ace.exec`;
- explicit **trap semantics**: the trapped instruction does not retire, `xepc` holds its address, and — deliberately deviating from ordinary RISC-V exceptions — an ACE exception *commits* its specified CR-state effects before the trap;
- a terminating **handler protocol** (set the Error State, advance `xepc`);
- a scoped restart license: once per-block effects of a multi-block `ace.exec` are committed, neither implementation nor software may restart it from the beginning.

Exception mnemonics were renamed for clarity (`ace_exc_unsupported`, `ace_exc_out_of_memory`, `ace_exc_privilege_violation`, `ace_exc_unconfigured_buffer`; later `ace_exc_fatal`), and the state-machine misuse rule was given a single owner (transition to Error State _Invalid_; Book 2's conflicting illegal-instruction rule was deleted).

### C2 — Dangling exception codes and CR states (`ace_exc_CR_unconf`, `ace_exc_CR_other`, `_Hidden_`, `Lazy`)

**Resolution:** `ace_exc_CR_hidden` and the `_Hidden_` state deleted; `ace_exc_CR_other` removed with its orphaned NOTE; use of a not-fully-configured CR folded into `ace_exc_privilege_violation` with the configuration-instruction exemption list restated inline. The **Lazy question was resolved by owner decision**: there is no distinct architectural Lazy state — the `*lcrstatus` _Off_ value plus `ace_exc_CR_off` *is* the on-demand (lazy) loading and trap-and-emulate mechanism, with authoritative-SCC bookkeeping the responsibility of the software that set _Off_. Reminder text now states this at every site a reader would consult (cause table, CSR summary, a dedicated NOTE in the `*lcrstatus` section, the architectural model, the error-handling taxonomy, and the `ace.mgmt` emulation NOTE). The surviving `*lcrstatus` machinery was repaired: CSR naming unified (`mlcrstatus`/`slcrstatus`/`vslcrstatus`), the `vslcrstatus` substitution rule correctly scoped to V=1 (it had been scoped to VU-mode, which cannot access S-level CSRs), and a dangling promise of unstated State/`*lcrstatus` conditions removed.

### C3 — No forward-progress guarantee; missing `acestart`↔memory-visibility invariant; unreconciled attached-unit asynchrony

**Resolution** (respecting the owner's policy that resumption from `acestart` is mandatory *only* for `ace.exec`, whose committed per-block effects make restart corrupting, while the idempotent transfer instructions may be restarted):

- a **completion guarantee**: every resumable instruction eventually completes under any pattern of asynchronous interrupts, via one of three sufficient strategies — background completion, atomic completion, or precise-halt-and-resume with at least one granule of progress per attempt; abandoning a transfer must not be the unconditional response to asynchronous interrupts;
- a **prefix-completeness invariant** defining what a precisely-recorded `acestart` = k means (reads consumed exactly [0, k); writes produced [0, k), with early stores beyond k permitted only because the frozen source guarantees identical rewrite; `ace.exec` at block/algorithm granularity; the `acestart` update commits at trap entry) — which also resolved the parked LSU-ordering question: no ordering constraint is needed, only prefix-complete reporting;
- a **conflicting-access rule** operationalizing "appear to execute in program order": before any same-hart conflicting access, an in-flight operation must have completed or been precisely halted;
- migration routed through the visible-restart protocol (CR left _Unconfigured_, software re-runs the management sequence), and the full axiomatic RVWMO integration explicitly parked as ARC ratification work. The corresponding introduction TODOs were retired.

### C4 — `Zklio` operand model self-contradictory (`ACELEN`, the `acestart` dual role, broken resumption checks)

**Resolution by the owner's model, on the V-extension analogy:** `aceiobuftop` plays the role of `VL` — it defines `ACELEN` = `aceiobuftop` × 8 and the fixed operand window [0, `aceiobuftop`); `acestart` plays the role of `vstart` — the position within that window at which processing starts or resumes; shortening an operand is done by lowering `aceiobuftop`, never by raising `acestart`. Two confirmed follow-on decisions: **(a)** `acestart` clears to 0 on successful completion of every honoring instruction (the RVV `vstart` rule), with `ace.mv` exempted as the deliberate accumulator; **(b)** an invalid window used only as an *output* is an explicit NOP, not an Error State and not undefined. `ace.input`/`ace.output` were rewritten with index-`j` semantics (octet `j` moves between memory `base + j` and ACEIOBUF octet `j`), making resumption automatically correct and retiring a truncation rule that would have silently NOP'd the following `ace.exec`.

### C5 — Ascon-AEAD128 with set Nonce permitted reset-to-_Ready_ (nonce reuse, two-time pad)

**Resolution:** full parity with "GCM with Set IV", per owner decision — a 32-bit `budget` in the Provisioning Input, Internal State and Serialized Context (in place of the final padding, lengths unchanged); **no transition back to _Ready_** (stated as an algorithm-specific prohibition, with the rationale that Ascon, unlike a misuse-resistant mode, does not survive keystream reuse); per-block decrement rules mirroring GCM-IV's; and exhaustion → no operation, CR to Error State _Invalid_. The Nonce-Masking + set-nonce combination explicitly inherits all of it.

---

## 3. Major Findings and Their Resolutions

| ID | Finding (abbreviated) | Resolution |
|----|----------------------|------------|
| M1 | GCM IV-length parameter contradicted itself between octets (API), bits (internals, the `len = 96` fast path, the GHASH length block), and Book 4 — a wire-format break for the standard 96-bit IV under the octets reading. | **Option A (bits)**, chosen after discussing both: the API reads "in bits" (the range 8–8192 was already written for bits); Book 4 passes `len_in_bits(IV)` with a separate octet count for `vsetvli`; the serialized field says "in bits". `granularity` returned to `b` = 128 once its semantics were clarified (owner's definition, now normative in `process_VLI`): granularity governs every transfer in a sequence **except the last**, which may be shorter or is internally truncated — so a 96-bit IV is a legal single-and-last transfer. |
| M2 | Zero-nonce AES-GCM-SIV sealing for the CSK lifetime asserted safe "by construction" without bounds, against RFC 8452's repeated-nonce guidance. | **Excluded from this session by owner decision.** The IMPORTANT block remains the expected pressure point for a future ARC/security review. |
| M3 | `ace.restrict*` treated _MLocality_ → _HLocality_ → _SLocality_ as "stricter", moving binding control to lower privilege (defeating higher-privilege revocation). | Owner decision: **replacements removed from the SW Filter chain**. Rules made per-subfield; replacement permitted only within the two HW Binding chains; non-zero Boot Session and SW Filter subfields immutable; rationale NOTE preserved (HW chains narrow under equal-or-higher hardware trust; SW Filter entries are configured at decreasing privilege). |
| M4 | WARZ software-Locality CSRs could not be context-switched (hypervisors could not swap `sacelocality` between guests; SLocality-bound SCCs silently broke). | Owner decision: the five locality groups are **RW at their respective privilege levels**; section texts updated from WARZ; a NOTE assigns swap responsibility (M for supervisor domains; HS for VM state including `sacelocality`, which has no `vs*` shadow) and records why readability does not weaken the binding. `macecsk` follows its own rule: M-mode RW, activation only when all segments are written, no Debug access. |
| M5 | Export/import completion protocol incomplete: author-flagged missing 64/128-bit MDH cases; Form B could not carry a vector-started import's 128-bit `ml`; the authenticated MDH image and the trust in software-supplied `ml` unstated. | Form C added for 128-bit completions (owner); the WARNING replaced by a transport-independence NOTE (the variants differ only in how MDH[127:64] travels, exactly what `acestart` = 8/16 encodes; import steps 1–6 are the start/load phases); normative sentence: only `ml._ConfigStatus_` is consumed, and the authenticated `AD[0]` is the SCC-carried MDH — verified that a hostile `ml` yields no security break. Book 4 explicitly need not cover all variants (owner clarification). |
| M6 | ECC core semantics undefined (`Point_Mul` computation, trigger instruction, phantom `PublicKey` field); EdDSA two-pass machinery internally contradictory. | Behavior blocks written to the standard of the symmetric sections: _Point_Mul_ (Form D; base = `SecondPt` if `HasSecondPt` else `Generator`; mandatory curve/subgroup validation; result to `SecondPt`); _Sign_Generate_/_Sign_Verify_ by precise reference to FIPS 186-5 §6.4.1/6.4.2 and GM/T 0003.2 with all required checks; `HasSecondPt` dropped from the signing precondition (public keys play no role in ECDSA/SM2 signing); `PublicKey` deleted (`SecondPt` documented as its carrier); P-521 infinity sentinel exempted from the 55-zero-msbs rule. EdDSA: a complete pass protocol (Form B entry to _Msg_Absorb_ with a pass selector; same-state re-entry as the pass boundary; per-pass finalization producing `r`/`Signature.R`/`k'`; mode inferred from the path, the setterless `PreHash` field deleted); a _Set_Ctx_ state; the secret pass-1 scalar `r` serialized only mid-signing, on the `RndNum` precedent. |
| M7 | `Zklesha2h`/`Zklsm3h` claimed with no normative instantiation; HMAC's internal finalization contradicted the caller-pads model. | New `[[ACE-SHA-2]]` section (parameter table for all six functions, the big-endian word/digest mapping in `bswap`/`bin` terms, FIPS 180-4 references for compression and §5.3 IVs, SC layout, whole-blocks rule) and `[[ACE-SM3]]` (SHA-2 rules with SM3's IV/compression, GB/T 32905-2016). HMAC resolved by the internal-padding rule: under HMAC the unit pads using `cumul_len` (widened to 64 bits); stand-alone hashing keeps caller-side padding. Extension table repointed. |
| M8 | ML-DSA Serialized Context prose totals 256 bits higher than the field list, in all three parameter sets. | Diagnosed as an arithmetic slip (field list + padding were self-consistent; `rnd` plausibly double-counted): totals corrected to 53,376 / 77,312 / 99,968 bits = 417 / 604 / 781 blocks. No missing field. |
| M9 | Extension partitioning: conformance circularity around `Zklmem`; `Zklv` prose lists contradicting instruction membership; SM4×OCB promised but not encoded; "CTR/XCTR with set initial counter" advertised but undefined. | Four strands: (1) conformance restated as (`Zklv` ∨ `Zklio`) ∧ `Zklkn` ∧ `Zklmem`, with `Zklmem` implementable by trap-and-emulate (then `Zklmv` mandatory in hardware) — `ace.load`/`ace.store` always architecturally present; (2) an authoritative **instruction–extension matrix** replacing the prose lists (also curing the omission of `ace.derive` and `ace.size` Form C's `Zklv`-only status), with per-instruction *Included in* tables subordinate; (3) owner decision: **SM4-OCB not architected** (not standardized) — footnote scoped accordingly; (4) set-initial-counter defined **in-band**: a Form B `ace.setst`/`set_aux_value` operation setting `ctr ← lsb_j(Xs)`, wrap detection re-anchored to the most recently established initial value, with a no-added-misuse NOTE. |
| M10 | CTR/XCTR counter wrap unspecified (silent keystream reuse). | Wrap → no operation for that and later blocks, CR to _Invalid_, partial-progress rule applied. |
| M11 | `ace.setst` `r`=1/`X0` simultaneously "reserved" and the encoding of `ace.reset`. | Disambiguated: `#immed7` = 0 is `ace.reset`; all other values reserved → illegal-instruction. |
| M12 | ML-KEM `ace.derive` Form A/B contradiction; duplicated conflicting _Encapsulate_ blocks. | Uniformly Form B; blocks merged (Form D, `encapsk` precondition, success → _ciphertext_Output_). |
| M13 | Implementation-VDS corruption: import rejected the whole SCC on `SIV2` failure while the format section said "silently restart". | `SIV2` failure discards the VDS (`Content2` dropped, `ImpDataLen` ← 0) and the import completes; only `SIV` failure rejects — removing the corrupt-optional-data DoS. |
| M14 | GCM-SIV decryption `last_blk_len` accepted non-byte lengths, contradicting encryption and RFC 8452. | Decryption rule matched to encryption (nonzero, ≤ 120, multiple of 8), with the byte-orientation rationale. |
| M15 | Non-multiple `ACELEN` behavior unspecified across algorithms. | New Generic Rule: granularity violation → no operation, CR to _Invalid_. |
| M16 | Debug-mode policy contradicted itself between Books 1 and 3; CRF zeroization question open. | Owner selected the authenticated-debug resolution and drafted it; review hardening added: the impossibility carve-outs (HW Binding secrets and the model-3 hardwired CSK are **masked to zero until the next ACE unit reset**, not zeroized — mask-until-reset closes the planted-code window), the ACEIOBUF and its CSRs added to the zeroization list, `*lcrstatus`/ACES set to _Dirty_ (owner choice), the authenticated-Debug access rule (M privilege; `macecsk` neither readable nor writable; CC *usage* additionally gated by _UsagePolicy_ bit 4, so Debug normally performs only management — save, run its own contexts, restore); the unenforceable "entry via M-mode handler" replaced by the RISC-V-native answer: the authenticated-debug signal anchored to the Debug Module authentication interface (`dmstatus.authenticated`), resumable debugging = authenticated debugging, recovery after unauthenticated entry = reset + re-establishment + re-provisioning, with full recovery in CSK models 1–2 via re-establishing the same CSK. |
| M17 | `ace.mgmt` "uninterruptible" vs "management operations may be interrupted"; unbounded import latency. | Instruction-vs-process disambiguated; the interleaving of import decryption/authentication with the load phase promoted from a Book 4 note into Book 1 as the latency answer. |
| M18 | XEX one-key/two-key selection not encodable in the PI; security-critical branch unreachable. | Resolved per the spec's own declared convention: **two-key only** (SP 800-38E). PI/SC keyed on `_KeyType_` (one SKID resolves to both keys); the single-key branch removed; the Rogaway rationale retained as a warning that `key2` = `key1` recreates the attackable single-key variant. |
| M19 | Big-endian harts: "behavior undefined" in a security extension. | Replaced by a defined rule: any ACE instruction under big-endian effective data endianness raises illegal-instruction. |
| M20 | Trap-with-side-effects deviation unstated. | Absorbed into C1's trap-semantics rule. |
| M21 | Generic-hash output loop mixed bits and octets (including an indexing typo); 32-bit `cumul_len` silently capped inputs; SHA-3's `cumul_len` unserialized. | Loop rewritten unit-consistently in bits with `acestart` conversions; `cumul_len` widened to 64 bits (required by M7's HMAC rule); SHA-3's `max_length` made explicitly optional (zero = untracked, unserialized). |
| M22 | RVV-mini normatively required nonexistent instructions (`vins`/`vext`). | Replaced with real RVV mnemonics (`vmv.x.s`/`vmv.s.x`, the slide instructions; proper `.v[vxi]` forms for the logical ops). RVV-mini's formal definition remains flagged as pre-ratification work. |
| M23 | CSK "implementation-defined out of reset" contradicted the unavailable-until-configured model. | Out of reset the CSK is unconfigured and the unit unavailable until establishment (immediate for a hardwired CSK). |

---

## 4. Minor Findings

Of the thirty minor findings, the majority were mechanical and are now fixed; several were resolved by the owner directly (the `binBE` leftovers from an earlier refactor; the removal of Algorithm value 4095; the deletion of the orphaned `ace-instruction-summary.adoc`; assorted typos). Highlights of the remainder:

- **Consistency/correctness:** `#ace_CR_{provision,import,export}_end` unified to the defined `#ace_CR_management_end` (11 sites); the OCB _Decrypt_ state gained its missing `index` exhaustion guard; OCB's unusable `tag_len/64` encoding became `tag_len/32 − 2`; the never-used `AD_finalized`/`text_finalized` fields were deleted and the `L*`/`L$`/`L[i]` serialization clarified (only `L*` is serialized, the rest recomputed on import); the Ascon-Hash256 `countdown` underflow fixed; GCM's `tag`-field description corrected; a missing `bin(…)` restored in GCM's length-block formula; the CMAC Book 4 example no longer reads out of bounds for empty or unaligned messages; `bin(n,m)` defined as unsigned zero-extend/truncate; the "Off" terminology collision resolved (the state-zero table is now captioned _Unconfigured_); `_UsagePolicy_` coverage extended to VU-mode and non-H S-mode; `acemaxiobuflen` given a minimum (≥ the largest implemented granularity); `funct3` = 4 under `custom-2` and nonzero unused register fields in `ace.exec` Forms B/C declared reserved; the HMAC Serialized-Context key row reconciled with `K0`.
- **Owner decisions on the last five:** CMAC gained an internal verification path (Form C `ace.setst` with `#ace_state_hash_verify` in _Hash_Output_ — tag compared internally, undisclosed, → _Success_/_Failure_); Ascon-AEAD128 gained a `tag_len` setter (64 ≤ `Xs` ≤ 128 per SP 800-232, an operation rather than a state) with truncated emission; `ace_guru_meditation` renamed `ace_exc_fatal`; the normative Notation chapter moved out of the preface to stand as the first numbered chapter; Algorithm value 4095 removed by the owner.
- **Deliberately left:** the ECC section's repeated "Data Structures" label (owner preference); `src/ace-old-error-architecture.adoc` as intentionally untracked parked material.

---

## 5. Known-Answer-Test Work

The KAT suite follows a two-sided discipline — a reference implementation written directly from each standard, and an "ACE model" implementing the specification's value conventions literally, with negative controls that reinstate previously wrong formulations and must fail. Against the final specification:

- **Audited as already current:** `gcm-kat` (models the bits-based IV length, the long-IV GHASH path, and the transcription negative controls — i.e., the M1 fix is under test); `xts-kat` (two-key construction only, matching M18); the sealing, OCB, CMAC, HMAC, KMAC, SHAKE, ECC, ML-KEM and ML-DSA harnesses, whose data paths were not altered.
- **Extended:** `ctr-kat` now verifies the set-initial-counter operation (keystream from offsets including near-wrap equals the SP 800-38A reference at the same offsets, for CTR splits and XCTR); `ascon-kat` now locks the `tag_len` truncation semantics (the emission formula selects the first `tag_len`/8 octets of the standard tag, for 64/96/128).
- **New:** `sha2-kat.py` — a from-scratch implementation of `[[ACE-SHA-2]]` exactly as written (value-model word absorption via `bswap`, big-endian digest emission, §5.3 IVs with the SHA-512/t IVs generated by the §5.3.6 procedure, constants computed from prime roots), verified against `hashlib` for all six functions over ten padding-boundary message lengths, with a no-`bswap` negative control. `sm3-kat.py` — SM3 per `[[ACE-SM3]]`, anchored on both GB/T 32905-2016 appendix-A vectors and cross-checked against OpenSSL's `sm3`, with the same negative control.

**Result: 15/15 known-answer tests pass.** Every algorithm section whose semantics changed during the review now has coverage that would catch a regression of the specific change.

---

## 6. Verification Summary

| Check | Result |
|---|---|
| Full document build (asciidoctor + bibtex/diagram/lists, from repo root) | Success, zero warnings |
| Cross-reference audit | 168 anchors, 368 references, 0 unresolved, no duplicates |
| Bibliography | All 38 distinct citation keys resolve in `ace.bib` |
| Known-answer tests (`run-kats.py`) | 15/15 pass |

---

## 7. Remaining and Deferred Items

1. **M2** (excluded this session): the fixed zero-nonce AES-GCM-SIV sealing construction still asserts safety "by construction" without a stated bound or CSK-rotation guidance; RFC 8452's repeated-nonce limits should be addressed (quantitative bound, per-export nonce carried in the SCC, or a rotation policy) before external security review.
2. **ARC/ratification-track**, flagged in the document itself: exception cause-code numbers and encoding (a single ACE cause with subcause/CR-number reporting was suggested); opcode assignments (currently `custom-0/1/2`); `misa.L` and `mstatus[26:25]` allocations; the axiomatic integration of ACE component memory operations into RVWMO; the formal definition of RVV-mini.
3. **Housekeeping:** the working tree carries the entire resolution uncommitted at the time of writing; a commit capturing this verified state is recommended.

---

## 8. Assessment

With the Critical and Major findings resolved and verified, the grounds for the original "not ready" assessment no longer hold. The specification now has: a total, internally consistent error architecture that works with and without the Privileged Architecture; defined resumption, forward-progress, and memory-visibility semantics; a coherent operand model on the `VL`/`vstart` analogy; complete behavior definitions for the asymmetric algorithms; a defensible Debug-mode policy anchored to the standard Debug Module authentication interface; a closed conformance formula with an authoritative instruction–extension matrix; and misuse protections (budgets, wrap guards, no-reset rules) applied uniformly across the preset-IV/nonce algorithm variants. Subject to the deferred ARC items and a decision on M2, the document is, in this reviewer's judgment, **ready to advance as a candidate extension**.
