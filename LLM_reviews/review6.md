# Review 6 — Adversarial Technical Review of the ACE (Zkl) Specification, rev 0.7.0

**Reviewer:** independent adversarial review (candidacy assessment)
**Scope:** `src/ace.adoc` and every file it includes (`ace-symbols`, `ace-acronyms`,
`ace-contributors`, `ace-introduction`, `ace-books`, `ace-notation`, `ace-ISA-unpriv`,
`ace-ISA-algorithms`, `ace-ISA-priv`, `ace-pseudocode`, `index`, `bibliography`).
`ace-whitepaper.adoc` is *not* included by `ace.adoc` and was excluded. `ace-annexes.adoc`
is commented out at `ace.adoc:110`.
**Method:** full read of all 13 included files; cross-reference reconciliation (all `<<…>>`
targets resolve to a `[[…]]` anchor); inspection of the KAT suite and `kat-results.txt`;
verification of Ascon IV constants against the official SP 800-232 reference implementation
(`github.com/ascon/ascon-c`, `constants.h`); tracing of prior review history
(`review1`–`review5`, root-level rev-0.6.0 review).

---

## 1. Executive assessment

**Conditionally ready.**

The specification has matured substantially since the rev-0.6.0 review, which judged it
"not ready." The five Critical findings of that round (broken algorithm/standard alignment,
inoperative SCC authentication, missing error-model coherence, debug-mode exposure, and
verbatim export of generated key material) are all resolved or explicitly dispositioned. The
symmetric-algorithm data paths (AES ECB/CTR/XCTR/XEX/XTS/GCM/GCM-SIV/OCB3/CMAC, SHA-2/SHA-3/
SHAKE/SM3, HMAC/KMAC, Ascon) are now aligned with their cited standards and are undergirded by
a two-sided KAT suite (a from-standard reference implementation plus an ACE-value-model
implementation, with negative controls) that is reported to pass 15/15. The SCC sealing
construction is a deliberate, documented AES-GCM-SIV variant. The error-handling architecture is
now total (defined both with and without the Privileged Architecture).

What keeps this at "conditionally ready" rather than "ready" is a set of **encoding/allocation
prerequisites that are still TBD** and a small number of **semantic gaps** that are not yet
closed. None indicates architectural unsoundness, and most are already flagged by the authors as
Architecture Review Committee (ARC) track items. They must be resolved before/at ratification:

- Exception cause codes are all `TBD` (no `mcause` values assigned).
- Instruction encodings occupy `custom-0/1/2`, acknowledged to need replacement.
- All ACE CSR addresses are `0xXXX` / `(Indirect)` placeholders.
- `misa.L` and `mstatus[26:25]` (ACES) allocations are provisional and contested.
- RVV-mini is a normative dependency of `Zklv` but is unfinalized (and contains `vins/vext?`
  placeholders).
- The RVWMO axiomatic integration of ACE memory operations is deferred.

Plus the semantic gaps catalogued under M1–M5 below (an `acestart` clamping inconsistency, the
zero-nonce sealing bound, ML-KEM/ML-DSA underspecified invalid-input behavior).

If the ARC-track encoding items are treated as the normal ratification-track work they are, the
document is suitable to advance to candidacy **conditional on** closing M1–M5 and committing the
deferred ARC items to a resolution plan.

---

## 2. Findings

### Critical

**C1 — All ACE exception cause codes are `TBD`; no `mcause` values, no subcause mechanism.**
- *Severity rationale:* Without assigned cause values, software cannot distinguish any of the six
  ACE exceptions from one another or from other traps, so no trap handler, delegation
  (`medeleg`/`hedeleg`), or lazy-loading flow can be implemented. This "prevent[s] safe
  interoperability" by definition.
- *Location:* `ace-ISA-priv.adoc` §"Exceptions Raised by ACE" (L39–69); the
  `[[ACE-exception-codes]]` table has `TBD` in the Value column for all six ACE exceptions.
  Acknowledged in `ace-introduction.adoc` TODO ("We need to have a cause/subcause for our
  traps", L100–101).
- *Description:* `ace_exc_fatal`, `ace_exc_unsupported`, `ace_exc_CR_off`,
  `ace_exc_out_of_memory`, `ace_exc_privilege_violation`, `ace_exc_unconfigured_buffer` are each
  normatively referenced throughout Books 1 and 3, but none has an assigned cause number. The
  table notes the codes are "listed in decreasing priority order" and that "the actual numbers
  are TBD," and even the *encoding shape* (single cause + subcause vs. distinct causes) is open.
- *Standard reference:* RISC-V Privileged Architecture assigns `mcause` values; a candidate
  extension must request/allocate cause space.
- *Resolution:* Allocate cause values (or a single ACE cause + subcause register) with ARC; state
  the priority order normatively; define which causes are delegable. This is acknowledged ARC
  track work — commit it to the ratification plan.

**C2 — Instruction encodings occupy `custom-0/1/2`; acknowledged to need replacement.**
- *Severity rationale:* Standard RISC-V extensions may not be encoded in the `custom-*` opcode
  space; as written the instructions collide with any user's custom extensions and cannot be
  ratified. Interoperability-blocking until reallocated.
- *Location:* `ace-ISA-unpriv.adoc` §"Instructions" (L1417–1422: "Under opcode `custom-2`, the
  `funct3` value 4 is reserved"); `ace.load` uses `custom-0` (0x0b), `ace.store`/`ace.input`/
  `ace.output` use `custom-1` (0x2b), and `ace.exec`/`ace.setst`/`ace.mgmt`/`ace.getmd*`/
  `ace.restrict*`/`ace.clone`/`ace.derive`/`ace.size` use `custom-2` (0x5b). Acknowledged in
  `ace-introduction.adoc` TODO ("Assignment of opcodes … are preliminary. At a minimum, we need
  three opcodes in place of `custom-0`, `custom-1`, and `custom-2`.", L107).
- *Description:* Three major opcodes are needed (load-class, store-class, exec-class). The
  `funct3`/`funct2`/`Form`/`r` sub-field layout within `custom-2` is internally consistent, but
  the base opcodes must come from assigned standard space.
- *Standard reference:* RISC-V Unprivileged ISA reserves `custom-0..3` for custom extensions.
- *Resolution:* Request three standard opcodes from ARC and re-derive the sub-field maps.
  Acknowledged ARC track work.

### Major

**M1 — `acestart` clamping policy ("`acestart` cannot be larger than `aceiobuftop`") is
inconsistent with CR-directed transfers (`ace.load`/`ace.store`/`ace.mv`).**
- *Severity rationale:* A literal implementation of the clamp breaks transfers larger than
  `aceiobuftop` — including every large CR (ML-KEM-1024 ≈ 4.8 KB, ML-DSA-87 ≈ 12.5 KB) — which
  can livelock a resume handler. Material correctness/implementability defect.
- *Location:* `ace-ISA-unpriv.adoc` §`acestart` (L1254–1256): "The following policy applies to
  `acestart`: `acestart` cannot be larger than `aceiobuftop`. If a value larger than
  `aceiobuftop` is written to `acestart`, `acestart` will be set to `aceiobuftop`." Contrast
  L1238–1241 (`acestart` also tracks `ace.load`, `ace.store`, `ace.mv`, and multi-block
  `ace.exec`) and L1249 ("for ACEIOBUF operands the window itself is always [0, `aceiobuftop`)").
- *Description:* `aceiobuftop` is, by its own definition (L1198–1202), the ACEIOBUF operand
  window bound (the `VL` analogue) for `ace.input`/`ace.output`. But `acestart` is *also* the
  progress counter for CR-directed transfers (`ace.load`/`ace.store`/`ace.mv`), whose transfer
  size is the PI/SCC size — unrelated to, and typically far larger than, `aceiobuftop`. As
  written, the clamp either (a) applies only to ACEIOBUF operands and is mis-scoped/mis-worded,
  or (b) applies generally and makes any transfer larger than `aceiobuftop` unable to advance
  `acestart` past `aceiobuftop`, so it can never complete. Either reading yields a different
  implementation.
- *Resolution:* Scope the clamp explicitly: "`acestart` is bounded above by the current operand
  window bound: `aceiobuftop` for ACEIOBUF operands, and the PI/SCC length (in bytes) for
  CR-directed transfers." State the bound for `ace.load`/`ace.store`/`ace.mv` normatively.

**M2 — Zero-nonce AES-GCM-SIV sealing asserts safety "by construction" without a quantitative
bound or CSK-rotation guidance (RFC 8452 repeated-nonce limits).**
- *Severity rationale:* This is the mechanism that protects *every* key at rest/in transit. The
  construction is sound in shape (GCM-SIV is nonce-misuse-resistant), but with a fixed zero nonce
  under a long-lived CSK the security bound degrades with the number of sealed contexts, and the
  spec gives neither a bound nor a rotation policy. (This was review5's M2, excluded by owner
  decision; re-raised because the task directs that omissions not be downgraded.)
- *Location:* `ace-ISA-unpriv.adoc` §"Generation of an SCC" (`SCC_Encrypt`/`SCC_Decrypt`
  L3377–3424, nonce passed as `zeros(96)`); the `[IMPORTANT]` block (L3484–3492) claims safety
  "by construction." The removed `acenonce0/1` CSRs survive only as commented-out text
  (L1277–1297).
- *Description:* Every export under a given CSK uses nonce = 0. GCM-SIV nonce-misuse resistance
  keeps plaintexts confidential under nonce reuse, but (a) sealing is deterministic — identical
  CR contents always produce identical SCCs, leaking equality of key material across exports and
  across harts sharing a CSK; and (b) RFC 8452 §9 / Gueron–Langley–Lindell bound the number of
  messages that should share a (key, nonce) pair. A context-switching system can seal many SCCs
  per CSK over its lifetime.
- *Standard reference:* RFC 8452 §9 (security considerations, nonce-reuse limits).
- *Resolution:* Either (a) carry a per-export nonce in the SCC (restore the `acenonce` design,
  plaintext nonce ahead of `SIV`), or (b) state a concrete advantage bound for `q` exports of ≤
  `l` blocks under one CSK and add a normative CSK-rotation requirement sized to that bound.

**M3 — `misa.L` and `mstatus[26:25]` (ACES) allocations are provisional and contested.**
- *Severity rationale:* The presence-detection and context-status mechanisms rest on field
  placements that "are contested by other extensions" and "not agreed with ARC." Until settled,
  OS/hypervisor integration cannot be written portably.
- *Location:* `ace-ISA-priv.adoc` §"ACE field in `misa`" (L101–120) and §"ACE Context Status in
  `mstatus` and `sstatus`" (L124–142); both carry `[WARNING]` blocks stating the allocations are
  provisional and may move (possibly to the unified discovery mechanism).
- *Description:* `misa.L` (bit 11) signals ACE presence; `mstatus[26:25]`/`sstatus[26:25]`/
  `vsstatus[26:25]` hold ACES (Off/Initial/Clean/Dirty, FS/VS-analogous). Both are flagged as
  unsettled. The semantics (not the offsets) are well-defined, so this is an allocation issue.
- *Resolution:* Resolve with ARC (discovery mechanism vs. `misa` bit; ACES offset or alternate
  carrier). Acknowledged ARC track work.

**M4 — RVV-mini is a normative dependency of `Zklv` but is unfinalized and under-specified.**
- *Severity rationale:* `Zklv` requires "at least the RVV-mini subset of `V`," yet RVV-mini is
  explicitly not finalized and may be defined *after* ACE ratification. A normative dependency
  cannot dangle on an undefined subset; `Zklv` conformance is currently uncheckable.
- *Location:* `ace-ISA-unpriv.adoc` §"RVV/RVV-mini" (L335–365); the red `[WARNING]` (L360–365)
  states RVV-mini "need not be finalized before ACE ratification begins; it may be defined
  later." Contains literal placeholders "`vmv.x.s` and `vmv.s.x` (`vins`/`vext`?)" (L349, L358).
- *Description:* RVV-mini is described (128-bit registers/groups, tail/mask-agnostic, LMUL
  1/2/4/8, unit-stride loads/stores, a move/insert/extract set, vector logicals, `Zvbc`
  `vclmul`), but the move/insert/extract instruction set is not pinned (`vins`/`vext` are not
  ratified RVV mnemonics), and the subset is declared amendable post-ratification.
- *Resolution:* Either fully specify RVV-mini in this document (it is small) with ratified RVV
  mnemonics, or make full `V` (with `Zvl128b`) the `Zklv` dependency and defer RVV-mini to a
  separate extension. Remove the `vins/vext?` placeholders.

**M5 — ML-KEM/ML-DSA underspecified behavior on invalid inputs; ML-KEM.Decaps modeled with a
Failure branch it cannot take.**
- *Severity rationale:* "may return unpredictable results" is not implementable normative
  language, and FIPS 203 `ML-KEM.Decaps` is total (implicit rejection) so a Failure branch is
  misleading. Under-specified fault behavior in a PQC primitive is a correctness/safety gap.
- *Location:* `ace-ISA-algorithms.adoc` §ML-KEM (L3783–3785: "If the values are not valid, the
  encapsulation and decapsulation procedures may return unpredictable results or fail with a
  transition to Error State `ace_state_failure`") and §ML-DSA (L3963–3966, same phrasing);
  `_Decapsulate_` "succeeds → `_Success_`, else → `_Failure_`".
- *Description:* FIPS 203 `ML-KEM.Decaps` always outputs a shared key (real or implicitly
  rejected); it does not signal failure, so the "else Failure" branch does not correspond to the
  standard. More importantly, "unpredictable results" on invalid input leaves implementations
  free to diverge (return garbage vs. trap), which is exactly the class of under-specification
  this review is directed to reject.
- *Standard reference:* FIPS 203 (ML-KEM.Decaps implicit rejection); FIPS 204.
- *Resolution:* Replace "may return unpredictable results" with defined behavior: on invalid
  input, transition to Error State `_Invalid` (or `_Failure`) and perform no output. Reconcile
  `_Decapsulate_` with FIPS 203 implicit rejection (decapsulation always yields a key; model any
  error as a malformed-encoding condition, not a decapsulation failure).

### Minor

**m1 — RVWMO axiomatic integration of ACE component memory operations is deferred.**
- *Location:* `ace-ISA-unpriv.adoc` §"Memory Model" (L907–936), `[WARNING]` (L931–936): "A full
  axiomatic integration … remains to be produced together with the ARC during ratification."
- *Description:* The prose memory model (program-order appearance on the local hart; RVWMO/RVTSO
  at instruction level; prefix-complete `acestart` reporting) is coherent and the resumability
  section closes the visibility question operationally, but the formal RVWMO embedding is
  outstanding. Acknowledged ARC track work.

**m2 — SCCs have no anti-replay; re-importing an old SCC rolls counter-mode state back.**
- *Location:* `ace-ISA-unpriv.adoc` §"Provisioning, Import, and Export" (L1465–1468); GCM-with-IV
  and Ascon-set-nonce NOTEs (L1249–1251, L2943–2946).
- *Description:* Explicitly by design ("individual CRs do not have to resist rollback via export
  and import, and cannot"). Re-import of a stale SCC can reinstall a counter/nonce and enable a
  multi-time pad in CTR/XCTR/GCM/OCB. The `budget` mechanism mitigates in-CR reset but not SCC
  replay. This is a documented acceptance, but it should be surfaced prominently (ideally a
  normative Security Considerations note) so integrators do not assume replay protection.

**m3 — Management operations are not usage-controlled; a lower-privileged mode can overwrite a
higher-privileged mode's CR.**
- *Location:* `ace-ISA-unpriv.adoc` §"Provisioning, Import, and Export" (L1470–1473).
- *Description:* By design (required for context switching). The spec places the obligation on
  higher-privileged software to clear CRs before yielding control. Correct as stated, but the
  context-substitution consequence deserves an explicit normative statement (it is currently in
  an informative subsection).

**m4 — POLYVAL omits RFC 8452's length block (acknowledged, by design).**
- *Location:* `ace-ISA-unpriv.adoc` §"AES-GCM-SIV Key Derivation and POLYVAL" (L3284–3291).
- *Description:* The length block is dropped on the stated rationale that all section lengths are
  determined by the MDH (which is itself authenticated AD). Reasonable, but it is a deviation from
  RFC 8452 whose security argument is no longer the standard's proof verbatim; the rationale
  (presently a note) should be elevated to normative text and the deviation stated plainly.

**m5 — RVV-mini move/insert/extract set uses unratified placeholders (`vins`/`vext?`).**
- *Location:* `ace-ISA-unpriv.adoc` L349, L358. (Folded into M4 for resolution.)

**m6 — `ace.exec` element-width / EGW question left open for non-power-of-two input sizes.**
- *Location:* `ace-ISA-unpriv.adoc` §"RVV/RVV-mini" `[WARNING]` (L326–330): "We need to define
  the element widths for the indivisible operations performed by `ace.exec`, esp. when some
  ciphers or hash functions have inputs whose size is not a power of two."
- *Description:* Open ARC discussion (issue #96). Affects how `ace.exec` granularity is expressed
  for inputs whose size is not a power of two. Should be resolved before freeze.

---

## 3. Cross-document inconsistencies and missing requirements

- **`acestart` bound** (M1): the general clamp to `aceiobuftop` conflicts with CR-directed
  transfers bounded by PI/SCC length. The only internal inconsistency of consequence found.
- **Cause codes / opcodes / CSR addresses** (C1, C2, and CSR `0xXXX`): three distinct allocation
  gaps, all acknowledged, all blocking ratification.
- **`mstatus.ACES` vs. `vsstatus.ACES` gating** is consistent (both must be non-Off when V=1);
  `*lcrstatus` evaluation is correctly ordered after illegal-instruction checks. No conflict found.
- **ML-KEM.Decaps Failure branch vs. FIPS 203 implicit rejection** (M5).
- **RVV-mini dependency** (M4) vs. `Zklv` conformance requirement (`ace-ISA-unpriv.adoc`
  L152–153): `Zklv` conformance is uncheckable while RVV-mini is undefined.
- **No missing cross-references:** every `<<…>>` resolves; the `[[ACE-forward-progress]]`,
  `[[ACE-resumability-memory-model]]`, `[[ACE-length-rule]]`, and `[[ACE-exception-codes]]`
  anchors all exist and are cited consistently.
- **KAT coverage note:** `ascon-kat.py` validates round-trip + tamper-rejection + a negative
  control but does **not** check against official SP 800-232 KAT vectors (the official repo ships
  `LWC_AEAD_KAT_128_128.txt`). The IV constants *do* match the official reference
  (`ASCON_128A_IV = 0x00001000808c0001`; Ascon-AEAD128 = formerly Ascon-128a), but adding the
  official vectors would strengthen conformance evidence.

## 4. Standards-compliance matrix

| Requirement / Standard | Doc location | Assessment | Evidence |
|---|---|---|---|
| AES ECB/CTR/XCTR (SP 800-38A) | `ace-ISA-algorithms.adoc` §ECB, §keystream | Compliant | `ctr-kat.py` anchors REF on SP 800-38A F.5.1; counter block `bswap(ctr) @ IV` |
| XEX/XTS (SP 800-38E / IEEE 1619) | §XEX/XTS, §XTS-from-XEX | Compliant | `xts-kat.py` vs IEEE 1619; two-key-only, `update_mask` little-endian |
| GCM (SP 800-38D) | §GCM | Compliant | `gcm-kat.py`; 96-bit-IV `J0` and GHASH length block correct |
| GCM-SIV (RFC 8452) | §GCM-SIV | Compliant (data path) | `ACE-SCC` KAT + GCM-SIV examples; counter `1 @ SIV[126:32] @ LE32` |
| OCB3 (RFC 7253) | §OCB | Compliant | `ocb-kat.py` vs RFC 7253 Appendix A; `double` = big-endian doubling |
| CMAC (SP 800-38B) | §CMAC | Compliant | `cmac-kat.py`; big-endian subkey `double` |
| SHA-2 (FIPS 180-4) / SHA-3/SHAKE (FIPS 202) / SM3 | §SHA-2, §SHA-3, §SM3 | Compliant | `sha2-kat.py`, `shake-kat.py` (FIPS 202 empty-msg KAT), `sm3-kat.py` |
| HMAC (FIPS 198-1 / RFC 4231) / KMAC (SP 800-185) | §HMAC, §KMAC | Compliant | `hmac-kat.py` (RFC 4231), `kmac-kat.py` (SP 800-185 samples) |
| Ascon (SP 800-232) | §Ascon-* | Compliant (constants/params) | IVs match official `ascon-c` `constants.h`; AEAD128 = former Ascon-128a; **no official KAT vectors run** |
| ECC (FIPS 186-5 / RFC 8032 / RFC 5639 / GM/T) | §ECC, §EdDSA | Stated compliant | References cited; `ecc-kat.py` present (secp256r1/ed25519) |
| ML-KEM (FIPS 203) / ML-DSA (FIPS 204) | §ML-KEM, §ML-DSA | Partially compliant | Sizes/params match; **Decaps Failure branch & "unpredictable results" diverge (M5)** |
| SCC sealing (AES-GCM-SIV variant) | §export-import-algorithms | Deliberate variant | Documented deviation (no length block, zero nonce); sound in shape, bound missing (M2, m4) |
| Exception causes / opcodes / CSR addresses | `ace-ISA-priv.adoc`, `ace-ISA-unpriv.adoc` | **Non-compliant (TBD)** | C1, C2, CSR `0xXXX` |
| RVV-mini dependency | `ace-ISA-unpriv.adoc` | **Unfinalized** | M4 |

## 5. Suggested prioritized remediation plan

1. **(Blocking, ARC track)** Allocate exception cause codes (C1) and three standard opcodes
   (C2); assign ACE CSR addresses. These gate ratification and are already acknowledged.
2. **(Blocking, ARC track)** Resolve `misa.L` / `mstatus[26:25]` ACES placement (M3) and the
   RVWMO axiomatic integration (m1).
3. **(High)** Fix the `acestart` bound wording (M1): scope the clamp to ACEIOBUF operands and
   define the bound for CR-directed transfers as the PI/SCC length.
4. **(High)** Either restore a per-export nonce for SCC sealing or state a quantitative
   (key,nonce)-reuse bound plus a CSK-rotation requirement (M2).
5. **(High)** Pin RVV-mini (ratified mnemonics, no `vins/vext?`) or switch `Zklv` to full
   `V`/`Zvl128b` (M4, m5).
6. **(Medium)** Replace "may return unpredictable results" with defined error-state transitions
   and reconcile ML-KEM.Decaps with FIPS 203 implicit rejection (M5).
7. **(Medium)** Resolve the `ace.exec` element-width/EGW question for non-power-of-two inputs
   (m6).
8. **(Low)** Elevate the SCC no-replay acceptance (m2), the management-op context-substitution
   obligation (m3), and the POLYVAL length-block deviation rationale (m4) into normative
   Security Considerations text.
9. **(Low)** Add official SP 800-232 Ascon KAT vectors to `ascon-kat.py`.

## 6. Remaining review questions and assumptions

- **Independently re-executed (this session):** the full KAT suite — `python3 run-kats.py`
  reports **"all 15 known-answer tests passed"** (ascon, cmac, ctr, ecc, gcm, hmac, kmac,
  mldsa, mlkem, ocb, scc, sha2, shake, sm3, xts). The harness (`run-kats.py`) is robust: a
  script either declares `KAT-RESULT: PASS/FAIL`, or the runner scans for FAIL and excuses only
  FAILs inside columns/lines declared via `KAT-EXPECT-FAIL:`; a declared negative control that
  *fails to fire* is itself reported as a failure, so the tests retain discriminating power.
  `ocb-kat.py` was additionally run standalone: ACE matches RFC 7253 Appendix A vectors for
  encrypt and decrypt, and tampered ciphertexts are rejected.
- **Independently re-executed (this session):** the document build —
  `make SKIP_DOCKER=true build-no-container` reports **"Build completed successfully"** with
  `--failure-level=ERROR`; the log contains no asciidoctor ERROR/WARNING lines (only benign
  Ruby-gem `strscan` and xcode-sandbox noise), and a fresh `build/ace.pdf` was produced.
  (Note: the Makefile passes `-a revnumber=v0.6.0`, its `VERSION` default, which overrides the
  document header's `:revnumber: 0.7.0` in the rendered PDF — a cosmetic build-config mismatch.)
- **Assumption:** the Ascon IV/parameter match was verified against the official `ascon-c`
  reference (`constants.h`, README), not against the SP 800-232 PDF text directly.
- **Open:** exact cause-code encoding shape (single cause + subcause vs. distinct causes) — an
  ARC decision that changes handler design.
- **Open:** whether RVV-mini will be a standalone extension or folded into `V`.
- **Open:** the `ace.exec` EGW/element-width model for non-power-of-two algorithm inputs
  (issue #96).
- **Question:** should SCC sealing carry a per-export nonce (restore `acenonce`) rather than rely
  on GCM-SIV misuse resistance with a zero nonce? (M2.)
- **Not reviewed:** `ace-whitepaper.adoc` (not included by `ace.adoc`), `ace-annexes.adoc`
  (commented out), the `LLM_reviews/` prior reviews (used as history only), and non-`src`
  build tooling.
