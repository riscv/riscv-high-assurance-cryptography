# ACE (Zkl) Technical Review — Readiness as a RISC-V Extension Candidate

Scope: `src/ace.adoc` and the files it includes only
(`ace-symbols`, `ace-acronyms`, `ace-contributors`, `ace-introduction`, `ace-books`,
`ace-ISA-unpriv`, `ace-ISA-algorithms`, `ace-ISA-priv`, `ace-pseudocode`, `index`,
`bibliography`). `ace-annexes.adoc` is commented out at `ace.adoc:105` and was not
reviewed; `ace-examples.adoc`, `ace-whitepaper.adoc` and `ace-instruction-summary.adoc`
are not included by the top file.

Focus: technical correctness, and alignment of the specified algorithms with the
standards they cite.

---

## Status update — Conventions section added

A normative **Conventions** section has since been added at the end of
`ace-conventions.adoc` (anchor `ACE-conventions`), together with `:alpha:` and `:sect:`
in `ace-symbols.adoc`. It resolves **C1** and **C2**, and with them the findings that
were flagged as contingent on the ordering convention. The adopted convention is:

> The octet at index *i* of a string occupies bits **[8i+7 : 8i]** of the corresponding
> value — the first octet in the least significant bits — and `A @ B` places `A` in the
> **more** significant bits.

This was not a free choice between the two candidates raised in the original review. It
is forced by the vector-register interface: a unit-stride `vle8.v` places the
lowest-addressed octet in the lowest-numbered element, and `ACE-ECB-mode` already
requires multi-block operands to be processed "from the blocks in the least significant
positions". The alternative (plain big-endian numbering of the 128-bit string) would
have made OCB's `double()` correct and essentially everything else wrong.

**Findings confirmed by the convention** (previously contingent):

| Finding | Status |
|---------|--------|
| C5, C6 (OCB3) | **Confirmed.** `double()` as written is the *XTS* operation; OCB specifies it over a big-endian string. The nonce assembly is reversed on top of the arithmetic errors. |
| C8 (Ascon empty final block) | **Confirmed.** `pad(∅,128)` = `zeros(127) @ 1` sets bit 0 of the rate, i.e. `state[0]`, not bit 127. |
| C9 (Ascon partial decrypt) | Confirmed; was never convention-dependent. |
| C3 (`RFC8452_KeyDeriv`) | **Partly retracted.** The counter block `nonce @ bin(i,32)` and the `[63:0]` selection are **correct** under the convention. Only the ordering of the concatenated key halves was wrong. |
| GCM-SIV `0 @ SIV[126:0]`, `1 @ SIV[126:32] @ …` | **Correct** under the convention — these clear/set the MSB of the *last* octet and increment the *first* four octets as an LE integer, exactly as RFC 8452 requires. Not defects. |

**New finding surfaced while writing the section** (now fixed):

* **C15 — GCM `J0` for a 96-bit IV was built in the wrong octet order.**
  `ace-ISA-algorithms.adoc` had `J0[127:0] <- J0[95:0] @ 0^31 @ 1`, which places the IV
  in `J0[127:32]` and the counter in `J0[31:0]` — the reverse of SP 800-38D §7.1, and
  with the counter octets little-endian rather than big-endian. Corrected to
  `J0 <- binBE(1,32) @ J0[95:0]`.

**A second finding surfaced while fixing m17** (now fixed):

* **C16 — the GCM and GCM-SIV counter increments performed no modular reduction.**
  Modulo was written `%` in four places and `mod` in seven; unifying on `mod` and
  defining it made a latent precedence bug explicit. `J0[31:0] + 1 mod 2^32` and
  `SIV[31:0] + ctr mod 2^32` parse as `a + (1 mod 2^32)` = `a + 1`, so the 32-bit
  counters would never wrap and the wrap-detection guard at
  `ace-ISA-algorithms.adoc:856` could never fire. All four sites are now parenthesised
  as `(J0[31:0] + 1) mod 2^32`. This is the precedence half of m22, escalated because
  the consequence is a counter that never wraps rather than a notational ambiguity.

**Two further findings surfaced while fixing C5 and C6** (both now fixed):

* **C17 — the OCB3 partial-block padding was oriented wrongly, at three sites.**
  The spec wrote `zeros(b-n-1) @ 1 @ X[n-1:0]`, placing the terminating `1` at bit `n`.
  RFC 7253 §4.2 appends the `1` immediately after the data *in string order*, and under
  <<ACE-Notation>> the first bit of an octet is its most significant bit — so for a
  byte-aligned `n` the `1` is the top bit of octet `n/8`, i.e. bit `n+7`. For a one-octet
  partial block the spec set bit 8 where bit 15 is required. This affected the AD last
  block as well as both text last blocks, so it was not covered by C6. Replaced
  throughout by a new `ocb_pad(X, n)` = `zeros(120-n) @ 0b10000000 @ X[n-1:0]`.
  `last_blk_len` is now also constrained to a multiple of 8 in `[0,120]`, since
  RFC 7253 defines OCB over byte strings.

* **C18 — OCB3 full-block decryption used the forward cipher.**
  `ace-ISA-algorithms.adoc:1513` read `tmp <- offset xor enc_blk(key, INPUT xor offset)`
  where RFC 7253 §4.2 requires `DECIPHER`. `dec_blk` was declared in OCB's
  Algorithm-Specific Functions and never used anywhere — the tell. Decryption of any
  multi-block message returned garbage. Corrected to `dec_blk`.

**Verification.** The corrected OCB3 text was transcribed literally into an executable
model (ACE value semantics: octet *i* at bits [8i+7:8i]) and run against all of
RFC 7253 Appendix A, alongside an independent byte-string reference implementation of
RFC 7253 and a pure-Python AES-128 checked against FIPS-197 C.1:

* encryption — 7/7 vectors match the RFC, and match the independent reference;
* decryption — 7/7 recover the plaintext, verify the tag, and reject a single-bit
  ciphertext flip.

This exercised `Nonce_be`, `bottom`, `Ktop`, `Stretch_be`, `Offset~0~`, `double`,
`ocb_pad`, both final-block checksums and `dec_blk`. It also caught an error in the
first draft of the correction: `Nonce_be` needs `bswap(N[N_len-1:0])`, not
`N[N_len-1:0]`, because `N` is stored in ACE octet order while `Nonce_be` is the
big-endian view. Without the test that would have shipped.

**Findings from the C7/C9-C14 round.** Two more normative defects were found while
correcting the GCM example, both confirmed by test and both fixed:

* **C19 - the GCM and GCM-SIV length blocks were assembled in the wrong order.**
  SP 800-38D 7.1 puts `[len(A)]~64~` in octets 0-7 and `[len(C)]~64~` in octets 8-15;
  RFC 8452 4 likewise puts the AAD length first. Under <<ACE-Notation>> the first
  octets are the *least* significant, so the AD length must be the **right** operand of
  `@`. All four normative sites had it as the left operand. Corrected to
  `binBE(len_in_bits(plaintext),64) @ binBE(len_in_bits(AD),64)` for GCM and the `bin`
  equivalent for GCM-SIV.

* **C20 - the GCM counter was taken from the wrong end of the counter block.**
  The spec incremented `J0[31:0]` and set `start_ctr <- J0[31:0]`. Under the convention
  `J0[31:0]` is octets 0-3, i.e. the first four octets of the *IV*; the GCM counter is
  octets 12-15, `J0[127:96]`, read as a big-endian integer. The state machine now keeps
  `ctr` and `start_ctr` as integers, increments `ctr` modulo 2^32^, and forms each
  counter block as `binBE(ctr,32) @ J0[95:0]`.

**Verification of this round.** `src/gcm-kat.py` builds a reference GCM on byte strings
and an ACE-model GCM, and runs both against the classic 96-bit-IV GCM test cases. Both
pass; the length-block-swapped variant and the counter-in-low-octets variant both fail,
so the two corrections above are confirmed rather than inferred. The run also
independently confirms the `Galoismul` mapping of <<ACE-conventions-fields>>: under the
ACE convention it is the plain SP 800-38D multiply on the octet string, with no `bswap`.

`src/ascon-kat.py` exercises the corrected Ascon `_Enc_Last_Block_`/`_Dec_Last_Block_`
text over 160 AD/plaintext length combinations (AD 0/5/16/23 octets x plaintext 0-39):
round-trip, tag verification and single-bit tamper rejection all pass, and the previous
text fails the same test - so C8 and C9 were real and the test has power over them.

**Corrections applied so far:**

| Finding | File | Change |
|---------|------|--------|
| C1, C2 | `ace-conventions.adoc`, `ace-symbols.adoc` | Conventions section; `Galoismul` / `Montmul` / `update_mask` / `double` defined with explicit coefficient mappings |
| C2 (`double`) | `ace-ISA-algorithms.adoc` | `double(S)` = `bswap(update_mask(bswap(S)))`, expanded, with a note that it is *not* `update_mask`. **This does not close C5 or C6**, which are separate defects in OCB's nonce processing and final-block checksum |
| C3 | `ace-ISA-unpriv.adoc` | `RFC8452_KeyDeriv` rewritten: valid syntax, named struct fields, halves concatenated in decreasing index order |
| C4 (part) | `ace-ISA-unpriv.adoc` | `AESE` → `AESE256`; `tmp` fully assigned before use in `AES_GCM_SIV_Decrypt` |
| C4 | `ace-ISA-unpriv.adoc` | Length-block omission documented as deliberate, with the argument that the MDH is the first AD block and determines every length in the computation (`ACE-SCC-no-length-block`), plus a note that the result is a *variant* and cannot be validated against RFC 8452 vectors. Nonce reuse across the two AEAD passes justified in `ACE-SCC-export`. Stale reference to "Sections 3.a and 3.b" corrected to Section 3 |
| C5 | `ace-ISA-algorithms.adoc` | Nonce-dependent variables recomputed in the `bswap` view: `Nonce_be` (with `tag_len mod 128`, `zeros(120-N_len)`, `bswap(N)`), `bottom` from 6 bits, `Ktop` with those bits cleared in place, `Stretch_be` 192 bits, `Offset~0~` = `bswap(Stretch_be[191-bottom : 64-bottom])` |
| C6 | `ace-ISA-algorithms.adoc` | Final-block checksum folds the plaintext: `ocb_pad(INPUT, ...)` when encrypting, `ocb_pad(OUTPUT, ...)` when decrypting |
| C7 | `ace-pseudocode.adoc` | GCM example counter starts at 2 (`inc32(J0)`); `J0` rebuilt as `binBE(counter,32) @ V0[95:0]`; tag mask uses counter 1; `vsetvli` with an immediate -> `vsetivli` throughout Book 4 |
| C8 | `ace-ISA-algorithms.adoc` | Both Ascon sites: `state[1] xor (1 << 63)` → `state[0] xor 1` |
| C9 | `ace-ISA-algorithms.adoc` | Ascon `_Dec_Last_Block_`: rate updated by `S_r xor pad(P)` on the recovered plaintext, replacing the assignment of `pad(INPUT)` |
| C10 | `ace-ISA-algorithms.adoc` | ECC, ML-KEM and ML-DSA now use `_Success_ (22)` / `_Failure_ (23)`, matching Book 1 |
| C11 | `ace-ISA-algorithms.adoc` | `process_VLI`: `cumul_len` advanced each iteration; `amount` no longer clamped by `len` when `len` = 0, so the loop terminates |
| C12 | `ace-ISA-unpriv.adoc` | `ace.store`, `ace.input`, `ace.output` moved from `0x27` (STORE-FP) to `0x2b` (custom-1) |
| C13, M4 | `ace-ISA-unpriv.adoc` | The CR operand is encoded in `rs1` in **all four** `ace.exec` Forms; each Form zeroes the fields it does not use (`rd` with no output vector, `rs2` with no input vector). `ace.mv` takes its sub-opcode from whichever field the corresponding Form leaves free: `rd` in Form B, `rs2` in Form C. `ace.mv`'s Description was rewritten to match, which also closes **M4** (its directions and operand names were inverted relative to its own encoding) |
| C14 | `ace-ISA-unpriv.adoc`, `ace-ISA-algorithms.adoc`, `ace-ISA-priv.adoc` | `ace.prov` / `ace.export` / `ace.import` replaced by `ace.mgmt` / `ace.load` / `ace.store` at all 16 sites |
| C15 | `ace-ISA-algorithms.adoc` | `J0 <- binBE(1,32) @ J0[95:0]` |
| C16, m22 (part) | `ace-ISA-algorithms.adoc`, `ace-ISA-unpriv.adoc` | Counter increments parenthesised at all four sites; missing opening backtick repaired at line 892 |
| C17 | `ace-ISA-algorithms.adoc` | `ocb_pad` introduced and used at all three partial-block sites; `last_blk_len` restricted to a multiple of 8 in [0,120] |
| C18 | `ace-ISA-algorithms.adoc` | Full-block OCB decryption: `enc_blk` -> `dec_blk` |
| C19 | `ace-ISA-algorithms.adoc`, `ace-pseudocode.adoc` | Length blocks reordered (AD length as the right operand) at all normative and example sites |
| C20 | `ace-ISA-algorithms.adoc` | GCM counter held as an integer; counter block `binBE(ctr,32) @ J0[95:0]` |
| M1 | `ace-ISA-unpriv.adoc` | `_UsagePolicy_` now fits its 5 bits: bits 0-3 disallow U-, (V)S-, HS- and M-mode use; bit 4 grants Debug use when set. `ace.restrict` given bit 4's inverted polarity explicitly: a one in the input *clears* it, so a restrict can still only ever remove a permission |
| M2 | `ace-ISA-unpriv.adoc` | New authoritative subsection `ACE-length-rule` fixing the three lengths separately: PI = f(_Algorithm_, _AlgorithmPolicy_, _KeyType_) with _ImpDataLen_, _SCProtection_ and _StateExtension_ required to be zero; SCC = the same plus _StateExtension_, plus the VDS sized by _ImpDataLen_, and explicitly *not* _SCProtection_; CRF capacity = f(_Algorithm_, _AlgorithmPolicy_, _SCProtection_). All 13 scattered per-field claims now point at it |
| M3 | `ace-ISA-unpriv.adoc` | `ace.size` no longer claims to report a PI length; a remark records that the caller constructs the PI and so knows its length, and that no code may assume an SCC is at least as long as the corresponding PI. The two provisioning snippets no longer call `ace.size` for it |
| M5 | `ace-ISA-unpriv.adoc` | `ace.restrict` bit `v` = 0 now correctly yields `ace.restrictl`/`ace.restricth`. `_SCProtection_` added to the fields `ace.restrictl` may modify: a non-zero input is a *request* to raise the level, only ever strengthening it, and it may fail with `ace_state_out_of_mem` / `ace_exc_out_of_mem` if the CRF cannot supply the extra capacity. Failure destroys the CC by design — fail-closed, since the caller has declared the current level inadequate — and that is stated as deliberate rather than left as an artefact of the Error-State rules |
| M6 | `ace-ISA-algorithms.adoc` | Single name for each quantity: `auth_key` throughout GCM and GCM-SIV (10 sites), `start_ctr` and `ctr` for the counter (`reset_ctr` / `reset_at` were already retired under C20) |
| M7 | `ace-ISA-algorithms.adoc` | `_Enc_Tag_Finalize_`: the `ace.setst` computes and retains the tag but produces no output and does not reach _Success_; the following Form C `ace.exec` reads it out and transitions. The `_Set_Aux_Value_` transition restated as a real Form B `ace.setst` instead of the `ace.exec` mnemonic |
| M8 | `ace-ISA-algorithms.adoc` | Maximum IV length stated once, as 1024 bytes (8192 bits), matching the other two statements |
| M10 | `ace-ISA-algorithms.adoc` | SHAKE128 and SHAKE256 specified: parameter table for all six functions (`c`, `b`, `t`, XOF flag, suffix `D`), `c` = 256 added; `t` = `c`/2 for the fixed-output functions and `t` = `b` for the XOFs; the suffix and padding string `S` = `D` followed by `pad10*1` defined, with the resulting `0x06`/`0x1F` first octet and the `b-1` final bit; XOF behaviour (no _Success_, unbounded squeezing) stated. "Granularity: 32 bits" clarified as the minimum vector element width, not a constraint on message length |
| M11 (HMAC) | `ace-ISA-algorithms.adoc` | `ipad`/`opad` defined as `0x36`/`0x5c` repeated `b`/8 times; the key is `K0` of FIPS 198-1 with its derivation assigned to the provisioner of the CC; `d` corrected in the inner-digest slice and defined as the digest size; re-initialisation of `state` to the hash IV before the outer compression added; `process_VLI` called with length `b` |
| M11 (KMAC) | `ace-ISA-algorithms.adoc`, `ace.bib` | New `ACE-KMAC` section specifying KMAC128/KMAC256 against SP 800-185: the CC holds the two prefabricated rate blocks `cshake_block` and `key_block`, keeping every variable-length encoding out of the ACE unit; `L` set on the transition to _Hash_Finalize_; `right_encode(L)` absorbed; cSHAKE suffix `00` (first octet `0x04`) rather than SHAKE's `1111`; key/customization length bounds tabulated. SP 800-185 added to the bibliography |
| M12 | `ace-ISA-algorithms.adoc` | Ascon-AEAD128 state machine repaired: `_Dec_Tag_Finalize_` added to the States and to the decryption chain; ; `AD_empty` removed and the empty-AD behaviour stated instead; `tag_len` fixed at 128 per SP 800-232, the truncated-verification path removed; `_Hash_Verify_` corrected from Form D to Form B. Deferral WARNING removed |
| M13 | `ace-ISA-algorithms.adoc` | `_Encapsulate_` corrected to match FIPS 203; `ace.derive` description corrected and given its design rationale; `_ciphertext_Input_` added, driven by `process_VLI` so the load is resumable, with `len`/`input_base`/`block_base`/`cumul_len` declared in the Internal State and Serialized Context and `process_block`/`finalize` passed as `None`; `_sharedkey_Output_` removed and `_decapsk_Output_` commented out, with a NOTE giving the reason; the `_AlgorithmUse_` paragraph brought in line. WARNING removed |
| M14 | `ace-ISA-algorithms.adoc` | ML-DSA completed: `_privkey_Input_` and `_compute_pubKey_` states added, with `HasPrivKey`/`HasPubKey` in _StateExtension_ and a guard on every operation that uses a key; importing a private key erases the public key; residual ML-KEM text removed; hedged and deterministic signing both provided, selected by the Form of the `ace.setst` entering `_Sign_Generate_` and recorded in a `Deterministic` flag; _AuxInfo_ restated as an unenforceable declaration of intent, with the reason. WARNING removed |
| M15 (part 1) | `ace-ISA-algorithms.adoc`, `ace.bib` | EdDSA: `v` = 2, since a signature is the pair (`R`,`S`); `b` = 456 for ed448; citation corrected from RFC 7748 to RFC 8032 and FIPS 186-5, and RFC 8032 added to the bibliography. ECDSA hash truncation per FIPS 186-5 6.4 stated as the caller's responsibility. `_Sign_Generate_`/`_Sign_Verify_` removed from the transitions out of _Initial_, resolving the contradiction with their guards. Remaining EdDSA and SM2 scheme gaps marked with a WARNING |
| M16 | `ace-ISA-algorithms.adoc` | `_Initial_ -> _Encrypt_`/`_Decrypt_` and `_Encrypt_ <-> _Decrypt_` added, making the machine reachable from a freshly provisioned CC; the dead `_Set_Aux_Value_ -> ...` transitions removed. `_Set_Aux_Value_` recast as an *operation* rather than a state, since with auto-return it never becomes the value of the _State_ field |
| M17 | `ace-ISA-algorithms.adoc` | The single-key extra `update_mask` explained and attributed to Rogaway, with a warning not to merge the two branches. New `ACE-XTS-from-XEX` procedure showing how SP 800-38E is realized on the XEX CC as specified: the tweak is `bin(i,b)`, encryption needs no reordering, and decryption obtains mask index `m` before `m-1` with one `ace.clone` and one discarded block operation |
| M18 | `ace-ISA-priv.adoc`, `ace-ISA-unpriv.adoc` | `macecsk` activation clears the flags, so the unit no longer locks itself out permanently; the availability rule restated as "while any flag is set"; "all either or four" corrected. The claim that the CSK is exposed to M-mode replaced: the `macecsk` CSRs are write-only and read as zero for every mode, M-mode included, which is what the `MRW (RZ)` designation already said |
| M19 | `ace-ISA-priv.adoc` | The `vscrstatus` subsection now names `vscrstatus` and `vscrstatush` throughout, instead of describing `scrstatus` |
| M20 | `ace-ISA-unpriv.adoc` | `ace.setst` is usage-controlled *except* with `#immed7` = `ace_state_off`: `ace.clear` and `ace.reset` are not usage-controlled, with the context-switching reason given |
| M22 | `ace-ISA-priv.adoc` | WARNING blocks added to the `misa.L` and `mstatus`/`sstatus` ACES subsections recording that both allocations are provisional, that unified discovery may replace the `misa` bit, and that nothing depends on the particular `*status` offset |
| M24 | `ace-ISA-unpriv.adoc` | New `ACE-SCC-rationale` subsection: Locality Secrets as associated data argued via POLYVAL's AXU property and its cost advantage over a KDF; the default zero nonce justified by nonce misuse-resistance with the loss of semantic security stated as accepted; RFC 8452 key-usage bounds recorded; a WARNING against manufacture-fixed CSKs |
| M25 | `ace-ISA-algorithms.adoc` | CMAC's last-block guard now tests `block_base != 0`, and `block_base` added to the internal state and serialized context so the test is well defined |
| M21 | `ace-ISA-unpriv.adoc`, `ace-ISA-algorithms.adoc` | Every extension name now resolves to one the table defines: `Zklcmac`->`Zklcmacm`; the `Zklkn` dependency list to `Zklaes128p`/`Zklaes256p`/`Zklesha2h`; `Zklm`->`Zklmem` in the three snippet captions and in a commented-out line; `ace.store` moved from `Zklv`/`Zklio` to `Zklmem`, matching `ace.load`; "At least of" -> "At least one of"; the `Zklkn` row's `2+` span removed so its columns line up |
| M23 | `ace-ISA-unpriv.adoc` | New `ACE-SCC-authenticated-MDH` rule: `AD[0]` is the *initial* MDH in both directions — the `_ace_cfgst_Complete_` image software saves before `#ace_CR_export_start`, and the image carried in the SCC and passed to `#ace_CR_import_start` — with no in-flight change reflected, and Section 1 of the SCC carrying that same image |
| M15 (part 2) | `ace-ISA-algorithms.adoc` | New `ACE-EdDSA` subsection: the seed held in `Scalar` with `s`/`prefix` derived internally, `ctx`/`ctxlen`, `PreHash` and `msg_pass`, a `_Msg_Absorb_` state, and the two-pass signing / one-pass verification structure. Pure mode conditioned on `Zklesha2h`/`Zklesha3h`, pre-hash always available. `h` = 512 and `j` dropped for both curves. SM2's `Hash` documented as `e = SM3(Z_A ‖ M)` with `Z_A` computed by the caller. WARNING removed |
| m17 | `ace-notation.adoc` | `len_in_bits`/`len_in_bytes` corrected; `bit_length` and `%` eliminated as duplicate spellings; `foreach`, `mod`, `ceil`, `floor`, `min`, `max`, comparison/arithmetic operators and `local` defined; `←` and `<-` stated to be synonymous |

**Document reorganisation.** The front matter was split into three files, included in this
order between `ace-books.adoc` and Book 1, all as `[preface]` so the Book numbering is
unaffected:

* `ace-acronyms.adoc` — the acronym table only;
* `ace-notation.adoc` — `== Pseudocode Notation` (anchor `ACE-Notation`),
  split into operators/control constructs and functions;
* `ace-conventions.adoc` — `== Conventions` (anchor `ACE-conventions`).

The Conventions subsections were promoted from `[discrete]` to real headings so they
appear in the table of contents. Note that `ACE-notation` was already in use for
“Notation in the Algorithm Descriptions” in Book 2, hence the distinct
`ACE-Notation` anchor.

Cross-references to `<<ACE-Notation>>` were added at the head of Book 2, in
`ACE-notation`, at the `update_mask` / `Galoismul` / `Montmul` / `double` definitions, at
the Ascon endianness note, at the head of `ACE-export-import-algorithms`, and at the head
of Book 4 — 35 links in total across the four sub-anchors.

Summary of state:

* **Fully resolved:** C1-C20, m17. Every Critical finding is now closed.
* **Partly resolved:** m22, m24.
* **Also closed:** M1–M3, M5–M8, M10–M14, M16–M25; M15 mostly; and M4, as a
  by-product of restating `ace.mv` under the uniform encoding.

* **Retracted (not defects):** M9.
* **Untouched:** the whole Major list and the remaining minor items.

**C7 remains open** — the GCM example in Book 4 still starts its counter at 1. OCB3 is
now fully corrected and validated against RFC 7253 Appendix A; the remaining OCB items
are the m23 editorial set (`hash_P` for `checksum_P`, `MAX_BLOCKS` unassigned, the
tag-length range contradiction, and the internal/serialized width mismatches).

**C4, length block — closed as intentional, not by adding the block.** At the author's
direction the omission is now documented rather than repaired. The argument holds: the
MDH is the first associated-data block, so it is authenticated and available first, and
it determines every length in the computation — the low-word fields give the length of
Section 3, _ImpDataLen_ gives the length of Section 6, and _Locality_ gives the number of
Locality Secret blocks that follow. Two inputs producing the same POLYVAL block sequence
therefore agree on the AD/payload split, which is exactly what the length block exists to
guarantee. Padding does not arise either, since every section is a whole number of
128-bit blocks.

The residual cost is one of process, not security: the construction is a *variant* of
AES-GCM-SIV, so it cannot be validated against RFC 8452 Appendix C, and conformance will
have to be shown against vectors generated for the variant. That is recorded in the
specification.

**Still open from m17:** `bin(n,m)` and `binBE(n,m)` retain their original wording,
including the "or sign extended" clause, which is meaningless for the unsigned uses these
functions actually have, and two typos ("ar", "signiicant"). They are now pinned
precisely by <<ACE-Notation>>, so the entries are redundant rather than wrong.

Everything else in the Critical and Major lists below is unchanged.

---

## Overall assessment

The architectural concept is coherent and, in its high-level design, well argued:
the CC/CR/SCC model, the separation of management from usage operations, the Locality
tweak mechanism, the interruption/resumption model and the split of the document into
Books 1–4 are all sound and, in places, elegant. Books 1 and 3 are close to the shape
of a RISC-V specification.

**Book 2 (Algorithms) is not yet in a state where it can be submitted.** The
normative algorithm pseudocode contains errors that would produce output that does not
match the cited standards' test vectors, and in three cases (OCB3 final block,
Ascon-AEAD128 last block, the GCM example) errors with direct security consequences.
Most seriously, the document has **no normative statement of its bit/byte ordering
convention**, and the concatenation operator `@` on which every algorithm depends is
never defined. Without that, "alignment with the standards" cannot be established at
all — several of the findings below are only *probably* bugs precisely because the
convention is missing.

For a specification intended for safety- and life-critical deployment, my
recommendation is: fix C1 and C2 first (they are prerequisites for judging everything
else), then re-derive every algorithm in Book 2 against a reference implementation and
publish known-answer test vectors as part of the specification.

Things that check out and should not be disturbed: the Ascon IV constants
(`0x00001000808c0001`, `0x0000080100cc0002`, `0x0000080000cc0003`, `0x0000080000cc0004`)
match SP 800-232; all ML-KEM and ML-DSA key/ciphertext/signature sizes match FIPS 203/204,
and the derived serialized-context totals (3248/4720/6352 bytes) are arithmetically
correct; GCM's `J0` derivation for |IV| ≠ 96 is structurally correct against SP 800-38D;
OCB's `L*`/`L$`/`L[i]` ladder and empty-final-block tag path match RFC 7253; CMAC's
subkey generation and last-block selection match SP 800-38B.

---

# CRITICAL

### C1 — No normative bit/byte-ordering convention; `@` is never defined — **FIXED**
`ace-acronyms.adoc:74-100` (Pseudocode Notation), affects the whole of Book 2 and
`ace-ISA-unpriv.adoc:2828-2992`.

The notation list defines `bin`, `binBE`, `m[j:i]`, `zeros`, `ones`, `msb`, `lsb` — but
**not `@`**, which is used in essentially every formula in the document. Its meaning is
only inferable indirectly from the Ascon note at `ace-ISA-algorithms.adoc:1935`
("`x || y` … corresponds to our `y @ x`"), i.e. the left operand is the *more*
significant. Nor is there any statement of how a byte string in memory maps onto the
bit-indexed values `X[j:i]` used in the pseudocode.

This is not editorial. The document simultaneously asserts three mutually incompatible
conventions:

* `ace-ISA-algorithms.adoc:718,719,735,737` — GCM `J0`, `reset_ctr`, `start_ctr` are
  "Big-endian as in the AES-GCM spec";
* `ace-ISA-algorithms.adoc:1186` — OCB3 uses "little-endian bit numbering instead of
  big-endian";
* `ace-ISA-algorithms.adoc:320-325` — ECB processes blocks "from the least significant
  positions to the most significant";
* `ace-ISA-algorithms.adoc:2415` — ECC values "are in little-endian format".

Under one reading of `@` the GCM-SIV sealing code in Book 1 is correct; under the other
it is wrong. The same ambiguity makes it impossible to decide whether OCB's `double()`,
`Stretch`, and `Offset_0` are right (see C4). **Add a normative Conventions subsection
in Book 1** fixing (a) the byte→bit-index mapping, (b) `@`, (c) shift direction, and
(d) how each algorithm's standard octet strings map into it — and then re-verify every
formula against it.

### C2 — Finite-field operations `Galoismul`, `Montmul` and `update_mask` are undefined — **FIXED**
`ace-acronyms.adoc:80,86`; `ace-ISA-algorithms.adoc:489`, `764`, `1042`;
`ace-ISA-unpriv.adoc:2877`.

`Galoismul(a,b)` is defined as "multiplication in a finite field **implied by the
context**" and `Montmul` as "Montgomery multiplication in a ring **implied by the
context**". These are the load-bearing primitives of GHASH (SP 800-38D), POLYVAL
(RFC 8452 §3) and XEX/XTS (SP 800-38E), and each uses a *different* representation:

* GHASH: GF(2^128) with reduction polynomial x^128+x^7+x^2+x+1 and the bit-reflected
  ("reverse") bit order specified in SP 800-38D §6.3;
* POLYVAL: the same field, but with the "Montgomery-friendly" convention and the
  mapping to GHASH given in RFC 8452 §3 (`POLYVAL(H,X) = ByteReverse(GHASH(...))`);
* XTS: multiplication by the primitive element α with the little-endian byte
  convention of SP 800-38E / IEEE 1619.

`update_mask` is described only as "updates the mask by a Galois Field multiplication
in GF(2^b)" (`ace-ISA-algorithms.adoc:489`) — the multiplier is not named and the
representation is not given. As written, two conformant implementations of ACE XTS
will not interoperate, and neither will match SP 800-38E.

### C3 — `RFC8452_KeyDeriv` is syntactically invalid and does not match RFC 8452 — **FIXED**
`ace-ISA-unpriv.adoc:2844-2857`.

This function derives the keys that seal **every** SCC in the system.

```
    AESE256(key, nonce @ bin(4,32))[63:0] @ AESE256(key, (nonce @ bin(5,32))[63:0] @
    AESE256(key, nonce @ bin(2,32))[63:0] @ AESE256(key, (nonce @ bin(3,32))[63:0],
    AESE256(key, nonce @ bin(0,32))[63:0] @ AESE256(key, (nonce @ bin(1,32))[63:0]
```

* Parentheses are unbalanced on three of six lines; `[63:0]` binds inside the `AESE256`
  argument rather than to its result; the `struct` fields are not named and the
  separator between `enc_key` and `auth_key` is a comma in the middle of an expression.
  The function as printed cannot be evaluated.
* The counter ordering is wrong. RFC 8452 §4 builds
  `auth_key = AES(K,N‖0)[0:8] ‖ AES(K,N‖1)[0:8]` and
  `enc_key  = AES(K,N‖2)[0:8] ‖ … ‖ AES(K,N‖5)[0:8]`, lowest counter in the *lowest*
  byte positions. The listing produces 4,5,2,3 for `enc_key` and 0,1 in the wrong order
  for `auth_key` under either reading of `@`.
* `AESE` (not `AESE256`) is used at `2903` and `2906`/`2923` with a 256-bit `enc_key`.

Consequence: SCCs are not portable between implementations, and no implementation can
be validated against RFC 8452 test vectors.

### C4 — SCC sealing is called AES-GCM-SIV but omits RFC 8452's length block — **RESOLVED AS INTENTIONAL**

Closed by documenting the omission rather than adding the block; see the status section
above for the argument, which holds. The other defects listed in this finding (`AESE` vs
`AESE256`, the unassigned `tmp[127:96]`, the nonexistent Sections 3.a/3.b) were fixed
separately, as was the reference to the nonexistent "Sections 3.a and 3.b". The nonce
reuse across the two AEAD passes is now justified in the specification: GCM-SIV is nonce
misuse-resistant, so a repeated nonce costs only determinism, and taking `SIV` as the
second pass's associated data binds the two payloads so that an Implementation VDS cannot
be grafted from one SCC onto another. **C4 is fully closed.**

The original finding follows.
`ace-ISA-unpriv.adoc:2892-2937`.

`AES_GCM_SIV_Encrypt` computes `SIV ← POLYVAL(auth_key, AD @ P, len_AD + len_PC)`.
RFC 8452 §4 requires POLYVAL over
`pad(AD) ‖ pad(PT) ‖ LE64(bitlen(AD)) ‖ LE64(bitlen(PT))`. The length block is absent.

The resulting construction is not AES-GCM-SIV and inherits none of its proofs; the
AD/plaintext boundary is unauthenticated except indirectly through the MDH. Since the
AD here is a *variable-length* list (MDH plus 0–5 Locality Secrets, per
`ace-ISA-unpriv.adoc:2950-2953`), this is exactly the case the length block exists to
protect.

Also in the same listings:

* `AES_GCM_SIV_Decrypt` (`2926-2927`) assigns only `tmp[95:0]`; `tmp[127:96]` is never
  written before `tmp ← AESE(enc_key, 0 @ tmp[126:0])` reads it.
* `len_PC <- lengths of Sections 3.a and 3.b combined` (`2954`) refers to sections that
  do not exist — `ACE-SCC` (`2719-2740`) has a single Section 3.
* The second AEAD pass reuses the *same* key and the *same* nonce as the first
  (`2959`); it is saved only by the differing AD. This should be stated explicitly with
  an argument, or a domain separator introduced.

### C5 — OCB3 nonce processing does not match RFC 7253 and is internally inconsistent — **FIXED**
`ace-ISA-algorithms.adoc:1361-1377`.

```
 . N_ext <- N[N_len-1:0] @ 1 @ zeros(128-N_len) @ bin(tag_len,7)
 . bottom <- int(N_ext[127:120])
 . Ktop <- enc_blk(key, zeros(6) @ N_ext[121:0])
 . Stretch <- (Ktop[63:0] xor Ktop[71:8]) @ Ktop
 . offset <- Stretch[b+bottom:bottom]
```

Against RFC 7253 §4.2 (`Nonce = num2str(TAGLEN mod 128, 7) ‖ zeros(120-|N|) ‖ 1 ‖ N`):

* `N_ext` is declared `bits(b)` = 128 but the expression is
  `N_len + 1 + (128-N_len) + 7 = 136` bits. `zeros(128-N_len)` must be
  `zeros(120-N_len)`.
* `bin(tag_len,7)` cannot represent `tag_len = 128`; RFC 7253 requires `TAGLEN mod 128`.
* `bottom` is taken from **8** bits (`N_ext[127:120]`) where RFC 7253 uses the low **6**
  bits; the declaration two lines above says `bot : bits(6)` and uses a different
  identifier (`bot` vs `bottom`).
* `Ktop` must be `ENCIPHER(K, Nonce)` with the low six bits of `Nonce` *zeroed in
  place*. `zeros(6) @ N_ext[121:0]` shifts the whole nonce by six bits instead.
* `Stretch` is declared `bits(96)`; RFC 7253's Stretch is 192 bits, and the code
  produces 64+128 = 192.
* `Stretch[b+bottom:bottom]` selects `129` bits; `Offset_0` is 128 bits
  (`Stretch[b+bottom-1:bottom]` under a consistent convention).

Any of these alone makes the mode non-interoperable; together they make it
unimplementable as written.

### C6 — OCB3 final partial block XORs the wrong value into the checksum — **FIXED**
`ace-ISA-algorithms.adoc:1399-1411` (encryption) and `1450-1463` (decryption).

Encryption, `_Enc_Last_Block_`:
```
 . tmp[last_blk_len-1:0] <- enc_blk(key, offset)[last_blk_len-1:0]    // PAD
 . OUTPUT <- zeros(...) @ (INPUT[...] xor tmp[...])
 . tmp <- offset xor (zeros(127-last_blk_len) @ 1 @ tmp[last_blk_len-1:0])
```
The third step re-uses `tmp`, which at that point holds the **PAD**, where RFC 7253
requires `Checksum_* = Checksum_m xor (P_* ‖ 1 ‖ 0*)` — i.e. the **plaintext**
`INPUT[last_blk_len-1:0]`.

Decryption, `_Dec_Last_Block_`, has the mirror-image error: it uses
`INPUT[last_blk_len-1:0]` — the **ciphertext** — where the checksum must take the
recovered plaintext.

Consequence: the tag is computed over the wrong value on both paths; encryption and
decryption do not even agree with each other, so authentication fails for every message
with a partial final block, and the tag has no defined relationship to the standard.

### C7 — GCM example reuses the tag-mask counter block for the first ciphertext block — **FIXED**
`ace-pseudocode.adoc:156-194` (`ACE-pseudocode-GCM-encryption-alternate`).  — **FIXED**

```
counter ← 1
foreach(i from 0 to ceil(len_in_bytes(PT)/16)-1) {
   V5[32:0] ← counter
   ...
   ace.exec V2, K0, V5                   // create mask by encrypting the counter
```
and at the end
```
V5[31:0] ← zeros(31) @ 1                 // Prepare IV @ 1 for tag encryption
ace.exec V2, K0, V5
tag ← V3 xor V2
```

SP 800-38D sets `J0 = IV ‖ 0^31 ‖ 1` and starts the GCTR keystream at `inc32(J0)`,
i.e. counter **2**. This example starts at 1, so the keystream block for `CT[0]` is
identical to the tag mask `E_K(J0)`. An attacker who knows or guesses one 16-byte
plaintext block recovers the tag mask and can forge arbitrary messages; conversely the
tag leaks `P[0] xor CT[0]`. This is a total break of the example.

The example is labelled non-normative, but it is presented as the recommended way to
build GCM on an ECB CC and will be copied. `counter` must start at 2.

### C8 — Ascon-AEAD128 empty final block contradicts the specification's own `pad()` — **FIXED**
`ace-ISA-algorithms.adoc:1988` vs `2071-2073` and `2134-2135`.  — **FIXED**

`pad(x,r)` is defined as `0^j @ 1 @ x`, so for an empty block `pad(∅,128) = 0^127 @ 1`
— a single 1 in bit position 0, which under `@` semantics must be XORed into
`state[0]`. The state machine instead does

```
. If INPUT is zero, then:
.. state[1] <- state[1] xor (1 << 63))
```

i.e. it sets bit 127. One of the two is wrong; either way the absorbed padding does not
match SP 800-232 and every message whose plaintext length is a multiple of the rate
produces a wrong tag.

### C9 — Ascon-AEAD128 last-block decryption destroys part of the rate — **FIXED**
`ace-ISA-algorithms.adoc:2143-2156`.  — **FIXED**

```
. tmp <- pad(INPUT[last_blk_len-1:0])
. state[0] <- tmp[63:0]
. state[1] <- tmp[127:64]
```

SP 800-232 (and Ascon generally) requires that for a partial final ciphertext block,
only the first `|C|` bits of the rate be replaced by the ciphertext, the remaining rate
bits retaining their current value, with the padding bit XORed in. Overwriting the whole
128-bit rate with `pad(C)` zeroes the un-replaced portion of `S_r`, so the finalisation
runs on a state that the encryptor never produces. Decryption of any message with a
partial last block fails authentication. (The full-block path at `2120-2123` is correct.)

### C10 — Conflicting global state numbering: `_Success_`/`_Failure_` are 22/23 or 21/22 — **FIXED**
`ace-ISA-unpriv.adoc:418-419` vs `ace-ISA-algorithms.adoc:2558-2559`, `2748-2749`,
`2908-2909`.  — **FIXED**

Book 1 defines `ace_state_success = 22` and `ace_state_failure = 23`, with 1–23 being
the "valid" range and ≥24 the error states. Every asymmetric algorithm (ECC, ML-KEM,
ML-DSA) instead declares `_Success_ (21)` and `_Failure_ (22)`.

This is not cosmetic: the normative rules at `ace-ISA-unpriv.adoc:437-462` and every
error check in the sample code (`bltu t3, t2, handle_errors` with `t3 = 23`) depend on
the numbering. Under the Book-2 numbering, a `_Failure_` from ECDSA verification (22)
would be read as `_Success_` by Book-1-conformant software.

### C11 — `process_VLI` never advances `cumul_len`; the loop cannot terminate — **FIXED**
`ace-ISA-algorithms.adoc:655-677`.  — **FIXED**

```
. While (input_base < ACELEN) do
.. amount <- min(ACELEN - input_base, b - block_base, len - cumul_len).
   ...
.. input_base <- input_base + amount
.. block_base <- block_base + amount
.. If len != 0 and cumul_len == len then { finalize(); ... }
```

`cumul_len` is initialised to 0 on state entry and never incremented, so:

* the `cumul_len == len` termination/`finalize()` condition can never become true;
* when `len` is non-zero, `amount` is bounded by `len - 0 = len` — harmless — but when
  `len` **is** zero (explicitly allowed: "If not defined by the caller … `len` is zero
  for the purpose of defining this procedure", line 628), `amount = min(…, 0) = 0`, so
  `input_base` never advances and the loop does not terminate.

This is the shared absorption engine for GCM's IV processing, every hash and XOF, and
HMAC. Add `cumul_len <- cumul_len + amount` and special-case `len = 0`.

### C12 — `ace.store`, `ace.input`, `ace.output` are encoded on the STORE-FP major opcode — **FIXED**
`ace-ISA-unpriv.adoc:1139`, `2131`, `2193`.  — **FIXED**

All three wavedrom diagrams give `{ bits: 7, name: 0x27, attr: ['custom-1'] }`. Opcode
`0x27` is **STORE-FP** (`fsw`/`fsd`/`fsq`), not custom-1; custom-1 is `0x2b`. As encoded,
these three instructions alias standard floating-point stores.

Related, and needing an ARC decision before submission: a ratified standard extension
cannot occupy `custom-0`/`custom-1`/`custom-2` (`0x0b`, `0x2b`, `0x5b`) at all. The
"encodings are preliminary" warning at `1003-1006` acknowledges this, but the opcode
budget (three major opcodes) should be negotiated early because it constrains the whole
instruction set design.

### C13 — `ace.exec` Forms B and D constrain away the CR operand — **FIXED**
`ace-ISA-unpriv.adoc:1229-1251`.  — **FIXED**

The encoding table places the CR in `rs1` for all Forms
(`{ bits: 5, name: 'rs1', attr: ['Ks1|K{Xs1}'] }`). The Form constraints then read:

```
B. Form = 0b01 and rs1 = 0b00000.
D. Form = 0b11 and rs2 = rs1 = 0b00000.
```

Form B is `ace.exec Kn|K{Xn}, Vs2` — it *has* a CR source, in `rs1`. Requiring
`rs1 = 0` makes Forms B and D unable to name a CR; the unused field in Form B is `rd`,
and in Form D it is `rd` and `rs2`. Form C's constraint (`rs2 = 0`) is correct.

This propagates: `ace.mv` (`1305-1315`) reuses `rs1` as a sub-opcode within Form
`0b01`, which is only consistent if Form B leaves `rs1` free — i.e. with the *incorrect*
constraint. The two sections cannot both be right.

### C14 — Normative conformance lists require instructions that do not exist — **FIXED**
`ace-ISA-unpriv.adoc:130-132`, `462`, `820`, `932`; `ace-ISA-priv.adoc:56-59`.

The `Zklv` and `Zklio` conformance footnotes require an implementation to support
`ace.prov`, `ace.export` and `ace.import`. The permitted-instruction rule for
`_Success_`/`_Failure_` states (line 462) lists the same three. The exception table in
Book 3 attributes load/store faults to them. **None of these instructions is defined
anywhere in the document** — they were superseded by `ace.mgmt` plus
`ace.load`/`ace.store`, but the replacement was not propagated.

The same lag appears inside the SCC chapter itself, which specifies export/import in
terms of `ace.setst Kd|K{Xd}, #ace_CR_export_start` / `#ace_CR_import_end`
(`ace-ISA-unpriv.adoc:2943`, `2969`) although those immediates belong to `ace.mgmt`
(`1515-1527`). An implementer cannot determine which instruction performs the
authenticated decryption of an SCC.

---

### C15 — GCM `J0` for a 96-bit IV was built in the wrong octet order — **FIXED**

Found while writing the Conventions section. See the status section above.

### C16 — the GCM and GCM-SIV counter increments performed no modular reduction — **FIXED**

Found while fixing m17, when defining `mod` made the precedence explicit. See above.

### C17 — the OCB3 partial-block padding was oriented wrongly, at three sites — **FIXED**

Found while fixing C6; it also affected the associated-data last block. See above.

### C18 — OCB3 full-block decryption used the forward cipher — **FIXED**

`enc_blk` where RFC 7253 requires DECIPHER; `dec_blk` was declared and never used. See above.

### C19 — the GCM and GCM-SIV length blocks were assembled in the wrong order — **FIXED**

Confirmed by test: the swapped variant fails the GCM vectors. See above.

### C20 — the GCM counter was taken from the wrong end of the counter block — **FIXED**

`J0[31:0]` is the first four octets of the IV; the counter is `J0[127:96]`. See above.

_These six were found during remediation rather than in the original review; each is
described in full in the status section at the top, together with how it was verified._


# MAJOR

### M1 — `_UsagePolicy_` is 5 bits but 6 are specified, and one has inverted polarity — **FIXED**
`ace-ISA-unpriv.adoc:314`.

Resolved by assigning M-mode to bit 3 and Debug to bit 4, so that all five bits of the
field are used and none lies outside it. Bit 4 keeps its *grant* polarity, which is the
author's intent; the escalation path it opened through `ace.restrict` is closed instead
at `ace.restrict` itself, where a one in the input bit is now defined to **clear** bit 4
rather than set it. A one in any `_UsagePolicy_` input bit therefore removes a permission
in every case, preserving the invariant that `ace.restrict` can only restrict. VU-mode is
still not distinguished from U-mode.

The original finding follows.

> `[68:64] | 5 | _UsagePolicy_ | Bits 0, 1, 2, and 4 … disallow CC usage in U-mode,
> (V)S-mode, HS-mode, and M-Mode, respectively. Bit 5 allows use in Debug only if set.`

Bit 5 does not exist in a 5-bit field; bit 3 is never assigned; VU-mode is not
distinguished from U-mode. Worse, the Debug bit is **enable**-polarity while the others
are **disable**-polarity, which breaks the monotonicity that `ace.restrict` relies on:
`ace-ISA-unpriv.adoc:1818-1820` says a 1 in `Xs._UsagePolicy_` sets the corresponding
bit, and that setting bits only ever restricts. Setting bit 5 would *grant* Debug-mode
use of a CC — a privilege escalation reachable from unprivileged code.

### M2 — Four mutually inconsistent statements of which MDH fields determine PI/SCC size — **FIXED**

Resolved by separating the three lengths, which the old text conflated, into one
authoritative subsection (`ACE-length-rule`, placed at the head of
<<ACE-external-formats>>) and subordinating every other statement to it. The
substantive decisions taken:

* the PI length does not depend on _ImpDataLen_ — a PI carries no implementation data,
  so the field must be zero in a PI, as must _SCProtection_ and _StateExtension_;
* the SCC length does not depend on _SCProtection_, which resolves the flat contradiction
  with the single-share threshold rule at <<ACE-rules-threshold-implementations>> in
  favour of that rule;
* CRF capacity is independent of _KeyType_ and _StateExtension_, which is what makes the
  "no other field" clause in the `ace.mgmt` allocation step true as written rather than
  contradictory.

The original finding follows.
* `ace-ISA-unpriv.adoc:1102` (`ace.load`), `1176` (`ace.store`): *Algorithm,
  AlgorithmPolicy, KeyType*.
* `ace-ISA-unpriv.adoc:2703` (PI table): *Algorithm, AlgorithmPolicy, KeyType*.
* `ace-ISA-unpriv.adoc:2729` (SCC table): *Algorithm, AlgorithmPolicy, KeyType,
  **StateExtension***.
* `ace-ISA-unpriv.adoc:375` (`_SCProtection_`) and `597` (`_StateExtension_`) and `392`
  (`_KeyType_`): each "may affect the size of an SCC".

None of the lists mentions `_ImpDataLen_`, although `2746` says it specifies the size of
the variable-length section, and `1545` requires CRF capacity to be allocated from
*Algorithm, AlgorithmPolicy and SCProtection* with "No other field must affect the
amount of capacity required" — contradicting `_KeyType_` and `_StateExtension_` above.

Additionally `ace-ISA-unpriv.adoc:2753-2758` states flatly that "The PI and SCC Formats
will be the same for non-threshold and threshold implementation variants … with the only
difference being the value of the _SCProtection_", directly contradicting line 375.

This must be reduced to one authoritative rule; `ace.size`, `ace.load`, `ace.store` and
all lazy-loading logic depend on it.

### M3 — `ace.size` Form A is defined only for SCCs, but is used for PIs — **FIXED**
`ace-ISA-unpriv.adoc:2074-2078` vs `2478` and `2529`.

Form A "returns the total size in bytes of the memory buffer that would be necessary to
store the exported SCC". The normative provisioning sequence
(`ace-ISA-management-code-snippets`) calls `ace.size a2, K{t0}` immediately after
`ace_CR_provision_start` to obtain the length of the **PI**. Form A needs a defined
behaviour when `_ConfigStatus_` is `_ace_cfgst_Provisioning_` / `_ace_cfgst_Importing_`.

### M4 — `ace.mv`: the Description contradicts the Encoding (directions swapped) — **FIXED**
`ace-ISA-unpriv.adoc:1305-1315` vs `1322-1346`.

Encoding: Form `0b01`/`rs1=0b00001` = `ace.mv Kd, Xs2` (GPR → CR);
Form `0b10`/`rs2=0b00001` = `ace.mv Xd, Ks1` (CR → GPR).

Description: "If `Form` = `0b10` and `rs2` = `0b00001`: the contents of `X[s1]` are
moved **to the CR**" and "If `Form` = `0b01` and `rs1` = `0b00001`: `XLEN/8` bytes at
offset `acestart` are moved **to `X[s2]`**" — both directions inverted relative to the
encoding, and both using `s1`/`s2` inconsistently with the field they name. The
`_ConfigStatus_` guards are attached to the wrong directions as a result (a CR→GPR move
is required to be in `_ace_cfgst_Provisioning_`).

### M5 — `ace.restrict`: encoding text is wrong, and the NOTE claims a capability the normative text forbids — **FIXED**

Resolved in favour of the NOTE rather than the normative list: `ace.restrict` *can* raise
`_SCProtection_`. The capability is worth having, and the failure mode it needed turned
out to be well defined — insufficient CRF capacity yields `ace_state_out_of_mem`, exactly
as the provisioning path does. Failure destroys the CC, which is the intended fail-closed
behaviour and is now stated as such.
`ace-ISA-unpriv.adoc:1738-1743`, `1773-1796`, `1860-1876`.

* "If bit `v` (bit 29) is 0, the input is taken from a GPR …, and the instruction is
  `ace.restrictv`" — with `v` = 0 the instruction is `ace.restrictl`/`ace.restricth`.
* The normative field list (`1796`) permits changes only to *AlgorithmPolicy, Locality,
  UsagePolicy, ExpirationDate, AlgorithmUse*; `_SCProtection_` is excluded and `1797`
  requires all other fields be 0. The NOTE at `1864-1865` nonetheless advertises
  "Enabling side-channel protection when supported by the microarchitecture, even if the
  original CC was not configured with it" as a use case. One of the two must change —
  and note that raising `_SCProtection_` may change the SCC size (M2), which
  `ace.restrict` is not equipped to handle.
* `ace.restrictl` is said to modify `_AlgorithmPolicy_` "in bits [63:0]" while the field
  list mixes low- and high-word fields.

### M6 — GCM: three names for the tag-mask counter, two for the hash key — **FIXED**
`ace-ISA-algorithms.adoc:719`, `720`, `737`, `755`, `810`, `821`, `848`.

The internal state declares `reset_ctr` (719) and `auth_key` (720); the serialized
context declares `start_ctr` (737); the behaviour writes `start_ctr` (810), then
`reset_at <- lsb_c(J0)` (821), then reads `start_ctr` for both the wrap check (829) and
the tag mask (848). Likewise the state declares `auth_key` but every formula uses
`hash_key` (764, 793, 802, 806-809, 895).

An implementer cannot tell whether the tag mask uses the value captured at IV
finalisation or the one captured on entry to `_Encrypt_`; when the CC is reused for a
second message these differ.

Also at 848/884: `J0[127,32]` should be `J0[127:32]`.

### M7 — GCM: contradictory specification of `_Enc_Tag_Finalize_` — **FIXED**
`ace-ISA-algorithms.adoc:839-857`.

The transition description says the `ace.setst` that enters `_Enc_Tag_Finalize_` absorbs
the lengths, computes the tag, and "Finally, `tag` is returned in `OUTPUT`, and the state
is changed to _Success_". The very next bullet says that *in* `_Enc_Tag_Finalize_`, a
Form C `ace.exec` "writes the `tag` to `OUTPUT`, and the state transitions to
_Success_". Both cannot hold — and `ace.setst` has no `OUTPUT` operand in any Form.
The Book 4 example (`ace-pseudocode.adoc:131-132`) follows the second reading.

The transition is also described as "Form C `ace.setst`" while the mnemonic quoted at
line 797 is "``ace.exec Kn|K{Xn}, INPUT``".

### M8 — GCM: three different maximum IV lengths — **FIXED**
`ace-ISA-algorithms.adoc:746` ("Maximum supported size is 1024 bits (8192 bytes)" —
internally inconsistent: 1024 bits is 128 bytes), `798` ("at most 8192 bits"), `801`
(`process_VLI(8192, …)`). The `len` field is 16 bits (746). SP 800-38D permits IVs up to
2^64−1 bits; restricting is fine but the limit must be stated once.

### M9 — Generic hash and SHA-3 state machines disagree — **NOT A DEFECT, RETRACTED**

Withdrawn at the author's correction. The generic construction of <<ACE-hash-functions>>
is a template, not a state machine every hash must reproduce: `_Hash_Absorb_Last_Block_`
is optional and present only in algorithms that need a distinct final-block treatment.
SHA-3 legitimately omits it and uses `_Hash_Finalize_` instead, which is an architected
state of <<ACE-state-constants-symmetric>>. The specification now says so explicitly
("(optionally)" in the state list, `{ … }` around the state in the transition chain).

I recorded this as a contradiction because I read the generic section as normative for
every instantiating algorithm. It is not, and no change was needed.

The original finding follows, retained only for the record.
`ace-ISA-algorithms.adoc:1693-1702` vs `1901-1905`.

The generic construction uses `_Initial_ → _Hash_Absorb_ → _Hash_Absorb_Last_Block_ →
_Hash_Output_ → _Success_`; SHA-3, declared to be "instantiations of the algorithm
specified in <<ACE-hash-functions>>", uses `_Initial_ → _Hash_Absorb_ → _Hash_Finalize_
→ _Hash_Output_ → _Success_`. `_Hash_Finalize_` (state 4) and
`_Hash_Absorb_Last_Block_` (state 3) are distinct states in
`ACE-state-constants-symmetric`. The SHA-3 behaviour then describes the padding as
happening "Upon transitioning to State _Hash_Output_" — from a state the transition list
does not mention.

### M10 — SHA-3: SHAKE128 is not covered, and the padding/domain-separation string is never defined — **FIXED**

All six functions now have parameters, and the domain-separation suffix and padding are
defined. Verified with `src/shake-kat.py`, which drives a Keccak-f[1600] sponge purely
from the values in the new table and reproduces the FIPS 202 empty-message digests for all
six.

The granularity sub-item was my misreading, corrected by the author: "Granularity: 32
bits" is the minimum element width of the *vector inputs*, not a constraint on message
length, and the exact bit length absorbed is given by `last_block_len`. The specification
now says so, since the bare word "granularity" invited the same misreading.

The state-mapping sub-item is discharged by reference: absorption is bit `j` of the input
to bit `block_base + j` of the rate, per cite:[nist-fips-202] B.1 together with the
conventions section, which is now stated explicitly in the padding paragraph.

The original finding follows.
`ace-ISA-algorithms.adoc:1845`, `1853`, `1911-1920`.

* `b = 1600 − c` with "`c` = 448, 512, 768, or 1024". SHAKE128 has capacity 256, which
  is absent from the list, so `Zklesha3h`'s SHAKE128 (algorithm Type 5, Mode 4) has no
  parameters.
* "The suffix and padding string `S` is generated" — `S` is never defined. FIPS 202
  requires `01‖pad10*1` for SHA3-n and `1111‖pad10*1` for SHAKE. Without this the
  digests are simply undefined.
* The mapping of the absorbed bit string into the 1600-bit Keccak state (FIPS 202 §3.1
  lane/bit indexing, little-endian lanes) is not given, and "Granularity: 32 bits"
  suggests a word-oriented view that FIPS 202 does not define. See C1.

### M11 — KMAC has no specification at all; HMAC's is incomplete — **FIXED**

The HMAC half is closed. `ipad` and `opad` are defined, the key is stated to be `K0` of
cite:[nist-fips-198-1] {sect}3 with its derivation assigned to the entity provisioning the
CC (which keeps the length branch out of the ACE unit), the inner digest slice now uses
`d` rather than `b`, and the outer compression re-initialises `state` to the hash IV.
Verified with `src/hmac-kat.py` against RFC 4231: the construction as specified matches
all three vectors, and the same code without the re-initialisation step fails all three,
so that step is load-bearing and not merely tidy.

The sub-item about the PI declaring a `b`-bit key while `_Set_Key_` uses `process_VLI` was
my misreading, corrected by the author: `process_VLI`'s "variable length" refers to its
parameters, and calling it with length `b` absorbs exactly `b` bits. The call now passes
`b` explicitly rather than an undefined `max_length`.

**KMAC is now specified**, in a new `ACE-KMAC` section. Verified with `src/kmac-kat.py`,
which implements KMAC both straight from SP 800-185 and as the ACE section describes it:
the two agree, and both reproduce the four SP 800-185 sample vectors.

The original finding follows.
`ace-ISA-unpriv.adoc:109-110`; `ace-ISA-algorithms.adoc:76-77`, `1768-1836`.

`Zklkmacm` (KMAC128/KMAC256) and `Zklhmacm` are listed as extensions with "Defined in:
**TBD**", and KMAC128/KMAC256 appear as Type 5 Modes 10–11 in the algorithm encoding
table, but there is no KMAC section anywhere. SP 800-185's `bytepad`/`encode_string`/
right-encoded output length are entirely absent.

For HMAC (`1768-1836`):

* The PI declares the key as exactly `b` bits (the hash *input block* size,
  "possibly pre-hashed by provider"), but the state machine introduces a `_Set_Key_`
  state that absorbs a variable-length key via `process_VLI`. These are two different
  key-input models and only one can be right.
* `ipad`/`opad` are used but never defined (FIPS 198-1: 0x36 and 0x5c repeated).
* FIPS 198-1's `K0` derivation for keys longer or shorter than the block size is not
  specified — it is pushed onto "the provider" without a normative statement.
* "Assume its value is in `state[b+state_offset-1, state_offset]`" — the inner digest is
  `d` bits, not `b`; `d` is declared at line 1777 and then never used.
* Re-initialisation of `state` to the hash IV before the outer compression is not
  specified.

### M12 — Ascon-AEAD128: state machine inconsistencies and a non-standard tag length — **FIXED**

All five items closed. `_Dec_Tag_Finalize_` now appears in the States list and in the
decryption chain, which it was driving without being declared; the chain ends in
_Success_ or _Failure_; `_Hash_Verify_` is a Form B, matching the `INPUT` it consumes.

`AD_empty` is removed rather than given a use: it recorded a distinction the caller
already makes, since the caller pads a non-empty associated data field and issues no
`ace.exec` at all for an empty one. The empty-AD behaviour — no permutation, not even a
padding block — is now stated directly.

`tag_len` is fixed at 128, as cite:[nist-SP-800-232] specifies, and the settable
32-to-128 range on the decryption path is gone. That range both broke interoperability
with the encryption path, which always emits 128 bits, and reduced forgery resistance by
the number of bits dropped. The field is retained in the Internal State and Serialized
Context at the value 128, so a future variant would not change the format.
`ace-ISA-algorithms.adoc:1992-2012`, `2130-2160`, `1963-1965`, `2024`.

* The declared states and transitions name `_Hash_Verify_`; the behaviour transitions to
  `_Dec_Tag_Finalize_` (2136, 2141, 2155), which is not in the state list.
* `AD_empty` is declared in the internal state (1965) and set (2024, 2042) but never
  read. Ascon's handling of an absent AD (no `p^8` invocation at all) is therefore
  unspecified.
* `tag_len` is settable to any value in [32,128] on the decryption path (2160), while the
  encryption path fixes it at 128 (2023) and `_Hash_Output_` always emits the full
  128-bit tag (2107). SP 800-232 specifies a 128-bit tag; permitting 32-bit tag
  *verification* with no matching generation path is both an interoperability break and a
  meaningful reduction in forgery resistance. If truncated tags are wanted, specify them
  symmetrically and state the security bound.
* `_Hash_Verify_` is said to expect "Form D" `ace.exec` (2162) while supplying `INPUT`
  — Form D has no input; this is Form B.

### M13 — ML-KEM: decapsulation cannot be given a ciphertext; Encaps is misdescribed — **FIXED**

The `_Encapsulate_` half is fixed: it now applies `ML-KEM.Encaps` to `encapsk` and derives
both outputs from one internally drawn value, rather than generating a shared key and then
a ciphertext for it.

The design rationale the author supplied — ML-KEM produces key material for a symmetric
algorithm, and `ace.derive` moves it straight into a second CR as a CC, so the shared
secret never reaches process memory — is now recorded in the specification. It also
corrected a second error: the existing text had `ace.derive` deriving the shared key "from
a ciphertext and the decapsulation key", which is not what it does and could not work, a
ciphertext being 768 to 1568 octets and the auxiliary operand a single GPR.

`_ciphertext_Input_` has since been added, taking the state number freed by
`_decapsk_Output_`. Because the field is 768 to 1568 octets and one `ace.exec` carries at
most `ACELEN` bits, the three `_*_Input_` states are now specified in terms of
`process_VLI`, which gives them resumable partial-progress accounting.

My first attempt at that was incomplete, as the author pointed out: it invoked
`process_VLI` with variables — `len`, `input_base`, `block_base`, `cumul_len` — that ML-KEM
declared nowhere, and with `process_block()`/`finalize()` described as doing nothing rather
than being absent. All four are now declared in the Internal State and in the Serialized
Context, 16 bits each plus 64 bits of padding so the section stays a multiple of 128 bits
(sizes become 3264/4736/6368 bytes, verified). `process_VLI` itself now accepts `None` for
`process_block` and `finalize` and skips the corresponding calls, at all three sites where
they are invoked. The call also had `b` = `ACELEN` and `state` = `block`, which would have
selected the procedure's *XOR* branch; it is now `b` = `len` with `state` distinct, so the
copy branch applies and the octets land in the field.

`_sharedkey_Output_` is removed and `_decapsk_Output_` commented out, with a NOTE
recording why: the shared key reaches its consumer through `ace.derive` and so never
becomes visible to software, and a decapsulation key leaves a CR only as an SCC. The
`_AlgorithmUse_` paragraph, which still named the removed states, was brought in line.
`ace-ISA-algorithms.adoc:2754-2759`, `2783-2788`.

The state list defines `_encapsk_Input_`, `_decapsk_Input_`, and four `*_Output_` states
including `_ciphertext_Output_` — but there is **no `_ciphertext_Input_`**. A responder
performing `ML-KEM.Decaps` has no architectural way to load the received ciphertext into
the CC.

The description of `_Encapsulate_` — "a shared key is randomly generated … and stored in
`sharedkey`. The corresponding ciphertext is generated using `ML-KEM.Encaps`" — inverts
FIPS 203: `ML-KEM.Encaps(ek)` samples randomness `m` and *derives* both `K` and `c` from
it; there is no step that generates a shared key and then finds a ciphertext for it. The
encapsulation key input is not mentioned either.

### M14 — ML-DSA: private keys cannot be loaded; extensive copy-paste from ML-KEM — **FIXED**

All four items closed.

*Key management.* `_privkey_Input_` (12) and `_compute_pubKey_` (13) added, both loading
through `process_VLI` as the ML-KEM input states do. `HasPrivKey` and `HasPubKey` live in
_StateExtension_ bits 0 and 1, following the ECC precedent, so they are readable with
`ace.getmdl`. Importing a private key erases the public key and clears its flag, since the
two would otherwise be an unrelated pair and the CC would verify under one key while
signing under another; importing a public key deliberately leaves the private one alone,
that being the ordinary verification-only configuration. `_Sign_Generate_` and
`_compute_pubKey_` require `HasPrivKey`, `_Sign_Verify_` and `_pubkey_Output_` require
`HasPubKey`.

*Signing mode.* Both modes of cite:[nist-fips-204] {sect}3.4 are now available. The Form of
the `ace.setst` that enters `_Sign_Generate_` selects them — Form A or Form B with `Xs` = 0
for hedged, Form B with `Xs` = 1 for deterministic — and the choice is recorded in a
`Deterministic` flag in _StateExtension_ bit 2 so that an interrupted or exported signing
operation completes in the mode it began in. Hedged is the default, and a failure of the
random bit generator produces no signature.

*_AuxInfo_.* Restated as what it can actually be: a declaration of intent that travels with
the CC, not an enforced binding. Since the caller supplies _tr_ and _μ_, the unit never
sees the message and never evaluates a hash, so it can neither check the binding nor need
to support the named function. The requirement that the implementation support it is
dropped accordingly.

*Copy-paste.* The residual ML-KEM passages are gone. Correcting them exposed a trap worth
recording: the ML-KEM and ML-DSA state lists open with two identical lines, so a
replacement keyed on them silently retitled the wrong section. Both are now labelled by
the state each list actually contains.
`ace-ISA-algorithms.adoc:2819`, `2905-2921`, `2935`, `2944-2958`.

* The PI contains only the MDH, and the state list has `_pubkey_Input_` but no
  `_privkey_Input_`. A key pair generated elsewhere (e.g. by a provisioning service) can
  never be imported into an ML-DSA CC.
* Residual ML-KEM text: "The principal procedures offered by the **ML-KEM**" (2819);
  "**ML-KEM** algorithms define" in the ML-DSA state list (2910); `_decapsk_Input_`
  listed among ML-DSA states (2935, 2948, 2950); "`_pubkey_Output_` and `_Sign_Output_`
  … store values of `encapsk`, `decapsk`, `ciphertext`, resp., `sharedkey`" (2955);
  `_GenerateKeyPair_` "will replace the `encapsk` and `decapsk` values" (2944).
* Deterministic vs hedged signing (FIPS 204 §3.4, the `rnd` input) is not specified.
* `_AuxInfo_` is declared to bind the hash function (2857-2859), but since the caller
  supplies both μ and *tr* (2826-2829), the ACE unit has no way to enforce it. Either
  drop the field for ML-DSA or state that it is advisory.
* The trailing "*Anything else?*" at 2971 indicates the section is unfinished.

### M15 — ECC: EdDSA signature field is half the required size; wrong citation; scheme details missing — **FIXED**
`ace-ISA-algorithms.adoc:2426`, `2434-2436`, `2505`, `2529`.

* `v` is "the number of elements used to represent a signature"; ed25519/ed448 are given
  `v = 1`, so the `Signature` field is `vb` = `b` bits. An Ed25519 signature is
  `R‖S` = 512 bits (`v = 2`); ed448 is 912 bits. As specified, EdDSA signatures do not
  fit.
* Ed25519/Ed448 are cited to RFC 7748, which specifies X25519/X448 (Montgomery ladder key
  agreement), not signatures. The correct references are RFC 8032 and FIPS 186-5.
* EdDSA's key expansion (seed → clamped scalar plus prefix) and its *deterministic*
  nonce `r = H(prefix‖M)` are incompatible with the `Scalar` / `RndNum` model as
  described; nothing says how a CC configured for ed25519 derives them.
* SM2 signature requires `Z_A = H(ENTL‖ID‖a‖b‖x_G‖y_G‖x_A‖y_A)`; not modelled.
* ECDSA hash truncation to the leftmost `min(N, outlen)` bits (FIPS 186-5 §6.4) is not
  stated; `h = 576` for P-521 does not correspond to any approved hash.
* Contradictory transitions: `_Initial_ -> … _Sign_Generate_` is permitted (2576) while
  the next bullet permits `_Sign_Generate_` "only if `HasSecondPt`, and `HasHash`"
  (2580). Also, ECDSA signing does not require the public key.

### M16 — Generic Tweakable Block Cipher state machine is a dead end — **FIXED**

Resolved in two rounds. The author first added `_Encrypt_ -> _Set_Aux_Value_` and
`_Decrypt_ -> _Set_Aux_Value_` with auto-return, which fixed re-tweaking but left the
machine unreachable: the only transition out of _Initial_ still led back to _Initial_, and
the `_Set_Aux_Value_ -> _Encrypt_`/`_Decrypt_` transitions were dead, because with
auto-return `_Set_Aux_Value_` is never a resting state from which an instruction can be
issued. Under `ACE-generic-rules` an unlisted transition raises an illegal instruction
exception *and invalidates the CR*, so `ace.setst #ace_state_encrypt` from _Initial_ would
have destroyed the CC.

The transitions are now `_Initial_ -> _Encrypt_`/`_Decrypt_`, `_Encrypt_ <-> _Decrypt_`,
and each of the three to itself by the set-tweak operation. Re-traced: _Encrypt_ and
_Decrypt_ are both reachable from a freshly provisioned CC, set-tweak is available in
every operational state, and no transition has an unreachable source.

`_Set_Aux_Value_` is also recast as an *operation* rather than a state. With auto-return
it never becomes the value of the _State_ field, so listing it under **States** would have
led implementers to reserve a `_State_` encoding that can never be observed through
`ace.getst`. This differs from GCM, where `_Set_Aux_Value_` is a genuine resting state in
which `ace.exec` absorbs the IV.

The original finding follows.
`ace-ISA-algorithms.adoc:587-599`.

Allowed transitions are `_Initial_ → _Set_Aux_Value_`, `_Set_Aux_Value_ → _Encrypt_`,
`_Set_Aux_Value_ → _Decrypt_`. The behaviour then says a Form C `ace.setst` sets the
tweak and "**Instead of transitioning to State `_Set_Aux_Value_`, the State remains
unchanged**". `_Set_Aux_Value_` is therefore never entered, and since there is no
`_Initial_ → _Encrypt_`/`_Decrypt_` transition, the CC can never reach an operational
state. Also `t` = tweak size is written `(8|`k`)` (line 548).

### M17 — XEX/XTS: mask derivation asymmetry unexplained; XTS not actually specified — **FIXED**

Both halves closed without adding architecture. The asymmetry is now explained: with one
key the raw `enc_blk(key1, T)` is simultaneously a mask and a value the same key can be
asked to encrypt, which cite:[DBLP-conf-asiacrypt-Rogaway04] shows to be attackable, so
the construction starts from `α · enc_blk(key1, T)`; with two keys the data path never
evaluates `key2` and no multiplication is needed. The text warns against merging the
branches.

XTS is now realizable from the XEX CC as specified, via `ACE-XTS-from-XEX`. The one real
difficulty is that decryption consumes mask index `m` before `m-1` while a mask only ever
advances; it is resolved with a single `ace.clone` plus one discarded block operation per
data unit, independent of data unit length. Verified with `src/xts-kat.py` against an
implementation written straight from IEEE 1619, over eleven data unit lengths spanning
the partial-block cases and three tweak values: encryption and decryption both agree, and
the round trip is exact.

The original finding follows.
`ace-ISA-algorithms.adoc:504-512`, `434-443`.

For two keys the mask is `enc_blk(key2, tweak)`; for one key it is
`update_mask(enc_blk(key1, tweak))` — one extra α-multiplication. This matches Rogaway's
XEX (where `Δ = α·E_K(N)` is needed precisely because a single key is used) but the
document neither says so nor cites the reason, so an implementer is likely to "fix" it.

More importantly, `Zklxexm` is named "XEX construction" but the extension table and the
prose both invoke SP 800-38E (XTS). XTS additionally requires (a) the tweak to be the
128-bit **little-endian** representation of the data unit sequence number and (b)
ciphertext stealing. Both are deferred to software with a single sentence
(`ace-pseudocode.adoc:87`) and no normative text. As specified, `Zklxexm` cannot be
claimed to implement SP 800-38E.

### M18 — `macecsk` activation logic locks the ACE unit out permanently — **FIXED**
`ace-ISA-priv.adoc:305-319`.

```
* Once all flags have been set, the values written by M-mode firmware are activated …
* Any mode change to M-mode will reset the flags.
* If any of the flags are set, the ACE unit is not available and any attempt to execute
  any ACE instruction will raise an illegal instruction exception.
```

The flags are never cleared on activation, so after a successful CSK programming *all*
flags are set and the last rule makes the unit permanently unavailable. The intended
rule is presumably "if some but not all flags are set". Separately, "Any mode change to
M-mode will reset the flags" means any trap taken between the first and last CSR write
silently discards a partially written CSK — with no way for firmware to detect it, since
"Reading the register will still return the old value". Line 311 also reads "if all
either or four CSRs have been written" (garbled).

There is also a contradiction with `ace-ISA-unpriv.adoc:970` ("clear values of the CSK
must never be exposed to software, except to M-mode … in the second model") versus the
`MRW (RZ)` (read-as-zero) designation at `ace-ISA-priv.adoc:91`.

### M19 — Book 3 `vscrstatus` section describes the wrong register throughout — **FIXED**
`ace-ISA-priv.adoc:227-248`.

"The 64-bit register **`scrstatus`** tracks … for virtualized contexts";
"`vscrstatus`(i) = **`scrstatus`**[2i+1:2i]"; "32-bit CSRs **`scrstatush`** shadows bits
[63:32] of **`scrstatus`**". This is normative text for a distinct architectural
register; every occurrence needs the `vs` prefix.

### M20 — `ace.clear` is both usage-controlled and not — **FIXED**
`ace-ISA-unpriv.adoc:1443` vs `2250-2262`.

`ace.setst` is declared "usage-controlled". `ace.clear`/`ace.reset` are defined as
*encodings of* `ace.setst` with immediate `ace_state_off`, and declared "not
usage-controlled". Since they are architecturally the same instruction, the hardware
must be told how to distinguish them; as written, a U-mode process cannot clear a CR
whose `_UsagePolicy_` excludes U-mode, which conflicts with the context-switch model at
`1054-1055` (which requires lower-privileged code to be able to erase CRs).

### M21 — Undefined and inconsistent extension names — **FIXED**

All six items corrected, and checked mechanically: every ``Zkl``-prefixed name appearing
anywhere in the included files now matches one of the 38 defined in the extension table,
and every defined name is referenced at least once. The `ace.store` correction is the one
with substance — it was assigned to `Zklv`/`Zklio` while `ace.load`, its counterpart, was in
`Zklmem`, so an implementation of `Zklmem` alone would have had a load instruction and no
store.
* `ace-ISA-algorithms.adoc:40`: AES128_CMAC requires "`Zklcmac`"; the extension is
  `Zklcmacm` (`ace-ISA-unpriv.adoc:105`).
* `ace-ISA-unpriv.adoc:129`: `Zklkn` depends on "`Zklaes128`, `Zklaes256`, `Zklesha2`" —
  the defined names are `Zklaes128p`, `Zklaes256p`, `Zklesha2h`.
* `ace-ISA-unpriv.adoc:1197-1199`: `ace.store` is "Included in" `Zklv`/`Zklio`; the
  extension table (line 92) places both `ace.load` and `ace.store` in `Zklmem`, and
  `ace.load`'s own box says `Zklmem`.
* `ace-ISA-unpriv.adoc:2501`, `2552`, `2625`: code snippets labelled "(`Zklm`)"; the
  extension is `Zklmem`.
* `ace-ISA-unpriv.adoc:133`: "At least of `Zklmem` or `Zklmv`" (missing "one").
* The `Zklkn` row (line 129) uses a `2+` column span that misaligns "Minimum version".

### M22 — Architectural resource allocation not yet negotiated — **FIXED**
`ace-ISA-priv.adoc:106`, `117`.

`misa` bit `L` (11) and `mstatus`/`sstatus`[26:25] are claimed unilaterally. RVI now
prefers the unified discovery mechanism over new `misa` bits, and `mstatus` bits in that
region are contested by recent extensions. This needs an explicit ARC/opcode-space
request alongside the C12 opcode question; flagging it here because it is a gating item
for candidacy, not a drafting detail.

### M23 — Which MDH snapshot is authenticated is never pinned — **FIXED**

Pinned to the initial image, per the author: the MDH as it stood when the operation began.
For an export that is the `_ace_cfgst_Complete_` image software reads with `ace.getmdl` and
saves before `#ace_CR_export_start`; for an import it is the image carried in the SCC and
passed to `#ace_CR_import_start`. Both assignment sites now say so, and the rule records
why it is forced rather than chosen: a CR is in ``ace_cfgst_exporting`` when its `SIV` is
computed and in `_ace_cfgst_Importing_` when that `SIV` is checked, so authenticating the
in-flight image would make every SCC fail to import.
`ace-ISA-unpriv.adoc:2950`, `1581-1587`, `1596-1604`.

`AD[0] ← K(i).MDH` — but the export sequence mutates `_ConfigStatus_` (Complete →
Exporting → restored) and possibly `_State_` around the point at which the SIV is
computed, and software separately saves and restores `MDH[63:0]` out of band. The
specification never says whether the authenticated MDH is the pre-export or the
in-export image. Since the MDH governs the SCC length, `_UsagePolicy_`, `_Locality_` and
`_ExpirationDate_`, an off-by-one-state here is directly exploitable: an SCC produced
under one image and verified against another either fails always or authenticates a
value different from the one the importer will act on.

### M24 — Security rationale gaps in the SCC construction — **FIXED**
`ace-ISA-unpriv.adoc:2939-2961`, `2953`.

* Locality Secrets are fed to GCM-SIV as **associated data** rather than through a KDF.
  This can be made to work, but no argument is given, and POLYVAL is linear in its
  blocks — a rationale (or a switch to `CSK' = KDF(CSK, localities)`) belongs in the
  specification.
* When Locality #11 (`_Nonce_`) is not selected, `N ← zeros(96)`, so sealing is fully
  deterministic under a fixed CSK: identical CCs produce byte-identical SCCs, which
  leaks equality across processes and across time and makes rollback detection harder.
  This interacts with the acknowledged non-resistance to SCC rollback
  (`ace-ISA-unpriv.adoc:1050-1052`).
* No key-usage bound is stated for the CSK. RFC 8452 §9 gives explicit limits; a
  long-lived, device-wide CSK with a fixed nonce needs those limits recorded.

### M25 — CMAC last-block guard checks the wrong variable — **FIXED**
`ace-ISA-algorithms.adoc:1583`.

> `. if `last_block_len` != 0, then the CR is *invalidated*. (The previous block is not
> complete.)`

`last_block_len` is zeroed on entry to `_Initial_` and set only by this very instruction;
the comment shows the intent, and the analogous rule for the generic hash
(`1720`) correctly tests `block_base != 0`. As written the check never fires, and CMAC
has no `block_base` in its internal state (1517-1521) with which to make it fire — so
CMAC cannot detect a partial pending block at all.

---

# minor

* **m1** — **FIXED** by the author: the bit is `MDH[63]`.
  _Original finding:_ `ace-ISA-unpriv.adoc:329` — "signalled by the _SystemFormat_ bit MDH[63:0]";
  should be MDH[63].
* **m2** — **FIXED.** "_unconfigured_meaning" -> "_unconfigured_, meaning".
  _Original finding:_ `ace-ISA-unpriv.adoc:155` — "a CR can be _unconfigured_meaning it does not
  contain a CC" (missing space/emphasis terminator).
* **m3** — **FIXED.** `ace.start` was used five times for the CSR `acestart`; all five
  corrected, together with a doubled full stop on one of them.
* **m4** — **FIXED.** "if set to" -> "is set to"; `_ace_cfgst_ace_CR_import_` -> `_ace_cfgst_Importing_`; and the case-mangled `_ace_cfgst_importing_`, `_CfgExporting_` and `_ace_cfgst_complete_` normalised throughout, including in the code comments.
  _Original finding:_ `ace-ISA-unpriv.adoc:1547` — "_ConfigStatus_ **if** set to _ace_cfgst_Provisioning_,
  resp., _ace_cfgst_**ace_CR_import**_"; also `_ace_cfgst_importing_` (1522) and `_CfgExporting_`
  (1524) for `_ace_cfgst_Importing_` / ``ace_cfgst_exporting``; `_ace_cfgst_complete_` in the code
  comments (2588, 2618, 2632, 2664).
* **m5** — **FIXED.** The note about random material being generated only at the final
  step said "(i.e., when `ace.mgmt` is used to terminate an **import** process)" inside a
  paragraph about **provisioning**; corrected to "a provisioning process". The note is
  moved from the end of the import-termination block to the end of the
  provisioning-termination block, where it belongs.
* **m6** — **FIXED.** `aceiobuflen`, `acemaxiobuflen` and `aceiobuftop` are now stated in **bits** everywhere, per the author. This is the reading the rest of the specification already required: `ACELEN` is defined as "`VL*SEW` or the length `aceiobuftop` of the ACEIOBUF **in bits**". **See the note below on `acestart`.**
  _Original finding:_ `ace-ISA-unpriv.adoc:865` — `aceiobuflen` "programs the ACEIOBUF length **in
  bits**"; the CSR table (770) and every other use say bytes.
**CHANGED TO BYTES**

* **m7** — **FIXED.** "invalid instruction exception" appeared 15 times where RISC-V
  terminology is "illegal instruction exception"; all replaced. The distinct identifier
  `ace_exc_invalid` was deliberately left alone.
* **m8** — **FIXED.** The prose used `acemvendorid`/`acemarchid`/`acemimpid` while the
  CSR table and `IMPQUAL` used `acevendorid`/`acearchid`/`aceimpid`. Standardised on the
  `m` forms, which the author confirms are correct: 15 occurrences across
  `ace-ISA-unpriv.adoc` and `ace-ISA-algorithms.adoc`.
* **m9** — **FIXED.** All eleven typos corrected in the included files: `ace.state`, `ace..restrictv`, `ace.mgmtt`, "mey", "Ths", the stray backtick in "32 or 96", "ads", "keepins",, "ML-KRM", and the stranded "not empty." table cell. (`ace-annexes.adoc` and `ace-instruction-summary.adoc` also contain `ace.state`, but neither is included by `ace.adoc`.)
  _Original finding:_ Typos in normative text: `ace.mgmtt` (2388), `ace..restrictv` (1837),
  `ace.state` (1435), `outout=J0` (801), "Currently, the allowed values **ads** 64, 96,
  and 128" (1224), "**Ths** subsection" (2459), "**mey**" (2424), "**teh** NTT" (2879),
  "**keepins**" (2359), "ML-K**R**M" (2773), "`32 or 96\`` " stray backtick (738),
  "not empty." stranded in a table cell (2532).
* **m10** — **FIXED** earlier, under C7: all eight `vsetvli` with an immediate became `vsetivli`.
  _Original finding:_ `ace-pseudocode.adoc` (8 occurrences) — `vsetvli zero, 4, e32, m1, ta, ma`
  passes an immediate in the `rs1` position; the immediate form is `vsetivli`.
* **m11** — **FIXED.** `bz` -> `beqz`; `sd 0(t6), t1` -> `sd t1, 0(t6)` in both export snippets; `ace.getmd` -> `ace.getmdl`; the `ace.mgmt` operand order corrected to match the defined mnemonic `Kd, #immed7, Xs` at four sites; the export snippets given a `restart:` label and an initialised `a2`/`t3`. `subi` had already gone under M3.
  _Original finding:_ `ace-ISA-unpriv.adoc:2471-2655` — the code snippets do not assemble: `subi`
  (2479, 2530) and `bz` (2567) are not RISC-V mnemonics (`addi …, -8`, `beqz`);
  `sd 0(t6), t1` (2594, 2638) has reversed operands; `ace.getmd` (2586, 2630) should be
  `ace.getmdl`; the export snippets branch to a `restart:` label that does not exist and
  use `a2`/`t3` uninitialised; the `ace.mgmt` operand order (`K{t0}, t1, #immed`) does not
  match the defined mnemonic (`Kd, #immed7, Xs`).
* **m12** — **FIXED.** The XEX example set the tweak in `V0` and then passed `V1`; it now passes `V0`.
  _Original finding:_ `ace-pseudocode.adoc:78-79` — `V0 ← IV` followed by
  `ace.setst K0, #ace_state_encrypt, V1` (wrong register).
* **m13** — **FIXED** earlier, under C7: the GCM-alternate example was rewritten, removing the 33-bit `V5[32:0]` and giving both length fields `binBE(...,64)`.
  _Original finding:_ `ace-pseudocode.adoc:179` — `V5[32:0] ← counter` (33 bits); `189` —
  `V3 xor (len_in_bits(AD) @ len_in_bits(PT))` needs `bin(·,64)` on both.
* **m14** — **FIXED.** The GCM-SIV decryption example now enters `_Decrypt_` before the decryption loop and finalises with `#ace_state_dec_tag_finalize`; the encryption example gained the missing `#ace_state_hash_absorb` transition.
  _Original finding:_ `ace-pseudocode.adoc:247-285` — the GCM-SIV *decryption* example uses
  `#ace_state_enc_tag_finalize` and never enters `_Decrypt_`; the encryption example
  omits the `#ace_state_hash_absorb` transition the decryption example has.
* **m15** — **FIXED.** CMAC mnemonics corrected to `ace_state_hash_*`, including the doubled `ace_hash_hash_finalize`; the `M_len = 0` case no longer drives `blocks` to -1.
  _Original finding:_ `ace-pseudocode.adoc:383-399` — CMAC: for `M_len = 0`, `blocks` becomes −1;
  mnemonics `ace_hash_absorb`, `ace_hash_last_block`, `ace_hash_hash_finalize` (double
  "hash") instead of `ace_state_hash_*`.
* **m16** — **FIXED.** OCB: the redundant `X1 mod 128 != 0` guards became `X1 != 0`, the immediately-overwritten `V0 <- zeros(128)` lines removed, and `ace_hash_verify` corrected to `ace_state_hash_verify`.
  _Original finding:_ `ace-pseudocode.adoc:328-334, 343-352` — OCB: `X1 ← AD_len mod 128` followed by
  `if (X1 mod 128 != 0)`; `V0 ← zeros(128)` is overwritten on the next line;
  `ace_hash_verify` (365) instead of `ace_state_hash_verify`.
* **m17** — **FIXED** (was `ace-acronyms.adoc:74-100`, now `ace-notation.adoc`).
  `len_in_bits(M) = ceil(log2(M))` and `len_in_bytes(M) = ceil(log2(M))/8` were wrong
  (that is the length of the *integer* M, not of the message); `lsb(x)` was defined as a
  single bit but used as `lsb_c(J0)` (`ace-ISA-algorithms.adoc:821`); `<<`, `int()`,
  `bit_length()`, `%`, `xor`, `foreach` and `@` were used but not defined; `←` and `<-`
  were used interchangeably. All are now defined in `ace-notation.adoc` and
  `ace-conventions.adoc`. Two duplicate spellings were eliminated rather than defined
  twice: `bit_length` (4 uses in Book 2) folded into `len_in_bits` (17 uses in Book 4),
  and `%` (4 uses) folded into `mod` (7 uses). `pad()` is defined locally in the Ascon
  section and was left there. Defining `mod` exposed **C16**; see the status section.
  Residual: the `bin`/`binBE` entries keep their original wording, including an "or sign
  extended" clause that is meaningless for their actual unsigned uses.
* **m18** — **FIXED.** RUP now reads "Release of Unverified Plaintext", matching the Introduction; the six unused entries `LF`/`KMA`/`PCBC`/`ASID`/`VMID`/`EPC` are commented out (verified absent from the rendered table); `ESG` corrected to `EGS`, matching the sole use in the text, and re-sorted above `EGW`; and the duplicate `HV` entry removed by the author. A scan of the table finds no remaining duplicate acronyms.
  _Original finding:_ `ace-acronyms.adoc` — `HV` listed twice; `ESG` vs the `EGS` used in the text
  (`ace-ISA-unpriv.adoc:1019`); `RUP` glossed "Release of *Unencrypted* Plaintext" vs
  "Release of *Unverified* Plaintext" in the Introduction (`ace-introduction.adoc:94`);
  `LF` ("Locker File"), `KMA`, `PCBC`, `ASID`, `VMID`, `EPC` appear unused.
* **m19** — **FIXED** by the author, apart from the naming, which is now `ML-DSA-nn`/`HashML-DSA-nn` in the extension table as well, matching FIPS 204 and the algorithm table.
  _Original finding:_ `ace-ISA-algorithms.adoc:44-51` — AES-192/256 rows say "Modes **1--12** …
  Analogues to Modes **1--11**"; AES-128 defines modes 0–12; SM4 says "1--10 …
  Analogues to Modes 1--10" but AES-128 mode 11/12 (OCB) are omitted without comment.
  ML-DSA occupies Modes 3, 5, 7 with 4, 6, 8 unassigned and unexplained;
  `ML-DSA-44-PH` (`ace-ISA-unpriv.adoc:126`) vs `HashML-DSA-44` (line 100) — FIPS 204
  uses the latter.
* **m20** — **FIXED.** The `0x425` constant for `b` = 256 is removed. Rather than deleting it silently, the line now states that 64 and 128 are the only block sizes for which SP 800-38B defines CMAC and that any other is outside both this specification and the standard — the CMAC parameters otherwise place no bound on `b`.
  _Original finding:_ `ace-ISA-algorithms.adoc:1542` — the CMAC subkey constant `0x425` for `b` = 256
  is outside SP 800-38B (which defines only `b` = 64 and 128). Flag it as an ACE
  extension and cite the polynomial.
* **m21** — **FIXED.** Applied to the GCM-SIV `absorb` as well as the GCM one cited, since both had it. This was not merely notational: with the body hardwired to `INPUT`, the call sites `absorb(tmp)` in GCM's encrypt path and `absorb(OUTPUT)` in GCM-SIV's decrypt path would have absorbed the wrong value — plaintext instead of ciphertext, and ciphertext instead of recovered plaintext.
  _Original finding:_ `ace-ISA-algorithms.adoc:762-764` — `absorb(data)` takes `data` but the body
  uses `INPUT`.
* **m22** — **FIXED.** `_Set_Aux_Value_2_ -> _Hash_Absorb_` added. The missing `_Encrypt_ -> _Success_` is **retracted**: the CC is not told the plaintext length and does not count blocks, so it cannot know when the last one has been encrypted, and the SIV was already produced in `_Enc_Tag_Finalize_`. That reasoning is now recorded in the specification, since its absence is otherwise indistinguishable from an omission. The `_Set_Aux_Value_2_` note, a verbatim copy of the `_Set_Aux_Value_` one, was rewritten to describe `SIV`, and the missing closing parenthesis was fixed at both sites.
  _Original finding:_ `ace-ISA-algorithms.adoc:1060-1064` — GCM-SIV transitions: no
  `_Set_Aux_Value_2_ → _Hash_Absorb_` and no `_Encrypt_ → _Success_`; the
  `_Set_Aux_Value_2_` note (1092) repeats the `_Set_Aux_Value_` text verbatim
  ("overwrites the `nonce` and recomputes `enc_key` and `auth_key`") although it sets
  `SIV`; `enc_blk(enc_key, 0 @ tmp[126:96] @ (tmp[95:0] xor nonce)` (1119, 1164) is
  missing a closing parenthesis. The precedence item — `SIV[31:0] + ctr % 2^32` — is
  **FIXED**; it turned out to suppress the modular reduction entirely and was escalated
  to **C16**. The remaining items are unchanged.
* **m23** — **FIXED.** `hash_P` corrected to `checksum_P`; `MAX_BLOCKS` assigned the value 2^48; `0 < 1 <` corrected to `0 < i <` at both sites; the "(only `u+1` bits used)" annotation moved from `L`, where it was a copy-paste, onto `N`, where it belongs, with `u+1` = 121 spelled out. The internal-vs-serialized width mismatch is **not a defect**: per the author the serialized fields are zero-padded and aligned to multiples of 8 bits so that an SCC can be parsed without bit-level extraction, which the specification now states. The tag-length contradiction is resolved by tightening the check: the argument must be 64, 96 or 128, matching the Parameters, and any other value including 0 invalidates the CR.
  _Original finding:_ `ace-ISA-algorithms.adoc:1240` — serialized `L` annotated "(only `u+1` bits
  used)", copied from `N`; `1476` — `_Hash_Verify_` compares against `hash_P`, undefined
  (should be `checksum_P`); `1300`, `1333` — "for all `i` with `0 < 1 <
  floor(log_2(MAX_BLOCKS))`"; `MAX_BLOCKS` (1198) is never assigned a value; `1224` says
  the allowed tag lengths are 64/96/128 while `1323` accepts any value in [1,128];
  internal widths `tag_len`:8, `N_len`:7, `last_blk_len`:`g` (1223-1225) disagree with the
  serialized widths 16/16/16 (1245-1247).
* **m24** — **FIXED.** `pad` is now called with both arguments; `INPUT` {ge} 127 corrected to > 127, with a note that a 127-bit final block is legal; and the truncated `_Enc_Last_Block_` prose repaired — the stray "And in the second case, the `ace.exec` instruction performs:" removed, and the lead-in rewritten, since "Otherwise" introduced the pseudocode for the non-zero case as though it were the zero case. That case does not arise: `_Enc_Last_Block_` is only entered when `last_block_len` is non-zero. The stray parenthesis in `state[1] xor (1 << 63))` had already gone under C8.
  _Original finding:_ `ace-ISA-algorithms.adoc:1988` — `pad(x,r)` is declared with two parameters and
  called with one (2087, 2152); `2070`, `2133` — "If `INPUT` {ge} 127" should be > 127
  (127 is a legal partial-block length); the stray parenthesis in
  `state[1] xor (1 << 63))` is **FIXED**, the whole expression having been replaced under
  **C8**; `2080-2096` — the `_Enc_Last_Block_` prose is truncated: "And in the second
  case, the `ace.exec` instruction performs: In state _Enc_Last_Block_ only one 128-bit
  block is processed."
* **m25** — **FIXED.** Ascon-XOF128 no longer claims that 64 bits of Ascon-Hash256's Serialized Context are absent; `countdown` lives in _AlgorithmUse_, so the two Serialized Contexts are identical.
  _Original finding:_ `ace-ISA-algorithms.adoc:2370-2371` — Ascon-XOF128 says "the last 64 bits of the
  Serialized Context of Ascon-Hash256 are not present", but the Ascon-Hash256 serialized
  table (2293-2302) has no such field (`countdown` lives in the MDH's `_AlgorithmUse_`).
* **m26** — **FIXED.** "Fields vii to x" -> "the optional Fields v to viii"; the dangling "Position x" replaced by a reference to the Implementation VDS of <<ACE-SCC>>; the spurious constant 8 removed from `varlen` and every term stated to be in octets; `RndNum` pinned to `j` bits in both the Internal State and the SCC.
  _Original finding:_ `ace-ISA-algorithms.adoc:2541-2547` — "The size in bits of Fields **vii to x**"
  and "Position **x**" refer to positions past the end of the table (which stops at
  viii); the `varlen` formula mixes bits and bytes (`ub`/8 added to a constant 8);
  `RndNum` is `h` bits in the internal state (2508) and `j` bits in the SCC (2531).
* **m27** — **FIXED** as a documented deliberate choice rather than a format change: a NOTE records that `decapsk` embeds `encapsk` per FIPS 203 7.1, that the duplication is kept because the two fields are configured independently and `ACE-length-rule` requires the SCC length to follow from the MDH alone, and that an implementation may omit `encapsk` from its Implementation VDS and recover it from `decapsk` on import.
  _Original finding:_ `ace-ISA-algorithms.adoc:2723`, `2739` — ML-KEM stores both `encapsk` and
  `decapsk`, but FIPS 203's `dk` already embeds `ek`, so ~800–1568 bytes per SCC are
  redundant.
* **m28** — **FIXED** in part, per the author: there is deliberately no `ace_exc_expired`. Expiry is reported through `ace_exc_invalid`, and the handler distinguishes it by reading the CR's _State_, which the hardware has set to `ace_state_expired`; the exception table now says so. The numeric code assignments remain TBD, which is expected at this stage.
  _Original finding:_ `ace-ISA-priv.adoc:47`, `63-69` — all exception codes are TBD, and there is no
  `ace_exc_expired`, although `_Expired_` has a dedicated CR state and
  `ace-ISA-unpriv.adoc:708` says an exception is raised (mapping it onto
  `ace_exc_invalid` — worth stating in the table).
* **m29** — **FIXED.** The clock question is answered as the author directs: the specification now states that it cannot give requirements for a secure clock, that the difficulty is common to every time-dependent security feature rather than particular to ACE, and gives the rule of thumb — a clock adequate for M-mode-only security features, or for a TPM in the same SoC, is adequate for the ACE unit. I added one consequence that follows from it: the clock must not be settable below the privilege level that manages the CSK, or a CC could be kept alive indefinitely by moving it backwards. The epoch now reads "00:00 UTC on 1 January 2027" at both sites, with the reason stated: a
  UTC epoch makes a CC exported on one device and imported on another expire at the same
  instant whatever local time each observes.
  _Original finding:_ `ace-ISA-unpriv.adoc:702` — `Zklexpire` "must have access to a secure clock", but
  no clock interface, epoch precision, or timezone is architected, and there is no CSR to
  read the current time. The epoch is "00:00, January 1, 2027" (318) — say UTC.
* **m30** Open items still in the document: the RVV-mini WARNING (`221-225`, `253-257`),
  the memory-model WARNING (`748-752`, `2438-2441`), the `ace.mgmt`-vs-`ace.setst`
  encoding question (`1415-1418`, `1462-1465`), the Debug-mode questions (`985-996`,
  `ace-ISA-priv.adoc:386-389`), the `ace_exc_CR_unconf` merge question
  (`ace-ISA-priv.adoc:71-74`), and the Introduction's TODO list
  (`ace-introduction.adoc:96-106`) including the unresolved `kl` vs `ace.` naming.
  `:revdate: 6/2025`, `:revnumber: 0.0` (`ace.adoc:6-7`) should be refreshed before
  submission.
---

## Suggested order of work

1. **C1, C2** — write the Conventions section (bit/byte order, `@`, shifts) and define
   `Galoismul`/`Montmul`/`update_mask` per algorithm. Nothing else in Book 2 can be
   verified until this exists.
2. **C3–C9, C11** — re-derive the SCC sealing, GCM, GCM-SIV, OCB3, Ascon and
   `process_VLI` pseudocode against reference implementations under the new convention.
3. **Publish known-answer test vectors** in the specification (at minimum: one vector per
   algorithm, plus one SCC export/import round trip). This is the only practical defence
   against the class of error found here, and for a security-critical extension it should
   arguably be normative.
4. **C10, C12, C13, C14, M1–M5, M21** — the ISA-level inconsistencies (state numbering,
   opcodes, instruction Forms, dangling instruction names, MDH field semantics).
5. **M22, C12** — open the opcode-space and `misa`/`mstatus` conversation with the ARC.
6. **M11, M13, M14** — complete KMAC, ML-KEM `_ciphertext_Input_`, ML-DSA key import.
7. Editorial pass for the minor items; consider a consistency lint over instruction
   mnemonics, state mnemonics and extension names, all of which drift measurably across
   the four books.
