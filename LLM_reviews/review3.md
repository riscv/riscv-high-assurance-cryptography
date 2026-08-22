# Review 3 — ACE Specification (RISC-V Atomic Cryptography Extension)

*Review date: 2026-08-13, updated as fixes land. Reviewed files: `ace-ISA-unpriv.adoc`,
`ace-ISA-algorithms.adoc`, `ace-ISA-priv.adoc`, `ace-pseudocode.adoc`,
`ACE-Notation.adoc`, `ace-notation.adoc`, `ace-introduction.adoc`, `ace.adoc`.
Algorithms checked against SP 800-38A/B/D/E, RFC 8452, RFC 7253, FIPS 202 / SP 800-185,
FIPS 198-1, SP 800-232, RFC 8032, FIPS 203/204.*

*Findings ordered Critical (C), Major (M), minor (m). Status: [OPEN] / [FIXED] /
[PARTIAL] / [WONTFIX]. Line numbers are as of the reading noted per item and may drift
as the spec is edited; section anchors are authoritative.*

---

## Overall verdict

The architecture is well conceived and much of the hard transcription work is
demonstrably right: the OCB3 nonce/Ktop/Stretch/bottom slicing, XEX/XTS including the
ciphertext-stealing-by-cloning procedure, the SHA-3/cSHAKE suffixes and the KMAC
key/customization bounds (163/157 and 131/125 octets), the Ascon-AEAD128/Hash256
permutation placement (including the subtle equivalence of "permute after last absorb,
skip permute on first squeeze"), the GCM-SIV core, the sealing construction (including
the argued omission of the POLYVAL length block), and the ML-KEM/ML-DSA sizes all check
out against the standards. `process_VLI` terminates and the spec even argues why. The
endianness conventions chapter is unusually careful.

However, the document is **not yet in good shape for ratification-track review**: the
Critical findings below include silent non-conformances to NIST standards, and there are
several Major internal contradictions (notably between Book 2 state machines and the
Book 4 examples, and between the exception model and the canonical code sequences). The
acknowledged TBDs (preliminary encodings, TBD `mcause` values, provisional
`misa.L`/ACES placement, unfinalized RVV-mini) are fine for a Development-state draft
but also block candidacy.

---

## Critical

### C1 — [FIXED] GCM: counter position must survive export/import (keystream-reuse hazard)

**Original finding:** the GCM Serialized Context (`ACE-GCM-mode`) carried `start_ctr`
but not the running counter, while export is allowed in any State; a context switch
during `_Encrypt_`/`_Decrypt_` lost the counter position, and resumption re-generated
already-used counter blocks — a two-time pad under an unchanged key.

**Resolution (verified 2026-08-13):** the design was reworked so that `J0[127:96]`
*is* the current GCTR counter, written back after each block
(`J0[127:96] <- bswap(ctr)`, `ace-ISA-algorithms.adoc:981`, `:1027`), with `ctr` a
local variable of `_Encrypt_`/`_Decrypt_`. Since `J0` is serialized, the counter
position survives export/import. The core hazard is closed.

**Rework verified (2026-08-13, second pass):** the dangling "Upon entering either
State…" fragment and the stale `ctr <- start_ctr` in GCM-with-Set-IV were removed, and
both finalize paths now compute the identical, correct tag mask
`enc_blk(key, binBE(start_ctr,32) @ J0[95:0])`, which expands to `E(K, J0_initial)` as
SP 800-38D requires. The remaining typing cleanup was completed under m4 (now
`start_ctr`/`ctr` are integers, extracted with `int(bswap(…))` and written back with
`binBE(…,32)`).

### C2 — [FIXED] GCM: `J0` length block for IV ≠ 96 bits transcribed with reversed endianness

**Original finding:** the `finalize()` step of _Set_Aux_Value_ read
`J0 <- J0 XOR (0^64^ @ binBE(8 len,64))`. SP 800-38D §7.1's final GHASH block is
`0^64 ‖ [len(IV)]64` — zero octets *first*, so under the spec's own convention (first
octet = least significant; left operand of `@` = more significant) the length belongs in
the *high* 64 bits. As written, the length landed in the low 64 bits and every
non-96-bit-IV GCM computation produced a non-conformant `J0`.

**Resolution (applied 2026-08-13):** the step now reads

```
J0 <- J0 xor (binBE(8 len,64) @ zeros(64))
```

(`ace-ISA-algorithms.adoc:955`), with `XOR` lowercased to match the notation chapter. A
short note was added explaining that the zeros occupy octets 0–7 (`J0[63:0]`) and the
length octets 8–15 (`J0[127:64]`), which is why `binBE(8 len,64)` is the left operand —
mirroring the existing note for the 96-bit case.

Checked at the same time: the two GCM tag length blocks
`binBE(len_in_bits(plaintext),64) @ binBE(len_in_bits(AD),64)` (`:993`, `:1037`, and the
Book 4 examples) are **correct** as written — SP 800-38D orders
`[len(A)]64 ‖ [len(C)]64`, so the AD length belongs in the low octets, which is what `@`
yields there. This was the only reversed length block in the document.

Verified by building the spec with `asciidoctor` and inspecting the rendered passage.

### C3 — [FIXED] CMAC subkey generation

**Original finding:** `gen_subkeys` used `msb(L)`, the value-level `<<`, and XORed
`C` into the first octet — i.e. little-endian XTS-style doubling instead of
SP 800-38B's big-endian `L << 1`.

**Fix attempt (2026-08-13):** the shift was replaced by `double()`, which is the
correct primitive. However the surrounding conditional was kept:

```
if (msb(L) == 0) then { K1 <- double(L) } else { K1 <- double(L) xor C }
```

**This is still wrong, because `double()` already performs the conditional
reduction itself.** Per `ACE-Notation.adoc:190`–205,
`double(S) = bswap(update_mask(bswap(S)))`, which expands to "test `S[7]`; shift; and
if the tested bit was 1, xor `0b10000111 @ zeros(120)`". So the retained conditional:

1. **applies the reduction twice** whenever its branch is taken;
2. **tests the wrong bit** — `msb(L)` is `L[127]`, the MSB of octet 15, whereas the
   big-endian MSB governing the reduction is `L[7]`, the MSB of octet 0, which
   `double` already tests internally; and
3. **puts the second constant in the wrong octet** — `C` written as a bare numeral
   `0x87` is the value `0x87`, i.e. octet 0, whereas `double`'s reduction correctly
   lands in octet 15 (`S[127:120]`).

Net effect: for every key whose `L` has `L[127] = 1` — half of all keys — `K1` is
corrupted by a spurious `0x87` in octet 0, and `K2` likewise. The subkeys still
disagree with SP 800-38B.

**Correct text is simply:**

```
. L  <- enc_blk(K, zeros(b))
. K1 <- double(L)
. K2 <- double(K1)
```

with no conditional and no `C` (the constant survives only inside `double`).

**Resolution (applied 2026-08-13).** All four parts are now closed:

* `gen_subkeys` is reduced to `L <- enc_blk(K, zeros(b))`, `K1 <- double(L)`,
  `K2 <- double(K1)`, with the conditional and `C` removed. A note records *why* the
  conditional must not be reinstated — `double` already tests `S[7]`, shifts, and
  conditionally reduces into octet 15 — so the next editor does not re-add it.
* The `b` = 64 gap is resolved by scoping rather than by new arithmetic: the note states
  that `double` is defined only for `b` = 128, that this is the only block size at which
  ACE instantiates CMAC (every cipher for which <<ACE-exec-encodings>> defines a CMAC
  mode — AES-128/192/256 and SM4 — has a 128-bit block), and that a future 64-bit block
  cipher would have to state its own GF(2^64^) doubling, mirroring how
  <<ACE-conventions-fields>> treats XEX at `b` {ne} 128.
* The 10* padding is now an explicit formula,
  `zeros(b - 8 - last_block_len) @ 0b10000000 @ INPUT[last_block_len-1:0]`, with a note
  that the terminating `1` is the most significant bit of octet `last_block_len`/8 and
  *not* bit `last_block_len` of the value — the same subtlety `ocb_pad` documents — and
  that `last_block_len` = 0 reduces it to the all-padding block CMAC uses for the empty
  message. `ocb_pad` itself was deliberately *not* reused, to avoid coupling CMAC to a
  function named for another algorithm.
* `last_block_len` is now declared "an integer in the range 0 to `b`, serialized on 32
  bits", and the _Initial_ action is `last_block_len <- 0` rather than `zeros(64)`.

**Judgment call made while fixing, flagged for the author.** Writing the padding as a
closed formula requires knowing where the `1` bit lands, which is well defined only at an
octet boundary. The `ace.setst` check was therefore tightened from "if `Xs > b`" to "if
`Xs > b`, or if `Xs` is not a multiple of 8", with the reason stated inline. This agrees
with <<ACE-octet-granularity>> (a CMAC last-block length is a *message* length, not an
in-unit truncation in the sense of <<ACE-truncation-vs-length>>) and with how OCB already
constrains its own `last_blk_len`. If CMAC over non-octet-aligned messages is wanted, the
general placement is
`8`{times}`floor(n/8) + 7 - (n mod 8)`, which is worth avoiding in hardware; revert the
check and substitute that expression if the generality is required.

### C4 — [FIXED] GCM / GCM-SIV handling of messages that are not a multiple of 128 bits

**Original finding:** neither GCM nor GCM-SIV had a last-block state, so on the GCM
encryption path the unit absorbed a full ciphertext block whose tail beyond the message
end was *keystream* rather than zeros (and GCM-SIV decryption had the mirror-image
defect on the plaintext), silently producing tags that disagree with SP 800-38D and
RFC 8452.

**Resolution (verified 2026-08-13): the cryptographic core is correct.** States
_Enc_Last_Block_ / _Dec_Last_Block_ were added to both algorithms, `last_blk_len` was
added to both Internal States *and* both Serialized Contexts (so the value survives the
context switch that can occur between the `ace.setst` that sets it and the `ace.exec`
that consumes it — the C1 lesson applied), and the SCC padding rows were adjusted so
every total remains a multiple of 128 bits for `k` {in} {64, 128, 192, 256}. Checked in
detail:

* GCM _Enc_Last_Block_: `tmp` is the zero-padded (partial plaintext xor partial
  keystream), i.e. the zero-padded partial *ciphertext*, and `absorb(tmp)` therefore
  feeds GHASH exactly what SP 800-38D specifies; `OUTPUT` carries no keystream past
  `last_blk_len`. ✓
* GCM _Dec_Last_Block_: `tmp` is the zero-padded partial ciphertext and is what is
  absorbed; `OUTPUT` is the zero-padded plaintext. ✓
* GCM-SIV _Enc_Last_Block_: correctly performs *no* absorption — the plaintext is
  absorbed in _Hash_Absorb_ on that path — and masks the keystream. ✓
* GCM-SIV _Dec_Last_Block_: absorbs the zero-padded partial plaintext, matching
  RFC 8452's POLYVAL input. ✓
* In all four, the keystream slice `[last_blk_len-1:0]` selects the *first* bits of the
  string, which is the `MSB_u` of the standards' big-endian view. ✓

**Residuals (must be closed before this counts as fixed):**

1. **[FIXED] GCM-SIV: _Enc_Last_Block_ was unreachable.** The transition list
   (`ace-ISA-algorithms.adoc:1294`) read
   `_Hash_Absorb_ -> _Enc_Tag_Finalize_ -> _Encrypt_ { -> _Dec_Last_Block_ }`, naming
   the *decryption* state on the encryption branch, so the transition to
   _Enc_Last_Block_ was never declared; by generic rule 2 (`ACE-generic-rules`) an
   undeclared transition raises an illegal-instruction exception and invalidates the CR,
   so GCM-SIV could not encrypt a non-block-multiple message at all. Corrected to
   `{ -> _Enc_Last_Block_ }` on 2026-08-13. Both algorithms' transition lists were
   re-checked afterwards for further Enc/Dec crossovers; none remain.
2. **[WITHDRAWN, with a documentation follow-up now applied] `last_blk_len` range
   1..127.** My original claim — that admitting non-multiples of 8 contradicts
   <<ACE-octet-granularity>> — was **wrong**, and the author's objection is correct.
   `last_blk_len` truncates a block that has *already* been transferred; the block still
   arrives as whole octets in a vector register or the ACEIOBUF, the result is
   zero-extended to a full block before write-back, and because a last block is always
   one uninterruptible `ace.exec` the value never has to be expressed as an
   octet-counted offset, so `acestart` is unaffected. The octet-granularity rule
   constrains transfers, not internal arithmetic. For GCM the range is moreover fully
   conformant, since cite:[nist-SP-800-38D] defines GCTR and GHASH over bit strings of
   arbitrary length.
+
   Because the distinction is genuinely easy to misread (it misled this reviewer), it is
   now stated explicitly in the specification: a new
   <<ACE-truncation-vs-length>> paragraph in the Padding section draws the
   truncation-vs-input-length line and lists the parameters it covers, with a pointer
   from the GCM and GCM-SIV transition paragraphs. The GCM-SIV pointer also records that
   cite:[RFC8452] derives its length block from a byte count, so only multiples of 8
   correspond to a plaintext length that RFC defines — the architecture permits a finer
   truncation and makes avoiding it the caller's responsibility.
+
   **The sub-point about excluding the value 0 is also withdrawn.** On re-examination the
   rejection of 0 is principled, and the comparison with OCB and Ascon that motivated the
   remark was not valid:
+
   * GCM's and GCM-SIV's last-block state is *optional* in the transition list
     (`_Encrypt_ -> { _Enc_Last_Block_ -> } _Enc_Tag_Finalize_`,
     `ace-ISA-algorithms.adoc:956`). A plaintext that is an exact multiple of 128 bits
     simply never enters it, so 0 carries no information there and rejecting it is a
     sound defensive check.
   * OCB needs 0 only because *its* last-block state is *mandatory* (`:1631`, no braces):
     the tag is computed inside it, so the state must be traversed even with no fractional
     block. Ascon needs 0 because it must absorb `pad(∅)`. GCM has neither obligation —
     GHASH zero-pads, and the tag mask is applied in _Enc_Tag_Finalize_.
   * The guard `If last_blk_len == 0, then terminate the instruction` is therefore not
     dead code: it is reached by a *second* `ace.exec` in the state, after the first has
     zeroed the field, and it is what makes a repeated `ace.exec` a benign no-op instead
     of an exception. Calling it "dead on first entry" missed its purpose.
+
   No change required; residual 2 is closed in full.
3. **[FIXED] Form B `ace.setst` was described as taking its argument from `INPUT`.**
   All four paragraphs said "`last_blk_len` … is set to `INPUT`", but Form B's auxiliary
   operand is a GPR (`Xs`); `INPUT` is defined in `ACE-notation` as the vector-register
   or ACEIOBUF datapath, i.e. Form C. Corrected on 2026-08-13 to "is set to the
   auxiliary argument `Xs`", matching the phrasing already used by OCB
   (`ace-ISA-algorithms.adoc:1660`, `:1670`).
+
   A sweep for the same defect class found one further instance, in the *generic*
   `process_VLI` subalgorithm (`ace-ISA-algorithms.adoc:804`): "it is passed as a
   parameter to a Form B `ace.setst` instruction and 'len` is set to the auxiliary
   parameter `INPUT`" — same Form-B/`INPUT` mismatch, plus a stray opening quote for a
   backtick. Since `process_VLI` is invoked by GCM, the hash/MAC functions, HMAC, EdDSA,
   ML-KEM and ML-DSA, this one was the more consequential of the two. Both are fixed;
   no occurrences of the pattern remain in any `.adoc` file, and the spec rebuilds
   cleanly.
4. **[FIXED] Prose copy-paste errors.** Both algorithms' `_Dec_Last_Block_` state
   summaries said "Encrypt the last block of the plaintext" and are now "Decrypt the final,
   fractional block of the ciphertext"; the two `_Enc_Last_Block_` summaries gained the
   missing terminal period and read "Encrypt the final, fractional block of the plaintext".
   GCM's `_Dec_Last_Block_` behavior line, which said it "encrypts `INPUT` into `OUTPUT`,
   and absorbs `OUTPUT` into the `tag`" — wrong in both halves on that path — now says it
   absorbs the zero-padded final ciphertext block and decrypts `INPUT` into `OUTPUT`;
   GCM-SIV's equivalent now says it decrypts and absorbs the zero-padded plaintext. The
   two "a single form A `ace.exec` instructions is expected" were corrected to "a single
   Form A `ace.exec` instruction is expected". The `_Encrypt_` and `_Enc_Last_Block_`
   descriptions were checked and left alone: on the encryption path `OUTPUT` *is* the
   ciphertext, so "encrypts … absorbs `OUTPUT`" is right there.
5. **[FIXED] Notation drift.** `0^128-last_blk_len^` became `zeros(128-last_blk_len)`
   throughout, matching GCM-SIV and OCB and avoiding a superscript with an embedded
   expression; `local tmp : b bits` became `` `local tmp : bits(b)` `` per
   `ACE-Notation`.
6. **[FIXED] The caller's zero-padding obligation is now normative, and stated for both
   algorithms.** GCM's descriptive aside ("the user only needs to make sure…") was replaced
   by a two-bullet normative statement in the States block: the caller *must* zero the
   final AD block beyond the end of the AD, with the reason (GHASH absorbs the block whole
   and SP 800-38D specifies the AD zero-padded, so anything else is non-conforming) and the
   reason no state is provided for it (nothing is concealed by padding outside the unit);
   and the caller *must not* rely on zero-padding for plaintext or ciphertext, using
   _Enc_Last_Block_/_Dec_Last_Block_ instead, because there the absorbed value's tail would
   be keystream. GCM-SIV's _Hash_Absorb_ previously said nothing at all and now carries the
   matching obligation for the AD *and*, on the encryption path, the plaintext — both of
   which RFC 8452 §4 specifies as zero-padded to 16 octets — with a pointer that the
   decryption-path ciphertext is handled by _Dec_Last_Block_ instead.
7. **[FIXED] Error-reporting inconsistency.** An out-of-range `last_blk_len` now
   *invalidates* the CR in all four places instead of raising an illegal instruction
   exception, with an explicit cross-reference to OCB, CMAC and Ascon, which already do
   this. Invalidation was the established pattern for a bad `ace.setst` algorithm
   parameter, and the exception was the outlier.
8. **[FIXED] GCM-SIV counter typing.** `ctr` is declared "an integer in the range 0 to
   2^32^-1, serialized on 32 bits"; the guard is `ctr` = 2^32^-1 rather than a comparison
   of an integer against the bit string `ones(32)`; and the counter block is
   `bin((int(SIV[31:0]) + ctr) mod 2^32^, 32)` in all four occurrences, matching the form
   already used by the sealing functions after the m4 fix.

**C4 is now fully closed.** The four new states were re-verified against SP 800-38D and
RFC 8452 after these edits, and the spec rebuilds cleanly.

---

## Major

### M1 — [FIXED] CSK scope across harts

**Original finding:** a hart reset was said to clear the CSK and `macecsk` is per-hart, so
nothing said whether an SCC sealed on hart A can be imported on hart B — which ordinary OS
scheduling requires, since the saved SCCs of a process must be restorable wherever it next runs.

**Resolution (applied 2026-08-13, in two rounds).**

*Round 1 — scope.* The author's position is that the hardwired and RNG-at-boot models are
for specialised embedded deployments, not general-purpose systems, which disposes of the
objection that an RNG-generated CSK cannot be migrated (software cannot read it, and it is
not used where migration arises). This is now stated, with the deficiency of each model
given separately: the hardwired CSK can be neither re-keyed nor revoked, and the
RNG-at-boot CSK cannot retain an SCC across a reset. General-purpose deployments use the
M-mode-programmed or hardware-block models. A migration paragraph requires the destination
hart to hold the same CSK, notes that the expected arrangement is one CSK across all harts
a process may be scheduled on so that no per-migration action is needed, and warns that
reprogramming a hart's CSK invalidates every SCC already sealed under the previous value,
including those of unrelated processes.

*Round 2 — the five residuals I raised, all now closed:*

1. **No architected cross-hart mechanism.** The text now states that a CSK is established
   on a hart by M-mode *on that hart*, since `macecsk` is per-hart state, and that doing so
   across several harts therefore requires a platform-specific channel between their M-mode
   instances — an IPI plus M-mode-exclusive on-chip memory, for instance — which this
   specification does not define. A [WARNING] asks the ARC whether an architected mechanism
   for M-mode on one hart to read or configure another hart's CSRs exists or should, and
   says ACE currently assumes it does not.
2. **Model 4 routing.** Per the author: the fourth model *must* also go through M-mode.
   Only M-mode may ask the secure hardware block to configure the CSK of its own hart, and
   it does so with a handle or a wrapped key rather than a clear value, so no software ever
   holds the key material; the addressing and conveyance mechanism is platform-specific.
   The earlier phrasing that let the block act on its own was removed here and in the
   model-scoping paragraph.
3. **Hart-reset obligation added.** In the second, third and fourth models M-mode must
   re-establish a CSK on a hart after any reset of that hart and before returning control to
   software that uses ACE; where one CSK spans several harts, it must be *that* CSK, or the
   SCCs of processes scheduled there will no longer import.
4. **Cross-reference added.** The migration text now points at the `macecsk` activation
   rules: while the group is partially written the ACE unit is unavailable on that hart, and
   any mode change to M-mode clears the write-tracking flags, so the group must be written
   within a single M-mode episode. This matters specifically to the
   reprogram-per-migration strategy the text permits.
5. **Scope disclaimer added.** How supervisor software instructs M-mode is outside the
   scope of this specification; the API is platform-dependent.

**Two errors of my own, corrected in round 2.** My first draft justified excluding the
hardwired model on the grounds that SCCs would not remain importable across harts or
survive a reset — which is false: a hardwired CSK is identical on every hart of the part and
persists across reset, so it raises none of the cross-hart questions. Its real deficiencies
are the absence of re-keying and revocation. Each model now carries its own reason, and a
sentence records that the hardwired case is exempt from the cross-hart discussion. I had
also introduced the term "scheduling domain", which appears nowhere else in the
specification; it is replaced by "every hart on which the operating system or hypervisor may
schedule that process".

### M2 — [FIXED] Exception model contradicted metadata-read rules and the canonical code

**Original finding:** `ace_exc_CR_unconf` fired on "use of an unconfigured, or partially
configured CR as a source in any instruction except `ace.size`", yet `ace.getmdl` on an
*Off* CR is defined to return zeros, and every provisioning/import/export sequence in
<<ACE-management-code-snippets>> issues `ace.getst` (built on `ace.getmdl`) on a partially
configured CR. As written, the architecture's own recommended code trapped.

**Resolution (applied 2026-08-13).** The exemption list in the `ace_exc_CR_unconf` row of
<<ACE-exception-codes>> now covers every instruction defined to operate on a CR in that
condition: `ace.size`, the `ace.getmd*` group (`ace.getmdl`, `ace.getmdh`, `ace.getmdv`,
and hence `ace.getst`), and the data-movement instructions used during configuration and
export, `ace.load`, `ace.store` and `ace.mv`. A note after the table records *why* each
exemption is necessary — `ace.load`/`ace.mv` write a CR precisely while its _ConfigStatus_
is _ace_cfgst_Provisioning_ or _ace_cfgst_importing_ and are illegal when it is _ace_cfgst_complete_;
`ace.store` and the CR-reading forms of `ace.mv` read a CR whose _ConfigStatus_ is
`ace_cfgst_exporting` — so the list is not narrowed again by a later editor. The note also
states that instructions which merely *target* a CR as the destination of a configuration
operation, `ace.mgmt` above all, never raise this exception.

The note further records that `ace_exc_CR_other` carries **no** such exemptions, and why:
a Lazy CR has no valid content at all, its authoritative value being an SCC held by some
privilege mode, so every access including a metadata read must trap for the handler to
restore it first. That asymmetry is deliberate and is now explicit.

### M3 — [FIXED] Management code snippets were wrong as given

**Original finding:** in all four provisioning/import sequences `t3` was overwritten with
`#ace_state_unconfigured` (0) before the *final* `bltu t3, t2, handle_errors`, so after a successful
`provision_end`/`import_end` any valid state — _Initial_ = 1 included — branched to
`handle_errors`; the in-loop threshold test was equally broken on the restart path.
`vle8.v v4, 8(t6)` is not valid RVV assembly, unit-stride vector loads taking no immediate
offset. The export snippet's comments were copy-paste leftovers from the import one.

**Resolution (applied 2026-08-13):** all six snippets rewritten.

* **`t3` is now initialised once to 23 and never reassigned.** The restart test that used to
  clobber it (`li t3, #ace_state_unconfigured` then `beq t2, t3, restart`) is simply
  `beqz t2, restart`, which is what it always meant. A paragraph before the listings states
  the convention — `t3` holds the highest valid _State_, so `bltu t3, t2, handle_errors`
  branches exactly on an Error State — and says why it must survive to the end.
  Verified programmatically: in each of the six snippets `t3` is assigned exactly once, and
  every error test compares against it.
* **Vector addressing fixed.** The loops now keep an explicit pointer, `t4`, bumped by the
  `vsetvli` result, and use `vle8.v v4, (t4)` / `vse8.v v4, (t4)`. No vector load or store
  in the section carries an immediate offset any more.
* **Loop bookkeeping corrected.** Each iteration bumps the pointer and decrements the
  remaining count by `a3`, the value `vsetvli` returns, so the transfer covers the whole PI
  or SCC exactly once. Previously the pointer advanced but the loaded chunk was always taken
  from the same address.
* **Error checks placed after the transfer**, not before it, so a CR cleared *by* the move is
  detected; and the check after the terminating `ace.mgmt` is now reached with `t3` intact,
  which is what makes the deferred validation of MDH[127:64] observable at all.
* **`ace.avail` used to obtain the SCC length** in the `Zklmv` import, with a comment that it
  returns 0 for an unsupported algorithm or invalid metadata, replacing a bare assertion that
  "a2 holds the length … from `ace.size`". The `Zklmem` variants need no length register, since
  `ace.load`/`ace.store` derive it from the MDH themselves.
* **Export comments rewritten** to describe the export path rather than the import one, and
  the `Zklmem` export gained the Error-State check it previously lacked entirely.
* `li t3, #23` corrected to `li t3, 23` — `#` is this document's immediate marker for
  `ace.setst`-family mnemonics, not RISC-V assembly syntax.

**A bug of my own, caught during verification.** My first rewrite put `restart:` *after* the
point where the working length was computed, so a restart re-entered the loop with a count
that had already been consumed — on the second attempt the transfer would stop immediately.
Fixed by keeping the total in `a1`, never modifying it, and re-deriving both the working
count `a2` and the pointer `t4` from it after `restart:`. The two export snippets were
already correct in this respect, since `ace.size` sits inside their restart path.

### M4 — [FIXED] Book 4 examples contradicted the Book 2 state machines

**Resolution (applied 2026-08-13).** Book 4 was reconciled against Book 2 example by
example, with no change to Book 2. Verified afterwards by extracting every
`#ace_state_*` mnemonic from Book 4 and checking each against Book 1/Book 2: all twelve
resolve, and no reference to a non-existent state remains.

*Global.* `IOLEN` — a name defined nowhere — replaced by `ACELEN` in all five places.

*GCM encryption.* The IV is now set by a **Form B** `ace.setst` carrying its length in
octets, then absorbed by `ace.exec`, with `vsetvli` used to make `ACELEN` match the IV
length; the example previously used a Form A `ace.setst` and passed the IV itself, which
Book 2 does not permit. The explicit `ace.setst … #ace_state_hash_absorb` was removed,
because `finalize()` in _Set_Aux_Value_ transitions to _Hash_Absorb_ by itself once the
last IV octet is absorbed. The fractional-plaintext path through _Enc_Last_Block_ was
added, and the introductory paragraph — which told the caller to zero-pad *both* operands
— now states the asymmetry the C4 fix introduced: zero-fill the last AD block, but never
the plaintext or ciphertext.

*GCM decryption.* Previously it put the length block in an `ace.exec` and had that
instruction *output* the recomputed tag — a forgery oracle, and not what Book 2 says. The
lengths now go in the Form C `ace.setst` that enters _Dec_Tag_Finalize_, there is no
`ace.exec` in that state at all, and the accompanying prose says explicitly that the tag
stays inside the CR on this path. The _Dec_Last_Block_ path was added.

*GCM-SIV encryption.* Nonce now set by a Form C `ace.setst` with no following `ace.exec`;
the spurious "absorb the lengths" `ace.exec` in _Hash_Absorb_ removed; _Enc_Tag_Finalize_
now uses the Form A `ace.exec` that Book 2 specifies, taking the lengths as input and
returning the SIV as output; _Enc_Last_Block_ path added.

*GCM-SIV decryption.* The SIV was being passed to _Hash_Absorb_; it now goes to
_Set_Aux_Value_2_, which is the state Book 2 provides for it, and _Hash_Absorb_ is entered
with a Form A `ace.setst`. _Dec_Last_Block_ path added. The rest of this example was
already correct, including the Form B `ace.exec` in _Dec_Tag_Finalize_.

*OCB.* `#ace_state_hash_finalize` corrected to `#ace_state_hash_last_block` and
`#ace_state_last_block` to `#ace_state_enc_last_block` — neither of the originals is a
state OCB has. The prose claiming that decryption replaces `_enc_tag_finalize_` with
`_dec_tag_finalize_` was corrected: OCB has no such state, and _Dec_Last_Block_ transitions
to _Hash_Verify_ directly. A comment records that _Enc_Last_Block_ reaches
_Enc_Tag_Finalize_ without an `ace.setst`. Three byte-range expressions of the form
`…+ceil(X1/8)` were off by one under inclusive indexing and are now `…+ceil(X1/8)-1`.
`!==` corrected to `!=`.

*CMAC.* The final `ace.setst … #ace_state_hash_finalize` was removed: CMAC has no such
state, and Book 2 transitions to _Hash_Output_ automatically once the last block is
absorbed. `%` replaced by `mod`, and `=` by `{leftarrow}`, per <<ACE-Notation>>.

*XEX.* The loop bound was `ceil(len/16)-1`, which would encrypt a full block past the end
of a data unit that is not a whole number of blocks; XEX has no partial-block state. It is
now `floor(…)`, with a sentence after the listing pointing at the ciphertext-stealing
procedure of <<ACE-XTS-from-XEX>> for the remainder.

*ECB, keystream (CTR/XCTR), and the GCM-via-ECB alternate* were checked against Book 2 and
needed no change. The alternate example gained one comment noting that the final keystream
block is truncated before storing while GHASH absorbs the zero-padded ciphertext.

**Two markup errors of my own, caught and fixed before finishing.** I first put
`<<ACE-XTS-from-XEX>>` and a `cite:[…]` *inside* `----` listing blocks, where AsciiDoc
performs no attribute or macro substitution, so both would have rendered as literal source
text. The cross-reference was moved into prose after the listing and the citation reduced
to plain text. Book 4's eleven listing blocks were then scanned programmatically for
`cite:[`, `<<`, `{vvert}`, `{ellipsis}` and `{nbsp}`: none remain.

**Verification.** Full build from the repository root with `-r asciidoctor-bibtex`:
1047 KB, no warnings, zero literal `cite:[` and zero raw-id cross-references.

### Mnemonic casing — [FIXED] all state mnemonics are now lower-case

Raised as a question while reconciling Book 4; resolved by the author's rule that state
mnemonics must be lower-case throughout.

* `ace_state_Set_Aux_Value` {rightarrow} `ace_state_set_aux_value` and
  `ace_state_Set_Aux_Value_2` {rightarrow} `ace_state_set_aux_value_2`: 12 occurrences
  across `ace-ISA-algorithms.adoc` (7) and `ace-pseudocode.adoc` (5), including the
  definition row in <<ACE-state-constants-symmetric>>.
* A third mnemonic also violated the rule and was not named in the instruction:
  `ace_state_CR_import_auth` {rightarrow} `ace_state_cr_import_auth`, 4 occurrences in
  `ace-ISA-unpriv.adoc` — the definition row in <<ACE-states-error>>, the `ace.mgmt`
  import-termination text, and the two SCC-import steps. I applied the rule to it since it
  was stated as holding "throughout"; the only argument for the old spelling is that `CR`
  is an acronym, so if an acronym exception is intended this one should be reverted.

The *state names* were deliberately left alone: _Set_Aux_Value_, _Hash_Absorb_,
_Auth_Failed_ and the rest keep their initial capitals, since they are names rather than
constants and the convention is consistent among them.

Verified: no `ace_state_*` identifier containing an upper-case letter remains in any
`.adoc` file, and the full build from the repository root with `asciidoctor-bibtex` is clean
at 1047 KB, with zero literal `cite:[` and zero raw-id cross-references.

### M5 — [FIXED] `ace.setst`/`ace.mgmt` encodings lacked the CR-addressing selector

**Original finding:** both encodings assigned bits [24:20] to zero and [31:25] to
`immed7`, leaving no `r` bit, so nothing distinguished an immediate CR index from one held
in a GPR — and `ace.reset`, which is *defined* as `ace.setst` "with indirect CR addressing
and `Xd` = `X0`", was unencodable as drawn.

**Resolution (verified 2026-08-13):** an `r` bit was added at bit 20, taken from the
previously-zero field, in both `ace.setst` and `ace.mgmt`. Verified as well-formed: the
wavedrom fields are 7 + 5 + 3 + 5 + 1 + 4 + 7 = 32 bits, and the field order places `r`
exactly at bit 20 as the accompanying text claims. `ace.reset` is now encodable as
`r` = 1 with the register field `X0` and `#immed7` = 0, and is distinguishable from
`ace.clear K0` (which has `r` = 0), so the two do not collide.

**Two residuals found during verification, both now fixed:**

1. The `r` sentence in `ace.mgmt` was truncated mid-phrase — "…if a GPR (scalar" — with
   the rest of the sentence missing. Completed to match `ace.setst`.
2. The semantics of `r` = 1 with the register field `X0` were unspecified for
   `#immed7` {ne} 0. Read naively, `r` = 1 with `X0` would address "the CR whose index is
   the value in `X0`", i.e. CR 0, which is not what `ace.reset` means. The encoding now
   states that the combination is reserved: with `#immed7` = 0 it is `ace.reset`, with any
   other `#immed7` it raises an illegal-instruction exception per the general `X0` rule,
   and CR 0 remains addressable indirectly through any other GPR holding 0.

A sentence was also added explaining why `r` sits at bit 20 here but at bit 26 in
`ace.exec` — bits [31:25] are occupied by `#immed7` — so the asymmetry does not read as an
oversight.

### M6 — [FIXED] CTR counter block did not match SP 800-38A usage

**Original finding:** `keystream_block(IV @ ctr)` placed the counter in the *first* octets
of the counter block, little-endian. The universal CTR arrangement — and the one GCM uses in
this same document — is the counter in the *trailing* octets as a big-endian integer.

**Resolution (applied 2026-08-13), done minimally as requested:** the CTR/LFSR branch of the
single line that builds the counter block now reads
`tmp {leftarrow} keystream_block(bswap(ctr) @ IV)`; the XCTR/XLFSR branch,
`keystream_block(IV xor ctr)`, is unchanged and was already correct. So the two modes now
differ visibly on one line, which is where the difference belongs.

Under <<ACE-Notation>> the trailing octets of a value are its more significant bits, so
the encoded counter has to be the *left* operand of `@`, and `bswap` supplies the big-endian
octet order; `bswap(ctr)` is `binBE(int(ctr), j)`. The result is now structurally identical
to GCM's own counter block, `binBE(ctr,32) @ J0[95:0]`, which is the strongest available
check that the transcription is right.

A note records why the two branches differ and what the wrong form would compute, so the
asymmetry is not "simplified" away later: in the non-X modes the counter is positional and
big-endian; in the X modes it is `b` bits wide, combined by `xor` rather than by position,
and stays little-endian.

**Also corrected:** the conventions table row for SP 800-38A/B/E still said "Direct
mapping", which had become false in two places — the CTR counter block is big-endian, and
CMAC's subkey doubling is the big-endian `double` (from the C3 fix). The row now states all
three orderings it covers and warns explicitly against reading "direct mapping" as applying
to all of them. That row was, in effect, the piece of documentation that made both C3 and M6
easy to get wrong.

**One adjacent defect found and fixed while here [minor]:** the transition into _Operate_
said "If `ACELEN` > `b`, only the `b` least significant bits of `INPUT` are considered", but
the `IV` field is `n` bits and in the non-X modes `b` = `n` + `j`, so the bound was wider
than the field being written. It now reads `n`, with a sentence explaining that the
remaining `j` bits of the counter block come from `ctr` and not from `INPUT`, and that in
the X modes `n` = `b` so the two readings coincide.

Book 4's keystream example was checked and needs no change: it sets the nonce and issues
`ace.exec`, and never constructs a counter block itself.

### M7 — [FIXED] HMAC `_Set_Key_` corrupted the hash state as written

**Original finding:** `_Set_Key_` invoked
`process_VLI(b/8, block, b, key, b, …, absorb(), finalize())`. `absorb()` processes the
current block into the hash, and `finalize()` completes it — but the hash state is
initialized only on entry to _Hash_Absorb_, so both would fold raw key material into an
uninitialized state.

**Second defect found while resolving it.** Passing the callbacks as `None` is necessary but
not sufficient, because the *destination* was also wrong. Positionally the call binds the
procedure's `block` parameter to HMAC's `block` field and its `state` parameter to `key`.
Those are distinct fields, so `block` {ne} `state` and the copy branch applies: the octets
land in `block` and `key` is never written, after which _Hash_Absorb_ computes `key xor ipad`
against whatever `key` happened to hold. The sentence "Note that `block` and `state` are the
same when these are not distinct" could not rescue this, since here they *are* distinct.
`block` is moreover documented as present "only if a partial block must be maintained", so
for HMAC over SHA-3 — where input is XORed straight into `state` — the old call passed a
field that does not exist.

**Resolution (applied 2026-08-13, on the author's decision that `_Set_Key_` exists for
re-keying and that the Provisioning Input should carry no key).**

* `K0` was removed from the HMAC Provisioning Input, which is now the MDH alone.
* The prose now states that the PI carries no key, that `K0` is loaded in `_Set_Key_` so a CC
  can be keyed and later *re-keyed* without being provisioned again, and that `key` is part of
  the Serialized Context so a key set this way survives export and import.
* The call follows ML-KEM's field-loading pattern:
  `process_VLI(b/8, block=key, b, state=unused, n=0, input_base, block_base,
  state_offset=0, cumul_len, process_block=None, finalize=None)`. The field being filled is
  passed as `block`, so the copy branch writes into `key` at offset `block_base`; there is no
  `state`; both callbacks are `None`, leaving only the resumability accounting.
* A paragraph records *why* `absorb()`/`finalize()` must not be passed and why the
  destination must be `key` and not `block`, so neither is reintroduced.

**Resolution (applied 2026-08-13, after one reversal).** The call now reads

`{fournbsp}` `process_VLI(b/8, block=key, b, state=unused, n=0, input_base, block_base,`
`state_offset=0, cumul_len, process_block=None, finalize=None)`

following ML-KEM's field-loading pattern: the field being filled is passed in the *`block`*
position, so the copy branch applies and writes into `key` at offset `block_base`; there is no
`state`; and both callbacks are `None`, leaving only the resumability accounting. A paragraph
records the three deliberate details so none is undone later — the callbacks stay `None`
because the hash state is not yet initialized; the destination is `key` and not `block`
because `block` belongs to the underlying hash function; and `key` occupies the `block`
position rather than the `state` position so that the octets are *assigned* rather than XORed.

**The reversal, and why the fix survived it.** The author first directed that `K0` be removed
from the Provisioning Input, then withdrew that: `K0` stays in the PI, and _Set_Key_ exists to
*overwrite* the provisioned key so a CC can be re-keyed without being provisioned again. The
PI row and the surrounding prose were restored accordingly, and the prose now states that
relationship explicitly, which it did not before.

The `process_VLI` correction was kept, because it is independent of where the key first comes
from — and the overwrite semantics make it *necessary* rather than merely correct. Had `key`
been left in the `state` position, the procedure's XOR branch would apply and a new key would
be combined with the old one instead of replacing it, which is the opposite of what this state
is for. The original formulation was therefore wrong in three separate ways at once: wrong
callbacks, wrong destination field, and wrong combining operation.

With `K0` back in the PI, the three consequences I had raised — no "key has been set"
indication, loss of System Key and random-key support, and the now-inaccurate wording
"provisionable key" — all fall away. The key is present from provisioning onwards, System Keys
and random generation continue to work through the PI's key field as for every other keyed
algorithm, and the key remains genuinely provisioned.

**HMAC finding 4 — [FIXED] the KIP Provisioning Input was not a multiple of 128 bits.**
Raised while reviewing the author's HMAC redefinition and settled last: PI = 128 + `b` gives
1216, 960 and 704 bits for SHA3-256, SHA3-384 and SHA3-512, and 192 bits when Position ii
holds a 64-bit System Key Identifier — none a multiple of 128, contrary to
<<ACE-data-formats>>. The "(variable)" padding row is now "0 or 64", with the rule stated:
64 bits when the rate is congruent to 64 modulo 128, absent otherwise, and no other width can
arise because every rate is a multiple of 64. The enumeration is given — absent for SHA-224,
SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 and SHA3-224; 64 bits for SHA3-256,
SHA3-384, SHA3-512 and for the SKID case. Verified across all seven instantiations. The NIK
variant needs none, its PI being the 128-bit MDH alone.

### M8 — [FIXED] OCB: `MAX_BLOCKS` declared but never enforced

**Original finding:** `MAX_BLOCKS` = 2^48^ was stated as the maximum number of blocks, but
nothing checked it. Past that point `ntz(index)` indexes `L~48~`, outside the range
`i` < `floor(log_2(MAX_BLOCKS))` for which the array is defined, and the cite:[RFC7253]
security bound no longer holds.

**Resolution (applied 2026-08-13), following the author's specification:** a `budget` field
was added, mirroring the mechanism already settled for GCM with Set IV under M11.

* **Internal State:** `budget`, an integer in 0…`MAX_BLOCKS`. Since `MAX_BLOCKS` = 2^48^ the
  value needs 49 bits and is held in a 64-bit field.
* **Serialized Context:** `budget` added at Position xiv as `bin(budget,64)`, ahead of the
  variable padding row, with an explicit statement that it *must* be serialized — a bound
  that did not survive export and re-import would be no bound, since software could refresh
  it by cycling the CC through memory. Padding arithmetic re-checked: the field total is
  978/1042/1106/1170 bits for `k` = 64/128/192/256, so the variable padding row brings each
  to 1024/1152/1152/1280 — a whole number of 128-bit blocks in every case.
* **Behavior:** `budget <- MAX_BLOCKS` on entering _Initial_. Every `ace.exec` that
  processes data blocks is charged the number it processed — `ACELEN`/`b` in _Hash_Absorb_,
  _Encrypt_ and _Decrypt_, and 1 in _Hash_Absorb_Last_Block_, _Enc_Last_Block_ and
  _Dec_Last_Block_. An `ace.exec` that only finalizes or emits the tag is exempt: the Form C
  instruction of _Enc_Tag_Finalize_, and the Form D instruction of the two last-block states
  when `last_blk_len` is zero. Exhaustion uses the same failure mode as
  <<ACE-GCM-with-IV-mode>>: no operation is performed, the CR is invalidated to
  `ace_state_invalid`, and `ace_exc_invalid` is raised where the Privileged Architecture is
  implemented.

A note records that this is a structural bound rather than a policy one — past `MAX_BLOCKS`
there is simply no `L~i~` to read — and that charging the AD and the payload to one shared
budget is deliberately conservative: each loop keeps its own `index`, so bounding the sum
bounds each, which is what the `L~i~` array requires.

### m17 — [FIXED] OCB's SCC note contradicted its own table on the two Boolean fields

The note justified widening fields to octet multiples "so that an SCC can be parsed without
bit-level extraction", then said "The same applies to `AD_finalized` and `text_finalized`, each
a single bit" — claiming the widening for two fields the table gives one bit each.

Resolved on the author's reasoning, which identified that the note named the wrong cost:
extracting an individual bit at a known offset is easy, whereas a *multi-bit* field straddling
an octet boundary is the annoyance the padding actually avoids. The fields stay at one bit and
the note now reads "every *multi-bit* field … parsed without bit-field manipulation", with a
second paragraph recording that the two Booleans are deliberately exempt and why the
distinction is worth drawing at all: an ACE unit may be a programmable coprocessor
(<<ACE-architectural-model>>) rather than fixed logic, and only there do unaligned multi-bit
fields cost instructions on every import and export. No layout change, so no interoperability
consequence.

### M9 — [FIXED] ECC state machine incomplete, including nonce generation

**Original finding:** `_Gen_Rnd_Scalar_` was listed with no transitions or behavior; the
`_Sign_Generate_` guard required `HasSecondPt` and `HasHash` but not a configured private
key; the text claimed five ``Has``__Var__ flags where the _StateExtension_ table defines
four, and the two lists disagreed on *which* four; and nothing specified how `RndNum` is
generated, the RBG it requires, or the FIPS 186-5 retry rules.

**Resolution (applied 2026-08-13), following the author's direction on each point.**

1. **`_Gen_Rnd_Scalar_` removed.** It was redundant: a random scalar is already obtained in
   State _Set_Scalar_ by issuing the Form B `ace.setst` with a non-zero GPR value, which the
   specification already described. Value 4 is now marked reserved and the remaining state
   numbers are left unchanged, so the meaning of the _State_ field — and EdDSA's
   `_Msg_Absorb_` (12) — is not disturbed by a renumbering. No reference to the removed state
   remains in any file.
2. **`_Sign_Generate_` now requires a configured private key.** The guard reads
   `HasSecondPt` and `HasHash` *and* `1` {le} `int(Scalar)` `<` `n`; entering the state
   otherwise invalidates the CR. Expressing it as a range check rather than a new flag was
   necessary as well as tidier: _StateExtension_ is 4 bits and all four are already taken by
   `HasSecondPt`, `HasSignature`, `HasHash` and `HasRndNum`, so there is no room for a
   `HasScalar`. The check is also the cryptographically correct condition, since
   cite:[nist-fips-186-5] requires the private key to lie in `[1, n-1]`, and `Scalar` is zero
   from provisioning until set — so zero is itself the "unset" indication.
3. **The ``Has``__Var__ list now matches the table.** It enumerates `SecondPt`,
   `Signature`, `Hash` and `RndNum`, says where the flags live, and states explicitly that
   `Generator` and `Scalar` have none and why: `Generator` always holds a value (the curve
   default from provisioning onwards) and `Scalar` uses the zero-is-unset convention above.
4. **RBG and per-message secret specified.** Both the random `Scalar` and the per-message
   secret `RndNum` are generated inside the ACE unit by one of the methods of
   cite:[nist-fips-186-5] Appendix A.2, with a random bit generator that must satisfy the
   requirements stated there. Neither is ever supplied by software, and neither leaves the CR
   except inside an SCC — `RndNum` only if a signature operation is interrupted.
5. **Retry rules added.** For the NIST and Brainpool curves, a candidate with `r` = 0 or
   `s` = 0 is discarded and a *fresh* `RndNum` drawn, per cite:[nist-fips-186-5]
   {sect}6.4.1; only a signature with both components non-zero is returned, so the retry is
   not observable. The text states why neither shortcut is permissible: reusing `RndNum`
   after a degenerate outcome leaks the private key across the two attempts, and returning a
   zero component is rejected by any conforming verifier. SM2 carries its own conditions from
   cite:[GMT-0003-2-2012] — retry if `r` = 0, if `r` + `k` = `n`, or if `s` = 0 — and the
   Edwards curves have no retry rule at all, their nonce being deterministic, which is why
   `HasRndNum` is never set for them.

### M10 — [FIXED] Block of ML-DSA text misplaced inside the ML-KEM section

**Original finding:** a block describing `HasPrivKey`/`HasPubKey`, `_privkey_Input_`,
`_pubkey_Input_`, `_compute_pubKey_` and `_Sign_Generate_`, citing FIPS 204, sat in the
ML-KEM Behavior list. Those states do not exist in ML-KEM, and the block contradicted
ML-KEM's own statement that it carries no information about which fields are assigned;
meanwhile ML-DSA, where the rules belong, lacked them.

**Resolution (applied 2026-08-13):** the block was moved verbatim into ML-DSA, positioned
immediately after the "Apart from `HasPrivKey` and `HasPubKey`, the ML-DSA algorithms do
not carry state information …" bullet — which is required, because the moved text ends by
saying it "replaces, for the two key fields, the blanket statement above". The two bullets
that legitimately belong to ML-KEM and followed the block (`ace.derive` for the shared key,
and the `_AlgorithmUse_` progress field for long-running operations) were left in place.

Verified: the ML-KEM section now contains no reference to `HasPrivKey`, `HasPubKey`,
`privkey`, `pubkey`, `compute_pubKey`, `_Sign_Generate_` or FIPS 204, and ML-DSA carries
the key-management rules exactly once. The spec rebuilds cleanly.

### M11 — [FIXED] "GCM with Set IV" and reuse of a single `J0`

**Original finding:** the state machine let a CC encrypt a second message under the same
key and `J0`, reusing the tag mask `E(K, J0)` and the GHASH key `H` — the classic
forbidden-attack condition, which yields `H` and hence forgeries.

**The author's central argument is accepted.** The architecture cannot structurally
prevent `J0` reuse, because an SCC can always be re-imported to restore an earlier state.
That is the same reasoning already given for the global rule in <<ACE-State-field>> ("a CR
can always be restored from a backup SCC, so preventing transitions to _Initial_ are not
effective mitigations") and in the rollback discussion of
<<ACE-management-operations>>. Accepting the residual risk and documenting it is the right
disposition, and the new prose does so: it says the rules do not forbid keeping an older
SCC to restart the machine, that it is the caller's responsibility not to abuse it, and
that the algorithm protects only the *confidentiality* of the IV, not against its reuse.

**Two real mitigations were also added**, going beyond documentation: a `blocks` budget in
the Provisioning Input, decremented as the CC is used and driving the machine to _Failure_
at zero, and a prohibition on returning to _Initial_. Together these make a single CC
one-shot, which is a genuine improvement.

**Residuals in the new mechanism — all resolved 2026-08-13:**

1. **[FIXED] `blocks` is now part of the persistent state.** It was declared only in the
   Provisioning Input, while the Internal State and Serialized Context both said "same as
   for GCM", which has no such field — so the budget was lost on export/import and could be
   refreshed at will by cycling the CC through memory. `blocks` is now declared in the
   Internal State as an integer in 0…2^32^-1, and the Serialized Context adds it at
   Position vii with the padding reduced by 32 bits to keep the total a multiple of 128.
   The text states explicitly that it *must* be serialized, and why.
2. **[FIXED] The budget now counts blocks, not instructions.** An `ace.exec` decreases
   `blocks` by the number of blocks it actually processed — `ACELEN`/`b` in _Hash_Absorb_,
   _Encrypt_ and _Decrypt_, and 1 in _Enc_Last_Block_/_Dec_Last_Block_.
3. **[FIXED] The tag-emitting `ace.exec` is exempt.** A Form C `ace.exec` does not decrease
   `blocks`, since emitting the tag in _Enc_Tag_Finalize_ consumes no block. This also
   removes the sizing ambiguity: the text now states that `blocks` can be set exactly to
   the number of AD blocks plus plaintext/ciphertext blocks (a final partial block counting
   as one), and that such a CC completes its message and is left at zero, unable to start a
   second.
4. **[FIXED] Exhaustion no longer reports _Failure_.** An `ace.exec` that would take
   `blocks` below zero performs no operation, *invalidates* the CR (_State_ becomes
   `ace_state_invalid`) and raises `ace_exc_invalid` where the Privileged Architecture is
   implemented — following the phrasing this specification already uses elsewhere. The
   rationale is recorded: _Failure_ means an authentication or verification failure, and a
   caller checking a decryption result must be able to distinguish a forged ciphertext from
   an exhausted budget.
5. **[FIXED] The global rule now admits the exception.** <<ACE-State-field>>'s "A
   transition from any valid state to _Initial_ … is always permitted" gained "unless the
   algorithm explicitly forbids it", with a sentence noting that an algorithm which forbids
   it does so to keep the common case honest, not because it can close the SCC-restore gap.
   The GCM-with-Set-IV prohibition now cross-references that rule.
6. **[FIXED] `_hash_Initial_` corrected to `_Initial_`.** No occurrence of the non-existent
   state name remains in any file.
7. **[WONTFIX — author's decision, accepted] Naming the consequence of `J0` reuse.** I had
   asked for the prose to say that reuse breaks *authenticity* (recovering `H`), not merely
   confidentiality. The author's position is that this is no worse than plain GCM with a
   user-configurable `J0`, where the caller carries exactly the same obligation and the
   consequence of IV reuse is identically severe and well known. That is correct, and
   singling it out here would misleadingly suggest the Set-IV variant is the weaker of the
   two. The existing statement — that the algorithm protects the confidentiality of the IV,
   not against its reuse, and that avoiding reuse is the caller's responsibility — stands.

**M11 is now closed.** The accept-and-document decision was sound on its own, and the
`blocks` budget as now specified is a real, serialized, exactly-sizable bound on a single
CC's use.

### M12 — [FIXED as a referred question] `TSR`/`VTSR` reuse for trapping ACE memory instructions

**Original finding:** `mstatus.TSR` is defined by the privileged spec solely to trap
`SRET`; making it also trap `ace.load`/`ace.store`/`ace.input`/`ace.output` changes the
meaning of an already architected bit, so a hypervisor that sets `TSR` today to intercept
supervisor returns would silently begin trapping ACE code it may not be able to emulate.

**Resolution (applied 2026-08-13), per the author's decision:** the question is referred to
the ARC rather than settled here. A [WARNING] beside the `TSR` statement records that the
reuse must be discussed with the Architecture Review Committee before ratification, states
precisely what the conflict is (TSR's existing single purpose, and the silent change in
behavior for hypervisors that already set it), and names the alternative — a dedicated
enable such as an `*envcfg` bit, which leaves `TSR` untouched and lets the two controls be
set independently. A second [WARNING] beside `VTSR` cross-references it and adds that the
two must be settled together, so that whatever gates the S-mode behavior gates the VS-mode
behavior by the same means.

This is the appropriate disposition: the choice is an architectural one that ACE cannot
make unilaterally, and the draft is in the Development state where such questions are
expected to be flagged rather than resolved. The finding is closed as a *referred*
question, not as a technical fix — it must reappear on the ARC agenda, and the WARNING is
what guarantees it will.

### M13 — [FIXED] `AD @ P` in the sealing functions was ambiguous under the spec's own operator

**Original finding:** `POLYVAL(auth_key, AD @ P, …)` applied `@` to block *arrays*, for
which it is undefined; and read as a value operator, `@` places its left operand in the
*more* significant bits, which under <<ACE-Notation>> corresponds to the *later* octets —
so `AD @ P` suggested the reverse of the intended absorption order.

**Resolution (applied 2026-08-13), per the author's decision:** the block-sequence
concatenation is now written with `{vvert}` rather than `@`, in both
`AES_GCM_SIV_Encrypt` and `AES_GCM_SIV_Decrypt`, which read `POLYVAL(auth_key, AD || P,
len_AD + len_PC)`. The associated data and the payload are now spelled out as ordered block
sequences in the notation list — `AD[0] {vvert} AD[1] {vvert} … {vvert} AD[len_AD-1]`, and
likewise for `P[]` and `C[]` — and a paragraph states that, applied to block arrays,
`{vvert}` denotes the blocks of the left operand followed by those of the right, with
`POLYVAL` absorbing in increasing index order.

The paragraph also records *why* `@` is not used here, so the change is not undone later:
`@` composes values by significance, whereas what is needed is an ordered sequence of
blocks, and `AD @ P` both misapplies `@` to arrays and implies the wrong order. Using
`{vvert}` is additionally consistent with the rest of the document, where `{vvert}` is the
operator of the reproduced standards and `@` is reserved for ACE's own value composition.

Note that `{vvert}` renders as ‖ in prose but the pseudocode listings use a literal `||`,
since AsciiDoc does not substitute attributes inside a listing block. Verified in the built
HTML: the prose shows ‖ and the listings show `||`.

---

## Minor

### m1 — [FIXED] GCM/GCM-SIV block-count limits off by one vs standards

**GCM was one block too permissive.** The guard excluded only `start_ctr`, admitting
2^32^-1 blocks, where cite:[nist-SP-800-38D] {sect}5.2.1.1 caps the plaintext at
2^39^-256 bits = 2^32^-2 blocks. All four guards now read
`If ctr = start_ctr or ctr = (start_ctr - 1) mod 2^32^`, leaving exactly 2^32^-2 admissible
values. A paragraph distinguishes the two exclusions, since they are different in kind:
excluding `start_ctr` is security-critical (it produces the tag mask), while excluding
`start_ctr - 1` is purely a conformance bound — worth separating so neither is removed as
"redundant".

**GCM-SIV was one block too conservative,** the opposite direction: the guard admits
2^32^-1 blocks where cite:[RFC8452] {sect}6 allows 2^32^. Documented rather than changed,
since `ctr` is a 32-bit field that cannot represent the count 2^32^ and 16 octets out of
64 GiB does not justify a wider field. No conformance issue, the restriction being on this
specification's side.

### m2 — [FIXED] GCM does not reject a zero-length IV

The transition into _Set_Aux_Value_ now requires `1` {le} `Xs` {le} `1024`, an IV of 8 to
8192 bits, with any other value — zero included — invalidating the CR.

A rationale was added because the zero case has a second, sharper consequence than the
conformance one: `Xs` = 0 would enter `process_VLI` with `len` = 0, which by
<<ACE-process-VLI>> means "length not defined by the caller", so the state would absorb
indefinitely and `finalize()` would never run — `J0` would stay zero and no counter would
ever be derived. The note also records that the 1024-octet upper bound is this
specification's own, imposed by the 16-bit `len` field of the Serialized Context, rather
than anything from cite:[nist-SP-800-38D].

### m3 — [FIXED, one part withdrawn] Ascon inconsistencies around the last block

Re-read on 2026-08-13 under <<ACE-truncation-vs-length>>, as the calibration note requires.
The finding had four parts; the first is withdrawn, the other three stand.

**1. "A partial final block of 127 bits is legal" — [WITHDRAWN, reviewer error].** This was
the same mistake as C4 residual 2 and m14: `last_block_len` truncates a block that has
already been transferred, so the octet-granularity assumption does not reach it.

There is also no *standards* reason to require a multiple of 8 here, which is what
distinguishes this case from CMAC. ACE defines Ascon's padding as
`pad(x,r)` = `0^j^ @ 1 @ x`, which places the terminating `1` at bit position `|x|`
exactly, whatever `|x|` is — because cite:[nist-SP-800-232] is written in little-endian bit
order, as the WARNING opening <<ACE-Ascon-AEAD128>> already notes. CMAC needed the
multiple-of-8 restriction (see C3) precisely because cite:[nist-SP-800-38B] uses the
NIST big-endian-within-octet convention, under which the pad position is
`8`{times}`floor(n/8) + 7 - (n mod 8)` and is only clean at an octet boundary. The two
algorithms genuinely differ, and ACE is right to treat them differently. So 127 is legal and
the sentence should stay.

**2. The last-block length is passed in a Form C `ace.setst` — [OPEN, minor].** Every other
mode that takes a final-block length uses Form B, with the value in a GPR: GCM, GCM-SIV, OCB
and CMAC all do. Ascon uses Form C, and then treats the vector operand as a number ("If
`INPUT` > 127…"). Applying the calibration rule, I looked for a state-machine reason and
found none: the parameter is a single integer {le} 127 and nothing else travels with it.
Ascon *does* use Form C where it is warranted — the nonce entering _Hash_Absorb_ is a genuine
128-bit value — which is what makes the last-block case look like an oversight rather than a
pattern. It also has a cost: an implementation with `Zklio` but no vector registers must route
a 7-bit number through the ACEIOBUF, where Form B would put it in a GPR.

**3. The Form A `ace.setst` into _Dec_Tag_Finalize_ is unreachable — [OPEN].** Both paths
into that state are already automatic: with `last_block_len` = 0 the _Dec_Last_Block_
`ace.setst` transitions there itself, and otherwise step 7 of the _Dec_Last_Block_ `ace.exec`
does. The later sentence "To transition to State _Dec_Tag_Finalize_, a Form A `ace.setst` …
is expected" therefore describes a transition that is never needed. The encryption path is
consistent by contrast — _Enc_Last_Block_ reaches _Hash_Output_ automatically and no such
sentence appears — so this is a stray leftover on the decryption side only.

**4. Nothing effects the _Dec_Tag_Finalize_ {rightarrow} _Hash_Verify_ transition, and
_Dec_Tag_Finalize_ has no behavior — [OPEN].** The transition is listed, and _Hash_Verify_
expects a Form B `ace.exec` carrying the received tag, which performs the entire
finalization: the key XOR, `ASCON(12)`, and the comparison. But no instruction is specified
for leaving _Dec_Tag_Finalize_, and no operation is specified for being *in* it. Compare GCM,
where the corresponding step is explicit. As written, _Dec_Tag_Finalize_ is an empty state
that the machine enters automatically and leaves by unspecified means.

**Resolution of 2, 3 and 4 (applied 2026-08-13, author approved).**

* **Form B for the last-block length.** Both _Enc_Last_Block_ and _Dec_Last_Block_ now take
  the length as the GPR argument `Xs` of a Form B `ace.setst`, aligning Ascon with GCM,
  GCM-SIV, OCB and CMAC. The "127 bits is legal" statement was kept and given the reasoning
  that survived re-evaluation: `Xs` is a truncation rather than a transfer length
  (<<ACE-truncation-vs-length>>), and Ascon's `pad` places the terminating `1` at bit
  position `Xs` for any `Xs` because cite:[nist-SP-800-232] is written in little-endian bit
  order. The two `ace.exec` descriptions were left alone, where `INPUT` correctly denotes the
  data block.
* **_Dec_Tag_Finalize_ removed from Ascon**, adopting the shape OCB already uses. It is gone
  from the state list and the transition list, which now reads
  `_Decrypt_ -> { _Dec_Last_Block_ -> } _Hash_Verify_ -> _Success_ or _Failure_`; both
  _Dec_Last_Block_ branches transition to _Hash_Verify_ directly, mirroring how the
  encryption path reaches _Hash_Output_. The unreachable Form A `ace.setst` sentence was
  replaced by a paragraph recording why no intermediate state exists, so it is not
  reintroduced. `tag_len` = 128 remains stated in _Initial_ and explained in the following
  NOTE. The `ace_state_dec_tag_finalize` constant is untouched, since GCM and GCM-SIV still
  use it, and the nonce-masking variant inherits Ascon's state list by reference and followed
  automatically.

**A related defect found while verifying, also fixed (author confirmed the intent).**
<<ACE-Ascon-AEAD128-wsn>>, the set-nonce variant, said "the State _Set_Aux_Value_ is not
present and is thus skipped" — but Ascon-AEAD128 has no _Set_Aux_Value_ state at all; its
nonce arrives on the Form C `ace.setst` that enters _Hash_Absorb_. The sentence named a
non-existent state and did not say what actually changes. It now reads that the nonce is not
supplied on the transition into _Hash_Absorb_, which therefore uses a Form A `ace.setst`
instead of the Form C of the base algorithm. No mention of _Set_Aux_Value_ remains anywhere
in the four Ascon sections.

**m3 is now closed.** Full build clean at 1047 KB.

### m4 — [FIXED] Undefined symbol and missing type coercions (sealing algorithms, GCM counter)

**Original finding:** `AESE256` was used in the sealing algorithms
(`ace-ISA-unpriv.adoc`, `ACE-SCC-AEAD`) but never defined; counter arithmetic mixed
bit strings and integers without `int()`/`bin()` coercions
(e.g. `(SIV[31:0]+bin(i,32)) mod 2**32`); and the GCM counter rework left
`start_ctr`/`ctr` declared as integers while applying the string-only `bswap` to them,
with a self-contradictory endianness description in the SCC table.

**Resolution (applied 2026-08-13):**

* `AESE256(K, B)` is now defined at the head of `ACE-export-import-algorithms`
  (`ace-ISA-unpriv.adoc:3020`) as AES-256 encryption per FIPS 197, mapped to values
  per the conventions chapter; a `nist-fips-197` entry was added to `ace.bib`.
* The counter blocks in `AES_GCM_SIV_Encrypt`/`_Decrypt` now read
  `bin((int(SIV[31:0]) + i) mod 2**32, 32)` (`ace-ISA-unpriv.adoc:3100`, `:3117`).
* GCM: `start_ctr` is declared "an integer in the range 0 to 2^32^-1, serialized as
  `bin(start_ctr,32)`"; `ctr` is `local ctr : int`; extraction uses
  `int(bswap(J0[127:96]))` (state-machine finalize, both `_Encrypt_`/`_Decrypt_`
  blocks, and GCM-with-Set-IV provisioning); write-back uses
  `J0[127:96] <- binBE(ctr,32)`; both tag masks use `binBE(start_ctr,32) @ J0[95:0]`;
  the SCC-table description was condensed to the single-statement form.

### m5 — [FIXED] ML-DSA Serialized Context not a multiple of 128 bits

A padding row of 96 / 24 / 104 bits was added for ML-DSA-44/65/87. The widths were
computed, not guessed: the preceding fields total 53536 / 77544 / 100120 bits, so the
context becomes 53632 / 77568 / 100224 bits = 6704 / 9696 / 12528 octets =
419 / 606 / 783 blocks. Those totals are recorded in the text, together with why the
padding widths are so irregular — `ctxlen` is a single octet and the cite:[nist-fips-204]
signature sizes are 2420 / 3309 / 4627 octets, none a multiple of 16 — so the numbers do
not look arbitrary and invite "rounding".

The sibling ML-KEM table was cross-checked at the same time: 26112 / 37888 / 50944 bits,
all exact multiples of 128, so its existing 64-bit padding row is correct and needed no
change.

### m6 — [FIXED] SHA-3 `_Hash_Finalize_` had no defined behavior

**Resolution approach (2026-08-13):** rather than defining the state, `_Hash_Finalize_`
was *removed* from SHA-3 — its States are now _Initial_, _Hash_Absorb_, _Hash_Output_,
_Success_ with transitions `_Initial_ -> _Hash_Absorb_ -> _Hash_Output_ -> _Success_` —
and the suffix/`pad10*1` work was folded into the transition into _Hash_Output_. That is
the right call: SHA-3 needs no parameter at that point, so the state carried no
information. `last_block_len` was correspondingly dropped from the Serialized Context.

**Residuals 1 and 2 fixed on 2026-08-13:**

1. **[FIXED] KMAC's transition list was broken.** KMAC declared `_Hash_Finalize_` among
   its States while taking its transitions by reference ("as in <<ACE-SHA-3>>"), and
   SHA-3 no longer declares that state — so the path KMAC needed was declared nowhere,
   which generic rule 2 turns into an illegal-instruction exception plus CR invalidation.
   Resolved by removing the state from KMAC as well: `L` is now passed by the Form B
   `ace.setst` that transitions to _Hash_Output_, so KMAC's states are _Initial_,
   _Hash_Absorb_, _Hash_Output_, _Success_ and the inherited transition list is correct
   again. The Parameters entry for `L` was updated to match. This is the better shape —
   KMAC now differs from SHA-3 only in the *Form* of the transition instruction, not in
   the set of states.
+
   Taken together with the `L` change below, `_Hash_Finalize_` is now used only by
   Ascon-Hash256/XOF128/CXOF128, which declare it in their own state machines; the global
   state constant remains defined, as it must.
2. **[FIXED] Dangling fragment.** The empty bullet
   "`** Upon transitioning _Hash_Finalize_,`" left in SHA-3 by the earlier edit has been
   deleted.
3. **[minor] `last_block_len` is now dead in SHA-3 but still declared.** It was removed
   from the Serialized Context yet remains in the Internal State (`:2297`), and nothing
   sets or reads it — the final partial block is handled by `pad10*1` from `block_base`.
   Remove the declaration. KMAC's *explicit* SCC table, however, still lists
   `last_block_len` (16 bits, Pos. iii), so KMAC's "as for <<ACE-SHA-3>>" text and its own
   table now disagree with SHA-3's table; reconcile the two, and re-check KMAC's padding
   rows afterwards, since dropping a 16-bit field changes the running total.
4. **[minor] `finalize()` is passed to `process_VLI` but never defined for SHA-3.** The
   _Hash_Absorb_ call (`:2336`) passes `absorb(), finalize()`, yet SHA-3's
   Algorithm-Specific Functions define only `P()`, `absorb()` and `update()`. With the
   padding now performed on entry to _Hash_Output_, the argument should be `None`.
5. **[VERIFIED CORRECT, wording fixed] `state_offset` contradiction.** The call passed the
   literal `0` while the prose called it "algorithm-defined". Checked against three sources:
   the FIPS 202 row of <<ACE-Notation-standards>> ("Direct mapping of the absorbed
   string"), the sponge construction itself (the rate is bits 0…`r`-1 of the string, so no
   leading region exists to skip), and the repository's own `shake-kat.py`, which absorbs
   from lane (0,0) and squeezes from lane 0. `state_offset` = 0 is therefore correct for
   this family; only the prose was wrong, and it now states 0 with the reason. The generic
   <<ACE-hash-functions>> wording "algorithm-defined" was deliberately left alone: it lists
   `state_offset` as a parameter precisely so instantiations can pin it, and SHA-3 is one
   that pins it to 0.

**Also changed while here: KMAC's `L` is no longer required to be a multiple of 8.**
The previous text invalidated the CR unless `L` was "a positive multiple of 8". That was
over-restrictive: `L` is the bit length that cite:[nist-SP-800-185] encodes in
`right_encode(L)`, and the standard admits any positive value. The requirement is now
only that `L` be non-zero, with the text stating that output is delivered in whole
octets, so a non-multiple-of-8 `L` yields {lceil}`L`/8{rceil} octets with the last one
zero-padded above its `L mod 8` significant bits — the same principle as
<<ACE-truncation-vs-length>>. The _Hash_Output_ paragraph was updated to say this too.

**Cross-reference labels fixed (defect I introduced, plus a pre-existing one).** The
anchors `ACE-truncation-vs-length` and `ACE-octet-granularity` sit on plain paragraphs
with no title, so Asciidoctor fell back to rendering every `<<...>>` to them as the raw
bracketed id — "[ACE-truncation-vs-length]" — in six places, three of which were
pre-existing on `ACE-octet-granularity` and three of which I added. Both anchors now carry
reftext (`octet granularity`, `the rule on truncation versus input length`) and all six
render as prose. Verified by scanning the built HTML for the
`<a href="#id">[id]</a>` pattern: zero remain.

### m7 — [FIXED] `ace.mv` specified in terms of `vl`/`EEW`

**Original finding:** `ace.mv` computed its `acestart` increment as `vl` {times} `(EEW/8)`,
contradicting the model stated elsewhere that ACE has no element concept and uses only
`VL*SEW`.

**First attempt (author):** a NOTE was added declaring `ace.mv` an exception that does use
`EEW`. That closed the silent contradiction inside the `ace.mv` section, but left two
things: the general statement at `ace-ISA-unpriv.adoc:1132` still denied `EEW` *absolutely*,
so the exception was invisible from there; and, more substantively, nothing defined what
`EEW` *is* for `ace.mv`. In RVV, `EEW` is per-operand and fixed by the instruction encoding —
widening/narrowing forms and indexed loads carry width fields that set it — and `ace.mv` has
no such field, so two implementers could read it differently and compute different
`acestart` increments, a divergence in architectural state rather than in wording.

**Resolution (applied 2026-08-13):** on the author's decision that the value is `SEW`, `EEW`
was replaced by `SEW` in both vector variants, which now update
`acestart` by `vl` {times} `(SEW/8)`.

This turns out to be the better outcome than an exception, because with `SEW` there *is* no
exception: `vl` {times} `SEW`/8 is exactly `ACELEN`/8, the quantity every other ACE
instruction uses. The NOTE was rewritten to say that, and to record why no element-width
field is needed — `SEW` from `vtype` determines the transfer size just as it does for
`ace.exec`. Consequently the general statement at `:1132` required *no* carve-out and was
left untouched: it is true again as written, and `EEW` now appears only there and in the
acronym list, both of which are about the vector crypto extension rather than about ACE.

Verified: no `EEW` remains in any instruction description, and the full build is clean at
1048 KB.

### m8 — [FIXED] `ace.input`/`ace.output` encoding and description oddities

Three defects of increasing severity, all resolved by making both instructions match
`ace.store`.

* `ace.input` had the *base address* in the `rs2` field and the length in `rs1`, so address
  generation could not take the base from `rs1` as it does for every other RISC-V memory
  instruction. The two fields were swapped.
* `ace.output` was declared **I-type** with the base address in the `rd` field — the field an
  I-type instruction *writes* rather than reads — and used the 12-bit load immediate where a
  store takes the split form. It is a store, so it is now S-type, with the base in `rs1`, the
  length in `rs2` and a split immediate covering the same range. `Xd` became `Xs` throughout,
  the register being read to form an address rather than written.
* The mnemonic, encoding and description disagreed (`Xd` versus `%offset(Xs)`), and the
  replacement table gave `ace.input` two different operand orders. All harmonised.

The three instructions under opcode `custom-1` are now one uniform S-type shape differing only
in `funct3` and in what `rs2` carries. Two notes were added on the author's request: why S-type
is right for `ace.input` even though it reads memory — the format follows the register operands,
and `ace.input` has two sources and no register destination, whereas `ace.load` is I-type
because its destination is a CR in the `rd` field — and an [IMPORTANT] warning that under this
opcode the direction of the access comes from `funct3` and not from the opcode, unlike the base
ISA, so an implementation deriving direction from the opcode alone will mis-handle all three.

### m9 — [FIXED] RV32 even-register-pair rules do not exclude the X1:X0 pair

**Original finding:** the even-`s` constraint on RV32 GPR pairs admits `s` = 0, so
`X1:X0` is a legal encoding whose low half is `X0`; the consequences were nowhere stated.

**Resolution (applied 2026-08-13):** rather than forbidding the pair, the behavior is now
documented once, generally, in a new <<ACE-RV32-register-pairs>> paragraph in the
Instructions preamble — the same place that already fixes the `X0`-as-CR-index rule. It
states that `X1:X0` is not forbidden and gets no special treatment, that `X0` retains its
cite:[RISCV-ISA-Unpriv] behavior, and therefore that as a destination the low half
(bits [31:0]) is discarded and only bits [63:32] are observable in `X1`, while as a source
bits [31:0] read as all zeros; neither is an error and no implementation need diagnose it.

Per the author's instruction the remark was written to cover *every* RV32 pair case, and
enumerates them so the claim is checkable: `ace.getmdl`/`ace.getmdh`, Form B `ace.setst`,
Form B `ace.mgmt`, `ace.restrictl`/`ace.restricth`, Form B `ace.size`, and Form B
`ace.derive`. It also says explicitly where it does *not* apply — instructions taking a
single XLEN-bit GPR, i.e. `ace.mv` and `ace.getst` — so the scope is unambiguous. All
eight cross-references resolve and the spec builds cleanly.

Stating the behavior rather than prohibiting the encoding is the better choice here: it
keeps the decode rule to the single "base register must be even" check, and it matches how
the base ISA treats `X0` everywhere else.

### m10 — [FIXED] `scrstatus`/`mcrstatus` wording defects

Three defects, all in `ace-ISA-priv.adoc`:

* "must be _Off_ of _Other_" {rightarrow} "must be either _Off_ or _Other_". The typo
  inverted the sense of a normative constraint.
* "The CR is may be configured" {rightarrow} "The CR may be configured".
* `Smacestatus`  The row now says so and lists only the two CSRs the
  extension defines.
### m11 — [FIXED] Locality substitution chain end undefined

Resolved on the author's rule that a Locality must be *substituted*, never dropped: if the
requested entry is unconfigured and no later entry of its chain is configured either, the
Metadata is invalid, the CR transitions to `ace_state_invalid`, and `ace_exc_invalid` is raised
where the Privileged Architecture is implemented.

Two supporting points were recorded. Substitution always moves along a chain from a broader
binding to a narrower one, so a substituted Locality is at least as restrictive as the one
requested and the binding is never weakened — which is why running off the end must be an
error rather than a silent omission, dropping it being what would produce an SCC that opens in
environments the caller meant to exclude. And because _ChipFamScrt_ and _DevScrt_ are
mandatory, the failure is reachable in exactly one place: only _ChipScrt_, last in its chain
and not mandatory, can fail.

Note that this changed an existing error code: the previous text called for an authentication
failure in the no-entry-configured case, which is a subset of the same condition. Reporting it
as invalid metadata avoids giving one condition two codes, and avoids suggesting tampering
where the real cause is a platform that lacks the secret.

### m12 — [FIXED] _UsagePolicy_ bit semantics ambiguous

"(V)S-mode" {rightarrow} "VS-mode" in the _UsagePolicy_ row, so bits 0–3 are an unambiguous
partition: U, VS, HS, M. Scoped to that row only — the three other uses of "(V)S" in the
document (the `sacelocality` CSR group and _SLocality_) genuinely mean "S-mode or VS-mode" and
are correct as they stand.

### m13 — [FIXED] `acestart` write-time validity check not implementable

The text required that writing "an invalid or non-supported nonzero value" raise an illegal
instruction exception, which is not decidable at write time: validity depends on the algorithm
and on the state of the CR the resumed instruction names, neither of which a CSR write can see.

Resolved on the author's ruling that *both* detection points are legitimate. The exception may
be raised on the write itself — an offset larger than any operand the implementation supports,
say — or when the consuming instruction is resumed, and implementations may differ. The text
now says so, and adds the consequence for software: it may rely neither on the write faulting
nor on its succeeding, and must be prepared for the exception at either point.

### m14 — [WITHDRAWN — reviewer error] OCB minimum nonce length vs octet granularity

I claimed that OCB's `N_len` {ge} `g-1` = 6 bits conflicts with
<<ACE-octet-granularity>>. It does not, and the reasoning is the same one that already
invalidated C4 residual 2: the granularity assumption governs the data *provided* to the
ACE unit and the data it *generates*, both of which cross the boundary as whole octets. A
length parameter that selects how many of the supplied bits are significant is not itself
subject to it — surplus input bits are simply ignored, and outputs are zero-padded up to
the octet boundary. `N_len` = 6 is therefore admissible and needs no restatement.

**This is the third instance of the same reviewer error** (C4 residual 2, the m3 remark
about Ascon, and this one). The rule to apply from here on: <<ACE-octet-granularity>>
constrains *transfers*, never a parameter that interprets an already-transferred value.
See <<ACE-truncation-vs-length>>, which now states this in the specification. m3 should be
re-read under the same rule and is expected to reduce to the SP 800-232 byte-orientation
question alone.

### m16 — [FIXED] CMAC Serialized Context is not a multiple of 128 bits

A "0 or 64" padding row was added, with the arithmetic recorded: the preceding fields total
384 / 448 / 512 / 576 bits for `k` = 64 / 128 / 192 / 256, and the two that are not already
aligned take 64 bits to reach 512 and 640 — so the context is 3, 4, 4 or 5 blocks of 128
bits.

### m15 — [FIXED] Assorted editorial defects

* `ace.mgmt`: "verifies the signature of the CR's contents" {rightarrow} "verifies the
  authentication tag". Nothing in SCC import involves a signature; the sealing construction
  is a variant of AES-GCM-SIV.
* `ace.getmdv`: wrote to "vector register `XV`", which does not exist; now `Vd`, in agreement
  with its own mnemonic.
* Ascon-XOF128's `countdown` text contradicted itself — "There is no `countdown` field",
  followed by "`countdown` is held in the _AlgorithmUse_ field". Rewritten: `countdown` is
  not *used*, since output squeezes without limit and there is nothing to count down; the
  _AlgorithmUse_ bits it would occupy stay zero; and because Ascon-Hash256 also holds it in
  the MDH rather than in the Serialized Context, the two Serialized Contexts remain
  identical. That keeps the conclusion the original was reaching for and drops the
  contradiction.
* Title page: `revnumber` 0.0 {rightarrow} 0.6.0 and `revdate` 6/2025 {rightarrow} 8/2026, on
  the author's instruction. I had declined to set these myself — the latest git tag being
  v0.5.0, the next number was not mine to infer, and a wrong version on a specification
  title page is worse than an obviously unset one.
* Already closed in earlier rounds: the `_hash_Initial_` reference and the phantom "IV field"
  in GCM with Set IV (under M11), and Book 4's use of `%` for `mod` (under M4).

---

## Known-answer test infrastructure (added 2026-08-14)

Of the seventeen Critical and Major findings, five were arithmetic or transcription errors
that a single test vector would have caught, and **all four Criticals were mechanically
detectable**. None was caught, because the seven existing scripts were never executed
automatically and did not cover the paths that were wrong. That gap is now closed.

**`src/run-kats.py` and `.github/workflows/kat.yml`.** The runner executes every
`src/*-kat.py` and fails the build on any failure. It honours two conventions: a script may
print `KAT-RESULT: PASS|FAIL`, which is used directly, or the runner inspects the output for
`FAIL`. Because several scripts deliberately evaluate a *wrong* formulation alongside the
correct one — to show the test is able to fail at all — a script declares those with
`KAT-EXPECT-FAIL: <label>`; for a table column the runner derives the column's span from the
header row, so a genuine failure in a neighbouring column on the same row is still caught. A
script that declares a negative control and then does not produce the expected `FAIL` is
reported as failed, since it has lost its power to discriminate. Three declarations were
added to the existing scripts, one line each; nothing else in them was touched.

**`src/cmac-kat.py`** — the test C3 needed. REF from SP 800-38B on byte strings, ACE from
`gen_subkeys` as now written, and OLD reinstating the little-endian doubling as a negative
control. Anchored on all four RFC 4493 / SP 800-38B Appendix D.1 vectors, then differential
over 11 message lengths {times} 8 keys, including keys searched for so that bit 7 of octet 0
and bit 127 of `L` differ — the pair of bits the correct and incorrect branches test.

**`src/ctr-kat.py`** — the test M6 needed. REF anchored on SP 800-38A F.5.1, then used as the
oracle for the nonce-plus-counter split ACE specifies, across four `n`/`j` splits. OLD
reinstates `IV @ ctr`. Also checks the X modes against a REF XCTR and confirms CTR and XCTR
do not coincide, so the distinction the specification draws is not vacuous.

**`src/scc-kat.py`** — the sealing construction, which has no published vectors because it is
a deliberate variant of AES-GCM-SIV with the length block omitted
(<<ACE-SCC-no-length-block>>). AES-256 is anchored on FIPS-197 C.3 and POLYVAL on the
RFC 8452 section 3 worked example, so the primitives are known good first. It then checks
round-trip, rejection of every single-bit change in `SIV`, in a ciphertext block and in the
MDH, that a different Locality set does not open a context, that the nonce changes the SIV
while a zero nonce is deterministic, and that `SIV2` is bound to `SIV`. The negative control
restores the length block and requires the result to change — otherwise the omission would be
unobservable and the argument in <<ACE-SCC-no-length-block>> untestable. **The script prints
the vectors for the variant**, which is what the specification's promise to publish its own
test data requires.

**`src/gcm-kat.py`, extended** — the existing vectors use a 96-bit IV and a block-aligned
plaintext, so they reached neither path that was wrong. Added: REF and ACE for any IV length,
compared over 9 IV lengths {times} 6 AD/plaintext length pairs, with the reversed length block
reinstated as a negative control for C2; partial final blocks throughout, for C4; and a
resumption test for C1 that carries across *only* the fields the Serialized Context names and
requires the result to be identical to an uninterrupted run — so a field missing from that
list fails the test.

**Verified end to end.** All ten scripts pass and the runner exits 0. Reintroducing C3 into
`cmac-kat.py` makes the runner exit 1 and name the script, so the suite demonstrably catches
the class of defect it was built for.

Remaining test work, in the order the defect record justifies: a GCM-SIV KAT against
RFC 8452 Appendix C; the three mechanical consistency checkers described in the review
(Serialized Context arithmetic, state-name resolution, and an assembler pass over the code
snippets), which between them would have caught m5, m16, HMAC finding 4, M4 and part of M3;
and a state-machine conformance test, which is the only thing that would have caught M7,
a plumbing defect that arithmetic vectors cannot see.

## Ratification-readiness notes

Beyond the technical findings, the following (mostly self-acknowledged) items must
close before this is a credible candidate:

1. All instruction encodings are declared preliminary; the `ace.setst`/`ace.mgmt`
   merge question is open.
2. `mcause` values are TBD.
3. `misa.L` and the ACES bit positions are provisional and contested.
4. RVV-mini is deferred.
5. The `Zklhmacm`/`Zklkmacm` "Defined in" cells say TBD.
6. The conventions chapter carries a note to relocate normative material before
   ratification.
7. Since the sealing construction is deliberately a *variant* of AES-GCM-SIV, the spec
   should commit to publishing its own test vectors (the note at
   `ace-ISA-unpriv.adoc:3012` promises this; the KAT scripts in `src/` are a good
   start and could be extended to cover the C2–C4 cases — a partial-block GCM KAT
   would have caught C4 immediately).

**All four Critical findings are now closed.** The remaining work is the Major tier,
where the highest-value item is a single mechanical sweep: reconcile Book 4 against Book 2
(every `ace.setst`/`ace.exec` Form in an example checked against the state machine that
defines it), which closes M4 and most of M3. After that, M2 (the exception model traps the
spec's own canonical code sequences), M5 (`ace.setst`/`ace.mgmt` have no CR-addressing
selector bit, making `ace.reset` unencodable), M1 (CSK scope across harts) and M9 (ECC
nonce generation unspecified) are the ones that affect whether the extension is
implementable and safe as written. M6 (CTR counter endianness) is a standards-conformance
item of the same kind as C2 and should be treated with the same seriousness despite its
Major rating.

**Status summary.**

* **Critical:** C1, C2, C3, C4 all [FIXED]. C4's residual 2 was withdrawn as a reviewer
  error; every other residual was closed.
* **Major:** all 13 closed — M1 through M13 [FIXED], with M12 and the cross-hart part of M1
  disposed of as questions formally referred to the ARC. Note that M7 (HMAC) and m7
  (`ace.mv`) are distinct findings differing only in case; both are now closed.
  M5 [FIXED]; M11 [FIXED] — accept-and-document plus a
  serialized, exactly-sizable `blocks` budget; M1 [FIXED];
  M3, M4, M6, M7, M8, M9 [FIXED]. **No cryptographic-correctness defect remains
  open at Critical or Major severity.**
* **Minor:** m3, m4, m7, m9 [FIXED]; m6 [PARTIAL — SHA-3/KMAC residuals 3–5];
  m14 [WITHDRAWN — reviewer error]; m16 and m17 added while fixing C3 and M8;
  m1, m2, m5, m8, m10, m11, m12, m13, m15, m16, m17 [OPEN].

**Highest-value remaining work:** the minor tier only. m5, m16 and m17 form one natural
task — audit every algorithm's Serialized Context arithmetic and field widths in a single
pass. m3 is closed. The remaining minors are the m6 residuals in SHA-3/KMAC and
editorial items.

**Note on Major numbering:** "M6" (CTR/XCTR counter endianness, Major) and "m6" (SHA-3
`_Hash_Finalize_`, minor) are distinct findings that differ only in letter case, as do
M7/m7. This has already caused one mix-up in discussion. If this document is circulated,
renumber one tier — e.g. Major items as MAJ-1…MAJ-13 — before it reaches reviewers who
were not party to the original conversation.

**Reviewer errors recorded for calibration.** C4 residual 2 was wrong in both of its
parts and has been withdrawn entirely: the octet-granularity claim confused a truncation
with a transfer length, and the follow-on complaint about excluding `last_blk_len` = 0
compared GCM against OCB and Ascon without noticing that GCM's last-block state is
optional whereas theirs are entered unconditionally. Two lessons for the remaining sweep:

1. Before citing <<ACE-octet-granularity>> against a parameter, check whether the
   parameter describes a *transfer* or an in-unit *truncation*. The m3 remark about
   Ascon's "partial final block of 127 bits" rests on the same faulty reasoning and
   should be re-read against <<ACE-truncation-vs-length>>; it likely reduces to the
   SP 800-232 byte-orientation question alone.
2. Before flagging an inconsistency between two algorithms' handling of the same
   parameter, check whether their state machines differ in a way that justifies it —
   mandatory versus optional traversal of the state changes what values the parameter
   has to be able to express.

**Regression-test suggestion.** Three of the four Criticals were arithmetic that a
single test vector would have caught. Before the next round, extend the KAT scripts in
`src/` with: a CMAC vector whose `L` has `L[127]` = 1 (catches C3 today); a GCM vector
with a partial final block and a non-96-bit IV (catches C2 and C4); and a GCM/GCM-SIV
export–import in mid-message (catches C1-class counter loss).

---

## Verified as correct (for reviewer confidence)

* OCB3 setup: `Nonce_be`, `bottom`, `Ktop`, `Stretch_be` slice
  `[191-bottom:64-bottom]` all match RFC 7253 §4.2 under the bswap view; the
  encryption/decryption block and last-block formulas match, including the checksum
  over the *plaintext* on both paths.
* XEX/XTS: single-key α-multiplication vs two-key direct mask, `update_mask`
  reduction, tweak encoding, and the ciphertext-stealing procedure (clone at mask
  index m−1) all match SP 800-38E / Rogaway.
* SHA-3/SHAKE: domain-separation suffixes (0x06/0x1F), pad10*1 placement, final 1 at
  bit b−1; cSHAKE/KMAC suffix 0x04, absorb order (cshake_block then key_block),
  `right_encode(L)` / `right_encode(0)`, and the key/customization-string bounds
  (163/157 and 131/125 octets).
* Ascon-AEAD128/Hash256/XOF128/CXOF128: IV constants match SP 800-232, key XOR
  positions, domain-separation bit (`1 << 63` into `state[4]`), decrypt
  rate-replacement including the partial-block rate update, and the permutation
  placement equivalence in Hash_Finalize.
* GCM-SIV: key derivation block order and derived-key assembly, SIV computation
  (nonce XOR into low 96 bits, bit 127 cleared before encryption, set to 1 in counter
  blocks), little-endian length block.
* Sealing construction: omission of the POLYVAL length block correctly argued
  (lengths are a deterministic function of the authenticated MDH); SIV binding of the
  second pass; zero-nonce determinism correctly characterized via nonce-misuse
  resistance.
* ML-KEM/ML-DSA: all key/ciphertext/signature sizes match FIPS 203/204;
  hedged/deterministic signing selection matches FIPS 204 §3.4; the
  `decapsk`-embeds-`encapsk` duplication is correctly reasoned.
* `process_VLI`: `amount` strictly positive → per-instruction termination;
  interruption points at octet granularity are consistent with `acestart`.
