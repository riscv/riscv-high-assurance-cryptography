# Adversarial Review — Zkl / KLEE (Cryptographic Locker Extensions)

**Scope.** This review covers only the files listed in the assignment:

* `src/Zkl.adoc`
* `modules/ROOT/pages/Zkl-acronyms.adoc`
* `modules/ROOT/pages/Zkl-notation.adoc`
* `Zkl-symbols.adoc` — found only at `modules/ROOT/partials/`
* `modules/ROOT/pages/Zkl-ISA-unpriv.adoc`
* `modules/ROOT/pages/Zkl-ISA-algorithms.adoc` — **does not exist**; see §6
* `modules/ROOT/pages/Zkl-ISA-priv.adoc`
* `modules/ROOT/pages/Zkl-pseudocode.adoc`

`Zkl-introduction.adoc` was consulted only for its *Discussion Points*, which define the exclusions. `Zkl-ISA-machines.adoc` was not read.

**Line numbers** refer to the working tree at commit `487b232`. "unpriv" means `Zkl-ISA-unpriv.adoc`, "priv" means `Zkl-ISA-priv.adoc`, and "pseudo" means `Zkl-pseudocode.adoc`.

**Exclusions honoured.** Nothing listed in the introduction's Discussion Points is reported as a finding:

* **Group A:**
  * opcode allocation
  * `misa.L` and the KLS position
  * CSR addresses and the Smstateen bit
  * cause codes and "mvalue"
  * KLV scope (`vill`, VS gating, EGW)
  * RVWMO axiomatic integration
  * cipher/mode discoverability
  * cross-hart CSR access
* **Group B:**
  * UBE/MPRV endianness
  * guest/host CSKs
  * delegating trap-and-emulate to HS
  * side-channel levels and formalization
  * `kl.mgmt` interruptibility
  * SCC nonces
  * KDF inputs
  * SCA/RBG requirements
  * the 2^64 claim
  * the "last block"
  * CLF capacity
  * random material in exportable States
  * depth of the Debug-mode interaction

Where a finding touches one of these topics, it reports only a defect that the Discussion Point does not acknowledge, such as a contradiction between two normative texts. The overlap is stated explicitly in each case.

**Method.** Each finding was verified against the literal text twice. Every live `<<xref>>` in the scoped files was resolved mechanically:

* All intra-scope references resolve.
* Unresolved references occur only in commented-out lines (unpriv 115–148, 790, 2054, 2389, 2823, 3424, 3811; priv 119).
* References into `Zkl-ISA-machines.adoc` could not be verified (§6).

---

## 1. Executive assessment

**Verdict: NOT READY** to advance as a candidate extension.

The architecture is mature in many respects:

* The error architecture, gate ordering and context-switch ordering are carefully built.
* The SCC construction matches RFC 8452 under the notation's `@` convention.
* The `*lclstatus` lazy-save machinery is well thought out.

Two defects are nevertheless security-critical, and they sit in the normative core rather than in placeholder areas:

* **C1 — `kl.derive` launders policy.** No normative rule constrains the MDH of a destination CL that receives derived key material. The pairing text that would have constrained it is commented out, so a derived key can escape the source's Locality, ExpirationDate, UsagePolicy and SCProtection. SGR5 still points to that removed text.
* **C2 — Debug entry installs a public CSK.** Unpriv §"Interaction with Debug Mode" says the unit uses "the all-zero value in its place". Priv §`mklcsk` says a zeroized CSK is *unconfigured*. An implementation that follows the unpriv text seals every later SCC under a key known to everyone.

Nine Major defects also block candidacy:

* M1: KLEE encodings collide with RVV opcodes that KLV itself requires.
* M2: the memory-instruction encodings contradict the effective-address definition.
* M3: Zklmem emulation silently mandates `medeleg[2]=0`.
* M4: no ownership check on the per-hart SIV/IMPQUAL/SIV2 registers.
* M5: `kl.rename`/`kl.swap` are underspecified.
* M6: `kl.derive` has internal length and invalidation contradictions.
* M7: the restart option permits livelock under synchronous faults.
* M8: `Version` = 3 is incoherent.
* M9: the reference pseudocode never completes Zklmem provisioning.

**Conditions for "conditionally ready":**

1. Close C1 and C2 with normative text.
2. Close M1–M8.
3. Mark the pseudocode non-normative with the M9 fixes applied, or remove it.

The minor findings can be closed during Candidate review.

Counts: **2 Critical, 9 Major, 22 minor.**

---

## 2. Findings

### *PARTIALLY FIXED (marked FIXED in 6071269; residuals in §8)* C1 — `kl.derive` places no normative constraint on the destination's policies

**Severity rationale.** This breaks the primary security property of KLEE: a key cannot outlive or escape the policy bound to it (Introduction, "binds cryptographic secrets … and metadata"). It needs no hardware attack. Any process holding a derivable CC can do it.

**Location.** unpriv §`kl.derive`:

* lines 1970–2037, the normative text
* lines 2040–2059, the commented-out "Allowed pairs"
* SGR5, line 2371
* extension matrix, line 200

**Description / trigger.**

* The only live constraints are:
  * State compatibility of the endpoints (1981–1988)
  * "A field configured by a SKID is never importable" (1998)
  * pair-specific limits delegated to the out-of-scope Machines chapter (2017–2018)
* No live text says how the destination's *UsagePolicy*, *Locality*, *ExpirationDate* or *SCProtection* relate to the source's. The sentence that would have done so ("constraints on the _UsagePolicy_, _Locality_, _ExpirationDate_ and _SCProtection_ of the destination CL, to which the source Machine may add") is commented out at 2058–2059.
* The companion rule "A field from the System Key Store is never exportable" is also commented out (2047).

**Consequences.**

* **Locality escape.** A key-agreement CL bound to `ChipScrt` + `MLocality` derives a shared secret into a freshly provisioned AES-GCM CL with `Locality` = 0. That CL is then exported, and the SCC can be imported on any hart sharing the CSK, or under any M-Locality. The secret has escaped its binding.
* **Expiration escape.** The destination may carry `ExpirationDate` = 0, so derivation extends a key's lifetime indefinitely. This defeats unpriv 669–708.
* **UsagePolicy escape.** A source restricted to M-mode (bits 0–2 set) derives into a destination with no restriction, which U-mode can then use.
* **SCProtection downgrade.** Secret material from an SCProtection-3 CL enters an SCProtection-0 implementation, defeating the side-channel protection the provisioner selected.
* **SKS leakage path.** Without the SKS non-exportability rule, SKS-resolved key material can be the source of a derive into a software-exportable CL.
* **Dangling reference.** SGR5 (2371) permits `kl.derive` in Success/Failure "where the source endpoint is one of its exportable fields (<<KLEE-instruction-derive>>)". "Exportable field" is defined only in the commented text (2042), so SGR5 has no defined meaning.

**Reasoning / standards.**

* NIST SP 800-57 Part 1 Rev. 5, §6.2.1 (key-usage and cryptoperiod metadata protection), and SP 800-108r1 §8 (derived keys inherit the security strength and use constraints of the key-derivation key) both expect derived material to inherit the constraints of its parent. The spec itself adopts this principle for SKID resolution (unpriv 3092) and for `kl.restrict*` (narrowing only, 1067). `kl.derive` is the one path that breaks it.
* Confirmed as a false-positive candidate and rejected: the Machines chapter might contain pair-specific rules, but (i) unpriv states no general inheritance rule, and (ii) the pair constraints are described as ones the pair "may define", so absence is permitted.

**Resolution.** Uncomment and repair 2040–2050, and add this Rule (normative) to §`kl.derive`, after "Checks":

> **Derivation Narrowing Rule.** The _UsagePolicy_ checks of both endpoints precede the narrowing. Before any byte is transferred, the MDH of the destination CL is narrowed by the MDH of the source CL exactly as a SKID resolution narrows a CL (<<KLEE-system-keys>>):
>
> * _UsagePolicy_ bits 0–3 of the destination become the OR of both, and bit 4 the AND of both.
> * The destination _Locality_ becomes the union of both _Localities_, taking the stricter entry in each HW Binding chain and OR-ing bits 6–8. If the two Boot Session entries are non-zero and differ, or the result names an unconfigured entry (<<KLEE-Localities>>), the destination transitions to Error State _Invalid_ and nothing is transferred.
> * If `Zklexpire` is implemented, the destination _ExpirationDate_ becomes the smaller non-zero of the two values, or 0 if both are 0.
> * If the destination _SCProtection_ is lower, in the ordering of <<KLEE-SC-protection-levels>>, than that of the source, the destination transitions to Error State _Invalid_ and nothing is transferred.
>
> A pair defined in <<Zkl-ISA-machines.adoc#KLEE-Machines>> may narrow further but never less.
>
> A field whose value originates from the System Key Store is never an exportable field.
>
> An _exportable field_ is a field of the source CC that its Machine lists as the source of a `kl.derive`. An _importable field_ is a field of the destination CC that its Machine lists as a destination. Only listed (source Machine, State, field; destination Machine, State, field) pairs are allowed. Any other pair transitions both CLs to Error State _Invalid_.

SCProtection is not raised in place (see Pass 1 below), because it selects the implementation that was instantiated at provisioning.

---

### *ALMOST FIXED (delete the new WARNING, §8)* C2 — Debug entry: unpriv substitutes an all-zero CSK, priv declares it unconfigured

**Severity rationale.** If the unpriv text is followed, every SCC exported after unauthenticated Debug entry, until hart reset, is sealed under a publicly known key. Every such SCC can then be decrypted offline, and SCCs with arbitrary MDH, including permissive policies, can be forged and imported. This is a total break of the sealing property. It sits in a normative list, not a Discussion item.

The Debug topic's depth is a Group B item ("more discussion seems warranted"), but the *contradiction between two normative statements* is not acknowledged there.

**Location.**

* unpriv §`KLEE-interaction-with-debug`, lines 3877–3878: "HW Binding Group entries … masked. Until the next hart reset, the KLEE unit receives zero for each such entry … The CSK is zeroized. If the CSK is hardwired, or shared …, the KLEE unit of the hart receives the all-zero value in its place until the next hart reset".
* priv §`KLEE-CSR-mklcsk`, line 381: "A CSK whose value is `zeros(256)` is unconfigured under every model …; an established CSK that is zeroized (<<…interaction-with-debug>>) becomes unconfigured".
* unpriv 628: only Boot Session and SW Filter entries can be "unconfigured" when zero.

**Description / trigger.**

1. An adversary with physical debug access asserts debug entry without authentication.
2. The KLEE state is destroyed. Under the hardwired or shared-CSK models the unit now "receives the all-zero value in its place" (unpriv).
3. Execution continues. No text forbids leaving Debug mode; the NOTE at 3882 says only that "normal execution cannot resume" in the sense that state was lost.
4. Trusted software re-provisions keys and exports them. Every SCC is sealed under `SCC_KeyDeriv(zeros(256), …)`.

Separately, masked HW Binding entries are treated as the *value* zero rather than as *unconfigured*. SCCs bound to `ChipScrt` are then bound to a public constant, and new SCCs are created with that binding, silently weakening the Locality binding.

**Reasoning.**

* Priv 381 is the safe reading, and unpriv 3791 defines "no active CSK ⇒ `kl_exc_no_csk`". Because the two texts disagree, an implementer can conform to one book while violating the other.
* Under the hardwired model, "unconfigured" means the unit is unavailable until reset. That matches the recovery NOTE (3884: "Recovery requires a hart reset, which restores … the hardwired CSK").

**Resolution.** Replace unpriv items 3877–3878 with:

> . The HW Binding Group entries cannot be zeroized and are therefore _masked_: until the next hart reset each such entry is _unconfigured_ for this hart (<<KLEE-Localities>>). A PI or SCC whose _Locality_ names a masked entry is invalid Metadata, and chain substitution does not substitute a masked entry.
> . The CSK is zeroized. If the CSK is hardwired, or shared under the fourth model of <<KLEE-CSK-requirements>>, the KLEE unit of the hart has no active CSK until the next hart reset, and every access that <<KLEE-CSK-requirements>> does not exempt raises `kl_exc_no_csk`. A shared CSK itself is not modified. At no time does the KLEE unit use an all-zero CSK or an all-zero HW Binding entry as key material.

Extend unpriv 628: "A Locality Secret of the Boot Session Group or of the SW Filter Group whose value is `zeros(128)`, **and a masked HW Binding entry (<<KLEE-interaction-with-debug>>)**, is _unconfigured_."

---

### **FIXED** M1 — LOAD-FP/STORE-FP `funct3` 5/6/7 are the RVV unit-stride vector loads and stores that KLV requires

**Severity rationale.** This is Major rather than Critical only because the final opcode allocation is a Group A item that must change anyway. The defect itself is a hard conflict. A hart that implements `Zklv` — which requires "unit-strided vector loads and stores" (unpriv 328) — together with hardware `Zklmem` or `Zklio` cannot decode both instruction sets. The draft is therefore not implementable in its mandated configuration.

The *allocation* is a Group A item. This finding reports something different: the introduction's stated premise, that these `funct3` values are unused, is false. The ARC would therefore be asked to rule on a wrong factual basis.

**Location.**

* unpriv 2075–2077 (`kl.load`, LOAD-FP, `funct3` 5/6)
* unpriv 2122–2124 (`kl.store`, STORE-FP, 5/6)
* unpriv 2179–2181 (`kl.input`, LOAD-FP, 7)
* unpriv 2231–2233 (`kl.output`, STORE-FP, 7)
* unpriv 157 (Zklmem conformance)
* unpriv 322–330 (KLV)

**Description.** The RISC-V "V" Standard Extension for Vector Operations, v1.0, §7.3 (Vector Load/Store Width Encoding) assigns:

* LOAD-FP (`0000111`) `width` = `000`, `101`, `110`, `111` to `vle8/16/32/64` (and the strided, indexed and segment variants selected by `mop`)
* STORE-FP (`0100111`) the same values to `vse8/16/32/64`

`width` values 1–4 are the scalar FP loads and stores (Zfh/Zfhmin `flh`, F `flw`, D `fld`, Q `flq`; Unprivileged ISA 20240411, chapters "F", "D", "Q", "Zfh"). With V and all FP extensions present, LOAD-FP and STORE-FP have **no** unused `funct3`.

KLEE's own examples use `vle8.v`/`vse8.v` (pseudo 128, 190). KLV is "fully opcode-compatible with RVV" (318), so code using `vle32.v` must work, and `vle32.v` is `funct3` 6, which is `kl.load` indirect. RVV decodes `mop`/`nf` in bits 31:26 as part of the same `funct3` space, so KLEE's `immed12` cannot coexist with it.

A related inaccuracy: MISC-MEM uses `funct3` 0 (FENCE/FENCE.TSO/PAUSE), 1 (FENCE.I, Zifencei) and 2 (CBO.*, Zicbom/Zicboz). Values 3–7 were free, and KLEE uses 4 and 5.

**Resolution.**

* Informative text: correct the premise so that the ARC gets accurate data, for example: "LOAD-FP/STORE-FP `funct3` 5–7 are the RVV 1.0 unit-stride/strided/indexed vector memory encodings (§7.3) and are unavailable to any hart implementing V or KLV. KLEE memory instructions therefore require a different major opcode, e.g. custom-0/1 during prototyping, or a new allocation."
* Normative text: add to §Extensions: "The encodings of `kl.load`, `kl.store`, `kl.input` and `kl.output` shall not overlap any encoding of a standard extension that `Zkl`, `Zklv` or `Zklio` require or permit on the same hart."

---

### *OPEN (almost; remaining edits in §8.3)* M2 — Memory-instruction encodings contradict each other and the effective-address definition

**Severity rationale.** Two conforming implementations would decode the same bits differently, so this is a direct interoperability failure. Because the base register differs, a wrong decode computes a wrong effective address, which means stores go to arbitrary memory.

**Location.**

* **EA definition, unpriv 1011–1020:** "the I-type `immed12` for `kl.load`, and the S-type pair `immed[11:5]`/`immed[4:0]` for `kl.store`, `kl.input`, and `kl.output`. The effective address of a transfer is `X[rs1] + sext(%offset)`."
* **`kl.load`, 2083–2085:**
  * Text: "`funct3` = `0b000` selects the immediate CL index … `0b001` selects the CL indexed by the GPR". The diagram (2077) shows `funct3` ∈ {5, 6}.
  * "`r` is the CL indexing mode selector": no `r` bit exists in the diagram; all 32 bits are allocated.
* **`kl.store`, 2121–2131:**
  * Diagram: `context` occupies bits 19:15 (rs1 slot) and `Xs1` bits 24:20 (rs2 slot). This contradicts `EA = X[rs1]` and RISC-V S-type convention (Unprivileged ISA 20240411 §2.3, "Base Instruction Formats", S-type: rs1 = base).
  * It also refers to the nonexistent `r` bit (2131).
* **`kl.input`, 2174–2184:**
  * "The base address `Xs` occupies the `rd` field and the length `Xl` the `rs1` field". So the base is not in `rs1`.
  * The instruction is I-type, but line 1013 calls it S-type.
* **`kl.output`, 2226–2236:** the base `Xs` is in the rs1 slot (19:15) and `Xl` in rs2 (24:20). `kl.input` and `kl.output` therefore put the base in different slots, even though 2226 says "encoded similarly to `kl.input`".

**Resolution.** Adopt standard base-register placement throughout and state it once. Replace unpriv 1011–1015 with:

> `%offset` denotes the sign-extended 12-bit immediate of the instruction: bits [31:20] for `kl.load` and `kl.input` (I-type), and bits [31:25] @ [11:7] for `kl.store` and `kl.output` (S-type). The base register is always in bits [19:15] (`rs1`). The effective address of a transfer is `X[rs1] + sext(%offset)`.

Then re-encode as follows:

* **`kl.load`:** `rd` = CL field, `rs1` = base. Delete the `r` sentence. Replace 2083 with: "The `funct3` value selects direct (`Kd`) or indirect (`K(Xd)`) CL addressing; indirect addressing requires `Zklind`, and otherwise the indirect `funct3` is an illegal instruction." The `funct3` numbers themselves remain Group A.
* **`kl.store`:** bits 19:15 = base `Xs1`, bits 24:20 = CL field. Delete 2131.
* **`kl.input`:** bits 19:15 = base `Xs`, bits 11:7 = length `Xl`. Replace 2175 accordingly.

---

### *OPEN — STARTED TO FIX, WOULD RATHER AVOID A NEW EXCEPTION TYPE (proposals in §8.4)* M3 — Zklmem trap-and-emulate silently mandates `medeleg[2]` = 0

**Severity rationale.** This is an undiscoverable platform constraint that conflicts with the conventional OS use of illegal-instruction delegation (Linux delegates cause 2 to S-mode). An OS that delegates cause 2 on such a platform receives `kl.load`/`kl.store` traps it cannot emulate, because only M-mode holds the emulator and the CLs. The result is broken key management or, worse, an OS that "handles" them as SIGILL.

The informal "(we are open to discussing alternatives)" in a normative conformance list is also not acceptable. Delegating trap-and-emulate *to HS* is Group B; the *M-mode* constraint is not.

**Location.**

* unpriv 157
* priv 112 (only three KLEE causes are non-delegable)

**Reasoning.** Privileged ISA 20240411 §3.1.8 ("Machine Trap Delegation Registers") makes `medeleg` WARL and software-owned. Requiring a particular value of a standard delegation bit for a feature to work, without a discovery mechanism, violates the principle that extension behavior is independent of delegation policy.

The spec already has the right pattern: `kl_exc_CL_off`, whose delegation bit is read-only zero (priv 112), is used for exactly this purpose, M-mode lazy emulation of CL state.

**Resolution.** Replace the clause in unpriv 157 after "trap-and-emulate" with:

> in that case the hardware raises KLEE exception `kl_exc_emulate` for `kl.load` and `kl.store`, whose encodings are assigned. `kl_exc_emulate` has the priority of the first group of illegal-instruction grounds, and its `medeleg`/`hedeleg` bits are read-only zero (<<Zkl-ISA-priv.adoc#KLEE-exceptions>>).

In priv 98–112, add `kl_exc_emulate` to the list of non-delegable causes. Its number is to be allocated by the ARC (Group A).

---

### **FIXED** M4 — The per-hart SIV/IMPQUAL/SIV2 registers have no ownership check on transfers

**Severity rationale.** A transfer on a CL other than the managed one silently reads or overwrites another operation's authentication registers. The in-flight CC is then lost, or a nested handler exports a wrong image. This is undefined architectural behavior on a security path, and it is reachable by ordinary user code.

*NOT A PROBLEM, HOW TO HANDLE IT IS DEFINED BY THE ARCHITECTURE.*

**Location.**

* unpriv 296–304 (registers per hart; the NOTE acknowledges overwriting only for *opening* `kl.mgmt`)
* 988–991 (`klmanagedcr`: "Internal values of SIV … are associated with this CL")
* 1370–1376 (`kl.mv` State checks)
* 2083–2108 (`kl.load`)
* 2136–2140 (`kl.store`)
* 828 (save rule)
* 2566–2569 (second-group illegal-instruction grounds: only `kl.mgmt` checks `klmanagedcr`)

**Description / trigger.**

1. `kl.mgmt K1, importing` opens an import, so `klmanagedcr` = 1 and SIV is zeroized.
2. The code (or a buggy library sharing the hart) opens `K2` for import as well. That `kl.mgmt` fails the `klmanagedcr` check, but after `csrw klmanagedcr, 32` (permitted, 993–999) it succeeds, and `K1` remains in `kl_cfg_importing`.
3. A `kl.load K1, …` passes SGR21: its State is `kl_cfg_importing`, and nothing checks `klmanagedcr`. It writes the SIV bytes of `K1`'s image into the per-hart SIV, which now belongs to `K2`.
4. Completion of either import authenticates against the other image's SIV.

Symmetrically, `kl.store` on an exporting CL that is not `klmanagedcr` emits the SIV of another CL. The save rule at 828 assumes the SIV belongs to the CL named by `klmanagedcr`, which step 3 falsifies.

**Resolution.** Add to the second group of illegal-instruction grounds (unpriv 2568), and restate in SGR21/SGR22:

> . `kl.load`, `kl.store` or `kl.mv` on a CL in `kl_cfg_importing` or `kl_cfg_exporting` whose number differs from `klmanagedcr`.

Add to SGR21 and SGR22: "In States `kl_cfg_importing` and `kl_cfg_exporting` the CL must additionally be the one named by `klmanagedcr`."

Provisioning and PPI states do not use the authentication registers (304), so they are left unconstrained, which keeps the change minimal.

---

### *PARTIALLY FIXED (IRR1, SGR20, Error-State table, priv 281 pending; §8)* M5 — `kl.rename` and `kl.swap` are underspecified

**Severity rationale.** These instructions move whole CCs, including partially managed ones, yet their exceptions, interaction with `klmanagedcr`, lazy-save (`*lclstatus`) behavior and uninterruptibility are undefined. The result is non-interoperable context switching and possible loss of the authoritative image of a CL.

**Location.**

* unpriv 1922–1926 (the entire semantics)
* IRR1, 2755 (uninterruptible list omits both)
* SGR20, 2446 (partial-State allowance omits both)
* the Error-State table, 2694–2710 (omits both)
* priv 281 (the `*lclstatus` exemption list names only `kl.clone`)
* unpriv 988 (`klmanagedcr` maintenance)

**Description.** The following are undefined:

* the behavior when `Ks` = `Kd`
* the exceptions raised: `kl_exc_out_of_memory` is impossible for rename but possible for swap in some representations, and `kl_exc_CL_off` depends on which operand is Off
* whether a source in a Configuration State is allowed, which contradicts the spirit of SGR18
* which `klmanagedcr` value results when the destination was the managed CL and is overwritten. Line 988 covers "cleared … destination of a `kl.clone`" but not rename
* for swap when both CLs are partial, "changed to the partial CL" is ambiguous
* whether an Off operand is exempt as for `kl.clone`, and which fields become Dirty

**Resolution.** Replace 1922–1926 with:

> `kl.rename`:::
> If `Ks` = `Kd`, no operation, and no field is set to Dirty. Otherwise the CC of `Ks`, including any Partial or Configuration State, becomes the CC of `Kd`, the previous CC of `Kd` is discarded, and `Ks` becomes _Unconfigured_. If `klmanagedcr` = `s`, it becomes `d`. Otherwise, if `klmanagedcr` = `d`, it becomes 32. The source access is not exempt from `kl_exc_CL_off`; the destination access is exempt as for `kl.clone`. The fields in effect for both CLs are set to Dirty.
>
> `kl.swap`:::
> If `Ks` = `Kd`, no operation. Otherwise the CCs of `Ks` and `Kd` are exchanged. If `klmanagedcr` ∈ {`s`,`d`}, it is replaced by the other index. Neither access is exempt from `kl_exc_CL_off`. The fields in effect for both CLs are set to Dirty.
>
> Neither instruction raises `kl_exc_out_of_memory`, and neither changes any MDH.

Also:

* Add `kl.rename` and `kl.swap` to IRR1 (2755) and SGR20 (2446), and to the Error-State table: "moved or exchanged unchanged".
* Add "`kl.rename` as a destination access" to priv 281.

---

### **FIXED** M6 — `kl.derive`: contradictory length and invalidation rules

**Severity rationale.** The contradictions admit zero-padded (low-entropy) keys, and implementations disagree on which CL is invalidated.

**Location.**

* unpriv 1990: "If the transfer is not allowed, then both CLs transition to Error State _Invalid_." This contradicts 2015–2020, where only "the offending CL" or "the destination" transitions.
* unpriv 2005–2009: "Both `length` and the source field's length must be at least as long as the destination field … exactly `b` bytes." This contradicts 2024–2027: "`eff_length` = min(`length`, `dest_length`) bytes and is zero-filled beyond them … zero-padded if shorter."
* Extension matrix, line 200: "`kl.derive` … All four `Form` values". `kl.derive` has no `Form` field (1952–1962: `R`, `0x3`, `0x0`, `funct2`).

**Consequence.** With `length` = 1, a 32-byte AES-256 key field receives one byte of secret material and 31 zero bytes: an 8-bit key. That is permitted by 2024 unless the pair's minimum (out of scope) forbids it.

**Resolution.**

* Replace the first sentence of 2024 with: "A destination _key_ field of `dest_length` bytes requires `length` {ge} `dest_length` and a source field or output of at least `dest_length` bytes, and receives exactly `dest_length` bytes. Otherwise the destination transitions to Error State _Invalid_ and nothing is transferred. For other destination fields, `eff_length` = min(`length`, `dest_length`) and the remainder is zero-filled."
* Replace 1990 with: "If the transfer is not allowed, the CLs transition as the Checks below specify."
* Line 200: "One encoding; the auxiliary input is always a GPR."

---

### *ALMOST FIXED (klstart item 1 pending; §8)* M7 — The restart option permits livelock on synchronous faults

**Severity rationale.** This is a liveness defect. A `kl.load`/`kl.store` spanning N pages under memory pressure can livelock forever, because every re-execution restarts from byte 0 and re-faults on an evicted earlier page. RVV forbids this for vector memory instructions.

**Location.**

* IRR3 option 5 (2774–2776): the only liveness condition ("restart is not the unconditional response to *asynchronous* interrupts")
* klstart item 1 (940–943: "0 in an implementation that selects the restart option")
* MMR3 (2733)
* IRR8 (2805–2806)

**Reasoning.**

* RVV 1.0 §3.7 (`vstart`) and the "Precise vector traps" subsection of the Exception Handling chapter require that on a synchronous exception `vstart` hold the index of the faulting element. Elements before it are complete and are not redone, which guarantees forward progress under demand paging.
* IRR3 option 3 already requires "advancing by at least one granule per execution attempt", but option 5 is explicitly available for the memory instructions (2776) and has no progress requirement for synchronous traps.

**Resolution.** Add to IRR3 option 5:

> For a synchronous exception raised by a component access, the restart option is not available: the instruction halts precisely with `klstart` at the last prefix-complete point before the faulting byte.

Amend klstart item 1 to "…or 0 **for an asynchronous interrupt** in an implementation that selects the restart option…". Amend the MMR3 parenthetical to "(0 is not permitted; see IRR3)".

---

### **FIXED** M8 — `Version` = 3 (system-specific format) is incoherent

**Severity rationale.** A normative hole: the system-specific import path can install arbitrary policies ("may be replaced"), with no architectural check that they are narrower, and the loader semantics are implementation-dependent. A Version-3 image is therefore a policy-bypass vector.

**Location.**

* unpriv 721–749
* unpriv 2108 ("When a system-defined format is used, the semantics of `kl.load` are implementation-dependent.")
* kl.size Form B (1240: bits [127:64], including `Version` [127:126] per 398, "are not examined")

**Description.**

* "Any such format must be preceded by a KLEE-format MDH" (731) contradicts the MDH that itself carries `Version` = 3. Which MDH is it?
* "must be converted … without weakening" (733) does not state what the conversion is compared against.
* "the MDH policies may be replaced accordingly" (734) permits replacement, not narrowing.
* `kl.size` Form B ignores `Version`, so the import pseudocode (pseudo 170) sizes a Version-3 image as if it were Version 0.

**Resolution.** Replace 731–735 with:

> Import of a system-specific format opens with an MDH whose _Version_ is 3 and whose other fields are those of a KLEE-format MDH (the _declared MDH_). At completion the CL's MDH is the declared MDH narrowed, as in <<KLEE-system-keys>>, by any policy the format carries. The format can only narrow the declared MDH, never widen it. _Version_ is then set to 0.

Also:

* `kl.size` Form B returns 0 for _Version_ ∉ {0} unless the implementation supports it (add at 1240).
* 2108: "…implementation-defined and must be documented; it must satisfy Rules SGR21 and IRR6–IRR8."

---

### *DEFERRED* M9 — The reference pseudocode fails on every Zklmem path and several Zklmv paths

**Severity rationale.** The pseudocode is informative and marked "being rewritten" (pseudo 17–20), but unpriv 2497 cites it as describing behavior. It is the only usage reference. The Zklmem provisioning, export and import paths *never issue the completing `kl.mgmt`*, which leaves CLs open indefinitely. Under the "do not downgrade" instruction this is Major.

**Location / defects (all verified).**

1. **pseudo 96, 156, 226 — `bltu t3, t2, …` after `kl.load`/`kl.store`.** `t2` is the full State (not masked with `0x38`); `t3` = `0x30`.
   * During provisioning the State is 56 > 48, so the branch is always taken: provisioning jumps to `finished` and never completes (96). Import jumps to `handle_errors` (226).
   * At 156 `t3` is not initialized on the Zklmem export path (the shared prefix at 106–119 sets no `t3`).
   * Fix: `andi t2,t2,0x38 ; beq t2,t3,handle_errors`.
2. **pseudo 50 comment.** "If the 3 top bits = 110, then prov. ended" is wrong: `0x30` = `110 000`, the Error-State group 48–55.
3. **pseudo 71.** `bltu t3, t2` misses State 48 (`kl_state_unsupported`), because 48 < 48 is false. Use the masked comparison.
4. **pseudo 115–139, Error-State export.**
   * `finished:` issues `kl.mgmt #kl_cfg_management_end` on a CL for which no management operation is open. This is illegal (unpriv 3296 and 3408).
   * `add t6,t6,16` and `sub s1,s1,16` should be `addi`; `sub` with an immediate is not an RV instruction.
   * After `restart`, `t6` has already advanced by 16.
5. **pseudo 170, `kl.size s1, s5:s4`.** Form B takes MDH[63:0] in one GPR on RV64 (unpriv 1179, 1227); the register-pair operand does not exist.
6. **pseudo 185, `subi`.** Not a RISC-V instruction.
7. **pseudo 177.** `restart:` follows `kl.size`, so `s1` is not re-derived, contrary to the comment at 173–175.
8. **pseudo 459–471, GCM via ECB.** The comment claims the final partial block absorbed into GHASH is the zero-padded ciphertext (SP 800-38D §7.1, step 5), but the code XORs the full `V1` into `V3` without masking the tail.

**Resolution.** Apply the fixes above. In the Error-State export path replace `finished:` with a return that issues no `kl.mgmt` (per unpriv 3390–3397). For item 8, mask the tail explicitly:

```
V1 ← V1 and mask(len_in_bytes(PT) − 16*i)
```

This goes before `V3 ← V3 xor V1` on the last iteration. Add a normative disclaimer to pseudo 11: "This chapter is informative; where it disagrees with Chapters … the latter prevail."

---

### minor findings (status per row, verified in §8)

| ID | Location | Defect | Resolution |
|---|---|---|---|
| **FIXED** m1 | unpriv 634 | Stray "?" after "…these Localities." | Delete. |
| *OPEN* m2 | unpriv 1908, 1922, 1925 | Labels `ace.clone`/`ace.rename`/`ace.swap` (old ACE name). | `kl.clone` etc. |
| **FIXED** m3 | unpriv 1892 | "Indirect CR addressing": CR is undefined (not in acronyms). | "Indirect CL addressing". |
| **FIXED** m4 | unpriv 3276, 2670, 2993 | Anchor `ace-mgmt-completes-export` still uses the old prefix. | Rename to `KLEE-mgmt-completes-export`. |
| **FIXED** m5 | unpriv 1376 | `kl.mv` cites only SGR21; the export direction is governed by SGR22. | "Rules SGR21 and SGR22". |
| **FIXED** m6 | unpriv 1331–1358 | Variant letters A–D in the mnemonics are reused as "Forms A–D" in 1353–1355 ("In Forms A and B, `rs2`…"), but the encodings use `kl.exec` Forms B and C. | Rename the variants i–iv and fix 1353–1355. |
| **FIXED** m7 | unpriv 1311 | Cites GR8 for register overlap; GR8 (1096) covers only LMUL alignment, and no Rule defines overlap. | Add an overlap Rule to GR8 or state it inline. |
| *OPEN* m8 | unpriv 421, 436, 451–452 | "three … levels" but values 0–3 exist; "asd per"; the Level 3 row says "In addition to SCProtection Level 3" (should be Level 2); "ISO/IEC-17825-ISO". | Fix text. |
| *OPEN* m9 | unpriv 1707–1718 | `kl.getst`/`kl.getstx` expansions given for RV64 only. On RV32 `kl.getmdl` writes a pair; the expansion from `X[d]` is the same but must be stated. | "On RV32 the same expansion applies to `X[d]`." |
| **FIXED** m10 | unpriv 1685 | `kl.getmdv` does not specify the destination bits above 128 or the tail policy. | "Bits above 127 follow the tail-agnostic policy (<<KLEE-KLV>>)." |
| **FIXED** m11 | unpriv 578–582 | UsagePolicy: "mode" is not defined as the effective privilege for MPRV-affected accesses; KLEE usage is not a data access, so the current mode applies. | "…the current privilege mode, unaffected by `mstatus.MPRV`." |
| **FIXED** m12 | unpriv 674 | Behavior when the secure clock is unavailable or unreadable is undefined. | "If the secure clock cannot be read, a CL with non-zero _ExpirationDate_ is treated as expired." |
| **FIXED** m13 | unpriv 843–846 | `klmvendorid` is not given the JEDEC bank/offset encoding of Priv ISA §3.1.2 (`mvendorid`); `klmarchid` lacks the MSB convention of §3.1.3. | Copy those encodings by reference. |
| *OPEN* m14 | unpriv 798–801 | Privilege column "RO" for CSRs that U-mode reads; other rows use "URW". | "URO". |
| **FIXED** m15 | unpriv 2802 | IRR7 "Handlers must not reset it to zero" gives no architectural consequence. | "…doing so is UNSPECIFIED and may transition the CL to _Invalid_." |
| **FIXED** m16 | unpriv 1920 | `kl.clone` "achieves the same result as exporting … and importing". False for IMPQUAL/Locality changes and ADSDropped; also a sealing/auth-register side effect. | "has the same effect on the destination CC as an export and import would, but touches no authentication register." |
| **FIXED** m17 | notation 109–145 | The Transcription section is commented out, yet `{vvert}` semantics depend on it (156, 195). | Restore it or define `{vvert}` in the live text. |
| *OPEN* m18 | acronyms | Missing PCCC, KLV, KLLEN, CR, RVWMO, RVTSO. KLEE's expansion "Cryptographic Lockers Extensions" matches neither the letters nor the introduction ("Cryptographic Locker Extensions"). | Add them and align. |
| *OPEN* m19 | src/Zkl.adoc 42/52, 58, 30, 112 | `:section-refsig:` defined twice; stray `:csrname: envcfg`; `:bibtex-file:` lacks `../` relative to `src/`; `[discrete]` precedes an `include::`, which has no effect. | Clean up. |
| **FIXED** m20 | unpriv 3398–3404 | The Error-State short import installs "the entire MDH … without applying the checks", including an arbitrary _Locality_ and a reserved _Version_. Harmless because no Content exists, but `kl.getmd` then reports invalid Metadata as if valid. | Apply the reserved-bit checks, or state that such a CL reports _Invalid_. |
| **FIXED** m21 | unpriv 1240 | `kl.size` Form B asserts that no field in [127:64] affects size; `Version` (127:126) can (see M8). | Carve out `Version`. |
| **FIXED** m22 | priv 379 | Readback "at the implementation's choice" of the active CSK under the programmable models conflicts with the spirit of unpriv 3810 ("Except for in M-mode …"). It is permitted, but it must be discoverable for audit. | Make the choice discoverable, or mandate read-as-zero under models 2–4. |

---

## 3. Cross-document inconsistencies and missing requirements

| # | Statement A | Statement B | Effect | Finding |
|---|---|---|---|---|
| X1 | unpriv 3878: all-zero CSK used "in its place" | priv 381: zeroized CSK "becomes unconfigured" | Public sealing key vs. unit unavailable | C2 |
| X2 | unpriv 1015: EA = `X[rs1]`; kl.input is S-type | unpriv 2121–2126, 2175, 2231 | Base register is ambiguous | M2 |
| X3 | unpriv 2083: `funct3` 0/1 | unpriv 2077: `funct3` 5/6 | Decode ambiguity | M2 |
| X4 | unpriv 2371 (SGR5) "exportable fields" | defined only in the commented 2042 | Undefined permission | C1 |
| X5 | priv 281 exemptions: clone destination only | unpriv 1922–1926: rename/swap move CCs | Undefined `kl_exc_CL_off`/Dirty behavior | M5 |
| X6 | unpriv 200: derive "All four Form values" | unpriv 1952–1962: no Form field | Matrix wrong | M6 |
| X7 | unpriv 1990: both CLs Invalid | unpriv 2015–2020: offender only | Divergent state | M6 |
| X8 | unpriv 2005: length ≥ dest | unpriv 2024: min() + zero-fill | Weak keys | M6 |
| X9 | pseudo 139, 115 | unpriv 3296, 3408 | Illegal instruction in reference code | M9 |
| X10 | introduction/Discussion A1 premise "unused `funct3`" | RVV 1.0 §7.3 | ARC misinformed | M1 |
| X11 | unpriv 157 | priv 112 | Implicit `medeleg` constraint | M3 |

**Missing requirements:**

* MR1: the ownership rule for authentication registers (M4)
* MR2: derivation narrowing (C1)
* MR3: forward progress on synchronous faults (M7)
* MR4: an overlap rule for vector operands (m7)
* MR5: the secure-clock failure mode (m12)
* MR6: `kl.rename`/`kl.swap` in IRR1 and SGR20 (M5)

---

## 4. Standards-compliance matrix

| Standard (version, section) | KLEE text | Status |
|---|---|---|
| RISC-V Unprivileged ISA 20240411, §2.3 Base Instruction Formats (S-type: rs1 = base) | kl.store, kl.input encodings | **Non-compliant** (M2) |
| RISC-V Unprivileged ISA 20240411, MISC-MEM `funct3` (FENCE 0, FENCE.I 1, CBO 2 in Zicbom/Zicboz) | kl.exec/setst `funct3` 4/5 | Compliant, no collision; introduction's "two unused" is inaccurate (3–7 free) |
| RVV 1.0 §7.3 Vector Load/Store Width Encoding | LOAD-FP/STORE-FP `funct3` 5/6/7 | **Collision** (M1) |
| RVV 1.0 §3.7 `vstart`; Exception Handling / precise traps | IRR3 option 5, klstart item 1 | **Weaker** than RVV (M7) |
| RVV 1.0 §3.4.3 `vill` | unpriv 327 | Compliant (KLV scope itself is Group A) |
| RISC-V Privileged ISA 20240411, §3.1.8 `medeleg` (WARL, software-owned) | unpriv 157 | **Constraint imposed** (M3); priv 112 read-only-zero bits compliant with WARL |
| Privileged ISA §3.1.2 `mvendorid`, §3.1.3 `marchid` | `klmvendorid`/`klmarchid` | Partial (m13) |
| Privileged ISA, `FS`/`VS` context-status fields | KLS, priv 187–250 | Compliant analogue |
| Smstateen 1.0 | priv 124–160 | Compliant ordering (bit allocation is Group A) |
| Smcsrind/Sscsrind 1.0 | `mklcsk` indirect | Consistent (indices are Group A) |
| RISC-V Debug Spec 1.0, `dmstatus.authenticated` | unpriv 3851–3862 | Informative mapping OK; internal contradiction (C2) |
| RFC 8452 §4 (key derivation), §5 (POLYVAL length block LE64(AD) ‖ LE64(PT)) | unpriv 3443–3714 | Compliant under the `@` convention (nonce omission is Group B) |
| NIST SP 800-38D §7.1 (length block BE len(A) ‖ len(C); zero-padding) | pseudo 459–475 | Length block correct; **partial-block masking missing** (M9) |
| FIPS 197 (AES) | SCC AES-256 | Compliant as used |
| NIST SP 800-108r1 §8, SP 800-57 Pt 1 Rev 5 §6.2.1 (derived-key constraints) | kl.derive | **Non-compliant** in spirit (C1) |
| ISO/IEC 19790:2025, ISO/IEC 17825:2024, ISO/IEC 24759:2025 | SCProtection table | References garbled (m8); levels are Group B |

Section numbers for RVV exception handling and the Debug spec are cited from memory of the ratified PDFs. They should be checked against the exact editions cited in `Zkl.bib` (not in scope).

---

## 5. Prioritized remediation plan

1. **C2:** replace unpriv 3877–3878 and extend 628 (text in C2). This is a one-paragraph change that removes a total break.
2. **C1:** add the Derivation Narrowing Rule, restore the exportable/importable definitions and the SKS rule, and repair SGR5.
3. **M4:** add the `klmanagedcr` ownership ground (one list item plus SGR21/22).
4. **M2 + M1:** fix the base-register slots and the EA text now, and correct the introduction's premise so that the ARC can allocate opcodes.
5. **M7:** add the forward-progress requirement on synchronous faults.
6. **M3:** specify a non-delegable emulation cause, with the number left to the ARC.
7. **M5, M6, M8:** complete rename/swap, derive lengths and Version 3.
8. **M9:** fix the pseudocode, or remove it until rewritten.
9. **m1–m22:** editorial pass.

---

## 6. Remaining questions and assumptions

* **A1.** `modules/ROOT/pages/Zkl-ISA-algorithms.adoc` does not exist. `src/Zkl.adoc` line 119 includes `Zkl-ISA-machines.adoc`, which was **not read** per the constraint. Findings that depend on Machine-level pair tables, minimum transfer lengths (C1, M6) or `exec-encodings` are therefore stated against unpriv alone. If the Machines chapter already imposes the narrowing, C1 downgrades to M: a normative rule would still be missing from the chapter that defines `kl.derive`.
* **A2.** `modules/ROOT/pages/Zkl-symbols.adoc` does not exist. `modules/ROOT/partials/Zkl-symbols.adoc` was used; it contains only attributes.
* **A3.** M1 assumes that a hart implementing `Zklv` implements the RVV unit-stride encodings, which unpriv 318 and 328 state.
* **Q1.** Is execution after unauthenticated Debug entry expected to continue without reset? C2's remedy is safe either way.
* **Q2.** Should `kl.rename` of the managed CL be allowed at all? M5 allows it, with `klmanagedcr` following the CL.
* **Q3.** Is `kl.derive`'s zero-fill intended for non-key destinations (for example, nonce fields)? M6 keeps it only there.

---

## 7. Remediation compatibility passes

### Pass 1

**(a) Mutual compatibility**

* **C1 vs SKID narrowing (unpriv 3092).** The narrowing is identical by construction. *Conflict found:* the first draft of C1 "raised" the destination SCProtection to the maximum. SCProtection selects the implementation instantiated at provisioning (unpriv 752 validity: the Machine/MachinePolicy/SCProtection combination), so it cannot be changed in place. **Adapted:** a lower destination SCProtection → Invalid, no transfer.
* **C1 vs M6.** Both add derive Checks. Order: M6's length check, then C1's narrowing, then transfer. Both are "nothing transferred" failures, so they compose.
* **M4 vs M5.** Rename/swap update `klmanagedcr` so that it follows the CL. The M4 ownership check then keeps holding for the moved partial CL. Compatible.
* **M3 vs M1/M2.** The emulation cause is keyed to the encodings; the re-encoding in M2 changes nothing in M3.
* **M7 vs M9.** The pseudocode's "CL cleared ⇒ restart" loops (pseudo 94, 154, 224) remain valid; M7 affects only `klstart` after synchronous faults.

**(b) Compatibility with untouched text**

* **C2 vs unpriv 3791 (CSK exemptions).** Locality/CSK CSR groups remain accessible without a CSK, so M-mode can still re-establish them under the programmable models. The hardwired model becomes unavailable until reset, which matches NOTE 3884. Compatible.
* **C2 vs priv 453 (reset).** Hart reset restores the hardwired CSK and HW entries; "until the next hart reset" matches.
* **M4 vs the context-switch order (unpriv 3756–3779).** The handler exports the managed CL *first* (step 3764) while `klmanagedcr` still names it, so the check passes. Restores run with `klmanagedcr` = 32 before each opening `kl.mgmt`, and the opening `kl.mgmt` then writes the target number (3134). Subsequent transfers pass. Compatible.
* **M4 vs the hint case (3784).** User code writes `klmanagedcr` = 0 with K0 Unconfigured. Transfers on K0 already fail SGR21, and transfers on other CLs now fail the ownership check. That is the intended behavior.

**(c) Adaptations applied:**

* C1 SCProtection wording changed to "Invalid if lower".
* M4 restricted to `kl_cfg_importing`/`kl_cfg_exporting`, because provisioning and PPI states do not touch the authentication registers (unpriv 304), avoiding an unnecessary constraint on provisioning code.

### Pass 2

**(a) Mutual compatibility**

* **M2 vs M9.** The pseudocode's `kl.load K(t0), 16(t6)` syntax is unchanged by the re-encoding (mnemonics are preserved). Compatible.
* **M8 vs m21.** M8 makes `kl.size` Form B examine `Version`; m21 carves `Version` out of the "not examined" sentence. The two edits touch the same sentence (1240) and are merged into one edit.
* **M7 vs MMR3.** MMR3 non-idempotent regions re-raise the same exception "before any component access". With M7 the halt point is the last prefix-complete point; the committed prefix is unchanged. Compatible.

**(b) Compatibility with untouched text**

* **C1 vs SGR17/SGR19 gate order (2423–2441).** Narrowing is a state change, so it must follow all gates. It is placed after "Checks", which follow SGR19. Compatible.
* **C1 vs the instruction-properties table (1069).** "Usage-controlled: Yes; the UsagePolicy of the source … and destination … evaluated independently" still holds. The evaluation happens *before* narrowing. Added clarifying clause: "evaluation precedes the narrowing".
* **C1 vs expiration (unpriv 690–708).** Expiry is checked at issue on both endpoints, before narrowing, so a narrowed ExpirationDate takes effect at the next issue. Compatible.
* **M5 vs Zklind (unpriv 110, 1892).** Indirect addressing is always available for rename/swap; M5 does not alter that.
* **M5 vs SGR18.** Moving a Configuration-State CL is not "usage" or "cloning", and SGR18 is not triggered. M5 states the admission explicitly, so there is no conflict.
* **M3 vs priv exception priorities (84–112).** The new cause takes first-group illegal-instruction priority. That places it above `kl_exc_fatal`, which is correct: the hardware does not implement the instruction, so no unit state is consulted. Consistent with the idea in commented priv 119.

**(c) Adaptations applied:**

* C1 text now states "the _UsagePolicy_ checks of both endpoints precede the narrowing".
* M8 and m21 are merged into one edit of unpriv 1240.

### Pass 3

**(a) Mutual compatibility, whole set**

* **C2 + C1.** After Debug entry no CSK is active, so `kl.derive` raises `kl_exc_no_csk`, and derivation cannot bind to a masked entry. Should a programmable-model M-mode re-establish the CSK, masked entries remain unconfigured until reset, and the C1 union rule then invalidates any derive naming them. This is consistent with the C2 extension of 628.
* **M4 + M5 + unpriv 988.** Every path that changes which CL is managed is now covered:
  * completing `kl.mgmt` (3134–3135)
  * clear, clone destination, Error State (988)
  * rename/swap (M5)
* **M7 + klstart 973 and IRR7.** No handler-forced restart is introduced; consistent with the prohibition.

**(b) Untouched text, re-read**

* **M2 vs the "In every encoding, fields shown with fixed values" rule (1008).** Unchanged.
* **M2 vs the Zklmem "encodings are assigned, not reserved" clause (157).** Preserved.
* **M9 vs 3390–3397 (Error-State export uses no `kl.mgmt`).** The revised pseudocode follows it.
* **C2 vs Debug NOTE 3884–3886 (recovery path).** Still true. Under the programmable models, SCCs exported *before* Debug entry become importable when M-mode re-establishes the same CSK. Under C2, no SCC is ever sealed with a zero key, so there are no post-Debug SCCs to strand.

**(c) Final adaptations:** none required beyond Passes 1–2. The remedies in §2 are the final versions.

---

## 8. Verification of spec changes (commits 8f46944, 6071269)

Line numbers in this section refer to the working tree at commit `2ecf127` and were verified by grep against it. "unpriv", "priv" and "pseudo" are as in the Scope section. A finding is marked **FIXED** in its title only when no normative residual remains. Editorial residuals are listed but do not block closure.

### 8.1 Status per finding

| Finding | Status | Residual |
|---|---|---|
| C1 | **Partial** | See 8.2 (C1). Exportable/importable fields are undefined, the SKID rule was inverted, and "at least as strict" has no ordering. ExpirationDate and SCProtection are unconstrained. |
| C2 | **Fixed in substance** | The new WARNING at unpriv 3935–3938 (text at 3937) contradicts the fix and must be deleted. The informal "here we must explicitly require both conditions" should go. |
| M1 | **FIXED** | Caveat: LOAD `funct3` 7 may be claimed by RV128 `LDU`; label it provisional in the Group A item. |
| M2 | **Open** | Text still disagrees with the diagrams (8.3). |
| M3 | **Open** | Still implies `medeleg[2]` = 0 (8.4). |
| M4 | **FIXED** | Editorial only: SGR21 (2495) and SGR22 (2499) each name both States, of which only one is relevant to the rule, and the sentences lack a final period. The author's note "not a problem, handled by the architecture" is answered in 8.2 (M4). |
| M5 | **Partial** | IRR1 (2802), SGR20 (2489), the Error-State table (2740–2757) and priv 281 were not updated. |
| M6 | **FIXED** | — |
| M7 | **Almost** | The klstart item 1 (955–958) still lacks "for an asynchronous interrupt". |
| M8 | **FIXED** | Also closes m21. |
| M9 | **Deferred** | Pseudocode changes are whitespace/comment only. Every defect listed in M9 remains (`subi`, unmasked `bltu`, `kl.size s1, s5:s4`, `kl.mgmt` in the Error-State export path, GCM tail). |
| m1, m3–m7, m10–m13, m15–m17, m20–m22 | **FIXED** | m7: the overlap constraint is now stated inline (1330), one of the two remedies offered. m20: the new sentence at 3459–3460 ends in a truncation, "so the CL is never observed." |
| m2 | Open | New label typo `klce.clone`::: (1936). |
| m8 | Open | "asd per" (435) and "In addition to _SCProtection_ Level 3," in the Level 3 row (449) remain. |
| m9 | Open | The new RV32 sentence is garbled (1748: "Or RV32, the code would similar"). |
| m14 | Open | Now "RO/MRW/HRW" (808–811), which contradicts "Software cannot modify these values" (851) and "Read only" (811). |
| m18 | Open | PCCC is expanded as "Partially *Provisioned* Cryptographic Context" (acronyms 63); the spec uses "Partially *Configured*" (unpriv 2982, 2994, 3043, 3088). RVWMO and RVTSO are still missing. |
| m19 | Open | `:csrname: envcfg` (src/Zkl.adoc 57) and `[discrete]` (111) remain. |

### 8.2 Residuals and newly introduced defects

**C1 — `kl.derive` (unpriv 1998–2080).**

1. *Stray review text in normative prose.* Lines 2057–2058 contain two bullets copied from this review: "Replace 1990 with: …" and "Line 200: …". Delete them.
2. *SKID/SKS rule inverted.* Line 2031 now reads "A field configured by a SKID is never **exportable**". The original rule had two halves: a field from the System Key Store is never exportable, and a field configured by a SKID is never importable. Restore both:
   > A field whose value originates from the System Key Store is never an exportable field. A field configured by a SKID is never an importable field.
3. *Exportable/importable fields are undefined.* The pairs text was deleted rather than repaired. SGR5 (2416) still says "one of its exportable fields", so SGR5 has no meaning. Restore the definition from the C1 remedy (last paragraph of the quoted Rule).
4. *"At least as strict" has no ordering.* Lines 2038 and 2055 use the phrase, but no text defines a strictness order for _UsagePolicy_, _Locality_, _ExpirationDate_ or _SCProtection_. The check is therefore not testable, and two implementations can disagree. Either adopt the narrowing formulation of the C1 remedy, or define strictness per field:
   > A destination MDH is _at least as strict_ as a source MDH if and only if all of the following hold:
   >
   > * every _UsagePolicy_ bit 0–3 set in the source is set in the destination, and bit 4 is clear in the destination if it is clear in the source;
   > * every Locality entry named by the source is named by the destination, or is replaced by a stricter entry of the same HW Binding chain, and bits 6–8 set in the source are set in the destination;
   > * if `Zklexpire` is implemented and the source _ExpirationDate_ is non-zero, the destination _ExpirationDate_ is non-zero and not later;
   > * the destination _SCProtection_ is not lower than the source's.
   >
   > Otherwise the destination transitions to Error State _Invalid_ and nothing is transferred.

   The check-only form is preferable to the narrowing form if the TG wants the destination MDH to stay exactly as provisioned. It then needs the four bullets above.
5. *Piping case.* Line 2050, "does not put restrictions on the policies of the source or destination Machine" reads as an exemption from the strictness check. If piping moves only public data (for example, a hash state), say so and require that the source field be non-secret. Otherwise apply the same check.
6. *Typos:* "DBRG" (2052; DRBG), "any constraint of on the data transfer" (2072).

**C2 — Debug (unpriv 3932–3938).** The replacement items (3932, 3933) are correct, and priv 381 now agrees with them. The new WARNING says that under hardwired or shared CSK models the SCCs are "sealed under a publicly known key … total break" and recommends disabling unauthenticated debug. It describes the *old* text, which the fix removed; it now contradicts items 1–2 immediately above it. Delete it. If a warning is wanted, use:
> [NOTE] After unauthenticated Debug entry under the hardwired or shared CSK models, the KLEE unit is unavailable on this hart until the next hart reset.

Minor: 626 reads "…entry (…), is _unconfigured_"; drop the comma.

**M4.** The author's note says that handling is defined by the architecture. After 6071269 this is true, because SGR21/SGR22 now check `klmanagedcr`. Before that change it was not, since nothing prevented a transfer on a non-managed CL in `kl_cfg_importing`. The finding is closed by the added sentence. Suggested editorial form, per rule:
> SGR21: In State `kl_cfg_importing` the CL must additionally be the one named by `klmanagedcr`.
> SGR22: In State `kl_cfg_exporting` the CL must additionally be the one named by `klmanagedcr`.

**M5.** The instruction text (1952–1960) now matches the remedy, but the rules that enumerate instructions were not updated:
* IRR1 (2802): add `kl.rename` and `kl.swap` to the uninterruptible list.
* SGR20 (2489): add both to the instructions admitted on a Partial or Configuration-State CL.
* Error-State table (2740–2757): add a row, "`kl.rename`, `kl.swap`: moved or exchanged unchanged".
* priv 281: add "`kl.rename` as a destination access" to the `*lclstatus` exemptions.

**M7.** klstart item 1 (955–958) still reads "…or 0 in an implementation that selects the restart option … for `kl.load`, `kl.store`, `kl.input` and `kl.output`". IRR3 now forbids restart on synchronous exceptions, so the two texts contradict. Insert "for an asynchronous interrupt" after "or 0".

**M3 text (unpriv 157).** "a illegal-instruction" (157) should be "an illegal-instruction". See 8.4 for the substance.

**Validity list.** Typos "satosfied" (753) and "it is a valid for an import operation" (756).

### 8.3 M2 — remaining edits

The diagrams are now correct: `kl.store` has `Xs1` at 19:15, and `kl.input` has `Xl` at 11:7 and `Xs` at 19:15. The EA definition (1034–1035) is generalized. The prose was not brought into line with the diagrams. All of the following are needed to close M2.

1. **General selector text (1032).** "In every encoding that offers both, bit `r` …" is false for the memory instructions, which select direct/indirect addressing via `funct3`. Replace with:
   > Instructions that offer both direct (`Kd`) and indirect (`K(Xd)`) CL addressing select between them with bit `r` of the encoding, except `kl.load` and `kl.store`, which select with `funct3`. In both cases the indirect form requires `Zklind`; without `Zklind` it is an illegal instruction.
2. **`kl.load` (2128–2130).** The text says "`funct3` = `0b0100` … `0b0101`": four-bit literals, values 4/5. The diagram shows 6/7. Replace with:
   > `funct3` = `0b110` selects direct CL addressing, and the CL number is the `rd` field. `funct3` = `0b111` selects indirect addressing, and the CL number is `X[rd]`{nbsp}mod{nbsp}32 (requires `Zklind`).

   Delete "`r` is the CL indexing mode selector … `r` = 1 is an illegal instruction" (2130). The encoding has no `r` bit.
3. **`kl.store` (2176).** Replace the four-bit literals `0b0110`/`0b0111` with `0b110`/`0b111`, and add the same direct/indirect sentence with `rs2` in place of `rd`.
4. **`kl.input` (2219).** "The base address `Xs` occupies the `rd` field and the length `Xl` the `rs1` field" contradicts the diagram. Replace with:
   > The base address `Xs` occupies the `rs1` field (bits 19:15), and the length `Xl` the `rd` field (bits 11:7). `kl.input` is I-type; its offset is bits [31:20].
5. **Consistency check.** After these edits, confirm that the EA text (1034–1035) names I-type for `kl.load` and `kl.input`, and S-type for `kl.store` and `kl.output`, now that `kl.load` sits under JALR and `kl.input` under LOAD.

One further observation on the new allocation, not blocking. `kl.load` under JALR `funct3` 6/7 is an I-type encoding whose `rd` is a CL number rather than a GPR. Tools that decode JALR generically will mis-disassemble it. Mention this in the Group A item.

### 8.4 M3 — proposals that avoid a new exception type

**What changed.** Unpriv 157 now says that the hart raises a virtual-instruction or illegal-instruction exception "depending on the `medeleg`/`hedeleg` bits … which the platform must deliver to M-mode, which requires `medeleg` bit 2 to be zero". The introduction gained a Group A item (`kl_exc_emulate`, introduction 154) and Group B items (165, 167) ("Delegate KLEE Unit trap-and-emulate to HSx", "Eliminate kl.load and kl.store?"). The *allocation* of a new cause is therefore out of scope. The residual defect is that the text still imposes `medeleg[2]` = 0, with no way for software to discover that it must.

The four options below avoid a new cause. They are ordered by recommendation.

**(b) Recommended — reuse `kl_exc_CL_off`.** `kl_exc_CL_off` already exists, is already non-delegable (priv 112), and already means "M-mode must act on this CL before the instruction can proceed". Emulating `kl.load`/`kl.store` is the same situation: only M-mode holds the emulator and the CL contents.

Proposed text for unpriv 157, replacing the clause after "trap-and-emulate":
> In that case `kl.load` and `kl.store` raise `kl_exc_CL_off` regardless of the Off status of the CL they address, and `mtval` holds the instruction bits as for an illegal-instruction exception. The M-mode handler distinguishes emulation from an Off CL by decoding the instruction. Their encodings are assigned, not reserved.

Add to priv §`KLEE-exceptions`, under `kl_exc_CL_off`:
> On an implementation whose `Zklmem` is trap-and-emulated, `kl_exc_CL_off` is also raised for every `kl.load` and `kl.store`, with the priority of the first group of illegal-instruction grounds.

Discovery: add one read-only bit to `klmarchid`-adjacent ID state, or define `kl.avail` to report `Zklmem` as available-by-emulation, so that software can choose between `kl.mv` and `kl.load` paths without trapping.

Advantages:
* No new cause and no new delegation bit.
* It works unchanged under H: `hedeleg` for the cause is already read-only zero.
* Delegation of cause 2 is untouched, so Linux keeps its SIGILL behavior for genuinely illegal instructions.

Cost: the handler must decode the instruction to tell the two cases apart. It must already do so to emulate it, so the cost is one comparison.

Compatibility with other text:
* SGR/IRR rules that name `kl_exc_CL_off` as exempt for some accesses do not apply, because the exception here is raised before any CL state is consulted. State this in one sentence.
* The context-switch order is unchanged, because an emulated `kl.load` is serviced entirely in M-mode.

**(c) Keep illegal-instruction, and specify forwarding.** Keep cause 2, but replace the `medeleg` requirement with a software contract:
> If cause 2 is delegated, the S-mode handler must forward an illegal-instruction trap whose instruction bits encode `kl.load` or `kl.store` to M-mode through the SBI (extension to be defined). Software discovers the need by …

This requires an SBI extension and a discovery bit. It adds two S→M round trips per instruction, and it relies on every OS doing the forwarding. It is weaker than (b) because a non-cooperating OS turns the instruction into SIGILL.

**(a) Reuse `kl_exc_unsupported`. Not suitable.** That cause is delegable, and it means that the *CL's Machine* is unsupported. Overloading it would send emulation requests to S-mode, recreating the defect.

**(d) Eliminate `kl.load`/`kl.store` for the trap-and-emulate case.** This is the new Group B item "Eliminate kl.load and kl.store?". If `Zklmem` becomes hardware-only, the emulation clause and M3 disappear. Software on a hart without hardware `Zklmem` uses `kl.mv` (Zklmv) or `kl.input`/`kl.output`. This is the simplest option. It costs code size only on platforms without KLV, where the import/export loop must fall back to GPR `kl.mv` forms.

**Recommendation.** Adopt (b) now, since it is a two-sentence change with no new allocation, and keep (d) as the Group B outcome if the TG prefers to remove the emulated path altogether. In either case delete "which requires `medeleg` bit 2 to be zero on such a platform" from unpriv 157.

### 8.5 M9 (deferred) — no change

The pseudocode diff in 8f46944 and 6071269 is whitespace and comments only. The M9 list stands as written. When the rewrite resumes, fix the Zklmem `bltu` sites first, because they make every Zklmem path skip the completing `kl.mgmt`.

### 8.6 Summary

* Closed: M1, M4, M6, M8, and the minors marked **FIXED** (m7 included, see 8.1).
* Closed once the WARNING is deleted: C2.
* One sentence remaining: M7.
* Rule updates remaining: M5 (IRR1, SGR20, Error-State table, priv 281).
* Open with concrete text above: C1, M2, M3.
* Deferred: M9.
* New defects introduced by the edits:
  * the contradicting C2 WARNING
  * the stray review bullets in §`kl.derive`
  * the inverted SKID rule
  * `klce.clone`
  * the PCCC expansion
  * RO/MRW/HRW on read-only ID CSRs
  * the typos listed above

The verdict moves from **NOT READY** to **NOT READY, close**. Once C1 items 1–4, the C2 WARNING, M2 and M3 are fixed, the remaining items are editorial, apart from M9, which can ship with the chapter marked informative.
