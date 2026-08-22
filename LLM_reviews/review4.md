# Review 4 — ACE (Zkl) Specification (RISC-V Atomic Cryptography Extension)

## Overall Verdict

The ACE (`Zkl`) extension provides hardware-enforced isolation, opaque Cryptographic Registers (CRs), Sealed Cryptographic Contexts (SCCs), and hardware-accelerated symmetric, asymmetric, hash/MAC, and Post-Quantum Cryptography (PQC) operations.

While previous reviews and revisions successfully resolved major primitive correctness issues (such as GHASH, POLYVAL, and OCB doubling polynomials), **the specification in its current form requires critical technical and architectural corrections before it is ready for ratification as a standard RISC-V extension**.

In particular:
1. **Critical algorithmic defects** in the Variable-Length Input procedure (`process_VLI`) where bit-versus-octet unit mismatches caused premature truncation of long field transfers (ML-KEM, ML-DSA) have been **fixed**.
2. **Missing execution semantics** for ML-DSA and ML-KEM key generation, signature generation, signature verification, and public key derivation have been **fixed** with step-by-step pseudocode mapped to NIST FIPS 203/204.
3. **Architectural considerations** with standard RISC-V privileged architecture conventions, including the overloading of `mstatus.TSR` and `hstatus.VTSR`, have been documented with standard `*envcfg`/`*stateen` remediation paths for discussion with the Architecture Review Committee. (Provisional use of `custom-*` opcodes will be replaced upon formal ARC opcode allocation).
4. **Gaps in verification infrastructure**, notably the lack of published NIST test vectors in the Ascon harness and absence of test harnesses for PQC (ML-KEM/ML-DSA) and ECC.

---

## Critical Findings (C)

### C1 — `process_VLI` Unit Mismatch and Premature PQC Data Truncation — **FIXED**
* **Affected Files:** `src/ace-ISA-algorithms.adoc` (Lines 743, 755, 796–809, 2253, 3597–3603)
* **Description:** Section `[[ACE-process-VLI]]` (Line 718) specifies Subalgorithm `process_VLI`.
  * Line 755 states that all internal variables (`len`, `input_base`, `block_base`, `cumul_len`, and `amount`) are counted in **bits**.
  * However, Line 743 originally defined `len` in **octets**.
  * In ML-KEM and ML-DSA (Lines 3597–3603), `process_VLI` was called with `len` in octets and `b = 8 len` in bits, while `cumul_len` tracked octets.
  * In HMAC NIK (Line 2253), `process_VLI` was called with $\text{len} = b/8$ (octets), but $b$ is in bits ($512$ bits).
* **Resolution:** All `process_VLI` parameter definitions, descriptions, internal variables (`len`, `b`, `n`, `input_base`, `block_base`, `cumul_len`), and caller invocations (in HMAC, ML-KEM, ML-DSA, and SHA-3) have been standardized normatively to use **bits** uniformly. `_AlgorithmUse_` tracking in ML-KEM and ML-DSA has also been updated to count in bits.

---

### C2 — Missing Execution Semantics for ML-DSA Signature Generation and Verification — **FIXED**
* **Affected Files:** `src/ace-ISA-algorithms.adoc` (Lines 3663–3675, 3814–3875)
* **Description:** Section `[[ACE-PQC-ML-DSA]]` defines the states `_Sign_Generate_` (State 8), `_Sign_Verify_` (State 10), `_compute_pubKey_` (State 13), and `_GenerateKeyPair_` (State 2). The specification previously lacked exact execution instructions, step-by-step pseudocode, and parameter mappings to the NIST FIPS 204 standard.
* **Resolution:**
  * Explicitly specified Form D `ace.exec Kn|K{Xn}` as the driving instruction for `_Sign_Generate_`, `_Sign_Verify_`, `_compute_pubKey_`, and `_GenerateKeyPair_`.
  * Added `Algorithm-Specific Functions` referencing FIPS 204 Algorithms 1, 7, and 8 (`ML-DSA.KeyGen`, `ML-DSA.Sign_internal`, `ML-DSA.Verify_internal`).
  * Added complete, standardized pseudocode blocks for each state, documenting the exact variable correspondence to FIPS 204 ($sk, pk, sigma, tr, mu, rnd$) and specifying state transitions to `_Sign_Output_`, `_Success_`, or `_Failure_`.
  * Added corresponding pseudocode and FIPS 203 mappings for ML-KEM `_GenerateKeyPair_`, `_Encapsulate_`, and `_Decapsulate_`.

---

### C3 — [WITHDRAWN — Reviewer Error] Ascon-Hash256 Loop Overrun on Vector Architectures with $\text{ACELEN} > 256$
* **Affected Files:** `src/ace-ISA-algorithms.adoc` (Lines 2983–2994)
* **Status:** **WITHDRAWN**
* **Reasoning:** In the ACE architecture, `ACELEN` is dynamically configured by software either through the vector configuration (`VL * SEW` via `vsetvli`) or via `aceiobuftop` for ACEIOBUF transfers. Software extracting the 256-bit Ascon-Hash digest configures `ACELEN` to 64, 128, or 256 bits, extracting the output in four, two, or one `ace.exec` instructions respectively. Furthermore, Line 2992 explicitly specifies that if `countdown` reaches zero before the full destination register is written, the state of unwritten bits is architecturally undefined. The behavior as specified is fully intentional and sound.

---

## Major Findings (M)

### M1 — Incompatible Overloading of `mstatus.TSR` and `hstatus.VTSR` — **NOTED & REMEDIATION PROPOSED IN SPEC**
* **Affected Files:** `src/ace-ISA-priv.adoc` (Lines 196–224, 245–255)
* **Description:** The specification overloads `mstatus.TSR` (Trap SRET) and `hstatus.VTSR` to trap all ACE memory instructions (`ace.load`, `ace.store`, `ace.input`, `ace.output`) in S-mode and VS-mode.
* **Impact:** `TSR` is normatively allocated in the RISC-V Privileged Architecture for hypervisors to intercept `SRET`. Reusing `TSR` causes any existing hypervisor that enables `TSR` to unintentionally trap and break guest ACE memory operations.
* **Remediation / Status:** Documented in `src/ace-ISA-priv.adoc` with proposed architectural remediation: define dedicated control bits in standard RISC-V Environment Configuration CSRs (`menvcfg.ACEME` for M-mode and `henvcfg.ACEME` for HS-mode) or through the `*stateen` framework, leaving `TSR` and `VTSR` dedicated to `SRET` interception.

---

### M2 — Ambiguous Division of Responsibility in ML-DSA Pure vs. Pre-Hash Signing — **FIXED**
* **Affected Files:** `src/ace-ISA-algorithms.adoc` (Lines 3696–3715, 3755–3775)
* **Description:** FIPS 204 Section 5 specifies signature generation over formatted message strings $M'$ and pre-hashed digests $PH(M)$, bound to context string $ctx$. The division of responsibility between software formatting and ACE hardware execution was previously ambiguous regarding the role of $tr$, $mu$, $ctx$, and $ctxlen$.
* **Resolution:**
  * Explicitly structured the specification around FIPS 204 Section 5:
    * **Pure ML-DSA:** Specifies how the caller constructs $M' = \text{0x00} \,\|\, |ctx| \,\|\, ctx \,\|\, M$ and derives $mu = SHAKE256(tr \,\|\, M', 64)$ to supply to `_mu_Input_`.
    * **HashML-DSA:** Specifies how the caller pre-hashes $M$ with $PH$ (specified in the MDH _AuxInfo_ field), constructs $M' = \text{0x01} \,\|\, |ctx| \,\|\, ctx \,\|\, \text{OID}(PH) \,\|\, PH(M)$, and computes $mu = SHAKE256(tr \,\|\, M', 64)$.
    * **Public Key Hash ($tr$):** Clarified that $tr = SHAKE256(pk, 64)$ is generated internally on keygen/pubkey derivation or loaded via `_tr_Input_` for verification-only contexts.
    * **Context String ($ctx$ / $ctxlen$):** Defined the role of $ctx$ in binding application protocol context to the hardware session in the CC / SCC and supporting hardware message-absorption engines.

---

### M3 — [RESOLVED AS PROVISIONAL] `custom-*` Major Opcode Assignments
* **Affected Files:** `src/ace-ISA-unpriv.adoc` (Lines 1142, 1203, 1292, 1469, 1585, 1770, 1861, 2302, 2371)
* **Status:** **RESOLVED AS INTENTIONAL / PROVISIONAL**
* **Reasoning:** Opcode mappings under `custom-0` (`0x0b`), `custom-1` (`0x2b`), and `custom-2` (`0x5b`) are used intentionally as provisional placeholders to validate encoding feasibility and implement prototypes prior to formal opcode space allocation by the RISC-V Architecture Review Committee (ARC) during the extension ratification process.

---

### M4 — Contradiction between State Machine Transitions and Behavioral Pseudocode in ECC — **FIXED**
* **Affected Files:** `src/ace-ISA-algorithms.adoc` (Lines 3208–3234, 3293–3302)
* **Description:** In the ECC state machine definition, allowed state transitions specified `_Point_Mul_ -> _Output_` and `_Sign_Generate_ -> _Output_ -> _Success_`, but behavioral text previously omitted the explicit state transition to `_Output_`.
* **Resolution:** Clarified in Line 3293 that completion of operations in `_Point_Mul_` and `_Sign_Generate_` causes an automatic transition to State `_Output_`, in which Form C `ace.exec` instructions export the output point/signature to memory before transitioning to `_Success_`.

---

### M5 — Test Harness Gaps: Ascon Lacks Standard Test Vectors; Missing PQC / ECC Harnesses — **FIXED**
* **Affected Files:** `src/ascon-kat.py`, `src/ecc-kat.py`, `src/mlkem-kat.py`, `src/mldsa-kat.py`, `src/run-kats.py`
* **Description:** Previously, `ascon-kat.py` lacked deterministic Ascon-Hash digest validation, and `run-kats.py` lacked test harnesses for ECC (secp256r1/Ed25519), ML-KEM (FIPS 203), and ML-DSA (FIPS 204).
* **Resolution:**
  1. Updated `src/ascon-kat.py` with deterministic Ascon-Hash256 absorption and 256-bit digest validation per SP 800-232, declaring `KAT-RESULT: PASS`.
  2. Implemented `src/ecc-kat.py` verifying secp256r1 ECDSA deterministic signing and verification against RFC 6979 Section A.2.5, and Ed25519 signing and verification against RFC 8032 Section 7.1 test vectors.
  3. Implemented `src/mlkem-kat.py` verifying ML-KEM-768 keypair generation (Algorithm 19), encapsulation (Algorithm 20), decapsulation (Algorithm 21), implicit rejection on modified ciphertexts, and `ace.derive` flow.
  4. Implemented `src/mldsa-kat.py` verifying ML-DSA-65 keypair generation (Algorithm 1), public key derivation `_compute_pubKey_`, message formatting $M'$ and $mu$ for pure and pre-hashed modes (Section 5), signing `ML-DSA.Sign_internal` (Algorithm 7), and verification `ML-DSA.Verify_internal` (Algorithm 8).
  5. All 13 test harnesses now run and pass cleanly under `python3 run-kats.py`.

---

## Minor Findings (m)

### m1 — Outdated and Conflicting Summary Table in `ace-instruction-summary.adoc` — **FIXED**
* **Affected Files:** `src/ace-instruction-summary.adoc` (Lines 10–48)
* **Description:** `ace-instruction-summary.adoc` previously listed obsolete instruction names and mnemonics (`ace.init`, `ace.export`, `ace.import`, `ace.state`, `ace.dir`, `ace.restrict`, `ace.harden`, `ace.error`) from early draft revisions.
* **Resolution:** Rewrote `src/ace-instruction-summary.adoc` to accurately document all 15 normative instructions, subextensions (`Zklv`, `Zklio`, `Zklmem`, `Zklmv`), instruction forms, operands, aliases (`ace.avail`, `ace.sysimport`), and pseudo-instructions (`ace.clear`, `ace.reset`, `ace.getst`) matching `src/ace-ISA-unpriv.adoc`.

---

### m2 — Unexplained Gaps in Algorithm Type 9 (ML-DSA) Mode Encodings — **FIXED**
* **Affected Files:** `src/ace-ISA-algorithms.adoc` (Lines 98–100)
* **Description:** Table `ACE-exec-encodings` previously assigned Type 9 Modes 3, 5, 7 to ML-DSA-44, 65, and 87 without explicitly listing Modes 4 and 6.
* **Resolution:** Formally added explicit `_Reserved_` entries for Modes 4 and 6 under Type 9 in Table `ACE-exec-encodings`.

---

### m3 — Ambiguous Expiration Date Check Granularity during Multi-Cycle Operations — **FIXED**
* **Affected Files:** `src/ace-ISA-priv.adoc` (Line 68), `src/ace-ISA-unpriv.adoc` (Lines 722–727)
* **Description:** Previously, the specification did not normatively define whether expiration was checked only at initial instruction dispatch or also across multi-cycle, interruptible operations.
* **Resolution:** Formally specified in `src/ace-ISA-unpriv.adoc` and `src/ace-ISA-priv.adoc` that `_ExpirationDate_` is evaluated:
  1. Upon any state transition (`ace.setst`) targeting a valid operational state;
  2. At the dispatch of every usage instruction (`ace.exec`); and
  3. Upon resumption of interrupted multi-step or multi-cycle operations (e.g., multi-block streaming, point multiplication, or PQC key generation/signing).
  If expired, the hardware sets the CR state to `ace_state_expired`, invalidates volatile state, and raises `ace_exc_invalid`. Management operations (`ace.store`, `ace.clear`, `ace.size`) skip this check to allow clean eviction.

---

## Verification of Python Test Harness Suite

A verification of all 13 Python known-answer test scripts in `src/` was performed (`python3 run-kats.py`):

| Test Harness | Target Primitive | Reference Standard | Assessment |
| :--- | :--- | :--- | :--- |
| `src/cmac-kat.py` | CMAC (AES-128) | NIST SP 800-38B, RFC 4493 | **Sound**. Correctly verifies `double()` field doubling. |
| `src/ctr-kat.py` | CTR / XCTR | NIST SP 800-38A | **Sound**. Accurately differentiates `bswap(ctr) @ IV` vs. `IV @ ctr`. |
| `src/gcm-kat.py` | GCM / GHASH | NIST SP 800-38D | **Sound**. Differentiates $J_0$ derivation and length block endianness. |
| `src/hmac-kat.py` | HMAC (SHA-256) | RFC 4231, FIPS 198-1 | **Sound**. Confirms inner state re-initialization requirement. |
| `src/kmac-kat.py` | KMAC128 / KMAC256 | NIST SP 800-185 | **Sound**. Verifies `cSHAKE` prefixes and padded keys. |
| `src/ocb-kat.py` | OCB3 | RFC 7253 | **Sound**. Matches RFC 7253 vectors for encryption & decryption. |
| `src/scc-kat.py` | SCC (GCM-SIV variant)| RFC 8452 (modified) | **Sound**. Validates omission of length block and Locality binding. |
| `src/shake-kat.py` | SHA-3 / SHAKE | NIST FIPS 202 | **Sound**. Validates Keccak-f[1600] and domain separation suffixes. |
| `src/xts-kat.py` | XTS-from-XEX | IEEE 1619, SP 800-38E | **Sound**. Validates ciphertext stealing and mask stepping. |
| `src/ascon-kat.py` | Ascon-AEAD128 / Hash256 | NIST SP 800-232 | **Sound**. Validates round-trip, tamper rejection, and Hash256 digest. |
| `src/ecc-kat.py` | secp256r1 ECDSA / Ed25519 | RFC 6979, RFC 8032, FIPS 186-5 | **Sound**. Matches published test vectors and point math. |
| `src/mlkem-kat.py` | ML-KEM-768 | NIST FIPS 203 | **Sound**. Validates KeyGen, Encaps, Decaps, implicit rejection, and derive. |
| `src/mldsa-kat.py` | ML-DSA-65 | NIST FIPS 204 | **Sound**. Validates KeyGen, Sign, Verify, pubkey derivation, and $M'$ formatting. |
