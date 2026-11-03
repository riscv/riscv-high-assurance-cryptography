# Comparison of the original and tightened chapters

The comparison found lost qualifications and unclear wording in the first tightened versions. These have been corrected. No remaining substantive loss, garbled sentence, awkward wording, or introduced ambiguity was identified in the reviewed changes.

The originals are the four chapter snapshots in `/private/tmp/zkl-concision-baseline/`, saved before tightening. The first tightened versions are in `/private/tmp/zkl-concision-audit/`. The review covered their 62 tightening hunks, the subsequent corrections, and the relocation of the State graph before its legend. Removed repetitions were checked against the governing Rules to confirm that their requirements, exceptions, check order, and rationale remain available through the references.

| Chapter | Corrections made during comparison |
|---|---|
| Unprivileged | Restored physical implementation freedom, simultaneous active CCs and configuration as needed, explicit CC constraints, and unconditional admission across State classes. Clarified the state each instruction may modify and the locker affected by narrowing. Restored the implementation-defined progress **format** and the prohibition on new input throughout a long-running operation. Corrected the overbroad claim that hardware prevents misuse, the nested-completion sentence, and the system-specific import note. |
| Privileged | Distinguished universally implemented exception causes from optional privileged support. Scoped KLS write ordering to Off, Initial, and Clean, and direct-write independence to distinct `*llockerstatus` registers. Made the lazy-loading handler's restoration duty explicit. |
| Machines | Preserved the mandatory final-block minimum in MR6 and scoped transfer-window checks to instructions with a window. Distinguished the fixed-width value consumed from `INPUT` from the input's size. Restored the explicit `kl.setst` action in MR10 and the separate management and restoration cases in MR17. Clarified output clearing and macro wording. |
| Software | Restored the single per-hart `klstart` explanation and clarified its failure cases. Preserved SR6's conditional save/write/restore duty and SR7's specific `kl_cfg_importing` exception. Scoped getter/setter use to `klstart` and `klnamedlocker`. Clarified routine subjects, nested use, and the handler's write of 32 to `klnamedlocker`. |

The consolidated privilege table preserves the original per-mode behavior: M has no per-locker fields in effect; (H)S uses `mllockerstatus`; VS and U use `mllockerstatus` and `sllockerstatus`; VU uses all three, where implemented. Off exemptions, Dirty updates, ownership, delegation, direct-write independence, and virtual CSR substitution remain intact.

The shorter instruction and Machine descriptions retain the details supplied by the cited Rules, including wrong-Form outcomes, fixed-width input handling, final-block processing, configured tag lengths, and output clearing. Examples and rationale remain present.

| Chapter | Original words | Final words | Reduction |
|---|---:|---:|---:|
| Unprivileged | 41,170 | 40,640 | 530 |
| Privileged | 6,146 | 5,884 | 262 |
| Machines | 47,954 | 47,455 | 499 |
| Software | 12,846 | 12,579 | 267 |
| Total | 108,116 | 106,558 | 1,558 |

Verification passed:

- All 411 source anchor occurrences and their labels are preserved, including Rule labels.
- Chapter headings, code blocks, encoding diagrams, image directives, and the sets of cited external sources are preserved.
- All 3,015 active local and page references in `modules/ROOT/pages/` resolve.
- `python3 scripts/check-cross-page-refs.py`, `git diff --check`, and `git diff --cached --check` pass.

This is an editorial equivalence review of the changed passages. It does not establish a formal proof or re-audit unchanged ISA semantics. Rendered output was not checked because Asciidoctor is unavailable.
