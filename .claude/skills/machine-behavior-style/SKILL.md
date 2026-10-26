---
name: machine-behavior-style
description: Rewrite a long paragraph in a KLE Machine's State Machine Behavior (Zkl-ISA-machines.adoc) into the house structure: entering / while in / leaving steps, one closing Invalid line, rationale moved to a NOTE. Use when asked to make a Machine description "structured", "concise" or "like 5.4.6".
---

# Restructuring Machine State Behavior text

The model is the State Machine Behavior of the `process_VLI` procedure (`<<KLE-process-VLI>>`), and the rewritten GCM and CMAC Machines.

## Shape

Split a paragraph by what happens when, one `**` bullet per moment, with numbered steps (`.`) under it:

- `** When entering State _X_:`
  1. the expected `kl.setst`, named by Form, immediate and auxiliary operand without the locker: "a Form B `kl.setst` with immediate `kl_state_x` and auxiliary operand `Xs`", and what `Xs` sets (`len <- Xs`);
  2. the admissible values, stated positively: "`Xs` must be a multiple of 8 with `8` {le} `Xs` {le} `120`". Don't list exclusions such as "zero, larger than 127, or not a multiple of 8";
  3. the entry operations (fields set or zeroed), in one step;
  4. same-State `kl.setst`: "repeats these operations…", or "is forbidden" (Rule GR23).
- `** While in State _X_,` or `** In State _X_, a single Form F ``kl.exec``…`: what the instruction does, as steps.
- `** When leaving State _X_:` one step per exit case (complete vs. incomplete, which `kl.setst` invalidates).
- For a choice of continuations, one bullet per purpose, gated in its heading:
  `** To output the CMAC where _MachinePolicy_[0] is set (Rule <<KLE-MGR-policy-gate>>):`, then three steps: the `kl.setst` that enters, the `kl.exec` that acts, the transition to _Success_/_Failure_.
- **All the conditions that lead to _Invalid_ go in one closing line**, after the steps (with a `+` continuation):
  "Any other `Xs`, a `KLLEN` smaller than `tag_len` (Rule MR6), or a same-State `kl.setst` into _X_ (Rule GR23) transitions the locker to Error State _Invalid_."
  Or, where the cases are several and parallel, a lead sentence: "The locker transitions to Error State _Invalid_ on:", followed by numbered cases.
- For a list of States that share an outcome, put the outcome in the lead and one State per step. Give each State its own reason only if a reason is kept.

## Content rules

- **Normative text stays in the step; rationale leaves it.** Move a justification ("since…", "because…", "so that…", "is what makes…") to a `NOTE:` after the algorithm, or delete it when the user says to trim. Keep Rule citations next to the normative sentence they support.
- **A normative definition that is not a step** (for example, the interruption points of a State) goes in a paragraph after the algorithm. If the user asks, it goes in a NOTE instead. Drop "therefore" once the sentence no longer follows the step it concluded.
- **Name operands precisely and never reuse a name.**
  - `Xs` is the auxiliary GPR of `kl.setst`; `INPUT`/`OUTPUT` are the `kl.exec` operands.
  - A length set by `kl.setst` is never `INPUT`.
  - Don't reuse a Parameter name (such as `t`) for a field; one quantity has one name, in the Internal State, the Serialized Content and the Behavior alike.
- **Remove restatements:** what another Rule already says (entry operations repeated in a same-State sentence, outcomes already covered by MR1 or GR19.c) becomes a citation or goes.
- **The usual citations:** MR1 (policy gate), MR6 (granularity, `KLLEN` limits), MR8 (fixed-width input), MR9 (clear the unwritten output), MR14 (load of a long field), MR12 (constant-time tag verification), GR23 (same-State `kl.setst`), GR64 (empty window).

## AsciiDoc mechanics

- Never write an instruction's operand syntax (`kl.setst Kn, …`, `kl.exec OUTPUT, Kn, INPUT`) in a Machine. Name the Form and describe the effect on the operands: "`kl.exec` instructions are expected to be of Form A, decrypting `INPUT` into `OUTPUT` as follows:"; a Form D `kl.exec` is just "a Form D `kl.exec`".
- Use `{le}`, `{ge}`, `{times}` and `<-` (inline). In listings use `←` and keep lines ≤ 80 characters.
- A NOTE, paragraph or open block placed after a step list *inside a list item* needs a `+` continuation line before it. Otherwise the list ends, and the next `**` bullet starts a new list.
- After editing, render and check: build `src/Zkl.adoc` with `--require=../scripts/cross-page-xrefs.rb` (no warnings), run `pypy3.12 scripts/check-cross-page-refs.py`, and, for a moved block, check in the HTML that it renders as `admonitionblock` and that no list closes early.

## Process

1. Re-read the passage (the user edits concurrently) and quote it exactly in the edit script, asserting it matches once.
2. Preserve the behavior exactly, or say what changed. If the semantics change, update the Machine's KAT under `src/kat` and run it.
3. Report the result as the new text, plus a short list of what moved, merged or was dropped.
