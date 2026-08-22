WARNING: This email originated from outside of Qualcomm. Please be wary of any links or attachments, and do not enable macros.

You did beat me to it! Great!

I'll re-add Leonidas to the mail so that we don't lose members. Someone
please find Jan's email and add him as well.

You have access to Fable? How? Are you paying the extra credits, or are
you in the super expensive plan? I only have access to lowly Opus 5.

Anyhow, quick thoughts on my part:

> **C1. The SCC import authentication check is inoperative.**
> `src/ace-ISA-unpriv.adoc:2853-2857`. The decryption routine computes
> `s ← POLYVAL(auth_key, AD @ P, ...)` and `tmp[95:0] ← s[95:0] xor
> N[95:0]`, then immediately overwrites the result: `tmp ← AESE(enc_key,
> 0 @ SIV[126:0])`. The candidate tag is therefore a function of the
> received `SIV` alone, not of the decrypted content, the MDH, or the
> Locality Secrets. The comparison `tmp != SIV` verifies nothing about
> the payload (and as written would also reject valid SCCs). Since
> `ace.mgmt #ace_CR_import_end` is defined by reference to this
> function, the integrity of every imported context rests on it.
> *Resolution:* compute the tag from `s` — `tmp ← AESE(enc_key, 0 @
> tmp[126:0])` — and add RFC 8452 known-answer vectors so the defect
> cannot recur silently.

This is a typo I claimed to fix that was also caught by my run. I can
open a PR and fix it.

> **C5. Debug mode may use every resident context by default, and
> nothing is zeroized on debug entry.**
> [snip]
> **C6. SCCs have no anti-replay, so re-import rolls algorithm state
> back and reuses keystream.**
> [snip]
> **C7. Registers are shared across privilege modes while management
> instructions are not usage-controlled, permitting context
> substitution.**

We know this and it is by design. I guess the one that pops out the most
the anti-replay protection. However, I don't recall we ever stated that
anti-replay is part of the security model.

Non-issues IMO.

> **C8. Verbatim export of a partially configured register can dump
> generated or system key material in the clear.**
> [snip]
> *Resolution:* require that random generation and SKS materialization
> occur only at `ace_CR_provision_end`, and forbid verbatim export of
> any register holding material the exporting context did not supply.

I though we had solved this when we added the move instruction. It may
not be clear in the text as the AI points out.

> **C9. Write-only secret CSRs are writable by the mode below the one
> that must manage them, making hypervisor save/restore and VM migration
> impossible.**
>
> ### Instruction definitions
> **C10. `ace.mv`'s encoding and description specify opposite data
> directions.**
> **C11. `ace.exec` Forms B and D leave the register index
> unencodable.**

Good point and easily fixable.

> **M6. A usage-policy violation destroys the context, giving any
> lower-privileged mode a cross-domain kill primitive.**

I don't think the security model ever claims availability, however this
is a true DOS.

> **M11. `ace.derive` has no restriction-inheritance rules.**
> **M12. `ace.clone` does not state that policy metadata is copied, and
> is not usage-controlled.**

Fair point.

> **M17. `mstatus.TSR` and `hstatus.VTSR` are overloaded to trap ACE
> memory instructions.**

This is no longer true. I thought we removed this.

> **M18. No `Smstateen`/`Ssstateen` integration for the new
> less-privileged state.**
> **M20. Behavior of ACE CSR accesses when ACES=Off is unspecified.**
> **M25. Trap-and-emulate has no effective-privilege mechanism, and
> hypervisors are forbidden from emulating.**
> **M26. Trap behavior beyond cause numbers is undefined.**

Fair points.

I need to get back to work but my overall impression is that the
feedback, for the most part, hits a lot of good points.

--
Lipe
