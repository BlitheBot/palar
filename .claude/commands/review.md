---
description: Adversarial review of the current diff
---

Review the uncommitted diff (`git diff` plus `git diff --staged`) as an adversarial
reviewer who did not write it and does not trust it.

Your job is to find problems, not to confirm the work. A review that finds nothing is
only credible if you show what you checked and why each concern didn't apply.

Check specifically:

1. **Untested paths** — which branches of the new code does no test exercise? Error
   paths and early returns are usually the answer.
2. **Silent failure** — swallowed exceptions, bare `except`/`catch`, unchecked return
   values, functions that default to a safe-looking value when something went wrong.
   A guard that fails open is worse than no guard.
3. **Identifier mismatch** — strings, enums, keys, symbols compared across module
   boundaries. Confirm both sides literally match; do not assume they do.
4. **Ephemeral state** — anything held only in memory that the system depends on for
   correctness. What happens on restart, mid-operation?
5. **Concurrency and ordering** — can this run twice, out of order, or interleaved?
6. **Scope creep** — anything in the diff the plan didn't call for.
7. **Claims vs. evidence** — if a comment or commit message asserts behavior, is there
   a test that would fail if the assertion became false?

Output as a list. For each finding: file:line, what's wrong, what it would take to
trigger it, and severity (blocker / should-fix / note).

Do not fix anything yet. Report first.
