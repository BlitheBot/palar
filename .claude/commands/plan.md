---
description: Write an implementation plan and stop before coding
---

Plan this work. Do not write implementation code in this turn.

Task: $ARGUMENTS

First read enough of the codebase to know what's actually there — do not plan against
what you assume the structure is.

Then write `docs/plans/<short-name>.plan.md` containing:

**Goal** — one paragraph, what's true after this that isn't true now.

**Changes** — file by file. For each: what it does today, what it does after, why here
rather than somewhere else.

**Blast radius** — what currently works that this could break. Name the callers. If a
shared type, string constant, or schema changes, list every site that reads it.

**Verification** — the exact command that proves this worked, and what its output looks
like on success. If there isn't one, say so; that's a finding.

**Explicitly out of scope** — things you noticed and chose not to do.

**Open questions** — anything you had to guess. Guessing silently is the failure mode.

Then stop and wait for approval. Do not begin implementation, do not create stub files,
do not "get a head start."
