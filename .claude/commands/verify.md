---
description: Run the real checks and report only what actually ran
---

Verify the current state of the working tree. Run the commands; do not reason about
what they would output.

Run, in order, stopping to report if any fails:

1. `git status` — confirm what's actually changed
2. Typecheck
3. Lint
4. Full test suite
5. Build

If you don't know the exact command for this repo, look in `package.json`,
`pyproject.toml`, `Makefile`, or CI config. Ask rather than guess.

Then report:

**Ran and passed** — command, and the tail of its real output.

**Ran and failed** — command, the actual error, and your diagnosis. Do not fix it in
this turn unless I say so.

**Not run** — anything you skipped, and why. Label it "unverified."

Rules for this report:
- Every green checkmark must correspond to output you saw in this session.
- If the test suite has skipped or excluded tests relevant to the change, say so.
- If a test passes but wouldn't catch the bug it was written for, say so.
- Do not summarize as "all clean" if anything in the third section is non-empty.
