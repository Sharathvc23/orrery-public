### The rename was recorded as finished, and the prose kept drifting back

The product-facing noun became **org**. The runtime completed that rename — the
install wizard asks for an "org display name" and the environment variables are
`ORG_*` — and the rule was written down in `CONTRIBUTING.md` and `docs/README.md`:
user-facing text says org, and the retired word survives only as a frozen wire id
or an internal module name. Nothing enforced it. Thirty occurrences of the
retired noun were standing in prose across sixteen files, four of them in a
changelog entry written days ago, after a release sign-off had already recorded
the rename as complete.

All thirty are corrected. The frozen wire ids are untouched and were never the
problem: `chapter_id`, the `/api/chapter/*` routes, the event topics, the
`chapter_keys` table and the `chapter_agent.py` module keep their names, because
they are contractually unable to change and naming them correctly is not drift.

`scripts/org_vocabulary_gate.py` now enforces the rule, as a fourth sibling of
the three existing gates and on the same one-failure-mode-per-gate principle.
Its whole content is a discrimination rule — the word is legitimate inside code,
in identifier shape, as the protocol's own name `Chapter Protocol`, and inside
quotes where it is being mentioned rather than used — so showing that it fires
proves only half of it. Every run therefore also plants both directions into a
real tracked file and requires the drift to be caught at its line and the four
legitimate forms beside it to be ignored.

There is no file allowlist, deliberately. The escape hatch is quoting, which is
visible at the point of use; a skip-list entry is invisible there and permanent
everywhere. The gate's own documentation page had to use it, since that page
necessarily contains the constructions it describes.
