<!--
Keep this short and honest. See CONTRIBUTING.md for the ground rules.
Delete sections that don't apply.
-->

## Summary

<!-- One paragraph: what changed and why now. The diff shows the "what" — focus on intent. -->

## Test plan

<!-- How you verified it. Concrete commands or CI jobs, not "it works". -->

- [ ] Relevant server/agent tests pass (`pytest`)
- [ ] `ruff` + `mypy` clean on touched packages
- [ ] For a runtime change: exercised the affected surface (curl / `orrery-up` / e2e probe) — describe how

## Checklist

- [ ] **No secrets in git** — no real `.env`, keys, tokens, or live control-plane detail; only `.env.example` placeholders.
- [ ] **Docs stay honest** — any capability claim added/changed in the docs matches merged code; `docs/CLAIMS.md` updated if a claim moved.
- [ ] **Vocabulary** — user-facing text says *org* / *agent*; `chapter` only where it's a frozen protocol field.
- [ ] **No new protocol here** — new primitives belong in their own `sm-*` repo, composed as a pinned dependency.
- [ ] **Frozen wire ids untouched** (event topics, `chapter_id`, schema `$id`s) unless this is a deliberate, versioned change.

## Out-of-band actions

<!-- Anything that must happen outside the merge: a redeploy, a pin bump, a schema/vector regen. Omit if none. -->
