# Audit scope — what was examined, and what was not

This page exists because the thing that discredits a security audit fastest is
not a finding: it is a reader discovering an unexamined surface that the document
never mentioned. `AUDIT_HARSH.md` assessed 62 findings without ever stating its
own boundary, and two of this project's **live, publicly reachable HTTP
surfaces** were absent from it entirely.

So the boundary is stated first, in full, including the parts that come off
badly. Every component directory tracked in this repository appears below.
`scripts/audit_gate.py` fails if one is added and not listed here.

**Provenance: this is a self-audit.** It was produced by the same people and
tooling that wrote the code. That is the weakest form of assurance and a reader
should discount it accordingly. It is recorded here rather than left for a
reviewer to work out.

**Adjudicated against** the `pinned_sha` in
[`findings.json`](./findings.json). A verdict here is anchored to that tree, not
to whatever `main` is when you read this.

## Coverage

`routes` counts HTTP route decorators — the externally reachable surface, and the
first thing an attacker and a reviewer both look at.

| Component | LOC | routes | Examined | Notes |
|---|---:|---:|---|---|
| `server` | 121,281 | 221 | ✅ yes | Primary subject. 87 references across the findings. |
| `agent` | 80,303 | 73 | ✅ yes | Sovereign runtime, key handling, signing. 48 references. |
| `infra` | 6,945 | 0 | ✅ yes | Compose, migrations, DB roles. 24 references; source of C3, C4, C14. |
| `index` | 1,437 | 6 | ✅ yes | Lean index write surface. 22 references; source of C12. |
| `smb_funnel` | 6,246 | 0 | ◐ partial | 9 references, all via C7 (`innerHTML` recovery phrase). No systematic pass. |
| `renderer` | 3,081 | 0 | ◐ partial | 7 references. Output encoding touched via C5/C7 only. |
| `skill` | 2,719 | 0 | ◐ partial | 7 references. Signed-skill trust path not examined end to end. |
| `orrery-up` | 768 | 0 | ◐ partial | 3 references. Installer secret generation only. |
| `smb_host` | 6,169 | 6 | ✅ yes | Examined 2026-09-12. Was zero-reference. Produced **H14** (unauthenticated, unbounded, unrated `/book`). Six checks held up — see the finding. |
| `smb_signup` | 1,520 | 5 | ✅ yes | Examined 2026-09-12. Carries a per-source rate limit and holds the provisioning token; its limiter is bypassable by addressing `smb_host` directly — recorded in H14. |
| `mcp_server` | 1,286 | 0 | ❌ no | Zero references. No HTTP surface; reachable via MCP transport. |
| `conformance` | 6,783 | 0 | ❌ no | 1 incidental reference. Test-only; not a deployed surface. Low priority, but unexamined. |
| `scripts` | 7,917 | 0 | ❌ no | 1 incidental reference. Operator tooling handling credentials; runs outside the served product. |

## What the gaps mean

**The two live public surfaces are now examined.** `smb_host` and `smb_signup`
were the material gap — 7,483 LOC and 11 HTTP routes on the deployed SMB path,
previously unmentioned. They were reviewed on 2026-09-12 and produced one High
finding (**H14**). The remaining ❌ entries are defensible and schedulable:
`mcp_server` serves no HTTP, `conformance` is test-only, `scripts` runs
operator-side rather than in the served product. `assets` holds the README's
animated SVG and nothing that is served or executed; it is not a component.

**Partial (◐) means touched incidentally, not assessed.** Those components appear
in the findings only because some other finding reached into them. A reader
should treat ◐ as unexamined for any question they actually care about.

## Method

Stated so a reader can judge the findings rather than trust them.

- **Type:** manual and model-assisted source review, plus live probing of the
  deployed mesh. Not a penetration test; no fuzzing, no dependency CVE sweep, no
  runtime instrumentation.
- **Adversary assumed:** an unauthenticated internet caller, and a registered
  member acting outside their authority. Not assumed: a malicious operator with
  database access, or a compromised host.
- **Evidence standard:** a finding marked `fixed` or `mitigated` must cite a path
  that exists. The stronger standard — a regression test that fails when the fix
  is reverted — is the target, and `findings.json` records which findings meet it
  today. Most do not yet.
- **Not covered by any status:** dependency supply chain, container image
  contents beyond C14, and the deployed Railway configuration as distinct from
  the Compose defaults described here.

## How to re-derive this table

**The figures describe the pinned tree, not HEAD.** They have to: a coverage
table beside verdicts reached against `pinned_sha` would otherwise describe a
tree those verdicts were never about. So re-deriving at HEAD is expected to
disagree with this page whenever `main` has moved on, and that disagreement is
not an error.

This was not always enforced, and the table drifted from its own anchor: on
2026-09-14 five of thirteen rows disagreed with the pinned tree, `index` by 34%
(1,073 listed against 1,437 actual). A reader running the commands below got
different numbers than the page showed — the exact credibility failure this page
exists to prevent. The figures now live beside `pinned_sha` in
[`findings.json`](./findings.json) under `coverage`, and `scripts/audit_gate.py`
fails when this table disagrees with them.

```bash
# Regenerate the coverage block at pinned_sha, and list the rows to edit here.
# Needs full history; refuses rather than falling back to HEAD.
python scripts/audit_gate.py --rederive

# The whole thing, checked — including that this table matches the block.
python scripts/audit_gate.py --self-test

# Per component, against the CURRENT tree. Expect these to differ from the
# table above whenever HEAD has moved past pinned_sha.
git ls-files <component> | xargs wc -l | tail -1          # LOC
grep -rhoE '@(app|router)\.(get|post|put|patch|delete)\(' <component> | wc -l   # routes
grep -oiE '\b<component>\b' AUDIT_HARSH.md | wc -l        # audit references
```
