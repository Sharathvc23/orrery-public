# L2 — the open admin page, and the gate behind it

**Design note. No implementation.** L2 stays `residual` in
[`findings.json`](./findings.json). Facts are from `server/chapter_agent.py`,
`server/auth_verify.py`, `server/admin.py`, `server/csp.py` and
`server/static/admin/index.html` as of 2026-09-14.

## The finding holds, and it is the least interesting thing here

`/admin`, `/admin/`, `/admin/index.html` and `/admin/pico.min.css` are in
`ADMIN_OPEN_PATHS`. The page is a 274-line shell that prompts for a token and
attaches it to `/admin/api/*` calls. A paste-your-token page cannot be gated on
the token it exists to collect, and a public login page is the industry norm:
Django's `/admin/`, Grafana, GitLab and Keycloak's admin console all serve one
unauthenticated. Nobody hides the login page, because the path is guessable
whether or not you serve it.

The reconnaissance is also priced correctly. The page names three endpoints
(`/admin/api/status`, `/admin/api/members`, `/admin/api/members/`) and tells a
reader the token lives in `.org-admin-token` or `ORG_ADMIN_TOKEN` and is printed
once at startup. That is an operational hint sheet, slightly more than "an admin
surface exists", and still low.

And the credential is strong. `secrets.token_hex(32)` is 256 bits;
`verify_admin_token` uses `compare_digest` on encoded bytes and returns `False`
for an unset token so a misconfigured org cannot authenticate against an empty
credential. Guessing is not the threat.

So accepting L2 as written is right. What the research turned up is that the
sentence used to justify it — the data surface at `/admin/api/*` requires the
token — is true today by convention, and nothing checks it.

## What is actually load-bearing: a handler-side gate no guard enumerates

At the middleware boundary, `auth_verify.is_open_path` classifies the entire
admin API as open:

```python
if is_admin_api_path(path):
    return True
```

Authentication is delegated to each handler. Measured against the running app:

| | count |
|---|---:|
| `/admin/api/*` routes served | 16 |
| classified open by the middleware | 16 |
| gated in-handler today | 16 |
| covered by the route-enumeration guard | **0 → 16** |
| declared in any class of that guard | 0 (not the mechanism used — see below) |

All 16 were gated when this was measured — 14 through `_authorize_admin`, 2
through `_require_admin` — so there was no live hole. The gap was that nothing
would notice a 17th that forgot. **Closed 2026-09-14** by
`server/tests/test_admin_route_gate_coverage.py`; the rest of this section
records why the gap existed, and the section after it records what the guard
does.

`test_route_auth_classification.py` is the guard that would normally catch this.
It walks `chapter_agent.app.routes` so "a route cannot hide from it by being
added", and it requires every anonymously-reachable route to be classified as
handler-gated, intentionally public, or an explicit backlog entry. But it
selects on a *third state* — `is_open_path` False **and** `requires_auth`
False — and `/admin/api/*` returns `is_open_path` True. The admin API is not in
the third state, so the scan skips all 16.

The other candidate, `test_admin_api_authz.py`, runs three adversarial
assertions (no credentials, signed non-admin, admin bearer) against a
hand-listed `ENDPOINTS` table holding **two** entries, both under `/api/admin/trust/*` —
a different prefix from the 16.

Two gate helpers in use across those handlers is the ordinary way a third one
gets added and a call gets missed.

## What others do

Three patterns, and the first two are already Orrery's:

1. **Serve the login page publicly.** Universal. Not worth changing.
2. **Put the real control at the network layer.** Keycloak's `--hostname-admin`
   splits the admin console onto its own hostname so a reverse proxy can
   allowlist it; Grafana and Django deployments do the same with proxy rules or
   a VPN. This is operator configuration, not application code, and it belongs
   in deployment documentation.
3. **Offer a switch to not serve the admin UI at all.** The useful
   application-level control, and the one Orrery lacks.

Nobody moves the path to an unguessable one. That is theatre: it does not
survive a bundled asset reference, a log line, or a bookmark, and it trades a
real control for the appearance of one.

## Proposed design

**Do not change the open page.** It is correct as it stands.

**Close the enumeration gap — this was the work, and it is done.** See
"The guard" below.

**Add an org-level switch for serving the admin UI**, defaulting on to preserve
current behaviour, so an operator who fronts the org with their own tooling can
decline to publish the shell. Mirrors `ORRERY_LISTING_ENABLED`'s posture:
publishing a surface is a decision somebody makes.

**Document the reverse-proxy allowlist as the real hardening**, since it is,
and since an operator reading only the audit would otherwise conclude the
application has an answer it does not have.

## The guard

`server/tests/test_admin_route_gate_coverage.py`, landed 2026-09-14.

**Derived, not declared.** The route set comes from walking
`chapter_agent.app.routes` for the `/admin/api/` prefix, so a route cannot hide
from it by being added without touching the test file.

**Behavioural, not textual.** The note above considered asserting that each
handler *contains* a gate call. That was rejected: grepping for a marker string
accepts a gate whose deny path is broken, and two different helpers are already
in use — which is exactly how a third gets added and a call gets missed.
Instead every route is called over HTTP with no credentials and must answer
401/403, and called again with a *wrong* token and must answer 401/403. The
second assertion exists because a gate that checks the header is present rather
than verifying its value passes the first.

**A 422 is a failure, not a pass.** FastAPI validates a request body before
invoking the handler, so a POST with no body answers 422 without the gate ever
running. Counting that as a pass is how a guard becomes decorative. The test
carries a `REQUEST_BODIES` table of minimal valid bodies and fails any route
that 422s, naming the entry to add.

**A positive control.** `GET /admin/api/status` must return 200 with the correct
token. Without it, a server that denied every request for an unrelated reason
would satisfy all 32 denial assertions while proving nothing. It reads no
database, so the control cannot break for reasons unrelated to authorization.

**Plant-proved, not assumed green.** Three defects were planted and each
reddened the assertion meant to catch it:

| planted defect | caught by |
|---|---|
| `GET /admin/api/__planted_ungated__`, no gate | unauthenticated **and** wrong-token |
| `GET /admin/api/__planted_header_only__`, gate checks header presence only | **wrong-token only** — which is why that assertion exists |
| `POST /admin/api/__planted_body__`, ungated behind body validation | the 422 refusal, with the `REQUEST_BODIES` guidance |

The file is collected by directory in the `server` CI job, so a new guard beside
it cannot land unrun.

## A second-order note: the token lives in `localStorage`

`server/static/admin/index.html` stores the admin token under the key
`org_admin_token`, durably — it is removed only on an explicit forget or a 401.
A 256-bit system-level credential with no expiry, on the same origin as
`/console`, `/join` and `/receipts`.

This is currently defended by a real control rather than by luck: `csp.policy_for`
computes a per-document hash-based CSP, so `script-src` is `'self'` plus the
hashes of that document's own inline scripts. Injected inline script does not
execute. Recording it because the defence is a property of the CSP, not of the
storage choice, and a page added with a bare `FileResponse` would carry no CSP —
which `_static_page`'s docstring already warns about. Session-scoped storage, or
exchanging the token for a short-lived cookie, would make the storage safe on
its own terms. Out of scope for L2; noted so it is not rediscovered.

## Status

L2 stays `residual` — the open page is accepted and is not changing; that was
never the actionable half. The enumeration gap it led to is **closed**: a
planted `/admin/api/*` route that omits its gate now fails CI, demonstrated
rather than asserted.
