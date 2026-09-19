# Server-surface reality audit

Every capability the README / PRODUCT / API docs advertise for the **org
server**, driven against a hermetic `docker compose` stack (org + agent + a
second org) with real Ed25519 signing — no mocks. Each claim is either
**PROVEN** by a test that runs in CI, or a **filed + fixed** issue with a
regression test that fails-before / passes-after.

Audit run: main @ `6beb457`. Method: boot the stack, drive each
surface end-to-end, compare behavior to the documented claim.

## Claims → evidence

| Surface (documented claim) | Verdict | Evidence |
|---|---|---|
| `GET /health` liveness + build provenance | PROVEN | e2e sign-of-life; `test_version_endpoint_baked` |
| `GET /api/version` protocol/build | PROVEN | driven 200; part of the parity guard |
| `GET /.well-known/nanda-agent.json` signed identity | PROVEN | live 200 with did/registries/conformance keys |
| `GET /.well-known/conformance.json` signed, self-attested, boot-generated | PROVEN | `test_conformance_boot` + e2e badge probe; verified offline, `self-attested` label present |
| `GET /.well-known/agentfacts.json` | PROVEN | live 200; agentfacts facet exercised by the reputation probe |
| `GET /metrics` "gated by `METRICS_BEARER_TOKEN`" | **FIXED — That change** | compose never forwarded the var → gate inert (open in every real deploy). Now passed through; `test_deploy_surface_reality::test_metrics_*`, verified live (401 without / 200 with) |
| `GET/POST /api/org/config` one-time first-run | PROVEN | live `{configured, profile}`; 403-after-configured is the existing contract |
| `GET /api/portal/{chapter,layout}` A2UI data | PROVEN | live 200 |
| `GET /api/surfaces/{id}` + `/stream` (SSE) | PROVEN | e2e SSE probe (post-open event delivered); principal-private surfaces 401 as designed |
| `POST /api/members` TOFU register | PROVEN | e2e + reputation/quilt probes register real members |
| `POST /api/members/rotate` | **FIXED — That change** | returned HTTP 200 on every failure (bad fields, rejected attestation). Now 400 / 401 / 200; `test_deploy_surface_reality::test_rotate_*`, verified live |
| `POST /api/receipts` signed ingest → reputation | PROVEN | receipt→reputation e2e: corroborated receipt moves the 0.2 score; un-cosigned gated |
| `GET /api/federation/divergence` keyless findings | PROVEN | e2e divergence probe (keyless, well-formed) |
| `POST /api/federation/peers/{id}/{block,forget}` leader-gated | PROVEN | `test_peer_prune` (forget + auto-prune + gate) |
| quilt: `/sm-bridge/{index,resolve,deltas}` cross-org | PROVEN | e2e quilt probe (index→resolve→delta feed) — the empty-delta-feed bug was fixed in the flagship-loop suite |
| `/api/subscriptions/*` event bus | PROVEN | e2e SSE probe + signed CRUD driven in the audit |
| `/api/skills/*` publish/list | PROVEN | live 200 list |
| disclosure `/api/local/disclose`, AAE `/api/local/aae/audit` — agent surfaces | PROVEN | e2e disclosure (offline-verified) + AAE probes |
| **`POST/GET /api/calls/*`** "open calls" | **FIXED (doc) — That change** | no such route (404). Removed from API.md; parity test guards it |
| **`/api/nominations/*`** | **FIXED (doc) — That change** | no route; `/api/approvals/*` is the real oversight surface. Corrected + guarded |
| **`/api/mentors/invite · /invites/*`** "mentor matchmaking" | **FIXED (doc) — That change** | no `/api/mentors`; the real surface is `/api/invites/*`. Corrected + guarded |
| **`GET /api/agents/{id}/reputation`** | **FIXED (doc) — That change** | no route; reputation is the `verifiable_receipts` facet of `/agentfacts/{id}.json` (+ `/api/agents/{id}/trust`). Corrected + guarded |

## Durable guards added

- `test_api_doc_route_parity` — extracts every path `docs/API.md` advertises and
  asserts each maps to a registered route; the doc can no longer drift ahead of
  the code (the four phantom routes above are explicit anti-regression anchors).
- `test_deploy_surface_reality` — the `/metrics` compose-plumbing invariant and
  the rotate status-code contract.

Nothing here changes a frozen wire id.
