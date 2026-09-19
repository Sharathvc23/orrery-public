# Handshake spec: SMB → NANDA
### Orrery (agent runtime) · host39 (card host + registrar) · api.nandaindex.org (the one index)

Engineering-ready. Grounded in **current code**, traced 2026-07-25:
- **Orrery `smb_host`** — `Sharathvc23/orrery-public` `main` (current). `/provision` returns `{tenant_id, endpoint, did, recovery_phrase}`; serves the card at `/t/<tenant>/.well-known/agent.json` and booking at `/t/<tenant>/book`. **Makes no index calls** (by design — one index, not ours).
- **host39** — `projnanda/host39` `origin/main` `3522ed3`. Account `POST /auth/register` (JWT); card `POST /cards` (JWT, `runtime_url` **optional/nullable**); serves `/:domain/:slug.json` + `/personal/:handle/:slug.json` as `application/a2a-agent-card+json`; URN `urn:ai:{domain|email}:…:agent:<slug>`. **No index client, no did:key/signing, JWT-only (no machine auth), domain ownership unverified.**
- **api.nandaindex.org** — `nanda-index-v2` `origin/main` `5b8b0d8`, live v2.0.0. `POST /api/v1/orgs` (JWT) inserts `status=pending`. **Activation: DNS-TXT for domain orgs (admin); email-link for PERSONAL (no-domain) orgs → `active`.** No host-vouched activation, no machine/API-key, no bulk. Resolve: `GET /api/v1/resolve?locator=<urn>` → `{index_record.registry_url}` → caller fetches the card.

---

## Key architectural rule (scoped to this SMB path)
**One index: `api.nandaindex.org`.** On **this path**, `smb_host` makes no index calls — registering the
tenant is host39's job, and `smb_host` is only the agent runtime the card points at.

> ⚠️ **This rule governs `smb_host` only. It is not a statement about Orrery.** An earlier version of this
> line read *"Orrery never hosts or registers to an index"*, which is false for the stack as a whole and
> has misled readers into thinking a business cannot get listed without host39. For the record:
>
> - **The org server registers itself.** `server/nanda_registry.py::register_on_index_v2()` performs
>   JWT signup (`POST /auth/register`, falling back to login on 409) and creates the org row, via the
>   admin-gated `POST /admin/api/index-v2/register`. It is an **explicit operator trigger — never
>   auto-fired on startup**, so there are no surprise network calls; `status="pending"` means the
>   operator must still click the verification email. It also publishes to NEST by default
>   (`REGISTRY_URL`).
> - **Orrery ships its own lean index** — `index/` — advertised in the README as a second corroboration
>   source, with a per-org attestation gate.
>
> So a business running the full stack **can** get listed without host39. The host39 build items below
> are what the *no-infra* path needs — a business that runs nothing at all — not what Orrery needs.

## Recommended flow — PERSONAL / email path (works against today's live index)

```
SMB (funnel)
   │  1. sign up (email, business name)
   ▼
host39 ──2. POST {orrery-smb-host}/provision {business_name}──► Orrery smb_host
   │                          ◄── {tenant_id, endpoint, did, recovery_phrase}
   │  3. POST /cards  (runtime_url = endpoint, did as credential)  → hosts card at
   │     https://agentcards.host39.org/personal/<handle>/<slug>.json
   │  4. POST api.nandaindex.org/api/v1/orgs
   │       {hosting_path:"personal", contact_email:<SMB email>,
   │        registry_url:<host39 card URL>, identifier:urn:ai:email:<email>:agent:<slug>}
   ▼
api.nandaindex.org ──5. emails verify link to <SMB email>──► SMB clicks → status=active
   ▼
resolvable: GET /api/v1/resolve?locator=urn:ai:email:<email>:agent:<slug>
   → registry_url (host39 card) → runtime_url (Orrery endpoint) → book → VERIFIABLE receipt
```

### Exact calls per leg

**Leg A — host39 → Orrery `/provision`** *(Orrery: DONE)*
`POST {ORRERY_SMB_HOST}/provision`  body `{business_name, service_type?}` →
`200 {tenant_id, endpoint:"{host}/t/<tenant>", did:"did:key:z…", recovery_phrase}`.
host39 keeps `endpoint` + `did`; hands `recovery_phrase` to the SMB (shown once).

**Leg B — host39 hosts the card** *(Orrery side: DONE)*
`POST /cards` (host39 JWT) with `runtime_url = <endpoint from A>`, `authentication.schemes=["ed25519","did-auth"]` + `credentials=<did from A>`, `is_public:true`. Card served at `/personal/<handle>/<slug>.json` (email identity) or `/<domain>/<slug>.json` (domain identity), as `application/a2a-agent-card+json`.

Orrery now ships the publisher for this leg:
- `agent/community_member/host39.py` — the A2A-card → `POST /cards` mapping, a client that cannot exist without a bearer token, and an **unauthenticated** re-fetch that proves the card is published (a 2xx from `POST /cards` alone is not treated as success).
- `scripts/publish_host39_card.py` — the operator trigger (`--dry-run` prints the exact body). Not wired into startup and not wired into `POST /provision`; `HOST39_BASE_URL` has no default, and unset ≡ empty. See `docs/CONFIGURATION.md`.

#### ⚠️ Which artifact host39 accepts — settled, do not re-litigate

Orrery has **two** descriptor artifacts and they are not interchangeable:

| | A2A agent card | canonical NANDA AgentFacts |
|---|---|---|
| Built by | `agent/community_member/a2a_card.py::build_agent_card` | `agent/community_member/sm_bridge_adapter.py::build_self_agentfacts` (sm-bridge `SmAgentFacts`) |
| Served at | `/.well-known/agent.json`, `/t/<tenant>/.well-known/agent.json` | `GET /agentfacts.json` |
| Distinctive fields | `name`, `url`, `provider{organization,url}`, `authentication{schemes,credentials}` | `id`, `agent_name`, `handle`, `label`, `endpoints` |

**host39 accepts the A2A card.** This is settled by host39's own OpenAPI (`GET
https://agentcards.host39.org/docs/json`): `POST /cards` declares
`additionalProperties: false` over exactly `slug, display_name, description,
runtime_url, version, capabilities, authentication, skills, provider_name,
provider_url, is_public, monitoring_enabled` — the A2A card flattened (`url` →
`runtime_url`, `provider` split in two, plus a host39-local `slug`). **None** of
AgentFacts' distinctive fields exist in that schema, and `additionalProperties: false`
means a request carrying them is rejected outright rather than partially stored. The
served media type, `application/a2a-agent-card+json`, says the same thing.

So the human framing "agent facts card on host39" is one artifact too many: **the card
on host39 is the A2A card.**

**Does AgentFacts need a home too? Yes — and it already has one:** the agent runtime's
`GET /agentfacts.json`. host39 stores no AgentFacts, so the only link from a published
card to them is the A2A `x-nanda` bag (`did` + `agentfacts_url`). That bag has no legal
top-level home in host39's schema, so the publisher carries it inside the free-form
`capabilities` object under the same `x-nanda` key — preserved for a NANDA-aware reader,
ignored by a plain A2A client. **This nesting is an Orrery-side convention that host39
has not blessed; it needs host39 confirmation, or a first-class extension field.**

> ✅ **Closed (runtime side, not Leg B).** `build_agent_card` sets
> `x-nanda.agentfacts_url` unconditionally whenever a did is present, and `smb_host` did
> not mount an AgentFacts route — so `GET /t/<tenant>/agentfacts.json` **404'd**, and a
> tenant card advertised a pointer that resolved nowhere. Recorded here on 2026-07-30 and
> re-confirmed against a locally driven `smb_host` before the fix. The host now mounts
> `GET /t/<tenant_id>/agentfacts.json`, built by the same `build_self_agentfacts` the
> agent runtime serves at its own `/agentfacts.json`, so the two surfaces cannot describe
> one agent differently. `host39.check_agentfacts_pointer` probes exactly this URL, so
> the pointer check now has a target instead of warning about a dead link.
>
> A tenant's AgentFacts also fell back to sm-bridge's `urn:nanda:skill:general`
> placeholder, because a provisioned tenant carries no configured skills — the same
> "says nothing about what it does" problem as the card's empty `skills`, and harder to
> notice because the field was populated. Both documents are now derived from
> `smb_host.TENANT_ACTION_TOOLS`, the table of tenant action routes the host actually
> serves, and a test walks the app's route table and fails if a route is added without
> being declared.

**Leg C — host39 → index register** *(host39: BUILD — no client today)*
`POST https://api.nandaindex.org/api/v1/orgs` with a JWT, body:
`{org_id, display_name, contact_email:<SMB email>, hosting_path:"personal", registry_url:<host39 card URL>, identifier:"urn:ai:email:<email>:agent:<slug>"}` → `201`, `status:pending`, verify-email sent.

**Leg D — activation** *(SMB: one email click; today's live behavior)*
Index emails `<SMB email>` a link `…/api/v1/verify-email?token=…`. SMB clicks → `markEmailVerifiedByToken` flips `status→active` for the no-domain org. Now resolvable.

---

## What must be BUILT (net-new), by owner

**host39 (3 items):**
0. ~~Map an Orrery A2A card onto `POST /cards`.~~ **Done on the Orrery side** — `scripts/publish_host39_card.py` provisions (or takes an existing tenant), maps, publishes, and proves the card fetchable. host39 needs no change for this; it only needs to confirm the `capabilities["x-nanda"]` nesting above.
1. **Call Orrery `/provision`** on signup and set the card's `runtime_url` + `did` from the response. (Removes the "SMB must supply a runtime URL" step — a barber has none.)
2. **Register-on-behalf to `api.nandaindex.org`** — host39 has *no* index HTTP client today (only a manual `curl` in its README). Build the `POST /api/v1/orgs` call.
3. **A credential to call the index with.** The index is JWT-only. Simplest today: host39 holds one machine account and registers all SMBs under it (host39 becomes org `admin`; `contact_email` is the SMB's, so the verify link still goes to them). Cleaner: an index **service-account/API-key** (see index item 1).

**api.nandaindex.org (all OPTIONAL for the personal path — none blocks the demo):**
1. **Service-account / API-key auth** — so host39 registers on-behalf without a shared human JWT. Net-new (JWT-only today). *Cleanliness, not a blocker.*
2. **Host-vouched activation** — a verified registrar (host39, which owns `agentcards.host39.org`) activates the subpaths it hosts *without the per-SMB email click*. This is what turns the personal path into a **true zero-extra-step 3-click** flow. Net-new.
3. **Bulk register** — for System B (a partner like Shopify onboarding many agents). Net-new.

**Orrery:** nothing — `/provision` already returns exactly what host39 needs.

---

## The two paths, and the trade-off

| | Personal / email (recommended) | Domain |
|---|---|---|
| Who | no-infra SMB (just an email) | SMB that owns a domain |
| URN | `urn:ai:email:<email>:agent:<slug>` | `urn:ai:domain:<domain>:agent:<slug>` |
| Activation **today** | **email link → active (no DNS, no vouching)** | DNS-TXT `_nanda-challenge.<domain>` (admin) |
| Blocks a no-domain barber? | **No** | Yes (needs a domain + DNS) |
| For true 3-click (no email click) | needs index **host-vouched activation** | needs index host-vouched activation |

## Open decisions / risks
- **Email click vs true 3-click.** The personal path works *today* but includes one email confirmation. Eliminating it (for the on-stage "3 clicks, done") requires the index **host-vouched activation** (index item 2). Decide whether the demo tolerates the email step or that item is in scope.
- **host39 on-behalf credential:** ship with a single host39 machine account now, or wait for the index service-account. The account works today.
- **Domain-path vouching needs domain verification first.** host39 does *not* verify domain ownership today (uniqueness only). If host39 ever vouches for `domain` orgs, it must add ownership proof — otherwise it'd be attesting an unproven claim. (The personal path sidesteps this entirely.)

## Bottom line
With the live index's new personal-org email-activation, **for the no-infra path** the only hard build is on host39 (call Orrery, register-on-behalf, hold a credential). A business that runs the stack itself does not need any of it — see the scope note above. The index changes (service-account, host-vouched activation, bulk) are **quality/scale improvements, not blockers** — the personal/email path already works end to end against the real index today.
