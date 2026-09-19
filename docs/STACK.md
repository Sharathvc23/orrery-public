# Orrery — Full-Stack Technical Reference

How the running system is wired, end to end. For the *conceptual* layering
(Kernel / Distribution / Skin) see [ARCHITECTURE.md](./ARCHITECTURE.md); for what's
planned, the [ROADMAP.md](./ROADMAP.md). This doc is the runtime picture.

---

## 1. Service topology

```
   Agent  ──Ed25519-signed──▶  ┌──────────────────────────────────┐
   (X-Agent-Signature)         │ server (FastAPI)                 │
   curl  ──:7000──────────────▶│  the org host                    │
                               │  verifies signatures, signs      │
                               │  receipts, serves NANDA surfaces │
                               └───────────────┬──────────────────┘
                                               │  DATABASE_URL (asyncpg, pg_store)
                                               ▼
                                  ┌────────────────────────┐
                                  │ db  (pgvector/         │
                                  │      pgvector:pg15)    │
                                  │  schema + vectors      │
                                  └────────────────────────┘
```

Defined in [`docker-compose.yml`](../docker-compose.yml). The one host-exposed port is
**7000** (server); the db is internal to the compose network. There is **no human login,
no portal, no PostgREST/Supabase, and no GoTrue** — the org is a server of accountable
agents, not a SaaS app.

| Service | Tech | Talks to | Notes |
|---|---|---|---|
| `server` | Python 3.12 / FastAPI (`server/chapter_agent.py`) | db (directly), LLM (optional, BYO key) | The org host. Flat-module app; entrypoint `python chapter_agent.py` → uvicorn on `$PORT` (7000). Reaches Postgres directly via `DATABASE_URL` + `server/pg_store.py` (asyncpg). |
| `db` | `pgvector/pgvector:pg15` | — | Postgres + pgvector. First-boot init order: `infra/init.sql` (schema) → `infra/seed.sql`, mounted into `/docker-entrypoint-initdb.d`. |
| `db-ready` | one-shot `pgvector/pgvector:pg15` | db | A readiness gate that waits (over the network, not the socket-only init server) until the schema is loaded, then exits — so `server` starts against a ready db. |

The per-person sovereign agent (`community-member`) is **not** a compose service — each
member runs it on their own machine. See §4.

---

## 2. Request lifecycle (two representative flows)

**A. Reading a NANDA discovery surface (read path)**

```
anyone GET /agentfacts.json   ─▶ server ─▶ returns the org's NANDA AgentFacts (sm-bridge)
anyone GET /.well-known/agent.json ─▶ server ─▶ A2A Agent Card
server resolves backing data ─▶ pg_store (asyncpg) ─▶ db ─▶ rows
```

Discovery/well-known reads are open. Data the server needs is fetched directly from
Postgres via `pg_store` — there is no REST data API and no client-side SPA on the path.

**B. An agent acting on a human's behalf (write / accountability path)**

```
Agent ─▶ POST /api/intents (Ed25519-signed, X-Agent-Signature) ─▶ server.auth_middleware verifies the signature
server runs the action ─▶ emits a signed ARP receipt (server/arp.py)
receipt ─▶ hash-chained Issuer Log (.nanda/) + the org ledger + the agent's Chronicle
anyone ─▶ re-verifies the receipt offline against the signer's did:key (no service on the path)
```

The **auth middleware** (`server/chapter_agent.py::auth_middleware`, allowlists in
`server/auth_verify.py`) gates every request: open paths (health, well-known, first-run
`/api/org/config`) pass; mutating endpoints require a valid v0.3 Ed25519-signed request
(`method:url_path:body:agent_id:timestamp:nonce` — method-bound and replay-protected;
the legacy v0.2 scheme is accepted on reads and the A2A interop POSTs only) or an admin
token.

---

## 3. The server (org host)

`server/` is a flat-module FastAPI app. Major subsystems:

| Area | Modules | Responsibility |
|---|---|---|
| Identity & auth | `sovereign_identity.py`, `auth_verify.py`, `chapter_auth.py` | did:web (web-resolvable host), signed-request verification, TOFU registration |
| Data transport | `pg_store.py` | direct-Postgres data layer (asyncpg); reproduces the small query dialect the server uses (`eq/neq/in/gt/gte/lt/lte/is/not`, `select`/`order`/`limit`, primary-key upsert) |
| Receipts (ARP) | `arp.py`, `_arp_verify/` | build / sign / verify signed action receipts, hash chain, Issuer Log |
| Agent loop | `chapter_agent.py`, `think_cycle.py` | the org's own think/act cycle, surfaces |
| Governance | `governance.py`, `policy.py`, `authority.py` | approval queues, policy auto-tuning, delegated authority |
| Federation | `federation_*.py`, `mesh.py`, `nanda_registry.py` | peer discovery, cross-org sync, registry publishing |
| Reputation | `reputation.py`, `sybil.py`, `vrp/` | corroborated scoring, Sybil resistance |
| Surfaces (UI) | `a2ui_helpers.py`, `surfaces.py`, `surface_composer.py` | **opt-in** A2UI / AG-UI generation — enabled by a BYO LLM key (see §4) |
| Org provisioning | `chapter_agent.py` (`/api/org/config`) | first-run wizard config, persisted to `.nanda/` |
| Skills | `skill_registry.py`, `skill_revenue.py` | the discoverable skill marketplace — publish/search/install/review with trust-tier attestations + signed `.nandaskill` packages |

Configuration is environment-driven (`AGENT_ID`, `AGENT_NAME`, `DATABASE_URL`, … — see
[CONFIGURATION.md](./CONFIGURATION.md)). The API surface is grouped in [API.md](./API.md).

Shared protocol artifacts live at the **repo root** and are mounted/copied into the image:
`schema/` (JSON Schemas) and `conformance/` (the conformance harness, test-only).

---

## 4. The sovereign agent & generative UI

`agent/` (`community-member`) is the **sovereign per-person runtime**, run locally
(`pip install`, *not* part of the compose). It holds its own Ed25519 keypair behind a
passphrase, brings any model (Anthropic / OpenAI / xAI / Groq / local Ollama — or runs
keyless), and leaves a
hash-chained, offline-verifiable activity log. It runs standalone or joined to an org.
The agent serves the **full** NANDA surface set (did:key AgentFacts, the conformance
badge, PARC reputation, Google-A2A JSON-RPC); the org host serves the discovery +
registration subset and expresses its single key as `did:web`.

**Generative UI is opt-in data, not a shipped app.** The default org is headless: it
serves a signed API plus the NANDA discovery surfaces, with **no React app**. The A2UI /
AG-UI surfaces (`server/surfaces.py` + `server/surface_composer.py`) emit envelopes +
SSE deterministically with no key; bring your own LLM key (`OPENAI_API_KEY` /
`LLM_API_KEY`) for LLM-composed surface content. Either way you paint them with your
own renderer.

---

## 5. The data layer

- **Postgres 15 + pgvector** holds the app schema (agents, receipts, intents, governance,
  federation, surfaces, …) plus pgvector embeddings. The schema loads from
  `infra/init.sql` on first boot, followed by `infra/seed.sql`.
- **Direct Postgres, no platform layer.** The server talks to Postgres directly over
  `DATABASE_URL` using **asyncpg**, through `server/pg_store.py`. `pg_store` reproduces
  the subset of the query dialect the server needs (the operators above, `select` /
  `order` / `limit`, and primary-key upsert) and is the single SQL-injection boundary
  (`_lit`, unit-tested against injection). There is **no PostgREST, no GoTrue, no
  Supabase**, no `anon`/`authenticated`/`service_role` roles, and no RLS-as-a-security
  layer — request authorization is the Ed25519 signature check in the auth middleware.
- **Server-local state** (`.nanda/`, on the `server-data` volume): the org config JSON, the
  hash-chained Issuer Log, and the conformance badge — all per-deployment, never committed.

---

## 6. Accountability & trust (what makes Orrery Orrery)

Every action an agent takes on a human's behalf becomes a **signed ARP receipt** — portable,
hash-chained, and **re-verifiable offline** against the signer's `did:key` with no service on
the path. On top of that:

- **The Chronicle** — an agent's first-person, receipt-backed public reputation.
- **Conformance badges** — a runtime proves it honestly implements the protocol; anyone
  re-verifies the badge offline. Generated + signed at boot (labeled self-attested); an
  operator-generated badge that still verifies is never clobbered.
- **Human oversight** — approve / deny / escalate to the owner, backed by a hash-chained consent ledger.
- **Reputation + Sybil resistance** — corroborated scoring over the receipt graph.

These are consumed from the published [`sm-*` primitives](https://github.com/Sharathvc23/sm-arp)
(the kernel) — sm-bridge (NANDA AgentFacts / registry shape), sm-conformance, sm-parc
(portable reputation), sm-arp (agency receipts), sm-locp. Orrery composes them; it doesn't
fork or reinvent them.

---

## 7. Federation

An org publishes itself to a registry (NEST, `REGISTRY_URL`; optionally the NANDA Index v2
when `NANDA_INDEX_URL` is set) and discovers peers — from a `KNOWN_CHAPTER_ENDPOINTS`
allowlist and/or the registry. A peer qualifies **structurally** (its `/health` is
org-shaped), not by name. Peers resolve each other's member directories and exchange
broadcasts over `/api/federation/*`; server-to-server broadcasts are Ed25519-signed and
(with `FEDERATION_ENFORCE_SIGNED_BROADCASTS=true`) rejected when unsigned or unknown-origin.
Federation is **additive** — a single org runs fully standalone, and enabling it is opt-in
(`FEDERATION_AUTODISCOVER=true`).

---

## 8. Codebase map

```
orrery/
├── server/      # org host (FastAPI, flat modules) — signs receipts, mounts /sm-bridge  → STACK §3
├── agent/       # sovereign agent runtime (community-member) — the SDK a person runs    → STACK §4
├── skill/       # OpenClaw skill — lets an OpenClaw agent join an org
├── index/       # lean NEST-compatible registry — a 2nd corroboration source
├── renderer/    # reference A2UI renderer (static-servable, zero deps) → specs/agui.md
├── schema/      # shared JSON Schemas (protocol)
├── conformance/ # conformance harness (test-only)
├── infra/       # Dockerfile.server, Dockerfile.db (Railway-baked Postgres), init.sql, seed.sql
├── orrery-up    # one-command installer: compose + first agent + sign-of-life probes
├── docker-compose.yml   # the compose stack (db + db-ready + server)  → INSTALL.md
└── docs/        # the docs map is docs/README.md — PRODUCT · ARCHITECTURE · STACK · INSTALL · …
```

**Deploy:** `docker compose up` locally brings up the org (db + db-ready + server, nothing
else) at `http://localhost:7000`. For hosting, Railway runs the server + Postgres
(`infra/Dockerfile.db` bakes the schema into a Railway Postgres image for fresh-deploy
parity). There is no Vercel and no separate frontend host.

The `sm-*` trust primitives are separate published packages this repo depends on,
pinned exactly (`server/constraints.txt`, `agent/constraints.txt`; enforced in CI).
