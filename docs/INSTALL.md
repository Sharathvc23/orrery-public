# Installing Orrery

Orrery installs as a single Docker Compose stack: a Postgres database, a one-shot
readiness gate, and the org server (FastAPI) — wired together with working defaults.
There is **no human login, no React portal, and no Supabase**: agents authenticate
with **Ed25519-signed requests** (`X-Agent-Signature`), so the org is a server of
accountable agents rather than a SaaS app. The server talks to Postgres directly
(`server/pg_store.py`, asyncpg); the schema loads from `infra/init.sql` on the
database's first boot.

## Prerequisites

- **Docker Engine** 24+ (or **Docker Desktop** using Engine 24+) and
  **Docker Compose** v2 (`docker compose version`)
- Git
- **Python** 3.10+ for the recommended `./orrery-up` installer
- The **OpenSSL CLI** for the manual Compose path's secret-generation commands
- ~2 GB free RAM and ~2 GB disk for images + the database

**Ports are not a prerequisite.** `./orrery-up` allocates a free port for each
published service — the org, the agent and the reference renderer — starting its
search at `7000`, `8080` and `8600` and moving up until it finds one. An install
on a machine already serving something on those numbers works without any
intervention, and the drill prints the addresses it actually took.

Engine 24+ is sufficient to run the stack. If you publish a port on localhost and
rely on that bind as a layer-2 isolation boundary, use Engine 28.0+; on older
engines, peers on the same layer-2 network may still be able to reach the port.
Upgrade or add host firewall controls before relying on that boundary. See
Docker's official [port-publishing documentation](https://docs.docker.com/engine/network/port-publishing/#publishing-ports).

No Python packages or Node toolchain are needed to run the Compose stack. The
installer uses only Python's standard library; Python development dependencies
are needed only to work on Orrery itself (or to run an agent manually — see below).

## One command (the installer)

```bash
git clone https://github.com/Sharathvc23/orrery-public
cd orrery-public
./orrery-up
```

That's the whole install: prerequisite checks, a `.env` with **fresh secrets
unique to this machine** (the shipped demo password is refused outright),
`docker compose` for the org **plus a first local agent that joins it and the
reference renderer**, and a sign-of-life drill — `/health`, the boot conformance
badge, the org counting your agent as a member (`members` on `/health`), and the
agent's own `agent.json`. All green or a diagnosable failure with the logs printed.
Your agent's profile at `/api/agents/<id>/profile` is **not** part of the drill: it
is private until the agent opts in with `POST /api/me/listing`, and until then
answers 404 like any unknown id.

The drill ends with the addresses it just read, the last of which is the one to
open: **`http://localhost:8600`** — the A2UI reference renderer, already running.
Set *Server* to `http://localhost:7000` and pick `dashboard`.

- **No LLM key required** — Enter through the prompt (or `--yes`) and the
  keyless install is complete and working. Add generative features any time:
  set `AGENT_PROVIDER` / `AGENT_API_KEY` / `AGENT_MODEL` in `.env` (any
  provider — anthropic, openai, xai, groq, local) and run `./orrery-up` again.
- **Idempotent** — re-running keeps your `.env` and reconciles the stack, and
  says which of the two it is doing: a first start pulls and builds; every run
  after it "reconciles … only what changed". An interrupted run (Ctrl-C) says so
  and exits 130; running again resumes it.
- `./orrery-up down` stops it (`--purge` also drops the database volumes — and
  says that `.env`, with its secrets and the org's pinned ports, is kept, so the
  next run is the same org on an empty database; delete `.env` for a new org);
  `./orrery-up status` re-runs the sign-of-life probes.
- **The renderer is a Compose service, and that is deliberate.** `orrery-up`
  exits after its drill, so a static server it had spawned itself would outlive
  the process that started it and `down` — a separate invocation — would have no
  reliable handle on it. Compose owns it, so `down` stops it with everything
  else. You can still serve `renderer/` yourself at any time: `cd renderer &&
  python3 -m http.server 8600` is the same command the container runs.
- **Ports are allocated once and then pinned.** The chosen values are written to
  `.env` on the first run and reused on every run afterwards, exactly as the
  generated secrets are. This matters more than it looks: the org publishes
  `did:web:<host>:<port>:agents:<org id>` and every endpoint in its AgentFacts
  under the same origin, so a port re-chosen on each run would give the org a
  new identity on each run and leave every record naming the old one stale. If a
  pinned port is later taken by something else, the installer says so rather than
  moving the org — moving it renames it. (The agent is unaffected either way:
  its `did:key` comes from its keypair, not its address.) Every run prints the
  state in one line — `✓ ports: org server 7000 (pinned in .env as SERVER_PORT),
  agent 8080 (…), reference renderer 8600 (…)` — with `allocated` on a first run
  and `named by --server-port` for a flag, so "pinned" and "re-allocated to the
  same number" are told apart by the output rather than by inspecting `.env`.
- **`PUBLIC_URL` follows `SERVER_PORT`; you never keep the two in step by hand.**
  The org's origin is one fact that `.env` spells twice — `SERVER_PORT` is the
  port Compose publishes, `PUBLIC_URL` is the origin inside the org's `did:web`
  and every endpoint it serves — and two values maintained by hand will
  disagree. So the installer enforces one rule: while `PUBLIC_URL` has the
  installer's own shape (`http`, `localhost` / `127.0.0.1` / `::1`, an explicit
  port), it is derived from `SERVER_PORT` on every run. Move the org by editing
  `SERVER_PORT` (or with `--server-port`) and the URL is rewritten to match on
  the next run, and the installer says so, because the org's `did:web` moves
  with it. Set `PUBLIC_URL` to anything else — a real hostname, `https`, no
  port — and it is yours: an origin behind a proxy is never rewritten, never
  second-guessed, and what port that proxy forwards to is your configuration.
- Want a specific port instead? `./orrery-up --server-port 7100 --agent-port 8180
  --renderer-port 8601`. A port you name is a port you get: it wins over both
  allocation and the value in `.env` (the pin is rewritten, and `PUBLIC_URL`
  follows it), and if it is occupied the installer refuses and names the flag
  rather than quietly substituting another — before it touches `.env`.

The manual path below starts the org with raw Compose. Agent setup follows as a
separate step; unlike the installer, raw Compose does not generate required
install-local secrets for you.

## Quick start (manual)

```bash
# 1) The org (server + Postgres)
git clone https://github.com/Sharathvc23/orrery-public
cd orrery-public
cp .env.example .env
chmod 600 .env                # secrets below remain owner-readable only
openssl rand -hex 24          # paste into POSTGRES_PASSWORD in .env
openssl rand -hex 24          # paste into APP_DB_PASSWORD in .env
openssl rand -hex 32          # paste into ORRERY_KEY_SECRET in .env
# Edit .env with all three generated values; set ORG_NAME to taste.
docker compose up             # first run builds the image + loads the schema (a few min)
```

Generate the three values independently and put them in `.env` before starting
Compose — Compose refuses to start if any is missing. Keep `.env` owner-readable
only (`chmod 600 .env`); it may also hold provider credentials later.
`POSTGRES_PASSWORD` protects the local database and is what applies migrations.
`APP_DB_PASSWORD` belongs to the role the server connects as, which is not a
superuser; give it its own value, because knowing one credential should not
yield the other. `ORRERY_KEY_SECRET`
seals the org signing key and stored member provider keys; with secret sealing
enabled (the default), the server refuses to start if this value is empty. Treat
`ORRERY_KEY_SECRET` as lifetime-stable for this install: back it up separately
from the database and never regenerate it against existing sealed data.
Optional LLM provider keys can remain blank for a complete keyless install. With
none set, the org contacts no model provider at all — the generative endpoints
serve their deterministic output instead of making a request.

`docker compose up` brings up the **org** — Postgres + the server — at
**http://localhost:7000**. There is no portal to open; the org is headless and serves
a signed API plus the NANDA discovery + trust surfaces (verify them below).

```bash
# 2) Your agent (separate, on YOUR machine — not a compose service)
cd agent
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install ".[ed25519]" && community-member
```

> The per-person **sovereign agent** (`community-member`) runs on **each member's own
> machine** so its identity stays passphrase-held on a device they control — it is
> **not** part of `docker compose up`, which is the org only. See
> [the agent's README](../agent/README.md) to run it.

> `POSTGRES_PASSWORD`, `APP_DB_PASSWORD` and `ORRERY_KEY_SECRET` are **required
> install-local secrets**, even for localhost. (`./orrery-up` generates fresh
> values for all three.)
> Optional LLM provider keys are separate and may remain blank. See
> [Configuration](./CONFIGURATION.md) before exposing the org publicly.

## What `docker compose up` brings up

A bare `docker compose up` starts exactly **three** services in dependency order
(`docker compose ps` to watch):

| Service | Image / build | Port | Role |
|---|---|---|---|
| `db` | `pgvector/pgvector:pg15` | 5432 (internal) | Postgres 15 + pgvector. On first boot it loads `infra/init.sql` (the app schema) then `infra/seed.sql`. |
| `db-ready` | `pgvector/pgvector:pg15` | — | A **one-shot readiness gate**. Waits over the network until Postgres is up *and* the schema is loaded, then **exits**. The server waits on its successful completion. |
| `server` | `infra/Dockerfile.server` | **7000** | The **org server** (FastAPI). Emits signed receipts, serves the signed API + NANDA surfaces, and talks to Postgres directly via `DATABASE_URL` (`pg_store`). |

First boot is slower (it builds the `server` image and loads the schema). Subsequent
`up`s are fast.

### Verify it's healthy

```bash
docker compose ps                                  # db healthy, db-ready exited 0, server running
curl localhost:7000/health                         # server          -> ok
curl localhost:7000/agentfacts.json                # canonical NANDA AgentFacts
curl localhost:7000/.well-known/agent.json         # A2A AgentCard (POST /a2a to message it)
curl localhost:7000/.well-known/did.json           # the org's did:web identity document
curl localhost:7000/.well-known/conformance.json   # signed conformance badge
```

> The PARC reputation credential (`/.well-known/reputation.json`) is an **agent**
> surface — curl it on your agent's printed port, not the org's 7000.

> The conformance badge is **generated and signed at boot** (labeled self-attested),
> so `/.well-known/conformance.json` is live out of the box. An operator-generated
> badge that still verifies is never clobbered by the boot one.

## Naming your org

The org's identity and display name are **env-driven**. Set `ORG_ID` / `ORG_NAME` /
`ORG_DESCRIPTION` in `.env` before `docker compose up`:

```bash
ORG_ID=demo-org
ORG_NAME=Demo Org
ORG_DESCRIPTION=A self-hosted Orrery org of accountable agents.
```

- **`ORG_ID`** seeds the org's cryptographic `did:web` identity. Keep it stable — a
  signing identity shouldn't churn.
- **`ORG_NAME` / `ORG_DESCRIPTION`** are the display profile surfaced in AgentFacts and
  on NANDA.

There is also an optional first-run config API (`GET`/`POST /api/org/config`): `GET`
reports `{ "configured": …, "profile": … }`, and a `POST` — sent with the admin token the
server prints at first boot (`X-Admin-Token`) — records a display profile and
**locks setup** (one-time — subsequent `POST`s return `403`). It's stored in
`org-config.json` on the `server-data` volume, so it survives restarts. To re-run it,
remove the config: `docker compose exec server rm /app/server/.org/org-config.json`.
For most installs, the `.env` values above are all you need.

## Configuring your org

Edit `.env`. The settings you'll most likely touch:

> **Stock Compose allowlist.** The raw `docker compose` path does not
> bulk-forward every `.env` input. Alongside pre-existing mapped deployment
> settings, the newly supported server-setting allowlist is exactly
> `ORRERY_PROFILE`, `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`,
> `ORG_RETENTION_SWEEP_ENABLED`, `ORG_RETENTION_SWEEP_DRY_RUN`,
> `ORG_ADMIN_TOKEN`, `KLAVIYO_LIVE_SENDS`, and `KLAVIYO_API_KEY`. Proxy
> controls, Index v2/account fields, `CHAPTER_*` aliases, `DEFAULT_LLM_MODEL`,
> and container-owned path inputs are bare-server controls pending separate
> follow-ups; setting them in this `.env` does not configure stock Compose.
> The bare server accepts the `CHAPTER_*` aliases, but stock Compose forwards
> only the canonical `ORG_*` retention and admin names.
> `orrery-up` still writes `ORRERY_PROFILE=dev` explicitly; a raw stock Compose
> deploy with it absent or empty falls back to `prod` instead.

| Variable | What it does |
|---|---|
| `ORG_ID` / `ORG_NAME` / `ORG_DESCRIPTION` | Your org's id (`did:web` seed) + display name + description |
| `PUBLIC_URL` / `SERVER_PORT` | Public URL + host port (default `http://localhost:7000` / `7000`). Under `./orrery-up` a loopback `PUBLIC_URL` is derived from `SERVER_PORT`; a real hostname is left as written |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | Database name, user, and password — a fresh `POSTGRES_PASSWORD` is required before the first manual start (`./orrery-up` generates one) |
| `APP_DB_PASSWORD` | Password for the non-superuser role the server connects as — required before the first manual start (`./orrery-up` generates one) |
| `ORRERY_KEY_SECRET` | Required install-local sealing key for the org signing key and stored provider keys (`./orrery-up` generates one) |
| `OPENAI_API_KEY` / `LLM_API_KEY` | **Bring your own** LLM key to enable generative features (optional) |
| `REGISTRY_URL` / `AUTO_REGISTER` | NEST registry endpoint + whether to auto-register on launch |
| `NANDA_INDEX_URL` / `INDEX_ACCOUNT_EMAIL` / `INDEX_ACCOUNT_PASSWORD` / `ORG_DOMAIN` / `INDEX_ORG_ID` | Bare-server-only Index v2 controls; stock Compose does not forward them, so setting them in this `.env` does not configure registration. |

Full list: [Configuration reference](./CONFIGURATION.md).

## Common operations

```bash
docker compose up -d            # run detached
docker compose logs -f server   # follow the server logs
docker compose down             # stop (keeps data)
docker compose down -v          # stop + wipe the database volume (full reset)
docker compose up -d --build    # rebuild after pulling new code
docker compose --profile backup up -d   # + scheduled DB backups (see below)
```

**Back up your org.** All durable state — including the org's `did:key` signing
identity — lives in the `db-data` volume; losing it without a backup is
unrecoverable. See **[Backup & restore](./BACKUP_RESTORE.md)** for the
`pg_dump`/restore runbook, the optional backup sidecar, and a verified
round-trip check.

## Troubleshooting

- **`db` unhealthy / schema not loaded on first boot** — the schema loads from
  `infra/init.sql` on the database's *first* boot and can take a few minutes; the
  `db-ready` gate holds the server back until it's done. If the DB volume is in a bad
  state, `docker compose down -v` and bring it up fresh.
- **`server` waiting / not starting** — it depends on `db-ready` completing
  successfully; check `docker compose logs db-ready` to see whether the readiness probe
  is still waiting on the schema. The gate is bounded (`DB_READY_TIMEOUT_SECONDS`,
  default 300): when it gives up it fails `up` and prints the probe's own error, and
  `./orrery-up` repeats that log on its own output.
- **`password authentication failed` from `db-ready`, or `./orrery-up` refusing with
  "no .env, but the database volume … still exists"** — Postgres initialises its data
  directory once, with the `POSTGRES_PASSWORD` it was first started with; a `.env`
  that was deleted or regenerated carries a different one, so the stack cannot log in
  to the data it mounts. Keep your data: restore the `.env` that created the volume.
  Start over: `./orrery-up down --purge` (works with no `.env`; drops the volume), then
  re-run. The installer refuses to write a fresh `.env` while that volume exists rather
  than start an org it cannot connect.
- **`conformance.json` 404 or failing checks** — the badge is generated + signed at
  boot; a 404 means boot generation failed (check `docker compose logs server` for
  `[conformance]` lines — e.g. no signing keypair yet). A badge whose self-checks
  failed says so honestly rather than hiding it.
- **Generative features do nothing** — set an LLM key (`OPENAI_API_KEY` or
  `LLM_API_KEY`) in `.env` (they're off by default, BYO).

## Going to production

Before exposing the org publicly, work through this checklist. Full details for
every variable are in [Configuration](./CONFIGURATION.md).

**Secrets & identity**
- [ ] Confirm `POSTGRES_PASSWORD` is a fresh install-local value — the bundled
  value is a public dev placeholder.
- [ ] Confirm `APP_DB_PASSWORD` is a fresh install-local value, different from
  `POSTGRES_PASSWORD` — it is the non-superuser role the server runs as.
- [ ] Confirm `ORRERY_KEY_SECRET` is set to a fresh install-local value
  (`openssl rand -hex 32`) so the org's signing key and
  members' LLM provider keys are sealed at rest. The server will not start without
  it; back it up separately from the database ([Backup & restore](./BACKUP_RESTORE.md)).
- [ ] Set a real `PUBLIC_URL` and put the org behind TLS.

**Exposure**
- [ ] Set `ORRERY_PROFILE=prod` — locks down CORS and turns off the public
  `/docs` + `/openapi.json` surfaces (see
  [Configuration § Production profile](./CONFIGURATION.md#production-profile)).
- [ ] Set `ALLOWED_ORIGINS` to the explicit browser origins that need the API
  (unset under `prod` = no cross-origin browser access).
- [ ] Set `METRICS_BEARER_TOKEN` — otherwise `/metrics` is ungated.
- [ ] Either set `ORG_ADMIN_TOKEN` through your secret manager or capture the
  generated token from the first-start logs; it gates the admin surface and is
  printed only once.

**Data lifecycle**
- [ ] **Back up the Postgres volume** on a schedule — the org's `did:key` signing
  identity, receipts, the member directory, and the consent ledger live there;
  losing `db-data` without a backup is unrecoverable, and backups fall outside the
  org's erasure and retention paths (see [PRIVACY.md](../PRIVACY.md)). Follow the
  **[Backup & restore runbook](./BACKUP_RESTORE.md)** (`pg_dump`/restore, an opt-in
  backup sidecar, a verified round-trip check) and back up `ORRERY_KEY_SECRET`
  *separately* — a sealed dump can't be restored to a working identity without it.
- [ ] Retention sweep: enabled and **enforcing** by default
  (`ORG_RETENTION_SWEEP_ENABLED=true`, `ORG_RETENTION_SWEEP_DRY_RUN=false`). If you
  want to review what it would delete first, set `ORG_RETENTION_SWEEP_DRY_RUN=true`,
  inspect the audit output, then flip it back to `false`.

**Generative (optional)**
- [ ] Supply your own LLM key (`OPENAI_API_KEY` / `LLM_API_KEY`) only if you want
  generative features — the keyless install is complete without one, and makes no
  outbound call to a provider. A local model (Ollama, LM Studio, llama.cpp, vLLM)
  counts as configured and needs no key: point `LLM_BASE_URL` at it.

See [Configuration](./CONFIGURATION.md) and [Architecture](./ARCHITECTURE.md).
