# Configuration

Orrery is configured through environment variables — set in `.env` (read by Docker
Compose) for a stack deploy, or directly in the environment for a bare `server` process.
For manual Compose setup, copy [`.env.example`](../.env.example) to `.env`, then
set the two required install-local secrets below before first startup.

There is **no human login and no Supabase** — agents authenticate with Ed25519-signed
requests, so there are no login credentials, JWTs, or service-role keys to configure.
Manual installs still need two fresh install-local secrets before first startup:
`POSTGRES_PASSWORD` for the database and `ORRERY_KEY_SECRET` for sealing the org's
signing key and stored provider keys. `./orrery-up` generates both automatically.

Everything in `.env.example` is reproduced below, grouped exactly as it ships.

## Compose configuration

### Stock Compose allowlist

Stock Compose uses an explicit allowlist; it does not bulk-forward every `.env`
input. Alongside the pre-existing mapped deployment settings, the newly
supported server-setting allowlist is exactly `ORRERY_PROFILE`, `LLM_PROVIDER`,
`LLM_MODEL`, `LLM_BASE_URL`, `ORG_RETENTION_SWEEP_ENABLED`,
`ORG_RETENTION_SWEEP_DRY_RUN`, `ORG_ADMIN_TOKEN`, `KLAVIYO_LIVE_SENDS`, and
`KLAVIYO_API_KEY`.

Proxy controls, Index v2/account fields, `CHAPTER_*` aliases,
`DEFAULT_LLM_MODEL`, and container-owned path inputs are bare-server runtime
controls and are not forwarded by stock Compose pending separate follow-ups.
Putting them in the stack's `.env` does not configure the Compose server. The
bare-server reference below remains useful when running `server` directly or
using a separately reviewed deployment configuration.

Existing Compose operators should review `.env` before recreating the server.
`LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`, the two retention controls,
`ORG_ADMIN_TOKEN`, `KLAVIYO_LIVE_SENDS`, and `KLAVIYO_API_KEY` were documented
or present as template controls but previously did not reach the container. They
now take effect: the LLM values select model egress, retention values control
deletion, an explicit admin token supersedes the persisted token, and the
Klaviyo pair can enable live delivery after the existing exact or bounded
operator authorization.

The stock Compose fallback for an absent or empty `ORRERY_PROFILE` also changes
from `dev` to `prod`. This disables wildcard CORS and `/docs`, `/redoc`, and
`/openapi.json`; operators who intentionally need the prior local behavior must
set `ORRERY_PROFILE=dev`. `orrery-up` continues to write `dev` explicitly.

Docker Compose interpolates dollar-prefixed names in unquoted and double-quoted
`.env` values. Single-quote any secret containing `$` so its bytes reach the
container unchanged. Canonical `docker compose config` output escapes each
literal `$` as `$$`; that rendered form does not mean the container receives
two dollar signs. Never diagnose this by posting rendered configuration,
because it includes secret values.

## Your org

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `ORG_ID` | `demo-org` | Optional | The org's stable id. Compose maps it to the server's `AGENT_ID`; the org's identity derives from it, so keep it stable once published. |
| `ORG_NAME` | `Demo Org` | Optional | The org's display name. |
| `ORG_DESCRIPTION` | `A self-hosted Orrery org of accountable agents.` | Optional | The org's tagline. |

## Server

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `PUBLIC_URL` | `http://localhost:7000` | Optional | The org server's public URL — goes into the org's served identity and discovery surfaces. Set it to the externally reachable URL when you expose the org. Under `./orrery-up` a loopback value with an explicit port is derived from `SERVER_PORT` on every run; any other value is never rewritten. |
| `SERVER_PORT` | `7000` | Optional | Host port the org server is published on. |
| `SERVER_BIND_HOST` | `127.0.0.1` | Optional | Host interface for the Compose-published org port. Set deliberately (for example `0.0.0.0`) only when an external reverse proxy or network must reach it. |
| `AGENT_BIND_HOST` | `127.0.0.1` | Optional | Host interface for the Compose-published agent port. Keep loopback-only unless the agent's local-control API has an intentional protection and exposure design. |
| `COMMUNITY_MEMBER_BIND_HOST` | `127.0.0.1` | Optional | Host interface the `community-member` command binds its dashboard to. Set it (for example `0.0.0.0`) only when the agent's API needs to be reachable from another machine. |
| `COMMUNITY_MEMBER_LOCAL_TOKEN` | unset | Optional | Overrides the token in `~/.community-member/.local-token`. The agent generates that file (mode 0600) on first start; set this only when the secret is managed elsewhere. Send the token as `Authorization: Bearer <token>` or `X-Orrery-Local-Token`; it is not accepted in the query string or a cookie. The routes that do not require it are listed in `agent/community_member/local_auth.py`. |
| `COMMUNITY_MEMBER_THINK_INTERVAL` | `300` | Optional | Seconds between autonomous think cycles. Honoured by both the `community-member` command and the container entrypoint. A value that is not a positive integer falls back to the default. A cycle in which every action is refused waits longer than this before retrying, backing off 10s, 20s, 40s and so on to a 10-minute ceiling, and returns to this interval on the first cycle that is not entirely refused. |
| `ORRERY_PROFILE` | `prod` | Safe by default; set `dev` for local ergonomics | Deployment profile. `prod` (the default) hardens the public face — empty CORS allowlist + no `/docs`/`/openapi.json`; `dev` opts into CORS `*` + the interactive docs. See [Production profile](#production-profile). |
| `TRUSTED_PROXY_HOPS` | `0` | Bare server only | Number of trusted proxies between the client and this server (a single edge proxy = `1`). The per-IP rate limiter then keys on the real client IP from `X-Forwarded-For` (the entry that many hops from the right — spoofed left-prepended entries are ignored) instead of the shared proxy IP. `0` = direct connect, `X-Forwarded-For` is not trusted. **`GET /health` reports the resolved value as `trusted_proxy_hops`** — the number the running limiter is using, not a re-read of this variable, so a process that has not picked up a change says so. `0` on a deployment that sits behind an edge proxy means every caller shares one bucket. The in-memory limiter is **per process** — a multi-worker/replica deploy needs a shared store (Redis) for a global ceiling. Stock Compose does not forward this input. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Bare server only | Peer address(es) uvicorn accepts forwarded headers from — the edge proxy's IP (or `*` when the network already isolates the server). Passed to `uvicorn.run(proxy_headers=True, ...)` so `request.client` resolves the real peer. Stock Compose does not forward this input. |
| `ORRERY_RATE_LIMIT_SALT` | — (empty) | Bare server on a volume-less platform | HMAC salt under which limiter bucket keys (client IPs) are hashed before they are snapshotted to `rate_limit_buckets`. The snapshot restores on the next boot **only if that process hashes with the same salt**. Unset, the salt is a file under the server's `.org` directory — durable on stock Compose (that directory is on the `server-data` volume) and minted fresh on every boot of a service with no persistent filesystem, which silently reduces persistence to the pre-persistence behaviour. Set it there. At least 16 characters (`openssl rand -hex 32`); keep it **outside the database** — a salt beside the hashes would let a table dump be turned back into IPs. Rotating it orphans the current snapshot (buckets start empty once), never the reverse. Not forwarded by stock Compose, which does not need it. **`GET /health` reports `rate_limit_salt`** — see [Process-local request-rate state](#process-local-request-rate-state). |
| `ORRERY_RATE_LIMIT_PERSIST_INTERVAL_S` | `10` | Optional | Seconds between limiter snapshots, and therefore the most budget a restart can hand back to a client. Floors at 1; a malformed value falls back to the default with a warning. |
| `ORRERY_RATE_LIMIT_PERSIST_MAX_KEYS` | `2000` | Optional | Buckets written per snapshot, fullest first, so lowering it drops the clients furthest from their ceiling. Floors at 1. |

### Process-local request-rate state

Each server worker keeps at most **10,000 tracked client buckets** for the
sliding-window request limiter. At that cap, only an unseen client key is
refused: a client already in the store continues to use its existing bucket and
may proceed while it remains below its normal per-window quota. An unseen key
is admitted as soon as the oldest bucket's last admitted request is more than
one 60-second window old; after tracked traffic stops, saturation therefore
clears within one window. A capacity refusal uses the same `429` response and
`Retry-After` header as an ordinary quota refusal.

This is a **per-worker** guard. It is not shared across workers or replicas.
The 10,000 limit bounds the number of keys, not an exact byte total.
Deployments that need one global ceiling or more than 10,000 distinct clients
per minute still need an edge or shared limiter. Capacity refusals increment
the bounded-cardinality `nanda_chapter_rate_limit_capacity_rejections_total`
metric, which has no client-key or other attacker-controlled labels; ordinary
per-key quota refusals do not.

**Across a restart.** The live buckets are snapshotted to the `rate_limit_buckets`
table every `ORRERY_RATE_LIMIT_PERSIST_INTERVAL_S` seconds and restored at boot,
so a restart hands a client back at most one interval of budget rather than the
whole window. Keys are stored as `HMAC-SHA256(salt, client IP)`; the table never
holds an address. Two things have to hold for a restart to restore anything, and
`GET /health` reports them **separately**, because a single flag read true on a
deployment where the second did not hold:

- `rate_limit_persistence` — the table exists and this process may write it.
  `false` on a least-privilege role that cannot create it (apply
  `infra/migrations/0008_rate_limit_persistence.sql` as superuser); the limiter
  still limits, it just forgets across restarts.
- `rate_limit_salt` — `{"source": ..., "durable": ...}`. The salt the NEXT process
  hashes with has to be the salt this one used, or every restored key is an
  orphan. `source` is one of `env` (`ORRERY_RATE_LIMIT_SALT`), `file` (read back
  from `.org/rate-limit-salt`, so it has survived at least one boot), `file-new`
  (minted and written this boot — the first boot of a volume-backed install, and
  **every** boot of a volume-less one), `ephemeral` (could not be written),
  `env-rejected` (the variable is set but shorter than 16 characters; an
  ephemeral salt is in use and the boot log says so), or `unresolved` (before
  boot has run). `durable` is `true` only for `env` and `file`. A process whose
  salt is not durable skips the restore rather than counting orphaned rows as
  buckets carried.

`file-new` on every boot of a deployment means the salt is not surviving: set
`ORRERY_RATE_LIMIT_SALT`, or mount the `.org` directory on persistent storage.

> **Docker Engine caveat:** Docker Engine 28.0.0 or later is required for
> Docker's localhost-published-port L2 isolation. On older Engines, hosts on the
> same L2 segment may still reach ports bound to `127.0.0.1`; upgrade or use host
> firewall controls. See [Docker's port-publishing documentation](https://docs.docker.com/engine/network/port-publishing/).

## Database

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `POSTGRES_DB` | `orrery` | Optional | Database name. |
| `POSTGRES_USER` | `postgres` | Optional | Database user. |
| `POSTGRES_PASSWORD` | `orrery-dev-password-change-me` | **Yes — replace before first manual start** | Database password. The compose file refuses to start if it is unset. |
| `ORRERY_DB_SSL` | — (host-derived) | Optional | asyncpg TLS mode for the Postgres link. Leave unset: the server then **requires** TLS for any real network hop and disables it only for loopback/compose hosts (`localhost`, `127.0.0.1`, `::1`, `db`, `postgres`, `pgvector`). Set explicitly (`require` / `disable` / `verify-full` / …) to override. An `sslmode` already present in `DATABASE_URL` wins over the host default and is left untouched. |

### TLS to Postgres

Everything on the server↔Postgres link is sensitive — signing keys, API keys,
tokens, receipts, member PII. asyncpg negotiates **no TLS at all** for a
`postgres://` URL that carries no `sslmode`, so the server now decides
explicitly rather than inheriting that default (AUDIT_HARSH C3).

The rule is **require by default, exempt local visibly**: a loopback or compose
host gets `disable`, anything else gets `require`, and the choice is logged once
per process as `db.tls_mode` with the source that decided it. `prefer` is never
chosen automatically — it falls back to plaintext with no signal, which is
indistinguishable from success.

> ⚠️ **Deploying this to an existing environment:** if your Postgres cannot do
> TLS, the pool will now fail to create rather than quietly connecting in
> plaintext. The log line `db.tls_required_but_unsupported` names the remedy —
> set `ORRERY_DB_SSL=disable` — but set it *before* the deploy if you already
> know your database has no TLS. The dev/CI compose Postgres is one such
> database (it reports `ssl=off`), which is exactly why loopback and compose
> hosts are exempt by default.

These three compose into the server's connection string:

```
DATABASE_URL=postgres://POSTGRES_USER:POSTGRES_PASSWORD@db:5432/POSTGRES_DB
```

Compose builds `DATABASE_URL` for you from the three variables above and the server
talks to Postgres directly (`pg_store`) — there is no PostgREST or data-API layer to
configure.

## Optional — BYOK generative features

Generative features are **off by default** and the org works fully without a key.
Bring your own LLM key to turn them on; with no key, the deterministic path renders
everything and nothing breaks.

**With no key configured, the org contacts no provider — under `LLM_STRICT=1`.**
The generative endpoints serve their deterministic output and report
`planner_disabled` as the reason. That is a property of the endpoint rather than of
the network: it makes no request, so there is nothing for a firewall or an egress
policy to block.

> **This paragraph was not true until now, and the correction is the point of the
> flag.** A keyless org built an LLM client anyway and posted member names, skill
> lists and federation peer names to the configured provider under
> `Authorization: Bearer MISSING` — 18 requests over 24 driven ticks. Twenty-four
> call sites use that client and four asked whether they were allowed to; the four
> that asked behaved as documented, and the twenty that did not sent the traffic.
>
> `LLM_STRICT=1` refuses to build the client at all, so there is no client to call
> and nothing to bypass. It **ships as `false`**, which is the behaviour described
> above minus the promise: a keyless org still builds a client, and each such
> construction logs what `LLM_STRICT` would have refused. Read those lines from a
> deployed server, then set `LLM_STRICT=1`. Setting it back to `0` is the whole
> rollback — no code revert, no redeploy of a different image.
>
> An **absent** key has been refused since the resolver landed; what the flag adds
> is refusing a *substituted placeholder* — the `MISSING` and `no-key-configured`
> strings call sites passed so the client would construct.
>
> A **deliberate local endpoint is not affected in either mode.** An unkeyed
> `LLM_BASE_URL` on this machine is a correct configuration, and locality is read
> off the configured URL rather than resolved through DNS.

**Turning off ambient provider detection.** `LLM_AUTODETECT` defaults to `true`,
which is the behaviour described below. Set it to `0` to require an explicit
`LLM_PROVIDER`: with it off, a stray provider key in the environment no longer
decides which third party this org is pointed at.

**Which provider you get when you set none.** Provider selection auto-detects from
whichever provider key is present, preferring `anthropic`. If no key is present at
all, selection falls through to that same default, so `LLM_PROVIDER` unset and no
key means the *configured* provider is `anthropic` at
`https://api.anthropic.com/v1/` — reported at startup — even though nothing is sent
there while the planner is off. Set `LLM_PROVIDER` explicitly if you want the
configuration to state your intent rather than inherit it.

**A local model needs no key.** An endpoint on this machine — Ollama, LM Studio,
llama.cpp, vLLM — is a configured provider, not a missing one, so the planner stays
on with `LLM_API_KEY` empty as long as `LLM_BASE_URL` (or the `ollama` provider's
default) points at `localhost` or `127.0.0.1`. Your intent text reaches no third
party in that setup either.

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `OPENAI_API_KEY` | — (empty) | Optional | OpenAI-compatible key for generative features. |
| `LLM_API_KEY` | — (empty) | Optional | Generic, provider-agnostic LLM key. |
| `XAI_API_KEY` | — (empty) | Optional | xAI / Grok API key. |
| `LLM_PROVIDER` | auto → `anthropic` | Optional | Select the provider explicitly (e.g. `anthropic`, `openai`, `xai`, `ollama`). Unset auto-detects from whichever provider key is set, preferring `anthropic`, and falls through to `anthropic` when no key is set at all. |
| `LLM_MODEL` | provider default | Optional | Model id to use. Falls back to `DEFAULT_LLM_MODEL`, then the provider's default model. `DEFAULT_LLM_MODEL` is a bare-server-only runtime input; stock Compose forwards `LLM_MODEL`, not that fallback override. |
| `LLM_BASE_URL` | provider default | Optional | Override the provider API base URL (e.g. a proxy or self-hosted endpoint). |

## Optional — outbound email (Klaviyo)

Live delivery requires a recognized-true `KLAVIYO_LIVE_SENDS` flag, a nonempty
`KLAVIYO_API_KEY`, and operator authorization through either an exact single-use
`send_external` approval or an applicable bounded `send_external` grant. Missing
live-transport configuration keeps an authorized send in the restricted sandbox
transport. Missing authorization refuses or queues the send and does not deliver
it; it is not sandbox delivery. An exact approval binds the recipient, subject,
and body.

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `KLAVIYO_LIVE_SENDS` | `false` | Required for live delivery | Enables the live transport only with a recognized true value; without it, an authorized send uses the restricted sandbox transport. |
| `KLAVIYO_API_KEY` | — (empty) | Required for live delivery | Klaviyo provider credential; without it, an authorized send uses the restricted sandbox transport. Neither transport runs without an exact approval or applicable bounded grant. |

## Optional — NANDA registration

Publishes the org to NANDA NEST so its agents are discoverable.

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `REGISTRY_URL` | *(none)* | Optional | The registry this org publishes to **and discovers peers from**. ⚠️ **No default.** Unset means the org talks to no registry at all: it publishes nowhere and finds no peers through one — federation peers then come only from `KNOWN_CHAPTER_ENDPOINTS`. Earlier versions silently defaulted to `https://nest.projectnanda.org`; set it explicitly to keep that. |
| `AUTO_REGISTER` | `false` | Optional | Whether to auto-publish to the registry on boot. |

## Security — signing + federation enforcement

Shipped **on** (or loudly warned about) in `.env.example` since the security audit.

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `FEDERATION_ENFORCE_SIGNED_BROADCASTS` | `true` (in `.env.example`) | Recommended on | Reject unsigned / unknown-origin server-to-server broadcasts (403). Turning it off downgrades to warn-and-log — a peer can then forge cross-org broadcasts. |
| `FEDERATION_REQUIRE_SIGNED_RECORDS` | `true` (in `.env.example`) | Recommended on | Require a valid self-certifying attestation on discovered registry records; off means tampered endpoints are used unverified (warn-only). |
| `ORRERY_KEY_SECRET` | — (empty) | **Yes — the server does not start without it** | Seals the org's Ed25519 signing key **and** members' LLM provider keys at rest (AES-256-GCM, PBKDF2-derived). Generate with `openssl rand -hex 32`; `./orrery-up` sets one automatically. Store it outside the database — a dump cannot be restored to a working identity without it (`docs/BACKUP_RESTORE.md`). |
| `ORRERY_KEY_SECRET_PREVIOUS` | — (empty) | Only during a rotation | The `ORRERY_KEY_SECRET` being rotated out. **Read-only**: values still sealed under it unseal, and the boot-time seal-in-place migrations rewrite them under the current `ORRERY_KEY_SECRET`; nothing is ever sealed under it. Procedure: set `ORRERY_KEY_SECRET` to the new value and `ORRERY_KEY_SECRET_PREVIOUS` to the old one, restart, confirm the boot log's `sealed in place` lines for the signing key and any provider keys, then unset `ORRERY_KEY_SECRET_PREVIOUS` and restart again. The signing key bytes and the org's `did:key` do not change; no peer re-pins. Without this variable a changed `ORRERY_KEY_SECRET` makes every sealed row undecryptable. |
| `ORRERY_REQUIRE_SEALED_SECRETS` | `true` | Leave on | Whether secrets MUST be sealed before they are written at rest. `false` is the deliberate opt-in to plaintext (local test box; database inside the server's trust boundary) and lets the server boot with `ORRERY_KEY_SECRET` empty, logging each unsealed write. Only a recognised false spelling (`false`/`0`/`no`/`off`) disables it — a typo still requires sealing. |

Until that change, an unset `ORRERY_KEY_SECRET` printed one warning line at boot and then
stored the org's signing key in plaintext. Anyone with database, dump or backup
access could read it and sign ARP receipts, VRP attestations and federation
broadcasts as the org. Existing plaintext rows are **sealed in place** on the first
boot that has the secret: the same key bytes are re-encoded, so `did:key` is
unchanged and no peer has to re-pin.

## Optional — NANDA Index v2 (leveled 4-hop discovery)

Registers the org on a NANDA Index v2 — the leveled 4-hop discovery layer. This
is bare-server runtime documentation: stock Compose does not forward the Index
v2/account fields below, so setting them in the stack's `.env` has no effect.
The org
registers as an **org** with `hosting_path=registry` (it serves its own card, so it is
its own registry). Registration is **operator-triggered** — `POST
/admin/api/index-v2/register` (admin-auth) — and **never auto-fires on startup**, so
there are no surprise network calls. Leave `INDEX_ACCOUNT_*` blank to keep it disabled.

Point `NANDA_INDEX_URL` at `http://localhost:3001` for the local testbed;
`https://api.nandaindex.org` is the live, operator-gated index.

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `NANDA_INDEX_URL` | — (empty) | Optional | The Index v2 base URL. Empty disables Index v2. |
| `INDEX_ACCOUNT_EMAIL` | — (empty) | Optional | Index account email. Blank disables registration. |
| `INDEX_ACCOUNT_PASSWORD` | — (empty) | Optional | Index account password. Blank disables registration. |
| `ORG_DOMAIN` | — (empty) | Optional | The org's registered domain at the index. |
| `ORG_CONTACT_EMAIL` | — (empty) | Optional | Contact email recorded with the index (falls back to `INDEX_ACCOUNT_EMAIL`). |
| `INDEX_ORG_ID` | — (empty) | Optional | The org id at the index (`^[a-z0-9][a-z0-9-]*[a-z0-9]$`); defaults to a sanitized, lowercase `ORG_ID` when blank. |

## Optional — host39 card publishing (SMB Leg B)

Publishes a provisioned SMB tenant's **A2A agent card** to a [host39](https://agentcards.host39.org)
card host, so a no-infra business gets a hosted card without running anything itself.
Triggered explicitly by `scripts/publish_host39_card.py` — it is **not** wired into app
startup and **not** wired into `POST /provision`, so nothing auto-fires.
It publishes only with the **business's own listing grant** on file — the owner-signed
grant naming the tenant's `did:key`, the same record `scripts/register_tenant_on_index.py`
checks — and refuses by name (`no_owner_consent`, `grantee_mismatch`, `revoked`, or the
`COMMUNITY_MEMBER_NO_REGISTRY` veto) before any host39 call. Pass `--tenant-home` or run
where `$SMB_HOST_DATA_DIR` is; the operator's credential alone does not publish a card.

**Which artifact:** host39 takes the **A2A agent card**, not canonical NANDA AgentFacts.
Its `POST /cards` schema is `additionalProperties: false` over a flattened A2A field set
(`slug / display_name / description / runtime_url / version / capabilities /
authentication / skills / provider_name / provider_url`), and it serves the result as
`application/a2a-agent-card+json`. AgentFacts keeps its own home at the agent runtime's
`GET /agentfacts.json`; the published card points back at it via the `x-nanda` bag
(carried inside `capabilities`, because host39 rejects unknown top-level fields).

**This leg stops at host39.** Registering on `api.nandaindex.org` is Leg C — see
`docs/integrations/SMB_NANDA_HANDSHAKE.md`.

`HOST39_BASE_URL` has **no default**: an unnamed target means *publish nowhere*, never
*publish to production*. An unset variable and an empty one are treated identically, and
neither falls through to a default target or to an unauthenticated call.

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `HOST39_BASE_URL` | — (empty) | Required to publish | host39 base URL, e.g. `https://agentcards.host39.org`. Empty ⇒ publishing disabled. |
| `HOST39_TOKEN` | — (empty) | One of these | A host39 JWT. Preferred over email+password. |
| `HOST39_EMAIL` | — (empty) | One of these | host39 account email (used with `HOST39_PASSWORD` to obtain a JWT). |
| `HOST39_PASSWORD` | — (empty) | One of these | host39 account password. A half-set login (email without password) counts as **not configured**. |

Credentials are read from the environment only — never from a file by the publisher,
never passed as a command-line argument (argv is world-readable), and never written to a
commit, fixture, or log. The live test drive (`agent/tests/test_host39_live.py`) **skips**
when no credential is present, so a contributor without a host39 account runs green.

## Agent capability grants

The agent's file, shell, network, browser and desktop actions are bounded twice:
the consent gate authorises one action at a time, and a capability policy says
what this install may reach at all. Both are required, and neither replaces the
other.

Grants live in `~/.community-member/grants.policy`, one per line, `#` for
comments. There is no default — a missing file grants nothing, and every action
of those kinds is refused.

```
# origins the agent may open in a browser (scheme required)
browser.navigate:https://docs.example.com,https://*.wikipedia.org
# hostnames it may fetch over HTTP
net.http:api.example.com,*.openai.com
fs.read:~/Downloads/**
shell.exec:git,jq
```

| Capability | Pattern | Notes |
|---|---|---|
| `browser.*` | Origin — `https://example.com`, `https://*.example.com` | Scheme required and matched exactly; port optional, defaulted from the scheme. A bare hostname is refused when the file is read. |
| `net.http` | Hostname — `example.com`, `*.example.com` | The wildcard requires at least one subdomain label. |
| `fs.*` | Path glob — `~/Downloads/**` | `~` expanded; `**` spans path segments. |
| `shell.exec` | Binary name — `git` | Basename only; arguments are not matched. |
| `desktop.*` | Target name | |

`browser.*` takes origins rather than hostnames because that capability drives a
persistent browser profile holding the agent's cookies: a hostname grant would
also authorise the cleartext scheme for the same host.

### The capabilities do not compose the way their names suggest

`shell.exec` says **which binary** may run and nothing about its **arguments**.
So a grant for a binary that takes a path or a URL permits whatever that binary
does to any path or any URL, and the `fs.*` or `net.http` patterns elsewhere in
the file do not bound it:

```
fs.read:~/Downloads/**      # looks like "only Downloads"
shell.exec:awk              # reads any file, if the path is inside the program
```

`awk '{print}' /etc/shadow` names the path as an argument and is refused.
`awk 'BEGIN{getline l < "/etc/shadow"}'` puts the same path inside the program
`awk` interprets, and runs. Same binary, same grants, opposite outcomes — the
narrowing described below reads arguments, not what a binary does with them.

| Granting | Also permits |
|---|---|
| `cat`, `grep`, `head`, `tail`, `less`, `jq` | reading any file |
| `sed`, `awk`, `cp`, `mv` | reading and writing any file |
| `tee`, `rm` | writing or deleting any path |
| `curl`, `wget` | reaching any host, and writing the response anywhere |
| `ssh`, `nc` | connecting to any host |
| `sh`, `bash`, `zsh`, `python`, `python3`, `perl`, `ruby`, `node`, `php`, `lua`, `deno`, `bun` | all of the above, and running binaries not in the grant |
| `env`, `xargs`, `find`, `make`, `docker`, `sudo`, `su`, `busybox` | running binaries not in the grant |
| `git` | running any command, through a config alias, `core.pager`, `core.sshCommand` or a repository hook |
| `tar` | reading and writing any path, and `--to-command` runs a program |
| `vi`, `vim`, `more` | reading or editing any file, and a shell escape runs any command |

The agent prints a warning at startup for any such grant, naming what it
permits and the narrower grant it is wider than. It is a warning and not a
refusal: the operator may mean it. The list above is
`SUBSUMING_BINARIES` in `agent/community_member/sandbox/policy.py` — one place,
so the warning and this table cannot drift apart.

**No warning is not a safety claim.** That list is not exhaustive and cannot be.
The agent narrows exactly one shape of argument — one naming an existing file
outside your `fs.*` grants, described below — and nothing else: not a host, not
a path inside a program string, not a file the command creates. So the property
is still true of almost any binary that takes a host or a command as an
argument. A grant the agent says nothing about has not been assessed — it has
not been cleared. Cases that escape the list include an interpreter not named there, a
binary installed under a different name or a local script (matching is on the
basename), and a tool whose subsuming behaviour is a flag rather than its main
purpose, as `tar --to-command` is.

Treat every `shell.exec` line as the widest line in your policy, whether or not
the agent says anything about it.

#### Shell arguments are narrowed against your file grants — narrowed, not bounded

An argument naming an existing file your `fs.*` grants do not cover is refused
before the command runs, and the refusal names the argument and the grant that
would allow it. `cat /etc/shadow` is refused when no `fs.read` covers it, even
though `shell.exec:cat` is granted.

**This narrows; it does not bound.** It reaches one shape — a path written as an
argument — and these escape it:

| Escapes | Why |
|---|---|
| `awk 'BEGIN{getline < "/secret"}'` | the path is inside a program, not an argument. `awk '{print}' /secret` **is** refused — the same binary and grant, opposite outcomes |
| `python -c`, `sh -c`, `sed -e`, `find -exec` | anything taking a program as an argument |
| `curl https://host` | a host is not a path; nothing here bounds the network |
| `tee /new/file` | a file that does not exist yet cannot be resolved or judged |

Coverage is therefore per-**invocation**, not per-binary: there is no rule that
tells you which of your commands are narrowed. Closing this properly requires
containing the child process rather than reading its arguments — Landlock on
Linux bounds the filesystem, and the network only from ABI v4, with no
equivalent on macOS or Windows.

It also refuses some harmless commands: an argument that happens to name an
existing path is refused even when the binary would never open it.

The child runs in `~/.community-member/shell-workdir` rather than inheriting the
agent's working directory, so a relative argument has one meaning. Its
environment is reduced to `PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ` and `TERM`: the
agent's own environment holds its provider API key, and a granted binary that
prints or forwards its environment would otherwise carry that key out.

`agent/grants.policy.example` is a commented starting point; copy it to
`~/.community-member/grants.policy` and uncomment only what the install needs.
The example itself grants nothing, and deliberately suggests no shell binary —
there is no narrow choice to recommend. `git` looks like one, being about
repositories rather than arbitrary paths, and runs any command through a config
alias.

A refused action names the grant that would have permitted it and the file to
put it in. A malformed file is not partially applied — the agent logs the parse
error and runs with no grants, refusing everything, rather than enforcing a
policy the operator did not write.

## Data retention

The org runs a periodic sweep that ages out retention-bounded rows. Stock
deploys enable the sweep and enforce deletion; set
`ORG_RETENTION_SWEEP_DRY_RUN=true` to audit what would be deleted before
returning to enforcement. Each variable has an `ORG_`-prefixed canonical name
and a back-compat `CHAPTER_`-prefixed runtime alias. The bare server accepts
either and the `ORG_` form wins; stock Compose forwards only the canonical
`ORG_` names.

| Variable | Default | Purpose |
|---|---|---|
| `ORG_RETENTION_SWEEP_ENABLED` (alias `CHAPTER_RETENTION_SWEEP_ENABLED`) | `true` | Master on/off for the retention sweeper. |
| `ORG_RETENTION_SWEEP_DRY_RUN` (alias `CHAPTER_RETENTION_SWEEP_DRY_RUN`) | `false` | Stock deploys **enforce** retention (real `DELETE`s past each category's TTL). Set to `true` to opt into a review period — the sweeper then logs "would-delete" counts to the audit log without deleting — then flip back to `false`. |

## Admin

| Variable | Default | Purpose |
|---|---|---|
| `ORG_ADMIN_TOKEN` (bare-server runtime alias: `CHAPTER_ADMIN_TOKEN`) | generated on first startup | Bearer token gating the admin endpoints. A nonempty environment value wins over the persisted mode-`0600` token file; otherwise the server loads that file or generates and prints a token exactly once. Stock Compose forwards only `ORG_ADMIN_TOKEN`. |
| `ORG_HOME` (alias `CHAPTER_HOME`) | module dir | Bare-server data-directory control (org-config, badge, issuer log, signing keys) so co-located org processes on one host don't collide. Stock Compose does not forward container-owned path inputs; it owns the server data path. |

## Connect your org to other orgs

Two orgs that federate can see each other's members, match intents across the
boundary, and exchange signed summaries of what their agents are doing. Your org
federates with nobody until you say so: on a new install it has no peers and
discovers none.

Turning it on takes two settings.

```bash
# .env
FEDERATION_AUTODISCOVER=true
KNOWN_CHAPTER_ENDPOINTS=https://partner-org.example,https://another-org.example
```

`KNOWN_CHAPTER_ENDPOINTS` is the list you control: an org appears there because
you put it there. `FEDERATION_AUTODISCOVER` lets your org contact the orgs on
that list, and — if you have also set `REGISTRY_URL` — find others through the
registry. Restart the server after changing either.

Check it worked:

```bash
curl https://<your org>/api/federation
```

The `chapters` object lists the peers your org has reached. An empty object means
it has reached none yet: either the setting is off, the endpoints are unreachable,
or discovery has not run since the restart.

**Peers you list are the ones you trust.** An org discovered through a registry
still has to prove its identity before your org will accept anything signed by
it, but an entry in `KNOWN_CHAPTER_ENDPOINTS` is a decision you have made — treat
that list the way you would treat a firewall rule.

**Traffic between orgs is signed and refused if it is not.** You do not need to
configure that; it is on by default.

### Try it on one machine first

The repository ships a two-org Compose file so you can watch federation work
before pointing your org at anything real:

```bash
docker compose -f docker-compose.yml -f infra/compose.e2e-federation.yml up -d
```

That brings up a second org alongside yours, on the same host, with discovery
already enabled between them.

The second org runs without a database of its own. That is enough to watch two
orgs find each other and exchange signed traffic, and it is not a template for a
real deployment — a production org needs its own database.

## Advanced — server-only tuning

This is a mixed-support reference. Stock Compose already forwards
`ALLOWED_ORIGINS`, `METRICS_BEARER_TOKEN`, and `FEDERATION_AUTODISCOVER`; it
owns and fixes `MEMBER_PERSIST_OUTBOX_PATH` to its persistent container path.
The remaining advanced controls are bare-server or separately configured
settings and are not forwarded by stock Compose. Set those through a bare
server process or a separately reviewed deployment configuration, not the stock
Compose `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `ALLOWED_ORIGINS` | — (prod default) / `*` (dev) | Comma-separated CORS allowlist for browser access to the API. Under the default `prod` profile there is no wildcard: unset means no cross-origin browser access (signed server-to-server requests are unaffected). |
| `ORG_SLUG` / `ORG_DISPLAY_NAME` | derived from `ORG_ID` / `ORG_NAME` | Explicit URL slug / display-name overrides. |
| `ORG_JURISDICTION` (alias `CHAPTER_JURISDICTION`) | — (empty) | Legal jurisdiction code for the org (upper-cased), e.g. `EU`, `US-FED`, `US-HIPAA`. Surfaced in org metadata **and consumed by the retention sweeper** — declaring one changes what gets `DELETE`d. Each per-region override declares its direction: a **minimisation** regime (GDPR, UK GDPR, CCPA, CPA) can only shorten a TTL, a **statutory minimum** (NIST 800-171, DFARS, HIPAA, GLBA/SOX) can only lengthen one, and neither can move a TTL you set yourself — `chapter_policy.retention_days_by_category` stays the top layer. Unset, or set to `US`, means the module defaults apply unchanged. |
| `ORG_AGENT_PREFIX` | — (empty) | Prefix stripped from a member id when building its Host39 card URL. |
| `AGENT_FOCUS` / `AGENT_REGION` / `AGENT_LEADERS` | `General AI` / — / `[]` | The org agent's focus area, region label, and a JSON array of leader identities. |
| `DEFAULT_SCORING_METHOD` | `nanda-rep/0.1` | VRP reputation scoring method; unsupported values fall back to the default. |
| `FEDERATION_PEER_PRUNE_AFTER_S` | `259200` (3d) | Age after which stale, non-anchored federation peers are pruned. |
| `FEDERATION_BROADCAST_MAX_AGE_S` | `300` | Freshness window (seconds) for an inbound signed server-to-server broadcast timestamp. |
| `REGISTRY_ATTESTATION_TTL_S` | `86400` (24h) | Validity window for a registry attestation. |
| `RAILWAY_PUBLIC_DOMAIN` | — (platform-set) | Platform-injected public domain; when set, `resolve_public_url()` returns `https://<domain>`. Falls back to `PUBLIC_URL`. |
| `MAX_MEMBERS` | `40` | Cap on the number of agents that can join the org. |
| `ORG_HOST39_CARD_BASE` | — (empty) | Base URL of externally (host39-)hosted member A2A cards. **Unset = self-serve member cards:** a member that sent its public URL on join resolves to `{endpoint}/.well-known/agent.json` — its own served card; pure self-hosters need no host39 dependency. Set = the host39 card path, unchanged. |
| `METRICS_BEARER_TOKEN` | — (empty) | Bearer token that gates `/metrics`. |
| `MEMBER_PERSIST_OUTBOX_PATH` | `member_persist_outbox.jsonl` | Durable outbox for member rows whose Postgres write failed after retries — replayed at boot so a member is never silently lost. Point it at a path on a **durable volume** in production (a fresh container filesystem is ephemeral). Watch `nanda_chapter_db_failures_total` + `nanda_chapter_member_persist_failures_total` for non-zero. |
| `FEDERATION_AUTODISCOVER` | `false` | Enable cross-org peer discovery + sync. Opt-in. |
| `KNOWN_CHAPTER_ENDPOINTS` | — (empty) | Comma-separated peer org URLs to federate with. A peer qualifies structurally (its `/health` is org-shaped) — no naming convention required. Survives a registry outage. |
| `FEDERATION_DIRECTORY_URLS` | — (empty) | Comma-separated federation-directory URLs — e.g. a lean-index deployment where orgs publish signed peer records. Discovery (under the same `FEDERATION_AUTODISCOVER` gate) admits directory peers **only** with a valid self-certifying attestation and probes the endpoint the org signed; the directory also becomes a leg of the cross-registry divergence detector. `KNOWN_CHAPTER_ENDPOINTS` remains the operator trust anchor. |
| `FEDERATION_QUERY_TIMEOUT` | `15` | Seconds to wait on a federation peer query. |
| `THINK_CYCLE_INTERVAL` | `120` | Seconds between org think-loop cycles. |
| `SSE_POLL_INTERVAL_S` | `2.0` | Seconds between server-sent-event poll ticks. |
| `CHAPTER_SLUG`, `CHAPTER_DISPLAY_NAME` | derived from `ORG_ID` / `ORG_NAME` | Internal slug / display-name overrides; `chapter` is an internal-only term — prefer `ORG_ID` / `ORG_NAME`. |

## Production profile

`ORRERY_PROFILE=prod` is the **default** in `.env.example`. It hardens the two
application surfaces described below, but it **does not by itself make an
install ready for public exposure**. Fresh install-local secrets, TLS, an
externally correct `PUBLIC_URL`, and the rest of the
[production checklist](./INSTALL.md#going-to-production) still
apply. Set `ORRERY_PROFILE=dev` only for local work. The prod profile changes
two things:

- **CORS** — no `*` default. Set `ALLOWED_ORIGINS` to the explicit origins that should
  reach the API from a browser (e.g. your portal's domain):
  `ALLOWED_ORIGINS=https://portal.example.org`. Leaving it unset disables cross-origin
  browser access entirely; agents' Ed25519-signed server-to-server requests are not
  affected by CORS either way. Configuring `*` under `prod` still works but logs a loud
  warning — every website a member visits could read the API from their browser session.
- **API docs surfaces** — `/docs`, `/redoc`, and `/openapi.json` are not served. They
  enumerate every route and schema; a public org host shouldn't hand that map out.
  Set `ORRERY_PROFILE=dev` to turn them back on for local exploration.

Everything else (auth, signing, rate limits) is enforced identically in both profiles —
`prod` only removes the development conveniences that assume a trusted network.
