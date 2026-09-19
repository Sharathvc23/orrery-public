# Deploying Orrery on AWS

**Status: partially verified. Read this section before the rest.**

Nothing in this document has been run on AWS. No AWS account was used, no
resources were provisioned, and no step below has been executed against RDS,
EC2, ECS or Secrets Manager. Every AWS-specific instruction is marked
**UNVERIFIED**, with the check that would settle it.

What **is** verified — locally, on 2026-08-05, against `main` — is the part that
usually breaks a deploy: the container's configuration contract, and the three
settings that took production down or left it exposed this week. Those are in
[Before you touch AWS](#before-you-touch-aws-three-settings-that-are-outages),
and they are first on purpose.

The honest summary: **the Docker Compose stack is the tested artifact.** The
closest AWS deployment to something known-good is that same stack on one EC2
instance. Anything more AWS-native — Fargate tasks, RDS, an ALB — is a
translation nobody here has run.

| Layer | Status |
|---|---|
| The stack boots and serves | **Verified** — full `./orrery-up` install run 2026-08-05 |
| Container contract (port, user, writable paths, health) | **Verified** — executed against the running container |
| `ORRERY_KEY_SECRET` boot behaviour | **Verified** — a real container refused to start |
| `REGISTRY_URL` / `AUTO_REGISTER` resolution | **Verified** — interpolation *and* the running org's `/health` |
| `ORRERY_DB_SSL` resolution for an RDS-shaped hostname | **Verified** — resolver executed across five DSNs |
| Where the signing identity actually lives | **Verified** — by destroying the `.org` volume |
| Applying the schema by hand (the step RDS forces) | **Verified** — against a plain Postgres with no initdb hook |
| Path A — compose on EC2 | Compose half verified; **the EC2 half UNVERIFIED** |
| Path B — ECS Fargate + RDS | **UNVERIFIED** — ECS, EFS, ALB, Secrets Manager all untested |
| pgvector **on RDS** | **UNVERIFIED** — privilege requirement characterised locally |
| TLS to RDS actually negotiating | **UNVERIFIED** — and the one to check first |

A full verification log is at the end: [What was actually run](#what-was-actually-run).

---

## What you are actually deploying

Two long-running processes and nothing else:

| Component | What it is |
|---|---|
| **Org server** | FastAPI, listens on **7000**. Runs as uid **10001** (`orrery`), non-root. Root filesystem is **read-only**; the only writable paths are `/tmp` (tmpfs) and `/app/server/.org`. |
| **Postgres 15 + pgvector** | The org's durable state — signing identity, member directory, receipts, consent ledger. |

### Where the signing identity actually lives — measure this, do not assume it

**With `DATABASE_URL` set, the org's Ed25519 signing key lives in Postgres**, in
the `chapter_keys` table, sealed. It is **not** in the `/app/server/.org` volume.
The local key file is the offline fallback used only when there is no database.

**Verified 2026-08-05** by destroying the `.org` volume outright on a running
install — server stopped, volume removed, `db-data` kept, server restarted. The
org's `did:key` came back **byte-identical**. Its sealed row was confirmed
directly in the database, carrying the `enc.v1:` prefix, with its `public_b64`
matching the `publicKeyBase64` served at `/.well-known/did.json`.

So the durability requirements split, and they are not equally severe:

| If you lose | You lose |
|---|---|
| **`db-data`** | The org's **signing identity**, member directory, receipts, consent ledger. Peers that pinned the old `did:key` stop trusting you. This is the unrecoverable one. |
| **`server-data`** (`/app/server/.org`) | The admin token (a fresh one is minted, so the old one stops working), `org-config.json` — display profile, join policy, the setup lock — the cached conformance badge, and the member-persist outbox. Disruptive, not identity-destroying. |

Back up both. But if you are deciding where to spend care, it is the database.

**Members' agents are not part of this deploy.** Each member runs their own
agent on their own machine so its private key stays on hardware they control —
see [JOIN.md](./JOIN.md). What you are standing up is the org.

**Verified 2026-08-05 against the running container**, not read from the
Dockerfile: `id` reports `uid=10001(orrery) gid=10001(orrery)`; a write to
`/app/test_write` is refused with `Read-only file system`; `/tmp` and
`/app/server/.org` are both writable. The image's own healthcheck curls `/health`
every 15s.

**Steady-state memory, measured on an idle install** (one member, no LLM key):
server ~104 MiB, agent ~75 MiB, Postgres ~67 MiB — about 245 MiB together. The
~2 GB figure quoted in [INSTALL.md](./INSTALL.md) is headroom for the image build
and the first schema load, not steady state. Size for the build, not the idle.

---

## Before you touch AWS: three settings that are outages

Each of these has already happened on the running deployments. They are ordered
by when you must get them right, not by severity — the first one cannot be fixed
after the fact without consequences.

### 1. `ORRERY_KEY_SECRET` — set it before the first boot, not after

This seals the org's Ed25519 signing key and members' LLM provider keys at rest
(AES-256-GCM, PBKDF2-derived). **The server refuses to start without it.**

**Verified 2026-08-05 by booting the real image** with `ORRERY_KEY_SECRET` empty
against a working database. The container raises `SealingNotConfigured`, prints
the remediation, and ends with:

```
ERROR:    Application startup failed. Exiting.
```

It never serves a request. The refusal happens *before* any key-store access, so
a first boot and a restart over an existing plaintext row fail identically rather
than one silently writing and the other silently reading.

Also checked, because a failed boot that leaves damage behind would be worse than
a clean refusal: **a refused boot does not rotate the admin token.** The token
file on the mounted volume was byte-identical before and after. The token is
minted only when absent.

On a fresh install with the secret set, the sealed result was confirmed in the
database directly — `chapter_keys.secret_b64` carries the `enc.v1:` prefix. The
control is not merely present; it is selected by default and observably applied.

Why it is first: **three deployed orgs ran for weeks with this unset**, on a
build where it was optional, and all three stored their signing key in the
clear — a database dump was identity-forgery material. The fix was to make the
default refuse.

What this means for your ordering:

- **Generate it before the first deploy.** `openssl rand -hex 32`.
- **Put it in the environment before the container starts**, not after it fails.
  On a current build there is no "boot now, secure it later" — the org will not
  boot at all.
- **Back it up separately from the database.** The sealed key lives in the
  database; the secret that opens it must not. A dump plus a lost
  `ORRERY_KEY_SECRET` is an unrecoverable identity. See
  [BACKUP_RESTORE.md](./BACKUP_RESTORE.md).
- **Rotate it through `ORRERY_KEY_SECRET_PREVIOUS`, never by replacing it.**
  It is the key-encryption key for rows already written; a bare change makes
  the existing signing key undecryptable, which means a new `did:key` and every
  federated peer re-pinning. Set the new value in `ORRERY_KEY_SECRET` and the
  old one in `ORRERY_KEY_SECRET_PREVIOUS`, restart, watch the boot log reseal
  the signing key in place, then unset the previous secret and restart again.
  The key bytes and the `did:key` are unchanged throughout.

There is an escape hatch — `ORRERY_REQUIRE_SEALED_SECRETS=false` lets the server
boot with the secret empty and write plaintext. **Do not use it on AWS.** It
exists for a local test box where the database and the process share one trust
boundary. On AWS they do not: RDS snapshots, automated backups and read replicas
are all copies of that plaintext key.

> **UNVERIFIED (AWS):** which secret store you use. Secrets Manager and SSM
> Parameter Store both work in principle; neither was tested here. What matters
> is only that the value is present in the container's environment at process
> start. **Settles it:** deploy, then confirm the server reached the point of
> serving `/health` at all — with the variable missing it cannot.

### 2. `REGISTRY_URL` / `AUTO_REGISTER` — a stock install talks to no registry

**Verified 2026-09-19** on a stock `./orrery-up` install (`/health`, first boot):

```json
"registries": {
  "nest": { "url": "", "configured": false, "registered_count": 0 },
  "indexes": []
}
```

and the server's own boot line: `[registry] NO REGISTRY CONFIGURED — REGISTRY_URL
is unset or empty. This org publishes to no registry AND discovers no peers
through one`. There is **no default registry** anywhere in the tree: the compose
file interpolates `${REGISTRY_URL-}` (unset and empty both stay empty),
`server/registry_policy.registry_url` returns `""` for both, and the sovereign
agent's `community_member.registry.registry_url` follows the same rule. A
private deployment cannot announce itself to a public index by omission — it
has to be pointed at one.

> Earlier revisions of this page recorded the opposite (verified 2026-08-05: an
> absent `REGISTRY_URL` resolved to `https://nest.projectnanda.org`). That was
> a real defect and it is closed at source; the passage is kept only so a reader
> who saw the old behaviour knows it changed rather than suspecting their eyes.

On AWS, still set both explicitly — a value present in the task definition
documents the intent where the next operator will read it:

- **`REGISTRY_URL`** — your own registry's URL if you run one, or the public
  NANDA registry if you *choose* to be listed there; empty to stay private.
- **`AUTO_REGISTER=false`** if you want the org to keep a registry configured
  (for peer discovery) without publishing itself to it.

Leave the federation defaults alone unless you have a reason:
`FEDERATION_ENFORCE_SIGNED_BROADCASTS=true`,
`FEDERATION_REQUIRE_SIGNED_RECORDS=true`, `FEDERATION_AUTODISCOVER=false`. All
three resolve that way already; setting them explicitly documents the intent.

### 3. TLS to Postgres — check, do not assume

`ORRERY_DB_SSL` controls the asyncpg TLS mode. Its resolution order is: an
explicit `ORRERY_DB_SSL` wins; otherwise an `sslmode=` already in
`DATABASE_URL` wins; otherwise the host decides — loopback and compose-network
hosts get `disable`, **anything else gets `require`**.

**Verified 2026-08-05** by calling the resolver directly:

| `DATABASE_URL` host | resolves to |
|---|---|
| `db` (compose service) | `disable` |
| `localhost` | `disable` |
| `<name>.<id>.<region>.rds.amazonaws.com` | **`require`** |
| any host, with `?sslmode=verify-full` in the DSN | *(left to asyncpg)* |
| any host, with `ORRERY_DB_SSL=disable` set | `disable` |

So **an RDS hostname resolves to `require` by default**, which is what you want —
*if* the database accepts TLS.

Here is why that sentence is doing real work. The three deployed orgs reach
Postgres over a provider-internal hostname that **refuses TLS**. Measured
2026-08-03: all three report `db.tls_available: false` on `/health`. Deploying
them without `ORRERY_DB_SSL=disable` would have resolved to `require`, asyncpg
would have been refused the upgrade, the connection pool would never have been
created, and none of the three would have booted. The interim posture there is
`ORRERY_DB_SSL=disable`, which means **the TLS requirement is correct in code and
inert in that production**.

> **UNVERIFIED (AWS):** whether RDS negotiates TLS on your hop. It very probably
> does — RDS terminates TLS and publishes CA bundles — but *probably* is exactly
> the word that produced the incident above, so this document will not assert it.
>
> **Settles it, and it is cheap:** the server probes TLS capability once at boot
> and reports the answer at `/health` as `db.tls_available`. Deploy, then
> `curl https://<your-org>/health` and read the field.
>
> **The probe is independent of the mode you resolved to** — verified 2026-08-05
> on the compose stack, whose host resolves to `disable`. The boot log carried
> both lines:
>
> ```
> {"event": "db.tls_mode",  "ssl": "disable", "source": "host-default"}
> {"event": "db.tls_probe", "available": false,
>  "detail": "ConnectionError: PostgreSQL server at \"db:5432\" rejected SSL upgrade"}
> ```
>
> The probe opened its own `ssl='require'` connection anyway and reported the
> database's real capability. So the field answers the question whatever you have
> configured — including telling you that a `disable` you set defensively is no
> longer necessary. (`false` on a local compose stack is expected and not a
> finding: that Postgres ships no certificate.)
>
> - `true` — leave `ORRERY_DB_SSL` unset. The host default already requires TLS.
> - `false` — you have a database that will not do TLS. `require` is an outage,
>   not a fix. Either fix the database or set `ORRERY_DB_SSL=disable` and record
>   that you have accepted the network as your encryption boundary.
> - `null` — the pool has not been created yet, or the probe could not run. Not
>   an answer; check again once the org is serving traffic.
>
> If you want certificate verification and not just encryption, `require` does
> **not** verify the server certificate. `ORRERY_DB_SSL=verify-full` with the RDS
> CA bundle available to the container is the stronger setting — **UNVERIFIED**,
> and it needs the bundle mounted somewhere the read-only rootfs can read.

---

## Path A — the compose stack on one EC2 instance

**Recommended, because the compose stack is the thing that is actually tested.**
The compose half of this path was run end to end on 2026-08-05 — `./orrery-up`
built both images, brought up `db` → `db-ready` → `server` → `agent`, the agent
joined, and the org served `/health`, `/version`, `/.well-known/did.json` and its
boot conformance badge. **The EC2 half below is UNVERIFIED.**

The trade is honest: you get the tested artifact, and you own the instance —
patching, backups, and a single availability zone.

1. **Instance.** Amazon Linux 2023 or Ubuntu LTS, x86-64, 2 vCPU / 4 GB as a
   starting point. Steady state is small — ~245 MiB across all three containers,
   measured — but the first `up` builds the server image from source and loads a
   ~5,700-line schema, and that is what the sizing is for.
   **UNVERIFIED:** the instance size on EC2. **Settles it:** watch memory during
   the first build and schema load, which is the heaviest moment, not after.
2. **Storage.** Put the Docker volumes on an EBS volume that is **not** the root
   volume, and snapshot it. **`db-data` is the one that holds the org's signing
   identity** — see [above](#where-the-signing-identity-actually-lives--measure-this-do-not-assume-it).
   `server-data` holds the admin token and org config; back it up too, but losing
   it is recoverable.
3. **Install Docker and the Compose v2 plugin**, then clone the repo. Do not
   start the stack until the deployment settings in the next step are present.
4. **Write `.env` before the first `up`**, with the deployment settings below
   set explicitly:

   ```bash
   ORRERY_KEY_SECRET=<openssl rand -hex 32>     # before first boot, always
   POSTGRES_PASSWORD=<a real secret>
   # The ALB reaches the instance, not its loopback interface.
   SERVER_BIND_HOST=0.0.0.0
   REGISTRY_URL=                                 # explicit empty = not published
   AUTO_REGISTER=false
   ORRERY_PROFILE=prod                           # locks CORS, closes /docs + /openapi.json
   ALLOWED_ORIGINS=https://<your-ui-origin>
   PUBLIC_URL=https://<your-org-hostname>
   METRICS_BEARER_TOKEN=<a real secret>          # otherwise /metrics is open
   ```

   `./orrery-up` generates `ORRERY_KEY_SECRET` and `POSTGRES_PASSWORD` for you if
   you let it write `.env`, and refuses outright to install with the shipped demo
   Postgres password. Orrery's safe local default publishes the server only on
   `127.0.0.1`; Path A must opt into `SERVER_BIND_HOST=0.0.0.0` so the ALB can
   reach the instance's port 7000. Existing EC2/ALB deployments must add this
   setting **before upgrading** to a release with the loopback default, or their
   ALB health checks will fail. Keep the security-group rule in step 6 so only
   the load balancer can reach that port.

   After writing `.env`, run `./orrery-up` — or `docker compose up -d` if you
   maintain `.env` yourself.
5. **TLS in front.** The server speaks plain HTTP on 7000. Put an ALB or a
   reverse proxy in front of it and terminate TLS there; `PUBLIC_URL` must be the
   external `https://` URL, because it seeds the org's `did:web` identity and its
   published discovery surfaces.
   **UNVERIFIED:** ALB health-check configuration. The container's own health
   endpoint is `GET /health` on 7000, returning `{"status": "ok", …}`.
6. **Security group.** Inbound 443 from the internet (or your VPC) to the load
   balancer; inbound 7000 only from the load balancer. Postgres stays on the
   Docker network and is never exposed.
7. **Backups.** EBS snapshots cover the volume. They do **not** cover
   `ORRERY_KEY_SECRET` — that lives in your secret store, and a snapshot without
   it restores to an org that cannot sign. The repo also ships an opt-in backup
   sidecar (`docker compose --profile backup up -d`) writing timestamped
   `pg_dump` files. See [BACKUP_RESTORE.md](./BACKUP_RESTORE.md).

### Keeping it up

- `docker compose logs -f server` for the boot sequence. The lines worth reading
  are the sealing check, the TLS probe (`db.tls_probe`), and the conformance
  badge generation.
- `curl https://<your-org>/health` — `status`, `members`, `federation_state`,
  `db.tls_available`, `trusted_proxy_hops`, `rate_limit_persistence` and
  `rate_limit_salt`.
- `curl https://<your-org>/version` — reports the exact `git_commit` running.
  This exists because a silent stale deploy is otherwise invisible; check it
  after every deploy.
- `docker compose up -d --build` after pulling new code. **UNVERIFIED:** whether
  you want to build on the instance at all — see the ECR note below.

---

## Path B — ECS Fargate + RDS

**Entirely UNVERIFIED.** No part of this has been run. It is written as a shape
to work from, not a procedure to follow, and the places where it will bite are
called out rather than smoothed over.

**Shape:** one Fargate service running the server image, an RDS PostgreSQL
instance, an ALB in front, secrets from Secrets Manager, and EFS for the
`/app/server/.org` volume.

What differs from compose, and needs deciding:

1. **The image has to come from somewhere.** Compose builds it locally from the
   repo root. On Fargate you need it in ECR, built by CI and tagged. Pass
   `GIT_COMMIT` / `GIT_BRANCH` / `BUILD_TIMESTAMP` as build args so `/version`
   reports the truth. Note that **the compose path only stamps the commit** —
   verified 2026-08-05, a local `./orrery-up` install reports
   `git_commit: "8375fd0"` but `git_branch: "unknown"` and
   `build_timestamp: "unknown"`. If you want all three, your CI has to pass all
   three; do not assume the compose behaviour carries over.
2. **The schema does not load itself — but applying it by hand works.** Under
   compose, `infra/init.sql` (~5,700 lines) and `infra/seed.sql` are mounted into
   the Postgres image's `docker-entrypoint-initdb.d` and run on the database's
   first boot. **RDS has no such hook**, so you must apply both by hand, once,
   before the server starts.

   **Verified 2026-08-05:** both files were applied with `psql -v ON_ERROR_STOP=1`
   to a *plain* Postgres started with no initdb mounts, as the master user. Both
   exited 0. Afterwards: **109 tables** in `public`, `vector 0.8.6` installed in
   schema `extensions`, and `consume_org_invite` present. So the SQL itself is
   fine outside the initdb path; what remains untested is RDS specifically.

   The server also waits on a one-shot `db-ready` gate under compose; on Fargate
   there is no equivalent, so a server task that starts against an unmigrated
   database will come up and fail its data calls.
3. **pgvector — this is where an under-privileged role fails, and it fails
   first.** The schema's opening statements are
   `CREATE SCHEMA IF NOT EXISTS extensions;` and
   `CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA extensions;`, and one table
   uses `extensions.vector(384)`.

   **Verified 2026-08-05:** applying the same file as a **non-superuser** role
   stops immediately at statement two —

   ```
   ERROR:  permission denied to create extension "vector"
   HINT:  Must be superuser to create this extension.
   ```

   That is the good case: it is loud, it is the first thing that happens, and
   nothing partial gets written. **UNVERIFIED on RDS**, where the privilege model
   differs — the master user is `rds_superuser` rather than a true superuser, and
   `vector` must be available to your engine version. **Settles it:** connect to
   the RDS instance as the master user and run those two statements alone, before
   anything else. If they fail, no later step matters.
4. **Confirm the function landed.** The invite redemption path depends on
   `consume_org_invite`, a SQL function defined in `init.sql` rather than in
   application code. After applying the schema, check for it explicitly:

   ```sql
   select proname from pg_proc where proname = 'consume_org_invite';
   ```

   An empty result means invite-gated joins will fail at redemption time, on a
   database that otherwise looks loaded.
5. **`/app/server/.org` must be writable by uid 10001.** The container runs
   non-root with a read-only rootfs, so this mount is one of only two writable
   paths. An EFS access point with a POSIX uid/gid of 10001 is the obvious fit.
   **UNVERIFIED on EFS.** Note the consequence is narrower than it first looks:
   the signing identity is in the database, so an unwritable or ephemeral `.org`
   costs you the admin token and `org-config.json` — including the join policy —
   not the org's `did:key`.
6. **Task count.** Nothing here was tested with more than one server process.
   Do not run two tasks until someone has, especially given both would share the
   same `.org` volume.
7. **`ORRERY_DB_SSL`.** Read trap 3 above. Deploy, then read
   `db.tls_available` from `/health` before deciding anything.

---

## Pre-deploy checklist

Ordering matters; the first item is not recoverable after the fact.

- [ ] `ORRERY_KEY_SECRET` generated and present in the environment **before the
      first boot**, and backed up separately from the database.
- [ ] `POSTGRES_PASSWORD` is a real secret.
- [ ] `REGISTRY_URL` set **explicitly** (empty unless you mean it).
- [ ] `AUTO_REGISTER=false` set explicitly.
- [ ] `ORRERY_PROFILE=prod` and `ALLOWED_ORIGINS` set.
- [ ] `METRICS_BEARER_TOKEN` set.
- [ ] `PUBLIC_URL` is the external `https://` URL.
- [ ] `db-data` (or your RDS instance) is on durable, backed-up storage — this is
      where the signing identity lives.
- [ ] The `/app/server/.org` volume is writable by uid 10001.
- [ ] The schema is applied (Path B only) and `consume_org_invite` exists.
- [ ] TLS terminated in front of port 7000.

## Post-deploy checks

```bash
curl https://<your-org>/health     # status ok; read db.tls_available and registries
curl https://<your-org>/version    # git_commit matches what you shipped
```

- `registries.nest.configured: true` when you did not intend to be discoverable →
  trap 2. `REGISTRY_URL` was left unset.
- `db.tls_available: false` → decide trap 3 deliberately; do not flip
  `ORRERY_DB_SSL=require` on a database that refuses TLS.
- `rate_limit_salt.source: file-new` on a second or later boot → the salt file
  is not surviving restarts, so `rate_limit_persistence: true` restores nothing
  and every restart hands every client a full quota. The stack in this guide
  mounts `.org` on a volume, so this reads `file` from the second boot on; a
  server with no persistent filesystem needs `ORRERY_RATE_LIMIT_SALT` set.
- `trusted_proxy_hops: 0` behind an edge proxy → the per-IP rate limiter is
  keying on the proxy's address, so every caller shares one bucket and one of
  them can 429 all of the others. Set `TRUSTED_PROXY_HOPS=1` for a single edge
  and **re-read this field after the restart**: it reports what the running
  process resolved, not what the variable now says, so it is the check that
  tells you the change actually landed.
- `git_commit: "unknown"` → your build did not stamp provenance; fix it before
  you need it.
- **Restart the server once and confirm the org's `did:key` at
  `/.well-known/did.json` is unchanged.** Cheap now, expensive to discover later.
  If it *did* change, your database is not durable — that is the failure this
  check exists for, and it is not the `.org` volume.

---

## What was actually run

Executed 2026-08-05 against `main` on a local machine. Listed so a reader can
tell which claims rest on observation and which rest on reading.

**Full install.** `./orrery-up --yes` on alternate ports: prerequisite checks,
`.env` with fresh secrets, both images built, `db` → `db-ready` (exited 0) →
`server` → `agent` all up, agent joined, sign-of-life drill green.

**Container contract.** `id` inside the running server → `uid=10001(orrery)`.
Write to `/app` refused, `Read-only file system`. `/tmp` and `/app/server/.org`
both writable. Idle memory measured across all three containers.

**Key sealing.** The image booted with `ORRERY_KEY_SECRET` empty →
`SealingNotConfigured`, `Application startup failed. Exiting.`, never served.
The admin-token file was byte-identical before and after that failed boot. On the
working install, `chapter_keys.secret_b64` carries the `enc.v1:` prefix and its
`public_b64` matches `/.well-known/did.json`.

**Identity durability.** `server-data` volume destroyed with `db-data` intact;
server restarted; `did:key` came back identical. The admin token was regenerated.

**Registry trap.** `docker compose config` against two env fixtures (absent vs.
explicit-empty `REGISTRY_URL`), plus the running org's own `/health` reporting
`nest` as `configured: true` on a stock install.

**DB TLS.** The resolver executed across five DSN shapes. The running stack's
boot log showing `db.tls_mode ssl=disable` alongside `db.tls_probe
available=false` — the probe running independently of the resolved mode.

**Schema by hand.** `infra/init.sql` + `infra/seed.sql` applied with
`ON_ERROR_STOP=1` to a plain Postgres with no initdb mounts: both exit 0, 109
public tables, `vector 0.8.6` in `extensions`, `consume_org_invite` present. The
same file as a non-superuser: `permission denied to create extension "vector"`,
stopping at the second statement.

### What remains genuinely unverifiable here

No AWS account was used, so none of the following can be settled from this
machine, and each is named with what would settle it:

| Claim | Settles it |
|---|---|
| RDS negotiates TLS on your hop | Deploy; read `db.tls_available` from `/health` |
| `vector` is available and creatable on your RDS engine version | Run the two `CREATE` statements as the master user, alone, first |
| An EFS access point maps uid 10001 correctly | Deploy; write to `/app/server/.org` from the task |
| Secrets Manager / SSM delivers the variable at process start | Deploy; the server not booting *is* the negative result |
| ALB health-check settings | Deploy; `GET /health` on 7000 is the target |
| EC2 instance sizing under a real build | Watch memory during the first build + schema load |
| More than one concurrent server task | Untested. Do not do it yet |

## See also

- [CONFIGURATION.md](./CONFIGURATION.md) — every variable
- [INSTALL.md](./INSTALL.md) — the compose install and the production checklist
- [BACKUP_RESTORE.md](./BACKUP_RESTORE.md) — `ORRERY_KEY_SECRET` and the dump
- [JOIN.md](./JOIN.md) — how members join once the org is up
