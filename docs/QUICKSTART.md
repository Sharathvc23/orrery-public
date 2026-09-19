# Quickstart — `./orrery-up` from a clean machine

One command, what it prints, and what each resulting state can and cannot do.
Everything quoted here is the installer's own output as observed on a clean
machine, not a paraphrase; where a state was not driven it says so.

## Before you start

- Docker with the Compose v2 plugin, daemon running.
- Python 3.10+ (the installer is a stdlib script; it needs no virtual
  environment and installs nothing on the host).
- No free ports required. The installer starts looking at `7000` (org), `8080`
  (agent) and `8600` (renderer), takes the next free port when one is busy,
  writes the result to `.env` and reuses it on every later run.
- No LLM key, no account, no cloud credential.

`./orrery-up` checks each prerequisite first and stops with the fix if one is
missing, so a wrong prerequisite costs a message rather than a half-built
stack.

## The command

```bash
git clone https://github.com/Sharathvc23/orrery-public
cd orrery-public
./orrery-up
```

The directory name is the Compose project name, so it is also the name of the
data volumes a later run picks up; keep it.

For a non-interactive run (CI, scripting) add `--yes`. Name a port with
`--server-port`, `--agent-port` or `--renderer-port`; a named port is used or
the collision is reported, never reassigned.

## What a first run prints, and what each line established

The drill probes four things and then prints only addresses it has just read
without a credential. Observed, in order:

```
✓ org /health is green
✓ boot conformance badge served
✓ agent 'demo-agent' joined — org reports a member on /health
✓ agent serves its own card (agent.json)
── sign of life: ALL GREEN ──
```

followed by five URLs — the org's `/health`, its conformance badge, its
dashboard surface, the agent's card, and the renderer — and then:

```
   SEE IT — open http://127.0.0.1:8600/
            set "Server" to http://127.0.0.1:7000, pick "dashboard".
            served by the stack; ./orrery-up down stops it with everything else.
   stop:    ./orrery-up down    (add --purge to drop data)
```

What each check established, measured after the run:

| Line | What it read | What that proves |
| --- | --- | --- |
| `/health is green` | `200 {"status":"ok","members":1,"federation":0,…}` | The server answers and counts one member. |
| `badge served` | `200`, a signed badge, `passed=3 failed=0`, `org.orrery.attestation: self-attested` | A badge is served and verifies. It is **self-attested**: the org ran its own checks and signed the result, and nobody witnessed the run. "Served" is what the line asserts; "conformant" is not. |
| `joined` | the agent's log `join → registered: True`; `/health` `members: 1` | The first local agent registered. The probe reads the member **count**, not the agent's profile — profiles are private until the agent opts in, so the count is the honest signal. |
| `serves its own card` | `200` with the agent's `did:key` | The agent is up and identifies itself. |

`ALL GREEN` is four reads. Nothing in the drill exercises a write or a signed
request; the first interactive thing a reader does — the dashboard form — is
driven in CI in a real browser and works, but the drill itself does not claim it.

A first run with nothing cached pulls the base images from Docker Hub, apt
packages from Debian and wheels from PyPI, and contacts nothing else; with
those cached, a run from clone to `ALL GREEN` took 23–64 seconds and its five
containers sent no packet outside the Compose network — measured with a packet
capture across install, first boot, the drill and one think cycle.

### First run or re-run — the installer says which

Before Compose starts, the installer asks whether it already holds containers
for this project and prints one of:

```
first start: pulling images and building the stack (db, server, agent, renderer) — be patient…
reconciling the stack (db, server, agent, renderer) — rebuilds and restarts only what changed…
```

A re-run prints `✓ .env kept (idempotent)`: the secrets and the pinned ports
are byte-identical to the first run, so the org keeps its identity. Every run
also prints one ports line naming each service's port and why it is that port
— on a first run:

```
✓ ports: org server 7000 (allocated at the default), agent 8080 (allocated at the default), reference renderer 8600 (allocated at the default)
```

and on every run after it `(pinned in .env as SERVER_PORT)` and so on, or
`(named by --server-port)` when you chose it.

## State 1 — keyless (what the command above produces)

The generated `.env` ships `AGENT_PROVIDER=`, `AGENT_API_KEY=` and
`AGENT_MODEL=` empty. The banner then ends with, verbatim:

```
   keyless install — DETERMINISTIC ONLY. The org, agent, joining,
   signing and governance all work; anything that needs an LLM
   (planning, conversation, generated content) does not run.
   To enable generative features: set AGENT_PROVIDER/AGENT_API_KEY/
   AGENT_MODEL in .env (any provider) and `./orrery-up` again.
```

The agent's log says the same: `no LLM configured … running DETERMINISTIC-ONLY.
The autonomous think loop is not started`. The server's think cycle logs
`Insight skipped: no LLM provider configured — no request was made`.

**What keyless can do, each observed:** every documented read answers `200` —
`/agentfacts.json`, `/.well-known/conformance.json`, `/.well-known/agent.json`,
`/api/skills`, `/api/surfaces/dashboard`; the surface stream at
`/api/surfaces/dashboard/stream` answers `200 text/event-stream`; the renderer
paints the dashboard in a browser — the org's card, `Members 1 / Peer orgs 0`,
the think-cycle count, the intent form — and submitting the form records an
intent and paints *Intent Matched*; an unsigned A2A `message/send` to the agent
answers `-32004` with a message that says exactly why and how to sign. Joining,
signing, receipts, the consent gate and governance all run: none of them needs
a model.

**What keyless cannot do:** anything generative — planning, conversation,
LLM-composed surface content, the digest headline (a deterministic fallback
builds it). The dashboard's *Think Cycles* counter still counts up on a keyless
install even though each cycle is skipped without a request; the number is
activity of the loop, not of a model.

## State 2 — with an LLM key

Set three values in `.env` and run the installer again:

```
AGENT_PROVIDER=<anthropic|openai|xai|groq|local>
AGENT_API_KEY=<your key>
AGENT_MODEL=<a model name that provider serves>
```

`./orrery-up` reconciles the stack and the banner no longer prints the keyless
block. The agent's think loop starts; planning, conversation and LLM-composed
surface content run against your provider; nothing else about the org changes
— the same surfaces, the same signatures, the same gate. The `AGENT_*` values
reach the agent's container; the org server's own generative features (the
digest headline, insights) read the separate `LLM_PROVIDER` / `LLM_API_KEY` /
`LLM_MODEL` values, which the installer does not write — see
[`CONFIGURATION.md`](./CONFIGURATION.md).

**Not driven in the release pass.** Every observation on this page above this
heading was made on a keyless install. The keyed state is exercised in CI by
the server and agent suites against provider transports under test doubles,
and against live providers only by the operator's own run; treat the
description of this state as read from the installer and the code, not from a
recorded drive.

## Stopping, restarting, starting over

```bash
./orrery-up down            # stop the stack; data and .env kept
./orrery-up down --purge    # stop it and drop the data volumes
```

`down` prints `✓ stack stopped (data kept — --purge to drop)`. `down --purge`
prints `✓ stack stopped and volumes purged (the database is gone)` and then,
because `.env` is deliberately kept:

```
   .env kept: its secrets and the org's pinned ports survive, so the next run is the same org on an empty database. Delete .env too for a new org.
```

**Deleting `.env` while the database volume still exists is refused by name.**
A fresh `.env` would carry a new database password, and the volume was
initialised with the old one, so the stack would start and wait on a database
it cannot log in to. The installer names the volume and both fixes: restore
the `.env` that created it, or `./orrery-up down --purge` and start over. If a
wrong password does reach the database, the wait is bounded (300 seconds by
default) and the installer prints the database's own
`password authentication failed` line and the fix instead of waiting forever.

**Interrupted mid-run** (Ctrl-C): the installer prints
`✗ interrupted → the stack may be partly started; ./orrery-up again resumes it
(.env is kept, running services are reconciled), ./orrery-up down stops it`
and exits 130. Running it again is the right move.

## See two agents transact

One script stands up two orgs and two agents on this machine — separate homes,
keystores, passphrases, consent ledgers and principals; A joins org one, B
joins org two; nothing is shared — has A call B once under a grant that names
exactly that action, verifies the result with a separate implementation, then
breaks the call four ways and shows each refusal. Docker, Python 3.10+ and
Node 20+; ports are allocated; it tears itself down, and the same script runs
in CI on every change to what it exercises.

```bash
bash scripts/demo_two_agents.sh
```

Everything quoted below is the script's own output from a recorded run
(identifiers vary per run); the evidence for each step lands under
`demo-evidence/` with a `README.txt` naming every file.

### The happy path

A's principal — a key that is not A's — signs a grant naming one action. A's
consent gate checks the grant (grantee is A, grantor is not A, signature,
window, scope names exactly this action), records the verdict as a
consent-ledger row and a signed sm-aae envelope **before** anything goes on
the wire, writes the pending attempt, sends over signed A2A, and B co-signs the
receipt:

```
SENT save_note → did:key:z6MkgGua… under dat:did:key:z6Mkjp7E…:e59aa8c9-…; receipt 8a5aac9a-… co-signed → demo-evidence/1-happy-path
   ✓ receipt 8a5aac9a-… co-signed by B; org one holds it (its signed principal-scoped read returns it)
```

### Verified by a separate implementation

Two JavaScript verifiers in `smb_funnel/` that share no code with the Python
that produced the receipt, fed the did:keys **from the agents' cards**, not
from the receipt:

```
VERIFIED ✓  issuer_did=did:key:z6MkogFj… action=message_sent
VERIFIED ✓  co-signed by witness_did=did:key:z6MkgGua… over action=message_sent
```

What each proves, and does not:

| Verifier | Checks | Does not check |
| --- | --- | --- |
| `verify.mjs --issuer <A's card did>` | the receipt's schema; the Ed25519 signature over the JCS-canonical receipt under `issuer_did`; that `issuer_did` equals the did on A's card | the co-signature, the grant or any authority, the receipt's place in A's chain, revocation |
| `verify_cosign.mjs --witness <B's card did>` | B's Ed25519 co-signature over the corroboration payload (the receipt minus its signature and witness entries) under the did on B's card | everything in the column above |

Two limits the demo makes visible rather than hides. **The grant (DAT) and
the signed sm-aae envelope have no verifier in this tree other than the
libraries that produced them** — the evidence directory holds both, and a
third party can only re-run the producer's own checks on them. **A
database-backed org serves no Merkle checkpoint**: `GET /api/checkpoint` and
the inclusion proof exist only over a SQLite issuer log, so
`demo-evidence/1-happy-path/org/checkpoint.json` records `404`, and org one's
holding of the receipt is shown by its signed, principal-scoped read instead.

### Four refusals

**Denial** — a grant naming a different action, and no grant at all:

```
REFUSED at the consent gate (authority_scope): grant … names ['a2a.tasks/send#install_skill'], not 'a2a.tasks/send#save_note'
```

exit 2 both ways (`authority_no_grant` for the second). The envelope records
*denied*; no receipt and no attempt exist; B's open `tasks/get` does not know
either task id — nothing reached the wire.

**Tampering** — one byte flipped in the receipt, and `issuer_did` swapped to
B's key while verifying against A's card:

```
FAILED ✗       stage=signature detail=Ed25519 verification failed
```

exit 1 both times; the co-signature verifier fails the flipped receipt at the
same stage.

**Expired** — a grant whose window has passed:

```
REFUSED at the consent gate (authority_expired): grant … expired at 2026-09-19T00:40:45Z (now 2026-09-19T01:40:51Z)
```

exit 2; a denied envelope; B never saw it.

**Interrupted** — the driver kills A after `tasks/send` returns and before the
outcome is recorded:

```
[fault] tasks/send returned (completed); killing A now (os._exit 9)
```

B's `tasks/get` answers — B executed. A has no receipt. On restart A prints:

```
[agency-log][UNKNOWN] message_sent started 2026-09-19T02:19:24Z ('Called Agent B (save_note).', counterparty Agent B, attempt 6991c0f0-…): the process died before the outcome was recorded. Not retried…
```

`GET /api/agency-log/unresolved` lists the attempt with `state=unknown`, and a
retry with the same task id is refused before it sends:

```
REFUSED as a duplicate: DuplicateActionError: action_ref … already has an attempt in state 'unknown' …
```

exit 3. Nothing re-fired. That is the UNKNOWN state [`TRUST_MODEL.md`](./TRUST_MODEL.md) § 2.5
describes: an action that happened, whose outcome was not observed, recorded
as exactly that rather than as nothing.

## Where to next

- The org's HTTP surface: [`API.md`](./API.md).
- Every setting the stack reads: [`CONFIGURATION.md`](./CONFIGURATION.md).
- The manual Compose path, naming the org, production: [`INSTALL.md`](./INSTALL.md).
- What a receipt, a badge and a signature do and do not prove: [`TRUST_MODEL.md`](./TRUST_MODEL.md).
