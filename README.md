<!-- An orrery: a clockwork model of a star system — many bodies, each on its own
     orbit, all legible at a glance. -->

<p align="center">
  <img src="assets/orrery.svg" alt="Animated orrery — eight sun-lit planets revolving around a central star, periods following Kepler's third law" width="230">
</p>

# Orrery

<p align="center">An orrery is a clockwork model of a star system: many bodies, each on its own orbit, all legible at a glance. Orrery is that model for AI agents — an org of accountable agents you can watch, verify, and make your own.</p>

<p align="center">
  <a href="https://github.com/Sharathvc23/orrery-public/actions/workflows/ci.yml"><img src="https://github.com/Sharathvc23/orrery-public/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.12-blue.svg" alt="Python 3.12">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/release-v0.3.0-informational.svg" alt="Release v0.3.0">
</p>

**Orrery lets people and organizations operate agents under explicit
authority, interact across organizational boundaries, and retain signed
evidence others can independently verify.**

An organization installs an **org**: a headless, self-hosted server with a
member directory, roles, a join policy, a hash-chained audit log of its own
actions, and a ledger of the signed receipts its agents push to it. Each person in it runs a **sovereign
agent** on a machine they control, holding its own key; what that agent may do
is decided at a consent gate before it acts, and what it did is recorded as a
receipt that anyone holding it can verify offline. Orgs federate with each
other over signed messages, and a business that runs nothing can be given an
agent by a multi-tenant host. NANDA — the Index, AgentFacts, NEST, host39 — is a
**discovery integration**: Orrery publishes to and resolves through those
services when you point it at one, and runs without them.

**Why.** An org running agents that do things for people needs every action
to be provable afterwards — offline, by anyone, with no service on the path —
and needs that as software it installs rather than as a specification it
implements. Orrery is that layer, assembled from published primitives and
shipped as a runtime. Who it is for, and against what alternatives, is in
[`docs/POSITIONING.md`](docs/POSITIONING.md). What every "signed" and
"verifiable" on this page proves, and what it does not, is in
[`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md) — read that page before relying on
any of it.

## Three ways in

Each path below was driven end to end on a clean machine before it was written
here; the commands are the ones that ran, not ones composed for the page. Where
the drive substituted a tool — `uv` standing in for `venv` on a machine without
`ensurepip`, which the verification page's own caveat covers — the page says so.

### 1. Verify evidence, installing nothing of Orrery's

An org's receipt verifies with one library from PyPI and no account:

```bash
python3 -m venv verify-receipt
source verify-receipt/bin/activate
pip install sm-arp
```

The recipe — fetch the org's published bundle and its `/.well-known/did.json`,
check the issuer, the signature and the inclusion proof — is
[`docs/VERIFY_A_RECEIPT.md`](docs/VERIFY_A_RECEIPT.md). Run against a stock
keyless org it printed `OK — 1 receipt(s) verified against did:key:…`; the same
checks re-run with no network namespace still passed, and one character
changed in the receipt's summary, or one byte of its signature, made them fail.
The verifying key is never in the bundle: you take it from the org's
`did.json`, at a host you chose.

### 2. Integrate an agent you already have

**Over MCP (stdio).** From the repository root:

```bash
pip install -r agent/requirements.lock
pip install -e ./agent --no-deps
pip install "mcp>=1.24.0,<2.0.0"
python -m mcp_server
```

A stock `mcp` client lists six tools — `register_agent`, `request_grant`,
`check_grant`, `issue_receipt`, `verify_receipt`, `resolve_peer` — the
accountability primitives and nothing that reasons or plans. `verify_receipt`
on a published bundle answers `ok`; the same receipt with one character changed
answers `{"ok": false, "stage": "signature", …}`. `register_agent` before an
identity exists refuses and names the command that mints one:

```bash
community-member wizard --express --name <name>
```

Known limit, stated: `issue_receipt` returns a summary of the receipt, not the
document, so its output does not feed `verify_receipt` over the wire; the
round trip works in-process from the Agency Log. See
[`mcp_server/README.md`](mcp_server/README.md).

**As an A2A counterparty.** Every agent serves a card at
`/.well-known/agent.json` and `/.well-known/agent-card.json` and JSON-RPC at
`POST /`; a stock `a2a-sdk` 1.1.2 client resolves the card, sends, and holds a
multi-turn streaming conversation in CI. Work-creating calls need an
Ed25519-signed caller; an unsigned `message/send` answers `-32004` with the
reason.

**From an OpenClaw agent.** `skill/` is a drop-in skill whose signer passes the
protocol's signing vectors in CI. Its shipped signer refuses plain-`http://`
URLs, so today it joins an org fronted by HTTPS and cannot join the local
`./orrery-up` org its own page describes; the limit is recorded in
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).

### 3. Deploy the complete runtime

You need Docker with the Compose v2 plugin and Python 3.10+. No LLM key, no
account, no cloud credential: the keyless install is complete, and it is what
this produces.

```bash
git clone https://github.com/Sharathvc23/orrery-public
cd orrery-public
./orrery-up
```

`Sharathvc23/orrery-public` is the project's public home. Until the source tree
is published there it carries the project page alone, and the tree behind these
instructions is shared by invitation — clone whichever you were given into a
directory named `orrery-public`, and every command on this page runs verbatim.
(The directory name matters: it names the Compose project, and so the data
volumes a later run picks up.)

That boots the org (server + Postgres), a first local agent that joins it, and
the reference renderer, then proves each is alive like a caller would and
prints the addresses it just read. On a clean machine with cached images it
finished in 23–64 seconds, exit 0, with **no packet to any host outside the
Compose network** across install, first boot, the sign-of-life drill and one
think cycle — measured with a packet capture, not read from the code. That run
had the images and packages cached; an uncached first install pulls them from
Docker Hub, Debian and PyPI, and nothing else. Ports
are allocated on the first run, written to `.env`, and kept; the org's
`did:web` is built from its origin, so a port re-chosen each run would rename
the org. Every run prints one line saying which port each service has and why
— `allocated` on the first run, `pinned in .env` on every run after it,
`named by --server-port` when you chose.

```bash
./orrery-up down            # stop it; add --purge to drop the data volumes too
```

What the keyless install can and cannot do, what one LLM key adds, and the
installer's own words for each state are in
[`docs/QUICKSTART.md`](docs/QUICKSTART.md). The manual Compose path, naming an
org, and going to production are in [`docs/INSTALL.md`](docs/INSTALL.md).

## See it

With the stack up, open the renderer address the installer printed
(`http://localhost:8600` by default), set *Server* to the org's address
(`http://localhost:7000`), pick **dashboard**, and click **Connect (live)**.
Driven in a real browser: the page paints the org's card, the member and peer
counts, the think-cycle count, and the org's intent form; typing a need and
clicking *Find Match* posts it to the org and paints *Intent Matched*, and the
dashboard's active-intent count goes up by one. The pages that render the
member directory answer `401` to an unauthenticated reader by design.

Four surfaces you can read with no credential on a keyless install, each
observed answering `200`:

```bash
curl localhost:7000/agentfacts.json                 # NANDA AgentFacts
curl localhost:7000/.well-known/conformance.json    # signed boot conformance badge, self-attested
curl localhost:7000/.well-known/agent.json          # A2A Agent Card
curl localhost:7000/api/surfaces/dashboard          # the dashboard, as A2UI data
```

## What runs

Five deployables, each its own directory and its own tests:

| Deployable | Directory | What it is | Its key |
| --- | --- | --- | --- |
| **Org server** | `server/` | The headless org: member directory, roles, join policy, governance, receipt ledger, federation, NANDA surfaces. Postgres behind it. | `did:web`; Ed25519 signing key sealed at rest under `ORRERY_KEY_SECRET` |
| **Sovereign agent** | `agent/` (`community-member`) | The per-person runtime: consent gate, hash-chained Agency Log, signed receipts, BYO model or none. Runs on the owner's machine. | `did:key` in a local vault (OS keychain, passphrase, or device); a 24-word recovery phrase |
| **SMB host, signup and funnel** | `smb_host/`, `smb_signup/`, `smb_funnel/` | A multi-tenant host that mints an agent for a business that runs nothing, a bounded public signup, and the browser front end. | Minted and held **by the host**; the business holds the recovery phrase |
| **Lean index** | `index/` | A NEST-compatible registry you can run as a second corroboration source. | — |
| **MCP server and OpenClaw skill** | `mcp_server/`, `skill/` | Orrery's primitives for an agent you already have. | The agent's own |

How they fit, the protocols between them, and where every key lives are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). A reader of the code will meet
two nouns for the org — the protocol calls it a "chapter" and the product calls
it an *org*; that is deliberate, and
[`docs/ARCHITECTURE.md` § Two nouns](docs/ARCHITECTURE.md#two-nouns-for-one-thing-protocol-and-product)
says which surfaces keep the protocol noun and why they cannot change.

## Status at a glance

Where each capability stands on this tree. **✅ live · ◐ opt-in / partial ·
⚗️ preview · ✂️ out of scope.** The evidence for each row is in
[`docs/CLAIMS.md`](docs/CLAIMS.md) and the tested versions in
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).

| Area | Capability | Status |
| --- | --- | --- |
| **Org server** | Multi-agent runtime + think/act loop · REST + A2A transport | ✅ |
| | Org provisioning (name + identity, at install) | ✅ |
| | Federation — publish to the registry you choose | ◐ off by default; no default registry anywhere; set `REGISTRY_URL` and `AUTO_REGISTER=true` |
| | Federation — peer discovery + cross-org sync | ◐ opt-in |
| | MCP server — identity, grants, receipts, peer resolution as tools, over stdio | ✅ accountability primitives only; nothing that reasons or plans |
| **Sovereign agent** | `did:key` + a real keystore (OS keychain, passphrase, or device-bound file) | ✅ |
| | Ed25519-signed requests · signed receipts · hash-chained log | ✅ |
| | LLM planner, bring-your-own provider | ✅ no key = planner off, and no outbound call |
| | Consent-gated actions (browser / shell / files / net) | ✅ you approve each action and grant what it may reach; capability-scoped, not OS-isolated |
| | Consent-gated desktop control | ◐ X11 (xdotool), macOS and Windows drivers; not Wayland |
| | Skills: install / run / publish / revoke | ✅ capability-gated |
| | OpenClaw drop-in skill | ◐ signing verified in CI; joins HTTPS-fronted orgs only |
| | Bundled reference renderer, served by the stack | ✅ a static A2UI viewer, not a product UI |
| | Desktop app / hosted portal | ✂️ headless; bring your own renderer |
| **Accountability** | Offline-verifiable, hash-chained, portable receipts · Chronicle | ✅ |
| | Human oversight: approve / deny / escalate, each decision a signed envelope | ✅ (single approver) |
| | Multi-party (M-of-N) consent quorum | ✂️ out of scope |
| | Reputation (corroborated) + duress detection | ✅ |
| | Sybil-ring detection | ◐ offline auditor only |
| | Conformance badges (offline) | ✅ self-attested, no witness |
| | Merkle checkpoints | ◐ served only over a SQLite-backed issuer log |
| | DSAR export | ◐ routes exist; the authorized path is not driven in CI |
| **Accountable discovery** | Signed registry records · DID pinning · divergence detection · lean index | ✅ (divergence needs ≥2 **distinct** registries) |
| **Generative UI** | A2UI renderer + AG-UI streaming · deterministic keyless shell | ✅ |
| | Agent-composed UI from intent (key-gated, safe fallback) | ◐ |
| **Economy** | Signed skill registry (publish / install / review) | ✅ free installs |
| | Revenue ledger | ⚗️ test currency, self-reported; settlement on the roadmap |
| | Receipts as tradeable / financial assets | ✂️ reputation-bearing, not financial |

## What it interoperates with

Labels are from evidence, not intent. **Supported** = a test drives the real
handler on the protocol's wire shape, in CI. **Experimental** = it works and was
driven by hand or behind a skip; no CI proof of the live counterpart.
**Unfinished** = the shape exists and nothing delivers. The version is what the
test pins. The full table with its evidence is
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).

| Integration | Tested against | Label |
| --- | --- | --- |
| A2A (agent JSON-RPC, cards) | `a2a-sdk` 1.1.2 as an external client; v0.2 `tasks/*` and current `message/*` names | Supported |
| A2UI (surfaces as data) | emits 0.10; reads 0.9; `?schema=v0.8` downgrade | Supported |
| AG-UI (SSE stream of a surface) | event vocabulary asserted; no protocol version pinned | Supported, version unpinned |
| MCP (stdio) | `mcp` ≥1.24 <2; `langchain-mcp-adapters` 0.3.x as an oracle | Supported, with the `issue_receipt` limit above |
| sm-federation, sm-listing, sm-arp, sm-parc, sm-aae, sm-conformance | exact pins in the lockfiles | Supported |
| NANDA NEST registration | record shape against a mock; never a live registry in CI | Experimental |
| NANDA Index resolve and v2 registration | the in-repo `index/` in CI; the live index only under a canary flag | Supported in-repo; experimental live |
| host39 card publication | mocked client; live path behind a skip | Experimental |
| OpenClaw skill | signing vectors in CI; cannot reach a plain-`http://` org | Supported for signing |
| Discord inbound signing | forgery, replay and injection cases | Supported for inbound |
| Owner OIDC (loopback + PKCE) | flow logic; no live identity provider in CI | Experimental |
| Klaviyo outbound email | sandbox by default; the live transport is never driven | Unfinished as delivery |
| Slack, IMAP, SMTP channels · OIDC/SSO for the org · voice | shape only; the honest "untested" chip is the tested part | Unfinished |

## What is recorded, and what a reader may conclude

Every action an agent takes on another agent, and every booking, produces a
signed ARP receipt in the issuer's Agency Log; a counterparty that agrees
co-signs it, which is what lets it count toward reputation. A local capability
execution — a file write, a shell command, a browser step — produces the
**consent decision** as a signed envelope and a ledger row, and no receipt. A
signature proves who produced some bytes; it does not prove the action
happened, and a valid chain does not prove it is complete. Nothing in the tree
confirms an external outcome: a booking's delivery is a webhook response, an
A2A result is the counterparty's word. The receipt for an outbound call is now
written **before** the call as a pending attempt and finalized after it, so a
crash between the two leaves an entry marked unknown rather than nothing.
[`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md) states all of this per action
kind with the code and the tests behind each sentence, and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) says who can do what to whom.

## How this relates to Project NANDA

[Project NANDA](https://projectnanda.org) is a research project with published
artefacts and proposed conventions — not an operating network. What exists and
what Orrery uses: the **NANDA Index**, a registry you can resolve against;
**AgentFacts**, a description format; **NEST**, a registry; **host39**, a card
host. Orrery publishes AgentFacts, registers with and resolves through a
registry when you configure one, and adds what discovery does not provide:
self-certifying signed records, DID pinning between orgs, and cross-registry
divergence detection, so a registry that lies is detectable rather than
trusted. **None of it is required, and none is reached unless named.** There
is no default registry anywhere in the tree: with `REGISTRY_URL` and
`NANDA_INDEX_URL` empty — the generated `.env` — an org runs, federates with
peers you name, and is not publicly resolvable, and the agent refuses to
announce by name rather than falling back to one. The agent also publishes
nothing without an owner-signed listing grant on its disk. An org that *is*
pointed at a registry
publishes its members' directory entries on the operator's decision, and there
is no per-member opt-out of that today — the join response says so.

```
  4-hop resolution (how anyone reaches one of your agents, when you publish):
    Index.resolve(urn:ai:domain:DOMAIN:agent:ID)
      → org   GET /agents/ID               (the registry hop → a CatalogEntry)
      → host39 GET /DOMAIN/slug.json        (the agent's A2A card)
      → agent GET /.well-known/agent.json  →  invoke
```

Orgs can serve member cards themselves when `ORG_HOST39_CARD_BASE` is unset.

### Surviving a cheating registry

A registry sits between an org and everyone who looks it up, so it can tamper a
record, serve a stale one, omit an org, or tell different clients different
things. Orrery treats it as an untrusted courier:

- **Self-certifying records.** Every registration carries an attestation the
  org signed over `{agent_id, did, endpoint, issued_at, expires_at}`; a `did:key`
  is the public key, so a consumer verifies it offline. A tampered endpoint
  breaks the signature; a stale record ages out.
- **Attested endpoint wins.** Discovery probes the endpoint the org signed, not
  the unsigned copy the registry served, and logs the divergence.
- **DID pinning between orgs.** The first attested `did:key` seen for a peer is
  pinned in Postgres; a later record with a different key raises
  `federation.peer.did_mismatch`, and only a leader clears the pin. Broadcast
  signatures verify against the pinned key. Without a database it degrades to
  per-cycle trust-on-first-use.
- **Cross-registry corroboration.** With two or more registries configured,
  each org asks all of them the same questions every heartbeat and emits
  `federation.registry.divergence` on any omission, endpoint or DID
  disagreement. `index/` is a lean registry you can run as the second source.
  With **one** registry this detector is a no-op.

The first sighting of any peer's DID is trust-on-first-use, and a single
registry that lies at first contact is not detected by anything here. Only a
transparency log closes that, and there isn't one.

## A business that runs nothing

`smb_host/` mints an Ed25519 identity for a business, serves its A2A card and
AgentFacts at a stable per-tenant URL, and takes bookings that return signed
receipts. The business installs nothing and holds a 24-word recovery phrase.
The host holds the key and signs with it — an operator who holds the host's
keystore secret can act as any tenant, and
[`docs/TRUST_MODEL.md` § 5](docs/TRUST_MODEL.md) says so in full. The host
registers nobody on any index and makes no outbound call. Start at
[`smb_host/README.md`](smb_host/README.md) and
[`smb_host/OPERATIONS.md`](smb_host/OPERATIONS.md); the browser front end and
what its verification badge does and does not prove are in
[`smb_funnel/README.md`](smb_funnel/README.md).

## Two agents, one call, verified by something else

[`scripts/demo_two_agents.sh`](scripts/demo_two_agents.sh) stands up two orgs and
two agents on this machine — separate homes, keystores, passphrases, consent
ledgers, principals — and has A call B once under a grant that names exactly
that action. Then it breaks the call four ways and shows each refusal. Docker,
Python 3.10+ and Node 20+; ports are allocated; it tears itself down.

```bash
bash scripts/demo_two_agents.sh                # evidence → ./demo-evidence/
```

What you will see, in order (actual output, identifiers vary per run):

```text
── 3. A's principal signs a grant naming exactly one action ──
   ✓ principal did:key:z6Mkjp7E… (not A's key) signed: save_note until 2026-09-19T02:39:08Z; install_skill; save_note expired …
── 4. A calls B (save_note) under the grant; B executes and co-signs ──
SENT save_note → did:key:z6MkgGua… under dat:did:key:z6Mkjp7E…:e59aa8c9-…; receipt 8a5aac9a-… co-signed → demo-evidence/1-happy-path
   ✓ receipt 8a5aac9a-… co-signed by B; org one holds it (its signed principal-scoped read returns it)
── 5. verify OFFLINE with smb_funnel/verify.mjs — issuer did:key from A's CARD, not the receipt ──
VERIFIED ✓  issuer_did=did:key:z6MkogFj… action=message_sent
VERIFIED ✓  co-signed by witness_did=did:key:z6MkgGua… over action=message_sent
── 6.1 DENIAL ──   REFUSED at the consent gate (authority_scope): grant … names ['a2a.tasks/send#install_skill'], not 'a2a.tasks/send#save_note'
── 6.2 TAMPERING ──  FAILED ✗  stage=signature detail=Ed25519 verification failed          (byte flipped, and issuer did swapped)
── 6.3 EXPIRED ──  REFUSED at the consent gate (authority_expired): grant … expired at 2026-09-19T00:40:45Z (now …)
── 6.4 INTERRUPTED ──  [fault] tasks/send returned (completed); killing A now (os._exit 9)
   ✓ on restart A logs the attempt as UNKNOWN, lists it under /api/agency-log/unresolved, claims no success, and refuses the retry (exit 3)
```

`demo-evidence/` holds the receipt, the grant, A's consent-ledger row and signed
sm-aae envelope, B's acknowledgement, org one's copy of the receipt, both agent
cards, and every refusal's output — with a `README.txt` naming each file.
`verify.mjs` checks the issuer's Ed25519 signature over the JCS-canonical receipt
under the did:key from A's card; `verify_cosign.mjs` checks B's co-signature the
same way under B's card. Neither checks the grant, the envelope, chain position
or revocation — those are the producer's verifiers. The same script runs in CI
on every change to what it exercises.

## Built on the `sm-*` stack

Orrery composes published primitives; it defines no protocol. Every dependency
is pinned exactly and the pins are enforced in CI.

| Package | Role |
| --- | --- |
| [`sm-arp`](https://github.com/Sharathvc23/sm-arp) | Agency Receipt Protocol — signed, offline-verifiable action receipts |
| [`sm-conformance`](https://github.com/Sharathvc23/sm-conformance) | Signed, offline-verifiable protocol conformance badges |
| [`sm-bridge`](https://github.com/Sharathvc23/sm-bridge) | NANDA AgentFacts converter and registry router |
| [`sm-parc`](https://pypi.org/project/sm-parc/) | Portable Agent Reputation Credential (W3C VC over a receipt ledger), selective disclosure |
| [`sm-aae`](https://pypi.org/project/sm-aae/) | Chained authorization envelopes — who authorized an agent to act |
| [`sm-federation`](https://pypi.org/project/sm-federation/) · [`sm-listing`](https://pypi.org/project/sm-listing/) | The published community-federation and member-listing surfaces |
| [`sm-divergence`](https://pypi.org/project/sm-divergence/) · [`sm-resolver`](https://pypi.org/project/sm-resolver/) | Cross-registry divergence detection and attested-record resolution |

## What Orrery does not do

- **Define a protocol.** It composes the ones above.
- **Replace an agent framework.** Build the agent's reasoning with anything;
  Orrery gives it an owned identity, a consent gate and receipts. It has no
  opinion about your loop and no framework code in this repository.
- **Fabricate trust.** The boot badge is labelled self-attested and has no
  witness; reputation is computed from co-signed receipts, never entered.
- **Run your agents for you.** The sovereign agent runs on the owner's machine.
  There is no hosted or managed offering. The SMB host is the one hosted shape,
  and its custody trade is stated above.
- **Sandbox a skill from your machine.** The consent gate is a capability
  boundary, not an OS one; an approved skill runs with the agent's privileges.
- **Confirm an external outcome, or close first-contact equivocation** — see
  the trust model.
- **Protect the operator's secrets for them.** `./orrery-up` generates fresh
  per-install values; the deployer owns the database password, the key-sealing
  secret and the backups. Nothing escrows a lost key.

## Status and history

`v0.3.0` is the first public release; Orrery was developed privately through
`0.1.0` and `0.2.0`, with two security audits whose every finding is
dispositioned in public — [`AUDIT_HARSH.md`](AUDIT_HARSH.md),
[`docs/HARDENING.md`](docs/HARDENING.md), and the per-finding ledger
`docs/audit/findings.json`, which a CI gate keeps consistent with the prose.
What is open and residual today is enumerated by id in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Every advertised capability is
adjudicated with its evidence in [`docs/CLAIMS.md`](docs/CLAIMS.md); what is
planned is in [`docs/ROADMAP.md`](docs/ROADMAP.md); releases are in
[`CHANGELOG.md`](CHANGELOG.md).

## Repository layout

```
orrery/
├── server/      # the org server                                    (Python)
├── agent/       # the sovereign agent, community-member             (Python)
├── skill/       # drop-in skill for OpenClaw agents                 (Python)
├── mcp_server/  # the accountability primitives as MCP tools        (Python)
├── index/       # lean NEST-compatible registry                     (Python)
├── smb_host/    # multi-tenant host for a business that runs nothing (Python)
├── smb_signup/  # the bounded public signup in front of it          (Python)
├── smb_funnel/  # the browser front end for that path                   (JS)
├── renderer/    # reference A2UI renderer                               (JS)
├── conformance/ # the protocol conformance suites and vectors
├── scripts/     # e2e probes, canaries, the repository gates
├── orrery-up    # the one-command installer
└── docs/        # start at docs/README.md
```

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md) — the workflow, the gates, and how a guard is proven.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability, and what a report should contain.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [PRIVACY.md](PRIVACY.md) · [CHANGELOG.md](CHANGELOG.md)
- Contributors: [James Carnley](https://github.com/JamesCarnley) · [Harsh Suthar](https://github.com/10234567Z)

## The animation

The banner is a working clockwork model, not a recorded clip — a self-contained
animated SVG, pure [SMIL](https://developer.mozilla.org/en-US/docs/Web/SVG/SVG_animation_with_SMIL)
with no JavaScript, generated offline by `scripts/generate_orrery.py`:

- **Radii** are the planets' real semi-major axes in AU, square-root-compressed so
  the inner worlds do not collapse into the Sun and Neptune still fits the frame.
- **Periods** are recomputed from the displayed radii using Kepler's third law
  (`T ∝ R^1.5`), so the rendered system is an internally consistent Kepler model —
  scaled rather than slowed. Each body is lit from the Sun; Earth carries a Moon
  and Saturn its rings.

## License

[MIT](LICENSE) — Orrery, the `sm-*` primitives it builds on, and the
[Project NANDA](https://projectnanda.org) umbrella spec are under the same
permissive license.
