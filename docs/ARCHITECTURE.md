# Architecture

Orrery is five deployables that speak a small set of published protocols to
each other, arranged in three layers. This page names the deployables as the
code has them, the protocols between them, and where every key lives. What a
signature on any of those protocols proves is a separate question, answered in
[`TRUST_MODEL.md`](./TRUST_MODEL.md).

## The five deployables

| Deployable | Directory · process | What it is | Protocols it speaks | Its key, and where it lives |
|---|---|---|---|---|
| **Org server** | `server/` · `orrery-server` (FastAPI + Postgres; `./orrery-up` runs it under Compose) | The org: member directory, roles and join policy, governance queues, receipt ledger, skill registry, federation, discovery surfaces. Headless — a signed HTTP API. | Signed HTTP from members (v0.3 `ed25519+nonce`; v0.2 accepted for reads); A2A `POST /a2a` at v0.2; federation broadcasts and signed peer reads; the `sm-federation` feed; `sm-listing`; NANDA AgentFacts, NEST and Index registration when configured; A2UI surfaces over AG-UI SSE | `did:web`. An Ed25519 signing key, sealed with AES-256-GCM under a key derived from `ORRERY_KEY_SECRET`, in the `chapter_keys` table or the offline key file (`server/secret_sealing.py`, `server/sovereign_identity.py`). The server refuses to boot without the secret unless the operator opts out. Members' LLM provider keys are sealed the same way. **Not** sealed, on disk by design: the admin token (`.org-admin-token`, mode 0600) and the rate-limit salt. Changing `ORRERY_KEY_SECRET` without a re-seal makes the stored key undecryptable — a new identity and every peer re-pinning; treat it as unrotatable in place. |
| **Sovereign agent** | `agent/` · `community-member` (runs on the owner's machine; `./orrery-up` starts one under Compose as the first member) | The per-person runtime: planner (BYO model or none), consent gate, capability runners, hash-chained Agency Log of signed receipts, sm-aae envelopes, skills, a local API on loopback. | Signed HTTP to its org; A2A JSON-RPC at `POST /` with cards at `/.well-known/agent.json` and `agent-card.json`, including `nanda/cosignReceipt`; NANDA AgentFacts and PARC at `/.well-known/`; NEST and Index announcement only on an owner-signed grant; inbound Discord-signed interactions; A2UI surfaces | `did:key`. The Ed25519 seed in a vault under the agent home, never plaintext on disk (`agent/community_member/keystore.py`): OS keychain, a user passphrase (PBKDF2, never written), or a device fingerprint. A 24-word BIP39 phrase re-derives it by SLIP-0010 (`recovery.py`). The org never receives it. |
| **SMB host, signup, funnel** | `smb_host/` · `orrery-smb-host`; `smb_signup/`; `smb_funnel/` (static browser app) | A multi-tenant host that mints an agent for a business that runs nothing and serves its card, AgentFacts and bookings at a per-tenant URL; a bounded public signup in front of it; the browser front end. Performs no consent-gated action and makes no outbound call. | A2A cards and AgentFacts per tenant; the booking skill's receipts; the signup's rate limit and tenant cap | Each tenant's seed is minted **by the host** (`smb_host/main.py::_provision_tenant`) into that tenant's own vault. The documented deployment uses one host-wide `COMMUNITY_MEMBER_PASSPHRASE`; whoever holds it opens every tenant vault and can sign as any tenant. The business holds only the recovery phrase, which the host never writes and cannot import ([`../smb_host/OPERATIONS.md`](../smb_host/OPERATIONS.md)). |
| **Lean index** | `index/` · `orrery-lean-index` | A NEST-compatible registry you can run yourself — the second corroboration source the divergence detector needs. | The NEST record shape; the Index v1 resolve media types | None of its own; it serves the attestations orgs sign. |
| **MCP server and OpenClaw skill** | `mcp_server/` · `python -m mcp_server` (stdio); `skill/` · `orrery-skill` | Orrery's accountability primitives for an agent you already have: six MCP tools (identity, grants, receipts, peer resolution); a drop-in skill that signs an OpenClaw agent's requests to an org. | MCP over stdio; the org's signed-HTTP scheme | The agent's own `did:key`, minted by `community-member wizard`; the skill signs with the key its host agent holds. |

The org server and the sovereign agent are the two most people run. The org
is a "chapter" in the protocol's vocabulary and an **org** in the product's;
[Two nouns](#two-nouns-for-one-thing-protocol-and-product) below says which
surfaces keep which word and why.

## The protocols between them

| Edge | Protocol | Where it is defined and tested |
|---|---|---|
| Member → org (every mutation, gated reads) | Ed25519-signed requests: v0.3 `ed25519+nonce` binds method, path, body, agent id, timestamp and a server-enforced nonce; v0.2 is accepted for reads only | `server/auth_verify.py`; the client signing conformance job runs the published vectors against the reference, the OpenClaw skill and the member SDK (`conformance/`) |
| Agent ↔ agent | A2A JSON-RPC: `message/send`, `message/stream` and the v0.2 `tasks/*` names, plus `nanda/cosignReceipt` for counterparty co-signatures | `agent/community_member/a2a_rpc.py`; a stock `a2a-sdk` client in CI (`agent/tests/test_a2a_current_spec_compat.py`) |
| Org ↔ org | Signed federation broadcasts (body + timestamp + nonce, verified against the peer's `/.well-known/did.json`), signed peer reads of gated routes, the `sm-federation` node descriptor and signed intelligence feed, DID pinning of peers | `server/federation_signing.py`, `server/federation_policy.py`, `server/federation_feed.py`; `conformance/federation/` |
| Org and agent → registries | NANDA AgentFacts; NEST registration and Index v1 resolve / v2 registration through `sm-bridge`; host39 card publication — each only when configured, the agent's only under an owner-signed listing grant | `server/nanda_registry.py`, `server/registry_policy.py`, `agent/community_member/registry.py`, `owner.py` |
| Org and agent → a renderer | A2UI 0.10 surfaces as data at `/api/surfaces/{page}`, streamed over AG-UI SSE at `/api/surfaces/{page}/stream`; `?schema=v0.8` downgrade | `server/surfaces.py`, `server/agui_streaming.py`; `renderer/` paints them |
| Any verifier → an org or agent | ARP receipts (`sm-arp`), PARC credentials with selective disclosure (`sm-parc`), conformance badges (`sm-conformance`), the member listing (`sm-listing`) — each verifiable offline against a `did:key` | [`VERIFY_A_RECEIPT.md`](./VERIFY_A_RECEIPT.md), [`VERIFY_A_BADGE.md`](./VERIFY_A_BADGE.md) |
| An existing agent → Orrery | MCP over stdio | `mcp_server/`; a stock `mcp` client and `langchain-mcp-adapters` as oracles in CI |

Versions per protocol, as the tests pin them, are in
[`COMPATIBILITY.md`](./COMPATIBILITY.md).

## The surfaces each deployable serves

| Surface | Endpoint | Served by | Built on |
|---|---|---|---|
| **AgentFacts** | `GET /agentfacts.json` · `GET /sm-bridge/{index,resolve}` | org + agent | `sm-bridge` |
| **Registration** | published to NEST when `REGISTRY_URL` is set, to the Index when `NANDA_INDEX_URL` is set — never by default. The agent publishes only on an owner-signed grant; the org publishes its members' directory entries on the operator's decision, with no per-member opt-out today | org + agent | `sm-bridge` |
| **Owner principal** | the listing grant's grantor, a key distinct from the agent's: OIDC for individuals (loopback + PKCE, no client secret); an HTTP-01 / DNS-01 challenge for a business that owns a domain | agent | `sm-authority`, `sm-dat` |
| **Listing lifecycle** | `GET /.well-known/agent-lifecycle.json` — `active` · `suspended` · `revoked` · `not_established`; always `200`, always a state, so a withdrawn business is distinguishable from one that never existed | agent | — |
| **Member listing** | `GET /.well-known/agent-community-listing.json` — members who opted in via `POST /api/me/listing`, only the fields they chose; served only when `ORRERY_LISTING_ENABLED=true` | org | `sm-listing` |
| **Conformance badge** | `GET /.well-known/conformance.json` — signed at boot, labelled self-attested, never regenerated while it still verifies | org + agent | `sm-conformance` |
| **Reputation** | `GET /.well-known/reputation.json` (PARC, a W3C Verifiable Credential); selective disclosure with Merkle inclusion proofs at `POST /api/local/disclose` | agent | `sm-parc` |
| **Identity documents** | `GET /.well-known/did.json` | org (`did:web`) · agent (`did:key`) | — |
| **A2A** | cards at `/.well-known/agent-card.json` and `/.well-known/agent.json`; JSON-RPC `POST /`; work-creating calls need a signed caller (`-32004` otherwise) | agent (the org has a v0.2 `POST /a2a`) | Google A2A |
| **Member cards** | registry hop `GET /agents/{id}` → host39, or the member's own card when `ORG_HOST39_CARD_BASE` is unset | org | — |
| **Community federation** | `GET /.well-known/agent-community.json`; `GET /api/federation/intelligence/feed` | org | `sm-federation`, `sm-feed` |
| **Merkle checkpoint** | `GET /api/checkpoint`, `GET /api/checkpoint/proof/{receipt_id}` — served only when the issuer log is the local SQLite backend; `404` on a Postgres-backed org | org | RFC 6962 (`server/merkle.py`) |
| **Generative UI** | `GET /api/surfaces/{page}` (A2UI 0.10 as data), `/stream` (AG-UI SSE), `POST /api/surfaces/action` | org + agent | A2UI, AG-UI |
| **Local control** | `/api/local/*` — consent decisions, chat, settings, skills, panic; loopback by default, protected by a 0600 token file | agent | — |

One Ed25519 key threads every surface of an entity: `did:key` for the agent,
`did:web` for the org.

## Three layers

```
  ┌──────────────────────────────────────────────────────────────┐
  │  SKIN  (opt-in)                                              │
  │     generative surfaces — per-org / per-agent UI emitted     │
  │     AS DATA (A2UI 0.10) from intent + receipts, BYOK,        │
  │     behind the trust guards · painted by a renderer of your  │
  │     choice. The org is headless by default; this is opt-in.  │
  ├──────────────────────────────────────────────────────────────┤
  │  DISTRIBUTION                                                 │
  │     ./orrery-up  →  server + Postgres + a first agent +       │
  │     the reference renderer, under Compose                    │
  │     opinionated defaults · the one-command promise          │
  ├──────────────────────────────────────────────────────────────┤
  │  KERNEL                                                       │
  │     orrery-server · orrery-agent · the sm-* primitives        │
  │     (sm-arp, sm-conformance, sm-parc, sm-aae, sm-bridge …)   │
  │     stable · semver'd · never forked                        │
  └──────────────────────────────────────────────────────────────┘
```

**Kernel.** The protocol surfaces and runtimes, as versioned packages. Every
org runs the same build/sign/verify code so receipts and badges cannot drift
between deployments. Orrery's kernel is the `sm-*` primitives plus the thin
runtimes that bind them to the org protocol — the way nginx implements HTTP.
New primitives get their own `sm-*` package and are pinned exactly
([`integrations/STELLARMINDS.md`](./integrations/STELLARMINDS.md)); no
third-party code is vendored or forked. Two modules are written against
published specifications (`server/nanda_models.py` against the NANDA
AgentFacts schema, `agent/community_member/a2a_*.py` against the A2A
protocol) and four are first-party copies kept in lockstep with
`conformance/` so the pip-installed agent needs nothing outside its wheel
([`LICENSES.md`](./LICENSES.md) names each).

**Distribution.** One opinionated bundle. `./orrery-up` generates fresh
secrets, boots the org, starts a first local agent that joins it, and probes
the whole thing for signs of life ([`QUICKSTART.md`](./QUICKSTART.md)). It
makes choices — ports, a default database, seed data — so a stranger does not
have to. Every other member's agent is not in the bundle: each person runs
`community-member` on their own machine so its key stays on a device they
control.

**Skin.** The org is headless by default. When an org wants UI it is opt-in
and emitted as data: an A2UI envelope from `/api/surfaces/*`, streamed over
AG-UI, painted by the bundled reference renderer or one of your own. A
generated surface is an attack surface, so the generative path sits behind the
same trust guards and degrades to the deterministic keyless path, never to
unguarded output.

## Data flow (one action)

```
an agent is about to act on another agent
  → its consent gate decides, and the decision is signed (sm-aae) and logged
  → a pending attempt is written to the Agency Log BEFORE the call
  → the A2A call runs; the counterparty may co-sign the receipt
  → the attempt is finalized: succeeded (with the signed ARP receipt), failed,
    or unknown when the outcome was not observed
  → (opt-in) the receipt is pushed to the org's ledger
  → any party holding the receipt re-verifies it offline (sm-arp)
```

A local capability execution — a file write, a shell command, a browser step —
takes the first step and no others: the signed decision is the record, and no
receipt is produced. [`TRUST_MODEL.md`](./TRUST_MODEL.md) § 1 and § 2 state
this per action kind.

## Dependency direction

Skin depends on Distribution depends on Kernel. Never the reverse. The kernel knows
nothing about rendering; a renderer consumes the kernel's surface **data** through
documented APIs. This is what lets the generative layer be added, swapped, or sold
later without disturbing the headless core underneath it.

## Two nouns for one thing: protocol and product

A reader of this tree meets two words for one thing, and that is deliberate.

**"Chapter" is the protocol noun.** The org server implements the
**Chapter Protocol** — the wire contract its federation peers, its members'
agents and every offline verifier were built against. The protocol's primitive is a
"chapter", its identifier is `chapter_id`, and those spellings are part of what
other software checks.

**"Org" is the product noun.** An operator installs an *org*; a member joins
an *org*; every page, wizard step, environment variable (`ORG_NAME`,
`ORG_ADMIN_TOKEN`, `ORG_HOME`) and human-facing string says *org*. That is the
rule `scripts/org_vocabulary_gate.py` enforces over prose and over strings
shown to a human, and this section is the rule it cites.

**The two are the same thing.** The product did not fork the protocol or
translate it: an org *is* a "chapter" as the protocol defines one, and the
protocol noun stays on every surface where another party depends on the
spelling.

### Which surfaces carry the protocol noun, and why they cannot change

Each of these is read by something other than this repository's prose — a
peer, an agent built against the published protocol, a signature, a database,
a verifier — so renaming it is a wire break, not an edit:

| Surface | Examples | Who depends on the spelling |
|---|---|---|
| Routes | `/api/chapter/*` (allowlist, audit, providers, SSO), `/api/federation/{chapter_id}/members`, `/api/portal/chapter`, `/.well-known/nanda-chapter-rotation.json` | Federation peers and agents built against the published protocol |
| Request headers | `X-Chapter-Origin`, `X-Chapter-DID`, `X-Chapter-Signature`, `X-Chapter-Timestamp`, `X-Chapter-Nonce` (`server/federation_signing.py`) | Every peer verifying a broadcast |
| Signed canonical strings | `ROTATE:{chapter_id}:{agent_id}:…` (`server/member_rotation.py`, `agent/community_member/auth.py`) | Every signature already produced under that string — changing one byte invalidates the attested rotation history |
| Wire field | `chapter_id` in registration, rotation attestations, federation envelopes and the conformance vectors under `vectors/` | Conformance suites and every existing client |
| Event names | `chapter.broadcast`, `chapter.digest.weekly` (`server/event_types.py`) | Subscribers on the event bus |
| Database | 14 tables named `chapter_*` and `chapters` (`infra/init.sql`; seven more were dropped as unreferenced), the columns that reference them | Every existing install's data |
| Metrics | `nanda_chapter_*` (`server/metrics.py`) | Operators' dashboards and alerts |
| Badge runtime name | `"chapter"` in the signed conformance badge (`server/conformance_boot.py`) | Badge verifiers; the value is inside a signature |
| Legacy environment aliases | `CHAPTER_HOME`, `CHAPTER_ADMIN_TOKEN` — still read when the `ORG_*` name is unset (`server/admin.py`) | Deployments configured before the product noun changed |
| Module and package names | `server/chapter_agent.py` (the org server's main module); the agent's import package `community_member` and its `community-member` command | Every import, entry point and container command line |

The names in the last row are internal to this repository, so they *could*
change; they have not, because the two names that face a user — the
`orrery-server` and `orrery-agent` distributions — already say what the
product calls each thing, and a rename of the internals would touch every
import for no reader's benefit. The package name `community_member` is a
third, older noun for the same agent; it appears only in imports and the
command name.

So a reader will see `chapter_agent.py` serve `/api/portal/chapter` while the
README says *org*, and will see `community_member` implement what the docs
call *the agent*. Neither is drift. Drift is the protocol noun appearing as a
common noun in prose or on a screen, and that is what the gate refuses.
