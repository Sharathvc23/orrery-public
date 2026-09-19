# Positioning — why Orrery, and who it's for

Orrery is an **installable org of accountable AI agents**: one command stands up
an organization's own agent infrastructure, each person in it runs a sovereign
agent on a machine they control, and every action any agent takes is
cryptographically provable to third parties. This page is for someone deciding
whether to run it — what it is relative to the tools they already know, who it
serves, and what it deliberately is not.

## The one-sentence version

Agent frameworks help you *build* an agent. Orrery is what you install so that
the agents acting for your people are **owned by them and accountable to
everyone else** — and it consumes those frameworks rather than competing with
them.

## Who it's for

- **A company or community operator** who wants members to have AI agents acting
  on their behalf — internally and across organizations — without putting
  identity, memory, or authority in a vendor's cloud. You get a member
  directory, roles, join policy, role-nomination governance, and a signed receipt
  for every action, out of one `./orrery-up`.
- **An organization that must prove what its agents did.** Regulated,
  procurement-heavy, or trust-sensitive environments where "our dashboard says
  so" is not evidence. Orrery's receipts, conformance badges, and reputation
  credentials all verify **offline** against public keys — an auditor or
  counterparty needs no account, no API access, and no trust in you.
- **Self-hosters and sovereignty-first teams.** No login, no SaaS, no telemetry
  home. The agent's key is passphrase-held on its owner's machine; the org is a
  headless signed API you run yourself. Any LLM key works, or none at all.
  One thing to know before you boot it, and it changed in `0.3.0`: the org
  **publishes to no registry at all** unless you configure one. `REGISTRY_URL` is
  empty in the generated `.env` and there is no fallback default, so a fresh
  install puts your endpoint nowhere. Set it deliberately to publish; that is
  discovery rather than telemetry, and no data goes to the maintainers, but it
  does put your endpoint on a public registry.
- **Publishing to a discovery service, when you want it.** If you want your agents
  discoverable and invokable by strangers — NANDA AgentFacts, Google A2A cards,
  and resolution through the NANDA Index — Orrery serves those surfaces out of the
  box, with self-certifying records that survive a cheating registry. You supply
  the registry address; nothing is published until you do.

**Who it's not for (yet):** teams that want a polished end-user web app out of
the box (Orrery is headless; UI is opt-in, emitted as data for your own
renderer), or anyone who needs a managed/hosted offering — there isn't one, by
design.

## Versus the tools you already use

None of these are competitors. Orrery sits **above** them, and most of them run
**inside** it.

| You already know | What it is | How Orrery relates |
| --- | --- | --- |
| **LangChain / CrewAI** (and every agent framework) | Libraries for building an agent's reasoning and orchestration | Build your agent's brain with them if you like. Orrery is the layer that gives that agent an owned identity, a consent gate, and receipts for what it does. |
| **MCP** | A protocol for wiring tools/context into a model | Complementary plumbing below the accountability layer. Orrery does not replace or wrap it. |
| **Google A2A** | An agent-to-agent interop protocol | Orrery **speaks** A2A — every agent serves an A2A card and JSON-RPC endpoint. A2A moves the messages; Orrery proves what happened. |
| **NANDA (Index, NEST, host39)** | A research project's discovery artefacts — a registry you can resolve against, a facts format, a card host. Services someone runs, not a network that runs itself | Orrery speaks them: it publishes AgentFacts, registers with and resolves through the Index, and adds the accountability that discovery alone doesn't give you — signed records, DID pinning, divergence detection. It treats every registry as an untrusted courier. |
| **A hosted agent platform** | Someone else runs your agents and holds the keys | The opposite of Orrery's model: here the person owns the agent, the org owns its own server, and trust comes from cryptography rather than the platform's word. |

## The layer that doesn't exist elsewhere

What a bare framework leaves you to build — and what Orrery is — is the
**accountability + ownership layer**:

- **Receipts, not logs.** Every action becomes a signed, hash-chained ARP
  receipt that anyone re-verifies offline. A log says what you claim happened; a
  receipt proves it, portable across trust boundaries.
- **Owned identity.** Each agent holds its own Ed25519 key (`did:key`),
  passphrase-protected on its owner's machine; the org's identity is a `did:web`
  anyone can resolve. There are no accounts to breach and no vendor who can
  impersonate your agents.
- **Consent as a gate.** Agent capabilities are capability-gated by the consent
  gate — consent-gated, not OS-isolated — with a hash-chained decision ledger and
  chained authorization envelopes (sm-aae), so who authorized an action is
  answerable cryptographically, per action. An approved skill runs with the
  agent's own privileges: the gate decides whether it runs, not what it can reach
  once it does.
- **Trust that composes.** Conformance badges (does the runtime honestly
  implement the protocol), corroborated reputation (a W3C VC computed from
  co-signed receipts, never invented), selective disclosure (prove k receipts
  with Merkle proofs, keep the rest private), and registry-divergence detection
  (catch a lying discovery layer). Each is an `sm-*` package usable alone;
  Orrery is the assembled product.

That assembly is the moat. Any team could wire a framework to a database and
call it an agent platform; the hard part — and the part that's already built,
audited, and pinned here — is making every layer of it *provable to a stranger*.

## What Orrery is NOT

- **Not a protocol.** It composes ARP, conformance badges, PARC, AAE, the NANDA
  bridge, and A2A. It defines no new wire format and asks nobody to adopt one.
- **Not an agent framework.** It has no opinion about how your agent thinks.
  LangChain, CrewAI, raw API calls, or no LLM at all — the accountability layer
  is the same.
- **Not a SaaS.** There is no hosted Orrery, no signup, no login. You run it;
  your members own their agents.
- **Not trust theater.** The boot conformance badge is labeled self-attested;
  reputation only accrues from co-signed receipts; the docs mark every feature
  with its evidence ([`CLAIMS.md`](./CLAIMS.md)) and every integration with its
  tested version ([`COMPATIBILITY.md`](./COMPATIBILITY.md)); and the known limits —
  e.g. the trust-on-first-use ceiling against a single equivocating registry —
  are documented rather than papered over.

## Honest maturity

Orrery is at **v0.3.0**, its first public release — early, but not unaudited:
three security audits, two fully dispositioned
([`audit/RELEASE_SIGNOFF_v0.2.0.md`](./audit/RELEASE_SIGNOFF_v0.2.0.md)) and a third
([`AUDIT_HARSH.md`](../AUDIT_HARSH.md)) whose 27 Critical and High findings each
carry an inline disposition while its 35 Medium and Low findings are openly
marked *not* dispositioned — plus an exactly-pinned supply chain and a CI e2e job
that boots the full stack and drives the advertised surfaces on every PR.

One Critical finding from that third audit still has an open residual in code:
C4 has no row-level-security policies. Its former prerequisite is fixed —
[PR &#35;556](https://github.com/Sharathvc23/orrery/pull/556), landed 2026-08-15,
changed the Compose default to `orrery_app`, a non-superuser `NOBYPASSRLS`
runtime role. Operators can override `APP_DB_USER` or `DATABASE_URL`; the role
also retains broad CRUD, sequence, and function grants. The default reduces
cluster and DDL privileges and makes future RLS enforceable; it does not itself
create row isolation. C6, the `/metrics` bearer token comparison, is fixed — it
uses `hmac.compare_digest`, and its severity was reduced to Medium on the
reasoning recorded in `AUDIT_HARSH.md`.

What's live is in [`CLAIMS.md`](./CLAIMS.md); what isn't yet is in
[`ROADMAP.md`](./ROADMAP.md); the evidence behind each claim, and what `0.3.0`
moved out from under, is in [`CLAIMS.md`](./CLAIMS.md).
If a claim in these docs isn't backed by running code, that's a bug — file it.
