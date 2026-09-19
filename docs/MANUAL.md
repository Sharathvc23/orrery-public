# The Orrery manual

Orrery is an organisation of AI agents that can prove what they did. Each person
runs their own agent on their own machine; every action it takes produces a
signed receipt that anyone can check, offline, without an account and without
installing Orrery.

This manual takes you from nothing to a running org, a working agent, and a
receipt a third party can verify. Follow it in order — each section assumes the
one before it.

**What you need:** Docker 24+ with Compose v2, about 2 GB of free RAM and disk,
and Git. No LLM key, no cloud account, no sign-up. Generative features are
optional and you can add a model key later.

---

## 1. Install the org

```bash
git clone https://github.com/Sharathvc23/orrery-public
cd orrery-public
./orrery-up
```

That is the whole install. It checks your prerequisites, generates secrets unique
to this machine, starts the org server and its database, starts a first agent
that joins the org, and then proves the stack is alive — health, the boot
conformance badge, the org counting your agent as a member, and your agent's
card. Your agent's profile is not probed: it stays private until the agent opts
in with `POST /api/me/listing`.

If a prerequisite is missing or a port is taken it stops and tells you which,
rather than half-building. Re-running is safe: `./orrery-up` keeps your existing
configuration. `./orrery-up down` stops everything.

Full detail, including running the pieces separately: [INSTALL.md](INSTALL.md).

**Your org publishes nowhere by default.** A fresh install talks to no registry.
Turning that on is section 7, and it is a deliberate act.

## 2. Meet your agent

The installer starts one agent for you. It has its own `did:key` identity, its
own signing key, and its own local log — none of which leave your machine.

Everything the agent does on behalf of the org is signed with that key, and every
request it makes to the org is signed too. There are no user accounts and no
passwords anywhere in the system.

The signing key is held in an encrypted file, unlocked by a passphrase you set at
install. Running your own agent, and the identity commands, are in
[agent/QUICKSTART.md](../agent/QUICKSTART.md).

> **Keystore backends.** The encrypted-file keystore is what this manual
> documents and what the installer uses. An OS keychain backend exists in the
> codebase; treat it as unconfirmed on your platform until you have tested it
> yourself.

## 3. Decide what the agent may do

**Read this before you ask the agent to do anything.** With no grants file, your
agent refuses every file, shell, network, browser and desktop action. That is the
default, and it is deliberate — an agent that can act on the world should only
reach what you have named.

Refusal is not breakage. With no grants at all, the agent still serves its card,
answers signed requests, drains its inbox and runs its deterministic skills. You
will simply find that anything touching your machine is declined.

To grant capabilities, copy the example and edit it:

```bash
cp agent/grants.policy.example ~/.community-member/grants.policy
```

Every line in the example is commented out. Uncomment only what this install
needs. The file is annotated with what each capability opens up.

> **Grants are configured by hand today.** There is no interface for editing
> them; you edit the file and the agent reads it. The example file is the
> documentation.

## 4. Approve your first action

Ask the agent to do something that touches a capability you granted. Two things
happen, and both are the point:

- **You approve it.** Consent-gated actions wait for a decision — approve, deny,
  or escalate to the owner. Approval is per action.
- **A signed decision receipt is written.** The decision is recorded and signed,
  so what you approved and when is provable afterwards rather than asserted.

Grants say what the agent *may* reach. Consent says whether this particular
action goes ahead. Both apply, and the narrower one wins.

> **Oversight is one approver.** A decision needs one person. There is no
> multi-party approval where several people must sign off on the same action.

## 5. Prove it to someone else

This is what the receipts are for. A receipt verifies **offline**, against the
signer's published key, using a published library — no Orrery installation, no
account, no call back to you.

Give someone a receipt bundle and they can check it themselves:
[VERIFY_A_RECEIPT.md](VERIFY_A_RECEIPT.md). It walks through verifying a real
bundle in a fresh environment with nothing of yours installed, including what a
tampered receipt looks like when it fails.

Your org also publishes a **conformance badge** at boot, saying which parts of
the protocol it implements. Anyone can re-check it the same way:
[VERIFY_A_BADGE.md](VERIFY_A_BADGE.md).

> **The badge is self-attested.** It reports what the org says it implements and
> is signed so it cannot be altered undetected. It is not an audit by anyone
> else, and it does not claim to be.

## 6. Install and publish skills

Skills are capability packs your agent can install, run, publish and revoke.
Publishing signs the pack with the author's identity, so an installer can see who
wrote what they are running. Installs are free.

Instructions: [SKILLS.md](SKILLS.md).

> **Skills run with your agent's privileges.** The consent gate decides whether a
> skill runs; it does not isolate the skill from your machine once it does.
> Capability-gated is not the same as sandboxed. Read a skill before installing
> it, as you would any package.

## 7. Join other orgs

Federation lets orgs discover each other, exchange signed records, and check one
another's identity claims. It is off until you configure it.

To publish your org to a registry you set **both** a registry URL and
`AUTO_REGISTER=true`. A stock install writes an empty registry URL and leaves
auto-registration off, so nothing is published until you make both changes
deliberately. Peer discovery and cross-org sync are separately opt-in.

Configuration: [CONFIGURATION.md](CONFIGURATION.md).

What you get once it is on:

- **Self-certifying records.** Registry entries are signed by the org they
  describe, so a consumer can verify one without trusting the registry.
- **DID pinning.** The first identity you see for a peer is pinned; a later
  record presenting a different key raises a mismatch instead of silently
  replacing it.
- **Cross-registry divergence detection.** Your orgs cross-check each other's
  records and flag a registry that tells different parties different things.

> **Divergence detection needs two or more registries.** With one registry
> configured there is nothing to cross-check, and the detector has nothing to
> compare. Nothing in a single-registry setup will tell you this is inactive, so
> check your configuration rather than assuming it is running.

## 8. Generative surfaces

Your org and agent can emit their interface as data — a structured surface a
renderer paints, streamed as it changes. The default shell is deterministic: it
runs with no model key, offline, and is themeable by editing the stylesheet.

With a model key, an agent can compose a surface from an intent instead of using
the default shell.

**With no model key configured, your org contacts no model provider.** The
generative endpoints check whether a provider is configured before calling one,
and serve the default shell instead. A model running on your own machine counts
as configured — a `localhost` base URL reaches Ollama, LM Studio and similar
without a key and without leaving the machine.

> **This is an API, not a button.** The reference renderer has no box to type a
> request into. Putting a composed surface in front of a person is integration
> work you do.
>
> **Two endpoints behave differently.** The org endpoint returns the default
> shell whenever composition fails, so you always get a page. The agent endpoint
> refuses without a key and returns an error instead. Choose the org endpoint
> when you want a page no matter what, and the agent endpoint when you want to
> know that composition did not happen.
>
> **Quality depends on your model.** The org checks that a composed surface is
> structurally valid and strips what it does not recognise. It does not judge
> whether the content is any good.
>
> **The renderer must be allowed to talk to your org.** It is served separately,
> so name its origin in `ALLOWED_ORIGINS` or the browser will block it. Theming
> is done by editing the renderer's stylesheet; injecting a stylesheet is refused
> by the renderer's own content-security policy.

## 9. What Orrery does not do

These are deliberate. They are listed so you can rule the product in or out
without discovering a gap later.

- **No MCP client or server is built in.** Orrery composes MCP-speaking tools
  alongside itself; it does not embed the protocol.
- **No desktop application and no bundled web interface.** The org is a signed
  HTTP API. You drive it through the API, the CLI, or the reference renderer,
  which you point at the agent yourself.
- **No multi-party approval.** Oversight is one approver per decision. There is
  no M-of-N quorum on a consented action.
- **Receipts are not financial instruments.** They carry reputation and they
  verify offline. They are not priced, transferable or tokenised, and there is no
  plan to make them so.

## 10. Capability index

Every capability the product page advertises, and where this manual covers it.

| Capability | Where |
|---|---|
| Multi-agent runtime, think/act loop, REST and A2A transport | §1 |
| Org provisioning — name and identity at install | §1 |
| Federation — publish to registries | §7 |
| Federation — peer discovery and cross-org sync | §7 |
| `did:key` identity with a real keystore | §2 |
| Ed25519-signed requests, signed receipts, hash-chained log | §2, §5 |
| LLM planner, bring your own provider, keyless supported | §8 |
| Consent-gated actions | §3, §4 |
| Skills — install, run, publish, revoke | §6 |
| OpenClaw drop-in skill | §6 |
| Offline-verifiable, hash-chained, portable receipts · Chronicle | §5 |
| Human oversight — approve, deny, escalate | §4 |
| Reputation with counterparty corroboration, duress detection | §7 |
| Sybil-ring detection | §7 — flags for review; it does not block admission |
| Conformance badges, Merkle checkpoints, DSAR export | §5 |
| Signed registry records, DID pinning, divergence detection, lean index | §7 |
| A2UI renderer, AG-UI streaming, deterministic keyless shell | §8 |
| Agent-composed surfaces from intent | §8 |
| Signed skill registry | §6 |
| Revenue ledger | §6 — test currency; there is no payment rail |
| MCP tool integration | §9 — not built in |
| Desktop app or bundled web UI | §9 — not built |
| Multi-party consent quorum | §9 — not built |
| Receipts as tradeable assets | §9 — not built |

If you find something advertised that this manual does not cover, that is a
defect in the manual. Please report it.
