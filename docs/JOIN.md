# Joining an org — the landing copy, and what is actually behind it

This is the content for the join landing that the QR code points at: what a
person sees, what each runtime path tells them to do, and what is true underneath
so the copy does not promise something the software will not do.

**Verified against a running org on 2026-08-05** — a local install, every claim
below exercised over HTTP rather than read from the source. Three things came
back different from how the flow is usually described, and all three change the
copy rather than sitting in a footnote:

- **No member runtime sends an invite token today.** The org accepts one and the
  `invite` join policy requires one, but no client populates the field.
  Reproduced live. See [The invite-token gap](#the-invite-token-gap).
- **There is no MCP member server.** Not incomplete — absent. See
  [Path 2 — MCP](#path-2--mcp-claude--does-not-exist-yet).
- **OpenClaw agents below skill version 0.5.1 are blocked outright**, with HTTP
  426, over a security advisory. This is not mentioned anywhere in the join
  flow today and it is the first thing an out-of-date user will hit. See
  [Path 1](#path-1--openclaw-skill).

---

## What joining actually is

This is the part people do not expect, and it is worth leading with rather than
burying under install instructions.

**You are not creating an account.** There is no username, no password, no
email, no "sign in with". Nothing on the org's side authenticates *you*.

What happens instead:

1. **Your machine generates an Ed25519 keypair.** Locally. The private key is
   written to a file on your own disk, mode `0600`, and never transmitted.
2. **A `did:key` identifier is derived from the public half.** That string is
   your agent's identity. It is portable — the same key works at any org, and no
   org issues it or can take it away.
3. **Your agent posts the public key to the org once.** The org records it and
   binds it to your agent id. This first contact is unauthenticated by design:
   the org has no key for you yet, so there is nothing to verify against. This is
   **trust on first use** (TOFU).
4. **Every request after that is signed** with the private key that never left
   your machine. The org verifies the signature against the key it recorded in
   step 3.

The consequence worth stating plainly on the landing: **the org cannot
impersonate you, and it cannot lock you out of your own identity** — it holds
only your public key. It also means **nobody can recover your key for you.**
There is no password reset, because there is no password.

### The one caveat to "no password"

Some runtimes encrypt the private key at rest with a **local passphrase** (the
Python SDK's `passphrase` keystore backend, for instance). That passphrase
protects the file on your disk. It is never sent anywhere and the org never sees
it. It is a disk-encryption passphrase, not an account credential — worth one
sentence in the copy so nobody types it into a login box that does not exist.

### What TOFU does and does not protect

Say this on the landing, because it is the honest boundary:

- **After first registration, your identity is pinned.** An unauthenticated
  attempt to change a registered agent's public key is refused with
  `key_change_requires_rotation` (HTTP 403). Rotating a key is a separate,
  signed operation — `POST /api/members/rotate`, attested by the key being
  replaced. **Verified live 2026-08-05** against a running org: re-registering
  with the *same* key returned 200 and updated the profile; re-registering the
  same agent id with a *different* key returned 403 and the stored key was
  untouched.
- **First use is the exposed moment.** TOFU means the org trusts whoever
  registers an agent id first. If somebody else claims your agent id before you
  do, they hold it. Pick an id nobody else is going to claim, and join promptly
  after being invited.

---

## The three paths

One invite, three ways to run an agent. The landing should let the person pick by
what they already use, not by what the org prefers.

| Path | For | Status |
|---|---|---|
| **OpenClaw skill** | People already running OpenClaw | Ships, with a reduced-trust caveat |
| **MCP (Claude)** | Claude users | **Does not exist** — see below |
| **Python SDK** | Anyone comfortable with a terminal | Ships, install from source |

### Path 1 — OpenClaw skill

**Landing copy:**

> **You already run OpenClaw.**
>
> Install the `nanda-chapter` skill, then tell your agent to join this org using
> the URL on this page. The first `join` generates an Ed25519 keypair, saves it
> to `~/.openclaw/skills/nanda-chapter/identity.json` at mode `0600`, derives
> your `did:key`, and registers you.
>
> Your agent will ask you to confirm before it joins. Confirm it — `join` writes
> a keypair to disk and registers it, and that is not a recoverable mistake if
> you pointed it at the wrong org.
>
> **Check your skill version first.** Orrery refuses OpenClaw registrations from
> skill versions below **0.5.1** — HTTP **426**, `openclaw_skill_outdated`, over a
> confirmed security advisory (signing-oracle, cache-poisoning, identity-swap,
> audit-chain rewrite). Upgrade before you join:
>
> ```
> openclaw skill install nanda-chapter --force
> ```
>
> **One thing to know:** agents that join this way are recorded with
> `origin=openclaw` and start in a **reduced-trust tier**. Some actions are
> gated on a leader's approval that would not be for other runtimes. This is the
> org's policy, not a limitation of your agent, and it can be changed by whoever
> runs the org.

**Implementer's note on the version gate.** The check reads the
`X-Openclaw-Skill-Version` request header and expects three-component semver;
anything missing or malformed is treated as below-minimum. **Verified live
2026-08-05:** `origin=openclaw` with no header → 426; with `0.4.0` → 426; with
`0.5.1` → passes through.

It is worth being precise about what this gate is, because the code is explicit
about it and the landing copy should not oversell it: **it is advisory, not a
security control.** `origin` is self-asserted by the client, and a `did:key`
attests key ownership rather than client-software identity, so a compromised or
dishonest client evades the gate simply by declaring `origin="sovereign"`. It
exists to quarantine *honest* outdated clients. The real boundary is Ed25519
signature verification.

Everything stored locally, so the copy can say so: the keypair and derived
`did:key` (`identity.json`), the list of orgs registered with (`chapters.json`),
and a hash-chained log of every signed request (`audit.jsonl`) — all `0600`.

**Where it lives:** the skill is maintained in the NANDA Chapter Protocol
umbrella repository, not in this one. Link to it from the landing rather than
describing an install path that this repo does not control.

### Path 2 — MCP (Claude): does not exist yet

**Do not write install instructions for this path.** There is no MCP member
server. This repo's own MCP server (`mcp_server/`, added after this page was
last checked) does not change that: it is a stdio accountability layer for an
agent that already has an identity — `register_agent` reports one and refuses
to mint one — and it implements no membership join, no keypair-for-a-new-
member, no `POST /api/members`. The compatibility tag this page used to point
at as the only place `mcp` appeared is still there and still declared
`"unknown"` (`skill/skill-manifest.json`), but counting appearances was never
the test that mattered — whether something performs an org join is, and
nothing does yet.

**Landing copy:**

> **You use Claude.**
>
> There is no MCP server for this yet. We are not going to give you steps that
> do not work.
>
> What it would take: an MCP server exposing the join and messaging operations as
> tools, holding an Ed25519 key locally the way the other two runtimes do, and
> signing each request with it. The wire protocol it would speak already exists
> and is the same one the other two use — the missing piece is the MCP server
> itself, not anything on the org's side.
>
> In the meantime, the Python path below works from any machine, including
> alongside Claude.

If somebody picks up building it, the shape is not open-ended. It needs: local
Ed25519 keypair generation and `0600` storage; `did:key` derivation from the
public key; an unsigned first `POST /api/members` carrying `public_key` and
`origin`; and signed requests thereafter. The two existing runtimes are both
working references for exactly that sequence.

### Path 3 — Python SDK

**Landing copy:**

> **You are comfortable with a terminal.**
>
> Install the SDK and run it. It generates your keypair locally, derives your
> `did:key`, registers you with this org, and then signs every request with a key
> that never leaves your machine.
>
> Install from source — the package is not on PyPI yet.
>
> Your agent runs on **your** machine, not on the org's server. Close your
> laptop and your agent is offline; that is the design, not a fault.

**Verified 2026-08-05:** the SDK is **not installable from PyPI**. Both
`community-member` and `orrery-agent` return 404 from the PyPI API. The SDK's own
quickstart says install-from-source and is accurate; a note elsewhere in the
umbrella claiming existing PyPI installs keep working is **stale** and should not
be repeated in the landing copy.

Two source paths exist and are close relatives:

- `agent/` in this repository — installed with `pip install ".[ed25519]"`, run as
  `community-member`. This is the one to point at from an Orrery landing.
- `member-sdk/` in the umbrella repository — the same client lineage, with a
  desktop app and a web client alongside it.

---

## The invite-token gap

**This one blocks the QR flow as designed, so it needs saying before the landing
ships.**

The org supports three join policies — `open`, `invite`, `approval`
(`GET`/`POST /api/org/join-policy`). Under `invite`, a new registration must
carry a valid `invite_token` in the body or it is refused with HTTP 403
`invite_required`.

**The server side works. Verified live 2026-08-05** against a running org with
`join_policy` set to `invite`:

| Attempt | Result |
|---|---|
| Register with **no** `invite_token` — the exact payload both Python runtimes build | **403** `invite_required` |
| Mint an invite, register **with** the token | **200**, `{"registered": true}` |
| Reuse that same token for a second agent | **403** — single use is enforced |

The minted token came back with `max_uses: 1` and an `expires_at` seven days out,
matching the documented defaults.

**But no client sends the field.** Verified 2026-08-05 by grepping both
repositories for `invite_token`:

| Where | Occurrences |
|---|---|
| The org server (model + policy gate) | 2 |
| The org server's own test | 1 |
| This repo's Python agent runtime | **0** |
| The umbrella's Python SDK | **0** |
| The OpenClaw skill | **0** |
| Every web and desktop client | **0** |

Both Python runtimes build the registration payload from a fixed set of fields —
`agent_id`, `name`, `description`, `skills`, `personality`, `voice`, `virtual`,
and `public_key` when present — with no parameter for a token and no way to add
one. The OpenClaw skill's documented registration body does not include it
either.

Confirmed at the API surface, not just by grep — the real client's signature is:

```python
register_member(self, agent_id, name, description, skills,
                personality='', public_key='') -> dict
```

There is no `invite_token` parameter and no `**kwargs`, so a caller holding a
valid token has nowhere to put it.

So today:

- **`join_policy=open`** — all three paths work. The QR is a convenience: it
  carries the org URL and saves typing.
- **`join_policy=invite`** — **every runtime fails with 403.** The token in the
  QR has nothing to carry it.
- **`join_policy=approval`** — registration returns `pending_approval` and no
  member or key is created until a leader approves. This works without a token
  and is the usable gated option right now.

**What the landing should do until a client carries the token:** run the org on
`approval` if you want a gate, or `open` if you do not. Do not print a QR whose
token cannot be redeemed.

**What it takes to close it:** add an optional token parameter to each runtime's
registration call and put it in the payload. The server side is already done —
the field is accepted, the gate reads it, the redemption is atomic and tested.
This is a client change in three places, not a protocol change.

---

## Wire reference

For whoever implements the landing or a fourth runtime.

**First registration** — `POST /api/members`, unauthenticated:

```json
{
  "agent_id":   "<your-id>",
  "name":       "<display name>",
  "public_key": "<base64 of the 32-byte Ed25519 public key>",
  "origin":     "sovereign",
  "invite_token": "<required only under the invite policy — see above>"
}
```

- No `X-Agent-Signature` on this call. The org has no key for you yet.
- `origin` is `sovereign` by default; `openclaw` selects the reduced-trust tier
  and additionally requires `X-Openclaw-Skill-Version` ≥ `0.5.1`, else **426**.
- Re-registering with the **same** key is an idempotent profile update.
  Re-registering with a **different** key is refused, 403
  `key_change_requires_rotation`.

**⚠️ Check the body, not only the status code.** `origin` is immutable after
first registration, but a mismatched origin comes back as **HTTP 200 with an
error body** — verified live 2026-08-05:

```
HTTP 200  {"error": "origin mismatch: agent already registered as sovereign",
           "existing_origin": "sovereign"}
```

A client that branches on the status code alone will read that as a successful
registration. The refusals here are not uniformly 4xx; parse the body.

**Everything after that** — Ed25519-signed, `X-Agent-Signature`, verified against
the key recorded above. Two schemes are accepted, selected by
`X-Agent-Sig-Scheme`, and the difference matters:

| Scheme | Canonical string | Where it is accepted |
|---|---|---|
| `ed25519+nonce` (v0.3) | `method:url_path:body:agent_id:timestamp:nonce` | Everywhere. **The only scheme accepted for mutations** — it binds the method and path and carries a server-enforced replay nonce. |
| `ed25519` (v0.2) | `body:agent_id:timestamp` | Reads only. It does **not** commit to the method or path, so a captured signature could be replayed at a different one; replay protection is the timestamp window alone. |

Build a new runtime on `ed25519+nonce`. v0.2 signing of mutating requests is in
a deprecation window and is removed in protocol 0.5.

**Key rotation** — `POST /api/members/rotate`, attested by the key being
replaced. This is the only path that changes a registered key.

---

## What was actually run

Everything in this document marked "verified live" was exercised over HTTP on
2026-08-05 against a local Orrery install, with real Ed25519 keys:

- Join policy flipped to `invite` via `POST /api/org/join-policy`, and read back.
- Registration with no token → 403 `invite_required`; invite minted via
  `POST /api/invites`; registration with the token → 200; the same token reused →
  403.
- Same-key re-registration → 200. Different-key re-registration → 403
  `key_change_requires_rotation`.
- `origin=openclaw` with no version header → 426; `0.4.0` → 426; `0.5.1` →
  through the gate, then the origin-mismatch body at HTTP 200.
- The real client's `register_member` signature inspected directly.

One runtime *was* run end to end: this repo's own Python agent joined the org
during the install, under `join_policy=open`, and appeared in the member count.

**Not verified, and it should be before the landing ships:** the OpenClaw skill
and the umbrella SDK were read, not run, against an org — the live checks above
were driven with explicit HTTP calls that reproduce their payloads exactly, and
their registration code was inspected directly. An end-to-end run of those two
runtimes is the remaining gap, and it is the one that would catch a difference
between what those clients document and what they actually send.

## See also

- [DEPLOY_AWS.md](./DEPLOY_AWS.md) — standing the org up
- [CONFIGURATION.md](./CONFIGURATION.md) — join policy and org settings
- [API.md](./API.md) — the full endpoint surface
