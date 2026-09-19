# Roadmap

What's **live today** is in the [README](../README.md) and [`CLAIMS.md`](./CLAIMS.md).
This page is the opposite: what's **planned but not done**. Items are grouped by horizon,
not committed to dates. Each is a real, scoped piece of work — nothing here is marketing.
A final section lists what's **deliberately out of scope** — cut or never planned — so
that absence from the product isn't mistaken for a promise.
When something ships it is *removed* from this page. Recently graduated: the `./orrery-up`
installer, the boot conformance badge, self-serve member cards, the federation directory,
the A2UI reference renderer, the discoverable skill marketplace with signed
`.nandaskill` packages, and an MCP server exposing accountability primitives
(`mcp_server/`) — each now carries a row in [`CLAIMS.md`](./CLAIMS.md) with the
evidence that graduated it, which is the checkable form of this sentence.

> Legend: 🔜 next · 🛠 in progress · 🔭 exploring

## Generative UI — server-side generation guards  🔜

The surface layer is live end to end: org and agent emit [A2UI v0.10](./specs/agui.md)
envelopes (`/api/surfaces/*`) streamed over AG-UI (SSE snapshot + deltas), deterministic
without a key, with the streaming contract hardened as normative client rules
(reconnect/backfill, atomic malformed-delta rejection, version negotiation — see the
[spec](./specs/agui.md)). A small **reference renderer** ships in the repo (`renderer/`,
static-servable, zero deps, untrusted-content guards + keyless deterministic fallback). What remains: the **server-side** trust/safety guard suite for `compose` output
(the renderer-side guards already shipped; a generated surface is an attack surface).

## Cross-org federation — the rest  🛠

Live today (opt-in): allowlist + attested-directory peer discovery, cross-org member
directories, Ed25519-signed broadcasts with enforcement shipped on. Still planned:

- **Autodiscovery on by default** — no allowlist or directory URL to configure.
- **Cross-org receipt / reputation portability** — a receipt earned in one org counting
  toward reputation in another, with the corroboration rules intact.

## Event bus — webhook delivery  🔜

Typed subscriptions deliver over SSE today. Webhook (push) delivery for subscribers that
can't hold a connection open is the missing half.

> The API does not report the gap. A subscription with `delivery="webhook"` is accepted:
> `validate_delivery` requires a `webhook_url` and an `https://` prefix, the
> `event_subscriptions` table has CHECK constraints for both, and the row persists. No
> dispatcher exists anywhere in `server/`, so nothing is ever POSTed to that URL and a
> caller receives a success response followed by no events. Until a dispatcher ships,
> `delivery="webhook"` is accepted and not honoured; the fix is to build the sender or to
> reject the value at the API.

## Governance — auto-resolving M-of-N promotion  🔜

Role-promotion nominations collect M-of-N approvals today; resolving the promotion
automatically when the quorum lands (instead of an admin closing it) is not built yet.

## Skill economy — settlement rails  🔭

The signed skill registry is live (publish / install / review / revoke, author DIDs,
trust-tier attestations). A revenue *ledger* records per-use splits today — but in a
**test currency** (`TEST_USD`), with billing self-reported through an endpoint rather
than minted at verified invocation, and no payout path. Real settlement — a payment
rail, splits keyed to policy, and use-events bound to a signed invocation instead of a
self-report — is what turns this from honest accounting into an economy.

## Packaged per-OS installer  🔭

`./orrery-up` gives a terminal user a one-command install. The remaining step is a
**double-click installer** (per-OS bundle) so a non-technical operator can stand up an
org and an agent without a terminal.

## Hardware keystore  🔭

The agent's `did:key` is software-held (passphrase-encrypted) today. A **hardware-backed
signing element** (TPM, YubiKey, Secure Enclave) would keep key bytes out of agent RAM —
the strongest defense against a compromised running process. Targets sovereign SDK v0.7.

## Quality gates — broaden the floors  🔜

ruff + mypy now cover the whole server, and coverage floors are enforced on the
auth/crypto modules. Remaining: raise coverage measurement from those floors to a
repo-wide gate, and keep extending the compose e2e probes as new surfaces ship.

## Transparency log for first-contact discovery  🔭

The documented honest gap: first-contact equivocation against a **single** registry is a
trust-on-first-use limit. Cross-registry corroboration narrows it; only an append-only
transparency log over registry records fully closes it.

## Deliberately out of scope

Not everything absent is planned. These were considered and cut — named here so the
roadmap isn't read as a promise-in-waiting:

- **Desktop app / bundled web UI** — removed on the headless pivot (the Electron app was
  deleted outright). Orrery is a signed HTTP API: drive it via the API, the CLI, or the
  BYO reference renderer (`renderer/`). No bundled GUI is planned.
- **Receipts as tradeable / financial assets** — receipts are reputation-bearing and
  offline-verifiable, not financial instruments. There is no plan to make them priced,
  transferable, or tokenised. (The economy work above is a *settlement rail for skill
  use*, not a market in receipts.)
- **Multi-party (M-of-N) consent quorum** — human-oversight approval is 1-of-1 by design
  (`decision_feed`). Multi-party *role-promotion* quorum is planned (see Governance
  above); a multi-signer gate on every consented action is not.

---

*See something you'd build first? Open an issue. Live capabilities are in
[`CLAIMS.md`](./CLAIMS.md); this page is intentionally only the not-yet.*
