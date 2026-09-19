# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities **privately** by emailing
**sharath@komputix.com** with the subject line `[security]`.

You can also report privately through GitHub: **Security → "Report a
vulnerability"** on this repository.

Do not open a public issue or pull request for a security report.

### What a report should contain

- The component: `server/`, `agent/`, `smb_host/`, `smb_signup/`,
  `smb_funnel/`, `index/`, `mcp_server/`, `skill/`, `renderer/`, or the
  installer `orrery-up`.
- The version or commit you tested, and how it was deployed (`./orrery-up`,
  the manual Compose path, a bare process).
- Reproduction steps, with the request or command that demonstrates the
  issue and the response you observed. A signed request can be reproduced
  from `agent/community_member/auth.py` or `skill/helpers/sign_request.py`.
- What you believe the impact is — which party from
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) gains what against whom.
- Whether the finding is already listed by id in
  `docs/audit/findings.json` as open or residual; a report that sharpens an
  accepted residual is welcome and should say so.

### What to expect

You will receive an acknowledgement, a severity assessment against the
threat model, and a fix or a recorded disposition. Fixes ship as ordinary
pull requests with a regression test that fails on the pre-fix code, and the
finding is added to the audit ledger with its outcome; residuals are
recorded there with the cost that was accepted, never silently. Credit is
given in the changelog entry unless you ask otherwise. No fixed response
time is promised.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes — every merge passes the `ci gate` aggregate. |
| The latest tagged release | Yes — fixes land on `main` and ship in the next release. |
| Earlier tags | No. |

The org server, agent, host, index, MCP server and skill are versioned
independently in their `pyproject.toml` files; a report should name the one
it concerns.

## Track record

Orrery has been through two full security audits with every finding
dispositioned in public: the audit narrative is
[`docs/HARDENING.md`](docs/HARDENING.md) and [`AUDIT_HARSH.md`](AUDIT_HARSH.md),
the per-finding ledger is `docs/audit/findings.json`, and a CI gate
(`scripts/audit_gate.py`) refuses a ledger entry marked fixed without
evidence or a finding named in prose that the ledger does not carry. What is
still open or residual, and the cost accepted for each, is enumerated by id in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Threat-relevant design notes

The scope of every "signed" and "verifiable" below — what a signature proves,
what a chain does not prove, and who can sign as whom — is stated per action
kind in [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md).

- **Receipts are signed and offline-verifiable.** Trust claims (`sm-arp`,
  `sm-conformance`) re-verify against a `did:key` with no service on the path.
- **The trust boundary is signature verification.** Every mutating request is
  bound to the Ed25519-verified caller (v0.3 method-bound, replay-protected
  scheme); auth-required is the default with an explicit public allowlist, and
  a route-enumeration test sweeps every confirmed-private GET route. A
  verified signature from an id that is not registered does not count as a
  member.
- **Secrets never enter git.** `.env` is ignored; the stack reads keys from the
  environment only. The org's signing key **and** members' LLM provider keys are
  sealed at rest with `ORRERY_KEY_SECRET` (AES-256-GCM) — required, the server
  does not start without it — and the agent's key is held in a vault on its
  owner's machine, never in plaintext on disk.
- **Generative surfaces are an attack surface.** UI is emitted as data (A2UI)
  and painted by a renderer; the bundled reference renderer treats all surface
  content as untrusted, and everything degrades to the deterministic, keyless
  path — never to unguarded output.
- **The OpenClaw skill-version gate is advisory, not a security control.** The
  server returns `426 Upgrade Required` to outdated `openclaw`-origin clients.
  That gate keys off a *self-asserted* `origin` field, which cannot be bound to
  the client's `did:key`; a compromised client can bypass it by declaring
  `origin="sovereign"`. The actual trust boundary is signature verification plus
  the per-route authorization checks — never the version gate.
- **Known limits are documented, not hidden.** The trust-on-first-use ceiling
  against a single registry, the absence of any confirmed external outcome,
  and the other accepted residuals are enumerated in
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
