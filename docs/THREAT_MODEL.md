# Threat model

Who can do what to whom, and what Orrery does and does not defend. This page
is anchored on [`TRUST_MODEL.md`](./TRUST_MODEL.md), which states what each
artifact proves; here the same facts are arranged by party. Every open and
residual audit finding is listed by its id in the ledger,
`docs/audit/findings.json`, with the cost that was accepted; the ledger is the
authority on status and a CI gate keeps the two in step.

## Assets

| Asset | Where it lives | Compromise means |
|---|---|---|
| The org's Ed25519 signing key | Postgres (`chapter_keys`) or the offline key file, sealed under `ORRERY_KEY_SECRET` | Whoever holds it signs receipts, badges, checkpoints, federation broadcasts and the rotation chain as the org. |
| `ORRERY_KEY_SECRET` | The operator's environment | With the database, the above. Without the database, nothing. Lost, the stored key is unrecoverable and the org is a new identity. |
| The admin token | `.org-admin-token` (0600) on the server host, printed once at first boot | Every `/admin/api/*` action: roles, revocations, invites, receipt publication, audit attestation. |
| A member's Ed25519 seed | The agent's vault on the owner's machine (keychain, passphrase or device backend); the 24-word phrase wherever the owner kept it | Whoever holds it acts and signs as that member everywhere. |
| A tenant's seed on the SMB host | The tenant's vault on the host's volume, under the host-wide keystore secret | The operator, or anyone holding that secret, signs bookings and receipts as any tenant and can rotate any tenant's identity. |
| Members' LLM provider keys | Sealed in Postgres (`agent_api_keys`) on the org; the owner's `.env` for a sovereign agent | The member's provider spend. |
| The receipt ledgers | The org's issuer log (Postgres); each agent's Agency Log (SQLite) | Read: the members' interaction history. Write: an org key or a member key, respectively — the chains and signatures make silent edits detectable to anyone re-verifying. |
| The consent ledger and AAE chain | SQLite beside the agent | The owner's decisions; the chain is hash-linked and signed, and a foreign-key append under the same agent id is not detected (`TRUST_MODEL.md` § 4). |
| The member directory | Postgres on the org | Names, descriptions, skills, endpoints — the roster. Served only to a registered member, an admin, or a signed federation peer. |
| The database itself | The Postgres volume and its backups | Everything above that is stored there, sealed values as ciphertext. |

## Parties, and what each can do to the others

**Owner of a sovereign agent.** Holds the agent's key and its recovery phrase;
decides at the consent gate what the agent may do, and can withdraw the
listing consent that makes the agent's profile visible. Cannot sign as the
org or as another member; cannot make the org publish or unpublish anything
except their own listing entry. Can be harmed by: a compromised machine (every
keystore backend falls to a compromised running process); an org operator who
pins a first-claim key on a member with no key on file, or vouches a successor
key at revocation — which re-points the org's directory entry, not the
member's `did:key`; a counterparty that declines to co-sign, which leaves the
owner's receipt valid but uncorroborated.

**Org operator.** Holds `ORRERY_KEY_SECRET`, the admin token and the database.
Can sign as the org; can change roles, revoke members, name a successor key
(recorded as *operator-vouched*, an assertion to review, never a checked fact),
publish the org's own receipts, and — when a registry is configured — publish
the members' directory entries on the operator's decision alone; there is no
per-member opt-out of that today. Cannot sign as a member, forge a member's
receipt, or read a member's Agency Log. Can be harmed by: a member who rotates
away from a compromised key (the operator sees a signed rotation, not a
choice); a peer org that lies in a broadcast, which the signature catches; a
registry that lies, which two registries catch and one does not.

**SMB host operator.** Holds the host's keystore secret and the volume. Can
act as any tenant — sign its bookings and receipts, rotate its identity,
delete it. The business cannot detect this from a receipt: the card and the
receipt come from the same origin. What limits the operator: the tenant's
recovery phrase is never written by the host, so a business that kept it holds
the one copy the operator does not; and the host performs no consent-gated
action, so there is no consent decision to forge. Cross-tenant reach was driven
and not found: path traversal, encoded separators, case-flips and body-named
tenants all fail to reach another tenant's home.

**Counterparty agent.** Receives a task over A2A and may co-sign the caller's
receipt. Can decline to co-sign, which is not an error; can return any result,
which nothing checks; can lie about its own outcome. Cannot forge the caller's
receipt or its own co-signature under a key it does not hold; a co-signature by
a party other than the named counterparty is rejected and rolled back.

**Registry** (NEST, the NANDA Index, a directory). An untrusted courier. Can
serve a tampered record (caught: the attestation's signature breaks), a stale
one (caught: it ages out), omit an org or equivocate between clients (caught
only with two or more registries configured; a single registry's omission or
equivocation is not detected by anything here). The first sighting of a peer's
DID is trust-on-first-use.

**Stranger.** Unauthenticated, no key. Can read every open surface: health,
AgentFacts, cards, badges, the dashboard, published disclosure bundles, an
opted-in member's profile and the opted-in listing. Cannot read the member
directory, a silent member's profile, receipts, or anything under `/admin`.
Can register a fresh keypair as a new member under the org's join policy (open
policy: TOFU — whoever signs first binds the identifier). A signature alone is
possession of a key, not membership: a verified signature from an unregistered
id does not count as a member on gated routes.

## What the defences are, in one line each

- **Signature verification is the trust boundary.** Every mutation and every
  gated read is bound to an Ed25519-verified caller (`server/auth_verify.py`);
  the v0.3 scheme binds method, path, body, id, timestamp and nonce.
- **Consent before action.** The agent's gate decides before any runner is
  invoked; untrusted-provenance proposals are never executable, one-shot
  approvals are consumed before the runner fires, and a runner's outcome is
  recorded whether it returned, raised or crashed (`agent/community_member/executor.py`).
- **Receipts written ahead.** An outbound call is recorded as a pending
  attempt before it is issued and finalized after, so a crash leaves *unknown*,
  not nothing; a retry of an attempt that succeeded or is unknown is refused
  before it sends.
- **Sealed at rest.** The org key and members' LLM keys are AES-256-GCM
  ciphertext under `ORRERY_KEY_SECRET`; the server refuses to start without it.
- **Nothing published by default.** There is no default registry anywhere:
  neither the org nor the agent reaches one it was not pointed at, and the
  agent publishes nothing without an owner-signed grant.
- **Untrusted courier.** Registry records are self-certifying; peers are
  DID-pinned; two registries are cross-checked.
- **Sandbox by default for outbound email.** Four independent conditions each
  prevent a live send; the sandbox transport holds no HTTP client.

## Open and residual findings, by id

Status and wording are the ledger's (`docs/audit/findings.json`,
[`../AUDIT_HARSH.md`](../AUDIT_HARSH.md)); the cost column is what was accepted
and why.

| Id | Sev | Finding | Accepted cost |
|---|---|---|---|
| **H1** | high | Registration is trust-on-first-use. | Whoever signs first for an identifier binds it. Bounded by the join policy (invite / approval) and by the key-provenance record, which marks such keys as claimed rather than attested. |
| **H8** | high | `ORG_ADMIN_TOKEN` ships blank in `.env.example`. | The server never runs without one: a blank value makes it generate a random token at first boot, write it to a 0600 file and print it exactly once (`server/admin.py::init`). The residual is an operator who never reads that line. |
| **M2** | medium | The v0.3 replay-nonce store is memory-only. | A signed request captured inside the ±300 s window can be replayed once after a restart. A durable store would put the database on the path of every signed request. |
| **M4** | open, medium | Thirteen `SECURITY DEFINER` functions in `infra/init.sql` were not individually assessed. | No decision recorded; it stays open. |
| **M9** | medium | The local agent API on loopback. | Routes require a bearer token from a 0600 file (`agent/community_member/local_auth.py`); any process running as the same user can read that file. Accepted for a loopback surface. |
| **M16** | medium | The rate limiter's key store. | Capped at 10,000 keys with a documented capacity refusal ([`CONFIGURATION.md`](./CONFIGURATION.md)). |
| **M17** | medium | CORS allows all methods and headers. | Origins are restricted to `ALLOWED_ORIGINS`; wildcard methods and headers do not widen who may call. |
| **M18** | medium | `/a2a` and `/run` are exempt from method binding. | They use the v0.2 scheme for interop; replay inside that scheme is the accepted cost of A2A compatibility. |
| **M20** | open, medium | Signed-request failures return specific reasons (`key_mismatch`, …). | The reason set is mandated by the published signing spec and asserted by the conformance suite; the membership oracle it implies is a spec-level property, and the status code, not the string, is what distinguishes a known id from an unknown one. |
| **L2** | low | `/admin/index.html` is served without auth. | A paste-your-token page cannot be gated on the token it collects; the token is 32 random bytes compared in constant time. |
| **L5** | low | An ephemeral in-memory key fallback exists. | Without persistence the org's signing key is fresh per process; the code names this at the site. |
| **L7**, **L8** | low | Two fail-closed checks deny on a database error. | Availability cost accepted over a replay or over-use. |
| **L10** | open, low | A deterministic `session_id` cookie was reported. | Not located in the source; recorded open rather than closed on an absence of evidence. |
| **L11** | low | Event payload text reaches SSE subscribers unescaped. | The server does not know the rendering context; the untrusted fields are enumerated and served at `GET /api/event-catalog`, and a subscriber that renders them raw has the defect. |
| **L12** | low | The public-CORS path list is a hand-maintained set. | A new public path silently lacks CORS — the restrictive direction. |
| **L13** | low | Rate limiting runs before authentication. | What makes it useful against anonymous scrapers; anonymous floods share the bucket authenticated callers use. |
| **L14** | low | The store's `in` filter cannot express a value containing a comma. | A correctness limit on the filter language, not an injection path. |

Two further residuals were recorded in the Phase-1 server inspection and land
with it: the three Index-resolution routes (`/agents/{id}`,
`/.well-known/agentfacts/{id}.json`, `/sm-bridge` resolve) answer existence
anonymously by design of the Index hop — consent-gating them would break
resolution for members who published without opting into the listing, which
is a product decision; and the memory-only nonce store above, restated with
its window. The [`RELEASE_CHECKLIST.md`](./RELEASE_CHECKLIST.md) names the
change that records them.

## Known gaps that are not findings

These are properties of the design as shipped, stated so that nobody infers
their opposite.

- **Local executions leave no receipt.** A file write, a shell command, a
  network fetch, a browser or desktop step, or a skill invocation produces the
  signed consent decision and a ledger row, and no ARP receipt. Whether an
  executed local action should be receipted is an open product decision, not
  an oversight in the code.
- **No confirmed external outcome exists.** A booking's delivery is a webhook
  response; an A2A result is the counterparty's word; an outbound email's
  `delivered` is the provider's response. No human is notified by the runtime,
  and nothing checks an effect against the world.
- **One registry is not corroborated.** The divergence detector needs two;
  first contact with any registry or peer is trust-on-first-use.
- **Offline verification goes stale silently.** A receipt does not carry a
  later skill revocation or key rotation; a badge has no expiry and can be as
  old as the first boot; a fetched listing does not show a later withdrawal;
  a PARC is self-issued for a window the issuer chose. `TRUST_MODEL.md` § 3.
- **The org checkpoint is served only on a SQLite-backed issuer log.** A member
  of a Postgres-backed org cannot obtain an inclusion proof from it today; the
  two-agent demo records `404` for it against its database-backed org and
  shows the org's holding of the receipt by a signed read instead.
- **A grant and a consent envelope have no non-producer verifier.** A receipt
  and its co-signature are checked by two JavaScript verifiers that share no
  code with the producer; the DAT and the sm-aae envelope are checked only by
  the libraries that made them. `TRUST_MODEL.md` § 2.2.
- **The hosted tenant's key is the host's.** Stated above and in
  `TRUST_MODEL.md` § 5; nothing in the code narrows it.
- **The org publishes members on the operator's decision.** When a registry is
  configured, a member's directory entry goes to it without a member-level
  consent record; the join response discloses this.
- **Horizontal scale.** Rate limiting and the nonce store are per process.

## What this page is not

Not an independent audit, and not a claim that the properties above hold
beyond the tests that state them. A reader deciding whether to run Orrery in
a setting with a real adversary should read the ledger, drive the flows they
depend on, and treat every "verified" above as verified *by the named test*.
