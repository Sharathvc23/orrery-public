# Gap map — delegated binding provisioning ("NANDA Connect")

**Status:** analysis, not a spec. Nothing here is built or promised. It maps a
requirements sketch for a *delegated binding-provisioning protocol* onto what
this repository actually contains, so the two are not confused.

**Traced against** `main` @ `c1ccdcf` (2026-07-26), and
[`docs/integrations/SMB_NANDA_HANDSHAKE.md`](../integrations/SMB_NANDA_HANDSHAKE.md),
which describes the same boundary from the registrar's side.

## The problem being mapped

An individual or SMB should not have to operate DNS, hold an index account, or
perform a second manual registration step to become discoverable. Something must
let an authorized agent store, website platform, commerce platform, or agent host
**provision and maintain a narrowly scoped index binding on the owner's behalf** —
create, update, suspend, migrate, revoke — without receiving unrestricted write
access to the registry, and without the owner losing control or portability.

The useful analogy is Domain Connect, with one load-bearing difference: Domain
Connect assumes the user has a DNS provider account. This must work for a subject
whose only credential is a consumer mailbox, or a merchant whose entire control
plane is a commerce platform.

Legend: **BUILT** in code · **PART** partial or adjacent · **GAP** nothing in code ·
**N/A** not this repository's layer.

## 1. Layer stack — who owns what, and where the hole is

```
   REQUIREMENT                            THIS REPOSITORY / ECOSYSTEM
   ────────────────────────               ──────────────────────────────────────
   IdP  or  Commerce Platform             GAP   no OIDC handshake; no commerce
   (mailbox provider, storefront,               platform integration of any kind.
    booking/POS platform)                       server/chapter_auth.py stores an
          │                                     IdP *binding config* and says so:
          │ signed identity /                   "does NOT perform the OIDC
          │ merchant attestation                handshake"
          ▼
   ┌───────────────────────────┐          card host + registrar
   │  Agent Store / Agent Host │          N/A   separate service. No index
   └───────────────────────────┘                client, no did:key signing,
          │                                     bearer-token auth only, domain
          │ ══ delegated grant ══>              ownership unverified
          │    ◄══ THE HOLE ══
          ▼
   ┌───────────────────────────┐          the index
   │  Binding registry         │          N/A   bearer-token only. No service
   └───────────────────────────┘                account, no on-behalf register,
          │                                     no bulk. This repo's lean
          │ subject → authorized card           index/ is the closest analogue
          ▼                                     and HAS the attestation gate (§5)
   ┌───────────────────────────┐
   │       Agent Card          │          BUILT smb_host serves
   └───────────────────────────┘                /t/<tenant>/.well-known/agent.json
          │
          │ auth, consent, runtime
          ▼
   ┌───────────────────────────┐          BUILT this repo IS this layer.
   │      Agent Runtime        │                /provision → {tenant_id,
   └───────────────────────────┘                endpoint, did, recovery_phrase};
                                                per-tenant AgentContext
                                                isolation; pre-warmed pool
```

**Read this first.** Orrery is strong at the bottom of the stack and absent at the
top. Everything from *Agent Card* down is built and signed. Everything from
*Agent Store → registry* up — the delegated provisioning protocol itself — exists
in no repository today.

That boundary is deliberate, not an oversight: the self-registration removal removed self-registration
from the SMB stack on the rule *one index, and it is not ours*. Orrery is the
agent runtime the card points at. Any protocol described here would be
implemented by the card host and the index, with Orrery as a participant that
supplies signed material — not as the thing that provisions bindings.

## 2. Subject onboarding, step by step

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Subject picks an agent store | N/A | not this repo |
| 2 | Subject proves account control | **GAP** | no identity-token verification, no JWKS |
| 2a | Durable identifier vs mutable locator | **GAP** | nothing binds a mailbox to an immutable provider-issued id |
| 3 | Store creates the Agent Card | **BUILT** | card advertises `ed25519` / `did-auth` |
| 4 | Subject grants publishing authority | **PART** | a signed delegated-grant *format* exists and is public — `sm-dat` ("what an agent is allowed to do, for how long, under what limits"), whose 34 conformance vectors ship in `agent/tests/vectors/sm_dat/0.1/` with a wire-anchor test. But no code constructs or enforces one, and its scope is *action* authority (amount caps, counterparty, jurisdiction, category, expiry, subdelegation narrowing) — never *binding provisioning* |
| 5 | Store provisions the binding | **GAP** | no delegated provisioning API |
| 6 | A counterparty discovers the subject | **PART** | resolve → card → runtime works; the binding leg is email-link activation only |

On (2a): a mailbox address is a fine human-readable *locator* and a poor
*authority anchor* — addresses are mutable and can be reassigned. A durable
binding needs the provider's immutable subject identifier underneath, with the
address recorded as the discoverable alias. That distinction does not exist here
yet. It also carries an unresolved privacy trade-off — a globally stable
identifier aids portability and enables cross-service correlation; a
pairwise-per-service identifier does the reverse — which is a design decision,
not an implementation detail.

## 3. Open problems, scored against code

| # | Problem | Status | Evidence |
|---|---------|--------|----------|
| 1 | Locator vs durable identity | **GAP** | `did:key` per tenant exists; nothing binds an address to an immutable provider id |
| 2 | Common authority-evidence format | **GAP** | two evidence types exist and neither is the one needed here: an Ed25519 endpoint attestation, and `sm-dat` grants (action authority). No email / domain / platform / civic credential model |
| 3 | Delegated provisioning protocol | **GAP** | the core ask. Nothing. A registrar today would register every subject under one shared machine credential |
| 4 | Template / field-scope semantics | **GAP** | no partition of store-managed vs owner-controlled vs registry-controlled fields |
| 5 | Cross-platform merchant identity | **GAP** | no platform identity at all |
| 6 | Domain alias without DNS access | **GAP** | activation is DNS-TXT or email-link; the card host leaves domain ownership unverified |
| 7 | Multi-store conflicts | **PART** | `index/attestation_gate.py` TOFU-pins the first valid DID and rejects re-registration under another key — takeover *defense*, not a policy for two legitimate stores |
| 8 | Migration / portability | **PART** | `server/member_rotation.py` rotates keys (old-key-signed attestation, nonce, clock skew, audit row). Moving between stores, hosts, or registries: nothing |
| 9 | Recovery / reassignment | **PART** | BIP39 recovery phrase at signup = self-custody only. Reassigned address, closed business, compromised provider: nothing |
| 10 | Fast revocation vs caching | **PART** | attestations carry `issued_at`/`expires_at` with clock-skew checks. No revocation endpoint, no cache invalidation on uninstall |
| 11 | Privacy-preserving exact lookup | **PART** | the enumeration closure closed the bulk hole: `GET /api/members` now requires a signed member, an operator token, or a signature-verified federation peer, and the `/api/federation/{peer}/members` proxy is gated with it. Exact lookup — "does THIS subject have an agent?" — is served openly by `GET /api/agents/{agent_id}/profile`. Still missing the *privacy-preserving* half: the lookup is a plaintext id against a surface that answers 200/404, so it confirms membership to anyone who can guess an id (no OPRF / blinded lookup, no per-caller scoping) |
| 12 | Scoped / contextual discoverability | **GAP** | no visibility policy on bindings |
| 13 | Precedence among authority sources | **PART** | `sm-divergence` / `sm-resolver` *detect* cross-registry disagreement (tamper-drilled). They do not rank sources or resist downgrade |
| 14 | Transparency / audit / dispute | **PART** | strongest partial: signed chained audit events at every consent decision including refusals, and offline-verifiable receipts. Missing: append-only *binding*-change log, signed update receipts, dispute procedure |
| 15 | Separation of binding, discovery, and commerce authorization | **BUILT** | already the architecture. The self-registration removal removed self-registration; resolution locates, `consent_gate` and `authority.py` authorize separately |

## 4. The lopsided half

Splitting the problem in two — *binding* (subject identity → authorized terminal
object) and *federation* (discovery system ↔ discovery system) — the maturity is
inverted relative to where the work is needed.

| Binding | Federation |
|---|---|
| GAP delegated provisioning | BUILT S2S Ed25519 signed broadcast inbox, enforcing on the live mesh |
| GAP authority-evidence format | BUILT federation allowlist + peer TOFU |
| GAP field scopes / templates | BUILT cross-registry divergence detection, tamper-drilled |
| GAP identity-provider attestation | BUILT directory hop / multi-hop resolution |
| PART revocation, precedence, migration, recovery | |
| BUILT self-certifying records, TOFU DID pinning | |

The mature column is the one a binding-provisioning protocol explicitly excludes.
The column it needs is the thin one.

## 5. Reuse rather than reinvent

Five pieces already here are close to what such a protocol needs — the first is
the most important, because it means the grant object should be *extended*, not
invented:

- **`sm-dat` — the delegated-authority grant.** A public, signed, portable grant
  recording what an agent may do, for how long, under what limits. Its 34
  conformance vectors ship in `agent/tests/vectors/sm_dat/0.1/` (amount caps,
  counterparty allowlists, jurisdiction, category scope, expiry, not-yet-valid,
  subdelegation narrowing, widening breach, multigrant) with a wire-anchor test.
  Everything a binding grant needs structurally — subject, delegate, scoped
  actions, expiry, subdelegation that can only narrow — is already specified and
  tested. What is missing is a *binding-provisioning profile* of it: target-host
  constraints, allowed agent roles, lifecycle actions (create / update-target /
  suspend / revoke), and a registry that accepts one. No orrery code constructs
  or enforces a DAT today; the vectors are anchored, not consumed.

- **`server/registry_attestation.py`** — the org signs
  `{agent_id, did, endpoint, issued_at, expires_at}` with RFC 8785 (JCS)
  canonicalization and Ed25519. Because a `did:key` *is* the public key, a
  consumer verifies entirely offline, with no fetch to a possibly hostile
  endpoint. This is close to the shape of a binding-update grant: add
  subject, delegate, and allowed actions and it becomes one.
- **`index/attestation_gate.py`** — the first valid attestation TOFU-pins the
  record's DID; every later write must be signed by the pinned DID or is
  rejected. A verdict-parity test keeps it agreeing with the server verifier.
  This is the natural enforcement point for a scoped grant.
- **`server/member_rotation.py`** — old-key-signed rotation attestation with
  nonce and clock-skew checks plus an audit row. The migration primitive.
- **`server/consent_gate.py`** + signed chained audit events — a consent receipt
  is largely already emitted, including on refusal.

And on the provisioning leg specifically, the handshake spec's conclusion is
that this repo needs no new work: `/provision` already returns exactly what a
registrar needs.

## 6. Notes for anyone extending this

- There is **no commerce-platform integration** in this tree. A grep can suggest
  otherwise: "toast" appears in several files as UI toast notifications, and one
  storefront vendor is named once in a doc as a future example.
- **`server/chapter_auth.py` is not OIDC support.** It stores an issuer URL and
  client id and offers a provider catalog. No token is ever verified. It says so
  in its own module docstring.
- The nearest existing work is
  [`docs/integrations/SMB_NANDA_HANDSHAKE.md`](../integrations/SMB_NANDA_HANDSHAKE.md),
  which names the same hole from the registrar's side: the card host needs an
  index client and a credential to call the index with, and the index needs a
  service account, host-vouched activation, and bulk registration. It is
  code-traced rather than aspirational, and is the better starting point for a
  concrete design.
- Of the problems above, **That change is the only one this repository can close alone**
, along with parts of that change and that change. The rest require the card host and
  the index to move.
