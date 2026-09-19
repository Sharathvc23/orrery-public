# StellarMinds integration architecture

The canonical plan for how Orrery consumes the `sm-*` trust stack
(github.com/Sharathvc23). Several modules cite this document as their
architecture rule — `server/aae_export.py`, `server/sm_bridge_adapter.py`,
`server/compliance.py`, and `server/requirements.txt`. This file is the source
of truth for what we integrate, how, and why; when an integration decision is
made, it is recorded here before code lands.

## The one rule: upstream is upstream

**The `sm-*` libraries are UPSTREAM. Orrery is DOWNSTREAM. We never modify an
`sm-*` library to teach it about Orrery.** Every integration is a thin
downstream adapter that speaks the library's published surface. This keeps the
primitives reusable by anyone, keeps our fork surface at zero, and means an
`sm-*` upgrade is a version bump, not a merge.

Concretely, the downstream adapter pattern is:

- `sm-bridge` is upstream; `server/sm_bridge_adapter.py` inherits its
  `AbstractAgentConverter` and implements `to_sm` / `list_agents` / `get_agent`
  against Orrery's in-memory `members` — the library is untouched.
- `sm-locp` is upstream; `server/compliance.py` passes Orrery's identity +
  attestation payload in and stores the signed VC the library returns.
- `sm-attest-viewer` is upstream; `server/aae_export.py` produces AAE-shaped
  JSON the viewer already understands, rather than teaching the viewer about
  ARP.

If a change *seems* to require editing an `sm-*` library, that is a signal to
either (a) push the change to the library as a first-class feature via its own
repo, or (b) keep it in the adapter. Never vendor-and-patch.

## Dependency direction (never invert)

Orrery depends on `sm-*`; **no `sm-*` library may depend on Orrery.** The arrow
points one way. This is what lets the primitives be published, reused, and
independently versioned. Any future `sm-*` feature Orrery wants is requested
upstream, not reached back for.

## What is integrated today

| Package | Status | How Orrery uses it | Adapter / seam |
|---|---|---|---|
| **sm-arp** (`sm_arp.vrp`) | **Live, heavy** | Reputation core: counterparty corroboration, collusion severance, `nanda-rep` scoring, facts attestation | `server/vrp.py`, `agent/community_member/ledger.py`, `cosign.py` |
| **sm-arp** (verifier) | **Live, vendored** | Offline receipt verification with no runtime drift | Byte-mirror `_arp_verify/` in both `server/` and `agent/community_member/`; drift-guarded by `tests/test_vrp_lockstep.py` |
| **sm-conformance** | **Live** | Signed conformance badge; `derive_did_key` | `agent/community_member/conformance_badge.py`, `crypto.py` (byte-identical local fallback) |
| **sm-bridge** | **Live** | NANDA AgentFacts converter + registry router (`/sm-bridge/{index,resolve}`) | `server/sm_bridge_adapter.py`, `agent/community_member/sm_bridge_adapter.py` |
| **sm-parc** | **Live** | Portable reputation credential at `/.well-known/reputation.json` (W3C VC); selective disclosure — reveal k receipts, each with a Merkle inclusion proof against the credential's `behavioral_merkle_root` (`inclusion_proof` / `verify_inclusion`, offline verify) | `agent/community_member/reputation_credential.py`, `agent/community_member/receipt_disclosure.py` |
| **sm-divergence** (+ `sm-resolver` kernel) | **Live** | Cross-registry divergence detection: per-id fetch classification (`fetch_view`) + pure corroboration diff (`diff_claims`); Orrery keeps budgets, `unconfirmed` synthesis, attestation verify, event emission | `server/registry_divergence.py` |
| **sm-aae** | **Live** | Signed, per-agent-chained pre-action authorization envelopes at the consent gate (allow AND refuse); envelope → viewer `decision`-event export | `agent/community_member/consent/aae_emit.py`, `aae_export.py` (agent + server) |
| **sm-locp** | **Declared, not wired** | *Future:* emit compliance VCs alongside ARP receipts for regulated actions | `server/compliance.py` (adapter written; no call site yet) |

## Vendoring policy

Two `sm-arp` surfaces, two treatments — deliberately:

- **The verifier is vendored** (`_arp_verify/`, a byte-for-byte mirror with its
  schema bundle). Verification is on the trust-critical path and must not drift
  or acquire a runtime dependency; the vendored copy ships with the app and is
  locked to the canonical source by `tests/test_vrp_lockstep.py`.
- **The reputation core is NOT vendored** (`sm_arp.vrp`, the published mirror).
  It evolves faster and is not on the offline-verification path; `conformance/vrp/`
  stays canonical and the lockstep test catches drift.

Rule: vendor a surface only when it is trust-critical *and* must be
drift-free offline. Everything else is a normal dependency. A vendored surface
always ships with a drift-guard test naming its canonical source.

## Version pinning policy — ENFORCED (R3)

Every `sm-*` dependency is pinned exactly. No dependency anywhere in the repo
may reference a moving branch; the CI job `supply-chain-pins` fails the build
if a git URL without a full 40-hex commit SHA reappears, if a constraints file
loses its exact (`==`) pins, or if `server/requirements.txt` drifts from
`server/constraints.txt`.

### Where the pins live

| Package | Server pin | Agent pin | Source |
|---|---|---|---|
| `sm-arp` | `==0.3.2` | `==0.3.2` | PyPI |
| `sm-bridge` | `==0.6.0` | `==0.6.0` | PyPI |
| `sm-authority` | — | `==0.2.0` | PyPI |
| `sm-conformance` | `==0.3.2` | `==0.3.2` | PyPI |
| `sm-parc` | — | `==0.2.3` | PyPI |
| `sm-divergence` | `==0.8.0` | — | PyPI |
| `sm-resolver` | `==0.2.0` | — | PyPI |
| `sm-aae` | `==0.1.0` | `==0.1.0` | PyPI |
| `sm-locp` | `==0.2.1` | — | PyPI |

- `server/requirements.txt` + `server/constraints.txt` — the server install
  (CI and `infra/Dockerfile.server` both pass `-c constraints.txt`).
- `agent/pyproject.toml` (floors) + `agent/constraints.txt` (exact) — the agent
  install (CI and `agent/infra/Dockerfile.agent` both pass `-c constraints.txt`).

**The server/agent `sm-arp` split is CLOSED** (2026-07-08): sm-parc 0.2.3
lifted its `sm-arp<0.3` cap (0.3.0's DAT bridge is opt-in and verified
compatible — sm-parc's full suite passes on both), so both sides now pin
`sm-arp==0.3.2`. The unification is not incidental: sm-parc 0.2.3 declares
`sm-arp<0.4,>=0.2.3`, so 0.3.2 is admitted on both sides (checked against the
published metadata, not assumed) and the two must be bumped together or the
"unified" claim above stops being true.

### PyPI status

Every pinned `sm-*` package is now published and consumed from PyPI.
`sm-locp` was the last holdout — published as 0.2.1 on 2026-07-08, retiring
its interim full-SHA git pin. Its integration status is unchanged: adapter
written (`server/compliance.py`), no live call site yet.

### Bumping a pin

1. Pick the target upstream release (a PyPI version; if a package must ever be
   consumed from git again, a full commit SHA — never a branch or tag name).
2. Update **both** the constraints file(s) and the matching requirement:
   `server/requirements.txt` + `server/constraints.txt` for the server,
   `agent/constraints.txt` (and the `pyproject.toml` floor if the minimum
   moved) for the agent. Keep `server/requirements.txt` and
   `server/constraints.txt` byte-consistent — CI checks this.
3. State the upstream behavior change in the PR body (upstream changelog link
   or commit range).
4. CI must be green — including `supply-chain-pins`, both test suites, and the
   e2e job, which rebuilds the server image with the new pins.
5. Squash-merge, then redeploy (see **Deploying to Railway** below); verify `/health` provenance.

## Deploying to Railway (and the `/health git_commit` stamp)

The mesh deploys with `railway up`, which uploads the **local working tree
without `.git`** and does **not** populate Railway's `RAILWAY_GIT_COMMIT_SHA`
(that variable is only set for github-connected deploys). So a build-time
`git rev-parse` sees nothing and `/health git_commit` would fall back to a stale
value — which is exactly how the live mesh once reported an old commit while
serving much newer surfaces.

**Every `railway up` deploy MUST inject the deployed commit** as a deploy-time
env var. The server reads `APP_GIT_COMMIT` at the top of its build-info
resolution (`_resolve_build_info`), above every stale-prone baked layer, and
falls back to a local `git rev-parse` only for a dev checkout, then to an honest
`"unknown"` — never a stale hardcoded SHA.

Use the helper (it stamps then uploads in one step):

```bash
# from a clean checkout at the commit you intend to deploy:
scripts/railway_deploy.sh <projectId> <service> [environment]
```

> The live demo mesh's concrete project id + service names are operator
> control-plane detail — see the gitignored `infra/railway-deploy.md`.

Or manually:

```bash
railway variables --set "APP_GIT_COMMIT=$(git rev-parse HEAD)" --skip-deploys \
  -s <service> -p <projectId> -e production
railway up -s <service> -p <projectId> -e production --ci
```

Then verify the stamp is live and current:

```bash
curl -s https://<public-url>/health | jq -r .git_commit   # must == git rev-parse HEAD
```

If `/health git_commit` reads `unknown` after a deploy, the stamp step was
skipped — re-run with `APP_GIT_COMMIT` set. It will **never** silently report a
stale commit.

## Reinvented primitives — keep vs. consolidate

Orrery independently grew working equivalents of two `sm-*` primitives *before*
those libraries were available. Both work; neither is a mechanical swap. The
decisions:

### Cross-registry divergence — kernel-backed via `sm-divergence`

*(Supersedes the earlier "keep Orrery's, don't swap" decision.)* The condition
that decision named for revisiting has happened: the shared diff core WAS
extracted — `sm-divergence` 0.8.0 (+ its zero-dep kernel `sm-resolver` 0.2.0)
was extracted **from** `server/registry_divergence.py`, hardened independently,
and is now the reference implementation of
`draft-chandra-agent-registry-corroboration-00`. Running the pre-extraction
copy alongside it is two diverging implementations of divergence detection —
exactly the drift this stack exists to prevent.

**Decision (human directive):** `server/registry_divergence.py` becomes a
thin downstream adapter over the published kernel. The split of
responsibilities:

- **Kernel (upstream):** per-id fetch classification
  (`sm_divergence.discovery.fetch_view` — present / positively-absent /
  error-is-no-claim, shared soft-404 handling) and the pure diff
  (`sm_resolver.diff_claims` — omission + per-field divergence).
- **Orrery (adapter):** the tamper-vs-corroboration split (DID extraction via
  `registry_attestation.verify` rides in as a `RecordAdapter` closure — the
  kernel never learns Orrery's attestation format), the F4 sweep wiring
  (concurrent fetches + total budget inside the heartbeat), the F4
  `unconfirmed` synthesis (per-id error on a registry while a sibling serves
  the id ⇒ `unconfirmed`, not silence — the kernel's diff excludes error
  claims, so this stays downstream), Orrery's finding dict shapes / event
  payloads (byte-compatible: the adapter keeps its own `comparable()` view with
  Orrery's endpoint handling rather than the kernel's RFC 3986
  `RecordView` normalization), the once-per-process emission dedup, and
  `event_bus` alarm emission.

Pinned exact per R3: `sm-divergence==0.8.0`, `sm-resolver==0.2.0` (PyPI, server
only). Regression bar: the pre-swap divergence + F4/F5 tests pass unmodified.

### Merkle inclusion proofs — KEEP BOTH trees; `_merkle/` does NOT defer to sm-parc

Orrery's `agent/community_member/_merkle/` (used by `checkpoint.py`) and
sm-parc's `disclosure` module both do Merkle inclusion proofs — over
**different commitments, in different trust directions**:

- `_merkle/` is the **RFC 6962** tree (domain-separated `0x00`/`0x01` leaf/node
  hashes, odd node *promoted*) over the **org's Issuer Log**, verified
  against the *org's* signed checkpoint. Direction: the member audits the
  org for silent omission of the member's own receipt.
- sm-parc's disclosure walks the **VRP `behavioral_merkle_root`** tree (plain
  `SHA-256(left‖right)`, leaves sorted by `issued_at`/`receipt_id`, odd node
  *duplicated*) over the **agent's own Agency Log**, verified against the
  *agent's* signed PARC. Direction: the agent proves selected receipts to a
  third-party verifier.

**Decision:** keep both. Same proof *shape*, different tree
constructions and different roots — a shared implementation would have to
carry both hash rules behind a flag, inviting exactly the cross-tree confusion
the domain separation exists to prevent. `_merkle/` stays the vendored RFC 6962
checkpoint verifier; receipt disclosure uses sm-parc's published surface. The
two are never interchanged (each module's docstring says so).

### DAT verifier — stays vendored from `conformance/dat`; anchored to `sm-dat` at the WIRE

`sm-dat` (github.com/Sharathvc23/sm-dat, commit `be782a85…`; not yet on PyPI)
is the standalone Delegated Authority Token library. Investigation for that change
established it is **not** a byte-level extraction of Orrery's verifier — it is
a redesigned superset: three-valued verdicts (SATISFIED / VIOLATED /
INDETERMINATE), stateful `LedgerContext` period caps, predicate hooks,
revocation-freshness semantics, `delegation` objects, initial-bind grants. A
byte-for-byte lockstep of `_dat/` against it is therefore impossible-by-design;
the byte anchor of the vendored copy remains `conformance/dat`
(`tests/test_dat_lockstep.py`, unchanged).

What the two implementations DO share is the wire: the same `dat/0.1` envelope
family, the same signing path (Ed25519 over JCS body-sans-`signature`,
did:key), and the same stateless-constraint vocabulary
(`amount_cents_per_action_max`, `amount_currency`, `counterparty_allowlist`,
`jurisdictions`). **The anchor is there:** sm-dat's canonical test vectors are
mirrored at `agent/tests/vectors/sm_dat/0.1/` (sha256-manifest-pinned, upstream
commit recorded) and `tests/test_dat_smdat_wire_anchor.py` cross-verifies
Orrery's vendored verifier against them — full signature-layer agreement (every
intact grant verifies, every broken one is rejected), plus validity-window,
leaf-category-scope, and shared-constraint agreement. Every vector is either
asserted or explicitly listed as out-of-surface with the reason (sm-dat-only
semantics), so an upstream vector change forces a triage here.

**Non-verifier surface (grant construction, stores, chain helpers): NOT
consumed.** Two hard blockers, both to be revisited together:

1. **Dependency conflict — CLEARED (2026-07-08):** sm-parc 0.2.3 lifted its
   `sm-arp<0.3` cap and the agent now pins `sm-arp==0.3.2`, so sm-dat is
   co-installable in the agent environment. (This line read `0.3.0` while the
   pin was already `0.3.1` — a stale figure, corrected here.)
2. **Wire delta — still binding** — sm-dat's grant body differs in layout
   (`scope.{stateless,stateful,predicate}` + `delegation` object + signed
   nulls, vs Orrery's `scope.constraints` + top-level `granted_by`). Swapping
   construction changes every emitted DAT body: that is a spec migration
   (dat/0.2), not a dependency bump. One known semantic divergence is also
   recorded in the anchor test: Orrery's counterparty allowlist binds by
   `counterparty_did`; sm-dat's also binds by label.

The wire delta is now the ONE remaining blocker: adopt via a spec bump
(dat/0.2), R3-pinned — PyPI publication is not a gate (standing supply-chain
decision, 2026-07-08: full-SHA GitHub pins are the accepted form, as
`sm-locp`'s was before its 0.2.1 PyPI release). No new runtime dependency
today — the mirrored vectors are the pinned artifact.

### Pre-action authorization — `sm-aae` live at the consent gate; server-side post-1.0

Orrery has an sm-aae-shaped mechanism *already* at the agent layer: the consent
gate (`agent/community_member/consent/gate.py` + `ledger.py`) is a pre-action,
Ed25519-signed, hash-chained (`prev_sha256` + `verify_chain()`) authorization
ledger with `denied` as a first-class outcome. And `aae_export.py` already
emits the AAE wire envelope — but display-only, hardcoded to `type:"action"` /
`lifecycle:"committed"`, feeding `sm-attest-viewer`.

The genuine gap is **server-side**: every server authorization (governance
approvals, admission, federation writes) is a synchronous allow/deny that
leaves either nothing or a *post-hoc* ARP receipt — never a signed, chained
*pre-action permit* a peer can independently verify.

**Decision (updated by that change, human directive):** `sm-aae` is consumed NOW at
the agent layer, as an *addition* to the consent gate — the gate itself is not
rewritten, and its hash-chained ledger remains the authoritative local record:

- **Terminology guard:** two shapes share the acronym. `sm-aae`'s *Attested
  Action Envelope* is the signed 8-field pre-action authorization record
  (`agent_id/action/policy_id/outcome/prev_hash/issued_at/sig/pubkey`);
  `sm-attest-viewer`'s *AttestationEvent* is the display wire shape
  `aae_export.py` produces. The exporter maps INTO the viewer shape; the
  envelope is what gets signed and chained.
- **The consent gate emits envelopes** (`consent/aae_emit.py`): every gate
  decision point (`record_decision`, `approve`, `deny`) issues a signed,
  per-agent-chained `sm-aae` envelope — refusals first-class
  (`reject → denied`, `prompt → conditional`, approval → `authorized`).
  Envelopes persist beside the consent ledger (`aae.db`) and cross-link to the
  ledger row via the consent event's `event_sha256` in `params`. Emission is
  configured through `ledger.init` (same signing key, same directory) and MUST
  NOT wedge the gate: an emission failure logs loudly and the gate decision
  stands — the consent ledger stays authoritative.
- **`aae_export.py` extends to the decision lifecycle** exactly as
  anticipated: both the server and agent exporters gain
  `aae_envelope_to_attestation_event` — an `sm_aae.verify_envelope`-gated
  conversion of a signed envelope into a viewer `type:"decision"` /
  `lifecycle:"signed"` event. No hand-rolled envelope shapes; the receipt →
  `type:"action"` mapping is unchanged (it is the sm-attest-viewer display
  adapter, not an sm-aae shape) and stays locked by its regression tests.
- **Server-side governance / admission / federation-write permits** remain the
  post-1.0 step; the server takes the `sm-aae` dependency now so both
  exporters stay mirrored and the envelope path is ready.

Pinned exact per R3: `sm-aae==0.1.0` (PyPI, server + agent).

## Catalog classification

The full disposition of the public `sm-*` catalog (github.com/Sharathvc23,
public repos as of 2026-07-07). Every library is **integrated**, **planned
(issue #)**, or **deliberately not** — nothing is silently unaccounted for.
Adding a new `sm-*` library means adding a row here.

| Package | Classification | Why |
|---|---|---|
| `sm-arp` | **Integrated** | Reputation core + vendored verifier — see the two-treatment split above |
| `sm-conformance` | **Integrated** | Signed conformance badge (`conformance_badge.py`) |
| `sm-bridge` | **Integrated** | AgentFacts converter + registry router (`sm_bridge_adapter.py`) |
| `sm-parc` | **Integrated** | Reputation credential + selective disclosure |
| `sm-divergence` | **Integrated** | Divergence-detection kernel behind `registry_divergence.py` |
| `sm-resolver` | **Integrated** | The zero-dep corroboration kernel `sm-divergence` composes |
| `sm-aae` | **Integrated** | Consent-gate authorization envelopes + decision-event export |
| `sm-attest-viewer` | **Integrated (one-way)** | `aae_export.py` emits its AttestationEvent shape (action + decision events); TS/React — no Python dep to pin |
| `sm-dat` | **Anchored, not consumed** | Wire-level vector cross-verification guard; verifier stays vendored — see the section for the two blockers |
| `sm-locp` | **Declared, not wired** | Compliance-VC adapter written (`server/compliance.py`); on PyPI since 0.2.1 (2026-07-08), first call site is post-1.0 |
| `sm-decision-inspector` | **Integrated (one-way)** | `decision_feed.py` serves the consent chain as the inspector's `DecisionEnvelope[]` (`/api/local/consent/decisions`): operator-verb taxonomy, `IntentProof` set from the sm-aae signature, pending prompts as `lifecycle:"proposed"`, `trace_id` linking prompt → resolution. Gestures stay on the EXISTING `/api/local/consent/{approve,deny}` (gate.approve/deny — the inspector renders, Orrery decides); M-of-N quorum out of scope (1-of-1 policy served). TS/React — no Python dep |
| `sm-attest-auditor` | **Integrated (one-way)** | `aae_audit.py` exports the agent's AAE chain as `AuditableEnvelope[]` (verify-gated, `envelope_hash`/`predecessor_hash` chain fields) + a checkpoint envelope with a plain-SHA-256-concat Merkle commitment and per-leaf inclusion proofs matching the auditor's fold; served at `/api/local/aae/audit`. TS/React — no Python dep. NOTE: the auditor labels its method "rfc6962-sha256" but folds WITHOUT the RFC 6962 domain prefixes; we emit the honest `"sha256-concat"` method id (display-only in the auditor today; mismatch flagged upstream) |
| `sm-federation` | **Deliberately not** | Orrery's federation is the Chapter Protocol's own live wire (multi-org production mesh); sm-federation is a different community-mesh protocol — adopting it is a spec-major protocol swap, not a dependency |
| `sm-enclave` | **Deliberately not** | Speculative execution with staged effects; Orrery's executor is consent-gated single-path — there is no speculative branching to stage. Revisit only if the planner grows branches |
| `sm-airlock` | **Deliberately not** | Attribute-level plugin allowlisting overlaps the consent gate + graduation + packs surface, which is provenance-aware and deeper; a second narrower permission model would blur the one boundary. Its Ed25519 plugin-manifest attestation is the one piece worth revisiting for packs |
| `sm-model-card` | **Deliberately not** | Orrery is deliberately model-agnostic (BYO key, any provider); it neither trains, serves, nor registers model artifacts. Revisit only if agents start advertising model facets in AgentFacts |
| `sm-model-provenance` | **Deliberately not** | Same rationale as `sm-model-card` (the two overlap; upstream may consolidate them) |
| `sm-model-integrity-layer` | **Deliberately not** | Same rationale — weight hashing / lineage / model policy checks presume a model registry, which Orrery is not |
| `sm-model-governance` | **Deliberately not** | Train/approve/serve plane separation governs ML deployment pipelines; Orrery has none |
| `sm-org-server` | **N/A (sibling)** | Not a dependency: a reference implementation of the Chapter Protocol itself — same family, no dependency direction either way |
| `sm-org-agent` | **N/A (sibling)** | Same — the client signing surface reference implementation |

## Adding a new integration

1. Confirm the direction: Orrery depends on the library, never the reverse.
2. Write a downstream adapter that speaks only the library's published surface.
   Do not modify the library.
3. If the surface is trust-critical and must be drift-free offline, vendor it
   with a drift-guard test; otherwise take a normal, pinned dependency.
4. Record the decision in the table above **before** the code lands.

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
