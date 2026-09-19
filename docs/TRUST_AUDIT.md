# Trust / reputation scoring-path reality audit

The flagship differentiator, driven end-to-end against a hermetic stack with
real Ed25519 signing: ARP receipt ingestion → corroboration/cosign verification
→ trust-event delta application → reputation compute under **nanda-rep/0.1**
(self-attested) and **nanda-rep/0.2** (corroborated-only). Each claim is PROVEN
by a test or a filed+fixed issue. (Agent-side ARP *generation* is audited
separately; this is the server-side scoring path only.)

Audit run: main @ `eb023b6`. Adversarial hunt: double-count, replay,
self-corroboration, cross-principal injection, negative underflow, monotonicity.

## Claims → evidence

| Claim | Verdict | Evidence |
|---|---|---|
| Trust-event delta **values are server-set + immutable** (CLAUDE.md "what never changes silently") | PROVEN | `EVENT_DELTAS` is the only authority; `record()` reads it and has **no `delta` parameter** — a client can't inject one. `test_trust_scoring_integrity::test_trust_event_deltas_are_the_frozen_values` pins the exact table; `test_record_ignores_any_client_supplied_delta` |
| No self-promotion (`source_agent_id == agent_id` rejected) + rolling-window caps | PROVEN | `record()` raises on self-source; caps on positive deltas (`test_trust_accrual`) |
| **An un-corroborated receipt cannot inflate a nanda-rep/0.2 score** | PROVEN | live: a self-attested receipt leaves `corroboration_rate` / 0.2 score at 0; the e2e reputation probe (`test/323`) is the standing guard; the sm-arp lib rejects self-corroboration (`_counterparty` requires a *distinct* verifying counterparty) |
| ledger validity is chain-aware (a receipt after an agent's first still counts) | PROVEN | `test_vrp_chain_validity` (fix) |
| **Replay of a `receipt_id` is idempotent, not double-counted** | **FIXED — That change** | replay returned **503** (looked like an outage), no 409 path — a duplicate was conflated with a real persistence failure. Now `arp.emit` detects the `(issuer_did, receipt_id)` duplicate pre-insert → distinct `duplicate` stage → endpoint **409 `{idempotent}`**. `test_trust_scoring_integrity` + updated `test_arp::test_R2_*`; verified live (200 → 409) |
| **A member cannot write into another principal's ledger** | **FIXED — That change** | `POST /api/receipts` called `arp.emit` WITHOUT the existing `require_principal_match` guard, so a member could submit an X-signed receipt with `principal_did=Y` and inflate **Y's** nanda-rep/0.1 (default) score. Now the endpoint enforces `principal_did == issuer_did` (org-issued authority grants are internal, unaffected). `test_trust_scoring_integrity` (arp-level + endpoint-wiring); verified live (200 → 400, victim ledger untouched); 0.2 was already safe (attacker can't forge the counterparty cosign) |
| the score served on `/agentfacts` matches the receipts actually ingested | PROVEN | live: `receipt_count` / `reputation_score` under 0.1 and 0.2 track the stored receipts (onboarding grant + real interactions); cross-checked against the Postgres `arp_receipts` rows |
| negative deltas / underflow — score floor | PROVEN (by-design) | `tier_for` floors at 0; `TRUST_TIERS` start at 0.0; negative event deltas (`revocation_received` −1, `complaint_validated` −3, `inactive_decay` −1) are bounded by the frozen table, never client-set |

## Guards added

- `test_trust_scoring_integrity` — the cross-principal guard (arp + endpoint
  wiring), the replay→409 contract, the frozen-delta-value pin, and the
  no-client-delta invariant.
- `test_arp::test_R2_*` updated to the clean `duplicate` contract.

Nothing here changes a frozen wire id or a trust-delta value.
