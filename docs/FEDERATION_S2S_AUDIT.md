# Federation server-to-server (S2S) security reality audit

The last high-value security surface — and historically the most bug-prone
(signed-broadcast enforcement, that change restart-replay). Drove the S2S inbound
path end-to-end against a hermetic 2-org stack with real Ed25519 signing: a
second org's real signing key signs broadcasts and POSTs them to the receiver's
`/api/federation/broadcast/inbox`, then the full adversarial matrix. Each claim
is PROVEN by a test or a filed+fixed issue. (Divergence-detection is audited
separately; this audit stayed on `federation_signing` + the broadcast inbox.)

Audit run: main @ `fd06644`, enforcement ON (the shipped default).

## Live adversarial matrix (real HTTP + real DB, enforcement on)

Every malicious case is **rejected** (403 under enforcement):

| Attack | Result | Reason |
|---|---|---|
| signature stripped | rejected | `missing_signature` |
| tampered body (sig over different bytes) | rejected | `invalid_signature` |
| stale timestamp (> 300s window) | rejected | `stale_timestamp` |
| legacy body-only (no ts/nonce) under enforcement | rejected | `missing_timestamp` |
| nonce stripped (ts kept) | rejected | `invalid_signature` (ts+nonce+body are one signed unit) |
| origin spoof (claim origin=peer, sign with our key) | rejected | `peer_key_unavailable` / key-mismatch |
| unknown origin (not a federation peer) | rejected | `unknown_origin` |
| replay of a captured signed broadcast | rejected | `duplicate` (in-memory ring + persistent store) |

## Claims → evidence

| Claim | Verdict | Evidence |
|---|---|---|
| S2S signature verified over ts+nonce+JCS(body); tamper/wrong-key/missing rejected | PROVEN | live matrix + `test_federation_signing` (roundtrip, tampered, wrong-key, missing) |
| freshness window rejects a stale/after-restart replay past 300s | PROVEN | live `stale_timestamp`; `test_replay_after_restart_rejected_by_freshness`, `test_attacker_cannot_refresh_timestamp` |
| ts/nonce bound into the signature — can't refresh a captured broadcast | PROVEN | live nonce-strip → invalid; `_signed_material` binds all three |
| warn-then-enforce gate, **default reads OFF in code** but shipped config sets it ON | PROVEN | `enforcement_enabled` default off; `.env.example` + compose default `true`; `test_enforcement_*` |
| legacy (no-timestamp) peer rejected under enforcement, accepted only in warn | PROVEN | live `missing_timestamp` under enforcement; `test_legacy_rejected_under_enforcement` |
| DID pin is authoritative + sticky — a registry-supplied key can't override it, mismatch fails closed | PROVEN | live: a stale/mismatched key → rejected (never accepted); `test_pin_defeats_registry_supplied_key`, `test_undecodable_pin_fails_closed` |
| pin-lookup DB error fails closed under enforcement (F5), not silent endpoint-trust downgrade | PROVEN | `test_inbox_rejects_broadcast_when_pin_lookup_fails_under_enforcement` |
| cross-tenant spoof: origin_chapter_id MUST equal the signing sender | PROVEN | `receive_broadcast` `origin_sender_mismatch` / `self_origin_via_federation`; live origin-spoof rejected |
| broadcast dedup survives a restart (in-memory ring is cleared) | PROVEN | persistent `federation_inbound_seen` (UNIQUE origin+broadcast_id); `test_receive_broadcast_dedupes_across_restart_via_persistent_store` |
| **the restart-replay dedup store is present + observable** | **FIXED — That change** | the persistent guard is baked into init.sql only — no boot DDL, no migration runner — so a DB predating it is missing the table and `_seen_persisted` silently fails open (replay protection degrades to the freshness window with no signal). Added `dedup_store_healthy()` + a boot probe that logs a prominent SECURITY warning under enforcement when the store is unavailable. `test_federation_dedup_health` |

## Note (fail-closed, not a bug)

A peer whose signing key changes (rotation, or a db-less peer regenerating its
key) is rejected by a receiver holding the old pin/attested-did — the pin is
sticky by design (anti-cheating-registry). Recovery is the leader
`unpin` + re-discovery TOFU path. Observed live during the drill (a rebuilt
db-less peer); the receiver correctly **rejected** the mismatched key rather
than accept it.

Nothing here changes a frozen wire id.
