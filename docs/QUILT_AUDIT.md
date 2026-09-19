# Quilt / cross-org resolution + delta-sync reality audit

Every claim on the **multi-org discovery / resolution / delta-sync** path,
driven end-to-end against a hermetic 2-org `docker compose` stack with real
Ed25519 signing — no mocks. (Divergence-detection is audited separately;
this table is the discovery/resolution/quilt path only.)

Audit run: main @ `123b499`. Method: register members, walk the full
quilt chain, restart, and check convergence + cursor behavior + partial-failure
handling.

## Claims → evidence

| Claim | Verdict | Evidence |
|---|---|---|
| `GET /sm-bridge/index` lists the org's members (register-once, pointer-fetch) | PROVEN | live: index reflects every registered member; e2e registry-integrity probe |
| `GET /sm-bridge/resolve?agent=<id>` resolves by member id | PROVEN | live 200; e2e quilt probe |
| resolve by **did** (`did:web:host:agents:<id>`) round-trips | PROVEN | live 200 — the index-advertised id resolves |
| resolve by **agent_name** / handle | PROVEN | live 200 |
| resolve **unknown** → 404 (not a fake record) | PROVEN | live 404 |
| cross-org member hop: org1 federation → org2 `/index` → `/resolve` | PROVEN | e2e quilt probe (`test/323` suite) |
| `GET /sm-bridge/deltas?since=<cursor>` — exclusive cursor, monotonic feed | PROVEN | live: `since=2` → `[3,4]`; registration appends `upsert`, removal `delete` (`test_quilt_delta_wiring`) |
| deltas cursor-gap (`since` past `next_seq`) → empty, no error | PROVEN | live 200, empty |
| **deltas survive a restart — a delta-only consumer converges** | **FIXED — That change** | in-memory store reset to empty on restart while `/index` kept members → consumer never converged; `next_seq` regressed 5→1 → post-restart registrations silently skipped past a stale cursor. Now seeded from persisted membership above a monotonic (wall-clock-ms) base. `test_quilt_delta_convergence` (convergence + monotonicity + stale-cursor + skew clamp); e2e `quilt-restart` probe; verified live across two restarts |
| partial failure: peer down | PROVEN (by-design) | resolve on a dead org = connection refused; the caller handles it (federation discovery health-probes + backs off) — no server-side hang |

## Documented ceiling (not a bug)

The `DeltaStore` prunes to `max_deltas` (10 000). An org with >10 000 members
would prune the oldest seeds, so a `since=0` consumer wouldn't see the pruned
members from the feed alone and must fall back to `/index` for a full snapshot.
Far beyond current scale (~300 members across the live mesh); noted for the
persisted-deltas follow-up.

## Guard added

- `test_quilt_delta_convergence` — the restart invariants (a delta-only
  consumer converges; `next_seq` never regresses; a post-restart registration
  lands above a stale cursor; seeding is a no-op without a mount and can't
  rewind a live counter).
- `scripts/e2e_probes.py --only quilt-restart` — registers, restarts the org
  container, and asserts the delta feed still reflects the membership on a real
  stack.

Nothing here changes a frozen wire id.
