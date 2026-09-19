# Release sign-off — the v0.2.0 security audits (historical record)

> This is the disposition record as it stood at `v0.2.0`. The current status of
> every finding is the ledger, `findings.json` beside this file, and the open and
> residual set is enumerated by id in [`../THREAT_MODEL.md`](../THREAT_MODEL.md).
> This page is kept as the record of what was found and decided then.

The per-finding disposition record for every security finding raised against
Orrery across its two audits, published as the "release mechanics" gate from
[`HARDENING.md`](../HARDENING.md). This is the document that says *what was
found, what happened to it, and what is knowingly still open*.

> **Why this reads as prose rather than as a list of ticket links.** Both audits
> ran while Orrery was developed privately, and every finding here was once a
> row pointing at an issue and a pull request in a repository no reader can
> open. Those pointers are gone. Keeping them would have been worse than
> dropping them: in a public repository with its own numbering, a bare issue
> number resolves to an unrelated issue or to nothing, and a wrong pointer reads
> as evidence.
>
> **Nothing was softened in the move.** Every finding, severity and residual
> below is the one that was recorded, including the ones still open. What each
> disposition now names is the thing a reader can actually check — the guard, the
> test, or the behaviour in this repository — instead of a ticket they cannot
> read. Audit 2's own identifiers (`C1`, `G1`, `F3`, `R3` …) are kept exactly as
> they were, because they are internal to the audit and are used throughout
> [`HARDENING.md`](../HARDENING.md).

**Verdict: cleared for a public, versioned release.** Both CRITICALs and every
HIGH are fixed with regression tests that fail on the pre-fix code; the P0 class
was additionally verified by independent exploit-replay. The release-tag blocker
(R3, supply-chain pinning) landed before the tag. Everything still open is either
a quality gate (coverage, mypy breadth) or a documented residual enumerated in
[Open dispositions](#open-dispositions) — none is a release blocker under the
`HARDENING.md` sequencing rule.

Disposition legend: **fixed** · **documented residual** · **tracked follow-up**.

## Audit 1 — release-readiness audit (June 2026)

26 findings. **All 26 fixed.** The P0 trio — account takeover, consent/PII
bypass, and the receipt leak, all rooted in the same identity-propagation defect
— was verified closed by independent exploit-replay against the fixed code
(positive control first; both the JSON and SSE surfaces for the receipt leak).

| Sev | Finding (abridged) | Disposition |
|---|---|---|
| P0 | Account takeover via unauthenticated key re-registration | Fixed; exploit-replay verified |
| P0 | Consent/PII bypass — `intents respond` trusted the body's responder | Fixed; exploit-replay verified |
| P0 | Private ARP receipt leak via an open surface prefix | Fixed; exploit-replay verified (JSON + SSE) |
| P0 | Root cause: verified identity never propagated to `request.state.agent_id` | Fixed |
| P0 | No cross-subsystem e2e — CI never booted docker compose | Fixed; the e2e job now runs on every PR |
| P0 | Build provenance broken (`/version` reported "unknown") | Fixed |
| P1 | CI lint + type gate covered `agent/` only | Fixed; the gate now covers all subsystems (see `.github/workflows/ci.yml`) |
| P1 | ~170 routes, ~20 auth-tested | Fixed; superseded by the I2 default-deny sweep |
| P1 | Retention sweep silently dead | Fixed |
| P1 | Meaningless `did:key` minted without PyNaCl | Fixed |
| P1 | Forgeable federation broadcast inbox | Fixed |
| P1 | PostgREST injection under the service-role key | Fixed, plus a repo-wide guard test |
| P1 | Cosign-broker SSRF | Fixed; DNS-rebinding hardening followed in F3 |
| P2 | README overstated a fresh install (`conformance.json` 404) | Fixed |
| P2 | Conformance badge not suite-enforced | Fixed |
| P2 | Broken quick start for outsiders | Fixed |
| P2 | `0.0.0` versions, no CHANGELOG, dead build artifacts | Fixed |
| P2 | Auth disabled by default | Fixed |
| P2 | Member persist fire-and-forget, silent divergence | Fixed |
| P2 | Untrusted text → LLM → auto-rebroadcast (prompt injection) | Fixed; the consent-gate provenance reject is the enforced defence, re-asserted at execution time by G1 |
| P2 | OpenClaw version gate was honour-system | Fixed |
| P2 | the "chapter"→org rename incomplete on operator surfaces | Fixed |
| P2 | `channels.test()` reported a fake success | Fixed |
| P2 | `/sm-bridge/resolve` could not resolve its own `did:key` | Fixed |
| P2 | Surface inconsistencies + correctness nits | Fixed across the P2 sweep |
| P2 | `conformance/` + `schema/` ungated; skill metadata-only | Fixed; the `conformance` CI job is the gate |

## Audit 2 — hardening audit

The full audit narrative is [`docs/HARDENING.md`](../HARDENING.md), and the
identifiers below are the ones it uses.

### Phase 0 — launch blockers

| ID | Sev | Disposition |
|---|---|---|
| C1 | CRITICAL | **Fixed** — HMAC-TOFU can no longer return `True` without cryptographic verification; TOFU is Ed25519 + `did:key` only |
| G1 | CRITICAL | **Fixed** — `provenance == "untrusted"` routes to the gate before any prior approval can authorise; a regression test proves the runner is never called |
| I1 + C2 | HIGH | **Fixed** — unauthenticated leak closed, `/export` ownership-checked; the authed-IDOR residual is documented below |
| F1 | HIGH | **Fixed** — both federation signature-enforcement flags default ON in every deploy artifact |
| S1 | HIGH | **Fixed** — org signing key sealed at rest (AES-256-GCM via `ORRERY_KEY_SECRET`), `0600` file, legacy rows still readable |

### Phase 1 — MEDIUM/LOW hardening

| ID | Disposition |
|---|---|
| G2 | **Fixed** — one-shot approvals are consumed by the executor, not only on the HTTP path |
| G3 | **Fixed** — a signed head-checkpoint detects consent-ledger tail-truncation (residual documented in `HARDENING.md`) |
| G4 | **Fixed** — the ledger never downgrades signed → unsigned |
| C3 / C5 / C6 | **Fixed** — caller derived only from the verified `request.state.agent_id` |
| C4 | **Fixed** — mutations require a method-bound `ed25519+nonce`; the latent middleware fail-open is closed. Residual: v0.2 reads still accept the nonce-less scheme (a replayed GET is non-escalating) — documented |
| I2 | **Fixed** — a data-driven default-deny sweep over every confirmed-private GET route |
| F2 | **Partially fixed** (DoS caps + optional write token); the attestation gate is a **tracked follow-up** |
| F3 | **Fixed** — the cosign relay pins the resolved IP (DNS rebinding closed) while retaining hostname TLS verification |
| F4 | **Fixed** — divergence sweep parallelised and budgeted; per-id errors surface as `unconfirmed` |
| F5 | **Fixed** — `pinned_did_for` fails closed on pin-lookup errors |
| S2 | **Fixed (documentation)** — a false "AES-256-GCM" claim corrected; cost and wire format pinned by test. The cipher/KDF migration is a **tracked follow-up** |

### Phase 2 — release readiness

| ID | Disposition |
|---|---|
| R3 | **Fixed** — every `sm-*` dependency exactly pinned (PyPI version or full-SHA git ref); constraints files wired into CI and both Docker images; the `supply-chain-pins` CI guard fails on any unpinned ref reappearing. *This was the release-tag blocker.* |
| R4 + R6 | **Fixed** — the malformed-DID fallback is removed (the builder raises, with a lenient logged variant for maybe-Ed25519 call sites); every silent `except` in the auth/crypto deny paths logs its reason before the unchanged deny |
| R7 | **Fixed** — `ORRERY_PROFILE=prod` closes the CORS wildcard and stops serving `/docs`, `/redoc` and `/openapi.json` |
| R5 | **Fixed** — `docs/HARDENING.md` and `docs/integrations/STELLARMINDS.md` are tracked in-repo |
| R1 | **Open — tracked follow-up**: coverage measurement plus an enforced floor on the auth/crypto modules |
| R2 | **Open — tracked follow-up**: mypy breadth beyond the three agent files |
| Release mechanics | **This document, and the release tag** |

## Open dispositions

Explicitly open at the audited release — accepted, documented, and owned:

- **F6 (LOW/INFO) — TOFU identity pre-seeding ceiling.** A first-writer in the
  open index can pin their own DID as an unanchored victim's identity. This is
  the documented trust ceiling of TOFU; known peers are anchored out-of-band via
  `KNOWN_CHAPTER_ENDPOINTS`. Documented residual.
- **S3 (LOW) — recomputable headless keystore passphrase; demo secrets in
  `.env.example`.** Both documented; any real deployment must regenerate them
  (see `docs/INSTALL.md` § Going to production). Documented residual.
- **C4 residual** — v0.2 reads still accept the nonce-less scheme; a replayed GET
  is non-escalating. Documented residual (nonce-on-reads is the follow-up).
- **I1 residual** — authenticated-member `target`-scoping on heterogeneous
  surfaces needs a maintainer visibility decision (per-caller scoping vs
  per-builder filtering vs classification of the uncertain surfaces). Documented
  residual, downgraded from HIGH-unauthenticated to MEDIUM-authenticated.
- **G3 residual** — checkpoint cadence is documented in `HARDENING.md`.
- **Tracked follow-ups**: the R1 coverage floor, the R2 mypy breadth, the F2
  lean-index attestation gate, and the S2 key-vault versioned-blob migration.
- **`provider.did` legacy format** — RESOLVED after the audited tag. Writes now
  emit the proper W3C `did:key` derivation (non-Ed25519 material gets no DID),
  every reader accepts both formats for the life of `0.x`, and existing rows
  converge on their next facts write. At the tag itself this was still open, and
  it is left here rather than deleted so the record shows what was outstanding
  when the sign-off was made.

## How this was verified

- Every fix above ships with a regression test asserted to fail on the pre-fix
  code (per the `HARDENING.md` definition of done).
- The P0/CRITICAL class was re-verified by independent exploit-replay against the
  fixed code, not by trusting the fixing change's own tests.
- CI at tag time: all seven jobs green (`supply-chain-pins`, `server`, `agent`,
  `skill`, `index`, `conformance`, and the docker-compose `e2e`), including the
  route default-deny sweep (I2) and the supply-chain pin guard (R3).
