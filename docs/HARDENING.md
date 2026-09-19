# Hardening plan

> **Status (v0.2.0):** this document is the audit-time snapshot and is kept as
> the record of what was found. No finding's claims are restated; only wording
> has been normalised. Its "NOT ready for public release"
> verdict is **superseded**: every Phase 0/1/2 finding has since been fixed or
> formally dispositioned — see [`audit/RELEASE_SIGNOFF_v0.2.0.md`](./audit/RELEASE_SIGNOFF_v0.2.0.md),
> which clears v0.2.0 for a public, versioned release and lists the open
> residuals.
>
> The key words MUST and MUST NOT, when in uppercase, are used in the sense of
> [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119): they mark a prohibition or
> a requirement rather than emphasis. Lowercase uses are descriptive.

Security + release-readiness hardening for Orrery, from the audit of `main`
@ `5f7f4c0` (six surfaces: federation/crypto, auth/authz, injection, secrets,
the agent consent gate, release readiness). Findings are prioritized into three
phases with a definition of done per item.

**Verdict: NOT ready for public release.** The crypto/federation *design* is
strong and several prior-audit classes are genuinely closed (X-Agent-ID header
trust, key re-registration takeover, the SQL boundary at `pg_store`, DID-pin
durability + leader-gated unpin, broadcast replay dedup). But the audit found
**2 CRITICAL** issues — a remote unauthenticated auth bypass and an agent-side
prompt-injection-defense bypass — plus **5 HIGH**, two of which are
unauthenticated PII IDORs reachable *because* of the CRITICAL. No release until
Phase 0 is fixed and re-verified.

Severity counts: **2 CRITICAL · 5 HIGH · ~14 MEDIUM · 8 LOW**.

C1 and F1 were re-verified against source directly; the remainder are from the
audit and should be re-confirmed at fix time.

## Systemic root cause — fix the pattern, not just its instances

C1, C2, C3, C5, C6, and I1 are the same defect in six places: **identity is
resolved inconsistently, and GET routes default to open.** Handlers that don't
take `Request`, routes that trust body/header-claimed `agent_id`, and a
`REQUIRE_AUTH_GET_PATHS` allowlist where a forgotten route is silently public.
Per-endpoint patches are necessary but insufficient. The structural fix:

1. **Single identity choke point.** Every per-agent/private route derives
   identity *only* from `request.state.agent_id` (the verified caller). No
   handler reads `agent_id` from a body or header.
2. **Invert the default.** Auth-required by default with an explicit *public*
   allowlist, replacing open-by-default with an auth allowlist.
3. **Route-enumeration test.** Walk every registered route and assert it is
   either in the public allowlist or requires auth *and* performs an ownership
   check. This is the durable fix for the whole IDOR family and closes the
   "found one at a time" gap the audit itself hit (I2: the default-deny test
   misses the surface alias that leaks).

## Phase 0 — Launch-blockers

No public release until all five are fixed **and** each has a regression test
that fails on the old code.

| ID | Severity | Finding | Location | Fix | Effort |
|---|---|---|---|---|---|
| **C1** | CRITICAL | HMAC-TOFU returns `True` for a novel `agent_id` without checking the signature — remote unauthenticated auth-as-anyone. Default scheme is `hmac-sha256`. | `server/auth_verify.py:666-668` | Never `return True` on a branch that didn't cryptographically verify. Require the self-authenticating Ed25519 + did:key TOFU path; HMAC identities register a secret out-of-band — no key-from-header acceptance. | S |
| **G1** | CRITICAL | Executor honors a pre-existing/forged approval via `find_valid_approval` and skips `evaluate()` — the only place the untrusted-provenance reject lives — bypassing the primary indirect-prompt-injection defense. | `agent/community_member/executor.py:316-335` | Re-run `evaluate()` (re-assert the untrusted-provenance reject) at execution time before honoring any approval; never build the approval `req` from client-supplied `provenance`. | M |

> **G1 — FIXED.** An S3 precondition now routes any `provenance == "untrusted"` proposal straight to the gate (reject + record via `evaluate`) before the graduation / trust / `find_valid_approval` paths can set an approved decision — so a prior approval for a (cap, scope, context) tuple can no longer authorize injected content. Regression test asserts the runner is never called despite a matching prior approval (fails on the pre-fix code).
| **I1 + C2** | HIGH | Surface-dispatch IDOR (`target` only scoped to caller for `page_id=="today"`; other pages leak conversations/intents/settings/security posture, GET default-unauth) and `/export` IDOR (no caller check → private DM bodies). | `server/chapter_agent.py:1671-1687, 3471-3478` | Scope `target`→verified caller for **all** per-agent surfaces; auth + ownership check on `/export`; apply the default-deny inversion. | M |
| **F1** | HIGH | Federation ships with signature enforcement OFF — neither `FEDERATION_ENFORCE_SIGNED_BROADCASTS` nor `FEDERATION_REQUIRE_SIGNED_RECORDS` is set in any deploy artifact, so the self-certifying/pinning stack runs advisory-only and the forgeable-inbox class is live. | `docker-compose.yml`, `.env.example`; `chapter_agent.py:3327-3335` | Default both flags ON (or set `true` in deploy config). Gate the README "federation is live/secure" claims on them. | S |

> **C2 — FIXED.** `export_agent_endpoint` resolves the verified caller and 403s
> unless the caller owns the id or holds an admin token (regression tests:
> cross-agent, unauthenticated, self). **I1 — unauthenticated leak CLOSED** for
> the confirmed-private surfaces (`intents`, `conversations`, `messages`,
> `settings`, `channels`, `voice`, `chapter-security` added to
> `REQUIRE_AUTH_GET_PATHS`); genuinely-public per-agent surfaces (profile,
> reputation, trust, endorsements, directory, members) and redacted-public
> surfaces (`audit`) stay open by design — `profile` has since become
> consent-gated: served only for a member who opted in via `POST /api/me/listing`,
> 404 otherwise (see C7 residual (b)).
>
> **I1 residual → Phase 1** (needs a maintainer visibility decision — surface
> `target` semantics are heterogeneous, `agent_id` vs `did:key`, so a blind
> caller-scope would break some surfaces while not fixing the no-filter ones):
> (a) per-caller `target`-scoping so an *authenticated* member sees only their
> own private surface (downgraded from HIGH-unauth to MEDIUM-authed-IDOR now
> that unauth is closed); (b) per-builder filtering for surfaces that ignore
> `target` and dump org-wide (`intents`, `conversations`); (c) classify the
> uncertain surfaces (`outcomes`, `activity`, `advisor-earnings`, `mesh`) as
> private-leak vs redacted-public before gating.

> **(c) — CLOSED.** All four are classified; none is left "uncertain". `activity`
> was a live leak (gated at the REST route, redacted at the builder).
> `outcomes` and `mesh` are public by intent — `outcomes` accepts `target` and
> never reads it, and its query selects no member column at all; `mesh` reads
> `target` but yields only `my_trust() -> {agent_id, trust_score, tier}`, which
> `/api/surfaces/trust` already serves openly. `advisor-earnings` was disclosing:
> its `target` went straight to `skill_revenue.get_earnings_for_did`, so an
> unauthenticated caller naming any did:key received that principal's earnings.
> It is now self-scoped alongside `today`.
>
> The 2026-07-30 pass had recorded the last three as clean. That verdict came from
> reading response field names on a route called with NO `target` — the empty
> case — which is also the method that missed the `activity` leak, because A2UI
> builders flatten values into `Text` components so the keys are absent while the
> values are served verbatim. Classifying a `target`-taking surface requires
> driving the parameter and reading the builder, not probing an idle instance.
| **S1** | HIGH | Chapter/org Ed25519 signing key stored plaintext at rest (DB + un-chmod'd, un-gitignored `chapter_ed25519.json`) → full identity + receipt forgery on any dump/backup/commit. | `server/sovereign_identity.py:166-192` | Encrypt at rest (reuse `keystore.py` crypto/KMS), `chmod 0600`, add `chapter_ed25519.json` to `.gitignore`. | M |

> **S1 — FIXED.** The key file already lives under gitignored `.org/`. Added: (1) AES-256-GCM at-rest sealing of the org secret in both the `chapter_keys` DB row and the local file, keyed by PBKDF2 over `ORRERY_KEY_SECRET` — a DB dump/backup is no longer forgery material when the secret is set; (2) legacy plaintext rows stay readable (marker-based decode) so it is non-breaking; (3) the local file is written `0600` (owner-only); (4) `ORRERY_KEY_SECRET` surfaced in `.env.example` + `docker-compose.yml` with a loud warning when unset. Regression tests: seal/unseal round-trip, legacy passthrough, sealed-without-secret raises, DB-sealed-and-reloads.

> **S1 — REOPENED and CLOSED as AUDIT_HARSH C11.** The clause "when the
> secret is set" above was doing more work than it looked like. `ORRERY_KEY_SECRET`
> was optional, `.env.example` shipped it empty, and unset meant one warning line
> at boot followed by a plaintext signing key — so the sealing landed but the
> default did not select it. Measured on the live mesh before changing anything:
> **none of the three deployed orgs had `ORRERY_KEY_SECRET` set**, so all three
> were running the unsealed branch that S1 was recorded as fixing.
>
> Closed by: (1) `secret_sealing.py` — sealing required by default via
> `env_flags.security_flag("ORRERY_REQUIRE_SEALED_SECRETS", default=True)`, so
> `ensure_chapter_keypair` raises at startup instead of writing a plaintext key,
> on a first boot and on a restart over an already-plaintext row; (2) seal-in-place
> migration for existing plaintext DB rows and key files — the same key bytes
> re-encoded, so `did:key` is unchanged and no peer re-pins; (3) the same mechanism
> extended to `agent_api_keys` (C1) through `api_key_store.py`; (4) the offline key
> file is chmod'd on rewrite, which `O_CREAT` alone does not do for an existing file.
>
> The generalisable point: a security control whose activation is optional is not
> closed by the control landing. What closes it is the default, and the default has
> to be measured against deployed configuration, not against `.env.example`.

## Phase 1 — Security hardening (before a confident 1.0)

**Consent gate**
- **G2** (HIGH) — one-shot approvals aren't consumed by the executor runners (only the HTTP path tombstones), so an approval replays for the 5-min TTL. Consume atomically inside `execute_plan` immediately after a `find_valid_approval` hit, before invoking the runner.
- **G3** (MED) — consent ledger is tail-truncatable (dropping trailing rows yields a shorter still-valid chain). Persist a signed head-checkpoint (length + last hash).
- **G4** (MED) — legacy `think()` inits the ledger with no signing key → unsigned rows that `verify_chain` skips. Always init with the signing key; reject unsigned rows once signing is enabled.

**Consent to be published**
- **P1** (HIGH) — the **agent runtime published a real person to a live public registry with no consent artifact, automatically, on opt-out semantics.** `agent/community_member/registry.py` defaulted `REGISTRY_URL` to `https://nest.projectnanda.org` and `should_announce()` asked only "not opted out · configured · not a `TEST-` id"; `announce_loop` was wired into the asyncio gather in both entry points (`agent/serve.py`, `community_member/cli.py`), so launching the agent published it. Nothing in the wizard gated it — its "Privacy" step only asked about LinkedIn. **This made Orrery register agents to an index on its own authority, which is exactly what the self-registration removal forbids**: the self-registration removal removed self-registration from the SMB stack (`smb_host` genuinely makes no index calls) and left the agent runtime doing it. **Fixed.** Publication now requires a valid **owner-signed listing grant** — a DAT whose grantor is an owner principal established out-of-band via OIDC (loopback + PKCE), and whose grantee is this agent's `did:key`. Opt-out became opt-in; `COMMUNITY_MEMBER_NO_REGISTRY` is kept as an additional hard opt-out so consent permits but never compels. The gate (`community_member/owner.listing_grant_verdict`) fails closed and names every refusal. Regression-pinned by `test_should_announce_requires_owner_consent`, which is the assertion that previously read `is True`.
- **P2** (HIGH) — **a self-granted consent verifies.** Orrery's vendored DAT verifier accepts a grant whose `grantor_did` equals its `grantee_did` — `_dat` checks delegation continuity only *across* hops, and a single self-granted DAT has no hop, so nothing looks (measured: `verify_counterparty_dat` → `ok=True, stage='accepted'`). Signature, scope and chain checks all pass while the artifact asserts nothing about who authorised anything. **Disposition: refused explicitly at the gate, NOT fixed in `_dat`** — that module is in byte-for-byte lockstep with `conformance/dat` and editing it would break that guard. Pinned by `test_dat_verifier_ACCEPTS_a_self_granted_consent` (the premise) plus `test_gate_refuses_the_self_granted_consent_that_dat_accepts` (the refusal), so the refusal cannot be deleted as redundant without the premise test explaining why it exists.
- **P3** (MED) — **`sm_authority`'s OIDC nonce is optional and nothing binds an ID token to `grantor_did`.** `OIDCVerifier.verify` checks `iss` and `oid`/`sub` against the anchor, then `if nonce is not None and …`; `build_authority_evidence` takes `grantor_did` as a plain field, and the envelope signature is by the *issuer*, whose authority the library itself disclaims. So any holder of a valid ID token for a subject — every relying party that person has signed into — can assemble a VERIFIED envelope naming their own key as grantor over that person's anchor. **Mitigated locally:** the OIDC nonce is a commitment to the owner DID, `base64url(sha256(owner_did ‖ random))`, sent in the authorization request so the IdP echoes the binding into the token it signs; required non-empty at construction *and* at the gate. **Upstream: RESOLVED (2026-07-30).** Filed as `[sm-authority issue 2](https://github.com/Sharathvc23/sm-authority/issues/2)` and fixed in **0.2.0**, which binds the nonce to `grantor_did` — the block carries `nonce_salt`, the verifier recomputes `oidc_binding_nonce(grantor_did, salt)` and requires the token's signed `nonce` to equal it — with `require_nonce` defaulting to `True`. Orrery pins and floors `>=0.2.0` in `agent/constraints.txt`, `agent/requirements.lock` and both `agent/pyproject.toml` extras. Verified against both published wheels rather than from the changelog: the attacker envelope (no nonce, attacker `grantor_did`, genuine victim token) returns `VERIFIED`/`ok` on 0.1.0 and `INDETERMINATE`/`malformed_evidence` on 0.2.0. `OIDCVerifier(require_nonce=False)` restores the vulnerable behaviour in full (measured: `VERIFIED`/`ok` again) and MUST NOT be set — it exists upstream only to migrate pre-`nonce_salt` evidence, and it warns. The local binding is retained as defence in depth so the property does not rest solely on a transitive pin.

- **P4** (HIGH) — **a domain-control challenge proves control of a domain, not that its controller authorised any particular key — and the proof is published on purpose.** nanda-connect's `make_challenge_validator` reads `key_authorization` from **caller-supplied claims** and merely checks the domain publishes that same string; `DomainControlVerifier.verify` then checks only `attested["domain"] == anchor["id"]`. Nothing binds either to `grantor_did`. This is a worse instance of **P3**'s confused-deputy shape, because the value an attacker needs is world-readable **by design**: an HTTP-01 response is served at `/.well-known/nanda-connect-challenge/<token>` and DNS-01 is a public TXT record. Any passive observer of a legitimate challenge can copy `{domain, method, token, key_authorization}` into their own envelope, name their own DID as grantor, and be VERIFIED as the owner of someone else's domain. **Filed upstream as an upstream issue filed against the NANDA Connect library; that repo is untouched and not waited on. Mitigated locally** by RFC 8555's construction applied to the owner key — `keyAuthorization = token || "." || base64url(JWK_Thumbprint(ownerKey))`, **computed locally and never accepted as input**, at acquisition *and* recomputed again at the listing gate from the envelope's own `grantor_did`. A copied challenge therefore carries the wrong thumbprint for whoever copied it. Pinned by `test_a_challenge_served_for_owner_A_is_refused_for_owner_B` (the attack, against a domain genuinely serving A's value) plus `test_the_same_replay_is_refused_at_the_gate_too` and a source assertion that the claim is never read back. The verifier also refuses **before** performing the challenge when the grantor does not match, so it cannot be used as a lookup oracle for arbitrary domains. **Scope, stated because it is easy to overclaim:** this unblocks **domain-owning** businesses, not businesses generally — HTTP-01 needs file hosting and DNS-01 needs registrar access.

- **P5** (MED) — **a withdrawn listing was indistinguishable from one that never existed.** Listing was consent-gated, which is presence or **absence**: `owner.py`/`registry.py` had no `lifecycle_state`, no `revoked`, no `suspended`, and withdrawal *deleted* the binding. So a caller could not tell *"this business no longer has an agent"* from *"resolution failed"* — and a stale endpoint then produces a plausible transaction with a party that no longer exists. **Same failure shape as the strict-selector rule one layer up**, where an unrecognised `?schema=` selector returned a plausible wrong answer instead of a 400: an ambiguous answer is worse than an honest error. **Fixed.** Explicit `active` / `suspended` / `revoked` / `not_established`, resolvable at `GET /.well-known/agent-lifecycle.json`, which **never 404s** — a 404 recreates the ambiguity. Withdrawal records a revocation carrying the revoking authority and time; `delete_binding` is retained for local cleanup only and a structural test asserts no withdrawal flow calls it. Revocation is **terminal** (re-listing needs fresh consent, so a resolver that cached "revoked" is never made wrong). The gate reports `revoked`/`suspended` as their own reasons rather than collapsing into "no consent", and revocation outranks an expired grant — *"expired"* reads as "renew it" when the truth is "it was withdrawn". **Attestation is optional and labelled:** the owner key is never persisted, so requiring a signature to withdraw would lock out anyone who lost their phrase — a worse failure than an unattested record. `owner_attested: false` means *this runtime says so*, never *the owner did not sign*, and a forged signature degrades to unattested without undoing the revocation.

**Frontend injection**
- **G3 / C7 + H13** (HIGH — **re-rated up from MED at fix time; see below**) — **stored-XSS sink on the recovery phrase in the SMB funnel.** `smb_funnel/src/app.js:158` built `chip.innerHTML` by interpolating a recovery-phrase word **unescaped**, four lines from a neighbour (`:198`) that used `escapeHtml` correctly. A recovery phrase re-derives the agent's `did:key`, so it is the highest-value string the product renders. **Fixed.** The audit's premise that this input is locally generated does not hold, which is why the rating moved. The funnel does not generate the phrase — it *receives* it in the `/provision` response, and `config.resolveApiBase()` lets a **URL query parameter** (`?api=`) choose which host answers, winning over both `localStorage` and the built-in constant. So `https://funnel/?api=https://evil.tld` makes the phrase fully attacker-controlled with nothing compromised and no refactor required: a one-click, no-prerequisite XSS in the funnel's origin, where real recovery phrases are displayed. Verified by driving `resolveApiBase()` with a query param, pinned as a test. **H13** (the receipt display, `:217`) shares the same fully-remote trust boundary but every interpolation there was `escapeHtml`-wrapped in a text position, so it was **not** exploitable — it was correct only because eleven call sites each remembered. **Both were rebuilt as element/text nodes** (`smb_funnel/src/render.js`) rather than wrapped in an escaper: the patch would have left the next interpolation one keystroke from the same bug. `escapeHtml` is deleted, because a live escaper invites the string-building style back. Two guards: adversarial tests that push a `<script>` tag, quotes and an `onerror` attribute through the **real** render path under a stub DOM that **throws on `innerHTML`** (so passing is itself proof no HTML parser was involved), plus a static source audit banning the sinks — the same two-layer discipline `renderer/` already used and the funnel never got.
- **G3 residual — closed.** `?api=` selected the host that answers `/provision`, above both `localStorage` and the built-in constant, so the author of a link chose which host produced the endpoint, `did:key` and recovery phrase the provisioning screen then displayed on the funnel's own origin. The parameter is no longer read (`smb_funnel/src/config.js`); the host is selected by `localStorage["smb_funnel.api_base"]` or by the `API_BASE` constant. `localStorage` still persists, so script execution in that origin can still redirect later visits — that path is unchanged and every `/provision` field is still treated as untrusted by the node-building render path. The funnel's demo instructions in `smb_funnel/README.md` use `localStorage` accordingly. The related URL sink (`a.href` assigned from the `/provision` `endpoint` field) is removed rather than sanitised: the card URL is rendered as text and copied, and `smb_funnel/tests/source-guard.test.mjs` rejects any assignment to `href`/`src`/`action` or `setAttribute` of a URL-bearing attribute in the funnel's source.
- **P6** (MED, **partly open by construction — read the residual**) — **a business that leaves its platform stops using it; it does not tell us.** The platform-uninstall work names the uninstall webhook as the load-bearing event for exactly that reason. **Built (buildable half):** a generic HMAC-over-raw-body receiver at `POST /webhooks/platform/{platform}/uninstall` that transitions the listing to **`suspended`** through the owner-attested rework's own lifecycle API, recording **the platform** as the authority with `owner_attested: false`. The state is `suspended` rather than `revoked`, deliberately: `revoked` means the owner withdrew, and an uninstall is a platform's observation of its own billing — recording it as a revocation would attribute a withdrawal to someone who never made one, and `revoked` is terminal, so a business that switches POS and returns would need fresh consent for an event it never performed. Fail-closed on the signature in the direction that matters: an unsigned POST that could suspend a listing would be a **denial-of-listing primitive** over every business served, so the secret is required (unset ≡ empty ≡ whitespace, no default), an unverified request is parsed and read *not at all*, replays are refused by a freshness window plus an event-id ledger, and a duplicate delivery is reported as already-applied rather than failed (failing a platform's retry produces a retry storm over an event handled correctly). Verification is **injected**, so a real provider's header/encoding drops in without touching the receiver; the assumed wire shape is labelled as an assumption in the module.
- **P6 residual — not closed. The webhook MUST NOT be read as closing it.** A webhook that never arrives — endpoint unreachable, secret rotated, platform retries exhausted, or a platform that simply does not send one — leaves a departed business listed **`active` forever**. That is precisely the stale endpoint the SMB resolution draft calls more dangerous than a missing one, and this receiver is **best-effort notification, not a guarantee of freshness**. Closing it needs reconciliation against the platform's API (poll installed-app state, expire on absence), which needs the partner account the platform-uninstall work is blocked on. Stated here rather than left implied, because a receiver that exists invites the assumption that absence of an event means presence of a customer. **The Square OAuth/install leg remains blocked and unbuilt; `platform_install.py` still refuses honestly.**


**Auth / authz**
- **C3** (MED) — `/api/feedback` attributes to body `agent_id` and mints an org-signed receipt → forged receipts in another member's ledger. Attribute to `_resolve_caller`; ignore body `agent_id`.
- **C4** (MED) — v0.2/hmac canonical string has no method/path/nonce; a captured signed GET replays as DELETE within the 300 s window. **Fixed:** the internal mutating API now requires the method-bound, replay-protected `ed25519+nonce` scheme (server rejects v0.2/hmac on POST/PUT/PATCH/DELETE with `method_binding_required`); `A2AClient` upgraded to sign v0.3 for all verbs. The A2A interop POSTs (`/a2a`, `/run`) are exempt — POST-only, no GET twin — keeping the cross-org v0.2 control set intact. Reads still accept v0.2 (a replayed GET is non-escalating; a nonce-on-reads follow-up is the residual). While fixing, closed a latent **middleware fail-open**: unhandled non-valid reasons (`method_binding_required`, `nonce_replay`, `unknown_sig_scheme`, missing/invalid timestamp, …) fell through the deny-list and passed unauthenticated — the block now fails closed.
- **C5** (MED) — `/api/agents/{id}/aae-events` is unauthenticated (in neither allowlist). Gate it.
- **C6** (LOW) — `update_projection_endpoint` retains a spoofable `X-Agent-ID` header fallback. Use `_resolve_caller`; reject empty.
- **C7** (HIGH) — `GET /api/members` was unauthenticated: one request returned every member's agent_id, name, description, skills, interests, availability, reputation, github_url and linkedin_url. **Fixed.** The listing moved to `REQUIRE_AUTH_GET_PATHS`; authorized readers are a signed member, an operator bearer (`is_operator_readable_path`), and a signature-verified federation peer (`federation_signing.verify_peer_request` — fail-closed, replay-protected, key from the peer's pin, not its endpoint). `POST /api/members` (first-contact TOFU register) stays open and is regression-pinned. `GET /api/federation/{peer}/members` was gated with it — open, it laundered the same enumeration through our federation key. The cross-org discovery leg now signs its outbound GET and **logs a failed peer query loudly** instead of returning `[]`. **Residuals** (deliberately out of scope, need a product decision): (a) half of this residual is closed as of `0.3.0`. `GET /api/surfaces/members` no longer renders a directory surface unauthenticated: it sits in `REQUIRE_AUTH_GET_PATHS` alongside `/api/surfaces/directory`, `/api/surfaces/chapter` and `/api/surfaces/subscriptions`, and `test_member_enumeration_closed.py` asserts the gate both exists and fires. What **remains** open is the `/api/mesh/peers` federation-aware peer search, which is still ungated; (b) **closed:** the exact-match `GET /api/agents/{id}/profile` was a 200/404 membership oracle for a guessed id; it now answers only for a member who opted in with `POST /api/me/listing` and 404s byte-identically for a silent member and an unknown id (`test_profile_consent_gate.py`), so a guessed id learns nothing — the *privacy-preserving* lookup (blinded/OPRF, per-caller scoping) remains unbuilt, and is no longer needed to close the oracle; (c) reads still accept the v0.2 scheme, so a captured signed listing read replays within the timestamp window (same non-escalating residual as C4).

**Federation / crypto**
- **F2** (MED) — the open-write lean index is a record-takeover/DoS primitive when consumers aren't enforcing. **Fixed (two stages).** Stage 1: always-on DoS caps (request-body size cap → 413, total-record capacity cap → 507, per-IP write rate limit → 429) plus an opt-in `INDEX_WRITE_TOKEN` — zero new dependencies, open-write default preserved. Stage 2: the **per-org attestation gate** (`index/attestation_gate.py`). Semantics: a write carrying an attestation must carry a *valid* one (signature over the JCS record against the DID's own key, freshness, `issued_at ≤ expires_at`, not-before with 300s skew, subject = path id, attested endpoint = body endpoint) → else 403; the first *valid* attested write **TOFU-pins** the record's DID (`did_pins` table, durable — survives DELETE, never overwritten); every later write to a pinned id requires a valid attestation by the pinned DID → takeover by re-registration or unsigned overwrite is rejected at the write surface. Unpinned ids without attestations stay open (NEST parity; member records never pin). `INDEX_ATTESTATION_GATE=off` restores the pure-open posture for tamper drills. **Dependency-budget decision:** accept `cryptography` + `jcs` + `base58` (the same stack the rest of the repo standardizes on) rather than hand-vendor Ed25519/JCS — vendored crypto is a correctness foot-gun, and "lean" means lean *surface*, not home-rolled primitives. Consumer-side DID pinning + the divergence detector (F4/F5) remain the primary, registry-independent defense; the gate is defense-in-depth on the one registry we operate.
- **F3** (MED) — cosign-broker SSRF guard is bypassable via DNS rebinding (check resolves the host, httpx re-resolves). Resolve once, validate the resolved IP, connect to that pinned IP.
- **F4** (MED) — divergence sweep is sequential and awaited inline in the heartbeat (stall risk), and a registry hides omission behind a 500/timeout. Parallelize with `asyncio.gather` + a total-sweep budget; treat a per-id error, when a sibling serves the record, as "unconfirmed" rather than silence.
> **F2 — open-write default SUPERSEDED (AUDIT_HARSH C12).** Stage 1 above
> recorded "open-write default preserved" and made `INDEX_WRITE_TOKEN` opt-in.
> That was a deliberate choice and it is being reversed deliberately, not
> overlooked. Two things changed:
>
> 1. **Measured 2026-08-03, read-only:** the deployed lean index had neither
>    `INDEX_ATTESTATION_GATE` nor `INDEX_WRITE_TOKEN` set. So it was accepting
>    unauthenticated writes in production — the opt-in was never taken up, which
>    is what an opt-in security control usually gets.
> 2. **The writer set is known and closed:** exactly three writers, all orgs we
>    operate (astrocity, rocketbrain, regentix). No third parties. The
>    "open ecosystem / NEST parity" rationale that justified the open default
>    describes an index with unknown consumers, and this is not that index.
>
> `INDEX_WRITE_TOKEN` unset now refuses writes (503, naming the variable).
> `INDEX_WRITE_OPEN=true` is the explicit opt-out and still restores the F2
> tamper-drill posture — the mode is preserved, it just has to be chosen.
>
> Separately, and this is the defect rather than the posture: `INDEX_ATTESTATION_GATE`
> was safe **by accident**. The inline check tested membership in
> `("off","0","false")`, so an unset value landed ON — and so did a typo, and so
> did `"no"`. Correct, but nothing declared it correct and the direction was
> unreadable at the call site. Both gates now go through
> `env_flags.security_flag` with a mandatory written-down default, the C9
> convention. A typo can no longer flip either one.
>
> Not deployed. Flipping this refuses writes on an index that currently has no
> token, so it needs the G1 ordering: set `INDEX_WRITE_TOKEN` on the index and on
> the three orgs that write to it, then deploy. Sequencing is a human decision.

> **C3 — TLS to Postgres: RESIDUAL, dated 2026-08-03, measured.** The code
> requires TLS for any non-loopback Postgres host. The three deployed orgs reach
> Postgres at `db.railway.internal`, which is NOT on `_LOCAL_DB_HOSTS` and whose
> DSNs carry no `sslmode`, so they would resolve to `require`.
>
> Measured 2026-08-03: that host does not accept TLS. All three deployed
> orgs report `db.tls_available: false` on `/health`, from the boot probe added
> with the C3 fix. It could not be answered from outside — the hostname resolves only
> inside Railway's private network — so the server was made to answer it, and it
> did on the first boot that carried the probe.
>
> **This confirms the pre-flight was load-bearing.** Deploying G5 without
> `ORRERY_DB_SSL=disable` would have resolved all three to `ssl=require`,
> asyncpg would have been refused the upgrade, the pool would never have been
> created, and none of the three orgs would have booted. The question was worth
> refusing to guess.
>
> **Interim posture:** `ORRERY_DB_SSL=disable` on the deployed orgs, which
> reproduces exactly the behaviour they have today. C3's fix is
> correct in code and inert on the deployed mesh. It is closed in the codebase
> and open in production, and this row exists so nothing reads it as closed.
>
> `.railway.internal` was deliberately NOT added to `_LOCAL_DB_HOSTS`: that list
> states what is physically loopback-or-sidecar, and C3's own threat model names
> "cloud provider network". Putting a cloud overlay on it would make the list lie
> to the next reader.
>
> **What would close it, now that the answer is known:** flipping
> `ORRERY_DB_SSL=require` is NOT available — the database refuses TLS, so that
> flip is an outage, not a fix. Closing C3 in production therefore requires
> either a Postgres that terminates TLS on this hop (a Railway configuration or
> a different database), or accepting the private network as the encryption
> boundary.
>
> That second option rests on a vendor claim that is still uncited.
> Whether Railway's private network is itself encrypted is what decides if
> `disable` is an honest boundary or a capitulation, and it must be cited here
> from Railway's own documentation — not remembered, not inferred. Until that
> citation exists, the honest reading of this row is: **C3 is closed in code,
> open in production, and the compensating control is unverified.**
>
> The probe stays. It costs one connection per boot and it converts this from a
> question somebody has to re-investigate into a field every org reports — so if
> the hop ever gains TLS, `db.tls_available` flips to `true` on its own and the
> flip becomes a one-variable change.

- **F5** (MED) — `pinned_did_for` fails open: `except: pass` falls through to the asserted DID, silently downgrading from the pinned key on any DB read error. Distinguish "no pin recorded" (fallback OK) from "read failed" (fail closed / retain last-known pin).
- **F6** (LOW/INFO) — TOFU identity pre-seeding: a first-writer in the open index can pin their own DID as a victim's identity (durable, never overwritten) unless the peer is out-of-band anchored. **Ceiling documented + sanity added:** the ceiling is inherent to TOFU — the index gate (F2 stage 2) narrows it (pre-seeding now requires a *validly signed* attestation, so a squatter burns a real keypair and the victim's later genuine write 403s loudly instead of silently fighting) but does not remove it; the mitigations remain publishing early (the org's boot + heartbeat registration) and out-of-band anchoring (`KNOWN_CHAPTER_ENDPOINTS`, consumer-side pins). A durable pin also means legitimate key rotation requires operator intervention on the index — that is the deliberate trade. The `issued_at ≤ expires_at` + not-before (300s skew) sanity checks are now in both verifiers (`server/registry_attestation.verify` and `index/attestation_gate.verify_attestation`), verdict-parity-tested.

**Secrets**
- **S2** (MED) — the agent key-vault cipher is a hand-rolled HMAC-CTR construction whose docstring falsely claims AES-256-GCM (correctly built, but non-standard, 128-bit halves, 100k PBKDF2). **Fixed in two stages.** Stage 1: documentation corrected — the construction is a *sound* HMAC-SHA256 encrypt-then-MAC AEAD; the defect was the misleading "AES-256-GCM" claim. Stage 2: **versioned blob + legacy-read migration** at the `crypto.encrypt_value`/`decrypt_value` layer (shared by the key vault and the config API-key blob, so both gain it). New writes are v2 — `{v: 2, kdf: {name: "pbkdf2-sha256", iterations}, cipher: "hmac-sha256-etm-v1", ciphertext, salt, nonce, tag}` — with the KDF cost read **from the blob** (clamped to a sane range before deriving, so a tampered blob can't demand 10^12 iterations as a DoS; a tampered count then just fails the MAC). Version-less blobs decrypt via a **frozen** `LEGACY_PBKDF2_ITERATIONS = 100_000` constant — decoupled from the live default, so a future cost bump (or AESGCM/argon2 under a new `cipher`/`kdf.name`) is a config change, not a vault-bricking event; unknown version/kdf/cipher values fail loud, never silently downgrade. The keystore vault **re-encrypts to v2 on first successful open** (`_read_vault` write-back). The core cipher and its MAC input are byte-identical to stage 1 — v2 is a metadata envelope, not a new construction. Guard tests updated deliberately: the v2 shape, both iteration constants, and a hardcoded golden legacy blob (must decrypt forever) are pinned.
- **S3** (LOW) — headless keystore passphrase is `sha256(hostname|home|machine-id)` (recomputable); `.env` ships the public Supabase demo `JWT_SECRET`. Both documented; regenerate for any real deploy.
  > **Re-checked 2026-08-14 — the second half no longer applies.** `.env.example` contains no `JWT_SECRET` and no Supabase value of any kind; that credential left the tree with the Supabase removal. The recomputable-passphrase half stands as written. Annotated rather than edited, because this file is the verbatim audit-time record and rewriting a finding to match today would destroy what it is for.

**Test coverage of the class**
- **I2** (MED) — extend the intents default-deny sweep to every surface exposing per-agent/private data (it currently misses `/api/surfaces/intents`). This is the route-enumeration test from the systemic fix.

## Phase 2 — Release-readiness (ship-quality gates)

- **R3** (MED) — **pin the supply chain.** `sm-arp/sm-bridge/sm-locp @ git+…@main` (CI installs bare HEAD each run) → non-reproducible builds; a push to any `sm-*` repo silently mutates Orrery. Pin to tags/SHAs, publish `sm-bridge`/`sm-locp` to PyPI, add a lockfile. This enforces the version-pinning standard in [`integrations/STELLARMINDS.md`](integrations/STELLARMINDS.md).
- **R1** (MED) — no coverage measurement anywhere (bare `pytest -q`). Add `pytest-cov` + `--cov-fail-under`, with an explicit floor on the auth/crypto modules.
- **R2** (MED) — mypy runs on 3 agent files only. Extend to `server/` (at least `auth_verify`, `federation_signing`, `sovereign_identity`), `index/`, `skill/`.
- **R4** (MED) — `sovereign_identity.py:242-243` silently returns a malformed, non-round-trippable DID on error. Let it raise.
- **R6** (LOW) — log-before-deny on the silent auth/crypto `except` blocks (`auth_verify.py:629,650,662`; `sovereign_identity.py:220`) — violates the repo's "no silent try/except" standard.
- **R7** (LOW) — close CORS `*` (`chapter_agent.py:1453`) and `/docs` + `/openapi.json` on the org host for prod.
- **R5** (LOW) — track this file and [`integrations/STELLARMINDS.md`](integrations/STELLARMINDS.md) (both cited by shipped modules; the latter was untracked).
- **Release mechanics** — cut the first versioned tag (the agent-native pivot is unversioned), and publish a post-audit sign-off doc enumerating the prior 26 findings + these and their disposition (the "no published disposition" gap).

## Definition of done

Per finding: the fix, a regression test that fails on the old code, and
re-verification against source. For the auth family, the single highest-value
artifact is the **route-enumeration default-deny sweep** — it is the durable fix
for the whole IDOR class and prevents the next one from shipping silently.

## Sequencing

Phase 0 in order C1 → I1/C2 → G1 → S1 → F1 (C1 first because it makes the IDORs
unauthenticated; F1 is a config change that can land any time). Phase 1 and 2
can proceed in parallel once Phase 0 is green. Do not tag a release until Phase
0 is fixed, tested, and re-verified, and R3 (dependency pinning) has landed —
an unpinned dependency on a release tag is itself a release blocker.
