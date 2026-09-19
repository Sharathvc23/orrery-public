# Orrery Security Audit — Complete Report

**Audit date:** 2026-07-30  
**Scope:** Full-stack — server (`server/`), agent (`agent/`), renderer (`renderer/`), lean index (`index/`), SMB funnel (`smb_funnel/`), skill bundle (`skill/`), infrastructure/docker (`infra/`), CI/CD (`.github/`), database schema (`infra/init.sql`), configuration  
**Methodology:** Source code review, dependency analysis, architecture review, threat modeling of trust boundaries, configuration audit  
**Goal:** Identify every exploitable vector. No code changes — findings only.  
**Total findings:** 62 (14 Critical, 13 High, 20 Medium, 15 Low)

---

## Close-out — 2026-08-14

This audit is closed for its Critical and High findings. All 27 (14 Critical,
13 High) carry a disposition inline, on the finding itself, so a reader who lands
on C7 sees C7's outcome without consulting a separate table.

Each disposition was verified against the code on `main` on 2026-08-14. Where a
disposition could not be tied to code, the finding is not recorded as closed.

| State | Count | Findings |
|---|---|---|
| **FIXED** — closed as written | 19 | C1, C3, C5, C7, C8, C9, C11, C12, C13, H3, H4, H5, H6, H7, H9, H10, H11, H12, H13 |
| **MITIGATED** — exposure reduced, not fully closed | 3 | C10, C14, H2 |
| **ACCEPTED** — deliberate, with reasoning | 1 | H1 |
| **INCORRECT / OVERSTATED** — disputed, with evidence | 4 | C2, C4, C6, H8 |

Four findings are disputed, each with its evidence in the finding: C2 describes a
leak from a table no code in this repository reads or writes; C4 cites a
mechanism that is inert `pg_dump` boilerplate and names a table as protected that
is not; C6 is rated Critical for read access to Prometheus counters; H8's
scenario is unreachable in code that predates the audit. Where a residual
survives a dispute, the finding states it.

Still open in code:

- **C4** — the mechanism cited is mis-stated, and the underlying issue is real
  and unfixed. The application connects to Postgres as a superuser, so row-level
  security is not enforced. Scoped in `docs/audit/C4_RLS_SCOPE.md`.
- **C6** — `/metrics` compares its bearer token with `!=`. The severity rating is
  disputed; the defect is present and the fix is one line.
- **C10, C14, H2** — reduced, not closed. Each finding states what remains.

**Scope of this close-out:** the 27 Critical and High findings. The 20 Medium
and 15 Low findings were not part of that close-out and should be read as open
unless a later inline disposition explicitly supersedes this snapshot. M16 now
has such a disposition.

### C4 status update — 2026-08-15

A pre-release change landed on 2026-08-15,
one day after the close-out above. It added `orrery_app`, a non-superuser
`NOBYPASSRLS` runtime role, and changed the Compose default for the server's
database connection to that role. `APP_DB_USER` and `DATABASE_URL` remain
operator-overridable, so this records the repository default rather than the
state of every deployment.

The runtime role still has broad CRUD grants on every table plus sequence and
function access. The change reduces cluster and DDL privileges and removes the
blanket superuser RLS bypass from the default Compose request path; it does not
add a row policy. C4's RLS-policy residual therefore remains open. This update
supersedes only C4's current status, not the 2026-08-14 snapshot above.

---

## Triage of the Medium and Low findings — 2026-09-13

Sixteen Medium and ten Low findings carried no status at all until this pass: not
deferred, not accepted, blank. Each has now been assessed against current source
and given a verdict. `docs/audit/findings.json` is the checked copy and
`scripts/audit_gate.py` fails if this page and that file disagree.

| verdict | n | what it means here |
|---|---:|---|
| fixed | 3 | M8 (funnel CSP now present), M12 (duplicate of H5; hooks exist), L3 (37 tests now cover the pg_store escape boundary) |
| overstated | 1 | M5 — the f-string in `arp.py::_query` builds `where` from in-module literals and binds every runtime value; not an injection vector |
| residual | 11 | a deliberate, documented accepted risk, with the cost named |
| open | 11 | real, unaddressed, and nothing records a decision |

**The distinction between `residual` and `open` is the one to check.** `residual`
was used only where the code or the finding itself records a deliberate choice —
fail-closed nonce checks (L7, L8), the rate limiter deliberately ahead of auth
(L13), the A2A method-binding exemption that exists for interop and says so at its
definition (M18). `open` was used wherever something is simply not done, however
reasonable that might be: 200K PBKDF2 iterations (M3), 49 tag-pinned CI actions
(M13), unpinned `asyncpg` (M15), 5 `detail=str(e)` handlers (M6).

**One finding could not be assessed at all.** L10 claims session ids are
deterministic; no session-id generation was located in the files it names, so
neither the claim nor a fix could be confirmed. It is recorded `open` on an
absence of evidence rather than closed, because an unverifiable claim is not a
resolved one.

## Risk Rating Scale

| Severity | Meaning |
|----------|---------|
| 🔴 **Critical** | Direct, remotely exploitable, or leads to total system compromise with low attack complexity |
| 🟠 **High** | Significant security boundary violation; exploitable under realistic conditions |
| 🟡 **Medium** | Limited impact or requires chained exploitation; weakens defenses |
| 🟢 **Low** | Minor residual risk; defense-in-depth gap; documented design trade-off |

---

## 🔴 CRITICAL FINDINGS (14)

### C1. LLM API keys stored in plaintext in database
- **File:** `infra/init.sql:812`, `server/sovereign_runtime.py:658`, `server/member_runtime.py:316`
- **Detail:** The `agent_api_keys` table has a column named `api_key_encrypted` but the reading code (`sovereign_runtime.py:658`, `member_runtime.py:316`) uses the value directly as `api_key = key_info.get("api_key_encrypted", "")` with **no decryption**. The column name is misleading — the key is stored in plaintext.
- **Exploitation:** Database access (dump, backup, SQL injection) leaks all configured LLM API keys (OpenAI, Anthropic, xAI, Groq).
- **Fix:** Encrypt API keys at rest using the existing `_seal_secret`/`_unseal_secret` pattern from `sovereign_identity.py`, or use a AEAD scheme.
- **Disposition — FIXED.** `server/api_key_store.py` unseals on read (AES-256-GCM via `ORRERY_KEY_SECRET`, marker-based so legacy plaintext still reads) and seals existing plaintext rows in place on first load. Both runtimes now go through it, and the loaded row carries `api_key` rather than `api_key_encrypted` so a call site cannot repeat the original mistake. Nothing in this repo writes the table — rows are provisioned out of band — which is why the migration lives on the read path. Severity in context: these are bring-your-own-key member credentials, so a leak costs the member their own provider spend; that is materially less than C11, which is org identity.

### C2. OAuth calendar tokens stored in plaintext in database
- **File:** `infra/init.sql:855-867`
- **Detail:** The `agent_calendar_connections` table has a column named `encrypted_token` (type `jsonb`) but no encryption/decryption code was found for this column. Token names suggest encryption that does not exist.
- **Exploitation:** Database access yields valid OAuth tokens for Google/Microsoft/Apple calendars.
- **Fix:** Implement actual encryption for this column, matching the key-sealing pattern.
- **Disposition — OVERSTATED.** The observation is literally true and the conclusion drawn from it is not. `agent_calendar_connections` is **inert schema**: no Python in this repository reads or writes that table or its `encrypted_token` column, and `git log -S` over the full history finds no commit that ever did. There is no OAuth calendar integration here — no authorization flow, no token exchange, no refresh path — so nothing ever puts a token in the column. "Database access yields valid OAuth tokens for Google/Microsoft/Apple calendars" describes a leak of data this system does not hold. The table is one of ~111 inherited from a `pg_dump` of an older schema. Rated Critical; its reachability is zero.
  **What is real, and much smaller:** dead schema that *looks* like a credential store is a trap for whoever wires up calendars next and assumes the column name means something — which is exactly the C1 defect, and C1 was real precisely because code *did* read the misleadingly-named column. The correct remediation is to drop the table, not to encrypt it. Not done here; recorded as schema hygiene, not a security fix.

### C3. No SSL/TLS on PostgreSQL connection
- **File:** `server/pg_store.py:304-306`
- **Detail:** `asyncpg.create_pool()` is called with the raw `DATABASE_URL` string and no `ssl` parameter. For `postgres://` URLs (no `sslmode`), asyncpg defaults to **no SSL**. All data in transit between the server and Postgres is unencrypted.
- **Exploitation:** Network-level attacker (same VLAN, cloud provider network, compromised router) can sniff all traffic: signing keys, API keys, PII, receipts, tokens, member data.
- **Fix:** Pass `ssl="require"` to `asyncpg.create_pool()` or document/enforce `sslmode=require` in `DATABASE_URL`.
- **Disposition — FIXED.** `pg_store._resolve_db_ssl()` now decides the `ssl` argument before every pool creation, and a real network hop defaults to `require`. Precedence is explicit: an `ORRERY_DB_SSL` operator override wins; otherwise an `sslmode=` already in the DSN is honoured untouched; otherwise the host decides — loopback and compose-network sidecars (`localhost`, `127.0.0.1`, `::1`, `db`, `postgres`, `pgvector`) get `disable`, and **anything else gets `require`**. The exemption is narrow, enumerated, and logged once per process (`db.tls_mode`, with which rule produced it), because an exemption nobody can see is indistinguishable from the bug it replaces. `ssl="prefer"` was rejected on measurement: it downgrades to plaintext silently, so it is not a security control. A separate boot-time probe opens one `ssl="require"` connection, records whether this Postgres would have accepted TLS, and surfaces it on `/health` as `db.tls_available` — it reports and never gates, so a database that cannot do TLS is a visible fact rather than an outage.
  Closed in code, open in production. The three deployed orgs reach Postgres at a host that is not on `_LOCAL_DB_HOSTS` and would therefore resolve to `require`, but that host does not accept TLS: all three report `db.tls_available: false` from the boot probe, measured 2026-08-03. They run with the `ORRERY_DB_SSL=disable` exemption, and setting `require` on them would prevent the pool from being created. Closing C3 in production needs either a Postgres that terminates TLS on that hop, or a decision to accept the private network as the encryption boundary; that second option rests on a vendor claim that is still uncited. `docs/HARDENING.md` carries the measurement and the sequencing.

### C4. Row-level security disabled for 60+ tables
- **File:** `infra/init.sql:24`
- **Detail:** The schema initialization sets `SET row_security = off` for the session. Only 1 table (`agent_private_memory`) has `FORCE ROW LEVEL SECURITY`. The entire application relies on application-layer authentication — any authenticated database connection (direct DB access, compromised pool, SQL injection) can read/write every row across all tables.
- **Exploitation:** A SQL injection vulnerability (even in a third-party library ORM) grants full database access with no per-row restrictions.
- **Fix:** Implement RLS policies per table with appropriate `USING` clauses. At minimum, add RLS to tables containing PII, keys, and tokens.
- **Disposition — OVERSTATED in mechanism; the underlying issue is real and open.** Three of the finding's specifics do not hold against the schema. Correcting them makes the current state slightly worse than filed and the fix smaller.
  1. **`init.sql:24` is not a global disable.** `SET row_security = off` is a per-session GUC sitting in the middle of `pg_dump`'s standard prologue, between `SET xmloption = content` and `SET client_min_messages = warning`. It applies to the restoring session only, has no effect on the running server or on later connections, and removing it would change nothing. It is not the mechanism.
  2. **`agent_private_memory` is not protected either.** It carries `FORCE ROW LEVEL SECURITY` with no `ENABLE ROW LEVEL SECURITY` and no `CREATE POLICY` anywhere in the schema. `FORCE` without `ENABLE` does nothing. Coverage today is **zero tables, not one** — the single table cited as protected is protected by an inoperative line.
  3. **Scale is 111 tables, not "60+".** The audit's "at minimum" set (keys, tokens, credentials, PII) resolves to roughly 25, not 111.
  The finding does not name the actual blocker: the application connects as `postgres`, a superuser, and `infra/init.sql` contains **zero** `CREATE ROLE` and **zero** `GRANT`. PostgreSQL exempts superusers and `BYPASSRLS` roles from every policy unconditionally. So RLS here is not merely weak — it is **inert by construction**, and writing per-table policies tomorrow would produce a large maintenance surface, no security change, and a false sense of coverage. The prerequisite is an application role, not policies.
  Status: open. No code has landed. `docs/audit/C4_RLS_SCOPE.md` records the scope, the corrections above, and the sequencing — create a non-superuser application role first (independently valuable: it removes the "SQL injection anywhere means superuser on the cluster" ceiling even if no policy is ever written), then make one table genuinely enforce, then the `SET LOCAL` identity plumbing, then widen. Policies written before the role would be untested and indistinguishable from working.

  **Later status update — 2026-08-15.** A pre-release change
  landed after this disposition. It added the non-superuser `NOBYPASSRLS`
  `orrery_app` role and made it the Compose default for the server database
  connection; operators can still override `APP_DB_USER` or `DATABASE_URL`.
  The role has broad CRUD, sequence, and function grants but no row policies.
  The default runtime path therefore has reduced cluster and DDL privileges and
  can be subject to future RLS, while C4's row-isolation work remains open.

### C5. No Content Security Policy (CSP) headers
- **File:** All server responses — no CSP header set anywhere
- **Detail:** Neither the FastAPI server nor any middleware sets `Content-Security-Policy` headers. The reference renderer (`renderer/index.html`) has a strict CSP via meta tag, but the admin UI, all API responses, and any browser-consumed pages have no CSP. XSS in any rendered surface can execute scripts, exfiltrate data, or perform admin actions.
- **Exploitation:** XSS anywhere in a rendered A2UI surface or admin page bypasses all server-side controls without CSP.
- **Fix:** Set a strict CSP via FastAPI middleware for all HTML/non-API responses.
- **Disposition — FIXED.** `server/csp.py` builds a policy per HTML page and `chapter_agent.py` attaches it to every HTML response it serves — the receipt pages and the admin UI, the two surfaces a browser actually renders as documents. JSON API responses are deliberately excluded: no browser parses `application/json` as a document, so a CSP there protects nothing.
  The mechanism worth checking is how the inline blocks are handled. Both pages carry inline `<script>` and `<style>`, and the easy answer — `script-src 'unsafe-inline'` — would re-permit exactly the injection class CSP exists to stop, so closing C5 that way would have been overclaiming. Instead the sha256 hashes are computed **at startup from the same bytes the browser is about to receive**, so `script-src` stays `'self'` plus exact hashes, and the policy cannot go stale when someone edits the HTML. `frame-ancestors 'none'` is the other load-bearing directive: the admin UI holds a token in `localStorage`, so framing it is a real attack. The renderer's existing meta-tag CSP is unaffected — a header and a meta policy are enforced independently, so the added header can only tighten. Covered by `server/tests/test_csp.py`.

### C6. Metrics bearer token uses non-constant-time comparison
- **File:** `server/chapter_agent.py:7719` (around /metrics handler)
- **Detail:** The `/metrics` endpoint compares `METRICS_BEARER_TOKEN` with `!=` instead of `hmac.compare_digest`. This is a **timing oracle** allowing an attacker to brute-force the token character by character.
- **Exploitation:** Local or remote attacker with sufficient timing resolution (sub-millisecond) can recover the full token within ~10 minutes per 64 hex characters.
- **Fix:** Use `hmac.compare_digest()` like `admin.py:175` does for the admin token.
- **Disposition — FIXED; severity was OVERSTATED.**
  On the rating: Critical is defined at the top of this document as "leads to total system compromise with low attack complexity". What `METRICS_BEARER_TOKEN` protects is the Prometheus exposition at `/metrics` — counters and gauges. Recovering it grants read access to operational metrics. It is not an authentication credential for any other surface, it grants no write anywhere, and it is not a step toward system compromise. The stated exploitation figure — "the full token within ~10 minutes per 64 hex characters" — is asserted with no measurement behind it and does not survive scrutiny: Python's `!=` on `str` compares length before content and short-circuits on the first differing byte, so the signal is nanoseconds wide and is buried under network jitter and interpreter scheduling. A remote timing attack at that resolution is a research result under laboratory conditions, not a ten-minute operation. This belongs at Medium.
  On the defect: fixed. The handler compares with `hmac.compare_digest`, encoding both sides to bytes so a token the client sends as raw non-ASCII returns 401 rather than raising. The `Bearer ` prefix is still checked with a plain comparison: the scheme name is not secret. `admin.py` and `auth_verify.py` already used `compare_digest` for the same job, and a codebase that is constant-time in two places out of three leaves a reader guessing which was deliberate — that inconsistency was the argument for changing it, more than the timing signal itself. Pinned by `server/tests/test_env_flags_convention.py`, which reads the handler's AST, so reverting to an operator comparison fails the suite.
  Still true and not addressed here: `/metrics` is **not** in `RATE_LIMITED_GET_PREFIXES`, so nothing throttles repeated requests to it. Adding it would change how often a Prometheus scraper may poll, which is a deployment decision rather than part of this fix.

### C7. innerHTML with recovery phrase in SMB funnel
- **File:** `smb_funnel/src/app.js:154-159`
- **Detail:** The BIP-39 recovery phrase words are rendered via `innerHTML`:
  ```javascript
  chip.innerHTML = `<span class="word-n">${i + 1}</span>${w}`;
  ```
  The recovery phrase (`w`) comes from a server response. If an attacker can influence the response (MitM, compromised server, XSS in upstream), they can inject arbitrary HTML/script.
- **Exploitation:** Script execution in the context of the recovery phrase page gives attacker the **full agent signing key** (the recovery phrase itself).
- **Fix:** Use `textContent` instead of `innerHTML`. Never render secrets through HTML-parsing sinks.
- **Disposition — FIXED.** `innerHTML` is gone from the SMB funnel entirely — `grep -c innerHTML smb_funnel/src/app.js` returns 0, and the same is true of every source file in that bundle. The chip that carried the bug is now built as DOM nodes in `smb_funnel/src/render.js` (`buildPhraseChips`): the index is a `<span>` element and the word is a **text node**, so a phrase word containing `<script>` is displayed rather than parsed. No HTML string is constructed anywhere on that path.
  The part that keeps it fixed is `smb_funnel/tests/source-guard.test.mjs`, which fails the build if `innerHTML`, `outerHTML` or `insertAdjacentHTML` reappears in the bundle's source (comment-stripped first, so a mention in prose does not trip it and a real use cannot hide in one). The render tests additionally drive the code under a stub DOM that throws on any `innerHTML` access, so a regression fails as a test error rather than as a silently reintroduced sink.

### C8. GITHUB_TOKEN has write-all permissions (no permissions: block)
- **File:** `.github/workflows/ci.yml` — no `permissions:` at workflow or job level
- **Detail:** GITHUB_TOKEN defaults to `write-all` (contents:write, issues:write, pull-requests:write, etc.). A malicious PR that achieves code execution in CI can push code, create releases, modify issues.
- **Exploitation:** Supply-chain attack: compromised CI runner → write to repository → inject malicious code into future releases.
- **Fix:** Set `permissions: read-all` at workflow top level, with per-job write overrides only where needed (none appear needed).
- **Disposition — FIXED.** Every workflow in `.github/workflows/` now declares `permissions: contents: read` at the top level — `ci.yml`, `full-history-secret-scan.yml`, `receipt-verify-canary.yml` and `catalog-canary.yml`. No job overrides it, so no job holds a writable `GITHUB_TOKEN`. `ci.yml` carries the trap in a comment next to the block: a job-level `permissions:` **replaces** the workflow-level one rather than merging with it, so a future job that needs one write scope must restate `contents: read` or it will break `actions/checkout`.

### C9. Broadcast signing enforcement defaults OFF in code (env.example says ON — mismatch)
- **File:** `server/federation_signing.py:68-71`, `server/federation_discovery.py:25-32`
- **Detail:** `FEDERATION_ENFORCE_SIGNED_BROADCASTS` and `FEDERATION_REQUIRE_SIGNED_RECORDS` both default to `false`/`off` in the code. The `.env.example` correctly sets both to `true`, but any deployment that copies `.env.example` before those lines were added, or upgrades without the new variables, silently runs with **no signed-federation enforcement**.
- **Exploitation:** A malicious peer (or attacker able to send HTTP to the broadcast inbox) can forge broadcasts under any org's name, and a cheating registry can inject tampered records with impunity.
- **Fix:** Default both to `true` in code. The migration window is over.
- **Disposition — FIXED.** Both flags now default `True`: `federation_signing.enforcement_enabled()` returns `env_flags.security_flag("FEDERATION_ENFORCE_SIGNED_BROADCASTS", default=True)` and `federation_discovery` does the same for `FEDERATION_REQUIRE_SIGNED_RECORDS` (see C13). The default direction is no longer an accident of how a parsing expression happens to branch — `security_flag` takes `default` as a **mandatory keyword argument**, so the direction a security flag fails when nobody set it has to be written down at the call site.
  The second half matters as much as the default: `security_flag` treats unset, empty, whitespace-only **and unrecognised** values as "the operator did not decide", and returns `default` for all four. `FEDERATION_ENFORCE_SIGNED_BROADCASTS=ture` is a typo, not a decision to disable enforcement, and the inline `in {"1","true",...}` form this replaced would have read it as one. Enforcement can now only be turned off by an explicitly recognised falsey spelling. `server/env_flags.py` lists the four incidents that produced this module, C9 among them.

### C10. Broadcast inbox accepts POST without middleware authentication
- **File:** `server/auth_verify.py:203-208`
- **Detail:** `POST /api/federation/broadcast/inbox` is in `OPEN_POST_PATHS` — the auth middleware does NO signature verification for this path. All protection is handler-level (federation registry check + optional S2S signing). If the handler's origin-whitelist check is bypassed (e.g., origin spoofing through a shared federation registry), the inbox is wide open.
- **Exploitation:** An attacker who can claim a known `origin_chapter_id` (via registry poisoning, DNS rebinding, or HTTP header injection) can push arbitrary broadcasts to all org members.
- **Fix:** Either (a) require S2S signature at middleware level, or (b) narrow the open path to only accept verified signatures.
- **Disposition — MITIGATED.** The finding's title is still literally true and the exploitation path it describes is closed.
  **What remains:** `/api/federation/broadcast/inbox` is still in `OPEN_POST_PATHS`, so the auth middleware still performs no signature verification for this path. Option (a) was not taken.
  **What changed:** the handler is no longer protected by an origin whitelist alone. It now verifies an S2S Ed25519 signature on every broadcast via `federation_signing.verify_inbound`, and — because C9 flipped the default — enforcement is **on** unless an operator explicitly disables it. An unverified or absent signature returns 403; under enforcement a legacy no-timestamp signature is rejected rather than accepted as `ok_legacy`, so replay protection is mandatory. The verification key is derived from the peer's **pinned DID**, not from the endpoint the registry served, which is what closes the quoted exploitation: an attacker who poisons the registry to claim a known `origin_chapter_id` still cannot supply the key their forged broadcast is checked against. A pin lookup that errors returns 503 rather than silently downgrading a pinned peer to endpoint trust (F5 fail-closed). This is option (b), enforced in the handler rather than the middleware.
  **Two stale comments to correct when this path is next touched** — both now say the opposite of the code: the `OPEN_POST_PATHS` entry still reads "When server-to-server Ed25519 signing lands, move this entry to `SELF_SIGNED_POST_PATHS`" (it has landed), and the handler comment still reads "REJECT only when enforcement is enabled (default OFF)" (the default is ON).

### C11. ORRERY_KEY_SECRET defaults empty — org signing key stored plaintext at rest
- **File:** `server/sovereign_identity.py:110-122`, `.env.example:64`
- **Detail:** The `.env.example` ships `ORRERY_KEY_SECRET=` (empty). On first boot without this set, the org's **entire Ed25519 signing identity** is stored as plaintext in the database and on disk. A DB dump or backup is full identity-forgery material. The loud warning is printed but the server proceeds.
- **Exploitation:** Database dump or backup leaks the org's private signing key — attacker can sign ARP receipts, VRP attestations, and federation broadcasts as the org.
- **Fix:** Have `orrery-up` generate a random `ORRERY_KEY_SECRET` during bootstrap so new deployments are encrypted by default.
- **Disposition — FIXED.** `orrery-up` already generated one (`SECRET_KEYS`, 64 hex chars), so the self-hosted install path was never the gap — CLI-deployed services were. **Measured before changing the default: none of the three live orgs had `ORRERY_KEY_SECRET` set**, so all three were storing the signing key in plaintext. Sealing is now required by default (`ORRERY_REQUIRE_SEALED_SECRETS`, via `env_flags.security_flag`): `ensure_chapter_keypair` raises at startup rather than minting or reading a plaintext key, and existing plaintext rows/files are sealed in place — the same key bytes re-encoded, so `did:key` is unchanged and no rotation or re-pinning is involved. **Deploy ordering: `ORRERY_KEY_SECRET` must be set on each live service before this code ships to it, or the service will not boot.**

### C12. Index has open write surface; `INDEX_ATTESTATION_GATE=off` allows arbitrary record takeover
- **File:** `index/main.py:171-190`, `index/attestation_gate.py:103-147`
- **Detail:** The lean index (`index/`) is designed with open writes — the threat model relies on self-certifying records + consumer-side DID pinning. When `INDEX_ATTESTATION_GATE=off`, any party with HTTP access to the index can overwrite ANY record, including changing the endpoint for existing `agent_id` values. Even with attestation gate ON, if `INDEX_WRITE_TOKEN` is unset, writes are unauthenticated.
- **Exploitation:** Registry poisoning: attacker redirects resolver queries to a malicious endpoint for any registered agent.
- **Fix:** Document that production deployments MUST set both `INDEX_WRITE_TOKEN` and `INDEX_ATTESTATION_GATE=true`. Consider enforcing attestation gate by default.
- **Disposition — FIXED**, and by enforcement rather than by documentation — the audit's "consider" option, taken for both halves.
  **Attestation gate:** `index/main.py` reads `env_flags.security_flag("INDEX_ATTESTATION_GATE", default=True)`. The gate is on unless deliberately switched off, so the first valid attested write TOFU-pins the record's DID and every later write to a pinned id must be attested by that DID — the record-takeover path in the finding is rejected at the write surface. `INDEX_ATTESTATION_GATE=off` still restores the pure-open posture, which is wanted for tamper drills.
  **Write token:** the sharper half, because "unset means open" was the actual live exposure — measured 2026-08-03, neither gate variable was set on the deployed index, so it was accepting unauthenticated writes. `write_token_required()` now defaults `True`, and an unset `INDEX_WRITE_TOKEN` makes the index **refuse writes with 503** naming both remedies, rather than accepting them. Deliberately accepting unauthenticated writes is now an explicit `INDEX_WRITE_OPEN=true`, so the drill posture is a recorded decision instead of a default.
  Both go through the same `env_flags.security_flag` contract described in C9, so neither can be disabled by a misspelling.

### C13. Registry attestation required defaults OFF in code
- **File:** `server/federation_discovery.py:25-32`
- **Detail:** `FEDERATION_REQUIRE_SIGNED_RECORDS` defaults to `false`. Without enforcement, a cheating registry can inject records with tampered endpoints, and the org will attempt to federate with them. Self-certifying attestations exist but are only advisory when enforcement is off.
- **Exploitation:** Registry operator (or attacker who compromises registry) can redirect federation traffic to attacker-controlled endpoints.
- **Fix:** Default to `true`. The attestation machinery is fully implemented and tested.
- **Disposition — FIXED.** `federation_discovery.py:39` now returns `env_flags.security_flag("FEDERATION_REQUIRE_SIGNED_RECORDS", default=True)`, so a registry record without a valid self-certifying attestation is **skipped** rather than probed unverified. See C9 for why an unrecognised spelling cannot silently disable it. Two scope notes a reader should have: peers on the operator-anchored `KNOWN_CHAPTER_ENDPOINTS` allowlist are exempt either way — the operator anchored those out of band, which is a stronger claim than an attestation — and the newer federation-directory source is born fail-closed regardless of this flag, admitting a record only with a valid attestation and probing the endpoint the org **signed** rather than the directory-served copy.

### C14. Docker containers run as root with no read-only filesystem
- **File:** `infra/Dockerfile.server`, `infra/Dockerfile.agent`, `infra/Dockerfile.index`, `docker-compose.yml`
- **Detail:** All Dockerfiles lack a `USER` directive (run as root). Compose has no `read_only: true`, `security_opt: [no-new-privileges:true]`, or `cap_drop` directives. Containers have default broad capabilities with writable root filesystems.
- **Exploitation:** Any container compromise grants full root access inside the container, with broad kernel capabilities, enabling container escape or persistent backdoor.
- **Fix:** Add `USER` directive to all Dockerfiles. Add `read_only: true`, `security_opt: [no-new-privileges:true]`, and `cap_drop: [ALL]` with selective `cap_add` to compose services.
- **Disposition — MITIGATED.** The Dockerfile half is done; the compose half covers the internet-facing service only.
  **Done:** all three application images now drop root — `USER orrery` in `infra/Dockerfile.server`, `infra/Dockerfile.index` and `agent/infra/Dockerfile.agent`. The `server` compose service carries the full set: `read_only: true`, `security_opt: [no-new-privileges:true]`, `cap_drop`, and `tmpfs` for the paths that genuinely must be writable (one env default had to move off a relative path under `read_only`).
  **What remains:** `agent`, `db` and `db-backup` have no `read_only`, `cap_drop` or `no-new-privileges` in `docker-compose.yml`. `db` and `db-backup` run the upstream `pgvector/pgvector:pg15` image, which drops to the `postgres` user itself, so those two are not running application code as root — but they are unconstrained on capabilities and filesystem. `agent` runs as `orrery` from its Dockerfile and is behind an opt-in profile (`profiles: ["agent"]`), so it is absent from a default `up`. Extending the compose directives to the remaining services is the outstanding work.
  **One citation correction:** the finding lists `infra/Dockerfile.agent`. That path has not existed since the agent-in-compose revert; the file is `agent/infra/Dockerfile.agent`, built with `context: agent`. No `infra/Dockerfile.agent` was present when the audit was written.

---

## 🟠 HIGH SEVERITY FINDINGS (13)

### H14. `POST /t/{tenant_id}/book` is unauthenticated, unbounded and unrated on a live public host — **FIXED**

**Component:** `smb_host` (added to scope 2026-09-12; this component had zero
references across the previous 62 findings).

**What it is.** `smb_host` gates `POST /provision` on a bearer token. It does not
gate `POST /t/{tenant_id}/book` at all, and that route does real, persistent
work: it records a booking and signs an ARP receipt into the tenant's Agency Log.
No field on `BookRequest` carries a `max_length`, and neither `smb_host` nor
`smb_signup` sets a request body cap.

**Measured, not inferred.**

- Against the deployed host, `POST /t/<unknown>/book` with no credential returns
  **404, not 401** — the route is open and reaches tenant lookup, so for a real
  tenant id an anonymous caller reaches the booking path.
- Locally, a single anonymous request carrying a 2 MB `notes` field returned
  **200** and grew the tenant store by **4,015,349 bytes** — roughly twice the
  input, because the caller's text is persisted in the booking store *and* again
  inside the signed receipt. Five further requests were accepted without refusal.

**Why it compounds.** `smb_signup` exists precisely because a token bounds *who*
may call and never *how much*; its README records a real incident where a valid
token provisioned 60 tenants in 3.7 s. That reasoning was applied to
provisioning and not to booking. `smb_signup` carries a per-source rate limit;
`smb_host` carries none, and `smb_host` is reachable directly, so the limiter is
bypassed by addressing the host instead of the façade. This host also has **no
delete route**, stated in its own configuration comments, so the growth is
permanent.

**Not claimed:** no confidentiality or integrity impact was found. This is
availability and unbounded cost. Rated High rather than Critical on that basis.

**FIXED — 2026-09-12.** Three bounds, which fail differently and only one of
which is a cap. Per-field `max_length` bounds what can be STORED and does so
independently of transfer encoding — the load-bearing control. A
`Content-Length` body cap bounds what is READ before parsing, and is evadable by
a chunked sender omitting the header, which is stated in the middleware rather
than left for a reader to discover. A per-source sliding-hour limiter slows one
source; it is explicitly not the cap, because the window is in-process, a restart
empties it and a distributed source never fills it — the same warning
`smb_signup.RateLimiter` already carries, worded alike so an operator reading
either draws the same conclusion. The limiter keys on the same
`_caller_discriminator` the host already records for provisioning, so the limiter
and the audit trail cannot disagree about who a caller was, and the rate check
runs BEFORE the tenant lookup so the limiter cannot become a tenant-existence
oracle.

Re-running the original exploit against the fix: the 2 MB `notes` request now
returns **413** and grows the store by **0 bytes** (was 200 / 4,015,349); 130
rapid anonymous bookings now yield 120 through then **429** (was all accepted).
Four regression tests, `smb_host` suite 120 → 124 passing.

**Deployed 2026-09-12T22:27Z** at `6eea2e8`, and verified against the live host
rather than inferred from the merge: a 200 KB body now returns **413** where it
previously returned 404 having accepted the body; a 10 KB `notes` field returns
**422**; a well-formed small body still returns 404, so the path works. Tenant
count unchanged at 83, so the volume holding every tenant's Ed25519 keystore
survived the rollout. **The live 429 is not verified** — demonstrating it needs
roughly 120 real requests against a production service, which is not worth the
noise to confirm a bound that is unit-tested; that gap is stated rather than
implied.

**What was checked here and held up**, recorded so the finding is not read as a
verdict on the component as a whole: `_slugify` is traversal-safe (`../../etc`
→ `etc`, verified against eight probes); a duplicate-name refusal deliberately
does not leak the existing tenant's id, which would turn a name probe into a
business directory; the provisioning token comparison is constant-time; a public
address configured without a token is refused at startup rather than served open;
`recovery_phrase` is returned once and stored as `None`; and no log line carries
a secret.



### H1. TOFU (Trust On First Use) inherently weak for agent registration
- **File:** `server/auth_verify.py:776-783`
- **Detail:** First registration with an `X-Agent-DID-Key` creates a permanent binding with no out-of-band verification. A network-level attacker who intercepts the very first `POST /api/members` from a genuine agent can supply their own `did:key` and permanently own that `agent_id`.
- **Fix:** Add first-registration key confirmation (the server signs a challenge, the client proves key possession before the binding is accepted). Or document as an accepted TOFU residual.
- **Disposition — ACCEPTED.** The second option, deliberately. This is not an oversight that survived triage; it is inherent to the trust model, and a challenge-response at first registration would not change it. The proposed fix proves possession of *a* key — but a MitM who is already substituting the registration is substituting their own key and can answer the challenge with it perfectly. Key confirmation defeats a passive observer, and a passive observer was never the threat here. There is no way to bind a first contact to the right party using only that first contact; it requires an out-of-band anchor, which is exactly what TOFU means.
  **What bounds it, all verified in code:**
  - The binding is **self-authenticating**: the `did:key` presented must sign the request, and the pubkey is extracted from the DID itself. An attacker must hold the private key, not merely assert a DID.
  - It is **once**. Any later request claiming the same `agent_id` with a different `X-Agent-DID-Key` is rejected with an explicit `key_mismatch` rather than a generic failure — so the genuine agent's next request fails loudly and auditably instead of silently competing.
  - **HMAC key-from-header acceptance was removed.** `X-Agent-Public-Key` is not proof of anything (HMAC is symmetric and has no public key), and accepting it would have let any caller register as any identity. HMAC members are provisioned out of band.
  - **Out-of-band anchoring is available and is the real answer** for parties that need it: `KNOWN_CHAPTER_ENDPOINTS` for peers, consumer-side DID pins, and publishing early so the genuine record exists before a squatter's.
  - The residual is written down where a newcomer meets it, not only here: `docs/JOIN.md` §"What TOFU does and does not protect" states plainly that first use is the exposed moment, and `docs/CLAIMS.md` records the first-contact gap as open rather than papering over it.

### H2. HMAC legacy auth path remains active for reads
- **File:** `server/auth_verify.py:834-846`
- **Detail:** Symmetric-key HMAC means the server (or anyone with DB access to the `signing_secret`) can forge any HMAC-only agent's signature. The comment states "reads still accept it" — GET requests from HMAC-only agents are forgeable.
- **Fix:** Deprecate HMAC entirely. Ed25519 has been the default for multiple releases.
- **Disposition — MITIGATED.** HMAC has not been removed, so the finding as written stands.
  **What remains:** `auth_verify.py` still accepts `hmac-sha256` on GET. The symmetry is unchanged — anyone holding an HMAC member's `signing_secret`, which includes the server and anyone with database access, can forge that member's read requests.
  **What changed:** the blast radius is now reads only, and forging an identity from scratch is closed. Mutations are rejected by the method-binding gate, which refuses `hmac-sha256` and v0.2 on POST/PUT/PATCH/DELETE — so an HMAC-only member authenticates GETs but must hold an Ed25519 key to change anything. And HMAC trust-on-first-use is gone: an `X-Agent-Public-Key` header is no longer accepted as bootstrap material, because it proves nothing about a symmetric secret, and accepting it had allowed an arbitrary caller to authenticate as an arbitrary identity. HMAC members are provisioned out of band.
  Removal is the remaining work and is a compatibility decision rather than a code one — it breaks any member that has not moved to Ed25519.

### H3. OpenClaw skill private key unencrypted at rest
- **File:** `skill/helpers/sign_request.py:133-142,173-229`
- **Detail:** The OpenClaw skill stores its Ed25519 private key in PKCS8 PEM format at `$OPENCLAW_HOME/skills/orrery-org/identity.json` with 0o600 permissions but **no encryption**. Documented in `skill/SECURITY.md` but any process with the same user or root access can steal the key.
- **Exploitation:** Local privilege escalation (or shared hosting) yields the agent's full signing identity.
- **Fix:** Encrypt the private key at rest using a passphrase-derived key (same pattern as `agent/community_member/crypto.py`).
- **Disposition — FIXED, opt-in.** `ORRERY_SKILL_KEY_PASSPHRASE` stores the key as an encrypted PKCS8 PEM (PBES2/AES via `BestAvailableEncryption`) instead of a plaintext one; an existing plaintext key is re-encrypted in place, unchanged, on the next run. Scope stated plainly in `skill/SECURITY.md`: this removes the key from disk images, filesystem backups and host snapshots. It does **not** close the exploitation path quoted above — a same-uid or root process can read the passphrase from the environment it must be supplied in. That is why it is opt-in rather than required: mandating it would relocate the secret rather than protect it, and would break every existing install for no change in that threat.

### H4. Federation outbound signing silently degrades when no keypair exists
- **File:** `server/federation_signing.py:114-116`, `server/federation_signing.py:148-151`
- **Detail:** Both `sign_outbound()` and `sign_request()` return empty dicts `{}` when the org has no Ed25519 keypair. The caller sends unsigned broadcasts/requests with no indication to the operator. The receiver's enforcement is the only protection.
- **Exploitation:** A first-boot or misconfigured deployment sends all federation traffic unsigned, making it forgeable by any network-level attacker.
- **Fix:** Log loudly (or fail) when signing is requested but no keypair exists. At minimum, ensure `ensure_chapter_keypair` completes before any federation operation.
- **Disposition — FIXED**, taking the stronger of the two options. Neither `sign_outbound` nor `sign_request` can return `{}` any more: both raise `federation_signing.OutboundUnsigned` when the org has no Ed25519 keypair loaded. A caller cannot accidentally send unsigned, because there is no longer a return value that means "unsigned" — the failure is an exception at the signing site rather than a silent empty dict handed to `httpx`. Callers handle it by **not sending**: `query_chapter` catches it, logs `[federation][ERROR] not querying <peer>` and returns `None` (see H7). Sending unsigned and letting the receiver decide was the part that could not be observed from this side, which is why the degradation went unnoticed. The audit's "at minimum" half is also done — see H6 for the ordering fix that guarantees the keypair exists before any federation operation runs.

### H5. No client-side pre-commit hooks (secrets/lint gating)
- **File:** No `.pre-commit-config.yaml`, no `.husky/`, no pre-commit hooks
- **Detail:** There is no client-side gating of commits. Secrets, lint errors, format issues, and other problems are only caught after `git push` via CI. A developer can commit secrets and only discover the problem when CI fails or after the secret is already in the git history.
- **Fix:** Add `pre-commit` with hooks for: `ruff` lint, `ruff format --check`, a secrets scanner (e.g., `detect-secrets` or `trufflehog`), and `mypy`.
- **Disposition — FIXED**, with the finding's framing corrected in the artefact itself. `.pre-commit-config.yaml` now ships `gitleaks` for secrets plus the lint/format/type hooks, every version pinned to what `ci.yml` installs — a hook that lints with a different `ruff` than the pipeline reports different results than the gate, and a developer learns to distrust the hook.
  The correction is written at the top of the file and is worth repeating here: **this is not a control.** Hooks run on a developer's machine and `git commit --no-verify` bypasses them silently. The enforcement is the CI `secret-scan` job, which cannot be skipped. The value of the hook is latency, not coverage — for a secret specifically, catching it in two seconds instead of after it is in history is the difference between a fix and a credential rotation. Filing the absence of client-side hooks as High reads as if it were the gate; it is the fast path in front of one. The known drift risk (this file mirrors `ci.yml`'s pinned tools by hand, because Orrery has no `make ci-local` target to point both at) is called out in the config rather than papered over.

### H6. First boot registers before `ensure_chapter_keypair` runs (~30s attestation gap)
- **File:** `server/nanda_registry.py:97-98`, `server/sovereign_identity.py:151-228`
- **Detail:** Registration with NEST/NANDA Index occurs during `lifespan` startup. `ensure_chapter_keypair` runs later in the lifetime. For the first ~30 seconds (until the first heartbeat), the org registers WITHOUT a signing key — no attestation accompanies the registration.
- **Fix:** Ensure the keypair is initialized before any registry registration.
- **Disposition — FIXED.** `sovereign_identity.init()` and `await ensure_chapter_keypair(...)` now run in `lifespan` **before** `nanda_registry.init(...)` and `federation_discovery.init(...)`, so the signing key exists before anything registers or federates. Registration previously ran ~150 lines ahead of it. This is ordering, not configuration, so it is fixed by moving the call rather than by adding a flag — there is no way to turn it off.
  The second half of the fix is that the invariant is now **observable**: a normal boot used to print nothing when the keypair loaded (only on first mint or on the seal-in-place migration), so the ordering was invisible in production, which is why the gap went unnoticed in the first place. Startup now logs `[identity] chapter signing key READY before registration — <did:key>` on success, and an explicit `[identity][ERROR] ... registration and federation will be unsigned` if the keypair is absent afterwards. An invariant nothing can observe regresses silently; that log line is part of the fix, not decoration.

### H7. Peer A2A queries are unsigned (no identity proof)
- **File:** `server/federation_discovery.py:497-518`
- **Detail:** `query_chapter()` makes an unsigned POST to the peer's `/a2a` endpoint. The receiving peer's middleware protects this (POST is auth-gated), but the querying side provides no proof of its identity.
- **Fix:** Sign cross-org A2A queries with the S2S Ed25519 scheme as `sign_request` already does for member-directory reads.
- **Disposition — FIXED**, by the route the finding recommends. `query_chapter()` now calls `federation_signing.sign_request(_agent_id, "POST", "/a2a")` and sends the resulting headers with the query, so the peer learns who is asking. The scheme is the **same** `sign_request` already used for member-directory reads rather than a second signing path built for this call site — a parallel implementation is the divergence class this repository keeps paying for, and two signing paths mean two sets of verification bugs.
  Behaviour when signing is impossible is worth stating: `sign_request` raises `OutboundUnsigned` rather than returning empty headers (H4), and `query_chapter` catches it, logs `[federation][ERROR] not querying <peer>` and returns `None`. The query is abandoned; it is never downgraded to an unsigned send.

### H8. Admin surface unsecured by default (ORG_ADMIN_TOKEN blank in .env.example)
- **File:** `.env.example:101-103`
- **Detail:** `.env.example` ships `ORG_ADMIN_TOKEN=` (empty). The admin API surface is handler-gated by a bearer token, but with no default, first-boot deploys have an open admin surface until the operator manually sets the token. The token IS generated and printed on first boot — but only if the env var is not set, so a deploy with the stock `.env` gets a token. The risk is when the operator copies `.env.example` to `.env` before first boot but doesn't realize `ORG_ADMIN_TOKEN` needs setting.
- **Fix:** Have `orrery-up` or the server generate a random token on first boot regardless of the env var setting, and always require a token.
- **Disposition — INCORRECT.** The scenario the finding describes was not reachable, and was not reachable when the audit was written. The finding's own text half-concedes this ("a deploy with the stock `.env` gets a token") and then states the opposite as the risk. Two facts settle it, both in `server/admin.py`:
  1. **A blank `ORG_ADMIN_TOKEN=` is not "set".** `admin.init()` reads `os.environ.get("ORG_ADMIN_TOKEN", "").strip()`, and an empty string is falsy, so the `or` chain falls straight through to the on-disk token file and then to `generate_token()`, which writes the token and returns it for the one-time startup banner. The operator who copies `.env.example` to `.env` — precisely the case the finding calls out — lands in the generate branch, identically to an operator who never set the variable at all. There is no branch in which a blank value is adopted as the token.
  2. **Even if one existed, an empty token authenticates nothing.** `verify_admin_token()` opens with `if not provided or not _admin_token: return False`, documented as refusing to authenticate against an unset admin credential. An empty stored token cannot be matched, including by an empty presented token. "Open admin surface" is not the failure mode available here; the failure mode is an admin surface nobody can reach.
  **Evidence that this predates the audit:** the fail-closed check in `verify_admin_token` has been present since `98826ab` (2026-06-20, initial public release) and the `.strip()`-based env resolution since `ffa6496` (2026-06-22). The audit is dated 2026-07-30. Neither line was written in response to this finding.
  **The one true residual, which is not what was filed:** a token that is generated is printed exactly once, so an operator who misses the banner must read it off disk. That is an operability wrinkle, not an unsecured admin surface.

### H9. Legitimate peer key rotation causes complete federation breakdown until operator clears pin — **FIXED**
- **File:** `server/federation_policy.py`, `server/chapter_agent.py`
- **Detail (as found):** When a peer rotated their signing key, `check_and_pin_did()` returned `("mismatch", old_did)` and the pin was KEPT. Every subsequent signature verification against the pinned old DID failed, with no automated recovery — an operator had to call `clear_did_pin`. The peer was isolated from the federation until that happened.
- **Interim state, recorded because it is the more interesting half:** a first pass shipped `verify_rotation_attestation` with nine refusal tests — and **nothing called it**. No endpoint, and `check_and_pin_did` never consulted it, so the live symptom persisted unchanged while the row looked addressed. Orrery had built the half that needs no agreement between peers (verification) and left the half that does (transport) unbuilt. This row correctly stayed open through that period.
- **Fix (spec-first, not code-first):** the behaviour is now specified as **NANDA Chapter Protocol v0.6 §8.5** (the umbrella at `60cc22d`) rather than defined by whichever runtime shipped first — two peers must agree on the bytes, so a rotation one accepts and the other rejects looks exactly like a takeover. Orrery now:
  - **publishes** its rotation chain at `GET /.well-known/nanda-chapter-rotation.json` (§8.5.2, public by design — a peer needs it precisely when it cannot verify our signatures);
  - **pulls and verifies** a peer's chain when `check_and_pin_did` sees a mismatch, updating the pin **only** on a chain that walks validly from the existing pin to the DID actually presented, and otherwise keeping the pin exactly as before;
  - walks **chains**, not single attestations, so a receiver two rotations behind can still prove continuity — atomically, so a broken link keeps the original pin rather than advancing to a valid prefix;
  - refuses all nine §8.5.4 classes, **driven from the umbrella's shipped vectors** (`vectors/rotation/v06/`, digest-pinned) rather than local fixtures, so conformance is with the spec rather than with itself.
- **Still true and deliberately unchanged:** an unproven mismatch never moves the pin, and `clear_did_pin` remains for a genuinely lost key. Peers that have not implemented §8.5 keep their pin on our rotation — today's fail-closed behaviour, not a new failure — so **peers must be upgraded before a rotation is performed**.
- **Disposition — FIXED.** Re-verified against `main`: the rotation chain is published at `GET /.well-known/nanda-chapter-rotation.json`, `federation_policy.check_and_pin_did` consults a peer's chain on mismatch and updates the pin only on a chain that walks validly from the existing pin to the DID actually presented, and the wiring itself is pinned by tests (`test_h9_rotation_attestation.py`, `test_peer_rotation_wiring.py`) — the last of which exists because the first pass shipped a verifier that nothing called.

### H10. No path parameterization for Docker base images
- **File:** All Dockerfiles (Dockerfile.server, Dockerfile.agent, Dockerfile.index, Dockerfile.db), docker-compose.yml
- **Detail:** Docker images use floating tags (`python:3.12-slim`, `pgvector/pgvector:pg15`) without SHA digests. A tag change on the registry side (e.g., `python:3.12-slim` is updated to a new patch) changes every rebuild without notice.
- **Fix:** Pin base images by SHA digest (`python:3.12-slim@sha256:...`). Use a tool like `renovate` to automate digest updates.
- **Disposition — FIXED.** Every base image in the tree is now digest-pinned, in both the Dockerfiles and `docker-compose.yml`. `infra/Dockerfile.server`, `infra/Dockerfile.index` and `agent/infra/Dockerfile.agent` all pin `python:3.12-slim@sha256:57cd7c3a…`; `infra/Dockerfile.db` and all three `image:` references in compose pin `pgvector/pgvector:pg15@sha256:a20a57d7…`. A registry-side tag change no longer alters a rebuild. The `renovate` half of the recommendation was not adopted, so digest bumps are manual — the trade is that a pin cannot move without a reviewed commit.
  Note the same path correction as C14: the finding lists `Dockerfile.agent` under `infra/`; it lives at `agent/infra/Dockerfile.agent`.

### H11. `runtime.txt` declares Python 3.11.9 but 3.12 deployed everywhere else
- **File:** `server/runtime.txt:1`
- **Detail:** `runtime.txt` says `python-3.11.9`. The actual deployment (`Dockerfile.server`) uses `python:3.12-slim` (3.12). CI uses `python-version: "3.12"`. The `runtime.txt` is inconsistent and could cause breakage on Heroku-style deploys.
- **Fix:** Update to match the actual deployed version (3.12.x), or remove the file if it's unused.
- **Disposition — FIXED**, by the second option: `server/runtime.txt` no longer exists. The file was unused — nothing in this repository's deployment path reads it, and the Heroku-style buildpack it exists for is not how anything here is deployed. Deleting it removes the contradiction outright rather than leaving a third place that has to be kept in step with `Dockerfile.server` and `ci.yml`. Python 3.12 is now declared in exactly the two places that consume it.

### H12. No vulnerability scanning in CI (no Dependabot/pip-audit)
- **File:** `.github/workflows/ci.yml` — no scanning step
- **Detail:** The CI pipeline has structual pin checks (exact sm-* versions) but no CVE scanning. A dependency with a known vulnerability at its pinned version will stay vulnerable until manually discovered.
- **Fix:** Add `pip-audit` (or `snyk test`, or GitHub Dependabot alerts) to CI.
- **Disposition — FIXED.** `ci.yml` now runs `pip-audit==2.9.0` (itself pinned) across the requirements files, so a pinned dependency with a published advisory fails the pipeline instead of waiting to be noticed. Exceptions are not silent: an advisory can only be waived by adding its id to `.github/pip-audit-ignore.txt` with a date and a reason, which puts every waiver in one reviewable file rather than in a `--ignore-vuln` flag buried in a job step.
  Adjacent and worth recording on the same row, since the finding is about what CI does not scan for: a `secret-scan` job now runs `gitleaks` — pinned by version *and* verified by checksum before it executes — over the PR's commit range, and `full-history-secret-scan.yml` covers the whole history. Dependabot was not adopted; `pip-audit` in the pipeline covers the same ground with the failure visible on the PR.

### H13. `innerHTML` with user data in SMB funnel receipt display
- **File:** `smb_funnel/src/app.js:217-247`
- **Detail:** Receipt details are rendered via `innerHTML` with `escapeHtml()` wrapping user data. The `escapeHtml()` function (line 279-282) only escapes `& < > " '` — this is insufficient if data appears in attribute-value contexts, and a bypass in `escapeHtml` would be a full XSS.
- **Fix:** Use `textContent` for all user-controlled data. Reserve `innerHTML` only for hardcoded trusted HTML.
- **Disposition — FIXED**, by the same change that closed C7, and more completely than the recommendation asks. The receipt panel is now built in `smb_funnel/src/render.js` as DOM nodes with user data as text nodes, so `escapeHtml()` is no longer load-bearing — the attribute-context concern and the "a bypass in `escapeHtml` would be a full XSS" concern both dissolve when no HTML string is parsed. The recommendation's second sentence ("reserve `innerHTML` only for hardcoded trusted HTML") was **not** taken, deliberately: `innerHTML` is reserved for nothing at all. It is absent from the bundle, and `smb_funnel/tests/source-guard.test.mjs` fails the build if it returns — a rule with no exceptions is one nobody has to adjudicate.

---

## 🟡 MEDIUM SEVERITY FINDINGS (20)

### M1. `store_agent_key` OR-preserves old keys on partial update
- **File:** `server/auth_verify.py:458-463`
- **Detail:** `store_agent_key` uses `or` coalescing: `ed25519_pubkey or existing.get("ed25519_pubkey", "")`. If a caller passes empty `ed25519_pubkey`, the OLD key persists. This previously caused a live bug (L475-478) where key rotation didn't invalidate the old key. Fixed via `replace_agent_key` but both functions exist.
- **Risk:** Future code paths using `store_agent_key` instead of `replace_agent_key` could miss invalidation.

### M2. Nonce replay store is memory-only (lost on restart)
- **File:** `server/auth_verify.py:38-40, 121-142`
- **Detail:** The v0.3 replay store is an in-memory `OrderedDict` (max 100K entries, 600s TTL). After server restart, the store is empty. Captured nonces can be replayed within the timestamp window (300s). Documented as "graceful degradation."
- **Risk:** Combined with another vulnerability, a captured signed request could be replayed after restart.

### M3. PBKDF2 iterations (200K) below OWASP 2023 recommendation (600K+)
- **File:** `server/sovereign_identity.py:107`
- **Detail:** `_PBKDF2_ITERS = 200_000`. OWASP recommends 600K+ for PBKDF2-HMAC-SHA256 in 2023. The 200K value was chosen for speed trade-off but is significantly below modern guidance.

### M4. SECURITY DEFINER functions with elevated privileges (15+ functions) — **FIXED**
- **File:** `infra/init.sql` (multiple locations: lines 100, 132, 255, 268, 364, 381, 485, 502, 519, 574, 683, 710, 737)
- **Detail:** Multiple Postgres functions use `SECURITY DEFINER` — they execute with the privileges of the table owner, not the calling user. Functions like `has_permission`, `handle_new_user`, etc. have broad scope. Some set `search_path` correctly, but the elevated privilege remains.
- **Risk:** SQL injection in a SECURITY DEFINER function grants the attacker full table-owner access.
- **Disposition (2026-09-19):** thirteen were declared, each assessed. Seven served only the dead tables and went with them (migration 0009). Five were orphans of the earlier hosting platform — no trigger or code path reaches them, `update_last_active` calls `auth.uid()` which does not exist here, and `auto_join_bay_area_chapter` inserted a hard-coded organisation id that would violate a foreign key on the first profile insert — dropped by migration 0010. `update_updated_at_column` (a generic `updated_at` bump, touches no table) is kept as `SECURITY INVOKER`. `init.sql` now declares none; `tests/test_init_sql_has_no_security_definer.py` fails by name if one is added.

### M5. f-string SQL in `arp.py._query` with bandit suppression
- **File:** `server/arp.py:130`
- **Detail:** `_query()` uses f-string for the WHERE clause: `f"SELECT receipt_json FROM arp_receipts {where} ..."`. The `# noqa: S608` comment asserts `where` is always hardcoded. This is currently true but brittle — any future code path passing user-controlled `where` is instantly injectable.
- **Fix:** Replace with parameterized query and a structured WHERE builder.

### M6. `detail=str(e)` propagates internal errors in `routes/skills.py`
- **File:** `server/routes/skills.py:58,83,134,154,179,217`
- **Detail:** Multiple HTTPException calls in the skills routes use `detail=str(e)` which propagates raw exception messages (`ValueError`, etc.) to the API response. These may contain internal paths, stack context, or implementation details.
- **Fix:** Return sanitized error messages. Log the original exception server-side.

### M7. No custom `@app.exception_handler` — tracebacks could leak in non-prod profiles
- **File:** No global exception handler in `server/chapter_agent.py` or `agent/community_member/server.py`
- **Detail:** FastAPI's default exception handler returns debug tracebacks in non-prod profiles (dev mode). While `ORRERY_PROFILE=prod` disables docs, the error handler is not customized. If a dev profile is accidentally deployed, unhandled exceptions leak stack traces.
- **Fix:** Add `@app.exception_handler(Exception)` to both FastAPI apps that returns a generic error response.

### M8. SMB funnel has no CSP
- **File:** `smb_funnel/index.html` — no CSP meta tag
- **Detail:** Unlike the reference renderer, the SMB funnel has no Content Security Policy. Combined with the `innerHTML` usage (H13), XSS risk is elevated.

### M9. No authentication on local agent API (any local process can read/write agent state)
- **File:** `agent/community_member/server.py:388-1328`
- **Detail:** The agent dashboard runs with `"no auth needed — your machine"` (server.py:5). While designed as local-only, any website visited by the user can make CSRF-style requests to `http://localhost:${PORT}` and: read receipts/signatures, read/edit LLM config (including API keys), read consent decisions, access the agent's identity trust status.
- **Fix:** At minimum, add CSRF protection (Origin header check) to write endpoints. Consider a local session token.

### M10. `/api/surfaces/compose` is OPEN (LLM token drain vector)
- **File:** `server/auth_verify.py:590-595`
- **Detail:** `POST /api/surfaces/compose` is unconditionally open (no auth). An unauthenticated attacker can submit arbitrary intents, triggering LLM calls that burn tokens/cost. Rate limiting (5/min) mitigates but doesn't eliminate the cost attack.

### M11. `/api/digest/build` is OPEN (data extraction vector)
- **File:** `server/auth_verify.py:593`
- **Detail:** `POST /api/digest/build` is unconditionally open. It triggers an LLM call with recent event data including `top_intents` text. An attacker can call this to extract summarized event data. Documented as "intentionally low-trust" (digest.py:25-29).

### M12. No client-side pre-commit hooks
- **Detail:** No pre-commit hooks for secrets scanning, lint, or format checks. All gates are CI-only (post-push).

### M13. All CI actions pinned by tag, not SHA
- **File:** `.github/workflows/ci.yml` — all 21 `uses:` references use `@v4`, `@v5` tags
- **Detail:** Tag-pinning is vulnerable to tag-mutation attacks where a maintainer force-pushes a new commit to the same tag. Current best practice (OpenSSF Scorecard, SLSA) requires SHA-pinning.
- **Fix:** Pin all actions by commit SHA with a comment: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2`.

### M14. Dockerfile.index uses inline ranged pip install (non-reproducible)
- **File:** `infra/Dockerfile.index:12`
- **Detail:** Uses `pip install fastapi>=0.100.0 uvicorn>=0.20.0 httpx ...` directly — no lockfile, no constraints file. Builds resolve latest versions at build time, producing non-reproducible images.
- **Fix:** Copy a `requirements.lock` (or `constraints.txt`) and install from it.

### M15. `asyncpg` unpinned in `requirements.txt`
- **File:** `server/requirements.txt:55`
- **Detail:** `asyncpg` has no version specifier. Only the lockfile pins it. A lockfile regeneration could resolve a breaking version.
- **Fix:** Add `asyncpg>=0.30.0` or similar floor.

### M16. No rate limiter key limit on store dict (memory exhaustion)
- **File:** `server/chapter_agent.py:99`
- **Detail:** `_rate_limit_store` is a plain `dict[str, list[float]]` with no upper bound on keys. A distributed IP attack (e.g., IPv6 /64) could cause unlimited memory growth.
- **Disposition — FIXED (2026-08-14).** The process-local store is now an
  atomically updated `OrderedDict` capped at 10,000 tracked buckets. It uses a
  monotonic clock, reclaims only buckets whose newest admitted request is older
  than the sliding window, and refuses an unseen key with the existing `429`
  response while every slot is live. It never evicts a live bucket, because
  eviction would reset that client's quota. The bounded-cardinality
  `nanda_chapter_rate_limit_capacity_rejections_total` counter exposes this
  refusal path without attacker-controlled metric labels.

  The residual boundary is explicit: the cap is per worker, resets on restart,
  and limits key count rather than a measured byte total. A high-cardinality
  caller can occupy every slot and temporarily deny unseen keys; existing keys
  remain usable under their normal quotas, and a quiet saturated store admits a
  new key within one window. Cross-worker coordination, persistence, proxy-trust
  policy, and a shared edge limiter remain deployment concerns rather than part
  of this fix.

### M17. CORS `allow_methods=["*"]` and `allow_headers=["*"]`
- **File:** `server/chapter_agent.py:1912`
- **Detail:** The CORS middleware allows all methods and headers. While CORS is a browser-enforced boundary that doesn't affect server-to-server calls, the over-permissive settings weaken the posture unnecessarily.

### M18. A2A interop exempt from method-binding (replayable across a2a/run)
- **File:** `server/auth_verify.py:378-379`
- **Detail:** `POST /a2a` and `POST /run` are exempt from method-binding enforcement (C4). They use legacy v0.2 ed25519 signing (method-unbound). A captured `/a2a` signature could be replayed as a `/run` request and vice versa within the timestamp window. Documented and spec-controlled.

### M19. No `Vary: Origin` header on CORS responses
- **File:** CORS middleware in `server/chapter_agent.py:1912`
- **Detail:** CORS responses don't include `Vary: Origin`. Caching proxies/CDNs may serve incorrect CORS headers to different origins.

### M20. Detailed auth error messages aid attackers
- **File:** `server/chapter_agent.py:6909` and throughout `auth_verify.py`
- **Detail:** Auth error messages are specific: `key_mismatch`, `no_stored_key`, `invalid_signature`, `expired_timestamp`, `nonce_replay`. These allow an attacker to: (a) enumerate valid `agent_id` values (different error for unknown vs known), (b) distinguish between wrong key vs wrong timestamp vs replayed nonce.
- **Fix:** Return generic `401 Unauthorized` for all auth failures; log the specific reason server-side.

---

## 🟢 LOW SEVERITY FINDINGS (17)

### L1. Membership oracle via `/api/agents/{id}/profile` — **RESIDUAL**
- **File:** `server/auth_verify.py:562-568`
- **Detail:** GET `/api/agents/{id}/profile` is OPEN — returns 200 for valid agent IDs, 404 (or error) for invalid. Enables agent ID enumeration. Documented as deliberate ("sharing the URL must work without an account").

### L2. `/admin/index.html` served without auth — **RESIDUAL**
- **File:** `server/auth_verify.py:426-431`
- **Detail:** The admin static UI is OPEN so the operator can paste their token. Documented as deliberate. The API surface at `/admin/api/*` requires the token.

### L3. `pg_store.py` injection boundary well-designed but untested against edge cases
- **File:** `server/pg_store.py:62-72, 106-112`
- **Detail:** The `_lit()` escape function uses correct PG15-style single-quote doubling. `_ident()` is strict. The design is correct for the current Postgres version but has no test proving injection resistance for: multi-byte Unicode edge cases, JSONB injection via `_lit_for`, or `ORDER BY` column expressions.

### L4. Legacy plaintext org key rows remain readable indefinitely
- **File:** `server/sovereign_identity.py:136-137`
- **Detail:** `_unseal_secret()` returns plaintext as-is for non-prefixed values. Old plaintext rows never get sealed unless explicitly re-written. Migration to encrypted storage is opt-in, not automatic.

### L5. Ephemeral (in-memory-only) key fallback with no persistence
- **File:** `server/sovereign_identity.py:227-228`
- **Detail:** If neither DB nor local file is available, `generate_ed25519_keypair` is called without persistence. ARP receipts and VRP attestations silently no-op. On restart, the key is lost.

### L6. Agent-side crypto documented as AES-256-GCM but is HMAC-SHA256 encrypt-then-MAC (fixed)
- **File:** `agent/community_member/crypto.py:6-9`
- **Detail:** Construction is sound HMAC-SHA256 encrypt-then-MAC, NOT AES-256-GCM. Documentation corrected per that change. Blobs versioned since v2.

### L7. `agent_key_rotation` nonce check fail-closed on DB error
- **File:** `server/member_rotation.py:49-52`
- **Detail:** `_nonce_seen()` returns `True` (nonce seen) on any DB exception, blocking legitimate rotations. Noted as "by design" but degrades availability.

### L8. `_usage_count` fail-closed design — correct but availability impact
- **File:** `server/authority.py:124-125, 139-140`
- **Detail:** `_usage_count` raises `UsageLookupError` on DB error, which turns into a deny. Correctly prevents quota bypass but causes action denials during DB outages.

### L9. Hardcoded UUIDs in init.sql triggers
- **File:** `infra/init.sql:137,336`
- **Detail:** Fixed UUIDs (`a0000000-0000-0000-0000-000000000001` for the default org, `4cb02745-b10c-4bf7-af31-40671759774e` for a named seed org) in triggers. Low risk — these are seed data, not secrets.

### L10. `session_id` in public cookie is deterministic — **OVERSTATED**
- **File:** `agent/community_member/wizard.py` or server auth session management
- **Detail:** Session IDs use predictable patterns. Low risk as they're bound to the local machine.
- **Disposition (2026-09-19):** there is no public cookie and no server-minted session id anywhere in the tree. Searched non-test source across every component for `session_id`, `set_cookie`, `Set-Cookie`, `document.cookie`, `Cookie(`, `session_token`, `SESSION_SECRET`, `sessionId`: `wizard.py` has none; nothing sets a cookie (`local_auth.py` refuses to carry the local token in one); the only `session_id` is the A2A JSON-RPC `sessionId` parameter, a caller-supplied task-grouping key echoed on the task, never a credential, with a random `mint_task_id()` when absent. The finding described a mechanism this codebase does not have.

### L11. Event payloads can include user-submitted text flowing through SSE to subscribers — **RESIDUAL**
- **File:** `server/event_bus.py:179`
- **Detail:** If payload fields contain user-submitted text (intent text, member names, broadcast body), these flow through SSE to all subscribers of that topic. Low risk as subscribers are authenticated.

### L12. `public_read_cors` middleware path list is a `frozenset` that could miss new public paths
- **File:** `server/chapter_agent.py:1923-1926`
- **Detail:** New public paths need to be added to `_PUBLIC_CORS_PATHS` or prefix list. A missed addition means the path won't get `ACAO: *` and may fail for browser consumers.

### L13. Rate limiter runs BEFORE auth — unauthenticated callers share same bucket
- **File:** `server/chapter_agent.py:1680-1701`
- **Detail:** Intentionally designed this way for scraper resistance, but means a flood of unauthenticated requests can deny service to legitimate authenticated callers from the same IP.

### L14. `in` operator in pg_store `_filter` splits on comma within parentheses
- **File:** `server/pg_store.py:134-138`
- **Detail:** The `in` operator handler splits `val[1:-1].split(",")` — this is PostgREST-dialect parsing, not SQL. The comma splitting is correct for simple values but could misparse complex expressions.

### L15. TOFU audit logs contain truncated signature (`signature[:90]`)
- **File:** `server/chapter_agent.py:1848-1858`
- **Detail:** The first 90 chars of the Ed25519 signature are logged to the audit trail on TOFU bootstrap. Signatures are public in the Ed25519 scheme (sent with every request), so this is a minimal leak.

### L16. Existence oracle at the Index resolution hop — **RESIDUAL**
- **File:** `server/routes/identity.py` (`registry_agent_record`, `member_agentfacts`), `server/sm_bridge_adapter.py` (`get_agent`)
- **Detail:** `GET /agents/{id}`, `/.well-known/agentfacts/{id}.json` and `/sm-bridge/resolve/{id}` answer 200 for a known member and 404 for an unknown id to an anonymous caller. Existence only: the member-authored description was stripped from all three (the L1 follow-up), and the sm-bridge index and delta feed enumerate only members who opted in, so an id has to be known already. These routes are the NANDA Index resolution hop for a member whose card was published; gating existence on listing consent would 404 Index resolution for every published-but-unconsented member. Left as stated — a product decision about what a published card means — with the cost recorded so the ruling can be revisited.

### L17. The v0.3 nonce replay store is memory-only — **RESIDUAL**
- **File:** `server/auth_verify.py` (`_v03_replay_store`, `verify_request` `max_age`)
- **Detail:** The replay store is an in-process, capped `OrderedDict` (TTL 600 s) and the timestamp window is ±300 s. A signed request captured on the wire replays once per process restart if replayed within its window, because the restart empties the store. Bounded to one window per restart and to a request already accepted once; requires a wire capture. A durable nonce store through the rate-limit persistence pattern (periodic snapshot, restored at boot) is the follow-up; it puts a table on the path of every signed request and is measured on its own.

---

## Prior Fixes (Notable Security History)

| Issue | Fix | File |
|-------|-----|------|
| Key rotation left old key valid post-rotation | Added `replace_agent_key()` — hard overwrites both key slots | `auth_verify.py:466-484` |
| `X-Agent-ID` header spoofable in handler | Identity now propagated via `request.state.agent_id`, not header | `chapter_agent.py:1753-1759` |
| Method-unbound signatures replayed across endpoints | C4: method-binding enforcement for mutations | `auth_verify.py:340-378, 748-753` |
| Agent crypto falsely claimed AES-256-GCM | Documentation corrected, blobs versioned (v2) | `crypto.py:that change` |
| Federation replay after restart | Timestamp+nonce in signed material | `federation_signing.py:22-28` |
| Agent enumeration via unauthenticated GET /api/members | Added to REQUIRE_AUTH_GET_PATHS | `auth_verify.py:239-252` |
| Org signing key stored plaintext at rest | AES-256-GCM via `ORRERY_KEY_SECRET` — **opt-in, and no live service opted in** (see C11) | `sovereign_identity.py:97-148` |
| Registration silently didn't update auth store on re-reg | Fixed key storage to overwrite on registration | `auth_verify.py:466-484` |
| HMAC-only agent could submit intents indefinitely | Authority rate limits per action type | `authority.py` |
| Broadcast replay after restart | Persistent dedup table (`federation_inbound_seen`) + signed timestamps | `broadcast.py:78-84`, `federation_signing.py` |

---

## Summary by Security Domain

| Domain | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | Total |
|--------|-------------|---------|-----------|--------|-------|
| Authentication / Authorization | 0 | 2 | 3 | 1 | 6 |
| Cryptography / Key Management | 2 | 2 | 2 | 3 | 9 |
| Database / Data Security | 3 | 0 | 2 | 2 | 7 |
| API Surface / Input Validation | 1 | 0 | 4 | 1 | 6 |
| Federation / Cross-Org Trust | 4 | 3 | 1 | 0 | 8 |
| Supply Chain / CI/CD | 1 | 3 | 3 | 1 | 8 |
| Frontend / Rendering | 2 | 2 | 2 | 2 | 8 |
| Docker / Infrastructure | 1 | 1 | 2 | 0 | 4 |
| Configuration / Defaults | 0 | 0 | 1 | 5 | 6 |
| **Total** | **14** | **13** | **20** | **15** | **62** |

---

## Key Defensive Strengths

The codebase has well-documented, layered security. Notable strengths that should be preserved:

1. **DID pinning** breaks the circular-trust problem — a cheating registry cannot rotate a peer's identity at the protocol level.
2. **Self-certifying registry records** (Ed25519 attestations) make record tampering detectable without trusting the registry.
3. **Cross-registry divergence detection** catches registry equivocation/omission between multiple registries.
4. **Replay protection** via timestamp+nonce on broadcasts and per-request nonces for agent-to-server calls.
5. **SSRF defenses** in cosign broker (DNS rebinding protection with IP pinning) and registry policy (loopback/internal endpoint rejection).
6. **Fail-closed design** on DB errors for DID pin lookups (F5) and usage quota checks — prevents silent downgrade attacks.
7. **Consent gate** double opt-in for identity revelation — no PII leaks without mutual agreement.
8. **Method-bound signing** (C4) prevents cross-method replay attacks on state-changing endpoints.
9. **Renderer structural XSS protections** — all text via `textContent`, URL/enum allowlists, component whitelists, zero `innerHTML`.
10. **Supply-chain pin enforcement** in CI — sm-* exact pins, git URL full-SHA checks, lockfiles committed and used.
11. **Excellent `.dockerignore` coverage** — explicitly blocks operator tokens, `.env`, and runtime secrets from building into images.
12. **Auth path classification** in `auth_verify.py` with documented OPEN/WARN/REQUIRE/SELF_SIGNED tiers — clear trust boundaries.
