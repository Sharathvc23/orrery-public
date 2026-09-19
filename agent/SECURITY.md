# SECURITY.md — Orrery agent Threat Model & Security Specification

This document defines the threat model, security controls, and test requirements for the `community-member` sovereign agent package. Every control listed here must be implemented, tested adversarially, and verified before any public release.

## Threat Model

### What We're Protecting

1. **Member's LLM API key** — worth money, grants access to paid LLM services
2. **Member's private memory** — goals, notes, preferences stored locally
3. **Member's identity** — agent_id, reputation, skills, DID keypair
4. **Org integrity** — agent actions shouldn't be spoofable or replayable
5. **Network trust** — federation shouldn't propagate poisoned data

### Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| **Malicious org operator** | Controls an org server | Steal API keys, exfiltrate private memory, impersonate members |
| **Network attacker (MITM)** | Intercepts HTTP traffic | Read messages, inject fake responses, steal credentials |
| **Malicious fork publisher** | Publishes typosquatted package | Backdoor agent to exfiltrate keys and memory |
| **Impersonator** | Knows an agent_id | Register as someone else, steal their reputation, intercept their intents |
| **Spam agent** | Has valid identity | Flood intents, DDoS org, poison skill graphs |
| **Local attacker** | File access on member's machine | Read API key from config, modify agent state, tamper with memory |

## Security Controls

### SC-1: Authenticated Registration

**Problem:** Anyone can `POST /api/members` with any agent_id.
**Control:** Registration requires a signed challenge-response:

1. Client requests a nonce from org: `GET /api/auth/challenge?agent_id=X`
2. Org returns a random nonce (valid 60 seconds)
3. Client signs the nonce with their private key
4. Client sends `POST /api/members` with signature in header
5. Org verifies signature against the agent's stored public key (or accepts first-time registration with a new public key)

**Deliverable:**
- `POST /api/auth/challenge` endpoint on org agent
- `POST /api/members` requires `X-Agent-Signature` header
- Challenge-response in `community_member/auth.py`
- Tests: valid signature accepted, forged signature rejected, expired nonce rejected, replay rejected

### SC-2: Encrypted Key Storage

**Problem:** Sensitive secrets (LLM API key, Ed25519 signing key) must never sit on disk in plaintext.

**Control — API key:** stored as PBKDF2-derived AES/HMAC ciphertext in `config.json`. The user's passphrase decrypts it on startup; an attacker with disk access cannot use the key without the passphrase.

**Control — Ed25519 signing key:** stored in a dedicated keystore module (`community_member/keystore.py`) with three backends, auto-selected by capability:

| Backend | Selected when | Defends against |
|---|---|---|
| `BACKEND_KEYRING` | OS keychain available | Backup leak, other-user processes, root (varies by platform) |
| `BACKEND_PASSPHRASE` | tty present, no keyring | Backup leak, other-user processes, root, sibling user-level processes |
| `BACKEND_DEVICE` | headless / CI fallback | Backup leak only — DOES NOT defend against root or sibling process |

The keystore advertises its active backend via `community-member keystore status` and allows operator-driven migration via `community-member keystore rotate <backend>`. The wizard records the selection in `keystore.meta.json` so the next process resolves the same backend without re-prompting.

**What no software backend can defend against:** a compromised running agent process. Only a hardware-backed signing element (TPM, YubiKey, Secure Enclave) keeps the key bytes out of agent RAM — a hardware keystore backend is on the [roadmap](../docs/ROADMAP.md) (sovereign SDK v0.7).

**Deliverable:**
- `community_member/crypto.py` — PBKDF2 + HMAC-authenticated encryption
- `community_member/keystore.py` — three-backend key-at-rest store with auto-probe + rotation
- `config.json` never persists the Ed25519 private key in any form (verified by `tests/test_keystore.py::test_S4_*`)
- Wizard prompts for passphrase only when BACKEND_PASSPHRASE is the resolved backend
- Tests: 35-case keystore suite covering round-trip, tamper detection, fingerprint binding, migration, and per-backend isolation

### SC-3: Signed Agent Exports

**Problem:** `.agent.json` export files have no integrity protection.
**Control:** Export file includes a signature over the content hash.

1. On export, compute SHA-256 hash of the agent state
2. Sign the hash with the agent's private key
3. Include signature + public key in the export file
4. On import, verify signature before accepting

**Deliverable:**
- Export includes `_signature` and `_public_key` fields
- Import rejects files with invalid or missing signatures
- Tests: valid export imports, tampered export rejected, missing signature rejected, wrong key rejected

### SC-4: Signed A2A Messages

**Problem:** A2A messages between agent and org are unsigned — any MITM can modify them.
**Control:** Every A2A message includes a signature header.

1. Before sending, agent signs the message body with its private key
2. `X-Agent-Signature` header included on every request
3. Org verifies signature before processing
4. Responses from org signed with org's key (bidirectional trust)

**Deliverable:**
- `a2a_client.py` signs all outgoing requests
- Org verifies signatures on incoming requests
- Tests: valid signature passes, tampered body rejected, missing signature rejected, replay protection (nonce/timestamp)

### SC-5: Rate Limiting & Abuse Prevention

**Problem:** Malicious agent could flood the org.
**Control:** Multi-layer rate limiting.

| Layer | Limit | Enforcement |
|-------|-------|-------------|
| Org API | 30 requests/minute per IP | Server-side (existing) |
| Intent submission | 5 intents/hour per agent | Server-side |
| Conversation creation | 3/day per agent | Server-side (existing) |
| Think cycle | 1 thought/5 minutes | Client-side |
| Registration | 1 per agent_id | Server-side (existing) |

**Deliverable:**
- Client-side rate limiter in `agent.py`
- Server-side per-agent rate limits (not just per-IP)
- Tests: rate limit at boundary, one over rejects, burst handling

### SC-6: Input Sanitization

**Problem:** Agent sends user-controlled text to org APIs.
**Control:** All inputs sanitized before transmission.

1. Agent names: alphanumeric + hyphens only, max 50 chars
2. Skills: alphanumeric + hyphens, max 50 chars each, max 20 skills
3. Intent text: max 500 chars, stripped of control characters
4. Private notes: max 10,000 chars, no executable content
5. No HTML, no script tags, no SQL fragments in any field

**Deliverable:**
- `community_member/sanitize.py` — shared sanitization functions
- All A2A client methods sanitize inputs before sending
- Tests: SQL injection strings sanitized, XSS payloads stripped, oversized inputs truncated, null bytes removed, unicode normalization

### SC-7: Memory Privacy

**Problem:** Private memory must never leave the member's machine.
**Control:** Strict separation between local and remote data.

1. Private memory file (`memory.json`) is NEVER sent to the org
2. Agent tools that save notes write ONLY to local file
3. No telemetry, no analytics, no crash reports that include memory content
4. Export includes private memory ONLY when user explicitly confirms with passphrase

**Deliverable:**
- Audit: grep entire codebase for any code path that sends memory.json content to HTTP
- Tests: mock all HTTP calls, verify no private memory appears in any request body
- Export with `include_private=True` requires passphrase confirmation

### SC-8: Org Trust Verification

**Problem:** Member connects to an org URL — how do they know it's legitimate?
**Control:** Org identity verification on first connect.

1. On first connection, fetch org's AgentFacts
2. Display org name, DID, member count to user
3. User confirms ("Is this the right org?")
4. Store org's public key for future verification
5. On subsequent connections, verify org's key hasn't changed (TOFU — Trust On First Use)

**Deliverable:**
- Wizard shows org identity on first connect
- Org public key stored in config
- Warning if org key changes (potential MITM)
- Tests: first connect stores key, same key passes, different key warns

## Test Specifications

### Security Tests (mandatory, blocking)

| Test ID | Category | What | Classification |
|---------|----------|------|---------------|
| SEC-01 | Auth | Valid signature accepted on registration | HAPPY |
| SEC-02 | Auth | Forged signature rejected | ADVERSARIAL |
| SEC-03 | Auth | Expired nonce rejected | EDGE |
| SEC-04 | Auth | Replay of valid signature rejected | ADVERSARIAL |
| SEC-05 | Crypto | Encrypt→decrypt roundtrip with correct passphrase | HAPPY |
| SEC-06 | Crypto | Wrong passphrase returns error, not garbage | FAILURE |
| SEC-07 | Crypto | Corrupted ciphertext detected | ADVERSARIAL |
| SEC-08 | Crypto | Salt is unique per encryption | EDGE |
| SEC-09 | Export | Valid signed export imports successfully | HAPPY |
| SEC-10 | Export | Tampered export rejected (modified skills) | ADVERSARIAL |
| SEC-11 | Export | Missing signature rejected | FAILURE |
| SEC-12 | Export | Wrong key signature rejected | ADVERSARIAL |
| SEC-13 | A2A | Signed message accepted by org | HAPPY |
| SEC-14 | A2A | Tampered message body rejected | ADVERSARIAL |
| SEC-15 | A2A | Missing signature header rejected | FAILURE |
| SEC-16 | Input | SQL injection in agent_id sanitized | ADVERSARIAL |
| SEC-17 | Input | XSS payload in skills stripped | ADVERSARIAL |
| SEC-18 | Input | Oversized intent text truncated | EDGE |
| SEC-19 | Input | Null bytes in name removed | ADVERSARIAL |
| SEC-20 | Privacy | No private memory in any HTTP request body | ADVERSARIAL |
| SEC-21 | Privacy | Export without passphrase excludes private memory | FAILURE |
| SEC-22 | Trust | First connect stores org key | HAPPY |
| SEC-23 | Trust | Changed org key triggers warning | ADVERSARIAL |
| SEC-24 | Rate | Rate limit at exact boundary passes | EDGE |
| SEC-25 | Rate | One over rate limit rejects | EDGE |

### Edge Case Tests (mandatory, blocking)

| Test ID | What | Classification |
|---------|------|---------------|
| EDGE-01 | Empty skills list accepted | EDGE |
| EDGE-02 | 20 skills (max) accepted, 21 rejected | EDGE |
| EDGE-03 | Agent ID with only hyphens rejected | EDGE |
| EDGE-04 | Zero-length passphrase rejected | EDGE |
| EDGE-05 | Config file missing on startup → wizard runs | EDGE |
| EDGE-06 | Config file corrupted → wizard runs (no crash) | EDGE |
| EDGE-07 | Org offline during registration → graceful error | FAILURE |
| EDGE-08 | LLM key invalid → agent reports error, doesn't crash | FAILURE |
| EDGE-09 | Network timeout on A2A call → retry or graceful fail | FAILURE |
| EDGE-10 | Concurrent think cycles don't race condition | EDGE |

### Load/Chaos Tests (advisory, non-blocking)

| Test ID | What |
|---------|------|
| LOAD-01 | 100 concurrent intent submissions from different agents |
| LOAD-02 | Agent think cycle under 1-second LLM latency |
| LOAD-03 | Agent think cycle under 30-second LLM timeout |
| LOAD-04 | Org with 1,000 members — intent matching performance |
| LOAD-05 | Kill agent mid-think → restart recovers cleanly |
| LOAD-06 | Kill agent during export → no partial file corruption |
| LOAD-07 | Disk full during memory save → graceful error |

## Deliverables

At the end of implementation, the following must be true:

1. **`community_member/auth.py`** — challenge-response authentication module
2. **`community_member/crypto.py`** — HMAC-SHA256 encrypt-then-MAC (not AES-GCM) for API keys at rest
3. **`community_member/sanitize.py`** — input sanitization for all fields
4. **Org endpoints updated** — `/api/auth/challenge`, signature verification on `/api/members` and `/a2a`
5. **Signed exports** — `_signature` + `_public_key` in export files, verification on import
6. **25 security tests** — all passing, all prosecution-grade (no HAPPY-only classes)
7. **10 edge case tests** — all passing
8. **7 load/chaos tests** — documented results
9. **Privacy audit** — documented grep showing no private memory in any HTTP call
10. **This SECURITY.md** — updated with implementation status for each control


---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai)