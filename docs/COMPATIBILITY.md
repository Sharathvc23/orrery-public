# Compatibility

What Orrery speaks, at which version, as the tests pin it. A version on this
page is one a test asserts or a lockfile fixes; prose that claims a newer one
is wrong, not this page. Labels follow the same rule:

- **Supported** — a test drives the real handler on the protocol's wire shape,
  in CI.
- **Experimental** — it works and was driven by hand or behind a skip; there
  is no CI proof against the live counterpart.
- **Unfinished** — the shape exists and nothing delivers.

## Protocols and integrations

| Integration | Version / vocabulary the tests pin | Evidence | Label |
|---|---|---|---|
| **A2A** — agent JSON-RPC at `POST /`, cards at `/.well-known/agent.json` and `agent-card.json` | External oracle `a2a-sdk==1.1.2` installed in CI. Methods driven: `message/send`, `message/stream`, `tasks/send`, `tasks/sendSubscribe`, `tasks/get`, `tasks/cancel`, `tasks/resubscribe`, `nanda/cosignReceipt`, `nanda/legacyTaskCensus` | `agent/tests/test_a2a_current_spec_compat.py` (a stock SDK client finds the card and reaches a handler), `test_a2a_multiturn_continuation.py`, `test_a2a_streaming_frames.py`, `test_a2a_server_assigned_task_id.py`; `server/tests/test_a2a_standard_card.py` (`application/a2a-agent-card+json`) | **Supported** — v0.2 names and current-spec aliases; a keyless install answers `input-required` |
| **A2A on the org** — `POST /a2a`, `POST /run` | v0.2 signed interop; exempt from method binding (audit M18) | `server/tests/test_c4_method_binding_middleware.py`; `scripts/e2e_probes.py` on the Compose stack | **Supported** at v0.2 |
| **A2UI** — surfaces as data | Server emits `version: "0.10"`; the schema pins `const "0.10"` and rejects `0.9`; the renderer reads native 0.9 and 0.10; `?schema=v0.8` downgrade for OpenClaw | `server/tests/test_a2ui_helpers.py`, `test_a2ui_v010_meta_helpers.py`; `conformance/tests/test_schema_and_manifest.py`; `renderer/tests/envelope.test.mjs`, `budget.test.mjs`; `conformance/tests/test_advertised_surfaces_conform.py` | **Supported** — 0.10 emit, 0.9 read, 0.8 downgrade |
| **AG-UI** — SSE at `/api/surfaces/{page}/stream` | No protocol version is pinned by any test. Event vocabulary asserted: `RunStarted → StateSnapshot → [StateDelta…] → RunFinished` | `server/tests/test_agui_streaming.py`; observed live `200 text/event-stream` | **Supported** for the vocabulary asserted; **version unpinned** |
| **MCP** — `python -m mcp_server` over stdio | `mcp>=1.24.0,<2.0.0`; oracle `langchain-mcp-adapters` 0.3.x | `mcp_server/test_stdio_oracle.py`, `test_langchain_oracle.py`, `test_tools.py`; driven by hand with a stock client | **Supported**, with one limit: `issue_receipt` returns a summary, not the receipt document, so its output does not verify over the wire — the round trip works in-process from the Agency Log |
| **ARP** receipts | Envelope `arp/0.1` (`agent/community_member/arp.py::ARP_VERSION`); co-signing per the 0.2 companion; `sm-arp==0.3.2` | `agent/tests/test_cosign.py`, `test_interactions.py`; `server/tests/test_arp.py`, `test_arp_verify_lockstep.py`; [`VERIFY_A_RECEIPT.md`](./VERIFY_A_RECEIPT.md) driven with `sm-arp` from PyPI and nothing of Orrery's | **Supported** |
| **Org signing scheme** | v0.3 `ed25519+nonce` for mutations; v0.2 accepted for reads; the boot badge names protocol majors `0.5, 0.4, 0.3, 0.2` | `conformance/client/` runs the published vectors against the reference adapter, the OpenClaw skill and the member SDK in CI | **Supported** |
| **sm-federation** — `/.well-known/agent-community.json`, `/api/federation/intelligence/feed` | `sm-federation==0.6.0` | `server/tests/test_federation_feed.py`, `test_federation_feed_guards.py`; `conformance/federation/` | **Supported** |
| **sm-listing** — `/.well-known/agent-community-listing.json` | `sm-listing==0.3.0`; the path equals `sm_listing.WELL_KNOWN_PATH` | `server/tests/test_member_listing.py`, `test_public_listing_gate.py`, `test_members_listing_authz.py` | **Supported**, member-consent-gated |
| **NANDA NEST** registration | The NEST record shape, against a mock transport; no live NEST in CI | `server/tests/test_nanda_registry.py`, `test_registry_no_outbound_when_disabled.py`; `agent/tests/test_registry.py` | **Experimental** — publish-when-configured is never driven against a live registry; off unless configured |
| **NANDA Index** — v1 resolve (`GET /api/v1/resolve`, media types `a2a-agent-card+json` / `ai-catalog+json`), v2 registration | Media-type dispatch, 2-hop and 4-hop resolve; v2 signup/login/409 | `agent/tests/test_nanda_index_discovery.py`; `server/tests/test_index_v2_registration.py`; the in-repo `index/` has its own CI job with a coverage floor | **Supported** against the in-repo index; **experimental** against the live index (canaries run only with `CANARY_ORGS` set) |
| **host39** card publication | The card body per host39's `additionalProperties: false` schema | `agent/tests/test_host39.py` (mocked client); `test_host39_live.py` skips without `HOST39_BASE_URL` and a credential | **Experimental** — live path behind a skip; publication requires the business's own listing grant |
| **OpenClaw skill** | Signing spec v0.3 with v0.2 fallback; server-side minimum skill version `0.5.1` | The client conformance job with `--adapter openclaw-skill --require-adapter`; `server/tests/test_openclaw_interop.py`, `test_openclaw_first_registration.py`, `test_openclaw_version_gate.py` | **Supported** for signing. **Known limit:** the shipped signer refuses every plain-`http://` URL with no loopback exception, so the skill cannot join a local `./orrery-up` org — only one fronted by HTTPS — while its own page's examples use `http://localhost`. Whether to allow loopback `http://` is a signing-oracle decision, recorded here rather than made. |
| **Discord** inbound interactions | Discord's Ed25519-over-(timestamp‖body) signing | `agent/tests/test_discord_receiver.py` (forgery, replay, injection); `test_channel_receiver.py` (5-minute window, hash-chained audit) | **Supported** for inbound verification; no outbound or live path |
| **Owner OIDC** (agent owner principal) | Loopback + PKCE S256, nonce-bound; id_token claims fail-fast; no signature verification by documented design (TLS to the token endpoint); `sm-authority==0.2.0` | `agent/tests/test_owner.py`, `test_owner_lifecycle.py`, `test_owner_domain_control.py` | **Experimental** — flow logic tested; no live identity provider in CI |
| **Klaviyo** outbound email | The transport exists; the default transport is the sandbox and holds no HTTP client; the live transport refuses to build without `KLAVIYO_LIVE_SENDS`; real recipients are refused before transport selection | `server/tests/test_external_send.py`, `test_external_send_edge.py` | **Unfinished** as a delivery integration — gated by design, live send never driven |
| **Slack / IMAP / SMTP** channels (org) | None — every integration is stubbed; `channels.test()` records *untested* rather than claiming success | `server/tests/test_channels.py` (routing, validation), `test_channels_test_honesty.py` | **Unfinished** — shape only |
| **OIDC / SSO** for the org | Provider configs validated (`okta`, `azure_ad`, `google_workspace`, `generic_oidc`); a leaders-only config row; no authorization or token flow exists | `server/tests/test_chapter_enterprise.py`, `test_sso_config_authz.py` | **Unfinished** — shape only |
| **Voice** | None — a provider catalogue with validation; setting a provider captures and synthesizes nothing | `server/tests/test_voice.py` | **Unfinished** |

## Runtime environment CI actually runs

| Component | Version | Where it is pinned |
|---|---|---|
| Python (every job) | 3.12 | `.github/workflows/ci.yml` `setup-python`; the packages declare `requires-python >= 3.10` |
| Server, agent, index and host images | `python:3.12-slim` by digest | `infra/Dockerfile.server`, `agent/infra/Dockerfile.agent`, `infra/Dockerfile.index`, `infra/Dockerfile.smb-host`, `docker-compose.yml` |
| Postgres | `pgvector/pgvector:pg15` by digest | `infra/Dockerfile.db`, `docker-compose.yml` |
| Docker Compose | v2 plugin (`docker compose`) | the e2e and installer jobs run `docker compose … up -d --build` |
| Node (renderer, funnel, console tests; portal e2e) | 22 (one legacy job at 20) | `ci.yml` `setup-node` |
| Playwright (browser e2e) | 1.62.0, Chromium headless shell | `ci.yml` `PLAYWRIGHT_VERSION` |
| Web framework and HTTP | `fastapi==0.139.0`, `uvicorn==0.51.0`, `httpx==0.28.1`, `pydantic==2.13.4` | `server/requirements.lock`, `agent/requirements.lock` |
| Database driver | `asyncpg==0.31.0` | `server/requirements.lock` |
| Cryptography | `cryptography==50.0.0` | both lockfiles |

## The `sm-*` pins

Every pin is exact in two files per package and resolves on public PyPI at
that exact version (checked by fetching each one):

| Package | Version |
|---|---|
| `sm-aae` | 0.1.0 |
| `sm-arp` | 0.3.2 |
| `sm-authority` | 0.2.0 (agent) |
| `sm-bridge` | 0.6.0 |
| `sm-conformance` | 0.3.2 |
| `sm-divergence` | 0.8.0 (server) |
| `sm-federation` | 0.6.0 (server; also `conformance/federation/requirements.txt`) |
| `sm-feed` | 0.2.0 (server) |
| `sm-listing` | 0.3.0 (server) |
| `sm-locp` | 0.2.1 (server) |
| `sm-parc` | 0.2.3 (agent) |
| `sm-resolver` | 0.2.0 (server) |

`index/`, `mcp_server/`, `skill/`, `smb_host/` and `smb_signup/` pin no
`sm-*` package. The `supply-chain-pins` job refuses a git dependency without a
full commit SHA and a Compose image without a digest; the dependency CVE scan
runs `pip-audit` over the lockfiles on every PR.
