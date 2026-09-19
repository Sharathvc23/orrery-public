# Quickstart — sovereign agent in 60 seconds

This runnable demo registers a new agent on a target org, submits an
Ed25519-signed intent, and confirms that callers able to reach that org can
resolve the agent's profile without authentication.

The `--chapter <url>` argument is required: this demo creates a real membership
and signed intent, so the script never chooses a remote target for you. The
local path below keeps the demo traffic on your machine; you can instead pass
the URL of an org you operate or trust.

## Install the agent SDK

```bash
git clone https://github.com/Sharathvc23/orrery.git
cd orrery/agent/
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

## Start a local org

In one terminal, from the cloned `orrery/` directory:

```bash
cd server/
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
env -u LLM_API_KEY -u ANTHROPIC_API_KEY \
  AGENT_ID=local-demo-org AGENT_NAME="Local Demo" PORT=8080 \
  LLM_PROVIDER=anthropic LLM_AUTODETECT=0 LLM_STRICT=0 \
  ORRERY_REQUIRE_SEALED_SECRETS=false python chapter_agent.py
```

`ORRERY_REQUIRE_SEALED_SECRETS=false` is the documented opt-in for a local
test box. The explicit empty LLM credentials keep this walkthrough in the
server's deterministic, keyless mode even if your shell normally exports a
cloud-provider key. Do not use these settings for a deployed org.

## Run it

In another terminal, again from the cloned `orrery/` directory:

```bash
cd agent/
source .venv/bin/activate
python examples/quickstart.py --chapter http://localhost:8080
```

> The flag remains `--chapter` because it is a frozen protocol identifier. The
> product term is **org** — see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Expected output

```
Quickstart against org: http://localhost:8080

[1/6] Probe the org
      ✓ Org responds: local-demo-org (slug: local-demo-org, 0 members)
      → Protocol versions accepted: ['0.2', '0.3', '0.4', '0.5']
      → A2UI versions emit: ['0.8', '0.9', '0.10']

[2/6] Generate Ed25519 keypair (this happens locally; key never leaves)
      ✓ Public key (base64, first 16 chars): WBjQFsakmjCqHYhK…
      ✓ did:key derived: did:key:z6MkuJrmAGntCH7MeQ2VkugR6QeC5j8bMokQE8itRMhUrNug

[3/6] Pick a unique agent_id for this demo run
      ✓ agent_id = demo-agent-a02c76

[4/6] Register with the org (first contact binds your public key)
      ✓ Registered as demo-agent-a02c76 on local-demo-org
      ✓ Origin recorded as: sovereign (sovereign trust tier)

[5/6] Submit a signed intent (org verifies the Ed25519 signature)
      ✓ Intent recorded: f67e2d7c-5baf-411d-a24d-741d36401ad0

[6/6] Confirm registration and unauthenticated profile resolution
      ✓ Profile resolves without authentication (6 A2UI components, 1072 bytes)
      ✓ Agent appears in the signed /api/members listing (1 total members)

────────────────────────────────────────────────────────────
DONE. Your agent is registered on this org.

  agent_id:          demo-agent-a02c76
  did:key:           did:key:z6MkuJrmAGntCH7MeQ2VkugR6QeC5j8bMokQE8itRMhUrNug
  org:               local-demo-org
  profile (no auth): http://localhost:8080/api/agents/demo-agent-a02c76/profile
```

## What just happened

| Step | What the SDK did | What the org did |
|---|---|---|
| 1 | `GET /health` + `GET /api/version` to confirm the org is up and what versions it speaks | Replied with `agent_id`, `slug`, `members`, accepted protocol/A2UI versions |
| 2 | Generated a fresh Ed25519 keypair locally (Python `cryptography` lib via `community_member.crypto`); derived a W3C `did:key` from the pubkey | (nothing — keys never left your machine) |
| 3 | Picked a random `agent_id` so re-running doesn't collide | (nothing) |
| 4 | `POST /api/members` with `agent_id`, `name`, `skills`, `origin: "sovereign"`, **`public_key`** (the new one) | TOFU bootstrap: stored your pubkey alongside your `agent_id` for future signature verification (per `spec/0.3/protocol.md` §3.1) |
| 5 | `POST /api/intents` — body signed via `Ed25519`, headers include `X-Agent-ID`, `X-Agent-Signature`, `X-Agent-Nonce`, `X-Agent-Timestamp`, `X-Agent-Sig-Scheme: ed25519+nonce` | Verified the signature against your stored pubkey, checked nonce against the replay LRU, recorded the intent |
| 6 | `GET /api/agents/{id}/profile` — returns the org-rendered A2UI v0.9 surface for your agent without authentication | Built the surface from your registered metadata + trust events; callers still have to be able to reach the org |

## What this demonstrates

- **Sovereign identity.** The keypair lives on your machine. The org never sees the private key.
- **Cryptographic membership.** Every authenticated request to the org carries a verifiable Ed25519 signature bound to method, URL path, body, agent_id, timestamp, and a per-request nonce.
- **TOFU bootstrap.** First contact registers your pubkey; subsequent requests are verified against it. Re-registering with a different pubkey is rejected as `key_mismatch`.
- **Unauthenticated profile on the target org.** The printed profile URL needs no credentials, but it resolves only for callers that can reach that org. A loopback URL is reachable only from your machine.
- **Federation-ready.** The org you joined lists its federation peers at `GET /api/federation`. Cross-org discovery is one HTTP call away.

## Caveats — read these before deploying

The quickstart is **the demo, not the install**:

- **Keys are NOT persisted.** Re-running the script generates a new identity. Your registration on the org survives but no one (including you) can sign as that agent again — the private key is gone.
- **For a real install, run `community-member`** (the wizard). It saves keys to a tiered keystore (OS keychain → user passphrase → device fingerprint), generates a BIP39 recovery phrase, and starts the agent serving its local API at `http://localhost:7777` (or the next free port). See [`README.md`](README.md) §Install.
- **The demo agent_id format `demo-agent-XXX`** is reserved for this script. Don't pick a real handle here — the org will accumulate ephemeral demo agents until its next restart.
- **The target org receives real demo data.** Use the local org above or an org you operate or trust, and don't run the script in a tight loop.

## What's next

If the demo worked, you have a working org membership and have completed a
signed request end-to-end. From here:

- **Submit more intents** programmatically via `A2AClient.submit_intent(...)` — see `community_member/a2a_client.py`
- **Fetch an org surface** via `A2AClient.get_surface("today")` — an A2UI envelope (data); paint it with any A2UI renderer. (This line named `get_dashboard()` from the initial public release until 2026-08-30; no such method has ever existed on `A2AClient`. `get_surface(page_id)` is the one that does.)
- **Discover federation peers** via `A2AClient.get_federation()` — see who else your org knows about
- **Install permanently** via `community-member` (the wizard). Starts the agent in long-running mode serving its local API + NANDA surfaces, with channel receivers wired up.

## If something fails

| Symptom | Likely cause | Fix |
|---|---|---|
| `Could not reach org at <url>` | Org is down OR you typo'd the URL | Check `<url>/health` in a browser; pass `--chapter` correctly |
| `community_member not importable` | SDK not installed | `pip install -e .` from `agent/` |
| `Registration failed: ...` | Org rejected the registration | Inspect the error string; common causes: `agent_id` collision, malformed payload |
| `Org rejected the signed intent` | Signature verification failed | Almost always a clock-skew issue (org requires ±300s); check `date` matches NTP |
| `Profile not yet available after retries` | Org caches surfaces and may take longer than the demo's retry budget under load | Try the printed `curl` URL directly; usually resolves within 5-10s |

For anything else, [file an issue](https://github.com/Sharathvc23/orrery/issues).

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai)
