# orrery-server

The host that runs an **org** and hosts many **agents**. Emits a cryptographically
signed ARP receipt for every action an agent takes on a human's behalf, and serves the
org's signed HTTP API + NANDA discovery surfaces. Headless — no portal, no human login;
agents authenticate with Ed25519-signed requests.

Kernel layer — see [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python chapter_agent.py          # flat-module app; binds 0.0.0.0:$PORT (default 7000)
# → GET /health
```

Normally you don't run the server directly — `docker compose up` from the repo
root brings up the org (db + server). The above is for hacking on the server in
isolation.

MIT.
