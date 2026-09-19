#!/usr/bin/env python3
"""Re-running `./orrery-up` must not move the org's identity.

The installer allocates free ports rather than demanding specific ones, which
makes a first run work on a machine that is already serving something. The
hazard that comes with it is not the allocation — it is re-allocation:

    GET /agentfacts.json
      "id":        "did:web:localhost:7000:agents:demo-org"
      "endpoints": { "a2a": "http://localhost:7000/a2a", ... }

The org's did:web and every endpoint it publishes are built from its public
origin, and the origin carries the host port. So a port chosen fresh on each run
would give the org a different identity on each run, and everything that pinned
the old one — a federation peer, a registry record, a link someone saved —
would be pointing at a name that no longer exists. Allocation therefore happens
ONCE and is pinned in `.env`, the same way the generated secrets are.

⚠️ NOTE THE ASYMMETRY, because checking the wrong half proves nothing. The
AGENT's did:key is derived from its keypair and survives a port change untouched.
The ORG's did:web is derived from host and port and does not. A run that
confirmed "the agent's DID is unchanged" would pass with the org renamed.

Five things are checked, and the fourth is here because the other three missed
a planted defect:

    1. `.env`                byte-identical (sha256)
    2. the resolved ports    unchanged
    3. the org's identity    `id` and every published endpoint unchanged
    4. the RESOLUTION itself reports every port as `pinned`
    5. the re-run's OUTPUT   says so — one line naming every port as pinned

⚠️ WHY 4 EXISTS. With `resolve_ports` planted to ignore the pin and allocate
fresh on every run, checks 1–3 all PASSED. `ensure_env` appends missing keys and
never rewrites existing ones, so `.env` kept the original port no matter what
resolution returned, and Compose reads `.env` — a second mechanism held the
property up while the one under test was broken, and the installer went on to
bind-check ports it was not going to use. A check that can only observe the
downstream effect cannot tell "the pin was honoured" from "something else
happened to preserve it". So this asks resolution directly, against the real
`.env`, and requires it to say `pinned`.

⚠️ WHY 5 EXISTS. Checks 1–4 prove the property to this script. They proved
nothing to a reader: a re-run printed no port line at all (the only one was
printed when an allocation moved off its default), so "pinned" and
"re-allocated to the same number" looked identical on the terminal. The
installer now prints the source of every port on every run, and this requires
the re-run's own output to say `pinned` for each — the property, made visible.

⚠️ AND THE ANCHOR IS CHECKED FIRST. Comparing the org's `id` across two runs
proves nothing about ports unless that `id` actually contains the port — if the
identity format ever stopped embedding it, this check would keep passing while
saying nothing. So it requires the port to appear inside the identity before it
will compare anything, and reports that requirement failing as a failure rather
than as a pass.

Exit status:
    0 — .env, ports and org identity all unchanged across the re-run
    1 — something moved, or the anchor could not be established
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]
OK, BAD = "\033[32m✓\033[0m", "\033[31m✗\033[0m"
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _installer():
    import importlib.machinery
    import importlib.util

    loader = importlib.machinery.SourceFileLoader("orrery_up_identity", str(REPO / "orrery-up"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _agentfacts(origin: str) -> dict:
    with _NO_PROXY_OPENER.open(f"{origin}/agentfacts.json", timeout=10) as r:
        return json.loads(r.read().decode())


def _identity(facts: dict) -> dict:
    return {"id": facts.get("id"), "endpoints": facts.get("endpoints")}


def _snapshot(installer) -> tuple[dict, str, dict, str]:
    env_text = (REPO / ".env").read_text(encoding="utf-8")
    env = installer.parse_env(env_text)
    ports = {key: env.get(key) for _, _, _, key, _, _ in installer.SERVICE_PORTS}
    origin = installer._service_origin(env, "SERVER", "7000")
    return env, hashlib.sha256(env_text.encode()).hexdigest(), ports, origin


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()

    installer = _installer()
    if not (REPO / ".env").is_file():
        print(f"{BAD} no .env — run ./orrery-up first; this compares a re-run against a first run")
        return 1

    env_before, sha_before, ports_before, origin = _snapshot(installer)
    try:
        identity_before = _identity(_agentfacts(origin))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"{BAD} could not read {origin}/agentfacts.json ({exc}) — the org must be running")
        return 1

    # ── the anchor ────────────────────────────────────────────────────────
    server_port = ports_before.get("SERVER_PORT") or "7000"
    identity_text = json.dumps(identity_before)
    if not identity_before["id"] or server_port not in identity_text:
        print(f"{BAD} ANCHOR FAILED — the org's published identity does not contain its port")
        print(f"    port {server_port} is not in {identity_text[:200]}")
        print("  Comparing this identity across a re-run would prove nothing about port stability.")
        print("  Either the identity format changed, or the port is no longer part of it; in")
        print("  either case this check needs rewriting rather than believing.")
        return 1
    # ── check 4: the mechanism under test is the one in the path ──────────
    resolved = installer.resolve_ports(
        SimpleNamespace(server_port=None, agent_port=None, renderer_port=None), env_before
    )
    not_pinned = [c for c in resolved if c["source"] != "pinned"
                  or str(c["port"]) != ports_before.get(c["key"])]
    if not_pinned:
        print(f"{BAD} RESOLUTION DID NOT HONOUR THE PIN — every port in .env must resolve as `pinned`")
        for c in not_pinned:
            print(f"    {c['service']:<9} resolved {c['port']} as {c['source']}, "
                  f".env says {c['key']}={ports_before.get(c['key'])}")
        print("  `.env` may still look unchanged afterwards, because ensure_env appends and")
        print("  never rewrites — that would leave the installer verifying one port and")
        print("  Compose publishing another, and a fresh install taking a new identity.")
        return 1
    print(f"{OK} every port in .env resolves as `pinned`, not re-allocated")

    print(f"{OK} anchor: the org publishes its port inside its identity")
    print(f"    id        {identity_before['id']}")
    print(f"    ports     {ports_before}")

    # ── the re-run ────────────────────────────────────────────────────────
    print("\n── ./orrery-up --yes (second run) ───────────────────────")
    proc = subprocess.run([sys.executable, str(REPO / "orrery-up"), "--yes"], cwd=REPO,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"{BAD} the re-run exited {proc.returncode}")
        print(proc.stdout[-2000:], proc.stderr[-2000:])
        return 1

    # ── check 5: the output says what the resolution did ──────────────────
    ports_lines = [line for line in proc.stdout.splitlines() if "ports:" in line]
    if len(ports_lines) != 1:
        print(f"{BAD} THE RE-RUN DID NOT PRINT ITS PORTS LINE — expected exactly one, got {len(ports_lines)}")
        print(proc.stdout[-1500:])
        return 1
    unsaid = [c for c in resolved if f"{c['what']} {c['port']} ({installer.port_source_label(c)})" not in ports_lines[0]]
    if unsaid:
        print(f"{BAD} THE PORTS LINE DOES NOT SAY EVERY PORT IS PINNED: {ports_lines[0].strip()}")
        for c in unsaid:
            print(f"    {c['service']:<9} expected '{c['what']} {c['port']} ({installer.port_source_label(c)})'")
        return 1
    print(f"{OK} the re-run's output names every port as pinned: {ports_lines[0].strip()}")

    env_after, sha_after, ports_after, origin_after = _snapshot(installer)
    try:
        identity_after = _identity(_agentfacts(origin_after))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"{BAD} could not read {origin_after}/agentfacts.json after the re-run ({exc})")
        return 1

    print("\n── after ────────────────────────────────────────────────")
    failures = []
    for label, before, after in (
        (".env (sha256)", sha_before, sha_after),
        ("resolved ports", ports_before, ports_after),
        ("org identity", identity_before, identity_after),
    ):
        same = before == after
        print(f"  {OK if same else BAD} {label:<16} {'unchanged' if same else 'CHANGED'}")
        if not same:
            failures.append((label, before, after))

    if failures:
        print(f"\n{BAD} the re-run moved something that must not move:")
        for label, before, after in failures:
            print(f"    {label}\n      before: {before}\n      after:  {after}")
        print("  Ports are allocated ONCE and pinned in .env. If they are being resolved")
        print("  again on every run, the org gets a new did:web every run and every record")
        print("  that named the old one is stale.")
        return 1

    print(f"\n{OK} .env byte-identical, ports pinned, and the org's did:web and published "
          "endpoints unchanged across a re-run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
