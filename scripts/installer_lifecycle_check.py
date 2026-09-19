#!/usr/bin/env python3
"""Assert that `./orrery-up down` releases every port `./orrery-up` bound.

The reference renderer is a Compose service rather than a process the installer
spawns, and lifecycle is the entire reason for that choice: `orrery-up` exits
after its drill, so a static server it started itself would be reparented to
init and outlive it, with `down` — a separate invocation that never met the
child — left holding a pidfile or a "kill whatever owns the port" heuristic.
This script is the assertion that the choice actually bought what it claims.

Two phases, and THE ORDER IS THE WHOLE DESIGN:

    1. WHILE UP   — every published port is listening, and the renderer serves
                    its page. Recorded as the anchor.
    2. AFTER DOWN — `./orrery-up down` is run, and every one of those same ports
                    refuses a connection.

Phase 2 alone proves nothing. A port that was never bound is free after `down`
for reasons that have nothing to do with teardown, so a check that only looks
afterwards passes most loudly when the service failed to start at all. This
script therefore REFUSES to report success unless phase 1 found the listener
first: a run that observed nothing must not read as a run that observed
cleanliness. Same reasoning as the survival check in ``smb_host_canary.py``.

It leaves the stack DOWN — that is the state it asserts. Volumes are untouched,
so data survives; pass --purge to drop them too.

Exit status:
    0 — every port was bound while up and free after down
    1 — a port was missing while up, or still held after down
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OK, BAD = "\033[32m✓\033[0m", "\033[31m✗\033[0m"

_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _installer():
    """Load `orrery-up` for its env parsing and port derivation.

    Imported rather than restated: the ports this script checks have to be the
    ports the installer publishes, and a second copy of that derivation would
    agree right up until someone changed one of them.
    """
    import importlib.machinery
    import importlib.util

    loader = importlib.machinery.SourceFileLoader("orrery_up_lifecycle", str(REPO / "orrery-up"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _listening(host: str, port: int, timeout: float = 2.0) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def _serves(url: str, timeout: float = 5.0) -> "int | str":
    try:
        with _NO_PROXY_OPENER.open(url, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError) as e:
        return str(e)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--purge", action="store_true", help="also drop volumes when tearing down")
    ap.add_argument("--settle-seconds", type=float, default=5.0,
                    help="grace period after `down` before re-probing (default 5)")
    args = ap.parse_args()

    installer = _installer()
    env_path = REPO / ".env"
    if not env_path.is_file():
        print(f"{BAD} no .env — run ./orrery-up first; this script asserts a teardown, it does not install")
        return 1
    env = installer.parse_env(env_path.read_text(encoding="utf-8"))

    published = [
        ("org server", installer._probe_host(env.get("SERVER_BIND_HOST", "127.0.0.1")),
         int(env.get("SERVER_PORT", "7000"))),
        ("agent", installer._probe_host(env.get("AGENT_BIND_HOST", "127.0.0.1")),
         int(env.get("AGENT_PORT", "8080"))),
        ("reference renderer", installer._probe_host(env.get("RENDERER_BIND_HOST", "127.0.0.1")),
         int(env.get("RENDERER_PORT", "8600"))),
    ]

    # ── phase 1: the anchor ───────────────────────────────────────────────
    print("── while up ─────────────────────────────────────────────")
    missing = []
    for what, host, port in published:
        up = _listening(host, port)
        print(f"  {OK if up else BAD} {what:<19} {host}:{port} {'listening' if up else 'NOT LISTENING'}")
        if not up:
            missing.append(f"{what} ({host}:{port})")

    renderer_url = installer._service_origin(env, "RENDERER", "8600") + "/"
    status = _serves(renderer_url)
    served = status == 200
    print(f"  {OK if served else BAD} renderer serves its page   {renderer_url} → {status}")
    if not served:
        missing.append(f"the renderer did not serve {renderer_url} (got {status})")

    if missing:
        print(f"\n{BAD} NOTHING WAS ASSERTED ABOUT TEARDOWN. The stack was not fully up, so a port")
        print("  found free after `down` would say nothing about whether `down` released it:")
        for m in missing:
            print(f"    - {m}")
        print("  Start it with ./orrery-up and re-run.")
        return 1

    # ── phase 2: teardown ─────────────────────────────────────────────────
    print("\n── ./orrery-up down ─────────────────────────────────────")
    cmd = [sys.executable, str(REPO / "orrery-up"), "down", *(["--purge"] if args.purge else [])]
    proc = subprocess.run(cmd, cwd=REPO)
    if proc.returncode != 0:
        print(f"{BAD} `{' '.join(cmd)}` exited {proc.returncode}")
        return 1
    time.sleep(args.settle_seconds)

    print("\n── after down ───────────────────────────────────────────")
    held = []
    for what, host, port in published:
        still = _listening(host, port)
        print(f"  {BAD if still else OK} {what:<19} {host}:{port} {'STILL LISTENING' if still else 'free'}")
        if still:
            held.append(f"{what} ({host}:{port})")

    if held:
        print(f"\n{BAD} `./orrery-up down` left {len(held)} listener(s) running:")
        for h in held:
            print(f"    - {h}")
        print("  A service the teardown does not stop is a process the installer cannot")
        print("  account for. Check that its compose profile is named in orrery-up PROFILES.")
        return 1

    print(f"\n{OK} every published port was bound while up and free after down "
          f"({len(published)} ports, renderer included)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
