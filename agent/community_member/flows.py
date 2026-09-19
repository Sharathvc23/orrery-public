"""Reusable flagship-loop flows for the CLI and the e2e harness.

Each returns a process-style exit code (0 ok, 1 failure) and prints what it
did — the sm-bridge verify-CLI ergonomics. Nothing here needs an LLM key;
identities are ephemeral Ed25519 unless the caller supplies its own.
"""

from __future__ import annotations

import base64
import json
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def _get_json(url: str, timeout: float = 15) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 — operator-supplied org URL
        return json.loads(r.read().decode())


def run_interaction(chapter_url: str | None, *, cosign: bool = True) -> int:
    """One recorded X→Y A2A interaction (loopback witness), co-signed unless
    ``cosign=False``; with ``chapter_url`` both agents register and the
    receipt is pushed so it lands in the org's reputation surfaces.

    This is the receipt→reputation ignition as a repeatable verb — the same
    flow ``examples/cosign_interaction.py`` walks through pedagogically.
    """
    import asyncio

    from .a2a_client_v2 import GoogleA2AClient
    from .a2a_rpc import A2ARPCHandler
    from .arp import AgencyLog, did_from_private_key, verify_receipt_signature
    from .cosign import make_cosigner
    from .task_store import TaskStore

    def _agent() -> tuple[bytes, str, str]:
        sk = Ed25519PrivateKey.generate()
        seed = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return seed, did_from_private_key(seed), base64.b64encode(pub).decode()

    x_seed, x_did, x_pub = _agent()
    y_seed, y_did, y_pub = _agent()

    with TemporaryDirectory() as tmp:
        tmpd = Path(tmp)
        handler = A2ARPCHandler(
            store=TaskStore(path=tmpd / "y-tasks.jsonl"),
            dispatcher=lambda tool, args: asyncio.sleep(0, result=json.dumps({"reply": f"handled {tool}"})),
            cosigner=make_cosigner(y_seed),
        )

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
                resp = asyncio.run(handler.handle(body))
                payload = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        y_url = f"http://{srv.server_address[0]}:{srv.server_address[1]}"
        log = AgencyLog(home=tmpd / "x-agency")
        client = GoogleA2AClient(base_url=y_url)
        try:
            if chapter_url:
                for did, name, pub in ((x_did, "cli-interact-issuer", x_pub), (y_did, "cli-interact-witness", y_pub)):
                    body = json.dumps(
                        {
                            "agent_id": f"{name}-{did[-6:].lower()}",
                            "name": name,
                            "origin": "sovereign",
                            "public_key": pub,
                        }
                    ).encode()
                    req = urllib.request.Request(
                        chapter_url.rstrip("/") + "/api/members",
                        data=body,
                        method="POST",
                        headers={"Content-Type": "application/json"},
                    )
                    urllib.request.urlopen(req, timeout=15).read()  # noqa: S310
            client.send_task_recorded(
                tool="greet",
                args={"text": "cli interaction"},
                counterparty_did=y_did,
                counterparty_label="cli-interact-witness",
                sk_bytes=x_seed,
                agency_log=log,
                category="message_sent",
                chapter_url=chapter_url,
                push=bool(chapter_url),
                cosign=cosign,
            )
            receipts = log.list_recent(limit=10)
            if not receipts:
                print("interact: FAILED — no receipt emitted")
                return 1
            newest = receipts[0]
            witnesses = len((newest.get("evidence") or {}).get("witness_signatures") or [])
            valid = verify_receipt_signature(newest)
            print(
                f"interact: receipt {newest['receipt_id'][:8]}… valid={valid} "
                f"witnesses={witnesses} cosign={'yes' if cosign else 'no'}"
                f"{' pushed to ' + chapter_url if chapter_url else ' (local only)'}"
            )
            if not valid or (cosign and witnesses < 1) or (not cosign and witnesses != 0):
                print("interact: FAILED — receipt shape does not match the requested mode")
                return 1
            return 0
        finally:
            client.close()
            srv.shutdown()


def resolve_agent(org_url: str, agent: str) -> int:
    """Quilt resolution verb: resolve ``agent`` on ``org_url`` via
    /sm-bridge/resolve, print the record. Exit 0 iff resolvable."""
    url = f"{org_url.rstrip('/')}/sm-bridge/resolve?{urllib.parse.urlencode({'agent': agent})}"
    try:
        record = _get_json(url)
    except Exception as e:  # noqa: BLE001 — CLI reports, exit code carries the verdict
        print(f"resolve: FAILED — {type(e).__name__}: {e}")
        return 1
    print(json.dumps(record, indent=2))
    return 0


def registry_dump(org_url: str) -> int:
    """Per-org registry integrity verb: list the ai-catalog and verify every
    entry resolves via the /agents/{id} hop and every sm-bridge index member
    via /sm-bridge/resolve. Exit 0 iff the registry is fully coherent."""
    base = org_url.rstrip("/")
    try:
        catalog = _get_json(f"{base}/.well-known/ai-catalog.json")
        index = _get_json(f"{base}/sm-bridge/index")
    except Exception as e:  # noqa: BLE001
        print(f"registry: FAILED — {type(e).__name__}: {e}")
        return 1
    bad = 0
    for e in catalog.get("entries") or []:
        ident = e.get("identifier") or ""
        try:
            hop = _get_json(f"{base}/agents/{urllib.parse.quote(ident)}")
            ok = bool(hop.get("url"))
        except Exception:  # noqa: BLE001
            ok = False
        bad += 0 if ok else 1
        print(f"  catalog {'✓' if ok else '✗'} {ident}")
    for a in index.get("agents") or []:
        aid = str(a.get("id") or "").rsplit(":", 1)[-1]
        try:
            _get_json(f"{base}/sm-bridge/resolve?{urllib.parse.urlencode({'agent': aid})}")
            ok = True
        except Exception:  # noqa: BLE001
            ok = False
        bad += 0 if ok else 1
        print(f"  sm-bridge {'✓' if ok else '✗'} {aid}")
    print(f"registry: {'OK' if bad == 0 else f'{bad} unresolvable entr(y/ies)'}")
    return 0 if bad == 0 else 1
