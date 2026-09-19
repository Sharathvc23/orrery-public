"""Runnable end-to-end: two agents do a co-signed A2A interaction that produces a
**corroborated** ARP receipt — the only form that builds reputation under
``nanda-rep/0.2`` (spec/arp/0.2/cosign-companion.md §1).

This is the "ignition" the quickstart leaves out. ``quickstart.py`` registers an
agent and submits one intent — it never *interacts*, so it emits no receipts. A
reputation system with no interactions has nothing to score. This script closes
that gap: it stands up a second agent as a real A2A server, calls it over the
wire, and the counterparty co-signs the receipt on the same connection.

Run (from the ``agent/`` dir):

    pip install -e ".[ed25519]"
    python examples/cosign_interaction.py                 # local, self-contained
    python examples/cosign_interaction.py --chapter https://my-chapter.example.com

Local mode (default) needs no chapter and no network: agent Y runs on a loopback
port, agent X calls it, and you see a corroborated receipt scored under both
``nanda-rep/0.1`` (self-attested) and ``nanda-rep/0.2`` (corroboration-gated) so
the difference is concrete. ``--chapter`` additionally registers both agents and
pushes the receipt so it shows up in the chapter's agentfacts — this creates real
test members + receipts on that chapter, so point it at a TEST chapter.

What it demonstrates, step by step:
  1. X calls Y's tool over real A2A JSON-RPC (``tasks/send``).
  2. X asks Y to co-sign the interaction receipt over the same connection
     (``nanda/cosignReceipt``); Y co-signs because it is the named counterparty.
  3. X inserts Y's witness entry and finalizes its own signature over it — the
     receipt is now corroborated and recomputable by anyone offline.
  4. A second interaction runs WITHOUT co-sign, so you can watch ``nanda-rep/0.2``
     gate it to zero while ``nanda-rep/0.1`` still counts it.

The keys are ephemeral (regenerated each run); nothing is persisted unless you
pass ``--chapter``.
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import sm_arp.vrp as _vrp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from community_member.a2a_client_v2 import GoogleA2AClient
from community_member.a2a_rpc import A2ARPCHandler
from community_member.arp import AgencyLog, did_from_private_key, verify_receipt_signature
from community_member.cosign import make_cosigner
from community_member.task_store import TaskStore


def _step(n: int, msg: str) -> None:
    print(f"\n[{n}] {msg}")


def _ok(msg: str) -> None:
    print(f"    ✓ {msg}")


def _info(msg: str) -> None:
    print(f"    → {msg}")


def _new_agent() -> tuple[bytes, str]:
    """A fresh ephemeral agent: (32-byte Ed25519 seed, did:key)."""
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return seed, did_from_private_key(seed)


# ── agent Y: a real A2A server (loopback) that answers tasks AND co-signs ─────


def _start_witness_server(y_seed: bytes, task_store_path: Path) -> tuple[ThreadingHTTPServer, str]:
    """Serve agent Y's A2A endpoint on a loopback port. Y answers ``tasks/send``
    and, because a cosigner is bound, co-signs receipts naming it as counterparty
    (``nanda/cosignReceipt``). Returns (server, base_url)."""

    async def dispatch(tool: str, args: dict[str, Any]) -> str:
        # Y's "tool": echo back a friendly reply. A real agent runs its model here.
        return json.dumps({"reply": f"Agent Y handled {tool!r}", "echo": args})

    handler = A2ARPCHandler(
        store=TaskStore(path=task_store_path),
        dispatcher=dispatch,
        cosigner=make_cosigner(y_seed),  # <- the witness side of the co-sign handshake
    )

    class _A2AHandler(BaseHTTPRequestHandler):
        def log_message(self, *_a):  # silence default request logging
            pass

        def do_POST(self):
            import asyncio

            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            resp = asyncio.run(handler.handle(body))
            payload = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _A2AHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def _emit_interaction(
    client: GoogleA2AClient, log: AgencyLog, *, text: str, cosign: bool, y_did: str, x_seed: bytes, chapter: str | None
) -> dict:
    """Run one X→Y interaction and return the receipt it just emitted, identified
    by id-diff (two receipts can share a second-granularity ``issued_at``, so
    ``list_recent(1)`` alone is ambiguous)."""
    before = {r["receipt_id"] for r in log.list_recent(limit=1000)}
    client.send_task_recorded(
        tool="greet",
        args={"text": text},
        counterparty_did=y_did,
        counterparty_label="Agent Y",
        sk_bytes=x_seed,
        agency_log=log,
        category="message_sent",
        chapter_url=chapter,
        push=bool(chapter),
        cosign=cosign,
    )
    new = [r for r in log.list_recent(limit=1000) if r["receipt_id"] not in before]
    return new[0]


def _summarize_score(receipts: list[dict]) -> None:
    """Print the 0.1-vs-0.2 score over a set of receipts — the flip's impact."""

    def is_valid(r: dict) -> bool:
        return verify_receipt_signature(r)

    score_01 = _vrp.reputation_score(receipts, is_valid=is_valid)
    score_02 = _vrp.reputation_score_v2(receipts, is_valid=is_valid)
    corr = _vrp.corroboration_rate(receipts, is_valid=is_valid)
    print(f"    nanda-rep/0.1 (self-attested)     score = {score_01}")
    print(f"    nanda-rep/0.2 (corroborated-only) score = {score_02}   corroboration_rate = {corr:.3f}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--chapter",
        default=None,
        help="Optional TEST chapter URL: also register both agents + push the receipt "
        "so it appears in the chapter's agentfacts. Creates real test data on that chapter.",
    )
    args = ap.parse_args(argv)

    x_seed, x_did = _new_agent()
    y_seed, y_did = _new_agent()
    print("Two ephemeral agents:")
    print(f"  X (caller / issuer):     {x_did}")
    print(f"  Y (counterparty / wit.): {y_did}")

    with TemporaryDirectory() as tmp:
        tmpd = Path(tmp)
        _step(1, "Starting agent Y as a real A2A server (loopback)…")
        server, y_url = _start_witness_server(y_seed, tmpd / "y-tasks.jsonl")
        _ok(f"Y listening at {y_url} (answers tasks/send + nanda/cosignReceipt)")

        log = AgencyLog(home=tmpd / "x-agency")
        client = GoogleA2AClient(base_url=y_url)
        chapter = args.chapter
        try:
            if chapter:
                _register_on_chapter(chapter, x_did, "Cosign Demo Issuer", x_seed)
                _register_on_chapter(chapter, y_did, "Cosign Demo Witness", y_seed)
                _ok(f"registered X + Y on {chapter}")

            _step(2, "X calls Y over A2A and asks Y to CO-SIGN the receipt (cosign=True)…")
            corroborated = _emit_interaction(
                client,
                log,
                text="Hello Y, this is X.",
                cosign=True,
                y_did=y_did,
                x_seed=x_seed,
                chapter=chapter,
            )
            witness = corroborated.get("evidence", {}).get("witness_signatures", [{}])[0].get("witness_did", "—")
            _ok(f"receipt {corroborated['receipt_id'][:8]}… signed by X")
            _ok(f"corroborated: {_vrp.is_corroborated(corroborated)} (witness = {witness})")
            _info("the witness is Y's own key — X cannot manufacture it")

            _step(3, "X calls Y again, but WITHOUT co-sign (cosign=False)…")
            uncorroborated = _emit_interaction(
                client,
                log,
                text="Second call, no witness.",
                cosign=False,
                y_did=y_did,
                x_seed=x_seed,
                chapter=chapter,
            )
            _ok(f"receipt {uncorroborated['receipt_id'][:8]}… corroborated: {_vrp.is_corroborated(uncorroborated)}")

            _step(4, "X's standing — what the flip to nanda-rep/0.2 actually does:")
            _summarize_score(log.list_recent(limit=100))
            _info("0.2 counts only the corroborated receipt; the self-attested one drops to zero.")

            if chapter:
                _step(5, "Reading X's live agentfacts from the chapter under 0.2…")
                _read_chapter_facts(chapter, x_did)

        finally:
            client.close()
            server.shutdown()

    print("\nDone. This is the loop real agents must run for reputation to flow:")
    print("  send_task_recorded(cosign=True, push=True) → corroborated receipt → chapter.")
    return 0


# ── optional chapter integration ─────────────────────────────────────────────


def _register_on_chapter(chapter_url: str, did: str, name: str, seed: bytes) -> None:
    import base64
    import urllib.request

    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    agent_id = name.lower().replace(" ", "-") + "-" + did[-6:]
    body = json.dumps(
        {"agent_id": agent_id, "name": name, "origin": "sovereign", "public_key": base64.b64encode(pub).decode()}
    ).encode()
    req = urllib.request.Request(
        chapter_url.rstrip("/") + "/api/members?origin=sovereign",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except Exception as e:  # best-effort; a re-run with the same did is idempotent
        _info(f"registration note for {agent_id}: {e}")


def _read_chapter_facts(chapter_url: str, did: str) -> None:
    import urllib.request

    # The member_id on the chapter is derived from the registration above.
    agent_id = "cosign-demo-issuer-" + did[-6:]
    url = f"{chapter_url.rstrip('/')}/agentfacts/{agent_id}.json?scoring_method=nanda-rep/0.2"
    try:
        data = json.loads(urllib.request.urlopen(url, timeout=15).read())
    except Exception as e:
        _info(f"could not read agentfacts: {e}")
        return

    def find(o, k):
        if isinstance(o, dict):
            if k in o:
                return o[k]
            for v in o.values():
                r = find(v, k)
                if r is not None:
                    return r
        elif isinstance(o, list):
            for v in o:
                r = find(v, k)
                if r is not None:
                    return r
        return None

    vr = find(data, "verifiable_receipts")
    if vr:
        _ok(
            f"chapter agentfacts: score={vr.get('reputation_score')} "
            f"corroboration_rate={vr.get('corroboration_rate')} receipts={vr.get('receipt_count')}"
        )
    else:
        _info("no verifiable_receipts facet yet (chapter may still be ingesting).")


if __name__ == "__main__":
    raise SystemExit(main())
