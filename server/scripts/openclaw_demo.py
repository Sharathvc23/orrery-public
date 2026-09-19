#!/usr/bin/env python3
"""
OpenClaw plain-English test harness for the NandaHack Commons arena.

Scripts a stock agent performing a full chapter interaction from zero
context, using ONLY the discovery endpoints our chapter advertises:

  1. Discover the chapter via /.well-known/nanda-agent.json
  2. Fetch AgentFacts to learn available skills + A2A endpoint
  3. Generate a fresh Ed25519 keypair + did:key
  4. Submit an intent ("find a Rust developer interested in climate tech")
  5. Poll for anonymized federation matches
  6. Respond accept/decline on at least one match
  7. List open agent-to-agent conversations
  8. Print a transcript for submission artifacts

The point: a stock OpenClaw-style agent can drive our whole public
surface from plain English + the discovery layer, with no custom
glue. If this works against a live chapter URL, we've proven the
Commons arena requirement.

Usage:
    # Against a live chapter
    python scripts/openclaw_demo.py --chapter https://org.example.com

    # Against localhost for dev
    python scripts/openclaw_demo.py --chapter http://localhost:7000

    # Save the transcript to a file for the submission package
    python scripts/openclaw_demo.py --chapter ... --transcript artifacts/openclaw_run.txt
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

import httpx

try:
    import base58
    from nacl.signing import SigningKey
except ImportError:
    print("ERROR: install pynacl and base58 for Ed25519 signing", file=sys.stderr)
    print("  pip install pynacl base58", file=sys.stderr)
    sys.exit(2)


ED25519_MULTICODEC_PREFIX = b"\xed\x01"


# ═══════════════════════════════════════════════════════════════
# Identity — matches community-member's signing contract
# ═══════════════════════════════════════════════════════════════


class StockAgent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        signing_key = SigningKey.generate()
        self._signing_key = signing_key
        self.private_key_b64 = base64.b64encode(bytes(signing_key)).decode()
        self.public_key_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode()
        prefixed = ED25519_MULTICODEC_PREFIX + bytes(signing_key.verify_key)
        self.did_key = f"did:key:z{base58.b58encode(prefixed).decode()}"

    def sign_headers(self, body: str) -> dict:
        ts = str(int(time.time()))
        message = f"{body}:{self.agent_id}:{ts}".encode()
        sig = self._signing_key.sign(message).signature
        return {
            "X-Agent-ID": self.agent_id,
            "X-Agent-Signature": base64.b64encode(sig).decode(),
            "X-Agent-Timestamp": ts,
            "X-Agent-Sig-Scheme": "ed25519",
            "X-Agent-DID-Key": self.did_key,
            "Content-Type": "application/json",
        }


# ═══════════════════════════════════════════════════════════════
# Demo flow
# ═══════════════════════════════════════════════════════════════


def step(transcript: list[str], label: str, status: str = "", detail: str = ""):
    line = f"[{time.strftime('%H:%M:%S')}] {label}"
    if status:
        line += f" → {status}"
    if detail:
        line += f" ({detail})"
    print(line)
    transcript.append(line)


def get_json(client: httpx.Client, url: str, **kw) -> dict:
    resp = client.get(url, timeout=15.0, **kw)
    resp.raise_for_status()
    return resp.json()


def post_signed(client: httpx.Client, url: str, body_str: str, headers: dict, **kw) -> tuple[int, dict | None]:
    """POST with a pre-serialized body so the signature matches bytes on the wire."""
    resp = client.post(url, content=body_str, headers=headers, timeout=20.0, **kw)
    try:
        payload = resp.json()
    except Exception:
        payload = None
    return resp.status_code, payload


def run_demo(chapter_url: str, transcript_path: Path | None) -> int:
    chapter_url = chapter_url.rstrip("/")
    transcript: list[str] = []
    agent = StockAgent(agent_id=f"openclaw-demo-{int(time.time())}")

    step(transcript, "START", "", f"agent_id={agent.agent_id} did={agent.did_key[:40]}...")

    with httpx.Client(follow_redirects=True) as client:
        # ── 1. Discover via well-known (with graceful fallback) ──
        try:
            wk = get_json(client, f"{chapter_url}/.well-known/nanda-agent.json")
            step(transcript, "1 DISCOVER /.well-known/nanda-agent.json", "200", f"facts_url={wk.get('facts_url', '?')}")
        except Exception as e:
            # Fallback: some deployments may not have /.well-known yet.
            # Spec says facts_url = PUBLIC_URL/agentfacts.json convention.
            step(
                transcript,
                "1 DISCOVER /.well-known/nanda-agent.json",
                "MISS",
                f"{str(e)[:60]} — falling back to /agentfacts.json",
            )
            wk = {
                "facts_url": f"{chapter_url}/agentfacts.json",
                "a2a_url": f"{chapter_url}/a2a",
            }

        # ── 2. Fetch AgentFacts ────────────────────────────────
        try:
            facts = get_json(client, wk["facts_url"])
            skills = facts.get("capabilities", {}).get("skills", [])
            step(transcript, "2 FETCH AgentFacts", "200", f"v={facts.get('facts_version')} skills={skills[:3]}...")
        except Exception as e:
            step(transcript, "2 FETCH AgentFacts", "FAIL", str(e)[:100])
            return _write(transcript, transcript_path, exit_code=1)

        # ── 3. Health + registry status ────────────────────────
        try:
            health = get_json(client, f"{chapter_url}/health")
            registries = health.get("registries", {})
            step(
                transcript, "3 HEALTH", "200", f"members={health.get('members')} federation={health.get('federation')}"
            )
            nest = registries.get("nest", {})
            step(transcript, "   NEST", "configured" if nest.get("configured") else "missing", nest.get("detail", ""))
            for idx in registries.get("indexes", []):
                step(transcript, "   Index", idx.get("url", "?"), idx.get("detail", ""))
        except Exception as e:
            step(transcript, "3 HEALTH", "FAIL", str(e)[:100])

        # ── 3b. Register as a chapter member (signed) ──────────
        reg_body = {
            "agent_id": agent.agent_id,
            "name": "OpenClaw Demo Agent",
            "description": "Stock Orrery agent running the Commons arena test",
            "skills": ["testing", "openclaw", "rust"],
            "personality": "helpful",
            "voice": "concise",
            "virtual": True,
            "public_key": agent.public_key_b64,
        }
        reg_body_str = json.dumps(reg_body)
        reg_headers = agent.sign_headers(reg_body_str)
        code, payload = post_signed(client, f"{chapter_url}/api/members", reg_body_str, reg_headers)
        step(transcript, "3b POST /api/members (TOFU)", str(code), f"name={reg_body['name']}")

        # ── 4. Submit intent ───────────────────────────────────
        intent_body = {
            "requester_agent_id": agent.agent_id,
            "intent_text": "find a Rust developer interested in climate tech",
            "intent_tags": ["rust", "climate"],
        }
        body_str = json.dumps(intent_body)
        headers = agent.sign_headers(body_str)
        code, payload = post_signed(client, f"{chapter_url}/api/intents", body_str, headers)
        step(
            transcript,
            "4 POST /api/intents",
            str(code),
            f"intent_id={payload.get('intent_id', '?') if payload else '?'}",
        )
        intent_id = (payload or {}).get("intent_id", "")

        # ── 5. Fetch pending matches ───────────────────────────
        try:
            matches = get_json(client, f"{chapter_url}/api/intents/pending/{agent.agent_id}")
            pending = matches.get("pending", [])
            step(transcript, "5 GET /api/intents/pending", "200", f"{len(pending)} match(es)")
        except Exception as e:
            step(transcript, "5 GET /api/intents/pending", "FAIL", str(e)[:100])
            pending = []

        # ── 6. Respond to first match (if any) ─────────────────
        if pending:
            first = pending[0]
            respond_body = {
                "intent_id": first.get("intent_id", intent_id),
                "responder_agent_id": agent.agent_id,
                "response": "accept",
            }
            respond_body_str = json.dumps(respond_body)
            respond_headers = agent.sign_headers(respond_body_str)
            code, payload = post_signed(client, f"{chapter_url}/api/intents/respond", respond_body_str, respond_headers)
            step(transcript, "6 POST /api/intents/respond", str(code), f"response={respond_body['response']}")
        else:
            step(transcript, "6 POST /api/intents/respond", "SKIP", "no pending matches yet")

        # ── 7. List conversations ──────────────────────────────
        try:
            convs = get_json(client, f"{chapter_url}/api/conversations/{agent.agent_id}")
            step(transcript, "7 GET /api/conversations", "200", f"{len(convs.get('conversations', []))} thread(s)")
        except Exception as e:
            step(transcript, "7 GET /api/conversations", "FAIL", str(e)[:100])

        # ── 8. Federation snapshot ─────────────────────────────
        try:
            fed = get_json(client, f"{chapter_url}/api/federation")
            chapters = fed.get("chapters", [])
            step(transcript, "8 GET /api/federation", "200", f"{len(chapters)} peer chapter(s)")
        except Exception as e:
            step(transcript, "8 GET /api/federation", "FAIL", str(e)[:100])

    step(transcript, "DONE", "ok", "")
    return _write(transcript, transcript_path, exit_code=0)


def _write(transcript: list[str], path: Path | None, exit_code: int) -> int:
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(transcript) + "\n")
        print(f"\nTranscript written: {path}")
    return exit_code


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--chapter", required=True, help="Chapter URL (e.g. https://org.example.com)"
    )
    p.add_argument("--transcript", type=Path, help="Write full transcript to this file")
    args = p.parse_args()
    return run_demo(args.chapter, args.transcript)


if __name__ == "__main__":
    sys.exit(main())
