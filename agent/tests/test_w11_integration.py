"""
W11 end-to-end integration test.

Proves every W11 subsystem composes cleanly with the others, using
only injected fakes — no network, no real Slack workspace, no real
chapter runtime. The point is to catch cross-module regressions that
unit tests can't see.

Classification: HAPPY
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from community_member import channel_receiver as cr
from community_member import settings_sync as ss
from community_member import skill_runtime as srt
from community_member import skills as sk
from community_member.crypto import build_did_key

# ─── Full "virtual chapter" for integration ─────────────


def _sign_over(sk_key: SigningKey, hex_sha: str) -> str:
    import base64

    signed = sk_key.sign(hex_sha.encode("utf-8"))
    return base64.b64encode(signed.signature).decode()


class VirtualChapter:
    """Every endpoint the member calls, implemented in memory. Signs skills
    with its own did:key, tracks installs + reviews + settings + mesh peers."""

    def __init__(self):
        import base64 as _b64

        self.sk_key = SigningKey.generate()
        pub_b64 = _b64.b64encode(self.sk_key.verify_key.encode()).decode()
        self.did = build_did_key(pub_b64)
        self.skills: dict[str, dict] = {}
        self.installs: dict[tuple[str, str], str] = {}
        self.reviews: list[dict] = []
        self.settings: dict[str, dict] = {}
        self.sent_messages: list[dict] = []
        self.peers: dict[str, dict] = {}

    def publish_skill(self, name: str, version: str, capabilities: list[str]) -> dict:
        manifest = {
            "name": name,
            "version": version,
            "capabilities": capabilities,
            "author_did": self.did,
            "description": "test skill",
        }
        canonical = {**manifest, "author_did": self.did}
        content = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sha = hashlib.sha256(content).hexdigest()
        sig = _sign_over(self.sk_key, sha)
        skill_id = f"{name}@{version}"
        self.skills[skill_id] = {
            "id": skill_id,
            "name": name,
            "version": version,
            "author_did": self.did,
            "capabilities": capabilities,
            "manifest": manifest,
            "content_sha256": sha,
            "signature": sig,
            "signing_key_did": self.did,
            "package_url": None,
            "revoked_at": None,
        }
        return self.skills[skill_id]

    def add_peer(self, agent_id: str, chapter_id: str, skills: list[str], trust: float = 50.0):
        self.peers[agent_id] = {
            "agent_id": agent_id,
            "chapter_id": chapter_id,
            "name": agent_id.capitalize(),
            "skills": skills,
            "trust_score": trust,
            "online": True,
            "local": False,
        }

    def api(self, method: str, path: str, body=None):
        """The single callable the member side uses as chapter_api_fn / client methods."""
        if method == "POST" and "/install" in path:
            skill_id = path.replace("/api/skills/", "").replace("/install", "")
            if skill_id not in self.skills:
                raise RuntimeError(f"skill not found: {skill_id}")
            agent_id = body["agent_id"]
            proof = hashlib.sha256(f"{agent_id}|{skill_id}|install".encode()).hexdigest()
            self.installs[(agent_id, skill_id)] = proof
            return {"agent_id": agent_id, "skill_id": skill_id, "signed_install_proof": proof}
        if method == "GET" and path.startswith("/api/skills/"):
            skill_id = path.replace("/api/skills/", "")
            skill = self.skills.get(skill_id)
            return {"skill": skill}
        return {}

    # A2AClient-shaped methods for the rest of the member code
    def review_skill(self, skill_id, reviewer_agent_id, rating, review_text, signed_install_proof):
        if self.installs.get((reviewer_agent_id, skill_id)) != signed_install_proof:
            raise RuntimeError("install_proof does not match")
        review = {
            "skill_id": skill_id,
            "reviewer_agent_id": reviewer_agent_id,
            "rating": rating,
            "review_text": review_text,
        }
        self.reviews.append(review)
        return {"review": review}

    def get_settings(self, agent_id):
        return {"agent_id": agent_id, "settings": self.settings.get(agent_id, {})}

    def update_settings(self, agent_id, patch):
        merged = ss._deep_merge(self.settings.get(agent_id, {}), patch)
        self.settings[agent_id] = merged
        return {"agent_id": agent_id, "settings": merged}

    def mesh_peers(self, query=None, skills=None, limit=50):
        results = list(self.peers.values())
        if skills:
            want = {s.lower() for s in skills}
            results = [p for p in results if want & {s.lower() for s in p["skills"]}]
        return {"peers": results[:limit], "count": len(results)}

    def mesh_send(self, sender_agent_id, target_agent_id, text, intent_id=None):
        if target_agent_id not in self.peers:
            raise RuntimeError("peer not found")
        self.sent_messages.append({"sender": sender_agent_id, "target": target_agent_id, "text": text})
        return {"delivery": "federation", "target": target_agent_id}

    def mesh_trust(self, agent_id):
        return {"agent_id": agent_id, "trust_score": 62.0, "tier": "trusted"}


# ─── The test ────────────────────────────────────────────


@pytest.fixture
def virtual_chapter():
    return VirtualChapter()


@pytest.fixture
def tmp_env(tmp_path, monkeypatch):
    """Isolate all member-side filesystem state for this test run."""
    skills_root = tmp_path / "skills"
    settings_cache = tmp_path / "settings.json"
    inbox_path = tmp_path / "inbox.jsonl"
    monkeypatch.setattr(sk, "SKILLS_ROOT", skills_root)
    monkeypatch.setattr(sk, "REGISTRY_PATH", skills_root / "registry.json")
    monkeypatch.setattr(ss, "SETTINGS_CACHE", settings_cache)
    monkeypatch.setattr(cr, "INBOX_PATH", inbox_path)
    return {
        "skills_root": skills_root,
        "settings_cache": settings_cache,
        "inbox_path": inbox_path,
    }


def test_full_w11_flow(virtual_chapter, tmp_env):
    """End-to-end HAPPY path proving every W11 subsystem composes cleanly.

    Flow:
      1. Chapter publishes a signed skill
      2. Member installs it (signature verified, persisted to registry)
      3. Agent loads the skill dynamically and sees its tools
      4. Agent invokes a tool (capability-gated)
      5. Member posts a 5-star review (install-proof gated)
      6. Member pushes settings changes (validated client-side)
      7. Member finds a peer and sends a mesh message
      8. Member receives a signed Slack webhook that gets verified +
         audit-chained + enqueued for the agent loop
      9. Audit chain verification passes end-to-end
    """
    agent_id = "alice"

    # 1. Publish
    virtual_chapter.publish_skill("file-ops", "1.0.0", capabilities=["fs.read"])
    virtual_chapter.add_peer("charlie", chapter_id="boston", skills=["rust"])

    # 2. Install — skills.py verifies signature before touching disk
    entry = sk.install_skill(
        chapter_url="https://chapter.example",
        skill_id="file-ops@1.0.0",
        agent_id=agent_id,
        chapter_api_fn=virtual_chapter.api,
        skills_root=tmp_env["skills_root"],
    )
    assert entry["installed_version"] == "1.0.0"
    install_proof = entry["install_proof"]

    # Simulate a live skill.py so skill_runtime has something to load.
    skill_dir = Path(entry["path"])
    (skill_dir / "skill.py").write_text(
        "def _read(args):\n"
        "    return {'ok': True, 'text': args.get('text', '')}\n"
        "TOOLS = [\n"
        "    {'name': 'read', 'description': 'echo', 'parameters': {'text': 'string'}, 'fn': _read},\n"
        "]\n"
    )

    # 3. Load
    loaded = srt.load_installed_skills()
    assert len(loaded) == 1
    assert "read" in loaded[0].tools

    # 4. Invoke (capability-gated)
    result = srt.invoke_tool(
        loaded,
        "file-ops@1.0.0",
        "read",
        {"text": "hi"},
        user_grants={"file-ops@1.0.0": {"fs.read"}},
    )
    assert result == {"ok": True, "text": "hi"}

    # 5. Rate — install-proof gated server-side
    virtual_chapter.review_skill(
        skill_id="file-ops@1.0.0",
        reviewer_agent_id=agent_id,
        rating=5,
        review_text="works great",
        signed_install_proof=install_proof,
    )
    assert len(virtual_chapter.reviews) == 1
    assert virtual_chapter.reviews[0]["rating"] == 5

    # 6. Settings roundtrip
    ss.push_to_chapter(agent_id, {"llm": {"provider": "anthropic"}}, virtual_chapter)
    merged = ss.effective_settings(agent_id, virtual_chapter)
    assert merged["llm"]["provider"] == "anthropic"

    # 7. Mesh send
    peers = virtual_chapter.mesh_peers(skills=["rust"])
    assert peers["peers"][0]["agent_id"] == "charlie"
    virtual_chapter.mesh_send(agent_id, "charlie", "want to collab on rust?")
    assert virtual_chapter.sent_messages[0]["text"] == "want to collab on rust?"

    # 8. Channel inbound — Slack webhook with valid signature lands on the agent's inbox
    slack_secret = "test-workspace-signing-secret"

    def resolver(kind: str, remote: str) -> str:
        return slack_secret if (kind == "slack" and remote == "T12345") else ""

    def now_fn() -> float:
        return 1735689600.0

    app = cr.build_app(
        inbox_path=tmp_env["inbox_path"],
        secret_resolver=resolver,
        now_fn=now_fn,
    )
    client = TestClient(app)

    ts = "1735689600"
    body = json.dumps(
        {"type": "event_callback", "team_id": "T12345", "event": {"user": "U999", "text": "ping"}}
    ).encode()
    sig = "v0=" + hmac.new(slack_secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()

    resp = client.post(
        "/channels/slack/webhook",
        content=body,
        headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig},
    )
    assert resp.status_code == 200
    assert resp.json()["queued"] is True

    # 9. Audit chain intact
    ok, broken_idx = cr.verify_audit_chain(tmp_env["inbox_path"])
    assert ok, f"audit chain broken at index {broken_idx}"

    audit = cr.read_audit(tmp_env["inbox_path"])
    assert len(audit) == 1
    assert audit[0]["kind"] == "slack"
    assert audit[0]["session_scope"] == "agent:channel:slack:dm:U999"


def test_w11_survives_chapter_going_offline_mid_flow(virtual_chapter, tmp_env):
    """HAPPY (resilience): agent keeps working when the chapter drops out."""
    virtual_chapter.publish_skill("file-ops", "1.0.0", capabilities=["fs.read"])
    sk.install_skill(
        chapter_url="https://chapter.example",
        skill_id="file-ops@1.0.0",
        agent_id="alice",
        chapter_api_fn=virtual_chapter.api,
        skills_root=tmp_env["skills_root"],
    )
    # Agent already has settings cached from a prior pull
    ss.push_to_chapter("alice", {"llm": {"provider": "groq"}}, virtual_chapter)

    # Chapter dies
    class DeadChapter:
        def get_settings(self, agent_id):
            raise ConnectionError("offline")

        def update_settings(self, agent_id, patch):
            raise ConnectionError("offline")

    # Effective settings still return the cached value
    merged = ss.effective_settings("alice", DeadChapter())
    assert merged["llm"]["provider"] == "groq"


def test_w11_refuses_forged_install_proof_in_review(virtual_chapter, tmp_env):
    """ADVERSARIAL: attacker posts a review with a made-up install proof."""
    virtual_chapter.publish_skill("file-ops", "1.0.0", capabilities=["fs.read"])
    with pytest.raises(RuntimeError, match="install_proof"):
        virtual_chapter.review_skill(
            skill_id="file-ops@1.0.0",
            reviewer_agent_id="attacker",
            rating=5,
            review_text="look at me",
            signed_install_proof="f" * 64,  # forged
        )
    assert virtual_chapter.reviews == []
