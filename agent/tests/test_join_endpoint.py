"""the join flow carries the agent's public URL so a host39-less org can
resolve this member to its own served card. Absent endpoint → older wire
shape (field omitted entirely), no crash.
"""

from community_member.a2a_client import A2AClient


def _captured_join(monkeypatch, **kwargs) -> dict:
    client = A2AClient("http://chapter.example", agent_id="alice")
    sent = {}

    def _capture(path, payload):
        sent["path"], sent["payload"] = path, payload
        return {"status": "ok"}

    monkeypatch.setattr(client, "_post_open", _capture)
    client.join_chapter("alice", "Alice", "an agent", ["python"], **kwargs)
    return sent


def test_join_includes_public_endpoint(monkeypatch):
    """HAPPY: endpoint passed → included verbatim in the /api/members payload."""
    sent = _captured_join(monkeypatch, endpoint="https://alice.example:8443")
    assert sent["path"] == "/api/members"
    assert sent["payload"]["endpoint"] == "https://alice.example:8443"


def test_join_without_endpoint_keeps_pre236_wire_shape(monkeypatch):
    """EDGE: no endpoint → the field is ABSENT (not empty) — byte-compatible
    with the older payload, and older servers see nothing new."""
    sent = _captured_join(monkeypatch)
    assert "endpoint" not in sent["payload"]
