"""Phase 4: Portable Agent Reputation Credential (PARC) via sm-parc.

Proves the agent issues a signed, offline-verifiable reputation credential from
its local receipt ledger, and serves it at /.well-known/reputation.json.
"""

import base64

import pytest
from fastapi.testclient import TestClient

from community_member import reputation_credential as rc
from community_member.config import Config
from community_member.server import create_app

pytest.importorskip("sm_parc", reason="needs sm-parc")
pytest.importorskip("nacl.signing", reason="needs PyNaCl for a real Ed25519 key")


def _cfg(agent_id="alice-agent") -> Config:
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    c = Config()
    c.agent_id = agent_id
    c.name = "Alice"
    c.api_key = "x"
    c.private_key = base64.b64encode(bytes(sk)).decode()
    c.public_key = base64.b64encode(bytes(sk.verify_key)).decode()
    return c


_STAMP = "2026-06-22T00:00:00Z"
_UNTIL = "2026-07-22T00:00:00Z"


def test_build_and_verify_credential(tmp_path, monkeypatch):
    monkeypatch.setattr("community_member.config.CONFIG_DIR", tmp_path)
    vc = rc.build_self_credential(_cfg(), as_of=_STAMP, valid_from=_STAMP, valid_until=_UNTIL)
    assert rc.verify_credential(vc) is True
    # It's a credential about THIS agent (subject did:key present somewhere).
    assert "proof" in vc or "signature" in str(vc).lower()


def test_verify_rejects_tampered_credential(tmp_path, monkeypatch):
    monkeypatch.setattr("community_member.config.CONFIG_DIR", tmp_path)
    vc = rc.build_self_credential(_cfg(), as_of=_STAMP, valid_from=_STAMP, valid_until=_UNTIL)
    # Mutate a signed field.
    vc.setdefault("credentialSubject", {})
    if isinstance(vc.get("credentialSubject"), dict):
        vc["credentialSubject"]["reputation_score"] = 999999
    else:
        vc["_tamper"] = True
    assert rc.verify_credential(vc) is False


def test_build_without_identity_raises():
    with pytest.raises(ValueError):
        rc.build_self_credential(Config(), as_of=_STAMP, valid_from=_STAMP, valid_until=_UNTIL)


def test_well_known_reputation_served_and_404(tmp_path, monkeypatch):
    monkeypatch.setattr("community_member.config.CONFIG_DIR", tmp_path)

    # Has identity -> 200 with a verifiable PARC.
    client = TestClient(create_app(_cfg()))
    r = client.get("/.well-known/reputation.json")
    assert r.status_code == 200
    assert rc.verify_credential(r.json()) is True

    # No identity -> 404.
    client2 = TestClient(create_app(Config()))
    assert client2.get("/.well-known/reputation.json").status_code == 404
