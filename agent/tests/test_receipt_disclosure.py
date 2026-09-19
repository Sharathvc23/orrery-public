"""sm-parc selective disclosure — reveal k receipts with inclusion proofs.

Round-trip: the agent emits a disclosure bundle (signed PARC + chosen receipts +
Merkle inclusion proofs, all from one ledger snapshot); a verifier checks it
fully offline — no fetch back to the discloser. Adversarial: a tampered proof,
a tampered/wrong root, a tampered receipt, and a receipt that was never in the
ledger are all rejected.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("sm_parc", reason="needs sm-parc")
pytest.importorskip("nacl.signing", reason="needs PyNaCl for a real Ed25519 key")

from community_member import receipt_disclosure as rd
from community_member.arp import (
    AgencyLog,
    build_receipt,
    did_from_private_key,
    sign_receipt,
)
from community_member.config import Config
from community_member.server import create_app

_STAMP = "2026-07-07T00:00:00Z"
_UNTIL = "2026-08-06T00:00:00Z"


def _cfg_and_seed(agent_id="alice-agent"):
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    c = Config()
    c.agent_id = agent_id
    c.name = "Alice"
    c.api_key = "x"
    c.private_key = base64.b64encode(bytes(sk)).decode()
    c.public_key = base64.b64encode(bytes(sk.verify_key)).decode()
    return c, bytes(sk)


def _receipt(seed: bytes, *, summary: str, issued_at: str) -> dict:
    did = did_from_private_key(seed)
    r = build_receipt(
        action={"category": "message_sent", "human_summary": summary, "outcome": "completed"},
        issuer_did=did,
        principal_did=did,
        issued_at=issued_at,
    )
    return sign_receipt(r, seed)


def _populate(home, seed: bytes, n: int) -> list[str]:
    """Append n signed receipts to the Agency Log; return their ids in issued order."""
    log = AgencyLog(home=home)
    ids = []
    for i in range(n):
        r = _receipt(seed, summary=f"receipt {i}", issued_at=f"2026-07-0{i + 1}T00:00:00Z")
        log.append(r)
        ids.append(r["receipt_id"])
    return ids


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("community_member.config.CONFIG_DIR", tmp_path)
    cfg, seed = _cfg_and_seed()
    # Odd N exercises the duplicated-leaf edge of the VRP tree.
    ids = _populate(tmp_path, seed, n=5)
    return cfg, seed, ids


def _bundle(cfg, ids):
    return rd.build_disclosure(cfg, receipt_ids=ids, as_of=_STAMP, valid_from=_STAMP, valid_until=_UNTIL)


def _issuer_of(bundle):
    """The did:key the bundle's credential names.

    These tests assert structural properties — proof validity and Merkle
    inclusion — so they supply the bundle's own issuer as the expected one.
    The separate issuer-binding tests are the ones that vary it.
    """
    return bundle["credential"]["issuer"]


def test_disclose_and_verify_roundtrip(env):
    cfg, _seed, ids = env
    bundle = _bundle(cfg, [ids[0], ids[4]])  # first + last leaf (odd-N edge)
    assert len(bundle["disclosed"]) == 2
    # The proofs commit to the FULL ledger, not just the disclosed subset.
    assert bundle["disclosed"][0]["proof"]["leaf_count"] == 5

    result = rd.verify_disclosure(bundle, expected_issuer=_issuer_of(bundle))
    assert result["ok"] is True
    assert result["credential_ok"] is True
    assert [r["included"] for r in result["receipts"]] == [True, True]

    # The bundle survives JSON serialization — what the CLI/API actually emit.
    assert rd.verify_disclosure(json.loads(json.dumps(bundle)), expected_issuer=_issuer_of(bundle))["ok"] is True


def test_tampered_proof_rejected(env):
    cfg, _seed, ids = env
    bundle = _bundle(cfg, [ids[1]])
    step = bundle["disclosed"][0]["proof"]["path"][0]
    step["sibling"] = "00" * 32
    result = rd.verify_disclosure(bundle, expected_issuer=_issuer_of(bundle))
    assert result["ok"] is False
    assert result["credential_ok"] is True  # the credential itself is untouched
    assert result["receipts"][0]["included"] is False


def test_wrong_root_rejected(env):
    cfg, _seed, ids = env
    bundle = _bundle(cfg, [ids[0]])
    bundle["credential"]["credentialSubject"]["behavioral_merkle_root"] = "sha256:" + "0" * 64
    result = rd.verify_disclosure(bundle, expected_issuer=_issuer_of(bundle))
    # The root is a signed field: mutating it breaks the credential proof too.
    assert result["credential_ok"] is False
    assert result["receipts"][0]["included"] is False
    assert result["ok"] is False


def test_tampered_receipt_rejected(env):
    cfg, _seed, ids = env
    bundle = _bundle(cfg, [ids[2]])
    bundle["disclosed"][0]["receipt"]["action"]["human_summary"] = "REWRITTEN HISTORY"
    result = rd.verify_disclosure(bundle, expected_issuer=_issuer_of(bundle))
    assert result["ok"] is False
    assert result["receipts"][0]["included"] is False


def test_non_member_receipt_rejected(env):
    cfg, _seed, ids = env
    # Emit refuses ids that are not in the Agency Log.
    with pytest.raises(ValueError, match="not in the agency log"):
        _bundle(cfg, ["no-such-receipt"])

    # A validly signed receipt that was never in the ledger cannot ride a
    # member receipt's proof.
    from nacl.signing import SigningKey

    outsider_seed = bytes(SigningKey.generate())
    foreign = _receipt(outsider_seed, summary="outsider", issued_at="2026-07-06T00:00:00Z")
    bundle = _bundle(cfg, [ids[0]])
    bundle["disclosed"][0]["receipt"] = foreign
    result = rd.verify_disclosure(bundle, expected_issuer=_issuer_of(bundle))
    assert result["ok"] is False
    assert result["receipts"][0]["included"] is False


def test_empty_and_malformed_inputs(env):
    cfg, _seed, _ids = env
    with pytest.raises(ValueError, match="nothing to disclose"):
        _bundle(cfg, [])

    # The verifier is an untrusted-input boundary: garbage verifies False.
    assert rd.verify_disclosure({}, expected_issuer="did:key:zAny")["ok"] is False
    assert rd.verify_disclosure([], expected_issuer="did:key:zAny")["ok"] is False
    junk = {"credential": "junk", "disclosed": [{"receipt": None, "proof": 3}, "x"]}
    result = rd.verify_disclosure(junk, expected_issuer="did:key:zAny")
    assert result["ok"] is False
    assert result["credential_ok"] is False


def test_local_disclose_route(env):
    cfg, _seed, ids = env
    client = TestClient(create_app(cfg))
    r = client.post("/api/local/disclose", json={"receipt_ids": [ids[0], ids[3]]})
    assert r.status_code == 200
    assert rd.verify_disclosure(r.json(), expected_issuer=_issuer_of(r.json()))["ok"] is True

    assert client.post("/api/local/disclose", json={"receipt_ids": ["nope"]}).status_code == 400
    assert client.post("/api/local/disclose", json={"receipt_ids": []}).status_code == 400

    # No identity -> 404, mirroring /.well-known/reputation.json.
    client2 = TestClient(create_app(Config()))
    assert client2.post("/api/local/disclose", json={"receipt_ids": [ids[0]]}).status_code == 404


def test_cli_emit_and_verify(env, tmp_path, monkeypatch):
    cfg, _seed, ids = env
    monkeypatch.setattr(Config, "load", classmethod(lambda cls: cfg))
    from community_member.cli import _cmd_disclose_emit, _cmd_disclose_verify

    out = tmp_path / "bundle.json"
    assert _cmd_disclose_emit([ids[0], ids[2]], out) == 0
    issuer = _issuer_of(json.loads(out.read_text()))
    assert _cmd_disclose_verify(out, issuer=issuer, issuer_from=None) == 0

    data = json.loads(out.read_text())
    data["disclosed"][0]["proof"]["path"][0]["sibling"] = "00" * 32
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data))
    assert _cmd_disclose_verify(bad, issuer=issuer, issuer_from=None) == 2

    unknown = _cmd_disclose_emit(["no-such-receipt"], tmp_path / "never.json")
    assert unknown == 1


# ── issuer binding ────────────────────────────────────────────────────────
#
# verify_disclosure's other two checks both read the key from the bundle: the
# credential's proof verifies under the did:key the credential itself names, and
# the inclusion proofs fold to the root that same credential signs. A bundle
# whose credential, root and receipts were produced by one keypair therefore
# passes both whoever holds that keypair. Only the issuer comparison distinguishes
# a bundle from a specific org from a bundle someone minted.


def _independent_bundle(receipt_ids, tmp_path):
    """A structurally valid bundle signed by a keypair unrelated to `env`'s."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sm_arp import vrp
    from sm_parc import build_reputation_credential, did_from_private_key, inclusion_proof

    sk = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    receipts = [
        {
            "receipt_id": rid,
            "issued_at": f"2026-08-0{i + 1}T00:00:00Z",
            "agent_id": "other",
            "action": "delivered",
            "counterparty": "cp",
            "outcome": "success",
        }
        for i, rid in enumerate(receipt_ids)
    ]
    ledger = {
        "subject": "did:key:zSubject",
        "behavioral_merkle_root": vrp.behavioral_merkle_root(receipts),
        "reputation_score": 100,
        "validity_rate": 1.0,
        "receipt_count": len(receipts),
        "as_of": _STAMP,
    }
    credential = build_reputation_credential(ledger=ledger, issuer_sk=sk, valid_from=_STAMP, valid_until=_UNTIL)
    bundle = {
        "credential": credential,
        "disclosed": [{"receipt": r, "proof": dict(inclusion_proof(receipts, receipt=r))} for r in receipts],
    }
    return did_from_private_key(sk), bundle


def test_bundle_signed_by_another_key_is_refused(env, tmp_path):
    """A bundle that is internally consistent but issued by a different key."""
    other_did, bundle = _independent_bundle(["x-1", "x-2"], tmp_path)

    # Internally consistent: proof verifies, every receipt is included.
    inspected = rd.inspect_disclosure(bundle)
    assert inspected["credential_ok"] is True
    assert [r["included"] for r in inspected["receipts"]] == [True, True]
    assert "ok" not in inspected

    # Refused when checked against a different issuer.
    result = rd.verify_disclosure(bundle, expected_issuer="did:key:z6MkSomeOtherOrgAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert result["ok"] is False
    assert result["issuer_ok"] is False
    assert result["credential_ok"] is True

    # Accepted when checked against the key that actually signed it.
    assert rd.verify_disclosure(bundle, expected_issuer=other_did)["ok"] is True


def test_verify_disclosure_requires_an_expected_issuer(env):
    cfg, _seed, ids = env
    bundle = _bundle(cfg, [ids[0]])
    with pytest.raises(TypeError):
        rd.verify_disclosure(bundle)  # type: ignore[call-arg]


@pytest.mark.parametrize("expected", ["", None])
def test_an_empty_expected_issuer_never_passes(env, expected):
    cfg, _seed, ids = env
    bundle = _bundle(cfg, [ids[0]])
    result = rd.verify_disclosure(bundle, expected_issuer=expected)  # type: ignore[arg-type]
    assert result["ok"] is False
    assert result["issuer_ok"] is False


def test_cli_refuses_a_bundle_from_a_different_issuer(env, tmp_path, monkeypatch):
    cfg, _seed, ids = env
    monkeypatch.setattr(Config, "load", classmethod(lambda cls: cfg))
    from community_member.cli import _cmd_disclose_emit, _cmd_disclose_verify

    out = tmp_path / "bundle.json"
    assert _cmd_disclose_emit([ids[0]], out) == 0
    wrong = "did:key:z6MkSomeOtherOrgAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert _cmd_disclose_verify(out, issuer=wrong, issuer_from=None) == 2
