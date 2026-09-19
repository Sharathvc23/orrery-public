"""Phase 2: signed conformance badge via sm-conformance + did:key delegation.

Proves the projectnanda conformance surface: the agent uses sm-conformance for
did:key, signs a real (offline-verifiable) badge, serves it at
/.well-known/conformance.json, and the generator REFUSES to fabricate one.
"""

import base64
import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from community_member import conformance_badge as cb
from community_member.config import Config
from community_member.crypto import build_did_key
from community_member.server import create_app

_REAL_KEY = pytest.importorskip("nacl.signing", reason="needs PyNaCl for a real Ed25519 key")


def _cfg(agent_id="alice-agent") -> Config:
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    c = Config()
    c.agent_id = agent_id
    c.name = "Alice"
    c.description = "A human"
    c.skills = ["calendar"]
    c.api_key = "x"
    c.private_key = base64.b64encode(bytes(sk)).decode()
    c.public_key = base64.b64encode(bytes(sk.verify_key)).decode()
    return c


# ── did:key delegation ──────────────────────────────────────────────


def test_build_did_key_matches_sm_conformance():
    from sm_conformance.badge import derive_did_key

    pk = b"\x07" * 32
    assert build_did_key(base64.b64encode(pk).decode()) == derive_did_key(pk)


# ── signing key extraction ──────────────────────────────────────────


def test_signing_key32_extracts_seed():
    c = _cfg()
    key = cb.signing_key32(c)
    assert isinstance(key, bytes) and len(key) == 32


def test_signing_key32_none_when_absent():
    c = Config()
    assert cb.signing_key32(c) is None


# ── real badge sign + verify ────────────────────────────────────────


def _badge(c):
    return cb.build_self_badge(
        c,
        suite_digest="sha256:" + "a" * 64,
        protocol_versions=["0.3", "0.2"],
        passed=42,
        failed=0,
        completed_at="2026-06-22T00:00:00+00:00",
    )


def test_build_and_verify_badge():
    c = _cfg()
    badge = _badge(c)
    payload = cb.verify_badge(badge)  # raises if invalid
    assert payload["passed"] == 42
    assert payload["failed"] == 0
    assert badge["signed_by"] == build_did_key(c.public_key)


def test_verify_rejects_tampered_badge():
    c = _cfg()
    badge = _badge(c)
    badge["passed"] = 999  # tamper after signing
    with pytest.raises(Exception):
        cb.verify_badge(badge)


def test_build_self_badge_without_key_raises():
    with pytest.raises(ValueError):
        cb.build_self_badge(
            Config(),
            suite_digest="sha256:" + "a" * 64,
            protocol_versions=["0.3"],
            passed=1,
            failed=0,
            completed_at="2026-06-22T00:00:00+00:00",
        )


# ── serving route ───────────────────────────────────────────────────


def test_well_known_conformance_present_and_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    client = TestClient(create_app(_cfg()))

    # absent -> 404
    assert client.get("/.well-known/conformance.json").status_code == 404

    # present -> 200 with the badge
    c = _cfg()
    cb.write_badge(_badge(c))
    r = client.get("/.well-known/conformance.json")
    assert r.status_code == 200
    assert r.json()["signed_by"] == build_did_key(c.public_key)


# ── generator honesty gates ─────────────────────────────────────────


def _load_generator():
    path = Path(__file__).resolve().parents[1] / "scripts" / "gen_conformance_badge.py"
    spec = importlib.util.spec_from_file_location("gen_conformance_badge", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generator_refuses_without_vectors(tmp_path):
    gen = _load_generator()
    rc = gen.main(["--vectors-root", str(tmp_path), "--passed", "5", "--failed", "0"])
    assert rc == 2  # no signing/ subtree -> refuse


def test_generator_refuses_without_counts(tmp_path):
    gen = _load_generator()
    (tmp_path / "signing").mkdir()
    (tmp_path / "signing" / "v.json").write_text("{}")
    rc = gen.main(["--vectors-root", str(tmp_path)])  # no counts
    assert rc == 2


def test_generator_happy_path_writes_verifiable_badge(tmp_path, monkeypatch):
    gen = _load_generator()
    (tmp_path / "signing").mkdir()
    (tmp_path / "signing" / "v.json").write_text('{"case": 1}')
    out = tmp_path / "badge.json"

    c = _cfg()
    monkeypatch.setattr(gen.Config, "load", classmethod(lambda cls: c))

    rc = gen.main(["--vectors-root", str(tmp_path), "--passed", "7", "--failed", "0", "--out", str(out)])
    assert rc == 0
    badge = cb.load_badge(out)
    assert badge is not None
    payload = cb.verify_badge(badge)  # real, verifiable
    assert payload["passed"] == 7


def test_generator_warns_on_asserted_counts(tmp_path, monkeypatch, capsys):
    """operator-asserted --passed/--failed counts (no junit from a real run)
    MUST emit a loud warning, so a badge can't be SILENTLY minted from numbers
    nobody verified (`--passed 999 --failed 0`). The signature proves origin +
    integrity, never that a suite actually ran."""
    gen = _load_generator()
    (tmp_path / "signing").mkdir()
    (tmp_path / "signing" / "v.json").write_text('{"case": 1}')
    monkeypatch.setattr(gen.Config, "load", classmethod(lambda cls: _cfg()))

    rc = gen.main(
        ["--vectors-root", str(tmp_path), "--passed", "7", "--failed", "0", "--out", str(tmp_path / "b.json")]
    )
    assert rc == 0
    err = capsys.readouterr().err.lower()
    assert "asserted" in err and "did not run" in err, f"no honesty warning on asserted counts: {err!r}"


def test_generator_does_not_warn_on_real_junit_run(tmp_path, monkeypatch, capsys):
    """Counts derived from a real pytest --junitxml report are a genuine run, so
    no asserted-counts warning is emitted."""
    gen = _load_generator()
    (tmp_path / "signing").mkdir()
    (tmp_path / "signing" / "v.json").write_text('{"case": 1}')
    junit = tmp_path / "junit.xml"
    junit.write_text('<testsuite tests="3" failures="0" errors="0" skipped="0"></testsuite>')
    monkeypatch.setattr(gen.Config, "load", classmethod(lambda cls: _cfg()))

    rc = gen.main(["--vectors-root", str(tmp_path), "--junitxml", str(junit), "--out", str(tmp_path / "b.json")])
    assert rc == 0
    assert "asserted" not in capsys.readouterr().err.lower()
