"""Chapter-side openclaw-skill version gate.

The chapter rejects any inbound request whose effective origin is
``openclaw`` and whose ``X-Openclaw-Skill-Version`` header is missing
or below ``MIN_OPENCLAW_SKILL_VERSION``. Response is HTTP 426
Upgrade Required carrying the upgrade-command in the body.

Prosecution cases (HAPPY / EDGE / FAILURE / ADVERSARIAL):
  - HAPPY: openclaw client at the minimum version passes through
  - HAPPY: sovereign client without the header passes through (gate
    is openclaw-specific)
  - EDGE: openclaw client BELOW minimum is blocked
  - EDGE: openclaw client at MINIMUM (exact match) passes
  - EDGE: openclaw client at well-above-minimum passes
  - FAILURE: openclaw client with no version header is blocked
  - FAILURE: malformed version string is blocked
  - ADVERSARIAL: self-asserted sovereign origin + a below-minimum
    openclaw version header → NOT blocked. The gate is advisory, not a
    security control: ``origin`` is self-asserted and cannot be bound to
    the did:key, so a compromised client bypasses it by design (and
    SECURITY.md). The real boundary is signature verification + authz.
"""

from __future__ import annotations

import pytest

import auth_verify

# ── Pure unit tests on the helper ──────────────────────────────────


@pytest.mark.parametrize(
    "version, expected_ok",
    [
        ("0.5.1", True),
        ("0.5.2", True),
        ("0.6.0", True),
        ("1.0.0", True),
        ("0.5.0", False),
        ("0.4.99", False),
        ("0.4.0", False),
        ("0.3.0", False),
        ("0.0.1", False),
    ],
)
def test_version_parse_min_floor(version: str, expected_ok: bool) -> None:
    """The min floor is 0.5.1 (the version that ships the gate +
    every confirmed security fix). 0.5.0 is below — 0.5.0 shipped
    the fixes but does NOT emit the version header so the chapter
    cannot distinguish it from a 0.4.x client without the header,
    and conservatively blocks both."""
    parsed = auth_verify._parse_openclaw_version(version)
    assert parsed is not None
    is_ok = parsed >= auth_verify.MIN_OPENCLAW_SKILL_VERSION
    assert is_ok is expected_ok, f"{version} → ok={is_ok}, expected {expected_ok}"


def test_version_parse_rejects_malformed() -> None:
    """Anything that isn't major.minor.patch with int components
    returns None and is treated as below-minimum."""
    for bad in ("", "0.5", "0.5.1.2", "v0.5.1", "0.5.x", "0.5.1-rc1", "abc"):
        assert auth_verify._parse_openclaw_version(bad) is None


def test_gate_passes_sovereign_origin() -> None:
    """A sovereign agent never carries the openclaw header. The
    gate must be a no-op for them regardless of header value."""
    out = auth_verify.check_openclaw_version({}, "sovereign")
    assert out is None
    out = auth_verify.check_openclaw_version({"x-openclaw-skill-version": "0.4.0"}, "sovereign")
    assert out is None
    out = auth_verify.check_openclaw_version({}, "")
    assert out is None


def test_gate_origin_is_self_asserted_advisory_not_a_security_control() -> None:
    """the gate keys off ``origin``, which is self-asserted by the
    client (peeked from the register body / stored from it). A compromised
    or malicious openclaw client can therefore bypass the gate entirely by
    declaring ``origin="sovereign"`` — even while carrying a vulnerable,
    below-minimum openclaw skill version. This is BY DESIGN, not a bug:

      - A ``did:key`` attests key ownership, not client-SOFTWARE identity;
        the openclaw skill and the sovereign SDK generate keypairs
        identically, so there is no verifiable anchor that could bind
        ``origin`` to the key. Option 1 of that change (bind origin to did:key) is
        infeasible without a publisher-signed software attestation we don't
        have.
      - The gate is an ADVISORY courtesy nudge for *honest* outdated
        clients, NOT a security boundary. The real boundary is Ed25519
        signature verification + the authz checks (see SECURITY.md).

    Locking this contract so the bypass is never re-filed as a regression
    and "fixed" by gating self-asserted sovereign origins (which would only
    break honest clients while a malicious one keeps lying)."""
    # Self-asserted sovereign origin + a known-vulnerable openclaw version
    # header → NOT gated. The header is ignored because origin != "openclaw".
    out = auth_verify.check_openclaw_version({"x-openclaw-skill-version": "0.4.0"}, "sovereign")
    assert out is None, "self-asserted sovereign origin is un-gated by design (advisory, not a control)"


def test_gate_blocks_openclaw_below_minimum() -> None:
    out = auth_verify.check_openclaw_version({"x-openclaw-skill-version": "0.4.0"}, "openclaw")
    assert out is not None
    assert out["error"] == "openclaw_skill_outdated"
    assert out["current_version"] == "0.4.0"
    assert out["minimum_version"] == "0.5.1"
    assert "upgrade_command" in out
    assert "openclaw skill install" in out["upgrade_command"]


def test_gate_blocks_openclaw_missing_header() -> None:
    """A 0.4.x client doesn't emit the header at all. The gate must
    fire on absence, not just on below-min."""
    out = auth_verify.check_openclaw_version({}, "openclaw")
    assert out is not None
    assert out["current_version"] == "<missing>"


def test_gate_passes_openclaw_at_minimum() -> None:
    out = auth_verify.check_openclaw_version({"x-openclaw-skill-version": "0.5.1"}, "openclaw")
    assert out is None


def test_gate_passes_openclaw_above_minimum() -> None:
    out = auth_verify.check_openclaw_version({"x-openclaw-skill-version": "0.6.0"}, "openclaw")
    assert out is None
    out = auth_verify.check_openclaw_version({"x-openclaw-skill-version": "1.0.0"}, "openclaw")
    assert out is None


def test_gate_handles_titlecase_header_name() -> None:
    """Starlette lowercases headers but defense-in-depth — accept
    either casing so a stricter middleware can't accidentally bypass."""
    out = auth_verify.check_openclaw_version({"X-Openclaw-Skill-Version": "0.4.0"}, "openclaw")
    assert out is not None
    assert out["current_version"] == "0.4.0"


def test_gate_response_body_contains_advisory_and_changelog() -> None:
    """The 426 body must surface enough context for the calling LLM
    to print a useful upgrade prompt to its user."""
    out = auth_verify.check_openclaw_version({}, "openclaw")
    assert out is not None
    assert "advisory" in out and out["advisory"]
    assert "upgrade_command" in out and out["upgrade_command"]
    assert "changelog_url" in out


def test_gate_malformed_version_treated_as_too_old() -> None:
    """A client sending garbage in the version header is blocked, not
    allowed through. Defends against an attacker probing what the
    parser accepts."""
    out = auth_verify.check_openclaw_version({"x-openclaw-skill-version": "0.5.x"}, "openclaw")
    assert out is not None
    out = auth_verify.check_openclaw_version({"x-openclaw-skill-version": "definitely-not-a-version"}, "openclaw")
    assert out is not None


# ── End-to-end: middleware actually returns 426 ─────────────────────


def test_e2e_post_members_openclaw_without_version_header_blocked():
    """Regression: a previous middleware ordering bug let POST /api/members
    short-circuit through the is_open_path branch without running the
    gate. This test pins the contract that a TOFU openclaw register
    WITHOUT the version header gets HTTP 426 before the handler runs.
    """
    import os

    os.environ.setdefault("AGENT_ID", "test-chapter")
    os.environ.setdefault("AGENT_NAME", "Test Chapter")

    from fastapi.testclient import TestClient

    import chapter_agent

    chapter_agent._rate_limit_store.clear()
    client = TestClient(chapter_agent.app)
    resp = client.post(
        "/api/members",
        json={
            "agent_id": "TEST-gate-probe-no-version",
            "name": "Gate Probe",
            "origin": "openclaw",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        },
    )
    assert resp.status_code == 426, f"expected 426, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert body["error"] == "openclaw_skill_outdated"
    assert "openclaw skill install" in body["upgrade_command"]


def test_e2e_post_members_openclaw_with_below_min_version_blocked():
    """openclaw client at 0.4.0 (carrying the header but below floor)
    must also be blocked."""
    import os

    os.environ.setdefault("AGENT_ID", "test-chapter")
    os.environ.setdefault("AGENT_NAME", "Test Chapter")

    from fastapi.testclient import TestClient

    import chapter_agent

    chapter_agent._rate_limit_store.clear()
    client = TestClient(chapter_agent.app)
    resp = client.post(
        "/api/members",
        json={
            "agent_id": "TEST-gate-probe-old-version",
            "name": "Gate Probe Old",
            "origin": "openclaw",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        },
        headers={"X-Openclaw-Skill-Version": "0.4.0"},
    )
    assert resp.status_code == 426
    assert resp.json()["current_version"] == "0.4.0"


def test_e2e_post_members_sovereign_origin_passes_gate():
    """A sovereign-origin register MUST NOT be gated by the openclaw
    check (no header, no version, no problem)."""
    import os

    os.environ.setdefault("AGENT_ID", "test-chapter")
    os.environ.setdefault("AGENT_NAME", "Test Chapter")

    from fastapi.testclient import TestClient

    import chapter_agent

    chapter_agent._rate_limit_store.clear()
    client = TestClient(chapter_agent.app)
    resp = client.post(
        "/api/members",
        json={
            "agent_id": "TEST-sovereign-passes",
            "name": "Sovereign",
            "origin": "sovereign",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        },
    )
    # Sovereign should not be gated by the openclaw check. The actual
    # registration behaviour (200 or different rejection) is up to
    # the handler; we only care that we're NOT at 426.
    assert resp.status_code != 426, f"sovereign incorrectly gated: {resp.text[:200]}"
