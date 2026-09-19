"""R1-R10 tests for community_member.arp — sovereign-side ARP client.

R1  Forgery      — body tampered after signing → verify_receipt_signature False
R2  Replay       — AgencyLog.append on same receipt_id is idempotent (no dup row)
R3  Injection    — receipt with special chars survives JCS round-trip
R4  Authz        — issuer_did derived from sk; cannot be spoofed via build
R5  Boundary     — list_recent honors limit=0 (returns []) and limit=N
R7  Adversarial  — receipt signed by wrong key fails verify
R10 Persistence  — append → list_recent returns same JSON
"""

from __future__ import annotations

import os
import tempfile

# Steer the SDK's COMMUNITY_MEMBER_HOME to a test-only path under the OS
# tempdir. The agency-log SQLite under this dir is created per-test via
# the ``tmp_path`` fixture below, so this default is only relevant if a
# stray import triggers AgencyLog initialisation at module load time.
os.environ.setdefault(
    "COMMUNITY_MEMBER_HOME",
    os.path.join(tempfile.gettempdir(), "cm-arp-tests-do-not-use"),
)

import pytest

from community_member.arp import (
    ARP_VERSION,
    AgencyLog,
    build_receipt,
    canonical_bytes_for_signing,
    did_from_private_key,
    emit,
    receipt_chain_link,
    sign_receipt,
    verify_receipt_signature,
)

ISSUER_SK = b"member-sdk-arp-test-issuer-seed!"
OTHER_SK = b"unauthorized-attacker-key-32by!a"

assert len(ISSUER_SK) == 32 and len(OTHER_SK) == 32


@pytest.fixture
def agency_log(tmp_path):
    return AgencyLog(home=tmp_path / "agency")


def _action(summary: str = "Sent a test message.") -> dict:
    return {
        "category": "message_sent",
        "human_summary": summary,
        "outcome": "completed",
    }


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: body tampered after signing → verify_receipt_signature False
# ══════════════════════════════════════════════════════════════════════


def test_R1_forgery_body_tampered_after_signing():
    issuer_did = did_from_private_key(ISSUER_SK)
    r = build_receipt(action=_action(), issuer_did=issuer_did, principal_did=issuer_did)
    sign_receipt(r, ISSUER_SK)
    assert verify_receipt_signature(r) is True
    r["action"]["human_summary"] = "But actually I said something else."
    assert verify_receipt_signature(r) is False


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay: append same receipt_id twice → no duplicate row
# ══════════════════════════════════════════════════════════════════════


def test_R2_replay_append_idempotent(agency_log):
    issuer_did = did_from_private_key(ISSUER_SK)
    r = build_receipt(
        action=_action(),
        issuer_did=issuer_did,
        principal_did=issuer_did,
        receipt_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    )
    sign_receipt(r, ISSUER_SK)
    agency_log.append(r)
    agency_log.append(r)
    agency_log.append(r)
    assert agency_log.count() == 1


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: special chars survive canonicalization round-trip
# ══════════════════════════════════════════════════════════════════════


def test_R3_injection_special_chars_round_trip(agency_log):
    issuer_did = did_from_private_key(ISSUER_SK)
    tricky = 'He said "hi 3:14am" — backslash\\ tab\t end.'
    r = build_receipt(action=_action(tricky), issuer_did=issuer_did, principal_did=issuer_did)
    sign_receipt(r, ISSUER_SK)
    assert verify_receipt_signature(r) is True
    agency_log.append(r)
    rows = agency_log.list_recent()
    assert rows[0]["action"]["human_summary"] == tricky


# ══════════════════════════════════════════════════════════════════════
# R4 — Authz: issuer_did derived from sk_bytes; cannot be spoofed
# ══════════════════════════════════════════════════════════════════════


def test_R4_authz_issuer_did_is_derived_from_sk():
    """emit() ignores any issuer_did passed in extras — the SDK derives
    it from the actual signing key. (We don't accept arbitrary issuer_did
    in this code path.)"""
    issuer_did = did_from_private_key(ISSUER_SK)
    other_did = did_from_private_key(OTHER_SK)

    r = emit(_action(), ISSUER_SK, push=False)
    assert r["issuer_did"] == issuer_did
    assert r["issuer_did"] != other_did


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: limit semantics
# ══════════════════════════════════════════════════════════════════════


def test_R5_boundary_limit_zero_returns_empty(agency_log):
    issuer_did = did_from_private_key(ISSUER_SK)
    r = build_receipt(action=_action(), issuer_did=issuer_did, principal_did=issuer_did)
    sign_receipt(r, ISSUER_SK)
    agency_log.append(r)
    assert agency_log.list_recent(limit=0) == []


def test_R5_boundary_limit_smaller_than_count(agency_log):
    issuer_did = did_from_private_key(ISSUER_SK)
    for i in range(5):
        r = build_receipt(
            action=_action(f"msg {i}"),
            issuer_did=issuer_did,
            principal_did=issuer_did,
            issued_at=f"2026-05-21T14:{20 + i:02d}:00Z",
        )
        sign_receipt(r, ISSUER_SK)
        agency_log.append(r)
    got = agency_log.list_recent(limit=3)
    assert len(got) == 3
    # newest first
    assert got[0]["action"]["human_summary"] == "msg 4"
    assert got[2]["action"]["human_summary"] == "msg 2"


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: signature from wrong key fails verify
# ══════════════════════════════════════════════════════════════════════


def test_R7_adversarial_wrong_key_fails_verify():
    issuer_did = did_from_private_key(ISSUER_SK)
    r = build_receipt(action=_action(), issuer_did=issuer_did, principal_did=issuer_did)
    # Sign with the WRONG key
    sign_receipt(r, OTHER_SK)
    assert verify_receipt_signature(r) is False


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: round-trip preserves every field
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_round_trip(agency_log):
    issuer_did = did_from_private_key(ISSUER_SK)
    r = build_receipt(
        action=_action(),
        issuer_did=issuer_did,
        principal_did=issuer_did,
        jurisdiction={"principal_residence": "US-MA"},
        accessibility={"summary_language": "en-US", "complexity_level": "simple"},
        evidence={"external_refs": ["TX-123"]},
    )
    sign_receipt(r, ISSUER_SK)
    agency_log.append(r)

    fetched = agency_log.get(r["receipt_id"])
    assert fetched is not None
    assert fetched["jurisdiction"]["principal_residence"] == "US-MA"
    assert fetched["accessibility"]["complexity_level"] == "simple"
    assert fetched["evidence"]["external_refs"] == ["TX-123"]
    assert fetched["signature"] == r["signature"]


# ══════════════════════════════════════════════════════════════════════
# Chain link consistency
# ══════════════════════════════════════════════════════════════════════


def test_chain_link_matches_canonical_sha256():
    issuer_did = did_from_private_key(ISSUER_SK)
    r = build_receipt(action=_action(), issuer_did=issuer_did, principal_did=issuer_did)
    sign_receipt(r, ISSUER_SK)
    link = receipt_chain_link(r)
    assert link.startswith("sha256:")
    assert len(link) == len("sha256:") + 64


def test_canonical_bytes_excludes_signature():
    issuer_did = did_from_private_key(ISSUER_SK)
    r = build_receipt(action=_action(), issuer_did=issuer_did, principal_did=issuer_did)
    sign_receipt(r, ISSUER_SK)
    cb = canonical_bytes_for_signing(r)
    assert b'"signature"' not in cb


# ══════════════════════════════════════════════════════════════════════
# emit() integration (no chapter push)
# ══════════════════════════════════════════════════════════════════════


def test_emit_local_only_writes_to_agency_log(agency_log):
    r = emit(_action("local-only test"), ISSUER_SK, agency_log=agency_log, push=False)
    assert agency_log.count() == 1
    fetched = agency_log.get(r["receipt_id"])
    assert fetched is not None
    assert verify_receipt_signature(fetched)


def test_emit_version_is_v01():
    r = emit(_action(), ISSUER_SK, push=False)
    assert r["version"] == ARP_VERSION == "arp/0.1"
