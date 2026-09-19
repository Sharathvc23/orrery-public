"""Tests for /page/reputation — the counterparty-corroborated reputation surface
(spec/vrp/0.3 §C). First surface that makes the VRP layer visible in the portal:
a member's nanda-rep/0.2 standing + recent receipts (corroborated vs self-attested)
+ a chapter leaderboard ranked by corroborated reputation.

The builder lazily imports ``arp`` + ``vrp`` and reads the module-global
``members``; tests monkeypatch those plus ``sm_arp.vrp.is_corroborated`` so the
render is exercised without an Issuer Log or real co-signing crypto (the
corroboration math itself is covered by test_cosign / test_vrp_lockstep).

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
import sm_arp.vrp as smvrp  # noqa: E402

import arp  # noqa: E402
import surfaces  # noqa: E402
import vrp  # noqa: E402


def _facet(*, root="sha256:r", score=5.0, corr=0.5, count=2) -> dict:
    return {
        "behavioral_merkle_root": root,
        "reputation_score": score,
        "corroboration_rate": corr,
        "receipt_count": count,
        "scoring_method": "nanda-rep/0.2",
    }


def _receipt(category="message_sent", summary="Replied to Maria.", *, corroborated=False) -> dict:
    r = {
        "version": "arp/0.1",
        "receipt_id": f"r-{summary[:8]}",
        "issued_at": "2026-06-13T14:00:00Z",
        "action": {"category": category, "human_summary": summary, "outcome": "completed"},
    }
    if corroborated:
        r["evidence"] = {"witness_signatures": ["sig"]}
    return r


@pytest.fixture
def world(monkeypatch):
    """Wire fake did-resolution, ledgers, receipts, and corroboration so the
    surface renders deterministically. ``facets`` / ``receipts`` are keyed by
    did; ``members`` is the chapter roster the leaderboard fans out over.
    """
    state = {"facets": {}, "receipts": {}}

    def fake_did(agent_id: str) -> str:
        # Every roster member resolves to a did EXCEPT those explicitly blanked.
        return "" if state.get("no_did") == agent_id else f"did:key:z{agent_id}"

    async def fake_ledger(did, *, ledger_uri="", method="nanda-rep/0.1", **kw):
        if state.get("raise_for") == did:
            raise RuntimeError("scoring service down")
        return {}, state["facets"].get(did, {"behavioral_merkle_root": None})

    async def fake_list(did, *, limit=100):
        return list(state["receipts"].get(did, []))[:limit]

    async def fake_principals(*, scan_limit=1000, limit=200):
        # The leaderboard's data source: principals that have receipts in the
        # Issuer Log (keyed by did), independent of the member roster.
        return list(state.get("principals", []))[:limit]

    monkeypatch.setattr(arp, "did_key_for_member", fake_did)
    monkeypatch.setattr(arp, "list_for_principal", fake_list)
    monkeypatch.setattr(arp, "list_principals_with_receipts", fake_principals)
    monkeypatch.setattr(vrp, "build_principal_ledger", fake_ledger)
    # is_corroborated is imported fresh inside the builder via `from sm_arp.vrp
    # import is_corroborated`, so patching the attribute on the module takes.
    monkeypatch.setattr(smvrp, "is_corroborated", lambda r: bool((r.get("evidence") or {}).get("witness_signatures")))
    monkeypatch.setattr(surfaces, "members", {})
    monkeypatch.setattr(surfaces, "AGENT_ID", "test-chapter")  # init() sets this in prod
    return state


def _components(surface_dict: dict) -> list[dict]:
    return (surface_dict.get("updateComponents") or {}).get("components", [])


def _by_id(surface_dict: dict) -> dict[str, dict]:
    return {c["id"]: c for c in _components(surface_dict)}


def _texts(surface_dict: dict) -> str:
    out: list[str] = []
    for c in _components(surface_dict):
        for k in ("text", "label", "title", "caption"):
            v = c.get(k)
            if isinstance(v, str):
                out.append(v)
    return " | ".join(out)


def _table_rows(surface_dict: dict, table_id: str) -> list[list[str]]:
    return _by_id(surface_dict)[table_id]["rows"]


# ══════════════════════════════════════════════════════════════════════
# Structural invariant — every render must be a well-formed surface
# ══════════════════════════════════════════════════════════════════════


def _assert_well_formed(surface_dict: dict) -> None:
    """C4: assert the surface is internally consistent, not just non-empty.
    Root resolves, every child id referenced resolves to a real component."""
    assert surface_dict["version"].startswith("0.1")  # 0.9 / 0.10 envelope
    uc = surface_dict["updateComponents"]
    ids = {c["id"] for c in uc["components"]}
    assert uc["root"] in ids
    for c in uc["components"]:
        for child in c.get("children", []):
            assert child in ids, f"dangling child ref {child!r}"
        if "child" in c:
            assert c["child"] in ids, f"dangling child ref {c['child']!r}"


# ══════════════════════════════════════════════════════════════════════
# HAPPY
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_renders_subject_standing_metrics(world):  # HAPPY
    world["facets"]["did:key:zalice"] = _facet(score=7.0, corr=0.75, count=4)
    world["receipts"]["did:key:zalice"] = [_receipt(corroborated=True)]
    result = await surfaces.build_reputation_surface(target="alice")
    _assert_well_formed(result)
    byid = _by_id(result)
    assert byid["pf-rep-score"]["value"] == "7"
    assert byid["pf-rep-corr"]["value"] == "75%"
    assert byid["pf-rep-count"]["value"] == "4"


@pytest.mark.asyncio
async def test_recent_receipts_flag_corroboration(world):  # HAPPY
    world["facets"]["did:key:zalice"] = _facet()
    world["receipts"]["did:key:zalice"] = [
        _receipt(summary="Co-signed deal.", corroborated=True),
        _receipt(summary="Solo note.", corroborated=False),
    ]
    result = await surfaces.build_reputation_surface(target="alice")
    rows = _table_rows(result, "rep-receipts")
    flags = {row[2]: row[3] for row in rows}  # summary -> standing flag
    assert flags["Co-signed deal."] == "✓ corroborated"
    assert flags["Solo note."] == "self-attested"


@pytest.mark.asyncio
async def test_leaderboard_ranks_principals_by_score(world):  # HAPPY
    surfaces.members = {
        "alice": {"name": "Alice"},
        "bob": {"name": "Bob"},
        "carol": {"name": "Carol"},
    }
    world["principals"] = ["did:key:zalice", "did:key:zbob", "did:key:zcarol"]  # from the Issuer Log
    world["facets"]["did:key:zalice"] = _facet(score=3.0, corr=0.3, count=3)
    world["facets"]["did:key:zbob"] = _facet(score=9.0, corr=0.9, count=9)
    world["facets"]["did:key:zcarol"] = _facet(score=6.0, corr=0.6, count=6)
    result = await surfaces.build_reputation_surface(target="alice")
    rows = _table_rows(result, "rep-board")
    members_in_order = [row[1] for row in rows]
    assert members_in_order == ["@bob", "@carol", "@alice"]  # 9 > 6 > 3, labelled from roster
    assert rows[0][2] == "9" and rows[0][3] == "90%" and rows[0][4] == "9"


# ══════════════════════════════════════════════════════════════════════
# EDGE
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_no_target_defaults_to_chapter(world):  # EDGE
    # AGENT_ID is "test-chapter"; with no facet it shows the empty-standing path
    # but must still render against the chapter's own did, not crash.
    result = await surfaces.build_reputation_surface(target=None)
    _assert_well_formed(result)
    assert "test-chapter" in _texts(result)


@pytest.mark.asyncio
async def test_subject_with_no_receipts_shows_empty_standing(world):  # EDGE
    world["facets"]["did:key:zalice"] = {"behavioral_merkle_root": None}
    result = await surfaces.build_reputation_surface(target="alice")
    _assert_well_formed(result)
    byid = _by_id(result)
    assert "pf-rep-score" not in byid  # no metrics rendered
    assert "rep-none" in byid  # the explicit empty-standing callout
    assert "No corroborated standing" in _texts(result)


@pytest.mark.asyncio
async def test_empty_issuer_log_shows_empty_leaderboard(world):  # EDGE
    world["facets"]["did:key:zalice"] = _facet()
    world["principals"] = []  # no receipt-bearing principals
    result = await surfaces.build_reputation_surface(target="alice")
    assert "rep-board-empty" in _by_id(result)
    assert "leaderboard fills in" in _texts(result)


@pytest.mark.asyncio
async def test_principal_without_roster_label_shown_as_short_did(world):  # EDGE
    # A receipt-bearing principal that isn't in the member roster still ranks —
    # it just shows a short did instead of an @handle.
    surfaces.members = {"alice": {"name": "Alice"}}
    external = "did:key:zSomeRandomExternalPrincipalABCDEFGH"
    world["principals"] = ["did:key:zalice", external]
    world["facets"]["did:key:zalice"] = _facet(score=4.0)
    world["facets"][external] = _facet(score=2.0)
    result = await surfaces.build_reputation_surface(target="alice")
    labels = [r[1] for r in _table_rows(result, "rep-board")]
    assert "@alice" in labels
    assert any(lbl.startswith("did:key:z") and "…" in lbl for lbl in labels)  # external → short did


@pytest.mark.asyncio
async def test_principal_with_zero_receipts_excluded_from_leaderboard(world):  # EDGE
    surfaces.members = {"alice": {"name": "Alice"}}
    world["principals"] = ["did:key:zalice", "did:key:znewbie"]
    world["facets"]["did:key:zalice"] = _facet(score=4.0)
    world["facets"]["did:key:znewbie"] = {"behavioral_merkle_root": None}  # no receipts
    result = await surfaces.build_reputation_surface(target="alice")
    rows = _table_rows(result, "rep-board")
    assert [r[1] for r in rows] == ["@alice"]


@pytest.mark.asyncio
async def test_startup_member_not_given_at_handle(world):  # EDGE
    # A startup team agent's did is excluded from the roster label map, so even
    # if it has receipts it ranks under a short did, never an @STARTUP handle.
    surfaces.members = {"alice": {"name": "Alice"}, "STARTUP-acme": {"name": "Acme Bot"}}
    world["principals"] = ["did:key:zSTARTUP-acme"]
    world["facets"]["did:key:zSTARTUP-acme"] = _facet(score=99.0)
    result = await surfaces.build_reputation_surface(target="alice")
    rows = _table_rows(result, "rep-board")
    assert all(not r[1].startswith("@STARTUP") for r in rows)


# ══════════════════════════════════════════════════════════════════════
# FAILURE
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_standing_service_failure_renders_warning_not_crash(world):  # FAILURE
    world["facets"]["did:key:zalice"] = _facet()
    world["raise_for"] = "did:key:zalice"  # subject ledger build throws
    result = await surfaces.build_reputation_surface(target="alice")  # must NOT raise
    _assert_well_formed(result)
    assert "rep-err" in _by_id(result)
    assert "temporarily unavailable" in _texts(result)


@pytest.mark.asyncio
async def test_subject_without_identity_renders_info_not_crash(world):  # FAILURE
    surfaces.members = {}
    world["no_did"] = "alice"
    result = await surfaces.build_reputation_surface(target="alice")
    _assert_well_formed(result)
    assert "rep-noid" in _by_id(result)


# ══════════════════════════════════════════════════════════════════════
# ADVERSARIAL
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_one_bad_principal_does_not_sink_leaderboard(world):  # ADVERSARIAL
    surfaces.members = {"alice": {"name": "Alice"}, "bob": {"name": "Bob"}}
    world["principals"] = ["did:key:zalice", "did:key:zbob"]
    world["facets"]["did:key:zalice"] = _facet(score=4.0)
    world["facets"]["did:key:zbob"] = _facet(score=8.0)
    world["raise_for"] = "did:key:zbob"  # bob's standing build explodes
    result = await surfaces.build_reputation_surface(target="alice")
    rows = _table_rows(result, "rep-board")
    # bob dropped (his ledger raised), alice survives — board is not empty.
    assert [r[1] for r in rows] == ["@alice"]


@pytest.mark.asyncio
async def test_hostile_target_is_sanitised(world):  # ADVERSARIAL
    result = await surfaces.build_reputation_surface(target="../../etc/@passwd")
    _assert_well_formed(result)
    # slashes + @ stripped before use; no path-y id leaks into the surface id
    assert "/" not in result["updateComponents"]["surfaceId"]


@pytest.mark.asyncio
async def test_receipt_summary_kept_opaque_no_markup_transform(world):  # ADVERSARIAL
    world["facets"]["did:key:zalice"] = _facet()
    hostile = "<script>alert(1)</script>"
    world["receipts"]["did:key:zalice"] = [_receipt(summary=hostile, corroborated=False)]
    result = await surfaces.build_reputation_surface(target="alice")
    rows = _table_rows(result, "rep-receipts")
    # Preserved verbatim as data (renderer escapes), not transformed to markup.
    assert any(hostile[:40] in cell for row in rows for cell in row)
    assert all(isinstance(cell, str) for row in rows for cell in row)
