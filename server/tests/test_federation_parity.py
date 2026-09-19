"""Tests for chapter/scripts/check_federation_parity.py.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.

These tests stub the network layer so they're hermetic — no live HTTP
to bayarea-agent during test runs. The script's structure separates
fetch_version (pure I/O) from check_parity (pure analysis), so tests
exercise check_parity directly.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add scripts/ to path so we can import the script
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_federation_parity as cfp  # noqa: E402


@pytest.fixture
def chapters_3():
    return [
        ("alpha", "https://alpha.example.com"),
        ("beta", "https://beta.example.com"),
        ("gamma", "https://gamma.example.com"),
    ]


# ══════════════════════════════════════════════════════════════════════
# HAPPY — all chapters agree
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_all_chapters_same_commit_returns_pass(chapters_3):
    def fake_fetch(url, timeout=10.0):
        return {"git_commit": "abc1234", "git_branch": "main"}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3)
    assert result["status"] == "pass"
    assert result["unique_commits"] == ["abc1234"]
    assert all(c["ok"] for c in result["chapters"])
    assert result["missing_or_unreachable"] == []


def test_HAPPY_pass_with_only_one_chapter(chapters_3):
    def fake_fetch(url, timeout=10.0):
        return {"git_commit": "abc1234"}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3[:1])
    assert result["status"] == "pass"


# ══════════════════════════════════════════════════════════════════════
# FAILURE — drift detection
# ══════════════════════════════════════════════════════════════════════


def test_FAILURE_two_different_commits_returns_drift(chapters_3):
    """Operator deployed 2 of 3 chapters — drift."""
    commits = {"alpha": "abc1234", "beta": "xyz9999", "gamma": "abc1234"}

    def fake_fetch(url, timeout=10.0):
        for name, _u in chapters_3:
            if name in url:
                return {"git_commit": commits[name]}
        return None

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3)
    assert result["status"] == "drift"
    assert sorted(result["unique_commits"]) == ["abc1234", "xyz9999"]


def test_FAILURE_one_chapter_reports_unknown_is_drift(chapters_3):
    """A chapter on 'unknown' SHA (deploy didn't bake _version.json) is
    treated as drift — it could be running any commit, we can't tell."""

    def fake_fetch(url, timeout=10.0):
        if "alpha" in url:
            return {"git_commit": "unknown"}
        return {"git_commit": "abc1234"}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3)
    assert result["status"] == "drift"


def test_FAILURE_unreachable_chapter_returns_error(chapters_3):
    """If any chapter doesn't respond, status=error (not drift) — we
    can't make a parity claim if one chapter is offline."""

    def fake_fetch(url, timeout=10.0):
        if "alpha" in url:
            return None  # unreachable
        return {"git_commit": "abc1234"}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3)
    assert result["status"] == "error"
    assert "alpha" in result["missing_or_unreachable"]


def test_FAILURE_all_chapters_unreachable_returns_error(chapters_3):
    with patch.object(cfp, "_fetch_version", return_value=None):
        result = cfp.check_parity(chapters_3)
    assert result["status"] == "error"
    assert len(result["missing_or_unreachable"]) == 3


# ══════════════════════════════════════════════════════════════════════
# EDGE
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_empty_chapter_list_is_pass(chapters_3):
    """Edge case — no chapters configured. Trivially passes."""
    with patch.object(cfp, "_fetch_version", return_value=None):
        result = cfp.check_parity([])
    assert result["status"] == "pass"
    assert result["chapters"] == []


def test_EDGE_version_response_missing_git_commit_field(chapters_3):
    """Chapter responds with /version but the payload doesn't have
    git_commit — treat as 'unknown'."""

    def fake_fetch(url, timeout=10.0):
        return {"agent_id": "alpha"}  # no git_commit key

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3)
    assert result["status"] == "drift"
    assert all(c["commit"] == "unknown" for c in result["chapters"])


# ══════════════════════════════════════════════════════════════════════
# Rendering
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_render_text_pass_format(chapters_3):
    result = {
        "status": "pass",
        "chapters": [
            {"name": "alpha", "url": "x", "commit": "abc1234", "ok": True},
            {"name": "beta", "url": "y", "commit": "abc1234", "ok": True},
        ],
        "unique_commits": ["abc1234"],
        "missing_or_unreachable": [],
    }
    text = cfp._render_text(result)
    assert "✓ PASS" in text
    assert "abc1234" in text


def test_FAILURE_render_text_drift_format(chapters_3):
    result = {
        "status": "drift",
        "chapters": [
            {"name": "alpha", "url": "x", "commit": "abc1234", "ok": True},
            {"name": "beta", "url": "y", "commit": "xyz9999", "ok": True},
        ],
        "unique_commits": ["abc1234", "xyz9999"],
        "missing_or_unreachable": [],
    }
    text = cfp._render_text(result)
    assert "DRIFT" in text
    assert "2 distinct commit" in text


# ══════════════════════════════════════════════════════════════════════
# CLI integration
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_main_with_json_output(chapters_3, capsys):
    def fake_fetch(url, timeout=10.0):
        return {"git_commit": "abc1234"}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        with patch.object(cfp, "FEDERATION_CHAPTERS", chapters_3):
            exit_code = cfp.main(["--format", "json"])
    captured = capsys.readouterr()
    import json

    parsed = json.loads(captured.out)
    assert parsed["status"] == "pass"
    assert exit_code == 0


def test_FAILURE_main_returns_exit_1_on_drift(capsys):
    chapters = [("alpha", "https://alpha.example.com"), ("beta", "https://beta.example.com")]

    def fake_fetch(url, timeout=10.0):
        return {"git_commit": "abc1234" if "alpha" in url else "xyz9999"}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        with patch.object(cfp, "FEDERATION_CHAPTERS", chapters):
            exit_code = cfp.main([])
    assert exit_code == 1


# ══════════════════════════════════════════════════════════════════════
# Stale-commit detection (Compliance-A / PR)
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_chapters_match_head_commit_returns_pass(chapters_3):
    """All chapters on the same SHA AND it matches HEAD of main."""
    from datetime import UTC, datetime, timedelta

    recent_ts = (datetime.now(UTC) - timedelta(hours=1)).isoformat()

    def fake_fetch(url, timeout=10.0):
        return {"git_commit": "c4322a6", "build_timestamp": recent_ts}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3, head_commit="c4322a6e9f8d7c6b")
    assert result["status"] == "pass"
    assert result["head_commit"] == "c4322a6"


def test_STALE_chapters_agree_but_lag_main_returns_stale(chapters_3):
    """All chapters report the same old SHA; main has moved >7 days ahead.

    This is the "nobody deployed in two weeks" failure mode that
    PR's cross-chapter parity check intentionally missed.
    """
    from datetime import UTC, datetime, timedelta

    old_ts = (datetime.now(UTC) - timedelta(days=14)).isoformat()

    def fake_fetch(url, timeout=10.0):
        return {"git_commit": "oldcommit", "build_timestamp": old_ts}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3, head_commit="newhead1234567")
    assert result["status"] == "stale"
    assert result["stale_days"] is not None
    assert result["stale_days"] > 7


def test_HAPPY_chapters_slightly_behind_main_returns_drift_not_stale(chapters_3):
    """All chapters agree but lag main by only 3 days — that's a
    routine "you should deploy" signal, not the alarming "nobody
    deployed in weeks" signal. Marked drift, not stale."""
    from datetime import UTC, datetime, timedelta

    recent_lag_ts = (datetime.now(UTC) - timedelta(days=3)).isoformat()

    def fake_fetch(url, timeout=10.0):
        return {"git_commit": "oldcommit", "build_timestamp": recent_lag_ts}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3, head_commit="newhead12")
    assert result["status"] == "drift"


def test_EDGE_no_head_commit_skips_stale_check(chapters_3):
    """When head_commit is not provided, stale detection is disabled
    and behavior matches the original pre-PR-237 semantics."""

    def fake_fetch(url, timeout=10.0):
        return {"git_commit": "abc1234"}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3, head_commit=None)
    assert result["status"] == "pass"
    assert result["head_commit"] is None


def test_EDGE_malformed_build_timestamp_does_not_crash(chapters_3):
    """A chapter that reports an unparseable build_timestamp should
    not crash the analyzer; falls back to drift."""

    def fake_fetch(url, timeout=10.0):
        return {"git_commit": "oldcommit", "build_timestamp": "not-an-iso-timestamp"}

    with patch.object(cfp, "_fetch_version", side_effect=fake_fetch):
        result = cfp.check_parity(chapters_3, head_commit="newhead12")
    # All chapters agree but timestamp parse fails → can't decide stale → drift
    assert result["status"] == "drift"


def test_HAPPY_stale_renders_with_head_and_days(chapters_3):
    """Stale status rendering surfaces head_commit + stale_days."""
    result = {
        "status": "stale",
        "chapters": [
            {"name": "alpha", "url": "x", "commit": "abc1234", "ok": True, "build_timestamp": "2026-05-01T00:00:00Z"},
        ],
        "unique_commits": ["abc1234"],
        "missing_or_unreachable": [],
        "head_commit": "newhead",
        "oldest_build_ts": "2026-05-01T00:00:00Z",
        "stale_days": 21.4,
    }
    text = cfp._render_text(result)
    assert "STALE" in text
    assert "abc1234" in text
    assert "newhead" in text
    assert "21.4" in text


def test_HAPPY_pass_renders_with_head_match_note(chapters_3):
    """Pass status with head_commit should note the match in the rendering."""
    result = {
        "status": "pass",
        "chapters": [{"name": "alpha", "url": "x", "commit": "abc1234", "ok": True, "build_timestamp": ""}],
        "unique_commits": ["abc1234"],
        "missing_or_unreachable": [],
        "head_commit": "abc1234",
        "oldest_build_ts": None,
        "stale_days": None,
    }
    text = cfp._render_text(result)
    assert "matches HEAD of main" in text
