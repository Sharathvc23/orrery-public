"""The agent-side LLM meter: on disk, under the agent's own home.

Two families of defect this pins:

* A store bound to a literal path at import is shared by every agent on the
  machine regardless of ``COMMUNITY_MEMBER_HOME`` — the exact shape a sweep of
  this codebase already found in several stores. This one resolves on use.
* A token total that includes calls whose provider reported no usage looks like
  a complete measurement and is not.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member import llm_meter


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Pin the agent home, and leave the module-level override unset so the
    tests exercise the SAME resolution path the runtime uses."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(llm_meter, "METER_PATH", None)
    return tmp_path


def _record(**overrides):
    args = {
        "callsite": "think",
        "principal": "self",
        "provider": "xai",
        "model": "grok-3-mini",
        "usage": {"input_tokens": 100, "output_tokens": 20, "cached_tokens": 5},
    }
    args.update(overrides)
    llm_meter.record(**args)


# ── the store follows the home ───────────────────────────────────────────────


def test_the_store_lands_under_the_configured_home(isolated_home, monkeypatch):
    _record()
    expected_root = isolated_home / "home"
    assert Path(llm_meter.spend()["path"]).is_relative_to(expected_root)


def test_two_homes_do_not_share_a_meter(tmp_path, monkeypatch):
    """The failure this prevents: one agent's spend appearing in another's
    report because the path was chosen before the home was known."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "a"))
    _record()
    assert llm_meter.spend()["totals"]["calls"] == 1

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "b"))
    assert llm_meter.spend()["totals"]["calls"] == 0, "agent b is reading agent a's meter"

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "a"))
    assert llm_meter.spend()["totals"]["calls"] == 1, "agent a lost its own figures"


def test_a_home_set_late_is_still_honoured(tmp_path, monkeypatch):
    """Resolved on every call, not bound at import — a process that sets the
    variable late must not be left writing where it was first pointed."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "first"))
    _record()
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "second"))
    _record()
    assert Path(llm_meter.spend()["path"]).is_relative_to(tmp_path / "second")
    assert llm_meter.spend()["totals"]["calls"] == 1


def test_figures_survive_a_restart(isolated_home):
    """sqlite rather than an in-memory counter, so a restart does not read as
    spend having stopped."""
    _record()
    _record()
    # A fresh process would re-open the same file; reopening is what spend() does.
    assert llm_meter.spend()["totals"]["calls"] == 2


# ── observed is never mixed with unobserved ──────────────────────────────────


def test_a_call_with_no_usage_report_adds_no_tokens_and_is_counted():
    """⚠️ THE CENTRAL PROPERTY. Every LLM figure this repo produced before the
    meter was an estimate: inputs from a tokenizer (3.4% low against a real
    model's own prompt_tokens) and outputs that were a max_tokens ceiling. The
    meter is only worth having if an unreported call cannot masquerade as a
    measured zero."""
    _record()
    _record(usage=None)
    totals = llm_meter.spend()["totals"]
    assert totals["calls"] == 2
    assert totals["calls_without_usage"] == 1
    assert totals["input_tokens"] == 100
    assert totals["output_tokens"] == 20


def test_usage_accumulates_when_it_is_reported():
    _record()
    _record()
    totals = llm_meter.spend()["totals"]
    assert (totals["input_tokens"], totals["output_tokens"], totals["cached_tokens"]) == (200, 40, 10)
    assert totals["calls_without_usage"] == 0


def test_a_partial_usage_report_contributes_only_what_it_carries():
    """Providers differ in what they report. A missing field is not a zero
    claim about the others."""
    _record(usage={"input_tokens": 70})
    totals = llm_meter.spend()["totals"]
    assert totals["input_tokens"] == 70
    assert totals["output_tokens"] == 0
    assert totals["calls_without_usage"] == 0, "a partial report is still a report"


# ── keying ───────────────────────────────────────────────────────────────────


def test_two_principals_are_never_summed_into_one_row():
    _record(principal="member-a")
    _record(principal="member-b")
    spend = llm_meter.spend()
    assert spend["series_count"] == 2
    assert {r["principal"] for r in spend["series"]} == {"member-a", "member-b"}


@pytest.mark.parametrize("field", ["side", "callsite", "provider", "model"])
def test_every_key_field_separates_rows(field):
    _record(**{field: "one"})
    _record(**{field: "two"})
    assert llm_meter.spend()["series_count"] == 2


def test_skips_are_counted_with_their_reason():
    llm_meter.record_skip(callsite="think", principal="self", provider="xai", model="grok-3-mini", reason="cache_hit")
    llm_meter.record_skip(callsite="think", principal="self", provider="xai", model="grok-3-mini", reason="cache_hit")
    totals = llm_meter.spend()["totals"]
    assert totals["calls_skipped"] == 2
    assert totals["skip_reason"] == {"cache_hit": 2}
    assert totals["calls"] == 0, "a skipped call is not a call"


def test_the_snapshot_carries_no_price_or_cost_field():
    """RECORD-ONLY: no price table in this unit. No output figure has ever been
    observed from a hosted provider, and a cap set on an approximation is a cap
    set on a guess."""
    _record()
    spend = llm_meter.spend()
    assert spend["record_only"] is True
    assert spend["observed_usage_only"] is True
    assert not any("price" in k or "cost" in k or "usd" in k for k in spend["totals"])


# ── the read surface ─────────────────────────────────────────────────────────


def _app(home):
    from community_member.config import Config
    from community_member.server import create_app

    cfg = Config(home=home)
    cfg.agent_id = "meter-agent"
    return create_app(cfg)


def test_the_spend_route_serves_the_meter(isolated_home):
    """Driven, not assumed: the route exists, answers, and returns the same
    figures the store holds."""
    from fastapi.testclient import TestClient

    _record()
    _record(usage=None)
    with TestClient(_app(isolated_home / "home")) as client:
        response = client.get("/api/local/llm/spend")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["totals"]["calls"] == 2
    assert body["totals"]["calls_without_usage"] == 1
    assert body["record_only"] is True


@pytest.mark.no_local_token
def test_the_spend_route_refuses_without_the_local_token(isolated_home):
    """Spend is operator-visible only. It is protected because it was never
    opened — the default is deny — and this is the check that it stayed that way."""
    from fastapi.testclient import TestClient

    with TestClient(_app(isolated_home / "home")) as client:
        assert client.get("/api/local/llm/spend").status_code == 401
