"""The boot step that claims an index name must report what it did.

⚠️ WHY THIS EXISTS. `announce_to_index` reports through `log.info`, which
uvicorn's log config does not surface. On a real deploy the outcome was
invisible: two agents were configured with `NANDA_INDEX_V3_URL`, neither
appeared in the index, and the deploy log said nothing either way — so there was
no way to tell "the hook never ran" from "it ran and declined" from "it ran and
failed". The only downstream symptom was a counterparty refusing the agent much
later, for a reason that pointed somewhere else entirely.

An operation whose outcome nobody can see is an operation nobody can debug.
"""

from __future__ import annotations

import serve


def test_the_outcome_is_printed(monkeypatch, capsys):
    monkeypatch.setenv("NANDA_INDEX_V3_URL", "https://index.example")
    monkeypatch.setattr(
        "community_member.index_boot.announce_to_index",
        lambda _c: {"action": "registered", "id": "urn:ai:key:uAAA/agent", "seq": 1},
    )

    outcome = serve.report_index_announce(object())

    printed = capsys.readouterr().out
    assert "index v3 →" in printed
    assert "registered" in printed
    assert "urn:ai:key:uAAA/agent" in printed, "the name claimed must be in the log to be checkable"
    assert outcome["action"] == "registered"


def test_a_skip_is_reported_as_a_skip_not_as_success(monkeypatch, capsys):
    """The case that actually bit: the hook ran, declined for want of an input,
    and nothing said so."""
    monkeypatch.setenv("NANDA_INDEX_V3_URL", "https://index.example")
    monkeypatch.setattr(
        "community_member.index_boot.announce_to_index", lambda _c: {"action": "skipped", "detail": "no signing key"}
    )

    serve.report_index_announce(object())

    printed = capsys.readouterr().out
    assert "skipped" in printed and "no signing key" in printed


def test_off_says_off_rather_than_printing_nothing(monkeypatch, capsys):
    """Silence and 'off' are different facts."""
    monkeypatch.delenv("NANDA_INDEX_V3_URL", raising=False)

    assert serve.report_index_announce(object()) is None
    assert "off (NANDA_INDEX_V3_URL unset)" in capsys.readouterr().out


def test_a_blank_url_counts_as_off(monkeypatch, capsys):
    monkeypatch.setenv("NANDA_INDEX_V3_URL", "   ")

    assert serve.report_index_announce(object()) is None
    assert "off" in capsys.readouterr().out


def test_a_failure_is_loud_and_the_agent_keeps_serving(monkeypatch, capsys):
    """An agent that cannot register is still an agent. It must not take the
    boot down, and it must not pretend it registered."""
    monkeypatch.setenv("NANDA_INDEX_V3_URL", "https://index.example")

    def boom(_c):
        raise RuntimeError("index unreachable")

    monkeypatch.setattr("community_member.index_boot.announce_to_index", boom)

    outcome = serve.report_index_announce(object())

    captured = capsys.readouterr()
    assert outcome["action"] == "failed"
    assert "still serving" in captured.err
    assert "index unreachable" in captured.err
    assert "registered" not in captured.out


def test_control_a_failure_is_not_reported_on_stdout_as_an_outcome(monkeypatch, capsys):
    """A failure printed like a success is worse than no logging at all."""
    monkeypatch.setenv("NANDA_INDEX_V3_URL", "https://index.example")
    monkeypatch.setattr(
        "community_member.index_boot.announce_to_index", lambda _c: (_ for _ in ()).throw(RuntimeError("nope"))
    )

    serve.report_index_announce(object())

    assert "index v3 →" not in capsys.readouterr().out
