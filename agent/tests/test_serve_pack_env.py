"""`AGENT_PACKS`: the deployment declares which tools an agent actually holds.

⚠️ WHY THIS EXISTS. A pack's installed state lives in `packs.json` on the agent's
volume, and nothing seeded it from the deployment. So the only way to give a
remote agent a capability was to reach into its volume by hand — which makes a
fleet unreproducible: a fresh deploy of the same service comes up without the
capabilities its predecessor had, and nothing says so.

The load-bearing test is `test_a_pack_that_does_not_exist_is_reported_loudly`.
A typo in this variable is an agent that comes up quietly unable to do its job,
and the only symptom is a capability search that returns nothing much later.
"""

from __future__ import annotations

import pytest

import serve
from community_member import skill_runtime


@pytest.fixture(autouse=True)
def _isolated_packs(tmp_path, monkeypatch):
    """Never touch the developer's real packs.json."""
    monkeypatch.setattr(skill_runtime, "_packs_registry_path", lambda: tmp_path / "packs.json")


def test_a_named_pack_is_installed(monkeypatch, capsys):
    monkeypatch.setenv("AGENT_PACKS", "hospitality")

    active = serve.apply_pack_env()

    assert "venue_book" in active, "the pack was named and its skill is not active"
    assert "hospitality" in skill_runtime.installed_pack_ids()


def test_the_default_pack_stays_active_alongside_it(monkeypatch):
    """Installing one pack must not displace the starter set."""
    monkeypatch.setenv("AGENT_PACKS", "hospitality")

    active = serve.apply_pack_env()

    assert {"booking", "calc", "datetime", "files", "web_fetch"} <= set(active)


def test_several_packs_can_be_named(monkeypatch):
    monkeypatch.setenv("AGENT_PACKS", "hospitality, team")

    active = serve.apply_pack_env()

    assert "venue_book" in active
    assert {"summarize", "draft", "tasks"} <= set(active), "the team pack's skills are missing"


def test_no_packs_named_leaves_the_defaults(monkeypatch, capsys):
    monkeypatch.delenv("AGENT_PACKS", raising=False)

    active = serve.apply_pack_env()

    assert "venue_book" not in active, "an unnamed pack was installed anyway"
    assert "booking" in active
    assert "requested=(none)" in capsys.readouterr().out


def test_a_pack_that_does_not_exist_is_reported_loudly(monkeypatch, capsys):
    """The load-bearing one. A typo here is an agent that quietly cannot do its
    job, and the only symptom appears much later as an empty capability search."""
    monkeypatch.setenv("AGENT_PACKS", "hosptality")  # deliberate typo

    active = serve.apply_pack_env()

    err = capsys.readouterr().err
    assert "not a known pack" in err
    assert "hosptality" in err
    assert "hospitality" in err, "the error must name what IS available"
    assert "venue_book" not in active


def test_a_good_pack_beside_a_typo_still_installs(monkeypatch, capsys):
    """One bad name must not cost the agent its other capabilities."""
    monkeypatch.setenv("AGENT_PACKS", "nonsense,hospitality")

    active = serve.apply_pack_env()

    assert "venue_book" in active
    assert "not a known pack" in capsys.readouterr().err


def test_the_effective_set_is_printed_not_just_the_request(monkeypatch, capsys):
    """This is additive, so env is not the whole truth — the effective set has to
    be visible or an operator is guessing."""
    monkeypatch.setenv("AGENT_PACKS", "hospitality")

    serve.apply_pack_env()

    out = capsys.readouterr().out
    assert "active_skills=" in out
    assert "venue_book" in out


def test_it_is_additive_and_does_not_uninstall(monkeypatch):
    """An operator who installed a pack through the dashboard must not lose it to
    an unrelated redeploy."""
    skill_runtime.set_pack_installed("team", True)
    monkeypatch.setenv("AGENT_PACKS", "hospitality")

    active = serve.apply_pack_env()

    assert "hospitality" in skill_runtime.installed_pack_ids()
    assert "team" in skill_runtime.installed_pack_ids(), "a redeploy removed a pack it was not asked about"
    assert "draft" in active


def test_running_twice_is_idempotent(monkeypatch):
    monkeypatch.setenv("AGENT_PACKS", "hospitality")

    first = serve.apply_pack_env()
    second = serve.apply_pack_env()

    assert first == second
