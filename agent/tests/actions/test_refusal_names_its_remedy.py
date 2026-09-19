"""Every policy refusal names the grant that would have allowed it.

A deny-by-default policy an operator cannot act on gets turned off by the next
person who hits it. The refusal has to carry its own fix.

The surfaces are derived from `LocalAgent.build_runners`, not listed here, so a
capability added later is covered without anyone remembering to add it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member.consent import gate, ledger
from community_member.consent.gate import ActionRequest
from community_member.sandbox import grants

CHAPTER = "local:remedy"

# One request shape per capability the runner map exposes. A capability with no
# entry here fails `test_every_runner_has_a_probe`, so adding a surface forces
# adding its probe rather than silently skipping it.
PROBES: dict[str, dict] = {
    "browser.navigate": {"scope": "https://example.com", "extra": {"url": "https://example.com/a"}},
    "fs.read": {"scope": "/etc/hostname", "extra": {"path": "/etc/hostname"}},
    "fs.write": {"scope": "/etc/hostname", "extra": {"path": "/etc/hostname", "content": "x"}},
    "shell.exec": {"scope": "echo", "extra": {"binary": "echo", "args": ["hi"]}},
    "net.http": {"scope": "example.com", "extra": {"url": "https://example.com/"}},
    "desktop.click": {"scope": "screen", "extra": {"target": "screen", "x": 1, "y": 1}},
    "desktop.type": {"scope": "screen", "extra": {"target": "screen", "text": "x"}},
    "desktop.read_screen": {"scope": "screen", "extra": {"target": "screen"}},
    "skill.invoke": {"scope": "s::t::h", "extra": {"skill_id": "s", "tool_name": "t", "args": {}}},
}


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def runners(tmp_path, monkeypatch):
    """The real runner map, with no grants file — a fresh install."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    from community_member.agent import LocalAgent
    from community_member.config import Config

    ledger.init(tmp_path / "consent.db")
    cfg = Config(home=tmp_path)
    cfg.agent_id = "ada"
    cfg.provider = ""
    cfg.api_key = ""
    assert not (tmp_path / grants.GRANTS_FILENAME).exists()
    return LocalAgent(cfg).build_runners(CHAPTER)


def _drive(runners, capability: str):
    probe = PROBES[capability]
    req = ActionRequest(capability=capability, context="c", provenance="trusted", **probe)
    gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256="click")
    return runners[capability](req)


def test_every_runner_has_a_probe(runners):
    """A capability with no probe would be silently untested by everything below."""
    missing = sorted(set(runners) - set(PROBES))
    assert not missing, f"add a probe for {missing} so its refusal is checked"


def test_the_probe_set_is_not_empty(runners):
    """Emptying PROBES or the runner map would make the sweep below vacuous."""
    assert runners
    assert PROBES


def test_every_policy_refusal_names_its_remedy(runners):
    """The sweep. Derived from the runner map, so a fifth policy-gated surface
    is covered the day it is added."""
    silent: list[str] = []
    checked: list[str] = []
    for capability in sorted(runners):
        out = _drive(runners, capability)
        if out.extra.get("reason") != "sandbox_policy_deny":
            continue  # refused or failed for some other reason; not this test's subject
        checked.append(capability)
        if not out.extra.get("remedy") or not out.extra.get("required_grant"):
            silent.append(capability)
    assert checked, "no surface refused on policy — the sweep proved nothing"
    assert not silent, f"policy refusals with no remedy: {silent}"


def test_the_remedy_names_a_grant_that_would_work(runners, tmp_path):
    """The remedy is not decoration: writing what it says and restarting lets
    the action through."""
    out = _drive(runners, "fs.read")
    assert out.extra["reason"] == "sandbox_policy_deny"
    (tmp_path / grants.GRANTS_FILENAME).write_text(out.extra["required_grant"] + "\n")

    from community_member.agent import LocalAgent
    from community_member.config import Config

    cfg = Config(home=tmp_path)
    cfg.agent_id = "ada"
    cfg.provider = ""
    cfg.api_key = ""
    again = _drive(LocalAgent(cfg).build_runners(CHAPTER), "fs.read")
    assert again.outcome == "ok", again.extra


def test_the_remedy_names_the_file_to_edit(runners, tmp_path):
    out = _drive(runners, "shell.exec")
    assert str(tmp_path / grants.GRANTS_FILENAME) in out.extra["remedy"]


def test_all_surfaces_phrase_the_remedy_the_same_way(runners):
    """One helper, so four surfaces cannot grow four dialects."""
    phrasings = set()
    for capability in sorted(runners):
        out = _drive(runners, capability)
        if out.extra.get("reason") == "sandbox_policy_deny":
            phrasings.add(out.extra["remedy"].split(" ")[0])
    assert phrasings == {"add"}, phrasings


def test_the_remedy_helper_is_the_only_source():
    """A surface building its own string would drift from the rest."""
    actions = Path(grants.__file__).resolve().parents[1] / "actions"
    offenders = [
        p.name for p in actions.glob("*.py") if '"remedy":' in p.read_text() and "refusal_remedy" not in p.read_text()
    ]
    assert not offenders, f"{offenders} build a remedy string instead of calling refusal_remedy"
