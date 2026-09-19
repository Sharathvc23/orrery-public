"""The 'crm' built-in — a thin, stateless caller of the org's CRM verbs.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.

Two properties carry this file, and neither is about the happy path:

  * **The skill holds no state.** Every other writing built-in (``booking``,
    ``tasks``) keeps a local JSON file. This one must not, because a CRM record
    is an ORG record — a local copy would be a second source of truth that
    nothing reconciles, and the org side is where the receipt, the consent
    surface and the ``record_write`` gate already are.
  * **A pending write must not read as a completed one.** Since PR1 the
    ordinary outcome of a CRM mutation is ``pending_approval`` with nothing
    written. The tool descriptions are what the model reads before it reports
    back to a human, so the distinction has to be stated there or the model will
    say "filed" about a record that does not exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member.builtin_skills.crm import skill as crm_skill

MUTATING = {"add_contact", "set_contact_stage", "add_deal", "set_deal_stage", "log_interaction"}
READING = {"list_contacts", "contact_history"}


def _tool(name: str) -> dict:
    return next(t for t in crm_skill.TOOLS if t["name"] == name)


def test_the_pack_exposes_exactly_the_expected_verbs():
    assert {t["name"] for t in crm_skill.TOOLS} == MUTATING | READING


@pytest.mark.parametrize("name", sorted(MUTATING))
def test_every_mutating_tool_says_a_write_may_not_have_happened(name):
    """⚠️ THE HONESTY PROPERTY. The model reads these descriptions and then tells
    a human what happened. A description that says "files a contact" full stop
    invites it to report the record as filed and quote an id that was never
    issued. It must be told the call can succeed without the write occurring."""
    desc = _tool(name)["description"]
    assert "pending_approval" in desc, f"{name} does not warn that the write may be pending"
    assert "NOTHING IS WRITTEN" in desc
    assert "never as done" in desc


@pytest.mark.parametrize("name", sorted(READING))
def test_reads_are_not_labelled_as_needing_approval(name):
    """A read is not a mutation. Warning about approval here would train the
    model to treat a plain lookup as a privileged action."""
    assert "pending_approval" not in _tool(name)["description"]


def test_the_skill_holds_no_local_state(tmp_path: Path, monkeypatch):
    """ADVERSARIAL — the design property most likely to erode. If someone later
    adds a local cache to make reads fast, this fails: the org stops being the
    single source of truth for records the operator is accountable for."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    before = {p for p in tmp_path.rglob("*") if p.is_file()}

    for name in sorted(MUTATING | READING):
        out = _tool(name)["fn"]({}, home=tmp_path)
        assert isinstance(out, dict)

    assert {p for p in tmp_path.rglob("*") if p.is_file()} == before, (
        "the crm skill wrote local state — a CRM record is an org record"
    )


def test_an_unjoined_agent_is_refused_with_a_reason_not_a_crash(tmp_path: Path, monkeypatch):
    """A keyless or unjoined agent is a VALID agent that simply cannot write org
    records. It should get a reason it can act on, not a stack trace — and above
    all the write must not be faked locally to be reconciled later."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    out = crm_skill.add_contact({"name": "Ada"}, home=tmp_path)
    assert out.get("error") in {"not_joined", "no_signing_identity"}
    assert out.get("detail")


def test_the_service_pack_is_opt_in_so_existing_agents_are_unaffected():
    """``service`` must not be installed by default. Turning it on for every
    agent would hand a social member a set of operational verbs it never asked
    for, and every existing starter/team install would silently gain them."""
    import json

    packs = Path(crm_skill.__file__).resolve().parents[2] / "packs"
    service = json.loads((packs / "service.json").read_text())
    assert service["default_installed"] is False
    assert "crm" in service["skills"]
    for other in packs.glob("*.json"):
        if other.name != "service.json":
            assert "crm" not in json.loads(other.read_text())["skills"], (
                f"{other.name} pulls in crm — the service verbs are opt-in"
            )
