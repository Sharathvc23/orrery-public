"""Guards on the catalog canary's floor.

``catalog_canary`` asserts that every entry an org ADVERTISES resolves. True,
and vacuous at the bottom: an org advertising only its own root card resolves
1/1 and passes having verified nothing about the member registry the catalog
exists to publish. Measured live 2026-10-15 — the astrocity org advertised 1
entry while omitting 24, and the canary printed ``1/1 entries resolved
(omittedMembers=24)`` followed by ``OK``.

The rule under test references no org's member count, so it encodes nobody's
current state. It cannot be satisfied by the estate getting worse, which is the
property a floor fitted to today's numbers would not have.

The subtle guard here is ``test_a_withholding_org_is_unobservable_not_failed``.
The canary is UNAUTHENTICATED, so an org that does not publish members publicly
withholds all of them and correctly shows no member entries. A floor that failed
that org would be a false alarm on a correct configuration; one that passed it
silently would rebuild the defect the floor exists to remove. Hence a third
outcome that is neither, reported by name.

And ``test_the_canary_actually_evaluates_the_floor``: a floor nothing calls is
dead code, which is this same defect one layer down — the lesson
``test_every_canary_workflow_sets_the_flag`` already records for the refusal a
workflow never arms.

Driven directly against ``scripts/_catalog_floor.py``, which is stdlib-only:
``doc-guards`` installs nothing but pytest, so a guard needing ``httpx`` is a
guard that job cannot run.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT / "scripts"


def _floor():
    """Import ``scripts/_catalog_floor.py`` by path, without a package."""
    path = _SCRIPTS / "_catalog_floor.py"
    spec = importlib.util.spec_from_file_location("_catalog_floor", path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _catalog(entries, *, omitted=0, withheld=0):
    doc = {"specVersion": "1.0", "entries": entries}
    if omitted is not None:
        doc["omittedMembers"] = omitted
    if withheld is not None:
        doc["withheldMembers"] = withheld
    return doc


def test_a_catalog_with_only_the_orgs_own_entry_does_not_pass():
    """The measured astrocity shape: 1 entry, 24 omitted, nothing withheld."""
    floor = _floor()
    doc = _catalog([{"identifier": "astrocity"}], omitted=24, withheld=0)
    verdict, message = floor.floor_verdict(doc, "astrocity")
    assert verdict == floor.FLOOR_FAILED
    # Names the remedy, not just the symptom — the operator reading a red check
    # has to act, and the action is recording the publication.
    assert "publish_host39_card.py --record-on-org" in message
    assert "24" in message


def test_an_org_advertising_members_passes():
    floor = _floor()
    doc = _catalog(
        [{"identifier": "regentix"}, {"identifier": "regentix-ceo"}, {"identifier": "regentix-cto"}],
        omitted=0,
        withheld=0,
    )
    verdict, _ = floor.floor_verdict(doc, "regentix")
    assert verdict == floor.FLOOR_OK


def test_a_rocketbrain_shaped_catalog_with_one_omission_still_passes():
    """A floor, not a perfection bar: some omission is a normal steady state."""
    floor = _floor()
    doc = _catalog(
        [{"identifier": "rocketbrain"}, *({"identifier": f"rocketbrain-{n}"} for n in "abcde")],
        omitted=1,
        withheld=0,
    )
    verdict, _ = floor.floor_verdict(doc, "rocketbrain")
    assert verdict == floor.FLOOR_OK


@pytest.mark.parametrize("withheld", [1, 24])
def test_a_withholding_org_is_unobservable_not_failed(withheld):
    """An org that withholds its members from strangers is CORRECT, not broken.

    This is the false alarm the floor must not raise. ``withheldMembers`` is
    checked before the member count and never folded into it: the catalog route
    keeps "withheld from an unauthenticated caller" separate from "omitted for
    want of a resolvable card" so a privacy decision cannot be read as an
    unpublished card, and the floor must not re-merge them.
    """
    floor = _floor()
    doc = _catalog([{"identifier": "private-org"}], omitted=0, withheld=withheld)
    verdict, message = floor.floor_verdict(doc, "private-org")
    assert verdict == floor.FLOOR_UNOBSERVABLE
    # Unobservable is NOT a pass, and must not read like one.
    assert "NOT evaluated" in message


def test_a_missing_withheld_count_is_unobservable_not_assumed_zero():
    """Absent is not zero. A deployment too old to emit the count cannot be ruled on."""
    floor = _floor()
    doc = {"specVersion": "1.0", "entries": [{"identifier": "old-org"}], "omittedMembers": 3}
    verdict, message = floor.floor_verdict(doc, "old-org")
    assert verdict == floor.FLOOR_UNOBSERVABLE
    assert "NOT evaluated" in message


def test_an_org_with_no_members_at_all_fails_for_a_different_reason():
    """Zero omitted AND zero members is a different finding from unpublished cards."""
    floor = _floor()
    doc = _catalog([{"identifier": "empty-org"}], omitted=0, withheld=0)
    verdict, message = floor.floor_verdict(doc, "empty-org")
    assert verdict == floor.FLOOR_FAILED
    assert "no members at all" in message
    # Must NOT misdirect the operator to the card publisher: no card would help.
    assert "publish_host39_card" not in message


def test_the_org_entry_is_identified_by_identifier_not_by_position():
    """Entry order is not a wire contract, so the floor must not depend on it."""
    floor = _floor()
    doc = _catalog([{"identifier": "a-ceo"}, {"identifier": "a"}], omitted=0, withheld=0)
    assert [e["identifier"] for e in floor.member_entries(doc, "a")] == ["a-ceo"]
    verdict, _ = floor.floor_verdict(doc, "a")
    assert verdict == floor.FLOOR_OK


def test_the_canary_actually_evaluates_the_floor():
    """A floor nothing calls is dead code — the same defect one layer down."""
    source = (_SCRIPTS / "catalog_canary.py").read_text(encoding="utf-8")
    assert "from _catalog_floor import" in source, "the canary does not import the floor"
    assert "floor_verdict(" in source, "the canary imports the floor but never evaluates it"


def test_the_success_line_claims_both_halves():
    """The old success sentence was true of a catalog with nothing in it.

    "every advertised catalog entry resolved" is exactly what the canary said
    while astrocity advertised one entry and omitted 24. If that sentence comes
    back unqualified, the report is misleading again even though the check now
    fails correctly.
    """
    source = (_SCRIPTS / "catalog_canary.py").read_text(encoding="utf-8")
    ok_lines = [ln for ln in source.splitlines() if "OK — every advertised" in ln]
    assert ok_lines, "the success line is gone — did it move? this guard needs updating"
    for line in ok_lines:
        assert "members to verify" in line, f"unqualified success claim: {line.strip()}"
