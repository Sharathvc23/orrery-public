"""The field-level delta between Orrery's intelligence summary and the profile.

This is the cross-repo half of the guard. ``envelope_field_map.json`` classifies
every field Orrery emits as MAPPED, DRIFT, or DELIBERATE-EXCLUSION, and the tests
below check each classification against **both** sides — the live emitter in this
repo and the published schema in the installed ``sm-federation`` distribution.

Why that matters: a classification file on its own is a comment. The reason these
verdicts are not comments is that each one is falsifiable by a change in *either*
repository, and the suite is what falsifies it:

  * a field added to ``get_our_summary`` and not classified      -> fail (here)
  * a classified field removed from ``get_our_summary``          -> fail (here)
  * a field claimed DELIBERATE-EXCLUSION that the profile adopts -> fail (there)
  * a field claimed MAPPED that the profile drops                -> fail (there)
  * any field left classified DRIFT                              -> fail

The last is deliberate. DRIFT is not a category things sit in; it is a category
that fails until the published profile is moved forward or the field is
reclassified with a stated reason. Somewhere to park a known divergence is
exactly the allowed-list this repo removed in that change.
"""

from __future__ import annotations

from typing import Any

import pytest

VERDICTS = {"MAPPED", "DRIFT", "DELIBERATE-EXCLUSION"}
REASON_CODES = {"PROFILE_FORBIDS", "OUT_OF_PROFILE_SCOPE", "IMPLEMENTATION_INTERNAL"}
MIN_REASON_MAPPED = 30
# An exclusion has to be argued, not identified — a longer floor on purpose.
MIN_REASON_EXCLUDED = 80


@pytest.fixture(scope="session")
def published_envelope_properties(wire) -> set[str]:
    return set(wire.load_schema("intelligence-envelope")["properties"])


def _entries(field_map: dict[str, Any]) -> list[dict[str, Any]]:
    return field_map["fields"]


# ── the classification covers exactly what Orrery emits ────────────────────────


def test_every_emitted_field_is_classified(field_map, orrery_emitted_fields) -> None:
    """Nothing opts out of classification by being unlisted."""
    classified = {e["orrery"] for e in _entries(field_map)}
    unclassified = orrery_emitted_fields - classified
    assert not unclassified, (
        "get_our_summary emits fields with no entry in envelope_field_map.json: "
        f"{sorted(unclassified)}. Classify each as MAPPED, DRIFT or "
        "DELIBERATE-EXCLUSION before it reaches a peer."
    )


def test_no_phantom_classifications(field_map, orrery_emitted_fields) -> None:
    """An entry for a field nothing emits is a stale exemption.

    Without this, a DELIBERATE-EXCLUSION outlives the field it excused and reads
    like an active decision.
    """
    classified = {e["orrery"] for e in _entries(field_map)}
    phantom = classified - orrery_emitted_fields
    assert not phantom, (
        f"envelope_field_map.json classifies fields get_our_summary does not emit: {sorted(phantom)}"
    )


def test_no_duplicate_classifications(field_map) -> None:
    names = [e["orrery"] for e in _entries(field_map)]
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"classified more than once: {dupes}"


# ── each verdict is checked against the published schema ───────────────────────


def test_mapped_fields_exist_in_the_published_profile(field_map, published_envelope_properties) -> None:
    """MAPPED means the profile really does define the target property.

    Fires when the OTHER repository drops or renames a property this repo maps
    onto — the direction a single-repo test cannot see.
    """
    broken = [
        (e["orrery"], e["protocol"])
        for e in _entries(field_map)
        if e["verdict"] == "MAPPED" and e["protocol"] not in published_envelope_properties
    ]
    assert not broken, (
        "fields mapped onto profile properties that the published intelligence-envelope "
        f"schema does not define: {broken}. Either the profile changed under this pin, or the "
        "mapping was wrong."
    )


def test_excluded_fields_are_absent_from_the_published_profile(field_map, published_envelope_properties) -> None:
    """DELIBERATE-EXCLUSION means the profile does not carry the field.

    This is the drift detector proper. The moment sm-federation adopts a field
    Orrery excludes, the exclusion is no longer a decision about a gap — it is a
    refusal to emit something the profile defines — and it must be re-argued as a
    MAPPED field or restated for the new situation.
    """
    contradicted = [
        e["orrery"]
        for e in _entries(field_map)
        if e["verdict"] == "DELIBERATE-EXCLUSION" and e["orrery"] in published_envelope_properties
    ]
    assert not contradicted, (
        f"claimed DELIBERATE-EXCLUSION for fields the published profile now defines: {contradicted}. "
        "The profile moved; reclassify as MAPPED or state why Orrery still withholds it."
    )


def test_no_field_is_classified_drift(field_map) -> None:
    """DRIFT fails. It is not a bucket to park divergence in.

    Resolve it by moving the published profile forward (a PR to sm-federation, as
    active_member_count was resolved) or by reclassifying with a real reason.
    """
    drifted = [e["orrery"] for e in _entries(field_map) if e["verdict"] == "DRIFT"]
    assert not drifted, (
        f"unresolved DRIFT: {drifted}. Orrery emits these and the published profile has no property "
        "for them, so with additionalProperties:false the signal cannot be carried at all. Open a PR "
        "to sm-federation, or reclassify as DELIBERATE-EXCLUSION with a stated reason."
    )


# ── the reasons have to be reasons ─────────────────────────────────────────────


def test_every_entry_is_well_formed(field_map) -> None:
    """Reported in one pass — fixing these one failure at a time is a waste."""
    problems: list[str] = []
    for e in _entries(field_map):
        name = e["orrery"]
        if e["verdict"] not in VERDICTS:
            problems.append(f"{name}: unknown verdict {e['verdict']!r}")
            continue
        floor = MIN_REASON_MAPPED if e["verdict"] == "MAPPED" else MIN_REASON_EXCLUDED
        reason = e.get("reason", "")
        if len(reason) < floor:
            problems.append(f"{name}: reason is {len(reason)} chars, {e['verdict']} requires >= {floor}")
        if reason.strip().lower().rstrip(".") == name.replace("_", " "):
            problems.append(f"{name}: reason restates the field name instead of justifying the verdict")
        if e["verdict"] == "MAPPED":
            if not isinstance(e.get("protocol"), str) or not e["protocol"]:
                problems.append(f"{name}: MAPPED needs a target property")
        elif e.get("protocol") is not None:
            problems.append(f"{name}: only MAPPED may name a profile property")
    assert not problems, "malformed field-map entries:\n  " + "\n  ".join(problems)


def test_exclusions_carry_a_reason_code_from_the_closed_set(field_map) -> None:
    for e in _entries(field_map):
        if e["verdict"] != "DELIBERATE-EXCLUSION":
            continue
        code = e.get("reason_code")
        assert code in REASON_CODES, (
            f"{e['orrery']}: reason_code {code!r} is not in the closed set {sorted(REASON_CODES)}. "
            "A free-text code is a label; the set is what makes the class reviewable."
        )
        if code == "PROFILE_FORBIDS":
            assert "§" in e["reason"], (
                f"{e['orrery']}: PROFILE_FORBIDS must cite the spec section that forbids it"
            )


# ── the other direction: profile properties Orrery does not emit ───────────────


def test_protocol_only_covers_exactly_the_unemitted_profile_properties(
    field_map, published_envelope_properties, orrery_emitted_fields
) -> None:
    """Both directions of the delta, and neither may go stale.

    ``protocol_only`` must list precisely the published properties nothing in
    Orrery maps onto. A property that starts being emitted has to leave the list;
    one the profile adds has to enter it.
    """
    mapped_targets = {e["protocol"] for e in _entries(field_map) if e["verdict"] == "MAPPED"}
    # A field Orrery emits under the profile's own name is mapped implicitly.
    covered = mapped_targets | (orrery_emitted_fields & published_envelope_properties)
    expected = published_envelope_properties - covered
    declared = {e["protocol"] for e in field_map["protocol_only"]}
    assert declared == expected, (
        f"protocol_only is stale. Published properties with no Orrery source: {sorted(expected)}; "
        f"declared: {sorted(declared)}."
    )
    for e in field_map["protocol_only"]:
        assert len(e.get("reason", "")) >= MIN_REASON_EXCLUDED, f"{e['protocol']}: needs a stated reason"


def test_active_members_never_reaches_the_wire(field_map, orrery_summary, orrery_summary_empty) -> None:
    """§3 forbids per-member identifiers in an envelope.

    ``active_members`` is a member LIST inside Orrery's intelligence cache. It is
    read only as a length. The field map records that it is not emitted; this is
    the assertion that keeps the record true, so a future edit cannot promote the
    list itself onto the wire unnoticed.
    """
    recorded = {e["field"] for e in field_map["not_emitted_by_either"]}
    assert "active_members" in recorded

    for summary in (orrery_summary, orrery_summary_empty):
        assert "active_members" not in summary, (
            "get_our_summary now emits active_members — a per-member identifier list. "
            "spec/federation/0.1 §3: an envelope carries aggregate signals only and MUST NOT "
            "place per-member identifiers in it. Emit the count, not the list."
        )
    assert orrery_summary["active_member_count"] == 3, "the count is what is derived from that list"
