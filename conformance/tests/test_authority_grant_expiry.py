"""The authority-expiry gate compares INSTANTS, not strings.

WHY THIS FILE EXISTS. ``verify_authority`` decided expiry with
``receipt["issued_at"] > grant_expires_at`` — a raw string comparison. That is
correct only when both sides are Zulu at identical precision, and RFC 3339 also
permits a numeric offset. So the SAME INSTANT written two legal ways produced two
different verdicts on a HIGH-STAKES gate: ``2026-08-13T20:00:00Z`` was refused
while ``2026-08-14T01:00:00+05:00`` — the identical moment — was accepted.

Nothing in the schema caught it. ``grant_expires_at`` carries only
``"format": "date-time"``, and the validator is built with no ``format_checker``,
so under JSON Schema semantics that keyword is an annotation and asserts nothing.
Every other timestamp in ``schema/arp/0.2`` is pinned by an explicit regex; this
one is not. The fix is in the verifier rather than the schema on purpose: an
offset timestamp is legal RFC 3339, so narrowing the schema would reject
conforming emitters instead of comparing their timestamps correctly.

⚠️ Both directions are asserted below. Proving refusal alone would not show the
gate still OPENS — a verifier that refuses everything passes every failure test
and is useless. The live-grant rows are what keep the fix honest.

Classification: FAILURE / ADVERSARIAL / HAPPY.
"""

from __future__ import annotations

import pytest

from conformance.arp import verify_authority

PRINCIPAL = "did:key:z6MkPrincipalAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#: The action under test is high-stakes, so the authority chain is enforced.
#: A category outside HIGH_STAKES_CATEGORIES skips the gate entirely and would
#: make every row below vacuously pass.
ACTION_ISSUED_AT = "2026-08-14T00:00:00Z"


def _grant(expires_at: str | None, *, omit: bool = False) -> dict:
    payload: dict = {"granted_scope": ["payment_sent"]}
    if not omit:
        payload["grant_expires_at"] = expires_at
    return {
        "version": "arp/0.2",
        "principal_did": PRINCIPAL,
        "issuer_did": PRINCIPAL,
        "action": {"category": "authority_granted", "machine_payload": payload},
    }


def _action(issued_at: str = ACTION_ISSUED_AT) -> dict:
    return {
        "version": "arp/0.2",
        "principal_did": PRINCIPAL,
        "issued_at": issued_at,
        "action": {"category": "payment_sent", "granted_by_receipt_id": "g1"},
    }


def _verdict(expires_at: str | None, *, omit: bool = False) -> bool:
    return verify_authority(
        _action(), authority_grants={"g1": _grant(expires_at, omit=omit)}
    ).ok


# ── FAILURE: an expired grant is refused however it is serialised ──────────


def test_FAILURE_expired_grant_in_zulu_is_refused() -> None:
    """The one serialisation the string compare happened to get right."""
    assert _verdict("2026-08-13T20:00:00Z") is False


@pytest.mark.parametrize(
    "expires_at",
    [
        "2026-08-14T01:00:00+05:00",  # the SAME INSTANT as the Zulu row above
        "2026-08-14T01:00:00+02:00",  # expired by an hour
        "2026-08-13T23:59:59+00:00",  # expired by a second, offset form of Z
    ],
)
def test_ADVERSARIAL_expired_grant_with_a_numeric_offset_is_refused(
    expires_at: str,
) -> None:
    """THE REGRESSION. Each of these is temporally expired and each was ACCEPTED
    by the string compare, because an offset form sorts differently from the Zulu
    form of the same moment. `+05:00` is the sharpest case: it names the exact
    instant the test above refuses."""
    assert _verdict(expires_at) is False


@pytest.mark.parametrize(
    "expires_at", ["never", "", "tomorrow", "9999", "2026-08-13T20:00:00"]
)
def test_ADVERSARIAL_an_unreadable_expiry_is_refused_not_ignored(
    expires_at: str,
) -> None:
    """An expiry we cannot read is an expiry we cannot honour, so the fail
    direction on this gate is REFUSAL.

    Before the fix these were ACCEPTED — any string starting with a letter sorts
    after one starting with a digit, so ``"never"`` read as *not yet expired* and
    handed out a perpetual grant to whoever wrote the worst timestamp. The last
    case is the subtle one: a naive timestamp with no offset is not RFC 3339 and
    must not be silently assumed to be UTC.
    """
    assert _verdict(expires_at) is False


# ── HAPPY: the gate still opens for a grant that is actually live ──────────


@pytest.mark.parametrize(
    "expires_at",
    [
        "2026-08-15T00:00:00Z",  # a day of headroom, Zulu
        "2026-08-14T00:00:00-05:00",  # five hours of headroom, negative offset
        "2026-08-14T00:00:00Z",  # exactly at the boundary: not yet PAST expiry
    ],
)
def test_HAPPY_a_live_grant_is_still_accepted(expires_at: str) -> None:
    """Without these the fix would be indistinguishable from a verifier that
    refuses everything. The boundary row also pins the comparison as strict
    (``issued > expiry``), which is the semantics that shipped — an action at the
    exact expiry instant remains authorised."""
    assert _verdict(expires_at) is True


def test_HAPPY_a_grant_with_no_expiry_never_expires() -> None:
    """Unchanged by the fix, and stated so it is not mistaken for an oversight:
    omitting ``grant_expires_at`` is the principal's own choice to grant open-ended
    authority. Absent is not the same as unreadable."""
    assert _verdict(None, omit=True) is True
