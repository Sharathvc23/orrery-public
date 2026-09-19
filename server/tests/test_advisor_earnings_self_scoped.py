"""The activity-feed PII closure residual: /api/surfaces/advisor-earnings is self-scoped, not target-driven.

``build_advisor_earnings_surface`` passes ``target`` straight to
``skill_revenue.get_earnings_for_did``. ``get_surface_endpoint`` used to override
a client-supplied ``target`` for ``today`` only, so an unauthenticated caller
naming any did:key received that principal's all-time earnings, last-7-day
earnings, ledger entry count and per-role breakdown.

The original the activity-feed PII closure triage recorded this route CLEAN. It called the route with no
``target``, which returns only the "Pass ?target=<your did:key>" prompt — so the
probe measured the empty case and the finding stayed open. These tests pin the
route BY NAME and drive the parameter, which is the thing that was never done.

Amounts on the live chapters read $0.00 because the revenue ledger is empty. The
tests therefore assert on WHICH PRINCIPAL is queried, not on amounts: a route
that returns zeros today would return real figures the moment the ledger fills.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import chapter_agent

OTHER_PRINCIPAL = "did:key:z6MkOtherPrincipalNotTheCaller00000000000000"


@pytest.fixture
def client() -> TestClient:
    return TestClient(chapter_agent.app)


@pytest.fixture
def recorded_targets(monkeypatch) -> list:
    """Record every did:key the earnings builder is asked about."""
    seen: list = []

    async def _fake_builder(target=None):
        seen.append(target)
        return {"version": "0.10", "surface_id": "surface-advisor-earnings", "components": []}

    import surface_cache
    import surfaces

    monkeypatch.setitem(surfaces.SURFACE_BUILDERS, "advisor-earnings", _fake_builder)
    # get_surface memoizes with a 10s TTL, so without this a second test in the
    # same session reads the first one's cached surface and records nothing —
    # which would make these assertions pass vacuously.
    surface_cache.reset()
    return seen


def test_ADVERSARIAL_unauthenticated_target_is_not_honoured(client, recorded_targets):
    """The finding: an anonymous caller naming another principal must get nothing.

    ``target=None`` is what the builder renders as its no-data prompt, so this is
    the state in which no earnings can be disclosed.
    """
    resp = client.get(f"/api/surfaces/advisor-earnings?target={OTHER_PRINCIPAL}")
    assert resp.status_code == 200
    assert recorded_targets == [None], (
        f"an unauthenticated caller's ?target= reached the earnings builder as "
        f"{recorded_targets!r}; it must be dropped to None"
    )


def test_ADVERSARIAL_other_principals_did_never_reaches_the_builder(client, recorded_targets):
    """Stated separately from the None assertion so the failure message names the leak."""
    client.get(f"/api/surfaces/advisor-earnings?target={OTHER_PRINCIPAL}")
    assert OTHER_PRINCIPAL not in recorded_targets, (
        "a caller-supplied did:key was used to query another principal's earnings"
    )


def test_HAPPY_no_target_still_renders_the_prompt(client, recorded_targets):
    """The anonymous view is unchanged — the portal links this page (AppSidebar).

    This is why the fix is self-scoping rather than a 401: the anonymous response
    was already a no-data prompt, so gating would break a consumer without
    removing any disclosure the override does not already remove.
    """
    resp = client.get("/api/surfaces/advisor-earnings")
    assert resp.status_code == 200
    assert recorded_targets == [None]


def test_the_route_is_in_the_self_scoped_set_by_name():
    """Pin the membership itself.

    The override is a tuple of page_ids; dropping `advisor-earnings` from it
    silently restores target-driven disclosure, and the behavioural tests above
    would still pass against a build where the surface had merely been renamed.
    """
    import inspect

    src = inspect.getsource(chapter_agent.get_surface_endpoint)
    assert '"advisor-earnings"' in src, (
        "advisor-earnings left the self-scoped set in get_surface_endpoint; a "
        "client-supplied target now reaches skill_revenue.get_earnings_for_did"
    )


# ── The two routes that stay open, pinned so a future change is deliberate ────


def test_outcomes_surface_ignores_target(client, monkeypatch):
    """outcomes is public by intent: `target` is accepted and never read.

    get_quality_scores() keys by ACTION TYPE and its query selects no member
    column, so per-member rows are impossible by construction. Pinned so a
    builder change that starts honouring `target` has to face this test.
    """
    seen: list = []

    async def _fake(target=None):
        seen.append(target)
        return {"version": "0.10", "surface_id": "surface-outcomes", "components": []}

    import surfaces

    monkeypatch.setitem(surfaces.SURFACE_BUILDERS, "outcomes", _fake)
    resp = client.get(f"/api/surfaces/outcomes?target={OTHER_PRINCIPAL}")
    assert resp.status_code == 200
    # The endpoint passes it through; the BUILDER is what must not read it.
    import inspect

    body = inspect.getsource(surfaces.build_outcomes_surface)
    assert body.count("target") == 1, (
        "build_outcomes_surface now reads `target`; it was public-by-intent only "
        "because the parameter was inert. Re-decide its visibility."
    )
