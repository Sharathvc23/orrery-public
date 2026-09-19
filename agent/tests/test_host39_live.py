"""Live drive against a real host39 (Leg B end-to-end).

**These tests SKIP, they never fail, when no host39 credential is present.** A
contributor with no host39 account runs the suite green. The gate is the same
fail-closed predicate the publisher itself uses
(:func:`community_member.host39.publishing_configured`), so an empty
``HOST39_BASE_URL=`` or ``HOST39_TOKEN=`` skips exactly like an unset one — it
never falls through to the live host.

To run (credentials come from the environment ONLY — never a file read by the
test, never a fixture):

    export HOST39_BASE_URL=https://agentcards.host39.org
    export HOST39_TOKEN=...            # or HOST39_EMAIL + HOST39_PASSWORD
    python -m pytest tests/test_host39_live.py -q -rA

No ``api.nandaindex.org`` call appears anywhere here: this leg stops at host39.
"""

from __future__ import annotations

import os

import pytest

from community_member import host39
from community_member.a2a_card import build_agent_card

pytestmark = pytest.mark.skipif(
    not host39.publishing_configured(),
    reason=(
        "no host39 credential in the environment — set "
        f"{host39.BASE_URL_ENV} and {host39.TOKEN_ENV} "
        f"(or {host39.EMAIL_ENV}+{host39.PASSWORD_ENV}) to run the live drive"
    ),
)

#: Slug used by the live drive. Overridable so a run can avoid clobbering a real
#: card; defaults to an obviously-synthetic name.
LIVE_SLUG = os.environ.get("HOST39_TEST_SLUG", "").strip() or "orrery-legb-probe"


@pytest.fixture(scope="module")
def client() -> host39.Host39Client:
    return host39.Host39Client.from_env()


@pytest.fixture(scope="module")
def probe_card() -> dict:
    """A synthetic tenant card, built through the canonical builder so the live
    drive exercises the same shape ``smb_host`` serves."""
    endpoint = (
        os.environ.get("HOST39_TEST_RUNTIME_URL", "").strip() or "https://smb-host.example.org/t/orrery-legb-probe"
    )
    card = build_agent_card(
        agent_id=LIVE_SLUG,
        display_name="Orrery Leg B probe",
        description="Synthetic card published by the Orrery Leg B live drive.",
        version="0.2.0",
        base_url=endpoint,
        chapter_url=None,
        did="did:key:z6MkoRrEryLEgBpRoBeSyNtHeTiCkEyOnLy00000",
        skills_declared=["probe"],
        tools=None,
    )
    return card.model_dump(mode="json", by_alias=True, exclude_none=True)


def test_account_is_reachable(client: host39.Host39Client) -> None:
    """The credential authenticates and the account tells us its own identity —
    so the published URL is derived, not guessed."""
    account = client.me()
    assert account.get("handle"), "host39 account has no handle"
    assert account.get("identity_type") in {"domain", "email"}


def test_publish_and_prove_fetchable(client: host39.Host39Client, probe_card: dict) -> None:
    """The done-when, end to end: publish, then prove the card is fetchable at
    its public URL with the right content-type, carrying the runtime URL and the
    did — verified by an unauthenticated HTTP probe, not by the POST's 2xx."""
    result = client.publish_a2a_card(probe_card, slug=LIVE_SLUG)

    assert result.fetched.status_code == 200, f"card not fetchable at {result.card_url}"
    assert result.fetched.is_a2a_media_type, f"content-type was {result.fetched.content_type!r}"
    assert result.runtime_url == probe_card["url"]
    assert result.did == probe_card["authentication"]["credentials"]
    assert result.problems == [], f"published card failed verification: {result.problems}"


def test_published_card_is_public(probe_card: dict, client: host39.Host39Client) -> None:
    """Fetch with a client that has no credential at all — this is what proves
    the card is *published* rather than merely stored."""
    result = client.publish_a2a_card(probe_card, slug=LIVE_SLUG)
    anonymous = host39.fetch_published_card(result.card_url)
    assert anonymous.status_code == 200
    assert anonymous.is_a2a_media_type
