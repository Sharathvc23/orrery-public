"""What this host SERVES must be a claim it also CHECKS, or the claim goes.

Found by an audit that booted a real host and captured every payload, plus an
AST sweep over every string literal in ``main.py``. Nine findings (S1-S9);
this file guards the ones fixed here. Each test boots a real tenant and reads
the served document — never the source text — so a fix that changes the
wording but not the underlying value would not satisfy it.

NOT DERIVED FROM A SINGLE MECHANISM, and that is stated rather than hidden:
there is no registry of "claims this host makes" to walk the way
``test_isolation_guards.py`` walks the SDK's own modules — these are prose
and booleans scattered through card-building code, not data with one shape.
Each test is named for the specific claim it guards and plants against.

S9 (receipt.principal_did == receipt.issuer_did) is a spec question held by
orch and is untouched here. The root cause — booking.status was set
unconditionally to "confirmed", a word implying an acceptance step this path
never had — was a coordinated wire-shape rename (booking.status is now
"recorded", landed with smb_funnel via smb_funnel/tests/host_contract.json)
rather than something this file guards.
"""

from __future__ import annotations

import importlib
import secrets
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

_TEST_TOKEN = secrets.token_urlsafe(24)
_TEST_CONTACT = "https://bookings.example/hook"
_TEST_TENANT_CAP = "1000"


def _make_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, public_url: str) -> TestClient:
    """A minimal, gated, pool-disabled host — deterministic provisioning for
    reading exactly what one tenant's own documents say."""
    monkeypatch.setenv("HOST_PUBLIC_URL", public_url)
    monkeypatch.setenv("SMB_HOST_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    monkeypatch.setenv("SMB_HOST_POOL_SIZE", "0")
    monkeypatch.setenv("SMB_HOST_PROVISION_TOKEN", _TEST_TOKEN)
    monkeypatch.setenv("SMB_HOST_TENANT_CAP", _TEST_TENANT_CAP)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import main as host_main

    importlib.reload(host_main)
    return TestClient(host_main.app, headers={"Authorization": f"Bearer {_TEST_TOKEN}"})


def _provision(host: TestClient, business_name: str, service_type: str | None = None) -> tuple[str, dict]:
    """Provision one tenant and return (tenant_id, card)."""
    body = {"contact": _TEST_CONTACT, "business_name": business_name}
    if service_type:
        body["service_type"] = service_type
    resp = host.post("/provision", json=body)
    assert resp.status_code == 201, resp.text
    tenant_id = resp.json()["tenant_id"]
    card = host.get(f"/t/{tenant_id}/.well-known/agent.json").json()
    return tenant_id, card


# ── S1: streaming is not implemented on this host ────────────────────────────


def test_the_card_does_not_claim_streaming_support(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """This host mounts plain REST routes; no JSON-RPC tasks/sendSubscribe
    exists anywhere in it. Advertising streaming=True claims a transport this
    host cannot serve."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    _, card = _provision(host, "Streaming Claim Co")
    assert card["capabilities"]["streaming"] is False, "the card claims a transport this host does not implement"


# ── S2: no route on this host authenticates a caller ─────────────────────────


def test_the_card_does_not_advertise_an_unenforced_auth_scheme(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """POST /t/{id}/book — the only action route — has no auth dependency at
    all. A scheme the card lists here is one a security-conscious consumer
    would rely on and find nothing enforcing."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    tenant_id, card = _provision(host, "Auth Claim Co")
    assert card["authentication"]["schemes"] == [], (
        f"the card advertises {card['authentication']['schemes']!r} for an endpoint nothing here authenticates"
    )
    # And the endpoint really is open — the claim's falseness is reachable, not theoretical.
    book = host.post(
        f"/t/{tenant_id}/book",
        json={"service": "Haircut", "provider": "Auth Claim Co", "datetime": "2026-09-01T10:00:00Z"},
    )
    assert book.status_code == 200, "the booking route the card describes as unauthenticated is not actually open"


# ── S3: the card's provider is this host, not the tenant it is hosting ──────


def test_the_card_provider_is_the_hosting_domain_not_the_tenant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ "Who runs this agent" is this host's operator, not the business it is
    hosting — the business does not hold its own key or run its own process."""
    public_url = "http://smb-host.example"
    host = _make_host(tmp_path, monkeypatch, public_url)
    tenant_id, card = _provision(host, "Provider Claim Co")
    assert card["provider"]["organization"] == urlparse(public_url).netloc, (
        f"provider.organization is {card['provider']['organization']!r}, which names the tenant rather than the host"
    )
    assert card["provider"]["organization"] != tenant_id
    assert card["provider"]["url"] == public_url


# ── S4: this host reaches no discovery-ranking mechanism ─────────────────────


def test_the_topical_skill_does_not_claim_discovery_ranking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """This host registers on no index and imports nothing from server/, where
    the only ranking code in the tree lives. Naming ranking here describes a
    mechanism this host cannot reach."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    _, card = _provision(host, "Ranking Claim Co", service_type="barber")
    topical = next((s for s in card["skills"] if s["id"] == "skill.topical"), None)
    assert topical is not None, "expected a topical skill from service_type=barber"
    assert "ranking" not in topical["description"].lower(), (
        f"the topical skill still claims a ranking mechanism: {topical['description']!r}"
    )
    assert "not directly invokable" in topical["description"].lower()


# ── S7: this host holds the key; the tenant does not run itself ─────────────


def test_the_served_description_does_not_claim_sovereignty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ "Sovereign" reads as independent control. One operator passphrase
    decrypts every tenant on this host and the tenant runs in the host's own
    process — OPERATIONS.md already calls this "separation of state, not a
    boundary." Checked on BOTH documents, and on BOTH provisioning paths,
    because the two used to disagree: the cold path never set
    config.description at all, so its AgentFacts fell back to a different,
    unreviewed string the card never showed."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    tenant_id, card = _provision(host, "Independence Claim Co")
    facts = host.get(f"/t/{tenant_id}/agentfacts.json").json()

    for label, description in (("card", card["description"]), ("agentfacts", facts["description"])):
        assert "sovereign" not in description.lower(), (
            f"the {label} description still claims sovereignty: {description!r}"
        )
    assert card["description"] == facts["description"], (
        "the card and AgentFacts describe the same tenant differently — "
        f"card={card['description']!r} agentfacts={facts['description']!r}"
    )


# ── S8: business_name is a display label nobody verified ────────────────────


def test_the_booking_skill_description_does_not_name_an_unverified_business(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """README says business_name "is a display label written onto the card; it
    is not a claim anyone verified." The booking skill's own description used
    to call it a business anyway."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    _, card = _provision(host, "Business Noun Co")
    booking = next(s for s in card["skills"] if s["id"] == "skill.booking")
    assert "business" not in booking["description"].lower(), (
        f"the booking skill still names an unverified business: {booking['description']!r}"
    )


# ── S1/S2, the other half: the SAME two claims, served one document over ────
#
# build_agent_card (the A2A card) was fixed first. build_self_agentfacts serves
# the identical streaming/authentication claims at /t/{id}/agentfacts.json,
# from the SAME sm-bridge-backed builder the member runtime uses — which
# genuinely implements both, so this is parameterised the same way rather than
# a literal flip.


def test_the_agentfacts_does_not_claim_streaming_support(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    tenant_id, _ = _provision(host, "Facts Streaming Claim Co")
    facts = host.get(f"/t/{tenant_id}/agentfacts.json").json()
    assert facts["capabilities"]["streaming"] is False, (
        "AgentFacts claims a transport this host does not implement, same as the card used to"
    )


def test_the_agentfacts_does_not_advertise_an_unenforced_auth_scheme(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    tenant_id, _ = _provision(host, "Facts Auth Claim Co")
    facts = host.get(f"/t/{tenant_id}/agentfacts.json").json()
    methods = facts["capabilities"]["authentication"]["methods"]
    assert methods == ["none"], f"AgentFacts advertises {methods!r} for an endpoint nothing here authenticates"


# ── S3, the other half: the SAME claim, served one document over ────────────
#
# The card was fixed at S3 and the AgentFacts was not: build_self_agentfacts
# took no provider override and fell back to config.name, i.e. the TENANT,
# while the card for that same tenant named the HOST. A consumer resolving both
# documents for one business was told two different things about who operates
# the endpoint — and AgentFacts is the half a card host hands onward to
# api.nandaindex.org, so it is the copy a stranger actually reads.
#
# EACH document is asserted against a THIRD source — HOST_PUBLIC_URL, the value
# this test configured the host with — never against the other document. A
# parity check that reads its expectation off one of the two things it compares
# cannot fail, and one that only fires on a single side is half a detector, so
# the two sides have a named test each and drift on either one reddens its own.


def test_the_agentfacts_provider_is_the_hosting_domain_not_the_tenant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ "Who runs this agent" is this host's operator on the NANDA-facing
    document too. The business does not hold its own key or run its own
    process, and its name is a display label nobody verified."""
    public_url = "http://smb-host.example"
    business = "Facts Provider Claim Co"
    host = _make_host(tmp_path, monkeypatch, public_url)
    tenant_id, _ = _provision(host, business)
    facts = host.get(f"/t/{tenant_id}/agentfacts.json").json()

    assert facts["provider"]["name"] == urlparse(public_url).netloc, (
        f"AgentFacts provider.name is {facts['provider']['name']!r}, which names the tenant rather than the host"
    )
    assert facts["provider"]["name"] not in (business, tenant_id)
    assert facts["provider"]["url"] == public_url

    # The tenant is still named where the tenant belongs — declining to put the
    # business in `provider` must not have removed it from the document.
    assert facts["label"] == business

    # provider.did is the PROVIDER's DID per sm-bridge. The only did this host
    # has is the TENANT's, so emitting it beside an operator name that is
    # somebody else would assert the operator's key is the tenant's key.
    assert "did" not in facts["provider"], (
        f"AgentFacts names {facts['provider']['name']!r} as the operator while carrying "
        f"did={facts['provider'].get('did')!r}, which is the tenant's key, not the operator's"
    )


def test_both_served_documents_name_the_same_operator_as_the_configured_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G1: the card and the AgentFacts for ONE tenant name ONE operator.

    Both are checked against ``HOST_PUBLIC_URL`` — the third thing, set by this
    test and read by neither document — rather than against each other, so this
    still fails if BOTH drift together, which an A-equals-B check would not.
    The equality is asserted afterwards as the property the row in
    ``docs/CLAIMS.md`` states, but it is not what makes the test able to fail.
    """
    public_url = "http://smb-host.example"
    expected = urlparse(public_url).netloc
    host = _make_host(tmp_path, monkeypatch, public_url)
    tenant_id, card = _provision(host, "One Operator Co")
    facts = host.get(f"/t/{tenant_id}/agentfacts.json").json()

    served = {
        "card provider.organization": card["provider"]["organization"],
        "agentfacts provider.name": facts["provider"]["name"],
    }
    wrong = {where: value for where, value in served.items() if value != expected}
    assert not wrong, f"these name an operator other than the configured host {expected!r}: {wrong}"

    assert card["provider"]["url"] == facts["provider"]["url"] == public_url
    assert card["provider"]["organization"] == facts["provider"]["name"]


# ── the third artifact: index_registrar's own copy of the description ───────


def test_the_index_record_description_matches_the_served_description() -> None:
    """index_registrar.py builds the SMB org record for registration, not
    something this host serves — so it carries its own copy of the tenant
    description rather than importing this host's (main.py is guarded against
    importing the registration module at all, see
    test_smb_host_imports_neither_the_registrar_nor_discovery in
    agent/tests/test_index_registrar.py). This is the equivalence check that
    stands in for a shared import: the two copies must say the same thing for
    the same business, or the registration record and the served card/facts
    would describe one tenant differently."""
    from community_member.index_registrar import tenant_description

    import main as host_main

    assert host_main._tenant_description("Equivalence Co") == tenant_description("Equivalence Co")
