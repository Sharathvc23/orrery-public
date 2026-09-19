"""sm-federation 0.1 §2 — the node descriptor Orrery publishes at
``/.well-known/agent-community.json``.

**The endpoint is the cheap part; what it may honestly say is the unit.** The
descriptor schema requires only ``version`` and ``node_id``, so a document
carrying nothing else validates. Schema-valid is therefore not evidence of
anything, and a suite that asserted only "it validates" would be green against a
descriptor that told a peer nothing true. These tests assert the *contents*
against live org state: every field either points at something this app actually
serves, or is absent.

Three prior incidents set the non-negotiables, and each has a test here rather
than a comment:

  * **The public-discovery rule — a discovery document behind auth defeats itself.** ``did.json``
    was gated because its openness was implicit and nothing argued for it. P2
    makes this path's openness a declared, asserted property.
  * **The public-discovery rule's side effect — an anonymous GET must not mint identity.** The
    ``did.json`` handler generated a keypair when one was absent, publishing an
    in-memory identity and poisoning the cache so the durable key was never
    loaded. M1/M2 cover the same surface one document later.
  * **The resolvable-card rule — do not advertise a URL because it *could* exist.** The catalog
    emitted a host39 URL for every member whenever the org had a card base
    configured; 18 of 24 advertised entries 404'd. H2/H3 apply that rule to this
    document: a URL appears only when the thing behind it does.

**On the schema.** §5 defines conformance as "the descriptors and envelopes it
emits validate against the schemas in ``schema/federation/0.1/``" — and those
schema files **are not shipped in the sm-federation wheel** (measured against
``sm_federation-0.2.0-py3-none-any.whl``: four ``.py`` files, ``py.typed``, and
dist-info; no JSON). So "resolve the schema from the installed package" is not
possible today, and hand-transcribing it here would create exactly the unpinned
mirror this repo keeps paying to remove. These tests instead validate with the
package's own ``validate_descriptor`` and derive the permitted key set from the
package's own ``build_node_descriptor`` (P3) — both resolved from the
distribution, so neither can drift from it. The JSON-Schema-level assertion is the
federation conformance suite under ``conformance/federation/``; the packaging
gap is reported upstream.

Classification: HAPPY (P1, P3) · CONTRACT (P2, I1) · ADVERSARIAL (M1-M3) ·
HONESTY (H1-H3 — the failure mode here is a document that validates and lies).
"""

from __future__ import annotations

import base64
import importlib
import json
import sys

import pytest
import sm_federation
from fastapi.testclient import TestClient

_PUBLIC_URL = "https://test-federation-org.example"

# Optional pointer fields. Named explicitly rather than derived, so that adding a
# field to the descriptor without deciding what it means here fails a test.
_OPTIONAL_FIELDS = (
    "did",
    "facts_url",
    "a2a_url",
    "conformance_url",
    "feed_url",
    "registries",
    "federation_versions",
    "capabilities",
)


@pytest.fixture
def chapter_agent_module(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_ID", "TEST-federation-org")
    monkeypatch.setenv("AGENT_NAME", "Test Federation Org")
    monkeypatch.setenv("AGENT_DESCRIPTION", "An org for the node-descriptor test")
    monkeypatch.setenv("AGENT_FOCUS", "federation, discovery")
    monkeypatch.delenv("CHAPTER_SLUG", raising=False)
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    # The lifespan that sets PUBLIC_URL does not run for a non-context TestClient
    # and the handlers read the module global, so set it directly.
    monkeypatch.setattr(mod, "PUBLIC_URL", _PUBLIC_URL)
    return mod


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    chapter_agent_module._rate_limit_store.clear()
    return TestClient(chapter_agent_module.app)


@pytest.fixture
def org_key(chapter_agent_module):
    """Give the org a signing key, as startup's ensure_chapter_keypair would."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair(chapter_agent_module.AGENT_ID)
    yield kp
    sovereign_identity._ed25519_keypairs.pop(chapter_agent_module.AGENT_ID, None)


@pytest.fixture
def keyless(chapter_agent_module):
    """An org with no key material at all — the state a first boot is in."""
    import sovereign_identity

    sovereign_identity._ed25519_keypairs.pop(chapter_agent_module.AGENT_ID, None)
    yield
    sovereign_identity._ed25519_keypairs.pop(chapter_agent_module.AGENT_ID, None)


@pytest.fixture
def published_badge(chapter_agent_module, monkeypatch: pytest.MonkeyPatch, tmp_path):
    """A conformance badge that exists on disk, as conformance_boot writes at boot."""
    badge = tmp_path / "conformance.json"
    badge.write_text(json.dumps({"suite": "test"}), encoding="utf-8")
    monkeypatch.setattr(chapter_agent_module, "_CONFORMANCE_BADGE_PATH", badge)
    return badge


@pytest.fixture
def no_badge(chapter_agent_module, monkeypatch: pytest.MonkeyPatch, tmp_path):
    """An org that has never published a badge — /.well-known/conformance.json 404s."""
    monkeypatch.setattr(chapter_agent_module, "_CONFORMANCE_BADGE_PATH", tmp_path / "absent.json")


def _get(client: TestClient) -> dict:
    resp = client.get("/.well-known/agent-community.json")
    assert resp.status_code == 200, resp.text[:300]
    return resp.json()


# ---------------------------------------------------------------------------
# P1-P3 — it is a conformant descriptor, and it is reachable by a stranger
# ---------------------------------------------------------------------------


def test_P1_anonymous_get_returns_a_valid_node_descriptor(client: TestClient, org_key) -> None:
    """The peering entry point, fetched the way a peer fetches it: no credentials.

    Validated with the PUBLISHED validator, not a local re-implementation of the
    rules — a second copy of the contract is the thing this test exists to catch.
    """
    doc = _get(client)

    assert doc["version"] == sm_federation.DESCRIPTOR_VERSION
    assert doc["node_id"] == "TEST-federation-org"
    ok, reason = sm_federation.validate_descriptor(doc)
    assert ok, f"served descriptor is not valid per sm_federation.validate_descriptor: {reason}"


def test_P2_openness_is_declared_not_incidental(chapter_agent_module) -> None:
    """The public-discovery rule's actual lesson. Unlisted GETs already default to open in this
    middleware, so this path would answer 200 without the OPEN_PATHS entry — and
    that is precisely the state ``did.json`` was in when it broke. "Open by
    default" is a fact about the middleware; "open on purpose" is a claim about
    this document, and only the second one survives a hardening pass that flips
    the GET default or adds a /.well-known/ prefix rule."""
    import auth_verify

    assert "/.well-known/agent-community.json" in auth_verify.OPEN_PATHS
    assert auth_verify.is_open_path("GET", "/.well-known/agent-community.json") is True
    assert auth_verify.requires_auth("GET", "/.well-known/agent-community.json") is False


def test_P3_no_field_the_published_contract_does_not_define(client: TestClient, org_key) -> None:
    """``additionalProperties: false``, checked without a copy of the schema.

    The permitted key set is read out of the package's own builder, so it tracks
    the distribution automatically. A hand-listed set here would be a mirror of
    the wire contract with nothing comparing the two — the drift shape
    ``a2ui_helpers`` and ``_conformance_vectors`` each needed a guard to close.
    """
    permitted = set(sm_federation.build_node_descriptor(node_id="probe"))

    assert set(_get(client)) <= permitted


# ---------------------------------------------------------------------------
# I1 — one identity, two documents, byte-identical
# ---------------------------------------------------------------------------


def test_I1_did_is_byte_identical_to_the_did_document(client: TestClient, org_key) -> None:
    """Both surfaces read off the SAME running app, in one test, deliberately.

    An org that advertises one DID in its descriptor and serves another at
    ``/.well-known/did.json`` is unverifiable to a peer that follows the pointer
    — it resolves the DID, gets a key, and cannot match it to the node it was
    talking to. Two independent derivations of one identity is how that happens,
    so both handlers derive from ``routes.identity.org_did`` and this asserts the
    result rather than the wiring.
    """
    descriptor = _get(client)
    did_document = client.get("/.well-known/did.json").json()

    assert descriptor["did"] == did_document["id"]
    assert descriptor["did"] == f"did:web:{_PUBLIC_URL.removeprefix('https://')}"


# ---------------------------------------------------------------------------
# M1-M3 — an anonymous read must not create, invent, or leak anything
# ---------------------------------------------------------------------------


def test_M1_reading_the_descriptor_does_not_mint_a_key(client: TestClient, chapter_agent_module, keyless) -> None:
    """The public-discovery rule on a new surface. The descriptor is a pure read: it must answer with
    what exists, and an org's identity must not be a side effect of a stranger
    fetching its discovery document."""
    import sovereign_identity

    client.get("/.well-known/agent-community.json")

    assert chapter_agent_module.AGENT_ID not in sovereign_identity._ed25519_keypairs, (
        "an anonymous descriptor read minted a signing key — identity creation is "
        "ensure_chapter_keypair's job at startup, where it is persisted"
    )


def test_M2_keyless_org_omits_did_rather_than_advertising_an_unresolvable_one(
    client: TestClient, keyless
) -> None:
    """The incomplete descriptor, and why it is the honest answer.

    A ``did:web`` derives from the domain alone, so this handler *could* always
    emit one. It would resolve to a ``/.well-known/did.json`` answering 503 — a
    pointer to nothing, which costs the peer a round trip and tells it something
    false. Absent is a fact the peer can act on; present-but-broken is not.
    The response is still a 200 descriptor: the node genuinely exists and its
    ``node_id`` is genuinely known.
    """
    doc = _get(client)

    assert "did" not in doc
    assert doc["node_id"], "the node still exists and still has an id"
    ok, reason = sm_federation.validate_descriptor(doc)
    assert ok, reason


def test_M3_the_document_carries_no_secret_material(client: TestClient, org_key) -> None:
    """Publishing this unauthenticated is safe only because every value in it is
    public. Assert the invariant, rather than trusting that it stays that way as
    fields are added."""
    body = client.get("/.well-known/agent-community.json").text

    assert org_key["private_key"] not in body
    assert base64.b64encode(base64.b64decode(org_key["private_key"])).decode() not in body
    for forbidden in ("privateKey", "private_key", "secret", "seed", "token"):
        assert forbidden not in body


# ---------------------------------------------------------------------------
# H1-H3 — the document must not validate and lie
# ---------------------------------------------------------------------------


def test_H1_feed_url_is_the_signed_feed_and_only_when_it_can_be_honoured(
    chapter_agent_module, org_key
) -> None:
    """INVERTED at the intelligence-feed work — kept, not deleted, because its purpose survived.

    It previously asserted ``feed_url`` was ABSENT, and its stated reason was to
    stop exactly the shortcut that exists now that a feed is expected: pointing
    ``feed_url`` at an existing unsigned surface satisfies the schema and breaks
    §4's guarantee. Deleting it once the feed shipped would have removed the
    guard at the moment it became load-bearing. So it now asserts the same
    property from the other side — the field is present when and only when the
    node can honour it, and it names the signed feed rather than the snapshot.

    ``/api/knowledge/summary`` is the specific trap: a full, UNSIGNED, cursorless
    snapshot — the v0.1 model §4 replaced. It still exists for Orrery's own peers
    and must never be what ``feed_url`` points at.
    """
    import federation_feed

    federation_feed.reset_for_tests(False, "no durable log in this deployment")
    try:
        off = _get(TestClient(chapter_agent_module.app))
        assert "feed_url" not in off, "a node that cannot honour §4 must not advertise a feed"
        assert sm_federation.section_token("4") not in off.get("capabilities", [])

        federation_feed.reset_for_tests(True, "")
        on = _get(TestClient(chapter_agent_module.app))
        assert on["feed_url"] == f"{_PUBLIC_URL}{federation_feed.FEED_PATH}"
        assert "/api/knowledge/summary" not in on["feed_url"], (
            "feed_url points at the unsigned snapshot — that satisfies the schema and "
            "breaks the completeness guarantee the schema exists to express"
        )
        assert sm_federation.section_token("4") in on["capabilities"], (
            "#4 must be DERIVED from feed_url by the builder, never hand-set"
        )
    finally:
        federation_feed.reset_for_tests(False, "reset")


def test_H2_conformance_url_appears_only_when_a_badge_exists(
    chapter_agent_module, org_key, published_badge, no_badge
) -> None:
    """The resolvable-card rule's rule, both directions. Asserting only the present case would pass
    against a handler that emits the URL unconditionally — which is the exact
    defect the resolvable-card rule was."""
    monkey = pytest.MonkeyPatch()
    try:
        # no_badge is active from the fixture: nothing on disk.
        client = TestClient(chapter_agent_module.app)
        assert "conformance_url" not in _get(client)

        monkey.setattr(chapter_agent_module, "_CONFORMANCE_BADGE_PATH", published_badge)
        assert _get(client)["conformance_url"] == f"{_PUBLIC_URL}/.well-known/conformance.json"
    finally:
        monkey.undo()


def test_H3_every_advertised_url_resolves_on_this_app(
    client: TestClient, org_key, published_badge
) -> None:
    """A pointer document is only as good as what it points at.

    Driven over the wire, one request per advertised URL, rather than by walking
    ``app.routes`` — the included routers are wrapped (``_IncludedRouter``) and a
    naive walk silently misses every path defined in ``routes/identity.py``,
    which is most of this document. A route-table check that cannot see the
    routes would have passed for the wrong reason.

    Asserted as "not 404", not "200": ``/a2a`` is a signed POST, so a GET
    correctly answers 405 — which still proves the route is there. 404 is the
    only status that means the pointer is a lie, and it is exactly what the resolvable-card rule's
    18 unbacked catalog entries returned.
    """
    import federation_feed

    # Turn the feed on so feed_url is among the URLs under test — otherwise this
    # assertion silently skips the newest field in the document, which is the
    # shape of coverage gap that lets a broken pointer ship.
    federation_feed.reset_for_tests(True, "")
    try:
        doc = _get(client)
    finally:
        federation_feed.reset_for_tests(False, "reset")

    advertised = {k: v for k, v in doc.items() if k.endswith("_url")}
    assert "feed_url" in advertised, "the feed URL must be covered by this assertion, not skipped"
    assert advertised, "the descriptor advertised no URLs at all — check PUBLIC_URL wiring"
    for field, url in advertised.items():
        assert url.startswith(_PUBLIC_URL), f"{field} is not rooted at this org's public URL: {url}"
        code = client.get(url.removeprefix(_PUBLIC_URL)).status_code
        assert code != 404, f"{field} advertises {url}, which this app does not serve"


def test_H4_optional_fields_are_present_or_absent_never_empty(client: TestClient, org_key) -> None:
    """``"feed_url": ""`` validates and is not the same statement as no
    ``feed_url``: it hands a peer a string to resolve, and an empty string
    resolves against the peer's own base. The published ``minimal`` vector omits
    absent fields rather than emptying them, so absence is the protocol's own
    idiom for "I do not have this"."""
    doc = _get(client)

    for field in _OPTIONAL_FIELDS:
        if field in doc:
            assert doc[field], f"{field} was emitted empty — omit it instead"


# ---------------------------------------------------------------------------
# LU — listing_url, and the trap it must not reintroduce
# ---------------------------------------------------------------------------


def test_LU1_the_listing_token_is_DERIVED_not_settable(chapter_agent_module, org_key, monkeypatch) -> None:
    """`listing/0.1` present ⟺ `listing_url` present, and the BUILDER decides.

    Hand-setting the token is how a descriptor comes to claim a surface the node
    does not serve — the same reason `federation/0.1#4` is derived from
    `feed_url`. Asserted in both directions off one running app, because either
    alone is satisfiable by a descriptor that never mentions the listing at all.
    """
    import sm_federation

    import member_listing

    monkeypatch.delenv(member_listing.ENABLED_FLAG, raising=False)
    off = _get(TestClient(chapter_agent_module.app))
    assert "listing_url" not in off
    assert sm_federation.LISTING_PROFILE not in off.get("capabilities", [])

    monkeypatch.setenv(member_listing.ENABLED_FLAG, "true")
    on = _get(TestClient(chapter_agent_module.app))
    assert on["listing_url"] == f"{_PUBLIC_URL}{member_listing.LISTING_PATH}"
    assert sm_federation.LISTING_PROFILE in on["capabilities"], "the token must be derived from listing_url"
    ok, reason = sm_federation.validate_descriptor(on)
    assert ok, reason


def test_LU2_the_url_is_advertised_even_when_the_listing_is_EMPTY(
    chapter_agent_module, org_key, monkeypatch
) -> None:
    """⚠️ THE TRAP test_E4 PROTECTS AGAINST, arriving from the descriptor side.

    `listing_url` present ⟺ token claimed. It does NOT imply the listing is
    non-empty. This org has NO members at all, so the listing it serves is empty
    — and the descriptor still advertises it, because "I run this surface; nobody
    has opted in" is a different and more useful fact than silence.

    Gating the URL on entry count would make the descriptor flap as members opt
    in and out, and would make an empty-but-consented org indistinguishable from
    one that never implemented the profile.
    """
    import member_listing

    monkeypatch.setenv(member_listing.ENABLED_FLAG, "true")
    client = TestClient(chapter_agent_module.app)
    assert chapter_agent_module.members == {}, "this assertion is about an org with nobody listed"

    doc = _get(client)
    listing = client.get(member_listing.LISTING_PATH).json()

    assert doc["listing_url"].endswith(member_listing.LISTING_PATH)
    assert listing["entries"] == [], "the org is empty — and the URL is advertised anyway"


def test_LU3_the_descriptor_and_the_listing_agree(chapter_agent_module, org_key, monkeypatch) -> None:
    """What the descriptor advertises is what the org serves. Driven over the
    wire in both states rather than compared to a constant: a descriptor that
    advertised a path the node 404s is the pointer-to-nothing class the resolvable-card rule was."""
    import member_listing

    monkeypatch.setenv(member_listing.ENABLED_FLAG, "true")
    client = TestClient(chapter_agent_module.app)
    doc = _get(client)
    assert client.get(doc["listing_url"].removeprefix(_PUBLIC_URL)).status_code == 200

    monkeypatch.delenv(member_listing.ENABLED_FLAG, raising=False)
    off_client = TestClient(chapter_agent_module.app)
    assert "listing_url" not in _get(off_client), "the descriptor advertises a listing this node 404s"
    assert off_client.get(member_listing.LISTING_PATH).status_code == 404
