"""Does Orrery implement the federation profile it publishes?

``claims.json`` states, per published surface, whether Orrery implements it. The
claim is checked in both directions, so it cannot rot in either:

  implemented = true   the surface must respond AND validate against the
                       published schema. A drifted implementation fails.
  implemented = false  the surface must genuinely be absent. The moment it
                       starts responding, THIS test fails — the claim has to be
                       flipped to true, and the schema validation then applies.

That second direction is the load-bearing one. Without it, "not implemented yet"
is a label that exempts a surface forever, and the day someone ships it there is
nothing asserting it conforms. With it, shipping the surface is what turns the
conformance assertion on.

Schemas come from ``sm_federation.wire`` — the installed distribution — never
from a copy in this repo.
"""

from __future__ import annotations

import json

import pytest

from conformance.federation.conftest import CLAIMS_PATH

VALID_SURFACE_KINDS = {"http", "emitter", "algorithm"}

# Parametrising over the claim list needs it at collection time, before fixtures
# exist. The `claims` fixture reads the same file, so there is one source.
_HTTP_SURFACES = [s for s in json.loads(CLAIMS_PATH.read_text(encoding="utf-8"))["surfaces"] if s["kind"] == "http"]


def test_every_claim_is_well_formed(claims, published_schema) -> None:
    """A malformed claim silently checks nothing, so shape is asserted first."""
    seen = set()
    for s in claims["surfaces"]:
        assert s["kind"] in VALID_SURFACE_KINDS, f"{s['id']}: unknown kind {s['kind']!r}"
        assert s["id"] not in seen, f"duplicate surface id {s['id']!r}"
        seen.add(s["id"])
        assert isinstance(s["implemented"], bool), f"{s['id']}: implemented must be a bool"
        assert len(s.get("note", "")) >= 40, f"{s['id']}: note must state what was measured"
        if s.get("schema") is not None:
            assert s["schema"] in published_schema, (
                f"{s['id']}: names schema {s['schema']!r}, which the published distribution does not define"
            )
        if s["kind"] == "http":
            assert s["path"].startswith("/"), f"{s['id']}: path must be absolute"


def test_the_published_profile_has_no_unclaimed_surface(claims, wire) -> None:
    """Every schema the distribution publishes must be claimed by some surface.

    If sm-federation adds a third wire object, this fails until Orrery states
    whether it implements it — a new published surface cannot land unmeasured.
    """
    claimed = {s["schema"] for s in claims["surfaces"] if s.get("schema")}
    missing = set(wire.SCHEMA_NAMES) - claimed
    assert not missing, f"published schemas with no claim in claims.json: {sorted(missing)}"


@pytest.mark.parametrize("surface", _HTTP_SURFACES, ids=lambda s: s["id"])
def test_http_surface_matches_its_claim(surface, orrery_client, published_schema) -> None:
    resp = orrery_client.request(surface["method"], surface["path"])

    if surface.get("may_degrade"):
        # Some surfaces are allowed to be absent on an instance that implements
        # them — Orrery's feed boot degrades rather than crashing when the app
        # role lacks DDL privilege, because bricking a self-hosted install to add
        # an optional feature is worse than the feature being absent. Presence is
        # therefore not the property to assert; coherence with the descriptor is,
        # and test_feed_completeness.py asserts that. What is still checked here
        # is that a surface which DOES respond conforms.
        if resp.status_code != 200:
            return

    if not surface["implemented"]:
        assert resp.status_code == 404, (
            f"{surface['id']} is claimed implemented:false but {surface['method']} {surface['path']} "
            f"returned {resp.status_code}. The surface now exists — flip the claim to true in claims.json, "
            f"which turns on the published-schema validation for it."
        )
        return

    assert resp.status_code == 200, (
        f"{surface['id']} is claimed implemented:true but returned {resp.status_code}"
    )
    if surface.get("schema"):
        errors = sorted(
            published_schema[surface["schema"]].iter_errors(resp.json()),
            key=lambda e: list(e.absolute_path),
        )
        assert not errors, (
            f"{surface['id']} does not conform to the published {surface['schema']} schema:\n"
            + "\n".join(f"  {list(e.absolute_path)}: {e.message}" for e in errors)
        )


def test_intelligence_envelope_emitter_matches_its_claim(claims, orrery_summary, published_schema) -> None:
    """The emitter claim, checked against what the emitter actually returns.

    ``implemented:false`` is not taken on trust — the summary must genuinely fail
    published validation. If someone makes Orrery emit a real envelope and
    forgets this file, the claim is caught as stale rather than sitting false
    forever next to a conformant emitter.
    """
    (surface,) = [s for s in claims["surfaces"] if s["id"] == "intelligence-envelope-emitter"]
    validator = published_schema[surface["schema"]]
    errors = sorted(validator.iter_errors(orrery_summary), key=lambda e: list(e.absolute_path))

    if surface["implemented"]:
        assert not errors, "claimed implemented:true but the emitted summary is not a valid envelope:\n" + "\n".join(
            f"  {list(e.absolute_path)}: {e.message}" for e in errors
        )
    else:
        assert errors, (
            "claims.json says the emitter does not implement the profile, but what it emits "
            "validates against the published envelope schema. Flip the claim to true."
        )


def test_skill_match_algorithm_matches_its_claim(claims) -> None:
    """Orrery's find_skill_matches vs the reference, on a shared input.

    Both are pure functions, so this compares them directly rather than
    inspecting either. ``implemented:false`` requires an observable divergence —
    the claim cannot survive Orrery being aligned with the reference.
    """
    import federation_intelligence as fi
    from sm_federation import build_intelligence_envelope, find_skill_matches

    (surface,) = [s for s in claims["surfaces"] if s["id"] == "skill-match-algorithm"]

    peer = build_intelligence_envelope(
        community_id="beta",
        community_name="Beta",
        generated_at="2026-01-01T00:00:00Z",
        skill_graph={"solidity": 9},
    )
    reference = find_skill_matches(["solidity"], [peer])

    fi.init(lambda *a, **k: None, {"chapter_intelligence": {"skill_gaps": ["solidity"]}}, "orrery-node", "Orrery Node")
    fi.federation_knowledge.clear()
    fi.federation_knowledge["beta"] = dict(peer)
    try:
        orrery = fi.find_skill_matches(["solidity"])
    finally:
        fi.federation_knowledge.clear()

    reference_keys = {k for m in reference for k in m}
    orrery_keys = {k for m in orrery for k in m}

    if surface["implemented"]:
        assert orrery_keys == reference_keys, (
            f"claimed implemented:true but the result shapes differ: {sorted(orrery_keys)} vs {sorted(reference_keys)}"
        )
    else:
        assert orrery_keys != reference_keys, (
            "claims.json says Orrery does not implement the reference skill-match algorithm, but its "
            "result shape now matches the reference. Flip the claim to true so the comparison is enforced."
        )


def test_substring_matching_is_the_documented_divergence() -> None:
    """The claim says the divergence is in the matching RULE, not only the shape.

    Asserting the rule keeps that sentence honest: the reference matches skills
    exactly, Orrery matches case-insensitive substrings in either direction, so
    a gap of 'ml' is satisfied by a peer whose only skill is 'html'.
    """
    import federation_intelligence as fi
    from sm_federation import build_intelligence_envelope, find_skill_matches

    peer = build_intelligence_envelope(
        community_id="beta", community_name="Beta", generated_at="t", skill_graph={"html": 3}
    )
    assert find_skill_matches(["ml"], [peer]) == [], "reference must not satisfy 'ml' with 'html'"

    fi.init(lambda *a, **k: None, {}, "orrery-node", "Orrery Node")
    fi.federation_knowledge.clear()
    fi.federation_knowledge["beta"] = dict(peer)
    try:
        assert fi.find_skill_matches(["ml"]), "Orrery's substring rule is the documented divergence"
    finally:
        fi.federation_knowledge.clear()


# ── the validator wired here must not be permissive ────────────────────────────


@pytest.mark.parametrize("corpus", ["descriptors-invalid", "envelopes-invalid"])
def test_published_invalid_vectors_are_rejected(corpus, wire, published_schema) -> None:
    """Run the profile's own rejection corpus through the validator used above.

    A schema alone lets a consumer confirm their happy path. The invalid-case
    vectors are what catch a *permissive* validator — and every assertion in this
    file is only as strong as the validator behind it. Without this, swapping
    `iter_errors` for something that returns nothing, or loading the wrong
    schema, would turn the whole suite green rather than red.

    This is why sm-federation 0.3.0 ships the vectors and not only the schemas:
    the rejection corpus is the half a consumer cannot reconstruct for
    themselves.
    """
    name = "node-descriptor" if corpus.startswith("descriptors") else "intelligence-envelope"
    key = "descriptor" if corpus.startswith("descriptors") else "envelope"
    validator = published_schema[name]

    cases = wire.load_vectors(corpus)["cases"]
    assert cases, f"{corpus} is empty — a rejection corpus with no cases proves nothing"

    accepted = [c["id"] for c in cases if not list(validator.iter_errors(c[key]))]
    assert not accepted, (
        f"the {name} validator ACCEPTED payloads the published profile says must be rejected: "
        f"{accepted}. Either the validator here is permissive or the wrong schema is loaded — "
        "every other assertion in this suite runs through it."
    )


@pytest.mark.parametrize("corpus", ["descriptors-valid", "envelopes-valid"])
def test_published_valid_vectors_are_accepted(corpus, wire, published_schema) -> None:
    """The other half: a validator that rejects everything is also useless."""
    name = "node-descriptor" if corpus.startswith("descriptors") else "intelligence-envelope"
    key = "descriptor" if corpus.startswith("descriptors") else "envelope"
    validator = published_schema[name]

    rejected = {
        c["id"]: [e.message for e in validator.iter_errors(c[key])]
        for c in wire.load_vectors(corpus)["cases"]
        if list(validator.iter_errors(c[key]))
    }
    assert not rejected, f"the {name} validator REJECTED published-valid payloads: {rejected}"


# ── §2.1: the descriptor's own declaration must agree with claims.json ─────────


def test_descriptor_declares_exactly_the_sections_orrery_implements(claims, orrery_client) -> None:
    """Two independent statements of the same fact, which must not disagree.

    ``claims.json`` says in this repo's vocabulary which profile sections Orrery
    implements. Since sm-federation 0.4.0 the descriptor says the same thing in
    the *protocol's* vocabulary, as §2.1 ``capabilities`` section tokens. Nothing
    compares them unless something does.

    Ship a feed and flip the claim but forget the descriptor — or the reverse —
    and this is what catches it. Before 0.4.0 the descriptor had no way to state
    it at all, and this suite recorded that as a limitation it could not assert.

    Tokens are built with the package's own ``section_token`` rather than written
    out, so a change to the token format upstream surfaces here instead of
    silently making the assertion vacuous.
    """
    from sm_federation import SECTION_DESCRIPTOR, SECTION_EXCHANGE, declared_sections

    doc = orrery_client.get("/.well-known/agent-community.json").json()
    declared = declared_sections(doc)

    assert SECTION_DESCRIPTOR in declared, (
        "the served descriptor does not declare §2, which it implements by existing"
    )

    # §4 against what THIS INSTANCE offers, which is `feed_url` — not against
    # whether Orrery implements the feature. The feed boot degrades rather than
    # crashing when the app role lacks DDL privilege, so an implemented feed can
    # legitimately be absent here; a node declaring §2 only is conformant.
    assert (SECTION_EXCHANGE in declared) == bool(doc.get("feed_url")), (
        f"the descriptor declares sections {sorted(declared)} but advertises "
        f"feed_url={doc.get('feed_url')!r}. §2.1 binds the §4 token to feed_url in both directions."
    )

    # The asymmetric direction: a node may implement §4 and offer nothing (a
    # degraded install), but may not offer what it has not implemented.
    (feed_claim,) = [s for s in claims["surfaces"] if s["id"] == "intelligence-feed"]
    if not feed_claim["implemented"]:
        assert SECTION_EXCHANGE not in declared, (
            "the descriptor declares §4 while claims.json says it is not implemented — the claim is "
            "stale, or the node advertises an exchange it cannot serve."
        )


def test_the_descriptor_advertisement_matches_the_runtime_that_backs_it(orrery_client) -> None:
    """§2.1's cross-field rule, applied to the live document by its producer.

    The published schema enforces this and the suite above validates against it,
    so this is belt-and-braces — but it is the assertion that would survive
    someone loading the wrong schema, and it names the runtime fact rather than
    the document shape: a node claiming the exchange must publish the feed a peer
    would subscribe to.
    """
    from sm_federation import SECTION_EXCHANGE, declared_sections

    doc = orrery_client.get("/.well-known/agent-community.json").json()
    claims_exchange = SECTION_EXCHANGE in declared_sections(doc)
    has_feed = bool(doc.get("feed_url"))
    assert claims_exchange == has_feed, (
        f"descriptor claims §4={claims_exchange} but feed_url present={has_feed}. "
        "A §4 claim without a feed is unverifiable; a feed without the claim makes a peer infer "
        "support from a URL instead of reading a declaration."
    )
