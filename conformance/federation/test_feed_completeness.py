"""§4: does Orrery's feed honour the completeness guarantee, or only sign pages?

§4 does not promise "returns signed pages". It promises a subscriber can verify
**authenticity and completeness** — that it saw every entry, in order, from the
sequence it was already following. **A feed that returns signed pages but cannot
prove a peer saw every entry is the unsigned snapshot with extra steps**, which
is what Orrery has today at `GET /api/knowledge/summary`.

Three failures a completeness guarantee exists to catch, each asserted here:

  1. a DROPPED entry
  2. a REORDERED entry
  3. a RESTARTED SEQUENCE — the publisher reseeds from a new genesis. Every entry
     is correctly signed and correctly chained; only a head the subscriber
     already accepted proves the sequence was replaced rather than extended.

(3) is a real failure mode here, though not for the reason previously written in
this directory. `server/constraints.txt` refused sm-bridge's `[feed]` extra
because the **member-delta** store is in-memory and reseeds from a wall-clock
base on every restart. That refusal is about a *different log* and says
nothing about an intelligence feed, which can sit on a durable store — the
conflation is corrected in `claims.json`. What survives is the failure class: any
store that reseeds produces exactly this, so it is asserted **across an actual
restart of the app**, not a simulated one. A reseed that only ever happens in a
fixture is not the failure being guarded against.

**Written before the endpoint existed, deliberately.** A conformance suite
written after an implementation tends to assert what the implementation does.
Building these first already found one thing: through sm-federation 0.4.2,
`read_intelligence` did not forward `expected_head` to `verify_page`, so the
reference seam for §4 **could not detect case (3) at all** — a reseeded feed
returned `ok`. Fixed upstream in the sm-federation protocol notes (0.5.0), and
`test_the_reference_verifier_detects_a_reseed` below is the regression guard that
keeps this suite from silently going back to asserting the weaker property.

Structure: the verifier assertions run **now**, against the published reference,
so they are proven to detect what they claim. The live-endpoint assertions read
what **this instance** advertises.

**A node with no feed is conformant.** §4 is optional — §2.1 exists precisely so
a node can say "I implement the descriptor and not the exchange". Orrery's feed
boot degrades rather than crashes when the app role lacks DDL privilege, so a
DB-less or least-privilege install legitimately serves no `feed_url` and claims no
`#4`. That is valid §2-only conformance and this suite treats it as such.

What is **not** valid is degrading *partially*. The failure to catch is an
instance advertising a feed it cannot serve, or serving one it does not
advertise: a peer reads the descriptor, and a pointer to nothing costs it a round
trip and tells it something false. So the rule asserted here is **coherence** —
`feed_url`, the `#4` claim, and the endpoint all agree — rather than presence.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

# ── the reference verifier: proven to detect all three, now ────────────────────


@pytest.fixture(scope="module")
def signed_feed():
    """A three-entry signed feed and the cursor a subscriber would persist."""
    from sm_feed import FeedLog, Identity, verify_page

    from sm_federation import build_intelligence_envelope

    log = FeedLog(Identity.from_seed(b"\x11" * 32))
    for i in (1, 2, 3):
        log.append(
            build_intelligence_envelope(
                community_id="probe",
                community_name="Probe",
                generated_at=f"2026-01-0{i}T00:00:00Z",
                skill_graph={"rust": i},
            ),
            issued_at=f"2026-01-0{i}T00:00:00Z",
        )
    page = log.page(None, generated_at="2026-01-04T00:00:00Z")
    ok, reason, cursor = verify_page(page)
    assert ok, f"the unmodified feed must verify before anything is planted: {reason}"
    return {"log": log, "page": page, "cursor": cursor}


def test_the_reference_verifier_detects_a_dropped_entry(signed_feed) -> None:
    from sm_feed import verify_page

    tampered = copy.deepcopy(signed_feed["page"])
    removed = tampered["entries"].pop(1)
    assert removed, "confirm the plant landed: an entry was actually removed"

    ok, reason, _ = verify_page(tampered)
    assert not ok, "a page with an entry removed must not verify"
    assert "chain" in reason or "gap" in reason, reason


def test_the_reference_verifier_detects_a_reordered_entry(signed_feed) -> None:
    from sm_feed import verify_page

    tampered = copy.deepcopy(signed_feed["page"])
    tampered["entries"][1], tampered["entries"][2] = tampered["entries"][2], tampered["entries"][1]
    assert tampered["entries"] != signed_feed["page"]["entries"], "confirm the plant landed"

    ok, reason, _ = verify_page(tampered)
    assert not ok, "a page with two entries swapped must not verify"


def test_the_reference_verifier_detects_a_reseed(signed_feed) -> None:
    """Case 3, and the regression guard for the sm-federation protocol notes.

    Through 0.4.2 ``read_intelligence`` did not forward ``expected_head``, so this
    returned ``ok``. If a future version stops forwarding it, this suite would go
    back to asserting authenticity while believing it asserted completeness.
    """
    from sm_feed import FeedLog, Identity

    from sm_federation import build_intelligence_envelope, read_intelligence

    reseeded_log = FeedLog(Identity.from_seed(b"\x11" * 32))  # SAME key, new genesis
    reseeded_log.append(
        build_intelligence_envelope(community_id="probe", community_name="Probe", generated_at="2026-02-01T00:00:00Z"),
        issued_at="2026-02-01T00:00:00Z",
    )
    reseeded = reseeded_log.page(None, generated_at="2026-02-01T00:00:01Z")

    head = signed_feed["cursor"]["head"]
    ok, reason, envelopes, _ = read_intelligence(reseeded, expected_head=head)
    assert not ok, (
        "a reseeded sequence verified against a head the subscriber already accepted. The reference "
        "seam is not forwarding expected_head — see the sm-federation protocol notes; without it this suite asserts "
        "authenticity while claiming completeness."
    )
    assert reason == "head_rewind", reason
    assert envelopes == [], "a peer must not act on intelligence from a page it could not verify"


def test_the_reseed_control_the_previous_test_depends_on(signed_feed) -> None:
    """Without the head, the reseeded page verifies — so the test above is testing
    the head check and nothing else.

    A plant proves nothing if the fixture would have failed anyway.
    """
    from sm_feed import FeedLog, Identity

    from sm_federation import build_intelligence_envelope, read_intelligence

    log = FeedLog(Identity.from_seed(b"\x11" * 32))
    log.append(
        build_intelligence_envelope(community_id="probe", community_name="Probe", generated_at="2026-02-01T00:00:00Z"),
        issued_at="2026-02-01T00:00:00Z",
    )
    ok, reason, envelopes, _ = read_intelligence(log.page(None, generated_at="2026-02-01T00:00:01Z"))
    assert ok and reason == "ok", reason
    assert len(envelopes) == 1


# ── the live surface, bound to the claim ───────────────────────────────────────


def _feed_claim(claims: dict[str, Any]) -> dict[str, Any]:
    (claim,) = [s for s in claims["surfaces"] if s["id"] == "intelligence-feed"]
    return claim


def _advertised(orrery_client) -> str:
    """The ``feed_url`` THIS instance advertises, or ``""``.

    Kept separate from the ``claims.json`` flag on purpose. The claim says
    whether Orrery *implements* §4; this says whether the running instance is
    *offering* it. They are different questions once the feed boot is allowed to
    degrade, and conflating them makes a legitimate least-privilege install look
    non-conformant.
    """
    return orrery_client.get("/.well-known/agent-community.json").json().get("feed_url") or ""


def test_the_descriptor_is_internally_coherent_about_section_4(orrery_client) -> None:
    """§2.1's cross-field rule, read off the live wire.

    ``feed_url`` non-empty ⟺ the descriptor claims ``federation/0.1#4``. Required
    in **both** states: a node offering a feed must say so, and a node that
    degraded to no feed must not leave the claim behind. The published schema
    enforces this; asserting it against the served document catches a runtime
    that assembles the descriptor by hand instead of through the builder.
    """
    from sm_federation import SECTION_EXCHANGE, declared_sections

    doc = orrery_client.get("/.well-known/agent-community.json").json()
    has_feed_url = bool(doc.get("feed_url"))
    claims_section_4 = SECTION_EXCHANGE in declared_sections(doc)

    assert has_feed_url == claims_section_4, (
        f"descriptor advertises feed_url={has_feed_url} but claims §4={claims_section_4}. "
        "sm-federation §2.1 binds them in both directions, so a partially-degraded node — one that "
        "dropped the feed but kept the claim, or the reverse — is non-conformant even though each "
        "field looks reasonable alone."
    )


def test_an_unimplemented_feed_is_not_advertised(claims, orrery_client) -> None:
    """The one direction that is *not* symmetric.

    A node MAY implement §4 and still advertise nothing — that is the degraded
    install, and it is conformant. A node may NOT advertise a feed it has not
    implemented: you cannot degrade into offering something that does not exist,
    so that direction stays a hard failure.
    """
    if _feed_claim(claims)["implemented"]:
        return
    assert not _advertised(orrery_client), (
        "the descriptor advertises a feed_url while claims.json says §4 is not implemented. "
        "Either the feed shipped and the claim is stale, or the descriptor points a peer at "
        "nothing."
    )


def test_the_live_feed_serves_a_verifiable_page(claims, orrery_client) -> None:
    """The moment a feed exists, it must verify — and until then, it must be absent.

    ``implemented: false`` is checked by absence rather than trusted, so shipping
    the endpoint is what switches this assertion on.
    """
    claim = _feed_claim(claims)
    feed_url = _advertised(orrery_client)
    resp = orrery_client.get(claim["path"])

    if not claim["implemented"]:
        assert resp.status_code == 404, (
            f"{claim['path']} returned {resp.status_code} while claimed implemented:false. "
            "The feed now exists — flip the claim, which turns on the §4 assertions here."
        )
        return

    if not feed_url:
        # Degraded: implemented, but this instance is not offering it. Valid
        # §2-only conformance — provided the degradation went all the way. An
        # endpoint still answering while the descriptor points nowhere is the
        # incoherent half-state a peer cannot reason about.
        assert resp.status_code != 200, (
            f"{claim['path']} serves a feed while the descriptor advertises no feed_url. A peer "
            "reads the descriptor, so this feed is unreachable by the only route §4 defines — and "
            "the node is advertising §2-only while behaving otherwise."
        )
        return

    assert resp.status_code == 200, (
        f"the descriptor advertises feed_url={feed_url!r} but {claim['path']} returned "
        f"{resp.status_code} — a pointer to nothing."
    )

    from sm_federation import read_intelligence

    ok, reason, envelopes, cursor = read_intelligence(resp.json())
    assert ok, f"the served feed page does not verify: {reason}"
    assert cursor and cursor.get("entry_hash"), "a verified page must yield a cursor to continue from"

    if envelopes:
        pytest.importorskip("jsonschema")
        from jsonschema import Draft202012Validator

        from sm_federation import wire

        validator = Draft202012Validator(wire.load_schema("intelligence-envelope"))
        for env in envelopes:
            errors = [e.message for e in validator.iter_errors(env)]
            assert not errors, f"an emitted envelope does not satisfy the published schema: {errors}"


def test_the_live_feed_supports_a_since_cursor(claims, orrery_client) -> None:
    """§4 is pull-based and idempotent: `?since=<cursor>` returns only what is new.

    A feed that ignores the cursor and re-sends everything is a snapshot with a
    query parameter.
    """
    claim = _feed_claim(claims)
    if not (claim["implemented"] and _advertised(orrery_client)):
        pytest.skip(
            "this instance advertises no feed; coherence is asserted by "
            "test_the_live_feed_serves_a_verifiable_page"
        )

    from sm_federation import read_intelligence

    first = orrery_client.get(claim["path"])
    assert first.status_code == 200
    ok, reason, _, cursor = read_intelligence(first.json())
    assert ok, reason

    again = orrery_client.get(claim["path"], params={"since": cursor["seq"]})
    assert again.status_code == 200, f"?since= returned {again.status_code}"
    ok, reason, _, _ = read_intelligence(
        again.json(), expected_prev_hash=cursor["entry_hash"], expected_head=cursor["head"]
    )
    assert ok, f"the page returned for ?since={cursor['seq']} does not continue the chain: {reason}"
