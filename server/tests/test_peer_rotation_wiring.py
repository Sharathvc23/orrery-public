"""§8.5 wiring: Orrery must PUBLISH its chain and PULL a peer's on mismatch.

Before this, `federation_policy.verify_rotation_attestation` existed with nine
refusal tests and **nothing called it** — no endpoint, and `check_and_pin_did`
never consulted it. Orrery had built the half that needs no agreement between
peers (verification) and left the half that does (transport) unbuilt, so H9's
live symptom persisted: a legitimately-rotating peer stayed isolated until an
operator ran `clear_did_pin`.

These tests cover the transport. The verification semantics are covered against
the shipped umbrella vectors in test_h9_rotation_attestation.py.
"""

from __future__ import annotations

import base64

import jcs
import nacl.signing
import pytest

import federation_policy as fp


def _identity():
    sk = nacl.signing.SigningKey.generate()
    import sovereign_identity

    did = sovereign_identity.build_did_key_from_ed25519(base64.b64encode(bytes(sk.verify_key)).decode())
    return sk, did


def _att(sk, *, peer, old, new, issued):
    a = {
        "type": fp.ROTATION_TYPE,
        "peer_chapter_id": peer,
        "old_did": old,
        "new_did": new,
        "issued_at": issued,
    }
    a["signature"] = base64.b64encode(sk.sign(jcs.canonicalize({k: v for k, v in a.items()})).signature).decode()
    return a


# ── publication (§8.5.2) ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_published_chain_is_empty_and_valid_before_any_rotation(monkeypatch):
    """An empty list is a valid chain, not an error. A peer walking it from a
    matching pin simply finds nothing to apply."""
    monkeypatch.setattr(fp, "_pg_request", None, raising=False)
    assert await fp.published_rotation_chain() == []


@pytest.mark.asyncio
async def test_published_chain_survives_a_missing_table(monkeypatch):
    """A pre-migration schema must not 500 the well-known endpoint. A peer that
    cannot fetch keeps its pin — degraded, not broken."""

    async def boom(*a, **k):
        raise RuntimeError("relation chapter_key_rotations does not exist")

    monkeypatch.setattr(fp, "_pg_request", boom, raising=False)
    assert await fp.published_rotation_chain() == []


def test_well_known_route_is_registered_and_public():
    """§8.5.2 requires it unauthenticated: a peer needs it precisely when it
    CANNOT verify our signatures, so any auth we demanded would be auth it
    cannot satisfy."""
    import chapter_agent

    paths = {r.path for r in chapter_agent.app.routes if hasattr(r, "path")}
    assert "/.well-known/nanda-chapter-rotation.json" in paths
    # The public-CORS prefix list must cover it, or a browser-side peer check
    # would fail on a route that is public by design.
    assert any("/.well-known/".startswith(p) or p == "/.well-known/" for p in chapter_agent._PUBLIC_CORS_PREFIXES)


# ── the pull, on mismatch (§8.5.2 + §8.5.3) ─────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_returns_none_when_peer_publishes_nothing(monkeypatch):
    """Absent/unreachable/malformed is not an error to route around — the caller
    keeps its pin, which is today's fail-closed behaviour."""
    assert await fp.fetch_peer_rotation_chain("") is None


@pytest.mark.asyncio
async def test_accept_requires_the_chain_to_reach_the_ATTESTED_did(monkeypatch):
    """ADVERSARIAL: an internally-valid chain that lands on a third key must not
    be accepted — it would pin a key neither party is presenting."""
    old_sk, old_did = _identity()
    _, mid_did = _identity()
    _, other_did = _identity()
    chain = [_att(old_sk, peer="p", old=old_did, new=mid_did, issued=1785000000)]

    async def fake_fetch(endpoint, **k):
        return chain

    monkeypatch.setattr(fp, "fetch_peer_rotation_chain", fake_fetch)
    # Widen the freshness window so this test isolates the reach check. Without
    # it the fixed issued_at is stale against the real clock and the refusal
    # comes from R6 instead — which is correct behaviour, and is asserted in
    # its own right by the shipped-vector suite.
    monkeypatch.setattr(fp, "ROTATION_MAX_AGE_S", 10**9, raising=False)
    ok, why = await fp.try_accept_peer_rotation(
        "p", attested_did=other_did, pinned_did=old_did, peer_endpoint="https://peer.example"
    )
    assert not ok and why == "chain_does_not_reach_attested_did"


@pytest.mark.asyncio
async def test_accept_succeeds_on_a_valid_chain_to_the_attested_did(monkeypatch):
    old_sk, old_did = _identity()
    _, new_did = _identity()
    chain = [_att(old_sk, peer="p", old=old_did, new=new_did, issued=1785000000)]

    async def fake_fetch(endpoint, **k):
        return chain

    monkeypatch.setattr(fp, "fetch_peer_rotation_chain", fake_fetch)
    monkeypatch.setattr(fp, "ROTATION_MAX_AGE_S", 10**9, raising=False)
    ok, why = await fp.try_accept_peer_rotation(
        "p", attested_did=new_did, pinned_did=old_did, peer_endpoint="https://peer.example"
    )
    assert ok and why == "ok"


@pytest.mark.asyncio
async def test_no_endpoint_means_no_pull_and_the_pin_stands(monkeypatch):
    """A peer we cannot reach cannot prove anything. Keep the pin."""
    _, old_did = _identity()
    _, new_did = _identity()
    ok, why = await fp.try_accept_peer_rotation("p", attested_did=new_did, pinned_did=old_did, peer_endpoint=None)
    assert not ok and why == "no_endpoint_to_pull_from"


@pytest.mark.asyncio
async def test_a_peer_that_publishes_nothing_keeps_our_pin(monkeypatch):
    """THE MIXED-MESH CASE. A peer below v0.6 has never heard of §8.5 and serves
    no chain. We must fall back to keeping the pin — today's behaviour — rather
    than treating the absence as permission."""
    _, old_did = _identity()
    _, new_did = _identity()

    async def no_chain(endpoint, **k):
        return None

    monkeypatch.setattr(fp, "fetch_peer_rotation_chain", no_chain)
    ok, why = await fp.try_accept_peer_rotation(
        "p", attested_did=new_did, pinned_did=old_did, peer_endpoint="https://old-peer.example"
    )
    assert not ok and why == "no_chain_published"
