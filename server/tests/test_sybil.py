"""Sybil-ring detection over the ARP interaction graph.

RING       a mutually-complete component isolated from the honest core is flagged
ANCHOR     the honest majority (largest SCC) is never flagged
UNFORGEABLE one honest cross-edge into a ring un-flags it (the signal a ring can't fake)
DENSITY    a loose, non-near-complete component is not flagged
EDGE       empty / tiny graphs flag nothing
"""

from __future__ import annotations

from sybil import detect_sybil_rings, strongly_connected_components


def _r(issuer: str, cp: str) -> dict:
    return {"issuer_did": issuer, "action": {"counterparty_did": cp}}


def _honest_core(names: list[str]) -> list[dict]:
    """A strongly-connected honest anchor: a bidirectional cycle over `names`."""
    rs = []
    for i in range(len(names)):
        a, b = names[i], names[(i + 1) % len(names)]
        rs.append(_r(a, b))
        rs.append(_r(b, a))
    return rs


def _full_ring(names: list[str]) -> list[dict]:
    return [_r(a, b) for a in names for b in names if a != b]


def test_empty_graph_flags_nothing():
    assert detect_sybil_rings([]).flagged_dids == []


def test_isolated_ring_is_flagged():
    rs = _honest_core(["h1", "h2", "h3", "h4"]) + _full_ring(["x", "y", "z"])
    res = detect_sybil_rings(rs)
    assert res.flagged_rings == [["x", "y", "z"]]
    assert set(res.flagged_dids) == {"x", "y", "z"}
    # The honest anchor (the largest component) is never flagged.
    anchor = next(c for c in res.components if c["is_anchor"])
    assert anchor["flagged"] is False
    assert set(anchor["members"]) == {"h1", "h2", "h3", "h4"}


def test_one_honest_cross_edge_unflags_the_ring():
    """The unforgeable signal: a ring can mint perfect internal edges, but it
    cannot fabricate an honest agent choosing to transact with it."""
    rs = _honest_core(["h1", "h2", "h3", "h4"]) + _full_ring(["x", "y", "z"])
    rs.append(_r("h1", "x"))  # one honest agent engages the ring → cross-edge
    res = detect_sybil_rings(rs)
    assert res.flagged_dids == []  # no longer isolated → not a ring


def test_loose_component_not_flagged_below_density():
    # x,y,z minimally strongly connected (a 3-cycle, density 0.5) — not near-complete.
    rs = _honest_core(["h1", "h2", "h3", "h4"]) + [_r("x", "y"), _r("y", "z"), _r("z", "x")]
    res = detect_sybil_rings(rs, density=0.8)
    assert res.flagged_dids == []


def test_scc_is_deterministic():
    rs = _full_ring(["a", "b", "c"]) + [_r("c", "d")]
    assert strongly_connected_components_from(rs) == strongly_connected_components_from(list(reversed(rs)))


def strongly_connected_components_from(receipts: list[dict]):
    from sybil import build_interaction_graph

    return strongly_connected_components(build_interaction_graph(receipts))
