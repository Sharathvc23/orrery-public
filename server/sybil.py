"""Sybil-ring detection over the ARP interaction graph (topology analysis).

Reputation is
relational: an agent earns standing by being *chosen* by others. A Sybil ring
games this by minting mutually-signed receipts among its own members — every
receipt is cryptographically perfect, yet the reputation is self-referential. We
build the directed interaction graph from receipts and flag components that are
mutually near-complete but ISOLATED from the honest core (the anchor set). A ring
can forge unlimited internal edges, but it cannot fabricate an honest agent
choosing to transact with it — that missing cross-edge is the unforgeable signal.

This complements the scoring path (``activity_tracker`` increments standing,
``governance.compute_trust_score`` ranks it): scoring ranks, this names the
rings. The old ``reputation.py`` it used to name was removed in that change as
superseded — the function survives, the module does not.
Pure functions over a list of receipt dicts. Deterministic (sorted throughout).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def build_interaction_graph(receipts: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Directed weighted graph of who engaged whom: issuer_did -> counterparty_did,
    weighted by receipt count. Any receipt that names a counterparty contributes."""
    graph: dict[str, dict[str, int]] = {}
    for r in receipts:
        src = r.get("issuer_did")
        dst = (r.get("action") or {}).get("counterparty_did")
        if not src or not dst or src == dst:
            continue
        graph.setdefault(src, {})
        graph.setdefault(dst, {})
        graph[src][dst] = graph[src].get(dst, 0) + 1
    return graph


def strongly_connected_components(graph: dict[str, dict[str, int]]) -> list[list[str]]:
    """Tarjan's SCC, fully deterministic: neighbours and roots visited in sorted
    order; each component sorted; components sorted by smallest member."""
    index_of: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    counter = [0]
    out: list[list[str]] = []

    def strongconnect(v: str) -> None:
        index_of[v] = counter[0]
        low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in sorted(graph.get(v, {})):
            if w not in index_of:
                strongconnect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index_of[w])
        if low[v] == index_of[v]:
            comp: list[str] = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            out.append(sorted(comp))

    for v in sorted(graph):
        if v not in index_of:
            strongconnect(v)
    return sorted(out, key=lambda c: c[0] if c else "")


def _internal_density(graph: dict[str, dict[str, int]], members: set[str]) -> float:
    """Distinct intra-component directed edges / possible directed edges."""
    n = len(members)
    if n < 2:
        return 0.0
    edges = sum(1 for s in members for d in graph.get(s, {}) if d in members and d != s)
    return edges / (n * (n - 1))


def _cross_edges(graph: dict[str, dict[str, int]], comp: set[str], other: set[str]) -> int:
    """Directed edges in either direction between ``comp`` and ``other``."""
    outbound = sum(1 for s in comp for d in graph.get(s, {}) if d in other)
    inbound = sum(1 for s in other for d in graph.get(s, {}) if d in comp)
    return outbound + inbound


@dataclass
class SybilAnalysis:
    components: list[dict[str, Any]]
    flagged_dids: list[str]
    flagged_rings: list[list[str]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "components": self.components,
            "flagged_rings": self.flagged_rings,
            "flagged_dids": self.flagged_dids,
        }


def detect_sybil_rings(receipts: list[dict[str, Any]], *, min_ring: int = 3, density: float = 0.8) -> SybilAnalysis:
    """Flag mutually near-complete components isolated from the honest core.

    The anchor set is the largest SCC (honest majority); ties broken by the
    lexicographically smallest membership. A component is a Sybil ring iff it is
    not the anchor, has zero cross-edges to the anchor (isolated), is at least
    ``density``-complete internally, and has at least ``min_ring`` members.
    """
    graph = build_interaction_graph(receipts)
    comps = strongly_connected_components(graph)
    if comps:
        max_len = max(len(c) for c in comps)
        anchor = set(sorted([c for c in comps if len(c) == max_len])[0])
    else:
        anchor = set()

    components: list[dict[str, Any]] = []
    flagged_dids: list[str] = []
    flagged_rings: list[list[str]] = []
    for comp in comps:
        cs = set(comp)
        is_anchor = cs == anchor
        dens = _internal_density(graph, cs)
        isolated = (not is_anchor) and _cross_edges(graph, cs, anchor) == 0
        flag = (not is_anchor) and isolated and dens >= density and len(cs) >= min_ring
        components.append(
            {
                "members": sorted(comp),
                "size": len(cs),
                "density": round(dens, 3),
                "is_anchor": is_anchor,
                "isolated_from_anchor": isolated,
                "flagged": flag,
            }
        )
        if flag:
            flagged_rings.append(sorted(comp))
            flagged_dids.extend(sorted(comp))

    return SybilAnalysis(
        components=components,
        flagged_dids=sorted(flagged_dids),
        flagged_rings=flagged_rings,
    )
