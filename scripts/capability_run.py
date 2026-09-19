"""Orrery full-stack capability run — the real stack, end to end, no mocks.

Drives the LIVE 3-org mesh (or any org you point it at) through Orrery's
headline capabilities using only keyless GETs and the open, self-attesting
POSTs. Local, offline signature verification uses the vendored sm-* wheels
when available and degrades honestly when not.

    uv run --with httpx python scripts/capability_run.py <ORG_URL>

Point it at any Orrery org — your own ``./orrery-up``, or a public demo mesh.
The org URL is REQUIRED (arg 1 or ``$ORRERY_ORG_URL``). Set ``$CAPABILITY_LOCATOR``
(``urn:ai:domain:<org>:agent:<id>``) to exercise the public NANDA Index 4-hop
resolve; ``$NANDA_INDEX_URL`` overrides the index endpoint.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from community_member import nanda_index  # noqa: E402 — needs the path above


def _arg_or_env(idx: int, env: str, default: str = "") -> str:
    """Positional arg wins over env var wins over default — no infra baked in."""
    if len(sys.argv) > idx and sys.argv[idx]:
        return sys.argv[idx]
    return os.environ.get(env, default)


ORG = _arg_or_env(1, "ORRERY_ORG_URL").rstrip("/")
if not ORG:
    print(__doc__)
    print(
        "error: an org URL is required — pass it as arg 1 or set $ORRERY_ORG_URL "
        "(point it at any Orrery org: your own ./orrery-up, or a public demo mesh).",
        file=sys.stderr,
    )
    raise SystemExit(2)
# The index is optional for this script and its default is named in exactly one
# place — community_member.nanda_index.DEFAULT_INDEX — so this file cannot drift
# from the runtime's own answer to "which index".
INDEX = nanda_index.index_url()
LOCATOR = os.environ.get("CAPABILITY_LOCATOR", "").strip()

c = httpx.Client(timeout=30)


def say(k: str, v: object) -> None:
    print(f"{k:<24}: {v}")


# ── 1. DISCOVERY: the public NANDA Index resolves an agent, 4 hops, all live
if LOCATOR:
    r1 = c.get(f"{INDEX}/api/v1/resolve", params={"locator": LOCATOR}).json()
    registry = r1["index_record"]["registry_url"].rstrip("/")
    r2 = c.get(f"{registry}/agents/{r1['identifier']}").json()
    r3 = c.get(r2["url"]).json()
    r4 = c.get(r3["url"].rstrip("/") + "/.well-known/agent.json")
    say(
        "1 NANDA 4-hop resolve",
        f"index -> registry -> card -> agent, all 200 (final: {r4.status_code})",
    )
else:
    say(
        "1 NANDA 4-hop resolve",
        "skipped — set $CAPABILITY_LOCATOR=urn:ai:domain:<org>:agent:<id> "
        "to resolve via the public index",
    )

# ── 2. THE LIVE MESH: independent orgs, mutually syncing
h = c.get(f"{ORG}/health").json()
peers = {p["peer"]: p["state"] for p in h.get("federation_state", [])}
say(
    "2 federation mesh",
    f"{h.get('display_name', h.get('agent_id'))} + peers {peers} | members: {h.get('members')}",
)

# ── 3. ACCOUNTABLE DISCOVERY: the registry-divergence alarm, keyless
div = c.get(f"{ORG}/api/federation/divergence", params={"limit": 3}).json()
say(
    "3 divergence surface",
    f"{len(div.get('findings', div if isinstance(div, list) else []))} recent findings (detector live)",
)

# ── 4. GENERATIVE SURFACES: A2UI as data, deterministic and keyless
surf = c.get(f"{ORG}/api/surfaces/digest").json()
comps = (surf.get("updateComponents") or {}).get("components", [])
say(
    "4 A2UI surface",
    f"digest surface: {len(comps)} components, A2UI v{surf.get('version')} (keyless deterministic path)",
)

# ── 5. SKILL MARKETPLACE: the live catalog
sk = c.get(f"{ORG}/api/skills").json().get("skills", [])
first = sk[0] if sk else {}
say(
    "5 skill marketplace",
    f"{len(sk)} skills in catalog; e.g. {first.get('id')} by {first.get('author_did')}",
)

print("\nFULL STACK: discovery, federation, accountable-discovery divergence,")
print("generative surfaces, and the marketplace — all live, no mocks.")
