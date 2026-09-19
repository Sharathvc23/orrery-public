#!/usr/bin/env python3
"""Resolve an org friendly-name (slug) to its endpoint URL via a registry.

Name-based discovery resolves a short slug (``join bayarea``) to an org's
endpoint via a registry **the user configured**. There is no default registry:
with neither ``REGISTRY_URL`` (preferred — the same name the org server and the
sovereign agent read) nor ``ORRERY_REGISTRY_URL`` set, slug discovery is off and
the helper says so by name. You can always reach an org directly by URL
(``join https://your-org.example.com``), which needs no registry at all.

Why no default: a skill that queried a public directory whenever a user typed a
short name would contact a third party on the user's behalf without the user
ever naming it. NANDA's registry is a discovery integration this helper can be
pointed at, not a dependency it reaches for.

The skill ships no hardcoded org→URL table. When a registry is
configured, discovery is dynamic: ask the registry at runtime, filter
to entries that are actually orgs by probing ``/health.slug``, and
return the endpoint matching the requested slug.

Usage (from the OpenClaw agent's tool-call)::

    ORRERY_REGISTRY_URL=https://registry.example.com \
        python helpers/discover_org.py myorg
    # → {"slug":"myorg","agent_id":"...","endpoint":"https://...",
    #    "display_name":"My Org"}

    python helpers/discover_org.py            # list every org
    # → {"orgs":[{"slug":"myorg","agent_id":...,"endpoint":...}, ...]}

Errors go to stderr; exit code is non-zero on failure.

Discovery algorithm (when a registry is configured):

  1. Paginate through GET ``$ORRERY_REGISTRY_URL/api/agents``.
  2. Strip any ``skill-`` id prefix some registries add.
  3. Heuristic: keep only agent_ids ending in ``-org`` or ``-agent``.
     Reduces the full list to a small candidate set.
  4. Drop entries with no endpoint (cannot route to them).
  5. /health probe: GET each candidate's /health and require a non-empty
     ``slug`` field. Orgs declare this; non-org agents that
     happen to share the suffix don't. The org's own /health.slug
     wins over any client-side derivation — operators control identity.
  6. KNOWN_ORGS pin: orgs listed in ``KNOWN_ORGS`` below MUST present
     the expected did:key in /health.did_key; otherwise they are
     dropped, even if /health.slug matches. This blocks slug
     collision / squatting on well-known names.
  7. Ambiguity rejection: if two distinct endpoints both claim the
     same slug, the slug is REMOVED from the result rather than
     resolving to a coin-flip winner. Users see "ambiguous slug" and
     can address by full URL.

A 30-second HMAC-SIGNED cache lives at
``$OPENCLAW_HOME/skills/orrery-org/org-cache.json``. The MAC
is keyed on the agent's identity private key so an attacker who can
write the cache file cannot poison the allowlist that
``sign_request.py`` consults. See helpers/_cache_signing.py.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

PAGE_LIMIT = 200
HTTP_TIMEOUT = 10.0
CACHE_TTL_SECONDS = 30

# Pinned did:keys for orgs with well-known slugs. Discovery refuses
# to resolve these slugs to any endpoint whose /health.did_key does
# not match. Empty by default; adding an entry is a deliberate trust
# decision for an operator running a shared registry, not a discovery
# affordance.
KNOWN_ORGS: dict[str, str] = {
    # Example shape: "myorg": "did:key:z6Mk..."
}


def _registry_url() -> str:
    """The registry base URL for slug discovery (no trailing slash), or ``""``.

    ⚠️ NO DEFAULT. ``REGISTRY_URL`` wins when set (even when set empty — an
    explicit empty means "off"); otherwise ``ORRERY_REGISTRY_URL``; otherwise
    empty, which the caller reports as ``no_registry_configured``.
    """
    raw = os.environ.get("REGISTRY_URL")
    if raw is None:
        raw = os.environ.get("ORRERY_REGISTRY_URL", "")
    return raw.strip().rstrip("/")


def _resolve_openclaw_home() -> Path:
    """Same validation contract as sign_request.py — refuses
    ``$OPENCLAW_HOME`` that resolves outside the calling user's home.
    """
    raw = os.environ.get("OPENCLAW_HOME", str(Path.home() / ".openclaw"))
    candidate = Path(raw).expanduser().resolve()
    home = Path.home().resolve()
    try:
        candidate.relative_to(home)
    except ValueError:
        print(
            json.dumps(
                {
                    "error": "openclaw_home_outside_user_home",
                    "openclaw_home": str(candidate),
                    "user_home": str(home),
                    "detail": (
                        "$OPENCLAW_HOME must resolve under the calling "
                        "user's home directory. Refusing to start."
                    ),
                }
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    return candidate


OPENCLAW_HOME = _resolve_openclaw_home()
SKILL_DIR = OPENCLAW_HOME / "skills" / "orrery-org"
IDENTITY_FILE = SKILL_DIR / "identity.json"


def _cache_path() -> Path:
    SKILL_DIR.mkdir(parents=True, exist_ok=True)
    return SKILL_DIR / "org-cache.json"


def _load_cache() -> list[dict[str, Any]] | None:
    """Return the cached org list, or None if cache is missing /
    expired / unsigned / MAC-invalid. See helpers/_cache_signing.py
    for the verification contract.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _cache_signing import load_signed_cache

    return load_signed_cache(_cache_path(), IDENTITY_FILE)


def _save_cache(orgs: list[dict[str, Any]]) -> None:
    """Write a HMAC-signed, 0o600 cache file. Best-effort — a write
    failure does NOT raise; the skill works without the cache (just
    re-queries the registry on the next call)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _cache_signing import write_signed_cache

    try:
        write_signed_cache(
            _cache_path(),
            IDENTITY_FILE,
            orgs=orgs,
            expires_at=int(time.time()) + CACHE_TTL_SECONDS,
        )
    except OSError:
        pass


def strip_skill_prefix(raw_id: str) -> str:
    """Some registries prefix ids with `skill-`; strip for matching."""
    return raw_id[len("skill-") :] if raw_id.startswith("skill-") else raw_id


def derive_org_slug(agent_id: str) -> str:
    """Best-effort slug derivation when /health is unreachable.

    The org's own /health.slug wins (see filter_to_orgs). This
    derivation is the fallback used to seed the candidate list; if
    /health is reachable the declared value overrides.
    """
    s = agent_id.lower()
    for suffix in ("-org", "-agent"):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            break
    return s or agent_id


def looks_like_org(agent_id: str) -> bool:
    """Heuristic — org naming convention vs. member agents."""
    s = agent_id.lower()
    return s.endswith("-org") or s.endswith("-agent")


def fetch_all_registry_agents(client: httpx.Client) -> list[dict[str, Any]]:
    """Paginate through every registry entry (org + member alike)."""
    registry = _registry_url()
    out: list[dict[str, Any]] = []
    page = 1
    while True:
        resp = client.get(
            f"{registry}/api/agents",
            params={"page": page, "limit": PAGE_LIMIT},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        agents = data.get("agents", []) if isinstance(data, dict) else data
        if not agents:
            break
        out.extend(agents)
        pagination = data.get("pagination", {}) if isinstance(data, dict) else {}
        if not pagination.get("hasNext"):
            break
        page += 1
        if page > 200:  # safety cap
            break
    return out


def filter_to_orgs(
    agents: list[dict[str, Any]],
    *,
    fast: bool = False,
    client: httpx.Client | None = None,
) -> list[dict[str, Any]]:
    """Reduce a registry list to org records with slug + endpoint.

    Two-pass filter:

      1. Heuristic — keep only agent_ids ending in ``-org`` or
         ``-agent``. Reduces a large registry to a small candidate
         set. Common convention but too loose on its own (unrelated
         agents like `echo-agent` end in -agent too).
      2. /health probe — GET each candidate's /health and require a
         non-empty ``slug`` field. Orgs declare slug as part of their
         /health contract; non-org agents don't have this field. This
         is the actual contract for "is this an org."

    Pass ``fast=True`` to skip the /health probe and trust the
    heuristic alone — used by the cache-rebuild path when registry
    pagination is the bottleneck. False positives may surface as
    cache entries the agent will rediscover when it tries to use
    them; harmless but noisy.

    After the /health probe:

      a. KNOWN_ORGS pin — pinned slugs MUST present the expected
         did_key in /health.did_key or they are dropped.
      b. Ambiguity rejection — if two distinct endpoints claim the
         same slug, the slug is removed entirely. Users must address
         by full URL rather than getting a coin-flip resolution.
    """
    candidates: list[dict[str, Any]] = []
    for agent in agents:
        agent_id = strip_skill_prefix(str(agent.get("id", "")))
        if not looks_like_org(agent_id):
            continue
        endpoint = agent.get("endpoint", "")
        if not endpoint:
            continue
        candidates.append(
            {
                "slug": derive_org_slug(agent_id),
                "agent_id": agent_id,
                "endpoint": endpoint,
                "display_name": agent.get("name") or agent_id,
                "description": agent.get("description", ""),
            }
        )

    if fast or client is None:
        return _reject_ambiguous_slugs(candidates)

    # /health probe — trust the org's own declared slug + display_name
    # + did_key. An entry without /health.slug is not an org and
    # gets dropped from the result.
    confirmed: list[dict[str, Any]] = []
    for org in candidates:
        try:
            health = client.get(f"{org['endpoint']}/health", timeout=HTTP_TIMEOUT).json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError):
            continue
        declared_slug = health.get("slug")
        if not declared_slug:
            continue  # not an org — heuristic false positive
        org["slug"] = declared_slug
        if health.get("display_name"):
            org["display_name"] = health["display_name"]
        if health.get("did_key"):
            org["did_key"] = health["did_key"]

        # KNOWN_ORGS pin — refuse to accept an org that claims a
        # well-known slug under a different did_key.
        pinned = KNOWN_ORGS.get(declared_slug)
        if pinned and org.get("did_key") != pinned:
            continue

        confirmed.append(org)

    return _reject_ambiguous_slugs(confirmed)


def _reject_ambiguous_slugs(orgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """If two endpoints claim the same slug, drop the slug entirely.

    Users see no resolution rather than a coin-flip winner. We do not
    silently pick one — that's how slug-squatting attacks become
    successful in practice.

    All surviving records have their externally-supplied string fields
    sanitized — control-character / RTL-override / lookalike attacks
    against display_name and description are stripped here so cached
    records are LLM-safe by construction (M6 / A5).
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _sanitize import sanitize_org_record

    by_slug: dict[str, list[dict[str, Any]]] = {}
    for org in orgs:
        by_slug.setdefault(org["slug"], []).append(org)
    out: list[dict[str, Any]] = []
    for _slug, entries in by_slug.items():
        # Distinct by endpoint — multiple registry rows for the SAME
        # endpoint are merged silently (registries occasionally double-list).
        unique_endpoints = {e["endpoint"] for e in entries}
        if len(unique_endpoints) <= 1:
            out.append(sanitize_org_record(entries[0]))
    return out


def list_orgs(*, fast: bool = False, force_refresh: bool = False) -> list[dict[str, Any]]:
    """Return every org in the configured registry. Cached 30s unless --refresh.

    ``fast=True`` skips the /health probe (heuristic-only); see
    ``filter_to_orgs`` for the tradeoff. Default does the probe.
    """
    if not force_refresh:
        cached = _load_cache()
        if cached is not None:
            return cached
    with httpx.Client(follow_redirects=False) as client:
        agents = fetch_all_registry_agents(client)
        orgs = filter_to_orgs(agents, fast=fast, client=client)
    _save_cache(orgs)
    return orgs


def find_org(slug: str, **kwargs: Any) -> dict[str, Any] | None:
    """Return the org matching ``slug``, or None if not found."""
    target = slug.lower().strip()
    for org in list_orgs(**kwargs):
        if org["slug"] == target:
            return org
    return None


def _no_registry_error() -> int:
    """Print the 'discovery is disabled' guidance and return exit code 2."""
    print(
        json.dumps(
            {
                "error": "no_registry_configured",
                "hint": (
                    "This skill has no org registry configured, so name-based "
                    "discovery is off — there is no default registry. Join your org "
                    "directly by URL, e.g. `join http://localhost:7000` or "
                    "`join https://your-org.example.com`. To enable slug discovery, set "
                    "REGISTRY_URL (or ORRERY_REGISTRY_URL) to a registry endpoint."
                ),
            }
        ),
        file=sys.stderr,
    )
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("slug", nargs="?", help="Org slug to resolve. Omit to list all.")
    ap.add_argument(
        "--fast",
        action="store_true",
        help=(
            "Skip the /health probe — return heuristic matches directly. "
            "Faster but may include non-org agents that happen to have "
            "an org-shaped agent_id."
        ),
    )
    ap.add_argument(
        "--refresh",
        action="store_true",
        help="Bypass the 30s cache and re-query the registry.",
    )
    args = ap.parse_args()

    if not _registry_url():
        return _no_registry_error()

    try:
        if args.slug is None:
            orgs = list_orgs(fast=args.fast, force_refresh=args.refresh)
            print(json.dumps({"orgs": orgs}))
            return 0

        org = find_org(args.slug, fast=args.fast, force_refresh=args.refresh)
        if org is None:
            available = [o["slug"] for o in list_orgs()]
            print(
                json.dumps(
                    {
                        "error": "org_not_found",
                        "slug": args.slug,
                        "available": available,
                    }
                )
            )
            return 2

        print(json.dumps(org))
        return 0
    except httpx.HTTPError as e:
        print(json.dumps({"error": "registry_unreachable", "detail": str(e)}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
