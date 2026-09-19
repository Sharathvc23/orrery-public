"""Whether this org may publish itself to a registry, and where.

One decision point, consulted by every publish path. It exists because the
answer used to be spread across compose interpolation, an env default, and a
heartbeat that ignored both — and the result was **31 non-routable records in
the production NEST registry**: 27 advertising `http://localhost:…` and 4
advertising docker-internal names like `http://agent:8080`. Roughly a third of
that registry was our own dev and CI stacks, each publishing an endpoint no
caller on earth could reach.

Three independent failures produced that, and all three are fixed here:

1. **`REGISTRY_URL=` meant LIVE.** `docker-compose.yml` read
   ``${REGISTRY_URL:-https://nest.projectnanda.org}`` and shell ``:-``
   substitutes the default for an *empty* value as well as an unset one — so the
   natural way to say "no registry" resolved to production. Fixed in the code
   path (:func:`registry_url`), not only in compose, so a bare
   ``python chapter_agent.py`` with ``REGISTRY_URL=`` is safe too.

2. **`AUTO_REGISTER=false` did nothing.** It is documented in
   `docs/CONFIGURATION.md` and `docs/INSTALL.md`, passed by compose, written by
   the setup wizard, and relied on by a comment in CI — and it was never read by
   any server code. A documented off-switch that is not wired is worse than no
   switch: operators believe they opted out. :func:`auto_register_enabled` reads
   it for real.

3. **Nothing checked what was being advertised.** The other two are
   configuration mistakes, and configuration mistakes recur. This does not:
   :func:`is_publishable_endpoint` refuses to publish a record whose own
   endpoint is unreachable from the public internet. A registry entry pointing
   at ``localhost`` is dead on arrival for every consumer, so publishing one is
   never correct *whatever the configuration says* — this single rule would have
   prevented all 31 records without anyone configuring anything.

Publishing by default is deliberately PRESERVED (`docs/PRODUCT.md`: "Registration
(NEST) — auto-published on launch"). The defect was never that we publish; it
was that there was no working way not to.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

#: Kept ONLY so an operator upgrading can be told what they used to inherit. It
#: is never returned as a value: :func:`registry_url` returns "" when
#: ``REGISTRY_URL`` is unset. See that function for why.
FORMER_DEFAULT_REGISTRY_URL = "https://nest.projectnanda.org"

_FALSEY = {"0", "false", "no", "off", ""}


def registry_url() -> str:
    """The registry this org talks to, or ``""`` for "none configured".

    ⚠️ **THERE IS NO DEFAULT.** An unset ``REGISTRY_URL`` used to resolve to
    ``https://nest.projectnanda.org``, so an org that configured nothing
    contacted a registry run by somebody else — and not only to publish:
    ``reconcile_stale_agents`` queried it at boot and ``federation_discovery``
    queried it on every cycle, neither of which consults ``AUTO_REGISTER``. A
    self-hoster who had explicitly set ``AUTO_REGISTER=false`` still reached out.
    A default that points a stranger's deployment at a third party is not a
    default, it is an assumption about who they federate with.

    The empty-vs-unset fix's distinction between *unset* and *explicitly empty* is now moot for
    the value — both mean "none" — but the reasoning behind it is not: compose's
    ``${VAR:-default}`` substituting for an empty value is exactly why the
    default had to go from the CODE rather than from the compose file.

    **The known cost, stated because it is the reason this is loud:** an org that
    relied on the default stops publishing AND stops discovering peers through
    the registry, and the failure mode is quiet — "no peers found" is
    indistinguishable from "no peers exist". So every path that would have
    queried says so at the point it declines, not only at boot.
    """
    return (os.environ.get("REGISTRY_URL") or "").strip()


def auto_register_enabled() -> bool:
    """Whether this org may publish itself at all.

    ``AUTO_REGISTER`` unset means enabled (publish-by-default). Any falsey
    spelling disables *every* publish path, including the heartbeat — which is
    what "false" was always supposed to mean.
    """
    return os.environ.get("AUTO_REGISTER", "true").strip().lower() not in _FALSEY


def is_publishable_endpoint(url: str) -> tuple[bool, str]:
    """Whether ``url`` is worth putting in a public registry.

    Returns ``(publishable, reason)``. The rule is not "is this valid" but "can
    a stranger reach it": a consumer reading the registry has no access to our
    loopback interface, our docker network, or our LAN, so a record pointing
    there is dead on arrival and pure noise for everyone else.

    Rejected: loopback (``localhost``, ``127.0.0.0/8``, ``::1``), unspecified
    (``0.0.0.0``), private and link-local ranges, and single-label hostnames
    (``agent``, ``server2`` — docker-compose service names, meaningless outside
    that network).
    """
    # AgentFacts `endpoints.static` is an ARRAY (see the AgentFacts schema), and
    # `register_on_index` passes it straight through — so this gate receives a
    # list as often as a string. Treating a list as a string raised
    # `AttributeError: 'list' object has no attribute 'strip'` INSIDE the
    # lifespan startup, which crash-looped the whole org (astrocity, 2026-07-29).
    # Normalise here rather than at the call site: the empty-vs-unset fix's stated intent is "one
    # gate, so a new publish path cannot quietly skip the checks", and a gate
    # that only accepts one shape is a gate the next caller trips over.
    #
    # A record advertising several endpoints is reachable if ANY of them is, so
    # publish when any candidate passes and only block when none do.
    if isinstance(url, (list, tuple)):
        candidates = [u for u in url if isinstance(u, str) and u.strip()]
        if not candidates:
            return False, "no endpoint configured"
        reasons = []
        for candidate in candidates:
            ok, reason = is_publishable_endpoint(candidate)
            if ok:
                return True, ""
            reasons.append(reason)
        return False, f"no reachable endpoint among {len(candidates)}: {reasons[0]}"

    if not isinstance(url, str) or not url.strip():
        return False, "no endpoint configured"

    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, f"endpoint has no host: {url!r}"

    if host == "localhost" or host.endswith(".localhost"):
        return False, f"loopback endpoint {url!r} — unreachable for every registry consumer"

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if ip.is_loopback:
            return False, f"loopback endpoint {url!r} — unreachable for every registry consumer"
        if ip.is_unspecified:
            return False, f"unspecified address {url!r} — not an endpoint anyone can reach"
        if ip.is_private or ip.is_link_local:
            return False, f"private-range endpoint {url!r} — unreachable from outside this network"
        return True, ""

    if "." not in host:
        # docker-compose service names (`agent`, `server2`) and other
        # single-label hosts resolve only inside their own network.
        return False, f"single-label host {host!r} in {url!r} — resolves only on this machine/network"

    return True, ""


def publication_blocked_reason(public_url: str) -> str | None:
    """The reason this org must NOT publish, or ``None`` when it may.

    Checked in the order an operator would want to hear about: an explicit
    opt-out first (they chose it), then the endpoint guard (they probably did
    not realise).
    """
    if not auto_register_enabled():
        return "AUTO_REGISTER is false"
    if not registry_url():
        return "REGISTRY_URL is empty (registration disabled)"
    ok, reason = is_publishable_endpoint(public_url)
    if not ok:
        return reason
    return None


# ── Saying so where the absence changes behaviour ───────────────────────────
#
# Dropping the default is safe for the org and INVISIBLE to the operator, which
# is the failure this session has spent its time removing: with no registry,
# federation discovery finds nothing, and "no peers found" is indistinguishable
# from "no peers exist". A boot line alone is not enough — it scrolls past once
# and every later cycle is silent.
#
# So each path that WOULD have queried says so at the point it declines. Rate
# limited because discovery runs on a timer: a warning per cycle would be noise,
# and noise is how a real warning stops being read.

_last_declined: dict[str, float] = {}
DECLINE_NOTICE_INTERVAL_S = 900.0


def note_declined(where: str, what: str, *, now: float | None = None) -> bool:
    """Say that ``where`` skipped ``what`` for want of a registry. True if printed.

    Returns whether it actually printed so a caller can assert the notice
    happened — a silent decline is the exact thing this exists to prevent, and a
    test that could not tell printing from not-printing would not catch its
    return.
    """
    import time as _time

    stamp = float(now if now is not None else _time.time())
    last = _last_declined.get(where)
    if last is not None and stamp - last < DECLINE_NOTICE_INTERVAL_S:
        return False
    _last_declined[where] = stamp
    print(
        f"[registry] {where}: {what} SKIPPED — no REGISTRY_URL is configured, so this org "
        f"talks to no registry. This is not an error and nothing failed; it means "
        f"registry-sourced results will be EMPTY rather than missing. Set REGISTRY_URL to "
        f"opt in. (Before this version an unset REGISTRY_URL silently used "
        f"{FORMER_DEFAULT_REGISTRY_URL} — if you relied on that, set it explicitly.)",
        flush=True,
    )
    return True


def reset_decline_notices() -> None:
    """Test seam — the rate limiter is module state and would leak between tests."""
    _last_declined.clear()
