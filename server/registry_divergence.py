"""Cross-registry divergence detector — the omission/equivocation alarm.

Signed endpoint attestations make a single registry's *tampering* detectable
(the record self-certifies), but a cheating registry can still lie by
OMISSION (hide an org) or EQUIVOCATION (tell different clients different
things), and no signature on a record can prove what a registry chose not to
serve. With two or more registries configured, the next-best defense is
corroboration: ask every registry the same question and make any disagreement
loud. This is not cryptographic proof — a transparency log would be — but it
turns silent lies into logged, comparable ``federation.registry.divergence``
events.

The detection internals are the published kernel this module was extracted
into: ``sm_divergence.discovery.fetch_view`` classifies one registry's
by-id answer (present / positively-absent / error-makes-no-claim, including
NEST's soft-404 body), and ``sm_resolver.diff_claims`` is the pure
corroboration diff — the reference implementation of
draft-chandra-agent-registry-corroboration-00. Per
``docs/integrations/STELLARMINDS.md`` this module is the thin downstream
adapter over that kernel and keeps what is Orrery's: the attestation-verified
DID extraction (a ``RecordAdapter`` closure — the kernel never learns Orrery's
attestation format), the F4 sweep budgets, the F4 ``unconfirmed`` synthesis,
the finding dict shapes / event payloads, and the ``event_bus`` emission.

Watch set: this org + its federation peers (org-level records only; members
share the org endpoint). Records are fetched BY-ID from each registry — list
endpoints paginate and (on live NEST) serve a trimmed projection that strips
attestations, so per-id raw documents are the only comparable view.

Divergence kinds:
- ``omission``  — an id a registry serves that another registry confirms
  absent (HTTP 404 / "not found" body). An UNREACHABLE registry is excluded
  from the comparison entirely — a timeout is not a claim of absence.
- ``endpoint``  — registries claim different (unsigned) endpoints for the
  same id. With attestations enforced the tampered copy can't be *used*, but
  the disagreement itself is the cheating signal worth surfacing.
- ``did``       — registries serve different VALID attestations whose DIDs
  disagree — identity equivocation, the thing DID pinning defends against.

Each distinct finding is emitted once per process (deduped by fingerprint);
findings also print to the server log every time they are computed fresh.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any

import httpx
from sm_divergence import Claim, diff_claims, fetch_view

import registry_attestation

# F4: the sweep runs inside the heartbeat, so it must be bounded. Each by-id
# fetch has a per-request timeout, all fetches run concurrently (not R×N in
# series), and the whole sweep is capped by a total budget so a hanging or
# 500-stalling registry can never wedge the heartbeat.
_PER_REQUEST_TIMEOUT_S = 5.0
_TOTAL_SWEEP_BUDGET_S = 12.0

# Fingerprints of findings already emitted this process — a persisting
# divergence stays visible in the log line but doesn't re-fire the event
# every heartbeat.
_emitted: set[str] = set()


def _fingerprint(finding: dict[str, Any]) -> str:
    return json.dumps(finding, sort_keys=True)


def _view_from_record(doc: dict[str, Any], agent_id: str) -> dict[str, Any]:
    """Orrery's ``RecordAdapter``: reduce a raw registry record to the view dict.

    ``endpoint`` is the registry's (unsigned) claim; ``did`` rides in only when
    a VALID attestation for this subject is on the record —
    ``registry_attestation`` stays downstream, the kernel never sees it.
    """
    view: dict[str, Any] = {"endpoint": str(doc.get("endpoint") or "").rstrip("/")}
    att = doc.get("attestation")
    if att is not None:
        att_ok, _reason = registry_attestation.verify(att)
        if att_ok and str(att["record"].get("agent_id", "")) == agent_id:
            view["did"] = str(att["record"]["did"])
    return view


async def _fetch_view(
    client: httpx.AsyncClient, registry_url: str, agent_id: str, timeout: float = _PER_REQUEST_TIMEOUT_S
) -> tuple[str, dict[str, Any] | None]:
    """One registry's claim about one agent id, from the raw by-id record.

    Classification (``present`` / ``absent`` / ``error``, including NEST's
    soft-404 body) is the kernel's ``fetch_view``; the record→view mapping is
    Orrery's adapter closure. Never raises.
    """
    return await fetch_view(
        client,
        registry_url,
        agent_id,
        adapter=lambda doc: _view_from_record(doc, agent_id),
        timeout=timeout,
    )


class _ComparableView:
    """Wrap Orrery's plain view dict in the kernel's ``View`` contract.

    ``comparable()`` keeps Orrery's field semantics — the endpoint exactly as
    fetched (falsy values excluded), no RFC 3986 rewriting — so finding
    payloads, fingerprints, and the events built from them stay byte-compatible
    with the pre-kernel detector. (The kernel's own ``RecordView`` normalizes
    endpoints; adopting it would silently change emitted payloads.)
    """

    __slots__ = ("_view",)

    def __init__(self, view: Mapping[str, Any]) -> None:
        self._view = view

    def comparable(self) -> Mapping[str, str | None]:
        return {
            "endpoint": str(self._view["endpoint"]) if self._view.get("endpoint") else None,
            "did": str(self._view["did"]) if self._view.get("did") else None,
        }


def _finding_dict(kind: str, agent_id: str, detail: Mapping[str, Any]) -> dict[str, Any]:
    """Map a kernel ``Finding`` back to Orrery's flat finding/event shape."""
    if kind == "omission":
        return {
            "kind": "omission",
            "agent_id": agent_id,
            "present_on": list(detail["present_on"]),
            "missing_from": list(detail["missing_from"]),
        }
    if kind == "endpoint":
        return {"kind": "endpoint", "agent_id": agent_id, "endpoints": dict(detail["values"])}
    if kind == "did":
        return {"kind": "did", "agent_id": agent_id, "dids": dict(detail["values"])}
    # A kernel kind this adapter doesn't know yet (e.g. a new comparable field)
    # still surfaces rather than vanishing.
    return {"kind": kind, "agent_id": agent_id, **dict(detail)}


def diff_views(
    views: dict[str, dict[str, dict[str, Any] | None]],
    watch_ids: set[str],
    errored: dict[str, set[str]] | None = None,
) -> list[dict[str, Any]]:
    """Pure diff of per-registry views. ``views[url][id]`` is the view dict
    (present), None (confirmed absent), or the id simply missing from the
    inner dict (registry made no claim — unreachable). ``errored[url]`` is the
    set of ids that registry FAILED to answer (timeout / 500 / unparseable) —
    used to raise an ``unconfirmed`` signal instead of silence. The
    omission/endpoint/did comparison is the kernel's ``diff_claims``; the F4
    ``unconfirmed`` synthesis stays here (the kernel's diff excludes error
    claims by design). Never raises."""
    errored = errored or {}
    findings: list[dict[str, Any]] = []
    for aid in sorted(watch_ids):
        claims: list[Claim[_ComparableView]] = []
        present_on: list[str] = []
        for url, per_registry in views.items():
            if aid not in per_registry:
                continue  # no claim from this registry — not an omission
            claim = per_registry[aid]
            if claim is None:
                claims.append(Claim(url, None, "absent", None, 0.0, "absent"))
            else:
                claims.append(Claim(url, None, "present", _ComparableView(claim), 0.0, "present"))
                present_on.append(url)

        mapped = [_finding_dict(f.kind, f.agent_id, f.detail) for f in diff_claims(aid, claims)]

        # F4: a registry that ERRORED on an id a sibling serves is not silence —
        # a cheating registry can hide an omission behind a 500/timeout. Surface
        # it as `unconfirmed` (weaker than a confirmed `omission`, louder than
        # nothing) so an operator sees the gap.
        unconfirmed_on = sorted(url for url, ids in errored.items() if aid in ids)
        if present_on and unconfirmed_on:
            pos = 1 if mapped and mapped[0]["kind"] == "omission" else 0
            mapped.insert(
                pos,
                {
                    "kind": "unconfirmed",
                    "agent_id": aid,
                    "present_on": sorted(present_on),
                    "unconfirmed_on": unconfirmed_on,
                },
            )
        findings.extend(mapped)
    return findings


MIN_REGISTRIES_TO_CORROBORATE = 2


def _dedupe(registry_urls: list[str]) -> list[str]:
    """Normalised, order-preserving unique registry list."""
    urls: list[str] = []
    for u in registry_urls:
        u = (u or "").rstrip("/")
        if u and u not in urls:
            urls.append(u)
    return urls


def corroboration_status(registry_urls: list[str]) -> dict[str, Any]:
    """Whether corroboration can run at all, as a value an operator can read.

    ⚠️ **A NO-OP AND A CLEAN RESULT ARE OTHERWISE INDISTINGUISHABLE.** ``check``
    returns ``[]`` both when it compared every registry and found no
    disagreement, and when it could not compare anything because fewer than two
    registries are configured. Those are opposite facts wearing the same answer.

    That is not hypothetical. Measured on the live mesh 2026-09-13: regentix had
    ``REGISTRY_URL`` unset, so it ran with one registry and its corroboration had
    been a permanent no-op — while ``/api/federation/divergence`` returned an
    empty findings list that read exactly like "nothing wrong". Nothing surfaced
    the difference; it was found by reading ``/health`` org by org for an
    unrelated reason.

    So the status is now a value: carried on ``/health`` where operators already
    look, and returned beside the findings so an empty list is interpretable.
    """
    urls = _dedupe(registry_urls)
    active = len(urls) >= MIN_REGISTRIES_TO_CORROBORATE
    return {
        "corroborating": active,
        "registry_count": len(urls),
        "registries": urls,
        "detail": (
            f"comparing {len(urls)} registries"
            if active
            else (
                f"NOT corroborating — {len(urls)} registry configured, "
                f"{MIN_REGISTRIES_TO_CORROBORATE} needed. An empty findings list here means "
                "'nothing was compared', not 'nothing was wrong'."
            )
        ),
    }


async def check(registry_urls: list[str], watch_ids: set[str]) -> list[dict[str, Any]]:
    """Compare what every configured registry claims about the watch set.

    No-op (returns []) with fewer than two registries — there is nothing to
    corroborate against. New findings emit ``federation.registry.divergence``
    once per process; all current findings are returned and logged. Never
    raises.
    """
    # Same deduper corroboration_status() uses, so the reported status and the
    # actual behaviour cannot drift apart.
    urls = _dedupe(registry_urls)
    if len(urls) < MIN_REGISTRIES_TO_CORROBORATE or not watch_ids:
        return []

    views: dict[str, dict[str, dict[str, Any] | None]] = {url: {} for url in urls}
    errored: dict[str, set[str]] = {url: set() for url in urls}
    sorted_ids = sorted(watch_ids)

    async def _one(client: httpx.AsyncClient, url: str, aid: str) -> tuple[str, str, str]:
        status, view = await _fetch_view(client, url, aid)
        if status != "error":
            views[url][aid] = view
        return url, aid, status

    try:
        async with httpx.AsyncClient() as client:
            coros = [_one(client, url, aid) for url in urls for aid in sorted_ids]
            # All fetches run concurrently (each with its own per-request
            # timeout); the total budget is a backstop so the sweep — and thus
            # the heartbeat — can never hang. return_exceptions keeps one bad
            # fetch from cancelling the rest.
            results = await asyncio.wait_for(
                asyncio.gather(*coros, return_exceptions=True), timeout=_TOTAL_SWEEP_BUDGET_S
            )
        for r in results:
            if isinstance(r, BaseException):
                continue  # a fetch that raised: no claim, not an error-on-id we can attribute
            url, aid, status = r
            if status == "error":
                errored[url].add(aid)
    except (TimeoutError, Exception) as e:  # noqa: BLE001 — the detector must never wedge the heartbeat
        print(f"[divergence] registry sweep failed/timed out: {e}")
        # Fall through with whatever partial views were populated before the
        # budget elapsed — a partial corroboration still beats none.

    findings = diff_views(views, watch_ids, errored)
    for finding in findings:
        detail = {k: v for k, v in finding.items() if k not in ("kind", "agent_id")}
        print(
            f"  Federation: REGISTRY DIVERGENCE ({finding['kind']}) for "
            f"{finding['agent_id']!r}: {json.dumps(detail, sort_keys=True)}"
        )
        fp = _fingerprint(finding)
        if fp in _emitted:
            continue
        _emitted.add(fp)
        try:
            import event_bus

            await event_bus.safe_publish("federation.registry.divergence", finding)
        except ImportError:
            pass
    return findings
