"""
Federation Discovery — find and communicate with peer chapter agents.

Discovers other chapters via KNOWN_CHAPTER_ENDPOINTS env var + NEST registry.
Health-checks endpoints in parallel, tracks failures, removes stale chapters.
"""

import asyncio
import os
import uuid
from typing import Any

import httpx

import env_flags
import registry_attestation
import registry_policy

_registry_url = ""
_agent_id = ""
_public_url = ""
_federation: dict = {}
_federation_failures: dict[str, int] = {}
MAX_FEDERATION_FAILURES = 3


def require_signed_records() -> bool:
    """Whether an unsolicited registry record WITHOUT a valid endpoint
    attestation is skipped entirely (fail-closed).

    Default **ON**, mirroring ``federation_signing.enforcement_enabled``. It
    defaulted OFF for the warn-then-enforce cutover so un-upgraded peers kept
    federating; that window closed on 2026-07-20. Unset, empty and unrecognised
    all read as enforcing (``env_flags.security_flag``) — an operator re-opens
    warn-only mode with an explicit falsey value.

    KNOWN_CHAPTER_ENDPOINTS allowlist peers are exempt either way: the operator
    anchored those out-of-band."""
    return env_flags.security_flag("FEDERATION_REQUIRE_SIGNED_RECORDS", default=True)


def directory_urls() -> list[str]:
    """Federation-directory base URLs (``FEDERATION_DIRECTORY_URLS``, comma-
    separated) — additional, curated peer sources, e.g. a lean-index
    deployment orgs publish their attested records to. Empty (the default)
    disables directory consumption entirely. These are also legs of the
    cross-registry divergence detector."""
    out: list[str] = []
    for u in os.environ.get("FEDERATION_DIRECTORY_URLS", "").split(","):
        u = u.strip().rstrip("/")
        if u and u not in out:
            out.append(u)
    return out


# Probe-volume bound for directory-sourced peers per sweep — a hostile or
# bloated directory must not turn discovery into a scan amplifier. Overflow is
# logged (no silent caps) and retried on later cycles.
_DIRECTORY_PROBE_CAP = 25


def init(registry_url, agent_id, public_url, federation_dict, federation_failures):
    global _registry_url, _agent_id, _public_url, _federation, _federation_failures
    _registry_url = registry_url
    _agent_id = agent_id
    _public_url = public_url
    _federation = federation_dict
    _federation_failures = federation_failures


async def _check_chapter_endpoint(client: httpx.AsyncClient, ep: str) -> tuple[str, dict] | None:
    """Health-check a single endpoint. Returns (chapter_id, info) or None.

    A peer qualifies STRUCTURALLY — its /health must look like an org server
    (carries both ``agent_id`` and ``members``) — not by name. Gating on
    name substrings ("chapter"/"nanda") silently rejected any org that
    wasn't named like the original chapter deployments, so two orgs named
    e.g. ``acme`` and ``globex`` could never federate.
    """
    try:
        health = await client.get(f"{ep}/health", timeout=10.0)
        if health.status_code == 200:
            hdata = health.json()
            if not isinstance(hdata, dict) or "agent_id" not in hdata or "members" not in hdata:
                return None  # reachable, but not an org server's health surface
            chapter_id = str(hdata["agent_id"])
            if not chapter_id or chapter_id == _agent_id:
                return None  # never federate with self (even via an alias URL)
            return (
                chapter_id,
                {
                    "name": hdata.get("display_name") or chapter_id.replace("-", " ").replace("TEST ", "").title(),
                    "endpoint": ep,
                    "focus": "",
                    "status": "online",
                    "members": hdata.get("members", 0),
                },
            )
    except Exception:
        pass
    return None


async def _fetch_record_attestation(client: httpx.AsyncClient, chapter_id: str, endpoint: str) -> str | None:
    """Verify the endpoint attestation on the peer's RAW registry record.

    NEST's list endpoint serves a trimmed camelCase projection that strips
    unknown fields — attestations stored on the document never appear in
    ``GET /api/agents``, only in the by-id ``GET /api/agents/{id}``. So when
    the list pass yields no attestation for a discovered peer, fetch the raw
    record once and verify from there.

    Returns the signer DID iff the attestation verifies, its subject is this
    chapter_id, and it attests the endpoint we are already connected to —
    anything else (missing, invalid, re-dressed, or pointing elsewhere) is
    None, never an exception.
    """
    if not _registry_url:
        return None
    try:
        resp = await client.get(f"{_registry_url}/api/agents/{chapter_id}", timeout=10.0)
        if resp.status_code != 200:
            return None
        doc = resp.json()
        att = doc.get("attestation") if isinstance(doc, dict) else None
        if att is None:
            return None
        att_ok, reason = registry_attestation.verify(att)
        if not att_ok:
            print(f"  Federation: invalid attestation on registry record {chapter_id!r}: {reason}")
            return None
        rec = att["record"]
        if str(rec.get("agent_id", "")) != chapter_id:
            return None
        if str(rec.get("endpoint", "")).rstrip("/") != endpoint.rstrip("/"):
            # The peer signed a DIFFERENT endpoint than the one we're talking
            # to. For an allowlisted peer that's an operator-vs-peer conflict
            # worth surfacing, not silently pinning through.
            print(
                f"  Federation: attestation for {chapter_id!r} attests "
                f"{rec.get('endpoint')!r}, not the connected endpoint {endpoint!r} — not pinning"
            )
            return None
        return str(rec["did"])
    except Exception:
        return None


async def discover() -> None:
    """Discover federation chapters via NEST + known endpoints."""
    try:
        async with httpx.AsyncClient() as client:
            # NEST is one *source* of peers, not a precondition: an explicit
            # KNOWN_CHAPTER_ENDPOINTS allowlist must keep working when the
            # registry is down or unset.
            agents: list = []
            # ⚠️ GUARDED. This call had NO `_registry_url` check — with the value
            # empty it would build the RELATIVE url "/api/agents" and attempt it,
            # so "the paths are all gated on truthiness" was false here. Found by
            # driving it with a recording client rather than by reading the guard
            # two functions further down (which does exist, on a different call).
            if _registry_url:
                try:
                    resp = await client.get(f"{_registry_url}/api/agents", timeout=10.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        agents = data.get("agents", data) if isinstance(data, dict) else data
                except Exception:
                    pass
            else:
                # Said at the point of declining, not only at boot: discovery runs
                # on a timer, and without this an operator sees "0 peers" forever
                # with nothing distinguishing "found none" from "did not look".
                registry_policy.note_declined("federation discovery", "registry peer lookup")

            known_chapters_env = os.environ.get("KNOWN_CHAPTER_ENDPOINTS", "")
            if known_chapters_env:
                known_chapters = [ep.strip() for ep in known_chapters_env.split(",") if ep.strip()]
            else:
                # OSS default: no hardcoded peers. Federation peers come from real
                # NEST discovery or an explicit KNOWN_CHAPTER_ENDPOINTS allowlist —
                # never from the bundled orgs.json demo deployments.
                known_chapters = []

            seen_endpoints: set[str] = set()
            my_endpoint = _public_url.rstrip("/") if _public_url else ""
            endpoints_to_check: list[str] = []

            for ep in known_chapters:
                ep = ep.rstrip("/")
                if ep != my_endpoint:
                    seen_endpoints.add(ep)
                    endpoints_to_check.append(ep)

            # Snapshot of the operator allowlist — attested registry records
            # pointing at these endpoints are verified even though the
            # endpoints are already queued for probing, so allowlisted peers
            # get DID pins too (the allowlist anchors WHERE we connect; the
            # attestation supplies WHICH key is the peer's — orthogonal).
            allowlist_endpoints = set(seen_endpoints)

            # Self-certifying records: an attested registry record carries a
            # {record, sig} envelope signed by the publishing org's did:key.
            # A valid attestation makes the ENDPOINT trustworthy even when the
            # registry is not — we probe the endpoint the org signed, not the
            # unsigned copy the registry serves, and remember the signer DID
            # so later verification can bypass the endpoint's did.json.
            enforcing = require_signed_records()
            attested_dids: dict[str, str] = {}  # verified endpoint → signer DID
            unattested_candidates = 0

            for agent in agents:
                # Probe-volume bound for UNSOLICITED registry records only (NEST
                # lists thousands of member agents; don't blanket health-probe
                # them). Explicit KNOWN_CHAPTER_ENDPOINTS peers skip this filter,
                # and the post-probe check is structural (org-shaped /health),
                # not name-based. Any host/domain is eligible. An attestation
                # does NOT bypass this bound — signatures are self-minted, so
                # they prove endpoint integrity, not probe-worthiness. Attested
                # records aimed at an ALLOWLISTED endpoint are still verified
                # (cheap, no probe) so the peer's DID gets pinned; org names
                # like "acme" never match the substring filter, and the
                # allowlist dedup below would otherwise skip them entirely.
                reg_ep = (agent.get("endpoint") or "").rstrip("/")
                att = agent.get("attestation")
                rec_id = str(agent.get("agent_id") or agent.get("name") or "").lower()
                org_shaped_id = "chapter" in rec_id or "nanda" in rec_id or "org" in rec_id
                if not org_shaped_id and not (att is not None and reg_ep in allowlist_endpoints):
                    continue

                ep = reg_ep
                att_ok = False
                if att is not None:
                    att_ok, reason = registry_attestation.verify(att)
                    if att_ok:
                        # The attestation must be FOR this record — a registry
                        # can't dress record B in org A's valid attestation.
                        subject = str(att["record"].get("agent_id", ""))
                        reg_id = str(agent.get("agent_id") or "")
                        if reg_id and subject and reg_id != subject:
                            att_ok, reason = False, "subject_mismatch"
                    if att_ok:
                        attested_ep = str(att["record"]["endpoint"]).rstrip("/")
                        if reg_ep and reg_ep != attested_ep:
                            # The cheating-registry signal: the registry serves
                            # an endpoint the org never signed.
                            print(
                                f"  Federation: registry endpoint for {rec_id!r} differs from its signed "
                                f"attestation ({reg_ep} != {attested_ep}) — using the attested endpoint"
                            )
                        ep = attested_ep
                    else:
                        print(f"  Federation: invalid endpoint attestation on registry record {rec_id!r}: {reason}")

                if att_ok and ep:
                    # Record the verified DID BEFORE the dedup below — an
                    # allowlisted peer's endpoint is already queued for
                    # probing, but its pin must still land.
                    attested_dids[ep] = str(att["record"]["did"])
                if not ep or ep == my_endpoint or ep in seen_endpoints:
                    continue
                if not org_shaped_id:
                    continue  # probe-volume bound: attested-but-unsolicited stays unprobed
                if not att_ok:
                    unattested_candidates += 1
                    if enforcing:
                        continue
                seen_endpoints.add(ep)
                endpoints_to_check.append(ep)

            if unattested_candidates:
                mode = (
                    "skipped (FEDERATION_REQUIRE_SIGNED_RECORDS=on)"
                    if enforcing
                    else "probed unverified (FEDERATION_REQUIRE_SIGNED_RECORDS=off)"
                )
                print(f"  Federation: {unattested_candidates} registry record(s) without a valid attestation — {mode}")

            # ── Federation directory: additional, curated peer sources.
            # Unlike NEST (a global agent index with a probe-volume name
            # filter), a directory record is only ever admitted with a VALID
            # self-certifying attestation (that change–that change scheme, verbatim) — this
            # surface is born fail-closed regardless of
            # FEDERATION_REQUIRE_SIGNED_RECORDS, which keeps governing the
            # legacy NEST path unchanged. The endpoint probed is the one the
            # org SIGNED, never the directory-served copy. Trust posture is
            # otherwise identical: structural /health probe, then the same
            # TOFU DID pin (fed_policy) as every other source;
            # KNOWN_CHAPTER_ENDPOINTS stays the operator anchor and the
            # FEDERATION_AUTODISCOVER gate on discover() is untouched.
            dir_admitted = 0
            dir_rejected = 0
            dir_url_list = directory_urls()
            for dir_url in dir_url_list:
                try:
                    dresp = await client.get(f"{dir_url}/api/agents", timeout=10.0)
                    if dresp.status_code != 200:
                        print(f"  Federation: directory {dir_url} unreachable (http {dresp.status_code})")
                        continue
                    ddata = dresp.json()
                    dir_records = ddata.get("agents", ddata) if isinstance(ddata, dict) else ddata
                except Exception as e:
                    print(f"  Federation: directory {dir_url} fetch failed ({type(e).__name__})")
                    continue
                if not isinstance(dir_records, list):
                    continue
                for rec in dir_records:
                    if not isinstance(rec, dict):
                        continue
                    rec_id = str(rec.get("agent_id") or "")
                    att = rec.get("attestation")
                    if att is None:
                        dir_rejected += 1
                        continue
                    att_ok, reason = registry_attestation.verify(att)
                    if att_ok and rec_id and str(att["record"].get("agent_id", "")) != rec_id:
                        # A directory can't dress record B in org A's valid
                        # attestation (same rule as the NEST path).
                        att_ok, reason = False, "subject_mismatch"
                    if not att_ok:
                        dir_rejected += 1
                        print(f"  Federation: directory record {rec_id!r} from {dir_url} rejected: {reason}")
                        continue
                    ep = str(att["record"]["endpoint"]).rstrip("/")
                    if not ep or ep == my_endpoint:
                        continue
                    attested_dids[ep] = str(att["record"]["did"])
                    if ep in seen_endpoints:
                        continue  # allowlisted or already queued — DID recorded above
                    if dir_admitted >= _DIRECTORY_PROBE_CAP:
                        print(
                            f"  Federation: directory probe cap ({_DIRECTORY_PROBE_CAP}) reached — "
                            "remaining directory records deferred to a later cycle"
                        )
                        break
                    seen_endpoints.add(ep)
                    endpoints_to_check.append(ep)
                    dir_admitted += 1
            if dir_url_list:
                print(
                    f"  Federation: directory sweep — {dir_admitted} attested peer(s) admitted, "
                    f"{dir_rejected} rejected (attestation required on this surface)"
                )

            results = await asyncio.gather(
                *[_check_chapter_endpoint(client, ep) for ep in endpoints_to_check],
                return_exceptions=True,
            )

            discovered_this_cycle: set[str] = set()
            # Snapshot the prior status of each known peer so we can
            # detect online↔offline transitions and emit corresponding
            # federation.peer.* events exactly ONCE per state change
            # (not every cycle while a peer stays in the same state).
            prior_status: dict[str, str] = {cid: (info.get("status") or "unknown") for cid, info in _federation.items()}

            # Try to lazy-import federation_policy — availability depends on
            # migration having been applied. Fall back to in-memory tracking
            # when the table isn't there yet.
            fed_policy: Any
            try:
                import federation_policy as fed_policy
            except ImportError:
                fed_policy = None

            # Lazy-import event_bus for the same reason — server startup
            # init wires it; tests that exercise discover() in isolation
            # don't need to fail if the bus isn't ready.
            try:
                import event_bus as _eb
            except ImportError:
                _eb = None  # type: ignore[assignment]

            peer_transitions: list[tuple[str, str, dict]] = []  # (event_type, peer_id, payload)

            for result in results:
                if isinstance(result, tuple) and result is not None:
                    chapter_id, chapter_info = result
                    # Carry the attestation's signer DID onto the peer entry —
                    # downstream verification can then check broadcasts against
                    # the key the org itself published, instead of whatever
                    # did.json the (registry-supplied) endpoint serves. Sources
                    # in order: this cycle's list-pass verification, the DID
                    # already carried on the peer entry (avoids re-fetching
                    # every cycle), then a one-shot by-id registry fetch
                    # (NEST's list projection strips attestations).
                    peer_ep = chapter_info.get("endpoint", "")
                    attested_did = attested_dids.get(peer_ep)
                    if not attested_did:
                        attested_did = (_federation.get(chapter_id) or {}).get("did")
                    if not attested_did:
                        attested_did = await _fetch_record_attestation(client, chapter_id, peer_ep)
                    if attested_did:
                        chapter_info["did"] = attested_did
                        if fed_policy is not None:
                            # TOFU pin: first attested sighting persists the DID;
                            # a later, DIFFERENT attested DID for the same peer id
                            # is an identity swap — a cheating registry re-keying
                            # a peer, or a real (rare) key rotation. The pin wins
                            # until a leader clears it (clear_did_pin).
                            try:
                                pin_status, pinned_did = await fed_policy.check_and_pin_did(
                                    chapter_id, attested_did, chapter_info.get("endpoint")
                                )
                            except Exception:
                                pin_status, pinned_did = "no_database", None
                            if pin_status == "mismatch":
                                print(
                                    f"  Federation: DID MISMATCH for {chapter_id} — attested {attested_did} "
                                    f"!= pinned {pinned_did} (possible registry identity swap)"
                                )
                                peer_transitions.append(
                                    (
                                        "federation.peer.did_mismatch",
                                        chapter_id,
                                        {
                                            "peer_chapter_id": chapter_id,
                                            "peer_endpoint": chapter_info.get("endpoint", ""),
                                            "pinned_did": pinned_did,
                                            "attested_did": attested_did,
                                        },
                                    )
                                )
                                if enforcing:
                                    # Identity suspect — do not (re)admit this
                                    # cycle. An already-federated peer falls
                                    # into the miss path below and backs off.
                                    continue
                                # Warn mode: keep the peer, but downstream
                                # verification trusts the PIN, not the new claim.
                                chapter_info["did"] = pinned_did
                    _federation[chapter_id] = chapter_info
                    _federation_failures.pop(chapter_id, None)
                    discovered_this_cycle.add(chapter_id)
                    # Online transition: peer was previously offline OR
                    # this is the first time we've seen them.
                    if prior_status.get(chapter_id) != "online":
                        peer_transitions.append(
                            (
                                "federation.peer.online",
                                chapter_id,
                                {
                                    "peer_chapter_id": chapter_id,
                                    "peer_endpoint": chapter_info.get("endpoint", ""),
                                    "member_count": int(chapter_info.get("members") or 0),
                                },
                            )
                        )
                    # Record persistent success
                    if fed_policy is not None:
                        try:
                            await fed_policy.record_success(chapter_id, chapter_info.get("endpoint"))
                        except Exception:
                            pass

            for cid in list(_federation.keys()):
                if cid not in discovered_this_cycle:
                    _federation_failures[cid] = _federation_failures.get(cid, 0) + 1
                    # Record persistent failure — backoff + state transition
                    if fed_policy is not None:
                        try:
                            await fed_policy.record_failure(
                                cid,
                                error=f"discovery_miss_x{_federation_failures[cid]}",
                                peer_endpoint=_federation[cid].get("endpoint"),
                            )
                        except Exception:
                            pass
                    if _federation_failures[cid] >= MAX_FEDERATION_FAILURES:
                        removed = _federation.pop(cid, None)
                        _federation_failures.pop(cid, None)
                        print(f"  Federation: removed {cid} after {MAX_FEDERATION_FAILURES} consecutive failures")
                        # Offline transition: peer dropped after sustained failure.
                        if prior_status.get(cid) == "online" and removed:
                            peer_transitions.append(
                                (
                                    "federation.peer.offline",
                                    cid,
                                    {
                                        "peer_chapter_id": cid,
                                        "peer_endpoint": removed.get("endpoint", ""),
                                        "consecutive_failures": _federation_failures.get(cid, MAX_FEDERATION_FAILURES),
                                    },
                                )
                            )
                    else:
                        # Soft offline — still in the registry but missed
                        # this cycle. Only emit once (transition from online).
                        if prior_status.get(cid) == "online":
                            peer_transitions.append(
                                (
                                    "federation.peer.offline",
                                    cid,
                                    {
                                        "peer_chapter_id": cid,
                                        "peer_endpoint": _federation[cid].get("endpoint", ""),
                                        "consecutive_failures": _federation_failures[cid],
                                    },
                                )
                            )
                        _federation[cid]["status"] = "offline"

            # Fire peer transition events (fire-and-forget; safe_publish
            # swallows any error so federation discovery can't be wedged
            # by a telemetry failure).
            if _eb is not None and peer_transitions:
                for ev_type, _peer, payload in peer_transitions:
                    asyncio.create_task(_eb.safe_publish(ev_type, payload))

            print(f"Federation: {len(_federation)} orgs: {list(_federation.keys())}")
    except Exception as e:
        print(f"Federation discovery failed: {e}")


async def query_chapter(chapter_id: str, question: str) -> str | None:
    """Send an A2A query to another chapter. Returns response text."""
    chapter = _federation.get(chapter_id)
    if not chapter or not chapter.get("endpoint"):
        return None
    endpoint = chapter["endpoint"].rstrip("/")
    # H7: the querying side used to provide NO proof of its identity — the peer's
    # middleware protected the route, but nothing said who was asking. Signed with
    # the SAME S2S scheme sign_request already uses for member-directory reads; a
    # parallel signing path here would be the divergence class this repo keeps
    # paying for.
    import federation_signing

    try:
        headers = federation_signing.sign_request(_agent_id, "POST", "/a2a")
    except federation_signing.OutboundUnsigned as exc:
        print(f"[federation][ERROR] not querying {chapter_id}: {exc}")
        return None
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{endpoint}/a2a",
                headers=headers,
                json={
                    "role": "user",
                    "content": {"type": "text", "text": question},
                    "conversation_id": f"federation-{_agent_id}-{uuid.uuid4().hex[:8]}",
                },
                timeout=15.0,
            )
            if resp.status_code == 200:
                return resp.json().get("content", {}).get("text", "")
    except Exception as e:
        print(f"cross-org query to {chapter_id} failed: {e}")
    return None


async def query_chapter_members(chapter_id: str, client: httpx.AsyncClient | None = None) -> list[dict]:
    """Get the member list from a peer chapter — as a SIGNED S2S request.

    The peer's directory is no longer public, so this leg authenticates with the
    federation Ed25519 scheme (``federation_signing.sign_request``, the same key
    and trust anchor as broadcasts). A peer that rejects our signature, or that
    is unreachable, is an OPERATIONAL FAULT — it is logged loudly, never
    laundered into an empty member list, because a silent ``[]`` here is
    indistinguishable from "that org has no members" and hid the regression
    class this endpoint's auth change could otherwise cause.

    ``client`` is injectable so a two-org test can drive a real peer app over
    the real signing path; production passes nothing.
    """
    chapter = _federation.get(chapter_id)
    if not chapter or not chapter.get("endpoint"):
        print(f"[federation] member query to {chapter_id!r} SKIPPED: no endpoint in the federation registry")
        return []
    url = f"{chapter['endpoint'].rstrip('/')}/api/members"
    import federation_signing

    try:
        headers = federation_signing.sign_request(_agent_id, "GET", "/api/members")
    except federation_signing.OutboundUnsigned as exc:
        # H4: refuse to emit rather than send unsigned and let the peer decide.
        print(f"[federation][ERROR] skipping peer member query: {exc}")
        return []
    if not headers:
        print(
            f"[federation] member query to {chapter_id!r} is UNSIGNED: this org has no Ed25519 keypair "
            f"({_agent_id!r}) — the peer will reject it if its directory is auth-gated"
        )
    owns_client = client is None
    http = client or httpx.AsyncClient()
    try:
        resp = await http.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            return resp.json().get("members", [])
        print(
            f"[federation] member query to {chapter_id!r} FAILED: HTTP {resp.status_code} from {url} "
            f"(signed={'yes' if headers else 'no'}) — {resp.text[:200]}"
        )
    except Exception as e:  # noqa: BLE001 — a peer we can't reach must be reported, not swallowed
        print(f"[federation] member query to {chapter_id!r} FAILED: {type(e).__name__}: {e} ({url})")
    finally:
        if owns_client:
            await http.aclose()
    return []
