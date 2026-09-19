"""
NANDA Registry — agent registration on NEST + NANDA Index + custom registries.

Handles multi-registry publication:
- NEST (nest.projectnanda.org) — sandbox/testbed registry (env REGISTRY_URL)
- NANDA Index — production global discovery layer (env NANDA_INDEX_URL)
- Additional registries — comma-separated in NANDA_INDEX_URL

If NANDA_INDEX_URL is empty, only NEST is used (backward compatible).
All Index URLs are tried in parallel; failure of one does not block
others or NEST.
"""

import asyncio
import os
import re
from typing import Any

import httpx

import registry_attestation
import sovereign_identity

_registry_url = ""  # NEST
_index_urls: list[str] = []  # NANDA Index(es) — comma-separated
_agent_id = ""
_agent_name = ""
_agent_description = ""
_agent_focus = ""
_members: dict = {}
_public_url = ""

# Track which members are registered this session
registered_on_nest: set[str] = set()
registered_on_index: set[str] = set()

# Per-registry status for /health exposure
_last_status: dict[str, dict] = {}


def _parse_index_urls(raw: str) -> list[str]:
    """Parse NANDA_INDEX_URL — supports comma-separated list with trimmed whitespace."""
    if not raw:
        return []
    return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]


def init(registry_url, agent_id, agent_name, agent_description, agent_focus, members, public_url):
    global _registry_url, _index_urls, _agent_id, _agent_name
    global _agent_description, _agent_focus, _members, _public_url
    _registry_url = registry_url
    _index_urls = _parse_index_urls(os.environ.get("NANDA_INDEX_URL", ""))
    _agent_id = agent_id
    _agent_name = agent_name
    _agent_description = agent_description
    _agent_focus = agent_focus
    _members = members
    _public_url = public_url
    _last_status.clear()


def configured_registries() -> list[str]:
    """All configured registry base URLs (NEST + NANDA Indexes), deduped —
    the corroboration set for the cross-registry divergence detector."""
    urls: list[str] = []
    if _registry_url:
        urls.append(_registry_url.rstrip("/"))
    for u in _index_urls:
        if u and u.rstrip("/") not in urls:
            urls.append(u.rstrip("/"))
    return urls


def get_registry_status() -> dict:
    """Return the most recent per-registry status for /health exposure."""
    return {
        "nest": {
            "url": _registry_url,
            "configured": bool(_registry_url),
            "registered_count": len(registered_on_nest),
            **_last_status.get("nest", {}),
        },
        "indexes": [
            {
                "url": url,
                "configured": True,
                **_last_status.get(f"index:{url}", {}),
            }
            for url in _index_urls
        ],
    }


def _attest(subject_id: str, endpoint: str) -> dict | None:
    """Signed endpoint attestation for a registry record, signed by THIS org's
    key (self-certifying for the org record; host-certifying for members, who
    are served at the org's endpoint). None until the org keypair exists —
    first boot registers before ensure_chapter_keypair runs, and the heartbeat
    re-publish carries the attestation shortly after."""
    return registry_attestation.build(subject_id, endpoint, _agent_id)


def _update_status(key: str, ok: bool, detail: str = ""):
    import time as _time

    _last_status[key] = {
        "last_attempt": int(_time.time()),
        "last_ok": ok,
        "detail": detail,
    }


# ─── NEST Registration (backward compatible) ────────────────


def _publication_blocked(subject: str, endpoint: str) -> str | None:
    """The reason this publish must not happen, or None. The empty-vs-unset fix — one gate, so a
    new publish path cannot quietly skip the checks."""
    import registry_policy

    reason = registry_policy.publication_blocked_reason(endpoint)
    if reason:
        print(f"[NandaRegistry] NOT publishing {subject!r}: {reason}")
    return reason


async def _register_on_nest(agent_id: str, payload: dict) -> bool:
    """Register an agent on NEST. Returns True on success."""
    if not _registry_url:
        import registry_policy

        registry_policy.note_declined("registry publication", f"publishing {agent_id!r}")
        return False
    if _publication_blocked(agent_id, payload.get("endpoint", "")):
        return False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{_registry_url}/api/agents", json=payload, timeout=10.0)
            if resp.status_code < 300:
                _update_status("nest", True, "registered")
                return True
            # Try update if create fails (already exists). The update carries
            # the attestation too — otherwise a re-register would strip the
            # signed record and leave the stale one in place.
            update_body = {"status": "running", "endpoint": payload.get("endpoint", "")}
            if payload.get("attestation"):
                update_body["attestation"] = payload["attestation"]
            resp2 = await client.put(
                f"{_registry_url}/api/agents/{agent_id}",
                json=update_body,
                timeout=10.0,
            )
            ok = resp2.status_code < 300
            _update_status("nest", ok, "updated" if ok else f"http_{resp2.status_code}")
            return ok
    except Exception as e:
        _update_status("nest", False, str(e)[:80])
        print(f"[NandaRegistry] NEST registration failed for {agent_id}: {e}")
        return False


# ─── NANDA Index Registration ────────────────────────────────


async def _register_on_one_index(index_url: str, agent_id: str, facts: dict) -> bool:
    """Register agent on a single NANDA Index URL. Returns True on success."""
    try:
        payload = {
            "agent_id": agent_id,
            # Top-level endpoint claim, NEST-parity: the divergence detector
            # compares this field across registries, so the Index record must
            # carry it too or endpoint corroboration silently has one leg.
            "endpoint": _public_url,
            "facts": facts,
            "facts_url": facts.get("endpoints", {}).get("agentfacts_url", ""),
            "status": "running",
        }
        attestation = _attest(agent_id, _public_url)
        if attestation:
            payload["attestation"] = attestation
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{index_url}/api/agents", json=payload, timeout=10.0)
            if resp.status_code < 300:
                _update_status(f"index:{index_url}", True, "registered")
                print(f"[NandaRegistry] Index registered on {index_url}: {agent_id}")
                return True
            resp2 = await client.put(
                f"{index_url}/api/agents/{agent_id}",
                json=payload,
                timeout=10.0,
            )
            if resp2.status_code < 300:
                _update_status(f"index:{index_url}", True, "updated")
                print(f"[NandaRegistry] Index updated on {index_url}: {agent_id}")
                return True
            _update_status(f"index:{index_url}", False, f"http_{resp2.status_code}")
            return False
    except Exception as e:
        _update_status(f"index:{index_url}", False, str(e)[:80])
        print(f"[NandaRegistry] Index registration failed on {index_url} for {agent_id}: {e}")
        return False


async def register_on_index(agent_id: str, facts: dict) -> bool:
    """Register agent on all configured NANDA Index URLs in parallel.

    Returns True if ANY index accepted the registration. Failure on one
    index does not affect others.
    """
    if not _index_urls:
        return False
    if _publication_blocked(agent_id, (facts.get("endpoints") or {}).get("static") or _public_url):
        return False
    results = await asyncio.gather(
        *[_register_on_one_index(url, agent_id, facts) for url in _index_urls],
        return_exceptions=True,
    )
    ok = any(r is True for r in results)
    if ok:
        registered_on_index.add(agent_id)
    return ok


async def update_index_entry(agent_id: str, facts: dict) -> bool:
    """Update an existing NANDA Index entry on all configured indexes.

    Gated like every other publish: a refresh IS a publication (it re-signs and
    re-sends the record), so ``AUTO_REGISTER=false`` or an unpublishable
    endpoint stops it here, not only at the one caller that remembered to check.
    """
    if not _index_urls:
        return False
    if _publication_blocked(agent_id, (facts.get("endpoints") or {}).get("static") or _public_url):
        return False

    update_body = {"endpoint": _public_url, "facts": facts, "status": "running"}
    attestation = _attest(agent_id, _public_url)
    if attestation:
        update_body["attestation"] = attestation

    async def _update(url: str) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.put(
                    f"{url}/api/agents/{agent_id}",
                    json=update_body,
                    timeout=10.0,
                )
            ok = resp.status_code < 300
            # Record the heartbeat's REAL result so /health reflects the live
            # index state. The boot register_on_index runs before the chapter
            # keypair is ensured, so it can't attest and 403s once; this
            # attested refresh succeeds — but until now it never updated the
            # status, leaving /health stuck on the stale boot 403.
            _update_status(f"index:{url}", ok, "updated" if ok else f"http_{resp.status_code}")
            return ok
        except Exception as e:  # noqa: BLE001 — a failed refresh must not wedge the heartbeat
            _update_status(f"index:{url}", False, str(e)[:80])
            return False

    results = await asyncio.gather(*[_update(u) for u in _index_urls], return_exceptions=True)
    return any(r is True for r in results)


async def unregister_from_index(agent_id: str) -> bool:
    """Remove agent from all configured NANDA Indexes."""
    if not _index_urls:
        return False

    async def _delete(url: str) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.delete(f"{url}/api/agents/{agent_id}", timeout=5.0)
                return resp.status_code < 300
        except Exception:
            return False

    results = await asyncio.gather(*[_delete(u) for u in _index_urls], return_exceptions=True)
    return any(r is True for r in results)


async def probe_indexes() -> list[dict]:
    """Probe configured NANDA Index URLs to check reachability.

    Returns per-index status — useful for /health and the admin surface.
    """

    async def _probe(url: str) -> dict:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{url}/health", timeout=5.0)
                return {
                    "url": url,
                    "reachable": resp.status_code < 500,
                    "status_code": resp.status_code,
                }
        except Exception as e:
            return {"url": url, "reachable": False, "error": str(e)[:80]}

    if not _index_urls:
        return []
    return await asyncio.gather(*[_probe(u) for u in _index_urls])


# ─── NANDA Index v2 (leveled 4-hop: JWT signup + hosting_path + email-verify) ───
# The real api.nandaindex.org contract (and the local testbed), distinct from
# the legacy POST /api/agents path above. OPERATOR-GATED: only fires on an
# explicit admin trigger (POST /admin/api/index-v2/register), never on startup,
# so dev/CI never makes a surprise network call. For hosting_path=registry the
# org IS its own registry — Orrery serves GET /agents/<id> + ai-catalog.json so
# the 4-hop resolves back here.

_INDEX_V2_TIMEOUT = 15.0


def _sanitize_org_id(raw: str) -> str:
    """Coerce a string to the Index v2 org_id pattern ^[a-z0-9][a-z0-9-]*[a-z0-9]$."""
    s = re.sub(r"[^a-z0-9-]", "-", raw.lower())
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "org"


def _index_v2_config() -> dict | None:
    """Index-v2 registration config from env, or None if not fully set.

    Requires an account (INDEX_ACCOUNT_EMAIL/PASSWORD) and the org's public
    identity (ORG_DOMAIN; ORG_CONTACT_EMAIL defaults to the account email).
    org_id defaults to a sanitized lowercase AGENT_ID (override via INDEX_ORG_ID).
    Returns None — and the caller makes NO network call — when unconfigured.
    """
    email = os.environ.get("INDEX_ACCOUNT_EMAIL", "").strip()
    password = os.environ.get("INDEX_ACCOUNT_PASSWORD", "").strip()
    domain = os.environ.get("ORG_DOMAIN", "").strip()
    if not (email and password and domain):
        return None
    return {
        "index_url": _index_urls[0] if _index_urls else "",
        "email": email,
        "password": password,
        "domain": domain,
        "contact_email": os.environ.get("ORG_CONTACT_EMAIL", "").strip() or email,
        "org_id": _sanitize_org_id(os.environ.get("INDEX_ORG_ID", "").strip() or _agent_id),
    }


async def _index_v2_token(client, index_url: str, email: str, password: str, display_name: str) -> str:
    """Obtain a JWT: POST /auth/register (201) or POST /auth/login on 409 (exists)."""
    r = await client.post(
        f"{index_url}/auth/register",
        json={"email": email, "password": password, "display_name": display_name},
    )
    if r.status_code == 201:
        return r.json().get("token", "")
    if r.status_code == 409:
        r2 = await client.post(f"{index_url}/auth/login", json={"email": email, "password": password})
        if r2.status_code == 200:
            return r2.json().get("token", "")
    return ""


async def register_on_index_v2() -> dict:
    """Register this org on a NANDA Index v2 (hosting_path=registry).

    Operator-gated explicit trigger — never auto-called on startup. Returns a
    status dict {ok, status, org_id, detail}. ``status='pending'`` means the org
    row was created and a verification email was sent (the operator must click
    it to activate). Idempotent: a re-trigger logs in and treats an existing
    org_id (409) as already-registered.
    """
    cfg = _index_v2_config()
    if not cfg or not cfg["index_url"]:
        return {
            "ok": False,
            "status": "unconfigured",
            "detail": "set NANDA_INDEX_URL + INDEX_ACCOUNT_EMAIL + INDEX_ACCOUNT_PASSWORD + ORG_DOMAIN",
        }
    index_url, org_id = cfg["index_url"], cfg["org_id"]
    try:
        async with httpx.AsyncClient(timeout=_INDEX_V2_TIMEOUT) as client:
            token = await _index_v2_token(client, index_url, cfg["email"], cfg["password"], _agent_name)
            if not token:
                _update_status(f"index:{index_url}", False, "auth_failed")
                return {
                    "ok": False,
                    "status": "auth_failed",
                    "org_id": org_id,
                    "detail": "could not obtain a JWT (register/login both failed)",
                }
            body = {
                "org_id": org_id,
                "display_name": _agent_name,
                "hosting_path": "registry",  # Orrery is its own registry
                "domain": cfg["domain"],
                "contact_email": cfg["contact_email"],
                "registry_url": _public_url,  # the 4-hop comes back here
                "media_type": "application/ai-catalog+json",  # org-level catalog type
                "description": _agent_description,
                "tags": [s.strip().lower() for s in _agent_focus.split(",") if s.strip()][:20],
            }
            r = await client.post(
                f"{index_url}/api/v1/orgs", json=body, headers={"Authorization": f"Bearer {token}"}
            )
            if r.status_code == 201:
                registered_on_index.add(org_id)
                _update_status(f"index:{index_url}", True, "pending_verification")
                return {
                    "ok": True,
                    "status": "pending",
                    "org_id": org_id,
                    "detail": "org created; a verification email was sent — the operator must click it to activate",
                    "index_record": r.json(),
                }
            if r.status_code == 409:
                registered_on_index.add(org_id)
                _update_status(f"index:{index_url}", True, "already_registered")
                return {
                    "ok": True,
                    "status": "exists",
                    "org_id": org_id,
                    "detail": "org_id already registered on this index (idempotent re-trigger)",
                }
            _update_status(f"index:{index_url}", False, f"http_{r.status_code}")
            return {
                "ok": False,
                "status": f"http_{r.status_code}",
                "org_id": org_id,
                "detail": (getattr(r, "text", "") or "")[:200],
            }
    except Exception as e:
        _update_status(f"index:{index_url}", False, str(e)[:80])
        return {"ok": False, "status": "error", "org_id": org_id, "detail": str(e)[:200]}


# ─── Dual Registration (NEST + Index) ────────────────────────


async def register_chapter(public_url: str, facts: dict | None = None) -> None:
    """Register this chapter agent on both NEST and NANDA Index."""
    nest_payload: dict[str, Any] = {
        "agent_id": _agent_id,
        "name": _agent_name,
        "endpoint": public_url,
        "facts_url": f"{public_url}/agentfacts.json",
        "description": _agent_description,
        "specialization": _agent_focus,
        "capabilities": [s.strip().lower().replace(" ", "-") for s in _agent_focus.split(",")],
        "agent_type": "skill",
        "status": "running",
    }
    attestation = _attest(_agent_id, public_url)
    if attestation:
        nest_payload["attestation"] = attestation

    # Register on both in parallel — Index failure does not block NEST
    nest_ok = await _register_on_nest(_agent_id, nest_payload)
    if nest_ok:
        print(f"[NandaRegistry] NEST registered: {_agent_id}")

    if facts:
        await register_on_index(_agent_id, facts)


async def register_member(member_id: str, member: dict, public_url: str, facts: dict | None = None):
    """Register a single member agent on NEST + NANDA Index.

    TEST-prefixed members are gated out of public discovery. The TEST-
    prefix convention marks conformance-suite probes (and any other
    deliberately-ephemeral agent) — these MUST stay on the chapter
    locally so tests can assert chapter behavior, but MUST NOT be
    published to NEST or NANDA Index where they pollute discovery.

    The gate is intentionally applied to *member* registration only.
    Test chapter agents (TEST-boston, TEST-london, etc.) DO need NEST
    visibility for federation testing and are registered through
    ``register_chapter`` instead, which is not gated.
    """
    if member_id.startswith("TEST-"):
        # Recorded as "registered" so periodic re-publish loops don't
        # keep retrying. The server still sees the member locally.
        registered_on_nest.add(member_id)
        return

    # Demo/synthetic members carry ``is_demo == true`` in their config.
    # They stay local for client rendering but MUST NOT be pushed to NEST
    # or to the NANDA Index — public registries are for real agents only.
    if member.get("is_demo"):
        registered_on_nest.add(member_id)
        return

    nest_payload = {
        "agent_id": member_id,
        "name": member["name"],
        "endpoint": public_url,
        "facts_url": f"{public_url}/agentfacts/{member_id}.json",
        "description": member.get("description", ""),
        "capabilities": member.get("skills", []),
        "agent_type": "skill",
        "status": "running",
    }
    attestation = _attest(member_id, public_url)
    if attestation:
        nest_payload["attestation"] = attestation

    nest_ok = await _register_on_nest(member_id, nest_payload)
    if nest_ok:
        print(f"  [NandaRegistry] NEST registered member: {member_id}")

    if facts:
        index_ok = await register_on_index(member_id, facts)
        if index_ok:
            registered_on_index.add(member_id)


async def register_all_members(public_url: str):
    """Register all members on NEST (Index registration requires facts, done separately)."""
    tasks = [register_member(mid, m, public_url) for mid, m in _members.items()]
    await asyncio.gather(*tasks)
    registered_on_nest.update(_members.keys())


async def register_new_members(public_url: str):
    """Register only members not yet registered this session."""
    new_members = [mid for mid in _members if mid not in registered_on_nest]
    if new_members:
        for mid in new_members:
            try:
                await register_member(mid, _members[mid], public_url)
                registered_on_nest.add(mid)
            except Exception:
                pass


def _our_did() -> str:
    """This org's did:key, or "" before the keypair exists."""
    kp = sovereign_identity._ed25519_keypairs.get(_agent_id)
    if not kp:
        return ""
    import base64

    return sovereign_identity.build_did_key_from_ed25519(base64.b64encode(kp["public_key"]).decode())


def _is_attributable_to_us(record: dict) -> tuple[bool, str]:
    """Did THIS org publish this registry record? Returns ``(ours, why)``.

    ⚠️ **AN ENDPOINT-STRING MATCH IS NOT IDENTITY**, and treating it as one is
    what made this function dangerous. Two orgs behind one hostname — a shared
    host, a reverse proxy, a redeployment that reused a name — both match, and
    each would delete the other's records. Measured: with two records carrying
    our endpoint and ids that were not ours, boot issued two DELETEs and logged
    *"NEST cleaned 2 stale agents"* as if that were success.

    Identity is one of two things, in order of strength:

    1. **We published it.** ``registered_on_nest`` is this process's own record
       of what it put there. Nothing about the registry's response can forge it.
    2. **It carries our signed endpoint attestation.** ``registry_attestation``
       is signed with the org's Ed25519 key, and its ``did`` IS that key, so a
       record attesting our DID could only have been published by something
       holding our private key. This is the check that survives a restart, since
       ``registered_on_nest`` is in-memory and empty on a fresh boot.

    Anything else is NOT ours — including a record that merely shares our
    endpoint. It is reported, never deleted.
    """
    aid = str(record.get("id") or "").replace("skill-", "")
    if aid and aid in registered_on_nest:
        return True, "published by this process"

    att = record.get("attestation")
    if att:
        ok, reason = registry_attestation.verify(att)
        if not ok:
            return False, f"attestation does not verify ({reason})"
        rec = att.get("record") if isinstance(att, dict) else None
        ours = _our_did()
        if ours and isinstance(rec, dict) and rec.get("did") == ours:
            return True, "attested by this org's key"
        return False, "attested by a different org"

    return False, "endpoint matches but nothing attributes it to us"


async def reconcile_stale_agents(public_url: str, *, delete: bool = False) -> dict:
    """Find registry records this org published that are no longer members.

    ⚠️ **READ-ONLY BY DEFAULT, AND BOOT NEVER PASSES ``delete=True``.** This ran
    unconditionally at startup and issued DELETEs against a registry, keyed on an
    endpoint-string match — a destructive call in a path nobody triggered, on a
    match that is not identity, and it fired even with ``AUTO_REGISTER=false``.
    Deleting is now an explicit act by an operator who decided to.

    Returns a report: ``{"candidates": [...], "ours": [...], "not_ours": [...],
    "deleted": [...]}``. The report is the point — "do not delete" must not be
    satisfied by a function that stopped looking, so this still reconciles and
    still says exactly what it found.
    """
    report: dict = {"candidates": [], "ours": [], "not_ours": [], "deleted": [], "delete_requested": delete}

    if not _registry_url:
        import registry_policy

        registry_policy.note_declined("registry reconcile", "stale-record reconciliation")

    if _registry_url:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{_registry_url}/api/agents", timeout=10.0)
                if resp.status_code == 200:
                    data = resp.json()
                    all_agents = data.get("agents", data) if isinstance(data, dict) else data
                    our_ids = set(_members.keys()) | {_agent_id}
                    for agent in all_agents or []:
                        if not isinstance(agent, dict):
                            continue
                        aid = str(agent.get("id", "")).replace("skill-", "")
                        if agent.get("endpoint", "") != public_url or aid in our_ids:
                            continue
                        report["candidates"].append(aid)
                        ours, why = _is_attributable_to_us(agent)
                        if not ours:
                            report["not_ours"].append({"id": aid, "why": why})
                            continue
                        report["ours"].append({"id": aid, "why": why})
                        if delete:
                            try:
                                await client.delete(f"{_registry_url}/api/agents/{aid}", timeout=5.0)
                                report["deleted"].append(aid)
                            except Exception:
                                pass
        except Exception:
            pass

    if report["not_ours"]:
        print(
            f"[NandaRegistry] {len(report['not_ours'])} registry record(s) share this endpoint but are "
            f"NOT attributable to this org — reported, never removed: "
            + ", ".join(f"{r['id']} ({r['why']})" for r in report["not_ours"][:5])
        )
    if report["ours"] and not delete:
        print(
            f"[NandaRegistry] {len(report['ours'])} stale record(s) of ours could be removed: "
            + ", ".join(r["id"] for r in report["ours"][:5])
            + ". Not removing — deletion is an explicit operator action, never a startup side effect."
        )

    # The Index half deletes only ids in `registered_on_index` — this process's
    # own record of what it published — which IS attributable identity rather
    # than an endpoint match, so it was never the defective half. It still only
    # runs when deletion was asked for.
    if delete and _index_urls:
        for aid in list(registered_on_index):
            if aid not in _members and aid != _agent_id:
                await unregister_from_index(aid)
                registered_on_index.discard(aid)
                report["deleted"].append(aid)

    return report


async def get_agent_count() -> int:
    """Get total agent count from NEST."""
    # Fourth ungated call, found by the same recorder run: with no registry this
    # built the relative url "/api/agents" and attempted it.
    if not _registry_url:
        import registry_policy

        registry_policy.note_declined("registry agent count", "registry agent count")
        return 0
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{_registry_url}/api/agents", timeout=10.0)
            if resp.status_code == 200:
                data = resp.json()
                agents = data.get("agents", data) if isinstance(data, dict) else data
                return len(agents) if isinstance(agents, list) else 0
    except Exception:
        pass
    return 0
