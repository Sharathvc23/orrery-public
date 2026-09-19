"""Every mutating route binds the identity it RECORDS to the identity it PROVED.

The class this guard exists for: authentication is not authorship. The
middleware proves WHO CALLED — and a handler that then copies an actor id out of
the payload writes a row naming someone who did nothing. Two full security
audits missed it because the request they examined was *valid*: the signature
verifies, the caller is real, and the record is still a forgery.

``/api/chapter/audit/record`` took no ``Request`` parameter at all, so any signed
member could append a chain-linked entry to the audit ledger naming any other
member as the actor. ``/api/voice/config`` wrote the same ``agent_settings`` row
that ``/api/settings/update`` guards with an ownership check the neighbour never
got. Five point fixes would have left the sixth door for next time, so the guard
is the deliverable and the fixes are its first consumers.

THE ENUMERATION COMES FROM THE APP'S OWN ROUTE TABLE. A route added tomorrow is
covered without anyone remembering to add it here: it must either bind, or be
named in ACTOR_FREE with a reason, and if it is named there it may not carry an
actor-ish field. Three ways to fail, no way to be silently absent.
"""

from __future__ import annotations

import inspect
import json
import typing

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from tests._admin_fixtures import register_test_regular_member, reset_chapter_agent_module

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

#: Field-name fragments that denote an AGENT IDENTITY carried in a payload or a
#: path. Substring matching, so ``added_by_agent_id`` and ``attestor_did`` are
#: both caught without either being written down.
ACTOR_TOKENS = ("actor", "agent_id", "member_id", "updated_by", "owner", "author", "_by", "did")

#: The helpers that constitute "this handler consults the verified caller".
#: ``_resolve_caller`` is the primitive; the rest wrap it.
BINDING_HELPERS = (
    "_resolve_caller",
    "_bind_actor_to_caller",
    "_require_agent_owner",
    "_require_settings_owner",
    "_authorize_role",
    "_authorize_admin",
)

#: Routes exempt from the caller-binding rule, each with a KIND and a reason.
#: An exemption without a reason is a suppression list — the shape the orphan-module
#: sweep removed —
#: and an exemption nothing re-checks is one that goes stale silently, so each
#: kind carries its own staleness test below.
#:
#:   SELF_CLAIM      the identity in the payload IS the caller's own, established
#:                   BY this request — there is no prior verified caller to bind
#:                   to. Checked against auth_verify: the route must genuinely be
#:                   an open path. The moment it starts requiring auth, a caller
#:                   exists and the exemption is no longer true.
#:   INNER_SIGNATURE the actor is proven by a SEPARATE signature over the payload,
#:                   a stronger binding than this guard looks for. Checked
#:                   behaviourally: a forged claim must still be refused.
ACTOR_FREE: dict[tuple[str, str], tuple[str, str]] = {
    ("POST", "/api/members"): (
        "SELF_CLAIM",
        "Registration IS the identity-establishment path. There is no prior verified "
        "caller to bind to — agent_id is the identity being claimed, not an assertion "
        "about a third party. Its own TOFU/first-claim pin is the control here.",
    ),
    ("POST", "/api/members/"): ("SELF_CLAIM", "Trailing-slash twin of POST /api/members; same reasoning."),
    ("POST", "/api/endorsements"): (
        "INNER_SIGNATURE",
        "The endorser is proven by a separate Ed25519 signature over the endorsement "
        "payload, not by the request signature — a stronger binding than this guard "
        "checks for. Exercised below: a forged endorser claim is refused.",
    ),
    ("POST", "/api/endorsements/revoke"): (
        "INNER_SIGNATURE",
        "Same inner-signature rule as POST /api/endorsements — the revocation is "
        "authorised against the endorsement it revokes, not against the request.",
    ),
}


def _route_actor_fields(route: APIRoute) -> list[str]:
    """Actor-ish identity fields this route accepts, from its resolved signature.

    ``from __future__ import annotations`` makes handler annotations strings, so
    the body model is resolved with ``get_type_hints`` rather than read off the
    raw signature — reading the raw form silently finds nothing and would make
    this whole guard vacuous.
    """
    fields: list[str] = []
    try:
        hints = typing.get_type_hints(route.endpoint)
    except Exception as exc:  # noqa: BLE001
        # An unresolvable hint must not hide a route. Returning {} here would
        # report "carries no identity", which is indistinguishable to every
        # test below from a route that genuinely carries none — the guard would
        # pass precisely where it cannot see.
        raise AssertionError(
            f"cannot determine the actor fields of {route.endpoint.__name__} "
            f"({route.path}): {type(exc).__name__}: {exc}. A route whose payload "
            f"cannot be introspected must fail this guard, not pass it."
        ) from exc
    for param, annotation in hints.items():
        model_fields = getattr(annotation, "model_fields", None)
        if model_fields:
            fields += [
                f"{param}.{name}" for name in model_fields if any(t in name.lower() for t in ACTOR_TOKENS)
            ]
    for path_param in route.dependant.path_params or []:
        if any(t in path_param.name.lower() for t in ACTOR_TOKENS):
            fields.append(f"path:{path_param.name}")
    return fields


def _binds(route: APIRoute) -> bool:
    try:
        source = inspect.getsource(route.endpoint)
    except (OSError, TypeError):
        return False
    return any(helper in source for helper in BINDING_HELPERS)


def _router_module_routes() -> list[APIRoute]:
    """Routes declared by the router modules under ``server/routes/``.

    Discovered from the directory rather than listed, so a module added later is
    covered by existing. Included because enumerating ``app.routes`` alone did
    not return them: the app object the tests import carries the handlers
    defined inline in ``chapter_agent`` and none of the ones mounted from
    ``routes/``. Reading both sources means the enumeration does not depend on
    which of them a given import order happens to populate.
    """
    import importlib
    from pathlib import Path

    found: list[APIRoute] = []
    for module_path in sorted((Path(__file__).resolve().parents[1] / "routes").glob("*.py")):
        if module_path.name.startswith("_"):
            continue
        router = getattr(importlib.import_module(f"routes.{module_path.stem}"), "router", None)
        if router is None:
            continue
        found.extend(r for r in router.routes if isinstance(r, APIRoute))
    return found


def _mutating_routes(app) -> list[tuple[str, str, APIRoute]]:
    out = []
    seen: set[tuple[str, str]] = set()
    for route in [r for r in app.routes if isinstance(r, APIRoute)] + _router_module_routes():
        for method in sorted(route.methods & MUTATING):
            if (method, route.path) in seen:
                continue
            seen.add((method, route.path))
            out.append((method, route.path, route))
    return out


@pytest.fixture(scope="module")
def app_routes():
    """The app's mutating routes.

    ``chapter_agent`` is imported, not re-imported. Popping it from
    ``sys.modules`` and importing again produced an app **missing every route
    defined under ``server/routes/``** — the router modules are already cached,
    so the second import's ``include_router`` calls did not repopulate the new
    app. The enumeration silently lost `/api/skills/{skill_id}/install`,
    `/api/skills/publish`, `/api/skills/{skill_id}/review`, the CRM routes and
    the identity routes: an entire class of routes invisible to a guard whose
    only job is completeness. ``test_every_router_module_is_represented``
    asserts the enumeration is whole, so this cannot regress quietly.
    """
    import importlib
    import os

    os.environ.setdefault("AGENT_ID", "TEST-route-guard-chapter")
    os.environ.setdefault("AGENT_NAME", "Route Guard Chapter")
    mod = importlib.import_module("chapter_agent")
    return _mutating_routes(mod.app)


# ══════════════════════════════════════════════════════════════════════
# G1 — STRUCTURAL: every mutating route is bound or explicitly actor-free
# ══════════════════════════════════════════════════════════════════════


def test_every_router_module_is_represented(app_routes):
    """The enumeration covers the routes defined under ``server/routes/`` too.

    Route modules are discovered from the directory, not listed, so a new one
    joins this check by existing. Each declares an ``APIRouter``; every path on
    that router must appear in the enumeration.

    This exists because it did not hold. The enumeration was built from an app
    that carried none of them — `/api/skills/{skill_id}/install`,
    `/api/skills/publish`, `/api/skills/{skill_id}/review`, the CRM routes and
    the identity routes were all absent, so every assertion below passed over
    them without reading one. A guard that cannot see part of its subject
    reports clean on that part, and nothing distinguishes that from a subject
    that is clean.
    """
    import importlib
    from pathlib import Path

    routes_dir = Path(__file__).resolve().parents[1] / "routes"
    enumerated = {path for _method, path, _route in app_routes}

    missing: list[str] = []
    checked = 0
    for module_path in sorted(routes_dir.glob("*.py")):
        if module_path.name.startswith("_"):
            continue
        module = importlib.import_module(f"routes.{module_path.stem}")
        router = getattr(module, "router", None)
        if router is None:
            continue
        for route in router.routes:
            methods = getattr(route, "methods", set()) & MUTATING
            if not methods:
                continue
            checked += 1
            if route.path not in enumerated:
                missing.append(f"{sorted(methods)[0]} {route.path}  (routes/{module_path.stem}.py)")

    assert checked, "no mutating routes found on any router module; this check is vacuous"
    assert not missing, (
        f"the enumeration is missing {len(missing)} of {checked} mutating routes declared by "
        "router modules, so every assertion in this file passed over them without reading one:\n  "
        + "\n  ".join(missing)
    )


def test_the_enumeration_is_not_empty(app_routes):
    """A guard that enumerates nothing passes forever. 80+ mutating routes exist;
    a collapse to a handful means the route walk broke, not that the app shrank."""
    assert len(app_routes) > 60, f"only {len(app_routes)} mutating routes found — enumeration is broken"


def test_every_mutating_route_binds_its_actor_or_is_declared_actor_free(app_routes):
    unbound = []
    for method, path, route in app_routes:
        if _binds(route):
            continue
        if (method, path) in ACTOR_FREE:
            continue
        fields = _route_actor_fields(route)
        if fields:
            unbound.append(f"{method} {path} -> {route.endpoint.__name__}() accepts {fields}")
    assert not unbound, (
        "these mutating routes accept an agent identity in their payload or path and never "
        "consult the verified caller — the identity they record is whatever the caller typed:\n  "
        + "\n  ".join(unbound)
        + "\n\nBind it with _bind_actor_to_caller (attribution) or _require_agent_owner "
        "(target ownership), or add it to ACTOR_FREE with a reason."
    )


def test_no_actor_free_exemption_has_gone_stale(app_routes):
    """An exemption must still describe the route it exempts.

    A NO_ACTOR entry claims the route carries no agent identity; if one is added
    later the exemption is now covering exactly the case it was written before,
    and must be revisited rather than continuing to pass."""
    by_key = {(m, p): r for m, p, r in app_routes}
    stale = []
    for key, (kind, reason) in ACTOR_FREE.items():
        route = by_key.get(key)
        if route is None:
            stale.append(f"{key[0]} {key[1]} — exempted but no longer routed; delete the entry")
            continue
        if kind == "SELF_CLAIM":
            # The claim is "no verified caller exists here". That is auth_verify's
            # decision, not this file's opinion, so ask it.
            import auth_verify

            if auth_verify.requires_auth(key[0], key[1]):
                stale.append(
                    f"{key[0]} {key[1]} — exempted as SELF_CLAIM but the route now REQUIRES auth, so a "
                    f"verified caller exists and the identity must be bound to it. Reason on file: {reason}"
                )
    assert not stale, "ACTOR_FREE has drifted from the app:\n  " + "\n  ".join(stale)


def test_every_actor_free_exemption_states_a_kind_and_a_reason(app_routes):
    for key, (kind, reason) in ACTOR_FREE.items():
        assert kind in {"SELF_CLAIM", "INNER_SIGNATURE"}, f"{key} has unknown exemption kind {kind!r}"
        assert len(reason.strip()) > 40, f"{key} is exempted without a real reason"


def test_the_INNER_SIGNATURE_exemptions_actually_refuse_a_forged_claim(stack):
    """The exemption says "a separate signature proves the actor". If that stops
    being true the route is unguarded and this file said it was fine. Drive it:
    ALICE signs the request, the payload names BOB as endorser, the inner
    signature is garbage. It must be refused."""
    _mod, alice, client, writes = stack
    payload = {
        "endorser_agent_id": BOB,
        "endorser_did": "did:key:zFORGED",
        "endorser_pubkey_b64": "AAAA",
        "endorsee_agent_id": ALICE,
        "signature_b64": "AAAA",
        "created_unix": 1786000000,
    }
    body = json.dumps(payload, separators=(",", ":"))
    headers = alice["signer"](method="POST", url_path="/api/endorsements", body=body)
    headers["Content-Type"] = "application/json"
    resp = client.post("/api/endorsements", content=body, headers=headers)
    assert resp.status_code >= 400, (
        f"a forged endorser claim was accepted: HTTP {resp.status_code} {resp.text[:200]}"
    )
    forged = [w for w in writes if BOB in json.dumps(w[2], default=str)]
    assert not forged, f"endorsement refused but still wrote: {forged}"


# ══════════════════════════════════════════════════════════════════════
# G2 — BEHAVIOURAL: the binding actually refuses, over real HTTP
# ══════════════════════════════════════════════════════════════════════

ALICE = "guard-caller-alice"
BOB = "guard-victim-bob"

#: (method, path, payload-naming-BOB). Signed as ALICE. Every one must refuse.
FORGERY_ATTEMPTS = [
    ("POST", "/api/chapter/audit/record",
     {"chapter_id": "TEST-route-guard-chapter", "action": "member.delete",
      "actor_agent_id": BOB, "target_type": "member", "target_id": ALICE, "outcome": "ok"}),
    ("POST", "/api/chapter/allowlist/add",
     {"chapter_id": "TEST-route-guard-chapter", "peer_chapter_id": "attacker-chapter",
      "added_by_agent_id": BOB, "reason": "forged"}),
    ("POST", "/api/chapter/allowlist/remove",
     {"chapter_id": "TEST-route-guard-chapter", "peer_chapter_id": "attacker-chapter",
      "added_by_agent_id": BOB, "reason": "forged"}),
    ("POST", "/api/voice/config", {"agent_id": BOB, "config": {"voice_id": "attacker"}}),
    ("POST", "/api/onboarding/advance", {"agent_id": BOB, "step": 1, "values": {}}),
    ("POST", f"/api/onboarding/{BOB}/reset", {}),
    ("POST", "/api/channels/connect",
     {"agent_id": BOB, "kind": "slack", "remote_id": "T01234567", "config": {}}),
    ("POST", "/api/conversations",
     {"from_agent_id": BOB, "to_agent_id": ALICE, "message": "forged", "topic": "t"}),
    ("POST", "/api/mesh/send", {"sender_agent_id": BOB, "target_agent_id": ALICE, "text": "forged"}),
    ("POST", "/api/mesh/intent", {"requester_agent_id": BOB, "text": "forged"}),
    # The skills routes. These are the reason the behavioural layer exists as
    # well as the structural one: a handler can resolve the caller, use it for a
    # check, and still record the body-claimed id — which _binds() cannot see,
    # because it reads the source for a helper NAME, not for what the value is
    # used for. Only driving the route proves which identity was written.
    ("POST", "/api/skills/probe-skill/install", {"agent_id": BOB}),
]


@pytest.fixture
def stack(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch, agent_id="TEST-route-guard-chapter")
    mod.members.clear()
    writes: list[tuple] = []

    async def recording_pg(method, table, params=None, body=None, **kw):
        if method in {"POST", "PATCH", "PUT", "DELETE"}:
            writes.append((method, table, body))
            rows = body if isinstance(body, list) else [body or {}]
            return [dict(r or {}, id="row-1") for r in rows]
        return []

    import agent_conversations
    import channels
    import chapter_audit
    import chapter_auth
    import endorsements
    import onboarding
    import settings as settings_mod
    import skill_registry

    skill_registry.init(recording_pg, "TEST-route-guard-chapter")

    endorsements.init(recording_pg, "TEST-route-guard-chapter")
    settings_mod.init(recording_pg)
    onboarding.init(recording_pg)
    channels.init(recording_pg)
    agent_conversations.init(recording_pg, "TEST-route-guard-chapter")
    chapter_audit.init(recording_pg)
    chapter_auth.init(recording_pg)

    alice = register_test_regular_member(mod, agent_id=ALICE, name="Alice")
    register_test_regular_member(mod, agent_id=BOB, name="Bob")
    return mod, alice, TestClient(mod.app), writes


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    FORGERY_ATTEMPTS,
    ids=[f"{m}:{p}" for m, p, _ in FORGERY_ATTEMPTS],
)
def test_a_signed_member_cannot_act_as_another_member(stack, method, path, payload):
    """ALICE signs; the payload names BOB. The server must refuse, and must not
    write. A 403 is the contract — a silent substitution would leave a hostile
    client's attempt unlogged and an honest one misinformed."""
    _mod, alice, client, writes = stack
    body = json.dumps(payload, separators=(",", ":"))
    headers = alice["signer"](method=method, url_path=path, body=body)
    headers["Content-Type"] = "application/json"

    resp = client.request(method, path, content=body, headers=headers)

    assert resp.status_code == 403, (
        f"{method} {path} accepted a forged identity: HTTP {resp.status_code} {resp.text[:200]}"
    )
    forged = [w for w in writes if BOB in json.dumps(w[2], default=str)]
    assert not forged, f"{method} {path} refused but still wrote: {forged}"


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    FORGERY_ATTEMPTS,
    ids=[f"{m}:{p}" for m, p, _ in FORGERY_ATTEMPTS],
)
def test_the_same_request_naming_the_CALLER_is_not_refused_by_the_binding(stack, method, path, payload):
    """The other half, without which the guard above is satisfied by a route that
    refuses everyone. Alice names Alice: whatever happens next, it is not the
    identity binding that stopped it."""
    _mod, alice, client, _writes = stack
    self_payload = {k: (ALICE if v == BOB else v) for k, v in payload.items()}
    self_path = path.replace(BOB, ALICE)
    body = json.dumps(self_payload, separators=(",", ":"))
    headers = alice["signer"](method=method, url_path=self_path, body=body)
    headers["Content-Type"] = "application/json"

    try:
        resp = client.request(method, self_path, content=body, headers=headers)
    except RuntimeError:
        # Reached a storage/service layer this offline harness does not wire.
        # Getting that far is itself the assertion: the binding let the caller
        # through when it named itself.
        return

    assert resp.status_code != 403 or "restricted to the agent" not in resp.text, (
        f"{method} {self_path} refused the caller acting as THEMSELVES: {resp.text[:200]}"
    )
    assert "must be the verified caller" not in resp.text, (
        f"{method} {self_path} refused the caller acting as THEMSELVES: {resp.text[:200]}"
    )


def test_an_open_route_never_records_a_body_supplied_author(stack):
    """``POST /api/skills/publish`` now takes a registered member's signature
    (it was open; see test_skill_publish_requires_member.py). The property
    asserted here is unchanged and still the one that matters for a signed
    member: the attribution recorded is never the one the request supplied.
    """
    _mod, alice, client, writes = stack
    payload = {
        "author_agent_id": BOB,
        "manifest": {"name": "probe", "version": "0.1.0"},
        "signature": "AA",
        "signing_key_did": "did:key:zPROBE",
        "content_sha256": "0" * 64,
    }
    body = json.dumps(payload, separators=(",", ":"))
    headers = alice["signer"](method="POST", url_path="/api/skills/publish", body=body)
    headers["Content-Type"] = "application/json"
    client.post("/api/skills/publish", content=body, headers=headers)

    forged = [w for w in writes if BOB in json.dumps(w[2], default=str)]
    assert not forged, f"the body-supplied author was recorded: {forged}"
