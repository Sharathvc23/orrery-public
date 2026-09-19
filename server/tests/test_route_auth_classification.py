"""Every anonymously-reachable route is classified, not merely discovered.

``auth_verify.is_open_path`` and ``auth_verify.requires_auth`` are two
independent predicates, and a route can be False on both: not declared open,
and not flagged as requiring auth either. The middleware then lets it through
unauthenticated regardless — ``/api/thoughts`` is the route that surfaced
this: reading either predicate alone suggests the route is gated, and
neither actually gates it. An enumeration over ``chapter_agent.app.routes``
found 60 of 192 registered routes in this THIRD STATE.

WHAT THIS GUARD ENFORCES

The set of registered routes is DERIVED — ``_registered_routes`` walks
``chapter_agent.app.routes``, so a route cannot hide from it by being added
without touching this file. The set of third-state routes considered SAFE is
DECLARED below, because no rule over paths decides it: a route's actual
authorization posture is a fact about its handler body, which nothing except
reading that body establishes.

``test_every_third_state_route_is_classified`` is where the two halves meet: a
route the scan finds in the third state, that no declaration covers, fails the
suite. A route added tomorrow with no classification cannot land silently in
the gap this file exists to close.

THE THREE CLASSES, AND THE HARD CONSTRAINT THEY EXIST TO HONOR

Classifying a route does NOT make it safe. The risk this file exists to avoid
is a declaration laundering an unauthenticated route into looking handled — so
the first two classes are for routes whose CURRENT state is DEFENSIBLE, and a
route that is merely unexamined does not qualify for either of them.

``HANDLER_GATED_PATHS``       the handler itself performs a real authorization
                               check with a deny path (401/403, or a 404
                               dev-only gate) before returning data. Every
                               entry here was verified by READING that
                               handler's full body, once, by hand — never by
                               grepping for a marker string. A route not read
                               in full does not go on this list.
``INTENTIONALLY_PUBLIC_PATHS`` the response is defensibly non-sensitive: either
                               the code states an explicit, checkable
                               rationale for staying open (a docstring
                               reasoning about why, not merely describing
                               what), or the returned data was traced to a
                               verified-static, non-per-principal source (a
                               module-level vocabulary constant, an aggregate
                               SQL view with no identifying columns) with
                               nothing else in the response.
``UNCLASSIFIED_PENDING_RULING`` the guard ACCEPTS these, but this is a backlog
                               with an owner, not an exemption. A route lands
                               here when it has no in-handler check AND no
                               defensible public-intent evidence, or when
                               reading it surfaced something that specifically
                               needs a ruling (a discrepancy between a
                               docstring's claim and what the code actually
                               does, a route that is the near-duplicate of an
                               already-declared-open one, an apparent
                               authorization check that does not actually
                               authorize anything). The length of this list is
                               itself the finding: 23 of the original 60 landed
                               here at creation; it shrinks as each is ruled on
                               and resolved into a real fix or classification.
"""

from __future__ import annotations

import pytest

# ══════════════════════════════════════════════════════════════════════
# The declaration
# ══════════════════════════════════════════════════════════════════════

# fmt: off
HANDLER_GATED_PATHS: dict[tuple[str, str], str] = {
    ("GET", "/api/admin/llm/spend"): (
        "Calls _authorize_admin(request) first and returns its denial response "
        "unless ok — a real signed-admin-or-bearer check with a deny path, before "
        "any data is read."
    ),
    ("GET", "/api/admin/trust/drift"): (
        "Same _authorize_admin(request) gate as /api/admin/llm/spend, checked "
        "before the drift computation runs."
    ),
    ("GET", "/api/agents/{agent_id}/aae-events"): (
        "Conditional, and both branches were read. When the agent's chronicle is "
        "not opted into public (agents.config.chronicle_public), the handler "
        "requires _resolve_caller(request) (the verified, non-spoofable caller) "
        "to equal the path's agent_id, or a valid X-Admin-Token, and otherwise "
        "answers exactly as it answers an unknown id — an empty list. It used to "
        "raise a 403 naming the chronicle as internal, which told a stranger the "
        "id exists while an unknown id got 200 and empty: an oracle by status "
        "code. Only an explicit per-agent opt-in flows through open."
    ),
    ("GET", "/api/approvals"): (
        "Calls _authorize_role(request, allowed_roles={leader,advisor,mentor,admin}) "
        "before touching governance.list_pending; returns the denial on failure."
    ),
    ("GET", "/api/audit"): (
        "Returns 404 immediately unless arp_mod.is_offline() is true. is_offline() "
        "reads a module-level flag set once at startup from whether Postgres is "
        "configured — not attacker-influenced. A real deployment (Postgres "
        "configured) always 404s here; the receipt dump only runs in local/dev "
        "mode with no durable backend to leak."
    ),
    ("GET", "/api/broadcast/log"): (
        "caller = _resolve_caller(request); returns 401 JSONResponse if empty, "
        "before reading broadcast_log. _resolve_caller reads request.state.agent_id, "
        "set by the middleware only after a valid Ed25519 signature — not the "
        "spoofable X-Agent-ID header."
    ),
    ("GET", "/api/chapter/allowlist/{chapter_id}"): (
        "FIXED: used to answer for an arbitrary chapter_id with no auth at all. "
        "Now calls _authorize_role(request, allowed_roles={leader,admin}) and "
        "rejects (403) any chapter_id other than this org's own AGENT_ID — same "
        "'a request cannot name an org it is not' scoping the allowlist/add and "
        "allowlist/remove write routes on this same resource already enforced."
    ),
    ("GET", "/api/chapter/audit/{chapter_id}"): (
        "FIXED: used to answer for an arbitrary chapter_id with no auth at all — "
        "the same audit ledger the admin-gated /admin/api/audit twin already "
        "serves, correctly gated and hardcoded to chapter_id=AGENT_ID. Now calls "
        "_authorize_admin(request) and rejects (403) any other chapter_id."
    ),
    ("GET", "/api/chapter/audit/{chapter_id}/export.jsonl"): (
        "Same fix as GET /api/chapter/audit/{chapter_id}: admin-gated twin of "
        "/admin/api/audit/export, scoped to this org."
    ),
    ("GET", "/api/chapter/audit/{chapter_id}/verify"): (
        "Same fix as GET /api/chapter/audit/{chapter_id}: admin-gated twin of "
        "/admin/api/audit/verify, scoped to this org."
    ),
    ("GET", "/api/chapter/sso/{chapter_id}"): (
        "Calls _authorize_role(request, allowed_roles={leader,admin}) and then also "
        "checks the path chapter_id equals this org's own AGENT_ID (403 otherwise) "
        "before reading chapter_auth.get_sso_config, which holds this org's actual "
        "issuer/client id."
    ),
    ("GET", "/api/checkpoint"): (
        "Same is_offline()-gated, 404-in-production shape as /api/audit; verified "
        "in the same read."
    ),
    ("GET", "/api/checkpoint/proof/{receipt_id}"): (
        "Same is_offline()-gated, 404-in-production shape as /api/audit."
    ),
    ("GET", "/api/dsar/export"): (
        "Calls _authorize_admin(request) before dsar.export_subject_data; returns "
        "the denial on failure. Docstring: admin-gated so a random caller cannot "
        "dump an arbitrary data subject's records."
    ),
    ("GET", "/api/dsar/inventory"): (
        "Same _authorize_admin(request) gate as /api/dsar/export."
    ),
    ("GET", "/api/intents"): (
        "caller = _resolve_caller(request); 401 if empty. Comment records this was "
        "the third unauthenticated hole on this exact surface (bulk-enumerable via "
        "?agent_id) and the fix is to ignore any client-supplied id and use only "
        "the verified caller."
    ),
    ("GET", "/api/intents/introductions/{agent_id}"): (
        "Same _resolve_caller + 401 shape as /api/intents; comment records "
        "introductions expose both parties' identity, so only the verified "
        "caller's own introductions are ever read, never the path's agent_id."
    ),
    ("GET", "/api/intents/pending/{agent_id}"): (
        "Same _resolve_caller + 401 shape; the path agent_id is ignored in favor "
        "of the verified caller."
    ),
    ("GET", "/api/intents/{intent_id}"): (
        "Same _resolve_caller + 401 shape, then passes the verified caller (not "
        "anything from the path or body) into intents.get_intent_detail for "
        "per-intent ownership authorization."
    ),
    ("GET", "/api/invites"): (
        "Calls _authorize_role(request, allowed_roles={leader,admin}) before "
        "listing invites; returns the denial on failure."
    ),
    ("GET", "/api/invites/"): (
        "Same handler (list_invites) and same _authorize_role gate as "
        "GET /api/invites — registered as a second route on the identical function."
    ),
    ("GET", "/api/receipts/ledger/{principal_did}"): (
        "Same is_offline()-gated, 404-in-production shape as /api/audit. Docstring: "
        "the full ledger exposes receipt contents, so it stays offline-only; "
        "production serves the contents-free facet at /agentfacts/{id}.json instead."
    ),
    ("GET", "/api/receipts/recent"): (
        "Same is_offline()-gated, 404-in-production shape. Docstring: a production "
        "chapter (Postgres configured) never exposes its Issuer Log through this "
        "route; GET /api/receipts is the authenticated, principal-scoped production "
        "surface."
    ),
    ("GET", "/api/sessions/"): (
        "FIXED, formerly a broken gate: the /-suffixed twin of GET /api/sessions "
        "(bare path, added to auth_verify.IDENTITY_AWARE_OPEN_PATHS). Never took "
        "the is_open_path short-circuit itself, so the generic middleware path "
        "already ran verify_request unconditionally for it; the handler now reads "
        "request.state.verified (set only after a real signature check) instead "
        "of the spoofable X-Auth-Status request header to decide the anonymous vs. "
        "authenticated tier. Guarded by "
        "test_sessions_spoofed_x_auth_status_header_does_not_unlock_the_rich_tier "
        "and test_sessions_verified_request_state_unlocks_the_rich_tier."
    ),
    ("GET", "/api/runtimes/"): (
        "FIXED, same shape as /api/sessions/ above: the /-suffixed twin of the "
        "already-open GET /api/runtimes. The handler used to return per-agent "
        "provider, model, thought_count and conversation_count unconditionally — "
        "the exact class of data /api/sessions was hardened to hide. Now reads "
        "request.state.verified (bare path added to IDENTITY_AWARE_OPEN_PATHS) "
        "and serves the same minimal/full tiering as /api/sessions. Guarded by "
        "test_runtimes_spoofed_x_auth_status_header_does_not_unlock_the_rich_tier "
        "and test_runtimes_verified_request_state_unlocks_the_rich_tier."
    ),
    ("GET", "/api/ledger/earnings"): (
        "FIXED: the docstring said 'caller should pass their own did:key', but "
        "did was a plain, unverified query parameter — any caller could read any "
        "DID's earnings, including a different org's. Now requires a resolved, "
        "signature-verified caller (_resolve_caller) whose OWN did:key replaces "
        "any client-supplied did (same idiom as the self-scoped today/"
        "advisor-earnings surfaces); the chapter:<id> aggregate form is reachable "
        "only by this chapter's own signed caller or a valid admin bearer. "
        "Guarded by tests/test_ledger_earnings_self_scoped.py."
    ),
}

INTENTIONALLY_PUBLIC_PATHS: dict[tuple[str, str], str] = {
    ("GET", "/api/event-catalog"): (
        "The event-bus contract: per event type, the min trust to subscribe and "
        "which payload fields this server authored versus which arrived from a "
        "member, a peer org or a language model. Content traced: every value is "
        "built from module-level constants in event_types (EventType, "
        "MIN_TRUST_TO_SUBSCRIBE, UNTRUSTED_TEXT_FIELDS, "
        "SERVER_AUTHORED_TEXT_FIELDS) — the handler reads no database, takes no "
        "parameters, and the response varies by nothing except AGENT_ID, which "
        "/health already serves. Public on purpose rather than incidentally: a "
        "statement about which text a subscriber must escape is worthless if "
        "reading it requires being a subscriber already, and the set of "
        "consumers is unbounded because three of the four text-bearing event "
        "types are trust 0.0."
    ),
    ("GET", "/api/events"): (
        "MOVED HERE from UNCLASSIFIED_PENDING_RULING: previously named only by "
        "a sibling's docstring as deliberately keyless, with no rationale in "
        "its own handler and an unvetted response. Now the handler's own "
        "docstring states the rationale (chapter_agent._PUBLIC_CORS_PATHS "
        "declares it, and the dedicated public_read_cors middleware forces "
        "ACAO:* on it regardless of profile), and the one field that made the "
        "response unvetted — suggested_speakers, a real member display name "
        "the event-proposal LLM was prompted with — is redacted before return "
        "(thought_redaction.redact_suggested_speakers). The rest of the row "
        "(title, description, event_type, status) was already non-per-"
        "principal content. Guarded by "
        "tests/test_group2_events_speaker_redaction.py."
    ),
    ("GET", "/.well-known/nanda-chapter-rotation.json"): (
        "Explicit design statement in the handler docstring, spec-anchored "
        "(spec/0.6 SS8.5.2): unauthenticated by necessity, since a peer needs this "
        "document exactly when its pin on our key no longer matches and any auth "
        "we demanded would be auth it cannot satisfy. Content traced: each entry "
        "is a stored 'attestation' dict (federation_policy.published_rotation_chain) "
        "— a signed rotation record, public key plus signature over public fields, "
        "nothing else."
    ),
    ("GET", "/api/agents/{agent_id}/trust"): (
        "Handler-gated since the anonymous-disclosure close: the route answered "
        "200 for every member and 404 for every non-member to a caller with no "
        "credential — the membership oracle the profile gate closed, one path "
        "over. It now consults chapter_agent._member_disclosable_to: a member "
        "who opted into the listing is served to anyone (as the profile is), a "
        "signed MEMBER may read any member's score, and a stranger asking about "
        "a member who did not opt in gets the 404 an unknown id gets, byte for "
        "byte. The earlier ruling that the route 'was always meant to be open' "
        "predates the consent model and is superseded by it; its one external "
        "consumer (agent/community_member/identity_trust.py) now signs. The one "
        "previously-unvetted part of the response — history's "
        "source_agent_id and free-text reason, which named a THIRD PARTY "
        "(the endorser) and in one call site embedded their raw agent_id "
        "directly in the reason string — is now redacted to "
        "endorser_role-grain before return (chapter_agent."
        "_redact_trust_history), which is what the docstring's own "
        "'redacted to endorser_role-grain' line already specified. Guarded "
        "by tests/test_group2_trust_history_redaction.py."
    ),
    ("GET", "/api/approvals/dashboard"): (
        "Docstring claims counts only, no identifying data; traced to source. "
        "governance.get_dashboard() reads the leader_dashboard SQL view "
        "(infra/init.sql), whose columns are pending_count, expiring_soon_count, "
        "approved_last_24h, rejected_last_24h, and pending_by_kind (a kind-to-count "
        "JSON object) — pure aggregates, no member id, name or approval content in "
        "any column."
    ),
    ("GET", "/api/approvals/kinds"): (
        "Returns governance.APPROVAL_KINDS / OPERATIONAL_KINDS, module-level set "
        "literals of vocabulary strings (governance.py) — a fixed enum, not data "
        "about any approval, member or org."
    ),
    ("GET", "/api/chapter/providers"): (
        "Returns chapter_auth.valid_providers(), which returns "
        "list(VALID_PROVIDERS) — a module-level constant naming supported SSO "
        "provider TYPES. Distinct from this org's actual configured issuer/client "
        "id, which lives behind the role-gated GET /api/chapter/sso/{chapter_id}."
    ),
    ("GET", "/api/federation/divergence"): (
        "Explicit design statement in the docstring: findings are public-tier "
        "because the registry records they compare are already public via each "
        "registry's /api/agents, so this route is deliberately keyless like the "
        "sibling /api/events and /api/digest. (Those two siblings are NOT "
        "separately classified here — see UNCLASSIFIED_PENDING_RULING; this "
        "route's own docstring reasons about itself, and that reasoning is not "
        "independently verified for the siblings it names.)"
    ),
    ("GET", "/api/invites/{token}/qr.svg"): (
        "Explicit design statement in the docstring: the QR is only a carrier for "
        "the join URL and grants nothing the URL does not; the handler does NOT "
        "look up, create or validate the token, specifically because doing so "
        "would turn the route into an oracle for guessing valid invite tokens. "
        "An unknown token yields a valid-looking QR pointing at a landing page "
        "that then refuses."
    ),
    ("GET", "/api/trust/drift-status"): (
        "Explicit design statement in the docstring: a chapter must not be able "
        "to hide trust drift behind an admin gate, so this exposes drift_count "
        "and drifts without credentials, deliberately mirroring the gated "
        "/api/admin/trust/drift (same computation) for the full operator view. "
        "A conformant chapter's list is empty, so nothing is exposed in the "
        "passing case; a non-empty list is the intended public integrity signal."
    ),
    ("GET", "/api/voice/providers"): (
        "Returns voice.stt_providers()/tts_providers(), module-level constant "
        "catalogs (provider ids/labels) — no per-org configuration or credentials."
    ),
    ("GET", "/api/voice/voices"): (
        "Returns voice.voice_options_for(...), a lookup into the module-level "
        "VOICES_BY_PROVIDER constant (label/value pairs) — same static-catalog "
        "shape as /api/voice/providers."
    ),
    ("GET", "/console"): (
        "Serves the bundled static console/index.html via FileResponse — same "
        "shape and same rationale as ADMIN_OPEN_PATHS' /admin/ and "
        "/admin/index.html (auth_verify.py): the static shell is open so an "
        "operator can load the page and paste credentials; the shell contains no "
        "data of its own, and every API call it makes client-side is separately "
        "authorized (/admin/api/*, or role-gated routes above)."
    ),
    ("GET", "/console/"): (
        "Same handler (console_ui) and same reasoning as GET /console — registered "
        "as a second route on the identical function."
    ),
    ("GET", "/health/surfaces"): (
        "Returns surface_cache.stats() — traced to source: per-surface-name "
        "counters (hits, misses, builds, avg_ms, last_built_at), all in-memory and "
        "aggregate. No principal, member or content identifier in any field."
    ),
    ("GET", "/join"): (
        "Serves the bundled static join/index.html via FileResponse. Docstring: "
        "'the QR landing' — the entire purpose of this page is to be reachable by "
        "an unauthenticated visitor scanning an invite QR, so pre-auth reachability "
        "is the requirement, not an oversight. Same no-data-in-the-shell reasoning "
        "as /console."
    ),
    ("GET", "/join/"): (
        "Same handler (join_ui) and same reasoning as GET /join."
    ),
    ("GET", "/receipts"): (
        "Serves the bundled static receipts/index.html via FileResponse. Same "
        "no-data-in-the-shell reasoning as /console; the page's own data calls go "
        "through GET /api/receipts/recent, which is itself dev-only gated above."
    ),
    ("GET", "/receipts/"): (
        "Same handler (receipts_ui) and same reasoning as GET /receipts."
    ),
    ("GET", "/ui/{asset}"): (
        "Serves one of a hard-coded seven-file allowlist of console/join JS "
        "modules by exact name match (never a path join on the URL parameter); "
        "unknown names 404. The files are the static shells' own script bundles, "
        "not data."
    ),
    ("GET", "/version"): (
        "Explicit design statement in the docstring: version info is non-sensitive "
        "and operators must be able to read it from external smoke-test scripts "
        "that hold no admin credentials. Content traced: build metadata "
        "(git_commit, git_branch, build_timestamp, protocol/arp version, agent "
        "name/id) — no secret or per-member field."
    ),
    ("GET", "/api/digest"): (
        "MOVED HERE from UNCLASSIFIED_PENDING_RULING: previously named only by a "
        "sibling's docstring as deliberately keyless. The route's own docstring "
        "now states the rationale and traces content: think_cycle.think_digest's "
        "highlights are aggregate counts, and the LLM summary is prompted from "
        "those counts alone, not from any member's name."
    ),
    ("GET", "/api/mesh/state"): (
        "No in-handler check, but the docstring now traces every field: "
        "mesh.get_mesh_state returns aggregate counts plus chapter-level "
        "opportunities (no individual agent), and the one per-principal field "
        "(my_trust, gated behind an explicit ?target=) is the same "
        "already-open shape as GET /api/agents/{id}/trust's score/tier."
    ),
    ("GET", "/api/mesh/trust/{agent_id}"): (
        "No in-handler check, but the docstring now traces it: mesh.my_trust "
        "returns the identical {agent_id, trust_score, tier} shape already open "
        "at GET /api/agents/{agent_id}/trust's score/tier fields, reached "
        "through a second, mesh-namespaced path — not a new disclosure."
    ),
    ("GET", "/api/org/join-policy"): (
        "MOVED HERE from UNCLASSIFIED_PENDING_RULING: the /join-landing-page "
        "rationale was this guard's own inference before, not a statement in "
        "the code. The docstring now cites the concrete consumer "
        "(static/ui/join-boot.js, join.js) that reads this before a visitor "
        "has any credential, and the response is a single value from a closed, "
        "org-wide vocabulary — no per-member field."
    ),
    ("GET", "/api/thoughts"): (
        "MOVED HERE from UNCLASSIFIED_PENDING_RULING, its own seed case: "
        "previously left unclassified because the posture read as illegible, "
        "not settled. The docstring now states the redaction is what makes "
        "this defensible, not an assumption that the prose is safe — hidden-"
        "prefix rows are dropped outright, the unredactable targets field is "
        "dropped, and every surviving row passes through "
        "thought_redaction.redact_deep before the response is built."
    ),
}

UNCLASSIFIED_PENDING_RULING: dict[tuple[str, str], str] = {}
# fmt: on

CLASSES = {
    "HANDLER_GATED_PATHS": HANDLER_GATED_PATHS,
    "INTENTIONALLY_PUBLIC_PATHS": INTENTIONALLY_PUBLIC_PATHS,
    "UNCLASSIFIED_PENDING_RULING": UNCLASSIFIED_PENDING_RULING,
}


# ══════════════════════════════════════════════════════════════════════
# The scan
# ══════════════════════════════════════════════════════════════════════


def _registered_routes(app) -> list[tuple[str, str]]:
    """Every (method, path) FastAPI actually serves. HEAD/OPTIONS excluded (no
    predicate distinguishes them from their GET twin) and de-duplicated (a path
    registered twice, e.g. with/without a trailing slash on the SAME handler,
    yields one entry per method+path pair, not one per decorator)."""
    seen: set[tuple[str, str]] = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or not methods:
            continue
        for method in methods:
            if method in ("HEAD", "OPTIONS"):
                continue
            seen.add((method, path))
    return sorted(seen)


def _third_state(routes: list[tuple[str, str]]) -> list[tuple[str, str]]:
    import auth_verify

    return [(m, p) for m, p in routes if not auth_verify.is_open_path(m, p) and not auth_verify.requires_auth(m, p)]


@pytest.fixture(scope="module")
def routes():
    import chapter_agent

    found = _registered_routes(chapter_agent.app)
    assert found, "the route scan found nothing; it is broken, not clean"
    return found


# ══════════════════════════════════════════════════════════════════════
# The declaration covers the code, and the classes are disjoint
# ══════════════════════════════════════════════════════════════════════


def test_the_scan_finds_a_realistic_number_of_routes(routes):
    """A scan that silently stopped walking app.routes would report a tiny tree."""
    assert len(routes) > 100, f"only {len(routes)} routes found; the scan is broken"


def test_every_third_state_route_is_classified(routes):
    third_state = _third_state(routes)
    declared = set().union(*(set(c) for c in CLASSES.values()))
    missing = sorted(k for k in third_state if k not in declared)
    assert not missing, (
        "these routes are anonymously reachable (is_open_path is False AND "
        "requires_auth is False) and not classified:\n  "
        + "\n  ".join(f"{m} {p}" for m, p in missing)
        + "\n\nAdd each to HANDLER_GATED_PATHS (verified by reading the handler "
        "in full), INTENTIONALLY_PUBLIC_PATHS (a defensible, checkable "
        "rationale), or UNCLASSIFIED_PENDING_RULING (a backlog entry, not an "
        "exemption) with a reason. Classifying it is where someone decides "
        "whether it is actually safe."
    )


def test_no_route_is_in_two_classes():
    seen: dict[tuple[str, str], str] = {}
    for class_name, members in CLASSES.items():
        for key in members:
            assert key not in seen, f"{key} is in both {seen[key]} and {class_name}"
            seen[key] = class_name


def test_classified_routes_still_exist_and_are_still_third_state(routes):
    """A classification for a route that was removed, renamed, or that moved
    into is_open_path/requires_auth coverage is a claim about code that is no
    longer true, and it hides that the underlying gap closed (or moved)."""
    registered = set(routes)
    third_state = set(_third_state(routes))
    declared = set().union(*(set(c) for c in CLASSES.values()))

    gone = sorted(k for k in declared if k not in registered)
    assert not gone, "classified but no longer a registered route:\n  " + "\n  ".join(f"{m} {p}" for m, p in gone)

    resolved = sorted(k for k in declared if k in registered and k not in third_state)
    assert not resolved, (
        "classified as third-state but is_open_path/requires_auth now cover it "
        "directly — remove it from its registry, the gap it recorded is closed:\n  "
        + "\n  ".join(f"{m} {p}" for m, p in resolved)
    )


def test_every_classification_states_a_reason():
    for class_name, members in CLASSES.items():
        for key, reason in members.items():
            assert len(reason.strip()) >= 25, f"{class_name}[{key}] has no real reason: {reason!r}"


# ══════════════════════════════════════════════════════════════════════
# The guard detects a new violation
# ══════════════════════════════════════════════════════════════════════


def test_a_newly_added_unclassified_route_is_caught():
    """Proven against the same functions the real guard uses, on a synthetic
    route list, so this stays a permanent regression test rather than a
    one-time manual plant. (The one-time plant — adding a real route to
    chapter_agent.py, watching test_every_third_state_route_is_classified
    redden, reverting — is recorded in the PR description, not re-run here.)
    """
    import auth_verify

    probe = ("GET", "/api/__never_classified_probe__")
    assert not auth_verify.is_open_path(*probe), "probe path collides with a real OPEN_PATHS/prefix entry"
    assert not auth_verify.requires_auth(*probe), "probe path collides with a real REQUIRE_AUTH entry"

    declared = set().union(*(set(c) for c in CLASSES.values()))
    assert probe not in declared, "the probe path collides with a real classification"

    synthetic_routes = [probe, ("GET", "/health")]  # /health resolves open — must NOT be flagged
    third_state = _third_state(synthetic_routes)
    assert third_state == [probe], f"expected only the probe in the third state, got {third_state}"

    missing = [k for k in third_state if k not in declared]
    assert missing == [probe], "the guard did not flag the newly-added unclassified route"
