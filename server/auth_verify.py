"""
Server-Side Auth Verification — verifies signed requests from community-member clients.

Checks X-Agent-ID, X-Agent-Signature, X-Agent-Timestamp headers on incoming requests.
Uses TOFU (Trust On First Use) for first registration — stores public key on first contact.

Supported signature schemes (via X-Agent-Sig-Scheme header):
  - hmac-sha256    (legacy v0.1 era)
  - ed25519        (the org protocol v0.2 — body:agent_id:timestamp)
  - ed25519+nonce  (the org protocol v0.3 — method:url_path:body:agent_id:timestamp:nonce)

Endpoint classification:
  OPEN: no auth required (GET /health, GET /api/surfaces/*, GET /api/federation)
  WARN: log missing auth but allow (transition period)
  REQUIRE: reject without valid auth (GET /api/members, POST /api/members re-reg,
           DELETE, POST /api/intents)
"""

import base64
import hashlib
import hmac
import os
import time
from collections import OrderedDict
from collections.abc import Callable

# Stored agent keys: agent_id → {"public_key": str, "signing_secret": str, "ed25519_pubkey": str}
_agent_keys: dict[str, dict] = {}

#: Who may bootstrap a key by trust-on-first-use. A predicate over agent_id,
#: installed by the app (``chapter_agent`` answers "is this a registered
#: member"). None — the standalone default — means NOBODY: fail closed.
#:
#: Without it, TOFU verified anyone. A caller who had never registered could
#: mint a keypair, pick any agent_id, sign a GET, and be ``tofu_accepted`` —
#: which set ``request.state.verified`` and passed every signed-only gate:
#: the member directory the gate exists to close, the directory surfaces, the
#: catalog's member list, another member's endorsements. Measured, not
#: inferred. TOFU is spec/0.2 §3.1's bootstrap for a REGISTERED member whose
#: key is not yet on file; it was never a registration path, and treating the
#: possession of some private key as membership is what made it one.
_tofu_eligible: Callable[[str], bool] | None = None


def set_tofu_eligibility(predicate: Callable[[str], bool] | None) -> None:
    """Install the predicate deciding which agent_ids may TOFU-bootstrap a key."""
    global _tofu_eligible
    _tofu_eligible = predicate


def tofu_eligible(agent_id: str) -> bool:
    """Whether ``agent_id`` may have a key pinned on first signed contact."""
    return _tofu_eligible is not None and bool(_tofu_eligible(agent_id))


def is_self_authenticating_path(path: str) -> bool:
    """The A2A interop surfaces, where a signature is ACCOUNTABILITY, not membership.

    ``/a2a`` and ``/run`` are invoked by resolvers and agents that never joined
    this org; the caller proves possession of the key behind its did:key so
    the exchange is attributable, and that is all the signature means there.
    Everywhere else a verified signature is read as "this member", which is
    only true if the id IS a member — so the same set that exempts these paths
    from method binding also decides where a non-member's signature counts.
    """
    bare = path.split("?", 1)[0]
    return bare in METHOD_BINDING_EXEMPT_PATHS or any(bare.startswith(p) for p in METHOD_BINDING_EXEMPT_PREFIXES)


# Nonce store for challenge-response: nonce → (agent_id, expires_at)
_nonces: dict[str, tuple[str, float]] = {}

# v0.3 replay-protection store: bounded LRU of (agent_id, nonce) → expires_at.
# A duplicate within the TTL is rejected with reason `nonce_replay`. Bounded
# so a misbehaving client cannot exhaust memory; on overflow we evict oldest,
# which means a very old request whose nonce row was evicted may slip back
# in — but that request would also be expired by the timestamp window check,
# so the replay store and timestamp window degrade gracefully together.
_v03_replay_store: "OrderedDict[tuple[str, str], float]" = OrderedDict()
_V03_REPLAY_TTL_SECONDS = 600
_V03_REPLAY_STORE_MAX = 100_000

# ─── OpenClaw skill version gate ───────────────────────────────────
#
# Quarantines outdated openclaw-skill clients (which carry confirmed
# vulnerabilities — signing-oracle, cache-poisoning, identity-swap,
# audit-chain rewrite, see openclaw-skill/CHANGELOG.md 0.5.0). Any
# inbound signed request whose origin is openclaw AND whose
# `X-Openclaw-Skill-Version` header is missing or below the minimum
# is rejected with HTTP 426 Upgrade Required and a JSON body that
# tells the calling LLM the exact upgrade command to run.
#
# Sovereign-origin clients (community-member SDK, custom clients)
# do NOT carry this header and are NOT gated by this check — the
# advisory is openclaw-skill-specific.
#
# ADVISORY, NOT A SECURITY CONTROL. `origin` is self-asserted by
# the client (peeked from the register body / stored from it). A `did:key`
# attests key ownership, not client-SOFTWARE identity, so `origin` cannot
# be bound to the verified key — a compromised client bypasses this gate
# by declaring `origin="sovereign"`. That is acceptable by design: this
# gate is a courtesy nudge to quarantine HONEST outdated clients, not a
# defense against a malicious one. The real boundary is Ed25519 signature
# verification (verify_signed_request) + the authz checks. See SECURITY.md.
OPENCLAW_VERSION_HEADER = "x-openclaw-skill-version"
MIN_OPENCLAW_SKILL_VERSION: tuple[int, int, int] = (0, 5, 1)


def _parse_openclaw_version(raw: str) -> tuple[int, int, int] | None:
    """Parse a major.minor.patch string. Return None if unparseable.

    Three-component semver only; pre-release / build-metadata
    suffixes are not supported (the openclaw-skill does not publish
    them). Anything malformed → None → treated as below-minimum.
    """
    if not raw:
        return None
    parts = raw.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def check_openclaw_version(headers: dict, origin: str) -> dict | None:
    """If origin=openclaw and the skill version is too old, return the
    426 response body to send. Otherwise return None (pass through).

    ``headers`` keys are lowercased per FastAPI's Starlette layer.
    The header name lookup uses both lowercase and title-case for
    safety against alternate middlewares.

    Returns a JSON-serializable dict the caller wraps in a 426
    JSONResponse. The caller is responsible for the HTTP status
    code; this function only decides whether to gate.
    """
    if origin != "openclaw":
        return None
    raw = headers.get(OPENCLAW_VERSION_HEADER, "") or headers.get("X-Openclaw-Skill-Version", "")
    parsed = _parse_openclaw_version(raw)
    if parsed is not None and parsed >= MIN_OPENCLAW_SKILL_VERSION:
        return None
    return {
        "error": "openclaw_skill_outdated",
        "current_version": raw or "<missing>",
        "minimum_version": ".".join(str(p) for p in MIN_OPENCLAW_SKILL_VERSION),
        "advisory": (
            "openclaw-skill versions below "
            f"{'.'.join(str(p) for p in MIN_OPENCLAW_SKILL_VERSION)} are blocked "
            "due to a confirmed security advisory (signing-oracle, "
            "cache-poisoning, identity-swap, audit-chain rewrite). "
            "Your installed version cannot talk to this chapter until "
            "you upgrade."
        ),
        "upgrade_command": "openclaw skill install nanda-chapter --force",
        "changelog_url": "https://projectnanda.org/skills/nanda-chapter#changelog",
    }


def _v03_replay_check_and_record(agent_id: str, nonce: str, now: float | None = None) -> bool:
    """Return True if (agent_id, nonce) is fresh; record it. False if replay.

    Sweeps expired entries on every call. Bounded; oldest entries evicted on
    overflow. Per spec/0.3/signing.md the replay-protection TTL is at least
    600 s (twice the timestamp window) to avoid edge cases at the boundary.
    """
    n = float(now if now is not None else time.time())
    cutoff = n - _V03_REPLAY_TTL_SECONDS
    while _v03_replay_store:
        oldest_key, oldest_exp = next(iter(_v03_replay_store.items()))
        if oldest_exp < cutoff:
            _v03_replay_store.popitem(last=False)
        else:
            break
    key = (agent_id, nonce)
    if key in _v03_replay_store:
        return False
    _v03_replay_store[key] = n
    while len(_v03_replay_store) > _V03_REPLAY_STORE_MAX:
        _v03_replay_store.popitem(last=False)
    return True


# Auth enforcement levels
OPEN_PATHS = {
    "/",  # friendly landing JSON pointer (Track 4)
    "/api/org/config",  # first-run org setup status (GET)
    "/health",
    "/ready",  # That change: readiness probe — public, same class as /health
    "/metrics",
    "/agentfacts.json",
    # Signed conformance badge — MUST be public: it is offline-verifiable by
    # anyone against the embedded did:key; gating a public proof defeats it.
    "/.well-known/conformance.json",
    # the standard A2A AgentCard is public/OPEN by design — a NANDA
    # resolver fetches it unauthenticated before it can know how to sign.
    "/.well-known/agent.json",
    # the W3C DID Document. MUST be world-readable, for two independent
    # reasons — either one is sufficient:
    #   1. did:web resolution IS an unauthenticated GET of
    #      https://<domain>/.well-known/did.json. That is the method's
    #      definition, so a did:web that requires credentials is not a did:web
    #      — nobody can verify the identity this org advertises.
    #   2. Inbound federation signature verification: a peer calls
    #      federation_signing.fetch_peer_pubkey(endpoint), which reads OUR
    #      Ed25519 public key from this document. Gate it and every peer that
    #      has not pinned our DID reports peer_key_unavailable — we become
    #      unverifiable to the mesh. Registry attestation anchors here too.
    # The document contains only public material (did, public key in
    # publicKeyMultibase + legacy publicKeyBase64); publishing it is the point.
    #
    # It is listed EXPLICITLY even though unlisted GETs already default to open,
    # because "open by default" is not the same claim as "open on purpose": a
    # future hardening pass that flips the GET default, or adds a /.well-known/
    # prefix rule, would silently break did:web resolution and federation key
    # discovery with no test and no comment to stop it.
    "/.well-known/did.json",
    # sm-federation 0.1 §2: the community federation node descriptor. Public/OPEN
    # for the same reason as did.json, arriving one step earlier in the handshake:
    # this is the document a peer that has NEVER met this org fetches first, to
    # learn the org's DID, facts, transport and conformance URLs. It is fetched
    # before the peer knows our identity and therefore before it could sign
    # anything we would accept. Gating it protects nothing (every value in it is
    # already public) and makes the org invisible to precisely the strangers
    # federation exists to reach — the peering handshake has no earlier step to
    # fall back to.
    "/.well-known/agent-community.json",
    # sm-listing 0.1: the consented member listing. PUBLIC, and unlike the member
    # directory there is nothing here that anyone declined to publish — every
    # entry is a member who explicitly opted in, carrying only the fields they
    # chose. This is the document a stranger reads to find a member inside an org
    # it has never met, so gating it would defeat its only purpose. It is NOT a
    # filter over the directory: that stays gated.
    "/.well-known/agent-community-listing.json",
    # sm-federation 0.1 §4: the signed intelligence feed the descriptor above
    # points at. Open for the same reason and one step later in the handshake —
    # a peer follows feed_url straight from the unauthenticated descriptor, so
    # gating it makes that pointer resolve to a 401 and puts us back where
    # did.json was in the public-discovery rule. Nothing here is protected by auth: §3 makes the
    # payload aggregate-only (skill graph, gaps, trends, counts — no per-member
    # identity), and every entry is Ed25519-signed and hash-chained, so the
    # subscriber verifies authenticity and completeness itself rather than
    # trusting the transport. Authentication would add a barrier to discovery
    # and no confidentiality.
    "/api/federation/intelligence/feed",
    # the org's AI Catalog (hosting_path=registry). Public/OPEN — the
    # registry hop is unauthenticated, same as the card.
    "/.well-known/ai-catalog.json",
    "/api/version",
    "/api/docs",  # 308 redirect to /docs (Track 4)
    "/api/federation",
    # kept here for POST — `is_open_path` consults this set only after
    # REQUIRE_AUTH_GET_PATHS has already claimed GET /api/members, so the
    # directory listing is auth-gated while first-time TOFU registration
    # (POST, via SELF_SIGNED_POST_PATHS) stays open. Removing the GET entry
    # from REQUIRE_AUTH_GET_PATHS re-opens bulk enumeration.
    "/api/members",
    "/api/knowledge/summary",
    "/api/knowledge/network",
    "/api/outcomes",
    "/api/runtimes",
    "/api/sessions",
}

# POST endpoints that are open to unauthenticated requests because the
# handler performs its OWN verification (whitelist, signed-body, etc.).
# Different from SELF_SIGNED_POST_PATHS which is specifically for
# embedded-cryptographic-proof endpoints. Both result in middleware
# pass-through, but keeping them separate documents the trust model.
OPEN_POST_PATHS = {
    # Federation broadcast inbox. Open at this gate because the caller is a
    # PEER ORG, not a member: it holds no member key, so the member signature
    # this gate checks is the wrong credential and requiring it would refuse
    # every legitimate peer. The handler runs the credential that does apply —
    # server-to-server Ed25519 verification against the sender's pinned or
    # attested did:key, rejecting on failure whenever
    # FEDERATION_ENFORCE_SIGNED_BROADCASTS is on, which is its default. Moving
    # this entry to SELF_SIGNED_POST_PATHS would not add a check; it would
    # substitute a member credential the peer cannot have.
    "/api/federation/broadcast/inbox",
    # Brokered co-sign relay (cosign-companion.md §4). Open by design: the
    # caller's identity is irrelevant to correctness — the counterparty B only
    # co-signs a receipt on which it is the named, distinct counterparty (its
    # own make_witness guard), so a forged caller cannot manufacture
    # corroboration. The server is a pure transport relay and signs nothing.
    # Abuse is bounded by EXPENSIVE_WRITE_LIMITS + registered-members-only
    # resolution (SSRF guard). Fail-safe to uncorroborated, never an error (§3).
    "/api/cosign/broker",
    "/api/cosign/broker/",
}

OPEN_PREFIXES = [
    "/api/surfaces/",
    "/api/portal/",
    "/agentfacts/",
    # the registry hop — GET /agents/<identifier> → CatalogEntry. Public
    # by design (a resolver reads it unauthenticated). Distinct from the
    # /api/agents/ namespace (which keeps its own auth rules).
    "/agents/",
    # published receipt-disclosure bundles. PUBLIC BY DESIGN and the whole
    # point — the product claim is that a third party can verify a receipt
    # without trusting us, which is impossible if checking requires an account.
    # Only bundles an operator EXPLICITLY published are served here; the handler
    # 404s anything else. This does NOT open /api/receipts, which stays 401 and
    # is a member's own private history — a different question from an org
    # publishing a receipt about its own action.
    "/.well-known/receipt-disclosure/",
]

# GET endpoints that MUST require an X-Agent-Signature even though
# default GET behavior is "let the request through whether auth was
# provided or not." Pre-launch audit (2026-05-10) found these returning
# 200 unauth + leaking operational details (full peer backoff history,
# server policy values, full per-agent export records 25KB each).
#
# Path matching uses both exact set + prefix list — templated paths like
# `/api/agents/{id}/export` and `/api/federation/peers/{id}/history`
# need prefix support.
#: A2UI page ids whose rendered document contains MEMBER data. Measured, by
#: driving all 42 registered surfaces anonymously against a running instance and
#: searching each response for a member's own id, name, description and skills —
#: not by reading builders. The audit found `directory` and
#: `members`; driving the rest found three more that nobody had named
#: (`chapter`, `reputation`, `subscriptions`), which is why the list is derived
#: from a probe and why `test_member_enumeration_closed.py` re-derives it on
#: every run rather than trusting this constant to stay complete.
MEMBER_BEARING_SURFACES = (
    "chapter",
    "directory",
    "members",
    "mesh",
    "subscriptions",
)

#: The shareable per-agent pages, deliberately left open: their URLs are meant
#: to work without an account — a decision `test_read_surface_lockdown.py`
#: already locks. A per-agent page necessarily names its own subject; that is
#: not enumeration, and gating it would break URL sharing for no privacy gain.
#: Recorded here because `reputation` was on the first draft of the gate list
#: and taking it off was a judgement, not an oversight.
#:
#: ⚠️ "discloses its subject's agent_id and NOTHING else" was written here as
#: though it held for all five, and it does not hold for `endorsements`.
#: `profile`, `reputation`, `trust` and `chronicle` disclose the SUBJECT, who
#: chose to share the page. An endorsement names a THIRD PARTY — the endorser —
#: who made no such choice and is not the one sharing, and a subject cannot
#: consent on an endorser's behalf. Being open is therefore not the same
#: property for `endorsements` as for the other four: it is open BECAUSE its
#: builder redacts the endorser to a chapter_role
#: (`surfaces.build_endorsements_surface`), the same grain and for the same
#: reason as `chapter_agent._redact_trust_history`. Remove that redaction and
#: this entry stops being defensible — do not read the membership of this tuple
#: as permission to render raw endorser detail.
PER_AGENT_SHAREABLE_SURFACES = ("profile", "reputation", "trust", "endorsements", "chronicle")

REQUIRE_AUTH_GET_PATHS = {
    "/api/policy",
    "/api/federation/peers",
    # GET /api/mesh/peers searches "peer agents across my chapter + federated
    # chapters" and, for LOCAL members, returned agent_id/name/skills/
    # trust_score for every one of them to anyone with no auth at all — the
    # same member-enumeration shape as the closed /api/members and
    # /api/surfaces/directory, just reached through the mesh search instead
    # of the directory. /api/surfaces/mesh (below) calls the same
    # mesh.list_peers underneath its peer browser, so both are gated here.
    "/api/mesh/peers",
    # GET /api/projections answered for anyone with no auth at all, and
    # returned each row's projection_id — the member's real agent_id —
    # despite the projections module's whole premise being that identity is
    # revealed only after bilateral consent (projections.py module
    # docstring). Not self-scoped: signed members are meant to browse the
    # anonymized capability directory to find collaborators, they just
    # should not learn WHO each entry is. The handler strips projection_id
    # before returning; this only closes the "no auth at all" half.
    "/api/projections",
    # The A2UI pages that render the member directory. Gated to match
    # GET /api/members: before this, `/api/surfaces/directory` — a document
    # literally titled "Agent Directory" — returned a MemberCard per member to
    # anyone, with name, agent id, skills and the member's own free-text
    # description. The JSON directory was closed and the same population was
    # published three other ways; this closes the A2UI ones.
    #
    # The page shell is NOT what was protected here and these are gated whole,
    # unlike /api/portal/layout: these pages ARE the member list, so a shell
    # without it would be an empty document rather than a useful one.
    #
    # ⚠️ WRITTEN OUT AS LITERALS, deliberately, and NOT derived from
    # MEMBER_BEARING_SURFACES with a starred comprehension. This set is READ
    # STATICALLY by renderer/tests/e2e/gen_contract.py, which walks the AST and
    # keeps only `ast.Constant` elements — a comprehension is invisible to it, so
    # the generated contract listed these pages as ungated and the portal e2e
    # asserted they still paint. It failed in CI for exactly that reason. A
    # security-relevant set should be greppable anyway; the agreement between
    # these literals and MEMBER_BEARING_SURFACES is asserted by
    # test_member_enumeration_closed.py rather than enforced by a comprehension
    # only Python can see.
    "/api/surfaces/chapter",
    "/api/surfaces/directory",
    "/api/surfaces/members",
    "/api/surfaces/mesh",
    "/api/surfaces/subscriptions",
    # the member directory. Unauthenticated it answered "who are ALL your
    # members?" — agent_id, name, description, skills, interests, availability,
    # reputation, github_url, linkedin_url for every member, to anyone. A
    # discovery system should answer "does THIS subject have an agent?" for a
    # caller who already knows the subject; that exact-match lookup lives at the
    # still-open GET /api/agents/{agent_id}/profile (its near-duplicate,
    # GET /api/member/{agent_id}/profile, was retired — same route, one
    # prefix). Authorized readers of the
    # LIST are: a signed member, an operator (X-Admin-Token, see
    # is_operator_readable_path), and a signature-verified federation peer (see
    # is_federation_peer_readable_path). POST /api/members — first-time TOFU
    # registration — is unaffected: this set is GET-only.
    "/api/members",
    "/api/members/",
    # EB-3: subscription list belongs to the caller — must be auth-gated
    # so an enumerable GET can't leak who is subscribed to what.
    "/api/subscriptions",
    "/api/subscriptions/",
    # ARP v0.1: the principal's receipt log is sensitive; reading requires
    # the principal to sign the GET request so we can verify they ARE the
    # principal whose receipts they're requesting.
    "/api/receipts",
    "/api/receipts/",
    # Chronicle layer: /page/today is the principal-private daily report.
    # /page/chronicle is intentionally public when opted in (handler-level
    # gate); only /page/today requires auth at the middleware layer.
    "/api/surfaces/today",
    # Per-agent private surfaces — an unauthenticated caller must not read
    # another principal's private data by passing ?target=<id>. These require a
    # verified signature; per-caller target-scoping (so an authed member only
    # sees their OWN) is hardened in get_surface_endpoint. Genuinely public
    # per-agent surfaces (profile, reputation, trust, endorsements, directory,
    # search, members) stay OPEN by design.
    "/api/surfaces/intents",
    "/api/surfaces/conversations",
    "/api/surfaces/messages",
    "/api/surfaces/settings",
    "/api/surfaces/channels",
    "/api/surfaces/voice",
    # Operator / org-security surface — SSO / allowlist state.
    "/api/surfaces/chapter-security",
    # RESOLVED the activity-feed PII closure — no route below is left "needing a maintainer decision".
    #
    # The 2026-07-30 pass probed all four live and recorded outcomes,
    # advisor-earnings and mesh as CLEAN. That verdict was reached by reading
    # response FIELD NAMES, which is the method this same comment goes on to say
    # does not work for A2UI surfaces (values are flattened into `Text`
    # components, so keys are absent while values are served verbatim). It also
    # called each route with NO `target`. Re-examined 2026-08-01 by driving the
    # `target` parameter and by reading each builder for what it renders under
    # real data, rather than what an idle instance happened to return:
    #
    #   outcomes          PUBLIC BY INTENT. `target` is accepted and never read.
    #                     outcome_tracker.get_quality_scores() selects only
    #                     action_type/signal/quality_score and keys the result by
    #                     ACTION TYPE, so per-member rows are impossible by
    #                     construction, not merely absent today.
    #   mesh              PUBLIC BY INTENT. `target` IS read
    #                     (mesh.get_mesh_state(agent_id=target)), so an anonymous
    #                     caller can name any agent — but the only per-agent field
    #                     it yields is my_trust() -> {agent_id, trust_score, tier},
    #                     the same data /api/surfaces/trust already serves openly
    #                     by design. Everything else is org-level counts and
    #                     cross-chapter skill gaps. A redundant path to public
    #                     data, not a new disclosure.
    #   advisor-earnings  WAS DISCLOSING. `target` went straight to
    #                     skill_revenue.get_earnings_for_did, so an unauthenticated
    #                     caller supplying any did:key received that principal's
    #                     all-time earnings, last-7-day earnings, ledger entry
    #                     count and per-role breakdown. Confirmed live against a
    #                     production chapter: with no target the route returns only
    #                     the "Pass ?target=..." prompt (which is what the earlier
    #                     probe measured), and with an arbitrary target it renders
    #                     the full dossier. Amounts read $0.00 today only because
    #                     the revenue ledger is empty — the authorization gap was
    #                     present regardless.
    #   activity          LEAKED — see below.
    #
    # advisor-earnings is now SELF-SCOPED in get_surface_endpoint alongside
    # `today`: the caller's verified did:key replaces any supplied target, so an
    # anonymous caller gets the no-data prompt and a signed caller gets only their
    # own figures. Deliberately NOT added to REQUIRE_AUTH_GET_PATHS — the portal
    # links this page anonymously (AppSidebar), its anonymous view was already a
    # no-data prompt, and self-scoping closes the disclosure completely, so a 401
    # would break a consumer for no additional protection.
    #
    # Surfaces with a built-in redacted safe-projection (e.g. `audit`, which
    # serves anon a redacted view — see test_admin_audit_surface) stay OPEN.
    # `outcomes` and `mesh` stay OPEN on the evidence above; `advisor-earnings`
    # stays reachable but yields data only to the principal it belongs to.
    #
    # `/api/surfaces/activity` also stays open but is now REDACTED AT THE
    # BUILDER (surfaces.build_activity_surface): it was rendering `member_name`
    # beside `user_message_snippet`. That leak was invisible to a field-name
    # probe because the builder flattens the values into A2UI `Text`
    # components — the keys are absent while the values are served verbatim.
    # Do not re-check this class of surface by grepping for field names.
    #
    # the REST route is gated instead of redacted. Unauthenticated it
    # returned 50 rows of `member_name` PAIRED WITH `user_message_snippet` — a
    # real person's name next to a snippet of what they said to their agent —
    # plus `member_agent_id` and `conversation_id`, ~20KB per response, on all
    # three orgs and all five chapters. Every field the route exists to serve is
    # that pairing, so a safe projection would leave `{id, created_at}`.
    "/api/activity",
}

REQUIRE_AUTH_GET_PREFIXES = (
    "/api/federation/peers/",  # /api/federation/peers/{peer_id}/history
    "/api/subscriptions/",  # /api/subscriptions/{id}/stream — long-lived SSE, owner-only
    # /api/settings/{agent_id} — a member's private prefs (llm/voice/channels/
    # trust/privacy). Requires a signature; the handler additionally scopes the
    # read to the caller's own id (or an admin token).
    "/api/settings/",
    # /api/conversations/{agent_id} — full message bodies between two agents.
    # Used to answer for any agent_id with no participation check, while the
    # write path on the same table (agent_conversations.send_message) has
    # always enforced from_agent_id in (thread.from_agent_id, thread.to_agent_id).
    # Requires a signature; the handler additionally scopes the read to a
    # participant (or an admin token), same idiom as /api/settings/ above.
    "/api/conversations/",
    # /api/agents/{agent_id}/export — gated handler-side because the
    # endpoint already needs to check self-vs-other anyway, and a
    # blanket prefix gate would hide /api/agents/{id}/profile which
    # is OPEN by design (sharing the URL must work without an account).
    # /api/authority/{agent_id} — an agent's authority scope. Answered for any
    # agent_id with no auth at all; the write side (POST, same path) has always
    # scoped to the caller's own id or an admin. Requires a signature; the
    # handler additionally scopes the read the same way.
    "/api/authority/",
    # /api/channels/{agent_id} — a member's channel connections (Slack/email/
    # …). Same gap: the write side (POST /api/channels/connect) has always
    # used _require_agent_owner; the read never did.
    "/api/channels/",
    # /api/onboarding/{agent_id} — a member's onboarding step/state. Same gap
    # as the two above: POST /api/onboarding/advance has always used
    # _require_agent_owner; the read never did.
    "/api/onboarding/",
    # /api/policy/{key}/history — a gate-SHAPE bug, not a missing entry:
    # GET /api/policy is in REQUIRE_AUTH_GET_PATHS, matched EXACTLY, so this
    # child path escaped its parent's gate entirely. Same org-wide policy
    # data (a hyperparameter's change history rather than its current value),
    # so the same auth requirement — any signed member, not self-scoped —
    # applies here too.
    "/api/policy/",
)

# Endpoints that carry their own cryptographic proof in the body and do not
# need the TOFU agent-id signature layer. The endpoint handler is responsible
# for verifying the embedded signature (e.g. /api/skills/publish verifies an
# Ed25519 sig over content_sha256 inside the request body).
#
# /api/members: the register_member handler does TOFU internally
# (accepts a new pubkey on first registration, enforces match on
# re-registration via the `if existing.origin != origin` check). OpenClaw
# users installing the skill for the first time don't have a stored
# identity yet — blocking them at the middleware breaks first-registration.
#
# /api/members/rotate: carries a full rotation attestation signed by the
# OLD key in the body. member_rotation.accept_rotation() does the full
# verification. No outer X-Agent-Signature layer needed.
SELF_SIGNED_POST_PATHS = {
    # POST /api/org/config (first-run setup) is NOT here any more. It was open
    # until the org was configured, on the reasoning that nothing exists to
    # sign with before provisioning — which is true of a member signature and
    # irrelevant to the operator's bearer: the admin token is minted and
    # printed at first boot, before the port is reachable. On a public deploy
    # the window between the process listening and the operator's first visit
    # was one in which a stranger could name the org and set its join policy.
    # It now takes the bearer (is_admin_bearer_path) and the handler authorizes.
    #
    # POST /api/skills/publish and /publish/package are NOT here any more. The
    # manifest (or package) carries the PUBLISHER's Ed25519 signature, which
    # proves the skill is authentic and nothing about who is putting it in
    # THIS org's registry. Open, any keypair on the internet could list a
    # package in an org's registry — the supply-chain shape a public deploy
    # meets on day one. Publication now takes a registered member's request
    # signature at the middleware; the package signature is still verified
    # fail-closed in the handler. Not a wire-format change — an auth tier.
    "/api/members",
    "/api/members/",
    "/api/members/rotate",
    "/api/members/rotate/",
    # ARP v0.1: the receipt body carries its own Ed25519 signature.
    # server.arp.emit() verifies it; outer X-Agent-Signature not needed.
    "/api/receipts",
    "/api/receipts/",
}

REQUIRE_AUTH_METHODS = {
    "DELETE",
}

# C4: state-changing methods MUST authenticate with a method-bound scheme.
# The v0.2 / hmac canonical string is ``body:agent_id:timestamp`` — it does not
# commit to the HTTP method or path, so a captured signed GET could be replayed
# as a DELETE (or a POST re-fired at a different path) within the timestamp
# window. Only ``ed25519+nonce`` (v0.3) binds ``method:url_path`` AND carries a
# server-enforced replay nonce, so it is the sole scheme accepted for mutations.
# Reads may still use v0.2 (a replayed GET is non-escalating; the residual is
# tracked in docs/HARDENING.md, C4).
METHOD_BOUND_REQUIRED_METHODS = {
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}

# A2A invoke is a deliberate v0.2 interop surface (the cross-org signed control
# set): external agents authenticate POST /a2a and POST /run with the
# method-unbound ed25519 v0.2 scheme. These are POST-only — there is no GET twin
# whose captured signature could be cross-method-replayed onto them — so the C4
# method-binding requirement is NOT applied here; the rest of the mutating API
# still requires v0.3.
#
# This set is spec/0.5/signing.md §"What mutating means" VERBATIM, and the spec
# says the enumeration is exhaustive: "a route not named here is not carved out,
# so a chapter MUST NOT extend the exemption to routes of its own choosing."
# Do not add to it locally — amend the spec.
#
# History worth keeping, because the round trip is the point: `/run` was dropped
# from this set in the advertised-version correction when this org started advertising 0.5, because v0.5 as
# first published named only the `/a2a` family and a chapter must not attest a
# version it bends. That was the honest reading, and it was also the trigger for
# fixing the spec rather than the runtime: umbrella / PR established
# the omission was accidental — `/run` is the standard A2A invoke (a caller
# reads the agent card and POSTs `<card.url>/run`), reached by the same third
# parties, and `chapter/`, the runtime v0.5 was drafted against, has no `/run`
# route at all, so the list reflected what was in front of the author. The spec
# now names `POST /run` and `POST /run/`, so the exemption is restored here —
# the spec moved, then the runtime followed.
METHOD_BINDING_EXEMPT_PATHS = {"/a2a", "/a2a/", "/run", "/run/"}
METHOD_BINDING_EXEMPT_PREFIXES = ("/a2a/@",)


def enforce_method_binding(method: str, path: str) -> bool:
    """Whether this request must use the method-bound scheme (v0.3) — True for a
    mutating method on the internal API, False for reads and the A2A interop
    exemption above. The middleware passes the result to ``verify_request``."""
    if method.upper() not in METHOD_BOUND_REQUIRED_METHODS:
        return False
    if path in METHOD_BINDING_EXEMPT_PATHS:
        return False
    if any(path.startswith(p) for p in METHOD_BINDING_EXEMPT_PREFIXES):
        return False
    return True


REQUIRE_AUTH_PATHS = {
    "/api/agents/import",
    # the standard A2A invoke. POST already requires auth by default,
    # but listing it explicitly documents intent and keeps the Ed25519 v0.2
    # signed control set (unsigned→401 / signed→200 / tampered→401) pinned —
    # same trust layer as the legacy /a2a.
    "/run",
    "/run/",
    # Chronicle settings: only the agent themselves can flip their
    # chronicle_public flag. Middleware enforces signed-by-caller.
    "/api/me/chronicle-public",
    "/api/me/chronicle-public/",
}

# Transition period: warn but don't block these
WARN_PATHS: set[str] = set()


# ── Admin-token paths ──────────────────────────────────────────────
#
# /admin/* endpoints accept an X-Admin-Token header (verified by
# server.admin.verify_admin_token). The token is a system-level
# credential generated at server startup — distinct from a member's
# X-Agent-Signature, and explicitly NOT a member identity. An admin-
# token-authenticated request CANNOT sign as a member, submit an
# intent, RSVP to a call, or take any action that requires a did:key
# in the request body.
#
# The static admin UI at /admin/ + /admin/index.html is served
# unauthenticated so the user can paste their token; the API surface
# at /admin/api/* is the one that requires the token.

ADMIN_OPEN_PATHS = {
    "/admin",
    "/admin/",
    "/admin/index.html",
    "/admin/pico.min.css",
}


def is_admin_api_path(path: str) -> bool:
    """True iff ``path`` is an admin-API endpoint (not the static UI)."""
    return path.startswith("/admin/api/") or path == "/admin/api"


def check_admin_token_header(headers: dict[str, str]) -> bool:
    """Pull the X-Admin-Token header and verify it.

    Both header-name variants are checked because middleware lower-cases
    headers but tests + curl sometimes use canonical case. Constant-time
    compare lives inside ``admin.verify_admin_token``.
    """
    import admin as _admin_mod  # local import to avoid cycle

    token = headers.get("x-admin-token") or headers.get("X-Admin-Token") or ""
    return _admin_mod.verify_admin_token(token)


def store_agent_key(agent_id: str, public_key: str, signing_secret: str = "", ed25519_pubkey: str = ""):
    """Store an agent's key for future verification (TOFU).

    public_key + signing_secret → HMAC-SHA256 path (legacy community-member).
    ed25519_pubkey → Ed25519 path (NANDA Index spec).
    """
    existing = _agent_keys.get(agent_id, {})
    _agent_keys[agent_id] = {
        "public_key": public_key or existing.get("public_key", ""),
        "signing_secret": signing_secret or existing.get("signing_secret", ""),
        "ed25519_pubkey": ed25519_pubkey or existing.get("ed25519_pubkey", ""),
    }


def replace_agent_key(agent_id: str, new_public_key: str) -> None:
    """Hard-overwrite both stored pubkey slots for an agent.

    Unlike store_agent_key (which OR-falls-back to existing values when
    a field is empty), this function REPLACES every field. Use this
    after a rotation where the old key is explicitly invalidated —
    we must NOT keep the stale ed25519_pubkey around or verify_request
    will happily authenticate with the old key.

    Discovered 2026-04-22 during end-to-end sovereign SDK test:
    after /api/members/rotate, signing with the new key failed because
    verify_request read ed25519_pubkey, which store_agent_key had left
    unchanged.
    """
    _agent_keys[agent_id] = {
        "public_key": new_public_key,
        "signing_secret": "",  # rotation invalidates HMAC path too
        "ed25519_pubkey": new_public_key,
    }


def store_did_key(agent_id: str, did_key: str):
    """Store an agent's Ed25519 public key parsed from a did:key string."""
    try:
        from sovereign_identity import extract_ed25519_pubkey_from_did_key
    except ImportError as e:
        # A missing sovereign_identity is a broken deployment, not a bad caller —
        # say so instead of surfacing it as an inexplicable invalid_did_key (R6).
        print(f"[auth][error] store_did_key: sovereign_identity unavailable ({e}) — did:key auth disabled")
        return False
    pubkey_b64 = extract_ed25519_pubkey_from_did_key(did_key)
    if pubkey_b64:
        store_agent_key(agent_id, "", "", ed25519_pubkey=pubkey_b64)
        return True
    return False


def get_agent_key(agent_id: str) -> dict | None:
    """Get stored key for an agent."""
    return _agent_keys.get(agent_id)


def has_agent_key(agent_id: str) -> bool:
    """Check if we have a key for this agent."""
    return agent_id in _agent_keys


def generate_nonce(agent_id: str, ttl: int = 60) -> str:
    """Generate a challenge nonce for registration."""
    nonce = base64.b64encode(os.urandom(32)).decode()
    _nonces[nonce] = (agent_id, time.time() + ttl)
    # Clean expired nonces
    now = time.time()
    expired = [n for n, (_, exp) in _nonces.items() if exp < now]
    for n in expired:
        _nonces.pop(n, None)
    return nonce


def verify_nonce(nonce: str, agent_id: str) -> bool:
    """Verify a challenge nonce is valid and not expired."""
    entry = _nonces.pop(nonce, None)
    if not entry:
        return False
    stored_id, expires = entry
    return stored_id == agent_id and time.time() < expires


#: Suffixes that make a SECOND path serve the SAME surface. A page and its
#: streaming twin were two independent decisions with nothing tying them
#: together, which is exactly how seven gated pages ended up world-readable over
#: `/stream`: 401 on the page, 200 on the stream, full snapshot, no credentials.
#:
#: Measured before generalising, not assumed: the route table has NO websocket
#: routes, and the other suffixed twins in this app (`/admin/api/audit/export`,
#: `/api/chapter/audit/{id}/export.jsonl`) already AGREE with their base paths,
#: so `/stream` was the only shape with a hole. The tuple exists so that adding
#: another paired form is one edit here rather than a second silent decision.
SURFACE_TWIN_SUFFIXES = ("/stream",)


def canonical_surface_path(path: str) -> str:
    """The path whose gate decides this one.

    `/api/surfaces/<page>/stream` is the AG-UI form of `/api/surfaces/<page>`.
    Collapsing it here means the gate is stated ONCE, for the page, and the twin
    inherits it — so a page gated tomorrow cannot ship with an open stream, and
    nobody has to remember the pairing. Applied in BOTH `is_open_path` and
    `requires_auth`, because a rule applied in only one of them would let the
    open-path fast return disagree with the gate.
    """
    if not path.startswith("/api/surfaces/"):
        return path
    for suffix in SURFACE_TWIN_SUFFIXES:
        if path.endswith(suffix) and len(path) > len("/api/surfaces/") + len(suffix):
            return path[: -len(suffix)]
    return path


def is_open_path(method: str, path: str) -> bool:
    """Check if this request doesn't require auth."""
    # An AG-UI stream inherits its page's gate — see canonical_surface_path.
    path = canonical_surface_path(path)
    # /admin/* — middleware bypasses auth, the admin handlers do their
    # own dual-path verification (signed admin member OR bearer token)
    # via chapter_agent._authorize_admin. The static UI (/admin/, the
    # CDN-served index.html) is genuinely open so the operator can
    # paste their credentials; the API surface at /admin/api/* is
    # handler-authenticated. Both flow through is_open_path == True
    # at the middleware boundary.
    if path in ADMIN_OPEN_PATHS:
        return True
    if is_admin_api_path(path):
        return True
    if method == "GET":
        # An explicit auth requirement wins over an open prefix. A
        # principal-private path that happens to sit under an otherwise-open
        # prefix (e.g. /api/surfaces/today under the /api/surfaces/ prefix)
        # must NOT be treated as open — otherwise the specific entry in
        # REQUIRE_AUTH_GET_PATHS becomes dead code and the route leaks
        # unauthenticated. Checked first so the open-prefix scan below can't
        # shadow it.
        if path in REQUIRE_AUTH_GET_PATHS or any(path.startswith(p) for p in REQUIRE_AUTH_GET_PREFIXES):
            return False
        if path in OPEN_PATHS:
            return True
        for prefix in OPEN_PREFIXES:
            if path.startswith(prefix):
                return True
        # Agent profile surface — `/api/agents/{id}/profile`. Unauthenticated
        # by design, because sharing the URL must work without an account: a
        # link to a member's profile has to render for everyone, crawlers
        # included. That is NOT the same as ungated, and this comment used to
        # say it was — it claimed the handler "returns ONLY public-by-design
        # fields (skills, trust score, did_key)". It also returned the member's
        # free-text `description`, and it served every member whether or not
        # they had agreed to be published.
        #
        # The gate now lives in the handler, where it can read the member's
        # consent record: `agent_profile_surface` answers 404 — identical to the
        # 404 for an id that never existed — unless `member_listing.consent_of`
        # says that member opted in. Open here means "no credential required to
        # ASK"; whether there is anything to return is the member's decision,
        # not the middleware's.
        if path.startswith("/api/agents/") and path.endswith("/profile"):
            return True
    # POST endpoints that verify their own embedded cryptographic proof
    # (the handler validates signatures in the body, so the middleware's
    # TOFU agent-id layer is redundant).
    if method == "POST" and path in SELF_SIGNED_POST_PATHS:
        return True
    # POST endpoints that perform handler-level non-cryptographic
    # verification (origin whitelist, etc.). Same middleware
    # pass-through as SELF_SIGNED_POST_PATHS, distinct semantic.
    if method == "POST" and path in OPEN_POST_PATHS:
        return True
    # Surface POST endpoints — open by convention. /compose generates
    # UI from intent (no state mutation beyond a cache row). /action is
    # form-submission from the rendered surface (intent_text, ratings,
    # etc.) and the handler does its own per-action validation. Same
    # pattern as GET /api/surfaces/* for read access.
    #
    # /api/digest/build is NOT here any more (audit M11). It used to be, on
    # the argument that the handler's docstring "declares it open" and the
    # 5/min EXPENSIVE_WRITE_LIMITS ceiling caps the LLM burn. That argument
    # was about COST and said nothing about CONTENT. Measured on a local org
    # with one member and one intent: an unauthenticated POST received the
    # intent's text verbatim in `top_intents[].text` (280 chars) and again in
    # the deterministic `summary_markdown` (100 chars), plus the joiner's
    # agent_id, display name and skills — and with the default `publish: true`
    # it wrote a `chapter.digest.weekly` row to event_log attributed to the
    # org. The rows the digest reads are delivered over SSE only to a SIGNED
    # member (`MIN_TRUST_TO_SUBSCRIBE` is 0.0 for member.joined and
    # intent.published, but the stream itself 401s without a caller), so the
    # route now requires that same tier: the global signature gate for a
    # member, or the operator bearer via `is_admin_bearer_path`. The handler
    # refuses on its own as well, so an edit here cannot reopen it alone.
    if method == "POST" and path in {
        "/api/surfaces/compose",
        "/api/surfaces/action",
    }:
        return True
    return False


def is_admin_bearer_path(method: str, path: str) -> bool:
    """POST admin endpoints whose handler authorizes a valid X-Admin-Token
    (operator break-glass) in addition to a signed leader/admin.

    The global signature gate only accepts X-Agent-Signature, so without this a
    bearer-only request 401s before the handler's bearer-aware _authorize_role
    runs (GET /api/invites already works because GETs aren't globally gated).
    The middleware lets a VALID bearer through for these paths; the handler still
    enforces role, and unauthenticated requests still 401.
    """
    if method != "POST":
        return False
    if path in ("/api/invites", "/api/invites/"):
        return True
    # First-run org setup. The operator holds the boot-printed admin token
    # before anyone else can reach the port; a member signature cannot exist
    # yet. So the bearer is the credential this POST is for.
    if path in ("/api/org/config", "/api/org/config/"):
        return True
    # Governance-sensitive admin POSTs whose handlers authorize a bearer via
    # _authorize_role/_authorize_admin. Without listing them here the global
    # signature gate 401s a valid bearer before the handler runs — the same
    # gap fixed for invites. The handler still enforces role.
    if path in ("/api/org/join-policy", "/api/org/join-policy/"):
        return True
    if path.startswith("/api/approvals/") and (path.endswith("/approve") or path.endswith("/reject")):
        return True
    # Trust maintenance + GDPR erasure. Both call _authorize_role, so both were
    # in the double-verify set — and NEITHER was listed here, so a bearer-only
    # request 401'd at the gate while the signed request 401'd as its own replay.
    # POST /api/admin/trust/decay-sweep was therefore reachable by no credential
    # at all: not degraded, dead. Listing them restores the break-glass half; the
    # handler still enforces role.
    if path in ("/api/admin/trust/decay-sweep", "/api/dsar/delete"):
        return True
    # On-demand digest build (audit M11). Any signed member passes the global
    # gate; this entry is the operator break-glass so a bearer-only caller
    # (a cron, a runbook) can still trigger the weekly digest without a
    # member key. The handler checks both credentials itself.
    if path == "/api/digest/build":
        return True
    return path.startswith("/api/invites/") and path.endswith("/revoke")


#: Open documents that serve MORE to a verified caller than to a stranger.
#: They are NOT gated — every one still answers an unauthenticated GET — but the
#: middleware verifies a signature when one is present so the handler can tell
#: who is asking. Introduced when member enumeration was closed: the catalog is the unauthenticated
#: registry hop AND was enumerating every member, and those two facts are
#: only reconcilable if the document can distinguish its callers.
#: GET /api/sessions and GET /api/runtimes serve a minimal anonymous tier and
#: a richer authenticated one (per-agent provider/model/thought-count data,
#: hidden from anonymous callers after a pre-launch audit). Both handlers used
#: to derive the tier from a request header the caller could set themselves;
#: adding them here is what makes request.state.verified — set only after a
#: real signature check — the thing they read instead.
IDENTITY_AWARE_OPEN_PATHS = frozenset(
    {"/.well-known/ai-catalog.json", "/api/portal/layout", "/api/sessions", "/api/runtimes"}
)


def is_identity_aware_open_path(method: str, path: str) -> bool:
    """Whether an open path should still have a present signature verified.

    GET/HEAD only: this exists to enrich a read, and letting it apply to writes
    would blur the line between "identity known" and "request authorized", which
    is the distinction the whole open-path fast path rests on.
    """
    return method.upper() in ("GET", "HEAD") and path.rstrip("/") in {p.rstrip("/") for p in IDENTITY_AWARE_OPEN_PATHS}


def has_signature_headers(headers: dict) -> bool:
    """Whether the caller even attempted to sign. Cheap check so an anonymous
    request on an open path pays nothing for a verification it did not ask for."""
    lower = {k.lower() for k in headers}
    return "x-agent-signature" in lower and "x-agent-id" in lower


def is_operator_readable_path(method: str, path: str) -> bool:
    """GET endpoints where a valid ``X-Admin-Token`` is sufficient authorization
    at the middleware.

    Distinct from ``is_admin_bearer_path``: there the handler does its own
    bearer-aware role check and the middleware only stops 401-ing early; here
    the middleware IS the authorization decision, so the set stays minimal —
    reads whose whole authorization rule is "an operator of this org may see
    this". The member directory qualifies: the operator already reads the same
    rows (with more detail) via GET /admin/api/members.
    """
    if method != "GET":
        return False
    return path in ("/api/members", "/api/members/")


def is_federation_peer_readable_path(method: str, path: str) -> bool:
    """GET endpoints a *signature-verified federation peer* may read.

    Cross-org discovery (``federation_discovery.query_chapter_members``) fetches
    a peer's member list; gating the list without this would silently kill it.
    The peer proves itself with the S2S Ed25519 scheme
    (``federation_signing.verify_peer_request``) — an allowlisted endpoint alone
    is NOT enough. Deliberately narrow: only the directory listing, never the
    ``/api/federation/{peer}/members`` proxy (a peer must not use us to relay
    another peer's directory).
    """
    if method != "GET":
        return False
    return path in ("/api/members", "/api/members/")


def is_warn_path(method: str, path: str) -> bool:
    """Check if this request should warn but allow without auth."""
    return path in WARN_PATHS


def requires_auth(method: str, path: str) -> bool:
    """Check if this request requires authentication."""
    # Same collapse as is_open_path: a surface's streaming twin is the same
    # surface, so it is the same decision. Both functions apply the rule, or the
    # open-path fast return and the gate could disagree about one URL.
    path = canonical_surface_path(path)
    if is_open_path(method, path):
        return False
    if method in REQUIRE_AUTH_METHODS:
        return True
    if path in REQUIRE_AUTH_PATHS:
        return True
    # All POST/PUT/PATCH require auth (except open paths)
    if method in ("POST", "PUT", "PATCH"):
        return True
    # GET endpoints flagged as auth-required by the pre-launch audit
    # (see REQUIRE_AUTH_GET_PATHS / REQUIRE_AUTH_GET_PREFIXES). Default
    # GET behaviour is unauth; the explicit lists carve out the small
    # set of operational/governance reads that should never be public.
    if method == "GET":
        if path in REQUIRE_AUTH_GET_PATHS:
            return True
        if any(path.startswith(p) for p in REQUIRE_AUTH_GET_PREFIXES):
            return True
        # /api/agents/{id}/export — full per-agent record (25KB+) with
        # skills, reputation, evolution history. Pre-launch audit found
        # this scrapable for every member. The sibling /api/agents/{id}/
        # profile remains open by design (shareable public profile
        # primitive — see is_open_path).
        if path.startswith("/api/agents/") and path.endswith("/export"):
            return True
        # /api/agents/{id}/endorsements — each row names a THIRD PARTY
        # (endorser_agent_id, endorser_did), not just the path's own
        # subject, plus free-text note_markdown: a who-endorsed-whom
        # social graph, not a "this agent exists" disclosure like the
        # open /profile sibling. Not self-scoped; any signed member may
        # read it.
        if path.startswith("/api/agents/") and path.endswith("/endorsements"):
            return True
        # /api/federation/{peer}/members proxies a PEER's directory
        # through us. Leaving it open would launder the very enumeration the
        # gate on /api/members closes — we hold a federation signing key, so
        # an anonymous caller could have us fetch the peer list on their
        # behalf. Same authorization class as the local listing.
        if path.startswith("/api/federation/") and path.endswith("/members"):
            return True
    return False


def _header(headers: dict, name: str) -> str:
    return headers.get(name, headers.get(name.lower(), ""))


def verify_request(
    body: str,
    headers: dict,
    max_age: int = 300,
    method: str = "",
    url_path: str = "",
    require_method_binding: bool = False,
) -> tuple[bool, str, str]:
    """Verify a signed request.

    Returns (valid, agent_id, reason).

    Signature scheme selected by X-Agent-Sig-Scheme header:
      - "ed25519+nonce" → the org protocol v0.3 — canonical string is
        `method:url_path:body:agent_id:timestamp:nonce`. Server enforces
        (agent_id, nonce) uniqueness within the replay-store TTL.
      - "ed25519"       → the org protocol v0.2 — canonical string is
        `body:agent_id:timestamp`. Replay protection is timestamp-window only.
      - "hmac-sha256" or missing → legacy v0.1, HMAC with stored secret.

    `method` and `url_path` are required for v0.3 verification and ignored
    for v0.2 / hmac. Callers (FastAPI middleware) MUST pass them when
    available; v0.3 requests with empty method/url_path will fail signature
    verification because the canonical string won't match what the client
    signed.

    TOFU: a first request with X-Agent-Public-Key (HMAC) or X-Agent-DID-Key
    (Ed25519) header is accepted and the key is stored for subsequent requests.
    """
    agent_id = _header(headers, "X-Agent-ID")
    signature = _header(headers, "X-Agent-Signature")
    timestamp_str = _header(headers, "X-Agent-Timestamp")
    did_key = _header(headers, "X-Agent-DID-Key")
    nonce = _header(headers, "X-Agent-Nonce")
    scheme = (_header(headers, "X-Agent-Sig-Scheme") or "hmac-sha256").lower()

    if not agent_id:
        return False, "", "missing_agent_id"
    if not signature:
        return False, agent_id, "missing_signature"
    if not timestamp_str:
        return False, agent_id, "missing_timestamp"
    if scheme not in ("hmac-sha256", "ed25519", "ed25519+nonce"):
        return False, agent_id, "unknown_sig_scheme"
    if scheme == "ed25519+nonce" and not nonce:
        return False, agent_id, "missing_nonce"
    # C4: a mutation must use the method-bound, replay-protected scheme so a
    # captured GET signature can't be replayed as a state-changing request. The
    # caller (middleware) decides which paths this applies to — the A2A interop
    # POSTs are exempt (see enforce_method_binding).
    if require_method_binding and method.upper() in METHOD_BOUND_REQUIRED_METHODS and scheme != "ed25519+nonce":
        return False, agent_id, "method_binding_required"

    try:
        timestamp = int(timestamp_str)
    except ValueError:
        return False, agent_id, "invalid_timestamp"

    now = int(time.time())
    if abs(now - timestamp) > max_age:
        return False, agent_id, "expired_timestamp"

    if scheme == "ed25519+nonce":
        # v0.3 binds method + url_path + nonce. method is uppercased in the
        # canonical string per spec/0.3/signing.md. Empty url_path is allowed
        # at the spec level (it just produces a different canonical string)
        # but practically every real HTTP request has at least "/".
        message = f"{method.upper()}:{url_path}:{body}:{agent_id}:{timestamp_str}:{nonce}"
    else:
        message = f"{body}:{agent_id}:{timestamp_str}"

    stored = _agent_keys.get(agent_id)

    # Ed25519 path (NANDA Server Protocol v0.2 + v0.3)
    if scheme in ("ed25519", "ed25519+nonce"):
        ed_pubkey = (stored or {}).get("ed25519_pubkey") or ""
        if not ed_pubkey and did_key:
            # Decided BEFORE the key is filed, so a refused caller leaves no
            # trace in _agent_keys and cannot pin a key on an id that is not
            # theirs to claim. The reason is `no_stored_key`, the closed-set
            # string spec/0.5/signing.md provides for exactly this: there is no
            # key on file for the id and one will not be accepted here. It used
            # to be `unknown_agent`, which is not in the set — and which told
            # the caller more, since an unknown id WITHOUT a DID header already
            # got `no_stored_key`; both now read the same.
            if not (tofu_eligible(agent_id) or is_self_authenticating_path(url_path)):
                return False, agent_id, "no_stored_key"
            if store_did_key(agent_id, did_key):
                ed_pubkey = _agent_keys[agent_id]["ed25519_pubkey"]
                tofu = True
            else:
                return False, agent_id, "invalid_did_key"
        else:
            tofu = False
            # spec/0.2 §3.1 idempotence invariant: once a public key has been
            # recorded for an agent_id, subsequent signed requests MUST verify
            # against that key. A request claiming the same agent_id with a
            # different X-Agent-DID-Key is rejected with `key_mismatch` rather
            # than the generic invalid_signature — the explicit reason makes
            # the failure auditable and prevents an attacker from probing
            # blindly with random keypairs hoping for a hash collision.
            if ed_pubkey and did_key:
                try:
                    from sovereign_identity import extract_ed25519_pubkey_from_did_key

                    header_pubkey = extract_ed25519_pubkey_from_did_key(did_key)
                except Exception as e:  # noqa: BLE001 — defensive, but never silent (R6)
                    print(
                        f"[auth][warn] {agent_id}: X-Agent-DID-Key unparseable, key-mismatch check "
                        f"skipped ({type(e).__name__}: {e})"
                    )
                    header_pubkey = ""
                if header_pubkey and header_pubkey != ed_pubkey:
                    return False, agent_id, "key_mismatch"

        if not ed_pubkey:
            return False, agent_id, "no_stored_key"

        try:
            from sovereign_identity import ed25519_verify

            if ed25519_verify(message, signature, ed_pubkey):
                # v0.3: enforce per-request nonce uniqueness AFTER signature
                # verification (so we don't poison the replay store with
                # nonces from forged requests). spec/0.3/signing.md §replay-
                # protection requires (agent_id, nonce) uniqueness within
                # the replay-store TTL.
                if scheme == "ed25519+nonce":
                    if not _v03_replay_check_and_record(agent_id, nonce):
                        return False, agent_id, "nonce_replay"
                return True, agent_id, "tofu_accepted" if tofu else "verified"
        except Exception as e:  # noqa: BLE001 — deny, but never silently (R6)
            print(
                f"[auth][deny] {agent_id}: ed25519 verification raised "
                f"({type(e).__name__}: {e}) — denying as invalid_signature"
            )
        return False, agent_id, "invalid_signature"

    # HMAC-SHA256 path (legacy). Reads still accept it; mutations do NOT — the
    # method-binding gate above (C4) rejects hmac/v0.2 on POST/PUT/PATCH/DELETE,
    # so an HMAC-only member can authenticate GETs but must use the Ed25519 v0.3
    # scheme to change state. The Ed25519 + did:key path is the current default.
    if stored and stored.get("signing_secret"):
        try:
            secret = base64.b64decode(stored["signing_secret"])
            expected = hmac.new(secret, message.encode(), hashlib.sha256).digest()
            provided = base64.b64decode(signature)
            if hmac.compare_digest(expected, provided):
                return True, agent_id, "verified"
        except Exception as e:  # noqa: BLE001 — deny, but never silently (R6)
            print(
                f"[auth][deny] {agent_id}: hmac verification failed to run "
                f"({type(e).__name__}: {e}) — denying as invalid_signature"
            )
        return False, agent_id, "invalid_signature"

    # No HMAC trust-on-first-use. An X-Agent-Public-Key header is NOT proof of
    # possession of an HMAC secret (HMAC is symmetric — it has no public key),
    # so accepting a first request on the strength of it would verify an
    # arbitrary caller as an arbitrary identity. HMAC members must be
    # registered with a signing_secret out-of-band (/api/members →
    # load_keys_from_members), after which the block above verifies them. A new
    # identity that wants first-contact TOFU must use the self-authenticating
    # Ed25519 + did:key path, where the signature is actually checked against
    # the key embedded in the DID.
    if not stored:
        return False, agent_id, "no_stored_key"

    # A stored key that the presented signature does not verify against. Said
    # with the closed-set word for it (spec/0.5/signing.md step 5); this used
    # to be `verification_failed`, which is not in the set.
    return False, agent_id, "invalid_signature"


def load_keys_from_members(members: dict):
    """Load stored keys from the members dict on startup.

    Extracts both HMAC (public_key + signing_secret) and Ed25519 (from
    agent_facts.provider.did did:key) keypairs so both verification
    paths work for already-registered members after a restart.
    """
    try:
        from sovereign_identity import pubkey_from_provider_did as _provider_did_pubkey
    except ImportError as e:
        # Broken deployment: without sovereign_identity no Ed25519 key can be
        # rehydrated on startup — every member silently degrades to HMAC-or-
        # nothing. Log it once here rather than as N mystery auth denials (R6).
        print(f"[auth][error] load_keys_from_members: sovereign_identity unavailable ({e}) — Ed25519 keys NOT loaded")

        def _provider_did_pubkey(did: str) -> str:
            return ""

    for agent_id, member in members.items():
        pk = member.get("public_key", "")
        secret = member.get("signing_secret", "")
        facts = member.get("agent_facts") or {}
        did = (facts.get("provider") or {}).get("did") or ""
        # dual-format — W3C did:key:z… AND the legacy raw-b64 carrier
        # both rehydrate, so pre-migration rows keep authenticating.
        ed_pub = _provider_did_pubkey(did)
        if pk or secret or ed_pub:
            store_agent_key(agent_id, pk, secret, ed25519_pubkey=ed_pub or "")
