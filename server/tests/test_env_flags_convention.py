"""Every environment variable is classified, and security gates use env_flags.

``env_flags.security_flag(name, *, default)`` exists so that the direction a
security flag fails when nobody set it is written at the call site rather than
emerging from a parsing expression. Its own docstring lists four incidents that
had that shape. Nothing asserted that a security-gating variable actually goes
through it: ``test_env_flags.py`` tests the function, not its use, and at the
time this guard was written 5 of 68 environment names used it.

WHAT THIS GUARD ENFORCES

The set of environment reads is DERIVED — ``env_read_scan`` walks the AST of
every module and resolves names given as module-level constants, so a read
cannot hide from it by being written indirectly. The set of names that are
SECURITY-RELEVANT is DECLARED below, because no rule over names decides it:
``ORG_HOST39_CARD_BASE`` contains no security token and is not a gate,
``ORG_ADMIN_TOKEN`` is a credential rather than a flag, and ``PUBLIC_URL``
matches a naive keyword scan while deciding nothing. A declared list of what is
security-relevant can be reviewed; a rule guessing where to look cannot.

The two halves meet at ``test_every_environment_read_is_classified``: a name the
scan finds and the declaration does not cover fails the suite. A variable added
tomorrow must be classified before it can land, and classifying it is where
someone decides whether it gates anything.

THE FOUR CLASSES

``SECURITY_FLAG_REQUIRED``      a boolean security gate. Must be read only through
                                ``env_flags.security_flag``.
``SECURITY_RELEVANT_DEVIATION`` a boolean security gate that is NOT read through
                                ``security_flag``, each with the reason routing it
                                would change behaviour. Reviewable, not silent.
``SECURITY_RELEVANT_VALUE``     security-relevant and not a boolean — a credential,
                                a trust anchor, a window, a cap. ``security_flag``
                                returns a bool and does not apply.
``NOT_SECURITY_RELEVANT``       everything else. Names that a keyword scan would
                                flag carry a reason; the rest are listed plainly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.env_read_scan import scan_file, scan_tree

SERVER = Path(__file__).resolve().parents[1]

#: Not scanned: the test suite sets variables rather than gating on them, and
#: _arp_verify is a byte-for-byte vendored mirror that must not be edited here.
SKIP_PARTS = ("tests", "_arp_verify", "scripts")


# ══════════════════════════════════════════════════════════════════════
# The declaration
# ══════════════════════════════════════════════════════════════════════

SECURITY_FLAG_REQUIRED: dict[str, str] = {
    "FEDERATION_ENFORCE_SIGNED_BROADCASTS": "Rejects unsigned peer broadcasts. Defaults on.",
    "FEDERATION_REQUIRE_SIGNED_RECORDS": "Rejects unsigned registry records. Defaults on.",
    "ORRERY_REQUIRE_SEALED_SECRETS": "Refuses to boot with secrets unsealed at rest. Defaults on.",
    "KLAVIYO_LIVE_SENDS": "Permits outbound messages to real recipients. Defaults off.",
    "ORRERY_LISTING_ENABLED": "Permits publishing a member listing. Defaults off.",
    "FEDERATION_AUTODISCOVER": "Permits discovering peers from the registry. Defaults off.",
    "LLM_STRICT": (
        "Refuses to build an LLM client without a usable credential. Decides whether "
        "member names, skill lists and federation peer names leave the box when no "
        "provider is configured. Defaults off for one release so the report-only diff "
        "can be read from deployed servers first."
    ),
    "LLM_AUTODETECT": (
        "Permits inferring a provider from whichever key is in the environment when "
        "LLM_PROVIDER is unset. With it on and nothing configured, a client is still "
        "aimed at a real third party. Defaults on, which is the existing behaviour."
    ),
}

SECURITY_RELEVANT_DEVIATION: dict[str, str] = {
    "AUTO_REGISTER": (
        "Boolean gate on publishing this org to a public registry. Reading it through "
        "security_flag would change what an unrecognised value means: the inline parse "
        "treats any unrecognised spelling as falsey (does not publish), security_flag "
        "treats it as undecided and returns the default (publishes). Widening 'publish' "
        "to cover typos is a decision about a public side effect, and the direction of "
        "this flag is an open question held elsewhere. Classified rather than changed."
    ),
    "ORG_RETENTION_SWEEP_ENABLED": (
        "Boolean gate on a sweeper that DELETEs. Two reasons it is not routed. It is an "
        "alias pair read in precedence order with CHAPTER_RETENTION_SWEEP_ENABLED, and "
        "security_flag takes a single name. And the current parse treats an EMPTY value "
        "as off, where security_flag treats empty as undecided and returns the default, "
        "which here is on — so routing it would turn an operator's paused sweeper into a "
        "deleting one. test_retention.py pins the empty-value behaviour."
    ),
    "CHAPTER_RETENTION_SWEEP_ENABLED": "Back-compat alias of ORG_RETENTION_SWEEP_ENABLED; same reasoning.",
    "ORG_RETENTION_SWEEP_DRY_RUN": (
        "Boolean gate deciding whether the sweeper deletes or only reports. Same alias-pair "
        "and empty-value reasoning as ORG_RETENTION_SWEEP_ENABLED."
    ),
    "CHAPTER_RETENTION_SWEEP_DRY_RUN": "Back-compat alias of ORG_RETENTION_SWEEP_DRY_RUN; same reasoning.",
}

SECURITY_RELEVANT_VALUE: dict[str, str] = {
    # Credentials
    "ORG_ADMIN_TOKEN": "Admin bearer credential. Empty never verifies; a token is generated if unset.",
    "CHAPTER_ADMIN_TOKEN": "Back-compat alias of ORG_ADMIN_TOKEN.",
    "METRICS_BEARER_TOKEN": "Bearer credential for /metrics. Unset serves the endpoint unauthenticated.",
    "ORRERY_KEY_SECRET": "Key-encryption secret. Absence is refused at boot by ORRERY_REQUIRE_SEALED_SECRETS.",
    "ORRERY_KEY_SECRET_PREVIOUS": (
        "The key-encryption secret being rotated out. Read-only: values sealed under it still "
        "unseal and are resealed in place under ORRERY_KEY_SECRET at boot; nothing is ever sealed "
        "under it. Unset once the migrations have run. Without it a changed ORRERY_KEY_SECRET "
        "strands every sealed row, the signing key first."
    ),
    "INDEX_ACCOUNT_PASSWORD": "Registry account credential used when registering this org.",
    "LLM_API_KEY": "Model provider credential; sealed at rest with the member keys.",
    "LLM_BASE_URL": (
        "Outbound destination that receives prompts and the resolved provider credential; "
        "an override changes the model egress trust boundary."
    ),
    "KLAVIYO_API_KEY": "Provider credential; sending is separately gated by KLAVIYO_LIVE_SENDS.",
    "DATABASE_URL": "Database DSN, carrying credentials.",
    # Trust anchors — what the org will believe
    "KNOWN_CHAPTER_ENDPOINTS": "Operator-named peer endpoints. An entry here is a trust anchor.",
    "FEDERATION_DIRECTORY_URLS": "Directories consulted for peers.",
    "REGISTRY_URL": "Registry this org publishes to and reads peers from.",
    "NANDA_INDEX_URL": "Index endpoint used for registration.",
    "ALLOWED_ORIGINS": "CORS allowlist. Unset disables cross-origin browser access.",
    "ORRERY_PROFILE": "Selects the prod or dev profile, which decides the ALLOWED_ORIGINS default.",
    # Request-attribution inputs
    "TRUSTED_PROXY_HOPS": "How many proxy hops may set X-Forwarded-For. Malformed parses to 0, trusting none.",
    "FORWARDED_ALLOW_IPS": "Peers uvicorn accepts forwarded headers from.",
    # Windows and caps
    "FEDERATION_BROADCAST_MAX_AGE_S": "Replay window for a signed broadcast. Malformed falls back to 300s.",
    "FEDERATION_ROTATION_MAX_AGE_S": "Freshness window for a key-rotation attestation.",
    "REGISTRY_ATTESTATION_TTL_S": "Validity window for a registry attestation.",
    "FEDERATION_PEER_PRUNE_AFTER_S": "Age at which a stale peer is pruned.",
    "MAX_MEMBERS": "Registration cap; the bound on unbounded growth from an open path.",
    "ORRERY_RATE_LIMIT_PERSIST_INTERVAL_S": (
        "Seconds between rate-limiter snapshots, and therefore the UPPER BOUND ON HOW MUCH "
        "budget a restart hands back to a client. Raising it widens that gap; the limiter "
        "itself keeps working either way. Floors at 1s; a malformed value degrades to the "
        "default with a warning, matching TRUSTED_PROXY_HOPS — a typo in a tuning knob for "
        "an optional feature has no better claim to stopping the server than a missing "
        "table does."
    ),
    "ORRERY_RATE_LIMIT_PERSIST_MAX_KEYS": (
        "Buckets written per snapshot. Decides WHOSE limiter state survives a restart: the "
        "fullest buckets are kept first, so lowering it drops the clients furthest from "
        "their ceiling last. Floors at 1."
    ),
    "ORRERY_RATE_LIMIT_SALT": (
        "HMAC salt under which rate-limiter bucket keys (client IPs) are hashed before they "
        "are persisted. A secret, not a flag: it is what keeps a dump of rate_limit_buckets "
        "from being turned back into client IPs, and it is the only salt source that survives "
        "a restart on a service with no persistent volume. Unset falls back to a file in the "
        "org data directory and /health names the source in use; a value shorter than 16 "
        "characters is rejected by name rather than used, and an ephemeral salt is minted "
        "so the limiter still limits."
    ),
    # Storage and data-handling posture
    "ORRERY_DB_SSL": "asyncpg ssl mode. Passed through unvalidated; an unrecognised value is not the default.",
    "ORG_JURISDICTION": "Selects per-region retention, which decides what the sweeper deletes.",
    "CHAPTER_JURISDICTION": "Back-compat alias of ORG_JURISDICTION.",
    "ORG_HOME": "Filesystem root for the admin token file.",
    "CHAPTER_HOME": "Back-compat alias of ORG_HOME.",
}

NOT_SECURITY_RELEVANT: dict[str, str] = {
    # Names a keyword scan flags but which gate nothing. These are the
    # must-not-match cases: without them the classifier looks stricter than it is.
    "PUBLIC_URL": "The org's own public address. Advertised, not trusted; decides no access.",
    "RAILWAY_PUBLIC_DOMAIN": "Platform-injected hostname used to derive PUBLIC_URL.",
    "ORG_HOST39_CARD_BASE": "Base URL for building a member's card link.",
    "ORG_AGENT_PREFIX": "String stripped from a member id when building that link.",
    "ORG_DOMAIN": "Domain shown in this org's registry metadata.",
    "INDEX_ACCOUNT_EMAIL": "Account identifier for registration; the password is the credential.",
    "ORG_CONTACT_EMAIL": "Contact address published in registry metadata.",
    "INDEX_ORG_ID": "Identifier of this org's own registry record; names a record, grants nothing.",
    "LLM_ELIDE_ENABLED": (
        "Skips an LLM call whose prompt inputs are unchanged. Gates only the two "
        "narrative types (insight, introduction_propose) — never approvals_sweep, "
        "retention_sweep or any path that decides access. Worst case with it on is "
        "a stale card for up to the 24h floor. Defaults off."
    ),
    "LLM_MAX_OUTPUT_TOKENS": (
        "Ceiling injected when a request omits max_tokens. Bounds spend and runaway "
        "output; grants nothing and gates no path. Zero disables injection, which is "
        "the escape hatch for wanting the provider default. Defaults 1024."
    ),
    "DEFAULT_SCORING_METHOD": "Reputation scoring method; unsupported values fall back to the default.",
    "MEMBER_PERSIST_OUTBOX_PATH": "On-disk path for the member-persistence outbox.",
    # Identity and presentation
    "AGENT_ID": "Identifier of this org agent; asserts no privilege by itself.",
    "AGENT_NAME": "Display name shown for this org agent.",
    "AGENT_DESCRIPTION": "Description shown in org metadata.",
    "AGENT_FOCUS": "Focus area shown in org metadata.",
    "AGENT_REGION": "Region label shown in org metadata.",
    "AGENT_LEADERS": "Leader names shown in org metadata; grants no authority.",
    "ORG_SLUG": "URL slug used in this org's public links.",
    "CHAPTER_SLUG": "Back-compat alias of ORG_SLUG.",
    "ORG_DISPLAY_NAME": "Display name override for the org agent.",
    "CHAPTER_DISPLAY_NAME": "Back-compat alias of ORG_DISPLAY_NAME.",
    # Model and runtime tuning
    "LLM_PROVIDER": "Which model provider to call.",
    "LLM_MODEL": "Model name passed to the provider.",
    "DEFAULT_LLM_MODEL": "Model name used when LLM_MODEL is unset.",
    # Read by llm_runtime.build_client, which is now the only place a client is
    # constructed. Neither decides whether a request leaves the box — only how
    # long one may take and how many times the SDK may repeat it — so both are
    # tuning rather than gates. The variables that DO decide egress are declared
    # among the security flags, not here.
    # Tiering, and it belongs here for the same reason LLM_MODEL does: it selects
    # WHICH model runs a call, never whether the call may leave the box. When set
    # it makes the selection stricter — refusing to move a call onto a model with
    # no capability measurement — so the permissive direction is the default and
    # the deviation is opt-in, which is the opposite of a gate that can be
    # accidentally disabled.
    "LLM_TIER_REQUIRE_MEASURED": "Require a positive capability measurement before a call is tiered.",
    # A latency and rate-limit bound rather than a spend one — the 40-call cycle
    # it was written for cost 1,897 tokens in total. It decides how many calls one
    # cycle may make, never whether a call may leave the box.
    "LLM_MAX_CALLS_PER_CYCLE": "How many LLM calls one think cycle may make before the factory refuses.",
    "LLM_MAX_RETRIES": "How many times the SDK may retry one logical call.",
    "LLM_TIMEOUT_S": "Seconds before one LLM request is abandoned.",
    "PORT": "TCP port the server listens on; the bind address is set elsewhere.",
    "THINK_CYCLE_INTERVAL": "Seconds between think cycles (org path).",
    "COMMUNITY_MEMBER_THINK_INTERVAL": "Seconds between think cycles (member path).",
    "SSE_POLL_INTERVAL_S": "Seconds between SSE polls.",
    "FEDERATION_QUERY_TIMEOUT": "Timeout for a federation query.",
}

CLASSES = {
    "SECURITY_FLAG_REQUIRED": SECURITY_FLAG_REQUIRED,
    "SECURITY_RELEVANT_DEVIATION": SECURITY_RELEVANT_DEVIATION,
    "SECURITY_RELEVANT_VALUE": SECURITY_RELEVANT_VALUE,
    "NOT_SECURITY_RELEVANT": NOT_SECURITY_RELEVANT,
}


@pytest.fixture(scope="module")
def reads():
    found = scan_tree(SERVER, skip=SKIP_PARTS)
    assert found, "the environment scan found nothing; it is broken, not clean"
    return found


def _names(reads) -> set[str]:
    return {r.name for r in reads}


# ══════════════════════════════════════════════════════════════════════
# The declaration covers the code, and the classes are disjoint
# ══════════════════════════════════════════════════════════════════════


def test_the_scan_finds_a_realistic_number_of_reads(reads):
    """A scan that silently stopped resolving names would report a clean tree."""
    assert len(_names(reads)) > 50, f"only {len(_names(reads))} names found; the scan is broken"


def test_every_environment_read_is_classified(reads):
    declared = set().union(*(set(c) for c in CLASSES.values()))
    unclassified = sorted(_names(reads) - declared)
    assert not unclassified, (
        "these environment variables are read and not classified:\n  "
        + "\n  ".join(unclassified)
        + "\n\nAdd each to one of SECURITY_FLAG_REQUIRED, SECURITY_RELEVANT_DEVIATION, "
        "SECURITY_RELEVANT_VALUE or NOT_SECURITY_RELEVANT with a reason. Classifying it "
        "is where someone decides whether it gates anything."
    )


def test_no_variable_is_in_two_classes():
    seen: dict[str, str] = {}
    for class_name, members in CLASSES.items():
        for name in members:
            assert name not in seen, f"{name} is in both {seen[name]} and {class_name}"
            seen[name] = class_name


def test_the_declaration_does_not_describe_variables_that_are_gone(reads):
    """A classification for a name nothing reads is a claim about code that does
    not exist, and it hides that the variable was removed."""
    present = _names(reads)
    stale = sorted(n for c in CLASSES.values() for n in c if n not in present)
    assert not stale, "classified but no longer read anywhere:\n  " + "\n  ".join(stale)


def test_every_classification_states_a_reason():
    for class_name, members in CLASSES.items():
        for name, reason in members.items():
            assert len(reason.strip()) >= 25, f"{class_name}[{name}] has no real reason: {reason!r}"


def test_llm_base_url_is_classified_as_a_security_relevant_egress_boundary() -> None:
    reason = SECURITY_RELEVANT_VALUE.get("LLM_BASE_URL", "")
    assert "egress" in reason.lower()
    assert "credential" in reason.lower()


# ══════════════════════════════════════════════════════════════════════
# The convention itself
# ══════════════════════════════════════════════════════════════════════


def test_security_gates_are_read_through_env_flags(reads):
    """The rule the helper exists for."""
    violations = [str(r) for r in reads if r.name in SECURITY_FLAG_REQUIRED and not r.via_security_flag]
    assert not violations, (
        "these security gates are parsed inline instead of through "
        "env_flags.security_flag, so the direction they fail when unset is not "
        "written at the call site:\n  " + "\n  ".join(violations)
    )


def test_a_deviation_is_never_also_read_through_env_flags(reads):
    """A name declared as deviating that in fact uses the helper is a stale
    justification for a problem someone already fixed."""
    wrong = [str(r) for r in reads if r.name in SECURITY_RELEVANT_DEVIATION and r.via_security_flag]
    assert not wrong, (
        "these are declared as deviations but do go through security_flag; move them "
        "to SECURITY_FLAG_REQUIRED:\n  " + "\n  ".join(wrong)
    )


def test_a_non_boolean_is_never_read_through_env_flags(reads):
    """security_flag returns a bool. A credential or a window read through it
    would be silently reduced to true/false."""
    wrong = [
        str(r) for r in reads if r.via_security_flag and r.name in (SECURITY_RELEVANT_VALUE | NOT_SECURITY_RELEVANT)
    ]
    assert not wrong, "non-boolean variables read through security_flag:\n  " + "\n  ".join(wrong)


def test_every_declared_security_gate_has_an_explicit_default():
    """``default`` is keyword-only and mandatory in the helper, so a call missing
    it does not run. Asserted from the source anyway: this file is where someone
    reads what the convention requires."""
    import inspect

    import env_flags

    signature = inspect.signature(env_flags.security_flag)
    default = signature.parameters["default"]
    assert default.kind is inspect.Parameter.KEYWORD_ONLY
    assert default.default is inspect.Parameter.empty, "default must stay mandatory"


# ══════════════════════════════════════════════════════════════════════
# The guard detects a new violation
# ══════════════════════════════════════════════════════════════════════


def test_a_newly_added_inline_security_flag_is_caught(tmp_path):
    """Proven by adding one, in the form someone would actually write."""
    module = tmp_path / "new_feature.py"
    module.write_text(
        "import os\n"
        "def enforcement_enabled() -> bool:\n"
        '    return os.environ.get("ORRERY_ENFORCE_NEW_THING", "").lower() in ("1", "true")\n'
    )
    found = scan_file(module)
    assert [r.name for r in found] == ["ORRERY_ENFORCE_NEW_THING"]
    assert found[0].via_security_flag is False

    declared = set().union(*(set(c) for c in CLASSES.values()))
    assert found[0].name not in declared, (
        "a variable that does not exist is already classified; the fixture name clashes"
    )


def test_an_indirectly_named_read_is_still_found(tmp_path):
    """A read whose name is held in a module constant. Without resolution the
    scan reports the constant's identifier and the classification never matches,
    which would make the guard pass by failing to see anything."""
    module = tmp_path / "indirect.py"
    module.write_text(
        "import os\n"
        'SECRET_ENV = "ORRERY_INDIRECT_SECRET"\n'
        "def read() -> str:\n"
        '    return os.environ.get(SECRET_ENV, "")\n'
    )
    assert [r.name for r in scan_file(module)] == ["ORRERY_INDIRECT_SECRET"]


def test_a_read_through_env_flags_is_recognised_as_such(tmp_path):
    module = tmp_path / "good.py"
    module.write_text(
        'import env_flags\ndef gate() -> bool:\n    return env_flags.security_flag("ORRERY_GOOD_GATE", default=True)\n'
    )
    found = scan_file(module)
    assert [r.name for r in found] == ["ORRERY_GOOD_GATE"]
    assert found[0].via_security_flag is True


# ══════════════════════════════════════════════════════════════════════
# The metrics bearer token is compared in constant time
# ══════════════════════════════════════════════════════════════════════


def test_the_metrics_token_is_compared_with_compare_digest():
    """``!=`` on str compares length first and stops at the first differing
    byte. ``admin.verify_admin_token`` and ``auth_verify`` already use
    ``compare_digest`` for the same job; this handler did not, and a codebase
    that is constant-time in two places out of three leaves the reader guessing
    which was deliberate.

    Asserted from the source because the property is the comparison used, not an
    observable response: both a right and a wrong token return the same status.
    """
    import ast
    import inspect

    import chapter_agent

    source = inspect.getsource(chapter_agent.metrics_endpoint)
    tree = ast.parse(source.lstrip())
    calls = {
        getattr(n.func, "attr", None) or getattr(n.func, "id", None) for n in ast.walk(tree) if isinstance(n, ast.Call)
    }
    assert "compare_digest" in calls, "the metrics bearer token is not compared in constant time"

    compares = [n for n in ast.walk(tree) if isinstance(n, ast.Compare)]
    for node in compares:
        ops = {type(op).__name__ for op in node.ops}
        if ops & {"Eq", "NotEq"}:
            src = ast.unparse(node)
            assert "expected" not in src, f"the token is still compared with an operator: {src}"


def test_a_wrong_metrics_token_is_refused_and_a_right_one_is_accepted(monkeypatch):
    """The behaviour the comparison change must not alter."""
    from fastapi.testclient import TestClient

    from tests._admin_fixtures import reset_chapter_agent_module

    token = "e" * 48
    monkeypatch.setenv("METRICS_BEARER_TOKEN", token)
    mod = reset_chapter_agent_module(monkeypatch, agent_id="TEST-metrics-chapter")
    client = TestClient(mod.app)

    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer " + "f" * 48}).status_code == 401
    assert client.get("/metrics", headers={"Authorization": token}).status_code == 401
    assert client.get("/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_a_non_ascii_token_is_refused_rather_than_raising(monkeypatch):
    """``compare_digest`` raises TypeError when handed str with a codepoint above
    255, so both sides are encoded first and a hostile token returns 401 rather
    than a 500.

    Sent as bytes: HTTP headers are latin-1 on the wire and the client refuses a
    str containing a codepoint it cannot encode, so the only way this input
    reaches the handler at all is as raw bytes."""
    from fastapi.testclient import TestClient

    from tests._admin_fixtures import reset_chapter_agent_module

    monkeypatch.setenv("METRICS_BEARER_TOKEN", "e" * 48)
    mod = reset_chapter_agent_module(monkeypatch, agent_id="TEST-metrics-chapter")
    client = TestClient(mod.app)

    resp = client.get("/metrics", headers={"Authorization": "Bearer ünïcödé".encode("latin-1")})
    assert resp.status_code == 401
