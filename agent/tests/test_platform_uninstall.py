"""Platform uninstall webhooks — the buildable half of the platform-uninstall work.

⚠️ THE LOAD-BEARING ASSERTION: an uninstall produces ``suspended``, NOT
``revoked``. The owner-attested rework built ``owner_attested`` precisely so a runtime's word is never
reported as the owner's; an uninstall is a PLATFORM's observation of its own
billing and the owner asserted nothing. Recording it as a revocation would
attribute a withdrawal to someone who never made one — and ``revoked`` is
terminal, so a business that switches POS and comes back would need fresh consent
for an event it never performed.

⚠️ AND THE SECURITY DIRECTION: an unverified webhook must transition NOTHING.
An attacker who could suspend arbitrary listings with an unsigned POST would hold
a denial-of-listing primitive over every business served, so the refusals here
matter as much as the happy path.
"""

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest

from community_member import owner, platform_events
from community_member.crypto import build_did_key

AGENT_DID = build_did_key(base64.b64encode(b"\x01" * 32).decode())
SECRET = "a-real-shared-secret"
PLATFORM = "square"


@pytest.fixture
def home(tmp_path):
    return tmp_path


@pytest.fixture
def owner_identity():
    return owner.mint_owner_identity()


def _establish(home, identity, subject="moonbakery.com"):
    nonce = owner.owner_nonce(identity.did, "r")
    anchor = {"method": "oidc", "issuer": "https://accounts.google.com", "id": "sub-1"}
    owner.save_binding(
        home,
        owner_did=identity.did,
        subject=subject,
        anchor=anchor,
        evidence=owner.build_owner_evidence(
            owner=identity, subject=subject, anchor=anchor, id_token="h.p.s", nonce=nonce
        ),
        grant=owner.build_listing_grant(owner=identity, agent_did=AGENT_DID),
    )


def _body(event_id="evt-1", *, when=None, extra=None):
    payload = {
        "event_id": event_id,
        "occurred_at": (when or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subject": "moonbakery.com",
    }
    payload.update(extra or {})
    return json.dumps(payload).encode()


def _sign(raw, secret=SECRET):
    return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def _env(secret=SECRET, platform=PLATFORM):
    return {f"ORRERY_PLATFORM_WEBHOOK_SECRET_{platform.upper()}": secret}


# ── ⚠️ suspended, not revoked ────────────────────────────────────────────────


def test_a_verified_uninstall_suspends_and_does_not_revoke(home, owner_identity):
    _establish(home, owner_identity)
    raw = _body()
    result = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())

    assert result.outcome == platform_events.APPLIED
    assert result.state_changed is True
    answer = owner.resolve_lifecycle(owner.load_binding(home))
    assert answer.state == owner.LIFECYCLE_SUSPENDED
    assert answer.state != owner.LIFECYCLE_REVOKED, "an uninstall must never be recorded as an owner withdrawal"


def test_the_recorded_authority_is_the_platform_not_the_owner(home, owner_identity):
    """The owner asserted nothing. Naming them as the actor would be a lie the
    resolution surface then repeats to every caller."""
    _establish(home, owner_identity)
    raw = _body()
    platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())

    answer = owner.resolve_lifecycle(owner.load_binding(home))
    assert answer.by == f"platform:{PLATFORM}"
    assert answer.by != owner_identity.did


def test_a_platform_suspension_is_never_owner_attested(home, owner_identity):
    _establish(home, owner_identity)
    raw = _body()
    platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())

    answer = owner.resolve_lifecycle(owner.load_binding(home))
    assert answer.attested is False
    assert answer.to_public_dict()["owner_attested"] is False


def test_the_suspension_is_reversible_which_is_the_point(home, owner_identity):
    """A business that switches POS and comes back must not need fresh consent
    for an event it never performed. That is why this is not terminal."""
    _establish(home, owner_identity)
    raw = _body()
    platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())
    assert owner.resume_listing(home).state == owner.LIFECYCLE_ACTIVE


def test_an_owner_revocation_outranks_a_later_platform_uninstall(home, owner_identity):
    """The owner's withdrawal is the stronger claim and is terminal. The event is
    recorded so the platform's retries stop, but nothing transitions and the
    outcome says which case it was."""
    _establish(home, owner_identity)
    owner.revoke_listing(home)
    raw = _body()
    result = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())

    assert result.outcome == platform_events.NO_TRANSITION
    assert result.state_changed is False
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_REVOKED


def test_the_listing_gate_reports_suspended_after_an_uninstall(home, owner_identity):
    """It composes with the owner-attested rework's gate rather than being a parallel state store."""
    _establish(home, owner_identity)
    raw = _body()
    platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())
    assert owner.listing_grant_verdict(owner.load_binding(home), AGENT_DID).reason == "suspended"


def test_no_parallel_state_store_is_created(home, owner_identity):
    """The transition goes through the owner-attested rework API, so the lifecycle lives in the
    binding. The only extra file is the replay ledger, which holds event ids."""
    _establish(home, owner_identity)
    raw = _body()
    platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())
    written = {p.name for p in home.iterdir() if p.is_file()}
    assert written <= {owner.BINDING_FILE, platform_events.EVENT_LEDGER_FILE}
    ledger = json.loads((home / platform_events.EVENT_LEDGER_FILE).read_text())
    assert ledger == [f"{PLATFORM}:evt-1"], "the ledger should hold event ids, not lifecycle state"


# ── ⚠️ fail closed: nothing unverified may transition anything ───────────────


def test_an_unsigned_event_changes_nothing(home, owner_identity):
    _establish(home, owner_identity)
    result = platform_events.receive_uninstall(home, PLATFORM, _body(), "", env=_env())
    assert result.outcome == platform_events.REFUSED
    assert result.reason == "invalid_signature"
    assert result.state_changed is False
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE


def test_a_wrongly_signed_event_changes_nothing(home, owner_identity):
    _establish(home, owner_identity)
    raw = _body()
    result = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw, "wrong-secret"), env=_env())
    assert result.outcome == platform_events.REFUSED
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE


def test_a_signature_over_different_bytes_is_refused(home, owner_identity):
    """The signature covers the RAW body. Re-serialising JSON changes bytes, so
    a signature computed over a re-encoding must not verify."""
    _establish(home, owner_identity)
    raw = _body()
    reserialised = json.dumps(json.loads(raw), sort_keys=True, indent=2).encode()
    assert reserialised != raw
    result = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(reserialised), env=_env())
    assert result.outcome == platform_events.REFUSED


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
def test_unset_and_empty_secret_are_the_same_error(home, owner_identity, blank):
    """⚠️ A blank secret is a deployment that looks
    configured while accepting an HMAC anyone can compute."""
    _establish(home, owner_identity)
    raw = _body()
    for env in ({}, _env(blank)):
        result = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=env)
        assert result.outcome == platform_events.REFUSED
        assert result.reason.startswith("not_configured")
        assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE


def test_there_is_no_default_secret():
    with pytest.raises(platform_events.PlatformEventError, match="not set"):
        platform_events.webhook_secret(PLATFORM, env={})
    with pytest.raises(platform_events.PlatformEventError, match="empty secret"):
        platform_events.make_hmac_verifier("  ")


def test_an_unverified_request_does_not_even_read_the_binding(home, owner_identity, monkeypatch):
    """Verification comes first, so a hostile caller cannot probe for whether a
    binding exists by watching how the endpoint behaves."""
    _establish(home, owner_identity)
    called = []
    monkeypatch.setattr(owner, "load_binding", lambda *a, **k: called.append(1))
    platform_events.receive_uninstall(home, PLATFORM, _body(), "nope", env=_env())
    assert called == []


def test_a_broken_verifier_refuses_rather_than_passing(home, owner_identity):
    _establish(home, owner_identity)

    def boom(*_a):
        raise RuntimeError("verifier exploded")

    result = platform_events.receive_uninstall(home, PLATFORM, _body(), "sig", verifier=boom, env=_env())
    assert result.outcome == platform_events.REFUSED
    assert "verifier_error" in result.reason
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        json.dumps({"occurred_at": "2026-01-01T00:00:00Z"}).encode(),  # no id
        json.dumps({"event_id": "e"}).encode(),  # no timestamp
    ],
)
def test_a_malformed_event_is_refused_not_guessed_at(home, owner_identity, body):
    """A guess here would transition state, so there is no guessing."""
    _establish(home, owner_identity)
    result = platform_events.receive_uninstall(home, PLATFORM, body, _sign(body), env=_env())
    assert result.outcome == platform_events.REFUSED
    assert result.reason.startswith("malformed_event")
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE


# ── replay ───────────────────────────────────────────────────────────────────


def test_a_replayed_event_transitions_nothing_a_second_time(home, owner_identity):
    _establish(home, owner_identity)
    raw = _body()
    first = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())
    owner.resume_listing(home)  # the owner puts it back
    second = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())

    assert first.outcome == platform_events.APPLIED
    assert second.outcome == platform_events.ALREADY_APPLIED
    assert second.state_changed is False
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE, (
        "a replayed uninstall re-suspended a listing the owner had resumed"
    )


def test_a_duplicate_delivery_is_not_reported_as_a_failure(home, owner_identity):
    """⚠️ Deliberately NOT a refusal. Platforms retry on non-success, so failing a
    duplicate would produce a retry storm over an event handled correctly."""
    _establish(home, owner_identity)
    raw = _body()
    platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())
    second = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())
    assert second.ok is True
    assert second.outcome != platform_events.REFUSED


def test_a_stale_but_correctly_signed_event_is_refused(home, owner_identity):
    """Without a freshness window a single captured webhook is a permanent
    suspend primitive."""
    _establish(home, owner_identity)
    old = datetime.now(timezone.utc) - timedelta(seconds=platform_events.MAX_EVENT_AGE_SECONDS + 60)
    raw = _body(when=old)
    result = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())
    assert result.outcome == platform_events.REFUSED
    assert result.reason.startswith("stale_event")
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE


def test_an_unparseable_timestamp_is_not_fresh(home, owner_identity):
    _establish(home, owner_identity)
    raw = _body(extra={"occurred_at": "whenever"})
    result = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())
    assert result.outcome == platform_events.REFUSED
    assert result.reason.startswith("stale_event")


def test_distinct_events_from_the_same_platform_are_both_honoured(home, owner_identity):
    _establish(home, owner_identity)
    for eid in ("evt-a", "evt-b"):
        raw = _body(eid)
        result = platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env())
        assert result.outcome in {platform_events.APPLIED, platform_events.NO_TRANSITION}
        owner.resume_listing(home)


def test_the_replay_ledger_survives_corruption_by_failing_open_to_empty(home, owner_identity):
    """A corrupt ledger must not wedge the receiver — worst case an event is
    processed twice, which suspends an already-suspended listing (a no-op)."""
    _establish(home, owner_identity)
    (home / platform_events.EVENT_LEDGER_FILE).write_text("{not json")
    raw = _body()
    assert platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env()).outcome == (
        platform_events.APPLIED
    )


# ── the injected seam, and what this module must never contain ───────────────


def test_verification_is_injectable_so_a_real_platform_scheme_drops_in(home, owner_identity):
    """The wire shape is an ASSUMPTION. A provider whose scheme differs supplies
    its own verifier and the receiver is untouched — the same seam discipline as
    owner.make_bound_domain_control_verifier."""
    _establish(home, owner_identity)
    seen = {}

    def square_style(raw, signature):
        seen["raw"] = raw
        seen["sig"] = signature
        return signature == "whatever-this-platform-does"

    result = platform_events.receive_uninstall(
        home, PLATFORM, _body(), "whatever-this-platform-does", verifier=square_style, env={}
    )
    assert result.outcome == platform_events.APPLIED
    assert seen["raw"] == _body()[: len(seen["raw"])] or isinstance(seen["raw"], bytes)
    # An injected verifier is used INSTEAD of the secret lookup, so an unset
    # secret does not block a platform that authenticates differently.


def test_base64_and_sha512_variants_are_supported_without_a_rewrite():
    raw = b'{"a":1}'
    b64 = base64.b64encode(hmac.new(SECRET.encode(), raw, hashlib.sha512).digest()).decode()
    verify = platform_events.make_hmac_verifier(SECRET, digest="sha512", encoding="base64")
    assert verify(raw, b64) is True
    assert verify(raw, "AAAA") is False


def test_unsupported_digest_or_encoding_is_refused_not_silently_downgraded():
    with pytest.raises(platform_events.PlatformEventError, match="digest"):
        platform_events.make_hmac_verifier(SECRET, digest="md5")
    with pytest.raises(platform_events.PlatformEventError, match="encoding"):
        platform_events.make_hmac_verifier(SECRET, encoding="rot13")


def test_the_comparison_is_constant_time():
    """Scoped to lines that actually compare the SIGNATURE.

    A blanket ban on `==` inside the verifier flags `encoding == "hex"`, which is
    a config check and leaks nothing — a guard that fires on the wrong line gets
    silenced, and then it is not a guard.
    """
    import inspect

    source = inspect.getsource(platform_events.make_hmac_verifier)
    assert "compare_digest" in source
    for line in source.splitlines():
        if "==" in line and ("signature" in line or "expected" in line):
            raise AssertionError(f"signature compared with a leaky equality: {line.strip()}")


def test_the_module_contains_no_partner_sdk_and_no_index_call():
    """⚠️ the platform-uninstall work's Square integration stays blocked. This is the generic half, and
    a provider SDK appearing here means the blocked half was quietly started.
    Also the self-registration removal: nothing in this path may write to an index. Asserted against the
    source the way the index-ban assertion asserted the api.nandaindex.org ban."""
    import inspect

    source = inspect.getsource(platform_events)
    for banned in ("nandaindex.org", "/api/v1/orgs", "import squareup", "import shopify", "shopify_api"):
        assert banned not in source, f"{banned!r} must not appear in the generic receiver"


def test_the_receiver_makes_no_outbound_call(home, owner_identity, monkeypatch):
    """Nothing auto-fires beyond the transition: no re-registration, no index
    write, no callback to the platform."""
    import httpx

    def explode(*_a, **_k):
        raise AssertionError("the uninstall receiver made an outbound HTTP call")

    monkeypatch.setattr(httpx, "get", explode)
    monkeypatch.setattr(httpx, "post", explode)
    _establish(home, owner_identity)
    raw = _body()
    assert platform_events.receive_uninstall(home, PLATFORM, raw, _sign(raw), env=_env()).outcome == (
        platform_events.APPLIED
    )
