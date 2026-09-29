"""`venue_book`: booking a table at a venue that can refuse.

⚠️ WHAT THESE PIN, in order of how badly each would fail in silence:

1. **The slot fold matches the venue's, byte for byte.** The design claims a
   confirmed booking carries two independent signatures over the *same* slot, so
   a verifier can pair them without trusting either party. Get the fold wrong and
   both receipts still verify, both still describe the booking, and nothing can
   pair them — which is exactly the failure neither receipt reveals on its own.
   `test_the_slot_fold_is_the_venues_fold` is the load-bearing one, and it caught
   a real bug: the first version copied the local `booking` skill's
   `provider@datetime` fold while the venue hashes with a NUL separator.

2. **One credential per request, and a fall-back that admits itself.** The venue
   takes the signature branch whenever any signature header is present, then
   fails closed if the key does not resolve in an index — so a token sent
   alongside is never read. Falling back to the token is fine; hiding that it
   happened is not, because booking as an anonymous secret-holder is a weaker
   claim than booking as an identified key.

3. **A refusal is a result, not an exception.** The LLM reading a tool result has
   to be able to tell "I need a credential" from "the venue is down".
"""

from __future__ import annotations

import hashlib
import json

import pytest

from community_member.builtin_skills.venue_book import skill as vb


def _real_key() -> tuple[str, str]:
    """A genuine 32-byte Ed25519 seed + public key, base64 — so the signing path
    is exercised rather than stubbed past."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    return (
        base64.b64encode(sk.private_bytes_raw()).decode(),
        base64.b64encode(sk.public_key().public_bytes_raw()).decode(),
    )


# ── the fold ────────────────────────────────────────────────────────────────


def test_the_slot_fold_is_the_venues_fold():
    """Pinned against the venue's own definition, restated here rather than
    imported — the harness must not import a service it tests, and neither
    should a skill's test reach into the venue's source."""
    expected = hashlib.sha256(b"lunch-table-4\x002026-12-20T12:30:00Z").hexdigest()

    assert vb._slot_ref("lunch-table-4", "2026-12-20T12:30:00Z") == expected


def test_control_the_old_fold_would_not_have_matched():
    """The bug this test exists for. Both folds are stable and plausible; only
    one pairs with the venue."""
    old = "lunch-table-4@2026-12-20T12:30:00Z"

    assert vb._slot_ref("lunch-table-4", "2026-12-20T12:30:00Z") != old


def test_the_separator_is_load_bearing():
    """Without the NUL, ('ab','c') and ('a','bc') fold to one slot — two
    different bookings sharing an idempotency key."""
    assert vb._slot_ref("ab", "c") != vb._slot_ref("a", "bc")


def test_the_fold_is_case_and_space_sensitive():
    """The venue does not normalise, so neither may we. Folding differently
    would pair a receipt with a booking the venue thinks is another slot."""
    assert vb._slot_ref("Table-7", "t") != vb._slot_ref("table-7", "t")
    assert vb._slot_ref("table-7 ", "t") != vb._slot_ref("table-7", "t")


# ── where the venue is ──────────────────────────────────────────────────────


def test_no_venue_configured_is_refused_not_guessed(monkeypatch):
    """An agent that silently books against a venue nobody chose is worse than
    one that says it does not know where to book."""
    monkeypatch.delenv("VENUE_URL", raising=False)

    with pytest.raises(ValueError, match="no venue"):
        vb._venue_url(None)


def test_an_explicit_url_beats_the_environment(monkeypatch):
    monkeypatch.setenv("VENUE_URL", "https://from-env.example")

    assert vb._venue_url("https://explicit.example/") == "https://explicit.example"


# ── credentials ─────────────────────────────────────────────────────────────


def _venue(monkeypatch, answers):
    """Stand in for the venue, recording the credential each request carried."""
    seen: list[dict] = []
    replies = list(answers)

    class _Resp:
        def __init__(self, payload):
            self._p = json.dumps(payload).encode()

        def read(self, _n=None):
            return self._p

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    def fake_urlopen(request, timeout=None):
        seen.append(dict(getattr(request, "headers", {})))
        return _Resp(replies.pop(0))

    monkeypatch.setattr(vb.urllib.request, "urlopen", fake_urlopen)
    return seen


def _task(payload):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"artifacts": [{"parts": [{"kind": "text", "text": json.dumps(payload)}]}]},
    }


def _unregistered():
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": vb.UNAUTHORISED,
            "message": "signature verifies, but no index record resolves for this key — "
            "possession of a key is not authorisation",
        },
    }


def test_a_signed_attempt_refused_for_no_index_record_falls_back_and_says_so(monkeypatch):
    monkeypatch.setattr(vb, "_credentials", lambda: ("me", *_real_key(), "tok"))
    seen = _venue(monkeypatch, [_unregistered(), _task({"state": "held", "hold_id": "h1"})])

    answer = vb._rpc("https://venue.example", {"skill": "venue.hold"})

    assert answer["state"] == "held"
    assert answer["fell_back_to_token"] is True
    assert "does not resolve" in answer["identity_not_used"]
    assert len(seen) == 2, "expected a signed attempt then a token attempt"


def test_control_a_successful_signed_booking_is_not_marked_as_a_fallback(monkeypatch):
    """Without this, every booking would claim to be anonymous."""
    monkeypatch.setattr(vb, "_credentials", lambda: ("me", *_real_key(), "tok"))
    _venue(monkeypatch, [_task({"state": "held", "hold_id": "h1"})])

    answer = vb._rpc("https://venue.example", {"skill": "venue.hold"})

    assert "fell_back_to_token" not in answer


def test_a_refusal_for_another_reason_does_not_retry(monkeypatch):
    """Only the unregistered-key case is worth a second request. Retrying a
    slot conflict with a weaker credential just books nothing, twice."""
    monkeypatch.setattr(vb, "_credentials", lambda: ("me", *_real_key(), "tok"))
    conflict = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "already taken"}}
    seen = _venue(monkeypatch, [conflict])

    answer = vb._rpc("https://venue.example", {"skill": "venue.hold"})

    assert answer["refused"] is True
    assert len(seen) == 1, "a non-credential refusal was retried"


def test_with_no_key_the_token_is_used_directly(monkeypatch):
    monkeypatch.setattr(vb, "_credentials", lambda: (None, None, None, "tok"))
    seen = _venue(monkeypatch, [_task({"state": "held"})])

    vb._rpc("https://venue.example", {"skill": "venue.hold"})

    assert any("Bearer tok" in str(v) for v in seen[0].values())


def test_with_nothing_at_all_the_call_is_still_made(monkeypatch):
    """A keyless, tokenless agent can still read availability — the venue
    leaves reads open and refuses the writes itself."""
    monkeypatch.setattr(vb, "_credentials", lambda: (None, None, None, None))
    seen = _venue(monkeypatch, [_task({"open": []})])

    assert "open" in vb._rpc("https://venue.example", {"skill": "venue.availability"})
    assert not any("Authorization" in k for k in seen[0])


# ── a refusal is a result ───────────────────────────────────────────────────


def test_a_credential_refusal_is_named_as_one(monkeypatch):
    monkeypatch.setattr(vb, "_credentials", lambda: (None, None, None, None))
    _venue(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "error": {"code": vb.UNAUTHORISED, "message": "a write credential is required"}}],
    )

    answer = vb._rpc("https://venue.example", {"skill": "venue.hold"})

    assert answer["reason"] == "needs a credential"
    assert answer["code"] == vb.UNAUTHORISED


def test_a_venue_that_is_down_is_distinguishable_from_one_that_refused(monkeypatch):
    """A caller that cannot tell these apart retries the one that can never
    succeed."""
    monkeypatch.setattr(vb, "_credentials", lambda: (None, None, None, None))

    def boom(request, timeout=None):
        raise vb.urllib.error.URLError("connection refused")

    monkeypatch.setattr(vb.urllib.request, "urlopen", boom)

    answer = vb._rpc("https://venue.example", {"skill": "venue.availability"})

    assert answer["refused"] is True
    assert answer["reason"] == "URLError"
    assert answer["reason"] != "needs a credential"


def test_an_unreadable_answer_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(vb, "_credentials", lambda: (None, None, None, None))
    _venue(monkeypatch, [{"jsonrpc": "2.0", "id": 1, "result": {"artifacts": []}}])

    assert vb._rpc("https://venue.example", {"skill": "x"})["reason"] == "unreadable answer"


# ── the tool surface ────────────────────────────────────────────────────────


def test_every_tool_the_skill_declares_is_callable():
    for tool in vb.TOOLS:
        assert callable(tool["fn"]), tool["name"]
        assert tool["description"].strip()
        assert tool["parameters"]["type"] == "object"


def test_a_booking_must_name_at_least_one_principal(monkeypatch):
    monkeypatch.setenv("VENUE_URL", "https://venue.example")

    assert "at least one principal" in vb.hold_table("t", "s", [])


def test_availability_needs_at_least_one_time(monkeypatch):
    monkeypatch.setenv("VENUE_URL", "https://venue.example")

    assert "one or more times" in vb.check_availability("t", [])


def test_a_key_the_agent_cannot_sign_with_degrades_and_reports_it(monkeypatch):
    """A misconfigured key must not take the call down, and must not look like
    the venue's fault either."""
    monkeypatch.setattr(vb, "_credentials", lambda: ("me", "not-a-valid-seed", "cHVi", "tok"))
    _venue(monkeypatch, [_task({"state": "held", "hold_id": "h1"})])

    answer = vb._rpc("https://venue.example", {"skill": "venue.hold"})

    assert answer["state"] == "held", "a bad key stopped a booking a token could have made"
    assert answer["signing_failed"]
    assert "could not sign" in answer["identity_not_used"]


# ── the receipt path ────────────────────────────────────────────────────────
#
# ⚠️ This is the part where an untested branch means a booking that LOOKS signed
# and is not. `_emit_receipt` has four ways to decline and one way to succeed,
# and a caller reading `our_receipt` has to be able to tell which happened.


def _agent_home(tmp_path, *, with_key=True, key=None):
    """A real agent home: config.json plus a keystore entry."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from community_member import keystore
    from community_member.config import Config

    home = tmp_path / "agent"
    home.mkdir(parents=True, exist_ok=True)
    cfg = Config(home=home)
    cfg.agent_id = "booker"
    cfg.chapter_url = ""
    if with_key:
        seed = key if key is not None else base64.b64encode(Ed25519PrivateKey.generate().private_bytes_raw()).decode()
        cfg.public_key = "x"
        keystore.store_private_key("booker", seed, dir=home)
    cfg.save()
    return home


def test_a_confirmed_booking_is_signed_over_the_venues_slot(tmp_path, monkeypatch):
    """The happy path, and the assertion that makes the pairing real: the receipt
    carries the venue's fold, not the agent's idea of one."""
    home = _agent_home(tmp_path)
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))

    out = vb._emit_receipt("lunch-table-4", "2026-12-20T12:30:00Z", ["did:key:zA", "did:key:zB"], "did:key:zVenue")

    assert out.get("receipt_id"), out
    from community_member import arp
    from community_member.config import Config

    log = arp.AgencyLog(Config.load(home=home).home)
    receipt = next(r for r in log.list_recent(limit=5) if r["receipt_id"] == out["receipt_id"])
    payload = receipt["action"]["machine_payload"]
    assert receipt["action"]["category"] == "appointment_booked"
    assert payload["slot_ref"] == vb._slot_ref("lunch-table-4", "2026-12-20T12:30:00Z")
    assert payload["counterparty_did"] == "did:key:zVenue"
    assert payload["principals"] == ["did:key:zA", "did:key:zB"]


def test_no_identity_declines_to_sign_and_says_why(tmp_path, monkeypatch):
    home = tmp_path / "empty"
    home.mkdir()
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))

    assert vb._emit_receipt("t", "s", [], None)["unsigned"] == "no agent identity"


def test_an_identity_with_no_key_declines_to_sign(tmp_path, monkeypatch):
    home = _agent_home(tmp_path, with_key=False)
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))

    assert "no signing key" in vb._emit_receipt("t", "s", [], None)["unsigned"]


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("!!!not base64!!!", "not valid base64"),
        ("c2hvcnQ=", "32-byte Ed25519 seed"),
    ],
)
def test_an_unusable_key_declines_to_sign_by_name(tmp_path, monkeypatch, key, expected):
    """Four distinct reasons, because "unsigned" alone sends an operator looking
    in the wrong place."""
    home = _agent_home(tmp_path, key=key)
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))

    assert expected in vb._emit_receipt("t", "s", [], None)["unsigned"]


def test_a_keyless_agent_still_completes_the_booking(tmp_path, monkeypatch):
    """A keyless agent is a valid agent. It books, and it says plainly that it
    could not countersign — rather than failing, or pretending it did."""
    home = _agent_home(tmp_path, with_key=False)
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))
    monkeypatch.setenv("VENUE_URL", "https://venue.example")
    monkeypatch.setattr(vb, "_credentials", lambda: (None, None, None, "tok"))
    _venue(
        monkeypatch,
        [
            _task(
                {
                    "state": "confirmed",
                    "resource": "t",
                    "start": "s",
                    "principals": ["did:key:zA"],
                    "receipt_id": "venue-1",
                }
            )
        ],
    )
    monkeypatch.setattr(
        vb.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(vb.urllib.error.URLError("no card")),
        raising=False,
    )

    # urlopen is now raising, so re-stub the RPC leg only.
    monkeypatch.setattr(
        vb,
        "_rpc",
        lambda *a, **k: {
            "state": "confirmed",
            "resource": "t",
            "start": "s",
            "principals": ["did:key:zA"],
            "receipt_id": "venue-1",
        },
    )
    result = json.loads(vb.agree("h1", "did:key:zA"))

    assert result["state"] == "confirmed"
    assert "no signing key" in result["our_receipt"]["unsigned"]


def test_a_card_that_cannot_be_reread_does_not_undo_a_confirmed_booking(tmp_path, monkeypatch):
    """The counterparty's did is evidence, not a precondition."""
    home = _agent_home(tmp_path)
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))
    monkeypatch.setenv("VENUE_URL", "https://venue.example")
    monkeypatch.setattr(
        vb, "_rpc", lambda *a, **k: {"state": "confirmed", "resource": "t", "start": "s", "principals": ["did:key:zA"]}
    )
    monkeypatch.setattr(
        vb.urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(vb.urllib.error.URLError("no card"))
    )

    result = json.loads(vb.agree("h1", "did:key:zA"))

    assert result["state"] == "confirmed"
    assert result["our_receipt"].get("receipt_id"), "a missing card blocked the countersignature"


def test_a_hold_that_did_not_confirm_is_not_signed(monkeypatch):
    """Signing a held-but-unconfirmed booking would attest to an agreement
    nobody reached."""
    monkeypatch.setenv("VENUE_URL", "https://venue.example")
    monkeypatch.setattr(vb, "_rpc", lambda *a, **k: {"state": "held", "pending": ["did:key:zB"]})
    called = []
    monkeypatch.setattr(vb, "_emit_receipt", lambda *a, **k: called.append(1) or {})

    result = json.loads(vb.agree("h1", "did:key:zA"))

    assert result["state"] == "held"
    assert "our_receipt" not in result
    assert called == [], "the agent signed a booking that had not confirmed"


# ── credential discovery ────────────────────────────────────────────────────


def test_credentials_are_read_from_the_agent_home(tmp_path, monkeypatch):
    home = _agent_home(tmp_path)
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))
    monkeypatch.setenv("VENUE_TOKEN", "tok")

    agent_id, private, _public, token = vb._credentials()

    assert agent_id == "booker" and private and token == "tok"


def test_a_broken_config_still_yields_the_token(tmp_path, monkeypatch):
    """A credential the skill cannot assemble is one it does not send — never a
    reason to fail the call."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "nope"))
    monkeypatch.setenv("VENUE_TOKEN", "tok")
    monkeypatch.setattr(vb, "_home", lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    assert vb._credentials() == (None, None, None, "tok")


# ── the tools end to end ────────────────────────────────────────────────────


def test_the_three_tools_reach_the_venue(monkeypatch):
    monkeypatch.setenv("VENUE_URL", "https://venue.example")
    sent: list[dict] = []
    monkeypatch.setattr(vb, "_rpc", lambda url, intent, **k: sent.append(intent) or {"ok": True})

    vb.check_availability("t", ["s"])
    vb.hold_table("t", "s", ["did:key:zA"])
    monkeypatch.setattr(vb, "_rpc", lambda url, intent, **k: sent.append(intent) or {"state": "held"})
    vb.agree("h1", "did:key:zA")

    assert [i["skill"] for i in sent] == ["venue.availability", "venue.hold", "venue.consent"]


def test_a_single_time_is_accepted_as_well_as_a_list(monkeypatch):
    monkeypatch.setenv("VENUE_URL", "https://venue.example")
    sent = []
    monkeypatch.setattr(vb, "_rpc", lambda url, intent, **k: sent.append(intent) or {})

    vb.check_availability("t", "2026-12-20T12:30:00Z")

    assert sent[0]["start"] == ["2026-12-20T12:30:00Z"]


def test_the_party_defaults_to_the_first_principal(monkeypatch):
    monkeypatch.setenv("VENUE_URL", "https://venue.example")
    sent = []
    monkeypatch.setattr(vb, "_rpc", lambda url, intent, **k: sent.append(intent) or {})

    vb.hold_table("t", "s", ["did:key:zA", "did:key:zB"])

    assert sent[0]["party"] == "did:key:zA"


def test_a_home_with_no_identity_yields_only_the_token(tmp_path, monkeypatch):
    """A configured home that has not been set up yet is not an error."""
    from community_member.config import Config

    home = tmp_path / "bare"
    home.mkdir()
    Config(home=home).save()
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))
    monkeypatch.setenv("VENUE_TOKEN", "tok")

    assert vb._credentials() == (None, None, None, "tok")


def test_an_http_error_from_the_venue_carries_its_status(monkeypatch):
    """A 500 and a refusal are different facts; the status is what separates them."""
    import io

    monkeypatch.setattr(vb, "_credentials", lambda: (None, None, None, None))

    def boom(request, timeout=None):
        raise vb.urllib.error.HTTPError(
            "https://venue.example/", 503, "Service Unavailable", {}, io.BytesIO(b"down for maintenance")
        )

    monkeypatch.setattr(vb.urllib.request, "urlopen", boom)

    answer = vb._rpc("https://venue.example", {"skill": "venue.availability"})

    assert answer["refused"] is True
    assert answer["reason"] == "HTTP 503"
    assert "maintenance" in answer["detail"]


def test_the_counterparty_did_is_read_from_the_card_when_it_can_be(tmp_path, monkeypatch):
    """The other half of the pairing: the receipt names who the agent booked with."""
    home = _agent_home(tmp_path)
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))
    monkeypatch.setenv("VENUE_URL", "https://venue.example")
    monkeypatch.setattr(
        vb, "_rpc", lambda *a, **k: {"state": "confirmed", "resource": "t", "start": "s", "principals": ["did:key:zA"]}
    )

    class _Card:
        def read(self, _n=None):
            return json.dumps({"x-nanda": {"did": "did:key:zTheVenue"}}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    monkeypatch.setattr(vb.urllib.request, "urlopen", lambda *a, **k: _Card())

    result = json.loads(vb.agree("h1", "did:key:zA"))
    receipt_id = result["our_receipt"]["receipt_id"]

    from community_member import arp
    from community_member.config import Config

    log = arp.AgencyLog(Config.load(home=home).home)
    receipt = next(r for r in log.list_recent(limit=5) if r["receipt_id"] == receipt_id)

    assert receipt["action"]["machine_payload"]["counterparty_did"] == "did:key:zTheVenue"
