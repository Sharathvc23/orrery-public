"""The front door is bounded, and the bound is proven by reaching it.

⚠️ WHAT WOULD MAKE THIS SUITE WORTHLESS. Asserting that ``SMB_SIGNUP_TENANT_CAP``
is read, or that a constant has the value it was given. A cap is a claim about
what happens at the boundary, so every test here DRIVES to the boundary and reads
the refusal. Reading the constant tests the environment, not the door.

The service under test talks to a real ``smb_host`` in-process, so "the cap is
counted from the host's authoritative tenant count" is exercised rather than
described.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "smb_host"))

HOST_TOKEN = "test-provisioning-secret"
# Reserved-for-documentation host: nothing in this suite delivers to anyone.
CONTACT = "https://bookings.invalid/hook"


def _host_data_dir(tmp_path: Path) -> Path:
    return tmp_path / "host"


def _stored_meta(tmp_path: Path, tenant_id: str) -> dict[str, object]:
    """What the HOST wrote to disk for this tenant.

    ⚠️ THE RECORD, NOT THE REQUEST. Attribution is only fixed if the value the
    host PERSISTED is right; asserting on what the façade sent would pass with
    the host ignoring every byte of it, which is the exact configuration this
    work has to be able to tell apart.
    """
    return json.loads((_host_data_dir(tmp_path) / tenant_id / "smb_tenant.json").read_text())


def _make_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, trusted_proxies: str | None = None
) -> TestClient:
    """A real smb_host, gated, with the pool off so counting is deterministic."""
    monkeypatch.setenv("HOST_PUBLIC_URL", "http://smb-host.example")
    monkeypatch.setenv("SMB_HOST_DATA_DIR", str(_host_data_dir(tmp_path)))
    if trusted_proxies is None:
        monkeypatch.delenv("SMB_HOST_TRUSTED_PROXIES", raising=False)
    else:
        monkeypatch.setenv("SMB_HOST_TRUSTED_PROXIES", trusted_proxies)
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    monkeypatch.setenv("SMB_HOST_POOL_SIZE", "0")
    monkeypatch.setenv("SMB_HOST_PROVISION_TOKEN", HOST_TOKEN)
    # Generously large: this suite's own cap is SMB_SIGNUP_TENANT_CAP, exercised
    # against small values by _make_signup. The host also enforces its own,
    # deeper total-tenant cap, and it must not trip first and mask what this
    # suite tests.
    monkeypatch.setenv("SMB_HOST_TENANT_CAP", "1000")
    import main as host_main

    importlib.reload(host_main)
    return TestClient(host_main.app)


def _make_signup(
    host: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    *,
    cap: str = "5",
    rate: str = "100",
    token: str = HOST_TOKEN,
    host_url: str = "http://smb-host.internal",
    sent: list[dict[str, str]] | None = None,
) -> TestClient:
    """The signup façade, with its outbound httpx wired to the in-process host.

    The host is reached through httpx's ASGI transport rather than a socket, so
    the façade's real relay code runs — the same call path, the same headers, and
    the same failure modes as a deployment.
    """
    monkeypatch.setenv("SMB_SIGNUP_HOST_URL", host_url)
    monkeypatch.setenv("SMB_HOST_PROVISION_TOKEN", token)
    monkeypatch.setenv("SMB_SIGNUP_TENANT_CAP", cap)
    monkeypatch.setenv("SMB_SIGNUP_RATE_PER_HOUR", rate)
    monkeypatch.delenv("SMB_SIGNUP_TRUSTED_PROXIES", raising=False)

    import smb_signup.main as signup_main  # noqa: PLC0415

    importlib.reload(signup_main)

    real_client = httpx.AsyncClient

    class _Recording(httpx.ASGITransport):
        """The transport, plus a copy of every header that left this service.

        Only used by the guard that has to look at the WIRE — see
        ``test_the_forwarded_chain_is_one_entry_whatever_the_caller_sends``. The
        record on disk is what the other guards assert against.
        """

        async def handle_async_request(self, request):  # type: ignore[override]
            if sent is not None:
                sent.append({k.lower(): v for k, v in request.headers.items()})
            return await super().handle_async_request(request)

    def wired(*args, **kwargs):
        transport = _Recording if sent is not None else httpx.ASGITransport
        kwargs["transport"] = transport(app=host.app)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(signup_main.httpx, "AsyncClient", wired)
    return TestClient(signup_main.create_app())


# ── the bound, reached rather than read ──────────────────────────────────────


def test_the_tenant_cap_is_reached_and_refuses_with_its_own_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE UNIT. Provision until the door shuts, and read what it says.

    The cap is 3 here and the test does not stop at 3 because it was told to —
    it keeps going and requires the refusal to arrive on its own.
    """
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch, cap="3")

    accepted, refusal = 0, None
    for i in range(8):
        resp = signup.post("/provision", json={"business_name": f"Bounded Barbers {i}", "contact": CONTACT})
        if resp.status_code == 201:
            accepted += 1
            continue
        refusal = resp
        break

    assert refusal is not None, "the cap was never reached — the front door is unbounded"
    assert accepted == 3, f"the cap admitted {accepted}, not 3"
    assert refusal.status_code == 507, f"at-capacity must have its own status, got {refusal.status_code}"
    detail = refusal.json()["detail"]
    assert "full allocation" in detail
    assert "3 of 3" in detail, detail

    # And it stays shut rather than admitting one more on the next attempt.
    again = signup.post("/provision", json={"business_name": "One More Please", "contact": CONTACT})
    assert again.status_code == 507


def test_the_cap_counts_tenants_the_operator_made_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The disk is shared, so the count has to be. A cap that only sees its own
    signups is not counting the thing it is protecting."""
    host = _make_host(tmp_path, monkeypatch)
    for i in range(3):
        direct = host.post(
            "/provision",
            json={"business_name": f"Operator Made {i}", "contact": CONTACT},
            headers={"Authorization": f"Bearer {HOST_TOKEN}"},
        )
        assert direct.status_code == 201

    signup = _make_signup(host, monkeypatch, cap="3")
    resp = signup.post("/provision", json={"business_name": "Public Signup", "contact": CONTACT})
    assert resp.status_code == 507, "tenants made through the operator path did not count against the cap"


def test_the_per_source_rate_limit_is_reached_and_says_when_to_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch, cap="50", rate="2")

    assert signup.post("/provision", json={"business_name": "Fast One", "contact": CONTACT}).status_code == 201
    assert signup.post("/provision", json={"business_name": "Fast Two", "contact": CONTACT}).status_code == 201
    third = signup.post("/provision", json={"business_name": "Fast Three", "contact": CONTACT})

    assert third.status_code == 429, "a third signup inside the window was not refused"
    assert "Retry-After" in third.headers
    assert int(third.headers["Retry-After"]) > 0
    assert "minute" in third.json()["detail"]


def test_rate_limit_and_capacity_are_different_refusals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """⚠️ THEY NEED DIFFERENT ADVICE, SO THEY NEED DIFFERENT STATES. Waiting fixes
    one and never fixes the other; collapsing them would tell a business to come
    back in an hour to a door that will still be shut."""
    host = _make_host(tmp_path, monkeypatch)

    rate_limited = _make_signup(host, monkeypatch, cap="50", rate="1")
    rate_limited.post("/provision", json={"business_name": "First", "contact": CONTACT})
    a = rate_limited.post("/provision", json={"business_name": "Second", "contact": CONTACT})

    full = _make_signup(host, monkeypatch, cap="1", rate="100")
    b = full.post("/provision", json={"business_name": "Third", "contact": CONTACT})

    assert a.status_code == 429
    assert b.status_code == 507
    assert a.status_code != b.status_code
    assert a.json()["detail"] != b.json()["detail"]


# ── the façade refuses to be an unbounded proxy ──────────────────────────────


@pytest.mark.parametrize("missing", ["SMB_SIGNUP_TENANT_CAP", "SMB_SIGNUP_RATE_PER_HOUR"])
def test_an_unconfigured_bound_refuses_rather_than_serving_openly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    """⚠️ THE FAILURE THIS SERVICE EXISTS TO PREVENT, ASSERTED DIRECTLY. A façade
    holding the token with no bound is exactly as open as publishing the token.
    So an unset bound is not a permissive default; it stops provisioning."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)
    monkeypatch.delenv(missing, raising=False)

    resp = signup.post("/provision", json={"business_name": "Unbounded Co", "contact": CONTACT})
    assert resp.status_code == 503
    assert missing in resp.json()["detail"]


@pytest.mark.parametrize("bad", ["", "   ", "0", "-4", "many"])
def test_unset_empty_and_unusable_bounds_are_all_the_same_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """A typo in a bound must not disable it. Tested by name, including the
    empty string, because that is the shape this tree has been bitten by."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)
    monkeypatch.setenv("SMB_SIGNUP_TENANT_CAP", bad)

    resp = signup.post("/provision", json={"business_name": "Typo Co", "contact": CONTACT})
    assert resp.status_code == 503
    assert "SMB_SIGNUP_TENANT_CAP" in resp.json()["detail"]


def test_a_missing_token_refuses_rather_than_provisioning_unauthenticated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)
    monkeypatch.delenv("SMB_HOST_PROVISION_TOKEN", raising=False)

    resp = signup.post("/provision", json={"business_name": "No Token Co", "contact": CONTACT})
    assert resp.status_code == 503
    assert "SMB_HOST_PROVISION_TOKEN" in resp.json()["detail"]


def test_an_unreachable_host_fails_closed_rather_than_ignoring_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ NOT KNOWING THE HEADROOM IS NOT PERMISSION TO IGNORE THE CAP."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    import smb_signup.main as signup_main

    def exploding(*args, **kwargs):
        raise httpx.ConnectError("host is down")

    monkeypatch.setattr(signup_main.httpx, "AsyncClient", exploding)
    resp = signup.post("/provision", json={"business_name": "Host Down Co", "contact": CONTACT})

    assert resp.status_code == 503
    assert "cap cannot be honoured" in resp.json()["detail"]


# ── the credential ───────────────────────────────────────────────────────────


def test_a_browser_supplied_authorization_header_is_discarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The credential on the wire to the host is this service's or there is none.

    Proven by sending a WRONG one and requiring success: if the header were
    relayed the host would answer 401, so a 201 is only reachable if this service
    substituted its own.
    """
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    resp = signup.post(
        "/provision",
        json={"business_name": "Header Spoof Co", "contact": CONTACT},
        headers={"Authorization": "Bearer not-the-real-secret"},
    )
    assert resp.status_code == 201, "a client-supplied Authorization header reached the host"
    assert resp.json()["did"].startswith("did:key:z6Mk")


def test_the_token_is_not_in_any_response_this_service_produces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    bodies = [
        signup.post("/provision", json={"business_name": "Leak Check Co", "contact": CONTACT}).text,
        signup.get("/health").text,
        signup.post("/provision", json={"business_name": "", "contact": CONTACT}).text,
    ]
    for body in bodies:
        assert HOST_TOKEN not in body, "the provisioning secret appeared in a response body"


# ── observability ────────────────────────────────────────────────────────────


def test_headroom_is_readable_before_anyone_is_turned_away(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ A CAP NOBODY CAN SEE COMING IS LEARNED FROM THE FIRST BUSINESS TURNED
    AWAY. Health reports the cap, the count and the headroom, and the headroom
    moves as tenants are issued."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch, cap="3")

    before = signup.get("/health").json()
    assert before["tenant_cap"] == 3
    assert before["headroom"] == 3
    assert before["at_capacity"] is False

    signup.post("/provision", json={"business_name": "Headroom One", "contact": CONTACT})
    mid = signup.get("/health").json()
    assert mid["tenants"] == 1
    assert mid["headroom"] == 2

    for i in range(2):
        signup.post("/provision", json={"business_name": f"Headroom Fill {i}", "contact": CONTACT})
    full = signup.get("/health").json()
    assert full["headroom"] == 0
    assert full["at_capacity"] is True


def test_health_admits_it_cannot_see_the_host_rather_than_inventing_headroom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    import smb_signup.main as signup_main

    def exploding(*args, **kwargs):
        raise httpx.ConnectError("host is down")

    monkeypatch.setattr(signup_main.httpx, "AsyncClient", exploding)
    body = signup.get("/health").json()

    assert body["headroom"] is None
    assert "host_unreachable" in body
    # Same rule for the other thing this surface reports about the host: a
    # control cannot be certified as working by a check that could not look.
    assert body["caller_attribution"] == "unknown", body


# ── the relayed contract ─────────────────────────────────────────────────────


def test_reading_a_card_and_booking_are_relayed_and_carry_no_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """These mint nothing and write no key material, so they are neither bounded
    nor credentialed — and the funnel needs the whole contract from one origin."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    made = signup.post("/provision", json={"business_name": "Relay Test Co", "contact": CONTACT})
    tenant = made.json()["tenant_id"]

    card = signup.get(f"/t/{tenant}/.well-known/agent.json")
    assert card.status_code == 200
    assert card.json()["x-nanda"]["did"] == made.json()["did"]

    booked = signup.post(
        f"/t/{tenant}/book",
        json={"service": "Haircut", "provider": "Relay Test Co", "datetime": "2026-08-25T10:00:00Z"},
    )
    assert booked.status_code == 200
    assert booked.json()["receipt"]["issuer_did"] == made.json()["did"]


def test_a_missing_contact_is_refused_and_no_tenant_is_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provisioning requires somewhere a booking can be delivered, so the front
    door cannot quietly drop the field on its way through."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    before = host.get("/health").json()["tenants"]
    resp = signup.post("/provision", json={"business_name": "No Contact Co"})

    assert resp.status_code == 422, resp.text
    assert host.get("/health").json()["tenants"] == before, "a refused signup still made a tenant"


@pytest.mark.parametrize(
    ("contact", "fragment"),
    [
        ("call me maybe", "neither an https webhook URL nor an email"),
        ("http://bookings.example/hook", "plain http webhook is refused"),
    ],
)
def test_the_hosts_contact_rules_are_the_hosts_and_reach_the_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contact: str, fragment: str
) -> None:
    """⚠️ THE FAÇADE DOES NOT RE-JUDGE WHAT A USABLE CONTACT IS. What counts is
    derived from what the host's delivery path can actually deliver on; a second
    opinion here could accept something the host would refuse. So the shape is
    checked at the door and the MEANING is the host's, passed through verbatim —
    which is also what lets the funnel render the host's own words."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    resp = signup.post("/provision", json={"business_name": "Bad Contact Co", "contact": contact})

    assert resp.status_code == 400, resp.text
    assert fragment in resp.json()["detail"]


def test_a_refused_contact_does_not_spend_the_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A refusal that consumed headroom would let anyone exhaust the front door
    with requests the host was never going to accept."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch, cap="2")

    for _ in range(5):
        signup.post("/provision", json={"business_name": "Rejected Co", "contact": "not a contact"})

    ok = signup.post("/provision", json={"business_name": "Good Co", "contact": CONTACT})
    assert ok.status_code == 201, "refused signups ate the headroom"
    assert signup.get("/health").json()["headroom"] == 1


def test_the_hosts_own_refusals_are_passed_through_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bounded façade must not flatten what the host said, or the funnel's
    refusal states stop matching the contract they were built against."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    punctuation = signup.post("/provision", json={"business_name": "!!!", "contact": CONTACT})
    assert punctuation.status_code == 400
    assert "alphanumeric" in punctuation.json()["detail"]

    signup.post("/provision", json={"business_name": "Duplicate Co", "contact": CONTACT})
    dup = signup.post("/provision", json={"business_name": "Duplicate Co", "contact": CONTACT})
    assert dup.status_code == 409
    assert "already provisioned" in dup.json()["detail"]


# ── source attribution ───────────────────────────────────────────────────────


def test_a_forwarded_for_header_cannot_buy_a_fresh_rate_limit_bucket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ X-Forwarded-For IS CLIENT-SUPPLIED. Trusting it by default would let one
    caller mint a new identity per request and defeat the per-source limit
    entirely, so it is ignored unless the hop count is configured."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch, cap="50", rate="1")

    assert signup.post("/provision", json={"business_name": "Spoof One", "contact": CONTACT}).status_code == 201
    spoofed = signup.post(
        "/provision",
        json={"business_name": "Spoof Two", "contact": CONTACT},
        headers={"X-Forwarded-For": "203.0.113.9"},
    )
    assert spoofed.status_code == 429, "a client-supplied X-Forwarded-For bought a fresh bucket"


def test_a_configured_hop_count_does_attribute_to_the_forwarded_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half: an operator who states how many proxies they run gets
    per-client limiting rather than one global bucket. A guard that only ever
    refuses would pass the test above and be useless in a deployment."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch, cap="50", rate="1")
    monkeypatch.setenv("SMB_SIGNUP_TRUSTED_PROXIES", "1")

    first = signup.post(
        "/provision", json={"business_name": "Client A", "contact": CONTACT}, headers={"X-Forwarded-For": "198.51.100.1"}
    )
    second = signup.post(
        "/provision", json={"business_name": "Client B", "contact": CONTACT}, headers={"X-Forwarded-For": "198.51.100.2"}
    )
    third = signup.post(
        "/provision", json={"business_name": "Client A Again", "contact": CONTACT}, headers={"X-Forwarded-For": "198.51.100.1"}
    )

    assert first.status_code == 201
    assert second.status_code == 201, "a different client shared the first one's bucket"
    assert third.status_code == 429, "the same client got a second signup inside the window"


# ── the caller reaches the host's record, and cannot choose it ───────────────


def test_two_callers_through_the_facade_are_recorded_as_two_callers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ G1. THE RELAY MUST NOT FLATTEN THE THING THE HOST RECORDS.

    Before this service forwarded anything, every provision reached the host on
    THIS service's socket, so `provisioned_by` was the façade's own address for
    every caller — measured on the deployed pair as three distinct public
    visitors and one direct operator call, all four recorded `127.0.0.1`. The cap
    still said how many had been issued; nothing said by whom.

    ⚠️ ASSERTED AGAINST WHAT THE HOST STORED. Reading the header the façade sent
    would pass with the host discarding it, which is a real and reachable
    configuration (`SMB_HOST_TRUSTED_PROXIES` unset) and the one in which this
    whole change does nothing.
    """
    host = _make_host(tmp_path, monkeypatch, trusted_proxies="1")
    signup = _make_signup(host, monkeypatch, cap="50", rate="100")
    monkeypatch.setenv("SMB_SIGNUP_TRUSTED_PROXIES", "1")

    recorded = {}
    for name, address in (("Caller One Co", "198.51.100.7"), ("Caller Two Co", "198.51.100.8")):
        resp = signup.post(
            "/provision",
            json={"business_name": name, "contact": CONTACT},
            headers={"X-Forwarded-For": address},
        )
        assert resp.status_code == 201, resp.text
        recorded[address] = _stored_meta(tmp_path, resp.json()["tenant_id"])["provisioned_by"]

    assert recorded["198.51.100.7"] == "198.51.100.7", (
        f"the host recorded {recorded['198.51.100.7']!r} for a caller at 198.51.100.7 — "
        "the façade's own address, not the caller's"
    )
    assert recorded["198.51.100.8"] == "198.51.100.8", recorded
    assert len(set(recorded.values())) == 2, (
        f"two distinct callers were recorded as one attribution: {recorded}"
    )


def test_a_caller_cannot_choose_the_attribution_the_host_writes_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ G2. FORWARDING MUST NOT BECOME A SPOOFING SURFACE.

    A façade that appends whatever `X-Forwarded-For` arrived lets any caller
    write its own attribution, and that is WORSE than the `127.0.0.1` it
    replaces: one obviously wrong value is visibly wrong, and a plausible forged
    address is not. So with no trusted hop configured — the default, and the
    shape of a service reachable directly from the internet — the inbound header
    is discarded unread and the socket peer is what reaches the record.

    The host is configured to TRUST one hop here on purpose: this test must fail
    because the façade refused to relay the forgery, never because the host
    happened to be ignoring the header anyway.
    """
    host = _make_host(tmp_path, monkeypatch, trusted_proxies="1")
    signup = _make_signup(host, monkeypatch, cap="50", rate="100")
    monkeypatch.delenv("SMB_SIGNUP_TRUSTED_PROXIES", raising=False)

    resp = signup.post(
        "/provision",
        json={"business_name": "Forged Attribution Co", "contact": CONTACT},
        headers={"X-Forwarded-For": "203.0.113.9"},
    )
    assert resp.status_code == 201, resp.text

    stored = _stored_meta(tmp_path, resp.json()["tenant_id"])["provisioned_by"]
    assert stored != "203.0.113.9", (
        "a caller wrote its own attribution: the façade relayed a client-supplied "
        "X-Forwarded-For from an untrusted peer"
    )
    # And it is the connection the façade actually saw — TestClient's own peer —
    # rather than a sentinel or a blank, so the record still distinguishes
    # callers instead of merely refusing to be forged.
    assert stored, "the record is empty: refusing the forgery also lost the real caller"


def test_the_forwarded_chain_is_one_entry_whatever_the_caller_sends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ G2, SECOND HALF: REPLACING, NOT APPENDING — and the difference is only
    visible in a hop count above one.

    A façade that APPENDS its resolved address to the caller's header is not
    forgeable at `SMB_HOST_TRUSTED_PROXIES=1`, because the rightmost entry is
    still the façade's own. It fails one step further out: the chain's LENGTH
    becomes caller-controlled, so the position an operator's declared hop count
    selects is chosen by the request rather than by the deployment. Two entries
    arrive where the operator configured for two hops of their own, and the entry
    that lands on the record is the caller's.

    Emitting exactly one entry is what makes `SMB_HOST_TRUSTED_PROXIES` mean a
    fixed thing. Asserted on the wire, and then on the record at the hop count
    where appending would actually pay.
    """
    sent: list[dict[str, str]] = []
    host = _make_host(tmp_path, monkeypatch, trusted_proxies="2")
    signup = _make_signup(host, monkeypatch, cap="50", rate="100", sent=sent)
    monkeypatch.delenv("SMB_SIGNUP_TRUSTED_PROXIES", raising=False)

    resp = signup.post(
        "/provision",
        json={"business_name": "Chain Length Co", "contact": CONTACT},
        headers={"X-Forwarded-For": "203.0.113.9, 203.0.113.10"},
    )
    assert resp.status_code == 201, resp.text

    forwarded = [h["x-forwarded-for"] for h in sent if "x-forwarded-for" in h]
    assert forwarded, "nothing was forwarded to the host at all"
    for chain in forwarded:
        entries = [part.strip() for part in chain.split(",") if part.strip()]
        assert len(entries) == 1, f"the caller lengthened the forwarded chain: {chain!r}"
        assert "203.0.113" not in chain, f"a caller-supplied entry survived into the chain: {chain!r}"

    stored = _stored_meta(tmp_path, resp.json()["tenant_id"])["provisioned_by"]
    assert stored not in ("203.0.113.9", "203.0.113.10"), (
        f"a caller chose the record by lengthening the chain: provisioned_by={stored!r}"
    )


def test_the_address_that_is_recorded_is_the_address_that_was_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One determination, not two. The rate limit and the record must name the
    same caller, or the bound counts one address while the record blames
    another — a pair that is individually defensible and jointly a lie."""
    host = _make_host(tmp_path, monkeypatch, trusted_proxies="1")
    signup = _make_signup(host, monkeypatch, cap="50", rate="1")
    monkeypatch.setenv("SMB_SIGNUP_TRUSTED_PROXIES", "1")

    first = signup.post(
        "/provision",
        json={"business_name": "Counted And Named Co", "contact": CONTACT},
        headers={"X-Forwarded-For": "198.51.100.21"},
    )
    assert first.status_code == 201, first.text
    assert _stored_meta(tmp_path, first.json()["tenant_id"])["provisioned_by"] == "198.51.100.21"

    # The same caller has spent its allowance...
    again = signup.post(
        "/provision",
        json={"business_name": "Counted Twice Co", "contact": CONTACT},
        headers={"X-Forwarded-For": "198.51.100.21"},
    )
    assert again.status_code == 429, "the address that was recorded was not the one being counted"

    # ...and a different one has not.
    other = signup.post(
        "/provision",
        json={"business_name": "Other Caller Co", "contact": CONTACT},
        headers={"X-Forwarded-For": "198.51.100.22"},
    )
    assert other.status_code == 201, other.text
    assert _stored_meta(tmp_path, other.json()["tenant_id"])["provisioned_by"] == "198.51.100.22"


def test_health_says_whether_the_host_records_what_this_service_states(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ A CONTROL SPLIT ACROSS TWO SERVICES CAN BE HALF-CONFIGURED SILENTLY.

    Forwarding without `SMB_HOST_TRUSTED_PROXIES` on the host is a fix that
    looks applied and records the façade's own address forever. Nothing refuses,
    nothing logs, and the only symptom is a directory of identical attributions
    discovered much later. It is readable from `/health` instead.
    """
    ignoring = _make_host(tmp_path, monkeypatch, trusted_proxies=None)
    signup = _make_signup(ignoring, monkeypatch, cap="50", rate="100")
    assert signup.get("/health").json()["caller_attribution"] == "discarded-by-host"

    recording = _make_host(tmp_path, monkeypatch, trusted_proxies="1")
    signup = _make_signup(recording, monkeypatch, cap="50", rate="100")
    assert signup.get("/health").json()["caller_attribution"] == "recorded"


def test_a_host_that_does_not_report_its_hop_count_yields_no_verdict() -> None:
    """A host older than this field is a real deployment state — the two services
    are versioned and shipped separately. Absent must read as "cannot tell",
    never as "not configured": the second is a claim about the host's settings
    made from a body that carried none.

    Read off the wire shape rather than driven, because an in-tree host cannot
    produce a body missing a field it always sends. The two states an in-tree
    host CAN produce are driven, in the test above.
    """
    import smb_signup.main as signup_main

    assert signup_main._attribution_state({"status": "ok", "tenants": 4}) == "unknown"
    # And the boolean shapes JSON allows here are not read as hop counts: `True`
    # is an int in Python and would otherwise certify attribution off a field
    # that never said a number.
    assert signup_main._attribution_state({"trusted_proxies": True}) == "unknown"
    assert signup_main._attribution_state({"trusted_proxies": "1"}) == "unknown"


# ── the bundle ───────────────────────────────────────────────────────────────


def test_the_facade_answers_no_cross_origin_caller(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """⚠️ THE ABSENCE OF CORS HERE IS A DECISION, NOT AN OVERSIGHT — asserted so it
    reads as one.

    This service SERVES the funnel, so the public shape is same-origin and needs
    no cross-origin permission. `smb_host` allows any origin because a static
    bundle hosted elsewhere has to reach it, AND because provisioning there is
    gated on a bearer token a stranger's page does not hold. This front door has
    no such gate by design — provisioning through it carries no caller credential
    at all — so the same permissiveness would let any page on the internet spend
    a visitor's rate-limit allowance and this cap from that visitor's browser,
    and (since the caller is now forwarded) record that visitor's address as
    having provisioned an agent. What made the permission safe on the host is
    the very thing this service does not have.

    If the bundle is ever hosted somewhere other than this service, this test is
    the thing that will fail and force the choice to be made again explicitly.

    ⚠️ AND THE PAGE SIDE NOW AGREES WITH IT. `smb_funnel/src/config.js` used to
    document "point API_BASE at a host and nothing else needs to change", which
    is true of `smb_host` and describes a shape this service cannot serve — a
    cross-origin page pointed here had its preflight refused, the request never
    left the browser, and the funnel rendered its generic retry message for a
    status it never received. `config.js` now names which target supports which
    shape, and the funnel has a distinct state for a request that was never
    delivered. Two places said different things about one decision; a refusal
    asserted here and contradicted in the page's own configuration file is not a
    decision the tree holds.
    """
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    preflight = signup.options(
        "/provision",
        headers={
            "Origin": "https://somewhere.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert "access-control-allow-origin" not in {k.lower() for k in preflight.headers}

    posted = signup.post(
        "/provision",
        json={"business_name": "Cross Origin Co", "contact": CONTACT},
        headers={"Origin": "https://somewhere.example"},
    )
    assert "access-control-allow-origin" not in {k.lower() for k in posted.headers}, (
        "the front door grants cross-origin access; a page anywhere could spend this cap"
    )


def test_the_served_bundle_carries_no_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """⚠️ GREPPED FROM WHAT IS SERVED, NOT FROM THE SOURCE TREE. The question is
    what reaches a browser."""
    host = _make_host(tmp_path, monkeypatch)
    signup = _make_signup(host, monkeypatch)

    page = signup.get("/")
    assert page.status_code == 200
    served = page.text
    for name in ("src/app.js", "src/api.js", "src/config.js", "src/render.js", "src/arp.js"):
        module = signup.get(f"/{name}")
        assert module.status_code == 200, f"{name} is not served"
        served += module.text

    # ⚠️ THE PROPERTY IS THE SECRET'S VALUE, NOT THE VARIABLE'S NAME. A first
    # draft banned the string "SMB_HOST_PROVISION_TOKEN" and failed on a COMMENT
    # in api.js explaining which gate the host applies — documentation, not a
    # leak. Banning the name would have pushed a true explanation out of the
    # source to make a test pass, which is the wrong direction entirely.
    assert HOST_TOKEN not in served, "the provisioning secret reached the browser"
    assert "Bearer test-" not in served and "Bearer sk" not in served
    # Nothing in the bundle may carry a literal credential of any shape.
    import re

    for literal in re.findall(r"""["'`]Bearer [^"'`]*["'`]""", served):
        assert "${" in literal, f"the bundle embeds a literal bearer credential: {literal}"
