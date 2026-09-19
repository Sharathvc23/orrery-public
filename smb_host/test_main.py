"""Tests for the SMB Host — provision (mint identity) → live card → book → verify.

This host registers on NO index. There is one NANDA Index (api.nandaindex.org)
and putting the agent there is host39's job, downstream of what ``POST /provision``
returns (``{tenant_id, endpoint, did, recovery_phrase}``). So these tests assert
the host's own roles only: minting an isolated identity, serving a live A2A card
at the tenant endpoint, and issuing signed booking receipts that verify OFFLINE.

The important one is ``test_provision_mints_identity_and_serves_live_card``: it
boots a real SMB host, provisions a business, and proves the tenant's endpoint
serves an A2A card carrying the SAME did:key the provision response returned.

Classification: HAPPY / EDGE / FAILURE
"""

from __future__ import annotations

import importlib
import json
import logging
import queue
import re
import secrets
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest
from fastapi.testclient import TestClient

# The provisioning secret these tests configure. Every helper below sets it and
# sends it, so the suite exercises the gated path by default: the public_url most
# of these tests use is NOT loopback, and an un-gated host at a public address is
# refused (see the SMB_HOST_PROVISION_TOKEN block in main.py). Pass token="" to a
# helper to build a host with no secret configured.
#
# GENERATED, not a literal, for two reasons: a checked-in credential-shaped
# string is what the secret scanner is for, and a value that differs every run
# proves no assertion below depends on the particular characters.
_TEST_TOKEN = secrets.token_urlsafe(24)

# Every provision call needs a contact channel: a business that cannot be
# reached cannot receive a booking, so the field is required. An https URL keeps
# the tests on the channel the shipped sender can actually deliver on; the
# delivery itself is stubbed where a test asserts it.
_TEST_CONTACT = "https://bookings.example/hook"

# Generously large so no pre-existing test brushes against it by accident — the
# cap has its own dedicated tests, which set it explicitly to something small.
_TEST_TENANT_CAP = "1000"


def _booking_status_from_contract() -> str:
    """The one value both this suite and smb_funnel's are held to for a
    successful booking's ``status`` field. Read rather than duplicated as a
    literal: a hardcoded copy here is exactly the shape that let the mock and
    the host disagree before host_contract.json existed (see
    test_refusal_contract_matches_the_shared_file above)."""
    contract = json.loads(
        (Path(__file__).resolve().parent.parent / "smb_funnel" / "tests" / "host_contract.json").read_text()
    )
    status: str = contract["book_success"]["booking_status"]
    return status


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def _make_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    public_url: str,
    token: str = _TEST_TOKEN,
    tenant_cap: str = _TEST_TENANT_CAP,
) -> TestClient:
    """Build a fresh SMB host app bound to ``public_url``, rooted at an isolated
    data dir under ``tmp_path``. No index is involved — the host registers
    nowhere. The returned client sends ``token`` as a bearer on every request."""
    monkeypatch.setenv("HOST_PUBLIC_URL", public_url)
    monkeypatch.setenv("SMB_HOST_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    monkeypatch.setenv("SMB_HOST_POOL_SIZE", "0")  # default to pure cold-provision
    monkeypatch.setenv("SMB_HOST_PROVISION_TOKEN", token)
    monkeypatch.setenv("SMB_HOST_TENANT_CAP", tenant_cap)
    # Force a clean import so create_app() reads the env set above.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import main as host_main

    importlib.reload(host_main)
    return TestClient(host_main.app, headers=_auth(token))


def _build_host_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    public_url: str,
    pool_size: int,
    token: str = _TEST_TOKEN,
    tenant_cap: str = _TEST_TENANT_CAP,
) -> ModuleType:
    """Reload the host module with ``SMB_HOST_POOL_SIZE`` set and return the
    MODULE (not a TestClient) so a B4 test can:
      * drive the app inside ``with TestClient(mod.app) as client`` — the ONLY
        way the pool warmer's lifespan fires (a bare ``TestClient(app)`` never
        runs startup, which is exactly why the pre-existing tests keep cold-path
        behavior); and
      * monkeypatch module-level functions (e.g. ``_cold_provision``) on it to
        structurally prove which path served a request.
    """
    monkeypatch.setenv("HOST_PUBLIC_URL", public_url)
    monkeypatch.setenv("SMB_HOST_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    monkeypatch.setenv("SMB_HOST_POOL_SIZE", str(pool_size))
    monkeypatch.setenv("SMB_HOST_PROVISION_TOKEN", token)
    monkeypatch.setenv("SMB_HOST_TENANT_CAP", tenant_cap)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import main as host_main

    importlib.reload(host_main)
    return host_main


def _client(mod: ModuleType, token: str = _TEST_TOKEN) -> TestClient:
    """A TestClient over a module built by :func:`_build_host_module`, carrying
    the same bearer that module was configured with."""
    return TestClient(mod.app, headers=_auth(token))


# Long enough for several warmer ticks (the backstop poll is _POOL_POLL_INTERVAL_S
# = 2.0s), so a loop that re-keys a slot it already made ready has room to do it
# before the assertion looks.
_POOL_SETTLE_S = 5.0


def _wait_for_pool(client: TestClient, n: int, timeout: float = 30.0) -> None:
    """Poll /health until the warmer has ``n`` ready tenants in the pool."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready = client.get("/health").json()["pool_ready"]
        if ready >= n:
            return
        time.sleep(0.15)
    raise AssertionError(f"pool did not warm to {n} within {timeout}s")


# ── provision mints identity + serves a live card ────────────────────────────────


def test_provision_mints_identity_and_serves_live_card(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """HAPPY (the important one): provision → mints an isolated did:key and returns
    exactly ``{tenant_id, endpoint, did, recovery_phrase}`` (NO urn — that was an
    index concept) → the returned endpoint serves a live A2A card with the SAME
    did:key. No index is touched anywhere."""
    public_url = "http://smb-host.example"
    host = _make_host(tmp_path, monkeypatch, public_url)

    resp = host.post(
        "/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts", "service_type": "barber"}
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    tenant_id = body["tenant_id"]
    did = body["did"]
    assert tenant_id == "sharp-cuts"
    assert did.startswith("did:key:z")
    assert body["endpoint"] == f"{public_url}/t/{tenant_id}"
    assert len(body["recovery_phrase"].split()) == 24
    # The response is exactly the host39 handoff shape — no urn, nothing else.
    assert set(body.keys()) == {"tenant_id", "endpoint", "did", "recovery_phrase"}

    # The endpoint RESOLVES to a live card on the host, same did:key.
    card = host.get(f"/t/{tenant_id}/.well-known/agent.json")
    assert card.status_code == 200, card.text
    card_json = card.json()
    assert card_json["name"] == "Sharp Cuts"
    assert card_json["url"] == f"{public_url}/t/{tenant_id}"
    # No auth dependency exists on any tenant route (see S2 in test_served_claims.py):
    # the card must not advertise a scheme nothing here enforces. `credentials` still
    # carries the did — that identifies the key this agent SIGNS with, a separate fact
    # from what a caller must present to be authenticated, which is nothing.
    assert card_json["authentication"]["schemes"] == []
    assert card_json["authentication"]["credentials"] == did
    assert card_json["x-nanda"]["did"] == did


# ── multi-tenant isolation ───────────────────────────────────────────────────────


def test_two_businesses_are_independent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """HAPPY: two businesses in one host process get distinct tenant_ids, distinct
    did:keys, distinct recovery phrases, and distinct cards."""
    public_url = "http://smb-host.example"
    host = _make_host(tmp_path, monkeypatch, public_url)

    a = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()
    b = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Bright Nails"}).json()

    assert a["tenant_id"] == "sharp-cuts"
    assert b["tenant_id"] == "bright-nails"
    assert a["did"] != b["did"]
    assert a["recovery_phrase"] != b["recovery_phrase"]
    assert a["endpoint"] == f"{public_url}/t/sharp-cuts"
    assert b["endpoint"] == f"{public_url}/t/bright-nails"

    # Both cards served, each with its own did:key.
    card_a = host.get(f"/t/{a['tenant_id']}/.well-known/agent.json").json()
    card_b = host.get(f"/t/{b['tenant_id']}/.well-known/agent.json").json()
    assert card_a["authentication"]["credentials"] == a["did"]
    assert card_b["authentication"]["credentials"] == b["did"]
    assert card_a["name"] == "Sharp Cuts"
    assert card_b["name"] == "Bright Nails"


# ── restart rehydration ──────────────────────────────────────────────────────────


def test_restart_rehydrates_tenants_from_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """EDGE: a fresh host process over the same data dir rehydrates the tenant —
    same did, card still served — without re-provisioning."""
    public_url = "http://smb-host.example"
    host = _make_host(tmp_path, monkeypatch, public_url)
    provisioned = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()

    # Simulate a restart: a brand-new app instance over the SAME data dir.
    host2 = _make_host(tmp_path, monkeypatch, public_url)
    assert host2.get("/health").json()["tenants"] == 1
    card = host2.get(f"/t/{provisioned['tenant_id']}/.well-known/agent.json").json()
    assert card["authentication"]["credentials"] == provisioned["did"]


# ── graceful failures ────────────────────────────────────────────────────────────


# The DEFAULT configuration is listed first on purpose. Both of these assertions
# used to run only with SMB_HOST_POOL_SIZE=0, which is not what anybody runs:
# the default is 3, the pool claim took a pre-minted id without consulting the
# name, and neither refusal executed. Measured at ebb0aeb on a real host with
# nothing set but HOST_PUBLIC_URL, the same name three times returned
# 201/201/201 — three did:keys, three cards all reading "Corner Bakery" — and a
# name of only punctuation returned 201 rather than the documented 400. The
# suite was covering a path nobody runs.
_BOTH_PROVISION_PATHS = pytest.mark.parametrize(
    "pool_size",
    [pytest.param(3, id="pooled-default"), pytest.param(0, id="cold-path")],
)


@_BOTH_PROVISION_PATHS
def test_duplicate_business_name_conflicts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool_size: int) -> None:
    """FAILURE: the same business name provisioned twice → 409, on BOTH paths.

    A refusal whose presence depends on a performance setting is worse than
    either having it or not having it, because the operator cannot tell which
    behaviour they have.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=pool_size)
    with _client(mod) as host:
        if pool_size:
            _wait_for_pool(host, pool_size)

        first = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"})
        assert first.status_code == 201
        dup = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"})
        assert dup.status_code == 409, f"the duplicate was accepted: {dup.status_code} {dup.text[:200]}"
        assert "Sharp Cuts" in dup.json()["detail"]


@_BOTH_PROVISION_PATHS
def test_the_409_does_not_disclose_an_existing_tenant_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool_size: int
) -> None:
    """The refusal names what the caller supplied, never somebody else's id.

    On the cold path the tenant_id is only the slug of the name the caller just
    sent. On the pool path it is a random id belonging to a live tenant, and
    /t/<id> is that tenant's endpoint, card and booking route — so a refusal
    that echoed it would turn a duplicate-name probe into a directory of every
    business on the host, on the loopback shape where provisioning is open.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=pool_size)
    with _client(mod) as host:
        if pool_size:
            _wait_for_pool(host, pool_size)

        taken = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()[
            "tenant_id"
        ]
        dup = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"})

        assert dup.status_code == 409
        assert taken not in dup.text, f"the 409 hands the caller a live tenant id: {dup.text[:200]}"
        # and the id it would have disclosed is a real, reachable tenant
        assert host.get(f"/t/{taken}/.well-known/agent.json").status_code == 200


@_BOTH_PROVISION_PATHS
def test_blank_business_name_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool_size: int) -> None:
    """EDGE: a name with no alphanumerics can't slug to an id → 400, on BOTH paths."""
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=pool_size)
    with _client(mod) as host:
        if pool_size:
            _wait_for_pool(host, pool_size)

        for name in ("!!!", "   ", "---"):
            resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": name})
            assert resp.status_code == 400, f"{name!r} provisioned instead of being refused: {resp.status_code}"


@_BOTH_PROVISION_PATHS
def test_which_names_collide_and_which_do_not(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool_size: int) -> None:
    """The exact boundary of the refusal, so the docs cannot overstate it.

    _slugify lowercases and collapses every non-alphanumeric run to a hyphen, so
    case, punctuation and spacing variants collide. A genuinely different slug
    does not — this refuses a repeated name, it does not establish name
    ownership, and the tenant URL still does not identify a business.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=pool_size)
    with _client(mod) as host:
        if pool_size:
            _wait_for_pool(host, pool_size)

        assert (
            host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Corner Bakery"}).status_code
            == 201
        )

        for collides in ("CORNER BAKERY", "Corner-Bakery", "corner  bakery", "Corner Bakery.", " corner bakery "):
            resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": collides})
            assert resp.status_code == 409, f"{collides!r} slugs to corner-bakery but was accepted"

        for distinct in ("Corner Bakery Ltd", "Corner Bakery NYC"):
            resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": distinct})
            assert resp.status_code == 201, f"{distinct!r} is a different slug and must still provision"


def test_a_duplicate_refusal_does_not_consume_a_pool_slot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refusing must not cost a pre-minted tenant.

    If the queue were read before the name were checked, every rejected
    duplicate would drain the pool by one and the slot would be stranded —
    minted, on disk, in no queue and claimable by nobody.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=3)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        assert (
            host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).status_code == 201
        )
        _wait_for_pool(host, 3)  # the warmer refills the one that WAS claimed

        for _ in range(3):
            assert (
                host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).status_code
                == 409
            )

        assert host.get("/health").json()["pool_ready"] == 3, "a refused duplicate consumed a pool slot"


def test_the_name_is_still_taken_after_a_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The refusal must survive a restart, or it is only a per-process accident.

    The answer is derived from the tenant table, which _rehydrate rebuilds from
    disk — so this is what proves it is not held in a second index that a
    restart forgets.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=3)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        assert (
            host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).status_code == 201
        )

    restarted = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=3)
    with _client(restarted) as host:
        dup = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"})
        assert dup.status_code == 409, f"the name was free again after a restart: {dup.status_code}"


def test_an_unclaimed_pool_tenant_does_not_reserve_its_placeholder_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existence is not what makes a name taken — being claimed is.

    Pre-minted pool tenants all carry the same placeholder display name. If the
    check looked at every tenant rather than every CLAIMED tenant, the first
    warm pool would make that placeholder permanently unavailable, and any two
    unclaimed tenants would look like a collision with each other.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=3)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": mod._POOL_PLACEHOLDER_NAME})
        assert resp.status_code == 201, (
            f"the pool's own placeholder name is unclaimable: {resp.status_code} {resp.text[:200]}"
        )


def test_refusal_contract_matches_the_shared_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CONTRACT: this host's refusals are what ``smb_funnel/tests/host_contract.json`` says.

    ⚠️ WHY A FILE AND NOT ASSERTIONS INLINE. The funnel's README claims it "speaks
    the real host contract either way", and its in-page mock answered refusals
    this host never sends — ``{"error": ...}`` with a 400 where this host sends
    ``{"detail": [...]}`` with a 422, and worse, it PROVISIONED a punctuation-only
    name and a non-string name that this host refuses outright. Its own smoke test
    asserted the mock's 400, so the suite meant to prove parity pinned the wrong
    side of it.

    One file now states the refusals. This test holds the host to it; the funnel's
    ``tests/contract-parity.test.mjs`` holds the mock to it. Change this host's
    wording and this test reddens; update the file to match and the mock's test
    reddens until the mock follows. A one-sided pin is what let them diverge.
    """
    contract = json.loads(
        (Path(__file__).resolve().parent.parent / "smb_funnel" / "tests" / "host_contract.json").read_text()
    )
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")

    def check(resp, expected, label: str) -> None:
        assert resp.status_code == expected["status"], f"{label}: {resp.status_code} != {expected['status']}"
        detail = resp.json().get("detail")
        if expected["detail"] == "string":
            assert isinstance(detail, str), f"{label}: detail is {type(detail).__name__}, not a string"
            assert detail == expected["message"], f"{label}: {detail!r} != {expected['message']!r}"
        else:
            assert isinstance(detail, list), f"{label}: detail is {type(detail).__name__}, not an array"
            assert detail, f"{label}: empty validation array"
            assert list(detail[0]["loc"]) == expected["loc"], f"{label}: loc {detail[0]['loc']}"
            assert detail[0]["type"] == expected["type"], f"{label}: type {detail[0]['type']}"

    for case in contract["provision"]:
        if case.get("provision_first"):
            assert host.post("/provision", json=case["body"]).status_code == 201
        check(host.post("/provision", json=case["body"]), case, f"provision / {case['case']}")

    live = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Parity Test Co"})
    assert live.status_code == 201
    tenant = live.json()["tenant_id"]

    for case in contract["card"]:
        check(host.get(f"/t/{case['tenant_id']}/.well-known/agent.json"), case, f"card / {case['case']}")
    for case in contract["book"]:
        target = case.get("tenant_id") or tenant
        check(host.post(f"/t/{target}/book", json=case["body"]), case, f"book / {case['case']}")

    unknown = contract["unknown_route"]
    check(host.get(unknown["path"]), unknown, "unknown route")

    # Guards the guard: an emptied file would make every loop above iterate zero
    # times and pass, which is the failure this whole test exists to prevent.
    assert len(contract["provision"]) >= 6, f"only {len(contract['provision'])} provision cases"
    assert any(c["detail"] == "array" for c in contract["provision"])
    assert any(c["detail"] == "string" for c in contract["provision"])


def test_cors_allows_browser_funnel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """EDGE: the browser funnel is served from another origin, so the host must
    answer cross-origin. A CORS preflight for POST /provision is allowed, and an
    actual request echoes an Access-Control-Allow-Origin header."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")

    preflight = host.options(
        "/provision",
        headers={
            "Origin": "http://localhost:8700",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] in ("*", "http://localhost:8700")

    # ⚠️ THE HEADERS THE FUNNEL ACTUALLY SENDS, NOT A SUBSET OF THEM. This test
    # asked only for "content-type" and passed while a preflight naming
    # "authorization" was answered 400 "Disallowed CORS headers" — so a browser
    # would never have sent the gated POST at all, with or without a valid token,
    # and the page would have shown a network failure instead of the 401 this
    # host is careful to word. A preflight assertion that omits the one header
    # the endpoint requires is testing the middleware, not the path.
    gated = host.options(
        "/provision",
        headers={
            "Origin": "http://localhost:8700",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type, authorization",
        },
    )
    assert gated.status_code == 200, gated.text
    allowed = {h.strip().lower() for h in gated.headers.get("access-control-allow-headers", "").split(",")}
    assert "authorization" in allowed, gated.headers.get("access-control-allow-headers")
    assert "content-type" in allowed

    resp = host.get("/health", headers={"Origin": "http://localhost:8700"})
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] in ("*", "http://localhost:8700")


# ── booking → verifiable signed receipt (B2b-2) ──────────────────────────────────


def test_book_returns_receipt_that_verifies_offline_under_tenant_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HAPPY (the important one): provision → POST /t/<tenant>/book → 200 with a
    signed receipt that ``arp.verify_receipt`` ACCEPTS offline and whose
    issuer_did == the tenant's did:key. The booking + receipt live under that
    tenant's home only."""
    from community_member import arp

    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    provisioned = host.post(
        "/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts", "service_type": "barber"}
    ).json()
    tenant_id, did = provisioned["tenant_id"], provisioned["did"]

    resp = host.post(
        f"/t/{tenant_id}/book",
        json={"service": "haircut", "provider": "Sharp Cuts", "datetime": "2026-08-01T14:30:00Z", "notes": "fade"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Response shape the funnel consumes.
    assert body["booking"]["status"] == _booking_status_from_contract()
    assert body["booking"]["service"] == "haircut"
    assert body["booking"]["provider"] == "Sharp Cuts"
    assert body["booking"]["datetime"] == "2026-08-01T14:30:00Z"
    assert body["booking"]["tenant_id"] == tenant_id
    assert body["receipt_id"] == body["receipt"]["receipt_id"]

    # The receipt is the REAL signed ARP receipt: verifies OFFLINE, no server.
    receipt = body["receipt"]
    assert receipt["issuer_did"] == did
    assert receipt["action"]["category"] == "appointment_booked"
    result = arp.verify_receipt(receipt)
    assert result.ok, f"receipt failed offline strict verify: {result}"
    # And its signature checks under the tenant's own did:key specifically.
    assert arp.verify_receipt_signature(receipt)

    # The booking + receipt landed under THIS tenant's home only.
    home = tmp_path / "data" / tenant_id
    assert (home / "bookings.json").is_file()
    assert (home / "agency-log.sqlite").is_file()
    assert arp.AgencyLog(home).get(body["receipt_id"]) is not None


def test_two_tenants_book_in_isolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """HAPPY: two tenants each book; each receipt verifies under ITS OWN key and
    neither booking/receipt leaks into the other's home."""
    from community_member import arp

    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    a = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()
    b = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Bright Nails"}).json()

    rc_a = host.post(
        f"/t/{a['tenant_id']}/book",
        json={"service": "haircut", "provider": "Sharp Cuts", "datetime": "2026-08-01T14:30:00Z"},
    ).json()
    rc_b = host.post(
        f"/t/{b['tenant_id']}/book",
        json={"service": "manicure", "provider": "Bright Nails", "datetime": "2026-08-02T10:00:00Z"},
    ).json()

    # Each receipt is signed by — and verifies under — its own tenant's did:key.
    assert rc_a["receipt"]["issuer_did"] == a["did"]
    assert rc_b["receipt"]["issuer_did"] == b["did"]
    assert a["did"] != b["did"]
    assert arp.verify_receipt(rc_a["receipt"]).ok
    assert arp.verify_receipt(rc_b["receipt"]).ok
    # A's receipt does NOT verify as if issued by B (distinct keys).
    assert rc_a["receipt"]["signature"] != rc_b["receipt"]["signature"]

    # No cross-contamination: each tenant's Agency Log holds only its own receipt.
    log_a = arp.AgencyLog(tmp_path / "data" / a["tenant_id"])
    log_b = arp.AgencyLog(tmp_path / "data" / b["tenant_id"])
    assert log_a.get(rc_a["receipt_id"]) is not None
    assert log_a.get(rc_b["receipt_id"]) is None
    assert log_b.get(rc_b["receipt_id"]) is not None
    assert log_b.get(rc_a["receipt_id"]) is None
    # B's booking never touched A's booking store.
    a_bookings = json.loads((tmp_path / "data" / a["tenant_id"] / "bookings.json").read_text())
    assert all(bk["provider"] == "Sharp Cuts" for bk in a_bookings)


def test_book_unknown_tenant_is_404(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FAILURE: booking an unknown tenant → 404, loud."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    resp = host.post(
        "/t/nope/book",
        json={"service": "haircut", "provider": "x", "datetime": "2026-08-01T14:30:00Z"},
    )
    assert resp.status_code == 404
    assert "nope" in resp.json()["detail"]


def test_book_malformed_body_is_400(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FAILURE: a body missing required fields → 400 (a client error we own)."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    provisioned = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()
    resp = host.post(f"/t/{provisioned['tenant_id']}/book", json={"service": "haircut"})
    assert resp.status_code == 400
    assert "provider" in resp.json()["detail"]
    assert "datetime" in resp.json()["detail"]


def test_book_that_cannot_record_the_attempt_stores_nothing_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FAILURE: the Agency Log cannot take the write-ahead attempt → no booking
    is stored, and the response says which tenant failed and that a retry is
    safe.

    Two things are asserted, because the pair is the finding. The booking store
    must not gain a row — a durable booking with no record of it anywhere is
    exactly what "every booking emits a signed receipt" denies. And the response
    must be usable: previously the exception escaped to FastAPI's generic
    handler, so the caller saw a bare "Internal Server Error" with no indication
    that nothing had been stored, while the route's own explanatory 500 was
    unreachable.

    The fault is injected at the FIRST Agency Log write — the attempt the skill
    records before the booking — as sqlite3.OperationalError('attempt to write
    a readonly database'), which is how an unwritable log actually presents.
    """
    import sqlite3

    from community_member import arp

    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    provisioned = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()
    tenant_id = provisioned["tenant_id"]
    good = {"service": "haircut", "provider": "Sam", "datetime": "2026-09-01T10:00:00Z"}

    assert host.post(f"/t/{tenant_id}/book", json=good).status_code == 200
    bookings_file = tmp_path / "data" / tenant_id / "bookings.json"
    before = json.loads(bookings_file.read_text())

    def unwritable(self, **kw):  # noqa: ANN001, ARG001
        raise sqlite3.OperationalError("attempt to write a readonly database")

    monkeypatch.setattr(arp.AgencyLog, "begin_action", unwritable)
    # A DIFFERENT slot: the same provider and datetime is now refused 409 before
    # the log is reached, and these tests are about what happens when the log
    # cannot be written.
    resp = host.post(
        f"/t/{tenant_id}/book",
        json={**good, "service": "beard trim", "datetime": "2026-09-01T11:00:00Z"},
    )

    assert resp.status_code == 500
    detail = resp.json()["detail"]
    assert tenant_id in detail, f"the response does not say which tenant failed: {detail!r}"
    assert "no booking was stored" in detail, f"the response does not say nothing was stored: {detail!r}"

    after = json.loads(bookings_file.read_text())
    assert after == before, "a booking was stored even though the Agency Log could not record it"


def test_book_whose_receipt_fails_after_the_store_write_says_the_slot_is_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FAILURE: the booking is written and the receipt write then fails → the
    booking stands, the response says so and says NOT to retry, and a retry of
    the slot is refused rather than booked twice.

    The receipt is signed only for a booking that exists (the skill's
    write-ahead order: attempt, booking, receipt). Telling this caller "no
    booking was stored — safe to retry" would be false in both halves: the slot
    is held, and the retry is a duplicate. What the caller is owed is the
    booking id and the attempt in the tenant's Agency Log that is owed a receipt.
    """
    import sqlite3

    from community_member import arp

    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    provisioned = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()
    tenant_id = provisioned["tenant_id"]
    bookings_file = tmp_path / "data" / tenant_id / "bookings.json"

    def unwritable(self, receipt):  # noqa: ANN001, ARG001
        raise sqlite3.OperationalError("attempt to write a readonly database")

    monkeypatch.setattr(arp.AgencyLog, "append", unwritable)
    body = {"service": "beard trim", "provider": "Sam", "datetime": "2026-09-01T11:00:00Z"}
    resp = host.post(f"/t/{tenant_id}/book", json=body)

    assert resp.status_code == 500
    detail = resp.json()["detail"]
    assert tenant_id in detail
    assert "stored booking 1" in detail and "do not retry" in detail, detail
    assert "no booking was stored" not in detail, "the response claims nothing was stored while the booking exists"
    stored = json.loads(bookings_file.read_text())
    assert [b["id"] for b in stored] == [1], "the booking the response reports as stored is not on disk"

    # The receipt is owed, and visible as such in the tenant's Agency Log.
    log = arp.AgencyLog(tmp_path / "data" / tenant_id)
    owed = log.unresolved_actions()
    assert len(owed) == 1 and owed[0]["state"] == "succeeded" and owed[0]["receipt_id"] is None
    assert owed[0]["attempt_id"] in detail

    # A retry does not book the slot twice.
    monkeypatch.undo()
    again = host.post(f"/t/{tenant_id}/book", json=body)
    assert again.status_code == 409, again.text
    assert [b["id"] for b in json.loads(bookings_file.read_text())] == [1]


def test_book_on_a_damaged_store_refuses_and_does_not_tell_the_caller_to_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FAILURE: an unreadable booking store → refuse, keep the file, say retrying
    will not help.

    Separated from the transient failure above because the advice differs and
    the advice is the point. A damaged store cannot be fixed by retrying, and a
    caller told "safe to retry" would hammer a tenant that needs an operator.

    The store must also come back byte-for-byte: the whole reason for refusing
    rather than reading it as empty is that the bookings it still holds stay
    recoverable.
    """
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    provisioned = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()
    tenant_id = provisioned["tenant_id"]
    good = {"service": "haircut", "provider": "Sam", "datetime": "2026-09-01T10:00:00Z"}

    assert host.post(f"/t/{tenant_id}/book", json=good).status_code == 200

    bookings_file = tmp_path / "data" / tenant_id / "bookings.json"
    # The shape concurrent writers actually produced: one array, then another.
    damaged = bookings_file.read_text() + "  " + bookings_file.read_text()
    bookings_file.write_text(damaged)

    # A DIFFERENT slot: the same provider and datetime is now refused 409 before
    # the receipt path is reached, and these tests are about what happens when
    # the receipt cannot be persisted.
    resp = host.post(
        f"/t/{tenant_id}/book",
        json={**good, "service": "beard trim", "datetime": "2026-09-01T11:00:00Z"},
    )

    assert resp.status_code == 500
    detail = resp.json()["detail"]
    assert tenant_id in detail
    assert "unreadable booking store" in detail
    assert "retrying will not help" in detail, f"the caller is not told retrying is futile: {detail!r}"

    assert bookings_file.read_text() == damaged, "the damaged store was modified, losing what it still held"


# ── B4: pre-warmed tenant pool ────────────────────────────────────────────────────


def test_provision_is_served_from_pool_without_cold_mint_on_request_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HAPPY (the important one): with a warm pool, POST /provision CLAIMS a
    pre-minted tenant and returns instantly — proven STRUCTURALLY, not by timing:

      1. the cold mint function (`_cold_provision`) is NOT called on the request
         path; and
      2. the returned tenant was already MINTED *before* the request arrived (its
         id is in the pre-request in-memory tenant table).

    Then: the claimed tenant's display reflects the business_name, and it books a
    receipt that verifies offline under its key. No index is involved anywhere."""
    from community_member import arp

    public_url = "http://smb-host.example"
    host_main = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=2)

    with _client(host_main) as client:
        _wait_for_pool(client, 2)

        # Pre-request snapshot: exactly which tenants are already minted in memory.
        pre = set(host_main.app.state.host.tenants.keys())
        assert len(pre) >= 2  # the warmer pre-minted the pool

        # STRUCTURAL PROOF #1: spy the cold path; it must NOT run for this request.
        cold_calls: list[str] = []
        real_cold = host_main._cold_provision

        def _spy_cold(state: object, req: object, caller: str) -> object:
            cold_calls.append(getattr(req, "business_name", ""))
            return real_cold(state, req, caller)

        monkeypatch.setattr(host_main, "_cold_provision", _spy_cold)

        resp = client.post(
            "/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts", "service_type": "barber"}
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        tenant_id, did = body["tenant_id"], body["did"]

        assert cold_calls == [], "claim path must not invoke the cold mint function"
        # STRUCTURAL PROOF #2: the served tenant was pre-minted BEFORE the request.
        assert tenant_id in pre, "claimed tenant was not pre-minted"
        assert tenant_id.startswith("smb-pool-")  # came from the pool, not a name-slug
        assert did.startswith("did:key:z")
        assert body["endpoint"] == f"{public_url}/t/{tenant_id}"
        assert len(body["recovery_phrase"].split()) == 24  # the pool tenant's REAL phrase
        assert set(body.keys()) == {"tenant_id", "endpoint", "did", "recovery_phrase"}

        # Display reflects the business_name: the served card (canonical display).
        card = client.get(f"/t/{tenant_id}/.well-known/agent.json").json()
        assert card["name"] == "Sharp Cuts"
        assert card["authentication"]["credentials"] == did

        # Booking works end-to-end on the claimed tenant: verifiable offline.
        bk = client.post(
            f"/t/{tenant_id}/book",
            json={"service": "haircut", "provider": "Sharp Cuts", "datetime": "2026-08-01T14:30:00Z", "notes": "fade"},
        )
        assert bk.status_code == 200, bk.text
        receipt = bk.json()["receipt"]
        assert receipt["issuer_did"] == did
        assert arp.verify_receipt(receipt).ok
        assert arp.verify_receipt_signature(receipt)


def test_two_pool_claims_are_isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """HAPPY: two claims from the pool get distinct tenants — distinct ids, dids,
    recovery phrases — each with its own card and each booking a receipt that
    verifies under ITS OWN key."""
    from community_member import arp

    public_url = "http://smb-host.example"
    host_main = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=2)

    with _client(host_main) as client:
        _wait_for_pool(client, 2)
        a = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()
        b = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Bright Nails"}).json()

        assert a["tenant_id"] != b["tenant_id"]
        assert a["did"] != b["did"]
        assert a["recovery_phrase"] != b["recovery_phrase"]

        # Each serves its own card with its own did:key + endpoint.
        card_a = client.get(f"/t/{a['tenant_id']}/.well-known/agent.json").json()
        card_b = client.get(f"/t/{b['tenant_id']}/.well-known/agent.json").json()
        assert card_a["authentication"]["credentials"] == a["did"]
        assert card_b["authentication"]["credentials"] == b["did"]
        assert card_a["url"] == f"{public_url}/t/{a['tenant_id']}"
        assert card_b["url"] == f"{public_url}/t/{b['tenant_id']}"

        # Each books under its own key; the two receipts do not cross.
        rc_a = client.post(
            f"/t/{a['tenant_id']}/book",
            json={"service": "haircut", "provider": "Sharp Cuts", "datetime": "2026-08-01T14:30:00Z"},
        ).json()
        rc_b = client.post(
            f"/t/{b['tenant_id']}/book",
            json={"service": "manicure", "provider": "Bright Nails", "datetime": "2026-08-02T10:00:00Z"},
        ).json()
        assert rc_a["receipt"]["issuer_did"] == a["did"]
        assert rc_b["receipt"]["issuer_did"] == b["did"]
        assert arp.verify_receipt(rc_a["receipt"]).ok
        assert arp.verify_receipt(rc_b["receipt"]).ok
        assert rc_a["receipt"]["signature"] != rc_b["receipt"]["signature"]


def test_drained_pool_falls_back_to_cold_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FAILURE-mode / graceful fallback: with the pool ENABLED but drained (and
    the warmer stopped so it can't refill), POST /provision still succeeds via
    the cold path — proven by (a) the cold function running and (b) the returned
    id being the name-slug, not a pool id. Correctness over latency."""
    public_url = "http://smb-host.example"
    host_main = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=2)

    with _client(host_main) as client:
        _wait_for_pool(client, 2)
        st = host_main.app.state.host
        # Stop the warmer and drain the pool → force the drained-fallback branch.
        st.pool_stop.set()
        st.pool_wake.set()
        if st.pool_thread is not None:
            st.pool_thread.join(timeout=5)
        while True:
            try:
                st.pool.get_nowait()
            except queue.Empty:
                break

        cold_calls: list[str] = []
        real_cold = host_main._cold_provision

        def _spy_cold(state: object, req: object, caller: str) -> object:
            cold_calls.append(getattr(req, "business_name", ""))
            return real_cold(state, req, caller)

        monkeypatch.setattr(host_main, "_cold_provision", _spy_cold)

        resp = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Late Comer"})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert cold_calls == ["Late Comer"], "a drained pool must fall back to the cold path"
        assert body["tenant_id"] == "late-comer"  # the name-slug ⇒ cold path served it
        assert body["endpoint"] == f"{public_url}/t/late-comer"
        # The cold-provisioned tenant serves a live card with the returned did.
        card = client.get("/t/late-comer/.well-known/agent.json").json()
        assert card["authentication"]["credentials"] == body["did"]


def test_pool_disabled_is_pure_cold_provision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """EDGE / backward-compat: SMB_HOST_POOL_SIZE=0 ⇒ today's behavior verbatim —
    no warmer, and /provision cold-provisions the name-slug tenant."""
    public_url = "http://smb-host.example"
    host_main = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=0)

    with _client(host_main) as client:
        assert client.get("/health").json()["pool_target"] == 0
        assert client.get("/health").json()["pool_ready"] == 0
        resp = client.post(
            "/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts", "service_type": "barber"}
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["tenant_id"] == "sharp-cuts"  # the name-slug ⇒ cold path
        assert resp.json()["endpoint"] == f"{public_url}/t/sharp-cuts"


# ── Leg B: the card this host serves is the one host39 publishes ─────────────────


def test_served_tenant_card_maps_to_a_valid_host39_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """HAPPY (Leg B, no-drift): the A2A card this host serves at
    ``/t/<tenant>/.well-known/agent.json`` maps cleanly onto host39's
    ``POST /cards`` body — runtime_url is this tenant's live endpoint and
    ``authentication.credentials`` is this tenant's did:key.

    host39's schema is ``additionalProperties: false``, so this also asserts the
    mapping produces no field host39 would reject. It is the coupling test: if
    ``_build_tenant_card`` ever changes shape, Leg B breaks HERE rather than as
    an opaque remote 400.
    """
    from community_member import host39

    public_url = "http://smb-host.example"
    host = _make_host(tmp_path, monkeypatch, public_url)

    provisioned = host.post(
        "/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts", "service_type": "barber"}
    ).json()
    tenant_id = provisioned["tenant_id"]
    did = provisioned["did"]
    card = host.get(f"/t/{tenant_id}/.well-known/agent.json").json()

    body = host39.a2a_card_to_host39_body(card, slug=tenant_id)

    declared = {
        "slug",
        "display_name",
        "description",
        "runtime_url",
        "version",
        "capabilities",
        "authentication",
        "skills",
        "provider_name",
        "provider_url",
        "is_public",
        "monitoring_enabled",
    }
    assert not (set(body) - declared), f"body carries fields host39 rejects: {sorted(set(body) - declared)}"
    assert body["slug"] == tenant_id
    assert body["display_name"] == "Sharp Cuts"
    assert body["runtime_url"] == provisioned["endpoint"]
    assert body["authentication"]["credentials"] == did
    # The pointer to canonical NANDA AgentFacts survives, inside capabilities —
    # it has no legal top-level home in host39's schema.
    assert body["capabilities"]["x-nanda"]["did"] == did


def test_provision_never_auto_publishes_to_host39(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FAILURE-MODE GUARD (empty is not configured-with-nothing): even with host39 FULLY configured
    in the environment, ``POST /provision`` must make no host39 call. Publishing
    is an explicit operator trigger (``scripts/publish_host39_card.py``), never a
    side effect of provisioning — and nothing fires on startup either.

    ``REGISTRY_URL=`` once meant LIVE PRODUCTION here and put 31 phantom records
    into a public registry. This test is the standing guard against the repeat.
    """
    import httpx as _httpx
    from community_member import host39

    monkeypatch.setenv(host39.BASE_URL_ENV, "https://cards.example.org")
    monkeypatch.setenv(host39.TOKEN_ENV, "a-token-that-must-never-be-used")
    assert host39.publishing_configured() is True, "the guard is only meaningful when configured"

    calls: list[str] = []

    def _record(method: str):
        def _fn(*args: object, **kwargs: object):
            calls.append(f"{method} {args[0] if args else ''}")
            raise AssertionError(f"provision made an outbound {method} call: {calls}")

        return _fn

    for attr in ("get", "post", "put", "request"):
        monkeypatch.setattr(_httpx, attr, _record(attr.upper()))

    public_url = "http://smb-host.example"
    host_main = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=0)

    # TestClient drives the ASGI app in-process, so it does not go through the
    # patched httpx module-level helpers; any call recorded below is a real
    # outbound request made BY the host.
    with _client(host_main) as client:
        resp = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"})
        assert resp.status_code == 201, resp.text
        client.get("/t/sharp-cuts/.well-known/agent.json")

    assert calls == [], f"provision/startup made outbound calls: {calls}"


# ── the card describes what the tenant can actually do ───────────────────────
#
# A tenant served "skills": [] while POST /t/<id>/book answered 200 with a
# signed receipt, and the card's x-nanda bag advertised an agentfacts_url that
# 404'd. Both were things the card asserted that were not true, on the one
# document a resolving client has to go on.


def _tenant_routes(app) -> set[str]:
    """Every tenant-scoped path in the app's own route table.

    Read from the live app rather than from a list in this file: a route added
    to the host must show up here without anyone remembering to update a test.
    """
    return {r.path for r in app.routes if getattr(r, "path", "").startswith("/t/{tenant_id}")}


def test_the_route_enumeration_can_see_the_tenant_routes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A walk that matched nothing would make the guard below pass on an empty
    set — the failure mode that lets a blind check report clean.

    Anchored on a route that must exist for the host to be the host at all,
    rather than on a count: a count would also fail when a route is legitimately
    removed, which is a different thing from the walk going blind.
    """
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    found = _tenant_routes(host.app)
    assert "/t/{tenant_id}/.well-known/agent.json" in found, (
        f"the route walk did not find the agent-card route; it found {sorted(found)}. "
        f"The walk has stopped seeing tenant routes, so the guard below would pass on an empty set."
    )


def test_the_card_declares_every_action_route_the_host_serves(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every tenant route is either a declared action or declared metadata.

    This is the divergence guard: adding POST /t/{tenant_id}/<something> without
    an entry in TENANT_ACTION_TOOLS fails here, so the card cannot silently stop
    describing what the host serves.
    """
    import main as host_main

    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    undeclared = _tenant_routes(host.app) - set(host_main.TENANT_ACTION_TOOLS) - host_main._TENANT_METADATA_ROUTES
    assert not undeclared, (
        f"tenant routes the card says nothing about: {sorted(undeclared)}. "
        f"Add each to TENANT_ACTION_TOOLS (a capability a caller can invoke) or "
        f"to _TENANT_METADATA_ROUTES (a document describing the agent)."
    )


def test_a_provisioned_tenant_advertises_the_booking_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Asserted against the SERVED card, not against the table it is built from.

    A test that checked the table would pass even if build_agent_card dropped
    the tools on the floor, which is what "skills": [] looked like.
    """
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    provisioned = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"}).json()
    card = host.get(f"/t/{provisioned['tenant_id']}/.well-known/agent.json").json()

    skill_ids = {s["id"] for s in card["skills"]}
    assert "skill.booking" in skill_ids, f"the card does not say the tenant takes bookings: {card['skills']}"

    # and the capability it advertises is real
    booked = host.post(
        f"/t/{provisioned['tenant_id']}/book",
        json={"service": "cake", "provider": "Moon Bakery", "datetime": "2026-09-01T10:00:00Z"},
    )
    assert booked.status_code == 200
    assert booked.json()["receipt_id"]


def test_the_agentfacts_url_the_card_advertises_resolves(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The card's x-nanda pointer must not 404.

    build_agent_card advertises <endpoint>/agentfacts.json whenever a did is
    present — always, for a provisioned tenant — and the host did not mount it.
    host39.check_agentfacts_pointer probes this exact URL, so the pointer was
    already being checked while the target did not exist.

    The path is taken FROM the card rather than hardcoded here, so if the
    advertised location moves this follows it instead of testing a stale one.
    """
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    provisioned = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"}).json()
    card = host.get(f"/t/{provisioned['tenant_id']}/.well-known/agent.json").json()

    advertised = card["x-nanda"]["agentfacts_url"]
    assert advertised, "the card advertises no agentfacts_url, so this test proves nothing"
    path = advertised[len("http://smb-host.example") :]

    resp = host.get(path)
    assert resp.status_code == 200, f"the advertised AgentFacts URL {advertised} returned {resp.status_code}"

    facts = resp.json()
    assert facts["id"] == card["x-nanda"]["did"], "AgentFacts describes a different identity than the card"


def test_agentfacts_names_the_capability_instead_of_general_purpose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AgentFacts must not fall back to the placeholder for a tenant that books.

    sm-bridge requires at least one skill, so an agent with none configured got
    "general-purpose agent" — the same defect as "skills": [] one document over,
    and less obvious because the field was not empty.
    """
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    provisioned = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"}).json()
    facts = host.get(f"/t/{provisioned['tenant_id']}/agentfacts.json").json()

    ids = {s["id"] for s in facts["skills"]}
    assert "urn:nanda:skill:general" not in ids, f"AgentFacts still says general-purpose: {ids}"
    assert any("book" in i for i in ids), f"AgentFacts does not name the booking capability: {ids}"


def test_agentfacts_for_an_unknown_tenant_is_404(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The new route must not become a way to probe for tenants that do not
    exist, or to serve a document for one."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    assert host.get("/t/no-such-tenant/agentfacts.json").status_code == 404


# ── the service can be stood up by following its own documentation ───────────
#
# Three defaults made this impossible for a stranger: the package cannot be
# pip-installed, its pyproject claimed it was "deployed from its own image" while
# no image for it existed anywhere in the repository, HOST_PUBLIC_URL defaulted
# to a hardcoded localhost:8080 that tracked neither host nor port, and
# SMB_HOST_DATA_DIR defaulted to /data/smb-tenants and killed the import with
# PermissionError on any normal machine.
#
# These guard the RUN PATH hardest, because that is the part that rotted: a
# comment named a deployment mechanism for weeks and nothing checked it existed.


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def test_the_image_the_pyproject_points_at_exists() -> None:
    """The pyproject names a Dockerfile; assert the file is really there.

    The previous comment said "deployed from its own image" and no image for this
    service existed in the repository, so a reader went looking for a file that
    was not there. A comment cannot be checked, a path can.
    """
    pyproject = (_repo_root() / "smb_host" / "pyproject.toml").read_text()
    assert "infra/Dockerfile.smb-host" in pyproject, (
        "smb_host/pyproject.toml no longer points at the Dockerfile that runs it"
    )
    assert (_repo_root() / "infra" / "Dockerfile.smb-host").is_file(), (
        "infra/Dockerfile.smb-host is missing, so the pyproject points at a file that does not exist"
    )


def test_the_readme_run_commands_name_what_the_code_reads() -> None:
    """Every env var the README documents is one the module actually reads.

    A run page drifts by naming a variable the code stopped using, which fails
    silently — the reader sets it and nothing happens.
    """
    import main as host_main

    readme = (_repo_root() / "smb_host" / "README.md").read_text()
    for env_const in (
        host_main._PUBLIC_URL_ENV,
        host_main._DATA_DIR_ENV,
        host_main._POOL_SIZE_ENV,
        host_main._CORS_ORIGINS_ENV,
        host_main._PROVISION_TOKEN_ENV,
        host_main._TENANT_CAP_ENV,
        host_main._TRUSTED_PROXIES_ENV,
    ):
        assert env_const in readme, f"{env_const} is read by the host but the README does not document it"

    # and the documented way in is a command, not a description of one
    assert "docker build -f infra/Dockerfile.smb-host" in readme
    assert "python -m uvicorn main:app" in readme


def test_provisioning_refuses_when_nobody_said_where_the_host_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No HOST_PUBLIC_URL → 503 naming the variable, not a guessed endpoint.

    The endpoint is what a business hands onward, so issuing a plausible-looking
    wrong one is worse than refusing: it fails later, somewhere else, to someone
    else.
    """
    host = _make_host(tmp_path, monkeypatch, "")  # explicit: operator said nothing

    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"})
    assert resp.status_code == 503, f"provisioned without knowing its own address: {resp.text[:200]}"
    assert "HOST_PUBLIC_URL" in resp.json()["detail"], "the refusal does not name the variable to set"

    # the host is otherwise alive — refusing to provision is not refusing to run
    assert host.get("/health").status_code == 200


def test_the_pool_does_not_mint_tenants_with_an_address_nobody_gave(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refusing at /provision alone would not be enough.

    The warmer mints tenants BEFORE any request arrives and writes them to disk,
    where a later rehydrate picks them up as fully provisioned — so it must not
    run without a public URL either.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "", pool_size=3)
    with _client(mod) as client:
        assert client.get("/health").json()["pool_ready"] == 0

    data_dir = tmp_path / "data"
    minted = [p for p in data_dir.iterdir() if p.is_dir()] if data_dir.exists() else []
    assert not minted, f"the warmer minted {len(minted)} tenant(s) carrying an endpoint nobody supplied"


def test_the_default_data_dir_is_writable_by_an_ordinary_user(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The default must not be a path only one deployment shape can create.

    It was /data/smb-tenants, and create_app() calls mkdir on it at import, so
    importing the module as any normal user raised PermissionError before a
    single route existed.
    """
    import main as host_main

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    resolved = host_main._default_data_dir()

    assert not str(resolved).startswith("/data"), (
        f"the default data dir is {resolved}, which only exists inside a container"
    )
    resolved.mkdir(parents=True, exist_ok=True)  # the assertion: an ordinary user can create it
    assert resolved.is_dir()


def test_an_unwritable_data_dir_says_which_variable_to_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When it genuinely cannot be created, the error must be actionable.

    The bare PermissionError this replaces named neither the variable nor the
    intent, so the fix was not discoverable from the failure.
    """
    import main as host_main

    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory")  # mkdir under a FILE fails on every platform

    monkeypatch.setenv("SMB_HOST_DATA_DIR", str(blocked / "tenants"))
    monkeypatch.setenv("HOST_PUBLIC_URL", "http://smb-host.example")
    with pytest.raises(RuntimeError) as caught:
        host_main.create_app()

    message = str(caught.value)
    assert "SMB_HOST_DATA_DIR" in message, f"the error does not name the variable: {message}"
    assert str(blocked / "tenants") in message, f"the error does not name the path: {message}"


# ── the README's worked example must be the call the route actually accepts ──────
#
# smb_host/README.md said the service "takes bookings that return signed receipts"
# and never showed the call. The obvious payload
# {"customer_name", "service", "when"} is rejected with
# 400 missing required field(s): provider, datetime — the correct field set was
# documented only in smb_funnel/README.md, a different component's page. A reader
# following this page got a 400 and no way to tell whether the service or the page
# was wrong, so the example is asserted against the route rather than reviewed.


def _readme_booking_example() -> tuple[str, dict[str, object]]:
    """Return (request path, JSON body) from the README's booking curl block."""
    readme = (_repo_root() / "smb_host" / "README.md").read_text()

    blocks = [b for b in re.findall(r"```bash\n(.*?)```", readme, re.DOTALL) if "/book" in b]
    assert len(blocks) == 1, f"expected exactly one booking example in the README, found {len(blocks)}"
    command = blocks[0].replace("\\\n", " ")

    path_match = re.search(r"https?://[^\s]+(/t/[^\s]+/book)", command)
    assert path_match, f"the booking example does not POST to a /t/<tenant>/book URL: {command}"

    body_match = re.search(r"-d '(\{.*?\})'", command, re.DOTALL)
    assert body_match, f"the booking example sends no JSON body: {command}"
    body = json.loads(body_match.group(1))
    assert isinstance(body, dict)

    return path_match.group(1), body


def test_the_readme_booking_example_sends_the_fields_the_route_requires() -> None:
    """The example's field set is exactly what POST /t/<tenant>/book validates.

    Checked both ways. A required field the example omits means following the page
    returns 400. A field the example sends that the route does not declare means
    the page names something the service ignores — the same silent failure in the
    other direction.
    """
    import main as host_main

    _, body = _readme_booking_example()

    missing = [f for f in host_main._BOOKING_REQUIRED_FIELDS if not str(body.get(f, "")).strip()]
    assert not missing, (
        f"the README's booking example omits required field(s) {missing}, so following the page returns 400"
    )

    declared = set(host_main.BookRequest.model_fields)
    unknown = sorted(set(body) - declared)
    assert not unknown, f"the README's booking example sends field(s) {unknown} that BookRequest does not declare"


def test_the_readme_booking_example_uses_the_tenant_provisioning_returned() -> None:
    """The book command's tenant id is the one the provision output shows.

    The page is one worked example. If the two ids diverge, the copied command
    404s and the reader cannot tell that the id was the only thing wrong.
    """
    readme = (_repo_root() / "smb_host" / "README.md").read_text()

    provisioned = re.search(r'"tenant_id":\s*"([^"]+)"', readme)
    assert provisioned, "the README no longer shows a tenant_id in the provision response"

    path, _ = _readme_booking_example()
    assert path == f"/t/{provisioned.group(1)}/book", (
        f"the booking example posts to {path}, but provisioning returned {provisioned.group(1)!r}"
    )


def test_the_readme_says_where_registration_happens_and_links_a_file_that_exists() -> None:
    """This host registers on no index, so the page must name who does.

    The reference is linked rather than restated; a link to a moved file is the
    same dead end as no link at all, so the target is asserted to exist.
    """
    readme = (_repo_root() / "smb_host" / "README.md").read_text()

    assert "api.nandaindex.org" in readme, "the README does not name the index the business must be registered at"
    assert "docs/integrations/SMB_NANDA_HANDSHAKE.md" in readme, (
        "the README does not link the handshake spec that says who registers the business"
    )
    assert (_repo_root() / "docs" / "integrations" / "SMB_NANDA_HANDSHAKE.md").is_file(), (
        "docs/integrations/SMB_NANDA_HANDSHAKE.md is missing, so the README links a file that does not exist"
    )


# ── provisioning authority ───────────────────────────────────────────────────────
#
# Measured on origin/main 9b81783 before this gate existed, against a real host on
# a free port: POST /provision with NO Authorization header returned 201, and with
# a deliberately bogus "Authorization: Bearer not-a-real-token" also returned 201 —
# the header was not read at all. Anyone who found the host could mint identities.
#
# The rule these tests pin, in full:
#   token set                  -> bearer required, 401 otherwise
#   token unset + loopback URL -> open (development and CI, unchanged)
#   token unset + other URL    -> 503 naming the variable
# and the pool warmer is gated on the same condition, because it mints BEFORE any
# request arrives.


def test_provisioning_with_the_configured_token_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Branch 1, allowed: the token is set and the caller presents it."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")

    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"})
    assert resp.status_code == 201, f"a correctly authorized provision was refused: {resp.text[:200]}"
    assert resp.json()["did"].startswith("did:key:z")


@pytest.mark.parametrize(
    ("headers", "why"),
    [
        ({}, "no Authorization header at all"),
        ({"Authorization": "Bearer wrong-secret"}, "a wrong secret"),
        ({"Authorization": "Bearer "}, "an empty bearer value"),
        ({"Authorization": _TEST_TOKEN}, "the raw secret with no Bearer scheme"),
        ({"Authorization": f"Basic {_TEST_TOKEN}"}, "the right secret under the wrong scheme"),
        # the prefix case: compare_digest, not startswith
        ({"Authorization": f"Bearer {_TEST_TOKEN[:-1]}"}, "the secret missing its last character"),
        ({"Authorization": f"Bearer {_TEST_TOKEN}x"}, "the secret with one character appended"),
    ],
)
def test_provisioning_without_the_configured_token_is_401(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, headers: dict[str, str], why: str
) -> None:
    """Branch 1, refused: the token is set and the caller does not present it."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example", token="")
    monkeypatch.setenv("SMB_HOST_PROVISION_TOKEN", _TEST_TOKEN)

    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"}, headers=headers)
    assert resp.status_code == 401, f"provisioned with {why}: HTTP {resp.status_code} {resp.text[:200]}"
    assert resp.headers.get("WWW-Authenticate") == "Bearer"

    # and nothing was minted
    data_dir = tmp_path / "data"
    minted = [p for p in data_dir.iterdir() if p.is_dir()] if data_dir.exists() else []
    assert not minted, f"a refused provision still minted {len(minted)} tenant(s)"


def test_an_unset_token_keeps_a_loopback_host_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Branch 2: no token + a loopback address stays open.

    This is the development and CI shape — scripts/demo_smb_stack.sh runs the host
    at http://127.0.0.1:<port> with no secret — and it must keep working unchanged.
    """
    for public_url in ("http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"):
        host = _make_host(tmp_path / public_url.replace(":", "_").replace("/", "_"), monkeypatch, public_url, token="")

        resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"})
        assert resp.status_code == 201, f"{public_url} is loopback but provisioning was refused: {resp.text[:200]}"


def test_an_unset_token_refuses_a_host_that_is_not_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Branch 3: no token + a public address is refused, not left open.

    An operator who has stated a public address and configured no secret has
    described a host that mints identities for strangers. The refusal names the
    variable, the same shape as the HOST_PUBLIC_URL 503.
    """
    host = _make_host(tmp_path, monkeypatch, "https://smb.example.com", token="")

    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"})
    assert resp.status_code == 503, f"an un-gated public host provisioned: HTTP {resp.status_code}"
    detail = resp.json()["detail"]
    assert "SMB_HOST_PROVISION_TOKEN" in detail, f"the refusal does not name the variable to set: {detail}"

    # refusing to provision is not refusing to run
    assert host.get("/health").status_code == 200


def test_a_host_that_only_looks_like_loopback_is_not_treated_as_loopback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The loopback test is on the parsed host, not a substring of the URL.

    "http://127.0.0.1.attacker.example/" contains "127.0.0.1" and resolves
    wherever its owner points it.
    """
    for public_url in (
        "http://127.0.0.1.attacker.example",
        "http://localhost.attacker.example",
        "http://not-localhost",
    ):
        host = _make_host(tmp_path / public_url.replace(":", "_").replace("/", "_"), monkeypatch, public_url, token="")
        resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"})
        assert resp.status_code == 503, f"{public_url} was treated as loopback and left open"


def test_the_warmer_follows_the_same_rule_as_the_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The warmer mints before any request arrives, so gating the route is not enough.

    Same argument as the HOST_PUBLIC_URL case: a pre-warmed tenant is written to
    disk and a later rehydrate picks it up as fully provisioned, so a host that
    refuses every request would still have produced identities.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "https://smb.example.com", pool_size=3, token="")
    with _client(mod, token="") as client:
        assert client.get("/health").json()["pool_ready"] == 0

    data_dir = tmp_path / "data"
    minted = [p for p in data_dir.iterdir() if p.is_dir()] if data_dir.exists() else []
    assert not minted, f"the warmer minted {len(minted)} tenant(s) on an un-gated public host"


def test_the_warmer_still_runs_on_a_gated_public_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The counterpart: the gate must not disable the pool on a correct deployment."""
    mod = _build_host_module(tmp_path, monkeypatch, "https://smb.example.com", pool_size=2)
    with _client(mod) as client:
        _wait_for_pool(client, 2)
        assert client.get("/health").json()["pool_ready"] == 2


# ── a restart does not strand pool slots, and never touches a claimed home ──────
#
# _load_tenant_from_home deliberately never re-enqueues a rehydrated pool tenant:
# its one-time recovery phrase is unrecoverable, so handing it to a claim would
# return an empty phrase — a silent downgrade of the one secret that recovers the
# business's key. The consequence was that every boot stranded the previous
# boot's un-claimed slots and the warmer minted a fresh set beside them. The
# warmer now re-keys a stranded slot in place before it mints anything new.


def _homes_on_disk(tmp_path: Path) -> set[str]:
    data = tmp_path / "data"
    return {p.name for p in data.iterdir() if p.is_dir()} if data.is_dir() else set()


def _dids(mod: ModuleType) -> dict[str, str]:
    return {t.tenant_id: t.did for t in mod.app.state.host.tenants.values()}


def test_tenant_count_is_stable_across_five_boots_with_no_provisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE GUARD (G2), and the regression test for the whole defect.

    Measured on this code before the reclaim existed, five boots at
    SMB_HOST_POOL_SIZE=3 and no provision at all: 3, 6, 9, 12, 15. Each boot's
    warmer minted three fresh homes because the queue starts empty and the
    previous boot's un-claimed slots were unreachable. The deployed host reached
    83 tenants the same way — 26 of its 58 container boots ran the warmer, which
    accounts for 78 of them; the other 5 are the only provisions it has served.

    A host that reclaims must give the SAME number five times.
    """
    public_url = "https://smb.example.com"
    counts = []
    for _ in range(5):
        mod = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=3)
        with _client(mod) as client:
            _wait_for_pool(client, 3)
            body = client.get("/health").json()
            counts.append(body["tenants"])
            assert body["pool_reclaimable"] == 0, f"the warmer left a slot stranded after filling: {body}"

    assert counts == [3, 3, 3, 3, 3], f"tenant count grew across boots with zero provisions: {counts}"
    assert len(_homes_on_disk(tmp_path)) == 3, "homes accumulated on disk even though the count reported stable"


def test_a_claimed_tenant_survives_a_boot_that_rekeys_the_slots_beside_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE GUARD (G1), and the one that matters most.

    Re-keying replaces the Ed25519 seed in a tenant's vault. On an un-claimed
    slot that costs nothing — nobody has ever seen its phrase. On a claimed
    tenant it destroys a business's signing identity, recoverable only from a
    phrase its owner saw once. So this boots a host holding BOTH, lets the
    warmer re-key every un-claimed home beside the claimed one, and asserts the
    claimed one came through untouched: same did:key, same business name, still
    serving its card, still signing.

    The un-claimed slots are asserted to have actually changed key in the same
    run, so this cannot pass on a host that simply reclaimed nothing.
    """
    public_url = "http://smb-host.example"
    mod = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=3)
    with _client(mod) as client:
        _wait_for_pool(client, 3)
        resp = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Corner Bakery"})
        assert resp.status_code == 201, resp.text
        claimed_id = resp.json()["tenant_id"]
        claimed_did = resp.json()["did"]
        _wait_for_pool(client, 3)  # the warmer refills the slot that was taken
        before = _dids(mod)
        # Checked HERE as well as after the restart: the invariant is that a
        # claimed tenant is never re-keyed, not that it survives a restart in
        # particular. A warmer that treats a pool-shaped id as a pool slot
        # destroys this tenant on the very tick that refills the pool, before
        # any restart is involved.
        assert before[claimed_id] == claimed_did, (
            f"the warmer re-keyed a tenant that had just been claimed: {claimed_did} -> {before[claimed_id]}"
        )
    stranded_before = {tid: did for tid, did in before.items() if tid != claimed_id}
    assert len(stranded_before) >= 3, f"expected un-claimed slots beside the claimed tenant: {before}"

    # Restart over the same data dir: the warmer now re-keys the stranded slots.
    mod2 = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=3)
    with _client(mod2) as client:
        _wait_for_pool(client, 3)
        after = _dids(mod2)

        # THE CLAIMED TENANT IS UNTOUCHED.
        assert after[claimed_id] == claimed_did, (
            f"the claimed tenant was re-keyed: {claimed_did} -> {after[claimed_id]}. "
            f"Its business cannot recover from this."
        )
        card = client.get(f"/t/{claimed_id}/.well-known/agent.json")
        assert card.status_code == 200, card.text
        assert card.json()["name"] == "Corner Bakery"
        assert card.json()["authentication"]["credentials"] == claimed_did
        meta = _meta(tmp_path, claimed_id)
        assert meta["claimed"] is True and meta["business_name"] == "Corner Bakery"
        assert meta["provisioned_by"], "the claimed tenant lost its attribution"

        # AND THE STRANDED SLOTS REALLY WERE RE-KEYED — otherwise the assertion
        # above would hold on a host that reclaimed nothing at all.
        rekeyed = [tid for tid, did in stranded_before.items() if after.get(tid) not in (None, did)]
        assert rekeyed, f"no stranded slot was re-keyed, so this proves nothing about the claimed one: {after}"


def test_a_tenant_with_no_attribution_recorded_is_not_treated_as_an_unclaimed_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE GUARD (G3). A tenant provisioned before attribution existed carries
    no provisioned_at/provisioned_by key at all — the same two fields an
    un-claimed pool slot lacks. It is a real business and must never be re-keyed
    on that resemblance.

    Built as the oldest shape this host can hold: no attribution keys, and no
    contact either (that field is younger than the tenants on the deployed
    volume). What keeps it safe is the positive property — `claimed` is true —
    and the reclaim predicate requires several of those together.
    """
    public_url = "http://smb-host.example"
    host = _make_host(tmp_path, monkeypatch, public_url)
    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Legacy Co"})
    assert resp.status_code == 201, resp.text
    legacy_id, legacy_did = resp.json()["tenant_id"], resp.json()["did"]

    meta_path = tmp_path / "data" / legacy_id / "smb_tenant.json"
    meta = json.loads(meta_path.read_text())
    del meta["provisioned_at"], meta["provisioned_by"]
    meta["contact"] = ""
    meta_path.write_text(json.dumps(meta))

    mod = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=2)
    with _client(mod) as client:
        _wait_for_pool(client, 2)
        health = client.get("/health").json()
        assert health["pool_reclaimable"] == 0
        assert _dids(mod)[legacy_id] == legacy_did, "a tenant with no attribution recorded was re-keyed as a pool slot"
        card = client.get(f"/t/{legacy_id}/.well-known/agent.json")
        assert card.status_code == 200 and card.json()["name"] == "Legacy Co"


def test_a_reclaimed_slot_hands_out_a_phrase_that_recovers_its_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reason a rehydrated slot could not simply be re-enqueued.

    Its phrase is generated at mint and returned only at claim, so a slot that
    survived a restart no longer has one — enqueueing it would hand a business
    an empty string in the field that is the sole means of recovering its key.
    Re-keying is what makes the slot usable again, and this asserts the property
    that makes it correct: the phrase returned for a RECLAIMED slot really does
    derive the did:key that slot now serves.
    """
    public_url = "http://smb-host.example"
    mod = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=1)
    with _client(mod) as client:
        _wait_for_pool(client, 1)
    stranded = _homes_on_disk(tmp_path)
    assert len(stranded) == 1

    mod2 = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=1)
    with _client(mod2) as client:
        _wait_for_pool(client, 1)
        resp = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Reclaimed Co"})
        assert resp.status_code == 201, resp.text

    body = resp.json()
    assert body["tenant_id"] in stranded, "the claim was served by a fresh mint, not the reclaimed slot"
    assert len(body["recovery_phrase"].split()) == 24, "a reclaimed slot handed out no usable phrase"

    from community_member import recovery

    assert recovery.recover_from_mnemonic(body["recovery_phrase"]).did_key == body["did"], (
        "the phrase handed to the business does not recover the key its agent signs with"
    )


def test_a_reclaimed_slot_is_not_rekeyed_again_on_the_next_tick(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reclaimed slot still looks un-claimed — it IS un-claimed, that is the
    point of a pool. What stops the warmer re-keying it forever is that it is in
    the queue. Without that condition the loop churns identities on every tick,
    and the card a caller resolved a second ago stops matching its did."""
    public_url = "http://smb-host.example"
    mod = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=2)
    with _client(mod) as client:
        _wait_for_pool(client, 2)
    mod2 = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=2)
    with _client(mod2) as client:
        _wait_for_pool(client, 2)
        settled = _dids(mod2)
        # several warmer ticks — the backstop poll is 2.0s, and a wake is not
        # needed for the loop to re-enter its inner while
        time.sleep(_POOL_SETTLE_S)
        assert _dids(mod2) == settled, "the warmer re-keyed a slot it had already made ready"
        assert client.get("/health").json()["pool_ready"] == 2, "the pool grew past its target on repeat ticks"


def test_a_host_at_its_cap_still_reclaims_its_stranded_slots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The capacity check gates MINTING, not reclaiming, and the difference is
    load-bearing: re-keying an existing home creates no new home and moves the
    count by nothing. A host sitting at its cap with stranded slots must still
    be able to make them usable, or it stays permanently unable to serve anyone
    while holding homes nobody can reach."""
    public_url = "http://smb-host.example"
    mod = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=2, tenant_cap="2")
    with _client(mod) as client:
        _wait_for_pool(client, 2)
        assert client.get("/health").json()["at_capacity"] is True

    # Restart at the same cap: no headroom to mint, but two homes to reclaim.
    mod2 = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=2, tenant_cap="2")
    with _client(mod2) as client:
        _wait_for_pool(client, 2)
        body = client.get("/health").json()
        assert body["tenants"] == 2 and body["pool_ready"] == 2, f"a full host did not reclaim its own slots: {body}"
        assert (
            client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Full House Co"}).status_code
            == 201
        ), "a reclaimed slot at cap could not be claimed"


# ── provisioning is attributable, and its headroom is observable ────────────────


def _meta(tmp_path: Path, tenant_id: str) -> dict[str, object]:
    return json.loads((tmp_path / "data" / tenant_id / "smb_tenant.json").read_text())


def test_a_cold_provision_records_who_when_and_from_where(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """HAPPY: a provision on the cold path is attributed, not just minted."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Corner Bakery"})
    assert resp.status_code == 201, resp.text

    meta = _meta(tmp_path, resp.json()["tenant_id"])
    assert meta["provisioned_by"], "the cold path recorded no attribution at all"
    assert meta["provisioned_by"] != "unattributable", "TestClient supplies a real client host; this should resolve"
    assert meta["provisioned_at"], "the cold path recorded no timestamp"


def test_a_pool_claim_records_who_when_and_from_where(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """HAPPY: attribution is recorded at the CLAIM, not at the warmer's mint —
    the warmer's own pre-mint is never attributable to an external caller."""
    public_url = "http://smb-host.example"
    mod = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=2)
    with _client(mod) as client:
        _wait_for_pool(client, 2)
        resp = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"})
        assert resp.status_code == 201, resp.text

    meta = _meta(tmp_path, resp.json()["tenant_id"])
    assert meta["provisioned_by"], "a pool claim recorded no attribution"
    assert meta["provisioned_at"], "a pool claim recorded no timestamp"


def test_an_unattributable_provision_is_recorded_as_unattributable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE GUARD (G1). When no usable caller signal exists, the record must say
    so BY NAME rather than carry a fabricated default. Proven by forcing the
    discriminator to resolve to nothing, the one condition an unusable signal
    (an unreachable socket peer, no trusted proxy configured) actually produces."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    import main as host_main

    monkeypatch.setattr(host_main, "_caller_discriminator", lambda request, trusted_proxies: "")

    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "No Signal Co"})
    assert resp.status_code == 201, resp.text

    meta = _meta(tmp_path, resp.json()["tenant_id"])
    assert meta["provisioned_by"] == "unattributable", (
        f"an unusable signal was defaulted to {meta['provisioned_by']!r} instead of being named"
    )


def test_an_unconfigured_trust_setting_does_not_trust_a_caller_supplied_forwarded_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE GUARD: on the DEFAULT configuration (SMB_HOST_TRUSTED_PROXIES
    unset), X-Forwarded-For is client-supplied and must NOT be trusted.
    Recording it anyway would let a caller choose the value this host later
    treats as an observed fact — the record overstating what it knows, the
    same failure class G1 guards against for a missing signal, here for a
    forged one instead."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    monkeypatch.delenv("SMB_HOST_TRUSTED_PROXIES", raising=False)

    resp = host.post(
        "/provision",
        json={"contact": _TEST_CONTACT, "business_name": "Forged Header Co"},
        headers={"X-Forwarded-For": "203.0.113.9"},
    )
    assert resp.status_code == 201, resp.text

    meta = _meta(tmp_path, resp.json()["tenant_id"])
    assert meta["provisioned_by"] != "203.0.113.9", (
        "the default configuration trusted a caller-supplied X-Forwarded-For header"
    )


def test_an_explicitly_trusted_proxy_hop_is_honoured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The opt-in direction, pinned alongside the default above so "fixing" the
    default into trusting X-Forwarded-For cannot pass without this test
    noticing the opposite guarantee break."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    monkeypatch.setenv("SMB_HOST_TRUSTED_PROXIES", "1")

    resp = host.post(
        "/provision",
        json={"contact": _TEST_CONTACT, "business_name": "Trusted Proxy Co"},
        headers={"X-Forwarded-For": "203.0.113.9"},
    )
    assert resp.status_code == 201, resp.text

    meta = _meta(tmp_path, resp.json()["tenant_id"])
    assert meta["provisioned_by"] == "203.0.113.9", (
        "an operator who configured a trusted proxy hop did not get the forwarded address recorded"
    )


def test_a_tenant_provisioned_before_attribution_existed_rehydrates_as_unrecorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 68 pre-existing tenants have no provisioned_at/provisioned_by key at
    all. That must rehydrate as "not recorded" (None), never backfilled with a
    guess and never conflated with the "unattributable" sentinel, which means
    something different: attribution was attempted and failed."""
    public_url = "http://smb-host.example"
    host = _make_host(tmp_path, monkeypatch, public_url)
    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Legacy Co"})
    tenant_id = resp.json()["tenant_id"]

    # Simulate a pre-existing tenant: strip the keys this feature added.
    meta_path = tmp_path / "data" / tenant_id / "smb_tenant.json"
    meta = json.loads(meta_path.read_text())
    del meta["provisioned_at"], meta["provisioned_by"]
    meta_path.write_text(json.dumps(meta))

    # Simulate a restart: a brand-new app instance over the SAME data dir.
    host2 = _make_host(tmp_path, monkeypatch, public_url)
    card = host2.get(f"/t/{tenant_id}/.well-known/agent.json")
    assert card.status_code == 200, "the legacy tenant failed to rehydrate at all"

    import main as host_main  # already reloaded by the _make_host call above

    tenant = host_main.app.state.host.tenants[tenant_id]
    assert tenant.provisioned_at is None
    assert tenant.provisioned_by is None


# ── the attribution record is readable, authenticated, and un-conflated ─────────
#
# Recording a provision landed without a reader: /health, the two well-known
# tenant reads and /t/{id}/book serve no attribution, so the host held the answer
# to "who provisioned these 83" and could only be asked by shelling into its
# volume. These cover the read half.


def _summary(client: TestClient) -> dict[str, object]:
    resp = client.get("/provisions/summary")
    assert resp.status_code == 200, resp.text
    body: dict[str, object] = resp.json()
    return body


def _assert_accounting_holds(body: dict[str, object]) -> None:
    """Both identities the summary promises, checked on every response that
    reaches an assertion below. A bucket that silently absorbs another still
    satisfies most single-bucket assertions; a total that no longer adds up
    does not."""
    recorded = body["recorded"]
    assert isinstance(recorded, list)
    counted = sum(int(r["count"]) for r in recorded)
    assert body["tenants"] == int(body["claimed"]) + int(body["unclaimed_pool_slots"]), (
        f"tenants != claimed + unclaimed_pool_slots: {body}"
    )
    assert body["claimed"] == counted + int(body["unattributable"]) + int(body["unrecorded"]), (
        f"claimed != recorded + unattributable + unrecorded: {body}"
    )


def test_the_attribution_read_refuses_an_unauthenticated_caller_on_the_default_pool_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE GUARD (G1). The refusal must run on the configuration this host
    actually serves.

    That is the duplicate-name rule restated: those checks were written for
    the cold path only, and SMB_HOST_POOL_SIZE defaults to 3, so on the shape
    operators run the checks were absent. So this drives the DEFAULT
    pool-enabled host — warmer started, pool filled — rather than the
    pool-disabled one most tests here use, and asserts the refusal is reached
    there.

    An attribution listing is a better enumeration surface than the duplicate
    name 409, which stopped naming an existing tenant's id to an anonymous
    caller, so it is gated on the same credential provisioning is. The 401 body must not vary either: an
    empty host and a busy one produce byte-identical refusals, so the refusal
    itself cannot be used to measure the host.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "https://smb.example.com", pool_size=3)
    with _client(mod) as client:
        _wait_for_pool(client, 3)

        anonymous = TestClient(mod.app)  # no Authorization header at all
        missing = anonymous.get("/provisions/summary")
        wrong = anonymous.get("/provisions/summary", headers={"Authorization": "Bearer nope"})
        wrong_scheme = anonymous.get("/provisions/summary", headers={"Authorization": f"Basic {_TEST_TOKEN}"})

        for label, resp in {
            "no header": missing,
            "wrong secret": wrong,
            "wrong scheme": wrong_scheme,
        }.items():
            assert resp.status_code == 401, f"{label} read the attribution record: HTTP {resp.status_code}"
        bodies = {resp.text for resp in (missing, wrong, wrong_scheme)}
        assert len(bodies) == 1, f"the 401 body varies with the credential supplied: {bodies}"

        # and the authorized caller is actually served — otherwise this test
        # would pass on a route that refuses everyone, including the operator.
        _assert_accounting_holds(_summary(client))


def test_the_attribution_read_answers_while_provisioning_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deployed host has SMB_HOST_TENANT_CAP unset, so POST /provision
    answers 503 and the warmer never starts. That is the state this endpoint
    exists to explain, so it must not be gated on the same configuration check —
    a diagnostic that refuses in the configuration it diagnoses is not one."""
    host = _make_host(tmp_path, monkeypatch, "https://smb.example.com", tenant_cap="1000")
    assert host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Before Co"}).status_code == 201

    monkeypatch.setenv("SMB_HOST_TENANT_CAP", "")
    assert host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "After Co"}).status_code == 503

    body = _summary(host)
    assert body["claimed"] == 1
    _assert_accounting_holds(body)


def test_unrecorded_and_unattributable_are_distinguishable_at_the_wire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE GUARD (G2). Three states of one field, three buckets.

    ``unrecorded`` is a tenant provisioned before the field existed: no
    provisioned_by key at all, nothing ever attempted. ``unattributable`` is a
    provision that WAS attributed and whose caller signal did not resolve. They
    mean different things — the first is a gap in the record, the second is a
    fact in it — and neither may be backfilled with the other.
    """
    public_url = "http://smb-host.example"
    host = _make_host(tmp_path, monkeypatch, public_url)
    import main as host_main

    assert host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Recorded Co"}).status_code == 201
    legacy = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Legacy Co"})
    assert legacy.status_code == 201

    monkeypatch.setattr(host_main, "_caller_discriminator", lambda request, trusted_proxies: "")
    assert host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "No Signal Co"}).status_code == 201

    # Make "Legacy Co" a legacy tenant: strip the keys the feature added.
    meta_path = tmp_path / "data" / legacy.json()["tenant_id"] / "smb_tenant.json"
    meta = json.loads(meta_path.read_text())
    del meta["provisioned_at"], meta["provisioned_by"]
    meta_path.write_text(json.dumps(meta))

    restarted = _make_host(tmp_path, monkeypatch, public_url)  # reload over the same data dir
    body = _summary(restarted)

    _assert_accounting_holds(body)
    assert body["tenants"] == 3
    assert body["claimed"] == 3
    assert body["unclaimed_pool_slots"] == 0
    assert body["unrecorded"] == 1, f"the legacy tenant was not reported as unrecorded: {body}"
    assert body["unattributable"] == 1, f"the unresolved-signal tenant was not reported by name: {body}"
    recorded = body["recorded"]
    assert isinstance(recorded, list) and len(recorded) == 1, body
    assert recorded[0]["count"] == 1
    assert recorded[0]["source"] not in ("", "unattributable"), recorded


@pytest.mark.parametrize("state", ["unrecorded", "unattributable"])
def test_neither_missing_attribution_bucket_absorbs_the_other(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    """⚠️ THE GUARD (G2), the half a summed implementation would still pass.

    A host holding ONLY one of the two states must report zero of the other. An
    implementation that adds them together, or that defaults a missing
    provisioned_by to the sentinel, satisfies "both keys are present" and fails
    here.
    """
    public_url = "http://smb-host.example"
    host = _make_host(tmp_path, monkeypatch, public_url)
    import main as host_main

    if state == "unattributable":
        monkeypatch.setattr(host_main, "_caller_discriminator", lambda request, trusted_proxies: "")

    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Only Co"})
    assert resp.status_code == 201, resp.text

    if state == "unrecorded":
        meta_path = tmp_path / "data" / resp.json()["tenant_id"] / "smb_tenant.json"
        meta = json.loads(meta_path.read_text())
        del meta["provisioned_at"], meta["provisioned_by"]
        meta_path.write_text(json.dumps(meta))

    body = _summary(_make_host(tmp_path, monkeypatch, public_url))
    _assert_accounting_holds(body)
    other = "unattributable" if state == "unrecorded" else "unrecorded"
    assert body[state] == 1, f"the {state} tenant was not reported as {state}: {body}"
    assert body[other] == 0, f"the {state} tenant was also counted as {other}: {body}"


def test_pool_slots_surviving_a_restart_are_reported_as_unprovisioned_not_as_unrecorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE GUARD (G3). A pool slot is the host's own output, not demand.

    ``_load_tenant_from_home`` never re-enqueues a rehydrated pool tenant
    directly — its one-time recovery phrase is unrecoverable, so it cannot be
    handed to a claim. Before the warmer learned to reclaim, that meant every
    restart stranded the previous boot's unclaimed slots and minted
    ``SMB_HOST_POOL_SIZE`` fresh ones beside them, and the tenant count rose by
    the pool size per boot with ZERO provisions. That was the measured
    explanation of the deployed host reaching 83 tenants on 5 lifetime
    provisions.

    The warmer now re-keys a surviving slot in place and puts it back in the
    pool, so the count is stable across restarts — asserted here from the
    summary endpoint's own view rather than from ``/health``, because these are
    the numbers an operator reads to answer "how many businesses".

    The assertion that matters is still the CLASSIFICATION, and it is
    independent of whether the slot was reclaimed or freshly minted. These
    tenants are not provisions with missing attribution — nobody provisioned
    them and nobody holds them. Counting them under ``unrecorded`` would report
    the host's own warmer output as unattributed demand, which is the exact
    reading that turned pool slots into "businesses signed up".
    """
    public_url = "https://smb.example.com"
    for _ in range(2):
        mod = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=3)
        with _client(mod) as client:
            _wait_for_pool(client, 3)

    body = _summary(client)
    _assert_accounting_holds(body)
    assert body["tenants"] == 3, f"a restart minted beside the surviving slots instead of reclaiming them: {body}"
    assert body["unclaimed_pool_slots"] == 3, f"surviving pool slots were not reported as unclaimed: {body}"
    assert body["claimed"] == 0
    assert body["unrecorded"] == 0, f"warmer output was reported as provisions with missing attribution: {body}"
    assert body["unattributable"] == 0, body
    assert body["recorded"] == []


def test_the_summary_answers_who_and_when_without_naming_a_tenant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The question is a distribution — how many provisions from where, and when
    — so the answer is an aggregate. Per-tenant would answer it too and would
    additionally hand its reader every tenant_id on the host, rebuilding the
    enumeration surface removed from the anonymous 409 when it stopped naming
    an existing tenant's id. A bearer does not make that safe to rebuild: the same leaked token then yields the roster as
    well as the ability to mint."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example", tenant_cap="10")
    names = ["Corner Bakery", "Sharp Cuts", "Moon Cafe"]
    for name in names:
        assert host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": name}).status_code == 201

    resp = host.get("/provisions/summary")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    _assert_accounting_holds(body)

    # one caller, three provisions, a window rather than a single instant
    assert len(body["recorded"]) == 1, body
    entry = body["recorded"][0]
    assert entry["count"] == 3
    assert entry["first_provisioned_at"] <= entry["last_provisioned_at"]

    raw = resp.text
    for name in names:
        assert name not in raw, f"the summary named a business: {name}"
        assert _slug_of(name) not in raw, f"the summary named a tenant_id: {_slug_of(name)}"


def _slug_of(business_name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", business_name.strip().lower()).strip("-")


@pytest.mark.parametrize("bad", ["", "   ", "0", "-4", "many"])
def test_unset_or_unusable_tenant_cap_refuses_provisioning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """⚠️ THE GUARD (G2). A cap that is unset, empty or unparsable is not a
    permissive default — it stops provisioning, the same rule smb_signup already
    enforces for its own cap. No loopback carve-out: this bounds identities
    minted and vaults written with no delete route, which is a resource concern
    regardless of who can reach the port."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    monkeypatch.setenv("SMB_HOST_TENANT_CAP", bad)

    resp = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Unbounded Co"})
    assert resp.status_code == 503, f"an unconfigured cap served a provision: {resp.text[:200]}"
    assert "SMB_HOST_TENANT_CAP" in resp.json()["detail"]

    # refusing to provision is not refusing to run
    assert host.get("/health").status_code == 200


def test_an_unconfigured_cap_also_stops_the_warmer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Same argument as the HOST_PUBLIC_URL/token case: the warmer mints before
    any request arrives, so gating the route alone is not enough."""
    mod = _build_host_module(tmp_path, monkeypatch, "https://smb.example.com", pool_size=3, tenant_cap="")
    with _client(mod) as client:
        assert client.get("/health").json()["pool_ready"] == 0

    data_dir = tmp_path / "data"
    minted = [p for p in data_dir.iterdir() if p.is_dir()] if data_dir.exists() else []
    assert not minted, f"the warmer minted {len(minted)} tenant(s) with no cap configured"


def test_headroom_is_observable_on_health(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Total capacity and remaining headroom sit beside tenants/pool_ready, so
    exhaustion is visible before a business is turned away."""
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example", tenant_cap="5")
    body = host.get("/health").json()
    assert body["tenant_cap"] == 5
    assert body["headroom"] == 5
    assert body["at_capacity"] is False

    host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Headroom Co"})
    body = host.get("/health").json()
    assert body["tenants"] == 1
    assert body["headroom"] == 4
    assert body["at_capacity"] is False


def test_at_capacity_refuses_507_on_the_default_pool_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠️ THE GUARD (G3): a check written only for the cold path is not a check
    on the configuration this host actually serves by default
    (SMB_HOST_POOL_SIZE=3, where most requests are served by claiming an
    already-minted pool tenant rather than minting one). This drives the
    DEFAULT pool-enabled configuration to its cap and confirms the request
    path itself refuses — not just the warmer — with a status distinguishable
    from the 503 an unconfigured cap produces."""
    public_url = "http://smb-host.example"
    mod = _build_host_module(tmp_path, monkeypatch, public_url, pool_size=3, tenant_cap="2")
    with _client(mod) as client:
        # The warmer wants 3 ready tenants but the cap is 2: it can only ever
        # reach 2, which is itself part of what this test proves.
        _wait_for_pool(client, 2)
        time.sleep(0.3)  # let the warmer's next tick observe capacity and stop
        assert client.get("/health").json()["pool_ready"] == 2

        first = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "First Co"})
        second = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Second Co"})
        assert first.status_code == 201 and second.status_code == 201

        # Both pool slots are now claimed and the warmer cannot replenish
        # (already at cap) — the THIRD request must fall to the cold path and
        # be refused there, on the default pool-enabled configuration.
        third = client.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Third Co"})
        assert third.status_code == 507, f"a full host did not refuse distinctly: {third.text[:200]}"
        assert "2 of 2" in third.json()["detail"]

        health = client.get("/health").json()
        assert health["at_capacity"] is True
        assert health["headroom"] == 0


def test_unconfigured_and_at_capacity_are_different_refusals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """They need different advice: one is an operator omission, the other is
    real demand outrunning a real limit. Collapsing them into one status would
    tell an operator to set a variable that is already set."""
    unconfigured = _make_host(tmp_path / "a", monkeypatch, "http://smb-host.example", tenant_cap="")
    a = unconfigured.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "A Co"})

    full = _make_host(tmp_path / "b", monkeypatch, "http://smb-host.example", tenant_cap="1")
    full.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Filled Co"})
    b = full.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Second Co"})

    assert a.status_code == 503
    assert b.status_code == 507
    assert a.status_code != b.status_code
    assert a.json()["detail"] != b.json()["detail"]


def test_the_401_is_reached_without_reading_the_business_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The refusal must not be an enumeration oracle.

    The cold path answers an already-taken name with 409 naming the tenant_id. If
    the body were validated before authority, an unauthenticated caller could
    tell "taken" from "free" by the status code. The gate is a route dependency,
    which FastAPI resolves before body parameters, so the name is never read: the
    401 is byte-identical for a free name, a taken name, and a body that is not
    valid against ProvisionRequest at all.
    """
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    assert host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Corner Bakery"}).status_code == 201
    # confirm the oracle exists for an AUTHORIZED caller — otherwise this test
    # would pass on a host that had simply stopped detecting collisions
    assert host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Corner Bakery"}).status_code == 409

    refusals = {
        label: host.post("/provision", json=body, headers={"Authorization": "Bearer wrong"})
        for label, body in {
            "name already taken": {"business_name": "Corner Bakery"},
            "name free": {"business_name": "Never Provisioned Ltd"},
            "name empty (invalid under ProvisionRequest)": {"business_name": ""},
            "no business_name field at all": {"other": "field"},
        }.items()
    }
    for label, resp in refusals.items():
        assert resp.status_code == 401, f"{label} produced HTTP {resp.status_code}, not 401"
    bodies = {resp.text for resp in refusals.values()}
    assert len(bodies) == 1, f"the 401 body varies with the request body, which makes it an oracle: {bodies}"


def test_the_token_never_reaches_a_log_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The value is the whole control, so it must not be written anywhere readable.

    Covers the paths that see it: a successful provision, a refused one, and the
    warmer's refusal message (built from the configured state, which is where a
    "helpful" diagnostic would most plausibly interpolate it).
    """
    secret = secrets.token_urlsafe(32)

    with caplog.at_level(logging.DEBUG):
        host = _make_host(tmp_path / "gated", monkeypatch, "https://smb.example.com", token=secret)
        assert (
            host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"}).status_code == 201
        )
        assert (
            host.post(
                "/provision",
                json={"contact": _TEST_CONTACT, "business_name": "Sun Cafe"},
                headers={"Authorization": "Bearer nope"},
            ).status_code
            == 401
        )

        mod = _build_host_module(tmp_path / "ungated", monkeypatch, "https://smb.example.com", pool_size=3, token="")
        with _client(mod, token="") as client:
            client.get("/health")

    for record in caplog.records:
        rendered = record.getMessage()
        assert secret not in rendered, f"the token was logged by {record.name}: {rendered}"
        assert secret not in str(record.args), f"the token is a log record argument on {record.name}"
    # and it is not in the refusals the caller sees either
    refusal = host.post(
        "/provision",
        json={"contact": _TEST_CONTACT, "business_name": "Sun Cafe"},
        headers={"Authorization": "Bearer nope"},
    )
    assert secret not in refusal.text, "the 401 body echoes the configured token"


def test_the_readme_documents_the_provisioning_token() -> None:
    """The gate is only usable if the page names the variable and shows the header."""
    import main as host_main

    readme = (_repo_root() / "smb_host" / "README.md").read_text()

    # the variable itself is covered by the env-coverage guard above; what that
    # one cannot see is whether the page says how to SEND it, which is the part a
    # reader needs and the part that has no other source.
    assert "Authorization: Bearer" in readme, "the README does not show how to send the token"
    blocks = [b for b in re.findall(r"```bash\n(.*?)```", readme, re.DOTALL) if "/provision" in b]
    assert any("Authorization: Bearer" in b for b in blocks), (
        "no runnable provisioning example on the page sends the bearer token"
    )
    assert host_main._PROVISION_TOKEN_ENV in readme


# ── the image must stay buildable on the platform it is deployed to ─────────────
#
# infra/Dockerfile.smb-host carried `VOLUME ["/data"]` and the deploy platform
# rejects the directive outright — "dockerfile invalid: docker VOLUME at Line 37
# is not supported, use Railway Volumes" — so the image did not build and the
# service could not be deployed at all. The constraint is recorded nowhere the
# build can see, which is exactly how it comes back: re-adding the line is a
# one-word edit whose failure surfaces on a later, unrelated deploy.


def test_the_dockerfile_carries_no_volume_directive() -> None:
    """A VOLUME directive makes this image unbuildable on the deploy platform.

    Persistence in the deployed shape comes from a platform volume attached at
    /data, not from this directive. For a plain `docker run` the directive gave
    an ANONYMOUS volume, which measurably is not a safety net: a redeploy
    (docker rm + docker run) attaches a NEW anonymous volume, so the tenants
    provisioned before it 404, while the old volume survives holding every
    tenant's encrypted key, referenced by nothing and findable only by hash.
    """
    dockerfile = (_repo_root() / "infra" / "Dockerfile.smb-host").read_text()

    offenders = [
        f"{n}: {line.strip()}"
        for n, line in enumerate(dockerfile.splitlines(), start=1)
        if line.strip().upper().startswith("VOLUME")
    ]
    assert not offenders, (
        "infra/Dockerfile.smb-host declares a VOLUME directive, which the deploy platform "
        f"refuses to build ('docker VOLUME ... is not supported, use Railway Volumes'): {offenders}. "
        "Mount the data directory at run time instead — the README's docker run command does."
    )


def test_the_readme_docker_command_mounts_the_data_dir() -> None:
    """With no VOLUME directive, the -v in the documented command is the whole thing.

    Without it the container writes tenant homes into its own filesystem layer and
    every provisioned business is destroyed by the next deploy, with nothing
    recoverable — this host never stores a recovery phrase. That used to be
    partially covered by the image declaring a volume; now it is covered by this
    one flag in one command on one page, so it is asserted rather than trusted.
    """
    readme = (_repo_root() / "smb_host" / "README.md").read_text()

    blocks = [b for b in re.findall(r"```bash\n(.*?)```", readme, re.DOTALL) if "docker run" in b]
    assert blocks, "the README no longer shows a docker run command"

    mounted = [b for b in blocks if re.search(r"-v\s+\S+:/data(\s|\\|$)", b)]
    assert mounted, (
        "no docker run command in smb_host/README.md mounts anything at /data. The image "
        "declares no VOLUME (the deploy platform rejects it), so without -v the container "
        "writes tenant homes into its own layer and the next deploy destroys every "
        f"provisioned business. Commands found: {blocks}"
    )


def test_the_dockerfile_and_the_readme_agree_on_the_container_data_path() -> None:
    """The mount point in the README must be the path the image actually writes to.

    A -v onto the wrong directory looks correct and persists nothing: the
    container would still write tenant homes into its own layer, and the failure
    only appears on the redeploy that destroys them.
    """
    dockerfile = (_repo_root() / "infra" / "Dockerfile.smb-host").read_text()

    declared = re.search(r"ENV\s+SMB_HOST_DATA_DIR=(\S+)", dockerfile)
    assert declared, "infra/Dockerfile.smb-host no longer sets SMB_HOST_DATA_DIR"
    data_dir = declared.group(1)

    readme = (_repo_root() / "smb_host" / "README.md").read_text()
    mount_points = set(re.findall(r"-v\s+\S+:(/\S*?)(?:\s|\\|$)", readme))
    assert mount_points, "the README's docker run mounts nothing"
    assert any(data_dir.startswith(m.rstrip("/") + "/") or data_dir == m for m in mount_points), (
        f"the image writes tenant homes to {data_dir!r}, but the README mounts {sorted(mount_points)} — "
        f"a volume mounted anywhere else persists nothing and the failure only shows on a redeploy"
    )


# ── the pages must describe the host this repository builds ─────────────────────
#
# A stranger drove the whole SMB path using only these pages and could get a
# working agent locally but not deploy one: the README's own docker run block is
# the configuration that destroys every provisioned business on the first
# redeploy, and both pages printed a /health response the host cannot return.
# These guard the corrections that are mechanical. The prose around them is not
# guarded and should not be.


def _readme_docker_blocks() -> list[str]:
    readme = (_repo_root() / "smb_host" / "README.md").read_text()
    return [b for b in re.findall(r"```bash\n(.*?)```", readme, re.DOTALL) if "docker run" in b]


def test_the_readme_docker_command_sets_a_keystore_that_survives_a_redeploy() -> None:
    """The documented container must not use the default keystore backend.

    The default backend derives its passphrase from a machine fingerprint that
    includes the hostname, and a replaced container has a new hostname. Driven on
    the image built from this tree: provision a business, remove the container,
    start a new one on the same named volume, and it exits 1 with
    "Decryption failed: wrong passphrase or tampered data" — every business on an
    intact volume unreadable, and nothing on this host can recover one.

    The mount is guarded separately (the image declares no VOLUME). A volume with
    the default backend loses the businesses just as completely, only later and
    with the data still on disk, so both halves have to hold.
    """
    blocks = _readme_docker_blocks()
    assert blocks, "the README no longer shows a docker run command"

    configured = [b for b in blocks if "COMMUNITY_MEMBER_KEYSTORE=passphrase" in b]
    assert configured, (
        "no docker run command in smb_host/README.md sets COMMUNITY_MEMBER_KEYSTORE=passphrase. "
        "An operator following the page verbatim loses every provisioned business on the first "
        f"redeploy, with the volume intact and unreadable. Commands found: {blocks}"
    )
    for block in configured:
        assert "COMMUNITY_MEMBER_PASSPHRASE" in block, (
            "a docker run command sets COMMUNITY_MEMBER_KEYSTORE=passphrase without supplying "
            "COMMUNITY_MEMBER_PASSPHRASE, which selects a backend with nothing to decrypt with"
        )


@pytest.mark.parametrize("page", ["README.md", "OPERATIONS.md"])
def test_the_documented_health_responses_are_ones_the_host_can_return(
    page: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every /health sample on a page must match a real /health response.

    Both pages printed {"tenants":0,…,"pool_ready":3}. That cannot occur: the
    pre-warmed tenants ARE tenants, so a default host reports 3. It mattered
    beyond neatness because OPERATIONS check 7 told the reader to compare a
    tenants count after a redeploy — the one check that detects a lost volume
    keyed on a number the host never returns.
    """
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    live = host.get("/health").json()

    text = (_repo_root() / "smb_host" / page).read_text()
    samples = [json.loads(m) for m in re.findall(r'(\{"status":\s*"ok",\s*"service":\s*"smb-host".*?\})', text)]
    assert samples, f"{page} shows no /health sample to check"

    for sample in samples:
        assert set(sample) == set(live), (
            f"{page} prints a /health response whose fields are {sorted(sample)}, but the route returns {sorted(live)}"
        )
        # the invariant the wrong sample violated: a ready pool tenant is a tenant
        assert not (sample["tenants"] == 0 and sample["pool_ready"] > 0), (
            f"{page} prints tenants={sample['tenants']} with pool_ready={sample['pool_ready']}, "
            f"which the host cannot return — every pre-warmed tenant is counted in `tenants`"
        )
        assert sample["pool_ready"] <= sample["tenants"], (
            f"{page} prints pool_ready={sample['pool_ready']} exceeding tenants={sample['tenants']}"
        )


def test_the_documented_attribution_summary_is_one_the_host_can_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The summary sample on OPERATIONS.md must match a real response.

    Same class as the /health guard above, and worth having for the same
    reason: the page is the only description of this endpoint an operator
    reads, and a sample naming a field the route does not return sends them
    looking for it in the wrong place. Field set and the two accounting
    identities are checked; the values themselves are illustrative.
    """
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    assert host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sample Co"}).status_code == 201
    live = _summary(host)

    text = (_repo_root() / "smb_host" / "OPERATIONS.md").read_text()
    samples = [json.loads(m) for m in re.findall(r'(\{"tenants":\s*\d+,\s*"claimed":.*?\})\n', text)]
    assert samples, "OPERATIONS.md shows no /provisions/summary sample to check"

    for sample in samples:
        assert set(sample) == set(live), (
            f"OPERATIONS.md prints a summary whose fields are {sorted(sample)}, but the route returns {sorted(live)}"
        )
        _assert_accounting_holds(sample)
        for entry in sample["recorded"]:
            assert set(entry) == set(live["recorded"][0]), (  # type: ignore[index]
                f"a documented `recorded` entry has fields {sorted(entry)}, "
                f"but the route returns {sorted(live['recorded'][0])}"  # type: ignore[index]
            )


def test_the_documented_duplicate_name_refusal_is_the_one_the_route_returns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 409 body on the page must be the 409 body the host sends.

    The page said the refusal names the `tenant_id`. It has not since the refusal
    was changed to echo the caller's own name — and the id is withheld
    deliberately, because /t/<id> is a live tenant's endpoint, card and booking
    route, so a page teaching an operator to expect it teaches them to expect an
    enumeration oracle that was closed.
    """
    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    name = "Moon Bakery"
    taken = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": name}).json()["tenant_id"]
    live = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": name})
    assert live.status_code == 409

    readme = (_repo_root() / "smb_host" / "README.md").read_text()
    documented = [json.loads(m) for m in re.findall(r'(\{"detail":\s*"a business is already[^}]*\})', readme)]
    assert documented, "the README no longer shows the 409 body a duplicate name returns"

    live_detail = live.json()["detail"]
    for doc in documented:
        assert doc["detail"].split("'")[0] == live_detail.split("'")[0], (
            f"the README documents the 409 as {doc['detail']!r} but the route returns {live_detail!r}"
        )
        assert taken not in doc["detail"], "the README's 409 sample discloses a tenant id"


# ── the two documents must agree about who the business is ──────────────────────
#
# A claimed tenant served a card reading "Moon Bakery" beside an AgentFacts
# reading label "(unclaimed)", provider.name "(unclaimed)", and no occurrence of
# the business name anywhere in the document. The card is built from the Tenant
# dataclass; AgentFacts is built from ctx.config by build_self_agentfacts, and
# claiming a pool tenant updated the first and not the second — so the pre-mint
# placeholder survived onto the NANDA-facing half, the one a card host hands
# onward to register the business at api.nandaindex.org.


def test_a_claimed_tenants_card_and_agentfacts_name_the_same_business(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The two documents a resolver can fetch must describe one business.

    Runs on the POOLED default, because that is the path that was broken: on the
    cold path the name is known at mint and both documents were always right.
    """
    business = "Moon Bakery"
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=3)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        provisioned = host.post(
            "/provision", json={"contact": _TEST_CONTACT, "business_name": business, "service_type": "bakery"}
        ).json()
        tenant_id = provisioned["tenant_id"]

        card = host.get(f"/t/{tenant_id}/.well-known/agent.json").json()
        facts = host.get(f"/t/{tenant_id}/agentfacts.json").json()

        assert card["name"] == business
        assert facts["label"] == business, (
            f"the card says {card['name']!r} and AgentFacts says label={facts['label']!r} — "
            f"the two documents describe different businesses"
        )
        # provider.name is deliberately NOT the business — it is the operator,
        # i.e. this host (see _operator_identity, and S3 in test_served_claims).
        # The property this line used to carry — the claimed name reaching the
        # NANDA-facing document — is asserted above on `label` and
        # below on `description` and on the placeholder scan over the WHOLE
        # document, which covers provider too and does not depend on which
        # field the business is expected to appear in.
        assert facts["provider"]["name"] == mod._operator_identity("http://smb-host.example")[0], (
            f"AgentFacts provider.name is {facts['provider']['name']!r}, not the hosting operator"
        )
        assert business in facts["description"], (
            f"AgentFacts describes the agent as {facts['description']!r}, which does not name the business"
        )

        # the placeholder must not survive anywhere in the NANDA-facing document
        assert mod._POOL_PLACEHOLDER_NAME not in json.dumps(facts), (
            f"the pre-mint placeholder {mod._POOL_PLACEHOLDER_NAME!r} is still somewhere in the "
            f"AgentFacts of a CLAIMED tenant"
        )

        # and both documents must still be about the same key
        assert facts["id"] == card["authentication"]["credentials"] == provisioned["did"]


def test_a_claimed_tenants_agentfacts_declares_the_service_it_was_provisioned_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same root cause, second symptom: service_type did not reach AgentFacts.

    The card declared the service type from the Tenant dataclass while
    ctx.config.skills stayed empty, so the document a card host registers listed
    the booking action and nothing about what the business does.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=3)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        tenant_id = host.post(
            "/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery", "service_type": "bakery"}
        ).json()["tenant_id"]

        skills = [s["id"] for s in host.get(f"/t/{tenant_id}/agentfacts.json").json()["skills"]]
        assert any("bakery" in s for s in skills), (
            f"AgentFacts lists {skills}, none of which is the service the tenant was provisioned for"
        )


def test_claiming_a_pool_tenant_does_not_disturb_its_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Applying the claim writes the tenant's config; that must not touch its key.

    The claim path now calls ctx.config.save(), and config.json is the file the
    public key lives in while the private half sits in the vault. A save that
    re-materialised or dropped the key would break signing, or worse, write the
    private half back to a plaintext file.
    """
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=3)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        provisioned = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"}).json()
        tenant_id, did = provisioned["tenant_id"], provisioned["did"]

        # the key still signs, under the did the caller was given
        booked = host.post(
            f"/t/{tenant_id}/book",
            json={"service": "cake", "provider": "Moon Bakery", "datetime": "2026-09-02T10:30:00Z"},
        )
        assert booked.status_code == 200
        assert booked.json()["receipt"]["issuer_did"] == did

        # and the private half is still not in the plaintext config
        config = json.loads((tmp_path / "data" / tenant_id / "config.json").read_text())
        assert not config.get("private_key"), "claiming wrote the private key back into config.json"
        assert config.get("public_key"), "claiming dropped the public key from config.json"


def test_the_claim_survives_a_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The claim must be on disk, not only in the live registry.

    AgentFacts is rebuilt from ctx.config on every request and rehydration reloads
    that config from disk, so a claim applied only in memory would revert to
    "(unclaimed)" the next time the host restarted — after the business had
    already been handed its card.
    """
    business = "Moon Bakery"
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=3)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        tenant_id = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": business}).json()[
            "tenant_id"
        ]

    restarted = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=3)
    with _client(restarted) as host:
        facts = host.get(f"/t/{tenant_id}/agentfacts.json").json()
        assert facts["label"] == business, (
            f"after a restart the tenant's AgentFacts reads label={facts['label']!r} — "
            f"the claim was applied in memory but not persisted"
        )


# ── a booking reaches the business, or the caller is told it did not ─────────
#
# book_appointment appended a row and signed a receipt and told nobody: no
# notification, no conflict check, no export. Measured on the default
# configuration before this change, the same provider and datetime booked twice
# returned 201 twice with two receipts. A customer could book a real business
# and the business never learn of it, while the customer held a signed receipt
# saying the appointment was made.

_SLOT = {"service": "haircut", "provider": "Moon Bakery", "datetime": "2026-09-02T10:30:00Z"}


def _claimed(tmp_path, monkeypatch, *, contact=_TEST_CONTACT, pool_size=3):
    """A claimed tenant on the DEFAULT pooled configuration."""
    mod = _build_host_module(tmp_path, monkeypatch, "http://smb-host.example", pool_size=pool_size)
    return mod


@_BOTH_PROVISION_PATHS
def test_the_same_slot_cannot_be_booked_twice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool_size: int) -> None:
    """The default configuration first, because that is the path the host serves.

    A refusal that only runs when the pool is disabled is the shape that let
    blank and punctuation-only names through on the path everybody runs.
    """
    mod = _claimed(tmp_path, monkeypatch, pool_size=pool_size)
    with _client(mod) as host:
        if pool_size:
            _wait_for_pool(host, pool_size)
        tenant_id = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"}).json()[
            "tenant_id"
        ]

        first = host.post(f"/t/{tenant_id}/book", json=_SLOT)
        assert first.status_code == 200

        second = host.post(f"/t/{tenant_id}/book", json={**_SLOT, "service": "something else"})
        assert second.status_code == 409, f"the slot was booked twice: {second.status_code}"
        detail = second.json()["detail"]
        assert "already booked" in detail and _SLOT["datetime"] in detail

        # and the refused booking left nothing behind: no second row, no second receipt
        assert first.json()["booking"]["id"] == 1
        third = host.post(f"/t/{tenant_id}/book", json={**_SLOT, "datetime": "2026-09-02T11:30:00Z"})
        assert third.json()["booking"]["id"] == 2, "the refused booking consumed an id"


def test_a_free_slot_for_a_different_provider_is_not_a_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal is one provider's slot, not a global clock."""
    mod = _claimed(tmp_path, monkeypatch)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        tenant_id = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Moon Bakery"}).json()[
            "tenant_id"
        ]

        assert host.post(f"/t/{tenant_id}/book", json=_SLOT).status_code == 200
        other = host.post(f"/t/{tenant_id}/book", json={**_SLOT, "provider": "Sun Cafe"})
        assert other.status_code == 200, "a different provider at the same time was refused"


def test_a_booking_with_no_deliverable_channel_does_not_report_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An undelivered booking says so by name, on the response and in the log.

    The booking and its receipt are real, so this is not an error — but a caller
    told nothing cannot tell a delivered booking from one the business will never
    see, which is the outcome this unit exists to remove.
    """
    mod = _claimed(tmp_path, monkeypatch)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        # An email contact: representable, and this build ships no email sender.
        tenant_id = host.post(
            "/provision", json={"contact": "owner@moonbakery.example", "business_name": "Moon Bakery"}
        ).json()["tenant_id"]

        booked = host.post(f"/t/{tenant_id}/book", json=_SLOT)
        assert booked.status_code == 200
        body = booked.json()

        assert body["delivered"] is False, "an undeliverable booking reported success"
        assert body["delivery_channel"] == "email"
        assert "no sender is configured for the email channel" in body["delivery_note"]
        # the booking still stands, receipted
        assert body["booking"]["status"] == _booking_status_from_contract()
        assert body["receipt_id"]


def test_a_booking_is_delivered_to_the_business_contact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The webhook sender reaches the address the business gave at claim time.

    The transport is stubbed; what is asserted is that the booking was handed to
    the sender for the tenant's own contact, and that what it carries is the same
    appointment the receipt was signed over.
    """
    from community_member.builtin_skills.booking import notify

    sent: list[tuple[str, dict]] = []

    class _Ok:
        status_code = 200

    def _post(url: str, json: dict) -> _Ok:
        sent.append((url, json))
        return _Ok()

    monkeypatch.setattr(notify, "default_senders", lambda: {notify.CONTACT_WEBHOOK: notify.WebhookSender(post=_post)})

    mod = _claimed(tmp_path, monkeypatch)
    with _client(mod) as host:
        _wait_for_pool(host, 3)
        tenant_id = host.post(
            "/provision", json={"contact": "https://moonbakery.example/bookings", "business_name": "Moon Bakery"}
        ).json()["tenant_id"]

        booked = host.post(f"/t/{tenant_id}/book", json=_SLOT).json()

    assert booked["delivered"] is True
    assert len(sent) == 1, f"the booking was handed to the sender {len(sent)} times"
    url, payload = sent[0]
    assert url == "https://moonbakery.example/bookings"
    assert payload["type"] == "booking.created"
    assert payload["booking"]["provider"] == _SLOT["provider"]
    assert payload["booking"]["datetime"] == _SLOT["datetime"]

    # the calendar event carries the same appointment the receipt was signed over
    ics = payload["ics"]
    receipt_payload = booked["receipt"]["action"]["machine_payload"]
    assert "BEGIN:VEVENT" in ics and "END:VCALENDAR" in ics
    assert "DTSTART:20260902T103000Z" in ics
    assert receipt_payload["datetime"] == _SLOT["datetime"]
    assert receipt_payload["provider"] == _SLOT["provider"]
    assert _SLOT["provider"] in ics


# ── H14: bounds on the unauthenticated booking path ──────────────────────────
# POST /t/{tenant_id}/book takes NO credential and does persistent work. Before
# these bounds, one anonymous request carrying a 2 MB `notes` field returned 200
# and grew the tenant store by 4,015,349 bytes — about twice the input, because
# the caller's text is persisted in the booking store AND again inside the signed
# ARP receipt. This host has no delete route, so that growth was permanent.


def _provisioned(tmp_path, monkeypatch):
    client = _make_host(tmp_path, monkeypatch, "http://127.0.0.1:8791")
    resp = client.post("/provision", json={"business_name": "H14 Probe", "contact": "a@example.org"})
    assert resp.status_code == 201, resp.text
    return client, resp.json()["tenant_id"]


def test_book_refuses_an_oversized_notes_field(tmp_path, monkeypatch):
    """ADVERSARIAL: the storage bound, and the one that does not depend on a header."""
    client, tenant_id = _provisioned(tmp_path, monkeypatch)
    resp = client.post(
        f"/t/{tenant_id}/book",
        # Deliberately UNDER the 64 KiB body cap so this isolates the FIELD
        # bound. At 100 KB the body middleware answers 413 first and this test
        # would pass while proving nothing about max_length.
        json={"service": "s", "provider": "p", "datetime": "t", "notes": "A" * 10_000},
    )
    assert resp.status_code == 422, "an over-long notes field must be refused, not persisted"


def test_book_refuses_an_oversized_body_before_parsing(tmp_path, monkeypatch):
    """ADVERSARIAL: the memory bound, enforced on Content-Length."""
    client, tenant_id = _provisioned(tmp_path, monkeypatch)
    resp = client.post(
        f"/t/{tenant_id}/book",
        content=b'{"service":"s","provider":"p","datetime":"t","notes":"' + b"A" * 200_000 + b'"}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413


def test_book_rate_limits_one_source_without_affecting_another():
    """ADVERSARIAL: a single source cannot book without bound.

    Asserts only what the limiter is: it slows ONE source. It is not the cap —
    the per-field length is — and this test deliberately does not imply a global
    guarantee the in-process window cannot give.
    """
    import main as host_main

    limiter = host_main._BookRateLimiter(per_hour=2)
    assert limiter.check("1.2.3.4") == 0
    assert limiter.check("1.2.3.4") == 0
    assert limiter.check("1.2.3.4") > 0, "third booking from one source must be told to wait"
    assert limiter.check("5.6.7.8") == 0, "a different source is unaffected"


def test_book_rate_check_precedes_tenant_lookup():
    """EDGE: probing for tenant ids must cost a prober the same as booking.

    If the rate check ran AFTER the lookup, an unknown id would 404 cheaply while
    a real one 429'd — turning the limiter into a tenant-existence oracle.
    """
    import inspect

    import main as host_main

    src = inspect.getsource(host_main.create_app)
    book_at = src.index('post("/t/{tenant_id}/book")')
    rate_at = src.index("book_limiter.check", book_at)
    lookup_at = src.index("state.tenants.get(tenant_id)", book_at)
    assert rate_at < lookup_at, "rate check must precede the tenant lookup"


# ── the tenant meta record is written atomically ─────────────────────────────


def test_a_crash_mid_write_does_not_tear_the_meta_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A simulated crash between the truncate and the write of ``smb_tenant.json``
    must leave the PREVIOUS record intact, not a torn file.

    The meta record is what a restart rehydrates a tenant from, and every field
    the pool-reclaim predicate reads comes from it. ``Path.write_text`` truncates
    first and writes second, so a crash in between left an empty or partial
    file and the tenant — a business, if claimed — failed to rehydrate. The
    write now goes to a sibling temp file and is renamed over the record.
    """
    import main as smb_main

    host = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    tenant_id = host.post("/provision", json={"contact": _TEST_CONTACT, "business_name": "Sharp Cuts"}).json()[
        "tenant_id"
    ]
    meta_path = tmp_path / "data" / tenant_id / "smb_tenant.json"
    before = meta_path.read_text()
    assert json.loads(before)["business_name"] == "Sharp Cuts"

    state = host.app.state.host
    tenant = state.tenants[tenant_id]
    tenant.business_name = "Sharp Cuts (renamed)"

    # The crash: the process dies after the temp file is opened and partly
    # written, before the rename. Simulated by making fsync raise — everything
    # up to that point has happened, nothing after it will.
    def _die(_fd: int) -> None:
        raise OSError("simulated crash mid-write")

    _real_fsync = smb_main.os.fsync
    monkeypatch.setattr(smb_main.os, "fsync", _die)
    with pytest.raises(OSError, match="simulated crash"):
        smb_main._write_meta(meta_path.parent, tenant)

    assert meta_path.read_text() == before, "the record on disk was torn or replaced by a partial write"
    assert json.loads(meta_path.read_text())["business_name"] == "Sharp Cuts"
    leftovers = [p.name for p in meta_path.parent.iterdir() if p.name.startswith(".smb_tenant.json.")]
    assert leftovers == [], f"a temp file from the failed write was left behind: {leftovers}"

    # And a restart over the same directory still rehydrates the tenant.
    monkeypatch.setattr(smb_main.os, "fsync", _real_fsync)
    again = _make_host(tmp_path, monkeypatch, "http://smb-host.example")
    assert again.get(f"/t/{tenant_id}/.well-known/agent.json").status_code == 200


def test_the_meta_record_is_never_written_with_write_text() -> None:
    """The three write sites all go through ``_write_meta``; a fourth that
    reaches for ``write_text`` reintroduces the torn-file window."""
    import inspect

    import main as smb_main

    src = inspect.getsource(smb_main)
    assert "_META_FILE).write_text(" not in src
    assert src.count("_write_meta(") >= 4  # the definition and three call sites
