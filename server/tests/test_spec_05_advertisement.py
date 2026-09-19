"""This org advertises spec 0.5 — and actually implements it.

The advertised-version correction was filed because the org *rejected* v0.2-signed mutations while
`spec/0.3/signing.md` said a chapter MUST accept them, and — worse — the
**signed** boot badge at `/.well-known/conformance.json` attested `["0.3","0.2"]`
while the signing path refused v0.2 writes. A peer that trusted the badge and
signed a mutation at v0.2 got a 401 it had no reason to expect.

The spec then adopted the rule (umbrella PR): `spec/0.5/signing.md`
§"v0.2 scope" makes rejecting v0.2 on mutations the normative behaviour of a
v0.5 chapter. So the resolution is not to weaken the runtime — it is to say
truthfully which major this org speaks, everywhere it says it.

The discipline this module enforces is: **never attest a version you bend.**
Advertising 0.5 is only honest while every 0.5 clause below holds, so each one
is a test rather than a claim in a doc.

Classification: HAPPY (advertisement), ADVERSARIAL (the clauses).
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def chapter_agent_module():
    """The already-imported app module.

    Deliberately NOT a sys.modules pop + re-import: nothing here depends on
    fresh module state, and re-importing `chapter_agent` mid-session leaves
    other modules holding references to the previous object — which segfaulted
    the full suite under coverage (the asyncpg/cffi extension state goes with
    it). Cheaper and stabler to read the live module.
    """
    import chapter_agent

    return chapter_agent


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    chapter_agent_module._rate_limit_store.clear()
    return TestClient(chapter_agent_module.app)


def _v02_headers(body: str, agent_id: str, priv_b64: str, pub_b64: str) -> dict[str, str]:
    import sovereign_identity

    ts = str(int(time.time()))
    sig = sovereign_identity.ed25519_sign(f"{body}:{agent_id}:{ts}", priv_b64)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Sig-Scheme": "ed25519",
        "X-Agent-DID-Key": sovereign_identity.build_did_key_from_ed25519(pub_b64),
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# The advertisement
# ---------------------------------------------------------------------------


def test_A1_version_endpoint_advertises_0_5(client: TestClient) -> None:
    body = client.get("/api/version").json()

    assert body["preferred_version"] == "0.5", "the org implements the 0.5 rule; say so"
    assert "0.5" in body["protocol_versions"]
    # §14 backward compat: the older majors are still accepted (within the
    # scope below), so dropping them would be its own false claim.
    for major in ("0.2", "0.3", "0.4"):
        assert major in body["protocol_versions"], f"{major} dropped from the advertised set"
    assert body["preferred_version"] in body["protocol_versions"]


def test_A2_version_endpoint_states_the_v02_scope(client: TestClient) -> None:
    """`protocol_versions` carries no per-method scope — the spec says so and
    calls it a residual. A v0.2-only client reading only that list concludes its
    writes are fine. This block is the missing negotiation-time signal."""
    scope = client.get("/api/version").json().get("signature_scheme_scope")

    assert isinstance(scope, dict), "a 0.5 chapter must publish where v0.2 still applies"
    assert "method_binding_required" in scope["ed25519"], scope
    assert "read" in scope["ed25519"].lower()
    assert scope["ed25519+nonce"] == "all requests"


def test_A3_signed_badge_no_longer_attests_what_the_signing_path_refuses() -> None:
    """The core of the advertised-version correction. The badge is SIGNED, so its version list is a
    cryptographic claim: it must not advertise a major without saying where it
    applies."""
    import conformance_boot

    assert conformance_boot.SELF_ATTESTATION_EXTENSIONS["org.orrery.v02_scheme_scope"]
    scope = conformance_boot.SELF_ATTESTATION_EXTENSIONS["org.orrery.v02_scheme_scope"]
    assert "method_binding_required" in scope
    assert "spec/0.5" in scope


# ---------------------------------------------------------------------------
# The clauses — advertising 0.5 is only honest while each of these holds
# ---------------------------------------------------------------------------


def test_C1_v02_mutation_is_rejected(client: TestClient) -> None:
    """spec/0.5: MUST REJECT `ed25519` on mutating requests, 401
    `method_binding_required`."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("TEST-spec05-alice")
    body = '{"intent_text":"hi","requester_agent_id":"TEST-spec05-alice","intent_tags":[]}'
    headers = _v02_headers(body, "TEST-spec05-alice", kp["private_key"], kp["public_key"])

    resp = client.post("/api/intents", content=body, headers=headers)

    assert resp.status_code == 401
    assert resp.json().get("detail") == "method_binding_required"


def test_C2_rejection_precedes_signature_verification() -> None:
    """spec/0.5 §"What the chapter does" step 3.1: reject BEFORE verifying —
    "verifying first would make the chapter a signature-validity oracle for a
    scheme it is refusing anyway". A garbage signature and a perfect one must be
    indistinguishable here."""
    import auth_verify

    headers = {
        "X-Agent-ID": "TEST-spec05-oracle",
        "X-Agent-Signature": "not-even-base64-@@@",
        "X-Agent-Timestamp": str(int(time.time())),
        "X-Agent-Sig-Scheme": "ed25519",
    }

    valid, _agent, reason = auth_verify.verify_request(
        "{}", headers, method="POST", url_path="/api/intents", require_method_binding=True
    )

    assert valid is False
    assert reason == "method_binding_required", (
        f"got {reason!r} — the scheme check must fire before any signature work, "
        "or the org leaks signature validity for a scheme it refuses"
    )


def test_C3_v02_read_is_still_accepted(client: TestClient, chapter_agent_module) -> None:
    """spec/0.5: MUST ACCEPT `ed25519` on non-mutating requests. Replaying a
    read signature onto another read discloses nothing the caller could not have
    requested under its own identity."""
    from ._admin_fixtures import register_test_regular_member

    member = register_test_regular_member(chapter_agent_module, agent_id="spec05-reader", name="Reader")
    headers = _v02_headers("", "spec05-reader", member["private_key"], member["public_key"])

    resp = client.get("/api/members", headers=headers)

    assert resp.status_code != 401, f"a v0.2-signed READ must still authenticate: {resp.text[:200]}"


@pytest.mark.parametrize("path", ["/a2a", "/a2a/", "/a2a/@alice"])
def test_C4_a2a_interop_surface_keeps_v02(path: str) -> None:
    """spec/0.5 carves out `POST /a2a`, `POST /a2a/` and `POST /a2a/@{handle}`:
    third-party traffic from implementations that track the A2A protocol rather
    than this one, which cannot be held to a NANDA version window."""
    import auth_verify

    assert auth_verify.enforce_method_binding("POST", path) is False


def test_C5_run_is_carved_out_now_that_the_spec_names_it(client: TestClient) -> None:
    """`/run` IS carved out — spec/0.5/signing.md names `POST /run` and
    `POST /run/` in the A2A interop surface (umbrella / PR).

    This assertion is inverted, not deleted. The advertised-version correction pinned the opposite while the
    spec named only the `/a2a` family, and that pin is what surfaced the
    omission rather than papering over it. Keeping the test either way means the
    route's behaviour is always claimed by something executable."""
    import auth_verify

    assert auth_verify.enforce_method_binding("POST", "/run") is False
    assert auth_verify.enforce_method_binding("POST", "/run/") is False


def test_C5b_the_exemption_set_is_the_spec_list_verbatim() -> None:
    """spec/0.5: "The enumeration is exhaustive: a route not named here is not
    carved out, so a chapter MUST NOT extend the exemption to routes of its own
    choosing." This pins the set against local growth — the failure mode the advertised-version correction
    was filed for, in the opposite direction."""
    import auth_verify

    assert auth_verify.METHOD_BINDING_EXEMPT_PATHS == {"/a2a", "/a2a/", "/run", "/run/"}
    assert auth_verify.METHOD_BINDING_EXEMPT_PREFIXES == ("/a2a/@",)
    # A route the spec does not name stays bound, however A2A-ish it looks.
    assert auth_verify.enforce_method_binding("POST", "/api/intents") is True
    assert auth_verify.enforce_method_binding("POST", "/invoke") is True


def test_C6_body_proof_endpoints_are_untouched() -> None:
    """spec/0.5: registration, rotation and the §8.4 federation envelope are not
    authenticated by the §3 header signature, so the rule does not reach them.
    They short-circuit as open paths before any scheme check — a v0.2-era client
    can still register and rotate."""
    import auth_verify

    for path in ("/api/members", "/api/members/rotate"):
        assert auth_verify.is_open_path("POST", path) is True, f"{path} must stay body-proof authenticated"
