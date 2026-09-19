"""Owner principal: the key separation, the nonce binding, and fail-closed config.

Three properties this file exists to pin, because each one fails SILENTLY:

  1. A grant whose grantor is its own grantee VERIFIES. Orrery's vendored DAT
     verifier accepts it. So the refusal cannot be delegated to verification and
     has to be asserted here.
  2. An OIDC evidence block with no nonce VERIFIED under ``sm_authority`` 0.1.0
     (its nonce check was ``if nonce is not None``), while binding an arbitrary
     key to a real person's anchor. Fixed upstream in 0.2.0, which this
     distribution now pins; the requirement is still asserted here because the
     guarantee must not depend solely on a transitive pin.
  3. Missing OIDC config must REFUSE, and unset and EMPTY are the same error.
"""

import base64
import hashlib
import json
import threading
import time
import urllib.parse
import urllib.request

import pytest

from community_member import owner
from community_member._dat import build_dat
from community_member.crypto import build_did_key

GOOGLE = owner.PROVIDERS[0]
AGENT_DID = build_did_key(base64.b64encode(b"\x01" * 32).decode())


def _b64u(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _id_token(claims: dict) -> str:
    return f"{_b64u({'alg': 'RS256'})}.{_b64u(claims)}.signature"


# A distinct sentinel, NOT None. Using None as "build the default" would make
# `_binding(evidence=None)` silently build real evidence, so the test that means
# "there is no evidence at all" would exercise the happy path instead — a check
# that reads like coverage and asserts nothing.
_DEFAULT = object()


def _binding(owner_identity, *, grant=_DEFAULT, evidence=_DEFAULT, nonce=None, anchor=None):
    nonce = nonce or owner.owner_nonce(owner_identity.did, "randomness")
    anchor = anchor or {"method": "oidc", "issuer": GOOGLE.issuer, "id": "sub-1"}
    if evidence is _DEFAULT:
        evidence = owner.build_owner_evidence(
            owner=owner_identity,
            subject="barber@example.com",
            anchor=anchor,
            id_token=_id_token({"iss": GOOGLE.issuer, "sub": "sub-1", "nonce": nonce}),
            nonce=nonce,
        )
    if grant is _DEFAULT:
        grant = owner.build_listing_grant(owner=owner_identity, agent_did=AGENT_DID)
    return {
        "owner_did": owner_identity.did,
        "subject": "barber@example.com",
        "anchor": anchor,
        "evidence": evidence,
        "grant": grant,
    }


# ── 1. the separation that verification will not enforce ─────────────────────


def test_dat_verifier_ACCEPTS_a_self_granted_consent():
    """⚠️ The premise of this whole module, measured rather than assumed.

    If this test ever fails because ``_dat`` started rejecting self-grants, the
    explicit refusal below becomes redundant — but until then it is load-bearing,
    and this test is what proves the refusal is not decoration. ``_dat`` is NOT
    to be "fixed": it is in byte-for-byte lockstep with ``conformance/dat``.
    """
    from community_member import dat as dat_module

    identity = owner.mint_owner_identity()
    self_grant = build_dat(
        grantor_sk_bytes=identity.signing_key_bytes(),
        grantor_did=identity.did,
        grantee_did=identity.did,  # grantor IS grantee
        action_categories=[owner.LISTING_ACTION_CATEGORY],
        not_after="2099-01-01T00:00:00Z",
    )
    assert dat_module.verify_counterparty_dat(self_grant, category=owner.LISTING_ACTION_CATEGORY).ok is True


def test_gate_refuses_the_self_granted_consent_that_dat_accepts():
    identity = owner.mint_owner_identity()
    self_grant = build_dat(
        grantor_sk_bytes=identity.signing_key_bytes(),
        grantor_did=identity.did,
        grantee_did=identity.did,
        action_categories=[owner.LISTING_ACTION_CATEGORY],
        not_after="2099-01-01T00:00:00Z",
    )
    verdict = owner.listing_grant_verdict(_binding(identity, grant=self_grant), identity.did)
    assert verdict.ok is False
    assert verdict.reason == "self_grant"


def test_build_listing_grant_refuses_to_mint_a_self_grant():
    identity = owner.mint_owner_identity()
    with pytest.raises(ValueError, match="self-granted"):
        owner.build_listing_grant(owner=identity, agent_did=identity.did)


def test_owner_identity_differs_from_the_agent_identity():
    identity = owner.mint_owner_identity()
    assert identity.did != AGENT_DID
    assert identity.did.startswith("did:key:z")


def test_owner_key_uses_a_distinct_derivation_path():
    """Defence in depth: even the SAME phrase yields a different owner key.

    The separate phrase is what makes the keys independent; this asserts the
    path separation holds too, so a future refactor that reuses one phrase does
    not silently collapse the two principals into one key.
    """
    from community_member import recovery

    identity = owner.mint_owner_identity()
    agent_material = recovery.recover_from_mnemonic(identity.mnemonic)  # default (agent) path
    assert owner.OWNER_DERIVATION_PATH != recovery.DEFAULT_PATH
    assert agent_material.did_key != identity.did


def test_recover_owner_identity_round_trips():
    identity = owner.mint_owner_identity()
    again = owner.recover_owner_identity(identity.mnemonic)
    assert again.did == identity.did
    assert again.private_key_b64 == identity.private_key_b64


# ── 2. the nonce binding ─────────────────────────────────────────────────────


def test_nonce_is_a_commitment_to_the_owner_did():
    identity = owner.mint_owner_identity()
    expected = base64.urlsafe_b64encode(hashlib.sha256(f"{identity.did}|rand".encode()).digest()).decode().rstrip("=")
    assert owner.owner_nonce(identity.did, "rand") == expected


def test_nonce_changes_with_the_owner_did():
    """Two owners must not be able to reuse each other's nonce."""
    a, b = owner.mint_owner_identity(), owner.mint_owner_identity()
    assert owner.owner_nonce(a.did, "same-rand") != owner.owner_nonce(b.did, "same-rand")


def test_nonce_refuses_empty_inputs():
    identity = owner.mint_owner_identity()
    with pytest.raises(ValueError):
        owner.owner_nonce("", "rand")
    with pytest.raises(ValueError, match="replayable"):
        owner.owner_nonce(identity.did, "")


def test_build_owner_evidence_refuses_without_a_nonce():
    identity = owner.mint_owner_identity()
    with pytest.raises(ValueError, match="without a nonce"):
        owner.build_owner_evidence(
            owner=identity,
            subject="a@b.c",
            anchor={"method": "oidc", "issuer": GOOGLE.issuer, "id": "sub-1"},
            id_token=_id_token({"iss": GOOGLE.issuer, "sub": "sub-1"}),
            nonce="",
        )


def test_gate_refuses_oidc_evidence_with_no_nonce():
    """⚠️ The second smell. ``sm_authority`` 0.1.0 VERIFIED this envelope.

    Its nonce check was ``if nonce is not None``, and nothing else in the
    envelope bound the token to ``grantor_did`` — so anyone holding a valid token
    for this subject could name their own key as grantor.

    Fixed upstream in 0.2.0 (nonce bound to ``grantor_did``, ``require_nonce``
    defaults True), which this distribution now floors and pins. This assertion
    stays: it covers OUR gate, so the property survives a resolver that lands on
    a different sm-authority than the lockfile intends, and it is what made the
    path safe before the upstream fix existed.
    """
    identity = owner.mint_owner_identity()
    envelope = _binding(identity)["evidence"]
    envelope["evidence"] = [{"type": "oidc", "claims": {"token": _id_token({"iss": GOOGLE.issuer, "sub": "sub-1"})}}]
    verdict = owner.listing_grant_verdict(_binding(identity, evidence=envelope), AGENT_DID)
    assert verdict.ok is False
    assert verdict.reason == "evidence_nonce_missing"


def test_verify_id_token_fail_fast_refuses_a_nonceless_token():
    with pytest.raises(ValueError, match="NO nonce"):
        owner.verify_id_token_fail_fast(
            {"iss": GOOGLE.issuer, "aud": "client-1", "exp": int(time.time()) + 600},
            issuer=GOOGLE.issuer,
            audience="client-1",
            nonce="expected",
        )


def test_verify_id_token_fail_fast_refuses_a_mismatched_nonce():
    with pytest.raises(ValueError, match="does not match the owner-DID commitment"):
        owner.verify_id_token_fail_fast(
            {"iss": GOOGLE.issuer, "aud": "client-1", "nonce": "someone-elses", "exp": int(time.time()) + 600},
            issuer=GOOGLE.issuer,
            audience="client-1",
            nonce="ours",
        )


@pytest.mark.parametrize(
    "claims,match",
    [
        ({"iss": "https://evil.example", "aud": "client-1", "nonce": "n"}, "issuer mismatch"),
        ({"iss": GOOGLE.issuer, "aud": "other-client", "nonce": "n"}, "audience"),
        ({"iss": GOOGLE.issuer, "aud": "client-1", "nonce": "n", "exp": 1}, "expired"),
        ({"iss": GOOGLE.issuer, "aud": "client-1", "nonce": "n", "nbf": 9999999999}, "not yet valid"),
    ],
)
def test_verify_id_token_fail_fast_rejections(claims, match):
    with pytest.raises(ValueError, match=match):
        owner.verify_id_token_fail_fast(claims, issuer=GOOGLE.issuer, audience="client-1", nonce="n")


def test_verify_id_token_fail_fast_accepts_a_good_token():
    owner.verify_id_token_fail_fast(
        {"iss": GOOGLE.issuer, "aud": ["client-1", "other"], "nonce": "n", "exp": int(time.time()) + 600},
        issuer=GOOGLE.issuer,
        audience="client-1",
        nonce="n",
    )


# ── 3. fail closed on configuration ──────────────────────────────────────────


@pytest.mark.parametrize("provider_id", [p.id for p in owner.PROVIDERS])
def test_client_id_unset_refuses(provider_id):
    with pytest.raises(owner.OwnerConfigError, match="not set"):
        owner.oidc_client_id(provider_id, env={})


@pytest.mark.parametrize("provider_id", [p.id for p in owner.PROVIDERS])
@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
def test_client_id_empty_is_the_same_error_as_unset(provider_id, blank):
    """⚠️ Empty is not "configured with nothing" — a blank value is an error."""
    var = f"ORRERY_OIDC_CLIENT_ID_{provider_id.upper()}"
    with pytest.raises(owner.OwnerConfigError, match="not set"):
        owner.oidc_client_id(provider_id, env={var: blank})


def test_client_id_present_is_returned_stripped():
    assert owner.oidc_client_id("google", env={"ORRERY_OIDC_CLIENT_ID_GOOGLE": "  abc.apps  "}) == "abc.apps"


def test_unknown_provider_refuses():
    with pytest.raises(owner.OwnerConfigError, match="unknown OIDC provider"):
        owner.oidc_client_id("facebook", env={"ORRERY_OIDC_CLIENT_ID_FACEBOOK": "x"})


def test_authorization_request_refuses_an_empty_client_id():
    identity = owner.mint_owner_identity()
    with pytest.raises(owner.OwnerConfigError):
        owner.authorization_request(
            GOOGLE, "  ", identity.did, authorization_endpoint="https://idp/auth", redirect_uri="http://127.0.0.1:1/cb"
        )


def test_no_client_secret_anywhere_in_the_module():
    """A desktop client cannot hold a secret, and an ID token does not need one.

    ``client_secret`` is the OAuth parameter name, so scanning the source for it
    catches the only way a secret could enter this flow. Asserted against the
    file rather than a call site so the property survives future edits: the
    module discusses "no client secret" in prose, and that phrase does not
    contain the underscore form.
    """
    from pathlib import Path

    assert "client_secret" not in Path(owner.__file__).read_text()


# ── the gate's remaining refusals ────────────────────────────────────────────


def test_gate_refuses_with_no_binding():
    assert owner.listing_grant_verdict(None, AGENT_DID).reason == "no_owner_consent"


def test_gate_refuses_without_an_agent_did():
    identity = owner.mint_owner_identity()
    assert owner.listing_grant_verdict(_binding(identity), "").reason == "no_agent_did"


def test_gate_refuses_a_consent_for_another_agent():
    identity = owner.mint_owner_identity()
    other = build_did_key(base64.b64encode(b"\x02" * 32).decode())
    assert owner.listing_grant_verdict(_binding(identity), other).reason == "grantee_mismatch"


def test_gate_refuses_a_tampered_grant():
    identity = owner.mint_owner_identity()
    binding = _binding(identity)
    binding["grant"]["scope"] = {"action_categories": [owner.LISTING_ACTION_CATEGORY, "spend_money"]}
    assert owner.listing_grant_verdict(binding, AGENT_DID).reason == "grant_invalid"


def test_gate_refuses_a_grant_outside_the_listing_scope():
    identity = owner.mint_owner_identity()
    grant = build_dat(
        grantor_sk_bytes=identity.signing_key_bytes(),
        grantor_did=identity.did,
        grantee_did=AGENT_DID,
        action_categories=["something_else"],
        not_after="2099-01-01T00:00:00Z",
    )
    assert owner.listing_grant_verdict(_binding(identity, grant=grant), AGENT_DID).reason == "scope"


def test_gate_refuses_an_expired_consent():
    identity = owner.mint_owner_identity()
    assert owner.listing_grant_verdict(_binding(identity), AGENT_DID, now="2099-01-01T00:00:00Z").reason == "expired"


@pytest.mark.parametrize("evidence", [None, {}, "nope", {"grantor_did": "did:key:zOther"}])
def test_gate_refuses_missing_or_foreign_evidence(evidence):
    identity = owner.mint_owner_identity()
    verdict = owner.listing_grant_verdict(_binding(identity, evidence=evidence), AGENT_DID)
    assert verdict.ok is False
    assert verdict.reason in {"no_evidence", "evidence_grantor_mismatch", "evidence_anchor_incomplete"}


def test_gate_refuses_a_malformed_binding():
    assert owner.listing_grant_verdict({"grant": "not-a-dict"}, AGENT_DID).reason == "malformed_binding"


def test_gate_accepts_a_real_binding():
    identity = owner.mint_owner_identity()
    verdict = owner.listing_grant_verdict(_binding(identity), AGENT_DID)
    assert verdict.ok is True, verdict
    assert bool(verdict) is True


# ── persistence ──────────────────────────────────────────────────────────────


def test_save_binding_writes_no_private_key(tmp_path):
    identity = owner.mint_owner_identity()
    binding = _binding(identity)
    owner.save_binding(
        tmp_path,
        owner_did=identity.did,
        subject=binding["subject"],
        anchor=binding["anchor"],
        evidence=binding["evidence"],
        grant=binding["grant"],
    )
    blob = owner.binding_path(tmp_path).read_text()
    assert identity.private_key_b64 not in blob
    assert identity.mnemonic not in blob
    assert identity.did in blob


def test_load_binding_absent_and_corrupt(tmp_path):
    assert owner.load_binding(tmp_path) is None
    owner.binding_path(tmp_path).write_text("{not json")
    assert owner.load_binding(tmp_path) is None


def test_delete_binding_withdraws_consent(tmp_path):
    identity = owner.mint_owner_identity()
    binding = _binding(identity)
    owner.save_binding(
        tmp_path,
        owner_did=identity.did,
        subject=binding["subject"],
        anchor=binding["anchor"],
        evidence=binding["evidence"],
        grant=binding["grant"],
    )
    assert owner.delete_binding(tmp_path) is True
    assert owner.load_binding(tmp_path) is None
    # Withdrawal needs no owner key — that is the point of it being a deletion.
    assert owner.delete_binding(tmp_path) is False


# ── the SMB path refuses, and does not mint anything ─────────────────────────


def test_platform_install_is_not_available():
    """There is no Shopify/Wix/Toast code and no partner account. Verified in
    nanda-connect: three string constants and an injected validator."""
    assert owner.PLATFORM_INSTALL_AVAILABLE is False


def test_platform_install_refusal_says_why_and_names_the_platforms():
    text = owner.platform_install_refusal("Toast")
    assert "Toast" in text
    assert "not available yet" in text
    # It must not imply success or a workaround that launders self-assertion.
    assert "own say-so" in text
    for word in ("verified", "approved", "success"):
        assert word not in text.lower()


# ── OIDC discovery + the full loopback/PKCE flow, against a fake IdP ─────────


def test_discover_endpoints_requires_https():
    with pytest.raises(owner.OwnerConfigError, match="https"):
        owner.discover_endpoints("http://accounts.google.com", fetch=lambda _u: {})


def test_discover_endpoints_refuses_a_mismatched_issuer():
    def fetch(_url):
        return {
            "issuer": "https://evil.example",
            "authorization_endpoint": "https://idp/auth",
            "token_endpoint": "https://idp/token",
        }

    with pytest.raises(owner.OwnerConfigError, match="does not match the pinned issuer"):
        owner.discover_endpoints(GOOGLE.issuer, fetch=fetch)


def test_discover_endpoints_refuses_an_incomplete_document():
    with pytest.raises(owner.OwnerConfigError, match="missing"):
        owner.discover_endpoints(GOOGLE.issuer, fetch=lambda _u: {"issuer": GOOGLE.issuer})


def test_acquire_owner_assertion_end_to_end_over_real_loopback():
    """The whole acquisition, driven against an in-process fake IdP.

    Exercises the real loopback HTTP server and the real PKCE derivation — the
    fake IdP recomputes S256(verifier) and refuses a mismatch, and asserts that
    no client secret is sent. A stubbed exchange would prove neither.
    """
    identity = owner.mint_owner_identity()
    seen: dict[str, str] = {}

    def fetch(url):
        assert url == GOOGLE.issuer + "/.well-known/openid-configuration"
        return {
            "issuer": GOOGLE.issuer,
            "authorization_endpoint": "https://idp.example/auth",
            "token_endpoint": "https://idp.example/token",
        }

    def open_url(url):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        seen["nonce"] = query["nonce"][0]
        seen["challenge"] = query["code_challenge"][0]
        assert query["code_challenge_method"] == ["S256"]
        assert query["response_type"] == ["code"]
        redirect = query["redirect_uri"][0]
        assert redirect.startswith("http://127.0.0.1:")
        threading.Thread(
            target=lambda: urllib.request.urlopen(f"{redirect}?code=CODE&state={query['state'][0]}").read()
        ).start()

    def post(url, data):
        assert url == "https://idp.example/token"
        assert "client_secret" not in data
        recomputed = (
            base64.urlsafe_b64encode(hashlib.sha256(data["code_verifier"].encode()).digest()).decode().rstrip("=")
        )
        assert recomputed == seen["challenge"], "PKCE verifier does not match the challenge we sent"
        return {
            "id_token": _id_token(
                {
                    "iss": GOOGLE.issuer,
                    "aud": "client-1",
                    "sub": "110000000000000000001",
                    "email": "barber@example.com",
                    "nonce": seen["nonce"],
                    "exp": int(time.time()) + 600,
                }
            )
        }

    assertion = owner.acquire_owner_assertion(
        GOOGLE, "client-1", identity.did, fetch=fetch, post=post, open_url=open_url, timeout=10
    )
    assert assertion.anchor == {"method": "oidc", "issuer": GOOGLE.issuer, "id": "110000000000000000001"}
    assert assertion.subject == "barber@example.com"
    # The IdP echoed OUR owner-DID commitment back inside the token it signed.
    # That echo is the entire binding between the token and the owner key.
    assert assertion.claims["nonce"] == assertion.nonce
    assert assertion.nonce == seen["nonce"]

    # And the assertion composes into a binding the gate accepts.
    evidence = owner.build_owner_evidence(
        owner=identity,
        subject=assertion.subject,
        anchor=assertion.anchor,
        id_token=assertion.id_token,
        nonce=assertion.nonce,
    )
    grant = owner.build_listing_grant(owner=identity, agent_did=AGENT_DID)
    binding = {
        "owner_did": identity.did,
        "subject": assertion.subject,
        "anchor": assertion.anchor,
        "evidence": evidence,
        "grant": grant,
    }
    assert owner.listing_grant_verdict(binding, AGENT_DID).ok is True


def test_acquire_owner_assertion_refuses_a_state_mismatch():
    identity = owner.mint_owner_identity()

    def fetch(_url):
        return {
            "issuer": GOOGLE.issuer,
            "authorization_endpoint": "https://idp.example/auth",
            "token_endpoint": "https://idp.example/token",
        }

    def open_url(url):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        redirect = query["redirect_uri"][0]
        threading.Thread(target=lambda: urllib.request.urlopen(f"{redirect}?code=C&state=WRONG").read()).start()

    with pytest.raises(ValueError, match="state mismatch"):
        owner.acquire_owner_assertion(
            GOOGLE, "client-1", identity.did, fetch=fetch, post=lambda *_a: {}, open_url=open_url, timeout=10
        )


def test_acquire_owner_assertion_surfaces_a_provider_refusal():
    identity = owner.mint_owner_identity()

    def fetch(_url):
        return {
            "issuer": GOOGLE.issuer,
            "authorization_endpoint": "https://idp.example/auth",
            "token_endpoint": "https://idp.example/token",
        }

    def open_url(url):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        redirect = query["redirect_uri"][0]
        threading.Thread(target=lambda: urllib.request.urlopen(f"{redirect}?error=access_denied").read()).start()

    with pytest.raises(ValueError, match="refused the sign-in"):
        owner.acquire_owner_assertion(
            GOOGLE, "client-1", identity.did, fetch=fetch, post=lambda *_a: {}, open_url=open_url, timeout=10
        )


def test_exchange_code_reports_a_missing_id_token():
    with pytest.raises(ValueError, match="no id_token"):
        owner.exchange_code(
            "https://idp/token",
            client_id="c",
            code="x",
            code_verifier="v",
            redirect_uri="http://127.0.0.1:1/cb",
            post=lambda _u, _d: {"error": "invalid_grant"},
        )


def test_claims_from_id_token_rejects_malformed_tokens():
    for bad in ["", "onlyone", "a.b", "a.b.c.d"]:
        with pytest.raises(ValueError, match="well-formed"):
            owner.claims_from_id_token(bad)
    with pytest.raises(ValueError, match="not decodable"):
        owner.claims_from_id_token("a.!!!!.c")


def test_anchor_prefers_the_durable_claim_over_sub_for_microsoft():
    microsoft = owner.provider_by_id("microsoft")
    anchor = owner.anchor_from_claims(microsoft, {"oid": "the-oid", "sub": "the-sub"})
    assert anchor["id"] == "the-oid"
    # Google's durable anchor is sub, not oid.
    assert owner.anchor_from_claims(GOOGLE, {"sub": "the-sub"})["id"] == "the-sub"


def test_anchor_refuses_a_token_with_no_durable_id():
    with pytest.raises(ValueError, match="no durable anchor"):
        owner.anchor_from_claims(GOOGLE, {"email": "a@b.c"})


# ── what a published listing may assert about the owner ──────────────────────
#
# The gate used to discard the evidence type once it had passed, so an OIDC
# sign-in and a domain-control challenge both produced
# GrantVerdict(True, "ok", "listing authorised by <owner did>") — a detail that
# names the key, not the evidence. Measured before the change, with the binding
# builder above whose subject is barber@example.com and whose anchor is a Google
# OIDC sign-in: ok=True reason='ok' detail='listing authorised by did:key:…',
# evidence block types ['oidc']. A business listing anchored by a personal
# sign-in, indistinguishable downstream from one anchored by domain control.


def _domain_binding(owner_identity, *, domain="operator.example"):
    """A binding whose only evidence is genuine domain control over ``domain``.

    This is the operator-as-owner shape: the challenge really is served, really
    is bound to this owner key, and the domain it proves is the operator's.
    """
    challenge = owner.build_domain_challenge(domain=domain, method=owner.HTTP_01, owner_did=owner_identity.did)
    assertion = owner.DomainAssertion(
        domain=challenge.domain,
        method=challenge.method,
        token=challenge.token,
        key_authorization=challenge.key_authorization,
        anchor={"method": "domain_control", "issuer": challenge.domain, "id": challenge.domain},
    )
    evidence = owner.build_domain_evidence(owner=owner_identity, assertion=assertion)
    return {
        "owner_did": owner_identity.did,
        "subject": challenge.domain,
        "anchor": assertion.anchor,
        "evidence": evidence,
        "grant": owner.build_listing_grant(owner=owner_identity, agent_did=AGENT_DID),
    }


def test_the_gate_reports_which_evidence_anchored_the_listing():
    """The type that satisfied the gate travels out of it.

    Without this a caller cannot tell the two bindings apart, which is the whole
    reason a record could not state what was checked.
    """
    identity = owner.mint_owner_identity()

    oidc = owner.listing_grant_verdict(_binding(identity), AGENT_DID)
    assert oidc.ok is True
    assert oidc.evidence_type == "oidc"
    assert oidc.evidence_anchor == "sub-1"

    domain = owner.listing_grant_verdict(_domain_binding(identity), AGENT_DID)
    assert domain.ok is True
    assert domain.evidence_type == "domain_control"
    assert domain.evidence_anchor == "operator.example"

    assert oidc.evidence_type != domain.evidence_type


def test_a_refused_verdict_reports_no_evidence_type():
    """An evidence type on a refusal would let a caller read one off a rejection."""
    identity = owner.mint_owner_identity()
    verdict = owner.listing_grant_verdict(_binding(identity, evidence=None), AGENT_DID)
    assert verdict.ok is False
    assert verdict.evidence_type == ""
    assert verdict.evidence_anchor == ""


def test_an_oidc_anchored_listing_is_not_domain_verified():
    """A personal sign-in must not produce the business-domain claim.

    Both values are named here so that a future change mapping the evidence type
    straight to an attestation reddens this test by name rather than by a count.
    """
    identity = owner.mint_owner_identity()
    verdict = owner.listing_grant_verdict(_binding(identity), AGENT_DID)

    attestation = owner.owner_attestation(verdict)
    assert attestation != owner.OWNER_DOMAIN_VERIFIED
    assert attestation == owner.OWNER_OPERATOR_VOUCHED


def test_operator_domain_control_is_operator_vouched_not_domain_verified():
    """The case a type lookup gets wrong.

    The evidence is real domain control, so `evidence_type` is `domain_control`.
    The domain proven is the operator's, not the listed business's, so the record
    may not say the business's domain was verified. Anyone who "simplifies" the
    derivation into a lookup of the block type fails here.
    """
    identity = owner.mint_owner_identity()
    verdict = owner.listing_grant_verdict(_domain_binding(identity), AGENT_DID)
    assert verdict.evidence_type == "domain_control"

    attestation = owner.owner_attestation(verdict)
    assert attestation == owner.OWNER_OPERATOR_VOUCHED
    assert attestation != owner.OWNER_DOMAIN_VERIFIED


def test_domain_verified_needs_the_businesss_own_domain():
    """The condition each stronger value requires, stated as a test.

    Not reachable from any caller today — nothing establishes a business domain —
    but it records what would have to be true, so the derivation is a comparison
    rather than a lookup that happens to return the weak value.
    """
    identity = owner.mint_owner_identity()
    verdict = owner.listing_grant_verdict(_domain_binding(identity, domain="thebusiness.example"), AGENT_DID)

    assert owner.owner_attestation(verdict, business_domain="thebusiness.example") == owner.OWNER_DOMAIN_VERIFIED
    # the operator's domain is not the business's, however genuine the evidence
    assert owner.owner_attestation(verdict, business_domain="operator.example") == owner.OWNER_OPERATOR_VOUCHED
    assert owner.owner_attestation(verdict) == owner.OWNER_OPERATOR_VOUCHED


def test_individual_oidc_needs_the_businesss_principal():
    identity = owner.mint_owner_identity()
    verdict = owner.listing_grant_verdict(_binding(identity), AGENT_DID)

    assert owner.owner_attestation(verdict, business_principal="sub-1") == owner.OWNER_INDIVIDUAL_OIDC
    assert owner.owner_attestation(verdict, business_principal="someone-else") == owner.OWNER_OPERATOR_VOUCHED
    assert owner.owner_attestation(verdict) == owner.OWNER_OPERATOR_VOUCHED


def test_a_missing_or_refused_verdict_yields_the_weakest_value():
    """Never absent, never a stronger value on less evidence."""
    identity = owner.mint_owner_identity()
    refused = owner.listing_grant_verdict(_binding(identity, evidence=None), AGENT_DID)

    assert owner.owner_attestation(None) == owner.OWNER_OPERATOR_VOUCHED
    assert owner.owner_attestation(refused) == owner.OWNER_OPERATOR_VOUCHED
