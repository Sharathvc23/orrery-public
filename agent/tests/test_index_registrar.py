"""Listing one SMB tenant on a NANDA Index: the record, the gate, and the proof.

Three properties this file exists to hold:

* A 201 proves nothing. Success is ``resolve`` returning our record.
* Listing is per business and opt-in, on the vocabulary the stack ALREADY has
  (an owner-signed listing grant), not a second flag with different words.
* Nothing here is reachable from ``smb_host``, which makes no outbound calls.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import httpx
import pytest

from community_member import index_registrar as registrar
from community_member import nanda_index, owner, registry
from community_member.config import Config
from community_member.tenant import AgentContext

DOMAIN = "stellarminds.ai"
CARD_URL = f"https://smb.{DOMAIN}/t/stellar-barbers/.well-known/agent.json"
DID = "did:key:z6MkrFpAWXdELWtJLpfD4YXgjqe7PTGgrHy3e3y2Ja84Gdcb"


def _record(**overrides):
    kwargs = dict(
        tenant_id="stellar-barbers",
        business_name="Stellar Barbers",
        did=DID,
        card_url=CARD_URL,
        domain=DOMAIN,
        contact_email=f"nanda-smb@{DOMAIN}",
        service_type="barber shop",
    )
    kwargs.update(overrides)
    return registrar.build_org_record(**kwargs)


# ── the record says two different things, and keeps them apart ───────────────


def test_the_urn_names_who_vouched_and_the_trust_manifest_names_who_signs():
    """The barber does not own our domain. The record must not imply they do:
    the publisher is the host operator's verified domain, and the tenant's key
    appears only as the identity that signs its receipts.

    The identifier is no longer ours to send — the index derives it from the
    domain it verified — so what is asserted here is that the derivation lands
    on our domain, and that the only publisher field we still send is a display
    name. Sending ``publisher.identifier`` would be a claim a client may not
    make: the index sets it to the bare verified domain itself."""
    record = _record()
    assert "identifier" not in record
    assert registrar.derived_identifier(record) == f"urn:air:{DOMAIN}:agent:stellar-barbers"
    assert record["publisher"] == {"displayName": DOMAIN}
    assert record["trust_manifest"] == {"identity": DID, "identityType": "did"}


def test_each_business_gets_its_own_urn_under_one_domain():
    """The reason for the domain path over the personal one: a personal record is
    anchored to the card host and named after the account email
    (``urn:air:host39.org:personal:<email>``), so a second business under one
    address collides. Under our own domain each business is its own short-name."""
    urns = {
        registrar.derived_identifier(_record(business_name=name, tenant_id=name))
        for name in ("Stellar Barbers", "Copperleaf Dental", "Harbour Yoga")
    }
    assert len(urns) == 3
    assert all(u.startswith(f"urn:air:{DOMAIN}:agent:") for u in urns)


def test_the_card_is_the_target_so_no_registry_surfaces_are_promised():
    """``media_type: a2a-agent-card+json`` means a resolver fetches registry_url
    and is done. ``hosting_path: registry`` would promise ``GET /agents/<id>``
    and an ai-catalog, which live in the chapter server — an smb_host tenant is
    in neither, so such a record would resolve to a 404 on hop two."""
    record = _record()
    assert record["media_type"] == registrar.MEDIA_A2A_CARD
    assert record["registry_url"] == CARD_URL
    assert record["hosting_path"] == "smb"


def test_hosting_path_says_smb_because_that_is_what_this_registers():
    """It was omitted while its effect was unobservable. The index has since
    published what each path does: ``smb`` anchors the identifier to our domain
    and stamps ``resolutionRole: smb-agent-card`` / ``preferredDiscovery:
    nandaindex`` — the two values this record used to assert by hand. So the
    claim did not change, only the field that carries it.

    ``personal`` is still the one we must not send: it anchors the identifier to
    the card host instead of our domain."""
    assert registrar.HOSTING_PATH == "smb"
    assert _record()["hosting_path"] == "smb"
    assert _record(hosting_path="registry")["hosting_path"] == "registry"
    nanda = _record()["extensions"]["org.projectnanda"]
    assert "resolutionRole" not in nanda, "server-owned — the index derives it from hosting_path"
    assert "preferredDiscovery" not in nanda


# ── refuse before the write, not after ───────────────────────────────────────


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"card_url": "http://127.0.0.1:8123/t/x/.well-known/agent.json"}, "not publicly reachable"),
        ({"card_url": "https://localhost/t/x/agent.json"}, "not publicly reachable"),
        ({"card_url": "/t/x/agent.json"}, "not an absolute URL"),
        ({"did": ""}, "is not a did:key"),
        ({"business_name": "!!!", "tenant_id": "!!!"}, "does not match"),
    ],
)
def test_a_record_the_index_would_reject_or_that_would_be_unresolvable_is_named(overrides, expected):
    problems = registrar.record_problems(_record(**overrides))
    assert any(expected in problem for problem in problems), problems


def test_a_loopback_card_url_would_still_have_returned_201():
    """The failure mode worth naming: registering a loopback address on the
    PUBLIC index succeeds at the write and produces a record nobody can resolve.
    The guard is here rather than after the POST for that reason."""
    record = _record(card_url="http://127.0.0.1:8123/t/x/.well-known/agent.json")
    assert registrar.record_problems(record)
    assert registrar.record_problems(_record()) == []


def test_create_org_makes_no_request_at_all_when_the_record_is_bad():
    """FAILURE-MODE GUARD. A rejected POST against a live third party is still a
    request that happened. Any call here is the failure."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"a bad record reached the network: {request.method} {request.url}")

    cfg = registrar.RegistrarConfig(
        base_url="https://index.example", email="a@b.c", password="pw", domain=DOMAIN, contact_email="a@b.c"
    )
    client = registrar.IndexRegistrarClient(cfg=cfg)
    client._client = lambda: httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[method-assign]
    with pytest.raises(registrar.IndexConfigError, match="not publicly reachable"):
        client.create_org(_record(card_url="http://127.0.0.1:9/t/x/agent.json"))


# ── a 201 proves nothing ─────────────────────────────────────────────────────


def test_a_record_that_resolves_but_lost_the_did_is_reported_as_not_listed():
    """No live record carries a did:key, so this is the field most likely to be
    silently dropped — and it is the whole reason for registering."""
    record = _record()
    found = nanda_index.Discovery(
        ok=True, reason="ok", record={"registry_url": CARD_URL, "trust_manifest": None}, did=DID
    )
    problems = registrar.confirmation_problems(record, found)
    assert any("trust_manifest.identity" in p for p in problems), problems


def test_convention_keys_dropped_by_the_write_are_reported():
    """The convention is written and read under one name now
    (``extensions["org.projectnanda"]``), but a key the index drops is still the
    failure that matters — an attestation that did not survive reads as a
    business nobody checked."""
    record = _record()
    found = nanda_index.Discovery(
        ok=True,
        reason="ok",
        record={
            "org_id": record["org_id"],
            "registry_url": CARD_URL,
            "trust_manifest": record["trust_manifest"],
            "extensions": {"org.projectnanda": {}},
        },
        did=DID,
    )
    problems = registrar.confirmation_problems(record, found)
    assert any("did not survive" in p and "ownerAttestation" in p for p in problems), problems


def test_a_publisher_match_is_not_our_record():
    """When no entry holds our identifier the index answers with the PUBLISHER's
    own entry — a 200 describing a different agent. For an a2a-agent-card record
    that is a wrong answer dressed as a right one, so it is named."""
    record = _record()
    found = nanda_index.Discovery(
        ok=True,
        reason="ok",
        match="publisher",
        record={
            "org_id": "someone-elses-org",
            "registry_url": CARD_URL,
            "trust_manifest": record["trust_manifest"],
            "extensions": record["extensions"],
        },
        did=DID,
    )
    problems = registrar.confirmation_problems(record, found)
    assert any("PUBLISHER" in p for p in problems), problems


def test_a_refused_resolve_is_the_whole_answer():
    record = _record()
    found = nanda_index.Discovery(ok=False, reason="not_resolvable", detail="the index does not resolve it")
    problems = registrar.confirmation_problems(record, found)
    assert problems == ["resolve refused: not_resolvable — the index does not resolve it"]


def test_a_clean_confirmation_has_no_problems():
    """The guard has to be able to PASS, or it is only ever asserting failure."""
    record = _record()
    found = nanda_index.Discovery(
        ok=True,
        reason="ok",
        record={
            "org_id": record["org_id"],
            "registry_url": CARD_URL,
            "trust_manifest": record["trust_manifest"],
            "extensions": {"org.projectnanda": dict(record["extensions"]["org.projectnanda"])},
        },
        did=DID,
    )
    assert registrar.confirmation_problems(record, found) == []


# ── opt-in, on the vocabulary that already existed ───────────────────────────


@pytest.fixture
def two_tenants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Two provisioned tenants in one runtime, each in its own home."""
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    homes = {}
    for name in ("stellar-barbers", "copperleaf-dental"):
        home = tmp_path / name
        ctx = AgentContext.load(home)
        ctx.ensure_identity(name)
        homes[name] = home
    return homes


def _grant_listing_to(home: Path) -> owner.OwnerIdentity:
    """The host operator vouches for one tenant, on domain-control evidence for
    the domain it actually controls."""
    operator = owner.mint_owner_identity()
    challenge = owner.build_domain_challenge(DOMAIN, owner.DNS_01, operator.did)
    assertion = owner.verify_domain_challenge(
        challenge, operator.did, dns_txt=lambda name: [challenge.key_authorization]
    )
    evidence = owner.build_domain_evidence(owner=operator, assertion=assertion)
    agent_did = registry.agent_did_key(Config.load(home=home))
    grant = owner.build_listing_grant(owner=operator, agent_did=agent_did)
    owner.save_binding(
        home, owner_did=operator.did, subject=DOMAIN, anchor=assertion.anchor, evidence=evidence, grant=grant
    )
    return operator


def test_a_freshly_provisioned_tenant_is_refused_by_name(two_tenants):
    """Default false, and the refusal says which check refused — 'not ok' with
    no reason is how a gate ends up silently protecting nothing."""
    refusal = registrar.listing_refusal(two_tenants["stellar-barbers"])
    assert refusal is not None
    assert "no_owner_consent" in refusal


def test_a_grant_authorises_exactly_one_business(two_tenants):
    """NO INHERITANCE, and it is unrepresentable rather than merely forbidden: a
    grant names ONE grantee did, so copying it verbatim onto a sibling fails on
    the identity, not on a rule someone could forget to write."""
    barbers, dental = two_tenants["stellar-barbers"], two_tenants["copperleaf-dental"]
    _grant_listing_to(barbers)
    assert registrar.listing_refusal(barbers) is None

    shutil.copy(owner.binding_path(barbers), owner.binding_path(dental))
    refusal = registrar.listing_refusal(dental)
    assert refusal is not None and "grantee_mismatch" in refusal


def test_withdrawal_is_its_own_answer_not_an_absence(two_tenants):
    barbers = two_tenants["stellar-barbers"]
    operator = _grant_listing_to(barbers)
    owner.revoke_listing(barbers, reason="the owner withdrew", owner=operator)
    refusal = registrar.listing_refusal(barbers)
    assert refusal is not None and "revoked" in refusal


def test_the_hard_opt_out_overrides_even_a_valid_grant(two_tenants, monkeypatch):
    """Opt-out and opt-in are not two competing flags here: the grant is the
    opt-in, and ``COMMUNITY_MEMBER_NO_REGISTRY`` is a veto layered on top."""
    barbers = two_tenants["stellar-barbers"]
    _grant_listing_to(barbers)
    assert registrar.listing_refusal(barbers) is None
    monkeypatch.setenv("COMMUNITY_MEMBER_NO_REGISTRY", "1")
    refusal = registrar.listing_refusal(barbers)
    assert refusal is not None and "COMMUNITY_MEMBER_NO_REGISTRY" in refusal


# ── the host stays callout-free ──────────────────────────────────────────────


def test_smb_host_imports_neither_the_registrar_nor_discovery():
    """``smb_host`` asserts that it makes no outbound calls. Listing is a
    SEPARATE CALLER for that reason — if either module became reachable from the
    host, the property would end quietly."""
    source = (Path(__file__).resolve().parents[2] / "smb_host" / "main.py").read_text()
    assert "index_registrar" not in source
    assert "nanda_index" not in source
    assert "httpx" not in source


# ── the record states what was checked about the owner ───────────────────────
#
# The record separated "who vouched" (the operator's verified domain) from "who
# signs" (the tenant's key) and said nothing about how the business itself was
# verified, so a listing authorised by a personal Google sign-in and one
# authorised by control of the business's own domain were byte-identical in that
# respect.

ATTESTATION_KEY = "ownerAttestation"


def test_every_record_carries_an_owner_attestation():
    """Always present. Absent-and-valid is not a state this field has.

    A reader who does not find it cannot tell "nobody checked" from "the writer
    forgot", so a record without it must not be reachable — including the record
    built with no verdict at all, which is the dry-run and the
    registering-from-another-machine shape.
    """
    from community_member import owner

    for record in (_record(), _record(service_type=None), _record(version="0.9.0"), _record(hosting_path=None)):
        assert ATTESTATION_KEY in record["extensions"]["org.projectnanda"]
        assert record["extensions"]["org.projectnanda"][ATTESTATION_KEY] == owner.OWNER_OPERATOR_VOUCHED


def test_no_caller_can_set_the_attestation():
    """The value is derived from evidence, not supplied alongside it.

    build_org_record takes the gate's verdict, which carries evidence. It takes
    no parameter that names an attestation, and an attempt to pass one is a
    TypeError rather than an override — a guard a caller can talk past is
    decoration.
    """
    import inspect

    from community_member import owner

    parameters = set(inspect.signature(registrar.build_org_record).parameters)
    assert "owner_attestation" not in parameters
    assert not any("attestation" in name for name in parameters), sorted(parameters)

    with pytest.raises(TypeError):
        _record(owner_attestation="domain_verified")

    # and the one parameter that does influence it carries evidence, not a verdict
    # about the business: an operator-domain-control verdict still reads as vouched
    identity = owner.mint_owner_identity()
    challenge = owner.build_domain_challenge(domain=DOMAIN, method=owner.HTTP_01, owner_did=identity.did)
    assertion = owner.DomainAssertion(
        domain=challenge.domain,
        method=challenge.method,
        token=challenge.token,
        key_authorization=challenge.key_authorization,
        anchor={"method": "domain_control", "issuer": challenge.domain, "id": challenge.domain},
    )
    binding = {
        "owner_did": identity.did,
        "subject": challenge.domain,
        "anchor": assertion.anchor,
        "evidence": owner.build_domain_evidence(owner=identity, assertion=assertion),
        "grant": owner.build_listing_grant(owner=identity, agent_did=DID),
    }
    verdict = owner.listing_grant_verdict(binding, DID)
    assert verdict.evidence_type == "domain_control"

    record = _record(grant_verdict=verdict)
    assert record["extensions"]["org.projectnanda"][ATTESTATION_KEY] == owner.OWNER_OPERATOR_VOUCHED


def test_the_operators_domain_is_never_read_as_the_businesss():
    """The record's `domain` is the operator's, and must not reach the derivation.

    It is what the publisher block and the identifier are built from. Handing it
    to the derivation as the business's domain would manufacture a
    domain_verified claim on a record where nothing about that business's domain
    was checked, which is the substitution this field exists to prevent.
    """
    from community_member import owner

    record = _record()
    assert record["publisher"] == {"displayName": DOMAIN}
    assert registrar.derived_identifier(record).startswith(f"urn:air:{DOMAIN}:agent:")
    assert record["extensions"]["org.projectnanda"][ATTESTATION_KEY] != owner.OWNER_DOMAIN_VERIFIED
