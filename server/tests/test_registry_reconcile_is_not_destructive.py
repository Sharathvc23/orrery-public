"""Boot does not delete, and an endpoint match is not identity.

`clean_stale_agents` ran unconditionally in the startup path and issued
`DELETE {registry}/api/agents/{id}` for every registry record whose `endpoint`
string equalled ours and whose id was not one of our members. Measured against a
real boot with a registry that answered `200`: **two DELETEs, for records that
were not ours**, logged as *"NEST cleaned 2 stale agents"*. It fired with
`AUTO_REGISTER=false`.

Two independent defects, and fixing only one leaves a live hazard:

  **D — destructive at boot.** Removal is now an explicit operator act. Nothing
  in the startup path passes `delete=True`.
  **I — an endpoint-string match is not identity.** Two orgs behind one hostname
  (a shared host, a reverse proxy, a redeployment that reused a name) both match,
  and each would delete the other's records. Attribution is now either *we
  published it this process* or *it carries our signed endpoint attestation*,
  whose `did` IS our public key.

⚠️ **"Do not delete" must not be satisfied by a function that stopped looking.**
`R1`/`R2` assert the reconciliation still finds and still classifies, because a
no-op would pass every assertion about not deleting.
"""

from __future__ import annotations

import base64

import pytest

import nanda_registry
import registry_attestation
import sovereign_identity

_ENDPOINT = "https://shared-host.example"


class FakeRegistry:
    """Records every call; answers the listing with whatever the test planted."""

    def __init__(self, agents):
        self.agents = agents
        self.calls: list[tuple[str, str]] = []

    def __call__(self, *a, **k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **k):
        self.calls.append(("GET", str(url)))
        return _Resp(200, {"agents": self.agents})

    async def delete(self, url, **k):
        self.calls.append(("DELETE", str(url)))
        return _Resp(200, {})

    @property
    def deletes(self) -> list[str]:
        return [u for m, u in self.calls if m == "DELETE"]


class _Resp:
    def __init__(self, code, payload):
        self.status_code, self._p = code, payload

    def json(self):
        return self._p


@pytest.fixture
def org(monkeypatch):
    """An org with a real signing key, wired to a registry."""
    monkeypatch.setattr(nanda_registry, "_registry_url", "https://registry.test.invalid")
    monkeypatch.setattr(nanda_registry, "_agent_id", "our-org")
    monkeypatch.setattr(nanda_registry, "_members", {"member-a": {}})
    monkeypatch.setattr(nanda_registry, "_index_urls", [])
    nanda_registry.registered_on_nest.clear()
    sovereign_identity.generate_ed25519_keypair("our-org")
    yield "our-org"
    sovereign_identity._ed25519_keypairs.pop("our-org", None)
    nanda_registry.registered_on_nest.clear()


def _attested(subject: str, signer: str) -> dict:
    """A registry record carrying a real signed attestation from `signer`."""
    return {
        "id": subject,
        "endpoint": _ENDPOINT,
        "attestation": registry_attestation.build(subject, _ENDPOINT, signer),
    }


def _install(monkeypatch, agents) -> FakeRegistry:
    reg = FakeRegistry(agents)
    monkeypatch.setattr(nanda_registry.httpx, "AsyncClient", reg)
    return reg


# ---------------------------------------------------------------------------
# D — boot does not delete
# ---------------------------------------------------------------------------


async def test_D1_the_default_is_report_only(org, monkeypatch) -> None:
    """Even for records that ARE ours. The default has to be safe for the
    startup caller, not merely safe for the case where nothing matched."""
    nanda_registry.registered_on_nest.add("stale-of-ours")
    reg = _install(monkeypatch, [{"id": "stale-of-ours", "endpoint": _ENDPOINT}])

    report = await nanda_registry.reconcile_stale_agents(_ENDPOINT)

    assert reg.deletes == [], "the default path deleted something"
    assert [r["id"] for r in report["ours"]] == ["stale-of-ours"], (
        "it stopped LOOKING — 'do not delete' must not be satisfied by a function that found nothing"
    )
    assert report["deleted"] == []


def test_D2_the_boot_path_does_not_ask_for_deletion(org) -> None:
    """Present, not just exercised. D1 shows the default is safe; this shows the
    startup caller uses the default — the two are different claims, and the
    original defect was entirely in the second."""
    import inspect
    import io
    import tokenize

    import chapter_agent

    src = inspect.getsource(chapter_agent.lifespan)
    # Comments stripped: the comment at the call site NAMES the operator form
    # (`delete=True`) so the next reader knows deletion still exists and where —
    # and a naive scan then reports that explanation as the defect. Same trap as
    # the provider hardcode guard in that change, and the same fix.
    code = "".join(
        t.string if t.type != tokenize.COMMENT else ""
        for t in tokenize.generate_tokens(io.StringIO(src).readline)
    )

    assert "reconcile_stale_agents(PUBLIC_URL)" in code, "boot no longer reconciles at all"
    assert "delete=True" not in code, "the startup path asks for deletion"
    assert "clean_stale_agents" not in code, "the destructive function is back in the boot path"


async def test_D3_an_explicit_operator_request_still_deletes(org, monkeypatch) -> None:
    """The capability is not removed, only its trigger. Asserting only D1 would
    be satisfied by deleting the feature, which is a different change."""
    nanda_registry.registered_on_nest.add("stale-of-ours")
    reg = _install(monkeypatch, [{"id": "stale-of-ours", "endpoint": _ENDPOINT}])

    report = await nanda_registry.reconcile_stale_agents(_ENDPOINT, delete=True)

    assert reg.deletes == ["https://registry.test.invalid/api/agents/stale-of-ours"]
    assert report["deleted"] == ["stale-of-ours"]


# ---------------------------------------------------------------------------
# I — an endpoint match is not identity
# ---------------------------------------------------------------------------


async def test_I1_a_stranger_sharing_our_endpoint_is_never_deleted(org, monkeypatch) -> None:
    """THE MEASURED DEFECT. Two orgs behind one hostname is not exotic — a shared
    host, a reverse proxy, or a redeployment that reused a name produces it — and
    each would have deleted the other's records at boot."""
    reg = _install(monkeypatch, [{"id": "somebody-else", "endpoint": _ENDPOINT}])

    report = await nanda_registry.reconcile_stale_agents(_ENDPOINT, delete=True)

    assert reg.deletes == [], "a record that merely shares our endpoint was deleted"
    assert report["not_ours"][0]["id"] == "somebody-else"
    assert "nothing attributes it to us" in report["not_ours"][0]["why"]


async def test_I2_another_orgs_valid_attestation_is_not_ours(org, monkeypatch) -> None:
    """A real, correctly-signed attestation — from the wrong key. Verifying the
    signature is not the check; verifying it is OUR signature is."""
    sovereign_identity.generate_ed25519_keypair("other-org")
    try:
        reg = _install(monkeypatch, [_attested("their-agent", "other-org")])

        report = await nanda_registry.reconcile_stale_agents(_ENDPOINT, delete=True)

        assert reg.deletes == []
        assert report["not_ours"][0]["why"] == "attested by a different org"
    finally:
        sovereign_identity._ed25519_keypairs.pop("other-org", None)


async def test_I3_our_own_attestation_survives_a_restart(org, monkeypatch) -> None:
    """The check that matters after a reboot. `registered_on_nest` is in-memory
    and empty on a fresh boot, so attribution would fall back to nothing — the
    attestation is what still ties the record to this org, because its `did` IS
    this org's public key."""
    nanda_registry.registered_on_nest.clear()  # as after a restart
    reg = _install(monkeypatch, [_attested("ours-from-before", "our-org")])

    report = await nanda_registry.reconcile_stale_agents(_ENDPOINT, delete=True)

    assert [r["why"] for r in report["ours"]] == ["attested by this org's key"]
    assert reg.deletes == ["https://registry.test.invalid/api/agents/ours-from-before"]


async def test_I4_a_forged_attestation_is_refused(org, monkeypatch) -> None:
    """Tamper the signed record and the signature stops verifying, so the record
    stops being ours. Without this, 'carries an attestation' would be the check
    rather than 'carries one that verifies'."""
    record = _attested("forged", "our-org")
    record["attestation"]["record"]["agent_id"] = "forged-different"
    reg = _install(monkeypatch, [record])

    report = await nanda_registry.reconcile_stale_agents(_ENDPOINT, delete=True)

    assert reg.deletes == []
    assert "does not verify" in report["not_ours"][0]["why"]


async def test_I5_the_did_in_the_attestation_is_this_org_signing_key(org) -> None:
    """The link the whole attribution rests on, asserted rather than assumed: the
    attestation's `did` is derived from the same key `/.well-known/did.json`
    publishes, so a record attesting it could only come from something holding
    this org's private key."""
    att = registry_attestation.build("x", _ENDPOINT, "our-org")
    kp = sovereign_identity._ed25519_keypairs["our-org"]
    expected = sovereign_identity.build_did_key_from_ed25519(base64.b64encode(kp["public_key"]).decode())

    assert att["record"]["did"] == expected
    assert nanda_registry._our_did() == expected


# ---------------------------------------------------------------------------
# R — it still reconciles
# ---------------------------------------------------------------------------


async def test_R1_the_report_classifies_every_candidate(org, monkeypatch) -> None:
    """A mixed registry, so the classification is exercised rather than a single
    branch. If reconciliation were quietly gutted, `candidates` would be empty
    and every not-deleted assertion above would still pass."""
    sovereign_identity.generate_ed25519_keypair("other-org")
    nanda_registry.registered_on_nest.add("published-by-us")
    try:
        _install(
            monkeypatch,
            [
                {"id": "published-by-us", "endpoint": _ENDPOINT},
                _attested("attested-by-us", "our-org"),
                _attested("attested-by-them", "other-org"),
                {"id": "stranger", "endpoint": _ENDPOINT},
                {"id": "elsewhere", "endpoint": "https://other-host.example"},
                {"id": "member-a", "endpoint": _ENDPOINT},
            ],
        )

        report = await nanda_registry.reconcile_stale_agents(_ENDPOINT)

        assert set(report["candidates"]) == {"published-by-us", "attested-by-us", "attested-by-them", "stranger"}
        assert {r["id"] for r in report["ours"]} == {"published-by-us", "attested-by-us"}
        assert {r["id"] for r in report["not_ours"]} == {"attested-by-them", "stranger"}
    finally:
        sovereign_identity._ed25519_keypairs.pop("other-org", None)


async def test_R2_a_current_member_and_a_foreign_endpoint_are_not_candidates(org, monkeypatch) -> None:
    """The two exclusions that were correct before and must stay: a live member is
    not stale, and a record pointing somewhere else was never ours to reason about."""
    _install(
        monkeypatch,
        [{"id": "member-a", "endpoint": _ENDPOINT}, {"id": "elsewhere", "endpoint": "https://other.example"}],
    )

    report = await nanda_registry.reconcile_stale_agents(_ENDPOINT)

    assert report["candidates"] == []


async def test_R3_no_registry_configured_is_a_quiet_no_op(monkeypatch) -> None:
    monkeypatch.setattr(nanda_registry, "_registry_url", "")
    monkeypatch.setattr(nanda_registry, "_index_urls", [])

    report = await nanda_registry.reconcile_stale_agents(_ENDPOINT, delete=True)

    assert report["candidates"] == [] and report["deleted"] == []
