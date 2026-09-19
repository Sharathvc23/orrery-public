"""Tests for sovereign-agent auto-launch on a public registry (NEST + NANDA Index)."""

import asyncio
import base64
import json

import httpx
import pytest

from community_member import config as config_mod
from community_member import owner, registry
from community_member.config import Config


@pytest.fixture(autouse=True)
def _clean_registry_env(monkeypatch, tmp_path):
    """Isolate from ambient registry env so call-counting tests are stable.

    Also pins the config home to a tmp dir: publication is now gated on an
    owner-consent file under ``config.home``, and a suite that read the
    developer's real ``~/.community-member`` would pass or fail depending on
    whose machine it ran on.
    """
    monkeypatch.delenv("NANDA_INDEX_URL", raising=False)
    monkeypatch.delenv("AGENT_PUBLIC_URL", raising=False)
    # Unset REGISTRY_URL means "publish nowhere" (see registry_url), so the
    # tests that exercise the HTTP path name a registry explicitly. The
    # default-behaviour tests below delete it again.
    monkeypatch.setenv("REGISTRY_URL", "https://registry.example")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)


def _cfg(**over) -> Config:
    c = Config()
    c.agent_id = over.get("agent_id", "alice-agent")
    c.name = over.get("name", "Alice")
    c.description = over.get("description", "A test human")
    c.skills = over.get("skills", ["calendar", "email"])
    c.api_key = over.get("api_key", "sk-test")  # makes is_configured() true
    c.public_key = over.get("public_key", base64.b64encode(b"\x01" * 32).decode())
    return c


def _consent(cfg: Config, *, grantee_did: str | None = None) -> str:
    """Write a real owner-signed listing consent for ``cfg``. Returns the owner did."""
    owner_identity = owner.mint_owner_identity()
    agent_did = grantee_did or registry.agent_did_key(cfg)
    nonce = owner.owner_nonce(owner_identity.did, "test-randomness")
    anchor = {"method": "oidc", "issuer": "https://accounts.google.com", "id": "sub-abc"}
    owner.save_binding(
        cfg.home,
        owner_did=owner_identity.did,
        subject="alice@example.com",
        anchor=anchor,
        evidence=owner.build_owner_evidence(
            owner=owner_identity,
            subject="alice@example.com",
            anchor=anchor,
            id_token="header.payload.signature",
            nonce=nonce,
        ),
        grant=owner.build_listing_grant(owner=owner_identity, agent_did=agent_did),
    )
    return owner_identity.did


def _consented_cfg(**over) -> Config:
    """A config that IS authorised to publish — for the announce-path tests.

    Publication requires consent now, so a test that wants to exercise the HTTP
    behaviour has to establish an owner first. Spelling that out here keeps
    those tests about the network and not about the gate.
    """
    cfg = _cfg(**over)
    _consent(cfg)
    return cfg


# ── config knobs ────────────────────────────────────────────────────


def test_registry_url_has_no_default(monkeypatch):
    """Unset means NO registry — the same rule as ``server/registry_policy``.

    This assertion used to read ``== "https://nest.projectnanda.org"``: a
    consenting owner who named no registry was published to a directory run by
    somebody else. If it ever reads that way again, the agent reaches for a
    third party on its own authority.
    """
    monkeypatch.delenv("REGISTRY_URL", raising=False)
    assert registry.registry_url() == ""
    assert registry.publication_targets() == []


def test_the_former_default_is_kept_only_to_be_named(monkeypatch):
    monkeypatch.delenv("REGISTRY_URL", raising=False)
    assert registry.FORMER_DEFAULT_REGISTRY_URL == "https://nest.projectnanda.org"
    assert registry.registry_url() != registry.FORMER_DEFAULT_REGISTRY_URL


def test_registry_url_override_strips_slash(monkeypatch):
    monkeypatch.setenv("REGISTRY_URL", "https://reg.example.com/")
    assert registry.registry_url() == "https://reg.example.com"


def test_registry_url_empty_means_do_not_publish(monkeypatch):
    """One variable name, one meaning across the repo.

    ``server/registry_policy.registry_url`` already treats an explicitly empty
    REGISTRY_URL as "do not publish" (after empty silently meant LIVE and
    wrote 31 phantom records). The agent module must not hold the opposite
    convention for the same name.
    """
    monkeypatch.setenv("REGISTRY_URL", "")
    assert registry.registry_url() == ""
    monkeypatch.setenv("REGISTRY_URL", "   ")
    assert registry.registry_url() == ""


def test_registry_url_unset_and_empty_are_the_same_answer(monkeypatch):
    """Both mean "none". Kept as two cases because compose's ``${VAR:-default}``
    substitutes for an EMPTY value too — the reason the default had to leave
    the code, not a compose file."""
    monkeypatch.delenv("REGISTRY_URL", raising=False)
    unset = registry.registry_url()
    monkeypatch.setenv("REGISTRY_URL", "")
    assert registry.registry_url() == unset == ""


async def test_register_nest_is_a_clean_noop_when_publication_disabled():
    """An empty base must not reach httpx at all.

    Previously ``f"{base}/api/agents"`` produced the relative URL
    ``/api/agents``, which raises inside httpx and was swallowed by the caller's
    bare ``except Exception`` — so "operator disabled publication" was
    indistinguishable from "the registry is down".
    """

    class _ExplodingClient:
        async def post(self, *a, **k):
            raise AssertionError("must not issue a request when REGISTRY_URL is empty")

        async def put(self, *a, **k):
            raise AssertionError("must not issue a request when REGISTRY_URL is empty")

    ok = await registry._register_nest(_ExplodingClient(), "", "agent-1", {}, "https://example.com")
    assert ok is False


def test_public_endpoint_defaults_to_local(monkeypatch):
    monkeypatch.delenv("AGENT_PUBLIC_URL", raising=False)
    assert registry.public_endpoint("http://localhost:7778") == "http://localhost:7778"


def test_public_endpoint_override(monkeypatch):
    monkeypatch.setenv("AGENT_PUBLIC_URL", "https://me.example.com/")
    assert registry.public_endpoint("http://localhost:7778") == "https://me.example.com"


def test_opt_out(monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_NO_REGISTRY", "1")
    assert registry.is_opted_out() is True
    monkeypatch.setenv("COMMUNITY_MEMBER_NO_REGISTRY", "no")
    assert registry.is_opted_out() is False


# ── gating ──────────────────────────────────────────────────────────


def test_should_announce_requires_owner_consent(monkeypatch):
    """⚠️ THE SELF-REGISTRATION REMOVAL REGRESSION GUARD. Before this gate, a configured agent
    published itself to the live public NEST automatically, on opt-out
    semantics, with no consent artifact — i.e. Orrery registered a real person
    on its own authority. This test is the assertion that used to read
    ``is True``. If it ever flips back, that crossing is live again."""
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    cfg = _cfg()
    assert registry.should_announce(cfg) is False
    assert registry.consent_verdict(cfg).reason == "no_owner_consent"


def test_should_announce_with_owner_consent(monkeypatch):
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    cfg = _cfg()
    _consent(cfg)
    assert registry.should_announce(cfg) is True


def test_owner_key_is_not_the_agent_did_key(monkeypatch):
    """The separation, asserted rather than left incidental.

    A grant signed by the agent's own key would pass grant verification, field
    scope and precedence while proving nothing — grantor and grantee would be
    one key. So the owner did MUST differ from the agent did:key.
    """
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    cfg = _cfg()
    owner_did = _consent(cfg)
    agent_did = registry.agent_did_key(cfg)
    assert agent_did
    assert owner_did != agent_did
    binding = owner.load_binding(cfg.home)
    assert binding["grant"]["grantor_did"] == owner_did
    assert binding["grant"]["grantee_did"] == agent_did


def test_owner_private_key_is_never_persisted(monkeypatch):
    """Nothing on disk under the agent home may contain the owner signing key.

    Checked as a substring sweep over every file, not just the binding: the
    claim is "the runtime cannot load it", and that only holds if it is absent
    from the filesystem rather than merely absent from one JSON document.
    """
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    cfg = _cfg()
    owner_identity = owner.mint_owner_identity()
    agent_did = registry.agent_did_key(cfg)
    nonce = owner.owner_nonce(owner_identity.did, "r")
    anchor = {"method": "oidc", "issuer": "https://accounts.google.com", "id": "sub-1"}
    owner.save_binding(
        cfg.home,
        owner_did=owner_identity.did,
        subject="alice@example.com",
        anchor=anchor,
        evidence=owner.build_owner_evidence(
            owner=owner_identity, subject="a@b.c", anchor=anchor, id_token="h.p.s", nonce=nonce
        ),
        grant=owner.build_listing_grant(owner=owner_identity, agent_did=agent_did),
    )
    cfg.save()
    secret = owner_identity.private_key_b64
    phrase_word = owner_identity.mnemonic.split()[0]
    for path in cfg.home.rglob("*"):
        if not path.is_file():
            continue
        blob = path.read_bytes()
        assert secret.encode() not in blob, f"owner private key leaked into {path.name}"
        assert owner_identity.mnemonic.encode() not in blob, f"owner phrase leaked into {path.name}"
    assert phrase_word  # the phrase existed at all — the sweep above is meaningful


def test_should_announce_refuses_a_self_granted_consent(monkeypatch):
    """⚠️ The check verification does NOT make.

    ``_dat`` accepts a grant whose grantor is its own grantee (measured — see
    ``test_owner.py``), so a self-granted consent passes signature, scope and
    chain verification. The refusal has to be explicit, and this is it.
    """
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    cfg = _cfg()
    agent_did = registry.agent_did_key(cfg)
    # Sign a consent with a key whose did IS the grantee — self-delegation.
    owner_identity = owner.mint_owner_identity()
    from community_member._dat import build_dat

    self_grant = build_dat(
        grantor_sk_bytes=owner_identity.signing_key_bytes(),
        grantor_did=owner_identity.did,
        grantee_did=owner_identity.did,
        action_categories=[owner.LISTING_ACTION_CATEGORY],
        not_after="2099-01-01T00:00:00Z",
    )
    nonce = owner.owner_nonce(owner_identity.did, "r")
    anchor = {"method": "oidc", "issuer": "https://accounts.google.com", "id": "sub-1"}
    owner.save_binding(
        cfg.home,
        owner_did=owner_identity.did,
        subject="a@b.c",
        anchor=anchor,
        evidence=owner.build_owner_evidence(
            owner=owner_identity, subject="a@b.c", anchor=anchor, id_token="h.p.s", nonce=nonce
        ),
        grant=self_grant,
    )
    assert registry.consent_verdict(cfg).reason == "self_grant"
    assert registry.should_announce(cfg) is False
    # And the same binding presented to the agent it names is still refused.
    cfg_self = _cfg()
    assert registry.consent_verdict(cfg_self).reason == "self_grant"
    assert agent_did  # sanity: the real agent identity exists and is not the grantee


def test_should_announce_refuses_consent_issued_to_another_agent(monkeypatch):
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    cfg = _cfg()
    other_did = owner.mint_owner_identity().did
    _consent(cfg, grantee_did=other_did)
    assert registry.consent_verdict(cfg).reason == "grantee_mismatch"
    assert registry.should_announce(cfg) is False


def test_should_announce_gated_when_opted_out(monkeypatch):
    """Opt-out still wins over a valid consent — consent permits, it never compels."""
    monkeypatch.setenv("COMMUNITY_MEMBER_NO_REGISTRY", "true")
    assert registry.should_announce(_consented_cfg()) is False


def test_should_announce_gated_for_test_prefix(monkeypatch):
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    assert registry.should_announce(_consented_cfg(agent_id="TEST-probe")) is False


def test_should_announce_gated_when_unconfigured(monkeypatch):
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    assert registry.should_announce(_cfg(agent_id="", api_key="")) is False


# ── payload ─────────────────────────────────────────────────────────


def test_build_payload_shape():
    p = registry.build_payload(_cfg(), "https://me.example.com")
    assert p["agent_id"] == "alice-agent"
    assert p["name"] == "Alice"
    assert p["endpoint"] == "https://me.example.com"
    assert p["facts_url"] == "https://me.example.com/agentfacts.json"
    assert p["capabilities"] == ["calendar", "email"]
    assert p["agent_type"] == "skill"
    assert p["status"] == "running"
    assert p["did_key"].startswith("did:key:z")


def test_build_payload_did_matches_canonical_agentfacts():
    """The NEST did:key is the same canonical did the agent serves in AgentFacts."""
    facts = registry.build_facts(_cfg(), "https://me.example.com")
    p = registry.build_payload(_cfg(), "https://me.example.com")
    assert p["did_key"] == facts["id"]
    assert p["did_key"].startswith("did:key:z")


def test_build_payload_did_web_fallback_without_ed25519():
    """No Ed25519 key -> a did:web fallback (always a DID), not an omission."""
    p = registry.build_payload(_cfg(public_key=""), "https://me.example.com")
    assert p["did_key"].startswith("did:web:")


# ── announce ────────────────────────────────────────────────────────


async def test_announce_post_success(monkeypatch):
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        return httpx.Response(201, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ok = await registry.announce(_consented_cfg(), local_url="http://localhost:7778", client=client)
    await client.aclose()
    assert ok is True
    assert seen == {"method": "POST", "path": "/api/agents"}


async def test_announce_falls_back_to_put_on_conflict(monkeypatch):
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            return httpx.Response(409, json={"error": "exists"})
        return httpx.Response(200, json={"updated": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ok = await registry.announce(_consented_cfg(), local_url="http://localhost:7778", client=client)
    await client.aclose()
    assert ok is True
    assert calls == [("POST", "/api/agents"), ("PUT", "/api/agents/alice-agent")]


async def test_announce_swallows_network_error(monkeypatch):
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("registry down")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ok = await registry.announce(_consented_cfg(), local_url="http://localhost:7778", client=client)
    await client.aclose()
    assert ok is False


async def test_announce_short_circuits_when_opted_out(monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_NO_REGISTRY", "1")
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(201)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ok = await registry.announce(_consented_cfg(), local_url="http://localhost:7778", client=client)
    await client.aclose()
    assert ok is False
    assert called["n"] == 0


async def test_announce_without_owner_consent_sends_nothing(monkeypatch):
    """The consent record is the owner-signed listing grant under config.home.
    With none on file — and a registry AND an index configured — announce()
    must not open a single request. Asserted on the wire, not on the boolean."""
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    monkeypatch.setenv("NANDA_INDEX_URL", "https://index.example.com")
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(201)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ok = await registry.announce(_cfg(), local_url="http://localhost:7778", client=client)
    await client.aclose()
    assert ok is False
    assert called["n"] == 0


async def test_announce_with_consent_but_no_target_sends_nothing(monkeypatch):
    """Consent answers WHETHER; the owner's configuration answers WHERE. With
    consent on file and neither REGISTRY_URL nor NANDA_INDEX_URL set, there is
    nowhere to publish and nothing leaves the machine."""
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    monkeypatch.delenv("REGISTRY_URL", raising=False)
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(201)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ok = await registry.announce(_consented_cfg(), local_url="http://localhost:7778", client=client)
    await client.aclose()
    assert ok is False
    assert called["n"] == 0


async def test_announce_loop_returns_at_once_when_no_target_and_says_so(monkeypatch, capsys):
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    monkeypatch.delenv("REGISTRY_URL", raising=False)
    # Bounded: if a default registry ever came back, the loop would have a
    # target and run forever — which must read as a failure, not a hang.
    await asyncio.wait_for(
        registry.announce_loop(_consented_cfg(), local_url="http://localhost:7778", interval=1), timeout=2
    )
    out = capsys.readouterr().out
    assert "publishes to no registry" in out
    assert registry.FORMER_DEFAULT_REGISTRY_URL in out


# ── NANDA Index (the full-AgentFacts discovery layer) ───────────────


async def test_announce_also_registers_nanda_index(monkeypatch):
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    monkeypatch.setenv("NANDA_INDEX_URL", "https://index.example.com")
    seen: dict = {"nest": None, "index": None}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        if request.url.host == "index.example.com":
            seen["index"] = body
        else:
            seen["nest"] = body
        return httpx.Response(201, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ok = await registry.announce(_consented_cfg(), local_url="http://localhost:7778", client=client)
    await client.aclose()

    assert ok is True
    # NEST got the flat directory record...
    assert seen["nest"]["agent_id"] == "alice-agent"
    assert seen["nest"]["did_key"].startswith("did:key:z")
    # ...the NANDA Index got the FULL canonical AgentFacts under "facts".
    assert seen["index"]["agent_id"] == "alice-agent"
    assert seen["index"]["facts"]["id"] == seen["nest"]["did_key"]
    assert seen["index"]["facts"]["agent_name"] == "alice-agent"
    assert seen["index"]["facts_url"].endswith("/agentfacts.json")
