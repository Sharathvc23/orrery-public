"""AgentFacts `provider` names the DEPLOYMENT, never the project that wrote the code.

`provider.url` was hardcoded to `https://projectnanda.org` and `provider.name`
fell back to `"NANDA Community"`, on every member of every self-hosted org. A
stranger resolving a self-hoster's member facts — the richest anonymous surface
this runtime serves — was told the provider was an organisation with
nothing to do with that deployment.

It was an outlier, not a convention: the A2A card already used `PUBLIC_URL`, and
`sm_bridge_adapter`'s own docstring already says *"provider_url = chapter's
PUBLIC_URL"*. Two of three surfaces derived it; one hardcoded it.

⚠️ **`provider.did` is LOAD-BEARING and the block must never disappear.** Member
keys are rehydrated from `agent_facts.provider.did` at boot, and `dsar` and
`agent_export` read it. `D3` asserts that, because "omit what is unknown" applied
one field too far would break key rehydration on every restart.
"""

from __future__ import annotations

import pytest

import sovereign_identity


@pytest.fixture
def org(monkeypatch):
    """An org that declares an id, as every deployment does."""
    monkeypatch.setattr(sovereign_identity, "_agent_id", "acme-co")
    return "acme-co"


def _facts(**kw):
    return sovereign_identity.build_nanda_facts("member-1", {"name": "Member One", "skills": ["wine"]}, **kw)


def test_D1_provider_is_the_hosting_deployment(org) -> None:
    facts = _facts(public_url="https://acme.example")

    assert facts["provider"]["url"] == "https://acme.example"
    assert facts["provider"]["name"] == "acme-co"


def test_D2_no_project_identity_appears_anywhere_in_the_facts(org) -> None:
    """The assertion is about the DOCUMENT, not about one field.

    Checking `provider.url` alone would pass while the same string sat in
    `endpoints`, a skill description or a resolver URL — and what a stranger
    harvests is the document. Searched as text for that reason.
    """
    import json

    body = json.dumps(_facts(public_url="https://acme.example"))

    for foreign in ("projectnanda.org", "NANDA Community"):
        assert foreign not in body, (
            f"a self-hoster's member facts still carry {foreign!r} — an identity the deployment did not choose"
        )


def test_D3_the_provider_block_survives_because_did_is_load_bearing(org) -> None:
    """Omit-what-is-unknown, applied one field too far, would break key
    rehydration on every restart: chapter_agent reads member keys out of
    `agent_facts.provider.did`, and dsar/agent_export read the same path."""
    import base64

    import nacl.signing

    pub = base64.b64encode(bytes(nacl.signing.SigningKey.generate().verify_key)).decode()
    facts = _facts(public_key=pub, public_url="https://acme.example")

    assert "provider" in facts, "the provider block vanished — member key rehydration reads through it"
    assert facts["provider"]["did"].startswith("did:key:")


def test_D4_an_unknown_value_is_ABSENT_not_defaulted(monkeypatch) -> None:
    """A field whose honest value is unknown should be missing, not filled with
    somebody else's. Both directions of every field, so "omit" cannot be
    satisfied by a surface that stopped emitting provider at all — D1 covers the
    populated case."""
    monkeypatch.setattr(sovereign_identity, "_agent_id", "acme-co")
    no_url = _facts()
    assert "url" not in no_url["provider"], "an unset public URL was defaulted rather than omitted"
    assert no_url["provider"]["name"] == "acme-co"

    monkeypatch.setattr(sovereign_identity, "_agent_id", "")
    nothing = _facts()
    assert nothing.get("provider", {}) == {}, "an org that declares nothing must claim nothing"


def test_D5_the_hardcode_is_gone_from_the_source() -> None:
    """Present-then-exercised, in the direction that matters for a hardcoded
    constant: assert its ABSENCE. D1-D4 exercise the derivation, but they would
    all still pass if a second hardcoded default were added on another path."""
    import inspect
    import io
    import tokenize

    src = inspect.getsource(sovereign_identity.build_nanda_facts)

    # Comments stripped before scanning. The comment at the fix site NAMES the
    # old constants, which is the most useful thing it can say — and a naive
    # text scan then reports the explanation as the defect. Strip them and the
    # assertion is about CODE, which is what it was always meant to be.
    code = "".join(
        tok.string if tok.type != tokenize.COMMENT else ""
        for tok in tokenize.generate_tokens(io.StringIO(src).readline)
    )

    for gone in ("projectnanda.org", "NANDA Community"):
        assert gone not in code, f"{gone!r} is back in build_nanda_facts — as code, not as a comment"
    assert "url=public_url or None" in src, "provider.url is no longer derived from the deployment's own URL"


def test_D6_the_A2A_card_and_agentfacts_agree_about_the_provider(monkeypatch) -> None:
    """The two documents describe one org, so they must not disagree about who
    hosts it. They did: the card used PUBLIC_URL and the facts used a constant.
    Asserted across both rather than trusting each in isolation — the same
    two-reads-of-one-identity class as the `did` in that change.
    """
    import importlib
    import sys

    monkeypatch.setenv("AGENT_ID", "acme-co")
    monkeypatch.setenv("AGENT_NAME", "Acme Co")
    sys.modules.pop("chapter_agent", None)
    ca = importlib.import_module("chapter_agent")
    monkeypatch.setattr(ca, "PUBLIC_URL", "https://acme.example")
    monkeypatch.setattr(sovereign_identity, "_agent_id", "acme-co")

    from fastapi.testclient import TestClient

    card = TestClient(ca.app).get("/.well-known/agent.json").json()
    facts = _facts(public_url="https://acme.example")

    assert card["provider"]["url"] == facts["provider"]["url"], (
        "the A2A card and AgentFacts name different providers for one org"
    )
