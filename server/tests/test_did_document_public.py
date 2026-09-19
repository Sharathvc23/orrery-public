"""The public-discovery rule — /.well-known/did.json is public, and reading it never mints an identity.

Two separate claims, and the investigation found them in opposite states — which
is why they are tested separately rather than as one "fix".

**The path is open, and that is now explicit.** Reported as a 401. It does not
reproduce: Orrery serves this document 200 under both `ORRERY_PROFILE=dev` and
`prod`, because unlisted GETs default to open in this middleware. The reported
live 401 came from a host that is not an Orrery org server (its `/health` is
`{"status":"ok","version":"0.0.1","environment":"production"}` and its `/version`
demands a bearer token — neither is this runtime's shape). So there was no
regression to fix. What was missing is the *reason*: the path's openness was
implicit, and load-bearing in two independent ways —

  * did:web resolution IS an unauthenticated GET of this URL. A did:web that
    requires credentials is not resolvable, so the identity the org advertises
    cannot be verified by anyone.
  * a peer reads OUR Ed25519 public key from here to verify what we sign
    (`federation_signing.fetch_peer_pubkey`).

D1-D4 make that explicit so a future hardening pass has to argue with a test.

**The minting side effect was real, and anonymously reachable already.** The
handler called `generate_ed25519_keypair()` when the key was absent. Measured
before the fix:

    before GET: key present? False
    after  GET: key present? True          <- minted by an anonymous read
    durable-key lookups after the mint: NONE  <- chapter_keys never read

Two consequences: the minted key is in-memory only (published as the org's
identity, gone on restart), and it poisons `_ed25519_keypairs` so
`ensure_chapter_keypair` early-returns and never loads the durable key from
`chapter_keys` — the org signs with a throwaway key while its real identity sits
in the database. M1-M3 cover it.

Classification: HAPPY (D1-D2), EDGE (D3-D4), ADVERSARIAL (M1-M3 — an anonymous
read must not be able to determine, or destroy, this org's identity).
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

WELL_KNOWN = [
    "/.well-known/did.json",
    "/.well-known/agent.json",
    "/.well-known/conformance.json",
    "/.well-known/ai-catalog.json",
    "/.well-known/nanda-agent.json",
]


@pytest.fixture
def chapter_agent_module():
    """Resolved through sys.modules, exactly as routes/identity.py's `ca` proxy
    does. Other modules re-import chapter_agent, so a reference captured at
    import time can be a stale object whose AGENT_ID is not the one the handler
    reads — which shows up as a mystifying "no signing key" 503."""
    import importlib
    import sys

    return sys.modules.get("chapter_agent") or importlib.import_module("chapter_agent")


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    chapter_agent_module._rate_limit_store.clear()
    return TestClient(chapter_agent_module.app)


@pytest.fixture
def org_key(chapter_agent_module):
    """Give the org a real signing key, as startup would."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair(chapter_agent_module.AGENT_ID)
    yield kp
    sovereign_identity._ed25519_keypairs.pop(chapter_agent_module.AGENT_ID, None)


# ---------------------------------------------------------------------------
# D1-D4 — public, on purpose, and provably so
# ---------------------------------------------------------------------------


def test_D1_anonymous_get_returns_the_did_document(client: TestClient, org_key) -> None:
    resp = client.get("/.well-known/did.json")

    assert resp.status_code == 200, f"did:web resolution requires an unauthenticated 200: {resp.text[:200]}"
    doc = resp.json()
    assert doc["id"].startswith("did:web:")
    vm = doc["verificationMethod"][0]
    assert vm["publicKeyMultibase"].startswith("z"), "standard DID tooling reads publicKeyMultibase"
    assert vm["publicKeyBase64"], "legacy field kept one transition window for live peers"


def test_D2_the_published_key_is_the_org_signing_key(client: TestClient, org_key) -> None:
    """Not just *a* key — the one this org actually signs with. A did.json that
    publishes anything else makes every signature unverifiable."""
    doc = client.get("/.well-known/did.json").json()

    assert doc["verificationMethod"][0]["publicKeyBase64"] == org_key["public_key"]


def test_D3_openness_is_declared_not_incidental() -> None:
    """The path is listed in OPEN_PATHS even though unlisted GETs already
    default to open. "Open by default" is not the same claim as "open on
    purpose": a future change to the GET default, or a /.well-known/ prefix
    rule, would otherwise break did:web resolution silently."""
    import auth_verify

    assert "/.well-known/did.json" in auth_verify.OPEN_PATHS
    assert auth_verify.is_open_path("GET", "/.well-known/did.json") is True


def test_D4_no_other_well_known_path_changed(client: TestClient, org_key) -> None:
    """The fix is one path: no other well-known document's AUTH changed.

    Asserted as "never 401", not "always 200" — deliberately. Some of these
    documents only exist once an artifact has been generated (the boot badge
    writes .org/conformance.json at startup), so a 404 is a legitimate "not
    generated in this process" and has nothing to do with authorization.
    Asserting 200 would make this test pass or fail on whether the working tree
    happens to carry a badge, which is exactly the kind of environment-shaped
    green that hides a real regression."""
    import auth_verify

    for path in WELL_KNOWN:
        code = client.get(path).status_code
        assert code != 401, f"{path} became auth-gated: {code}"
        assert auth_verify.requires_auth("GET", path) is False, f"{path} was moved behind auth"


def test_D5_the_document_carries_no_secret_material(client: TestClient, org_key) -> None:
    """Publishing this is safe precisely because it is public material. If a
    private key ever leaks into the document, opening the path becomes a
    disclosure — so assert the invariant rather than trusting the shape."""
    body = client.get("/.well-known/did.json").text
    secret_b64 = base64.b64encode(base64.b64decode(org_key["private_key"])).decode()

    assert secret_b64 not in body
    for forbidden in ("privateKey", "secret", "seed"):
        assert forbidden not in body


# ---------------------------------------------------------------------------
# M1-M3 — an anonymous read must not mint, publish, or destroy an identity
# ---------------------------------------------------------------------------


def test_M1_reading_did_json_does_not_mint_a_key(client: TestClient, chapter_agent_module) -> None:
    """THE REAL DEFECT. Before the fix an anonymous GET called
    generate_ed25519_keypair() and this assertion failed."""
    import sovereign_identity

    agent_id = chapter_agent_module.AGENT_ID
    sovereign_identity._ed25519_keypairs.pop(agent_id, None)

    client.get("/.well-known/did.json")

    assert agent_id not in sovereign_identity._ed25519_keypairs, (
        "an anonymous read minted a signing key — identity creation is "
        "ensure_chapter_keypair's job at startup, where it is persisted"
    )


def test_M2_missing_key_answers_503_not_a_fresh_identity(client: TestClient, chapter_agent_module) -> None:
    """A read surface answers with what exists. 'Not ready' is an honest answer;
    inventing an identity on the spot is not."""
    import sovereign_identity

    sovereign_identity._ed25519_keypairs.pop(chapter_agent_module.AGENT_ID, None)

    resp = client.get("/.well-known/did.json")

    assert resp.status_code == 503
    assert resp.json()["error"] == "identity_not_initialized"


async def test_M3_an_anonymous_read_cannot_block_the_durable_key(client: TestClient, chapter_agent_module) -> None:
    """The consequence that makes M1 serious. ensure_chapter_keypair returns
    early when the id is already cached, so a minted ephemeral key would mean
    the durable key in chapter_keys is NEVER loaded — the org signs with a
    throwaway key while its real identity sits in the database, and every peer
    that pinned the real DID rejects it."""
    import sovereign_identity

    agent_id = chapter_agent_module.AGENT_ID
    sovereign_identity._ed25519_keypairs.pop(agent_id, None)
    client.get("/.well-known/did.json")  # the read that used to poison the cache

    lookups: list[tuple] = []

    async def _pg(method, table, **kwargs):
        lookups.append((method, table))
        return []

    await sovereign_identity.ensure_chapter_keypair(agent_id, pg_request=_pg)

    assert any(t == "chapter_keys" for _m, t in lookups), (
        "the durable key was never read — an anonymous did.json GET left an "
        "ephemeral key in the cache and ensure_chapter_keypair short-circuited"
    )
    sovereign_identity._ed25519_keypairs.pop(agent_id, None)
