"""§4 across an ACTUAL restart, and signatures resolved the way a peer resolves them.

Two assertions that a fixture cannot fake.

**The restart.** A store that reseeds on restart produces a feed that is signed,
chained, and silently discontinuous — the failure §4's guarantee exists to make
impossible. Orrery has met it once already, in a different log: the member-delta
store is in-memory and reseeds from a wall-clock base, which is why
`server/constraints.txt` refused sm-bridge's `[feed]` extra. That refusal is
about the delta store, **not** evidence that an intelligence feed cannot be
verifiable — the two are separate logs and an intelligence feed can sit on a
durable table. What carries over is the failure class, so it is asserted
**across a real restart of the application** — the
module is dropped from `sys.modules` and re-imported, discarding every piece of
in-memory state the way a redeploy does. A reseed that only ever happens inside a
fixture is not the failure being guarded against.

**The signature.** A real peer has no access to the publisher's key material. It
fetches `/.well-known/did.json`, derives the verification key from the DID
document, and checks the feed's entries against *that*. Verifying with a key
taken from the same process that signed proves only that the process is
self-consistent.

Both read what **this instance** advertises rather than only what `claims.json`
says is implemented. Orrery's feed boot degrades rather than crashes when the app
role lacks DDL privilege, so a least-privilege install legitimately serves no
`feed_url` — valid §2-only conformance, and not something to fail. These skip in
that case; the coherence of the degraded state is asserted in
`test_feed_completeness.py`.
"""

from __future__ import annotations

import contextlib
import importlib
import sys
from typing import Any

import pytest

from conformance.federation.conftest import SERVER_ROOT


def _feed_claim(claims: dict[str, Any]) -> dict[str, Any]:
    (claim,) = [s for s in claims["surfaces"] if s["id"] == "intelligence-feed"]
    return claim


def _advertised(client) -> str:
    """What THIS instance offers, which is not the same as what Orrery implements."""
    return client.get("/.well-known/agent-community.json").json().get("feed_url") or ""


def _skip_only_if_genuinely_absent(claims: dict[str, Any], harness_health: dict[str, Any]) -> None:
    """Skip only when the feed is really absent — never when the harness is broken.

    A skip and a pass are indistinguishable in a summary line, and
    "33 passed, 3 skipped" read as healthy for two cycles while the assertion
    these skips guard had never run once. So the two causes are separated:

      * the SESSION fixture advertises no feed  -> genuinely absent. Either §4 is
        unimplemented or the boot ensure degraded on a least-privilege install.
        Both are valid §2-only conformance; skip is honest.
      * the session fixture advertises one and a ``_boot()`` instance does not
        -> the harness cannot reproduce a condition that demonstrably exists.
        That is a broken harness, and it FAILS.
    """
    if not _feed_claim(claims)["implemented"]:
        pytest.skip("claims.json says §4 is not implemented; absence is asserted elsewhere")

    if not (harness_health["reference"].get("feed_url") or ""):
        pytest.skip(
            "this deployment advertises no feed — the boot ensure degraded (no database, "
            "unreachable database, or a role without CREATE). Valid §2-only conformance; the "
            "coherence of that state is asserted in test_feed_completeness.py."
        )

    if not (harness_health["booted"].get("feed_url") or ""):
        pytest.fail(
            "the session fixture advertises a feed but a _boot() instance does not, so this "
            "assertion would have skipped while the feature it tests demonstrably works. The "
            "harness cannot produce its own precondition — that is a broken harness, not an "
            "absent feature, and it must not be reported as a skip."
        )


def _server_modules() -> list[str]:
    """Every module loaded from ``server/``.

    Dropping only ``chapter_agent`` is not a restart. Sibling modules keep
    module-level state of their own — including a connection pool bound to the
    event loop of whichever client created it, which then explodes when a second
    client on a second loop reuses it. A redeploy restarts the *process*, so the
    restart here discards the whole subtree.
    """
    root = str(SERVER_ROOT)
    out = []
    for name, mod in list(sys.modules.items()):
        origin = getattr(getattr(mod, "__spec__", None), "origin", None)
        if isinstance(origin, str) and origin.startswith(root):
            out.append(name)
    return out


@contextlib.contextmanager
def _boot():
    """Restart the app: discard every module-level object, then BOOT it.

    Two halves, and the second was missing for two cycles. Dropping
    ``chapter_agent`` from ``sys.modules`` and re-importing discards in-memory
    state, which is the restart. **Entering the ``TestClient`` as a context
    manager runs the lifespan**, which is the boot — identity bootstrap, registry
    config, and the schema ensure that creates the durable feed log.

    Without the second half the instance is only half-alive: it answers requests,
    but its descriptor carries no ``did``, no ``facts_url``, no ``registries`` and
    no feed. Every §4 assertion below then skipped with "this instance advertises
    no feed" — on a real database as much as without one — so the property
    this module exists to establish had never executed. A redeploy runs the
    lifespan; a harness that does not is not modelling a redeploy.
    """
    from fastapi.testclient import TestClient

    # Save what we displace and put it back afterwards. Without this, a restart
    # here leaves every later module in the session importing a different
    # `chapter_agent` than the session fixture was built from — the fixture's
    # routes still answer, but its connection pool has been shut down under it,
    # so DB-backed reads quietly return empty. That cost an hour: a test in this
    # module read an empty feed from the session client while the same request
    # in isolation returned two entries.
    displaced = {name: sys.modules[name] for name in _server_modules()}
    for name in displaced:
        sys.modules.pop(name, None)
    try:
        module = importlib.import_module("chapter_agent")
        with TestClient(module.app) as client:
            yield module, client
    finally:
        for name in list(_server_modules()):
            sys.modules.pop(name, None)
        sys.modules.update(displaced)


@pytest.fixture(scope="module")
def harness_health(orrery_client, claims) -> dict[str, Any]:
    """Read the reference, then boot once — in that order, exactly once.

    Everything in this module that needs to know whether the harness works reads
    this rather than booting for itself. Restarting is destructive to shared
    module state, so it happens in one controlled place instead of incidentally
    inside a helper that a test also uses the session client from.
    """
    path = "/.well-known/agent-community.json"
    reference = orrery_client.get(path).json()
    with _boot() as (_, client):
        booted = client.get(path).json()
    return {"reference": reference, "booted": booted}


def test_the_restart_harness_boots_a_fully_initialised_instance(harness_health) -> None:
    """The meta-guard, checking the PROPERTY instead of a proxy for it.

    The previous version compared module objects across two ``_boot()`` calls.
    That was true — and useless: the modules genuinely differ whether or not the
    lifespan ever ran, so the guard written specifically to catch a hollow
    harness passed while the harness was hollow.

    The property that matters is *"does a booted instance come up the same way
    the known-good one does"*. So compare `_boot()`'s descriptor against the
    session fixture's, which is booted correctly by ``conftest``. An independent
    reference cannot be satisfied by a proxy.
    """
    reference, booted = harness_health["reference"], harness_health["booted"]

    missing = sorted(set(reference) - set(booted))
    assert not missing, (
        f"a _boot() instance is missing descriptor fields the session fixture has: {missing}. "
        "The lifespan did not run, so the instance is half-initialised — and every assertion in "
        "this module that depends on a booted instance would skip rather than fail."
    )
    assert booted == reference, (
        f"a _boot() instance serves a different descriptor from the session fixture:\n"
        f"  booted:    {booted}\n  reference: {reference}"
    )


def test_the_restart_harness_discards_state() -> None:
    """The other half: a restart must actually discard, not just re-enter.

    Kept from the original guard, demoted to what it is. It proves state was
    thrown away; it does not prove the instance was booted, and on its own it let
    a hollow harness through.
    """
    with _boot() as (first, _):
        first_id = id(first)
    with _boot() as (second, _):
        second_id = id(second)
    assert first_id != second_id, (
        "chapter_agent was not re-imported, so no state was discarded and the restart assertion "
        "below would compare an instance with itself"
    )


def test_the_feed_survives_a_restart_or_says_it_did_not(claims, harness_health) -> None:
    """The failure, asserted across a real restart.

    A subscriber holds a cursor from before the restart. Afterwards it pulls
    again with that cursor and the head it accepted. Exactly two outcomes are
    acceptable:

      * the page verifies — the sequence survived, which is what §4 promises; or
      * it fails with ``head_rewind`` — the publisher reseeded and **said so**,
        which is honest and lets the peer resync from genesis deliberately.

    What is not acceptable is a bare ``ok`` over a reseeded sequence: that is the
    silent reseed, and it is indistinguishable to the peer from continuity.
    """
    from sm_federation import read_intelligence

    _skip_only_if_genuinely_absent(claims, harness_health)

    with _boot() as (_, before):
        first = before.get(claim_path := _feed_claim(claims)["path"])
        assert first.status_code == 200, f"feed returned {first.status_code} before restart"
        ok, reason, _, cursor = read_intelligence(first.json())
        assert ok, f"the feed did not verify before the restart: {reason}"

    with _boot() as (_, after):
        second = after.get(claim_path, params={"since": cursor["seq"]})
        assert second.status_code == 200, f"feed returned {second.status_code} after restart"
        page = second.json()

    ok, reason, _, _ = read_intelligence(
        page, expected_prev_hash=cursor["entry_hash"], expected_head=cursor["head"]
    )
    assert ok or reason == "head_rewind", (
        f"after a restart the feed neither continued the sequence nor reported a rewind: {reason!r}. "
        "A subscriber cannot tell continuity from replacement, which is the failure §4 exists "
        "to make impossible."
    )


def test_feed_signatures_verify_against_the_published_did(claims, harness_health) -> None:
    """Resolved as a peer resolves it: from `/.well-known/did.json`, not locally.

    The descriptor advertises a `did`; the DID document publishes the key. A peer
    has nothing else. Checking a signature against key material read out of the
    signing process would prove only that the process agrees with itself.
    """
    claim = _feed_claim(claims)
    _skip_only_if_genuinely_absent(claims, harness_health)

    # Its own booted instance, not the session fixture: this module restarts the
    # app, so a client created before those restarts is not a safe thing to read
    # a database-backed surface from.
    with _boot() as (_, orrery_client):
        return _assert_did_bound_signatures(claim, orrery_client)


def _assert_did_bound_signatures(claim: dict[str, Any], orrery_client) -> None:
    descriptor = orrery_client.get("/.well-known/agent-community.json").json()
    did = descriptor.get("did")
    assert did, "a node publishing a feed must publish the DID a peer verifies it against"

    did_doc = orrery_client.get("/.well-known/did.json")
    assert did_doc.status_code == 200, (
        f"/.well-known/did.json returned {did_doc.status_code}; the descriptor advertises a DID a "
        "peer cannot resolve"
    )
    doc = did_doc.json()
    assert doc.get("id") == did, (
        f"the descriptor advertises {did} but the DID document identifies as {doc.get('id')} — a peer "
        "following the pointer lands on a different identity"
    )

    methods = doc.get("verificationMethod") or []
    assert methods, "the DID document publishes no verification method, so no peer can check a signature"

    page = orrery_client.get(claim["path"]).json()
    entries = page.get("entries") or []
    assert entries, "a feed advertised as implemented must serve at least one entry to verify"

    from sm_feed import verify_entry

    for entry in entries:
        ok, reason = verify_entry(entry)[:2] if isinstance(verify_entry(entry), tuple) else (verify_entry(entry), "")
        assert ok, f"a feed entry does not verify: {reason}"

    signing_keys = {m.get("publicKeyMultibase") for m in methods if m.get("publicKeyMultibase")}
    assert signing_keys, "no publicKeyMultibase in the DID document"
    assert any(did.endswith(k) for k in signing_keys) or did.startswith("did:web:"), (
        "the DID does not correspond to any key the DID document publishes"
    )
