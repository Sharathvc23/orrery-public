"""Co-sign handshake — member-sdk wiring (spec/arp/0.2/cosign-companion.md).

Covers both sides of the inline handshake and the failure modes the spec makes
normative: single receipt per interaction (§2), decline-is-valid-uncorroborated
(§3), insertion-before-finalize (issuer signature covers the witness, §1), and
the adversarial paths that must NOT corroborate (forged signature, wrong signer,
third-party witness, self-corroboration).

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL per the Behavioral Testing
Constitution. Security tests assert the corroboration verdict, not mere presence.
"""

from __future__ import annotations

import asyncio
import base64
import os
from typing import Any

from sm_arp.vrp import cosign_receipt, is_corroborated

from community_member import a2a_auth as _a2a_auth
from community_member.a2a_rpc import A2ARPCHandler
from community_member.arp import (
    build_receipt,
    did_from_private_key,
    verify_receipt_signature,
)
from community_member.cosign import (
    attach_corroboration,
    attach_entry,
    make_cosigner,
    make_witness,
)
from community_member.interactions import record_interaction

# These tests drive the dispatcher directly, so they supply the verified caller
# the route would have derived from the request headers. Sends require one —
# see ``a2a_auth.METHOD_ACCESS`` — and the gate itself is tested in
# ``tests/test_a2a_surface_auth.py`` rather than re-asserted at every call here.
# Passed uniformly at these call sites, including for reads that do NOT require
# it — tasks/get, tasks/cancel and tasks/resubscribe are open. Do not read its
# presence here as the classification; the classification is a2a_auth.METHOD_ACCESS
# and it is pinned in tests/test_a2a_surface_auth.py.
PEER = _a2a_auth.CallerIdentity(agent_id="peer-agent", did_key="did:key:zPeerTest")


def _seed() -> bytes:
    return os.urandom(32)


def _unsigned(issuer_seed: bytes, counterparty_did: str) -> dict[str, Any]:
    """An unsigned interaction receipt naming ``counterparty_did`` — the form a
    counterparty co-signs (issuer has not finalized its signature yet)."""
    issuer = did_from_private_key(issuer_seed)
    action = {
        "category": "message_sent",
        "human_summary": "called B",
        "outcome": "completed",
        "counterparty_did": counterparty_did,
        "counterparty_label": "B",
    }
    return build_receipt(action=action, issuer_did=issuer, principal_did=issuer)


class _FakeLog:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def tip(self, *, issuer_did: str) -> str | None:
        return self.items[-1].get("receipt_id") if self.items else None

    def append(self, receipt: dict[str, Any]) -> None:
        self.items.append(receipt)


def _cosign_envelope(receipt: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": "1", "method": "nanda/cosignReceipt", "params": {"receipt": receipt}}


# ─── make_witness (B side) ───────────────────────────────────────────────


def test_make_witness_cosigns_when_counterparty():  # HAPPY
    a, b = _seed(), _seed()
    b_did = did_from_private_key(b)
    r = _unsigned(a, b_did)
    entry = make_witness(r, sk_bytes=b)
    assert entry is not None
    assert entry["witness_did"] == b_did
    assert attach_entry(r, entry) is True
    assert is_corroborated(r)


def test_make_witness_declines_third_party():  # ADVERSARIAL — not the counterparty
    a, b, c = _seed(), _seed(), _seed()
    r = _unsigned(a, did_from_private_key(b))  # counterparty is B
    assert make_witness(r, sk_bytes=c) is None  # C must not attest


def test_make_witness_declines_self_corroboration():  # ADVERSARIAL — issuer == counterparty
    a = _seed()
    a_did = did_from_private_key(a)
    r = _unsigned(a, a_did)
    assert make_witness(r, sk_bytes=a) is None


def test_make_witness_declines_malformed():  # FAILURE — no action block
    assert make_witness({"issuer_did": "did:key:zX"}, sk_bytes=_seed()) is None


# ─── attach_entry / attach_corroboration (A side) ────────────────────────


def test_attach_none_is_uncorroborated_no_residue():  # EDGE — decline
    a, b = _seed(), _seed()
    r = _unsigned(a, did_from_private_key(b))
    assert attach_entry(r, None) is False
    assert "evidence" not in r  # nothing left to alter the signed bytes


def test_attach_forged_signature_rolled_back():  # ADVERSARIAL — garbage signature
    a, b = _seed(), _seed()
    b_did = did_from_private_key(b)
    r = _unsigned(a, b_did)
    forged = {"witness_did": b_did, "signature": base64.b64encode(b"\x00" * 64).decode()}
    assert attach_entry(r, forged) is False
    assert "evidence" not in r


def test_attach_wrong_signer_rolled_back():  # ADVERSARIAL — labelled B, signed by C
    a, b, c = _seed(), _seed(), _seed()
    b_did = did_from_private_key(b)
    r = _unsigned(a, b_did)
    entry = cosign_receipt(r, signing_key_bytes=c, witness_did=b_did)  # claims B, C's key
    assert attach_entry(r, entry) is False
    assert "evidence" not in r


def test_attach_corroboration_swallows_fetcher_failure():  # FAILURE — transport down
    a, b = _seed(), _seed()
    r = _unsigned(a, did_from_private_key(b))

    def boom(_r: dict[str, Any]) -> dict[str, Any] | None:
        raise RuntimeError("network down")

    assert attach_corroboration(r, boom) is False
    assert "evidence" not in r  # decline, not error


# ─── record_interaction end-to-end (A asks B via a fetcher) ──────────────


def test_record_interaction_corroborated_and_signed():  # HAPPY — the whole point
    a, b = _seed(), _seed()
    b_did = did_from_private_key(b)
    log = _FakeLog()

    def fetcher(unsigned: dict[str, Any]) -> dict[str, Any] | None:
        return make_witness(unsigned, sk_bytes=b)

    r = record_interaction(
        sk_bytes=a,
        agency_log=log,
        counterparty_did=b_did,
        counterparty_label="B",
        summary="x",
        witness_fetcher=fetcher,
    )
    assert verify_receipt_signature(r)  # issuer sig valid — covers the witness (§1)
    assert is_corroborated(r)  # corroborated — builds reputation under nanda-rep/0.2
    assert len(log.items) == 1  # single receipt (§2) — no mirror
    assert r["evidence"]["witness_signatures"][0]["witness_did"] == b_did


def test_record_interaction_decline_is_valid_uncorroborated():  # EDGE — §3
    a, b = _seed(), _seed()
    log = _FakeLog()
    r = record_interaction(
        sk_bytes=a,
        agency_log=log,
        counterparty_did=did_from_private_key(b),
        counterparty_label="B",
        summary="x",
        witness_fetcher=lambda _u: None,  # counterparty declines
    )
    assert verify_receipt_signature(r)  # still valid
    assert not is_corroborated(r)  # earns zero reputation, not an error
    assert not (r.get("evidence") or {}).get("witness_signatures")
    assert len(log.items) == 1


def test_record_interaction_without_fetcher_is_backward_compatible():  # EDGE — legacy
    a, b = _seed(), _seed()
    log = _FakeLog()
    r = record_interaction(
        sk_bytes=a,
        agency_log=log,
        counterparty_did=did_from_private_key(b),
        counterparty_label="B",
        summary="x",
    )
    assert verify_receipt_signature(r)
    assert not is_corroborated(r)  # unchanged: uncorroborated, as before this feature


# ─── A2ARPCHandler nanda/cosignReceipt (the witness endpoint) ────────────


def test_handler_cosigns_when_counterparty():  # HAPPY
    a, b = _seed(), _seed()
    b_did = did_from_private_key(b)
    handler = A2ARPCHandler(store=None, dispatcher=None, cosigner=make_cosigner(b))  # type: ignore[arg-type]
    r = _unsigned(a, b_did)
    resp = asyncio.run(handler.handle(_cosign_envelope(r), caller=PEER))
    entry = resp["result"]["witness"]
    assert entry["witness_did"] == b_did
    assert attach_entry(r, entry) and is_corroborated(r)


def test_handler_declines_when_not_counterparty():  # ADVERSARIAL
    a, b, c = _seed(), _seed(), _seed()
    handler = A2ARPCHandler(store=None, dispatcher=None, cosigner=make_cosigner(c))  # type: ignore[arg-type]
    r = _unsigned(a, did_from_private_key(b))  # names B, but C is asked
    resp = asyncio.run(handler.handle(_cosign_envelope(r), caller=PEER))
    assert resp["result"]["witness"] is None


def test_handler_without_cosigner_declines():  # EDGE — co-signing disabled
    a, b = _seed(), _seed()
    handler = A2ARPCHandler(store=None, dispatcher=None, cosigner=None)  # type: ignore[arg-type]
    resp = asyncio.run(handler.handle(_cosign_envelope(_unsigned(a, did_from_private_key(b))), caller=PEER))
    assert resp["result"]["witness"] is None


def test_handler_invalid_params_when_receipt_missing():  # FAILURE
    handler = A2ARPCHandler(store=None, dispatcher=None, cosigner=make_cosigner(_seed()))  # type: ignore[arg-type]
    resp = asyncio.run(
        handler.handle({"jsonrpc": "2.0", "id": "1", "method": "nanda/cosignReceipt", "params": {}}, caller=PEER)
    )
    assert "error" in resp and resp["error"]["code"] == -32602


def test_handler_end_to_end_through_fetcher_shape():  # HAPPY — handler result feeds A's fetcher
    """The handler's ``{"witness": entry}`` result is exactly what the client
    fetcher unwraps, so co-signing across the wire corroborates byte-identically."""
    a, b = _seed(), _seed()
    b_did = did_from_private_key(b)
    handler = A2ARPCHandler(store=None, dispatcher=None, cosigner=make_cosigner(b))  # type: ignore[arg-type]
    log = _FakeLog()

    def wire_fetcher(unsigned: dict[str, Any]) -> dict[str, Any] | None:
        resp = asyncio.run(handler.handle(_cosign_envelope(unsigned), caller=PEER))
        return resp["result"]["witness"]

    r = record_interaction(
        sk_bytes=a,
        agency_log=log,
        counterparty_did=b_did,
        counterparty_label="B",
        summary="x",
        witness_fetcher=wire_fetcher,
    )
    assert verify_receipt_signature(r)
    assert is_corroborated(r)
