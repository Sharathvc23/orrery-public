"""``delegated_call``: one A2A call under a DAT, verdict on record before the wire.

The peer here is a real A2A JSON-RPC endpoint with a real co-signer, serving a
real agent card — everything the verb reads from the other side comes over
HTTP, the way it does between two separately administered agents. The
principal is a fresh owner identity; the DAT is signed by its key.

What each test pins:

  * a grant that names exactly this action → sent, co-signed by the peer,
    the ``authorized`` envelope and ledger row on disk beside the receipt;
  * no such action in the grant, or a grant for someone else, or a
    self-granted DAT → refused BEFORE anything is sent (the peer's counter
    stays at zero), and the refusal is a signed ``denied`` envelope;
  * an expired grant → the refusal says ``expired`` and names the instant;
  * the same ``task_id`` twice → refused as a duplicate, sent once;
  * the peer's identity in the receipt is the card's, not the grant's.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from community_member import a2a_auth, delegated_call
from community_member.a2a_card import build_agent_card
from community_member.a2a_rpc import A2ARPCHandler
from community_member.arp import did_from_private_key
from community_member.config import Config
from community_member.consent import aae_emit, ledger
from community_member.cosign import make_cosigner
from community_member.task_store import TaskStore


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


NOW = datetime.now(UTC)
TOMORROW = _iso(NOW + timedelta(days=1))
YESTERDAY = _iso(NOW - timedelta(days=1))


class _Peer:
    """Agent B: a real RPC handler, a real co-signer, a real card."""

    def __init__(self, tmp: Path) -> None:
        self.seed = Ed25519PrivateKey.generate().private_bytes_raw()
        self.did = did_from_private_key(self.seed)
        self.executed: list[tuple[str, dict]] = []
        outer = self

        async def dispatch(tool: str, args: dict) -> str:
            outer.executed.append((tool, args))
            return json.dumps({"saved": True, "tool": tool})

        handler = A2ARPCHandler(
            store=TaskStore(path=tmp / "b-tasks.jsonl"), dispatcher=dispatch, cosigner=make_cosigner(self.seed)
        )

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_GET(self):
                # The real card shape (a2a_card.build_agent_card), did under x-nanda.
                card = build_agent_card(
                    agent_id="bee",
                    display_name="Agent B",
                    description="",
                    version="0",
                    base_url=outer.url,
                    chapter_url=None,
                    did=outer.did,
                    skills_declared=[],
                    tools=[],
                ).model_dump(mode="json", by_alias=True, exclude_none=True)
                payload = json.dumps(card).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n) or b"{}"
                body = json.loads(raw)
                # The same caller verification the real agent server performs:
                # tasks/send needs a signed request, so the verb must sign.
                caller = a2a_auth.verify_caller(dict(self.headers), raw.decode("utf-8", "replace"))
                resp = asyncio.run(handler.handle(body, caller=caller))
                payload = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self) -> None:
        self.srv.shutdown()


@pytest.fixture
def peer(tmp_path):
    p = _Peer(tmp_path)
    yield p
    p.close()


@pytest.fixture
def alice(tmp_path, monkeypatch) -> Config:
    """Agent A: its own home, keypair and ledger."""
    home = tmp_path / "alice"
    home.mkdir()
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(home))
    sk = Ed25519PrivateKey.generate()
    config = Config()
    config._home = home
    config.agent_id = "alice"
    config.name = "Alice"
    config.private_key = base64.b64encode(sk.private_bytes_raw()).decode()
    config.public_key = base64.b64encode(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    config.chapter_url = ""
    ledger._reset_for_tests()
    aae_emit._reset_for_tests()
    return config


def _did(config: Config) -> str:
    return did_from_private_key(base64.b64decode(config.private_key))


def _grant(config: Config, tool: str = "save_note", **kw) -> dict:
    dat, _phrase = delegated_call.mint_grant(
        grantee_did=_did(config), tool=tool, not_after=kw.pop("not_after", TOMORROW), **kw
    )
    return dat


def _call(config: Config, peer: _Peer, dat: dict, evidence: Path, **kw) -> delegated_call.CallReport:
    return delegated_call.call_under_authority(
        config,
        peer_url=peer.url,
        tool=kw.pop("tool", "save_note"),
        args={"key": "k", "value": "v"},
        dat=dat,
        evidence_dir=evidence,
        push=False,
        **kw,
    )


# ── the happy path ────────────────────────────────────────────────────────


def test_a_grant_naming_the_action_sends_cosigns_and_exports(alice, peer, tmp_path):
    evidence = tmp_path / "evidence"
    report = _call(alice, peer, _grant(alice), evidence, task_id="demo-1")

    assert report.outcome == "sent", report
    assert peer.executed == [("save_note", {"key": "k", "value": "v"})]
    assert report.corroborated is True, "the peer must have co-signed"
    assert report.counterparty_did == peer.did, "the counterparty is who the CARD says, not who anyone claims"

    receipt = json.loads((evidence / "receipt.json").read_text())
    assert receipt["issuer_did"] == _did(alice)
    assert receipt["action"]["counterparty_did"] == peer.did
    assert receipt["evidence"]["witness_signatures"][0]["witness_did"] == peer.did

    envelope = json.loads((evidence / "authorization" / "aae_envelope.json").read_text())
    assert envelope["outcome"] == "authorized"
    assert envelope["policy_id"] == f"consent-gate:dat:{report.verdict.grant_id}"
    row = json.loads((evidence / "authorization" / "consent_event.json").read_text())
    assert row["action"] == "consent.approved" and row["outcome"] == "ok"
    assert row["event_sha256"] == envelope["action"]["params"]["consent_event_sha256"], "envelope ↔ ledger row"
    dat = json.loads((evidence / "authorization" / "dat.json").read_text())
    assert dat["scope"]["action_categories"] == [delegated_call.action_name("save_note")]
    attempt = json.loads((evidence / "attempt.json").read_text())
    assert attempt["state"] == "succeeded" and attempt["receipt_id"] == receipt["receipt_id"]
    ack = json.loads((evidence / "acknowledgement.json").read_text())
    assert ack["id"] == "demo-1"
    card = json.loads((evidence / "counterparty_card.json").read_text())
    assert delegated_call.did_from_card(card) == peer.did and "id" not in card, (
        "the did comes from the card's x-nanda/authentication, not an id field"
    )


# ── refusals: nothing sent, and the "no" is on record ─────────────────────


@pytest.mark.parametrize(
    ("make_dat", "stage", "words"),
    [
        (lambda a: _grant(a, tool="install_skill"), "scope", "not 'a2a.tasks/send#save_note'"),
        (lambda a: _grant(a, not_after=YESTERDAY), "expired", f"expired at {YESTERDAY}"),
        (
            lambda a: _grant(a, not_before=TOMORROW, not_after=_iso(NOW + timedelta(days=2))),
            "not_yet_valid",
            "not valid until",
        ),
    ],
)
def test_a_grant_that_does_not_authorise_this_action_now_is_refused_before_the_wire(
    alice, peer, tmp_path, make_dat, stage, words
):
    evidence = tmp_path / "evidence"
    report = _call(alice, peer, make_dat(alice), evidence)

    assert report.outcome == "refused"
    assert report.verdict.stage == stage
    assert words in report.verdict.detail, report.verdict
    assert peer.executed == [], "a refused call must never reach the peer"
    assert not (evidence / "receipt.json").exists() and not (evidence / "attempt.json").exists()
    envelope = json.loads((evidence / "authorization" / "aae_envelope.json").read_text())
    assert envelope["outcome"] == "denied"
    assert f"authority_{stage}" in envelope["policy_id"]
    row = json.loads((evidence / "authorization" / "consent_event.json").read_text())
    assert row["action"] == "consent.reject" and row["outcome"] == "denied"


def test_no_grant_at_all_is_refused_by_name(alice, peer, tmp_path):
    report = _call(alice, peer, {}, tmp_path / "e")
    assert report.outcome == "refused" and report.verdict.stage == "no_grant"
    assert peer.executed == []
    envelope = json.loads((tmp_path / "e" / "authorization" / "aae_envelope.json").read_text())
    assert envelope["outcome"] == "denied"


def test_a_grant_for_a_different_agent_is_refused(alice, peer, tmp_path):
    other = Ed25519PrivateKey.generate().private_bytes_raw()
    dat, _ = delegated_call.mint_grant(grantee_did=did_from_private_key(other), tool="save_note", not_after=TOMORROW)
    report = _call(alice, peer, dat, tmp_path / "e")
    assert report.outcome == "refused" and report.verdict.stage == "grantee"
    assert peer.executed == []


def test_a_self_granted_dat_is_refused_even_though_it_verifies(alice, peer, tmp_path):
    """The vendored verifier accepts a DAT whose grantor is its grantee (no hop
    to check); the verb refuses it by name, as owner.py does for listings."""
    from community_member._dat import build_dat

    seed = base64.b64decode(alice.private_key)
    me = _did(alice)
    dat = build_dat(
        grantor_sk_bytes=seed,
        grantor_did=me,
        grantee_did=me,
        action_categories=[delegated_call.action_name("save_note")],
        not_after=TOMORROW,
    )
    report = _call(alice, peer, dat, tmp_path / "e")
    assert report.outcome == "refused" and report.verdict.stage == "grantor"
    assert peer.executed == []


def test_a_forged_grant_fails_on_signature_not_on_expiry(alice, peer, tmp_path):
    """A tampered expired grant is a forgery first: the signature stage comes
    before the window, so the refusal does not lend the document credence."""
    dat = _grant(alice, not_after=YESTERDAY)
    dat["not_after"] = TOMORROW  # "fix" the expiry without the grantor's key
    report = _call(alice, peer, dat, tmp_path / "e")
    assert report.outcome == "refused" and report.verdict.stage == "signature"


# ── the same action twice ─────────────────────────────────────────────────


def test_the_same_task_id_is_sent_once_and_refused_the_second_time(alice, peer, tmp_path):
    dat = _grant(alice)
    first = _call(alice, peer, dat, tmp_path / "e1", task_id="demo-dup")
    second = _call(alice, peer, dat, tmp_path / "e2", task_id="demo-dup")

    assert first.outcome == "sent"
    assert second.outcome == "duplicate" and second.exit_code() == delegated_call.EXIT_DUPLICATE
    assert [t for t, _ in peer.executed] == ["save_note"], "sent exactly once"
    decision = json.loads((tmp_path / "e2" / "decision.json").read_text())
    assert decision["prior_attempt"]["state"] == "succeeded"
    assert not (tmp_path / "e2" / "receipt.json").exists()


# ── the exit codes are the contract ───────────────────────────────────────


def test_exit_codes_are_distinct_and_named():
    v = delegated_call.AuthorityVerdict(True, "accepted", "", "g")
    assert delegated_call.CallReport("sent", "d", None, v).exit_code() == 0
    assert delegated_call.CallReport("refused", "d", None, v).exit_code() == delegated_call.EXIT_REFUSED
    assert delegated_call.CallReport("duplicate", "d", None, v).exit_code() == delegated_call.EXIT_DUPLICATE
    assert delegated_call.CallReport("unreceipted", "d", None, v).exit_code() == delegated_call.EXIT_UNRECEIPTED
    assert len({0, delegated_call.EXIT_REFUSED, delegated_call.EXIT_DUPLICATE, delegated_call.EXIT_UNRECEIPTED}) == 4


def test_mint_grant_names_exactly_one_action_and_keeps_the_phrase_out_of_the_dat(alice):
    dat, phrase = delegated_call.mint_grant(grantee_did=_did(alice), tool="save_note", not_after=TOMORROW)
    assert dat["scope"]["action_categories"] == ["a2a.tasks/send#save_note"]
    assert dat["grantor_did"] != _did(alice)
    assert len(phrase.split()) >= 12
    assert phrase not in json.dumps(dat)
    # The same phrase re-derives the same principal.
    again, _ = delegated_call.mint_grant(
        grantee_did=_did(alice), tool="save_note", not_after=TOMORROW, grantor_phrase=phrase
    )
    assert again["grantor_did"] == dat["grantor_did"]
    with pytest.raises(ValueError, match="RFC 3339"):
        delegated_call.mint_grant(grantee_did=_did(alice), tool="save_note", not_after="tomorrow")
