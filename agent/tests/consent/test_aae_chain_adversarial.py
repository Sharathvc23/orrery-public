"""F3: aae_emit.verify_chain catches every advertised tamper class.

aae_emit.verify_chain's docstring claims it returns ok=False on "gap, fork,
splice, duplicate" (aae_emit.py:167-181). The existing suite covers the happy
chain, ONE tampered-envelope case, and concurrency — but not each named class.
These build a real multi-envelope signed chain via the gate, then corrupt the
persisted aae_envelopes rows one class at a time and assert verify_chain flips
to ok=False. (order_chain is the upstream sm-aae primitive; this pins the
downstream guarantee the agent advertises.)
"""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("sm_aae", reason="needs sm-aae")

from community_member.consent import aae_emit, gate, ledger

SEED = b"aae-adversarial!".ljust(32, b"!")
KEY_B64 = base64.b64encode(SEED).decode()
CHAPTER = "local:test-device"


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    aae_emit._reset_for_tests()
    yield
    ledger._reset_for_tests()
    aae_emit._reset_for_tests()


@pytest.fixture
def chain_db(tmp_path: Path) -> Path:
    """A real 4-envelope signed chain: prompt → approve → prompt → deny."""
    ledger.init(tmp_path / "consent.db", signing_key_b64=KEY_B64)
    db = tmp_path / "aae.db"

    def req(ctx: str) -> gate.ActionRequest:
        return gate.ActionRequest(
            capability="browser.navigate",
            scope="https://example.com",
            context=ctx,
            provenance="trusted",
        )

    r1 = req("c1")
    p1 = gate.check_and_record(r1, chapter_id=CHAPTER)
    gate.approve(r1, chapter_id=CHAPTER, prompt_event_sha256=p1.event_sha256)
    r2 = req("c2")
    p2 = gate.check_and_record(r2, chapter_id=CHAPTER)
    gate.deny(r2, chapter_id=CHAPTER, prompt_event_sha256=p2.event_sha256)

    assert len(aae_emit.list_envelopes()) == 4
    assert aae_emit.verify_chain()["ok"] is True
    return db


def _rows(db: Path) -> list[sqlite3.Row]:
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        return list(conn.execute("SELECT * FROM aae_envelopes ORDER BY id ASC"))


def test_baseline_chain_verifies(chain_db):
    assert aae_emit.verify_chain()["ok"] is True


def test_gap_detected(chain_db):
    """Drop a middle envelope → the chain has a hole."""
    rows = _rows(chain_db)
    victim = rows[1]["id"]
    with sqlite3.connect(chain_db) as conn:
        conn.execute("DELETE FROM aae_envelopes WHERE id = ?", (victim,))
        conn.commit()
    assert aae_emit.verify_chain()["ok"] is False


def test_duplicate_detected(chain_db):
    """Re-insert an existing envelope under a fresh row id → duplicate node."""
    rows = _rows(chain_db)
    dup = rows[1]
    with sqlite3.connect(chain_db) as conn:
        conn.execute(
            "INSERT INTO aae_envelopes (agent_id, envelope_hash, prev_hash, issued_at, envelope_json)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                dup["agent_id"],
                dup["envelope_hash"] + "-dup",  # UNIQUE column; the JSON body is the real duplicate
                dup["prev_hash"],
                dup["issued_at"],
                dup["envelope_json"],
            ),
        )
        conn.commit()
    assert aae_emit.verify_chain()["ok"] is False


def test_fork_detected(chain_db):
    """Two envelopes sharing one predecessor → a fork."""
    rows = _rows(chain_db)
    # Repoint the last envelope's prev_hash to the same predecessor the
    # second envelope already chains onto: two children of one parent.
    forked = json.loads(rows[3]["envelope_json"])
    forked["prev_hash"] = rows[1]["prev_hash"]
    with sqlite3.connect(chain_db) as conn:
        conn.execute(
            "UPDATE aae_envelopes SET prev_hash = ?, envelope_json = ? WHERE id = ?",
            (rows[1]["prev_hash"], json.dumps(forked), rows[3]["id"]),
        )
        conn.commit()
    assert aae_emit.verify_chain()["ok"] is False


def test_splice_foreign_agent_envelope_detected(chain_db):
    """Splice in an envelope from a DIFFERENT agent_id (the "foreign-chain
    splice" order_chain names) → verify_chain fails: >1 agent represented."""
    from sm_aae import envelope_hash, issue_envelope

    foreign_seed = b"a-totally-other-key".ljust(32, b"?")[:32]
    foreign = issue_envelope(
        foreign_seed.hex(),
        agent_id="did:key:zForeignAgent",
        verb="browser.navigate",
        resource="https://evil.example",
        params={},
        policy_id="spliced",
        outcome="authorized",
        prev_hash=_rows(chain_db)[-1]["envelope_hash"],
        issued_at="2026-07-12T00:00:00+00:00",
    )
    real_agent = aae_emit.list_envelopes()[0]["agent_id"]
    with sqlite3.connect(chain_db) as conn:
        # Store under the REAL agent_id row so list_envelopes returns it, but
        # the envelope body carries the foreign agent_id → order_chain sees
        # two agents and rejects.
        conn.execute(
            "INSERT INTO aae_envelopes (agent_id, envelope_hash, prev_hash, issued_at, envelope_json)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                real_agent,
                envelope_hash(foreign),
                foreign["prev_hash"],
                foreign["issued_at"],
                json.dumps(foreign),
            ),
        )
        conn.commit()
    assert aae_emit.verify_chain()["ok"] is False


def test_same_agent_foreign_key_append_is_NOT_detected(chain_db):
    """Documents a real boundary (filed as an issue): verify_chain pins no
    per-agent signing key across the chain. An envelope signed by a DIFFERENT
    key but carrying the SAME agent_id and chaining correctly is self-certifying
    under sm-aae (verify_envelope checks its embedded pubkey), so order_chain —
    and thus verify_chain — accepts it. The consent ledger pins its key via the
    G3 signed checkpoint; the AAE chain has no equivalent. Exploiting this needs
    aae.db write access; still, the "signed, per-agent-chained" framing invites
    the stronger assumption. This test asserts today's behavior so a future
    key-pinning fix flips it deliberately."""
    from sm_aae import envelope_hash, issue_envelope

    other_key = b"second-signer-key!!".ljust(32, b"#")[:32]
    real_agent = aae_emit.list_envelopes()[0]["agent_id"]
    appended = issue_envelope(
        other_key.hex(),
        agent_id=real_agent,  # SAME agent id, DIFFERENT key
        verb="browser.navigate",
        resource="https://evil.example",
        params={},
        policy_id="key-substituted",
        outcome="authorized",
        prev_hash=_rows(chain_db)[-1]["envelope_hash"],
        issued_at="2026-07-12T00:00:00+00:00",
    )
    with sqlite3.connect(chain_db) as conn:
        conn.execute(
            "INSERT INTO aae_envelopes (agent_id, envelope_hash, prev_hash, issued_at, envelope_json)"
            " VALUES (?, ?, ?, ?, ?)",
            (real_agent, envelope_hash(appended), appended["prev_hash"], appended["issued_at"], json.dumps(appended)),
        )
        conn.commit()
    # Documented gap: this is accepted today.
    assert aae_emit.verify_chain()["ok"] is True
