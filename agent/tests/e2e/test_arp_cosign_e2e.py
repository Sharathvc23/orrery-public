"""ARP receipts + cosign/corroboration, against live processes.

Claims driven (examples/cosign_interaction.py docstring, STELLARMINDS.md:44,
cosign-companion §1/§3):
  - an A2A call auto-emits a signed ARP receipt; with cosign=True the named
    counterparty co-signs over the same connection → a corroborated receipt
  - only corroborated receipts build reputation under nanda-rep/0.2 (the
    self-attested one scores under 0.1 but is gated to zero under 0.2)
  - a LIVE serve.py member co-signs when it is the named counterparty and
    declines when it is not (never blocks the interaction)
  - --chapter mode pushes the receipt so the chapter's agentfacts reflect it
"""

from __future__ import annotations

import json
import subprocess
import sys

from tests.e2e.conftest import AGENT_DIR, e2e_gate

pytestmark = e2e_gate


def _run_example(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "examples/cosign_interaction.py", *argv],
        cwd=AGENT_DIR,
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_cosign_example_local_verbatim():
    """The advertised 'ignition' example, self-contained loopback mode."""
    out = _run_example()
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-2000:]
    assert "corroborated: True" in out.stdout
    assert "corroborated: False" in out.stdout
    # The 0.1 vs 0.2 flip: one of two receipts corroborated.
    assert "corroboration_rate = 0.500" in out.stdout


def test_cosign_example_pushes_to_chapter(org_server):
    """--chapter mode registers both agents and the receipt lands in the
    chapter's agentfacts under nanda-rep/0.2."""
    out = _run_example("--chapter", org_server)
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-2000:]
    assert "registered X + Y" in out.stdout
    assert "chapter agentfacts: score=" in out.stdout, out.stdout[-2000:]


def test_live_member_cosigns_as_witness(member_factory, tmp_path):
    """The LIVE agent process is the witness: it co-signs receipts naming it
    as counterparty and declines to corroborate ones that don't."""
    import sm_arp.vrp as vrp
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    from community_member.a2a_client_v2 import GoogleA2AClient
    from community_member.arp import AgencyLog, verify_receipt_signature

    witness = member_factory("e2e-witness")
    witness_did = witness.did()

    sk = Ed25519PrivateKey.generate()
    x_seed = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    log = AgencyLog(home=tmp_path / "x-agency")
    client = GoogleA2AClient(base_url=witness.base)
    try:
        # Corroborated: the live member IS the named counterparty.
        client.send_task_recorded(
            tool="save_note",
            args={"key": "e2e", "value": "hello witness"},
            counterparty_did=witness_did,
            counterparty_label="E2E Witness",
            sk_bytes=x_seed,
            agency_log=log,
            cosign=True,
        )
        receipts = log.list_recent(limit=10)
        assert receipts, "no receipt emitted"
        corroborated = receipts[0]
        assert verify_receipt_signature(corroborated), corroborated
        assert vrp.is_corroborated(corroborated), json.dumps(corroborated)[:500]
        witness_entry = corroborated["evidence"]["witness_signatures"][0]
        assert witness_entry["witness_did"] == witness_did

        # Declined: receipt names a DIFFERENT counterparty — the live member
        # must refuse to witness it (no self-serving corroboration), while
        # the interaction itself still succeeds (§3: never fails for lack
        # of a witness).
        other = Ed25519PrivateKey.generate()
        other_seed = other.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        from community_member.arp import did_from_private_key

        stranger_did = did_from_private_key(other_seed)
        before = {r["receipt_id"] for r in log.list_recent(limit=100)}
        client.send_task_recorded(
            tool="save_note",
            args={"key": "e2e2", "value": "wrong counterparty"},
            counterparty_did=stranger_did,
            counterparty_label="Stranger",
            sk_bytes=x_seed,
            agency_log=log,
            cosign=True,
        )
        new = [r for r in log.list_recent(limit=100) if r["receipt_id"] not in before]
        assert len(new) == 1
        assert verify_receipt_signature(new[0])
        assert not vrp.is_corroborated(new[0]), json.dumps(new[0])[:500]

        # The 0.2 gate: only the corroborated receipt scores.
        all_receipts = log.list_recent(limit=100)
        rate = vrp.corroboration_rate(all_receipts, is_valid=verify_receipt_signature)
        assert 0.0 < rate < 1.0, rate
    finally:
        client.close()
