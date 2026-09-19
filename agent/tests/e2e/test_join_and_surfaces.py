"""Join-an-org, TOFU key binding, and the 5 NANDA surfaces on one did:key.

Claims driven:
  - QUICKSTART.md:69-73 — sovereign identity, cryptographic membership
    (ed25519+nonce over method/URL/body/id/timestamp/nonce), TOFU bootstrap
    with ``key_mismatch`` on a key swap, public profile.
  - docs/STACK.md:106-108 — the full NANDA surface set on ONE did:key:
    /agentfacts.json, /.well-known/agent.json (x-nanda ext),
    /.well-known/conformance.json, /.well-known/reputation.json, and the
    Google-A2A JSON-RPC endpoint (POST /).
  - examples/quickstart.py — the advertised 60-second arc, run verbatim.
"""

from __future__ import annotations

import json
import subprocess
import sys

import httpx

from tests.e2e.conftest import AGENT_DIR, e2e_gate

pytestmark = e2e_gate


def _find_x_nanda(tree):
    """The agent card nests the x-nanda extension; locate it wherever it is."""
    if isinstance(tree, dict):
        if "x-nanda" in tree:
            return tree["x-nanda"]
        for v in tree.values():
            found = _find_x_nanda(v)
            if found is not None:
                return found
    elif isinstance(tree, list):
        for v in tree:
            found = _find_x_nanda(v)
            if found is not None:
                return found
    return None


def test_quickstart_arc_verbatim(org_server):
    """The advertised 60-second quickstart passes against a real org."""
    out = subprocess.run(
        [sys.executable, "examples/quickstart.py", "--chapter", org_server],
        cwd=AGENT_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-2000:]
    assert "DONE" in out.stdout


def test_five_nanda_surfaces_bind_one_did(member_factory):
    m = member_factory("e2e-surfaces")

    facts = m.get("/agentfacts.json").json()
    card = m.get("/.well-known/agent.json").json()
    badge = m.get("/.well-known/conformance.json").json()
    rep = m.get("/.well-known/reputation.json").json()

    did = facts["id"]
    assert did.startswith("did:key:z6Mk")

    ext = _find_x_nanda(card)
    assert ext is not None, f"agent card carries no x-nanda extension: {list(card)}"
    assert ext.get("did") == did

    assert badge.get("signed_by") == did

    rep_subject = rep.get("credentialSubject", {}).get("id")
    assert rep_subject == did

    # Surface 5: the A2A JSON-RPC endpoint answers on POST /.
    rpc = m.post(
        "/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {"id": "nope"}},
    ).json()
    assert rpc.get("jsonrpc") == "2.0"
    assert "result" in rpc or "error" in rpc


def test_join_tofu_and_key_mismatch(org_server):
    """TOFU: first key binds; a swapped key is rejected as key_mismatch and
    the original key keeps working."""
    helper = """
import json, sys
from community_member import auth, crypto
from community_member.a2a_client import A2AClient

org = sys.argv[1]
agent_id = "e2e-tofu-victim"

kp1 = crypto.generate_ed25519_keypair()
priv1, pub1 = kp1["private_key"], kp1["public_key"]
auth.init_keys(priv1, pub1)
c1 = A2AClient(org, agent_id=agent_id, private_key=priv1, public_key=pub1)
joined = c1.join_chapter(agent_id, "TOFU victim", "e2e", [])
first_signed = c1.submit_intent(agent_id, "tofu check one", tags=["e2e"])

# Attacker: same agent_id, brand-new keypair.
kp2 = crypto.generate_ed25519_keypair()
priv2, pub2 = kp2["private_key"], kp2["public_key"]
auth.init_keys(priv2, pub2)
c2 = A2AClient(org, agent_id=agent_id, private_key=priv2, public_key=pub2)
rejoin = c2.join_chapter(agent_id, "TOFU attacker", "e2e", [])
attacker_signed = c2.submit_intent(agent_id, "tofu check two", tags=["e2e"])

# Victim again — original key must still be the bound one.
auth.init_keys(priv1, pub1)
victim_signed_again = c1.submit_intent(agent_id, "tofu check three", tags=["e2e"])

print(json.dumps({
    "joined": joined,
    "first_signed": first_signed,
    "rejoin": rejoin,
    "attacker_signed": attacker_signed,
    "victim_signed_again": victim_signed_again,
}))
"""
    out = subprocess.run(
        [sys.executable, "-c", helper, org_server],
        cwd=AGENT_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    r = json.loads(out.stdout.strip().splitlines()[-1])

    assert not r["first_signed"].get("error"), r["first_signed"]
    # The attacker's signed call must NOT verify.
    att = r["attacker_signed"]
    assert att.get("error") or "mismatch" in json.dumps(att).lower(), att
    # And the original key still works after the attempt.
    assert not r["victim_signed_again"].get("error"), r["victim_signed_again"]


def test_joined_member_is_neither_enumerable_nor_individually_probeable(org_server, member_factory):
    """Neither "who are all your members?" nor "does THIS subject have an agent?"
    is answerable without credentials.

    This test asserted the opposite half of that, and said so: "Does THIS
    subject have an agent?" is public. It was, and it should not have been —
    answering per-id for every member made the org enumerable by anyone willing
    to guess ids, and the profile also carried the member's own free-text
    description out to an unauthenticated caller. The per-agent surface is now
    consent-gated: it serves a member who opted in through
    ``POST /api/me/listing``, and a member who has not answered is
    indistinguishable from an id that was never registered.

    ``e2e-visible`` auto-joins and does not opt in, so it must look like a
    stranger. The indistinguishability assertion is the one that matters: if the
    two responses differed, the gate would have closed a disclosure and opened
    an oracle in its place.
    """
    import time

    member_factory("e2e-visible")  # boots + auto-joins the org

    # Wait for the join to land, using a signal that is not the surface under
    # test — otherwise a 404 could mean "not joined yet" rather than "gated".
    deadline = time.time() + 30
    while time.time() < deadline:
        health = httpx.get(org_server + "/health", timeout=10)
        if health.status_code == 200 and int(health.json().get("members") or 0) >= 1:
            break
        time.sleep(1)
    else:
        raise AssertionError("member never reached the org")

    joined = httpx.get(org_server + "/api/agents/e2e-visible/profile", timeout=10)
    stranger = httpx.get(org_server + "/api/agents/never-registered-at-all/profile", timeout=10)

    assert joined.status_code == 404, f"a member who never opted in has a public profile (status {joined.status_code})"
    assert joined.status_code == stranger.status_code and joined.text == stranger.text, (
        "membership oracle: a joined member is distinguishable from a stranger"
    )

    listing = httpx.get(org_server + "/api/members", timeout=10)
    assert listing.status_code == 401, f"member directory is anonymously enumerable: {listing.text[:300]}"
