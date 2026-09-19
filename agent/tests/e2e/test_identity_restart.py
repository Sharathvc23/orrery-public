"""Identity + keypair persistence across restart, against live processes.

Claims driven (agent/README.md:3-5, serve.py:13-18):
  - a fresh HOME mints a real Ed25519 identity and serves it as a did:key
  - the SAME HOME + passphrase across a restart yields the SAME did:key
  - signed org calls still verify after the restart (TOFU key unchanged)
  - a different HOME yields a different did:key (negative control)

This is the subprocess-level companion to
tests/test_headless_identity_stability.py, which exercises the re-mint
trap in-process.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time

import httpx

from tests.e2e.conftest import AGENT_DIR, PASSPHRASE, e2e_gate

pytestmark = e2e_gate

# Runs with the member's HOME: loads its persisted identity, signs one
# intent against the org, prints the JSON result. A clean process is used
# so the pytest process never mutates COMMUNITY_MEMBER_* globals.
_SIGNED_CALL = """
import json, sys
from community_member import auth, keystore
from community_member.a2a_client import A2AClient
from community_member.config import Config

cfg = Config.load()
priv = keystore.load_private_key(cfg.agent_id)
assert priv, "private key must be recoverable from the persisted keystore"
auth.init_keys(priv, cfg.public_key)
client = A2AClient(sys.argv[1], agent_id=cfg.agent_id, private_key=priv, public_key=cfg.public_key)
print(json.dumps(client.submit_intent(cfg.agent_id, "e2e persistence check-in", tags=["e2e"])))
"""


def signed_intent_from_home(home, org_server: str) -> dict:
    env = {
        "PATH": "/usr/bin:/bin",
        "COMMUNITY_MEMBER_HOME": str(home),
        "COMMUNITY_MEMBER_KEYSTORE": "passphrase",
        "COMMUNITY_MEMBER_PASSPHRASE": PASSPHRASE,
    }
    out = subprocess.run(
        [sys.executable, "-c", _SIGNED_CALL, org_server],
        cwd=AGENT_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def _org_has_a_member(org_server: str) -> bool:
    """Readiness: the org has processed at least one join.

    This used to be ``_org_knows_member(org_server, agent_id)``, asking the
    per-agent profile surface whether a SPECIFIC id was known and treating 200
    as yes. That worked only because the route answered for every member
    regardless of whether they had agreed to be published — it was a membership
    oracle, and it is now consent-gated and answers 404 by default.

    Nothing open should answer "does this org know X?" for an arbitrary X; that
    is the question the gate exists to refuse. Readiness does not need it: this
    test's subject is that the keypair survives a restart, and the identity is
    asserted directly (``m2.did() == did_first``) and against the org
    (``signed_intent_from_home`` verifies server-side with no key_mismatch,
    which only holds if the org retained THIS member's TOFU key).
    """
    r = httpx.get(f"{org_server}/health", timeout=10)
    return r.status_code == 200 and int(r.json().get("members") or 0) >= 1


def test_keypair_persists_across_restart(org_server, member_factory):
    m1 = member_factory("e2e-persist")
    did_first = m1.did()
    assert did_first.startswith("did:key:z6Mk"), did_first

    # Identity artifacts exist under HOME.
    assert (m1.home / "keystore.enc").exists()
    assert (m1.home / "config.json").exists()

    # Auto-join reached the org. That THIS member is the one it knows is
    # asserted below, by a signed call the org must verify without key_mismatch.
    deadline = time.time() + 30
    while time.time() < deadline and not _org_has_a_member(org_server):
        time.sleep(1)
    assert _org_has_a_member(org_server)

    m1.stop()

    # Same HOME, same env → same identity.
    m2 = member_factory("e2e-persist", home=m1.home)
    assert m2.did() == did_first

    # The org still holds the same TOFU key: a signed call using the
    # restarted identity verifies server-side (no key_mismatch).
    result = signed_intent_from_home(m2.home, org_server)
    assert not result.get("error"), result


def test_fresh_home_mints_new_identity(member_factory):
    a = member_factory("e2e-fresh-a")
    b = member_factory("e2e-fresh-b")
    assert a.did() != b.did()
