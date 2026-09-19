"""The host39 card publisher publishes only with the business's listing grant.

A hosted card is a public listing of the business. The publisher used to check
only the OPERATOR's side — a target and a credential — so a business that had
never consented could be listed by whoever held the host39 token. It now
consults the same owner-signed listing grant the index registrar does, and
refuses by name before any host39 call.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from community_member import host39, owner, registry
from community_member.config import Config
from community_member.tenant import AgentContext

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "publish_host39_card.py"
DOMAIN = "stellarminds.ai"
CARD = {
    "name": "Stellar Barbers",
    "description": "walk-ins welcome",
    "url": "https://smb.example.org/t/stellar-barbers",
    "version": "1.0.0",
    "capabilities": {"streaming": False},
    "authentication": {
        "schemes": ["ed25519"],
        "credentials": "did:key:z6MkrFpAWXdELWtJLpfD4YXgjqe7PTGgrHy3e3y2Ja84Gdcb",
    },
    "skills": [],
}


@pytest.fixture
def publisher(monkeypatch: pytest.MonkeyPatch):
    spec = importlib.util.spec_from_file_location("publish_host39_card", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "fetch_tenant_card", lambda url: dict(CARD))
    monkeypatch.setattr(mod.host39, "check_agentfacts_pointer", lambda body: None)
    # A fully configured host39 target, so the only thing standing between the
    # script and the network is the business's consent.
    monkeypatch.setenv(host39.BASE_URL_ENV, "https://cards.example.org")
    monkeypatch.setenv(host39.TOKEN_ENV, "a-token-that-must-never-be-used")
    monkeypatch.delenv("SMB_HOST_DATA_DIR", raising=False)
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")

    def _tripwire(*a, **k):
        raise AssertionError("Host39Client was constructed — the publisher reached the network path")

    monkeypatch.setattr(mod.host39.Host39Client, "from_env", classmethod(lambda cls: _tripwire()))
    return mod


@pytest.fixture
def tenant(tmp_path: Path) -> Path:
    home = tmp_path / "stellar-barbers"
    ctx = AgentContext.load(home)
    ctx.ensure_identity("stellar-barbers")
    return home


def _grant_listing_to(home: Path) -> None:
    operator = owner.mint_owner_identity()
    challenge = owner.build_domain_challenge(DOMAIN, owner.DNS_01, operator.did)
    assertion = owner.verify_domain_challenge(
        challenge, operator.did, dns_txt=lambda name: [challenge.key_authorization]
    )
    evidence = owner.build_domain_evidence(owner=operator, assertion=assertion)
    agent_did = registry.agent_did_key(Config.load(home=home))
    owner.save_binding(
        home,
        owner_did=operator.did,
        subject=DOMAIN,
        anchor=assertion.anchor,
        evidence=evidence,
        grant=owner.build_listing_grant(owner=operator, agent_did=agent_did),
    )


def test_no_tenant_home_is_refused_before_any_call(publisher, capsys):
    rc = publisher.main(["--tenant-card-url", "https://smb.example.org/t/stellar-barbers/.well-known/agent.json"])
    err = capsys.readouterr().err
    assert rc == 3
    assert "cannot find this tenant's home" in err and "--tenant-home" in err


def test_a_tenant_without_a_grant_is_refused_by_name(publisher, tenant, capsys):
    rc = publisher.main(
        ["--tenant-card-url", "https://smb.example.org/t/x/.well-known/agent.json", "--tenant-home", str(tenant)]
    )
    err = capsys.readouterr().err
    assert rc == 3
    assert "no_owner_consent" in err


def test_the_hard_opt_out_vetoes_a_valid_grant(publisher, tenant, monkeypatch, capsys):
    _grant_listing_to(tenant)
    monkeypatch.setenv("COMMUNITY_MEMBER_NO_REGISTRY", "1")
    rc = publisher.main(
        ["--tenant-card-url", "https://smb.example.org/t/x/.well-known/agent.json", "--tenant-home", str(tenant)]
    )
    assert rc == 3
    assert "COMMUNITY_MEMBER_NO_REGISTRY" in capsys.readouterr().err


def test_with_a_grant_the_publisher_proceeds_to_the_network_path(publisher, tenant):
    """The gate must not refuse everyone: with the grant on file the script
    reaches the client construction, which the tripwire turns into the proof."""
    _grant_listing_to(tenant)
    with pytest.raises(AssertionError, match="reached the network path"):
        publisher.main(
            ["--tenant-card-url", "https://smb.example.org/t/x/.well-known/agent.json", "--tenant-home", str(tenant)]
        )


def test_dry_run_needs_no_grant_and_sends_nothing(publisher, capsys):
    rc = publisher.main(["--tenant-card-url", "https://smb.example.org/t/x/.well-known/agent.json", "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "dry run" in out
    body = json.loads(out.split("\n", 1)[1])
    assert body["slug"] == "stellar-barbers"


def test_tenant_home_is_found_under_smb_host_data_dir(publisher, tenant, monkeypatch, capsys):
    """Run where the host runs, and the tenant id names the home — the same
    convention register_tenant_on_index.py uses."""
    monkeypatch.setenv("SMB_HOST_DATA_DIR", str(tenant.parent))
    rc = publisher.main(["--tenant-card-url", "https://smb.example.org/t/x/.well-known/agent.json"])
    assert rc == 3
    assert "no_owner_consent" in capsys.readouterr().err, "the home was found (so the grant, not the path, refused)"
