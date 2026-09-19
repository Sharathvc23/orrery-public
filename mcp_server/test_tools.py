"""Direct unit tests of mcp_server.tools — no MCP transport involved.

Each test builds its own signed identity at an isolated ``tmp_path``, passed
through the ``_home`` internal override every function accepts (never an
MCP-facing parameter — see tools.py's own docstring on that). The MCP
transport itself is exercised separately by test_stdio_oracle.py (the stock
``mcp`` SDK) and test_langchain_oracle.py (``langchain-mcp-adapters``); this
file is where the tool LOGIC is proven, fast and without a subprocess.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("COMMUNITY_MEMBER_KEYSTORE", "device")

from mcp_server import tools  # noqa: E402


def _signed_identity(tmp_path: Path, agent_id: str = "test-agent", name: str = "Test Agent"):
    """A minimal signed identity at ``tmp_path`` — Config + Ed25519 keypair,
    stored the same way ``Config.save()`` always does. Deliberately NOT
    ``wizard.express_setup``: that always resolves the process-global
    ``COMMUNITY_MEMBER_HOME`` (it takes no ``home`` argument), which is
    exactly the coupling ``_home`` exists to avoid in tests."""
    from community_member.config import Config

    cfg = Config(home=tmp_path)
    cfg.agent_id = agent_id
    cfg.name = name
    cfg.ensure_keypair()
    cfg.save()
    return cfg


# ── register_agent ────────────────────────────────────────────────────────


def test_register_agent_refuses_to_mint_when_unconfigured(tmp_path: Path) -> None:
    """The one thing this tool must never do: hand back a recovery phrase, or
    mint anything, over MCP.

    The refusal names the command to run instead, and that command must be one
    the CLI accepts: driven by hand, `community_member --express --name` was
    rejected by argparse (no such top-level flags — the CLI has subcommands),
    so the tool sent a stranger to a command that does not exist."""
    with pytest.raises(tools.ToolError, match="community-member wizard --express --name") as exc:
        tools.register_agent(_home=tmp_path)

    import re

    from community_member import cli

    named = re.search(r"`(community-member [^`]+)`", str(exc.value)).group(1).split()
    # The CLI's own parser must accept the named subcommand and flags
    # (`<name>` stands in for a value).
    args = cli._build_parser().parse_args(named[1:-1] + ["x"])
    assert args.express is True and args.name == "x"


def test_register_agent_reports_the_existing_identity(tmp_path: Path) -> None:
    cfg = _signed_identity(tmp_path)
    result = tools.register_agent(_home=tmp_path)
    assert result["agent_id"] == cfg.agent_id
    assert result["did"].startswith("did:key:z")
    assert result["has_signing_key"] is True


def test_register_agent_never_returns_a_recovery_phrase(tmp_path: Path) -> None:
    """Structural, not just behavioral: the word must not appear in the
    result at all, so a future field addition can't reintroduce it quietly."""
    _signed_identity(tmp_path)
    result = tools.register_agent(_home=tmp_path)
    assert not any("phrase" in str(k).lower() for k in result), f"a phrase-shaped field leaked: {result.keys()}"


# ── request_grant ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("provenance", ["trusted", "semi_trusted", "untrusted"])
def test_request_grant_never_returns_approved(tmp_path: Path, provenance: str) -> None:
    """⚠️ THE CORE GUARANTEE. No matter what a model asks for, this tool alone
    cannot produce an approval."""
    _signed_identity(tmp_path)
    result = tools.request_grant(
        capability="test.capability",
        scope="test",
        context="a proposed action",
        provenance=provenance,  # type: ignore[arg-type]
        _home=tmp_path,
    )
    assert result["state"] in ("reject", "prompt")
    assert result["state"] != "approved"


def test_request_grant_rejects_untrusted_provenance(tmp_path: Path) -> None:
    _signed_identity(tmp_path)
    result = tools.request_grant(
        capability="test.capability", scope="test", context="from a web page", provenance="untrusted", _home=tmp_path
    )
    assert result["state"] == "reject"
    assert "untrusted" in result["reason"]


def test_request_grant_prompts_for_trusted_content(tmp_path: Path) -> None:
    _signed_identity(tmp_path)
    result = tools.request_grant(
        capability="test.capability", scope="test", context="I decided this", provenance="trusted", _home=tmp_path
    )
    assert result["state"] == "prompt"


# ── check_grant ───────────────────────────────────────────────────────────


def test_check_grant_reports_unapproved_when_nothing_was_asked(tmp_path: Path) -> None:
    _signed_identity(tmp_path)
    result = tools.check_grant(
        capability="never.asked", scope="test", context="nothing", provenance="trusted", _home=tmp_path
    )
    assert result == {"approved": False}


def test_check_grant_reports_unapproved_after_a_bare_request(tmp_path: Path) -> None:
    """A request_grant call alone — with no human approve() — must never
    make check_grant report approved. This is request_grant/check_grant's
    load-bearing separation, proven end to end rather than assumed from
    reading the two function bodies."""
    _signed_identity(tmp_path)
    tools.request_grant(capability="test.capability", scope="test", context="ctx", provenance="trusted", _home=tmp_path)
    result = tools.check_grant(
        capability="test.capability", scope="test", context="ctx", provenance="trusted", _home=tmp_path
    )
    assert result == {"approved": False}


def test_check_grant_reports_approved_after_a_real_human_approval(tmp_path: Path) -> None:
    """The other side: check_grant DOES see a real approval — proving the
    plumbing works, not just that it correctly reports nothing when there is
    nothing. Uses the human-only gate.approve() path directly, exactly the
    way a dashboard click would, never through an MCP tool."""
    from community_member import keystore
    from community_member.consent import ledger
    from community_member.consent.gate import ActionRequest, approve

    cfg = _signed_identity(tmp_path)
    # ``ledger``'s db path (and signing key) is module-global state (see
    # ledger.init's own docstring) that persists across tests in one
    # process — init it to THIS tmp_path, WITH the same signing key
    # tools._ensure_ledger_init would use, so approve() below and
    # check_grant's later read agree on both the file and whether rows are
    # expected to be signed.
    ledger.init(tmp_path / "consent.db", signing_key_b64=keystore.load_private_key(cfg.agent_id, dir=cfg._home))
    req = ActionRequest(capability="test.capability", scope="test", context="ctx", provenance="trusted")
    approve(req, chapter_id=f"local:{cfg.agent_id}", prompt_event_sha256="0" * 64, actor_agent_id=cfg.agent_id)

    result = tools.check_grant(
        capability="test.capability", scope="test", context="ctx", provenance="trusted", _home=tmp_path
    )
    assert result["approved"] is True
    assert result["event_sha256"]


# ── issue_receipt ─────────────────────────────────────────────────────────


def test_issue_receipt_rejects_an_unknown_category(tmp_path: Path) -> None:
    _signed_identity(tmp_path)
    with pytest.raises(tools.ToolError, match="not an ARP action category"):
        tools.issue_receipt(category="shell.exec", human_summary="ran a command", provenance="trusted", _home=tmp_path)


def test_issue_receipt_refuses_untrusted_provenance(tmp_path: Path) -> None:
    """⚠️ THE GUARD THIS UNIT EXISTS TO ASSERT. Untrusted content must never
    result in a signature — proven by checking the Agency Log stayed empty,
    not only that the call raised."""
    from community_member import arp

    cfg = _signed_identity(tmp_path)
    with pytest.raises(tools.ToolError, match="refused by the consent gate"):
        tools.issue_receipt(
            category="purchase",
            human_summary="a purchase a scraped web page told me to report",
            provenance="untrusted",
            _home=tmp_path,
        )
    log = arp.AgencyLog(cfg.home)
    assert log.list_recent(limit=10) == [], "a receipt was persisted despite the untrusted-provenance refusal"


def test_issue_receipt_signs_for_trusted_content(tmp_path: Path) -> None:
    cfg = _signed_identity(tmp_path)
    result = tools.issue_receipt(
        category="appointment_booked",
        human_summary="Booked a haircut",
        provenance="trusted",
        machine_payload={"service": "haircut"},
        _home=tmp_path,
    )
    assert result["receipt_id"]
    assert result["issuer_did"].startswith("did:key:z")
    assert result["screening"]["state"] == "prompt"

    from community_member import arp

    log = arp.AgencyLog(cfg.home)
    assert len(log.list_recent(limit=10)) == 1, "the signed receipt was not persisted to the Agency Log"


def test_issue_receipt_refuses_without_an_identity(tmp_path: Path) -> None:
    with pytest.raises(tools.ToolError, match="no sovereign identity"):
        tools.issue_receipt(category="purchase", human_summary="x", provenance="trusted", _home=tmp_path)


# ── verify_receipt ────────────────────────────────────────────────────────


def test_verify_receipt_round_trips_a_freshly_issued_one(tmp_path: Path) -> None:
    _signed_identity(tmp_path)
    issued = tools.issue_receipt(
        category="purchase", human_summary="Bought a widget", provenance="trusted", _home=tmp_path
    )
    from community_member import arp

    cfg = tools._config(tmp_path)
    log = arp.AgencyLog(cfg.home)
    full_receipt = log.get(issued["receipt_id"])
    assert full_receipt is not None

    result = tools.verify_receipt(full_receipt)
    assert result["ok"] is True, result["detail"]
    assert result["stage"] == "accepted"


def test_verify_receipt_catches_a_tampered_receipt(tmp_path: Path) -> None:
    _signed_identity(tmp_path)
    issued = tools.issue_receipt(
        category="purchase", human_summary="Bought a widget", provenance="trusted", _home=tmp_path
    )
    from community_member import arp

    cfg = tools._config(tmp_path)
    log = arp.AgencyLog(cfg.home)
    full_receipt = dict(log.get(issued["receipt_id"]))
    full_receipt["action"] = dict(full_receipt["action"])
    full_receipt["action"]["human_summary"] = "Bought something else entirely"

    result = tools.verify_receipt(full_receipt)
    assert result["ok"] is False
    assert result["stage"] == "signature"


def test_verify_receipt_needs_no_identity_of_its_own(tmp_path: Path) -> None:
    """No config, no keystore — verifying a receipt is pure and offline."""
    other_home = tmp_path / "issuer"
    other_home.mkdir()
    cfg = _signed_identity(other_home)
    issued = tools.issue_receipt(
        category="purchase", human_summary="Bought a widget", provenance="trusted", _home=other_home
    )
    from community_member import arp

    log = arp.AgencyLog(cfg.home)
    full_receipt = log.get(issued["receipt_id"])

    verifier_home = tmp_path / "verifier"  # deliberately never configured
    result = tools.verify_receipt(full_receipt)
    assert result["ok"] is True
    assert not verifier_home.exists(), "verify_receipt touched a directory it has no business creating"


# ── resolve_peer ──────────────────────────────────────────────────────────


def test_resolve_peer_reports_a_named_reason_for_an_unreachable_index() -> None:
    result = tools.resolve_peer("urn:ai:email:nobody@example.invalid", index="https://index.invalid.test")
    assert result["ok"] is False
    assert result["reason"]


def test_resolve_peer_reports_a_named_reason_for_no_locator() -> None:
    result = tools.resolve_peer("")
    assert result["ok"] is False
    assert result["reason"] == "no_locator"


# ── the category allowlist stays in lockstep with the ARP schema ──────────


def test_the_category_allowlist_matches_the_arp_schema() -> None:
    """tools.ARP_ACTION_CATEGORIES is a hand-kept copy (see its own comment
    for why it isn't imported); this is the guard that catches drift."""
    import json

    schema_path = Path(__file__).resolve().parents[1] / "schema" / "arp" / "0.1" / "action.schema.json"
    schema = json.loads(schema_path.read_text())
    schema_categories = set(schema["properties"]["category"]["enum"])
    assert tools.ARP_ACTION_CATEGORIES == schema_categories, (
        f"drifted from the schema: only here={tools.ARP_ACTION_CATEGORIES - schema_categories}, "
        f"only in schema={schema_categories - tools.ARP_ACTION_CATEGORIES}"
    )
