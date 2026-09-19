"""The six accountability primitives, as plain Python — no MCP in this file.

Kept apart from ``server.py`` (which only wraps these as MCP tools) so every
function here is testable by calling it directly, and so the MCP transport
layer can never be the thing under test when a tool's own logic is wrong.

WHAT THIS WRAPS, AND WHY NOTHING IS REIMPLEMENTED HERE: every primitive below
is an existing ``community_member`` function. This module adds no new
identity, consent, or signing mechanism — it is a thin adapter from "an MCP
tool call" to "the same call the CLI, the dashboard, and the built-in skills
already make." See each function's docstring for its one canonical source.

THE ONE RULE THAT GOVERNS EVERY "ACTING" TOOL HERE (request_grant,
issue_receipt): an MCP tool is invoked BY A MODEL, not a person, and a model's
input can carry attacker-controlled content it never asked for (indirect
prompt injection). ``consent.gate.evaluate`` already has exactly one rule for
this — an ``ActionRequest`` whose ``provenance`` is ``"untrusted"`` is
REJECTED outright, before any prompt is ever raised (see
``agent/community_member/consent/gate.py``'s own docstring: "the single most
important rule in the gate"). Both acting tools require the caller to state
``provenance`` and run the SAME ``evaluate`` call before doing anything
irreversible. This is reused, not reimplemented — see ``_screen`` below.

WHAT THIS DELIBERATELY DOES NOT DO: bridge a receipt's ``action.category`` to
a specific approved ``ActionRequest``. No such bridge exists anywhere else in
this codebase today — the consent gate's capability vocabulary
(``browser.navigate``, ``shell.exec``, ...) and the ARP receipt's category
vocabulary (``purchase``, ``appointment_booked``, ...) are disjoint, and
nothing translates between them (measured: neither ``arp.py`` nor the ARP
schema nor any action module references the other's vocabulary). Building
that bridge would be a new mechanism, not a wrapper around an existing one,
so it is out of scope here — see mcp_server/README.md's Security model
section for the full reasoning and what this DOES still close.
"""

from __future__ import annotations

import base64
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal

Provenance = Literal["trusted", "semi_trusted", "untrusted"]

# The ARP action.category enum, schema/arp/0.1/action.schema.json:12-35.
# Kept as a literal tuple (not imported) because the schema file is JSON, not
# Python, and importing a schema to get one enum would pull the whole
# validator in for a single list. Duplicated with intent: if this drifts from
# the schema, test_tools.py's own guard reddens (see
# test_the_category_allowlist_matches_the_arp_schema).
ARP_ACTION_CATEGORIES = frozenset(
    {
        "purchase",
        "payment_sent",
        "payment_received",
        "message_sent",
        "message_received",
        "decision_made",
        "data_shared",
        "appointment_booked",
        "appointment_cancelled",
        "subscription_changed",
        "record_filed",
        "account_created",
        "account_closed",
        "attestation_issued",
        "attestation_received",
        "commitment_entered",
        "commitment_fulfilled",
        "commitment_breached",
        "vote_cast",
        "authority_granted",
        "authority_revoked",
        "other",
    }
)


class ToolError(RuntimeError):
    """Raised for a refusal an MCP tool must surface to its caller, never a
    traceback. Every public function in this module catches its own domain
    errors and raises this instead, so ``server.py`` has one exception type
    to turn into an MCP tool error result."""


def _config(_home: Path | None = None) -> Any:
    """``_home`` is an internal override for tests only — never an MCP tool
    parameter (see server.py: none of the public wrappers accept it). A model
    choosing this agent's identity directory is not a capability anything
    should expose; production always resolves the one real
    ``COMMUNITY_MEMBER_HOME``, exactly like the CLI and the dashboard do."""
    from community_member.config import Config

    return Config.load(home=_home)


def _chapter_id(cfg: Any) -> str:
    """Mirrors server.py's own ``_chapter_id`` exactly (W5 consent ledger
    scoping id) — a chapter-joined agent uses its chapter's identity; a
    standalone one gets a stable local id so its own ledger rows are still
    self-consistent across calls."""
    return f"local:{cfg.agent_id}" if cfg.agent_id else "local:unknown"


def _ensure_ledger_init(cfg: Any) -> None:
    """Mirrors server.py's own ``_ensure_ledger_init`` exactly: lazy-init,
    signed when a signing key exists, silently unsigned otherwise (never
    raises — the ledger's job is to record, not to gate on its own health)."""
    from community_member import keystore
    from community_member.consent import ledger as _ledger

    priv = keystore.load_private_key(cfg.agent_id, dir=cfg._home) if cfg.agent_id else None
    try:
        _ledger.init(cfg.home / "consent.db", signing_key_b64=priv)
    except Exception:
        pass


def _screen(
    *, capability: str, scope: str, context: str, provenance: Provenance, rationale: str = ""
) -> tuple[Any, Any]:
    """Run the caller's request through the REAL consent gate and return its
    verdict. Never mutates the ledger — callers that want an audit trail
    call ``gate.check_and_record`` themselves (request_grant does)."""
    from community_member.consent.gate import ActionRequest, evaluate

    req = ActionRequest(
        capability=capability,
        scope=scope,
        context=context[:2000],
        provenance=provenance,
        rationale=rationale[:2000],
    )
    return req, evaluate(req)


# ── register_agent ────────────────────────────────────────────────────────


def register_agent(*, _home: Path | None = None) -> dict[str, Any]:
    """Report this machine's sovereign identity. Read-only — never mints one.

    Canonical source: ``community_member.wizard.express_setup`` mints a fresh
    identity from a one-time recovery phrase that is returned exactly once
    and never persisted anywhere (see its own docstring). An MCP tool call
    is a model-facing channel, not the owner's own terminal — handing a
    durable recovery secret to whatever process is driving the model is
    exactly the kind of exposure this whole stack exists to prevent. So this
    tool refuses to mint: if no identity exists yet, it names the command
    the owner runs locally (`community-member wizard --express --name <name>`) and
    stops there. Once an identity exists, this is a plain, safe read.
    """
    from community_member.crypto import build_did_key

    cfg = _config(_home)
    if not cfg.is_configured():
        raise ToolError(
            "no sovereign identity is set up on this machine yet. This tool will not mint one "
            "over MCP — the recovery phrase must never cross a model-facing channel. Run "
            "`community-member wizard --express --name <name>` locally first, then retry."
        )
    did = build_did_key(cfg.public_key) if cfg.public_key else ""
    return {
        "agent_id": cfg.agent_id,
        "name": cfg.name or cfg.agent_id,
        "did": did,
        "chapter_url": cfg.chapter_url or None,
        "has_signing_key": cfg.has_keypair(),
    }


# ── request_grant / check_grant ──────────────────────────────────────────


def request_grant(
    *,
    capability: str,
    scope: str,
    context: str,
    provenance: Provenance,
    rationale: str = "",
    _home: Path | None = None,
) -> dict[str, Any]:
    """Propose an action for consent and record the verdict.

    Canonical source: ``community_member.consent.gate.check_and_record`` —
    literally the same call ``execute_plan`` makes for every gated action
    (browser/desktop/shell/files/net). Returns the gate's verdict AS
    RECORDED, never invented here.

    ⚠️ THIS CAN NEVER RETURN "approved". ``evaluate()`` (which
    ``check_and_record`` calls) has exactly two possible outcomes, "reject"
    and "prompt" — there is no code path in it that constructs "approved".
    An actual approval is a separate, human-only action
    (``consent.gate.approve``), deliberately NOT exposed as an MCP tool: a
    model can ask for consent and can be told a human already granted it
    (``check_grant``), but it can never grant itself one.
    """
    from community_member.consent.gate import check_and_record

    cfg = _config(_home)
    _ensure_ledger_init(cfg)
    req, _ = _screen(capability=capability, scope=scope, context=context, provenance=provenance, rationale=rationale)
    decision = check_and_record(req, chapter_id=_chapter_id(cfg), actor_agent_id=cfg.agent_id or None)
    if decision.state == "approved":  # pragma: no cover — see docstring; asserted directly in test_tools.py
        raise ToolError("internal invariant broken: the consent gate returned 'approved' from a bare proposal")
    return {"state": decision.state, "reason": decision.reason, "event_sha256": decision.event_sha256}


def check_grant(
    *,
    capability: str,
    scope: str,
    context: str,
    provenance: Provenance,
    _home: Path | None = None,
) -> dict[str, Any]:
    """Read whether a human already approved this exact action. Never mints,
    never prompts, never mutates the ledger.

    Canonical source: ``community_member.consent.gate.find_valid_approval`` —
    matches on the same four fields a stored approval's own detail carries
    (capability, scope, context, provenance), verifies the stored row's hash
    and signature, and honours its 5-minute expiry. A capability/scope/
    context combination that was never approved, or whose approval expired
    or was already spent, reads as not-approved here — the same as one that
    was never asked for.
    """
    from community_member.consent.gate import find_valid_approval

    cfg = _config(_home)
    _ensure_ledger_init(cfg)
    req, _ = _screen(capability=capability, scope=scope, context=context, provenance=provenance)
    approval = find_valid_approval(req, chapter_id=_chapter_id(cfg))
    if approval is None:
        return {"approved": False}
    detail = approval.get("detail") or {}
    return {
        "approved": True,
        "event_sha256": approval.get("event_sha256"),
        "expires_at": detail.get("expires_at"),
    }


# ── issue_receipt ─────────────────────────────────────────────────────────


def issue_receipt(
    *,
    category: str,
    human_summary: str,
    provenance: Provenance,
    outcome: str = "completed",
    machine_payload: dict[str, Any] | None = None,
    _home: Path | None = None,
) -> dict[str, Any]:
    """Sign and persist an ARP receipt for something that already happened.

    Canonical source: the exact pattern
    ``agent/community_member/builtin_skills/booking/skill.py``'s
    ``_emit_receipt`` already uses — load the identity, load its signing key,
    ``arp.emit`` into the local Agency Log. This tool generalises that one
    hardcoded category to any caller-supplied one.

    ⚠️ THE GUARD THIS UNIT WAS BUILT TO ASSERT: before anything is signed,
    the request is screened through the SAME ``consent.gate.evaluate`` an
    action module calls. A request whose ``provenance`` is ``"untrusted"``
    is refused, exactly as it would be for a gated action — a model cannot
    get a receipt signed for something whose only authorization trail is
    content this agent does not trust. This is deliberately the ONE check
    reused here rather than a bespoke one: the untrusted-provenance rule is
    the load-bearing anti-injection rule the whole consent gate is built
    around, so reusing it (instead of writing a second, divergent version of
    it) is what keeps the two systems from disagreeing about what counts as
    unsafe.

    NOT A FULL CONSENT-TO-RECEIPT BRIDGE — see the module docstring's "what
    this deliberately does not do." A "prompt"-state screening result
    (trusted/semi_trusted content, no rule against it) does not block
    signing: booking's own receipt has never required a human approval
    either, and inventing that requirement here — for this one call path
    only — would make issue_receipt inconsistent with every other receipt
    this codebase already signs unconditionally.
    """
    if category not in ARP_ACTION_CATEGORIES:
        raise ToolError(f"{category!r} is not an ARP action category. Valid: {sorted(ARP_ACTION_CATEGORIES)}")

    cfg = _config(_home)
    _ensure_ledger_init(cfg)
    _, decision = _screen(
        capability="mcp.issue_receipt",
        scope=category,
        context=human_summary,
        provenance=provenance,
    )
    if decision.state == "reject":
        raise ToolError(f"refused by the consent gate: {decision.reason}")

    if not cfg.is_configured():
        raise ToolError("no sovereign identity is set up on this machine yet; call register_agent's setup step first")

    from community_member import arp, keystore

    priv_b64 = keystore.load_private_key(cfg.agent_id, dir=cfg._home)
    if not priv_b64:
        raise ToolError("no signing key for this identity — a receipt cannot be signed")
    try:
        seed = base64.b64decode(priv_b64)
    except (ValueError, TypeError) as exc:
        raise ToolError("signing key is not valid base64") from exc
    if len(seed) != 32:
        raise ToolError("signing key is not a 32-byte Ed25519 seed")

    log = arp.AgencyLog(cfg.home)
    receipt = arp.emit(
        {
            "category": category,
            "outcome": outcome,
            "human_summary": human_summary,
            "machine_payload": machine_payload or {},
        },
        seed,
        agency_log=log,
        chapter_url=cfg.chapter_url or None,
        push=bool(cfg.chapter_url),
    )
    return {
        "receipt_id": receipt["receipt_id"],
        "issuer_did": receipt["issuer_did"],
        "principal_did": receipt["principal_did"],
        "signature": receipt["signature"],
        "screening": {"state": decision.state, "reason": decision.reason},
    }


# ── verify_receipt ────────────────────────────────────────────────────────


def verify_receipt(receipt: dict[str, Any], *, mode: str = "strict") -> dict[str, Any]:
    """Verify a receipt fully offline — schema, Ed25519 signature, hash chain.

    Canonical source: ``community_member.arp.verify_receipt``, the same
    pipeline the chapter runs on ingest. No network call, no identity of
    this agent's own required — this checks the RECEIPT's own signature
    under its own ``issuer_did``, so it verifies a stranger's receipt as
    readily as one this agent issued itself.
    """
    from community_member import arp

    result = arp.verify_receipt(receipt, mode=mode)
    return asdict(result)


# ── resolve_peer ──────────────────────────────────────────────────────────


def resolve_peer(locator: str, *, index: str | None = None) -> dict[str, Any]:
    """Resolve a URN locator to a callable peer through the NANDA Index.

    Canonical source: ``community_member.nanda_index.discover`` — resolve the
    locator, then follow the record to the actual agent card. Read-only: no
    identity of this agent is presented, nothing is registered, nothing is
    called. Returns ``ok: False`` with a named ``reason`` on any failure
    (unreachable index, unresolvable locator, no card) rather than raising —
    "the peer could not be found" is an ordinary outcome for a discovery
    tool, not an error.
    """
    from community_member.nanda_index import discover

    found = discover(locator, index=index)
    return {
        "ok": found.ok,
        "reason": found.reason,
        "detail": found.detail,
        "locator": found.locator,
        "identifier": found.identifier,
        "endpoint": found.endpoint,
        "did": found.did,
    }
