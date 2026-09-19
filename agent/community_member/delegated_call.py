"""One A2A call to another agent, under an explicit authority, with the evidence exported.

The runtime already has every piece of this: a principal can sign a Delegated
Authority Token naming what its agent may do (``_dat.build_dat``), the consent
gate records every pre-action verdict as a hash-chained ledger row and a signed
sm-aae envelope (``consent.gate.record_decision``), and
``GoogleA2AClient.send_task_recorded`` writes the attempt ahead of the call,
asks the counterparty to co-sign and finalizes the receipt. What did not exist
was one verb that put them in order for a single outbound call:

    authority → consent verdict (recorded, signed) → attempt → call → co-signed
    receipt → evidence on disk

so a reader could run one thing and carry the result away. That is this module.
``community-member call`` is its CLI.

What the authority check establishes, exactly:

* the DAT's ``grantee_did`` is THIS agent, and its ``grantor_did`` is a
  different key (``owner.py``: a self-granted DAT verifies but proves nothing);
* the DAT's signature verifies under ``grantor_did``, its validity window
  contains now, and its ``scope.action_categories`` names the action being
  taken — ``a2a.tasks/send#<tool>`` — not a broader or different one. The
  vendored verifier reports a window failure as "outside validity window";
  this module says which side (expired at / not valid until), because "your
  authority expired at 09:00" and "your authority starts at 09:00" are
  different instructions to the operator.

It does NOT establish that the grantor is the agent's real principal (that is
the owner binding's job, ``owner.py``), nor anything about the counterparty's
authority to act — the counterparty runs its own gate.

Every verdict, approve or refuse, is recorded before anything is sent. A
refusal leaves a ledger row and an envelope whose outcome is ``denied``, and
no attempt, no receipt, no wire traffic. Refusals are exit statuses a caller
can act on (:data:`EXIT_REFUSED`, :data:`EXIT_DUPLICATE`), never exceptions
dressed as generic failure.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .arp import AgencyLog, DuplicateActionError, did_from_private_key
from .config import Config
from .consent import aae_emit, gate, ledger
from .dat import verify_counterparty_dat

__all__ = [
    "EXIT_DUPLICATE",
    "EXIT_REFUSED",
    "EXIT_UNRECEIPTED",
    "AuthorityVerdict",
    "CallReport",
    "action_name",
    "call_under_authority",
    "check_authority",
    "did_from_card",
    "export_refusal",
]

EXIT_REFUSED = 2  # the authority check refused; nothing was sent
EXIT_DUPLICATE = 3  # this action_ref already ran (or has an unknown outcome); not re-sent
EXIT_UNRECEIPTED = 4  # the call succeeded, the receipt stage failed; a receipt is owed

CAPABILITY = "a2a.send"
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def action_name(tool: str) -> str:
    """The name a DAT must carry to authorise ``tool`` on a peer. One tool, one
    name: a grant for ``save_note`` says nothing about ``install_skill``."""
    return f"a2a.tasks/send#{tool}"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def did_from_card(card: dict[str, Any]) -> str:
    """The did:key an agent card publishes, read the way smb_funnel/src/arp.js
    reads it (``x-nanda.did``, else ``authentication.credentials``), with
    AgentFacts' ``id`` accepted too. Empty string when the card carries none."""
    if not isinstance(card, dict):
        return ""
    ext = card.get("x-nanda")
    auth = card.get("authentication")
    for candidate in (
        ext.get("did") if isinstance(ext, dict) else None,
        auth.get("credentials") if isinstance(auth, dict) else None,
        card.get("id"),
    ):
        if isinstance(candidate, str) and candidate.startswith("did:key:"):
            return candidate
    return ""


@dataclass(frozen=True)
class AuthorityVerdict:
    ok: bool
    # no_grant | grantee | grantor | signature | expired | not_yet_valid |
    # scope | delegation | revoked | depth | accepted
    stage: str
    detail: str
    grant_id: str | None


def check_authority(dat: dict[str, Any], *, self_did: str, tool: str, now: str | None = None) -> AuthorityVerdict:
    """Decide whether ``dat`` authorises THIS agent to call ``tool`` now."""
    grant_id = dat.get("grant_id") if isinstance(dat, dict) else None
    if not isinstance(dat, dict) or not isinstance(grant_id, str):
        return AuthorityVerdict(False, "no_grant", "no grant was presented (not a DAT: no grant_id)", None)
    if dat.get("grantee_did") != self_did:
        detail = f"grant {grant_id} names grantee {dat.get('grantee_did')!r}, this agent is {self_did}"
        return AuthorityVerdict(False, "grantee", detail, grant_id)
    if dat.get("grantor_did") == self_did:
        detail = f"grant {grant_id} is self-granted: grantor is this agent's own key"
        return AuthorityVerdict(False, "grantor", detail, grant_id)
    now = now or _now_iso()
    result = verify_counterparty_dat(dat, now=now, category=action_name(tool))
    if result.ok:
        return AuthorityVerdict(True, "accepted", f"grant {grant_id} authorises {action_name(tool)}", grant_id)
    if result.stage == "window":
        not_after, not_before = str(dat.get("not_after", "")), str(dat.get("not_before", ""))
        if not_after and now > not_after:
            return AuthorityVerdict(False, "expired", f"grant {grant_id} expired at {not_after} (now {now})", grant_id)
        detail = f"grant {grant_id} is not valid until {not_before} (now {now})"
        return AuthorityVerdict(False, "not_yet_valid", detail, grant_id)
    if result.stage == "scope":
        named = (dat.get("scope") or {}).get("action_categories")
        return AuthorityVerdict(
            False, "scope", f"grant {grant_id} names {named!r}, not {action_name(tool)!r}", grant_id
        )
    return AuthorityVerdict(False, result.stage, f"grant {grant_id}: {result.detail}", grant_id)


@dataclass
class CallReport:
    outcome: str  # sent | refused | duplicate | unreceipted
    self_did: str
    counterparty_did: str | None
    verdict: AuthorityVerdict | None
    consent_event_sha256: str | None = None
    aae_envelope_hash: str | None = None
    attempt_id: str | None = None
    receipt_id: str | None = None
    corroborated: bool | None = None
    result: dict[str, Any] | None = None
    error: str | None = None

    def exit_code(self) -> int:
        return {"sent": 0, "refused": EXIT_REFUSED, "duplicate": EXIT_DUPLICATE, "unreceipted": EXIT_UNRECEIPTED}[
            self.outcome
        ]


# ── the pieces ─────────────────────────────────────────────────────────────


def _fetch_json(url: str, timeout: float = 15.0) -> dict[str, Any]:
    with _NO_PROXY.open(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _init_ledger(config: Config) -> None:
    ledger.init(config.home / "consent.db", signing_key_b64=config.private_key)


def _record_verdict(
    config: Config, *, self_did: str, peer_url: str, tool: str, verdict: AuthorityVerdict, task_id: str | None
) -> tuple[str, dict[str, Any] | None]:
    """The consent gate's record of this verdict: a ledger row and, beside it,
    a signed sm-aae envelope whose outcome is ``authorized`` or ``denied``.
    Returns (consent event sha256, envelope or None)."""
    req = gate.ActionRequest(
        capability=CAPABILITY,
        scope=f"{peer_url} {action_name(tool)}",
        context=f"delegated_call:{verdict.grant_id or 'no-grant'}",
        provenance="trusted",
        source_ref=verdict.grant_id,
        extra={"tool": tool, "task_id": task_id or "", "authority_stage": verdict.stage},
    )
    decision = gate.ConsentDecision(
        state="approved" if verdict.ok else "reject",
        reason=(f"dat:{verdict.grant_id}" if verdict.ok else f"authority_{verdict.stage}: {verdict.detail}"),
    )
    event_sha = gate.record_decision(req, decision, chapter_id=f"local:{config.agent_id}", actor_agent_id=self_did)
    # list_envelopes is oldest-first and unbounded by default; the envelope for
    # this verdict is the newest, so read the whole chain and search from the end.
    envelope = next(
        (
            e
            for e in reversed(aae_emit.list_envelopes(self_did))
            if ((e.get("action") or {}).get("params") or {}).get("consent_event_sha256") == event_sha
        ),
        None,
    )
    return event_sha, envelope


def _consent_row(event_sha: str) -> dict[str, Any] | None:
    for row in ledger.list_events(limit=1000):
        if row.get("event_sha256") == event_sha:
            return row
    return None


def _org_evidence(config: Config, receipt_id: str) -> dict[str, Any]:
    """What the org holds about this receipt, read back from the org.

    ``receipt_record``: the org's own copy, from the principal-scoped signed
    read (``GET /api/receipts`` as this agent) — the proof that the push landed.
    ``checkpoint`` / ``inclusion_proof``: the org's signed Merkle checkpoint and
    this receipt's proof under it, which the server serves only when its Issuer
    Log is local SQLite (no database). A database-backed org answers 404 there,
    and that is written down as ``unavailable`` rather than left out.
    """
    from .a2a_client import A2AClient
    from .auth import init_keys

    out: dict[str, Any] = {}
    base = config.chapter_url.rstrip("/")
    try:
        # The org client signs with the process-wide keys auth.init_keys loads
        # (serve.py does this at boot); this process is the CLI, so load them here.
        init_keys(config.private_key, config.public_key)
        mine = A2AClient(base, config.agent_id, config.private_key, config.public_key).api_call("GET", "/api/receipts")
        rows = mine.get("receipts", mine) if isinstance(mine, dict) else mine
        match = next((r for r in rows if isinstance(r, dict) and r.get("receipt_id") == receipt_id), None)
        out["receipt_record"] = (
            match if match is not None else {"unavailable": "the org's signed read does not list it"}
        )
    except Exception as exc:  # noqa: BLE001 — the org's answer is evidence either way; say what it was
        out["receipt_record"] = {"unavailable": f"{type(exc).__name__}: {exc}"}
    for name, path in (("checkpoint", "/api/checkpoint"), ("inclusion_proof", f"/api/checkpoint/proof/{receipt_id}")):
        try:
            out[name] = _fetch_json(base + path)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            out[name] = {"unavailable": f"{type(exc).__name__}: {exc}"}
    return out


def export_refusal(
    evidence_dir: Path, *, report: CallReport, dat: dict[str, Any] | None, envelope: dict | None
) -> None:
    """What a refusal leaves behind: the verdict, the grant it judged, the
    ledger row and the envelope that says ``denied`` — and pointedly no receipt."""
    _write(evidence_dir / "decision.json", _report_dict(report))
    if dat is not None:
        _write(evidence_dir / "authorization" / "dat.json", dat)
    if report.consent_event_sha256:
        _write(evidence_dir / "authorization" / "consent_event.json", _consent_row(report.consent_event_sha256))
    if envelope is not None:
        _write(evidence_dir / "authorization" / "aae_envelope.json", envelope)


def _report_dict(report: CallReport) -> dict[str, Any]:
    d = {k: v for k, v in report.__dict__.items() if k != "verdict"}
    d["verdict"] = report.verdict.__dict__ if report.verdict else None
    return d


# ── the verb ───────────────────────────────────────────────────────────────


def call_under_authority(
    config: Config,
    *,
    peer_url: str,
    tool: str,
    args: dict[str, Any],
    dat: dict[str, Any],
    evidence_dir: Path,
    task_id: str | None = None,
    cosign: bool = True,
    push: bool = True,
    now: str | None = None,
) -> CallReport:
    """The verb. See the module docstring for the order and the guarantees."""
    from .a2a_client_v2 import ActionSucceededUnreceipted, GoogleA2AClient

    if not config.private_key:
        raise RuntimeError("no private key: the keystore did not unlock (check COMMUNITY_MEMBER_PASSPHRASE)")
    sk = base64.b64decode(config.private_key)
    self_did = did_from_private_key(sk)
    _init_ledger(config)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # 1. Authority, then the verdict on record — before anything touches the wire.
    verdict = check_authority(dat, self_did=self_did, tool=tool, now=now)
    event_sha, envelope = _record_verdict(
        config, self_did=self_did, peer_url=peer_url, tool=tool, verdict=verdict, task_id=task_id
    )
    report = CallReport(
        outcome="refused" if not verdict.ok else "sent",
        self_did=self_did,
        counterparty_did=None,
        verdict=verdict,
        consent_event_sha256=event_sha,
        aae_envelope_hash=(envelope or {}).get("envelope_hash") or (aae_hash(envelope) if envelope else None),
    )
    if not verdict.ok:
        export_refusal(evidence_dir, report=report, dat=dat, envelope=envelope)
        return report

    # 2. Who is being called: the counterparty's identity from ITS card, not from the grant or the caller.
    card = _fetch_json(peer_url.rstrip("/") + "/.well-known/agent.json")
    counterparty_did = did_from_card(card)
    counterparty_label = str(card.get("name") or card.get("label") or card.get("agent_name") or counterparty_did)
    if not counterparty_did:
        raise RuntimeError(f"the peer's agent card carries no did:key: {card!r}")
    report.counterparty_did = counterparty_did
    _write(evidence_dir / "counterparty_card.json", card)
    _write(evidence_dir / "authorization" / "dat.json", dat)
    _write(evidence_dir / "authorization" / "consent_event.json", _consent_row(event_sha))
    if envelope is not None:
        _write(evidence_dir / "authorization" / "aae_envelope.json", envelope)

    # 3. The call, written ahead, co-signed, receipted.
    log = AgencyLog(home=config.home)
    client = GoogleA2AClient(
        peer_url, agent_id=config.agent_id, private_key=config.private_key, public_key=config.public_key
    )
    try:
        result = client.send_task_recorded(
            tool,
            args,
            counterparty_did=counterparty_did,
            counterparty_label=counterparty_label,
            sk_bytes=sk,
            agency_log=log,
            category="message_sent",
            chapter_url=config.chapter_url or None,
            push=push and bool(config.chapter_url),
            cosign=cosign,
            task_id=task_id,
        )
    except DuplicateActionError as exc:
        report.outcome, report.error = "duplicate", f"{type(exc).__name__}: {exc}"
        prior = log.latest_attempt(task_id) if task_id else None
        _write(evidence_dir / "decision.json", {**_report_dict(report), "prior_attempt": prior})
        return report
    except ActionSucceededUnreceipted as exc:
        report.outcome, report.attempt_id = "unreceipted", exc.attempt_id
        report.error = f"receipt stage failed: {exc.cause}"
        report.result = exc.result
        _write(evidence_dir / "acknowledgement.json", exc.result)
        _write(evidence_dir / "attempt.json", log.get_attempt(exc.attempt_id))
        _write(evidence_dir / "decision.json", _report_dict(report))
        return report
    finally:
        client.close()

    attempt = log.latest_attempt(task_id) if task_id else None
    if attempt is None:
        attempts = log.list_attempts(state="succeeded", limit=1)
        attempt = attempts[0] if attempts else None
    receipt = log.get(attempt["receipt_id"]) if attempt and attempt.get("receipt_id") else None
    if receipt is None:
        raise RuntimeError("the attempt finalized succeeded but no receipt is in the Agency Log")
    from sm_arp.vrp import is_corroborated

    report.attempt_id = attempt["attempt_id"]
    report.receipt_id = receipt["receipt_id"]
    report.corroborated = bool(is_corroborated(receipt))
    report.result = result
    _write(evidence_dir / "receipt.json", receipt)
    _write(evidence_dir / "attempt.json", attempt)
    _write(evidence_dir / "acknowledgement.json", result)
    if config.chapter_url and push:
        for name, payload in _org_evidence(config, receipt["receipt_id"]).items():
            _write(evidence_dir / "org" / f"{name}.json", payload)
    _write(evidence_dir / "decision.json", _report_dict(report))
    return report


def aae_hash(envelope: dict[str, Any]) -> str | None:
    try:
        from sm_aae import envelope_hash

        return str(envelope_hash(envelope))
    except Exception:  # noqa: BLE001 — the hash is a convenience field, the envelope file is the evidence
        return None


# ── the principal's side: minting a grant ──────────────────────────────────


def mint_grant(
    *,
    grantee_did: str,
    tool: str,
    not_after: str,
    not_before: str | None = None,
    grantor_phrase: str | None = None,
    human_summary: str | None = None,
) -> tuple[dict[str, Any], str]:
    """A principal signs a DAT naming exactly one action for exactly one agent.

    The grantor is derived from ``grantor_phrase`` (BIP39, the owner path) when
    given, otherwise from a fresh phrase minted here — either way the signing
    key lives for this call and is dropped; only the phrase can recreate it.
    Returns (dat, mnemonic). The mnemonic is the principal's secret and is
    returned to the caller to keep; it is never written by this function.
    """
    from . import owner
    from ._dat import build_dat

    identity = owner.recover_owner_identity(grantor_phrase) if grantor_phrase else owner.mint_owner_identity()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", not_after):
        raise ValueError(f"not_after must be RFC 3339 UTC like 2026-01-01T00:00:00Z, got {not_after!r}")
    dat = build_dat(
        grantor_sk_bytes=identity.signing_key_bytes(),
        grantor_did=identity.did,
        grantee_did=grantee_did,
        action_categories=[action_name(tool)],
        not_after=not_after,
        not_before=not_before,
        human_summary=human_summary or f"may call {tool} on a peer over A2A",
    )
    return dat, identity.mnemonic
