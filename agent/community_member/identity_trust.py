"""Identity trust — auto-approve trusted-provenance actions when the
user (or the federation) trusts the agent enough.

Two trust signals:

  - ``local_trust`` (0-100): the user's own assertion of how much
    they trust their local agent. Lives in ``identity_trust.json``
    under ``CONFIG_DIR``. Default 30 — visible friction so a fresh
    install doesn't quietly auto-execute. The user can crank to 100
    via the Settings page.

  - ``chapter_trust`` (0-100): the federation's view of this agent,
    fetched from the chapter's ``/api/agents/{agent_id}/trust``
    endpoint. Cached for 15 minutes in ``chapter_trust_cache.json``.
    Read-only — only the chapter's governance can move it.

The integration rule (mirrors :mod:`graduation.auto_approval`)::

    effective = max(local_trust, chapter_trust)
    if req.provenance == "trusted" and effective >= AUTO_APPROVE_THRESHOLD:
        → auto-approve, write a ``consent.auto_approved`` row with
          ``decision_reason="trust_threshold"`` and the trust scores
          snapshot (so the audit chain can reconstruct exactly why).
    else:
        → fall through to graduation / user prompt.

Untrusted-provenance actions (the planner read external content) are
*unconditionally* gated regardless of trust. That's the indirect
prompt-injection defense and is non-negotiable.

Distinct from :mod:`community_member.trust` which handles the
separate concern of chapter-identity TOFU verification.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from community_member.consent import gate, ledger
from community_member.consent.gate import ActionRequest

__all__ = [
    "AUTO_APPROVE_THRESHOLD",
    "CHAPTER_TRUST_TTL_SECONDS",
    "DEFAULT_LOCAL_TRUST",
    "TrustSnapshot",
    "auto_approve_if_trusted",
    "effective_trust",
    "fetch_chapter_trust",
    "load_chapter_trust",
    "load_local_trust",
    "save_chapter_trust",
    "save_local_trust",
    "snapshot",
]

AUTO_APPROVE_THRESHOLD = 70
DEFAULT_LOCAL_TRUST = 30
CHAPTER_TRUST_TTL_SECONDS = 900  # 15 min

_LOCAL_TRUST_FILENAME = "identity_trust.json"
_CHAPTER_TRUST_FILENAME = "chapter_trust_cache.json"


@dataclass(frozen=True)
class TrustSnapshot:
    local: int
    chapter: int
    chapter_refreshed_at: float | None
    effective: int
    threshold: int


def load_local_trust(config_dir: Path) -> int:
    """Read the user's self-asserted trust ceiling. Returns the
    default if the file is missing, empty, or malformed."""
    p = config_dir / _LOCAL_TRUST_FILENAME
    if not p.exists():
        return DEFAULT_LOCAL_TRUST
    try:
        data = json.loads(p.read_text() or "{}")
    except json.JSONDecodeError:
        return DEFAULT_LOCAL_TRUST
    raw = data.get("local_trust", DEFAULT_LOCAL_TRUST)
    try:
        return max(0, min(100, int(raw)))
    except (TypeError, ValueError):
        return DEFAULT_LOCAL_TRUST


def save_local_trust(config_dir: Path, value: int) -> None:
    """Persist the user's trust ceiling. Clamps to 0-100."""
    config_dir.mkdir(parents=True, exist_ok=True)
    v = max(0, min(100, int(value)))
    (config_dir / _LOCAL_TRUST_FILENAME).write_text(json.dumps({"local_trust": v}, indent=2))


def load_chapter_trust(config_dir: Path) -> tuple[int, float | None]:
    """Returns (score, refreshed_at). (0, None) if never fetched."""
    p = config_dir / _CHAPTER_TRUST_FILENAME
    if not p.exists():
        return 0, None
    try:
        data = json.loads(p.read_text() or "{}")
    except json.JSONDecodeError:
        return 0, None
    score = data.get("score", 0)
    refreshed_at = data.get("refreshed_at")
    try:
        return (
            max(0, min(100, int(score))),
            float(refreshed_at) if refreshed_at else None,
        )
    except (TypeError, ValueError):
        return 0, None


def save_chapter_trust(
    config_dir: Path,
    score: int,
    *,
    raw: dict | None = None,
) -> None:
    """Cache the chapter-attested trust with a wall-clock timestamp.
    The raw payload (tier, projection, history) is stored so the
    dashboard can show next-tier info without a re-fetch."""
    config_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "score": max(0, min(100, int(score))),
        "refreshed_at": time.time(),
        "raw": raw or {},
    }
    (config_dir / _CHAPTER_TRUST_FILENAME).write_text(json.dumps(payload, indent=2))


def fetch_chapter_trust(chapter_url: str, agent_id: str, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    """Hit ``/api/agents/{agent_id}/trust`` and return ``(score_0_100, raw)``.

    The chapter's score scale isn't formally bounded; we clamp to
    0-100 so it composes with ``local_trust`` symmetrically. Raises
    on network or HTTP errors so the caller can decide whether to
    keep the stale cache or surface the failure.

    ``headers`` carries the agent's own signature. The org answers this
    route to a stranger only for a member who opted into its listing; a
    member reading their OWN score signs, and the server treats a signed
    member like any other. Unsigned, a member who has not opted in gets the
    404 an unknown id gets — by design, so the route cannot be used to probe
    which ids exist.
    """
    import httpx

    url = f"{chapter_url.rstrip('/')}/api/agents/{agent_id}/trust"
    resp = httpx.get(url, headers=headers or {}, timeout=5.0)
    resp.raise_for_status()
    data = resp.json()
    raw_score = data.get("score", 0)
    try:
        score = max(0, min(100, int(float(raw_score))))
    except (TypeError, ValueError):
        score = 0
    return score, data


def effective_trust(local: int, chapter: int) -> int:
    return max(0, min(100, max(int(local), int(chapter))))


def snapshot(config_dir: Path, *, threshold: int = AUTO_APPROVE_THRESHOLD) -> TrustSnapshot:
    local = load_local_trust(config_dir)
    chapter, refreshed_at = load_chapter_trust(config_dir)
    return TrustSnapshot(
        local=local,
        chapter=chapter,
        chapter_refreshed_at=refreshed_at,
        effective=effective_trust(local, chapter),
        threshold=threshold,
    )


def auto_approve_if_trusted(
    req: ActionRequest,
    *,
    chapter_id: str,
    local_trust: int,
    chapter_trust: int,
    actor_agent_id: str | None = None,
    threshold: int = AUTO_APPROVE_THRESHOLD,
) -> str | None:
    """Mirror of :func:`graduation.auto_approval.auto_approve_if_graduated`.

    Synthesizes a self-approval when the effective trust meets the
    threshold AND the provenance isn't ``untrusted``. Returns the
    ``event_sha256`` the executor needs, or ``None`` to fall through.

    Provenance policy
    -----------------

      * ``trusted``     — user typed the request directly. Auto-
                          approves at high trust.
      * ``semi_trusted``— originated from a chapter-peer-signed
                          message. Cryptographically verified by the
                          chapter's TOFU layer; auto-approves at high
                          trust. (This is most of what the autonomous
                          think loop emits, so excluding it would
                          make the trust dial near-useless.)
      * ``untrusted``   — planner read external content (web, email,
                          skill output). Returns ``None`` always.
                          Prompt-injection defense cannot be unlocked
                          by trust under any circumstances.
    """
    if req.provenance == "untrusted":
        return None
    eff = effective_trust(local_trust, chapter_trust)
    if eff < threshold:
        return None

    auto_hash = gate.approve(
        req,
        chapter_id=chapter_id,
        prompt_event_sha256="trust_threshold",
        actor_agent_id=actor_agent_id,
    )
    ledger.record(
        chapter_id=chapter_id,
        action="consent.auto_approved",
        actor_agent_id=actor_agent_id,
        target_type="capability",
        target_id=req.capability,
        outcome="ok",
        detail={
            "approval_event_sha256": auto_hash,
            "capability": req.capability,
            "scope": req.scope,
            "provenance": req.provenance,
            "decision_reason": "trust_threshold",
            "trust": {
                "local": int(local_trust),
                "chapter": int(chapter_trust),
                "effective": eff,
                "threshold": threshold,
            },
        },
    )
    return auto_hash
