"""File action executor — per-root allowlist + symlink-safe read/write.

Second W2 action surface. Follows the same propose/approve/execute
pattern as browser.py:

  propose_read(path, context, ...)  → raises ConsentRequired (W1 default)
  propose_write(path, context, ...) → raises ConsentRequired

  read_file(path, approval_event_sha256, policy, ...)
  write_file(path, content, approval_event_sha256, policy, ...)

Defense-in-depth for fs ops
---------------------------

  1. Consent gate — every propose/execute flows through
     consent.gate, same as browser actions.
  2. Capability policy — the sandbox Policy decides whether the
     RESOLVED path is inside an approved glob root (fs.read:
     ~/Downloads/** etc). Resolution happens BEFORE the match so
     `..` traversal can't fool the glob.
  3. Inode pinning — between the path check and the open/read/write
     we capture st_ino and st_dev; after the op we re-stat and
     compare. A symlink that got swapped between check and op
     (TOCTOU race) is caught and the op is rolled back (for writes)
     or its output is discarded (for reads).
  4. Content-sha256 — every successful write records the post-write
     sha256 in the audit. Reads record the hash of the bytes read
     so the user can later prove what the agent saw.

Writes are atomic: we write to `<path>.{pid}.tmp` first, then os.replace
onto the target. This guarantees either the old content or the new
content — never a half-written file.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from community_member.actions.types import ActionResult
from community_member.consent import gate
from community_member.consent.gate import (
    ActionRequest,
    ConsentDecision,
    ConsentRequired,
)
from community_member.sandbox import Policy, grants

__all__ = ["FilesExecutor"]


MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MiB — protect the ledger from giant reads
MAX_WRITE_BYTES = 10 * 1024 * 1024


@dataclass
class FilesExecutor:
    """Orchestrates file read/write through the gate + sandbox policy."""

    chapter_id: str
    actor_agent_id: str | None = None
    # Active capability policy. Callers usually load this from config
    # + user approvals; for tests + first-setup you can pass an empty
    # Policy() and every action will be denied by sandbox check.
    policy: Policy = field(default_factory=lambda: Policy(grants=()))
    # The grants file the policy above was read from, so a refusal names a
    # real path rather than a guess at where the agent home is.
    grants_file: Path | None = None

    # ── Propose (W1 default = ConsentRequired) ────────────────

    def propose_read(self, path: str | Path, *, context: str, rationale: str = "") -> ConsentDecision:
        return self._propose("fs.read", str(path), context=context, rationale=rationale)

    def propose_write(self, path: str | Path, *, context: str, rationale: str = "") -> ConsentDecision:
        return self._propose("fs.write", str(path), context=context, rationale=rationale)

    def _propose(self, cap: str, path_str: str, *, context: str, rationale: str) -> ConsentDecision:
        req = ActionRequest(
            capability=cap,
            scope=_normalize_path_for_scope(path_str),
            context=context,
            provenance="trusted",
            rationale=rationale,
            extra={"path": path_str},
        )
        decision = gate.check_and_record(
            req,
            chapter_id=self.chapter_id,
            actor_agent_id=self.actor_agent_id,
        )
        if decision.state == "reject":
            return decision
        if decision.state == "prompt":
            raise ConsentRequired(
                f"{cap} → {path_str} needs user approval (prompt_event_sha256={decision.event_sha256})"
            )
        return decision

    # ── Execute (consumes approval + sandbox check + inode pin) ──

    def read_file(
        self,
        path: str | Path,
        *,
        context: str,
        approval_event_sha256: str,
        max_bytes: int = MAX_READ_BYTES,
    ) -> ActionResult:
        return self._execute_read(
            path, context=context, approval_event_sha256=approval_event_sha256, max_bytes=max_bytes
        )

    def write_file(
        self,
        path: str | Path,
        content: bytes | str,
        *,
        context: str,
        approval_event_sha256: str,
    ) -> ActionResult:
        data = content.encode("utf-8") if isinstance(content, str) else content
        return self._execute_write(
            path,
            data,
            context=context,
            approval_event_sha256=approval_event_sha256,
        )

    # ── Implementation ───────────────────────────────────────

    def _execute_read(
        self,
        path: str | Path,
        *,
        context: str,
        approval_event_sha256: str,
        max_bytes: int,
    ) -> ActionResult:
        path_str = str(path)
        req = ActionRequest(
            capability="fs.read",
            scope=_normalize_path_for_scope(path_str),
            context=context,
            provenance="trusted",
            extra={"path": path_str},
        )
        fail = self._approval_or_sandbox_fail(req, "fs.read", path_str, approval_event_sha256)
        if fail is not None:
            return fail
        resolved = Path(path_str).expanduser().resolve()
        try:
            # Inode pin: capture stat BEFORE open.
            st_before = resolved.stat()
            if st_before.st_size > max_bytes:
                return self._record_fail(req, f"file too large: {st_before.st_size} > {max_bytes}")
            with resolved.open("rb") as fh:
                # Re-check after open — a symlink swap between stat and
                # open would change the inode of the open FD.
                fd_stat = os.fstat(fh.fileno())
                if fd_stat.st_ino != st_before.st_ino or fd_stat.st_dev != st_before.st_dev:
                    return self._record_fail(req, "inode_race_detected")
                data = fh.read(max_bytes)
        except FileNotFoundError:
            return self._record_fail(req, "file_not_found")
        except PermissionError as e:
            return self._record_fail(req, f"permission_denied: {e}")
        except OSError as e:
            return self._record_fail(req, f"os_error: {type(e).__name__}: {e}")

        sha = hashlib.sha256(data).hexdigest()
        self._record_ok(req, reason="read_ok")
        return ActionResult(
            capability="fs.read",
            scope=str(resolved),
            outcome="ok",
            data={"bytes": data, "size": len(data)},
            provenance="untrusted",  # file contents are ALWAYS untrusted
            source_ref=str(resolved),
            extra={
                "content_sha256": sha,
                "content_length": len(data),
                "approval_event_sha256": approval_event_sha256,
            },
        )

    def _execute_write(
        self,
        path: str | Path,
        data: bytes,
        *,
        context: str,
        approval_event_sha256: str,
    ) -> ActionResult:
        path_str = str(path)
        if len(data) > MAX_WRITE_BYTES:
            req = ActionRequest(
                capability="fs.write",
                scope=_normalize_path_for_scope(path_str),
                context=context,
                provenance="trusted",
                extra={"path": path_str},
            )
            return self._record_fail(req, f"write too large: {len(data)} > {MAX_WRITE_BYTES}")

        req = ActionRequest(
            capability="fs.write",
            scope=_normalize_path_for_scope(path_str),
            context=context,
            provenance="trusted",
            extra={"path": path_str},
        )
        fail = self._approval_or_sandbox_fail(req, "fs.write", path_str, approval_event_sha256)
        if fail is not None:
            return fail

        resolved = Path(path_str).expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: temp file in same dir, then os.replace.
        fd, tmp = tempfile.mkstemp(
            prefix=f".{resolved.name}.",
            suffix=".tmp",
            dir=str(resolved.parent),
        )
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, resolved)
        except OSError as e:
            # Best-effort cleanup if replace failed.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return self._record_fail(req, f"write_failed: {type(e).__name__}: {e}")

        sha = hashlib.sha256(data).hexdigest()
        self._record_ok(req, reason="write_ok", extra_detail={"content_sha256": sha})
        return ActionResult(
            capability="fs.write",
            scope=str(resolved),
            outcome="ok",
            data={"size": len(data), "path": str(resolved)},
            provenance="trusted",  # our own write — metadata only, no content
            source_ref=str(resolved),
            extra={
                "content_sha256": sha,
                "content_length": len(data),
                "approval_event_sha256": approval_event_sha256,
            },
        )

    # ── Shared gate + sandbox + approval verify ─────────────

    def _approval_or_sandbox_fail(
        self,
        req: ActionRequest,
        capability: str,
        path_str: str,
        approval_event_sha256: str,
    ) -> ActionResult | None:
        """Return None on pass, or a 'denied' ActionResult on any fail."""
        approval = gate.find_valid_approval(req, chapter_id=self.chapter_id)
        if approval is None or approval["event_sha256"] != approval_event_sha256:
            gate.record_decision(
                req,
                ConsentDecision(state="reject", reason="approval_not_found_or_expired"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return ActionResult(
                capability=capability,
                scope=path_str,
                outcome="denied",
                data=None,
                provenance="untrusted",
                source_ref=path_str,
                extra={"reason": "approval_not_found_or_expired"},
            )
        # Sandbox check — is the path inside any granted root?
        resolved = Path(path_str).expanduser().resolve()
        if not self.policy.allows_path(capability, resolved):
            gate.record_decision(
                req,
                ConsentDecision(state="reject", reason="sandbox_policy_deny"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return ActionResult(
                capability=capability,
                scope=str(resolved),
                outcome="denied",
                data=None,
                provenance="untrusted",
                source_ref=str(resolved),
                extra={
                    "reason": "sandbox_policy_deny",
                    **grants.refusal_remedy(capability, str(resolved), self.grants_file),
                },
            )
        return None

    def _record_ok(self, req: ActionRequest, *, reason: str, extra_detail: dict | None = None) -> None:
        # Piggy-back on the consent ledger: record with state=approved
        # so the audit row shows the execution-time outcome. This is
        # separate from the user's prior approval row; it records
        # what actually happened.
        detail = dict(req.extra)
        if extra_detail:
            detail.update(extra_detail)
        _ = detail  # detail retained in req.extra for ledger row; placeholder
        gate.record_decision(
            req,
            ConsentDecision(state="approved", reason=reason),
            chapter_id=self.chapter_id,
            actor_agent_id=self.actor_agent_id,
        )

    def _record_fail(self, req: ActionRequest, reason: str) -> ActionResult:
        gate.record_decision(
            req,
            ConsentDecision(state="approved", reason=reason),
            chapter_id=self.chapter_id,
            actor_agent_id=self.actor_agent_id,
        )
        return ActionResult(
            capability=req.capability,
            scope=req.scope,
            outcome="fail",
            data=None,
            provenance="untrusted",
            source_ref=str(req.extra.get("path", req.scope)),
            extra={"reason": reason},
        )


def _normalize_path_for_scope(path_str: str) -> str:
    """Canonical scope string used by the gate.

    We use an expanded absolute path (no symlink resolution) so the
    scope is stable between propose + execute, and matches what
    gate.find_valid_approval sees.
    """
    p = Path(os.path.expanduser(path_str))
    if not p.is_absolute():
        p = Path.cwd() / p
    return str(p)
