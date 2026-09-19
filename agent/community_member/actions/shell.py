"""Shell action executor — binary-allowlist subprocess with shell=False.

Third W2 action surface. Runs subprocess commands after checking
the sandbox policy binary allowlist. Explicit non-goals:

  * No shell metacharacter support. We use `subprocess.run(args, shell=False)`
    so `tail;rm -rf ~` stays literal argv — no shell interprets `;`.
  * No arg-based allowlisting. Grants are binary names only
    (shell.exec:tail,grep). Enforcing argument shapes in a grant is
    brittle and easy to bypass.

Every exec returns an ActionResult with:
  - data: {"stdout_sha256", "stderr_sha256", "exit_code", "duration_ms"}
  - provenance: "untrusted" (stdout/stderr bytes from the child process
    are data, not instructions — future planners MUST put them in
    UntrustedContext)
  - extra.stdout_bytes / stderr_bytes (capped) so the caller can
    surface small outputs; full bytes hashed only.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from community_member.actions.types import ActionResult
from community_member.consent import gate
from community_member.consent.gate import (
    ActionRequest,
    ConsentDecision,
    ConsentRequired,
)
from community_member.sandbox import Policy, grants, unpermitted_path_arguments

__all__ = ["ShellExecutor"]


DEFAULT_TIMEOUT_SEC = 30
MAX_CAPTURE_BYTES = 64 * 1024  # 64 KiB per stream — keeps audit rows reasonable


@dataclass
class ShellExecutor:
    chapter_id: str
    actor_agent_id: str | None = None
    policy: Policy = field(default_factory=lambda: Policy(grants=()))
    # The grants file the policy above was read from, so a refusal names a
    # real path rather than a guess at where the agent home is.
    grants_file: Path | None = None
    timeout_sec: int = DEFAULT_TIMEOUT_SEC
    # Working directory for the child. Pinned rather than inherited: a relative
    # argument means nothing without one, and the agent's own cwd is wherever
    # the operator happened to start it.
    workdir: Path | None = None
    # Environment variables passed through to the child. Everything else is
    # dropped: the agent's own environment holds its provider API key, and a
    # granted binary that prints or forwards its environment would carry that
    # key out. No grant mentions it and no binary allowlist bounds it.
    env_passthrough: tuple[str, ...] = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "TERM")

    def propose_exec(
        self,
        binary: str,
        args: Sequence[str] = (),
        *,
        context: str,
        rationale: str = "",
    ) -> ConsentDecision:
        req = ActionRequest(
            capability="shell.exec",
            scope=binary,  # binary name is the scope
            context=context,
            provenance="trusted",
            rationale=rationale,
            extra={"argv": [binary, *args]},
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
                f"shell.exec → {binary} needs user approval (prompt_event_sha256={decision.event_sha256})"
            )
        return decision

    def _workdir(self) -> Path:
        """Where the child runs. Pinned so a relative argument has one meaning,
        and so a command cannot act on whatever directory the operator happened
        to start the agent in."""
        from community_member import config as _config

        target = self.workdir or (_config.CONFIG_DIR / "shell-workdir")
        target.mkdir(parents=True, exist_ok=True)
        return target

    def _child_env(self) -> dict[str, str]:
        """The child's environment: the passthrough names and nothing else.

        The agent's own environment holds its provider API key. Inheriting it
        means any granted binary that prints or forwards its environment
        carries that key out, which no grant mentions and the binary allowlist
        does not bound.
        """
        return {name: os.environ[name] for name in self.env_passthrough if name in os.environ}

    def exec_command(
        self,
        binary: str,
        args: Sequence[str] = (),
        *,
        context: str,
        approval_event_sha256: str,
        stdin_data: bytes | None = None,
    ) -> ActionResult:
        req = ActionRequest(
            capability="shell.exec",
            scope=binary,
            context=context,
            provenance="trusted",
            extra={"argv": [binary, *args]},
        )
        # Approval match
        approval = gate.find_valid_approval(req, chapter_id=self.chapter_id)
        if approval is None or approval["event_sha256"] != approval_event_sha256:
            gate.record_decision(
                req,
                ConsentDecision(state="reject", reason="approval_not_found_or_expired"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return _deny(binary, "approval_not_found_or_expired")

        # Sandbox policy: is this binary allowlisted?
        if not self.policy.allows_binary("shell.exec", binary):
            gate.record_decision(
                req,
                ConsentDecision(state="reject", reason="sandbox_policy_deny"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return _deny(binary, "sandbox_policy_deny", grants.refusal_remedy("shell.exec", binary, self.grants_file))

        # Resolve to absolute path via which — fail if not on PATH.
        resolved = shutil.which(binary)
        if resolved is None:
            gate.record_decision(
                req,
                ConsentDecision(state="approved", reason="binary_not_on_path"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return _fail(binary, "binary_not_on_path")

        # Narrowing (NOT a bound): refuse an argument naming an existing file the
        # file grants do not cover. This closes the accidental over-reach —
        # a granted binary pointed at a path outside fs.* — and does not reach a
        # path inside a program string, a host, or a file yet to be created. See
        # sandbox.policy.unpermitted_path_arguments for what escapes and why.
        workdir = self._workdir()
        outside = unpermitted_path_arguments(self.policy, args, cwd=workdir)
        if outside:
            gate.record_decision(
                req,
                ConsentDecision(state="reject", reason="argument_outside_file_grants"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return _deny(
                binary,
                "argument_outside_file_grants",
                extra={
                    "arguments": outside,
                    "remedy": f"grant fs.read for {outside[0]} or drop it from the command",
                },
            )

        # Run with shell=False; full argv is literal.
        start = time.monotonic()
        try:
            proc = subprocess.run(
                [resolved, *args],
                input=stdin_data,
                capture_output=True,
                timeout=self.timeout_sec,
                check=False,
                cwd=str(workdir),
                env=self._child_env(),
            )
        except subprocess.TimeoutExpired:
            gate.record_decision(
                req,
                ConsentDecision(state="approved", reason="timeout"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return _fail(binary, f"timeout after {self.timeout_sec}s")
        except FileNotFoundError:
            return _fail(binary, "exec_file_not_found")
        except OSError as e:
            return _fail(binary, f"os_error: {type(e).__name__}: {e}")
        duration_ms = int((time.monotonic() - start) * 1000)

        stdout = proc.stdout or b""
        stderr = proc.stderr or b""
        stdout_sha = hashlib.sha256(stdout).hexdigest()
        stderr_sha = hashlib.sha256(stderr).hexdigest()

        gate.record_decision(
            req,
            ConsentDecision(
                state="approved",
                reason="exec_ok" if proc.returncode == 0 else f"exit_{proc.returncode}",
            ),
            chapter_id=self.chapter_id,
            actor_agent_id=self.actor_agent_id,
        )
        return ActionResult(
            capability="shell.exec",
            scope=binary,
            outcome="ok" if proc.returncode == 0 else "fail",
            data={
                "exit_code": proc.returncode,
                "duration_ms": duration_ms,
                "stdout_len": len(stdout),
                "stderr_len": len(stderr),
            },
            provenance="untrusted",
            source_ref=f"shell:{binary}",
            extra={
                "stdout_sha256": stdout_sha,
                "stderr_sha256": stderr_sha,
                "stdout_bytes": stdout[:MAX_CAPTURE_BYTES],
                "stderr_bytes": stderr[:MAX_CAPTURE_BYTES],
                "approval_event_sha256": approval_event_sha256,
                "resolved_path": resolved,
            },
        )


def _deny(binary: str, reason: str, extra: dict | None = None) -> ActionResult:
    return ActionResult(
        capability="shell.exec",
        scope=binary,
        outcome="denied",
        data=None,
        provenance="untrusted",
        source_ref=f"shell:{binary}",
        extra={"reason": reason, **(extra or {})},
    )


def _fail(binary: str, reason: str) -> ActionResult:
    return ActionResult(
        capability="shell.exec",
        scope=binary,
        outcome="fail",
        data=None,
        provenance="untrusted",
        source_ref=f"shell:{binary}",
        extra={"reason": reason},
    )
