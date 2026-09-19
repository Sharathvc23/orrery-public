"""Desktop / OS automation executor — click, type, read screen.

Fifth action surface and the riskiest of the bunch. A clicked
button or typed text is *executed* by the host OS — there is no
sandbox between the agent and the user's system once an event is
emitted. Defense lives entirely in the gate + sandbox policy + the
audit trail.

Threat model (worst-case if these defenses fail):

  * Skill emits ``desktop.click(2_500, 800)`` while the user happens
    to have a confirm-payment dialog open. The click sends money.
  * Skill emits ``desktop.type("rm -rf ~")`` while a terminal has
    focus. The shell runs the command.
  * Skill calls ``desktop.read_screen`` while the user is typing
    a password into a 1Password prompt. The captured frame leaks
    the secret.

Controls (all enforced here, none deferred):

  1. Consent gate — every propose/execute path runs through
     ``consent.gate``, like every other surface. ``untrusted``
     provenance proposals never reach prompt state.
  2. Sandbox policy — desktop grants are TARGETED. A grant is
     ``desktop.click:com.firefox,Code*`` — clicks are only allowed
     when the focused-window descriptor matches one of those
     patterns. The descriptor is read from the OS at execute time,
     never from the LLM proposal, so a hostile proposer can't
     spoof "the focused app is firefox" to bypass the check.
  3. Provenance pinning — ``desktop.read_screen`` always returns
     ``provenance="untrusted"``. Screen pixels (and any OCR text
     derived from them) are an external input, not user intent.
     The executor enforces this in the same way browser/file/shell
     surfaces do; a runner that returns ``trusted`` for one of
     these capabilities is rejected upstream.
  4. Capture hygiene — read_screen stores ``sha256(image_bytes)``
     by default, never the bytes themselves. Raw retention is
     ``raw_capture=True`` opt-in per executor instance. Hash-only
     mode lets the user later prove "this is what the agent saw"
     without leaving pixel-perfect screenshots on disk.
  5. Path safety on capture_dir — the directory is resolved once
     at construction; we never let a per-call argument supply an
     output path. Defends against a hostile proposal trying to
     write a screenshot through a path-traversal payload.

Platform drivers
----------------

The executor doesn't talk to the OS directly. It calls a
``DesktopDriver`` protocol with three methods (``click``, ``type_text``,
``read_screen``). Real drivers wrap xdotool (Linux), AppleScript +
``CGWindowList`` (macOS) and ``user32.dll`` (Windows). Tests inject a
fake driver so the unit suite never touches a real display server.
The fake driver is the canonical reference — every real driver must
present the same observable surface (return bytes for read_screen,
raise ``DesktopUnavailable`` if the OS surface is missing, etc.).

Real drivers stay deliberately thin: this module owns the
gate / sandbox / provenance discipline; drivers only translate calls
to OS APIs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from community_member.actions.types import ActionResult
from community_member.consent import gate
from community_member.consent.gate import (
    ActionRequest,
    ConsentDecision,
    ConsentRequired,
)
from community_member.sandbox import Policy

__all__ = [
    "DesktopDriver",
    "DesktopExecutor",
    "DesktopUnavailable",
    "FocusInfo",
]


MAX_TYPE_LEN = 4 * 1024  # 4 KiB of text per type call — defends ledger
MAX_CAPTURE_BYTES = 8 * 1024 * 1024  # 8 MiB raw frame cap


class DesktopUnavailable(RuntimeError):
    """Raised by drivers when no display / accessibility surface exists."""


@dataclass(frozen=True)
class FocusInfo:
    """Snapshot of what the OS reports as currently focused.

    The driver reads this AT EXECUTE TIME — the planner never gets to
    declare it. ``descriptor`` is the canonical string the sandbox
    policy matches against (window title or bundle id depending on
    platform). ``url`` is set by browser-aware drivers when the
    focused app is a browser; it lets the policy distinguish
    e.g. ``desktop.click:browser:gmail.com`` vs ``browser:bank.com``.
    """

    descriptor: str
    pid: int | None = None
    url: str | None = None


class DesktopDriver(Protocol):
    """Pluggable host-side OS adapter."""

    def focus(self) -> FocusInfo: ...

    def click(self, *, x: int, y: int, button: str = "left") -> None: ...

    def type_text(self, *, text: str) -> None: ...

    def read_screen(self) -> bytes: ...


@dataclass
class DesktopExecutor:
    """Orchestrates desktop actions through gate + policy + driver."""

    chapter_id: str
    actor_agent_id: str | None = None
    policy: Policy = field(default_factory=lambda: Policy(grants=()))
    driver: DesktopDriver | None = None
    capture_dir: Path | None = None
    raw_capture: bool = False

    def __post_init__(self) -> None:
        # Resolve the capture dir ONCE and store the resolved path. A
        # caller passing "~/captures/../etc" gets the resolved value
        # here; per-call arguments cannot redirect later writes.
        if self.capture_dir is not None:
            self.capture_dir = Path(self.capture_dir).expanduser().resolve()
            self.capture_dir.mkdir(parents=True, exist_ok=True)

    # ── Propose ───────────────────────────────────────────────

    def propose_click(
        self,
        target: str,
        *,
        x: int,
        y: int,
        context: str,
        rationale: str = "",
    ) -> ConsentDecision:
        return self._propose(
            "desktop.click",
            target,
            context=context,
            rationale=rationale,
            extra={"x": int(x), "y": int(y), "target": target},
        )

    def propose_type(
        self,
        target: str,
        text: str,
        *,
        context: str,
        rationale: str = "",
    ) -> ConsentDecision:
        if len(text) > MAX_TYPE_LEN:
            return ConsentDecision(
                state="reject",
                reason=f"text_too_long: {len(text)} > {MAX_TYPE_LEN}",
            )
        # We don't audit the literal text in the propose row — it may
        # be a password under coercion. Hash it instead and keep the
        # length so the user can recognise the request without the
        # plaintext sitting in the ledger.
        text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return self._propose(
            "desktop.type",
            target,
            context=context,
            rationale=rationale,
            extra={"text_sha256": text_sha, "text_len": len(text), "target": target},
        )

    def propose_read_screen(
        self,
        target: str,
        *,
        context: str,
        rationale: str = "",
    ) -> ConsentDecision:
        return self._propose(
            "desktop.read_screen",
            target,
            context=context,
            rationale=rationale,
            extra={"target": target},
        )

    def _propose(
        self,
        cap: str,
        target: str,
        *,
        context: str,
        rationale: str,
        extra: dict[str, object],
    ) -> ConsentDecision:
        req = ActionRequest(
            capability=cap,
            scope=target,
            context=context,
            provenance="trusted",
            rationale=rationale,
            extra=extra,
        )
        decision = gate.check_and_record(
            req,
            chapter_id=self.chapter_id,
            actor_agent_id=self.actor_agent_id,
        )
        if decision.state == "reject":
            return decision
        if decision.state == "prompt":
            raise ConsentRequired(f"{cap} → {target} needs user approval (prompt_event_sha256={decision.event_sha256})")
        return decision

    # ── Execute ───────────────────────────────────────────────

    def click(
        self,
        target: str,
        *,
        x: int,
        y: int,
        context: str,
        approval_event_sha256: str,
        button: str = "left",
    ) -> ActionResult:
        req = ActionRequest(
            capability="desktop.click",
            scope=target,
            context=context,
            provenance="trusted",
            extra={"x": int(x), "y": int(y), "target": target, "button": button},
        )
        fail = self._approval_or_policy_fail(req, "desktop.click", target, approval_event_sha256)
        if fail is not None:
            return fail
        focus = self._focus_or_fail(req, "desktop.click", target)
        if isinstance(focus, ActionResult):
            return focus
        if not self.policy.allows_target("desktop.click", focus.descriptor):
            return self._policy_deny(req, "desktop.click", focus.descriptor, "focus_not_allowlisted")
        try:
            assert self.driver is not None  # guaranteed by _focus_or_fail
            self.driver.click(x=int(x), y=int(y), button=button)
        except DesktopUnavailable as e:
            return self._record_fail(req, f"driver_unavailable: {e}")
        except Exception as e:
            return self._record_fail(req, f"driver_error: {type(e).__name__}: {e}")
        self._record_ok(req, reason="click_ok")
        return ActionResult(
            capability="desktop.click",
            scope=target,
            outcome="ok",
            data={"x": int(x), "y": int(y), "button": button},
            provenance="untrusted",
            source_ref=f"desktop:{focus.descriptor}",
            extra={
                "approval_event_sha256": approval_event_sha256,
                "focus_descriptor": focus.descriptor,
                "focus_url": focus.url,
            },
        )

    def type_text(
        self,
        target: str,
        text: str,
        *,
        context: str,
        approval_event_sha256: str,
    ) -> ActionResult:
        if len(text) > MAX_TYPE_LEN:
            req = ActionRequest(
                capability="desktop.type",
                scope=target,
                context=context,
                provenance="trusted",
                extra={"target": target, "text_len": len(text)},
            )
            return self._record_fail(req, f"text_too_long: {len(text)} > {MAX_TYPE_LEN}")
        text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        req = ActionRequest(
            capability="desktop.type",
            scope=target,
            context=context,
            provenance="trusted",
            extra={"target": target, "text_sha256": text_sha, "text_len": len(text)},
        )
        fail = self._approval_or_policy_fail(req, "desktop.type", target, approval_event_sha256)
        if fail is not None:
            return fail
        focus = self._focus_or_fail(req, "desktop.type", target)
        if isinstance(focus, ActionResult):
            return focus
        if not self.policy.allows_target("desktop.type", focus.descriptor):
            return self._policy_deny(req, "desktop.type", focus.descriptor, "focus_not_allowlisted")
        try:
            assert self.driver is not None
            self.driver.type_text(text=text)
        except DesktopUnavailable as e:
            return self._record_fail(req, f"driver_unavailable: {e}")
        except Exception as e:
            return self._record_fail(req, f"driver_error: {type(e).__name__}: {e}")
        self._record_ok(req, reason="type_ok")
        return ActionResult(
            capability="desktop.type",
            scope=target,
            outcome="ok",
            data={"text_len": len(text), "text_sha256": text_sha},
            provenance="untrusted",
            source_ref=f"desktop:{focus.descriptor}",
            extra={
                "approval_event_sha256": approval_event_sha256,
                "focus_descriptor": focus.descriptor,
                "focus_url": focus.url,
                "text_sha256": text_sha,
            },
        )

    def read_screen(
        self,
        target: str,
        *,
        context: str,
        approval_event_sha256: str,
    ) -> ActionResult:
        req = ActionRequest(
            capability="desktop.read_screen",
            scope=target,
            context=context,
            provenance="trusted",
            extra={"target": target},
        )
        fail = self._approval_or_policy_fail(req, "desktop.read_screen", target, approval_event_sha256)
        if fail is not None:
            return fail
        focus = self._focus_or_fail(req, "desktop.read_screen", target)
        if isinstance(focus, ActionResult):
            return focus
        if not self.policy.allows_target("desktop.read_screen", focus.descriptor):
            return self._policy_deny(req, "desktop.read_screen", focus.descriptor, "focus_not_allowlisted")
        try:
            assert self.driver is not None
            frame = self.driver.read_screen()
        except DesktopUnavailable as e:
            return self._record_fail(req, f"driver_unavailable: {e}")
        except Exception as e:
            return self._record_fail(req, f"driver_error: {type(e).__name__}: {e}")
        if not isinstance(frame, bytes | bytearray):
            return self._record_fail(req, "driver_returned_non_bytes")
        if len(frame) > MAX_CAPTURE_BYTES:
            return self._record_fail(req, f"capture_too_large: {len(frame)} > {MAX_CAPTURE_BYTES}")
        frame_bytes = bytes(frame)
        sha = hashlib.sha256(frame_bytes).hexdigest()
        capture_path: str | None = None
        if self.raw_capture and self.capture_dir is not None:
            # Filename is the hash → no per-call name from the LLM
            # ever reaches the filesystem.
            out = self.capture_dir / f"{sha}.bin"
            try:
                out.write_bytes(frame_bytes)
                capture_path = str(out)
            except OSError as e:
                # Best-effort: keep the hash in the audit even if
                # raw write failed.
                capture_path = f"write_error:{type(e).__name__}"
        self._record_ok(req, reason="read_screen_ok")
        return ActionResult(
            capability="desktop.read_screen",
            scope=target,
            outcome="ok",
            data={
                "sha256": sha,
                "size": len(frame_bytes),
                "raw_capture": self.raw_capture,
            },
            # Screen content is ALWAYS untrusted — see _ALWAYS_UNTRUSTED_OUTPUTS.
            provenance="untrusted",
            source_ref=f"desktop:{focus.descriptor}",
            extra={
                "approval_event_sha256": approval_event_sha256,
                "focus_descriptor": focus.descriptor,
                "focus_url": focus.url,
                "capture_path": capture_path,
                "sha256": sha,
            },
        )

    # ── Shared helpers ────────────────────────────────────────

    def _approval_or_policy_fail(
        self,
        req: ActionRequest,
        capability: str,
        target: str,
        approval_event_sha256: str,
    ) -> ActionResult | None:
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
                scope=target,
                outcome="denied",
                data=None,
                provenance="untrusted",
                source_ref=f"desktop:{target}",
                extra={"reason": "approval_not_found_or_expired"},
            )
        return None

    def _focus_or_fail(self, req: ActionRequest, capability: str, target: str) -> FocusInfo | ActionResult:
        if self.driver is None:
            return self._record_fail(req, "no_driver_configured")
        try:
            focus = self.driver.focus()
        except DesktopUnavailable as e:
            return self._record_fail(req, f"driver_unavailable: {e}")
        except Exception as e:
            return self._record_fail(req, f"focus_error: {type(e).__name__}: {e}")
        if not isinstance(focus, FocusInfo) or not focus.descriptor:
            return self._record_fail(req, "focus_unknown")
        return focus

    def _policy_deny(self, req: ActionRequest, capability: str, descriptor: str, reason: str) -> ActionResult:
        gate.record_decision(
            req,
            ConsentDecision(state="reject", reason=reason),
            chapter_id=self.chapter_id,
            actor_agent_id=self.actor_agent_id,
        )
        return ActionResult(
            capability=capability,
            scope=req.scope,
            outcome="denied",
            data=None,
            provenance="untrusted",
            source_ref=f"desktop:{descriptor}",
            extra={"reason": reason, "focus_descriptor": descriptor},
        )

    def _record_ok(self, req: ActionRequest, *, reason: str) -> None:
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
            source_ref=f"desktop:{req.scope}",
            extra={"reason": reason},
        )
