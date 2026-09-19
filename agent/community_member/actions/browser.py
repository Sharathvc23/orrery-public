"""Browser action executor — the first of four v2 action surfaces.

Every browser action flows through `BrowserExecutor.<method>()`:

  propose(url)  → builds an ActionRequest, runs it through the gate,
                  raises ConsentRequired (W1 default) so the tray UI
                  can prompt the user. Never touches Playwright.

  navigate(url, approval_event_sha256=...)
                → consumes a valid recent approval (verified via
                  `gate.find_valid_approval`), then performs the actual
                  navigation via Playwright (`page_goto`). A missing,
                  mismatched, or expired approval fails closed with a
                  denied ActionResult — no navigation occurs.

Why split propose/navigate? The agent's think() loop proposes; the
desktop tray UI approves; the executor then runs with a proof of
approval. Splitting the methods makes each call site explicit about
which half of the dance it's in, and lets us unit-test the security-
critical glue without Playwright running.

All extracted web content is tagged `provenance="untrusted"` in the
returned `ActionResult` — downstream planners can never launder it
into `trusted`. This is the indirect-prompt-injection defense from
plans/yes-the-whole-point-humble-hopcroft.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from community_member.actions.browser_page import (
    PageGotoFn,
    PageGotoResult,
    default_page_goto,
)
from community_member.actions.types import ActionResult
from community_member.consent import gate
from community_member.consent.gate import (
    ActionRequest,
    ConsentDecision,
    ConsentRequired,
)
from community_member.sandbox import Policy, grants

DEFAULT_NAV_TIMEOUT_MS = 30_000


def _default_state_root() -> Path:
    """Browser profiles under the configured agent home, read at call time so
    a test or a second agent that sets COMMUNITY_MEMBER_HOME is honoured."""
    from community_member import config as _config

    return _config.CONFIG_DIR / "browser-state"


@dataclass
class BrowserExecutor:
    """Orchestration layer for browser actions.

    Holds the security-critical glue (consent gate + approval
    verification). Actual navigation is delegated to `page_goto`,
    which defaults to `default_page_goto` (lazy-imports Playwright)
    but can be overridden for tests or alternative browser drivers.
    """

    chapter_id: str
    actor_agent_id: str | None = None
    # Per-chapter persistent browser state lives under this root.
    # Each chapter gets its own subdir so cookies/localStorage are
    # isolated across chapters the user belongs to. Derived from CONFIG_DIR
    # rather than Path.home() so it follows COMMUNITY_MEMBER_HOME; the two
    # resolve to the same path on a default install, and to different ones
    # when a second agent or a test sets its own home.
    browser_state_root: Path = field(default_factory=lambda: _default_state_root())
    # Callable that actually drives the browser. Defaults to a lazy
    # Playwright binding; tests inject a fake.
    page_goto: PageGotoFn = field(default=default_page_goto)
    nav_timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS
    # Which origins this install may reach at all, as browser.navigate grants.
    # Empty denies every navigation, matching the file, shell, network and
    # desktop executors. The consent gate is the other bound and neither
    # replaces the other: consent authorises one action, the policy says which
    # origins are reachable in the first place.
    policy: Policy = field(default_factory=lambda: Policy(grants=()))
    # Where an operator writes those grants, quoted in the refusal so it names
    # a file that exists. None when the caller did not say.
    grants_file: Path | None = None

    # ── Propose (never executes; always raises ConsentRequired in W1) ──

    def propose_navigate(
        self,
        url: str,
        *,
        context: str,
        provenance: gate.Provenance = "trusted",
        source_ref: str | None = None,
        rationale: str = "",
    ) -> ConsentDecision:
        """Propose navigating to `url`. Raises ConsentRequired on prompt,
        returns a decision on reject. Never returns on "approved" in W1 —
        that branch is unreachable until graduation lands.
        """
        req = self._build_request(
            capability="browser.navigate",
            scope=_origin_of(url),
            context=context,
            provenance=provenance,
            source_ref=source_ref,
            rationale=rationale,
            extra={"url": url},
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
                f"browser.navigate → {_origin_of(url)} needs user approval "
                f"(prompt_event_sha256={decision.event_sha256})"
            )
        # state == "approved" is currently unreachable (W1). The guard
        # preserves forward-compat for when W4 graduation flips this on.
        return decision

    # ── Execute (consumes a recent approval) ──────────────────────

    def navigate(
        self,
        url: str,
        *,
        context: str,
        approval_event_sha256: str,
        source_ref: str | None = None,
    ) -> ActionResult:
        """Execute a navigation, given a valid recent user approval.

        Re-derives the ActionRequest from arguments this method controls,
        then looks the approval up via `gate.find_valid_approval()`. A
        mismatch (different origin, different context, different
        provenance, expired, missing) fails closed — no navigation occurs
        and a denied row is recorded.

        `provenance` is pinned to "trusted" here rather than taken from
        the caller, matching every other action executor
        (files/shell/net/desktop). The approval match-key includes
        provenance, so an approval minted for a semi-trusted proposal does
        not match and the navigation is refused. Accepting the caller's
        value would make the planner's own label the thing that decides
        whether its proposal executes.
        """
        req = self._build_request(
            capability="browser.navigate",
            scope=_origin_of(url),
            context=context,
            provenance="trusted",
            source_ref=source_ref,
            rationale="",
            extra={"url": url},
        )
        approval = gate.find_valid_approval(req, chapter_id=self.chapter_id)
        if approval is None or approval["event_sha256"] != approval_event_sha256:
            # Record the rejection + fail closed. Do NOT prompt again —
            # a caller that asks with a stale approval is either
            # confused or compromised; either way, quiet failure plus
            # an audit row is the right response.
            gate.record_decision(
                req,
                ConsentDecision(state="reject", reason="approval_not_found_or_expired"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return ActionResult(
                capability="browser.navigate",
                scope=_origin_of(url),
                outcome="denied",
                data=None,
                provenance="untrusted",
                source_ref=url,
                extra={"reason": "approval_not_found_or_expired"},
            )

        # Sandbox policy — the second bound. Consent authorises THIS action;
        # the policy says which origins this install may reach at all, and both
        # are required. Checked before the driver is touched, so an ungranted
        # origin is never contacted and no cookie from the persistent profile
        # leaves the machine.
        origin = _origin_of(url)
        if not self.policy.allows_origin("browser.navigate", origin):
            remedy = grants.refusal_remedy("browser.navigate", origin, self.grants_file)
            gate.record_decision(
                req,
                ConsentDecision(state="reject", reason="sandbox_policy_deny"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return ActionResult(
                capability="browser.navigate",
                scope=origin,
                outcome="denied",
                data=None,
                provenance="untrusted",
                source_ref=url,
                # The refusal carries its own fix. A denial that does not say
                # what would have allowed it is how a deny-by-default policy
                # gets reverted by the next person to hit it.
                extra={"reason": "sandbox_policy_deny", **remedy},
            )

        # Approval and policy both cleared. Drive the browser. Failure is
        # captured as a "fail" ActionResult rather than raising — the caller
        # (think loop / tray UI) treats it as any other errored action.
        state_dir = self.browser_state_root / self.chapter_id
        try:
            result: PageGotoResult = self.page_goto(state_dir, url, self.nav_timeout_ms)
        except Exception as e:
            gate.record_decision(
                req,
                ConsentDecision(state="approved", reason=f"navigation_failed: {type(e).__name__}"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return ActionResult(
                capability="browser.navigate",
                scope=_origin_of(url),
                outcome="fail",
                data=None,
                provenance="untrusted",
                source_ref=url,
                extra={"reason": f"{type(e).__name__}: {e}"},
            )

        # Record the successful navigation. The content_sha256 goes
        # into the audit so the user can later prove "the agent saw
        # exactly this page" without us storing the full HTML.
        ok = 200 <= result.status < 400
        gate.record_decision(
            req,
            ConsentDecision(state="approved", reason="navigation_ok" if ok else "navigation_http_error"),
            chapter_id=self.chapter_id,
            actor_agent_id=self.actor_agent_id,
        )
        return ActionResult(
            capability="browser.navigate",
            scope=_origin_of(result.final_url),
            outcome="ok" if ok else "fail",
            data={
                "final_url": result.final_url,
                "title": result.title,
                "status": result.status,
            },
            provenance="untrusted",
            source_ref=result.final_url,
            extra={
                "content_sha256": result.html_sha256,
                "content_length": result.content_length,
                "requested_url": url,
                "approval_event_sha256": approval_event_sha256,
            },
        )

    # ── Helpers ───────────────────────────────────────────────────

    def _build_request(
        self,
        *,
        capability: str,
        scope: str,
        context: str,
        provenance: gate.Provenance,
        source_ref: str | None,
        rationale: str,
        extra: dict[str, object],
    ) -> ActionRequest:
        return ActionRequest(
            capability=capability,
            scope=scope,
            context=context,
            provenance=provenance,
            source_ref=source_ref,
            rationale=rationale,
            extra=extra,
        )


def _origin_of(url: str) -> str:
    """Extract `scheme://netloc` from a URL, lowercased, no path.

    The gate uses this as the `scope` — so `https://DOCS.example.com/a`
    and `https://docs.example.com/b` share an approval. Path-based
    scoping is deliberately NOT done: a malicious redirect inside the
    approved origin cannot escape the scope, and the allowlist stays
    manageable.
    """
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        # Intentionally strict — an unparseable URL is a bug at the
        # planner layer, not something to paper over with a default.
        raise ValueError(f"invalid URL: {url!r}")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
