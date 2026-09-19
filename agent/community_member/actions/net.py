"""Net.http action executor — egress allowlist + content-sha audit.

Fourth W2 action surface. Drives HTTP GET through the consent gate +
sandbox policy. S6 in the v2 threat model: \"Skill attempting HTTP to
non-allowlisted domain fails at sandbox, not at DNS.\"

We check the hostname against the policy BEFORE any resolution or
network call. Failed check → denied + audit row, no DNS lookup, no
connection. This closes the \"what if they smuggle a request via DNS
prefetch or ambient OS resolver\" class of leaks.

Scope: GET-only for W1/W2. POST / method-specific grants can land as
an extension later if/when a use case surfaces. Keeping the surface
small reduces attack surface.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from community_member.actions.types import ActionResult
from community_member.consent import gate
from community_member.consent.gate import (
    ActionRequest,
    ConsentDecision,
    ConsentRequired,
)
from community_member.sandbox import Policy, grants

__all__ = ["NetExecutor"]


DEFAULT_TIMEOUT_SEC = 15
MAX_RESPONSE_BYTES = 256 * 1024  # 256 KiB — audit-friendly cap


@dataclass
class NetExecutor:
    chapter_id: str
    actor_agent_id: str | None = None
    policy: Policy = field(default_factory=lambda: Policy(grants=()))
    # The grants file the policy above was read from, so a refusal names a
    # real path rather than a guess at where the agent home is.
    grants_file: Path | None = None
    timeout_sec: int = DEFAULT_TIMEOUT_SEC

    def propose_get(
        self,
        url: str,
        *,
        context: str,
        rationale: str = "",
    ) -> ConsentDecision:
        host = _hostname_of(url)
        req = ActionRequest(
            capability="net.http",
            scope=host,
            context=context,
            provenance="trusted",
            rationale=rationale,
            extra={"url": url, "method": "GET"},
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
                f"net.http GET → {host} needs user approval (prompt_event_sha256={decision.event_sha256})"
            )
        return decision

    def http_get(
        self,
        url: str,
        *,
        context: str,
        approval_event_sha256: str,
        fetcher=None,  # injection seam for tests
    ) -> ActionResult:
        host = _hostname_of(url)
        req = ActionRequest(
            capability="net.http",
            scope=host,
            context=context,
            provenance="trusted",
            extra={"url": url, "method": "GET"},
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
            return _deny(host, "approval_not_found_or_expired", url=url)

        # Sandbox policy — THE S6 check. Happens BEFORE any resolution,
        # so a non-allowlisted hostname cannot leak via DNS prefetch,
        # connection establishment, or any ambient OS side-channel.
        if not self.policy.allows_host("net.http", host):
            gate.record_decision(
                req,
                ConsentDecision(state="reject", reason="sandbox_policy_deny"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return _deny(
                host, "sandbox_policy_deny", url=url, extra=grants.refusal_remedy("net.http", host, self.grants_file)
            )

        # Perform the GET. Default fetcher uses httpx; tests inject.
        fetcher = fetcher or _default_fetcher
        try:
            fetched = fetcher(url, self.timeout_sec)
            # A fetcher may return (status, body) — the shape tests inject —
            # or (status, body, location) from the default one.
            status, body = fetched[0], fetched[1]
            location = fetched[2] if len(fetched) > 2 else None
        except Exception as e:
            gate.record_decision(
                req,
                ConsentDecision(state="approved", reason=f"http_failed: {type(e).__name__}"),
                chapter_id=self.chapter_id,
                actor_agent_id=self.actor_agent_id,
            )
            return _fail(host, f"http_failed: {type(e).__name__}: {e}", url=url)

        body = body[:MAX_RESPONSE_BYTES]
        sha = hashlib.sha256(body).hexdigest()
        # A redirect is NOT a success: the allowlisted host declined to answer
        # and named another one. It is reported, not followed — the approval
        # and the sandbox grant were for `host`, and nothing here may GET a
        # host they did not name. The planner may propose the new URL.
        redirected = 300 <= status < 400
        gate.record_decision(
            req,
            ConsentDecision(
                state="approved",
                reason="http_ok" if 200 <= status < 300 else f"http_{status}",
            ),
            chapter_id=self.chapter_id,
            actor_agent_id=self.actor_agent_id,
        )
        data: dict = {"status": status, "body_len": len(body), "url": url}
        if redirected:
            data["redirect_not_followed"] = True
            data["location"] = location
        return ActionResult(
            capability="net.http",
            scope=host,
            outcome="ok" if 200 <= status < 300 else "fail",
            data=data,
            provenance="untrusted",
            source_ref=url,
            extra={
                "content_sha256": sha,
                "body_bytes": body,
                "approval_event_sha256": approval_event_sha256,
            },
        )


def _hostname_of(url: str) -> str:
    parsed = urlparse(url.strip())
    if not parsed.hostname:
        raise ValueError(f"invalid URL (no hostname): {url!r}")
    return parsed.hostname.lower()


def _default_fetcher(url: str, timeout_sec: int) -> tuple[int, bytes, str | None]:
    """Real HTTP GET via httpx. Tests inject a fake.

    REDIRECTS ARE NOT FOLLOWED. The sandbox host check runs once, on the URL
    the planner proposed and the user approved; with ``follow_redirects=True``
    the allowlisted host could answer 302 and this fetcher would GET any host
    it named — measured: a grant for ``localhost`` fetched a body from
    ``127.0.0.1`` through one redirect. A 3xx is returned as the result, with
    its ``Location`` as the third element, so the planner can propose the new
    URL and that proposal goes through consent and the policy like any other.
    """
    import httpx

    resp = httpx.get(url, timeout=timeout_sec, follow_redirects=False)
    return resp.status_code, resp.content, resp.headers.get("location")


def _deny(host: str, reason: str, *, url: str, extra: dict | None = None) -> ActionResult:
    return ActionResult(
        capability="net.http",
        scope=host,
        outcome="denied",
        data=None,
        provenance="untrusted",
        source_ref=url,
        extra={"reason": reason, **(extra or {})},
    )


def _fail(host: str, reason: str, *, url: str) -> ActionResult:
    return ActionResult(
        capability="net.http",
        scope=host,
        outcome="fail",
        data=None,
        provenance="untrusted",
        source_ref=url,
        extra={"reason": reason},
    )
