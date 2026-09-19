### Fixed — a refused action is reported as refused, not as a failure

The runner boundary in `LocalAgent.build_runners` re-derived a `ToolOutput`'s
outcome as `"ok" if result.outcome == "ok" else "fail"`. Seven refusal sites
across `community_member/actions/` produce `denied` — a missing or expired
approval, a sandbox policy that does not grant the path, host or binary — and
all seven arrived at the caller as `fail`, the same word an action that ran and
errored produces. The sibling path `_denied_output` already returned `denied`
for the same refusal, so which word reached the caller depended on which layer
refused.

The outcome is now passed through. `POST /api/local/consent/approve` reports
`"outcome": "denied"` where it previously reported `"fail"`; no code branches on
the value, so nothing else changes.

This is the same defect as several others fixed in this release: a reader that
cannot distinguish a refusal from a failure or an absence. The surface probes
parsed a 401 body as an empty result set, and the executor's denial-suppression
window and the endpoint that displays it read the same rows through different
limits.

`agent/tests/test_outcome_passthrough.py` reads the producible outcomes out of
`community_member/actions/` and asserts each survives the boundary, so an
outcome added there later is covered without editing the test. It also asserts
`ToolOutcome` declares every outcome those modules produce.
