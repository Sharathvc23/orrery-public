### Security — `browser.navigate` pins provenance at the executor

`gate.find_valid_approval` matches an approval on capability, scope, context
and provenance. The file, shell, network and desktop executors each rebuild
their `ActionRequest` with `provenance="trusted"`, so an approval minted for a
proposal labelled semi-trusted does not match and the action is refused.
`BrowserExecutor.navigate` took provenance from its caller and passed the
planner's label straight through, so it was the one capability where a
non-trusted-provenance proposal could satisfy its own approval and reach a
driver — a persistent Chromium profile holding the agent's cookies.

`navigate` no longer accepts a `provenance` argument and pins `"trusted"` like
its four siblings.

`agent/tests/test_runner_provenance.py` derives the runner set from
`LocalAgent.build_runners` and fails if any runner forwards a caller-supplied
provenance, if any execute path in `community_member/actions/` builds an
`ActionRequest` whose provenance is not a literal, or if `navigate` regains the
argument. It also drives the wired runner with a semi-trusted proposal and
asserts the driver is not reached.

`BrowserExecutor.origin_allowlist` was declared and never read; it is removed.
What bounds a navigation is the consent gate: `scope` is the URL's origin and
approvals match on it, so an approval for one origin does not authorise
another. `build_runners` gives the browser executor no `sandbox.Policy` — the
other four surfaces receive an empty policy, which denies every path, host and
binary until the operator grants one, and there is no equivalent grant syntax
for origins.
