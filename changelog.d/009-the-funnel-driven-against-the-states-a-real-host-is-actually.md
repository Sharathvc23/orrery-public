### The funnel, driven against the states a real host is actually in

The funnel words eight refusal states carefully, and every one of them was tested
against a hand-written node server whose bodies were copied from a reading of
`smb_host`'s source. That proves the app's own wiring and cannot prove the copy
is right. The gap was not hypothetical: the stand-in's 503 is the
`SMB_HOST_PROVISION_TOKEN`-not-set variant, while the state a host with no
`SMB_HOST_TENANT_CAP` returns is a different refusal with a different sentence,
and no test had ever rendered it — the branch every visitor to such a host lands
in.

`smb_funnel/tests/host-states.test.mjs` boots a REAL `smb_host` per case,
configured only through its environment, drives the REAL app against it, and
asserts what the page RENDERED rather than the status the fetch received. Six
states: 503 with the cap unconfigured, 401 with no token, 401 with the wrong
token, 507 at capacity, 429 rate-limited, and a 201 success. The 503 panel is
pinned as never advising a retry, by name — nothing the visitor does or waits for
changes a setting an operator has not made — and the six are asserted to render
six distinguishable pages, with exactly one of them (the rate limit) telling the
visitor that waiting helps.

**`smb_host` has no rate limiter**, so 429 is not one of its states at all; the
per-source limit belongs to `smb_signup`, the front door that holds the
credential on a static page's behalf. That case therefore boots a real
`smb_signup` in front of a real `smb_host`, which is the deployment shape a
public visitor would meet.

**And the browser path is now asserted rather than inferred.** Node's `fetch`
performs no preflight and enforces no cross-origin rule, so every suite that
drove the funnel "against a real host" was driving it against a host with CORS
switched off — which is how the gated host stayed unreachable from a browser for
a whole release with every test green. `tests/corsfetch.mjs` applies the rule at
the moment a browser applies it, before the request is sent, and
`tests/browser-cors.test.mjs` asserts that a cross-origin page completes a real
credentialed provision, and that when a preflight refuses, the page renders a
network failure and NOT a verdict about a credential whose request was never
sent. Proven by planting the original regression: with `Authorization` dropped
from the preflight allowlist the browser suite reddens while the six-state suite
stays entirely green, which is that outage's signature in one line.

The funnel's CI job installs the host it now drives, and the suites REFUSE rather
than skip when it is absent: a suite whose claim is "this had never been driven
against the real thing" must not report green where the real thing was missing.
