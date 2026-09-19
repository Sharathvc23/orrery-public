### The front door is driven in a browser now, because nothing else could see it

The CORS defect this repository shipped — `Authorization` missing from `smb_host`'s
allowlist, so a gated host was unreachable from a browser **with a valid token
exactly as much as without one** — was invisible to every suite in this
repository. `smb_funnel/tests/wiring.test.mjs` boots the real `app.js`, but a
constructed document performs no preflight. `smoke.mjs` never touches the
network. `scripts/demo_smb_stack.sh` drives the host with curl and node, where
there is no `Origin` and so no preflight to fail. `smb_host`'s own preflight test
asked only for `content-type`. Five green suites, and the front door was shut; it
took a person opening a browser to find it.

`scripts/browser_smb_funnel.py` closes that class. It boots the real host gated on
a provisioning token, serves the funnel on a **separate origin** — same-origin
would remove the preflight, which is the thing being tested — and drives the page
itself: fill the fields, click through, read the endpoint, `did:key` and recovery
phrase it rendered, click *Try it*, and assert the badge the page painted. Three
cases: a credentialed happy path (including that the token is gone from the
address bar, lives in `sessionStorage`, and appears nowhere in the document), a
browser with no credential (the credential-required panel, not a generic
failure), and a host serving one key on its card while signing with another (the
mismatch badge, through a real fetch).

**Proven by planting the defect it exists for.** With `Authorization` removed from
the host's allowlist, cases A and C go red and the browser's own diagnosis is
printed — *"blocked by CORS policy: Response to preflight request doesn't pass
access control check"*. Case B stays green, correctly: without a token there is no
`Authorization` header, so no preflight to refuse. Reverted, all three pass.

It runs as the `smb_browser` job, listed in `ci gate`'s dependencies so a red
front door cannot leave the gate green. Cost, measured: the browser is the
headless **shell** only — 267 MB and ~14 s cold, against 622 MB and ~25 s for full
chromium — cached across runs by pinned Playwright version, and the drive itself
is ~10 s.
