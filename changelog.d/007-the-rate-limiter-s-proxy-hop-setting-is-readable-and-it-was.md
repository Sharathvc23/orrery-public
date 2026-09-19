### The rate limiter's proxy-hop setting is readable, and it was off everywhere

`server/chapter_agent.py` has had `TRUSTED_PROXY_HOPS` and
`client_ip_for_rate_limit` for as long as the per-IP rate limiter has existed,
and the startup comment states what they are for in its own words: *"so one
attacker can't 429 everyone by sharing the proxy's IP bucket"*. Behind an edge
proxy with the setting at `0`, the limiter keys on the proxy's address, so every
caller is in one bucket and any one of them can 429 all the others.

**It was unset on every live deployment, for the whole life of the setting.**
Measured: the limiter was keying on the platform edge address — `100.64.0.2/.3/.4`,
RFC 6598 CGNAT — which *rotates per request*, so the bucket identity was not
merely shared, it was noise. The control was written, documented, deployed and
never switched on.

**Nobody noticed because nothing reported it.** `smb_host` puts its own hop count
on `GET /health`; the org server exposed nothing, so the only way to check was to
read the hosting platform's variables, per deployment, by hand. That asymmetry is
what this change closes: `GET /health` now carries `trusted_proxy_hops`.

**It reports the value the limiter is using — not a fresh read of the
environment, and the distinction is the entire point.** `TRUSTED_PROXY_HOPS` is
resolved once at import. A field that re-read `os.environ` in the handler would
print the number an operator had just set while the limiter went on keying with
the number it was imported with: a surface that agrees with the person reading it
exactly when they most need to be contradicted. On a sibling service the
platform's variable listing read back the new value while the process used the
old one through eighteen consecutive polls. The field is the same module object
`client_ip_for_rate_limit` consults, so an environment that has moved on from the
process is visible rather than papered over.

Named `trusted_proxy_hops` — for the variable an operator sets, rather than for
`smb_host`'s flat `trusted_proxies` — because the check it exists to enable is
"does the running process agree with what I just set", and that comparison should
not need a translation step. It is a count of hops, not a list of proxies.

Published on an unauthenticated endpoint deliberately. A wrong hop count is
marginally easier to exploit when stated, but the bucketing is discoverable
anyway by varying a prepended `X-Forwarded-For` and observing whether buckets
separate — so concealment buys an attacker little and costs the operator the one
signal that would have caught this. Same posture as `db.tls_available` in the
same payload: reported, never enforced. `FORWARDED_ALLOW_IPS` is untouched and
stays at its strict default; the limiter reads `X-Forwarded-For` directly when
hops > 0, so it does not depend on uvicorn trusting the edge.

Guarded, each planted and observed reddening by name:

* **the reported value tracks the resolver, not the environment** — proven by
  making the two disagree after import. Planted twice: the naive mirror
  (`os.environ.get(...)`) reddens nine of ten tests, and a *careful* mirror that
  reproduces the module's `max()`/`int()`/`ValueError` parse exactly still
  reddens the two adversarial tests — it is right about every input and wrong
  about the running process, which is the whole defect.
* **an unusable setting cannot make the liveness probe raise** — planted with an
  unguarded `int(os.environ.get(...))`, which turns a typo in an unrelated
  variable into a 500 and a serving org taken out of rotation.
* **the field costs no backing-store contact** — asserted by recording what
  `/health` touches. A first draft raised from the stub, which
  `_db_tls_available_safe` catches like any other exception, so it passed whether
  or not the store was touched; recording is the version that can fail.
* **additive** — a superset assertion, not a frozen key list: every key the
  endpoint already carried is still present. Freezing the set would fail every
  future addition, including this one.
