### The join landing takes its org name from the server and states that it has not checked the invite

`server/static/ui/join-boot.js` read the page's heading from a `?org=` query
parameter, so a link of the form `/join?invite=x&org=Example%20Payments` set the
heading of the org's own page to text chosen by whoever wrote the link. The value
reaches the page through a text node, so this was not script injection; the org
name now comes from `GET /api/portal/chapter`, with `location.host` as the
fallback.

The page also rendered a full join flow for any non-empty token. `if (!token)`
tests presence, not validity, so a revoked, expired, mistyped or never-issued code
produced the same page as a usable one, and the refusal appeared only later in the
terminal.

The page still does not check the code. An unauthenticated endpoint answering
whether a given invite is usable would let anyone test invite codes against the
org, which is why the QR route also declines to validate. What the page now states
instead is the org's join policy, read from the already-public
`GET /api/org/join-policy` — an org-wide value that discloses nothing about any
token, and which determines whether the invite is what admits the user at all:

* `invite` — the page says it has not checked the code, says why, and quotes the
  refusal the server returns, so a user who hits it can tell it apart from a local
  misconfiguration.
* `open` — no invite is needed; the code is carried but does not admit.
* `approval` — the command registers a request a leader must approve.
* unreachable — stated as such, rather than rendering as an invite-gated org.

A revoked, expired, exhausted or never-issued token still render identically.
