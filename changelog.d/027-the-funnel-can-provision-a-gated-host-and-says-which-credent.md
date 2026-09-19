### The funnel can provision a gated host, and says which credential is missing

`POST /provision` is now gated on a shared secret, so the browser funnel needed
to send one — and needed to say something useful when it has none.

**The header is sent when this browser holds a token, and is absent when it does
not.** Not empty: `Authorization: Bearer ` with nothing after it is a third state
neither side has a rule for, and a browser with no token now sends the request
byte-identical to the one it sent before the gate existed, which is the shape CI,
the demo scripts and every loopback host use.

**The token is never built into the page.** This funnel is static, so anything
compiled into it is public. It is handed to a running page as
`?provision_token=…`, read once at boot, moved into `sessionStorage` — which dies
with the tab, unlike the `localStorage` the funnel never clears — and stripped
from the address bar before anything renders, so it does not survive a copied
URL, a bookmark, the back button or a screen share. `src/render.js` is given a
boolean rather than the value, so the module that writes to the document cannot
leak a secret it was never handed. A query parameter is read again here after
`?api=` was removed for being one; the two are opposite risks and `src/config.js`
states the difference where a reader will meet it: `?api=` let a link's author
choose the host that mints a stranger's recovery phrase, while
`?provision_token=` can only give away the link author's own secret.

**A refusal now says which refusal it is.** One line — "Couldn't create your
agent … please try again" — covered every failure, and "try again" is wrong
advice for most of them: a gated host answers 401 forever. There are four states
now: the host wants a credential this browser has not got (with how to supply
it), the host rejected the credential it has, the host is not configured to
provision at all (`503`, reachable only when the host has no token, so pasting a
secret would change nothing), and an ordinary failure, which keeps "please try
again" because a name collision is worth retrying.

**The host's own words were being thrown away.** The client read `data.error` —
the shape `smb_funnel/src/mock_core.js` returns — while `smb_host` is FastAPI and
raises `HTTPException(detail=…)` at every refusal. Against the deployed host that
meant every message was discarded and rendered as a bare `HTTP 409` or `HTTP 400`,
the duplicate-name and malformed-name refusals included, long before this gate
existed. Both shapes are read now.

**`Authorization` was missing from the host's CORS allowlist, and that made the
gate unreachable from a browser in both directions.** The funnel is served from
another origin, so its `POST /provision` is preceded by a preflight naming the
header; the middleware allowed only `Content-Type` and `Accept`, so the preflight
was answered `400 Disallowed CORS headers` and the browser never sent the request
at all — with a valid token as much as without one. The existing preflight test
asked only for `content-type` and passed throughout; it now asks for the headers
the funnel actually sends.

Guards, each planted and reverted: the bearer asserted from **what the server
received** rather than what the client believes it sent; the header's total
absence without a token; each of the four states from a real response; the token's
absence across the **whole node tree** rather than the elements a leak was
expected in; the stripped address bar; and the preflight. 43/43 in the funnel,
49/49 in `smb_host`.
