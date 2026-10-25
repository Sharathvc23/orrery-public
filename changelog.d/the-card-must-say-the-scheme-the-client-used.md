### The card must say the scheme the client used

`_agent_base_url` built an agent card's `url` from `request.url.scheme`. Behind
a TLS-terminating proxy — Railway, Fly, any ingress — the application leg is
plain HTTP, so that reports `http` for a request the client made over HTTPS.

**Measured live 2026-10-25 on the astrocity org: all six agent services served
`url: http://<domain>` in their A2A cards**, while each service's
`AGENT_PUBLIC_URL` was correctly `https://<domain>`. A non-`https` URL is
dropped outright by the NANDA Index's entry sanitizer, so the card advertised
an address the index would refuse.

Nothing local could show this. There is no proxy in front of a dev run, so
`request.url.scheme` is right there by accident — the value was only ever wrong
in the one environment that matters.

The scheme now comes from `X-Forwarded-Proto` (first entry of the chain: the
originating client), falling back to the request's own scheme when the header
is absent or unusable. The header is attacker-settable on a direct request, so
it is a best-effort fallback and nothing more: it affects only the URL echoed
back to that one caller.

The second half of the defect was duplication. `registry.public_endpoint`
already resolved `AGENT_PUBLIC_URL` for the endpoint registered on the org, and
this function ignored it — so the card's URL and the registered endpoint were
two independent derivations of one fact, free to disagree. In production they
did: the card said `http`, the registered endpoint said `https`. Both now route
through `public_endpoint`, with a source guard asserting the delegation rather
than trusting it to stay.
