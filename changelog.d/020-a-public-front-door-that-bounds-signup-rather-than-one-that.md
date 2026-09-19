### A public front door that bounds signup, rather than one that hides a token

`smb_host` gates provisioning on a shared secret and `smb_funnel` is a static
bundle that cannot hold one, so the funnel has been reading the secret from
`?provision_token=` — correct for an operator demo and unusable for a public
product. The obvious replacement is a server-side component that keeps the token
and forwards the call.

**On its own, that component is exactly as open as publishing the token.** One
extra hop, the same openness. Measured before building anything: nothing else
bounds provisioning. There is no rate limiting in `smb_host`,
`SMB_HOST_POOL_SIZE` bounds pre-warming rather than the total, the cold path
mints on demand with no cap, and there is no expiry or per-source accounting. A
loop with a valid token provisioned **60 tenants in 3.7 s and was never refused**,
at roughly 20 KB of key material each. The token was the only bound that had ever
existed, so removing it without replacing it opens the door rather than widening
it.

`smb_signup` is therefore a **bounded** façade, and it refuses to provision at all
unless both bounds are configured — unset, empty, `0`, negative and unparseable
are one answer, and it is not "unlimited". A total tenant cap is counted from the
**host's own** tenant count rather than anything the service remembers, so a
redeploy does not reset it and operator-path tenants count against it too; if the
host cannot be reached, signup refuses, because not knowing the headroom is not
permission to ignore the cap. A per-source rate limit sits in front of it, and the
documentation says plainly which of the two is load-bearing: a restart empties the
rate limiter and a distributed source never fills it, so the cap is what bounds
the damage. `X-Forwarded-For` is client-supplied and is ignored unless the
deployment states how many proxies it runs — trusting it would let one caller mint
a fresh bucket per request.

**The cap is observable before it bites.** `GET /health` reports the cap, the
count and the headroom, so exhaustion is visible to a canary or an operator rather
than learned from the first business turned away. An unreachable host reports a
`null` headroom and says why instead of inventing one.

**Reaching the cap is its own state, and so is being rate-limited — two, not
one.** Waiting clears a rate limit and never clears a full allocation, so
collapsing them would send a business away for an hour to a door that will still
be shut. The funnel's refusal panel now distinguishes eight outcomes, each with
advice that fits it, and asserts that no two share a state or a headline.

Provisioning now requires a contact channel, and the front door carries it
through: the request shape is checked here so a malformed one stops at the door,
while **what counts as a usable contact stays the host's rule**, derived from what
its delivery path can actually deliver on. A second opinion in the façade could
accept something the host would refuse. A refused contact does not spend cap
headroom either, or anyone could exhaust the front door with requests the host was
never going to accept.

That refusal is rendered by the **existing** validation state rather than a new
one, because it calls for the same action — change what you entered and submit
again — and a separate state would give identical advice under a different
heading. Its headline had to stop naming one field, though: it read "That business
name can't be used", which is false when the contact is what was refused. The
specificity a person needs is the host's own message, which is rendered below.

Bookings and card reads are relayed untouched: they mint nothing and write no key
material, so they are neither bounded nor credentialed. An `Authorization` header
supplied by a browser is discarded rather than forwarded.

**Not yet open.** Bookings now reach a business, which removes the reason the gate
existed, but deploying a public signup surface is its own step: this is built and
wired into CI, not announced or linked. The operator path via `?provision_token=`
is unchanged and still works against a host directly.
