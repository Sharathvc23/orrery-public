### Two different things were called DID pinning, and one of them was read onto the other

The claim "DID pinning (trust-on-first-use)" covered two mechanisms with the same
name and different scopes, and nothing in the documentation separated them. The
first pins a **peer org's** attested `did:key` in a Postgres row keyed by peer,
written by the federation discovery cycle and cleared only through a leader-gated
route; it needs a `DATABASE_URL` and degrades to per-cycle trust-on-first-use
without one. The second stores a tenant's card key in a customer's **browser**.
An org-to-org guarantee could therefore be read as a guarantee about a receipt in
a customer's hands, which it is not.

Both are now scoped where they are claimed, and the browser-side one is recorded
with the two limits its own test suite cannot see: the remembered pin is not the
value the receipt is checked against (the funnel passes the card DID fetched in
the same session, and `pinnedDid()` has no caller outside the tests), and the pin
is keyed by the host rather than the tenant, so every business on a multi-tenant
host shares one slot.

The limit that survives either way is now stated wherever the consumer story is
told: the tenant card and the receipt come from the **same origin**, so checking
one against the other shows the host is internally consistent, not that the host
is the business. What anchors that is how the customer reached the URL, and
nothing in the product can distinguish a code on the counter from a link inside
the receipt. The name on a card is a display label rather than a claim anyone
verified: a repeated name is refused on both provisioning paths, but that
refusal is exact-slug, so `Corner Bakery Ltd` and `Corner Bakery NYC` still
provision alongside `Corner Bakery`.
