### The funnel's browser pin was removed, because nothing on the verdict path read it

The SMB funnel computed a trust-on-first-use pin — `src/pin.js` stored a tenant's
`did:key` in `localStorage` and reported `new` / `trusted` / `warning` /
`unknown` — and then verified the booking receipt against something else: the
card DID fetched from the host in the same session. `pinnedDid()` had no caller
outside the tests, and the `pinState` the funnel computed was assigned to
`liveTenant` and never read. The success tooltip nevertheless told the customer
that "the issuer matches this business's pinned did:key". A control the UI cited,
its own suite covered, and the code did not call reads as protection while
checking nothing, which is worse than its absence.

**It was removed rather than wired, and the reason is structural.**
Trust-on-first-use needs a **second encounter**: the first sighting is only
stored, and the value appears when a later one disagrees. This funnel provisions a
**new tenant on every run** — the tenant does not exist before the request that
creates it, and no path returns to one. Keyed correctly by host **and** tenant, the
pin would therefore be written and read inside a single session, and its verdict
would be a function of its own write: it could report `trusted` and never
`warning`. That is the same shape as the defect being fixed — a check that cannot
disagree — so wiring it would have replaced a control nobody called with one that
cannot fail. If a repeat-visit customer surface is ever built, a pin belongs
there, where the second encounter exists.

The pin was also keyed by the API base URL rather than the tenant, so every
business on a multi-tenant host shared one slot; that is recorded because it was
measured, not because it was the reason.

**What is checked, and what the badge now says.** The anchor is the `did:key` on
the agent card this host served for this tenant, read in this session. The success
label read "Verified offline — signed by this business ✓"; it now reads "Verified
offline — matches this agent's card ✓", and the tooltip states the limit rather
than a pin: the card and the receipt come from the same origin, so their agreement
shows the host is internally consistent, not that the host is the business. The
mismatch label names the card it differed from. Each badge label names the
comparison that ran.

**The anchor is now asserted where it is used.** `smb_funnel/tests/wiring.test.mjs`
boots the real `app.js` under a document built from the ids in `index.html` and
drives its own submit and booking handlers against an HTTP host, then reads the
badge the app painted. The load-bearing case is a host that serves **one** key on
the agent card and signs the receipt with **another**: every byte of that receipt
is honestly signed and internally consistent, and only consulting the card
refuses it. Two further cases cover an honest host and a host that serves no card
at all. Each was validated by planting its regression — dropping `expectedIssuer`,
and anchoring the receipt to its own `issuer_did` — and confirming the suite goes
red on the assertion meant to catch it. `tests/source-guard.test.mjs` fails on any
funnel string claiming a pin and on `pin.js` returning, so quieter copy over the
same dead module does not pass either. 37/37 green.
