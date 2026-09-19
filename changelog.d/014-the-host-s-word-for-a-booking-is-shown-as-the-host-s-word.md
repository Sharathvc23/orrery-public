### The host's word for a booking is shown as the host's word

The same audit as the funnel pass, one layer down: what `smb_host` **serves** —
the tenant agent card, `agentfacts.json` and the `/book` response — measured by
driving a real host and reading the payloads rather than the source.

The funnel re-renders exactly one human-readable string out of all of it, and it
is the one that matters. `smb_host` sets `booking["status"] = "confirmed"`
unconditionally, **before** delivery is consulted: a booking comes back
`confirmed` alongside `delivered: false` in the same response, and there is no
acceptance step anywhere in the path — nobody at the business confirms anything.
Rendered unattributed in the success green, that word tells a reader the business
agreed. It now names its speaker — *Status (as the host recorded it)* — and
carries neutral styling instead of the green, because green is a verdict on an
outcome this panel does not know.

⚠️ **Neutral is not negative.** No "unconfirmed" label is added and nothing is
hidden; the host's word is shown verbatim. The colour moves to the Delivery row,
which is the one backed by something the host actually observed. Both properties
are pinned by tests and each was planted and reverted.

Everything else found in what the host serves is recorded as a finding against
`smb_host` and the shared card builders rather than changed here — the funnel
renders none of those strings, and that subtree is out of bounds for this change.
