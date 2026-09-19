### The front door states who called, and stops lying about what a browser refused

**`smb_signup` forwarded no caller, so `smb_host` recorded the façade for
everyone.** `smb_host` records `provisioned_by` from the caller it can see, and
every request it saw from the front door arrived on the front door's socket.
Measured on a real pair: three distinct visitors through the façade and one
operator calling the host directly were **all four recorded `127.0.0.1`**. The
tenant cap still said how many agents had been issued; nothing said by whom, on
exactly the deployment where by-whom starts to matter. Both configuration halves
already existed — `SMB_SIGNUP_TRUSTED_PROXIES` and `SMB_HOST_TRUSTED_PROXIES` —
and nothing in between carried the value.

`smb_signup` now resolves the caller **once** per provision and uses that one
value for both the rate-limit bucket and a **single-entry `X-Forwarded-For`**
sent to the host, replacing whatever the caller supplied. It is the authoritative
party for the decision because it terminates the visitor's connection and already
has to make it in order to rate-limit; two determinations could disagree, and a
bound that counted one address while the record named another would be worse than
no record. With no trusted hop configured the inbound header is discarded unread,
so a caller cannot write its own attribution — the naive relay is *worse* than
`127.0.0.1`, because one obviously wrong value is visibly wrong and a plausible
forged one is not. Appending rather than replacing is refused for a second
reason: it makes the chain's length caller-controlled, so what a hop count
selects stops being fixed.

**What `provisioned_by` identifies after this, stated rather than implied:** the
network address `smb_signup` resolved for the connection that asked, under the
hop count its operator declared. It is a network-path observation, not a person
and not an identity — shared by everyone behind one NAT, changing when an address
changes, and never used to authorize or refuse.

**The host half is configuration and can be silently unset, so it is now
observable.** `smb_host` ignores `X-Forwarded-For` entirely below
`SMB_HOST_TRUSTED_PROXIES=1`; with it unset, forwarding is a fix that looks
applied and records the façade's address forever. `smb_host`'s `/health` reports
`trusted_proxies`, and `smb_signup`'s reports `caller_attribution`
(`recorded` / `discarded-by-host` / `unknown`), so the mismatch is read off a
surface instead of discovered later from a directory of identical attributions.

**Cross-origin access to `smb_signup` is ruled unsupported, and the tree now says
so in both places.** `smb_host` allows any origin because a static bundle hosted
elsewhere has to reach it *and* because provisioning there is bearer-gated. The
front door has no such gate by design, so the same permission would let any page
on the internet spend a visitor's rate-limit allowance and the operator's cap from
that visitor's browser — and, now that the caller is forwarded, record that
visitor's address as having provisioned an agent. The suite already asserted the
refusal; `smb_funnel/src/config.js` documented the opposite, telling readers to
point `API_BASE` at another origin without saying which target that works for.
It now names both: cross-origin at `smb_host`, same-origin only at the front
door, which serves the bundle itself.

**And a page in the unsupported shape is told the truth.** A browser that stops a
request hands page script an error with **no status**, so the funnel fell through
every branch of its status table into the catch-all *"Couldn't create your agent.
Please try again."* Measured in a real Chromium against a real pair with the rate
limit spent: the visitor saw that sentence for a **429 whose request never left
the browser**, and 507, 401 and 201 were equally invisible — a verdict on an
exchange that did not happen, with advice that could never work. There are now two
states for a request that was never delivered, checked *before* the status table
rather than inside it, claiming nothing about the details entered or about
capacity and naming the one cause a page can check for itself: it is configured to
call another origin. The page does **not** claim the cause was CORS, because page
script cannot tell a refused preflight from a dead host.

Guarded, each planted and observed reddening by name:

* two distinct callers through the façade are recorded as two distinct
  `provisioned_by` values — asserted against what the host **stored**, not
  against what the façade sent, because the sent-header version passes with the
  host discarding every byte of it. Planted by dropping the forwarding: it
  reddens with `the host recorded '127.0.0.1' for a caller at 198.51.100.7`.
* a caller behind an untrusted peer cannot choose its recorded attribution.
  Planted with the pass-through relay: reddens by name. The append variant is
  caught by a second guard on the chain's length, planted separately.
* the browser path is asserted in a **real Chromium** (`scripts/browser_smb_funnel.py`,
  case E), not with node's `fetch`, which performs no preflight and would drive
  the service with its cross-origin rule effectively off. Planted by restoring
  the old status table: the case reddens with `data-state=failed`.
