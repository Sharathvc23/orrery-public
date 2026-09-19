### The SMB funnel says what it checked, and stops implying what it did not

An audit of every consumer-facing string a stranger reaches on the SMB path,
against one sentence: **the host serves the tenant's agent card and signs the
tenant's receipts, so checking one against the other shows the host is internally
consistent, not that the host is the business.** The verification badge and its
tooltips already said exactly that and are unchanged — they are the model the
rest of the page has now been brought up to.

**The one with real consumer consequence: the panel said a booking was confirmed
and threw away the field that says whether anyone got it.** `smb_host` puts
`delivered`, `delivery_channel` and `delivery_note` on every `/book` response,
for a reason its own source states — *"a caller that is told nothing cannot tell
a delivered booking from one the business will never see."* The funnel read none
of the three. A booking that reached nobody rendered identically to one that
arrived, headed **Booking confirmed**, on a page whose form promises the contact
address is where bookings go. The receipt panel now carries a Delivery row in
**three** states, because three things can be true: delivered (naming the
channel), not delivered (repeating the host's reason), and *not stated* — and
absence is styled as silence rather than as a warning, because a reader shown a
failure for silence would be told a judgement nobody made. The Status cell no
longer falls back to the literal `"confirmed"` when the response carries no
status, and the panel's title names what the panel is rather than asserting the
outcome above a row that reports it.

**The in-page mock was the permissive side again.** It omitted the delivery
fields entirely, and `API_BASE = "mock"` is the default at the public front door,
so the demo backend was the one path that could not have reported delivery even
once the page started reading for it. It now answers `delivered: false` with a
note saying it sends the booking nowhere — the honest answer for a backend that
delivers nothing, asserted in the parity suite beside the refusal contract.

**Claims corrected on the shipped page.** *"You keep the keys"* — the host mints
the tenant's Ed25519 key, persists it and signs bookings with it, so the customer
holds a copy and not the only one; the line now promises the recovery phrase,
which is what is actually handed over. *"signed did:key identity"* — a `did:key`
is a self-describing public key that nobody signs; the receipts are what carry a
signature. The hero lede no longer scopes receipt-checking as third-party
identity verification. A receipt's `notes` field claimed the booking arrived
*"via the NANDA Index"*, and no code on this path calls any index — a false
statement that was **signed over**, so the hedge did not survive the receipt
being exported or checked from the command line.

**And one contradiction inside a single file.** `smb_funnel/README.md` called
verification *"client-side and trustless"* and said *"a lying server … is
detected in the browser"*, three hundred lines below its own section explaining
that a lying server is precisely the case nothing in the browser catches. Both
sentences were written in good faith; nothing compared them.

**The guard.** A second claims family in `smb_funnel/tests/source-guard.test.mjs`,
beside the pin guard that already catches a label naming a check that never ran.
This one catches the opposite shape — a label naming a check that *did* run and
claiming more from it than its inputs carry: affirmative trustlessness, exclusive
key custody, and a verified *business*. Scanned over every paintable string
literal, `index.html`, and the funnel's own README, with each regex pinned
against sentences it must catch and correct prose it must not block. Plus the
positive half, because banning an overclaim leaves a page that could simply say
less: the success tooltip must keep naming the same-origin limit and what it does
not prove. Eleven regressions planted and reverted, each reddening its own named
assertion.
