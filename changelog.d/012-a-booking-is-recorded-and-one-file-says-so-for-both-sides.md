### A booking is `recorded`, and one file says so for both sides

`booking.status` came back as `confirmed`. Nobody at the business confirmed
anything: the host writes a row, checks the slot was free, and sets the value
**before delivery is even consulted** — so `confirmed` shipped alongside
`delivered: false` in the same response. There is no acceptance step anywhere in
the path. The value is now `recorded`, which is what happened, and it finally
agrees with the label the panel already carried: *Status (as the host recorded
it)*.

**The rename is not the point; the parity check is.** The value was a literal
held twice — `smb_host` assigned it, `smb_funnel`'s mock constructed it, and each
side's suite asserted its own copy. That is exactly the shape that let the mock
become **more permissive than the host** on the refusal path, where the parity
suite read its expectation off one of the two things it was comparing and
therefore could not fail. Renaming without fixing that would leave the next
divergence just as invisible.

So the value is stated once, in `smb_funnel/tests/host_contract.json` under
`book_success.booking_status`, and every assertion reads it from there:
`smb_host`'s suite, the funnel's parity suite, and `smoke.mjs`, which had been
holding a third copy. Editing the file wakes both suites, so neither side can
move alone.

**One direction of that pair had no cross-check, and now does.** Editing the
contract runs both jobs and a mock change runs the funnel's — but a change to
`smb_host/main.py` *alone* does not re-run the funnel suite, because its CI
filter matches `smb_funnel/`. The funnel's parity suite therefore reads the
host's assigned literal out of its source and compares it to the contract.
Read-only: the funnel imports, executes and modifies nothing there.

Proven by planting a divergence in all three directions and reverting each:
the host drifts (funnel guard **and** both host assertions redden), the mock
drifts (parity test and `smoke.mjs` redden), and the contract itself drifts
(all four redden — the interlock is symmetric).

⚠️ **The word "confirmed" has a second, unrelated meaning here** and it was left
alone: the receipt badge's *"Signature valid — issuer not confirmed"* is about a
receipt's **issuer**, not a booking. A sweep over the word would have rewritten a
load-bearing label that two suites pin, and the booking rename would have looked
clean while quietly changing what the badge claims. A test now fails if that
wording goes or if a booking-status literal returns to the render path.

Also hardened: the *never invents a status* test asserted the **absence** of the
word `confirmed`. That form passes for a renderer that invents any other word —
and it was about to fail for the wrong reason, since the panel's own label
contains the status word, so scanning the whole panel cannot tell a label from a
value. It now asserts what the status **cell** renders.
