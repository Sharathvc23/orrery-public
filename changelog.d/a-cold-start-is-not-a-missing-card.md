### A cold start is not a missing card

The catalog canary resolved every entry an org advertises and treated every
non-200 identically. Measured 2026-10-16, on the first run after the canaries
were armed: it failed on three HTTP 502s — `regentix-head-of-sales`,
`regentix-cto` and `astrocity-executive-director` — each of which returned 200
when re-probed by hand minutes later, twice, with no intervention. They were
idle containers waking up.

**That is a false red, and it is the same defect as the false greens this canary
was built to remove:** its result did not depend on the condition it claims to
check. It reported "this org advertises a URL nothing backs"; what it had
observed was "this host had not served a request lately". A monitor that cries
wolf every six hours gets muted, and a muted monitor and a sleeping one fail
identically — so left alone this would have undone the two fixes before it.

Every HTTP call in the canary now goes through `scripts/_probe_status.py`, which
names what was seen rather than sorting it into whichever bucket was nearest:

- **404 / 410 — the card is NOT THERE.** The real condition, reported at once.
  Not retried: waiting does not make an unpublished card appear.
- **502 / 503 / 504, and any transport-level failure — the host is present and
  NOT READY.** Retried twice over a short backoff, and reported as a failure
  only once it persists.
- Anything else is reported as itself, unclassified rather than guessed at.

**Three call sites, not one, and the one that was easiest to miss was the
worst.** The entry loop was the visible half. The catalog fetch turned a cold
start into `catalog unreadable` *and* silently skipped the floor for that org.
And `GET /agents/root` — read to tell an org's own entry from its members —
returned nothing on a cold start, which the floor correctly fails **closed** on,
so a sleeping container **manufactured a FLOOR BREACH on a healthy org**: a
false red living inside the floor shipped one change earlier. The fix is to
retry *before* reaching the fail-closed path, not to soften where that path
leads; the floor's refusal to rule on an unreadable identifier is unchanged and
still guarded.

**A persistent 502 still fails.** Absorbing a real outage into a pass would
trade the false red for a false green in the same place, which is the worse bug;
`test_a_persistent_not_ready_is_still_a_failure` holds that line. And a retry
that succeeds is *printed* — `woke:` per probe plus a run-level count — because
a host that cold-starts on every single run is degraded, and a silent retry is a
deleted signal.

**The remediation branches on what was measured.** The failure text said to run
`publish_host39_card.py --record-on-org`, which for a 502 points the operator at
a missing card that is not missing. A not-ready host now gets its own section
and its own paragraph, which says the card exists and names the deploy as the
thing to look at.

Verified by driving the real script against a local server that reproduces each
condition, and against the pre-fix script as a control: a single cold start on
the catalog, on an entry, or on `/agents/root` took the old canary to EXIT 1 —
the last of those reporting a collapsed registry — and all three now pass while
naming the retry. A persistent 502 and a genuine 404 both still EXIT 1, and
print different advice. The classifier and the retry loop are stdlib-only, in
`scripts/`, driven directly by `tests/test_probe_status.py`: `doc-guards`
installs nothing but pytest, so a guard needing `httpx` is one that job cannot
run.

Scoped to this canary deliberately. `smb_host_canary` probes the same live hosts
and has the same exposure, but its sequence includes `POST /provision`, which is
not idempotent and is a separate decision; `receipt_verify_canary` already reads
a 404 as "not published" rather than as a failure. Both are follow-ups.
