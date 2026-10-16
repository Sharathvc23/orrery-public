### An unconfigured canary refuses, instead of reporting green for a check that did not run

Both live canaries take their targets from `ORGS` and have no default. That is
deliberate: a hardcoded hostname would print live infrastructure into a public
Actions log every six hours, and a fork's scheduled run would probe hosts its
owner does not operate. So an unset `ORGS` skips — and the skip message has
always said, in as many words, "This is NOT a pass".

It said so in a log, while the exit status said the opposite.

The `CANARY_ORGS` repository variable was never recreated when this tree was
snapshotted into its public home. From 2026-09-19 to 2026-10-15 both canaries
ran every six hours, skipped, and reported success — 11-second runs that read no
catalog, fetched no bundle and checked no signature, while the two checks whose
whole purpose is to observe production said production was fine. Three breaking
upstream Index changes and three org records frozen for 93–112 days all went
past them.

The repository already holds the rule this violates. `smb_host`'s front door
refuses to serve when its bound is unconfigured, and
`test_an_unconfigured_bound_refuses_rather_than_serving_openly` holds it there. A
canary with no targets serving a green check is that same shape, one layer out.

`scripts/_canary_targets.py` now holds the decision in one place — stdlib only,
so the guard can be driven from the cheap doc-guards job without installing
`httpx` and `sm_arp` to check a two-branch choice. The canary workflows set
`CANARY_REQUIRE_TARGETS` bound to a `github.repository` comparison, so it is
true only where the deployments exist: a fork keeps the clean skip, and an
unconfigured target here is a failure that names `CANARY_ORGS` as the thing to
set. Bound to the repository rather than to `github.event.repository.fork`,
which is absent on `schedule` events — and `schedule` is the path that produced
the false green.

Three guards come with it, and the workflow one matters most: a refusal the
workflow never arms is unreachable, which is this same defect one layer down.
The workflow set is derived from the directory rather than listed, so the next
canary added cannot land unguarded.
