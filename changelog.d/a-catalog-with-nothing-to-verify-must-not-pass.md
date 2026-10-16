### The catalog canary fails an org that advertises nothing but itself

"Every entry the org advertises resolves" is the right claim, and it is vacuous
at the bottom. An org that advertises only its own root card resolves 1/1 and
passes most convincingly, having verified nothing about the member registry the
catalog exists to publish.

Measured live on 2026-10-15: the astrocity org advertised **1 entry while
omitting 24**, and the 01:21 UTC canary run printed exactly that —
`1/1 entries resolved (omittedMembers=24)` — and then `OK — every advertised
catalog entry resolved.` The check observed the collapse, reported the number,
and exited 0. This is the same shape as the unconfigured target fixed just
before it: a check that cannot observe the condition it is trusted to observe.

`scripts/_catalog_floor.py` now holds the floor — stdlib only, so the guards run
in the `doc-guards` job, which installs nothing but pytest so that a
documentation-only pull request cannot skip them. The rule references no org's
member count, so it encodes nobody's current state and cannot be satisfied by
the estate getting worse.

There are three outcomes, not two, and the third is the one that matters. The
canary is unauthenticated, so an org that does not publish members publicly
withholds all of them and correctly shows no member entries. Failing that org
would be a false alarm on a correct configuration; passing it silently would
rebuild the defect the floor exists to remove. It is reported as UNOBSERVABLE,
by name, on every run — as is a deployment too old to emit `withheldMembers`,
because absent is not zero. `withheldMembers` is read before the member count
and never folded into it: the catalog route keeps "withheld from an
unauthenticated caller" separate from "omitted for want of a resolvable card" so
a privacy decision cannot be read as an unpublished card, and the floor does not
re-merge what that route took care to split.

The org's own entry is identified by asking the org — `GET /agents/root` serves
that very entry — rather than by entry order, which is not a wire contract, or
by URL shape, which breaks for an org whose `PUBLIC_URL` is a custom domain
while the canary probes the platform URL.

The success line now claims both halves. The old sentence was true of a catalog
with nothing in it, and a guard holds the qualifier there.
