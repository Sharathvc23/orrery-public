### The host39 publication step is documented, not just implemented

Setting `ORG_HOST39_CARD_BASE` tells the org **where** member cards live. It does
not assert that any particular card **exists**, and the AI Catalog needs the
second fact: a member is advertised with a host39 card URL only once that member
carries a publication record. That rule is right — the catalog used to emit a URL
for every member whenever the base was set, and on 2026-08-02 one org advertised
24 entries of which 18 returned 404 — but it has a cost that falls entirely on
the operator, once, on the deploy that first enforces it.

That cost was undocumented. `scripts/backfill_host39_publications.py` shipped
with an excellent docstring, a dry-run default and the whole ordering trap
written out, and appeared in **no markdown file in the repository**. Nor did
`POST /admin/api/host39/record-publication/{agent_id}` or
`publish_host39_card.py --record-on-org`. Meanwhile `docs/CONFIGURATION.md`
described a set card base as "the host39 card path, unchanged", which invited
exactly the reading that setting it was the whole job.

Two of three deployed orgs got the step. The third did not, and its catalog
advertised one entry while omitting 24. Nothing went red, because the strict code
was working as designed.

`docs/CONFIGURATION.md` now carries the procedure next to the variable that
triggers it: both ways to record a publication, and the ordering trap in full —
the first-time backfill needs a member list captured **before** the deploy,
because afterwards the live catalog has already omitted the members it would have
discovered and `GET /api/members` is auth-gated by design, so no open surface can
rebuild that list.

A guard holds it there, with the script set **derived from the code** — the
scripts that call the recording endpoint — rather than listed, so the next script
to write publication state cannot land undocumented.
