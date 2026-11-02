### The Index sees one agent unless the org publishes its members, and the docs now say so

The org's answer to the NANDA Index's agent search applies the catalog's member
gate verbatim. The fan-out is anonymous, so an org with `ORG_PUBLIC_MEMBER_CATALOG`
off is discoverable on the Index as **one agent, not as its roster**. That is the
privacy default doing its job, and there is deliberately no bypass. It is also
invisible to the operator: nothing is set, nothing errors, nothing logs, and the
members are simply never candidates.

The variable had no row in `docs/CONFIGURATION.md` at all. It now has one, in the
same "necessary but NOT sufficient" register as `ORG_HOST39_CARD_BASE`. A new section,
*What the Index can see of this org*, states what the Index actually holds and how a
consumer reaches a member.

- **What the Index holds.** One catalog root per org, `urn:air:<domain>:catalog:root`.
  Members are not records there: search never returns one, and resolving a member's
  URN returns the org's root with `"match": "publisher"`.
- **How a consumer reaches a member.** Resolve the root, then read the org's
  `/.well-known/ai-catalog.json`.
- **Agentic search.** It is the one surface that returns members, built live from the
  fan-out. The section lists the five conditions that must all hold.

The first condition is the one most easily missed: the Index ranks the org on its
**stored copy** of `description` and `tags`, and member skills play no part. Measured
2026-11-01, `q="peer review"`, a live member's skill, ranked astrocity out entirely.
Its stored tags were still the June default. Only the admin resync route refreshes
that copy.

The section ends with a copy-pasteable check. It uses public endpoints only and puts
the Index's `agentic-search` (including `orgsUnreachable`) next to the org's own
anonymous `/agents/search`, with a table that tells "dropped", "withheld", "not
ranked" and "no match" apart. Every URL in it was driven against both live orgs
before merge.

`tests/test_member_catalog_discoverability_is_documented.py` keeps the row and the
check in place. It is stdlib-only and derives the variable name from the gate's own
constant.
