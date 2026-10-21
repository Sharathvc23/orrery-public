### A 409 does not mean the record is right

`register_on_index_v2()` re-triggered on an org that already exists got a 409
from `POST /api/v1/orgs` and returned `{"ok": true, "status": "exists"}`,
commented "re-trigger is a no-op success". A 409 proves exactly one thing: the
`org_id` is taken. It says nothing about whether the record behind it still
matches what the org serves — and that function has no path that can update a
field, so every re-trigger reported success having written nothing.

**Measured 2026-10-21, on all three live orgs.** Each advertised
`tags: ["general ai"]` on the NANDA Index — the default `AGENT_FOCUS` captured
when they registered in June — while serving their real tags
(`space-science, education, outreach, …` for astrocity). `updated_at` had not
moved since `2026-06-25`.

That is not cosmetic. In the index's `organizations_search_vector` tags carry
the **highest** weight, `'A'`, and org ranking is a hard relevance filter
(`search_vector @@ to_tsquery`). So the stale copy decided whether an org was
ranked in **at all**:

- `q="communications press media"` → `orgsQueried=0`, though astrocity serves a
  `communications` tag and a `communications-lead` agent.
- `q="fundraising development grants"` → astrocity never ranked in.
- `q="space science education outreach"` → matched, but only through the
  *description* at weight `'C'`.

Agents that were published, resolvable and durable were unreachable, because
the org was never asked. The same shape as the false greens before it: a
success report whose truth did not depend on the thing it claimed.

Two changes:

- **A 409 is now checked, and has three outcomes.** The record is fetched and
  compared with what the org serves: `exists` (matches — a genuine success),
  `stale` with `ok: false` and the differing field names (and a pointer to the
  operation that *can* fix it), or `unverifiable` when the record could not be
  read. Unknown is reported as unknown rather than folded into either.
- **`POST /admin/api/index-v2/resync`** pushes the served `description`/`tags`
  over the index's copy — the update path registration never had. It sends only
  fields that actually differ, logs in and *never* registers, writes nothing
  when the remote record cannot be read, and returns the tags and the org
  identifier either side of the write so the caller can compare values instead
  of trusting an `ok`.

`description` and `tags` now have one derivation, shared by registration and
resync. Two copies of that transform is how the index's stored copy and the
served card came to disagree in the first place.
