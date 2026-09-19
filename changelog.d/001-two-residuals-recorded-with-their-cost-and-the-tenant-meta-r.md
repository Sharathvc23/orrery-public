### Two residuals recorded with their cost, and the tenant meta record is written atomically

Two suspects from the release-readiness inspection are ruled residual and
recorded in the audit ledger with the cost stated rather than closed. L16: the
NANDA Index resolution hop — `GET /agents/{id}`, the AgentFacts document and
`/sm-bridge/resolve/{id}` — answers 200 for a known member and 404 for an
unknown id to an anonymous caller. Existence only, now that the member's prose
is stripped and the enumerating surfaces are consent-gated; gating existence on
listing consent would 404 Index resolution for every published-but-unconsented
member, which is a product decision about what a published card means. L17:
the v0.3 nonce replay store is memory-only, so a signed request captured on the
wire replays inside its ±300 s window once per restart; a durable store through
the rate-limit persistence pattern is the follow-up.

`smb_host`: the tenant meta record — what a restart rehydrates a tenant from,
and every field the pool-reclaim predicate reads — was written with
`Path.write_text`, which truncates before it writes, so a crash in between left
a torn file and the tenant, a business if claimed, failed to rehydrate. It is
now written to a sibling temp file, fsynced and renamed over the record.
Guarded: a simulated crash mid-write (planted as the old truncate-in-place
shape, observed red by name) leaves the previous record byte-identical and no
temp file behind, and the tenant still rehydrates.
