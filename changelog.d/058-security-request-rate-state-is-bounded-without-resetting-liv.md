### Security — request-rate state is bounded without resetting live quotas

The org server's process-local rate limiter kept one bucket for every client
key it had ever seen, so key churn could grow memory without bound. Each worker
now keeps at most 10,000 tracked buckets and updates them atomically using a
monotonic clock. At capacity it reclaims only expired buckets; if every bucket
is live, an unseen key receives the existing `429` response rather than evicting
a live client and resetting that client's quota. Existing tracked keys continue
under their normal limits.

The new bounded-cardinality
`nanda_chapter_rate_limit_capacity_rejections_total` metric counts only this
capacity path and has no client-key or other attacker-controlled labels. The
store remains per worker, resets on restart, and does not replace a shared or
edge limiter for deployments that need a global ceiling.
