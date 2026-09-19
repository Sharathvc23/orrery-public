### Removed — the unrouted leaderboard page

`server/static/leaderboard/index.html` was bundled and its two modules were named in
the `/ui/{asset}` allowlist, but no route served the page. The page, both modules and
the allowlist entries are removed. The receipts tests that shared a file with it are
now `server/static/tests/receipts.test.mjs`.
