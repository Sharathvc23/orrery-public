### Security — an audit row is written to this org's ledger

`POST /api/chapter/audit/record` binds its actor to the verified caller but took
`chapter_id` from the request body, so a correctly-attributed row could be
appended to a different org's hash-chained ledger. The row is now written to this
org's ledger. The endpoint still requires only a member signature: a member may
append an attributed event to their own org's log.
