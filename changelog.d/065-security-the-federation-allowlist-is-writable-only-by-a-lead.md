### Security — the federation allowlist is writable only by a leader or admin, and only for this org

`POST /api/chapter/allowlist/add` and `/remove` required a member signature and
nothing else, so any member with a keypair could add or remove an entry. Both
also took `chapter_id` from the request body, so the row could name any org, not
only the one serving the request. Both now require `chapter_role` in
`{leader, admin}` and write to this org's own id.

What made member-level access to this table a federation-wide decision:
`chapter_auth.is_peer_allowed` returns True for every peer while the allowlist
is **empty**, and switches to default-deny as soon as it holds one row. So a
single entry naming an unrelated peer does not add one peer — it excludes every
peer the org actually federates with. `is_peer_allowed` currently has no callers,
so nothing consults it today; the behaviour is asserted in
`server/tests/test_federation_allowlist_authz.py` because it decides how much a
stale or unauthorised row costs if it ever is wired.

**Two related gaps are recorded and not fixed here.** `POST /api/chapter/sso`
and `DELETE /api/chapter/sso/{chapter_id}` have no role check and take
`chapter_id` from the request, so a member can set another org's SSO issuer with
`enforce_sso` on, or clear it. `POST /api/chapter/audit/record` binds its actor
to the verified caller but still takes `chapter_id` from the body with no role
check. All three are declared in the same test file, which enumerates handlers
accepting an org or peer identifier from the app's own route table and fails on
one that is neither role-checked nor declared.

**Knowingly left open:** `GET /api/chapter/allowlist/{chapter_id}` still answers
an unauthenticated request. Its contents are peer org identifiers, which are
already public through the federation surface, and reading it is the only way an
operator can inventory existing rows without a database credential. It is a
follow-up, not an oversight.
