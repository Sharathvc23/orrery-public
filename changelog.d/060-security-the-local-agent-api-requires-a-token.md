### Security — the local agent API requires a token

The agent's 63 routes carried no authentication. `PUT /api/local/identity-trust`
set the trust score the executor compares against its auto-approve threshold,
above which trusted- and semi-trusted-provenance actions run without a consent
prompt. `POST /api/local/consent/approve` recorded an approval from the request
body when the named prompt was not on file, and `POST /api/local/consent/deny`
recorded denials the same way; `find_recent_denial` reads the 50 most recent
denial rows, so enough of them displace a real one and stop the executor
suppressing the action it refers to.

A token is generated on first start and stored in
`~/.community-member/.local-token` with mode 0600. An install that predates the
file gets one on the next start with no operator action. `community-member`
prints the file's path at startup.

One middleware requires it on every route. The exceptions are declared as an
explicit `(method, path)` list in `agent/community_member/local_auth.py`, each
with the reason it is open: the four `.well-known` documents and
`/agentfacts.json` (a peer resolves these before it can know how to sign),
`/api/health`, the A2A JSON-RPC endpoint at `POST /` (the caller is a peer agent
and holds no local token), and the platform uninstall webhook (open by route,
closed by the per-platform HMAC its handler requires). A route that is not on
that list is protected without anyone adding anything to it.

The token is read from `Authorization: Bearer <token>` or
`X-Orrery-Local-Token`, and compared with `hmac.compare_digest`. It is not read
from the query string or from a cookie: a query-string token reaches logs,
shell history and `Referer` headers, and a cookie would be attached by the
browser to cross-site requests. `COMMUNITY_MEMBER_LOCAL_TOKEN` overrides the
file.

`agent/tests/test_local_api_auth_guard.py` enumerates the route decorators in
`server.py` and drives each one without a token, failing on any that answers.
It also fails when a declaration names a route that no longer exists, when the
open list gains an entry, and when `server.py` mounts a sub-application whose
routes that enumeration would not see.
