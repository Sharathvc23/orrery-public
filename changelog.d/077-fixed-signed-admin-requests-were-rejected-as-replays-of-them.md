### Fixed — signed admin requests were rejected as replays of themselves

`auth_verify.verify_request` consumes the request's `(agent_id, nonce)` pair in the
replay store. `_authorize_role` called it a second time on a request the middleware
had already verified, so the second call found the nonce spent by the first and
returned `nonce_replay`.

Eight mutating routes were affected: `POST /api/invites` and its trailing-slash
form, `POST /api/invites/{token}/revoke`, both approval decisions,
`POST /api/org/join-policy`, `POST /api/admin/trust/decay-sweep`,
`POST /api/dsar/delete`, and the admin branch of `DELETE /api/members/{id}`. On each
of them the signed `did:key` admin path was unusable and only the shared
`X-Admin-Token` worked. The failure direction was closed rather than open, but it
left the role gate on these routes unexercised over the signed path.

`POST /api/admin/trust/decay-sweep` and `POST /api/dsar/delete` were also absent
from the admin-bearer list, so neither credential reached the handler. Both are now
listed; the handler continues to enforce role.

The failure surfaced under two different reasons. v0.3 signs `METHOD:url_path` with
the path including the query string. The middleware verified that form; the second
call passed the bare path, so on a route carrying a query string it rebuilt a
different canonical string and returned `invalid_signature`. Routes without a query
string returned `nonce_replay`.

`_authorize_role` now reads the middleware's recorded result
(`request.state.verified` and `request.state.agent_id`) and verifies only where
nothing has, leaving handler-first paths such as `/admin/api/*` unchanged.

`server/tests/test_signed_admin_path_is_usable.py` asserts per route that a signed
admin succeeds, a signed non-admin is refused for its role, an unauthenticated
request is refused, and the bearer path still reaches the handler. A separate test
asserts the replay guard still rejects a genuine replay.
