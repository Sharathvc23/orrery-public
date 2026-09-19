### Security — mutating handlers bind the recorded actor to the verified caller

Twelve mutating handlers took an actor or target identifier from the request body
or path and wrote it to storage. The signing middleware verified the caller on every
one of them, but the handlers did not consult that result, so a signed member could
record an action attributed to a different member.

`POST /api/chapter/audit/record` took no `Request` parameter and copied
`actor_agent_id` from the body into `chapter_audit_events`, which is hash-chained —
the chain covers append order, not authorship, so the row was indistinguishable from
one the named member wrote. `POST /api/chapter/allowlist/add` and `/remove` wrote a
federation-allowlist entry and an audit row under a body-supplied
`added_by_agent_id`.

The full set, with the field each took the identity from:

| Route | Identity source |
|---|---|
| `POST /api/chapter/audit/record` | body `actor_agent_id` |
| `POST /api/chapter/allowlist/add` | body `added_by_agent_id` |
| `POST /api/chapter/allowlist/remove` | body `added_by_agent_id` |
| `POST /api/conversations` | body `from_agent_id` |
| `POST /api/conversations/{thread_id}/message` | body `from_agent_id` |
| `POST /api/mesh/send` | body `sender_agent_id` |
| `POST /api/mesh/intent` | body `requester_agent_id` |
| `POST /api/voice/config` | body `agent_id` |
| `POST /api/onboarding/advance` | body `agent_id` |
| `POST /api/onboarding/{agent_id}/reset` | path `agent_id` |
| `POST /api/channels/connect` | body `agent_id` |
| `POST /api/channels/{connection_id}/disconnect` | body `agent_id` |

All twelve now resolve the actor from the verified caller. Where a request body still
carries an actor field, a value that disagrees with the verified caller returns
`403` rather than being silently replaced.

`server/tests/test_mutating_routes_bind_the_actor.py` enumerates mutating routes
from the running app and fails on any that records an identity it did not verify.
Three paths are exempt and declare why: registration establishes the caller's
identity in the same request, and the two endorsement routes carry a separate
signature over the payload. They appear as four entries in the guard, because
registration is routed with and without a trailing slash.
