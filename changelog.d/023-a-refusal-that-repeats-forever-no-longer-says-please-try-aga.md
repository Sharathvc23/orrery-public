### A refusal that repeats forever no longer says "please try again"

The provisioning-error panel had four states and routed everything that was not
`401` or `503` to "Couldn't create your agent — please try again", justified on a
name collision being worth retrying. That was wrong twice: a `400` (the name has
no alphanumeric character to build an id from) and a `409` (the id is already
claimed) both repeat forever, so resubmitting unchanged is the single action that
cannot work. There are six states now, one per distinct action, and only one of
them advises retrying.

A `422` is also read rather than reduced to its status. FastAPI refuses an
absent, empty or wrongly-typed name *before* the handler runs, so its `detail` is
a list of `{loc, msg}` objects; the client checked `typeof detail === "string"`
and fell through to a bare `HTTP 422`, naming a status code where the host had
sent a field and a reason. It now renders `business_name: Field required`.
