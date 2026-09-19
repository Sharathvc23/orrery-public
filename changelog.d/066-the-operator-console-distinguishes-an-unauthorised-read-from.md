### The operator console distinguishes an unauthorised read from an empty org

`/console/` read `/api/members`, received `401` because anonymous member
enumeration is closed, and rendered the refusal as "No agents have registered with
this org yet." on an org that had members. `console-boot.js` folded every failure
into a fallback value — `getJson(url, {members: []})` returned that fallback on any
non-`ok` response — so an authorisation failure, a missing endpoint and a dead
server all painted the same empty state.

Each read now returns a tagged outcome and each panel renders its own reason:
unauthorised, forbidden, missing, unreachable, malformed, or another status. An
authorised read that returns nothing still reads as empty, which is the case that
was correct before.

The console attaches the admin token the admin page already stores on this origin,
so an operator who has signed in once sees the panels without a second token
prompt and without a second place that stores the token. Reading anonymously is
still supported and now says so, with a link to where the token is entered.

An approval decision that the org refuses no longer reloads the queue unchanged.
The refusal is stated, and the console says nothing was recorded.

The Tasks panel is served by no route: `/api/tasks` answers 404 and has done since
the console shipped. It now says the endpoint is absent rather than reporting no
tasks. Whether the panel should exist is a separate question.
