### A member agent reports its own build

A member agent exposed no build identity of its own. The one agent route that
carried a commit was `/api/health`, and it returned the **org's** `/health`
verbatim, so its `git_commit` named the org server's build while reading as the
agent's.

**Measured live 2026-11-01 on a member agent:** `/.well-known/agent.json`,
`agent-card.json`, `agent-lifecycle.json`, `conformance.json`,
`reputation.json` and `/agentfacts.json` all answered 200 with no commit.
`/api/health` answered `git_commit: ed56597…`, which was the org's commit, and
that value was used to verify a deployment of the wrong service. A stamp that is
correct about a service you did not ask about is worse than no stamp at all.

**`GET /version` (open, no local token)** now reports the agent's own
`git_commit`, `git_branch` and `build_timestamp`. These are the same field names
as the org server's `/version`, so one probe reads both. When the build's two
commit sources disagree, it also reports the org's `platform_commit` /
`provenance_conflict` pair.

**The commit is baked at build time**, by the same mechanism as the org image
(#47): `ARG GIT_COMMIT=${RAILWAY_GIT_COMMIT_SHA:-unknown}`, so a
github-connected Railway build bakes the builder's commit and an explicit
`--build-arg` still wins. The difference is the sink. The value goes into a file
inside the package, `community_member/_build_info.json`, and never into an
`ENV`. A runtime service variable named `GIT_COMMIT` can shadow an `ENV`, and
that is how the org's `/health` came to report a commit it was not running. A
file baked into the image cannot be shadowed that way. With no file, the stamp
is an honest `unknown`. There is no `git rev-parse` fallback, because an
installed package can sit inside an unrelated checkout.

**`/api/health` says whose health it is.** The org's payload now sits under
`org`, next to `payload: "org"` and a pointer to `/version`, and nothing about a
build sits at the top level. `jq .git_commit` on the old response returned the
org's commit; on the new one it returns nothing. The route is still a proxy,
because the e2e harness waits on it as liveness. It just no longer passes itself
off as the agent's own health.
