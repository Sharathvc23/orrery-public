### Publishing a skill into the org's registry is a member's act

`POST /api/skills/publish` and `/publish/package` verify the publisher's
Ed25519 signature over the content, which proves the skill is authentic and
nothing about who is listing it in *this* org's registry. Both were open at the
middleware, so any keypair on the internet could put a package in an org's
registry — the supply-chain shape a public deploy meets on day one — and the
package route honoured an `author_agent_id` query parameter verbatim, a label
anyone could set to anyone.

Publication now takes a registered member's request signature: the routes are
no longer declared self-signed, the middleware refuses everyone else, and each
handler checks for itself that the verified caller is a member of this org — a
signature alone is possession of a key, not membership. The registration is
attributed to that member; the query parameter is ignored. The package
signature is still verified fail-closed. Not a wire-format change — an
authorization tier. The skill's own documentation now says the request is
signed.

Guarded, each planted and observed reddening by name, the tree clean after each
revert: the handlers' own membership check removed; the routes re-declared
self-signed so the middleware waves them through.
