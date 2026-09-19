### First-run setup is the operator's to perform, not whoever reaches the port first

`POST /api/org/config` names the org and sets its join policy, once. It was open
until the org was configured, on the reasoning that nothing exists to sign with
before provisioning. That is true of a member signature and beside the point:
the admin token is minted and printed at first boot, before the port is
reachable, so it is exactly the credential a first-run POST can carry. On a
public deploy the window between the process listening and the operator's first
visit was one in which a stranger could name the org and open its join policy.

The route now takes the boot-printed `ORG_ADMIN_TOKEN` bearer (or a signed admin
member), through the same break-glass path the invite and join-policy routes
use, and is no longer declared self-signed. `GET /api/org/config` stays open —
the join page reads it before a visitor has any credential, and it discloses
only `{configured, profile}`. The installer never calls the POST (the profile
comes from the `ORG_*` variables), so an unattended first run is unchanged.

Guarded, each planted and observed reddening by name, the tree clean after each
revert: the handler's authorization removed (caught by the test that calls the
handler directly — the middleware gate alone would have hidden it); the route
re-declared self-signed so the middleware waves it through.
