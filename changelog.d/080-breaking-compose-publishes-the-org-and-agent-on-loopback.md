### ⚠️ BREAKING — Compose publishes the org and agent on loopback

Compose published the org-server and local-agent ports without a host address.
Docker binds all interfaces in that case, so `docker compose up` exposed the org on
every interface of the host, including public ones. The printed URLs used
`localhost`, which did not reflect the binding.

`SERVER_BIND_HOST` and `AGENT_BIND_HOST` now default to `127.0.0.1`. The second org
used by the local end-to-end workflow is also bound to loopback. The documented AWS
load-balancer path sets an external bind explicitly.

**Migration.** To reach the org from another machine — a device on the same network,
or a reverse proxy on a different host — set `SERVER_BIND_HOST` (for example
`0.0.0.0`). Without it the org is reachable only from the host itself; the symptom
is a connection refused from the remote machine while local health checks pass.

`orrery-up` now distinguishes the address Compose binds from the address a local
client can reach: a wildcard bind is normalised before probing, IPv6 addresses are
bracketed in URLs, and local probes bypass any configured HTTP proxy.

On Docker Engine before 28, a host on the same layer-2 segment can still reach a
port published to `127.0.0.1`. On those versions, use host firewall rules as the
control.
