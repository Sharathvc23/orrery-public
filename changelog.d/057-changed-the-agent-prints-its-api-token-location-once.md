### Changed — the agent prints its API token location once

`community-member` printed the path of `.local-token` on every start. It now
prints it only on the start that generated the file, matching how the org
server surfaces its admin token. The token value is not printed at any point.
