### Fixed — the think interval is honoured on both entry points

`COMMUNITY_MEMBER_THINK_INTERVAL` was read by the container entrypoint and
ignored by the `community-member` command, which hardcoded 300 seconds. An
operator who set it on the path the setup wizard produces got no effect and no
indication why. Both now read it through one helper, so the two cannot diverge
again, and a value that is not a positive integer falls back to the default
rather than busy-looping or crashing the loop.
