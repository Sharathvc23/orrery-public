### Fixed — agent state follows the configured home

An agent's stores did not all agree on where its home was. `COMMUNITY_MEMBER_HOME`
moved the config, identity, trust and skills state, but the A2A task log and the
settings cache used the literal `~/.nanda`, so every agent on a machine shared
one task log and one settings cache regardless of the home it was given. The
outbox likewise resolved to `~/.community-member` rather than the configured
home. The `.nanda` directory name is a convention shared with the sibling
member-SDK and is kept; what changes is where it is rooted, matching the
conformance badge, which already resolved it under the agent home.

Existing state is carried over rather than orphaned. On first use a legacy
`~/.nanda/tasks.jsonl` or `~/.nanda/settings.json` is copied to the new location
and the original is left in place as a backup; if a file already exists at the
new location it wins and the legacy copy is ignored. This mirrors the server's
`.nanda` to `.org` migration. Operators who never set `COMMUNITY_MEMBER_HOME`
are also affected, since the default home is `~/.community-member`.

These two paths now resolve when they are used rather than when the module is
imported, so a home set after import — by a test, a wizard, or an embedding
host — is honoured instead of being fixed to whatever was current at import.
