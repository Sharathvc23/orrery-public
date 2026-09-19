### Fixed — capability grants are read from the agent's own home

`build_runners` loaded the grants file from the module-level `CONFIG_DIR`, which
is bound when the module is first imported. An agent whose home is configured
after that point — a second agent on one machine, or any process setting
`COMMUNITY_MEMBER_HOME` late — read grants from the wrong directory and named
the wrong file in its refusals. It now uses the home that agent was configured
with.
