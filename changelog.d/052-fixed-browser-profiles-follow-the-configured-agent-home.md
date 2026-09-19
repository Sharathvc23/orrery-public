### Fixed — browser profiles follow the configured agent home

`BrowserExecutor.browser_state_root` was rooted at `Path.home()` and ignored
`COMMUNITY_MEMBER_HOME`, so a second agent or a test run wrote Chromium profile
directories into the invoking user's real agent home. It now derives from
`CONFIG_DIR`. On a default install both resolve to the same path.
