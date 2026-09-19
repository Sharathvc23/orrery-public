### Fixed — a pinned Config home covers the consent ledger and the signing key

`Config(home=...)` documented that it pinned every store it touched. Three call
sites in `agent.py` read from the process-global home instead: both consent
ledger initialisations opened `consent.db` under it, and the A2A client
constructor loaded the agent's Ed25519 signing key without a per-instance
directory, so a pinned agent would sign with another's key or find none. All
three now resolve from the instance.

The comment on `Config.__init__` no longer claims complete isolation. It lists
the stores that follow a pinned home and the four that do not — the trust file,
the skills root and its registry, the channel inbox and the channel secrets —
and records that a second tenant in one process is therefore not yet safe to run.

A pinned skills root now keeps its own registry. `install_skill` accepted a
`skills_root` for the files while the registry functions read and wrote a single
process-global index, so two pinned roots shared one registry and an uninstall
against either removed the other's entries.

`agent/tests/test_pinned_home_is_followed.py` derives the import-time path
bindings from the package and classifies each one, so a binding added later
fails the suite until someone decides whether it should follow a pinned home.
The sweep asserts it finds the two bindings that motivated it, because a
detector that stops matching reports the same clean result as a clean codebase.
