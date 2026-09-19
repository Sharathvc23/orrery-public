### Fixed — an oversight decision made with the admin token names no approver

The break-glass admin token authenticates a shared secret rather than a person.
Both the approve and reject endpoints resolved the approver by falling back to
the org's own agent id when the caller carried none, so a decision made through
the token was recorded as having been approved by this org. The row was complete
and well-formed, and the name in it was invented; an auditor reading the ledger
had nothing to distinguish it from a decision a named member actually made.

Both endpoints now resolve the approver through one function, which records
`break-glass:unattributed` when the caller carries no identity. Member ids are
sanitised to a character set that excludes the colon, so no member can register
a name that collides with the sentinel.

The approval receipt follows the same distinction. On the break-glass path it
records no approver DID rather than resolving one, since the only DID available
is the org's own and recording it would repeat the false attribution one artefact
further on. The receipt summary names the token instead of a person.

`server/tests/test_break_glass_attribution.py` derives the check from the source:
any assignment to an approver that reaches for the org id fails the suite, as
does any decision endpoint that resolves an approver without the shared function,
so the fallback cannot return through a third endpoint added later.
