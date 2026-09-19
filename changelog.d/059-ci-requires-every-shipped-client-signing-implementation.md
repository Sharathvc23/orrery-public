### CI requires every shipped client-signing implementation

The client signing-conformance job now runs the existing five-check suite in
three separate processes: the executable specification, the OpenClaw Skill
helper, and the member SDK. Each CI invocation uses `--require-adapter`, so an
implementation that is absent or cannot import fails the job instead of
turning all five checks into skips. Optional local and downstream runs retain
the prior skip behavior when that flag is omitted.

This changes the release gate, not the signing contract: the five checks,
committed vectors, signing formats, and conformance-badge semantics are
unchanged. Three implementation runs do not constitute a new fifteen-check
badge or aggregate conformance claim.
