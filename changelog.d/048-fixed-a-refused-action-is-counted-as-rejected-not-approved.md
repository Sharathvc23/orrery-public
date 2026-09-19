### Fixed — a refused action is counted as rejected, not approved

`make_think_outcome` classified each result by what the consent gate decided.
That was the same fact as what happened to the action while the gate was the
only bound that could refuse it. It stopped being the same fact when the sandbox
policy began refusing after the gate had approved: such a result carried
`decision.state == "approved"` and an output reporting `denied`, and was counted
as approved. The agent's per-cycle summary — the only consumer of these buckets
— therefore reported a navigation that never happened as `approved=1`.

Classification now reads the outcome the runner reported and falls back to the
gate's decision only where there is no outcome. The refusing outcomes are named
in `executor.REFUSED_OUTCOMES` rather than special-cased by reason, so a bound
that refuses for a new reason is covered without changing the classifier.

This is the same defect as several others in this release: a reader that cannot
distinguish a refusal from a success, a failure, or an absence.

`make_think_outcome`'s docstring described the partition as "the contract the
tray UI relies on". No such consumer exists in this repository; the docstring
now names the one that does.
