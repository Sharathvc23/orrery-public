### Added — the think loop backs off when every action is refused

The capability policy refuses any action the operator has not granted. An
unattended agent with no grants therefore woke on its interval, called the
model, had every proposed action refused, and repeated — spending a model call
per cycle on a plan that could not run until something outside the loop changed.

A cycle in which every result was refused now widens the wait: 10s, 20s, 40s and
so on to a 10-minute ceiling, on the same curve the retryable-failure path and
the outbox already use, and never shorter than the configured interval. The
first cycle that is not entirely refused restores the configured interval
immediately, so writing a grant takes effect on the next wake rather than after
a backoff.

Actions awaiting a human are not refusals. An attended agent produces consent
prompts every cycle while it waits, and those cycles keep the configured pace.

The state is reported rather than silent: the per-cycle line names the refusal
and the next attempt, on the terminal and on the dashboard thought stream, so it
is distinguishable from a healthy quiet agent.
