"""Action executors — drivers the agent uses to take real actions on the device.

Every executor shares the same contract: produce a structured
`ActionRequest`, run it through `consent.gate`, and either raise
`ConsentRequired` (when the user must be prompted) or execute against
the appropriate OS/browser/sandbox layer and return a `ActionResult`.

An `ActionResult` carries a `provenance` tag on any extracted data —
web-page text is `untrusted`, shell stdout is `untrusted`, chapter
RPC results are `semi_trusted`, the user's own input is `trusted`.
These tags propagate back through the planner when the result feeds
into the next decision, so prompt-injected content never gets
re-wrapped as `trusted`.

No executor in W1 may execute an action without a valid recent user
approval — the gate's `approved` state is unreachable until W4
graduation lands. See plans/yes-the-whole-point-humble-hopcroft.md.
"""

from community_member.actions.browser import BrowserExecutor
from community_member.actions.files import FilesExecutor
from community_member.actions.net import NetExecutor
from community_member.actions.shell import ShellExecutor
from community_member.actions.types import ActionResult

__all__ = [
    "ActionResult",
    "BrowserExecutor",
    "FilesExecutor",
    "NetExecutor",
    "ShellExecutor",
]
