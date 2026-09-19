"""Remove member handles from agent-authored prose.

``agent_thoughts.thought_text`` is a sentence the agent wrote, and
``think_conversation`` composes it one ``"@{speaker}: {text}"`` line per turn —
so a member handle sits inside the prose rather than in a column that could be
dropped from a ``select``. ``surfaces.build_activity_surface`` serves that
column to anonymous callers.

⚠️ THIS IS APPLIED IN TWO PLACES ON PURPOSE, AND THEY ARE NOT REDUNDANT.

  AT WRITE, in ``chapter_helpers.log_agent_thought`` — the durable one. Data at
  rest that never carried the handle cannot be leaked by a surface added next
  year, and read-time filtering in N places is precisely the pattern that
  produced this: ``/api/thoughts`` had a filter, ``build_activity_surface``
  did not, and nothing detected the difference.

  AT READ, in ``build_activity_surface`` — the stopgap, and the only thing that
  covers the rows ALREADY WRITTEN. Write-time redaction protects nothing
  retroactively. Removing this read-side call would re-expose every historical
  row, so it stays until a backfill has run and been verified, not until the
  write-side ships.

⚠️ WHAT THIS IS NOT. It is not ``_mentions_hidden``. That filter tests
``any(p in body for p in ("TEST-",))``, which catches a seeded test account and
lets ``@priya-sharma-12`` through — so applying it to another surface would
produce a leak with a filter in front of it, which is worse than an unfiltered
one because the next reader stops looking.

OVER-REDACTING IS ITS OWN DEFECT. A feed rendered unreadable is a feed someone
removes the redaction from. An ``@`` inside a word — an email address — is not
a handle and is left alone, and the replacement marker is visible so a reader
can tell that redaction happened rather than assuming the agent wrote it that
way.
"""

from __future__ import annotations

import re

__all__ = [
    "HANDLE_RE",
    "REDACTED",
    "contains_handle",
    "redact_deep",
    "redact_handles",
    "redact_suggested_speakers",
]

#: What replaces a handle. Visible on purpose: a handle that silently vanished
#: reads as prose the agent composed, and a reader cannot tell a redacted feed
#: from a confusing one.
REDACTED = "@[member]"

#: A handle is an ``@`` at a word boundary followed by the identifier charset
#: agent ids use. The leading ``(?<![\w@.])`` is what keeps an email address
#: intact: in ``ann@example.com`` the ``@`` is preceded by a word character, so
#: it is not a handle. Without that guard this would mangle every address in
#: every thought, which is the kind of collateral damage that gets a redaction
#: reverted rather than fixed.
HANDLE_RE = re.compile(r"(?<![\w@.])@([A-Za-z0-9][A-Za-z0-9._-]{0,63})")


def redact_handles(text: str | None) -> str:
    """Prose with every ``@handle`` replaced by :data:`REDACTED`.

    ``None`` becomes an empty string rather than raising: this sits on the
    write path of every thought, and a redactor that can throw is a redactor
    that gets wrapped in a bare ``except`` and stops running.
    """
    if not text:
        return ""
    return HANDLE_RE.sub(REDACTED, text)


def contains_handle(text: str | None) -> bool:
    """Whether ``text`` carries anything this module would redact.

    Exists so a count or an audit asks the same question the redactor answers.
    A separate expression for "does it leak" and "what do we remove" is how the
    two drift apart.
    """
    if not text:
        return False
    return HANDLE_RE.search(text) is not None


def redact_deep(value: object) -> object:
    """Redact handles in every string inside a nested structure.

    ``agent_thoughts.a2ui_surface`` is a stored card, and its titles are built
    as ``f"@{agent_id} thinks"`` and ``f"@{agent_id} (sovereign)"``. Routes that
    return a whole row therefore ship handles in a field no ``thought_text``
    filter inspects — the same leak one column across, which is the shape that
    produced this one.

    Walks dicts, lists and tuples; leaves every non-string leaf alone. Keys are
    NOT rewritten: a key is a schema name, and rewriting one would change the
    document's shape rather than redact its contents.
    """
    if isinstance(value, str):
        return redact_handles(value)
    if isinstance(value, dict):
        return {k: redact_deep(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_deep(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_deep(v) for v in value)
    return value


def redact_suggested_speakers(events: list[dict]) -> list[dict]:
    """Drop ``suggested_speakers`` (member display names) from event rows.

    ``think_cycle.propose_event`` prompts the LLM with real member names
    ("Some members: ...") and asks it to name specific ones as
    ``suggested_speakers``; the LLM's JSON reply is persisted verbatim into
    ``agent_events`` and served to anyone by ``GET /api/events`` and its A2UI
    twin ``GET /api/surfaces/events`` — both CORS-declared keyless-public by
    design, so neither can be closed behind auth without breaking that
    contract. Dropping the one structured field the prompt explicitly asked
    to be filled with member names closes the leak without touching either
    surface's public posture.

    Applied at read time in both places independently: the column itself is
    untouched (a future internal, non-public consumer can still read it from
    the row directly), this only controls what the two anonymous-facing
    surfaces are allowed to re-publish.
    """
    return [{k: v for k, v in ev.items() if k != "suggested_speakers"} for ev in events]
