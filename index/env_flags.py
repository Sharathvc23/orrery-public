"""Parsing for environment variables that gate SECURITY behaviour (index copy).

Byte-identical in contract to ``server/env_flags.py``. The lean index is a
separate deployable with no import path into ``server/``, so the choice is a
copy or a shared package; a ~20-line pure function is the cheaper of the two and
``index/test_main.py`` pins its behaviour independently. If this ever diverges
from the server copy, the server copy is canonical.

Original module docstring follows.

Parsing for environment variables that gate SECURITY behaviour.

Four separate incidents have now had the same shape: a security-relevant flag is
parsed inline as ``os.environ.get(NAME, "").strip().lower() in {"1","true",...}``,
which silently makes *absent* mean *permissive*.

  1. ``REGISTRY_URL=`` (empty) meant LIVE PRODUCTION — 31 phantom records.
  2. ``AUTO_REGISTER=false`` was read by no server code at all.
  3. ``strength_map`` silently inherited an unowned default.
  4. ``FEDERATION_ENFORCE_SIGNED_BROADCASTS`` defaulted to OFF while
     ``.env.example`` advertised ``true`` (C9, AUDIT_HARSH.md).

The inline form has no place to record which direction the flag should fail, so
"unset" lands in whichever branch the expression happens to produce. This module
makes the direction an explicit, required argument.

``security_flag`` deliberately treats THREE inputs as "the operator did not
decide": unset, empty/whitespace, and unrecognised. All three return ``default``.

Unrecognised mapping to ``default`` rather than ``False`` is the load-bearing
choice: ``FEDERATION_ENFORCE_SIGNED_BROADCASTS=ture`` is a typo, not a decision
to disable enforcement, and the inline form would have read it as one. A flag
whose default is ``True`` therefore cannot be turned off by accident — only by
an explicitly recognised falsey spelling.
"""

from __future__ import annotations

import os

# Recognised spellings. Anything outside both sets is "not a decision".
TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def security_flag(name: str, *, default: bool) -> bool:
    """Read a boolean env var that gates a security behaviour.

    ``default`` is keyword-only and mandatory: the direction a flag fails when
    nobody set it is a security decision, so it has to be written down at the
    call site rather than emerging from the parsing expression.

    Unset, empty, whitespace-only and unrecognised values are all indistinguishable
    from "the operator did not decide" and return ``default``. Only an explicitly
    recognised spelling overrides it.
    """
    raw = os.environ.get(name, "").strip().lower()
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    return default
