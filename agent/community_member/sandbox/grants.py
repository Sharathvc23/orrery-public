"""Where an operator writes capability grants.

The policy DSL in :mod:`community_member.sandbox.policy` had no reader: nothing
in the runtime called ``parse_policy``, so every executor ran with
``Policy(grants=())`` and every path, host, binary and origin was refused with
no way to permit one. This module is that reader.

The file is ``<CONFIG_DIR>/grants.policy``, one grant per line, ``#`` comments:

    # what the agent may reach in a browser, as origins
    browser.navigate:https://docs.example.com,https://*.wikipedia.org
    # what it may fetch over HTTP, as hostnames
    net.http:api.example.com
    fs.read:~/Downloads/**
    shell.exec:git,jq

A missing file means no grants, which means every capability is refused. That
is the default and it is deliberate: an action reaching an executor has already
passed the consent gate, and the policy is the second bound, so it opens only
what the operator has written down.

A malformed file is refused whole rather than partially applied. Skipping the
bad line and keeping the rest would silently apply a policy the operator did
not write.
"""

from __future__ import annotations

from pathlib import Path

from community_member.sandbox.policy import Policy, PolicyParseError, lint_policy, parse_policy

__all__ = [
    "GRANTS_FILENAME",
    "grant_line_for",
    "grant_line_for_origin",
    "grants_path",
    "lint_policy",
    "load_policy",
    "refusal_remedy",
]

GRANTS_FILENAME = "grants.policy"


def grants_path(config_dir: Path) -> Path:
    return Path(config_dir) / GRANTS_FILENAME


def load_policy(config_dir: Path) -> Policy:
    """Read the operator's grants. Returns an empty policy when none exist.

    Raises :class:`PolicyParseError` when the file exists and does not parse —
    the caller decides whether to refuse to start or to run with no grants, but
    it is never silently partial.
    """
    path = grants_path(config_dir)
    try:
        text = path.read_text()
    except (FileNotFoundError, NotADirectoryError):
        return Policy(grants=())
    try:
        return parse_policy(text)
    except PolicyParseError as e:
        raise PolicyParseError(f"{path}: {e}") from e


def grant_line_for(capability: str, target: str) -> str:
    """The grant line that would permit `target` for `capability`.

    `target` is whatever that capability matches on — an origin for browser.*,
    a hostname for net.http, a path for fs.*, a binary name for shell.exec.
    The caller supplies it because only the caller knows which of those it has.
    """
    return f"{capability}:{target}"


# Retained for callers written against the browser-only form.
grant_line_for_origin = grant_line_for


def refusal_remedy(capability: str, target: str, grants_file: Path | None = None) -> dict[str, str]:
    """The `extra` fields a policy refusal carries so it names its own fix.

    A denial that does not say what would have allowed it is how a
    deny-by-default policy earns a reputation for being unusable and gets
    turned off by the next person to hit it. Every policy-gated surface uses
    this, so the four of them cannot say four different things — and a fifth
    surface added later gets the same message by calling one function.

    `grants_file` defaults to the configured agent home, so a caller that does
    not track the path still names a real file.
    """
    grant = grant_line_for(capability, target)
    if grants_file is None:
        from community_member.config import CONFIG_DIR

        grants_file = grants_path(CONFIG_DIR)
    return {"required_grant": grant, "remedy": f"add {grant} to {grants_file}"}
