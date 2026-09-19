"""Capability policy DSL — parse, store, and match capability grants.

A capability grant is a string like:

  fs.read:~/Downloads/**
  fs.write:~/Documents/notes/*.md,~/Downloads/agent/*
  browser.navigate:https://docs.example.com,https://*.wikipedia.org
  net.http:docs.example.com,api.example.com,*.openai.com
  shell.exec:<binary>

The grant type is the dotted capability. The comma-separated payload
is a list of PATTERNS whose interpretation depends on the capability:

  fs.*       → glob pattern over resolved absolute paths
               (leading ~ expanded; symlinks resolved by caller;
               then matched via fnmatch with '**' wildcard support)
  net.http   → hostname patterns, either exact match or single
               leading wildcard '*.example.com' that matches any
               subdomain (but not parent)
  browser.*  → ORIGIN patterns: scheme required, port optional and
               defaulted from the scheme, host component using the
               same wildcard as net.http. 'https://*.example.com'.
               Origins rather than hostnames because this capability
               drives a persistent browser profile holding cookies, so
               a hostname grant would also authorise the cleartext
               scheme for the same host. A browser grant written as a
               bare hostname is refused by parse_grant rather than
               stored and silently unmatched.
  shell.exec → BINARY NAMES (basename only). The grant itself does
               not describe arguments; the executor narrows them
               against the fs.* grants at run time
               (unpermitted_path_arguments), refusing an argument that
               names an existing file no fs.* grant covers. That is
               ONE shape and not a bound on the binary — see below.
               ⚠ THE CAPABILITIES DO NOT COMPOSE THE WAY THEIR NAMES
               SUGGEST. Because arguments are unconstrained, a shell
               grant can permit what another capability's grant was
               written to bound. shell.exec:awk refuses
               awk '{print}' /etc/shadow, where the path is an
               argument, and runs awk 'BEGIN{getline < "/etc/shadow"}',
               where it is inside the program — same binary, same
               grants. shell.exec:curl reaches any host regardless of
               net.http, because a host is not a path. SUBSUMING_BINARIES below names the binaries
               this applies to, and lint_policy reports them at load
               time — but it is NOT EXHAUSTIVE, so no warning is not a
               safety claim. No binary is named in the example above
               because there is no narrow choice to recommend: git
               looks like one and runs any command through a config
               alias or a repository hook.

Module is pure: no I/O, no globals except for parse errors. Callers
(actions/files.py, actions/shell.py, etc.) do the actual
filesystem/network/process interaction and invoke match_* here.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "CapabilityGrant",
    "Policy",
    "PolicyParseError",
    "SUBSUMING_BINARIES",
    "lint_policy",
    "match_binary",
    "unpermitted_path_arguments",
    "host_pattern_matches",
    "match_host",
    "match_origin",
    "match_path",
    "match_target",
    "parse_grant",
    "parse_policy",
]


class PolicyParseError(ValueError):
    """Malformed capability grant string."""


@dataclass(frozen=True)
class CapabilityGrant:
    """Parsed representation of one grant.

    `patterns` is a tuple of the raw pattern strings — interpretation
    happens at match time (match_path / match_host / match_binary).
    """

    capability: str
    patterns: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    """A set of capability grants.

    Multiple grants for the same capability are allowed and cumulative:
    `grants_for("fs.read")` returns all of them; `match_path` tries each.
    """

    grants: tuple[CapabilityGrant, ...]

    def grants_for(self, capability: str) -> tuple[CapabilityGrant, ...]:
        return tuple(g for g in self.grants if g.capability == capability)

    def allows_path(self, capability: str, path: str | Path) -> bool:
        return any(match_path(g, path) for g in self.grants_for(capability))

    def allows_host(self, capability: str, hostname: str) -> bool:
        return any(match_host(g, hostname) for g in self.grants_for(capability))

    def allows_binary(self, capability: str, binary: str) -> bool:
        return any(match_binary(g, binary) for g in self.grants_for(capability))

    def allows_target(self, capability: str, target: str) -> bool:
        return any(match_target(g, target) for g in self.grants_for(capability))

    def allows_origin(self, capability: str, origin: str) -> bool:
        return any(match_origin(g, origin) for g in self.grants_for(capability))


# ── Composition: which shell grants subsume another capability ─────
#
# shell.exec constrains WHICH binary runs and nothing about its arguments, so
# a grant for a binary that takes a path or a URL permits whatever that binary
# does to any path or any URL. The narrower grant elsewhere in the policy is
# not consulted and does not bound it.
#
# One place, with the reason attached, because three readers need it: the
# module docstring points at it, lint_policy reports from it, and the shipped
# example file explains itself in its terms. Adding a binary here is the way to
# extend the warning; there is no second list.
#
# Only binaries whose ORDINARY, documented use reads a path, reaches a host or
# runs another program are listed. THIS IS NOT AND CANNOT BE EXHAUSTIVE —
# the only argument the executor narrows is one naming an existing file, so a
# binary that takes a host, a program, or a path it creates is unconstrained,
# and that is true of almost any useful binary. The list names the cases an operator reaches for as
# a convenience without expecting to widen anything. Absence from it means
# unassessed, never safe; lint_policy's docstring says so to the reader who
# sees only the warnings.
SUBSUMING_BINARIES: dict[str, tuple[frozenset[str], str]] = {
    # Read any path given as an argument.
    "cat": (frozenset({"fs.read"}), "prints any file given as an argument"),
    "grep": (frozenset({"fs.read"}), "reads any file it is pointed at, and -f takes a pattern file"),
    "head": (frozenset({"fs.read"}), "reads any file it is pointed at, and -f takes a pattern file"),
    "tail": (frozenset({"fs.read"}), "reads any file it is pointed at, and -f takes a pattern file"),
    "less": (frozenset({"fs.read"}), "reads any file it is pointed at, and -f takes a pattern file"),
    "jq": (frozenset({"fs.read"}), "reads any file it is pointed at, and -f takes a pattern file"),
    "awk": (frozenset({"fs.read", "fs.write"}), "reads and writes any file given as an argument"),
    "sed": (frozenset({"fs.read", "fs.write"}), "reads, and with -i rewrites, any file given as an argument"),
    "cp": (frozenset({"fs.read", "fs.write"}), "copies any path to any path"),
    "mv": (frozenset({"fs.read", "fs.write"}), "moves any path to any path"),
    "tee": (frozenset({"fs.write"}), "writes any file given as an argument"),
    "rm": (frozenset({"fs.write"}), "deletes any path given as an argument"),
    # Reach any host given as an argument.
    "curl": (frozenset({"net.http", "fs.write"}), "fetches any URL, and writes the response to any path"),
    "wget": (frozenset({"net.http", "fs.write"}), "fetches any URL, and writes the response to any path"),
    "ssh": (frozenset({"net.http"}), "connects to any host given as an argument"),
    "nc": (frozenset({"net.http"}), "connects to any host and port given as arguments"),
    # Run anything at all, which subsumes the binary allowlist itself.
    "sh": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs any command, including binaries not granted",
    ),
    "bash": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs any command, including binaries not granted",
    ),
    "zsh": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs any command, including binaries not granted",
    ),
    "env": (frozenset({"shell.exec"}), "runs any binary given as an argument"),
    "xargs": (frozenset({"shell.exec"}), "runs any binary given as an argument"),
    "find": (frozenset({"fs.read", "shell.exec"}), "reads any directory, and -exec runs any binary"),
    "python": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs arbitrary code, so reads, writes and network calls are all unbounded",
    ),
    "python3": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs arbitrary code, so reads, writes and network calls are all unbounded",
    ),
    "perl": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs arbitrary code, so reads, writes and network calls are all unbounded",
    ),
    "ruby": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs arbitrary code, so reads, writes and network calls are all unbounded",
    ),
    "node": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs arbitrary code, so reads, writes and network calls are all unbounded",
    ),
    # Run other programs by design or by configuration.
    "git": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs any command through a config alias, core.pager, core.sshCommand or a repository hook",
    ),
    "make": (frozenset({"fs.read", "fs.write", "shell.exec"}), "runs the commands in any makefile it is given"),
    "tar": (frozenset({"fs.read", "fs.write"}), "reads and writes any path, and --to-command runs a program"),
    "docker": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs a container that can mount any path and reach any host",
    ),
    "sudo": (frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}), "runs any command, with elevated rights"),
    "su": (frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}), "runs any command as another user"),
    "busybox": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "provides a shell and most of the coreutils under one binary name",
    ),
    "vi": (frozenset({"fs.read", "fs.write", "shell.exec"}), "edits any file, and its shell escape runs any command"),
    "vim": (frozenset({"fs.read", "fs.write", "shell.exec"}), "edits any file, and its shell escape runs any command"),
    "more": (frozenset({"fs.read", "shell.exec"}), "reads any file, and its shell escape runs any command"),
    "php": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs arbitrary code, so reads, writes and network calls are all unbounded",
    ),
    "lua": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs arbitrary code, so reads, writes and network calls are all unbounded",
    ),
    "deno": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs arbitrary code, so reads, writes and network calls are all unbounded",
    ),
    "bun": (
        frozenset({"fs.read", "fs.write", "net.http", "shell.exec"}),
        "runs arbitrary code, so reads, writes and network calls are all unbounded",
    ),
}


def lint_policy(policy: Policy) -> list[str]:
    """Warnings about grants that permit more than their capability suggests.

    Returns one line per subsuming shell binary, naming what it permits and —
    when the policy also carries a narrower grant of the capability it
    subsumes — that the narrower grant does not bound it.

    Warnings, never refusals: the operator may mean it, and a policy layer that
    refuses the operator's own choice has stopped being a policy layer. Pure;
    the caller decides where the lines go.

    THE ABSENCE OF A WARNING IS NOT A SAFETY CLAIM. SUBSUMING_BINARIES names
    the binaries known to subsume another capability. It is NOT EXHAUSTIVE and
    cannot be. The executor narrows exactly one shape of argument — one naming
    an existing file outside the fs.* grants — and nothing else: not a host,
    not a path inside a program string, not a file the command creates. So the
    property this warns about is still true of almost any binary that takes a
    host or a command as an argument. What escapes the list has a shape worth seeing —

      * an interpreter not listed here (a newer runtime, a language we have
        not thought of) runs arbitrary code exactly as python does;
      * a binary installed under a different name, or a local script, matches
        nothing here because matching is on the basename;
      * a tool whose subsuming behaviour is a documented flag rather than its
        main purpose, the way tar --to-command is.

    So a shell grant this returns nothing for has not been assessed. It has
    not been cleared.
    """
    warnings: list[str] = []
    for grant in policy.grants:
        if not grant.capability.startswith("shell."):
            continue
        for pattern in grant.patterns:
            entry = SUBSUMING_BINARIES.get(os.path.basename(pattern.strip()).lower())
            if entry is None:
                continue
            subsumes, reason = entry
            line = f"{grant.capability}:{pattern} {reason}"
            narrowed = sorted(
                cap for cap in subsumes if cap != grant.capability and any(g.capability == cap for g in policy.grants)
            )
            if narrowed:
                line += f" — wider than your {', '.join(narrowed)} grant" + ("s" if len(narrowed) > 1 else "")
            else:
                line += f" — unbounded by any {', '.join(sorted(subsumes))} pattern"
            warnings.append(line)
    return warnings


# ── Narrowing shell arguments against the file grants ──────────────
#
# ⚠ THIS IS A NARROWING, NOT A BOUND, and the distinction is the whole point.
#
# shell.exec grants a binary and cannot constrain what that binary does. What
# CAN be checked is one specific, common shape: an argument that names a file
# the policy does not permit. `grep SECRET /etc/shadow` is refused; the class of
# accidental over-reach where a planner proposes a granted binary against a path
# outside the file grants is closed.
#
# WHAT IT DOES NOT REACH, measured rather than supposed:
#
#   awk '{print}' /secret                      -> REFUSED (path is an argument)
#   awk 'BEGIN{getline < "/secret"}'           -> ALLOWED (path is in a program)
#
# Same binary, same grant, opposite outcomes. Coverage is per-INVOCATION, not
# per-binary, so an operator cannot learn a rule that tells them which of their
# commands are narrowed. Anything that takes a program as an argument escapes
# entirely — python -c, sh -c, sed -e, find -exec — as does any host (curl takes
# a URL, not a path) and any file that does not exist yet (a write target).
#
# Closing the property properly needs the CHILD PROCESS contained rather than
# its arguments inspected: Landlock on Linux bounds the filesystem from ABI v1
# and the network only from v4, and there is no equivalent on macOS or Windows.
# Until that exists this is a narrowing, and calling it a bound would be the
# defect it is trying to reduce.
_FS_GRANT_CAPABILITIES = ("fs.read", "fs.write")


def unpermitted_path_arguments(policy: Policy, args: Sequence[str], *, cwd: Path) -> list[str]:
    """Arguments naming an existing path that no fs.* grant covers.

    Resolution is against `cwd` — pinned by the caller, because a relative
    argument means nothing without one — and follows symlinks, so a link into
    an ungranted tree is judged by its target.

    An argument that does not resolve to an existing path is NOT returned: it
    may be a pattern, a flag, or a file about to be created, and this cannot
    tell those apart without the argument grammar we are deliberately not
    building. Returning nothing therefore means "nothing recognisable here",
    never "this invocation is bounded".
    """
    offenders: list[str] = []
    for arg in args:
        text = str(arg)
        if not text or text.startswith("-"):
            continue
        candidate = Path(os.path.expanduser(text))
        if not candidate.is_absolute():
            candidate = Path(cwd) / candidate
        try:
            resolved = candidate.resolve()
            if not resolved.exists():
                continue
        except OSError:
            continue
        if not any(policy.allows_path(cap, resolved) for cap in _FS_GRANT_CAPABILITIES):
            offenders.append(text)
    return offenders


# ── Parsing ───────────────────────────────────────────────────────


def parse_grant(s: str) -> CapabilityGrant:
    """Parse one grant string. Raises PolicyParseError on malformed input.

    Format: 'capability:pattern1,pattern2,...'
      - capability must be non-empty and contain at least one '.'
      - patterns must be non-empty after stripping
      - at least one pattern required
    """
    if not isinstance(s, str) or not s:
        raise PolicyParseError("grant must be a non-empty string")
    if ":" not in s:
        raise PolicyParseError(f"grant {s!r} missing ':' — expected 'cap:pattern'")
    cap_raw, _, payload = s.partition(":")
    cap = cap_raw.strip()
    if not cap:
        raise PolicyParseError(f"grant {s!r} has empty capability")
    if "." not in cap:
        raise PolicyParseError(f"grant {s!r} capability {cap!r} must be dotted (e.g. 'fs.read')")
    patterns = tuple(p.strip() for p in payload.split(",") if p.strip())
    if not patterns:
        raise PolicyParseError(f"grant {s!r} has no patterns")
    if cap.startswith("browser."):
        # Caught here rather than at match time: a browser grant written as a
        # bare hostname would parse and then match nothing, which is the
        # failure this module is being changed to make impossible.
        for pattern in patterns:
            if _split_origin(pattern) is None:
                raise PolicyParseError(
                    f"grant {s!r} pattern {pattern!r} must be an origin with a scheme "
                    f"(for example 'https://example.com' or 'https://*.example.com')"
                )
    return CapabilityGrant(capability=cap, patterns=patterns)


def parse_policy(lines: list[str] | str) -> Policy:
    """Parse a multi-grant policy.

    Accepts either a list of grant strings or a single newline/semicolon-
    separated blob. Empty/whitespace-only lines are skipped; '#' begins
    a comment that runs to end-of-line.
    """
    if isinstance(lines, str):
        lines = [lines]
    flat: list[str] = []
    for chunk in lines:
        for line in chunk.splitlines():
            # Comments are stripped BEFORE ';' is treated as a separator.
            # The other order split a comment containing a semicolon, and its
            # tail was then parsed as a grant — so one stray ';' in a comment
            # made the whole file unparseable, which (grants being all-or-
            # nothing) refused every action on the install.
            code = line.split("#", 1)[0]
            for part in code.split(";"):
                stripped = part.strip()
                if stripped:
                    flat.append(stripped)
    grants = tuple(parse_grant(line) for line in flat)
    return Policy(grants=grants)


# ── Matching: paths ────────────────────────────────────────────────


def _resolve(path: str | Path) -> Path:
    """Expand ~ + make absolute. Does NOT follow symlinks — caller is
    responsible for that, so symlink-race tests can pass a pre-resolved
    Path and get the same result."""
    p = Path(os.path.expanduser(str(path)))
    return p if p.is_absolute() else Path.cwd() / p


def match_path(grant: CapabilityGrant, path: str | Path) -> bool:
    """Return True iff `path` matches any pattern in a fs.* grant.

    Supports '**' as a multi-level glob via fnmatch.translate with a
    manual adjustment: fnmatch treats '**' like '*', which is wrong for
    path globs. We split on '/' and match segment-by-segment with
    special handling for '**' (matches any number of path segments).
    """
    if not grant.capability.startswith("fs."):
        return False
    resolved = _resolve(path)
    for pattern in grant.patterns:
        if _glob_match(pattern, str(resolved)):
            return True
    return False


def _glob_match(pattern: str, path: str) -> bool:
    """Path-aware glob with '**' support.

    ** matches zero or more path segments. * matches within a single
    segment. Patterns are expanded for '~' and made absolute using
    cwd — same as _resolve so the comparison is apples-to-apples.
    """
    pattern = str(_resolve(pattern))

    # Split both into segments for segment-aware comparison.
    pat_parts = pattern.split(os.sep)
    path_parts = path.split(os.sep)
    return _match_parts(pat_parts, path_parts)


def _match_parts(pat: list[str], path: list[str]) -> bool:
    # Base cases.
    if not pat and not path:
        return True
    if not pat:
        return False
    if pat[0] == "**":
        # ** matches zero or more segments. Try consuming 0, 1, 2, ...
        # segments from path and see if the rest matches.
        for i in range(len(path) + 1):
            if _match_parts(pat[1:], path[i:]):
                return True
        return False
    if not path:
        return False
    if fnmatch.fnmatchcase(path[0], pat[0]):
        return _match_parts(pat[1:], path[1:])
    return False


# ── Matching: hostnames ────────────────────────────────────────────


def host_pattern_matches(pattern: str, hostname: str) -> bool:
    """Return True iff `hostname` matches one host pattern.

    Case-insensitive. '*.example.com' matches 'a.example.com' and
    'a.b.example.com' but NOT 'example.com' — the wildcard requires at least
    one subdomain label.

    The single definition of host-wildcard semantics. `match_host` and
    `match_origin` both call it so the two cannot drift apart.
    """
    hn = hostname.lower()
    pat = pattern.lower()
    if pat.startswith("*."):
        suffix = pat[1:]  # ".example.com"
        return hn.endswith(suffix) and len(hn) > len(suffix)
    return pat == hn


def match_host(grant: CapabilityGrant, hostname: str) -> bool:
    """Return True iff `hostname` matches any pattern in a net.* grant."""
    if not grant.capability.startswith("net."):
        return False
    return any(host_pattern_matches(p, hostname) for p in grant.patterns)


# ── Matching: origins ──────────────────────────────────────────────

# Ports a scheme implies, so 'https://x.example' and 'https://x.example:443'
# are the same origin to the policy. The consent gate does not normalise this
# — `_origin_of` returns whatever the URL carried — so the two differ there and
# need separate approvals. Normalising the gate changes which stored approvals
# match and is a separate decision; the policy normalises so that a grant an
# operator writes without a port still covers the explicit-port form.
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _split_origin(value: str) -> tuple[str, str, int] | None:
    """Split 'scheme://host[:port]' into (scheme, host, port). None if it is
    not a well-formed origin or its scheme implies no default port."""
    scheme, sep, rest = value.strip().lower().partition("://")
    if not sep or not scheme or not rest:
        return None
    host, colon, port_raw = rest.partition(":")
    if not host or "/" in rest:
        return None
    if colon:
        try:
            port = int(port_raw)
        except ValueError:
            return None
    elif scheme in _DEFAULT_PORTS:
        port = _DEFAULT_PORTS[scheme]
    else:
        return None
    return scheme, host, port


def match_origin(grant: CapabilityGrant, origin: str) -> bool:
    """Return True iff `origin` matches any pattern in a browser.* grant.

    Patterns are origins, not hostnames: 'https://*.example.com'. The scheme
    is required and matched exactly, because this capability drives a
    persistent browser profile carrying the agent's cookies — a hostname
    grant would also authorise the cleartext scheme for the same host. The
    port is optional and defaults from the scheme. The host component uses
    :func:`host_pattern_matches`, the same wildcard the net.* matcher uses.
    """
    if not grant.capability.startswith("browser."):
        return False
    target = _split_origin(origin)
    if target is None:
        return False
    t_scheme, t_host, t_port = target
    for pattern in grant.patterns:
        parsed = _split_origin(pattern)
        if parsed is None:
            # A hostname-shaped pattern for a browser grant is refused rather
            # than matched loosely; parse_grant rejects it at read time so
            # this is only reachable for a hand-built CapabilityGrant.
            continue
        p_scheme, p_host, p_port = parsed
        if p_scheme == t_scheme and p_port == t_port and host_pattern_matches(p_host, t_host):
            return True
    return False


# ── Matching: shell binaries ──────────────────────────────────────


# ── Matching: desktop targets ─────────────────────────────────────


def match_target(grant: CapabilityGrant, target: str) -> bool:
    """Return True iff `target` matches a pattern in a desktop.* grant.

    `target` is a window title, application bundle id, or accessibility
    role identifier — whatever the caller normalised. Patterns are
    fnmatch-style, case-insensitive (window titles and bundle ids are
    routinely mixed-case). An empty target never matches.
    """
    if not grant.capability.startswith("desktop."):
        return False
    if not target:
        return False
    t = target.lower()
    for pattern in grant.patterns:
        if fnmatch.fnmatchcase(t, pattern.lower()):
            return True
    return False


def match_binary(grant: CapabilityGrant, binary: str) -> bool:
    """Return True iff `binary` (basename) is in a shell.* grant.

    We match on the basename, not the full path, because a user who
    grants `shell.exec:grep` means "any grep on $PATH" — they don't
    want to distinguish /usr/bin/grep from /usr/local/bin/grep. If a
    caller wants stricter pinning they can pass an absolute path and
    the match will simply fail (grants don't contain slashes by
    convention).
    """
    if not grant.capability.startswith("shell."):
        return False
    base = os.path.basename(binary.strip())
    if not base:
        return False
    for pattern in grant.patterns:
        if pattern == base:
            return True
    return False
