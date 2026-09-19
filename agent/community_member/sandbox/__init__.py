"""Capability sandbox — policy DSL + per-action match functions.

Foundation for W2 file / shell / net executors. A `Policy` is a list
of parsed `CapabilityGrant` objects; matching is performed by the
specific executor (path matching for fs.*, hostname for net.*,
binary name for shell.*).

See plans/yes-the-whole-point-humble-hopcroft.md §"Capability sandbox"
for the architectural intent.
"""

from community_member.sandbox.policy import (
    SUBSUMING_BINARIES,
    CapabilityGrant,
    Policy,
    PolicyParseError,
    host_pattern_matches,
    lint_policy,
    match_binary,
    match_host,
    match_origin,
    match_path,
    match_target,
    parse_grant,
    parse_policy,
    unpermitted_path_arguments,
)

__all__ = [
    "CapabilityGrant",
    "Policy",
    "PolicyParseError",
    "SUBSUMING_BINARIES",
    "lint_policy",
    "match_binary",
    "host_pattern_matches",
    "match_host",
    "match_origin",
    "match_path",
    "match_target",
    "parse_grant",
    "parse_policy",
    "unpermitted_path_arguments",
]
