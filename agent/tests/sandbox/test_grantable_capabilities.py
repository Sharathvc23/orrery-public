"""No capability can be granted in a form the matcher silently refuses.

Every matcher in `sandbox.policy` guards on a capability prefix — `fs.`,
`net.`, `desktop.`, `shell.`, `browser.` — and returns False for anything else.
A grant naming a capability outside those prefixes therefore parses, is stored
in the Policy, and matches nothing: the operator is told their grant was
accepted and it permits nothing.

This asserts the general form rather than the instance. Every capability the
executor knows about must either be matchable, or be listed in
`NOT_POLICY_GATED` with the reason it is not.
"""

from __future__ import annotations

import pytest

from community_member.executor import KNOWN_CAPABILITIES
from community_member.sandbox import (
    CapabilityGrant,
    Policy,
    PolicyParseError,
    match_binary,
    match_host,
    match_origin,
    match_path,
    match_target,
)

# Capabilities deliberately outside the Policy layer, each with its reason.
# An entry here is a claim that no Policy grant should be written for it.
NOT_POLICY_GATED: dict[str, str] = {
    "skill.invoke": (
        "Gated by skill_runtime's own per-skill capability grants "
        "(LocalAgent.skill_grants), not by sandbox.Policy. A Policy grant "
        "naming it would be the wrong mechanism."
    ),
}

# Every matcher, with the argument shape it takes. A capability is matchable if
# some matcher accepts a grant for it and can return True for some value.
_MATCHERS = (
    ("path", match_path, "/tmp/probe"),
    ("host", match_host, "probe.example"),
    ("binary", match_binary, "probe"),
    ("target", match_target, "probe"),
    ("origin", match_origin, "https://probe.example"),
)


def _matchers_accepting(capability: str) -> list[str]:
    """Which matchers will consider a grant for `capability` at all.

    A matcher that refuses on the capability prefix returns False for every
    pattern, including one built to match — that is the silent refusal.
    """
    accepting = []
    for name, matcher, sample in _MATCHERS:
        # A pattern that matches `sample` outright, so the only reason for a
        # False here is the prefix guard.
        grant = CapabilityGrant(capability=capability, patterns=(sample,))
        if matcher(grant, sample):
            accepting.append(name)
    return accepting


def test_every_known_capability_is_grantable_or_declared():
    silent: list[str] = []
    for capability in sorted(KNOWN_CAPABILITIES):
        if capability in NOT_POLICY_GATED:
            continue
        if not _matchers_accepting(capability):
            silent.append(capability)
    assert not silent, (
        f"grants for these capabilities parse and match nothing: {silent} — "
        "add a matcher, or list them in NOT_POLICY_GATED with the reason"
    )


def test_no_capability_is_matched_by_two_vocabularies():
    """One capability, one pattern language.

    `browser.navigate` matched by both the host and origin matchers would mean
    an operator could write either, with different security properties for the
    same line.
    """
    ambiguous = {
        capability: names
        for capability in sorted(KNOWN_CAPABILITIES)
        if capability not in NOT_POLICY_GATED and len(names := _matchers_accepting(capability)) > 1
    }
    assert not ambiguous, f"capabilities accepted by more than one matcher: {ambiguous}"


def test_every_declared_exemption_is_a_real_capability():
    """A reason attached to a capability that no longer exists is a stale claim."""
    unknown = sorted(set(NOT_POLICY_GATED) - set(KNOWN_CAPABILITIES))
    assert not unknown, f"NOT_POLICY_GATED names capabilities the executor does not know: {unknown}"


def test_every_declared_exemption_carries_a_reason():
    for capability, reason in NOT_POLICY_GATED.items():
        assert isinstance(reason, str) and len(reason.strip()) >= 40, (
            f"{capability} needs a reason a reviewer can weigh, not a placeholder"
        )


def test_an_exemption_is_not_a_way_to_hide_a_missing_matcher():
    """The exemption list only excuses capabilities that are genuinely gated
    elsewhere. If one of them becomes matchable, the entry is stale."""
    now_matchable = [c for c in NOT_POLICY_GATED if _matchers_accepting(c)]
    assert not now_matchable, (
        f"{now_matchable} now has a matcher — remove it from NOT_POLICY_GATED so the grant is checked"
    )


@pytest.mark.parametrize("capability", sorted(KNOWN_CAPABILITIES))
def test_a_policy_grant_is_never_silently_inert(capability):
    """Per-capability form of the same property, so a failure names the one
    that broke rather than a list."""
    if capability in NOT_POLICY_GATED:
        pytest.skip(NOT_POLICY_GATED[capability])
    assert _matchers_accepting(capability), f"a grant for {capability} would parse and match nothing"


def test_a_browser_grant_without_a_scheme_is_refused_at_parse_time():
    """The other end of the same defect: the grant an operator is most likely
    to write by analogy with net.http must not be silently stored."""
    from community_member.sandbox import parse_grant

    with pytest.raises(PolicyParseError) as e:
        parse_grant("browser.navigate:example.com")
    assert "scheme" in str(e.value)


def test_an_empty_policy_permits_nothing():
    """The default every executor starts from."""
    empty = Policy(grants=())
    assert not empty.allows_origin("browser.navigate", "https://example.com")
    assert not empty.allows_host("net.http", "example.com")
    assert not empty.allows_path("fs.read", "/tmp/x")
    assert not empty.allows_binary("shell.exec", "ls")
