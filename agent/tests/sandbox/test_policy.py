"""Tests for community_member.sandbox.policy — capability DSL + matchers.

Coverage:

  R1  Forgery — malformed grant strings caught (no partial/silent parse)
  R3  Injection — shell metacharacters in grant patterns are data, not
      code; paths with '..' traversal don't match outer roots
  R4  Authz — a grant for fs.read doesn't accidentally authorize fs.write
  R5  Boundary — '*.example.com' matches subdomain but NOT bare domain
  R7  Adversarial — attacker-controlled hostnames / paths get no
      unintended match; '**' glob doesn't spill into parent dir
  R9  Timing — parse + match are pure (no globals, no I/O)
  R10 Persistence — parse_policy round-trips stable; multi-line + comments
      + semicolons all supported

  S6  Egress allowlist — net.http:docs.example.com blocks evil.example,
      the path that un-skips S6 in the companion executor PR
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member.sandbox import policy

# ── parse_grant ───────────────────────────────────────────────────


def test_parse_grant_basic():
    g = policy.parse_grant("fs.read:~/Downloads/**")
    assert g.capability == "fs.read"
    assert g.patterns == ("~/Downloads/**",)


def test_parse_grant_multi_pattern():
    g = policy.parse_grant("net.http:docs.example.com,api.example.com")
    assert g.patterns == ("docs.example.com", "api.example.com")


def test_parse_grant_strips_whitespace():
    g = policy.parse_grant("  shell.exec : tail , grep , jq  ")
    assert g.capability == "shell.exec"
    assert g.patterns == ("tail", "grep", "jq")


# ── R1 / R4: malformed grants rejected ────────────────────────────


def test_R1_missing_colon_rejected():
    with pytest.raises(policy.PolicyParseError, match="':'"):
        policy.parse_grant("fs.read~/Downloads")


def test_R1_empty_capability_rejected():
    with pytest.raises(policy.PolicyParseError, match="empty capability"):
        policy.parse_grant(":~/Downloads")


def test_R1_non_dotted_capability_rejected():
    with pytest.raises(policy.PolicyParseError, match="dotted"):
        policy.parse_grant("fs:~/Downloads")


def test_R1_no_patterns_rejected():
    with pytest.raises(policy.PolicyParseError, match="no patterns"):
        policy.parse_grant("fs.read:")


def test_R1_empty_string_rejected():
    with pytest.raises(policy.PolicyParseError, match="non-empty"):
        policy.parse_grant("")


# ── parse_policy: multi-grant + comments ──────────────────────────


def test_parse_policy_multiline():
    pol = policy.parse_policy(
        [
            "fs.read:~/Docs/**",
            "fs.write:~/Docs/notes/**",
            "net.http:api.openai.com",
        ]
    )
    assert len(pol.grants) == 3
    assert pol.grants[0].capability == "fs.read"


def test_parse_policy_comments_stripped():
    pol = policy.parse_policy(
        """
        # this is a comment
        fs.read:~/Docs/**  # inline comment
        # another comment

        net.http:api.example.com
        """
    )
    assert len(pol.grants) == 2
    assert pol.grants[0].patterns == ("~/Docs/**",)


def test_parse_policy_semicolon_separated():
    pol = policy.parse_policy("fs.read:~/a;fs.write:~/b")
    assert len(pol.grants) == 2


# ── match_path ───────────────────────────────────────────────────


def test_match_path_basic(tmp_path: Path):
    g = policy.parse_grant(f"fs.read:{tmp_path}/*.md")
    assert policy.match_path(g, tmp_path / "note.md")
    assert not policy.match_path(g, tmp_path / "note.txt")


def test_match_path_recursive_glob(tmp_path: Path):
    g = policy.parse_grant(f"fs.read:{tmp_path}/**")
    assert policy.match_path(g, tmp_path / "a.md")
    assert policy.match_path(g, tmp_path / "sub" / "b.md")
    assert policy.match_path(g, tmp_path / "sub" / "deep" / "c.md")


def test_R7_match_path_no_spillover_to_parent(tmp_path: Path):
    """A grant for ~/Downloads/** must NOT match ~/Documents/x."""
    g = policy.parse_grant(f"fs.read:{tmp_path}/sub/**")
    assert not policy.match_path(g, tmp_path / "other.txt")


def test_R3_match_path_traversal_does_not_match_outer(tmp_path: Path):
    """A caller passing ~/Downloads/../etc/passwd as the path resolves
    to /etc/passwd, which isn't under ~/Downloads, so the grant for
    ~/Downloads/** refuses."""
    g = policy.parse_grant(f"fs.read:{tmp_path}/inner/**")
    evil = tmp_path / "inner" / ".." / "sibling"
    # _resolve uses Path(...); Path normalizes ".." lazily so we call
    # .resolve() explicitly to simulate what an executor would do.
    assert not policy.match_path(g, str(evil.resolve()))


def test_R4_fs_read_grant_does_not_authorize_fs_write(tmp_path: Path):
    g_read = policy.parse_grant(f"fs.read:{tmp_path}/**")
    # match_path only fires for the correct capability family.
    # Simulate: the executor asks "does my fs.read grant cover a write?"
    pol = policy.Policy(grants=(g_read,))
    assert pol.allows_path("fs.read", tmp_path / "a.md")
    assert not pol.allows_path("fs.write", tmp_path / "a.md")


def test_match_path_returns_false_for_non_fs_capability():
    g = policy.parse_grant("net.http:example.com")
    assert not policy.match_path(g, "/anywhere")


# ── match_host ───────────────────────────────────────────────────


def test_match_host_exact():
    g = policy.parse_grant("net.http:docs.example.com")
    assert policy.match_host(g, "docs.example.com")
    assert not policy.match_host(g, "evil.example")


def test_match_host_is_case_insensitive():
    g = policy.parse_grant("net.http:DOCS.example.com")
    assert policy.match_host(g, "docs.EXAMPLE.com")


def test_R5_wildcard_matches_subdomain_not_bare():
    g = policy.parse_grant("net.http:*.example.com")
    assert policy.match_host(g, "a.example.com")
    assert policy.match_host(g, "a.b.example.com")
    # Bare domain does NOT match.
    assert not policy.match_host(g, "example.com")


def test_R7_wildcard_does_not_match_unrelated_domain():
    g = policy.parse_grant("net.http:*.example.com")
    assert not policy.match_host(g, "example.com.evil.org")


# ── match_binary ────────────────────────────────────────────────


def test_match_binary_basename():
    g = policy.parse_grant("shell.exec:grep,tail,jq")
    assert policy.match_binary(g, "grep")
    assert policy.match_binary(g, "/usr/bin/grep")
    assert not policy.match_binary(g, "wget")


def test_match_binary_rejects_absolute_path_patterns():
    """Grants don't contain slashes; a grant trying to pin
    /usr/bin/grep is a user error."""
    g = policy.parse_grant("shell.exec:/usr/bin/grep")
    # The pattern is "/usr/bin/grep" (contains slash) → basename match
    # against "grep" passed in — pattern has slash so exact-match fails.
    assert not policy.match_binary(g, "grep")


def test_R3_shell_binary_match_doesnt_allow_arg_injection():
    """If a user says shell.exec:tail, that authorizes 'tail' — but NOT
    'tail;rm -rf ~'. The match function only sees the binary, not args.
    Arg safety is the executor's job (use shell=False subprocess)."""
    g = policy.parse_grant("shell.exec:tail")
    # A matching binary.
    assert policy.match_binary(g, "tail")
    # A binary name with injected shell metacharacters does NOT match.
    assert not policy.match_binary(g, "tail;rm")
    assert not policy.match_binary(g, "tail$(rm)")


# ── Policy-level helpers ───────────────────────────────────────


def test_policy_grants_for():
    pol = policy.parse_policy(["fs.read:~/a", "fs.read:~/b", "fs.write:~/c"])
    assert len(pol.grants_for("fs.read")) == 2
    assert len(pol.grants_for("fs.write")) == 1
    assert pol.grants_for("shell.exec") == ()


def test_policy_allows_path_checks_all_grants(tmp_path: Path):
    pol = policy.parse_policy([f"fs.read:{tmp_path}/a/**", f"fs.read:{tmp_path}/b/**"])
    assert pol.allows_path("fs.read", tmp_path / "a" / "x.md")
    assert pol.allows_path("fs.read", tmp_path / "b" / "y.md")
    assert not pol.allows_path("fs.read", tmp_path / "c" / "z.md")


def test_policy_allows_host():
    pol = policy.parse_policy(["net.http:api.example.com,*.openai.com"])
    assert pol.allows_host("net.http", "api.example.com")
    assert pol.allows_host("net.http", "platform.openai.com")
    assert not pol.allows_host("net.http", "evil.com")


# ── S6: egress allowlist integration ───────────────────────────


def test_S6_net_http_blocks_non_allowlisted():
    """S6 canonical slice — a net.http grant with a whitelist must
    reject any hostname not on the list. The companion executor PR
    uses this to fail HTTP requests to disallowed hosts at the
    sandbox layer, not at DNS (so leaks can't smuggle through)."""
    pol = policy.parse_policy(["net.http:docs.openai.com"])
    assert pol.allows_host("net.http", "docs.openai.com")
    assert not pol.allows_host("net.http", "evil.example")
    assert not pol.allows_host("net.http", "docs.openai.com.evil")


# ── R9: purity ──────────────────────────────────────────────────


def test_R9_match_functions_are_pure(tmp_path: Path):
    g = policy.parse_grant(f"fs.read:{tmp_path}/*.md")
    for _ in range(5):
        assert policy.match_path(g, tmp_path / "a.md") is True
        assert policy.match_path(g, tmp_path / "a.txt") is False


def test_R9_frozen_dataclasses():
    g = policy.parse_grant("fs.read:~/a")
    with pytest.raises((AttributeError, TypeError)):
        g.capability = "shell.exec"  # type: ignore[misc]
    pol = policy.Policy(grants=(g,))
    with pytest.raises((AttributeError, TypeError)):
        pol.grants = ()  # type: ignore[misc]


# ── match_target (desktop.*) ─────────────────────────────────────


def test_match_target_exact_case_insensitive():
    g = policy.parse_grant("desktop.click:com.firefox")
    assert policy.match_target(g, "com.firefox")
    assert policy.match_target(g, "COM.FIREFOX")  # case-insensitive
    assert not policy.match_target(g, "com.bank.app")


def test_match_target_glob_patterns():
    g = policy.parse_grant("desktop.click:Code*,*.firefox")
    assert policy.match_target(g, "Code")
    assert policy.match_target(g, "Code - Insiders")
    assert policy.match_target(g, "com.firefox")
    assert not policy.match_target(g, "Notepad++")


def test_match_target_empty_target_never_matches():
    g = policy.parse_grant("desktop.click:com.firefox")
    assert not policy.match_target(g, "")


def test_match_target_rejects_non_desktop_grants():
    """Cross-capability isolation: an fs.read grant can't accidentally
    authorize a desktop.click via match_target."""
    g = policy.parse_grant("fs.read:com.firefox")
    assert not policy.match_target(g, "com.firefox")


def test_policy_allows_target_aggregates():
    pol = policy.parse_policy(["desktop.click:com.firefox,Code*", "desktop.type:com.firefox"])
    assert pol.allows_target("desktop.click", "com.firefox")
    assert pol.allows_target("desktop.click", "Code")
    assert pol.allows_target("desktop.type", "com.firefox")
    # Wrong capability for the same target must NOT match.
    assert not pol.allows_target("desktop.read_screen", "com.firefox")
