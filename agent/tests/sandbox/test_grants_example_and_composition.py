"""The shipped example grants nothing, and a subsuming shell grant is reported.

`shell.exec` constrains which binary runs and nothing about its arguments, so a
grant for a binary that takes a path or a URL permits whatever that binary does
to any path or any URL. The `fs.*` and `net.http` patterns beside it do not
bound it. That property is not obvious from the capability names, so it is
warned about at load time and stated in the example file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member.sandbox import (
    SUBSUMING_BINARIES,
    Policy,
    grants,
    lint_policy,
    parse_policy,
)

AGENT_DIR = Path(__file__).resolve().parents[2]
EXAMPLE = AGENT_DIR / "grants.policy.example"


# ── The example ships nothing active ──────────────────────────────────


def test_the_example_file_exists():
    assert EXAMPLE.is_file()


def test_the_example_activates_no_grants():
    """People copy examples verbatim, so a generous example becomes the default
    by accident. Every line is commented."""
    policy = parse_policy(EXAMPLE.read_text())
    assert policy.grants == ()


def test_the_example_has_no_uncommented_lines():
    live = [ln for ln in EXAMPLE.read_text().splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert not live, f"the example has active lines: {live}"


def test_the_example_is_not_the_file_the_agent_reads():
    assert EXAMPLE.name != grants.GRANTS_FILENAME


def test_the_example_parses():
    """Commented out is not an excuse for syntax nobody checked — an operator
    uncommenting a line must get a working grant."""
    body = EXAMPLE.read_text()
    uncommented = "\n".join(ln.lstrip("# ") for ln in body.splitlines() if ln.strip().startswith("# ") and ":" in ln)
    # Only the grant-shaped comment lines; prose comments are skipped by the
    # ':' filter above being paired with a known capability prefix.
    known = tuple(f"{c}:" for c in ("fs.read", "fs.write", "net.http", "browser.navigate", "shell.exec"))
    lines = [ln for ln in uncommented.splitlines() if ln.startswith(known)]
    assert lines, "no example grant lines found — the example has stopped demonstrating anything"
    assert parse_policy("\n".join(lines)).grants


def test_the_example_suggests_no_shell_binary_at_all():
    """The example must not teach the hole it documents, and there is no binary
    that can honestly be offered as the narrow choice: shell.exec does not
    constrain arguments, so anything named here reads as a vetted default."""
    body = EXAMPLE.read_text()
    lines = [ln.lstrip("# ").strip() for ln in body.splitlines() if ln.strip().startswith("# shell.exec:")]
    for line in lines:
        for pattern in line.split(":", 1)[1].split(","):
            named = pattern.strip()
            assert named in ("", "<binary>"), f"the example suggests the binary {named!r}"
            assert named not in SUBSUMING_BINARIES


# ── An install with no grants file still refuses everything ───────────


def test_an_install_with_no_grants_file_refuses_everything(tmp_path):
    """The property this whole unit must not disturb."""
    assert not grants.grants_path(tmp_path).exists()
    policy = grants.load_policy(tmp_path)

    assert policy.grants == ()
    assert not policy.allows_path("fs.read", "/etc/hostname")
    assert not policy.allows_binary("shell.exec", "grep")
    assert not policy.allows_host("net.http", "example.com")
    assert not policy.allows_origin("browser.navigate", "https://example.com")


def test_the_example_being_present_does_not_grant_anything(tmp_path):
    """Copying the example next to the real file must not activate it."""
    (tmp_path / EXAMPLE.name).write_text(EXAMPLE.read_text())
    assert grants.load_policy(tmp_path).grants == ()


# ── The lint ──────────────────────────────────────────────────────────


def test_a_subsuming_binary_is_reported_against_a_narrower_grant():
    warnings = lint_policy(parse_policy("fs.read:~/Downloads/**\nshell.exec:grep"))
    assert len(warnings) == 1
    assert "grep" in warnings[0]
    assert "wider than your fs.read grant" in warnings[0]


def test_a_subsuming_binary_is_reported_with_no_narrower_grant():
    """Granting grep with no fs.read at all is more surprising, not less."""
    warnings = lint_policy(parse_policy("shell.exec:grep"))
    assert len(warnings) == 1
    assert "unbounded by any fs.read pattern" in warnings[0]


def test_a_shell_that_runs_anything_is_reported_as_subsuming_the_allowlist():
    warnings = lint_policy(parse_policy("shell.exec:bash"))
    assert "runs any command" in warnings[0]
    assert "shell.exec" in SUBSUMING_BINARIES["bash"][0]


def test_a_binary_outside_the_list_is_not_reported():
    """Today's behaviour, pinned so a change to it is visible. An earlier
    version of this test used git as the narrow example; git runs any command
    through a config alias, so it is now reported and the premise was wrong."""
    assert lint_policy(parse_policy("shell.exec:some-local-script")) == []


def test_an_empty_policy_reports_nothing():
    assert lint_policy(Policy(grants=())) == []


def test_a_network_binary_is_reported_against_a_net_grant():
    warnings = lint_policy(parse_policy("net.http:api.example.com\nshell.exec:curl"))
    assert "wider than your net.http grant" in warnings[0]


def test_the_lint_matches_a_binary_given_as_a_path():
    """`shell.exec:/usr/bin/grep` is the same grant by basename."""
    assert lint_policy(parse_policy("shell.exec:/usr/bin/grep"))


def test_the_lint_never_refuses():
    """Warnings, not refusals — the operator may mean it, and a policy layer
    that overrides the operator's own choice has stopped being one."""
    policy = parse_policy("shell.exec:bash,curl,python")
    assert lint_policy(policy)
    assert policy.allows_binary("shell.exec", "bash"), "the lint must not change what is permitted"


# ── The set is declared, non-empty, and reasoned ──────────────────────


def test_the_subsuming_set_is_not_empty():
    """Emptying it would silence every warning above rather than failing."""
    assert SUBSUMING_BINARIES


@pytest.mark.parametrize("binary", sorted(SUBSUMING_BINARIES))
def test_every_subsuming_entry_names_what_it_subsumes_and_why(binary):
    subsumes, reason = SUBSUMING_BINARIES[binary]
    assert subsumes, f"{binary} declares no subsumed capability"
    assert all(c.count(".") == 1 for c in subsumes), f"{binary} names a malformed capability"
    assert len(reason.strip()) >= 20, f"{binary} needs a reason a reviewer can weigh"


def test_the_documented_binaries_are_the_declared_ones():
    """The module docstring, the example and the set must not drift apart."""
    from community_member.sandbox import policy as policy_mod

    doc = policy_mod.__doc__ or ""
    assert "SUBSUMING_BINARIES" in doc
    assert "shell.exec:awk" in doc, "the docstring should name the case it warns about"
    assert "shell.exec:tail,grep,jq" not in doc, "the docstring example still teaches the hole"
    assert "shell.exec:git" not in doc, "the docstring example names a binary that runs any command"
    assert "NOT EXHAUSTIVE" in doc, "the docstring does not say the list is incomplete"


# ── The parser defect the example surfaced ────────────────────────────


def test_a_comment_containing_a_semicolon_does_not_break_the_file():
    """';' separates grants, and comments are stripped first. The other order
    parsed a comment's tail as a grant, so one stray ';' in a comment made the
    file unparseable — which, grants being all-or-nothing, refused every action
    on the install."""
    policy = parse_policy("# scheme required; port defaults\nfs.read:~/x/**")
    assert [g.capability for g in policy.grants] == ["fs.read"]


def test_a_trailing_comment_containing_a_semicolon_is_stripped():
    policy = parse_policy("fs.read:~/x/**  # narrow; deliberate")
    assert policy.grants[0].patterns == ("~/x/**",)


def test_a_semicolon_still_separates_grants():
    policy = parse_policy("fs.read:~/a/**; net.http:example.com")
    assert [g.capability for g in policy.grants] == ["fs.read", "net.http"]


# ── The lint states its own limits ────────────────────────────────────


def test_the_lint_says_its_list_is_not_exhaustive():
    """A lint that warns about some grants and is silent about others teaches
    that silence means safety. It has to say that it does not."""
    doc = lint_policy.__doc__ or ""
    assert "NOT EXHAUSTIVE" in doc
    assert "not been cleared" in doc


def test_the_lint_names_the_shapes_that_escape_it():
    """A bare caveat is taken on faith; naming what escapes lets the reader
    recognise a case rather than trust the disclaimer."""
    doc = lint_policy.__doc__ or ""
    for shape in ("interpreter", "basename", "flag"):
        assert shape in doc, f"the caveat does not describe the {shape} case"


def test_the_operator_documentation_carries_the_same_caveat():
    """The person choosing what to grant is reading the docs, not the module."""
    docs = (AGENT_DIR.parent / "docs" / "CONFIGURATION.md").read_text()
    assert "No warning is not a safety claim" in docs
    assert "has not been assessed" in docs


def test_git_is_recognised_as_running_arbitrary_commands():
    """Proven rather than assumed: `git -c alias.x='!cmd' x` runs any command,
    as do core.pager, core.sshCommand and repository hooks. An earlier draft of
    the example offered git as the narrow choice on the basis that it operates
    on repositories."""
    assert "git" in SUBSUMING_BINARIES
    subsumes, reason = SUBSUMING_BINARIES["git"]
    assert "shell.exec" in subsumes
    assert "alias" in reason


def test_an_unrecognised_binary_produces_no_warning():
    """Recorded so the behaviour is deliberate rather than incidental: the lint
    is silent on a binary it does not know. Whether that silence should become
    a stated unknown is an open question; this pins today's answer so a change
    to it is visible."""
    assert lint_policy(parse_policy("shell.exec:some-local-script")) == []


# ── The stated reason must match what the code does ───────────────────


def test_no_artefact_claims_shell_arguments_are_wholly_unconstrained():
    """`shell.exec does not constrain arguments at all` was true until the
    argument narrowing shipped. It is the stated reason the list cannot be
    exhaustive, and the conclusion still holds — for a narrower reason. Seven
    copies of that sentence existed across four files; this asserts none return.
    """
    from community_member.sandbox import policy as policy_mod

    roots = [
        Path(policy_mod.__file__),
        Path(policy_mod.__file__).parents[1] / "agent.py",
        EXAMPLE,
        AGENT_DIR.parent / "docs" / "CONFIGURATION.md",
    ]
    stale = ["does not constrain arguments at all", "says NOTHING about its arguments"]
    offenders = [f"{path.name}: {phrase}" for path in roots for phrase in stale if phrase in path.read_text()]
    assert not offenders, offenders


def test_the_caveat_still_gives_a_reason_for_being_inexhaustive():
    """Removing the false reason must not leave the conclusion unsupported."""
    doc = lint_policy.__doc__ or ""
    assert "one shape of argument" in doc
    assert "not a host" in doc
