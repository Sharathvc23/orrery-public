"""Shell arguments are narrowed against the file grants. This is not a bound.

`shell.exec` grants a binary and cannot constrain what that binary does. What is
checked is one shape: an argument naming an existing file the policy does not
permit. That closes the accidental over-reach — a granted binary pointed at a
path outside `fs.*` — and reaches nothing else.

Half of this file asserts what it catches. The other half asserts what it does
NOT, because a narrowing described as a bound is the defect it exists to reduce,
and an untested claim about coverage is how that description survives.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from community_member.actions.shell import ShellExecutor
from community_member.consent import gate, ledger
from community_member.consent.gate import ActionRequest
from community_member.sandbox import parse_policy, unpermitted_path_arguments

CHAPTER = "local:narrow"


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    ledger.init(tmp_path / "consent.db")
    (tmp_path / "allowed").mkdir()
    (tmp_path / "secret").mkdir()
    (tmp_path / "allowed" / "ok.txt").write_text("PUBLIC\n")
    (tmp_path / "secret" / "private.txt").write_text("SECRET-CONTENTS\n")
    return tmp_path


def _executor(tree: Path, binaries: str = "cat,echo,grep") -> ShellExecutor:
    policy = parse_policy(f"fs.read:{tree}/allowed/**\nshell.exec:{binaries}")
    return ShellExecutor(chapter_id=CHAPTER, policy=policy, workdir=tree)


def _run(ex: ShellExecutor, binary: str, args: list[str]):
    req = ActionRequest(
        capability="shell.exec",
        scope=binary,
        context="c",
        provenance="trusted",
        extra={"argv": [binary, *args]},
    )
    approval = gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256="click")
    return ex.exec_command(binary, tuple(args), context="c", approval_event_sha256=approval)


# ── What it catches ───────────────────────────────────────────────────


def test_a_granted_binary_cannot_read_outside_the_file_grants(tree):
    result = _run(_executor(tree), "cat", [str(tree / "secret" / "private.txt")])
    assert result.outcome == "denied"
    assert result.extra["reason"] == "argument_outside_file_grants"
    assert b"SECRET-CONTENTS" not in (result.extra.get("stdout_bytes") or b"")


def test_the_same_binary_still_reads_inside_the_grants(tree):
    result = _run(_executor(tree), "cat", [str(tree / "allowed" / "ok.txt")])
    assert result.outcome == "ok"
    assert b"PUBLIC" in result.extra["stdout_bytes"]


def test_the_refusal_names_the_argument_and_the_remedy(tree):
    result = _run(_executor(tree), "cat", [str(tree / "secret" / "private.txt")])
    assert result.extra["arguments"] == [str(tree / "secret" / "private.txt")]
    assert "grant fs.read" in result.extra["remedy"]


def test_a_relative_argument_is_resolved_against_the_pinned_workdir(tree):
    result = _run(_executor(tree), "cat", ["secret/private.txt"])
    assert result.outcome == "denied"


def test_a_symlink_is_judged_by_its_target(tree):
    link = tree / "allowed" / "looks-fine.txt"
    link.symlink_to(tree / "secret" / "private.txt")
    result = _run(_executor(tree), "cat", [str(link)])
    assert result.outcome == "denied"


def test_a_traversal_out_of_a_granted_directory_is_refused(tree):
    result = _run(_executor(tree), "cat", [str(tree / "allowed" / ".." / "secret" / "private.txt")])
    assert result.outcome == "denied"


def test_with_no_file_grants_every_path_argument_is_refused(tree):
    """Granting a binary and no file access permits no file access. The
    narrowing does not evaporate when the operator expressed no file policy —
    that is the least-bounded state, not an exemption."""
    ex = ShellExecutor(chapter_id=CHAPTER, policy=parse_policy("shell.exec:cat"), workdir=tree)
    assert _run(ex, "cat", [str(tree / "allowed" / "ok.txt")]).outcome == "denied"


# ── What it does NOT catch, asserted so the limit cannot be forgotten ──


def test_a_path_inside_a_program_string_escapes(tree):
    """The decisive case. Same binary, same grant, opposite outcomes depending
    on which syntax the caller chose — so coverage is per-invocation, not
    per-binary, and no operator can learn a rule that predicts it."""
    policy = parse_policy(f"fs.read:{tree}/allowed/**\nshell.exec:awk")
    secret = tree / "secret" / "private.txt"

    as_argument = unpermitted_path_arguments(policy, ["{print}", str(secret)], cwd=tree)
    in_a_program = unpermitted_path_arguments(policy, [f'BEGIN{{while((getline l < "{secret}")>0) print l}}'], cwd=tree)
    assert as_argument == [str(secret)], "the path-as-argument form should be caught"
    assert in_a_program == [], "the path-in-a-program form is NOT caught — this is the limit"


def test_a_host_is_not_narrowed(tree):
    """curl takes a URL, not a path. Nothing here bounds the network, and
    finding a host in argv needs the argument grammar this refuses to build."""
    policy = parse_policy("net.http:api.example.com\nshell.exec:curl")
    assert unpermitted_path_arguments(policy, ["https://evil.example/exfil"], cwd=tree) == []


def test_a_file_that_does_not_exist_yet_is_not_narrowed(tree):
    """A write target resolves to nothing, so it cannot be judged."""
    policy = parse_policy(f"fs.read:{tree}/allowed/**\nshell.exec:tee")
    assert unpermitted_path_arguments(policy, [str(tree / "secret" / "new.txt")], cwd=tree) == []


def test_an_argument_that_is_merely_a_word_is_not_narrowed(tree):
    policy = parse_policy(f"fs.read:{tree}/allowed/**\nshell.exec:grep")
    assert unpermitted_path_arguments(policy, ["SECRET", "-r"], cwd=tree) == []


def test_the_narrowing_refuses_some_harmless_commands(tree):
    """The cost, asserted rather than left for an operator to discover. An
    argument that happens to name an existing path is refused even when the
    binary would never open it."""
    result = _run(_executor(tree), "echo", [str(tree / "secret")])
    assert result.outcome == "denied", "echo does not read its argument, and is refused anyway"


# ── The child's environment and working directory ─────────────────────


def test_the_child_does_not_inherit_the_agents_secrets(tree, monkeypatch):
    """The agent's environment holds its provider API key. A granted binary that
    prints its environment would carry that key out; no grant mentions it and
    the binary allowlist does not bound it."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-THE-AGENTS-REAL-KEY")
    ex = ShellExecutor(chapter_id=CHAPTER, policy=parse_policy("shell.exec:printenv"), workdir=tree)
    result = _run(ex, "printenv", ["OPENAI_API_KEY"])

    assert b"sk-THE-AGENTS-REAL-KEY" not in (result.extra.get("stdout_bytes") or b"")


def test_the_child_keeps_the_variables_it_needs_to_run(tree):
    ex = ShellExecutor(chapter_id=CHAPTER, policy=parse_policy("shell.exec:printenv"), workdir=tree)
    assert _run(ex, "printenv", ["PATH"]).extra["stdout_bytes"].strip() == os.environ["PATH"].encode()


def test_the_child_runs_in_the_pinned_workdir(tree):
    ex = ShellExecutor(chapter_id=CHAPTER, policy=parse_policy("shell.exec:pwd"), workdir=tree)
    out = _run(ex, "pwd", []).extra["stdout_bytes"].decode().strip()
    assert Path(out).resolve() == tree.resolve()


def test_the_workdir_defaults_under_the_agent_home(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    import importlib

    from community_member import config as config_mod

    importlib.reload(config_mod)
    ex = ShellExecutor(chapter_id=CHAPTER, policy=parse_policy("shell.exec:pwd"))
    assert ex._workdir().parent == config_mod.CONFIG_DIR
