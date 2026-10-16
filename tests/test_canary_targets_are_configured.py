"""Guards on the live canaries' target configuration.

The two scheduled canaries assert properties of the DEPLOYED system, and both
take their targets from ``ORGS`` with no default. That design is right: a
hardcoded hostname would print live infrastructure into a public Actions log
every six hours, and a fork's scheduled run would probe hosts its owner does not
operate. The cost is that "no targets" and "all targets healthy" both exit 0.

That cost came due. ``CANARY_ORGS`` was never recreated when the tree was
snapshotted into the public repository, so from 2026-09-19 to 2026-10-15 both
canaries skipped on every six-hourly run and reported success — 11-second runs
that fetched nothing. Each printed "This is NOT a pass" into a log, while the
exit status said the opposite. The repository already holds the rule this
violates, on ``smb_host``'s front door: *an unconfigured bound must refuse or
warn by name, never serve openly.*

Three guards:

``test_an_unconfigured_canary_refuses_rather_than_reporting_green``
    With the flag set and no targets, the decision is a refusal, and the message
    names the variable an operator has to set. The predicate is driven directly
    rather than through the scripts, because ``scripts/_canary_targets`` imports
    stdlib only while the canaries need ``httpx`` and ``sm_arp`` — installing
    those into the cheap doc-guards job to check a two-branch decision is how a
    guard stops being run.

``test_a_fork_with_no_targets_still_skips_cleanly``
    The fork path is preserved, including for the literal ``false`` GitHub
    substitutes when its ``github.repository`` comparison does not match. A
    fork must never be made to fail by a variable it did not set.

``test_every_canary_workflow_sets_the_flag``
    The refusal is unreachable unless the workflow sets the flag, and an
    unreachable refusal is the defect this file exists about, one layer down.
    The workflow set is DERIVED from the directory, never listed here: a
    hand-list goes stale in the direction that reports green, so the next canary
    added would land unguarded — the same reasoning
    ``test_cve_scan_covers_every_lock`` uses for lockfiles.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOWS = _ROOT / ".github" / "workflows"


def _load_targets_module():
    """Import ``scripts/_canary_targets.py`` by path, without a package."""
    path = _ROOT / "scripts" / "_canary_targets.py"
    spec = importlib.util.spec_from_file_location("_canary_targets", path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canary_workflows() -> list[Path]:
    """Every workflow that runs a canary script — derived, never hand-listed."""
    found = [
        p
        for p in sorted(_WORKFLOWS.glob("*.yml"))
        if "_canary.py" in p.read_text(encoding="utf-8")
    ]
    assert found, "no canary workflows found — the derivation broke, not the property"
    return found


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", " true "])
def test_an_unconfigured_canary_refuses_rather_than_reporting_green(value, monkeypatch):
    targets = _load_targets_module()
    monkeypatch.setenv(targets.REQUIRE_TARGETS_ENV, value)
    assert targets.targets_are_required() is True

    message = targets.refusal("read or resolved")
    # Names the variable to SET, not just the one that is set: the operator
    # reading this has to act, and CANARY_REQUIRE_TARGETS is not the knob.
    assert "CANARY_ORGS" in message
    assert "did not run" in message


@pytest.mark.parametrize("value", [None, "", "false", "False", "0", "no", "maybe"])
def test_a_fork_with_no_targets_still_skips_cleanly(value, monkeypatch):
    targets = _load_targets_module()
    if value is None:
        monkeypatch.delenv(targets.REQUIRE_TARGETS_ENV, raising=False)
    else:
        monkeypatch.setenv(targets.REQUIRE_TARGETS_ENV, value)
    assert targets.targets_are_required() is False


def test_every_canary_workflow_sets_the_flag():
    targets = _load_targets_module()
    for workflow in _canary_workflows():
        text = workflow.read_text(encoding="utf-8")
        assert targets.REQUIRE_TARGETS_ENV in text, (
            f"{workflow.name} runs a canary but never sets "
            f"{targets.REQUIRE_TARGETS_ENV}, so its refusal can never fire"
        )
        # Bound to a repository comparison, so it is TRUE only where the
        # deployments exist. A bare `true` would make every fork fail.
        assert re.search(
            rf"{targets.REQUIRE_TARGETS_ENV}:\s*\$\{{\{{\s*github\.repository\s*==",
            text,
        ), f"{workflow.name} must bind the flag to a github.repository comparison"
