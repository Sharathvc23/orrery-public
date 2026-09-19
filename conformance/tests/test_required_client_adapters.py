"""Release-CI contracts for Orrery's shipped client-signing adapters.

The five protocol checks live in ``conformance/client``.  These tests protect
the release gate around that suite: downstream users may still omit an
optional adapter, while Orrery's own CI must fail closed if any shipped
implementation is unavailable.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
AGENT_REQUIREMENTS = REPO_ROOT / "agent" / "requirements.lock"


@pytest.fixture
def run_client_conformance(
    tmp_path: Path,
) -> Callable[..., subprocess.CompletedProcess[str]]:
    """Run the real client suite with an intentionally absent member SDK."""

    missing_sdk = tmp_path / "missing-member-sdk"

    def _run(*extra_args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.pop("PYTEST_ADDOPTS", None)
        env["COMMUNITY_MEMBER_PATH"] = str(missing_sdk)
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "conformance/client",
                "-q",
                *extra_args,
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    return _run


def _combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}\n{result.stderr}"


def _workflow_job(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        workflow,
    )
    assert match is not None, f"workflow job {job_name!r} not found"
    return match.group("body")


def _shipped_adapters() -> set[str]:
    """Read the conformance module's exported set in an isolated process."""

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json; "
                "from conformance.client.conftest import SHIPPED_ADAPTERS; "
                "print(json.dumps(SHIPPED_ADAPTERS))"
            ),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, _combined_output(result)
    return set(json.loads(result.stdout))


def test_missing_optional_adapter_remains_skippable(run_client_conformance) -> None:
    result = run_client_conformance("--adapter", "member-sdk")

    assert result.returncode == 0, _combined_output(result)
    assert "5 skipped" in _combined_output(result)


def test_missing_required_adapter_fails_closed(run_client_conformance) -> None:
    result = run_client_conformance("--adapter", "member-sdk", "--require-adapter")
    output = _combined_output(result).lower()

    assert result.returncode != 0
    assert "required adapter" in output
    assert "unavailable" in output


def test_ci_runs_each_shipped_adapter_in_separate_required_mode_command() -> None:
    conformance_job = _workflow_job(CI_WORKFLOW.read_text(encoding="utf-8"), "conformance")
    required_runs = re.findall(
        r"(?m)^\s*run:\s*python -m pytest conformance/client -q "
        r"--adapter ([a-z0-9-]+) --require-adapter\s*$",
        conformance_job,
    )

    shipped_adapters = _shipped_adapters()
    assert len(required_runs) == len(shipped_adapters)
    assert set(required_runs) == shipped_adapters


def test_conformance_path_filter_covers_shipped_adapter_sources() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        r"(?m)^\s*hit '([^']+)'\s+&& emit conformance true\s+\|\| emit conformance false\s*$",
        workflow,
    )
    assert match is not None, "conformance change-detector expression not found"

    path_filter = re.compile(match.group(1))
    for changed_path in (
        "conformance/client/conftest.py",
        "schema/0.4/agent-card.json",
        "vectors/signing/did-key.json",
        "agent/community_member/auth.py",
        "skill/helpers/sign_request.py",
    ):
        assert path_filter.search(changed_path), f"conformance CI ignores {changed_path}"


def test_conformance_job_uses_member_sdk_pynacl_pin() -> None:
    requirements = AGENT_REQUIREMENTS.read_text(encoding="utf-8")
    pin_match = re.search(r"(?mi)^PyNaCl==([^\s]+)$", requirements)
    assert pin_match is not None, "agent/requirements.lock has no exact PyNaCl pin"

    conformance_job = _workflow_job(CI_WORKFLOW.read_text(encoding="utf-8"), "conformance")
    install_commands = re.findall(r"(?m)^\s*- run:\s*(pip install[^\n]+)$", conformance_job)
    expected_pin = re.compile(rf"(?:^|\s)PyNaCl=={re.escape(pin_match.group(1))}(?:\s|$)")
    assert any(expected_pin.search(command) for command in install_commands)
