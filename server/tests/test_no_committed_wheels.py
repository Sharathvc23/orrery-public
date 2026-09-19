"""Built wheels must NEVER be committed to this repo — a tracked ``.whl`` is an
opaque binary blob in a source tree (supply-chain smell) and any private/vendored
package must be supplied out-of-band at build time, never checked in. This guards
against a regression that force-adds an ignored wheel.

Classification: SECURITY / REGRESSION.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_no_wheels_tracked_in_git():
    out = subprocess.run(
        ["git", "ls-files", "*.whl"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
    )
    tracked = [ln for ln in out.stdout.splitlines() if ln.strip()]
    assert not tracked, (
        "built wheels must not be committed — found tracked .whl files:\n"
        + "\n".join(tracked)
        + "\nSupply any vendored package out-of-band at build time; keep .whl git-ignored."
    )
