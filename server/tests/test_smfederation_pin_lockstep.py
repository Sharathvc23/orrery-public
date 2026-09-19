"""The `sm-federation` pin has to be ONE number across this repo.

Found by measuring rather than by review: at that change `conformance/federation/`
was pinned to **0.4.2** while `server/` was still on **0.2.0**, and nothing
compared them. Two pins for one contract, in one repo, for four merged PRs.

That is not a tidiness problem, and the consequence is specific: 0.4.0 made
`capabilities` section tokens part of the wire contract and bound
`federation/0.1#4` to a non-empty `feed_url` **in both directions**, enforced in
the JSON Schema. `build_node_descriptor` DERIVES those tokens — but only from
0.4.0 onward. A server on 0.2.0 that set `feed_url` would emit a descriptor
carrying a feed and **no `#4` token**, which the schema the conformance suite
validates against REJECTS. The suite would have gone red against a server that
was doing exactly what its own installed library told it to.

So the runtime that BUILDS the document and the suite that JUDGES it must resolve
the same distribution. This asserts that, from the pin files themselves.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

#: Every file that pins sm-federation. A new one must be added here — which is
#: the point: the failure mode was a pin nobody knew existed.
PIN_FILES = (
    "server/requirements.txt",
    "server/constraints.txt",
    "server/requirements.lock",
    "conformance/federation/requirements.txt",
)

_PIN_RE = re.compile(r"^sm-federation==(\d+\.\d+\.\d+)\s*$", re.MULTILINE)


def _pins() -> dict[str, str]:
    found = {}
    for rel in PIN_FILES:
        text = (_REPO / rel).read_text(encoding="utf-8")
        matches = _PIN_RE.findall(text)
        assert matches, f"{rel} no longer pins sm-federation — either it moved or this guard is stale"
        assert len(set(matches)) == 1, f"{rel} pins sm-federation more than once: {matches}"
        found[rel] = matches[0]
    return found


def test_every_sm_federation_pin_is_the_same_version() -> None:
    pins = _pins()

    assert len(set(pins.values())) == 1, (
        "sm-federation is pinned to different versions across this repo — the runtime that "
        f"builds the descriptor and the suite that judges it disagree: {pins}"
    )


def test_the_pin_is_at_or_above_the_correctness_floor() -> None:
    """0.5.0 is a floor, not a preference, for two independent reasons.

    * **0.4.0** — `capabilities` section tokens, derived by the builder and
      cross-bound to `feed_url` in the schema. Below it, serving a feed emits a
      descriptor the published schema rejects.
    * **0.5.0** — `read_intelligence` finally passes `expected_head` to
      `verify_page`. Through 0.4.2 a subscriber could not detect a publisher that
      RESTARTED ITS SEQUENCE at all: dropped and reordered were caught, a reseed
      returned a plain `ok`. That is the exact failure `server/federation_feed.py`
      exists to make impossible, so below 0.5.0 the feature ships with its
      central guarantee missing.
    """
    floor = (0, 5, 0)
    for rel, version in _pins().items():
        assert tuple(int(p) for p in version.split(".")) >= floor, (
            f"{rel} pins sm-federation {version}, below the {'.'.join(map(str, floor))} correctness floor"
        )


def test_the_installed_distribution_matches_the_pin() -> None:
    """A pin nothing installs is a comment. Asserts the environment the tests
    actually ran in is the one the pin names — the same class of gap as a plant
    that never landed."""
    import importlib.metadata as md

    try:
        installed = md.version("sm-federation")
    except md.PackageNotFoundError:  # pragma: no cover - only in a broken env
        pytest.fail("sm-federation is not installed; the descriptor tests below would be measuring nothing")

    assert installed == _pins()["server/requirements.txt"], (
        f"tests are running against sm-federation {installed} but server/ pins "
        f"{_pins()['server/requirements.txt']} — this suite is not measuring what ships"
    )
