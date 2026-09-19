"""A field the wizard MAKES an operator fill must reach something that reads it.

The failure this exists for is not a dead key. It is a dead key the operator was
required to fill and told mattered. Step "Pick a chapter" was `required: True`,
described as how an agent "joins a chapter to find peers and participate in
federation", and wrote `channels.primary_chapter_url` — a key whose only
reference in the repository was that write. The operator could not skip it,
could not get it wrong, and could not have it matter.

That is worse than an absent field: it manufactures confidence in a connection
that was never made, and nothing in the suite could tell the difference.

⚠️ BOTH SIDES ARE DERIVED, and that is the whole design.

* WHERE A FIELD LANDS is discovered by RUNNING the wizard twice with one field
  changed and diffing the writes a recording store received. Reading `advance()`
  for its destinations would re-state the code under test; a value that is
  written and a value that is not are distinguishable only by running it.
* WHETHER A LANDING SITE HAS A READER is counted from the tree, excluding the
  writer itself and the tests. A hand-written list of "keys that are fine" is
  the drift this is meant to catch.

Generic column names (`name`, `provider`) inevitably match a great deal and so
can never FAIL the check. That asymmetry is deliberate and safe: this guard
exists to catch a distinctive key with no readers, and over-counting a common
one can only make it quieter, never wrong.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import onboarding
import settings as settings_mod

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_settings_onboarding import _FakePostgres  # noqa: E402  (needs the tests dir above)

_REPO = Path(__file__).resolve().parents[2]
_WRITER = "server/onboarding.py"

#: Landing sites the sweep finds with no reader, that are ALLOWED to have none.
#: One entry, one reason. Bounded by ``test_every_exemption_is_still_needed``
#: below: an exemption the sweep never produces, or one whose key has acquired a
#: reader, fails — an exemption with nothing to exempt only pre-authorises the
#: next dead key.
UNREAD_BY_DESIGN: dict[str, str] = {
    "llm_key_": (
        "The member's own sealed copy of their provider credential, in private "
        "memory. The runtime reads agent_api_keys, not this. Kept deliberately "
        "rather than dropped, because removing it would discard state an "
        "operator may already depend on. Its field (api_key) is optional, so an "
        "operator is never made to fill something that reaches no reader."
    ),
}


#: A distinct value per field, so a diff attributes a written value to exactly
#: one field. Select fields must use a value their own option list admits — an
#: arbitrary canary would be refused by validation and land nowhere, which the
#: sweep would then report as "reaches no reader" for the wrong reason.
def _value_for(field: dict, variant: int) -> str:
    if field.get("type") == "select":
        options = [o["value"] for o in field.get("options", [])]
        return str(options[variant % len(options)])
    return f"canary-{field['key']}-{variant}"


def _values_for_step(step: int, variant: int, *, vary: str | None = None) -> dict:
    """Every field on a step. Only ``vary`` changes between variants."""
    out = {}
    for f in onboarding.STEP_SPEC[step]["fields"]:
        out[f["key"]] = _value_for(f, variant if f["key"] == vary else 0)
    return out


async def _run_wizard(vary: str | None, variant: int) -> list[tuple]:
    """Drive every step end to end, recording each write. Returns the writes."""
    pg = _FakePostgres()
    pg.tables["agents"] = [{"agent_id": "canary-member", "profile_id": "p1", "onboarding_step": 0}]
    pg.tables["agent_private_memory"] = []
    onboarding.init(pg_request_fn=pg)
    settings_mod.init(pg_request_fn=pg)

    secrets: list[tuple] = []

    async def store_secret(agent_id: str, key_name: str, value: str) -> None:
        secrets.append(("agent_private_memory", key_name, value))

    for step in sorted(onboarding.STEP_SPEC):
        if not onboarding.STEP_SPEC[step]["fields"]:
            break
        await onboarding.advance(
            "canary-member",
            step,
            _values_for_step(step, variant, vary=vary),
            store_secret=store_secret,
            settings_module=settings_mod,
        )
    return [(m, t, b) for (m, t, _p, b) in pg.calls if m in ("PATCH", "POST")] + secrets


def _flatten(prefix: str, value, out: dict) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten(f"{prefix}.{k}" if prefix else k, v, out)
    else:
        out[prefix] = value


def _written_values(writes: list[tuple]) -> dict[str, object]:
    """Every (table.key.path -> value) a run wrote, flattened."""
    out: dict[str, object] = {}
    for entry in writes:
        if entry[0] == "agent_private_memory":
            _, key_name, value = entry
            out[f"agent_private_memory.{key_name}"] = value
            continue
        _, table, body = entry
        if isinstance(body, dict):
            _flatten(table, body, out)
    return out


def _differing(a: dict, b: dict) -> set[str]:
    return {k for k in set(a) | set(b) if a.get(k) != b.get(k)}


async def _landing_sites(field_key: str) -> set[str]:
    """The write destinations whose value changes BECAUSE this field changed.

    ⚠️ A CONTROL RUN, NOT JUST A DIFF, and the guard was useless without it. Two
    runs of the wizard differ in places that have nothing to do with any field:
    ``agent_api_keys.api_key_encrypted`` is sealed under a fresh nonce every
    time, and ``onboarding_completed_at`` is a timestamp. A plain
    before/after diff therefore attributed those two sites to EVERY field, both
    have readers, and so every field looked live — including the one this file
    was written to catch. Caught by planting the removed field back and watching
    nothing redden.

    So: run twice with identical inputs to learn what moves on its own, and
    subtract that from the diff that changed one field.
    """
    a = _written_values(await _run_wizard(field_key, 0))
    control = _written_values(await _run_wizard(field_key, 0))
    b = _written_values(await _run_wizard(field_key, 1))
    return _differing(a, b) - _differing(a, control)


def _reader_count(site: str) -> int:
    """References to a landing site's key outside the writer and the tests."""
    key = site.split(".")[-1]
    # A key built from a runtime value (llm_key_anthropic) is searched by its
    # stable prefix — the suffix is the provider and is not in any source.
    for prefix in UNREAD_BY_DESIGN:
        if key.startswith(prefix):
            key = prefix
    proc = subprocess.run(
        ["git", "grep", "-I", "-c", "--", key],
        cwd=_REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    total = 0
    for line in proc.stdout.splitlines():
        path, _, count = line.rpartition(":")
        if path == _WRITER or "/tests/" in path or path.startswith("tests/"):
            continue
        total += int(count)
    return total


def _exempt(site: str) -> bool:
    key = site.split(".")[-1]
    return any(key.startswith(p) for p in UNREAD_BY_DESIGN)


# ── the guard ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_sweep_finds_where_fields_land():
    """DETECTOR VALIDATION. Every assertion below is about landing sites, so a
    sweep that found none would pass the file while proving nothing."""
    sites = await _landing_sites("display_name")
    assert sites, "the sweep attributed no write to display_name — it is not measuring anything"
    assert any(s.endswith(".name") for s in sites), f"display_name landed somewhere unexpected: {sites}"


@pytest.mark.asyncio
async def test_no_required_field_reaches_a_store_nothing_reads():
    """The guard. A field an operator cannot skip must reach something that
    reads it — or be removed, which is what happened to the one that could not."""
    offenders: list[str] = []
    for step, spec in sorted(onboarding.STEP_SPEC.items()):
        for field in spec["fields"]:
            if not field.get("required"):
                continue
            sites = await _landing_sites(field["key"])
            if not sites:
                offenders.append(f"step {step} field {field['key']!r}: its value reaches NO store at all")
                continue
            live = [s for s in sites if _exempt(s) or _reader_count(s) > 0]
            if not live:
                offenders.append(
                    f"step {step} field {field['key']!r}: required, and every place it lands "
                    f"({', '.join(sorted(sites))}) has no reader outside {_WRITER}"
                )
    assert not offenders, (
        "the wizard requires answers that reach nothing:\n  "
        + "\n  ".join(offenders)
        + "\n\nRemove the field, or wire it to a reader. A required field that changes nothing "
        "manufactures operator confidence in something that did not happen."
    )


@pytest.mark.asyncio
async def test_every_exemption_is_still_needed():
    """The exemption list is the one part of this file that can be widened to
    silence it, so it is bounded the same way the provider-vocabulary exemption
    is: an entry the sweep never produces, or one whose key has since acquired a
    reader, fails rather than sitting there pre-authorising the next dead key."""
    produced: set[str] = set()
    for spec in onboarding.STEP_SPEC.values():
        for field in spec["fields"]:
            produced |= await _landing_sites(field["key"])

    for prefix, reason in UNREAD_BY_DESIGN.items():
        assert reason.strip(), f"exemption {prefix!r} carries no reason"
        matching = [s for s in produced if s.split(".")[-1].startswith(prefix)]
        assert matching, f"UNREAD_BY_DESIGN exempts {prefix!r}, which the wizard no longer writes. Remove the entry."
        assert all(_reader_count(s) == 0 for s in matching), (
            f"UNREAD_BY_DESIGN exempts {prefix!r}, which now HAS a reader. Remove the entry — "
            "an exemption that is not needed only weakens the check."
        )
