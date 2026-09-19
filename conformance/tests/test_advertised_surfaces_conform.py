"""Fail-on-drift gates for every advertised profile/surface (Part 2).

Before this, ``schema/**`` was meta-validated (well-formed JSONSchema) and a
few instances were checked, but several *advertised* runtime surfaces had no
gate that would FAIL if the runtime drifted from the schema it ships:

  1. The conformance badge the runtime serves at ``/.well-known/conformance.json``
     is produced by ``sm_conformance.build_badge`` — but nothing validated it
     against ``schema/arp/**/conformance-envelope.schema.json``. It had drifted:
     the badge carries ``errored`` + ``skipped_vectors`` the schema rejected.
  2. The A2UI surfaces the runtime actually emits (``a2ui_helpers``) were never
     validated against ``schema/0.4`` — only a hand-written instance was.
  3. ``schema/0.3`` (A2UI 0.9) and both component schemas were meta-validated
     but never exercised as real accept/reject gates.
  4. The A2UI version set the runtime *advertises* (``a2ui_versions``) had no
     check tying each advertised version to a shipped schema.
  5. A2UI **0.8** — the OpenClaw wire shape the runtime advertises and
     serves via ``?schema=v0.8`` — had no schema at all, so the one envelope a
     third-party consumer actually fetches was the one nothing could validate.
     It was pinned in ``A2UI_KNOWN_UNSCHEMATIZED`` as a declared gap; that
     allowlist is now empty and the 0.8 envelope has its own accept/reject gate
     driven by real downgraded output.

These gates close all five. Each is designed to FAIL on drift, not just on a
malformed schema.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from conformance.tests.conftest import REPO_ROOT, SCHEMA_ROOT, _load_json

# The runtime code lives under server/; import it standalone to validate what it
# actually emits (a2ui_helpers is a pure dict-builder, no heavy deps).
SERVER_ROOT = REPO_ROOT / "server"
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))


def _registry_for(directory: Path) -> Registry:
    resources = []
    for path in sorted(directory.glob("*.json")):
        doc = _load_json(path)
        if "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


def _validator(schema_path: Path) -> Draft202012Validator:
    directory = schema_path.parent
    return Draft202012Validator(
        _load_json(schema_path), registry=_registry_for(directory)
    )


# ── (1) The advertised conformance badge conforms to the shipped envelope schema ──


def _build_real_badge() -> dict:
    """A badge from the SAME builder the runtime serves (sm_conformance)."""
    from sm_conformance.badge import build_badge

    return build_badge(
        "chapter",
        signing_key32=bytes(range(32)),
        suite_digest="sha256:" + "0" * 64,
        protocol_versions=["0.3", "0.2"],
        completed_at="2026-07-11T00:00:00Z",
        passed=5,
        failed=0,
        skipped=1,
        skipped_vectors=["some-skipped-vector"],
        extensions={"org.conformance.surface": "server"},
    )


@pytest.mark.parametrize("arp_version", ["0.1", "0.2"])
def test_served_conformance_badge_conforms_to_envelope_schema(arp_version: str) -> None:
    """The badge the runtime advertises at /.well-known/conformance.json MUST
    validate against the conformance-envelope schema it ships. This is the gate
    that catches sm-conformance's badge shape drifting from orrery's schema
    (it had: the badge's ``errored`` + ``skipped_vectors`` were schema-rejected)."""
    schema_path = SCHEMA_ROOT / "arp" / arp_version / "conformance-envelope.schema.json"
    validator = _validator(schema_path)
    badge = _build_real_badge()
    errors = sorted(validator.iter_errors(badge), key=str)
    assert not errors, (
        f"served conformance badge does not conform to schema/arp/{arp_version}/"
        f"conformance-envelope.schema.json: {errors[0].message}"
    )


def test_conformance_envelope_schema_still_rejects_a_bad_badge() -> None:
    """Negative side: the envelope schema must still REJECT a malformed badge,
    or widening it for ``errored``/``skipped_vectors`` turned it into a rubber
    stamp. A missing required count field must fail."""
    validator = _validator(
        SCHEMA_ROOT / "arp" / "0.2" / "conformance-envelope.schema.json"
    )
    badge = _build_real_badge()
    del badge["payload"]["passed"]  # required
    assert list(validator.iter_errors(badge)), (
        "envelope schema accepted a badge missing a required field"
    )


# ── (2) The A2UI surfaces the runtime EMITS conform to their schema ──

def _a2ui_schema_by_version() -> dict[str, Path]:
    """Map each A2UI envelope version (the surface schema's ``version`` const)
    to its surface schema path — discovered, not hardcoded, so a new schema dir
    is picked up automatically.

    The glob is ``a2ui-surface*.json``, not ``a2ui-surface.json``: a directory
    holds the NATIVE envelope for its spec version plus any downgrade shape that
    version must also serve (``a2ui-surface-v08.json``). Keying off the
    ``version`` const rather than the filename means the map is right either way.
    """
    out: dict[str, Path] = {}
    for surface in SCHEMA_ROOT.glob("0.*/a2ui-surface*.json"):
        const = (
            _load_json(surface).get("properties", {}).get("version", {}).get("const")
        )
        if const:
            out[const] = surface
    return out


def _emitted_surfaces() -> dict[str, dict]:
    """Real envelopes from the runtime's own A2UI builders."""
    import a2ui_helpers as a

    return {
        "build_member_cards": a.build_member_cards(
            [{"agent_id": "x", "name": "X", "score": 1.0}]
        ),
        "build_insight_card": a.build_insight_card("Title", "an insight", ["a", "b"]),
        "build_chapter_info": a.build_chapter_info(
            "AstroCity", "desc", "focus", "US-CA", 5, 2
        ),
        "build_federation_cards": a.build_federation_cards(
            {
                "chapters": {
                    "p": {
                        "name": "P",
                        "endpoint": "https://x",
                        "status": "online",
                        "members": 1,
                    }
                }
            }
        ),
    }


@pytest.mark.parametrize("builder", list(_emitted_surfaces().keys()))
def test_emitted_a2ui_surface_conforms_to_its_schema(builder: str) -> None:
    """Real ``a2ui_helpers`` output validates against the schema pinning its
    version — catching the runtime emitting non-conformant wire (the hand-written
    instance in the old test could not)."""
    env = _emitted_surfaces()[builder]
    assert env is not None, f"{builder} returned None"
    version = env.get("version")
    schemas = _a2ui_schema_by_version()
    assert version in schemas, (
        f"{builder} emits A2UI version {version!r} with no shipped schema"
    )
    validator = _validator(schemas[version])
    errors = sorted(validator.iter_errors(env), key=str)
    assert not errors, (
        f"{builder} emitted a non-conformant A2UI {version} surface: {errors[0].message}"
    )


# ── (3) Every shipped A2UI schema is a REAL gate (accept valid, reject bad) ──

A2UI_SURFACE_SCHEMAS = sorted(SCHEMA_ROOT.glob("0.*/a2ui-surface*.json"))
A2UI_COMPONENT_SCHEMAS = sorted(SCHEMA_ROOT.glob("0.*/a2ui-component*.json"))


def _has_meta_key(obj) -> bool:
    """True if a ``meta`` KEY appears anywhere in the structure.

    Structural, not a substring search over the serialised JSON: surface ids and
    component text can contain the letters "meta" (``surface-metaprobe``,
    "metadata"), which would report a strip failure that never happened."""
    if isinstance(obj, dict):
        return "meta" in obj or any(_has_meta_key(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_meta_key(v) for v in obj)
    return False


def _minimal_valid_surface(version: str) -> dict:
    """A minimal valid envelope for whichever wire shape ``version`` names.

    v0.8 is not a variant of the v0.9/v0.10 envelope, it is a different one
    (``beginRendering``/``surfaceUpdate``, payload nested under a type-name key),
    so the accept/reject gate below has to build the shape the schema is FOR.
    Asserting the flat shape against every schema would just prove the 0.8
    schema rejects a 0.9 body — which it must, but that is a different claim."""
    if version == "0.8":
        return {
            "version": "0.8",
            "beginRendering": {"root": "c1"},
            "surfaceUpdate": {
                "surfaceId": "s1",
                "components": [{"id": "c1", "Text": {"text": "hello"}}],
            },
        }
    return {
        "version": version,
        "createSurface": {"surfaceId": "s1"},
        "updateComponents": {
            "surfaceId": "s1",
            "root": "c1",
            "components": [{"id": "c1", "component": "Text", "text": "hello"}],
        },
    }


@pytest.mark.parametrize(
    "surface_schema",
    A2UI_SURFACE_SCHEMAS,
    ids=lambda p: str(p.relative_to(SCHEMA_ROOT)),
)
def test_a2ui_surface_schema_accepts_valid_and_rejects_bad(
    surface_schema: Path,
) -> None:
    """Each shipped surface schema (0.8, 0.9, 0.10, …) must accept a minimal
    valid surface at its own version const and reject a bad component — proving
    it is an enforced gate, not just well-formed JSON."""
    version = _load_json(surface_schema)["properties"]["version"]["const"]
    validator = _validator(surface_schema)
    valid = _minimal_valid_surface(version)
    validator.validate(valid)
    bad = json.loads(json.dumps(valid))
    if version == "0.8":
        # Swap the type-name key for one no renderer knows.
        bad["surfaceUpdate"]["components"][0] = {"id": "c1", "NotARealComponent": {}}
    else:
        bad["updateComponents"]["components"][0]["component"] = "NotARealComponent"
    with pytest.raises(ValidationError):
        validator.validate(bad)


@pytest.mark.parametrize(
    "component_schema",
    A2UI_COMPONENT_SCHEMAS,
    ids=lambda p: str(p.relative_to(SCHEMA_ROOT)),
)
def test_a2ui_component_schema_accepts_valid_and_rejects_bad(
    component_schema: Path,
) -> None:
    """Each shipped component schema must accept a known component and reject an
    unknown one directly (not only via the surface $ref).

    Which shape to feed is read off the schema itself — a ``component``
    discriminator property means the flat v0.9/v0.10 form, its absence means the
    v0.8 nested form — so this stays correct without keying off filenames."""
    schema = _load_json(component_schema)
    validator = _validator(component_schema)
    if "component" in schema.get("properties", {}):
        validator.validate({"id": "c1", "component": "Text", "text": "hello"})
        with pytest.raises(ValidationError):
            validator.validate({"id": "c1", "component": "NotARealComponent"})
    else:
        validator.validate({"id": "c1", "Text": {"text": "hello"}})
        with pytest.raises(ValidationError):
            validator.validate({"id": "c1", "NotARealComponent": {}})


# ── (4) Every A2UI version the runtime ADVERTISES has a shipped schema ──

# Known coverage gaps, pinned so they cannot grow silently: an advertised
# version with no schema must either gain one or be named here with a reason.
# EMPTY as of the A2UI 0.8 schema pin — its only entry was "0.8" (the legacy OpenClaw wire shape),
# now covered by schema/0.4/a2ui-surface-v08.json. The mechanism stays so a
# future gap can be declared instead of hidden; the gate below therefore passes
# on merit, not on an excuse.
A2UI_KNOWN_UNSCHEMATIZED: dict[str, str] = {}


def _advertised_a2ui_versions() -> list[str]:
    """The set the runtime advertises in its capabilities. Read from source (no
    heavy chapter_agent import); a change to the advertised list flows through."""
    src = (SERVER_ROOT / "chapter_agent.py").read_text(encoding="utf-8")
    m = re.search(r'"a2ui_versions"\s*:\s*\[([^\]]*)\]', src)
    assert m, "could not find advertised a2ui_versions in chapter_agent.py"
    return re.findall(r'"([^"]+)"', m.group(1))


def test_advertised_a2ui_versions_are_schema_backed() -> None:
    """Every A2UI version the runtime advertises must have a shipped schema
    pinning that version const — except the documented known gaps. Adding a new
    advertised version without a schema breaks this gate (the drift the task
    exists to catch)."""
    advertised = _advertised_a2ui_versions()
    assert advertised, "runtime advertises no a2ui_versions — unexpected"
    schematized = set(_a2ui_schema_by_version())
    for version in advertised:
        assert version in schematized or version in A2UI_KNOWN_UNSCHEMATIZED, (
            f"advertised A2UI version {version!r} has no shipped schema and is not a documented "
            f"known gap — add schema/<dir>/a2ui-surface.json pinning it, or an A2UI_KNOWN_UNSCHEMATIZED entry"
        )


def test_known_unschematized_a2ui_gaps_are_still_advertised_and_still_unschematized() -> (
    None
):
    """Keep the allowlist honest: if a known-gap version stops being advertised,
    OR gains a schema, the allowlist entry is stale and must be removed.

    Vacuous while the allowlist is empty (emptied it) — kept because it is
    what makes a future entry a declaration with an expiry rather than a
    permanent excuse."""
    advertised = set(_advertised_a2ui_versions())
    schematized = set(_a2ui_schema_by_version())
    for version in A2UI_KNOWN_UNSCHEMATIZED:
        assert version in advertised, (
            f"{version} is allowlisted but no longer advertised — drop the entry"
        )
        assert version not in schematized, (
            f"{version} now HAS a schema — drop the allowlist entry, it's covered"
        )


def test_a2ui_08_is_still_advertised_and_is_now_schematized() -> None:
    """INVERSION of the old ``0.8 is advertised and unschematized`` assertion,
    not a deletion of it — a deleted test is an untested claim.

    Both halves matter. 0.8 must STILL be advertised: the openclaw skill's e2e
    requests ``/api/surfaces/dashboard?schema=v0.8`` against the live mesh daily,
    so dropping 0.8 to close the gap would have broken a real consumer. And 0.8
    must now HAVE a schema, so the schema-backed gate above passes because the
    envelope is described, not because it was excused."""
    assert "0.8" in _advertised_a2ui_versions(), (
        "0.8 is no longer advertised — the openclaw skill requests ?schema=v0.8; "
        "closing the A2UI 0.8 schema pin by dropping the version was explicitly rejected"
    )
    assert "0.8" in _a2ui_schema_by_version(), (
        "no shipped schema pins the A2UI 0.8 envelope — The A2UI 0.8 schema pin has regressed"
    )
    assert "0.8" not in A2UI_KNOWN_UNSCHEMATIZED, (
        "0.8 is schematized; an allowlist entry for it would now be a stale excuse"
    )


# ── (5) The A2UI 0.8 downgrade the runtime EMITS conforms to its schema ──


def _real_v08_envelopes() -> dict[str, dict]:
    """v0.8 envelopes produced by the runtime's OWN downgrade path.

    Every case is real ``a2ui_helpers`` output pushed through the real
    ``surfaces.to_v08`` — never a hand-written v0.8 dict, and never derived from
    the docstring, which is prose the code can drift from (it does: it shows
    ``beginRendering: {root}`` unconditionally, while the code emits ``{}`` when
    the source surface has no root — the ``no-root`` case below)."""
    import asyncio

    import a2ui_helpers as a
    import surfaces

    every_component = [
        a.text("t", "hello", "h2"),
        a.badge("b", "live", "secondary", "green"),
        a.progress("pr", 42.5, "done", "green"),
        a.metric("me", "12", "members", "k", "up"),
        a.stat("st", "Members", "12"),
        a.list_component("li", ["a", "b"], True),
        a.avatar("av", "Ann", "https://x/a.png", "sub"),
        a.alert("al", "careful", "Heads up", "warning"),
        a.link("ln", "docs", "https://x/docs"),
        a.image("im", "https://x/i.png", "alt", 10, 20),
        a.divider("dv"),
        a.grid("gr", ["t"], 2),
        a.tabs("tb", [{"label": "One", "child": "t"}]),
        a.card("cd", "gr"),
        a.column("co", ["t"]),
        a.row("ro", ["t"]),
        a.input_field("in", "Name", "type here", "", "text"),
        a.textarea("ta", "Bio", "about you", "", 3),
        a.select("se", "Pick", [{"label": "A", "value": "a"}], "a"),
        a.toggle("tg", "On?", True),
        a.action_button("ab", "Go", "act.go", "default", {"k": "v"}),
        a.form("fo", ["in"], "act.submit", "Send"),
        a.chip("ch", "tag", True, "tag"),
        a.chip_group("cg", ["ch"], True),
        a.toast("to", "saved", "OK", "success"),
        # The 10 v0.9-only components — no v0.8 equivalent, so each MUST come
        # out the far side as a Text node. This is the downgrade branch that a
        # schema written from the docstring would never have exercised.
        a.markdown("md", "## Section"),
        a.heading("hd", 2, "Title"),
        a.code_block("cb", "x = 1", "python"),
        a.accordion("ac", [{"title": "T", "content": "C"}]),
        a.table("tl", ["h1"], [["r1"]], "cap"),
        a.callout("ca", "note", "info", "Title"),
        a.trust_badge("tr", 47.5),
        a.timeline("ti", [{"title": "T", "description": "d"}]),
        a.member_card("mc", "Ann", "ann", "https://x/a.png", "member", 50.0, ["py"], "sub"),
        a.stat_group("sg", [{"label": "L", "value": "V"}]),
    ]

    out = {
        # The same builders the native gate above uses, downgraded.
        name: surfaces.to_v08(env)
        for name, env in _emitted_surfaces().items()
    }
    out["every-component"] = surfaces.to_v08(a.surface("s-all", every_component, "co"))
    # The real dashboard — the page the openclaw skill fetches — carries v0.10
    # `meta` on Row and Input. Since the strict-selector rule the downgrade STRIPS it, so this case
    # is the one that proves the strip against real builder output; the schema
    # rejects a payload that still has it.
    out["dashboard-shape-with-v010-meta-stripped"] = surfaces.to_v08(
        a.surface(
            "surface-dashboard",
            [
                a.with_meta(
                    a.row("dash-stats", ["dash-members"]),
                    responsive={"stackBelow": "md"},
                ),
                a.with_meta(
                    a.input_field("dash-intent-input", "Describe your need", "e.g. Rust", "", "text"),
                    a11y={"ariaLabel": "Describe what you are looking for"},
                ),
                a.metric("dash-members", "5", "Members"),
            ],
            "dash-stats",
        )
    )
    # A component type in neither downgrade table falls back to Text/caption.
    out["unknown-component-fallback"] = surfaces.to_v08(
        a.surface("s-unk", [{"id": "u", "component": "NotAThing", "x": 1}], "u")
    )
    # No root → beginRendering is {}, which is why `root` is not required.
    out["no-root"] = surfaces.to_v08(
        {"updateComponents": {"surfaceId": "s", "root": None, "components": []}}
    )
    # End-to-end through the real ?schema=v0.8 selector, not just the transform:
    # the unknown-page error surface is the one real surface that needs no DB.
    out["get_surface-selector"] = asyncio.run(
        surfaces.get_surface("no-such-page-id", schema="v0.8")
    )
    return out


@pytest.mark.parametrize("case", sorted(_real_v08_envelopes().keys()))
def test_emitted_a2ui_08_downgrade_conforms_to_its_schema(case: str) -> None:
    """Real downgraded output validates against the shipped 0.8 schema.

    Before this the runtime advertised A2UI 0.8 and served it via ``?schema=v0.8``
    with nothing able to validate it — an advertised surface with no fail-on-drift
    gate."""
    env = _real_v08_envelopes()[case]
    assert env.get("version") == "0.8", f"{case} is not a v0.8 envelope"
    schemas = _a2ui_schema_by_version()
    assert "0.8" in schemas, "no shipped schema pins A2UI 0.8"
    validator = _validator(schemas["0.8"])
    errors = sorted(validator.iter_errors(env), key=str)
    assert not errors, (
        f"{case} emitted a non-conformant A2UI 0.8 surface: "
        f"{errors[0].json_path}: {errors[0].message}"
    )


def test_real_v08_output_carries_no_meta() -> None:
    """the v0.8 wire has no ``meta``, proven on real output.

    The schema rejects it, but only if a case actually exercises it — so this
    states the claim positively against the surface that carries ``meta``
    natively (the dashboard shape), and confirms the fixture is still capable of
    failing. Three documents said the strip happened while the code never did
    it; a test is what makes them agree from now on."""
    import a2ui_helpers as a
    import surfaces

    source = a.surface(
        "surface-dashboard",
        [a.with_meta(a.row("r", ["t"]), responsive={"stackBelow": "md"}), a.text("t", "hi", "body")],
        "r",
    )
    assert _has_meta_key(source), "fixture no longer carries meta — it proves nothing"

    for case, env in _real_v08_envelopes().items():
        assert not _has_meta_key(env), f"{case} carried meta onto the v0.8 wire"
    assert not _has_meta_key(surfaces.to_v08(source))


def test_every_v09_only_component_degrades_to_text_in_real_output() -> None:
    """The Text-downgrade path is covered by real output, not asserted in prose.

    All 10 v0.9-only components must arrive as ``{id, Text: {...}}``: any of them
    surviving under its own type-name key would be schema-rejected above, but
    this states the positive claim so a downgrade that silently DROPPED them
    (also schema-valid — the array would just be shorter) still fails."""
    import surfaces

    env = _real_v08_envelopes()["every-component"]
    by_id = {c["id"]: c for c in env["surfaceUpdate"]["components"]}
    v09_only_ids = {
        "md": "Markdown", "hd": "Heading", "cb": "CodeBlock", "ac": "Accordion",
        "tl": "Table", "ca": "Callout", "tr": "TrustBadge", "ti": "Timeline",
        "mc": "MemberCard", "sg": "StatGroup",
    }
    assert set(v09_only_ids.values()) == set(surfaces._V09_ONLY), (
        "this test's fixture no longer covers every v0.9-only component — "
        f"runtime table: {sorted(surfaces._V09_ONLY)}"
    )
    for comp_id, type_name in v09_only_ids.items():
        assert comp_id in by_id, f"{type_name} was dropped by the downgrade, not degraded"
        comp = by_id[comp_id]
        assert "Text" in comp, f"{type_name} did not degrade to Text: {comp}"
        assert comp["Text"]["text"].startswith(f"[{type_name}]"), (
            f"{type_name} degraded without its [{type_name}] prefix: {comp}"
        )


V08_MALFORMED_CASES = {
    "wrong-version-const": lambda e: e | {"version": "0.9"},
    "v09-flat-discriminator": lambda e: _with_components(
        e, [{"id": "c1", "component": "Text", "text": "x"}]
    ),
    "v09-only-type-key-not-degraded": lambda e: _with_components(
        e, [{"id": "h", "Heading": {"text": "x", "level": 1}}]
    ),
    "two-type-keys": lambda e: _with_components(
        e, [{"id": "c1", "Text": {"text": "x"}, "Badge": {"text": "y"}}]
    ),
    "no-type-key": lambda e: _with_components(e, [{"id": "c1"}]),
    "unknown-type-key": lambda e: _with_components(e, [{"id": "c1", "NotAThing": {}}]),
    "unknown-payload-field": lambda e: _with_components(
        e, [{"id": "c1", "Text": {"text": "x", "bogus": 1}}]
    ),
    "payload-missing-required-field": lambda e: _with_components(
        e, [{"id": "c1", "Text": {"usageHint": "body"}}]
    ),
    "bad-usage-hint": lambda e: _with_components(
        e, [{"id": "c1", "Text": {"text": "x", "usageHint": "huge"}}]
    ),
    "bad-meta-namespace": lambda e: _with_components(
        e, [{"id": "c1", "Text": {"text": "x", "meta": {"nope": {}}}}]
    ),
    "missing-surface-update": lambda e: {
        k: v for k, v in e.items() if k != "surfaceUpdate"
    },
    "v09-envelope-keys-present": lambda e: e
    | {"updateComponents": {"surfaceId": "s1", "root": "c1", "components": []}},
    "surface-update-missing-surface-id": lambda e: e
    | {"surfaceUpdate": {"components": []}},
    "empty-component-id": lambda e: _with_components(
        e, [{"id": "", "Text": {"text": "x"}}]
    ),
}


def _with_components(env: dict, components: list[dict]) -> dict:
    return env | {"surfaceUpdate": env["surfaceUpdate"] | {"components": components}}


@pytest.mark.parametrize("case", sorted(V08_MALFORMED_CASES))
def test_a2ui_08_schema_rejects_malformed_envelopes(case: str) -> None:
    """The negative side of the A2UI 0.8 schema pin: a schema that only ever accepts proves nothing.

    Each case is a way the downgrade could realistically go wrong — emitting the
    v0.9 flat discriminator, letting a v0.9-only type reach the wire undegraded,
    or the two envelopes' keys bleeding into each other — and each must FAIL."""
    validator = _validator(_a2ui_schema_by_version()["0.8"])
    valid = _minimal_valid_surface("0.8")
    validator.validate(valid)  # control: the base instance really is valid
    malformed = V08_MALFORMED_CASES[case](json.loads(json.dumps(valid)))
    assert list(validator.iter_errors(malformed)), (
        f"the 0.8 schema ACCEPTED a malformed envelope ({case}) — it is not a gate"
    )


def test_a2ui_08_component_schema_covers_exactly_the_runtime_passthrough_set() -> None:
    """The schema's permitted type keys are the runtime's own downgrade table.

    ``surfaces._V09_TO_V08_PASSTHROUGH`` is what actually reaches the v0.8 wire
    under its own type-name key. If a component is added there without a schema
    def (or vice versa), the two have drifted and this fails — the coupling is
    checked mechanically instead of being remembered."""
    import surfaces

    schema = _load_json(SCHEMA_ROOT / "0.4" / "a2ui-component-v08.json")
    schema_types = set(schema["properties"]) - {"id"}
    assert schema_types == set(surfaces._V09_TO_V08_PASSTHROUGH), (
        "v0.8 component schema and the runtime passthrough table disagree: "
        f"schema-only={sorted(schema_types - surfaces._V09_TO_V08_PASSTHROUGH)} "
        f"runtime-only={sorted(surfaces._V09_TO_V08_PASSTHROUGH - schema_types)}"
    )


#: Fields the v0.8 downgrade removes from a native component's payload: the two
#: v0.9 discriminator fields, plus ``meta`` since the strict-selector rule strips it.
_V08_DROPPED_FIELDS = ("id", "component", "meta")


def test_a2ui_08_payloads_are_the_native_defs_minus_the_discriminator() -> None:
    """v0.8 payload rules are DERIVED from the native 0.10 defs, and stay so.

    The downgrade copies the payload verbatim except for the fields in
    ``_V08_DROPPED_FIELDS`` (``surfaces.to_v08``:
    ``{k: v for k, v in c.items() if k not in ("id", "component", "meta")}``), so
    each v0.8 payload schema must equal the native per-type def with exactly
    those removed. Re-deriving it here means widening a native component without
    widening its v0.8 twin fails CI rather than producing a v0.8 envelope nothing
    describes."""
    native = _load_json(SCHEMA_ROOT / "0.4" / "a2ui-component.json")
    v08 = _load_json(SCHEMA_ROOT / "0.4" / "a2ui-component-v08.json")

    for type_name in set(v08["properties"]) - {"id"}:
        expected = {
            key: (
                {k: v for k, v in val.items() if k not in _V08_DROPPED_FIELDS}
                if key == "properties"
                else [r for r in val if r not in _V08_DROPPED_FIELDS]
                if key == "required"
                else val
            )
            for key, val in native["$defs"][type_name].items()
        }
        assert v08["$defs"][type_name] == expected, (
            f"v0.8 payload def for {type_name} is not the native def minus "
            f"{_V08_DROPPED_FIELDS} — the downgrade passes the payload through "
            f"verbatim apart from those, so they cannot legitimately differ"
        )

    # Shared defs are $ref'd by the per-type defs above; they must be copies too.
    # The Meta* defs are deliberately NOT among them any more: no v0.8
    # payload can carry `meta`, so shipping its schema here would suggest one can.
    for shared in ("idRef", "childrenArray"):
        assert v08["$defs"][shared] == native["$defs"][shared], (
            f"shared def {shared} diverged from the native component schema"
        )
    assert not [d for d in v08["$defs"] if d.startswith("Meta")], (
        "the v0.8 component schema still ships Meta defs — nothing can reference "
        "them now that meta is stripped; a dangling def reads as support"
    )


def test_a2ui_08_schema_rejects_meta_on_a_payload() -> None:
    """The strict-selector rule's schema half: `meta` on a v0.8 payload must be REJECTED.

    Before the strict-selector rule this schema deliberately PERMITTED `meta`, because the runtime
    passed it through and a schema must describe what is emitted. Now the runtime
    strips it, so permitting it would leave the schema describing reality in the
    other direction."""
    validator = _validator(_a2ui_schema_by_version()["0.8"])
    envelope = _minimal_valid_surface("0.8")
    validator.validate(envelope)
    envelope["surfaceUpdate"]["components"][0]["Text"]["meta"] = {
        "responsive": {"stackBelow": "md"}
    }
    assert list(validator.iter_errors(envelope)), (
        "the 0.8 schema accepted a payload carrying `meta` — The strict-selector rule says the v0.8 "
        "wire has none, so this is not a gate any more"
    )


def test_advertised_a2ui_versions_match_the_runtime_emittable_set() -> None:
    """The advertised set and the set the code can EMIT are the same list.

    This is the strict-selector rule's root cause as a gate: ``a2ui_versions`` said 0.8/0.9/0.10
    while ``_maybe_downgrade`` implemented only 0.8, and nothing compared the
    two — so an advertised version that did nothing looked fine for months.
    The literal in ``chapter_agent.py`` stays a literal (the discovery above
    reads it from source without importing the app); this test is what keeps it
    honest."""
    import surfaces

    assert set(_advertised_a2ui_versions()) == set(surfaces.A2UI_EMITTABLE_VERSIONS), (
        "advertised a2ui_versions != surfaces.A2UI_EMITTABLE_VERSIONS: "
        f"advertised-only={sorted(set(_advertised_a2ui_versions()) - set(surfaces.A2UI_EMITTABLE_VERSIONS))} "
        f"emittable-only={sorted(set(surfaces.A2UI_EMITTABLE_VERSIONS) - set(_advertised_a2ui_versions()))}"
    )


@pytest.mark.parametrize("version", sorted(_advertised_a2ui_versions()))
def test_every_advertised_a2ui_version_is_actually_emitted(version: str) -> None:
    """Asking for an advertised version returns THAT version.

    The behavioural counterpart to ``test_advertised_a2ui_versions_are_schema_backed``:
    a schema proves the shape is described, this proves the runtime honours the
    selector. It is the check the strict-selector rule needed and did not have — ``?schema=v0.9`` was
    accepted and then ignored, so callers asking for 0.9 were handed 0.10.
    Exercised through the real selector for both the ``v``-prefixed and bare
    forms, since clients send both."""
    import a2ui_helpers as a
    import surfaces

    native = a.surface("s", [a.text("t", "hello", "body")], "t")
    for selector in (f"v{version}", version):
        out = surfaces._maybe_downgrade(native, selector)
        assert out["version"] == version, (
            f"?schema={selector} returned version {out.get('version')!r}, not {version!r} "
            f"— an advertised version that silently answers with another one is the strict-selector rule"
        )


@pytest.mark.parametrize("selector", ["v0.7", "0.11", "0.9.1", "junk", "v1.0", "10"])
def test_unrecognised_a2ui_selector_is_refused_not_defaulted(selector: str) -> None:
    """An unknown ``?schema=`` raises rather than falling through (the strict-selector rule's floor).

    Silently serving the default version to a caller that named a different one
    is the actual defect — worse than an unimplemented feature, because the
    caller cannot tell."""
    import surfaces

    with pytest.raises(surfaces.UnsupportedSchemaVersion):
        surfaces.normalize_schema_selector(selector)


def test_real_v09_downgrade_conforms_to_the_shipped_v09_schema() -> None:
    """``?schema=v0.9`` output validates against schema/0.3.

    spec/0.4/a2ui.md §8 item 3 requires a v0.9 envelope with every ``meta``
    stripped, and schema/0.3 declares ``additionalProperties: false`` per type —
    so validating REAL downgraded output against the v0.9 schema is the
    mechanical proof of both halves at once. Fed from the meta-carrying surface,
    which is the only input that can fail."""
    import a2ui_helpers as a
    import surfaces

    native = a.surface(
        "surface-dashboard",
        [
            a.with_meta(a.row("r", ["m"]), responsive={"stackBelow": "md"}),
            a.with_meta(a.metric("m", "5", "Members"), a11y={"ariaLabel": "member count"}),
        ],
        "r",
    )
    assert _has_meta_key(native), "fixture no longer carries meta — it proves nothing"

    v09 = surfaces.to_v09(native)
    assert v09["version"] == "0.9"
    assert not _has_meta_key(v09), f"meta survived the v0.9 strip: {v09}"

    schemas = _a2ui_schema_by_version()
    assert "0.9" in schemas, "no shipped schema pins A2UI 0.9"
    errors = sorted(_validator(schemas["0.9"]).iter_errors(v09), key=str)
    assert not errors, (
        f"real ?schema=v0.9 output is not conformant v0.9: "
        f"{errors[0].json_path}: {errors[0].message}"
    )


def test_v09_and_v08_strips_do_not_mutate_the_source_surface() -> None:
    """Neither downgrade may mutate its input (hazard).

    ``get_surface`` memoises built surfaces in ``surface_cache`` and downgrades
    the CACHED object per request, so an in-place strip would serve a later
    native request a meta-less surface out of the cache — one client's selector
    silently changing another's response."""
    import a2ui_helpers as a
    import surfaces

    native = a.surface(
        "s", [a.with_meta(a.row("r", ["t"]), responsive={"stackBelow": "md"}),
              a.text("t", "hi", "body")], "r"
    )
    before = json.dumps(native, sort_keys=True)
    surfaces.to_v09(native)
    surfaces.to_v08(native)
    assert json.dumps(native, sort_keys=True) == before, (
        "a downgrade mutated the source surface — the cache would then serve it"
    )


def test_downgrade_tables_partition_the_native_component_vocabulary() -> None:
    """Every native component is classified as passthrough OR v0.9-only.

    A component in neither table takes ``to_v08``'s last-resort branch and
    reaches OpenClaw as ``[TypeName]`` caption text — a silent content loss that
    is still schema-valid, so only this check catches it. Adding a component to
    ``a2ui_helpers`` without classifying it here fails."""
    import surfaces

    native_enum = set(
        _load_json(SCHEMA_ROOT / "0.4" / "a2ui-component.json")["properties"][
            "component"
        ]["enum"]
    )
    passthrough = set(surfaces._V09_TO_V08_PASSTHROUGH)
    v09_only = set(surfaces._V09_ONLY)
    assert not passthrough & v09_only, (
        f"components in both downgrade tables: {sorted(passthrough & v09_only)}"
    )
    assert passthrough | v09_only == native_enum, (
        "downgrade tables do not cover the native component vocabulary — "
        f"unclassified={sorted(native_enum - passthrough - v09_only)} "
        f"not-a-real-component={sorted((passthrough | v09_only) - native_enum)}"
    )
