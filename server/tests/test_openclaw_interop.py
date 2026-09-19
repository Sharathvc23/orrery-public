"""
R1-R10 adversarial + behavioral tests for OpenClaw interop.

Covers two surfaces introduced in feat/openclaw-interop:
  1. MemberRegistration.origin field + /api/members handling
  2. surfaces.to_v08 + /api/surfaces/{page_id}?schema=v0.8 transform

Per R1-R10 convention (nanda-bridge ordering): adversarial tests first,
happy-path tests last.

  R1  Forgery            — malformed / unauthorized origin claims
  R2  Replay             — origin immutability under re-registration
  R3  Injection          — origin value sanitization
  R4  Authorization      — origin cannot be upgraded by claimant
  R5  Boundary           — empty, whitespace, case sensitivity
  R6  Concurrency        — registration idempotence (origin stays)
  R7  Adversarial input  — unicode, control chars, long payloads
  R8  Downgrade          — v0.8 transform preserves semantics
  R9  Timing             — no info leak in origin rejection
  R10 Persistence        — transform output has documented shape
"""

from __future__ import annotations

import os

# Ensure env-required module-level constants resolve when .env is absent
# (the agents/ mirror directory has no .env; chapter_agent.py calls
# os.environ["AGENT_ID"] at import time).
os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import chapter_agent  # noqa: E402
import surfaces  # noqa: E402

# ── Shared setup ──────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolate_members(monkeypatch):
    """Each test gets a fresh members dict."""
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")
    yield


def _make_reg(agent_id="alice", origin="sovereign", **kwargs):
    return chapter_agent.MemberRegistration(
        agent_id=agent_id,
        name=kwargs.get("name", "Alice"),
        origin=origin,
        **{k: v for k, v in kwargs.items() if k != "name"},
    )


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: claimed origin values that aren't in the allowlist
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R1_forgery_rejects_unknown_origin():
    result = await chapter_agent.register_member(_make_reg(origin="sovereign_admin"))
    assert "error" in result
    assert "invalid origin" in result["error"].lower()


@pytest.mark.asyncio
async def test_R1_forgery_rejects_sql_like_origin():
    result = await chapter_agent.register_member(_make_reg(origin="sovereign'; DROP TABLE agents;--"))
    assert "error" in result


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay: re-registration preserves original origin
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R2_replay_re_register_same_origin_ok():
    r1 = await chapter_agent.register_member(_make_reg(origin="openclaw"))
    assert r1.get("registered") is True
    r2 = await chapter_agent.register_member(_make_reg(origin="openclaw"))
    assert r2.get("registered") is True
    assert r2["origin"] == "openclaw"


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: origin field rejects payloads that sneak past sanitization
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R3_injection_null_byte_rejected():
    result = await chapter_agent.register_member(_make_reg(origin="sovereign\x00openclaw"))
    assert "error" in result


@pytest.mark.asyncio
async def test_R3_injection_html_tag_rejected():
    result = await chapter_agent.register_member(_make_reg(origin="<script>alert(1)</script>"))
    assert "error" in result


# ══════════════════════════════════════════════════════════════════════
# R4 — Authorization: cannot upgrade openclaw → sovereign by re-registering
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R4_authz_cannot_upgrade_origin():
    # First register as openclaw
    r1 = await chapter_agent.register_member(_make_reg(origin="openclaw"))
    assert r1["origin"] == "openclaw"
    # Attempt to re-register the SAME agent_id as sovereign — should be blocked
    r2 = await chapter_agent.register_member(_make_reg(origin="sovereign"))
    assert "error" in r2
    assert "origin mismatch" in r2["error"]
    assert r2.get("existing_origin") == "openclaw"


@pytest.mark.asyncio
async def test_R4_authz_cannot_downgrade_either():
    """Symmetry check — sovereign can't be re-registered as openclaw_sandboxed."""
    r1 = await chapter_agent.register_member(_make_reg(origin="sovereign"))
    assert r1["origin"] == "sovereign"
    r2 = await chapter_agent.register_member(_make_reg(origin="openclaw_sandboxed"))
    assert "error" in r2


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: empty, whitespace, case-folding
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R5_boundary_empty_origin_defaults_to_sovereign():
    # Empty string should coerce via default to "sovereign" or explicit validation
    result = await chapter_agent.register_member(_make_reg(origin=""))
    # Empty → falls through to "sovereign" default behavior
    assert result.get("registered") is True
    assert result.get("origin") == "sovereign"


@pytest.mark.asyncio
async def test_R5_boundary_whitespace_origin_normalized():
    result = await chapter_agent.register_member(_make_reg(origin="  openclaw  "))
    assert result.get("origin") == "openclaw"


@pytest.mark.asyncio
async def test_R5_boundary_uppercase_origin_normalized():
    result = await chapter_agent.register_member(_make_reg(origin="OPENCLAW"))
    assert result.get("origin") == "openclaw"


# ══════════════════════════════════════════════════════════════════════
# R6 — Concurrency: registration idempotent on origin when same values
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R6_concurrency_idempotent_same_origin():
    import asyncio

    results = await asyncio.gather(
        chapter_agent.register_member(_make_reg(agent_id="bob", origin="openclaw")),
        chapter_agent.register_member(_make_reg(agent_id="bob", origin="openclaw")),
        chapter_agent.register_member(_make_reg(agent_id="bob", origin="openclaw")),
    )
    # All three should succeed; members["bob"] should have origin=openclaw
    assert all(r.get("origin") == "openclaw" for r in results)
    assert chapter_agent.members["bob"]["origin"] == "openclaw"


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial input: long payload, unicode
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R7_adversarial_long_origin_rejected():
    result = await chapter_agent.register_member(_make_reg(origin="sovereign" * 10000))
    assert "error" in result


@pytest.mark.asyncio
async def test_R7_adversarial_unicode_lookalike_rejected():
    # Cyrillic "о" looks like Latin "o"
    result = await chapter_agent.register_member(_make_reg(origin="sоvereign"))
    assert "error" in result


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: v0.8 transform preserves structure
# ══════════════════════════════════════════════════════════════════════


def test_R8_downgrade_v08_envelope_shape():
    v09 = {
        "createSurface": {"surfaceId": "surface-test"},
        "updateComponents": {
            "surfaceId": "surface-test",
            "root": "page",
            "components": [
                {"id": "page", "component": "Card", "child": "root"},
                {"id": "root", "component": "Column", "children": ["h"]},
                {"id": "h", "component": "Text", "text": "hi", "usageHint": "h1"},
            ],
        },
        "version": "0.9",
    }
    v08 = surfaces.to_v08(v09)

    assert v08["version"] == "0.8"
    assert "beginRendering" in v08
    assert v08["beginRendering"]["root"] == "page"
    assert "surfaceUpdate" in v08
    assert v08["surfaceUpdate"]["surfaceId"] == "surface-test"
    # v0.8 components wrap payload under type-name key
    comps = v08["surfaceUpdate"]["components"]
    assert len(comps) == 3
    # Text component in v0.8 shape: {id, Text: {text, usageHint}}
    text_comp = [c for c in comps if c["id"] == "h"][0]
    assert "Text" in text_comp
    assert text_comp["Text"]["text"] == "hi"
    assert text_comp["Text"]["usageHint"] == "h1"


def _has_meta_key(obj) -> bool:
    """True if a ``meta`` KEY appears anywhere in the structure.

    Structural on purpose: a substring search for "meta" matches surface ids
    like ``surface-metaprobe`` and any component text containing "metadata",
    so it would report a strip failure that did not happen."""
    if isinstance(obj, dict):
        return "meta" in obj or any(_has_meta_key(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_meta_key(v) for v in obj)
    return False


def _v08_surface_validator():
    """Validator for the shipped A2UI 0.8 envelope schema.

    Built here rather than imported from conformance/ so the HTTP boundary is
    gated in the suite that owns the endpoint: the schema is only worth shipping
    if what the route actually returns satisfies it."""
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    schema_dir = Path(__file__).resolve().parents[2] / "schema" / "0.4"
    resources = []
    for path in sorted(schema_dir.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc)))
    return Draft202012Validator(
        json.loads((schema_dir / "a2ui-surface-v08.json").read_text(encoding="utf-8")),
        registry=Registry().with_resources(resources),
    )


def test_R8_downgrade_http_schema_v08_returns_a_conformant_v08_envelope():
    """``?schema=v0.8`` over HTTP still returns a v0.8 envelope, and it conforms.

    The openclaw skill's e2e does exactly this (``GET /api/surfaces/dashboard
    ?schema=v0.8``) against the live mesh daily, so this asserts the selector at
    the route — not just ``to_v08`` in isolation — and pins the response against
    the schema shipped for the A2UI 0.8 schema pin. The unknown-page error surface is used because
    it is the one real surface that needs no database, so the assertion is about
    the wire shape and nothing else."""
    from fastapi.testclient import TestClient

    client = TestClient(chapter_agent.app)
    resp = client.get("/api/surfaces/no-such-page-id?schema=v0.8")
    assert resp.status_code == 200
    body = resp.json()

    assert body["version"] == "0.8"
    assert "beginRendering" in body and "surfaceUpdate" in body
    # v0.9/v0.10 envelope keys must NOT leak into the downgraded response.
    assert "createSurface" not in body
    assert "updateComponents" not in body

    errors = sorted(_v08_surface_validator().iter_errors(body), key=str)
    assert not errors, (
        f"GET ?schema=v0.8 returned a non-conformant A2UI 0.8 envelope: "
        f"{errors[0].json_path}: {errors[0].message}"
    )


def test_R8_downgrade_v08_wire_carries_no_meta():
    """the v0.8 response strips the v0.10 ``meta`` block.

    spec/0.4/a2ui.md §8 item 4 and skill/SKILL.md:54 both state a v0.8 response
    carries no ``meta``; the code never stripped it, so live dashboards shipped
    it on Row and Input against two documented contracts. Asserted at the route
    on a surface that carries ``meta`` natively — the error surface has none, so
    it could not have caught this."""
    from fastapi.testclient import TestClient

    import a2ui_helpers as a
    import surfaces

    async def build_metaprobe(target=None):
        return a.surface(
            "surface-metaprobe",
            [
                a.with_meta(a.row("r", ["m"]), responsive={"stackBelow": "md"}),
                a.with_meta(a.metric("m", "5", "Members"), a11y={"ariaLabel": "member count"}),
            ],
            "r",
        )

    surfaces.SURFACE_BUILDERS["metaprobe"] = build_metaprobe
    try:
        client = TestClient(chapter_agent.app)
        native = client.get("/api/surfaces/metaprobe").json()
        assert _has_meta_key(native), "the fixture surface must carry meta natively"

        v08 = client.get("/api/surfaces/metaprobe?schema=v0.8").json()
        assert v08["version"] == "0.8"
        assert not _has_meta_key(v08), f"meta reached the v0.8 wire: {v08}"
        errors = sorted(_v08_surface_validator().iter_errors(v08), key=str)
        assert not errors, f"{errors[0].json_path}: {errors[0].message}"
    finally:
        surfaces.SURFACE_BUILDERS.pop("metaprobe", None)


def test_R8_downgrade_v09_selector_returns_a_real_v09_envelope():
    """``?schema=v0.9`` returns v0.9, not the native v0.10.

    The selector was accepted and then ignored — a caller asking for 0.9 got 0.10
    byte-identically, i.e. a silent wrong answer. spec/0.4/a2ui.md §8 item 3 and
    protocol.md:15 make honouring it a MUST for a v0.4 chapter, and this chapter
    advertises 0.4 and 0.5."""
    from fastapi.testclient import TestClient

    import a2ui_helpers as a
    import surfaces

    async def build_metaprobe(target=None):
        return a.surface(
            "surface-metaprobe",
            [a.with_meta(a.row("r", ["t"]), responsive={"stackBelow": "md"}), a.text("t", "hi", "body")],
            "r",
        )

    surfaces.SURFACE_BUILDERS["metaprobe"] = build_metaprobe
    try:
        client = TestClient(chapter_agent.app)
        v09 = client.get("/api/surfaces/metaprobe?schema=v0.9").json()

        assert v09["version"] == "0.9", f"?schema=v0.9 returned {v09.get('version')!r}"
        # Same envelope as native — v0.10 is an additive minor over v0.9 …
        assert "createSurface" in v09 and "updateComponents" in v09
        assert "surfaceUpdate" not in v09
        # … with every meta block gone, deeply (spec §10.2).
        assert not _has_meta_key(v09), f"meta survived ?schema=v0.9: {v09}"

        # The bare form works too — clients send both.
        assert client.get("/api/surfaces/metaprobe?schema=0.9").json()["version"] == "0.9"
    finally:
        surfaces.SURFACE_BUILDERS.pop("metaprobe", None)


def test_R8_downgrade_v09_selector_does_not_poison_the_native_cache():
    """A selector must not change what the NEXT caller gets.

    ``get_surface`` memoises the built surface and downgrades the cached object,
    so an in-place strip would serve a later native request the meta-less
    surface — one client's ``?schema=`` silently rewriting another's response.
    The metaprobe page is cacheable (not in ``_UNCACHED_SURFACES``), so the
    second request here is a cache hit."""
    from fastapi.testclient import TestClient

    import a2ui_helpers as a
    import surfaces

    async def build_metaprobe(target=None):
        return a.surface(
            "surface-metaprobe",
            [a.with_meta(a.row("r", ["t"]), responsive={"stackBelow": "md"}), a.text("t", "hi", "body")],
            "r",
        )

    surfaces.SURFACE_BUILDERS["metaprobe"] = build_metaprobe
    try:
        client = TestClient(chapter_agent.app)
        assert _has_meta_key(client.get("/api/surfaces/metaprobe").json())
        client.get("/api/surfaces/metaprobe?schema=v0.9")
        client.get("/api/surfaces/metaprobe?schema=v0.8")
        after = client.get("/api/surfaces/metaprobe").json()
        assert _has_meta_key(after), (
            "the native response lost its meta after a downgrade request — "
            "the strip mutated the cached surface"
        )
        assert after["version"] == "0.10"
    finally:
        surfaces.SURFACE_BUILDERS.pop("metaprobe", None)


def test_R8_downgrade_v010_selector_returns_the_native_envelope():
    """``?schema=v0.10`` is the native version, explicitly honoured rather than
    accidentally correct by falling through to the default."""
    from fastapi.testclient import TestClient

    client = TestClient(chapter_agent.app)
    for selector in ("v0.10", "0.10"):
        body = client.get(f"/api/surfaces/no-such-page-id?schema={selector}").json()
        assert body["version"] == "0.10"
        assert "createSurface" in body


@pytest.mark.parametrize("selector", ["v0.7", "0.11", "0.9.1", "junk", "v1.0", "10", "v"])
def test_R8_downgrade_unrecognised_selector_is_a_400_not_a_silent_default(selector):
    """The strict-selector rule's floor: an unknown ``?schema=`` is a 400, never the default version.

    ADVERSARIAL/FAILURE: before this, every one of these values returned a 200
    carrying v0.10 — a caller that asked for something else could not tell it had
    been ignored. The error names the closed set so the client can recover."""
    from fastapi.testclient import TestClient

    client = TestClient(chapter_agent.app)
    resp = client.get(f"/api/surfaces/no-such-page-id?schema={selector}")
    assert resp.status_code == 400, f"schema={selector!r} returned {resp.status_code}"
    body = resp.json()
    assert body["error"] == "unsupported_a2ui_version"
    assert body["requested"] == selector
    assert body["supported"] == ["0.8", "0.9", "0.10"]


def test_R8_downgrade_unrecognised_selector_on_the_stream_is_also_a_400():
    """The SSE variant must refuse before the stream opens.

    Once StreamingResponse is returned the status line is 200, so a late
    rejection could only be an in-band event the consumer may never surface —
    the same silence the strict-selector rule is about, one layer down."""
    from fastapi.testclient import TestClient

    client = TestClient(chapter_agent.app)
    resp = client.get("/api/surfaces/no-such-page-id/stream?schema=v0.7&max_iterations=1")
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_a2ui_version"
    assert "text/event-stream" not in resp.headers.get("content-type", "")


def test_R8_downgrade_stream_still_serves_a_recognised_selector():
    """The stream's new guard must not break the selector it does support."""
    from fastapi.testclient import TestClient

    client = TestClient(chapter_agent.app)
    resp = client.get("/api/surfaces/no-such-page-id/stream?schema=v0.8&max_iterations=1")
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("content-type", "")
    assert '"version":"0.8"' in resp.text.replace(" ", "")


def test_R8_strip_meta_is_deep_and_removes_empty_blocks():
    """spec/0.4/a2ui.md §10.2: the strip is deep and an empty ``meta: {}`` goes too.

    Byte-equivalence with a v0.9-native emission is the requirement, and
    ``schema/0.3`` declares ``additionalProperties: false``, so a surviving empty
    block is just as non-conformant as a populated one. Surface-level
    ``createSurface.meta`` is covered here because ``schema/0.3``'s
    ``createSurface`` forbids it too."""
    stripped = surfaces.strip_meta(
        {
            "createSurface": {"surfaceId": "s", "meta": {"density": {"preferred": "compact"}}},
            "updateComponents": {
                "surfaceId": "s",
                "root": "r",
                "components": [
                    {"id": "r", "component": "Row", "children": ["t"], "meta": {}},
                    {"id": "t", "component": "Text", "text": "hi", "meta": {"a11y": {"ariaLabel": "x"}}},
                ],
            },
            "version": "0.10",
        }
    )
    assert stripped["createSurface"] == {"surfaceId": "s"}
    assert all("meta" not in c for c in stripped["updateComponents"]["components"])
    # Everything else is preserved verbatim — the strip is not a rebuild.
    assert stripped["updateComponents"]["root"] == "r"
    assert stripped["updateComponents"]["components"][1]["text"] == "hi"


def test_R8_downgrade_is_opt_in_native_response_is_unchanged():
    """The selector is a selector: without ``?schema=v0.8`` the same page returns
    the native envelope. A downgrade that applied unconditionally would satisfy
    the test above while breaking every v0.9/v0.10 consumer."""
    from fastapi.testclient import TestClient

    client = TestClient(chapter_agent.app)
    body = client.get("/api/surfaces/no-such-page-id").json()
    assert body["version"] != "0.8"
    assert "createSurface" in body and "updateComponents" in body
    assert "surfaceUpdate" not in body


def test_R8_downgrade_v08_stays_in_the_advertised_version_set():
    """``/api/version`` must keep advertising 0.8. The skill reads this set to
    decide it may ask for ``?schema=v0.8``; dropping the version was the other
    way to close the A2UI 0.8 schema pin and was explicitly rejected because it breaks the skill."""
    from fastapi.testclient import TestClient

    client = TestClient(chapter_agent.app)
    body = client.get("/api/version").json()
    assert "0.8" in body["a2ui_versions"], (
        f"0.8 is no longer advertised: {body.get('a2ui_versions')}"
    )


def test_R8_downgrade_v09_only_components_degrade_to_text():
    """Markdown, Heading, etc. have no v0.8 equivalent — degrade to Text."""
    v09 = {
        "updateComponents": {
            "surfaceId": "s",
            "root": "r",
            "components": [
                {"id": "r", "component": "Column", "children": ["m", "cb"]},
                {"id": "m", "component": "Markdown", "text": "# Heading"},
                {"id": "cb", "component": "CodeBlock", "text": "x = 1"},
            ],
        },
        "version": "0.9",
    }
    v08 = surfaces.to_v08(v09)
    comps = v08["surfaceUpdate"]["components"]
    m_comp = [c for c in comps if c["id"] == "m"][0]
    # Markdown degraded to Text with [Markdown] prefix
    assert "Text" in m_comp
    assert "[Markdown]" in m_comp["Text"]["text"]
    cb_comp = [c for c in comps if c["id"] == "cb"][0]
    assert "Text" in cb_comp
    assert "[CodeBlock]" in cb_comp["Text"]["text"]


# ══════════════════════════════════════════════════════════════════════
# R9 — Timing: all origin-rejection paths return quickly + similarly
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R9_timing_all_invalid_origins_return_same_error_shape():
    import time

    bad_origins = ["admin", "root", "xxx", "a" * 100]
    timings = []
    for bad in bad_origins:
        t0 = time.monotonic()
        r = await chapter_agent.register_member(_make_reg(agent_id=f"t-{bad[:5]}", origin=bad))
        t1 = time.monotonic()
        assert "error" in r, f"origin={bad!r} should have failed"
        timings.append(t1 - t0)
    # All rejections should complete within ~10ms of each other
    # (no DB call reached, no remote work; timing should be tight)
    assert max(timings) - min(timings) < 0.05


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: transform output shape is stable
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_empty_components_produces_valid_shape():
    v09 = {"updateComponents": {"surfaceId": "empty", "root": None, "components": []}, "version": "0.9"}
    v08 = surfaces.to_v08(v09)
    assert v08["version"] == "0.8"
    assert v08["surfaceUpdate"]["components"] == []


def test_R10_persistence_non_dict_input_passes_through():
    """Defensive: transform should not crash on weird inputs."""
    assert surfaces.to_v08(None) is None
    assert surfaces.to_v08("not a dict") == "not a dict"


# ══════════════════════════════════════════════════════════════════════
# HAPPY path — kept last per R1-R10 ordering
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_happy_sovereign_default_registration():
    result = await chapter_agent.register_member(_make_reg())
    assert result["registered"] is True
    assert result["origin"] == "sovereign"


@pytest.mark.asyncio
async def test_happy_openclaw_registration():
    result = await chapter_agent.register_member(_make_reg(agent_id="claw-user", origin="openclaw"))
    assert result["registered"] is True
    assert result["origin"] == "openclaw"
    assert chapter_agent.members["claw-user"]["origin"] == "openclaw"


@pytest.mark.asyncio
async def test_happy_openclaw_sandboxed_registration():
    result = await chapter_agent.register_member(_make_reg(agent_id="sandbox", origin="openclaw_sandboxed"))
    assert result["origin"] == "openclaw_sandboxed"


def test_happy_v08_passes_common_components():
    """End-to-end: grab a real surface, transform it, verify it's v0.8 shaped."""
    v09 = {
        "createSurface": {"surfaceId": "dashboard"},
        "updateComponents": {
            "surfaceId": "dashboard",
            "root": "page",
            "components": [
                {"id": "page", "component": "Card", "child": "col"},
                {"id": "col", "component": "Column", "children": ["title"]},
                {"id": "title", "component": "Text", "text": "Bay Area", "usageHint": "h1"},
            ],
        },
        "version": "0.9",
    }
    v08 = surfaces.to_v08(v09)
    assert v08["version"] == "0.8"
    # Every component id from input appears in output
    in_ids = {c["id"] for c in v09["updateComponents"]["components"]}
    out_ids = {c["id"] for c in v08["surfaceUpdate"]["components"]}
    assert in_ids == out_ids
