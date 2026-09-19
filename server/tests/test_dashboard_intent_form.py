"""The dashboard's intent form: the surface and the handler agree on the key.

A2UI gives an Input no name of its own. A renderer submits a Form's values
keyed by each child's component id (renderer/src/render.js, c_Input sets
`name` to `c.id`), so the id the surface declares is the key the action
handler receives. The two halves were spelled independently — the surface
said `dash-intent-input`, the handler read `intent_text` — and every
submission made through a renderer answered "Missing Intent". Driven in real
Chromium against a compose stack before this test existed: the POST carried
`{"dash-intent-input": "someone who can review a Python package"}` and the
org painted the error surface; `agent_intents` stayed at 0 rows.

This module reads the key OUT OF THE RENDERED SURFACE rather than restating
it, so a rename on either side reddens it: the handler is fed exactly the
Form's children as a renderer would send them.
"""

from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture
def chapter_agent_module(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-fixture-chapter")
    if "chapter_agent" in sys.modules:
        del sys.modules["chapter_agent"]
    return importlib.import_module("chapter_agent")


def _req(agent_id: str = ""):
    class _State:
        pass

    st = _State()
    st.agent_id = agent_id

    class _Req:
        state = st
        headers: dict = {}

    return _Req()


async def _dashboard_form(chapter_agent_module) -> tuple[dict, dict[str, dict]]:
    """The dashboard's Form component and its child Inputs, from the surface
    builder itself with only the database stubbed out."""
    surfaces = chapter_agent_module.surfaces

    async def none(*_a, **_k):
        return []

    class _NoIntents:
        get_active_intents = staticmethod(none)

    # The wiring chapter_agent does at startup, with a database that answers
    # nothing: the form is declared unconditionally, so that is all it needs.
    surfaces.init(
        pg_request_fn=none,
        members_dict={},
        federation_dict={},
        knowledge_cache={},
        agent_id="TEST-fixture-chapter",
        agent_name="Test Org",
        get_think_count=lambda: 0,
        intents_mod=_NoIntents,
    )
    built = await surfaces.build_dashboard_surface()
    by_id = {c["id"]: c for c in built["updateComponents"]["components"]}
    forms = [c for c in by_id.values() if c["component"] == "Form" and c["action"] == "submit_intent"]
    assert len(forms) == 1, "the dashboard declares exactly one submit_intent form"
    return forms[0], by_id


def _renderer_values(form: dict, by_id: dict[str, dict], typed: dict[str, str]) -> dict[str, str]:
    """What the reference renderer POSTs: every Input child of the Form,
    keyed by its component id, carrying what the user typed (or its
    declared value)."""
    values = {}
    for child in form["children"]:
        comp = by_id[child]
        assert comp["component"] == "Input", f"{child} is a {comp['component']}, not an Input"
        values[child] = typed.get(child, comp.get("value", ""))
    return values


@pytest.mark.asyncio
async def test_the_handler_reads_the_keys_the_surface_declares(chapter_agent_module, monkeypatch):
    """THE DEFECT. Feed the handler exactly what a renderer sends for this
    form — values keyed by the Form's child ids — and the intent must be
    created with the typed text, not refused as missing."""
    seen: dict = {}

    async def fake_create(requester, text, tags):
        seen.update(requester=requester, text=text, tags=tags)
        return "intent-1"

    async def empty(*_a, **_k):
        return {}

    async def noop(*_a, **_k):
        return None

    ca = chapter_agent_module
    monkeypatch.setattr(ca.intents, "create_intent", fake_create)
    monkeypatch.setattr(ca.intents, "match_intent", empty)
    monkeypatch.setattr(ca.intents, "match_intent_federation", empty)
    monkeypatch.setattr(ca.activity_tracker, "track", noop)
    monkeypatch.setattr(ca.projections, "match_intent_against_projections", lambda *a, **k: [])
    monkeypatch.setattr(ca.projections, "get_projections", lambda *a, **k: [])
    monkeypatch.setattr(ca, "llm", None)  # keyless, as ./orrery-up installs

    form, by_id = await _dashboard_form(ca)
    tags_id = next(c for c in form["children"] if by_id[c]["label"].startswith("Skills"))
    text_id = next(c for c in form["children"] if c != tags_id)
    values = _renderer_values(
        form, by_id, {text_id: "someone who can review a Python package", tags_id: "python, review"}
    )

    out = await ca.handle_surface_action(
        ca.SurfaceAction(surface_id="surface-dashboard", component_id=form["id"], action=form["action"], values=values),
        _req(""),
    )

    assert seen, f"the handler refused the form's own values: {out}"
    assert seen["text"] == "someone who can review a Python package"
    assert seen["tags"] == ["python", "review"]
    assert seen["requester"] == "anonymous"
    assert out["createSurface"]["surfaceId"] != "action-error", out


@pytest.mark.asyncio
async def test_an_empty_need_is_still_refused_by_name(chapter_agent_module, monkeypatch):
    """The refusal is right when the field really is empty — it was wrong only
    because it fired on a filled one."""
    ca = chapter_agent_module
    form, by_id = await _dashboard_form(ca)
    values = _renderer_values(form, by_id, {})
    out = await ca.handle_surface_action(
        ca.SurfaceAction(surface_id="surface-dashboard", component_id=form["id"], action=form["action"], values=values),
        _req(""),
    )
    assert out["createSurface"]["surfaceId"] == "action-error"
    titles = [c.get("title") for c in out["updateComponents"]["components"]]
    assert "Missing Intent" in titles


def test_the_field_names_are_declared_once(chapter_agent_module):
    """`surfaces.py` names the fields; `chapter_agent.py` reads them by that
    name and never by a literal of its own. A second spelling in the handler
    is how the drift began."""
    from pathlib import Path

    source = (Path(chapter_agent_module.__file__)).read_text(encoding="utf-8")
    handler = source[source.index("async def handle_surface_action") :]
    handler = handler[: handler.index('if action == "submit_feedback"')]
    assert "surfaces.DASH_INTENT_INPUT" in handler and "surfaces.DASH_INTENT_TAGS" in handler
    assert '"intent_text"' not in handler and '"dash-intent-input"' not in handler, (
        "the handler spells the field name itself instead of reading surfaces.DASH_INTENT_*"
    )
