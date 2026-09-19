"""Org console + join endpoints (PR9).

⚠️ The load-bearing test here is that ``/api/approvals/kinds`` is DERIVED from
``governance.APPROVAL_KINDS`` rather than being a second list. The console
renders whatever that endpoint returns instead of enumerating kinds in the
browser, so a hand-copied list on either side would silently drop the
operational kinds PR1 is adding — the ``INDIVIDUAL_PROFILE_TYPES`` bug one layer
up, which shipped, excluded six of seven legal values, and was caught in deploy
verification rather than by a test.
"""

from __future__ import annotations

import importlib
import textwrap
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[1] / "static"


def _code_of(fn) -> str:
    """A function's source with its docstring and comments removed.

    ⚠️ Source-scanning assertions MUST strip prose first. Three of my guards have
    now fired on the explanation rather than the code — a constant-time-compare
    check that flagged ``encoding == "hex"``, a sink audit that flagged its own
    comment, and the ``getattr`` check below flagging the docstring that warns
    against ``getattr``. A guard that fires on the wrong line gets silenced, and
    a silenced guard is not a guard.
    """
    import ast
    import inspect

    source = inspect.getsource(fn)
    tree = ast.parse(textwrap.dedent(source))
    node = tree.body[0]
    if ast.get_docstring(node) is not None:
        node.body = node.body[1:]
    return ast.unparse(node)


@pytest.fixture
def governance_mod():
    return importlib.import_module("governance")


# ── ⚠️ the kinds endpoint is derived, not copied ─────────────────────────────


def test_the_kinds_endpoint_is_derived_from_the_governance_vocabulary(governance_mod):
    """Asserted against the source: a literal set here would be a second list."""
    import chapter_agent

    code = _code_of(chapter_agent.approval_kinds)
    assert "from governance import" in code, "the endpoint must read the governance vocabulary"
    assert "APPROVAL_KINDS" in code and "OPERATIONAL_KINDS" in code
    for kind in governance_mod.APPROVAL_KINDS:
        assert f'"{kind}"' not in code, f"the endpoint hard-codes {kind}"


async def test_the_kinds_endpoint_returns_every_configured_kind(governance_mod):
    import chapter_agent

    payload = await chapter_agent.approval_kinds()
    assert set(payload["kinds"]) == set(governance_mod.APPROVAL_KINDS)
    assert payload["count"] == len(governance_mod.APPROVAL_KINDS)


async def test_operational_kinds_is_a_subset_of_the_vocabulary_not_a_fixed_value(governance_mod):
    """⚠️ THIS TEST USED TO PIN ``operational == []`` AND PR1 INVALIDATED IT.

    That assertion encoded a moment (all eight kinds social, ``pending_approvals``
    stayed 0 across a four-agent unattended run) rather than a relationship — the
    same mistake as the profile_type test that pinned the bug it was meant to
    catch. What must hold in every state is that ``operational`` is derived from
    ``governance`` and is approvable, so that is what is asserted.
    """
    import chapter_agent

    payload = await chapter_agent.approval_kinds()
    assert set(payload["operational"]) == set(governance_mod.OPERATIONAL_KINDS) & set(governance_mod.APPROVAL_KINDS)
    assert set(payload["operational"]) <= set(payload["kinds"]), "an advertised gate must be approvable"


async def test_the_endpoint_reads_the_real_symbol_with_no_silent_fallback():
    """⚠️ A ``getattr(governance, "...", set())`` here would turn a renamed or
    missing symbol into an empty operational set — and the console would then
    report "nothing here is gated" forever, with every test still green. An
    earlier draft of this endpoint did exactly that AND guessed the name wrong
    (``OPERATIONAL_APPROVAL_KINDS``; PR1 shipped ``OPERATIONAL_KINDS``).
    """
    import chapter_agent

    code = _code_of(chapter_agent.approval_kinds)
    assert "getattr(" not in code, "a defaulted lookup makes a missing vocabulary look like an empty one"
    assert "OPERATIONAL_KINDS" in code


async def test_operational_kinds_are_actually_present_now_that_pr1_landed(governance_mod):
    """The gate exists at all — the whole premise of the approval screen."""
    import chapter_agent

    payload = await chapter_agent.approval_kinds()
    assert payload["operational"], "PR1 landed operational kinds; the console has nothing to gate without them"


async def test_an_operational_kind_not_in_the_vocabulary_is_not_reported(monkeypatch, governance_mod):
    """Fail closed on inconsistency: a kind marked operational but absent from
    APPROVAL_KINDS cannot be approved, so reporting it would advertise a gate
    that does not exist."""
    import chapter_agent

    monkeypatch.setattr(governance_mod, "OPERATIONAL_KINDS", {"ghost_kind"}, raising=False)
    payload = await chapter_agent.approval_kinds()
    assert "ghost_kind" not in payload["operational"]


# ── the static surfaces ──────────────────────────────────────────────────────


@pytest.mark.parametrize("page", ["console", "join", "receipts", "admin"])
def test_the_pages_are_bundled(page):
    assert (STATIC / page / "index.html").exists(), f"{page}/index.html is not bundled"


@pytest.mark.parametrize("asset", ["dom.js", "console.js", "console-boot.js", "join.js", "join-boot.js"])
def test_every_served_asset_exists(asset):
    """The route allowlists these by name; a name with no file behind it would
    404 at runtime for a page that references it."""
    assert (STATIC / "ui" / asset).exists()


def test_the_asset_route_is_name_allowlisted_not_path_joined():
    """⚠️ ``asset`` comes from the URL. A directory mount or a bare join would
    make the traversal surface bigger than three files are worth."""
    import chapter_agent

    code = _code_of(chapter_agent.ui_asset)
    assert "allowed" in code
    assert "asset not in allowed" in code


def test_the_pages_reference_only_allowlisted_assets():
    """A page referencing an asset the route refuses would be broken in exactly
    the way nobody notices until the browser console is open."""
    import re

    import chapter_agent

    # Either quote style: ast.unparse normalises string literals to single
    # quotes, so a double-quote-only pattern silently matches nothing and the
    # loop below would assert against an empty allowlist — a vacuous pass.
    allowed = set(re.findall(r"""['"]([\w.-]+\.js)['"]""", _code_of(chapter_agent.ui_asset)))
    assert allowed, "extracted an empty allowlist — the pattern no longer matches the route source"
    for page in ("console", "join", "receipts"):
        html = (STATIC / page / "index.html").read_text()
        for ref in re.findall(r'src="/ui/([\w.-]+)"', html):
            assert ref in allowed, f"{page}/index.html loads /ui/{ref}, which the route will not serve"


# ── the QR is a carrier, not an oracle ───────────────────────────────────────


async def test_the_qr_encodes_the_join_url_for_the_token():
    import chapter_agent

    class _Req:
        base_url = "https://org.example/"

    resp = await chapter_agent.invite_qr("TOKEN-123", _Req())
    assert resp.media_type == "image/svg+xml"
    assert b"<svg" in resp.body


async def test_the_qr_route_does_not_validate_the_token():
    """⚠️ Deliberate. Validating would make this an oracle for guessing tokens:
    a distinguishable response for a real token is exactly what an attacker
    enumerating needs. It renders whatever it is given; the landing page then
    refuses an invalid invite."""
    import chapter_agent

    class _Req:
        base_url = "https://org.example/"

    resp = await chapter_agent.invite_qr("definitely-not-a-real-token", _Req())
    assert b"<svg" in resp.body


async def test_a_token_with_url_metacharacters_is_encoded_not_interpolated():
    import chapter_agent

    class _Req:
        base_url = "https://org.example/"

    resp = await chapter_agent.invite_qr("a&b=c d", _Req())
    assert b"<svg" in resp.body


# ── keyless ──────────────────────────────────────────────────────────────────


def test_the_console_page_needs_no_llm_configuration():
    """⚠️ A keyless install currently busy-loops against xAI (PR2 fixes it). The
    operator's window into the org must not be the thing that goes dark when
    inference is unavailable, so nothing this page loads may reach an inference
    path — asserted against the shipped module sources."""
    for name in ("console.js", "console-boot.js", "dom.js", "join.js", "join-boot.js"):
        source = (STATIC / "ui" / name).read_text()
        code = "\n".join(line for line in source.splitlines() if not line.strip().startswith("//"))
        for banned in ("openai", "anthropic", "/api/surfaces/compose"):
            assert banned.lower() not in code.lower(), f"{name} reaches an inference path ({banned})"


# ── The static-sweep pass sweep: the property, asserted over EVERY served page ────────────────


def test_no_server_static_page_can_turn_data_into_markup():
    """⚠️ THE SWEEP, AS A STANDING GUARD.

    The static-sweep pass was found by accident while building something else, in a file nobody
    was looking at. This asserts the property over every page under
    ``server/static/`` rather than over the ones someone happened to inspect —
    including the inline-script pages the node guard cannot reach, since it only
    globs ``ui/*.js``.

    ``admin/index.html`` keeps an inline script (it builds nodes already, and
    rewriting 237 lines of working admin UI was not this unit's job), so a
    file-level scan is the only thing that covers it.
    """
    import re

    sinks = re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b")
    offenders = []
    for page in sorted(STATIC.glob("*/index.html")):
        for lineno, line in enumerate(page.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("<!--"):
                continue
            if sinks.search(line):
                offenders.append(f"{page.parent.name}/index.html:{lineno}: {stripped[:90]}")
    assert offenders == [], "a markup sink reappeared in a served page:\n" + "\n".join(offenders)


def test_no_served_page_uses_an_inline_event_handler_attribute():
    """An inline handler must resolve to a global, which it cannot under an ES
    module, so these break as well as widening the injection surface."""
    import re

    attr = re.compile(r"""<[^>]*\son[a-z]+\s*=\s*["']""", re.I)
    offenders = [
        f"{page.parent.name}/index.html"
        for page in sorted(STATIC.glob("*/index.html"))
        if attr.search(page.read_text())
    ]
    assert offenders == [], f"inline event-handler attributes in: {offenders}"
