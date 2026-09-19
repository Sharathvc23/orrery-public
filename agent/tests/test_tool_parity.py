"""Cross-channel verb/tool parity for the NANDA agent surfaces.

Three surfaces must stay aligned:

1. **Sovereign SDK agent tools** (``community_member.agent.AGENT_TOOLS``) —
   what the local LLM is taught it can do.
2. **A2A client methods** (``community_member.a2a_client.A2AClient``) —
   what those tools actually call into.
3. **Chapter routes** (``chapter.chapter_agent``) — what the chapter
   serves on the wire.

A drift in any of those three causes user-visible failures the user
cannot diagnose:

- Tool exists but no A2AClient method → ``execute_tool`` falls through
  to ``Unknown tool`` or worse, calls a missing attribute and crashes.
- A2AClient method exists but the chapter route doesn't → the request
  404s, or (worse) the chapter's auth middleware rejects it as
  ``missing_agent_id`` BEFORE route resolution, hiding the 404 behind
  a confusing "auth" error. We saw this exact failure on
  ``search_federation`` calling ``POST /api/federation/search`` (no
  such route), where the visible error was ``missing_agent_id`` and
  the user concluded the auth layer was broken.
- Tool name on one side, different on the other → search/discovery
  fails silently.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

from community_member import agent as agent_mod
from community_member.a2a_client import A2AClient

# ── Tool inventory ───────────────────────────────────────────


# Every tool exposed to the local LLM. Drift reduction: this is the
# single source of truth and individual tests pull from it. Add a tool
# here and the per-tool wiring tests fail until it's wired through.
LOCAL_SOVEREIGN_TOOLS = {
    # Membership
    "join_chapter",
    "search_chapter",
    # Intents + matching
    "search_federation",
    "submit_intent",
    "respond_to_intent",
    "update_projection",
    "save_note",
    "get_chapter_intelligence",
    # Conversations
    "start_conversation",
    "list_conversations",
    # W11: skill registry
    "install_skill",
    "rate_skill",
    "list_installed_skills",
    # W11: mesh
    "find_peer",
    "send_to_peer",
    "my_trust",
    # W11: settings + channels
    "update_settings",
    "connect_channel",
}

# Map: tool name → A2AClient method name it dispatches into.
# ``None`` means the tool does not call a chapter endpoint (local-only,
# e.g. ``save_note`` writes to the config dir, ``list_installed_skills``
# reads the local skill registry).
TOOL_TO_CLIENT_METHOD: dict[str, str | None] = {
    "join_chapter": "join_chapter",
    "search_chapter": "send_message",
    "search_federation": "search_federation",
    "submit_intent": "submit_intent",
    "respond_to_intent": "respond_to_intent",
    "update_projection": "update_projection",
    "save_note": None,  # local-only
    "get_chapter_intelligence": "get_knowledge",
    "start_conversation": "start_conversation",
    "list_conversations": "get_conversations",
    "install_skill": None,  # routed through community_member.skills helper
    "rate_skill": "review_skill",
    "list_installed_skills": None,  # local registry
    "find_peer": "mesh_peers",
    "send_to_peer": "mesh_send",
    "my_trust": "mesh_trust",
    "update_settings": "update_settings",
    "connect_channel": "connect_channel",
}

# Map: A2AClient method → chapter route(s) it hits.
# Format: ``(http_method, path_template)`` where ``path_template`` may
# contain ``{var}`` placeholders matching FastAPI path-param syntax.
# ``None`` means the method exists but is open / probe-only (health,
# version) and does not need wire-level parity.
CLIENT_METHOD_TO_ROUTE: dict[str, tuple[str, str] | None] = {
    "join_chapter": ("POST", "/api/members"),
    "register_member": ("POST", "/api/members"),
    "send_message": ("POST", "/a2a"),
    "search_federation": ("GET", "/api/mesh/peers"),  # post-fix routes here
    "submit_intent": ("POST", "/api/intents"),
    "respond_to_intent": ("POST", "/api/intents/respond"),
    "update_projection": ("POST", "/api/projections"),
    "get_knowledge": ("GET", "/api/knowledge/network"),
    "start_conversation": ("POST", "/api/conversations"),
    "get_conversations": ("GET", "/api/conversations/{agent_id}"),
    "review_skill": ("POST", "/api/skills/{skill_id}/review"),
    "mesh_peers": ("GET", "/api/mesh/peers"),
    "mesh_send": ("POST", "/api/mesh/send"),
    "mesh_trust": ("GET", "/api/mesh/trust/{agent_id}"),
    "update_settings": ("POST", "/api/settings/update"),
    "connect_channel": ("POST", "/api/channels/connect"),
    "version": None,  # probe
    "health": None,  # probe
    "get_agent_profile": ("GET", "/api/agents/{agent_id}/profile"),
}

# ── Helpers ───────────────────────────────────────────────────


def _tool_names(tool_list) -> set[str]:
    return {t["function"]["name"] for t in tool_list}


def _chapter_routes() -> set[tuple[str, str]]:
    """Extract every declared FastAPI route the chapter serves.

    Returns the set of ``(method_upper, path_template)`` tuples.
    Reading the source rather than importing the module avoids
    pulling in the full FastAPI app + Postgres client just to list
    routes, which is fragile and slow in CI.

    Two source shapes are unioned:

    - ``server/chapter_agent.py`` — routes still declared on the app
      directly via ``@app.<verb>("...")``.
    - ``server/routes/*.py`` — routes extracted into APIRouter modules
      via ``@router.<verb>("...")`` (e.g. ``review_skill`` lives in
      ``server/routes/skills.py``). These are included on the app by
      ``include_router`` but the path templates are declared verbatim
      on the ``@router`` decorator, so the same regex (matching either
      ``app`` or ``router``) resolves them.
    """
    # Orrery monorepo layout: the server (the chapter host) is a sibling
    # subsystem at ../server. If it's absent (the agent was extracted
    # standalone), skip — this is a cross-subsystem parity check.
    server_dir = Path(__file__).resolve().parents[2] / "server"
    main_src = server_dir / "chapter_agent.py"
    if not main_src.exists():
        import pytest

        pytest.skip("cross-subsystem parity check requires the server subsystem")

    # ``@app.get(...)`` on the main module + ``@router.get(...)`` in the
    # extracted route modules. Match either dispatcher name.
    # The path may be followed by decorator kwargs (e.g. response_model=None
    # after the type sweep) — anchor on the first string argument only.
    pattern = re.compile(r'@(?:app|router)\.(get|post|put|patch|delete)\("([^"]+)"')

    sources = [main_src]
    routes_dir = server_dir / "routes"
    if routes_dir.is_dir():
        sources.extend(sorted(routes_dir.glob("*.py")))

    routes: set[tuple[str, str]] = set()
    for src in sources:
        text = src.read_text()
        routes |= {(m.group(1).upper(), m.group(2)) for m in pattern.finditer(text)}
    return routes


def _route_exists(routes: set[tuple[str, str]], method: str, path: str) -> bool:
    """Match ``(method, path)`` allowing trailing-slash and equivalent
    parameter-name variants (FastAPI treats ``/a/`` and ``/a`` the same
    once the trailing slash is normalized; chapter declares both)."""
    candidates = {path, path.rstrip("/"), path + "/"}
    return any((method, c) in routes for c in candidates)


# ── Surface 1 → Surface 2: every tool has a dispatch path ─────


def test_HAPPY_every_tool_listed_is_in_AGENT_TOOLS():
    """The inventory in this test must match the SDK's AGENT_TOOLS exactly.

    If a tool gets added to AGENT_TOOLS but not to LOCAL_SOVEREIGN_TOOLS
    (or vice versa), drift goes undetected by the per-tool tests below.
    """
    declared = _tool_names(agent_mod.AGENT_TOOLS)
    assert declared == LOCAL_SOVEREIGN_TOOLS, (
        f"AGENT_TOOLS drifted from the test inventory.\n"
        f"  In AGENT_TOOLS only:    {sorted(declared - LOCAL_SOVEREIGN_TOOLS)}\n"
        f"  In test inventory only: {sorted(LOCAL_SOVEREIGN_TOOLS - declared)}\n"
        f"Add the tool to BOTH places, with TOOL_TO_CLIENT_METHOD entry."
    )


def test_HAPPY_every_tool_has_a_dispatch_path():
    """Every declared tool either has an A2AClient method or is local-only."""
    missing = LOCAL_SOVEREIGN_TOOLS - set(TOOL_TO_CLIENT_METHOD)
    assert not missing, (
        f"These tools have no entry in TOOL_TO_CLIENT_METHOD: {sorted(missing)}. "
        f'Add ``"<tool>": "<a2a_method>"`` or ``"<tool>": None`` for local-only.'
    )


@pytest.mark.parametrize("tool_name", sorted(LOCAL_SOVEREIGN_TOOLS), ids=sorted(LOCAL_SOVEREIGN_TOOLS))
def test_HAPPY_tool_dispatches_to_real_a2a_method(tool_name: str) -> None:
    """Each tool's mapped A2AClient method must actually exist."""
    method = TOOL_TO_CLIENT_METHOD[tool_name]
    if method is None:
        # Local-only tool; nothing to verify on A2AClient.
        return
    assert hasattr(A2AClient, method), (
        f"Tool {tool_name!r} maps to A2AClient.{method}, but that method does not exist. "
        f"Either add the method to a2a_client.py or update TOOL_TO_CLIENT_METHOD."
    )
    fn = getattr(A2AClient, method)
    assert callable(fn), f"A2AClient.{method} is not callable: {fn!r}"


# ── Surface 2 → Surface 3: every A2A method hits a real route ─


@pytest.mark.parametrize("method_name", sorted(CLIENT_METHOD_TO_ROUTE), ids=sorted(CLIENT_METHOD_TO_ROUTE))
def test_HAPPY_a2a_method_hits_real_chapter_route(method_name: str) -> None:
    """Each A2AClient method maps to a route that the chapter actually
    serves. Catches the ``POST /api/federation/search`` class of bug
    (SDK calls a path the chapter never exposed).
    """
    expected = CLIENT_METHOD_TO_ROUTE[method_name]
    if expected is None:
        # Probe / open-only; not a chapter API route in the strict sense.
        return
    assert hasattr(A2AClient, method_name), (
        f"CLIENT_METHOD_TO_ROUTE references A2AClient.{method_name} which does not exist."
    )
    method, path = expected
    routes = _chapter_routes()
    assert _route_exists(routes, method, path), (
        f"A2AClient.{method_name} expects {method} {path} on the chapter, "
        f"but no such route is declared in chapter_agent.py.\n"
        f"Either add the route in chapter_agent.py, or update "
        f"a2a_client.py to call an existing route."
    )


def test_ADVERSARIAL_no_orphan_a2a_method_targets_a_phantom_route():
    """Defense in depth: every method we declare in CLIENT_METHOD_TO_ROUTE
    MUST exist on A2AClient. Catches the case where someone adds a route
    expectation here without writing the method."""
    missing = [m for m in CLIENT_METHOD_TO_ROUTE if not hasattr(A2AClient, m)]
    assert not missing, f"CLIENT_METHOD_TO_ROUTE references methods that don't exist on A2AClient: {missing}"


# ── Tool description hygiene (R7 — adversarial input shaping) ─


_LEAKY_EXAMPLE_PATTERNS = [
    # Phrases previously found leaking from descriptions into the
    # LLM's understanding of what the user is asking for.
    re.compile(r"\bcofounder in [A-Z]", re.IGNORECASE),
    re.compile(r"\bquantum computing in [A-Z]", re.IGNORECASE),
    re.compile(r"\bAI infra cofounder", re.IGNORECASE),
]


def test_ADVERSARIAL_no_concrete_query_examples_in_tool_descriptions():
    """Tool descriptions must not contain example *queries* that the
    LLM can interpret as user intent. Format hints (``e.g. file-ops@1.0.0``)
    are fine because they describe parameter SHAPE; topic examples
    (``e.g. AI infra cofounder in Boston``) leak as INTENT.

    The user observed this exact failure: the SDK agent invented
    ``quantum computing in Boston`` as a search query when the user
    had only said ``join boston chapter``. The leak source was a
    description like ``submit intent (e.g. looking for an AI infra
    cofounder in Boston)`` — semantically adjacent but worded
    similarly enough that the LLM grafted the example onto an
    unrelated user prompt.
    """
    for tool in agent_mod.AGENT_TOOLS:
        fn = tool["function"]
        text = fn.get("description", "")
        for pat in _LEAKY_EXAMPLE_PATTERNS:
            assert not pat.search(text), (
                f"Tool {fn['name']!r} description contains a query-shaped example "
                f"that may leak as user intent: pattern {pat.pattern!r} matched."
            )
        # Also check parameter descriptions.
        params = fn.get("parameters", {}).get("properties", {}) or {}
        for pname, pdef in params.items():
            pdesc = (pdef or {}).get("description", "")
            for pat in _LEAKY_EXAMPLE_PATTERNS:
                assert not pat.search(pdesc), (
                    f"Tool {fn['name']!r} parameter {pname!r} description contains a "
                    f"query-shaped example: pattern {pat.pattern!r} matched."
                )


def test_HAPPY_every_tool_has_description_and_schema():
    for tool in agent_mod.AGENT_TOOLS:
        fn = tool["function"]
        assert fn["name"]
        assert fn["description"], f"Tool {fn['name']!r} has empty description"
        assert isinstance(fn["parameters"], dict)


# ── Auth fail-loud invariant (closes the silent-{} bug) ───────


def test_FAILURE_unsigned_signed_call_raises_not_silent():
    """An A2AClient with no agent_id must raise ``MissingCredentialsError``
    instead of silently sending an unsigned request. The user observed
    the silent path: the chapter rejected with ``missing_agent_id`` and
    it took a full debugging session to trace the failure back to the
    SDK rather than the chapter.
    """
    from community_member.a2a_client import MissingCredentialsError

    client = A2AClient("http://example.invalid")
    with pytest.raises(MissingCredentialsError):
        client._auth_headers("{}")


def test_FAILURE_signed_call_with_agent_id_but_no_key_raises():
    """Half-configured client (agent_id set, key missing) also raises
    rather than sending unsigned."""
    from community_member.a2a_client import MissingCredentialsError

    client = A2AClient("http://example.invalid", agent_id="alice")
    with pytest.raises(MissingCredentialsError):
        client._auth_headers("{}")


def test_HAPPY_open_endpoints_do_not_raise_on_unauthed_client():
    """Open endpoints (`/api/version`, `/health`, `/api/sessions`,
    `/api/federation`, etc.) must remain reachable from a brand-new
    client that has no credentials yet. They go through ``_get_open`` /
    ``_post_open`` which intentionally do not call ``_auth_headers``.
    """
    # We only verify the dispatch shape (no httpx round-trip in unit
    # tests). The fact that these methods exist and use the open
    # variants is enforced by inspecting the source.
    client_src = inspect.getsource(A2AClient)
    for fragment in [
        '_get_open("/api/version")',
        '_get_open(f"/api/surfaces/',
        '_get_open("/api/sessions")',
        '_get_open("/api/federation")',
        '_get_open("/api/knowledge/network")',
        '_post_open("/api/members"',
    ]:
        assert fragment in client_src, (
            f"Expected open-endpoint dispatch via {fragment!r} in A2AClient; "
            f"open endpoints must NOT route through _auth_headers."
        )
