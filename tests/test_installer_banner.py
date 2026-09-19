"""The installer's sign-of-life banner may only advertise open surfaces.

`./orrery-up` ends by printing a block headed "sign of life: ALL GREEN" with a
short list of URLs. Its whole job is to tell a brand-new user that the install
worked, so every URL in it has to answer them — and one of them did not:
`GET /api/members` returns 401 to an unauthenticated caller, correctly, because
the bulk member directory requires a signature and is deliberately not an
enumeration surface. The first thing a first run invited a user to open was the
one thing that refused them.

Two independent checks hold that closed, and both are needed:

  * LIVE — `verify_banner` inside `orrery-up` requests every entry anonymously
    before the banner is printed, so the installer fails on its own output
    rather than in the reader's browser. That runs on a booted stack (the
    `installer` CI job, and any local `./orrery-up` / `./orrery-up status`).
  * OFFLINE — this module, which needs no Docker and is therefore always-on.
    It reads the gated-path set out of `server/auth_verify.py` by AST rather
    than restating it, so the two sides cannot drift: closing a new route in
    the server is enough to redden a banner that advertises it.

The offline half exists because the live half only runs where a stack does.
A guard that can only fire in the one job a docs-shaped change skips is the
half-skipped interlock this repository has found in its own instruments before.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[1]


def _load_installer():
    """Import `orrery-up` as a module. It has no `.py` suffix and a hyphen in
    its name, so neither `import` nor a package path reaches it."""
    spec = importlib.util.spec_from_loader(
        "orrery_up_under_test",
        importlib.machinery.SourceFileLoader("orrery_up_under_test", str(REPO / "orrery-up")),
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _require_auth_get_paths() -> set[str]:
    """REQUIRE_AUTH_GET_PATHS, read out of server source.

    Parsed rather than imported: importing `server.auth_verify` pulls the whole
    server dependency tree in, and this guard is always-on precisely so it runs
    in jobs that install none of it. Same technique as
    `renderer/tests/e2e/gen_contract.py`, for the same reason.
    """
    tree = ast.parse((REPO / "server" / "auth_verify.py").read_text())
    for node in ast.walk(tree):
        targets = (
            node.targets if isinstance(node, ast.Assign)
            else [node.target] if isinstance(node, ast.AnnAssign)
            else []
        )
        for t in targets:
            if isinstance(t, ast.Name) and t.id == "REQUIRE_AUTH_GET_PATHS" and node.value is not None:
                if isinstance(node.value, (ast.Set, ast.List, ast.Tuple)):
                    return {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
    raise AssertionError("REQUIRE_AUTH_GET_PATHS not found in server/auth_verify.py")


def _banner_paths() -> list[tuple[str, str]]:
    installer = _load_installer()
    env = {"SERVER_PORT": "7000", "AGENT_PORT": "8080"}
    return [(label, urlparse(url).path) for label, url in installer.banner_urls(env)]


def test_banner_advertises_no_auth_gated_path():
    """The defect itself: `/api/members` is in REQUIRE_AUTH_GET_PATHS, so a
    banner line naming it promises a reader something the server refuses them.
    Reinstating that line reddens this test with no Docker and no network."""
    gated = _require_auth_get_paths()
    offenders = [(label, path) for label, path in _banner_paths() if path in gated]
    assert not offenders, (
        "the sign-of-life banner advertises auth-gated path(s) "
        f"{offenders} — an unauthenticated first run gets 401 on them. "
        "Gated set read from server/auth_verify.py REQUIRE_AUTH_GET_PATHS."
    )


def test_the_gated_set_is_real_and_still_names_the_member_directory():
    """A guard comparing against an empty set passes for the wrong reason. If
    the AST walk ever stops finding the assignment, or the member directory is
    re-opened, this fails instead of silently disarming the test above."""
    gated = _require_auth_get_paths()
    assert "/api/members" in gated, (
        "GET /api/members is no longer in REQUIRE_AUTH_GET_PATHS. Either the "
        "bulk member directory has been re-opened to anonymous enumeration, or "
        "this parse has drifted — both make the banner guard meaningless."
    )


def test_banner_is_what_the_installer_actually_prints():
    """`banner_urls` has to BE the banner, not a second list beside it, or this
    whole module guards a copy. `drill` must print by iterating it."""
    source = (REPO / "orrery-up").read_text()
    drill = source.split("def drill(")[1].split("\ndef ")[0]
    assert "verify_banner(entries)" in drill, "drill must verify the banner before printing it"
    assert "for label, url in entries:" in drill, (
        "drill must print the banner by iterating banner_urls(); a hand-written "
        "line beside it is a second list this guard does not see"
    )


def test_drill_asserts_rate_limit_persistence_on_the_default_install():
    """The limiter's snapshot table is created by init.sql on every fresh
    install, and the boot ensure reported it unavailable on every one of them
    anyway, because it issued DDL the application role is refused even for a
    table that exists. `/health` said `rate_limit_persistence: false`; nothing
    in the installer looked. The drill now polls the field, so the installer
    job goes red if a default install ever boots with persistence off again."""
    source = (REPO / "orrery-up").read_text()
    drill = source.split("def drill(")[1].split("\ndef ")[0]
    assert 'b.get("rate_limit_persistence") is True' in drill, (
        "drill must poll /health for rate_limit_persistence being exactly True"
    )
