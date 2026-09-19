"""Present, then exercised — the structural layer over ``federation_feed.py``.

``test_federation_feed.py`` asserts BEHAVIOUR, and its planted breaks prove the
behaviour can fail. Nothing asserted the guards were still THERE. A deleted guard
and a guard that never fires look identical to a suite that only checks messages:
delete the guard, its message disappears, the behavioural test never reaches it,
and nothing goes red.

Three properties, in order, because each is worthless without the one before it:

  **G1  PRESENT**    — every defensive exit in the module is enumerated FROM THE
                       CODE. Not from a list: a hand-maintained list is the
                       suppression-list shape that change removed, and a typo in it makes
                       the whole layer vacuous while looking thorough.
  **G2  EXERCISED**  — every enumerated guard actually executes during the
                       behavioural suite, measured by coverage. The enumeration
                       comes from the AST and the evidence comes from the tracer;
                       neither reads the other.
  **G3  LOAD-BEARING** — deleting any enumerated guard makes the behavioural suite
                       FAIL. This is the meta-plant, and it is the point.

⚠️ **The sharpest constraint here, and it came from a harness that failed this
way: a meta-guard must assert against an INDEPENDENT reference, not an internal
property.** That harness satisfied module-identity while the property it existed
to protect was false. So G3 does not ask "did my enumeration notice the deletion" — an
enumeration noticing its own edit proves nothing. It asks whether **a different
suite, which knows nothing about this enumeration, goes red.** A guard whose
removal breaks no test was never a guard; it was a comment with syntax.

And the producer (P1/P2), from the defect the federation conformance suite caught
in that change that 30 green tests could not see: **is anything asserting the producer is
WIRED, as opposed to that it works when called?**
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SERVER = Path(__file__).resolve().parents[1]
MODULE = SERVER / "federation_feed.py"
BEHAVIOUR_SUITE = "tests/test_federation_feed.py"

#: Modules that must call the producer for the feed to be anything but empty.
PRODUCER_CALL_SITES = ("chapter_agent.py", "think_cycle.py")
PRODUCER = "publish_if_changed"


# ---------------------------------------------------------------------------
# Enumeration — derived from the code, never from a list
# ---------------------------------------------------------------------------


class _GuardFinder(ast.NodeVisitor):
    """A guard is a control-flow exit that is NOT the function's ordinary result.

    Concretely: every ``raise``, and every ``return`` that sits inside an ``if``
    or an ``except`` — the shape of "something is wrong or absent, stop here".
    The plain final ``return`` of a function is its answer, not a guard, and is
    excluded so the enumeration means something.

    Deriving it structurally is what makes this layer maintenance-free: a guard
    added to the module joins the enumeration automatically and must then be
    exercised and load-bearing, without anyone remembering to list it.
    """

    def __init__(self) -> None:
        self.guards: list[dict] = []
        self._func: list[str] = []
        self._depth = 0
        self._handler_tails: set[int] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._func.append(node.name)
        self.generic_visit(node)
        self._func.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _guarded(self, node: ast.AST) -> None:
        self._depth += 1
        self.generic_visit(node)
        self._depth -= 1

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        self._guarded(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        # The HANDLER is itself a guard — it is what stops an exception
        # propagating, and for publish_if_changed that IS the "never raises into
        # its caller" guarantee. Recorded separately from the statements inside
        # it, and mutated differently (see MUTATION below).
        if node.type is not None:
            self.guards.append(
                {"function": self._func[-1] if self._func else "<module>", "line": node.lineno,
                 "kind": "except-handler", "mutation": "narrow"}
            )
        self._handler_tails.add(id(node.body[-1])) if node.body else None
        self._guarded(node)

    def _record(self, node: ast.AST, kind: str) -> None:
        self.guards.append(
            {"function": self._func[-1] if self._func else "<module>", "line": node.lineno,
             "kind": kind, "mutation": "pass"}
        )

    def visit_Raise(self, node: ast.Raise) -> None:  # noqa: N802
        self._record(node, "raise")

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        if not self._depth:
            return  # a function's ordinary result, not a guard
        # A bare `return None` that ENDS an except handler is not a guard: Python
        # returns None from a fallthrough anyway, so deleting it changes nothing
        # and it would be reported as inert forever. The guard there is the
        # HANDLER, which is enumerated in its own right. This is a structural
        # rule with a stated reason, not an exclusion list — it applies to any
        # such statement, including ones added later.
        if id(node) in self._handler_tails and (
            node.value is None or (isinstance(node.value, ast.Constant) and node.value.value is None)
        ):
            return
        self._record(node, "early-return")


def _enumerate_guards() -> list[dict]:
    source = MODULE.read_text(encoding="utf-8")
    finder = _GuardFinder()
    finder.visit(ast.parse(source))
    lines = source.splitlines()
    for g in finder.guards:
        g["source"] = lines[g["line"] - 1].strip()
    return sorted(finder.guards, key=lambda g: g["line"])


@pytest.fixture(scope="module")
def guards() -> list[dict]:
    return _enumerate_guards()


# ---------------------------------------------------------------------------
# G1 — PRESENT
# ---------------------------------------------------------------------------


def test_G1_guards_are_enumerated_from_the_code(guards) -> None:
    """The enumeration must be non-trivial and must cover the functions that
    carry the policy, or "every guard is exercised" is a claim about an empty
    set — a suite that guards nothing and reports green."""
    assert guards, "no guards enumerated — the finder is broken, not the module"

    functions = {g["function"] for g in guards}
    for owner in ("ensure_schema", "publish_if_changed", "feed_identity", "append_envelope", "feed_url"):
        assert owner in functions, f"{owner} carries load-bearing policy but contributed no guard"


def test_G1b_the_named_policy_decisions_are_all_present(guards) -> None:
    """The specific decisions that were ruled on deliberately, located in the
    enumeration rather than listed beside it.

    This is the one place a human-meaningful name appears, and it is deliberately
    a LOOKUP INTO the derived set, not a second list the set is compared against:
    if a policy branch is deleted, the lookup fails. If a new guard is added,
    nothing here needs updating — G2 and G3 pick it up on their own.
    """
    by_function: dict[str, list[str]] = {}
    for g in guards:
        by_function.setdefault(g["function"], []).append(g["source"])

    ensure = " ".join(by_function["ensure_schema"])
    assert "return False" in ensure, "ensure_schema must be able to degrade"
    assert "raise" in ensure, "ensure_schema must still raise on a real DDL failure"

    publish = " ".join(by_function["publish_if_changed"])
    assert publish.count("return None") >= 3, (
        "publish_if_changed must decline on: no feed, no key, and nothing new to say"
    )

    assert any("raise" in s for s in by_function["append_envelope"]), (
        "append_envelope must refuse to advance a chain it did not persist"
    )


# ---------------------------------------------------------------------------
# G2 — EXERCISED, measured by an independent tracer
# ---------------------------------------------------------------------------


def _coverage_of_behaviour_suite(tmp: Path) -> set[int]:
    """Lines of federation_feed.py executed by the behavioural suite.

    Run in a subprocess so the measurement is of a clean process rather than of
    whatever this one has already imported — an in-process tracer started here
    would miss every line executed at import time and report them as unexercised.
    """
    data = tmp / "cov.json"
    subprocess.run(
        [
            sys.executable, "-m", "pytest", BEHAVIOUR_SUITE, "-q", "-p", "no:cacheprovider",
            "--cov=federation_feed", f"--cov-report=json:{data}", "--no-header",
        ],
        cwd=SERVER, capture_output=True, text=True, check=True,
    )
    report = json.loads(data.read_text(encoding="utf-8"))
    for path, entry in report["files"].items():
        if Path(path).name == "federation_feed.py":
            return set(entry["executed_lines"])
    raise AssertionError("coverage produced no data for federation_feed.py")


def test_G2_every_enumerated_guard_is_exercised(guards, tmp_path) -> None:
    """PRESENT is not ENOUGH — a guard nothing reaches is decoration.

    The independence matters: the enumeration is produced by parsing the source,
    and the evidence is produced by the interpreter's tracer. Neither consults the
    other, so this cannot pass by agreeing with itself.
    """
    executed = _coverage_of_behaviour_suite(tmp_path)

    unexercised = [g for g in guards if g["line"] not in executed]

    assert not unexercised, "guards present in the source but never reached by the behavioural suite:\n" + "\n".join(
        f"  {MODULE.name}:{g['line']} in {g['function']}() — {g['source']}" for g in unexercised
    )


# ---------------------------------------------------------------------------
# G3 — LOAD-BEARING. The meta-plant, anchored to an independent reference.
# ---------------------------------------------------------------------------


def _mutate(line: str, strategy: str) -> str:
    """Disable one guard while keeping the file parseable.

    ``pass`` rather than a blank line, because blanking the sole statement of a
    block leaves an empty block and the subprocess dies on IndentationError —
    which is a failure, so the test would "pass" on a syntax error rather than on
    the assertion it claims to make. ``pass`` disables the guard and lets
    execution continue, which is precisely "this guard is not here".

    An except handler is disabled by NARROWING it to an exception the code under
    test does not raise, so the error propagates instead of being swallowed.
    """
    indent = " " * (len(line) - len(line.lstrip()))
    if strategy == "narrow":
        return line.replace("except Exception", "except ZeroDivisionError").replace("except OSError", "except ZeroDivisionError")
    return f"{indent}pass  # guard disabled by the meta-plant\n"


def _run_behaviour_suite(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", BEHAVIOUR_SUITE, "-q", "-x", "-p", "no:cacheprovider", "--no-header",
         "--no-cov"],
        cwd=root, capture_output=True, text=True,
    )


@pytest.fixture(scope="module")
def sandbox():
    """A throwaway copy of server/ that guards can be deleted from.

    The real tree is never mutated. An earlier suite of mine pinned a script IN
    PLACE and had to restore it on every exit path; a copy has no such failure
    mode, and an unreverted plant cannot ship because there is nothing to revert.
    """
    tmp = Path(tempfile.mkdtemp(prefix="feed-guards-"))
    root = tmp / "server"
    shutil.copytree(SERVER, root, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".ruff_cache"))
    shutil.copytree(SERVER.parent / "infra", tmp / "infra", ignore=shutil.ignore_patterns("__pycache__"))
    yield root
    shutil.rmtree(tmp, ignore_errors=True)


def test_G3_the_meta_plant_baseline_is_green(sandbox) -> None:
    """Assert the mechanism before asserting anything with it.

    If the untouched copy does not pass, every "deleting a guard made it fail"
    below would be measuring the copy being broken. This is the check that the earlier
    harness was missing when it verified module identity and not boot.
    """
    result = _run_behaviour_suite(sandbox)

    assert result.returncode == 0, (
        "the unmutated sandbox does not pass, so no deletion result below means anything:\n"
        + result.stdout[-2000:]
    )


def test_G4_deleting_ANY_guard_makes_an_INDEPENDENT_suite_fail(guards, sandbox) -> None:
    """THE POINT OF THE WHOLE FILE, and the narrowing applied.

    It would be easy — and worthless — to delete a guard and assert that this
    file's enumeration noticed. An enumeration noticing its own edit is an
    internal property: it can hold while the guard does nothing at all.

    So the reference is external: delete the guard and require
    ``test_federation_feed.py``, which knows nothing about this enumeration, to
    go RED. A guard whose removal breaks no test was never load-bearing, and
    saying it is "present" would be a claim about syntax rather than about
    behaviour.

    Each deletion is confirmed to have LANDED (the line is really gone from the
    file the subprocess will import) before its result is trusted, and the file
    is restored and re-confirmed afterwards — an unreverted plant would silently
    invalidate every deletion after it.
    """
    target = sandbox / "federation_feed.py"
    original = target.read_text(encoding="utf-8")
    inert: list[str] = []

    for guard in guards:
        lines = original.splitlines(keepends=True)
        mutated_line = _mutate(lines[guard["line"] - 1], guard["mutation"])
        target.write_text("".join(lines[: guard["line"] - 1] + [mutated_line] + lines[guard["line"] :]), "utf-8")

        # PLANT CONFIRMED LANDED: read it back out of the file the subprocess
        # will import, not out of the string we just built.
        readback = target.read_text(encoding="utf-8").splitlines(keepends=True)
        assert readback[guard["line"] - 1] == mutated_line and mutated_line != lines[guard["line"] - 1], (
            f"PLANT DID NOT LAND at line {guard['line']} — the result below would be "
            "the unmutated module passing, which is indistinguishable from a guard working"
        )

        result = _run_behaviour_suite(sandbox)

        # PLANT CONFIRMED REVERTED, before anything else runs against this copy.
        target.write_text(original, encoding="utf-8")
        assert target.read_text(encoding="utf-8") == original, "revert failed — later deletions are now unsound"

        if result.returncode == 0:
            inert.append(
                f"  {MODULE.name}:{guard['line']} in {guard['function']}() — {guard['source']}"
            )

    assert not inert, (
        "these guards can be DELETED with the behavioural suite still green, so nothing is "
        "actually guarding them — they are syntax, not policy:\n" + "\n".join(inert)
    )


def test_G5_the_meta_plant_can_detect_an_inert_guard(sandbox) -> None:
    """Prove G4 is capable of failing, by giving it something that SHOULD be inert.

    A guard-detector that has only ever seen load-bearing guards has never been
    shown to distinguish them from decoration. Inserting a genuinely unreachable
    early return — enumerated exactly like a real guard, and reached by nothing —
    must be reported as inert. Without this, G4 passing tells us the module is
    healthy OR that G4 cannot tell the difference.
    """
    target = sandbox / "federation_feed.py"
    original = target.read_text(encoding="utf-8")
    decoy = "\n\ndef _never_called_guard(x: int) -> int | None:\n    if x < 0:\n        return None\n    return x\n"
    target.write_text(original + decoy, encoding="utf-8")

    try:
        found = _GuardFinder()
        found.visit(ast.parse(target.read_text(encoding="utf-8")))
        decoys = [g for g in found.guards if g["function"] == "_never_called_guard"]
        assert decoys, "PLANT DID NOT LAND: the decoy guard was not even enumerated"

        result = _run_behaviour_suite(sandbox)
        assert result.returncode == 0, "the decoy must not break the suite — that is what makes it a decoy"

        # Deleting an unreachable guard changes nothing, which is exactly the
        # verdict G4 reports as "inert". The detector can therefore tell the two
        # apart, and G4's clean result above is meaningful rather than vacuous.
        lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
        lines[decoys[0]["line"] - 1] = _mutate(lines[decoys[0]["line"] - 1], decoys[0]["mutation"])
        target.write_text("".join(lines), encoding="utf-8")
        assert _run_behaviour_suite(sandbox).returncode == 0, (
            "removing an unreachable guard broke the suite — the decoy was not inert after all"
        )
    finally:
        target.write_text(original, encoding="utf-8")
        assert target.read_text(encoding="utf-8") == original


# ---------------------------------------------------------------------------
# P1/P2 — is the PRODUCER wired, or only correct when called?
# ---------------------------------------------------------------------------


def _calls_producer(path: Path) -> list[tuple[int, int]]:
    """(start, end) line spans of statements calling ``federation_feed.publish_if_changed``.

    Spans, not single lines, because the meta-plant deletes the call and a
    multi-line call whose first line is blanked leaves dangling arguments and an
    IndentationError. That would make P3 "pass" on a syntax error rather than on
    the assertion it claims to make — a plant that landed on the wrong thing.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    spans = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.stmt):
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == PRODUCER
            ):
                spans.append((node.lineno, node.end_lineno or node.lineno))
                break
    # ast.walk yields every ENCLOSING statement too — the function definition that
    # contains the call is itself a stmt — so keep only the innermost spans: those
    # containing no other candidate. Written the other way round first, which kept
    # the whole `async def lifespan` and made the meta-plant replace a function
    # body with `pass`, i.e. a SyntaxError rather than a removed call.
    return [s for s in spans if not any(o != s and s[0] <= o[0] and o[1] <= s[1] for o in spans)]


def _assert_wired(root: Path) -> None:
    """The source-level wiring assertion, factored out so the meta-plant can drive
    the same code the real test does rather than a re-implementation of it."""
    for name in PRODUCER_CALL_SITES:
        assert _calls_producer(root / name), (
            f"{name} does not call federation_feed.{PRODUCER} — the feed has no producer at that site, "
            "which yields a §4 surface that is conformant in shape and serves an empty page forever"
        )


def test_P1_the_producer_is_wired_at_every_site_that_must_call_it() -> None:
    """THE DEFECT 30 GREEN TESTS COULD NOT SEE, made structural.

    In that change ``append_envelope`` and the endpoint were both built and both tested,
    and NOTHING IN THE RUNNING SERVER CALLED APPEND. The feed served an empty page
    forever: no entries, no head, so ``read_intelligence`` returns a None cursor
    and a subscriber cannot even obtain a starting point. Every one of those tests
    called the producer directly, so a 31st test of the same shape would also have
    passed — the gap was not coverage, it was that nothing asked whether the
    runtime calls the thing.

    ⚠️ This assertion is SOURCE-LEVEL and cannot see whether the call is reachable
    at runtime; P2 is the behavioural half. Both are stated because neither alone
    is the claim: P1 catches a deleted call site, P2 catches a call site that
    exists and never runs.
    """
    _assert_wired(SERVER)


def test_P2_booting_the_app_actually_publishes(monkeypatch) -> None:
    """The independent reference for P1: DRIVE THE REAL BOOT and observe the row.

    ⚠️ The first version of this test called ``publish_if_changed`` directly and
    asserted a row appeared. That is the SAME SHAPE as the 30 tests that could not
    see the missing producer — a test that constructs its own precondition cannot
    discover that the system never constructs it. It also failed, for the very
    reason the original defect existed: called outside the boot sequence,
    ``federation_intelligence`` was uninitialised, so the envelope had an empty
    ``community_id`` and was correctly skipped.

    So this enters the app's lifespan — the same ``with TestClient(app)`` form
    ``conformance/federation`` uses, and the form that change had to fix in
    ``test_feed_restart`` for exactly this reason — and asserts an entry exists
    afterwards. Could it pass against a runtime where the producer is absent? No:
    nothing else in the boot writes to that table, which is what P3 confirms by
    deleting the call.
    """
    import importlib

    from fastapi.testclient import TestClient

    import federation_feed
    import pg_store

    written: list[dict] = []

    async def fake_pg(method, table, params=None, body=None):
        if table != "federation_feed_entries":
            return None
        if method == "POST":
            written.append(dict(body))
            return dict(body)
        rows = sorted(written, key=lambda r: r["seq"], reverse=(params or {}).get("order") == "seq.desc")
        limit = (params or {}).get("limit")
        return rows[:limit] if limit else rows

    async def ddl_ok(sql: str) -> None:
        return None

    async def reachable() -> bool:
        return True

    monkeypatch.setenv("AGENT_ID", "TEST-producer-org")
    monkeypatch.setenv("AGENT_NAME", "Producer Org")
    monkeypatch.setenv("AGENT_FOCUS", "federation")
    monkeypatch.setattr(pg_store, "database_url", lambda: "postgres://stub/stub")
    monkeypatch.setattr(pg_store, "execute_ddl", ddl_ok)
    monkeypatch.setattr(pg_store, "db_reachable", reachable)

    sys.modules.pop("chapter_agent", None)
    ca = importlib.import_module("chapter_agent")
    monkeypatch.setattr(ca, "pg_request", fake_pg)

    try:
        with TestClient(ca.app):
            pass
    finally:
        federation_feed.reset_for_tests(False, "reset")

    assert written, (
        "booting the app published nothing — the producer is not wired into the boot path, "
        "so the feed would serve an empty page forever and a subscriber could not obtain a cursor"
    )
    assert written[0]["seq"] == 0
    assert written[0]["feed_id"].startswith("did:key:")


def test_P3_removing_a_producer_call_site_is_detected(sandbox) -> None:
    """The meta-plant for P1, against an independent reference.

    Deleting the boot call must make P1 red. Confirmed landed by re-parsing the
    mutated file — not by trusting the edit — and reverted immediately.
    """
    target = sandbox / "chapter_agent.py"
    original = target.read_text(encoding="utf-8")
    sites = _calls_producer(target)
    assert sites, "PLANT PRECONDITION MISSING: the sandbox copy has no producer call to delete"

    start, end = sites[0]
    lines = original.splitlines(keepends=True)
    indent = " " * (len(lines[start - 1]) - len(lines[start - 1].lstrip()))
    mutated = lines[: start - 1] + [f"{indent}pass  # producer removed by the meta-plant\n"] + lines[end:]
    target.write_text("".join(mutated), encoding="utf-8")

    try:
        # PLANT CONFIRMED LANDED, by re-parsing the file the subprocess will import.
        assert not _calls_producer(target), (
            "PLANT DID NOT LAND: the call is still there, so the assertions below would pass "
            "for the wrong reason"
        )

        # (a) the source-level check notices. On its own this is an INTERNAL
        #     property — my parser noticing my own edit — and an internal property
        #     is not enough, so it is only half the assertion.
        with pytest.raises(AssertionError, match="does not call"):
            _assert_wired(sandbox)

        # (b) THE INDEPENDENT REFERENCE: P2 drives the real boot and observes the
        #     row. It knows nothing about _calls_producer. If P2 stays green with
        #     the call deleted, then P1 is guarding something that does not matter
        #     and the wiring is proven by neither.
        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/test_federation_feed_guards.py::test_P2_booting_the_app_actually_publishes",
             "-q", "-p", "no:cacheprovider", "--no-header", "--no-cov"],
            cwd=sandbox, capture_output=True, text=True,
        )
        assert result.returncode != 0, (
            "the boot-observation test stayed GREEN with the producer call deleted, so it is not "
            "observing the wiring at all:\n" + result.stdout[-2000:]
        )
        assert "published nothing" in result.stdout, (
            "it failed, but not on the wiring assertion — it may simply be broken:\n" + result.stdout[-2000:]
        )
    finally:
        target.write_text(original, encoding="utf-8")
        # PLANT CONFIRMED REVERTED — an unreverted plant would ship, and would
        # also silently invalidate anything else this sandbox is used for.
        assert _calls_producer(target), "revert failed — the sandbox no longer matches the real tree"
