"""Reachability guards: a module that works in isolation but the app cannot
reach is not shipped, it is only written.

WHY THIS FILE EXISTS. The approval-parity fix and the reachability fix were both green on their own unit tests and
both non-functional in the assembled app:

  APPROVAL PARITY — `governance` gained three operational approval kinds in
        Python. The `pending_approvals` CHECK constraint was never updated, so every
        operational INSERT was rejected, swallowed, and reported as "pending".
        The unit tests passed because they used an in-memory fake with no
        constraint — they tested the Python set against itself.
  REACHABILITY — `agent_scheduler` shipped a complete API that nothing
        imported. Its 35 unit tests all passed. `agent_schedule` had 0 rows because the module
        never ran.

The shared root is that neither was ever asserted REACHABLE. These tests assert
the two properties a unit test structurally cannot: that the assembled app
imports the module, and that the DATABASE agrees with the Python declaration.

Static — no handler execution, no network, no database.

Classification: CODE↔APP REACHABILITY / CODE↔SCHEMA PARITY.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

os.environ.setdefault("AGENT_ID", "test-reachability")
os.environ.setdefault("AGENT_NAME", "Test Reachability")

import governance

REPO = Path(__file__).resolve().parents[2]
SERVER = REPO / "server"


def _app_sources() -> dict[str, str]:
    """Every server module except tests, keyed by path RELATIVE TO server/.

    Relative path rather than basename: ``server/external_send.py`` and
    ``server/routes/external_send.py`` are different modules with the same
    basename, and keying by basename made the importer invisible — the first
    draft of this file reported an imported module as orphaned. A reachability
    guard that produces false orphans gets its assertion loosened, which is how
    a guard stops guarding.
    """
    return {
        str(p.relative_to(SERVER)): p.read_text()
        for p in SERVER.rglob("*.py")
        if "tests" not in p.parts and p.name != "__init__.py"
    }


def _imports_module(name: str) -> list[str]:
    """Files that import top-level ``name``, excluding the module itself."""
    pattern = re.compile(rf"^\s*(?:import\s+{name}\b|from\s+{name}\s+import\b)", re.M)
    return [rel for rel, src in _app_sources().items() if rel != f"{name}.py" and pattern.search(src)]


# ── The approval-parity fix: the database must agree with the Python declaration ──────


def _kind_constraint_terms() -> set[str]:
    """The kinds the shipped CHECK constraint actually permits."""
    line = next(
        ln for ln in (REPO / "infra" / "init.sql").read_text().splitlines() if "pending_approvals_kind_check" in ln
    )
    return set(re.findall(r"'([a-z_]+)'::text", line))


def test_every_approval_kind_is_permitted_by_the_database():
    """THE APPROVAL-PARITY FIX GUARD, and written to catch the NEXT one rather than this one.

    A kind present in APPROVAL_KINDS but absent from the constraint is rejected
    by Postgres at INSERT. Because the failure is swallowed, nothing surfaces:
    the verb is refused, never queued, therefore never approvable. Asserting
    the whole set means adding a kind to Python without the schema fails here
    instead of deadlocking in production.
    """
    missing = governance.APPROVAL_KINDS - _kind_constraint_terms()
    assert not missing, (
        f"kinds declared in Python but rejected by the database: {sorted(missing)} — "
        "add them to pending_approvals_kind_check in infra/init.sql AND ship a migration"
    )


def test_the_operational_kinds_specifically_reach_the_database():
    """Named explicitly so the regression that caused the approval-parity fix is pinned by name,
    not only by the general rule above."""
    permitted = _kind_constraint_terms()
    for kind in ("send_external", "record_write", "external_fetch"):
        assert kind in permitted, f"{kind} is still rejected by pending_approvals_kind_check"


def test_a_migration_carries_the_kinds_to_existing_databases():
    """init.sql runs ONLY at first initialisation. Editing it leaves every
    deployed org on the old constraint — the divergence class."""
    migrations = list((REPO / "infra" / "migrations").glob("*.sql"))
    carrying = [
        m for m in migrations if "pending_approvals_kind_check" in m.read_text() and "send_external" in m.read_text()
    ]
    assert carrying, "no migration adds the operational kinds to an existing database"
    for m in carrying:
        assert "IF EXISTS" in m.read_text() or "IF NOT EXISTS" in m.read_text(), f"{m.name} must be idempotent"


def test_the_gate_is_reachable_from_a_registered_route():
    """The gate existing is not the same as the app calling it. Something in
    the app must consume `consume_operational_approval`, or every service verb
    is ungated by construction."""
    callers = [f for f, src in _app_sources().items() if "consume_operational_approval" in src and f != "governance.py"]
    assert callers, "nothing in the app calls consume_operational_approval — the gate is unreachable"


def test_governance_is_initialised_by_the_app():
    """An uninitialised governance module raises on every propose; the gate
    would be permanently closed rather than permanently open, but equally
    broken."""
    assert "governance.init(" in (SERVER / "chapter_agent.py").read_text()


# ── The reachability fix: the scheduler must be imported, initialised and driven ───


def test_agent_scheduler_is_imported_by_the_app():
    """THE REACHABILITY FIX GUARD. It shipped a complete API, 35 passing unit tests, and
    zero importers — so `agent_schedule` held 0 rows and restart-resume was
    untestable because the module never ran."""
    assert _imports_module("agent_scheduler"), "nothing in the app imports agent_scheduler — it is dead code"


def test_agent_scheduler_is_initialised_by_the_app():
    """Importing is not running. Without init() the store is never wired and
    every call quietly no-ops back to the caller."""
    assert any("agent_scheduler.init(" in src for rel, src in _app_sources().items() if rel != "agent_scheduler.py"), (
        "agent_scheduler.init() is never called — the scheduler has no store"
    )


def test_the_schedule_is_actually_written_and_resumed():
    """Wired but never written is still dead. The app must both persist a
    schedule and read it back on boot, or durability is a claim rather than a
    behaviour."""
    sources = {rel: src for rel, src in _app_sources().items() if rel != "agent_scheduler.py"}
    assert any("agent_scheduler.record(" in src for src in sources.values()), "nothing persists a schedule"
    assert any("_resume_think_schedule" in src for src in sources.values()), "nothing resumes on boot"


def test_the_failure_half_of_the_scheduler_is_reached():
    """⚠️ THE HALF THAT WAS WRITTEN AND NEVER CALLED.

    ``after_success`` was wired; ``after_failure`` was not, and neither was
    ``resume``. So the terminal-vs-retryable verdict — correct, and reached
    through the table both trees share byte for byte — decided nothing, and a
    sustained 401 cost 418 org calls a day forever because every failed cycle
    was recorded as a success.

    Named here rather than left to a unit test for the reason this whole file
    exists: ``after_failure`` had passing unit tests the entire time it was
    unreachable. Reachability is the property those tests structurally cannot
    assert.
    """
    sources = {rel: src for rel, src in _app_sources().items() if rel != "agent_scheduler.py"}
    assert any("agent_scheduler.after_failure(" in src for src in sources.values()), (
        "nothing calls agent_scheduler.after_failure — a failed cycle is recorded as a success"
    )
    assert any("agent_scheduler.resume(" in src for src in sources.values()), (
        "nothing calls agent_scheduler.resume — a halted chapter can never be restarted by an operator"
    )


# ── The standing rule, applied going forward ───────────────────────


#: The ONLY reason a top-level server module may be unreachable: it is a copy of
#: a canonical source elsewhere, vendored because the Docker build context does
#: not include that source. Each entry names the file that copy must match.
#:
#: ⚠️ This is a rule, not a list of names. Membership is not enough — the drift
#: guard named here must exist and must actually pin the copy, so "vendored" is a
#: claim the suite checks rather than a label that exempts a file from checking.
#: Anything else — dead code, an unwired feature — has to be deleted or wired.
VENDORED = {
    "dat.py": ("conformance/dat/__init__.py", "tests/test_dat_lockstep.py"),
}


def test_every_server_module_is_reachable():
    """The general form of both bugs: a top-level server module that no other
    server module imports is either dead code or an unwired feature.

    ⚠️ THE EXCEPTION LIST WENT FROM SEVEN NAMES TO ONE RULE. It previously held
    `chapter_agent.py` and `retry_policy.py`, and NEITHER was ever an orphan —
    `sovereign_runtime` imports the first, `agent_scheduler` the second. Listing
    reachable modules as exceptions is how a suppression list hides the real
    entries: it looks load-bearing, so nobody re-checks it. The other five were
    genuine and are resolved in this change rather than recorded again:

      router.py             DEAD  — imports `nanda_bridge`, which is not
                                    installed, so it could not even be imported.
                                    Superseded by `chapter_agent.agent_logic`,
                                    a strict superset of its @agent-id routing.
      agent_card_client.py  DEAD  — its `agent_card_cache` table is not in
                                    init.sql, so every cached fetch would have
                                    failed. Superseded by the advertise-don't-
                                    mirror catalog in `routes/identity.py`:
                                    the org publishes card URLs and never
                                    mirrors card content.
      github_verify.py      DEAD  — its only consumer, the "github-verified"
                                    tier in `sovereign_identity.attest_skill`,
                                    is itself reachable only from tests.
                                    Superseded by `attestations.py` +
                                    `skill_registry`: Ed25519-signed vouches by
                                    trusted-tier members, bound to a content
                                    hash, with no GitHub tier at all.
      jurisdiction.py       WIRED — it was load-bearing and unreachable, the
                                    shape exactly. Now a layer in
                                    `retention.resolve_retention_policy`.
      dat.py                KEPT  — vendored; see VENDORED above.
    """
    top_level = {p.name for p in SERVER.glob("*.py")} - {"__init__.py"}
    orphans = sorted(name for name in top_level - set(VENDORED) if not _imports_module(name[: -len(".py")]))
    assert not orphans, (
        f"server modules nothing imports: {orphans} — wire them, delete them, or, if one is a "
        f"vendored copy, add it to VENDORED with the canonical source and its drift guard"
    )


def test_a_vendored_module_is_actually_pinned_to_its_source():
    """The exception has to earn itself. A module is allowed to be unreachable
    only because it is a copy under a drift guard — so assert both the canonical
    source and the guard exist, and that the guard really names this file.

    Without this, `VENDORED` is just the old ALLOWED set with a better name: any
    module added to it would stop being checked, which is precisely how five
    orphans sat unexamined behind the previous list.
    """
    for module, (canonical, guard) in VENDORED.items():
        assert (SERVER / module).exists(), f"{module} is listed as vendored but does not exist"
        assert (REPO / canonical).exists(), f"{module}'s canonical source {canonical} is missing"
        guard_src = (REPO / "server" / guard).read_text()
        assert module in guard_src, f"{guard} does not mention {module}"
        assert Path(canonical).name in guard_src or canonical.split("/")[-2] in guard_src, (
            f"{guard} does not pin {module} against {canonical}"
        )


def test_a_vendored_copy_has_not_drifted_from_its_source():
    """And the guard must currently PASS, not merely exist. A drift guard that
    is skipped or broken leaves the copy unpinned, which is the same state as
    having no guard — the module would then be an ordinary orphan wearing an
    exemption."""
    for module, (canonical, _guard) in VENDORED.items():
        anchor = "from __future__ import annotations"
        def body(text: str) -> str:
            lines = text.splitlines()
            start = next(i for i, ln in enumerate(lines) if ln.strip() == anchor)
            return "\n".join(lines[start:])

        assert body((SERVER / module).read_text()) == body((REPO / canonical).read_text()), (
            f"{module} has drifted from {canonical} — it is no longer a vendored copy, "
            f"so it no longer qualifies for the reachability exemption"
        )


def test_the_jurisdiction_layer_is_reachable_from_the_retention_sweep():
    """`jurisdiction.py` was the load-bearing orphan: a complete, tested module
    that nothing imported, so `ORG_JURISDICTION` was documented in
    CONFIGURATION.md, read by one module, and that module never ran.

    Reachability only — what the sweeper DOES with it is asserted behaviourally
    in test_jurisdiction.py, because a string check here would have passed before
    the wiring too: retention.py's docstring already claimed to be
    jurisdiction-aware while consulting nothing.
    """
    assert _imports_module("jurisdiction"), "nothing imports jurisdiction — the compliance layer is unreachable"


# ── The approval-parity fix: the service role must be assignable at join ──────────────


def test_a_service_agent_can_declare_itself_at_registration():
    """PR1 built the `service` role and nothing ever assigned it — all four
    spike agents landed `member`. The field must exist on the request model AND
    reach the persisted row; a model field that reaches nothing is the same
    unreachability class this file exists for."""
    src = (SERVER / "chapter_agent.py").read_text()
    assert "agent_kind: str" in src, "MemberRegistration has no agent_kind field"
    assert '"agent_kind": "service" if reg.agent_kind' in src, "agent_kind never reaches the member dict"
    assert '"chapter_role": "service" if member.get("agent_kind")' in src, (
        "the persisted row still hardcodes chapter_role=member"
    )


def test_only_the_less_privileged_role_is_self_assignable():
    """Self-declaration is safe for `service` and ONLY for `service`, because
    it is strictly less privileged than `member`. A self-declared leader or
    admin would be privilege escalation by request body."""
    src = (SERVER / "chapter_agent.py").read_text()
    for escalation in ('"chapter_role": reg.', "chapter_role=reg."):
        assert escalation not in src, f"registration assigns chapter_role from the request ({escalation!r})"
    assert "service" not in governance.APPROVER_ROLES
    assert "service" not in governance.LEADER_ROLES
