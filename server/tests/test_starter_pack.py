"""
Tests for the non-profit Starter Skills Pack.

Verifies:
1. All 5 manifests are valid per skill_registry._validate_manifest.
2. seed_starter_pack() populates the registry with all 5 skills.
3. Calling seed_starter_pack() twice is idempotent (no duplicates).
4. Seeded skills serialise the same way skills_list (GET /api/skills) returns them.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import skill_registry as sr
import starter_pack

# ── Minimal FakePostgres (self-contained; does not import from test_skill_registry) ──


class _FakePostgres:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {
            "chapter_skills": [],
            "chapter_skill_reviews": [],
            "chapter_skill_installs": [],
        }

    async def __call__(self, method, table_or_path, params=None, body=None):
        table = table_or_path.split("?")[0]

        if method == "GET":
            rows = list(self.tables.get(table, []))
            if params:
                rows = self._filter(rows, params)
            return rows

        if method == "POST":
            body = dict(body or {})
            body.setdefault("id", body.get("id") or f"id-{len(self.tables[table]) + 1}")
            body.setdefault("created_at", datetime.now(UTC).isoformat())
            body.setdefault("install_count", 0)
            body.setdefault("trust_score", 0)
            body.setdefault("revoked_at", None)
            body.setdefault("chapter_id", body.get("chapter_id") or "public")
            self.tables.setdefault(table, []).append(body)
            return [body]

        if method == "PATCH":
            filters = self._parse_path_filters(table_or_path, params)
            matched = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched

        return None

    @staticmethod
    def _parse_path_filters(path, params):
        out: dict[str, str] = {}
        if "?" in path:
            _, qs = path.split("?", 1)
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    out[k] = v
        if params:
            for k, v in params.items():
                if k not in ("select", "order", "limit"):
                    out[k] = str(v)
        return out

    def _filter(self, rows, params):
        out = []
        for row in rows:
            ok = True
            for k, v in params.items():
                if k in ("select", "order", "limit"):
                    continue
                if not self._match(row, k, v):
                    ok = False
                    break
            if ok:
                out.append(row)
        order = params.get("order") if params else None
        if order:
            key = order.split(",")[0].split(".")[0]
            reverse = "desc" in order
            out.sort(key=lambda r: r.get(key) or "", reverse=reverse)
        limit = params.get("limit") if params else None
        if limit:
            out = out[: int(limit)]
        return out

    @staticmethod
    def _match(row, key, predicate):
        if "." not in str(predicate):
            return row.get(key) == predicate
        op, val = str(predicate).split(".", 1)
        rv = row.get(key)
        if op == "eq":
            return str(rv) == val
        if op == "is" and val == "null":
            return rv is None
        if op == "gte":
            try:
                return float(rv or 0) >= float(val)
            except (TypeError, ValueError):
                return False
        return True


@pytest.fixture
def env():
    sb = _FakePostgres()
    sr.init(pg_request_fn=sb, chapter_id="public")
    return sb


# ── 1. Manifest validity ───────────────────────────────────────────────────────


def test_all_manifests_are_valid():
    """Every starter manifest passes the registry's own validator."""
    for manifest in starter_pack.NONPROFIT_SKILLS:
        ok, reason = sr._validate_manifest(manifest)
        assert ok, f"Manifest {manifest.get('name')!r} failed validation: {reason}"


def test_all_manifests_have_expected_names():
    expected = {
        "donor-acknowledgement",
        "grant-deadline-tracker",
        "volunteer-scheduler",
        "impact-report-summarizer",
        "event-outreach",
    }
    actual = {m["name"] for m in starter_pack.NONPROFIT_SKILLS}
    assert actual == expected


def test_all_manifests_have_semver_version():
    import re

    semver_re = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
    for m in starter_pack.NONPROFIT_SKILLS:
        assert semver_re.match(m["version"]), f"{m['name']} has invalid version {m['version']!r}"


def test_no_manifest_uses_high_risk_capabilities():
    """Starter skills must be low-risk (no shell.exec, eval.code, etc.)."""
    for m in starter_pack.NONPROFIT_SKILLS:
        caps = set(m.get("capabilities") or [])
        bad = caps & sr.HIGH_RISK_CAPABILITIES
        assert not bad, f"{m['name']} declares high-risk capability: {bad}"


def test_all_manifests_have_nonempty_description():
    for m in starter_pack.NONPROFIT_SKILLS:
        assert m.get("description", "").strip(), f"{m['name']} has no description"


def test_all_manifests_have_inputs_and_outputs():
    for m in starter_pack.NONPROFIT_SKILLS:
        assert m.get("inputs"), f"{m['name']} has no inputs"
        assert m.get("outputs"), f"{m['name']} has no outputs"


# ── 2. seed_starter_pack populates the registry ────────────────────────────────


async def test_seed_populates_all_five_skills(env):
    result = await starter_pack.seed_starter_pack()
    assert result["errors"] == [], f"Unexpected errors: {result['errors']}"
    assert len(result["seeded"]) == 5
    assert result["skipped"] == []

    rows = env.tables["chapter_skills"]
    assert len(rows) == 5
    stored_names = {r["name"] for r in rows}
    assert stored_names == {
        "donor-acknowledgement",
        "grant-deadline-tracker",
        "volunteer-scheduler",
        "impact-report-summarizer",
        "event-outreach",
    }


async def test_seed_each_skill_has_author_agent_id(env):
    await starter_pack.seed_starter_pack()
    for row in env.tables["chapter_skills"]:
        assert row.get("author_agent_id") == "orrery-starter-pack"


# ── 3. Idempotency ────────────────────────────────────────────────────────────


async def test_seed_is_idempotent(env):
    """Calling seed_starter_pack() twice must not duplicate any skill."""
    first = await starter_pack.seed_starter_pack()
    second = await starter_pack.seed_starter_pack()

    # First call seeds, second call skips all.
    assert first["seeded"] == [m["name"] + "@" + m["version"] for m in starter_pack.NONPROFIT_SKILLS]
    assert second["seeded"] == []
    assert set(second["skipped"]) == set(first["seeded"])
    assert second["errors"] == []

    # Table must still have exactly 5 rows.
    assert len(env.tables["chapter_skills"]) == 5


async def test_seed_refreshes_drifted_signature(env):
    """A starter skill whose stored content hash drifted from the code (e.g. an
    old canonicalization) is re-signed in place on the next seed — not skipped —
    and the stored hash returns to the freshly-computed one. No version bump, no
    duplicate row."""
    await starter_pack.seed_starter_pack()
    row = env.tables["chapter_skills"][0]
    skill_id = row["id"]
    good_sha = row["content_sha256"]

    # Simulate drift: an old signature/hash from a prior canonicalization.
    row["content_sha256"] = "0" * 64
    row["signature"] = "stale"

    result = await starter_pack.seed_starter_pack()

    assert skill_id in result["refreshed"]
    assert skill_id not in result["skipped"]
    # Hash restored to the correct freshly-computed value; still one row.
    refreshed_row = next(r for r in env.tables["chapter_skills"] if r["id"] == skill_id)
    assert refreshed_row["content_sha256"] == good_sha
    assert refreshed_row["signature"] != "stale"
    assert len(env.tables["chapter_skills"]) == 5


async def test_refresh_skill_signature_unchanged_when_current(env):
    """No drift → refresh_skill_signature reports 'unchanged' and writes nothing new."""
    await starter_pack.seed_starter_pack()
    m = starter_pack.NONPROFIT_SKILLS[0]
    sha_hex, sig_b64 = starter_pack._sign_manifest(m)
    status = await sr.refresh_skill_signature(
        manifest=m, signature=sig_b64, signing_key_did=starter_pack._did(), content_sha256=sha_hex
    )
    assert status == "unchanged"


# ── 4. Serialisation matches GET /api/skills shape ────────────────────────────


async def test_seeded_skills_appear_in_list_skills(env):
    """After seeding, sr.list_skills() returns all 5 — the same data the endpoint serves."""
    await starter_pack.seed_starter_pack()

    rows = await sr.list_skills()
    response = {"skills": rows, "count": len(rows)}

    assert response["count"] == 5
    names = {s["name"] for s in response["skills"]}
    assert "donor-acknowledgement" in names
    assert "grant-deadline-tracker" in names
    assert "volunteer-scheduler" in names
    assert "impact-report-summarizer" in names
    assert "event-outreach" in names


async def test_each_skill_row_has_registry_required_fields(env):
    """Every row returned from the registry contains the fields the API exposes."""
    await starter_pack.seed_starter_pack()
    rows = await sr.list_skills()
    required = {"id", "name", "version", "description", "capabilities", "author_did", "chapter_id"}
    for row in rows:
        missing = required - set(row)
        assert not missing, f"Skill {row.get('name')!r} row missing fields: {missing}"


async def test_list_skills_excludes_revoked_by_default(env):
    """Seeded skills are non-revoked and must show up; a manually revoked one must not."""
    await starter_pack.seed_starter_pack()
    # Revoke one skill directly in the fake store.
    for row in env.tables["chapter_skills"]:
        if row["name"] == "event-outreach":
            row["revoked_at"] = datetime.now(UTC).isoformat()
            break

    rows = await sr.list_skills()
    names = {r["name"] for r in rows}
    assert "event-outreach" not in names
    assert len(names) == 4


async def test_capabilities_are_stored_on_row(env):
    """The top-level capabilities column is populated on every row."""
    await starter_pack.seed_starter_pack()
    rows = await sr.list_skills()
    for row in rows:
        assert isinstance(row["capabilities"], list), f"{row['name']} capabilities not a list"
        assert len(row["capabilities"]) > 0, f"{row['name']} has empty capabilities"
