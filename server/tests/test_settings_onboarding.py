"""
Prosecution-grade tests for settings.py and onboarding.py.

Covers: get/update/reset settings, deep merge, validation, unknown-key
rejection, oversize payload rejection, onboarding step transitions,
validation errors, step-mismatch refusal, full flow to completion.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import onboarding
import settings as settings_mod

# ─── Fake Postgres ───────────────────────────────────────


class _FakePostgres:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {
            "agents": [],
            "agent_settings": [],
        }
        self.calls: list[tuple] = []

    async def __call__(self, method, table_or_path, params=None, body=None):
        self.calls.append((method, table_or_path, params, body))
        table = table_or_path.split("?")[0]

        if method == "GET":
            rows = list(self.tables.get(table, []))
            if params:
                rows = self._filter(rows, params)
            return rows

        if method == "POST":
            body = dict(body or {})
            body.setdefault("updated_at", datetime.now(UTC).isoformat())
            self.tables.setdefault(table, []).append(body)
            return [body]

        if method == "PATCH":
            filters = self._parse_filters(table_or_path, params)
            matched = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched

        return None

    @staticmethod
    def _parse_filters(path, params):
        out = {}
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
        return True


def _seed_agent(sb: _FakePostgres, agent_id: str, onboarding_step: int = 0, **extra) -> None:
    sb.tables["agents"].append({"agent_id": agent_id, "onboarding_step": onboarding_step, **extra})


@pytest.fixture
def sb():
    bs = _FakePostgres()
    settings_mod.init(pg_request_fn=bs)
    onboarding.init(pg_request_fn=bs)
    return bs


# ═══════════════════════════════════════════════════════════════
# settings.get_settings / get_setting — defaults + merging
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_settings_returns_defaults_for_unknown_agent(sb):
    result = await settings_mod.get_settings("ghost")
    # The llm section is an OBSERVATION of what the chapter executes, not a
    # literal this module gets to choose. Asserting a fixed "anthropic" here is
    # what let the surface display claude-opus-4-7 against a runtime that
    # resolved something else.
    assert result["llm"] == settings_mod.resolved_llm()
    assert result["voice"]["always_on"] is False


@pytest.mark.asyncio
async def test_get_settings_merges_stored_over_defaults(sb):
    # A PREFERENCE section, deliberately not `llm`. Every section merges stored
    # over default except `llm`, which reports what the runtime executes and is
    # therefore not something a stored value may claim to have changed.
    sb.tables["agent_settings"].append({"agent_id": "alice", "settings": {"voice": {"wake_word": True}}})
    result = await settings_mod.get_settings("alice")
    # Override wins for a preference
    assert result["voice"]["wake_word"] is True
    # Unspecified keys still come from defaults
    assert result["voice"]["always_on"] is False


@pytest.mark.asyncio
async def test_get_setting_dotted_lookup(sb):
    sb.tables["agent_settings"].append({"agent_id": "alice", "settings": {"llm": {"provider": "xai"}}})
    assert await settings_mod.get_setting("alice", "llm.provider") == "xai"
    # ⚠️ A STORED PROVIDER DOES NOT CARRY A MODEL WITH IT. The model still comes
    # from what the runtime resolved, so this pair can disagree — a stored
    # preference is not executed (llm_config reads the environment, never the
    # stored settings). Pinned here so the disagreement stays visible.
    assert await settings_mod.get_setting("alice", "llm.model") == settings_mod.resolved_llm()["model"]


@pytest.mark.asyncio
async def test_get_setting_missing_returns_default(sb):
    assert await settings_mod.get_setting("ghost", "nonexistent.path", default="fallback") == "fallback"


# ═══════════════════════════════════════════════════════════════
# update_settings — validation + merge + persistence
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_update_settings_creates_row_on_first_write(sb):
    result = await settings_mod.update_settings("alice", {"voice": {"wake_word": True}})
    assert result["voice"]["wake_word"] is True
    assert len(sb.tables["agent_settings"]) == 1
    assert sb.tables["agent_settings"][0]["agent_id"] == "alice"


@pytest.mark.asyncio
async def test_update_settings_merges_patch_into_existing(sb):
    sb.tables["agent_settings"].append(
        {"agent_id": "alice", "settings": {"voice": {"stt_provider": "whisper", "wake_word": True}}}
    )
    result = await settings_mod.update_settings("alice", {"voice": {"always_on": True}})
    # Patch merges into existing sub-dict — the other keys are preserved.
    assert result["voice"]["stt_provider"] == "whisper"
    assert result["voice"]["wake_word"] is True
    assert result["voice"]["always_on"] is True
    # The llm section is the runtime's answer, not a merged preference.
    assert result["llm"] == settings_mod.resolved_llm()


@pytest.mark.asyncio
async def test_update_settings_rejects_unknown_top_level_key(sb):
    """ADVERSARIAL: hostile client dumps arbitrary keys."""
    with pytest.raises(ValueError, match="unknown top-level key"):
        await settings_mod.update_settings("alice", {"ARBITRARY_INJECTION": {"x": 1}})


@pytest.mark.asyncio
async def test_update_settings_rejects_oversized_payload(sb):
    """ADVERSARIAL: 128KB patch rejected."""
    huge = {"llm": {"model": "x" * (128 * 1024)}}
    with pytest.raises(ValueError, match="too large"):
        await settings_mod.update_settings("alice", huge)


@pytest.mark.asyncio
async def test_update_settings_rejects_non_dict(sb):
    with pytest.raises(ValueError, match="patch must be a dict"):
        await settings_mod.update_settings("alice", "not-a-dict")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_reset_settings_wipes_to_defaults(sb):
    sb.tables["agent_settings"].append({"agent_id": "alice", "settings": {"llm": {"provider": "groq"}}})
    result = await settings_mod.reset_settings("alice")
    assert result["llm"] == settings_mod.resolved_llm()  # default restored
    assert sb.tables["agent_settings"][0]["settings"] == {}


@pytest.mark.asyncio
async def test_mark_onboarding_complete_sets_timestamp(sb):
    await settings_mod.mark_onboarding_complete("alice")
    assert len(sb.tables["agent_settings"]) == 1
    assert sb.tables["agent_settings"][0]["onboarding_completed_at"] is not None
    assert await settings_mod.is_onboarding_complete("alice") is True


@pytest.mark.asyncio
async def test_is_onboarding_complete_false_for_new_agent(sb):
    assert await settings_mod.is_onboarding_complete("alice") is False


# ═══════════════════════════════════════════════════════════════
# onboarding.get_step / advance / reset
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_step_new_agent_returns_zero(sb):
    assert await onboarding.get_step("ghost") == 0


@pytest.mark.asyncio
async def test_get_step_reads_persisted_value(sb):
    _seed_agent(sb, "alice", onboarding_step=1)
    assert await onboarding.get_step("alice") == 1


@pytest.mark.asyncio
async def test_a_completed_member_is_done_whatever_integer_they_carry(sb):
    """Completion is read from where it is RECORDED, not from the ordinal. An
    install that finished onboarding under the old four-step numbering carries a
    3 that no longer names a step at all."""
    _seed_agent(sb, "alice", onboarding_step=3)
    sb.tables["agent_settings"].append(
        {"agent_id": "alice", "settings": {}, "onboarding_completed_at": "2026-01-01T00:00:00Z"}
    )
    assert await onboarding.get_step("alice") == onboarding.STEPS - 1


@pytest.mark.asyncio
async def test_an_unfinished_member_is_never_reported_done_off_the_integer(sb):
    """⚠️ THE RENUMBERING GUARD. Removing the "pick a chapter" step shifted every
    index after it, so an operator stored at the old step 2 — about to connect an
    LLM — would read as the terminal screen and be told they were set up having
    never named a provider. Their agent would then never start, because a member
    with no provider row is correctly refused a session.

    Without the completion timestamp there is nothing to say they finished, so
    the integer is clamped to the last step that still asks something. The
    failure becomes a repeated question instead of a false success.
    """
    for stored in (2, 3, 99):
        sb.tables["agents"].clear()
        _seed_agent(sb, "alice", onboarding_step=stored)
        got = await onboarding.get_step("alice")
        assert got != onboarding.STEPS - 1, (
            f"a member stored at {stored} with no recorded completion was reported done"
        )
        assert onboarding.step_spec(got) is not None, f"stored {stored} resolved to a step with no spec"
        assert got == onboarding.STEPS - 2


@pytest.mark.asyncio
async def test_advance_step_0_persists_identity(sb):
    _seed_agent(sb, "alice", onboarding_step=0)
    result = await onboarding.advance(
        "alice",
        step=0,
        values={"display_name": "Alice", "bio": "engineer"},
        settings_module=settings_mod,
    )
    assert result["next_step"] == 1
    assert result["completed"] is False
    agent = sb.tables["agents"][0]
    assert agent["name"] == "Alice"
    assert agent["description"] == "engineer"
    assert agent["onboarding_step"] == 1


@pytest.mark.asyncio
async def test_advance_step_0_requires_display_name(sb):
    _seed_agent(sb, "alice")
    with pytest.raises(ValueError, match="display_name"):
        await onboarding.advance("alice", step=0, values={"bio": "no name"})


@pytest.mark.asyncio
async def test_advance_step_mismatch_rejected(sb):
    """ADVERSARIAL: client submits step 2 when agent is on step 0."""
    _seed_agent(sb, "alice", onboarding_step=0)
    with pytest.raises(ValueError, match="step mismatch"):
        await onboarding.advance("alice", step=1, values={"provider": "anthropic"}, settings_module=settings_mod)


@pytest.mark.asyncio
async def test_advance_step_2_invalid_provider_rejected(sb):
    _seed_agent(sb, "alice", onboarding_step=1)
    with pytest.raises(ValueError, match="invalid value for 'provider'"):
        await onboarding.advance("alice", step=1, values={"provider": "openrouter"}, settings_module=settings_mod)


@pytest.mark.asyncio
async def test_advance_step_2_persists_provider_and_stores_key(sb):
    _seed_agent(sb, "alice", onboarding_step=1)
    stored_secrets: list[tuple] = []

    async def fake_store(aid, key, val):
        stored_secrets.append((aid, key, val))

    await onboarding.advance(
        "alice",
        step=1,
        values={"provider": "anthropic", "api_key": "sk-test"},
        store_secret=fake_store,
        settings_module=settings_mod,
    )

    # The choice is PERSISTED — read it from the stored row, not from the
    # effective view. The effective view reports the provider the runtime
    # executes, which is a different question and not what this test is about.
    assert sb.tables["agent_settings"][0]["settings"]["llm"]["provider"] == "anthropic"

    # Key stored via private-memory injection.
    assert stored_secrets == [("alice", "llm_key_anthropic", "sk-test")]


@pytest.mark.asyncio
async def test_advance_to_completion_sets_completed_flag(sb):
    _seed_agent(sb, "alice", onboarding_step=1)
    result = await onboarding.advance(
        "alice",
        step=1,
        values={"provider": "openai"},
        settings_module=settings_mod,
    )
    assert result["next_step"] == 2
    assert result["completed"] is True
    assert await settings_mod.is_onboarding_complete("alice") is True


@pytest.mark.asyncio
async def test_advance_unknown_step_rejected(sb):
    _seed_agent(sb, "alice")
    with pytest.raises(ValueError, match="unknown step"):
        await onboarding.advance("alice", step=99, values={})


@pytest.mark.asyncio
async def test_reset_returns_agent_to_step_zero(sb):
    _seed_agent(sb, "alice", onboarding_step=2)
    await onboarding.reset("alice")
    assert await onboarding.get_step("alice") == 0


# ═══════════════════════════════════════════════════════════════
# Spec introspection used by the A2UI surface builder
# ═══════════════════════════════════════════════════════════════


def test_step_spec_has_required_fields():
    for step in range(onboarding.total_steps()):
        spec = onboarding.step_spec(step)
        assert spec is not None
        assert "title" in spec
        assert "description" in spec
        assert "fields" in spec
        # Last step has no fields (just confirmation).
        if step < onboarding.total_steps() - 1:
            assert len(spec["fields"]) > 0


def test_step_spec_unknown_step_returns_none():
    assert onboarding.step_spec(99) is None


def test_total_steps_is_finite():
    assert onboarding.total_steps() > 0
    assert onboarding.total_steps() < 100
