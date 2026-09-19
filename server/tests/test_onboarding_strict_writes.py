"""Onboarding must not report a success it did not achieve.

``advance()`` computes its answer as ``next_step = min(step + 1, STEPS - 1)`` —
arithmetic, never a function of whether anything landed. Every write underneath
it went through ``pg_request``, which logs ``db.operation_failed``, emits a
metric and returns None. So a refused write produced ``{"next_step": n,
"completed": ...}`` exactly like a successful one.

That is not a theoretical gap. It is how an unknown ``avatar_url`` column
silently ate an operator's display name and bio — the PATCH carries all three
fields, the column did not exist, and the wizard advanced anyway.

The store here refuses ONE NAMED WRITE and behaves normally otherwise, because
a fake that fails everything cannot tell "the wizard stopped on the write I
broke" from "the wizard stops on anything".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import onboarding
import settings as settings_mod

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_settings_onboarding import _FakePostgres  # noqa: E402  (needs the tests dir above)

AID = "strict-writes-member"


class _RefusingPostgres(_FakePostgres):
    """A store that refuses one write the way a configured database does.

    ``pg_store.pg_request`` does not raise on a failed write: it returns None.
    Reproducing that exactly is the point — a fake that raised would prove the
    exception propagates, not that the None is noticed.
    """

    def __init__(self, refuse: tuple[str, str] | None = None, refuse_body_key: str | None = None):
        super().__init__()
        self.refuse = refuse
        self.refuse_body_key = refuse_body_key
        self.refused: list[tuple] = []

    async def __call__(self, method, table_or_path, params=None, body=None):
        table = table_or_path.split("?")[0]
        if self.refuse == (method, table):
            if self.refuse_body_key is None or self.refuse_body_key in (body or {}):
                self.refused.append((method, table, body))
                return None
        return await super().__call__(method, table_or_path, params=params, body=body)


@pytest.fixture
def store(monkeypatch):
    def _make(refuse=None, refuse_body_key=None, step=0):
        pg = _RefusingPostgres(refuse=refuse, refuse_body_key=refuse_body_key)
        pg.tables["agents"] = [
            {"agent_id": AID, "profile_id": "p1", "name": "before", "description": "", "onboarding_step": step}
        ]
        onboarding.init(pg_request_fn=pg)
        settings_mod.init(pg_request_fn=pg)
        return pg

    return _make


def _row(pg) -> dict:
    return pg.tables["agents"][0]


# ── detector validation ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_step_that_lands_still_reports_success(store):
    """Every assertion below is that a failure does NOT return. If the ordinary
    path did not return either, the whole file would pass on a wizard that never
    works at all."""
    pg = store()
    result = await onboarding.advance(AID, 0, {"display_name": "Ada", "bio": "builds things"})
    assert result == {"next_step": 1, "completed": False}
    assert _row(pg)["name"] == "Ada"
    assert _row(pg)["onboarding_step"] == 1


# ── G1: a refused write is not a reported success ────────────────────────────


@pytest.mark.asyncio
async def test_a_refused_field_write_does_not_report_a_saved_step(store):
    """The measured case: the identity PATCH is refused, so the name and bio the
    operator typed are not stored. Reporting next_step here is what let that
    loss pass unnoticed."""
    pg = store(refuse=("PATCH", "agents"), refuse_body_key="name")

    with pytest.raises(onboarding.OnboardingWriteFailed):
        await onboarding.advance(AID, 0, {"display_name": "Ada", "bio": "builds things"})

    assert pg.refused, "the store never refused anything — this test proved nothing"
    assert _row(pg)["name"] == "before", "the fake stored a write it was told to refuse"


@pytest.mark.asyncio
async def test_a_refused_step_increment_does_not_report_a_saved_step(store):
    """⚠️ THE SHARPEST CASE. The field write lands and only the INCREMENT is
    refused, so the row holds the operator's data at the old step while the
    caller is told to move on. Their next submit is then rejected as a step
    mismatch and they retype what they just typed — a defect one row over from
    the one everybody looks at."""
    pg = store(refuse=("PATCH", "agents"), refuse_body_key="onboarding_step")

    with pytest.raises(onboarding.OnboardingWriteFailed):
        await onboarding.advance(AID, 0, {"display_name": "Ada", "bio": "builds things"})

    assert pg.refused and pg.refused[0][2] == {"onboarding_step": 1}
    assert _row(pg)["name"] == "Ada", "the field write should have landed — only the increment was refused"
    assert _row(pg)["onboarding_step"] == 0, "the step advanced in the row despite the refusal"


@pytest.mark.asyncio
async def test_a_refused_settings_write_does_not_report_a_saved_step(store):
    """The LLM step also persists through the settings module, whose return
    value is built from an in-memory merge and never read back — so without a
    strict path the caller cannot tell a stored patch from a dropped one.

    (This used to drive the "pick a chapter" step, which was removed: it was
    required, promised federation, and wrote a key nothing read.)
    """
    pg = store(refuse=("POST", "agent_settings"), step=1)

    with pytest.raises((onboarding.OnboardingWriteFailed, settings_mod.SettingsWriteFailed)):
        await onboarding.advance(AID, 1, {"provider": "anthropic"}, settings_module=settings_mod)

    assert pg.refused
    assert _row(pg)["onboarding_step"] == 1, "the step advanced despite the settings write being refused"


@pytest.mark.asyncio
async def test_a_refused_provider_write_does_not_report_a_saved_step(store):
    """Step 2's provider PATCH is the write that makes the operator's choice
    reach the runtime — the path that runs a member reads ``agents.llm_provider``.
    Refused and swallowed, the member silently keeps the column DEFAULT, which is
    a REMOTE provider nobody chose."""
    pg = store(refuse=("PATCH", "agents"), refuse_body_key="llm_provider", step=1)

    with pytest.raises(onboarding.OnboardingWriteFailed):
        await onboarding.advance(AID, 1, {"provider": "ollama_local"})

    assert pg.refused
    assert _row(pg)["onboarding_step"] == 1


@pytest.mark.asyncio
async def test_a_refused_reset_does_not_report_a_reset_wizard(store):
    """``onboarding_reset`` returns a constant ``{"step": 0}``, so a refused
    write tells a member the wizard was reset when it was not."""
    pg = store(refuse=("PATCH", "agents"), step=2)

    with pytest.raises(onboarding.OnboardingWriteFailed):
        await onboarding.reset(AID)

    assert pg.refused
    assert _row(pg)["onboarding_step"] == 2


# ── G1, at the route: a refusal is a readable 503, not a traceback ───────────


@pytest.mark.asyncio
async def test_the_route_answers_a_refused_write_with_503(store, monkeypatch):
    """A raised DatabaseError reaching FastAPI unhandled is a 500 with a
    traceback. The operator needs to know their step did not finish and that
    retrying is the right move, and must not be shown the values they submitted
    coming back in an error body.

    The wording assertion moved once the writes stopped being reported as
    all-or-nothing: this step's identity write LANDS and only the increment is
    refused, so a detail claiming nothing was recorded would be false. What is
    asserted here is the invariant, not the phrasing — the reply must not deny
    that anything was saved when something was."""
    import importlib

    monkeypatch.setenv("AGENT_ID", "TEST-strict-writes-chapter")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    sys.modules.pop("chapter_agent", None)
    ca = importlib.import_module("chapter_agent")

    pg = store(refuse=("PATCH", "agents"), refuse_body_key="onboarding_step")
    monkeypatch.setattr(ca, "_require_agent_owner", lambda *a, **k: None)

    req = ca.OnboardingAdvanceRequest(agent_id=AID, step=0, values={"display_name": "Ada"})
    with pytest.raises(ca.HTTPException) as exc:
        await ca.onboarding_advance(req, request=None)  # type: ignore[arg-type]

    detail = str(exc.value.detail)
    assert exc.value.status_code == 503, f"got {exc.value.status_code}, not a readable refusal"
    assert "Nothing was recorded" not in detail, (
        "the identity write landed, so telling the operator nothing was recorded is false"
    )
    assert "Already saved" in detail, "the reply does not say what did land"
    assert "Ada" not in detail, "the submitted value came back in the error body"
    assert pg.refused
