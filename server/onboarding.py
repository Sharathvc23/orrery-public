"""
First-run onboarding flow — rendered as an A2UI surface per step.

The flow:
    0. Identity        — display name, bio, optional avatar
    1. LLM             — provider + api key (key stored in private memory)
    2. Done            — summary + "open dashboard" button

⚠️ A "PICK A CHAPTER" STEP USED TO SIT BETWEEN IDENTITY AND LLM AND WAS REMOVED.
It was `required: True`, it told the operator it was how their agent "joins a
chapter to find peers and participate in federation", and its answer was written
to `agent_settings` under `channels.primary_chapter_url` — a key with exactly one
reference in the repository: that write. Nothing read it, it was absent from
`settings.DEFAULTS`, and no surface rendered it.

It was removed rather than wired up because the value it asked for was already
known and used elsewhere: a member's chapter is `agents.config.parent_chapter`,
fixed at registration, and this wizard is served BY that chapter on routes that
require a signature bound to the calling member. The member SDK keeps its own
`chapter_url` in its own config, written by `community-member init`, and that is
what federation actually reads. A required field that changes nothing is worse
than an absent one: it manufactures confidence in a connection never made.

State (current step) lives in `agents.onboarding_step` (existing column) — see
`get_step` for why that integer is DERIVED rather than trusted. Answers are
persisted incrementally: identity → agents table; LLM provider → agent_settings
via settings module; LLM key → agent_private_memory.

The A2UI surface (`build_onboarding_surface`) reads the step and renders
just the current step's Form. Submitting the form hits
`POST /api/onboarding/advance` which validates + persists + increments.

Public API
----------
get_step(agent_id)                        — int 0..STEPS
advance(agent_id, step, values, ...deps)  — validate + persist + ++step
reset(agent_id)                           — back to step 0
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

STEPS = 3  # 0..2 → step 2 is "done"

# ── DI ───────────────────────────────────────────────────

_pg_request: Callable | None = None
_pg_write: Callable | None = None


class OnboardingWriteFailed(RuntimeError):
    """A write this step depends on was refused by the database.

    Distinct from ``ValueError`` (the operator's input was invalid, which is
    their problem and a 400) — this says the input was fine and the store would
    not take it, which is the server's problem. The route maps it to a 503.
    """


class StepPartiallyApplied(OnboardingWriteFailed):
    """A step failed PART WAY THROUGH, and says how far it got.

    ⚠️ THESE WRITES ARE NOT ATOMIC AND CANNOT BE MADE SO HERE — see
    ``advance``. Making the failure loud did not make the sequence whole: a
    refusal on write N leaves 1..N-1 applied. The wizard used to answer that
    with "Nothing was recorded; retry", which is false in the other direction
    the moment anything landed, and is the same defect as reporting a success
    that did not happen.

    ``saved`` names the writes that DID land, in order. ``failed`` names the one
    that did not. Both are write labels, never values the operator submitted.
    """

    def __init__(self, failed: str, saved: list[str], cause: BaseException) -> None:
        self.failed = failed
        self.saved = list(saved)
        detail = ", ".join(self.saved) if self.saved else "nothing"
        super().__init__(f"{failed} was refused ({cause}). Already saved: {detail}.")


def _strict_adapter(pg_request_fn: Callable) -> Callable:
    """Hold a plain ``pg_request``-shaped function to the strict contract.

    ``pg_store.pg_request`` returns None on a configured-DB failure — it logs
    ``db.operation_failed`` and a metric, and the caller carries on. That is the
    behaviour this module must NOT have, so production injects
    ``pg_store.pg_execute_strict`` directly.

    This adapter exists so a caller that injects only a plain function — every
    test, and any future caller that forgets — is held to the same contract
    rather than silently getting the old swallow back. Strictness is not
    something a call site can opt out of by omission.
    """

    async def _write(method: str, table: str, params: dict | None = None, body: Any = None) -> Any:
        result = await pg_request_fn(method, table, params=params, body=body)
        if result is None:
            raise OnboardingWriteFailed(f"{method} {table}: the database refused the write")
        return result

    return _write


@asynccontextmanager
async def _step_write(label: str, saved: list[str]):
    """One write in the sequence: recorded if it lands, named if it does not.

    The label is operator-facing prose, so it describes what was SAVED and never
    what was submitted — "your provider key", not the key.
    """
    try:
        yield
    except StepPartiallyApplied:
        raise
    except Exception as exc:
        raise StepPartiallyApplied(label, saved, exc) from exc
    saved.append(label)


async def _write(method: str, table: str, params: dict | None = None, body: Any = None) -> Any:
    """Every durable write this module makes goes through here."""
    if _pg_write is None:
        raise RuntimeError("onboarding not initialized")
    return await _pg_write(method, table, params=params, body=body)


def init(pg_request_fn: Callable, execute_strict_fn: Callable | None = None) -> None:
    """Wire the datastore. Reads go through ``pg_request_fn``; WRITES go through
    ``execute_strict_fn``, which must raise rather than return None on failure.

    ⚠️ ONBOARDING IS WHERE A HUMAN TYPES DATA ONCE AND NEVER LOOKS AGAIN. A
    swallowed write here is not a degraded feature, it is a name and a bio that
    the operator was told were saved and were not.
    """
    global _pg_request, _pg_write
    _pg_request = pg_request_fn
    _pg_write = execute_strict_fn or _strict_adapter(pg_request_fn)


# ── Step definitions — introspected by the surface builder ──

STEP_SPEC: dict[int, dict[str, Any]] = {
    0: {
        "title": "Who are you?",
        "description": "A display name and one-line bio. This is what peer agents see.",
        "fields": [
            {"key": "display_name", "label": "Display name", "type": "text", "required": True, "max_length": 80},
            {"key": "bio", "label": "One-line bio", "type": "text", "max_length": 240},
            {"key": "avatar_url", "label": "Avatar URL (optional)", "type": "text", "max_length": 500},
        ],
    },
    1: {
        "title": "Connect an LLM",
        "description": "Your agent uses an LLM for reasoning. Pick a provider and paste a key. "
        "Your key is sent to this org over TLS and stored encrypted at rest, so your agent can use it to reason. It is never returned by any page or API, and never sent to anyone but the provider you choose.",
        "fields": [
            {
                "key": "provider",
                "label": "Provider",
                "type": "select",
                "options": [
                    {"label": "Anthropic Claude", "value": "anthropic"},
                    {"label": "OpenAI", "value": "openai"},
                    {"label": "xAI Grok", "value": "xai"},
                    {"label": "Groq", "value": "groq"},
                    {"label": "Local (Ollama)", "value": "ollama_local"},
                ],
                "default": "anthropic",
                "required": True,
            },
            {"key": "api_key", "label": "API key", "type": "password", "max_length": 500},
        ],
    },
    2: {
        "title": "You're ready",
        "description": "Your agent is set up. Head to the dashboard to start using it.",
        "fields": [],
    },
}


def step_spec(step: int) -> dict[str, Any] | None:
    return STEP_SPEC.get(step)


def total_steps() -> int:
    return STEPS


# ── Read current step ────────────────────────────────────


def _last_answerable_step() -> int:
    """The highest index that still ASKS the operator something.

    ``STEPS - 1`` is the terminal "you're ready" screen and has no fields, so it
    is the one step that must never be reached by arithmetic alone.
    """
    return STEPS - 2


async def get_step(agent_id: str) -> int:
    """Return the agent's onboarding step (0 = just started, STEPS-1 = done).

    ⚠️ THE STORED INTEGER IS DERIVED FROM, NOT TRUSTED. ``agents.onboarding_step``
    is an ordinal whose meaning is defined by the current STEP_SPEC, and this
    wizard just lost a step: an install carries integers written under a
    four-step numbering into a three-step one. Read literally, an operator
    stored at the old step 2 ("about to connect an LLM") would read as DONE and
    be told they were set up having never named a provider — and after the
    provider work, a member with no provider row is correctly refused a session,
    so their agent would simply never start. An operator stored at the old step
    3 ("done") would fall off the end entirely: ``step_spec`` returns None and
    the next submit is rejected as ``unknown step 3``.

    So completion is read from where completion is actually RECORDED — the
    timestamp ``mark_onboarding_complete`` writes — and the integer is clamped
    to something answerable otherwise. Two properties follow, and both are the
    point:

    * **Nobody is reported done off an integer.** A stored value at or past the
      terminal screen without the timestamp sends the operator back to the last
      question instead, so the failure is a repeated question rather than an
      agent that silently never runs.
    * **It is idempotent because it is a derivation, not a mutation.** A data
      migration (``onboarding_step - 1``) could not be: re-running it walks
      completed members back into the wizard, and ``infra/migrations/README.md``
      requires every migration to be safe to re-run — there is no runner and no
      applied-migrations table to stop a second application.

    Reading ``agent_settings`` directly is a small deliberate coupling: it is
    one column, it is the flag the settings module already writes for exactly
    this question, and the alternative is threading a checker through three
    call sites to ask it.
    """
    if _pg_request is None:
        raise RuntimeError("onboarding not initialized")
    rows = await _pg_request(
        "GET",
        "agents",
        params={"agent_id": f"eq.{agent_id}", "select": "onboarding_step", "limit": "1"},
    )
    if not rows:
        return 0
    raw = rows[0].get("onboarding_step")
    stored = int(raw) if raw is not None else 0
    if stored <= 0:
        return 0

    done_rows = await _pg_request(
        "GET",
        "agent_settings",
        params={"agent_id": f"eq.{agent_id}", "select": "onboarding_completed_at", "limit": "1"},
    )
    if done_rows and done_rows[0].get("onboarding_completed_at"):
        return STEPS - 1
    return min(stored, _last_answerable_step())


# ── Validate step values ─────────────────────────────────


def _validate_step_values(step: int, values: dict) -> tuple[bool, str]:
    spec = STEP_SPEC.get(step)
    if spec is None:
        return False, f"unknown step {step}"
    for f in spec.get("fields", []):
        v = values.get(f["key"])
        if f.get("required") and not v:
            return False, f"missing required field {f['key']!r}"
        if v and f.get("max_length") and isinstance(v, str) and len(v) > f["max_length"]:
            return False, f"field {f['key']!r} too long (max {f['max_length']})"
        if f.get("type") == "select":
            allowed = [o["value"] for o in f.get("options", [])]
            if v and v not in allowed:
                return False, f"invalid value for {f['key']!r} — must be one of {allowed}"
    return True, "ok"


# ── Advance ──────────────────────────────────────────────


#: Onboarding's option list, the resolver registry and the ``agent_api_keys``
#: CHECK constraint were three different vocabularies for one question. The
#: option list offered ``ollama_local``, which is in neither of the other two —
#: ``llm_runtime.resolve`` refuses it by name and the constraint rejects it — so
#: choosing "Local (Ollama)" produced a stored provider nothing could run.
_PROVIDER_ALIASES = {"ollama_local": "ollama", "local": "ollama"}


def normalise_provider_choice(raw: object) -> str:
    """An option-list value as the name the rest of the stack uses."""
    name = str(raw or "").strip().lower()
    return _PROVIDER_ALIASES.get(name, name)


async def _store_provider_key(agent_id: str, provider: str, api_key: str) -> None:
    """Seal the operator's key into the table the member runtime reads.

    Keyed by ``profile_id``, which is what that table uses, so the agent row is
    read first. A local provider needs no credential and is skipped rather than
    written: it would be refused by the CHECK constraint anyway, and storing a
    key for an endpoint that ignores it is a secret held for no reason.
    """
    import api_key_store

    if _pg_request is None or provider in _LOCAL_PROVIDERS or not api_key_store.writable(provider):
        return
    rows = await _pg_request(
        "GET", "agents", params={"agent_id": f"eq.{agent_id}", "select": "profile_id", "limit": "1"}
    )
    profile_id = (rows[0].get("profile_id") if rows else "") or ""
    if not profile_id:
        print(f"[onboarding] {agent_id} has no profile_id yet; the provider key was not stored for execution")
        return
    # The STRICT writer, not the plain one. ``save_api_key`` returns True as
    # soon as it has issued the write and never inspects the result, so its
    # bool cannot tell this caller whether the credential landed — the only
    # place that can refuse is the writer itself. Its own SELECT is unaffected:
    # an absent row comes back as an empty list, not None.
    if _pg_write is None:
        raise RuntimeError("onboarding not initialized")
    await api_key_store.save_api_key(
        _pg_write, profile_id=profile_id, provider=provider, api_key=api_key
    )


#: Providers reached without leaving the machine. They take no credential.
_LOCAL_PROVIDERS = frozenset({"ollama", "llama_cpp", "mlx_lm"})


async def advance(
    agent_id: str,
    step: int,
    values: dict,
    store_secret: Callable[[str, str, str], Any] | None = None,
    settings_module: Any = None,
) -> dict:
    """Persist values from the current step and increment onboarding_step.

    Returns {'next_step': int, 'completed': bool}. Raises ValueError on
    invalid input.

    ⚠️ THIS SEQUENCE IS NOT ATOMIC, AND CANNOT BE MADE SO FROM HERE.
    A step performs several independent writes across ``agents``,
    ``agent_settings``, ``agent_api_keys`` and ``agent_private_memory``.
    ``pg_store`` runs each statement on its own pooled connection
    (``pool.fetch``), and an asyncpg transaction lives on ONE connection, so
    these statements cannot share one today. Giving them one would need a
    connection-scoped request API in ``pg_store`` AND a per-call writer on
    ``settings``, which resolves its writer from module globals shared by every
    concurrent request — rebinding those for the duration of a step would leak
    across concurrent callers, which is a worse defect than the one it fixes.
    That is a datastore-layer change, not an onboarding one.

    So the property this function offers instead is **every partial application
    is a safe partial**, achieved by ORDER:

    1. The member's own credential is written BEFORE the provider recorded on
       their agent row. ``load_sessions`` reads a stored key row as its own
       provider-and-key PAIR, so "key landed, agent row did not" is a member who
       RUNS on the provider they chose. The reverse — provider recorded, no
       credential — is a member who is correctly refused a session and simply
       does not start. Both are honest; the first is strictly closer to done.
    2. The private-memory copy of the credential goes LAST, because nothing
       reads it (see below) and its failure must not strand the writes that
       matter.
    3. The step increment is last of all, so the wizard never advances past a
       step whose state did not land.

    On a refusal it raises ``StepPartiallyApplied``, which NAMES the writes that
    landed. The caller must not tell the operator that nothing was recorded.

    RESUBMITTING THE SAME STEP IS SAFE. Every write here is idempotent, measured
    against the real schema rather than assumed: the ``agents`` PATCHes set
    absolute values; ``settings.update_settings`` and ``mark_onboarding_complete``
    read-merge-then-write; ``api_key_store.save_api_key`` selects the
    ``(profile_id, provider)`` row before choosing INSERT or UPDATE, and
    re-sealing under a fresh nonce still unseals to the same key.

    Dependencies injected so tests don't need the live integrations:
    - `store_secret(agent_id, key_name, value)` persists LLM API keys to
      private memory. If None, the key is silently dropped (useful for
      tests; real callers must pass this).
    - `settings_module` is the `settings` module (for LLM provider, etc).
    """
    if _pg_request is None:
        raise RuntimeError("onboarding not initialized")

    ok, reason = _validate_step_values(step, values)
    if not ok:
        raise ValueError(reason)

    current = await get_step(agent_id)
    if step != current:
        raise ValueError(f"step mismatch — expected {current}, got {step}")

    # Every write that lands is recorded, in order, so a refusal can say how far
    # the step actually got instead of guessing.
    saved: list[str] = []

    # Persist per-step side effects.
    if step == 0:
        patch: dict[str, Any] = {}
        if values.get("display_name"):
            patch["name"] = values["display_name"][:80]
        if values.get("bio"):
            patch["description"] = values["bio"][:240]
        if values.get("avatar_url"):
            patch["avatar_url"] = values["avatar_url"][:500]
        if patch:
            # ⚠️ ONE BODY, THREE FIELDS. Before 0007 added `agents.avatar_url`,
            # an operator who filled the optional avatar field made this whole
            # PATCH fail on the unknown column — and it carries their name and
            # bio too, so all three were lost while the wizard advanced. Strict
            # now, so a refusal reaches them instead of a log nobody reads.
            async with _step_write("your name and bio", saved):
                await _write(
                    "PATCH",
                    "agents",
                    params={"agent_id": f"eq.{agent_id}"},
                    body=patch,
                )

    elif step == 1:
        provider = normalise_provider_choice(values.get("provider"))
        api_key = values.get("api_key")
        if settings_module is not None and provider:
            async with _step_write("your recorded provider preference", saved):
                await settings_module.update_settings(agent_id, {"llm": {"provider": provider}}, strict=True)
        # ⚠️ THE CREDENTIAL GOES FIRST, and the order is the guarantee. If this
        # lands and the agent row below does not, ``load_sessions`` still runs
        # the member: it reads a stored key row as its own provider-and-key
        # PAIR. Written the other way round, the same failure leaves a member
        # recorded as using a provider they have no credential for — refused a
        # session, and no worse, but strictly further from done.
        if api_key and provider:
            async with _step_write("your provider key", saved):
                await _store_provider_key(agent_id, provider, api_key)
        if provider:
            # ⚠️ THE WRITE THAT MAKES THE CHOICE REAL. The path that runs a
            # member reads ``agents.llm_provider`` and ``agent_api_keys``; until
            # this, onboarding wrote neither, so the operator's answer was
            # stored, displayed, and executed by nothing.
            async with _step_write("your chosen provider", saved):
                await _write("PATCH", "agents", params={"agent_id": f"eq.{agent_id}"}, body={"llm_provider": provider})
        if api_key and store_secret is not None:
            # ⚠️ BEST-EFFORT, LAST, AND DELIBERATELY NOT STRICT — the one write
            # here that is allowed to fail quietly, so it is named and reasoned
            # rather than left to inference.
            #
            # It is a second copy of the credential in the member's private
            # memory under ``llm_key_<provider>``, and NOTHING READS IT: the
            # runtime reads ``agent_api_keys``, written just above. Measured
            # against a database loaded from init.sql, it does not even land —
            # ``agent_private_memory.owner_id`` is ``uuid NOT NULL`` and the
            # caller supplies the member's TEXT handle, so every write is
            # refused with `invalid input syntax for type uuid` and swallowed.
            # An earlier comment here claimed removing it "would drop state an
            # operator may already depend on"; there has never been any state.
            #
            # Left in place rather than deleted or repaired because both are
            # decisions beyond this change: repairing it would START creating
            # copies of a credential that nothing reads, and deleting it is a
            # scope call. What it must NOT do is strand the two writes above, so
            # it goes last and its outcome is reported rather than asserted.
            try:
                await store_secret(agent_id, f"llm_key_{provider}", api_key)
            except Exception as exc:  # noqa: BLE001 — deliberately best-effort; see above
                print(f"[onboarding] the private-memory copy of the credential was not stored: {exc}")

    # ⚠️ THE INCREMENT IS A WRITE LIKE ANY OTHER, AND THE SHARPEST ONE.
    # `next_step` is arithmetic — it does not depend on anything landing. If
    # this PATCH is refused and swallowed, the wizard moves the operator on
    # while the row still records the old step, so their next submit is
    # rejected as a step mismatch and they retype what they just typed. The
    # return below is only allowed to describe a step that was actually stored.
    next_step = min(step + 1, STEPS - 1)
    async with _step_write("your progress through the wizard", saved):
        await _write(
            "PATCH",
            "agents",
            params={"agent_id": f"eq.{agent_id}"},
            body={"onboarding_step": next_step},
        )

    completed = next_step >= STEPS - 1
    if completed and settings_module is not None:
        async with _step_write("that you finished onboarding", saved):
            await settings_module.mark_onboarding_complete(agent_id, strict=True)

    return {"next_step": next_step, "completed": completed}


async def reset(agent_id: str) -> None:
    """Back to step 0 — lets a member re-run the wizard.

    Strict for the same reason the increment is: the caller returns
    ``{"step": 0}`` unconditionally, so a refused write here tells a member the
    wizard was reset when it was not, and their first submit fails on a step
    mismatch they cannot see the cause of.
    """
    if _pg_write is None:
        raise RuntimeError("onboarding not initialized")
    await _write(
        "PATCH",
        "agents",
        params={"agent_id": f"eq.{agent_id}"},
        body={"onboarding_step": 0},
    )
