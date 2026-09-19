"""Whether the legacy-task population is answerable, and what it refuses to guess.

Recording a task's creator arrived after tasks already existed. The change that
added ``creatorDidKey`` allowed the tasks predating it and counted them, so the legacy
population would be observable rather than assumed before anyone flipped the
default to deny. The counter it shipped could not carry that ruling:

  - ``a2a_rpc.legacy_tasks_without_creator`` is a module-level int, so it resets
    to 0 on every process start and is not comparable between two readings of a
    fleet that redeploys;
  - it counts APPENDS TO creatorless tasks, not creatorless tasks that EXIST,
    and those are different populations;
  - and its zero is ambiguous in the direction that matters — a freshly booted
    process reports 0 whether the population is empty or enormous, so the number
    an operator would use to retire a fail-open default fails toward "safe to
    flip".

⚠️ THIS FILE DOES NOT FLIP ANYTHING. Legacy tasks are still allowed and still
counted; the last test here asserts that, because a PR that made the population
readable by quietly closing it would satisfy every other test in this file.
Nothing here decides whether a caller is KNOWN — a creator is a did:key compared
to a did:key, and a census only counts how many tasks have none.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from community_member import a2a_auth
from community_member import a2a_rpc as rpc
from community_member.a2a_auth import CallerIdentity
from community_member.a2a_models import Message as StoredMessage
from community_member.config import Config
from community_member.crypto import generate_ed25519_keypair
from community_member.server import create_app
from community_member.task_store import TaskStore

pytestmark = pytest.mark.no_local_token

ALICE = CallerIdentity(agent_id="alice", did_key="did:key:zAlice")
BOB = CallerIdentity(agent_id="bob", did_key="did:key:zBob")


async def _dispatch(name: str, args: dict) -> str:
    return json.dumps({"tool": name, "args": args})


@pytest.fixture
def store(tmp_path):
    return TaskStore(path=tmp_path / "tasks.jsonl")


@pytest.fixture
def handler(store):
    return rpc.A2ARPCHandler(store=store, dispatcher=_dispatch)


def _env(params: dict, method: str) -> dict:
    return {"jsonrpc": "2.0", "id": "rpc-1", "method": method, "params": params}


def _msg(text: str, **extra) -> dict:
    return {"role": "user", "parts": [{"type": "text", "text": text}], **extra}


def _seed_legacy(store: TaskStore, task_id: str) -> None:
    """A task on the volume with no recorded creator — the real legacy shape.

    Seeded through the STORE because a creatorless task cannot be made over the
    wire any more: a send needs a verified caller and records its key.
    """
    store.create(
        task_id=task_id,
        session_id=None,
        initial_message=StoredMessage(role="user", parts=[]),
        context_id=f"{task_id}-ctx",
    )
    assert store.get(task_id).creatorDidKey is None, "the seeded task recorded a creator"


# ── G1: a since-boot zero is not a measured absence ──────────────────────────


@pytest.mark.asyncio
async def test_a_fresh_process_reports_the_population_it_holds_not_its_own_zero(handler, store):
    """⚠️ THE DEFECT THIS PR EXISTS FOR, ASSERTED AS A CONTRAST. Both numbers
    are read from the SAME fresh handler with three creatorless tasks on the
    volume and nothing appended yet. The since-boot counter says 0 and is
    right; reporting that 0 as the population would tell an operator the legacy
    set is drained while three tasks sit in the store."""
    for i in range(3):
        _seed_legacy(store, f"legacy-{i}")

    census = rpc.legacy_task_census(store)

    assert census["measurement"]["creatorless_tasks_present"] == 3, (
        "the census did not count the creatorless tasks actually present"
    )
    assert census["observation"]["appends_to_creatorless_tasks_since_boot"] == 0, (
        "nothing was appended, so the since-boot observation must be 0 — if it is not, this "
        "test is not showing the contrast it claims to"
    )
    assert (
        census["measurement"]["creatorless_tasks_present"]
        != census["observation"]["appends_to_creatorless_tasks_since_boot"]
    ), "the measured population and the since-boot observation are the same number here — one of them is not being read"


def test_the_two_numbers_live_in_separately_named_objects(store):
    """Distinguishable at the READ SURFACE, not merely in this module. An
    operator parsing the reply must not be able to reach the wrong number by
    reading the obvious key."""
    census = rpc.legacy_task_census(store)
    assert "creatorless_tasks_present" in census["measurement"]
    assert "creatorless_tasks_present" not in census["observation"], (
        "the since-boot object publishes the population's key name — the two are confusable again"
    )
    assert "appends_to_creatorless_tasks_since_boot" not in census["measurement"]


def test_each_number_states_whether_it_survives_a_restart(store):
    census = rpc.legacy_task_census(store)
    assert census["measurement"]["durable"] is True
    assert census["observation"]["durable"] is False, (
        "the since-boot counter claims to survive a restart; it is a module-level int and does not"
    )
    assert census["observation"]["process_booted_at"], (
        "'since boot' is published without saying when boot was, so a reader cannot tell whether "
        "the window is five minutes or five weeks"
    )


def test_the_measured_count_actually_survives_a_restart(tmp_path):
    """The durability claim, exercised rather than declared. A second store over
    the same log is what a redeployed agent does."""
    path = tmp_path / "tasks.jsonl"
    first = TaskStore(path=path)
    _seed_legacy(first, "legacy-a")
    _seed_legacy(first, "legacy-b")
    assert rpc.legacy_task_census(first)["measurement"]["creatorless_tasks_present"] == 2

    reborn = TaskStore(path=path)
    assert rpc.legacy_task_census(reborn)["measurement"]["creatorless_tasks_present"] == 2, (
        "the measured population did not survive a restart — then it is the same kind of number "
        "as the counter it replaces"
    )


@pytest.mark.asyncio
async def test_a_task_with_a_creator_is_not_counted_as_legacy(handler, store):
    """DETECTOR VALIDATION. A census that counted every task would pass every
    assertion above and be useless to the ruling."""
    result = await handler.handle(_env({"message": _msg("alice")}, "message/send"), caller=ALICE)
    assert "error" not in result

    census = rpc.legacy_task_census(store)
    assert census["measurement"]["tasks_present"] == 1
    assert census["measurement"]["creatorless_tasks_present"] == 0, (
        "a task created by a verified caller was counted as legacy"
    )


def test_the_store_reports_lines_it_could_not_read(tmp_path):
    """The one way the count can understate the file, measured rather than
    assumed zero. ``_load`` skips a corrupt line silently; a census that did not
    say so would be claiming completeness it cannot check."""
    path = tmp_path / "tasks.jsonl"
    path.write_text('{"id":"good","status":{"state":"submitted"},"history":[],"artifacts":[]}\n{ not json\n')
    census = rpc.legacy_task_census(TaskStore(path=path))
    assert census["measurement"]["unreadable_log_lines"] == 1, (
        "an unparseable log line was skipped without being counted — the census cannot name its own blind spot"
    )


# ── G2: the read surface refuses an anonymous caller ─────────────────────────


def _cfg() -> Config:
    c = Config()
    c.agent_id = "census-agent"
    c.name = "Census"
    c.description = "A member"
    c.skills = ["calendar"]
    c.api_key = "x"
    c.public_key = base64.b64encode(b"\x02" * 32).decode()
    return c


@pytest.fixture
def client():
    return TestClient(create_app(_cfg()))


def _census_envelope() -> dict:
    return {"jsonrpc": "2.0", "id": "1", "method": "nanda/legacyTaskCensus", "params": {}}


def _error(response) -> dict:
    return (response.json() or {}).get("error") or {}


def test_an_anonymous_caller_gets_no_task_inventory(client):
    r = client.post("/", json=_census_envelope())
    assert _error(r).get("code") == rpc.ERROR_CALLER_REQUIRED, (
        "an unsigned caller obtained the agent's task inventory size: " + r.text[:300]
    )
    assert "result" not in r.json(), "the refusal still carried a result"


def test_the_census_is_declared_caller_required(client):
    assert a2a_auth.METHOD_ACCESS["nanda/legacyTaskCensus"] == a2a_auth.Access.CALLER_REQUIRED
    assert "nanda/legacyTaskCensus" not in a2a_auth.OPEN_METHODS
    card = client.get("/.well-known/agent-card.json").json()
    assert card["x-nanda"]["a2a_method_access"]["nanda/legacyTaskCensus"] == "caller-required", (
        "the card advertises the census as open while the handler gates it"
    )


def test_a_signed_caller_is_admitted_and_gets_the_census(client):
    """DETECTOR VALIDATION for the refusal above: if nothing could get through,
    the refusal would be indistinguishable from an unrouted method."""
    from community_member.a2a_client_v2 import _signed_headers

    payload = json.dumps(_census_envelope())
    kp = generate_ed25519_keypair()
    headers = _signed_headers(payload, "operator", kp["private_key"], kp["public_key"], scheme="ed25519")
    r = client.post("/", content=payload, headers=headers)
    body = r.json()
    assert "error" not in body, f"a correctly signed operator was refused the census: {body.get('error')}"
    assert "creatorless_tasks_present" in body["result"]["measurement"]


def test_the_census_never_returns_task_ids(handler, store):
    """Counts answer the ruling; ids would be the inventory itself. A verified
    caller does not get one either — the gate is not the only control here."""
    _seed_legacy(store, "legacy-secret-id")
    blob = json.dumps(rpc.legacy_task_census(store))
    assert "legacy-secret-id" not in blob, "the census disclosed a task id"


# ── G3: allow-and-count for creatorless tasks is unchanged ───────────────────


@pytest.mark.asyncio
async def test_a_legacy_append_is_still_allowed_and_still_counted(handler, store):
    """⚠️ THE THING THIS PR MUST NOT HAVE DONE. Making the population readable
    by closing it would satisfy every test above. The flip to deny is a ruling
    that has not been made."""
    _seed_legacy(store, "legacy")
    before = rpc.legacy_tasks_without_creator

    appended = await handler.handle(_env({"message": _msg("bob appends", taskId="legacy")}, "message/send"), caller=BOB)
    assert "error" not in appended, (
        f"a legacy task refused an append — the default was flipped: {appended.get('error')}"
    )

    assert rpc.legacy_tasks_without_creator == before + 1, (
        "the legacy append was allowed but not counted — the counter that makes the fail-open "
        "default visible stopped moving"
    )
    assert rpc.legacy_task_census(store)["observation"]["appends_to_creatorless_tasks_since_boot"] == before + 1, (
        "the census publishes a since-boot number that disagrees with the counter it reads"
    )


@pytest.mark.asyncio
async def test_the_measured_population_does_not_shrink_when_a_legacy_task_is_appended_to(handler, store):
    """An append is not a migration. The task still carries no creator, so it is
    still deniable and must still be counted as present."""
    _seed_legacy(store, "legacy")
    await handler.handle(_env({"message": _msg("bob appends", taskId="legacy")}, "message/send"), caller=BOB)
    census = rpc.legacy_task_census(store)
    assert census["measurement"]["creatorless_tasks_present"] == 1, (
        "appending to a legacy task removed it from the measured population without giving it a creator"
    )
    assert store.get("legacy").creatorDidKey is None, "the append silently adopted the appender as creator"
