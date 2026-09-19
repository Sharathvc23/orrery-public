"""
Persistent task store for A2A tasks/send lifecycle.

JSONL-backed, in-memory cache. Each task is written as a single line on
create and on every state transition, so a crash loses at most the
currently-running task's final state — the complete audit trail remains
on disk.

File format (one task per line):
    {"id": "...", "status": {...}, "artifacts": [...], ...}

Not thread-safe for cross-process writes. A single agent process owns
the file. If we ever need multi-process writes, switch to advisory
fcntl locking — but that's a W13+ concern.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .a2a_models import Artifact, Message, Task, TaskState

# Override, not a location. ``None`` means "resolve from the agent home on
# use", which is what honours COMMUNITY_MEMBER_HOME; tests set this to pin a
# temp file. Previously this was bound at import to the literal ``~/.nanda``,
# so every agent on a machine shared one task log regardless of its home.
TASK_STORE_PATH: Path | None = None


def default_path() -> Path:
    """``<agent home>/.nanda/tasks.jsonl``, carrying over a legacy ``~/.nanda`` log."""
    from community_member import agent_home

    return agent_home.resolve("tasks.jsonl")


class TaskStore:
    """Thread-safe-within-process task store."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or TASK_STORE_PATH or default_path()
        self._tasks: dict[str, Task] = {}
        # Log lines the replay below could not parse. Reported by :meth:`census`
        # because it is the ONLY way the census can understate what is on disk,
        # and a census that cannot name its own blind spot is a guess.
        self._unreadable_lines = 0
        # RLock because cancel() calls transition() while already holding the lock.
        self._lock = threading.RLock()
        self._load()

    # ─── Persistence ─────────────────────────────────────

    def _load(self) -> None:
        """Replay the JSONL log to reconstruct in-memory state.

        Last write per task id wins — later lines overwrite earlier ones,
        which is exactly the semantics we want for a mutation log.
        """
        from .a2a_models import Task  # avoid circular import at module load

        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    task = Task.model_validate(data)
                    self._tasks[task.id] = task
                except (json.JSONDecodeError, ValueError):
                    # Corrupt line — skip. We prefer to keep booting over
                    # refusing to start because of a bad historical row.
                    self._unreadable_lines += 1
                    continue

    def _append(self, task: Task) -> None:
        """Append the task state to the JSONL log. Called under self._lock."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = task.model_dump(mode="json", by_alias=True, exclude_none=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, separators=(",", ":")) + "\n")
        # 0o600 every write — JSONL rotation logic below may recreate the file.
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # ─── Public API ──────────────────────────────────────

    def create(
        self,
        task_id: str,
        session_id: str | None,
        initial_message: Message,
        metadata: dict[str, Any] | None = None,
        context_id: str | None = None,
        creator_did_key: str | None = None,
    ) -> Task:
        from .a2a_models import Task, TaskStatus

        with self._lock:
            if task_id in self._tasks:
                # A2A: tasks/send with an existing id is a *continuation*,
                # not a create. Append the new message to history and flip
                # status back to 'working'.
                task = self._tasks[task_id]
                task.history.append(initial_message)
                task.status = TaskStatus(
                    state="working",
                    timestamp=datetime.now(UTC).isoformat(),
                )
                self._append(task)
                return task

            task = Task(
                id=task_id,
                sessionId=session_id,
                contextId=context_id,
                creatorDidKey=creator_did_key,
                status=TaskStatus(
                    state="submitted",
                    timestamp=datetime.now(UTC).isoformat(),
                ),
                artifacts=[],
                history=[initial_message],
                metadata=metadata,
            )
            self._tasks[task_id] = task
            self._append(task)
            return task

    def transition(
        self,
        task_id: str,
        new_state: TaskState,
        artifact: Artifact | None = None,
        agent_reply: Message | None = None,
    ) -> Task:
        from .a2a_models import TaskStatus

        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                raise KeyError(task_id)
            task.status = TaskStatus(
                state=new_state,
                message=agent_reply,
                timestamp=datetime.now(UTC).isoformat(),
            )
            if artifact is not None:
                task.artifacts.append(artifact)
            if agent_reply is not None:
                task.history.append(agent_reply)
            self._append(task)
            return task

    def get(self, task_id: str) -> Task | None:
        with self._lock:
            return self._tasks.get(task_id)

    def census(self) -> dict[str, int]:
        """How many tasks this store holds, and how many carry no creator.

        ⚠️ THIS IS A MEASUREMENT, NOT AN OBSERVATION, and the distinction is the
        reason the method exists. It counts records that EXIST — recomputed from
        the replayed log every time it is called — so it does not reset when the
        process restarts, and a zero from it means "no creatorless tasks here"
        rather than "nothing has happened yet".

        ⚠️ IT IS ALSO EXACT, NOT A SAMPLE. The ownership check in
        ``a2a_rpc._creator_permits`` is consulted only when ``get`` returns a
        task, so the set of tasks a flip-to-deny could refuse is exactly the set
        this store holds: a creatorless task absent from the store is not
        refused, it is simply not found, and the send that named its id creates
        a fresh task with a creator recorded. So this count is the deniable
        population for this agent, not an estimate of it.

        The one way it can understate the file is a log line that would not
        parse, which is why ``unreadable_log_lines`` is returned alongside
        rather than left to be assumed zero. Such a task is absent from the
        store, so it is outside the ownership check too — it is a blind spot in
        the log, not in the count of what is deniable.
        """
        with self._lock:
            tasks = list(self._tasks.values())
            unreadable = self._unreadable_lines
        return {
            "tasks_present": len(tasks),
            "creatorless_tasks_present": sum(1 for t in tasks if not getattr(t, "creatorDidKey", None)),
            "unreadable_log_lines": unreadable,
        }

    def cancel(self, task_id: str) -> Task | None:
        """Idempotent cancel: canceling an already-terminal task is a no-op."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            if task.status.state in ("completed", "canceled", "failed"):
                return task
            return self.transition(task_id, "canceled")
