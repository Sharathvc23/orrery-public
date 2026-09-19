"""
Google A2A (Agent-to-Agent) protocol models — spec v0.2.

Source: https://google.github.io/A2A/
Reference: https://github.com/google/A2A

These models describe the Agent Card (served at /.well-known/agent.json)
and the JSON-RPC message envelope used for inter-agent communication.

Design note: A2A and NANDA AgentFacts are complementary. A2A describes
*how* agents talk (wire protocol, JSON-RPC, task lifecycle). NANDA
describes *who* agents are (DID-based identity, discovery, certification).
We serve both: /.well-known/agent.json (A2A spec) and /agentfacts.json
(NANDA Index spec). The A2A card includes a `x-nanda` extension object
so NANDA-aware clients get the bridge to our NANDA identity without
breaking A2A-only clients.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field

# ─── Agent Card primitives ─────────────────────────────────


class AgentProvider(BaseModel):
    """Who runs this agent."""

    organization: str = Field(..., description="Human-readable organization name")
    url: str | None = Field(None, description="Organization website")


class AgentCapabilities(BaseModel):
    """Which optional A2A features this agent supports."""

    streaming: bool = Field(default=False, description="Supports tasks/sendSubscribe (SSE)")
    pushNotifications: bool = Field(default=False, description="Supports webhook callbacks")
    stateTransitionHistory: bool = Field(default=False, description="Exposes full task state history")


class AgentAuthentication(BaseModel):
    """Credentials the caller must present. `schemes` lists the methods
    the agent accepts; `credentials` is an opaque server-specific string
    (public key, token issuer URL, etc.)."""

    schemes: list[str] = Field(..., description="e.g. ['bearer', 'apiKey', 'ed25519-hmac']")
    credentials: str | None = Field(None, description="Opaque credential hint, e.g. public key or token issuer")


class AgentSkill(BaseModel):
    """One capability the agent exposes.

    In A2A, a skill is discoverable ahead of time. It does NOT describe
    *tools* (those live behind tasks/send) — it describes what the agent
    is good at, so clients can pick the right agent for a task.
    """

    id: str = Field(..., description="Stable unique id for the skill (e.g. 'skill.submit_intent')")
    name: str = Field(..., description="Human-readable display name")
    description: str | None = Field(None, description="What the skill does")
    tags: list[str] | None = Field(None, description="Searchable tags")
    examples: list[str] | None = Field(None, description="Sample prompts")
    inputModes: list[str] | None = Field(None, description="Modalities accepted for input")
    outputModes: list[str] | None = Field(None, description="Modalities produced for output")


class AgentCard(BaseModel):
    """The /.well-known/agent.json payload — A2A v0.2."""

    name: str
    description: str
    url: str = Field(..., description="JSON-RPC endpoint for tasks/*")
    version: str
    documentationUrl: str | None = None
    provider: AgentProvider | None = None
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    authentication: AgentAuthentication

    # ⚠️ THE CURRENT SPEC'S FIELDS, ALONGSIDE THE v0.2 ONE ABOVE — not instead
    # of it. ``authentication`` is what a v0.2 client reads and our own client
    # still does; ``securitySchemes``/``security`` are what a current client
    # reads, and without them a stock client cannot see that this surface
    # authenticates until it is refused. A 401 a caller can anticipate is a
    # different product from one it discovers.
    securitySchemes: dict[str, dict[str, Any]] | None = None
    security: list[dict[str, list[str]]] | None = None

    defaultInputModes: list[str] = Field(default_factory=lambda: ["text"])
    defaultOutputModes: list[str] = Field(default_factory=lambda: ["text"])
    skills: list[AgentSkill] = Field(default_factory=list)

    # NANDA extension: A2A explicitly allows `x-` prefixed extensions.
    # Carries the NANDA DID + agentfacts URL so NANDA-aware clients can
    # cross-reference us in the NANDA Index. A2A-only clients ignore it.
    x_nanda: dict[str, Any] | None = Field(
        None,
        alias="x-nanda",
        description="NANDA Index cross-reference (did, agentfacts_url, chapter_url)",
    )

    model_config = {"populate_by_name": True}


# ─── JSON-RPC envelope (for Day 2) ─────────────────────────


class JSONRPCRequest(BaseModel):
    """A2A uses JSON-RPC 2.0 on the endpoint named by AgentCard.url."""

    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int | None = None
    method: str
    params: dict[str, Any] | list[Any] | None = None


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Any | None = None


class JSONRPCResponse(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int | None = None
    result: Any | None = None
    error: JSONRPCError | None = None


# ─── Task model (for Day 2) ────────────────────────────────

TaskState = Literal[
    "submitted",
    "working",
    "input-required",
    "completed",
    "canceled",
    "failed",
]


class TextPart(BaseModel):
    type: Literal["text"] = "text"
    text: str


class DataPart(BaseModel):
    type: Literal["data"] = "data"
    data: dict[str, Any]


class FilePart(BaseModel):
    type: Literal["file"] = "file"
    file: dict[str, Any]  # {name, mimeType, bytes | uri}


Part = TextPart | DataPart | FilePart


def _mint_message_id() -> str:
    """An identifier for one message within a conversation.

    ⚠️ DELIBERATELY NOT THE TASK-ID CONTRACT, AND THE DIFFERENCE MATTERS.
    ``a2a_rpc.mint_task_id`` uses 256 bits of CSPRNG because ``tasks/get`` and
    ``tasks/cancel`` are OPEN: there, the id IS the access control, so guessing
    one reaches a stranger's task. A messageId reaches nothing. No route takes
    one, nothing is addressable by it, and it exists so a client can tell two
    messages apart inside a conversation it already holds.

    So this is a uuid4, not a token, and that is not an oversight to be
    "fixed" later — implying an unguessability contract where none is required
    would make the next reader either over-engineer this or mistake the real
    one for a bug.
    """
    return uuid.uuid4().hex


class Message(BaseModel):
    role: Literal["user", "agent"]
    parts: list[Part]

    # ── Current-spec fields, added alongside the v0.2 shape, never replacing it.
    # A v0.2 caller sends neither and is unaffected; a current-spec client
    # requires both to parse the reply at all.
    messageId: str = Field(default_factory=_mint_message_id, description="Minted if absent, honoured if supplied")
    contextId: str | None = Field(None, description="Conversation this message belongs to, when the caller names one")
    taskId: str | None = Field(None, description="Task this message continues — how a current-spec client resumes")


def _mint_artifact_id() -> str:
    """Names one artifact within a task. Same reasoning as ``_mint_message_id``:
    no route accepts an artifactId, so it is an identifier, not an access
    control, and it does not carry the task id's entropy contract."""
    return uuid.uuid4().hex


class Artifact(BaseModel):
    #: Current-spec requirement, added beside the v0.2 fields. Minted if absent.
    artifactId: str = Field(default_factory=_mint_artifact_id)
    name: str | None = None
    description: str | None = None
    parts: list[Part]
    index: int = 0
    append: bool = False
    lastChunk: bool = False


class TaskStatus(BaseModel):
    state: TaskState
    message: Message | None = None
    timestamp: str | None = None


class Task(BaseModel):
    id: str
    sessionId: str | None = None
    #: The conversation this task belongs to. Additive: ``sessionId`` above is
    #: the v0.2 field and is unchanged, and this is what a current-spec client
    #: reads. See ``a2a_rpc.resolve_context_id`` for how the value is chosen —
    #: it is a decision, not a default, because the spec uses it to GROUP tasks.
    contextId: str | None = None
    #: The did:key of the caller that created this task, when there was one.
    #:
    #: ⚠️ OPTIONAL BY NECESSITY, NOT BY PREFERENCE. Task state lives on volumes
    #: that survive a deploy, so records written before this field existed are
    #: read back by this model every time an agent boots. An optional field with
    #: a default loads them unchanged; a required one would make every existing
    #: task a corrupt line that ``_load`` skips — silent data loss on upgrade.
    #: ``_append`` writes with ``exclude_none=True``, so a task with no creator
    #: serialises exactly as it did before: old and new records are
    #: byte-identical for that case.
    #:
    #: Absent means "created before ownership was recorded", NOT "owned by
    #: nobody, do as you like" — see ``a2a_rpc._creator_permits``.
    creatorDidKey: str | None = None
    status: TaskStatus
    artifacts: list[Artifact] = Field(default_factory=list)
    history: list[Message] = Field(default_factory=list)
    metadata: dict[str, Any] | None = None


# ─── Streaming events (tasks/sendSubscribe, tasks/resubscribe) ─────


class TaskStatusUpdateEvent(BaseModel):
    """Emitted when a task's status changes (working, input-required,
    completed, canceled, failed). `final: true` signals end-of-stream."""

    #: ⚠️ THE DISCRIMINATOR, AND IT IS WHY THE STREAM FAILED THE WAY IT DID.
    #: A current-spec client reads ``kind`` to decide which model to parse a
    #: frame as. With it absent the SDK falls back to guessing from the keys —
    #: it looks for ``taskId`` + ``final``, then ``messageId``, then ``id`` —
    #: and our frames carried only ``id``, so EVERY frame was parsed as a whole
    #: Task. The status frames happened to survive that; the artifact frame,
    #: which has no ``status``, could not.
    kind: Literal["status-update"] = "status-update"
    #: v0.2 field, kept. Our own client reads it.
    id: str
    #: Current-spec name for the same value, added alongside rather than
    #: replacing — that would be a breaking rename of a shipped wire format.
    taskId: str
    #: The conversation the frame's task belongs to; required by the
    #: current-spec event model.
    contextId: str | None = None
    status: TaskStatus
    final: bool = False
    metadata: dict[str, Any] | None = None


class TaskArtifactUpdateEvent(BaseModel):
    """Emitted when an artifact is produced or appended to. `append: true`
    on the artifact means "add these parts to the artifact at `index`";
    `lastChunk: true` means "this artifact is complete"."""

    kind: Literal["artifact-update"] = "artifact-update"
    id: str
    taskId: str
    contextId: str | None = None
    artifact: Artifact
    metadata: dict[str, Any] | None = None
