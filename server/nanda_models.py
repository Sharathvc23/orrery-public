"""
Vendored NANDA AgentFacts models — aligned with NANDA Index specification.

Source: https://github.com/projnanda/agentfacts-format
Spec: https://arxiv.org/abs/2507.14263

Models match the full AgentFacts schema including telemetry, adaptive
resolution, and version tracking for CRDT-lite compatibility.

When nanda-bridge publishes to PyPI, replace with: from nanda_bridge.models import *
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# ─── Provider & Identity ────────────────────────────────────


class NandaProvider(BaseModel):
    """Who hosts this agent — the DEPLOYMENT, never the project that wrote the code.

    ``name`` and ``url`` are optional because a field whose honest value is
    unknown should be ABSENT, not defaulted to somebody else's identity. They
    were required, and the defaults were the NANDA project's own name and URL,
    so a stranger resolving a self-hoster's member facts was told the provider
    was an organisation with nothing to do with that deployment — on the richest
    anonymous surface this runtime serves. Facts are dumped with
    ``exclude_none=True``, so None omits the field.

    ``did`` stays as it was and is LOAD-BEARING: member keys are rehydrated from
    ``agent_facts.provider.did`` at boot (chapter_agent), and dsar/agent_export
    read it. The block itself must never disappear.
    """

    name: str | None = Field(None, description="Human-readable provider name — the hosting org, omitted if unset")
    url: str | None = Field(None, description="The hosting org's own URL, omitted if unset")
    did: str | None = Field(None, description="Provider's DID (e.g., did:web:example.com)")


# ─── Endpoints & Resolution ─────────────────────────────────


class NandaAdaptiveResolver(BaseModel):
    url: str = Field(..., description="Resolver URL for dynamic routing")
    policies: list[str] = Field(default_factory=list, description="Routing policies: geo, load, threat-shield")


class NandaEndpoints(BaseModel):
    static: list[str] = Field(default_factory=list, description="Static endpoint URLs")
    dynamic: list[str] = Field(default_factory=list, description="Dynamic/load-balanced URLs")
    adaptive_resolver: NandaAdaptiveResolver | None = Field(None, description="NANDA adaptive resolver config")
    a2a: str | None = Field(None, description="A2A protocol endpoint URL")
    agentfacts_url: str | None = Field(None, description="Self-referencing AgentFacts URL for live fetching")


# ─── Authentication ──────────────────────────────────────────


class NandaAuthentication(BaseModel):
    # Default to Ed25519/did-auth (how the org actually signs) — not the stale
    # bespoke hmac.
    methods: list[str] = Field(default_factory=lambda: ["ed25519", "did-auth"])
    requiredScopes: list[str] | None = None


# ─── Capabilities & Skills ───────────────────────────────────


class NandaCapabilities(BaseModel):
    modalities: list[str] = Field(default_factory=lambda: ["text"])
    skills: list[str] = Field(default_factory=list)
    authentication: NandaAuthentication = Field(default_factory=NandaAuthentication)
    streaming: bool = False
    batch: bool = False


class NandaSkill(BaseModel):
    id: str = Field(..., description="Unique skill identifier (e.g., 'urn:nanda:skill:summarize:v1')")
    description: str = Field(..., description="Human-readable skill description")
    inputModes: list[str] = Field(default_factory=lambda: ["text"])
    outputModes: list[str] = Field(default_factory=lambda: ["text"])
    version: str | None = None
    parameters: dict[str, Any] | None = None
    maxTokens: int | None = Field(None, description="Max token budget for this skill")
    latencyBudgetMs: int | None = Field(None, description="Target latency in milliseconds")
    supportedLanguages: list[str] | None = Field(None, description="ISO 639-1 language codes")


# ─── Certification & Trust ───────────────────────────────────


class NandaCertification(BaseModel):
    level: str = Field(
        ..., description="'self-declared', 'github-verified', 'peer-attested', 'chapter-confirmed', 'audited'"
    )
    issuer: str | None = None
    attestations: list[str] = Field(default_factory=list)
    issuanceDate: datetime | None = None
    expirationDate: datetime | None = None


# ─── Evaluations & Telemetry ────────────────────────────────


class NandaEvaluations(BaseModel):
    performanceScore: float | None = Field(None, description="0-5 composite quality score")
    availability90d: str | None = Field(None, description="e.g. '99.5%'")
    lastAudited: datetime | None = None
    totalInteractions: int | None = Field(None, description="Total A2A interactions processed")
    avgResponseTimeMs: float | None = Field(None, description="Average response latency in ms")
    skillScores: dict[str, float] | None = Field(None, description="Per-skill quality scores")


class NandaTelemetry(BaseModel):
    enabled: bool = Field(default=True)
    latency_p50_ms: float | None = None
    latency_p99_ms: float | None = None
    throughput_rpm: float | None = Field(None, description="Requests per minute")
    error_rate_pct: float | None = Field(None, description="Error rate as percentage")
    uptime_90d_pct: float | None = Field(None, description="Uptime over 90 days as percentage")
    last_updated: datetime | None = None


# ─── AgentFacts (Top-Level) ──────────────────────────────────


class NandaAgentFacts(BaseModel):
    id: str = Field(..., description="Agent's DID (e.g., did:web:domain:agents:id)")
    handle: str | None = Field(None, description="@agent_id@domain handle for routing")
    agent_name: str = Field(..., description="Machine-readable agent identifier")
    label: str | None = Field(None, description="Human-readable display name")
    description: str = Field(..., description="Agent description")
    version: str = Field(..., description="Agent software version")
    provider: NandaProvider
    endpoints: NandaEndpoints = Field(default_factory=NandaEndpoints)
    capabilities: NandaCapabilities = Field(default_factory=NandaCapabilities)
    skills: list[NandaSkill] = Field(default_factory=list)
    certification: NandaCertification | None = None
    evaluations: NandaEvaluations | None = None
    telemetry: NandaTelemetry | None = None
    updated_at: datetime | None = Field(None, description="Last facts update timestamp")
    facts_version: int = Field(default=1, description="Monotonic version counter for change tracking")
