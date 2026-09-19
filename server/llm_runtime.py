"""One provider registry, one resolver, one place a provider string is normalised.

VENDORED BYTE-IDENTICALLY to agent/community_member/ and server/. Copy this file
whole; do not edit one side. server/tests/test_llm_runtime_vendoring.py pins the
two copies together, the same way retry_policy.py is pinned. That constraint is
why this module imports only the standard library and ``openai``: it must be
importable from both trees, and neither image contains the other. The server
image copies only server/, conformance/, schema/, vectors/ and infra/migrations/;
the agent builds with context: agent and also ships as a standalone
distributable. A repo-root shared package would be outside both.

WHAT THIS REPLACES, and why it is worth one file existing twice.

Five provider tables disagreed with each other, and six default-model
declarations disagreed with those. They also disagreed about string handling:
one call site stripped, another lowercased without stripping. Measured on the
agent's own table, with the resolution its server path performs:

    provider='ollama'         -> http://localhost:11434/v1/
    provider=' ollama '       -> https://api.openai.com/v1/   <-- OpenAI
    provider=''               -> https://api.openai.com/v1/   <-- OpenAI
    provider='typo-provider'  -> https://api.openai.com/v1/   <-- OpenAI

That last column is the defect. The call sites read

    base_url = base_urls.get(provider, "https://api.openai.com/v1")
    client = OpenAI(api_key=api_key or "local", base_url=base_url)

so an empty, misspelt, or merely space-padded provider silently resolves to
OpenAI's endpoint WHILE STILL CARRYING WHATEVER KEY WAS RESOLVED. A driven
measurement caught a live third-party key in an Authorization header addressed to
api.openai.com. This module makes that unrepresentable: an unknown provider
yields no entry, therefore no base_url, therefore no client. There is no default
argument to ``get`` anywhere in this file, and adding one would reintroduce the
whole defect.

REPORT-ONLY IN THIS UNIT. Nothing here gates anything. ``describe_resolution``
exists so a call site can log what this module WOULD resolve alongside what the
current path resolved, and the two can be compared in production before any
behaviour depends on this. No call site changes behaviour by importing it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_TIMEOUT_S",
    "LEGACY_PROVIDER_VALUES",
    "LOCAL_PROVIDERS",
    "MAX_OUTPUT_TOKENS_ENV",
    "DEFAULT_MAX_OUTPUT_TOKENS",
    "RETRIES_ENV",
    "TIMEOUT_ENV",
    "max_output_tokens",
    "max_retries",
    "timeout_s",
    "PROVIDERS",
    "TIERS",
    "TIER_FAST",
    "TIER_BALANCED",
    "TIER_DEEP",
    "TIER_REQUIRE_MEASURED_ENV",
    "TierChoice",
    "model_for_tier",
    "LLMNotConfigured",
    "LLMCallBudgetExceeded",
    "CALLS_PER_CYCLE_ENV",
    "DEFAULT_CALLS_PER_CYCLE",
    "CYCLE_BUDGET",
    "CallBudget",
    "BudgetedClient",
    "calls_per_cycle",
    "ProviderCaps",
    "Provider",
    "Resolution",
    "TerminalProviderError",
    "build_client",
    "describe_resolution",
    "egress_allowed",
    "normalise_provider",
    "resolve",
]

# The three tiers a caller can ask for. Names describe what the caller wants of
# the model, not what any provider calls its models.
# One logical call must not become three HTTP requests by default. The SDK ships
# max_retries=2 and timeout=600s, and every construction site this module
# replaces ran both — so a wedged provider could hold a think cycle for ten
# minutes and bill three attempts for it. Set explicitly here, once, and
# overridable per deployment rather than per call site.
RETRIES_ENV = "LLM_MAX_RETRIES"
TIMEOUT_ENV = "LLM_TIMEOUT_S"
DEFAULT_MAX_RETRIES = 1
DEFAULT_TIMEOUT_S = 60.0

# An omitted max_tokens is not "no opinion" — it is the provider's own default,
# which on a chat-completions endpoint is the model's full context. The agent
# chat stream omitted it inside a five-iteration tool loop, and the measured
# worst case was five calls and 11,469 input tokens that produced no assistant
# text at all. A ceiling turns that from unbounded into bounded.
#
# Generous on purpose: measured need is far below this, so the ceiling should
# never be what shapes an answer. It exists to stop a runaway, not to compress
# one. A request that sets its own max_tokens keeps it — this only fills a gap.
MAX_OUTPUT_TOKENS_ENV = "LLM_MAX_OUTPUT_TOKENS"
DEFAULT_MAX_OUTPUT_TOKENS = 1024


def max_retries() -> int:
    """How many times the SDK may retry one logical call. Default 1, not 2."""
    raw = (os.environ.get(RETRIES_ENV) or "").strip()
    if not raw:
        return DEFAULT_MAX_RETRIES
    try:
        return max(int(raw), 0)
    except ValueError:
        return DEFAULT_MAX_RETRIES


def max_output_tokens() -> int:
    """The ceiling injected when a request omits ``max_tokens``. Default 1024.

    Zero or a negative value disables injection, which is the escape hatch for
    a deployment that genuinely wants the provider default. Unset, empty and
    unparseable all read as the default rather than as "disabled": a typo must
    not silently remove a bound.
    """
    raw = (os.environ.get(MAX_OUTPUT_TOKENS_ENV) or "").strip()
    if not raw:
        return DEFAULT_MAX_OUTPUT_TOKENS
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_MAX_OUTPUT_TOKENS


def timeout_s() -> float:
    """Seconds before one request is abandoned. Default 60, not the SDK's 600."""
    raw = (os.environ.get(TIMEOUT_ENV) or "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_S
    return value if value > 0 else DEFAULT_TIMEOUT_S


TIER_FAST = "fast"
TIER_BALANCED = "balanced"
TIER_DEEP = "deep"
TIERS = (TIER_FAST, TIER_BALANCED, TIER_DEEP)

# Refuse to tier onto a model whose forced tool_choice was MEASURED to misbehave.
# ⚠️ THE DANGEROUS CASE IS THE PARTIAL ONE, AND IT IS MEASURED, NOT HYPOTHETICAL.
# The committed probe (docs/integrations/llm-compat-probe.json, five trials each)
# found four models and four behaviours: one honoured a forced tool_choice 5 of 5,
# one refused with HTTP 400 every time, one ignored it 5 of 5, and one honoured it
# 2 OF 5. The 400 is the GOOD failure — loud, immediate, unmistakable. The 2-of-5
# is the bad one: a site that works three times in five reads as bad luck rather
# than as a misconfiguration, and its failure shape is an empty plan, which is the
# production zero-output signature this whole track exists to remove.
#
# "ignored" therefore covers BOTH the 0-of-5 and the 2-of-5 model, and that is the
# correct classification: PARTIAL HONOURING IS NOT SUPPORT.
_TIER_BLOCKING_CAPS = ("ignored", "rejected")

# Require a POSITIVE measurement before tiering, rather than only the absence of a
# negative one. Off by default, and the reason is a measurement rather than taste:
# the probe ran against local ollama models, so NOT ONE model named in the tier
# table above has been measured — every one resolves "unknown". Turning this on
# today disables tiering for every provider, which is a legitimate posture (refuse
# to move a call onto anything unproven) but not a silent one. See the tiering
# section of docs/integrations/LLM_MODEL_PINS.md.
TIER_REQUIRE_MEASURED_ENV = "LLM_TIER_REQUIRE_MEASURED"


@dataclass(frozen=True)
class TierChoice:
    """Which model a tier resolved to, and whether the tier was honoured.

    ``refused_reason`` is empty when the tier was applied. When it is not, the
    caller is being told the tier was DECLINED and the balanced model used
    instead — never that the tier succeeded.
    """

    model: str
    tier: str
    requested_tier: str
    refused_reason: str = ""

    @property
    def tiered(self) -> bool:
        return not self.refused_reason


def _require_measured() -> bool:
    return os.environ.get(TIER_REQUIRE_MEASURED_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def model_for_tier(
    provider: str,
    tier: str,
    *,
    caps_lookup: Any = None,
) -> TierChoice:
    """The model a provider offers for ``tier``, unless measurement forbids it.

    ``caps_lookup`` is a callable taking a model name and returning something with
    a ``forced_tool_choice`` string; injected so this stays importable in both
    trees without either depending on the other's caps module.

    ⚠️ THE FALLBACK IS THE BALANCED MODEL, NOT AN ERROR. A refused tier must not
    take down a call site that would have worked perfectly well on the default —
    the tier is an optimisation, and the failure mode of an optimisation is that
    it does not happen.
    """
    # Normalised into a name first, then looked up UNDEFAULTED — the module's own
    # guard pins that call form, because the defect it was written for was a
    # provider lookup with a fallback that quietly routed strangers to OpenAI.
    name = normalise_provider(provider) or ""
    spec = PROVIDERS.get(name)
    if spec is None:
        raise LLMNotConfigured(f"unknown provider {provider!r}")
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}; expected one of {TIERS}")

    model = spec.models[tier]
    balanced = spec.models[TIER_BALANCED]
    if tier == TIER_BALANCED or model == balanced:
        # Nothing is being moved, so there is nothing to refuse.
        return TierChoice(model=model, tier=tier, requested_tier=tier)

    status = "unknown"
    if caps_lookup is not None:
        measured = caps_lookup(model)
        status = getattr(measured, "forced_tool_choice", "unknown") or "unknown"

    if status in _TIER_BLOCKING_CAPS:
        return TierChoice(
            model=balanced,
            tier=TIER_BALANCED,
            requested_tier=tier,
            refused_reason=(
                f"{model!r} measured forced_tool_choice={status!r}; partial or absent honouring is "
                f"not support, so this call stays on {balanced!r}"
            ),
        )
    if status != "supported" and _require_measured():
        return TierChoice(
            model=balanced,
            tier=TIER_BALANCED,
            requested_tier=tier,
            refused_reason=(
                f"{model!r} has no forced_tool_choice measurement and {TIER_REQUIRE_MEASURED_ENV} "
                f"is set, so this call stays on {balanced!r}"
            ),
        )
    return TierChoice(model=model, tier=tier, requested_tier=tier)


# How many LLM calls one think cycle may make before the factory refuses.
#
# ⚠️ THIS IS A LATENCY AND RATE-LIMIT BOUND, NOT A SPEND SAVING, AND THE
# MEASUREMENT IS WHY. ``think_approvals_sweep`` makes two calls per approved row
# and was measured making 40 SEQUENTIAL calls in one cycle at its own row limit of
# 20 — against 9 calls for the entire rest of the rotation. All 40 cost 1,897
# tokens in total. The intuition said "that is the expensive one"; the
# measurement said otherwise and the measurement wins. What forty sequential
# round-trips actually costs is wall-clock inside one cycle andheadroom against a
# provider's rate limit, so that is what this bounds and that is all it claims.
#
# The default sits above measured normal (~49 calls in the worst observed cycle)
# and below a runaway, so an ordinary cycle never meets it.
CALLS_PER_CYCLE_ENV = "LLM_MAX_CALLS_PER_CYCLE"
DEFAULT_CALLS_PER_CYCLE = 60


class LLMCallBudgetExceeded(Exception):
    """This cycle has made as many LLM calls as it is allowed to.

    ⚠️ RAISED, NOT SWALLOWED, AND THAT IS THE POINT. A cap that silently returned
    nothing would truncate whatever the caller was working through — somebody's
    approved introductions, in the case this was measured on — and truncation is
    indistinguishable from "there was nothing to do". A caller catches this,
    records what it did not reach, and leaves that work for the next cycle.
    """


class LLMNotConfigured(Exception):
    """No usable provider: unknown name, or a remote provider with no key.

    Distinct from TerminalProviderError because it is recoverable by
    configuration — the caller has not been told a request failed, only that it
    cannot be attempted.
    """


class TerminalProviderError(Exception):
    """The provider answered in a way that retrying cannot fix.

    Raised by callers, not by this module. It exists here so both trees name the
    same exception for the same condition rather than each inventing one, which
    is how the tables diverged in the first place.
    """


@dataclass(frozen=True)
class ProviderCaps:
    """What a provider's OpenAI-compatible surface actually accepts.

    EVERY FIELD IS None, MEANING UNKNOWN, AND THAT IS DELIBERATE. These four
    differ per provider and the differences are not documented consistently
    anywhere; guessing them here would produce a table that looks authoritative
    and is not, which is the failure this module exists to end. They are measured
    by a separate probe against each live endpoint and filled in from that
    measurement. Until then a caller must treat None as "do not assume" rather
    than as "not supported".
    """

    # Whether tool_choice must be forced rather than left to the model.
    forced_tool_choice: bool | None = None
    # Whether response_format={"type": "json_object"} is honoured.
    json_object_response_format: bool | None = None
    # Whether stream_options={"include_usage": True} is accepted.
    stream_options_include_usage: bool | None = None
    # Whether per-block cache_control is honoured.
    cache_control: bool | None = None


@dataclass(frozen=True)
class Provider:
    """One provider, and everything needed to reach it."""

    name: str
    base_url: str
    # The environment variable holding this provider's key. Empty for a local
    # provider, which has no key to hold.
    key_env: str
    is_local: bool
    # Default model per tier. Every provider declares all three so a caller can
    # ask for a tier without knowing which provider it will get.
    models: dict[str, str]
    caps: ProviderCaps = field(default_factory=ProviderCaps)


# THE UNION OF BOTH TREES' TABLES. Seven providers: the agent declared all seven
# in two places, the server declared five in one. Where the two disagreed, the
# disagreement is recorded next to the value rather than silently resolved.
PROVIDERS: dict[str, Provider] = {
    "anthropic": Provider(
        name="anthropic",
        # The server declared this with a trailing slash and the agent without
        # one. Normalised to no trailing slash, matching every other entry here
        # and both of the agent's tables.
        base_url="https://api.anthropic.com/v1",
        key_env="ANTHROPIC_API_KEY",
        is_local=False,
        # Ids checked against the current published model list rather than
        # recalled. The balanced value is what server/llm_config.py already
        # declares; changing which model this repo defaults to is a decision in
        # its own right and is NOT part of this unit, which changes no behaviour.
        models={
            TIER_FAST: "claude-haiku-4-5",
            TIER_BALANCED: "claude-sonnet-4-6",
            TIER_DEEP: "claude-opus-5",
        },
    ),
    "openai": Provider(
        name="openai",
        base_url="https://api.openai.com/v1",
        key_env="OPENAI_API_KEY",
        is_local=False,
        models={
            TIER_FAST: "gpt-4o-mini",
            TIER_BALANCED: "gpt-4o-mini",
            TIER_DEEP: "gpt-4o",
        },
    ),
    "xai": Provider(
        name="xai",
        base_url="https://api.x.ai/v1",
        key_env="XAI_API_KEY",
        is_local=False,
        models={
            TIER_FAST: "grok-3-mini",
            TIER_BALANCED: "grok-3-mini",
            TIER_DEEP: "grok-3",
        },
    ),
    "groq": Provider(
        name="groq",
        base_url="https://api.groq.com/openai/v1",
        key_env="GROQ_API_KEY",
        is_local=False,
        models={
            TIER_FAST: "llama-3.1-8b-instant",
            TIER_BALANCED: "llama-3.3-70b-versatile",
            TIER_DEEP: "llama-3.3-70b-versatile",
        },
    ),
    "ollama": Provider(
        name="ollama",
        base_url="http://localhost:11434/v1",
        # The server named an OLLAMA_API_KEY. A local provider has no key to
        # hold, and treating it as though it did is how a local request ends up
        # carrying a credential. Left empty on purpose.
        key_env="",
        is_local=True,
        # The server declared llama3.1 and the agent llama3.2 for the same
        # provider. Taking the agent's, which both of its tables agree on.
        models={
            TIER_FAST: "llama3.2",
            TIER_BALANCED: "llama3.2",
            TIER_DEEP: "llama3.2",
        },
    ),
    "llama_cpp": Provider(
        name="llama_cpp",
        base_url="http://localhost:8080/v1",
        key_env="",
        is_local=True,
        models={
            TIER_FAST: "local-model",
            TIER_BALANCED: "local-model",
            TIER_DEEP: "local-model",
        },
    ),
    "mlx_lm": Provider(
        name="mlx_lm",
        base_url="http://localhost:8081/v1",
        key_env="",
        is_local=True,
        models={
            TIER_FAST: "local-model",
            TIER_BALANCED: "local-model",
            TIER_DEEP: "local-model",
        },
    ),
}

LOCAL_PROVIDERS = frozenset(name for name, p in PROVIDERS.items() if p.is_local)

#: Provider names the DATABASE accepts that this registry does not resolve.
#:
#: ``agents.llm_provider`` predates the registry and its CHECK constraint still
#: admits ``'custom'``. ``resolve('custom')`` raises ``LLMNotConfigured``, so a
#: member recorded that way cannot start — the value is accepted at rest and
#: refused at run time. It stays in the constraint because dropping it would
#: make any UPDATE to such a row fail too, turning a member who cannot run into
#: a row nobody can repair.
#:
#: Declared here so the registry-vs-constraint guard
#: (``tests/test_provider_vocabularies.py``) can subtract a KNOWN gap rather
#: than hand-copying either side. Anything else the constraint admits and the
#: registry does not know is drift, and that test fails on it.
LEGACY_PROVIDER_VALUES = frozenset({"custom"})


@dataclass(frozen=True)
class Resolution:
    """Everything a caller needs to reach a provider, and nothing more.

    Carries no key. ``key_env`` names the variable; reading it is
    ``build_client``'s job and happens once, so a resolution can be logged
    without logging a credential.
    """

    provider: Provider
    tier: str
    model: str

    @property
    def base_url(self) -> str:
        return self.provider.base_url

    @property
    def is_local(self) -> bool:
        return self.provider.is_local


def normalise_provider(raw: str | None) -> str:
    """The ONLY place a provider string is normalised.

    ``.strip().lower()``, exactly once. The call sites this replaces disagreed:
    one stripped, another lowercased without stripping, so ``' ollama '``
    resolved to OpenAI on one path and to Ollama on the other. Normalising in one
    function means the two cannot disagree again.
    """
    return (raw or "").strip().lower()


def resolve(provider: str | None, *, tier: str = TIER_BALANCED, model: str | None = None) -> Resolution:
    """The provider a name refers to, or LLMNotConfigured.

    NO FALLBACK. An unknown name is not resolved to anything — there is no
    default provider and no default base_url in this module. A caller that wants
    a default has to say which, in its own code, where the choice is visible.
    """
    name = normalise_provider(provider)
    if not name:
        raise LLMNotConfigured(
            "no provider was named. Set one explicitly — this resolver has no default, "
            "because a default is how an unset provider became a request to OpenAI."
        )
    entry = PROVIDERS.get(name)
    if entry is None:
        raise LLMNotConfigured(
            f"{name!r} is not a known provider. Known: {', '.join(sorted(PROVIDERS))}. "
            f"Refusing to guess: an unrecognised provider used to resolve to OpenAI's "
            f"endpoint while still carrying the resolved key."
        )
    if tier not in TIERS:
        raise LLMNotConfigured(f"{tier!r} is not a known tier. Known: {', '.join(TIERS)}.")
    return Resolution(provider=entry, tier=tier, model=(model or "").strip() or entry.models[tier])


def egress_allowed(resolution: Resolution) -> bool:
    """Whether reaching this provider leaves the machine.

    A local provider is reachable with no credential and no egress. Callers that
    must not make outbound calls check this rather than pattern-matching a URL.
    """
    return not resolution.is_local


class CallBudget:
    """Counts LLM calls within one cycle and refuses past the limit."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def reset(self, limit: int | None = None) -> None:
        self.used = 0
        if limit is not None:
            self.limit = limit

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def spend(self) -> None:
        if self.used >= self.limit:
            raise LLMCallBudgetExceeded(
                f"this cycle has made {self.used} LLM calls, its limit ({CALLS_PER_CYCLE_ENV}={self.limit}). "
                f"Remaining work is not lost — it is left for the next cycle."
            )
        self.used += 1


def calls_per_cycle() -> int:
    raw = os.environ.get(CALLS_PER_CYCLE_ENV, "").strip()
    if not raw:
        return DEFAULT_CALLS_PER_CYCLE
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_CALLS_PER_CYCLE
    return value if value > 0 else DEFAULT_CALLS_PER_CYCLE


# One budget per process, reset at the top of each cycle by the caller that owns
# the cycle. Module-level because the factory hands out many clients and the
# bound is on the CYCLE, not on any one of them.
CYCLE_BUDGET = CallBudget(calls_per_cycle())


class _BudgetedCompletions:
    """``client.chat.completions`` with the per-cycle budget in front of create."""

    def __init__(self, inner: Any, budget: CallBudget) -> None:
        self._inner = inner
        self._budget = budget

    def create(self, *args: Any, **kwargs: Any) -> Any:
        self._budget.spend()
        return self._inner.create(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _BudgetedChat:
    def __init__(self, inner: Any, budget: CallBudget) -> None:
        self._inner = inner
        self.completions = _BudgetedCompletions(inner.completions, budget)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class BudgetedClient:
    """An OpenAI-shaped client that counts its calls against the cycle budget.

    ⚠️ THE CAP LIVES IN THE FACTORY SO IT BOUNDS EVERY CALLER. Putting it in the
    one call site measured making forty calls would bound that site and nothing
    else, and the next caller to loop over rows would rediscover the same hazard.
    Everything not ``chat.completions.create`` is delegated untouched.
    """

    def __init__(self, inner: Any, budget: CallBudget) -> None:
        self._inner = inner
        self.chat = _BudgetedChat(inner.chat, budget)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


# A caller SUBSTITUTED one of these for a key it did not have. "MISSING" is the
# exact string the chapter's own config used, so it travelled in an Authorization
# header to a real provider; "local" is what a local endpoint ignores and must
# never reach a remote one; "no-key-configured" is member_runtime's. The empty
# string is NOT here — an absent key raises unconditionally, above.
_PLACEHOLDER_KEYS = frozenset({"missing", "local", "none", "null", "unset", "no-key-configured"})


def _is_placeholder(key: str) -> bool:
    return (key or "").strip().lower() in _PLACEHOLDER_KEYS


def _report_would_refuse(resolution: Resolution, message: str) -> None:
    """Say what strict mode would have done, without doing it.

    Logged rather than raised, and logged WITHOUT the key: this runs on the path
    that is about to send a request, and a diagnostic that printed the credential
    would put it wherever the surrounding logs go.
    """
    import logging

    logging.getLogger("llm_runtime").warning(
        "LLM_STRICT is off: building a client for %s anyway. Under LLM_STRICT this would refuse — %s",
        resolution.base_url,
        message,
    )


def build_client(resolution: Resolution, *, api_key: str | None = None, strict: bool = False) -> Any:
    """An OpenAI-compatible client pointed at the resolved provider.

    The key is read from the resolution's OWN ``key_env`` and from nowhere else.
    The call sites this replaces fell back through several variables in order —
    ``config.api_key or OPENAI_API_KEY or XAI_API_KEY`` — so the key that
    travelled was whichever happened to be set, not the one belonging to the
    provider being addressed. Combined with the endpoint fallback, that is how a
    third-party key reached OpenAI.

    A remote provider with no key raises rather than sending ``"local"`` as a
    placeholder, which is what made an unauthenticated request look like a
    configured one.
    """
    if resolution.is_local:
        # A local endpoint requires a key by the OpenAI client's signature and
        # ignores its value. The placeholder never leaves the machine.
        #
        # A DELIBERATE LOCAL ENDPOINT IS NOT A MISCONFIGURATION. A chapter
        # pointed at an unkeyed local model is correctly configured, and strict
        # mode must never gate it off — locality is read off the configured URL
        # rather than resolved through DNS, because the question is what the
        # operator configured and a name that resolves to loopback today is not
        # a promise about tomorrow.
        key = "local"
    else:
        key = (api_key or "").strip() or os.environ.get(resolution.provider.key_env, "").strip()
        if not key:
            # NO KEY AT ALL. This has raised since the resolver landed and is not
            # governed by LLM_STRICT — that flag widens the refusal, it does not
            # introduce it, and making it conditional here would LOOSEN a
            # guarantee that already shipped. Caught by the resolver's own tests
            # when this was first written the other way round.
            raise LLMNotConfigured(
                f"provider {resolution.provider.name!r} needs a key in "
                f"${resolution.provider.key_env}, which is unset. Refusing to send a "
                f"placeholder key to a remote endpoint."
            )
        if _is_placeholder(key):
            # NO USABLE CREDENTIAL FOR A REMOTE ENDPOINT.
            #
            # A keyless process built a client anyway and posted member names,
            # skill lists and federation peer names to a provider under
            # ``Authorization: Bearer MISSING`` — 18 requests over 24 driven
            # ticks — while the configuration documentation promised it "makes
            # no request, so there is nothing for a firewall or an egress policy
            # to block".
            #
            # Gating HERE rather than at the call sites is the point: twenty-four
            # sites use the client and four ask whether they may. There is no
            # client to call when this raises, so there is nothing to bypass.
            message = (
                f"provider {resolution.provider.name!r} was given the placeholder {key!r} "
                f"instead of a credential; set ${resolution.provider.key_env}. "
                f"Refusing to build a client for {resolution.base_url} — a request "
                f"would carry the prompt to a provider the operator did not configure."
            )
            if strict:
                raise LLMNotConfigured(message)
            # REPORT-ONLY. Ships at strict=False for one release so the diff
            # between what this would refuse and what the current path does can
            # be read off deployed servers before behaviour changes everywhere at
            # once. The placeholder below is exactly today's behaviour.
            _report_would_refuse(resolution, message)

    from openai import OpenAI

    # THE ONLY SANCTIONED OpenAI() CONSTRUCTION. An AST guard forbids the call
    # anywhere else, so the retry cap, the timeout, the resolved endpoint and the
    # provider-owned key are properties of the object every caller receives
    # rather than thirteen things a future change can forget one of.
    client = OpenAI(
        api_key=key,
        base_url=resolution.base_url,
        max_retries=max_retries(),
        timeout=timeout_s(),
    )
    # ⚠️ TWO WRAPPERS ON ONE SEAM, AND BOTH APPLY. The output ceiling and the
    # per-cycle call budget both sit on ``chat.completions.create`` and arrived in
    # separate units, so this is the one line where they could silently have
    # replaced each other rather than composed.
    #
    # The ORDER is deliberate. The budget is outermost, so a refused call is
    # refused before any other work happens; the ceiling is innermost, because it
    # MUTATES the request and belongs closest to the SDK that receives it. Either
    # order refuses the same calls — nothing reaches the provider either way —
    # but this one does the least before saying no.
    return _with_call_budget(_with_output_ceiling(client))


class _CeilingCompletions:
    """Fills in ``max_tokens`` when a caller omitted it, and nothing else.

    The ceiling belongs here for the same reason the retry cap and the timeout
    do: it is a property every caller should receive rather than a line each
    call site can forget. The agent chat stream is exactly that forgotten line —
    it omits ``max_tokens`` inside a five-iteration tool loop.

    A caller that PASSES ``max_tokens`` keeps its own value, including a larger
    one. This raises no ceiling and lowers none; it only refuses to leave the
    field unset.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def create(self, **kwargs: Any) -> Any:
        if kwargs.get("max_tokens") is None:
            ceiling = max_output_tokens()
            if ceiling > 0:
                kwargs["max_tokens"] = ceiling
        return self._inner.create(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _CeilingChat:
    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.completions = _CeilingCompletions(inner.completions)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _CeilingClient:
    """The resolved client, with ``chat.completions.create`` wrapped.

    Everything else is passed through by ``__getattr__``, so a caller reaching
    for ``models``, ``embeddings`` or any future surface gets the real object.
    Wrapping the whole client rather than patching one method keeps the
    behaviour inspectable: ``isinstance`` checks fail loudly instead of a
    monkeypatched attribute silently disappearing on a client rebuild.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.chat = _CeilingChat(inner.chat)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _with_call_budget(client: Any) -> Any:
    """Wrap a client so every completion is counted against the cycle budget.

    Guarded the same way as the ceiling below, and for the same reason: a client
    shape without ``.chat.completions`` is not one this wrapper understands, and a
    wrapper that raises here would take down every caller. Losing the bound on an
    unrecognised shape is the lesser failure, and it is loud in the sense that
    such a client cannot be one this tree builds.
    """
    try:
        return BudgetedClient(client, CYCLE_BUDGET)
    except AttributeError:
        return client


def _with_output_ceiling(client: Any) -> Any:
    """Wrap a client so an omitted ``max_tokens`` is filled from the ceiling."""
    try:
        return _CeilingClient(client)
    except AttributeError:
        # A client shape without .chat.completions is not one this wrapper
        # understands. Returning it unwrapped loses the ceiling, which is worse
        # than the alternative only if the alternative works — and a wrapper
        # that raises here would take down every caller.
        return client


def describe_resolution(provider: str | None, *, tier: str = TIER_BALANCED, model: str | None = None) -> dict[str, Any]:
    """What this module WOULD resolve, as a loggable record. Never raises.

    This is the whole of the module's use in this unit: a call site logs this
    beside what its current path resolved, and the two are compared in production
    before anything depends on the answer. Nothing is gated on it.

    Carries no key and no key value — only the NAME of the variable a key would
    be read from, so the record is safe to log wherever the surrounding code logs.
    """
    record: dict[str, Any] = {"input_provider": provider, "normalised": normalise_provider(provider), "tier": tier}
    try:
        resolution = resolve(provider, tier=tier, model=model)
    except LLMNotConfigured as exc:
        record["resolved"] = False
        record["reason"] = str(exc)
        # Said explicitly, because it is the difference this module exists for:
        # the path being replaced would have produced an OpenAI base_url here.
        record["would_have_fallen_back"] = True
        return record
    record["resolved"] = True
    record["provider"] = resolution.provider.name
    record["base_url"] = resolution.base_url
    record["model"] = resolution.model
    record["is_local"] = resolution.is_local
    record["egress"] = egress_allowed(resolution)
    record["key_env"] = resolution.provider.key_env or None
    record["key_present"] = (
        bool(os.environ.get(resolution.provider.key_env, "").strip()) if resolution.provider.key_env else None
    )
    return record
