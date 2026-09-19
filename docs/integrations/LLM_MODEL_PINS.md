# Claude model pins — state, hazards, and the unrun probe

Working notes for the model-pin guard. Read this before changing any `claude-*` string.
Verified against Anthropic's published model and deprecation pages on
**2026-08-01**; the probe section records what is *measured* versus what is
merely *documented*, because for this codebase those are not the same thing.

## Every Claude pin in the tree

| # | Site | Pinned | Vendor status (2026-08-01) |
|---|---|---|---|
| 1 | `agent/community_member/settings_sync.py:53` | `claude-opus-4-7` | Active (retires no sooner than 2027-04-16) |
| 2 | `server/settings.py:55` | `claude-opus-4-7` | Active |
| 3 | `server/llm_config.py:31` | `claude-sonnet-4-6` | Active (retires no sooner than 2027-02-17) |
| 4 | `agent/community_member/wizard.py` (`PROVIDERS`) | ~~dated Sonnet 4 snapshot~~ → `claude-sonnet-4-6` | **was RETIRED 2026-06-15** — fixed here |
| 5 | `agent/community_member/server.py` (`_PROVIDER_CATALOGUE`) | ~~dated Sonnet 4 snapshot~~ → `claude-sonnet-4-6` | **was RETIRED 2026-06-15** — fixed here |

Issue that change inventoried sites 1–3. **Sites 4 and 5 were not in the issue** and
were the only ones actually broken: Anthropic retired the dated Claude Sonnet 4
snapshot on 2026-06-15, and *"requests to retired models will fail"*. Site 4 is
the onboarding wizard's provider catalogue — the model a new user gets the
moment they pick "Anthropic (Claude)". Both are fixed in this change and are now
held by `agent/tests/test_model_pins.py`.

Sites 1–3 are **not** changed here. See *The decision*, below.

## The two hazards, and which pin they actually attach to

Both are real, but they attach to *different* pins, and conflating them leads to
the wrong fix.

### Hazard A — non-default `temperature` returns 400 on Claude 4.7 and later

Anthropic's parameter-deprecation table is explicit: `temperature`, `top_p`, and
`top_k` *"return a 400 error when set to a **non-default** value on Claude 4.7
and later models."* Non-default is the trigger — not the mere presence of the
parameter.

Call sites that set one:

| Site | Value | Model it actually uses |
|---|---|---|
| `server/chronicle.py:251` | `0.5` | `llm_config.DEFAULT_MODEL` → `claude-sonnet-4-6` |
| `server/digest.py:215` | `0.4` | `llm_config.DEFAULT_MODEL` → `claude-sonnet-4-6` |
| `agent/community_member/llm_client.py:27` | `0.3` (default arg, every caller) | the user's configured model — **`claude-opus-4-7` by default** |

This is why nothing is visibly broken today: the two server call sites resolve to
Sonnet 4.6, which is *pre*-4.7, so the rule does not apply to them. **The agent
path is different** — sites 1–2 default the user's configured model to
`claude-opus-4-7`, which *is* "4.7 and later", and `llm_client.py` passes
`temperature=0.3` on every call. That path is already inside the documented 400
zone on the native API today, before any bump.

Whether it 400s **through the OpenAI-compat shim** is the open question. Hazard A
is therefore *not introduced by bumping* — bumping `llm_config.py` to a `-5`
model would merely extend an exposure the agent path already has.

### Hazard B — `max_tokens` caps thinking *and* response together

On `claude-opus-5` and `claude-sonnet-5`, adaptive thinking is **on by default**
(omitting the field runs it); on `claude-opus-4-7` and `claude-sonnet-4-6`,
omitting it means no thinking. And `max_tokens` is a hard cap on thinking *plus*
response text.

`server/think_cycle.py` budgets, at its tightest:

| Line | Budget | What it asks for | What happens if truncated |
|---|---|---|---|
| 461, 478 | 50 | "Introduce yourself in one sentence" | `content or ""` → an **empty string is appended to the conversation as a real utterance** |
| 606 | 60 | "Suggest ONE discussion topic" | falls back to a generic string, silently |
| 625, 637, 649 | 60 | "One sentence only" | same empty-string-as-utterance path |
| 1188 | 80 | **JSON** `{"new_skill", "personality_addition"}` | regex finds no `{...}` → bare `return`; the evolution silently never happens |
| 545, 946, 1053, 802, 251 | 100–400 | assorted | proportionally less exposed |

Also outside `think_cycle.py`: `server/chapter_agent.py:899` and `:4124` (50),
`server/member_runtime.py:214` (100).

**None of these raise.** Every one swallows a short or empty result. This is the
failure mode the issue flagged as the nasty one, and it is worse than "a short,
plausible answer" — at 50 tokens with thinking enabled the likely outcome is *no
answer at all*, recorded as if it were one.

Hazard B **is** introduced by bumping, and only by bumping to a `-5` model.

> The compat shim has no `thinking` field — the OpenAI `chat.completions` shape
> has nowhere to put it. So if the endpoint enables thinking by default for `-5`
> models, there may be **no provider-agnostic way to turn it off**, and the only
> remedy is raising every tight budget. Whether `extra_body={"thinking": ...}`
> passes through is one of the probe's questions. This is reported, not worked
> around: adding Anthropic-specific branching to the call sites would break the
> provider-agnostic contract the shim exists to uphold.

## The probe — method, and why it has not run

The endpoint under test is the OpenAI-compatible one the org actually uses:
`https://api.anthropic.com/v1/` via `from openai import OpenAI`. Every published
statement above describes the **native Messages API**. Nothing documents whether
the compat endpoint enforces the same rules — it could reject, silently strip,
or honour these parameters, and the three outcomes imply three different fixes.

`scripts/probe_llm_compat.py` answers it. Per model (`claude-sonnet-4-6`,
`claude-opus-4-7`, `claude-sonnet-5`, `claude-opus-5`) it runs four cases:
a no-params baseline; `temperature=0.5` (non-default); `temperature=1.0` (the
documented default — this separates a *value*-based rule from a
*parameter*-based one, which decides whether a call site may pass the parameter
at all); and a 50-token budget mirroring `think_cycle.py`, recording
`finish_reason`, returned text length, and any `reasoning_tokens`.

```sh
export ANTHROPIC_API_KEY=sk-ant-...      # environment only, never argv
scripts/probe_llm_compat.py --out docs/integrations/llm-compat-probe.json
```

**STATUS: ATTEMPTED 2026-08-03, STILL UNANSWERED — no working credential.**

Re-checked on 2026-08-03 after a report that a key had been added to the
environment. What is actually present:

| Variable | State |
|---|---|
| `ANTHROPIC_API_KEY` | unset |
| `LLM_API_KEY` | unset |
| `OPENAI_API_KEY` | unset |
| `GROQ_API_KEY` | unset |
| `ANTHROPIC_AUTH_TOKEN` | unset |
| `XAI_API_KEY` | **set** (`xai-…`, 84 chars) — **but rejected by xAI** |

Two independent reasons the probe still cannot answer its question:

1. **The only key present is for the wrong provider.** The question is whether
   *Anthropic's* OpenAI-compat endpoint rejects a non-default `temperature` on
   `claude-*-5`. An xAI key cannot answer that — different provider, different
   parameter rules. It was **not** sent to `api.anthropic.com`: that would
   transmit a live xAI credential to a third party, which is a worse outcome
   than an unanswered question.
2. **The key does not work at all.** Pointed at xAI's own endpoint, where it
   belongs, every request returns
   `400 invalid-argument: "Incorrect API key provided"`, and
   `GET https://api.x.ai/v1/models` returns an empty list. It is not a
   wrong-provider key that might be repurposed; it is a dead credential.

So `temperature` behaviour on the compat endpoint remains **unmeasured**, and
the bump remains blocked. No credential path was improvised.

### What the attempt did establish

The probe harness itself is exercised and correct, which de-risks the run for
whoever has a live key. Against a real endpoint it authenticated, issued all
four cases, captured the provider's own error verbatim, marked the baseline
`ok: false`, and — by design — reported the remaining verdicts as `unknown`
rather than inferring anything from cases whose baseline had failed. That last
behaviour is the one that matters: a harness that reported a confident verdict
off a broken baseline would be worse than no harness.

Run it, unchanged, the moment an Anthropic key exists:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
scripts/probe_llm_compat.py --out docs/integrations/llm-compat-probe.json
```

Two things *were* established without a credential, so the next person does not
repeat them:

1. **The compat endpoint exists and is reachable.** `POST /v1/chat/completions`
   against `api.anthropic.com` returns `401 authentication_error`, not `404` —
   so `llm_config.py`'s `base_url` and path are correct.
2. **Auth is validated before parameters, so no credential-free probe is
   possible.** Identical requests with and without `temperature` both return the
   same 401. Parameter validation is never reached. This closes off the
   otherwise-tempting "probe it with an invalid key" shortcut.

## Pre-bump checklist — the `max_tokens` budgets, named not raised

Every budget below shares its allowance with adaptive thinking the moment a pin
moves to a `-5` model, and every one of them **swallows a short result** rather
than raising. They are named here rather than raised because raising them is
part of the bump, not independent of it: on the current pins (`claude-opus-4-7`,
`claude-sonnet-4-6`) thinking is off unless asked for, so a raise today buys
nothing and costs tokens on every call. Raise them **in the same change that
moves the pins**, not before.

| File:line | Budget | What breaks, silently |
|---|---:|---|
| `think_cycle.py:461,478` | 50 | `content or ""` → an empty string is appended to a conversation as a real utterance |
| `think_cycle.py:606` | 60 | falls back to a generic topic string |
| `think_cycle.py:625,637,649` | 60 | same empty-utterance path |
| `think_cycle.py:1188` | 80 | asks for JSON; regex finds no `{...}` → bare `return`, evolution never happens |
| `think_cycle.py:545,946` | 100,150 | proportionally less exposed |
| `chapter_agent.py:899,4124` | 50 | outside the file the issue named |
| `member_runtime.py:214` | 100 | outside the file the issue named |

Sonnet 5 additionally uses a new tokenizer (~30% more tokens for the same text
than Sonnet 4.6), so these budgets buy less output even before thinking takes
its share. Opus 4.7 → Opus 5 is tokenizer-neutral.

## The decision

**Unchanged after the 2026-08-03 probe attempt: Sonnet as the single product
default, and sites 1–3 stay where they are until the probe actually runs.**

The probe was attempted and could not run (no working credential — see above),
so the hazard it exists to measure is still unmeasured. Bumping now would take
silent truncation across the twelve call sites above on trust. Holding is the
issue's own stated-reason branch, not an omission.

Rationale:

- **The split is accidental, not reasoned.** Sites 1–2 mirror each other by
  explicit comment (*"Mirrors the org server runtime settings.py DEFAULTS
  exactly"*) and say Opus; site 3 independently says Sonnet. Nothing in the code
  or history ties the split to a cost-on-server / capability-on-agent argument.
  Consolidating on one model is right regardless of which generation wins.
- **Sonnet over Opus** because the tight-budget call sites dominate this
  workload — dozens of one-sentence generations per think cycle — and Sonnet is
  the documented default for "the best combination of speed and intelligence" at
  40% of Opus's output price. Nothing in the LLM call sites needs Opus-tier
  reasoning.
- **Not bumped to `-5` yet** because the done-when requires the pins be bumped
  *with the hazards verified*, and the probe that verifies them cannot run here.
  A `-5` bump today would take Hazard B (silent truncation across ~12 call sites)
  on trust. The issue explicitly permits staying with a stated reason; this is
  that reason.

**What unblocks the bump:** run the probe with a key. If it shows the compat
endpoint tolerates non-default `temperature` and does not enable thinking by
default, sites 1–3 go to `claude-sonnet-5` in one change with no call-site edits.
If it shows thinking is on by default, the bump additionally requires raising
every budget in the Hazard B table — a larger change that should be its own unit.

## Tiering — which calls may move, and what forbids it

Call sites name a **tier** (`fast` / `balanced` / `deep`) rather than reading one
module-global default. `llm_runtime.PROVIDERS[provider].models[tier]` already held
that mapping; tiering uses it rather than adding a second table, because a second
table is how five provider tables came to disagree about base URLs.

**What moves.** Measured on a driven 720-tick day, 360 of 486 daily org calls
(74%) cap output at 100 tokens or fewer: `think_conversation` 240 at 60,
`think_insight` 60 at 100, `think_evolve` 60 at 80. Those six call sites name the
fast tier. Same volume costs 47.74/mo/org on a sonnet-class model and 15.91 on a
haiku-class one.

**What does not, and it is a measurement rather than a preference.** Sites that
force `tool_choice` stay deep — `planner_llm` and `surface_composer.compose`. The
committed probe found four models and four behaviours on a forced `tool_choice`,
five trials each:

| model | verdict | honoured |
| --- | --- | :---: |
| `llama3.1:8b` | supported | 5 of 5 |
| `phi3:mini` | rejected — HTTP 400 | 0 of 5 |
| `qwen2.5-coder:14b` | ignored | 0 of 5 |
| `qwen2.5:14b` | ignored | **2 of 5** |

The HTTP 400 is the **good** failure: loud, immediate, unmistakable. The 2-of-5 is
the dangerous one — a site that works three times in five reads as bad luck rather
than as a misconfiguration, and its failure shape is an empty plan, which is the
production zero-output signature this track exists to remove. So `ignored` covers
both the 0-of-5 and the 2-of-5 model, and that is the right classification:
**partial honouring is not support.**

`json_object_response_format` was honoured **5 of 5 on all four models** — the one
universally reliable capability measured, and the planner's fallback.

**The refusal.** `llm_runtime.model_for_tier` declines to move a call onto a model
whose `forced_tool_choice` was measured `ignored` or `rejected`, falling back to
the balanced model and saying why. A refused tier is not an error: the tier is an
optimisation, and the failure mode of an optimisation is that it does not happen.

**⚠️ The stricter posture, and why it is off by default.** Requiring a *positive*
measurement before moving any call — `LLM_TIER_REQUIRE_MEASURED=true` — is
available. It is off because the probe ran against local ollama models and **not
one model named in the tier table has been measured**; every one resolves
`unknown`. Turning it on today disables tiering for every provider, which is a
legitimate posture but not a silent one. `test_no_registry_fast_model_is_measured_yet`
asserts that state, so the day a tier model *is* measured, that test fails and the
failure is the prompt to reconsider the default.

An operator's explicit `LLM_MODEL` still wins over every tier: they pinned a
model, and a tier is this code's opinion about cost, not theirs about capability.

## Keeping this from rotting again

`agent/tests/test_model_pins.py` fails the suite if any **retired** model id
appears in shipped source, prints a note for deprecated-but-live ones, asserts
the onboarding wizard offers a live model, and asserts the two provider
catalogues agree. It is offline and needs no key. Refresh its
`RETIRED_MODEL_IDS` from Anthropic's [model
deprecations](https://platform.claude.com/docs/en/about-claude/model-deprecations)
page whenever pins are reviewed.
