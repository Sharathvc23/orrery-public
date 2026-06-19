---
name: doc-tone
description: Tone and style rules for all prose in this repo — README, docs/*.md, code comments, commit/PR copy, repo descriptions. Invoke BEFORE writing or editing any human-facing prose here, and use it to review prose you just wrote. Goal: measured, technical writing by an engineer for engineers, not marketing copy.
---

# Documentation tone

Write like an engineer explaining the system to a peer. Not like a landing page.
The reader is technical, skeptical, and short on time. Earn their trust with
precise, verifiable statements — not enthusiasm.

## The core test

Before shipping any sentence, ask: **"Would this appear in a product ad?"** If yes,
rewrite it as a plain statement of fact. The most common offender is the rule of
three — stacking short imperative fragments for rhythm:

> ❌ Run an org of accountable AI agents. Install in one command. Make the UI your own.

That is a slogan, not a description. Replace it with one complete sentence that says
what the thing actually is:

> ✅ A self-hostable platform for running AI agents that produce a verifiable,
> signed record of everything they do.

## Rules

1. **Complete sentences, connected prose.** Don't use sentence fragments as
   punchlines. A period is not a drum beat.
2. **Describe, don't sell.** State what the software *does* and let the capability
   stand on its own. Cut adjectives that only add excitement.
3. **No second-person sales pitch for features.** Describe the feature, not the
   feeling. "Make the UI your own" → "The UI is themeable, and can be replaced
   per-org or per-agent."
4. **Claims must be specific and verifiable.** Avoid round-number hype like
   "in 60 seconds" or "one command" used as a boast rather than a fact. If you mean
   a literal command, show the command.
5. **Imperative mood is for instructions only** — quick-start steps, "run this",
   "edit that." Never for describing the product.
6. **Metaphors must inform, not decorate.** "The front door, not yet the house" is
   decoration; "this repo holds the README and the orrery generator, not the agent
   code" informs. Keep the second kind.
7. **One voice, calm register.** Asides and em-dashes are fine when they carry
   information. They are not fine as drama.

## Banned vocabulary

Treat these as smells; if one appears, the sentence almost certainly needs a rewrite:

`superpower` · `missing piece` · `one-click promise` · `magical` / `magic` ·
`seamless` · `effortless` · `blazing(ly) fast` · `game-changing` · `next-gen` ·
`unleash` · `supercharge` · `delightful` · `simply` / `just` (as in "just works") ·
`in N seconds" / "in N minutes` as a pitch · exclamation marks in body prose.

## What stays

This is not a demand for dry, lifeless text. Keep:
- Precise technical detail (the orrery's Kepler model writeup is the right register).
- Dry wit that is also accurate ("Neptune's true 165-year orbit would otherwise
  look frozen" is fine — it's a fact that happens to be vivid).
- Section structure, code blocks, tables.

## Before / after

| Before (ad copy) | After (documentation) |
|---|---|
| Install in one command. | `docker compose up` starts the server, an agent, the portal, and the database. |
| Make the UI your own. | The shell is themeable, and can be replaced per-org or per-agent. |
| ...as an opt-in superpower (bring a key, and agents render their own faces). | As an opt-in, agents can generate their own interface when you supply a model key. |
| go from nothing to a live agent org in 60 seconds | install and run a working agent org without assembling the parts by hand |

When in doubt, prefer the version that would survive a code review comment that
says "this reads like marketing — what does it actually do?"
