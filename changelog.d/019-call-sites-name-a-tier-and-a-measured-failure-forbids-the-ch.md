### Call sites name a tier, and a measured failure forbids the cheap one

Every org LLM call read one module-global default model, so a 60-token
conversational reply and a planning call that must produce a tool call ran the
same model — the expensive one, because the planner needed it. Measured on a
driven 720-tick day, 360 of 486 daily calls (74%) cap output at 100 tokens or
fewer; the same volume costs 47.74/mo/org on a sonnet-class model and 15.91 on a
haiku-class one.

Six call sites now name the **fast** tier. The (provider, tier) mapping was
already in the shared resolver, so tiering uses it rather than adding a second
table — a second table is how five provider tables came to disagree about base
URLs in the first place.

**What may not move is decided by measurement, not by preference.** The committed
probe found four models and four different forced-`tool_choice` behaviours, five
trials each: one honoured it 5 of 5, one refused with HTTP 400 every time, one
ignored it 5 of 5, and one honoured it **2 of 5**. The 400 is the *good* failure —
loud and immediate. The 2-of-5 is the dangerous one: a site that works three times
in five reads as bad luck rather than as a misconfiguration, and its failure shape
is an empty plan, which is the production zero-output signature this track exists
to remove. `ignored` therefore covers both the 0-of-5 and the 2-of-5 model, and
that is the correct classification — partial honouring is not support.

So the resolver declines to move a call onto a model measured `ignored` or
`rejected`, falls back to the balanced model, and says why; a refused tier is not
an error, because the failure mode of an optimisation is that it does not happen.
Sites that force `tool_choice` are not tiered at all, and a test reads the source
to confirm every tiered site caps its output and forces none.

**The stricter posture is available and off, and the reason is a measurement.**
`LLM_TIER_REQUIRE_MEASURED=true` requires a positive measurement before moving any
call. The probe ran against local ollama models, so **not one model named in the
tier table has been measured** — turning it on today disables tiering for every
provider. A test asserts that state, so the day a tier model is measured the test
fails and the failure is the prompt to reconsider the default.

An operator's explicit `LLM_MODEL` still wins over every tier, and `settings.py`
still shows the resolved model with no literal in it.
