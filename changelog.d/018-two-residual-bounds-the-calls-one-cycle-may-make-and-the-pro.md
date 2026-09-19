### Two residual bounds: the calls one cycle may make, and the prompt that grows

**The per-cycle call cap, in the factory.** `think_approvals_sweep` makes two LLM
calls per approved row and was measured making **40 sequential calls in one
cycle** at its own row limit of 20 — against 9 calls for the entire rest of the
rotation.

⚠️ **It is a latency and rate-limit bound, not a spend saving, and the
measurement is why.** All 40 of those calls cost **1,897 tokens in total**. The
intuition said this was the expensive one; the measurement said otherwise and the
measurement wins. What forty sequential round-trips actually costs is wall-clock
inside one cycle and headroom against a provider's rate limit, so that is what
the bound claims and all it claims — a bound that advertises the wrong benefit
teaches the next reader the wrong thing, and the next reader is who decides
whether to raise it. A test fails if the code starts selling it as a saving.

The cap lives in the client factory, so it bounds every caller rather than the one
site that happened to be measured. Reaching it raises a named refusal, and the
sweep catches it, stops, and records how many approvals it deferred. Nothing is
lost: a row is marked executed only after it succeeds, so a deferred row is still
approved and the next sweep takes it. Silent truncation is the failure this
shape exists to avoid — it is indistinguishable from "there was nothing to do",
and the work in question is somebody's approved introductions.

**The insight prompt's skill join is sampled.** It goes 145 → 1,335 tokens (9×)
from a bare fixture to a realistic 300-skill org, the one org prompt that
grows without limit as an org does. The prompt now names an evenly spread
sample — spread rather than the alphabetical head, since the list is sorted and a
head slice would show an org's "a" skills and present them as a picture of the
org — and the sample size travels with it, so a reader can tell a sampled
list from a complete one. A list that already fits is unchanged and unannotated.

⚠️ **The sample does not feed the watermark, and that is the whole care in this
change.** `think_insight` is elided against a watermark, and the introduction
gate shipped a bug of exactly this shape: it hashed a member list truncated to 30
for prompt-size reasons, so past member 30 a joiner never released the gate. A
value truncated, sampled or capped for prompt-size reasons cannot double as the
change detector for the thing it was truncated from. So the watermark takes the
**full** skill set and the prompt takes the sample — two different values on
purpose. A sample is in fact worse than a head slice for this, because a new
entry can land outside a sample at any position rather than only past the end.

Note the criterion is narrower than "capped is unsafe": the recent-pairs cap in
the same file is fine, because `recent_memories` returns the newest 20 and a new
entry always lands inside that window. Only a bound that can hide a **new** entry
can hide a change.
