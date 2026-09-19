# Repository gates

Four checks run on every pull request, in the `supply-chain-pins` job, over
every file `git ls-files` reports. They are not linters: none of them looks at
code style, and passing them says nothing about whether a change is correct.
Each refuses one specific thing that is easy to commit and expensive to discover
later.

If one of them failed on your PR and you believe your text is right, read
[When a gate fires on correct prose](#when-a-gate-fires-on-correct-prose) — that
case is real, it has happened, and the fix is not a skip-list entry.

| Gate | Refuses | Because |
|---|---|---|
| [`internal_reference_gate.py`](../scripts/internal_reference_gate.py) | a reference a reader cannot **resolve** | this repository is public; a task ID, a role handle or a bare issue number points at nothing a stranger can open |
| [`claims_language_gate.py`](../scripts/claims_language_gate.py) | a claim whose subject does not **exist** | describing an aspiration as running infrastructure states as fact something the reality does not deliver |
| [`conflict_marker_gate.py`](../scripts/conflict_marker_gate.py) | a file that is not **intact** | a `>>>>>>>` left by a merge resolution reached `main` once, past every other check |
| [`org_vocabulary_gate.py`](../scripts/org_vocabulary_gate.py) | prose **and strings shown to a human** calling a thing by a **name the software does not use** | the product noun became *org* and the runtime finished the rename; the documentation kept drifting back, including in entries written after the rename was recorded as done |

## Why four modules and not one

The distinction is the point, and it is what keeps each module's name accurate.

- A **reference** problem is about reachability. The words are true; the reader
  cannot follow them.
- A **claim** problem is about truth. The words resolve fine; the thing they name
  does not exist.
- An **integrity** problem is about the file. It says nothing about the prose at
  all — a conflict marker is not a statement, it is damage.
- A **vocabulary** problem is about a name. The thing exists, the reader can
  reach it, the sentence is true — and it calls the thing something the software
  does not call it.

A single module covering all four would need a name describing none of them, and
its failure message could not tell you which kind of problem you had.

## Running them locally

Each takes no arguments and scans the tracked tree from the repository root:

```bash
python3 scripts/internal_reference_gate.py
python3 scripts/claims_language_gate.py
python3 scripts/conflict_marker_gate.py
```

Each also has a `--self-test` that checks the patterns still match what they
claim to match, **and still leave alone the things they must not match**:

```bash
python3 scripts/internal_reference_gate.py --self-test
python3 scripts/claims_language_gate.py --self-test
python3 scripts/conflict_marker_gate.py --self-test
```

All three derive their file set from `git ls-files`, so **a new file is not
scanned until it is staged or committed.** Running a gate over a change whose
files are still untracked reports a clean tree without having read them. Add your
files first, then run.

CI runs the self-test **before** the scan for each gate, and the self-test gates
the scan. A pattern that had silently stopped matching would otherwise report a
clean tree, which is worse than no gate: it is a green check that means nothing.
Run the self-test first for the same reason if you change a pattern.

## What each one refuses

### `internal_reference_gate.py`

Task IDs (a role prefix, a hyphen and a number), internal role handles cited as
actors, coordination commands, live deployment hostnames, absolute paths from one
machine (a home directory under a named user), the private umbrella repository by
its repo-identifier spelling, internal programme names held back from the public
release, bare tracker references (a hash followed by digits), cross-repository
ones (a repository name before the hash), and committed credential material.

The failure message names the category and says what to write instead — for a
task ID, describe what the defect *was* rather than citing the ticket.

### `claims_language_gate.py`

Three shapes of one class, aspirational infrastructure described as operating:

- **coined-network** — a name for a network that does not exist, built from
  *agent* or *agentic* joined to *internet* or *web*.
- **unowned-operator** — operation attributed to nobody: a verb such as *run*,
  *operated* or *hosted*, followed by *by the* and a collective noun. A service
  has an operator; if the sentence cannot name one, it is describing an
  aspiration. Naming the operator passes.
- **citizenship-metaphor** — a membership construction that assumes a polity to
  belong to.

NANDA is a research project with artefacts — the Index (a registry you can
resolve against), AgentFacts, NEST, host39 — not a fabric anyone operates.
"NANDA-ready" is fine: it is a claim about this project's own surfaces, and it is
true.

The exact strings each pattern matches are in the module, in `SELF_TEST_CASES`.
They are not reproduced here, because this page is scanned by the gate it
documents — which is the same reason a failing run prints the text it matched:
the failure output tells you what tripped, and the module tells you why.

### `conflict_marker_gate.py`

All four markers git can write at the start of a line: `<<<<<<<`, `|||||||`
(diff3 conflict style), `=======` and `>>>>>>>`.

`=======` needs a rule rather than a pattern, because a markdown setext heading
underline is a run of `=`, and a seven-character heading produces a line
byte-identical to a conflict separator:

```
Summary
=======
```

So a separator is reported only when **both** hold: it is exactly seven
characters alone on the line, and the same file also contains a `<<<<<<<` or a
`>>>>>>>`. Setext headings therefore keep working, and a real conflict is still
caught by its opening or closing marker even if its separator is missed.

### `org_vocabulary_gate.py`

The product-facing noun in this repository is **org**. The runtime finished that
rename on every surface a human reads — the install wizard asks for an "org
display name", the environment variables are `ORG_*` — while the protocol noun
stays on the wire, in the database and in module names. The rule and the list of
frozen surfaces are stated once in
[`ARCHITECTURE.md` § Two nouns](./ARCHITECTURE.md#two-nouns-for-one-thing-protocol-and-product),
which the gate cites in its failure message. The rule had no enforcement, and
prose kept drifting back to the retired word, including in changelog entries
written after the rename was recorded as complete.

The word stays legitimate in four situations, and separating them from the fifth
is the entire gate. It is **not** flagged when it is:

1. **Inside code** — fenced blocks and inline spans are removed before scanning,
   which is what keeps `chapter_id`, `/api/chapter/*`, `CHAPTER_HOME` and
   `chapter.digest.weekly` silent wherever they are marked up as identifiers.
2. **Identifier-shaped even unmarked** — adjacent to `_`, `.` or `/`. The hyphen
   is deliberately not a separator: "cross-chapter" and "per-chapter" are English
   compounds, and they are the drift, not the exception. (Those two are quoted
   here for the reason given in point 4 — this page is scanned by the gate it
   documents, and quoting is how it says a word without using it.)
3. **The protocol's own name** — `Chapter Protocol`, capitalised and spaced.
4. **A mention rather than a use** — the word inside quotes, as in the rule being
   stated. This is also the escape hatch, and it is deliberately the only one:
   quoting is visible at the point of use, where a skip-list entry is invisible
   there and permanent everywhere.

It is flagged when it is a common noun in prose standing where *org* belongs.

### The second rule: strings a human is shown

Reading `.md` only was a blind spot, and it shipped. The first-run wizard's
step 1 was titled "Pick a chapter" and its field was labelled "Chapter URL",
on screen, in the one surface built for someone who has never seen this product
— while this gate reported OK over 62 files and `docs/PRODUCT.md` claimed the
word is never user-facing. The gate was green and the claim it enforces was
false on the surface that mattered most.

Scanning `.py` for the word is not the fix: it is everywhere in code and almost
always right there. `chapter_id`, `chapter_agent.py`, `/api/chapter/*`, the
event topics, internal comments and log lines are all legitimate and unmovable,
so a naive scan floods — and a gate that floods gets exempted into uselessness.

The rule is **a string a human is shown**, and this codebase shows humans
strings by exactly three routes. Each is recognised through the AST, never by
matching source text, which is what keeps comments, docstrings, identifiers and
log lines out *by construction* rather than by a pattern that has to keep
guessing.

| Class | What it reads | Why it is defensible |
|---|---|---|
| **A — component arguments** | text-bearing arguments to the A2UI helpers in `server/a2ui_helpers.py` | the positions are **derived from those signatures by parameter name**, not hand-listed |
| **B — step specs** | dict literals carrying `title` *and* `description` *and* `fields` | that is the contract the surface builder requires, so it is a rule and not an alias for one file |
| **C — terminal output** | `console.print`, `typer.echo`/`secho`, `click.echo` | a terminal-UI library call is unambiguously presentation to a person |

Three details carry the weight:

- **Deriving Class A rather than listing it.** `stat(id, label, value)` and
  `metric(id, value, label)` put `label` in *different* positions, so any fixed
  positional assumption is wrong on one of them — only the name is stable. It
  also means a helper written tomorrow with a `label` parameter is covered that
  day, not the day someone remembers this file. `value` is deliberately excluded:
  `{"label": "Anthropic Claude", "value": "anthropic"}` is the shape everywhere,
  where the value is a wire code and the label is the human's words.
- **Class B keys off the contract, not the name `STEP_SPEC`.** Class A cannot see
  the wizard at all, because the builder renders it as
  `heading("step-heading", 2, spec["title"])` — a subscript, not a literal. And
  `STEP_SPEC` is currently the only constant of its kind in the tree, so a
  name-based test would have been a one-file allowlist wearing a rule's clothes.
  The same shape is what excludes the LLM function-tool schemas, which carry
  `description` too but have `parameters` rather than `fields`, and are sent to a
  model rather than shown to a person.
- **Bare `print()` is excluded, and that was measured rather than assumed.** It
  produces 26 matches across 11 files here and every one is a log or diagnostic
  line. Those are the log lines that are legitimate by rule; including them would
  have meant an exemption list on day one.

**Both rules are proven in both directions on every run**, which is why the CI
step has three commands rather than two. `--self-test` checks both rules in
process, and fails if fewer than five text-bearing helpers were derived — a
signature move that quietly emptied the code scan would otherwise read as a pass.
`--prove` plants real drift *and* every legitimate form into a tracked prose file
**and** a tracked module, runs the whole pipeline over the real `git ls-files`
output, requires each planted string caught at its line and the rest ignored, and
restores both files. A gate whose entire content is a discrimination rule is only
half proven by showing that it fires.

What it does **not** catch, and this is worth reading before trusting it: the
same drift expressed without the word; any doc-vs-code disagreement that is not
about vocabulary; an artifact whose own name is genuinely the retired one; data
files such as `server/agentfacts.json`, which are neither prose nor code and are
not scanned; and the LLM tool-schema descriptions above, which are drifted
product prose that nothing currently gates.

## When a gate fires on correct prose

This happens. When it does, **fix the pattern by shape — do not add the file to a
skip list.** A skip list turns one false positive into a permanent hole, and the
next real instance in that file goes unreported.

Two precedents in the tree, both from a gate flagging text that was right:

- `agent/community_member/profile.py` documents `"photo_path": "/home/.../avatar.png"` — already
  anonymised by its author. The local-path pattern was flagging correct prose, so
  it now requires the user segment to contain a letter or digit. `...` is
  excluded **by shape**, and any real home directory is still caught.
- **NANDA Chapter Protocol** with spaces is the public protocol name and must
  keep working in prose; only the repo-identifier spelling is withheld. The
  separator class is `[_-]` rather than `\s` for exactly that reason.

The procedure:

1. Work out what distinguishes your correct text from the thing the gate is for.
   It is usually a shape: a placeholder, a separator, a length, a missing pair.
2. Narrow the pattern on that shape.
3. **Add a must-not-match case** to `SELF_TEST_CASES` carrying your text, so the
   narrowing is pinned and cannot be undone silently.
4. Run `--self-test`. A widening that breaks a positive fails here.

The must-not-match cases are not decoration. A gate that blocks correct prose
does not get obeyed — it gets deleted, and takes its true positives with it. Each
gate's self-test therefore counts must-match and must-not-match separately, and
reports both.

If narrowing by shape is genuinely impossible, say so in the PR and leave the
pattern alone. A gate is easier to argue about than to quietly weaken.

## What these gates do not do

They check shapes, not truth. **No gate here can tell you whether a claim is
accurate.**

- No pattern separates a planned feature written in the present tense from a
  shipped one. "The detector emits divergence findings" is ordinary English
  whether or not the detector was ever wired up.
- Every false claim found in this repository's documentation review was
  grammatically impeccable: federation advertised as publishing by default when a
  fresh install publishes nowhere; self-hosters warned about a publication that
  had stopped happening; an evidence row citing a file that was real and did not
  support the claim. None would be caught by any pattern here.

Claims are checked against evidence in [`CLAIMS.md`](./CLAIMS.md), by finding the
test, endpoint or measurement that would fail if the claim were false. A green
gate run means the tree contains no unresolvable reference, no coined network and
no conflict marker. It does not mean the documentation is honest.
