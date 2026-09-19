### The vocabulary gate could not see the screen

The vocabulary gate read markdown and nothing else. That blind spot was not
theoretical: the first-run wizard's step 1 was titled "Pick a chapter" with a
field labelled "Chapter URL", on screen, in the one surface built for someone
who has never seen this product — while the gate reported OK over 62 files and
`docs/PRODUCT.md` said the word is never user-facing. A green gate and a false
claim, on the surface that mattered most.

It now also reads **the strings a human is shown**, through the AST rather than
by matching source text, so identifiers, comments, docstrings and log lines stay
out by construction. Three routes, each recognised structurally:

- **A2UI component arguments**, at positions **derived from the signatures in
  `server/a2ui_helpers.py` by parameter name**. Deriving is not decoration:
  `stat(id, label, value)` and `metric(id, value, label)` put `label` in
  different positions, so any fixed positional assumption is wrong on one of
  them, and a helper added later is covered the day it is written.
- **Wizard step specs**, recognised by the contract their consumer requires —
  `title` and `description` and `fields` — rather than by the name `STEP_SPEC`,
  which is currently the only such constant in the tree and would have made the
  rule a one-file allowlist. This is also what excludes the LLM function-tool
  schemas, which carry `description` but have `parameters`, and go to a model
  rather than to a person.
- **Terminal-UI output** — `console.print`, `typer.echo`/`secho`, `click.echo`.
  Bare `print()` is deliberately excluded, and that was measured rather than
  assumed: it produces 26 matches across 11 files here and every one is a log or
  diagnostic line.

Eleven user-facing strings outside the wizard are corrected with it — the
"Org Leaders" heading and the federation count in `server/chapter_agent.py`, four
strings in `server/surfaces.py`, and five in the operator's terminal setup script
`server/scripts/setup_chapter.py`, which had been telling operators
"Your chapter gets a unique ID" and "The chapter needs a public URL" —
each quoted here, on one line, because a quote broken across a newline is not a
quote as far as the rule is concerned. Component ids, wire keys
and module names are untouched: `metric("b-chapter", …)` keeps its id and its
`by_role` key, and only the label a person reads changed.

`--self-test` and `--prove` both extend to the new rule, and `--self-test` now
fails if fewer than five text-bearing helpers were derived — a signature move
that quietly emptied the code scan would otherwise have read as a pass.
