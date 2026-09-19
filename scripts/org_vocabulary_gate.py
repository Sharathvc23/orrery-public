#!/usr/bin/env python3
"""Refuse prose — and strings shown to a human — that call an org a chapter.

Fourth sibling of ``internal_reference_gate.py``, ``claims_language_gate.py`` and
``conflict_marker_gate.py``, and a separate module for the same reason they are
separate from each other: one gate, one failure mode, one accurate name.

- A *reference* problem is about reachability — the reader cannot follow it.
- A *claim* problem is about truth — the subject does not exist.
- An *integrity* problem is about the file — a conflict marker is damage.
- A *vocabulary* problem is about a name — the thing exists, the reader can
  reach it, and the documentation calls it something the software does not.

This repository renamed its product-facing noun from *chapter* to *org* on every
surface a human reads: the install wizard asks for an "org display name", the
environment variables are ``ORG_*``. The protocol noun stays on every surface
another party depends on — routes, headers, signed canonical strings, wire
fields, event names, tables, metrics, module names. **The rule this gate
enforces, and the list of frozen surfaces, is stated once in
``docs/ARCHITECTURE.md`` § Two nouns**; ``CONTRIBUTING.md`` and
``docs/README.md`` point at it. The rule had no enforcement, so prose kept
drifting back, including in changelog entries written after the rename was
recorded as finished.

═══ THE DISCRIMINATION RULE ═══

The word is legitimate in four situations and wrong in one. Separating them is
the whole job, because a gate that flags every occurrence would flag the frozen
wire ids this project is contractually unable to rename.

FLAGGED — the word used as a common noun in prose, standing where *org* belongs:
"skills move between chapters", "a chapter leader", "the chapter's Issuer Log".

NOT FLAGGED, and how each is recognised:

1. **Anything inside code.** Fenced blocks and inline code spans are removed
   before scanning. A command, a route, a field name or a sample of output is
   quoted software, not prose about it — and this is what keeps ``chapter_id``,
   ``/api/chapter/*``, ``CHAPTER_HOME`` and ``chapter.digest.weekly`` silent
   wherever a writer marked them up as the identifiers they are.

2. **Identifier shape, even unmarked.** A ``chapter`` adjacent to ``_``, ``.``
   or ``/`` is part of a name: ``chapter_keys``, ``chapter_agent.py``,
   ``nanda_chapter_db_failures_total``, ``/api/portal/chapter``. Prose does not
   punctuate that way. The hyphen is deliberately NOT an identifier separator:
   "cross-chapter", "per-chapter" and "chapter-scoped" are ordinary English
   compounds and are exactly the drift this gate exists to catch.

3. **The protocol's own name.** ``Chapter Protocol``, capitalised and spaced, is
   what the underlying protocol is called. It is permanent and correct, and
   ``docs/GATES.md`` already records that spelling as the public name.

4. **A mention rather than a use.** The word inside quotes — 'the word "chapter"
   is never user-facing' — is the rule being stated, not the rule being broken.
   This is also the escape hatch: a historical record that must preserve the old
   wording quotes it, and quoting is a visible act a reader can see, unlike a
   file added to a skip list where the exemption is invisible at the point of
   use. There is deliberately no file allowlist for that reason.

═══ WHAT THIS GATE DOES NOT CATCH ═══

- **Drift in code.** It reads prose files only. A Python module, a JSON fixture
  and a schema are out of scope, and the wire ids inside them are frozen anyway.
- **The same drift expressed without the word.** A page describing the old
  model in different vocabulary reads clean here. No pattern separates that from
  correct prose.
- **Any other doc-vs-code disagreement.** A document wrong about behaviour,
  about a flag name, or about what a command prints is not a vocabulary problem
  and is not machine-checkable by this or any pattern. It is caught by driving
  the flow the document describes, which is a person's job.
- **An artifact whose own name is stale.** Where a package or file is genuinely
  called ``nanda-chapter`` or ``chapters.json``, naming it correctly is not
  drift, and this gate stays silent so that a document can go on telling a
  reader the command that actually works.

The must-not-match cases in ``SELF_TEST_CASES`` carry the same weight as the
must-match ones. Each is correct prose from this tree that a careless pattern
would block, and a gate that blocks correct prose gets deleted rather than
obeyed.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path

# ── Masking: what is removed before the word is looked for ──────────────────

#: Fenced code blocks. Replaced by their own newlines so line numbers survive.
FENCE_RE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)

#: Inline code spans. Replaced by spaces, same width, for the same reason.
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")

#: Identifier shape: ``chapter`` joined to something by ``_``, ``.`` or ``/``.
#: ``nanda-chapter`` is named explicitly because it is a real package name and
#: the hyphen is otherwise not a separator here.
IDENTIFIER_RE = re.compile(
    r"[\w./]*[_./]chapters?\b|\bchapters?[_./][\w./]*|\bnanda-chapter\b",
    re.IGNORECASE,
)

#: The protocol's own name, which is permanent.
PROTOCOL_NAME_RE = re.compile(r"\bChapter Protocol\b")

#: A mention rather than a use: the word inside quotes, straight or typographic.
QUOTED_MENTION_RE = re.compile(
    r"[\"'“‘][^\"'”’\n]{0,60}\bchapters?\b[^\"'”’\n]{0,60}[\"'”’]",
    re.IGNORECASE,
)

MASKS: tuple[re.Pattern[str], ...] = (
    IDENTIFIER_RE,
    PROTOCOL_NAME_RE,
    QUOTED_MENTION_RE,
)

#: What is left over after all of the above is the finding.
BARE_WORD_RE = re.compile(r"\bchapters?\b", re.IGNORECASE)

REASON = (
    "the product-facing noun is **org**. This word survives only as a frozen "
    "wire id (chapter_id, /api/chapter/*, event topics), an internal module "
    "name, the protocol's own name written 'Chapter Protocol', or a real "
    "artifact name. If this instance is one of those, write it as the "
    "identifier it is or quote it; if it is prose, it is an org. The rule and "
    "the frozen surfaces: docs/ARCHITECTURE.md § Two nouns."
)

SELF = "scripts/org_vocabulary_gate.py"

#: Prose the gate reads. Deliberately narrow: this is a vocabulary rule about
#: what a reader is told, so it applies to documentation, not to fixtures.
PROSE_SUFFIXES = (".md",)

SKIP_DIRS = ("node_modules/", "__pycache__/", ".venv/")


def tracked_files(suffixes: tuple[str, ...] = PROSE_SUFFIXES) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    return [
        f
        for f in out.split("\n")
        if f
        and f != SELF
        and not f.endswith(SELF)
        and f.lower().endswith(suffixes)
        and not any(d in f for d in SKIP_DIRS)
    ]


def prose_of(text: str) -> str:
    """``text`` with code, identifiers, the protocol name and quoted mentions
    blanked out, and every line number preserved."""
    text = FENCE_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    text = INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), text)
    chars = list(text)
    for pattern in MASKS:
        for match in pattern.finditer(text):
            for i in range(match.start(), match.end()):
                if chars[i] != "\n":
                    chars[i] = " "
    return "".join(chars)


def scan(files: list[str]) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    for name in files:
        try:
            raw = Path(name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        prose = prose_of(raw)
        lines = raw.split("\n")
        for match in BARE_WORD_RE.finditer(prose):
            line_no = prose.count("\n", 0, match.start()) + 1
            context = lines[line_no - 1].strip()
            findings.append((name, line_no, context[:120]))
    return findings


#: (text, should-it-fire). Positives are wording that shipped in this tree or is
#: the same class. Negatives are correct prose from this tree; if one of them
#: starts firing, the rule has widened past what it claims.
SELF_TEST_CASES: tuple[tuple[str, bool], ...] = (
    # ── Positives: prose calling an org a chapter ──
    ("skills move between chapters as portable signed packages", True),
    ("signed author, or a chapter leader or admin", True),
    ("the member audits the chapter for silent omission", True),
    ("verified against the *chapter's* signed checkpoint", True),
    ("The endpoint under test is the one the chapter actually uses", True),
    ("Today a chapter skill is manifest plus content-reference", True),
    ("a realistic 300-skill chapter, the one org prompt that grows", True),
    ("live per-chapter catalog", True),
    ("Cross-chapter discovery is one HTTP call away", True),
    ("the rest are chapter-scoped or operational", True),
    ("mints a chapter-signed receipt", True),
    ("Install the NANDA chapter skill", True),
    ("a peer whose chapter key changes", True),
    # ── Negatives: the frozen wire ids, unmarked ──
    ("the chapter_id is a frozen wire id", False),
    ("routes under /api/chapter/allowlist stay open", False),
    ("the sealed row lives in chapter_keys.secret_b64", False),
    ("entrypoint server/chapter_agent.py binds port 7000", False),
    ("watch nanda_chapter_db_failures_total for non-zero", False),
    ("topics like chapter.digest.weekly are frozen", False),
    ("KNOWN_CHAPTER_ENDPOINTS is the list you control", False),
    # ── Negatives: the protocol's own name ──
    ("This follows the NANDA Chapter Protocol v0.5", False),
    ("the skill is maintained in the Chapter Protocol umbrella", False),
    # ── Negatives: a real artifact name ──
    ("openclaw skill install nanda-chapter --force", False),
    ("written to ~/.openclaw/skills/nanda-chapter/identity.json", False),
    # ── Negatives: the rule being stated, not broken ──
    ('User-facing text says org. "chapter" is a frozen protocol field only', False),
    ('The word "chapter" is never user-facing', False),
    ('it survives only in frozen wire ids like "chapter_id"', False),
    # ── Negatives: ordinary prose a wider pattern would break ──
    ("an org hosts agents, and each org runs its own server", False),
    ("the org you joined sees three peer orgs", False),
    ("a chapter of a book is not what this word means here", True),
)


def self_test() -> int:
    failures = []
    for text, should_fire in SELF_TEST_CASES:
        fired = bool(BARE_WORD_RE.search(prose_of(text)))
        if fired != should_fire:
            failures.append(
                f"  {text!r}\n    expected {'a match' if should_fire else 'no match'}, "
                f"got {'a match' if fired else 'none'}"
            )
    if failures:
        print(
            "SELF-TEST FAILED — the gate no longer discriminates as it claims:",
            file=sys.stderr,
        )
        print("\n".join(failures), file=sys.stderr)
        return 1
    helpers = derive_text_parameters(Path(HELPER_MODULE).read_text(encoding="utf-8"))
    if len(helpers) < 5:
        print(
            f"SELF-TEST FAILED — only {len(helpers)} text-bearing helpers derived from "
            f"{HELPER_MODULE}. The signatures moved, or the file did, and the code scan "
            "would silently cover almost nothing.",
            file=sys.stderr,
        )
        return 1

    code_failures = []
    for source, should_fire in CODE_SELF_TEST_CASES:
        try:
            fired = bool(scan_code_source(source, helpers))
        except SyntaxError as exc:
            code_failures.append(f"  {source!r}\n    case does not parse: {exc}")
            continue
        if fired != should_fire:
            code_failures.append(
                f"  {source!r}\n    expected {'a match' if should_fire else 'no match'}, "
                f"got {'a match' if fired else 'none'}"
            )
    if code_failures:
        print(
            "SELF-TEST FAILED — the code rule no longer discriminates as it claims:",
            file=sys.stderr,
        )
        print("\n".join(code_failures), file=sys.stderr)
        return 1

    positives = sum(1 for _, fires in SELF_TEST_CASES if fires)
    negatives = len(SELF_TEST_CASES) - positives
    code_positives = sum(1 for _, fires in CODE_SELF_TEST_CASES if fires)
    code_negatives = len(CODE_SELF_TEST_CASES) - code_positives
    print(
        f"OK: self-test — prose {len(SELF_TEST_CASES)} cases "
        f"({positives} must-match, {negatives} must-NOT-match); "
        f"code {len(CODE_SELF_TEST_CASES)} cases "
        f"({code_positives} must-match, {code_negatives} must-NOT-match); "
        f"{len(helpers)} text-bearing helpers derived from {HELPER_MODULE}"
    )
    return 0


#: The file the plant proof writes into. A real tracked prose file, so the proof
#: exercises the whole pipeline — `git ls-files` enumeration, masking, scan and
#: the report — rather than the regex alone. A gate proven only against its own
#: pattern is proven against the half that was never in doubt.
PLANT_TARGET = "docs/GATES.md"

#: What gets planted. The positive is drift of the shape this gate exists for.
#: The negatives are each of the four legitimate situations, planted together:
#: if any one of them fires, the discrimination rule has broken in a way the
#: in-process self-test would not necessarily show.
PLANT_POSITIVE = "A skill published on one chapter installs on another."
PLANT_NEGATIVES = (
    "The `chapter_id` field and the `/api/chapter/*` routes are frozen wire ids.",
    "Orrery speaks the NANDA Chapter Protocol.",
    "Run `openclaw skill install nanda-chapter` and read chapters.json.",
    'The word "chapter" is never user-facing.',
)


def prove_both_ways() -> int:
    """Plant drift into a tracked file and require the gate to name it; plant the
    legitimate forms and require silence. Restores the file either way."""
    target = Path(PLANT_TARGET)
    original = target.read_text(encoding="utf-8")
    planted_line = original.count("\n") + 2
    failures: list[str] = []
    try:
        # ── Direction 1: it must FIRE, and name the file and line ──
        target.write_text(original + "\n" + PLANT_POSITIVE + "\n", encoding="utf-8")
        hits = [f for f in scan(tracked_files()) if f[0] == PLANT_TARGET]
        if not hits:
            failures.append(
                f"  planted drift into {PLANT_TARGET} and the gate stayed silent: {PLANT_POSITIVE!r}"
            )
        elif not any(line == planted_line for _, line, _ in hits):
            failures.append(
                f"  the gate fired on {PLANT_TARGET} but not at the planted line {planted_line}: "
                f"reported {[ln for _, ln, _ in hits]}"
            )

        # ── Direction 2: it must stay SILENT on every legitimate form ──
        target.write_text(
            original + "\n" + "\n".join(PLANT_NEGATIVES) + "\n", encoding="utf-8"
        )
        noise = [f for f in scan(tracked_files()) if f[0] == PLANT_TARGET]
        for name, line, context in noise:
            failures.append(f"  fired on a legitimate form at {name}:{line}  {context}")
    finally:
        target.write_text(original, encoding="utf-8")

    if failures:
        print("PLANT PROOF FAILED:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(
        f"OK: plant proof — drift planted in {PLANT_TARGET} was caught at its line, "
        f"and {len(PLANT_NEGATIVES)} legitimate forms planted beside it were not"
    )
    return 0


# ══════════════════════════════════════════════════════════════════════════════
# USER-FACING STRINGS IN CODE
# ══════════════════════════════════════════════════════════════════════════════
#
# The prose scan above reads ``.md`` only, and that blind spot shipped: the
# first-run wizard said "Pick a chapter" on screen while this gate reported OK
# over 62 files and ``docs/PRODUCT.md`` claimed the word is never user-facing.
# A gate that is green while the claim it enforces is false on the one surface
# built for someone who has never seen the product is worse than no gate.
#
# The hard part is NOT finding the word in Python — it is everywhere and is
# almost always right there. ``chapter_id``, ``chapter_agent.py``,
# ``/api/chapter/*``, the event topics, internal comments and log lines are all
# legitimate and unmovable. Scanning ``.py`` files for the word would flood, and
# a gate that floods gets exempted into uselessness.
#
# So the rule is not "scan Python". It is: **a string a human is shown**, and
# this codebase shows humans strings by exactly three routes. Each is recognised
# structurally, through the AST, never by matching source text — which is what
# keeps comments, docstrings, identifiers and log lines out by construction
# rather than by a pattern that has to keep guessing.
#
# ── CLASS A — arguments to the A2UI component helpers ────────────────────────
# ``server/a2ui_helpers.py`` is the single module that builds the components a
# renderer paints. Its parameter NAMES declare which positions carry human text:
# ``text_str``, ``label``, ``content``, ``items``, ``suffix``. ``id``, ``value``,
# ``variant``, ``color`` and ``level`` do not.
#
# The positions are DERIVED from those signatures, not hand-listed, for two
# reasons that are both load-bearing:
#   * ``stat(id, label, value)`` and ``metric(id, value, label)`` put ``label``
#     in DIFFERENT positions. Any fixed positional assumption is wrong on one of
#     them. Only the name is stable.
#   * A helper added tomorrow with a ``label`` parameter is covered the day it is
#     written, not the day someone remembers to update a list here. Same reason
#     the conformance guards are selected by directory and not by module list.
#
# ``value`` is deliberately NOT a text parameter even though it is rendered:
# ``{"label": "Anthropic Claude", "value": "anthropic"}`` is the shape all over
# this tree, where the value is a wire code and the label is the human's words.
#
# ── CLASS B — the step specs a surface builder introspects ───────────────────
# Class A alone cannot see the wizard, and that is the whole reason Class B
# exists. ``build_onboarding_surface`` renders the step with
# ``heading("step-heading", 2, spec["title"])`` — the argument is a SUBSCRIPT,
# so the literal sitting in ``STEP_SPEC`` is invisible to helper-call scanning.
#
# A spec dict is recognised by the contract its consumer requires — it carries
# ``title`` AND ``description`` AND ``fields`` — and NOT by being named
# ``STEP_SPEC``. That distinction decides whether this is a rule or an alias for
# one file: ``STEP_SPEC`` is currently the only constant of its kind in the
# tree, so a name-based test would have been a one-file allowlist in a rule's
# clothes, enforcing nothing about the next surface anyone writes.
#
# This shape is also what excludes the LLM function-tool schemas in
# ``agent/community_member/agent.py`` and ``server/sovereign_runtime.py``. They
# carry ``description`` too, and 13 of them mention the retired noun — but they
# have ``parameters``, not ``fields``, and they are sent to a model rather than
# shown to a person. They are drifted product prose and nothing gates them;
# that is a separate rule for a separate unit, recorded here rather than
# silently swept in.
#
# ── CLASS C — terminal-UI output ─────────────────────────────────────────────
# ``server/scripts/setup_chapter.py`` is a second wizard — the operator's, in a
# terminal — and it told them "Your chapter gets a unique ID" and "The chapter
# needs a public URL".
#
# Only calls into a terminal-UI library count: ``console.print``,
# ``typer.echo``/``secho``, ``click.echo``. **Bare ``print()`` is deliberately
# excluded, and this was measured rather than assumed**: bare ``print`` produces
# 26 matches across 11 files in this tree and every one is a log or diagnostic
# line — ``[serve] chapter:``, ``[arp][WARN] chapter-action receipt refused``,
# ``CHAPTER TRUST WARNING:``. Those are the log lines that are legitimate by
# rule. Including bare ``print`` would have meant an exemption list on day one.
# f-string literal segments are read; interpolated values are not, because a
# runtime value is not a string anyone wrote here.

#: Files the code scan reads.
CODE_SUFFIXES = (".py",)

#: The module whose signatures define what a human-readable argument is.
HELPER_MODULE = "server/a2ui_helpers.py"

#: Parameter names that carry human-readable text. See the note on ``value``.
TEXT_PARAM_NAMES = frozenset(
    {"text_str", "label", "content", "items", "suffix", "title", "description"}
)

#: The contract ``build_onboarding_surface`` requires of a step spec.
SPEC_REQUIRED_KEYS = frozenset({"title", "description", "fields"})

#: Human-readable keys within a spec's field dicts and their option dicts.
SPEC_FIELD_TEXT_KEYS = frozenset({"label", "placeholder", "hint"})

#: Terminal-UI output. Receiver names are checked so an unrelated ``.print`` or
#: ``.echo`` on some other object does not enrol itself into the scan.
UI_OUTPUT_METHODS = frozenset({"print", "echo", "secho"})
UI_OUTPUT_RECEIVERS = frozenset({"console", "err_console", "typer", "click"})

CODE_REASON = (
    "this string is shown to a human — an A2UI component, a wizard step spec, "
    "or terminal output — and the product-facing noun is **org**. Identifiers, "
    "wire ids, module names, comments and log lines are not scanned and need no "
    "change; if this text must quote the retired word, put it in quotes."
)


def _literal_segments(node: ast.AST):
    """Yield (node, text) for a string constant, or for each literal segment of
    an f-string. Interpolated values are skipped — they are not text written
    here. Implicit concatenation is already folded into one Constant by the
    parser, which is how the multi-line description in ``STEP_SPEC`` is read as
    the single sentence a reader actually sees."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node, node.value
    elif isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                yield node, part.value


def derive_text_parameters(source: str) -> dict[str, dict[int, str]]:
    """Map helper name -> {positional index: parameter name} for every parameter
    that carries human text, read out of ``HELPER_MODULE``'s own signatures."""
    helpers: dict[str, dict[int, str]] = {}
    for node in ast.parse(source).body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        positions = {
            index: arg.arg
            for index, arg in enumerate(node.args.args)
            if arg.arg in TEXT_PARAM_NAMES
        }
        if positions:
            helpers[node.name] = positions
    return helpers


def _dict_keys(node: ast.Dict) -> set[str]:
    return {
        k.value
        for k in node.keys
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }


def _dict_get(node: ast.Dict, name: str):
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and key.value == name:
            return value
    return None


def scan_code_source(
    source: str, helpers: dict[str, dict[int, str]], name: str = "<source>"
) -> list[tuple[str, int, str]]:
    """The three classes, over one parsed module."""
    findings: list[tuple[str, int, str]] = []

    def check(node, where: str) -> None:
        if node is None:
            return
        for literal, text in _literal_segments(node):
            if BARE_WORD_RE.search(prose_of(text)):
                findings.append(
                    (name, literal.lineno, f"[{where}] {text.strip()[:100]}")
                )

    tree = ast.parse(source)
    for node in ast.walk(tree):
        # ── Class A ──
        if isinstance(node, ast.Call):
            func = node.func
            called = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            if called in helpers:
                for index, arg in enumerate(node.args):
                    if index in helpers[called]:
                        check(arg, f"{called}({helpers[called][index]})")
                for keyword in node.keywords:
                    if keyword.arg in TEXT_PARAM_NAMES:
                        check(keyword.value, f"{called}({keyword.arg}=)")
            # ── Class C ──
            elif (
                isinstance(func, ast.Attribute)
                and func.attr in UI_OUTPUT_METHODS
                and isinstance(func.value, ast.Name)
                and func.value.id in UI_OUTPUT_RECEIVERS
            ):
                for arg in node.args:
                    check(arg, f"{func.value.id}.{func.attr}")
        # ── Class B ──
        elif isinstance(node, ast.Dict) and SPEC_REQUIRED_KEYS <= _dict_keys(node):
            check(_dict_get(node, "title"), "step spec title")
            check(_dict_get(node, "description"), "step spec description")
            fields = _dict_get(node, "fields")
            if isinstance(fields, ast.List):
                for field in fields.elts:
                    if not (isinstance(field, ast.Dict) and "key" in _dict_keys(field)):
                        continue
                    for key in sorted(SPEC_FIELD_TEXT_KEYS):
                        check(_dict_get(field, key), f"step spec field {key}")
                    options = _dict_get(field, "options")
                    if isinstance(options, ast.List):
                        for option in options.elts:
                            if isinstance(option, ast.Dict):
                                check(
                                    _dict_get(option, "label"), "step spec option label"
                                )
    return findings


def scan_code(
    files: list[str], helpers: dict[str, dict[int, str]]
) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    for name in files:
        try:
            source = Path(name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        try:
            findings.extend(scan_code_source(source, helpers, name))
        except SyntaxError:
            # A file git tracks but Python cannot parse is a different problem
            # than a vocabulary one, and not this gate's to report.
            continue
    return findings


#: (source, should-it-fire). Positives are the shapes that shipped. Negatives
#: are real constructions from this tree that a careless rule would break —
#: they carry the same weight, because a gate that blocks correct code gets
#: deleted rather than obeyed.
CODE_SELF_TEST_CASES: tuple[tuple[str, bool], ...] = (
    # ── Class A positives ──
    ('heading("leaders-title", 2, "Chapter Leaders")', True),
    ('metric("b-chapter", total, "as chapter")', True),
    ('callout("c", "x", title="Agent not found in chapter registry")', True),
    ('text("t", "Active subscriptions on this chapter\'s event bus.")', True),
    # ── Class A negatives: the id and the value are not human text ──
    ('metric("b-chapter", chapter_total, "as author")', False),
    ('metric("fed-chapters", str(n), "Orgs")', False),
    ('card("chapter-card", "root")', False),
    ('row("chapter-row", ["a", "b"])', False),
    ('text("t", chapter_label)', False),
    # ── Class B ──
    (
        'STEP_SPEC = {1: {"title": "Pick a chapter", "description": "d", "fields": []}}',
        True,
    ),
    (
        'S = {"title": "t", "description": "Your agent joins a chapter to find peers.", "fields": []}',
        True,
    ),
    (
        'S = {"title": "t", "description": "d", "fields": [{"key": "chapter_url", "label": "Chapter URL"}]}',
        True,
    ),
    # the wire key itself is an identifier and must stay silent
    (
        'S = {"title": "t", "description": "d", "fields": [{"key": "chapter_url", "label": "Org URL"}]}',
        False,
    ),
    # an LLM function-tool schema is not a step spec: parameters, not fields
    (
        '{"type": "function", "function": {"name": "search_chapter", '
        '"description": "Search for members in the chapter.", "parameters": {}}}',
        False,
    ),
    # ── Class C ──
    ('console.print("  Your chapter gets a unique ID.")', True),
    ('typer.echo("The chapter needs a public URL.")', True),
    ('console.print(f"  Federation lets your chapter reach {n} peers.")', True),
    # ── Class C negatives: log lines and diagnostics are not terminal UI ──
    ('print("[serve] chapter: %s" % url)', False),
    ('print("CHAPTER TRUST WARNING: pin changed")', False),
    ('logger.info("chapter sync complete")', False),
    ('log.print("chapter sync complete")', False),
    # ── Negatives that hold across all three classes ──
    ("# every chapter agent gets a policy row\nx = 1", False),
    ('"""Reuse portal/layout as chapter surface."""', False),
    ('CHAPTER_HOME = os.environ["CHAPTER_URL"]', False),
    ('console.print("Orrery speaks the NANDA Chapter Protocol.")', False),
    ("console.print('The word \"chapter\" is never user-facing.')", False),
    ('console.print("Run: openclaw skill install nanda-chapter")', False),
)


#: The code plant writes into a real tracked module, so the proof exercises the
#: whole pipeline — enumeration, parse, derivation, all three classes — and not
#: the matcher alone. ``server/a2ui_helpers.py`` would be the wrong target: it is
#: what the text parameters are DERIVED from, so planting a function there would
#: change the rule mid-proof.
PLANT_CODE_TARGET = "server/surfaces.py"

#: One positive per class. All three must be caught, each at its own line.
PLANT_CODE_POSITIVES = (
    'def _plant_a():\n    return heading("plant-a", 2, "Chapter Leaders")',
    'PLANT_B = {"title": "Pick a chapter", "description": "d", "fields": []}',
    'def _plant_c():\n    console.print("  Your chapter gets a unique ID.")',
)

#: Every legitimate in-code form, planted together. If any one fires, the rule
#: has broken in a direction the in-process self-test would not necessarily show
#: — these run through `git ls-files`, the real parse and the real derivation.
PLANT_CODE_NEGATIVES = (
    "# every chapter agent gets a policy row when the migration runs",
    'def _plant_n1(chapter_label):\n    """Reuse portal/layout as chapter surface."""\n'
    "    chapter_url = CHAPTER_HOME\n"
    '    print("[serve] chapter: %s" % chapter_url)\n'
    '    logger.info("chapter sync complete")\n'
    "    return [\n"
    '        metric("b-chapter", chapter_url, "as author"),\n'
    '        card("chapter-card", "root"),\n'
    '        text("plant-t", chapter_label),\n'
    '        heading("plant-p", 2, "Orrery speaks the NANDA Chapter Protocol"),\n'
    "    ]",
    'PLANT_N2 = {"type": "function", "function": {"name": "search_chapter",\n'
    '    "description": "Search for members in the chapter.", "parameters": {}}}',
    'PLANT_N3 = {"title": "t", "description": "d",\n'
    '    "fields": [{"key": "chapter_url", "label": "Org URL"}]}',
    "def _plant_n4():\n    console.print('The word \"chapter\" is never user-facing.')",
)


def prove_code_both_ways() -> int:
    """Same proof as the prose plant, for the three code classes: plant a
    user-facing string of each kind and require each named at its line; plant
    every legitimate in-code form and require silence. Restores the file."""
    target = Path(PLANT_CODE_TARGET)
    original = target.read_text(encoding="utf-8")
    helpers = derive_text_parameters(Path(HELPER_MODULE).read_text(encoding="utf-8"))

    def scan_target() -> list[tuple[str, int, str]]:
        return [
            f
            for f in scan_code(tracked_files(CODE_SUFFIXES), helpers)
            if f[0] == PLANT_CODE_TARGET
        ]

    preexisting = scan_target()
    if preexisting:
        # Name them here rather than deferring to the scan. `--prove` runs BEFORE
        # the scan in the CI step, and the step is `set -e`, so a message saying
        # "the scan reports them" describes output that never gets produced.
        print(
            f"PLANT PROOF CANNOT RUN: {PLANT_CODE_TARGET} already reports "
            f"{len(preexisting)} finding(s) before anything is planted, so silence "
            "cannot be asserted against it. Fix these first:",
            file=sys.stderr,
        )
        for name, line, context in preexisting:
            print(f"  {name}:{line}  {context}", file=sys.stderr)
        print("", file=sys.stderr)
        print(f"  {CODE_REASON}", file=sys.stderr)
        return 1

    failures: list[str] = []
    try:
        # ── Direction 1: each planted class must FIRE, at its own line ──
        body = original
        for positive in PLANT_CODE_POSITIVES:
            body += "\n\n" + positive + "\n"
        # The literal is not always on the plant's first line, so locate the line
        # that actually carries the word rather than assuming the block start.
        expected: list[int] = []
        for positive in PLANT_CODE_POSITIVES:
            offset = body.index(positive)
            within = next(
                i
                for i, ln in enumerate(positive.split("\n"))
                if BARE_WORD_RE.search(ln)
            )
            expected.append(body.count("\n", 0, offset) + 1 + within)
        target.write_text(body, encoding="utf-8")
        caught = {line for _, line, _ in scan_target()}
        for positive, line in zip(PLANT_CODE_POSITIVES, expected):
            if line not in caught:
                failures.append(
                    f"  planted at line {line} and the gate did not name it: "
                    f"{positive.splitlines()[-1].strip()!r} (caught {sorted(caught)})"
                )

        # ── Direction 2: every legitimate form must stay SILENT ──
        target.write_text(
            original + "\n\n" + "\n\n".join(PLANT_CODE_NEGATIVES) + "\n",
            encoding="utf-8",
        )
        for name, line, context in scan_target():
            failures.append(
                f"  fired on a legitimate in-code form at {name}:{line}  {context}"
            )
    finally:
        target.write_text(original, encoding="utf-8")

    if failures:
        print("CODE PLANT PROOF FAILED:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(
        f"OK: code plant proof — {len(PLANT_CODE_POSITIVES)} user-facing strings planted in "
        f"{PLANT_CODE_TARGET} (one per class) were each caught at their line, and "
        f"{len(PLANT_CODE_NEGATIVES)} legitimate in-code forms planted beside them were not"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refuse prose, and strings shown to a human, that call an org a chapter."
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove both rules still fire on drift AND still leave wire ids, identifiers, "
        "comments and log lines alone, then exit",
    )
    parser.add_argument(
        "--prove",
        action="store_true",
        help="plant drift AND the legitimate forms in a real tracked prose file and a "
        "real tracked module, and require the gate to catch the drift and ignore the rest",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.prove:
        return prove_both_ways() or prove_code_both_ways()

    files = tracked_files()
    if len(files) < 20:
        print(
            f"REFUSING: only {len(files)} prose files enumerated, which is too few to be this tree — "
            "`git ls-files` is not reaching it and a clean result here would mean nothing.",
            file=sys.stderr,
        )
        return 1

    code = tracked_files(CODE_SUFFIXES)
    if len(code) < 20:
        print(
            f"REFUSING: only {len(code)} code files enumerated, which is too few to be this "
            "tree — `git ls-files` is not reaching it and a clean result here would mean "
            "nothing.",
            file=sys.stderr,
        )
        return 1

    helpers = derive_text_parameters(Path(HELPER_MODULE).read_text(encoding="utf-8"))

    findings = scan(files)
    code_findings = scan_code(code, helpers)
    failed = False

    if findings:
        print(
            f"::error::{len(findings)} occurrence(s) of the retired product noun in prose:",
            file=sys.stderr,
        )
        for name, line, context in findings:
            print(f"  {name}:{line}  {context}", file=sys.stderr)
        print("", file=sys.stderr)
        print(f"  {REASON}", file=sys.stderr)
        failed = True

    if code_findings:
        print(
            f"::error::{len(code_findings)} occurrence(s) of the retired product noun in "
            "strings shown to a human:",
            file=sys.stderr,
        )
        for name, line, context in code_findings:
            print(f"  {name}:{line}  {context}", file=sys.stderr)
        print("", file=sys.stderr)
        print(f"  {CODE_REASON}", file=sys.stderr)
        failed = True

    if failed:
        return 1

    print(
        f"OK: no retired product vocabulary in the prose of {len(files)} tracked files, "
        f"nor in the user-facing strings of {len(code)} code files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
