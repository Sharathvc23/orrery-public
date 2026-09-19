# Contributing to Orrery

Start with the [docs map](docs/README.md): [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the five deployables and the protocols between them,
[`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md) for what a signature does and does
not prove, [`docs/CLAIMS.md`](docs/CLAIMS.md) for what is live with its
evidence, and [`docs/ROADMAP.md`](docs/ROADMAP.md) for what is wanted next —
roadmap items are the highest-leverage contributions.

## The workflow

1. **Branch, then pull request.** `main` takes no direct pushes. One slice per
   PR where possible; a PR that fixes a defect carries the regression test that
   fails on the pre-fix code.
2. **Squash-merge.** The PR title becomes the commit subject on `main`, so
   write it as what changed and why, in the conventional `type(scope): …` form.
3. **One required check: `ci gate`.** It is an aggregate, not a test: every
   job it depends on must succeed or be skipped. Jobs are path-filtered, so a
   docs-only PR runs the doc guards and the prose gates and skips the heavy
   suites honestly; a change that touches a runtime runs that runtime's suite,
   the conformance jobs, the Compose e2e boot, and the installer drill. The
   dependency CVE scan and the secret scan run on every PR.
4. **No review is required** — this is a solo-maintainer repository and the
   mechanical gate is the control. That is why the gate has to be able to go
   red; see *Proving a guard* below.
5. **Record the change as a changelog fragment, not in `CHANGELOG.md`.** Add
   `changelog.d/<slug>.md`: first line a `### ` heading, then the entry as it
   should read in the changelog. Do not write under `## [Unreleased]` — every
   PR used to prepend there, so any two open PRs conflicted, and resolving
   those conflicts by merging `main` into a branch is how one squash reverted
   four merged PRs. `tests/test_changelog_fragments.py` fails, naming the
   entry, if [Unreleased] is hand-edited. `python3 scripts/changelog_assemble.py
   --preview` renders the pending entries; at release,
   `--release X.Y.Z` writes the section (newest first) and removes the
   fragments. **Bring a branch up to date by rebasing onto `main`, not by
   merging `main` in**: on a squash-merge repository a merge commit whose
   conflict resolution touched other files becomes a silent reversal of them.

## Ground rules

- **Vocabulary.** User-facing text says **org** / **agent**. "chapter" is the
  protocol noun and stays on the frozen wire surfaces — `chapter_id`,
  `/api/chapter/*`, the `X-Chapter-*` headers, event topics, table names, the main
  module — never in product copy or docs prose. The mapping and the frozen list:
  [`docs/ARCHITECTURE.md` § Two nouns](docs/ARCHITECTURE.md#two-nouns-for-one-thing-protocol-and-product);
  `scripts/org_vocabulary_gate.py` enforces it.
- **Frozen wire ids untouched** unless the change is a deliberate, versioned
  protocol change: event topics, `chapter_id`, the signed canonical strings,
  schema `$id`s, the badge runtime name.
- **No protocol here.** New primitives get their own `sm-*` package; Orrery
  composes them as exactly pinned upstream dependencies
  ([`docs/integrations/STELLARMINDS.md`](docs/integrations/STELLARMINDS.md)) —
  never fork or vendor-patch an `sm-*` library.
- **Layering.** The deterministic shell is the floor; generative surfaces are the
  opt-in ceiling. A change that makes generative UI *required* to run is out of scope.
- **No secrets in git.** `.env` is ignored; only `.env.example` is tracked. The
  secret scan runs on every PR over the new commits, and a full-history baseline
  is kept in `scripts/full_history_secret_baseline.txt`.
- **Docs stay honest.** A capability claim in the docs must match merged code,
  and a command in `README.md` or `docs/QUICKSTART.md` must be one that was
  driven — `tests/test_readme_commands_driven.py` refuses one that was not.
  `docs/CLAIMS.md` is updated when a claim moves.

## The four prose gates

They run in the `supply-chain-pins` job on every PR, over every file
`git ls-files` reports, each with a self-test that runs first and gates the
scan:

| Gate | Refuses |
|---|---|
| `scripts/internal_reference_gate.py` | a reference a reader cannot resolve — a task id, a role handle, a bare tracker number, a private hostname or path |
| `scripts/claims_language_gate.py` | a claim whose subject does not exist — an aspiration stated as running infrastructure |
| `scripts/conflict_marker_gate.py` | a committed merge-conflict marker |
| `scripts/org_vocabulary_gate.py` | prose, or a string shown to a human, calling a thing by a name the software does not use |

Run them locally from the repository root, self-test first:

```bash
python3 scripts/internal_reference_gate.py --self-test && python3 scripts/internal_reference_gate.py
python3 scripts/claims_language_gate.py --self-test && python3 scripts/claims_language_gate.py
python3 scripts/conflict_marker_gate.py --self-test && python3 scripts/conflict_marker_gate.py
python3 scripts/org_vocabulary_gate.py --self-test && python3 scripts/org_vocabulary_gate.py --prove && python3 scripts/org_vocabulary_gate.py
```

They read `git ls-files`, so **stage a new file before running them** — an
unstaged file is not scanned and the run reports a clean tree having read
nothing. If a gate fires on text you believe is correct, narrow the pattern by
shape rather than adding a skip-list entry; the procedure, and what the gates
deliberately cannot check, are in [`docs/GATES.md`](docs/GATES.md). The audit
ledger has its own gate, `scripts/audit_gate.py`, which refuses a finding
marked fixed without evidence and a finding named in prose that the ledger does
not carry.

## Proving a guard

A check that reports nothing wrong is indistinguishable from a check that
looked at nothing; both are green. So every guard added here is **planted**
before it is trusted: put the defect it exists to catch into the tree, run the
guard, watch it go red *by name*, revert, and confirm the tree is clean. State
the plant and its result in the PR. Two plants are always worth running:

- **The defect itself**, in the shape it would really arrive — a stale
  sentence hard-wrapped across a line break, a test renamed in the tree rather
  than in the document, a route re-declared as open.
- **The correct form the guard must not flag** — a valid citation wrapped
  across a line, a legitimate identifier — so the guard is shown to
  discriminate, not merely to fire.

A guard whose input is derived from the code (a route list from the app, a
header set from the signer, a file set from `git ls-files`) beats one that
carries a hand-list, because a hand-list goes stale in the direction that
reports green. And a guard that reads a document should read it
whitespace-normalized: prose here is hard-wrapped, and a phrase split across a
line break must count as present.

## Environment variables

Every environment read is classified. `server/tests/test_env_flags_convention.py`
derives the set of names the server reads from the AST and fails on any name
that is not in one of four declared classes:

| Class | Rule |
|---|---|
| `SECURITY_FLAG_REQUIRED` | a boolean security gate; read only through `env_flags.security_flag(name, default=…)`, so the direction it fails when unset is written at the call site |
| `SECURITY_RELEVANT_DEVIATION` | a boolean gate deliberately not routed through `security_flag`, with the reason |
| `SECURITY_RELEVANT_VALUE` | security-relevant and not a boolean — a credential, a trust anchor, a window, a cap |
| `NOT_SECURITY_RELEVANT` | everything else |

A new variable lands only once it is classified, and classifying it is where
someone decides whether it gates anything. Document it in
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) in the same PR; several
sections there are pinned by tests.

## Where the protocol lives

Orrery implements published protocols; it does not define them here.

- `vectors/` — the signing and rotation test vectors (`vectors/signing/`,
  `vectors/rotation/`); `schema/` — the ARP receipt and A2UI surface schemas
  by version.
- `conformance/` — the suites that run those vectors and schemas: the client
  signing conformance (`conformance/client/`, run in CI against the reference,
  the OpenClaw skill and the member SDK), the federation profile
  (`conformance/federation/`), ARP, DAT and Merkle checks.
- `docs/specs/` — the A2UI/AG-UI contract and the design notes for surfaces
  this repository adds.
- The `sm-*` packages carry their own specifications; the pins are in each
  package's `constraints.txt` and `requirements.lock`, enforced by the
  `supply-chain-pins` job.

A change to a wire format is a change to a vector or a schema first, then to
the runtimes, with the conformance jobs green — never the other way round.

## Dev loop (per Python package)

```bash
cd server   # or agent, skill, index, smb_host, smb_signup
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest -q
```

CI enforces more than the local loop: ruff + **mypy** + pytest per package,
coverage floors on the auth/crypto modules, exact supply-chain pins, base
images by digest, and a `docker compose` e2e job that boots the full stack and
probes the advertised surfaces. Run `./orrery-up` for a full local stack when
your change touches a served surface.

## Reviewing a check, a reader, or a control

No gate catches what follows, and none can. Ask these of any change that adds
a check, renders a result, or bounds a behaviour.

**Can this check fail? What would make it red, and has anyone watched it go
red?** A check whose input is empty passes. Before relying on a check, make it
fail on purpose.

**Can this reader tell refused from absent from empty?** These are three
different facts arriving through one door. A console that renders any non-ok
response as its empty state reports a `401` from `/api/members` as an org
nobody has joined. Name the three states and render them differently
(`server/static/ui/console-boot.js` maps status to `unauthorised`, `forbidden`,
`missing` and `error`).

**Does this control observe the thing it claims to bound, or a proxy for it?**
A proxy is correct until something moves between it and the fact. The think
loop once classified outcomes by the consent gate's decision; once a sandbox
policy or a runner could refuse *after* the gate approved, a refused action
still counted as approved. `make_think_outcome` in
`agent/community_member/runtime/think_loop.py` now reads the reported outcome.
Two readers of one source diverge the same way: `find_recent_denial` reads 50
rows of the consent ledger while the surface that lists denials reads 200.

## Security findings

Go through [SECURITY.md](SECURITY.md), not a public issue or pull request.
