"""No internal references in a repository strangers will read.

The repo carries its own history of shorthand written when nobody outside could
see it: task IDs from a private tracker cited as if they named a defect
(``the be-0641 shape``), and the handles of internal roles cited as actors
(``reported to `be```, ``the decisions orch ruled on``). Both point a reader at
something they cannot reach, and both read as a private conversation left in
public.

The same argument covers everything else that was written for an audience that
could already see the deployment, so the gate now also refuses: **live deploy
hostnames** (a public tree naming running hosts is a map to someone's
infrastructure, and scheduled CI reading it prints that map into public logs on a
timer), **absolute paths from a developer's machine**, **the private umbrella
repository by name**, **internal programme names held back from the release**,
and **credential material by shape**.

⚠️ **What this must never touch.** ``chapter`` is the PUBLIC PROTOCOL PRIMITIVE.
``chapter_id``, ``ROTATE:{chapter_id}:…``, ``/api/chapter/*``, the ``chapter`` /
``chapters`` response keys and the did:key derivation are FROZEN WIRE
IDENTIFIERS shared with every deployed peer. Renaming one would not redact a
secret; it would break the protocol for everyone already running it. The tree
holds ~1700 uses of ``chapter_id`` alone. The self-test asserts these as
must-NOT-match cases so that tightening a pattern into the wire fails loudly
here instead of in production.

**Why this is a gate and not another sweep.** It was already swept once — the
go-public checklist records the sweep as done, naming the exact two prefixes — and
at the time of writing this module the tree carried **45 such references across 25
files**. A one-time sweep removes the instances that existed; nothing stopped the
next author adding more, because nothing was watching. A checklist item that has
to be re-run by hand to stay true is not a guard, and marking it done made it
invisible.

Design notes, because a hygiene scanner is easy to write in a way that quietly
stops covering things:

* **The file set is derived, never listed.** ``git ls-files`` is the input, so a
  new file is covered the moment it is tracked. A scanner with a hand-maintained
  list of places to look goes stale in exactly the direction that reports green.
* **The whole file is scanned.** No line ranges, no "below this marker", nothing
  positional — a scanner whose coverage depends on where the next author appends
  is not a guard either.
* **It is proven to detect.** ``--self-test`` runs the patterns against strings
  that must match and strings that must not, and fails if detection has broken.
  The CI job runs the self-test before the scan, so a scanner that has stopped
  matching cannot report a clean tree.

Run locally:

    python scripts/internal_reference_gate.py            # scan the tree
    python scripts/internal_reference_gate.py --self-test # prove it still detects
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

#: Prefixes of task IDs from the private tracker.
TASK_PREFIXES = ("be", "fe", "oss", "orch", "docs", "qa", "dev")

#: Role handles unambiguous enough to flag on their own, even bare in backticks.
#: ``docs`` and ``dev`` are NOT here and must not be: ``\`dev\``` is the value of
#: ``ORRERY_PROFILE`` and ``\`docs\``` is a directory, so flagging them bare would
#: block correct prose — and a gate that blocks correct prose gets deleted rather
#: than obeyed, which costs more than the references it catches.
ROLE_HANDLES = ("be", "fe", "oss", "orch", "qa")

#: Handles that are only a role reference when something in the sentence makes them
#: an ACTOR. ``dev`` earns its place here: the tree carried ``\`dev\` measured that…``
#: and ``\`dev\`'s slice`` while also using ``\`dev\``` correctly as a config value
#: four lines from it, and the first hand sweep caught neither.
AMBIGUOUS_HANDLES = ("be", "fe", "oss", "orch", "qa", "dev")

#: Nouns that make a possessive handle a claim about who owns work.
OWNED_NOUNS = ("harness", "suite", "slice", "narrowing", "conformance", "run", "call")

#: Verbs that turn a handle into an actor.
ACTOR_VERBS = (
    "measured",
    "found",
    "ruled",
    "gated",
    "reported",
    "caught",
    "filed",
    "narrowed",
    "asked",
)

# ── The classes added when the sweep was widened past task IDs ───────────────
#
# Same reasoning as the module docstring: each of these was a hand sweep once,
# and a hand sweep only removes the instances that existed on the day. Every one
# below is anchored on a SHAPE that is specific to the thing being withheld, and
# every one has a must-NOT-match case in the self-test, because the cost of a
# pattern that also blocks correct prose is that the gate gets deleted.

#: Deploy-target hostnames: a name under Railway's `*.up.railway.app` deploy
#: domain is a RUNNING SERVICE, and a 20-character `*.supabase.co` subdomain is a
#: real project ref (that is Supabase's project-id format).
#:
#: Deliberately NOT matched — the platform's generic vocabulary, which is
#: identical in every deployment and reveals nothing: ``railway up``,
#: ``RAILWAY_PUBLIC_DOMAIN``, ``db.railway.internal`` (Railway's in-container DNS
#: name for the database, the same string for every user), and short obviously
#: fake hosts like ``fake.supabase.co``.
DEPLOY_TARGET_RE = re.compile(
    r"\b[a-z0-9][a-z0-9-]*\.up\.railway\.app\b|\b[a-z]{20}\.supabase\.co\b"
)

#: A path that only exists on one person's machine. Names the developer, and in
#: a public tree tells a reader to create a directory that means nothing to them.
#:
#: The user segment must contain a LETTER OR DIGIT, which is what separates a
#: real home directory from an anonymised placeholder. Found by running this:
#: ``profile.py`` documents ``"photo_path": "/home/.../avatar.png"``, already
#: redacted by its author. Flagging that is flagging correct prose — the failure
#: this module's docstring says gets the gate deleted — so ``...`` is excluded by
#: shape rather than by adding the file to a skip list.
LOCAL_PATH_RE = re.compile(
    r"(?<![\w$])/(?:home|Users)/[._-]*[A-Za-z0-9][A-Za-z0-9._-]*/"
    r"|\bC:\\Users\\[._-]*[A-Za-z0-9][A-Za-z0-9._-]*"
)

#: The private umbrella repository BY NAME. ``Nanda_Chapter_Protocol@<sha>`` and
#: ``Nanda_Chapter_Protocol:vectors/…`` read as git refs into a repo the reader
#: cannot open.
#:
#: ⚠️ The separator class is ``[_-]`` and NOT ``\s``, on purpose: **NANDA Chapter
#: Protocol** with spaces is the PUBLIC protocol name and must keep working in
#: prose. Only the repo-identifier spelling is withheld. Provenance survives the
#: rewrite — the commit SHA and the corpus digest are what make a mirror
#: checkable, not the repository's private name.
INTERNAL_REPO_RE = re.compile(r"\bNanda[_-]Chapter[_-]Protocol\b", re.IGNORECASE)

#: Programs deliberately withheld from the public release. Named here rather
#: than described, because the whole point is that these exact names do not ship.
INTERNAL_PROGRAM_RE = re.compile(
    r"\bmemory[- ]integrity\b|\bprovable forgetting\b|\bdissociation receipts?\b",
    re.IGNORECASE,
)

#: Tracker cross-references — ``#476``, ``orrery#493``, ``sm-federation#8``.
#:
#: WHY THESE CANNOT STAY. This repository is published as a NEW repository with
#: its own numbering, so every one of these is a DANGLING POINTER: ``#476``
#: resolves to an unrelated issue or to nothing. That is worse than deleting it,
#: because a wrong pointer still reads as evidence. Two of the repositories that
#: were cited as if public — measured with ``gh repo view``, not assumed from the
#: name — are in fact PRIVATE, so those references never resolved for anyone
#: outside in the first place.
#:
#: The disposition is one of three, never a fourth: rewrite the meaning as prose,
#: keep it only as a fully resolvable URL to a repository measured public, or
#: delete it where it carries nothing a stranger can use.
#:
#: ⚠️ MUST NOT MATCH — all four were found by running this over the real tree,
#: and each would be a false positive that gets the gate deleted rather than
#: obeyed:
#:   * ``federation/0.1#4`` — an sm-federation PROTOCOL CAPABILITY TOKEN. It is
#:     on the wire and derived by ``build_node_descriptor``; rewriting it would
#:     break federation, not tidy a document.
#:   * ``PRODUCT.md#6-naming`` — a markdown ANCHOR into a document in this repo.
#:   * ``spec/0.6/protocol.md#85-peer-chapter-key-rotation`` — a SPEC anchor, and
#:     it lives in a digest-pinned mirrored corpus where any edit breaks the
#:     conformance digest by design.
#:   * ``&#60;`` — an HTML numeric character entity, not a reference at all.
CROSS_REPO_REF_RE = re.compile(r"(?<![A-Za-z0-9_.\-/])[a-z][a-z0-9-]*#\d{1,4}\b")
TRACKER_REF_RE = re.compile(r"(?<![A-Za-z0-9_&.\-/])#\d{2,4}\b(?!;)")

#: Credential and key MATERIAL, by shape. Deliberately narrow, high-confidence
#: shapes only — gitleaks (`.gitleaks.toml`, the `secret scan` job) is the
#: primary control here and does entropy analysis this must not duplicate badly.
#: What this adds is that it runs on the same tracked-file sweep as the rest of
#: the classes, so the checklist has one gate rather than two half-covered ones.
#:
#: The PEM alternative requires the ``-----`` delimiters. That is what separates
#: real key material from the MARKER STRINGS the code legitimately matches on
#: (``_ENCRYPTED_PEM_MARKER = "BEGIN ENCRYPTED PRIVATE KEY"``), which are how
#: the keystore detects an encrypted key and must not be flagged.
CREDENTIAL_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\bsk-[A-Za-z0-9]{20,}"
    r"|\bsk_live_[A-Za-z0-9]{10,}"
    r"|\bghp_[A-Za-z0-9]{20,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\."
)

#: Binary and vendored paths where a match is meaningless, plus this file, which
#: necessarily contains the patterns it searches for. Everything else is scanned;
#: this is not a place to add a file that trips the gate.
SKIP_DIRS = ("node_modules/", "__pycache__/", ".venv/")
SKIP_SUFFIXES = (
    ".lock",
    ".png",
    ".webp",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".woff",
    ".woff2",
)
SELF = "scripts/internal_reference_gate.py"

_TASKS = "|".join(TASK_PREFIXES)
_ROLES = "|".join(ROLE_HANDLES)
_AMBIG = "|".join(AMBIGUOUS_HANDLES)
_VERBS = "|".join(ACTOR_VERBS)
_NOUNS = "|".join(OWNED_NOUNS)

PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "task-id",
        re.compile(rf"\b(?:{_TASKS})-\d{{3,4}}\b"),
        "a task ID from a tracker no reader can open. Say what the defect WAS: "
        "'empty is not configured-with-nothing', not 'the be-0641 shape'.",
    ),
    (
        "handle-as-actor",
        re.compile(
            rf"`(?:{_ROLES})`(?:'s)?"
            rf"|`(?:{_AMBIG})`(?:'s\s+(?:{_NOUNS})|\s+(?:{_VERBS}))\b"
            rf"|\b(?:{_AMBIG})'s\s+(?:{_NOUNS})\b"
        ),
        "an internal role handle cited as an actor. Name what did the work "
        "('the federation conformance suite'), not who was assigned it.",
    ),
    (
        "coordination-channel",
        re.compile(r"\bvia coord\b|\bcoord (?:board|reply|inbox)\b"),
        "the private coordination channel. Describe the action ('filed against "
        "the server'), not the mechanism used to route it.",
    ),
    (
        "deploy-target",
        DEPLOY_TARGET_RE,
        "a live deployment hostname. A public tree that names running hosts is "
        "a map to someone's infrastructure, and scheduled CI reading it prints "
        "that map into public logs on a timer. Make it configuration (an unset "
        "variable must SKIP, not fall back), and give tests fixture hostnames "
        "on a reserved-for-documentation domain.",
    ),
    (
        "local-path",
        LOCAL_PATH_RE,
        "an absolute path from one developer's machine. Name it relative to the "
        "repository root, or take it as an argument.",
    ),
    (
        "internal-repo",
        INTERNAL_REPO_RE,
        "the private umbrella repository by name — a git ref a reader cannot "
        "resolve. Say 'the NANDA Chapter Protocol umbrella' (the public protocol "
        "name) and keep the commit SHA and corpus digest, which are what make "
        "the provenance checkable.",
    ),
    (
        "internal-program",
        INTERNAL_PROGRAM_RE,
        "an internal program name held back from the public release. Describe "
        "what was removed, without the internal name.",
    ),
    (
        "cross-repo-reference",
        CROSS_REPO_REF_RE,
        "a cross-repository tracker reference. It resolves to nothing — or, "
        "worse, to an unrelated issue — in a repository with its own numbering. "
        "Say what the change DID, or link a full URL to a repository you have "
        "measured public with `gh repo view <owner>/<repo> --json visibility`.",
    ),
    (
        "tracker-reference",
        TRACKER_REF_RE,
        "a bare tracker reference. This tree is published as a new repository, "
        "so the number points at nothing a reader can open. Rewrite it as what "
        "was fixed — that is what makes the docs self-explanatory rather than "
        "merely legal.",
    ),
    (
        "credential-material",
        CREDENTIAL_RE,
        "credential or key material. Rotate it first — it is compromised the "
        "moment it is committed — then remove it and load it from the "
        "environment.",
    ),
)


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    return [
        f
        for f in out.split("\n")
        if f
        and f != SELF
        and not f.endswith(SELF)
        and not any(d in f for d in SKIP_DIRS)
        and not f.lower().endswith(SKIP_SUFFIXES)
    ]


def scan(files: list[str]) -> list[tuple[str, int, str, str]]:
    findings: list[tuple[str, int, str, str]] = []
    for name in files:
        try:
            text = Path(name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary or gone; nothing a reader will read as prose
        for label, pattern, _ in PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append((name, line, label, match.group(0)))
    return findings


#: (text, expected-labels). The negatives matter as much as the positives: a
#: pattern that matched ordinary prose would be reverted by whoever it blocked,
#: and the gate would come off with it.
SELF_TEST_CASES: tuple[tuple[str, set[str]], ...] = (
    ("FAIL CLOSED (the " + "be-0641" + " shape)", {"task-id"}),
    ("closed in " + "oss-0855" + "'s limit (a)", {"task-id"}),
    ("Agent-side generation is " + "`dev`" + "'s slice", {"handle-as-actor"}),
    (
        "⚠️ " + "`dev`" + " measured that a keyless install busy-loops",
        {"handle-as-actor"},
    ),
    ("reported to " + "`be`" + ", not edited", {"handle-as-actor"}),
    ("posted to the server " + "via coord", {"coordination-channel"}),
    ("Divergence detection is " + "oss's suite" + " to run", {"handle-as-actor"}),
    # Must NOT match: ordinary prose, this project's own PR refs, package pins,
    # versions, and hyphenated identifiers that merely end in a handle name.
    ("the member-directory closure closed anonymous member enumeration", set()),
    ("pinned sm-federation==0.6.1 and sm-arp 0.3.2", set()),
    ("the docs describe what a stranger can verify", set()),
    ("see `docs` for the directory layout", set()),
    ("Safe by default; set `dev` for local ergonomics", set()),
    ("set to `dev` ONLY for local work", set()),
    ("this cannot be-cause it would break", set()),
    ("coordinates are ISO 6709", set()),
    ("did:key:z6MktKxCXMenDrkAwtDXFze8E3pKJVY8FrwNyL9e8D1bk8Be", set()),
    # ── deploy targets ──────────────────────────────────────────────────────
    # Invented service labels, never real ones. The case proves the SHAPE
    # `<label>.up.railway.app` is matched; using an actual deployment's name
    # would publish the hostname in the one file the scan skips (SELF), which
    # is the exact thing this pattern exists to prevent.
    ("https://svc-production-0000" + ".up.railway.app/x", {"deploy-target"}),
    ("example-agent-production" + ".up.railway.app", {"deploy-target"}),
    ("https://" + "abcdefghijklmnopqrst" + ".supabase.co", {"deploy-target"}),
    # …and the platform vocabulary that is the same for everyone, so says nothing
    ("railway up -s <service> -p <projectId> --ci", set()),
    ("os.environ.get('RAILWAY_PUBLIC_DOMAIN')", set()),
    ("postgres://u:p@db.railway.internal:5432/railway", set()),
    ("SUPABASE_URL = 'https://fake.supabase.co'", set()),
    ("insert into supabase.arp_receipts values (…)", set()),
    ("fixture host test-chapter.example.com is not a deployment", set()),
    # ── local paths ─────────────────────────────────────────────────────────
    ("cd " + "/home/somedev/" + "orrery && make ci-local", {"local-path"}),
    ("/Users/somedev/" + "src/orrery", {"local-path"}),
    ("$HOME/.orrery/keys is created on first run", set()),
    ("~/.config/orrery holds the profile", set()),
    ("installed to /usr/local/bin/orrery", set()),
    ("WORKDIR /app  # the container root", set()),
    # An author who already redacted the path is not leaking one.
    ('"photo_path": "/home/.../avatar.png"', set()),
    ("copy it to /home/<user>/.orrery/", set()),
    # ── the private umbrella, and the PUBLIC protocol name it must not eat ──
    ("pinned to " + "Nanda_Chapter_Protocol" + "@60cc22d", {"internal-repo"}),
    ("re-copy from " + "Nanda_Chapter_Protocol" + ":vectors/rotation/v06/", {"internal-repo"}),
    ("specified as NANDA Chapter Protocol v0.6 §8.5", set()),
    ("the NANDA Chapter Protocol umbrella ships the corpus", set()),
    ("the member-directory closure and the sm-federation protocol notes both resolve for a stranger", set()),
    ("pip install sm-arp==0.3.2 sm-divergence", set()),
    # ── internal programs ───────────────────────────────────────────────────
    ("Removed: " + "Memory-integrity" + " moat", {"internal-program"}),
    ("the " + "provable forgetting" + " routes were never shipped", {"internal-program"}),
    ("emits a " + "dissociation receipt" + " per member", {"internal-program"}),
    ("the agent memory store is compacted nightly", set()),
    ("GET /.well-known/receipt-disclosure/sample.json", set()),
    ("supabase.arp_receipts holds the receipt rows", set()),
    # ── credential material, and the marker strings that are not material ───
    ("-----BEGIN " + "OPENSSH PRIVATE KEY-----", {"credential-material"}),
    ("token = '" + "ghp_" + "A" * 30 + "'", {"credential-material"}),
    ("aws_key = '" + "AKIA" + "ABCDEFGHIJKLMNOP" + "'", {"credential-material"}),
    ("key = '" + "sk-" + "B" * 32 + "'", {"credential-material"}),
    ("jwt = '" + "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "yb2xlIjoiYW5vbiJ9" + ".sig'", {"credential-material"}),
    # The keystore's own detection markers — no `-----`, so not key material.
    ('_ENCRYPTED_PEM_MARKER = "BEGIN ENCRYPTED PRIVATE KEY"', set()),
    ('assert "BEGIN PRIVATE KEY" in stored["private_key_pem"]', set()),
    ("POSTGRES_PASSWORD=orrery-dev-password-change-me", set()),
    # ══════════════════════════════════════════════════════════════════════
    # FROZEN WIRE IDENTIFIERS — must NEVER match, at any tightening.
    #
    # `chapter` is the PUBLIC PROTOCOL PRIMITIVE, not an internal leak. These
    # strings are on the wire between deployed peers and in the did:key
    # derivation: a sanitizer that renamed any of them would not redact a
    # secret, it would break the protocol for every peer already running. The
    # tree carries ~1700 uses of `chapter_id` alone, so a pattern that reached
    # them would be both catastrophic and, at that scale, easy to wave through.
    # Asserted here so a future author tightening a pattern gets a red self-test
    # instead of a silent wire break.
    # ══════════════════════════════════════════════════════════════════════
    ("chapter_id is the wire identifier", set()),
    ("ROTATE:{chapter_id}:{new_did}:{timestamp}", set()),
    ("GET /api/chapter/receipts and /api/chapter/audit", set()),
    ('{"chapter": "boston", "chapters": ["boston", "london"]}', set()),
    ("did:key derivation over the chapter Ed25519 public key", set()),
    ("chapter.example.com is a documentation host", set()),
    # ── tracker cross-references ────────────────────────────────────────────
    ("closed in " + "#493" + ": the four surfaces answer 401", {"tracker-reference"}),
    ("fixed in " + "#54" + " and regression-pinned", {"tracker-reference"}),
    ("filed upstream as " + "orrery#493", {"cross-repo-reference"}),
    ("see " + "sm-federation#8" + " for why", {"cross-repo-reference"}),
    ("blocked on " + "nanda-connect#30", {"cross-repo-reference"}),
    # ══════════════════════════════════════════════════════════════════════
    # MUST NOT MATCH — every one of these was found by running the gate over
    # the real tree, and each is something a stranger genuinely needs.
    # ══════════════════════════════════════════════════════════════════════
    # A PROTOCOL CAPABILITY TOKEN. On the wire, derived by build_node_descriptor.
    # Rewriting it breaks federation; it does not tidy a document.
    ("the descriptor declares federation/0.1#4 for the feed", set()),
    ("advertises listing/0.1 and federation/0.1#4 together", set()),
    # Markdown and spec ANCHORS into documents that ship in this repository.
    ("see [`PRODUCT.md` § Naming](./PRODUCT.md#6-naming)", set()),
    ('"spec": "spec/0.6/protocol.md#85-peer-chapter-key-rotation"', set()),
    ("linked as ./HARDENING.md#open-dispositions", set()),
    # HTML numeric character entities — not references at all.
    ("assert '&#60;script&#62;' not in result", set()),
    ("escaped to &#38; and &#39; before rendering", set()),
    # A full URL to a repository MEASURED public is the keep-as-URL disposition.
    ("[sm-authority issue 2](https://github.com/Sharathvc23/sm-authority/issues/2)", set()),
    # Ordinary prose and identifiers that merely contain a hash or digits.
    ("the colour is #ff0088 in the palette", set()),
    ("pinned sm-federation==0.6.1 and sm-arp 0.3.2", set()),
    ("PBKDF2_ITERATIONS = 100_000  # frozen — legacy blobs", set()),
)


def self_test() -> int:
    failures = []
    for text, expected in SELF_TEST_CASES:
        got = {label for label, pattern, _ in PATTERNS if pattern.search(text)}
        if got != expected:
            failures.append(
                f"  {text!r}\n    expected {sorted(expected) or 'no match'}, got {sorted(got) or 'none'}"
            )
    if failures:
        print(
            "SELF-TEST FAILED — the gate no longer detects what it claims:",
            file=sys.stderr,
        )
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(
        f"OK: self-test — {len(SELF_TEST_CASES)} cases, detection and non-detection both as declared"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the patterns still detect, then exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    files = tracked_files()
    if len(files) < 100:
        print(
            f"REFUSING: only {len(files)} tracked files enumerated, which is too few to be the tree — "
            "`git ls-files` is not reaching it and a clean result here would mean nothing.",
            file=sys.stderr,
        )
        return 1

    findings = scan(files)
    if findings:
        reasons = {label: reason for label, _, reason in PATTERNS}
        print(
            f"::error::{len(findings)} internal reference(s) in a repository strangers read:",
            file=sys.stderr,
        )
        for name, line, label, text in findings:
            print(f"  {name}:{line}  [{label}]  {text}", file=sys.stderr)
        print("", file=sys.stderr)
        for label in sorted({f[2] for f in findings}):
            print(f"  {label}: {reasons[label]}", file=sys.stderr)
        return 1

    print(
        f"OK: no internal task IDs, role handles, coordination references, deploy "
        f"targets, local paths, internal repo/programme names, tracker or "
        f"cross-repo references, or credential material in {len(files)} tracked files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
