"""Guards on the security policy's reporting channel.

The policy's reporting section is a routing instruction: a reader who has found
a vulnerability follows it, and every other page that mentions security sends
them to it. Prose that routes people is worth asserting mechanically, because
the failure is silent — a page can name a channel nobody reads, or two pages
can name different channels, and nothing about either page looks wrong.

The property these guards hold is a normal one for a security policy to
guarantee: **the policy always offers at least one reporting channel that is
not hosted on the code forge**, so a reporter always has a route, and every
document that mentions security reporting names it. Email is that channel here,
and it is the primary route; GitHub's private vulnerability reporting is named
alongside it as a second way in.

Four guards:

``test_security_md_names_the_email_channel_as_its_primary_route``
    The policy names the email channel, using the address the Code of Conduct
    publishes and no other, with the subject tag, ahead of any code-forge
    route.

``test_no_document_gives_a_code_forge_route_as_its_only_security_instruction``
    Over ``git ls-files``: any page that points a reporter at the forge names
    the email channel too. The file set is derived, never listed here — the
    four repository gates take their input the same way, because a hand-list
    goes stale in the direction that reports green and the next page to add a
    forge-only instruction would land unseen.

``test_code_of_conduct_redirect_names_the_channel_security_md_documents``
    The Code of Conduct sends security reporters somewhere; that has to be a
    channel the security policy actually documents. Two pages agreeing is
    exactly the kind of thing nobody re-checks, so it is asserted rather than
    assumed.

``test_no_security_policy_states_a_response_time_commitment``
    No security policy in the tree promises a reply within a fixed time. A
    promise like that is easy to re-add in a single sentence and impossible to
    keep by accident.

Run locally::

    python3 -m pytest tests/test_security_reporting_channel.py -v
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# This module quotes the strings it refuses, so it would report itself.
# Self-exclusion is by identity, not by a list of documents to skip — every
# other tracked file stays in scope by construction.
SELF = Path(__file__).resolve().relative_to(REPO).as_posix()

# An address, deliberately not written down here. Every assertion below reads
# the address out of CODE_OF_CONDUCT.md, so a guard that still passed after the
# address changed would be comparing a stale copy rather than the repository.
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# The forge route, matched as a ROUTE rather than as a turn of phrase: the
# advisory URL path, and the navigation instruction that leads to it. "Report a
# vulnerability" on its own is ordinary English and appears in prose pointing
# somewhere else entirely.
# ``\s+`` between every word, not a literal space: this prose is hard-wrapped,
# so the instruction is routinely split across two lines. A matcher that only
# recognised the unwrapped form would report clean on the exact page it is
# pointed at, which is the way a guard fails without anyone noticing.
FORGE_ROUTE_RE = re.compile(
    r"security/advisories"
    r"|Security\s*(?:tab|>|->|→|–|—)\s*[\"'“]?\s*Report\s+a\s+vulnerability"
    r"|GitHub\s*(?:>|->|→)\s*Security",
    re.IGNORECASE,
)

# "we will get back to you inside N hours/days" in the shapes a policy writes it.
RESPONSE_TIME_RE = re.compile(
    r"(?:acknowledge\w*|respond\w*|response|reply|replies|triage\w*)"
    r"[^.\n]{0,40}?within\s+\d+\s*(?:hour|day|week|business)",
    re.IGNORECASE,
)

TEXT_SUFFIXES = {
    ".md",
    ".markdown",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".cfg",
    ".ini",
    ".py",
    ".sh",
    ".mjs",
    ".js",
    ".ts",
    ".html",
    ".css",
    ".sql",
}


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    names = [n for n in out.split("\0") if n]
    assert names, "git ls-files returned nothing — these guards would pass vacuously"
    return names


def _tracked_text_files() -> list[Path]:
    paths = []
    for name in _tracked():
        if name == SELF:
            continue
        path = REPO / name
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name != "Dockerfile":
            continue
        paths.append(path)
    return paths


def _security_policies() -> list[Path]:
    """Every security policy in the tree, found by name rather than listed."""
    paths = [
        REPO / n
        for n in _tracked()
        if Path(n).name.lower() == "security.md" and n != SELF
    ]
    assert paths, "no security policy found — this guard would pass vacuously"
    return paths


def _coc_reporting_address() -> str:
    text = (REPO / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    found = EMAIL_RE.findall(text)
    assert found, "CODE_OF_CONDUCT.md publishes no address to compare against"
    return found[0]


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def test_security_md_names_the_email_channel_as_its_primary_route() -> None:
    """G1: the policy leads with the email channel."""
    text = (REPO / "SECURITY.md").read_text(encoding="utf-8")
    address = _coc_reporting_address()

    email_at = text.find(address)
    assert email_at != -1, (
        "SECURITY.md names no email reporting channel. The policy must offer a "
        "route that is not hosted on the code forge, and the address "
        f"{address!r} is the one this project publishes."
    )

    other = [a for a in EMAIL_RE.findall(text) if a != address]
    assert not other, (
        "SECURITY.md names an address other than the one this project publishes "
        f"in CODE_OF_CONDUCT.md: {sorted(set(other))}. A second address is a "
        "second inbox to keep alive, and an alias nobody reads is a channel in "
        "name only."
    )

    assert "[security]" in text, (
        "SECURITY.md names no subject tag. CODE_OF_CONDUCT.md and "
        "skill/SECURITY.md both carry one, and the tag is what keeps a report "
        "out of ordinary mail."
    )

    forge = FORGE_ROUTE_RE.search(text)
    if forge is not None:
        assert email_at < forge.start(), (
            f"SECURITY.md names the code-forge route on line "
            f"{_line_of(text, forge.start())}, ahead of the email channel on "
            f"line {_line_of(text, email_at)}. Email is the primary route; the "
            f"forge route is named alongside it, not in front of it."
        )


def test_no_document_gives_a_code_forge_route_as_its_only_security_instruction() -> None:
    """G2: every page that points at the forge names the email channel too."""
    address = _coc_reporting_address()
    offenders: list[str] = []

    for path in _tracked_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        forge = FORGE_ROUTE_RE.search(text)
        if forge is None:
            continue
        if address in text:
            continue
        rel = path.relative_to(REPO).as_posix()
        offenders.append(
            f"{rel}:{_line_of(text, forge.start())} sends a security reporter to "
            f"the code forge and names no other channel. Every page that routes a "
            f"reporter must also name the email channel, so the policy always "
            f"offers a route that is not hosted on the forge."
        )

    assert not offenders, "\n".join(offenders)


def test_code_of_conduct_redirect_names_the_channel_security_md_documents() -> None:
    """G3: the sign and the destination name the same channel."""
    coc = (REPO / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    security = (REPO / "SECURITY.md").read_text(encoding="utf-8")

    paragraphs = [p for p in coc.split("\n\n") if "ecurity vulnerabilit" in p]
    assert paragraphs, (
        "CODE_OF_CONDUCT.md no longer redirects security reporters anywhere. It "
        "must, or a reporter who starts there is left with the conduct address "
        "and the wrong subject tag."
    )
    redirect = "\n".join(paragraphs)

    tags = set(re.findall(r"\[[a-z][a-z-]*\]", redirect))
    tags.discard("[code-of-conduct]")
    assert tags, (
        "the Code of Conduct's security redirect names no subject tag, so it "
        f"describes no channel SECURITY.md could be checked against. Redirect "
        f"text: {redirect!r}"
    )
    for tag in sorted(tags):
        assert tag in security, (
            f"CODE_OF_CONDUCT.md tells a security reporter to use {tag}, and "
            f"SECURITY.md documents no such tag. The two pages name different "
            f"channels."
        )

    address = _coc_reporting_address()
    assert address in security, (
        "the Code of Conduct redirects security reporters to the same address it "
        f"publishes ({address}), and SECURITY.md does not name it."
    )


def test_no_security_policy_states_a_response_time_commitment() -> None:
    """G4: no policy promises a reply inside a fixed window."""
    offenders: list[str] = []
    for path in _security_policies():
        text = path.read_text(encoding="utf-8")
        for match in RESPONSE_TIME_RE.finditer(text):
            rel = path.relative_to(REPO).as_posix()
            offenders.append(
                f"{rel}:{_line_of(text, match.start())} promises a response time "
                f"({match.group(0)!r}). The policies in this tree state their "
                f"channel and do not commit to a turnaround."
            )
    assert not offenders, "\n".join(offenders)


if __name__ == "__main__":  # pragma: no cover - convenience
    raise SystemExit(pytest.main([__file__, "-v"]))
