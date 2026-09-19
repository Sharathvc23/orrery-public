"""Jurisdiction detection + region-specific compliance defaults.

Chapters can be deployed in different regulatory contexts: a US-CA chapter
needs CCPA-aligned defaults; an EU chapter needs GDPR-style minimization;
a US federal contractor needs NIST 800-171 + DFARS minima. This module
resolves the chapter's jurisdiction from configuration and provides the
per-region defaults that other modules (retention.py, ARP jurisdiction
field, compliance.py regime mapping) consume.

Every retention override declares a **direction** — FLOOR (a statutory
minimum, applied with ``max``) or CEILING (a minimisation regime, applied
with ``min``). See ``Direction``; there is no default and an entry without
one fails at import.

Resolution order:

  1. Explicit env var ``CHAPTER_JURISDICTION`` (e.g., ``"US-CA"``,
     ``"EU"``, ``"US-FED"``). Operator override; always wins.
  2. Postgres ``chapter_policy.jurisdiction`` column for the chapter
     (set via the admin UI).
  3. Default ``"US"`` — common-baseline US protections without state-
     specific overrides.

Supported jurisdiction codes:

  US                — Generic US (no state-specific overrides)
  US-CA             — California (CCPA / CPRA)
  US-CO             — Colorado (CPA / Colorado AI Act effective 2026)
  US-VA             — Virginia (VCDPA)
  US-CT, US-UT, US-TX, US-IN
                    — Other state privacy laws
  US-FED            — Federal contractor (NIST 800-171 / DFARS / FedRAMP-track)
  US-DOD            — DoD contractor (CMMC L2/L3, DFARS 252.204-7012)
  US-HIPAA          — Healthcare-touching deployment (HIPAA)
  US-GLBA           — Financial deployment (Gramm-Leach-Bliley)
  EU                — EU-anywhere (GDPR)
  EU-DE, EU-FR, EU-IE, etc. — Country-specific EU (mostly identical to EU)
  UK                — UK GDPR (post-Brexit, similar to EU)
  CA                — Canada (PIPEDA)
  AU                — Australia (Privacy Act 1988)
  GLOBAL            — Multi-jurisdictional deployment (strictest of all)

This module is NOT a complete regulatory expert system. It provides
sane defaults; chapters operating in regulated verticals MUST consult
counsel and override the defaults to match their actual obligations.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

# ── Default jurisdiction code ──────────────────────────────────────
DEFAULT_JURISDICTION = "US"


# ── Which way an override binds ─────────────────────────────────────
class Direction(str, Enum):
    """Whether a jurisdiction's number is a MINIMUM or a MAXIMUM.

    The two regime families want opposite operators and one assignment
    cannot serve both:

      FLOOR    a statutory minimum — NIST 800-171, DFARS, HIPAA, GLBA,
               SOX. "Keep security audit logs at least 3 years." Resolved
               as ``max(module_default, declared)``: it may only LENGTHEN
               retention, never shorten it.
      CEILING  a minimisation regime — GDPR, UK GDPR, CCPA/CPRA, CPA.
               "Keep no longer than necessary." Resolved as
               ``min(module_default, declared)``: it may only SHORTEN.

    Applied as a plain assignment (``policy[table] = days``, which is what
    this table did until the floor-versus-ceiling fix), a FLOOR silently became a CEILING wherever
    the module default was already longer: ``ORG_JURISDICTION=US-FED``
    SHORTENED ``chapter_audit_events`` from 2555 days to 1095 and the
    sweeper DELETED the difference, in the name of a rule whose own comment
    called 1095 a three-year *minimum*.
    """

    FLOOR = "floor"
    CEILING = "ceiling"


FLOOR = Direction.FLOOR
CEILING = Direction.CEILING


class RetentionDirectionError(TypeError):
    """A RETENTION_OVERRIDES entry does not declare how it binds.

    Raised where the table is loaded, not where it is applied. This path
    DELETES rows, and a defaulted direction on a delete path is how an
    unreviewed deletion policy ships — so an entry that does not say
    FLOOR or CEILING is a hard error rather than a guess.
    """


@dataclass(frozen=True)
class RetentionRule:
    """One jurisdiction's retention override for one table.

    ``days`` alone is not a policy: 1095 means "at least three years" under
    DFARS and "at most three years" under GDPR, and the difference decides
    whether the sweeper deletes. ``direction`` is therefore structural and
    required — a comment saying "minimum" is exactly what was here before
    the floor-versus-ceiling fix, and it bound nothing.

    ``basis`` names the rule the direction comes from, so the next author
    changing a number can see which regime they are arguing with.
    """

    days: int
    direction: Direction
    basis: str

    def apply(self, default_days: int) -> int:
        """Resolve this rule against the module default.

        The single definition of what a direction MEANS. ``retention.py``
        calls this rather than re-deriving max/min at the call site: two
        near-identical implementations where one is subtly wrong is the
        drift this module already carries a warning about.
        """
        if self.direction is Direction.FLOOR:
            return max(default_days, self.days)
        return min(default_days, self.days)


# ── Per-jurisdiction retention overrides ────────────────────────────
# Only categories where the regime differs from the global default
# (see chapter/retention.py:DEFAULT_RETENTION_DAYS). Missing entries
# fall back to the global defaults.
#
# ⚠️ EVERY entry declares a Direction. There is no default direction — see
# RetentionDirectionError. ``validate_retention_overrides()`` runs at import
# and enumerates this table, so an entry added later without one fails at
# load rather than quietly deleting to the wrong side of a statute.
RETENTION_OVERRIDES: dict[str, dict[str, RetentionRule]] = {
    "US": {},  # baseline
    "US-CA": {
        # CCPA — businesses must retain only as long as "reasonably
        # necessary for the disclosed purpose." Aggressive minimization
        # for the most-private categories.
        "agent_intents": RetentionRule(30, CEILING, "CCPA/CPRA data minimisation"),  # was 90
        "agent_action_outcomes": RetentionRule(90, CEILING, "CCPA/CPRA data minimisation"),  # was 180
    },
    "US-CO": {
        # Colorado Privacy Act — similar minimization to CCPA, plus
        # Colorado AI Act (CAIA) heightened oversight for high-risk
        # automated decisions starting Feb 2026.
        "agent_intents": RetentionRule(30, CEILING, "Colorado Privacy Act minimisation"),
        "agent_action_outcomes": RetentionRule(90, CEILING, "Colorado Privacy Act minimisation"),
        # Trust events become impact-assessment evidence under CAIA;
        # extend retention to ensure they're available for the 2-year
        # auditor review window CAIA mandates.
        "trust_events": RetentionRule(730 * 2, FLOOR, "CAIA 2-year auditor review window"),  # was 730
    },
    "US-FED": {
        # NIST 800-171 / DFARS 252.204-7012 — 3-year minimum for
        # security audit logs. A MINIMUM: the module default of 7 years
        # already satisfies it, so declaring US-FED must not shorten
        # anything. Applied as an assignment it did exactly that.
        "chapter_audit_events": RetentionRule(3 * 365, FLOOR, "NIST 800-171 3.3.1 / DFARS 252.204-7012 3-year minimum"),
        # ARP receipts as evidence: align with DFARS retention
        # (7 years, same as default but stated explicitly).
        "arp_receipts": RetentionRule(7 * 365, FLOOR, "DFARS evidence retention"),
    },
    "US-DOD": {
        # CMMC L2/L3 — same NIST 800-171 floor PLUS CUI handling
        # implies longer audit retention (DoD audits go back 6+ years
        # for major incident review).
        "chapter_audit_events": RetentionRule(7 * 365, FLOOR, "CMMC L2/L3 incident review"),
        "arp_receipts": RetentionRule(7 * 365, FLOOR, "CMMC L2/L3 incident review"),
        # Intents and outcomes may carry CUI — shorter retention
        # reduces breach blast radius.
        "agent_intents": RetentionRule(60, CEILING, "CUI blast-radius minimisation"),
        "agent_action_outcomes": RetentionRule(90, CEILING, "CUI blast-radius minimisation"),
    },
    "US-HIPAA": {
        # HIPAA — 6-year minimum for medical records.
        "arp_receipts": RetentionRule(6 * 365, FLOOR, "HIPAA 45 CFR 164.316(b)(2)(i) 6-year minimum"),
        "chapter_audit_events": RetentionRule(6 * 365, FLOOR, "HIPAA 45 CFR 164.316(b)(2)(i) 6-year minimum"),
        # Aggressive minimization for non-essential telemetry.
        "agent_intents": RetentionRule(30, CEILING, "HIPAA minimum-necessary for non-PHI telemetry"),
        "agent_action_outcomes": RetentionRule(90, CEILING, "HIPAA minimum-necessary for non-PHI telemetry"),
    },
    "US-GLBA": {
        # GLBA / financial — 7-year SOX-aligned retention.
        "arp_receipts": RetentionRule(7 * 365, FLOOR, "SOX/GLBA 7-year records retention"),
        "chapter_audit_events": RetentionRule(7 * 365, FLOOR, "SOX/GLBA 7-year records retention"),
    },
    "EU": {
        # GDPR — data minimization principle pushes shorter defaults
        # across the board.
        "arp_receipts": RetentionRule(365, CEILING, "GDPR Art. 5(1)(e) storage limitation"),  # was 7 years
        "chapter_audit_events": RetentionRule(365, CEILING, "GDPR Art. 5(1)(e) storage limitation"),
        "agent_intents": RetentionRule(30, CEILING, "GDPR Art. 5(1)(e) storage limitation"),
        "agent_action_outcomes": RetentionRule(60, CEILING, "GDPR Art. 5(1)(e) storage limitation"),
        "trust_events": RetentionRule(365, CEILING, "GDPR Art. 5(1)(e) storage limitation"),
        "chronicles": RetentionRule(90, CEILING, "GDPR Art. 5(1)(e) storage limitation"),
    },
    "UK": {
        # UK GDPR — mirrors EU minimization.
        "arp_receipts": RetentionRule(365, CEILING, "UK GDPR storage limitation"),
        "chapter_audit_events": RetentionRule(365, CEILING, "UK GDPR storage limitation"),
        "agent_intents": RetentionRule(30, CEILING, "UK GDPR storage limitation"),
        "agent_action_outcomes": RetentionRule(60, CEILING, "UK GDPR storage limitation"),
    },
    "CA": {
        # PIPEDA — 1-year minimum for personal info access requests,
        # but no statutory upper bound. Mirror CCPA's minimization.
        "agent_intents": RetentionRule(90, CEILING, "PIPEDA Principle 4.5 — retain only as needed"),
        "agent_action_outcomes": RetentionRule(180, CEILING, "PIPEDA Principle 4.5 — retain only as needed"),
    },
    "AU": {
        # Australian Privacy Act — destroy/deidentify when no longer
        # needed for the original purpose. Mirror CCPA-style limits.
        "agent_intents": RetentionRule(90, CEILING, "Australian Privacy Act APP 11.2 destruction"),
        "agent_action_outcomes": RetentionRule(180, CEILING, "Australian Privacy Act APP 11.2 destruction"),
    },
    "GLOBAL": {
        # Strictest of all — shortest defaults across categories. Every
        # entry is a CEILING by construction: "strictest" here means
        # "delete soonest", so nothing in this profile may lengthen.
        "arp_receipts": RetentionRule(365, CEILING, "strictest-of-all multi-jurisdiction profile"),
        "chapter_audit_events": RetentionRule(365, CEILING, "strictest-of-all multi-jurisdiction profile"),
        "agent_intents": RetentionRule(30, CEILING, "strictest-of-all multi-jurisdiction profile"),
        "agent_action_outcomes": RetentionRule(60, CEILING, "strictest-of-all multi-jurisdiction profile"),
        "trust_events": RetentionRule(365, CEILING, "strictest-of-all multi-jurisdiction profile"),
        "chronicles": RetentionRule(90, CEILING, "strictest-of-all multi-jurisdiction profile"),
    },
}


def validate_retention_overrides(table: Mapping[str, Mapping[str, Any]] | None = None) -> None:
    """Refuse any override entry that does not declare how it binds.

    Enumerates the table it is given — every jurisdiction, every entry —
    rather than checking a hand-listed set of entries known to need a
    direction. A list would have to be remembered; an enumeration cannot
    be forgotten, so an override added in six months is covered by the
    same rule as the ones written today.

    Called at import on ``RETENTION_OVERRIDES`` and again by
    ``retention_overrides_for`` on what it is about to hand the resolver.

    Raises ``RetentionDirectionError``.
    """
    entries = RETENTION_OVERRIDES if table is None else table
    for code, overrides in entries.items():
        if not isinstance(overrides, Mapping):
            raise RetentionDirectionError(f"RETENTION_OVERRIDES[{code!r}] is not a mapping of table -> RetentionRule")
        for table_name, rule in overrides.items():
            if not isinstance(rule, RetentionRule):
                raise RetentionDirectionError(
                    f"RETENTION_OVERRIDES[{code!r}][{table_name!r}] is {rule!r}, not a RetentionRule. "
                    "Every override must declare FLOOR (a statutory minimum) or CEILING (a minimisation "
                    "regime); this table drives a sweeper that DELETES, so there is no default direction."
                )
            if not isinstance(rule.direction, Direction):
                raise RetentionDirectionError(
                    f"RETENTION_OVERRIDES[{code!r}][{table_name!r}].direction is {rule.direction!r}, "
                    "not a Direction"
                )
            if isinstance(rule.days, bool) or not isinstance(rule.days, int) or rule.days <= 0:
                raise RetentionDirectionError(
                    f"RETENTION_OVERRIDES[{code!r}][{table_name!r}].days is {rule.days!r}; "
                    "a TTL must be a positive integer number of days"
                )
            if not rule.basis or not isinstance(rule.basis, str):
                raise RetentionDirectionError(
                    f"RETENTION_OVERRIDES[{code!r}][{table_name!r}] declares no basis for its direction"
                )


validate_retention_overrides()

# ── Per-jurisdiction applicable compliance regime hints ─────────────
# These are returned to operator tooling so it can flag which regimes
# the server SHOULD be ready to satisfy. Each regime maps to a list of
# (acronym, full_name, citation) triples. Not exhaustive — meant as a
# starting point for the operator's compliance program.
APPLICABLE_REGIMES: dict[str, list[dict[str, str]]] = {
    "US": [
        {"acronym": "FTC-S5", "full_name": "FTC Section 5", "citation": "15 USC §45"},
    ],
    "US-CA": [
        {"acronym": "FTC-S5", "full_name": "FTC Section 5", "citation": "15 USC §45"},
        {
            "acronym": "CCPA",
            "full_name": "California Consumer Privacy Act",
            "citation": "Cal Civ Code §1798.100 et seq",
        },
        {"acronym": "CPRA", "full_name": "California Privacy Rights Act", "citation": "Cal Civ Code §1798.140"},
        {"acronym": "BIPA", "full_name": "California version absent — see Illinois BIPA precedent", "citation": ""},
    ],
    "US-CO": [
        {"acronym": "FTC-S5", "full_name": "FTC Section 5", "citation": "15 USC §45"},
        {"acronym": "CPA", "full_name": "Colorado Privacy Act", "citation": "Colo Rev Stat §6-1-1301 et seq"},
        {
            "acronym": "CAIA",
            "full_name": "Colorado AI Act (effective Feb 2026)",
            "citation": "Colo Rev Stat §6-1-1701 et seq",
        },
    ],
    "US-FED": [
        {"acronym": "FTC-S5", "full_name": "FTC Section 5", "citation": "15 USC §45"},
        {"acronym": "NIST-800-171", "full_name": "NIST Special Publication 800-171", "citation": "NIST SP 800-171"},
        {"acronym": "DFARS-7012", "full_name": "DFARS 252.204-7012", "citation": "48 CFR §252.204-7012"},
        {
            "acronym": "FedRAMP",
            "full_name": "Federal Risk and Authorization Management Program",
            "citation": "OMB Memorandum M-22-09",
        },
    ],
    "US-DOD": [
        {"acronym": "NIST-800-171", "full_name": "NIST 800-171", "citation": "NIST SP 800-171"},
        {"acronym": "DFARS-7012", "full_name": "DFARS 252.204-7012", "citation": "48 CFR §252.204-7012"},
        {"acronym": "CMMC-L2", "full_name": "CMMC Level 2", "citation": "32 CFR Part 170"},
        {"acronym": "FedRAMP-High", "full_name": "FedRAMP High (or IL5)", "citation": ""},
    ],
    "US-HIPAA": [
        {
            "acronym": "HIPAA",
            "full_name": "Health Insurance Portability and Accountability Act",
            "citation": "45 CFR Parts 160, 162, 164",
        },
        {"acronym": "HITECH", "full_name": "HITECH Act", "citation": "42 USC §17931"},
    ],
    "US-GLBA": [
        {"acronym": "GLBA", "full_name": "Gramm-Leach-Bliley Act", "citation": "15 USC §§6801-6809"},
        {"acronym": "Reg-P", "full_name": "Regulation P (privacy)", "citation": "12 CFR §1016"},
        {"acronym": "SOX", "full_name": "Sarbanes-Oxley Act (for public companies)", "citation": "15 USC §7241"},
    ],
    "EU": [
        {"acronym": "GDPR", "full_name": "General Data Protection Regulation", "citation": "Regulation (EU) 2016/679"},
        {"acronym": "EU-AI-Act", "full_name": "EU AI Act", "citation": "Regulation (EU) 2024/1689"},
    ],
    "UK": [
        {
            "acronym": "UK-GDPR",
            "full_name": "UK General Data Protection Regulation",
            "citation": "Data Protection Act 2018",
        },
    ],
    "CA": [
        {
            "acronym": "PIPEDA",
            "full_name": "Personal Information Protection and Electronic Documents Act",
            "citation": "SC 2000, c 5",
        },
    ],
    "AU": [
        {"acronym": "AU-PA", "full_name": "Australian Privacy Act 1988", "citation": "Privacy Act 1988 (Cth)"},
    ],
    "GLOBAL": [
        {"acronym": "GDPR", "full_name": "GDPR (apply as strictest default)", "citation": ""},
        {"acronym": "CCPA", "full_name": "CCPA (US baseline)", "citation": ""},
        {"acronym": "EU-AI-Act", "full_name": "EU AI Act (highest-risk-tier deployment)", "citation": ""},
    ],
}


async def resolve_jurisdiction(
    pg_request: Callable[..., Awaitable[Any]] | None,
    chapter_id: str,
) -> str:
    """Resolve the chapter's effective jurisdiction code.

    Order: env var → chapter_policy.jurisdiction column → DEFAULT.
    Returns a normalized uppercase region code (e.g., ``"US-CA"``).
    """
    # ORG_JURISDICTION canonical; CHAPTER_JURISDICTION back-compat.
    env_value = (
        os.environ.get("ORG_JURISDICTION", "").strip() or os.environ.get("CHAPTER_JURISDICTION", "").strip()
    ).upper()
    if env_value:
        return env_value

    if pg_request is not None:
        try:
            # ⚠️ chapter_policy is a KEY/VALUE table — (chapter_id, key, value
            # jsonb), init.sql:1480 — not a wide table with a `jurisdiction`
            # column. This read asked for the column form, so PostgREST rejected
            # every request and the bare `except` below swallowed it: the
            # database layer of this resolution has never once returned a value,
            # and an operator who set the policy row got the default silently.
            # Only the env var above has ever worked.
            rows = await pg_request(
                "GET",
                "chapter_policy",
                params={
                    "chapter_id": f"eq.{chapter_id}",
                    "key": "eq.jurisdiction",
                    "select": "value",
                    "limit": "1",
                },
            )
            if rows and isinstance(rows, list) and rows:
                # jsonb: a bare string ("EU") or an object ({"code": "EU"}).
                raw = rows[0].get("value")
                stored = (raw.get("code") if isinstance(raw, dict) else raw) or ""
                stored = str(stored).strip().upper()
                if stored:
                    return stored
        except Exception:  # noqa: BLE001
            pass

    return DEFAULT_JURISDICTION


def retention_overrides_for(jurisdiction: str) -> dict[str, RetentionRule]:
    """Return the per-table retention rules for the given jurisdiction.
    Returns an empty dict for unknown jurisdictions (caller falls back to
    module defaults from retention.py).

    ⚠️ Returns ``RetentionRule``s, not day counts. It returned bare ints
    until the floor-versus-ceiling fix and the one caller did ``policy[table] = days`` — an
    assignment, which is neither of the two things a regime can mean.
    Handing back a rule is what makes the direction impossible to drop
    silently: an old-style assignment now puts a RetentionRule into an
    int-keyed policy map and breaks loudly instead of deleting quietly.
    """
    code = (jurisdiction or "").strip().upper()
    overrides = dict(RETENTION_OVERRIDES.get(code, {}))
    # Re-validated on the way out: import-time validation covers the
    # checked-in table, this covers whatever the table holds at call time.
    validate_retention_overrides({code: overrides})
    return overrides


def applicable_regimes_for(jurisdiction: str) -> list[dict[str, str]]:
    """Return a list of (acronym, full_name, citation) describing the
    compliance regimes the chapter SHOULD be ready to satisfy. For
    unknown jurisdictions returns the US baseline."""
    code = (jurisdiction or "").strip().upper()
    return list(APPLICABLE_REGIMES.get(code, APPLICABLE_REGIMES["US"]))


async def effective_retention_policy(
    pg_request: Callable[..., Awaitable[Any]] | None,
    chapter_id: str,
) -> dict[str, int]:
    """The effective per-category retention TTL: defaults, then jurisdiction,
    then the operator override.

    ⚠️ DELEGATES to ``retention.resolve_retention_policy`` rather than layering
    it again here. It used to do its own three-layer stack, and the third layer
    read ``chapter_policy`` as a WIDE table (``select=retention_days_by_category``)
    when it is a KEY/VALUE table — the mistake ``retention.py`` warns about in its
    own comment. Every such read was rejected by PostgREST and swallowed, so this
    function would have silently dropped the operator override had anything
    called it. Two near-identical implementations where one is subtly wrong is
    the drift this whole exercise is about, so there is now exactly one.

    Kept as a name because it reads better at a call site that cares about
    jurisdiction, and because it is public API with its own tests.
    """
    import retention

    return await retention.resolve_retention_policy(pg_request, chapter_id)


__all__ = [
    "DEFAULT_JURISDICTION",
    "RETENTION_OVERRIDES",
    "APPLICABLE_REGIMES",
    "CEILING",
    "FLOOR",
    "Direction",
    "RetentionDirectionError",
    "RetentionRule",
    "resolve_jurisdiction",
    "retention_overrides_for",
    "applicable_regimes_for",
    "effective_retention_policy",
    "validate_retention_overrides",
]
