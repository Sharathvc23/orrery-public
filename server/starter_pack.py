"""
Non-profit Starter Skills Pack for Orrery.

Exposes a single async entry point:

    await seed_starter_pack()

Call it inside an async context AFTER skill_registry.init(...) has already run
(which happens at line 1310 inside `async def lifespan(application)` in
chapter_agent.py). Each skill is idempotent — calling seed_starter_pack() a
second time is a no-op for every skill already registered.

The five skills are first-party convenience manifests that ship with every fresh
Orrery install. They are signed by an ephemeral Ed25519 key generated once per
server process — this is an intentional first-party convenience pack, not a
third-party trust anchor.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging

from nacl.signing import SigningKey

logger = logging.getLogger(__name__)

# ── First-party signing key (ephemeral per-process) ──────────────────────────
# A stable private key would embed a secret in source.  An ephemeral key is
# fine here: these manifests are first-party content published at server startup.
# The author_did changes across restarts, which is acceptable for a local pack.
_PACK_KEY: SigningKey = SigningKey.generate()


def _did() -> str:
    from sovereign_identity import build_did_key_from_ed25519

    pub_b64 = base64.b64encode(_PACK_KEY.verify_key.encode()).decode()
    return build_did_key_from_ed25519(pub_b64)


def _sign_manifest(manifest: dict) -> tuple[str, str]:
    """Return (content_sha256_hex, base64_signature) for *manifest*.

    The registry verifies the signature over the hex-string form of the hash
    (not over the raw bytes), matching skill_registry.verify_skill_signature.
    """
    # JCS-canonical bytes (RFC 8785: sorted keys, compact separators, UTF-8) —
    # the same canonical form the rest of the stack signs over (cosign receipts).
    # The installing client (agent skills.py) recomputes this byte-for-byte to
    # verify, so the two MUST agree.
    content_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sha_hex = hashlib.sha256(content_bytes).hexdigest()
    signed = _PACK_KEY.sign(sha_hex.encode("utf-8"))
    sig_b64 = base64.b64encode(signed.signature).decode()
    return sha_hex, sig_b64


# ── Manifests ─────────────────────────────────────────────────────────────────

NONPROFIT_SKILLS: list[dict] = [
    {
        "name": "donor-acknowledgement",
        "version": "1.0.0",
        "description": (
            "Draft a personalized, warm thank-you note for a donor. "
            "Accepts the donor's name, gift amount, and the program they supported."
        ),
        "author_did": "did:web:labs.stellarminds.ai",
        "capabilities": ["text.generate", "data.read"],
        "category": "nonprofit-fundraising",
        "use_cases": [
            "Generate a heartfelt acknowledgement letter after receiving a donation",
            "Personalise boilerplate thank-you templates per donor",
            "Draft gift-receipt language that complies with IRS requirements",
        ],
        "inputs": [
            {"name": "donor_name", "description": "Full name of the donor."},
            {"name": "gift_amount", "description": "Monetary amount or in-kind description of the gift."},
            {"name": "program", "description": "The program or fund the gift supports."},
        ],
        "outputs": [
            {"name": "acknowledgement_letter", "description": "Personalised thank-you letter body text."},
        ],
        "permissions": {
            "network": False,
            "filesystem": False,
            "code_execution": False,
            "external_api": False,
            "user_data_access": False,
        },
        "safety_level": "low",
        "risk_tags": [],
        "compatibility": {
            "generic_agents": "supported",
            "nanda_agentfacts": "supported",
            "claude_skills": "experimental",
            "mcp": "unknown",
            "chatgpt_skills": "unknown",
        },
        "license": "Apache-2.0",
        "maintainers": [{"name": "Orrery Starter Pack", "contact": "https://labs.stellarminds.ai"}],
        "readme_markdown": (
            "# donor-acknowledgement\n\n"
            "Compose personalised donor acknowledgement letters for non-profit organisations.\n\n"
            "## Inputs\n- `donor_name` — full name\n- `gift_amount` — dollar amount or in-kind description\n"
            "- `program` — program or fund the gift supports\n\n"
            "## Output\nA warm, personalised thank-you letter body that can be copied into your email "
            "or letter-head template.\n"
        ),
    },
    {
        "name": "grant-deadline-tracker",
        "version": "1.0.0",
        "description": (
            "Record upcoming grant application deadlines and summarise what deliverables "
            "are due, sorted by urgency."
        ),
        "author_did": "did:web:labs.stellarminds.ai",
        "capabilities": ["data.store", "data.read", "text.summarize"],
        "category": "nonprofit-fundraising",
        "use_cases": [
            "Track multiple open grant cycles and their LOI / full-application deadlines",
            "Surface the next 30-day horizon of grant obligations",
            "Summarise outstanding requirements per funder",
        ],
        "inputs": [
            {"name": "funder_name", "description": "Name of the granting foundation or agency."},
            {"name": "deadline_date", "description": "ISO-8601 date (YYYY-MM-DD) when the submission is due."},
            {"name": "deliverable_type", "description": "Type of submission: LOI, full application, report, etc."},
            {"name": "notes", "description": "Optional free-text notes about requirements or contacts."},
        ],
        "outputs": [
            {"name": "deadline_summary", "description": "Sorted list of upcoming deadlines with actionable notes."},
        ],
        "permissions": {
            "network": False,
            "filesystem": False,
            "code_execution": False,
            "external_api": False,
            "user_data_access": True,
        },
        "safety_level": "low",
        "risk_tags": [],
        "compatibility": {
            "generic_agents": "supported",
            "nanda_agentfacts": "supported",
            "claude_skills": "experimental",
            "mcp": "unknown",
            "chatgpt_skills": "unknown",
        },
        "license": "Apache-2.0",
        "maintainers": [{"name": "Orrery Starter Pack", "contact": "https://labs.stellarminds.ai"}],
        "readme_markdown": (
            "# grant-deadline-tracker\n\n"
            "Keep on top of grant cycles without a spreadsheet. Submit deadline entries one at a time "
            "and ask the agent for an urgency-sorted summary at any point.\n\n"
            "## Inputs\n- `funder_name`, `deadline_date` (YYYY-MM-DD), `deliverable_type`, `notes`\n\n"
            "## Output\nA ranked list of upcoming deadlines with notes and days-until counts.\n"
        ),
    },
    {
        "name": "volunteer-scheduler",
        "version": "1.0.0",
        "description": (
            "Propose volunteer shift assignments that best match declared availabilities "
            "to open shift slots, minimising scheduling conflicts."
        ),
        "author_did": "did:web:labs.stellarminds.ai",
        "capabilities": ["data.read", "data.store", "text.generate"],
        "category": "nonprofit-operations",
        "use_cases": [
            "Assign volunteers to weekend event shifts based on submitted availability",
            "Resolve scheduling conflicts and propose alternates",
            "Generate a human-readable shift roster for coordinator review",
        ],
        "inputs": [
            {"name": "volunteer_name", "description": "Name of the volunteer."},
            {"name": "availability_windows", "description": "List of ISO-8601 datetime ranges the volunteer is free."},
            {"name": "shift_slots", "description": "List of shift definitions: role, start, end, location."},
            {"name": "constraints", "description": "Optional free-text constraints (e.g. certifications required)."},
        ],
        "outputs": [
            {"name": "shift_roster", "description": "Proposed volunteer-to-shift assignments with conflict notes."},
        ],
        "permissions": {
            "network": False,
            "filesystem": False,
            "code_execution": False,
            "external_api": False,
            "user_data_access": True,
        },
        "safety_level": "low",
        "risk_tags": [],
        "compatibility": {
            "generic_agents": "supported",
            "nanda_agentfacts": "supported",
            "claude_skills": "experimental",
            "mcp": "unknown",
            "chatgpt_skills": "unknown",
        },
        "license": "Apache-2.0",
        "maintainers": [{"name": "Orrery Starter Pack", "contact": "https://labs.stellarminds.ai"}],
        "readme_markdown": (
            "# volunteer-scheduler\n\n"
            "Automate shift assignments for non-profit events. Provide volunteer availabilities "
            "and open shift definitions; receive a draft roster ready for coordinator approval.\n\n"
            "## Inputs\n- `volunteer_name`, `availability_windows`, `shift_slots`, `constraints`\n\n"
            "## Output\nA proposed shift roster listing each volunteer's assigned slot and any unresolved gaps.\n"
        ),
    },
    {
        "name": "impact-report-summarizer",
        "version": "1.0.0",
        "description": (
            "Transform raw program activity notes into a concise, donor-ready impact summary "
            "with headline metrics and a narrative paragraph."
        ),
        "author_did": "did:web:labs.stellarminds.ai",
        "capabilities": ["text.summarize", "text.generate", "data.read"],
        "category": "nonprofit-communications",
        "use_cases": [
            "Convert staff field notes into a one-page impact brief for annual reports",
            "Generate donor-ready programme outcomes from internal tracking data",
            "Distil multi-month activity logs into a quarter's headline results",
        ],
        "inputs": [
            {"name": "program_name", "description": "Name of the programme or initiative."},
            {"name": "activity_notes", "description": "Raw notes or structured data describing programme activities."},
            {"name": "reporting_period", "description": "Time period covered (e.g. Q1 2026 or Jan–Mar 2026)."},
            {"name": "audience", "description": "Intended audience: donor, board, public, government, etc."},
        ],
        "outputs": [
            {"name": "impact_summary", "description": "Concise impact narrative with key metrics highlighted."},
        ],
        "permissions": {
            "network": False,
            "filesystem": False,
            "code_execution": False,
            "external_api": False,
            "user_data_access": False,
        },
        "safety_level": "low",
        "risk_tags": [],
        "compatibility": {
            "generic_agents": "supported",
            "nanda_agentfacts": "supported",
            "claude_skills": "experimental",
            "mcp": "unknown",
            "chatgpt_skills": "unknown",
        },
        "license": "Apache-2.0",
        "maintainers": [{"name": "Orrery Starter Pack", "contact": "https://labs.stellarminds.ai"}],
        "readme_markdown": (
            "# impact-report-summarizer\n\n"
            "Turn messy field notes into polished programme outcomes for donors, boards, and the public.\n\n"
            "## Inputs\n- `program_name`, `activity_notes`, `reporting_period`, `audience`\n\n"
            "## Output\nA short impact narrative (2–4 paragraphs) with bullet metrics, "
            "tailored to the stated audience.\n"
        ),
    },
    {
        "name": "event-outreach",
        "version": "1.0.0",
        "description": (
            "Compose a compelling event announcement or outreach message for a non-profit event, "
            "adapted for email, social media, or flyer copy."
        ),
        "author_did": "did:web:labs.stellarminds.ai",
        "capabilities": ["text.generate", "data.read"],
        "category": "nonprofit-communications",
        "use_cases": [
            "Write an email invitation for a fundraising gala",
            "Generate social-media copy for a volunteer recruitment drive",
            "Draft a short flyer blurb for a community awareness event",
        ],
        "inputs": [
            {"name": "event_name", "description": "Name of the event."},
            {"name": "event_date", "description": "Date and time of the event (ISO-8601 preferred)."},
            {"name": "event_location", "description": "Physical address or virtual platform link."},
            {"name": "event_description", "description": "Brief description of the event purpose and activities."},
            {"name": "channel", "description": "Target channel: email, twitter, facebook, flyer, or press-release."},
        ],
        "outputs": [
            {
                "name": "outreach_message",
                "description": "Ready-to-send announcement text optimised for the chosen channel.",
            },
        ],
        "permissions": {
            "network": False,
            "filesystem": False,
            "code_execution": False,
            "external_api": False,
            "user_data_access": False,
        },
        "safety_level": "low",
        "risk_tags": [],
        "compatibility": {
            "generic_agents": "supported",
            "nanda_agentfacts": "supported",
            "claude_skills": "experimental",
            "mcp": "unknown",
            "chatgpt_skills": "unknown",
        },
        "license": "Apache-2.0",
        "maintainers": [{"name": "Orrery Starter Pack", "contact": "https://labs.stellarminds.ai"}],
        "readme_markdown": (
            "# event-outreach\n\n"
            "Generate polished event announcements for any non-profit occasion.\n\n"
            "## Inputs\n- `event_name`, `event_date`, `event_location`, `event_description`, `channel`\n\n"
            "## Output\nChannel-appropriate announcement copy ready to paste into your email client, "
            "social media dashboard, or print layout.\n"
        ),
    },
]


# ── Seed function ─────────────────────────────────────────────────────────────


async def seed_starter_pack() -> dict:
    """Register all five non-profit starter skills into the active registry.

    Idempotent: an already-present skill whose stored content hash still matches
    the code is skipped; one whose hash has DRIFTED (e.g. a canonicalization
    change) is re-signed in place so the first-party pack tracks the code without
    a version bump. Calling this function a second time is safe.

    Returns a summary dict:
    {"seeded": [...], "refreshed": [...], "skipped": [...], "errors": [...]}.

    Prerequisites
    -------------
    skill_registry.init(pg_request_fn=..., chapter_id=...) must have been
    called before this function is awaited.  In chapter_agent.py this happens at
    line 1310 inside ``async def lifespan(application: FastAPI)``.
    """
    import skill_registry as sr

    author_did = _did()
    seeded: list[str] = []
    skipped: list[str] = []
    refreshed: list[str] = []
    errors: list[str] = []

    for manifest in NONPROFIT_SKILLS:
        skill_id = f"{manifest['name']}@{manifest['version']}"
        try:
            sha_hex, sig_b64 = _sign_manifest(manifest)
            await sr.publish_skill(
                manifest=manifest,
                signature=sig_b64,
                signing_key_did=author_did,
                content_sha256=sha_hex,
                author_agent_id="orrery-starter-pack",
            )
            seeded.append(skill_id)
            logger.info("starter_pack: seeded %s", skill_id)
        except ValueError as exc:
            msg = str(exc)
            if "already published" in msg:
                # First-party pack already present — re-sign it in place if the
                # stored content hash has drifted from the current code (e.g. a
                # manifest canonicalization change), so the pack tracks the code
                # without a version bump. No drift → a genuine skip.
                status = await sr.refresh_skill_signature(
                    manifest=manifest,
                    signature=sig_b64,
                    signing_key_did=author_did,
                    content_sha256=sha_hex,
                )
                if status == "refreshed":
                    refreshed.append(skill_id)
                    logger.info("starter_pack: refreshed drifted signature for %s", skill_id)
                else:
                    skipped.append(skill_id)
                    logger.debug("starter_pack: skipped (already current) %s", skill_id)
            else:
                errors.append(f"{skill_id}: {msg}")
                logger.warning("starter_pack: rejected %s — %s", skill_id, msg)
        except Exception as exc:
            # Infrastructure failure (e.g. registry backend unavailable at boot).
            # A first-party convenience pack must NEVER crash server startup — log
            # loudly and continue; the pack is idempotent and re-seeds on next boot.
            errors.append(f"{skill_id}: {exc}")
            logger.warning(
                "starter_pack: could not seed %s (registry backend unavailable?) — %s",
                skill_id,
                exc,
            )

    logger.info(
        "starter_pack complete — seeded=%d refreshed=%d skipped=%d errors=%d",
        len(seeded),
        len(refreshed),
        len(skipped),
        len(errors),
    )
    return {"seeded": seeded, "refreshed": refreshed, "skipped": skipped, "errors": errors}
