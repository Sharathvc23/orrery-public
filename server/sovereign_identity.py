"""
Sovereign Identity — cryptographic identity + attestation for member agents.

Uses nanda-bridge's NandaAgentFacts as the canonical model.
Adds Ed25519 keypairs for message signing, and attestation tiers
for skill verification.

Architecture:
- Each member gets an Ed25519 keypair on agent creation
- Private key: stored in agent_private_memory (member-only RLS)
- Public key: stored in AgentFacts.provider.did field (public)
- Every A2A message is signed with the private key
- Chapter agent verifies signatures before accepting actions
- Skills have trust levels based on attestation evidence
"""

import base64
import json
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import secret_sealing

# Vendored from sm-bridge
# Replace with: from nanda_bridge.models import ... when published to PyPI
from nanda_models import (
    NandaAgentFacts,
    NandaAuthentication,
    NandaCapabilities,
    NandaCertification,
    NandaEndpoints,
    NandaEvaluations,
    NandaProvider,
    NandaSkill,
    NandaTelemetry,
)

# Injected
_pg_request: Callable[..., Awaitable] | None = None
_agent_id = ""


def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran.

    The unguarded call sites previously produced a bare `TypeError: 'NoneType'
    object is not callable`; this raises the same crash with an actionable
    message (R2/that change typing surfaced the pattern)."""
    if _pg_request is None:
        raise RuntimeError("sovereign_identity.init() was never called — no pg_request injected")
    return _pg_request

# AgentFacts version tracking (CRDT-lite): agent_id → monotonic counter
_facts_versions: dict[str, int] = {}

# The org/server semver advertised in AgentFacts. Keep in sync with
# pyproject.toml [project].version (was a hardcoded "1.0.0").
SERVER_VERSION = "0.2.0"


def init(pg_request, agent_id):
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


# ─── Ed25519 Signing (NANDA Index spec-compliant) ────────────

# Cached Ed25519 keypairs: agent_id → {"private_key": bytes, "public_key": bytes}
_ed25519_keypairs: dict[str, dict] = {}


def generate_ed25519_keypair(agent_id: str) -> dict:
    """Generate an Ed25519 keypair for an agent.

    Returns {"private_key": b64, "public_key": b64} and caches it.
    """
    from nacl.signing import SigningKey

    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    private_b64 = base64.b64encode(bytes(signing_key)).decode()
    public_b64 = base64.b64encode(bytes(verify_key)).decode()

    _ed25519_keypairs[agent_id] = {
        "private_key": bytes(signing_key),
        "public_key": bytes(verify_key),
    }

    return {"private_key": private_b64, "public_key": public_b64}


PostgresRequest = Callable[..., Awaitable["dict | list | None"]]


# ── Chapter signing-key encryption at rest (S1, AUDIT_HARSH C11) ──
# The chapter's Ed25519 private key authorizes every ARP receipt and VRP
# attestation the org signs — a plaintext copy in a DB dump or backup is full
# identity-forgery material. The secret is sealed with AES-256-GCM under a
# PBKDF2 key (see secret_sealing) before it is written to the chapter_keys table
# or the local file.
#
# Sealing is REQUIRED by default. Until that change an unset ORRERY_KEY_SECRET printed
# a warning and stored the key in the clear, so the least safe branch was the
# one absent configuration selected; ensure_chapter_keypair now refuses to start
# instead. Legacy plaintext rows still READ (marker-based decode) and are sealed
# in place on the next boot that has the secret — the stored bytes are re-encoded,
# not replaced, so did:key is unchanged and no rotation is involved.
_KEY_SECRET_ENV = secret_sealing.KEY_SECRET_ENV
_ENC_PREFIX = secret_sealing.ENC_PREFIX
_SEALED_SUBJECT = "the chapter's Ed25519 signing key"


def _seal_secret(secret_b64: str) -> str:
    """Encrypt ``secret_b64`` for at-rest storage.

    Raises ``secret_sealing.SealingNotConfigured`` when sealing is required and
    no ORRERY_KEY_SECRET is set, rather than falling back to plaintext.
    """
    return secret_sealing.seal(secret_b64, subject=_SEALED_SUBJECT)


def _unseal_secret(stored: str) -> str:
    """Return the plaintext ``secret_b64``. Sealed values (``enc.v1:`` prefix)
    are decrypted with ORRERY_KEY_SECRET; legacy plaintext is returned as-is."""
    return secret_sealing.unseal(stored)


async def ensure_chapter_keypair(
    chapter_id: str,
    *,
    pg_request: PostgresRequest | None = None,
    local_home: str | None = None,
) -> None:
    """Ensure the chapter's Ed25519 signing keypair exists in ``_ed25519_keypairs``,
    loaded from a DURABLE store and minted+persisted on first boot.

    Without this the chapter's signing key is ephemeral (a fresh random key per
    process, created lazily), so ``_chapter_keypair_bytes`` returns None at request
    time and both ARP receipt signing and the VRP AgentFacts Attestation silently
    no-op. Call once at startup.

    - **Prod** (``pg_request`` given): load the secret from the ``chapter_keys``
      table; mint + upsert it on first boot. Durable across restarts AND replicas.
    - **Offline/dev** (``local_home`` given): same, backed by a local JSON file.
    - Idempotent: returns immediately if the key is already in memory.

    Failures to REACH the key store degrade to an ephemeral key (loudly logged)
    rather than crashing startup — a chapter that can't reach its store still serves,
    just un-attested. A missing ORRERY_KEY_SECRET is NOT that kind of failure: it is a
    misconfiguration that would put the signing key in the clear, so it raises
    ``secret_sealing.SealingNotConfigured`` and the process does not start.
    """
    if chapter_id in _ed25519_keypairs:
        return

    # Checked BEFORE any store access so the refusal is deterministic: a first boot
    # (which would mint and write a plaintext key) and a restart on an already-plaintext
    # row fail the same way, rather than the first silently writing and the second
    # silently reading.
    secret_sealing.require_sealing_configured(_SEALED_SUBJECT)

    if pg_request is not None:
        rows = await pg_request(
            "GET",
            "chapter_keys",
            params={"chapter_id": f"eq.{chapter_id}", "select": "secret_b64,public_b64"},
        )
        if rows:
            row = rows[0] if isinstance(rows, list) else rows
            stored_secret = row["secret_b64"]
            _ed25519_keypairs[chapter_id] = {
                "private_key": base64.b64decode(_unseal_secret(stored_secret)),
                "public_key": base64.b64decode(row["public_b64"]),
            }
            await _migrate_plaintext_row(chapter_id, stored_secret, pg_request)
            return
        kp = generate_ed25519_keypair(chapter_id)
        stored = await pg_request(
            "POST",
            "chapter_keys",
            body={
                "chapter_id": chapter_id,
                "secret_b64": _seal_secret(kp["private_key"]),
                "public_b64": kp["public_key"],
            },
        )
        if stored is None:
            print(
                f"[identity][ERROR] chapter keypair for {chapter_id} could NOT be persisted "
                "(chapter_keys table missing/unreachable) — signing key is EPHEMERAL until persisted"
            )
        return

    if local_home is not None:
        path = os.path.join(local_home, "chapter_ed25519.json")
        if os.path.exists(path):
            with open(path) as f:
                d = json.load(f)
            _ed25519_keypairs[chapter_id] = {
                "private_key": base64.b64decode(_unseal_secret(d["secret_b64"])),
                "public_key": base64.b64decode(d["public_b64"]),
            }
            _migrate_plaintext_file(chapter_id, d, path)
            return
        kp = generate_ed25519_keypair(chapter_id)
        os.makedirs(local_home, exist_ok=True)
        _write_key_file(path, _seal_secret(kp["private_key"]), kp["public_key"])
        return

    # Last resort: ephemeral (no durability) — kept so isolated tests/dev still run.
    generate_ed25519_keypair(chapter_id)


def _write_key_file(path: str, secret_b64: str, public_b64: str) -> None:
    """Write the offline key file at 0600 (owner-only), creating or replacing it.

    ``os.open`` sets the mode at creation so there is no window where the file is
    readable per umask. The explicit ``chmod`` covers the REPLACE case: O_CREAT's
    mode argument is ignored for a file that already exists, so a key file written
    by a build predating the 0600 change would otherwise keep its original mode
    through the seal-in-place rewrite.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"secret_b64": secret_b64, "public_b64": public_b64}, f)
    os.chmod(path, 0o600)


# ── Seal-in-place migration for rows/files written before sealing ─────────────
# Sealing only NEW writes would leave every key minted before that change in the clear
# while the code read as fixed. These re-encode the SAME key bytes under
# ORRERY_KEY_SECRET on the first boot that has the secret. The private key is
# unchanged, so the derived did:key is unchanged and nothing downstream re-pins.
#
# The same paths complete a ROTATION of ORRERY_KEY_SECRET: a row sealed under
# ORRERY_KEY_SECRET_PREVIOUS reads (secret_sealing.unseal tries it second) and
# needs_migration reports it, so it is unsealed and resealed under the current
# secret here. Unsealed FIRST — sealing the stored blob as if it were plaintext
# would wrap ciphertext in ciphertext and strand the key.
# A failed migration is logged and does not stop startup — the key is already
# loaded and usable, and the next boot retries.


async def _migrate_plaintext_row(
    chapter_id: str, stored_secret: str, pg_request: PostgresRequest
) -> None:
    """Seal an existing plaintext ``chapter_keys`` row in place."""
    if not secret_sealing.needs_migration(stored_secret):
        return
    result = await pg_request(
        "PATCH",
        "chapter_keys",
        params={"chapter_id": f"eq.{chapter_id}"},
        body={"secret_b64": _seal_secret(secret_sealing.unseal(stored_secret))},
    )
    if result is None:
        print(
            f"[identity][ERROR] chapter signing key for {chapter_id} is stored in PLAINTEXT and the "
            "seal-in-place UPDATE failed — the key is still readable to anyone with database access. "
            "Retrying on next boot."
        )
        return
    print(f"[identity] chapter signing key for {chapter_id} sealed in place (was plaintext at rest)")


def _migrate_plaintext_file(chapter_id: str, data: dict, path: str) -> None:
    """Seal an existing plaintext offline key file in place."""
    stored_secret = data["secret_b64"]
    if not secret_sealing.needs_migration(stored_secret):
        return
    try:
        _write_key_file(path, _seal_secret(secret_sealing.unseal(stored_secret)), data["public_b64"])
    except OSError as e:
        print(
            f"[identity][ERROR] chapter signing key for {chapter_id} is stored in PLAINTEXT at {path} "
            f"and the seal-in-place rewrite failed ({type(e).__name__}: {e}). Retrying on next boot."
        )
        return
    print(f"[identity] chapter signing key file {path} sealed in place (was plaintext at rest)")


def ed25519_sign(message: str, private_key_b64: str) -> str:
    """Sign a message with an Ed25519 private key. Returns base64 signature."""
    from nacl.signing import SigningKey

    private_bytes = base64.b64decode(private_key_b64)
    signing_key = SigningKey(private_bytes)
    signed = signing_key.sign(message.encode())
    return base64.b64encode(signed.signature).decode()


def ed25519_verify(message: str, signature_b64: str, public_key_b64: str) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    try:
        public_bytes = base64.b64decode(public_key_b64)
        verify_key = VerifyKey(public_bytes)
        signature = base64.b64decode(signature_b64)
    except Exception as e:  # noqa: BLE001 — deny, but never silently (R6)
        print(f"[Identity][deny] ed25519_verify: malformed key/signature material ({type(e).__name__}: {e})")
        return False
    try:
        verify_key.verify(message.encode(), signature)
        return True
    except BadSignatureError:
        print("[Identity][deny] ed25519_verify: signature does not verify against the provided key")
        return False
    except Exception as e:  # noqa: BLE001 — e.g. nacl length checks; deny, never silently (R6)
        print(f"[Identity][deny] ed25519_verify: malformed key/signature material ({type(e).__name__}: {e})")
        return False


ED25519_MULTICODEC_PREFIX = b"\xed\x01"


def build_did_key_from_ed25519(public_key_b64: str) -> str:
    """Build a W3C-compliant did:key from an Ed25519 public key.

    Format: did:key:z{base58btc(multicodec(0xed01) || pubkey)}
    Spec: https://w3c-ccg.github.io/did-method-key/#ed25519

    Raises (ValueError / binascii.Error) on input that is not a valid 32-byte
    Ed25519 key. It used to return a malformed `did:key:{b64-prefix}` fallback
    that extract_ed25519_pubkey_from_did_key could never round-trip — a DID
    that poisons every store it lands in (R4). Call sites whose input is
    only *maybe* Ed25519 material use try_build_did_key_from_ed25519 instead.
    """
    import base58

    pubkey_bytes = base64.b64decode(public_key_b64)
    if len(pubkey_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pubkey_bytes)}")
    prefixed = ED25519_MULTICODEC_PREFIX + pubkey_bytes
    encoded = base58.b58encode(prefixed).decode()
    return f"did:key:z{encoded}"


def try_build_did_key_from_ed25519(public_key_b64: str) -> str | None:
    """did:key if the input is a valid 32-byte Ed25519 key (base64), else None.

    For call sites whose semantic is "derive when derivable" — e.g. member
    `public_key` slots that may hold legacy HMAC material. Logs the reason
    before returning None; never produces a malformed DID.
    """
    try:
        return build_did_key_from_ed25519(public_key_b64)
    except Exception as e:  # noqa: BLE001 — lenient variant: log, then None
        print(f"[Identity] public key is not did:key material ({type(e).__name__}: {e}) — no DID derived")
        return None


def extract_ed25519_pubkey_from_did_key(did_key: str) -> str | None:
    """Extract the Ed25519 public key (base64) from a did:key string.

    Returns None if the DID is malformed or not Ed25519.
    Inverse of build_did_key_from_ed25519.
    """
    import base58

    if not did_key or not did_key.startswith("did:key:z"):
        return None
    try:
        encoded = did_key[len("did:key:z") :]
        raw = base58.b58decode(encoded)
        if len(raw) != 34 or raw[:2] != ED25519_MULTICODEC_PREFIX:
            return None
        return base64.b64encode(raw[2:]).decode()
    except Exception:
        return None


def pubkey_from_provider_did(did: str) -> str:
    """Ed25519 public key (base64) from a member ``provider.did`` in EITHER
    format (migration, permanent dual-read within 0.x):

    * W3C ``did:key:z6Mk…`` — the proper multicodec form new writes emit.
    * legacy ``did:key:{raw-b64}`` — the legacy internal carrier; accepted
      only when the payload actually decodes to 32-byte Ed25519 material
      (a legacy HMAC pubkey riding in the field is NOT a key we can verify
      Ed25519 signatures with, so it yields "").

    Returns "" when neither parses.
    """
    if not did or not did.startswith("did:key:"):
        return ""
    w3c = extract_ed25519_pubkey_from_did_key(did)
    if w3c:
        return w3c
    raw = did[len("did:key:") :]
    try:
        return raw if len(base64.b64decode(raw, validate=True)) == 32 else ""
    except Exception:
        return ""


def _extract_domain(url: str) -> str:
    """Extract domain from a URL for DID generation."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0] or "localhost"


def build_nanda_facts(
    agent_id: str,
    member: dict,
    public_key: str = "",
    public_url: str = "",
    evaluations: dict | None = None,
    telemetry: dict | None = None,
) -> dict:
    """Build full NANDA Index-compliant AgentFacts from member data.

    Aligned with: https://github.com/projnanda/agentfacts-format
    Spec: https://arxiv.org/abs/2507.14263

    Args:
        agent_id: Unique agent identifier
        member: Member dict with name, skills, description
        public_key: Agent's public signing key (HMAC or Ed25519)
        public_url: Base URL where this agent is reachable (e.g. https://agent.example.com)
        evaluations: Pre-computed NandaEvaluations-compatible dict
        telemetry: Pre-computed NandaTelemetry-compatible dict
    """
    skills = member.get("skills", [])
    description = member.get("description", "")
    domain = _extract_domain(public_url) if public_url else "localhost"
    base_url = public_url.rstrip("/") if public_url else ""

    # W3C-compliant DID
    agent_did = f"did:web:{domain}:agents:{agent_id}" if domain != "localhost" else f"did:nanda:{agent_id}"

    # Resolvable handle for @agent routing
    handle = f"@{agent_id}@{domain}" if domain != "localhost" else f"@{agent_id}"

    # Build endpoints from public_url
    endpoints = NandaEndpoints(
        static=[f"{base_url}/a2a"] if base_url else [],
        a2a=f"{base_url}/a2a" if base_url else None,
        agentfacts_url=f"{base_url}/agentfacts/{agent_id}.json" if base_url else None,
    )

    # Build evaluations model if data provided
    eval_model = None
    if evaluations:
        eval_model = NandaEvaluations(**evaluations)

    # Build telemetry model if data provided
    telemetry_model = None
    if telemetry:
        telemetry_model = NandaTelemetry(**telemetry)

    facts = NandaAgentFacts(
        id=agent_did,
        handle=handle,
        agent_name=agent_id,
        label=member.get("name", f"@{agent_id}"),
        description=description or f"NANDA agent @{agent_id}",
        version=SERVER_VERSION,
        provider=NandaProvider(
            # THE HOSTING DEPLOYMENT, derived from what it already declares —
            # never the project that wrote this code. `url` was hardcoded to
            # https://projectnanda.org and `name` fell back to "NANDA Community",
            # so a self-hoster's own members told every anonymous reader that
            # their provider was an organisation with nothing to do with the
            # deployment. Two other surfaces in this runtime already got this
            # right — the A2A card uses PUBLIC_URL, and sm_bridge_adapter
            # documents `provider_url = chapter's PUBLIC_URL` — so this was the
            # outlier, not the convention.
            #
            # Omitted rather than defaulted when unset: a field whose honest
            # value is unknown should be ABSENT. `model_dump(exclude_none=True)`
            # below does the omitting.
            name=_agent_id or None,
            url=public_url or None,
            # DID migration: the proper W3C did:key for Ed25519 material;
            # non-Ed25519 (legacy HMAC) keys get NO DID — they never were one,
            # and HMAC verification never read this field (it uses the
            # signing_secret). Old rows keep working via dual-format readers
            # and converge to this form on their next facts write.
            did=try_build_did_key_from_ed25519(public_key) if public_key else None,
        ),
        endpoints=endpoints,
        capabilities=NandaCapabilities(
            modalities=["text"],
            skills=[s for s in skills[:20]],
            # The org signs with Ed25519 (did:key) — advertise that, not the
            # stale bespoke hmac (org-side twin of the agent's that change).
            authentication=NandaAuthentication(methods=["ed25519", "did-auth"]),
            streaming=False,
        ),
        skills=[
            NandaSkill(
                id=f"urn:nanda:skill:{s.lower().replace(' ', '-')}",
                description=f"Expertise in {s}",
                supportedLanguages=["en"],
            )
            for s in skills[:20]
        ],
        certification=NandaCertification(
            level="self-declared",
            issuer=_agent_id or "NANDA",
            attestations=[],
            issuanceDate=datetime.now(UTC),
        ),
        evaluations=eval_model,
        telemetry=telemetry_model,
        updated_at=datetime.now(UTC),
        facts_version=get_facts_version(agent_id),
    )

    return facts.model_dump(mode="json", exclude_none=True)


def get_facts_version(agent_id: str) -> int:
    """Get and increment the monotonic version counter for an agent's facts.

    Counter state is hydrated from Postgres by load_facts_versions() at
    startup so restarts don't break CRDT-lite monotonicity — a rebuilt
    AgentFacts always increments past the last persisted value.
    """
    _facts_versions[agent_id] = _facts_versions.get(agent_id, 0) + 1
    return _facts_versions[agent_id]


async def load_facts_versions():
    """Hydrate _facts_versions from Postgres agents.agent_facts.facts_version.

    Must run after _pg_request is injected via init(). Ensures that
    on process restart, the next get_facts_version() call returns a value
    strictly greater than the last persisted version, preserving monotonic
    ordering for Index/NEST update clients that dedupe on facts_version.
    """
    if _pg_request is None:
        return 0

    try:
        rows = await _pg_request(
            "GET",
            "agents",
            params={"select": "agent_id,agent_facts"},
        )
    except Exception as e:
        print(f"[Identity] load_facts_versions failed: {e}")
        return 0

    if not rows:
        return 0

    loaded = 0
    for row in rows:
        aid = row.get("agent_id", "")
        facts = row.get("agent_facts") or {}
        version = facts.get("facts_version") or 0
        if aid and isinstance(version, int) and version > 0:
            # Preserve strict monotonicity: never decrease a live counter
            _facts_versions[aid] = max(_facts_versions.get(aid, 0), version)
            loaded += 1

    if loaded:
        print(f"[Identity] Hydrated {loaded} facts_version counters")
    return loaded


# ─── Attestation System ──────────────────────────────────────

TRUST_LEVELS = {
    "self-declared": 1,
    "github-verified": 2,
    "peer-attested": 3,
    "chapter-confirmed": 4,
}


async def attest_skill(agent_id: str, skill: str, trust_level: str, evidence: dict | None = None) -> dict:
    """Add or upgrade attestation for a skill.

    trust_level: 'self-declared', 'github-verified', 'peer-attested', 'chapter-confirmed'
    evidence: supporting data (github repo URL, peer agent_id, activity count)
    """
    if trust_level not in TRUST_LEVELS:
        return {"error": f"Invalid trust level: {trust_level}"}

    # Load current agent facts
    data = await _pg()(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{agent_id}",
            "select": "agent_facts",
        },
    )
    if not data:
        return {"error": "Agent not found"}

    facts = data[0].get("agent_facts") or {}

    # Update certification based on highest attestation
    attestations = facts.get("certification", {}).get("attestations", [])
    attestation_entry = f"{skill}:{trust_level}"
    if attestation_entry not in attestations:
        attestations.append(attestation_entry)

    # Determine overall certification level
    all_levels = [a.split(":")[-1] for a in attestations if ":" in a]
    highest = max((TRUST_LEVELS.get(lvl, 0) for lvl in all_levels), default=1)
    level_name = {v: k for k, v in TRUST_LEVELS.items()}.get(highest, "self-declared")

    facts["certification"] = {
        "level": level_name,
        "issuer": "NANDA",
        "attestations": attestations,
    }

    await _pg()(
        "PATCH",
        "agents", params={"agent_id": f"eq.{agent_id}"},
        body={
            "agent_facts": facts,
        },
    )

    return {"agent_id": agent_id, "skill": skill, "trust_level": trust_level, "attestations": attestations}


async def get_skill_trust(agent_id: str, skill: str) -> dict:
    """Get the trust level for a specific skill."""
    data = await _pg()(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{agent_id}",
            "select": "agent_facts",
        },
    )
    if not data:
        return {"trust_level": "unknown", "score": 0}

    facts = data[0].get("agent_facts") or {}
    attestations = facts.get("certification", {}).get("attestations", [])

    for att in attestations:
        if att.startswith(f"{skill}:"):
            level = att.split(":")[-1]
            return {"trust_level": level, "score": TRUST_LEVELS.get(level, 0)}

    return {"trust_level": "self-declared", "score": 1}
