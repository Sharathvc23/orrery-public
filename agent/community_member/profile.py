"""Local agent profile — owned by the agent, published in the Agent Card.

Part of the lean-chapter migration (see chapter-runtime
docs/architecture/lean-chapter.md). Profile data — name, bio,
interests, skills, socials, contact info, photo — moves out of the
chapter's ``agents`` table and into local config here. The
``/.well-known/agent.json`` endpoint exposes the public subset in
the existing A2A AgentCard's ``x-nanda.profile`` extension so any
chapter (or any A2A-aware client) can fetch it.

Privacy is opt-in per field. ``email`` and ``phone`` ship with
``visible=False`` by default — the card publishes ``null`` for
those fields. The user can flip ``visible=True`` per field through
``profile edit`` or the web UI.

The profile is signed by the agent's Ed25519 key on every change.
The signature lives in the card next to the data; chapters that
fetch the card verify the signature against the agent's
``did:key`` before trusting any field. This means a stolen card
URL can't fool a chapter into displaying tampered data — the
chapter rejects unsigned or wrong-signed cards.

Storage layout (``~/.community-member/profile.json``)::

    {
      "name": "Ada",
      "bio": "...",
      "interests": ["ai", "agents"],
      "skills": ["python", "react"],
      "email": {"value": "x@y", "visible": false},
      "phone": {"value": null, "visible": false},
      "socials": {
        "twitter": "@ada",
        "linkedin": "https://...",
        "github": "https://github.com/ada"
      },
      "photo_path": "/home/.../avatar.png",
      "updated_at": "2026-04-26T15:00:00Z",
      "signature": "<base64 ed25519 over canonical JSON>"
    }

The ``signature`` covers the canonical JSON of every field except
``signature`` itself. Canonicalization sorts keys and uses ``,``
``:`` separators. ``profile.verify()`` recomputes and rejects any
profile whose signature doesn't match the agent's public key.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

__all__ = [
    "PRIVATE_FIELDS",
    "PUBLIC_FIELDS",
    "Profile",
    "ProfileField",
    "load_profile",
    "save_profile",
    "to_card_extension",
]


# Fields whose values are public by default (always go in the card).
PUBLIC_FIELDS: frozenset[str] = frozenset({"name", "bio", "interests", "skills", "socials", "photo_url"})
# Fields that are opt-in per-instance via ProfileField.visible.
PRIVATE_FIELDS: frozenset[str] = frozenset({"email", "phone"})


@dataclass
class ProfileField:
    """A field with an explicit privacy bit.

    Used for ``email`` and ``phone`` so the user can store the
    value locally for their own reference but choose whether to
    publish it to chapters that fetch the card.
    """

    value: str | None = None
    visible: bool = False

    def to_card_value(self) -> str | None:
        """Return the value to embed in the Agent Card.

        Hidden fields publish as None — the card shape is
        identical, only the value differs, so a chapter can't
        infer "user has phone but won't share" from the absence
        of the key.
        """
        return self.value if self.visible else None


@dataclass
class Profile:
    """The agent's full profile. Some fields stay local-only."""

    name: str = ""
    bio: str = ""
    interests: list[str] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)
    email: ProfileField = field(default_factory=ProfileField)
    phone: ProfileField = field(default_factory=ProfileField)
    # Free-form social handles. Caller may add any platform key.
    socials: dict[str, str] = field(default_factory=dict)
    # Local path to an avatar image. Public URL is set when the
    # agent serves the file at /api/profile/photo. We never upload
    # to server storage post-migration.
    photo_path: str | None = None
    photo_url: str | None = None
    updated_at: str = ""
    # Base64-encoded Ed25519 signature over canonical JSON of all
    # other fields. Empty when unsigned (initial config write).
    signature: str = ""

    def to_canonical_dict(self) -> dict:
        """The dict that gets signed. Excludes ``signature``."""
        d = asdict(self)
        d.pop("signature", None)
        # Make ProfileField values stable for canonical JSON.
        for k in ("email", "phone"):
            v = d.get(k)
            if isinstance(v, dict):
                d[k] = {"value": v.get("value"), "visible": bool(v.get("visible"))}
        return d

    def to_card_extension(self) -> dict:
        """Build the dict that goes inside the Agent Card's
        ``x-nanda.profile`` extension. Hidden fields are scrubbed."""
        return {
            "name": self.name,
            "bio": self.bio,
            "interests": list(self.interests),
            "skills": list(self.skills),
            "email": self.email.to_card_value(),
            "phone": self.phone.to_card_value(),
            "socials": dict(self.socials),
            "photo_url": self.photo_url,
            "updated_at": self.updated_at,
            "signature": self.signature,
        }


# ─── Persistence ────────────────────────────────────────────────


def _canonical_json(obj: dict) -> bytes:
    """Stable-byte-encoded JSON used for signing.

    sort_keys + compact separators mean the same logical content
    serialises to the same bytes regardless of insertion order.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _profile_path(config_dir: Path) -> Path:
    return Path(config_dir) / "profile.json"


def load_profile(config_dir: Path) -> Profile:
    """Load profile from ``~/.community-member/profile.json``.

    Returns an empty Profile if the file doesn't exist (first run).
    Raises ``ValueError`` only on malformed JSON; missing fields
    fall back to dataclass defaults.
    """
    p = _profile_path(config_dir)
    if not p.exists():
        return Profile()
    raw = json.loads(p.read_text("utf-8"))
    return _from_dict(raw)


def save_profile(
    profile: Profile,
    config_dir: Path,
    *,
    sign: object | None = None,
) -> Profile:
    """Persist + optionally re-sign a profile.

    ``sign`` is a callable ``(message_bytes) -> base64_signature``;
    when supplied, the saved profile will have a fresh
    ``signature`` covering its canonical bytes. Pass
    ``crypto.sign_message`` (or a wrapper that grabs the agent's
    private key from keystore) here.

    The saved file always has ``updated_at`` set to now() and is
    written via temp-file + atomic rename so a crash during write
    cannot corrupt the existing file.
    """
    profile.updated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if sign is not None:
        canonical = _canonical_json(profile.to_canonical_dict())
        sig_bytes = sign(canonical)
        if isinstance(sig_bytes, bytes):
            profile.signature = base64.b64encode(sig_bytes).decode("ascii")
        else:
            profile.signature = str(sig_bytes)
    p = _profile_path(config_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(_to_dict(profile), indent=2), encoding="utf-8")
    tmp.replace(p)
    return profile


def to_card_extension(profile: Profile) -> dict:
    """Build the ``x-nanda.profile`` payload. Convenience export."""
    return profile.to_card_extension()


# ─── Verify ─────────────────────────────────────────────────────


def verify_signature(
    profile: Profile,
    *,
    verify: object,
) -> bool:
    """Return True if ``profile.signature`` is valid for the
    profile's canonical bytes under ``verify``.

    ``verify`` is a callable ``(message_bytes, signature_bytes) -> bool``.
    Pass ``crypto.verify_signature`` bound to the agent's pubkey.
    Empty signature → False (caller must sign before publish).
    """
    if not profile.signature:
        return False
    try:
        sig_bytes = base64.b64decode(profile.signature.encode("ascii"))
    except Exception:
        return False
    canonical = _canonical_json(profile.to_canonical_dict())
    try:
        return bool(verify(canonical, sig_bytes))  # type: ignore[operator]
    except Exception:
        return False


def content_hash(profile: Profile) -> str:
    """Stable sha256 of the profile (excluding signature). Useful
    for cache-keys and "did the profile actually change" checks."""
    return hashlib.sha256(_canonical_json(profile.to_canonical_dict())).hexdigest()


# ─── Internal: dict ↔ dataclass ────────────────────────────────


def _to_dict(p: Profile) -> dict:
    """Serialise to JSON-friendly dict."""
    return {
        "name": p.name,
        "bio": p.bio,
        "interests": list(p.interests),
        "skills": list(p.skills),
        "email": {"value": p.email.value, "visible": bool(p.email.visible)},
        "phone": {"value": p.phone.value, "visible": bool(p.phone.visible)},
        "socials": dict(p.socials),
        "photo_path": p.photo_path,
        "photo_url": p.photo_url,
        "updated_at": p.updated_at,
        "signature": p.signature,
    }


def _from_dict(raw: dict) -> Profile:
    """Parse a dict (potentially partial) into a Profile.

    Garbage shapes (interests=string, socials=string) silently
    fall back to defaults rather than raising — the file might
    have been hand-edited or written by an older version.
    """
    email_raw = raw.get("email")
    email = email_raw if isinstance(email_raw, dict) else {}
    phone_raw = raw.get("phone")
    phone = phone_raw if isinstance(phone_raw, dict) else {}
    interests_raw = raw.get("interests")
    interests = list(interests_raw) if isinstance(interests_raw, list) else []
    skills_raw = raw.get("skills")
    skills = list(skills_raw) if isinstance(skills_raw, list) else []
    socials_raw = raw.get("socials")
    socials = dict(socials_raw) if isinstance(socials_raw, dict) else {}
    return Profile(
        name=str(raw.get("name") or ""),
        bio=str(raw.get("bio") or ""),
        interests=interests,
        skills=skills,
        email=ProfileField(
            value=email.get("value"),
            visible=bool(email.get("visible", False)),
        ),
        phone=ProfileField(
            value=phone.get("value"),
            visible=bool(phone.get("visible", False)),
        ),
        socials=socials,
        photo_path=raw.get("photo_path"),
        photo_url=raw.get("photo_url"),
        updated_at=str(raw.get("updated_at") or ""),
        signature=str(raw.get("signature") or ""),
    )
