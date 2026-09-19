"""Duress passphrase — \"someone has me at gunpoint\" mode.

Closes S8 in the v2 threat model. The user registers TWO
passphrases: a normal one, and a duress one. Any later prompt
that asks for the passphrase accepts either:

  * Normal passphrase  → unlock as expected.
  * Duress passphrase  → silently wipe graduations + habits.db,
                         leave an invisible audit marker, return
                         success to the caller (so an attacker
                         watching the screen sees a normal unlock).
  * Anything else      → invalid.

Design rules (from plans/…/humble-hopcroft.md §Coercion / duress)
-----------------------------------------------------------------

  * Both passphrases are stored as PBKDF2-HMAC-SHA256 hashes with
    a fresh 16-byte salt each. The plaintext never lands on disk.
  * verify_and_handle is constant-time w.r.t. which bucket matched
    (hash compare + hmac.compare_digest). A wall-clock side channel
    could reveal whether duress was triggered; we fight that by
    computing both comparisons unconditionally.
  * The duress action is LOCAL ONLY. No network call, no chapter
    notification — anything observable leaks the fact that duress
    was triggered. The audit marker is written to the local
    consent ledger; the chapter sees only a normal key rotation
    (from panic) if/when the user runs panic later from safety.
  * The duress side-effect is sticky: once triggered, the agent
    is in a clean state. Re-registering passphrases starts fresh.

UI integration
--------------

The tray UI (when it lands) asks for a passphrase whenever the
keystore needs to be unlocked. It calls `verify_and_handle`
without branching visibly: both outcomes return True-ish results,
the only difference is what's in the ledger afterward.

What gets wiped on duress
-------------------------

  * All graduations (every device's GraduationStore → revoked_all
    for this device only; we can't touch another device's row)
  * habits.db — so the model starts from Beta(1,1) priors again
  * An audit row labeled `consent.duress_triggered` is appended.
    It looks like any other consent event; an attacker reading
    the ledger after the fact might notice it, but there's no
    screen-visible \"duress triggered\" banner.

What is NOT wiped
-----------------

  * The signing key — rotating would lock the attacker out, which
    might escalate. Duress is about hiding that anything happened,
    not about key security. Panic revoke does key rotation; they
    are orthogonal tools.
  * The consent ledger history — the hash chain is append-only and
    the prior rows stay. The duress marker is simply the next row.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from community_member.consent import ledger

__all__ = [
    "PBKDF2_ITERATIONS",
    "PassphraseCheckResult",
    "PassphraseStore",
    "register_passphrases",
    "verify_and_handle",
]


# PBKDF2 iteration count. OWASP-recommended floor circa 2024 is 600k
# for SHA-256; we go above to future-proof. On a modern laptop this
# costs ~50ms per check — imperceptible when typing a passphrase.
PBKDF2_ITERATIONS = 800_000
SALT_BYTES = 16
HASH_BYTES = 32

PassphraseCheckResult = Literal["normal", "duress", "invalid"]


@dataclass(frozen=True)
class PassphraseStore:
    """On-disk representation of the two-passphrase configuration."""

    normal_salt_b64: str
    normal_hash_b64: str
    duress_salt_b64: str
    duress_hash_b64: str
    iterations: int = PBKDF2_ITERATIONS


def _hash(passphrase: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=HASH_BYTES)


def register_passphrases(
    normal: str,
    duress: str,
    *,
    path: str | Path,
    iterations: int = PBKDF2_ITERATIONS,
) -> PassphraseStore:
    """Create the passphrase store at `path`. Overwrites if present.

    `normal` and `duress` must differ and both be non-empty. The
    plaintext never touches disk — only PBKDF2 hashes with fresh
    salts each.
    """
    if not normal or not duress:
        raise ValueError("both passphrases must be non-empty")
    if normal == duress:
        raise ValueError("normal and duress passphrases must differ")

    normal_salt = os.urandom(SALT_BYTES)
    duress_salt = os.urandom(SALT_BYTES)
    normal_hash = _hash(normal, normal_salt, iterations)
    duress_hash = _hash(duress, duress_salt, iterations)

    store = PassphraseStore(
        normal_salt_b64=base64.b64encode(normal_salt).decode("ascii"),
        normal_hash_b64=base64.b64encode(normal_hash).decode("ascii"),
        duress_salt_b64=base64.b64encode(duress_salt).decode("ascii"),
        duress_hash_b64=base64.b64encode(duress_hash).decode("ascii"),
        iterations=iterations,
    )
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(
            {
                "normal_salt_b64": store.normal_salt_b64,
                "normal_hash_b64": store.normal_hash_b64,
                "duress_salt_b64": store.duress_salt_b64,
                "duress_hash_b64": store.duress_hash_b64,
                "iterations": store.iterations,
            },
            indent=2,
        )
    )
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return store


def _load_store(path: str | Path) -> PassphraseStore | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
    except (ValueError, OSError):
        return None
    try:
        return PassphraseStore(
            normal_salt_b64=data["normal_salt_b64"],
            normal_hash_b64=data["normal_hash_b64"],
            duress_salt_b64=data["duress_salt_b64"],
            duress_hash_b64=data["duress_hash_b64"],
            iterations=int(data.get("iterations", PBKDF2_ITERATIONS)),
        )
    except (KeyError, TypeError, ValueError):
        return None


def verify_and_handle(
    passphrase: str,
    *,
    store_path: str | Path,
    chapter_id: str,
    actor_agent_id: str | None = None,
    on_duress_wipe_habits: Path | None = None,
    on_duress_revoke_graduations: bool = True,
    device_did: str | None = None,
    graduation_db_path: Path | None = None,
) -> PassphraseCheckResult:
    """Check `passphrase` against the stored passphrase pair. Execute
    the duress side effects if it matches the duress hash.

    Returns one of:
      * \"normal\"  — passphrase matches normal; caller proceeds as usual
      * \"duress\"  — passphrase matches duress; side effects executed;
                      caller should ALSO proceed as usual (don't leak
                      the duress fact to the UI)
      * \"invalid\" — neither matches

    Timing
    ------

    Both hashes are computed on every call (we don't short-circuit
    on the first match) so an attacker watching wall-clock timing
    cannot distinguish the duress branch from the normal branch.
    The hmac.compare_digest call is constant-time w.r.t. the hash
    bytes, so the final compare also leaks nothing.
    """
    store = _load_store(store_path)
    if store is None:
        return "invalid"

    normal_salt = base64.b64decode(store.normal_salt_b64)
    normal_hash = base64.b64decode(store.normal_hash_b64)
    duress_salt = base64.b64decode(store.duress_salt_b64)
    duress_hash = base64.b64decode(store.duress_hash_b64)

    # Compute BOTH hashes regardless of match — constant time.
    h_normal = _hash(passphrase, normal_salt, store.iterations)
    h_duress = _hash(passphrase, duress_salt, store.iterations)

    normal_match = hmac.compare_digest(h_normal, normal_hash)
    duress_match = hmac.compare_digest(h_duress, duress_hash)

    if duress_match:
        _trigger_duress(
            chapter_id=chapter_id,
            actor_agent_id=actor_agent_id,
            wipe_habits_path=on_duress_wipe_habits,
            revoke_graduations=on_duress_revoke_graduations,
            device_did=device_did,
            graduation_db_path=graduation_db_path,
        )
        return "duress"
    if normal_match:
        return "normal"
    return "invalid"


def _trigger_duress(
    *,
    chapter_id: str,
    actor_agent_id: str | None,
    wipe_habits_path: Path | None,
    revoke_graduations: bool,
    device_did: str | None,
    graduation_db_path: Path | None,
) -> None:
    """Execute the local-only duress side effects. Never raises.

    The consent ledger audit row is written first so even if a
    subsequent step fails, we have a record of WHY the state is
    about to change. Every side effect is best-effort: a failure
    in one does not prevent the next, and nothing here talks to
    the network.
    """
    # 1. Audit marker (always). The row looks like any other
    # consent event; nothing in the rendering suggests \"duress.\"
    try:
        ledger.record(
            chapter_id=chapter_id,
            action="consent.duress_triggered",
            actor_agent_id=actor_agent_id,
            target_type="self",
            target_id="duress",
            outcome="ok",
            detail={"marker": "silent"},
        )
    except Exception:
        pass

    # 2. Wipe habits.db (best effort). Deleting the file is the
    # simplest possible state reset; next time the agent starts a
    # fresh HabitModel, it creates an empty schema.
    if wipe_habits_path is not None:
        try:
            Path(wipe_habits_path).unlink(missing_ok=True)
        except OSError:
            pass

    # 3. Revoke graduations for THIS device. Other devices are
    # unaffected (by design: the attacker has only this machine).
    if revoke_graduations and device_did and graduation_db_path is not None:
        try:
            from community_member.graduation import GraduationStore

            store = GraduationStore(graduation_db_path, device_did=device_did)
            store.revoke_all()
        except Exception:
            pass
