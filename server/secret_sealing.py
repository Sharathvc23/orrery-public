"""At-rest sealing for the secrets the org stores in Postgres and on disk.

Two kinds of secret land in the database:

1. The org's **Ed25519 chapter signing key** (``chapter_keys.secret_b64``). It
   authorizes every ARP receipt, VRP attestation and federation broadcast the
   org emits, and it is the key a peer pins by ``did:key``. A plaintext copy in
   a dump, a backup or a compromised replica is identity-forgery material.
2. **Member LLM provider keys** (``agent_api_keys.api_key_encrypted``). These
   are bring-your-own-key user credentials; the blast radius of a leak is the
   member's own provider spend, not the org's identity. Lower severity than (1),
   same storage boundary.

Both are sealed with AES-256-GCM under a PBKDF2-HMAC-SHA256 key derived from
``ORRERY_KEY_SECRET``. Sealed values carry the ``enc.v1:`` prefix, so decode is
marker-based and rows written before sealing existed still read.

``ORRERY_KEY_SECRET`` used to be optional: unset meant "store plaintext, print a
warning, keep going" (AUDIT_HARSH C11/C1). That is the fail-open shape
``env_flags.security_flag`` exists to remove — absent configuration selected the
least safe branch, and the branch it selected was silent after the first boot
line scrolled away. Sealing is now required by default:
``ORRERY_REQUIRE_SEALED_SECRETS`` gates it, defaults ``True``, and with no
``ORRERY_KEY_SECRET`` set the server refuses to start rather than writing a
plaintext signing key.

An operator who deliberately accepts plaintext at rest (an ephemeral local test
box, a machine where the database and the process share the same trust boundary)
sets ``ORRERY_REQUIRE_SEALED_SECRETS=false``. That is a decision recorded in the
environment, which is what the previous behaviour lacked.
"""

from __future__ import annotations

import base64
import hashlib
import os

import env_flags

KEY_SECRET_ENV = "ORRERY_KEY_SECRET"
#: The key-encryption secret being ROTATED OUT. Set alongside a new
#: ``ORRERY_KEY_SECRET``: values still sealed under it unseal, the boot-time
#: seal-in-place migrations reseal them under the new secret, and once nothing
#: in the store needs it the operator unsets it. Without this a changed
#: ``ORRERY_KEY_SECRET`` made every sealed row permanently undecryptable —
#: the signing key first — so a leaked secret could only be rotated by
#: re-keying the org and having every federated peer re-pin it.
PREVIOUS_KEY_SECRET_ENV = "ORRERY_KEY_SECRET_PREVIOUS"
REQUIRE_SEALED_ENV = "ORRERY_REQUIRE_SEALED_SECRETS"

# ── at-rest format versions ──────────────────────────────────────────────────
# The iteration count is NOT stored inside the blob, so it cannot be recovered
# from the ciphertext — the FORMAT PREFIX is what carries it. That makes raising
# the count a format change, not a constant change: bumping PBKDF2_ITERS in place
# would re-derive a different key for every value already written and make every
# sealed secret in the database permanently undecryptable.
#
# So v1 is frozen at the count it was written with and stays readable forever,
# and v2 is what gets written from now on. M3 asked for OWASP's 600K; this is how
# to get there without stranding existing rows.
ENC_PREFIX_V1 = "enc.v1:"
ENC_PREFIX_V2 = "enc.v2:"
# What unseal() uses per prefix. Frozen: changing a value here breaks every value
# already sealed under it.
_ITERS_BY_PREFIX = {
    ENC_PREFIX_V1: 200_000,
    ENC_PREFIX_V2: 600_000,
}
# What seal() writes today.
ENC_PREFIX = ENC_PREFIX_V2
PBKDF2_ITERS = _ITERS_BY_PREFIX[ENC_PREFIX]

_SALT_LEN = 16
_NONCE_LEN = 12


class SealingNotConfigured(RuntimeError):
    """Sealing is required but ``ORRERY_KEY_SECRET`` is unset or empty."""


def key_encryption_secret() -> str:
    """The configured key-encryption secret, or ``""`` when unset/whitespace."""
    return os.environ.get(KEY_SECRET_ENV, "").strip()


def previous_key_encryption_secret() -> str:
    """The secret being rotated out, or ``""``. Read-only: nothing is ever sealed under it."""
    return os.environ.get(PREVIOUS_KEY_SECRET_ENV, "").strip()


def sealing_required() -> bool:
    """Whether secrets MUST be sealed before they are written at rest.

    Defaults ``True``. Unset, empty and unrecognised all read as required —
    see ``env_flags.security_flag`` for why unrecognised maps to the default
    rather than to ``False``.
    """
    return env_flags.security_flag(REQUIRE_SEALED_ENV, default=True)


def is_sealed(stored: str) -> bool:
    """Whether ``stored`` is a sealed value rather than legacy plaintext.

    Recognises EVERY known format version, not just the one being written. A
    check that only knew the current prefix would classify last week's sealed
    rows as legacy plaintext and hand the ciphertext back to a caller as though
    it were a secret.
    """
    return any(stored.startswith(p) for p in _ITERS_BY_PREFIX)


def require_sealing_configured(subject: str) -> None:
    """Raise if sealing is required and no key-encryption secret is available.

    ``subject`` names the secret in the error so the operator knows what would
    otherwise have been written in the clear. Call this at startup, before any
    write path runs, so the failure is a refusal to boot rather than a silent
    plaintext row.
    """
    if key_encryption_secret() or not sealing_required():
        return
    raise SealingNotConfigured(
        f"{KEY_SECRET_ENV} is not set, so {subject} would be stored UNENCRYPTED at rest. "
        f"Anyone with database, dump or backup access could read it. "
        f"Set {KEY_SECRET_ENV} to a long random value (openssl rand -hex 32) and keep it "
        f"outside the database. To accept plaintext at rest deliberately — a local test "
        f"box, or a deployment where the database shares the process's trust boundary — "
        f"set {REQUIRE_SEALED_ENV}=false."
    )


def seal(plaintext: str, *, subject: str) -> str:
    """Return the at-rest form of ``plaintext``.

    Sealed (``enc.v1:``-prefixed) when ``ORRERY_KEY_SECRET`` is set. When it is
    not set: raises ``SealingNotConfigured`` if sealing is required, otherwise
    returns ``plaintext`` unchanged after logging that the operator opted out.
    """
    kek = key_encryption_secret()
    if not kek:
        require_sealing_configured(subject)
        print(
            f"[sealing][WARN] {REQUIRE_SEALED_ENV}=false and {KEY_SECRET_ENV} is unset — "
            f"{subject} is being written UNENCRYPTED at rest."
        )
        return plaintext

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key = hashlib.pbkdf2_hmac("sha256", kek.encode(), salt, PBKDF2_ITERS)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return ENC_PREFIX + base64.b64encode(salt + nonce + ct).decode()


def unseal(stored: str) -> str:
    """Return the plaintext behind an at-rest value.

    Sealed values are decrypted with ``ORRERY_KEY_SECRET``. Legacy plaintext
    (no ``enc.v1:`` marker) is returned as-is so rows written before sealing
    existed keep loading — that read path is what makes the seal-in-place
    migration possible instead of forcing a key rotation.
    """
    if not is_sealed(stored):
        return stored
    kek = key_encryption_secret()
    if not kek:
        raise SealingNotConfigured(
            f"a stored secret is sealed but {KEY_SECRET_ENV} is not set — cannot decrypt. "
            f"Restore the same {KEY_SECRET_ENV} the value was sealed with."
        )

    from cryptography.exceptions import InvalidTag

    try:
        return _unseal_with(stored, kek)
    except InvalidTag:
        previous = previous_key_encryption_secret()
        if not previous:
            raise
        # Sealed under the secret being rotated out. Readable, and reported by
        # needs_migration so the boot-time seal-in-place rewrites it under the
        # current secret; until that runs, this is the read path.
        return _unseal_with(stored, previous)


def _unseal_with(stored: str, kek: str) -> str:
    """Decrypt ``stored`` under one specific key-encryption secret.

    Raises ``cryptography.exceptions.InvalidTag`` when ``kek`` is not the
    secret the value was sealed under — AES-GCM authenticates, so a wrong key
    is a detected failure rather than garbage plaintext.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Derive with the count THIS value was sealed under, read from its prefix —
    # never with the current one. That is the whole reason the prefix is versioned.
    prefix = next(p for p in _ITERS_BY_PREFIX if stored.startswith(p))
    iters = _ITERS_BY_PREFIX[prefix]
    blob = base64.b64decode(stored[len(prefix) :])
    salt = blob[:_SALT_LEN]
    nonce = blob[_SALT_LEN : _SALT_LEN + _NONCE_LEN]
    ct = blob[_SALT_LEN + _NONCE_LEN :]
    key = hashlib.pbkdf2_hmac("sha256", kek.encode(), salt, iters)
    return AESGCM(key).decrypt(nonce, ct, None).decode()


def sealed_under_previous_secret(stored: str) -> bool:
    """Whether ``stored`` is sealed, and only the ROTATED-OUT secret opens it.

    False when no previous secret is configured, when the value is plaintext,
    or when the current secret opens it. Two key derivations at most, on the
    boot-time migration paths only — never on a request path.
    """
    if not is_sealed(stored):
        return False
    kek, previous = key_encryption_secret(), previous_key_encryption_secret()
    if not (kek and previous):
        return False
    from cryptography.exceptions import InvalidTag

    try:
        _unseal_with(stored, kek)
        return False
    except InvalidTag:
        pass
    try:
        _unseal_with(stored, previous)
        return True
    except InvalidTag:
        return False


def needs_migration(stored: str) -> bool:
    """Whether ``stored`` should be resealed in place under the current secret.

    Two cases, both re-encoding the same bytes under a key the process holds,
    so neither changes the secret nor requires a rotation of the org's keys:

    * legacy plaintext, when a key-encryption secret is available;
    * a value sealed under ``ORRERY_KEY_SECRET_PREVIOUS``, which is how a
      rotation of the key-encryption secret completes — every migration path
      that calls this reseals the row, and once none does the operator drops
      the previous secret.
    """
    if not stored or not key_encryption_secret():
        return False
    if not is_sealed(stored):
        return True
    return sealed_under_previous_secret(stored)
