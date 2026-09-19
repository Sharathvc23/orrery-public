"""
Cryptographic primitives for the community-member agent.

Provides:
- API key encryption at rest — HMAC-SHA256 encrypt-then-MAC (a PRF-CTR
  keystream XORed with the plaintext, authenticated by a separate HMAC tag
  verified before decryption), with the key derived via PBKDF2-HMAC-SHA256.
  This is a sound authenticated-encryption construction; it is NOT AES-256-GCM
  (a deliberate choice to stay standard-library-only — see the note below).
- HMAC-SHA256 message signing for A2A authentication
- Key derivation from passphrase
- Challenge-response signing for registration

All crypto uses standard library only — no external dependencies.
"""

import base64
import hashlib
import hmac
import os
import struct
import time

# A standard AEAD (AES-256-GCM or ChaCha20-Poly1305) via the `cryptography`
# lib would be preferable, but this module stays standard-library-only, so we
# use an HMAC-SHA256 encrypt-then-MAC construction (below). It is sound, but
# non-standard — do NOT describe it as AES-GCM to auditors/operators.
#
# S2 stage 2: blobs are VERSIONED. A v2 blob carries its own KDF params
# ({v: 2, kdf: {name, iterations}, cipher, ...}), so bumping PBKDF2_ITERATIONS
# (or adding a new cipher/KDF under a new name) no longer bricks existing
# vaults. Version-less legacy blobs decrypt via LEGACY_PBKDF2_ITERATIONS — a
# FROZEN constant, deliberately decoupled from the live default below. Do not
# ever change the legacy constant; it is what legacy vaults were sealed with.
PBKDF2_ITERATIONS = 100_000
LEGACY_PBKDF2_ITERATIONS = 100_000  # frozen — legacy blobs; never change
SALT_LENGTH = 32
NONCE_LENGTH = 16

BLOB_VERSION = 2
KDF_NAME = "pbkdf2-sha256"
CIPHER_NAME = "hmac-sha256-etm-v1"

# Bounds on the per-blob iteration count. A tampered count can't decrypt (the
# MAC key is derived from it, so verification fails) — but without a ceiling a
# hostile blob could demand absurd KDF work BEFORE the MAC check runs. Clamp
# to a sane range and treat anything outside it as malformed.
_MIN_KDF_ITERATIONS = 50_000
_MAX_KDF_ITERATIONS = 10_000_000


def derive_key(
    passphrase: str, salt: bytes | None = None, *, iterations: int = PBKDF2_ITERATIONS
) -> tuple[bytes, bytes]:
    """Derive a 256-bit key from a passphrase using PBKDF2.

    Returns (key, salt). If salt is None, generates a new one. ``iterations``
    defaults to the live cost; decryption passes the per-blob value.
    """
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    if salt is None:
        salt = os.urandom(SALT_LENGTH)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations)
    return key, salt


def _keystream_xor(data: bytes, enc_key: bytes, nonce: bytes) -> bytes:
    """The PRF-CTR core: HMAC-SHA256(enc_key, nonce||counter) keystream XORed
    with ``data``. Symmetric — encrypts and decrypts. Byte-identical to the
    legacy construction; v2 changed the envelope, never the cipher."""
    out = bytearray(len(data))
    for i in range(0, len(data), 32):
        counter = struct.pack(">I", i // 32)
        block = hmac.new(enc_key, nonce + counter, hashlib.sha256).digest()
        for j in range(min(32, len(data) - i)):
            out[i + j] = data[i + j] ^ block[j]
    return bytes(out)


def encrypt_value(plaintext: str, passphrase: str) -> dict:
    """Encrypt a string value with a passphrase — emits a v2 versioned blob.

    Returns ``{v, kdf: {name, iterations}, cipher, ciphertext, salt, nonce,
    tag}`` (binary fields base64). HMAC-SHA256 encrypt-then-MAC: a PRF-CTR
    keystream (HMAC(enc_key, nonce||ctr)) XORed with the plaintext, then an
    HMAC(mac_key, nonce||ciphertext) tag. The enc/mac keys are independent
    halves of the PBKDF2-derived key. NOT AES-GCM.

    The KDF cost is recorded IN the blob, so a future ``PBKDF2_ITERATIONS``
    bump (or a new cipher/KDF under new names) only affects new writes —
    existing blobs keep decrypting with their own recorded params.
    """
    if not plaintext:
        raise ValueError("Nothing to encrypt")

    iterations = PBKDF2_ITERATIONS
    key, salt = derive_key(passphrase, iterations=iterations)
    enc_key = key[:16]
    mac_key = key[16:]

    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = _keystream_xor(plaintext.encode(), enc_key, nonce)
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()

    return {
        "v": BLOB_VERSION,
        "kdf": {"name": KDF_NAME, "iterations": iterations},
        "cipher": CIPHER_NAME,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def _blob_iterations(encrypted: dict) -> int:
    """The PBKDF2 cost to decrypt ``encrypted`` with — per-blob for v2, the
    frozen legacy constant for version-less blobs. Unknown versions, KDF or
    cipher names, and out-of-range costs fail LOUD (never a silent downgrade
    to some guessed interpretation)."""
    if "v" not in encrypted:
        # Legacy blob: {ciphertext, salt, nonce, tag}, cost baked in.
        return LEGACY_PBKDF2_ITERATIONS
    if encrypted["v"] != BLOB_VERSION:
        raise ValueError(f"Unsupported blob version: {encrypted['v']!r}")
    if encrypted.get("cipher") != CIPHER_NAME:
        raise ValueError(f"Unsupported cipher: {encrypted.get('cipher')!r}")
    kdf = encrypted.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("name") != KDF_NAME:
        raise ValueError(f"Unsupported KDF: {kdf!r}")
    iterations = kdf.get("iterations")
    # Bound BEFORE deriving — a hostile blob must not get to demand absurd
    # KDF work (the MAC would catch the tamper, but only after we paid it).
    if not isinstance(iterations, int) or not _MIN_KDF_ITERATIONS <= iterations <= _MAX_KDF_ITERATIONS:
        raise ValueError(f"KDF iterations out of range: {iterations!r}")
    return iterations


def is_legacy_blob(encrypted: dict) -> bool:
    """True for a legacy version-less blob — the caller's cue to re-encrypt
    (see ``keystore._read_vault``'s migrate-on-open)."""
    return isinstance(encrypted, dict) and "v" not in encrypted


def decrypt_value(encrypted: dict, passphrase: str) -> str:
    """Decrypt an encrypted value with a passphrase — v2 and legacy blobs.

    Raises ValueError if the passphrase is wrong, the data is tampered, or the
    blob declares a version/KDF/cipher this build doesn't know.
    """
    if not isinstance(encrypted, dict):
        raise ValueError("Invalid encrypted data format: not an object")
    # Version/KDF/cipher problems raise their own loud, specific ValueErrors.
    iterations = _blob_iterations(encrypted)
    try:
        ciphertext = base64.b64decode(encrypted["ciphertext"])
        salt = base64.b64decode(encrypted["salt"])
        nonce = base64.b64decode(encrypted["nonce"])
        stored_tag = base64.b64decode(encrypted["tag"])
    except (KeyError, Exception) as e:
        raise ValueError(f"Invalid encrypted data format: {e}") from e

    key, _ = derive_key(passphrase, salt, iterations=iterations)
    enc_key = key[:16]
    mac_key = key[16:]

    # Verify authentication tag FIRST (before decryption)
    expected_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, stored_tag):
        raise ValueError("Decryption failed: wrong passphrase or tampered data")

    return _keystream_xor(ciphertext, enc_key, nonce).decode()


# ─── Signing ─────────────────────────────────────────────────


def generate_keypair() -> dict:
    """Generate a signing keypair for agent authentication.

    Returns {"private_key": str, "public_key": str} — both base64 encoded.
    """
    private_key = os.urandom(32)
    public_key = hashlib.sha256(private_key).digest()
    return {
        "private_key": base64.b64encode(private_key).decode(),
        "public_key": base64.b64encode(public_key).decode(),
    }


def sign_message(message: str, private_key_b64: str) -> str:
    """Sign a message with the private key. Returns base64 signature."""
    private_key = base64.b64decode(private_key_b64)
    sig = hmac.new(private_key, message.encode(), hashlib.sha256).digest()
    return base64.b64encode(sig).decode()


def verify_signature(message: str, signature_b64: str, public_key_b64: str, private_key_b64: str | None = None) -> bool:
    """Verify a message signature.

    In HMAC-based signing, verification requires the private key
    (or the server stores the public key and re-derives).
    For our use case, the chapter stores the public key hash and
    the agent proves knowledge of the private key.

    For server-side verification: the challenge-response protocol
    means the server generates a nonce, the client signs it, and
    the server verifies by checking HMAC(private_key, nonce) matches.
    Since the server doesn't have the private key, we use a different
    approach: the public key IS the hash of the private key. The server
    checks that SHA256(provided_private_key_proof) == stored_public_key.

    In practice: the client signs nonce with private key, server
    checks the signature matches.
    """
    if not private_key_b64:
        return False
    try:
        private_key = base64.b64decode(private_key_b64)
        expected = hmac.new(private_key, message.encode(), hashlib.sha256).digest()
        provided = base64.b64decode(signature_b64)
        return hmac.compare_digest(expected, provided)
    except Exception:
        return False


def sign_challenge(nonce: str, private_key_b64: str, agent_id: str) -> str:
    """Sign a registration challenge.

    Signs: "challenge:{nonce}:{agent_id}:{timestamp}"
    Timestamp provides replay protection (5-minute window).
    """
    timestamp = str(int(time.time()))
    message = f"challenge:{nonce}:{agent_id}:{timestamp}"
    signature = sign_message(message, private_key_b64)
    # Return signature + timestamp so server can verify
    return base64.b64encode(f"{signature}:{timestamp}".encode()).decode()


def verify_challenge(
    signed_challenge_b64: str, nonce: str, agent_id: str, private_key_b64: str, max_age_seconds: int = 300
) -> bool:
    """Verify a signed registration challenge.

    Checks: valid signature + timestamp within max_age_seconds.
    """
    try:
        decoded = base64.b64decode(signed_challenge_b64).decode()
        signature, timestamp_str = decoded.rsplit(":", 1)
        timestamp = int(timestamp_str)
    except Exception:
        return False

    # Check timestamp freshness
    now = int(time.time())
    if abs(now - timestamp) > max_age_seconds:
        return False

    # Verify signature
    message = f"challenge:{nonce}:{agent_id}:{timestamp_str}"
    return verify_signature(message, signature, "", private_key_b64)


# ─── Ed25519 Signing (NANDA Index spec-compliant, optional) ──
#
# Requires PyNaCl + base58 (both optional). If not installed, the
# HMAC path above is used for backward-compat with server agents
# that haven't upgraded to Ed25519 verification yet.
#
# Separate functions so import failures are localized and don't
# block the zero-dependency core.


def ed25519_available() -> bool:
    """Return True if Ed25519 signing is available in this environment."""
    try:
        import base58  # noqa: F401
        import nacl.signing  # noqa: F401
    except ImportError:
        return False
    return True


def generate_ed25519_keypair() -> dict:
    """Generate an Ed25519 keypair. Raises ImportError if PyNaCl missing."""
    from nacl.signing import SigningKey

    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return {
        "private_key": base64.b64encode(bytes(signing_key)).decode(),
        "public_key": base64.b64encode(bytes(verify_key)).decode(),
    }


def ed25519_sign_message(message: str, private_key_b64: str) -> str:
    """Sign a message with Ed25519. Returns base64 signature."""
    from nacl.signing import SigningKey

    private_bytes = base64.b64decode(private_key_b64)
    signing_key = SigningKey(private_bytes)
    return base64.b64encode(signing_key.sign(message.encode()).signature).decode()


def ed25519_public_from_private(private_key_b64: str) -> str:
    """Derive the Ed25519 public key (b64) from the private seed (b64).

    The private key is the 32-byte seed (``bytes(SigningKey)``); the verify key
    is a deterministic function of it. Used to recover a headless agent's
    ``public_key`` from a keystore-restored private key WITHOUT config.json, so
    ``has_keypair()`` is true and the identity is never silently re-minted on a
    redeploy (which would orphan its org/NEST/host39 registrations).
    """
    from nacl.signing import SigningKey

    signing_key = SigningKey(base64.b64decode(private_key_b64))
    return base64.b64encode(bytes(signing_key.verify_key)).decode()


ED25519_MULTICODEC_PREFIX = b"\xed\x01"


def build_did_key(public_key_b64: str) -> str:
    """Build a W3C-compliant did:key from an Ed25519 public key.

    Format: did:key:z{base58btc(multicodec(0xed01) || pubkey)}
    Spec: https://w3c-ccg.github.io/did-method-key/#ed25519

    Delegates to ``sm_conformance.derive_did_key`` (the published primitive) so
    the agent's did:key encoding can never drift from the conformance toolkit's;
    the local base58 path is a byte-identical fallback when sm-conformance is
    absent (verified equal in tests).

    Refuses unless real Ed25519 is available: without PyNaCl the keypair is
    the HMAC fallback, whose ``public_key`` is ``sha256(private_key)`` — a
    32-byte HASH, not a verify-key. Minting a did:key from it would advertise an
    identity nothing can verify a signature against. Callers (AgentFacts, A2A)
    fall back to did:web on this error.
    """
    if not ed25519_available():
        raise ValueError(
            "cannot mint a publishable did:key without Ed25519 — the HMAC-fallback "
            "public key is sha256(private_key), not an Ed25519 verify-key"
        )
    pubkey_bytes = base64.b64decode(public_key_b64)
    if len(pubkey_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pubkey_bytes)}")
    try:
        from sm_conformance.badge import derive_did_key

        return derive_did_key(pubkey_bytes)
    except ImportError:
        import base58

        prefixed = ED25519_MULTICODEC_PREFIX + pubkey_bytes
        return f"did:key:z{base58.b58encode(prefixed).decode()}"
