"""BIP39 mnemonic + SLIP-0010 Ed25519 key derivation.

Supports sovereign identity recovery: lose the laptop, enter the 24-word
phrase on a new machine, get the same `did:key` back.

Why SLIP-0010 specifically: Ed25519 curves are "hardened-only" — you cannot
derive non-hardened child keys the way secp256k1 BIP32 allows. SLIP-0010
is the canonical derivation spec for Ed25519. Test vectors from
https://github.com/satoshilabs/slips/blob/master/slip-0010.md.

Default derivation path for the member identity:
    m/44'/9004'/0'/0'/0'

  44'   — BIP44 purpose
  9004' — NANDA coin type (arbitrary but stable; picked to avoid clash
          with registered SLIP-0044 assignments)
  0'    — account
  0'    — change
  0'    — address index (first key)

R1-R10 coverage lives in tests/test_recovery.py.

This module needs `mnemonic` (BIP39) and `pynacl` (Ed25519 signing). Both
are core dependencies of the `orrery-agent` distribution, so a complete
install already has them:
    pip install -e .        # from the agent/ directory
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import NamedTuple

try:
    from mnemonic import Mnemonic  # type: ignore
except ImportError:
    Mnemonic = None  # type: ignore

try:
    import nacl.signing  # type: ignore
except ImportError:
    nacl = None  # type: ignore


ED25519_MASTER_KEY = b"ed25519 seed"
HARDENED_OFFSET = 0x80000000
# Default derivation path for the member identity (all hardened, Ed25519-required)
DEFAULT_PATH = "m/44'/9004'/0'/0'/0'"


class RecoveryMaterial(NamedTuple):
    """Returned by generate_recovery() and recover_from_mnemonic().

    Every field is base64-encoded for transport; mnemonic is the 24-word
    phrase the user writes down.
    """

    mnemonic: str
    private_key_b64: str
    public_key_b64: str
    did_key: str
    derivation_path: str


def _require_mnemonic_lib() -> None:
    if Mnemonic is None:
        raise RuntimeError(
            "mnemonic library not installed. It is a core dependency, so this "
            "install is incomplete: pip install -e . from the agent/ directory."
        )


def _require_nacl() -> None:
    if nacl is None:
        raise RuntimeError(
            "pynacl not installed. It is a core dependency, so this install is "
            "incomplete: pip install -e . from the agent/ directory."
        )


def generate_mnemonic(strength: int = 256) -> str:
    """Generate a fresh BIP39 mnemonic.

    Args:
        strength: entropy bits. 256 → 24 words (recommended for Ed25519
                  identities); 128 → 12 words (shorter but less entropy).
                  Must be one of {128, 160, 192, 224, 256}.

    Returns:
        Space-separated BIP39 phrase. Caller is responsible for showing
        it exactly once and never persisting to disk.
    """
    _require_mnemonic_lib()
    if strength not in (128, 160, 192, 224, 256):
        raise ValueError(f"strength must be one of {{128,160,192,224,256}}, got {strength}")
    return Mnemonic("english").generate(strength=strength)


def validate_mnemonic(phrase: str) -> bool:
    """Return True iff phrase is a valid BIP39 English mnemonic."""
    _require_mnemonic_lib()
    return bool(Mnemonic("english").check(phrase.strip()))


def mnemonic_to_seed(phrase: str, passphrase: str = "") -> bytes:
    """BIP39 seed derivation: PBKDF2-HMAC-SHA512(phrase, 'mnemonic'+passphrase, 2048, 64 bytes)."""
    _require_mnemonic_lib()
    normalized = phrase.strip()
    if not validate_mnemonic(normalized):
        raise ValueError("invalid BIP39 mnemonic")
    return Mnemonic("english").to_seed(normalized, passphrase=passphrase)


def _slip10_master(seed: bytes) -> tuple[bytes, bytes]:
    """SLIP-0010 master key derivation for Ed25519.

    Loops until the derived left half is non-zero and within curve order,
    but for Ed25519 SLIP-0010 mandates unconditional accept of the first
    iteration. The spec notes this curve doesn't have the "retry" case.
    """
    i = hmac.new(ED25519_MASTER_KEY, seed, hashlib.sha512).digest()
    il, ir = i[:32], i[32:]
    return il, ir


def _slip10_ckd_priv(k_par: bytes, c_par: bytes, index: int) -> tuple[bytes, bytes]:
    """SLIP-0010 Ed25519 child key derivation (hardened only).

    Per spec: data = 0x00 || k_par || ser32(i), then HMAC-SHA512(c_par, data).
    Ed25519 supports ONLY hardened derivation — index must have the
    hardened bit set (index >= 2**31).
    """
    if index < HARDENED_OFFSET:
        raise ValueError(f"Ed25519 supports hardened derivation only; index {index} < 2**31")
    data = b"\x00" + k_par + index.to_bytes(4, "big")
    i = hmac.new(c_par, data, hashlib.sha512).digest()
    il, ir = i[:32], i[32:]
    return il, ir


def _parse_path(path: str) -> list[int]:
    """Parse 'm/44'/9004'/0'/0'/0'' → [2**31+44, 2**31+9004, ...]."""
    if not path.startswith("m/"):
        raise ValueError("path must start with 'm/'")
    parts = path[2:].split("/")
    indices = []
    for p in parts:
        if not p.endswith("'"):
            raise ValueError(f"Ed25519 requires hardened derivation; got unhardened {p!r}")
        indices.append(HARDENED_OFFSET + int(p.rstrip("'")))
    return indices


def derive_ed25519_keypair(seed: bytes, path: str = DEFAULT_PATH) -> tuple[bytes, bytes]:
    """SLIP-0010 Ed25519 derivation from a BIP39 seed + hardened path.

    Returns (private_key_32_bytes, public_key_32_bytes).
    """
    _require_nacl()
    priv, chain = _slip10_master(seed)
    for index in _parse_path(path):
        priv, chain = _slip10_ckd_priv(priv, chain, index)

    signing_key = nacl.signing.SigningKey(priv)
    verify_key = signing_key.verify_key
    return priv, bytes(verify_key)


def _build_did_key(pub: bytes) -> str:
    """did:key for Ed25519 per the W3C spec: 'did:key:z' + base58btc(0xed01 || pubkey).

    Uses the multibase/multicodec encoding consistent with community_member.crypto.build_did_key.
    """
    # Import locally so this module can be imported without nacl if only
    # mnemonic funcs are called.
    try:
        from community_member.crypto import build_did_key

        return build_did_key(base64.b64encode(pub).decode())
    except ImportError:
        # Fallback: plain base64url — NOT canonical did:key but unambiguous
        return "did:key:z" + base64.urlsafe_b64encode(b"\xed\x01" + pub).decode().rstrip("=")


def generate_recovery(
    strength: int = 256,
    path: str = DEFAULT_PATH,
    passphrase: str = "",
) -> RecoveryMaterial:
    """Generate a fresh recovery material: new mnemonic + derived Ed25519 keypair + did:key.

    CRITICAL: the returned mnemonic is the ONLY way to recover this keypair.
    Show it to the user exactly once; do not log it, do not write it to disk
    yourself. The community-member desktop wizard handles the UX (show →
    confirm re-entry → encrypt with OS keychain).
    """
    phrase = generate_mnemonic(strength)
    return recover_from_mnemonic(phrase, path=path, passphrase=passphrase)


def recover_from_mnemonic(
    phrase: str,
    path: str = DEFAULT_PATH,
    passphrase: str = "",
) -> RecoveryMaterial:
    """Recover Ed25519 keypair + did:key from an existing BIP39 mnemonic.

    Deterministic: same (phrase, path, passphrase) → same keypair every time.
    """
    seed = mnemonic_to_seed(phrase, passphrase=passphrase)
    priv, pub = derive_ed25519_keypair(seed, path=path)
    return RecoveryMaterial(
        mnemonic=phrase,
        private_key_b64=base64.b64encode(priv).decode(),
        public_key_b64=base64.b64encode(pub).decode(),
        did_key=_build_did_key(pub),
        derivation_path=path,
    )


def secure_wipe(data: bytes | bytearray) -> None:
    """Best-effort zero-out of a mutable byte buffer.

    Python's immutable bytes can't be wiped. Use bytearray for secrets
    that need post-use scrubbing. This is defense-in-depth — the OS can
    still swap, the GC can still copy. Real secret-erasure needs C-level
    work or hardware enclaves.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0


__all__ = [
    "DEFAULT_PATH",
    "RecoveryMaterial",
    "derive_ed25519_keypair",
    "generate_mnemonic",
    "generate_recovery",
    "mnemonic_to_seed",
    "recover_from_mnemonic",
    "secure_wipe",
    "validate_mnemonic",
]
