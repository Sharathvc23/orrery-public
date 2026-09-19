#!/usr/bin/env python3
"""Ed25519-sign outbound requests to org endpoints.

Implements the v0.3 wire-protocol contract for the org
Protocol (request signing + did:key derivation). Verified against
the protocol's vector-based conformance suite on every change.

Usage (from the OpenClaw agent's tool-call)::

    python helpers/sign_request.py \\
      --method POST \\
      --url "https://<org-url>/api/feedback" \\
      --body '{"action_id":"...","signal":"positive","agent_id":"..."}' \\
      --agent-id "claw-user-7f3a"

To avoid putting request bodies on the process command line (visible
to other users via ``ps``), pass the body via ``--body-file <path>``
or pipe it to stdin and pass ``--body-stdin``.

Output (JSON to stdout)::

    {"method":..., "url":..., "status":..., "headers_sent":{...},
     "response":..., "did_key":...}

Errors go to stderr; exit code is non-zero on failure.

Identity is stored at ``$OPENCLAW_HOME/skills/orrery-org/identity.json``
(default: ``~/.openclaw/skills/orrery-org/identity.json``). The first
invocation generates an Ed25519 keypair; every subsequent call reuses
the same identity. ``did:key`` is derived from the public key per W3C
spec (base58btc multibase, multicodec prefix ``0xed01``).

Security hardening (v0.5.0):

  - ``$OPENCLAW_HOME`` is validated to resolve under the calling
    user's home directory; refuses to start if redirected elsewhere.
  - Identity and audit files are created with O_CREAT|O_EXCL|O_WRONLY
    + mode 0o600 atomically — no umask race window.
  - ``did_key`` is re-derived from the loaded public key on every load
    and cross-checked against the value stored on disk; an attacker
    cannot swap PEM and stored did_key independently.
  - Non-HTTPS URLs (``http://``, ``file://``, etc.) are refused.
  - The target host must appear in the HMAC-signed org cache
    (built by ``discover_org.py``) unless ``--trust-host`` is
    explicitly passed. This makes ``sign_request.py`` reject ad-hoc
    signing-oracle requests for hosts the agent has not deliberately
    joined.
  - Signed requests do NOT follow HTTP redirects; a 3xx response is
    surfaced as-is so a captured signature cannot be silently
    re-targeted by a hostile or compromised org.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import base58
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ED25519_MULTICODEC_PREFIX = b"\xed\x01"

# Sent on every signed request so the org can quarantine outdated
# clients server-side. The org rejects openclaw-origin requests
# carrying a version below its configured minimum with HTTP 426 and an
# upgrade-command in the response body. See SECURITY.md.
OPENCLAW_SKILL_VERSION = "0.6.1"


def _resolve_openclaw_home() -> Path:
    """Return the OPENCLAW_HOME directory, after validating it.

    The directory MUST resolve under the calling user's home directory.
    A symlink that escapes home, or an explicit env value pointing
    outside home, is rejected with a clear stderr message and exit 1
    — this prevents an attacker who can set process env from
    redirecting identity-dir lookups to a directory under their
    control.
    """
    raw = os.environ.get("OPENCLAW_HOME", str(Path.home() / ".openclaw"))
    candidate = Path(raw).expanduser().resolve()
    home = Path.home().resolve()
    try:
        candidate.relative_to(home)
    except ValueError:
        print(
            json.dumps(
                {
                    "error": "openclaw_home_outside_user_home",
                    "openclaw_home": str(candidate),
                    "user_home": str(home),
                    "detail": (
                        "$OPENCLAW_HOME must resolve under the calling "
                        "user's home directory. Refusing to start."
                    ),
                }
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    return candidate


# Resolve once at import time so child helpers see the validated path.
OPENCLAW_HOME = _resolve_openclaw_home()
IDENTITY_DIR = OPENCLAW_HOME / "skills" / "orrery-org"
IDENTITY_FILE = IDENTITY_DIR / "identity.json"


def _build_did_key(pubkey_bytes: bytes) -> str:
    """Derive ``did:key:z<base58btc(0xed01||pubkey)>`` per W3C did:key spec.

    Reference: the org protocol v0.3 (did:key derivation).
    """
    if len(pubkey_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pubkey_bytes)}")
    prefixed = ED25519_MULTICODEC_PREFIX + pubkey_bytes
    return f"did:key:z{base58.b58encode(prefixed).decode()}"


def _atomic_write_0600(path: Path, content: str) -> None:
    """Create ``path`` with mode 0o600 atomically; fail if it exists.

    Uses ``os.open(O_CREAT | O_EXCL | O_WRONLY, 0o600)`` so the file is
    created with restrictive permissions BEFORE any bytes are written —
    closing the TOCTOU window that ``Path.write_text`` + ``os.chmod``
    used to leave open (where the file was briefly readable per umask).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass  # non-POSIX
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except Exception:
        # If write failed mid-flight, drop the truncated file rather
        # than leave a half-written identity file that subsequent runs
        # would refuse to overwrite.
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _replace_0600(path: Path, content: str) -> None:
    """Replace an existing file's contents, forcing mode 0o600.

    ``_atomic_write_0600`` uses ``O_EXCL`` and so cannot rewrite a file that
    already exists. The explicit ``chmod`` is required because ``O_CREAT``'s
    mode argument is ignored for an existing file — an identity file written
    by a build predating the 0600 change would otherwise keep its old mode.
    """
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # non-POSIX


# ── Identity-key encryption at rest (H3) ──────────────────────────────────────
# The identity file holds the Ed25519 private key that signs every request this
# skill makes. Setting ORRERY_SKILL_KEY_PASSPHRASE stores it as an ENCRYPTED
# PKCS8 PEM (PBES2/AES via cryptography's BestAvailableEncryption) instead of a
# plaintext one; an existing plaintext key is re-encrypted in place on the next
# run, keeping the same key so did:key does not change.
#
# SCOPE, stated precisely because the file mode already implies more than it
# delivers: this closes exposure of the key through a disk image, a filesystem
# backup, or a host snapshot. It does NOT close the threat skill/SECURITY.md
# lists under "what the skill does not defend against" — a process running as
# the same uid, or as root, can read the passphrase out of the environment it
# would have to be supplied in. That is why it is opt-in rather than required:
# making it mandatory would relocate the secret rather than protect it, and
# would break every existing install for no change in that threat.
_PASSPHRASE_ENV = "ORRERY_SKILL_KEY_PASSPHRASE"
_ENCRYPTED_PEM_MARKER = "BEGIN ENCRYPTED PRIVATE KEY"


def _key_passphrase() -> str:
    """The configured identity passphrase, or ``""`` when unset/whitespace."""
    return os.environ.get(_PASSPHRASE_ENV, "").strip()


def _pem_is_encrypted(priv_pem: str) -> bool:
    return _ENCRYPTED_PEM_MARKER in priv_pem


def _serialize_private_key(priv: Ed25519PrivateKey, passphrase: str) -> str:
    """PKCS8 PEM for ``priv``, encrypted under ``passphrase`` when one is set."""
    algorithm: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=algorithm,
    ).decode()


def _deserialize_private_key(priv_pem: str) -> Ed25519PrivateKey:
    """Load a stored PKCS8 PEM, supplying the passphrase when it is encrypted."""
    passphrase = _key_passphrase()
    if _pem_is_encrypted(priv_pem) and not passphrase:
        raise ValueError(
            f"{IDENTITY_FILE} holds an ENCRYPTED private key but {_PASSPHRASE_ENV} "
            "is not set — cannot load the identity. Set it to the passphrase the "
            "key was encrypted with."
        )
    password = passphrase.encode() if _pem_is_encrypted(priv_pem) else None
    priv = serialization.load_pem_private_key(priv_pem.encode(), password=password)
    if not isinstance(priv, Ed25519PrivateKey):
        raise TypeError("identity file does not contain an Ed25519 key")
    return priv


def _encrypt_identity_in_place(data: dict[str, Any], priv: Ed25519PrivateKey) -> None:
    """Re-store a plaintext identity file encrypted, once a passphrase exists.

    Encrypting only NEWLY generated identities would leave every key created
    before this change in the clear while the code read as fixed. The key bytes
    are unchanged — only their on-disk encoding — so ``did_key`` is the same and
    nothing the agent has registered needs to be re-registered.
    """
    passphrase = _key_passphrase()
    if not passphrase or _pem_is_encrypted(data["private_key_pem"]):
        return
    updated = dict(data)
    updated["private_key_pem"] = _serialize_private_key(priv, passphrase)
    try:
        _replace_0600(IDENTITY_FILE, json.dumps(updated, indent=2))
    except OSError as e:
        print(
            f"warning: {IDENTITY_FILE} holds an UNENCRYPTED private key and the "
            f"re-encrypt failed ({type(e).__name__}: {e}); retrying next run",
            file=sys.stderr,
        )


def _atomic_append_0600(path: Path, line: str) -> None:
    """Append a line to ``path``; create with 0o600 if missing.

    Same TOCTOU concern as ``_atomic_write_0600`` for first-append.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        # First append: create atomically with restrictive mode.
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(line)
        return
    with path.open("a") as f:
        f.write(line)


def _load_or_create_identity() -> tuple[Ed25519PrivateKey, bytes, str]:
    """Load the skill's Ed25519 identity, generating it on first call.

    Returns ``(private_key, public_key_bytes, did_key)``.

    On load, ``did_key`` is RE-DERIVED from the loaded public key and
    cross-checked against the value stored in the identity file.
    A mismatch indicates the file was tampered with (someone swapped
    PEM and did_key in a way that doesn't match) — the function
    raises rather than continuing with an inconsistent identity.
    """
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(IDENTITY_DIR, 0o700)
    except OSError:
        pass  # non-POSIX

    if IDENTITY_FILE.exists():
        data = json.loads(IDENTITY_FILE.read_text())
        priv = _deserialize_private_key(data["private_key_pem"])
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        derived_did = _build_did_key(pub_bytes)
        stored_did = data.get("did_key", "")
        if derived_did != stored_did:
            raise ValueError(
                "identity.json did_key does not match the key derived "
                "from private_key_pem — file has been tampered with. "
                "Refusing to use this identity. Inspect "
                f"{IDENTITY_FILE} and re-create if needed."
            )
        # Only after the did_key cross-check passes — never rewrite a file that
        # failed the tamper check.
        _encrypt_identity_in_place(data, priv)
        return priv, pub_bytes, derived_did

    # First run — generate.
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    did_key = _build_did_key(pub_bytes)
    priv_pem = _serialize_private_key(priv, _key_passphrase())

    _atomic_write_0600(
        IDENTITY_FILE,
        json.dumps(
            {
                "did_key": did_key,
                "private_key_pem": priv_pem,
                "public_key_b64": base64.b64encode(pub_bytes).decode(),
                "created_at": int(time.time()),
            },
            indent=2,
        ),
    )
    return priv, pub_bytes, did_key


def canonical_string_v02(body: str, agent_id: str, timestamp: str) -> str:
    """v0.2 canonical string: ``body:agent_id:timestamp`` (spec/0.2/signing.md)."""
    return f"{body}:{agent_id}:{timestamp}"


def canonical_string_v03(
    method: str, url_path: str, body: str, agent_id: str, timestamp: str, nonce: str
) -> str:
    """v0.3 canonical: ``METHOD:url_path:body:agent_id:timestamp:nonce`` (spec/0.3/signing.md)."""
    return f"{method.upper()}:{url_path}:{body}:{agent_id}:{timestamp}:{nonce}"


def ed25519_sign(priv: Ed25519PrivateKey, canonical: str) -> str:
    """Sign the canonical string; standard base64 of the 64-byte Ed25519 signature."""
    return base64.b64encode(priv.sign(canonical.encode())).decode()


def compose_signed_headers_v02(
    agent_id: str, did_key: str, timestamp: str, signature_b64: str
) -> dict[str, str]:
    """v0.2 ``ed25519`` header set."""
    return {
        "Content-Type": "application/json",
        "X-Agent-ID": agent_id,
        "X-Agent-DID-Key": did_key,
        "X-Agent-Sig-Scheme": "ed25519",
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Signature": signature_b64,
        "X-Openclaw-Skill-Version": OPENCLAW_SKILL_VERSION,
    }


def compose_signed_headers_v03(
    agent_id: str, did_key: str, timestamp: str, nonce: str, signature_b64: str
) -> dict[str, str]:
    """v0.3 ``ed25519+nonce`` header set."""
    return {
        "Content-Type": "application/json",
        "X-Agent-ID": agent_id,
        "X-Agent-DID-Key": did_key,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": signature_b64,
        "X-Openclaw-Skill-Version": OPENCLAW_SKILL_VERSION,
    }


def _signed_headers(
    priv: Ed25519PrivateKey,
    did_key: str,
    agent_id: str,
    body: str,
    *,
    scheme: str,
    method: str = "",
    url_path: str = "",
) -> dict[str, str]:
    """Build the signed-request header set.

    ``scheme`` is REQUIRED and selects the protocol version. There is
    no default — every caller must explicitly pick v0.3 (the standard)
    or v0.2 (back-compat for orgs that haven't migrated).

      - ``"ed25519+nonce"`` (v0.3): canonical is
        ``f"{method}:{url_path}:{body}:{agent_id}:{timestamp}:{nonce}"``.
        Adds X-Agent-Nonce (32 random bytes, base64) so the org
        can enforce per-request uniqueness.
      - ``"ed25519"`` (v0.2): canonical is ``f"{body}:{agent_id}:{timestamp}"``.
        Method and url_path ignored.
    """
    if scheme not in ("ed25519", "ed25519+nonce"):
        raise ValueError(f"unsupported signing scheme: {scheme!r}")
    timestamp = str(int(time.time()))
    if scheme == "ed25519+nonce":
        nonce = base64.b64encode(os.urandom(32)).decode()
        canonical = canonical_string_v03(method, url_path, body, agent_id, timestamp, nonce)
        signature_b64 = ed25519_sign(priv, canonical)
        return compose_signed_headers_v03(agent_id, did_key, timestamp, nonce, signature_b64)
    canonical = canonical_string_v02(body, agent_id, timestamp)
    signature_b64 = ed25519_sign(priv, canonical)
    return compose_signed_headers_v02(agent_id, did_key, timestamp, signature_b64)


# Audit ledger maintains a sidecar "tip" file with the last hash + count
# so append is O(1) instead of O(n) — see _audit_append.
_AUDIT_TIP_NAME = "audit.tip"


def _audit_append(
    method: str,
    url: str,
    status: int,
    response_hash: str,
    *,
    sign_with: Ed25519PrivateKey | None = None,
) -> None:
    """Hash-chained append to audit.jsonl for forgery-detection.

    The chain is local to this skill instance; it does not need to
    match the org's audit ledger. Its purpose is per-instance
    tamper detection — useful when the skill ships with multiple
    agents on one OpenClaw gateway.

    Performance: maintains ``audit.tip`` alongside ``audit.jsonl``
    containing the last hash and entry count, so we never need to
    re-scan the whole ledger to find the previous hash. The full
    ledger remains the source of truth for verification (R10).
    """
    audit_path = IDENTITY_DIR / "audit.jsonl"
    tip_path = IDENTITY_DIR / _AUDIT_TIP_NAME

    prev_hash = "0" * 64
    if tip_path.exists():
        try:
            tip_data = json.loads(tip_path.read_text())
            tip_hash = tip_data.get("hash")
            if isinstance(tip_hash, str) and len(tip_hash) == 64:
                prev_hash = tip_hash
        except (OSError, json.JSONDecodeError):
            pass  # corrupt tip → recompute from ledger below
    elif audit_path.exists():
        # Migration: ledger exists but no tip. Recompute once.
        last_hash = "0" * 64
        with audit_path.open() as f:
            for line in f:
                if line.strip():
                    try:
                        last_hash = json.loads(line).get("hash", last_hash)
                    except json.JSONDecodeError:
                        continue
        prev_hash = last_hash

    entry = {
        "ts": int(time.time()),
        "method": method,
        "url": url,
        "status": status,
        "response_sha256": response_hash,
        "prev_hash": prev_hash,
    }
    entry["hash"] = hashlib.sha256(
        f"{entry['ts']}:{method}:{url}:{status}:{response_hash}:{prev_hash}".encode()
    ).hexdigest()
    # Per-entry Ed25519 signature over hash — a whole-chain rewrite is
    # detectable because the attacker would have to re-sign every
    # entry, which requires the identity private key. Without sign_with,
    # the audit still chains (back-compat) but loses signature
    # protection; callers should always pass sign_with in production.
    if sign_with is not None:
        entry_hash = str(entry["hash"])
        sig = sign_with.sign(entry_hash.encode())
        entry["sig"] = base64.b64encode(sig).decode()
    _atomic_append_0600(audit_path, json.dumps(entry) + "\n")

    # Update the tip file. Best-effort — a missing tip is recoverable
    # from the ledger on the next append (migration branch above).
    try:
        tip_path.write_text(json.dumps({"hash": entry["hash"]}))
        try:
            os.chmod(tip_path, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def _read_body(args: argparse.Namespace) -> str:
    """Resolve the request body from ``--body``, ``--body-file``, or
    ``--body-stdin``. Returns "" if none provided.

    ``--body`` puts the body on the process command line where any
    user on the host can see it via ``ps auxww``. ``--body-file`` and
    ``--body-stdin`` are the safe options on shared hosts; ``--body``
    still works but emits a stderr warning.
    """
    sources_used = sum(1 for x in (args.body, args.body_file, args.body_stdin) if x)
    if sources_used > 1:
        raise SystemExit("only one of --body, --body-file, --body-stdin may be given")
    if args.body_stdin:
        return sys.stdin.read()
    if args.body_file:
        return Path(args.body_file).read_text()
    if args.body:
        print(
            "[warning] --body puts request content on argv (visible to "
            "other users via ps). Prefer --body-file or --body-stdin "
            "on shared hosts.",
            file=sys.stderr,
        )
        return str(args.body)
    return ""


def _allowlisted_hosts() -> set[str]:
    """Return the set of hosts the skill has discovered + recorded.

    Reads the HMAC-signed org cache produced by
    ``discover_org.py``. If the cache MAC fails to verify the
    cache is treated as empty (fail-closed) — refusing to sign rather
    than relying on a forged allowlist.
    """
    try:
        from _cache_signing import load_signed_cache
    except ImportError:
        # _cache_signing.py is a sibling module in helpers/. Add
        # helpers/ to path so we can import it whether called as a
        # script or imported as a module.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from _cache_signing import load_signed_cache

    orgs = load_signed_cache(IDENTITY_DIR / "org-cache.json", IDENTITY_FILE)
    hosts: set[str] = set()
    for ch in orgs or []:
        endpoint = ch.get("endpoint", "") if isinstance(ch, dict) else ""
        if endpoint:
            try:
                hosts.add(httpx.URL(endpoint).host)
            except (TypeError, ValueError):
                continue
    return hosts


def _enforce_url_policy(url: str, trust_host: bool) -> str:
    """Validate ``url`` is acceptable for a signed request.

    Returns the URL unchanged on success. Raises ``SystemExit`` with a
    JSON error on stderr otherwise.

    Two checks:

      1. Scheme must be ``https://``. Plain HTTP exposes the signature
         in transit (any on-path observer can capture and replay
         within the timestamp window); other schemes (file://, etc.)
         make no sense for an org call.
      2. Host must be in the allowlist (signed org cache) unless
         the caller explicitly passed ``--trust-host``. Without this
         check, ``sign_request.py`` acts as a signing oracle: an
         attacker tricks the user into signing for ``attacker.example``
         and replays the signature against a real org at the same
         path. (Real orgs don't bind host into the canonical
         string per spec/0.3/signing.md to preserve DNS-migration
         portability, so the protective layer must live in the
         client.)
    """
    parsed = httpx.URL(url)
    if parsed.scheme != "https":
        print(
            json.dumps(
                {
                    "error": "non_https_url_refused",
                    "scheme": parsed.scheme,
                    "url": url,
                    "detail": (
                        "Signed requests must use https://. Refusing to "
                        "sign for plain HTTP or other schemes."
                    ),
                }
            ),
            file=sys.stderr,
        )
        sys.exit(2)
    if trust_host:
        return url
    host = parsed.host
    allowed = _allowlisted_hosts()
    if host not in allowed:
        print(
            json.dumps(
                {
                    "error": "host_not_in_org_allowlist",
                    "host": host,
                    "allowlist": sorted(allowed),
                    "detail": (
                        "This host is not in the signed org cache. "
                        "Run `python helpers/discover_org.py` first "
                        "to register the org, or pass --trust-host "
                        "for an explicit one-off (signing oracle "
                        "protection — see SECURITY.md)."
                    ),
                }
            ),
            file=sys.stderr,
        )
        sys.exit(2)
    return url


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--method", required=True, help="HTTP method (POST, GET, ...).")
    p.add_argument("--url", required=True, help="Full org URL (https://...).")
    p.add_argument(
        "--body",
        default="",
        help=(
            "Request body inline. UNSAFE on shared hosts (argv visible); "
            "prefer --body-file or --body-stdin."
        ),
    )
    p.add_argument(
        "--body-file",
        default="",
        help="Path to a file containing the request body. Preferred on shared hosts.",
    )
    p.add_argument(
        "--body-stdin",
        action="store_true",
        help="Read the request body from stdin. Preferred on shared hosts.",
    )
    p.add_argument(
        "--agent-id",
        required=True,
        help="Org-assigned agent_id. Required header per the protocol signing spec.",
    )
    p.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout in seconds.")
    p.add_argument(
        "--scheme",
        default="ed25519+nonce",
        choices=("ed25519", "ed25519+nonce"),
        help=(
            "Signing scheme. `ed25519+nonce` (default, v0.3 — binds "
            "method+url_path+nonce per spec/0.3/signing.md) or `ed25519` "
            "(v0.2 fallback for older orgs). v0.3-capable orgs "
            "advertise both in GET /api/version."
        ),
    )
    p.add_argument(
        "--trust-host",
        action="store_true",
        help=(
            "Skip the org-cache allowlist check. ONLY for ad-hoc "
            "testing against a private org you control — emits a "
            "stderr warning when used. Otherwise the cached allowlist "
            "blocks signing-oracle attacks where an attacker tricks "
            "you into signing for a hostile host."
        ),
    )
    args = p.parse_args()

    # Enforce URL policy FIRST — before reading the body or printing
    # any warning. A rejected URL must not produce side effects (no
    # argv-warning, no stdin slurp) that could mislead the caller.
    _enforce_url_policy(args.url, args.trust_host)
    body = _read_body(args)
    if args.trust_host:
        print(
            f"[warning] --trust-host bypass active for {args.url!r}; "
            "signature will be produced for a host outside the org "
            "allowlist.",
            file=sys.stderr,
        )

    parsed = httpx.URL(args.url)
    url_path = parsed.path
    if parsed.query:
        q = parsed.query.decode() if isinstance(parsed.query, bytes) else parsed.query
        url_path = f"{url_path}?{q}"

    priv, _pub, did_key = _load_or_create_identity()
    headers = _signed_headers(
        priv,
        did_key,
        args.agent_id,
        body,
        scheme=args.scheme,
        method=args.method,
        url_path=url_path,
    )

    try:
        # follow_redirects=False — a 3xx from a hostile or compromised
        # org must NOT silently re-target a signed request to a
        # different host. The caller sees the 3xx and decides.
        resp = httpx.request(
            args.method.upper(),
            args.url,
            content=body if body else None,
            headers=headers,
            timeout=args.timeout,
            follow_redirects=False,
        )
    except httpx.HTTPError as e:
        print(json.dumps({"error": f"network: {e}"}), file=sys.stderr)
        return 1

    response_text = resp.text
    response_hash = hashlib.sha256(response_text.encode()).hexdigest()
    _audit_append(args.method, args.url, resp.status_code, response_hash, sign_with=priv)

    print(
        json.dumps(
            {
                "method": args.method,
                "url": args.url,
                "status": resp.status_code,
                "headers_sent": {k: v for k, v in headers.items() if k != "X-Agent-Signature"},
                "response": response_text[:8000],
                "did_key": did_key,
            },
            indent=2,
        )
    )
    return 0 if 200 <= resp.status_code < 300 else 1


if __name__ == "__main__":
    sys.exit(main())
