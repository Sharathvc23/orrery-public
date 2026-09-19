"""SigningAdapter that delegates to a non-Python CLI per CLI_ADAPTER.md.

Adopters in Rust, Go, TypeScript, Swift, etc. ship a single executable
that exposes the six subcommands documented in
``conformance/client/adapters/CLI_ADAPTER.md`` §4. This module presents
that CLI to pytest as a standard ``SigningAdapter``, so the entire
client conformance suite runs against the non-Python runtime through
``--adapter=cli-shell``.

Selection:

    export CONFORMANCE_CLI_ADAPTER_CMD=/path/to/mysigner
    pytest conformance/client/ --adapter=cli-shell

Exit-code semantics (per CLI_ADAPTER.md §5):

    0   success — stdout is the documented output
    64  subcommand not implemented (v0.3 on a v0.2-only adapter, etc.)
        — translated into ``NotImplementedError``, which the v0.3 tests
        catch and skip rather than fail
    65  malformed input — surfaced as ``ValueError``
    70  internal error — surfaced as ``RuntimeError``
    other  treated as opaque failure — ``RuntimeError`` with stderr

The wrapper is **deliberately thin**: it does not parse, validate, or
re-canonicalize CLI output. The point is to let the conformance suite
catch CLI bugs by treating its output as ground truth and comparing
against the spec's vectors. If the CLI emits a malformed canonical
string, the canonical-string test will fail with a clear diff against
the vector — that is the conformance feedback the adopter needs.
"""

from __future__ import annotations

import json
import os
import subprocess

CONTRACT_VERSION: int = 1

# Per CLI_ADAPTER.md §5 — BSD sysexits(3)-aligned.
EXIT_NOT_IMPLEMENTED: int = 64
EXIT_MALFORMED_INPUT: int = 65
EXIT_INTERNAL_ERROR: int = 70


class CLIAdapterError(RuntimeError):
    """Raised when a CLI subcommand fails for a reason that isn't
    'not-implemented'. Carries the CLI's stderr verbatim for diagnosis.
    """


class CLIShellAdapter:
    """Wrap a non-Python signing CLI as a ``SigningAdapter``.

    The CLI path is read from ``CONFORMANCE_CLI_ADAPTER_CMD`` at
    construction time. The adapter is stateless across calls; each
    method spawns a fresh subprocess.
    """

    name: str = "cli-shell"

    def __init__(self, cli_cmd: str | None = None) -> None:
        cmd = cli_cmd if cli_cmd is not None else os.environ.get("CONFORMANCE_CLI_ADAPTER_CMD")
        if not cmd:
            raise RuntimeError(
                "cli-shell adapter requires CONFORMANCE_CLI_ADAPTER_CMD env var "
                "(or cli_cmd ctor arg) pointing at the runtime's signing CLI. "
                "See conformance/client/adapters/CLI_ADAPTER.md for the contract."
            )
        self._cmd = cmd
        # runtime_path encodes the contract version so badge reports
        # record which contract the runtime implemented.
        self.runtime_path = f"cli-shell@v{CONTRACT_VERSION}:{cmd}"

    # ------------------------------------------------------------------
    # Internal subprocess helper.
    # ------------------------------------------------------------------

    def _run(self, *args: str, stdin: bytes | None = None) -> str:
        """Run the CLI with the given subcommand args + optional stdin.

        Returns stdout (decoded, with trailing newline stripped). Raises
        ``NotImplementedError`` on exit 64, ``ValueError`` on 65,
        ``CLIAdapterError`` on anything else non-zero.
        """
        completed = subprocess.run(  # noqa: S603 — adopter-controlled CLI by design
            [self._cmd, *args],
            input=stdin,
            capture_output=True,
            check=False,
        )
        if completed.returncode == 0:
            return completed.stdout.decode("utf-8").rstrip("\n")
        if completed.returncode == EXIT_NOT_IMPLEMENTED:
            raise NotImplementedError(
                f"CLI {self._cmd} reports subcommand not implemented "
                f"({' '.join(args[:1])}); v0.3 tests will skip per the contract."
            )
        if completed.returncode == EXIT_MALFORMED_INPUT:
            raise ValueError(
                f"CLI {self._cmd} rejected malformed input "
                f"(exit 65): {completed.stderr.decode('utf-8', errors='replace')[:200]}"
            )
        raise CLIAdapterError(
            f"CLI {self._cmd} {' '.join(args[:1])} failed with exit "
            f"{completed.returncode}: "
            f"{completed.stderr.decode('utf-8', errors='replace')[:500]}"
        )

    # ------------------------------------------------------------------
    # SigningAdapter v0.2 surface.
    # ------------------------------------------------------------------

    def derive_did_key(self, pubkey32: bytes) -> str:
        if len(pubkey32) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pubkey32)}")
        return self._run("derive-did-key", pubkey32.hex())

    def canonical_string(self, body: str, agent_id: str, timestamp: str) -> str:
        return self._run("canonical-string-v02", agent_id, timestamp, stdin=body.encode("utf-8"))

    def sign(self, private_key32: bytes, canonical: str) -> str:
        if len(private_key32) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(private_key32)}")
        return self._run("sign", private_key32.hex(), stdin=canonical.encode("utf-8"))

    def compose_headers(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        signature_b64: str,
    ) -> dict[str, str]:
        raw = self._run("compose-headers-v02", agent_id, did_key, timestamp, signature_b64)
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise CLIAdapterError(f"compose-headers-v02 must return a JSON object, got {raw!r}")
        return {str(k): str(v) for k, v in parsed.items()}

    # ------------------------------------------------------------------
    # SigningAdapter v0.3 surface.
    # ------------------------------------------------------------------

    def canonical_string_v03(
        self,
        method: str,
        url_path: str,
        body: str,
        agent_id: str,
        timestamp: str,
        nonce: str,
    ) -> str:
        return self._run(
            "canonical-string-v03",
            method,
            url_path,
            agent_id,
            timestamp,
            nonce,
            stdin=body.encode("utf-8"),
        )

    def compose_headers_v03(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        nonce: str,
        signature_b64: str,
    ) -> dict[str, str]:
        raw = self._run(
            "compose-headers-v03",
            agent_id,
            did_key,
            timestamp,
            nonce,
            signature_b64,
        )
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise CLIAdapterError(f"compose-headers-v03 must return a JSON object, got {raw!r}")
        return {str(k): str(v) for k, v in parsed.items()}
