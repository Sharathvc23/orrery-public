"""Demonstrator CLI implementing the CLI_ADAPTER.md v1 contract in Python.

This is **not** a production binary — it is a reference implementation
that adopters in other languages can read alongside CLI_ADAPTER.md to
see the exact byte-for-byte behavior expected from each subcommand.
It delegates everything to ``spec_reference`` so any drift between this
CLI's output and the rest of the conformance suite is impossible.

The same CLI is the test fixture for ``conformance/test_cli_adapter.py``
which spawns it under ``cli-shell`` and runs assertions through.

Usage (matches CLI_ADAPTER.md §4 exactly)::

    python -m conformance.client.adapters._demo_cli derive-did-key <hex>
    printf '%s' '<body>' | python -m conformance.client.adapters._demo_cli \\
        canonical-string-v02 <agent_id> <timestamp>
    printf '%s' '<body>' | python -m conformance.client.adapters._demo_cli \\
        canonical-string-v03 <method> <url_path> <agent_id> <timestamp> <nonce>
    printf '%s' '<canonical>' | python -m conformance.client.adapters._demo_cli \\
        sign <key-hex>
    python -m conformance.client.adapters._demo_cli compose-headers-v02 \\
        <agent_id> <did_key> <timestamp> <sig_b64>
    python -m conformance.client.adapters._demo_cli compose-headers-v03 \\
        <agent_id> <did_key> <timestamp> <nonce> <sig_b64>
"""

from __future__ import annotations

import json
import sys

from conformance.client.adapters.spec_reference import SpecReferenceAdapter

EXIT_OK = 0
EXIT_NOT_IMPLEMENTED = 64
EXIT_MALFORMED_INPUT = 65
EXIT_INTERNAL_ERROR = 70


def _read_stdin_bytes() -> bytes:
    """Read all of stdin as bytes. Empty stdin returns ``b''``."""
    return sys.stdin.buffer.read()


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: <subcommand> [args...]", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    subcommand, rest = args[0], args[1:]
    adapter = SpecReferenceAdapter()

    try:
        if subcommand == "derive-did-key":
            (pubkey_hex,) = rest
            sys.stdout.write(adapter.derive_did_key(bytes.fromhex(pubkey_hex)))
            sys.stdout.write("\n")
            return EXIT_OK

        if subcommand == "canonical-string-v02":
            agent_id, timestamp = rest
            body = _read_stdin_bytes().decode("utf-8")
            sys.stdout.write(adapter.canonical_string(body, agent_id, timestamp))
            sys.stdout.write("\n")
            return EXIT_OK

        if subcommand == "canonical-string-v03":
            method, url_path, agent_id, timestamp, nonce = rest
            body = _read_stdin_bytes().decode("utf-8")
            sys.stdout.write(
                adapter.canonical_string_v03(method, url_path, body, agent_id, timestamp, nonce)
            )
            sys.stdout.write("\n")
            return EXIT_OK

        if subcommand == "sign":
            (key_hex,) = rest
            canonical = _read_stdin_bytes().decode("utf-8")
            sys.stdout.write(adapter.sign(bytes.fromhex(key_hex), canonical))
            sys.stdout.write("\n")
            return EXIT_OK

        if subcommand == "compose-headers-v02":
            agent_id, did_key, timestamp, signature_b64 = rest
            headers = adapter.compose_headers(agent_id, did_key, timestamp, signature_b64)
            json.dump(headers, sys.stdout)
            sys.stdout.write("\n")
            return EXIT_OK

        if subcommand == "compose-headers-v03":
            agent_id, did_key, timestamp, nonce, signature_b64 = rest
            headers = adapter.compose_headers_v03(
                agent_id, did_key, timestamp, nonce, signature_b64
            )
            json.dump(headers, sys.stdout)
            sys.stdout.write("\n")
            return EXIT_OK

        print(f"unknown subcommand: {subcommand}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT

    except ValueError as exc:
        # Most likely: malformed hex or wrong byte length.
        print(f"malformed input: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except Exception as exc:
        print(f"internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":
    sys.exit(main())
