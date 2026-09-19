"""
CLI — the single entry point.

Run ``community-member --help`` for usage. The argparse subparsers
below are the canonical command surface; this module's docstring is
not.

Two backward-compat behaviours intentionally preserved:

  1. Bare ``community-member`` (no subcommand) runs the wizard. This is
     how every existing user invokes it — argparse routes ``None``
     subcommand to the same handler as ``wizard``.
  2. ``community-member init`` is an alias for ``wizard``. Some error
     messages elsewhere in the SDK (a2a_client.MissingCredentialsError)
     point users at ``init``; rather than rewriting every error string,
     we make the alias real.
"""

import argparse
import asyncio
import json
import os
import signal
import sys
import webbrowser
from pathlib import Path

from rich.console import Console

from . import DASHBOARD_PORT, think_interval_seconds
from .agent import LocalAgent
from .config import Config
from .consent import ledger
from .server import create_app
from .wizard import run_wizard

console = Console()


# Pull the package version dynamically so --version stays honest across
# bumps without a manual touch here. Falls back to "unknown" if
# importlib metadata isn't populated (editable installs without the
# pyproject.toml resolver path can hit this).
def _package_version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version

        # 'orrery-agent' is the current dist; 'community-member' is the
        # pre-rename name kept as a legacy fallback.
        for dist in ("orrery-agent", "community-member"):
            try:
                return version(dist)
            except PackageNotFoundError:
                continue
    except ImportError:
        pass
    # Editable checkout / dist not registered: fall back to the in-package
    # __version__ rather than reporting a useless "unknown".
    try:
        from community_member import __version__

        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"


def _cmd_panic() -> int:
    """Emergency revoke: wipe graduations + rotate signing key.

    This is a one-way operation — it records an audit row and swaps
    the signing key immediately. No confirmation prompt by design;
    if the user typed `community-member panic`, they meant it.
    """
    from community_member import keystore, panic
    from community_member.config import CONFIG_DIR

    config = Config.load()
    if not config.agent_id:
        console.print("[red]No agent configured.[/red] Run `community-member` first.")
        return 1

    # Make sure the ledger is initialized so the panic row can land.
    ledger.init(CONFIG_DIR / "consent.db", signing_key_b64=keystore.load_private_key(config.agent_id))

    report = panic.execute_panic(
        chapter_id=f"local:{config.agent_id}",
        agent_id=config.agent_id,
        config=config,
    )
    console.print("[bold yellow]PANIC REVOKE COMPLETE[/bold yellow]")
    console.print(f"  revoked_graduations = {report.revoked_graduations}")
    console.print(f"  key_rotated         = {report.key_rotated}")
    console.print(f"  new_public_key      = {report.new_public_key[:24]}…")
    console.print(f"  audit_event_sha256  = {report.audit_event_sha256[:24]}…")
    console.print("\n  All existing approvals are void. Each next action will re-prompt.")
    return 0


def _cmd_graduations_list() -> int:
    """List all graduations for this device."""
    from community_member.config import CONFIG_DIR
    from community_member.graduation import GraduationStore

    config = Config.load()
    if not config.agent_id:
        console.print("[red]No agent configured.[/red]")
        return 1

    db_path = CONFIG_DIR / "graduations.db"
    if not db_path.exists():
        console.print("[yellow]No graduations recorded yet.[/yellow]")
        return 0

    import sqlite3

    store = GraduationStore(db_path, device_did=config.agent_id)  # noqa: F841

    # Read directly — GraduationStore doesn't expose a list_all yet.
    # This is safe because the schema is stable per state.py.
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT capability, scope, context_sha256, state, "
            "graduated_at, revoked_at FROM graduations "
            "WHERE device_did = ? ORDER BY graduated_at DESC",
            (config.agent_id,),
        ).fetchall()

    if not rows:
        console.print("[yellow]No graduations for this device.[/yellow]")
        return 0

    console.print(f"[bold]Graduations for {config.agent_id}:[/bold]\n")
    for cap, scope, ctx_sha, state, grad_at, revk_at in rows:
        color = {"graduated": "green", "revoked": "red"}.get(state, "white")
        ctx_short = ctx_sha[:12] + "…"
        console.print(f"  [{color}]{state:>10}[/{color}]  {cap}  {scope}  ctx={ctx_short}")
        if grad_at:
            console.print(f"                          graduated_at = {grad_at}")
        if revk_at:
            console.print(f"                          revoked_at   = {revk_at}")
    return 0


def _cmd_graduations_revoke(capability: str, scope: str, ctx_prefix: str) -> int:
    """Revoke one specific graduation identified by capability+scope+context prefix."""
    from community_member.config import CONFIG_DIR
    from community_member.graduation import GraduationStore

    config = Config.load()
    if not config.agent_id:
        console.print("[red]No agent configured.[/red]")
        return 1
    db_path = CONFIG_DIR / "graduations.db"

    import sqlite3

    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT context_sha256 FROM graduations "
            "WHERE device_did=? AND capability=? AND scope=? "
            "AND context_sha256 LIKE ?",
            (config.agent_id, capability, scope, f"{ctx_prefix}%"),
        ).fetchall()

    if not rows:
        console.print(f"[red]No graduation matches[/red] {capability} {scope} ctx={ctx_prefix}…")
        return 1
    if len(rows) > 1:
        console.print(f"[yellow]Ambiguous: {len(rows)} matches.[/yellow] Provide a longer ctx prefix.")
        return 1

    (ctx_full,) = rows[0]
    store = GraduationStore(db_path, device_did=config.agent_id)
    store.revoke(capability=capability, scope=scope, context_sha256=ctx_full)
    console.print(f"[green]Revoked[/green] {capability} {scope} ctx={ctx_full[:12]}…")
    return 0


def _cmd_audit_verify() -> int:
    """Re-derive the local consent ledger hash chain. Exit 0 if clean."""
    from community_member import keystore
    from community_member.config import CONFIG_DIR

    config = Config.load()
    priv = keystore.load_private_key(config.agent_id) if config.agent_id else None
    ledger.init(CONFIG_DIR / "consent.db", signing_key_b64=priv)
    result = ledger.verify_chain()
    if result["ok"]:
        # `ok` says the chain is internally consistent. It does NOT say every row
        # was written by record() — that is `authenticated`, and saying
        # "verified" without it would overstate what was checked.
        length, signed = result["length"], result["signatures_verified"]
        unsigned, authentic = result.get("unsigned_rows", 0), result.get("authenticated")
        if authentic is True:
            console.print(f"[green]Audit chain verified and authenticated[/green] (length={length})")
        elif authentic is None:
            console.print(
                f"[yellow]Audit chain consistent; authenticity NOT CHECKED[/yellow] "
                f"(length={length}) — this ledger has no signing key, so it cannot be "
                f"shown whether any row was added outside the agent."
            )
        else:
            console.print(
                f"[yellow]Audit chain consistent; NOT authenticated[/yellow] "
                f"(length={length}, signed={signed}, unsigned={unsigned}) — "
                f"{unsigned} row(s) carry no signature and were not written by the agent."
            )
        return 0
    console.print(
        f"[red]Audit chain BROKEN[/red] at index {result.get('broken_index')} ({result.get('reason', 'hash mismatch')})"
    )
    return 2


def _cmd_disclose_emit(receipt_ids: list[str], out: Path | None) -> int:
    """Emit a selective-disclosure bundle (signed PARC + k receipts, each with
    a Merkle inclusion proof) from the local Agency Log. See receipt_disclosure."""
    import json
    from datetime import UTC, datetime, timedelta

    from community_member.receipt_disclosure import build_disclosure

    config = Config.load()
    now = datetime.now(UTC)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        bundle = build_disclosure(
            config,
            receipt_ids=receipt_ids,
            as_of=stamp,
            valid_from=stamp,
            valid_until=(now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    except ValueError as e:
        console.print(f"[red]Cannot disclose:[/red] {e}")
        return 1
    text = json.dumps(bundle, indent=2)
    if out is not None:
        out.write_text(text + "\n")
        console.print(f"[green]Disclosure bundle written[/green] to {out} ({len(bundle['disclosed'])} receipt(s)).")
    else:
        print(text)
    return 0


def _resolve_issuer_did(org_url: str) -> str:
    """Build a did:key from an org's own DID document.

    Fetches ``<org_url>/.well-known/did.json`` and returns
    ``did:key:<verificationMethod[0].publicKeyMultibase>``, the same resolution
    ``docs/VERIFY_A_RECEIPT.md`` documents and ``scripts/receipt_verify_canary.py``
    performs. The caller chooses the host, which is what makes the resulting
    did:key independent of the bundle being checked.
    """
    import httpx

    base = org_url.rstrip("/")
    doc = httpx.get(f"{base}/.well-known/did.json", timeout=30, follow_redirects=True).json()
    methods = doc.get("verificationMethod") or []
    if not methods or not isinstance(methods[0], dict):
        raise ValueError(f"{base}/.well-known/did.json has no verificationMethod")
    multibase = methods[0].get("publicKeyMultibase")
    if not isinstance(multibase, str) or not multibase:
        raise ValueError(f"{base}/.well-known/did.json verificationMethod[0] has no publicKeyMultibase")
    return f"did:key:{multibase}"


def _cmd_disclose_verify(bundle_path: Path, *, issuer: str | None, issuer_from: str | None) -> int:
    """Verify a disclosure bundle against an issuer named on the command line.

    Checks that the credential names that issuer, that its proof verifies, and
    that every disclosed receipt folds up to the root the credential signs.
    Exit 0 iff all three hold.
    """
    import json

    from community_member.receipt_disclosure import verify_disclosure

    try:
        bundle = json.loads(bundle_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Cannot read bundle:[/red] {e}")
        return 1

    expected = issuer
    if expected is None:
        try:
            expected = _resolve_issuer_did(str(issuer_from))
        except Exception as e:  # noqa: BLE001 — an unresolvable issuer is a refusal
            console.print(f"[red]Cannot resolve issuer from {issuer_from}:[/red] {e}")
            return 1
        # emoji=False throughout: rich would render the ":key:" in a did:key as 🔑.
        console.print(f"expected issuer (resolved from {issuer_from}): {expected}", emoji=False)

    result = verify_disclosure(bundle, expected_issuer=expected)
    iss = "[green]matches[/green]" if result["issuer_ok"] else "[red]MISMATCH[/red]"
    console.print(f"issuer: {result['issuer']} — {iss}", emoji=False)
    cred = "[green]ok[/green]" if result["credential_ok"] else "[red]FAILED[/red]"
    console.print(f"credential proof: {cred}")
    for r in result["receipts"]:
        mark = "[green]included[/green]" if r["included"] else "[red]NOT PROVEN[/red]"
        console.print(f"  {r['receipt_id']}: {mark}")
    if result["ok"]:
        console.print(
            f"[green]Disclosure verified[/green] — issued by {expected}, every receipt included.", emoji=False
        )
        return 0
    if not result["issuer_ok"]:
        console.print(
            f"[red]Disclosure verification FAILED[/red] — the credential names {result['issuer']}, "
            f"not {expected}. The bundle was not issued by that org.",
            emoji=False,
        )
        return 2
    console.print("[red]Disclosure verification FAILED[/red]")
    return 2


def _cmd_dat_verify(dat_path: Path, chain_path: Path | None, category: str | None) -> int:
    """Verify a counterparty's Delegated Authority Token — signature, validity
    window, scope, the full sub-delegation chain, and revocation — BEFORE
    transacting, instead of trusting a chapter to vouch. Exit 0 iff verified."""
    import json

    from community_member import dat as dat_mod

    try:
        dat = json.loads(dat_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Cannot read DAT:[/red] {e}")
        return 1

    dats_by_id = None
    if chain_path is not None:
        try:
            chain = json.loads(chain_path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            console.print(f"[red]Cannot read chain:[/red] {e}")
            return 1
        if isinstance(chain, list):
            dats_by_id = {d.get("grant_id", f"_{i}"): d for i, d in enumerate(chain)}
        elif isinstance(chain, dict):
            dats_by_id = chain

    try:
        result = dat_mod.verify_counterparty_dat(dat, category=category, dats_by_id=dats_by_id)
    except (KeyError, TypeError, ValueError) as e:
        console.print(f"[red]Malformed DAT:[/red] {type(e).__name__}: {e}")
        return 1

    if result.ok:
        console.print(f"[green]DAT verified[/green] — {result.detail}")
        return 0
    console.print(f"[red]DAT verification FAILED[/red] (stage: {result.stage}) — {result.detail}")
    return 2


def _plain(text: str) -> None:
    """Rich, minus what mangles identifiers: ``did:key:…`` contains ``:key:``,
    which rich renders as an emoji, and soft-wrapping splits a did or a
    receipt id across lines. Markup stays so the colour words still work."""
    console.print(text, emoji=False, soft_wrap=True)


def _cmd_dat_grant(args: argparse.Namespace) -> int:
    """A principal signs a DAT naming one action for one agent (see
    ``delegated_call.mint_grant``). The grantor's phrase is read from the
    environment (``COMMUNITY_MEMBER_OWNER_PHRASE``), never from argv, so it
    does not land in shell history or `ps`; without one a fresh principal is
    minted and its phrase printed ONCE to stderr for the operator to keep."""
    import os

    from community_member import delegated_call

    phrase = os.environ.get("COMMUNITY_MEMBER_OWNER_PHRASE", "").strip() or None
    try:
        dat, mnemonic = delegated_call.mint_grant(
            grantee_did=args.grantee,
            tool=args.tool,
            not_after=args.not_after,
            not_before=args.not_before,
            grantor_phrase=phrase,
            human_summary=args.summary,
        )
    except ValueError as e:
        _plain(f"[red]cannot mint grant:[/red] {e}")
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dat, indent=2, sort_keys=True) + "\n")
    if phrase is None:
        print(f"[dat grant] new principal {dat['grantor_did']}; its phrase (keep it, shown once):", file=sys.stderr)
        print(f"  {mnemonic}", file=sys.stderr)
    _plain(
        f"[green]granted[/green] {dat['grant_id']}: {dat['grantor_did'][:24]}… → {args.grantee[:24]}… "
        f"may {delegated_call.action_name(args.tool)} until {args.not_after} → {args.out}"
    )
    return 0


def _cmd_call(args: argparse.Namespace) -> int:
    """One A2A call to a peer under a DAT, with the evidence exported
    (``delegated_call.call_under_authority``). Exit codes: 0 sent and
    receipted; 2 refused by the authority check (nothing sent); 3 refused as a
    duplicate of an action that already ran; 4 sent but unreceipted."""
    from community_member import delegated_call

    config = Config.load()
    if not config.agent_id or not config.private_key:
        _plain("[red]No agent configured or keystore locked.[/red] Run `community-member` first.")
        return 1
    try:
        dat = json.loads(args.under.read_text())
        call_args = json.loads(args.args) if args.args else {}
    except (OSError, json.JSONDecodeError) as e:
        _plain(f"[red]Cannot read input:[/red] {e}")
        return 1
    report = delegated_call.call_under_authority(
        config,
        peer_url=args.peer,
        tool=args.tool,
        args=call_args,
        dat=dat,
        evidence_dir=args.evidence,
        task_id=args.task_id,
        cosign=not args.no_cosign,
        push=not args.no_push,
    )
    verdict = report.verdict
    if report.outcome == "refused" and verdict is not None:
        _plain(f"[red]REFUSED[/red] at the consent gate (authority_{verdict.stage}): {verdict.detail}")
        _plain(f"  nothing was sent; the denial is on record → {args.evidence}")
    elif report.outcome == "duplicate":
        _plain(f"[red]REFUSED[/red] as a duplicate: {report.error}")
        _plain(f"  not re-sent; see prior_attempt in {args.evidence / 'decision.json'}")
    elif report.outcome == "unreceipted":
        _plain(f"[yellow]SENT, RECEIPT OWED[/yellow] attempt {report.attempt_id}: {report.error}")
        _plain("  the action happened — do not retry; the attempt is listed under agency-log/unresolved")
    else:
        grant = verdict.grant_id if verdict else "?"
        witnessed = "co-signed" if report.corroborated else "NOT co-signed"
        _plain(
            f"[green]SENT[/green] {args.tool} → {report.counterparty_did} under {grant}; "
            f"receipt {report.receipt_id} {witnessed} → {args.evidence}"
        )
    return report.exit_code()


def _cmd_checkpoint_verify(receipt_path: Path, checkpoint_path: Path, proof_path: Path) -> int:
    """Prove your OWN receipt is committed under your chapter's signed Merkle
    checkpoint — offline — so you can DETECT a chapter that silently drops it.
    The failure stage names whether the chapter's commitment is forged or your
    receipt was simply omitted. Exit 0 iff committed."""
    import json

    from community_member import checkpoint as cp_mod

    try:
        receipt = json.loads(receipt_path.read_text())
        checkpoint = json.loads(checkpoint_path.read_text())
        proof = json.loads(proof_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Cannot read inputs:[/red] {e}")
        return 1

    try:
        result = cp_mod.verify_membership(receipt, checkpoint=checkpoint, proof=proof)
    except (KeyError, TypeError, ValueError) as e:
        console.print(f"[red]Malformed checkpoint/proof inputs:[/red] {type(e).__name__}: {e}")
        return 1

    if result.ok:
        console.print(f"[green]Membership verified[/green] — {result.detail}")
        return 0
    console.print(f"[red]Membership verification FAILED[/red] (stage: {result.stage}) — {result.detail}")
    return 2


def _cmd_receipt_verify(receipt_path: Path) -> int:
    """Verify a SINGLE raw ARP receipt fully OFFLINE — schema + Ed25519
    signature (the verify-key is embedded in ``issuer_did``) + hash-chain
    claim. No network, no DB: a clean skeptic proof that a receipt stands on
    its own. Prints PASS/FAIL and exits 0 iff the receipt verifies.

    A receipt that declares a ``previous_receipt_hash`` is a chain link; with
    no prior supplied it cannot be evaluated and strict verification reports a
    ``hash_chain`` failure (the chain claim is unproven, not accepted)."""
    import json

    from community_member import arp

    try:
        receipt = json.loads(receipt_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Cannot read receipt:[/red] {e}")
        return 1
    if not isinstance(receipt, dict):
        console.print("[red]Malformed receipt:[/red] top-level JSON is not an object")
        return 1

    result = arp.verify_receipt(receipt)
    if result.ok:
        console.print(f"[green]PASS[/green] — {result.detail}")
        return 0
    console.print(f"[red]FAIL[/red] (stage: {result.stage}) — {result.detail}")
    return 2


def _express_requested(args: argparse.Namespace) -> bool:
    """True when non-interactive EXPRESS provisioning is asked for — either the
    ``--express`` flag or ``COMMUNITY_MEMBER_EXPRESS`` set to a truthy value."""
    if getattr(args, "express", False):
        return True
    return os.environ.get("COMMUNITY_MEMBER_EXPRESS", "").strip().lower() in ("1", "true", "yes", "on")


def _express_name(args: argparse.Namespace) -> str:
    """The display name for EXPRESS provisioning: ``--name`` wins, else the
    ``COMMUNITY_MEMBER_NAME`` env var."""
    name = getattr(args, "name", None)
    if name:
        return str(name).strip()
    return os.environ.get("COMMUNITY_MEMBER_NAME", "").strip()


def _cmd_express(name: str) -> int:
    """Headless provisioning: mint + persist a keyless, local-LLM identity with
    ZERO interactive prompts, print the agent_id + did:key, and exit. Never
    starts the server (a separate run serves it). Safe to run with no TTY."""
    from community_member import crypto
    from community_member.wizard import express_setup

    name = (name or "").strip()
    if not name:
        console.print("[red]Express onboarding needs a name.[/red] Pass --name <NAME> or set COMMUNITY_MEMBER_NAME.")
        return 1

    config, recovery_phrase = express_setup(name)

    try:
        did_key = crypto.build_did_key(config.public_key)
    except Exception as e:  # noqa: BLE001 — HMAC fallback has no publishable did:key
        console.print(f"[yellow]Warning: could not derive did:key ({e}).[/yellow]")
        did_key = ""

    # Machine-readable identity lines on plain stdout (no rich markup) so a
    # provisioning script can parse them straight out of the subprocess.
    print(f"agent_id: {config.agent_id}")
    print(f"did:key: {did_key}")

    if recovery_phrase is not None:
        # The phrase is the ONLY way to restore this identity and is surfaced
        # exactly once — there is no interactive acknowledgement in this path.
        print(f"recovery_phrase: {recovery_phrase}")
        console.print(
            "  [yellow]Save the recovery phrase above offline — it is shown once and is the "
            "only way to restore this identity.[/yellow]"
        )
    elif config.public_key and not did_key:
        console.print(
            "  [yellow]This identity is NOT restorable (no recovery phrase minted). "
            "Install the recovery extra and re-provision for a restorable key.[/yellow]"
        )
    console.print(f"  [green]@{config.agent_id} provisioned[/green] — run community-member to serve it.")
    return 0


def _cmd_reset() -> int:
    """Wipe ALL local agent state — keys, profile, ledger, habits.

    Used when the user wants to test the signup flow from scratch
    or hand the machine to someone else. Removes the entire
    CONFIG_DIR (default ``~/.community-member`` or whatever
    ``COMMUNITY_MEMBER_HOME`` points at).

    Asks for explicit confirmation before deleting because:

      - Private signing key disappears (BIP39 phrase is the only
        recovery path; if you didn't write it down, you lose this
        identity permanently).
      - Hash-chained audit ledger is wiped (regulatory replay
        becomes impossible).
      - Habit Bayesian posteriors reset to uniform priors (any
        graduations are erased).

    Run ``community-member reset --yes`` to skip the confirmation
    prompt. The chapter-side row at ``agents/{did_key}`` is NOT
    touched by this; that needs a separate API call (or just sign
    up fresh with a new did:key — the old chapter row becomes a
    dangling membership the chapter cleans up via TTL).
    """
    import shutil

    from .config import CONFIG_DIR

    target = Path(CONFIG_DIR)
    if not target.exists():
        console.print(f"  [yellow]No config dir at {target} — already clean.[/yellow]")
        return 0

    auto_yes = "--yes" in sys.argv or "-y" in sys.argv
    console.print(f"\n  [bold red]This will permanently delete:[/bold red] {target}")
    console.print("  [red]Everything in the directory goes — keys, profile, audit, habits, graduations.[/red]")
    console.print(
        "  [dim]The BIP39 recovery phrase you saved at signup is the only way to restore this identity.[/dim]\n"
    )

    if not auto_yes:
        try:
            reply = input("  Type 'wipe' to confirm: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n  [yellow]Cancelled.[/yellow]")
            return 1
        if reply != "wipe":
            console.print("  [yellow]Cancelled (you typed something other than 'wipe').[/yellow]")
            return 1

    try:
        shutil.rmtree(target)
    except OSError as e:
        console.print(f"  [red]Failed to remove {target}: {e}[/red]")
        return 2

    console.print(f"  [green]Removed {target}.[/green]")
    console.print("  Run [bold]community-member[/bold] (no args) to start the wizard fresh.")
    return 0


def _cmd_keystore_status() -> int:
    """Print the active backend and which agents have keys recorded."""
    from community_member import keystore

    backend = keystore.current_backend()
    label = {
        keystore.BACKEND_KEYRING: "OS keychain (Tier 2)",
        keystore.BACKEND_PASSPHRASE: "user passphrase (Tier 1)",
        keystore.BACKEND_DEVICE: "device fingerprint (fallback)",
    }.get(backend, backend)
    console.print(f"  Active backend: [bold]{backend}[/bold] — {label}")
    console.print(f"  Keystore dir:   {keystore.KEYSTORE_DIR}")

    meta_path = keystore.KEYSTORE_DIR / "keystore.meta.json"
    if meta_path.exists():
        import json as _json

        try:
            meta = _json.loads(meta_path.read_text())
            agents = meta.get("agents") or {}
            if agents:
                console.print(f"  Stored agents:  {len(agents)}")
                for aid in sorted(agents.keys()):
                    console.print(f"    • {aid}")
            else:
                console.print("  Stored agents:  (none yet)")
        except Exception:
            pass
    return 0


def _cmd_keystore_rotate(target: str) -> int:
    """Migrate the keystore to ``target`` (keyring | passphrase | device).

    For ``passphrase``, prompts the operator for a new passphrase with
    confirmation BEFORE we touch any vault. The new passphrase is held
    in process memory only — never written to disk.
    """
    from community_member import keystore

    valid = {keystore.BACKEND_KEYRING, keystore.BACKEND_PASSPHRASE, keystore.BACKEND_DEVICE}
    if target not in valid:
        console.print(f"[red]Unknown target {target!r}[/red]. Pick one of: {', '.join(sorted(valid))}")
        return 1

    new_passphrase: str | None = None
    if target == keystore.BACKEND_PASSPHRASE:
        # Use the keystore module's own prompt so confirmation rules
        # (length floor, double-entry verify) stay in one place.
        try:
            new_passphrase = keystore._prompt_for_new_passphrase()
        except keystore.WrongPassphraseError as e:
            console.print(f"[red]{e}[/red]")
            return 2

    try:
        result = keystore.rotate_backend(target, new_passphrase=new_passphrase)
    except (RuntimeError, keystore.WrongPassphraseError, ValueError) as e:
        console.print(f"[red]Rotation failed:[/red] {e}")
        return 3

    if result.get("noop"):
        console.print(f"  Already on [bold]{target}[/bold] — nothing to do.")
        return 0
    console.print(f"  [green]Migrated[/green] {result['migrated']} key(s): {result['source']} → {result['target']}")
    if target == keystore.BACKEND_PASSPHRASE:
        console.print(
            "  [yellow]Heads up:[/yellow] you'll be prompted for this passphrase "
            "on every fresh process. Cache cleared on logout / panic / lock."
        )
    return 0


def _cmd_wizard(args: argparse.Namespace) -> int:
    """Run the setup wizard, then keep the agent + dashboard running.

    This is the bare-invocation default. The wizard is idempotent:
    re-running it on an already-configured machine simply confirms or
    updates the existing identity; no destructive action.

    EXPRESS short-circuit: when ``--express`` (or COMMUNITY_MEMBER_EXPRESS) is
    set, provisioning runs fully non-interactively and returns WITHOUT starting
    the server — for headless / no-TTY provisioning.
    """
    if _express_requested(args):
        return _cmd_express(_express_name(args))
    try:
        config = run_wizard()
        if not config or not config.is_configured():
            console.print("[red]Setup incomplete. Run community-member again.[/red]")
            return 1

        agent = LocalAgent(config)
        app = create_app(config, agent)

        def shutdown(sig, frame):
            console.print("\n  [yellow]Stopping agent...[/yellow]")
            agent.stop()

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

        # Auto-pick a free port so we run even when 7777 (or COMMUNITY_MEMBER_PORT)
        # is already taken by something else.
        from . import DASHBOARD_BIND_HOST, find_free_port

        port = find_free_port(DASHBOARD_PORT)
        url = f"http://localhost:{port}"
        console.print(f"\n  [bold green]@{config.agent_id} is live[/bold green]")
        console.print(f"  Dashboard: [link]{url}[/link]")
        if port != DASHBOARD_PORT:
            console.print(f"  [dim](port {DASHBOARD_PORT} was busy — using {port})[/dim]")
        from . import local_auth

        # The API needs the token on every route that is not public identity or
        # liveness. Print where it lives once, on the start that created it —
        # not what it is, and not on every start. Mirrors server/admin.py.
        if local_auth.was_generated_this_process():
            console.print(f"  API token written to {config.home / local_auth.TOKEN_FILENAME}")
        if DASHBOARD_BIND_HOST not in ("127.0.0.1", "localhost", "::1"):
            # The dashboard API has no authentication, so the bind host decides
            # who can change this agent's consent settings.
            console.print(
                f"  [yellow]Listening on {DASHBOARD_BIND_HOST} — the dashboard API is "
                f"unauthenticated and reachable from the network.[/yellow]"
            )
        console.print(f"  Org: {config.chapter_url}")
        from . import registry

        if registry.should_announce(config) and not registry.publication_targets():
            console.print(
                "  Discoverable: [dim]consent on file, but no registry is configured — "
                "publishing nowhere. Set REGISTRY_URL and/or NANDA_INDEX_URL to opt in.[/dim]"
            )
        elif registry.should_announce(config):
            console.print(f"  Discoverable: yes — publishing to {', '.join(registry.publication_targets())}")
            # Say WHAT WAS CHECKED, not just that something was. "authorised by
            # your owner consent" is true of all four evidence kinds and
            # therefore tells a reader nothing about which one they have — the
            # generic "verified" the owner-attestation decision exists to
            # replace. The published record has always carried the answer.
            from . import attestation_copy, owner

            copy = attestation_copy.rendering_for(owner.owner_attestation(registry.consent_verdict(config)))
            console.print(f"  [dim]{copy.sentence}[/dim]")
            console.print(f"  [dim]{copy.caveat}[/dim]")
            console.print("  [dim](COMMUNITY_MEMBER_NO_REGISTRY=1 stays private)[/dim]")
        elif registry.is_opted_out():
            console.print("  Discoverable: [dim]no — private (COMMUNITY_MEMBER_NO_REGISTRY set)[/dim]")
        else:
            # Say WHICH check refused. "Not listed" with no reason is how a user
            # concludes the feature is broken rather than un-consented.
            verdict = registry.consent_verdict(config)
            console.print(f"  Discoverable: [dim]no — {verdict.reason}[/dim]")
            if verdict.reason == "no_owner_consent":
                console.print("  [dim]Run the wizard's consent step to authorise a public listing.[/dim]")
        console.print("  Press Ctrl+C to stop.\n")

        if not args.no_browser:
            webbrowser.open(url)

        asyncio.run(_run_both(app, agent, port))
        return 0
    except KeyboardInterrupt:
        console.print("\n  [yellow]Goodbye![/yellow]")
        return 0
    except Exception as e:
        console.print(f"\n  [red]Error: {e}[/red]")
        return 1


def _add_express_args(p: argparse.ArgumentParser) -> None:
    """Attach the non-interactive EXPRESS provisioning flags to a parser.

    Shared by ``wizard`` and its ``init`` alias so either verb can stand up an
    agent headlessly. Both flags also fall back to env (COMMUNITY_MEMBER_EXPRESS
    / COMMUNITY_MEMBER_NAME) so container orchestration can provision with no
    argv at all."""
    p.add_argument(
        "--express",
        action="store_true",
        help="Provision non-interactively (no prompts, no TTY, keyless local LLM); does not start the server.",
    )
    p.add_argument(
        "--name",
        default=None,
        help="Display name for --express provisioning (or set COMMUNITY_MEMBER_NAME).",
    )


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argparse tree.

    Kept in its own function so the test suite can import + introspect
    it without invoking ``main()``. Subcommand handlers are wired via
    ``set_defaults(func=_cmd_*)`` so each routes to the right
    implementation without a long if/elif chain.
    """
    parser = argparse.ArgumentParser(
        prog="community-member",
        description=(
            "Sovereign member runtime for orgs. Local-first, "
            "Ed25519-signed, BIP39-recoverable. Run with no subcommand to "
            "start the wizard + agent."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"community-member {_package_version()}",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── wizard (default) + alias `init` ─────────────────────────────
    p_wizard = sub.add_parser(
        "wizard",
        help="Run the setup wizard, then start the agent + dashboard.",
        description=_cmd_wizard.__doc__,
    )
    p_wizard.add_argument(
        "--no-browser",
        action="store_true",
        help="Skip auto-opening the dashboard in a browser (for Electron / headless).",
    )
    _add_express_args(p_wizard)
    p_wizard.set_defaults(func=_cmd_wizard)

    p_init = sub.add_parser(
        "init",
        help="Alias for `wizard` — same setup + agent flow.",
        description=(
            "Alias for `community-member wizard`. Some error messages elsewhere "
            "in the SDK direct users here; both names invoke the same flow. "
            "Pass --express --name <NAME> to provision non-interactively (no TTY, "
            "no API key, does not start the server)."
        ),
    )
    p_init.add_argument("--no-browser", action="store_true", help=argparse.SUPPRESS)
    _add_express_args(p_init)
    p_init.set_defaults(func=_cmd_wizard)

    # ── panic ───────────────────────────────────────────────────────
    p_panic = sub.add_parser(
        "panic",
        help="Emergency revoke: nuke graduations + rotate signing key.",
        description=_cmd_panic.__doc__,
    )
    p_panic.set_defaults(func=lambda args: _cmd_panic())

    # ── reset ───────────────────────────────────────────────────────
    p_reset = sub.add_parser(
        "reset",
        help="Permanently delete the local identity (keys, profile, ledger).",
        description=(
            "Wipes ~/.community-member/ entirely. The BIP39 phrase is the "
            "only way to restore. Pass --yes to skip the 'wipe' prompt."
        ),
    )
    p_reset.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the 'type wipe to confirm' prompt.",
    )
    p_reset.set_defaults(func=lambda args: _cmd_reset())

    # ── audit verify ────────────────────────────────────────────────
    p_audit = sub.add_parser("audit", help="Inspect the local consent ledger.")
    audit_sub = p_audit.add_subparsers(dest="audit_command", metavar="ACTION")
    p_audit_verify = audit_sub.add_parser(
        "verify",
        help="Re-derive the consent-ledger hash chain end-to-end.",
    )
    p_audit_verify.set_defaults(func=lambda args: _cmd_audit_verify())

    # ── disclose ────────────────────────────────────────────────────
    p_disclose = sub.add_parser(
        "disclose",
        help="Selectively disclose Agency Log receipts with Merkle inclusion proofs (sm-parc).",
    )
    disclose_sub = p_disclose.add_subparsers(dest="disclose_command", metavar="ACTION")
    p_disc_emit = disclose_sub.add_parser(
        "emit",
        help="Emit chosen receipts + inclusion proofs + the signed PARC as one offline-verifiable bundle.",
    )
    p_disc_emit.add_argument("receipt_ids", nargs="+", metavar="RECEIPT_ID")
    p_disc_emit.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the bundle JSON to this file instead of stdout.",
    )
    p_disc_emit.set_defaults(func=lambda args: _cmd_disclose_emit(args.receipt_ids, args.out))
    p_disc_verify = disclose_sub.add_parser(
        "verify",
        help="Verify a disclosure bundle against an issuer you name (credential proof + every inclusion proof).",
    )
    p_disc_verify.add_argument("bundle", type=Path, help="Path to a disclosure bundle JSON file.")
    # One of these is required. The credential's proof verifies under the did:key
    # written inside the credential, so without an independently obtained issuer
    # there is nothing to distinguish a bundle from one the presenter minted.
    issuer_src = p_disc_verify.add_mutually_exclusive_group(required=True)
    issuer_src.add_argument(
        "--issuer",
        metavar="DID",
        help="The did:key you expect issued this bundle, obtained independently of the bundle.",
    )
    issuer_src.add_argument(
        "--issuer-from",
        metavar="ORG_URL",
        help="Resolve the expected did:key from ORG_URL/.well-known/did.json. Requires network.",
    )
    p_disc_verify.set_defaults(
        func=lambda args: _cmd_disclose_verify(args.bundle, issuer=args.issuer, issuer_from=args.issuer_from)
    )

    # ── receipt verify ──────────────────────────────────────────────
    p_receipt = sub.add_parser(
        "receipt",
        help="Verify a raw ARP receipt fully offline (a clean skeptic proof).",
    )
    receipt_sub = p_receipt.add_subparsers(dest="receipt_command", metavar="ACTION", required=True)
    p_receipt_verify = receipt_sub.add_parser(
        "verify",
        help="Verify a single raw ARP receipt offline — schema + Ed25519 signature + hash chain.",
    )
    p_receipt_verify.add_argument("receipt", type=Path, help="Path to the ARP receipt JSON file.")
    p_receipt_verify.set_defaults(func=lambda args: _cmd_receipt_verify(args.receipt))

    # ── graduations ─────────────────────────────────────────────────
    # ── The flagship-loop suite flagship-loop verbs (mirror the verify-CLI ergonomics) ──
    p_interact = sub.add_parser(
        "interact",
        help="Drive one recorded A2A interaction (loopback witness); co-signed "
        "by default so it builds nanda-rep/0.2 reputation when pushed.",
    )
    p_interact.add_argument("--chapter", default=None, help="Org URL: register both agents + push the receipt.")
    p_interact.add_argument("--no-cosign", action="store_true", help="Emit a self-attested (uncorroborated) receipt.")
    p_interact.set_defaults(
        func=lambda args: __import__("community_member.flows", fromlist=["run_interaction"]).run_interaction(
            args.chapter, cosign=not args.no_cosign
        )
    )

    p_resolve = sub.add_parser("resolve", help="Resolve an agent on an org via /sm-bridge/resolve (quilt).")
    p_resolve.add_argument("--org", required=True, help="Org base URL.")
    p_resolve.add_argument("agent", help="Agent id, DID, or handle.")
    p_resolve.set_defaults(
        func=lambda args: __import__("community_member.flows", fromlist=["resolve_agent"]).resolve_agent(
            args.org, args.agent
        )
    )

    p_registry = sub.add_parser("registry", help="Per-org registry tools.")
    registry_sub = p_registry.add_subparsers(dest="registry_cmd", required=True)
    p_reg_dump = registry_sub.add_parser(
        "dump", help="Dump the org's catalog + sm-bridge index and verify every entry resolves."
    )
    p_reg_dump.add_argument("--org", required=True, help="Org base URL.")
    p_reg_dump.set_defaults(
        func=lambda args: __import__("community_member.flows", fromlist=["registry_dump"]).registry_dump(args.org)
    )

    p_grads = sub.add_parser(
        "graduations",
        help="Manage capabilities that have graduated from prompt-to-allow.",
    )
    grads_sub = p_grads.add_subparsers(dest="graduations_command", metavar="ACTION")

    p_grads_list = grads_sub.add_parser("list", help="List all graduations recorded for this device.")
    p_grads_list.set_defaults(func=lambda args: _cmd_graduations_list())

    p_grads_revoke = grads_sub.add_parser(
        "revoke",
        help="Revoke one graduation. CTX is a sha256 prefix.",
    )
    p_grads_revoke.add_argument("capability", help="Capability the graduation covers (e.g. files.read).")
    p_grads_revoke.add_argument("scope", help="Scope of the graduation.")
    p_grads_revoke.add_argument("ctx", help="Context-hash prefix (sha256, first chars).")
    p_grads_revoke.set_defaults(func=lambda args: _cmd_graduations_revoke(args.capability, args.scope, args.ctx))

    # ── keystore ────────────────────────────────────────────────────
    p_ks = sub.add_parser("keystore", help="Inspect / rotate the at-rest key backend.")
    ks_sub = p_ks.add_subparsers(dest="keystore_command", metavar="ACTION")

    p_ks_status = ks_sub.add_parser(
        "status",
        help="Show the active backend (keyring | passphrase | device).",
    )
    p_ks_status.set_defaults(func=lambda args: _cmd_keystore_status())

    p_ks_rotate = ks_sub.add_parser(
        "rotate",
        help="Migrate keys to a different backend.",
    )
    p_ks_rotate.add_argument(
        "backend",
        choices=["keyring", "passphrase", "device"],
        help="Target backend to rotate the keystore to.",
    )
    p_ks_rotate.set_defaults(func=lambda args: _cmd_keystore_rotate(args.backend))

    # Cross-device portability — export/import the whole agent state
    # into a single file. Lives in its own module so cli.py stays a
    # routing surface rather than collecting business logic.
    from . import portable

    portable.register_subcommands(sub)

    # Sovereign admin ops — for members whose chapter_role='admin'.
    # Signs each /admin/api/* request with the SDK's Ed25519 key.
    # See community_member/admin.py for the full subcommand surface.
    from . import admin as _admin_module

    _admin_module.register_subcommands(sub)

    # Member-side verification verbs — expose the (already tested) checkpoint +
    # DAT verification libraries so a member can audit its chapter and vet a
    # counterparty from the command line.
    p_dat = sub.add_parser("dat", help="Verify Delegated Authority Tokens.")
    dat_sub = p_dat.add_subparsers(dest="dat_command", metavar="ACTION", required=True)
    p_dat_verify = dat_sub.add_parser(
        "verify",
        help="Verify a counterparty's DAT (signature / window / scope / chain / revocation) before transacting.",
    )
    p_dat_verify.add_argument("dat", type=Path, help="Path to the DAT JSON the counterparty presented.")
    p_dat_verify.add_argument(
        "--chain",
        type=Path,
        default=None,
        help="Ancestor DATs for a sub-delegated DAT (JSON list, or {grant_id: dat} map).",
    )
    p_dat_verify.add_argument("--category", default=None, help="Category to check against the leaf grant's scope.")
    p_dat_verify.set_defaults(func=lambda args: _cmd_dat_verify(args.dat, args.chain, args.category))
    p_dat_grant = dat_sub.add_parser(
        "grant",
        help="As a principal, sign a DAT letting one agent call one tool on a peer over A2A "
        "(grantor phrase from COMMUNITY_MEMBER_OWNER_PHRASE, else a fresh principal is minted).",
    )
    p_dat_grant.add_argument("--grantee", required=True, help="The agent's did:key (from its agent card).")
    p_dat_grant.add_argument("--tool", required=True, help="The one A2A tool the grant authorises.")
    p_dat_grant.add_argument("--not-after", required=True, help="Expiry, RFC 3339 UTC (2026-01-01T00:00:00Z).")
    p_dat_grant.add_argument("--not-before", default=None, help="Start, RFC 3339 UTC (default: now).")
    p_dat_grant.add_argument("--summary", default=None, help="Human summary written into the grant.")
    p_dat_grant.add_argument("--out", type=Path, required=True, help="Where to write the signed DAT JSON.")
    p_dat_grant.set_defaults(func=_cmd_dat_grant)

    p_call = sub.add_parser(
        "call",
        help="Call one tool on a peer agent over A2A under a DAT: the authority verdict is recorded "
        "(consent ledger + sm-aae envelope) before anything is sent, the attempt is written ahead of "
        "the call, the peer co-signs the receipt, and everything is exported to a directory.",
    )
    p_call.add_argument("--peer", required=True, help="The peer agent's base URL (serves /.well-known/agent.json).")
    p_call.add_argument("--tool", required=True, help="The tool to invoke on the peer.")
    p_call.add_argument("--args", default="{}", help="JSON object of tool arguments.")
    p_call.add_argument("--under", type=Path, required=True, help="The DAT (JSON) this call is made under.")
    p_call.add_argument("--evidence", type=Path, required=True, help="Directory to write the evidence into.")
    p_call.add_argument("--task-id", default=None, help="Action reference; a repeat with the same id is refused.")
    p_call.add_argument("--no-cosign", action="store_true", help="Do not ask the peer to co-sign.")
    p_call.add_argument("--no-push", action="store_true", help="Do not push the receipt to this agent's org.")
    p_call.set_defaults(func=_cmd_call)

    p_cp = sub.add_parser("checkpoint", help="Audit your chapter's signed Merkle checkpoint.")
    cp_sub = p_cp.add_subparsers(dest="checkpoint_command", metavar="ACTION", required=True)
    p_cp_verify = cp_sub.add_parser(
        "verify",
        help="Prove your receipt is committed under the chapter's signed checkpoint — offline.",
    )
    p_cp_verify.add_argument("--receipt", type=Path, required=True, help="Your receipt JSON (the Merkle leaf).")
    p_cp_verify.add_argument(
        "--checkpoint", type=Path, required=True, help="The chapter's /api/checkpoint response JSON."
    )
    p_cp_verify.add_argument(
        "--proof",
        type=Path,
        required=True,
        help="The /api/checkpoint/proof/{receipt_id} response JSON.",
    )
    p_cp_verify.set_defaults(func=lambda args: _cmd_checkpoint_verify(args.receipt, args.checkpoint, args.proof))

    return parser


def main(argv: list[str] | None = None) -> None:
    """Entry point for the community-member command.

    ``argv`` defaults to ``sys.argv[1:]`` when called as a script; the
    parameter exists so tests can invoke ``main([...])`` without
    monkeypatching ``sys.argv``.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Default behavior: no subcommand → wizard. We can't make `wizard`
    # the argparse default (subparsers don't support that cleanly), so
    # the routing happens here.
    if args.command is None:
        # Synthesize a wizard namespace so _cmd_wizard sees the expected
        # attributes. --no-browser without a subcommand is supported via
        # the synthesis.
        args = argparse.Namespace(
            command="wizard",
            no_browser="--no-browser" in (argv if argv is not None else sys.argv[1:]),
            func=_cmd_wizard,
        )

    func = getattr(args, "func", None)
    if func is None:
        # The user typed a parent subcommand without an action
        # (`community-member audit` with no `verify`). Show help and
        # exit non-zero so scripts treat it as a usage error.
        parser.parse_args([args.command, "--help"])
        sys.exit(2)

    sys.exit(func(args))


async def _run_both(app, agent, port: int = DASHBOARD_PORT, host: str | None = None):
    """Run FastAPI server, agent loop, and registry announcer concurrently.

    ``host`` defaults to :data:`DASHBOARD_BIND_HOST` (``127.0.0.1``). The
    dashboard serves ``/api/local/*`` without authentication, so binding it to
    every interface exposes the consent-gate settings to the network.
    """
    import uvicorn

    from . import DASHBOARD_BIND_HOST, registry

    bind_host = host or DASHBOARD_BIND_HOST
    server_config = uvicorn.Config(app, host=bind_host, port=port, log_level="warning")
    server = uvicorn.Server(server_config)
    local_url = f"http://localhost:{port}"

    # The announcer is bulletproof (swallows all errors) so a down or
    # unreachable registry can never stop the local agent from serving.
    await asyncio.gather(
        server.serve(),
        agent.run(interval=think_interval_seconds()),
        registry.announce_loop(agent.config, local_url=local_url),
    )


if __name__ == "__main__":
    main()
