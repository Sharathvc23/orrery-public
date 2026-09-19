"""That change — a receipt must be verifiable by a stranger, and forgeries must FAIL.

The product claim is "verify cryptographically, offline, without trusting a
vendor". Audited 2026-08-02: no outsider could verify a receipt — /api/receipts
is 401 (correctly) and disclosure was agent-local, file-based, with no public URL.

A test showing a GOOD bundle verifies proves nothing: every broken
implementation passes that too. What these pin is the failures.

⚠️ THE CENTRAL PROPERTY: the verifying key must NOT come from the bundle. If it
did, a forger would supply both the receipt and the key that checks it, and it
would verify perfectly. So verification resolves the key independently — the
issuer's did:key is checked against the org's /.well-known/did.json, and the
Ed25519 key is then DERIVED from that did:key (did:key is self-certifying, so no
key material is transported at all). test_wrong_key_fails is what makes that
real rather than asserted.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
import sm_arp

import receipt_publication as rp

_REPO_SERVER = Path(__file__).resolve().parents[1]


def _org_receipt(ident, note: str = "published sample") -> dict:
    """A real signed ARP receipt issued by ``ident`` (receipt_id is a UUIDv4)."""
    action = sm_arp.build_action(category="chapter_action", human_summary=note, outcome="completed")
    return sm_arp.issue_receipt(ident, principal_did=ident.did, action=action)


@pytest.fixture
def org():
    """An org identity plus a 3-receipt issuer log and a published bundle."""
    sk = sm_arp.gen_key()
    ident = sm_arp.Identity(sk)
    did = ident.did
    # SEVEN receipts: deliberately not a power of two. A balanced fixture is why
    # the naive fold passed here while failing on the first real bundle.
    log = [_org_receipt(ident, f"action {i}") for i in range(7)]
    log.sort(key=lambda r: (r.get("issued_at", ""), r.get("receipt_id", "")))
    target = log[1]["receipt_id"]
    bundle = rp.build_bundle(
        publication_id="sample",
        published_at="2026-08-02T22:00:00+00:00",
        receipt_ids=[target],
        issuer_log=log,
        issuer_did=did,
        sk_bytes=bytes(sk),
    )
    return {"sk": sk, "did": did, "log": log, "bundle": bundle, "target": target}


# ── The bundle must not carry its own verifying key ──────────────────────────


def _data_only(bundle: dict) -> str:
    """The bundle's DATA, excluding the human-readable instructions.

    ``how_to_verify`` necessarily names the fields an auditor must look up
    (``publicKeyMultibase``, ``did.json``); that is guidance, not key material.
    The assertions below are about what a verifier could mistakenly TRUST, so
    they scan the data and not the prose.
    """
    d = {k: v for k, v in bundle.items() if k != "how_to_verify"}
    return json.dumps(d)


def test_bundle_carries_no_key_material(org):
    """The whole unit. A key in the bundle makes verification self-referential."""
    blob = _data_only(org["bundle"])
    for forbidden in ("publicKey", "public_key", "publicKeyMultibase", "verificationMethod"):
        assert forbidden not in blob, f"bundle carries {forbidden} — a forger would supply both"


def test_bundle_carries_no_did_document_url(org):
    """A forger who names the did-document URL points it at a host they control.

    The URL has to come from outside the artifact — the auditor uses the org they
    chose to audit — so it is deliberately absent from the data.
    """
    blob = _data_only(org["bundle"])
    assert "did.json" not in blob, "bundle supplies its own authority URL"
    assert "http" not in blob.replace("https://w3id.org", ""), "bundle carries a fetchable URL"


# ── Tamper: each must FAIL ───────────────────────────────────────────────────


def test_TAMPER_receipt_field_fails_signature(org):
    """Flip one field in a disclosed receipt — the signature must stop verifying."""
    tampered = copy.deepcopy(org["bundle"]["disclosed"][0]["receipt"])
    assert sm_arp.verify_signature(tampered).ok, "control: the untampered receipt verifies"

    tampered["action"]["human_summary"] = tampered["action"]["human_summary"] + " (altered)"
    assert not sm_arp.verify_signature(tampered).ok, "a tampered receipt still verified"


def test_TAMPER_signature_bytes_fail(org):
    """Corrupt the signature itself."""
    tampered = copy.deepcopy(org["bundle"]["disclosed"][0]["receipt"])
    sig = tampered["signature"]
    tampered["signature"] = ("B" if sig[0] != "B" else "C") + sig[1:]
    assert not sm_arp.verify_signature(tampered).ok, "a corrupted signature still verified"


def test_TAMPER_merkle_proof_fails_inclusion(org):
    """Corrupt one node of the inclusion proof — it must stop folding to the root."""
    entry = org["bundle"]["disclosed"][0]
    root_hex = org["bundle"]["checkpoint"]["payload"]["merkle_root"].removeprefix("sha256:")

    good = [bytes.fromhex(h) for h in entry["proof"]]
    assert _folds_to(entry, good, root_hex, len(org["log"])), "control: the real proof folds to the signed root"

    bad = list(good)
    bad[0] = bytes([bad[0][0] ^ 0xFF]) + bad[0][1:]
    assert not _folds_to(entry, bad, root_hex, len(org["log"])), "a corrupted Merkle proof still verified"


def _folds_to(entry: dict, proof: list[bytes], root_hex: str, tree_size: int) -> bool:
    """RFC 6962 §2.1.1 audit-path verification — the arithmetic the docs publish.

    This test previously used a naive ``idx & 1`` binary fold, which agrees with
    RFC 6962 only on a perfectly balanced tree. Every fixture here happened to be
    balanced, so the suite passed while the SAME wrong fold shipped in
    docs/VERIFY_A_RECEIPT.md and failed on the first real 7-leaf bundle. Hence
    ``tree_size``: without it the algorithm cannot be written correctly at all,
    which is the tell that the naive version was wrong.
    """
    import hashlib

    import arp as arp_mod

    node = hashlib.sha256(b"\x00" + arp_mod.checkpoint_leaves([entry["receipt"]])[0]).digest()
    fn, sn = entry["leaf_index"], tree_size - 1
    for sib in proof:
        if fn & 1 or fn == sn:
            node = hashlib.sha256(b"\x01" + sib + node).digest()
            while fn != 0 and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            node = hashlib.sha256(b"\x01" + node + sib).digest()
        fn >>= 1
        sn >>= 1
    return node.hex() == root_hex and sn == 0


def test_TAMPER_swapped_receipt_fails(org):
    """Substituting a DIFFERENT real receipt under the same proof must fail.

    Both receipts are genuinely signed by the org, so this is not caught by the
    signature check — only the Merkle proof binds a receipt to its position.
    """
    entry = copy.deepcopy(org["bundle"]["disclosed"][0])
    root_hex = org["bundle"]["checkpoint"]["payload"]["merkle_root"].removeprefix("sha256:")
    entry["receipt"] = copy.deepcopy(org["log"][5])
    assert sm_arp.verify_signature(entry["receipt"]).ok, "the substituted receipt is genuinely signed"
    assert not _folds_to(entry, [bytes.fromhex(h) for h in entry["proof"]], root_hex, len(org["log"]))


# ── Wrong key: the property that makes independent resolution real ───────────


def test_WRONG_KEY_another_orgs_did_fails(org):
    """Org A's bundle must NOT verify as org B.

    This is the check a verifier performs against /.well-known/did.json. Without
    it, a forger's internally-consistent bundle passes every other test here.
    """
    other_did = sm_arp.Identity(sm_arp.gen_key()).did
    assert other_did != org["did"]
    assert org["bundle"]["issuer_did"] != other_did, (
        "the bundle claims org A; a verifier holding org B's did:key must reject it"
    )


def test_WRONG_KEY_forged_bundle_is_internally_consistent_but_wrong_issuer(org):
    """The forgery this design defends against, made concrete.

    A forger with their OWN key produces a bundle where the signature verifies
    and every proof folds — internally perfect. The ONLY thing that exposes it is
    that issuer_did is not the did:key published at the org's did.json.
    """
    forger_sk = sm_arp.gen_key()
    forger = sm_arp.Identity(forger_sk)
    forger_did = forger.did
    forged_log = [_org_receipt(forger, "totally legitimate")]
    forged = rp.build_bundle(
        publication_id="sample",
        published_at="2026-08-02T22:00:00+00:00",
        receipt_ids=[forged_log[0]["receipt_id"]],
        issuer_log=forged_log,
        issuer_did=forger_did,
        sk_bytes=bytes(forger_sk),
    )

    # Internally flawless.
    assert sm_arp.verify_signature(forged["disclosed"][0]["receipt"]).ok

    # And caught the instant it is checked against the real org's identity.
    assert forged["issuer_did"] != org["did"], "the issuer_did check is what catches the forgery"


# ── Refusal to publish another issuer's receipt ──────────────────────────────


def test_refuses_to_publish_a_receipt_this_org_did_not_issue(org):
    """Publishing someone else's receipt from our surface would lend it our authority."""
    foreign = _org_receipt(sm_arp.Identity(sm_arp.gen_key()))
    log = sorted(org["log"] + [foreign], key=lambda r: (r.get("issued_at", ""), r.get("receipt_id", "")))
    with pytest.raises(rp.PublicationError, match="not by this org"):
        rp.build_bundle(
            publication_id="p",
            published_at="",
            receipt_ids=[foreign["receipt_id"]],
            issuer_log=log,
            issuer_did=org["did"],
            sk_bytes=bytes(org["sk"]),
        )


def test_refuses_an_unknown_receipt_id(org):
    with pytest.raises(rp.PublicationError, match="not in this org"):
        rp.build_bundle(
            publication_id="p",
            published_at="",
            receipt_ids=["nope"],
            issuer_log=org["log"],
            issuer_did=org["did"],
            sk_bytes=bytes(org["sk"]),
        )


# ── The stranger's test: verify with no Orrery code at all ───────────────────


_STRANGER = r'''
import json, sys, hashlib
import sm_arp

bundle = json.load(open(sys.argv[1]))
org_did = sys.argv[2]           # resolved from /.well-known/did.json, NOT from the bundle

if bundle["issuer_did"] != org_did:
    print("FAIL: issuer_did is not the org's published did:key"); sys.exit(1)

root = bundle["checkpoint"]["payload"]["merkle_root"].removeprefix("sha256:")

import jcs as _jcs   # RFC 8785; a dependency sm-arp already pulls in

def jcs(o):
    return _jcs.canonicalize(o)

for d in bundle["disclosed"]:
    r = d["receipt"]
    res = sm_arp.verify_signature(r)
    if not res.ok:
        print("FAIL: signature", res.detail); sys.exit(1)
    node = hashlib.sha256(b"\x00" + jcs(r)).digest()
    fn, sn = d["leaf_index"], bundle["checkpoint"]["payload"]["tree_size"] - 1
    for sib_hex in d["proof"]:
        sib = bytes.fromhex(sib_hex)
        if fn & 1 or fn == sn:
            node = hashlib.sha256(b"\x01" + sib + node).digest()
            while fn != 0 and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            node = hashlib.sha256(b"\x01" + node + sib).digest()
        fn >>= 1
        sn >>= 1
    if node.hex() != root or sn != 0:
        print("FAIL: inclusion proof does not fold to the signed root"); sys.exit(1)

print("OK")
'''


def _run_stranger(tmp_path: Path, bundle: dict, org_did: str) -> subprocess.CompletedProcess[str]:
    script = tmp_path / "verify.py"
    script.write_text(_STRANGER)
    doc = tmp_path / "bundle.json"
    doc.write_text(json.dumps(bundle))
    # cwd is deliberately NOT the server dir: nothing of ours is importable.
    return subprocess.run(  # noqa: S603
        [sys.executable, str(script), str(doc), org_did],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )


def test_NO_ORRERY_IMPORTS_a_stranger_can_verify(org, tmp_path):
    """Verification in a process that imports only sm_arp and the stdlib.

    If this were awkward to express, that awkwardness would itself be the
    finding: it would mean the bundle is not self-describing.
    """
    proc = _run_stranger(tmp_path, org["bundle"], org["did"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK" in proc.stdout


def test_NO_ORRERY_IMPORTS_stranger_rejects_the_wrong_org(org, tmp_path):
    """The same script, given a different org's did:key, must refuse."""
    other = sm_arp.Identity(sm_arp.gen_key()).did
    proc = _run_stranger(tmp_path, org["bundle"], other)
    assert proc.returncode == 1
    assert "issuer_did is not the org" in proc.stdout


def test_NO_ORRERY_IMPORTS_stranger_rejects_a_tampered_receipt(org, tmp_path):
    tampered = copy.deepcopy(org["bundle"])
    tampered["disclosed"][0]["receipt"]["action"]["human_summary"] = "altered"
    proc = _run_stranger(tmp_path, tampered, org["did"])
    assert proc.returncode == 1
    assert "FAIL" in proc.stdout


def test_the_stranger_script_does_not_import_orrery():
    """Pin the recipe itself: no server./agent. imports may creep in."""
    for banned in ("import arp", "import merkle", "receipt_publication", "chapter_agent", "sys.path"):
        assert banned not in _STRANGER, f"the published recipe imports Orrery code ({banned})"


# ── /api/receipts must stay private ──────────────────────────────────────────


def test_api_receipts_still_requires_auth_for_anonymous_callers():
    """Pinned BY NAME. Publishing an org receipt must never widen a member's
    private history — different question, different endpoint."""
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/receipts") is True
    assert auth_verify.is_open_path("GET", "/api/receipts") is False


def test_the_public_bundle_path_is_open():
    import auth_verify

    assert auth_verify.is_open_path("GET", "/.well-known/receipt-disclosure/sample.json") is True
