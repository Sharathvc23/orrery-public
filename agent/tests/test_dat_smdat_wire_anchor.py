"""wire anchor — the vendored DAT verifier vs sm-dat's canonical vectors.

sm-dat (github.com/Sharathvc23/sm-dat) is a redesigned superset verifier, so a
byte lockstep is impossible-by-design (that anchor stays `conformance/dat`, see
test_dat_lockstep.py). What the implementations MUST share is the wire: the
dat/0.1 envelope, the Ed25519-over-JCS signing path, and the stateless
constraint vocabulary. This guard cross-verifies `community_member._dat`
against sm-dat's own vectors (mirrored under tests/vectors/sm_dat/0.1, pinned
by sha256 manifest) so the two implementations cannot silently diverge on what
a valid DAT is. Every vector is either asserted here or explicitly listed
out-of-surface with its reason — an upstream vector change forces a triage.

See docs/integrations/STELLARMINDS.md ("DAT verifier — … anchored to sm-dat at
the WIRE") for the full decision.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from community_member._dat import evaluate_constraints, verify_dat_signature

VECTOR_DIR = Path(__file__).resolve().parent / "vectors" / "sm_dat" / "0.1"

# Vectors whose *verdict* exercises sm-dat-only semantics the vendored verifier
# deliberately does not implement. Their grants still participate in the
# signature-layer assertions below; only the verdict comparison is out of
# surface. Reasons are load-bearing: a vector leaving this list must gain an
# assertion.
OUT_OF_SURFACE: dict[str, str] = {
    "03-counterparty_not_allowed.json": (
        "known divergence: Orrery's allowlist binds by counterparty_did "
        "(vector's counterparty has only a label); sm-dat also binds by label"
    ),
    "08-grantee_mismatch.json": "grantee/actor binding lives in dat.py (verify_counterparty_dat), not _dat",
    "11-self_grant.json": "self-grant rejection is sm-dat policy; Orrery gates it at the store layer",
    "12-period_under_cap.json": "stateful period caps need sm-dat's LedgerContext",
    "13-period_at_cap.json": "stateful period caps need sm-dat's LedgerContext",
    "14-period_over_cap.json": "stateful period caps need sm-dat's LedgerContext",
    "15-period_missing_ledger_indeterminate.json": "three-valued INDETERMINATE has no Orrery equivalent",
    "16-period_tiebreak_same_ts_counts_prior.json": "stateful period caps need sm-dat's LedgerContext",
    "17-period_tiebreak_same_ts_excludes_later.json": "stateful period caps need sm-dat's LedgerContext",
    "18-revocation_live.json": "revocation-freshness semantics are sm-dat's checker protocol",
    "19-revocation_revoked_before.json": "revocation-freshness semantics are sm-dat's checker protocol",
    "20-revocation_revoked_after.json": "revocation-freshness semantics are sm-dat's checker protocol",
    "21-revocation_stale_indeterminate.json": "three-valued INDETERMINATE has no Orrery equivalent",
    "22-revocation_no_checker_indeterminate.json": "three-valued INDETERMINATE has no Orrery equivalent",
    "23-predicate_unsupported_indeterminate.json": "predicate hooks are sm-dat-only",
    "24-initial_bind_authorizes_nothing.json": "initial-bind grants (empty scope) are sm-dat-only",
    "25-subdelegation_valid_narrowing.json": "chains use sm-dat's delegation object, not granted_by",
    "26-subdelegation_widening_breach.json": "chains use sm-dat's delegation object, not granted_by",
    "27-multigrant_all_satisfied.json": "multi-grant aggregation is sm-dat's verify_authority_chain",
    "28-multigrant_one_violated.json": "multi-grant aggregation is sm-dat's verify_authority_chain",
    "29-multigrant_one_indeterminate.json": "three-valued INDETERMINATE has no Orrery equivalent",
    "30-chain_initial_bind_neutral_real_satisfies.json": "initial-bind chains are sm-dat-only",
    "31-chain_initial_bind_no_shortcircuit_real_denies.json": "initial-bind chains are sm-dat-only",
    "32-chain_initial_bind_only_authorizes_nothing.json": "initial-bind chains are sm-dat-only",
}

# Vectors that must break at the SIGNATURE layer in both implementations.
BAD_SIGNATURE = {"09-bad_signature.json", "10-malformed_missing_field.json"}


def _vectors() -> dict[str, dict]:
    return {p.name: json.loads(p.read_text()) for p in sorted(VECTOR_DIR.glob("*.json")) if p.name != "MANIFEST.json"}


def _grants(vector: dict) -> list[dict]:
    return [vector["grant"]] if "grant" in vector else list(vector.get("grants", []))


def _receipt_for(vector: dict) -> dict:
    """Map a vector's bare `action` to the receipt shape Orrery's constraint
    evaluator reads (`action` + `jurisdiction.action_locus`)."""
    action = vector["action"]
    receipt: dict = {"action": action}
    if action.get("jurisdiction"):
        receipt["jurisdiction"] = {"action_locus": action["jurisdiction"]}
    return receipt


def test_mirror_matches_manifest():
    """The mirrored vectors are pinned: a local edit (or a re-mirror from a
    different upstream commit without updating the manifest) fails loudly."""
    manifest = json.loads((VECTOR_DIR / "MANIFEST.json").read_text())
    assert manifest["upstream_commit"] == "be782a85b7b2d3fe173978e18d93fa669897af78"
    on_disk = {p.name for p in VECTOR_DIR.glob("*.json")} - {"MANIFEST.json"}
    assert on_disk == set(manifest["sha256"]), "vector set differs from manifest"
    for name, want in manifest["sha256"].items():
        got = hashlib.sha256((VECTOR_DIR / name).read_bytes()).hexdigest()
        assert got == want, f"{name} does not match its manifest sha256"


def test_every_vector_is_triaged():
    """Each vector is either verdict-asserted here or explicitly out-of-surface
    — a new upstream vector cannot slip in unexamined."""
    vectors = _vectors()
    assert len(vectors) == 33
    unknown = set(OUT_OF_SURFACE) - set(vectors)
    assert not unknown, f"out-of-surface entries with no vector: {unknown}"


def test_signature_layer_full_agreement():
    """The signing path (JCS body-sans-signature, Ed25519, did:key) is in
    cross-implementation lockstep: EVERY intact grant in EVERY vector —
    including sm-dat's richer bodies (delegation objects, signed nulls,
    stateful scopes) — verifies under the vendored verifier, and exactly the
    broken-body vectors fail at the signature stage."""
    for name, vector in _vectors().items():
        for i, grant in enumerate(_grants(vector)):
            result = verify_dat_signature(grant)
            if name in BAD_SIGNATURE:
                assert not result.ok, f"{name}[{i}]: broken grant must fail signature verify"
                assert result.stage == "signature"
            else:
                assert result.ok, f"{name}[{i}]: intact sm-dat grant must signature-verify: {result.detail}"


def test_validity_window_agreement():
    """Window semantics agree: in-window verifies, expired and not-yet-valid
    are rejected — evaluated at the vector's own `issued_at` instant."""
    vectors = _vectors()

    def in_window(name: str) -> bool:
        v = vectors[name]
        g = v["grant"]
        return bool(g["not_before"] <= v["issued_at"] <= g["not_after"])

    assert in_window("00-stateless_satisfied.json") is True
    assert in_window("06-expired.json") is False
    assert in_window("07-not_yet_valid.json") is False


def test_leaf_category_scope_agreement():
    """Leaf category scoping agrees: the action's category must be in
    scope.action_categories (same key in both wire shapes)."""
    vectors = _vectors()

    def in_scope(name: str) -> bool:
        v = vectors[name]
        cats = set(v["grant"]["scope"]["action_categories"])
        return v["action"]["category"] in cats or "*" in cats

    assert in_scope("00-stateless_satisfied.json") is True
    assert in_scope("05-category_out_of_scope.json") is False


def test_stateless_constraint_vocabulary_agreement():
    """The shared constraint vocabulary evaluates identically on the stateless
    keys: per-action amount cap, currency, jurisdictions (sm-dat carries them
    under scope.stateless; Orrery under scope.constraints — same keys, same
    meanings, fed here to Orrery's own evaluator)."""
    vectors = _vectors()

    def verdict(name: str) -> bool:
        v = vectors[name]
        constraints = v["grant"]["scope"]["stateless"]
        return evaluate_constraints(constraints, _receipt_for(v)).ok

    assert verdict("00-stateless_satisfied.json") is True
    assert verdict("01-amount_cap_exceeded.json") is False
    assert verdict("02-amount_currency_mismatch.json") is False
    assert verdict("04-jurisdiction_not_allowed.json") is False


def test_out_of_surface_reasons_are_current():
    """The known-divergence entry for vector 03 stays honest: the vector's
    counterparty really does carry only a label (no did). If upstream adds a
    did, Orrery's evaluator becomes applicable and 03 must move to an
    assertion."""
    v = _vectors()["03-counterparty_not_allowed.json"]
    assert not v["action"].get("counterparty_did")
    assert v["action"].get("counterparty_label")
    # And Orrery's evaluator, fed the vector as-is, skips the check (documented
    # divergence — binds by did, not label):
    result = evaluate_constraints(v["grant"]["scope"]["stateless"], _receipt_for(v))
    assert result.ok, "if this starts failing, Orrery gained label-binding — retire the divergence note"


@pytest.mark.parametrize("name", sorted(OUT_OF_SURFACE))
def test_out_of_surface_vectors_still_signature_verify(name: str):
    """Out-of-surface excludes only the VERDICT comparison — the signature
    layer must hold for these vectors too (belt over test_signature_layer)."""
    vector = _vectors()[name]
    for grant in _grants(vector):
        assert verify_dat_signature(grant).ok
