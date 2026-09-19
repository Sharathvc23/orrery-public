"""Tie the deterministic ARP vector generator to the ARP receipt schema.

The generators (``conformance/arp/_vector_gen.py``) and the schema
(``schema/arp/0.1/receipt.schema.json``) were two independent artifacts
with nothing checking they agree. This test makes them co-enforcing:

  - ``verify_pass`` / ``signature_fail`` / ``hash_chain_fail`` vectors are
    STRUCTURALLY valid receipts (their failure, if any, is cryptographic,
    not structural) → they MUST validate against the receipt schema.
  - ``schema_fail`` vectors are deliberately malformed (wrong version,
    oversized summary, invalid did) → they MUST be REJECTED.

If the generator's receipt shape drifts from the schema in either
direction, exactly one side of this test breaks.
"""

from __future__ import annotations

from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from conformance.tests.conftest import SCHEMA_ROOT, _load_json

# Outcomes whose receipts are structurally valid (crypto failures aside).
STRUCTURALLY_VALID = {"verify_pass", "signature_fail", "hash_chain_fail"}
# Outcomes whose receipts must fail schema validation.
STRUCTURALLY_INVALID = {"schema_fail"}


def _receipt_validator() -> Draft202012Validator:
    arp_dir = SCHEMA_ROOT / "arp" / "0.1"
    resources = []
    for path in sorted(arp_dir.glob("*.json")):
        doc = _load_json(path)
        if "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc)))
    registry = Registry().with_resources(resources)
    receipt_schema = _load_json(arp_dir / "receipt.schema.json")
    return Draft202012Validator(receipt_schema, registry=registry)


def test_arp_vectors_conform_to_receipt_schema(arp_vectors: list[Path]) -> None:
    validator = _receipt_validator()
    checked = 0
    for vector_path in arp_vectors:
        vector = _load_json(vector_path)
        receipt = vector.get("receipt")
        outcome = vector.get("expected_outcome")
        if receipt is None or outcome is None:
            continue
        name = vector_path.name
        if outcome in STRUCTURALLY_VALID:
            errors = sorted(validator.iter_errors(receipt), key=str)
            assert not errors, f"{name} ({outcome}) should validate but: {errors[0].message}"
            checked += 1
        elif outcome in STRUCTURALLY_INVALID:
            errors = list(validator.iter_errors(receipt))
            assert errors, f"{name} ({outcome}) should be schema-rejected but it validated"
            checked += 1
    # Guard the test isn't a silent no-op (e.g. outcome field renamed).
    assert checked >= 15, f"expected to check >=15 vectors, checked {checked}"
