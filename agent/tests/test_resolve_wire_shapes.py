"""Both shapes the index has served for a resolved record.

⚠️ THE INDEX CHANGED THIS TWICE IN ONE DAY, measured hours apart on the same
endpoint. It served an IndexRecord — snake_case, ``media_type``/``registry_url``,
``status`` at the top level — under ``index_record``. It now serves an AI
Catalog IndexEntry — camelCase, ``type``/``url``, operational fields nested
under ``extensions["org.projectnanda"]`` — under ``entry``.

Reading only the old key turned a working four-hop into ``no_index_record``
with nothing wrong on either side. Reading only the new one would break every
peer that has not migrated, and this client talks to several indexes that do
not migrate together.
"""

from __future__ import annotations

from community_member import nanda_index

# The live payload, trimmed. Captured from api.nandaindex.org.
NEW_ENVELOPE = {
    "locator": "urn:air:regentix.ai:catalog:root",
    "identifier": "root",
    "match": "exact",
    "entry": {
        "identifier": "urn:air:regentix.ai:catalog:root",
        "displayName": "Regentix AI",
        "type": "application/ai-catalog+json",
        "url": "https://org.example",
        "tags": ["general ai"],
        "extensions": {"org.projectnanda": {"orgId": "regentix", "status": "active"}},
    },
}

OLD_ENVELOPE = {
    "locator": "urn:air:regentix.ai:catalog:root",
    "identifier": "root",
    "match": "exact",
    "index_record": {
        "org_id": "regentix",
        "display_name": "Regentix AI",
        "media_type": "application/ai-catalog+json",
        "registry_url": "https://org.example",
        "status": "active",
    },
}


def test_the_record_is_found_under_either_key():
    assert nanda_index.entry_of(NEW_ENVELOPE) is NEW_ENVELOPE["entry"]
    assert nanda_index.entry_of(OLD_ENVELOPE) is OLD_ENVELOPE["index_record"]
    assert nanda_index.entry_of({"locator": "x"}) is None


def test_both_shapes_normalise_to_the_same_record():
    """The rest of the module reads one spelling, so a wire change lands in one
    function rather than at every field access."""
    new = nanda_index.normalise_entry(NEW_ENVELOPE["entry"])
    old = nanda_index.normalise_entry(OLD_ENVELOPE["index_record"])
    for field in ("media_type", "registry_url", "status", "org_id"):
        assert new[field] == old[field], field
    assert new["media_type"] == "application/ai-catalog+json"
    assert new["registry_url"] == "https://org.example"
    assert new["status"] == "active"
    assert new["org_id"] == "regentix"


def test_a_missing_status_is_not_active():
    """The caller refuses what it cannot confirm. If absence read as active, a
    suspended org would resolve as a live one."""
    entry = {"type": "application/ai-catalog+json", "url": "https://x.test", "extensions": {}}
    assert nanda_index.normalise_entry(entry)["status"] in (None, "")


def test_the_camelcase_trust_manifest_is_found():
    """trust_manifest on an IndexRecord, trustManifest on an IndexEntry. The
    did comparison is the only thing standing between a changed key and a
    wrong answer, so it must not silently see None."""
    entry = {"trustManifest": {"identity": "did:key:zAbc", "identityType": "did"}}
    assert nanda_index.normalise_entry(entry)["trust_manifest"]["identity"] == "did:key:zAbc"
    record = {"trust_manifest": {"identity": "did:key:zAbc"}}
    assert nanda_index.normalise_entry(record)["trust_manifest"]["identity"] == "did:key:zAbc"


def test_an_unknown_shape_degrades_to_a_named_refusal_not_a_crash():
    entry = {"something": "else"}
    out = nanda_index.normalise_entry(entry)
    assert out["media_type"] is None and out["registry_url"] is None
