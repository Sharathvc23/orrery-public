"""Profile 'Corroborated standing' section — the nanda-rep/0.2 (counterparty-
corroborated) reputation + corroboration rate, shown on the public agent profile
surface (the README's "foundation primitive for organic growth").

Pure helper test: given a verifiable_receipts facet, it produces the right A2UI
nodes; an empty facet renders nothing. The facet-build integration is covered by
tests/test_vrp_ledger.py.

Classification: HAPPY / EDGE.
"""

import os

os.environ.setdefault("AGENT_ID", "test-profile-chapter")
os.environ.setdefault("AGENT_NAME", "Test Profile Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import surfaces  # noqa: E402


def _by_id(components):
    return {c["id"]: c for c in components}


def test_corroboration_section_renders_metrics():  # HAPPY
    sections, components = surfaces._corroboration_section(
        {
            "behavioral_merkle_root": "sha256:abc",
            "reputation_score": 5.0,
            "corroboration_rate": 0.5,
            "receipt_count": 2,
            "scoring_method": "nanda-rep/0.2",
        }
    )
    assert sections == ["pf-rep-label", "pf-rep-card", "pf-rep-caption"]
    byid = _by_id(components)
    assert byid["pf-rep-score"]["value"] == "5"  # only corroborated receipts
    assert byid["pf-rep-corr"]["value"] == "50%"  # half were corroborated
    assert byid["pf-rep-count"]["value"] == "2"
    # The row binds the three metrics in order.
    assert byid["pf-rep-card"]["component"] == "Row"
    assert byid["pf-rep-card"]["children"] == ["pf-rep-score", "pf-rep-corr", "pf-rep-count"]


def test_corroboration_section_empty_when_no_receipts():  # EDGE — render nothing, not an empty card
    assert surfaces._corroboration_section({}) == ([], [])
    assert surfaces._corroboration_section({"behavioral_merkle_root": None}) == ([], [])


def test_corroboration_section_defaults_missing_scores_to_zero():  # EDGE
    sections, components = surfaces._corroboration_section({"behavioral_merkle_root": "sha256:x"})
    assert sections  # a root means there are receipts → render the section
    byid = _by_id(components)
    assert byid["pf-rep-score"]["value"] == "0"
    assert byid["pf-rep-corr"]["value"] == "0%"
    assert byid["pf-rep-count"]["value"] == "0"
