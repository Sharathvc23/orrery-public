"""A silent no-op must not look like a clean result.

``registry_divergence.check`` returns ``[]`` in two opposite situations: it
compared every registry and found no disagreement, or it compared nothing because
fewer than two registries were configured. Nothing distinguished them.

Measured on the live mesh 2026-09-13: regentix had ``REGISTRY_URL`` unset, so it
ran with one registry and its corroboration had been a permanent no-op, while
``/api/federation/divergence`` returned an empty findings list that read exactly
like "nothing wrong". It was found by reading ``/health`` org by org for an
unrelated reason — nothing surfaced it.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import registry_divergence as rd


def test_two_registries_report_corroborating():
    """HAPPY: the ordinary configuration says so plainly."""
    st = rd.corroboration_status(["https://a.example", "https://b.example"])
    assert st["corroborating"] is True
    assert st["registry_count"] == 2


def test_one_registry_is_reported_as_not_corroborating():
    """ADVERSARIAL: the regentix state. The whole point of the guard.

    Asserts the detail says what an empty findings list means, because the
    number alone still leaves a reader to work out the consequence.
    """
    st = rd.corroboration_status(["https://only.example"])
    assert st["corroborating"] is False
    assert st["registry_count"] == 1
    assert "not corroborating" in st["detail"].lower()
    assert "nothing was compared" in st["detail"].lower()


def test_no_registries_is_also_not_corroborating():
    """EDGE: zero is not a special case that slips through as healthy."""
    assert rd.corroboration_status([])["corroborating"] is False


def test_duplicates_do_not_fake_corroboration():
    """ADVERSARIAL: one registry listed twice is still one registry.

    A naive len() on the raw list would report corroborating here and compare a
    registry against itself, which agrees by construction — the most misleading
    possible green.
    """
    st = rd.corroboration_status(["https://a.example", "https://a.example/"])
    assert st["corroborating"] is False
    assert st["registry_count"] == 1


def test_status_and_behaviour_cannot_disagree():
    """EDGE: the reported status uses the same deduper and threshold as check().

    If they diverged, /health could claim corroboration while check() no-ops —
    a worse failure than the one this guard exists to fix, because it would be
    actively reassuring.
    """
    import inspect

    src = inspect.getsource(rd.check)
    assert "_dedupe(registry_urls)" in src, "check() must use the shared deduper"
    assert "MIN_REGISTRIES_TO_CORROBORATE" in src, "check() must use the shared threshold"
