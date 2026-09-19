from __future__ import annotations

import runpy
from pathlib import Path

import httpx
import pytest

QUICKSTART_PATH = Path(__file__).resolve().parents[1] / "examples" / "quickstart.py"


def test_missing_chapter_exits_during_argument_validation_before_network(monkeypatch, capsys):
    """Omitting --chapter must not fall through to an HTTP request."""
    attempted_urls: list[str] = []

    def record_network_attempt(url: str, **_kwargs):
        attempted_urls.append(url)
        raise RuntimeError("network operation attempted")

    monkeypatch.setattr(httpx, "get", record_network_attempt)
    quickstart_main = runpy.run_path(str(QUICKSTART_PATH))["main"]

    with pytest.raises(SystemExit) as exc_info:
        quickstart_main([])

    assert attempted_urls == []
    assert exc_info.value.code == 2
    assert "--chapter" in capsys.readouterr().err
