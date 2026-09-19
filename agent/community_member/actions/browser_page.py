"""Playwright binding for BrowserExecutor.navigate.

Factored out of browser.py so the executor's security-critical
orchestration (consent gate + approval verification) stays
Playwright-free and unit-testable without Chromium, while the actual
navigation is a thin well-tested function.

The default implementation is `default_page_goto()` which lazy-imports
Playwright. Tests and callers that don't need real navigation can
inject their own `PageGotoFn` callable into `BrowserExecutor.navigate`.

What the page function guarantees:
  1. Navigation runs inside a Chromium persistent context bound to
     `~/.community-member/browser-state/{chapter_id}/` — each chapter
     gets its own cookie jar, no cross-contamination.
  2. Returns structured metadata only (final URL, title, status,
     html_sha256, content length). No HTML body is returned to the
     executor by default; it would bloat the audit ledger and risk
     leaking secrets into prompts. The content hash lets the user
     later prove "I saw exactly this page."
  3. The context object is closed at the end of every call — no
     stale global browser handle.

Chromium launch is intentionally simple for W1: headless, no custom
args. W2 adds sandbox profile + download-to-sandbox-dir.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

__all__ = ["PageGotoFn", "PageGotoResult", "default_page_goto"]


@dataclass(frozen=True)
class PageGotoResult:
    """Structured navigation result — what the executor audits.

    The HTML body is NOT carried here. Only a sha256 over it so the
    user can later verify what the agent saw without the ledger
    needing to store megabytes of page text.
    """

    final_url: str
    title: str
    html_sha256: str
    status: int
    content_length: int


# Signature of a page-goto callable. Takes (state_dir, url, timeout_ms)
# and returns a PageGotoResult or raises on navigation failure.
PageGotoFn = Callable[[Path, str, int], PageGotoResult]


def default_page_goto(state_dir: Path, url: str, timeout_ms: int) -> PageGotoResult:
    """Real Playwright implementation.

    Lazy-imports `playwright.sync_api` so callers without Chromium
    installed (CI, tests that mock the factory) are unaffected at
    import time. Raises `RuntimeError` with an install hint if the
    import fails.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise RuntimeError(
            "playwright is not installed. It is not a dependency of this "
            "distribution: install it directly with 'pip install playwright' "
            "and run 'playwright install chromium' once."
        ) from e

    state_dir.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(state_dir),
            headless=True,
        )
        page = context.new_page()
        try:
            response = page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            final_url = page.url or url
            title = page.title() or ""
            html = page.content() or ""
            status = response.status if response else 0
        finally:
            context.close()

    html_bytes = html.encode("utf-8", errors="replace")
    return PageGotoResult(
        final_url=final_url,
        title=title,
        html_sha256=hashlib.sha256(html_bytes).hexdigest(),
        status=status,
        content_length=len(html_bytes),
    )
