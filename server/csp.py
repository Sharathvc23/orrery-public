"""Content-Security-Policy for this org's HTML surfaces (AUDIT_HARSH C5).

Scoped to HTML. A CSP on a JSON API response protects nothing — no browser
parses `application/json` as a document — so the header would only add bytes to
every call. The documents this covers are `/console/`, `/join/`, `/receipts/`
and `/admin/`, served by `chapter_agent._static_page` and the two routes that
call `document_headers` directly.

Those pages carry inline `<style>` blocks, and `/admin/` an inline `<script>`,
which leaves three ways to write the policy:

* `script-src 'unsafe-inline'`, which re-permits the injection class the policy
  exists to stop;
* a build step emitting hashes, which go stale when the HTML is edited and then
  break the page in a browser rather than in CI;
* hashing the file at serve time, which cannot go stale because the input to the
  hash is the same bytes the browser receives.

The third is what this does, so editing the HTML needs no other step: the next
boot hashes the new content.

`frame-ancestors 'none'` is set because the admin UI keeps a token in
localStorage, which makes framing it worth preventing.

A header does not weaken a page's own meta policy. When both are present the
browser enforces each independently, so the effective policy is their
intersection.
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

#: Directives that hold regardless of what the page contains.
_BASE = (
    "default-src 'self'",
    "object-src 'none'",  # no plugin-based script execution
    "base-uri 'none'",  # a injected <base> cannot re-point relative URLs
    "frame-ancestors 'none'",  # the admin UI keeps a token — do not let it be framed
    "form-action 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
)

_INLINE_SCRIPT = re.compile(rb"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
_INLINE_STYLE = re.compile(rb"<style[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
#: `style="..."` attribute VALUES — hashed separately, see policy_for().
_INLINE_STYLE_ATTR = re.compile(rb"""\sstyle=["']([^"']*)["']""", re.IGNORECASE)

_cache: dict[str, str] = {}


def _sha256_source(block: bytes) -> str:
    """A CSP `'sha256-...'` source for one inline block.

    The digest is over the block's exact bytes — the browser hashes what sits
    between the tags, so no stripping or normalisation is allowed here.
    """
    return f"'sha256-{base64.b64encode(hashlib.sha256(block).digest()).decode()}'"


def policy_for(path: str | Path) -> str:
    """The CSP header value for the HTML document at ``path``.

    Cached per path: the file is read once per process, and these are static
    bundle assets that do not change under a running server.
    """
    key = str(path)
    if key in _cache:
        return _cache[key]

    try:
        html = Path(path).read_bytes()
    except OSError:
        # Cannot read it ⇒ cannot hash it. Fall back to the strictest policy
        # that is still correct rather than to a permissive one.
        return "; ".join((*_BASE, "script-src 'none'", "style-src 'none'"))

    scripts = [_sha256_source(m.group(1)) for m in _INLINE_SCRIPT.finditer(html)]
    styles = [_sha256_source(m.group(1)) for m in _INLINE_STYLE.finditer(html)]

    # Inline style="..." ATTRIBUTES are a separate case from <style> elements:
    # they need BOTH `'unsafe-hashes'` and a hash of each attribute's own value.
    # `'unsafe-hashes'` on its own permits nothing — it only says "the hashes
    # listed here may also match attributes", so the values must be hashed too.
    attr_values = {m.group(1) for m in _INLINE_STYLE_ATTR.finditer(html)}
    style_attrs = sorted(_sha256_source(v) for v in attr_values)

    style_sources = ["style-src", "'self'", *styles]
    if style_attrs:
        style_sources += ["'unsafe-hashes'", *style_attrs]

    directives = [
        *_BASE,
        " ".join(["script-src", "'self'", *scripts]),
        " ".join(style_sources),
    ]
    value = "; ".join(directives)
    _cache[key] = value
    return value


def clear_cache() -> None:
    """Drop the memoised policies (tests build pages on the fly)."""
    _cache.clear()


#: Referrer policy for served HTML documents.
#:
#: `no-referrer` because `/join/` carries a single-use invite token in its query
#: string, and none of these documents needs a referrer. A uniform value means a
#: page added here inherits it rather than the browser default.
#:
#: Scoped to HTML for the same reason the CSP above is: a JSON response is not a
#: document and generates no referrer, so the header there would have no effect.
#:
#: `/join/` also carries `<meta name="referrer" content="no-referrer">`, so the
#: policy holds when that file is served by something other than this app.
REFERRER_POLICY = "no-referrer"


def document_headers(path: str | Path) -> dict[str, str]:
    """The full response-header set for the HTML document at ``path``.

    Kept in one place so a route cannot set the CSP and omit the referrer policy.
    """
    return {
        "Content-Security-Policy": policy_for(path),
        "Referrer-Policy": REFERRER_POLICY,
    }
