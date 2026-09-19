"""CSP on the HTML surfaces, and nowhere else (AUDIT_HARSH C5).

The scoping matters as much as the policy. A CSP header on a JSON API response
protects nothing — no browser parses `application/json` as a document — so
blanket-applying one would be noise on every call. These tests pin both halves:
the two real HTML documents carry a policy, and the API does not.

The other thing pinned here is that the policy is *derived from the bytes served*.
Both pages use inline `<script>`/`<style>`, so the alternatives were
`'unsafe-inline'` (which would re-permit the exact injection class CSP exists to
stop) or a build-time hash that goes stale silently the next time someone edits
the HTML. Hashing at serve time is neither.

Classification: ADVERSARIAL (security control).
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import csp


@pytest.fixture
def client() -> TestClient:
    import chapter_agent

    chapter_agent._rate_limit_store.clear()
    return TestClient(chapter_agent.app)


#: Every HTML document this app serves. Kept in one place: the strength and
#: scoping assertions below covered `/receipts/` and `/admin/` only, while
#: `/console/` and `/join/` were served with a policy nothing checked.
SERVED_PAGES = ("console", "join", "receipts", "admin")

#: Their request paths, in the same order.
SERVED_PATHS = tuple(f"/{page}/" for page in SERVED_PAGES)


def _page_path(page: str) -> Path:
    return Path(__file__).resolve().parents[1] / "static" / page / "index.html"


def _directive(policy: str, name: str) -> str:
    for part in policy.split(";"):
        part = part.strip()
        if part.split(" ")[0] == name:
            return part
    return ""


class TestScoping:
    @pytest.mark.parametrize("path", SERVED_PATHS)
    def test_html_surfaces_carry_a_policy(self, client: TestClient, path: str) -> None:
        r = client.get(path)
        if r.status_code == 503:
            pytest.skip(f"{path} UI not bundled in this build")
        assert r.headers.get("Content-Security-Policy"), f"{path} served HTML with no CSP"

    @pytest.mark.parametrize("path", ["/health", "/api/receipts/recent"])
    def test_json_apis_do_not_carry_one(self, client: TestClient, path: str) -> None:
        """A CSP on JSON is bytes with no effect — scope it out deliberately."""
        r = client.get(path)
        assert "Content-Security-Policy" not in r.headers, (
            f"{path} returns {r.headers.get('content-type')} — a CSP there is noise"
        )


class TestPolicyStrength:
    """The directives that must not quietly weaken, on every served page.

    `policy` is parameterised over all of them. It previously covered
    `admin/index.html` alone, so the three other served documents had no strength
    assertion at all.
    """

    @pytest.fixture(params=SERVED_PAGES)
    def policy(self, request) -> str:
        # Resolved from this file rather than the relative string
        # "static/admin/index.html", which names the shipped page only when the
        # process runs from `server/`. From elsewhere `policy_for` took its
        # fail-closed OSError branch and returned a deny-all policy, under which
        # five of the six assertions below hold for any input.
        page = _page_path(request.param)
        if not page.exists():
            pytest.skip(f"{request.param} UI not bundled in this build")
        csp.clear_cache()
        return csp.policy_for(page)

    def test_never_unsafe_inline(self, policy: str) -> None:
        """`'unsafe-inline'` in script-src would make the whole exercise
        decorative — that is the failure this must never regress into."""
        assert "'unsafe-inline'" not in _directive(policy, "script-src")

    def test_no_wildcard_sources(self, policy: str) -> None:
        assert " *" not in policy and "'unsafe-eval'" not in policy

    @pytest.mark.parametrize(
        "directive,expected",
        [
            ("default-src", "default-src 'self'"),
            ("object-src", "object-src 'none'"),
            ("base-uri", "base-uri 'none'"),
            # the admin UI holds a token in localStorage — framing it is a real attack
            ("frame-ancestors", "frame-ancestors 'none'"),
        ],
    )
    def test_baseline_directives(self, policy: str, directive: str, expected: str) -> None:
        assert _directive(policy, directive) == expected

    def test_every_inline_block_is_covered_by_a_hash(self, policy: str, request) -> None:
        """A page with no inline `<script>` gets `script-src 'self'` and needs no
        hash, so the assertion is per block present in the document rather than a
        flat requirement that some hash exist. All four carry an inline
        `<style>`; only `admin` still carries an inline `<script>`."""
        page = _page_path(request.node.callspec.params["policy"])
        html = page.read_bytes()
        for pattern, directive in ((csp._INLINE_SCRIPT, "script-src"), (csp._INLINE_STYLE, "style-src")):
            blocks = list(pattern.finditer(html))
            sources = _directive(policy, directive)
            assert sources.count("'sha256-") >= len(blocks), (
                f"{page.parent.name}: {len(blocks)} inline block(s) but {sources.count(chr(39) + 'sha256-')} hash(es) in {directive}"
            )


class TestHashesMatchTheBytesServed:
    """The property that makes serve-time hashing safe: the policy can never be
    stale, because it is computed from the same bytes the browser receives."""

    def test_hash_tracks_an_edit(self, tmp_path) -> None:
        page = tmp_path / "p.html"
        page.write_text("<html><script>alert(1)</script></html>")
        csp.clear_cache()
        before = csp.policy_for(page)

        page.write_text("<html><script>alert(2)</script></html>")
        csp.clear_cache()
        after = csp.policy_for(page)

        assert before != after, "editing the inline script did not change the policy"

    def test_hash_is_the_real_sha256_of_the_block(self, tmp_path) -> None:
        body = "console.log('hi')"
        page = tmp_path / "p.html"
        page.write_text(f"<html><script>{body}</script></html>")
        csp.clear_cache()

        expected = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
        assert f"'sha256-{expected}'" in csp.policy_for(page)

    def test_external_script_src_is_not_hashed(self, tmp_path) -> None:
        """Only INLINE blocks get a hash; `<script src=...>` is covered by 'self'."""
        page = tmp_path / "p.html"
        page.write_text('<html><script src="/app.js"></script></html>')
        csp.clear_cache()
        assert _directive(csp.policy_for(page), "script-src") == "script-src 'self'"

    def test_style_attributes_get_unsafe_hashes_and_their_own_hash(self, tmp_path) -> None:
        """`'unsafe-hashes'` alone permits nothing — the attribute VALUE must be
        hashed too, or the page silently loses its styling."""
        page = tmp_path / "p.html"
        page.write_text('<html><div style="color:red">x</div></html>')
        csp.clear_cache()
        style = _directive(csp.policy_for(page), "style-src")
        expected = base64.b64encode(hashlib.sha256(b"color:red").digest()).decode()
        assert "'unsafe-hashes'" in style
        assert f"'sha256-{expected}'" in style

    def test_unreadable_page_fails_closed(self, tmp_path) -> None:
        csp.clear_cache()
        policy = csp.policy_for(tmp_path / "does-not-exist.html")
        assert _directive(policy, "script-src") == "script-src 'none'"


def test_renderer_meta_policy_is_untouched() -> None:
    """#C5 says do not weaken the renderer's existing strict policy to make one
    generic header fit everything. It is a separate static bundle with its own
    meta-tag CSP; assert that policy still says what it said."""
    from pathlib import Path

    here = Path(__file__).resolve().parents[2] / "renderer" / "index.html"
    if not here.exists():
        pytest.skip("renderer bundle not present")
    html = here.read_text()
    match = re.search(r'http-equiv="Content-Security-Policy"\s*\n?\s*content="([^"]+)"', html)
    assert match, "the renderer lost its meta CSP"
    policy = match.group(1)
    assert "default-src 'none'" in policy
    assert "'unsafe-inline'" not in policy


class TestReferrerPolicy:
    """`Referrer-Policy` on the served documents.

    `/join/` carries a single-use invite token in its query string. Before this,
    no response and no page declared a referrer policy, so whether that URL
    reached a third party depended on the browser default. `/join/` has no
    cross-origin subresource and no outbound link, so nothing sent it; `/admin/`
    does load a third-party asset.

    Scoped to HTML for the same reason the CSP is: a JSON response is not a
    document and generates no referrer.
    """

    @pytest.mark.parametrize("path", SERVED_PATHS)
    def test_every_served_document_carries_no_referrer(self, client: TestClient, path: str) -> None:
        r = client.get(path)
        if r.status_code == 503:
            pytest.skip(f"{path} UI not bundled in this build")
        assert r.headers.get("Referrer-Policy") == "no-referrer", (
            f"{path} served HTML with Referrer-Policy={r.headers.get('Referrer-Policy')!r}"
        )

    @pytest.mark.parametrize("path", ["/health", "/api/receipts/recent"])
    def test_json_apis_do_not_carry_one(self, client: TestClient, path: str) -> None:
        r = client.get(path)
        assert "Referrer-Policy" not in r.headers, (
            f"{path} returns {r.headers.get('content-type')} — a referrer policy there is noise"
        )

    def test_the_join_page_also_carries_the_meta(self) -> None:
        """The header covers this app's own responses. The meta covers the file
        being served by something else, as `renderer/` and `smb_funnel/` already
        are; a static file server sends none of these headers."""
        from pathlib import Path

        page = Path(__file__).resolve().parents[1] / "static" / "join" / "index.html"
        if not page.exists():
            pytest.skip("join UI not bundled in this build")
        html = page.read_text()
        assert re.search(
            r'<meta\s+name="referrer"\s+content="no-referrer"\s*/?>', html
        ), "the join page lost its no-referrer meta"

    def test_headers_come_from_one_place(self) -> None:
        """Both headers come from one helper, so a route cannot set the CSP and
        omit the referrer policy."""
        assert csp.document_headers("static/admin/index.html").keys() == {
            "Content-Security-Policy",
            "Referrer-Policy",
        }


class TestPagesLoadUnderTheirOwnPolicy:
    """Every subresource a served page references must be permitted by that
    page's own policy.

    The policy and the document were checked separately: one test asserted a
    header was present, another asserted directives in a policy computed from a
    file, and nothing compared the two. `admin/index.html` linked a stylesheet
    from a public CDN while its own policy said `style-src 'self'` plus a hash,
    so the stylesheet was blocked on every load and the page rendered without it.

    This compares them. It reads the shipped bytes rather than driving a browser,
    so it runs in this suite with no additional dependency; what it cannot see is
    a request issued by script at runtime, which `connect-src 'self'` governs.
    """

    #: Element/attribute pairs that fetch a subresource, and the directive that
    #: governs each. `connect-src` is deliberately absent: fetch targets are not
    #: visible in the markup.
    SUBRESOURCES = (
        (re.compile(rb"""<link\b[^>]*\brel=["']?stylesheet["']?[^>]*>""", re.I), rb"""\bhref=["']([^"']+)["']""", "style-src"),
        (re.compile(rb"""<script\b[^>]*\bsrc=[^>]*>""", re.I), rb"""\bsrc=["']([^"']+)["']""", "script-src"),
        (re.compile(rb"""<img\b[^>]*\bsrc=[^>]*>""", re.I), rb"""\bsrc=["']([^"']+)["']""", "img-src"),
    )

    @staticmethod
    def _permitted(url: str, sources: str) -> bool:
        """Whether ``url`` is allowed by a directive's source list.

        Only the cases these pages actually use: a relative or same-origin path
        needs `'self'`, and a `data:` URI needs `data:`. An absolute URL to
        another origin needs that origin listed, which none of these policies do.
        """
        if url.startswith("data:"):
            return "data:" in sources
        if url.startswith(("http://", "https://", "//")):
            return url.split("/")[2] in sources if "//" in url else False
        return "'self'" in sources

    def _subresources(self, page: str) -> tuple[str, list[tuple[str, str, str]]]:
        """(policy, [(url, directive, sources)]) for one page's markup."""
        static = Path(__file__).resolve().parents[1] / "static" / page / "index.html"
        if not static.exists():
            pytest.skip(f"{page} UI not bundled in this build")
        csp.clear_cache()
        policy = csp.policy_for(static)
        html = static.read_bytes()
        found = []
        for tag_re, attr_re, directive in self.SUBRESOURCES:
            sources = _directive(policy, directive)
            for tag in tag_re.finditer(html):
                m = re.search(attr_re, tag.group(0), re.I)
                if m:
                    found.append((m.group(1).decode(), directive, sources))
        return policy, found

    @pytest.mark.parametrize("page", SERVED_PAGES)
    def test_no_page_references_a_subresource_its_policy_blocks(self, page: str) -> None:
        _policy, found = self._subresources(page)
        for url, _directive_name, sources in found:
            assert self._permitted(url, sources), (
                f"{page}/index.html loads {url!r}, which its own policy blocks: {sources}"
            )

    def test_the_scan_finds_subresources_across_the_served_pages(self) -> None:
        """A page with no external subresource is legitimate — `admin` is one —
        but zero across all of them would mean the extraction patterns stopped
        matching, and every assertion above would then hold vacuously."""
        total = sum(len(self._subresources(page)[1]) for page in SERVED_PAGES)
        assert total >= 3, f"examined {total} subresources across {len(SERVED_PAGES)} pages"

    def test_the_extraction_finds_a_blocked_stylesheet(self, tmp_path) -> None:
        """The guard is only as good as its extraction, so the case it was
        written for is pinned directly."""
        page = tmp_path / "p.html"
        page.write_text('<html><link rel="stylesheet" href="https://cdn.example/x.css" /><style>a{}</style></html>')
        csp.clear_cache()
        policy = csp.policy_for(page)
        sources = _directive(policy, "style-src")
        assert not self._permitted("https://cdn.example/x.css", sources)
        assert self._permitted("./styles.css", sources)
