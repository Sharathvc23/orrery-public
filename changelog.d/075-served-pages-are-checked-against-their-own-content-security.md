### Served pages are checked against their own Content-Security-Policy, and the admin UI no longer loads a stylesheet from a CDN

`server/static/admin/index.html` linked a stylesheet from a public CDN. Its own
policy is `style-src 'self'` plus a hash of its inline block, so the stylesheet
was blocked on every load and the page rendered without it, including the custom
properties the page's own rules referenced. The link is removed and the palette is
defined in the page, matching the other served documents; the admin UI now loads no
third-party resource.

Nothing detected that, because the policy and the document were only ever checked
separately: one test asserted a header was present, another asserted directives in a
policy computed from a file, and nothing compared the two. `server/tests/test_csp.py`
now extracts each page's subresource references from the shipped bytes and asserts
each is permitted by that page's own computed policy. It reads markup rather than
driving a browser, so requests issued by script at runtime — governed by
`connect-src 'self'` — remain outside its view.

The strength assertions covered `admin/index.html` alone. They are parameterised over
all four served documents, so `/console/`, `/join/` and `/receipts/` are covered too,
and the inline-hash assertion now counts the blocks present in each document instead
of requiring that some hash exist. `server/csp.py`'s description of its own scope
named two documents and is corrected to four.
