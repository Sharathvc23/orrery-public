### Served HTML documents send a referrer policy

The join URL carries a single-use invite token in its query string, and no
response or page declared a referrer policy, so whether that URL reached a third
party depended on the browser default. `/join/` has no cross-origin subresource
and no outbound link, so nothing sent it; `/admin/` does load a third-party asset.

`/console/`, `/join/`, `/receipts/` and `/admin/` now send
`Referrer-Policy: no-referrer` from a single `csp.document_headers()` helper, so a
route cannot set the CSP and omit the referrer policy. `/join/` also carries the
equivalent `<meta>`, so the policy holds when that file is served by a static file
server.
