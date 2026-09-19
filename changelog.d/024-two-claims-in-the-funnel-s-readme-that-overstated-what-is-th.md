### Two claims in the funnel's README that overstated what is there

`connect-src` was described as permitting "the configured host". The header is
`connect-src 'self' http: https:` — any http or https host. It stops `ws:` and
`data:` destinations and nothing narrower, and what actually constrains where the
funnel talks is `API_BASE`, which no browser enforces. Corrected to what the
header says.

`npm test` existed in `package.json` and on no page, while the README cited
individual suites as evidence without telling a reader how to run them, and
`tests/` and `package.json` were missing from the Files table. All three fixed,
with a table of what each suite holds down.
