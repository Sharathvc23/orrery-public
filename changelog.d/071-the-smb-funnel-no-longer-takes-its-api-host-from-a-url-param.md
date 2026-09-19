### The SMB funnel no longer takes its API host from a URL parameter, and no longer assigns a URL from the response

`smb_funnel/src/config.js` read a `?api=` query parameter to select the host that
answers `/provision`, above both `localStorage` and the built-in `API_BASE`
constant. The provisioning screen renders that response directly — the agent's
endpoint, its `did:key`, and the recovery phrase the page instructs the user to
write down — so a link of the form `index.html?api=https://other.example` caused
those values to be produced by a host the reader of the link did not choose and
displayed on the funnel's own origin. No script execution is involved, so the
page's Content-Security-Policy does not affect it.

The parameter is no longer read. The host is selected by
`localStorage["smb_funnel.api_base"]` or by the `API_BASE` constant, and
`smb_funnel/README.md` gives the `localStorage` form for local demos.

Separately, the agent-card field was an `<a>` whose `href` was assigned from the
response's `endpoint` value, so a response of `{"endpoint": "javascript:..."}`
produced a `javascript:` URL that runs on click wherever inline script is
permitted. The card URL is now rendered as text and copied, in the same shape as
the endpoint and `did:key` fields beside it.
`smb_funnel/tests/source-guard.test.mjs` rejects assignment to `href`, `src`,
`action` or `formAction`, and `setAttribute` of a URL-bearing attribute, anywhere
in the funnel's source.
