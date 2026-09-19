### Security — the `community-member` dashboard binds loopback

The `community-member` command bound its dashboard to `0.0.0.0` while printing
`Dashboard: http://localhost:<port>`, so the dashboard was reachable from the
network on every install run outside Compose. That surface includes
`/api/local/*`, which has no authentication: `PUT /api/local/identity-trust`
sets the trust score the executor compares against its auto-approve threshold,
above which trusted- and semi-trusted-provenance actions run without a consent
prompt.

The bind host now defaults to `127.0.0.1` and is set with
`COMMUNITY_MEMBER_BIND_HOST`. When it is not loopback, startup prints that the
dashboard API is unauthenticated and reachable from the network. The port probe
(`find_free_port`) binds the same address the server will.

The Compose-published agent port is governed separately by `AGENT_BIND_HOST`
and already defaulted to loopback; the container entrypoint (`agent/serve.py`)
still binds all interfaces inside the container, which is what the published
port maps onto.
