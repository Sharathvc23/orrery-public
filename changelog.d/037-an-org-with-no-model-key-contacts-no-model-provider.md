### An org with no model key contacts no model provider

Provider selection auto-detects from whichever provider key is set and falls
through to a default when none is. With no key configured that default still
resolves a real remote endpoint, so `POST /api/surfaces/compose` built a client
aimed at `https://api.anthropic.com/v1/` holding the literal string `MISSING`,
sent each uncached intent there, and served its deterministic fallback once the
request was rejected. An operator who had chosen no provider was reaching one per
request, and would have learned it from an egress log rather than from the
documentation.

The endpoint now checks whether a provider is configured before calling one. With
none, it serves the same default shell and reports `planner_disabled` as the
reason, without making the request — so a keyless deployment produces no outbound
traffic and answers in milliseconds rather than after a rejected round trip.

An endpoint on the same machine counts as configured: Ollama, LM Studio,
llama.cpp and vLLM need no key, and a `localhost` or `127.0.0.1` base URL reaches
no third party either way.

`server/tests/test_compose_endpoint_fallback.py` asserts the absence of the call
at the socket, failing on any non-loopback connection attempt, because a test that
only inspects the response passes just as well while the request is being made.

`docs/CONFIGURATION.md` now states which provider is selected when none is set,
and where intent text goes.
