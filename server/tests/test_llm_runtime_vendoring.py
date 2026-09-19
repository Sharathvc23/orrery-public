"""server/llm_runtime.py is a copy, not a second implementation.

The same pin as test_agent_scheduler.py holds over retry_policy.py, and it is
here as well as in the agent's suite on purpose: the two trees run in separate
CI jobs with separate path filters, so a pin that lived on only one side would
let a change to the other tree land unchecked. That is the one-sided-pin failure
this repository has already paid for once.

Why the file is vendored rather than shared: infra/Dockerfile.server copies only
server/, conformance/, schema/, vectors/ and infra/migrations/, and the agent
image builds with context: agent, so a repo-root package would be outside both
images — and the agent additionally ships as a standalone distributable that
cannot depend on a repo sibling.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_llm_runtime_is_byte_identical_to_the_agent_copy():
    vendored = (REPO / "server" / "llm_runtime.py").read_bytes()
    upstream = (REPO / "agent" / "community_member" / "llm_runtime.py").read_bytes()
    assert vendored == upstream, (
        "server/llm_runtime.py has drifted from agent/community_member/llm_runtime.py — "
        "re-copy it whole rather than editing one side. "
        f"server md5={hashlib.md5(vendored).hexdigest()} "
        f"agent md5={hashlib.md5(upstream).hexdigest()}"
    )


def test_the_server_copy_imports_nothing_the_server_image_lacks():
    """stdlib + openai only.

    The agent package is not in the server image, so an import of
    community_member here would fail at runtime in production and pass in a
    developer checkout, where both trees are on the path.
    """
    source = (REPO / "server" / "llm_runtime.py").read_text()
    assert "from community_member" not in source
    assert "import community_member" not in source
    # openai is imported inside build_client, so importing the module for a
    # report-only resolution costs nothing and needs no dependency.
    top = source.split("def build_client", 1)[0]
    assert "from openai import" not in top


def test_the_server_copy_resolves_without_a_fallback():
    """The defect this module removes, asserted from the server tree too.

    server/chapter_agent.py's LLM path and the agent's both used
    `.get(provider, "https://api.openai.com/v1")`, so an unset or misspelt
    provider became a request to OpenAI carrying whatever key was resolved.
    """
    import sys

    sys.path.insert(0, str(REPO / "server"))
    import llm_runtime

    for unusable in ("", "   ", "typo-provider"):
        try:
            llm_runtime.resolve(unusable)
        except llm_runtime.LLMNotConfigured:
            continue
        raise AssertionError(f"{unusable!r} resolved to something instead of refusing")

    assert llm_runtime.resolve(" Ollama ").base_url == "http://localhost:11434/v1"
