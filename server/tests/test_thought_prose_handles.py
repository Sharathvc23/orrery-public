"""Member handles must not reach an anonymous caller inside agent-authored prose.

``agent_thoughts.thought_text`` is prose the agent wrote, and
``think_conversation`` composes it as ``"@{speaker}: {text}"`` per line — so a
real member handle is embedded in the sentence, not in a column.
``surfaces.build_activity_surface`` serves that column to ANONYMOUS callers on
every chapter.

⚠️ WHY THE EXISTING CLOSURE DID NOT CATCH THIS, because the shape recurs. The
activity-feed PII closure removed ``member_name`` and ``user_message_snippet``
from this exact surface, and its test asserts on VALUES rather than key names
for exactly the right reason. But its sentinel lived in ``member_name``; the
row it fed in carried the prose ``"a public agent-authored thought"``. The
field it was guarding got clean and the field beside it was never probed.

⚠️ AND WHY ``_mentions_hidden`` IS NOT THE ANSWER AS WRITTEN. That filter, on
``/api/thoughts``, tests ``any(p in body for p in _PUBLIC_HIDDEN_PREFIXES)``
where the prefixes are ``("TEST-",)``. It catches a seeded test account and
nothing else: ``@priya-sharma-12`` passes it untouched. Applying that filter to
one more surface would convert a leak into a leak with a filter in front of it,
which is worse, because the next reader believes the surface is filtered.

So every assertion below uses a REAL handle shape. A TEST- sentinel would pass
on the leaking build.
"""

from __future__ import annotations

import json

import pytest

#: Deliberately NOT ``TEST-something``. This is the distinction that is the
#: whole bug: a sentinel carrying the one prefix the old filter matches would
#: have gone green against the code this test was written to fail against.
REAL_HANDLE = "priya-sharma-12"
HANDLE_IN_PROSE = f"@{REAL_HANDLE}: I have been reading about supply chain audits"


class TestAnonymousActivitySurface:
    @pytest.mark.asyncio
    async def test_a_real_handle_in_thought_prose_never_reaches_the_surface(self, monkeypatch):
        """THE GUARD. Serve the surface as an anonymous caller with a handle in
        the prose, and assert the handle is not in the response body."""
        import surfaces

        async def fake_pg(method, table, params=None, **kwargs):
            if table == "agent_thoughts":
                return [
                    {
                        "id": "t1",
                        "thought_type": "conversation",
                        "thought_text": HANDLE_IN_PROSE,
                        "chapter_name": "AstroCity",
                        "created_at": "2026-08-24T00:00:00Z",
                    }
                ]
            return []

        monkeypatch.setattr(surfaces, "pg_request", fake_pg)
        body = json.dumps(await surfaces.build_activity_surface())

        assert f"@{REAL_HANDLE}" not in body, (
            "a real member handle leaked into the public activity surface inside agent-authored prose"
        )
        assert REAL_HANDLE not in body, (
            "the handle leaked without its @ — redaction must remove the identifier, not just the sigil"
        )

    @pytest.mark.asyncio
    async def test_the_surface_still_says_something(self, monkeypatch):
        """Redaction must not empty the feed.

        A surface that renders nothing is not private, it is broken — and the
        difference matters because the fix for a broken feed is to undo the
        redaction.
        """
        import surfaces

        async def fake_pg(method, table, params=None, **kwargs):
            if table == "agent_thoughts":
                return [
                    {
                        "id": "t1",
                        "thought_type": "conversation",
                        "thought_text": HANDLE_IN_PROSE,
                        "chapter_name": "AstroCity",
                        "created_at": "2026-08-24T00:00:00Z",
                    }
                ]
            return []

        monkeypatch.setattr(surfaces, "pg_request", fake_pg)
        body = json.dumps(await surfaces.build_activity_surface())
        assert "supply chain audits" in body, "redaction removed the whole thought, not the handle"


class TestRedaction:
    def test_a_real_handle_is_redacted(self):
        import thought_redaction

        out = thought_redaction.redact_handles(HANDLE_IN_PROSE)
        assert REAL_HANDLE not in out
        assert "supply chain audits" in out

    def test_the_test_prefix_is_not_the_rule(self):
        """The old filter's entire behaviour, asserted as insufficient.

        If redaction ever narrows back to a prefix match, this fails.
        """
        import thought_redaction

        assert "priya" not in thought_redaction.redact_handles("@priya-sharma-12 said hello")

    def test_multiple_handles_on_multiple_lines(self):
        """The real shape: think_conversation joins one @handle line per turn."""
        import thought_redaction

        prose = "@ann-lee-4: hello there\n@bo-tan-9: hi back"
        out = thought_redaction.redact_handles(prose)
        assert "ann-lee-4" not in out
        assert "bo-tan-9" not in out
        assert "hello there" in out and "hi back" in out

    def test_an_email_address_is_not_mangled(self):
        """A bare @ inside a word is not a handle.

        Over-redacting prose is its own defect: it makes the feed unreadable
        and gives the next person a reason to remove the redaction entirely.
        """
        import thought_redaction

        out = thought_redaction.redact_handles("write to ann@example.com about it")
        assert "example.com" in out

    def test_prose_with_no_handles_is_returned_unchanged(self):
        import thought_redaction

        prose = "The chapter is growing steadily this quarter."
        assert thought_redaction.redact_handles(prose) == prose

    def test_none_and_empty_are_survivable(self):
        import thought_redaction

        assert thought_redaction.redact_handles("") == ""
        assert thought_redaction.redact_handles(None) == ""

    def test_the_replacement_says_something_was_removed(self):
        """A silently vanished handle reads as prose the agent wrote that way.

        Leaving a marker means a reader can tell redaction happened, which is
        the difference between a redacted feed and a confusing one.
        """
        import thought_redaction

        out = thought_redaction.redact_handles("@ann-lee-4: hello")
        assert thought_redaction.REDACTED in out


class TestWholeRowRoutes:
    """A route returning the whole row leaks through fields no prose filter reads."""

    def test_a2ui_card_titles_are_redacted_too(self):
        """``@{agent_id} thinks`` is a card title, not thought prose.

        ``_mentions_hidden`` reads ``thought_text`` and nothing else, so a
        filter that passed would still ship the handle in ``a2ui_surface``.
        """
        import thought_redaction

        row = {
            "thought_text": "a clean thought",
            "a2ui_surface": {
                "components": [
                    {"type": "heading", "text": f"@{REAL_HANDLE} thinks"},
                    {"type": "body", "text": "nothing identifying here"},
                ]
            },
            "thought_type": "member_insight",
        }
        out = thought_redaction.redact_deep(row)
        assert REAL_HANDLE not in json.dumps(out)
        assert "nothing identifying here" in json.dumps(out)

    def test_keys_are_not_rewritten(self):
        """A key is a schema name. Rewriting one changes the document shape."""
        import thought_redaction

        out = thought_redaction.redact_deep({"@odd_key": "@ann-lee-4"})
        assert "@odd_key" in out
        assert "ann-lee-4" not in json.dumps(out)

    def test_non_string_leaves_survive(self):
        import thought_redaction

        out = thought_redaction.redact_deep({"n": 3, "b": True, "z": None, "l": [1, 2]})
        assert out == {"n": 3, "b": True, "z": None, "l": [1, 2]}


class TestGetThoughtsRoute:
    """``GET /api/thoughts`` returns the whole row, not a projection.

    ``TestWholeRowRoutes`` above exercises ``redact_deep`` as a bare function —
    nothing asserted that the ROUTE calls it. Planting away the ``redact_deep``
    call in ``chapter_agent.get_thoughts`` left the rest of the suite at 17
    passed: this class exists because that gap was found by planting, not by
    reading.

    The stubbed row carries a real handle in both ``thought_text`` and
    ``a2ui_surface`` — the two fields ``redact_deep`` walks — plus a ``targets``
    entry with the same handle as a bare value, which ``redact_deep`` does not
    touch (``HANDLE_RE`` requires a leading ``@``). The route drops ``targets``
    from the response rather than redacting it: see
    ``test_targets_no_longer_reaches_anonymous_callers``.
    """

    @staticmethod
    def _stub_row(monkeypatch):
        import chapter_agent

        row = {
            "id": "t1",
            "thought_type": "member_insight",
            "member_agent_id": REAL_HANDLE,
            "thought_text": HANDLE_IN_PROSE,
            "a2ui_surface": {"components": [{"type": "heading", "text": f"@{REAL_HANDLE} thinks"}]},
            "targets": [{"agent_id": REAL_HANDLE, "name": "Priya", "chapter": "boston"}],
            "created_at": "2026-08-24T00:00:00Z",
        }

        async def fake_pg(method, table, params=None, **kwargs):
            if table == "agent_thoughts":
                return [row]
            return []

        monkeypatch.setattr(chapter_agent, "pg_request", fake_pg)
        return chapter_agent

    @pytest.mark.asyncio
    async def test_a_real_handle_never_reaches_the_thoughts_route(self, monkeypatch):
        """THE GUARD. Neither the prose nor the a2ui card title survives the route.

        Asserts on the two explicit fields ``redact_deep`` is responsible for,
        not the whole row — ``targets`` is a separate mechanism (dropped, not
        redacted; see ``test_targets_no_longer_reaches_anonymous_callers``) and
        this test should not need to change if that mechanism does.
        """
        chapter_agent = self._stub_row(monkeypatch)

        result = await chapter_agent.get_thoughts()
        thought = result["thoughts"][0]
        redacted_fields = json.dumps({"thought_text": thought["thought_text"], "a2ui_surface": thought["a2ui_surface"]})

        assert f"@{REAL_HANDLE}" not in redacted_fields, (
            "a real member handle reached /api/thoughts in prose or an a2ui card title — "
            "redact_deep is not being applied to the route's rows"
        )
        assert REAL_HANDLE not in redacted_fields, (
            "the handle leaked without its @ — redaction must remove the identifier, not just the sigil"
        )
        assert "supply chain audits" in redacted_fields, "redaction removed the whole thought, not the handle"

    @pytest.mark.asyncio
    async def test_targets_no_longer_reaches_anonymous_callers(self, monkeypatch):
        """THE GAP CLOSING. This test used to record that ``targets`` shipped
        bare member ids and names unredacted — accepted at the time because no
        column removal belongs in a redaction bugfix.

        That follow-up landed: a repo-wide search (server/, renderer/, agent/,
        conformance/, docs/, index/, infra/, schema/, scripts/, skill/,
        smb_funnel/, smb_host/, smb_signup/) found no reader of a thought row's
        ``targets`` field anywhere — every non-write hit for the string
        ``targets`` was Python AST's unrelated ``ast.Assign.targets``, and
        nothing outside ``server/`` even references ``/api/thoughts``. Dropping
        the field from the route was therefore the cheap, honest fix: not a
        redaction (``redact_deep`` cannot reach a bare value), a removal.

        If this starts failing because ``targets`` reappeared in the response,
        that is itself the finding — a route regression, not a test to relax.
        """
        chapter_agent = self._stub_row(monkeypatch)

        result = await chapter_agent.get_thoughts()
        thought = result["thoughts"][0]

        assert "targets" not in thought, (
            "targets reappeared in the anonymous /api/thoughts response — "
            "it carries bare member ids and names redact_deep cannot reach"
        )


class TestWriteSide:
    """The durable half, covered directly rather than through a surface.

    ⚠️ THIS CLASS EXISTS BECAUSE ITS ABSENCE WAS FOUND BY PLANTING. Removing
    ``redact_handles`` from ``log_agent_thought`` reddened NOTHING across the
    whole suite: every existing caller asserts on what a surface renders, and
    the surface redacts again on read, so the write-side call was covered by
    its own stopgap. A durable fix with no direct test is a fix that survives
    exactly until someone reads the read-side redaction as the real one and
    deletes the duplicate.

    So these assert on the STORED ROW — the body handed to the database — and
    on nothing downstream of it.
    """

    @staticmethod
    def _capture(monkeypatch):
        import chapter_helpers

        written: list[dict] = []

        async def fake_pg(method, table, params=None, body=None, **kwargs):
            if method == "POST" and table == "agent_thoughts":
                written.append(body or {})
            return [{"id": "noop"}]

        monkeypatch.setattr(chapter_helpers, "pg_request", fake_pg)
        return chapter_helpers, written

    @pytest.mark.asyncio
    async def test_the_stored_row_does_not_contain_the_handle(self, monkeypatch):
        """THE GUARD FOR THE DURABLE HALF."""
        chapter_helpers, written = self._capture(monkeypatch)

        await chapter_helpers.log_agent_thought("conversation", HANDLE_IN_PROSE)

        assert written, "log_agent_thought did not write a row"
        stored = written[0]["thought_text"]
        assert REAL_HANDLE not in stored, (
            "the handle was persisted — write-time redaction is not running, and "
            "every row written from here on carries it at rest"
        )
        assert "supply chain audits" in stored, "redaction removed the thought, not the handle"

    @pytest.mark.asyncio
    async def test_the_whole_written_body_is_searched_not_just_the_column(self, monkeypatch):
        """Assert on VALUES anywhere in the body, not on one key.

        A key-name assertion is exactly the check that reported the activity
        surface clean while it was leaking.
        """
        chapter_helpers, written = self._capture(monkeypatch)

        await chapter_helpers.log_agent_thought("conversation", f"@{REAL_HANDLE}: hello", targets=[{"name": "Priya"}])
        assert REAL_HANDLE not in json.dumps(written[0]["thought_text"])

    @pytest.mark.asyncio
    async def test_multi_line_conversation_prose_is_redacted_at_write(self, monkeypatch):
        """The real shape think_conversation composes."""
        chapter_helpers, written = self._capture(monkeypatch)

        await chapter_helpers.log_agent_thought("conversation", "@ann-lee-4: hello there\n@bo-tan-9: hi back")
        stored = written[0]["thought_text"]
        assert "ann-lee-4" not in stored and "bo-tan-9" not in stored
        assert "hello there" in stored and "hi back" in stored

    @pytest.mark.asyncio
    async def test_member_agent_id_is_still_stored_unredacted(self, monkeypatch):
        """Deliberate, and asserted so it is not "fixed" later.

        ``member_agent_id`` is a COLUMN, so each read surface decides whether to
        select it, and the internal readers that attribute a thought need it.
        Redacting it would break attribution to close a leak that dropping the
        column already closes. The prose is the part no ``select`` can reach.
        """
        chapter_helpers, written = self._capture(monkeypatch)

        await chapter_helpers.log_agent_thought("member_insight", "a clean thought", member_agent_id=REAL_HANDLE)
        assert written[0]["member_agent_id"] == REAL_HANDLE

    @pytest.mark.asyncio
    async def test_clean_prose_is_stored_verbatim(self, monkeypatch):
        """Redaction must not rewrite thoughts that carry no handle."""
        chapter_helpers, written = self._capture(monkeypatch)

        prose = "The chapter is growing steadily this quarter."
        await chapter_helpers.log_agent_thought("insight", prose)
        assert written[0]["thought_text"] == prose
