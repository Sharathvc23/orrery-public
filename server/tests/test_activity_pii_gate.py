"""The activity-feed PII closure — the activity feed must not hand member PII to an anonymous caller.

GET /api/activity returned 50 rows of ``member_name`` PAIRED WITH
``user_message_snippet`` — a real person's name next to a snippet of what they
said to their agent — plus ``member_agent_id`` and ``conversation_id``. ~17KB
per response, unauthenticated, on all three deployed orgs (and the five
chapters running the umbrella twin of this module).

The sibling A2UI surface leaked the SAME VALUES while looking clean to a
field-name probe, because the builder flattens them into ``Text`` components:
``member_name`` was absent as a key and present as a value. The surface test
below therefore asserts on VALUES, not on key names — a key-name assertion is
exactly the check that reported this surface clean while it was leaking.

Twin of chapter/tests/test_activity_pii_gate.py in the NANDA Chapter Protocol
umbrella. Both runtimes serve this route; fixing one leaves the other exposed
(the divergence class).
"""

from __future__ import annotations

import json

import pytest

import auth_verify


class TestActivityRestRouteIsGated:
    def test_activity_requires_auth_for_anonymous_get(self):
        """The regression under test — assert on ``requires_auth``, NOT ``is_open_path``.

        ``is_open_path("GET", "/api/activity")`` was ALREADY False before the
        fix, because the path is in no open list. It leaked anyway: the
        middleware short-circuits only on ``is_open_path``, then consults
        ``requires_auth``, which returned False because the path was in no
        require-auth list either. "Not open" and "requires auth" are different
        questions, and the route sat in the third state — neither — which reads
        as gated at a glance. A test asserting ``is_open_path is False`` would
        have passed on the leaking build.
        """
        assert auth_verify.requires_auth("GET", "/api/activity") is True

    def test_is_open_path_alone_does_not_prove_the_gate(self):
        """Pin the trap above so nobody 'simplifies' this suite into a no-op."""
        assert auth_verify.is_open_path("GET", "/api/activity") is False

    def test_activity_is_in_the_require_auth_set_by_name(self):
        assert "/api/activity" in auth_verify.REQUIRE_AUTH_GET_PATHS


class TestActivitySurfaceIsRedacted:
    """The surface stays PUBLIC but must carry no member identity or message text."""

    def test_surface_stays_open(self):
        assert auth_verify.is_open_path("GET", "/api/surfaces/activity") is True

    @pytest.mark.asyncio
    async def test_surface_carries_no_member_name_or_message_text(self, monkeypatch):
        """ADVERSARIAL: assert on VALUES appearing anywhere in the rendered body."""
        import surfaces

        NAME = "Wilhelmina-Sentinel-Personname"
        MSG = "sentinel-private-question-about-my-medical-results"
        RESP = "sentinel-private-answer-text"

        async def fake_pg(method, table, params=None, **kwargs):
            select = (params or {}).get("select", "")
            # Prove the builder never even ASKS the database for the PII.
            assert "member_name" not in select, f"{table}: member_name must not be selected"
            assert "user_message_snippet" not in select, f"{table}: snippet must not be selected"
            assert "agent_response_snippet" not in select, f"{table}: response must not be selected"
            if table == "agent_activity":
                # Return the PII anyway: a `select=` is a request, not a
                # guarantee, and a future backend that ignores it must not
                # turn this surface back into a leak.
                return [
                    {
                        "id": "a1",
                        "chapter_name": "AstroCity",
                        "is_cross_chapter": True,
                        "created_at": "2026-07-30T00:00:00Z",
                        "member_name": NAME,
                        "user_message_snippet": MSG,
                        "agent_response_snippet": RESP,
                    }
                ]
            if table == "agent_thoughts":
                return [
                    {
                        "id": "t1",
                        "thought_type": "insight",
                        "thought_text": "a public agent-authored thought",
                        "chapter_name": "AstroCity",
                        "created_at": "2026-07-30T00:00:00Z",
                        "member_name": NAME,
                    }
                ]
            return []

        monkeypatch.setattr(surfaces, "pg_request", fake_pg)
        body = json.dumps(await surfaces.build_activity_surface())

        assert NAME not in body, "member name leaked into the public activity surface"
        assert MSG not in body, "private message text leaked into the public activity surface"
        assert RESP not in body, "agent response text leaked into the public activity surface"

    @pytest.mark.asyncio
    async def test_surface_still_reports_activity_volume(self, monkeypatch):
        """The page must remain useful: counts are not PII."""
        import surfaces

        async def fake_pg(method, table, params=None, **kwargs):
            if table == "agent_activity":
                return [
                    {"id": "a1", "is_cross_chapter": True},
                    {"id": "a2", "is_cross_chapter": False},
                ]
            return []

        monkeypatch.setattr(surfaces, "pg_request", fake_pg)
        body = json.dumps(await surfaces.build_activity_surface())
        assert "2 recent conversations" in body
        assert "1 cross-server" in body
