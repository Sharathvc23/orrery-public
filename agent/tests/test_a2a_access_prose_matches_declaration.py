"""The prose a caller reads must agree with the gate that refused them.

MEASURED FAILURE, NOT A STYLE RULE. ``tasks/cancel`` moved from open to
caller-required when the task-ownership ruling landed. Two human-readable sentences
still named it as open,
and both are consumer-facing:

  * the ``-32004`` refusal itself — so the caller refused for ``tasks/cancel``
    was told, in the same string, that ``tasks/cancel`` is open;
  * ``securitySchemes.agentSignature.description`` on the served agent card —
    so every stranger resolving the card read that cancel was open, while
    ``x-nanda.a2a_method_access`` on the SAME card, being derived, said
    caller-required. The card contradicted itself in two adjacent fields.

Nothing compared the prose to the declaration, so nothing failed. This module is
that comparison. It asserts the RENDERED strings, not that they are built by a
particular expression, so re-typing a literal fails here rather than shipping.
"""

from __future__ import annotations

from community_member import a2a_card
from community_member import a2a_rpc as rpc
from community_member.a2a_auth import AUTHENTICATED_METHODS, OPEN_METHODS


def _refusal(method: str = "tasks/send") -> str:
    return rpc._CALLER_REQUIRED_MESSAGE.format(method=method)


def _card_description() -> str:
    return a2a_card._security_declaration(None)["securitySchemes"]["agentSignature"]["description"]


def test_no_gated_method_is_described_as_open_in_the_refusal():
    """The exact defect: a caller-required method named inside the open list."""
    refusal = _refusal()
    open_clause = refusal.split("Reads (", 1)[1].split(")", 1)[0]
    for method in AUTHENTICATED_METHODS:
        assert method not in open_clause, (
            f"{method} is caller-required but the -32004 refusal lists it as open. "
            "Derive the phrase from a2a_auth.METHOD_ACCESS rather than typing it out."
        )


def test_no_gated_method_is_described_as_open_on_the_card():
    """Same assertion against the string strangers actually resolve."""
    description = _card_description()
    open_clause = description.split("reads (", 1)[1].split(")", 1)[0]
    for method in AUTHENTICATED_METHODS:
        assert method not in open_clause, (
            f"{method} is caller-required but the served agent card describes it as open — "
            "while x-nanda.a2a_method_access on the same card says otherwise."
        )


def test_every_open_method_is_named_in_both_places():
    """Under-listing is the other direction of the same drift.

    A method that is open and unnamed sends a caller to sign a request that
    needed no signature — less dangerous than the reverse, and still wrong.
    """
    refusal, description = _refusal(), _card_description()
    for method in OPEN_METHODS:
        assert method in refusal, f"{method} is open but the refusal does not name it"
        assert method in description, f"{method} is open but the card description does not name it"


def test_the_card_names_the_gated_methods_a_stock_client_will_call():
    """A current-spec client sends ``message/send``; it must find itself here.

    The classified names are the v0.2 ones the handler dispatches on, so a
    reader holding a stock client cannot map the list to what it sends unless
    the aliases are named too.
    """
    description = _card_description()
    for method in AUTHENTICATED_METHODS:
        assert method in description, f"{method} is caller-required but the card does not name it"
    assert "message/send" in description
    assert "message/stream" in description


def test_both_strings_state_possession_not_identity():
    """A claim names its scope AND its limit, at the point the claim is made.

    A signature here proves possession of the presented key. There is no peer
    registry, so a fresh keypair verifies. Saying "verified caller" without that
    limit reads as an allowlist, which is the overstatement class this repo
    removes rather than hedges.
    """
    for name, text in (("refusal", _refusal()), ("card description", _card_description())):
        lowered = text.lower()
        assert "possession" in lowered, f"the {name} does not say what signing proves"
        assert "allowlist" in lowered or "no peer registry" in lowered or "not that the key is known" in lowered, (
            f"the {name} does not state the limit — that possession is not identity"
        )
