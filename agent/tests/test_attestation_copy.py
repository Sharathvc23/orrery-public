"""The consumer-facing half of the owner-attestation decision.

The decision says a published listing carries a statement of what was checked
about the owner **and the consumer surface renders that statement instead of a
generic "verified"**. The writing half shipped; the reading half is this module
and ``community_member.attestation_copy``.

⚠️ THE GUARD IS THE POINT, AND THE VOCABULARY IS NOT RESTATED HERE. A test that
hand-copies the four values passes forever after a fifth is added: the new value
renders as nothing at all, and the suite that was supposed to notice was reading
its own copy of the list. So the vocabulary is PARSED OUT OF ``owner.py``'s
source and compared for SET EQUALITY with what the copy module can describe.
Both directions matter — a value with no rendering fails, and a rendering for a
value that no longer exists fails too.

⚠️ AND THE ENUMERATION IS CHECKED FOR VACUITY. A parser that matches nothing
reports an empty set, and an empty set is a subset of everything: the equality
above would then hold over no input and go green having read nothing. That is
the failure shape ``CONTRIBUTING.md`` names, so the floor below is deliberate
and is the ONLY place values appear as literals in this file.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

from community_member import attestation_copy, index_registrar, nanda_index, owner

OWNER_SOURCE = Path(inspect.getfile(owner))

#: An attestation value is a lower snake_case token. The shape, not a name list:
#: a fifth value matches it and is picked up, while ``OWNER_DERIVATION_PATH``
#: (a BIP32 path, ``m/44'/9004'/1'/0'/0'``) does not. A future ``OWNER_*``
#: constant that is snake_case but not a vocabulary value would be a false
#: positive here — and it would fail LOUDLY, demanding a rendering for something
#: that needs none, which is the safe direction for this filter to be wrong in.
_VALUE_SHAPE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")


def _vocabulary_from_owner_source() -> set[str]:
    """Every attestation value ``owner.py`` defines, read from its source.

    AST rather than ``dir(owner)``: the module object also carries whatever it
    imported, and a name-prefix sweep over that would drift with imports rather
    than with the vocabulary.
    """
    tree = ast.parse(OWNER_SOURCE.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.startswith("OWNER_"):
                if _VALUE_SHAPE.match(node.value.value):
                    found.add(node.value.value)
    return found


VOCABULARY = _vocabulary_from_owner_source()


# ── the guard ────────────────────────────────────────────────────────────────


def test_the_enumeration_is_not_vacuous():
    """The parser found the values that exist, so the equality below reads input.

    The floor is the four the decision names. It is a FLOOR, not the
    enumeration: it catches a parser that has stopped matching, which would make
    every other assertion here pass over an empty set.
    """
    assert VOCABULARY >= {
        owner.OWNER_OPERATOR_VOUCHED,
        owner.OWNER_INDIVIDUAL_OIDC,
        owner.OWNER_DOMAIN_VERIFIED,
        owner.OWNER_PLATFORM_ATTESTED,
    }, VOCABULARY


def test_every_attestation_value_has_its_own_rendering():
    """Set equality with the vocabulary in ``owner.py``.

    ⚠️ THIS IS THE TEST THAT REDDENS WHEN A FIFTH VALUE IS ADDED. Proven by
    planting one: adding a constant to ``owner.py``'s attestation section fails
    this assertion by name rather than letting the new value render as blank on
    every consumer surface.

    The reverse direction is asserted by the same equality: a rendering left
    behind for a value that was removed is dead copy that a reader could still
    be shown by a stale record.
    """
    assert set(attestation_copy.RENDERINGS) == VOCABULARY


def test_each_rendering_is_distinct_in_every_field():
    """Four values, four different things said — no two share any wording.

    A value that silently reused another's sentence would be the fifth-value
    failure with extra steps: present, rendered, and wrong.
    """
    for field in ("label", "who", "how", "sentence", "caveat"):
        seen = {value: getattr(copy, field) for value, copy in attestation_copy.RENDERINGS.items()}
        assert len(set(seen.values())) == len(seen), (field, seen)


def test_every_rendering_names_who_and_how_and_what_it_does_not_show():
    """The three parts are all required, on every value.

    The caveat is the one most likely to be dropped from the values that sound
    conclusive, and dropping it there is exactly how a ranking appears: two
    values with caveats and two without read as two tiers.
    """
    for value, copy in attestation_copy.RENDERINGS.items():
        assert copy.who.strip(), value
        assert copy.how.strip(), value
        assert copy.caveat.strip(), value
        assert copy.label.strip(), value
        # composed, so a sentence that names only one of the two cannot exist
        assert copy.who.lower() in copy.sentence.lower(), value
        assert copy.how in copy.sentence, value
        assert copy.sentence.endswith("."), value


# ── no ordering, anywhere ────────────────────────────────────────────────────

#: Words that would place these four on one axis. ``unverified`` is deliberately
#: absent: the decision REQUIRES it for a record that states nothing, and
#: ``test_no_vocabulary_value_reads_as_unverified`` pins where it may appear.
_ORDERING_WORDS = re.compile(
    r"\b("
    r"strong(?:er|est)?|weak(?:er|est)?|better|worse|best|highest|lowest|higher|lower|"
    r"level|tier|rank(?:ed|ing)?|score|grade|star|percent|basic|premium|standard|"
    r"partial|upgrade|downgrade|stronger than|more secure|less secure"
    r")\b",
    re.IGNORECASE,
)


def test_no_rendering_carries_ordering_vocabulary():
    """Copy is where a scale would be stated in words rather than in markup."""
    for value, copy in attestation_copy.RENDERINGS.items():
        for field, text in copy.as_dict().items():
            assert not _ORDERING_WORDS.search(text), (value, field, text)


def test_no_rendering_carries_an_ordinal_field():
    """The payload has no place to PUT a rank, so no consumer can sort by one.

    A ``rank``/``score``/``level`` key would be a scale invented here that every
    downstream surface would then order by, and the evidence supports none.
    """
    banned = {"rank", "score", "level", "strength", "weight", "stars", "percent", "order", "index", "tier"}
    for value, copy in attestation_copy.RENDERINGS.items():
        payload = copy.as_dict()
        assert not banned & set(payload), (value, sorted(banned & set(payload)))
        assert all(isinstance(v, str) for v in payload.values()), value


def test_the_presentation_order_is_sorted_and_therefore_claims_nothing():
    """A row of four is read as an ordering, so the only safe order is one that
    visibly encodes nothing. Alphabetical is that order.

    This reddens if someone arranges the vocabulary weakest-to-strongest — the
    most natural-looking edit anyone will ever make to this module, and the one
    that would ship a scale without a word of copy changing.
    """
    assert attestation_copy.vocabulary() == tuple(sorted(VOCABULARY))
    assert attestation_copy.vocabulary() != (
        # the strongest-to-weakest arrangement, named so the assertion above is
        # not merely "sorted() equals sorted()"
        owner.OWNER_PLATFORM_ATTESTED,
        owner.OWNER_DOMAIN_VERIFIED,
        owner.OWNER_INDIVIDUAL_OIDC,
        owner.OWNER_OPERATOR_VOUCHED,
    )


#: Names through which a vocabulary value or a rendering could reach a
#: comparison. The rule below is scoped to these rather than banning every
#: ordered comparison in the file: ``len(text) <= _MAX_ECHOED_VALUE`` is a
#: length clamp on an untrusted string and orders nothing, and a guard that
#: blocked it would be a guard someone deletes rather than follows.
_ORDERABLE_NAMES = ("RENDERINGS", "vocabulary", "attestation", "copy", "AttestationCopy")


def test_the_copy_module_orders_no_two_attestation_values():
    """No ``<``/``>`` and no keyed sort reaches the vocabulary, in the source.

    Read from the source rather than from behaviour: an ordering added as a
    helper nobody calls yet is still an ordering the next contributor wires up,
    and every rendered output would look identical until they did.

    ``sorted(RENDERINGS)`` is deliberately NOT caught — an unkeyed sort of the
    keys is the alphabetical presentation order this module wants, and it is
    what ``test_the_presentation_order_is_sorted_and_therefore_claims_nothing``
    pins. A ``key=`` is what would make it a ranking, so that is what is banned.
    """
    tree = ast.parse(Path(inspect.getfile(attestation_copy)).read_text(encoding="utf-8"))
    ordered = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(isinstance(op, ordered) for op in node.ops):
            rendered = ast.unparse(node)
            assert not any(name in rendered for name in _ORDERABLE_NAMES), rendered
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "sorted":
            assert not any(kw.arg == "key" for kw in node.keywords), ast.unparse(node)


# ── operator_vouched is neither a failure nor "unverified" ───────────────────

_FAILURE_WORDS = re.compile(
    r"\b(unverified|not verified|unchecked|failed|failure|invalid|missing|absent|none|untrusted|no evidence)\b",
    re.IGNORECASE,
)


def test_operator_vouched_reads_as_what_it_is():
    """Evidence exists, is valid, and anchors the operator.

    A listing with no valid owner evidence is refused by
    ``listing_grant_verdict`` and never published at all, so rendering this as
    an absence would describe a state the publishing path cannot produce. It
    names the operator as the party that acted, and it says so positively.
    """
    copy = attestation_copy.RENDERINGS[owner.OWNER_OPERATOR_VOUCHED]
    assert not _FAILURE_WORDS.search(copy.label), copy.label
    assert not _FAILURE_WORDS.search(copy.sentence), copy.sentence
    assert "operator" in copy.who.lower()
    # the caveat says what was NOT established without saying nothing was
    assert not _FAILURE_WORDS.search(copy.caveat), copy.caveat


def test_no_vocabulary_value_reads_as_unverified():
    """ "unverified" belongs to ABSENT alone.

    The decision says a record MISSING the field is to be read as unverified.
    Every published value means some real evidence was checked, so the word must
    not leak onto one of them — it is the exact conflation that would make
    ``operator_vouched`` read as a failed check.
    """
    for value, copy in attestation_copy.RENDERINGS.items():
        for field, text in copy.as_dict().items():
            assert "unverified" not in text.lower(), (value, field)
    assert "unverified" in attestation_copy.rendering_for(None).caveat.lower()


# ── absent, unrecognised, and never falling through ──────────────────────────


def test_absent_empty_and_whitespace_are_one_answer_and_it_is_not_a_value():
    """Unset, empty and whitespace are the same fact and must render the same.

    None of them may render as a vocabulary value: a record that states nothing
    shown as ``operator_vouched`` would be this stack asserting a check nobody
    performed, on a record we did not write.
    """
    for missing in (None, "", "   ", "\t\n"):
        copy = attestation_copy.rendering_for(missing)
        assert copy.value == attestation_copy.ABSENT, missing
        assert copy.value not in attestation_copy.RENDERINGS, missing


def test_an_unknown_value_is_named_rather_than_defaulted():
    """A vocabulary this build does not know is a THIRD answer, not the weakest.

    Defaulting to ``operator_vouched`` would answer a question nobody asked, in
    the direction of reassurance; defaulting to ABSENT would erase the fact that
    the record did state something. Both are wrong in a way the reader cannot see.
    """
    copy = attestation_copy.rendering_for("bank_account_verified")
    assert copy.value == attestation_copy.UNRECOGNISED
    assert copy.value != attestation_copy.ABSENT
    assert "bank_account_verified" in copy.sentence
    assert copy.value not in attestation_copy.RENDERINGS


def test_absent_and_unrecognised_are_distinct_from_each_other_and_from_every_value():
    """Three states through one field, told apart on the page as well as in code."""
    absent = attestation_copy.rendering_for(None)
    unknown = attestation_copy.rendering_for("something_else")
    assert absent.sentence != unknown.sentence
    assert absent.label != unknown.label
    for copy in attestation_copy.RENDERINGS.values():
        assert copy.sentence not in (absent.sentence, unknown.sentence)
        assert copy.label not in (absent.label, unknown.label)


def test_an_untrusted_value_is_clamped_before_it_is_echoed():
    """The string comes off a third party's index record and is shown to a reader.

    Escaping belongs to the surface that renders it; bounding the length belongs
    here, because a caller cannot un-print a kilobyte someone else chose.
    """
    copy = attestation_copy.rendering_for("x" * 5000)
    assert len(copy.sentence) < 400
    assert "…" in copy.sentence


# ── the value this reads is the value the record writes ──────────────────────


def test_the_key_read_is_the_key_the_record_writes():
    """One spelling, asserted against the record ``index_registrar`` builds.

    ``build_org_record`` writes the key as a literal inside a dict and exports no
    constant, so ``attestation_copy`` restates it. Two spellings of one key is
    how a reader reports ABSENT for a record that stated its attestation.
    """
    record = index_registrar.build_org_record(
        tenant_id="stellar-barbers",
        business_name="Stellar Barbers",
        did="did:key:z6MkrFpAWXdELWtJLpfD4YXgjqe7PTGgrHy3e3y2Ja84Gdcb",
        card_url="https://smb.example.com/t/stellar-barbers/.well-known/agent.json",
        domain="example.com",
        contact_email="nanda-smb@example.com",
    )
    assert attestation_copy.ATTESTATION_KEY in record["catalog_metadata"]
    assert attestation_copy.attestation_of(record) == owner.OWNER_OPERATOR_VOUCHED
    assert attestation_copy.rendering_for(attestation_copy.attestation_of(record)).value == owner.OWNER_OPERATOR_VOUCHED


def test_the_read_side_key_name_is_honoured_too():
    """``catalog_metadata`` on write, ``metadata`` on read — the mapping is an
    inference, so both names are read. A reader that knew only the write name
    would call every LIVE record absent."""
    read_shape = {"metadata": {attestation_copy.ATTESTATION_KEY: owner.OWNER_DOMAIN_VERIFIED}}
    assert attestation_copy.attestation_of(read_shape) == owner.OWNER_DOMAIN_VERIFIED


def test_a_non_string_value_is_not_passed_off_as_one():
    """A record is a third party's JSON. A number or an object where a string
    belongs is an unusable value, and it reads as ABSENT rather than as
    ``str(...)`` of whatever arrived."""
    for junk in (7, {"a": 1}, ["domain_verified"], True, None):
        record = {"metadata": {attestation_copy.ATTESTATION_KEY: junk}}
        assert attestation_copy.attestation_of(record) is None, junk


# ── the consumer surfaces actually render it ─────────────────────────────────


def test_discovery_carries_the_attestation_of_the_record_it_resolved():
    """The read path any consumer uses to reach a listed business.

    The value was in ``Discovery.record`` all along and nothing looked at it.
    """
    found = nanda_index.Discovery(
        ok=True,
        reason="ok",
        record={"metadata": {attestation_copy.ATTESTATION_KEY: owner.OWNER_INDIVIDUAL_OIDC}},
    )
    assert found.owner_attestation == owner.OWNER_INDIVIDUAL_OIDC
    assert found.attestation.value == owner.OWNER_INDIVIDUAL_OIDC
    assert "person" in found.attestation.sentence.lower()


def test_discovery_of_a_record_that_states_nothing_is_absent_not_vouched():
    """Including a refusal, which carries no record at all."""
    assert nanda_index.Discovery(ok=True, reason="ok", record={}).attestation.value == attestation_copy.ABSENT
    refused = nanda_index.Discovery(ok=False, reason="not_resolvable", detail="")
    assert refused.attestation.value == attestation_copy.ABSENT


@pytest.mark.parametrize(
    "module_path",
    [
        "scripts/register_tenant_on_index.py",
        "agent/community_member/cli.py",
        "agent/community_member/wizard.py",
        "agent/community_member/nanda_index.py",
    ],
)
def test_every_wired_consumer_surface_still_imports_the_copy_module(module_path):
    """The wiring, asserted against the source rather than against a render.

    A surface that stops importing this module renders nothing about the owner
    and looks exactly as it did before the decision — a silent removal that no
    output diff would show. Named surfaces, because the set of places a reader
    sees a listed business is a judgement, not something a pattern can derive.
    """
    repo = Path(__file__).resolve().parents[2]
    source = (repo / module_path).read_text(encoding="utf-8")
    assert "attestation_copy" in source, module_path


def _listed_agent(tmp_path):
    """A configured agent with a real, valid, OIDC-anchored owner binding.

    The exact shape the decision is about: the grant verifies, the evidence is
    genuine, and it anchors a PERSON — so the derived attestation is
    ``operator_vouched`` and the panel must not say the person authorised it.
    """
    from community_member import registry
    from community_member.config import Config
    from tests.test_owner import _binding

    config = Config(home=tmp_path)
    config.agent_id = "stellar-barbers"
    config.name = "Stellar Barbers"
    config.description = "Haircuts and beard trims"
    # ensure_keypair rather than assigning the key fields: it mints the Ed25519
    # pair the listing grant is checked against, and it is the call the runtime
    # itself makes, so this fixture cannot drift from a real agent's material.
    config.ensure_keypair()
    config.save()

    identity = owner.mint_owner_identity()
    binding = _binding(identity)
    binding["grant"] = owner.build_listing_grant(owner=identity, agent_did=registry.agent_did_key(config))
    owner.save_binding(tmp_path, **binding)
    return config


def _panel_text(config, monkeypatch):
    """What ``show_agent_card`` actually puts on screen."""
    import io

    from rich.console import Console

    from community_member import wizard

    buffer = io.StringIO()
    monkeypatch.setattr(wizard, "console", Console(file=buffer, width=200, no_color=True))
    wizard.show_agent_card(config, {"skills": ["haircut"], "reputation": {}})
    return buffer.getvalue()


def test_the_agent_card_panel_says_what_was_checked(tmp_path, monkeypatch):
    """Driven, not read. The panel is where an owner learns what their listing asserts."""
    rendered = " ".join(_panel_text(_listed_agent(tmp_path), monkeypatch).split())
    copy = attestation_copy.RENDERINGS[owner.OWNER_OPERATOR_VOUCHED]
    assert copy.label in rendered
    assert copy.sentence in rendered
    assert copy.caveat in rendered


def test_the_agent_card_panel_no_longer_names_the_subject_as_the_authoriser(tmp_path, monkeypatch):
    """⚠️ THE LINE THIS REPLACED WAS WRONG, NOT MERELY GENERIC.

    ``Listing: authorised by <subject>`` read the subject off the owner binding,
    which for an OIDC binding is the person's email address. So the panel told
    the reader that ``barber@example.com`` had authorised the listing — while
    the derivation, on the very same binding, says ``operator_vouched``: THE
    OPERATOR authorised it, and the sign-in proved a person, not a business.

    The rendered output was never malformed, so nothing that inspected the panel
    for shape could have caught it; only asking where the string came FROM does.
    The subject is still shown, labelled as the binding it is.
    """
    config = _listed_agent(tmp_path)
    rendered = " ".join(_panel_text(config, monkeypatch).split())
    subject = owner.load_binding(config.home)["subject"]
    assert subject == "barber@example.com"
    assert f"authorised by {subject}" not in rendered
    assert f"Owner binding subject: {subject}" in rendered


def test_the_copy_module_pulls_nothing_from_the_package():
    """Rendering must be importable from anywhere, including the read path.

    ``nanda_index`` is the READ half, and its own docstring says nothing an
    agent imports to FIND a peer should also be able to CREATE an org. Keying
    these renderings on ``owner.OWNER_*`` would have dragged the owner-key and
    signing module onto that path for the sake of four strings, and
    ``index_registrar`` already imports ``owner`` inside a function to avoid
    exactly that.

    The link to the vocabulary is
    ``test_every_attestation_value_has_its_own_rendering`` instead — set
    equality against ``owner.py``'s source, which is a stricter check than an
    import and costs the read path nothing.
    """
    tree = ast.parse(Path(inspect.getfile(attestation_copy)).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, ast.unparse(node)
            assert not (node.module or "").startswith("community_member"), ast.unparse(node)
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("community_member"), ast.unparse(node)
