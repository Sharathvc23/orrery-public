"""What a reader is told about the owner evidence behind a listed business.

``org.projectnanda.ownerAttestation`` is written into every index record by
``index_registrar``, and names WHICH check was satisfied when the listing was
authorised. Until this module there was nowhere it was read back and said in
words: the value travelled to the index and stopped there, so a consumer who
resolved a business saw a name, an endpoint and a did:key, and nothing about who
had authorised the association between them.

This module is the one place that turns a value into words. It obtains no
evidence, derives no value, and adds none to the vocabulary — the derivation is
``owner.owner_attestation`` and is deliberately not restated here.

⚠️ THE FOUR VALUES ARE NOT A SCALE AND MUST NOT BE RENDERED AS ONE. That is the
whole constraint, so it is written here rather than left to be inferred:

* ``domain_verified`` and ``platform_attested`` bear on ownership of a BUSINESS.
* ``individual_oidc`` is a strong check of a PERSON and no check of a business.
* ``operator_vouched`` is a check of the HOST OPERATOR — real evidence, validly
  anchored, about a third party.

Those are three different subjects, not three positions on one axis. Ordering
them — stars, a percentage, a badge that gets greener, a list that reads
top-to-bottom as strongest-to-weakest — would restate the conflation the
vocabulary exists to remove, and would restate it on the one surface a
non-engineer reads. So:

* Every rendering carries BOTH a positive ``who``/``how`` clause and a ``caveat``
  naming what it does not establish. No value gets only-positive treatment and
  none gets only-negative treatment. The symmetry is the mechanism: a reader
  comparing two of these finds two different subjects rather than two ranks.
* ``operator_vouched`` reads as neither a failure nor "unverified". A listing
  with no valid owner evidence is refused by ``owner.listing_grant_verdict`` and
  never published, so a published ``operator_vouched`` means evidence exists, is
  valid, and anchors the operator. Rendering it as an absence would describe a
  state the publishing path cannot produce.
* :data:`ABSENT` is the one rendering that does say unverified, because the
  decision is explicit that a record missing the field is to be read as
  unverified rather than as unspecified.

⚠️ NO DEPENDENCIES, DELIBERATELY. This module imports nothing from the package —
not even ``owner``, whose constants it mirrors. Two reasons, and the second is
the load-bearing one:

1. ``owner`` pulls in the signing stack. ``index_registrar`` already imports it
   inside a function for that reason, and ``nanda_index`` is the READ half whose
   own docstring says nothing an agent imports to *find* a peer should also be
   able to *create* an org. A copy module that dragged the owner-key module onto
   the read path would undo that separation for the sake of four strings.
2. Keying on imported constants would make a fifth value a ``KeyError`` at the
   point of use — a failure at the reader's request, in production. Keying on
   literals and asserting SET EQUALITY against the vocabulary parsed out of
   ``owner.py``'s source is a stricter link and it fails at merge instead: it
   catches a value added there with no rendering here AND a rendering here for a
   value that no longer exists. That assertion is
   ``agent/tests/test_attestation_copy.py``, and it is the deliverable.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The record key the value is published under. ``index_registrar`` writes it as
#: a literal inside a dict and exports no constant, so it is restated here; the
#: test asserts the two spellings agree against the record that module builds.
ATTESTATION_KEY = "org.projectnanda.ownerAttestation"

#: What a reader is shown when the record carries no attestation at all — key
#: missing, or present and empty. Not a member of the vocabulary: it is what
#: this module says ABOUT a record that names nothing.
ABSENT = "absent"

#: What a reader is shown when the record names a check this build does not
#: know: a newer writer, or a record from somewhere else. Distinct from
#: :data:`ABSENT` because "nothing was stated" and "something was stated that I
#: cannot describe" are different facts, and collapsing them hides a vocabulary
#: that has moved on.
UNRECOGNISED = "unrecognised"

#: A third party's string is echoed back to a reader in the UNRECOGNISED
#: sentence, so it is clamped before it gets there. Length only — escaping
#: belongs to whichever surface renders it, the only layer that knows whether it
#: is writing a terminal, HTML or JSON.
_MAX_ECHOED_VALUE = 64


@dataclass(frozen=True)
class AttestationCopy:
    """One value, said in words a non-engineer reads correctly.

    ``sentence`` is composed from ``who`` and ``how`` rather than authored beside
    them, so a sentence that fails to name both cannot be written.
    """

    #: The value described, or :data:`ABSENT` / :data:`UNRECOGNISED`.
    value: str
    #: A short heading: a noun phrase naming the subject that was checked. Never
    #: an adjective — an adjective is where a scale gets in.
    label: str
    #: WHO was verified. The grammatical subject of :attr:`sentence`.
    who: str
    #: HOW they were verified. Its predicate.
    how: str
    #: What this evidence does not establish. Present on every rendering,
    #: including the ones a reader might otherwise take as conclusive.
    caveat: str

    @property
    def sentence(self) -> str:
        """One sentence naming who was verified and how."""
        return f"{self.who[:1].upper()}{self.who[1:]} {self.how}."

    def as_dict(self) -> dict[str, str]:
        """The rendering as plain data, for a JSON surface.

        Carries no numeric or ordinal field, deliberately. A ``rank``, ``score``,
        ``level`` or ``strength`` here would be a scale every downstream consumer
        would then sort by — and a scale invented by this module rather than one
        the evidence supports.
        """
        return {
            "value": self.value,
            "label": self.label,
            "who": self.who,
            "how": self.how,
            "sentence": self.sentence,
            "caveat": self.caveat,
        }


#: Keyed by the wire value. Mirrors ``owner.OWNER_*``; set equality with the
#: vocabulary parsed out of ``owner.py`` is asserted by the guard test.
RENDERINGS: dict[str, AttestationCopy] = {
    # Names the operator as the party that acted. Not "unverified", not "basic",
    # not "self-declared": the operator's own evidence was checked and is real.
    # It is evidence about the operator rather than about the business.
    "operator_vouched": AttestationCopy(
        value="operator_vouched",
        label="Authorised by the host operator",
        who="the host operator",
        how=("authorised this listing with the operator's own verified identity, and is the party accountable for it"),
        caveat="It does not show that the business named here asked to be listed.",
    ),
    "individual_oidc": AttestationCopy(
        value="individual_oidc",
        label="A person signed in",
        who="a person",
        how=("signed in with an identity provider, and that sign-in was bound to the key that authorised this listing"),
        # The sentence the vocabulary exists to make sayable. A personal sign-in
        # reading as proof of business ownership is the substitution owner.py's
        # platform refusal was written to stop.
        caveat="It does not show that the person owns or runs the business named here.",
    ),
    "domain_verified": AttestationCopy(
        value="domain_verified",
        label="The business's own domain name was proven",
        who="whoever controls the business's own domain name",
        how=(
            "answered a challenge on that domain — an HTTP file or a DNS record — "
            "with the key that authorised this listing"
        ),
        caveat="It does not identify the person who answered the challenge.",
    ),
    "platform_attested": AttestationCopy(
        value="platform_attested",
        label="The platform running the business issued a credential",
        who="the commerce platform that runs this business day to day",
        how=(
            "issued an install credential for this listing, so the platform is the party that identified the business"
        ),
        caveat=(
            "It does not identify the person who installed the app, and it carries "
            "the platform's checks rather than this host's."
        ),
    ),
}

#: :data:`ABSENT` and :data:`UNRECOGNISED` live outside :data:`RENDERINGS` so
#: that a caller iterating the vocabulary gets the vocabulary. They are reached
#: only through :func:`rendering_for`.
_ABSENT_COPY = AttestationCopy(
    value=ABSENT,
    label="Nothing was stated about who authorised this listing",
    who="nobody",
    how=("is recorded as having authorised this listing, because the record carries no statement of what was checked"),
    caveat="Read this listing as unverified rather than as unspecified.",
)


def _clamp(text: str) -> str:
    """Bound an untrusted string by LENGTH. Nothing here orders anything."""
    return text if len(text) <= _MAX_ECHOED_VALUE else text[:_MAX_ECHOED_VALUE] + "…"


def _unrecognised_copy(value: str) -> AttestationCopy:
    shown = _clamp(value)
    return AttestationCopy(
        value=UNRECOGNISED,
        label="This listing names a check that cannot be described here",
        who="this reader",
        how=(f"does not recognise the check this listing names ({shown!r}), so it cannot say what was verified"),
        caveat="Nothing here should be read as verified.",
    )


def rendering_for(value: str | None) -> AttestationCopy:
    """The words for one attestation value.

    Three outcomes, never two. A missing value, an empty value and a value from
    a vocabulary this build does not know arrive through the same field, and a
    reader who cannot tell them apart is being told something false about at
    least one of them:

    * missing, or empty, or whitespace → :data:`ABSENT`
    * a value not in :data:`RENDERINGS` → :data:`UNRECOGNISED`, echoing what was
      named so a reader can act on it
    * otherwise → that value's rendering

    An unknown value NEVER falls through to ``operator_vouched`` or to any other
    vocabulary rendering. That would answer a question nobody asked, in the
    direction of reassurance.
    """
    if value is None:
        return _ABSENT_COPY
    text = value.strip()
    if not text:
        return _ABSENT_COPY
    found = RENDERINGS.get(text)
    return _unrecognised_copy(text) if found is None else found


def vocabulary() -> tuple[str, ...]:
    """Every value this module can describe, in a presentation order.

    ⚠️ SORTED, AND THE SORT IS THE POINT. Any other fixed order is a claim: a
    reader shown four things in a row reads the row as an ordering, and the only
    ordering the evidence supports is none. Alphabetical is the one arrangement
    that visibly encodes nothing about strength, and the guard asserts it — so a
    later edit that arranges these weakest-to-strongest fails at merge rather
    than shipping a scale in the markup.
    """
    return tuple(sorted(RENDERINGS))


def attestation_of(record: dict) -> str | None:
    """The attestation an index record carries, or ``None`` if it carries none.

    ⚠️ ``catalog_metadata`` ON WRITE, ``metadata`` ON READ. The pairing is an
    inference recorded in ``index_registrar`` and not yet confirmed against a
    live read-back, so both names are looked at. A reader that knew only one of
    them would report the field ABSENT for a record that states its attestation
    under the other — the value read as unverified because of a key name.

    Returns the raw string. It is a third party's data and is not validated
    here: deciding what an unknown value means is :func:`rendering_for`'s job,
    and dropping one silently would erase the fact that something was stated.
    """
    for key in ("metadata", "catalog_metadata"):
        bag = record.get(key)
        if isinstance(bag, dict) and ATTESTATION_KEY in bag:
            found = bag[ATTESTATION_KEY]
            return found if isinstance(found, str) else None
    return None
