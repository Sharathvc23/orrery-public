# L11 — telling subscribers which event text is untrusted

**Design note. No implementation.** L11 stays `residual` in
[`findings.json`](./findings.json). Facts are from `server/event_types.py`,
`server/chapter_agent.py` and `server/event_bus.py` as of 2026-09-14.

## The finding's reasoning is right

The server does not escape event text on the way out, and it should not. It
does not know the rendering context: the same string may land in an HTML body,
an attribute, a JS string, a terminal, or a markdown renderer, and each needs a
different escape. Escaping server-side either double-escapes for a consumer
doing its job or under-escapes for the context it guessed wrong. Output encoding
belongs at the point of output.

What the server owes consumers is not pretending the text is safe. L11 records
that debt. This note is about paying it.

## Three corrections to the finding as written

**1. Most fields are already provably safe, so the problem is smaller than
"event payloads carry user text".** The payload models are Pydantic and many
fields are constrained types that cannot carry a payload at all: `origin` and
`reason` are `Literal`, `peer_endpoint` is `HttpUrl`, `kind` is `Literal`,
`trust_score` / `match_score` are floats, the counts are ints, `event_id` and
`occurred_at` are server-set. The untrusted set is bounded and enumerable:

| Event type | Member- or model-authored fields | Min trust to subscribe |
|---|---|---:|
| `member.joined` | `name`, `skills[]` | **0.0 — anonymous** |
| `intent.published` | `text`, `tags[]` | **0.0 — anonymous** |
| `chapter.digest.weekly` | `headline`, `summary_markdown`, `top_intents[]`, `new_members[]`, `federation_changes[]` | **0.0 — anonymous** |
| `chapter.broadcast` | `title`, `body`, `tags[]` | 25.0 |

**2. The consumer set is unbounded, not "subscribers".** Three of the four
untrusted-bearing event types are `0.0` in `MIN_TRUST_TO_SUBSCRIBE` — public
tier. The digest's own comment names the intended consumers: "the
podcast-as-agent, a newsletter generator, a public dashboard". So the text
reaches renderers that were never onboarded, never read a contract, and cannot
be asked to.

**3. For the digest, the closed schema does not bound shape either.** `top_intents`,
`new_members` and `federation_changes` are bare `list[dict]`, deliberately:

> we don't enforce a nested schema here because the digest evolves faster than
> the event-bus catalog

That is a defensible product call and it makes the finding's phrase "validated
against the closed schema in `event_types`, which bounds shape but not the text
inside a permitted field" inaccurate for these three: nothing bounds them.
`summary_markdown` compounds it — the field name tells a consumer to run a
markdown renderer, and most markdown renderers pass raw HTML through unless
explicitly configured not to.

## `sanitize_text` is not a defence here, and its name suggests it is

```python
def sanitize_text(text: str, max_length: int = 2000) -> str:
    """Strip dangerous patterns from user input."""
    text = text[:max_length]
    text = text.replace("\x00", "")
    for marker in ["<|system|>", "<|user|>", ...]:
        text = text.replace(marker, "")
    return text.strip()
```

It truncates, drops null bytes, and removes prompt-injection markers. It does
nothing about HTML. It is also not applied on the event publish path at all.
Recorded because the docstring reads as a general-purpose sanitizer, and a
future maintainer could reasonably conclude a field that passed through it is
safe to render.

## What others do

Nobody escapes at the producer. Everybody labels.

- **ActivityPub / Mastodon** ship `content` as HTML and publish a sanitization
  allowlist; clients sanitize on receipt.
- **Slack Block Kit** types every text field at the schema level — `plain_text`
  versus `mrkdwn` — so the renderer is told which mode applies rather than
  sniffing.
- **CloudEvents** carries `datacontenttype` for exactly this reason: the
  producer declares how to interpret the bytes.
- **JSON Schema** provides `contentMediaType` as the standard slot for that
  declaration.

The common shape: a machine-readable, per-field statement of what the text is,
shipped with the schema, so a consumer can be correct without guessing.

Orrery cannot do this today for a mundane reason — **it publishes no event
schema at all.** There is no catalog endpoint and no events contract document;
`PAYLOAD_FOR` is server-internal. A subscriber has no way to learn which fields
are untrusted even if it wanted to.

## Proposed design

**Classify every text-bearing field, as a closed set.** Add a table beside
`PAYLOAD_FOR`:

```python
UNTRUSTED_TEXT_FIELDS: dict[EventType, frozenset[str]] = {...}
```

naming the fields whose contents originate with a member or a language model.

**Make the classification total, and enforce it the way the catalog is already
enforced.** `test_event_types.py` has
`test_every_event_type_has_a_payload_class`; the sibling assertion is that every
`str`, `list[str]` and `dict` field on every payload class is classified either
server-set or untrusted. A new payload field then cannot land unclassified —
the same discipline, one step further.

**Publish it.** Expose the catalog — event types, payload schemas, and the
untrusted-field set — at a read endpoint, and emit the annotation with the
schema so a consumer can assert it handled every untrusted field it received. A
label nobody can read is not a contract.

**Fix the two digest-specific problems, which are the server's own:**

- Give `top_intents`, `new_members` and `federation_changes` nested schemas, or
  classify the whole field untrusted and say so. Today a reader is told the
  schema is closed when for these it is not.
- State that `summary_markdown` is markdown *without* embedded HTML, and
  classify it untrusted regardless — it is model-composed from member text.

**Do not start escaping server-side.** The reasoning in the finding is correct
and the change would make consumers worse off.

## What landed, 2026-09-14

All three parts of the proposal above.

**The tables**, in `server/event_types.py`: `UNTRUSTED_TEXT_FIELDS` and
`SERVER_AUTHORED_TEXT_FIELDS`, plus `text_provenance()` returning the served
shape. The dividing rule is stated in the module, because the borderline cases
are where this goes wrong: **a field is server-authored iff this server produced
the value; a value this server merely constrained is not.** So `agent_id` is
untrusted even though `sanitize_agent_id` restricts it today, and
`broadcast_id` is untrusted even though it is a UUID — a federated broadcast
arrives from a peer and this server did not mint it. Four text fields survive as
server-authored: `occurred_at`, `last_success_at`, `window_start`/`window_end`,
and `intent_id` (`str(uuid.uuid4())`, minted in `intents.py`).

**The guard**, `server/tests/test_event_text_provenance.py`. The field set is
derived by walking `model_fields` of every class in `PAYLOAD_FOR`, so a field
cannot hide by being added without touching `event_types`. Text-bearing is
computed from the annotation rather than hardcoded — widening `Literal[...]` to
`str` pulls a field into the guard automatically. Four assertions: every
text-bearing field is classified, no classification outlives its field, the two
classes are disjoint, and the served catalog matches the tables.

**The catalog**, `GET /api/event-catalog`. Deliberately not
`/api/events/catalog`: `/api/events` is the agent-proposed community events
list, and nesting the bus catalog under it would read as a sub-resource of that
list. Open, and it can afford to be — every value comes from module-level
constants, no database, no parameters. It is open *on purpose* rather than
incidentally: a statement about which text to escape is worthless if reading it
requires being a subscriber already, and three of the four text-bearing types
are trust `0.0`. `test_route_auth_classification` caught the new route as
unclassified on its first run, which is the guard from L2's neighbourhood doing
its job; it now carries a traced rationale in `INTENTIONALLY_PUBLIC_PATHS`.

**Plant-proved.** Four defects, each reddening the assertion meant to catch it:

| planted defect | caught by |
|---|---|
| a new unclassified `str` field on a payload | `test_every_text_bearing_field_is_classified` |
| a classification left behind after its field is removed | `test_no_classified_field_has_been_removed_or_renamed` |
| a field classified both untrusted and server-authored | `test_the_two_classes_are_disjoint` |
| the catalog serving an empty provenance split | `test_catalog_matches_the_tables_it_publishes` (9 failures, one per event type) |

The digest's two specific problems are handled by classification rather than by
reshaping the payload, which the note offered as the alternative: `top_intents`,
`new_members` and `federation_changes` are marked untrusted **whole** — keys as
well as values, since nothing bounds them — and `summary_markdown` is published
with the statement that it is markdown *without* embedded HTML, so a renderer
permitting raw HTML must disable it for that field.

## Status

L11 stays `residual`, and this is the smallest it can honestly get. The XSS
lives in a subscriber and the server still does not escape — correctly. What has
changed is that the residual is no longer "consumers are not told": the
classification is total, enforced by a test that reddens on an unclassified
field, and served where a subscriber can read it. What remains is that a
consumer may ignore what it was told, which is not something this server can
close.
