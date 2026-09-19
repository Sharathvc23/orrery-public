# Decision — a published listing states what was checked about the owner

**Status:** decision, partially built. The evidence types it names already exist
in code; the carrying of them into a published record does not. Where this
document describes something that is not built, it says so.

**Traced against** `main` @ `244713b` (2026-08-21). Measurements below were taken
by running the code, not by reading it.

Related: [`NANDA_CONNECT_GAPS.md`](NANDA_CONNECT_GAPS.md) maps the delegated
provisioning problem from the protocol side. This document is narrower: it is
about what a record we publish is entitled to assert.

## The problem

`scripts/register_tenant_on_index.py` publishes a record to the NANDA Index
saying that a `did:key` is the agent for a named business. Somebody has to have
authorised that, and a consumer has to be able to tell how hard anyone looked.

Three authority paths exist in `agent/community_member/owner.py`, and its module
docstring already separates them correctly:

| Path | Evidence | State |
|---|---|---|
| Individual | OIDC ID token, nonce-bound to the owner key | built |
| Domain-owning business | HTTP-01 or DNS-01 challenge, bound to the owner key | built |
| Platform install | an install credential from Shopify / Wix / Toast / Square | refuses (`owner.py:1690`) |

The refusal is correct and should stay. `platform_install_refusal`
(`owner.py:1693`) explains that proving you own a business needs a credential
from the platform that runs it, that no such integration exists in this stack,
and that the path therefore stops rather than reporting a success it cannot back.

The docstring also states the property that matters here: an OIDC sign-in proves
a **person**, and letting it read as proof of business ownership is the outcome
the refusal exists to prevent.

## What is actually happening today

Two observations, both measured against `244713b`.

**1. The gate does not report which evidence satisfied it.** `GrantVerdict`
(`owner.py:1517`) has three fields — `ok`, `reason`, `detail`. `_evidence_verdict`
(`owner.py:1606`) iterates the evidence blocks, dispatches on the first block
whose `type` is `oidc` or `domain_control`, and returns. On success
`listing_grant_verdict` returns a single shared value (`owner.py:1603`):

```
GrantVerdict(True, "ok", f"listing authorised by {owner_did[:32]}…")
```

The detail names the **key**, not the evidence. An OIDC-anchored binding and a
domain-control-anchored binding produce answers a caller cannot distinguish.
Driven directly, using the binding builder in `agent/tests/test_owner.py` whose
subject is `barber@example.com` and whose anchor is a Google OIDC sign-in:

```
ok=True  reason='ok'  detail='listing authorised by did:key:z6Mkva5mq8jasHZK5kzd7Lwx…'
evidence block types: ['oidc']
```

That is an authorised business listing backed by a personal sign-in. Nothing
downstream can see the difference, because the evidence type is checked and then
discarded. A binding carrying both block types is decided by list order.

**2. The published record makes no statement about it.** `_build_record`
(`agent/community_member/index_registrar.py:205`) already separates two claims,
deliberately and correctly:

- `publisher.identifier: urn:ai:domain:<domain>` — who vouched, the operator's
  verified domain, `identityType: "dns"`.
- `trust_manifest.identity: did:key:…` — who signs, the tenant.

There is no third field for **how the business itself was verified**, so a record
authorised by a personal Google sign-in and a record authorised by control of the
business's own domain are byte-identical in that respect.

## Decision

**A published listing carries a statement of what was checked about the owner,
the statement is derived from the evidence actually present rather than
configured, and the consumer surface renders that statement instead of a generic
"verified".**

Four values, which are not new vocabulary — three of them are `owner.py`'s
existing evidence types, and the fourth is the case the code currently has no
name for:

| Value | What was checked | Backed by |
|---|---|---|
| `operator_vouched` | nothing about the business; the host operator asserts the association | no owner evidence — the operator's own grant |
| `individual_oidc` | a person authenticated with an identity provider | `_OIDC` block (`owner.py:219`) |
| `domain_verified` | control of the domain named in the identifier | `_DOMAIN_CONTROL` block (`owner.py:220`) |
| `platform_attested` | an install credential from the platform running the business | not built; `owner.py:1690` refuses |

**These are not a linear scale and must not be rendered as one.** Only
`domain_verified` and `platform_attested` bear on *business* ownership.
`individual_oidc` is a strong check of a person and no check at all of a
business; ranking it "between" the other two would reintroduce exactly the
conflation this decision exists to remove.

### Deriving the value is not a lookup of the evidence type

Reading the block `type` and mapping `domain_control` to `domain_verified` would
be wrong, and wrong in the dangerous direction.

In the operator-as-owner shape the grant is signed by the **operator's** key and
anchored by domain-control evidence over the **operator's** domain. The evidence
type is `domain_control` and the evidence is entirely genuine, but the domain it
proves control of is not the listed business's. A type lookup would publish
`domain_verified` on a record where nothing about that business's domain was
checked.

The derivation therefore has two inputs, not one: the evidence type, and whose
identity the evidence anchors relative to the business being listed.

- `domain_verified` requires that the domain proven in the `_DOMAIN_CONTROL`
  block is the business's own. Under the current identifier scheme
  (`urn:ai:domain:<operator-domain>:agent:<slug>`, `index_registrar.py:208`) the
  domain in the identifier is always the operator's, so **`domain_verified` is
  not derivable for any tenant today.** That is a true statement about where the
  code is, and the implementation should produce `operator_vouched` rather than
  reaching for a value it cannot substantiate.
- `individual_oidc` requires that the OIDC subject is the business's principal
  rather than the operator's.
- Otherwise: `operator_vouched`.

`operator_vouched` is not "no evidence". A listing with no valid owner evidence
is refused outright by `listing_grant_verdict` and is never published at all. It
means evidence exists, is valid, and anchors the operator.

### Where the statement lives

`catalog_metadata`, under the `org.projectnanda.*` convention the record already
uses (`index_registrar.py:224`):

```
"org.projectnanda.ownerAttestation": "operator_vouched"
```

This requires no change to the index schema, which we do not control. The
existing caveat on that field applies unchanged: the `catalog_metadata` →
`metadata` read/write pairing is an inference, and the post-registration check
reports whether the keys survived rather than assuming they did.

### The default is the weakest honest value

Absent owner evidence, a record is `operator_vouched`. It must never be absent
and must never fall back to a stronger value. A listing whose attestation field
is missing is to be read as unverified, not as unspecified.

## What this permits immediately

The three test businesses can be listed today as `operator_vouched`. That is an
accurate description of what happened: the host operator authorised the listing,
and nobody verified the business. It unblocks a live index record without
asserting anything false.

## What it does not permit

A real business must not be published until either `domain_verified` or
`platform_attested` is available to it. The operator-as-owner grant passes every
check in `listing_grant_verdict` honestly — the evidence is real and bound to the
grantor key — but the claim it supports is "the operator authorised this
listing", not "the business authorised its own listing". Publishing the second on
the strength of the first is the substitution `platform_install_refusal` was
written to prevent, moved one layer up from the gate into the record.

## Consequences

**Platform install is the SMB path and it is real work.** A business whose entire
control plane is a commerce platform has already been identity-checked by that
platform at onboarding. Federating on that check through an install credential is
the only mechanism that reaches a business with no domain. Square is the first
target for the booking use case. This is a build, not a configuration change, and
it is not scoped here.

**`nanda-connect` remains a dependency to consume, not a thing to extend.** Its
`providers/platform_install.py` is a 66-line verifier with an injected validator
and three string constants; the missing pieces are a partner account and an
integration, neither of which live in that repository. Nothing in this decision
authorises work there.

**Revocation exists; dispute does not.** `listing_grant_verdict` reports
`revoked` and `suspended` as distinct reasons rather than collapsing them into
absent consent, so withdrawal is already representable and already checked. What
does not exist is a route by which a business that did not authorise a listing
can report it. A published record asserting an association that the named
business never agreed to is the failure mode this whole area guards against, and
the mechanism to withdraw one is only half of handling it.

## Not decided here

- The wire name and shape of a platform install credential.
- Whether `hosting_path` should ever be sent. It stays omitted for the reason
  already recorded in `index_registrar.py`: the field is write-only, absent from
  every read schema and from all 251 live records, so no value's effect is
  observable.
- Whether the attestation value should also appear on the tenant's agent card as
  well as in the index record.
