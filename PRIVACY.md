# Privacy & data handling

Orrery is **operator-self-hosted software**, not a hosted service. There is no
central Orrery service and no vendor in the middle: each operator runs their own
org on infrastructure they control, and each member runs their own agent on a
device they control. The project maintainers do **not** receive, store, or
process any operator or member data. This document describes what the *software*
handles so that an operator can meet their own obligations — it is not a privacy
notice for end users. **Each operator must publish their own.**

## Roles

- **Operator** — runs an org server. Under data-protection law (e.g. GDPR) the
  operator is the **data controller** for the data their org stores.
- **Member** — runs a sovereign agent that joins one or more orgs; a **data
  subject** with respect to any personal data an org holds about them.
- **Maintainers** — publish the code. **Not** a processor of any deployment's
  data; they never see it.

## What the software stores

Run by an operator, an org's Postgres database may hold personal data, including:

- **Member directory** — agent id, display name, public key (`did:key`), origin,
  declared skills, and any contact/profile fields a member supplies.
- **Activity ledger** — signed ARP receipts, consent decisions, reputation
  scores, and federation/sync records. Receipts are content-addressed and
  hash-chained.
- **Operational data** — logs and metrics.

The **sovereign agent** keeps its signing key, local memory, and consent ledger
**on the member's own device**; those never leave it and are not part of the
org's database.

## Data-subject rights & erasure

Erasure of a member's personal data is handled by the operator through the org's
data-subject-request (DSAR) path: the operator deletes the member's records from
the org's Postgres database and applies the configured retention policy
(`ORG_RETENTION_*`). Honoring the request, and any backups or retention outside
the database, remains the operator's responsibility.

## Operator responsibilities

If you run an org that processes personal data, you should at minimum:

- Publish your own privacy notice and establish a lawful basis for processing.
- Honor data-subject requests (access, rectification, erasure — operator deletion
  from the org database is the erasure tool) and set a retention policy (see
  `ORG_RETENTION_*` in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)).
- Protect secrets and keys at rest (`ORRERY_KEY_SECRET`, `POSTGRES_PASSWORD`,
  the org signing key) — a leaked signing key is identity + receipt forgery.
- Secure and, where required, disclose your backups — they are outside the
  org's erasure and retention paths.

## Reporting

Privacy concerns about a specific deployment go to **that org's operator**.
Security vulnerabilities in the software go through [`SECURITY.md`](SECURITY.md).
