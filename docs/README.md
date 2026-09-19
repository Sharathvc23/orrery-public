# Orrery docs map

One page per question. Start with the [repo README](../README.md) — the product
pitch, install, and the NANDA stack picture — then come here for depth.

## Deciding whether to run it

| Doc | The question it answers |
| --- | --- |
| [`POSITIONING.md`](./POSITIONING.md) | Why Orrery vs a bare agent framework — who it's for, what it is NOT |
| [`QUICKSTART.md`](./QUICKSTART.md) | `./orrery-up` from a clean machine: what it prints, what the keyless install can and cannot do, what a key adds, how to stop and start over |
| [`COMPATIBILITY.md`](./COMPATIBILITY.md) | Every protocol and integration at the version the tests pin, labelled supported / experimental / unfinished; the toolchain CI runs |
| [`ROADMAP.md`](./ROADMAP.md) | What's planned but **not** done (only the not-yet — shipped items are removed) |

## Running it

| Doc | The question it answers |
| --- | --- |
| [`MANUAL.md`](./MANUAL.md) | **Start here** after the quickstart. From nothing to a running org, a working agent, and a receipt someone else can verify |
| [`INSTALL.md`](./INSTALL.md) | How to install: `./orrery-up`, the manual compose path, verify, troubleshoot, go to production |
| [`CONFIGURATION.md`](./CONFIGURATION.md) | Every environment variable, grouped as `.env.example` ships them, plus the `prod` profile |
| [`API.md`](./API.md) | The org server's HTTP surface, grouped by area, with the auth rules |
| [`SKILLS.md`](./SKILLS.md) | Publish, install and review skills — what a signature tells you, and what installing does not sandbox |
| [`DEPLOY_AWS.md`](./DEPLOY_AWS.md) | Standing the org up on AWS: the three settings that are outages if you get them wrong, plus two deployment shapes with every untested step labelled UNVERIFIED |
| [`JOIN.md`](./JOIN.md) | How a member joins — TOFU registration with a `did:key` they hold, landing copy for all three runtimes, and the invite-token gap that blocks the QR flow today |
| [`../smb_host/OPERATIONS.md`](../smb_host/OPERATIONS.md) | Running the SMB host for other businesses: what a tenant home holds, why a persistent volume is necessary and not sufficient, the four settings, and the redeploy check that proves the volume is real — driven by hand or by `scripts/smb_host_canary.py` |

## Understanding it

| Doc | The question it answers |
| --- | --- |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | The three-layer conceptual model: Kernel / Distribution / Skin, and the dependency direction |
| [`STACK.md`](./STACK.md) | The runtime picture: service topology, request lifecycle, data layer, federation |
| [`specs/agui.md`](./specs/agui.md) | The generative-UI contract: A2UI v0.10 envelopes over AG-UI SSE |
| [`integrations/STELLARMINDS.md`](./integrations/STELLARMINDS.md) | How the `sm-*` packages are adopted and pinned (supply-chain policy) |
| [`specs/NANDA_CONNECT_GAPS.md`](./specs/NANDA_CONNECT_GAPS.md) | Delegated binding provisioning: what a store-provisions-on-your-behalf protocol needs, and what this repo does and does not have (analysis, nothing built) |
| [`specs/SMB_RESOLUTION_RESPONSE.md`](./specs/SMB_RESOLUTION_RESPONSE.md) | Response to the SMB resolution draft on two points it leaves open — badge-gated accreditation (§7.3/§9) and attributable divergence proofs (§3.2/§9) — with each claim checked against deployed state and its limits stated |
| [`specs/OWNER_ATTESTATION_STRENGTH.md`](./specs/OWNER_ATTESTATION_STRENGTH.md) | Decision: a published index listing states what was checked about the owner, derived from the evidence present rather than configured, and the consumer surface renders it instead of a generic "verified" |

## Trusting it

| Doc | The question it answers |
| --- | --- |
| [`TRUST_MODEL.md`](./TRUST_MODEL.md) | **What a signature proves and what it does not.** Per action kind, what is recorded and who can verify it; the four artifacts a reader must not conflate; offline freshness limits; checkpoint and fork assumptions; who holds which key. Every claim cited to a code symbol or a named test, and guarded |
| [`VERIFY_A_RECEIPT.md`](./VERIFY_A_RECEIPT.md) | Check an org's receipt yourself, offline, with nothing from this repository |
| [`VERIFY_A_BADGE.md`](./VERIFY_A_BADGE.md) | Check an org's conformance badge yourself — what it proves, and what self-attested means |
| [`CLAIMS.md`](./CLAIMS.md) | Every advertised capability adjudicated PROVEN / PARTIAL / ASPIRATIONAL, with the evidence cited |
| [`GATES.md`](./GATES.md) | The four repository gates: what each refuses, how to run them, what to do when one fires on correct prose |
| [`THREAT_MODEL.md`](./THREAT_MODEL.md) | Assets, parties and what each can do to the others; every open and residual audit finding by id with its accepted cost; the known gaps |
| [`RELEASE_CHECKLIST.md`](./RELEASE_CHECKLIST.md) | The ordered walk before a release snapshot, with the evidence line each step produces |
| [`../SECURITY.md`](../SECURITY.md) | How to report a vulnerability, what a report should contain, supported versions |
| [`HARDENING.md`](./HARDENING.md) | The security audit, verbatim: every finding, severity, and fix plan |
| [`audit/RELEASE_SIGNOFF_v0.2.0.md`](./audit/RELEASE_SIGNOFF_v0.2.0.md) | The historical disposition record at v0.2.0; current status is the ledger, enumerated in `THREAT_MODEL.md` |

## Project meta

[`../CONTRIBUTING.md`](../CONTRIBUTING.md) — build, test, submit ·
[`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) — community standards ·
[`../PRIVACY.md`](../PRIVACY.md) — what the software stores; the operator's duty ·
[`../CHANGELOG.md`](../CHANGELOG.md) — release history ·
[`../LICENSE`](../LICENSE) — MIT across the stack: the product, the `sm-*` primitives and the NANDA spec ·
[`LICENSES.md`](LICENSES.md) — every dependency, vendored component, base image and opt-in service with its license, read from metadata; the CI gate that keeps it true

### Terminology note

User-facing language is **org** and **agent**. The code keeps the protocol noun:
the word "chapter" stays in wire ids, routes, headers, signed strings, event
topics, table names, metrics and the main module, because the org server
implements the Chapter Protocol and other software depends on those spellings.
The mapping and the full list of frozen surfaces are stated once in
[`ARCHITECTURE.md` § Two nouns](./ARCHITECTURE.md#two-nouns-for-one-thing-protocol-and-product).
