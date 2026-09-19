# Release checklist

The ordered list walked before the source snapshot is pushed to the public
home. Each item names the evidence that closes it — a command's output, a
job's result, a page's table — and the last section is the set of lines the
walk produces. A release is GO when every line is filled with an observed
value and none of them is the wrong one.

This page is walked, not read: an item without its evidence line is an item
that is not done.

## 1. Every release-readiness change is on `main`

Merged means squash-merged to `main` with the `ci gate` green on the merge.
Titles are the pull requests' own.

**Execution path (agent).**
- [ ] pull request 706 — write-ahead receipts and consume-before-execute on
      the execution path: a pending attempt precedes every outbound call, an
      unobserved outcome is *unknown* and never silently dropped, a one-shot
      approval is spent before its runner fires; redirect-following in
      `net.http` closed; panic spends live approvals and resets trust.

**Server and host.**
- [ ] pull request 700 — `POST /api/digest/build` requires a signed member or
      the operator bearer (audit M11).
- [ ] pull request 702 — rate-limit persistence engages on the default
      install (the table is probed before DDL is issued).
- [ ] pull request 711 — a signature is not membership, and a silent member is
      not disclosed: TOFU no longer counts an unregistered signer as a member
      on gated routes; the Index hop, AgentFacts, trust and AAE surfaces stop
      republishing member prose or answering membership; the delta feed and
      the boot re-seed admit only members who opted in.
- [ ] pull request 715 — `ORRERY_KEY_SECRET` rotates through
      `ORRERY_KEY_SECRET_PREVIOUS` instead of re-keying the org.
- [ ] pull request 716 — an approval past its TTL cannot be approved before
      the sweeper runs.
- [ ] pull request 717 — `X-Auth-Status` says verified or not and stops naming
      the reason; audit M20 recorded residual with the spec-mandated cost.
- [ ] pull request 719 — first-run org setup (`POST /api/org/config`) requires
      the boot-printed admin token.
- [ ] pull request 722 — publishing into the org's skill registry requires a
      registered member's signature.
- [ ] pull request 723 — two residuals recorded with their cost (the Index-hop
      existence answer; the memory-only nonce store); the SMB host's tenant
      metadata written atomically.

**Installer and surfaces.**
- [ ] pull request 704 — the dashboard intent form submits through the
      shipped renderer.
- [ ] pull request 705 — a database volume that outlives its `.env` is refused
      by name; database readiness is bounded.
- [ ] pull request 707 — every run prints each port and why it is that port.
- [ ] pull request 709 — the installer says what is true for the kind of run
      it is; `down --purge` states what it kept; an interrupt says how to
      resume.

**Discovery and supply chain.**
- [ ] pull request 708 — no runtime reaches a registry it was not pointed at:
      the agent's fallback default registry removed; the heartbeat refresh and
      host39 publication gated on consent. Two behaviour changes need the
      human's yes before this merges: a consenting agent with `REGISTRY_URL`
      unset now publishes nowhere; the host's provision-then-publish in one
      call now refuses (a fresh tenant has no grant).
- [ ] pull request 710 — every clone instruction names the public home.
- [ ] pull request 712 — the MCP server's documented install works.
- [ ] pull request 713 — `anyio` 4.14.2 (three CVEs).
- [ ] pull request 718 — the secret scan allowlists the
      assignment-from-identifier shape rather than 24 blobs.
- [ ] pull request 720 — the CVE scan audits every pinned requirement file.
- [ ] pull request 721 — every Dockerfile base image pins a digest, as a rule.

**Documentation.**
- [ ] pull request 699 — the profile route is consent-gated, said so.
- [ ] pull request 703 — the trust model, cited and guarded.
- [ ] pull request 725 — the chapter/org statement, pointed at and cited by
      the gate.
- [ ] this change — README, QUICKSTART, ARCHITECTURE, THREAT_MODEL, SECURITY,
      CONTRIBUTING, COMPATIBILITY, this checklist.

Evidence line: `git log --oneline` on `main` at the release commit contains
each title above.

## 2. The demo runs

`bash scripts/demo_two_agents.sh` on the release commit, and the
`two_agent_demo` CI job on it. Observed on the pre-release tree: exit 0,
50 evidence files, teardown 0 containers / 0 volumes, and these lines in order:

- [ ] `SENT save_note → did:key:… under dat:…; receipt … co-signed → demo-evidence/1-happy-path`
- [ ] `VERIFIED ✓  issuer_did=did:key:… action=message_sent` (`verify.mjs`, issuer from A's card)
- [ ] `VERIFIED ✓  co-signed by witness_did=did:key:… over action=message_sent` (`verify_cosign.mjs`, witness from B's card)
- [ ] `REFUSED at the consent gate (authority_scope): …` exit 2, and `authority_no_grant` exit 2
- [ ] `FAILED ✗       stage=signature detail=Ed25519 verification failed` exit 1, twice (byte flipped; issuer swapped)
- [ ] `REFUSED at the consent gate (authority_expired): grant … expired at …` exit 2
- [ ] `[fault] tasks/send returned (completed); killing A now (os._exit 9)` exit 9, then on restart `[agency-log][UNKNOWN] message_sent started …`, the attempt under `/api/agency-log/unresolved` with `state=unknown`, and the retry `REFUSED as a duplicate` exit 3
- [ ] `demo-evidence/1-happy-path/org/checkpoint.json` records `404` (database-backed org; no checkpoint), and `org/receipt_record.json` holds the org's signed read

Evidence line: the script's exit code, the evidence file count, the teardown
counts, and the `two_agent_demo` job result on the release commit.

## 3. A clean install works, from the public home

Walked by a person on a machine with no prior Orrery state, following
[`QUICKSTART.md`](./QUICKSTART.md) verbatim from `git clone` of the public home.

- [ ] `./orrery-up` exits 0 with `── sign of life: ALL GREEN ──` and five
      addresses.
- [ ] `/health` reads `"status": "ok"`, `"members": 1`,
      `"rate_limit_persistence": true`.
- [ ] The renderer paints the dashboard; a need typed into the form paints
      *Intent Matched*.
- [ ] `./orrery-up` a second time prints `✓ .env kept (idempotent)` and the
      ports line naming every port as pinned.
- [ ] `./orrery-up down --purge` leaves 0 containers, 0 volumes, 0 listeners
      on the three ports.

The last full walk on the pre-release tree took 23–64 seconds to `ALL GREEN`
and found the defects that pull requests 702, 704, 705, 707 and 709 close; the
walk is repeated on the release commit because those are now claimed fixed.

Evidence line: the installer's output from `first start` to `ALL GREEN`, the
`/health` body, the second run's ports line, the teardown counts.

## 4. Egress is clean

Measured with a packet capture, not read from the code: a VM-wide capture for
the whole run plus a per-container capture attached to each Compose container
at start, across install, first boot, the sign-of-life drill and one think
cycle, on a keyless install with nothing configured.

- [ ] Runtime egress from the five containers: **none** outside the Compose
      network.
- [ ] Build-time egress, on an uncached build: only `registry-1.docker.io`,
      `deb.debian.org`, `pypi.org` and `files.pythonhosted.org`.
- [ ] `/health` on the stock install reads `registries.nest.configured: false`
      and `indexes: []`.

The pre-release measurement found exactly this, with the caveat that its
build was cached; the release walk repeats it uncached.

Evidence line: the capture summary — packets per container, the set of
non-private destination addresses (expected empty at runtime), the hosts seen
at build time.

## 5. The tree and its history carry no secret

- [ ] `gitleaks dir .` with the repository configuration: every hit classified
      as a published test vector, a documentation example, a deliberately-wrong
      value, or an assignment-from-identifier — no live credential.
- [ ] `scripts/full_history_secret_scan.py`: 0 findings not in
      `scripts/full_history_secret_baseline.txt`, exit 0.
- [ ] The Dockerfiles copy only source and lockfiles; `.dockerignore` excludes
      `.env`, `.org` and the admin-token files; `infra/seed.sql` carries no
      credential.

The pre-release audit found nothing to rotate: two tree hits (an environment
variable name; a throwaway local test password) and four history hits (a
deleted test's fixture; two public demo JWTs already recorded in
[`SECRET_SCAN_BASELINE.md`](./SECRET_SCAN_BASELINE.md)).

Evidence line: the two scans' summary lines and the classification of each hit.

## 6. Licensing is settled

- [ ] Every runtime dependency's license is compatible with MIT, listed with
      its source.
- [ ] No vendored code carries a different license than the file it sits in
      says.
- [ ] `LICENSE` and `NOTICE` at the root are current, and each distributable
      package's `pyproject.toml` names the same license.
- [ ] Anything license-shaped that is unclear has been put to the maintainer
      as a question and answered — nothing decided by inference.

Evidence line: the license inventory's output and the maintainer's answer to
each question raised.

## 7. Open findings are enumerated

- [ ] `python3 scripts/audit_gate.py --self-test && python3 scripts/audit_gate.py`
      exits 0.
- [ ] The open and residual ids in [`THREAT_MODEL.md`](./THREAT_MODEL.md) are
      exactly the ledger's open and residual ids (`docs/audit/findings.json`).
- [ ] Nothing in `README.md`, `QUICKSTART.md`, `SECURITY.md` or
      `COMPATIBILITY.md` states a finding closed that the ledger lists open.

Evidence line: the gate's `OK` line and the id list, side by side with the
ledger's.

## 8. The repository is ready to be public

Measured on the pre-release repository; each is the maintainer's decision.

- [ ] Visibility: the snapshot is pushed to the public home, which today
      carries the project page and no code.
- [ ] The README's CI badge points at a workflow a stranger can open.
- [ ] Wiki: disabled (it has no pages).
- [ ] Discussions: either enabled on the public home or the issue-template
      contact link retargeted; today the link resolves only on the
      pre-release repository.
- [ ] Dependabot alerts enabled; on the public repository, secret scanning,
      push protection and private vulnerability reporting enabled — the
      security policy's "Report a vulnerability" sentence is true only once
      the last of those is on.
- [ ] Branch protection on `main`: the single required check `ci gate`,
      strict; no force pushes; no deletions; the write-collaborator set
      reviewed before the flip.
- [ ] Every `sm-*` pin resolves on public PyPI at its exact version (twelve
      packages; measured true before release).
- [ ] A fresh clone installs every package from public PyPI alone and its
      suites pass (measured before release: every suite green; the skips are
      named and none is a missing private package).

Evidence line: the `gh api` outputs for visibility, protection and the
security settings, and the fresh-clone install log.

## 9. Decisions the maintainer owns

Raised by the release-readiness passes and not decided by anyone else. Each
is either decided here or carried as a known limit into the release notes.

- The org publishes its members' directory entries to a configured registry
  on the operator's consent alone; there is no member-level consent record.
- The OpenClaw skill's signer refuses plain-`http://` URLs, so it cannot join a
  local `./orrery-up` org; allowing loopback `http://` is a signing-oracle
  decision.
- The MCP `issue_receipt` tool returns a summary that `verify_receipt` cannot
  consume over the wire.
- [`VERIFY_A_RECEIPT.md`](./VERIFY_A_RECEIPT.md) does not say where a receipt
  id comes from, and its "no member's data" sentence overstates on a fresh org
  whose one receipt is an authority grant about the demo agent.
- AG-UI has no protocol version pinned by any test.
- The three Index-resolution routes answer existence anonymously by design of
  the Index hop; consent-gating them breaks resolution for published members
  who did not opt into the listing.
- An org-supplied trust score can lift a member over the auto-approve
  threshold for semi-trusted proposals; whether that is design or a defect.
- Whether executed local capability actions should produce a receipt.
- Whether to require review on `main` beyond the mechanical gate, and whether
  to keep admin bypass (recommended kept while the maintainer is the one
  admin).

## 10. GO / NO-GO

Filled in at the walk. Every line is an observed value; a blank is a NO-GO.

```
release commit ............: <sha>
section 1, all merged .....: yes / no — missing: <numbers>
section 2, demo ...........: <job url> <result>
section 3, clean install ..: exit <code>; ALL GREEN at <seconds>s; /health members=<n> rate_limit_persistence=<bool>; teardown <c>/<v>/<l>
section 4, egress .........: runtime non-private destinations: <set>; build hosts: <set>
section 5, secrets ........: tree hits <n> (all classified); history new findings <n>
section 6, license ........: <inventory result>; questions answered: <n>/<n>
section 7, findings .......: audit gate OK; open ids <list>; residual ids <list>
section 8, repository .....: visibility <value>; protection <contexts>; alerts/scanning/push-protection/private-reporting <on|off ×4>
section 9, decisions ......: <each, decided or carried>
verdict ...................: GO / NO-GO — <one line>
```
