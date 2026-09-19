# Full-history secret scan — what was found, and why each finding is accepted

`scripts/full_history_secret_scan.py` scans **every commit and every blob
reachable from every ref**, not the PR range. This file is the classification
record behind `scripts/full_history_secret_baseline.txt`: that file pins accepted
findings by location, and this one says why each is acceptable.

**A baseline entry is an assertion that a human looked at a finding and it was
not a live credential.** Adding a line to make CI green, without doing that, is
the only way this control fails.

> **The fingerprints are deliberately portable across a republish.** Blob ids are
> content-addressed and survive; commit ids do not, and neither do line numbers
> once history is squashed. A baseline keyed on either would match nothing in a
> freshly published repository, so the first scheduled run there would go red and
> read as *"the published repo leaks secrets"*. Blob entries therefore carry
> `blob:<id>:<file>:<rule>:<line>` and commit entries only `commit:<file>:<rule>`.
> Detection does not rest on the commit pass: adding a secret changes a file's
> content, so the blob sweep sees an id it has never seen and fails, with file and
> line intact. Verified by publishing this tree as a squashed single commit and
> planting a fresh Ed25519 PEM and a random `AKIA` token in it — both passes
> reported them and the scan exited non-zero.

## Method

Run on **2026-08-13** against 747 reachable commits with gitleaks **8.24.3** —
the same version and the same `.gitleaks.toml` as the `secret scan (new commits)`
merge gate, deliberately: a full-history scan using a looser ruleset than the PR
gate would report a different number for the same tree, and neither number would
mean anything.

Two passes, because the obvious one has a blind spot:

| Pass | What it scans | Result |
|---|---|---|
| Commit walk (`--log-opts=--all`) | diffs, all refs | 711 of 747 commits, 48 findings |
| Blob sweep | every unique reachable blob (3,399) | 46 findings |

The commit walk scanned **711 of 747** commits: `git log` does not diff merge
commits, so content that entered only through a merge resolution is never shown
to it. The blob sweep is topology-independent and closes that gap. It surfaced
no secret class the commit walk had missed — but that is a measured result, not
an assumption, which is the reason both passes are kept.

Together: **16 unique candidate secrets. 0 live credentials, 2 fixtures, 14
false positives.**

## Classification

### False positives (14) — the entropy rule firing on identifiers, not values

`gitleaks`' broad `generic-api-key` rule matches *source identifiers* and
*placeholders*, which is expected and not tunable without weakening it.

> These are **described rather than quoted verbatim**, deliberately. The first
> draft of this file pasted the offending lines in full and the PR-range secret
> scan promptly flagged the file — correctly, and for exactly the reason it
> flagged the originals: the rule matches the *shape*, and a shape does not stop
> being one because it appears inside documentation about itself.

- `wizard.py`, `smb_host/main.py` — a `private_key` attribute assigned from a
  `private_key_b64` field
- `auth.py`, `portable.py` — a `_private_key` local bound from a
  `private_key_b64` parameter
- `test_recovery_rotation.py` — an equality assertion between two
  `private_key_b64` attributes
- `test_ledger.py` — a tuple unpack whose second name is `signature_b64`
- `backup_restore_check.sh` — a SQL upsert clause referencing `EXCLUDED.secret_b64`
- placeholder DIDs: `z6MkPrincipal`, `z6MkPlaceholder`, `zE2ePrincipal`,
  `z6MkOtherPrincipalDidThatHasNoReceipts`
- `test_channel_receiver.py` — a 32-character stub containing the run `yyyzzz`,
  so not hex at all: hand-typed, never a real key
- `test_keystore_passphrase_env.py` — a `_KEY_B64` constant that is plain base64
  of the ASCII string `foobarbazqux…`
- `did-key-derivations.json` — a `z7QHXWpg…` value that is a **`must_not_equal`
  negative case**, asserting base64url encoding yields a *non-conforming* DID

### Fixtures (2) — real material, published on purpose, both verified

**1. `.env.example` `ANON_KEY` / `SERVICE_KEY` (history only).**
Both are the canonical, publicly-published Supabase *self-hosted demo* tokens
(`iss: supabase-demo`). **Verified, not assumed:** recomputing HMAC-SHA256 over
each token with the published demo secret reproduces both signatures exactly. The
file labelled them `well-known Supabase DEV demo keys` at the time, and no live
project URL accompanied them. Introduced in `98826ab` (initial release), removed
in `9bdc606` (the SaaS → agent-native pivot) — so they survive **only in
history**, which is precisely the class a HEAD-only scan cannot see.

**2. `vectors/signing/ed25519-canonical-strings.json` → `private_key32_hex`**
(and its copy under `agent/community_member/_conformance_vectors/`).
This *is* genuine Ed25519 private key material, published deliberately so an
adapter can prove a real sign/verify roundtrip. **Verified:** deriving the public
key and the `did:key` from the seed reproduces the file's stated values exactly,
and that DID appears nowhere outside the two vector files — it is not an identity
on any deployment.

> ⚠️ **That keypair is compromised by design.** It is a conformance fixture, like
> a NIST test vector. It must never be used as an identity anywhere.

## What the allowlist in `.gitleaks.toml` does — audited, not trusted

Default rules over the same history give **332** findings; the repo config gives
**48**. All **284** suppressed matches were checked against the config's three
shape regexes and **0 were unexplained** — it masks only `z6Mk…` public
multicodec DIDs and 88-character Ed25519 signatures. Zero `private-key`,
`aws-access-token` or `github-pat` hits anywhere in history.

> ⚠️ **Re-deriving that 332 needs an explicit `-c` pointing elsewhere.** gitleaks
> **auto-loads `.gitleaks.toml` from the scan target path**, so a run that simply
> omits `-c` to get an unconfigured baseline silently loads the repo config
> anyway and returns the identical number — which reads as "the allowlist does
> nothing" when in fact it was applied to both runs. This was hit while producing
> the numbers above.

## Limits — stated so a green run is not over-read

Carried forward from `.gitleaks.toml`, verified by planting material:

- a **bare 32-byte base64 seed** is not detected
- a **low-entropy token** (`sk_live_aaa…`) is not detected

Neither is caused by this repo's config — baseline gitleaks with no config misses
them identically. A green full-history scan means *no known secret shape is
present*, not *no key of any shape can be present*.

Detection itself is proven rather than asserted: planting a fresh Ed25519 PEM and
a random `AKIA…` token into a commit makes both passes report them as new
findings and the script exit non-zero.

## History was NOT rewritten

Nothing was purged, rebased or force-pushed, and the scanner must never gain that
ability. No live credential was found, so nothing needed rotating. Had one been
found, the order is **rotate first** — a committed credential is compromised from
the moment it lands, and rotation is what closes the exposure — and only then is
purge-versus-leave worth discussing. Rewriting invalidates SHAs already cited
across this repo's issues and PRs, and no PR can undo it. That call belongs to a
human.
